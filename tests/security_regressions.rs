use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use anyhow::Result;
use axum::{Json, Router, response::Redirect, routing::get};
use futures_util::{StreamExt, stream};
use mysyncfiles::{
    client::{self, ClientConfig},
    model::{BeginUpload, Entry, Manifest, RestoreRequest, TrashItem, UploadProgress, valid_path},
    server, update,
};
use reqwest::{Client, StatusCode};
use sha2::{Digest, Sha256};
use tokio::{sync::Notify, task::JoinHandle};

fn unfinished_body(bytes: usize) -> axum::body::Body {
    axum::body::Body::from_stream(
        stream::iter((0..bytes.div_ceil(8192)).map(|_| Ok::<_, std::io::Error>(vec![b' '; 8192])))
            .chain(stream::pending()),
    )
}

#[tokio::test]
async fn api_json_limits_reject_large_headers_and_unfinished_chunked_bodies() -> Result<()> {
    for route in ["/v1/manifest", "/v1/trash", "/v1/trash/restore"] {
        let limit = if route.ends_with("restore") {
            64 * 1024
        } else {
            32 * 1024 * 1024
        };
        for advertised in [false, true] {
            let server = TestServer::start(Router::new().fallback(move || async move {
                let mut response = axum::http::Response::builder();
                if advertised {
                    response = response.header("content-length", limit + 1);
                }
                response
                    .body(unfinished_body(if advertised { 0 } else { limit + 1 }))
                    .unwrap()
            }))
            .await?;
            let temp = tempfile::tempdir()?;
            let api = client::Api::new(&config(&server.url, temp.path()))?;
            let result = tokio::time::timeout(Duration::from_secs(5), async {
                match route {
                    "/v1/manifest" => api.manifest().await.map(|_| ()),
                    "/v1/trash" => api.trash().await.map(|_| ()),
                    _ => api.restore(1).await.map(|_| ()),
                }
            })
            .await?;
            assert!(
                result.unwrap_err().to_string().contains("exceeds"),
                "{route}, content-length={advertised}"
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn overlong_download_stops_before_eof_and_leaves_local_data_and_staging_safe() -> Result<()> {
    for advertised in [false, true] {
        let server = TestServer::start(
            Router::new()
                .route(
                    "/v1/manifest",
                    get(|| async {
                        Json(Manifest {
                            generation: 1,
                            entries: vec![Entry {
                                path: "keep".into(),
                                revision: 1,
                                sha256: Some(sha(b"x")),
                                size: Some(1),
                                deleted: false,
                            }],
                        })
                    }),
                )
                .route(
                    "/v1/file",
                    get(move || async move {
                        let mut response = axum::http::Response::builder();
                        if advertised {
                            response = response.header("content-length", 8192);
                        }
                        response
                            .body(unfinished_body(if advertised { 0 } else { 8192 }))
                            .unwrap()
                    }),
                ),
        )
        .await?;
        let temp = tempfile::tempdir()?;
        let root = temp.path().join("mirror");
        std::fs::create_dir(&root)?;
        std::fs::write(root.join("keep"), b"local edit")?;
        let path = temp.path().join("config.json");
        std::fs::write(&path, serde_json::to_vec(&config(&server.url, &root))?)?;
        let error = tokio::time::timeout(Duration::from_secs(3), client::sync(&path))
            .await?
            .err()
            .unwrap();
        assert!(
            error
                .to_string()
                .contains(if advertised { "length" } else { "exceeds" })
        );
        assert_eq!(std::fs::read(root.join("keep"))?, b"local edit");
        assert_eq!(std::fs::read_dir(root.join(".mysync-staging"))?.count(), 0);
        assert!(!path.with_extension("state.json").exists());
    }
    Ok(())
}

#[tokio::test]
async fn maximum_relative_path_can_be_downloaded_scanned_and_deleted() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let (server, key) = TestServer::sync_server(&temp.path().join("data")).await?;
    let http = Client::new();
    let mut components = vec!["x".repeat(255); 15];
    components.extend(["y".repeat(253), "z".into()]);
    let path = components.join("/"); // Parent alone is 4093 bytes.
    assert_eq!(path.len(), 4095);
    let mut entry: Entry = put(&http, &server, &key, &path, 0)
        .await?
        .error_for_status()?
        .json()
        .await?;
    let root = temp.path().join("mirror");
    let config_path = temp.path().join("config.json");
    assert_eq!(
        client::configure(
            &config_path,
            server.url.clone(),
            key.clone(),
            root.clone(),
            false
        )
        .await?
        .downloaded,
        1
    );
    assert_eq!(client::status(&config_path).await?.local_files, 1);
    assert_eq!(client::sync(&config_path).await?.uploaded, 0);
    let mut directory = std::fs::File::open(&root)?;
    for component in &components[..components.len() - 1] {
        directory = std::fs::File::from(rustix::fs::openat(
            &directory,
            component.as_str(),
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )?);
    }
    let mut edited = std::fs::File::from(rustix::fs::openat(
        &directory,
        "z",
        rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::TRUNC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )?);
    std::io::Write::write_all(&mut edited, b"local edit")?;
    drop(edited);
    entry = put(&http, &server, &key, &path, entry.revision)
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(client::sync(&config_path).await?.conflicts, 1);
    assert_eq!(client::status(&config_path).await?.conflicts, 1);
    remove(&http, &server, &key, &entry).await?;
    assert_eq!(client::sync(&config_path).await?.deleted_local, 1);
    assert_eq!(client::status(&config_path).await?.local_files, 0);
    client::sync(&config_path).await?;
    Ok(())
}

#[tokio::test]
async fn negative_or_missing_download_size_is_rejected_without_fetching_content() -> Result<()> {
    for size in [None, Some(-1)] {
        let hits = Arc::new(AtomicUsize::new(0));
        let server = TestServer::start(
            Router::new()
                .route(
                    "/v1/manifest",
                    get(move || async move {
                        Json(Manifest {
                            generation: 1,
                            entries: vec![Entry {
                                path: "bad-size".into(),
                                revision: 1,
                                sha256: Some(sha(b"x")),
                                size,
                                deleted: false,
                            }],
                        })
                    }),
                )
                .route(
                    "/v1/file",
                    get({
                        let hits = hits.clone();
                        move || {
                            hits.fetch_add(1, Ordering::SeqCst);
                            async { "x" }
                        }
                    }),
                ),
        )
        .await?;
        let temp = tempfile::tempdir()?;
        let root = temp.path().join("mirror");
        std::fs::create_dir(&root)?;
        let path = temp.path().join("config.json");
        std::fs::write(&path, serde_json::to_vec(&config(&server.url, &root))?)?;
        assert!(client::sync(&path).await.is_err());
        assert_eq!(hits.load(Ordering::SeqCst), 0);
        assert_eq!(std::fs::read_dir(root.join(".mysync-staging"))?.count(), 0);
    }
    Ok(())
}

#[tokio::test]
async fn directory_file_transitions_converge_and_preserve_local_edits() -> Result<()> {
    for modified in [false, true] {
        let temp = tempfile::tempdir()?;
        let (server, key) = TestServer::sync_server(&temp.path().join("data")).await?;
        let first = temp.path().join("first");
        let second = temp.path().join("second");
        let first_config = temp.path().join("first.json");
        let second_config = temp.path().join("second.json");
        std::fs::create_dir_all(first.join("a"))?;
        std::fs::write(first.join("a/b"), b"original")?;
        client::configure(
            &first_config,
            server.url.clone(),
            key.clone(),
            first.clone(),
            true,
        )
        .await?;
        client::configure(
            &second_config,
            server.url.clone(),
            key.clone(),
            second.clone(),
            false,
        )
        .await?;
        if modified {
            std::fs::write(second.join("a/b"), b"edited")?;
            std::fs::write(second.join("a/new"), b"untracked")?;
        }
        std::fs::remove_file(first.join("a/b"))?;
        std::fs::remove_dir(first.join("a"))?;
        std::fs::write(first.join("a"), b"replacement")?;
        std::fs::write(first.join("unrelated"), b"still syncing")?;
        client::sync(&first_config).await?;
        let report = client::sync(&second_config).await?;
        assert_eq!(std::fs::read(second.join("a"))?, b"replacement");
        assert_eq!(std::fs::read(second.join("unrelated"))?, b"still syncing");
        if modified {
            let mut saved = conflicts(&second)?;
            saved.sort();
            assert_eq!(saved, vec![b"edited".to_vec(), b"untracked".to_vec()]);
        } else {
            assert_eq!(report.conflicts, 0);
        }
        assert_eq!(client::sync(&second_config).await?.uploaded, 0);
        // The reverse transition must work in the same sync, too.
        std::fs::remove_file(first.join("a"))?;
        std::fs::create_dir(first.join("a"))?;
        std::fs::write(first.join("a/b"), b"back to directory")?;
        client::sync(&first_config).await?;
        client::sync(&second_config).await?;
        assert_eq!(std::fs::read(second.join("a/b"))?, b"back to directory");
    }
    Ok(())
}

#[tokio::test]
async fn files_created_in_replaced_directory_during_download_survive() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let fixture = PausedDownload::new(temp.path(), "a", false).await?;
    std::fs::create_dir(fixture.root.join("a"))?;
    let report = fixture
        .run(|| Ok(std::fs::write(fixture.root.join("a/new"), b"late edit")?))
        .await?;
    assert_eq!(report.conflicts, 1);
    assert_eq!(std::fs::read(fixture.root.join("a"))?, b"remote winner");
    assert_eq!(conflicts(&fixture.root)?, vec![b"late edit".to_vec()]);
    Ok(())
}

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

struct TestServer {
    url: String,
    task: JoinHandle<()>,
}

impl TestServer {
    async fn start(router: Router) -> Result<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        Ok(Self {
            url: format!("http://{address}"),
            task,
        })
    }

    async fn sync_server(data: &Path) -> Result<(Self, String)> {
        let state = server::open(data)?;
        mysyncfiles::device_auth::allow_legacy_for_migration(&state)?;
        let key = server::add_device(&state, "test-device")?;
        Ok((Self::start(server::router(state)).await?, key))
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn config(server: &str, root: &Path) -> ClientConfig {
    ClientConfig {
        server: server.to_owned(),
        token: "test-device-key".into(),
        identity: None,
        root: root.to_path_buf(),
        auto_update: false,
        update_public_key: mysyncfiles::release::PUBLIC_KEY_HEX.trim().into(),
    }
}

// Block the first download at the server until the test has changed the local
// filesystem. No timing-dependent sleeps or client implementation hooks.
struct PausedDownload {
    _server: TestServer,
    root: PathBuf,
    config: PathBuf,
    started: Arc<Notify>,
    resume: Arc<Notify>,
}

impl PausedDownload {
    async fn new(base: &Path, path: &str, existing: bool) -> Result<Self> {
        let root = base.join("mirror");
        std::fs::create_dir_all(root.join(path).parent().unwrap())?;
        if existing {
            std::fs::write(root.join(path), b"original")?;
        }
        let remote = Entry {
            path: path.into(),
            revision: 2,
            sha256: Some(sha(b"remote winner")),
            size: Some(13),
            deleted: false,
        };
        let started = Arc::new(Notify::new());
        let resume = Arc::new(Notify::new());
        let first = Arc::new(AtomicBool::new(true));
        let router = Router::new()
            .route(
                "/v1/manifest",
                get(move || {
                    let entry = remote.clone();
                    async move {
                        Json(Manifest {
                            generation: 2,
                            entries: vec![entry],
                        })
                    }
                }),
            )
            .route(
                "/v1/file",
                get({
                    let started = started.clone();
                    let resume = resume.clone();
                    move || {
                        let started = started.clone();
                        let resume = resume.clone();
                        let first = first.clone();
                        async move {
                            if first.swap(false, Ordering::SeqCst) {
                                started.notify_one();
                                resume.notified().await;
                            }
                            "remote winner"
                        }
                    }
                }),
            );
        let server = TestServer::start(router).await?;
        let config_path = base.join("client.json");
        std::fs::write(
            &config_path,
            serde_json::to_vec(&config(&server.url, &root))?,
        )?;
        if existing {
            std::fs::write(
                config_path.with_extension("state.json"),
                serde_json::to_vec(&serde_json::json!({
                    "entries": {path: {"revision": 1, "sha256": sha(b"original")}}
                }))?,
            )?;
        }
        Ok(Self {
            _server: server,
            root,
            config: config_path,
            started,
            resume,
        })
    }

    async fn run<F>(&self, during_download: F) -> Result<client::SyncReport>
    where
        F: FnOnce() -> Result<()>,
    {
        // Poll both futures together so a failed sync cannot leave a detached
        // task running against a directory already dropped by the test.
        let mutation = async {
            tokio::time::timeout(Duration::from_secs(5), self.started.notified()).await?;
            let result = during_download();
            self.resume.notify_one();
            result
        };
        let (report, mutation) = tokio::join!(
            tokio::time::timeout(Duration::from_secs(10), client::sync(&self.config)),
            mutation,
        );
        mutation?;
        report?
    }
}

fn conflicts(root: &Path) -> Result<Vec<Vec<u8>>> {
    let mut contents = Vec::new();
    for entry in walkdir::WalkDir::new(root.join(".mysync-conflicts")) {
        let entry = entry?;
        if entry.file_type().is_file() {
            contents.push(std::fs::read(entry.path())?);
        }
    }
    Ok(contents)
}

#[tokio::test]
async fn modification_during_download_is_preserved_as_conflict() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let fixture = PausedDownload::new(temp.path(), "docs/file.txt", true).await?;
    let report = fixture
        .run(|| {
            Ok(std::fs::write(
                fixture.root.join("docs/file.txt"),
                b"edited during download",
            )?)
        })
        .await?;
    assert_eq!(report.conflicts, 1);
    assert_eq!(
        std::fs::read(fixture.root.join("docs/file.txt"))?,
        b"remote winner"
    );
    assert_eq!(
        conflicts(&fixture.root)?,
        vec![b"edited during download".to_vec()]
    );
    assert_eq!(client::sync(&fixture.config).await?.conflicts, 0);
    assert_eq!(
        conflicts(&fixture.root)?,
        vec![b"edited during download".to_vec()]
    );
    Ok(())
}

#[tokio::test]
async fn file_created_during_download_is_preserved() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let fixture = PausedDownload::new(temp.path(), "file.txt", false).await?;
    let report = fixture
        .run(|| {
            Ok(std::fs::write(
                fixture.root.join("file.txt"),
                b"created during download",
            )?)
        })
        .await?;
    assert_eq!(report.conflicts, 1);
    assert_eq!(
        conflicts(&fixture.root)?,
        vec![b"created during download".to_vec()]
    );
    assert_eq!(
        std::fs::read(fixture.root.join("file.txt"))?,
        b"remote winner"
    );
    Ok(())
}

#[tokio::test]
async fn deletion_during_download_is_reconciled_on_a_fresh_pass() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let fixture = PausedDownload::new(temp.path(), "file.txt", true).await?;
    let report = fixture
        .run(|| Ok(std::fs::remove_file(fixture.root.join("file.txt"))?))
        .await?;
    assert_eq!(report.downloaded, 1);
    assert_eq!(
        std::fs::read(fixture.root.join("file.txt"))?,
        b"remote winner"
    );
    Ok(())
}

#[tokio::test]
async fn parent_symlink_swap_during_download_cannot_write_outside_mirror() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let fixture = PausedDownload::new(temp.path(), "docs/file.txt", true).await?;
    let outside = temp.path().join("outside");
    std::fs::create_dir(&outside)?;
    std::fs::write(outside.join("file.txt"), b"outside sentinel")?;
    let result = fixture
        .run(|| {
            std::fs::rename(
                fixture.root.join("docs"),
                fixture.root.join("docs-original"),
            )?;
            std::os::unix::fs::symlink(&outside, fixture.root.join("docs"))?;
            Ok(())
        })
        .await;
    assert!(result.is_err());
    assert_eq!(
        std::fs::read(outside.join("file.txt"))?,
        b"outside sentinel"
    );
    assert_eq!(
        std::fs::read(fixture.root.join("docs-original/file.txt"))?,
        b"original"
    );
    assert_eq!(std::fs::read_dir(&outside)?.count(), 1);
    Ok(())
}

#[tokio::test]
async fn staging_symlink_swap_cannot_redirect_download_writes() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let fixture = PausedDownload::new(temp.path(), "file.txt", false).await?;
    let outside = temp.path().join("outside");
    std::fs::create_dir(&outside)?;
    std::fs::write(outside.join("sentinel"), b"untouched")?;
    fixture
        .run(|| {
            std::fs::rename(
                fixture.root.join(".mysync-staging"),
                fixture.root.join("old-staging"),
            )?;
            std::os::unix::fs::symlink(&outside, fixture.root.join(".mysync-staging"))?;
            Ok(())
        })
        .await?;
    assert_eq!(std::fs::read_dir(&outside)?.count(), 1);
    assert_eq!(std::fs::read(outside.join("sentinel"))?, b"untouched");
    assert_eq!(
        std::fs::read(fixture.root.join("file.txt"))?,
        b"remote winner"
    );
    Ok(())
}

#[tokio::test]
async fn conflict_symlink_swap_cannot_move_local_data_outside_mirror() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let fixture = PausedDownload::new(temp.path(), "docs/file.txt", true).await?;
    let outside = temp.path().join("outside");
    std::fs::create_dir(&outside)?;
    std::fs::create_dir_all(fixture.root.join(".mysync-conflicts/docs"))?;
    let result = fixture
        .run(|| {
            std::fs::write(fixture.root.join("docs/file.txt"), b"local edit")?;
            std::fs::rename(
                fixture.root.join(".mysync-conflicts/docs"),
                fixture.root.join("conflicts-original"),
            )?;
            std::os::unix::fs::symlink(&outside, fixture.root.join(".mysync-conflicts/docs"))?;
            Ok(())
        })
        .await;
    assert!(result.is_err());
    assert_eq!(std::fs::read_dir(&outside)?.count(), 0);
    assert_eq!(
        std::fs::read(fixture.root.join("docs/file.txt"))?,
        b"local edit"
    );
    Ok(())
}

#[tokio::test]
async fn maximum_length_filename_can_still_have_a_conflict_copy() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let name = format!("{}a", "é".repeat(127)); // 255 bytes, not 255 characters.
    let fixture = PausedDownload::new(temp.path(), &name, true).await?;
    assert_eq!(
        fixture
            .run(|| Ok(std::fs::write(fixture.root.join(&name), b"edit")?))
            .await?
            .conflicts,
        1
    );
    assert_eq!(conflicts(&fixture.root)?, vec![b"edit".to_vec()]);
    Ok(())
}

#[tokio::test]
async fn api_and_updater_never_follow_redirects() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let hits = Arc::new(AtomicUsize::new(0));
    let destination = TestServer::start(Router::new().fallback({
        let hits = hits.clone();
        move || {
            hits.fetch_add(1, Ordering::SeqCst);
            async {
                Json(Manifest {
                    generation: 0,
                    entries: vec![],
                })
            }
        }
    }))
    .await?;
    // Same-origin redirects also retain Authorization in reqwest. Exercise one
    // as well as a redirect to a different port.
    for same_origin in [false, true] {
        let redirect_target = destination.url.clone();
        let router = Router::new()
            .route(
                "/capture",
                get({
                    let hits = hits.clone();
                    move || {
                        hits.fetch_add(1, Ordering::SeqCst);
                        async {
                            Json(Manifest {
                                generation: 0,
                                entries: vec![],
                            })
                        }
                    }
                }),
            )
            .fallback(move || {
                let target = if same_origin {
                    "/capture".to_owned()
                } else {
                    redirect_target.clone()
                };
                async move { Redirect::temporary(&target) }
            });
        let source = TestServer::start(router).await?;
        let config = config(&source.url, temp.path());
        assert!(client::Api::new(&config)?.manifest().await.is_err());
        let installed = temp.path().join("mysync");
        std::fs::write(&installed, b"original binary")?;
        assert!(
            update::check_and_install_at(&config, &installed, "0.1.0")
                .await
                .is_err()
        );
        assert_eq!(std::fs::read(&installed)?, b"original binary");
    }
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    assert!(client::Api::new(&config("http://example.invalid", temp.path())).is_err());
    Ok(())
}

async fn put(
    http: &Client,
    server: &TestServer,
    key: &str,
    path: &str,
    base: i64,
) -> Result<reqwest::Response> {
    Ok(http
        .put(format!("{}/v1/file", server.url))
        .bearer_auth(key)
        .query(&[("path", path), ("base_revision", &base.to_string())])
        .body("content")
        .send()
        .await?)
}

async fn remove(http: &Client, server: &TestServer, key: &str, entry: &Entry) -> Result<()> {
    http.delete(format!("{}/v1/file", server.url))
        .bearer_auth(key)
        .query(&[
            ("path", entry.path.as_str()),
            ("base_revision", &entry.revision.to_string()),
        ])
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

#[tokio::test]
async fn uploads_reject_ancestors_and_descendants_in_both_orders() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let (server, key) = TestServer::sync_server(temp.path()).await?;
    let http = Client::new();
    for (first, second) in [("a", "a/b"), ("c/d", "c")] {
        assert_eq!(
            put(&http, &server, &key, first, 0).await?.status(),
            StatusCode::OK
        );
        assert_eq!(
            put(&http, &server, &key, second, 0).await?.status(),
            StatusCode::CONFLICT
        );
    }
    // Neither SQL wildcards nor differently cased names are ancestors on Linux.
    for path in [
        "case/child",
        "Case",
        "a_b/child",
        "a%b",
        "literal%/child",
        "literal_",
    ] {
        assert_eq!(
            put(&http, &server, &key, path, 0).await?.status(),
            StatusCode::OK,
            "{path}"
        );
    }
    assert_eq!(
        put(&http, &server, &key, "literal%", 0).await?.status(),
        StatusCode::CONFLICT
    );
    Ok(())
}

#[tokio::test]
async fn concurrent_uploads_cannot_publish_a_file_and_its_descendant() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let (server, key) = TestServer::sync_server(temp.path()).await?;
    let http = Client::new();
    let (parent, child) = tokio::join!(
        put(&http, &server, &key, "a", 0),
        put(&http, &server, &key, "a/b", 0),
    );
    let mut statuses = [parent?.status().as_u16(), child?.status().as_u16()];
    statuses.sort();
    assert_eq!(statuses, [200, 409]);
    let manifest: Manifest = http
        .get(format!("{}/v1/manifest", server.url))
        .bearer_auth(&key)
        .send()
        .await?
        .json()
        .await?;
    assert_eq!(manifest.generation, 1);
    assert_eq!(manifest.entries.len(), 1);
    Ok(())
}

#[tokio::test]
async fn chunked_upload_rechecks_hierarchy_at_commit() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let (server, key) = TestServer::sync_server(temp.path()).await?;
    let http = Client::new();
    for (pending, other) in [("a/b", "a"), ("c", "c/d")] {
        let progress: UploadProgress = http
            .post(format!("{}/v1/uploads", server.url))
            .bearer_auth(&key)
            .json(&BeginUpload {
                path: pending.into(),
                base_revision: 0,
                size: 1,
                sha256: sha(b"x"),
            })
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        http.put(format!("{}/v1/uploads/{}", server.url, progress.id))
            .bearer_auth(&key)
            .query(&[("offset", 0)])
            .body("x")
            .send()
            .await?
            .error_for_status()?;
        assert_eq!(
            put(&http, &server, &key, other, 0).await?.status(),
            StatusCode::OK
        );
        let response = http
            .post(format!("{}/v1/uploads/{}/commit", server.url, progress.id))
            .bearer_auth(&key)
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }
    Ok(())
}

#[tokio::test]
async fn restore_rejects_collisions_but_allows_deleted_ancestors_and_descendants() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let (server, key) = TestServer::sync_server(temp.path()).await?;
    let http = Client::new();
    for (original, blocking) in [("a", "a/b"), ("c/d", "c")] {
        let entry: Entry = put(&http, &server, &key, original, 0)
            .await?
            .error_for_status()?
            .json()
            .await?;
        remove(&http, &server, &key, &entry).await?;
        let blocker: Entry = put(&http, &server, &key, blocking, 0)
            .await?
            .error_for_status()?
            .json()
            .await?;
        let trash: Vec<TrashItem> = http
            .get(format!("{}/v1/trash", server.url))
            .bearer_auth(&key)
            .send()
            .await?
            .json()
            .await?;
        let id = trash.iter().find(|item| item.path == original).unwrap().id;
        let response = http
            .post(format!("{}/v1/trash/restore", server.url))
            .bearer_auth(&key)
            .json(&RestoreRequest { id })
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        remove(&http, &server, &key, &blocker).await?;
        http.post(format!("{}/v1/trash/restore", server.url))
            .bearer_auth(&key)
            .json(&RestoreRequest { id })
            .send()
            .await?
            .error_for_status()?;
    }
    Ok(())
}

#[tokio::test]
async fn path_component_limits_are_measured_in_bytes_at_all_ingress_points() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let (server, key) = TestServer::sync_server(temp.path()).await?;
    let http = Client::new();
    for path in [
        "a".repeat(256),
        "é".repeat(128),
        format!("dir/{}/file", "x".repeat(256)),
    ] {
        assert!(!valid_path(&path));
        assert_eq!(
            put(&http, &server, &key, &path, 0).await?.status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            http.post(format!("{}/v1/uploads", server.url))
                .bearer_auth(&key)
                .json(&BeginUpload {
                    path,
                    base_revision: 0,
                    size: 1,
                    sha256: sha(b"x")
                })
                .send()
                .await?
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    for path in ["a".repeat(255), format!("{}b", "é".repeat(127))] {
        assert!(valid_path(&path));
        assert_eq!(
            put(&http, &server, &key, &path, 0).await?.status(),
            StatusCode::OK
        );
    }
    // Old trash may predate the validation change. Restoration must validate it.
    let entry: Entry = put(&http, &server, &key, "old", 0).await?.json().await?;
    remove(&http, &server, &key, &entry).await?;
    let db = rusqlite::Connection::open(temp.path().join("metadata.sqlite3"))?;
    db.execute("UPDATE trash SET path = ?1", ["a".repeat(256)])?;
    let id: i64 = db.query_row("SELECT id FROM trash", [], |row| row.get(0))?;
    assert_eq!(
        http.post(format!("{}/v1/trash/restore", server.url))
            .bearer_auth(&key)
            .json(&RestoreRequest { id })
            .send()
            .await?
            .status(),
        StatusCode::BAD_REQUEST
    );
    Ok(())
}
