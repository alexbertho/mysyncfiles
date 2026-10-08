use anyhow::Result;
use mysyncfiles::{
    client::ClientConfig,
    release, server,
    update::{self, UpdateOutcome},
};
use std::{
    os::unix::fs::PermissionsExt,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

fn executable(path: &Path, version: &str) -> Result<()> {
    std::fs::write(
        path,
        format!(
            "#!/bin/sh\ncase \"$1:$2\" in\n  --version:) printf 'mysync {version}\\n';;\n  setup:--help) exit 0;;\n  *) exit 1;;\nesac\n"
        ),
    )?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[test]
fn publishing_rejects_a_client_without_setup() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let signing_key = temp.path().join("signing.key");
    release::generate_key(&signing_key)?;
    let binary = temp.path().join("source-mysync");
    std::fs::write(
        &binary,
        "#!/bin/sh\ncase \"$1\" in --version) echo 'mysync 0.3.3';; *) exit 2;; esac\n",
    )?;
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700))?;
    let releases = temp.path().join("releases");
    let error = release::publish(
        &signing_key,
        &binary,
        "0.3.3",
        release::current_target().unwrap(),
        &releases,
    )
    .unwrap_err();
    assert!(error.to_string().contains("setup command"), "{error}");
    assert!(!releases.exists());
    Ok(())
}

#[test]
fn publishing_requires_a_new_version_for_a_changed_binary() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let key = temp.path().join("signing.key");
    release::generate_key(&key)?;
    let binary = temp.path().join("mysync");
    executable(&binary, "0.3.6")?;
    let releases = temp.path().join("releases");
    let target = release::current_target().unwrap();
    let manifest = release::publish(&key, &binary, "0.3.6", target, &releases)?;
    let envelope = releases.join(target).join("latest.signed.json");
    let previous = std::fs::read(&envelope)?;
    let original_binary = std::fs::read(&binary)?;
    let mut changed = original_binary.clone();
    changed.extend_from_slice(b"\n# new client behavior\n");
    std::fs::write(&binary, changed)?;
    let error = release::publish(&key, &binary, "0.3.6", target, &releases).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("newer than the published version")
    );
    assert_eq!(std::fs::read(envelope)?, previous);
    assert_eq!(
        std::fs::read(releases.join(target).join(manifest.artifact))?,
        original_binary
    );
    Ok(())
}

#[tokio::test]
async fn installer_is_served_from_the_image_only_after_public_url_configuration() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let data = temp.path().join("data");
    let state = server::open(&data)?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}/install.sh", listener.local_addr()?);
    let task =
        tokio::spawn(async move { axum::serve(listener, server::router(state)).await.unwrap() });
    let http = reqwest::Client::new();
    assert_eq!(
        http.get(&url).send().await?.status(),
        reqwest::StatusCode::SERVICE_UNAVAILABLE
    );
    rusqlite::Connection::open(data.join("metadata.sqlite3"))?.execute(
        "INSERT INTO auth_settings(key, value) VALUES('public_url', ?1)",
        ["https://sync.example.test"],
    )?;
    let response = http.get(&url).send().await?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let script = response.text().await?;
    assert!(script.contains("SERVER_URL='https://sync.example.test'"));
    assert!(script.contains(release::PUBLIC_KEY_HEX.trim()));
    assert!(script.contains("ExecStart=%h/.local/bin/mysync daemon"));
    assert!(!script.contains("@MYSYNC_"));
    task.abort();
    Ok(())
}

#[tokio::test]
async fn releases_refuse_symlinks_even_during_atomic_parent_and_leaf_swaps() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let releases = temp.path().join("releases");
    let target = release::current_target().unwrap();
    std::fs::create_dir_all(releases.join(target))?;
    std::fs::write(releases.join(target).join("latest.json"), b"public")?;
    let private = temp.path().join("private");
    std::fs::create_dir(&private)?;
    std::fs::write(private.join("latest.json"), b"private sentinel")?;
    let state = server::open_with_releases(temp.path().join("data"), Some(releases.clone()))?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let url = format!(
        "http://{}/v1/updates/{target}/latest.json",
        listener.local_addr()?
    );
    let task =
        tokio::spawn(async move { axum::serve(listener, server::router(state)).await.unwrap() });
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()?;
    for parent in [false, true] {
        let (directory, name) = if parent {
            (releases.clone(), target)
        } else {
            (releases.join(target), "latest.json")
        };
        let link = directory.join("swap");
        std::os::unix::fs::symlink(
            if parent {
                private.clone()
            } else {
                private.join("latest.json")
            },
            &link,
        )?;
        let dir = std::fs::File::open(&directory)?;
        let swap = || {
            rustix::fs::renameat_with(&dir, name, &dir, "swap", rustix::fs::RenameFlags::EXCHANGE)
        };
        swap()?;
        assert_eq!(
            http.get(&url).send().await?.status(),
            reqwest::StatusCode::NOT_FOUND
        );
        swap()?;
        let running = Arc::new(AtomicBool::new(true));
        let running_thread = running.clone();
        let swaps = std::thread::spawn(move || {
            while running_thread.load(Ordering::Relaxed) {
                rustix::fs::renameat_with(
                    &dir,
                    name,
                    &dir,
                    "swap",
                    rustix::fs::RenameFlags::EXCHANGE,
                )
                .unwrap();
            }
        });
        let result: Result<()> = async {
            for _ in 0..200 {
                let response = http.get(&url).send().await?;
                if response.status().is_success() {
                    assert_eq!(response.bytes().await?.as_ref(), b"public");
                } else {
                    assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
                }
            }
            Ok(())
        }
        .await;
        running.store(false, Ordering::Relaxed);
        swaps.join().unwrap();
        result?;
        // Put the ordinary file/directory back for the next case.
        if std::fs::symlink_metadata(directory.join(name))?
            .file_type()
            .is_symlink()
        {
            let dir = std::fs::File::open(&directory)?;
            rustix::fs::renameat_with(&dir, name, &dir, "swap", rustix::fs::RenameFlags::EXCHANGE)?;
        }
        std::fs::remove_file(link)?;
    }
    // The configured release root is itself pinned for the server's lifetime.
    std::fs::rename(&releases, temp.path().join("original-releases"))?;
    std::os::unix::fs::symlink(&private, &releases)?;
    assert_eq!(
        http.get(&url).send().await?.bytes().await?.as_ref(),
        b"public"
    );
    task.abort();
    Ok(())
}

#[tokio::test]
async fn delayed_older_signed_update_cannot_replace_a_newer_installation() -> Result<()> {
    use axum::{Router, routing::get};
    let temp = tempfile::tempdir()?;
    let key = temp.path().join("key");
    let public = release::generate_key(&key)?;
    let target = release::current_target().unwrap();
    let installed = temp.path().join("mysync");
    executable(&installed, "0.1.0")?;
    let started = Arc::new(tokio::sync::Notify::new());
    let resume = Arc::new(tokio::sync::Notify::new());
    let mut configs = Vec::new();
    let mut tasks = Vec::new();
    for version in ["0.2.0", "0.3.0"] {
        let binary = temp.path().join(format!("source-{version}"));
        executable(&binary, version)?;
        let root = temp.path().join(version);
        let manifest = release::publish(&key, &binary, version, target, &root)?;
        let bytes = std::fs::read(root.join(target).join("latest.json"))?;
        let sig = std::fs::read(root.join(target).join("latest.sig"))?;
        let artifact = std::fs::read(&binary)?;
        let first = Arc::new(AtomicBool::new(true));
        let router = Router::new()
            .route(
                &format!("/v1/updates/{target}/latest.json"),
                get(move || {
                    let b = bytes.clone();
                    async move { b }
                }),
            )
            .route(
                &format!("/v1/updates/{target}/latest.sig"),
                get(move || {
                    let b = sig.clone();
                    async move { b }
                }),
            )
            .route(
                &format!("/v1/updates/{target}/{}", manifest.artifact),
                get({
                    let started = started.clone();
                    let resume = resume.clone();
                    move || {
                        let (started, resume, b, first) = (
                            started.clone(),
                            resume.clone(),
                            artifact.clone(),
                            first.clone(),
                        );
                        async move {
                            if version == "0.2.0" && first.swap(false, Ordering::SeqCst) {
                                started.notify_one();
                                resume.notified().await;
                            }
                            b
                        }
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        configs.push(ClientConfig {
            server_public_key: String::new(),
            server: format!("http://{}", listener.local_addr()?),
            identity: None,
            root: temp.path().into(),
            auto_update: true,
            web_status_enabled: false,
            web_files_enabled: false,
            web_uploads_enabled: false,
            web_management_enabled: false,
            web_edit_enabled: false,
            web_run_enabled: false,
            update_public_key: public.clone(),
        });
        tasks.push(tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap()
        }));
    }
    let newer = async {
        tokio::time::timeout(Duration::from_secs(10), started.notified()).await?;
        let result = update::check_and_install_at(
            &configs[1].server,
            &configs[1].update_public_key,
            &installed,
            "0.1.0",
        )
        .await;
        resume.notify_one();
        result
    };
    let (old, new) = tokio::join!(
        update::check_and_install_at(
            &configs[0].server,
            &configs[0].update_public_key,
            &installed,
            "0.1.0"
        ),
        newer
    );
    assert_eq!(new?, UpdateOutcome::Installed("0.3.0".into()));
    let current = UpdateOutcome::Current {
        installed_version: "0.3.0".into(),
        published_version: "0.2.0".into(),
    };
    assert_eq!(old?, current);
    assert!(std::fs::read_to_string(&installed)?.contains("0.3.0"));
    // Also cover a stale daemon that starts its check after the newer install.
    assert_eq!(
        update::check_and_install_at(
            &configs[0].server,
            &configs[0].update_public_key,
            &installed,
            "0.1.0"
        )
        .await?,
        current
    );
    for task in tasks {
        task.abort();
    }
    Ok(())
}

#[tokio::test]
async fn update_keeps_installed_client_when_signed_candidate_cannot_run() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    for incompatible in ["exit 127", "printf 'mysync 0.0.0\\n'"] {
        let temp = tempfile::tempdir()?;
        let key = temp.path().join("key");
        let public_key = release::generate_key(&key)?;
        let binary = temp.path().join("source-mysync");
        let version = env!("CARGO_PKG_VERSION");
        // Publication host succeeds; installation host cannot execute the same
        // signed candidate (or sees a mismatched version).
        std::fs::write(
            &binary,
            format!(
                "#!/bin/sh\ncase \"$0:$1:$2\" in\n*/source-mysync:--version:) printf 'mysync {version}\\n';;\n*/source-mysync:setup:--help) exit 0;;\n*) {incompatible};;\nesac\n"
            ),
        )?;
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700))?;
        let releases = temp.path().join("releases");
        release::publish(
            &key,
            &binary,
            version,
            release::current_target().unwrap(),
            &releases,
        )?;
        let state = server::open_with_releases(temp.path().join("data"), Some(releases))?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let task =
            tokio::spawn(
                async move { axum::serve(listener, server::router(state)).await.unwrap() },
            );
        let installed = temp.path().join("mysync");
        std::fs::write(&installed, "old binary")?;
        let config = ClientConfig {
            server_public_key: String::new(),
            server: format!("http://{address}"),
            identity: None,
            root: temp.path().into(),
            auto_update: true,
            web_status_enabled: false,
            web_files_enabled: false,
            web_uploads_enabled: false,
            web_management_enabled: false,
            web_edit_enabled: false,
            web_run_enabled: false,
            update_public_key: public_key,
        };
        assert!(
            update::check_and_install_at(
                &config.server,
                &config.update_public_key,
                &installed,
                "0.1.0"
            )
            .await
            .is_err()
        );
        assert_eq!(std::fs::read(&installed)?, b"old binary");
        assert!(!std::fs::read_dir(temp.path())?.any(|e| {
            e.unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".mysync-update-")
        }));
        task.abort();
    }
    Ok(())
}

#[tokio::test]
async fn signed_release_is_served_and_installed_atomically() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let signing_key = temp.path().join("signing.key");
    let public_key = release::generate_key(&signing_key)?;
    let binary = temp.path().join("source-mysync");
    let version = env!("CARGO_PKG_VERSION");
    executable(&binary, version)?;
    let target = release::current_target().unwrap();
    let releases = temp.path().join("releases");
    let manifest = release::publish(&signing_key, &binary, version, target, &releases)?;
    let manifest_bytes = std::fs::read(releases.join(target).join("latest.json"))?;
    let signature = std::fs::read_to_string(releases.join(target).join("latest.sig"))?;
    let verified = release::verify_manifest(&manifest_bytes, &signature, &public_key)?;
    assert_eq!(verified.sha256, manifest.sha256);
    let mut tampered = manifest_bytes.clone();
    tampered[0] ^= 1;
    assert!(release::verify_manifest(&tampered, &signature, &public_key).is_err());

    let state = server::open_with_releases(temp.path().join("data"), Some(releases))?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let task = tokio::spawn(async move {
        axum::serve(listener, server::router(state)).await.unwrap();
    });
    let installed = temp.path().join("mysync");
    executable(&installed, "0.3.6")?;
    let config = ClientConfig {
        server_public_key: String::new(),
        server: format!("http://{address}"),
        identity: None,
        root: temp.path().to_path_buf(),
        auto_update: true,
        web_status_enabled: false,
        web_files_enabled: false,
        web_uploads_enabled: false,
        web_management_enabled: false,
        web_edit_enabled: false,
        web_run_enabled: false,
        update_public_key: public_key,
    };
    let response =
        reqwest::get(format!("{}/v1/updates/{target}/latest.json", config.server)).await?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    // An independently opened lock is shared by every updater process.
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(temp.path().join(".mysync-update.lock"))?;
    fs2::FileExt::lock_exclusive(&lock)?;
    let previous = std::fs::read(&installed)?;
    assert!(
        update::check_and_install_at(
            &config.server,
            &config.update_public_key,
            &installed,
            "0.3.6"
        )
        .await
        .is_err()
    );
    assert_eq!(std::fs::read(&installed)?, previous);
    fs2::FileExt::unlock(&lock)?;
    assert_eq!(
        update::check_and_install_at(
            &config.server,
            &config.update_public_key,
            &installed,
            "0.3.6"
        )
        .await?,
        UpdateOutcome::Installed(version.into())
    );
    assert_eq!(std::fs::read(&installed)?, std::fs::read(&binary)?);
    assert_eq!(
        update::check_and_install_at(
            &config.server,
            &config.update_public_key,
            &installed,
            version
        )
        .await?,
        UpdateOutcome::Current {
            installed_version: version.into(),
            published_version: version.into(),
        }
    );
    task.abort();
    Ok(())
}

#[tokio::test]
async fn update_reports_the_actual_published_version_without_replacing_current_clients()
-> Result<()> {
    let temp = tempfile::tempdir()?;
    let key = temp.path().join("signing.key");
    let public_key = release::generate_key(&key)?;
    let binary = temp.path().join("source-mysync");
    executable(&binary, "0.3.6")?;
    let target = release::current_target().unwrap();
    let releases = temp.path().join("releases");
    let manifest = release::publish(&key, &binary, "0.3.6", target, &releases)?;
    // Reproduce an existing deployment with legacy signed metadata. Neither an
    // equal nor a newer installed client should try to download the artifact.
    std::fs::remove_file(releases.join(target).join("latest.signed.json"))?;
    std::fs::remove_file(releases.join(target).join(manifest.artifact))?;
    let state = server::open_with_releases(temp.path().join("data"), Some(releases))?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let server_url = format!("http://{}", listener.local_addr()?);
    let task = tokio::spawn(async move {
        axum::serve(listener, server::router(state)).await.unwrap();
    });
    let installed = temp.path().join("mysync");
    for version in ["0.3.6", env!("CARGO_PKG_VERSION")] {
        executable(&installed, version)?;
        let previous = std::fs::read(&installed)?;
        assert_eq!(
            update::check_and_install_at(&server_url, &public_key, &installed, version).await?,
            UpdateOutcome::Current {
                installed_version: version.into(),
                published_version: "0.3.6".into(),
            }
        );
        assert_eq!(std::fs::read(&installed)?, previous);
    }
    // Exercise the real CLI in its supported installation location, using an
    // isolated HOME and profile. It must distinguish source/server deployment
    // from the signed release currently offered to this client.
    let home = temp.path().join("home");
    let bin_dir = home.join(".local/bin");
    std::fs::create_dir_all(&bin_dir)?;
    std::fs::set_permissions(&bin_dir, std::fs::Permissions::from_mode(0o700))?;
    let cli = bin_dir.join("mysync");
    std::fs::copy(env!("CARGO_BIN_EXE_mysync"), &cli)?;
    let config = ClientConfig {
        server: server_url,
        server_public_key: String::new(),
        identity: None,
        root: temp.path().into(),
        auto_update: true,
        web_status_enabled: false,
        web_files_enabled: false,
        web_uploads_enabled: false,
        web_management_enabled: false,
        web_edit_enabled: false,
        web_run_enabled: false,
        update_public_key: public_key,
    };
    let config_path = temp.path().join("config.json");
    let config_bytes = serde_json::to_vec(&config)?;
    std::fs::write(&config_path, &config_bytes)?;
    let output = tokio::process::Command::new(&cli)
        .env("HOME", &home)
        .args(["--config", config_path.to_str().unwrap(), "update"])
        .output()
        .await?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let message = String::from_utf8(output.stdout)?;
    assert!(message.contains(&format!("installed client: {}", env!("CARGO_PKG_VERSION"))));
    assert!(message.contains("latest signed release: 0.3.6; no update installed"));
    assert_eq!(std::fs::read(config_path)?, config_bytes);
    task.abort();
    Ok(())
}

#[tokio::test]
async fn update_rejects_unsigned_metadata() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let signing_key = temp.path().join("signing.key");
    let public_key = release::generate_key(&signing_key)?;
    let binary = temp.path().join("source-mysync");
    let version = env!("CARGO_PKG_VERSION");
    executable(&binary, version)?;
    let target = release::current_target().unwrap();
    let releases = temp.path().join("releases");
    release::publish(&signing_key, &binary, version, target, &releases)?;
    let envelope_path = releases.join(target).join("latest.signed.json");
    let mut invalid_envelope: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&envelope_path)?)?;
    invalid_envelope["signature"] = serde_json::Value::String("00".repeat(64));
    std::fs::write(&envelope_path, serde_json::to_vec(&invalid_envelope)?)?;
    let signature_path = releases.join(target).join("latest.sig");
    let valid_signature = std::fs::read(&signature_path)?;
    let state = server::open_with_releases(temp.path().join("data"), Some(releases.clone()))?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let task = tokio::spawn(async move {
        axum::serve(listener, server::router(state)).await.unwrap();
    });
    let installed = temp.path().join("mysync");
    std::fs::write(&installed, "old binary")?;
    let server_url = format!("http://{address}");
    assert!(
        update::check_and_install_at(&server_url, &public_key, &installed, "0.1.0")
            .await
            .is_err()
    );
    assert_eq!(std::fs::read(&installed)?, b"old binary");
    task.abort();

    // Legacy fallback is accepted only after the envelope is absent.
    std::fs::remove_file(&envelope_path)?;
    // Exercise the legacy fallback explicitly; a present envelope has priority
    // and must not be bypassed by a damaged legacy signature.
    std::fs::write(&signature_path, "bad signature\n")?;
    let artifact_path = releases
        .join(target)
        .join(format!("mysync-{version}-{target}"));
    let state = server::open_with_releases(temp.path().join("data"), Some(releases))?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let task = tokio::spawn(async move {
        axum::serve(listener, server::router(state)).await.unwrap();
    });
    let installed = temp.path().join("mysync");
    std::fs::write(&installed, "old binary")?;
    let config = ClientConfig {
        server_public_key: String::new(),
        server: format!("http://{address}"),
        identity: None,
        root: temp.path().to_path_buf(),
        auto_update: true,
        web_status_enabled: false,
        web_files_enabled: false,
        web_uploads_enabled: false,
        web_management_enabled: false,
        web_edit_enabled: false,
        web_run_enabled: false,
        update_public_key: public_key,
    };
    assert!(
        update::check_and_install_at(
            &config.server,
            &config.update_public_key,
            &installed,
            "0.1.0"
        )
        .await
        .is_err()
    );
    assert_eq!(std::fs::read(&installed)?, b"old binary");
    std::fs::write(&signature_path, valid_signature)?;
    let mut corrupted = std::fs::read(&artifact_path)?;
    corrupted[0] ^= 1;
    std::fs::write(&artifact_path, corrupted)?;
    assert!(
        update::check_and_install_at(
            &config.server,
            &config.update_public_key,
            &installed,
            "0.1.0"
        )
        .await
        .is_err()
    );
    assert_eq!(std::fs::read(&installed)?, b"old binary");
    task.abort();
    Ok(())
}
