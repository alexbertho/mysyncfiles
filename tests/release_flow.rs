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
    std::fs::write(path, format!("#!/bin/sh\nprintf 'mysync {version}\\n'\n"))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
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
            server: format!("http://{}", listener.local_addr()?),
            token: "test".into(),
            identity: None,
            root: temp.path().into(),
            auto_update: true,
            update_public_key: public.clone(),
        });
        tasks.push(tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap()
        }));
    }
    let newer = async {
        tokio::time::timeout(Duration::from_secs(3), started.notified()).await?;
        let result = update::check_and_install_at(&configs[1], &installed, "0.1.0").await;
        resume.notify_one();
        result
    };
    let (old, new) = tokio::join!(
        update::check_and_install_at(&configs[0], &installed, "0.1.0"),
        newer
    );
    assert_eq!(new?, UpdateOutcome::Installed("0.3.0".into()));
    assert_eq!(old?, UpdateOutcome::Current);
    assert!(std::fs::read_to_string(&installed)?.contains("0.3.0"));
    // Also cover a stale daemon that starts its check after the newer install.
    assert_eq!(
        update::check_and_install_at(&configs[0], &installed, "0.1.0").await?,
        UpdateOutcome::Current
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
                "#!/bin/sh\ncase \"$0\" in\n*/source-mysync) printf 'mysync {version}\\n';;\n*) {incompatible};;\nesac\n"
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
            server: format!("http://{address}"),
            token: "test-key".into(),
            identity: None,
            root: temp.path().into(),
            auto_update: true,
            update_public_key: public_key,
        };
        assert!(
            update::check_and_install_at(&config, &installed, "0.1.0")
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
    std::fs::write(
        &binary,
        format!("#!/bin/sh\nprintf 'mysync {version}\\n'\n"),
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700))?;
    }
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
    executable(&installed, "0.1.0")?;
    let config = ClientConfig {
        server: format!("http://{address}"),
        token: "test-key".into(),
        identity: None,
        root: temp.path().to_path_buf(),
        auto_update: true,
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
        update::check_and_install_at(&config, &installed, "0.1.0")
            .await
            .is_err()
    );
    assert_eq!(std::fs::read(&installed)?, previous);
    fs2::FileExt::unlock(&lock)?;
    assert_eq!(
        update::check_and_install_at(&config, &installed, "0.1.0").await?,
        UpdateOutcome::Installed(version.into())
    );
    assert_eq!(std::fs::read(&installed)?, std::fs::read(&binary)?);
    assert_eq!(
        update::check_and_install_at(&config, &installed, version).await?,
        UpdateOutcome::Current
    );
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
    std::fs::write(
        &binary,
        format!("#!/bin/sh\nprintf 'mysync {version}\\n'\n"),
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700))?;
    }
    let target = release::current_target().unwrap();
    let releases = temp.path().join("releases");
    release::publish(&signing_key, &binary, version, target, &releases)?;
    let signature_path = releases.join(target).join("latest.sig");
    let valid_signature = std::fs::read(&signature_path)?;
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
        server: format!("http://{address}"),
        token: "test-key".into(),
        identity: None,
        root: temp.path().to_path_buf(),
        auto_update: true,
        update_public_key: public_key,
    };
    assert!(
        update::check_and_install_at(&config, &installed, "0.1.0")
            .await
            .is_err()
    );
    assert_eq!(std::fs::read(&installed)?, b"old binary");
    std::fs::write(&signature_path, valid_signature)?;
    let mut corrupted = std::fs::read(&artifact_path)?;
    corrupted[0] ^= 1;
    std::fs::write(&artifact_path, corrupted)?;
    assert!(
        update::check_and_install_at(&config, &installed, "0.1.0")
            .await
            .is_err()
    );
    assert_eq!(std::fs::read(&installed)?, b"old binary");
    task.abort();
    Ok(())
}
