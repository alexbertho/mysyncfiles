use std::{path::Path, time::Duration};

use anyhow::Result;
use mysyncfiles::{
    client,
    model::{BeginUpload, UPLOAD_CHUNK_BYTES, UploadProgress},
    server,
};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

async fn running_server(
    temp: &TempDir,
) -> Result<(String, String, String, tokio::task::JoinHandle<()>)> {
    let data = temp.path().join("server");
    let state = server::open(&data)?;
    mysyncfiles::device_auth::allow_legacy_for_migration(&state)?;
    let first = server::add_device(&state, "laptop")?;
    let second = server::add_device(&state, "desktop")?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let task = tokio::spawn(async move {
        axum::serve(listener, server::router(state)).await.unwrap();
    });
    Ok((format!("http://{address}"), first, second, task))
}

fn conflict_contents(root: &Path) -> Result<Vec<String>> {
    let mut contents = Vec::new();
    for entry in walkdir::WalkDir::new(root.join(".mysync-conflicts")) {
        let entry = entry?;
        if entry.file_type().is_file() {
            contents.push(std::fs::read_to_string(entry.path())?);
        }
    }
    Ok(contents)
}

#[tokio::test]
async fn two_devices_conflict_trash_restore_and_revoke() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let (url, first_key, second_key, task) = running_server(&temp).await?;
    let laptop = temp.path().join("laptop");
    let desktop = temp.path().join("desktop");
    let laptop_config = temp.path().join("laptop-config.json");
    let desktop_config = temp.path().join("desktop-config.json");
    std::fs::create_dir_all(laptop.join("docs"))?;
    std::fs::write(laptop.join("notes.txt"), "initial")?;
    std::fs::write(laptop.join("docs/item.txt"), "recoverable")?;

    client::configure(
        &laptop_config,
        url.clone(),
        first_key.clone(),
        laptop.clone(),
        true,
    )
    .await?;
    client::configure(
        &desktop_config,
        url.clone(),
        second_key,
        desktop.clone(),
        false,
    )
    .await?;
    assert_eq!(
        std::fs::read_to_string(desktop.join("notes.txt"))?,
        "initial"
    );
    assert_eq!(
        std::fs::read_to_string(desktop.join("docs/item.txt"))?,
        "recoverable"
    );

    std::fs::write(laptop.join("notes.txt"), "server winner")?;
    std::fs::write(desktop.join("notes.txt"), "local loser")?;
    client::sync(&laptop_config).await?;
    let report = client::sync(&desktop_config).await?;
    assert_eq!(report.conflicts, 1);
    assert_eq!(
        std::fs::read_to_string(desktop.join("notes.txt"))?,
        "server winner"
    );
    assert_eq!(conflict_contents(&desktop)?, vec!["local loser"]);

    std::fs::remove_file(laptop.join("docs/item.txt"))?;
    client::sync(&laptop_config).await?;
    client::sync(&desktop_config).await?;
    assert!(!desktop.join("docs/item.txt").exists());
    let api = client::Api::new(&client::load_config(&laptop_config)?)?;
    let trash = api.trash().await?;
    let item = trash
        .iter()
        .find(|item| item.path == "docs/item.txt")
        .unwrap();
    assert!(item.expires_at - item.deleted_at >= 30 * 24 * 60 * 60);
    api.restore(item.id).await?;
    client::sync(&laptop_config).await?;
    client::sync(&desktop_config).await?;
    assert_eq!(
        std::fs::read_to_string(desktop.join("docs/item.txt"))?,
        "recoverable"
    );

    let state = server::open(temp.path().join("server"))?;
    assert!(server::revoke_device(&state, "desktop")?);
    assert!(client::sync(&desktop_config).await.is_err());
    client::sync(&laptop_config).await?;
    task.abort();
    Ok(())
}

#[tokio::test]
async fn expired_trash_is_purged_and_invalid_paths_are_rejected() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let (url, key, _, task) = running_server(&temp).await?;
    let root = temp.path().join("files");
    let config = temp.path().join("config.json");
    std::fs::create_dir_all(&root)?;
    std::fs::write(root.join("remove.txt"), "trash me")?;
    client::configure(&config, url.clone(), key.clone(), root.clone(), true).await?;
    std::fs::create_dir_all(root.join(".mysync-staging"))?;
    std::fs::write(root.join(".mysync-staging/orphan"), "partial download")?;
    client::sync(&config).await?;
    assert!(!root.join(".mysync-staging/orphan").exists());
    assert!(
        client::Api::new(&client::load_config(&config)?)?
            .manifest()
            .await?
            .entries
            .iter()
            .all(|entry| !entry.path.contains(".mysync-staging"))
    );
    std::fs::remove_file(root.join("remove.txt"))?;
    client::sync(&config).await?;

    let db_path = temp.path().join("server/metadata.sqlite3");
    let db = rusqlite::Connection::open(db_path)?;
    let blob: String = db.query_row("SELECT blob FROM trash LIMIT 1", [], |row| row.get(0))?;
    db.execute("UPDATE trash SET expires_at = 1", [])?;
    let state = server::open(temp.path().join("server"))?;
    assert_eq!(server::purge_expired(&state)?, 1);
    assert!(!temp.path().join("server/blobs").join(blob).exists());
    assert!(
        client::Api::new(&client::load_config(&config)?)?
            .trash()
            .await?
            .is_empty()
    );

    std::fs::write(root.join("manual.txt"), "purge this")?;
    client::sync(&config).await?;
    std::fs::remove_file(root.join("manual.txt"))?;
    client::sync(&config).await?;
    let api = client::Api::new(&client::load_config(&config)?)?;
    let item = api.trash().await?.remove(0);
    let blob: String = db.query_row("SELECT blob FROM trash WHERE id = ?1", [item.id], |row| {
        row.get(0)
    })?;
    assert!(server::purge_trash_item(&state, item.id)?);
    assert!(!temp.path().join("server/blobs").join(blob).exists());
    assert!(api.trash().await?.is_empty());

    let response = reqwest::Client::new()
        .put(format!("{url}/v1/file"))
        .query(&[("path", "../escape"), ("base_revision", "0")])
        .bearer_auth(key)
        .body("bad")
        .timeout(Duration::from_secs(5))
        .send()
        .await?;
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    assert!(!temp.path().join("escape").exists());
    task.abort();
    Ok(())
}

#[tokio::test]
async fn daemon_watches_local_changes_and_polls_remote_changes() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let (url, first_key, second_key, server_task) = running_server(&temp).await?;
    let laptop = temp.path().join("laptop");
    let desktop = temp.path().join("desktop");
    let laptop_config = temp.path().join("laptop-config.json");
    let desktop_config = temp.path().join("desktop-config.json");
    client::configure(&laptop_config, url.clone(), first_key, laptop.clone(), true).await?;
    client::configure(&desktop_config, url, second_key, desktop.clone(), false).await?;

    let daemon_config = laptop_config.clone();
    let daemon_task = tokio::spawn(async move { client::daemon(&daemon_config).await });
    tokio::time::sleep(Duration::from_millis(500)).await;
    std::fs::write(laptop.join("live.txt"), "watch event")?;
    let desktop_api = client::Api::new(&client::load_config(&desktop_config)?)?;
    tokio::time::timeout(Duration::from_secs(7), async {
        loop {
            if desktop_api
                .manifest()
                .await?
                .entries
                .iter()
                .any(|entry| entry.path == "live.txt")
            {
                break Ok::<(), anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await??;
    client::sync(&desktop_config).await?;
    // Let file-watch notifications settle so the next update is found by polling.
    tokio::time::sleep(Duration::from_secs(2)).await;
    std::fs::write(desktop.join("live.txt"), "remote event")?;
    client::sync(&desktop_config).await?;
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if std::fs::read_to_string(laptop.join("live.txt"))? == "remote event" {
                break Ok::<(), anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await??;
    daemon_task.abort();
    server_task.abort();
    Ok(())
}

#[tokio::test]
async fn large_upload_rejects_oversized_chunks_and_resumes() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let (url, first_key, second_key, task) = running_server(&temp).await?;
    let laptop = temp.path().join("laptop");
    let desktop = temp.path().join("desktop");
    let laptop_config = temp.path().join("laptop-config.json");
    let desktop_config = temp.path().join("desktop-config.json");
    client::configure(
        &laptop_config,
        url.clone(),
        first_key.clone(),
        laptop.clone(),
        true,
    )
    .await?;

    let bytes = vec![0x5a; UPLOAD_CHUNK_BYTES as usize + 1024 * 1024];
    let digest = hex::encode(Sha256::digest(&bytes));
    std::fs::write(laptop.join("large.bin"), &bytes)?;
    let http = reqwest::Client::new();
    let progress: UploadProgress = http
        .post(format!("{url}/v1/uploads"))
        .bearer_auth(&first_key)
        .json(&BeginUpload {
            path: "large.bin".into(),
            base_revision: 0,
            size: bytes.len() as i64,
            sha256: digest.clone(),
        })
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(progress.offset, 0);

    let oversized = http
        .put(format!("{url}/v1/uploads/{}", progress.id))
        .query(&[("offset", 0)])
        .bearer_auth(&first_key)
        .body(bytes.clone())
        .send()
        .await?;
    assert_eq!(oversized.status(), reqwest::StatusCode::PAYLOAD_TOO_LARGE);

    let oversized_direct = http
        .put(format!("{url}/v1/file"))
        .query(&[("path", "too-large.bin"), ("base_revision", "0")])
        .bearer_auth(&first_key)
        .body(bytes.clone())
        .send()
        .await?;
    assert_eq!(
        oversized_direct.status(),
        reqwest::StatusCode::PAYLOAD_TOO_LARGE
    );
    assert_eq!(
        std::fs::read_dir(temp.path().join("server/blobs"))?.count(),
        0
    );

    let progress: UploadProgress = http
        .put(format!("{url}/v1/uploads/{}", progress.id))
        .query(&[("offset", 0)])
        .bearer_auth(&first_key)
        .body(bytes[..UPLOAD_CHUNK_BYTES as usize].to_vec())
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(progress.offset, UPLOAD_CHUNK_BYTES);

    let report = client::sync(&laptop_config).await?;
    assert_eq!(report.uploaded, 1);
    client::configure(&desktop_config, url, second_key, desktop.clone(), false).await?;
    assert_eq!(std::fs::read(desktop.join("large.bin"))?, bytes);
    assert_eq!(
        client::Api::new(&client::load_config(&laptop_config)?)?
            .manifest()
            .await?
            .entries[0]
            .sha256
            .as_deref(),
        Some(digest.as_str())
    );
    task.abort();
    Ok(())
}

#[tokio::test]
async fn pending_uploads_are_limited_per_device() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let (url, key, _, task) = running_server(&temp).await?;
    let http = reqwest::Client::new();
    let digest = hex::encode(Sha256::digest(b"a"));
    for index in 0..16 {
        let response = http
            .post(format!("{url}/v1/uploads"))
            .bearer_auth(&key)
            .json(&BeginUpload {
                path: format!("file-{index}"),
                base_revision: 0,
                size: 1,
                sha256: digest.clone(),
            })
            .send()
            .await?;
        assert_eq!(response.status(), reqwest::StatusCode::OK);
    }
    let response = http
        .post(format!("{url}/v1/uploads"))
        .bearer_auth(&key)
        .json(&BeginUpload {
            path: "file-17".into(),
            base_revision: 0,
            size: 1,
            sha256: digest,
        })
        .send()
        .await?;
    assert_eq!(response.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);
    task.abort();
    Ok(())
}

#[tokio::test]
async fn first_device_accepts_a_server_with_only_deleted_entries() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let (url, first_key, second_key, task) = running_server(&temp).await?;
    let original = temp.path().join("original");
    let original_config = temp.path().join("original.json");
    std::fs::create_dir(&original)?;
    std::fs::write(original.join("old.txt"), "deleted before enrollment")?;
    client::configure(
        &original_config,
        url.clone(),
        first_key,
        original.clone(),
        true,
    )
    .await?;
    std::fs::remove_file(original.join("old.txt"))?;
    client::sync(&original_config).await?;

    let fresh = temp.path().join("fresh");
    let fresh_config = temp.path().join("fresh.json");
    std::fs::create_dir(&fresh)?;
    std::fs::write(fresh.join("new.txt"), "enrolled")?;
    client::configure(&fresh_config, url, second_key, fresh, true).await?;
    assert!(client::load_config(&fresh_config).is_ok());
    task.abort();
    Ok(())
}
