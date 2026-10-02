use anyhow::Result;
use mysyncfiles::{client, model::Manifest};
use rusqlite::{Connection, params};

mod common;

#[tokio::test]
async fn manifest_boundaries_and_summary_include_every_file() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let data = temp.path().join("server");
    let mut server = common::TestServer::start(&data).await?;
    let key = server.add_device("pagination-client").await?;
    let root = temp.path().join("files");
    std::fs::create_dir(&root)?;
    let config = common::config(&server.url, &root, key.clone());
    let api = client::Api::new(&config)?;
    let mut db = Connection::open(data.join("metadata.sqlite3"))?;
    let sha = mysyncfiles::auth_protocol::hash([]);
    for count in [0, 1000, 1001, 2000, 2001, 10_000] {
        let tx = db.transaction()?;
        tx.execute("DELETE FROM entries", [])?;
        {
            let mut statement = tx.prepare("INSERT INTO entries VALUES(?1,?2,NULL,?3,0,?4,1)")?;
            for i in 0..count {
                let deleted = i % 7 == 0;
                statement.execute(params![
                    format!("file-{i:05}"),
                    i + 1,
                    (!deleted).then_some(&sha),
                    deleted
                ])?;
            }
        }
        tx.execute("UPDATE meta SET value=?1 WHERE key='generation'", [count])?;
        tx.commit()?;
        let manifest = api.manifest().await?;
        assert_eq!(manifest.entries.len(), count as usize);
        assert_eq!(manifest.generation, count);
        for (i, entry) in manifest.entries.iter().enumerate() {
            assert_eq!(entry.path, format!("file-{i:05}"));
        }
        let summary = api.manifest_summary().await?;
        assert_eq!(summary.generation, manifest.generation);
        assert_eq!(
            summary.files,
            manifest
                .entries
                .iter()
                .filter(|entry| !entry.deleted)
                .count()
        );
        if count <= 1000 {
            // The default endpoint still returns the legacy schema.
            let legacy: Manifest = common::send_signed(
                reqwest::Client::new().get(format!("{}/v1/manifest", server.url)),
                &key,
            )
            .await?
            .error_for_status()?
            .json()
            .await?;
            assert_eq!(legacy.entries.len(), count as usize);
        }
    }
    // A no-op sync must not lose previously seen entries at page boundaries.
    let mut state = serde_json::Map::new();
    for entry in api.manifest().await?.entries {
        if !entry.deleted {
            std::fs::write(root.join(&entry.path), [])?;
        }
        state.insert(
            entry.path,
            serde_json::json!({"revision":entry.revision,"sha256":entry.sha256}),
        );
    }
    let config_path = temp.path().join("config.json");
    std::fs::write(&config_path, serde_json::to_vec(&config)?)?;
    std::fs::write(
        config_path.with_extension("state.json"),
        serde_json::to_vec(&serde_json::json!({"entries":state}))?,
    )?;
    let report = client::sync(&config_path).await?;
    assert_eq!(
        (report.uploaded, report.downloaded, report.conflicts),
        (0, 0, 0)
    );
    let status = client::status(&config_path).await?;
    assert_eq!(status.pending_local, 0);
    assert_eq!(status.remote_files, status.local_files);
    Ok(())
}
