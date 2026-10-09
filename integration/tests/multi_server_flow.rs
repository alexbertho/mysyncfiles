use anyhow::Result;
use mysyncfiles::{auth_protocol::hash, client};
mod common;

#[tokio::test]
async fn independent_servers_keep_revisions_files_sessions_and_revocation_separate() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let mut one = common::TestServer::start(&temp.path().join("server-one")).await?;
    let mut two = common::TestServer::start(&temp.path().join("server-two")).await?;
    mysyncfiles::device_auth::set_server_name(&one.state, "First server")?;
    mysyncfiles::device_auth::set_server_name(&two.state, "Second server")?;
    let identity1 = one.add_device("first-client").await?;
    let identity2 = two.add_device("second-client").await?;
    let root1 = temp.path().join("mirror-one");
    std::fs::create_dir(&root1)?;
    let root2 = temp.path().join("mirror-two");
    std::fs::create_dir(&root2)?;
    std::fs::write(root1.join("same.txt"), b"first server")?;
    std::fs::write(root2.join("same.txt"), b"second server")?;
    let config1 = common::config(&one.url, &root1, identity1);
    let config2 = common::config(&two.url, &root2, identity2);
    let profile1 = temp.path().join("one.json");
    std::fs::write(&profile1, serde_json::to_vec(&config1)?)?;
    let profile2 = temp.path().join("two.json");
    std::fs::write(&profile2, serde_json::to_vec(&config2)?)?;
    let (a, b) = tokio::join!(client::sync(&profile1), client::sync(&profile2));
    assert_eq!(a?.uploaded, 1);
    assert_eq!(b?.uploaded, 1);
    assert_eq!(client::status(&profile1).await?.server_name, "First server");
    assert_eq!(
        client::status(&profile2).await?.server_name,
        "Second server"
    );
    let api1 = client::Api::new(&config1)?;
    let api2 = client::Api::new(&config2)?;
    for _ in 0..10 {
        let (a, b) = tokio::join!(api1.manifest(), api2.manifest());
        let a = a?;
        let b = b?;
        assert_eq!(a.entries[0].sha256, Some(hash(b"first server")));
        assert_eq!(b.entries[0].sha256, Some(hash(b"second server")));
        assert_eq!(a.entries[0].revision, b.entries[0].revision);
    }
    let db = rusqlite::Connection::open(temp.path().join("server-one/metadata.sqlite3"))?;
    let sessions: i64 = db.query_row("SELECT COUNT(*) FROM device_sessions", [], |r| r.get(0))?;
    assert_eq!(sessions, 3); // Sync, status, then one persistent API for ten requests.
    // A cached client credential invalidated by the server triggers a fresh TPM
    // authorization and a new key; it never retries with the old TPM-per-request protocol.
    db.execute("UPDATE device_sessions SET expires_at=1", [])?;
    assert!(api1.manifest().await.is_ok());
    let sessions: i64 = db.query_row("SELECT COUNT(*) FROM device_sessions", [], |r| r.get(0))?;
    assert_eq!(sessions, 1);
    let mut crossed = config1.clone();
    crossed.server = two.url.clone();
    crossed.server_public_key = two.state.public_key();
    assert!(client::Api::new(&crossed)?.manifest().await.is_err());
    assert!(mysyncfiles::server::revoke_device(
        &one.state,
        "first-client"
    )?);
    assert!(api1.manifest().await.is_err());
    assert!(api2.manifest().await.is_ok());
    assert_eq!(std::fs::read(root1.join("same.txt"))?, b"first server");
    assert_eq!(std::fs::read(root2.join("same.txt"))?, b"second server");
    Ok(())
}

#[tokio::test]
async fn one_daemon_synchronizes_two_profiles_and_survives_a_server_revocation() -> Result<()> {
    use std::{process::Stdio, time::Duration};
    let temp = tempfile::tempdir()?;
    let mut one = common::TestServer::start(&temp.path().join("server-one")).await?;
    let mut two = common::TestServer::start(&temp.path().join("server-two")).await?;
    let identity1 = one.add_device("first-client").await?;
    let identity2 = two.add_device("second-client").await?;
    let registry = temp.path().join("config/mysync/profiles");
    std::fs::create_dir_all(&registry)?;
    for (name, server, identity) in [("one", &one, identity1), ("two", &two, identity2)] {
        let root = temp.path().join(name);
        std::fs::create_dir(&root)?;
        std::fs::write(root.join("same.txt"), name)?;
        let config = common::config(&server.url, &root, identity);
        std::fs::write(
            registry.join(format!("{name}.json")),
            serde_json::to_vec(&config)?,
        )?;
    }
    let executable = std::env::var_os("MYSYNC_TEST_CLIENT_BIN")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_mysync").into());
    let mut child = tokio::process::Command::new(executable)
        .args(["daemon", "--all"])
        .env("XDG_CONFIG_HOME", temp.path().join("config"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    async fn uploaded(data: &std::path::Path, expected: i64) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let db = rusqlite::Connection::open(data.join("metadata.sqlite3"))?;
                let count: i64 =
                    db.query_row("SELECT COUNT(*) FROM entries WHERE deleted=0", [], |r| {
                        r.get(0)
                    })?;
                if count == expected {
                    return Ok::<(), anyhow::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await??;
        Ok(())
    }
    uploaded(&temp.path().join("server-one"), 1).await?;
    uploaded(&temp.path().join("server-two"), 1).await?;
    assert!(mysyncfiles::server::revoke_device(
        &one.state,
        "first-client"
    )?);
    std::fs::write(temp.path().join("one/revoked.txt"), "local preserved")?;
    std::fs::write(
        temp.path().join("two/continues.txt"),
        "second server continues",
    )?;
    uploaded(&temp.path().join("server-two"), 2).await?;
    assert!(child.try_wait()?.is_none());
    assert_eq!(
        std::fs::read(temp.path().join("one/revoked.txt"))?,
        b"local preserved"
    );
    child.kill().await?;
    Ok(())
}
