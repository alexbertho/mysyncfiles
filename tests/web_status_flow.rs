//! Real TPM presence exchange, with the same transport/development loopback
//! exception as the other integration tests. No production authentication bypass.
use anyhow::{Result, ensure};
use mysyncfiles::{
    auth_protocol::{now, random_secret},
    client::{self, Api, local_api::LocalBridge},
    server,
    web_status_protocol::*,
};
use reqwest::{Client, StatusCode};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
mod common;

async fn browser(http: &Client, server: &str) -> Result<String> {
    let page = http
        .get(format!("{server}/status"))
        .send()
        .await?
        .error_for_status()?;
    ensure!(page.headers()["cache-control"] == "no-store");
    ensure!(
        page.headers()["content-security-policy"]
            .to_str()?
            .contains("frame-ancestors 'none'")
    );
    Ok(page.headers()["set-cookie"]
        .to_str()?
        .split(';')
        .next()
        .unwrap()
        .to_owned())
}
async fn challenge(
    http: &Client,
    server: &str,
    cookie: &str,
    previous: Option<&str>,
) -> Result<ChallengeResponse> {
    Ok(http
        .post(format!("{server}/v1/web/status/challenges"))
        .header("cookie", cookie)
        .header("origin", server)
        .header("x-mysync-web", "1")
        .json(&serde_json::json!({"previous_challenge_id":previous}))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}
async fn result(http: &Client, server: &str, cookie: &str, id: &str) -> Result<reqwest::Response> {
    Ok(http
        .get(format!("{server}/v1/web/status/challenges/{id}"))
        .header("cookie", cookie)
        .header("x-mysync-web", "1")
        .send()
        .await?)
}
fn proof(ticket: &str, origin: &str) -> Result<PresenceProof> {
    Ok(PresenceProof {
        ticket: ticket.into(),
        observed_origin: origin.into(),
        instance_id: random_secret()?,
        status: LocalStatus {
            api_version: 1,
            client_version: env!("CARGO_PKG_VERSION").into(),
            daemon_state: DaemonState::Idle,
            communication: CommunicationState::Unknown,
            observed_at: now(),
            last_authenticated_at: None,
            error: None,
        },
    })
}

#[tokio::test]
async fn two_tpms_loopback_presence_replay_revocation_and_daemon_lifecycle() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let data = temp.path().join("server");
    let mut server = common::TestServer::start(&data).await?;
    let key_a = server.add_device("device-a").await?;
    let key_b = server.add_device("device-b").await?;
    let root = temp.path().join("mirror");
    std::fs::create_dir(&root)?;
    let http = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(12))
        .build()?;
    let cookie = browser(&http, &server.url).await?;
    let other_cookie = browser(&http, &server.url).await?;
    let api = Arc::new(Api::new(&common::config(
        &server.url,
        &root,
        key_a.clone(),
    ))?);
    let bridge = LocalBridge::start(api.clone(), Arc::new(Mutex::new(DaemonState::Idle)))?;
    let endpoint = format!("http://127.0.0.1:{PORT}/v1/status");
    let first = challenge(&http, &server.url, &cookie, None).await?;
    let response = http
        .get(&endpoint)
        .header("origin", &server.url)
        .header(BRIDGE_HEADER, "1")
        .header(CHALLENGE_HEADER, &first.ticket)
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let presence: VerifiedPresence = result(&http, &server.url, &cookie, &first.challenge_id)
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(presence.device_name, "device-a");
    assert!(presence.device_id > 0);
    assert_eq!(
        result(&http, &server.url, &other_cookie, &first.challenge_id)
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    assert!(
        api.submit_presence(&proof(&first.ticket, &server.url)?)
            .await
            .is_err()
    );
    let replay = http
        .get(&endpoint)
        .header("origin", &server.url)
        .header(BRIDGE_HEADER, "1")
        .header(CHALLENGE_HEADER, &first.ticket)
        .send()
        .await?;
    assert_eq!(replay.status(), StatusCode::CONFLICT);
    let renewal = challenge(&http, &server.url, &cookie, Some(&first.challenge_id)).await?;
    // A copied profile with another TPM's transport cannot use the key.
    let mut copied = key_a.clone();
    copied.tcti = key_b.tcti.clone();
    let copied_api = Api::new(&common::config(&server.url, &root, copied))?;
    assert!(
        copied_api
            .submit_presence(&proof(&renewal.ticket, &server.url)?)
            .await
            .is_err()
    );
    drop(copied_api);
    let api_b = Api::new(&common::config(&server.url, &root, key_b.clone()))?;
    assert!(
        api_b
            .submit_presence(&proof(&renewal.ticket, &server.url)?)
            .await
            .is_err()
    );
    let second = challenge(&http, &server.url, &cookie, None).await?;
    api_b
        .submit_presence(&proof(&second.ticket, &server.url)?)
        .await?;
    let presence_b: VerifiedPresence = result(&http, &server.url, &cookie, &second.challenge_id)
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(presence_b.device_name, "device-b");
    assert_ne!(presence.device_id, presence_b.device_id);
    // Atlas requires a distinct cookie, signed scope and explicit client consent.
    let files_page = http
        .get(format!("{}/files", server.url))
        .send()
        .await?
        .error_for_status()?;
    let files_cookie = files_page.headers()["set-cookie"]
        .to_str()?
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let entries_url = format!("{}/v1/web/files/entries", server.url);
    for cookie in [&cookie, &files_cookie] {
        assert_eq!(
            http.get(&entries_url)
                .header("cookie", cookie)
                .header("x-mysync-web", "1")
                .send()
                .await?
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    let files_challenge: ChallengeResponse = http
        .post(format!("{}/v1/web/files/challenges", server.url))
        .header("cookie", &files_cookie)
        .header("origin", &server.url)
        .header("x-mysync-web", "1")
        .json(&serde_json::json!({}))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let file_proof = proof(&files_challenge.ticket, &server.url)?;
    assert!(api.submit_presence(&file_proof).await.is_err());
    let refused = http
        .get(&endpoint)
        .header("origin", &server.url)
        .header(BRIDGE_HEADER, "1")
        .header(CHALLENGE_HEADER, &files_challenge.ticket)
        .send()
        .await?;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        refused.json::<serde_json::Value>().await?["error"],
        "files_read_disabled"
    );
    let mut consent = common::config(&server.url, &root, key_a.clone());
    consent.web_files_enabled = true;
    let files_api = Api::new(&consent)?;
    files_api.submit_presence(&file_proof).await?;
    assert!(files_api.submit_presence(&file_proof).await.is_err());
    assert_eq!(
        http.get(&entries_url)
            .header("cookie", &files_cookie)
            .header("x-mysync-web", "1")
            .send()
            .await?
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        http.get(&entries_url)
            .header("cookie", &cookie)
            .header("x-mysync-web", "1")
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let file_session: serde_json::Value = http
        .get(format!("{}/v1/web/files/session", server.url))
        .header("cookie", &files_cookie)
        .header("x-mysync-web", "1")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert!(file_session["expires_at"].as_i64().unwrap() > now() + 1700);
    assert_eq!(
        result(&http, &server.url, &cookie, &first.challenge_id)
            .await?
            .status(),
        StatusCode::OK
    );
    assert!(server::revoke_device(&server.state, "device-a")?);
    assert_eq!(
        http.get(&entries_url)
            .header("cookie", &files_cookie)
            .header("x-mysync-web", "1")
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    drop(files_api);
    assert_eq!(
        result(&http, &server.url, &cookie, &first.challenge_id)
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    assert!(
        api.submit_presence(&proof(&renewal.ticket, &server.url)?)
            .await
            .is_err()
    );
    // No browser credential, raw ID or unauthenticated local JSON grants proof authority.
    assert_eq!(
        http.post(format!("{}{}", server.url, PROOFS_PATH))
            .json(&proof(&renewal.ticket, &server.url)?)
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        result(&http, &server.url, "", &second.challenge_id)
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(std::fs::read_dir(&root)?.count(), 0);
    drop(bridge);
    tokio::task::yield_now().await;
    drop(api);
    drop(api_b);
    // Old profiles without the setting enable the bridge by default. A port
    // collision must still allow synchronization and must not rewrite the profile.
    let collision = tokio::net::TcpListener::bind(("127.0.0.1", PORT)).await?;
    let config = common::config(&server.url, &root, key_b);
    let config_path = temp.path().join("client.json");
    let mut legacy_profile = serde_json::to_value(&config)?;
    legacy_profile
        .as_object_mut()
        .unwrap()
        .remove("web_status_enabled");
    let config_bytes = serde_json::to_vec(&legacy_profile)?;
    std::fs::write(&config_path, &config_bytes)?;
    std::fs::write(root.join("sample"), b"unchanged")?;
    let path = config_path.clone();
    let daemon = tokio::spawn(async move { client::daemon(&path).await });
    let state_path = config_path.with_extension("state.json");
    for _ in 0..200 {
        if state_path.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        state_path.exists(),
        "sync must continue with a bridge collision"
    );
    daemon.abort();
    let _ = daemon.await;
    drop(collision);
    let path = config_path.clone();
    let daemon = tokio::spawn(async move { client::daemon(&path).await });
    for _ in 0..200 {
        if http
            .get(&endpoint)
            .header("origin", &server.url)
            .header(BRIDGE_HEADER, "1")
            .send()
            .await
            .is_ok()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let saved_state = std::fs::read(&state_path)?;
    for _ in 0..3 {
        assert_eq!(
            http.get(&endpoint)
                .header("origin", &server.url)
                .header(BRIDGE_HEADER, "1")
                .send()
                .await?
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    let final_challenge = challenge(&http, &server.url, &other_cookie, None).await?;
    http.get(&endpoint)
        .header("origin", &server.url)
        .header(BRIDGE_HEADER, "1")
        .header(CHALLENGE_HEADER, &final_challenge.ticket)
        .send()
        .await?
        .error_for_status()?;
    assert_eq!(std::fs::read(&config_path)?, config_bytes);
    assert_eq!(std::fs::read(&state_path)?, saved_state);
    assert_eq!(std::fs::read(root.join("sample"))?, b"unchanged");
    daemon.abort();
    let _ = daemon.await;
    tokio::task::yield_now().await;
    assert!(
        tokio::net::TcpStream::connect(("127.0.0.1", PORT))
            .await
            .is_err()
    );
    client::set_web_status(&config_path, false)?;
    std::fs::remove_file(&state_path)?;
    let path = config_path.clone();
    let daemon = tokio::spawn(async move { client::daemon(&path).await });
    for _ in 0..200 {
        if state_path.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        state_path.exists(),
        "disabling web status must keep synchronization running"
    );
    assert!(
        tokio::net::TcpStream::connect(("127.0.0.1", PORT))
            .await
            .is_err()
    );
    daemon.abort();
    let _ = daemon.await;
    Ok(())
}
