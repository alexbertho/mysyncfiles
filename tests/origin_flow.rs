use anyhow::Result;
use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    extract::Request,
    http::{HeaderMap, StatusCode},
    response::Response,
};
use mysyncfiles::{auth_protocol::hash, client, origin_auth::RESPONSE_HEADER};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
mod common;

// A terminating proxy can read and replace every response byte, but has no
// origin signing key. This exercises the real server, TPM client and storage.
struct Proxy {
    url: String,
    mode: Arc<AtomicUsize>,
    polls: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Proxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Proxy {
    async fn start(origin: String) -> Result<Self> {
        let mode = Arc::new(AtomicUsize::new(0));
        let polls = Arc::new(AtomicUsize::new(0));
        let cached = Arc::new(Mutex::new(None::<(HeaderMap, Bytes)>));
        let router = Router::new().fallback({
            let mode = mode.clone();
            let polls = polls.clone();
            let http = reqwest::Client::new();
            move |request: Request| {
                let (mode, polls, cached, http, origin) = (
                    mode.clone(),
                    polls.clone(),
                    cached.clone(),
                    http.clone(),
                    origin.clone(),
                );
                async move {
                    let (parts, body) = request.into_parts();
                    let manifest = parts.uri.path() == "/v1/manifest";
                    let presence =
                        parts.uri.path() == mysyncfiles::web_status_protocol::PROOFS_PATH;
                    let mutation = parts.method == "PUT" && parts.uri.path() == "/v1/file";
                    if manifest {
                        polls.fetch_add(1, Ordering::SeqCst);
                    }
                    let mut bytes = to_bytes(body, 8 * 1024 * 1024).await.unwrap();
                    if presence && mode.load(Ordering::SeqCst) == 9 {
                        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                        value["status"]["client_version"] = "99.0.0".into();
                        bytes = serde_json::to_vec(&value).unwrap().into();
                    }
                    let response = http
                        .request(parts.method, format!("{origin}{}", parts.uri))
                        .headers(parts.headers)
                        .body(bytes)
                        .send()
                        .await
                        .unwrap();
                    let mut status = response.status();
                    let mut headers = response.headers().clone();
                    let mut bytes = response.bytes().await.unwrap();
                    match mode.load(Ordering::SeqCst) {
                        0 if manifest => {
                            *cached.lock().unwrap() = Some((headers.clone(), bytes.clone()));
                        }
                        mode @ (1 | 2) if manifest => {
                            let mut value: serde_json::Value =
                                serde_json::from_slice(&bytes).unwrap();
                            let entry = &mut value["entries"][0];
                            entry["revision"] = 999.into();
                            if mode == 1 {
                                entry["sha256"] = hash(b"attacker bytes").into();
                                entry["size"] = 14.into();
                            } else {
                                entry["deleted"] = true.into();
                                entry["sha256"] = serde_json::Value::Null;
                                entry["size"] = serde_json::Value::Null;
                            }
                            bytes = serde_json::to_vec(&value).unwrap().into();
                        }
                        3 if mutation => {
                            let mut value: serde_json::Value =
                                serde_json::from_slice(&bytes).unwrap();
                            value["revision"] = 999.into();
                            bytes = serde_json::to_vec(&value).unwrap().into();
                        }
                        4 if manifest => {
                            (headers, bytes) = cached.lock().unwrap().clone().unwrap();
                        }
                        5 if manifest => {
                            status = StatusCode::CONFLICT;
                        }
                        6 if manifest => {
                            headers.remove(RESPONSE_HEADER);
                        }
                        7 if presence => {
                            let mut value: serde_json::Value =
                                serde_json::from_slice(&bytes).unwrap();
                            value["challenge_id"] = "0".repeat(64).into();
                            bytes = serde_json::to_vec(&value).unwrap().into();
                        }
                        8 if presence => {
                            headers.remove(RESPONSE_HEADER);
                        }
                        10 if manifest => {
                            let mut value: serde_json::Value =
                                serde_json::from_slice(&bytes).unwrap();
                            value["files"] = 0.into();
                            bytes = serde_json::to_vec(&value).unwrap().into();
                        }
                        _ => {}
                    }
                    headers.remove("transfer-encoding");
                    headers.insert("content-length", bytes.len().to_string().parse().unwrap());
                    let mut response = Response::new(Body::from(bytes));
                    *response.status_mut() = status;
                    *response.headers_mut() = headers;
                    response
                }
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}", listener.local_addr()?);
        let task = tokio::spawn(async move {
            axum::serve(mysyncfiles::server::api_listener(listener), router)
                .await
                .unwrap()
        });
        Ok(Self {
            url,
            mode,
            polls,
            task,
        })
    }
}

#[tokio::test]
async fn presence_rejects_proxy_changes_to_signed_status_and_acknowledgements() -> Result<()> {
    use mysyncfiles::{auth_protocol::now, web_status_protocol::*};
    let temp = tempfile::tempdir()?;
    let data = temp.path().join("server");
    let mut server = common::TestServer::start(&data).await?;
    let device = server.add_device("client").await?;
    let proxy = Proxy::start(server.url.clone()).await?;
    rusqlite::Connection::open(data.join("metadata.sqlite3"))?.execute(
        "UPDATE auth_settings SET value=?1 WHERE key='public_url'",
        [&proxy.url],
    )?;
    common::register_origin(&proxy.url, server.state.public_key());
    let api = client::Api::new(&common::config(&proxy.url, temp.path(), device))?;
    let http = reqwest::Client::new();
    let page = http
        .get(format!("{}/status", proxy.url))
        .send()
        .await?
        .error_for_status()?;
    let cookie = page.headers()["set-cookie"]
        .to_str()?
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    for mode in [7, 8, 9] {
        let challenge: ChallengeResponse = http
            .post(format!("{}/v1/web/status/challenges", proxy.url))
            .header("cookie", &cookie)
            .header("origin", &proxy.url)
            .header("x-mysync-web", "1")
            .json(&serde_json::json!({}))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let proof = PresenceProof {
            ticket: challenge.ticket,
            observed_origin: proxy.url.clone(),
            instance_id: "a".repeat(64),
            status: LocalStatus {
                api_version: 1,
                client_version: "0.3.6".into(),
                daemon_state: DaemonState::Idle,
                communication: CommunicationState::Unknown,
                observed_at: now(),
                last_authenticated_at: None,
                error: None,
            },
        };
        proxy.mode.store(mode, Ordering::SeqCst);
        assert!(api.submit_presence(&proof).await.is_err());
        let result = http
            .get(format!(
                "{}/v1/web/status/challenges/{}",
                proxy.url, challenge.challenge_id
            ))
            .header("cookie", &cookie)
            .header("x-mysync-web", "1")
            .send()
            .await?;
        if mode == 9 {
            assert_eq!(result.status(), StatusCode::ACCEPTED);
        } else {
            let verified: VerifiedPresence = result.error_for_status()?.json().await?;
            assert_eq!(verified.status.client_version, "0.3.6");
        }
    }
    Ok(())
}

#[tokio::test]
async fn proxy_cannot_forge_files_tombstones_mutations_status_or_replay_responses() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let data = temp.path().join("server");
    let mut server = common::TestServer::start(&data).await?;
    let device = server.add_device("client").await?;
    let root = temp.path().join("mirror");
    std::fs::create_dir(&root)?;
    std::fs::write(root.join("file"), b"original")?;
    let config_path = temp.path().join("client.json");
    common::configure_client(&config_path, &server.url, device, root.clone()).await?;
    let proxy = Proxy::start(server.url.clone()).await?;
    rusqlite::Connection::open(data.join("metadata.sqlite3"))?.execute(
        "UPDATE auth_settings SET value=?1 WHERE key='public_url'",
        [&proxy.url],
    )?;
    let mut config = client::load_config(&config_path)?;
    config.server = proxy.url.clone();
    std::fs::write(&config_path, serde_json::to_vec(&config)?)?;
    client::sync(&config_path).await?;
    let state_path = config_path.with_extension("state.json");
    let original_state = std::fs::read(&state_path)?;
    for mode in [1, 2, 4, 5, 6] {
        proxy.mode.store(mode, Ordering::SeqCst);
        let error = client::sync(&config_path)
            .await
            .err()
            .expect("proxy substitution must fail");
        assert!(
            error.to_string().contains("origin response"),
            "{mode}: {error:#}"
        );
        assert_eq!(std::fs::read(root.join("file"))?, b"original");
        assert_eq!(std::fs::read(&state_path)?, original_state);
    }
    for mode in [10, 4, 5, 6] {
        proxy.mode.store(mode, Ordering::SeqCst);
        let error = client::status(&config_path)
            .await
            .err()
            .expect("summary must be authenticated");
        assert!(
            error.to_string().contains("origin response"),
            "{mode}: {error:#}"
        );
        assert_eq!(std::fs::read(&state_path)?, original_state);
    }
    proxy.mode.store(3, Ordering::SeqCst);
    std::fs::write(root.join("file"), b"local edit")?;
    assert!(
        client::sync(&config_path)
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("integrity")
    );
    assert_eq!(std::fs::read(root.join("file"))?, b"local edit");
    assert_eq!(std::fs::read(&state_path)?, original_state);
    proxy.mode.store(0, Ordering::SeqCst);
    // A lost acknowledgement converges from the genuine manifest on retry.
    assert_eq!(client::sync(&config_path).await?.conflicts, 0);
    config.server_public_key = hex::encode(
        ed25519_dalek::SigningKey::from_bytes(&[9; 32])
            .verifying_key()
            .to_bytes(),
    );
    assert!(client::Api::new(&config)?.manifest().await.is_err());
    config.server_public_key.clear();
    assert!(client::Api::new(&config).is_err());
    std::fs::write(&config_path, serde_json::to_vec(&config)?)?;
    client::trust_server(&config_path, &server.state.public_key()).await?;
    client::sync(&config_path).await?;
    assert_eq!(
        mysyncfiles::server::open(&data)?.public_key(),
        server.state.public_key()
    );
    Ok(())
}

#[tokio::test]
async fn noop_sync_does_not_checkpoint_or_retrigger_the_daemon() -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let temp = tempfile::tempdir()?;
    let data = temp.path().join("server");
    let mut server = common::TestServer::start(&data).await?;
    let device = server.add_device("client").await?;
    let root = temp.path().join("mirror");
    std::fs::create_dir(&root)?;
    std::fs::write(root.join("file"), b"unchanged")?;
    let config_path = temp.path().join("client.json");
    common::configure_client(&config_path, &server.url, device, root.clone()).await?;
    let proxy = Proxy::start(server.url.clone()).await?;
    rusqlite::Connection::open(data.join("metadata.sqlite3"))?.execute(
        "UPDATE auth_settings SET value=?1 WHERE key='public_url'",
        [&proxy.url],
    )?;
    let mut config = client::load_config(&config_path)?;
    config.server = proxy.url.clone();
    std::fs::write(&config_path, serde_json::to_vec(&config)?)?;
    let before = std::fs::metadata(config_path.with_extension("state.json"))?;
    let path = config_path.clone();
    let task = tokio::spawn(async move { client::daemon(&path).await });
    tokio::time::sleep(Duration::from_secs(4)).await;
    let polls = proxy.polls.load(Ordering::SeqCst);
    let after = std::fs::metadata(config_path.with_extension("state.json"))?;
    task.abort();
    let _ = task.await;
    assert_eq!(
        polls, 1,
        "an unchanged mirror should wait for its 15-second poll"
    );
    assert_eq!(
        (before.ino(), before.mtime(), before.mtime_nsec()),
        (after.ino(), after.mtime(), after.mtime_nsec())
    );
    assert!(!config_path.with_extension("state.journal").exists());
    Ok(())
}
