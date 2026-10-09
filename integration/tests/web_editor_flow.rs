mod common;
use anyhow::Result;
use mysyncfiles::{
    client::{self, Api, local_api::LocalBridge},
    web_status_protocol::*,
};
use reqwest::{Client, Method, StatusCode};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

#[tokio::test]
async fn tpm_editor_scopes_and_runner_exchange_are_separate_and_instance_bound() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let data = temp.path().join("server");
    let mut server = common::TestServer::start(&data).await?;
    let identity = server.add_device("editor-device").await?;
    let root = temp.path().join("mirror");
    std::fs::create_dir(&root)?;
    let mut config = common::config(&server.url, &root, identity);
    config.web_files_enabled = true;
    let profile = temp.path().join("client.json");
    std::fs::write(&profile, serde_json::to_vec(&config)?)?;
    std::fs::write(root.join("example.py"), b"print(1)\n")?;
    client::sync(&profile).await?;
    let http = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(20))
        .build()?;
    let page = http
        .get(format!("{}/editor", server.url))
        .send()
        .await?
        .error_for_status()?;
    let cookie = page.headers()["set-cookie"]
        .to_str()?
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let web = |method, path: &str| {
        http.request(method, format!("{}{path}", server.url))
            .header("cookie", &cookie)
            .header("origin", &server.url)
            .header("x-mysync-web", "1")
    };
    let bridge = LocalBridge::start(
        Arc::new(Api::new(&config)?),
        Arc::new(Mutex::new(DaemonState::Idle)),
    )?;
    let local = |ticket: String| {
        http.get(format!("http://127.0.0.1:{PORT}/v1/status"))
            .header("origin", &server.url)
            .header(BRIDGE_HEADER, "1")
            .header(CHALLENGE_HEADER, ticket)
    };
    let challenge: ChallengeResponse = web(Method::POST, "/v1/web/files/challenges")
        .json(&serde_json::json!({}))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(
        local(challenge.ticket).send().await?.status(),
        StatusCode::OK
    );
    for (scope, error) in [
        ("edit", "files_edit_disabled"),
        ("run", "code_run_disabled"),
    ] {
        let challenge: ChallengeResponse =
            web(Method::POST, &format!("/v1/web/editor/{scope}/challenges"))
                .json(&serde_json::json!({}))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
        let denied: serde_json::Value = local(challenge.ticket).send().await?.json().await?;
        assert_eq!(denied["error"], error);
        assert_eq!(
            web(Method::GET, &format!("/v1/web/editor/{scope}/session"))
                .send()
                .await?
                .status(),
            StatusCode::FORBIDDEN
        );
    }
    drop(bridge);
    tokio::time::sleep(Duration::from_millis(30)).await;
    config.web_edit_enabled = true;
    config.web_run_enabled = true;
    let bridge = LocalBridge::start(
        Arc::new(Api::new(&config)?),
        Arc::new(Mutex::new(DaemonState::Idle)),
    )?;
    for scope in ["edit", "run"] {
        let challenge: ChallengeResponse =
            web(Method::POST, &format!("/v1/web/editor/{scope}/challenges"))
                .json(&serde_json::json!({}))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
        assert_eq!(
            local(challenge.ticket).send().await?.status(),
            StatusCode::OK
        );
        assert_eq!(
            web(Method::GET, &format!("/v1/web/editor/{scope}/session"))
                .send()
                .await?
                .status(),
            StatusCode::OK
        );
    }
    let original: serde_json::Value = web(Method::GET, "/v1/web/editor/file?path=example.py")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    // Exercises the HTTP body limit beyond the ordinary 4 KiB web JSON limit.
    let source = format!("# {}\nprint(2)\n", "a".repeat(10000));
    let saved: serde_json::Value=web(Method::PUT,"/v1/web/editor/file").json(&serde_json::json!({"path":"example.py","base_revision":original["entry"]["revision"],"content":source})).send().await?.error_for_status()?.json().await?;
    assert_eq!(saved["sha256"], mysyncfiles::auth_protocol::hash(&source));
    let issued: serde_json::Value = web(Method::POST, "/v1/web/editor/tickets")
        .json(&serde_json::json!({"action":"tools"}))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let invoke = |ticket: &serde_json::Value| {
        http.post(format!("http://127.0.0.1:{PORT}/v1/editor"))
            .header("origin", &server.url)
            .header(BRIDGE_HEADER, "1")
            .json(ticket)
    };
    let tools: serde_json::Value = invoke(&issued)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert!(tools["isolation"].is_boolean() && tools["python"].is_boolean());
    assert_eq!(
        invoke(&issued).send().await?.status(),
        StatusCode::FORBIDDEN,
        "one use only"
    );
    let issued: serde_json::Value = web(Method::POST, "/v1/web/editor/tickets")
        .json(&serde_json::json!({"action":"tools"}))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    drop(bridge);
    tokio::time::sleep(Duration::from_millis(30)).await;
    let _replacement = LocalBridge::start(
        Arc::new(Api::new(&config)?),
        Arc::new(Mutex::new(DaemonState::Idle)),
    )?;
    assert_eq!(
        invoke(&issued).send().await?.status(),
        StatusCode::FORBIDDEN,
        "a restarted bridge needs a new execution proof"
    );
    assert_eq!(
        http.post(format!("http://127.0.0.1:{PORT}/v1/editor"))
            .header("origin", "https://other.example.test")
            .header(BRIDGE_HEADER, "1")
            .json(&issued)
            .send()
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    Ok(())
}
