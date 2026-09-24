//! Real TPM commands against swtpm, with an ephemeral test-only EK CA. The
//! production verifier has no test bypass and never trusts these roots by default.
use anyhow::{Context, Result, ensure};
use mysyncfiles::{
    auth_protocol::*,
    client::{self, ClientConfig},
    device_auth, server,
    tpm::Identity,
};
use openssl::{
    asn1::Asn1Time,
    hash::MessageDigest,
    pkey::{PKey, Private, Public},
    rsa::Rsa,
    x509::{
        X509, X509NameBuilder,
        extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage},
    },
};
use reqwest::{Client, Method, StatusCode};
use std::{
    process::{Child, Command, Stdio},
    sync::Arc,
    time::Duration,
};

struct Simulator {
    process: Child,
    _dir: tempfile::TempDir,
    tcti: String,
}
impl Drop for Simulator {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}
impl Simulator {
    fn start() -> Result<Self> {
        let dir = tempfile::tempdir()?;
        let (port, _first, _second) = loop {
            let first = std::net::TcpListener::bind("127.0.0.1:0")?;
            let port = first.local_addr()?.port();
            if port == 65535 {
                continue;
            }
            if let Ok(second) = std::net::TcpListener::bind(("127.0.0.1", port + 1)) {
                break (port, first, second);
            }
        };
        drop((_first, _second));
        let process = Command::new("swtpm")
            .args(["socket", "--tpm2", "--tpmstate"])
            .arg(format!("dir={}", dir.path().display()))
            .arg("--ctrl")
            .arg(format!("type=tcp,bindaddr=127.0.0.1,port={}", port + 1))
            .arg("--server")
            .arg(format!("type=tcp,bindaddr=127.0.0.1,port={port}"))
            .args(["--flags", "not-need-init,startup-clear"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("install swtpm and tpm2-tools, or run tests in deploy/Dockerfile.tpm-dev")?;
        let result = Self {
            process,
            _dir: dir,
            tcti: format!("swtpm:host=127.0.0.1,port={port}"),
        };
        for _ in 0..100 {
            if result.tool("tpm2_getcap", &["properties-fixed"]).is_ok() {
                return Ok(result);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        anyhow::bail!("simulator did not start")
    }
    fn tool(&self, name: &str, args: &[&str]) -> Result<()> {
        let output = Command::new(name)
            .arg("-T")
            .arg(&self.tcti)
            .args(args)
            .output()?;
        ensure!(
            output.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(())
    }
    fn certify_ek(&self, ca: &Certificate, kind: &str) -> Result<Vec<u8>> {
        let context = self._dir.path().join("ek.ctx");
        let pem = self._dir.path().join("ek.pem");
        self.tool(
            "tpm2_createek",
            &["-G", kind, "-c", context.to_str().unwrap()],
        )?;
        self.tool(
            "tpm2_readpublic",
            &[
                "-c",
                context.to_str().unwrap(),
                "-f",
                "pem",
                "-o",
                pem.to_str().unwrap(),
            ],
        )?;
        let key = PKey::public_key_from_pem(&std::fs::read(pem)?)?;
        let certificate = ca.sign_ek(&key, kind, false, true)?;
        let der = certificate.to_der()?;
        self.install_cert(&der, kind)?;
        self.tool("tpm2_flushcontext", &["-t"])?;
        Ok(der)
    }
    fn install_cert(&self, der: &[u8], kind: &str) -> Result<()> {
        let path = self._dir.path().join("ek.der");
        std::fs::write(&path, der)?;
        let index = if kind == "rsa" {
            "0x01c00002"
        } else {
            "0x01c0000a"
        };
        self.tool(
            "tpm2_nvdefine",
            &[
                index,
                "-C",
                "o",
                "-s",
                &der.len().to_string(),
                "-a",
                "ownerread|ownerwrite|authread",
            ],
        )?;
        self.tool(
            "tpm2_nvwrite",
            &[index, "-C", "o", "-i", path.to_str().unwrap()],
        )?;
        Ok(())
    }
}
struct Certificate {
    key: PKey<Private>,
    certificate: X509,
}
impl Certificate {
    fn ca() -> Result<Self> {
        let key = PKey::from_rsa(Rsa::generate(2048)?)?;
        let mut name = X509NameBuilder::new()?;
        name.append_entry_by_text("CN", "MySync ephemeral test CA")?;
        let name = name.build();
        let mut builder = X509::builder()?;
        builder.set_version(2)?;
        let serial = openssl::bn::BigNum::from_u32(1)?.to_asn1_integer()?;
        builder.set_serial_number(&serial)?;
        builder.set_subject_name(&name)?;
        builder.set_issuer_name(&name)?;
        builder.set_pubkey(&key)?;
        let start = Asn1Time::days_from_now(0)?;
        let end = Asn1Time::days_from_now(2)?;
        builder.set_not_before(&start)?;
        builder.set_not_after(&end)?;
        builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;
        builder.append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()?,
        )?;
        builder.sign(&key, MessageDigest::sha256())?;
        Ok(Self {
            key,
            certificate: builder.build(),
        })
    }
    fn sign_ek(&self, key: &PKey<Public>, kind: &str, expired: bool, eku: bool) -> Result<X509> {
        let mut name = X509NameBuilder::new()?;
        name.append_entry_by_text("CN", "Test TPM Endorsement Key")?;
        let name = name.build();
        let mut builder = X509::builder()?;
        builder.set_version(2)?;
        let serial = openssl::bn::BigNum::from_u32(2)?.to_asn1_integer()?;
        builder.set_serial_number(&serial)?;
        builder.set_subject_name(&name)?;
        builder.set_issuer_name(self.certificate.subject_name())?;
        builder.set_pubkey(key)?;
        let start = Asn1Time::from_unix(now() - 3600)?;
        let end = Asn1Time::from_unix(if expired { now() - 1800 } else { now() + 86400 })?;
        builder.set_not_before(&start)?;
        builder.set_not_after(&end)?;
        builder.append_extension(BasicConstraints::new().critical().build()?)?;
        let mut usage = KeyUsage::new();
        usage.critical();
        if kind == "rsa" {
            usage.key_encipherment();
        } else {
            usage.key_agreement();
        }
        builder.append_extension(usage.build()?)?;
        if eku {
            builder.append_extension(ExtendedKeyUsage::new().other("2.23.133.8.1").build()?)?;
        }
        builder.sign(&self.key, MessageDigest::sha256())?;
        Ok(builder.build())
    }
}
struct Server {
    state: Arc<server::ServerState>,
    url: String,
    _dir: tempfile::TempDir,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Server {
    async fn start(ca: &Certificate) -> Result<Self> {
        let dir = tempfile::tempdir()?;
        let state = server::open(dir.path().join("data"))?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}", listener.local_addr()?);
        let roots = dir.path().join("roots.pem");
        std::fs::write(&roots, ca.certificate.to_pem()?)?;
        device_auth::configure(&state, &url, &roots, true)?;
        let router = server::router(state.clone());
        let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        Ok(Self {
            state,
            url,
            _dir: dir,
            task,
        })
    }
    fn db(&self) -> Result<rusqlite::Connection> {
        Ok(rusqlite::Connection::open(
            self._dir.path().join("data/metadata.sqlite3"),
        )?)
    }
}
async fn start_enroll(
    http: &Client,
    server: &Server,
    token: &str,
    key: &Identity,
    cert: &[u8],
) -> Result<reqwest::Response> {
    Ok(http
        .post(format!("{}/v1/enroll/start", server.url))
        .json(&EnrollStart {
            invitation: token.into(),
            public: key.public.clone(),
            ek_chain: vec![hex::encode(cert)],
        })
        .send()
        .await?)
}
async fn enroll(
    http: &Client,
    server: &Server,
    token: &str,
    key: &mut Identity,
    cert: &[u8],
) -> Result<String> {
    let response = start_enroll(http, server, token, key, cert).await?;
    ensure!(
        response.status() == StatusCode::OK,
        "start failed: {}",
        response.text().await?
    );
    let challenge: EnrollChallenge = response.json().await?;
    let activation = key.activate(&challenge)?;
    key.device = challenge.id.clone();
    let response = http
        .post(format!("{}/v1/enroll/finish", server.url))
        .json(&EnrollFinish {
            id: challenge.id,
            activation,
        })
        .send()
        .await?;
    ensure!(
        response.status() == StatusCode::OK,
        "finish failed: {}",
        response.text().await?
    );
    let enrollment: Enrollment = response.json().await?;
    assert_eq!(enrollment.fingerprint, key.fingerprint()?);
    Ok(enrollment.fingerprint)
}
async fn signed(
    http: &Client,
    url: &str,
    method: Method,
    body: Vec<u8>,
    key: &Identity,
    token: &str,
) -> Result<reqwest::Request> {
    let claims = Claims::new(&key.device, method.as_str(), url, &body, token)?;
    let proof = key.proof(claims)?;
    let mut request = http
        .request(method, url)
        .body(body)
        .header(PROOF_HEADER, proof);
    if !token.is_empty() {
        request = request.header("authorization", format!("MySync {token}"));
    }
    Ok(request.build()?)
}
async fn session(http: &Client, server: &Server, key: &Identity) -> Result<Session> {
    Ok(http
        .execute(
            signed(
                http,
                &format!("{}/v1/auth/session", server.url),
                Method::POST,
                vec![],
                key,
                "",
            )
            .await?,
        )
        .await?
        .error_for_status()?
        .json()
        .await?)
}

fn pending_body() -> reqwest::Body {
    reqwest::Body::wrap_stream(futures_util::stream::pending::<
        Result<Vec<u8>, std::io::Error>,
    >())
}

#[tokio::test]
async fn signed_requests_authenticate_before_buffering_and_bound_in_flight_bodies() -> Result<()> {
    let ca = Certificate::ca()?;
    let simulator = Simulator::start()?;
    let cert = simulator.certify_ek(&ca, "rsa")?;
    let (mut key, _) = Identity::create(&simulator.tcti, "rsa")?;
    let server = Server::start(&ca).await?;
    let http = Client::new();
    let invitation = device_auth::invite(&server.state, "body-limits")?;
    let fingerprint = enroll(&http, &server, &invitation, &mut key, &cert).await?;
    device_auth::approve(&server.state, &key.device, &fingerprint)?;
    let active = session(&http, &server, &key).await?;
    let url = format!("{}/v1/file?path=probe&base_revision=0", server.url);
    for case in [
        "signature",
        "expired",
        "future",
        "session",
        "method",
        "query",
    ] {
        let token = if case == "session" {
            "nonexistent-session"
        } else {
            &active.token
        };
        let mut claims = Claims::new(&key.device, "PUT", &url, b"x", token)?;
        if case == "expired" {
            claims.issued_at = now() - 120;
        }
        if case == "future" {
            claims.issued_at = now() + 120;
        }
        let mut proof = Proof::decode(&key.proof(claims)?)?;
        if case == "signature" {
            proof.signature = "00".repeat(64);
        }
        let mut request = http
            .put(&url)
            .header("authorization", format!("MySync {token}"))
            .header(PROOF_HEADER, proof.encode()?)
            .body(pending_body())
            .build()?;
        if case == "method" {
            *request.method_mut() = Method::POST;
        }
        if case == "query" {
            request
                .url_mut()
                .set_query(Some("path=other&base_revision=0"));
        }
        let response =
            tokio::time::timeout(Duration::from_secs(3), http.execute(request)).await??;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{case}");
    }
    let replay = signed(&http, &url, Method::PUT, b"x".to_vec(), &key, &active.token).await?;
    assert_eq!(
        http.execute(replay.try_clone().unwrap()).await?.status(),
        StatusCode::OK
    );
    let mut replay = replay;
    *replay.body_mut() = Some(pending_body());
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(3), http.execute(replay))
            .await??
            .status(),
        StatusCode::UNAUTHORIZED
    );

    let mut tasks = tokio::task::JoinSet::new();
    let mut nonces = Vec::new();
    for _ in 0..8 {
        let mut request =
            signed(&http, &url, Method::PUT, b"x".to_vec(), &key, &active.token).await?;
        nonces.push(
            Proof::decode(request.headers()[PROOF_HEADER].to_str()?)?
                .claims
                .nonce,
        );
        *request.body_mut() = Some(pending_body());
        let http = http.clone();
        tasks.spawn(async move { http.execute(request).await });
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let db = server.db().unwrap();
            if nonces.iter().all(|nonce| {
                db.query_row(
                    "SELECT EXISTS(SELECT 1 FROM proof_nonces WHERE nonce=?1)",
                    [nonce],
                    |r| r.get::<_, bool>(0),
                )
                .unwrap()
            }) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    let mut request = signed(&http, &url, Method::PUT, b"x".to_vec(), &key, &active.token).await?;
    *request.body_mut() = Some(pending_body());
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(3), http.execute(request))
            .await??
            .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    // Cancellation releases admission slots; a new legitimate request works.
    let request = signed(
        &http,
        &format!("{}/v1/manifest", server.url),
        Method::GET,
        vec![],
        &key,
        &active.token,
    )
    .await?;
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let status = http.execute(request.try_clone().unwrap()).await?.status();
            if status == StatusCode::OK {
                break Ok::<_, anyhow::Error>(());
            }
            assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await??;

    // Revocation during an admitted body read is rechecked after EOF.
    use futures_util::StreamExt;
    let late_url = format!("{}/v1/file?path=revoked-upload&base_revision=0", server.url);
    let mut request = signed(
        &http,
        &late_url,
        Method::PUT,
        b"x".to_vec(),
        &key,
        &active.token,
    )
    .await?;
    let nonce = Proof::decode(request.headers()[PROOF_HEADER].to_str()?)?
        .claims
        .nonce;
    let (finish, done) = tokio::sync::oneshot::channel::<()>();
    let body = futures_util::stream::once(async { Ok::<_, std::io::Error>(vec![b'x']) }).chain(
        futures_util::stream::once(async {
            let _ = done.await;
            Ok(vec![])
        }),
    );
    *request.body_mut() = Some(reqwest::Body::wrap_stream(body));
    let http_task = http.clone();
    let upload = tokio::spawn(async move { http_task.execute(request).await });
    tokio::time::timeout(Duration::from_secs(3), async {
        while !server
            .db()
            .unwrap()
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM proof_nonces WHERE nonce=?1)",
                [&nonce],
                |r| r.get::<_, bool>(0),
            )
            .unwrap()
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    server::revoke_device(&server.state, "body-limits")?;
    finish.send(()).unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(3), upload)
            .await???
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert!(!server.db()?.query_row(
        "SELECT EXISTS(SELECT 1 FROM entries WHERE path='revoked-upload')",
        [],
        |r| r.get::<_, bool>(0)
    )?);
    Ok(())
}

#[tokio::test]
async fn tpm_enrollment_request_binding_replay_revocation_and_migration() -> Result<()> {
    let ca = Certificate::ca()?;
    let simulator = Simulator::start()?;
    let cert = simulator.certify_ek(&ca, "rsa")?;
    let (mut key, _) = Identity::create(&simulator.tcti, "rsa")?;
    let server = Server::start(&ca).await?;
    let http = Client::new();
    let legacy = server::add_device(&server.state, "device-a")?;
    let invitation = device_auth::invite(&server.state, "device-a")?;
    assert!(device_auth::require_tpm(&server.state).is_err());
    let fingerprint = enroll(&http, &server, &invitation, &mut key, &cert).await?;
    assert!(session(&http, &server, &key).await.is_err());
    assert!(device_auth::approve(&server.state, &key.device, &"0".repeat(64)).is_err());
    device_auth::approve(&server.state, &key.device, &fingerprint)?;
    assert_eq!(
        http.get(format!("{}/v1/manifest", server.url))
            .bearer_auth(&legacy)
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    device_auth::require_tpm(&server.state)?;
    let active = session(&http, &server, &key).await?;
    let url = format!("{}/v1/manifest", server.url);
    let request = signed(&http, &url, Method::GET, vec![], &key, &active.token).await?;
    let replay = request.try_clone().unwrap();
    assert_eq!(http.execute(request).await?.status(), StatusCode::OK);
    assert_eq!(
        http.execute(replay).await?.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        http.get(&url)
            .header("authorization", format!("MySync {}", active.token))
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let file_url = format!("{}/v1/file?path=a&base_revision=0", server.url);
    for mutation in ["body", "query", "method", "token"] {
        let mut request = signed(
            &http,
            &file_url,
            Method::PUT,
            b"original".to_vec(),
            &key,
            &active.token,
        )
        .await?;
        match mutation {
            "body" => *request.body_mut() = Some("tampered".into()),
            "query" => request
                .url_mut()
                .set_query(Some("path=other&base_revision=0")),
            "method" => *request.method_mut() = Method::DELETE,
            _ => {
                request
                    .headers_mut()
                    .insert("authorization", "MySync other-token".parse()?);
            }
        }
        assert_eq!(
            http.execute(request).await?.status(),
            StatusCode::UNAUTHORIZED,
            "{mutation}"
        );
    }
    let mut expired = Claims::new(&key.device, "GET", &url, b"", &active.token)?;
    expired.issued_at = now() - 120;
    assert_eq!(
        http.get(&url)
            .header("authorization", format!("MySync {}", active.token))
            .header(PROOF_HEADER, key.proof(expired)?)
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );

    // Exercise the real client, including a chunked signed upload and download.
    let local = tempfile::tempdir()?;
    let root = local.path().join("mirror");
    std::fs::create_dir(&root)?;
    let config = ClientConfig {
        server: server.url.clone(),
        token: String::new(),
        identity: Some(key.clone()),
        root: root.clone(),
        auto_update: false,
        update_public_key: mysyncfiles::release::PUBLIC_KEY_HEX.trim().into(),
    };
    let config_path = local.path().join("config.json");
    std::fs::write(&config_path, serde_json::to_vec(&config)?)?;
    std::fs::write(root.join("small"), b"small file")?;
    let large = vec![7u8; mysyncfiles::model::UPLOAD_CHUNK_BYTES as usize + 1];
    std::fs::write(root.join("large"), &large)?;
    assert_eq!(client::sync(&config_path).await?.uploaded, 2);
    let download_root = local.path().join("download");
    std::fs::create_dir(&download_root)?;
    let mut download_config = config.clone();
    download_config.root = download_root.clone();
    let download_path = local.path().join("download.json");
    std::fs::write(&download_path, serde_json::to_vec(&download_config)?)?;
    assert_eq!(client::sync(&download_path).await?.downloaded, 2);
    assert_eq!(std::fs::read(download_root.join("large"))?, large);

    // Expiring a cached session must force a signed renewal, not a downgrade.
    let api = client::Api::new(&config)?;
    api.manifest().await?;
    server
        .db()?
        .execute("UPDATE device_sessions SET expires_at=1", [])?;
    let request = signed(&http, &url, Method::GET, vec![], &key, &active.token).await?;
    assert_eq!(
        http.execute(request).await?.status(),
        StatusCode::UNAUTHORIZED
    );
    api.manifest().await?;

    // A copied blob cannot sign on another TPM, even though it has all config data.
    let other = Simulator::start()?;
    let mut copied = key.clone();
    copied.tcti = other.tcti.clone();
    assert!(
        copied
            .proof(Claims::new(&key.device, "GET", &url, b"", &active.token)?)
            .is_err()
    );
    assert!(server::revoke_device(&server.state, "device-a")?);
    let request = signed(&http, &url, Method::GET, vec![], &key, &active.token).await?;
    assert_eq!(http.execute(request).await?.status(), StatusCode::FORBIDDEN);
    assert!(session(&http, &server, &key).await.is_err());
    Ok(())
}

#[tokio::test]
async fn tpm_attestation_requires_trusted_valid_ek_and_one_key_per_invitation() -> Result<()> {
    let ca = Certificate::ca()?;
    let simulator = Simulator::start()?;
    let cert = simulator.certify_ek(&ca, "ecc")?;
    let (mut key, _) = Identity::create(&simulator.tcti, "ecc")?;
    let server = Server::start(&ca).await?;
    let http = Client::new();
    let token = device_auth::invite(&server.state, "device")?;
    let ek = X509::from_der(&cert)?.public_key()?;
    let untrusted = Certificate::ca()?
        .sign_ek(&ek, "ecc", false, true)?
        .to_der()?;
    let expired = ca.sign_ek(&ek, "ecc", true, true)?.to_der()?;
    let wrong_usage = ca.sign_ek(&ek, "ecc", false, false)?.to_der()?;
    for invalid in [&untrusted, &expired, &wrong_usage] {
        assert_eq!(
            start_enroll(&http, &server, &token, &key, invalid)
                .await?
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        start_enroll(&http, &server, "bad invitation", &key, &cert)
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let challenge: EnrollChallenge = start_enroll(&http, &server, &token, &key, &cert)
        .await?
        .error_for_status()?
        .json()
        .await?;
    let retry: EnrollChallenge = start_enroll(&http, &server, &token, &key, &cert)
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(retry.credential, challenge.credential);
    let (different, _) = Identity::create(&simulator.tcti, "ecc")?;
    assert_eq!(
        start_enroll(&http, &server, &token, &different, &cert)
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    assert!(different.activate(&challenge).is_err());
    assert_eq!(
        http.post(format!("{}/v1/enroll/finish", server.url))
            .json(&EnrollFinish {
                id: challenge.id.clone(),
                activation: "00".repeat(32)
            })
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let fingerprint = enroll(&http, &server, &token, &mut key, &cert).await?;
    assert!(
        device_auth::list(&server.state)?
            .iter()
            .any(|e| e.status == "pending-approval")
    );
    device_auth::approve(&server.state, &key.device, &fingerprint)?;
    session(&http, &server, &key).await?;
    let expired_token = device_auth::invite(&server.state, "expired")?;
    server.db()?.execute(
        "UPDATE device_enrollments SET expires_at=1 WHERE invitation_hash=?1",
        [hash(&expired_token)],
    )?;
    assert_eq!(
        start_enroll(&http, &server, &expired_token, &different, &cert)
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let cancelled = device_auth::invite(&server.state, "cancelled")?;
    let entry = device_auth::list(&server.state)?
        .into_iter()
        .find(|e| e.name == "cancelled")
        .unwrap();
    device_auth::cancel(&server.state, &entry.id)?;
    assert_eq!(
        start_enroll(&http, &server, &cancelled, &different, &cert)
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    device_auth::invite(&server.state, "cancelled")?;
    assert!(device_auth::cancel(&server.state, &key.device).is_err());
    Ok(())
}

#[tokio::test]
async fn client_enrollment_is_resumable_and_preserves_existing_settings() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let ca = Certificate::ca()?;
    let simulator = Simulator::start()?;
    simulator.certify_ek(&ca, "rsa")?;
    for migrate in [false, true] {
        let server = Server::start(&ca).await?;
        let local = tempfile::tempdir()?;
        let root = local.path().join("mirror");
        std::fs::create_dir(&root)?;
        std::fs::write(root.join("keep.txt"), b"keep local data")?;
        let path = local.path().join("config.json");
        let original = if migrate {
            let config = ClientConfig {
                server: server.url.clone(),
                token: server::add_device(&server.state, "lifecycle")?,
                identity: None,
                root: root.clone(),
                auto_update: false,
                update_public_key: "11".repeat(32),
            };
            let bytes = serde_json::to_vec(&config)?;
            std::fs::write(&path, &bytes)?;
            client::sync(&path).await?;
            Some(bytes)
        } else {
            None
        };
        let invitation = device_auth::invite(&server.state, "lifecycle")?;
        let mut fingerprint = String::new();
        let mut enrollment_id = String::new();
        for _ in 0..2 {
            let enrolled = client::enroll_with_tcti(
                &path,
                server.url.clone(),
                root.clone(),
                invitation.clone(),
                None,
                simulator.tcti.clone(),
            )
            .await?;
            assert_eq!(enrolled.status, "pending-approval");
            if !fingerprint.is_empty() {
                assert_eq!(fingerprint, enrolled.fingerprint);
                assert_eq!(enrollment_id, enrolled.id);
            }
            fingerprint = enrolled.fingerprint;
            enrollment_id = enrolled.id;
            assert!(client::activate_enrollment(&path).await.is_err());
            if let Some(bytes) = &original {
                assert_eq!(&std::fs::read(&path)?, bytes);
            } else {
                assert!(!path.exists());
            }
            assert_eq!(
                std::fs::metadata(path.with_extension("enrollment.json"))?
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        device_auth::approve(&server.state, &enrollment_id, &fingerprint)?;
        let report = client::activate_enrollment(&path).await?;
        assert_eq!(report.uploaded, usize::from(!migrate));
        assert_eq!(report.conflicts, 0);
        assert!(!path.with_extension("enrollment.json").exists());
        let config = client::load_config(&path)?;
        assert!(config.token.is_empty());
        assert_eq!(config.identity.as_ref().unwrap().device, enrollment_id);
        assert_eq!(config.auto_update, !migrate);
        if migrate {
            assert_eq!(config.update_public_key, "11".repeat(32));
        }
        assert_eq!(std::fs::read(root.join("keep.txt"))?, b"keep local data");
        assert_eq!(
            std::fs::metadata(&path)?.permissions().mode() & 0o777,
            0o600
        );
        device_auth::require_tpm(&server.state)?;
        assert!(server::add_device(&server.state, "no-legacy").is_err());
    }
    Ok(())
}

#[test]
fn fresh_server_rejects_legacy_device_keys() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let state = server::open(dir.path())?;
    assert!(server::add_device(&state, "legacy").is_err());
    let export = dir.path().join("invitation");
    assert!(device_auth::invite_to_file(&state, "unconfigured", &export).is_err());
    assert!(!export.exists());
    std::fs::write(&export, "existing secret")?;
    assert!(device_auth::invite_to_file(&state, "unconfigured", &export).is_err());
    assert_eq!(std::fs::read(export)?, b"existing secret");
    Ok(())
}
