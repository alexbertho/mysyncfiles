use anyhow::Result;
use mysyncfiles_server::{auth_protocol::*, device_auth, server};
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey},
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    sign::Signer,
};
use reqwest::{Client, Method, StatusCode};
use rusqlite::params;

struct Fixture {
    dir: tempfile::TempDir,
    state: std::sync::Arc<server::ServerState>,
    url: String,
    task: tokio::task::JoinHandle<()>,
    tpm_key: PKey<Private>,
    device: String,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Fixture {
    async fn new() -> Result<Self> {
        let dir = tempfile::tempdir()?;
        let state = server::open(dir.path())?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}", listener.local_addr()?);
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let ec = EcKey::generate(&group)?;
        let mut x = BigNum::new()?;
        let mut y = BigNum::new()?;
        let mut context = BigNumContext::new()?;
        ec.public_key()
            .affine_coordinates_gfp(ec.group(), &mut x, &mut y, &mut context)?;
        let mut area = hex::decode("0023000b00050072000000100018000b00030010")?;
        for coordinate in [x, y] {
            area.extend(32u16.to_be_bytes());
            area.extend(coordinate.to_vec_padded(32)?);
        }
        let public = hex::encode(area);
        signing_public(&public)?;
        let tpm_key = PKey::from_ec_key(ec)?;
        let db = rusqlite::Connection::open(dir.path().join("metadata.sqlite3"))?;
        db.execute("INSERT INTO auth_settings VALUES('public_url', ?1)", [&url])?;
        db.execute(
            "INSERT INTO devices(id,name,created_at) VALUES(1,'fixture',?1)",
            [now()],
        )?;
        db.execute("INSERT INTO device_enrollments(id,device_id,invitation_hash,expires_at,public,approved_at) VALUES('enrollment',1,'fixture',?1,?2,?3)", params![now()+900, public, now()])?;
        let router = server::router(state.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        Ok(Self {
            dir,
            state,
            url,
            task,
            tpm_key,
            device: "enrollment".into(),
        })
    }
    fn tpm_proof(&self, claims: Claims) -> Result<String> {
        let mut signer = Signer::new(MessageDigest::sha256(), &self.tpm_key)?;
        let der = signer.sign_oneshot_to_vec(&claims.message()?)?;
        let sig = EcdsaSig::from_der(&der)?;
        let mut bytes = sig.r().to_vec_padded(32)?;
        bytes.extend(sig.s().to_vec_padded(32)?);
        Proof {
            claims,
            signature: hex::encode(bytes),
        }
        .encode()
    }
    async fn session(&self, key: &ed25519_dalek::SigningKey) -> Result<Session> {
        let url = format!("{}/v1/auth/session", self.url);
        let body = serde_json::to_vec(&SessionRequest {
            version: PROTOCOL_VERSION,
            public_key: hex::encode(key.verifying_key().to_bytes()),
        })?;
        let claims = Claims::new(&self.device, "POST", &url, &body, "")?;
        Ok(Client::new()
            .post(url)
            .header(PROOF_HEADER, self.tpm_proof(claims)?)
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }
    fn request(
        &self,
        session: &Session,
        key: &ed25519_dalek::SigningKey,
        path: &str,
    ) -> Result<reqwest::Request> {
        let url = format!("{}{path}", self.url);
        let claims = Claims::new(&self.device, "GET", &url, b"", &session.token)?;
        Ok(Client::new()
            .get(url)
            .header("authorization", format!("MySync {}", session.token))
            .header(PROOF_HEADER, Proof::session(claims, key)?.encode()?)
            .build()?)
    }
}

#[tokio::test]
async fn session_requires_tpm_and_binds_requests_to_the_ephemeral_key() -> Result<()> {
    let fixture = Fixture::new().await?;
    let key = ed25519_dalek::SigningKey::from_bytes(&[11; 32]);
    let other = ed25519_dalek::SigningKey::from_bytes(&[12; 32]);
    let session = fixture.session(&key).await?;
    assert!((now() + 895..=now() + 900).contains(&session.expires_at));
    let http = Client::new();
    let request = fixture.request(&session, &key, "/v1/manifest")?;
    let replay = request.try_clone().unwrap();
    assert_eq!(http.execute(request).await?.status(), StatusCode::OK);
    assert_eq!(
        http.execute(replay).await?.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        http.execute(fixture.request(&session, &other, "/v1/manifest")?)
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let mut tampered = fixture.request(&session, &key, "/v1/manifest")?;
    tampered.url_mut().set_query(Some("summary=true"));
    assert_eq!(
        http.execute(tampered).await?.status(),
        StatusCode::UNAUTHORIZED
    );
    let url = format!("{}/v1/manifest", fixture.url);
    let old_proof = fixture.tpm_proof(Claims::new(
        &fixture.device,
        "GET",
        &url,
        b"",
        &session.token,
    )?)?;
    assert_eq!(
        http.get(url)
            .header("authorization", format!("MySync {}", session.token))
            .header(PROOF_HEADER, old_proof)
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let mut browser = fixture.request(&session, &key, web_path())?;
    *browser.method_mut() = Method::POST;
    assert_ne!(http.execute(browser).await?.status(), StatusCode::OK);
    // Even a correctly bound software proof cannot authorize a browser session.
    for path in [
        web_path(),
        mysyncfiles_server::editor_protocol::AUTHORIZE_PATH,
    ] {
        let url = format!("{}{}", fixture.url, path);
        let proof = Proof::session(
            Claims::new(&fixture.device, "POST", &url, b"{}", &session.token)?,
            &key,
        )?
        .encode()?;
        assert_eq!(
            http.post(url)
                .header("authorization", format!("MySync {}", session.token))
                .header(PROOF_HEADER, proof)
                .header("content-type", "application/json")
                .body("{}")
                .send()
                .await?
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    device_auth::set_server_name(&fixture.state, "Maison")?;
    let info: ServerInfo = http
        .execute(fixture.request(&session, &key, "/v1/server")?)
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(info.name, "Maison");
    assert_eq!(info.protocol, 2);
    assert_eq!(
        http.get(format!("{}/install.sh", fixture.url))
            .send()
            .await?
            .status(),
        StatusCode::NOT_FOUND
    );
    assert!(server::revoke_device(&fixture.state, "fixture")?);
    assert_eq!(
        http.execute(fixture.request(&session, &key, "/v1/manifest")?)
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    Ok(())
}
fn web_path() -> &'static str {
    mysyncfiles_server::web_status_protocol::PROOFS_PATH
}

#[tokio::test]
async fn expired_sessions_and_legacy_session_creation_are_rejected() -> Result<()> {
    let fixture = Fixture::new().await?;
    let key = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
    let session = fixture.session(&key).await?;
    let db = rusqlite::Connection::open(fixture.dir.path().join("metadata.sqlite3"))?;
    db.execute("UPDATE device_sessions SET expires_at=1", [])?;
    let http = Client::new();
    assert_eq!(
        http.execute(fixture.request(&session, &key, "/v1/manifest")?)
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let url = format!("{}/v1/auth/session", fixture.url);
    let proof = fixture.tpm_proof(Claims::new(&fixture.device, "POST", &url, b"", "")?)?;
    assert!(
        !http
            .post(url)
            .header(PROOF_HEADER, proof)
            .send()
            .await?
            .status()
            .is_success()
    );
    for _ in 0..12 {
        fixture.session(&key).await?;
    }
    let count: i64 = db.query_row("SELECT COUNT(*) FROM device_sessions", [], |r| r.get(0))?;
    assert_eq!(count, 8);
    Ok(())
}
