use crate::{
    auth_protocol::*,
    server::{ApiError, ServerState},
};
use anyhow::{Context, Result, ensure};
use axum::{
    Json,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use openssl::{
    pkey::{PKey, Public},
    stack::Stack,
    x509::{X509, X509StoreContext, store::X509StoreBuilder},
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::{path::Path, sync::Arc, time::Duration};

const REQUEST_BODY_TIMEOUT: Duration = Duration::from_secs(30);

async fn read_signed_body(body: Body) -> Result<axum::body::Bytes, ApiError> {
    read_body(body, crate::model::UPLOAD_CHUNK_BYTES as usize).await
}

async fn read_body(body: Body, limit: usize) -> Result<axum::body::Bytes, ApiError> {
    tokio::time::timeout(REQUEST_BODY_TIMEOUT, to_bytes(body, limit))
        .await
        .map_err(|_| ApiError(StatusCode::REQUEST_TIMEOUT, "request body timed out".into()))?
        .map_err(|_| {
            ApiError(
                StatusCode::PAYLOAD_TOO_LARGE,
                "invalid or oversized request body".into(),
            )
        })
}

/// Admission must precede JSON extraction, including on failed invitations.
pub async fn enrollment_middleware(
    State(state): State<Arc<ServerState>>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let _permit = state
        .enrollment_limit
        .try_acquire()
        .map_err(|_| ApiError(StatusCode::TOO_MANY_REQUESTS, "enrollment busy".into()))?;
    let limit = if request.uri().path() == "/v1/enroll/ready" {
        128
    } else {
        256 * 1024
    };
    let (parts, body) = request.into_parts();
    let bytes = read_body(body, limit).await?;
    Ok(next
        .run(Request::from_parts(parts, Body::from(bytes)))
        .await)
}

fn check_active_session(
    db: &Connection,
    enrollment: &str,
    token: &str,
    is_session: bool,
) -> Result<(), ApiError> {
    let active: bool = db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM devices d JOIN device_enrollments e ON e.device_id=d.id
        WHERE e.id=?1 AND e.approved_at IS NOT NULL AND d.revoked_at IS NULL)",
            [enrollment],
            |r| r.get(0),
        )
        .map_err(auth_error)?;
    if !active {
        return Err(auth_error("device revoked"));
    }
    if !is_session {
        let valid: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM device_sessions WHERE token_hash=?1 AND enrollment_id=?2 AND expires_at>?3)",
            params![hash(token), enrollment, now()], |r| r.get(0)).map_err(auth_error)?;
        if !valid {
            return Err(auth_error("expired or mismatched session"));
        }
    }
    Ok(())
}

pub fn initialize(db: &Connection) -> Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS auth_settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS device_enrollments(
          id TEXT PRIMARY KEY,device_id INTEGER NOT NULL REFERENCES devices(id),
          invitation_hash TEXT NOT NULL UNIQUE,expires_at INTEGER NOT NULL,
          public TEXT,fingerprint TEXT,ek_fingerprint TEXT,activation_hash TEXT,challenge TEXT,
          verified_at INTEGER,approved_at INTEGER);
        CREATE TABLE IF NOT EXISTS device_sessions(token_hash TEXT PRIMARY KEY,enrollment_id TEXT NOT NULL REFERENCES device_enrollments(id),expires_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS proof_nonces(enrollment_id TEXT NOT NULL,nonce TEXT NOT NULL,expires_at INTEGER NOT NULL,
          PRIMARY KEY(enrollment_id,nonce));")?;
    Ok(())
}
fn setting(db: &Connection, key: &str) -> Result<Option<String>> {
    Ok(db
        .query_row("SELECT value FROM auth_settings WHERE key=?1", [key], |r| {
            r.get(0)
        })
        .optional()?)
}
pub fn configure(state: &ServerState, public_url: &str, roots: &Path) -> Result<()> {
    let url = reqwest::Url::parse(public_url)?;
    ensure!(
        url.scheme() == "https"
            || (url.scheme() == "http"
                && matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"))),
        "HTTPS public URL required"
    );
    ensure!(
        url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.path() == "/",
        "public URL must be an origin without credentials or path"
    );
    let pem = std::fs::read(roots)?;
    ensure!(
        !X509::stack_from_pem(&pem)?.is_empty(),
        "at least one trusted EK CA certificate required"
    );
    let mut db = state.db.lock().unwrap();
    let tx = db.transaction()?;
    for (key, value) in [
        ("public_url", url.as_str().trim_end_matches('/').to_owned()),
        ("ek_roots", String::from_utf8(pem)?),
    ] {
        tx.execute(
            "INSERT OR REPLACE INTO auth_settings VALUES(?1,?2)",
            params![key, value],
        )?;
    }
    tx.commit()?;
    Ok(())
}
pub fn invite(state: &ServerState, name: &str) -> Result<String> {
    let token = random_secret()?;
    insert_invitation(state, name, &token)?;
    Ok(token)
}

/// A human-readable code carries no authority until a local administrator
/// registers it. The enrollment protocol still requires TPM proof and approval.
pub fn pairing_code() -> Result<String> {
    let mut bytes = [0u8; 13];
    getrandom::fill(&mut bytes).map_err(|e| anyhow::anyhow!("random generation: {e}"))?;
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut code = String::with_capacity(23);
    for (index, bit) in (0..100).step_by(5).enumerate() {
        if index != 0 && index % 5 == 0 {
            code.push('-');
        }
        let byte = bit / 8;
        let shift = bit % 8;
        let value =
            ((bytes[byte] as u16) << 8) | bytes.get(byte + 1).copied().unwrap_or_default() as u16;
        let digit = ((value >> (11 - shift)) & 31) as usize;
        code.push(ALPHABET[digit] as char);
    }
    Ok(code)
}

pub fn normalize_pairing_code(code: &str) -> Result<String> {
    let value: String = code
        .chars()
        .filter(|c| *c != '-')
        .map(|c| match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            other => other,
        })
        .collect();
    ensure!(
        value.len() == 20
            && value
                .bytes()
                .all(|c| b"0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(&c)),
        "pairing code must contain 20 Base32 characters"
    );
    Ok(value)
}

pub fn register_pair(state: &ServerState, name: &str, code: &str) -> Result<String> {
    let code = normalize_pairing_code(code)?;
    let hash = hash(&code);
    {
        let db = state.db.lock().unwrap();
        let existing: Option<(String, String, Option<i64>, i64)> = db
            .query_row(
                "SELECT e.id,d.name,e.approved_at,e.expires_at FROM device_enrollments e JOIN devices d ON d.id=e.device_id WHERE e.invitation_hash=?1",
                [&hash],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        if let Some((id, old_name, approved, expires)) = existing {
            ensure!(
                old_name == name && approved.is_none() && expires > now(),
                "pairing code is already used or expired"
            );
            return Ok(id);
        }
    }
    insert_invitation(state, name, &code)
}

pub fn enrollment_by_id(state: &ServerState, id: &str) -> Result<DeviceEnrollment> {
    list(state)?
        .into_iter()
        .find(|entry| entry.id == id)
        .context("enrollment no longer exists")
}

pub fn invite_to_file(state: &ServerState, name: &str, path: &Path) -> Result<()> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let token = random_secret()?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    let result = (|| {
        writeln!(file, "{token}")?;
        file.sync_all()?;
        // Publish the invitation only after its private export is durable.
        insert_invitation(state, name, &token).map(|_| ())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(path);
    }
    result
}

fn insert_invitation(state: &ServerState, name: &str, token: &str) -> Result<String> {
    ensure!(
        !name.trim().is_empty() && name.len() <= 255,
        "invalid device name"
    );
    let mut db = state.db.lock().unwrap();
    let tx = db.transaction()?;
    ensure!(
        setting(&tx, "ek_roots")?.is_some(),
        "configure the public URL and EK CA roots first"
    );
    let existing: Option<(i64, Option<i64>)> = tx
        .query_row(
            "SELECT id,revoked_at FROM devices WHERE name=?1",
            [name],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let id = if let Some((id, revoked)) = existing {
        ensure!(revoked.is_none(), "revoked name; use a new device name");
        id
    } else {
        tx.execute(
            "INSERT INTO devices(name,created_at) VALUES(?1,?2)",
            params![name, now()],
        )?;
        tx.last_insert_rowid()
    };
    let occupied:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM device_enrollments WHERE device_id=?1 AND (approved_at IS NOT NULL OR expires_at>?2))",params![id,now()],|r|r.get(0))?;
    ensure!(
        !occupied,
        "device already enrolled or an invitation is pending"
    );
    let enrollment_id = uuid::Uuid::new_v4().to_string();
    tx.execute("INSERT INTO device_enrollments(id,device_id,invitation_hash,expires_at) VALUES(?1,?2,?3,?4)",
        params![enrollment_id,id,hash(token),now()+900])?;
    tx.commit()?;
    Ok(enrollment_id)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairReadyRequest {
    code: String,
}

pub async fn pair_ready(
    State(state): State<Arc<ServerState>>,
    Json(request): Json<PairReadyRequest>,
) -> Result<StatusCode, ApiError> {
    if !state.allow_pair_ready() {
        return Err(ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            "pairing checks are busy".into(),
        ));
    }
    let code = normalize_pairing_code(&request.code)
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid pairing code".into()))?;
    let db = state.db.lock().unwrap();
    let row: Option<(i64, Option<i64>)> = db
        .query_row(
            "SELECT expires_at,approved_at FROM device_enrollments WHERE invitation_hash=?1",
            [hash(code)],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(ApiError::internal)?;
    Ok(match row {
        None => StatusCode::ACCEPTED,
        Some((expires, approved)) if expires <= now() || approved.is_some() => StatusCode::GONE,
        Some(_) => StatusCode::NO_CONTENT,
    })
}

#[derive(Serialize)]
pub struct DeviceEnrollment {
    pub id: String,
    pub name: String,
    pub fingerprint: Option<String>,
    pub status: String,
}
pub fn list(state: &ServerState) -> Result<Vec<DeviceEnrollment>> {
    let db = state.db.lock().unwrap();
    let mut q=db.prepare("SELECT e.id,d.name,e.fingerprint,CASE
        WHEN d.revoked_at IS NOT NULL THEN 'revoked' WHEN e.approved_at IS NOT NULL THEN 'approved'
        WHEN e.expires_at<=?1 THEN 'expired' WHEN e.verified_at IS NOT NULL THEN 'pending-approval'
        ELSE 'invited' END FROM device_enrollments e JOIN devices d ON d.id=e.device_id ORDER BY d.id")?;
    Ok(q.query_map([now()], |r| {
        Ok(DeviceEnrollment {
            id: r.get(0)?,
            name: r.get(1)?,
            fingerprint: r.get(2)?,
            status: r.get(3)?,
        })
    })?
    .collect::<rusqlite::Result<_>>()?)
}
pub fn approve(state: &ServerState, id: &str, expected_fingerprint: &str) -> Result<()> {
    let mut db = state.db.lock().unwrap();
    let tx = db.transaction()?;
    let exists:Option<i64>=tx.query_row("SELECT e.device_id FROM device_enrollments e JOIN devices d ON d.id=e.device_id
        WHERE e.id=?1 AND e.fingerprint=?2 AND verified_at IS NOT NULL AND expires_at>?3 AND d.revoked_at IS NULL",
        params![id,expected_fingerprint,now()],|r|r.get(0)).optional()?;
    exists.context("no verified enrollment with this fingerprint")?;
    tx.execute("UPDATE device_enrollments SET approved_at=?2,activation_hash=NULL,challenge=NULL WHERE id=?1",params![id,now()])?;
    tx.commit()?;
    Ok(())
}

/// Cancel only an unapproved invitation. Approved keys must be revoked instead.
pub fn cancel(state: &ServerState, id: &str) -> Result<()> {
    let changed = state.db.lock().unwrap().execute(
        "UPDATE device_enrollments SET expires_at=0,activation_hash=NULL,challenge=NULL
         WHERE id=?1 AND approved_at IS NULL AND expires_at>0",
        [id],
    )?;
    ensure!(
        changed == 1,
        "no cancellable invitation; revoke approved devices instead"
    );
    Ok(())
}

fn verify_ek(roots: &str, chain: &[String]) -> Result<PKey<Public>> {
    ensure!(
        !chain.is_empty() && chain.len() <= 8,
        "invalid EK certificate chain"
    );
    let certs = chain
        .iter()
        .map(|c| {
            ensure!(c.len() <= 32768, "certificate too large");
            Ok(X509::from_der(&hex::decode(c)?)?)
        })
        .collect::<Result<Vec<_>>>()?;
    let mut store = X509StoreBuilder::new()?;
    for ca in X509::stack_from_pem(roots.as_bytes())? {
        store.add_cert(ca)?;
    }
    let mut untrusted = Stack::new()?;
    for cert in certs.iter().skip(1) {
        untrusted.push(cert.clone())?;
    }
    let mut ctx = X509StoreContext::new()?;
    ensure!(
        ctx.init(&store.build(), &certs[0], &untrusted, |ctx| ctx
            .verify_cert())?,
        "untrusted or expired EK certificate"
    );
    let key = certs[0].public_key()?;
    let der = certs[0].to_der()?;
    let (_, leaf) = x509_parser::parse_x509_certificate(&der)
        .map_err(|e| anyhow::anyhow!("EK certificate: {e}"))?;
    ensure!(!leaf.is_ca(), "EK certificate must not be a CA");
    let usage = leaf
        .extended_key_usage()?
        .context("EK extended key usage missing")?;
    ensure!(
        usage
            .value
            .other
            .iter()
            .any(|oid| oid.to_id_string() == "2.23.133.8.1"),
        "certificate is not a TPM endorsement certificate"
    );
    let usage = leaf.key_usage()?.context("EK key usage missing")?;
    ensure!(
        if key.rsa().is_ok() {
            usage.value.key_encipherment()
        } else {
            usage.value.key_agreement()
        },
        "invalid EK key usage"
    );
    ensure!(
        key.rsa().is_ok_and(|k| k.size() == 256)
            || key
                .ec_key()
                .is_ok_and(|k| k.group().curve_name() == Some(openssl::nid::Nid::X9_62_PRIME256V1)),
        "unsupported EK public key"
    );
    Ok(key)
}

// Use the upstream TPM2 software implementation of MakeCredential, without a
// TPM on the server. All paths belong to a private temporary directory; no shell
// or client-supplied executable/flags are involved.
async fn make_credential(
    ek: &PKey<Public>,
    name: &[u8],
    activation: &str,
) -> Result<(String, String)> {
    let temp = tempfile::tempdir()?;
    let public = temp.path().join("ek.pem");
    let secret = temp.path().join("secret");
    let output = temp.path().join("credential");
    std::fs::write(&public, ek.public_key_to_pem()?)?;
    std::fs::write(&secret, hex::decode(activation)?)?;
    let mut command = tokio::process::Command::new("/usr/bin/tpm2_makecredential");
    command
        .args([
            "-T",
            "none",
            "-G",
            if ek.rsa().is_ok() { "rsa" } else { "ecc" },
            "-u",
        ])
        .arg(&public)
        .arg("-s")
        .arg(&secret)
        .arg("-n")
        .arg(hex::encode(name))
        .arg("-o")
        .arg(&output)
        .kill_on_drop(true);
    let result =
        tokio::time::timeout(std::time::Duration::from_secs(10), command.output()).await??;
    ensure!(result.status.success(), "TPM MakeCredential failed");
    let bytes = std::fs::read(output)?;
    ensure!(
        bytes.len() >= 12 && bytes[..8] == [0xba, 0xdc, 0xc0, 0xde, 0, 0, 0, 1],
        "unexpected MakeCredential format"
    );
    let n = u16::from_be_bytes([bytes[8], bytes[9]]) as usize;
    ensure!(bytes.len() >= 12 + n, "truncated credential");
    let m = u16::from_be_bytes([bytes[10 + n], bytes[11 + n]]) as usize;
    ensure!(bytes.len() == 12 + n + m, "truncated secret");
    Ok((
        hex::encode(&bytes[10..10 + n]),
        hex::encode(&bytes[12 + n..]),
    ))
}
fn auth_error(error: impl std::fmt::Display) -> ApiError {
    eprintln!("device authentication rejected: {error}");
    ApiError(
        StatusCode::UNAUTHORIZED,
        "device authentication failed".into(),
    )
}
pub async fn enroll_start(
    State(state): State<Arc<ServerState>>,
    Json(request): Json<EnrollStart>,
) -> Result<Json<EnrollChallenge>, ApiError> {
    let (roots, id) = {
        let db = state.db.lock().unwrap();
        let roots = setting(&db, "ek_roots")
            .map_err(auth_error)?
            .ok_or_else(|| auth_error("EK roots not configured"))?;
        let id:Option<String>=db.query_row("SELECT e.id FROM device_enrollments e JOIN devices d ON d.id=e.device_id
            WHERE invitation_hash=?1 AND expires_at>?2 AND verified_at IS NULL AND d.revoked_at IS NULL",
            params![hash(&request.invitation),now()],|r|r.get(0)).optional().map_err(auth_error)?;
        (roots, id.ok_or_else(|| auth_error("invalid invitation"))?)
    };
    let key = verify_ek(&roots, &request.ek_chain).map_err(auth_error)?;
    let fp = fingerprint(&request.public).map_err(auth_error)?;
    let name = key_name(&request.public).map_err(auth_error)?;
    let activation = random_secret().map_err(auth_error)?;
    let (credential, secret) = make_credential(&key, &name, &activation)
        .await
        .map_err(ApiError::internal)?;
    let challenge = EnrollChallenge {
        id: id.clone(),
        credential,
        secret,
    };
    let ek_fp = hash(key.public_key_to_der().map_err(auth_error)?);
    let mut db = state.db.lock().unwrap();
    let tx = db.transaction().map_err(ApiError::internal)?;
    let existing:Option<(Option<String>,Option<String>)>=tx.query_row("SELECT public,challenge FROM device_enrollments
        WHERE id=?1 AND expires_at>?2 AND verified_at IS NULL AND EXISTS(SELECT 1 FROM devices WHERE id=device_id AND revoked_at IS NULL)",params![id,now()],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(ApiError::internal)?;
    let (old_public, old_challenge) =
        existing.ok_or_else(|| auth_error("invitation no longer valid"))?;
    if let Some(old) = old_public {
        if old != request.public {
            return Err(ApiError::conflict(
                "invitation already bound to another key",
            ));
        }
        return Ok(Json(
            serde_json::from_str(&old_challenge.unwrap()).map_err(ApiError::internal)?,
        ));
    }
    tx.execute("UPDATE device_enrollments SET public=?2,fingerprint=?3,ek_fingerprint=?4,activation_hash=?5,challenge=?6 WHERE id=?1",
        params![id,request.public,fp,ek_fp,hash(hex::decode(activation).map_err(auth_error)?),serde_json::to_string(&challenge).map_err(ApiError::internal)?]).map_err(ApiError::internal)?;
    tx.commit().map_err(ApiError::internal)?;
    Ok(Json(challenge))
}
pub async fn enroll_finish(
    State(state): State<Arc<ServerState>>,
    Json(request): Json<EnrollFinish>,
) -> Result<Json<Enrollment>, ApiError> {
    let bytes = hex::decode(&request.activation).map_err(auth_error)?;
    if bytes.len() != 32 {
        return Err(auth_error("invalid activation"));
    }
    let mut db = state.db.lock().unwrap();
    let tx = db.transaction().map_err(ApiError::internal)?;
    let row:Option<(String,String)>=tx.query_row("SELECT activation_hash,fingerprint FROM device_enrollments e JOIN devices d ON d.id=e.device_id
        WHERE e.id=?1 AND expires_at>?2 AND approved_at IS NULL AND d.revoked_at IS NULL",params![request.id,now()],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(ApiError::internal)?;
    let (expected, fp) = row.ok_or_else(|| auth_error("unknown enrollment"))?;
    if !openssl::memcmp::eq(hash(bytes).as_bytes(), expected.as_bytes()) {
        return Err(auth_error("activation failed"));
    }
    tx.execute("UPDATE device_enrollments SET verified_at=COALESCE(verified_at,?2),expires_at=CASE WHEN verified_at IS NULL THEN ?2+86400 ELSE expires_at END,challenge=NULL WHERE id=?1",params![request.id,now()]).map_err(ApiError::internal)?;
    tx.commit().map_err(ApiError::internal)?;
    Ok(Json(Enrollment {
        id: request.id,
        fingerprint: fp,
        status: "pending-approval".into(),
    }))
}

pub async fn middleware(
    State(state): State<Arc<ServerState>>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let is_session = request.uri().path() == "/v1/auth/session";
    // Retain the permit until the handler releases the buffered request too.
    let body_permit;
    let authorization = request
        .headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_owned();
    {
        let proof = request
            .headers()
            .get(PROOF_HEADER)
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| auth_error("missing proof"))?;
        let proof = Proof::decode(proof).map_err(auth_error)?;
        let (public, origin, device) = {
            let db = state.db.lock().unwrap();
            let row:Option<(String,i64)>=db.query_row("SELECT e.public,d.id FROM device_enrollments e JOIN devices d ON d.id=e.device_id
                WHERE e.id=?1 AND e.approved_at IS NOT NULL AND d.revoked_at IS NULL",[&proof.claims.device],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(auth_error)?;
            let (public, device) = row.ok_or_else(|| {
                ApiError(
                    StatusCode::FORBIDDEN,
                    "device not approved or revoked".into(),
                )
            })?;
            (
                public,
                setting(&db, "public_url")
                    .map_err(auth_error)?
                    .ok_or_else(|| auth_error("public URL missing"))?,
                device,
            )
        };
        let token = if is_session {
            if !authorization.is_empty() {
                return Err(auth_error("unexpected session credential"));
            }
            ""
        } else {
            authorization
                .strip_prefix("MySync ")
                .ok_or_else(|| auth_error("missing bound session"))?
        };
        let url = format!(
            "{origin}{}",
            request
                .uri()
                .path_and_query()
                .map(|p| p.as_str())
                .unwrap_or("/")
        );
        let (parts, body) = request.into_parts();
        proof
            .verify_headers(&public, parts.method.as_str(), &url, token)
            .map_err(auth_error)?;
        {
            let mut db = state.db.lock().unwrap();
            let tx = db.transaction().map_err(ApiError::internal)?;
            check_active_session(&tx, &proof.claims.device, token, is_session)?;
            body_permit = state.signed_request_limit.try_acquire().map_err(|_| {
                ApiError(
                    StatusCode::TOO_MANY_REQUESTS,
                    "too many signed requests in flight".into(),
                )
            })?;
            tx.execute("DELETE FROM proof_nonces WHERE expires_at<=?1", [now()])
                .map_err(ApiError::internal)?;
            let inserted = tx
                .execute(
                    "INSERT OR IGNORE INTO proof_nonces VALUES(?1,?2,?3)",
                    params![proof.claims.device, proof.claims.nonce, now() + 120],
                )
                .map_err(ApiError::internal)?;
            if inserted != 1 {
                return Err(auth_error("replayed proof"));
            }
            tx.commit().map_err(ApiError::internal)?;
        }
        // The nonce is consumed even on a failed/cancelled body read. A retry
        // must sign a fresh proof, so concurrent replays cannot reserve memory.
        let bytes = read_signed_body(body).await?;
        proof.verify_body(&bytes).map_err(auth_error)?;
        check_active_session(
            &state.db.lock().unwrap(),
            &proof.claims.device,
            token,
            is_session,
        )?;
        request = Request::from_parts(parts, Body::from(bytes));
        request.extensions_mut().insert(device);
        request.extensions_mut().insert(proof.claims.device);
    }
    let response = next.run(request).await;
    drop(body_permit);
    Ok(response)
}
pub async fn session(
    State(state): State<Arc<ServerState>>,
    axum::Extension(id): axum::Extension<String>,
) -> Result<Json<Session>, ApiError> {
    let token = random_secret().map_err(ApiError::internal)?;
    let expires = now() + SESSION_SECONDS;
    let db = state.db.lock().unwrap();
    db.execute("DELETE FROM device_sessions WHERE expires_at<=?1", [now()])
        .map_err(ApiError::internal)?;
    db.execute(
        "INSERT INTO device_sessions VALUES(?1,?2,?3)",
        params![hash(&token), id, expires],
    )
    .map_err(ApiError::internal)?;
    Ok(Json(Session {
        token,
        expires_at: expires,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn enrollment_admission_precedes_body_reads_and_releases_on_timeout() -> Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let temp = tempfile::tempdir()?;
        let state = crate::server::open(temp.path())?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let router = crate::server::router(state.clone());
        let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let mut held = Vec::new();
        for route in ["start", "finish", "start", "finish"] {
            let mut socket = tokio::net::TcpStream::connect(address).await?;
            socket.write_all(format!("POST /v1/enroll/{route} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 262144\r\nConnection: close\r\n\r\n{{").as_bytes()).await?;
            held.push(socket);
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while state.enrollment_limit.available_permits() != 0 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await?;
        for route in ["start", "finish", "ready"] {
            let mut socket = tokio::net::TcpStream::connect(address).await?;
            socket.write_all(format!("POST /v1/enroll/{route} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\nConnection: close\r\n\r\n").as_bytes()).await?;
            let mut response = [0; 256];
            let n =
                tokio::time::timeout(Duration::from_secs(2), socket.read(&mut response)).await??;
            assert!(std::str::from_utf8(&response[..n])?.starts_with("HTTP/1.1 429"));
        }
        tokio::time::pause();
        tokio::time::advance(REQUEST_BODY_TIMEOUT).await;
        for mut socket in held {
            let mut response = String::new();
            socket.read_to_string(&mut response).await?;
            assert!(response.starts_with("HTTP/1.1 408"), "{response}");
        }
        tokio::time::resume();
        assert_eq!(state.enrollment_limit.available_permits(), 4);
        let http = reqwest::Client::new();
        for route in ["start", "finish"] {
            let url = format!("http://{address}/v1/enroll/{route}");
            assert_eq!(
                http.post(&url)
                    .header("content-type", "application/json")
                    .body("{")
                    .send()
                    .await?
                    .status(),
                StatusCode::BAD_REQUEST
            );
            assert_eq!(
                http.post(&url)
                    .header("content-type", "application/json")
                    .body(vec![b' '; 256 * 1024 + 1])
                    .send()
                    .await?
                    .status(),
                StatusCode::PAYLOAD_TOO_LARGE
            );
        }
        assert_eq!(state.enrollment_limit.available_permits(), 4);
        task.abort();
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn signed_body_has_a_deadline_and_a_byte_limit() {
        let body = Body::from_stream(futures_util::stream::pending::<
            Result<Vec<u8>, std::io::Error>,
        >());
        let start = tokio::time::Instant::now();
        assert_eq!(
            read_signed_body(body).await.unwrap_err().0,
            StatusCode::REQUEST_TIMEOUT
        );
        assert_eq!(start.elapsed(), REQUEST_BODY_TIMEOUT);
        let body = Body::from(vec![0; crate::model::UPLOAD_CHUNK_BYTES as usize + 1]);
        assert_eq!(
            read_signed_body(body).await.unwrap_err().0,
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }
}
