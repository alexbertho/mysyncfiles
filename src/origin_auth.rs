//! Origin authentication independent of the HTTPS terminating proxy. The TPM
//! request proof contains a fresh random nonce and binds method, URL and body.
//! Binding each response to that entire proof prevents substitution and replay.
use anyhow::{Context, Result, ensure};
use axum::{
    body::{Body, to_bytes},
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{
    auth_protocol::{PROOF_HEADER, hash, random_secret},
    server::ServerState,
};

pub const RESPONSE_HEADER: &str = "x-mysync-origin";
pub const MAX_JSON_BYTES: usize = 32 * 1024 * 1024;

pub fn public_key(encoded: &str) -> Result<VerifyingKey> {
    let bytes: [u8; 32] = hex::decode(encoded.trim())?
        .try_into()
        .map_err(|_| anyhow::anyhow!("server public key must contain 32 bytes"))?;
    let key = VerifyingKey::from_bytes(&bytes)?;
    ensure!(!key.is_weak(), "weak server public key");
    Ok(key)
}

pub(crate) fn load_key(db: &Connection) -> Result<SigningKey> {
    // The key lives in the private database and is backed up with it. Atomic
    // INSERT avoids generating different keys in concurrent admin processes.
    db.execute(
        "INSERT OR IGNORE INTO auth_settings(key,value) VALUES('origin_signing_key',?1)",
        [random_secret()?],
    )?;
    let value: String = db.query_row(
        "SELECT value FROM auth_settings WHERE key='origin_signing_key'",
        [],
        |r| r.get(0),
    )?;
    let bytes: [u8; 32] = hex::decode(value)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid stored origin key"))?;
    Ok(SigningKey::from_bytes(&bytes))
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseProof {
    request_sha256: String,
    status: u16,
    // None is permitted only for successful file streams, whose bytes are
    // checked against the already authenticated manifest's size and hash.
    pub body_sha256: Option<String>,
    signature: String,
}

impl ResponseProof {
    fn message(&self) -> Result<Vec<u8>> {
        let mut bytes = b"mysync/origin-response/v1\n".to_vec();
        bytes.extend(serde_json::to_vec(&(
            &self.request_sha256,
            self.status,
            &self.body_sha256,
        ))?);
        Ok(bytes)
    }

    pub fn sign(
        key: &SigningKey,
        request_proof: &str,
        status: u16,
        body: Option<&[u8]>,
    ) -> Result<String> {
        let mut proof = Self {
            request_sha256: hash(request_proof),
            status,
            body_sha256: body.map(hash),
            signature: String::new(),
        };
        proof.signature = hex::encode(key.sign(&proof.message()?).to_bytes());
        Ok(B64.encode(serde_json::to_vec(&proof)?))
    }

    pub fn verify(
        encoded: &str,
        key: &VerifyingKey,
        request_proof: &str,
        status: u16,
    ) -> Result<Self> {
        ensure!(encoded.len() <= 2048, "origin response proof too large");
        let proof: Self = serde_json::from_slice(&B64.decode(encoded)?)?;
        ensure!(
            proof.request_sha256 == hash(request_proof) && proof.status == status,
            "origin response request binding mismatch"
        );
        let signature = Signature::from_slice(&hex::decode(&proof.signature)?)?;
        key.verify_strict(&proof.message()?, &signature)
            .context("origin response signature verification failed")?;
        Ok(proof)
    }
}

pub async fn middleware(
    State(state): State<Arc<ServerState>>,
    request: Request,
    next: Next,
) -> Response {
    let request_proof = request
        .headers()
        .get(PROOF_HEADER)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    if request_proof.len() > 4096 {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let request_proof = request_proof.to_owned();
    let file = request.method() == "GET" && request.uri().path() == "/v1/file";
    let response = next.run(request).await;
    let (mut parts, body) = response.into_parts();
    let (body, signature) = if file && parts.status == StatusCode::OK {
        (
            body,
            ResponseProof::sign(
                &state.origin_key,
                &request_proof,
                parts.status.as_u16(),
                None,
            ),
        )
    } else {
        let bytes = match to_bytes(body, MAX_JSON_BYTES).await {
            Ok(bytes) => bytes,
            Err(_) => {
                parts.status = StatusCode::INTERNAL_SERVER_ERROR;
                parts.headers.remove("content-length");
                axum::body::Bytes::from_static(b"{\"error\":\"origin response exceeds limit\"}")
            }
        };
        let signature = ResponseProof::sign(
            &state.origin_key,
            &request_proof,
            parts.status.as_u16(),
            Some(&bytes),
        );
        (Body::from(bytes), signature)
    };
    match signature.and_then(|s| Ok(s.parse()?)) {
        Ok(value) => {
            parts.headers.insert(RESPONSE_HEADER, value);
        }
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
    Response::from_parts(parts, body)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn proof_rejects_replay_status_substitution_and_other_origins() -> Result<()> {
        let key = SigningKey::from_bytes(&[1; 32]);
        let text = ResponseProof::sign(&key, "fresh TPM proof", 200, Some(b"manifest"))?;
        let proof = ResponseProof::verify(&text, &key.verifying_key(), "fresh TPM proof", 200)?;
        assert_eq!(proof.body_sha256, Some(hash(b"manifest")));
        assert!(
            ResponseProof::verify(&text, &key.verifying_key(), "another request", 200).is_err()
        );
        assert!(
            ResponseProof::verify(&text, &key.verifying_key(), "fresh TPM proof", 409).is_err()
        );
        assert!(
            ResponseProof::verify(
                &text,
                &SigningKey::from_bytes(&[2; 32]).verifying_key(),
                "fresh TPM proof",
                200
            )
            .is_err()
        );
        Ok(())
    }
}
