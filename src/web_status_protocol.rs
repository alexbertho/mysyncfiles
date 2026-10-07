//! Short-lived browser challenges. Only the pinned origin key can issue tickets;
//! the existing TPM HTTP proof binds the complete presence submission.
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

pub const PORT: u16 = 47831;
pub const MAX_TICKET_BYTES: usize = 2048;
pub const MAX_JSON_BYTES: usize = 4096;
pub const CHALLENGE_SECONDS: i64 = 60;
pub const SESSION_SECONDS: i64 = 300;
pub const PRESENCE_SECONDS: i64 = 120;
pub const FILES_SESSION_SECONDS: i64 = 30 * 60;
pub const PROOFS_PATH: &str = "/v1/web/status/proofs";
pub const BRIDGE_HEADER: &str = "x-mysync-bridge";
pub const CHALLENGE_HEADER: &str = "x-mysync-challenge";
const DOMAIN: &[u8] = b"mysync/web-status-challenge/v1\n";

pub fn valid_secret(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Matches the existing transport policy: HTTPS, or HTTP on literal loopback
/// / localhost for isolated development. Never derives trust from proxy headers.
pub fn origin(server: &str) -> Result<String> {
    crate::auth_protocol::validate_server_url(server)?;
    let url = reqwest::Url::parse(server)?;
    Ok(url.origin().ascii_serialization())
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    pub version: u8,
    pub challenge_id: String,
    pub session_binding: String,
    pub origin: String,
    pub audience: String,
    pub scope: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub expected_device_id: Option<i64>,
}

impl Challenge {
    pub fn sign(&self, key: &SigningKey) -> Result<String> {
        let bytes = serde_json::to_vec(self)?;
        let signature = key.sign(&[DOMAIN, &bytes].concat());
        let ticket = format!("{}.{}", B64.encode(bytes), B64.encode(signature.to_bytes()));
        ensure!(ticket.len() <= MAX_TICKET_BYTES, "ticket_too_large");
        Ok(ticket)
    }

    pub fn verify(ticket: &str, key: &VerifyingKey, audience: &str, time: i64) -> Result<Self> {
        ensure!(ticket.len() <= MAX_TICKET_BYTES, "ticket_too_large");
        let (payload, signature) = ticket
            .split_once('.')
            .ok_or_else(|| anyhow::anyhow!("invalid_ticket"))?;
        let bytes = B64.decode(payload)?;
        let signature = Signature::from_slice(&B64.decode(signature)?)?;
        // Authenticate the original bytes before parsing any claims.
        key.verify_strict(&[DOMAIN, &bytes].concat(), &signature)?;
        let claims: Self = serde_json::from_slice(&bytes)?;
        ensure!(
            claims.version == 1
                && matches!(
                    claims.scope.as_str(),
                    "status.read" | "files.read" | "files.write"
                ),
            "invalid_scope"
        );
        ensure!(
            valid_secret(&claims.challenge_id) && valid_secret(&claims.session_binding),
            "invalid_binding"
        );
        ensure!(
            claims.origin == audience && claims.audience == audience,
            "wrong_audience"
        );
        ensure!(
            claims.issued_at >= time - CHALLENGE_SECONDS
                && claims.issued_at <= time + 5
                && claims.expires_at > time
                && claims.expires_at > claims.issued_at
                && claims.expires_at <= claims.issued_at.saturating_add(CHALLENGE_SECONDS),
            "challenge_expired"
        );
        ensure!(
            claims.expected_device_id.is_none_or(|id| id > 0),
            "invalid_device"
        );
        Ok(claims)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DaemonState {
    Starting,
    Idle,
    Syncing,
    Error,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CommunicationState {
    Unknown,
    Authenticated,
    Failed,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StatusError {
    SyncFailed,
    CommunicationFailed,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LocalStatus {
    pub api_version: u8,
    pub client_version: String,
    pub daemon_state: DaemonState,
    pub communication: CommunicationState,
    pub observed_at: i64,
    pub last_authenticated_at: Option<i64>,
    pub error: Option<StatusError>,
}

impl LocalStatus {
    pub fn validate(&self, time: i64) -> Result<()> {
        ensure!(
            self.api_version == 1
                && self.client_version.len() <= 64
                && semver::Version::parse(&self.client_version).is_ok(),
            "invalid_status"
        );
        ensure!(
            self.observed_at >= time - CHALLENGE_SECONDS
                && self.observed_at <= time + 30
                && self
                    .last_authenticated_at
                    .is_none_or(|t| t > 0 && t <= time + 30),
            "invalid_observation"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PresenceProof {
    pub ticket: String,
    pub observed_origin: String,
    pub instance_id: String,
    pub status: LocalStatus,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeResponse {
    pub challenge_id: String,
    pub ticket: String,
    pub expires_at: i64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProofAccepted {
    pub challenge_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedPresence {
    pub challenge_id: String,
    pub device_id: i64,
    pub device_name: String,
    pub instance_id: String,
    pub status: LocalStatus,
    pub verified_at: i64,
    pub presence_expires_at: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tickets_bind_every_claim_and_expire() -> Result<()> {
        let key = SigningKey::from_bytes(&[7; 32]);
        let audience = "https://sync.example.com";
        let mut claims = Challenge {
            version: 1,
            challenge_id: "a".repeat(64),
            session_binding: "b".repeat(64),
            origin: audience.into(),
            audience: audience.into(),
            scope: "status.read".into(),
            issued_at: 100,
            expires_at: 160,
            expected_device_id: None,
        };
        let ticket = claims.sign(&key)?;
        assert_eq!(
            Challenge::verify(&ticket, &key.verifying_key(), audience, 100)?,
            claims
        );
        for time in [94, 160, 200] {
            assert!(Challenge::verify(&ticket, &key.verifying_key(), audience, time).is_err());
        }
        assert!(
            Challenge::verify(
                &ticket,
                &key.verifying_key(),
                "https://other.example.com",
                110
            )
            .is_err()
        );
        assert!(
            Challenge::verify(
                &ticket,
                &SigningKey::from_bytes(&[8; 32]).verifying_key(),
                audience,
                110
            )
            .is_err()
        );
        claims.expected_device_id = Some(2);
        let changed = claims.sign(&key)?;
        let forged = format!(
            "{}.{}",
            changed.split_once('.').unwrap().0,
            ticket.split_once('.').unwrap().1
        );
        assert!(Challenge::verify(&forged, &key.verifying_key(), audience, 110).is_err());
        assert!(Challenge::verify(&"x".repeat(2049), &key.verifying_key(), audience, 110).is_err());
        Ok(())
    }
}
