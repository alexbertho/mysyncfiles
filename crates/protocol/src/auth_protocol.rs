//! MySync proof-of-possession profile. This is not an OAuth/DPoP wire format.
//! The signed transcript binds the entire externally visible request, including
//! query and body, and uses a domain separator to prevent cross-protocol reuse.
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use openssl::{
    bn::BigNum,
    ec::{EcGroup, EcKey, EcPoint},
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Public as PublicKey},
    sign::Verifier,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const SESSION_SECONDS: i64 = 15 * 60;
pub const PROOF_HEADER: &str = "x-mysync-proof";
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}
pub fn hash(bytes: impl AsRef<[u8]>) -> String {
    hex::encode(openssl::sha::sha256(bytes.as_ref()))
}
pub fn random_secret() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| anyhow::anyhow!("random generation: {e}"))?;
    Ok(hex::encode(bytes))
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Claims {
    pub version: u8,
    pub device: String,
    pub nonce: String,
    pub issued_at: i64,
    pub method: String,
    pub url_sha256: String,
    pub body_sha256: String,
    pub session_sha256: String,
}
impl Claims {
    pub fn new(device: &str, method: &str, url: &str, body: &[u8], token: &str) -> Result<Self> {
        Ok(Self {
            version: 1,
            device: device.into(),
            nonce: random_secret()?,
            issued_at: now(),
            method: method.into(),
            url_sha256: hash(url),
            body_sha256: hash(body),
            session_sha256: hash(token),
        })
    }
    pub fn message(&self) -> Result<Vec<u8>> {
        let mut message = match self.version {
            1 => b"mysync/request/v1\n".to_vec(),
            2 => b"mysync/session-request/v2\n".to_vec(),
            _ => bail!("unsupported proof version"),
        };
        message.extend(serde_json::to_vec(self)?);
        ensure!(message.len() <= 1024, "proof is too large for TPM hashing");
        Ok(message)
    }
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Proof {
    pub claims: Claims,
    pub signature: String,
}
impl Proof {
    pub fn encode(&self) -> Result<String> {
        Ok(B64.encode(serde_json::to_vec(self)?))
    }
    pub fn decode(text: &str) -> Result<Self> {
        ensure!(text.len() <= 4096, "proof too large");
        Ok(serde_json::from_slice(&B64.decode(text)?)?)
    }
    pub fn verify(
        &self,
        public: &str,
        method: &str,
        url: &str,
        body: &[u8],
        token: &str,
    ) -> Result<()> {
        self.verify_headers(public, method, url, token)?;
        self.verify_body(body)
    }

    /// Authenticate the signed body digest without reading an untrusted body.
    pub fn verify_headers(&self, public: &str, method: &str, url: &str, token: &str) -> Result<()> {
        ensure!(self.claims.version == 1, "TPM proof required");
        self.verify_binding(method, url, token)?;
        let key = signing_public(public)?;
        let signature = hex::decode(&self.signature)?;
        ensure!(signature.len() == 64, "invalid signature size");
        let der = EcdsaSig::from_private_components(
            BigNum::from_slice(&signature[..32])?,
            BigNum::from_slice(&signature[32..])?,
        )?
        .to_der()?;
        let mut verifier = Verifier::new(MessageDigest::sha256(), &key)?;
        ensure!(
            verifier.verify_oneshot(&der, &self.claims.message()?)?,
            "invalid signature"
        );
        Ok(())
    }

    fn verify_binding(&self, method: &str, url: &str, token: &str) -> Result<()> {
        let c = &self.claims;
        let time = now();
        ensure!(
            c.issued_at >= time - 60 && c.issued_at <= time + 30,
            "expired proof"
        );
        ensure!(
            c.nonce.len() == 64 && c.nonce.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid nonce"
        );
        ensure!(
            c.method == method && c.url_sha256 == hash(url) && c.session_sha256 == hash(token),
            "proof request binding mismatch"
        );
        Ok(())
    }

    pub fn session(claims: Claims, key: &ed25519_dalek::SigningKey) -> Result<Self> {
        use ed25519_dalek::Signer;
        let claims = Claims {
            version: 2,
            ..claims
        };
        let signature = hex::encode(key.sign(&claims.message()?).to_bytes());
        Ok(Self { claims, signature })
    }

    pub fn verify_session_headers(
        &self,
        public: &str,
        method: &str,
        url: &str,
        token: &str,
    ) -> Result<()> {
        ensure!(
            self.claims.version == 2 && !token.is_empty(),
            "bound session proof required"
        );
        self.verify_binding(method, url, token)?;
        let key = crate::origin_auth::public_key(public)?;
        let signature = ed25519_dalek::Signature::from_slice(&hex::decode(&self.signature)?)?;
        key.verify_strict(&self.claims.message()?, &signature)
            .context("invalid session signature")
    }

    pub fn verify_body(&self, body: &[u8]) -> Result<()> {
        ensure!(self.claims.body_sha256 == hash(body), "proof body mismatch");
        Ok(())
    }
}

// Decode the narrowly supported TPMT_PUBLIC signing template without linking a
// TPM driver into the server or wire-contract crate. Reject unknown fields,
// algorithms, reserved bits and trailing bytes rather than interpreting them.
fn signing_area(encoded: &str) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    ensure!(encoded.len() <= 4096, "TPM public area too large");
    let bytes = hex::decode(encoded)?;
    let mut input = bytes.as_slice();
    fn take<'a>(input: &mut &'a [u8], len: usize) -> Result<&'a [u8]> {
        ensure!(input.len() >= len, "truncated TPM public area");
        let (value, rest) = input.split_at(len);
        *input = rest;
        Ok(value)
    }
    fn word(input: &mut &[u8]) -> Result<u16> {
        Ok(u16::from_be_bytes(take(input, 2)?.try_into()?))
    }
    fn buffer(input: &mut &[u8], max: usize) -> Result<Vec<u8>> {
        let len = word(input)? as usize;
        ensure!(len <= max, "oversized TPM public field");
        Ok(take(input, len)?.to_vec())
    }
    ensure!(word(&mut input)? == 0x23, "P-256 signing key required");
    ensure!(word(&mut input)? == 0x0b, "SHA256 TPM name required");
    let attrs = u32::from_be_bytes(take(&mut input, 4)?.try_into()?);
    // fixedTPM, fixedParent, sensitiveDataOrigin, userWithAuth, restricted,
    // signEncrypt: precisely the template used by the client.
    ensure!(
        attrs == 0x0005_0072,
        "key is not a restricted TPM signing key"
    );
    ensure!(
        buffer(&mut input, 32)?.is_empty(),
        "unexpected signing policy"
    );
    ensure!(word(&mut input)? == 0x10, "unexpected symmetric algorithm");
    ensure!(word(&mut input)? == 0x18, "ECDSA signing scheme required");
    ensure!(word(&mut input)? == 0x0b, "SHA256 signing scheme required");
    ensure!(word(&mut input)? == 0x03, "P-256 signing key required");
    ensure!(
        word(&mut input)? == 0x10,
        "unexpected key derivation function"
    );
    let x = buffer(&mut input, 32)?;
    let y = buffer(&mut input, 32)?;
    ensure!(
        !x.is_empty() && !y.is_empty() && input.is_empty(),
        "invalid TPM public area"
    );
    Ok((bytes, x, y))
}

pub fn signing_public(encoded: &str) -> Result<PKey<PublicKey>> {
    let (_, x, y) = signing_area(encoded)?;
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let mut ctx = openssl::bn::BigNumContext::new()?;
    let mut point = EcPoint::new(&group)?;
    let x = BigNum::from_slice(&x)?;
    let y = BigNum::from_slice(&y)?;
    point.set_affine_coordinates_gfp(&group, &x, &y, &mut ctx)?;
    let ec = EcKey::from_public_key(&group, &point)?;
    ec.check_key()?;
    Ok(PKey::from_ec_key(ec)?)
}
pub fn key_name(encoded: &str) -> Result<Vec<u8>> {
    let (public, _, _) = signing_area(encoded)?;
    let mut bytes = vec![0, 0x0b];
    bytes.extend(Sha256::digest(public));
    Ok(bytes)
}
pub fn fingerprint(public: &str) -> Result<String> {
    Ok(hash(signing_public(public)?.public_key_to_der()?))
}

#[cfg(test)]
mod proof_tests {
    use super::*;

    // The P-256 generator encoded in the client's restricted signing template.
    const AREA: &str = concat!(
        "0023000b00050072000000100018000b000300100020",
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "0020",
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
    );

    #[test]
    fn signing_template_rejects_truncation_changed_algorithms_and_exportable_keys() -> Result<()> {
        signing_public(AREA)?;
        let bytes = hex::decode(AREA)?;
        for length in 0..bytes.len() {
            assert!(signing_public(&hex::encode(&bytes[..length])).is_err());
        }
        assert!(signing_public(&format!("{AREA}00")).is_err());
        // Every field in the header is fixed, including fixedTPM/fixedParent,
        // the empty policy, ECDSA/SHA256, P-256 and coordinate lengths.
        for offset in 0..22 {
            let mut changed = bytes.clone();
            changed[offset] ^= 1;
            assert!(
                signing_public(&hex::encode(changed)).is_err(),
                "byte {offset}"
            );
        }
        let mut invalid_point = bytes;
        invalid_point[22..54].fill(0);
        invalid_point[56..].fill(0);
        assert!(signing_public(&hex::encode(invalid_point)).is_err());
        Ok(())
    }

    #[test]
    fn session_proof_binds_body_token_method_url_and_signature_domain() -> Result<()> {
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let public = hex::encode(key.verifying_key().to_bytes());
        let url = "https://sync.example.test/v1/manifest?summary=true";
        let mut proof =
            Proof::session(Claims::new("device", "POST", url, b"body", "token")?, &key)?;
        proof.verify_session_headers(&public, "POST", url, "token")?;
        proof.verify_body(b"body")?;
        assert!(proof.verify_body(b"changed").is_err());
        for (method, address, token) in [
            ("GET", url, "token"),
            (
                "POST",
                "https://other.example.test/v1/manifest?summary=true",
                "token",
            ),
            ("POST", url, "other"),
            ("POST", url, ""),
        ] {
            assert!(
                proof
                    .verify_session_headers(&public, method, address, token)
                    .is_err()
            );
        }
        assert!(proof.verify_headers(AREA, "POST", url, "token").is_err());
        proof.claims.version = 1;
        assert!(
            proof
                .verify_session_headers(&public, "POST", url, "token")
                .is_err()
        );
        proof.claims.version = 2;
        proof.claims.device = "another-device".into();
        assert!(
            proof
                .verify_session_headers(&public, "POST", url, "token")
                .is_err()
        );
        Ok(())
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollStart {
    pub invitation: String,
    pub public: String,
    pub ek_chain: Vec<String>,
}
#[derive(Clone, Deserialize, Serialize)]
pub struct EnrollChallenge {
    pub id: String,
    pub credential: String,
    pub secret: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollFinish {
    pub id: String,
    pub activation: String,
}
#[derive(Deserialize, Serialize)]
pub struct Enrollment {
    pub id: String,
    pub fingerprint: String,
    pub status: String,
}
pub const PROTOCOL_VERSION: u8 = 2;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRequest {
    pub version: u8,
    pub public_key: String,
}

/// These operations always require a fresh TPM signature, even within a session.
pub fn requires_tpm(path: &str) -> bool {
    matches!(path, "/v1/auth/session")
        || path == crate::web_status_protocol::PROOFS_PATH
        || path == crate::editor_protocol::AUTHORIZE_PATH
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServerInfo {
    pub protocol: u8,
    pub name: String,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct Session {
    pub token: String,
    pub expires_at: i64,
}

pub fn validate_server_url(server: &str) -> Result<()> {
    let url = url::Url::parse(server).context("invalid server URL")?;
    let host = url.host_str().unwrap_or_default();
    let local = matches!(host, "localhost" | "127.0.0.1" | "[::1]");
    if url.scheme() != "https" && !(url.scheme() == "http" && local) {
        bail!("server URL must use HTTPS (HTTP is allowed only on loopback)");
    }
    if url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        bail!("server URL must not contain credentials, a query, or a fragment");
    }
    if !matches!(url.path(), "" | "/") {
        bail!("server URL must point to the origin root without a path prefix");
    }
    Ok(())
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
