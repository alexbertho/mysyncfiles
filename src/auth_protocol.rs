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
use tss_esapi::{
    interface_types::{algorithm::HashingAlgorithm, ecc::EccCurve},
    structures::Public,
    traits::{Marshall, UnMarshall},
};

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
        let mut message = b"mysync/request/v1\n".to_vec();
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
        let c = &self.claims;
        let time = now();
        ensure!(
            c.version == 1 && c.issued_at >= time - 60 && c.issued_at <= time + 30,
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
            verifier.verify_oneshot(&der, &c.message()?)?,
            "invalid signature"
        );
        Ok(())
    }

    pub fn verify_body(&self, body: &[u8]) -> Result<()> {
        ensure!(self.claims.body_sha256 == hash(body), "proof body mismatch");
        Ok(())
    }
}

pub fn public_area(encoded: &str) -> Result<Public> {
    ensure!(encoded.len() <= 4096, "TPM public area too large");
    let bytes = hex::decode(encoded)?;
    let public = Public::unmarshall(&bytes)?;
    ensure!(public.marshall()? == bytes, "noncanonical TPM public area");
    Ok(public)
}
pub fn signing_public(encoded: &str) -> Result<PKey<PublicKey>> {
    let public = public_area(encoded)?;
    let attrs = public.object_attributes();
    ensure!(
        attrs.fixed_tpm()
            && attrs.fixed_parent()
            && attrs.sensitive_data_origin()
            && attrs.restricted()
            && attrs.sign_encrypt()
            && !attrs.decrypt()
            && public.name_hashing_algorithm() == HashingAlgorithm::Sha256,
        "key is not a restricted TPM signing key"
    );
    match public {
        Public::Ecc {
            parameters, unique, ..
        } if parameters.ecc_curve() == EccCurve::NistP256 => {
            let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
            let mut ctx = openssl::bn::BigNumContext::new()?;
            let mut point = EcPoint::new(&group)?;
            let x = BigNum::from_slice(unique.x().value())?;
            let y = BigNum::from_slice(unique.y().value())?;
            point.set_affine_coordinates_gfp(&group, &x, &y, &mut ctx)?;
            let ec = EcKey::from_public_key(&group, &point)?;
            ec.check_key()?;
            Ok(PKey::from_ec_key(ec)?)
        }
        _ => bail!("P-256 signing key required"),
    }
}
pub fn key_name(encoded: &str) -> Result<Vec<u8>> {
    let public = public_area(encoded)?;
    ensure!(
        public.name_hashing_algorithm() == HashingAlgorithm::Sha256,
        "SHA256 TPM name required"
    );
    let mut bytes = vec![0, 0x0b];
    bytes.extend(Sha256::digest(public.marshall()?));
    Ok(bytes)
}
pub fn fingerprint(public: &str) -> Result<String> {
    Ok(hash(signing_public(public)?.public_key_to_der()?))
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
#[derive(Clone, Deserialize, Serialize)]
pub struct Session {
    pub token: String,
    pub expires_at: i64,
}

pub(crate) fn validate_server_url(server: &str) -> Result<()> {
    let url = reqwest::Url::parse(server).context("invalid server URL")?;
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
