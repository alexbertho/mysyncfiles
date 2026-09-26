use crate::auth_protocol::{self, Claims, EnrollChallenge, Proof};
use anyhow::{Context as _, Result, bail, ensure};
use openssl::bn::{BigNum, BigNumContext};
use openssl::nid::Nid;
use openssl::x509::X509;
use serde::{Deserialize, Serialize};
use std::{io::Read, path::Path, str::FromStr};
use tokio::sync::{mpsc, oneshot};
use tss_esapi::{
    Context, TctiNameConf,
    abstraction::{AsymmetricAlgorithmSelection, ek, nv},
    attributes::{ObjectAttributesBuilder, SessionAttributesBuilder},
    constants::SessionType,
    handles::{AuthHandle, KeyHandle, NvIndexTpmHandle, SessionHandle},
    interface_types::{
        algorithm::{EccSchemeAlgorithm, HashingAlgorithm, PublicAlgorithm},
        ecc::EccCurve,
        key_bits::RsaKeyBits,
        resource_handles::{Hierarchy, NvAuth},
        session_handles::{AuthSession, PolicySession},
    },
    structures::{
        EccPoint, EccScheme, KeyDerivationFunctionScheme, Private, Public, PublicBuilder,
        PublicEccParametersBuilder, Signature, SignatureScheme, SymmetricDefinition,
        SymmetricDefinitionObject,
    },
    traits::{Marshall, UnMarshall},
};

/// Opaque TPM-wrapped private material is unusable on another TPM. It is never
/// an exported software private key. EK certificates are only used at enrollment.
#[derive(Clone, Deserialize, Serialize)]
pub struct Identity {
    pub device: String,
    pub public: String,
    pub private: String,
    pub ek_kind: String,
    #[serde(default = "default_tcti")]
    pub tcti: String,
}

/// Serializes TPM operations on one dedicated thread and keeps the loaded key
/// for the lifetime of an API client. Every call still signs fresh claims.
pub struct RequestSigner {
    sender: Option<mpsc::Sender<(Claims, oneshot::Sender<Result<String>>)>>,
    device: String,
    worker: Option<std::thread::JoinHandle<()>>,
}

struct LoadedSigner {
    ctx: Context,
    key: KeyHandle,
}

impl RequestSigner {
    pub fn new(identity: Identity) -> Result<Self> {
        let device = identity.device.clone();
        let (sender, mut receiver) = mpsc::channel::<(Claims, oneshot::Sender<Result<String>>)>(8);
        let worker = std::thread::Builder::new()
            .name("mysync-tpm-signer".into())
            .spawn(move || {
                // Context is owned and used only by this thread; it never has
                // to cross an async suspension point or run concurrently.
                let mut loaded: Option<LoadedSigner> = None;
                while let Some((claims, reply)) = receiver.blocking_recv() {
                    if reply.is_closed() {
                        continue;
                    }
                    let result = (|| {
                        if loaded.is_none() {
                            loaded = Some(identity.load_signer()?);
                        }
                        loaded.as_mut().expect("signer was loaded").proof(claims)
                    })();
                    // A failed TPM command may have invalidated a transient
                    // handle. Reopen the key on the next request, failing this
                    // one closed instead of silently retrying its proof.
                    if result.is_err() {
                        loaded = None;
                    }
                    let _ = reply.send(result);
                }
            })?;
        Ok(Self {
            sender: Some(sender),
            device,
            worker: Some(worker),
        })
    }

    pub fn device(&self) -> &str {
        &self.device
    }

    pub async fn proof(&self, claims: Claims) -> Result<String> {
        let (reply, result) = oneshot::channel();
        self.sender
            .as_ref()
            .context("TPM signer stopped")?
            .send((claims, reply))
            .await
            .context("TPM signer stopped")?;
        result.await.context("TPM signer stopped")?
    }
}

impl Drop for RequestSigner {
    fn drop(&mut self) {
        // Closing the channel lets the worker drop its Context, flushing its
        // transient TPM handles before another API instance needs them.
        self.sender.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl LoadedSigner {
    fn proof(&mut self, claims: Claims) -> Result<String> {
        let message = claims.message()?;
        let (digest, ticket) = self.ctx.execute_without_session(|ctx| {
            ctx.hash(
                message.try_into()?,
                HashingAlgorithm::Sha256,
                Hierarchy::Owner,
            )
        })?;
        let signature = self.ctx.execute_with_nullauth_session(|ctx| {
            ctx.sign(self.key, digest, SignatureScheme::Null, ticket)
        })?;
        let Signature::EcDsa(signature) = signature else {
            bail!("TPM returned an unexpected signature");
        };
        let mut bytes = Vec::new();
        for component in [signature.signature_r(), signature.signature_s()] {
            let value = component.value();
            ensure!(value.len() <= 32, "invalid ECDSA component");
            bytes.extend(vec![0; 32 - value.len()]);
            bytes.extend(value);
        }
        Proof {
            claims,
            signature: hex::encode(bytes),
        }
        .encode()
    }
}
pub fn default_tcti() -> String {
    "device:/dev/tpmrm0".into()
}
fn algorithm(kind: &str) -> Result<AsymmetricAlgorithmSelection> {
    match kind {
        "rsa" => Ok(AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa2048)),
        "ecc" => Ok(AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP256)),
        _ => bail!("unsupported EK algorithm"),
    }
}
fn context(tcti: &str) -> Result<Context> {
    Context::new(TctiNameConf::from_str(tcti)?)
        .context("opening TPM 2.0; check /dev/tpmrm0 access and TPM dependencies")
}

const MAX_EK_CERT_BYTES: u64 = 16 * 1024;
const INTEL_EK_CHAIN_NV_INDEX: u32 = 0x01c00100;
const INTEL_EK_CHAIN_NV_LAST_INDEX: u32 = 0x01c001ff;
const MAX_EK_CHAIN_NV_BYTES: usize = 128 * 1024;
const MAX_EK_CHAIN_NV_CERTIFICATES: usize = 64;

/// Intel PTT may store its per-device issuing certificates as concatenated DER
/// across the TCG EK chain NV index range. Treat the bytes as untrusted: the
/// server verifies the selected chain against its configured manufacturer roots.
fn certificates_from_nv_chain(bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_EK_CHAIN_NV_BYTES,
        "TPM EK chain is empty or too large"
    );
    let mut certificates = Vec::new();
    let mut offset = 0;
    while offset + 2 <= bytes.len() {
        if bytes[offset] != 0x30 {
            offset += 1;
            continue;
        }
        let (header, length) = match bytes[offset + 1] {
            n @ 0..=127 => (2, n as usize),
            0x81 if offset + 3 <= bytes.len() => (3, bytes[offset + 2] as usize),
            0x82 if offset + 4 <= bytes.len() => (
                4,
                u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize,
            ),
            _ => {
                offset += 1;
                continue;
            }
        };
        let Some(end) = offset.checked_add(header + length) else {
            bail!("invalid TPM EK chain length");
        };
        if length < 128 || end > bytes.len() || header + length > MAX_EK_CERT_BYTES as usize {
            offset += 1;
            continue;
        }
        let candidate = &bytes[offset..end];
        if let Ok(cert) = X509::from_der(candidate)
            && cert.to_der()? == candidate
        {
            ensure!(
                certificates.len() < MAX_EK_CHAIN_NV_CERTIFICATES,
                "too many TPM EK chain certificates"
            );
            certificates.push(candidate.to_vec());
            offset = end;
            continue;
        }
        offset += 1;
    }
    ensure!(
        !certificates.is_empty(),
        "TPM EK chain contains no DER certificates"
    );
    Ok(certificates)
}

/// Read an explicitly supplied manufacturer certificate without unbounded I/O.
/// Trust in its issuer is established by the server, not by this parser.
pub fn read_ek_certificate(path: &Path) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .with_context(|| format!("opening EK certificate {}", path.display()))?
        .take(MAX_EK_CERT_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        !bytes.is_empty() && bytes.len() as u64 <= MAX_EK_CERT_BYTES,
        "EK certificate is empty or exceeds 16 KiB"
    );
    let certificate = X509::from_der(&bytes).context("EK certificate must be DER")?;
    ensure!(
        certificate.to_der()? == bytes,
        "EK certificate must contain exactly one canonical DER certificate"
    );
    Ok(bytes)
}

pub fn certificate_kind(certificate: &[u8]) -> Result<&'static str> {
    ensure!(
        certificate.len() as u64 <= MAX_EK_CERT_BYTES,
        "EK certificate is too large"
    );
    let key = X509::from_der(certificate)?.public_key()?;
    if let Ok(rsa) = key.rsa() {
        ensure!(rsa.size() == 256, "EK certificate must use RSA-2048");
        return Ok("rsa");
    }
    if let Ok(ec) = key.ec_key() {
        ensure!(
            ec.group().curve_name() == Some(Nid::X9_62_PRIME256V1),
            "EK certificate must use P-256"
        );
        return Ok("ecc");
    }
    bail!("unsupported EK certificate public key")
}

fn matching_ek(
    ctx: &mut Context,
    alg: AsymmetricAlgorithmSelection,
    certificate: &[u8],
) -> Result<KeyHandle> {
    let cert = X509::from_der(certificate).context("invalid EK certificate")?;
    ensure!(
        cert.to_der()? == certificate,
        "EK certificate must contain exactly one canonical DER certificate"
    );
    let key = cert.public_key()?;
    let parent =
        ek::create_ek_object_2(ctx, alg, None).context("creating the TPM endorsement key")?;
    let (public, _, _) = ctx.read_public(parent)?;
    match public {
        Public::Rsa {
            unique, parameters, ..
        } => {
            let rsa = key
                .rsa()
                .context("EK certificate algorithm differs from TPM EK")?;
            let exponent = match parameters.exponent().value() {
                0 => 65537,
                value => value,
            };
            ensure!(
                rsa.n().to_vec() == BigNum::from_slice(unique.value())?.to_vec()
                    && rsa.e().to_vec() == BigNum::from_u32(exponent)?.to_vec(),
                "EK certificate public key does not match this TPM"
            );
        }
        Public::Ecc {
            unique, parameters, ..
        } => {
            ensure!(
                parameters.ecc_curve() == EccCurve::NistP256,
                "unsupported TPM EK curve"
            );
            let ec = key
                .ec_key()
                .context("EK certificate algorithm differs from TPM EK")?;
            ensure!(
                ec.group().curve_name() == Some(Nid::X9_62_PRIME256V1),
                "EK certificate must use P-256"
            );
            let mut x = BigNum::new()?;
            let mut y = BigNum::new()?;
            let mut bn_context = BigNumContext::new()?;
            ec.public_key()
                .affine_coordinates_gfp(ec.group(), &mut x, &mut y, &mut bn_context)?;
            ensure!(
                x.to_vec() == BigNum::from_slice(unique.x().value())?.to_vec()
                    && y.to_vec() == BigNum::from_slice(unique.y().value())?.to_vec(),
                "EK certificate public key does not match this TPM"
            );
        }
        _ => bail!("unexpected TPM EK algorithm"),
    }
    Ok(parent)
}

/// A read-only preflight for installation. Enrollment still performs the full
/// manufacturer-chain verification against the server's configured EK roots.
pub fn doctor(tcti: &str) -> Result<&'static str> {
    doctor_with_certificate(tcti, None)
}

pub fn doctor_with_certificate(tcti: &str, external: Option<&[u8]>) -> Result<&'static str> {
    if tcti == default_tcti() {
        let device = Path::new("/dev/tpmrm0");
        if !device.exists() {
            bail!("TPM 2.0 is unavailable: /dev/tpmrm0 is missing; enable the TPM in firmware");
        }
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(device)
            .context(
                "cannot access /dev/tpmrm0; check TPM device permissions and your group membership",
            )?;
    }
    let mut ctx = context(tcti)?;
    if let Some(certificate) = external {
        let kind = certificate_kind(certificate)?;
        matching_ek(&mut ctx, algorithm(kind)?, certificate)?;
        return Ok(kind);
    }
    for (kind, selection) in [
        (
            "rsa",
            AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa2048),
        ),
        ("ecc", AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP256)),
    ] {
        if let Ok(certificate) = ek::retrieve_ek_pubcert(&mut ctx, selection)
            && matching_ek(&mut ctx, selection, &certificate).is_ok()
        {
            return Ok(kind);
        }
    }
    bail!("TPM 2.0 is reachable, but no readable RSA-2048 or P-256 EK certificate was found")
}

/// The low-range RSA-2048 and P-256 EK profiles both use SHA-256 PolicySecret.
/// Salt the session with the EK: unlike an unsalted policy session with an empty
/// auth value, this authenticates the response and actually protects parameters.
/// It also avoids tpm2-tss 4.2's empty-policy-HMAC path, which skips updating the
/// response nonce before decrypting Create's returned private blob.
fn ek_policy(ctx: &mut Context, parent: KeyHandle) -> Result<AuthSession> {
    let session = ctx
        .start_auth_session(
            Some(parent),
            None,
            None,
            SessionType::Policy,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )?
        .context("missing salted EK policy session")?;
    ctx.execute_with_nullauth_session(|ctx| {
        ctx.policy_secret(
            PolicySession::try_from(session)?,
            AuthHandle::Endorsement,
            Default::default(),
            Default::default(),
            Default::default(),
            None,
        )
    })?;
    let (attributes, mask) = SessionAttributesBuilder::new()
        .with_decrypt(true)
        .with_encrypt(true)
        .build();
    ctx.tr_sess_set_attributes(session, attributes, mask)?;
    Ok(session)
}

fn signing_template() -> Result<Public> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_restricted(true)
        .with_sign_encrypt(true)
        .with_decrypt(false)
        .with_user_with_auth(true)
        .build()?;
    Ok(PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_ecc_parameters(
            PublicEccParametersBuilder::new()
                .with_symmetric(SymmetricDefinitionObject::Null)
                .with_ecc_scheme(EccScheme::create(
                    EccSchemeAlgorithm::EcDsa,
                    Some(HashingAlgorithm::Sha256),
                    None,
                )?)
                .with_curve(EccCurve::NistP256)
                .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
                .build()?,
        )
        .with_ecc_unique_identifier(EccPoint::default())
        .build()?)
}
impl Identity {
    /// Read optional manufacturer intermediates from the contiguous TCG NV
    /// index range. A missing first index is normal for TPMs without a chain.
    pub fn ek_intermediates(&self) -> Result<Vec<Vec<u8>>> {
        let mut ctx = context(&self.tcti)?;
        let indices = nv::list(&mut ctx)?;
        let mut bytes = Vec::new();
        for number in INTEL_EK_CHAIN_NV_INDEX..=INTEL_EK_CHAIN_NV_LAST_INDEX {
            let index = NvIndexTpmHandle::new(number)?;
            let Some((public, _)) = indices
                .iter()
                .find(|(public, _)| public.nv_index() == index)
            else {
                break;
            };
            ensure!(
                public.data_size() > 0 && public.data_size() <= MAX_EK_CHAIN_NV_BYTES - bytes.len(),
                "TPM EK chain NV indices are empty or too large"
            );
            let auth = if public.attributes().owner_read() {
                NvAuth::Owner
            } else if public.attributes().auth_read() {
                let handle =
                    ctx.execute_without_session(|ctx| ctx.tr_from_tpm_public(index.into()))?;
                NvAuth::NvIndex(handle.into())
            } else {
                bail!("TPM EK chain NV index is not readable without a hierarchy password");
            };
            let part = ctx
                .execute_with_nullauth_session(|ctx| nv::read_full(ctx, auth, index))
                .with_context(|| format!("reading TPM EK chain NV index {number:#010x}"))?;
            ensure!(
                part.len() == public.data_size(),
                "TPM EK chain NV index size changed during reading"
            );
            bytes.extend_from_slice(&part);
        }
        if bytes.is_empty() {
            return Ok(Vec::new());
        }
        certificates_from_nv_chain(&bytes)
    }

    pub fn ek_certificate(&self) -> Result<Vec<u8>> {
        let mut ctx = context(&self.tcti)?;
        let alg = algorithm(&self.ek_kind)?;
        let certificate = ek::retrieve_ek_pubcert(&mut ctx, alg)
            .context("TPM has no readable EK certificate; supply --ek-cert with a manufacturer DER certificate")?;
        matching_ek(&mut ctx, alg, &certificate)?;
        Ok(certificate)
    }
    pub fn ek_certificate_from(&self, certificate: &[u8]) -> Result<Vec<u8>> {
        let mut ctx = context(&self.tcti)?;
        matching_ek(&mut ctx, algorithm(&self.ek_kind)?, certificate)?;
        Ok(certificate.to_vec())
    }
    pub fn create(tcti: &str, kind: &str) -> Result<(Self, Vec<u8>)> {
        Self::create_with_certificate(tcti, kind, None)
    }
    pub fn create_with_certificate(
        tcti: &str,
        kind: &str,
        external: Option<&[u8]>,
    ) -> Result<(Self, Vec<u8>)> {
        let mut ctx = context(tcti)?;
        let alg = algorithm(kind)?;
        let certificate = if let Some(certificate) = external {
            ensure!(
                certificate_kind(certificate)? == kind,
                "EK certificate algorithm differs from selected EK"
            );
            certificate.to_vec()
        } else {
            ek::retrieve_ek_pubcert(&mut ctx, alg)
                .context("TPM has no readable manufacturer EK certificate; supply --ek-cert with a manufacturer DER certificate")?
        };
        let parent = matching_ek(&mut ctx, alg, &certificate)?;
        let template = signing_template()?;
        let session = ek_policy(&mut ctx, parent)?;
        let created =
            ctx.execute_with_temporary_object(SessionHandle::from(session).into(), |ctx, _| {
                ctx.execute_with_session(Some(session), |ctx| {
                    ctx.create(parent, template, None, None, None, None)
                })
            })?;
        Ok((
            Self {
                device: String::new(),
                public: hex::encode(created.out_public.marshall()?),
                private: hex::encode(created.out_private.value()),
                ek_kind: kind.into(),
                tcti: tcti.into(),
            },
            certificate,
        ))
    }
    fn loaded(
        &self,
    ) -> Result<(
        Context,
        tss_esapi::handles::KeyHandle,
        tss_esapi::handles::KeyHandle,
    )> {
        let mut ctx = context(&self.tcti)?;
        let parent = ek::create_ek_object_2(&mut ctx, algorithm(&self.ek_kind)?, None)?;
        let private = Private::try_from(hex::decode(&self.private)?)?;
        let public = Public::unmarshall(&hex::decode(&self.public)?)?;
        let session = ek_policy(&mut ctx, parent)?;
        let key =
            ctx.execute_with_temporary_object(SessionHandle::from(session).into(), |ctx, _| {
                ctx.execute_with_session(Some(session), |ctx| ctx.load(parent, private, public))
            })?;
        Ok((ctx, parent, key))
    }
    fn load_signer(&self) -> Result<LoadedSigner> {
        let (mut ctx, parent, key) = self.loaded()?;
        // The signing key is independent once loaded. Releasing its EK parent
        // leaves a TPM object slot for another process (or a one-shot CLI).
        ctx.flush_context(parent.into())?;
        Ok(LoadedSigner { ctx, key })
    }
    pub fn activate(&self, challenge: &EnrollChallenge) -> Result<String> {
        let blob = tss_esapi::structures::IdObject::try_from(hex::decode(&challenge.credential)?)?;
        let secret =
            tss_esapi::structures::EncryptedSecret::try_from(hex::decode(&challenge.secret)?)?;
        let (mut ctx, parent, key) = self.loaded()?;
        let session = ek_policy(&mut ctx, parent)?;
        let credential = ctx
            .execute_with_sessions((Some(AuthSession::Password), Some(session), None), |ctx| {
                ctx.activate_credential(key, parent, blob, secret)
            })?;
        Ok(hex::encode(credential.value()))
    }
    pub fn proof(&self, claims: Claims) -> Result<String> {
        self.load_signer()?.proof(claims)
    }
    pub fn fingerprint(&self) -> Result<String> {
        auth_protocol::fingerprint(&self.public)
    }
}
