use crate::auth_protocol::{self, Claims, EnrollChallenge, Proof};
use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use tss_esapi::{
    Context, TctiNameConf,
    abstraction::{AsymmetricAlgorithmSelection, ek},
    attributes::{ObjectAttributesBuilder, SessionAttributesBuilder},
    constants::SessionType,
    handles::{AuthHandle, KeyHandle, SessionHandle},
    interface_types::{
        algorithm::{EccSchemeAlgorithm, HashingAlgorithm, PublicAlgorithm},
        ecc::EccCurve,
        key_bits::RsaKeyBits,
        resource_handles::Hierarchy,
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
    pub fn ek_certificate(&self) -> Result<Vec<u8>> {
        Ok(ek::retrieve_ek_pubcert(
            &mut context(&self.tcti)?,
            algorithm(&self.ek_kind)?,
        )?)
    }
    pub fn create(tcti: &str, kind: &str) -> Result<(Self, Vec<u8>)> {
        let mut ctx = context(tcti)?;
        let alg = algorithm(kind)?;
        let certificate = ek::retrieve_ek_pubcert(&mut ctx, alg)
            .context("TPM has no readable manufacturer EK certificate")?;
        let parent = ek::create_ek_object_2(&mut ctx, alg, None)?;
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
        let message = claims.message()?;
        let (mut ctx, _, key) = self.loaded()?;
        let (digest, ticket) = ctx.execute_without_session(|ctx| {
            ctx.hash(
                message.try_into()?,
                HashingAlgorithm::Sha256,
                Hierarchy::Owner,
            )
        })?;
        let signature = ctx.execute_with_nullauth_session(|ctx| {
            ctx.sign(key, digest, SignatureScheme::Null, ticket)
        })?;
        let Signature::EcDsa(signature) = signature else {
            bail!("TPM returned an unexpected signature");
        };
        let mut bytes = Vec::new();
        for component in [signature.signature_r(), signature.signature_s()] {
            let value = component.value();
            anyhow::ensure!(value.len() <= 32, "invalid ECDSA component");
            bytes.extend(vec![0; 32 - value.len()]);
            bytes.extend(value);
        }
        Proof {
            claims,
            signature: hex::encode(bytes),
        }
        .encode()
    }
    pub fn fingerprint(&self) -> Result<String> {
        auth_protocol::fingerprint(&self.public)
    }
}
