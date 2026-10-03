//! Resumable pairing and manufacturer EK certificate discovery.
use super::api::{CONTROL_JSON_LIMIT, JSON_TIMEOUT, bounded_json};
use super::{
    Api, ClientConfig, SyncReport, acquire_lock, default_update_public_key, load_config,
    private_write_json, status, sync,
};
use crate::auth_protocol::validate_server_url;
use anyhow::{Context, Result, anyhow, bail, ensure};
use futures_util::StreamExt;
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

const EK_ISSUER_LIMIT: usize = 16 * 1024;

fn allowed_intel_ca_issuer_url(uri: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(uri)?;
    ensure!(
        url.scheme() == "https"
            && url.host_str() == Some("tsci.intel.com")
            && url.port_or_known_default() == Some(443)
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.path().starts_with("/content/OnDieCA/certs/"),
        "TPM EK issuer URL is outside Intel's HTTPS certificate repository"
    );
    Ok(url)
}

fn intel_ca_issuer_url(der: &[u8]) -> Result<Option<reqwest::Url>> {
    use x509_parser::extensions::{GeneralName, ParsedExtension};

    let (_, certificate) = x509_parser::parse_x509_certificate(der)
        .map_err(|error| anyhow!("invalid TPM EK chain certificate: {error}"))?;
    for extension in certificate.extensions() {
        if let ParsedExtension::AuthorityInfoAccess(access) = extension.parsed_extension() {
            for description in access.iter() {
                if description.access_method.to_id_string() == "1.3.6.1.5.5.7.48.2"
                    && let GeneralName::URI(uri) = &description.access_location
                {
                    return Ok(Some(allowed_intel_ca_issuer_url(uri)?));
                }
            }
        }
    }
    Ok(None)
}

async fn fetch_intel_issuer(http: &Client, url: reqwest::Url) -> Result<Vec<u8>> {
    let response = http.get(url).send().await?.error_for_status()?;
    ensure!(
        response
            .content_length()
            .is_none_or(|n| n <= EK_ISSUER_LIMIT as u64),
        "Intel EK issuer certificate is too large"
    );
    tokio::time::timeout(JSON_TIMEOUT, async {
        let mut stream = response.bytes_stream();
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            ensure!(
                chunk.len() <= EK_ISSUER_LIMIT - bytes.len(),
                "Intel EK issuer certificate is too large"
            );
            bytes.extend_from_slice(&chunk);
        }
        let certificate = openssl::x509::X509::from_der(&bytes)
            .context("Intel EK issuer certificate must be DER")?;
        ensure!(
            certificate.to_der()? == bytes,
            "Intel EK issuer response contains trailing data"
        );
        Ok(bytes)
    })
    .await?
}

async fn complete_intel_ek_chain(leaf: &[u8], embedded: Vec<Vec<u8>>) -> Result<Vec<Vec<u8>>> {
    if embedded.is_empty() {
        return Ok(Vec::new());
    }
    let http = Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(JSON_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let mut remaining = embedded;
    let mut chain = Vec::new();
    let mut current = openssl::x509::X509::from_der(leaf)?;
    loop {
        if current
            .subject_name()
            .try_cmp(current.issuer_name())?
            .is_eq()
        {
            let key = current.public_key()?;
            if current.verify(&key)? {
                break;
            }
        }
        ensure!(chain.len() < 7, "TPM EK certificate chain is too long");
        let position = remaining.iter().position(|der| {
            openssl::x509::X509::from_der(der)
                .and_then(|cert| cert.subject_name().try_cmp(current.issuer_name()))
                .is_ok_and(|order| order.is_eq())
        });
        let der = if let Some(position) = position {
            remaining.remove(position)
        } else {
            let url = intel_ca_issuer_url(&current.to_der()?)?.context(
                "TPM EK issuer is absent from the embedded chain and has no Intel CA Issuers URL",
            )?;
            fetch_intel_issuer(&http, url).await?
        };
        let issuer = openssl::x509::X509::from_der(&der)?;
        let issuer_key = issuer.public_key()?;
        ensure!(
            issuer
                .subject_name()
                .try_cmp(current.issuer_name())?
                .is_eq()
                && current.verify(&issuer_key)?,
            "TPM EK issuer certificate does not sign its child"
        );
        chain.push(der);
        current = issuer;
    }
    Ok(chain)
}

#[derive(Deserialize, Serialize)]
struct PendingEnrollment {
    config: ClientConfig,
    challenge: Option<crate::auth_protocol::EnrollChallenge>,
}

#[derive(Deserialize, Serialize)]
struct PairingRequest {
    server: String,
    server_public_key: String,
    root: PathBuf,
    code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    web_status_enabled: Option<bool>,
}

#[derive(Default)]
pub struct SetupOptions {
    pub ek_cert: Option<PathBuf>,
    pub ek_chain: Option<PathBuf>,
    pub web_status_enabled: Option<bool>,
    /// Override the TPM transport for tests; manufacturer trust is unchanged.
    pub tcti: Option<String>,
}

pub struct SetupOutcome {
    pub report: SyncReport,
    pub conflicts: usize,
}

async fn wait_for_pair_ready(
    server: &str,
    code: &str,
    deadline: tokio::time::Instant,
) -> Result<bool> {
    validate_server_url(server)?;
    let http = Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let url = format!("{}/v1/enroll/ready", server.trim_end_matches('/'));
    let mut interval = Duration::from_secs(5);
    loop {
        match http
            .post(&url)
            .json(&serde_json::json!({"code": code}))
            .send()
            .await
        {
            Ok(response) if response.status() == StatusCode::NO_CONTENT => return Ok(true),
            Ok(response) if response.status() == StatusCode::GONE => return Ok(false),
            Ok(response) if response.status() == StatusCode::ACCEPTED => {
                interval = Duration::from_secs(5);
            }
            Ok(response) if response.status() == StatusCode::TOO_MANY_REQUESTS => {
                interval = Duration::from_secs(30);
            }
            Ok(response) => bail!("pairing readiness failed: HTTP {}", response.status()),
            Err(_) => interval = std::cmp::min(interval * 2, Duration::from_secs(30)),
        }
        if tokio::time::Instant::now() >= deadline {
            bail!("timed out waiting for administrator; rerun setup to resume")
        }
        tokio::time::sleep(interval).await;
    }
}

async fn wait_for_approval(
    config_path: &Path,
    server: &str,
    code: &str,
    deadline: tokio::time::Instant,
) -> Result<bool> {
    let pending_path = config_path.with_extension("enrollment.json");
    let pending: PendingEnrollment = serde_json::from_slice(&std::fs::read(&pending_path)?)?;
    let api = Api::new(&pending.config)?;
    let ready_url = format!("{}/v1/enroll/ready", server.trim_end_matches('/'));
    loop {
        if api.is_approved().await? {
            return Ok(true);
        }
        let response = api
            .http
            .post(&ready_url)
            .json(&serde_json::json!({"code": code}))
            .send()
            .await?;
        if response.status() == StatusCode::GONE {
            if api.is_approved().await? {
                return Ok(true);
            }
            return Ok(false);
        }
        if response.status() != StatusCode::NO_CONTENT
            && response.status() != StatusCode::TOO_MANY_REQUESTS
        {
            bail!("pairing status failed: HTTP {}", response.status());
        }
        if tokio::time::Instant::now() >= deadline {
            bail!("timed out waiting for administrator approval; rerun setup to resume")
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

pub async fn setup(
    config_path: &Path,
    server: String,
    server_public_key: String,
    root: PathBuf,
    ek_cert: Option<PathBuf>,
    ek_chain: Option<PathBuf>,
) -> Result<SetupOutcome> {
    setup_with_tcti(
        config_path,
        server,
        server_public_key,
        root,
        ek_cert,
        ek_chain,
        crate::tpm::default_tcti(),
    )
    .await
}

pub async fn setup_with_tcti(
    config_path: &Path,
    server: String,
    server_public_key: String,
    root: PathBuf,
    ek_cert: Option<PathBuf>,
    ek_chain: Option<PathBuf>,
    tcti: String,
) -> Result<SetupOutcome> {
    setup_with_options(
        config_path,
        server,
        server_public_key,
        root,
        SetupOptions {
            ek_cert,
            ek_chain,
            tcti: Some(tcti),
            ..SetupOptions::default()
        },
    )
    .await
}

pub async fn setup_with_options(
    config_path: &Path,
    server: String,
    server_public_key: String,
    root: PathBuf,
    options: SetupOptions,
) -> Result<SetupOutcome> {
    let SetupOptions {
        ek_cert,
        ek_chain,
        web_status_enabled,
        tcti,
    } = options;
    let tcti = tcti.unwrap_or_else(crate::tpm::default_tcti);
    validate_server_url(&server)?;
    let server_public_key =
        hex::encode(crate::origin_auth::public_key(&server_public_key)?.to_bytes());
    std::fs::create_dir_all(&root)?;
    let root = root.canonicalize()?;
    let parent = config_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    if parent.canonicalize()?.starts_with(&root) {
        bail!("config must be outside the synchronized folder");
    }
    let pair_path = config_path.with_extension("pairing.json");
    if config_path.exists() {
        let config = load_config(config_path)?;
        if config.server != server
            || config.root != root
            || config.server_public_key != server_public_key
        {
            bail!("existing client profile has a different server, key or folder");
        }
        if let Some(enabled) = web_status_enabled {
            super::set_web_status(config_path, enabled)?;
        }
        let report = sync(config_path).await?;
        let conflicts = status(config_path).await?.conflicts;
        if pair_path.exists() {
            std::fs::remove_file(pair_path)?;
        }
        return Ok(SetupOutcome { report, conflicts });
    }
    let pair_lock = acquire_lock(config_path).await?;
    if config_path.exists() {
        bail!("client was configured by another setup process; rerun setup");
    }
    let resuming_pair = pair_path.exists();
    let mut request: PairingRequest = if resuming_pair {
        let request: PairingRequest = serde_json::from_slice(&std::fs::read(&pair_path)?)?;
        if request.server != server
            || request.root != root
            || request.server_public_key != server_public_key
        {
            bail!("another pairing is already pending");
        }
        request
    } else {
        if config_path.with_extension("enrollment.json").exists() {
            bail!("a manual enrollment is already pending");
        }
        let request = PairingRequest {
            server: server.clone(),
            server_public_key: server_public_key.clone(),
            root: root.clone(),
            code: crate::auth_protocol::pairing_code()?,
            web_status_enabled: Some(
                web_status_enabled.unwrap_or_else(super::default_web_status_enabled),
            ),
        };
        private_write_json(&pair_path, &request)?;
        request
    };
    if let Some(enabled) = web_status_enabled
        && request.web_status_enabled != Some(enabled)
    {
        request.web_status_enabled = Some(enabled);
        private_write_json(&pair_path, &request)?;
    }
    drop(pair_lock);
    println!("Pairing code: {}", request.code);
    println!("Ask the administrator to run `make pair` on the server. Waiting...");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30 * 60);
    let pending_path = config_path.with_extension("enrollment.json");
    let already_approved = if pending_path.exists() {
        let pending: PendingEnrollment = serde_json::from_slice(&std::fs::read(&pending_path)?)?;
        if pending.challenge.is_some() {
            Api::new(&pending.config)?.is_approved().await?
        } else {
            false
        }
    } else {
        false
    };
    if !already_approved {
        if !wait_for_pair_ready(&server, &request.code, deadline).await? {
            if pending_path.exists() {
                std::fs::remove_file(&pending_path)?;
            }
            std::fs::remove_file(&pair_path)?;
            if !resuming_pair {
                bail!("pairing code expired or was cancelled; rerun setup for a new code");
            }
            request.code = crate::auth_protocol::pairing_code()?;
            private_write_json(&pair_path, &request)?;
            println!(
                "Previous pairing code expired or was cancelled. New pairing code: {}",
                request.code
            );
            println!("Ask the administrator to run `make pair` on the server. Waiting...");
            if !wait_for_pair_ready(&server, &request.code, deadline).await? {
                std::fs::remove_file(&pair_path)?;
                bail!("pairing code expired or was cancelled; rerun setup for a new code");
            }
        }
        let enrolled = enroll_with_tcti(
            config_path,
            server,
            server_public_key,
            root,
            crate::auth_protocol::normalize_pairing_code(&request.code)?,
            ek_cert,
            ek_chain,
            tcti,
        )
        .await?;
        println!("TPM fingerprint: {}", enrolled.fingerprint);
        println!("Waiting for administrator fingerprint confirmation...");
        if !wait_for_approval(config_path, &request.server, &request.code, deadline).await? {
            std::fs::remove_file(&pending_path)?;
            std::fs::remove_file(&pair_path)?;
            bail!("pairing was cancelled or expired; rerun setup for a new code");
        }
    }
    let report = activate_enrollment(config_path).await?;
    let conflicts = status(config_path).await?.conflicts;
    std::fs::remove_file(pair_path)?;
    Ok(SetupOutcome { report, conflicts })
}

fn pairing_web_status(config_path: &Path, config: &ClientConfig) -> Result<Option<bool>> {
    let bytes = match std::fs::read(config_path.with_extension("pairing.json")) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let request: PairingRequest = serde_json::from_slice(&bytes)?;
    if request.server != config.server
        || request.server_public_key != config.server_public_key
        || request.root != config.root
    {
        bail!("pairing preferences belong to a different client profile");
    }
    Ok(request.web_status_enabled)
}

pub async fn enroll(
    config_path: &Path,
    server: String,
    server_public_key: String,
    root: PathBuf,
    invitation: String,
    ek_cert: Option<PathBuf>,
    ek_chain: Option<PathBuf>,
) -> Result<crate::auth_protocol::Enrollment> {
    enroll_with_tcti(
        config_path,
        server,
        server_public_key,
        root,
        invitation,
        ek_cert,
        ek_chain,
        crate::tpm::default_tcti(),
    )
    .await
}

/// Enroll through a specific TPM transport. Certificate verification on the
/// server is unchanged; simulated TPMs require an explicitly trusted test CA.
// The explicit TCTI is a test hook; grouping these values would add an API
// object without making the enrollment flow easier to follow.
#[allow(clippy::too_many_arguments)]
pub async fn enroll_with_tcti(
    config_path: &Path,
    server: String,
    server_public_key: String,
    root: PathBuf,
    invitation: String,
    ek_cert: Option<PathBuf>,
    ek_chain: Option<PathBuf>,
    tcti: String,
) -> Result<crate::auth_protocol::Enrollment> {
    use crate::auth_protocol::{EnrollChallenge, EnrollFinish, EnrollStart, Enrollment};
    validate_server_url(&server)?;
    let server_public_key =
        hex::encode(crate::origin_auth::public_key(&server_public_key)?.to_bytes());
    let parent = config_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    std::fs::create_dir_all(&root)?;
    let root = root.canonicalize()?;
    if parent.canonicalize()?.starts_with(&root) {
        bail!("config must be outside the synchronized folder");
    }
    let _lock = acquire_lock(config_path).await?;
    if config_path.exists() {
        bail!("config already exists; enrollment requires a fresh client profile");
    }
    let pending_path = config_path.with_extension("enrollment.json");
    let external_certificate = ek_cert
        .as_deref()
        .map(crate::tpm::read_ek_certificate)
        .transpose()?;
    let mut pending: PendingEnrollment = if pending_path.exists() {
        let value: PendingEnrollment = serde_json::from_slice(&std::fs::read(&pending_path)?)?;
        if value.config.root != root
            || value.config.server != server
            || value.config.server_public_key != server_public_key
        {
            bail!("another enrollment is already pending");
        }
        value
    } else {
        let creation_certificate = external_certificate.clone();
        let identity = tokio::task::spawn_blocking(move || {
            if let Some(certificate) = creation_certificate {
                let kind = crate::tpm::certificate_kind(&certificate)?;
                crate::tpm::Identity::create_with_certificate(&tcti, kind, Some(&certificate))
                    .map(|(identity, _)| identity)
            } else {
                crate::tpm::Identity::create(&tcti, "rsa")
                    .or_else(|_| crate::tpm::Identity::create(&tcti, "ecc"))
                    .map(|(identity, _)| identity)
            }
        })
        .await??;
        let mut config = ClientConfig {
            server,
            server_public_key,
            identity: Some(identity),
            root,
            auto_update: true,
            web_status_enabled: super::default_web_status_enabled(),
            web_files_enabled: false,
            update_public_key: default_update_public_key(),
        };
        if let Some(enabled) = pairing_web_status(config_path, &config)? {
            config.web_status_enabled = enabled;
        }
        Api::new(&config)?;
        let pending = PendingEnrollment {
            config,
            challenge: None,
        };
        private_write_json(&pending_path, &pending)?;
        pending
    };
    if let Some(enabled) = pairing_web_status(config_path, &pending.config)?
        && pending.config.web_status_enabled != enabled
    {
        pending.config.web_status_enabled = enabled;
        private_write_json(&pending_path, &pending)?;
    }
    let api = Api::new(&pending.config)?;
    if pending.challenge.is_none() {
        let identity = pending
            .config
            .identity
            .clone()
            .context("missing pending TPM key")?;
        let cert_identity = identity.clone();
        let leaf = tokio::task::spawn_blocking(move || {
            if let Some(certificate) = external_certificate {
                cert_identity.ek_certificate_from(&certificate)
            } else {
                cert_identity.ek_certificate()
            }
        })
        .await??;
        let mut chain = vec![hex::encode(&leaf)];
        let intermediates = if let Some(path) = ek_chain {
            openssl::x509::X509::stack_from_pem(&std::fs::read(path)?)?
                .into_iter()
                .map(|cert| cert.to_der().map_err(Into::into))
                .collect::<Result<Vec<_>>>()?
        } else {
            let cert_identity = identity.clone();
            let embedded =
                tokio::task::spawn_blocking(move || cert_identity.ek_intermediates()).await??;
            complete_intel_ek_chain(&leaf, embedded).await?
        };
        for cert in intermediates {
            chain.push(hex::encode(cert));
        }
        let challenge: EnrollChallenge = bounded_json(
            api.http
                .post(api.url("/v1/enroll/start"))
                .json(&EnrollStart {
                    invitation,
                    public: identity.public,
                    ek_chain: chain,
                })
                .send()
                .await?,
            CONTROL_JSON_LIMIT,
        )
        .await?;
        pending.config.identity.as_mut().unwrap().device = challenge.id.clone();
        pending.challenge = Some(challenge);
        private_write_json(&pending_path, &pending)?;
    }
    let identity = pending.config.identity.clone().unwrap();
    let challenge = pending.challenge.clone().unwrap();
    let id = challenge.id.clone();
    let activation = tokio::task::spawn_blocking(move || identity.activate(&challenge)).await??;
    let result: Enrollment = bounded_json(
        api.http
            .post(api.url("/v1/enroll/finish"))
            .json(&EnrollFinish { id, activation })
            .send()
            .await?,
        CONTROL_JSON_LIMIT,
    )
    .await?;
    if result.fingerprint != pending.config.identity.as_ref().unwrap().fingerprint()? {
        bail!("server returned an unexpected device fingerprint");
    }
    Ok(result)
}

pub async fn activate_enrollment(config_path: &Path) -> Result<SyncReport> {
    let lock = acquire_lock(config_path).await?;
    let pending_path = config_path.with_extension("enrollment.json");
    let mut pending: PendingEnrollment =
        serde_json::from_slice(&std::fs::read(&pending_path).context("no pending enrollment")?)?;
    if let Some(enabled) = pairing_web_status(config_path, &pending.config)? {
        pending.config.web_status_enabled = enabled;
    }
    Api::new(&pending.config)?.authenticate().await?;
    private_write_json(config_path, &pending.config)?;
    std::fs::remove_file(pending_path)?;
    drop(lock);
    sync(config_path).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn intel_issuer_aia_accepts_only_the_manufacturer_certificate_repository() -> Result<()> {
        // Public CA certificate from Intel's OnDieCA certificate repository.
        let certificate = include_bytes!("../../tests/fixtures/intel-odca-ca2.der");
        assert_eq!(
            intel_ca_issuer_url(certificate)?.unwrap().as_str(),
            "https://tsci.intel.com/content/OnDieCA/certs/OnDie_CA_RootCA_Certificate.cer"
        );
        for url in [
            "http://tsci.intel.com/content/OnDieCA/certs/issuer.cer",
            "https://example.org/content/OnDieCA/certs/issuer.cer",
            "https://tsci.intel.com.evil.example/content/OnDieCA/certs/issuer.cer",
            "https://tsci.intel.com:8443/content/OnDieCA/certs/issuer.cer",
            "https://tsci.intel.com/private/issuer.cer",
        ] {
            assert!(allowed_intel_ca_issuer_url(url).is_err(), "{url}");
        }
        Ok(())
    }
}
