use std::{
    fs::OpenOptions,
    io::{Read, Write},
    path::Path,
};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use fs2::FileExt;
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const PUBLIC_KEY_HEX: &str = include_str!("update_public_key.hex");
pub const MAX_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;
const SIGNING_CONTEXT: &[u8] = b"MySyncFiles release manifest v1\n";
pub const MAX_ENVELOPE_BYTES: usize = 32 * 1024;

/// Preserve the exact signed bytes, independently of JSON serialization.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRelease {
    pub manifest: String,
    pub signature: String,
}

pub fn verify_envelope(bytes: &[u8], public_key: &str) -> Result<ReleaseManifest> {
    if bytes.len() > MAX_ENVELOPE_BYTES {
        bail!("release envelope is too large");
    }
    let envelope: SignedRelease = serde_json::from_slice(bytes)?;
    verify_manifest(
        &B64.decode(envelope.manifest)?,
        &envelope.signature,
        public_key,
    )
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseManifest {
    pub version: String,
    pub target: String,
    pub artifact: String,
    pub size: u64,
    pub sha256: String,
}

pub fn valid_target(target: &str) -> bool {
    matches!(target, "linux-x86_64" | "linux-aarch64")
}

pub fn current_target() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Some("linux-x86_64"),
        ("linux", "aarch64") => Some("linux-aarch64"),
        _ => None,
    }
}

pub fn valid_release_file(file: &str) -> bool {
    file == "latest.json"
        || file == "latest.sig"
        || file == "latest.signed.json"
        || (file.starts_with("mysync-")
            && file.len() <= 128
            && file
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            && !file.contains(".."))
}

impl ReleaseManifest {
    pub fn validate(&self) -> Result<Version> {
        let version = Version::parse(&self.version).context("invalid release version")?;
        if !version.build.is_empty() {
            bail!("release version must not contain build metadata");
        }
        if !valid_target(&self.target) {
            bail!("unsupported release target");
        }
        if self.artifact != format!("mysync-{}-{}", self.version, self.target)
            || !valid_release_file(&self.artifact)
        {
            bail!("invalid release artifact name");
        }
        if self.size == 0 || self.size > MAX_ARTIFACT_BYTES {
            bail!("release artifact size is invalid");
        }
        if self.sha256.len() != 64 || !self.sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            bail!("release checksum is invalid");
        }
        Ok(version)
    }
}

fn signed_payload(manifest_bytes: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(SIGNING_CONTEXT.len() + manifest_bytes.len());
    payload.extend_from_slice(SIGNING_CONTEXT);
    payload.extend_from_slice(manifest_bytes);
    payload
}

pub fn verify_manifest(
    manifest_bytes: &[u8],
    signature_hex: &str,
    public_key_hex: &str,
) -> Result<ReleaseManifest> {
    if manifest_bytes.len() > 16 * 1024 {
        bail!("release manifest is too large");
    }
    let key_bytes: [u8; 32] = hex::decode(public_key_hex.trim())?
        .try_into()
        .map_err(|_| anyhow!("release public key must contain 32 bytes"))?;
    let signature_bytes: [u8; 64] = hex::decode(signature_hex.trim())?
        .try_into()
        .map_err(|_| anyhow!("release signature must contain 64 bytes"))?;
    let key = VerifyingKey::from_bytes(&key_bytes)?;
    key.verify_strict(
        &signed_payload(manifest_bytes),
        &Signature::from_bytes(&signature_bytes),
    )
    .context("release signature verification failed")?;
    let manifest: ReleaseManifest = serde_json::from_slice(manifest_bytes)?;
    manifest.validate()?;
    Ok(manifest)
}

fn private_write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

pub fn generate_key(path: &Path) -> Result<String> {
    let mut secret = [0_u8; 32];
    getrandom::fill(&mut secret).map_err(|error| anyhow!("random source failed: {error}"))?;
    let signing_key = SigningKey::from_bytes(&secret);
    private_write_new(path, format!("{}\n", hex::encode(secret)).as_bytes())?;
    Ok(hex::encode(signing_key.verifying_key().to_bytes()))
}

fn read_signing_key(path: &Path) -> Result<SigningKey> {
    let metadata = std::fs::metadata(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("signing key must not be readable by group or others");
        }
    }
    if !metadata.is_file() {
        bail!("signing key is not a regular file");
    }
    let bytes: [u8; 32] = hex::decode(std::fs::read_to_string(path)?.trim())?
        .try_into()
        .map_err(|_| anyhow!("signing key must contain 32 bytes"))?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("invalid output path"))?;
    let temp = parent.join(format!(".mysync-release-{}", Uuid::new_v4()));
    let result: Result<()> = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o644);
        }
        let mut file = options.open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&temp, path)?;
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temp);
    }
    result
}

pub fn publish(
    signing_key_path: &Path,
    binary: &Path,
    version: &str,
    target: &str,
    output_dir: &Path,
) -> Result<ReleaseManifest> {
    let parsed_version = Version::parse(version)?;
    if !parsed_version.build.is_empty() || !valid_target(target) {
        bail!("invalid release version or target");
    }
    let output = std::process::Command::new(binary)
        .arg("--version")
        .output()
        .context("running client binary to verify its version")?;
    if !output.status.success()
        || String::from_utf8_lossy(&output.stdout).trim() != format!("mysync {version}")
    {
        bail!("client binary version does not match the release version");
    }
    let setup = std::process::Command::new(binary)
        .args(["setup", "--help"])
        .output()
        .context("running client binary to verify the setup command")?;
    if !setup.status.success() {
        bail!("client binary lacks a working setup command");
    }
    let signing_key = read_signing_key(signing_key_path)?;
    let release_dir = output_dir.join(target);
    std::fs::create_dir_all(&release_dir)?;
    use std::os::unix::fs::OpenOptionsExt;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(release_dir.join(".publish.lock"))?;
    if !lock.metadata()?.is_file() {
        bail!("invalid release publication lock");
    }
    lock.lock_exclusive()
        .context("locking release publication")?;
    let latest_path = release_dir.join("latest.json");
    let envelope_path = release_dir.join("latest.signed.json");
    let previous = match std::fs::read(&envelope_path) {
        Ok(bytes) => Some(verify_envelope(
            &bytes,
            &hex::encode(signing_key.verifying_key().to_bytes()),
        )?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => match std::fs::read(&latest_path) {
            Ok(bytes) => Some(serde_json::from_slice::<ReleaseManifest>(&bytes)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        },
        Err(e) => return Err(e.into()),
    };
    if let Some(previous) = previous
        && parsed_version <= previous.validate()?
    {
        bail!("release version must be newer than the published version");
    }
    let artifact = format!("mysync-{version}-{target}");
    let artifact_path = release_dir.join(&artifact);
    let mut source = std::fs::File::open(binary)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o644);
    }
    let mut destination = options.open(&artifact_path)?;
    let mut publishing = false;
    let result: Result<ReleaseManifest> = (|| {
        let mut hash = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        let mut size = 0_u64;
        loop {
            let count = source.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            size = size
                .checked_add(count as u64)
                .ok_or_else(|| anyhow!("artifact too large"))?;
            if size > MAX_ARTIFACT_BYTES {
                bail!("artifact exceeds 64 MiB");
            }
            hash.update(&buffer[..count]);
            destination.write_all(&buffer[..count])?;
        }
        destination.sync_all()?;
        std::fs::File::open(&release_dir)?.sync_all()?;
        let manifest = ReleaseManifest {
            version: version.to_owned(),
            target: target.to_owned(),
            artifact,
            size,
            sha256: hex::encode(hash.finalize()),
        };
        manifest.validate()?;
        let mut manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
        manifest_bytes.push(b'\n');
        let signature = signing_key.sign(&signed_payload(&manifest_bytes));
        // From this point an I/O error may follow a successful rename. Keep the
        // immutable artifact rather than risk deleting published content.
        publishing = true;
        atomic_write(
            &envelope_path,
            &serde_json::to_vec(&SignedRelease {
                manifest: B64.encode(&manifest_bytes),
                signature: hex::encode(signature.to_bytes()),
            })?,
        )?;
        // Compatibility for installed v1 clients. New clients use the atomic
        // envelope exclusively when it is available.
        atomic_write(
            &release_dir.join("latest.sig"),
            format!("{}\n", hex::encode(signature.to_bytes())).as_bytes(),
        )?;
        atomic_write(&latest_path, &manifest_bytes)?;
        Ok(manifest)
    })();
    if result.is_err() && !publishing {
        let _ = std::fs::remove_file(artifact_path);
    }
    result
}
