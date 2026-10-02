use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use fs2::FileExt;
use futures_util::StreamExt;
use reqwest::Client;
use semver::Version;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use crate::release;

#[derive(Debug, PartialEq, Eq)]
pub enum UpdateOutcome {
    Current {
        installed_version: String,
        published_version: String,
    },
    Installed(String),
}

struct PendingUpdate(PathBuf);
impl Drop for PendingUpdate {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

async fn executable_version(path: &Path) -> Result<Version> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        bail!("client executable must be a regular file");
    }
    let probe = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::process::Command::new(path)
            .arg("--version")
            .kill_on_drop(true)
            .output(),
    )
    .await??;
    if !probe.status.success() {
        bail!("client cannot run here; check native dependencies");
    }
    let output = std::str::from_utf8(&probe.stdout)?.trim();
    Ok(Version::parse(
        output
            .strip_prefix("mysync ")
            .context("client reported an invalid version")?,
    )?)
}

fn installed_executable() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").ok_or_else(|| anyhow!("HOME is required"))?;
    let parent = Path::new(&home)
        .join(".local/bin")
        .canonicalize()
        .context("client must be installed in ~/.local/bin/mysync for automatic updates")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if std::fs::metadata(&parent)?.permissions().mode() & 0o022 != 0 {
            bail!("client installation directory is writable by another user");
        }
    }
    let executable = parent.join("mysync");
    let metadata = std::fs::symlink_metadata(&executable)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        bail!("installed client must be a regular file, not a symbolic link");
    }
    if std::env::current_exe()? != executable {
        bail!("automatic updates require running ~/.local/bin/mysync");
    }
    Ok(executable)
}

async fn fetch_small(http: &Client, url: &str, limit: usize) -> Result<Option<Vec<u8>>> {
    let response = http
        .get(url)
        .timeout(Duration::from_secs(20))
        .send()
        .await?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    let response = response.error_for_status()?;
    if response
        .content_length()
        .is_some_and(|size| size > limit as u64)
    {
        bail!("release metadata is too large");
    }
    let mut stream = response.bytes_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if bytes.len() + chunk.len() > limit {
            bail!("release metadata is too large");
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(Some(bytes))
}

pub async fn check_and_install(server: &str, public_key: &str) -> Result<UpdateOutcome> {
    let executable = installed_executable()?;
    check_and_install_at(server, public_key, &executable, env!("CARGO_PKG_VERSION")).await
}

pub async fn check_and_install_at(
    server: &str,
    public_key: &str,
    executable: &Path,
    current_version: &str,
) -> Result<UpdateOutcome> {
    crate::auth_protocol::validate_server_url(server)?;
    let target = release::current_target().ok_or_else(|| anyhow!("unsupported client platform"))?;
    let http = Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let base = format!("{}/v1/updates/{target}", server.trim_end_matches('/'));
    let manifest = if let Some(bytes) = fetch_small(
        &http,
        &format!("{base}/latest.signed.json"),
        release::MAX_ENVELOPE_BYTES,
    )
    .await?
    {
        release::verify_envelope(&bytes, public_key)?
    } else {
        // Only absence permits v1 fallback; invalid signatures never do.
        let bytes = fetch_small(&http, &format!("{base}/latest.json"), 16 * 1024)
            .await?
            .context("release manifest missing")?;
        let signature = fetch_small(&http, &format!("{base}/latest.sig"), 256)
            .await?
            .context("release signature missing")?;
        release::verify_manifest(&bytes, std::str::from_utf8(&signature)?, public_key)?
    };
    if manifest.target != target {
        bail!("release target does not match this client");
    }
    if manifest.validate()? <= Version::parse(current_version)? {
        return Ok(UpdateOutcome::Current {
            installed_version: current_version.to_owned(),
            published_version: manifest.version,
        });
    }

    let parent = executable
        .parent()
        .ok_or_else(|| anyhow!("invalid client executable path"))?;
    let temp_path = parent.join(format!(".mysync-update-{}", Uuid::new_v4()));
    let _cleanup = PendingUpdate(temp_path.clone());
    let result: Result<UpdateOutcome> = async {
        let response = http
            .get(format!("{base}/{}", manifest.artifact))
            .timeout(Duration::from_secs(60 * 60))
            .send()
            .await?
            .error_for_status()?;
        if response
            .content_length()
            .is_some_and(|size| size != manifest.size)
        {
            bail!("release length does not match signed manifest");
        }
        let mut options = tokio::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            options.mode(0o700);
        }
        let mut file = options.open(&temp_path).await?;
        let mut stream = response.bytes_stream();
        let mut hash = Sha256::new();
        let mut size = 0_u64;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            size = size
                .checked_add(chunk.len() as u64)
                .ok_or_else(|| anyhow!("release too large"))?;
            if size > manifest.size || size > release::MAX_ARTIFACT_BYTES {
                bail!("release exceeds signed length");
            }
            hash.update(&chunk);
            file.write_all(&chunk).await?;
        }
        if size != manifest.size || hex::encode(hash.finalize()) != manifest.sha256 {
            bail!("release checksum verification failed");
        }
        file.sync_all().await?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o755))
                .await?;
        }
        drop(file);
        // Verify that the signed candidate actually starts on this distribution
        // before replacing the running client (including native TPM libraries).
        if executable_version(&temp_path).await? != manifest.validate()? {
            bail!("signed client cannot run here or reports the wrong version; check native dependencies");
        }
        // Serialize publication across daemon/manual processes, not just tasks.
        // Never unlink the lock file: all processes must lock the same inode.
        use std::os::unix::fs::OpenOptionsExt;
        let lock = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(false)
            .mode(0o600).custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(parent.join(".mysync-update.lock"))?;
        if !lock.metadata()?.is_file() { bail!("invalid update lock file"); }
        FileExt::try_lock_exclusive(&lock).context("another client update is being installed; retry shortly")?;
        // The running process can be older than the binary currently on disk.
        // Recheck that actual binary while holding the lock, after download.
        let installed_version = executable_version(executable).await?;
        if installed_version >= manifest.validate()? {
            return Ok(UpdateOutcome::Current {
                installed_version: installed_version.to_string(),
                published_version: manifest.version.clone(),
            });
        }
        tokio::fs::rename(&temp_path, executable).await?;
        std::fs::File::open(parent)?.sync_all()?;
        Ok(UpdateOutcome::Installed(manifest.version.clone()))
    }
    .await;
    result
}
