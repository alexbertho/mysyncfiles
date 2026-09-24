use std::{
    collections::{BTreeMap, BTreeSet},
    io::SeekFrom,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use fs2::FileExt;
use futures_util::StreamExt;
use notify::{RecursiveMode, Watcher};
use reqwest::{Client, Method, StatusCode};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use uuid::Uuid;

use crate::local_fs::Mirror;
use crate::model::{
    BeginUpload, Entry, Manifest, RestoreRequest, TrashItem, UPLOAD_CHUNK_BYTES, UploadProgress,
};

#[derive(Clone, Deserialize, Serialize)]
pub struct ClientConfig {
    pub server: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<crate::tpm::Identity>,
    pub root: PathBuf,
    #[serde(default = "default_auto_update")]
    pub auto_update: bool,
    #[serde(default = "default_update_public_key")]
    pub update_public_key: String,
}

fn default_auto_update() -> bool {
    true
}

fn default_update_public_key() -> String {
    crate::release::PUBLIC_KEY_HEX.trim().to_owned()
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct LocalState {
    entries: BTreeMap<String, Seen>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Seen {
    revision: i64,
    sha256: Option<String>,
}

#[derive(Default)]
pub struct SyncReport {
    pub uploaded: usize,
    pub downloaded: usize,
    pub deleted_local: usize,
    pub deleted_remote: usize,
    pub conflicts: usize,
}

pub struct Status {
    pub local_files: usize,
    pub remote_files: usize,
    pub pending_local: usize,
    pub conflicts: usize,
    pub generation: i64,
}

pub struct Api {
    http: Client,
    base: String,
    token: String,
    identity: Option<crate::tpm::Identity>,
    session: tokio::sync::Mutex<Option<crate::auth_protocol::Session>>,
}

const CONTROL_JSON_LIMIT: usize = 64 * 1024;
const LIST_JSON_LIMIT: usize = 32 * 1024 * 1024;
const JSON_TIMEOUT: Duration = Duration::from_secs(30);

// Never let a server choose our allocation size, including for chunked bodies.
async fn bounded_json<T: DeserializeOwned>(response: reqwest::Response, limit: usize) -> Result<T> {
    let response = response.error_for_status()?;
    if response
        .content_length()
        .is_some_and(|size| size > limit as u64)
    {
        bail!("API JSON response exceeds {limit} bytes");
    }
    tokio::time::timeout(JSON_TIMEOUT, async {
        let mut stream = response.bytes_stream();
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            if chunk.len() > limit - bytes.len() {
                bail!("API JSON response exceeds {limit} bytes");
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(serde_json::from_slice(&bytes)?)
    })
    .await
    .context("API JSON response timed out")?
}

pub fn default_config_path() -> Result<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .ok_or_else(|| anyhow!("HOME or XDG_CONFIG_HOME is required"))?;
    Ok(base.join("mysync").join("config.json"))
}

fn state_path(config_path: &Path) -> PathBuf {
    config_path.with_extension("state.json")
}

fn lock_path(config_path: &Path) -> PathBuf {
    config_path.with_extension("lock")
}

async fn acquire_lock(config_path: &Path) -> Result<std::fs::File> {
    let path = lock_path(config_path);
    tokio::task::spawn_blocking(move || {
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path)?;
        file.lock_exclusive()?;
        Ok(file)
    })
    .await?
}

fn private_write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("invalid config path"))?;
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    std::fs::create_dir_all(parent)?;
    let temp = parent.join(format!(".mysync-{}", Uuid::new_v4()));
    let result: Result<()> = (|| {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temp)?;
        serde_json::to_writer_pretty(&mut file, value)?;
        use std::io::Write;
        file.flush()?;
        file.sync_all()?;
        std::fs::rename(&temp, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

pub fn load_config(path: &Path) -> Result<ClientConfig> {
    let config: ClientConfig = serde_json::from_slice(
        &std::fs::read(path).with_context(|| format!("reading {}", path.display()))?,
    )?;
    if !config.root.is_dir() {
        bail!("sync folder does not exist: {}", config.root.display());
    }
    Ok(config)
}

fn load_state(config_path: &Path) -> Result<LocalState> {
    let path = state_path(config_path);
    match std::fs::read(&path) {
        Ok(contents) => serde_json::from_slice(&contents).context("reading local sync state"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(LocalState::default()),
        Err(error) => Err(error.into()),
    }
}

fn save_state(config_path: &Path, state: &LocalState) -> Result<()> {
    private_write_json(&state_path(config_path), state)
}

impl Api {
    pub fn new(config: &ClientConfig) -> Result<Self> {
        let url = reqwest::Url::parse(&config.server).context("invalid server URL")?;
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
        if config.token.is_empty() && config.identity.is_none() {
            bail!("device key is empty");
        }
        let http = Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .read_timeout(Duration::from_secs(30))
            .timeout(Duration::from_secs(60))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            http,
            base: config.server.trim_end_matches('/').to_owned(),
            token: config.token.clone(),
            identity: config.identity.clone(),
            session: tokio::sync::Mutex::new(None),
        })
    }

    async fn sign_request(&self, request: &mut reqwest::Request, token: &str) -> Result<()> {
        let identity = self.identity.clone().context("TPM identity missing")?;
        let bytes = match request.body() {
            None => &[][..],
            Some(body) => body
                .as_bytes()
                .context("signed requests require a bounded body")?,
        };
        let claims = crate::auth_protocol::Claims::new(
            &identity.device,
            request.method().as_str(),
            request.url().as_str(),
            bytes,
            token,
        )?;
        let proof = tokio::task::spawn_blocking(move || identity.proof(claims)).await??;
        request
            .headers_mut()
            .insert(crate::auth_protocol::PROOF_HEADER, proof.parse()?);
        if !token.is_empty() {
            request.headers_mut().insert(
                reqwest::header::AUTHORIZATION,
                format!("MySync {token}").parse()?,
            );
        }
        Ok(())
    }

    pub async fn authenticate(&self) -> Result<()> {
        self.session_token().await?;
        Ok(())
    }

    async fn session_token(&self) -> Result<String> {
        let mut session = self.session.lock().await;
        if let Some(current) = session
            .as_ref()
            .filter(|s| s.expires_at > crate::auth_protocol::now() + 30)
        {
            return Ok(current.token.clone());
        }
        let mut request = self.http.post(self.url("/v1/auth/session")).build()?;
        self.sign_request(&mut request, "").await?;
        let response = self.http.execute(request).await?;
        if response.status() == StatusCode::FORBIDDEN {
            bail!("device awaits administrator approval or was revoked");
        }
        let created: crate::auth_protocol::Session =
            bounded_json(response, CONTROL_JSON_LIMIT).await?;
        let token = created.token.clone();
        *session = Some(created);
        Ok(token)
    }

    async fn send(&self, builder: reqwest::RequestBuilder) -> Result<reqwest::Response> {
        if self.identity.is_none() {
            return Ok(builder.bearer_auth(&self.token).send().await?);
        }
        let request = builder.build()?;
        for attempt in 0..2 {
            let token = self.session_token().await?;
            let mut request = request.try_clone().context("request cannot be retried")?;
            self.sign_request(&mut request, &token).await?;
            let response = self.http.execute(request).await?;
            if response.status() != StatusCode::UNAUTHORIZED || attempt == 1 {
                return Ok(response);
            }
            *self.session.lock().await = None;
        }
        unreachable!()
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    pub async fn manifest(&self) -> Result<Manifest> {
        bounded_json(
            self.send(self.http.get(self.url("/v1/manifest"))).await?,
            LIST_JSON_LIMIT,
        )
        .await
    }

    async fn upload(
        &self,
        path: &str,
        base: i64,
        local: std::fs::File,
        expected_sha: &str,
    ) -> Result<Option<Entry>> {
        let size = i64::try_from(local.metadata()?.len())?;
        if size > UPLOAD_CHUNK_BYTES {
            return self
                .upload_chunked(path, base, local, size, expected_sha)
                .await;
        }
        let mut bytes = Vec::new();
        tokio::fs::File::from_std(local)
            .take(UPLOAD_CHUNK_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .await?;
        if bytes.len() > UPLOAD_CHUNK_BYTES as usize {
            bail!("local file grew during upload; retry sync");
        }
        let response = self
            .send(
                self.http
                    .request(Method::PUT, self.url("/v1/file"))
                    .query(&[("path", path), ("base_revision", &base.to_string())])
                    .body(bytes),
            )
            .await?;
        if response.status() == StatusCode::CONFLICT {
            return Ok(None);
        }
        Ok(Some(bounded_json(response, CONTROL_JSON_LIMIT).await?))
    }

    async fn upload_chunked(
        &self,
        path: &str,
        base: i64,
        local: std::fs::File,
        size: i64,
        expected_sha: &str,
    ) -> Result<Option<Entry>> {
        let response = self
            .send(self.http.post(self.url("/v1/uploads")).json(&BeginUpload {
                path: path.to_owned(),
                base_revision: base,
                size,
                sha256: expected_sha.to_owned(),
            }))
            .await?;
        if response.status() == StatusCode::CONFLICT {
            return Ok(None);
        }
        let mut progress: UploadProgress = bounded_json(response, CONTROL_JSON_LIMIT).await?;
        if progress.offset < 0 || progress.offset > size {
            bail!("server returned an invalid upload offset");
        }
        while progress.offset < size {
            let length = (size - progress.offset).min(UPLOAD_CHUNK_BYTES) as u64;
            let mut file = tokio::fs::File::from_std(local.try_clone()?);
            file.seek(SeekFrom::Start(progress.offset as u64)).await?;
            let mut bytes = Vec::new();
            file.take(length).read_to_end(&mut bytes).await?;
            if bytes.len() != length as usize {
                bail!("local file changed during upload");
            }
            let response = self
                .send(
                    self.http
                        .put(self.url(&format!("/v1/uploads/{}", progress.id)))
                        .query(&[("offset", progress.offset)])
                        .header(reqwest::header::CONTENT_LENGTH, length.to_string())
                        .body(bytes),
                )
                .await?
                .error_for_status()?;
            let next: UploadProgress = bounded_json(response, CONTROL_JSON_LIMIT).await?;
            if next.id != progress.id || next.offset != progress.offset + length as i64 {
                bail!("server returned an invalid upload offset");
            }
            progress = next;
        }
        let response = self
            .send(
                self.http
                    .post(self.url(&format!("/v1/uploads/{}/commit", progress.id))),
            )
            .await?;
        if response.status() == StatusCode::CONFLICT {
            return Ok(None);
        }
        Ok(Some(bounded_json(response, CONTROL_JSON_LIMIT).await?))
    }

    async fn delete(&self, path: &str, base: i64) -> Result<Option<Entry>> {
        let response = self
            .send(
                self.http
                    .request(Method::DELETE, self.url("/v1/file"))
                    .query(&[("path", path), ("base_revision", &base.to_string())]),
            )
            .await?;
        if response.status() == StatusCode::CONFLICT {
            return Ok(None);
        }
        Ok(Some(bounded_json(response, CONTROL_JSON_LIMIT).await?))
    }

    async fn download(&self, entry: &Entry, file: std::fs::File) -> Result<bool> {
        let expected_size = u64::try_from(entry.size.context("download size missing")?)
            .context("negative download size")?;
        let response = self
            .send(
                self.http
                    .get(self.url("/v1/file"))
                    .timeout(Duration::from_secs(60 * 60))
                    .query(&[
                        ("path", entry.path.as_str()),
                        ("revision", &entry.revision.to_string()),
                    ]),
            )
            .await?;
        if response.status() == StatusCode::CONFLICT {
            return Ok(false);
        }
        let response = response.error_for_status()?;
        if response
            .content_length()
            .is_some_and(|size| size != expected_size)
        {
            bail!("download length does not match manifest");
        }
        let mut file = tokio::fs::File::from_std(file);
        let mut stream = response.bytes_stream();
        let mut hash = Sha256::new();
        let mut size = 0_u64;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            size = size
                .checked_add(chunk.len() as u64)
                .context("download size overflow")?;
            if size > expected_size {
                bail!("download exceeds manifest size for {}", entry.path);
            }
            hash.update(&chunk);
            file.write_all(&chunk).await?;
        }
        file.sync_all().await?;
        if Some(hex::encode(hash.finalize())) != entry.sha256 || size != expected_size {
            bail!("download integrity check failed for {}", entry.path);
        }
        Ok(true)
    }

    pub async fn trash(&self) -> Result<Vec<TrashItem>> {
        bounded_json(
            self.send(self.http.get(self.url("/v1/trash"))).await?,
            LIST_JSON_LIMIT,
        )
        .await
    }

    pub async fn restore(&self, id: i64) -> Result<Entry> {
        bounded_json(
            self.send(
                self.http
                    .post(self.url("/v1/trash/restore"))
                    .json(&RestoreRequest { id }),
            )
            .await?,
            CONTROL_JSON_LIMIT,
        )
        .await
    }
}

pub async fn configure(
    config_path: &Path,
    server: String,
    token: String,
    root: PathBuf,
    first_device: bool,
) -> Result<SyncReport> {
    if config_path.exists() {
        bail!("config already exists: {}", config_path.display());
    }
    std::fs::create_dir_all(&root)?;
    let root = root.canonicalize()?;
    let config_parent = config_path
        .parent()
        .ok_or_else(|| anyhow!("invalid config path"))?;
    let config_parent = if config_parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        config_parent
    };
    std::fs::create_dir_all(config_parent)?;
    let config_parent = config_parent.canonicalize()?;
    if config_parent.starts_with(&root) {
        bail!("config must be outside the synchronized folder");
    }
    let config = ClientConfig {
        server,
        token,
        identity: None,
        root,
        auto_update: true,
        update_public_key: default_update_public_key(),
    };
    let api = Api::new(&config)?;
    let manifest = api.manifest().await?;
    if first_device && manifest.entries.iter().any(|entry| !entry.deleted) {
        bail!("server already contains files; use 'connect' for this device");
    }
    private_write_json(config_path, &config)?;
    sync(config_path).await
}

#[derive(Deserialize, Serialize)]
struct PendingEnrollment {
    config: ClientConfig,
    challenge: Option<crate::auth_protocol::EnrollChallenge>,
}

pub async fn enroll(
    config_path: &Path,
    server: String,
    root: PathBuf,
    invitation: String,
    ek_chain: Option<PathBuf>,
) -> Result<crate::auth_protocol::Enrollment> {
    enroll_with_tcti(
        config_path,
        server,
        root,
        invitation,
        ek_chain,
        crate::tpm::default_tcti(),
    )
    .await
}

/// Enroll through a specific TPM transport. Certificate verification on the
/// server is unchanged; simulated TPMs require an explicitly trusted test CA.
pub async fn enroll_with_tcti(
    config_path: &Path,
    server: String,
    root: PathBuf,
    invitation: String,
    ek_chain: Option<PathBuf>,
    tcti: String,
) -> Result<crate::auth_protocol::Enrollment> {
    use crate::auth_protocol::{EnrollChallenge, EnrollFinish, EnrollStart, Enrollment};
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
    let previous = if config_path.exists() {
        let old = load_config(config_path)?;
        if old.root != root || old.server.trim_end_matches('/') != server.trim_end_matches('/') {
            bail!("enrollment must keep the configured server and folder");
        }
        if old.identity.is_some() {
            bail!("client is already TPM-enrolled; revoke it before creating a new identity");
        }
        Some(old)
    } else {
        None
    };
    let pending_path = config_path.with_extension("enrollment.json");
    let mut pending: PendingEnrollment = if pending_path.exists() {
        let value: PendingEnrollment = serde_json::from_slice(&std::fs::read(&pending_path)?)?;
        if value.config.root != root || value.config.server != server {
            bail!("another enrollment is already pending");
        }
        value
    } else {
        let identity = tokio::task::spawn_blocking(move || {
            crate::tpm::Identity::create(&tcti, "rsa")
                .or_else(|_| crate::tpm::Identity::create(&tcti, "ecc"))
                .map(|(identity, _)| identity)
        })
        .await??;
        let config = ClientConfig {
            server,
            token: String::new(),
            identity: Some(identity),
            root,
            auto_update: previous.as_ref().map_or(true, |old| old.auto_update),
            update_public_key: previous
                .map_or_else(default_update_public_key, |old| old.update_public_key),
        };
        Api::new(&config)?;
        let pending = PendingEnrollment {
            config,
            challenge: None,
        };
        private_write_json(&pending_path, &pending)?;
        pending
    };
    let api = Api::new(&pending.config)?;
    if pending.challenge.is_none() {
        let identity = pending
            .config
            .identity
            .clone()
            .context("missing pending TPM key")?;
        let cert_identity = identity.clone();
        let leaf = tokio::task::spawn_blocking(move || cert_identity.ek_certificate()).await??;
        let mut chain = vec![hex::encode(leaf)];
        if let Some(path) = ek_chain {
            for cert in openssl::x509::X509::stack_from_pem(&std::fs::read(path)?)? {
                chain.push(hex::encode(cert.to_der()?));
            }
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
    let pending: PendingEnrollment =
        serde_json::from_slice(&std::fs::read(&pending_path).context("no pending enrollment")?)?;
    Api::new(&pending.config)?.authenticate().await?;
    private_write_json(config_path, &pending.config)?;
    std::fs::remove_file(pending_path)?;
    drop(lock);
    sync(config_path).await
}

fn hash_file(mut file: std::fs::File) -> Result<String> {
    use std::io::Read;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let size = file.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        hash.update(&buffer[..size]);
    }
    Ok(hex::encode(hash.finalize()))
}

fn scan(mirror: &Mirror) -> Result<BTreeMap<String, String>> {
    let mut found = BTreeMap::new();
    mirror.visit_files(false, |path, file| {
        found.insert(path, hash_file(file)?);
        Ok(())
    })?;
    Ok(found)
}

async fn apply_remote(
    api: &Api,
    mirror: &Mirror,
    entry: &Entry,
    observed: Option<&String>,
    preserve_local: bool,
    report: &mut SyncReport,
) -> Result<bool> {
    let temp = if entry.deleted {
        None
    } else {
        let temp = mirror.download_file()?;
        if !api.download(entry, temp.file.try_clone()?).await? {
            return Ok(false);
        }
        Some(temp)
    };

    // Resolve again AFTER the network wait. Holding directory descriptors then
    // makes every move, deletion and permission change independent of symlinks
    // installed at a previously checked path.
    let Some(target) = mirror.entry(&entry.path, !entry.deleted)? else {
        return Ok(true); // The parent of a remotely deleted file is absent.
    };
    let directory = target.is_directory()?;
    // A tombstone refers to a file, never to all files below a directory that
    // now occupies its name (including a local file -> directory transition).
    if directory && entry.deleted {
        return Ok(true);
    }
    let current = if directory { None } else { target.read()? };
    if !directory && current.is_none() && observed.is_some() {
        return Ok(false); // A concurrent local deletion needs a fresh scan.
    }

    // Capture the actual file before replacing it. No local data ever enters
    // staging, and an error or cancellation leaves this recovery copy intact.
    let saved = if directory || current.is_some() {
        let (backup, display) = mirror.conflict_entry(&entry.path)?;
        match target.move_to(&backup) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        }
        eprintln!("local recovery copy: {display}");
        if !backup.is_directory()? {
            let captured = backup
                .read()?
                .ok_or_else(|| anyhow!("recovery copy disappeared"))?;
            if let Some(temp) = &temp {
                temp.file
                    .set_permissions(captured.metadata()?.permissions())?;
            }
        }
        Some((backup, display))
    } else {
        None
    };

    if let Some(temp) = &temp {
        match temp.entry.move_to(&target) {
            Ok(()) => report.downloaded += 1,
            // An editor created another file after capture: leave it and the
            // recovery copy untouched, then reconcile on a fresh pass.
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                if saved.is_some() {
                    report.conflicts += 1;
                }
                return Ok(false);
            }
            Err(error) => return Err(error.into()),
        }
    } else if saved.is_some() {
        report.deleted_local += 1;
    }

    if let Some((backup, display)) = saved {
        if backup.is_directory()? {
            // Preserve whole subtrees, including files created during download.
            if !backup.remove_empty_directory()? {
                eprintln!("directory conflict saved: {display}");
                report.conflicts += 1;
            }
            return Ok(true);
        }
        // Hash the displaced file after publication, not the stale pre-download
        // pathname. Edits made while downloading or just before capture survive.
        let captured = backup
            .read()?
            .ok_or_else(|| anyhow!("recovery copy disappeared"))?;
        let changed = Some(hash_file(captured)?) != observed.cloned();
        if preserve_local || changed {
            eprintln!("conflict copy saved: {display}");
            report.conflicts += 1;
        } else {
            backup.remove()?;
        }
    }
    Ok(true)
}

async fn sync_pass(
    config_path: &Path,
    api: &Api,
    mirror: &Mirror,
    report: &mut SyncReport,
) -> Result<bool> {
    let manifest = api.manifest().await?;
    let remote: BTreeMap<String, Entry> = manifest
        .entries
        .into_iter()
        .map(|entry| (entry.path.clone(), entry))
        .collect();
    let local = scan(mirror)?;
    let mut state = load_state(config_path)?;
    let paths: BTreeSet<String> = remote
        .keys()
        .chain(local.keys())
        .chain(state.entries.keys())
        .cloned()
        .collect();
    // Deletions before creations, deepest first, allow both a/b -> a and
    // a -> a/b without transient file/directory collisions.
    let replaced_paths: BTreeSet<String> = paths
        .iter()
        .filter(|path| {
            path.match_indices('/').any(|(index, _)| {
                let ancestor = &path[..index];
                remote.get(ancestor).is_some_and(|e| {
                    !e.deleted
                        && state
                            .entries
                            .get(ancestor)
                            .is_none_or(|s| s.revision != e.revision)
                })
            })
        })
        .cloned()
        .collect();
    let mut paths: Vec<_> = paths.into_iter().collect();
    paths.sort_by_key(|path| {
        let deletion = remote.get(path).is_some_and(|e| {
            e.deleted
                && (!local.contains_key(path)
                    || replaced_paths.contains(path)
                    || state
                        .entries
                        .get(path)
                        .is_none_or(|s| s.revision != e.revision))
        }) || (!local.contains_key(path)
            && state.entries.get(path).is_some_and(|s| s.sha256.is_some()));
        let remote_creation = remote.get(path).is_some_and(|e| {
            !e.deleted
                && state
                    .entries
                    .get(path)
                    .is_none_or(|s| s.revision != e.revision)
        });
        (
            if deletion {
                0
            } else if remote_creation {
                1
            } else {
                2
            },
            std::cmp::Reverse(path.matches('/').count()),
            path.clone(),
        )
    });
    let mut rescan = false;
    for path in paths {
        let server = remote.get(&path);
        let observed = local.get(&path);
        let prior = state.entries.get(&path);
        if server.is_none() && prior.is_some() {
            bail!("server lost metadata for {path}; refusing to guess how to reconcile it");
        }
        let remote_revision = server.map(|entry| entry.revision).unwrap_or(0);
        let remote_sha = server.and_then(|entry| entry.sha256.as_ref());
        if remote_revision > 0 && observed == remote_sha {
            state.entries.insert(
                path.clone(),
                Seen {
                    revision: remote_revision,
                    sha256: remote_sha.cloned(),
                },
            );
            save_state(config_path, &state)?;
            continue;
        }
        let replaced_by_ancestor = replaced_paths.contains(&path);
        if replaced_by_ancestor && server.is_none() {
            continue; // The incoming ancestor captures this untracked subtree.
        }
        let remote_changed = replaced_by_ancestor
            || prior
                .map(|seen| seen.revision != remote_revision)
                .unwrap_or(remote_revision != 0);
        let local_changed = prior
            .map(|seen| seen.sha256.as_ref() != observed)
            .unwrap_or(observed.is_some());
        if remote_changed {
            let entry = server.expect("remote revision implies entry");
            let preserve = local_changed && observed.is_some();
            if !apply_remote(api, mirror, entry, observed, preserve, report).await? {
                return Ok(true);
            }
            state.entries.insert(
                path.clone(),
                Seen {
                    revision: entry.revision,
                    sha256: entry.sha256.clone(),
                },
            );
            save_state(config_path, &state)?;
            if !entry.deleted && local.keys().any(|p| p.starts_with(&format!("{path}/"))) {
                rescan = true; // Check all displaced directories on a fresh pass.
            }
        } else if local_changed {
            let base = prior.map(|seen| seen.revision).unwrap_or(0);
            let result = if observed.is_some() {
                let Some(file) = mirror.read(&path)? else {
                    return Ok(true);
                };
                api.upload(&path, base, file, observed.expect("local file exists"))
                    .await?
            } else if server.is_some_and(|entry| !entry.deleted) {
                api.delete(&path, base).await?
            } else {
                continue;
            };
            let Some(entry) = result else {
                return Ok(true);
            };
            if entry.deleted {
                report.deleted_remote += 1;
            } else {
                report.uploaded += 1;
            }
            state.entries.insert(
                path.clone(),
                Seen {
                    revision: entry.revision,
                    sha256: entry.sha256.clone(),
                },
            );
            save_state(config_path, &state)?;
        }
    }
    Ok(rescan)
}

pub async fn sync(config_path: &Path) -> Result<SyncReport> {
    let _lock = acquire_lock(config_path).await?;
    let config = load_config(config_path)?;
    let mirror = Mirror::open(&config.root)?;
    mirror.clear_staging()?;
    let api = Api::new(&config)?;
    let mut report = SyncReport::default();
    for _ in 0..5 {
        if !sync_pass(config_path, &api, &mirror, &mut report).await? {
            return Ok(report);
        }
    }
    bail!("files kept changing during sync; retry shortly")
}

pub async fn status(config_path: &Path) -> Result<Status> {
    let config = load_config(config_path)?;
    let api = Api::new(&config)?;
    let manifest = api.manifest().await?;
    let mirror = Mirror::open(&config.root)?;
    let local = scan(&mirror)?;
    let state = load_state(config_path)?;
    let changed_files = local
        .iter()
        .filter(|(path, hash)| {
            state
                .entries
                .get(*path)
                .and_then(|seen| seen.sha256.as_ref())
                != Some(*hash)
        })
        .count();
    let deleted_files = state
        .entries
        .iter()
        .filter(|(path, seen)| seen.sha256.is_some() && !local.contains_key(*path))
        .count();
    let mut conflicts = 0;
    mirror.visit_files(true, |_, _| {
        conflicts += 1;
        Ok(())
    })?;
    Ok(Status {
        local_files: local.len(),
        remote_files: manifest
            .entries
            .iter()
            .filter(|entry| !entry.deleted)
            .count(),
        pending_local: changed_files + deleted_files,
        conflicts,
        generation: manifest.generation,
    })
}

pub async fn daemon(config_path: &Path) -> Result<()> {
    let config = load_config(config_path)?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    let mut watcher = notify::recommended_watcher(move |event: notify::Result<notify::Event>| {
        if event.is_ok() {
            let _ = tx.try_send(());
        }
    })?;
    if let Err(error) = watcher.watch(&config.root, RecursiveMode::Recursive) {
        eprintln!("filesystem watcher unavailable ({error}); continuing with 15-second polling");
    }
    let mut interval = tokio::time::interval(Duration::from_secs(15));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval.tick().await;
    let mut update_interval = tokio::time::interval(Duration::from_secs(6 * 60 * 60));
    update_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        if let Err(error) = sync(config_path).await {
            eprintln!("sync failed: {error:#}");
        }
        tokio::select! {
            _ = interval.tick() => {},
            event = rx.recv() => {
                if event.is_none() {
                    bail!("filesystem watcher stopped");
                }
                tokio::time::sleep(Duration::from_millis(700)).await;
                while rx.try_recv().is_ok() {}
            },
            _ = update_interval.tick(), if config.auto_update => {
                match crate::update::check_and_install(&config).await {
                    Ok(crate::update::UpdateOutcome::Installed(version)) => {
                        eprintln!("client updated to {version}; restarting service");
                        return Ok(());
                    }
                    Ok(crate::update::UpdateOutcome::Current) => {}
                    Err(error) => eprintln!("client update check failed: {error:#}"),
                }
            },
            _ = tokio::signal::ctrl_c() => return Ok(()),
            _ = terminate.recv() => return Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn json_body_deadline_does_not_wait_for_eof() -> Result<()> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}", listener.local_addr()?);
        let router = axum::Router::new().fallback(|| async {
            axum::body::Body::from_stream(futures_util::stream::pending::<
                Result<Vec<u8>, std::io::Error>,
            >())
        });
        let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let response = Client::new().get(url).send().await?;
        tokio::time::pause();
        let start = tokio::time::Instant::now();
        let result = bounded_json::<serde_json::Value>(response, CONTROL_JSON_LIMIT).await;
        assert!(result.unwrap_err().to_string().contains("timed out"));
        assert!(
            start.elapsed() >= JSON_TIMEOUT
                && start.elapsed() <= JSON_TIMEOUT + Duration::from_millis(10)
        );
        task.abort();
        Ok(())
    }
}
