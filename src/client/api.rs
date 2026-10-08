//! Bounded HTTP transfers and authenticated protocol messages.
use super::ClientConfig;
use crate::auth_protocol::validate_server_url;
use crate::model::{
    BeginUpload, Entry, Manifest, ManifestPage, ManifestSummary, RestoreRequest, TrashItem,
    UPLOAD_CHUNK_BYTES, UploadProgress, valid_path,
};
use anyhow::{Context, Result, bail};
use futures_util::StreamExt;
use openssl::sha::Sha256;
use reqwest::{Client, Method, StatusCode};
use serde::de::DeserializeOwned;
use std::{
    io::SeekFrom,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

pub struct Api {
    pub(super) http: Client,
    base: String,
    signer: crate::tpm::RequestSigner,
    session: tokio::sync::Mutex<Option<crate::auth_protocol::Session>>,
    origin_key: ed25519_dalek::VerifyingKey,
    web_files_enabled: bool,
    web_uploads_enabled: bool,
    web_management_enabled: bool,
    web_edit_enabled: bool,
    web_run_enabled: bool,
    communication: Arc<Mutex<(crate::web_status_protocol::CommunicationState, Option<i64>)>>,
}

struct AuthenticatedResponse {
    response: reqwest::Response,
    proof: crate::origin_auth::ResponseProof,
    communication: Arc<Mutex<(crate::web_status_protocol::CommunicationState, Option<i64>)>>,
}

impl AuthenticatedResponse {
    fn status(&self) -> StatusCode {
        self.response.status()
    }
    fn error_for_status(self) -> Result<Self> {
        self.response.error_for_status_ref()?;
        Ok(self)
    }
}

pub(super) const CONTROL_JSON_LIMIT: usize = 64 * 1024;
const LIST_JSON_LIMIT: usize = 32 * 1024 * 1024;
pub(super) const JSON_TIMEOUT: Duration = Duration::from_secs(30);
// Never let a server choose our allocation size, including for chunked bodies.
pub(super) async fn bounded_json<T: DeserializeOwned>(
    response: reqwest::Response,
    limit: usize,
) -> Result<T> {
    json_body(response, limit, None).await
}

async fn authenticated_json<T: DeserializeOwned>(
    response: AuthenticatedResponse,
    limit: usize,
) -> Result<T> {
    let digest = response
        .proof
        .body_sha256
        .context("unsigned JSON body from origin")?;
    let result = json_body(response.response, limit, Some(&digest)).await;
    if result.is_err() {
        response.communication.lock().unwrap().0 =
            crate::web_status_protocol::CommunicationState::Failed;
    }
    result
}

async fn json_body<T: DeserializeOwned>(
    response: reqwest::Response,
    limit: usize,
    digest: Option<&str>,
) -> Result<T> {
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
        if let Some(expected) = digest
            && crate::auth_protocol::hash(&bytes) != expected
        {
            bail!("origin response body integrity check failed");
        }
        Ok(serde_json::from_slice(&bytes)?)
    })
    .await
    .context("API JSON response timed out")?
}

impl Api {
    pub fn new(config: &ClientConfig) -> Result<Self> {
        validate_server_url(&config.server)?;
        let origin_key = crate::origin_auth::public_key(&config.server_public_key)
            .context("missing or invalid pinned server key; obtain it from the administrator and run mysync trust-server --public-key KEY")?;
        if config.identity.is_none() {
            bail!("TPM identity is missing; enroll this device first");
        }
        let http = Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .read_timeout(Duration::from_secs(30))
            .timeout(Duration::from_secs(60))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            origin_key,
            web_files_enabled: config.web_files_enabled,
            web_uploads_enabled: config.web_uploads_enabled,
            web_management_enabled: config.web_management_enabled,
            web_edit_enabled: config.web_edit_enabled,
            web_run_enabled: config.web_run_enabled,
            http,
            base: config.server.trim_end_matches('/').to_owned(),
            signer: crate::tpm::RequestSigner::new(
                config.identity.clone().context("TPM identity is missing")?,
            )?,
            session: tokio::sync::Mutex::new(None),
            communication: Arc::new(Mutex::new((
                crate::web_status_protocol::CommunicationState::Unknown,
                None,
            ))),
        })
    }

    async fn sign_request(&self, request: &mut reqwest::Request, token: &str) -> Result<()> {
        let bytes = match request.body() {
            None => &[][..],
            Some(body) => body
                .as_bytes()
                .context("signed requests require a bounded body")?,
        };
        let claims = crate::auth_protocol::Claims::new(
            self.signer.device(),
            request.method().as_str(),
            request.url().as_str(),
            bytes,
            token,
        )?;
        let proof = self.signer.proof(claims).await?;
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

    async fn execute_signed(&self, request: reqwest::Request) -> Result<AuthenticatedResponse> {
        let result = self.execute_signed_inner(request).await;
        let mut communication = self.communication.lock().unwrap();
        match &result {
            Ok(response) => {
                communication.0 = if response.status().is_success() {
                    crate::web_status_protocol::CommunicationState::Authenticated
                } else {
                    crate::web_status_protocol::CommunicationState::Failed
                };
                communication.1 = Some(crate::auth_protocol::now());
            }
            Err(_) => communication.0 = crate::web_status_protocol::CommunicationState::Failed,
        }
        result
    }

    async fn execute_signed_inner(
        &self,
        request: reqwest::Request,
    ) -> Result<AuthenticatedResponse> {
        let request_proof = request
            .headers()
            .get(crate::auth_protocol::PROOF_HEADER)
            .context("missing outgoing request proof")?
            .to_str()?
            .to_owned();
        let response = self.http.execute(request).await?;
        let encoded = response
            .headers()
            .get(crate::origin_auth::RESPONSE_HEADER)
            .context("origin response signature missing")?
            .to_str()?;
        let proof = crate::origin_auth::ResponseProof::verify(
            encoded,
            &self.origin_key,
            &request_proof,
            response.status().as_u16(),
        )?;
        Ok(AuthenticatedResponse {
            response,
            proof,
            communication: self.communication.clone(),
        })
    }

    pub(super) fn web_origin(&self) -> Result<String> {
        crate::web_status_protocol::origin(&self.base)
    }

    pub(super) fn verify_status_ticket(
        &self,
        ticket: &str,
    ) -> Result<crate::web_status_protocol::Challenge> {
        let claims = crate::web_status_protocol::Challenge::verify(
            ticket,
            &self.origin_key,
            &self.web_origin()?,
            crate::auth_protocol::now(),
        )?;
        anyhow::ensure!(
            !matches!(
                claims.scope.as_str(),
                "files.read" | "files.write" | "files.manage" | "files.edit" | "code.run"
            ) || self.web_files_enabled,
            "files_read_disabled"
        );
        anyhow::ensure!(
            claims.scope != "files.write" || self.web_uploads_enabled,
            "files_write_disabled"
        );
        anyhow::ensure!(
            claims.scope != "files.manage" || self.web_management_enabled,
            "files_manage_disabled"
        );
        anyhow::ensure!(
            claims.scope != "files.edit" || self.web_edit_enabled,
            "files_edit_disabled"
        );
        anyhow::ensure!(
            claims.scope != "code.run" || self.web_run_enabled,
            "code_run_disabled"
        );
        Ok(claims)
    }

    pub(super) async fn authorize_runner(
        &self,
        ticket: String,
        instance_id: String,
    ) -> Result<crate::editor_protocol::Authorization> {
        anyhow::ensure!(
            self.web_files_enabled && self.web_run_enabled,
            "code_run_disabled"
        );
        let response = self
            .send(
                self.http
                    .post(self.url(crate::editor_protocol::AUTHORIZE_PATH))
                    .json(&crate::editor_protocol::AuthorizationRequest {
                        ticket,
                        instance_id,
                    }),
            )
            .await?;
        authenticated_json(response, crate::editor_protocol::JSON_BYTES).await
    }

    pub(super) fn communication(
        &self,
    ) -> (crate::web_status_protocol::CommunicationState, Option<i64>) {
        *self.communication.lock().unwrap()
    }

    /// Fixed destination and typed payload; never exposes a generic signing API.
    pub async fn submit_presence(
        &self,
        proof: &crate::web_status_protocol::PresenceProof,
    ) -> Result<crate::web_status_protocol::ProofAccepted> {
        let claims = self.verify_status_ticket(&proof.ticket)?;
        anyhow::ensure!(claims.origin == proof.observed_origin, "wrong_origin");
        let bytes = serde_json::to_vec(proof)?;
        anyhow::ensure!(
            bytes.len() <= crate::web_status_protocol::MAX_JSON_BYTES,
            "proof_too_large"
        );
        let result = tokio::time::timeout(Duration::from_secs(10), async {
            let response = self
                .send(
                    self.http
                        .post(self.url(crate::web_status_protocol::PROOFS_PATH))
                        .header(reqwest::header::CONTENT_TYPE, "application/json")
                        .body(bytes),
                )
                .await?;
            let accepted: crate::web_status_protocol::ProofAccepted =
                authenticated_json(response, crate::web_status_protocol::MAX_JSON_BYTES).await?;
            anyhow::ensure!(
                accepted.challenge_id == claims.challenge_id,
                "challenge_mismatch"
            );
            Ok(accepted)
        })
        .await
        .context("presence_timeout")
        .and_then(|result| result);
        if result.is_err() {
            self.communication.lock().unwrap().0 =
                crate::web_status_protocol::CommunicationState::Failed;
        }
        result
    }

    pub async fn authenticate(&self) -> Result<()> {
        self.session_token().await?;
        Ok(())
    }

    pub async fn is_approved(&self) -> Result<bool> {
        let mut request = self.http.post(self.url("/v1/auth/session")).build()?;
        self.sign_request(&mut request, "").await?;
        let response = self.execute_signed(request).await?;
        if response.status() == StatusCode::FORBIDDEN {
            return Ok(false);
        }
        let _: crate::auth_protocol::Session =
            authenticated_json(response, CONTROL_JSON_LIMIT).await?;
        Ok(true)
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
        let response = self.execute_signed(request).await?;
        if response.status() == StatusCode::FORBIDDEN {
            bail!("device awaits administrator approval or was revoked");
        }
        let created: crate::auth_protocol::Session =
            authenticated_json(response, CONTROL_JSON_LIMIT).await?;
        let token = created.token.clone();
        *session = Some(created);
        Ok(token)
    }

    async fn send(&self, builder: reqwest::RequestBuilder) -> Result<AuthenticatedResponse> {
        let request = builder.build()?;
        for attempt in 0..2 {
            let token = self.session_token().await?;
            let mut request = request.try_clone().context("request cannot be retried")?;
            self.sign_request(&mut request, &token).await?;
            let response = self.execute_signed(request).await?;
            if response.status() != StatusCode::UNAUTHORIZED || attempt == 1 {
                return Ok(response);
            }
            *self.session.lock().await = None;
        }
        unreachable!()
    }

    pub(super) fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    pub async fn manifest(&self) -> Result<Manifest> {
        let response = self.send(self.http.get(self.url("/v1/manifest"))).await?;
        if response.status() != StatusCode::PAYLOAD_TOO_LARGE {
            return authenticated_json(response, LIST_JSON_LIMIT).await;
        }
        self.manifest_pages().await
    }

    pub async fn manifest_summary(&self) -> Result<ManifestSummary> {
        // An optional query keeps the signed response path compatible with old
        // servers: they ignore it and return the full manifest (or a 413).
        let response = self
            .send(
                self.http
                    .get(self.url("/v1/manifest"))
                    .query(&[("summary", true)]),
            )
            .await?;
        if response.status() == StatusCode::PAYLOAD_TOO_LARGE {
            return Ok(self.manifest_pages().await?.into());
        }
        #[derive(serde::Deserialize)]
        #[serde(untagged)]
        enum Reply {
            Full(Manifest),
            Summary(ManifestSummary),
        }
        Ok(match authenticated_json(response, LIST_JSON_LIMIT).await? {
            Reply::Full(manifest) => manifest.into(),
            Reply::Summary(summary) => summary,
        })
    }

    async fn manifest_pages(&self) -> Result<Manifest> {
        let mut entries = Vec::new();
        let mut after: Option<String> = None;
        let mut generation = None;
        loop {
            let mut request = self.http.get(self.url("/v1/manifest/page"));
            let mut query = vec![("limit", "1000".to_owned())];
            if let Some(value) = &after {
                query.push(("after", value.clone()));
            }
            request = request.query(&query);
            let page: ManifestPage =
                authenticated_json(self.send(request).await?, LIST_JSON_LIMIT).await?;
            if page.entries.len() > 1000 {
                bail!("server returned an oversized manifest page");
            }
            if let Some(expected) = generation {
                if expected != page.generation {
                    bail!("manifest changed during pagination; retry synchronization");
                }
            } else {
                generation = Some(page.generation);
            }
            let mut previous_path = after.clone();
            for entry in &page.entries {
                if !valid_path(&entry.path)
                    || previous_path
                        .as_deref()
                        .is_some_and(|previous| entry.path.as_str() <= previous)
                {
                    bail!("server returned an invalid or unsorted manifest page");
                }
                previous_path = Some(entry.path.clone());
            }
            let page_empty = page.entries.is_empty();
            entries.extend(page.entries);
            match page.next {
                Some(next) => {
                    if !valid_path(&next)
                        || page_empty
                        || previous_path
                            .as_deref()
                            .is_some_and(|previous| next.as_str() <= previous)
                    {
                        bail!("server returned a non-advancing manifest cursor");
                    }
                    // Legacy servers advertise the first OMITTED path in next,
                    // but their SQL cursor is exclusive. Resume at the last
                    // returned path so no file is skipped, on either version.
                    after = previous_path;
                }
                None => break,
            }
        }
        Ok(Manifest {
            generation: generation.unwrap_or_default(),
            entries,
        })
    }

    pub(super) async fn upload(
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
        // Leave room for EOF without growing the allocation of a stable file.
        let mut bytes = Vec::with_capacity(size as usize + 1);
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
        Ok(Some(
            authenticated_json(response, CONTROL_JSON_LIMIT).await?,
        ))
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
        let mut progress: UploadProgress = authenticated_json(response, CONTROL_JSON_LIMIT).await?;
        if progress.offset < 0 || progress.offset > size {
            bail!("server returned an invalid upload offset");
        }
        let mut file = tokio::fs::File::from_std(local);
        file.seek(SeekFrom::Start(progress.offset as u64)).await?;
        while progress.offset < size {
            let length = (size - progress.offset).min(UPLOAD_CHUNK_BYTES) as u64;
            // The length is bounded by our protocol constant, not chosen by
            // the server. Avoid repeated Vec growth/copies and fd duplication.
            let mut bytes = vec![0; length as usize];
            file.read_exact(&mut bytes)
                .await
                .context("local file changed during upload")?;
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
            let next: UploadProgress = authenticated_json(response, CONTROL_JSON_LIMIT).await?;
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
        Ok(Some(
            authenticated_json(response, CONTROL_JSON_LIMIT).await?,
        ))
    }

    pub(super) async fn delete(&self, path: &str, base: i64) -> Result<Option<Entry>> {
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
        Ok(Some(
            authenticated_json(response, CONTROL_JSON_LIMIT).await?,
        ))
    }

    pub(super) async fn download(&self, entry: &Entry, file: std::fs::File) -> Result<bool> {
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
        let response = response.error_for_status()?.response;
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
        if Some(hex::encode(hash.finish())) != entry.sha256 || size != expected_size {
            bail!("download integrity check failed for {}", entry.path);
        }
        Ok(true)
    }

    pub async fn trash(&self) -> Result<Vec<TrashItem>> {
        authenticated_json(
            self.send(self.http.get(self.url("/v1/trash"))).await?,
            LIST_JSON_LIMIT,
        )
        .await
    }

    pub async fn restore(&self, id: i64) -> Result<Entry> {
        authenticated_json(
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
