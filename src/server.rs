use std::{
    collections::HashSet,
    io::{Read, SeekFrom, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow};
use axum::{
    Extension, Json, Router,
    body::Body,
    extract::{Path as UrlPath, Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use futures_util::StreamExt;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncSeekExt, AsyncWriteExt};
use tokio_util::io::ReaderStream;
use uuid::Uuid;

use crate::model::{
    BeginUpload, Entry, Manifest, RestoreRequest, TrashItem, UPLOAD_CHUNK_BYTES, UploadProgress,
    valid_path,
};
use crate::release;

const RETENTION_SECONDS: i64 = 30 * 24 * 60 * 60;
const UPLOAD_SESSION_SECONDS: i64 = 24 * 60 * 60;
const MAX_UPLOAD_SESSIONS_PER_DEVICE: i64 = 16;

pub struct ServerState {
    data_dir: PathBuf,
    releases_dir: Option<crate::local_fs::Mirror>,
    pub(crate) db: Mutex<Connection>,
    pub(crate) enrollment_limit: tokio::sync::Semaphore,
    pub(crate) signed_request_limit: tokio::sync::Semaphore,
    active_uploads: Mutex<HashSet<String>>,
}

struct ActiveUpload {
    state: Arc<ServerState>,
    id: String,
}

impl Drop for ActiveUpload {
    fn drop(&mut self) {
        self.state.active_uploads.lock().unwrap().remove(&self.id);
    }
}

#[derive(Debug)]
struct UploadRow {
    id: String,
    path: String,
    base_revision: i64,
    size: i64,
    sha256: String,
    offset: i64,
    temp_name: String,
}

#[derive(Deserialize)]
struct ChunkQuery {
    offset: i64,
}

#[derive(Debug)]
struct StoredEntry {
    public: Entry,
    blob: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct FileQuery {
    path: String,
    #[serde(default)]
    revision: Option<i64>,
    #[serde(default)]
    base_revision: Option<i64>,
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

pub struct ApiError(pub(crate) StatusCode, pub(crate) String);

impl ApiError {
    fn bad(message: impl Into<String>) -> Self {
        Self(StatusCode::BAD_REQUEST, message.into())
    }

    pub(crate) fn conflict(message: impl Into<String>) -> Self {
        Self(StatusCode::CONFLICT, message.into())
    }

    pub(crate) fn internal(error: impl std::fmt::Display) -> Self {
        eprintln!("server error: {error}");
        Self(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal server error".into(),
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(ErrorBody { error: self.1 })).into_response()
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before UNIX epoch")
        .as_secs() as i64
}

fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

fn private_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

pub fn open(data_dir: impl AsRef<Path>) -> Result<Arc<ServerState>> {
    open_with_releases(data_dir, None)
}

pub fn open_with_releases(
    data_dir: impl AsRef<Path>,
    releases_dir: Option<PathBuf>,
) -> Result<Arc<ServerState>> {
    let data_dir = data_dir.as_ref().to_path_buf();
    private_dir(&data_dir)?;
    private_dir(&data_dir.join("blobs"))?;
    private_dir(&data_dir.join("tmp"))?;
    let conn = Connection::open(data_dir.join("metadata.sqlite3"))?;
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA foreign_keys = ON;
         CREATE TABLE IF NOT EXISTS meta (
             key TEXT PRIMARY KEY, value INTEGER NOT NULL
         );
         INSERT OR IGNORE INTO meta(key, value) VALUES('generation', 0);
         CREATE TABLE IF NOT EXISTS devices (
             id INTEGER PRIMARY KEY,
             name TEXT NOT NULL UNIQUE,
             token_hash TEXT NOT NULL UNIQUE,
             created_at INTEGER NOT NULL,
             revoked_at INTEGER
         );
         CREATE TABLE IF NOT EXISTS entries (
             path TEXT PRIMARY KEY,
             revision INTEGER NOT NULL,
             blob TEXT,
             sha256 TEXT,
             size INTEGER,
             deleted INTEGER NOT NULL,
             updated_at INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS trash (
             id INTEGER PRIMARY KEY,
             path TEXT NOT NULL,
             blob TEXT NOT NULL,
             sha256 TEXT NOT NULL,
             size INTEGER NOT NULL,
             deleted_at INTEGER NOT NULL,
             expires_at INTEGER NOT NULL
         );
         CREATE INDEX IF NOT EXISTS trash_expires ON trash(expires_at);
         CREATE TABLE IF NOT EXISTS uploads (
             id TEXT PRIMARY KEY,
             device_id INTEGER NOT NULL,
             path TEXT NOT NULL,
             base_revision INTEGER NOT NULL,
             size INTEGER NOT NULL,
             sha256 TEXT NOT NULL,
             received_size INTEGER NOT NULL DEFAULT 0,
             temp_name TEXT NOT NULL,
             touched_at INTEGER NOT NULL,
             FOREIGN KEY(device_id) REFERENCES devices(id)
         );
         CREATE INDEX IF NOT EXISTS uploads_touched ON uploads(touched_at);",
    )?;
    crate::device_auth::initialize(&conn)?;
    Ok(Arc::new(ServerState {
        data_dir,
        releases_dir: releases_dir
            .as_deref()
            .map(crate::local_fs::Mirror::open)
            .transpose()?,
        db: Mutex::new(conn),
        enrollment_limit: tokio::sync::Semaphore::new(4),
        signed_request_limit: tokio::sync::Semaphore::new(8),
        active_uploads: Mutex::new(HashSet::new()),
    }))
}

pub fn add_device(state: &ServerState, name: &str) -> Result<String> {
    let token = new_device_token();
    insert_device(state, name, &token)?;
    Ok(token)
}

fn new_device_token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

fn insert_device(state: &ServerState, name: &str, token: &str) -> Result<()> {
    if name.trim().is_empty() {
        return Err(anyhow!("device name cannot be empty"));
    }
    let db = state.db.lock().unwrap();
    let allowed: bool = db.query_row(
        "SELECT value='1' FROM auth_settings WHERE key='allow_legacy'",
        [],
        |r| r.get(0),
    )?;
    if !allowed {
        return Err(anyhow!(
            "legacy keys disabled; use device invite for TPM enrollment"
        ));
    }
    db.execute(
        "INSERT INTO devices(name, token_hash, created_at) VALUES(?1, ?2, ?3)",
        params![name, token_hash(&token), now()],
    )?;
    Ok(())
}

pub fn add_device_to_file(state: &ServerState, name: &str, path: &Path) -> Result<()> {
    if name.trim().is_empty() {
        return Err(anyhow!("device name cannot be empty"));
    }
    let token = new_device_token();
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    let result: Result<()> = (|| {
        writeln!(file, "{token}")?;
        file.sync_all()?;
        insert_device(state, name, &token)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(path);
    }
    result
}

pub fn list_devices(state: &ServerState) -> Result<Vec<(i64, String, bool)>> {
    let db = state.db.lock().unwrap();
    let mut query =
        db.prepare("SELECT id, name, revoked_at IS NOT NULL FROM devices ORDER BY id")?;
    let rows = query.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

pub fn revoke_device(state: &ServerState, name: &str) -> Result<bool> {
    let mut db = state.db.lock().unwrap();
    let tx = db.transaction()?;
    let count = tx.execute(
        "UPDATE devices SET revoked_at = ?2 WHERE name = ?1 AND revoked_at IS NULL",
        params![name, now()],
    )?;
    tx.execute("DELETE FROM device_sessions WHERE enrollment_id IN(SELECT e.id FROM device_enrollments e JOIN devices d ON e.device_id=d.id WHERE d.name=?1)",[name])?;
    tx.commit()?;
    Ok(count > 0)
}

fn validate_path(path: &str) -> Result<(), ApiError> {
    if valid_path(path) {
        Ok(())
    } else {
        Err(ApiError::bad("invalid path"))
    }
}

fn stored_entry(db: &Connection, path: &str) -> rusqlite::Result<Option<StoredEntry>> {
    db.query_row(
        "SELECT revision, blob, sha256, size, deleted FROM entries WHERE path = ?1",
        [path],
        |row| {
            Ok(StoredEntry {
                public: Entry {
                    path: path.to_owned(),
                    revision: row.get(0)?,
                    sha256: row.get(2)?,
                    size: row.get(3)?,
                    deleted: row.get(4)?,
                },
                blob: row.get(1)?,
            })
        },
    )
    .optional()
}

// Call under the same transaction as the mutation: two simultaneous uploads
// must not publish a file and one of its descendants. Avoid LIKE, whose case
// folding and wildcard characters do not match Linux filename semantics.
fn check_path_namespace(db: &Connection, path: &str) -> Result<(), ApiError> {
    for (index, _) in path.match_indices('/') {
        if stored_entry(db, &path[..index])
            .map_err(ApiError::internal)?
            .is_some_and(|entry| !entry.public.deleted)
        {
            return Err(ApiError::conflict(
                "an ancestor of this path is a live file",
            ));
        }
    }
    let has_descendant: bool = db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM entries
             WHERE path >= ?1 AND path < ?2 AND deleted = 0)",
            params![format!("{path}/"), format!("{path}0")],
            |row| row.get(0),
        )
        .map_err(ApiError::internal)?;
    if has_descendant {
        return Err(ApiError::conflict("this path contains live files"));
    }
    Ok(())
}

fn next_revision(db: &Connection) -> rusqlite::Result<i64> {
    db.execute(
        "UPDATE meta SET value = value + 1 WHERE key = 'generation'",
        [],
    )?;
    db.query_row(
        "SELECT value FROM meta WHERE key = 'generation'",
        [],
        |row| row.get(0),
    )
}

async fn health() -> &'static str {
    "ok"
}

async fn client_release(
    State(state): State<Arc<ServerState>>,
    UrlPath((target, file)): UrlPath<(String, String)>,
) -> Result<Response, ApiError> {
    if !release::valid_target(&target) || !release::valid_release_file(&file) {
        return Err(ApiError(StatusCode::NOT_FOUND, "release not found".into()));
    }
    let root = state
        .releases_dir
        .as_ref()
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "release not found".into()))?;
    // Pin the configured root at startup and open every component with
    // O_NOFOLLOW. The length and stream must refer to the very same inode.
    let opened = root
        .read(&format!("{target}/{file}"))
        .map_err(|_| ApiError(StatusCode::NOT_FOUND, "release not found".into()))?
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "release not found".into()))?;
    let metadata = opened.metadata().map_err(ApiError::internal)?;
    let opened = tokio::fs::File::from_std(opened);
    let cache = if file.starts_with("latest.") {
        "public, no-cache"
    } else {
        "public, max-age=31536000, immutable"
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, metadata.len().to_string())
        .header(header::CACHE_CONTROL, cache)
        .body(Body::from_stream(ReaderStream::new(opened)))
        .map_err(ApiError::internal)
}

async fn manifest(
    State(state): State<Arc<ServerState>>,
    Extension(_device): Extension<i64>,
) -> Result<Json<Manifest>, ApiError> {
    let db = state.db.lock().unwrap();
    let generation = db
        .query_row(
            "SELECT value FROM meta WHERE key = 'generation'",
            [],
            |row| row.get(0),
        )
        .map_err(ApiError::internal)?;
    let mut query = db
        .prepare("SELECT path, revision, sha256, size, deleted FROM entries ORDER BY path")
        .map_err(ApiError::internal)?;
    let entries = query
        .query_map([], |row| {
            Ok(Entry {
                path: row.get(0)?,
                revision: row.get(1)?,
                sha256: row.get(2)?,
                size: row.get(3)?,
                deleted: row.get(4)?,
            })
        })
        .map_err(ApiError::internal)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(ApiError::internal)?;
    Ok(Json(Manifest {
        generation,
        entries,
    }))
}

async fn download(
    State(state): State<Arc<ServerState>>,
    Extension(_device): Extension<i64>,
    Query(query): Query<FileQuery>,
) -> Result<Response, ApiError> {
    validate_path(&query.path)?;
    let requested = query
        .revision
        .ok_or_else(|| ApiError::bad("revision required"))?;
    let (file, size) = {
        let db = state.db.lock().unwrap();
        let current = stored_entry(&db, &query.path).map_err(ApiError::internal)?;
        let current =
            current.ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "file not found".into()))?;
        if current.public.revision != requested || current.public.deleted {
            return Err(ApiError::conflict("revision changed"));
        }
        let blob = current
            .blob
            .ok_or_else(|| ApiError::internal("missing blob reference"))?;
        let file = std::fs::File::open(state.data_dir.join("blobs").join(blob))
            .map_err(ApiError::internal)?;
        (file, current.public.size.unwrap_or(0))
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, size.to_string())
        .body(Body::from_stream(ReaderStream::new(
            tokio::fs::File::from_std(file),
        )))
        .map_err(ApiError::internal)
}

async fn upload(
    State(state): State<Arc<ServerState>>,
    Extension(_device): Extension<i64>,
    Query(query): Query<FileQuery>,
    body: Body,
) -> Result<Json<Entry>, ApiError> {
    validate_path(&query.path)?;
    let base = query
        .base_revision
        .ok_or_else(|| ApiError::bad("base_revision required"))?;
    if base < 0 {
        return Err(ApiError::bad("invalid base_revision"));
    }
    let temp_name = Uuid::new_v4().to_string();
    let temp_path = state.data_dir.join("tmp").join(&temp_name);
    let mut file = tokio::fs::File::create(&temp_path)
        .await
        .map_err(ApiError::internal)?;
    let mut stream = body.into_data_stream();
    let mut hash = Sha256::new();
    let mut size: i64 = 0;
    let write_result: Result<(), ApiError> = async {
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(ApiError::internal)?;
            size = size
                .checked_add(chunk.len() as i64)
                .ok_or_else(|| ApiError::bad("file is too large"))?;
            if size > UPLOAD_CHUNK_BYTES {
                return Err(ApiError(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "use chunked upload for files larger than 8 MiB".into(),
                ));
            }
            hash.update(&chunk);
            file.write_all(&chunk).await.map_err(ApiError::internal)?;
        }
        file.sync_all().await.map_err(ApiError::internal)?;
        Ok(())
    }
    .await;
    drop(file);
    if let Err(error) = write_result {
        let _ = tokio::fs::remove_file(&temp_path).await;
        return Err(error);
    }
    let digest = hex::encode(hash.finalize());
    let result = commit_upload(&state, &query.path, base, &temp_path, digest, size);
    if result.is_err() {
        let _ = tokio::fs::remove_file(&temp_path).await;
    }
    result.map(Json)
}

fn commit_upload(
    state: &ServerState,
    path: &str,
    base: i64,
    temp_path: &Path,
    digest: String,
    size: i64,
) -> Result<Entry, ApiError> {
    validate_path(path)?;
    let mut db = state.db.lock().unwrap();
    let tx = db.transaction().map_err(ApiError::internal)?;
    check_path_namespace(&tx, path)?;
    let previous = stored_entry(&tx, path).map_err(ApiError::internal)?;
    let current_revision = previous
        .as_ref()
        .map(|entry| entry.public.revision)
        .unwrap_or(0);
    if current_revision != base {
        return Err(ApiError::conflict("server version wins; refresh manifest"));
    }
    let revision = next_revision(&tx).map_err(ApiError::internal)?;
    let blob = Uuid::new_v4().to_string();
    tx.execute(
        "INSERT INTO entries(path, revision, blob, sha256, size, deleted, updated_at)
         VALUES(?1, ?2, ?3, ?4, ?5, 0, ?6)
         ON CONFLICT(path) DO UPDATE SET revision = excluded.revision, blob = excluded.blob,
             sha256 = excluded.sha256, size = excluded.size, deleted = 0,
             updated_at = excluded.updated_at",
        params![path, revision, blob, digest, size, now()],
    )
    .map_err(ApiError::internal)?;
    let new_blob_path = state.data_dir.join("blobs").join(&blob);
    std::fs::rename(temp_path, &new_blob_path).map_err(ApiError::internal)?;
    if let Err(error) = tx.commit() {
        let _ = std::fs::remove_file(&new_blob_path);
        return Err(ApiError::internal(error));
    }
    if let Some(old_blob) = previous.and_then(|entry| entry.blob) {
        let _ = std::fs::remove_file(state.data_dir.join("blobs").join(old_blob));
    }
    Ok(Entry {
        path: path.to_owned(),
        revision,
        sha256: Some(digest),
        size: Some(size),
        deleted: false,
    })
}

fn lock_upload(state: &Arc<ServerState>, id: &str) -> Result<ActiveUpload, ApiError> {
    let mut active = state.active_uploads.lock().unwrap();
    if !active.insert(id.to_owned()) {
        return Err(ApiError::conflict("upload is already in progress"));
    }
    Ok(ActiveUpload {
        state: state.clone(),
        id: id.to_owned(),
    })
}

fn upload_row(db: &Connection, id: &str, device_id: i64) -> rusqlite::Result<Option<UploadRow>> {
    db.query_row(
        "SELECT id, path, base_revision, size, sha256, received_size, temp_name
         FROM uploads WHERE id = ?1 AND device_id = ?2",
        params![id, device_id],
        |row| {
            Ok(UploadRow {
                id: row.get(0)?,
                path: row.get(1)?,
                base_revision: row.get(2)?,
                size: row.get(3)?,
                sha256: row.get(4)?,
                offset: row.get(5)?,
                temp_name: row.get(6)?,
            })
        },
    )
    .optional()
}

async fn begin_upload(
    State(state): State<Arc<ServerState>>,
    Extension(device_id): Extension<i64>,
    Json(request): Json<BeginUpload>,
) -> Result<Json<UploadProgress>, ApiError> {
    validate_path(&request.path)?;
    if request.base_revision < 0
        || request.size < 0
        || request.sha256.len() != 64
        || !request.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(ApiError::bad("invalid upload metadata"));
    }
    let db = state.db.lock().unwrap();
    check_path_namespace(&db, &request.path)?;
    let current = stored_entry(&db, &request.path).map_err(ApiError::internal)?;
    if current.map(|entry| entry.public.revision).unwrap_or(0) != request.base_revision {
        return Err(ApiError::conflict("server version wins; refresh manifest"));
    }
    let existing: Option<(String, i64, String)> = db
        .query_row(
            "SELECT id, received_size, temp_name FROM uploads
             WHERE device_id = ?1 AND path = ?2 AND base_revision = ?3
               AND size = ?4 AND sha256 = ?5 ORDER BY touched_at DESC LIMIT 1",
            params![
                device_id,
                request.path,
                request.base_revision,
                request.size,
                request.sha256
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(ApiError::internal)?;
    if let Some((id, offset, temp_name)) = existing {
        if state.data_dir.join("tmp").join(temp_name).exists() && offset <= request.size {
            db.execute(
                "UPDATE uploads SET touched_at = ?2 WHERE id = ?1",
                params![id, now()],
            )
            .map_err(ApiError::internal)?;
            return Ok(Json(UploadProgress { id, offset }));
        }
        db.execute("DELETE FROM uploads WHERE id = ?1", [&id])
            .map_err(ApiError::internal)?;
    }
    let pending: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM uploads WHERE device_id = ?1",
            [device_id],
            |row| row.get(0),
        )
        .map_err(ApiError::internal)?;
    if pending >= MAX_UPLOAD_SESSIONS_PER_DEVICE {
        return Err(ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            "too many pending uploads for this device".into(),
        ));
    }
    let id = Uuid::new_v4().to_string();
    let temp = state.data_dir.join("tmp").join(&id);
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .map_err(ApiError::internal)?;
    if let Err(error) = db.execute(
        "INSERT INTO uploads(id, device_id, path, base_revision, size, sha256,
             received_size, temp_name, touched_at) VALUES(?1, ?2, ?3, ?4, ?5, ?6, 0, ?7, ?8)",
        params![
            id,
            device_id,
            request.path,
            request.base_revision,
            request.size,
            request.sha256,
            id,
            now()
        ],
    ) {
        let _ = std::fs::remove_file(&temp);
        return Err(ApiError::internal(error));
    }
    Ok(Json(UploadProgress { id, offset: 0 }))
}

async fn upload_chunk(
    State(state): State<Arc<ServerState>>,
    Extension(device_id): Extension<i64>,
    UrlPath(id): UrlPath<String>,
    Query(query): Query<ChunkQuery>,
    body: Body,
) -> Result<Json<UploadProgress>, ApiError> {
    let _guard = lock_upload(&state, &id)?;
    let session = {
        let db = state.db.lock().unwrap();
        upload_row(&db, &id, device_id)
            .map_err(ApiError::internal)?
            .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "upload not found".into()))?
    };
    if query.offset != session.offset {
        return Err(ApiError::conflict(
            "upload offset changed; retry synchronization",
        ));
    }
    let remaining = session.size - session.offset;
    if remaining <= 0 {
        return Err(ApiError::bad("upload already complete"));
    }
    let temp = state.data_dir.join("tmp").join(&session.temp_name);
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .open(&temp)
        .await
        .map_err(ApiError::internal)?;
    file.set_len(session.offset as u64)
        .await
        .map_err(ApiError::internal)?;
    file.seek(SeekFrom::Start(session.offset as u64))
        .await
        .map_err(ApiError::internal)?;
    let mut stream = body.into_data_stream();
    let mut written = 0_i64;
    let result: Result<(), ApiError> = async {
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(ApiError::internal)?;
            written = written
                .checked_add(chunk.len() as i64)
                .ok_or_else(|| ApiError::bad("chunk is too large"))?;
            if written > UPLOAD_CHUNK_BYTES || written > remaining {
                return Err(ApiError(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "chunk is too large".into(),
                ));
            }
            file.write_all(&chunk).await.map_err(ApiError::internal)?;
        }
        if written == 0 {
            return Err(ApiError::bad("empty upload chunk"));
        }
        file.sync_all().await.map_err(ApiError::internal)?;
        Ok(())
    }
    .await;
    if let Err(error) = result {
        let _ = file.set_len(session.offset as u64).await;
        return Err(error);
    }
    let offset = session.offset + written;
    let updated = state
        .db
        .lock()
        .unwrap()
        .execute(
            "UPDATE uploads SET received_size = ?3, touched_at = ?4
             WHERE id = ?1 AND device_id = ?2 AND received_size = ?5",
            params![id, device_id, offset, now(), session.offset],
        )
        .map_err(ApiError::internal)?;
    if updated != 1 {
        return Err(ApiError::conflict(
            "upload offset changed; retry synchronization",
        ));
    }
    Ok(Json(UploadProgress { id, offset }))
}

fn hash_upload(path: &Path) -> Result<(String, i64)> {
    let mut file = std::fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut size = 0_i64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
        size += read as i64;
    }
    Ok((hex::encode(hash.finalize()), size))
}

async fn finish_upload(
    State(state): State<Arc<ServerState>>,
    Extension(device_id): Extension<i64>,
    UrlPath(id): UrlPath<String>,
) -> Result<Json<Entry>, ApiError> {
    let _guard = lock_upload(&state, &id)?;
    let session = {
        let db = state.db.lock().unwrap();
        upload_row(&db, &id, device_id)
            .map_err(ApiError::internal)?
            .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "upload not found".into()))?
    };
    if session.offset != session.size {
        return Err(ApiError::bad("upload is incomplete"));
    }
    let temp = state.data_dir.join("tmp").join(&session.temp_name);
    let hash_path = temp.clone();
    let (digest, size) = tokio::task::spawn_blocking(move || hash_upload(&hash_path))
        .await
        .map_err(ApiError::internal)?
        .map_err(ApiError::internal)?;
    if digest != session.sha256 || size != session.size {
        state
            .db
            .lock()
            .unwrap()
            .execute("DELETE FROM uploads WHERE id = ?1", [&id])
            .map_err(ApiError::internal)?;
        let _ = std::fs::remove_file(&temp);
        return Err(ApiError::bad("upload integrity check failed"));
    }
    let result = commit_upload(
        &state,
        &session.path,
        session.base_revision,
        &temp,
        digest,
        size,
    );
    if result.is_ok()
        || result
            .as_ref()
            .is_err_and(|error| error.0 == StatusCode::CONFLICT)
    {
        state
            .db
            .lock()
            .unwrap()
            .execute("DELETE FROM uploads WHERE id = ?1", [&session.id])
            .map_err(ApiError::internal)?;
        let _ = std::fs::remove_file(&temp);
    }
    result.map(Json)
}

async fn delete(
    State(state): State<Arc<ServerState>>,
    Extension(_device): Extension<i64>,
    Query(query): Query<FileQuery>,
) -> Result<Json<Entry>, ApiError> {
    validate_path(&query.path)?;
    let base = query
        .base_revision
        .ok_or_else(|| ApiError::bad("base_revision required"))?;
    let mut db = state.db.lock().unwrap();
    let tx = db.transaction().map_err(ApiError::internal)?;
    let current = stored_entry(&tx, &query.path).map_err(ApiError::internal)?;
    let current = current.ok_or_else(|| ApiError::conflict("file is absent on server"))?;
    if current.public.revision != base {
        return Err(ApiError::conflict("server version wins; refresh manifest"));
    }
    if current.public.deleted {
        return Ok(Json(current.public));
    }
    let deleted_at = now();
    tx.execute(
        "INSERT INTO trash(path, blob, sha256, size, deleted_at, expires_at)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            query.path,
            current.blob,
            current.public.sha256,
            current.public.size,
            deleted_at,
            deleted_at + RETENTION_SECONDS
        ],
    )
    .map_err(ApiError::internal)?;
    let revision = next_revision(&tx).map_err(ApiError::internal)?;
    tx.execute(
        "UPDATE entries SET revision = ?2, blob = NULL, sha256 = NULL, size = NULL,
             deleted = 1, updated_at = ?3 WHERE path = ?1",
        params![query.path, revision, deleted_at],
    )
    .map_err(ApiError::internal)?;
    tx.commit().map_err(ApiError::internal)?;
    Ok(Json(Entry {
        path: query.path,
        revision,
        sha256: None,
        size: None,
        deleted: true,
    }))
}

async fn list_trash(
    State(state): State<Arc<ServerState>>,
    Extension(_device): Extension<i64>,
) -> Result<Json<Vec<TrashItem>>, ApiError> {
    let db = state.db.lock().unwrap();
    let mut query = db
        .prepare("SELECT id, path, size, deleted_at, expires_at FROM trash WHERE expires_at > ?1 ORDER BY deleted_at DESC")
        .map_err(ApiError::internal)?;
    let items = query
        .query_map([now()], |row| {
            Ok(TrashItem {
                id: row.get(0)?,
                path: row.get(1)?,
                size: row.get(2)?,
                deleted_at: row.get(3)?,
                expires_at: row.get(4)?,
            })
        })
        .map_err(ApiError::internal)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(ApiError::internal)?;
    Ok(Json(items))
}

async fn restore(
    State(state): State<Arc<ServerState>>,
    Extension(_device): Extension<i64>,
    Json(request): Json<RestoreRequest>,
) -> Result<Json<Entry>, ApiError> {
    let mut db = state.db.lock().unwrap();
    let tx = db.transaction().map_err(ApiError::internal)?;
    let item: Option<(String, String, String, i64)> = tx
        .query_row(
            "SELECT path, blob, sha256, size FROM trash WHERE id = ?1 AND expires_at > ?2",
            params![request.id, now()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(ApiError::internal)?;
    let (path, blob, digest, size) =
        item.ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "trash item not found".into()))?;
    validate_path(&path)?;
    check_path_namespace(&tx, &path)?;
    if stored_entry(&tx, &path)
        .map_err(ApiError::internal)?
        .is_some_and(|entry| !entry.public.deleted)
    {
        return Err(ApiError::conflict(
            "a live file already exists at this path",
        ));
    }
    let revision = next_revision(&tx).map_err(ApiError::internal)?;
    tx.execute(
        "INSERT INTO entries(path, revision, blob, sha256, size, deleted, updated_at)
         VALUES(?1, ?2, ?3, ?4, ?5, 0, ?6)
         ON CONFLICT(path) DO UPDATE SET revision = excluded.revision, blob = excluded.blob,
             sha256 = excluded.sha256, size = excluded.size, deleted = 0,
             updated_at = excluded.updated_at",
        params![path, revision, blob, digest, size, now()],
    )
    .map_err(ApiError::internal)?;
    tx.execute("DELETE FROM trash WHERE id = ?1", [request.id])
        .map_err(ApiError::internal)?;
    tx.commit().map_err(ApiError::internal)?;
    Ok(Json(Entry {
        path,
        revision,
        sha256: Some(digest),
        size: Some(size),
        deleted: false,
    }))
}

pub fn purge_expired(state: &ServerState) -> Result<usize> {
    let mut db = state.db.lock().unwrap();
    let tx = db.transaction()?;
    let cutoff = now();
    let blobs = {
        let mut query = tx.prepare("SELECT blob FROM trash WHERE expires_at <= ?1")?;
        query
            .query_map([cutoff], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    tx.execute("DELETE FROM trash WHERE expires_at <= ?1", [cutoff])?;
    tx.commit()?;
    for blob in &blobs {
        let _ = std::fs::remove_file(state.data_dir.join("blobs").join(blob));
    }
    Ok(blobs.len())
}

pub fn purge_trash_item(state: &ServerState, id: i64) -> Result<bool> {
    let mut db = state.db.lock().unwrap();
    let tx = db.transaction()?;
    let blob: Option<String> = tx
        .query_row("SELECT blob FROM trash WHERE id = ?1", [id], |row| {
            row.get(0)
        })
        .optional()?;
    let Some(blob) = blob else {
        return Ok(false);
    };
    tx.execute("DELETE FROM trash WHERE id = ?1", [id])?;
    tx.commit()?;
    match std::fs::remove_file(state.data_dir.join("blobs").join(blob)) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(true)
}

pub fn purge_upload_sessions(state: &ServerState) -> Result<usize> {
    let active = state.active_uploads.lock().unwrap();
    let db = state.db.lock().unwrap();
    let mut query = db.prepare("SELECT id, temp_name FROM uploads WHERE touched_at < ?1")?;
    let stale = query
        .query_map([now() - UPLOAD_SESSION_SECONDS], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut removed = 0;
    for (id, temp_name) in stale {
        if active.contains(&id) {
            continue;
        }
        db.execute("DELETE FROM uploads WHERE id = ?1", [&id])?;
        let _ = std::fs::remove_file(state.data_dir.join("tmp").join(temp_name));
        removed += 1;
    }
    Ok(removed)
}

pub fn router(state: Arc<ServerState>) -> Router {
    let protected = Router::new()
        .route("/v1/manifest", get(manifest))
        .route("/v1/file", get(download).put(upload).delete(delete))
        .route("/v1/uploads", post(begin_upload))
        .route("/v1/uploads/{id}", axum::routing::put(upload_chunk))
        .route("/v1/uploads/{id}/commit", post(finish_upload))
        .route("/v1/trash", get(list_trash))
        .route("/v1/trash/restore", post(restore))
        .route("/v1/auth/session", post(crate::device_auth::session))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::device_auth::middleware,
        ));
    Router::new()
        .merge(protected)
        .route("/v1/health", get(health))
        .route("/v1/updates/{target}/{file}", get(client_release))
        .route("/v1/enroll/start", post(crate::device_auth::enroll_start))
        .route("/v1/enroll/finish", post(crate::device_auth::enroll_finish))
        .layer(axum::extract::DefaultBodyLimit::max(256 * 1024))
        .with_state(state)
}

pub async fn serve(
    data_dir: impl AsRef<Path>,
    listen: SocketAddr,
    releases_dir: Option<PathBuf>,
) -> Result<()> {
    let state = open_with_releases(data_dir, releases_dir)?;
    purge_expired(&state).context("purging expired trash")?;
    purge_upload_sessions(&state).context("purging expired upload sessions")?;
    let purge_state = state.clone();
    tokio::spawn(async move {
        let mut timer = tokio::time::interval(Duration::from_secs(60 * 60));
        loop {
            timer.tick().await;
            if let Err(error) = purge_expired(&purge_state) {
                eprintln!("trash purge failed: {error:#}");
            }
            if let Err(error) = purge_upload_sessions(&purge_state) {
                eprintln!("upload cleanup failed: {error:#}");
            }
        }
    });
    let listener = tokio::net::TcpListener::bind(listen).await?;
    println!("mysync-server listening on {}", listener.local_addr()?);
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let shutdown = async move {
        tokio::select! {
            _ = terminate.recv() => {},
            _ = tokio::signal::ctrl_c() => {},
        }
    };
    axum::serve(listener, router(state))
        .with_graceful_shutdown(shutdown)
        .await?;
    Ok(())
}
