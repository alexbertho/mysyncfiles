//! Revision-checked edits and one-use local runner tickets. No server execution.
use super::*;
use crate::{
    auth_protocol::{hash, random_secret},
    editor_protocol::*,
    model::Entry,
    server,
};
use axum::{Extension, body::Bytes, extract::DefaultBodyLimit};
use std::io::Write;

struct EditFile {
    path: std::path::PathBuf,
    file: std::fs::File,
}
impl Drop for EditFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

pub(super) fn router() -> Router<Arc<ServerState>> {
    Router::new()
        .route(
            "/v1/web/editor/file",
            get(read).put(save).layer(DefaultBodyLimit::max(JSON_BYTES)),
        )
        .route("/v1/web/editor/{scope}/session", get(scoped_session))
        .route("/v1/web/editor/{scope}/challenges", post(challenge))
        .route(
            "/v1/web/editor/{scope}/challenges/{id}",
            get(challenge_result),
        )
        .route("/v1/web/editor/tickets", post(ticket))
}

fn scope(value: &str) -> Result<&'static str, ApiError> {
    match value {
        "edit" => Ok("files.edit"),
        "run" => Ok("code.run"),
        _ => Err(failure(StatusCode::NOT_FOUND, "invalid_scope")),
    }
}

fn grant(db: &Connection, headers: &HeaderMap, scope: &str) -> Result<(String, String), ApiError> {
    authorize(db, headers)?;
    let browser = web_status::named_session(db, headers, COOKIE)?;
    let id = db.query_row("SELECT challenge_id FROM web_editor_grants WHERE session_hash=?1 AND scope=?2 AND expires_at>?3",
        params![browser.hash, scope, now()], |r| r.get(0)).optional().map_err(ApiError::internal)?;
    Ok((
        browser.hash,
        id.ok_or_else(|| {
            failure(
                StatusCode::FORBIDDEN,
                if scope == "files.edit" {
                    "files_edit_required"
                } else {
                    "code_run_required"
                },
            )
        })?,
    ))
}

async fn scoped_session(
    State(state): State<Arc<ServerState>>,
    Path(value): Path<String>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    browser(&state, &headers, false)?;
    grant(&state.db.lock().unwrap(), &headers, scope(&value)?)?;
    Ok(Json(serde_json::json!({})))
}

async fn challenge(
    State(state): State<Arc<ServerState>>,
    Path(value): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<ChallengeResponse>, ApiError> {
    authorize(&state.db.lock().unwrap(), &headers)?;
    web_status::issue_challenge(&state, &headers, &body, COOKIE, scope(&value)?).map(Json)
}

async fn challenge_result(
    State(state): State<Arc<ServerState>>,
    Path((value, id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    browser(&state, &headers, false)?;
    let scope = scope(&value)?;
    let db = state.db.lock().unwrap();
    let session = web_status::named_session(&db, &headers, COOKIE)?;
    let row: Option<(bool, i64)> = db.query_row("SELECT result IS NOT NULL,expires_at FROM web_status_challenges WHERE session_hash=?1 AND id=?2 AND scope=?3",
        params![session.hash,id,scope], |r| Ok((r.get(0)?,r.get(1)?))).optional().map_err(ApiError::internal)?;
    match row {
        Some((true, _)) => {
            grant(&db, &headers, scope)?;
            Ok(Json(serde_json::json!({})))
        }
        Some((false, expires)) if expires > now() => Err(failure(StatusCode::ACCEPTED, "pending")),
        _ => Err(failure(StatusCode::GONE, "challenge_expired")),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileQuery {
    path: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct Source {
    entry: Entry,
    content: String,
}

fn source(state: &ServerState, db: &Connection, path: &str) -> Result<Source, ApiError> {
    if language(path).is_none() {
        return Err(failure(StatusCode::BAD_REQUEST, "unsupported_file"));
    }
    let stored = server::stored_entry(db, path)
        .map_err(ApiError::internal)?
        .filter(|e| !e.public.deleted)
        .ok_or_else(|| failure(StatusCode::NOT_FOUND, "file_not_found"))?;
    if !stored
        .public
        .size
        .is_some_and(|size| (0..=CODE_BYTES as i64).contains(&size))
    {
        return Err(failure(StatusCode::PAYLOAD_TOO_LARGE, "code_too_large"));
    }
    let mirror =
        crate::local_fs::Mirror::open(&state.data_dir.join("blobs")).map_err(ApiError::internal)?;
    let blob = stored
        .blob
        .ok_or_else(|| ApiError::internal("missing blob"))?;
    let file = mirror
        .read(&blob)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::internal("missing blob"))?;
    let mut bytes = Vec::new();
    file.take(CODE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(ApiError::internal)?;
    if bytes.len() > CODE_BYTES
        || stored.public.size != Some(bytes.len() as i64)
        || stored.public.sha256.as_deref() != Some(hash(&bytes).as_str())
    {
        return Err(failure(StatusCode::CONFLICT, "content_changed"));
    }
    let content =
        String::from_utf8(bytes).map_err(|_| failure(StatusCode::BAD_REQUEST, "invalid_text"))?;
    if content.contains('\0') {
        return Err(failure(StatusCode::BAD_REQUEST, "invalid_text"));
    }
    Ok(Source {
        entry: stored.public,
        content,
    })
}

async fn read(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Query(input): Query<FileQuery>,
) -> Result<Json<Source>, ApiError> {
    browser(&state, &headers, false)?;
    state
        .blocking(move |state| {
            let db = state.db.lock().unwrap();
            authorize(&db, &headers)?;
            source(&state, &db, &input.path).map(Json)
        })
        .await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Edit {
    path: String,
    base_revision: i64,
    content: String,
}

// Preserve rejected versions through directory descriptors, including when a
// directory is replaced concurrently. Never silently discard at the quota.
fn preserve(state: &ServerState, input: &Edit) -> Result<(), ApiError> {
    let mirror = crate::local_fs::Mirror::open(&state.data_dir).map_err(ApiError::internal)?;
    let mut total = input.content.len() as u64;
    let mut count = 0usize;
    let issues = mirror
        .visit_files(true, |_, file| {
            total = total.saturating_add(file.metadata()?.len());
            count += 1;
            Ok(())
        })
        .map_err(ApiError::internal)?;
    if !issues.is_empty() || total > 64 * 1024 * 1024 || count >= 4096 {
        return Err(failure(
            StatusCode::INSUFFICIENT_STORAGE,
            "conflict_storage_full",
        ));
    }
    let mut temp = mirror.download_file().map_err(ApiError::internal)?;
    temp.file
        .write_all(input.content.as_bytes())
        .map_err(ApiError::internal)?;
    temp.file.sync_all().map_err(ApiError::internal)?;
    let (destination, _) = mirror
        .conflict_entry(&format!("web/{}", input.path))
        .map_err(ApiError::internal)?;
    temp.entry.move_to(&destination).map_err(ApiError::internal)
}

async fn save(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Json(input): Json<Edit>,
) -> Result<Json<Entry>, ApiError> {
    browser(&state, &headers, true)?;
    if language(&input.path).is_none() || input.base_revision <= 0 || input.content.contains('\0') {
        return Err(failure(StatusCode::BAD_REQUEST, "invalid_edit"));
    }
    if input.content.len() > CODE_BYTES {
        return Err(failure(StatusCode::PAYLOAD_TOO_LARGE, "code_too_large"));
    }
    state
        .blocking(move |state| {
            grant(&state.db.lock().unwrap(), &headers, "files.edit")?;
            // UUID names participate in the server's existing crash recovery.
            use std::os::unix::fs::OpenOptionsExt;
            let path = state
                .data_dir
                .join("tmp")
                .join(uuid::Uuid::new_v4().to_string());
            let file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .map_err(ApiError::internal)?;
            let mut temp = EditFile { path, file };
            temp.file
                .write_all(input.content.as_bytes())
                .map_err(ApiError::internal)?;
            temp.file.sync_all().map_err(ApiError::internal)?;
            server::commit_upload_checked(
                &state,
                &input.path,
                input.base_revision,
                &temp.path,
                hash(&input.content),
                input.content.len() as i64,
                |db| {
                    grant(db, &headers, "files.edit")?;
                    let current =
                        server::stored_entry(db, &input.path).map_err(ApiError::internal)?;
                    if current.is_none_or(|entry| {
                        entry.public.deleted || entry.public.revision != input.base_revision
                    }) {
                        preserve(&state, &input)?;
                        return Err(failure(StatusCode::CONFLICT, "revision_changed"));
                    }
                    Ok(())
                },
            )
            .map(Json)
        })
        .await
}

async fn ticket(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Json(operation): Json<Operation>,
) -> Result<Json<serde_json::Value>, ApiError> {
    browser(&state, &headers, true)?;
    if !operation.valid() {
        return Err(failure(StatusCode::BAD_REQUEST, "invalid_operation"));
    }
    let db = state.db.lock().unwrap();
    let (session, grant_id) = grant(&db, &headers, "code.run")?;
    db.execute(
        "DELETE FROM web_runner_tickets WHERE expires_at<=?1",
        [now()],
    )
    .map_err(ApiError::internal)?;
    let pending: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM web_runner_tickets WHERE session_hash=?1",
            [&session],
            |r| r.get(0),
        )
        .map_err(ApiError::internal)?;
    if pending >= 8 {
        return Err(failure(StatusCode::TOO_MANY_REQUESTS, "runner_busy"));
    }
    let token = random_secret().map_err(ApiError::internal)?;
    db.execute(
        "INSERT INTO web_runner_tickets VALUES(?1,?2,?3,?4,?5)",
        params![
            hash(&token),
            session,
            grant_id,
            serde_json::to_string(&operation).map_err(ApiError::internal)?,
            now() + 15
        ],
    )
    .map_err(ApiError::internal)?;
    Ok(Json(serde_json::json!({"ticket":token})))
}

/// Machine-authenticated and origin-signed by the existing middleware. The
/// browser has neither the TPM proof nor authority to choose an instance ID.
pub(in crate::server) async fn runner_authorize(
    State(state): State<Arc<ServerState>>,
    Extension(device): Extension<i64>,
    Extension(enrollment): Extension<String>,
    Json(input): Json<AuthorizationRequest>,
) -> Result<Json<Authorization>, ApiError> {
    if !valid_secret(&input.ticket) || !valid_secret(&input.instance_id) {
        return Err(expired());
    }
    state.blocking(move |state| {
        let mut db = state.db.lock().unwrap();
        let tx = db.transaction().map_err(ApiError::internal)?;
        let row: Option<(String, String, String, i64)> = tx.query_row("SELECT t.operation,s.binding,g.challenge_id,MIN(g.expires_at,r.expires_at,s.expires_at)
            FROM web_runner_tickets t JOIN web_status_sessions s ON s.token_hash=t.session_hash
            JOIN web_editor_grants g ON g.session_hash=t.session_hash AND g.scope='code.run' AND g.challenge_id=t.grant_id
            JOIN web_file_grants r ON r.session_hash=t.session_hash
            JOIN devices d ON d.id=r.device_id JOIN device_enrollments e ON e.id=r.enrollment_id
            WHERE t.ticket_hash=?1 AND t.expires_at>?2 AND s.expires_at>?2 AND r.expires_at>?2 AND g.expires_at>?2
            AND g.instance_id=?3 AND r.device_id=?4 AND r.enrollment_id=?5 AND e.device_id=d.id
            AND d.revoked_at IS NULL AND e.verified_at IS NOT NULL AND e.approved_at IS NOT NULL",
            params![hash(&input.ticket),now(),input.instance_id,device,enrollment], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional().map_err(ApiError::internal)?;
        let (json,binding,grant_id,expires_at) = row.ok_or_else(expired)?;
        let operation: Operation = serde_json::from_str(&json).map_err(ApiError::internal)?;
        let source = if let Operation::Start { path, revision, sha256, .. } = &operation {
            let value = source(&state, &tx, path)?;
            if value.entry.revision != *revision || value.entry.sha256.as_ref() != Some(sha256) { return Err(failure(StatusCode::CONFLICT, "revision_changed")); }
            Some(value.content)
        } else { None };
        tx.execute("DELETE FROM web_runner_tickets WHERE ticket_hash=?1", [hash(&input.ticket)]).map_err(ApiError::internal)?;
        tx.commit().map_err(ApiError::internal)?;
        Ok(Json(Authorization { operation, owner: hash(format!("{binding}:{grant_id}")), source, expires_at }))
    }).await
}

#[cfg(test)]
mod tests;
