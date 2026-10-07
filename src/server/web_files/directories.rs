//! Atomic directory management with a separate, explicitly consented TPM scope.
use super::*;
use openssl::sha::Sha256;
use rusqlite::TransactionBehavior;

pub(super) const FILE_LIMIT: usize = 10_000;

pub(super) fn router() -> Router<Arc<ServerState>> {
    Router::new()
        .route("/v1/web/files/directories", get(properties))
        .route("/v1/web/files/directories/rename", post(rename))
        .route("/v1/web/files/directories/delete", post(delete))
        .route("/v1/web/files/manage/session", get(manage_session))
        .route("/v1/web/files/manage/challenges", post(challenge))
        .route(
            "/v1/web/files/manage/challenges/{id}",
            get(challenge_result),
        )
}

fn grant(db: &Connection, headers: &HeaderMap) -> Result<FileSession, ApiError> {
    let session = authorize(db, headers)?;
    let browser = web_status::named_session(db, headers, COOKIE)?;
    let accepted: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM web_file_manage_grants WHERE session_hash=?1 AND expires_at>?2)",
        params![browser.hash, now()], |row| row.get(0),
    ).map_err(ApiError::internal)?;
    if !accepted {
        return Err(failure(StatusCode::FORBIDDEN, "files_manage_required"));
    }
    Ok(session)
}

async fn manage_session(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
) -> Result<Json<FileSession>, ApiError> {
    browser(&state, &headers, false)?;
    grant(&state.db.lock().unwrap(), &headers).map(Json)
}

async fn challenge(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<ChallengeResponse>, ApiError> {
    browser(&state, &headers, true)?;
    authorize(&state.db.lock().unwrap(), &headers)?;
    web_status::issue_challenge(&state, &headers, &body, COOKIE, "files.manage").map(Json)
}

async fn challenge_result(
    State(state): State<Arc<ServerState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<FileSession>, ApiError> {
    browser(&state, &headers, false)?;
    let db = state.db.lock().unwrap();
    let session = web_status::named_session(&db, &headers, COOKIE).map_err(|_| expired())?;
    let pending: Option<(bool, i64)> = db.query_row(
        "SELECT result IS NULL,expires_at FROM web_status_challenges WHERE id=?1 AND session_hash=?2 AND scope='files.manage'",
        params![id, session.hash], |r| Ok((r.get(0)?, r.get(1)?)),
    ).optional().map_err(ApiError::internal)?;
    match pending {
        Some((false, _)) => grant(&db, &headers).map(Json),
        Some((true, expires)) if expires > now() => Err(failure(StatusCode::ACCEPTED, "pending")),
        _ => Err(failure(StatusCode::GONE, "challenge_expired")),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectoryQuery {
    path: String,
}

#[derive(Debug, Serialize)]
struct DirectoryInfo {
    path: String,
    size: i64,
    file_count: usize,
    updated_at: i64,
    snapshot: Option<String>,
}

struct DirectoryFile {
    path: String,
    revision: i64,
    blob: String,
    sha256: String,
    size: i64,
}

fn files(db: &Connection, path: &str) -> Result<Vec<DirectoryFile>, ApiError> {
    let mut query = db.prepare("SELECT path,revision,blob,sha256,size FROM entries WHERE deleted=0 AND path>=?1 AND path<?2 ORDER BY path LIMIT ?3").map_err(ApiError::internal)?;
    query
        .query_map(
            params![
                format!("{path}/"),
                format!("{path}0"),
                (FILE_LIMIT + 1) as i64
            ],
            |r| {
                Ok(DirectoryFile {
                    path: r.get(0)?,
                    revision: r.get(1)?,
                    blob: r.get(2)?,
                    sha256: r.get(3)?,
                    size: r.get(4)?,
                })
            },
        )
        .map_err(ApiError::internal)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(ApiError::internal)
}

fn fingerprint(files: &[DirectoryFile]) -> String {
    let mut hash = Sha256::new();
    for file in files {
        hash.update(&(file.path.len() as u64).to_be_bytes());
        hash.update(file.path.as_bytes());
        hash.update(&file.revision.to_be_bytes());
    }
    hex::encode(hash.finish())
}

fn info(db: &Connection, path: &str) -> Result<DirectoryInfo, ApiError> {
    super::super::validate_path(path)?;
    let (count, size, updated): (i64, i64, i64) = db.query_row(
        "SELECT COUNT(*),COALESCE(SUM(size),0),COALESCE(MAX(updated_at),0) FROM entries WHERE deleted=0 AND path>=?1 AND path<?2",
        params![format!("{path}/"), format!("{path}0")], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    ).map_err(ApiError::internal)?;
    let count = usize::try_from(count).map_err(ApiError::internal)?;
    if count == 0 {
        return Err(failure(StatusCode::NOT_FOUND, "directory_not_found"));
    }
    let snapshot = if count <= FILE_LIMIT {
        Some(fingerprint(&files(db, path)?))
    } else {
        None
    };
    Ok(DirectoryInfo {
        path: path.into(),
        size,
        file_count: count,
        updated_at: updated,
        snapshot,
    })
}

async fn properties(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Query(query): Query<DirectoryQuery>,
) -> Result<Json<DirectoryInfo>, ApiError> {
    browser(&state, &headers, false)?;
    state
        .blocking(move |state| {
            let mut db = state.db.lock().unwrap();
            let tx = db.transaction().map_err(ApiError::internal)?;
            authorize(&tx, &headers)?;
            info(&tx, &query.path).map(Json)
        })
        .await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Mutation {
    path: String,
    snapshot: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Rename {
    path: String,
    snapshot: String,
    name: String,
}

#[derive(Debug, Serialize)]
struct Changed {
    path: String,
    file_count: usize,
}

fn checked_files(
    db: &Connection,
    path: &str,
    snapshot: &str,
) -> Result<Vec<DirectoryFile>, ApiError> {
    super::super::validate_path(path)?;
    if !valid_secret(snapshot) {
        return Err(failure(StatusCode::BAD_REQUEST, "invalid_request"));
    }
    let files = files(db, path)?;
    if files.is_empty() {
        return Err(failure(StatusCode::NOT_FOUND, "directory_not_found"));
    }
    if files.len() > FILE_LIMIT {
        return Err(failure(
            StatusCode::PAYLOAD_TOO_LARGE,
            "directory_too_large",
        ));
    }
    if fingerprint(&files) != snapshot {
        return Err(failure(StatusCode::CONFLICT, "directory_changed"));
    }
    Ok(files)
}

fn tombstone(db: &Connection, path: &str, time: i64) -> Result<(), ApiError> {
    let revision = super::super::next_revision(db).map_err(ApiError::internal)?;
    db.execute("UPDATE entries SET revision=?2,blob=NULL,sha256=NULL,size=NULL,deleted=1,updated_at=?3 WHERE path=?1",
        params![path, revision, time]).map_err(ApiError::internal)?;
    Ok(())
}

async fn rename(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Json(input): Json<Rename>,
) -> Result<Json<Changed>, ApiError> {
    browser(&state, &headers, true)?;
    state.blocking(move |state| {
        let mut db = state.db.lock().unwrap();
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate).map_err(ApiError::internal)?;
        grant(&tx, &headers)?;
        let files = checked_files(&tx, &input.path, &input.snapshot)?;
        if !crate::model::valid_path(&input.name) || input.name.contains('/') || input.name.len() > 255 {
            return Err(failure(StatusCode::BAD_REQUEST, "invalid_name"));
        }
        let target = match input.path.rsplit_once('/') { Some((parent, _)) => format!("{parent}/{}", input.name), None => input.name };
        if target == input.path { return Err(failure(StatusCode::BAD_REQUEST, "invalid_name")); }
        super::super::check_path_namespace(&tx, &target).map_err(|_| failure(StatusCode::CONFLICT, "directory_exists"))?;
        if super::super::stored_entry(&tx, &target).map_err(ApiError::internal)?.is_some_and(|entry| !entry.public.deleted) {
            return Err(failure(StatusCode::CONFLICT, "directory_exists"));
        }
        let targets = files.iter().map(|file| format!("{target}{}", &file.path[input.path.len()..])).collect::<Vec<_>>();
        if targets.iter().any(|path| !crate::model::valid_path(path)) {
            return Err(failure(StatusCode::BAD_REQUEST, "invalid_name"));
        }
        let time = now();
        for (file, destination) in files.iter().zip(targets) {
            tombstone(&tx, &file.path, time)?;
            let revision = super::super::next_revision(&tx).map_err(ApiError::internal)?;
            tx.execute("INSERT INTO entries(path,revision,blob,sha256,size,deleted,updated_at) VALUES(?1,?2,?3,?4,?5,0,?6)
                ON CONFLICT(path) DO UPDATE SET revision=excluded.revision,blob=excluded.blob,sha256=excluded.sha256,size=excluded.size,deleted=0,updated_at=excluded.updated_at",
                params![destination, revision, file.blob, file.sha256, file.size, time]).map_err(ApiError::internal)?;
        }
        tx.commit().map_err(ApiError::internal)?;
        Ok(Json(Changed { path: target, file_count: files.len() }))
    }).await
}

async fn delete(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Json(input): Json<Mutation>,
) -> Result<Json<Changed>, ApiError> {
    browser(&state, &headers, true)?;
    state.blocking(move |state| {
        let mut db = state.db.lock().unwrap();
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate).map_err(ApiError::internal)?;
        grant(&tx, &headers)?;
        let files = checked_files(&tx, &input.path, &input.snapshot)?;
        let time = now();
        for file in &files {
            tx.execute("INSERT INTO trash(path,blob,sha256,size,deleted_at,expires_at) VALUES(?1,?2,?3,?4,?5,?6)",
                params![file.path, file.blob, file.sha256, file.size, time, time + super::super::RETENTION_SECONDS]).map_err(ApiError::internal)?;
            tombstone(&tx, &file.path, time)?;
        }
        tx.commit().map_err(ApiError::internal)?;
        Ok(Json(Changed { path: input.path, file_count: files.len() }))
    }).await
}

#[cfg(test)]
mod tests;
