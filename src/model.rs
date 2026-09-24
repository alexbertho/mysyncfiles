use serde::{Deserialize, Serialize};

pub const UPLOAD_CHUNK_BYTES: i64 = 8 * 1024 * 1024;

#[derive(Debug, Deserialize, Serialize)]
pub struct BeginUpload {
    pub path: String,
    pub base_revision: i64,
    pub size: i64,
    pub sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct UploadProgress {
    pub id: String,
    pub offset: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Entry {
    pub path: String,
    pub revision: i64,
    pub sha256: Option<String>,
    pub size: Option<i64>,
    pub deleted: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Manifest {
    pub generation: i64,
    pub entries: Vec<Entry>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TrashItem {
    pub id: i64,
    pub path: String,
    pub size: i64,
    pub deleted_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RestoreRequest {
    pub id: i64,
}

/// Reject paths that could escape a synchronization root or collide with client-owned data.
pub fn valid_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 4096
        && !path.starts_with('/')
        && !path.contains('\\')
        && !path.contains('\0')
        && path.split('/').all(|part| {
            !part.is_empty()
                && part.len() <= 255
                && part != "."
                && part != ".."
                && part != ".mysync-conflicts"
                && part != ".mysync-staging"
        })
}
