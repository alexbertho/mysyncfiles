//! Bounded, explicitly authorized single-file editing and local execution.
use serde::{Deserialize, Serialize};

pub const CODE_BYTES: usize = 256 * 1024;
pub const JSON_BYTES: usize = CODE_BYTES * 6 + 16384;
pub const OUTPUT_BYTES: usize = 64 * 1024;
pub const AUTHORIZE_PATH: &str = "/v1/web/editor/authorize";

pub fn language(path: &str) -> Option<&'static str> {
    if !crate::model::valid_path(path) {
        return None;
    }
    match path.rsplit('.').next()?.to_ascii_lowercase().as_str() {
        "py" => Some("python"),
        "c" => Some("c"),
        _ => None,
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    Tools,
    Start {
        path: String,
        revision: i64,
        sha256: String,
        job_id: String,
    },
    Poll {
        job_id: String,
    },
    Stop {
        job_id: String,
    },
}

impl Operation {
    pub fn valid(&self) -> bool {
        match self {
            Self::Tools => true,
            Self::Start {
                path,
                revision,
                sha256,
                job_id,
            } => {
                language(path).is_some()
                    && *revision > 0
                    && crate::web_status_protocol::valid_secret(sha256)
                    && uuid::Uuid::parse_str(job_id).is_ok()
            }
            Self::Poll { job_id } | Self::Stop { job_id } => uuid::Uuid::parse_str(job_id).is_ok(),
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationRequest {
    pub ticket: String,
    pub instance_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Authorization {
    pub operation: Operation,
    pub owner: String,
    pub source: Option<String>,
    pub expires_at: i64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Tools {
    pub python: bool,
    pub compiler: Option<String>,
    pub isolation: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Phase {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
    pub duration_ms: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Run {
    pub job_id: String,
    pub sha256: String,
    pub state: String,
    pub compilation: Option<Phase>,
    pub execution: Option<Phase>,
}
