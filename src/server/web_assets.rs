//! Native web files are read from disk on every request, without a build step.
use super::{ApiError, ServerState};
use axum::{
    Router,
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use std::{io::Read, sync::Arc};

const MAX_ASSET_BYTES: u64 = 1024 * 1024;
const ASSETS: &[(&str, &str)] = &[
    ("status.css", "text/css; charset=utf-8"),
    ("status.js", "text/javascript; charset=utf-8"),
    ("atlas.js", "text/javascript; charset=utf-8"),
    ("editor.js", "text/javascript; charset=utf-8"),
    ("editor.css", "text/css; charset=utf-8"),
    ("atlas-icons.svg", "image/svg+xml"),
    ("atlas-icons.LICENSE", "text/plain; charset=utf-8"),
    ("atlas-brand.png", "image/png"),
    ("atlas-brand-dark.png", "image/png"),
];

pub(super) fn router() -> Router<Arc<ServerState>> {
    let mut router = Router::new();
    // Explicit public routes keep secrets or editor backups out of HTTP, even
    // if they are accidentally placed in the web directory.
    for &(name, content_type) in ASSETS {
        router = router.route(
            &format!("/{name}"),
            get(move |State(state): State<Arc<ServerState>>| async move {
                let bytes = read(&state, name).await?;
                Ok::<Response, ApiError>(
                    ([(header::CONTENT_TYPE, content_type)], bytes).into_response(),
                )
            }),
        );
    }
    router
}

pub(super) async fn read(
    state: &Arc<ServerState>,
    name: &'static str,
) -> Result<Vec<u8>, ApiError> {
    state
        .blocking(move |state| {
            let contents = (|| -> anyhow::Result<Vec<u8>> {
                let root = crate::local_fs::Mirror::open(&state.web_dir)?;
                let file = root
                    .read(name)?
                    .ok_or_else(|| anyhow::anyhow!("missing web asset"))?;
                anyhow::ensure!(
                    file.metadata()?.len() <= MAX_ASSET_BYTES,
                    "web asset too large"
                );
                let mut bytes = Vec::new();
                file.take(MAX_ASSET_BYTES + 1).read_to_end(&mut bytes)?;
                anyhow::ensure!(bytes.len() as u64 <= MAX_ASSET_BYTES, "web asset too large");
                if name == "index.html" {
                    let label = crate::device_auth::server_name(&state)?;
                    let label = label
                        .replace('&', "&amp;")
                        .replace('<', "&lt;")
                        .replace('>', "&gt;")
                        .replace('"', "&quot;")
                        .replace('\'', "&#39;");
                    let html = String::from_utf8(bytes)?
                        .replace("MySyncFiles</a>", &format!("{label}</a>"))
                        .replace(
                            "compact-brand-name\">MySyncFiles</span>",
                            &format!("compact-brand-name\">{label}</span>"),
                        )
                        .replace(
                            "Fichiers · MySyncFiles</title>",
                            &format!("Fichiers · {label}</title>"),
                        );
                    return Ok(html.into_bytes());
                }
                Ok(bytes)
            })();
            contents.map_err(|error| {
                eprintln!("cannot read web asset {name}: {error:#}");
                ApiError(StatusCode::SERVICE_UNAVAILABLE, "web_unavailable".into())
            })
        })
        .await
}
