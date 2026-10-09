//! Test-only facade joining the independently built client and server.
pub use mysyncfiles_client::{client, release, tpm, update};
pub use mysyncfiles_server::*;
pub mod server {
    pub use mysyncfiles_server::server::*;
    pub fn open(data: impl AsRef<std::path::Path>) -> anyhow::Result<std::sync::Arc<ServerState>> {
        open_with_web_dir(data, std::path::PathBuf::from("../web"))
    }
}
