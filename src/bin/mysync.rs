use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use mysyncfiles::client::{self, Api, SyncReport};

#[derive(Parser)]
#[command(
    name = "mysync",
    version,
    about = "Synchronize a local folder with a personal server"
)]
struct Cli {
    /// Configuration file (default: XDG_CONFIG_HOME/mysync/config.json)
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Enroll a TPM identity; administrator approval is required before activation
    Enroll {
        #[arg(long)]
        server: String,
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        invitation_stdin: bool,
        /// PEM intermediate EK certificates, obtained from the TPM manufacturer
        #[arg(long)]
        ek_chain: Option<PathBuf>,
    },
    /// Activate an approved enrollment and retire the local legacy credential
    EnrollActivate,
    /// Connect the first device and upload its existing files
    Init {
        #[arg(long)]
        server: String,
        #[arg(long)]
        token: Option<String>,
        /// Read the device key from standard input
        #[arg(long, conflicts_with = "token")]
        token_stdin: bool,
        #[arg(long)]
        dir: PathBuf,
    },
    /// Connect another device to an existing server
    Connect {
        #[arg(long)]
        server: String,
        #[arg(long)]
        token: Option<String>,
        /// Read the device key from standard input
        #[arg(long, conflicts_with = "token")]
        token_stdin: bool,
        #[arg(long)]
        dir: PathBuf,
    },
    /// Run one synchronization pass
    Sync,
    /// Watch local changes and poll the server continuously
    Daemon,
    /// Show local and server file counts
    Status,
    /// List recoverable server-side deletions
    Trash,
    /// Check for a signed client release and install it if newer
    Update,
    /// Restore an item from the server trash
    Restore { id: i64 },
}

fn print_report(report: SyncReport) {
    println!(
        "uploaded={} downloaded={} deleted_local={} deleted_remote={} conflicts={}",
        report.uploaded,
        report.downloaded,
        report.deleted_local,
        report.deleted_remote,
        report.conflicts
    );
}

fn device_key(value: Option<String>, from_stdin: bool) -> Result<String> {
    if from_stdin {
        let mut value = String::new();
        std::io::stdin().read_line(&mut value)?;
        return Ok(value.trim_end_matches(['\r', '\n']).to_owned());
    }
    Ok(match value {
        Some(value) => value,
        None => rpassword::prompt_password("Device key: ")?,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let config_path = cli.config.unwrap_or(client::default_config_path()?);
    match cli.command {
        Command::Enroll {
            server,
            dir,
            invitation_stdin,
            ek_chain,
        } => {
            let invitation = if invitation_stdin {
                device_key(None, true)?
            } else {
                rpassword::prompt_password("Enrollment invitation: ")?
            };
            let result = client::enroll(&config_path, server, dir, invitation, ek_chain).await?;
            println!(
                "enrollment={}\nfingerprint={}\nstatus={}\nCompare this fingerprint with the administrator, then run mysync enroll-activate.",
                result.id, result.fingerprint, result.status
            );
        }
        Command::EnrollActivate => print_report(client::activate_enrollment(&config_path).await?),
        Command::Init {
            server,
            token,
            token_stdin,
            dir,
        } => {
            print_report(
                client::configure(
                    &config_path,
                    server,
                    device_key(token, token_stdin)?,
                    dir,
                    true,
                )
                .await?,
            );
        }
        Command::Connect {
            server,
            token,
            token_stdin,
            dir,
        } => {
            print_report(
                client::configure(
                    &config_path,
                    server,
                    device_key(token, token_stdin)?,
                    dir,
                    false,
                )
                .await?,
            );
        }
        Command::Sync => print_report(client::sync(&config_path).await?),
        Command::Daemon => client::daemon(&config_path).await?,
        Command::Status => {
            let status = client::status(&config_path).await?;
            println!(
                "local_files={} remote_files={} pending_local={} conflicts={} server_generation={}",
                status.local_files,
                status.remote_files,
                status.pending_local,
                status.conflicts,
                status.generation
            );
        }
        Command::Trash => {
            let api = Api::new(&client::load_config(&config_path)?)?;
            for item in api.trash().await? {
                println!(
                    "id={} path={} bytes={} deleted_at={} expires_at={}",
                    item.id, item.path, item.size, item.deleted_at, item.expires_at
                );
            }
        }
        Command::Update => {
            let config = client::load_config(&config_path)?;
            match mysyncfiles::update::check_and_install(&config).await? {
                mysyncfiles::update::UpdateOutcome::Current => println!("client is up to date"),
                mysyncfiles::update::UpdateOutcome::Installed(version) => {
                    println!("installed {version}; restart mysync.service if it is running")
                }
            }
        }
        Command::Restore { id } => {
            let api = Api::new(&client::load_config(&config_path)?)?;
            let entry = api.restore(id).await?;
            println!("restored {} at revision {}", entry.path, entry.revision);
            print_report(client::sync(&config_path).await?);
        }
    }
    Ok(())
}
