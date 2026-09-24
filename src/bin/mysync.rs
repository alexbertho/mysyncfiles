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
    /// Check TPM 2.0 access and an EK certificate without enrolling
    Doctor {
        /// Manufacturer EK leaf certificate in DER when absent from TPM NV
        #[arg(long)]
        ek_cert: Option<PathBuf>,
    },
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
        /// Manufacturer EK leaf certificate in DER when absent from TPM NV
        #[arg(long)]
        ek_cert: Option<PathBuf>,
    },
    /// Activate an approved enrollment
    EnrollActivate,
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

fn invitation_from_stdin() -> Result<String> {
    let mut value = String::new();
    std::io::stdin().read_line(&mut value)?;
    Ok(value.trim_end_matches(['\r', '\n']).to_owned())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let config_path = cli.config.unwrap_or(client::default_config_path()?);
    match cli.command {
        Command::Doctor { ek_cert } => {
            let certificate = ek_cert
                .as_deref()
                .map(mysyncfiles::tpm::read_ek_certificate)
                .transpose()?;
            let kind = mysyncfiles::tpm::doctor_with_certificate(
                &mysyncfiles::tpm::default_tcti(),
                certificate.as_deref(),
            )?;
            println!("TPM 2.0 is reachable and the {kind} EK matches its certificate.");
            println!("Manufacturer trust is checked during enrollment.");
        }
        Command::Enroll {
            server,
            dir,
            invitation_stdin,
            ek_chain,
            ek_cert,
        } => {
            let invitation = if invitation_stdin {
                invitation_from_stdin()?
            } else {
                rpassword::prompt_password("Enrollment invitation: ")?
            };
            let result =
                client::enroll(&config_path, server, dir, invitation, ek_cert, ek_chain).await?;
            println!(
                "enrollment={}\nfingerprint={}\nstatus={}\nCompare this fingerprint with the administrator, then run mysync enroll-activate.",
                result.id, result.fingerprint, result.status
            );
        }
        Command::EnrollActivate => print_report(client::activate_enrollment(&config_path).await?),
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
