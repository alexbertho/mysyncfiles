use std::{
    io::{self, IsTerminal, Write},
    net::SocketAddr,
    path::PathBuf,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use mysyncfiles::server;

#[derive(Parser)]
#[command(
    name = "mysync-server",
    version,
    about = "Personal file synchronization server"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create the server data directory and database
    Init {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Start the HTTP API on a loopback address behind an HTTPS reverse proxy
    Serve {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long, default_value = "127.0.0.1:8484")]
        listen: SocketAddr,
        #[arg(long)]
        releases_dir: Option<PathBuf>,
    },
    /// Manage TPM-enrolled devices
    Device {
        #[command(subcommand)]
        command: DeviceCommand,
    },
    /// Manage deleted server files
    Trash {
        #[command(subcommand)]
        command: TrashCommand,
    },
}

#[derive(Subcommand)]
enum TrashCommand {
    /// Permanently remove one item from the server trash
    Purge {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        id: i64,
    },
}

#[derive(Subcommand)]
enum DeviceCommand {
    /// Pair a client by its temporary code and confirm its TPM fingerprint
    Pair {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Configure TPM manufacturer trust and the externally visible server origin
    AuthConfigure {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        public_url: String,
        #[arg(long)]
        ek_roots: PathBuf,
    },
    /// Create a single-use, 15-minute TPM enrollment invitation
    Invite {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        name: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// List enrollment IDs, fingerprints and approval status
    Pending {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Cancel an unapproved invitation
    Cancel {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        id: String,
    },
    /// Approve a verified TPM after comparing its fingerprint with the client
    Approve {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        id: String,
        #[arg(long)]
        fingerprint: String,
    },
    /// List device names and revocation status
    List {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Revoke one device
    Revoke {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        name: String,
    },
}

fn prompt_line(prompt: &str) -> Result<String> {
    print!("{prompt}");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_owned())
}

async fn pair(data_dir: PathBuf) -> Result<()> {
    if !io::stdin().is_terminal() {
        bail!("device pair requires an interactive terminal");
    }
    let name = prompt_line("Device name: ")?;
    let code = rpassword::prompt_password("Code shown by the client: ")?;
    let state = server::open(data_dir)?;
    let id = mysyncfiles::device_auth::register_pair(&state, &name, &code)?;
    println!("Waiting for the client's TPM proof (up to 15 minutes)...");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(900);
    let fingerprint = loop {
        let entry = mysyncfiles::device_auth::enrollment_by_id(&state, &id)?;
        match entry.status.as_str() {
            "pending-approval" => {
                break entry
                    .fingerprint
                    .context("verified enrollment has no fingerprint")?;
            }
            "expired" | "revoked" => bail!("pairing request expired or was cancelled"),
            "approved" => bail!("device is already approved"),
            _ => {}
        }
        if tokio::time::Instant::now() >= deadline {
            bail!(
                "timed out waiting for TPM proof; rerun this command with the same code to resume"
            );
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    };
    println!("TPM fingerprint: {fingerprint}");
    println!("Compare the full fingerprint directly with the client.");
    let answer = prompt_line("Approve this device? [y/N] ")?;
    if !matches!(answer.as_str(), "y" | "Y" | "yes" | "YES") {
        mysyncfiles::device_auth::cancel(&state, &id)?;
        bail!("pairing cancelled; the client was not approved");
    }
    mysyncfiles::device_auth::approve(&state, &id, &fingerprint)?;
    println!("Device approved. The client will finish its first synchronization.");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Init { data_dir } => {
            server::open(&data_dir)?;
            println!("server initialized at {}", data_dir.display());
        }
        Command::Serve {
            data_dir,
            listen,
            releases_dir,
        } => server::serve(data_dir, listen, releases_dir).await?,
        Command::Device { command } => match command {
            DeviceCommand::Pair { data_dir } => pair(data_dir).await?,
            DeviceCommand::AuthConfigure {
                data_dir,
                public_url,
                ek_roots,
            } => {
                mysyncfiles::device_auth::configure(
                    server::open(data_dir)?.as_ref(),
                    &public_url,
                    &ek_roots,
                )?;
                println!("TPM trust configured");
            }
            DeviceCommand::Invite {
                data_dir,
                name,
                output,
            } => {
                mysyncfiles::device_auth::invite_to_file(
                    server::open(data_dir)?.as_ref(),
                    &name,
                    &output,
                )?;
                println!("invitation created; valid for 15 minutes");
            }
            DeviceCommand::Pending { data_dir } => {
                for entry in mysyncfiles::device_auth::list(server::open(data_dir)?.as_ref())? {
                    println!(
                        "id={} name={} status={} fingerprint={}",
                        entry.id,
                        entry.name,
                        entry.status,
                        entry.fingerprint.as_deref().unwrap_or("-")
                    );
                }
            }
            DeviceCommand::Cancel { data_dir, id } => {
                mysyncfiles::device_auth::cancel(server::open(data_dir)?.as_ref(), &id)?;
                println!("invitation cancelled; approved devices are unchanged");
            }
            DeviceCommand::Approve {
                data_dir,
                id,
                fingerprint,
            } => {
                mysyncfiles::device_auth::approve(
                    server::open(data_dir)?.as_ref(),
                    &id,
                    &fingerprint,
                )?;
                println!("device approved");
            }
            DeviceCommand::List { data_dir } => {
                let state = server::open(data_dir)?;
                for (id, name, revoked) in server::list_devices(&state)? {
                    println!("id={id} name={name} revoked={revoked}");
                }
            }
            DeviceCommand::Revoke { data_dir, name } => {
                let state = server::open(data_dir)?;
                if !server::revoke_device(&state, &name)? {
                    bail!("active device not found: {name}");
                }
                println!("revoked {name}");
            }
        },
        Command::Trash { command } => match command {
            TrashCommand::Purge { data_dir, id } => {
                let state = server::open(data_dir)?;
                if !server::purge_trash_item(&state, id)? {
                    bail!("trash item not found: {id}");
                }
                println!("purged trash item {id}");
            }
        },
    }
    Ok(())
}
