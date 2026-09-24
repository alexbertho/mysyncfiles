use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use mysyncfiles::release;

#[derive(Parser)]
#[command(
    name = "mysync-release",
    version,
    about = "Sign and publish client releases"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new signing key; keep this file outside the served release directory
    Keygen {
        #[arg(long)]
        secret_key: PathBuf,
    },
    /// Publish a signed release to a static directory
    Publish {
        #[arg(long)]
        secret_key: PathBuf,
        #[arg(long)]
        binary: PathBuf,
        #[arg(long)]
        version: String,
        #[arg(long)]
        target: String,
        #[arg(long)]
        output_dir: PathBuf,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Keygen { secret_key } => {
            let public_key = release::generate_key(&secret_key)?;
            println!("public_key={public_key}");
        }
        Command::Publish {
            secret_key,
            binary,
            version,
            target,
            output_dir,
        } => {
            let manifest = release::publish(&secret_key, &binary, &version, &target, &output_dir)?;
            println!("published {} {}", manifest.version, manifest.target);
        }
    }
    Ok(())
}
