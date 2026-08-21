use std::path::PathBuf;

use clap::{Args, Subcommand};
use dp_rust_sdk::{normalize_ca_file_pem, ResolvedConfig};

use crate::client;

#[derive(Args, Debug)]
pub struct PlatformArgs {
    #[command(subcommand)]
    command: PlatformCommand,
}

#[derive(Subcommand, Debug)]
enum PlatformCommand {
    /// Fetch the Platform Root PEM (for HAProxy ca-file)
    Root {
        /// Write PEM to this file instead of stdout
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

pub async fn run(args: PlatformArgs, cfg: &ResolvedConfig) -> dp_rust_sdk::Result<()> {
    match args.command {
        PlatformCommand::Root { output } => {
            let res = client(cfg).platform_root().await?;
            let pem = res.pem().and_then(normalize_ca_file_pem).ok_or_else(|| {
                dp_rust_sdk::Error::Message("server did not return a platform root PEM".into())
            })?;
            if let Some(path) = output {
                std::fs::write(&path, pem)?;
                println!("wrote {}", path.display());
            } else {
                print!("{pem}");
            }
            if let Some(ski) = res.ski {
                eprintln!("ski {ski}");
            }
            Ok(())
        }
    }
}
