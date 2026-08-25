//! Delegate Permissions machine certificate lifecycle CLI.

mod commands;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use dp_rust_sdk::{DpClient, FileKeyStore, ResolvedConfig};

const PRODUCT_NAME: &str = match option_env!("DP_PRODUCT_NAME") {
    Some(name) => name,
    None => "dp",
};

#[derive(Parser, Debug)]
#[command(
    name = PRODUCT_NAME,
    version,
    about = "Delegate Permissions — machine certificate lifecycle. Product: auth, signup, register, csr.",
    arg_required_else_help = true
)]
struct Cli {
    /// Better Auth base URL (overrides the compiled default)
    #[arg(long, global = true, env = "DP_BACKEND_URL")]
    backend_url: Option<String>,

    /// Bearer token or session cookie (`better-auth.session_token=...`)
    #[arg(long, global = true, env = "DP_AUTH_TOKEN")]
    token: Option<String>,

    /// State directory (keys + state.json)
    #[arg(long, global = true, env = "DP_STATE_DIR")]
    state_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Kickstart an entity (SSO session required). Keys stay on this machine.
    Init {
        entity_id: String,
        /// Billing package
        #[arg(long, default_value = "enterprise")]
        package: String,
        /// Ask the server to generate Entity CA keys (test/dev only).
        #[arg(long)]
        server_keys: bool,
    },
    /// Generate a machine key + CSR, sign locally, enroll-instant (localhost).
    Gen {
        /// Entity id (e.g. smoke.test)
        #[arg(long)]
        org: String,
        /// Machine name (e.g. db1). Combined as name<sep>org
        #[arg(long)]
        name: String,
        /// Machine kind
        #[arg(long, value_enum, default_value_t = commands::machine::KindArg::Target)]
        kind: commands::machine::KindArg,
        /// Key algorithm
        #[arg(long, value_enum, default_value_t = commands::machine::KeyAlgoArg::Ed25519)]
        key_algo: commands::machine::KeyAlgoArg,
    },
    /// Human session (device-code or pasted cookie)
    Auth(commands::auth::AuthArgs),
    /// Create an org (kickstart-entity). Requires `auth login`.
    Signup(commands::signup::SignupArgs),
    /// Register this machine (CSR to admin inbox). Localhost: `--local`. Invite: `--invite`.
    Register(commands::machine::EnrollArgs),
    /// Pre-claim an org for a device CSR (session required). Device: `register --invite --name`.
    Invite(commands::invite::InviteArgs),
    /// Numbered CSR inbox (list / approve N)
    Csr(commands::csr::CsrArgs),
    /// Entity kickstart / status
    Org(commands::org::OrgArgs),
    /// Machine enrollment and local identity
    Machine(commands::machine::MachineArgs),
    /// Admin enrollment and credential operations
    Admin(commands::admin::AdminArgs),
    /// Platform CA helpers
    Platform(commands::platform::PlatformArgs),
    /// Print version and resolved backend URL
    Version,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = parse_cli();
    let cfg = ResolvedConfig::from_env();
    match run(cli, cfg).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{} {err}", console::style("error:").red().bold());
            ExitCode::FAILURE
        }
    }
}

fn parse_cli() -> Cli {
    let mut args: Vec<String> = std::env::args().collect();
    if let Some(first) = args.first_mut() {
        if let Some(stem) = std::path::Path::new(first).file_stem() {
            *first = stem.to_string_lossy().into_owned();
        }
    }
    Cli::parse_from(args)
}

async fn run(cli: Cli, mut cfg: ResolvedConfig) -> dp_rust_sdk::Result<()> {
    if let Some(url) = &cli.backend_url {
        cfg.backend_url = url.clone();
    }
    if let Some(token) = &cli.token {
        cfg.auth_token = Some(token.clone());
    }
    if let Some(dir) = &cli.state_dir {
        cfg.state_dir = dir.clone();
    }
    if cfg.auth_token.is_none() {
        cfg.apply_stored_session();
    }

    match cli.command {
        Command::Version => {
            commands::print_version(&cfg);
            Ok(())
        }
        Command::Init {
            entity_id,
            package,
            server_keys,
        } => commands::org::init_entity(&cfg, &entity_id, &package, server_keys).await,
        Command::Gen {
            org,
            name,
            kind,
            key_algo,
        } => commands::machine::gen(&cfg, org, name, kind, key_algo).await,
        Command::Auth(args) => commands::auth::run(args, &cfg).await,
        Command::Signup(args) => commands::signup::run(args, &cfg).await,
        Command::Register(args) => commands::machine::enroll_cmd(args, &cfg).await,
        Command::Invite(args) => commands::invite::run(args, &cfg).await,
        Command::Csr(args) => commands::csr::run(args, &cfg).await,
        Command::Org(args) => commands::org::run(args, &cfg).await,
        Command::Machine(args) => commands::machine::run(args, &cfg).await,
        Command::Admin(args) => commands::admin::run(args, &cfg).await,
        Command::Platform(args) => commands::platform::run(args, &cfg).await,
    }
}

pub(crate) fn client(cfg: &ResolvedConfig) -> DpClient {
    let mut client = DpClient::new(&cfg.backend_url).with_user_agent(format!(
        "{}/{}",
        cfg.product_name,
        env!("CARGO_PKG_VERSION")
    ));
    if let Some(token) = &cfg.auth_token {
        client = client.with_auth(token);
    }
    client
}

pub(crate) fn store(cfg: &ResolvedConfig) -> dp_rust_sdk::Result<FileKeyStore> {
    FileKeyStore::open(&cfg.state_dir)
}
