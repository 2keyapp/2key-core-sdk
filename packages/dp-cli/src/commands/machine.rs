use std::time::Duration;

use clap::{Args, Subcommand, ValueEnum};
use console::style;
use dp_rust_sdk::{
    decommission_machine, enroll_machine, load_state, pull_enrollment, renew_machine,
    require_entity_ca, EnrollParams, EnrollmentStatus, KeyAlgo, KeyStore, MachineKind, ResolvedConfig, KEY_CHAIN, KEY_MACHINE_CRT, KEY_PLATFORM_ENDORSED,
};

use crate::{client, store};

#[derive(Args, Debug)]
pub struct MachineArgs {
    #[command(subcommand)]
    command: MachineCommand,
}

#[derive(Subcommand, Debug)]
enum MachineCommand {
    /// Generate a key + CSR, submit enrollment, optionally wait for approval
    Enroll(EnrollArgs),
    /// Show local machine identity and certificate status
    Status,
    /// Pull an approved certificate (when enroll was not --wait)
    Pull,
    /// Print the machine identity string
    Whoami,
    /// Show the local leaf certificate
    Certificate(CertificateArgs),
    /// Generate a new key and submit renewal
    Renew {
        /// Skip confirmation
        #[arg(long)]
        yes: bool,
    },
    /// Alias for renew
    RotateKey {
        /// Skip confirmation
        #[arg(long)]
        yes: bool,
    },
    /// Self-decommission this machine (deletes local keys)
    Decommission {
        /// Skip confirmation
        #[arg(long)]
        yes: bool,
        #[arg(long, default_value = "decommissioned")]
        reason: String,
    },
}

#[derive(Args, Debug)]
pub struct EnrollArgs {
    /// Entity id (e.g. acme.com)
    #[arg(long, required_unless_present = "invite")]
    org: Option<String>,
    /// Unique name within the org (laptop1). Wire form: name{sep}org
    #[arg(long, required_unless_present = "name_pos")]
    name: Option<String>,
    /// Positional name (`register --org acme.com laptop1`)
    #[arg(value_name = "NAME", required_unless_present = "name")]
    name_pos: Option<String>,
    /// Machine kind
    #[arg(long, value_enum, default_value_t = KindArg::Target)]
    kind: KindArg,
    /// Poll until approved or rejected
    #[arg(long)]
    wait: bool,
    /// Sign locally and POST enroll-instant (localhost / same host as Entity CA)
    #[arg(long, visible_alias = "local")]
    instant: bool,
    /// Key algorithm
    #[arg(long, value_enum, default_value_t = KeyAlgoArg::Ed25519)]
    key_algo: KeyAlgoArg,
    /// Redeem an org invite (entity from the token; still pass --name)
    #[arg(long)]
    invite: Option<String>,
}

impl EnrollArgs {
    fn machine_name(&self) -> dp_rust_sdk::Result<String> {
        self.name
            .clone()
            .or_else(|| self.name_pos.clone())
            .ok_or_else(|| {
                dp_rust_sdk::Error::enrollment("pass --name <machine> or a positional name")
            })
    }
}

/// Localhost `idr gen`: generate machine key + CSR, sign with Entity CA, enroll-instant.
pub async fn gen(
    cfg: &ResolvedConfig,
    org: String,
    name: String,
    kind: KindArg,
    key_algo: KeyAlgoArg,
) -> dp_rust_sdk::Result<()> {
    enroll_cmd(
        EnrollArgs {
            org: Some(org),
            name: Some(name),
            name_pos: None,
            kind,
            wait: false,
            instant: true,
            key_algo,
            invite: None,
        },
        cfg,
    )
    .await
}

#[derive(Args, Debug)]
struct CertificateArgs {
    #[arg(long, value_enum, default_value_t = CertFormat::Text)]
    format: CertFormat,
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum KindArg {
    Target,
    Source,
}

impl From<KindArg> for MachineKind {
    fn from(value: KindArg) -> Self {
        match value {
            KindArg::Target => MachineKind::Target,
            KindArg::Source => MachineKind::Source,
        }
    }
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum KeyAlgoArg {
    Ed25519,
    P256,
}

impl From<KeyAlgoArg> for KeyAlgo {
    fn from(value: KeyAlgoArg) -> Self {
        match value {
            KeyAlgoArg::Ed25519 => KeyAlgo::Ed25519,
            KeyAlgoArg::P256 => KeyAlgo::P256,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CertFormat {
    Pem,
    Text,
    Json,
}

pub async fn run(args: MachineArgs, cfg: &ResolvedConfig) -> dp_rust_sdk::Result<()> {
    match args.command {
        MachineCommand::Enroll(enroll) => enroll_cmd(enroll, cfg).await,
        MachineCommand::Status => status_cmd(cfg).await,
        MachineCommand::Pull => pull_cmd(cfg).await,
        MachineCommand::Whoami => whoami_cmd(cfg),
        MachineCommand::Certificate(opts) => certificate_cmd(opts, cfg),
        MachineCommand::Renew { yes } | MachineCommand::RotateKey { yes } => {
            renew_cmd(cfg, yes).await
        }
        MachineCommand::Decommission { yes, reason } => decommission_cmd(cfg, yes, &reason).await,
    }
}

pub(crate) async fn enroll_cmd(args: EnrollArgs, cfg: &ResolvedConfig) -> dp_rust_sdk::Result<()> {
    let client = client(cfg);
    let store = store(cfg)?;
    let (entity_id, machine_name, kind, invite_token) = if let Some(token) = args.invite.clone() {
        if args.instant {
            return Err(dp_rust_sdk::Error::enrollment(
                "invite enroll cannot use --local / --instant",
            ));
        }
        let preview = client.get_enroll_invite(&token).await?;
        let invited_org = preview
            .entity_id
            .filter(|id| !id.is_empty())
            .ok_or_else(|| {
                dp_rust_sdk::Error::enrollment("enroll-invite lookup missing entityId")
            })?;
        if let Some(org) = args.org.as_deref() {
            if org.to_ascii_lowercase() != invited_org {
                return Err(dp_rust_sdk::Error::enrollment(format!(
                    "--org {org} does not match invite org {invited_org}"
                )));
            }
        }
        (
            invited_org,
            args.machine_name()?,
            args.kind.into(),
            Some(token),
        )
    } else {
        let org = args.org.clone().ok_or_else(|| {
            dp_rust_sdk::Error::enrollment("pass --org <entity> or --invite <token>")
        })?;
        (org, args.machine_name()?, args.kind.into(), None)
    };
    let state = enroll_machine(
        &client,
        &store,
        EnrollParams {
            entity_id,
            machine_name,
            kind,
            key_algo: args.key_algo.into(),
            wait: args.wait,
            wait_interval: Duration::from_secs(5),
            separator: cfg.separator.clone(),
            instant: args.instant,
            invite_token,
        },
    )
    .await?;

    match state.status {
        EnrollmentStatus::Active => {
            println!(
                "{} {}",
                style("enrolled").green().bold(),
                state.machine_identity
            );
            if let Some(ski) = &state.ski {
                println!("  ski     {ski}");
            }
        }
        EnrollmentStatus::PendingAdmin => {
            println!(
                "{} {} — waiting for admin approval",
                style("submitted").yellow().bold(),
                state.machine_identity
            );
            if let Some(id) = &state.enrollment_id {
                println!("  enroll  {id}");
            }
            println!("  pull    {bin} machine pull", bin = cfg.product_name);
            println!(
                "  admin   {bin} csr list --org {org}",
                bin = cfg.product_name,
                org = state.entity_id
            );
            println!("  or re-run with --wait");
        }
        other => {
            println!("{} {other}", state.machine_identity);
        }
    }
    Ok(())
}

async fn status_cmd(cfg: &ResolvedConfig) -> dp_rust_sdk::Result<()> {
    let store = store(cfg)?;
    let Some(state) = load_state(&store)? else {
        println!(
            "uninitialized (no state.json in {})",
            cfg.state_dir.display()
        );
        return Ok(());
    };
    println!("identity {}", state.machine_identity);
    println!("status   {}", state.status);
    if let Some(ski) = &state.ski {
        println!("ski      {ski}");
    }
    if let Some(exp) = &state.cert_expires_at {
        println!("expires  {exp}");
    }
    if let Some(id) = &state.enrollment_id {
        println!("enroll   {id}");
    }
    println!("state    {}", cfg.state_dir.display());

    if let Some(ski) = &state.ski {
        match client(cfg).credential_status(ski).await {
            Ok(remote) => {
                if let Some(status) = remote.status {
                    println!("remote   {status}");
                }
            }
            Err(err) => {
                eprintln!(
                    "{} could not fetch remote status: {err}",
                    style("warn:").yellow()
                );
            }
        }
    }
    Ok(())
}

async fn pull_cmd(cfg: &ResolvedConfig) -> dp_rust_sdk::Result<()> {
    let client = client(cfg);
    let store = store(cfg)?;
    let state = pull_enrollment(&client, &store).await?;
    match state.status {
        EnrollmentStatus::Active => {
            println!(
                "{} {}",
                style("active").green().bold(),
                state.machine_identity
            );
        }
        EnrollmentStatus::PendingAdmin => {
            println!(
                "{} still pending admin approval",
                style("pending").yellow().bold()
            );
        }
        EnrollmentStatus::Rejected => {
            return Err(dp_rust_sdk::Error::enrollment("enrollment was rejected"));
        }
        other => println!("{other}"),
    }
    Ok(())
}

fn whoami_cmd(cfg: &ResolvedConfig) -> dp_rust_sdk::Result<()> {
    let store = store(cfg)?;
    let state = load_state(&store)?
        .ok_or_else(|| dp_rust_sdk::Error::enrollment("no local machine identity"))?;
    println!("{}", state.machine_identity);
    Ok(())
}

fn certificate_cmd(args: CertificateArgs, cfg: &ResolvedConfig) -> dp_rust_sdk::Result<()> {
    let store = store(cfg)?;
    let pem = store.load_string(KEY_MACHINE_CRT)?.ok_or_else(|| {
        dp_rust_sdk::Error::enrollment("no local certificate — enroll or pull first")
    })?;
    let state = load_state(&store)?;
    match args.format {
        CertFormat::Pem => print!("{pem}"),
        CertFormat::Text => {
            if let Some(state) = &state {
                println!("identity {}", state.machine_identity);
                println!("status   {}", state.status);
                if let Some(ski) = &state.ski {
                    println!("ski      {ski}");
                }
                if let Some(exp) = &state.cert_expires_at {
                    println!("expires  {exp}");
                }
            }
            println!("---");
            print!("{pem}");
        }
        CertFormat::Json => {
            let chain = store.load_string(KEY_CHAIN)?;
            let endorsed = store.load_string(KEY_PLATFORM_ENDORSED)?;
            let mut obj = serde_json::json!({
                "certPem": pem,
            });
            if let Some(state) = state {
                obj["machineIdentity"] = serde_json::json!(state.machine_identity);
                obj["status"] = serde_json::json!(state.status.as_str());
                obj["ski"] = serde_json::json!(state.ski);
                obj["expiresAt"] = serde_json::json!(state.cert_expires_at);
            }
            if let Some(chain) = chain {
                obj["chainPem"] = serde_json::json!(chain);
            }
            if let Some(endorsed) = endorsed {
                obj["platformCertPem"] = serde_json::json!(endorsed);
            }
            println!("{}", serde_json::to_string_pretty(&obj)?);
        }
    }
    Ok(())
}

async fn renew_cmd(cfg: &ResolvedConfig, yes: bool) -> dp_rust_sdk::Result<()> {
    let store = store(cfg)?;
    let state = load_state(&store)?
        .ok_or_else(|| dp_rust_sdk::Error::lifecycle("no local machine identity"))?;
    let pending = matches!(
        state.status,
        EnrollmentStatus::Renewing | EnrollmentStatus::Rotating
    );
    let prompt = if pending {
        format!("Complete pending renewal for {}?", state.machine_identity)
    } else {
        format!("Renew key and certificate for {}?", state.machine_identity)
    };
    if !crate::commands::confirm(&prompt, true, yes)? {
        println!("cancelled");
        return Ok(());
    }
    let ca = require_entity_ca(&store, &state.entity_id)?;
    let client = client(cfg).with_stored_mtls(&store)?;
    let updated = renew_machine(&client, &store, &ca, &cfg.separator, 365).await?;
    println!(
        "{} {}",
        style("renewed").green().bold(),
        updated.machine_identity
    );
    if let Some(old) = &updated.renewed_from_ski {
        println!("  from ski {old}");
    }
    if let Some(ski) = &updated.ski {
        println!("  ski      {ski}");
    }
    Ok(())
}

async fn decommission_cmd(
    cfg: &ResolvedConfig,
    yes: bool,
    reason: &str,
) -> dp_rust_sdk::Result<()> {
    let store = store(cfg)?;
    let state = load_state(&store)?
        .ok_or_else(|| dp_rust_sdk::Error::lifecycle("no local machine identity"))?;
    if !crate::commands::confirm(
        &format!(
            "Decommission {}? This deletes local keys.",
            state.machine_identity
        ),
        false,
        yes,
    )? {
        println!("cancelled");
        return Ok(());
    }
    let client = client(cfg).with_stored_mtls(&store)?;
    let updated = decommission_machine(&client, &store, reason).await?;
    println!(
        "{} {}",
        style("decommissioned").red().bold(),
        updated.machine_identity
    );
    println!("  state kept at {} (no secrets)", cfg.state_dir.display());
    Ok(())
}
