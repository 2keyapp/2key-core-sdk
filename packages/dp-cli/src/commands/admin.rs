use clap::{Args, Subcommand};
use console::style;
use dp_rust_sdk::{
    admin_ca_cert, approve_enrollment, csr_fingerprint, enrollment_id, fetch_enrollment,
    load_state, reject_enrollment, requester_label, require_entity_ca, save_state, EnrollListItem,
    EnrollmentStatus, ResolvedConfig,
};

use crate::client;
use crate::store;

#[derive(Args, Debug)]
pub struct AdminArgs {
    #[command(subcommand)]
    command: AdminCommand,
}

#[derive(Subcommand, Debug)]
enum AdminCommand {
    /// Enrollment and credential administration
    Machine(AdminMachineArgs),
}

#[derive(Args, Debug)]
struct AdminMachineArgs {
    #[command(subcommand)]
    command: AdminMachineCommand,
}

#[derive(Subcommand, Debug)]
enum AdminMachineCommand {
    /// List enrollment requests
    List {
        entity_id: String,
        #[arg(long, default_value = "pending")]
        status: String,
    },
    /// Show one enrollment request
    Show {
        request_id: String,
        /// Entity id, used if enroll-get is unavailable
        #[arg(long)]
        org: Option<String>,
    },
    /// Sign CSR with Entity CA and approve
    Approve {
        request_id: String,
        /// Skip confirmation
        #[arg(long)]
        yes: bool,
        /// Entity id, used if enroll-get is unavailable
        #[arg(long)]
        org: Option<String>,
    },
    /// Reject an enrollment
    Reject {
        request_id: String,
        /// Skip confirmation
        #[arg(long)]
        yes: bool,
    },
    /// Revoke a credential by SKI
    Revoke {
        ski: String,
        /// Skip confirmation
        #[arg(long)]
        yes: bool,
        /// key_compromise | decommissioned | machine_lost | replaced | organization_policy | renewed | other
        #[arg(long, default_value = "other")]
        reason: String,
    },
    /// Decommission a machine remotely
    Decommission {
        ski: String,
        /// Skip confirmation
        #[arg(long)]
        yes: bool,
        #[arg(long, default_value = "decommissioned")]
        reason: String,
    },
    /// List credentials for an entity
    Credentials {
        entity_id: String,
        #[arg(long, default_value = "active")]
        status: String,
    },
}

pub async fn run(args: AdminArgs, cfg: &ResolvedConfig) -> dp_rust_sdk::Result<()> {
    match args.command {
        AdminCommand::Machine(m) => match m.command {
            AdminMachineCommand::List { entity_id, status } => {
                list_cmd(cfg, &entity_id, &status).await
            }
            AdminMachineCommand::Show { request_id, org } => {
                show_cmd(cfg, &request_id, org.as_deref()).await
            }
            AdminMachineCommand::Approve {
                request_id,
                yes,
                org,
            } => approve_cmd(cfg, &request_id, org.as_deref(), yes).await,
            AdminMachineCommand::Reject { request_id, yes } => {
                reject_cmd(cfg, &request_id, yes).await
            }
            AdminMachineCommand::Revoke { ski, yes, reason } => {
                revoke_cmd(cfg, &ski, &reason, yes).await
            }
            AdminMachineCommand::Credentials { entity_id, status } => {
                credentials_cmd(cfg, &entity_id, &status).await
            }
            AdminMachineCommand::Decommission { ski, yes, reason } => {
                admin_decommission_cmd(cfg, &ski, &reason, yes).await
            }
        },
    }
}

pub(crate) async fn list_cmd(
    cfg: &ResolvedConfig,
    entity_id: &str,
    status: &str,
) -> dp_rust_sdk::Result<()> {
    let status_filter = if status.eq_ignore_ascii_case("all") {
        None
    } else {
        Some(status)
    };
    let list = client(cfg).enroll_list(entity_id, status_filter).await?;
    if list.is_empty() {
        println!("no enrollments for {entity_id} ({status})");
        return Ok(());
    }
    println!("{:<22} {:<28} {:<12} {}", "ENROLL", "HOST", "STATUS", "SKI");
    for item in &list {
        let id = enrollment_id(item).unwrap_or("—");
        let host = item.host.as_deref().unwrap_or("—");
        let st = item.status.as_deref().unwrap_or("—");
        let ski = item.ski.as_deref().unwrap_or("—");
        println!("{id:<22} {host:<28} {st:<12} {ski}");
    }
    Ok(())
}

pub(crate) async fn show_cmd(
    cfg: &ResolvedConfig,
    request_id: &str,
    org: Option<&str>,
) -> dp_rust_sdk::Result<()> {
    let item = fetch_enrollment(&client(cfg), request_id, org).await?;
    print_enrollment(&item);
    Ok(())
}

pub(crate) async fn approve_cmd(
    cfg: &ResolvedConfig,
    request_id: &str,
    org: Option<&str>,
    yes: bool,
) -> dp_rust_sdk::Result<()> {
    let client = client(cfg);
    let store = store(cfg)?;
    let item = fetch_enrollment(&client, request_id, org).await?;
    print_enrollment(&item);

    let entity_id = item
        .entity_id
        .clone()
        .or_else(|| org.map(str::to_string))
        .ok_or_else(|| {
            dp_rust_sdk::Error::admin("enrollment has no entityId — pass --org <entity-id>")
        })?;
    let ca = require_entity_ca(&store, &entity_id)?;
    println!("entity CA {}", ca.ski);
    println!(
        "ca cert   {}",
        cfg.state_dir.join(admin_ca_cert(&entity_id)?).display()
    );

    if !crate::commands::confirm("Approve?", true, yes)? {
        println!("cancelled");
        return Ok(());
    }

    let res = approve_enrollment(&client, &ca, &item, &cfg.separator, None, 365).await?;
    println!(
        "{} {}",
        style("approved").green().bold(),
        enrollment_id(&item).unwrap_or(request_id)
    );
    if let Some(cred) = &res.issued.credential {
        println!("  ski {}", cred.ski);
    } else if let Some(ski) = &item.ski {
        println!("  ski {ski}");
    }
    if res.issued.platform_cert_pem.is_some() {
        println!("  platform cosign received");
    }
    Ok(())
}

pub(crate) async fn reject_cmd(
    cfg: &ResolvedConfig,
    request_id: &str,
    yes: bool,
) -> dp_rust_sdk::Result<()> {
    if !crate::commands::confirm(&format!("Reject enrollment {request_id}?"), false, yes)? {
        println!("cancelled");
        return Ok(());
    }
    reject_enrollment(&client(cfg), request_id).await?;
    println!("{} {request_id}", style("rejected").red().bold());
    Ok(())
}

fn print_enrollment(item: &EnrollListItem) {
    let id = enrollment_id(item).unwrap_or("—");
    println!("enroll   {id}");
    if let Some(entity) = &item.entity_id {
        println!("org      {entity}");
    }
    if let Some(host) = &item.host {
        println!("identity {host}");
    }
    if let Some(status) = &item.status {
        println!("status   {status}");
    }
    if let Some(kind) = &item.kind {
        println!("kind     {kind}");
    }
    if let Some(ski) = &item.ski {
        println!("ski      {ski}");
    }
    if let Some(who) = requester_label(item) {
        println!("requester {who}");
    }
    if let Some(csr) = &item.csr_pem {
        println!("csr      sha256:{}", csr_fingerprint(csr));
    }
}

async fn admin_decommission_cmd(
    cfg: &ResolvedConfig,
    ski: &str,
    reason: &str,
    yes: bool,
) -> dp_rust_sdk::Result<()> {
    if !crate::commands::confirm(&format!("Decommission machine {ski} remotely?"), false, yes)? {
        println!("cancelled");
        return Ok(());
    }
    let res = client(cfg).machine_decommission(ski, reason).await?;
    println!("{} {ski}", style("decommissioned").red().bold());
    if let Some(status) = res.status {
        println!("  status {status}");
    }
    Ok(())
}

async fn revoke_cmd(
    cfg: &ResolvedConfig,
    ski: &str,
    reason: &str,
    yes: bool,
) -> dp_rust_sdk::Result<()> {
    if !crate::commands::confirm(&format!("Revoke credential {ski} ({reason})?"), false, yes)? {
        println!("cancelled");
        return Ok(());
    }
    let res = client(cfg).credential_revoke(ski, reason).await?;
    println!("{} {ski}", style("revoked").red().bold());
    if let Some(status) = res.status {
        println!("  status {status}");
    }
    println!("  reason {reason}");

    let store = store(cfg)?;
    if let Some(mut state) = load_state(&store)? {
        if state.ski.as_deref() == Some(ski)
            && state.status.can_transition_to(EnrollmentStatus::Revoked)
        {
            state.transition(EnrollmentStatus::Revoked)?;
            save_state(&store, &state)?;
            println!("  local state marked revoked");
        }
    }
    Ok(())
}

async fn credentials_cmd(
    cfg: &ResolvedConfig,
    entity_id: &str,
    status: &str,
) -> dp_rust_sdk::Result<()> {
    let status_filter = if status.eq_ignore_ascii_case("all") {
        None
    } else {
        Some(status)
    };
    let list = client(cfg)
        .credential_list(entity_id, status_filter)
        .await?;
    if list.is_empty() {
        println!("no credentials for {entity_id} ({status})");
        return Ok(());
    }
    println!("{:<44} {:<28} {:<16} {}", "SKI", "HOST", "STATUS", "KIND");
    for item in &list {
        let ski = item.ski.as_deref().unwrap_or("—");
        let host = item.host.as_deref().unwrap_or("—");
        let st = item.status.as_deref().unwrap_or("—");
        let kind = item.kind.as_deref().unwrap_or("—");
        println!("{ski:<44} {host:<28} {st:<16} {kind}");
    }
    Ok(())
}
