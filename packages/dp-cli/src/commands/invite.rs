//! Org invite: admin authorizes a device to submit a CSR for this entity.
//! The device chooses its own name at `register --invite`.

use clap::{ArgGroup, Args};
use console::style;
use dp_rust_sdk::{EnrollInviteRequest, ResolvedConfig};

use crate::client;
use crate::commands::infer_entity_id;

#[derive(Args, Debug)]
#[command(group(ArgGroup::new("uses_mode").args(["uses", "unlimited"])))]
pub struct InviteArgs {
    /// Entity id. Inferred when this state dir has exactly one Entity CA.
    #[arg(long)]
    org: Option<String>,
    /// Seconds until expiry. Omit to use the plugin `inviteExpiresIn` (default 7d; capped by `inviteMaxExpiresIn`).
    #[arg(long)]
    expires_in: Option<u64>,
    /// How many machines may redeem (default 1). `0` is unlimited until expiry.
    #[arg(long)]
    uses: Option<u64>,
    /// Unlimited redeems until expiry (`maxUses = 0`)
    #[arg(long)]
    unlimited: bool,
}

pub async fn run(args: InviteArgs, cfg: &ResolvedConfig) -> dp_rust_sdk::Result<()> {
    let org = infer_entity_id(cfg, args.org.as_deref())?;
    let max_uses = if args.unlimited {
        Some(0)
    } else {
        args.uses
    };
    let res = client(cfg)
        .enroll_invite(&EnrollInviteRequest {
            entity_id: org.clone(),
            kind: None,
            expires_in: args.expires_in,
            max_uses,
        })
        .await?;
    let token = res.invite_token.ok_or_else(|| {
        dp_rust_sdk::Error::enrollment("enroll-invite response missing inviteToken")
    })?;
    let entity = res.entity_id.as_deref().unwrap_or(&org);
    println!("{} {}", style("invite").green().bold(), entity);
    if let Some(id) = &res.invite_id {
        println!("  id      {id}");
    }
    println!("  token   {token}");
    match res.max_uses {
        Some(0) => println!("  uses    unlimited (until expiry)"),
        Some(n) => println!("  uses    {n}"),
        None => {}
    }
    if let Some(exp) = &res.expires_at {
        println!("  expires {exp}");
    }
    println!(
        "  device  {bin} register --invite {token} --name <machine>",
        bin = cfg.product_name
    );
    println!(
        "  admin   {bin} csr list --org {entity}",
        bin = cfg.product_name
    );
    Ok(())
}
