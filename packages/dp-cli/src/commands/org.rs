use clap::{Args, Subcommand};
use dp_rust_sdk::{
    admin_ca_cert, load_entity_ca, persist_kickstart_response, prepare_client_keyed_kickstart,
    save_entity_ca, KeyStore, KickstartRequest, ResolvedConfig, KEY_PLATFORM_CA,
};

use crate::client;
use crate::store;

#[derive(Args, Debug)]
pub struct OrgArgs {
    #[command(subcommand)]
    command: OrgCommand,
}

#[derive(Subcommand, Debug)]
enum OrgCommand {
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
    /// Show entity info from the server
    Status { entity_id: String },
}

pub async fn run(args: OrgArgs, cfg: &ResolvedConfig) -> dp_rust_sdk::Result<()> {
    match args.command {
        OrgCommand::Init {
            entity_id,
            package,
            server_keys,
        } => init_entity(cfg, &entity_id, &package, server_keys).await,
        OrgCommand::Status { entity_id } => {
            let res = client(cfg).get_entity(&entity_id).await?;
            println!("{}", serde_json::to_string_pretty(&res)?);
            Ok(())
        }
    }
}

pub async fn init_entity(
    cfg: &ResolvedConfig,
    entity_id: &str,
    package: &str,
    server_keys: bool,
) -> dp_rust_sdk::Result<()> {
    let client = client(cfg);
    let store = store(cfg)?;
    let entity_id = entity_id.to_ascii_lowercase();

    if let Some(existing) = load_entity_ca(&store, &entity_id)? {
        println!("entity CA existing {}", existing.ski);
        println!(
            "  cert {}",
            cfg.state_dir.join(admin_ca_cert(&entity_id)?).display()
        );
        let res = client.get_entity(&entity_id).await?;
        println!("{}", serde_json::to_string_pretty(&res)?);
        return Ok(());
    }

    let _ = client.seed_catalog().await;

    if server_keys {
        let res = client
            .kickstart_entity(&KickstartRequest {
                entity_id: entity_id.clone(),
                package: package.to_string(),
                ..Default::default()
            })
            .await?;
        let ca = persist_kickstart_response(&store, &entity_id, &res)?;
        print_kickstart(cfg, &entity_id, &ca.ski, true);
        return Ok(());
    }

    let (material, request) = prepare_client_keyed_kickstart(&entity_id, package)?;
    save_entity_ca(&store, &material)?;
    let res = client.kickstart_entity(&request).await?;
    if let Some(root_pem) = &res.platform_root_pem {
        store.save_string(KEY_PLATFORM_CA, root_pem)?;
    }
    print_kickstart(cfg, &entity_id, &material.ski, false);
    if let Some(admin) = &material.admin_ski {
        println!("  admin  {admin}");
    }
    Ok(())
}

fn print_kickstart(cfg: &ResolvedConfig, entity_id: &str, ski: &str, server_keys: bool) {
    println!("kickstarted {entity_id}");
    println!("  ca ski {ski}");
    if let Ok(path) = admin_ca_cert(entity_id) {
        println!("  cert   {}", cfg.state_dir.join(path).display());
    }
    if server_keys {
        println!("  keys   returned by server (dev/test allowServerKeygen)");
    } else {
        println!("  keys   generated locally (never sent)");
    }
}
