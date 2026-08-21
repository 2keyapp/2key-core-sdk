pub mod admin;
pub mod auth;
pub mod csr;
pub mod invite;
pub mod machine;
pub mod org;
pub mod platform;
pub mod signup;

use std::fs;

use dp_rust_sdk::ResolvedConfig;

pub fn print_version(cfg: &ResolvedConfig) {
    println!("{} {}", cfg.product_name, env!("CARGO_PKG_VERSION"));
    println!("backend  {}", cfg.backend_url);
    println!("state    {}", cfg.state_dir.display());
    println!("separator {:?}", cfg.separator);
    println!("client   {}", cfg.client_id);
    let session = cfg.state_dir.join("session");
    if session.is_file() {
        println!("session  {}", session.display());
    } else {
        println!("session  (none — run auth login)");
    }
}

/// `--org` or the single Entity CA under `$DP_STATE_DIR/admin/`.
pub fn infer_entity_id(
    cfg: &ResolvedConfig,
    explicit: Option<&str>,
) -> dp_rust_sdk::Result<String> {
    if let Some(id) = explicit {
        let id = id.trim();
        if id.is_empty() {
            return Err(dp_rust_sdk::Error::admin("pass --org <entity-id>"));
        }
        return Ok(id.to_ascii_lowercase());
    }
    let admin_dir = cfg.state_dir.join("admin");
    let mut found = Vec::new();
    if admin_dir.is_dir() {
        for entry in fs::read_dir(&admin_dir)
            .map_err(|e| dp_rust_sdk::Error::admin(format!("read {}: {e}", admin_dir.display())))?
        {
            let entry = entry.map_err(|e| dp_rust_sdk::Error::admin(e.to_string()))?;
            if entry.path().join("entity-ca.json").is_file() {
                found.push(entry.file_name().to_string_lossy().into_owned());
            }
        }
    }
    found.sort();
    match found.as_slice() {
        [only] => Ok(only.to_ascii_lowercase()),
        [] => Err(dp_rust_sdk::Error::admin(
            "pass --org <entity-id> (no Entity CA in this state dir)",
        )),
        many => Err(dp_rust_sdk::Error::admin(format!(
            "pass --org <entity-id> (multiple orgs in state dir: {})",
            many.join(", ")
        ))),
    }
}

#[allow(dead_code)]
pub fn not_yet(phase: &str, command: &str) -> dp_rust_sdk::Result<()> {
    Err(dp_rust_sdk::Error::Unsupported(format!(
        "{command} is planned for {phase}"
    )))
}

pub fn confirm(prompt: &str, default: bool, yes: bool) -> dp_rust_sdk::Result<bool> {
    if yes {
        return Ok(true);
    }
    dialoguer::Confirm::new()
        .with_prompt(prompt)
        .default(default)
        .interact()
        .map_err(|e| {
            dp_rust_sdk::Error::Message(format!(
                "prompt failed: {e} (pass --yes for non-interactive use)"
            ))
        })
}
