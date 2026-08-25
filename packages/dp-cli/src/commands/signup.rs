//! Product `signup`: session + client-keyed `kickstart-entity`.

use clap::{ArgGroup, Args};
use console::style;
use dp_rust_sdk::{load_session, ResolvedConfig};

use crate::client;
use crate::commands::org;
use crate::store;

#[derive(Args, Debug)]
#[command(group(
    ArgGroup::new("org_kind")
        .required(true)
        .args(["personal", "domain", "brand"])
))]
pub struct SignupArgs {
    /// Personal org: entity id = session email, package `personal`
    #[arg(long)]
    personal: bool,
    /// Enterprise org keyed by a domain (entity id = DOMAIN)
    #[arg(long, value_name = "DOMAIN")]
    domain: Option<String>,
    /// Enterprise org keyed by a brand slug (entity id = SLUG)
    #[arg(long, value_name = "SLUG")]
    brand: Option<String>,
}

pub struct SignupTarget {
    pub entity_id: String,
    pub package: &'static str,
    pub kind: &'static str,
}

pub async fn run(args: SignupArgs, cfg: &ResolvedConfig) -> dp_rust_sdk::Result<()> {
    require_session(cfg)?;
    let target = if args.personal {
        let email = session_email(cfg).await?;
        resolve_signup(SignupKind::Personal { email })?
    } else if let Some(domain) = args.domain {
        resolve_signup(SignupKind::Domain { domain })?
    } else if let Some(brand) = args.brand {
        resolve_signup(SignupKind::Brand { brand })?
    } else {
        return Err(dp_rust_sdk::Error::auth(
            "pass --personal, --domain <name>, or --brand <slug>",
        ));
    };

    org::init_entity(cfg, &target.entity_id, target.package, false).await?;
    println!(
        "  package {} ({})",
        target.package,
        style(target.kind).dim()
    );
    println!(
        "  next    {bin} register --org {org} --name laptop1",
        bin = cfg.product_name,
        org = target.entity_id
    );
    println!(
        "  or      {bin} register --local --org {org} --name laptop1",
        bin = cfg.product_name,
        org = target.entity_id
    );
    Ok(())
}

pub enum SignupKind {
    Personal { email: String },
    Domain { domain: String },
    Brand { brand: String },
}

pub fn resolve_signup(kind: SignupKind) -> dp_rust_sdk::Result<SignupTarget> {
    match kind {
        SignupKind::Personal { email } => {
            let entity_id = normalize_entity_id(&email, "email")?;
            if !entity_id.contains('@') {
                return Err(dp_rust_sdk::Error::auth(format!(
                    "session email {entity_id:?} does not look like an email — use --domain or --brand"
                )));
            }
            Ok(SignupTarget {
                entity_id,
                package: "personal",
                kind: "personal",
            })
        }
        SignupKind::Domain { domain } => Ok(SignupTarget {
            entity_id: normalize_entity_id(&domain, "domain")?,
            package: "enterprise",
            kind: "domain",
        }),
        SignupKind::Brand { brand } => Ok(SignupTarget {
            entity_id: normalize_entity_id(&brand, "brand")?,
            package: "enterprise",
            kind: "brand",
        }),
    }
}

fn normalize_entity_id(raw: &str, label: &str) -> dp_rust_sdk::Result<String> {
    let id = raw.trim().to_ascii_lowercase();
    if id.is_empty() {
        return Err(dp_rust_sdk::Error::auth(format!(
            "{label} must not be empty"
        )));
    }
    if id.contains("--") {
        return Err(dp_rust_sdk::Error::auth(format!(
            "{label} {id:?} must not contain `--` (plugin host separator)"
        )));
    }
    if !id.is_ascii() {
        return Err(dp_rust_sdk::Error::auth(format!(
            "{label} {id:?} must be ASCII"
        )));
    }
    Ok(id)
}

fn require_session(cfg: &ResolvedConfig) -> dp_rust_sdk::Result<()> {
    if cfg.auth_token.is_some() {
        return Ok(());
    }
    Err(dp_rust_sdk::Error::auth(format!(
        "not logged in — run `{} auth login` first",
        cfg.product_name
    )))
}

async fn session_email(cfg: &ResolvedConfig) -> dp_rust_sdk::Result<String> {
    let http = client(cfg);
    if let Some(info) = http.get_session().await? {
        if let Some(email) = info.user.and_then(|u| u.email).filter(|e| !e.is_empty()) {
            return Ok(email);
        }
    }
    let store = store(cfg)?;
    if let Some(session) = load_session(&store)? {
        if let Some(email) = session.user.and_then(|u| u.email).filter(|e| !e.is_empty()) {
            return Ok(email);
        }
    }
    Err(dp_rust_sdk::Error::auth(
        "no email on this session — use --domain / --brand, or `auth login` again",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn personal_uses_email_and_personal_package() {
        let t = resolve_signup(SignupKind::Personal {
            email: "Alice@Example.COM".into(),
        })
        .unwrap();
        assert_eq!(t.entity_id, "alice@example.com");
        assert_eq!(t.package, "personal");
    }

    #[test]
    fn domain_and_brand_are_enterprise() {
        let d = resolve_signup(SignupKind::Domain {
            domain: "Acme.COM".into(),
        })
        .unwrap();
        assert_eq!(d.entity_id, "acme.com");
        assert_eq!(d.package, "enterprise");
        let b = resolve_signup(SignupKind::Brand {
            brand: "Acme".into(),
        })
        .unwrap();
        assert_eq!(b.entity_id, "acme");
        assert_eq!(b.package, "enterprise");
        assert_eq!(b.kind, "brand");
    }

    #[test]
    fn rejects_separator_in_slug() {
        assert!(resolve_signup(SignupKind::Brand {
            brand: "acme--corp".into(),
        })
        .is_err());
    }

    #[test]
    fn rejects_personal_without_at() {
        assert!(resolve_signup(SignupKind::Personal {
            email: "not-an-email".into(),
        })
        .is_err());
    }
}
