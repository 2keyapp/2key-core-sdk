//! Numbered CSR inbox (`idr csr`) — product wrapper over `admin machine *`.

use clap::{Args, Subcommand};
use dp_rust_sdk::{enrollment_id, EnrollListItem, ResolvedConfig};

use crate::client;
use crate::commands::admin;
use crate::commands::infer_entity_id;

#[derive(Args, Debug)]
pub struct CsrArgs {
    /// Entity id. Inferred when this state dir has exactly one Entity CA.
    #[arg(long, global = true)]
    org: Option<String>,
    #[command(subcommand)]
    command: Option<CsrCommand>,
}

#[derive(Subcommand, Debug)]
enum CsrCommand {
    /// List enrollment CSRs (default)
    List {
        #[arg(long, default_value = "pending")]
        status: String,
    },
    /// Show one row (`1` from the current list, or an enroll id)
    Show {
        selector: String,
        #[arg(long, default_value = "pending")]
        status: String,
    },
    /// Sign with Entity CA and approve
    Approve {
        selector: String,
        #[arg(long)]
        yes: bool,
        #[arg(long, default_value = "pending")]
        status: String,
    },
    /// Reject an enrollment
    Reject {
        selector: String,
        #[arg(long)]
        yes: bool,
        #[arg(long, default_value = "pending")]
        status: String,
    },
}

pub async fn run(args: CsrArgs, cfg: &ResolvedConfig) -> dp_rust_sdk::Result<()> {
    let org = infer_entity_id(cfg, args.org.as_deref())?;
    match args.command.unwrap_or(CsrCommand::List {
        status: "pending".into(),
    }) {
        CsrCommand::List { status } => list_cmd(cfg, &org, &status).await,
        CsrCommand::Show { selector, status } => {
            let item = load_selector(cfg, &org, &status, &selector).await?;
            let id = enrollment_id(&item)?;
            admin::show_cmd(cfg, id, Some(&org)).await
        }
        CsrCommand::Approve {
            selector,
            yes,
            status,
        } => {
            let item = load_selector(cfg, &org, &status, &selector).await?;
            let id = enrollment_id(&item)?;
            admin::approve_cmd(cfg, id, Some(&org), yes).await
        }
        CsrCommand::Reject {
            selector,
            yes,
            status,
        } => {
            let item = load_selector(cfg, &org, &status, &selector).await?;
            let id = enrollment_id(&item)?;
            admin::reject_cmd(cfg, id, yes).await
        }
    }
}

async fn list_cmd(cfg: &ResolvedConfig, org: &str, status: &str) -> dp_rust_sdk::Result<()> {
    let list = fetch_sorted(cfg, org, status).await?;
    if list.is_empty() {
        println!("no CSRs for {org} ({status})");
        return Ok(());
    }
    println!("  #  {:<28} {:<12} {}", "HOST", "STATUS", "ENROLL");
    for (i, item) in list.iter().enumerate() {
        let host = item.host.as_deref().unwrap_or("—");
        let st = item.status.as_deref().unwrap_or("—");
        let id = enrollment_id(item).unwrap_or("—");
        println!("{:>3}  {host:<28} {st:<12} {id}", i + 1);
    }
    println!();
    println!(
        "approve with: {} csr approve 1 --org {org}",
        cfg.product_name
    );
    Ok(())
}

async fn load_selector(
    cfg: &ResolvedConfig,
    org: &str,
    status: &str,
    selector: &str,
) -> dp_rust_sdk::Result<EnrollListItem> {
    let list = fetch_sorted(cfg, org, status).await?;
    resolve_enroll_selector(&list, selector).cloned()
}

async fn fetch_sorted(
    cfg: &ResolvedConfig,
    org: &str,
    status: &str,
) -> dp_rust_sdk::Result<Vec<EnrollListItem>> {
    let status_filter = if status.eq_ignore_ascii_case("all") {
        None
    } else {
        Some(status)
    };
    let mut list = client(cfg).enroll_list(org, status_filter).await?;
    list.sort_by(|a, b| {
        enrollment_id(a)
            .unwrap_or("")
            .cmp(enrollment_id(b).unwrap_or(""))
    });
    Ok(list)
}

/// `1` = first row of the filtered list. Anything else matches `enrollId`.
pub fn resolve_enroll_selector<'a>(
    list: &'a [EnrollListItem],
    selector: &str,
) -> dp_rust_sdk::Result<&'a EnrollListItem> {
    let trimmed = selector.trim();
    if trimmed.is_empty() {
        return Err(dp_rust_sdk::Error::admin(
            "pass a list index (1) or an enroll id",
        ));
    }
    if trimmed.chars().all(|c| c.is_ascii_digit()) {
        let n: usize = trimmed
            .parse()
            .map_err(|_| dp_rust_sdk::Error::admin(format!("invalid CSR index {trimmed}")))?;
        if n == 0 || n > list.len() {
            return Err(dp_rust_sdk::Error::admin(format!(
                "CSR index {n} is out of range (1..={})",
                list.len()
            )));
        }
        return Ok(&list[n - 1]);
    }
    list.iter()
        .find(|item| enrollment_id(item).ok() == Some(trimmed))
        .ok_or_else(|| {
            dp_rust_sdk::Error::admin(format!("enrollment {trimmed} is not in this CSR list"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(id: &str, host: &str) -> EnrollListItem {
        EnrollListItem {
            enroll_id: Some(id.into()),
            entity_id: Some("acme.com".into()),
            host: Some(host.into()),
            status: Some("pending".into()),
            kind: None,
            ski: None,
            csr_pem: None,
            extra: Default::default(),
        }
    }

    #[test]
    fn index_is_one_based() {
        let list = vec![item("aaa", "a--acme.com"), item("bbb", "b--acme.com")];
        assert_eq!(
            enrollment_id(resolve_enroll_selector(&list, "1").unwrap()).unwrap(),
            "aaa"
        );
        assert_eq!(
            enrollment_id(resolve_enroll_selector(&list, "2").unwrap()).unwrap(),
            "bbb"
        );
        assert!(resolve_enroll_selector(&list, "0").is_err());
        assert!(resolve_enroll_selector(&list, "3").is_err());
    }

    #[test]
    fn enroll_id_still_works() {
        let list = vec![item("enr_1", "a--acme.com"), item("enr_2", "b--acme.com")];
        assert_eq!(
            enrollment_id(resolve_enroll_selector(&list, "enr_2").unwrap()).unwrap(),
            "enr_2"
        );
        assert!(resolve_enroll_selector(&list, "missing").is_err());
    }
}
