//! 2key Billing CLI — thin entrypoint over two-key-core.

mod keyring_store;

use std::env;
use std::fs;
use std::process::ExitCode;
use two_key_core::{
    normalize_api_base_url, AuthPort, InMemoryStorage, LicenseVerifier, SdkConfig, StaticTokenAuth,
    SystemClock, TwoKeyClient, VerifyOutcome,
};

use keyring_store::KeyringStorage;

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("version") => {
            println!("two-key {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some("normalize-url") => {
            let Some(url) = args.next() else {
                eprintln!("usage: two-key normalize-url <url>");
                return ExitCode::FAILURE;
            };
            println!("{}", normalize_api_base_url(&url));
            ExitCode::SUCCESS
        }
        Some("check-config") => match load_config_from_env() {
            Ok(c) => {
                println!("ok api_base_url={}", c.api_base_url);
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("{e}");
                ExitCode::FAILURE
            }
        },
        Some("verify-license") => {
            let mut pem_path: Option<String> = None;
            let mut jwt_arg: Option<String> = None;
            while let Some(a) = args.next() {
                match a.as_str() {
                    "--pem" => pem_path = args.next(),
                    "--jwt" => jwt_arg = args.next(),
                    other if pem_path.is_none() && !other.starts_with('-') => {
                        pem_path = Some(other.to_string());
                    }
                    other if jwt_arg.is_none() && !other.starts_with('-') => {
                        jwt_arg = Some(other.to_string());
                    }
                    _ => {}
                }
            }
            let Some(pem_path) = pem_path else {
                eprintln!("usage: two-key verify-license --pem <public.pem> --jwt <token-or-file>");
                return ExitCode::FAILURE;
            };
            let Some(jwt_arg) = jwt_arg else {
                eprintln!("usage: two-key verify-license --pem <public.pem> --jwt <token-or-file>");
                return ExitCode::FAILURE;
            };
            let pem = match fs::read_to_string(&pem_path) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("read pem: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let jwt = read_token_or_file(&jwt_arg);

            let verifier = match LicenseVerifier::from_pem(&pem) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::FAILURE;
                }
            };
            match verifier.verify_and_decode(&jwt, &SystemClock) {
                VerifyOutcome::Success(p) => {
                    println!(
                        "ok paying_party={} subscriptions={}",
                        p.paying_party.id,
                        p.subscriptions.len()
                    );
                    ExitCode::SUCCESS
                }
                VerifyOutcome::Failure { code, message } => {
                    eprintln!("{code}: {message}");
                    ExitCode::FAILURE
                }
            }
        }
        Some("session-demo") => {
            let cfg = match load_config_from_env() {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("{e}");
                    eprintln!("hint: set TWOKEY_API_BASE_URL, TWOKEY_PUBLIC_KEY_PEM, TWOKEY_STORAGE_PREFIX");
                    return ExitCode::FAILURE;
                }
            };
            let use_keyring = env::var("TWOKEY_USE_KEYRING")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);

            let result = if use_keyring {
                let store = KeyringStorage::new("two-key");
                run_session_demo(cfg, store)
            } else {
                run_session_demo(cfg, InMemoryStorage::new())
            };
            match result {
                Ok(msg) => {
                    println!("{msg}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("{e}");
                    ExitCode::FAILURE
                }
            }
        }
        Some("auth-token") => {
            // Headless Phase A: pasted / env token via AuthPort.
            let token = env::var("TWOKEY_ACCESS_TOKEN").unwrap_or_else(|_| {
                args.next().unwrap_or_default()
            });
            let auth = StaticTokenAuth {
                access_token: token,
            };
            match auth.acquire_api_token() {
                Ok(t) => {
                    println!("ok token_len={}", t.len());
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("{e}");
                    eprintln!("usage: TWOKEY_ACCESS_TOKEN=... two-key auth-token");
                    eprintln!("   or: two-key auth-token <token>");
                    ExitCode::FAILURE
                }
            }
        }
        Some("sync-license") => {
            // TWOKEY_API_BASE_URL + TWOKEY_PUBLIC_KEY_PEM + TWOKEY_ACCESS_TOKEN
            // optional: --etag <etag>  --party <paying_party_id>
            let mut etag: Option<String> = None;
            let mut party: Option<String> = None;
            while let Some(a) = args.next() {
                match a.as_str() {
                    "--etag" => etag = args.next(),
                    "--party" => party = args.next(),
                    _ => {}
                }
            }
            let cfg = match load_config_from_env() {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::FAILURE;
                }
            };
            let token = env::var("TWOKEY_ACCESS_TOKEN").unwrap_or_default();
            if token.trim().is_empty() {
                eprintln!("set TWOKEY_ACCESS_TOKEN (billing API JWT)");
                return ExitCode::FAILURE;
            }
            let client = match TwoKeyClient::with_memory(cfg) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::FAILURE;
                }
            };
            let mut session = two_key_core::AccountSession::new("cli");
            session.access_token = Some(token);
            session.license_etag = etag;
            session.paying_party_id_header = party;
            match client.sync_license(&mut session) {
                Ok(payload) => {
                    println!(
                        "ok paying_party={} subscriptions={} etag={}",
                        payload.paying_party.id,
                        payload.subscriptions.len(),
                        session.license_etag.as_deref().unwrap_or("-")
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("{e}");
                    ExitCode::FAILURE
                }
            }
        }
        _ => {
            eprintln!("two-key — 2key Billing CLI");
            eprintln!("commands:");
            eprintln!("  version");
            eprintln!("  normalize-url <url>");
            eprintln!("  check-config");
            eprintln!("  verify-license --pem <public.pem> --jwt <token-or-file>");
            eprintln!("  session-demo   (TWOKEY_* env; TWOKEY_USE_KEYRING=1 for OS keyring)");
            eprintln!("  auth-token     (pasted token / TWOKEY_ACCESS_TOKEN)");
            eprintln!("  sync-license   (TWOKEY_API_BASE_URL + PEM + ACCESS_TOKEN; --etag --party)");
            ExitCode::SUCCESS
        }
    }
}

fn read_token_or_file(jwt_arg: &str) -> String {
    if jwt_arg.contains('.') && !std::path::Path::new(jwt_arg).exists() {
        jwt_arg.to_string()
    } else {
        fs::read_to_string(jwt_arg)
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| jwt_arg.to_string())
    }
}

fn load_config_from_env() -> Result<SdkConfig, two_key_core::TwoKeyError> {
    let api = env::var("TWOKEY_API_BASE_URL").unwrap_or_default();
    let pem = env::var("TWOKEY_PUBLIC_KEY_PEM").unwrap_or_default();
    let prefix = env::var("TWOKEY_STORAGE_PREFIX").unwrap_or_else(|_| "two_key_cli".into());
    SdkConfig {
        api_base_url: api,
        public_key_pem: pem,
        storage_prefix: prefix,
        portal_base_url: None,
        shop_path: "/shop".into(),
        deep_link_scheme: None,
        license_poll_interval: std::time::Duration::from_secs(6 * 3600),
    }
    .validate()
}

fn run_session_demo<S: two_key_core::Storage>(
    cfg: SdkConfig,
    store: S,
) -> Result<String, two_key_core::TwoKeyError> {
    let client = TwoKeyClient::new(cfg, store, SystemClock)?;
    let mut s = two_key_core::AccountSession::new("demo");
    s.access_token = Some("demo-token".into());
    client.save_session(&s)?;
    let loaded = client
        .load_session("demo")?
        .ok_or_else(|| two_key_core::TwoKeyError::new(
            two_key_core::ErrorCode::Unknown,
            "session missing after save",
        ))?;
    Ok(format!(
        "ok session account={} token={}",
        loaded.account_key,
        loaded.access_token.as_deref().unwrap_or("")
    ))
}
