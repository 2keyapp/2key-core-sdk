//! Human AuthN: Better Auth device-code (`gh auth login`) or pasted cookie.

use std::io::{self, IsTerminal, Write};
use std::process::Command;
use std::time::Duration;

use clap::{Args, Subcommand};
use console::style;
use dp_rust_sdk::{
    delete_session, load_session, save_session, DeviceCodeResponse, SessionUser, StoredSession,
};

use crate::client;
use crate::store;

#[derive(Args, Debug)]
pub struct AuthArgs {
    #[command(subcommand)]
    command: AuthCommand,
}

#[derive(Subcommand, Debug)]
enum AuthCommand {
    /// Sign in via device code (browser) or `--paste` a session cookie
    Login {
        /// Skip device flow; prompt for a cookie or Bearer token
        #[arg(long)]
        paste: bool,
        /// Do not open a browser
        #[arg(long)]
        no_browser: bool,
        /// OAuth client_id (default: `{product}-cli` or DP_CLIENT_ID)
        #[arg(long)]
        client_id: Option<String>,
        /// Do not fall back to paste when device authorization is missing
        #[arg(long)]
        no_paste: bool,
    },
    /// Show the stored session user
    Status,
    /// Delete the local session file (and sign-out on the server if possible)
    Logout,
}

pub async fn run(args: AuthArgs, cfg: &dp_rust_sdk::ResolvedConfig) -> dp_rust_sdk::Result<()> {
    match args.command {
        AuthCommand::Login {
            paste,
            no_browser,
            client_id,
            no_paste,
        } => login(cfg, paste, no_browser, client_id, no_paste).await,
        AuthCommand::Status => status(cfg).await,
        AuthCommand::Logout => logout(cfg).await,
    }
}

async fn login(
    cfg: &dp_rust_sdk::ResolvedConfig,
    paste: bool,
    no_browser: bool,
    client_id: Option<String>,
    no_paste: bool,
) -> dp_rust_sdk::Result<()> {
    let store = store(cfg)?;
    let mut session = if paste {
        prompt_paste()?
    } else {
        let client_id = client_id.unwrap_or_else(|| cfg.client_id.clone());
        match device_login(cfg, &client_id, no_browser).await {
            Ok(s) => s,
            Err(err) if !no_paste && should_paste_fallback(&err) && io::stdin().is_terminal() => {
                eprintln!("{} {err}", style("warn:").yellow());
                eprintln!(
                    "device authorization is not available — paste a browser session cookie instead"
                );
                eprintln!(
                    "(enable deviceAuthorization() + bearer() on the auth server to skip this)"
                );
                prompt_paste()?
            }
            Err(err) => return Err(err),
        }
    };

    let authed = client(cfg).with_auth(&session.to_client_auth());
    match authed.get_session().await {
        Ok(Some(info)) => {
            if let Some(user) = info.user {
                print_hello(&user);
                session.user = Some(user);
            } else {
                println!("{}", style("logged in").green().bold());
            }
        }
        Ok(None) => {
            println!("{}", style("logged in").green().bold());
            println!(
                "  (get-session was empty — enable bearer() for device tokens, or paste a cookie)"
            );
        }
        Err(err) => {
            eprintln!(
                "{} could not call get-session: {err}",
                style("warn:").yellow()
            );
            println!("{}", style("token saved").yellow().bold());
        }
    }

    save_session(&store, &session)?;
    println!("  session {}", cfg.state_dir.join("session").display());
    Ok(())
}

async fn device_login(
    cfg: &dp_rust_sdk::ResolvedConfig,
    client_id: &str,
    no_browser: bool,
) -> dp_rust_sdk::Result<StoredSession> {
    let http = client(cfg);
    let code: DeviceCodeResponse = match http
        .device_code(client_id, Some("openid profile email"))
        .await
    {
        Ok(c) => c,
        Err(err) => return Err(err),
    };

    println!("{}", style("device authorization").bold());
    println!("  visit    {}", code.verification_uri);
    println!("  code     {}", style(&code.user_code).cyan().bold());
    if let Some(complete) = &code.verification_uri_complete {
        println!("  or       {complete}");
        if !no_browser {
            try_open_browser(complete);
        }
    } else if !no_browser {
        try_open_browser(&code.verification_uri);
    }
    println!("waiting for approval (ctrl-c to cancel)…");

    let interval = Duration::from_secs(code.interval.unwrap_or(5).max(1));
    let timeout = Duration::from_secs(code.expires_in.unwrap_or(600).max(30));
    let issued = tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            return Err(dp_rust_sdk::Error::auth("cancelled"));
        }
        result = http.poll_device_token(client_id, &code.device_code, interval, timeout) => {
            result?
        }
    };
    Ok(StoredSession::from_device_token(
        &issued.access_token,
        issued.expires_in,
    ))
}

async fn status(cfg: &dp_rust_sdk::ResolvedConfig) -> dp_rust_sdk::Result<()> {
    let store = store(cfg)?;
    let Some(local) = load_session(&store)? else {
        if cfg.auth_token.is_some() {
            println!("session  from --token / DP_AUTH_TOKEN (no session file)");
        } else {
            println!("logged out");
        }
        return Ok(());
    };
    println!("session  {}", cfg.state_dir.join("session").display());
    println!("transport {:?}", local.transport);
    if let Some(user) = &local.user {
        if let Some(email) = &user.email {
            println!("email    {email}");
        }
        if let Some(name) = &user.name {
            println!("name     {name}");
        }
        if let Some(id) = &user.id {
            println!("user     {id}");
        }
    }
    let http = client(cfg);
    match http.get_session().await? {
        Some(info) => {
            if let Some(user) = info.user {
                print_hello(&user);
            } else {
                println!("server   session ok");
            }
        }
        None => println!("server   no session (token may be expired or bearer() missing)"),
    }
    Ok(())
}

async fn logout(cfg: &dp_rust_sdk::ResolvedConfig) -> dp_rust_sdk::Result<()> {
    let store = store(cfg)?;
    if cfg.auth_token.is_some() {
        let _ = client(cfg).sign_out().await;
    }
    delete_session(&store)?;
    println!(
        "{} local session removed",
        style("logged out").green().bold()
    );
    Ok(())
}

fn prompt_paste() -> dp_rust_sdk::Result<StoredSession> {
    eprint!("paste session cookie or Bearer token: ");
    let _ = io::stderr().flush();
    let mut line = String::new();
    io::stdin()
        .read_line(&mut line)
        .map_err(|e| dp_rust_sdk::Error::auth(format!("read token: {e}")))?;
    StoredSession::from_pasted(&line)
}

fn print_hello(user: &SessionUser) {
    let who = user
        .email
        .as_deref()
        .or(user.name.as_deref())
        .or(user.id.as_deref())
        .unwrap_or("user");
    println!("{} {who}", style("logged in").green().bold());
}

fn should_paste_fallback(err: &dp_rust_sdk::Error) -> bool {
    match err {
        dp_rust_sdk::Error::Http { status, .. } if (400..500).contains(status) => true,
        dp_rust_sdk::Error::Auth(msg) => {
            let m = msg.to_ascii_lowercase();
            m.contains("device/code") || m.contains("not found") || m.contains("404")
        }
        _ => false,
    }
}

fn try_open_browser(url: &str) {
    let cmds = if cfg!(target_os = "macos") {
        vec!["open"]
    } else if cfg!(target_os = "windows") {
        vec!["cmd", "/C", "start"]
    } else {
        vec!["xdg-open"]
    };
    let mut iter = cmds.into_iter();
    let Some(bin) = iter.next() else { return };
    let mut cmd = Command::new(bin);
    for arg in iter {
        cmd.arg(arg);
    }
    let _ = cmd
        .arg(url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}
