//! Machine agent: present the Platform-endorsed leaf and stay resident.
//!
//! Lifecycle CLI (`idr` / `dp-cli`) enrolls then exits. This binary is the
//! long-running Target/Source process. It does not implement Presence/QUIC.
//!
//! Default: stay in this terminal until ctrl-c or the terminal closes.
//! `--keep` / `--detach`: run as a background service.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use clap::Parser;
use console::style;
use dp_rust_sdk::{load_agent_identity, DpClient, FileKeyStore, ResolvedConfig};

const PRODUCT_NAME: &str = match option_env!("DP_PRODUCT_NAME") {
    Some(name) => name,
    None => "dp",
};

const RESIDENT_ENV: &str = "DP_AGENT_RESIDENT";

#[derive(Parser, Debug)]
#[command(
    name = "dp-agent",
    version,
    about = "Delegate Permissions machine agent. Default: stay in this terminal until ctrl-c."
)]
struct AgentCli {
    /// Better Auth base URL (overrides the compiled default)
    #[arg(long, global = true, env = "DP_BACKEND_URL")]
    backend_url: Option<String>,

    /// State directory (keys). User: ~/.idr  service: /var/lib/idr  (`DP_STATE_DIR`)
    #[arg(long, global = true, env = "DP_STATE_DIR")]
    state_dir: Option<PathBuf>,

    /// Run as a background service. `--detach` is the same word.
    #[arg(long, visible_alias = "detach")]
    keep: bool,

    /// Optional mTLS GET probe (does not implement Presence)
    #[arg(long)]
    pep_url: Option<String>,
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let cli = parse_cli();
    let mut cfg = ResolvedConfig::from_env();
    if let Some(url) = cli.backend_url.clone() {
        cfg.backend_url = url;
    }
    if let Some(dir) = cli.state_dir.clone() {
        cfg.state_dir = dir;
    }

    match run(cli, cfg).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{} {err}", style("error:").red().bold());
            std::process::ExitCode::FAILURE
        }
    }
}

fn parse_cli() -> AgentCli {
    let mut args: Vec<String> = std::env::args().collect();
    if let Some(first) = args.first_mut() {
        if let Some(stem) = std::path::Path::new(first).file_stem() {
            *first = stem.to_string_lossy().into_owned();
        }
    }
    AgentCli::parse_from(args)
}

async fn run(cli: AgentCli, cfg: ResolvedConfig) -> dp_rust_sdk::Result<()> {
    let store = FileKeyStore::open(&cfg.state_dir)?;
    let identity = load_agent_identity(&store)?;
    warn_state_dir_privilege(&cfg.state_dir);

    let already_resident = std::env::var_os(RESIDENT_ENV).is_some();
    if cli.keep && !already_resident {
        return daemonize(&cfg);
    }

    let banner = format!(
        "agent {}  state {}  product {PRODUCT_NAME}",
        identity.machine_identity,
        cfg.state_dir.display()
    );
    println!("{} {banner}", style("agent").green().bold());

    if let Some(url) = cli.pep_url.as_deref() {
        let client =
            DpClient::new(url).with_client_cert(&identity.endorsed_pem, &identity.key_pem)?;
        match client.probe_url(url).await {
            Ok(status) => println!("  pep     {url} → HTTP {status}"),
            Err(err) => {
                eprintln!("{} pep probe failed: {err}", style("warn:").yellow());
            }
        }
    }

    write_pid_file(&pid_path(&cfg.state_dir), std::process::id())?;
    println!("  pid     {} (ctrl-c to stop)", std::process::id());
    wait_until_stop().await?;
    let _ = fs::remove_file(pid_path(&cfg.state_dir));
    println!("stopped");
    Ok(())
}

fn daemonize(cfg: &ResolvedConfig) -> dp_rust_sdk::Result<()> {
    let pid_file = pid_path(&cfg.state_dir);
    if let Some(pid) = read_pid_file(&pid_file) {
        if process_exists(pid) {
            return Err(dp_rust_sdk::Error::agent(format!(
                "already running (pid {pid}, {})",
                pid_file.display()
            )));
        }
        let _ = fs::remove_file(&pid_file);
    }

    let exe = std::env::current_exe()
        .map_err(|e| dp_rust_sdk::Error::agent(format!("current exe: {e}")))?;
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    args.retain(|a| a != "--keep" && a != "--detach");

    let log_path = cfg.state_dir.join("agent.log");
    let log = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|e| dp_rust_sdk::Error::agent(format!("open {}: {e}", log_path.display())))?;
    let log_err = log
        .try_clone()
        .map_err(|e| dp_rust_sdk::Error::agent(format!("clone log: {e}")))?;

    let mut cmd = std::process::Command::new(&exe);
    cmd.args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err))
        .env(RESIDENT_ENV, "1");
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x00000008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;
        cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
    }

    let child = cmd
        .spawn()
        .map_err(|e| dp_rust_sdk::Error::agent(format!("start service: {e}")))?;
    write_pid_file(&pid_file, child.id())?;
    println!(
        "{} {}  pid {}  (background)",
        style("agent").green().bold(),
        PRODUCT_NAME,
        child.id()
    );
    println!("  state   {}", cfg.state_dir.display());
    println!("  pidfile {}", pid_file.display());
    println!("  log     {}", log_path.display());
    println!("  stop    kill $(cat {})", pid_file.display());
    Ok(())
}

fn pid_path(state_dir: &Path) -> PathBuf {
    state_dir.join("agent.pid")
}

fn write_pid_file(path: &Path, pid: u32) -> dp_rust_sdk::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            dp_rust_sdk::Error::agent(format!("mkdir {}: {e}", parent.display()))
        })?;
    }
    fs::write(path, format!("{pid}\n"))
        .map_err(|e| dp_rust_sdk::Error::agent(format!("write {}: {e}", path.display())))
}

fn read_pid_file(path: &Path) -> Option<u32> {
    fs::read_to_string(path)
        .ok()?
        .trim()
        .parse()
        .ok()
}

fn process_exists(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    #[cfg(target_os = "linux")]
    {
        Path::new(&format!("/proc/{pid}")).exists()
    }
    #[cfg(not(target_os = "linux"))]
    {
        std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}

fn warn_state_dir_privilege(state_dir: &Path) {
    let Some(uid) = effective_uid() else {
        return;
    };
    let path = state_dir.to_string_lossy();
    if uid == 0 && !path.starts_with("/var/lib") && !path.starts_with("/etc") {
        eprintln!(
            "{} running as root with state dir {path} — prefer /var/lib/{PRODUCT_NAME} so keys are not under a login home",
            style("warn:").yellow()
        );
    }
    if uid != 0 && path.starts_with("/var/lib") {
        eprintln!(
            "{} non-root process using {path} — this directory is usually root-owned",
            style("warn:").yellow()
        );
    }
}

fn effective_uid() -> Option<u32> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|l| l.starts_with("Uid:"))?;
    line.split_whitespace().nth(2)?.parse().ok()
}

async fn wait_until_stop() -> dp_rust_sdk::Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate())
            .map_err(|e| dp_rust_sdk::Error::agent(format!("sigterm: {e}")))?;
        tokio::select! {
            r = tokio::signal::ctrl_c() => {
                r.map_err(|e| dp_rust_sdk::Error::agent(format!("ctrl-c: {e}")))?;
            }
            _ = sigterm.recv() => {}
        }
        return Ok(());
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .map_err(|e| dp_rust_sdk::Error::agent(format!("ctrl-c: {e}")))
    }
}
