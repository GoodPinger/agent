//! `gpr` — the Goodpinger agent. Optional; reports from inside the customer's
//! server so an alert becomes an answer.
//!
//! Hard rules that this binary must never violate:
//!   - `gpr run` passes the wrapped command's exit code through unchanged.
//!   - No listening port, no remote execution, ever.
//!   - Bounded buffers everywhere; never fill a disk or OOM a host.

mod brand;
mod buffer;
mod check;
mod collect;
mod config;
mod doctor;
mod logs;
mod redact;
mod run;
mod transport;
mod watch;

use std::io::{IsTerminal, Read};
use std::path::PathBuf;

use clap::{Parser, Subcommand};

use config::Config;
use transport::Client;

/// The wire protocol version this build speaks.
pub const PROTOCOL_VERSION: u8 = 1;

#[derive(Parser)]
#[command(name = brand::CLI, version, about = brand::NAME, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Wrap a command: run it, report exit code, duration, and output tail.
    Run {
        /// Heartbeat slug this run reports to.
        #[arg(long)]
        slug: String,
        /// The command to run, after `--`. Its exit code is passed through unchanged.
        #[arg(last = true, required = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Send a bare heartbeat for a slug.
    Ping { slug: String },
    /// Diagnose clock skew, firewall, permissions, and token problems.
    Doctor,
    /// Authenticate this host with the control plane.
    Login {
        /// Token to store. If omitted, read one line from stdin.
        #[arg(long)]
        token: Option<String>,
    },
    /// Show this host's registration and last report status.
    Status,
    /// Inspect log sources: show what the parser would detect and send.
    Logs {
        /// Dry-run the log parser (the only mode today). Prints detected
        /// fingerprints, counts, and redacted samples; sends nothing.
        #[arg(long)]
        test: bool,
        /// Optional single log file to test against. Omit to use configured
        /// sources.
        path: Option<PathBuf>,
    },
    /// List the watched processes and their current state.
    Ps,
    /// Run the inside-out daemon, or manage what it watches.
    ///
    /// With no subcommand, runs the daemon: report metrics, processes, checks, and
    /// error signatures. `add` / `list` / `rm` edit the configured checks and
    /// watched processes.
    Watch {
        /// Run a single tick and exit (for testing / one-shot reports).
        #[arg(long)]
        once: bool,
        #[command(subcommand)]
        action: Option<WatchAction>,
    },
    /// Check internal reachability of a service (one-shot, by hand).
    Check {
        #[command(subcommand)]
        target: CheckTarget,
    },
}

#[derive(Subcommand)]
enum CheckTarget {
    /// TCP connect to host:port.
    Tcp { addr: String },
    /// HTTP GET a URL and report status + latency.
    Http { url: String },
    /// Outbound reachability to a dependency URL.
    Egress { url: String },
    /// Read a pidfile and check the process it names is alive.
    Pidfile { path: String },
}

#[derive(Subcommand)]
enum WatchAction {
    /// Add a check or watched process to what `gpr watch` reports.
    Add {
        #[command(subcommand)]
        what: WatchAdd,
    },
    /// List the configured checks and watched processes.
    List,
    /// Remove a configured check (by target) or process (by name).
    Rm {
        /// The check target or process name to remove.
        target: String,
    },
}

#[derive(Subcommand)]
enum WatchAdd {
    /// TCP port, e.g. gpr watch add tcp localhost:5432
    Tcp { target: String },
    /// HTTP health endpoint, e.g. gpr watch add http http://localhost:8080/health
    Http { target: String },
    /// Outbound dependency, e.g. gpr watch add egress https://api.example.com
    Egress { target: String },
    /// PID file, e.g. gpr watch add pidfile /var/run/nginx.pid
    Pidfile { target: String },
    /// Watched process, e.g. gpr watch add process nginx [--match <cmdline substring>]
    Process {
        /// Display name (and default match string).
        name: String,
        /// Match this substring of the full command line instead of the name.
        #[arg(long = "match")]
        pattern: Option<String>,
    },
}

fn main() {
    let cli = Cli::parse();
    let code: i32 = match cli.command {
        Command::Run { slug, command } => run::cmd_run(&slug, &command),
        Command::Ping { slug } => cmd_ping(&slug),
        Command::Doctor => doctor::cmd_doctor(),
        Command::Login { token } => cmd_login(token),
        Command::Status => cmd_status(),
        Command::Logs { test, path } => logs::cmd::cmd_logs_test(test, path.as_deref()),
        Command::Ps => cmd_ps(),
        Command::Watch { once, action } => match action {
            None => watch::cmd_watch(once),
            Some(WatchAction::Add { what }) => cmd_watch_add(what),
            Some(WatchAction::List) => cmd_watch_list(),
            Some(WatchAction::Rm { target }) => cmd_watch_rm(&target),
        },
        Command::Check { target } => match target {
            CheckTarget::Tcp { addr } => check::cmd_tcp(&addr),
            CheckTarget::Http { url } => check::cmd_http(&url),
            CheckTarget::Egress { url } => check::cmd_egress(&url),
            CheckTarget::Pidfile { path } => check::cmd_pidfile(&path),
        },
    };
    // Exit with the resolved code — for `run`, this is the wrapped command's
    // own code, unchanged.
    std::process::exit(code);
}

/// `gpr ping <slug>` — bare `GET /p/{slug}` heartbeat.
fn cmd_ping(slug: &str) -> i32 {
    let cfg = match Config::load_or_init() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}: {e}", brand::CLI);
            return 1;
        }
    };
    let client = match Client::new(cfg.effective_base_url(), None, config::http_timeout()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}: {e}", brand::CLI);
            return 1;
        }
    };
    match client.ping(slug) {
        Ok(()) => {
            println!("{}: heartbeat sent for {slug}", brand::CLI);
            0
        }
        Err(e) => {
            eprintln!("{}: heartbeat failed: {e}", brand::CLI);
            1
        }
    }
}

/// `gpr login` — persist a token from `--token` or stdin.
fn cmd_login(token: Option<String>) -> i32 {
    let token = match token {
        Some(t) => t,
        None => {
            if std::io::stdin().is_terminal() {
                eprintln!("{}: paste agent token, then press Enter:", brand::CLI);
            }
            let mut s = String::new();
            if let Err(e) = std::io::stdin().read_to_string(&mut s) {
                eprintln!("{}: could not read token: {e}", brand::CLI);
                return 1;
            }
            s.trim().to_string()
        }
    };
    if token.is_empty() {
        eprintln!("{}: no token provided", brand::CLI);
        return 1;
    }
    let mut cfg = match Config::load_or_init() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}: {e}", brand::CLI);
            return 1;
        }
    };
    cfg.token = Some(token);
    if let Err(e) = cfg.save() {
        eprintln!("{}: could not save token: {e}", brand::CLI);
        return 1;
    }
    println!("{}: token saved for host {}", brand::CLI, cfg.host_id);

    // Best-effort registration announce (POST /agent/hello). A network failure
    // here must not fail login — the token is already persisted.
    match Client::new(
        cfg.effective_base_url(),
        cfg.token.clone(),
        config::http_timeout(),
    ) {
        Ok(client) => {
            let hello = transport::HelloReq::for_host(cfg.host_id.clone());
            match client.hello(&hello) {
                Ok(()) => println!("{}: registered with control plane", brand::CLI),
                Err(e) => eprintln!(
                    "{}: token saved, but registration deferred: {e}",
                    brand::CLI
                ),
            }
        }
        Err(e) => eprintln!(
            "{}: token saved, but registration deferred: {e}",
            brand::CLI
        ),
    }
    0
}

/// `gpr ps` — list the configured watched processes and their current state.
fn cmd_ps() -> i32 {
    let cfg = match Config::load_or_init() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}: {e}", brand::CLI);
            return 1;
        }
    };
    if cfg.processes.is_empty() {
        eprintln!(
            "{}: no processes configured to watch — set `processes` in the config",
            brand::CLI
        );
        return 0;
    }
    let mut collector = collect::Collector::new(cfg.processes.clone());
    for p in collector.sample_processes() {
        let pid = p
            .pid
            .map(|x| x.to_string())
            .unwrap_or_else(|| "-".to_string());
        let state = if p.running { "running" } else { "stopped" };
        println!(
            "{:<28} pid={:<8} {:<8} restarts={}",
            p.name, pid, state, p.restarts
        );
    }
    0
}

/// Load the config for a `gpr watch add/list/rm` edit, printing a friendly error.
fn load_cfg_for_edit() -> Result<Config, i32> {
    Config::load_or_init().map_err(|e| {
        eprintln!("{}: {e}", brand::CLI);
        1
    })
}

/// `gpr watch add <kind> <target>` — append a check or process to the config.
fn cmd_watch_add(what: WatchAdd) -> i32 {
    let mut cfg = match load_cfg_for_edit() {
        Ok(c) => c,
        Err(code) => return code,
    };

    // Build the check kind/target, or handle the process case separately.
    let (kind, target) = match what {
        WatchAdd::Tcp { target } => (check::KIND_TCP, target),
        WatchAdd::Http { target } => (check::KIND_HTTP, target),
        WatchAdd::Egress { target } => (check::KIND_EGRESS, target),
        WatchAdd::Pidfile { target } => (check::KIND_PIDFILE, target),
        WatchAdd::Process { name, pattern } => {
            if cfg.processes.len() >= config::MAX_PROCESSES {
                eprintln!(
                    "{}: process limit reached ({} max)",
                    brand::CLI,
                    config::MAX_PROCESSES
                );
                return 1;
            }
            if cfg.processes.iter().any(|p| p.name == name) {
                println!("{}: process '{name}' is already watched", brand::CLI);
                return 0;
            }
            cfg.processes.push(config::ProcessSpec {
                name: name.clone(),
                pattern,
            });
            if let Err(e) = cfg.save() {
                eprintln!("{}: could not save config: {e}", brand::CLI);
                return 1;
            }
            println!("{}: now watching process '{name}'", brand::CLI);
            return 0;
        }
    };

    if cfg.checks.len() >= config::MAX_CHECKS {
        eprintln!(
            "{}: check limit reached ({} max)",
            brand::CLI,
            config::MAX_CHECKS
        );
        return 1;
    }
    if cfg
        .checks
        .iter()
        .any(|ck| ck.kind == kind && ck.target == target)
    {
        println!(
            "{}: {kind} check for '{target}' already configured",
            brand::CLI
        );
        return 0;
    }
    cfg.checks.push(config::CheckSpec {
        kind: kind.to_string(),
        target: target.clone(),
    });
    if let Err(e) = cfg.save() {
        eprintln!("{}: could not save config: {e}", brand::CLI);
        return 1;
    }
    println!("{}: added {kind} check for '{target}'", brand::CLI);
    println!(
        "{}: it runs each tick once `{} watch` is running",
        brand::CLI,
        brand::CLI
    );
    0
}

/// `gpr watch list` — show configured checks and processes.
fn cmd_watch_list() -> i32 {
    let cfg = match load_cfg_for_edit() {
        Ok(c) => c,
        Err(code) => return code,
    };
    if cfg.checks.is_empty() && cfg.processes.is_empty() {
        println!(
            "{}: nothing configured yet. Add one, e.g. `{} watch add tcp localhost:5432`",
            brand::CLI,
            brand::CLI
        );
        return 0;
    }
    if !cfg.checks.is_empty() {
        println!("checks:");
        for ck in &cfg.checks {
            println!("  {:<8} {}", ck.kind, ck.target);
        }
    }
    if !cfg.processes.is_empty() {
        println!("processes:");
        for p in &cfg.processes {
            match &p.pattern {
                Some(pat) => println!("  {:<20} match={pat}", p.name),
                None => println!("  {}", p.name),
            }
        }
    }
    0
}

/// `gpr watch rm <target>` — remove a check (by target) or process (by name).
fn cmd_watch_rm(target: &str) -> i32 {
    let mut cfg = match load_cfg_for_edit() {
        Ok(c) => c,
        Err(code) => return code,
    };
    let before = cfg.checks.len() + cfg.processes.len();
    cfg.checks.retain(|ck| ck.target != target);
    cfg.processes.retain(|p| p.name != target);
    let removed = before - (cfg.checks.len() + cfg.processes.len());
    if removed == 0 {
        eprintln!("{}: nothing matched '{target}'", brand::CLI);
        return 1;
    }
    if let Err(e) = cfg.save() {
        eprintln!("{}: could not save config: {e}", brand::CLI);
        return 1;
    }
    println!(
        "{}: removed {removed} entr{}",
        brand::CLI,
        if removed == 1 { "y" } else { "ies" }
    );
    0
}

/// `gpr status` — host id, base URL, token presence, buffered-report count.
fn cmd_status() -> i32 {
    let cfg = match Config::load_or_init() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}: {e}", brand::CLI);
            return 1;
        }
    };
    let buffered = Config::buffer_path()
        .ok()
        .and_then(|p| buffer::Buffer::open(p).ok())
        .map(|b| b.len())
        .unwrap_or(0);

    println!("host id:          {}", cfg.host_id);
    println!("base url:         {}", cfg.effective_base_url());
    println!(
        "token:            {}",
        if cfg.token.is_some() {
            "present"
        } else {
            "absent"
        }
    );
    println!("buffered reports: {buffered}");
    if let Some(rss) = collect::current_rss_bytes() {
        println!("agent rss:        {} MB", rss / (1024 * 1024));
    }
    0
}
