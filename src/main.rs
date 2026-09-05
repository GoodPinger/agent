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
    /// Run the inside-out daemon: report metrics, processes, and error signatures.
    Watch {
        /// Run a single tick and exit (for testing / one-shot reports).
        #[arg(long)]
        once: bool,
    },
    /// Check internal reachability of a service.
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
        Command::Watch { once } => watch::cmd_watch(once),
        Command::Check { target } => match target {
            CheckTarget::Tcp { addr } => check::cmd_tcp(&addr),
            CheckTarget::Http { url } => check::cmd_http(&url),
            CheckTarget::Egress { url } => check::cmd_egress(&url),
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
