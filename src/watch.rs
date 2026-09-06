//! `gpr watch` — the inside-out daemon.
//!
//! Each interval it collects host metrics + process state, drains the log
//! pipeline's error signatures, and POSTs `/agent/report`; when a new error
//! appears it flushes the ring buffer as `/agent/context` (cost scales with
//! incidents, not log volume — §5.1). Every step is panic-isolated so one
//! failing collector never takes down the others. Tailing state
//! is persisted each tick, so a kill at any point resumes cleanly — no listening
//! port, all outbound.

use std::io::IsTerminal;
use std::panic::{catch_unwind, AssertUnwindSafe};
#[cfg(unix)]
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::brand;
use crate::check;
use crate::collect::Collector;
use crate::config::{self, Config};
use crate::logs::file::FileTailer;
use crate::logs::journald::JournaldReader;
use crate::logs::state::LogState;
use crate::logs::{pipeline_config_for, LogSourceConfig, Pipeline};
use crate::transport::{CheckReport, Client, ContextReq, Metrics, ProcessReport, ReportReq};

/// Incident context is bounded to ≤32 KB on the wire (protocol.md).
const CONTEXT_MAX_BYTES: usize = 32 * 1024;
/// Belt-and-braces cap on file poll iterations per tick (each poll advances the
/// offset, so this only guards a pathologically fast-growing file).
const MAX_POLLS_PER_TICK: usize = 10_000;

struct FileSrc {
    key: String,
    tailer: FileTailer,
}
struct JournalSrc {
    key: String,
    reader: JournaldReader,
}

/// Startup banner: what `gpr watch` is doing, its interval, and what it watches —
/// so a foreground run doesn't look frozen, and the service journal has a header.
fn print_startup(cfg: &Config, interval: Duration) {
    println!(
        "{}: watching this host — reporting every {}s (Ctrl-C to stop)",
        brand::CLI,
        interval.as_secs()
    );
    let mut what = Vec::new();
    if !cfg.processes.is_empty() {
        let names: Vec<&str> = cfg.processes.iter().map(|p| p.name.as_str()).collect();
        what.push(format!("processes: {}", names.join(", ")));
    }
    if !cfg.checks.is_empty() {
        what.push(format!("checks: {}", cfg.checks.len()));
    }
    if !cfg.log_sources.is_empty() {
        what.push(format!("log sources: {}", cfg.log_sources.len()));
    }
    if what.is_empty() {
        println!(
            "{}: metrics only — add processes/checks with `{} watch add` or `{} watch manage`",
            brand::CLI,
            brand::CLI,
            brand::CLI
        );
    } else {
        println!("{}: {}", brand::CLI, what.join("  ·  "));
    }
}

/// One compact heartbeat line per successful report, so the daemon visibly ticks.
fn print_tick(metrics: &Option<Metrics>, processes: &[ProcessReport], checks: &[CheckReport]) {
    let m = metrics.as_ref();
    let mut parts = vec![format!(
        "cpu {:.0}% mem {:.0}% disk {:.0}%",
        m.map(|x| x.cpu_pct).unwrap_or(0.0),
        m.map(|x| x.mem_pct).unwrap_or(0.0),
        m.map(|x| x.disk_pct).unwrap_or(0.0),
    )];
    if !processes.is_empty() {
        let up = processes.iter().filter(|p| p.running).count();
        parts.push(format!("procs {up}/{} up", processes.len()));
    }
    if !checks.is_empty() {
        let ok = checks.iter().filter(|c| c.ok).count();
        parts.push(format!("checks {ok}/{} ok", checks.len()));
    }
    println!("{}: reported — {}", brand::CLI, parts.join("  ·  "));
}

pub fn cmd_watch(once: bool) -> i32 {
    let cfg = match Config::load_or_init() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}: {e}", brand::CLI);
            return 1;
        }
    };
    if cfg.token.is_none() {
        eprintln!(
            "{}: no agent token — run `{} login --token <token>` first",
            brand::CLI,
            brand::CLI
        );
        return 1;
    }
    let client = match Client::new(
        cfg.effective_base_url(),
        cfg.token.clone(),
        config::http_timeout(),
    ) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}: {e}", brand::CLI);
            return 1;
        }
    };
    let dir = match Config::dir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{}: {e}", brand::CLI);
            return 1;
        }
    };

    let mut collector = Collector::new(cfg.processes.clone());
    let mut pipeline = match Pipeline::new(pipeline_config_for(&cfg.log_sources)) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{}: {e}", brand::CLI);
            return 1;
        }
    };

    // Resume tailing positions from disk so a restart neither replays history nor
    // drops lines (state.rs).
    let mut state = LogState::load(&dir).unwrap_or_default();
    let (mut files, mut journals) = build_sources(&cfg.log_sources, &state);

    let interval = Duration::from_secs(cfg.watch_interval_secs.max(1));
    if !once {
        print_startup(&cfg, interval);
        // Only nudge an interactive foreground run — the background child and the
        // service journal shouldn't carry this tip.
        if std::io::stdout().is_terminal() {
            println!(
                "{}: tip — run detached with `{} watch --background`, or install a start-on-boot service with `{} service install`",
                brand::CLI,
                brand::CLI,
                brand::CLI
            );
        }
    }
    loop {
        tick(
            &mut collector,
            &mut pipeline,
            &mut files,
            &mut journals,
            &client,
            &cfg,
            &mut state,
            &dir,
        );
        if once {
            break;
        }
        std::thread::sleep(interval);
    }
    0
}

fn build_sources(sources: &[LogSourceConfig], state: &LogState) -> (Vec<FileSrc>, Vec<JournalSrc>) {
    let mut files = Vec::new();
    let mut journals = Vec::new();
    for source in sources {
        match source {
            LogSourceConfig::File(f) => {
                let key = f.path.to_string_lossy().to_string();
                // Resume from the persisted mark if we have one; else follow from EOF.
                let tailer = match state.files.get(&key) {
                    Some(mark) => FileTailer::resume(&f.path, mark.clone().into()),
                    None => FileTailer::following(&f.path),
                };
                files.push(FileSrc { key, tailer });
            }
            LogSourceConfig::Journald(j) => {
                let key = j.unit.clone().unwrap_or_else(|| "*".to_string());
                let reader = JournaldReader::new(j.unit.clone(), j.min_priority)
                    .with_cursor(state.journal_cursors.get(&key).cloned());
                journals.push(JournalSrc { key, reader });
            }
        }
    }
    (files, journals)
}

#[allow(clippy::too_many_arguments)]
fn tick(
    collector: &mut Collector,
    pipeline: &mut Pipeline,
    files: &mut [FileSrc],
    journals: &mut [JournalSrc],
    client: &Client,
    cfg: &Config,
    state: &mut LogState,
    dir: &std::path::Path,
) {
    // Each collector is isolated: a panic in one must not skip the others.
    let metrics = catch_unwind(AssertUnwindSafe(|| collector.metrics())).ok();
    let processes =
        catch_unwind(AssertUnwindSafe(|| collector.sample_processes())).unwrap_or_default();

    // Internal reachability checks → report `checks[]`, so a failing dependency
    // (a dead port, a stale pidfile) becomes the stated cause. Bounded + isolated.
    let checks = catch_unwind(AssertUnwindSafe(|| {
        check::run_configured(&cfg.checks, config::http_timeout())
    }))
    .unwrap_or_default();

    // Drain log sources into the pipeline, persisting resume positions.
    let _ = catch_unwind(AssertUnwindSafe(|| {
        for f in files.iter_mut() {
            for _ in 0..MAX_POLLS_PER_TICK {
                match f.tailer.poll() {
                    Ok(poll) if !poll.lines.is_empty() => {
                        for line in &poll.lines {
                            pipeline.push_line(line);
                        }
                    }
                    _ => break,
                }
            }
            pipeline.flush();
            if let Some(mark) = f.tailer.mark() {
                state.files.insert(f.key.clone(), mark.into());
            }
        }
        for j in journals.iter_mut() {
            if let Ok(entries) = j.reader.poll() {
                for e in &entries {
                    pipeline.push_journal(&e.message, e.priority);
                }
            }
            if let Some(cursor) = j.reader.cursor() {
                state
                    .journal_cursors
                    .insert(j.key.clone(), cursor.to_string());
            }
        }
    }));
    if let Err(e) = state.save(dir) {
        eprintln!("{}: could not persist log state: {e}", brand::CLI);
    }

    let drained = pipeline.drain();

    let report = ReportReq {
        host: cfg.host_id.clone(),
        reported_at: now_rfc3339(),
        metrics,
        processes,
        checks,
        error_signatures: drained.error_signatures.clone(),
        dropped_signatures: drained.dropped_signatures,
    };
    match client.report(&report) {
        // Periodic state — a lost report is recovered by the next tick.
        Err(e) => eprintln!("{}: report deferred: {e}", brand::CLI),
        // A concise heartbeat so `gpr watch` visibly shows it is alive and working
        // (and lands one line per tick in the service journal).
        Ok(()) => print_tick(&report.metrics, &report.processes, &report.checks),
    }

    // Flush context only when a new error surfaced this interval.
    if !drained.error_signatures.is_empty() {
        let lines = bounded_tail(pipeline.context_lines(), CONTEXT_MAX_BYTES);
        let ctx = ContextReq {
            incident_hint: cfg.host_id.clone(),
            lines,
        };
        if let Err(e) = client.context(&ctx) {
            eprintln!("{}: context deferred: {e}", brand::CLI);
        }
    }
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Keep the most recent lines whose total size fits the byte budget — the tail
/// around the error is what matters (§5.1).
fn bounded_tail(lines: Vec<String>, max_bytes: usize) -> Vec<String> {
    let mut kept: Vec<String> = Vec::new();
    let mut total = 0usize;
    for line in lines.into_iter().rev() {
        let cost = line.len() + 1; // +1 for the newline the server rejoins with
        if total + cost > max_bytes {
            break;
        }
        total += cost;
        kept.push(line);
    }
    kept.reverse();
    kept
}

// --- Background daemon: `gpr watch --background` / `--stop` ----------------------
//
// A lightweight, dependency-free backgrounder for a quick detached run — NOT a
// supervisor. For restart-on-crash and start-on-boot, `gpr service install` is the
// right tool. We avoid `unsafe` (§19) and a daemonize crate by re-exec'ing
// `gpr watch` as a child in its own process group, its stdio sent to a log file,
// and track it via a pidfile. Unix-only (like `gpr service`); other platforms get
// a pointer to the OS service manager.

/// Path of the background daemon's pidfile inside the config dir.
#[cfg(unix)]
fn pidfile_path(dir: &Path) -> PathBuf {
    dir.join("watch.pid")
}

/// Path of the background daemon's log file inside the config dir.
#[cfg(unix)]
fn logfile_path(dir: &Path) -> PathBuf {
    dir.join("watch.log")
}

/// Parse a pidfile's contents into a PID. Pure: trims and rejects non-numeric or
/// zero values so a truncated/garbage file never yields a bogus signal target.
#[cfg(unix)]
fn parse_pid(contents: &str) -> Option<u32> {
    match contents.trim().parse::<u32>() {
        Ok(pid) if pid > 0 => Some(pid),
        _ => None,
    }
}

/// True if `pid` is a live process. `kill -0` probes existence without delivering a
/// signal — portable across Linux and macOS with no signaling crate or `unsafe`.
#[cfg(unix)]
fn process_alive(pid: u32) -> bool {
    std::process::Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// The PID of a live background watcher from the pidfile, if one is running.
#[cfg(unix)]
fn running_pid(dir: &Path) -> Option<u32> {
    let contents = std::fs::read_to_string(pidfile_path(dir)).ok()?;
    let pid = parse_pid(&contents)?;
    process_alive(pid).then_some(pid)
}

/// `gpr watch --background` — start the daemon detached and return the shell.
#[cfg(unix)]
pub fn cmd_watch_background() -> i32 {
    use std::os::unix::process::CommandExt;
    // Fail fast on the same prerequisites the foreground daemon checks, so the user
    // sees the real error here instead of a "started" message for a child that dies
    // immediately into the log.
    match Config::load_or_init() {
        Ok(cfg) if cfg.token.is_none() => {
            eprintln!(
                "{}: no agent token — run `{} login --token <token>` first",
                brand::CLI,
                brand::CLI
            );
            return 1;
        }
        Ok(_) => {}
        Err(e) => {
            eprintln!("{}: {e}", brand::CLI);
            return 1;
        }
    }
    let dir = match Config::dir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{}: {e}", brand::CLI);
            return 1;
        }
    };
    if let Some(pid) = running_pid(&dir) {
        println!(
            "{}: already watching in the background (pid {pid}) — stop it with `{} watch --stop`",
            brand::CLI,
            brand::CLI
        );
        return 0;
    }
    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!("{}: could not create {}: {e}", brand::CLI, dir.display());
        return 1;
    }
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            eprintln!(
                "{}: could not locate the gpr binary to relaunch: {e}",
                brand::CLI
            );
            return 1;
        }
    };
    let log_path = logfile_path(&dir);
    let log = match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
    {
        Ok(f) => f,
        Err(e) => {
            eprintln!("{}: could not open {}: {e}", brand::CLI, log_path.display());
            return 1;
        }
    };
    let log_err = match log.try_clone() {
        Ok(f) => f,
        Err(e) => {
            eprintln!("{}: {e}", brand::CLI);
            return 1;
        }
    };
    // Re-exec the foreground daemon, detached into its own process group so it
    // outlives this shell, with stdio to the log file.
    let child = std::process::Command::new(&exe)
        .arg("watch")
        .stdin(std::process::Stdio::null())
        .stdout(log)
        .stderr(log_err)
        .process_group(0)
        .spawn();
    let child = match child {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}: could not start the background daemon: {e}", brand::CLI);
            return 1;
        }
    };
    let pid = child.id();
    if let Err(e) = std::fs::write(pidfile_path(&dir), pid.to_string()) {
        // Not fatal — it's running; the user can still stop it with `kill`.
        eprintln!(
            "{}: started (pid {pid}) but could not write the pidfile: {e}",
            brand::CLI
        );
    }
    println!(
        "{}: watching in the background (pid {pid}) · logs: {} · stop: `{} watch --stop`",
        brand::CLI,
        log_path.display(),
        brand::CLI
    );
    println!(
        "{}: for restart-on-crash and start-on-boot, install a service instead: `{} service install`",
        brand::CLI,
        brand::CLI
    );
    0
}

/// `gpr watch --stop` — stop a background watcher started with `--background`.
#[cfg(unix)]
pub fn cmd_watch_stop() -> i32 {
    let dir = match Config::dir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{}: {e}", brand::CLI);
            return 1;
        }
    };
    let pidfile = pidfile_path(&dir);
    let contents = match std::fs::read_to_string(&pidfile) {
        Ok(c) => c,
        Err(_) => {
            println!("{}: no background watcher is running", brand::CLI);
            return 0;
        }
    };
    let pid = match parse_pid(&contents) {
        Some(p) => p,
        None => {
            let _ = std::fs::remove_file(&pidfile);
            println!(
                "{}: no background watcher is running (removed a stale pidfile)",
                brand::CLI
            );
            return 0;
        }
    };
    if !process_alive(pid) {
        let _ = std::fs::remove_file(&pidfile);
        println!(
            "{}: not running (removed a stale pidfile for pid {pid})",
            brand::CLI
        );
        return 0;
    }
    let stopped = std::process::Command::new("kill")
        .arg(pid.to_string())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if stopped {
        let _ = std::fs::remove_file(&pidfile);
        println!("{}: stopped the background watcher (pid {pid})", brand::CLI);
        0
    } else {
        eprintln!(
            "{}: could not stop pid {pid} — stop it by hand with `kill {pid}`",
            brand::CLI
        );
        1
    }
}

#[cfg(not(unix))]
pub fn cmd_watch_background() -> i32 {
    eprintln!(
        "{}: --background isn't supported on this platform — install a service with `{} service install` or use Task Scheduler",
        brand::CLI,
        brand::CLI
    );
    1
}

#[cfg(not(unix))]
pub fn cmd_watch_stop() -> i32 {
    eprintln!("{}: --stop isn't supported on this platform", brand::CLI);
    1
}

#[cfg(all(test, unix))]
mod tests {
    use super::{logfile_path, parse_pid, pidfile_path};
    use std::path::Path;

    #[test]
    fn pidfile_and_logfile_live_in_the_config_dir() {
        let d = Path::new("/tmp/gpr-example");
        assert_eq!(pidfile_path(d), d.join("watch.pid"));
        assert_eq!(logfile_path(d), d.join("watch.log"));
    }

    #[test]
    fn parse_pid_accepts_a_clean_pid() {
        assert_eq!(parse_pid("12345"), Some(12345));
        assert_eq!(parse_pid("  678\n"), Some(678));
    }

    #[test]
    fn parse_pid_rejects_garbage_and_zero() {
        assert_eq!(parse_pid(""), None);
        assert_eq!(parse_pid("   "), None);
        assert_eq!(parse_pid("0"), None);
        assert_eq!(parse_pid("-1"), None);
        assert_eq!(parse_pid("nope"), None);
        assert_eq!(parse_pid("12x"), None);
    }
}
