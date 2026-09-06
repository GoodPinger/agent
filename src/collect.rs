//! Host metrics + process sampling for `gpr watch`. Metrics are commodity — the product is the *diagnosis* — so
//! this module stays deliberately small: enough signal to correlate an outage
//! with a cause, nothing more.
//!
//! Two pieces:
//!   - [`RestartTracker`] — a PURE, clock-injected detector of process restarts
//!     within a 5-minute rolling window. Pure so it is exhaustively testable
//!     without spawning processes. The 5-minute window is a wire
//!     contract: the server assumes exactly this window when reading `restarts`.
//!   - [`Collector`] — wraps `sysinfo`, produces the `metrics` and `processes`
//!     blocks each tick, and owns one `RestartTracker`.
//!
//! Everything is bounded: the restart-event history per process is capped on both
//! time (the window) and count, so a pathologically flapping process can never
//! grow memory without limit.

use std::collections::{HashMap, VecDeque};
use std::time::Instant;

use sysinfo::{Disks, ProcessesToUpdate, System};

use crate::config::ProcessSpec;
use crate::transport::{Metrics, ProcessReport};

/// One process row for the interactive watch manager (`gpr watch edit`). A plain
/// data DTO so the pure state machine can be tested without `sysinfo`.
#[derive(Debug, Clone)]
pub struct ProcInfo {
    pub pid: u32,
    pub name: String,
    pub cmdline: String,
    pub cpu_pct: f32,
    pub mem_pct: f32,
}

/// Snapshot every running process, sorted by memory usage descending. CPU% needs
/// two samples an interval apart, so we refresh, sleep the minimum CPU interval,
/// and refresh again — acceptable for an interactive, on-demand snapshot.
pub fn snapshot_all() -> Vec<ProcInfo> {
    let mut sys = System::new();
    sys.refresh_memory(); // total_memory() is 0 until memory is refreshed
    sys.refresh_processes(ProcessesToUpdate::All, true);
    std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
    sys.refresh_processes(ProcessesToUpdate::All, true);

    let total_mem = sys.total_memory().max(1);
    let mut out: Vec<ProcInfo> = sys
        .processes()
        .iter()
        .map(|(pid, p)| {
            let cmdline = p
                .cmd()
                .iter()
                .map(|s| s.to_string_lossy())
                .collect::<Vec<_>>()
                .join(" ");
            ProcInfo {
                pid: pid.as_u32(),
                name: p.name().to_string_lossy().to_string(),
                cmdline,
                cpu_pct: p.cpu_usage(),
                mem_pct: (p.memory() as f64 / total_mem as f64 * 100.0) as f32,
            }
        })
        .collect();
    out.sort_by(|a, b| {
        b.mem_pct
            .partial_cmp(&a.mem_pct)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    out
}

/// The restart-counting window. **Must match the server's assumption** — do not
/// change without a protocol conversation.
pub const RESTART_WINDOW_MS: u64 = 5 * 60 * 1000;
/// Hard cap on restart events retained per process (belt-and-braces on top of the
/// time window, so a flapping process cannot grow memory unbounded).
pub const MAX_RESTART_EVENTS: usize = 256;

/// Tracks the last-seen PID per process name and the timestamps of observed PID
/// changes, so `restarts` reports how many restarts happened in the last window.
///
/// A restart is counted only when a process is present in two consecutive
/// observations with a *different* PID. When a process is absent, its last PID is forgotten, so a later
/// reappearance is not miscounted as a restart across the gap.
pub struct RestartTracker {
    window_ms: u64,
    max_events: usize,
    last_pid: HashMap<String, u32>,
    events: HashMap<String, VecDeque<u64>>,
}

impl Default for RestartTracker {
    fn default() -> Self {
        Self::new(RESTART_WINDOW_MS, MAX_RESTART_EVENTS)
    }
}

impl RestartTracker {
    pub fn new(window_ms: u64, max_events: usize) -> Self {
        Self {
            window_ms,
            max_events: max_events.max(1),
            last_pid: HashMap::new(),
            events: HashMap::new(),
        }
    }

    /// Observe one sample for `name` at `now_ms` (a monotonic millisecond clock)
    /// and return the number of restarts within the window. `pid` is `None` when
    /// the process is not running this tick.
    pub fn observe(&mut self, name: &str, pid: Option<u32>, now_ms: u64) -> u32 {
        match pid {
            Some(current) => {
                if let Some(&prev) = self.last_pid.get(name) {
                    if prev != current {
                        self.push_event(name, now_ms);
                    }
                }
                self.last_pid.insert(name.to_string(), current);
            }
            None => {
                // Absent: forget the last PID so a reappearance is not counted as
                // a restart across the gap ("both present" rule).
                self.last_pid.remove(name);
            }
        }
        self.restarts_in_window(name, now_ms)
    }

    fn push_event(&mut self, name: &str, now_ms: u64) {
        let dq = self.events.entry(name.to_string()).or_default();
        dq.push_back(now_ms);
        // Count bound (time pruning happens in `restarts_in_window`).
        while dq.len() > self.max_events {
            dq.pop_front();
        }
    }

    fn restarts_in_window(&mut self, name: &str, now_ms: u64) -> u32 {
        let cutoff = now_ms.saturating_sub(self.window_ms);
        let Some(dq) = self.events.get_mut(name) else {
            return 0;
        };
        while let Some(&front) = dq.front() {
            if front < cutoff {
                dq.pop_front();
            } else {
                break;
            }
        }
        dq.len() as u32
    }
}

/// Wraps `sysinfo` and produces the `/agent/report` metrics + process blocks.
/// One instance is reused across ticks so CPU deltas and restart windows are
/// meaningful.
pub struct Collector {
    sys: System,
    tracker: RestartTracker,
    /// Process specs to sample, from config (`processes`).
    processes: Vec<ProcessSpec>,
    /// Monotonic origin for the restart tracker's millisecond clock.
    origin: Instant,
}

impl Collector {
    pub fn new(processes: Vec<ProcessSpec>) -> Self {
        Self {
            sys: System::new(),
            tracker: RestartTracker::default(),
            processes,
            origin: Instant::now(),
        }
    }

    fn now_ms(&self) -> u64 {
        self.origin.elapsed().as_millis() as u64
    }

    /// Collect host metrics. All fractions are 0–100 (protocol.md). `load1` is 0
    /// where the platform has no load average (e.g. Windows), as the task
    /// requires.
    pub fn metrics(&mut self) -> Metrics {
        self.sys.refresh_cpu_usage();
        self.sys.refresh_memory();

        // CPU: global usage is already a 0–100 percentage. The very first reading
        // after construction can be 0 (sysinfo needs an interval between refreshes
        // to compute a delta); over `gpr watch`'s tick cadence it is accurate.
        let cpu_pct = clamp_pct(self.sys.global_cpu_usage() as f64);

        let total_mem = self.sys.total_memory();
        let mem_pct = if total_mem > 0 {
            clamp_pct(self.sys.used_memory() as f64 / total_mem as f64 * 100.0)
        } else {
            0.0
        };

        Metrics {
            cpu_pct,
            mem_pct,
            disk_pct: disk_pct(),
            load1: load1(),
            uptime_s: System::uptime(),
        }
    }

    /// Sample each configured process: resolve its PID + running state, and fold
    /// the restart count from the tracker.
    pub fn sample_processes(&mut self) -> Vec<ProcessReport> {
        self.sys.refresh_processes(ProcessesToUpdate::All, true);
        let now_ms = self.now_ms();

        // Snapshot the specs so we do not hold a borrow of `self.sys` across the
        // mutable `tracker.observe` call.
        let mut out = Vec::with_capacity(self.processes.len());
        let specs = self.processes.clone();
        for spec in &specs {
            let pid = self.find_pid(spec);
            // Track restarts keyed by the display name (stable, unique per spec).
            let restarts = self.tracker.observe(&spec.name, pid, now_ms);
            out.push(ProcessReport {
                name: spec.name.clone(),
                matcher: spec.pattern.clone().unwrap_or_else(|| spec.name.clone()),
                pid,
                running: pid.is_some(),
                restarts,
            });
        }
        out
    }

    /// Find the PID of the running process matching `spec`. With a `pattern`, match
    /// against the full command line (so a service can be pinned to its binary
    /// path, disambiguating `postgres` from a shell mentioning it). Otherwise match
    /// the process name: exact first, then substring (Linux truncates `comm` to 15
    /// chars, so substring catches long names). Returns the lowest matching PID for
    /// stability across ticks.
    fn find_pid(&self, spec: &ProcessSpec) -> Option<u32> {
        let mut best: Option<u32> = None;
        for (pid, proc_) in self.sys.processes() {
            let matched = match &spec.pattern {
                Some(pat) => {
                    let cmdline = proc_
                        .cmd()
                        .iter()
                        .map(|s| s.to_string_lossy())
                        .collect::<Vec<_>>()
                        .join(" ");
                    cmdline.contains(pat.as_str())
                }
                None => {
                    let pname = proc_.name().to_string_lossy();
                    pname == spec.name || pname.contains(spec.name.as_str())
                }
            };
            if matched {
                let p = pid.as_u32();
                best = Some(best.map_or(p, |b| b.min(p)));
            }
        }
        best
    }
}

fn clamp_pct(v: f64) -> f64 {
    if v.is_nan() {
        0.0
    } else {
        v.clamp(0.0, 100.0)
    }
}

/// Disk usage of the root/most-used filesystem, as a 0–100 percentage. Picks the
/// `/` mount if present, otherwise the fullest disk — the one most likely to
/// cause an incident.
fn disk_pct() -> f64 {
    let disks = Disks::new_with_refreshed_list();
    let mut root_pct: Option<f64> = None;
    let mut max_pct: f64 = 0.0;
    for disk in &disks {
        let total = disk.total_space();
        if total == 0 {
            continue;
        }
        let used = total.saturating_sub(disk.available_space());
        let pct = clamp_pct(used as f64 / total as f64 * 100.0);
        if disk.mount_point() == std::path::Path::new("/") {
            root_pct = Some(pct);
        }
        if pct > max_pct {
            max_pct = pct;
        }
    }
    root_pct.unwrap_or(max_pct)
}

/// 1-minute load average, or 0 where the platform provides none (Windows).
fn load1() -> f64 {
    let avg = System::load_average();
    if avg.one.is_nan() {
        0.0
    } else {
        avg.one
    }
}

/// Best-effort resident set size of THIS process, in bytes. Used by CI to prove
/// the agent stays under its RSS ceiling.
///
/// On Linux this reads `/proc/self/statm` directly (cheap, no full process table
/// scan). The resident field is in pages; we assume the standard 4 KiB page size,
/// which holds on the shipped x86_64/aarch64 musl targets. On other platforms it
/// returns `None` (the ceiling is asserted where it maps to a release target).
pub fn current_rss_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        const PAGE_SIZE: u64 = 4096;
        let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
        // Fields: size resident shared text lib data dt — we want `resident`.
        let resident_pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
        Some(resident_pages * PAGE_SIZE)
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A name-only process spec (no cmdline pattern) — the common test shape.
    fn name_spec(name: &str) -> ProcessSpec {
        ProcessSpec {
            name: name.to_string(),
            pattern: None,
        }
    }

    #[test]
    fn snapshot_all_is_non_panicking_and_in_range() {
        let procs = snapshot_all();
        // This test process must appear in the snapshot.
        assert!(!procs.is_empty(), "expected at least this process");
        for p in &procs {
            assert!(
                (0.0..=100.0).contains(&p.mem_pct),
                "mem {} out of range",
                p.mem_pct
            );
        }
        // Sorted by memory descending.
        for w in procs.windows(2) {
            assert!(w[0].mem_pct >= w[1].mem_pct, "not sorted by mem desc");
        }
    }

    #[test]
    fn same_pid_across_ticks_is_zero_restarts() {
        let mut t = RestartTracker::new(RESTART_WINDOW_MS, MAX_RESTART_EVENTS);
        assert_eq!(t.observe("app", Some(100), 0), 0);
        assert_eq!(t.observe("app", Some(100), 1_000), 0);
        assert_eq!(t.observe("app", Some(100), 2_000), 0);
    }

    #[test]
    fn changed_pid_counts_one_restart() {
        let mut t = RestartTracker::new(RESTART_WINDOW_MS, MAX_RESTART_EVENTS);
        assert_eq!(t.observe("app", Some(100), 0), 0);
        assert_eq!(t.observe("app", Some(200), 1_000), 1);
    }

    #[test]
    fn multiple_changes_within_window_are_counted() {
        let mut t = RestartTracker::new(RESTART_WINDOW_MS, MAX_RESTART_EVENTS);
        assert_eq!(t.observe("app", Some(1), 0), 0);
        assert_eq!(t.observe("app", Some(2), 10_000), 1);
        assert_eq!(t.observe("app", Some(3), 20_000), 2);
        assert_eq!(t.observe("app", Some(4), 30_000), 3);
    }

    #[test]
    fn events_outside_the_window_drop_off() {
        let mut t = RestartTracker::new(RESTART_WINDOW_MS, MAX_RESTART_EVENTS);
        // A restart at t=0 …
        t.observe("app", Some(1), 0);
        assert_eq!(t.observe("app", Some(2), 1_000), 1);
        // … is still counted just inside the window …
        assert_eq!(
            t.observe("app", Some(2), RESTART_WINDOW_MS),
            1,
            "event at 1_000ms is still within [now-window, now]"
        );
        // … but drops off once `now - window` passes it.
        assert_eq!(
            t.observe("app", Some(2), RESTART_WINDOW_MS + 2_000),
            0,
            "event at 1_000ms is now older than the window"
        );
    }

    #[test]
    fn absence_then_reappearance_is_not_a_restart() {
        let mut t = RestartTracker::new(RESTART_WINDOW_MS, MAX_RESTART_EVENTS);
        assert_eq!(t.observe("app", Some(100), 0), 0);
        // Process gone this tick.
        assert_eq!(t.observe("app", None, 1_000), 0);
        // Back with a different PID — not counted (not "both present").
        assert_eq!(t.observe("app", Some(200), 2_000), 0);
    }

    #[test]
    fn restart_history_is_bounded_by_count() {
        let mut t = RestartTracker::new(u64::MAX, 4);
        // Force many restarts; a huge window means none time out, so the count cap
        // is what keeps memory bounded.
        let mut last = 0u32;
        for i in 0..1000u32 {
            last = t.observe("flap", Some(i + 1), i as u64);
        }
        assert!(
            last <= 4,
            "restart history capped at max_events, got {last}"
        );
    }

    #[test]
    fn metrics_are_non_panicking_and_in_range() {
        let mut c = Collector::new(vec![]);
        let m = c.metrics();
        assert!((0.0..=100.0).contains(&m.cpu_pct), "cpu {}", m.cpu_pct);
        assert!((0.0..=100.0).contains(&m.mem_pct), "mem {}", m.mem_pct);
        assert!((0.0..=100.0).contains(&m.disk_pct), "disk {}", m.disk_pct);
        assert!(m.load1 >= 0.0, "load1 {}", m.load1);
    }

    #[test]
    fn sample_processes_reports_configured_names() {
        // Sample this very test process by a name that will not match, so we get a
        // deterministic not-running result without depending on the host.
        let mut c = Collector::new(vec![name_spec("definitely-not-a-real-process-xyz")]);
        let procs = c.sample_processes();
        assert_eq!(procs.len(), 1);
        assert_eq!(procs[0].name, "definitely-not-a-real-process-xyz");
        assert_eq!(procs[0].matcher, "definitely-not-a-real-process-xyz");
        assert!(!procs[0].running);
        assert!(procs[0].pid.is_none());
        assert_eq!(procs[0].restarts, 0);
    }

    #[test]
    fn rss_helper_after_collect_is_under_ceiling() {
        // Exercise the collectors once, then measure.
        let mut c = Collector::new(vec![name_spec("init")]);
        let _ = c.metrics();
        let _ = c.sample_processes();

        match current_rss_bytes() {
            Some(rss) => {
                eprintln!(
                    "RSS after collect: {} bytes ({:.1} MB)",
                    rss,
                    rss as f64 / 1e6
                );
                // The 20 MB ceiling is a claim about the shipped
                // Linux release binary; assert it where the helper maps to that
                // target. A debug test binary elsewhere is not comparable.
                #[cfg(target_os = "linux")]
                assert!(
                    rss < 20 * 1024 * 1024,
                    "RSS {} bytes exceeds the 20 MB ceiling",
                    rss
                );
            }
            None => {
                eprintln!(
                    "current_rss_bytes() is Linux-only; RSS ceiling asserted there"
                );
            }
        }
    }
}
