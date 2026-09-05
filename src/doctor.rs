//! `gpr doctor` — diagnose the common things that stop the agent working:
//! clock skew, reachability/firewall, config + token presence, and (best
//! effort) log-read permissions. Prints a pass/fail line per check with the
//! exact fix on failure. Exits non-zero if any CRITICAL check fails
//!.

use crate::brand;
use crate::config::{self, Config};
use crate::transport::Client;

/// Clock skew beyond this is flagged (seconds).
const SKEW_WARN_SECS: i64 = 5;

#[derive(Clone, Copy, PartialEq)]
enum Level {
    Pass,
    Warn,
    Fail,
}

struct Check {
    level: Level,
    /// True if a failure here should make the whole command exit non-zero.
    critical: bool,
    title: String,
    detail: String,
    /// Exact remediation shown on warn/fail.
    fix: Option<String>,
}

impl Check {
    fn pass(title: &str, detail: impl Into<String>) -> Self {
        Self {
            level: Level::Pass,
            critical: false,
            title: title.into(),
            detail: detail.into(),
            fix: None,
        }
    }
    fn warn(title: &str, detail: impl Into<String>, fix: impl Into<String>) -> Self {
        Self {
            level: Level::Warn,
            critical: false,
            title: title.into(),
            detail: detail.into(),
            fix: Some(fix.into()),
        }
    }
    fn fail(title: &str, detail: impl Into<String>, fix: impl Into<String>) -> Self {
        Self {
            level: Level::Fail,
            critical: true,
            title: title.into(),
            detail: detail.into(),
            fix: Some(fix.into()),
        }
    }
    fn print(&self) {
        let mark = match self.level {
            Level::Pass => "ok  ",
            Level::Warn => "warn",
            Level::Fail => "FAIL",
        };
        println!("[{mark}] {}: {}", self.title, self.detail);
        if self.level != Level::Pass {
            if let Some(fix) = &self.fix {
                println!("       fix: {fix}");
            }
        }
    }
}

pub fn cmd_doctor() -> i32 {
    let mut checks: Vec<Check> = Vec::new();

    // 1. Config + token.
    let cfg = Config::load_or_init();
    let cfg = match cfg {
        Ok(c) => {
            checks.push(Check::pass(
                "config",
                format!("host id {} loaded", c.host_id),
            ));
            if c.token.is_some() {
                checks.push(Check::pass("token", "agent token present"));
            } else {
                checks.push(Check::warn(
                    "token",
                    "no agent token (heartbeats work; /agent/* will not)",
                    format!("{} login --token <token>", brand::CLI),
                ));
            }
            Some(c)
        }
        Err(e) => {
            checks.push(Check::fail(
                "config",
                format!("could not load config: {e}"),
                "check permissions on the config directory (see GPR_CONFIG_DIR)",
            ));
            None
        }
    };

    // 2. Reachability + 3. clock skew (one probe answers both).
    let base_url = cfg
        .as_ref()
        .map(|c| c.effective_base_url())
        .unwrap_or_else(|| brand::BASE_URL.to_string());

    match Client::new(&base_url, None, config::http_timeout()) {
        Ok(client) => match client.probe() {
            Ok(probe) => {
                checks.push(Check::pass(
                    "reachability",
                    format!("{base_url} responded HTTP {}", probe.status.as_u16()),
                ));
                match probe.server_date {
                    Some(server) => {
                        let skew = (chrono::Utc::now() - server).num_seconds();
                        if skew.abs() > SKEW_WARN_SECS {
                            checks.push(Check::warn(
                                "clock",
                                format!("local clock is {skew}s from server"),
                                "sync time (e.g. `sudo timedatectl set-ntp true` or `sudo ntpdate -u pool.ntp.org`)",
                            ));
                        } else {
                            checks.push(Check::pass("clock", format!("within {skew}s of server")));
                        }
                    }
                    None => checks.push(Check::warn(
                        "clock",
                        "server sent no Date header; skew not checked",
                        "no action needed unless alerts look time-shifted",
                    )),
                }
            }
            Err(e) => checks.push(Check::fail(
                "reachability",
                format!("cannot reach {base_url}: {e}"),
                "check DNS, outbound HTTPS (443), and any egress firewall/proxy",
            )),
        },
        Err(e) => checks.push(Check::fail(
            "reachability",
            format!("could not build HTTP client: {e}"),
            "report this as a bug",
        )),
    }

    // 4. Log-read permissions (best-effort, most relevant on Linux).
    checks.push(log_permission_check());

    // Render.
    println!("{} doctor", brand::CLI);
    let mut any_critical_fail = false;
    for c in &checks {
        c.print();
        if c.critical && c.level == Level::Fail {
            any_critical_fail = true;
        }
    }

    if any_critical_fail {
        println!("\none or more critical checks failed");
        1
    } else {
        println!("\nall critical checks passed");
        0
    }
}

/// Probe a few well-known log locations. This is advisory: on failure we print
/// the exact `usermod` fix but never fail the command over it,
/// since `gpr run` needs no log permissions at all.
fn log_permission_check() -> Check {
    #[cfg(target_os = "linux")]
    let candidates: &[&str] = &[
        "/var/log/syslog",
        "/var/log/messages",
        "/run/log/journal",
        "/var/log/journal",
    ];
    #[cfg(not(target_os = "linux"))]
    let candidates: &[&str] = &["/var/log"];

    let mut found_any = false;
    let mut readable_any = false;
    for path in candidates {
        let p = std::path::Path::new(path);
        if p.exists() {
            found_any = true;
            if config::is_readable(p) {
                readable_any = true;
                break;
            }
        }
    }

    if !found_any {
        Check::warn(
            "log access",
            "no standard system log path found (fine if you only use `gpr run`)",
            "point log_source at your app's log file in config",
        )
    } else if readable_any {
        Check::pass("log access", "can read a system log source")
    } else {
        Check::warn(
            "log access",
            "system logs exist but are not readable by this user",
            "sudo usermod -aG adm,systemd-journal $USER   (then log out and back in)",
        )
    }
}
