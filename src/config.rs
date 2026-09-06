//! Agent configuration: a stable host UUID chosen once and reused, the agent
//! token, and an optional base-URL override. Persisted as JSON under
//! `~/.config/gpr` on Unix (XDG; Linux and macOS alike), or the platform
//! app-data dir on Windows. `GPR_CONFIG_DIR` overrides it.
//!
//! `host` on the wire is a persisted UUID, never the hostname — hostnames
//! collide.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::brand;

/// Env var overriding the config directory. Primarily for tests, but also lets
/// an operator relocate state.
pub const ENV_CONFIG_DIR: &str = "GPR_CONFIG_DIR";
/// Env var overriding the control-plane base URL (highest precedence).
pub const ENV_BASE_URL: &str = "GPR_BASE_URL";
/// Env var overriding the per-request HTTP timeout, in milliseconds.
pub const ENV_TIMEOUT_MS: &str = "GPR_HTTP_TIMEOUT_MS";

const CONFIG_FILE: &str = "config.json";
const BUFFER_FILE: &str = "buffer.jsonl";
const DEFAULT_TIMEOUT_MS: u64 = 8_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Stable host identifier, chosen once at first use and reused forever.
    pub host_id: String,
    /// Agent token for `/agent/*` requests. Absent until `gpr login`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// Per-install base-URL override. `GPR_BASE_URL` still wins over this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    /// Log sources tailed by `gpr watch` / inspected by `gpr logs --test`
    ///. Absent/empty means no log capture is configured.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub log_sources: Vec<crate::logs::LogSourceConfig>,
    /// Seconds between `gpr watch` report ticks. The server
    /// opens an incident after 2× this with no report, so keep it sane.
    #[serde(default = "default_watch_interval_secs")]
    pub watch_interval_secs: u64,
    /// Process specs `gpr watch` samples for liveness + restart detection. Empty
    /// means metrics-only. A bare string in the config is accepted as a name-only
    /// spec (backward compatible).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub processes: Vec<ProcessSpec>,
    /// Internal reachability checks `gpr watch` runs each tick, attached to the
    /// report's `checks[]` (protocol) so a failing dependency becomes the stated
    /// cause. Empty means no internal checks. Bounded by `MAX_CHECKS`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub checks: Vec<CheckSpec>,
}

/// Hard cap on scheduled checks per host — every buffer/loop is bounded (agent
/// rule 20). Extra entries past the cap are ignored with a warning.
pub const MAX_CHECKS: usize = 32;
/// Hard cap on watched processes, same rationale.
pub const MAX_PROCESSES: usize = 64;

/// A scheduled internal check. `kind` is `tcp` | `http` | `egress` | `pidfile`;
/// `target` is `host:port` (tcp), a URL (http/egress), or a pidfile path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckSpec {
    pub kind: String,
    pub target: String,
}

/// A watched process. `name` is the display label; `pattern`, when set, is matched
/// against the full command line (so `postgres` can be pinned to a path) instead
/// of the process name alone.
#[derive(Debug, Clone, Serialize)]
pub struct ProcessSpec {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
}

// Accept either a bare string (`"nginx"`) or an object (`{"name":…, "pattern":…}`)
// so existing configs keep working after the richer form was introduced.
impl<'de> Deserialize<'de> for ProcessSpec {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Name(String),
            Obj {
                name: String,
                #[serde(default)]
                pattern: Option<String>,
            },
        }
        Ok(match Raw::deserialize(d)? {
            Raw::Name(name) => ProcessSpec {
                name,
                pattern: None,
            },
            Raw::Obj { name, pattern } => ProcessSpec { name, pattern },
        })
    }
}

/// Default `gpr watch` interval. One minute is the common choice.
pub fn default_watch_interval_secs() -> u64 {
    60
}

impl Default for Config {
    fn default() -> Self {
        Self {
            host_id: uuid::Uuid::now_v7().to_string(),
            token: None,
            base_url: None,
            log_sources: Vec::new(),
            watch_interval_secs: default_watch_interval_secs(),
            processes: Vec::new(),
            checks: Vec::new(),
        }
    }
}

impl Config {
    /// The directory holding config + buffer state, honoring `GPR_CONFIG_DIR`.
    ///
    /// Unix (Linux + macOS) standardizes on the XDG path so it is predictable and
    /// identical on both: `$XDG_CONFIG_HOME/gpr`, else `~/.config/gpr`. Windows
    /// keeps the platform app-data dir.
    pub fn dir() -> Result<PathBuf> {
        if let Some(dir) = std::env::var_os(ENV_CONFIG_DIR) {
            return Ok(PathBuf::from(dir));
        }
        if cfg!(unix) {
            if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
                if !xdg.is_empty() {
                    return Ok(PathBuf::from(xdg).join(brand::CLI));
                }
            }
            let home = std::env::var_os("HOME")
                .context("could not determine HOME for the config directory")?;
            Ok(PathBuf::from(home).join(".config").join(brand::CLI))
        } else {
            let proj = directories::ProjectDirs::from("com", brand::NAME, brand::CLI)
                .context("could not determine a config directory for this platform")?;
            Ok(proj.config_dir().to_path_buf())
        }
    }

    /// Pre-0.1.1 path: macOS stored config under the app-specific dir. Returns it
    /// only when it differs from the current dir (so migration is a macOS no-op
    /// elsewhere), for a one-time move on upgrade.
    fn legacy_dir() -> Option<PathBuf> {
        let cur = Self::dir().ok()?;
        let proj = directories::ProjectDirs::from("com", brand::NAME, brand::CLI)?;
        let old = proj.config_dir().to_path_buf();
        if old == cur {
            None
        } else {
            Some(old)
        }
    }

    fn config_path() -> Result<PathBuf> {
        Ok(Self::dir()?.join(CONFIG_FILE))
    }

    /// Path to the offline buffer file.
    pub fn buffer_path() -> Result<PathBuf> {
        Ok(Self::dir()?.join(BUFFER_FILE))
    }

    /// Load config, creating (and persisting) a fresh one with a new host UUID
    /// if none exists yet.
    pub fn load_or_init() -> Result<Config> {
        let path = Self::config_path()?;
        // One-time migration from the pre-0.1.1 config location (macOS moved from
        // the app-specific dir to ~/.config/gpr). Best-effort: on any failure we
        // simply fall through to a fresh init.
        if !path.exists() {
            if let Some(old) = Self::legacy_dir().map(|d| d.join(CONFIG_FILE)) {
                if old.exists() {
                    if let Some(parent) = path.parent() {
                        let _ = fs::create_dir_all(parent);
                    }
                    let _ = fs::rename(&old, &path).or_else(|_| fs::copy(&old, &path).map(|_| ()));
                }
            }
        }
        match fs::read(&path) {
            Ok(bytes) => {
                let cfg: Config = serde_json::from_slice(&bytes)
                    .with_context(|| format!("parsing config at {}", path.display()))?;
                Ok(cfg)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let cfg = Config::default();
                cfg.save()?;
                Ok(cfg)
            }
            Err(e) => Err(e).with_context(|| format!("reading config at {}", path.display())),
        }
    }

    /// Persist config atomically-ish (write temp, rename).
    pub fn save(&self) -> Result<()> {
        let dir = Self::dir()?;
        fs::create_dir_all(&dir)
            .with_context(|| format!("creating config dir {}", dir.display()))?;
        let path = Self::config_path()?;
        let tmp = path.with_extension("json.tmp");
        let json = serde_json::to_vec_pretty(self).context("serializing config")?;
        fs::write(&tmp, &json).with_context(|| format!("writing {}", tmp.display()))?;
        fs::rename(&tmp, &path).with_context(|| format!("renaming into {}", path.display()))?;
        Ok(())
    }

    /// Effective base URL: `GPR_BASE_URL` > config `base_url` > brand default.
    pub fn effective_base_url(&self) -> String {
        if let Ok(url) = std::env::var(ENV_BASE_URL) {
            if !url.is_empty() {
                return url;
            }
        }
        self.base_url
            .clone()
            .unwrap_or_else(|| brand::BASE_URL.to_string())
    }
}

/// Per-request HTTP timeout, honoring `GPR_HTTP_TIMEOUT_MS` (tests set this low
/// so reporting to an unreachable host never blocks a run for long).
pub fn http_timeout() -> Duration {
    let ms = std::env::var(ENV_TIMEOUT_MS)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_TIMEOUT_MS);
    Duration::from_millis(ms)
}

/// True if `path` is readable by the current process (best-effort probe used by
/// `gpr doctor`).
pub fn is_readable(path: &Path) -> bool {
    fs::File::open(path).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_spec_accepts_bare_string_and_object() {
        // Backward compat: a config written before the richer form must still load.
        let bare: ProcessSpec = serde_json::from_str("\"nginx\"").unwrap();
        assert_eq!(bare.name, "nginx");
        assert!(bare.pattern.is_none());

        let obj: ProcessSpec =
            serde_json::from_str(r#"{"name":"postgres","pattern":"/usr/lib/postgresql"}"#).unwrap();
        assert_eq!(obj.name, "postgres");
        assert_eq!(obj.pattern.as_deref(), Some("/usr/lib/postgresql"));
    }

    #[test]
    fn config_with_mixed_process_forms_round_trips() {
        let json = r#"{
            "host_id": "h",
            "processes": ["nginx", {"name":"pg","pattern":"postgres"}],
            "checks": [{"kind":"tcp","target":"localhost:5432"}]
        }"#;
        let cfg: Config = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.processes.len(), 2);
        assert_eq!(cfg.processes[0].name, "nginx");
        assert_eq!(cfg.processes[1].pattern.as_deref(), Some("postgres"));
        assert_eq!(cfg.checks.len(), 1);
        assert_eq!(cfg.checks[0].kind, "tcp");
    }
}
