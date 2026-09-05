//! HTTP transport to the control plane. A `reqwest` blocking client (rustls),
//! request types matching the wire protocol exactly, protocol header + UA on
//! every request, bearer auth on `/agent/*` only, bounded-backoff retry.

use std::thread::sleep;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use serde::Serialize;

use crate::brand;
use crate::PROTOCOL_VERSION;

/// Header carried by every request.
pub const PROTOCOL_HEADER: &str = "X-Gpr-Protocol";

const MAX_ATTEMPTS: u32 = 3;
const BACKOFF_BASE_MS: u64 = 100;

// ---- Request bodies — shapes are the wire contract; do not reorder meaning. ----

/// `POST /p/{slug}/start`
#[derive(Debug, Clone, Serialize)]
pub struct StartReq {
    pub run_id: String,
    pub host: String,
    pub started_at: String,
}

/// `POST /p/{slug}/finish`
#[derive(Debug, Clone, Serialize)]
pub struct FinishReq {
    pub run_id: String,
    pub exit_code: i32,
    pub duration_ms: u64,
    pub output_tail: String,
}

/// `POST /agent/hello`
#[derive(Debug, Clone, Serialize)]
pub struct HelloReq {
    pub host: String,
    pub agent_version: String,
    pub protocol_version: u8,
    pub os: String,
    pub arch: String,
}

impl HelloReq {
    /// Build a hello for this host from the running platform.
    pub fn for_host(host: String) -> Self {
        Self {
            host,
            agent_version: brand::VERSION.to_string(),
            protocol_version: PROTOCOL_VERSION,
            os: normalize_os(std::env::consts::OS),
            arch: std::env::consts::ARCH.to_string(),
        }
    }
}

fn normalize_os(os: &str) -> String {
    // Wire allows linux|macos|windows; std uses "macos" already.
    match os {
        "macos" => "macos",
        "windows" => "windows",
        "linux" => "linux",
        other => other,
    }
    .to_string()
}

/// Host metrics block of `/agent/report`. Fractions are
/// 0–100, matching the wire; `load1` is 0 where the platform has no load average.
#[derive(Debug, Clone, Serialize)]
pub struct Metrics {
    pub cpu_pct: f64,
    pub mem_pct: f64,
    pub disk_pct: f64,
    pub load1: f64,
    pub uptime_s: u64,
}

/// One entry of `/agent/report`'s `processes[]`. `restarts`
/// counts PID changes observed in a 5-minute rolling window — the server assumes
/// exactly that window, so it must not drift.
#[derive(Debug, Clone, Serialize)]
pub struct ProcessReport {
    pub name: String,
    /// The configured match string. Serialized as `match` on the wire; `match`
    /// is a Rust keyword, hence the rename.
    #[serde(rename = "match")]
    pub matcher: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    pub running: bool,
    pub restarts: u32,
}

/// One entry of `/agent/report`'s `checks[]`.
#[derive(Debug, Clone, Serialize)]
pub struct CheckReport {
    /// `tcp` | `http` | `egress`.
    pub kind: String,
    pub target: String,
    pub ok: bool,
    pub ms: u64,
}

/// `POST /agent/report` — the periodic inside-out report. Every collection is
/// optional and additive: an empty block is simply omitted,
/// so an M1 agent may send only `host` + `reported_at`.
#[derive(Debug, Clone, Serialize)]
pub struct ReportReq {
    pub host: String,
    pub reported_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics: Option<Metrics>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub processes: Vec<ProcessReport>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub checks: Vec<CheckReport>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub error_signatures: Vec<crate::logs::ErrorSignature>,
    pub dropped_signatures: u64,
}

/// `POST /agent/context` — the ±N lines around an incident, sent ONLY when a new
/// error appears (never streamed). Bounded to ≤32 KB by the caller.
#[derive(Debug, Clone, Serialize)]
pub struct ContextReq {
    pub incident_hint: String,
    pub lines: Vec<String>,
}

/// A single reachability probe result (used by `gpr doctor`).
pub struct Probe {
    pub status: reqwest::StatusCode,
    /// The server's `Date` header, if present, parsed to a UTC instant.
    pub server_date: Option<chrono::DateTime<chrono::Utc>>,
}

pub struct Client {
    http: reqwest::blocking::Client,
    base_url: String,
    token: Option<String>,
}

impl Client {
    pub fn new(
        base_url: impl Into<String>,
        token: Option<String>,
        timeout: Duration,
    ) -> Result<Self> {
        let http = reqwest::blocking::Client::builder()
            .user_agent(brand::user_agent())
            .connect_timeout(timeout)
            .timeout(timeout)
            .build()
            .context("building HTTP client")?;
        let base_url = base_url.into().trim_end_matches('/').to_string();
        Ok(Self {
            http,
            base_url,
            token,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// Common headers every request carries.
    fn base_headers(
        &self,
        rb: reqwest::blocking::RequestBuilder,
    ) -> reqwest::blocking::RequestBuilder {
        rb.header(PROTOCOL_HEADER, PROTOCOL_VERSION.to_string())
    }

    /// Add bearer auth for `/agent/*` endpoints only.
    fn with_auth(
        &self,
        rb: reqwest::blocking::RequestBuilder,
    ) -> Result<reqwest::blocking::RequestBuilder> {
        match &self.token {
            Some(t) => Ok(rb.bearer_auth(t)),
            None => Err(anyhow!(
                "no agent token configured — run `{} login` first",
                brand::CLI
            )),
        }
    }

    /// Send with bounded exponential backoff. Retries on transport errors and
    /// 5xx; returns the response otherwise (including 4xx, which is terminal).
    fn send_retry(
        &self,
        build: impl Fn() -> reqwest::blocking::RequestBuilder,
    ) -> Result<reqwest::blocking::Response> {
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            match build().send() {
                Ok(resp) => {
                    if resp.status().is_server_error() && attempt < MAX_ATTEMPTS {
                        sleep(backoff(attempt));
                        continue;
                    }
                    return Ok(resp);
                }
                Err(e) => {
                    if attempt < MAX_ATTEMPTS {
                        sleep(backoff(attempt));
                        continue;
                    }
                    return Err(e).context("request failed after retries");
                }
            }
        }
    }

    /// `GET /p/{slug}` — bare heartbeat. Unauthenticated by slug design.
    pub fn ping(&self, slug: &str) -> Result<()> {
        let url = self.url(&format!("/p/{slug}"));
        let resp = self.send_retry(|| self.base_headers(self.http.get(&url)))?;
        ensure_2xx(resp, "heartbeat")
    }

    /// `POST /p/{slug}/start`
    pub fn start(&self, slug: &str, body: &StartReq) -> Result<()> {
        let url = self.url(&format!("/p/{slug}/start"));
        let resp = self.send_retry(|| self.base_headers(self.http.post(&url).json(body)))?;
        ensure_2xx(resp, "run start")
    }

    /// `POST /p/{slug}/finish`
    pub fn finish(&self, slug: &str, body: &FinishReq) -> Result<()> {
        let url = self.url(&format!("/p/{slug}/finish"));
        let resp = self.send_retry(|| self.base_headers(self.http.post(&url).json(body)))?;
        ensure_2xx(resp, "run finish")
    }

    /// `POST /agent/hello` (authenticated).
    pub fn hello(&self, body: &HelloReq) -> Result<()> {
        // Fail closed with a precise message before touching the network.
        if self.token.is_none() {
            return Err(anyhow!(
                "no agent token configured — run `{} login` first",
                brand::CLI
            ));
        }
        let url = self.url("/agent/hello");
        let resp = self.send_retry(|| {
            // Auth is guaranteed present by the check above; `with_auth` cannot
            // fail here.
            self.with_auth(self.base_headers(self.http.post(&url).json(body)))
                .expect("token presence checked above")
        })?;
        ensure_2xx(resp, "hello")
    }

    /// `POST /agent/report` (authenticated). Periodic inside-out report.
    pub fn report(&self, body: &ReportReq) -> Result<()> {
        self.post_agent("/agent/report", body, "report")
    }

    /// `POST /agent/context` (authenticated). Incident context blob, sent only
    /// when a new error appears — never streamed.
    pub fn context(&self, body: &ContextReq) -> Result<()> {
        self.post_agent("/agent/context", body, "context")
    }

    /// Shared body for authenticated `/agent/*` POSTs: fail closed with a precise
    /// message before touching the network, then send with the usual retry.
    fn post_agent<T: Serialize>(&self, path: &str, body: &T, what: &str) -> Result<()> {
        if self.token.is_none() {
            return Err(anyhow!(
                "no agent token configured — run `{} login` first",
                brand::CLI
            ));
        }
        let url = self.url(path);
        let resp = self.send_retry(|| {
            // Auth is guaranteed present by the check above; `with_auth` cannot
            // fail here.
            self.with_auth(self.base_headers(self.http.post(&url).json(body)))
                .expect("token presence checked above")
        })?;
        ensure_2xx(resp, what)
    }

    /// A lightweight reachability probe for `gpr doctor`: GET the base URL and
    /// report status + server Date. Any HTTP response counts as reachable.
    pub fn probe(&self) -> Result<Probe> {
        let url = self.url("/");
        let resp = self
            .base_headers(self.http.get(&url))
            .send()
            .context("connecting to control plane")?;
        let server_date = resp
            .headers()
            .get(reqwest::header::DATE)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| chrono::DateTime::parse_from_rfc2822(s).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc));
        Ok(Probe {
            status: resp.status(),
            server_date,
        })
    }
}

fn ensure_2xx(resp: reqwest::blocking::Response, what: &str) -> Result<()> {
    let status = resp.status();
    if status.is_success() {
        Ok(())
    } else {
        Err(anyhow!("{what} rejected with HTTP {status}"))
    }
}

fn backoff(attempt: u32) -> Duration {
    // attempt 1 -> base, 2 -> 2x, capped implicitly by MAX_ATTEMPTS.
    let mult = 1u64 << (attempt.saturating_sub(1).min(6));
    Duration::from_millis(BACKOFF_BASE_MS * mult)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logs::ErrorSignature;
    use serde_json::Value;

    /// A fully-populated report must serialize to the exact shape in
    /// the wire protocol `POST /agent/report`.
    #[test]
    fn report_body_matches_protocol_shape() {
        let req = ReportReq {
            host: "host-uuid".into(),
            reported_at: "2026-08-25T03:14:02Z".into(),
            metrics: Some(Metrics {
                cpu_pct: 12.5,
                mem_pct: 40.1,
                disk_pct: 72.0,
                load1: 0.5,
                uptime_s: 12345,
            }),
            processes: vec![ProcessReport {
                name: "nginx".into(),
                matcher: "nginx".into(),
                pid: Some(1234),
                running: true,
                restarts: 2,
            }],
            checks: vec![CheckReport {
                kind: "tcp".into(),
                target: "localhost:5432".into(),
                ok: true,
                ms: 3,
            }],
            error_signatures: vec![ErrorSignature {
                fingerprint: "deadbeef".into(),
                sample: "redacted line".into(),
                count: 2847,
                first_seen: "2026-08-25T03:14:02Z".into(),
                last_seen: "2026-08-25T03:19:02Z".into(),
            }],
            dropped_signatures: 0,
        };
        let v: Value = serde_json::to_value(&req).unwrap();

        assert_eq!(v["host"], "host-uuid");
        assert_eq!(v["reported_at"], "2026-08-25T03:14:02Z");
        // Metrics block.
        assert_eq!(v["metrics"]["cpu_pct"], 12.5);
        assert_eq!(v["metrics"]["mem_pct"], 40.1);
        assert_eq!(v["metrics"]["disk_pct"], 72.0);
        assert_eq!(v["metrics"]["load1"], 0.5);
        assert_eq!(v["metrics"]["uptime_s"], 12345);
        // Processes: note the `match` field, not `matcher`.
        assert_eq!(v["processes"][0]["name"], "nginx");
        assert_eq!(v["processes"][0]["match"], "nginx");
        assert_eq!(v["processes"][0]["pid"], 1234);
        assert_eq!(v["processes"][0]["running"], true);
        assert_eq!(v["processes"][0]["restarts"], 2);
        assert!(
            v["processes"][0].get("matcher").is_none(),
            "must serialize as `match`, never `matcher`"
        );
        // Checks.
        assert_eq!(v["checks"][0]["kind"], "tcp");
        assert_eq!(v["checks"][0]["target"], "localhost:5432");
        assert_eq!(v["checks"][0]["ok"], true);
        assert_eq!(v["checks"][0]["ms"], 3);
        // Signatures.
        assert_eq!(v["error_signatures"][0]["fingerprint"], "deadbeef");
        assert_eq!(v["error_signatures"][0]["count"], 2847);
        assert_eq!(v["dropped_signatures"], 0);
    }

    /// Empty collections and absent metrics are omitted so an M1 agent can send
    /// only `host` + `reported_at` (additive protocol).
    #[test]
    fn minimal_report_omits_empty_blocks() {
        let req = ReportReq {
            host: "h".into(),
            reported_at: "2026-08-25T00:00:00Z".into(),
            metrics: None,
            processes: vec![],
            checks: vec![],
            error_signatures: vec![],
            dropped_signatures: 0,
        };
        let v: Value = serde_json::to_value(&req).unwrap();
        assert!(v.get("metrics").is_none());
        assert!(v.get("processes").is_none());
        assert!(v.get("checks").is_none());
        assert!(v.get("error_signatures").is_none());
        // dropped_signatures is always present (a scalar, cheap, informative).
        assert_eq!(v["dropped_signatures"], 0);
    }

    #[test]
    fn context_body_matches_protocol_shape() {
        let req = ContextReq {
            incident_hint: "host-uuid".into(),
            lines: vec!["line a".into(), "line b".into()],
        };
        let v: Value = serde_json::to_value(&req).unwrap();
        assert_eq!(v["incident_hint"], "host-uuid");
        assert_eq!(v["lines"][0], "line a");
        assert_eq!(v["lines"][1], "line b");
    }
}
