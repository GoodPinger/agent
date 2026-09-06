//! journald source. Where most Linux service logs actually live,
//! and it hands us two gifts:
//!   - `__CURSOR` — persist it and resume exactly; no byte offsets, no rotation.
//!   - `PRIORITY` and `_SYSTEMD_UNIT` — trusted severity and service, set by
//!     journald and unforgeable by the app. Free, deterministic tier-1 signal;
//!     no regex needed.
//!
//! Read via `journalctl -o json`; native libsystemd only if subprocess overhead
//! proves real. The JSON parsing is a pure function so it is
//! testable without a running journal.

use std::process::Command;

use anyhow::{Context, Result};
use serde_json::Value;

/// Cap on entries pulled per poll — bounds work and memory per call.
pub const MAX_ENTRIES_PER_POLL: usize = 1000;

/// One journal entry, reduced to what the pipeline needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub message: String,
    /// journald PRIORITY (0 emerg … 7 debug). ≤ 3 is a trusted error.
    pub priority: u8,
    pub unit: Option<String>,
    /// Opaque resume token; persist the LAST one seen.
    pub cursor: String,
}

impl Entry {
    /// Trusted tier-1 error verdict from journald's own severity.
    pub fn is_error(&self) -> bool {
        self.priority <= 3
    }
}

pub struct JournaldReader {
    unit: Option<String>,
    min_priority: u8,
    cursor: Option<String>,
}

impl JournaldReader {
    pub fn new(unit: Option<String>, min_priority: u8) -> Self {
        Self {
            unit,
            min_priority,
            cursor: None,
        }
    }

    /// Resume from a previously persisted `__CURSOR`.
    pub fn with_cursor(mut self, cursor: Option<String>) -> Self {
        self.cursor = cursor;
        self
    }

    pub fn cursor(&self) -> Option<&str> {
        self.cursor.as_deref()
    }

    /// Poll journald once. Spawns `journalctl`; on any spawn/exec failure (e.g.
    /// not Linux, no permission) returns an error the caller surfaces — it never
    /// panics.
    pub fn poll(&mut self) -> Result<Vec<Entry>> {
        let mut cmd = Command::new("journalctl");
        cmd.arg("-o").arg("json").arg("--no-pager").arg("-q");
        cmd.arg("-p").arg(self.min_priority.to_string());
        if let Some(unit) = &self.unit {
            cmd.arg("-u").arg(unit);
        }
        match &self.cursor {
            Some(c) => {
                cmd.arg("--after-cursor").arg(c);
            }
            // No cursor yet: only the tail, so a first run does not replay the
            // entire journal history.
            None => {
                cmd.arg("-n").arg(MAX_ENTRIES_PER_POLL.to_string());
            }
        }

        let output = cmd.output().context("spawning journalctl")?;
        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("journalctl exited with {}: {}", output.status, err.trim());
        }

        let text = String::from_utf8_lossy(&output.stdout);
        let mut entries = Vec::new();
        for line in text.lines().take(MAX_ENTRIES_PER_POLL) {
            if let Some(entry) = parse_entry(line) {
                self.cursor = Some(entry.cursor.clone());
                entries.push(entry);
            }
        }
        Ok(entries)
    }
}

/// Parse one `journalctl -o json` line into an `Entry`. Returns `None` for lines
/// without a usable string MESSAGE (e.g. binary blobs journald encodes as arrays).
pub fn parse_entry(line: &str) -> Option<Entry> {
    let v: Value = serde_json::from_str(line.trim()).ok()?;
    let obj = v.as_object()?;

    let message = obj.get("MESSAGE").and_then(|m| m.as_str())?.to_string();
    // journald encodes most fields as strings.
    let priority = obj
        .get("PRIORITY")
        .and_then(field_as_str)
        .and_then(|s| s.parse::<u8>().ok())
        .unwrap_or(6); // default to INFO when absent
    let unit = obj
        .get("_SYSTEMD_UNIT")
        .and_then(field_as_str)
        .map(|s| s.to_string());
    let cursor = obj
        .get("__CURSOR")
        .and_then(field_as_str)
        .unwrap_or("")
        .to_string();

    Some(Entry {
        message,
        priority,
        unit,
        cursor,
    })
}

fn field_as_str(v: &Value) -> Option<&str> {
    v.as_str()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_message_priority_unit_cursor() {
        let line = r#"{"__CURSOR":"s=abc;i=1","PRIORITY":"3","_SYSTEMD_UNIT":"myapp.service","MESSAGE":"connection refused"}"#;
        let e = parse_entry(line).unwrap();
        assert_eq!(e.message, "connection refused");
        assert_eq!(e.priority, 3);
        assert_eq!(e.unit.as_deref(), Some("myapp.service"));
        assert_eq!(e.cursor, "s=abc;i=1");
        assert!(e.is_error(), "priority 3 is a trusted error");
    }

    #[test]
    fn non_error_priority_is_not_an_error() {
        let line = r#"{"__CURSOR":"s=abc;i=2","PRIORITY":"6","MESSAGE":"listening on :8080"}"#;
        let e = parse_entry(line).unwrap();
        assert_eq!(e.priority, 6);
        assert!(!e.is_error());
        assert!(e.unit.is_none());
    }

    #[test]
    fn skips_entries_without_string_message() {
        // Binary MESSAGE is emitted as an array of byte values.
        let line = r#"{"__CURSOR":"s=abc;i=3","PRIORITY":"4","MESSAGE":[104,105]}"#;
        assert!(parse_entry(line).is_none());
    }

    #[test]
    fn tolerates_missing_priority() {
        let line = r#"{"__CURSOR":"s=abc;i=4","MESSAGE":"no priority field"}"#;
        let e = parse_entry(line).unwrap();
        assert_eq!(e.priority, 6, "defaults to INFO");
    }
}
