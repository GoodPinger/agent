//! Log capture and error detection. The whole design in one line:
//! **a ring buffer, not a pipe** — the agent keeps a bounded in-memory window per
//! source, detects and fingerprints errors locally, and reports AGGREGATES on the
//! normal interval. It never streams logs upstream; cost scales with incident
//! count, not log volume.
//!
//! Wiring:
//! ```text
//! source → redact → ring buffer (bounded)
//!                 → multiline group → detect (3 tiers) → fingerprint + count
//!                                                       → drain aggregates each interval
//! ```
//!
//! Redaction happens BEFORE buffering, so a secret never sits in memory longer
//! than a line. Everything downstream sees redacted text.

// `logs` is a cohesive, unit-tested sub-library living inside a BINARY crate.
// Several diagnostic fields and small accessors (detect tier/reason, file
// rotated/truncated, multiline line_count/truncated, ring/table len/is_empty,
// dropped, journald is_error) are asserted by this module's own tests and are
// part of its API surface, but are not read on the binary's runtime path — so
// the bin's dead-code pass flags them. A `lib` target would silence this
// cleanly; until that split is worth doing, this scoped allow is the honest,
// low-churn choice. New product code must still earn its keep.
#![allow(dead_code)]

pub mod cmd;
pub mod detect;
pub mod file;
pub mod fingerprint;
pub mod journald;
pub mod multiline;
pub mod ring;
pub mod signatures;
pub mod state;

use std::path::PathBuf;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::redact::Redactor;
use detect::Detector;
use fingerprint::Normalizer;
use multiline::Grouper;
use ring::RingBuffer;
use signatures::SignatureTable;

/// Longest single line the pipeline will hold or process (bounds memory).
pub const MAX_LINE_LEN: usize = 8 * 1024;

// ---------------------------------------------------------------------------
// Configuration (persisted in config.json under `log_sources`; see config.rs).
// sketches this in TOML — the store here is JSON to match the
// existing config format and avoid a TOML dependency for a handful of fields.
// ---------------------------------------------------------------------------

/// How a source's lines are grouped into events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Multiline {
    /// Timestamp-prefix + marker heuristic. The sensible default.
    #[default]
    Auto,
    /// One JSON object per line; never grouped.
    Json,
    /// Timestamp-prefix rule only.
    Timestamp,
    /// No grouping; each line is its own event.
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum LogSourceConfig {
    File(FileSourceConfig),
    Journald(JournaldSourceConfig),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSourceConfig {
    pub path: PathBuf,
    #[serde(default)]
    pub multiline: Multiline,
    /// Tier-3 user regexes for this source.
    #[serde(default)]
    pub user_patterns: Vec<String>,
    /// Extra redaction patterns.
    #[serde(default)]
    pub redact_extra: Vec<String>,
    /// Per-interval signature cap override (defaults to 20).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_events_per_interval: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournaldSourceConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    /// Report entries at this PRIORITY or worse (err = 3).
    #[serde(default = "default_min_priority")]
    pub min_priority: u8,
    #[serde(default)]
    pub user_patterns: Vec<String>,
    #[serde(default)]
    pub redact_extra: Vec<String>,
}

fn default_min_priority() -> u8 {
    3
}

// ---------------------------------------------------------------------------
// Wire type (matches the wire protocol `error_signatures[]`).
// ---------------------------------------------------------------------------

/// One entry of `/agent/report`'s `error_signatures[]`.
#[derive(Debug, Clone, Serialize)]
pub struct ErrorSignature {
    pub fingerprint: String,
    pub sample: String,
    pub count: u64,
    pub first_seen: String,
    pub last_seen: String,
}

/// The result of draining a pipeline for one report interval — exactly what
/// `gpr watch` puts on the wire.
#[derive(Debug, Clone, Serialize)]
pub struct DrainedSignatures {
    pub error_signatures: Vec<ErrorSignature>,
    pub dropped_signatures: u64,
}

// ---------------------------------------------------------------------------
// Pipeline.
// ---------------------------------------------------------------------------

/// Tunables for a pipeline. `Default` matches the ceilings.
pub struct PipelineConfig {
    pub ring_max_lines: usize,
    pub ring_max_bytes: usize,
    pub group_max_lines: usize,
    pub group_max_bytes: usize,
    pub max_signatures: usize,
    pub user_patterns: Vec<String>,
    pub redact_extra: Vec<String>,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            ring_max_lines: ring::DEFAULT_MAX_LINES,
            ring_max_bytes: ring::DEFAULT_MAX_BYTES,
            group_max_lines: multiline::DEFAULT_MAX_LINES,
            group_max_bytes: multiline::DEFAULT_MAX_BYTES,
            max_signatures: signatures::DEFAULT_MAX_SIGNATURES,
            user_patterns: Vec::new(),
            redact_extra: Vec::new(),
        }
    }
}

/// The per-host log pipeline. One instance aggregates across all sources so the
/// distinct-signature cap is enforced per host, as the spec requires.
pub struct Pipeline {
    ring: RingBuffer,
    grouper: Grouper,
    detector: Detector,
    normalizer: Normalizer,
    table: SignatureTable,
    redactor: Redactor,
}

impl Pipeline {
    /// Build a pipeline. Fails only if a user tier-3 pattern is an invalid regex
    /// (surfaced early, at `gpr logs --test`).
    pub fn new(cfg: PipelineConfig) -> Result<Self> {
        Ok(Self {
            ring: RingBuffer::new(cfg.ring_max_lines, cfg.ring_max_bytes),
            grouper: Grouper::new(cfg.group_max_lines, cfg.group_max_bytes),
            detector: Detector::new(&cfg.user_patterns)?,
            normalizer: Normalizer::new(),
            table: SignatureTable::new(cfg.max_signatures),
            redactor: Redactor::with_extra(&cfg.redact_extra)?,
        })
    }

    /// Feed one raw text line from a file source. Redaction happens here, BEFORE
    /// the line touches the ring buffer or the grouper.
    pub fn push_line(&mut self, raw: &str) {
        let line = cap_line(&self.redactor.redact(raw));
        self.ring.push(line.clone());
        if let Some(event) = self.grouper.push(&line) {
            self.handle_event(&event.text, None);
        }
    }

    /// Feed one journald entry. journald delimits entries for us, so it bypasses
    /// the multiline grouper; `priority` supplies the trusted tier-1 verdict.
    pub fn push_journal(&mut self, message: &str, priority: u8) {
        let line = cap_line(&self.redactor.redact(message));
        self.ring.push(line.clone());
        self.handle_event(&line, Some(priority <= 3));
    }

    /// Flush the multiline grouper — call once a file source is exhausted.
    pub fn flush(&mut self) {
        if let Some(event) = self.grouper.finish() {
            self.handle_event(&event.text, None);
        }
    }

    fn handle_event(&mut self, text: &str, trusted_error: Option<bool>) {
        if self.detector.detect(text, trusted_error).is_none() {
            return;
        }
        let fingerprint = self.normalizer.fingerprint(text);
        // The sample is the (already redacted) first line — a human-readable
        // representative, never the whole trace.
        let sample = text.lines().next().unwrap_or(text);
        self.table.record(fingerprint, sample, chrono::Utc::now());
    }

    /// Drain aggregated signatures for one report interval. This is the API
    /// `gpr watch` calls; it resets the table for the next interval.
    pub fn drain(&mut self) -> DrainedSignatures {
        let (sigs, dropped) = self.table.drain();
        let error_signatures = sigs
            .into_iter()
            .map(|s| ErrorSignature {
                fingerprint: s.fingerprint.clone(),
                first_seen: s.first_seen_rfc3339(),
                last_seen: s.last_seen_rfc3339(),
                sample: s.sample,
                count: s.count,
            })
            .collect();
        DrainedSignatures {
            error_signatures,
            dropped_signatures: dropped,
        }
    }

    /// Current ring-buffer contents — the material `gpr watch` flushes as
    /// incident context (±N lines) when an incident opens.
    pub fn context_lines(&self) -> Vec<String> {
        self.ring.snapshot()
    }
}

/// Build a single [`PipelineConfig`] covering every configured source, so the
/// per-host distinct-signature cap is enforced across all of them at once
/// (matching how `gpr watch` and `gpr logs --test` both behave). Unions the
/// per-source tier-3 patterns and redaction extras; takes the largest per-source
/// `max_events_per_interval` override if any is set.
pub fn pipeline_config_for(sources: &[LogSourceConfig]) -> PipelineConfig {
    let mut cfg = PipelineConfig::default();
    let mut max_events: Option<usize> = None;
    for s in sources {
        match s {
            LogSourceConfig::File(f) => {
                cfg.user_patterns.extend(f.user_patterns.iter().cloned());
                cfg.redact_extra.extend(f.redact_extra.iter().cloned());
                if let Some(m) = f.max_events_per_interval {
                    max_events = Some(max_events.map_or(m, |cur| cur.max(m)));
                }
            }
            LogSourceConfig::Journald(j) => {
                cfg.user_patterns.extend(j.user_patterns.iter().cloned());
                cfg.redact_extra.extend(j.redact_extra.iter().cloned());
            }
        }
    }
    if let Some(m) = max_events {
        cfg.max_signatures = m;
    }
    cfg
}

/// Cap a line to `MAX_LINE_LEN` bytes on a char boundary (bounds memory).
fn cap_line(line: &str) -> String {
    if line.len() <= MAX_LINE_LEN {
        return line.to_string();
    }
    let mut end = MAX_LINE_LEN;
    while end > 0 && !line.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = line[..end].to_string();
    out.push_str("… [line truncated]");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_sample_before_it_is_stored() {
        // Every §5.6 secret pattern, on a detectable ERROR line.
        let fixture = include_str!("../../tests/fixtures/app_with_secret.log");
        let mut p = Pipeline::new(PipelineConfig::default()).unwrap();
        for line in fixture.lines() {
            p.push_line(line);
        }
        p.flush();
        let drained = p.drain();

        assert_eq!(
            drained.error_signatures.len(),
            1,
            "one ERROR line detected: {drained:#?}"
        );
        let sample = &drained.error_signatures[0].sample;
        for leaked in [
            "hunter2",
            "abc123DEF",
            "AKIAIOSFODNN7EXAMPLE",
            "topsecretvalue",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            "dbpass",
        ] {
            assert!(
                !sample.contains(leaked),
                "secret survived into the stored sample: {leaked}\nsample: {sample}"
            );
        }
        assert!(
            sample.contains("[REDACTED]"),
            "sample should show redaction happened: {sample}"
        );
    }

    #[test]
    fn json_source_detects_error_and_fatal_levels() {
        let fixture = include_str!("../../tests/fixtures/node.jsonl");
        let mut p = Pipeline::new(PipelineConfig::default()).unwrap();
        for line in fixture.lines() {
            p.push_line(line);
        }
        p.flush();
        let drained = p.drain();
        // The error and fatal objects; info/warn ignored.
        assert_eq!(drained.error_signatures.len(), 2, "{drained:#?}");
    }

    #[test]
    fn aggregates_repeated_errors_into_one_signature() {
        let mut p = Pipeline::new(PipelineConfig::default()).unwrap();
        for i in 0..1000 {
            p.push_line(&format!(
                "2024-01-01T03:14:{:02}Z ERROR connection to 10.0.0.{} refused (id={:08x})",
                i % 60,
                i % 254,
                i
            ));
        }
        p.flush();
        let drained = p.drain();
        assert_eq!(drained.error_signatures.len(), 1, "{drained:#?}");
        assert_eq!(drained.error_signatures[0].count, 1000);
    }

    #[test]
    fn user_patterns_enable_lowercase_nginx_detection() {
        let cfg = PipelineConfig {
            user_patterns: vec![r"\[error\]".to_string()],
            ..Default::default()
        };
        let mut p = Pipeline::new(cfg).unwrap();
        let fixture = include_str!("../../tests/fixtures/nginx_error.log");
        for line in fixture.lines() {
            p.push_line(line);
        }
        p.flush();
        let drained = p.drain();
        // Two distinct `[error]` shapes (different upstream port) collapse under
        // normalization to one fingerprint; the `[warn]` line is ignored.
        assert_eq!(drained.error_signatures.len(), 1, "{drained:#?}");
        assert_eq!(drained.error_signatures[0].count, 2);
    }
}
