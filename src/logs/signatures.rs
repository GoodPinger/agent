//! The local error-signature table: `fingerprint → {count, first_seen,
//! last_seen, one redacted sample}`.
//!
//! An app emitting 10,000 errors/sec must not produce 10,000 rows, uploads, or
//! alerts. The table aggregates by fingerprint and is hard-capped at 20 distinct
//! signatures per interval; occurrences past the cap are counted in `dropped`
//! (a bounded counter — never an unbounded set of fingerprints), so a cardinality
//! explosion can never become the bill.

use chrono::{DateTime, SecondsFormat, Utc};

/// Hard cap on distinct fingerprints reported per interval per host.
pub const DEFAULT_MAX_SIGNATURES: usize = 20;
/// Longest sample line stored/reported per signature.
pub const SAMPLE_MAX_BYTES: usize = 1024;

#[derive(Debug, Clone)]
pub struct Signature {
    pub fingerprint: String,
    /// One representative line, ALREADY REDACTED before it reached this table.
    pub sample: String,
    pub count: u64,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

pub struct SignatureTable {
    map: std::collections::HashMap<String, Signature>,
    cap: usize,
    /// Occurrences that could not be recorded because the distinct-signature cap
    /// was full. A counter, not a set — bounded memory.
    dropped: u64,
}

impl SignatureTable {
    pub fn new(cap: usize) -> Self {
        Self {
            map: std::collections::HashMap::new(),
            cap: cap.max(1),
            dropped: 0,
        }
    }

    /// Record one occurrence. `sample` MUST already be redacted. New shapes past
    /// the cap are dropped (counted), not stored.
    pub fn record(&mut self, fingerprint: String, sample: &str, now: DateTime<Utc>) {
        if let Some(sig) = self.map.get_mut(&fingerprint) {
            sig.count += 1;
            sig.last_seen = now;
            return;
        }
        if self.map.len() >= self.cap {
            self.dropped += 1;
            return;
        }
        let sample = truncate_bytes(sample, SAMPLE_MAX_BYTES);
        self.map.insert(
            fingerprint.clone(),
            Signature {
                fingerprint,
                sample,
                count: 1,
                first_seen: now,
                last_seen: now,
            },
        );
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Drain the table for the next report interval: returns signatures sorted by
    /// count (descending) plus the dropped counter, and resets both. This is the
    /// API `gpr watch` calls each interval.
    pub fn drain(&mut self) -> (Vec<Signature>, u64) {
        let mut sigs: Vec<Signature> = self.map.drain().map(|(_, s)| s).collect();
        sigs.sort_by(|a, b| {
            b.count
                .cmp(&a.count)
                .then(a.fingerprint.cmp(&b.fingerprint))
        });
        let dropped = self.dropped;
        self.dropped = 0;
        (sigs, dropped)
    }
}

impl Signature {
    /// RFC 3339 UTC (`Z`) rendering of `first_seen`, for the wire.
    pub fn first_seen_rfc3339(&self) -> String {
        self.first_seen.to_rfc3339_opts(SecondsFormat::Secs, true)
    }

    pub fn last_seen_rfc3339(&self) -> String {
        self.last_seen.to_rfc3339_opts(SecondsFormat::Secs, true)
    }
}

/// Truncate to at most `max` bytes on a char boundary, marking if cut.
pub fn truncate_bytes(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = s[..end].to_string();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> DateTime<Utc> {
        Utc::now()
    }

    #[test]
    fn same_fingerprint_aggregates_count() {
        let mut t = SignatureTable::new(DEFAULT_MAX_SIGNATURES);
        for _ in 0..2_847 {
            t.record("abc".to_string(), "ERROR boom", now());
        }
        let (sigs, dropped) = t.drain();
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].count, 2_847);
        assert_eq!(dropped, 0);
    }

    #[test]
    fn caps_distinct_fingerprints_and_counts_dropped() {
        let mut t = SignatureTable::new(20);
        // 25 distinct shapes, each seen 3×.
        for i in 0..25 {
            for _ in 0..3 {
                t.record(format!("fp{i}"), "ERROR boom", now());
            }
        }
        let (sigs, dropped) = t.drain();
        assert_eq!(sigs.len(), 20, "distinct signatures capped at 20");
        // 5 shapes × 3 occurrences each landed after the cap filled.
        assert_eq!(dropped, 15, "occurrences past the cap are counted");
    }

    #[test]
    fn drain_resets_the_table() {
        let mut t = SignatureTable::new(20);
        t.record("x".to_string(), "ERROR", now());
        assert_eq!(t.drain().0.len(), 1);
        assert!(t.is_empty());
        assert_eq!(t.drain().0.len(), 0);
    }

    #[test]
    fn sample_is_truncated() {
        let mut t = SignatureTable::new(20);
        let big = "E".repeat(SAMPLE_MAX_BYTES * 2);
        t.record("x".to_string(), &big, now());
        let (sigs, _) = t.drain();
        assert!(sigs[0].sample.len() <= SAMPLE_MAX_BYTES + 4);
    }
}
