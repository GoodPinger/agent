//! Fingerprinting: collapse the varying parts of an error into a stable hash so
//! 10,000 occurrences of one error become one signature, not 10,000.
//!
//! Normalization strips timestamps, ids, ips, numbers, quoted strings, paths and
//! addresses; the normalized form is hashed with FNV-1a (deterministic, no
//! dependency — the fingerprint only has to be stable, not cryptographic).
//!
//! Normalization feeds the HASH only. The human-readable sample stored in the
//! signature table is the redacted original line, so aggressive normalization
//! here never hurts what a user actually reads.

use regex::Regex;

/// FNV-1a 64-bit over `bytes`, rendered as 16 lowercase hex chars.
///
/// Reused for content fingerprinting of files (first N bytes) in `file.rs`.
pub fn fnv1a_hex(bytes: &[u8]) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

/// A compiled set of normalization rules, applied in order. Build once, reuse.
pub struct Normalizer {
    rules: Vec<(Regex, &'static str)>,
}

impl Default for Normalizer {
    fn default() -> Self {
        Self::new()
    }
}

impl Normalizer {
    pub fn new() -> Self {
        // ORDER MATTERS. Broad, structural tokens first (timestamps contain
        // colons and ints; ids/ips contain hex and dots) so the greedy integer
        // rule runs last and cannot pre-empt them.
        let sources: &[(&str, &str)] = &[
            // Timestamps: ISO-8601 / Postgres, nginx `Y/M/D H:M:S`, syslog `Mon D H:M:S`.
            (
                r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?(?:\s[A-Z]{2,5})?",
                "<TS>",
            ),
            (r"\d{4}/\d{2}/\d{2}\s\d{2}:\d{2}:\d{2}", "<TS>"),
            (r"[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}", "<TS>"),
            // UUID before the generic hex rule.
            (
                r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
                "<ID>",
            ),
            // IPv4 before the integer rule.
            (r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "<IP>"),
            // IPv6: full form, or any run containing `::`.
            (r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b", "<IP>"),
            (r"(?:[0-9a-fA-F]{1,4}:)*::(?:[0-9a-fA-F]{1,4}:?)*", "<IP>"),
            // Memory addresses before the generic hex rule (0x… would otherwise
            // partially match).
            (r"\b0x[0-9a-fA-F]+\b", "<ADDR>"),
            // Long hex runs (ids, hashes) — 8+ chars.
            (r"\b[0-9a-fA-F]{8,}\b", "<ID>"),
            // Quoted strings (single or double).
            (r#""[^"]*""#, "<STR>"),
            (r"'[^']*'", "<STR>"),
            // Absolute paths (two+ segments so a lone `/` is not eaten).
            (r"/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)+", "<PATH>"),
            // Any remaining integer (also normalizes floats to <N>.<N>).
            (r"\b\d+\b", "<N>"),
        ];
        let rules = sources
            .iter()
            .map(|(re, rep)| (Regex::new(re).expect("valid normalization regex"), *rep))
            .collect();
        Self { rules }
    }

    /// Return `input` with all varying spans replaced by their placeholders.
    pub fn normalize(&self, input: &str) -> String {
        let mut out = input.to_string();
        for (re, rep) in &self.rules {
            out = re.replace_all(&out, *rep).into_owned();
        }
        out
    }

    /// Normalize then hash: the fingerprint of an error shape.
    pub fn fingerprint(&self, input: &str) -> String {
        fnv1a_hex(self.normalize(input).as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ten_thousand_varying_instances_collapse_to_one_fingerprint() {
        // One nginx-shaped error, varied across every dimension normalization is
        // supposed to erase: timestamp, ip, port, connection id, request path.
        let n = Normalizer::new();
        let mut fingerprints = std::collections::HashSet::new();
        for i in 0..10_000u32 {
            let a = i % 254 + 1;
            let b = (i / 254) % 254 + 1;
            let port = 1024 + (i % 40000);
            let line = format!(
                "2024/01/01 {:02}:{:02}:{:02} [error] {}#0: *{} connect() failed (111: Connection refused), client: 10.{}.{}.{}, upstream: \"http://127.0.0.1:{}/\", id={:016x}",
                i % 24, i % 60, i % 60, 1000 + i, i, a, b, a, port, i as u64 * 2654435761
            );
            fingerprints.insert(n.fingerprint(&line));
        }
        assert_eq!(
            fingerprints.len(),
            1,
            "10,000 varied instances of one error must collapse to a single fingerprint, got {}",
            fingerprints.len()
        );
    }

    #[test]
    fn distinct_error_shapes_do_not_collide() {
        let n = Normalizer::new();
        let a = n.fingerprint("ERROR connection to 10.0.0.5:5432 refused");
        let b = n.fingerprint("ERROR disk full on /var/lib/pgsql");
        assert_ne!(
            a, b,
            "genuinely different errors must not share a fingerprint"
        );
    }

    #[test]
    fn normalizer_replaces_each_variable_class() {
        let n = Normalizer::new();
        let got = n.normalize(
            "2024-01-01T03:14:02Z req 550e8400-e29b-41d4-a716-446655440000 from 10.0.0.5 at 0xdeadbeef path /var/log/app.log count 42 msg \"boom\"",
        );
        assert!(got.contains("<TS>"), "timestamp: {got}");
        assert!(got.contains("<ID>"), "uuid: {got}");
        assert!(got.contains("<IP>"), "ip: {got}");
        assert!(got.contains("<ADDR>"), "address: {got}");
        assert!(got.contains("<PATH>"), "path: {got}");
        assert!(got.contains("<N>"), "int: {got}");
        assert!(got.contains("<STR>"), "quoted: {got}");
    }

    #[test]
    fn fnv_is_deterministic() {
        assert_eq!(fnv1a_hex(b"hello"), fnv1a_hex(b"hello"));
        assert_ne!(fnv1a_hex(b"hello"), fnv1a_hex(b"world"));
        assert_eq!(fnv1a_hex(b"hello").len(), 16);
    }
}
