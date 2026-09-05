//! Secret redaction. Scrub before buffering, so a secret never sits in memory
//! (or on disk) longer than one captured line.
//!
//! Best-effort by design — documented as such. Deterministic, regex-based.

use anyhow::{Context, Result};
use regex::Regex;

const PLACEHOLDER: &str = "[REDACTED]";

/// A set of compiled redaction rules. Build once, reuse for a whole tail.
pub struct Redactor {
    /// `key`-style rules that keep the key and mask the value.
    kv: Vec<Regex>,
    /// Whole-token rules that mask the entire match.
    token: Vec<Regex>,
}

impl Default for Redactor {
    fn default() -> Self {
        Self::new()
    }
}

impl Redactor {
    pub fn new() -> Self {
        // key=value / key: value  → capture group 1 is the key label kept.
        let kv_sources = [
            r"(?i)\b(password|passwd|pwd)\s*[=:]\s*\S+",
            r"(?i)\b(token)\s*[=:]\s*\S+",
            r"(?i)\b(api[_-]?key)\s*[=:]\s*\S+",
            // Any key whose name contains "secret" (e.g. secret, client_secret,
            // aws_secret_access_key).
            r"(?i)\b([a-z0-9_]*secret[a-z0-9_]*)\s*[=:]\s*\S+",
            // Authorization value is scheme + credential ("Basic xxx",
            // "Bearer xxx"); consume both tokens, not just the scheme.
            r"(?i)\b(authorization)\s*[=:]\s*\S+(?:\s+\S+)?",
        ];
        // Whole-match rules — the entire matched span is a secret.
        let token_sources = [
            // "Bearer <token>" (Authorization header value form).
            r"(?i)\bbearer\s+[A-Za-z0-9._\-+/=]+",
            // AWS access key id.
            r"\bAKIA[0-9A-Z]{16}\b",
            // JWT: three base64url segments separated by dots, starting eyJ.
            r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
            // PEM private key header (and its BEGIN line).
            r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----",
            // Connection strings carrying credentials: scheme://user:pass@host
            r"(?i)\b[a-z][a-z0-9+.\-]*://[^\s:/@]+:[^\s:/@]+@\S+",
        ];

        Self {
            kv: kv_sources
                .iter()
                .map(|s| Regex::new(s).expect("valid kv redaction regex"))
                .collect(),
            token: token_sources
                .iter()
                .map(|s| Regex::new(s).expect("valid token redaction regex"))
                .collect(),
        }
    }

    /// Like [`Redactor::new`], plus user-supplied whole-match patterns from the
    /// config `redact.extra` list. A bad pattern is a hard
    /// error so the user finds out at `gpr logs --test`, not in production.
    pub fn with_extra(extra: &[String]) -> Result<Self> {
        let mut r = Self::new();
        for pat in extra {
            r.token.push(
                Regex::new(pat)
                    .with_context(|| format!("invalid extra redaction pattern: {pat}"))?,
            );
        }
        Ok(r)
    }

    /// Return `input` with every recognized secret masked.
    pub fn redact(&self, input: &str) -> String {
        let mut out = input.to_string();
        for re in &self.kv {
            out = re
                .replace_all(&out, |caps: &regex::Captures| {
                    format!("{}={}", &caps[1], PLACEHOLDER)
                })
                .into_owned();
        }
        for re in &self.token {
            out = re.replace_all(&out, PLACEHOLDER).into_owned();
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_pattern_is_scrubbed() {
        let r = Redactor::new();
        let fixture = concat!(
            "password=hunter2 ",
            "passwd: s3cr3tpw ",
            "token=abc123DEF ",
            "api_key=AKIAIOSFODNN7EXAMPLE ",
            "api-key: xyzzy-value ",
            "secret=topsecretvalue ",
            "client_secret=anotherone ",
            "Authorization: Basic dXNlcjpwYXNz ",
            "authorization=Bearer sometoken ",
            "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.dozjgNryP4J3jVmNHl0w5N ",
            "aws_secret_access_key=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY ",
            "AKIAIOSFODNN7EXAMPLE ",
            "jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIifQ.abc123def456 ",
            "conn=postgres://dbuser:dbpass@db.internal:5432/app ",
            "-----BEGIN RSA PRIVATE KEY-----",
        );
        let out = r.redact(fixture);

        // No raw secret value survives.
        for leaked in [
            "hunter2",
            "s3cr3tpw",
            "abc123DEF",
            "AKIAIOSFODNN7EXAMPLE",
            "xyzzy-value",
            "topsecretvalue",
            "anotherone",
            "dXNlcjpwYXNz",
            "sometoken",
            "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY",
            "dbpass",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9",
            "-----BEGIN RSA PRIVATE KEY-----",
        ] {
            assert!(
                !out.contains(leaked),
                "secret survived redaction: {leaked}\ngot: {out}"
            );
        }
    }

    #[test]
    fn leaves_ordinary_output_alone() {
        let r = Redactor::new();
        let line = "GET /error.log 200 in 12ms; error_count=0";
        assert_eq!(r.redact(line), line);
    }
}
