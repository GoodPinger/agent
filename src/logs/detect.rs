//! Error identification, three tiers, best available wins. No
//! tier 4 ever — no ML, no anomaly detection, no LLM classification. Only
//! deterministic rules a user can read, predict, and verify with
//! `gpr logs --test`.
//!
//! | Tier | Signal                                            | Reliability |
//! |------|---------------------------------------------------|-------------|
//! | 1    | journald PRIORITY ≤ 3; JSON level error/fatal/…   | Certain     |
//! | 2    | severity token regex (case-sensitive, bounded)    | Good        |
//! | 3    | user-supplied regex per source                    | User's      |

use anyhow::{Context, Result};
use regex::Regex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    One,
    Two,
    Three,
}

#[derive(Debug, Clone)]
pub struct Detection {
    pub tier: Tier,
    /// What matched — surfaced by `gpr logs --test` so users can see WHY a line
    /// was flagged.
    pub reason: String,
}

pub struct Detector {
    tier2: Regex,
    tier3: Vec<Regex>,
}

impl Detector {
    /// `user_patterns` are tier-3 regexes; a bad pattern is a hard error so the
    /// user finds out at `gpr logs --test` time, not silently in production.
    pub fn new(user_patterns: &[String]) -> Result<Self> {
        // Case-sensitive and word-bounded ON PURPOSE: matching
        // `error` case-insensitively would fire on `error_count=0` and
        // `/var/log/nginx/error.log` — a monitor crying wolf on its own log path.
        let tier2 = Regex::new(
            r"\bERROR\b|\bFATAL\b|\bPANIC\b|\bCRITICAL\b|\bSEVERE\b|\bException\b|\bTraceback\b|\bpanic:",
        )
        .expect("valid tier-2 severity regex");
        let mut tier3 = Vec::with_capacity(user_patterns.len());
        for p in user_patterns {
            tier3.push(Regex::new(p).with_context(|| format!("invalid user log pattern: {p}"))?);
        }
        Ok(Self { tier2, tier3 })
    }

    /// Classify an event. `trusted_error` carries journald's authoritative
    /// verdict (PRIORITY ≤ 3): `Some(true)` is a certain error, `Some(false)` is
    /// a certain non-error (skip it), `None` means "no trusted signal, inspect
    /// the text".
    pub fn detect(&self, text: &str, trusted_error: Option<bool>) -> Option<Detection> {
        match trusted_error {
            Some(true) => {
                return Some(Detection {
                    tier: Tier::One,
                    reason: "journald PRIORITY <= 3".to_string(),
                })
            }
            // journald severity is trusted — do not second-guess a non-error.
            Some(false) => return None,
            None => {}
        }

        let first = text.lines().next().unwrap_or("");
        if let Some(level) = json_error_level(first) {
            return Some(Detection {
                tier: Tier::One,
                reason: format!("JSON level={level}"),
            });
        }

        if let Some(m) = self.tier2.find(text) {
            return Some(Detection {
                tier: Tier::Two,
                reason: format!("severity token `{}`", m.as_str()),
            });
        }

        for re in &self.tier3 {
            if let Some(m) = re.find(text) {
                return Some(Detection {
                    tier: Tier::Three,
                    reason: format!("user pattern matched `{}`", m.as_str()),
                });
            }
        }

        None
    }
}

/// If `line` is a JSON object whose `level`/`severity` denotes an error, return
/// that level. JSON level is structured metadata, so matching is case-insensitive
/// (unlike the free-text tier-2 tokens).
fn json_error_level(line: &str) -> Option<String> {
    let line = line.trim();
    if !line.starts_with('{') {
        return None;
    }
    let value: serde_json::Value = serde_json::from_str(line).ok()?;
    let obj = value.as_object()?;
    for key in ["level", "severity", "lvl", "loglevel"] {
        if let Some(v) = obj.get(key).and_then(|v| v.as_str()) {
            let lv = v.to_ascii_lowercase();
            if matches!(
                lv.as_str(),
                "error" | "fatal" | "panic" | "critical" | "crit" | "emerg" | "alert"
            ) {
                return Some(lv);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn det() -> Detector {
        Detector::new(&[]).unwrap()
    }

    #[test]
    fn tier2_matches_uppercase_and_bounded_tokens() {
        let d = det();
        for line in [
            "2024-01-01T00:00:00Z ERROR boom",
            "Traceback (most recent call last):",
            "panic: runtime error: index out of range",
            "FATAL: could not connect",
            "Exception in thread \"main\" java.lang.NullPointerException",
        ] {
            let got = d.detect(line, None);
            assert!(got.is_some(), "tier-2 should fire on: {line}");
            assert_eq!(got.unwrap().tier, Tier::Two);
        }
    }

    #[test]
    fn tier2_does_not_cry_wolf_on_lowercase_error() {
        let d = det();
        // These are THE embarrassing false positives §5.4 calls out.
        for line in [
            "GET /var/log/nginx/error.log 200 in 12ms",
            "metrics: error_count=0 warnings=0",
            "the error was handled gracefully",
            "info: everything nominal",
        ] {
            assert!(
                d.detect(line, None).is_none(),
                "must NOT flag benign lowercase `error`: {line}"
            );
        }
    }

    #[test]
    fn tier1_json_level_wins() {
        let d = det();
        assert_eq!(
            d.detect(r#"{"level":"error","msg":"boom"}"#, None)
                .unwrap()
                .tier,
            Tier::One
        );
        assert_eq!(
            d.detect(r#"{"level":"fatal","msg":"dead"}"#, None)
                .unwrap()
                .tier,
            Tier::One
        );
        assert!(d.detect(r#"{"level":"info","msg":"ok"}"#, None).is_none());
    }

    #[test]
    fn tier1_trusted_priority() {
        let d = det();
        assert_eq!(d.detect("anything", Some(true)).unwrap().tier, Tier::One);
        assert!(
            d.detect("ERROR even this", Some(false)).is_none(),
            "trusted non-error priority must suppress detection"
        );
    }

    #[test]
    fn tier3_user_pattern_catches_lowercase_nginx() {
        // nginx writes `[error]` lowercase; the user opts in with a regex.
        let d = Detector::new(&[r"\[error\]".to_string()]).unwrap();
        let line = include_str!("../../tests/fixtures/nginx_error.log")
            .lines()
            .next()
            .unwrap();
        let got = d.detect(line, None).unwrap();
        assert_eq!(got.tier, Tier::Three);
    }

    #[test]
    fn bad_user_pattern_is_a_hard_error() {
        assert!(Detector::new(&["(unclosed".to_string()]).is_err());
    }
}
