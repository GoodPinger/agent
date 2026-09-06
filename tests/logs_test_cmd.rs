//! End-to-end `gpr logs --test <path>`. Verifies the dry-run
//! detects errors, aggregates them, and — the load-bearing part — shows the
//! sample REDACTED so a user can verify redaction before trusting the agent.

use std::path::Path;

use assert_cmd::Command;
use predicates::prelude::PredicateBooleanExt;

fn fixture(name: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

fn gpr() -> Command {
    let mut cmd = Command::cargo_bin("gpr").expect("gpr binary builds");
    // Isolated config dir; no network is touched by --test.
    cmd.env("GPR_CONFIG_DIR", std::env::temp_dir().join("gpr-logs-test"));
    cmd
}

#[test]
fn detects_error_and_redacts_sample() {
    gpr()
        .args(["logs", "--test", &fixture("app_with_secret.log")])
        .assert()
        .code(0)
        .stdout(predicates::str::contains("error signature"))
        .stdout(predicates::str::contains("[REDACTED]"))
        // No secret value may appear anywhere in the output.
        .stdout(predicates::str::contains("hunter2").not())
        .stdout(predicates::str::contains("AKIAIOSFODNN7EXAMPLE").not())
        .stdout(predicates::str::contains("dbpass").not())
        // The honesty line users are meant to read.
        .stdout(predicates::str::contains("best-effort"));
}

#[test]
fn reports_nothing_for_a_clean_log() {
    // node.jsonl has errors; use a benign temp file instead.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("clean.log");
    std::fs::write(&path, "2024-01-01T00:00:00Z INFO all good\n").unwrap();
    gpr()
        .args(["logs", "--test", path.to_str().unwrap()])
        .assert()
        .code(0)
        .stdout(predicates::str::contains("no errors detected"));
}

#[test]
fn without_test_flag_is_a_usage_error() {
    gpr()
        .args(["logs"])
        .assert()
        .code(2)
        .stderr(predicates::str::contains("--test"));
}
