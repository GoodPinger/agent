//! `gpr run` exit-code passthrough — the load-bearing test.
//!
//! Reporting is pointed at an unreachable base URL with a short timeout, so the
//! agent must BUFFER rather than block, and must NEVER let a reporting failure
//! change the wrapped command's exit code.

use std::path::Path;

use assert_cmd::Command;
use tempfile::TempDir;

/// A `gpr run ...` command wired to an unreachable control plane and an
/// isolated config/buffer dir.
fn gpr(config_dir: &Path) -> Command {
    let mut cmd = Command::cargo_bin("gpr").expect("gpr binary builds");
    cmd.env("GPR_CONFIG_DIR", config_dir)
        // Connection-refused address: fails fast, exercises the buffer path.
        .env("GPR_BASE_URL", "http://127.0.0.1:1")
        .env("GPR_HTTP_TIMEOUT_MS", "300");
    cmd
}

fn run_shell(config_dir: &Path, script: &str) -> assert_cmd::assert::Assert {
    gpr(config_dir)
        .args(["run", "--slug", "t", "--", "sh", "-c", script])
        .assert()
}

#[test]
fn passes_through_exit_zero() {
    let dir = TempDir::new().unwrap();
    run_shell(dir.path(), "exit 0").code(0);
}

#[test]
fn passes_through_exit_one() {
    let dir = TempDir::new().unwrap();
    run_shell(dir.path(), "exit 1").code(1);
}

#[test]
fn passes_through_arbitrary_code() {
    let dir = TempDir::new().unwrap();
    run_shell(dir.path(), "exit 42").code(42);
}

#[test]
fn passes_through_exit_130() {
    let dir = TempDir::new().unwrap();
    run_shell(dir.path(), "exit 130").code(130);
}

#[cfg(unix)]
#[test]
fn sigterm_becomes_143() {
    let dir = TempDir::new().unwrap();
    // Process kills itself with SIGTERM (15) → shell convention 128+15 = 143.
    run_shell(dir.path(), "kill -TERM $$").code(143);
}

#[cfg(unix)]
#[test]
fn sigkill_becomes_137() {
    let dir = TempDir::new().unwrap();
    // SIGKILL (9) → 128+9 = 137.
    run_shell(dir.path(), "kill -KILL $$").code(137);
}

#[test]
fn output_is_teed_to_the_caller() {
    let dir = TempDir::new().unwrap();
    gpr(dir.path())
        .args(["run", "--slug", "t", "--", "sh", "-c", "echo hello-stdout"])
        .assert()
        .code(0)
        .stdout(predicates::str::contains("hello-stdout"));
}

#[test]
fn failed_report_is_buffered_and_does_not_change_exit_code() {
    let dir = TempDir::new().unwrap();
    // A non-zero run whose report cannot be delivered.
    run_shell(dir.path(), "exit 7").code(7);
    // The run outcome landed in the offline buffer.
    let buf = dir.path().join("buffer.jsonl");
    assert!(
        buf.exists(),
        "buffer file should exist after a failed report"
    );
    let contents = std::fs::read_to_string(&buf).unwrap();
    assert!(
        contents.contains("\"exit_code\":7"),
        "buffered run should record the real exit code, got: {contents}"
    );
}

#[test]
fn missing_command_reports_127() {
    let dir = TempDir::new().unwrap();
    gpr(dir.path())
        .args([
            "run",
            "--slug",
            "t",
            "--",
            "this-command-does-not-exist-xyz",
        ])
        .assert()
        .code(127);
}
