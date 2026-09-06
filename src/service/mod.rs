//! `gpr service` — register `gpr watch` with the host init system so it starts on
//! boot. `unit` is the pure renderer; this module is the thin privileged shell
//! (file writes + systemctl/launchctl). Verified by build + manual run.

pub mod unit;

use std::process::Command;

use crate::brand;
use crate::config::Config;
use unit::{
    launchd_path, render_launchd, render_systemd, systemd_path, Scope, UnitParams, LAUNCHD_LABEL,
    SERVICE_NAME,
};

/// The `gpr service` sub-actions.
pub enum ServiceCmd {
    Install { user: bool },
    Uninstall { user: bool },
    Status,
}

/// Which init system this host uses.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Init {
    Systemd,
    Launchd,
    Unsupported,
}

fn detect_init() -> Init {
    if cfg!(target_os = "linux") {
        Init::Systemd
    } else if cfg!(target_os = "macos") {
        Init::Launchd
    } else {
        Init::Unsupported
    }
}

pub fn cmd_service(action: ServiceCmd) -> i32 {
    let init = detect_init();
    if init == Init::Unsupported {
        eprintln!(
            "{}: auto-start is supported on Linux (systemd) and macOS (launchd) only",
            brand::CLI
        );
        return 1;
    }
    match action {
        ServiceCmd::Install { user } => install(init, scope(user)),
        ServiceCmd::Uninstall { user } => uninstall(init, scope(user)),
        ServiceCmd::Status => status(init),
    }
}

fn scope(user: bool) -> Scope {
    if user {
        Scope::User
    } else {
        Scope::System
    }
}

/// Absolute path to this gpr binary, for the unit's ExecStart.
fn exec_path() -> String {
    std::env::current_exe()
        .and_then(|p| p.canonicalize())
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| brand::CLI.to_string())
}

/// The home dir of the user the service will run as (the human, under sudo).
fn run_home(scope: Scope) -> Option<String> {
    match scope {
        // Under sudo, HOME is root's — resolve the invoking user's home instead.
        Scope::System => std::env::var("SUDO_USER").ok().map(|u| {
            if cfg!(target_os = "macos") {
                format!("/Users/{u}")
            } else {
                format!("/home/{u}")
            }
        }),
        Scope::User => std::env::var("HOME").ok(),
    }
}

fn build_params(scope: Scope) -> UnitParams {
    let run_user = match scope {
        Scope::System => std::env::var("SUDO_USER").ok(),
        Scope::User => None,
    };
    UnitParams {
        exec_path: exec_path(),
        scope,
        run_user,
        home: if detect_init() == Init::Launchd {
            run_home(scope)
        } else {
            None
        },
        config_dir: std::env::var("GPR_CONFIG_DIR").ok(),
    }
}

fn unit_file(init: Init, scope: Scope, home: &str) -> std::path::PathBuf {
    match init {
        Init::Systemd => systemd_path(scope, home),
        Init::Launchd => launchd_path(scope, home),
        Init::Unsupported => unreachable!(),
    }
}

fn home_for_path(scope: Scope) -> String {
    run_home(scope)
        .or_else(|| std::env::var("HOME").ok())
        .unwrap_or_default()
}

/// Run a command, echoing it; return whether it succeeded.
fn run(cmd: &str, args: &[&str]) -> bool {
    eprintln!("{}: + {cmd} {}", brand::CLI, args.join(" "));
    Command::new(cmd)
        .args(args)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn install(init: Init, scope: Scope) -> i32 {
    let params = build_params(scope);
    let text = match init {
        Init::Systemd => render_systemd(&params),
        Init::Launchd => render_launchd(&params),
        Init::Unsupported => unreachable!(),
    };
    let path = unit_file(init, scope, &home_for_path(scope));

    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = std::fs::write(&path, &text) {
        if e.kind() == std::io::ErrorKind::PermissionDenied && scope == Scope::System {
            eprintln!(
                "{}: writing {} needs root — re-run with: sudo {} service install",
                brand::CLI,
                path.display(),
                brand::CLI
            );
        } else {
            eprintln!("{}: could not write {}: {e}", brand::CLI, path.display());
        }
        return 1;
    }
    eprintln!("{}: wrote {}", brand::CLI, path.display());

    let ok = match (init, scope) {
        (Init::Systemd, Scope::System) => {
            run("systemctl", &["daemon-reload"])
                && run("systemctl", &["enable", "--now", SERVICE_NAME])
        }
        (Init::Systemd, Scope::User) => {
            let r = run("systemctl", &["--user", "daemon-reload"])
                && run("systemctl", &["--user", "enable", "--now", SERVICE_NAME]);
            eprintln!(
                "{}: to keep it running after logout/reboot: loginctl enable-linger",
                brand::CLI
            );
            r
        }
        (Init::Launchd, Scope::System) => run(
            "launchctl",
            &["bootstrap", "system", &path.to_string_lossy()],
        ),
        (Init::Launchd, Scope::User) => run(
            "launchctl",
            &[
                "bootstrap",
                &format!("gui/{}", uid()),
                &path.to_string_lossy(),
            ],
        ),
        (Init::Unsupported, _) => unreachable!(),
    };
    if !ok {
        eprintln!(
            "{}: the unit was written but enabling it failed — see the command output above",
            brand::CLI
        );
        return 1;
    }

    // The daemon needs a token to report; warn (don't fail) if none is set yet.
    if Config::load_or_init()
        .map(|c| c.token.is_none())
        .unwrap_or(true)
    {
        eprintln!(
            "{}: NOTE this host isn't logged in yet — run `{} login <token>` or the service will idle",
            brand::CLI,
            brand::CLI
        );
    }
    println!(
        "{}: gpr watch will now start on boot and restart on failure",
        brand::CLI
    );
    0
}

fn uninstall(init: Init, scope: Scope) -> i32 {
    let path = unit_file(init, scope, &home_for_path(scope));
    if !path.exists() {
        println!(
            "{}: nothing to remove ({} not present)",
            brand::CLI,
            path.display()
        );
        return 0;
    }
    match (init, scope) {
        (Init::Systemd, Scope::System) => {
            run("systemctl", &["disable", "--now", SERVICE_NAME]);
        }
        (Init::Systemd, Scope::User) => {
            run("systemctl", &["--user", "disable", "--now", SERVICE_NAME]);
        }
        (Init::Launchd, Scope::System) => {
            run(
                "launchctl",
                &["bootout", &format!("system/{LAUNCHD_LABEL}")],
            );
        }
        (Init::Launchd, Scope::User) => {
            run(
                "launchctl",
                &["bootout", &format!("gui/{}/{LAUNCHD_LABEL}", uid())],
            );
        }
        (Init::Unsupported, _) => unreachable!(),
    }
    if let Err(e) = std::fs::remove_file(&path) {
        if e.kind() == std::io::ErrorKind::PermissionDenied && scope == Scope::System {
            eprintln!(
                "{}: removing {} needs root — re-run with: sudo {} service uninstall",
                brand::CLI,
                path.display(),
                brand::CLI
            );
            return 1;
        }
        eprintln!("{}: could not remove {}: {e}", brand::CLI, path.display());
        return 1;
    }
    if init == Init::Systemd {
        let reload: &[&str] = if scope == Scope::User {
            &["--user", "daemon-reload"]
        } else {
            &["daemon-reload"]
        };
        run("systemctl", reload);
    }
    println!("{}: removed the gpr auto-start service", brand::CLI);
    0
}

fn status(init: Init) -> i32 {
    let mut any = false;
    for scope in [Scope::System, Scope::User] {
        let path = unit_file(init, scope, &home_for_path(scope));
        let label = match scope {
            Scope::System => "system",
            Scope::User => "user",
        };
        if !path.exists() {
            continue;
        }
        any = true;
        let state = match (init, scope) {
            (Init::Systemd, Scope::System) => {
                active_word(run_out("systemctl", &["is-active", SERVICE_NAME]))
            }
            (Init::Systemd, Scope::User) => {
                active_word(run_out("systemctl", &["--user", "is-active", SERVICE_NAME]))
            }
            (Init::Launchd, _) => "installed".to_string(),
            (Init::Unsupported, _) => unreachable!(),
        };
        println!("{label}: {state}  ({})", path.display());
    }
    if !any {
        println!("{}: not installed", brand::CLI);
    }
    0
}

fn active_word(out: Option<String>) -> String {
    match out.as_deref().map(str::trim) {
        Some("active") => "running".to_string(),
        Some(other) if !other.is_empty() => other.to_string(),
        _ => "installed".to_string(),
    }
}

fn run_out(cmd: &str, args: &[&str]) -> Option<String> {
    Command::new(cmd)
        .args(args)
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
}

/// Current uid for launchd user-domain targets. Read from an env the OS sets, so
/// no `getuid` FFI is needed; falls back to `id -u`, then 501 (first macOS user).
fn uid() -> String {
    std::env::var("UID")
        .ok()
        .or_else(|| run_out("id", &["-u"]).map(|s| s.trim().to_string()))
        .unwrap_or_else(|| "501".to_string())
}
