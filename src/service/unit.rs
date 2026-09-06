//! Pure renderers for the systemd unit and launchd plist, plus their file paths.
//! No I/O — the shell resolves inputs and does the writing/`systemctl`/`launchctl`.

use std::path::PathBuf;

/// Install scope: boot-time system service, or per-user (login-time) service.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Scope {
    System,
    User,
}

/// Everything the unit/plist text depends on; resolved by the shell.
pub struct UnitParams {
    /// Absolute path to the gpr binary.
    pub exec_path: String,
    pub scope: Scope,
    /// systemd `User=` / launchd `UserName` (system scope, when known).
    pub run_user: Option<String>,
    /// Baked into the launchd env (launchd does not set HOME itself).
    pub home: Option<String>,
    /// Baked as GPR_CONFIG_DIR when it was set at install time.
    pub config_dir: Option<String>,
}

/// systemd unit name (`gpr.service`).
pub const SERVICE_NAME: &str = "gpr";
/// launchd label.
pub const LAUNCHD_LABEL: &str = "com.goodpinger.gpr";

/// Render the systemd unit for `p`.
pub fn render_systemd(p: &UnitParams) -> String {
    let mut s = String::new();
    s.push_str("[Unit]\n");
    s.push_str("Description=Goodpinger agent (gpr watch)\n");
    s.push_str("After=network-online.target\n");
    s.push_str("Wants=network-online.target\n\n");
    s.push_str("[Service]\n");
    s.push_str("Type=simple\n");
    s.push_str(&format!("ExecStart={} watch\n", p.exec_path));
    s.push_str("Restart=on-failure\n");
    s.push_str("RestartSec=5\n");
    if let Some(u) = &p.run_user {
        s.push_str(&format!("User={u}\n"));
    }
    if let Some(c) = &p.config_dir {
        s.push_str(&format!("Environment=GPR_CONFIG_DIR={c}\n"));
    }
    s.push_str("\n[Install]\n");
    let target = match p.scope {
        Scope::System => "multi-user.target",
        Scope::User => "default.target",
    };
    s.push_str(&format!("WantedBy={target}\n"));
    s
}

/// Render the launchd plist for `p`.
pub fn render_launchd(p: &UnitParams) -> String {
    let user_block = match (p.scope, &p.run_user) {
        (Scope::System, Some(u)) => format!("  <key>UserName</key><string>{u}</string>\n"),
        _ => String::new(),
    };
    let mut env = String::new();
    if let Some(h) = &p.home {
        env.push_str(&format!("    <key>HOME</key><string>{h}</string>\n"));
    }
    if let Some(c) = &p.config_dir {
        env.push_str(&format!(
            "    <key>GPR_CONFIG_DIR</key><string>{c}</string>\n"
        ));
    }
    let env_block = if env.is_empty() {
        String::new()
    } else {
        format!("  <key>EnvironmentVariables</key>\n  <dict>\n{env}  </dict>\n")
    };
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{label}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{exec}</string>
    <string>watch</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key>
  <dict><key>SuccessfulExit</key><false/></dict>
{user}{env}</dict>
</plist>
"#,
        label = LAUNCHD_LABEL,
        exec = p.exec_path,
        user = user_block,
        env = env_block
    )
}

/// Absolute path of the systemd unit file for `scope`.
pub fn systemd_path(scope: Scope, home: &str) -> PathBuf {
    match scope {
        Scope::System => PathBuf::from("/etc/systemd/system/gpr.service"),
        Scope::User => PathBuf::from(home).join(".config/systemd/user/gpr.service"),
    }
}

/// Absolute path of the launchd plist file for `scope`.
pub fn launchd_path(scope: Scope, home: &str) -> PathBuf {
    match scope {
        Scope::System => PathBuf::from("/Library/LaunchDaemons/com.goodpinger.gpr.plist"),
        Scope::User => PathBuf::from(home).join("Library/LaunchAgents/com.goodpinger.gpr.plist"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(scope: Scope) -> UnitParams {
        UnitParams {
            exec_path: "/usr/local/bin/gpr".to_string(),
            scope,
            run_user: match scope {
                Scope::System => Some("alice".to_string()),
                Scope::User => None,
            },
            home: Some("/home/alice".to_string()),
            config_dir: None,
        }
    }

    #[test]
    fn systemd_system_unit_has_user_and_multiuser_target() {
        let s = render_systemd(&params(Scope::System));
        assert!(s.contains("ExecStart=/usr/local/bin/gpr watch"), "{s}");
        assert!(s.contains("Restart=on-failure"), "{s}");
        assert!(s.contains("User=alice"), "{s}");
        assert!(s.contains("WantedBy=multi-user.target"), "{s}");
        assert!(
            !s.contains("GPR_CONFIG_DIR"),
            "no config dir baked when None"
        );
    }

    #[test]
    fn systemd_user_unit_omits_user_and_uses_default_target() {
        let s = render_systemd(&params(Scope::User));
        assert!(
            !s.contains("User="),
            "user-scope unit must not pin User=: {s}"
        );
        assert!(s.contains("WantedBy=default.target"), "{s}");
    }

    #[test]
    fn systemd_bakes_config_dir_when_set() {
        let mut p = params(Scope::System);
        p.config_dir = Some("/home/alice/.config/gpr".to_string());
        assert!(render_systemd(&p).contains("Environment=GPR_CONFIG_DIR=/home/alice/.config/gpr"));
    }

    #[test]
    fn launchd_daemon_has_username_program_args_and_keepalive() {
        let s = render_launchd(&params(Scope::System));
        assert!(s.contains("<string>com.goodpinger.gpr</string>"), "{s}");
        assert!(s.contains("<string>/usr/local/bin/gpr</string>"), "{s}");
        assert!(s.contains("<string>watch</string>"), "{s}");
        assert!(s.contains("<key>RunAtLoad</key>"), "{s}");
        assert!(s.contains("<key>KeepAlive</key>"), "{s}");
        assert!(
            s.contains("<key>UserName</key><string>alice</string>"),
            "{s}"
        );
        assert!(
            s.contains("<key>HOME</key><string>/home/alice</string>"),
            "{s}"
        );
    }

    #[test]
    fn launchd_agent_omits_username() {
        let s = render_launchd(&params(Scope::User));
        assert!(
            !s.contains("<key>UserName</key>"),
            "agent must not set UserName: {s}"
        );
    }

    #[test]
    fn paths_are_correct_per_scope() {
        assert_eq!(
            systemd_path(Scope::System, "/home/alice"),
            PathBuf::from("/etc/systemd/system/gpr.service")
        );
        assert_eq!(
            systemd_path(Scope::User, "/home/alice"),
            PathBuf::from("/home/alice/.config/systemd/user/gpr.service")
        );
        assert_eq!(
            launchd_path(Scope::System, "/Users/alice"),
            PathBuf::from("/Library/LaunchDaemons/com.goodpinger.gpr.plist")
        );
        assert_eq!(
            launchd_path(Scope::User, "/Users/alice"),
            PathBuf::from("/Users/alice/Library/LaunchAgents/com.goodpinger.gpr.plist")
        );
    }
}
