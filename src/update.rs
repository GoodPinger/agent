//! `gpr update` — self-update from the public GitHub Releases. Downloads the
//! release binary for this platform, verifies its SHA-256, and atomically swaps
//! it in. The pure helpers (target/asset/version/checksum) are unit-tested; the
//! download + replace is thin I/O verified by hand.

use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::brand;

/// The release target triple for this build — matches the release workflow's
/// asset names. Empty on an unsupported platform.
pub fn target_triple() -> &'static str {
    if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        "x86_64-unknown-linux-musl"
    } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
        "aarch64-unknown-linux-musl"
    } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        "x86_64-apple-darwin"
    } else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        "aarch64-apple-darwin"
    } else if cfg!(all(target_os = "windows", target_arch = "x86_64")) {
        "x86_64-pc-windows-msvc"
    } else {
        ""
    }
}

/// Release asset filename for a target (`gpr-<target>`, `.exe` on Windows).
pub fn asset_name(target: &str) -> String {
    if target.contains("windows") {
        format!("gpr-{target}.exe")
    } else {
        format!("gpr-{target}")
    }
}

/// Extract the version (tag without a leading `v`) from a GitHub "latest release"
/// JSON response. `None` if the field is absent.
pub fn parse_latest_version(json: &str) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct Rel {
        tag_name: String,
    }
    let rel: Rel = serde_json::from_str(json).ok()?;
    Some(rel.tag_name.trim_start_matches('v').to_string())
}

/// True if `latest` is a newer semver than `current` (numeric, 3 components).
pub fn is_newer(latest: &str, current: &str) -> bool {
    let parse = |v: &str| -> [u64; 3] {
        let mut out = [0u64; 3];
        for (i, part) in v.split('.').take(3).enumerate() {
            out[i] = part.parse().unwrap_or(0);
        }
        out
    };
    parse(latest) > parse(current)
}

/// Verify `data` against a `.sha256` file's contents (its first token is the hex
/// digest, as produced by `sha256sum`/`shasum -a 256`).
pub fn verify_sha256(data: &[u8], sha_file: &str) -> bool {
    let expected = sha_file
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_lowercase();
    if expected.len() != 64 {
        return false;
    }
    let mut hasher = Sha256::new();
    hasher.update(data);
    let got = hasher.finalize();
    let got_hex: String = got.iter().map(|b| format!("{b:02x}")).collect();
    got_hex == expected
}

/// `gpr update`.
pub fn cmd_update() -> i32 {
    let target = target_triple();
    if target.is_empty() {
        eprintln!(
            "{}: self-update is not available on this platform",
            brand::CLI
        );
        return 1;
    }
    let client = match reqwest::blocking::Client::builder()
        .user_agent(brand::user_agent())
        .timeout(Duration::from_secs(60))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}: {e}", brand::CLI);
            return 1;
        }
    };

    // Latest release version.
    let api = format!(
        "https://api.github.com/repos/{}/releases/latest",
        brand::RELEASE_REPO
    );
    let latest = match client
        .get(&api)
        .header("Accept", "application/vnd.github+json")
        .send()
        .and_then(|r| r.error_for_status())
        .and_then(|r| r.text())
    {
        Ok(body) => match parse_latest_version(&body) {
            Some(v) => v,
            None => {
                eprintln!("{}: could not read the latest release version", brand::CLI);
                return 1;
            }
        },
        Err(e) => {
            eprintln!("{}: could not reach the release server: {e}", brand::CLI);
            return 1;
        }
    };

    if !is_newer(&latest, brand::VERSION) {
        println!("{}: already up to date (v{})", brand::CLI, brand::VERSION);
        return 0;
    }

    // Download the binary + its checksum for this target.
    let asset = asset_name(target);
    let base = format!(
        "https://github.com/{}/releases/download/v{latest}",
        brand::RELEASE_REPO
    );
    let bin = match client
        .get(format!("{base}/{asset}"))
        .send()
        .and_then(|r| r.error_for_status())
        .and_then(|r| r.bytes())
    {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{}: could not download {asset}: {e}", brand::CLI);
            return 1;
        }
    };
    let sha = match client
        .get(format!("{base}/{asset}.sha256"))
        .send()
        .and_then(|r| r.error_for_status())
        .and_then(|r| r.text())
    {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{}: could not download the checksum: {e}", brand::CLI);
            return 1;
        }
    };
    if !verify_sha256(&bin, &sha) {
        eprintln!(
            "{}: checksum mismatch — refusing to install a corrupt or tampered binary",
            brand::CLI
        );
        return 1;
    }

    // Swap it in.
    let exe = match std::env::current_exe().and_then(|p| p.canonicalize()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{}: could not locate the running binary: {e}", brand::CLI);
            return 1;
        }
    };
    match replace_binary(&exe, &bin) {
        Ok(()) => {
            println!(
                "{}: updated {} -> {latest}. Restart `{} watch` (or `sudo {} service …`) to run the new version.",
                brand::CLI,
                brand::VERSION,
                brand::CLI,
                brand::CLI
            );
            0
        }
        Err(e) => {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                eprintln!(
                    "{}: updating {} needs write permission — re-run with: sudo {} update",
                    brand::CLI,
                    exe.display(),
                    brand::CLI
                );
            } else {
                eprintln!("{}: could not replace {}: {e}", brand::CLI, exe.display());
            }
            1
        }
    }
}

/// Atomically replace the on-disk binary: write a temp file beside it, mark it
/// executable, then rename over the original (works on Unix while running).
#[cfg(unix)]
fn replace_binary(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let tmp = path.with_extension("new");
    std::fs::write(&tmp, data)?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(not(unix))]
fn replace_binary(_path: &std::path::Path, _data: &[u8]) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "self-update is not supported on this platform; re-run the installer",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asset_name_per_platform() {
        assert_eq!(
            asset_name("x86_64-unknown-linux-musl"),
            "gpr-x86_64-unknown-linux-musl"
        );
        assert_eq!(
            asset_name("aarch64-apple-darwin"),
            "gpr-aarch64-apple-darwin"
        );
        assert_eq!(
            asset_name("x86_64-pc-windows-msvc"),
            "gpr-x86_64-pc-windows-msvc.exe"
        );
    }

    #[test]
    fn target_triple_is_a_known_release_target() {
        // On any host the test runs, it must be one of the shipped targets.
        let t = target_triple();
        assert!(
            [
                "x86_64-unknown-linux-musl",
                "aarch64-unknown-linux-musl",
                "x86_64-apple-darwin",
                "aarch64-apple-darwin",
                "x86_64-pc-windows-msvc"
            ]
            .contains(&t),
            "unexpected target: {t}"
        );
    }

    #[test]
    fn parse_latest_version_strips_v() {
        assert_eq!(
            parse_latest_version(r#"{"tag_name":"v0.1.8"}"#).as_deref(),
            Some("0.1.8")
        );
        assert_eq!(
            parse_latest_version(r#"{"tag_name":"0.2.0","x":1}"#).as_deref(),
            Some("0.2.0")
        );
        assert_eq!(parse_latest_version(r#"{"nope":1}"#), None);
        assert_eq!(parse_latest_version("not json"), None);
    }

    #[test]
    fn is_newer_compares_semver() {
        assert!(is_newer("0.1.8", "0.1.7"));
        assert!(is_newer("0.2.0", "0.1.9"));
        assert!(is_newer("1.0.0", "0.9.9"));
        assert!(!is_newer("0.1.7", "0.1.7"));
        assert!(!is_newer("0.1.6", "0.1.7"));
    }

    #[test]
    fn verify_sha256_matches_and_rejects() {
        // echo -n "hello" | sha256sum
        let expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        assert!(verify_sha256(b"hello", &format!("{expected}  gpr-x")));
        assert!(!verify_sha256(
            b"hello world",
            &format!("{expected}  gpr-x")
        ));
        assert!(!verify_sha256(b"hello", "tooshort  gpr-x"));
        assert!(!verify_sha256(b"hello", ""));
    }
}
