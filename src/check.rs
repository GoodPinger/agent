//! `gpr check`: one-shot reachability probes an operator runs by
//! hand, and that `gpr watch` / `gpr doctor` can reuse to attach inside-out
//! `checks[]` to a report.
//!
//!   - `gpr check tcp <host:port>`   — is an internal service accepting connections?
//!   - `gpr check http <url>`        — does an endpoint return a healthy status?
//!   - `gpr check egress <url>`      — can we reach an outbound dependency at all?
//!
//! Each prints a single pass/fail line and exits non-zero on failure, so it drops
//! straight into a shell `&&` chain. No listening port, outbound-only — same
//! posture as the rest of the agent.

use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use crate::brand;
use crate::config;
use crate::transport::CheckReport;

/// Kinds accepted on the wire and CLI (`kind` field of `checks[]`).
pub const KIND_TCP: &str = "tcp";
pub const KIND_HTTP: &str = "http";
pub const KIND_EGRESS: &str = "egress";
pub const KIND_PIDFILE: &str = "pidfile";
pub const KIND_UDS: &str = "uds";
pub const KIND_UDS_HTTP: &str = "uds-http";

/// TCP connect probe: resolve `target` (`host:port`) and attempt a connection
/// within `timeout`. `ok` iff the connection is established.
pub fn check_tcp(target: &str, timeout: Duration) -> CheckReport {
    let start = Instant::now();
    let ok = tcp_connect(target, timeout).is_ok();
    CheckReport {
        kind: KIND_TCP.to_string(),
        target: target.to_string(),
        ok,
        ms: start.elapsed().as_millis() as u64,
    }
}

fn tcp_connect(target: &str, timeout: Duration) -> std::io::Result<()> {
    let mut addrs = target.to_socket_addrs()?;
    let addr = addrs
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no address resolved"))?;
    TcpStream::connect_timeout(&addr, timeout)?;
    Ok(())
}

/// HTTP health probe: GET `url`; `ok` iff the response status is 2xx/3xx.
pub fn check_http(url: &str, timeout: Duration) -> CheckReport {
    http_probe(KIND_HTTP, url, timeout, |status| {
        status.is_success() || status.is_redirection()
    })
}

/// Egress/reachability probe: GET `url`; `ok` iff we received ANY HTTP response.
/// A dependency that answers 401/500 is still reachable — the point is whether we
/// can get out to it, not whether it is healthy.
pub fn check_egress(url: &str, timeout: Duration) -> CheckReport {
    http_probe(KIND_EGRESS, url, timeout, |_status| true)
}

fn http_probe(
    kind: &str,
    url: &str,
    timeout: Duration,
    ok_if: impl Fn(reqwest::StatusCode) -> bool,
) -> CheckReport {
    let start = Instant::now();
    let ok = match reqwest::blocking::Client::builder()
        .user_agent(brand::user_agent())
        .connect_timeout(timeout)
        .timeout(timeout)
        .build()
    {
        Ok(client) => match client.get(url).send() {
            Ok(resp) => ok_if(resp.status()),
            Err(_) => false,
        },
        Err(_) => false,
    };
    CheckReport {
        kind: kind.to_string(),
        target: url.to_string(),
        ok,
        ms: start.elapsed().as_millis() as u64,
    }
}

/// PID-file liveness probe: read `path`, parse the PID it holds, and report `ok`
/// iff a process with that PID is currently running. This is the classic nginx /
/// apache / unicorn liveness signal — a stale pidfile whose process has exited
/// reads as down, which is exactly the failure we want to surface. Outbound-only
/// and read-only; the agent never writes or signals the process.
pub fn check_pidfile(path: &str) -> CheckReport {
    let start = Instant::now();
    let ok = pid_from_file(path).is_some_and(pid_is_alive);
    CheckReport {
        kind: KIND_PIDFILE.to_string(),
        target: path.to_string(),
        ok,
        ms: start.elapsed().as_millis() as u64,
    }
}

/// Read and parse the first integer token of a pidfile. `None` on any read/parse
/// failure (missing file, empty, non-numeric) — all of which mean "not alive".
fn pid_from_file(path: &str) -> Option<u32> {
    let contents = std::fs::read_to_string(path).ok()?;
    contents.split_whitespace().next()?.parse::<u32>().ok()
}

/// True iff a process with `pid` is currently running, via sysinfo (no `unsafe`,
/// no signals).
fn pid_is_alive(pid: u32) -> bool {
    use sysinfo::{Pid, ProcessesToUpdate, System};
    let mut sys = System::new();
    let target = Pid::from_u32(pid);
    sys.refresh_processes(ProcessesToUpdate::Some(&[target]), true);
    sys.process(target).is_some()
}

/// Unix-domain-socket connect probe: connect to the socket file at `path`; `ok`
/// iff the connection is accepted. Protocol-agnostic — the universal "is this
/// local service listening?" check, so it works for a Python WSGI app on a
/// gunicorn (HTTP) socket and a uWSGI (binary protocol) socket alike. A local
/// socket connect returns immediately (accepted) or fails fast (no listener), so
/// no network-style timeout is needed. Unix-only.
#[cfg(unix)]
pub fn check_uds(path: &str, _timeout: Duration) -> CheckReport {
    use std::os::unix::net::UnixStream;
    let start = Instant::now();
    let ok = UnixStream::connect(path).is_ok();
    CheckReport {
        kind: KIND_UDS.to_string(),
        target: path.to_string(),
        ok,
        ms: start.elapsed().as_millis() as u64,
    }
}
#[cfg(not(unix))]
pub fn check_uds(path: &str, _timeout: Duration) -> CheckReport {
    CheckReport {
        kind: KIND_UDS.to_string(),
        target: path.to_string(),
        ok: false,
        ms: 0,
    }
}

/// HTTP-over-unix-socket probe: connect the socket, send a minimal HTTP/1.0 GET,
/// and read the status line; `ok` iff it is 2xx/3xx. Confirms a WSGI app actually
/// responds (not just that the socket exists) — for HTTP-speaking sockets such as
/// gunicorn. `target` is `"<socket path> <request path>"` (see
/// [`parse_uds_http_target`]). Unix-only; hand-rolled over `UnixStream` so it adds
/// no dependency, with read/write timeouts and a bounded read.
#[cfg(unix)]
pub fn check_uds_http(target: &str, timeout: Duration) -> CheckReport {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    let start = Instant::now();
    let (sock, path) = parse_uds_http_target(target);
    let ok = (|| -> Option<bool> {
        let mut stream = UnixStream::connect(&sock).ok()?;
        stream.set_read_timeout(Some(timeout)).ok()?;
        stream.set_write_timeout(Some(timeout)).ok()?;
        let req = format!(
            "GET {path} HTTP/1.0\r\nHost: localhost\r\nUser-Agent: {}\r\nConnection: close\r\n\r\n",
            brand::user_agent()
        );
        stream.write_all(req.as_bytes()).ok()?;
        // Bounded read: the status line lives in the first bytes; never read the
        // whole body (rule 20).
        let mut buf = [0u8; 256];
        let n = stream.read(&mut buf).ok()?;
        Some(status_is_ok(&String::from_utf8_lossy(&buf[..n])))
    })()
    .unwrap_or(false);
    CheckReport {
        kind: KIND_UDS_HTTP.to_string(),
        target: target.to_string(),
        ok,
        ms: start.elapsed().as_millis() as u64,
    }
}
#[cfg(not(unix))]
pub fn check_uds_http(target: &str, _timeout: Duration) -> CheckReport {
    CheckReport {
        kind: KIND_UDS_HTTP.to_string(),
        target: target.to_string(),
        ok: false,
        ms: 0,
    }
}

/// Split a `uds-http` target into `(socket_path, request_path)`. The socket path
/// is the first whitespace-delimited token; the request path is the rest,
/// defaulting to `/`. Socket paths do not contain spaces in practice, so a single
/// space is an unambiguous delimiter.
pub fn parse_uds_http_target(target: &str) -> (String, String) {
    let mut it = target.splitn(2, char::is_whitespace);
    let sock = it.next().unwrap_or("").trim().to_string();
    let path = it
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("/")
        .to_string();
    (sock, path)
}

/// Join a socket path and request path into a `uds-http` target for storage.
pub fn join_uds_http_target(socket: &str, path: &str) -> String {
    let p = path.trim();
    format!("{} {}", socket.trim(), if p.is_empty() { "/" } else { p })
}

/// Parse the status code from an HTTP response head; `ok` iff it is 2xx/3xx.
fn status_is_ok(head: &str) -> bool {
    let first = head.lines().next().unwrap_or("");
    let code = first
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok());
    matches!(code, Some(c) if (200..=399).contains(&c))
}

/// Print a single human-readable pass/fail line for a check.
pub fn print_result(r: &CheckReport) {
    let verdict = if r.ok { "ok  " } else { "FAIL" };
    println!("[{verdict}] {} {} ({} ms)", r.kind, r.target, r.ms);
}

/// Exit code for a check result: 0 on pass, 1 on fail.
fn exit_code(r: &CheckReport) -> i32 {
    i32::from(!r.ok)
}

/// `gpr check tcp <target>`.
pub fn cmd_tcp(target: &str) -> i32 {
    let r = check_tcp(target, config::http_timeout());
    print_result(&r);
    if !r.ok {
        eprintln!(
            "{}: could not connect to {target} — check the service is listening and any firewall",
            brand::CLI
        );
    }
    exit_code(&r)
}

/// `gpr check http <url>`.
pub fn cmd_http(url: &str) -> i32 {
    let r = check_http(url, config::http_timeout());
    print_result(&r);
    if !r.ok {
        eprintln!(
            "{}: {url} did not return a healthy status — check the endpoint and DNS",
            brand::CLI
        );
    }
    exit_code(&r)
}

/// `gpr check egress <url>`.
pub fn cmd_egress(url: &str) -> i32 {
    let r = check_egress(url, config::http_timeout());
    print_result(&r);
    if !r.ok {
        eprintln!(
            "{}: cannot reach {url} — check outbound HTTPS (443), DNS, and any egress proxy",
            brand::CLI
        );
    }
    exit_code(&r)
}

/// `gpr check pidfile <path>`.
pub fn cmd_pidfile(path: &str) -> i32 {
    let r = check_pidfile(path);
    print_result(&r);
    if !r.ok {
        eprintln!(
            "{}: {path} does not name a running process — the pidfile is missing, empty, or stale",
            brand::CLI
        );
    }
    exit_code(&r)
}

/// `gpr check uds <path>`.
pub fn cmd_uds(path: &str) -> i32 {
    let r = check_uds(path, config::http_timeout());
    print_result(&r);
    if !r.ok {
        eprintln!(
            "{}: could not connect to the socket {path} — check the service is listening and the path is right",
            brand::CLI
        );
    }
    exit_code(&r)
}

/// `gpr check uds-http <socket> [path]`.
pub fn cmd_uds_http(socket: &str, path: &str) -> i32 {
    let target = join_uds_http_target(socket, path);
    let r = check_uds_http(&target, config::http_timeout());
    print_result(&r);
    if !r.ok {
        eprintln!(
            "{}: {socket} did not return a healthy HTTP status over the socket — check the app and the request path",
            brand::CLI
        );
    }
    exit_code(&r)
}

/// Run one configured check spec, dispatching on its kind. An unknown kind yields
/// a failed report (so a typo surfaces rather than silently doing nothing).
pub fn run_spec(spec: &config::CheckSpec, timeout: Duration) -> CheckReport {
    match spec.kind.as_str() {
        KIND_TCP => check_tcp(&spec.target, timeout),
        KIND_HTTP => check_http(&spec.target, timeout),
        KIND_EGRESS => check_egress(&spec.target, timeout),
        KIND_PIDFILE => check_pidfile(&spec.target),
        KIND_UDS => check_uds(&spec.target, timeout),
        KIND_UDS_HTTP => check_uds_http(&spec.target, timeout),
        _ => CheckReport {
            kind: spec.kind.clone(),
            target: spec.target.clone(),
            ok: false,
            ms: 0,
        },
    }
}

/// Run every configured check, capped at `MAX_CHECKS` (bounded — agent rule 20).
pub fn run_configured(specs: &[config::CheckSpec], timeout: Duration) -> Vec<CheckReport> {
    specs
        .iter()
        .take(config::MAX_CHECKS)
        .map(|s| run_spec(s, timeout))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::net::TcpListener;

    #[test]
    fn tcp_passes_against_a_live_listener() {
        // Bind an ephemeral port; the OS picks a free one.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let target = addr.to_string();

        let r = check_tcp(&target, Duration::from_millis(500));
        assert_eq!(r.kind, KIND_TCP);
        assert_eq!(r.target, target);
        assert!(r.ok, "expected a successful connect to {target}");
        assert_eq!(exit_code(&r), 0);
    }

    #[test]
    fn tcp_fails_against_a_closed_port() {
        // Bind then drop the listener so the port is (almost certainly) closed.
        let addr = {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap()
        };
        let target = addr.to_string();

        let r = check_tcp(&target, Duration::from_millis(300));
        assert!(!r.ok, "expected connect to a closed port to fail");
        assert_eq!(exit_code(&r), 1);
    }

    #[test]
    fn http_maps_a_live_listener_response() {
        // A minimal one-shot HTTP/1.1 server on an ephemeral port.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf);
                use std::io::Write;
                let _ = sock.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                );
            }
        });

        let url = format!("http://{addr}/");
        let r = check_http(&url, Duration::from_millis(1000));
        let _ = handle.join();

        assert_eq!(r.kind, KIND_HTTP);
        assert!(r.ok, "expected 200 to be healthy");
        assert_eq!(exit_code(&r), 0);
    }

    #[test]
    fn http_fails_when_nothing_is_listening() {
        let addr = {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap()
        };
        let url = format!("http://{addr}/");
        let r = check_http(&url, Duration::from_millis(300));
        assert!(!r.ok);
        assert_eq!(exit_code(&r), 1);
    }

    #[test]
    fn pidfile_ok_for_this_live_process() {
        // Write our own PID; we are, by definition, alive.
        let mut path = std::env::temp_dir();
        path.push(format!("gpr-pidtest-live-{}.pid", std::process::id()));
        std::fs::write(&path, format!("{}\n", std::process::id())).unwrap();

        let r = check_pidfile(path.to_str().unwrap());
        let _ = std::fs::remove_file(&path);
        assert_eq!(r.kind, KIND_PIDFILE);
        assert!(r.ok, "our own pid should read as alive");
        assert_eq!(exit_code(&r), 0);
    }

    #[test]
    fn pidfile_fails_for_a_stale_pid() {
        // A PID near u32::MAX is almost certainly not a running process.
        let mut path = std::env::temp_dir();
        path.push(format!("gpr-pidtest-stale-{}.pid", std::process::id()));
        std::fs::write(&path, "4294967294").unwrap();

        let r = check_pidfile(path.to_str().unwrap());
        let _ = std::fs::remove_file(&path);
        assert!(!r.ok, "a stale pid should read as down");
        assert_eq!(exit_code(&r), 1);
    }

    #[test]
    fn pidfile_fails_when_missing_or_empty() {
        let missing = check_pidfile("/nonexistent/gpr/does-not-exist.pid");
        assert!(!missing.ok);

        let mut path = std::env::temp_dir();
        path.push(format!("gpr-pidtest-empty-{}.pid", std::process::id()));
        std::fs::write(&path, "   \n").unwrap();
        let empty = check_pidfile(path.to_str().unwrap());
        let _ = std::fs::remove_file(&path);
        assert!(!empty.ok, "an empty pidfile is not a running process");
    }

    #[test]
    fn run_spec_dispatches_on_kind() {
        let spec = crate::config::CheckSpec {
            kind: KIND_PIDFILE.to_string(),
            target: "/nonexistent/x.pid".to_string(),
        };
        let r = run_spec(&spec, Duration::from_millis(200));
        assert_eq!(r.kind, KIND_PIDFILE);
        assert!(!r.ok);
    }

    #[test]
    fn uds_http_target_parses_and_joins() {
        assert_eq!(
            parse_uds_http_target("/run/gunicorn.sock /health"),
            ("/run/gunicorn.sock".to_string(), "/health".to_string())
        );
        // No request path defaults to "/".
        assert_eq!(
            parse_uds_http_target("/run/app.sock"),
            ("/run/app.sock".to_string(), "/".to_string())
        );
        assert_eq!(join_uds_http_target("/run/app.sock", ""), "/run/app.sock /");
        assert_eq!(
            join_uds_http_target("/run/app.sock", "/x"),
            "/run/app.sock /x"
        );
    }

    #[test]
    fn status_line_parsing() {
        assert!(status_is_ok("HTTP/1.0 200 OK\r\n"));
        assert!(status_is_ok("HTTP/1.1 301 Moved\r\n"));
        assert!(!status_is_ok("HTTP/1.1 500 Internal Server Error\r\n"));
        assert!(!status_is_ok("garbage"));
    }

    #[cfg(unix)]
    #[test]
    fn uds_connects_to_a_live_socket() {
        use std::os::unix::net::UnixListener;
        let mut path = std::env::temp_dir();
        path.push(format!("gpr-uds-live-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let target = path.to_string_lossy().to_string();

        let r = check_uds(&target, Duration::from_millis(500));
        drop(listener);
        let _ = std::fs::remove_file(&path);
        assert_eq!(r.kind, KIND_UDS);
        assert!(r.ok, "expected connect to a live unix socket");
        assert_eq!(exit_code(&r), 0);
    }

    #[cfg(unix)]
    #[test]
    fn uds_fails_when_nothing_is_listening() {
        // A path that does not exist, and a path that existed then was unbound.
        let missing = check_uds("/nonexistent/gpr/none.sock", Duration::from_millis(300));
        assert!(!missing.ok);

        use std::os::unix::net::UnixListener;
        let mut path = std::env::temp_dir();
        path.push(format!("gpr-uds-dead-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        {
            let _l = UnixListener::bind(&path).unwrap();
        } // dropped → socket file lingers but nothing accepts
        let r = check_uds(&path.to_string_lossy(), Duration::from_millis(300));
        let _ = std::fs::remove_file(&path);
        assert!(!r.ok, "expected connect to an unbound socket path to fail");
    }

    #[cfg(unix)]
    #[test]
    fn uds_http_maps_a_live_socket_response() {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixListener;
        let mut path = std::env::temp_dir();
        path.push(format!("gpr-udshttp-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let handle = std::thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf);
                let _ = sock.write_all(
                    b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                );
            }
        });
        let target = join_uds_http_target(&path.to_string_lossy(), "/health");
        let r = check_uds_http(&target, Duration::from_millis(1000));
        let _ = handle.join();
        let _ = std::fs::remove_file(&path);
        assert_eq!(r.kind, KIND_UDS_HTTP);
        assert!(r.ok, "expected 200 over the socket to be healthy");
    }

    #[cfg(unix)]
    #[test]
    fn uds_http_fails_on_5xx_and_missing_socket() {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixListener;
        let mut path = std::env::temp_dir();
        path.push(format!("gpr-udshttp-5xx-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let handle = std::thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf);
                let _ = sock.write_all(b"HTTP/1.0 502 Bad Gateway\r\nConnection: close\r\n\r\n");
            }
        });
        let r = check_uds_http(
            &join_uds_http_target(&path.to_string_lossy(), "/"),
            Duration::from_millis(1000),
        );
        let _ = handle.join();
        let _ = std::fs::remove_file(&path);
        assert!(!r.ok, "502 is not healthy");

        let missing = check_uds_http("/nonexistent/gpr/none.sock /", Duration::from_millis(300));
        assert!(!missing.ok);
    }

    #[cfg(unix)]
    #[test]
    fn run_spec_dispatches_uds_kinds() {
        let s1 = crate::config::CheckSpec {
            kind: KIND_UDS.to_string(),
            target: "/nonexistent/x.sock".to_string(),
        };
        assert_eq!(run_spec(&s1, Duration::from_millis(100)).kind, KIND_UDS);
        let s2 = crate::config::CheckSpec {
            kind: KIND_UDS_HTTP.to_string(),
            target: "/nonexistent/x.sock /".to_string(),
        };
        assert_eq!(
            run_spec(&s2, Duration::from_millis(100)).kind,
            KIND_UDS_HTTP
        );
    }

    #[test]
    fn run_configured_is_capped() {
        let specs: Vec<_> = (0..config::MAX_CHECKS + 5)
            .map(|_| crate::config::CheckSpec {
                kind: KIND_PIDFILE.to_string(),
                target: "/nonexistent/x.pid".to_string(),
            })
            .collect();
        let out = run_configured(&specs, Duration::from_millis(50));
        assert_eq!(out.len(), config::MAX_CHECKS, "must not exceed the cap");
    }
}
