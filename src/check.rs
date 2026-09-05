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
}
