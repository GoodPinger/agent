//! `gpr run --slug <slug> -- <cmd...>` — wrap a command, report its outcome,
//! and pass its exit code through UNCHANGED.
//!
//! The wrapped command's stdout/stderr are inherited-by-tee: streamed to the
//! real terminal AND mirrored into a bounded ring buffer so the last few KB can
//! be reported. Reporting failure NEVER changes the exit code — a failed send
//! is buffered for later replay.

use std::io::{Read, Write};
use std::panic::AssertUnwindSafe;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::brand;
use crate::buffer::{Buffer, BufferedRun};
use crate::config::{self, Config};
use crate::redact::Redactor;
use crate::transport::{Client, FinishReq, StartReq};

/// Bounded tail of combined stdout+stderr (protocol `output_tail` ≤ 8 KB).
const OUTPUT_TAIL_BYTES: usize = 8 * 1024;
/// Exit code when the wrapped command cannot be spawned (shell convention).
const EXIT_CANNOT_EXEC: i32 = 127;

/// A fixed-size, drop-oldest byte ring holding the tail of combined output.
struct RingTail {
    buf: Vec<u8>,
    cap: usize,
}

impl RingTail {
    fn new(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap.min(4096)),
            cap,
        }
    }

    fn push(&mut self, data: &[u8]) {
        if data.len() >= self.cap {
            // Keep only the trailing `cap` bytes of this chunk.
            self.buf.clear();
            self.buf.extend_from_slice(&data[data.len() - self.cap..]);
            return;
        }
        self.buf.extend_from_slice(data);
        if self.buf.len() > self.cap {
            let excess = self.buf.len() - self.cap;
            self.buf.drain(0..excess);
        }
    }

    fn into_string(self) -> String {
        String::from_utf8_lossy(&self.buf).into_owned()
    }
}

/// Entry point wired from `main`. Returns the code the process must exit with.
pub fn cmd_run(slug: &str, command: &[String]) -> i32 {
    // Config load failing must not stop the wrapped command from running — that
    // would break the passthrough promise. Degrade to "no reporting".
    let cfg = Config::load_or_init().ok();

    let started_at = chrono::Utc::now();
    let run_id = uuid::Uuid::now_v7().to_string();

    // Build a client if we have config; reporting is entirely best-effort.
    let client = cfg.as_ref().map(|c| {
        Client::new(
            c.effective_base_url(),
            c.token.clone(),
            config::http_timeout(),
        )
    });
    let client = match client {
        Some(Ok(c)) => Some(c),
        Some(Err(e)) => {
            eprintln!("{}: reporting disabled: {e}", brand::CLI);
            None
        }
        None => None,
    };

    // Best-effort start ping (buffered runs already carry started_at, so a lost
    // start is fine).
    if let Some(client) = &client {
        let _ = client.start(
            slug,
            &StartReq {
                run_id: run_id.clone(),
                host: cfg.as_ref().map(|c| c.host_id.clone()).unwrap_or_default(),
                started_at: started_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            },
        );
    }

    // Run the wrapped command and capture its outcome. This never panics out.
    let outcome = execute(command);

    // Redact the captured tail BEFORE it is buffered or sent.
    let tail = Redactor::new().redact(&outcome.tail);

    let finish = FinishReq {
        run_id: run_id.clone(),
        exit_code: outcome.exit_code,
        duration_ms: outcome.duration_ms,
        output_tail: tail.clone(),
    };

    report(client.as_ref(), slug, &started_at, &finish);

    // The wrapped command's code, unchanged.
    outcome.exit_code
}

struct Outcome {
    exit_code: i32,
    duration_ms: u64,
    tail: String,
}

/// Spawn the command, tee its output to the terminal while capturing a bounded
/// tail, and resolve its exit code (128+signo on signal death, per shell
/// convention / protocol.md).
fn execute(command: &[String]) -> Outcome {
    let ring = Arc::new(Mutex::new(RingTail::new(OUTPUT_TAIL_BYTES)));
    let start = Instant::now();

    let mut child = match Command::new(&command[0])
        .args(&command[1..])
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}: cannot run `{}`: {e}", brand::CLI, command[0]);
            return Outcome {
                exit_code: EXIT_CANNOT_EXEC,
                duration_ms: start.elapsed().as_millis() as u64,
                tail: format!("cannot run `{}`: {e}", command[0]),
            };
        }
    };

    // Tee stdout and stderr on their own threads. Each thread body is isolated
    // with catch_unwind so a pump panic can never take down the run or the
    // exit-code handling.
    let mut pumps = Vec::new();
    if let Some(out) = child.stdout.take() {
        let ring = Arc::clone(&ring);
        pumps.push(std::thread::spawn(move || {
            let _ = std::panic::catch_unwind(AssertUnwindSafe(|| {
                pump(out, Sink::Out, &ring);
            }));
        }));
    }
    if let Some(err) = child.stderr.take() {
        let ring = Arc::clone(&ring);
        pumps.push(std::thread::spawn(move || {
            let _ = std::panic::catch_unwind(AssertUnwindSafe(|| {
                pump(err, Sink::Err, &ring);
            }));
        }));
    }

    let status = child.wait();
    for p in pumps {
        let _ = p.join();
    }
    let duration_ms = start.elapsed().as_millis() as u64;

    let exit_code = match status {
        Ok(status) => exit_code_of(status),
        Err(e) => {
            eprintln!("{}: failed waiting on child: {e}", brand::CLI);
            EXIT_CANNOT_EXEC
        }
    };

    let tail = match Arc::try_unwrap(ring) {
        Ok(m) => m
            .into_inner()
            .unwrap_or_else(|e| e.into_inner())
            .into_string(),
        // Threads still hold a ref (shouldn't happen after join) — read a copy.
        Err(arc) => arc
            .lock()
            .map(|g| String::from_utf8_lossy(&g.buf).into_owned())
            .unwrap_or_default(),
    };

    Outcome {
        exit_code,
        duration_ms,
        tail,
    }
}

enum Sink {
    Out,
    Err,
}

/// Copy `src` to the real stream while mirroring into the ring buffer.
fn pump<R: Read>(mut src: R, sink: Sink, ring: &Arc<Mutex<RingTail>>) {
    let mut buf = [0u8; 4096];
    loop {
        match src.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let chunk = &buf[..n];
                match sink {
                    Sink::Out => {
                        let mut w = std::io::stdout();
                        let _ = w.write_all(chunk);
                        let _ = w.flush();
                    }
                    Sink::Err => {
                        let mut w = std::io::stderr();
                        let _ = w.write_all(chunk);
                        let _ = w.flush();
                    }
                }
                if let Ok(mut r) = ring.lock() {
                    r.push(chunk);
                }
            }
            Err(_) => break,
        }
    }
}

/// Resolve a child's exit code: real code, or 128+signal on signal death.
fn exit_code_of(status: ExitStatus) -> i32 {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return 128 + sig;
        }
    }
    status.code().unwrap_or(EXIT_CANNOT_EXEC)
}

/// Send the finish report; on any failure, buffer the whole run for replay.
/// After a successful send, opportunistically drain any previously buffered
/// runs. Never returns an error that could affect the exit code.
fn report(
    client: Option<&Client>,
    slug: &str,
    started_at: &chrono::DateTime<chrono::Utc>,
    finish: &FinishReq,
) {
    let client = match client {
        Some(c) => c,
        None => return,
    };

    match client.finish(slug, finish) {
        Ok(()) => {
            // Network is up — try to drain the backlog too.
            drain_buffer(client);
        }
        Err(e) => {
            eprintln!("{}: report deferred (buffering): {e}", brand::CLI);
            buffer_run(slug, started_at, finish);
        }
    }
}

fn buffer_run(slug: &str, started_at: &chrono::DateTime<chrono::Utc>, finish: &FinishReq) {
    let path = match Config::buffer_path() {
        Ok(p) => p,
        Err(_) => return,
    };
    let Ok(mut buf) = Buffer::open(path) else {
        return;
    };
    let run = BufferedRun {
        slug: slug.to_string(),
        run_id: finish.run_id.clone(),
        started_at: started_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        exit_code: finish.exit_code,
        duration_ms: finish.duration_ms,
        output_tail: finish.output_tail.clone(),
    };
    let _ = buf.enqueue(run);
}

/// Replay buffered runs, re-sending start (original timestamp) then finish.
fn drain_buffer(client: &Client) {
    let path = match Config::buffer_path() {
        Ok(p) => p,
        Err(_) => return,
    };
    let host = Config::load_or_init()
        .map(|c| c.host_id)
        .unwrap_or_default();
    let Ok(mut buf) = Buffer::open(path) else {
        return;
    };
    if buf.is_empty() {
        return;
    }
    let _ = buf.flush(|r| {
        // Best-effort replay of start with the ORIGINAL timestamp.
        let _ = client.start(
            &r.slug,
            &StartReq {
                run_id: r.run_id.clone(),
                host: host.clone(),
                started_at: r.started_at.clone(),
            },
        );
        client.finish(
            &r.slug,
            &FinishReq {
                run_id: r.run_id.clone(),
                exit_code: r.exit_code,
                duration_ms: r.duration_ms,
                output_tail: r.output_tail.clone(),
            },
        )
    });
}
