//! Bounded offline disk queue for run reports.
//!
//! When a report send fails, the whole run is enqueued here and replayed on a
//! later invocation with its ORIGINAL timestamp, so a brief network blip never
//! turns into a false "job missed" alert. Bounded on BOTH count and total
//! bytes; drop-oldest when full — the agent must never fill a customer's disk.
//! Dedupe is by `run_id`, so a replay never double-reports.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Default cap on queued runs.
pub const DEFAULT_MAX_ENTRIES: usize = 256;
/// Default cap on total serialized bytes (~1 MiB).
pub const DEFAULT_MAX_BYTES: usize = 1024 * 1024;

/// A complete wrapped-run outcome, enough to replay both `start` and `finish`
/// with the original timestamp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BufferedRun {
    pub slug: String,
    pub run_id: String,
    /// Original RFC3339 start time — preserved verbatim on replay.
    pub started_at: String,
    pub exit_code: i32,
    pub duration_ms: u64,
    pub output_tail: String,
}

/// A drop-oldest, doubly-bounded queue persisted as JSONL.
pub struct Buffer {
    path: PathBuf,
    max_entries: usize,
    max_bytes: usize,
    entries: Vec<BufferedRun>,
}

impl Buffer {
    /// Open (or create in memory) the buffer at `path` with default bounds.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        Self::open_with_bounds(path, DEFAULT_MAX_ENTRIES, DEFAULT_MAX_BYTES)
    }

    pub fn open_with_bounds(
        path: impl Into<PathBuf>,
        max_entries: usize,
        max_bytes: usize,
    ) -> Result<Self> {
        let path = path.into();
        let entries = load(&path)?;
        Ok(Self {
            path,
            max_entries: max_entries.max(1),
            max_bytes: max_bytes.max(1),
            entries,
        })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Snapshot of queued runs (front = oldest). For inspection/tests.
    #[cfg(test)]
    pub fn entries(&self) -> &[BufferedRun] {
        &self.entries
    }

    /// Enqueue a run and persist. Dedupe by `run_id` (an existing entry with the
    /// same id is replaced in place). Enforces both bounds, dropping oldest.
    pub fn enqueue(&mut self, run: BufferedRun) -> Result<()> {
        if let Some(slot) = self.entries.iter_mut().find(|e| e.run_id == run.run_id) {
            *slot = run;
        } else {
            self.entries.push(run);
        }
        self.enforce_bounds();
        self.persist()
    }

    /// Attempt to send every queued run via `send` (front = oldest first). A run
    /// is removed only when `send` returns `Ok(())`; on the first failure we
    /// stop and keep the rest for next time. Returns the number sent.
    pub fn flush<F>(&mut self, mut send: F) -> Result<usize>
    where
        F: FnMut(&BufferedRun) -> Result<()>,
    {
        let mut sent = 0usize;
        while let Some(front) = self.entries.first() {
            match send(front) {
                Ok(()) => {
                    self.entries.remove(0);
                    sent += 1;
                }
                Err(_) => break,
            }
        }
        if sent > 0 {
            self.persist()?;
        }
        Ok(sent)
    }

    fn enforce_bounds(&mut self) {
        // Count bound.
        while self.entries.len() > self.max_entries {
            self.entries.remove(0);
        }
        // Byte bound — drop oldest until under cap (always keep at least one so a
        // single oversized entry is still recorded rather than silently lost).
        while self.entries.len() > 1 && self.total_bytes() > self.max_bytes {
            self.entries.remove(0);
        }
    }

    fn total_bytes(&self) -> usize {
        self.entries
            .iter()
            .map(|e| serde_json::to_vec(e).map(|v| v.len() + 1).unwrap_or(0))
            .sum()
    }

    fn persist(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("creating buffer dir {}", parent.display()))?;
        }
        let mut out = String::new();
        for e in &self.entries {
            out.push_str(&serde_json::to_string(e).context("serializing buffered run")?);
            out.push('\n');
        }
        let tmp = self.path.with_extension("jsonl.tmp");
        fs::write(&tmp, out.as_bytes()).with_context(|| format!("writing {}", tmp.display()))?;
        fs::rename(&tmp, &self.path)
            .with_context(|| format!("renaming into {}", self.path.display()))?;
        Ok(())
    }
}

fn load(path: &Path) -> Result<Vec<BufferedRun>> {
    match fs::read_to_string(path) {
        Ok(text) => {
            let mut out = Vec::new();
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                // Tolerate a corrupt trailing/partial line rather than losing the
                // whole queue.
                if let Ok(run) = serde_json::from_str::<BufferedRun>(line) {
                    // Dedupe on load, keeping the latest for a run_id.
                    if let Some(slot) = out
                        .iter_mut()
                        .find(|e: &&mut BufferedRun| e.run_id == run.run_id)
                    {
                        *slot = run;
                    } else {
                        out.push(run);
                    }
                }
            }
            Ok(out)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e).with_context(|| format!("reading buffer {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn run(id: &str) -> BufferedRun {
        BufferedRun {
            slug: "t".into(),
            run_id: id.into(),
            started_at: "2026-08-25T00:00:00Z".into(),
            exit_code: 0,
            duration_ms: 10,
            output_tail: "ok".into(),
        }
    }

    #[test]
    fn drops_oldest_past_count_cap_and_stays_bounded() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("buffer.jsonl");
        let mut buf = Buffer::open_with_bounds(&path, 3, DEFAULT_MAX_BYTES).unwrap();
        for i in 0..10 {
            buf.enqueue(run(&format!("id-{i}"))).unwrap();
        }
        assert_eq!(buf.len(), 3, "count bound enforced");
        let ids: Vec<_> = buf.entries().iter().map(|e| e.run_id.clone()).collect();
        assert_eq!(ids, vec!["id-7", "id-8", "id-9"], "oldest dropped first");

        // Survives reopen.
        let buf2 = Buffer::open_with_bounds(&path, 3, DEFAULT_MAX_BYTES).unwrap();
        assert_eq!(buf2.len(), 3);
    }

    #[test]
    fn byte_bound_drops_oldest() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("buffer.jsonl");
        // Tiny byte cap; each entry is well over it, so only the newest remains.
        let mut buf = Buffer::open_with_bounds(&path, 100, 200).unwrap();
        for i in 0..5 {
            let mut r = run(&format!("id-{i}"));
            r.output_tail = "x".repeat(150);
            buf.enqueue(r).unwrap();
        }
        assert!(
            buf.len() <= 2,
            "byte bound keeps queue small, got {}",
            buf.len()
        );
    }

    #[test]
    fn replay_preserves_timestamp_and_dedupes_by_run_id() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("buffer.jsonl");
        let mut buf = Buffer::open(&path).unwrap();

        let mut a = run("run-a");
        a.started_at = "2026-08-25T03:14:02Z".into();
        buf.enqueue(a.clone()).unwrap();
        // Enqueue same run_id again (e.g. a retry) — must not duplicate.
        buf.enqueue(a.clone()).unwrap();
        buf.enqueue(run("run-b")).unwrap();
        assert_eq!(buf.len(), 2, "same run_id deduped");

        // Flush and capture what would be sent.
        let mut seen: Vec<(String, String)> = Vec::new();
        let sent = buf
            .flush(|r| {
                seen.push((r.run_id.clone(), r.started_at.clone()));
                Ok(())
            })
            .unwrap();
        assert_eq!(sent, 2);
        assert_eq!(buf.len(), 0);
        // Original timestamp preserved on replay.
        assert_eq!(seen[0], ("run-a".into(), "2026-08-25T03:14:02Z".into()));
    }

    #[test]
    fn flush_stops_on_failure_and_keeps_remainder() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("buffer.jsonl");
        let mut buf = Buffer::open(&path).unwrap();
        buf.enqueue(run("a")).unwrap();
        buf.enqueue(run("b")).unwrap();
        buf.enqueue(run("c")).unwrap();

        let mut n = 0;
        let sent = buf
            .flush(|_| {
                n += 1;
                if n == 2 {
                    Err(anyhow::anyhow!("network down"))
                } else {
                    Ok(())
                }
            })
            .unwrap();
        assert_eq!(sent, 1, "only the first was delivered");
        assert_eq!(buf.len(), 2, "failed + untried remain");
        assert_eq!(buf.entries()[0].run_id, "b");
    }
}
