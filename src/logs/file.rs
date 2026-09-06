//! Resumable file tailing. Read from a persisted byte offset;
//! track files by CONTENT FINGERPRINT (first N bytes), not filename, so rotation
//! is recognized rather than re-read from the top. Truncation
//! (the file shrank in place) is handled as a DISTINCT case from rotation.
//!
//! Identity is the file's head bytes, compared by PREFIX (not a fixed-length
//! hash): a file shorter than N bytes that later grows keeps the same identity
//! because its old head is a prefix of the new one — this is what stops a small,
//! still-growing log from being mistaken for a rotation and re-read (which is the
//! classic duplicate-events bug,). A genuinely new file at the same
//! path shares no prefix and is correctly seen as rotated.
//!
//! Every read is bounded: at most `MAX_READ_PER_POLL` bytes are pulled per call,
//! and only complete lines are emitted (a partial trailing line waits for the
//! next poll), so a long line can never stall the tailer or blow memory.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;

/// Bytes read from the head of a file to identify it across rotation.
pub const FINGERPRINT_BYTES: usize = 256;
/// Upper bound on bytes read in a single `poll` (bounded work per call).
pub const MAX_READ_PER_POLL: usize = 1024 * 1024;
/// Longest single line emitted; longer lines are truncated with a marker.
pub const MAX_LINE_LEN: usize = 8 * 1024;

/// The resumable position of a file, suitable for persistence (see `state.rs`).
/// `fingerprint` is the hex-encoded head bytes, so identity survives a restart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMark {
    pub fingerprint: String,
    pub offset: u64,
}

pub struct FileTailer {
    path: PathBuf,
    /// The file's head bytes (≤ `FINGERPRINT_BYTES`), the identity we compare by
    /// prefix. `None` until the first poll.
    head: Option<Vec<u8>>,
    offset: u64,
    /// On the first poll of a never-seen file, skip to the end (live tailing)
    /// instead of replaying history. `gpr logs --test` sets this false.
    start_at_end: bool,
    initialized: bool,
}

/// Outcome of one poll: newly completed lines, plus what happened to the file.
pub struct Poll {
    pub lines: Vec<String>,
    pub rotated: bool,
    pub truncated: bool,
}

impl FileTailer {
    /// Live tailer: first poll jumps to EOF, then follows appends.
    pub fn following(path: impl Into<PathBuf>) -> Self {
        Self::make(path.into(), true)
    }

    /// Read-from-start tailer: used by `gpr logs --test` to inspect existing
    /// content.
    pub fn from_start(path: impl Into<PathBuf>) -> Self {
        Self::make(path.into(), false)
    }

    /// Resume from a persisted mark (survives agent restarts).
    pub fn resume(path: impl Into<PathBuf>, mark: FileMark) -> Self {
        Self {
            path: path.into(),
            head: Some(hex_decode(&mark.fingerprint)),
            offset: mark.offset,
            start_at_end: false,
            initialized: true,
        }
    }

    fn make(path: PathBuf, start_at_end: bool) -> Self {
        Self {
            path,
            head: None,
            offset: 0,
            start_at_end,
            initialized: false,
        }
    }

    /// The current resumable position, for persistence.
    pub fn mark(&self) -> Option<FileMark> {
        self.head.as_ref().map(|h| FileMark {
            fingerprint: hex_encode(h),
            offset: self.offset,
        })
    }

    /// Read newly-available complete lines, resolving rotation and truncation.
    pub fn poll(&mut self) -> std::io::Result<Poll> {
        let mut file = File::open(&self.path)?;
        let len = file.metadata()?.len();
        let current_head = read_head(&mut file, FINGERPRINT_BYTES)?;

        let mut rotated = false;
        let mut truncated = false;

        match &self.head {
            None => {
                // First sight of this file.
                self.offset = if self.start_at_end && !self.initialized {
                    len
                } else {
                    0
                };
            }
            Some(prev) if !same_file(prev, &current_head) => {
                // The head shares no prefix → a NEW file occupies this path
                // (rotation). Read it from the beginning; do not re-read the old.
                rotated = true;
                self.offset = 0;
            }
            Some(_) => {
                // Same file. If it shrank, it was truncated in place (`> file`),
                // which is distinct from rotation: restart at 0.
                if len < self.offset {
                    truncated = true;
                    self.offset = 0;
                }
            }
        }
        // Always adopt the freshest head so a still-growing short file keeps a
        // stable, lengthening identity.
        self.head = Some(current_head);
        self.initialized = true;

        let lines = self.read_from_offset(&mut file, len)?;
        Ok(Poll {
            lines,
            rotated,
            truncated,
        })
    }

    fn read_from_offset(&mut self, file: &mut File, len: u64) -> std::io::Result<Vec<String>> {
        if self.offset >= len {
            return Ok(Vec::new());
        }
        let want = ((len - self.offset) as usize).min(MAX_READ_PER_POLL);
        file.seek(SeekFrom::Start(self.offset))?;
        let mut buf = vec![0u8; want];
        let read = file.read(&mut buf)?;
        buf.truncate(read);

        // Emit only complete lines; keep a partial trailing line for next poll.
        let consumable = match buf.iter().rposition(|&b| b == b'\n') {
            Some(idx) => idx + 1,
            None => {
                if read == MAX_READ_PER_POLL {
                    // A single line longer than the read window: consume it so the
                    // tailer can never stall on an unterminated giant line.
                    read
                } else {
                    return Ok(Vec::new());
                }
            }
        };

        let mut lines = Vec::new();
        for chunk in buf[..consumable].split(|&b| b == b'\n') {
            if chunk.is_empty() {
                continue;
            }
            let line = String::from_utf8_lossy(chunk);
            lines.push(cap_line(line.trim_end_matches('\r')));
        }
        self.offset += consumable as u64;
        Ok(lines)
    }
}

fn cap_line(line: &str) -> String {
    if line.len() <= MAX_LINE_LEN {
        return line.to_string();
    }
    let mut end = MAX_LINE_LEN;
    while end > 0 && !line.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = line[..end].to_string();
    out.push_str("… [line truncated]");
    out
}

/// Read up to the first `n` bytes of `file` as its identity. Leaves the cursor
/// at 0 (the caller seeks explicitly before reading content).
fn read_head(file: &mut File, n: usize) -> std::io::Result<Vec<u8>> {
    file.seek(SeekFrom::Start(0))?;
    let mut head = vec![0u8; n];
    let read = file.read(&mut head)?;
    head.truncate(read);
    Ok(head)
}

/// Two heads identify the SAME file if the shorter is a non-empty prefix of the
/// longer. A still-growing short file keeps its identity; a fresh file at the
/// same path (no shared prefix) is a rotation.
fn same_file(a: &[u8], b: &[u8]) -> bool {
    let (short, long) = if a.len() <= b.len() { (a, b) } else { (b, a) };
    !short.is_empty() && long.starts_with(short)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex_decode(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    bytes
        .chunks_exact(2)
        .filter_map(|pair| {
            let hi = (pair[0] as char).to_digit(16)?;
            let lo = (pair[1] as char).to_digit(16)?;
            Some((hi * 16 + lo) as u8)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::Path;

    fn write(path: &Path, contents: &str) {
        let mut f = File::create(path).unwrap();
        f.write_all(contents.as_bytes()).unwrap();
    }

    fn append(path: &Path, contents: &str) {
        let mut f = std::fs::OpenOptions::new().append(true).open(path).unwrap();
        f.write_all(contents.as_bytes()).unwrap();
    }

    #[test]
    fn reads_from_start_then_only_new_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.log");
        write(&path, "a\nb\n");
        let mut t = FileTailer::from_start(&path);

        let p = t.poll().unwrap();
        assert_eq!(p.lines, vec!["a", "b"]);
        assert!(!p.rotated && !p.truncated);

        // Nothing new.
        assert!(t.poll().unwrap().lines.is_empty());

        append(&path, "c\n");
        assert_eq!(t.poll().unwrap().lines, vec!["c"]);
    }

    #[test]
    fn following_skips_existing_history() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.log");
        write(&path, "old1\nold2\n");
        let mut t = FileTailer::following(&path);
        // First poll on a live tailer ignores pre-existing content.
        assert!(t.poll().unwrap().lines.is_empty());
        append(&path, "new1\n");
        assert_eq!(t.poll().unwrap().lines, vec!["new1"]);
    }

    #[test]
    fn rotation_is_detected_by_fingerprint_and_not_reread() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.log");
        write(&path, "line1\nline2\n");
        let mut t = FileTailer::from_start(&path);
        assert_eq!(t.poll().unwrap().lines, vec!["line1", "line2"]);

        // Re-open the SAME file (same head bytes): must NOT re-read from the top.
        let p = t.poll().unwrap();
        assert!(!p.rotated, "same file must not look rotated");
        assert!(p.lines.is_empty(), "same file must not be re-read");

        // Rotate: a brand-new file with different head bytes at the same path.
        write(&path, "fresh1\nfresh2\n");
        let p = t.poll().unwrap();
        assert!(p.rotated, "new head bytes must be seen as rotation");
        assert_eq!(p.lines, vec!["fresh1", "fresh2"]);
    }

    #[test]
    fn truncation_is_handled_distinctly_from_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.log");
        // A long head so truncation keeps the SAME fingerprint (head unchanged
        // until it is short), forcing the size-shrank branch rather than rotation.
        let head = "X".repeat(FINGERPRINT_BYTES);
        write(&path, &format!("{head}\nkeep-a\nkeep-b\n"));
        let mut t = FileTailer::from_start(&path);
        let first = t.poll().unwrap();
        assert_eq!(first.lines.len(), 3);

        // Truncate in place to just the head line (offset now exceeds len, head
        // fingerprint unchanged) → truncation, not rotation.
        write(&path, &format!("{head}\n"));
        let p = t.poll().unwrap();
        assert!(p.truncated, "shrink with same head = truncation");
        assert!(!p.rotated, "truncation must not be misreported as rotation");
        // Offset reset to 0 and the surviving content re-read once.
        assert_eq!(p.lines, vec![head.as_str()]);
    }

    #[test]
    fn mark_round_trips_for_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.log");
        write(&path, "one\ntwo\n");
        let mut t = FileTailer::from_start(&path);
        assert_eq!(t.poll().unwrap().lines.len(), 2);
        let mark = t.mark().expect("mark after read");

        append(&path, "three\n");
        // A fresh tailer resumed from the mark reads only what came after.
        let mut resumed = FileTailer::resume(&path, mark);
        assert_eq!(resumed.poll().unwrap().lines, vec!["three"]);
    }
}
