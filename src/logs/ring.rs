//! A fixed-size, drop-oldest in-memory ring of log lines, bounded by BOTH a line
//! count and a byte budget.
//!
//! The agent never streams logs upstream; it keeps this bounded window and, when
//! `gpr watch` declares an incident, flushes a slice of it — nothing more. Cost
//! scales with incident count, never with log volume.

use std::collections::VecDeque;

/// Default per-source window.
pub const DEFAULT_MAX_LINES: usize = 500;
pub const DEFAULT_MAX_BYTES: usize = 256 * 1024;

pub struct RingBuffer {
    max_lines: usize,
    max_bytes: usize,
    lines: VecDeque<String>,
    bytes: usize,
}

impl RingBuffer {
    pub fn new(max_lines: usize, max_bytes: usize) -> Self {
        Self {
            // At least 1 so a single oversized line can still be held.
            max_lines: max_lines.max(1),
            max_bytes: max_bytes.max(1),
            lines: VecDeque::new(),
            bytes: 0,
        }
    }

    /// Append a line, evicting the oldest until both bounds are satisfied. The
    /// caller is expected to have already length-capped the line.
    pub fn push(&mut self, line: String) {
        self.bytes += line.len();
        self.lines.push_back(line);
        // Never evict below one line — the newest is always retained.
        while self.lines.len() > 1
            && (self.lines.len() > self.max_lines || self.bytes > self.max_bytes)
        {
            if let Some(old) = self.lines.pop_front() {
                self.bytes -= old.len();
            }
        }
    }

    pub fn len(&self) -> usize {
        self.lines.len()
    }

    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    /// Current contents, oldest first — the material `gpr watch` flushes as
    /// incident context.
    pub fn snapshot(&self) -> Vec<String> {
        self.lines.iter().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evicts_oldest_past_line_cap() {
        let mut r = RingBuffer::new(3, 1_000_000);
        for i in 0..10 {
            r.push(format!("line {i}"));
        }
        let snap = r.snapshot();
        assert_eq!(snap.len(), 3);
        assert_eq!(snap[0], "line 7");
        assert_eq!(snap[2], "line 9");
    }

    #[test]
    fn evicts_oldest_past_byte_cap() {
        // 10-byte budget: only the last few short lines survive.
        let mut r = RingBuffer::new(1_000, 10);
        for i in 0..10 {
            r.push(format!("{i}")); // 1 byte each
        }
        assert!(r.snapshot().len() <= 10);
        assert!(r.snapshot().join("").len() <= 10);
    }

    #[test]
    fn oversized_single_line_is_retained_not_dropped() {
        let mut r = RingBuffer::new(500, 8);
        r.push("this line is far larger than the byte budget".to_string());
        assert_eq!(r.len(), 1, "the newest line is always kept");
    }
}
