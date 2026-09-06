//! Multi-line grouping: a stack trace split into 40 "errors" is worse than
//! useless, so continuation lines are folded into the event they belong to
//!.
//!
//! Heuristic, in order:
//!   1. A line beginning with a timestamp starts a NEW event.
//!   2. Indented / marker lines (`at `, `\tat`, `Caused by:`, `File "`, `...`)
//!      are continuations of the current event.
//!   3. An untimestamped event (a bare `Traceback (...)` header) may be closed
//!      by a terminating exception line, so Python/Java traces stay whole.
//!
//! Caps: 200 lines OR 16 KB per event, then truncate and MARK. An unterminated
//! group must hit the cap, never grow unbounded — that is how
//! log agents OOM their hosts.

use regex::Regex;

/// Caps per grouped event.
pub const DEFAULT_MAX_LINES: usize = 200;
pub const DEFAULT_MAX_BYTES: usize = 16 * 1024;

/// A completed, possibly multi-line event ready for detection + fingerprinting.
#[derive(Debug, Clone)]
pub struct Event {
    /// Joined text, newline-separated. If `truncated`, a marker line is appended.
    pub text: String,
    /// Number of source lines retained (excludes the truncation marker).
    pub line_count: usize,
    /// True if the event hit a cap and further lines were dropped.
    pub truncated: bool,
}

struct Group {
    lines: Vec<String>,
    bytes: usize,
    /// The header carried a timestamp (a reliable delimiter exists).
    timestamped: bool,
    /// A terminating exception line closed the group; the next line starts anew.
    terminated: bool,
    /// A cap was hit; further continuation lines are dropped.
    truncated: bool,
}

pub struct Grouper {
    max_lines: usize,
    max_bytes: usize,
    ts: Regex,
    cont: Regex,
    terminator: Regex,
    current: Option<Group>,
}

impl Grouper {
    pub fn new(max_lines: usize, max_bytes: usize) -> Self {
        // A timestamp at the very start of the line begins a new event.
        let ts = Regex::new(
            r"^\s*(?:\[)?(?:\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}|\d{4}/\d{2}/\d{2}\s\d{2}:\d{2}:\d{2}|[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})",
        )
        .expect("valid timestamp regex");
        // Continuation markers (Java, Python, Go, Node): leading whitespace, or a
        // known frame prefix.
        let cont = Regex::new(r#"^(?:\s+|at\s|Caused by:|\.\.\.|File ")"#)
            .expect("valid continuation regex");
        // Lines that TERMINATE an untimestamped trace: `SomeError: msg`,
        // `pkg.Qualified.Exception: msg`.
        let terminator = Regex::new(r"^[A-Za-z_][A-Za-z0-9_.]*(?:Error|Exception|Warning)\b")
            .expect("valid terminator regex");
        Self {
            max_lines: max_lines.max(1),
            max_bytes: max_bytes.max(1),
            ts,
            cont,
            terminator,
            current: None,
        }
    }

    /// Feed one (already length-capped, already redacted) line. Returns a
    /// completed event when this line closed the previous group.
    pub fn push(&mut self, line: &str) -> Option<Event> {
        let is_ts = self.ts.is_match(line);

        // No open group: this line opens one.
        if self.current.is_none() {
            self.start(line, is_ts);
            return None;
        }

        // A timestamp, or the previous group was already terminated → flush and
        // start fresh.
        let terminated = self.current.as_ref().map(|g| g.terminated).unwrap_or(false);
        if is_ts || terminated {
            let done = self.flush();
            self.start(line, is_ts);
            return done;
        }

        // Continuation of the current event.
        if self.cont.is_match(line) {
            self.append(line);
            return None;
        }

        // An untimestamped trace can be closed by its exception line; keep it in
        // the same event, then mark the group terminated.
        let untimestamped = self
            .current
            .as_ref()
            .map(|g| !g.timestamped)
            .unwrap_or(false);
        if untimestamped && self.terminator.is_match(line) {
            self.append(line);
            if let Some(g) = self.current.as_mut() {
                g.terminated = true;
            }
            return None;
        }

        // Otherwise it is a new standalone event.
        let done = self.flush();
        self.start(line, is_ts);
        done
    }

    /// Flush any open group — call once the stream ends.
    pub fn finish(&mut self) -> Option<Event> {
        self.flush()
    }

    fn start(&mut self, line: &str, timestamped: bool) {
        self.current = Some(Group {
            lines: vec![line.to_string()],
            bytes: line.len(),
            timestamped,
            terminated: false,
            truncated: false,
        });
    }

    /// Append a continuation, respecting the per-event caps. Past a cap the line
    /// is DROPPED and the group is marked truncated — it can never grow.
    fn append(&mut self, line: &str) {
        let Some(g) = self.current.as_mut() else {
            return;
        };
        if g.truncated {
            return;
        }
        if g.lines.len() >= self.max_lines || g.bytes + line.len() + 1 > self.max_bytes {
            g.truncated = true;
            return;
        }
        g.bytes += line.len() + 1;
        g.lines.push(line.to_string());
    }

    fn flush(&mut self) -> Option<Event> {
        let g = self.current.take()?;
        let line_count = g.lines.len();
        let mut text = g.lines.join("\n");
        if g.truncated {
            text.push_str("\n... [truncated: event exceeded cap]");
        }
        Some(Event {
            text,
            line_count,
            truncated: g.truncated,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group_all(input: &str) -> Vec<Event> {
        let mut g = Grouper::new(DEFAULT_MAX_LINES, DEFAULT_MAX_BYTES);
        let mut events = Vec::new();
        for line in input.lines() {
            if let Some(ev) = g.push(line) {
                events.push(ev);
            }
        }
        if let Some(ev) = g.finish() {
            events.push(ev);
        }
        events
    }

    #[test]
    fn java_stacktrace_groups_into_one_event() {
        let fixture = include_str!("../../tests/fixtures/java_stacktrace.log");
        let events = group_all(fixture);
        // header ERROR line, the whole Exception trace, then the INFO line.
        assert_eq!(events.len(), 3, "got: {events:#?}");
        let trace = &events[1];
        assert!(trace.line_count > 3, "trace should be grouped: {trace:#?}");
        assert!(trace.text.contains("NullPointerException"));
        assert!(trace.text.contains("Caused by:"));
        assert!(!trace.truncated);
    }

    #[test]
    fn python_traceback_groups_including_terminating_line() {
        let fixture = include_str!("../../tests/fixtures/python_traceback.log");
        let events = group_all(fixture);
        // ERROR header, the Traceback (with its ValueError terminator), INFO line.
        assert_eq!(events.len(), 3, "got: {events:#?}");
        let trace = &events[1];
        assert!(trace.text.starts_with("Traceback"));
        assert!(
            trace.text.contains("ValueError"),
            "terminating exception line must stay in the trace: {trace:#?}"
        );
    }

    #[test]
    fn separate_timestamped_lines_are_separate_events() {
        let input = "2024-01-01 03:14:02 ERROR one\n2024-01-01 03:14:03 ERROR two";
        let events = group_all(input);
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn unterminated_group_hits_cap_and_does_not_grow() {
        let mut g = Grouper::new(DEFAULT_MAX_LINES, DEFAULT_MAX_BYTES);
        // A header, then 5,000 continuation frames with NO closing timestamp.
        assert!(g.push("2024-01-01 03:14:02 ERROR boom").is_none());
        for i in 0..5_000 {
            assert!(
                g.push(&format!("\tat com.example.Frame{i}(File.java:{i})"))
                    .is_none(),
                "an unterminated group must never emit mid-stream"
            );
        }
        let ev = g.finish().expect("group flushes at end");
        assert!(ev.truncated, "must be marked truncated");
        assert!(
            ev.line_count <= DEFAULT_MAX_LINES,
            "must be capped at {DEFAULT_MAX_LINES} lines, got {}",
            ev.line_count
        );
        assert!(
            ev.text.len() <= DEFAULT_MAX_BYTES + 64,
            "must be capped near {DEFAULT_MAX_BYTES} bytes, got {}",
            ev.text.len()
        );
    }
}
