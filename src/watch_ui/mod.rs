//! `gpr watch manage` — the interactive watch manager. `state` is the pure state
//! machine; this module is the thin crossterm shell that feeds it key events and
//! paints its output. It holds no logic and is verified by build + manual run.

pub mod state;

use std::io::{IsTerminal, Write};

use crossterm::event::{Event, KeyEventKind};
use crossterm::style::Stylize;
use crossterm::{cursor, event, execute, queue, style, terminal};

use crate::brand;
use crate::collect::{self, ProcInfo};
use crate::config::Config;
use state::{Effect, Focus, ManagerState, Mode};

/// Restores the terminal on every exit path (including panic) via `Drop`.
struct TerminalGuard;

impl TerminalGuard {
    fn enter() -> std::io::Result<Self> {
        terminal::enable_raw_mode()?;
        execute!(
            std::io::stdout(),
            terminal::EnterAlternateScreen,
            cursor::Hide
        )?;
        Ok(TerminalGuard)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = execute!(
            std::io::stdout(),
            cursor::Show,
            terminal::LeaveAlternateScreen
        );
        let _ = terminal::disable_raw_mode();
    }
}

/// `gpr watch manage` entry point.
pub fn cmd_watch_manage() -> i32 {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        eprintln!(
            "{}: `{} watch manage` needs an interactive terminal — use `{} watch add`, `list`, or `rm`",
            brand::CLI,
            brand::CLI,
            brand::CLI
        );
        return 1;
    }
    let cfg = match Config::load_or_init() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}: {e}", brand::CLI);
            return 1;
        }
    };
    let snapshot = collect::snapshot_all();

    let guard = match TerminalGuard::enter() {
        Ok(g) => g,
        Err(e) => {
            eprintln!("{}: could not set up the terminal: {e}", brand::CLI);
            return 1;
        }
    };
    // The loop must never leave raw mode dangling; catch a panic, then Drop restores.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_loop(cfg, snapshot)));
    drop(guard);
    match result {
        Ok(code) => code,
        Err(_) => {
            eprintln!("{}: watch manage exited abnormally", brand::CLI);
            1
        }
    }
}

fn run_loop(cfg: Config, snapshot: Vec<ProcInfo>) -> i32 {
    let mut st = ManagerState::new(cfg, snapshot);
    loop {
        if render(&st).is_err() {
            return 1;
        }
        let ev = match event::read() {
            Ok(e) => e,
            Err(_) => return 1,
        };
        // Only act on key *presses* (Windows/kitty also emit Release/Repeat).
        if let Event::Key(key) = ev {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            for eff in st.on_key(key) {
                match eff {
                    Effect::Quit => return 0,
                    Effect::SaveConfig => {
                        if let Err(e) = st.config().save() {
                            st.set_error(format!("save failed: {e}"));
                        }
                    }
                    Effect::Refresh => st.set_snapshot(collect::snapshot_all()),
                }
            }
        }
    }
}

/// Paint the current state. Bounded: only the rows that fit are drawn. All styling
/// is crossterm (already linked) — no TUI framework, so the binary stays small.
fn render(st: &ManagerState) -> std::io::Result<()> {
    let mut out = std::io::stdout();
    let (cols, rows) = terminal::size().unwrap_or((80, 24));
    let width = cols.max(20) as usize;
    let watched = st.watched();
    let snap = st.snapshot();

    queue!(
        out,
        terminal::Clear(terminal::ClearType::All),
        cursor::MoveTo(0, 0)
    )?;

    if st.help() {
        return render_help(&mut out, width, rows);
    }

    // Title bar.
    let title = format!(
        " gpr watch manage — {} watched · {} processes ",
        watched.len(),
        snap.len()
    );
    queue!(
        out,
        style::PrintStyledContent(pad(&title, width).black().on_yellow()),
        cursor::MoveToNextLine(2)
    )?;

    // Watchlist section.
    let wfocus = st.focus() == Focus::Watchlist;
    let wtitle = if wfocus {
        format!("WATCHLIST ({})  — dd to remove", watched.len())
    } else {
        format!("WATCHLIST ({})", watched.len())
    };
    queue!(
        out,
        style::PrintStyledContent(wtitle.bold()),
        cursor::MoveToNextLine(1)
    )?;
    if watched.is_empty() {
        queue!(
            out,
            style::PrintStyledContent("  (nothing watched yet — pick one below)".dark_grey()),
            cursor::MoveToNextLine(1)
        )?;
    }
    for (i, spec) in watched.iter().enumerate() {
        let label = match spec.pattern.as_deref() {
            Some(p) => format!("   ·  by command line: {p}"),
            None => "   ·  by name".to_string(),
        };
        if wfocus && i == st.watch_cursor() {
            let line = format!("  {}{}", spec.name, label);
            queue!(out, style::PrintStyledContent(pad(&line, width).reverse()))?;
        } else {
            queue!(
                out,
                style::Print(format!("  {}", spec.name)),
                style::PrintStyledContent(label.dark_grey())
            )?;
        }
        queue!(out, cursor::MoveToNextLine(1))?;
    }

    // Add-a-process section: header + filter line.
    queue!(
        out,
        cursor::MoveToNextLine(1),
        style::PrintStyledContent("ADD A PROCESS".bold()),
        cursor::MoveToNextLine(1)
    )?;
    let filter_line = if st.mode() == Mode::Filter {
        format!("  /{}\u{2588}", st.filter()) // block cursor while typing
    } else if st.filter().is_empty() {
        "  filter: (press / to search)".to_string()
    } else {
        format!("  filter: {}   (/ to edit)", st.filter())
    };
    let styled_filter = if st.mode() == Mode::Filter {
        pad(&filter_line, width).yellow()
    } else {
        filter_line.dark_grey()
    };
    queue!(
        out,
        style::PrintStyledContent(styled_filter),
        cursor::MoveToNextLine(1)
    )?;

    // Column header.
    queue!(
        out,
        style::PrintStyledContent("  PID     CPU    MEM   COMMAND".dark_grey()),
        cursor::MoveToNextLine(1)
    )?;

    // Process rows, capped to the remaining height (reserve the help + attach lines).
    let header_lines = 3 + watched.len().max(1) + 4;
    let reserve = if st.attach().is_some() { 4 } else { 2 };
    let budget = (rows as usize).saturating_sub(header_lines + reserve);
    let pfocus = st.focus() == Focus::Picker;
    for (row, &idx) in st.filtered().iter().take(budget).enumerate() {
        let p = &snap[idx];
        let cmd = if p.cmdline.is_empty() {
            &p.name
        } else {
            &p.cmdline
        };
        let selected = pfocus && row == st.picker_cursor();
        let marker = if selected { "▶ " } else { "  " };
        let line = format!(
            "{marker}{:<6} {:>5.1}% {:>5.1}%  {}",
            p.pid, p.cpu_pct, p.mem_pct, cmd
        );
        if selected {
            queue!(out, style::PrintStyledContent(pad(&line, width).reverse()))?;
        } else {
            queue!(out, style::Print(line))?;
        }
        queue!(out, cursor::MoveToNextLine(1))?;
    }

    // Attach/edit editor — a prominent highlighted block that explains the choice
    // live: leave the field as the name to match by name, or type a command-line
    // substring to match by path.
    if let Some(a) = st.attach() {
        let verb = if a.edit_index.is_some() {
            "Edit match for"
        } else {
            "Watch"
        };
        let l1 = format!("  {} \"{}\":  {}\u{2588}", verb, a.proc_name, a.field);
        let by_name = a.field.trim().is_empty() || a.field.trim() == a.proc_name.trim();
        let l2 = if by_name {
            format!(
                "  → matches any process named \"{}\"  ·  Enter save · type a path for a command-line match",
                a.proc_name
            )
        } else {
            format!(
                "  → matches any command line containing \"{}\"  ·  Enter save · Esc cancel",
                a.field.trim()
            )
        };
        queue!(
            out,
            cursor::MoveToNextLine(1),
            style::PrintStyledContent(pad(&l1, width).black().on_yellow()),
            cursor::MoveToNextLine(1),
            style::PrintStyledContent(pad(&l2, width).black().on_yellow()),
            cursor::MoveToNextLine(1)
        )?;
    }

    // Error line.
    if let Some(err) = st.error() {
        queue!(
            out,
            style::PrintStyledContent(format!("! {err}").yellow()),
            cursor::MoveToNextLine(1)
        )?;
    }

    // Mode-aware help bar pinned to the last row.
    let (tag, hints) = match st.mode() {
        Mode::Normal => (
            " NORMAL ",
            if st.focus() == Focus::Picker {
                "Enter add · / filter · Tab watchlist · r refresh · ? help · q quit"
            } else {
                "Enter edit · dd remove · Tab list · / filter · ? help · q quit"
            },
        ),
        Mode::Filter => (
            " FILTER ",
            "type to filter · Enter add · \u{2191}\u{2193} move · Esc done · ^C clear",
        ),
        Mode::AttachEdit => (" ATTACH ", "Enter save · Esc cancel"),
    };
    queue!(
        out,
        cursor::MoveTo(0, rows.saturating_sub(1)),
        style::PrintStyledContent(tag.black().on_yellow()),
        style::PrintStyledContent(
            pad(&format!(" {hints}"), width.saturating_sub(tag.len())).reverse()
        )
    )?;

    out.flush()
}

/// The `?` help overlay: every keybinding plus a plain-language note on what
/// "match" means. Any key closes it (handled in the state machine).
fn render_help(out: &mut impl Write, width: usize, rows: u16) -> std::io::Result<()> {
    queue!(
        out,
        style::PrintStyledContent(pad(" gpr watch manage — help ", width).black().on_yellow()),
        cursor::MoveToNextLine(2)
    )?;
    let keys = [
        ("Move", "j / k   or   \u{2193} / \u{2191}"),
        ("Jump", "gg top · G bottom · Ctrl-d / Ctrl-u half-page"),
        (
            "Filter",
            "/ then type · Enter adds the selected process · Esc done · Ctrl-c clear",
        ),
        ("Switch pane", "Tab   (or h / l)"),
        ("Add a process", "Enter on a process in the lower list"),
        ("Edit a match", "Enter on an item in the watchlist"),
        ("Remove", "dd on an item in the watchlist"),
        ("Refresh", "r  (re-sample running processes)"),
        ("Help", "?"),
        ("Quit", "q   or   Ctrl-c"),
    ];
    for (k, v) in keys {
        queue!(
            out,
            style::PrintStyledContent(format!("  {k:<16}").bold()),
            style::Print(v),
            cursor::MoveToNextLine(1)
        )?;
    }
    queue!(
        out,
        cursor::MoveToNextLine(1),
        style::PrintStyledContent("  What \"match\" means".bold()),
        cursor::MoveToNextLine(1)
    )?;
    for l in [
        "  A watched process is found each tick so we can tell if it is alive.",
        "  by name         — finds a running process by its name (the default)",
        "  by command line — finds one whose full command line contains your text;",
        "                    use a path to pin an exact service, e.g. /usr/lib/postgresql",
    ] {
        queue!(
            out,
            style::PrintStyledContent(l.dark_grey()),
            cursor::MoveToNextLine(1)
        )?;
    }
    queue!(
        out,
        cursor::MoveTo(0, rows.saturating_sub(1)),
        style::PrintStyledContent(pad(" press any key to close ", width).reverse())
    )?;
    out.flush()
}

/// Right-pad (or truncate) a string to `width` columns so a styled background
/// fills the whole line. Uses char count — close enough for the ASCII-ish content
/// here; wide glyphs at the far edge only cost a trailing space.
fn pad(s: &str, width: usize) -> String {
    let len = s.chars().count();
    if len >= width {
        s.chars().take(width).collect()
    } else {
        format!("{s}{}", " ".repeat(width - len))
    }
}
