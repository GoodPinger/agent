//! Pure state machine for `gpr watch edit`. No terminal I/O, no filesystem — it
//! only maps key events to state changes and returns the side effects the shell
//! must perform. crossterm's `KeyEvent` is used purely as a data type.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::collect::ProcInfo;
use crate::config::{self, Config, ProcessSpec};

/// Which input mode the manager is in (vim-style).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Normal,
    Filter,
    AttachEdit,
}

/// Which pane the cursor acts on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    Picker,
    Watchlist,
}

/// A side effect the shell performs after `on_key`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    SaveConfig,
    Refresh,
    Quit,
}

/// The inline match editor, used both to attach a picked process and to edit a
/// watched item's match. `edit_index` is `Some(i)` when editing `watchlist[i]` in
/// place, or `None` when adding a newly picked process.
#[derive(Debug, Clone)]
pub struct AttachEdit {
    pub proc_name: String,
    pub field: String,
    pub edit_index: Option<usize>,
}

/// fzf-style fuzzy score: `Some(score)` if every char of `needle` appears in
/// order in `haystack` (case-insensitive); lower is better (earlier start, fewer
/// gaps). `None` if not a subsequence. Empty needle scores 0.
pub(crate) fn fuzzy_score(haystack: &str, needle: &str) -> Option<i32> {
    if needle.trim().is_empty() {
        return Some(0);
    }
    let hay: Vec<char> = haystack.to_lowercase().chars().collect();
    let ndl: Vec<char> = needle.to_lowercase().chars().collect();
    let mut ni = 0usize;
    let mut score = 0i32;
    let mut first_match: Option<usize> = None;
    let mut last_match: Option<usize> = None;
    for (hi, &hc) in hay.iter().enumerate() {
        if ni < ndl.len() && hc == ndl[ni] {
            if first_match.is_none() {
                first_match = Some(hi);
            }
            if let Some(lm) = last_match {
                score += (hi - lm - 1) as i32; // gap penalty
            }
            last_match = Some(hi);
            ni += 1;
        }
    }
    if ni == ndl.len() {
        Some(score + first_match.unwrap_or(0) as i32)
    } else {
        None
    }
}

/// Indices of `snapshot` matching `query`, best first. Empty query returns every
/// index in the snapshot's existing (memory-sorted) order.
pub fn filter_processes(snapshot: &[ProcInfo], query: &str) -> Vec<usize> {
    if query.trim().is_empty() {
        return (0..snapshot.len()).collect();
    }
    let q = query.trim();
    let mut scored: Vec<(i32, usize)> = snapshot
        .iter()
        .enumerate()
        .filter_map(|(i, p)| {
            let hay = format!("{} {}", p.name, p.cmdline);
            fuzzy_score(&hay, q).map(|s| (s, i))
        })
        .collect();
    // Better score first; ties keep the snapshot's memory order (lower index).
    scored.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    scored.into_iter().map(|(_, i)| i).collect()
}

/// The stable matcher to store for an attached process. If the edit field is
/// unchanged (or blank), watch by name; otherwise watch by the command-line
/// pattern the user typed, keeping the process name as the display label.
pub fn derive_spec(attach: &AttachEdit) -> ProcessSpec {
    let field = attach.field.trim();
    if field.is_empty() || field == attach.proc_name.trim() {
        ProcessSpec {
            name: attach.proc_name.clone(),
            pattern: None,
        }
    } else {
        ProcessSpec {
            name: attach.proc_name.clone(),
            pattern: Some(field.to_string()),
        }
    }
}

/// Ctrl-d / Ctrl-u step. Fixed so the state machine is independent of terminal
/// height (the shell scrolls the view to keep the cursor visible).
const HALF_PAGE: i64 = 10;

/// The full interactive-manager state. Pure: every method is deterministic and
/// terminal-free.
pub struct ManagerState {
    cfg: Config,
    snapshot: Vec<ProcInfo>,
    filtered: Vec<usize>,
    filter: String,
    mode: Mode,
    focus: Focus,
    picker_cursor: usize,
    watch_cursor: usize,
    attach: Option<AttachEdit>,
    pending_g: bool,
    pending_d: bool,
    error: Option<String>,
    help: bool,
}

impl ManagerState {
    pub fn new(cfg: Config, snapshot: Vec<ProcInfo>) -> Self {
        let filtered = (0..snapshot.len()).collect();
        Self {
            cfg,
            snapshot,
            filtered,
            filter: String::new(),
            mode: Mode::Normal,
            focus: Focus::Picker,
            picker_cursor: 0,
            watch_cursor: 0,
            attach: None,
            pending_g: false,
            pending_d: false,
            error: None,
            help: false,
        }
    }

    // --- read accessors (renderer) -----------------------------------------
    pub fn mode(&self) -> Mode {
        self.mode
    }
    pub fn focus(&self) -> Focus {
        self.focus
    }
    pub fn filter(&self) -> &str {
        &self.filter
    }
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }
    pub fn attach(&self) -> Option<&AttachEdit> {
        self.attach.as_ref()
    }
    pub fn watched(&self) -> &[ProcessSpec] {
        &self.cfg.processes
    }
    pub fn watch_cursor(&self) -> usize {
        self.watch_cursor
    }
    pub fn picker_cursor(&self) -> usize {
        self.picker_cursor
    }
    pub fn filtered(&self) -> &[usize] {
        &self.filtered
    }
    pub fn snapshot(&self) -> &[ProcInfo] {
        &self.snapshot
    }
    pub fn config(&self) -> &Config {
        &self.cfg
    }
    pub fn help(&self) -> bool {
        self.help
    }

    // --- shell-driven mutation ---------------------------------------------
    pub fn set_error(&mut self, msg: String) {
        self.error = Some(msg);
    }
    pub fn set_snapshot(&mut self, snapshot: Vec<ProcInfo>) {
        self.snapshot = snapshot;
        self.refilter();
    }

    // --- key handling ------------------------------------------------------
    pub fn on_key(&mut self, key: KeyEvent) -> Vec<Effect> {
        self.error = None; // any key dismisses a transient error
                           // The help overlay is modal-lite: while it's up, any key closes it and
                           // nothing else happens (so no accidental edits while reading help).
        if self.help {
            self.help = false;
            return vec![];
        }
        match self.mode {
            Mode::Normal => self.on_key_normal(key),
            Mode::Filter => self.on_key_filter(key),
            Mode::AttachEdit => self.on_key_attach(key),
        }
    }

    fn on_key_normal(&mut self, key: KeyEvent) -> Vec<Effect> {
        let was_g = std::mem::take(&mut self.pending_g);
        let was_d = std::mem::take(&mut self.pending_d);

        if key.modifiers.contains(KeyModifiers::CONTROL) {
            return match key.code {
                KeyCode::Char('c') => vec![Effect::Quit],
                KeyCode::Char('d') => {
                    self.move_cursor(HALF_PAGE);
                    vec![]
                }
                KeyCode::Char('u') => {
                    self.move_cursor(-HALF_PAGE);
                    vec![]
                }
                _ => vec![],
            };
        }

        match key.code {
            KeyCode::Char('q') => vec![Effect::Quit],
            KeyCode::Char('j') | KeyCode::Down => {
                self.move_cursor(1);
                vec![]
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.move_cursor(-1);
                vec![]
            }
            KeyCode::Char('G') => {
                self.cursor_to_end();
                vec![]
            }
            KeyCode::Char('g') => {
                if was_g {
                    self.cursor_to_start();
                } else {
                    self.pending_g = true;
                }
                vec![]
            }
            KeyCode::Char('d') => {
                if was_d {
                    self.delete_watched()
                } else {
                    self.pending_d = true;
                    vec![]
                }
            }
            KeyCode::Tab | KeyCode::Char('h') | KeyCode::Char('l') => {
                self.toggle_focus();
                vec![]
            }
            KeyCode::Char('/') => {
                self.mode = Mode::Filter;
                self.focus = Focus::Picker; // filtering always acts on the process list
                vec![]
            }
            KeyCode::Char('r') => vec![Effect::Refresh],
            KeyCode::Char('?') => {
                self.help = true;
                vec![]
            }
            KeyCode::Enter => self.on_enter(),
            _ => vec![],
        }
    }

    /// Enter acts on the focused pane: attach the picked process, or edit the
    /// highlighted watched item's match.
    fn on_enter(&mut self) -> Vec<Effect> {
        match self.focus {
            Focus::Picker => self.begin_attach(),
            Focus::Watchlist => self.begin_edit(),
        }
    }

    fn on_key_filter(&mut self, key: KeyEvent) -> Vec<Effect> {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.filter.clear();
            self.refilter();
            self.mode = Mode::Normal;
            return vec![];
        }
        match key.code {
            // Enter confirms the highlighted process (fzf-style), rather than just
            // leaving filter mode — the intuitive "filter then add".
            KeyCode::Enter => self.begin_attach(),
            KeyCode::Esc => {
                self.mode = Mode::Normal;
                vec![]
            }
            KeyCode::Down => {
                self.move_cursor(1);
                vec![]
            }
            KeyCode::Up => {
                self.move_cursor(-1);
                vec![]
            }
            KeyCode::Backspace => {
                self.filter.pop();
                self.refilter();
                vec![]
            }
            KeyCode::Char(c) => {
                self.filter.push(c);
                self.refilter();
                vec![]
            }
            _ => vec![],
        }
    }

    fn on_key_attach(&mut self, key: KeyEvent) -> Vec<Effect> {
        match key.code {
            KeyCode::Esc => {
                self.attach = None;
                self.mode = Mode::Normal;
                vec![]
            }
            KeyCode::Enter => {
                self.mode = Mode::Normal;
                let Some(a) = self.attach.take() else {
                    return vec![];
                };
                let spec = derive_spec(&a);
                // Editing an existing item: replace its spec in place (the name is
                // unchanged, so no dedup concern).
                if let Some(i) = a.edit_index {
                    if i < self.cfg.processes.len() {
                        self.cfg.processes[i] = spec;
                        return vec![Effect::SaveConfig];
                    }
                    return vec![];
                }
                match config::add_process(&mut self.cfg, spec) {
                    config::AddResult::Added => vec![Effect::SaveConfig],
                    config::AddResult::Duplicate => {
                        self.error = Some(format!("already watching '{}'", a.proc_name));
                        vec![]
                    }
                    config::AddResult::Full => {
                        self.error = Some("process limit reached".to_string());
                        vec![]
                    }
                }
            }
            KeyCode::Backspace => {
                if let Some(a) = self.attach.as_mut() {
                    a.field.pop();
                }
                vec![]
            }
            KeyCode::Char(c) => {
                if let Some(a) = self.attach.as_mut() {
                    a.field.push(c);
                }
                vec![]
            }
            _ => vec![],
        }
    }

    // --- helpers -----------------------------------------------------------
    fn current_len(&self) -> usize {
        match self.focus {
            Focus::Picker => self.filtered.len(),
            Focus::Watchlist => self.cfg.processes.len(),
        }
    }

    fn move_cursor(&mut self, delta: i64) {
        let len = self.current_len();
        let cursor = match self.focus {
            Focus::Picker => &mut self.picker_cursor,
            Focus::Watchlist => &mut self.watch_cursor,
        };
        if len == 0 {
            *cursor = 0;
            return;
        }
        let max = (len - 1) as i64;
        *cursor = (*cursor as i64 + delta).clamp(0, max) as usize;
    }

    fn cursor_to_start(&mut self) {
        match self.focus {
            Focus::Picker => self.picker_cursor = 0,
            Focus::Watchlist => self.watch_cursor = 0,
        }
    }

    fn cursor_to_end(&mut self) {
        let last = self.current_len().saturating_sub(1);
        match self.focus {
            Focus::Picker => self.picker_cursor = last,
            Focus::Watchlist => self.watch_cursor = last,
        }
    }

    fn toggle_focus(&mut self) {
        self.focus = match self.focus {
            Focus::Picker => Focus::Watchlist,
            Focus::Watchlist => Focus::Picker,
        };
    }

    fn refilter(&mut self) {
        self.filtered = filter_processes(&self.snapshot, &self.filter);
        let max = self.filtered.len().saturating_sub(1);
        if self.picker_cursor > max {
            self.picker_cursor = max;
        }
    }

    fn begin_attach(&mut self) -> Vec<Effect> {
        if self.focus != Focus::Picker {
            return vec![];
        }
        if let Some(&idx) = self.filtered.get(self.picker_cursor) {
            let name = self.snapshot[idx].name.clone();
            self.attach = Some(AttachEdit {
                proc_name: name.clone(),
                field: name,
                edit_index: None,
            });
            self.mode = Mode::AttachEdit;
        }
        vec![]
    }

    /// Edit the highlighted watched item's match in place. The field pre-fills
    /// with its current match (its pattern, or its name for a name-match).
    fn begin_edit(&mut self) -> Vec<Effect> {
        if self.focus != Focus::Watchlist {
            return vec![];
        }
        if let Some(spec) = self.cfg.processes.get(self.watch_cursor) {
            let field = spec.pattern.clone().unwrap_or_else(|| spec.name.clone());
            self.attach = Some(AttachEdit {
                proc_name: spec.name.clone(),
                field,
                edit_index: Some(self.watch_cursor),
            });
            self.mode = Mode::AttachEdit;
        }
        vec![]
    }

    fn delete_watched(&mut self) -> Vec<Effect> {
        if self.focus != Focus::Watchlist {
            return vec![];
        }
        // Bind the name in a match so the immutable borrow ends before the
        // &mut self.cfg call below (borrow checker).
        let name = match self.cfg.processes.get(self.watch_cursor) {
            Some(s) => s.name.clone(),
            None => return vec![],
        };
        config::remove_process(&mut self.cfg, &name);
        let max = self.cfg.processes.len().saturating_sub(1);
        if self.watch_cursor > max {
            self.watch_cursor = max;
        }
        vec![Effect::SaveConfig]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn proc(name: &str, cmd: &str) -> ProcInfo {
        ProcInfo {
            pid: 1,
            name: name.to_string(),
            cmdline: cmd.to_string(),
            cpu_pct: 0.0,
            mem_pct: 0.0,
        }
    }

    #[test]
    fn filter_empty_returns_all_in_order() {
        let snap = vec![proc("a", ""), proc("b", ""), proc("c", "")];
        assert_eq!(filter_processes(&snap, ""), vec![0, 1, 2]);
        assert_eq!(filter_processes(&snap, "   "), vec![0, 1, 2]);
    }

    #[test]
    fn filter_matches_name_and_cmdline_case_insensitively() {
        let snap = vec![
            proc("nginx", "nginx: master"),
            proc("postgres", "/usr/lib/postgresql/16/bin/postgres"),
            proc("redis-server", "redis-server *:6379"),
        ];
        assert_eq!(filter_processes(&snap, "NGINX"), vec![0]);
        assert_eq!(filter_processes(&snap, "postgresql"), vec![1]);
        // 'rds' is a subsequence of "redis-server".
        assert_eq!(filter_processes(&snap, "rds"), vec![2]);
        assert!(filter_processes(&snap, "zzzzz").is_empty());
    }

    #[test]
    fn filter_ranks_earlier_contiguous_matches_first() {
        let snap = vec![
            proc("xxredis", "background redis mention"),
            proc("redis", "redis-server"),
        ];
        // "redis" is contiguous and earlier in index 1 → ranked before the
        // scattered match in index 0.
        assert_eq!(filter_processes(&snap, "redis"), vec![1, 0]);
    }

    #[test]
    fn derive_spec_name_vs_pattern() {
        let a = AttachEdit {
            proc_name: "nginx".into(),
            field: "nginx".into(),
            edit_index: None,
        };
        let s = derive_spec(&a);
        assert_eq!(s.name, "nginx");
        assert!(s.pattern.is_none());

        let a = AttachEdit {
            proc_name: "postgres".into(),
            field: "/usr/lib/postgresql".into(),
            edit_index: None,
        };
        let s = derive_spec(&a);
        assert_eq!(s.name, "postgres");
        assert_eq!(s.pattern.as_deref(), Some("/usr/lib/postgresql"));

        let a = AttachEdit {
            proc_name: "x".into(),
            field: "   ".into(),
            edit_index: None,
        };
        assert!(derive_spec(&a).pattern.is_none());
    }

    fn state_with(procs: &[&str], names: &[&str]) -> ManagerState {
        let snap: Vec<ProcInfo> = procs.iter().map(|n| proc(n, "")).collect();
        let cfg = Config {
            processes: names
                .iter()
                .map(|n| ProcessSpec {
                    name: n.to_string(),
                    pattern: None,
                })
                .collect(),
            ..Config::default()
        };
        ManagerState::new(cfg, snap)
    }

    fn key(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
    }
    fn code(kc: KeyCode) -> KeyEvent {
        KeyEvent::new(kc, KeyModifiers::NONE)
    }
    fn ctrl(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
    }

    #[test]
    fn j_k_move_within_bounds_and_clamp() {
        let mut st = state_with(&["a", "b", "c"], &[]);
        assert_eq!(st.picker_cursor(), 0);
        st.on_key(key('k'));
        assert_eq!(st.picker_cursor(), 0);
        st.on_key(key('j'));
        assert_eq!(st.picker_cursor(), 1);
        st.on_key(key('j'));
        st.on_key(key('j'));
        assert_eq!(st.picker_cursor(), 2);
    }

    #[test]
    fn arrows_move_in_filter_mode_without_editing_text() {
        let mut st = state_with(&["a", "b", "c"], &[]);
        st.on_key(key('/'));
        assert_eq!(st.mode(), Mode::Filter);
        st.on_key(code(KeyCode::Down));
        assert_eq!(st.picker_cursor(), 1);
        assert_eq!(st.filter(), "");
    }

    #[test]
    fn gg_and_upper_g_jump_top_and_bottom() {
        let mut st = state_with(&["a", "b", "c", "d"], &[]);
        st.on_key(key('G'));
        assert_eq!(st.picker_cursor(), 3);
        st.on_key(key('g'));
        st.on_key(key('g'));
        assert_eq!(st.picker_cursor(), 0);
    }

    #[test]
    fn lone_g_then_other_key_cancels_pending() {
        let mut st = state_with(&["a", "b", "c"], &[]);
        st.on_key(key('G'));
        st.on_key(key('g'));
        st.on_key(key('j'));
        assert_eq!(st.picker_cursor(), 2);
    }

    #[test]
    fn ctrl_d_u_half_page_and_clamp() {
        let names: Vec<String> = (0..30).map(|i| format!("p{i}")).collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let mut st = state_with(&refs, &[]);
        st.on_key(ctrl('d'));
        assert_eq!(st.picker_cursor(), HALF_PAGE as usize);
        st.on_key(ctrl('u'));
        assert_eq!(st.picker_cursor(), 0);
    }

    #[test]
    fn tab_and_hl_toggle_focus() {
        let mut st = state_with(&["a"], &["nginx"]);
        assert_eq!(st.focus(), Focus::Picker);
        st.on_key(code(KeyCode::Tab));
        assert_eq!(st.focus(), Focus::Watchlist);
        st.on_key(key('h'));
        assert_eq!(st.focus(), Focus::Picker);
        st.on_key(key('l'));
        assert_eq!(st.focus(), Focus::Watchlist);
    }

    #[test]
    fn slash_enters_filter_typing_filters_and_enter_attaches_selected() {
        let mut st = state_with(&["nginx", "postgres"], &[]);
        st.on_key(key('/'));
        assert_eq!(st.focus(), Focus::Picker); // filter focuses the picker
        st.on_key(key('p'));
        st.on_key(key('g'));
        assert_eq!(st.filter(), "pg");
        assert_eq!(st.filtered(), &[1]);
        // Enter in filter mode confirms the highlighted process (fzf-style).
        st.on_key(code(KeyCode::Enter));
        assert_eq!(st.mode(), Mode::AttachEdit);
        assert_eq!(st.attach().unwrap().proc_name, "postgres");
        // Esc leaves filter mode without adding, keeping the filter.
        let mut st2 = state_with(&["nginx", "postgres"], &[]);
        st2.on_key(key('/'));
        st2.on_key(key('p'));
        st2.on_key(code(KeyCode::Esc));
        assert_eq!(st2.mode(), Mode::Normal);
        assert_eq!(st2.filter(), "p");
    }

    #[test]
    fn filter_backspace_and_ctrl_c_clear() {
        let mut st = state_with(&["nginx", "postgres"], &[]);
        st.on_key(key('/'));
        st.on_key(key('p'));
        st.on_key(code(KeyCode::Backspace));
        assert_eq!(st.filter(), "");
        st.on_key(key('x'));
        st.on_key(ctrl('c'));
        assert_eq!(st.filter(), "");
        assert_eq!(st.mode(), Mode::Normal);
    }

    #[test]
    fn enter_attaches_and_saves_the_right_spec() {
        let mut st = state_with(&["nginx"], &[]);
        let eff = st.on_key(code(KeyCode::Enter));
        assert!(eff.is_empty());
        assert_eq!(st.mode(), Mode::AttachEdit);
        assert_eq!(st.attach().unwrap().field, "nginx");
        let eff = st.on_key(code(KeyCode::Enter));
        assert_eq!(eff, vec![Effect::SaveConfig]);
        assert_eq!(st.mode(), Mode::Normal);
        assert_eq!(st.config().processes.len(), 1);
        assert_eq!(st.config().processes[0].name, "nginx");
        assert!(st.config().processes[0].pattern.is_none());
    }

    #[test]
    fn attach_edit_to_pattern_stores_cmdline_match() {
        let mut st = state_with(&["postgres"], &[]);
        st.on_key(code(KeyCode::Enter));
        for _ in 0.."postgres".len() {
            st.on_key(code(KeyCode::Backspace));
        }
        for c in "/usr/lib/pg".chars() {
            st.on_key(key(c));
        }
        st.on_key(code(KeyCode::Enter));
        assert_eq!(
            st.config().processes[0].pattern.as_deref(),
            Some("/usr/lib/pg")
        );
    }

    #[test]
    fn attach_esc_cancels_with_no_change() {
        let mut st = state_with(&["nginx"], &[]);
        st.on_key(code(KeyCode::Enter));
        let eff = st.on_key(code(KeyCode::Esc));
        assert!(eff.is_empty());
        assert_eq!(st.mode(), Mode::Normal);
        assert!(st.config().processes.is_empty());
    }

    #[test]
    fn attach_duplicate_sets_error_and_adds_nothing() {
        let mut st = state_with(&["nginx"], &["nginx"]);
        st.on_key(code(KeyCode::Enter));
        let eff = st.on_key(code(KeyCode::Enter));
        assert!(eff.is_empty());
        assert!(st.error().is_some());
        assert_eq!(st.config().processes.len(), 1);
    }

    #[test]
    fn dd_removes_highlighted_watched_item() {
        let mut st = state_with(&["a"], &["nginx", "postgres"]);
        st.on_key(code(KeyCode::Tab));
        let eff = st.on_key(key('d'));
        assert!(eff.is_empty());
        let eff = st.on_key(key('d'));
        assert_eq!(eff, vec![Effect::SaveConfig]);
        assert_eq!(st.config().processes.len(), 1);
    }

    #[test]
    fn dd_does_nothing_in_picker_focus() {
        let mut st = state_with(&["a"], &["nginx"]);
        st.on_key(key('d'));
        let eff = st.on_key(key('d'));
        assert!(eff.is_empty());
        assert_eq!(st.config().processes.len(), 1);
    }

    #[test]
    fn r_refreshes_q_and_ctrl_c_quit() {
        let mut st = state_with(&["a"], &[]);
        assert_eq!(st.on_key(key('r')), vec![Effect::Refresh]);
        assert_eq!(st.on_key(key('q')), vec![Effect::Quit]);
        assert_eq!(st.on_key(ctrl('c')), vec![Effect::Quit]);
    }

    #[test]
    fn set_snapshot_refilters_and_clamps_cursor() {
        let mut st = state_with(&["a", "b", "c"], &[]);
        st.on_key(key('j'));
        st.on_key(key('j'));
        st.set_snapshot(vec![proc("only", "")]);
        assert_eq!(st.picker_cursor(), 0);
        assert_eq!(st.filtered(), &[0]);
    }

    #[test]
    fn set_error_is_readable_and_cleared_on_next_key() {
        let mut st = state_with(&["a"], &[]);
        st.set_error("boom".into());
        assert_eq!(st.error(), Some("boom"));
        st.on_key(key('j'));
        assert!(st.error().is_none());
    }

    #[test]
    fn watchlist_pane_navigation_moves_watch_cursor() {
        let mut st = state_with(&["a"], &["p0", "p1", "p2", "p3"]);
        st.on_key(code(KeyCode::Tab)); // focus watchlist
        st.on_key(key('G'));
        assert_eq!(st.watch_cursor(), 3);
        st.on_key(key('g'));
        st.on_key(key('g'));
        assert_eq!(st.watch_cursor(), 0);
        st.on_key(key('j'));
        assert_eq!(st.watch_cursor(), 1);
        st.on_key(key('k'));
        assert_eq!(st.watch_cursor(), 0);
    }

    #[test]
    fn moving_on_an_empty_pane_stays_at_zero() {
        let mut st = state_with(&[], &[]); // no processes, no watchlist
        st.on_key(key('j'));
        st.on_key(key('G'));
        assert_eq!(st.picker_cursor(), 0);
        // Enter on an empty picker does nothing (no attach).
        let eff = st.on_key(code(KeyCode::Enter));
        assert!(eff.is_empty());
        assert_eq!(st.mode(), Mode::Normal);
    }

    #[test]
    fn unhandled_keys_are_no_ops_in_each_mode() {
        let mut st = state_with(&["a"], &[]);
        assert!(st.on_key(code(KeyCode::Home)).is_empty()); // normal
        st.on_key(key('/'));
        assert!(st.on_key(code(KeyCode::Left)).is_empty()); // filter
        assert_eq!(st.mode(), Mode::Filter);
        st.on_key(code(KeyCode::Esc));
        st.on_key(code(KeyCode::Enter)); // begin attach
        assert!(st.on_key(code(KeyCode::Left)).is_empty()); // attach-edit
        assert_eq!(st.mode(), Mode::AttachEdit);
    }

    #[test]
    fn enter_on_watchlist_edits_match_in_place() {
        let mut st = state_with(&["a"], &["nginx", "postgres"]);
        st.on_key(code(KeyCode::Tab)); // focus watchlist, cursor 0 = nginx
        let eff = st.on_key(code(KeyCode::Enter)); // begin edit
        assert!(eff.is_empty());
        assert_eq!(st.mode(), Mode::AttachEdit);
        assert_eq!(st.attach().unwrap().field, "nginx"); // name-match → field = name
        assert_eq!(st.attach().unwrap().edit_index, Some(0));

        // Change nginx to a command-line match.
        for _ in 0.."nginx".len() {
            st.on_key(code(KeyCode::Backspace));
        }
        for c in "/usr/sbin/nginx".chars() {
            st.on_key(key(c));
        }
        let eff = st.on_key(code(KeyCode::Enter));
        assert_eq!(eff, vec![Effect::SaveConfig]);
        assert_eq!(st.config().processes.len(), 2); // edited in place, not added
        assert_eq!(st.config().processes[0].name, "nginx");
        assert_eq!(
            st.config().processes[0].pattern.as_deref(),
            Some("/usr/sbin/nginx")
        );

        // Re-editing prefills the field with the current pattern.
        st.on_key(code(KeyCode::Enter));
        assert_eq!(st.attach().unwrap().field, "/usr/sbin/nginx");
    }

    #[test]
    fn question_mark_toggles_help_and_any_key_closes_it() {
        let mut st = state_with(&["a"], &["nginx"]);
        assert!(!st.help());
        st.on_key(key('?'));
        assert!(st.help());
        // Any key closes help and does nothing else (no accidental edits).
        let eff = st.on_key(key('j'));
        assert!(eff.is_empty());
        assert!(!st.help());
        assert_eq!(st.picker_cursor(), 0); // j did not move while closing help
    }

    #[test]
    fn filter_up_arrow_moves_selection() {
        let mut st = state_with(&["a", "b", "c"], &[]);
        st.on_key(key('/'));
        st.on_key(code(KeyCode::Down));
        st.on_key(code(KeyCode::Down));
        assert_eq!(st.picker_cursor(), 2);
        st.on_key(code(KeyCode::Up));
        assert_eq!(st.picker_cursor(), 1);
    }
}
