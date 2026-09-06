# Changelog

All notable changes to the `gpr` agent are documented here. Versions follow
[Semantic Versioning](https://semver.org).

## [0.1.10]

- Fleet self-join: `gpr login --group <name>` and a config `group` field, sent
  additively on `/agent/hello`. The server resolves-or-creates the fleet by name
  within the project and assigns the host, so autoscaled nodes sharing a name
  cluster into one fleet. Absent/empty never clears a dashboard-set fleet.

## [0.1.9]

- `gpr watch --background` / `gpr watch --stop` — run the inside-out daemon
  detached and stop it again. A lightweight backgrounder (own process group,
  logs to the config dir, tracked by a pidfile); for restart-on-crash and
  start-on-boot use `gpr service install`.
- Renamed `gpr watch edit` to `gpr watch manage` (the interactive watchlist
  manager); `edit` stays as a hidden alias.

## [0.1.8]

- `gpr update` — self-update to the latest release. Fetches the newest GitHub
  release for this platform, verifies its SHA-256, and atomically swaps the
  binary in (no re-running the install script). Says so when already current;
  asks for sudo if the binary isn't user-writable. Unix; Windows re-uses the
  installer.

## [0.1.7]

- `gpr watch` now prints a startup banner (what it watches, the report interval,
  and that Ctrl-C stops it) and a concise heartbeat line per successful report,
  so the daemon no longer looks frozen when run in the foreground (and leaves a
  readable trace in the service journal).

## [0.1.6]

- `gpr service install|uninstall|status` — run `gpr watch` automatically on host
  reboot. systemd on Linux, launchd on macOS; system scope (starts at boot, needs
  sudo) or `--user` (rootless, starts at login). Uninstall fully removes it;
  status shows what's installed and whether it's running. The service runs as you,
  so it uses the token and watchlist you already configured.

## [0.1.5]

- `gpr watch edit` — an interactive, vim-modal manager to browse running
  processes (fuzzy filter with `/`), attach one to the watchlist as a stable
  name/command-line matcher, and inspect or remove watched processes (`dd`).
  Keys: `j`/`k`/arrows move, `gg`/`G` jump, `Tab` switches panes, `r` refreshes,
  `q` quits. Needs an interactive terminal; falls back to a hint pointing at
  `gpr watch add`/`list`/`rm` otherwise.

## [0.1.4]

- New check kinds for services on a unix socket file (e.g. a Python WSGI app
  behind nginx):
  - `uds` — connect to the socket; works for both gunicorn (HTTP) and uWSGI
    (binary), since it doesn't assume the protocol.
  - `uds-http` — send an HTTP GET over the socket and require a 2xx/3xx reply.
  Use them as `gpr check uds /run/gunicorn.sock`,
  `gpr check uds-http /run/gunicorn.sock /health`, and the matching
  `gpr watch add uds …` / `gpr watch add uds-http … [path]`. Unix-only;
  dependency-free (std sockets).

## [0.1.3]

- `gpr watch` now runs configured internal checks each tick and reports them,
  so a failing dependency inside the host becomes the stated cause. Manage them
  with `gpr watch add|list|rm`:
  - `gpr watch add tcp localhost:5432` — TCP port reachable?
  - `gpr watch add http http://localhost:8080/health` — endpoint healthy (2xx/3xx)?
  - `gpr watch add egress https://api.example.com` — outbound dependency reachable?
  - `gpr watch add pidfile /var/run/nginx.pid` — the pidfile names a live process?
  - `gpr watch add process nginx [--match <cmdline substring>]` — process alive +
    restart-tracked; `--match` pins by command line instead of name.
- New one-shot `gpr check pidfile <path>`.
- Config `processes` now also accepts `{ "name": …, "pattern": … }` objects for
  command-line matching; bare strings keep working. Checks and processes are
  capped (32 / 64) so the agent stays bounded.

## [0.1.2]

- `hello` now reports the machine hostname, so the console shows a real name
  instead of the internal host id. Additive and backward-compatible: older
  servers ignore it, and the identity id is unchanged.

## [0.1.1]

- Config location standardized to `~/.config/gpr/config.json` on Unix (XDG) —
  macOS now matches Linux instead of using `~/Library/Application Support`.
  Existing configs are migrated automatically on first run. Windows unchanged.
  `GPR_CONFIG_DIR` still overrides it.

## [0.1.0]

Initial public release.

- `gpr run` — wrap a command; exit code (and signal termination) passes through
  unchanged, while the run's start, result, and a redacted error tail are reported.
- Heartbeats — `gpr ping <slug>` and `gpr run --slug` for cron jobs and workers.
- Host metrics and process snapshot (`gpr ps`), collected without spawning shells.
- Log tailing with rotation handling, multiline grouping, error-signature
  fingerprinting, and secret redaction before anything is buffered.
- Outside-in one-off checks: `gpr check tcp|http|egress`.
- `gpr doctor` for connectivity and configuration diagnostics.
- Outbound-only: no listening port, no remote command execution. Static musl
  Linux builds; bounded memory and buffers.
