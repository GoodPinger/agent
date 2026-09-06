# Changelog

All notable changes to the `gpr` agent are documented here. Versions follow
[Semantic Versioning](https://semver.org).

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
