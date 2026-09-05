# Changelog

All notable changes to the `gpr` agent are documented here. Versions follow
[Semantic Versioning](https://semver.org).

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
