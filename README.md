<div align="center">

<img src="assets/logo.svg" alt="GoodPinger" width="380">

### The open-source agent that turns an alert into an answer

`gpr` reports inside-out signal from your server — host metrics, the error lines
behind a failure, and heartbeats for scheduled jobs — so an incident states a
**cause**, not just that something is down.

[![Release](https://img.shields.io/github/v/release/goodpinger/agent?color=facc15&label=release)](https://github.com/goodpinger/agent/releases/latest)
[![CI](https://img.shields.io/github/actions/workflow/status/goodpinger/agent/ci.yml?label=CI)](https://github.com/goodpinger/agent/actions)
[![License: MIT](https://img.shields.io/github/license/goodpinger/agent?color=555)](LICENSE)
![Platforms](https://img.shields.io/badge/platform-Linux%20%C2%B7%20macOS%20%C2%B7%20Windows-555)
![Built with Rust](https://img.shields.io/badge/built%20with-Rust-dea584?logo=rust&logoColor=white)

[Website](https://goodpinger.com) · [Install](#install) · [Usage](#usage) · [Why gpr](#why-gpr)

</div>

---

## Why gpr

Most monitors tell you **what**: _"site is down."_ Then you SSH in and start
guessing. `gpr` gives GoodPinger the inside-out signal to tell you **why**:

```
✗ tabot.example.com — down
  ↳ nginx exited — could not bind 0.0.0.0:443 (address already in use)
```

That one line — the stated cause plus the error tail that produced it — is the
whole point. Uptime is a commodity; the diagnosis is the product.

It is **safe by construction**:

- **Outbound-only.** No listening port, no remote command execution — ever.
- **Exit codes pass through unchanged.** `gpr run` wraps a command and returns
  its exact exit status, including signal termination.
- **Bounded.** Every buffer, queue, and log ring is capped; it will not fill your
  disk or grow without limit (target ceiling: ~20 MB RSS, ~1% CPU).
- **Redacts before buffering.** Secrets are scrubbed from captured output before
  it is ever held in memory or sent.
- **Memory-safe.** Written in Rust with `unsafe` banned in our own code.

## Install

```sh
curl -fsSL https://goodpinger.com/install | sh
```

The script detects your OS/arch, downloads the matching release binary and its
checksum, **verifies the sha256 before installing**, and places `gpr` on your
PATH. Linux binaries are static (musl), so they run on old distros too. Windows:
download the asset from the [latest release](https://github.com/goodpinger/agent/releases/latest).

Update any time with `gpr update`.

## Usage

Link the host, then choose how it reports.

```sh
gpr login --token <agent-token>            # link this host to your project
gpr login --token <token> --group web      # ...and self-join a fleet by name (see Fleets)
```

### Wrap a scheduled job (heartbeat)

Create a heartbeat monitor in the dashboard to get a slug, then wrap the command:

```sh
gpr run --slug <slug> -- /opt/backup.sh    # reports start, exit code, and the error tail
gpr ping <slug>                            # or a bare heartbeat ping
```

`gpr run` reports the run's start and its exit code, so a run that **failed**
(non-zero exit) is distinguished from one that **never ran** — and the captured
error output attaches to the incident. Exit codes pass through unchanged.

### Watch the host continuously (inside-out daemon)

```sh
gpr watch                       # report host metrics, processes, checks, and error signatures
gpr watch --background          # ...detached; returns your shell  (gpr watch --stop to stop it)
gpr watch add tcp localhost:5432   # watch an internal dependency
                                   #   also: http, egress, pidfile, uds, uds-http, process
gpr watch list                     # show what's configured
gpr watch manage                   # interactive TUI: browse processes and edit the watchlist
```

For a supervised, restart-on-crash, start-on-boot setup, install it as a service
instead of `--background`:

```sh
gpr service install             # systemd (Linux) / launchd (macOS); add --user for a rootless install
gpr service status
gpr service uninstall
```

### Fleets

Group servers that run the same job (a web tier, a DB cluster) so a partial
outage pages **once**, naming each node's cause. A host joins a fleet by name —
autoscaled nodes sharing a name cluster automatically:

```sh
gpr login --token <token> --group web
```

### Utilities

```sh
gpr doctor                      # check connectivity and configuration
gpr status                      # show this host's link + last report
gpr check http <url>            # one-off outside-in probe (tcp | http | egress)
gpr update                      # self-update to the latest release (verifies sha256)
```

## Build from source

Requires a stable Rust toolchain.

```sh
cargo build --release          # target/release/gpr
make build-all                 # all release targets (musl for Linux)
cargo test
cargo clippy -- -D warnings
```

## How it fits

`gpr` is optional — GoodPinger monitors your endpoints from the outside with no
agent at all. Install `gpr` on a server when you want the **inside** story too:
the process that died, the dependency that stopped answering, the error that
repeated 2,847 times. The wire contract it speaks is documented and stable —
v1 never breaks, so an agent a year stale keeps working.

## License

MIT — see [LICENSE](LICENSE). Issues and PRs welcome.

<div align="center"><sub>Part of <a href="https://goodpinger.com">GoodPinger</a> — uptime, host metrics, heartbeats, and a stated cause.</sub></div>
