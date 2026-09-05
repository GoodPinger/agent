# gpr — the GoodPinger agent

`gpr` is the optional, open-source agent for [GoodPinger](https://goodpinger.com).
It reports inside-out signal from your server — host metrics, the error lines
behind a failure, and a heartbeat for scheduled jobs — so an incident can state a
**cause**, not just that something is down.

It is safe by construction:

- **Outbound-only.** No listening port, no remote command execution — ever.
- **Exit codes pass through unchanged.** `gpr run` wraps a command and returns
  its exact exit status, including signal termination.
- **Bounded.** Every buffer, queue, and log ring is capped; it will not fill your
  disk or grow without limit (target ceiling: ~20 MB RSS, ~1% CPU).
- **Redacts before buffering.** Secrets are scrubbed from captured output before
  it is ever held in memory or sent.

## Install

```sh
curl -fsSL https://goodpinger.com/install | sh
```

The script detects your OS/arch, downloads the matching release binary and its
checksum, **verifies the sha256 before installing**, and places `gpr` on your
PATH. Linux binaries are static (musl), so they run on old distros too. Windows:
download the asset from the [latest release](https://github.com/goodpinger/agent/releases/latest).

## Usage

```sh
gpr login --token <agent-token>      # link this host to your project
gpr run --slug <slug> -- <command>   # wrap a cron job / worker (reports start, exit code, error tail)
gpr ping <slug>                      # bare heartbeat ping
gpr doctor                           # check connectivity and configuration
gpr status                           # show this host's link + last report
gpr check http <url>                 # one-off outside-in probe (tcp | http | egress)
```

### Heartbeats

Create a heartbeat monitor in the dashboard to get a ping URL, then either add a
one-line `curl` to your cron job or wrap the command:

```sh
gpr run --slug <slug> -- /opt/backup.sh
```

`gpr run` reports the run's start and its exit code, so a run that **failed**
(non-zero exit) is distinguished from one that **never ran** — and the captured
error output attaches to the incident.

## Build from source

Requires a stable Rust toolchain.

```sh
cargo build --release          # target/release/gpr
make build-all                 # all release targets (musl for Linux)
cargo test
cargo clippy -- -D warnings
```

## License

MIT — see [LICENSE](LICENSE).
