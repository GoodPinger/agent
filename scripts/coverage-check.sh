#!/usr/bin/env bash
#
# Scoped coverage gate for the agent. We do NOT chase a global
# coverage number — we gate the modules whose failure loses customers:
#
#   - buffer.rs  — the bounded offline queue (must never fill a disk / lose runs)
#   - redact.rs  — secret redaction before buffering (a leak is an incident)
#
# run.rs's load-bearing behavior (exit-code passthrough, incl. signals) is gated
# by explicit tests in tests/run_exit_codes.rs, not by a line percentage — line
# coverage of best-effort reporting glue is exactly what §6 says not to chase.
#
# Usage: scripts/coverage-check.sh
set -euo pipefail
cd "$(dirname "$0")/.."

OUT="target/llvm-cov.json"
cargo llvm-cov --json --output-path "$OUT" >/dev/null

node - "$OUT" <<'NODE'
const fs = require("fs");
const data = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const files = data.data[0].files;

// module suffix -> minimum line coverage %
const MIN = { "src/buffer.rs": 88, "src/redact.rs": 90 };

let failed = false;
for (const [suffix, min] of Object.entries(MIN)) {
  const file = files.find((f) => f.filename.endsWith(suffix));
  if (!file) {
    console.error(`✖ ${suffix}: not found in coverage report`);
    failed = true;
    continue;
  }
  const pct = file.summary.lines.percent;
  const ok = pct >= min;
  console.log(`${ok ? "✓" : "✖"} ${suffix}: ${pct.toFixed(1)}% (min ${min}%)`);
  if (!ok) failed = true;
}
process.exit(failed ? 1 : 0);
NODE
