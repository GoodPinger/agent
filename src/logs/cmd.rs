//! `gpr logs --test`: a dry-run that reads the configured
//! sources (or a single path argument) and prints EXACTLY what it would detect
//! and send — fingerprints, counts, and the redacted samples — so a user can
//! verify redaction before trusting the agent with production logs.
//!
//! This never sends anything. Log parsing fails silently and confusingly; this
//! command is the antidote.

use std::path::Path;

use crate::brand;
use crate::config::Config;
use crate::logs::file::FileTailer;
use crate::logs::journald::JournaldReader;
use crate::logs::{JournaldSourceConfig, LogSourceConfig, Pipeline, PipelineConfig};

/// Bound on poll iterations while draining a file in `--test` (belt-and-braces:
/// each poll already advances the offset, so this only guards a pathological
/// growing file).
const MAX_POLLS: usize = 100_000;

/// Entry point wired from `main`. Returns the process exit code.
pub fn cmd_logs_test(test: bool, path: Option<&Path>) -> i32 {
    if !test {
        eprintln!(
            "{}: only `--test` is supported today. Try: {} logs --test <path>",
            brand::CLI,
            brand::CLI
        );
        return 2;
    }

    // A single-path invocation is fully self-contained (no config needed).
    if let Some(path) = path {
        let mut pipeline = match Pipeline::new(PipelineConfig::default()) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{}: {e}", brand::CLI);
                return 1;
            }
        };
        println!("{} logs --test — dry run, nothing is sent\n", brand::CLI);
        let count = drain_file(&mut pipeline, path);
        println!("source: file {}", path.display());
        println!("  read {count} line(s)\n");
        report(&mut pipeline);
        return 0;
    }

    // Otherwise, read configured sources.
    let cfg = match Config::load_or_init() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}: {e}", brand::CLI);
            return 1;
        }
    };
    if cfg.log_sources.is_empty() {
        eprintln!(
            "{}: no log sources configured. Point at a file directly: {} logs --test <path>",
            brand::CLI,
            brand::CLI
        );
        return 1;
    }

    // One pipeline across all sources, so the distinct-signature cap is enforced
    // per host — matching how `gpr watch` will behave.
    let pcfg = crate::logs::pipeline_config_for(&cfg.log_sources);
    let mut pipeline = match Pipeline::new(pcfg) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{}: {e}", brand::CLI);
            return 1;
        }
    };

    println!("{} logs --test — dry run, nothing is sent\n", brand::CLI);
    for source in &cfg.log_sources {
        match source {
            LogSourceConfig::File(f) => {
                let count = drain_file(&mut pipeline, &f.path);
                println!("source: file {}", f.path.display());
                println!("  read {count} line(s)");
            }
            LogSourceConfig::Journald(j) => {
                describe_journald(&mut pipeline, j);
            }
        }
    }
    println!();
    report(&mut pipeline);
    0
}

/// Tail a file from the start, feeding every line into the pipeline. Returns the
/// number of lines read.
fn drain_file(pipeline: &mut Pipeline, path: &Path) -> usize {
    let mut tailer = FileTailer::from_start(path);
    let mut total = 0usize;
    for _ in 0..MAX_POLLS {
        match tailer.poll() {
            Ok(poll) => {
                if poll.lines.is_empty() {
                    break;
                }
                for line in &poll.lines {
                    pipeline.push_line(line);
                    total += 1;
                }
            }
            Err(e) => {
                eprintln!("{}: cannot read {}: {e}", brand::CLI, path.display());
                break;
            }
        }
    }
    pipeline.flush();
    total
}

/// Poll journald once (best-effort) and feed entries into the pipeline.
fn describe_journald(pipeline: &mut Pipeline, cfg: &JournaldSourceConfig) {
    let label = cfg.unit.as_deref().unwrap_or("(all units)");
    println!("source: journald {label}");
    let mut reader = JournaldReader::new(cfg.unit.clone(), cfg.min_priority);
    match reader.poll() {
        Ok(entries) => {
            for e in &entries {
                pipeline.push_journal(&e.message, e.priority);
            }
            println!("  read {} entr(y/ies)", entries.len());
        }
        Err(e) => {
            println!("  unavailable: {e}");
            println!(
                "  (journald requires Linux + read access; `{} doctor` explains permissions)",
                brand::CLI
            );
        }
    }
}

/// Print what the pipeline would send this interval.
fn report(pipeline: &mut Pipeline) {
    let drained = pipeline.drain();
    if drained.error_signatures.is_empty() {
        println!("no errors detected — nothing would be sent");
    } else {
        println!(
            "would send {} error signature(s) to /agent/report:",
            drained.error_signatures.len()
        );
        for sig in &drained.error_signatures {
            println!(
                "  [{}] {}× first={} last={}",
                sig.fingerprint, sig.count, sig.first_seen, sig.last_seen
            );
            println!("      sample: {}", sig.sample);
        }
    }
    if drained.dropped_signatures > 0 {
        println!(
            "dropped {} occurrence(s) past the per-interval signature cap",
            drained.dropped_signatures
        );
    }
    println!(
        "\nredaction is best-effort — verify the samples above before trusting production logs."
    );
}
