//! Persisted tailing state: a byte offset + content fingerprint per file, and a
//! `__CURSOR` per journald source. Lets the agent resume exactly
//! after a restart instead of replaying history or dropping lines.
//!
//! Fingerprint counts themselves are intentionally NOT persisted — losing them
//! on restart is acceptable and simpler. Only resume positions
//! are durable.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::logs::file::FileMark;

const STATE_FILE: &str = "logs_state.json";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LogState {
    /// Keyed by absolute file path.
    #[serde(default)]
    pub files: BTreeMap<String, FileMarkDto>,
    /// Keyed by source key (unit name, or "*" for the whole journal).
    #[serde(default)]
    pub journal_cursors: BTreeMap<String, String>,
}

/// Serializable twin of `file::FileMark` (that type stays serde-free so the
/// tailer has no wire concerns).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMarkDto {
    pub fingerprint: String,
    pub offset: u64,
}

impl From<FileMark> for FileMarkDto {
    fn from(m: FileMark) -> Self {
        Self {
            fingerprint: m.fingerprint,
            offset: m.offset,
        }
    }
}

impl From<FileMarkDto> for FileMark {
    fn from(d: FileMarkDto) -> Self {
        Self {
            fingerprint: d.fingerprint,
            offset: d.offset,
        }
    }
}

impl LogState {
    pub fn path_in(dir: &Path) -> PathBuf {
        dir.join(STATE_FILE)
    }

    /// Load state from `dir`, returning an empty state if none exists yet.
    pub fn load(dir: &Path) -> Result<Self> {
        let path = Self::path_in(dir);
        match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .with_context(|| format!("parsing log state at {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("reading log state at {}", path.display())),
        }
    }

    /// Persist atomically-ish (write temp, rename), matching `config.rs`.
    pub fn save(&self, dir: &Path) -> Result<()> {
        fs::create_dir_all(dir).with_context(|| format!("creating state dir {}", dir.display()))?;
        let path = Self::path_in(dir);
        let tmp = path.with_extension("json.tmp");
        let json = serde_json::to_vec_pretty(self).context("serializing log state")?;
        fs::write(&tmp, &json).with_context(|| format!("writing {}", tmp.display()))?;
        fs::rename(&tmp, &path).with_context(|| format!("renaming into {}", path.display()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = LogState::default();
        s.files.insert(
            "/var/log/app.log".to_string(),
            FileMarkDto {
                fingerprint: "deadbeef".to_string(),
                offset: 4096,
            },
        );
        s.journal_cursors
            .insert("myapp.service".to_string(), "s=abc;i=9".to_string());
        s.save(dir.path()).unwrap();

        let loaded = LogState::load(dir.path()).unwrap();
        assert_eq!(loaded.files["/var/log/app.log"].offset, 4096);
        assert_eq!(loaded.journal_cursors["myapp.service"], "s=abc;i=9");
    }

    #[test]
    fn missing_file_is_empty_state() {
        let dir = tempfile::tempdir().unwrap();
        let loaded = LogState::load(dir.path()).unwrap();
        assert!(loaded.files.is_empty());
        assert!(loaded.journal_cursors.is_empty());
    }
}
