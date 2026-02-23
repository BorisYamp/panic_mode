/// Path: PanicMode/src/detector/state.rs
use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{warn};

use super::Incident;

/// Wire format for JSON persistence.
#[derive(Debug, Serialize, Deserialize)]
struct PersistedState {
    /// incident_name -> unix timestamp of last occurrence (seconds)
    incidents: HashMap<String, u64>,
    dedup_window_secs: u64,
}

/// Tracks recent incident history for deduplication.
///
/// State is persisted to disk so that a quick restart does not lose
/// the dedup window.  On every clean startup expired entries are pruned.
#[derive(Debug, Clone)]
pub struct IncidentState {
    /// incident_name -> time of last occurrence
    incidents: HashMap<String, Instant>,
    dedup_window: Duration,
    state_file: String,
}

impl Default for IncidentState {
    fn default() -> Self {
        Self {
            incidents: HashMap::new(),
            dedup_window: Duration::from_secs(300), // 5 minutes
            state_file: "/var/lib/panicmode/incident_state.json".to_string(),
        }
    }
}

impl IncidentState {
    /// Load persisted state from `state_file`.
    ///
    /// Never fails — if the file is missing, corrupt, or unreadable,
    /// a fresh empty state is returned and a warning is logged.
    pub fn load(state_file: String) -> Self {
        let mut state = Self {
            incidents: HashMap::new(),
            dedup_window: Duration::from_secs(300),
            state_file: state_file.clone(),
        };

        let data = match std::fs::read_to_string(&state_file) {
            Ok(d) => d,
            Err(e) => {
                if e.kind() != std::io::ErrorKind::NotFound {
                    warn!("Could not read state file {state_file}: {e}");
                }
                return state; // file absent → fresh state, that's fine
            }
        };

        let persisted: PersistedState = match serde_json::from_str(&data) {
            Ok(p) => p,
            Err(e) => {
                warn!("State file {state_file} is corrupt, starting fresh: {e}");
                return state;
            }
        };

        state.dedup_window = Duration::from_secs(persisted.dedup_window_secs);

        let now_unix = now_unix_secs();
        let window = persisted.dedup_window_secs;

        for (name, ts) in persisted.incidents {
            let age_secs = now_unix.saturating_sub(ts);
            if age_secs >= window {
                // Entry expired — skip it, no need to restore
                continue;
            }
            // Reconstruct an Instant that is `age_secs` in the past
            let age = Duration::from_secs(age_secs);
            if let Some(instant) = Instant::now().checked_sub(age) {
                state.incidents.insert(name, instant);
            }
        }

        state
    }

    /// Persist state to disk using an atomic write (tmp → rename).
    pub async fn save(&self) -> Result<()> {
        let now_unix = now_unix_secs();

        let incidents: HashMap<String, u64> = self
            .incidents
            .iter()
            .map(|(name, instant)| {
                let age_secs = instant.elapsed().as_secs();
                let ts = now_unix.saturating_sub(age_secs);
                (name.clone(), ts)
            })
            .collect();

        let persisted = PersistedState {
            incidents,
            dedup_window_secs: self.dedup_window.as_secs(),
        };

        let json = serde_json::to_string(&persisted)
            .context("Failed to serialize incident state")?;

        // Ensure parent directory exists
        if let Some(parent) = std::path::Path::new(&self.state_file).parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("Failed to create dir {}", parent.display()))?;
        }

        // Atomic write: write to .tmp, then rename
        let tmp_path = format!("{}.tmp", self.state_file);
        tokio::fs::write(&tmp_path, &json)
            .await
            .with_context(|| format!("Failed to write {tmp_path}"))?;

        tokio::fs::rename(&tmp_path, &self.state_file)
            .await
            .with_context(|| format!("Failed to rename {tmp_path} -> {}", self.state_file))?;

        Ok(())
    }

    /// Returns `true` if the same incident occurred within the dedup window.
    pub fn is_duplicate(&self, incident: &Incident) -> bool {
        match self.incidents.get(&incident.name) {
            Some(last_seen) => last_seen.elapsed() < self.dedup_window,
            None => false,
        }
    }

    /// Record that an incident just occurred.
    pub fn record_incident(&mut self, incident: &Incident) {
        self.incidents.insert(incident.name.clone(), Instant::now());
    }
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::ActionType;
    use crate::config::MonitorType;
    use crate::detector::{IncidentMetadata, IncidentSeverity};

    fn make_incident(name: &str) -> Incident {
        Incident {
            name: name.to_string(),
            severity: IncidentSeverity::Critical,
            description: "test".to_string(),
            actions: vec![ActionType::AlertCritical],
            metadata: IncidentMetadata {
                monitor_type: MonitorType::CpuUsage,
                threshold: 80.0,
                current_value: 95.0,
                details: "test".to_string(),
            },
        }
    }

    #[test]
    fn test_new_incident_not_duplicate() {
        let state = IncidentState::load("/tmp/panicmode_test_state_new.json".to_string());
        assert!(!state.is_duplicate(&make_incident("cpu_high")));
    }

    #[test]
    fn test_recorded_incident_is_duplicate() {
        let mut state = IncidentState::load("/tmp/panicmode_test_state_rec.json".to_string());
        let incident = make_incident("cpu_high");
        state.record_incident(&incident);
        assert!(state.is_duplicate(&incident));
    }

    #[test]
    fn test_different_incidents_independent() {
        let mut state = IncidentState::load("/tmp/panicmode_test_state_ind.json".to_string());
        let inc1 = make_incident("cpu_high");
        let inc2 = make_incident("memory_high");
        state.record_incident(&inc1);
        assert!(state.is_duplicate(&inc1));
        assert!(!state.is_duplicate(&inc2));
    }

    #[tokio::test]
    async fn test_save_and_load_roundtrip() {
        let path = "/tmp/panicmode_test_roundtrip.json".to_string();
        // Clean up from previous run
        let _ = std::fs::remove_file(&path);

        let mut state = IncidentState::load(path.clone());
        let incident = make_incident("disk_full");
        state.record_incident(&incident);
        state.save().await.expect("save should succeed");

        let loaded = IncidentState::load(path.clone());
        assert!(loaded.is_duplicate(&incident), "should still be in dedup window after reload");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_missing_file_returns_fresh_state() {
        let state = IncidentState::load("/tmp/panicmode_does_not_exist_xyz.json".to_string());
        assert!(state.incidents.is_empty());
    }
}
