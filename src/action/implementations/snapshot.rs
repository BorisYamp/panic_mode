/// Path: PanicMode/scr/action/implementations/snapshot.rs
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use async_trait::async_trait;
use tokio::process::Command;
use tokio::time::{timeout, Duration};

use crate::action::r#trait::{Action, ActionContext};
use crate::config::Config;

/// Takes a snapshot of the system state at the moment of an incident.
///
/// Runs diagnostic commands and saves their output to a file,
/// enabling post-mortem analysis of what was happening on the server.
pub struct SnapshotAction {
    config: Arc<Config>,
}

impl SnapshotAction {
    pub fn new(config: Arc<Config>) -> Result<Self> {
        Ok(Self { config })
    }

    async fn run_cmd(cmd: &str, args: &[&str]) -> String {
        match timeout(
            Duration::from_secs(5),
            Command::new(cmd).args(args).output(),
        )
        .await
        {
            Ok(Ok(output)) => {
                let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
                let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
                if stdout.is_empty() && !stderr.is_empty() {
                    format!("[stderr] {}", stderr)
                } else {
                    stdout
                }
            }
            Ok(Err(e)) => format!("[error] {}: {}", cmd, e),
            Err(_) => format!("[timeout] {} timed out after 5s", cmd),
        }
    }
}

#[async_trait]
impl Action for SnapshotAction {
    async fn execute(&self, ctx: &ActionContext<'_>) -> Result<()> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let snapshot_dir = &self.config.storage.snapshot_dir;
        tokio::fs::create_dir_all(snapshot_dir).await?;
        let path = format!("{}/panicmode-snapshot-{}.txt", snapshot_dir, timestamp);

        let incident_name = ctx.incident.name.clone();
        let incident_severity = format!("{:?}", ctx.incident.severity);
        let incident_desc = ctx.incident.description.clone();
        let incident_details = ctx.incident.metadata.details.clone();

        // Collect diagnostic data in parallel
        let (ps, netstat, mem, df, uptime) = tokio::join!(
            Self::run_cmd("ps", &["aux", "--sort=-%cpu"]),
            Self::run_cmd("ss", &["-tulpn"]),
            Self::run_cmd("free", &["-m"]),
            Self::run_cmd("df", &["-h"]),
            Self::run_cmd("uptime", &[]),
        );

        let content = format!(
            "=== PanicMode Snapshot ===\n\
             Timestamp: {}\n\
             Incident: {}\n\
             Severity: {}\n\
             Description: {}\n\
             Details: {}\n\
             \n\
             === UPTIME ===\n{}\n\
             === PROCESSES (top CPU) ===\n{}\n\
             === NETWORK (listening ports) ===\n{}\n\
             === MEMORY ===\n{}\n\
             === DISK ===\n{}\n",
            timestamp,
            incident_name,
            incident_severity,
            incident_desc,
            incident_details,
            uptime,
            ps,
            netstat,
            mem,
            df,
        );

        tokio::fs::write(&path, content).await?;

        tracing::error!("📸 Snapshot saved: {}", path);

        Ok(())
    }

    fn name(&self) -> &str {
        "snapshot"
    }
}
