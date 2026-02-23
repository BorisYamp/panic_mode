/// Path: PanicMode/scr/action/implementations/process.rs
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;

use crate::action::r#trait::{Action, ActionContext};
use crate::config::{Config, MassFreezeConfig};

/// Freezes the top CPU-consuming processes via SIGSTOP.
///
/// This is PanicMode's primary protective action: when the server is under load,
/// we immediately stop the offenders so the server can "catch its breath"
/// while the team investigates.
///
/// Processes can be unfrozen via SIGCONT or `kill -CONT <pid>`.
pub struct ProcessAction {
    _config: Arc<Config>,
    whitelist: Vec<String>,
    freeze_count: usize,
}

impl ProcessAction {
    pub fn new(config: Arc<Config>) -> Result<Self> {
        // Load whitelist and top_cpu.count from mass_freeze.yaml.
        // On any error fall back to defaults so sshd and panicmode are always protected.
        let freeze_cfg = MassFreezeConfig::load_from_path_or_default("/etc/panicmode")
            .unwrap_or_default();

        tracing::info!(
            "ProcessAction: freeze_count={}, whitelist={:?}",
            freeze_cfg.top_cpu.count,
            freeze_cfg.whitelist,
        );

        Ok(Self {
            _config: config,
            whitelist: freeze_cfg.whitelist,
            freeze_count: freeze_cfg.top_cpu.count,
        })
    }
}

#[async_trait]
impl Action for ProcessAction {
    async fn execute(&self, _ctx: &ActionContext<'_>) -> Result<()> {
        let freeze_count = self.freeze_count;
        let own_pid = std::process::id();
        let whitelist = self.whitelist.clone();

        tokio::task::spawn_blocking(move || {
            use sysinfo::System;

            let mut system = System::new();
            system.refresh_processes();

            let mut processes: Vec<_> = system.processes().values().collect();
            processes.sort_by(|a, b| {
                b.cpu_usage()
                    .partial_cmp(&a.cpu_usage())
                    .unwrap_or(std::cmp::Ordering::Equal)
            });

            let to_freeze: Vec<_> = processes
                .iter()
                .filter(|p| {
                    let pid = p.pid().as_u32();
                    let name = p.name().to_string().to_lowercase();
                    // Skip our own process
                    if pid == own_pid {
                        return false;
                    }
                    // Skip processes below the CPU threshold
                    if p.cpu_usage() <= 1.0 {
                        return false;
                    }
                    // Check whitelist: substring match (case-insensitive)
                    let is_whitelisted = whitelist
                        .iter()
                        .any(|w| name.contains(w.to_lowercase().as_str()));

                    if is_whitelisted {
                        tracing::debug!("Skipping whitelisted process: {} (pid {})", name, pid);
                    }

                    !is_whitelisted
                })
                .take(freeze_count)
                .collect();

            if to_freeze.is_empty() {
                tracing::info!("No processes to freeze (none above threshold or all whitelisted)");
                return Ok(());
            }

            for proc in &to_freeze {
                let pid = proc.pid().as_u32() as i32;
                #[cfg(unix)]
                unsafe {
                    if libc::kill(pid, libc::SIGSTOP) == 0 {
                        tracing::warn!(
                            "FROZEN: {} (pid {}, cpu {:.1}%)",
                            proc.name(),
                            pid,
                            proc.cpu_usage()
                        );
                    } else {
                        tracing::warn!(
                            "Failed to freeze {} (pid {}): permission denied or process gone",
                            proc.name(),
                            pid
                        );
                    }
                }
                #[cfg(not(unix))]
                {
                    tracing::warn!(
                        "SIGSTOP not supported on this platform, skipping {} (pid {})",
                        proc.name(),
                        pid
                    );
                }
            }

            tracing::warn!(
                "Frozen {} process(es). To resume: kill -CONT <pid>",
                to_freeze.len()
            );

            Ok::<(), anyhow::Error>(())
        })
        .await?
    }

    fn name(&self) -> &str {
        "process_freeze"
    }
}
