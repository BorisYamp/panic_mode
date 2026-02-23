/// Path: PanicMode/scr/detector/rules.rs
use anyhow::Result;
use std::sync::Arc;
use std::cmp::Ordering;
use crate::config::{Config, MonitorRule, MonitorType, ActionType};
use crate::monitor::{Metrics, MonitorEngine};
use super::{Incident, IncidentSeverity, IncidentMetadata};

#[derive(Clone)]
pub struct RuleEvaluator {
    config: Arc<Config>,
    monitor_engine: Arc<MonitorEngine>, // needed for file/custom metrics
}

impl RuleEvaluator {
    pub fn new(config: Arc<Config>, monitor_engine: Arc<MonitorEngine>) -> Self {
        Self { config, monitor_engine }
    }
    
    /// Evaluate rule (async for file/custom metrics support).
    pub async fn evaluate(&self, rule: &MonitorRule, metrics: &Metrics) -> Result<Option<Incident>> {
        let current_value = self.get_current_value(rule, metrics).await?;
        
        if current_value > rule.threshold {
            let incident = Incident {
                name: rule.name.clone(),
                severity: self.determine_severity(rule),
                description: format!(
                    "{} exceeded threshold: {:.2} > {:.2}",
                    rule.name, current_value, rule.threshold
                ),
                actions: rule.actions.clone(),
                metadata: IncidentMetadata {
                    monitor_type: rule.monitor_type.clone(),
                    threshold: rule.threshold,
                    current_value,
                    details: self.get_details(rule, metrics),
                },
            };
            
            return Ok(Some(incident));
        }
        
        Ok(None)
    }
    
    /// Get current value (async!)
    async fn get_current_value(&self, rule: &MonitorRule, metrics: &Metrics) -> Result<f64> {
        let value = match rule.monitor_type {
            MonitorType::CpuUsage => metrics.cpu.usage_percent as f64,
            MonitorType::MemoryUsage => metrics.memory.usage_percent as f64,
            
            MonitorType::DiskUsage => {
                metrics.disk.mounts.iter()
                    .filter_map(|m| {
                        let val = m.usage_percent as f64;
                        if val.is_finite() { Some(val) } else { None }
                    })
                    .max_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal))
                    .unwrap_or(0.0)
            }
            
            MonitorType::ConnectionRate => metrics.network.connection_rate,
            MonitorType::AuthFailures => metrics.auth.failed_attempts as f64,
            MonitorType::ProcessCount => metrics.cpu.top_processes.len() as f64,
            MonitorType::SwapUsage => metrics.memory.swap_percent as f64,
            MonitorType::LoadAverage => metrics.cpu.load_avg.0,
            MonitorType::DiskIo => metrics.disk_io.max_util_percent as f64,
            
            // Full FileMonitor implementation.
            MonitorType::FileMonitor => {
                if rule.paths.is_empty() {
                    tracing::warn!("FileMonitor rule '{}' has no paths configured", rule.name);
                    return Ok(0.0);
                }
                
                // Get event count from file watcher
                self.monitor_engine.get_file_event_count(&rule.paths).await as f64
            }
            
            // Full Custom metric implementation.
            MonitorType::Custom => {
                match self.monitor_engine.execute_custom_metric(&rule.name).await {
                    Ok(value) => value,
                    Err(e) => {
                        tracing::error!("Custom metric '{}' failed: {}", rule.name, e);
                        0.0
                    }
                }
            }
        };
        
        Ok(value)
    }
    
    fn determine_severity(&self, rule: &MonitorRule) -> IncidentSeverity {
        for action in &rule.actions {
            match action {
                ActionType::AlertCritical | 
                ActionType::BlockIp | 
                ActionType::FreezeTopProcess |
                ActionType::KillProcess => {
                    return IncidentSeverity::Critical;
                }
                ActionType::AlertWarning | ActionType::RateLimit => {
                    return IncidentSeverity::Warning;
                }
                _ => {}
            }
        }
        IncidentSeverity::Info
    }
    
    fn get_details(&self, rule: &MonitorRule, metrics: &Metrics) -> String {
        match rule.monitor_type {
            MonitorType::CpuUsage => format!(
                "CPU: {:.1}%, load avg: {:.2}/{:.2}/{:.2} (1/5/15min), top: {}",
                metrics.cpu.usage_percent,
                metrics.cpu.load_avg.0,
                metrics.cpu.load_avg.1,
                metrics.cpu.load_avg.2,
                metrics.cpu.top_processes.first().map(|p| p.name.as_str()).unwrap_or("none"),
            ),
            MonitorType::MemoryUsage => format!(
                "RAM: {:.1}% ({}/{}MB), swap: {:.1}% ({}/{}MB)",
                metrics.memory.usage_percent,
                metrics.memory.used_mb,
                metrics.memory.total_mb,
                metrics.memory.swap_percent,
                metrics.memory.swap_used_mb,
                metrics.memory.swap_total_mb,
            ),
            MonitorType::DiskUsage => format!(
                "Disk: max {:.1}% across {} mount(s)",
                metrics.disk.mounts.iter()
                    .map(|m| m.usage_percent)
                    .fold(0.0_f32, f32::max),
                metrics.disk.mounts.len(),
            ),
            MonitorType::ConnectionRate => format!(
                "Connections: {} active, {:.1}/s, top IPs: {}",
                metrics.network.active_connections,
                metrics.network.connection_rate,
                metrics.network.top_ips.iter()
                    .take(3)
                    .map(|ip| format!("{}({})", ip.ip, ip.connection_count))
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
            MonitorType::AuthFailures => format!(
                "Auth failures: {}, from {} IP(s), successful logins: {}",
                metrics.auth.failed_attempts,
                metrics.auth.failures_by_ip.len(),
                metrics.auth.successful_logins,
            ),
            MonitorType::ProcessCount => format!(
                "Top processes tracked: {}",
                metrics.cpu.top_processes.len(),
            ),
            MonitorType::FileMonitor => format!(
                "File events on {} path(s): {}",
                rule.paths.len(),
                rule.paths.join(", "),
            ),
            MonitorType::Custom => format!(
                "Custom metric: {}",
                rule.name,
            ),
            MonitorType::SwapUsage => format!(
                "Swap: {:.1}% ({}/{}MB)",
                metrics.memory.swap_percent,
                metrics.memory.swap_used_mb,
                metrics.memory.swap_total_mb,
            ),
            MonitorType::LoadAverage => format!(
                "Load avg: {:.2}/{:.2}/{:.2} (1/5/15min)",
                metrics.cpu.load_avg.0,
                metrics.cpu.load_avg.1,
                metrics.cpu.load_avg.2,
            ),
            MonitorType::DiskIo => format!(
                "Disk I/O: max {:.1}% util, {} device(s), top: {}",
                metrics.disk_io.max_util_percent,
                metrics.disk_io.devices.len(),
                metrics.disk_io.devices.first().map(|d| d.name.as_str()).unwrap_or("none"),
            ),
        }
    }
}