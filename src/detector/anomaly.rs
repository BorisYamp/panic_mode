/// Path: PanicMode/src/detector/anomaly.rs
use anyhow::Result;
use super::{Incident, IncidentSeverity, IncidentMetadata};
use crate::monitor::Metrics;
use crate::config::{ActionType, AnomalyConfig, MonitorType};

#[derive(Clone)]
pub struct AnomalyDetector {
    cpu_spike_threshold: f32,
    memory_spike_threshold: f32,
    connection_spike_threshold: u64,
    suspicious_ip_threshold: usize,
    high_load_threshold: f64,
}

impl AnomalyDetector {
    /// Build from the [anomaly] section of panicmode.yaml.
    pub fn from_config(cfg: &AnomalyConfig) -> Self {
        Self {
            cpu_spike_threshold: cfg.cpu_spike_threshold,
            memory_spike_threshold: cfg.memory_spike_threshold,
            connection_spike_threshold: cfg.connection_spike_threshold,
            suspicious_ip_threshold: cfg.suspicious_ip_threshold,
            high_load_threshold: cfg.high_load_threshold,
        }
    }

    /// Detect ALL anomalies (do not stop at the first one!)
    pub fn detect_anomalies(&self, metrics: &Metrics) -> Result<Option<Incident>> {
        let mut detected = Vec::new();

        if let Some(i) = self.detect_cpu_spike(metrics)? {
            detected.push(i);
        }
        if let Some(i) = self.detect_high_load(metrics)? {
            detected.push(i);
        }
        if let Some(i) = self.detect_memory_spike(metrics)? {
            detected.push(i);
        }
        if let Some(i) = self.detect_connection_flood(metrics)? {
            detected.push(i);
        }
        if let Some(i) = self.detect_suspicious_ips(metrics)? {
            detected.push(i);
        }

        if detected.is_empty() {
            return Ok(None);
        }

        // Sort: Critical first
        detected.sort_by(|a, b| b.severity.cmp(&a.severity));

        let critical_count = detected.iter()
            .filter(|i| i.severity == IncidentSeverity::Critical)
            .count();

        if critical_count > 1 {
            let combined_names: Vec<_> = detected.iter()
                .take(critical_count)
                .map(|i| i.name.clone())
                .collect();

            let combined_actions: Vec<_> = detected.iter()
                .take(critical_count)
                .flat_map(|i| i.actions.clone())
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect();

            Ok(Some(Incident {
                name: format!("Multiple Critical Anomalies: {}", combined_names.join(", ")),
                severity: IncidentSeverity::Critical,
                description: format!("{} critical anomalies detected simultaneously", critical_count),
                actions: combined_actions,
                metadata: detected[0].metadata.clone(),
            }))
        } else {
            Ok(Some(detected.into_iter().next().unwrap()))
        }
    }

    /// High CPU usage — fires as soon as CPU >= threshold.
    /// Does NOT require high load average (that's a separate detector).
    fn detect_cpu_spike(&self, metrics: &Metrics) -> Result<Option<Incident>> {
        if metrics.cpu.usage_percent < self.cpu_spike_threshold {
            return Ok(None);
        }
        Ok(Some(Incident {
            name: "CPU Spike".to_string(),
            severity: IncidentSeverity::Critical,
            description: format!(
                "CPU at {:.1}% (threshold: {:.1}%)",
                metrics.cpu.usage_percent,
                self.cpu_spike_threshold,
            ),
            actions: vec![ActionType::AlertCritical, ActionType::FreezeTopProcess],
            metadata: IncidentMetadata {
                monitor_type: MonitorType::CpuUsage,
                threshold: self.cpu_spike_threshold as f64,
                current_value: metrics.cpu.usage_percent as f64,
                details: format!(
                    "Load: {:.2} {:.2} {:.2}, Top: {}",
                    metrics.cpu.load_avg.0,
                    metrics.cpu.load_avg.1,
                    metrics.cpu.load_avg.2,
                    metrics.cpu.top_processes.first()
                        .map(|p| format!("{} ({:.1}%)", p.name, p.cpu_percent))
                        .unwrap_or_else(|| "none".to_string())
                ),
            },
        }))
    }

    /// High load average — fires regardless of CPU percentage.
    /// Catches I/O-bound servers where CPU% is moderate but the system is overloaded.
    fn detect_high_load(&self, metrics: &Metrics) -> Result<Option<Incident>> {
        if metrics.cpu.load_avg.0 < self.high_load_threshold {
            return Ok(None);
        }
        Ok(Some(Incident {
            name: "High Load Average".to_string(),
            severity: IncidentSeverity::Critical,
            description: format!(
                "Load average {:.2} exceeds threshold {:.2}",
                metrics.cpu.load_avg.0,
                self.high_load_threshold,
            ),
            actions: vec![ActionType::AlertCritical, ActionType::Snapshot],
            metadata: IncidentMetadata {
                monitor_type: MonitorType::CpuUsage,
                threshold: self.high_load_threshold,
                current_value: metrics.cpu.load_avg.0,
                details: format!(
                    "Load: {:.2} {:.2} {:.2}, CPU: {:.1}%",
                    metrics.cpu.load_avg.0,
                    metrics.cpu.load_avg.1,
                    metrics.cpu.load_avg.2,
                    metrics.cpu.usage_percent,
                ),
            },
        }))
    }

    fn detect_memory_spike(&self, metrics: &Metrics) -> Result<Option<Incident>> {
        if metrics.memory.usage_percent < self.memory_spike_threshold
            || metrics.memory.swap_percent <= 50.0
        {
            return Ok(None);
        }
        Ok(Some(Incident {
            name: "Memory Exhaustion".to_string(),
            severity: IncidentSeverity::Critical,
            description: format!(
                "Memory at {:.1}% with heavy swapping ({:.1}%) - OOM risk",
                metrics.memory.usage_percent,
                metrics.memory.swap_percent,
            ),
            actions: vec![ActionType::AlertCritical, ActionType::Snapshot],
            metadata: IncidentMetadata {
                monitor_type: MonitorType::MemoryUsage,
                threshold: self.memory_spike_threshold as f64,
                current_value: metrics.memory.usage_percent as f64,
                details: format!(
                    "Available: {}MB, Swap: {}MB ({:.1}%)",
                    metrics.memory.available_mb,
                    metrics.memory.swap_used_mb,
                    metrics.memory.swap_percent,
                ),
            },
        }))
    }

    fn detect_connection_flood(&self, metrics: &Metrics) -> Result<Option<Incident>> {
        if metrics.network.active_connections <= self.connection_spike_threshold {
            return Ok(None);
        }
        Ok(Some(Incident {
            name: "Connection Flood".to_string(),
            severity: IncidentSeverity::Critical,
            description: format!(
                "{} active connections (threshold: {}) - possible DDoS",
                metrics.network.active_connections,
                self.connection_spike_threshold,
            ),
            actions: vec![
                ActionType::BlockIp,
                ActionType::RateLimit,
                ActionType::AlertCritical,
            ],
            metadata: IncidentMetadata {
                monitor_type: MonitorType::ConnectionRate,
                threshold: self.connection_spike_threshold as f64,
                current_value: metrics.network.active_connections as f64,
                details: format!(
                    "Rate: {:.2}/s, New: {}, Top IPs: {}",
                    metrics.network.connection_rate,
                    metrics.network.new_connections,
                    metrics.network.top_ips.iter()
                        .take(5)
                        .map(|ip| format!("{}({})", ip.ip, ip.connection_count))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            },
        }))
    }

    fn detect_suspicious_ips(&self, metrics: &Metrics) -> Result<Option<Incident>> {
        let suspicious_count = metrics.network.top_ips.iter()
            .filter(|ip| ip.is_suspicious)
            .count();

        if suspicious_count < self.suspicious_ip_threshold {
            return Ok(None);
        }

        let suspicious_ips: Vec<_> = metrics.network.top_ips.iter()
            .filter(|ip| ip.is_suspicious)
            .map(|ip| format!("{}({})", ip.ip, ip.connection_count))
            .collect();

        Ok(Some(Incident {
            name: "Coordinated Attack".to_string(),
            severity: IncidentSeverity::Critical,
            description: format!(
                "{} suspicious IPs (threshold: {}) - coordinated attack pattern",
                suspicious_count,
                self.suspicious_ip_threshold,
            ),
            actions: vec![ActionType::BlockIp, ActionType::AlertCritical],
            metadata: IncidentMetadata {
                monitor_type: MonitorType::ConnectionRate,
                threshold: self.suspicious_ip_threshold as f64,
                current_value: suspicious_count as f64,
                details: suspicious_ips.join(", "),
            },
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AnomalyConfig;
    use crate::monitor::*;
    use std::time::SystemTime;

    fn default_detector() -> AnomalyDetector {
        AnomalyDetector::from_config(&AnomalyConfig::default())
    }

    fn empty_metrics() -> Metrics {
        Metrics {
            timestamp: SystemTime::now(),
            cpu: CpuMetrics {
                usage_percent: 0.0,
                per_core: vec![],
                load_avg: (0.0, 0.0, 0.0),
                top_processes: vec![],
            },
            memory: MemoryMetrics {
                total_mb: 8000,
                used_mb: 0,
                available_mb: 8000,
                usage_percent: 0.0,
                swap_total_mb: 2000,
                swap_used_mb: 0,
                swap_percent: 0.0,
            },
            network: NetworkMetrics {
                new_connections: 0,
                active_connections: 0,
                connection_rate: 0.0,
                bytes_received: 0,
                bytes_sent: 0,
                top_ips: vec![],
            },
            auth: AuthMetrics {
                failed_attempts: 0,
                failures_by_ip: vec![],
                successful_logins: 0,
            },
            disk: DiskMetrics { mounts: vec![] },
            disk_io: DiskIoMetrics::default(),
        }
    }

    #[test]
    fn test_no_anomalies_on_clean_metrics() {
        let result = default_detector().detect_anomalies(&empty_metrics()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_cpu_spike_fires_without_load_condition() {
        let mut m = empty_metrics();
        m.cpu.usage_percent = 97.0;
        m.cpu.load_avg = (1.0, 1.0, 1.0); // low load — must still fire
        let result = default_detector().detect_anomalies(&m).unwrap();
        assert!(result.is_some());
        let inc = result.unwrap();
        assert!(inc.name.contains("CPU Spike") || inc.name.contains("Multiple"));
    }

    #[test]
    fn test_high_load_fires_without_cpu_spike() {
        let mut m = empty_metrics();
        m.cpu.usage_percent = 40.0; // moderate CPU
        m.cpu.load_avg = (15.0, 12.0, 10.0); // high load — I/O-bound
        let result = default_detector().detect_anomalies(&m).unwrap();
        assert!(result.is_some());
        let inc = result.unwrap();
        assert!(inc.name.contains("High Load") || inc.name.contains("Multiple"));
    }

    #[test]
    fn test_multiple_anomalies_combined() {
        let mut m = empty_metrics();
        m.cpu.usage_percent = 98.0;
        m.cpu.load_avg = (12.0, 10.0, 8.0);
        m.memory.usage_percent = 96.0;
        m.memory.swap_percent = 75.0;
        m.network.active_connections = 15_000;

        let result = default_detector().detect_anomalies(&m).unwrap();
        assert!(result.is_some());
        assert!(result.unwrap().name.contains("Multiple"));
    }

    #[test]
    fn test_from_config_uses_thresholds() {
        let cfg = AnomalyConfig {
            cpu_spike_threshold: 80.0,
            memory_spike_threshold: 80.0,
            connection_spike_threshold: 5_000,
            suspicious_ip_threshold: 2,
            high_load_threshold: 5.0,
        };
        let detector = AnomalyDetector::from_config(&cfg);

        // CPU at 82% must fire with threshold=80
        let mut m = empty_metrics();
        m.cpu.usage_percent = 82.0;
        let result = detector.detect_anomalies(&m).unwrap();
        assert!(result.is_some());

        // CPU at 78% must NOT fire
        m.cpu.usage_percent = 78.0;
        let result = detector.detect_anomalies(&m).unwrap();
        assert!(result.is_none());
    }
}
