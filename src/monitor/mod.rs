/// Path: PanicMode/scr/monitor/mod.rs
use anyhow::Result;
use std::sync::Arc;
use std::time::{SystemTime, Duration, Instant};
use tokio::sync::{RwLock, Mutex};
use serde::{Deserialize, Serialize};

mod cpu;
mod memory;
mod network;
mod auth;
mod file_watcher;
mod custom_metrics;
mod disk_io;

pub use cpu::CpuMonitor;
pub use memory::MemoryMonitor;
pub use network::NetworkMonitor;
pub use auth::AuthMonitor;
pub use file_watcher::FileWatcher;
pub use custom_metrics::CustomMetricsExecutor;
pub use disk_io::{DiskIoMetrics, DiskIoDevice, DiskIoMonitor};

use crate::config::Config;

// ============================================================================
// Metrics structures
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metrics {
    pub timestamp: SystemTime,
    pub cpu: CpuMetrics,
    pub memory: MemoryMetrics,
    pub network: NetworkMetrics,
    pub auth: AuthMetrics,
    pub disk: DiskMetrics,
    pub disk_io: DiskIoMetrics,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CpuMetrics {
    pub usage_percent: f32,
    pub per_core: Vec<f32>,
    pub load_avg: (f64, f64, f64),
    pub top_processes: Vec<ProcessInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub cpu_percent: f32,
    pub memory_mb: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemoryMetrics {
    pub total_mb: u64,
    pub used_mb: u64,
    pub available_mb: u64,
    pub usage_percent: f32,
    pub swap_total_mb: u64,
    pub swap_used_mb: u64,
    pub swap_percent: f32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkMetrics {
    pub new_connections: u64,
    pub active_connections: u64,
    pub connection_rate: f64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub top_ips: Vec<IpConnectionInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpConnectionInfo {
    pub ip: String,
    pub connection_count: u64,
    pub is_suspicious: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthMetrics {
    pub failed_attempts: u64,
    pub failures_by_ip: Vec<AuthFailureInfo>,
    pub successful_logins: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthFailureInfo {
    pub ip: String,
    pub username: String,
    pub attempt_count: u64,
    pub last_attempt: SystemTime,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiskMetrics {
    pub mounts: Vec<MountInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountInfo {
    pub mount_point: String,
    pub total_gb: u64,
    pub used_gb: u64,
    pub available_gb: u64,
    pub usage_percent: f32,
}

// ============================================================================
// MonitorEngine
// ============================================================================

pub struct MonitorEngine {
    config: Arc<Config>,
    cpu_monitor: CpuMonitor,
    memory_monitor: MemoryMonitor,
    network_monitor: NetworkMonitor,
    auth_monitor: AuthMonitor,
    disk_io_monitor: DiskIoMonitor,

    // File watcher
    file_watcher: Arc<Mutex<FileWatcher>>,

    // Custom metrics executor
    custom_metrics: Arc<CustomMetricsExecutor>,

    // Thread-safe disk cache
    disk_cache: Arc<RwLock<Option<(Instant, DiskMetrics)>>>,
    disk_cache_ttl: Duration,
}

impl MonitorEngine {
    pub fn new(config: Arc<Config>) -> Result<Self> {
        // Initialize file watcher
        let file_watcher = FileWatcher::new(
            config.file_monitor.max_events_per_path,
            config.file_monitor.aggregation_window.unwrap_or(Duration::from_secs(60))
        )?;
        
        Ok(Self {
            config,
            cpu_monitor: CpuMonitor::new()?,
            memory_monitor: MemoryMonitor::new()?,
            network_monitor: NetworkMonitor::new(config.anomaly.suspicious_connections_per_ip)?,
            auth_monitor: AuthMonitor::new()?,
            disk_io_monitor: DiskIoMonitor::new()?,
            file_watcher: Arc::new(Mutex::new(file_watcher)),
            custom_metrics: Arc::new(CustomMetricsExecutor::new()),
            disk_cache: Arc::new(RwLock::new(None)),
            disk_cache_ttl: Duration::from_secs(60),
        })
    }
    
    /// Start watching paths
    pub async fn start_file_monitoring(&self, paths: Vec<String>) -> Result<()> {
        let mut watcher = self.file_watcher.lock().await;
        
        for path in paths {
            watcher.watch_path(&path)?;
        }
        
        Ok(())
    }
    
    /// Get file event count
    pub async fn get_file_event_count(&self, paths: &[String]) -> u64 {
        let watcher = self.file_watcher.lock().await;
        watcher.get_event_count(paths).await
    }
    
    /// Execute custom metric
    pub async fn execute_custom_metric(&self, metric_name: &str) -> Result<f64> {
        let metric_config = self.config.custom_metrics.get(metric_name)
            .ok_or_else(|| anyhow::anyhow!("Custom metric '{}' not configured", metric_name))?;
        
        self.custom_metrics.execute_metric(
            metric_name,
            &metric_config.command,
            metric_config.timeout,
            metric_config.cache_ttl,
            &metric_config.output_format
        ).await
    }
    
    /// Collect all metrics (parallel execution)
    pub fn check_interval(&self) -> Duration {
        self.config.performance.check_interval
    }

    pub async fn collect_metrics(&self) -> Result<Metrics> {
        let cpu_monitor = self.cpu_monitor.clone();
        let memory_monitor = self.memory_monitor.clone();
        let network_monitor = self.network_monitor.clone();
        let auth_monitor = self.auth_monitor.clone();
        let disk_io_monitor = self.disk_io_monitor.clone();

        // Parallel collection
        let (cpu_result, memory_result, network_result, auth_result, disk_result, disk_io_result) =
            tokio::join!(
                tokio::task::spawn_blocking(move || cpu_monitor.collect()),
                tokio::task::spawn_blocking(move || memory_monitor.collect()),
                tokio::task::spawn_blocking(move || network_monitor.collect()),
                tokio::task::spawn_blocking(move || auth_monitor.collect()),
                self.collect_disk_metrics_cached(),
                tokio::task::spawn_blocking(move || disk_io_monitor.collect()),
            );

        // Graceful degradation: a single failing monitor returns zeroed defaults
        // instead of failing the entire collection cycle.
        fn unwrap_monitor<T, E1, E2>(
            result: Result<Result<T, E1>, E2>,
            name: &str,
        ) -> T
        where
            T: Default,
            E1: std::fmt::Display,
            E2: std::fmt::Display,
        {
            match result {
                Ok(Ok(m)) => m,
                Ok(Err(e)) => {
                    tracing::error!("{} monitor error: {}", name, e);
                    T::default()
                }
                Err(e) => {
                    tracing::error!("{} monitor task panicked: {}", name, e);
                    T::default()
                }
            }
        }

        Ok(Metrics {
            timestamp: SystemTime::now(),
            cpu:      unwrap_monitor(cpu_result,     "CPU"),
            memory:   unwrap_monitor(memory_result,  "Memory"),
            network:  unwrap_monitor(network_result, "Network"),
            auth:     unwrap_monitor(auth_result,    "Auth"),
            disk:     disk_result.unwrap_or_else(|e| {
                          tracing::error!("Disk monitor error: {}", e);
                          DiskMetrics::default()
                      }),
            disk_io:  unwrap_monitor(disk_io_result, "DiskIO"),
        })
    }
    
    async fn collect_disk_metrics_cached(&self) -> Result<DiskMetrics> {
        let now = Instant::now();
        
        {
            let cache = self.disk_cache.read().await;
            if let Some((cached_at, ref metrics)) = *cache {
                if now.duration_since(cached_at) < self.disk_cache_ttl {
                    return Ok(metrics.clone());
                }
            }
        }
        
        let metrics = tokio::task::spawn_blocking(|| collect_disk_info()).await??;
        
        {
            let mut cache = self.disk_cache.write().await;
            *cache = Some((now, metrics.clone()));
        }
        
        Ok(metrics)
    }
}

impl Clone for MonitorEngine {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            cpu_monitor: self.cpu_monitor.clone(),
            memory_monitor: self.memory_monitor.clone(),
            network_monitor: self.network_monitor.clone(),
            auth_monitor: self.auth_monitor.clone(),
            disk_io_monitor: self.disk_io_monitor.clone(),
            file_watcher: self.file_watcher.clone(),
            custom_metrics: self.custom_metrics.clone(),
            disk_cache: self.disk_cache.clone(),
            disk_cache_ttl: self.disk_cache_ttl,
        }
    }
}

fn collect_disk_info() -> Result<DiskMetrics> {
    use sysinfo::{System, Disks};
    
    let disks = Disks::new_with_refreshed_list();
    let mut mounts = Vec::new();
    
    for disk in disks.list() {
        let total_bytes = disk.total_space();
        let available_bytes = disk.available_space();
        let used_bytes = total_bytes.saturating_sub(available_bytes);
        
        let total_gb = total_bytes / (1024 * 1024 * 1024);
        let used_gb = used_bytes / (1024 * 1024 * 1024);
        let available_gb = available_bytes / (1024 * 1024 * 1024);
        
        let usage_percent = if total_bytes > 0 {
            (used_bytes as f64 / total_bytes as f64 * 100.0) as f32
        } else {
            0.0
        };
        
        mounts.push(MountInfo {
            mount_point: disk.mount_point().to_string_lossy().to_string(),
            total_gb,
            used_gb,
            available_gb,
            usage_percent,
        });
    }
    
    Ok(DiskMetrics { mounts })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::*;
    use std::collections::HashMap;

    fn create_test_config() -> Config {
        Config {
            performance: PerformanceConfig {
                cpu_limit: 5.0,
                memory_limit_mb: 50,
                check_interval: Duration::from_secs(5),
            },
            monitors: vec![],
            actions: HashMap::new(),
            alerts: AlertsConfig {
                critical: vec![],
                warning: vec![],
                info: vec![],
            },
            integrations: IntegrationsConfig {
                telegram: None,
                discord: None,
                ntfy: None,
                email: None,
                twilio: None,
            },
            custom_metrics: HashMap::new(),
            file_monitor: FileMonitorConfig::default(),
            circuit_breakers: CircuitBreakerConfig::default(),
            ..Config::default()
        }
    }

    #[tokio::test]
    async fn test_collect_metrics() {
        let config = Arc::new(create_test_config());
        let engine = MonitorEngine::new(config).unwrap();
        
        let metrics = engine.collect_metrics().await.unwrap();
        
        assert!(metrics.cpu.usage_percent >= 0.0 && metrics.cpu.usage_percent <= 100.0);
        assert!(metrics.memory.usage_percent >= 0.0 && metrics.memory.usage_percent <= 100.0);
        assert!(metrics.memory.total_mb > 0);
    }
}