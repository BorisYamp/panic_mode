/// Path: PanicMode/scr/monitor/cpu.rs
use anyhow::Result;
use super::{CpuMetrics, ProcessInfo};
use std::thread;
use std::time::Duration;

#[derive(Clone)]
pub struct CpuMonitor {
    // No internal state needed
}

impl CpuMonitor {
    pub fn new() -> Result<Self> {
        Ok(Self {})
    }
    
    pub fn collect(&self) -> Result<CpuMetrics> {
        // Double measurement for accuracy
        let measurement1 = self.measure_cpu()?;
        thread::sleep(Duration::from_millis(100));
        let measurement2 = self.measure_cpu()?;
        
        let usage_percent = self.calculate_cpu_usage(&measurement1, &measurement2);
        let per_core = self.calculate_per_core_usage(&measurement1, &measurement2);
        let load_avg = self.get_load_average()?;
        let top_processes = self.get_top_processes()?;
        
        Ok(CpuMetrics {
            usage_percent,
            per_core,
            load_avg,
            top_processes,
        })
    }
    
    fn measure_cpu(&self) -> Result<CpuMeasurement> {
        use std::fs;
        
        let stat = fs::read_to_string("/proc/stat")?;
        let mut total_time = 0u64;
        let mut idle_time = 0u64;
        let mut per_core_times = Vec::new();
        
        for line in stat.lines() {
            if line.starts_with("cpu ") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                for i in 1..parts.len() {
                    total_time += parts[i].parse::<u64>().unwrap_or(0);
                }
                idle_time = parts.get(4).and_then(|s| s.parse().ok()).unwrap_or(0);
            } else if line.starts_with("cpu") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                let mut core_total = 0u64;
                let mut core_idle = 0u64;
                
                for i in 1..parts.len() {
                    core_total += parts[i].parse::<u64>().unwrap_or(0);
                }
                core_idle = parts.get(4).and_then(|s| s.parse().ok()).unwrap_or(0);
                
                per_core_times.push((core_total, core_idle));
            }
        }
        
        Ok(CpuMeasurement {
            total_time,
            idle_time,
            per_core_times,
        })
    }
    
    fn calculate_cpu_usage(&self, m1: &CpuMeasurement, m2: &CpuMeasurement) -> f32 {
        let total_delta = m2.total_time.saturating_sub(m1.total_time);
        let idle_delta = m2.idle_time.saturating_sub(m1.idle_time);
        
        if total_delta == 0 {
            return 0.0;
        }
        
        let usage = total_delta.saturating_sub(idle_delta);
        (usage as f64 / total_delta as f64 * 100.0) as f32
    }
    
    fn calculate_per_core_usage(&self, m1: &CpuMeasurement, m2: &CpuMeasurement) -> Vec<f32> {
        let mut per_core = Vec::new();
        
        for (i, (total2, idle2)) in m2.per_core_times.iter().enumerate() {
            if let Some((total1, idle1)) = m1.per_core_times.get(i) {
                let total_delta = total2.saturating_sub(*total1);
                let idle_delta = idle2.saturating_sub(*idle1);
                
                if total_delta > 0 {
                    let usage = total_delta.saturating_sub(idle_delta);
                    per_core.push((usage as f64 / total_delta as f64 * 100.0) as f32);
                } else {
                    per_core.push(0.0);
                }
            }
        }
        
        per_core
    }
    
    fn get_load_average(&self) -> Result<(f64, f64, f64)> {
        use std::fs;
        
        let loadavg = fs::read_to_string("/proc/loadavg")?;
        let parts: Vec<&str> = loadavg.split_whitespace().collect();
        
        let load1 = parts.get(0).and_then(|s| s.parse().ok()).unwrap_or(0.0);
        let load5 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0.0);
        let load15 = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0.0);
        
        Ok((load1, load5, load15))
    }
    
    fn get_top_processes(&self) -> Result<Vec<ProcessInfo>> {
        use sysinfo::{System, ProcessRefreshKind};
        
        let mut sys = System::new();
        sys.refresh_processes_specifics(ProcessRefreshKind::everything());
        
        let mut processes: Vec<_> = sys.processes()
            .iter()
            .map(|(pid, process)| {
                ProcessInfo {
                    pid: pid.as_u32(),
                    name: process.name().to_string_lossy().to_string(),
                    cpu_percent: process.cpu_usage(),
                    memory_mb: process.memory() / 1024,
                }
            })
            .collect();
        
        processes.sort_by(|a, b| b.cpu_percent.partial_cmp(&a.cpu_percent).unwrap_or(std::cmp::Ordering::Equal));
        processes.truncate(10);
        
        Ok(processes)
    }
}

struct CpuMeasurement {
    total_time: u64,
    idle_time: u64,
    per_core_times: Vec<(u64, u64)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpu_monitor() {
        let monitor = CpuMonitor::new().unwrap();
        let metrics = monitor.collect().unwrap();
        
        assert!(metrics.usage_percent >= 0.0 && metrics.usage_percent <= 100.0);
        assert!(!metrics.per_core.is_empty());
    }
}