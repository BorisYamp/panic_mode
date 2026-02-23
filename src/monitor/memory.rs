/// Path: PanicMode/scr/monitor/memory.rs
use anyhow::Result;
use super::MemoryMetrics;
use std::fs;

#[derive(Clone)]
pub struct MemoryMonitor {
    // No state needed for memory — always read current values
}

impl MemoryMonitor {
    pub fn new() -> Result<Self> {
        Ok(Self {})
    }
    
    pub fn collect(&mut self) -> Result<MemoryMetrics> {
        // Use sysinfo for cross-platform compatibility and reliability
        use sysinfo::System; // SystemExt was removed in sysinfo 0.30; methods are now directly on System
        
        let mut sys = System::new_all();
        sys.refresh_memory();
        
        // RAM metrics
        let total_mb = sys.total_memory() / 1024;
        let used_mb = sys.used_memory() / 1024;
        let available_mb = sys.available_memory() / 1024;
        
        let usage_percent = if total_mb > 0 {
            (used_mb as f64 / total_mb as f64 * 100.0) as f32
        } else {
            0.0
        };
        
        // Swap metrics
        let swap_total_mb = sys.total_swap() / 1024;
        let swap_used_mb = sys.used_swap() / 1024;
        
        let swap_percent = if swap_total_mb > 0 {
            (swap_used_mb as f64 / swap_total_mb as f64 * 100.0) as f32
        } else {
            0.0
        };
        
        Ok(MemoryMetrics {
            total_mb,
            used_mb,
            available_mb,
            usage_percent,
            swap_total_mb,
            swap_used_mb,
            swap_percent,
        })
    }
}

// ============================================================================
// Alternative: Direct /proc/meminfo parsing (Linux-specific, but more detailed)
// ============================================================================

#[allow(dead_code)]
fn collect_from_proc_meminfo() -> Result<MemoryMetrics> {
    let content = fs::read_to_string("/proc/meminfo")?;
    
    let mut mem_total = 0u64;
    let mut mem_free = 0u64;
    let mut mem_available = 0u64;
    let mut buffers = 0u64;
    let mut cached = 0u64;
    let mut swap_total = 0u64;
    let mut swap_free = 0u64;
    
    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        
        let key = parts[0].trim_end_matches(':');
        let value = parts[1].parse::<u64>().unwrap_or(0);
        
        match key {
            "MemTotal" => mem_total = value,
            "MemFree" => mem_free = value,
            "MemAvailable" => mem_available = value,
            "Buffers" => buffers = value,
            "Cached" => cached = value,
            "SwapTotal" => swap_total = value,
            "SwapFree" => swap_free = value,
            _ => {}
        }
    }
    
    // Convert KB to MB
    let total_mb = mem_total / 1024;
    let available_mb = mem_available / 1024;
    
    // Used = Total - Free - Buffers - Cached (more precise calculation)
    let used_kb = mem_total.saturating_sub(mem_free).saturating_sub(buffers).saturating_sub(cached);
    let used_mb = used_kb / 1024;
    
    let usage_percent = if total_mb > 0 {
        (used_mb as f64 / total_mb as f64 * 100.0) as f32
    } else {
        0.0
    };
    
    // Swap
    let swap_total_mb = swap_total / 1024;
    let swap_used_kb = swap_total.saturating_sub(swap_free);
    let swap_used_mb = swap_used_kb / 1024;
    
    let swap_percent = if swap_total_mb > 0 {
        (swap_used_mb as f64 / swap_total_mb as f64 * 100.0) as f32
    } else {
        0.0
    };
    
    Ok(MemoryMetrics {
        total_mb,
        used_mb,
        available_mb,
        usage_percent,
        swap_total_mb,
        swap_used_mb,
        swap_percent,
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_monitor() {
        let mut monitor = MemoryMonitor::new().unwrap();
        let metrics = monitor.collect().unwrap();
        
        // Basic checks
        assert!(metrics.total_mb > 0, "Total memory should be > 0");
        assert!(metrics.usage_percent >= 0.0);
        assert!(metrics.usage_percent <= 100.0);

        // Used + available should be approximately equal to total
        // (may differ slightly due to buffers/cache)
        let sum = metrics.used_mb + metrics.available_mb;
        let diff_percent = ((sum as f64 - metrics.total_mb as f64).abs() / metrics.total_mb as f64) * 100.0;
        assert!(diff_percent < 50.0, "Used + available should be close to total");
        
        // Swap may be 0 (if not configured)
        assert!(metrics.swap_percent >= 0.0);
        assert!(metrics.swap_percent <= 100.0);
    }
    
    #[test]
    fn test_proc_meminfo_parsing() {
        // Test the alternative method (Linux only)
        if cfg!(target_os = "linux") {
            let result = collect_from_proc_meminfo();
            assert!(result.is_ok(), "Should parse /proc/meminfo successfully");
            
            let metrics = result.unwrap();
            assert!(metrics.total_mb > 0);
            assert!(metrics.usage_percent >= 0.0);
            assert!(metrics.usage_percent <= 100.0);
        }
    }
    
    #[test]
    fn test_memory_consistency() {
        let mut monitor = MemoryMonitor::new().unwrap();
        
        // Collect metrics twice
        let metrics1 = monitor.collect().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        let metrics2 = monitor.collect().unwrap();
        
        // Total memory should not change
        assert_eq!(metrics1.total_mb, metrics2.total_mb);
        
        // Usage may change slightly, but not drastically
        let usage_diff = (metrics2.usage_percent - metrics1.usage_percent).abs();
        assert!(usage_diff < 50.0, "Memory usage shouldn't change drastically");
    }
    
    #[test]
    fn test_swap_metrics() {
        let mut monitor = MemoryMonitor::new().unwrap();
        let metrics = monitor.collect().unwrap();
        
        // If swap is present
        if metrics.swap_total_mb > 0 {
            // Used cannot exceed total
            assert!(metrics.swap_used_mb <= metrics.swap_total_mb);

            // Percent must match used/total
            let expected_percent = (metrics.swap_used_mb as f64 / metrics.swap_total_mb as f64 * 100.0) as f32;
            let diff = (metrics.swap_percent - expected_percent).abs();
            assert!(diff < 1.0, "Swap percent calculation should be accurate");
        } else {
            // If no swap, everything should be 0
            assert_eq!(metrics.swap_used_mb, 0);
            assert_eq!(metrics.swap_percent, 0.0);
        }
    }
}