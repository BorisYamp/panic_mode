/// Path: PanicMode/scr/monitor/disk_io.rs
///
/// Disk I/O utilization monitor via /proc/diskstats.
///
/// Algorithm: two-sample delta.
/// - First call: stores baseline, returns 0.0% for all devices.
/// - Subsequent calls: computes (delta_io_time_ms / delta_wall_ms) * 100.
/// - Clamps to [0.0, 100.0].
/// - Filters loop/ram/zram/dm devices to reduce noise.
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

// ============================================================================
// Output types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskIoMetrics {
    /// Per-device metrics (real block devices only).
    pub devices: Vec<DiskIoDevice>,
    /// Maximum utilization % across all tracked devices (0..=100).
    pub max_util_percent: f32,
}

impl Default for DiskIoMetrics {
    fn default() -> Self {
        Self {
            devices: Vec::new(),
            max_util_percent: 0.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskIoDevice {
    pub name: String,
    /// I/O utilization in percent [0..=100].
    pub util_percent: f32,
    pub reads_per_sec: f64,
    pub writes_per_sec: f64,
}

// ============================================================================
// Internal sampling state (per device)
// ============================================================================

#[derive(Clone)]
struct DeviceSample {
    /// time_doing_io_ms (field 13 in /proc/diskstats, 0-indexed from name col)
    time_io_ms: u64,
    reads_completed: u64,
    writes_completed: u64,
    sampled_at: Instant,
}

// ============================================================================
// DiskIoMonitor
// ============================================================================

pub struct DiskIoMonitor {
    prev: Mutex<HashMap<String, DeviceSample>>,
}

impl DiskIoMonitor {
    pub fn new() -> Result<Self> {
        Ok(Self {
            prev: Mutex::new(HashMap::new()),
        })
    }

    /// Collect current disk I/O metrics.
    ///
    /// Blocking — call via `spawn_blocking`.
    pub fn collect(&self) -> Result<DiskIoMetrics> {
        let now = Instant::now();
        let raw = parse_diskstats().context("Failed to parse /proc/diskstats")?;

        let mut prev_map = self.prev.lock().unwrap_or_else(|e| e.into_inner());

        let mut devices = Vec::new();

        for entry in &raw {
            if should_skip(&entry.name) {
                continue;
            }

            let util_percent;
            let reads_per_sec;
            let writes_per_sec;

            if let Some(prev) = prev_map.get(&entry.name) {
                let elapsed_ms = now
                    .checked_duration_since(prev.sampled_at)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(1)
                    .max(1); // prevent division by zero

                let delta_io_ms = entry.time_io_ms.saturating_sub(prev.time_io_ms);
                let delta_reads = entry.reads_completed.saturating_sub(prev.reads_completed);
                let delta_writes = entry.writes_completed.saturating_sub(prev.writes_completed);

                let elapsed_secs = elapsed_ms as f64 / 1000.0;

                util_percent = ((delta_io_ms as f64 / elapsed_ms as f64) * 100.0)
                    .clamp(0.0, 100.0) as f32;
                reads_per_sec = delta_reads as f64 / elapsed_secs;
                writes_per_sec = delta_writes as f64 / elapsed_secs;
            } else {
                // First sample — no delta yet, report 0
                util_percent = 0.0;
                reads_per_sec = 0.0;
                writes_per_sec = 0.0;
            }

            // Update baseline
            prev_map.insert(
                entry.name.clone(),
                DeviceSample {
                    time_io_ms: entry.time_io_ms,
                    reads_completed: entry.reads_completed,
                    writes_completed: entry.writes_completed,
                    sampled_at: now,
                },
            );

            devices.push(DiskIoDevice {
                name: entry.name.clone(),
                util_percent,
                reads_per_sec,
                writes_per_sec,
            });
        }

        // Sort by util descending so max is first
        devices.sort_by(|a, b| {
            b.util_percent
                .partial_cmp(&a.util_percent)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let max_util_percent = devices
            .first()
            .map(|d| d.util_percent)
            .unwrap_or(0.0);

        Ok(DiskIoMetrics {
            devices,
            max_util_percent,
        })
    }
}

impl Clone for DiskIoMonitor {
    fn clone(&self) -> Self {
        let prev_copy = self
            .prev
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        Self {
            prev: Mutex::new(prev_copy),
        }
    }
}

// ============================================================================
// /proc/diskstats parser
// ============================================================================

struct DiskstatsEntry {
    name: String,
    reads_completed: u64,
    writes_completed: u64,
    /// Field 13 (0-indexed from name): time spent doing I/Os (ms)
    time_io_ms: u64,
}

/// Returns empty Vec on non-Linux (no /proc/diskstats).
fn parse_diskstats() -> Result<Vec<DiskstatsEntry>> {
    #[cfg(not(target_os = "linux"))]
    {
        return Ok(Vec::new());
    }

    #[cfg(target_os = "linux")]
    {
        let content = std::fs::read_to_string("/proc/diskstats")
            .context("/proc/diskstats not found")?;

        let mut entries = Vec::new();

        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            // /proc/diskstats layout (1-indexed):
            // 1:major 2:minor 3:name 4:reads_completed 5:reads_merged
            // 6:sectors_read 7:time_read_ms 8:writes_completed 9:writes_merged
            // 10:sectors_written 11:time_write_ms 12:io_in_progress
            // 13:time_doing_io_ms 14:weighted_time_io_ms
            // Minimum 14 fields required.
            if parts.len() < 14 {
                continue;
            }

            let name = parts[2].to_string();
            let reads_completed: u64 = parts[3].parse().unwrap_or(0);
            let writes_completed: u64 = parts[7].parse().unwrap_or(0);
            let time_io_ms: u64 = parts[12].parse().unwrap_or(0);

            entries.push(DiskstatsEntry {
                name,
                reads_completed,
                writes_completed,
                time_io_ms,
            });
        }

        Ok(entries)
    }
}

/// Returns true for devices that should be excluded from monitoring.
fn should_skip(name: &str) -> bool {
    // Partitions (sda1, nvme0n1p1, etc.) — we only want the whole disk
    let is_partition = name.chars().last().map(|c| c.is_ascii_digit()).unwrap_or(false)
        && (name.starts_with("sd")
            || name.starts_with("hd")
            || name.starts_with("vd")
            || name.starts_with("nvme"));

    name.starts_with("loop")
        || name.starts_with("ram")
        || name.starts_with("zram")
        || name.starts_with("dm-")
        || is_partition
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_skip_loop() {
        assert!(should_skip("loop0"));
        assert!(should_skip("loop7"));
    }

    #[test]
    fn test_should_skip_ram() {
        assert!(should_skip("ram0"));
        assert!(should_skip("ram15"));
    }

    #[test]
    fn test_should_skip_zram() {
        assert!(should_skip("zram0"));
    }

    #[test]
    fn test_should_skip_dm() {
        assert!(should_skip("dm-0"));
        assert!(should_skip("dm-1"));
    }

    #[test]
    fn test_should_skip_partition() {
        assert!(should_skip("sda1"));
        assert!(should_skip("sda2"));
        assert!(should_skip("nvme0n1p1"));
    }

    #[test]
    fn test_should_not_skip_whole_disk() {
        assert!(!should_skip("sda"));
        assert!(!should_skip("sdb"));
        assert!(!should_skip("nvme0n1"));
        assert!(!should_skip("vda"));
    }

    #[test]
    fn test_collect_returns_default_first_call() {
        let monitor = DiskIoMonitor::new().unwrap();
        // First call: all util = 0.0 (no prev sample)
        let result = monitor.collect().unwrap();
        for device in &result.devices {
            assert_eq!(device.util_percent, 0.0);
        }
        assert_eq!(result.max_util_percent, 0.0);
    }

    #[test]
    fn test_default_metrics() {
        let metrics = DiskIoMetrics::default();
        assert_eq!(metrics.max_util_percent, 0.0);
        assert!(metrics.devices.is_empty());
    }
}
