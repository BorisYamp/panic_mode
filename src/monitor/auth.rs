/// Path: PanicMode/scr/monitor/auth.rs
use anyhow::Result;
use super::{AuthMetrics, AuthFailureInfo};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::time::SystemTime;
use regex::Regex;
use chrono::{DateTime, Datelike, Local, NaiveDateTime, TimeZone};

#[derive(Clone)]
pub struct AuthMonitor {
    // File position for incremental reading
    last_position: u64,

    // Path to the auth log
    auth_log_path: String,

    // Regex for parsing SSH failures (enhanced)
    ssh_failure_regex: Regex,
    ssh_success_regex: Regex,

    // Regex for parsing timestamps
    timestamp_regex: Regex,
}

impl AuthMonitor {
    pub fn new() -> Result<Self> {
        // Detect the auth log path based on the OS distribution
        let auth_log_path = if std::path::Path::new("/var/log/auth.log").exists() {
            "/var/log/auth.log".to_string() // Debian/Ubuntu
        } else if std::path::Path::new("/var/log/secure").exists() {
            "/var/log/secure".to_string() // RHEL/CentOS
        } else {
            "/var/log/auth.log".to_string() // Fallback
        };
        
        Ok(Self {
            last_position: 0,
            auth_log_path,
            // Enhanced regexes with named capture groups
            ssh_failure_regex: Regex::new(
                r"Failed (?:password|publickey|none) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d\.:a-fA-F]+) port (?P<port>\d+)"
            )?,
            ssh_success_regex: Regex::new(
                r"Accepted (?:password|publickey|keyboard-interactive/pam) for (?P<user>\S+) from (?P<ip>[\d\.:a-fA-F]+) port (?P<port>\d+)"
            )?,
            // Regex for parsing syslog timestamp: "Jan 15 10:30:00" or "2024-01-15T10:30:00"
            timestamp_regex: Regex::new(
                r"^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})"
            )?,
        })
    }
    
    pub fn collect(&mut self) -> Result<AuthMetrics> {
        // Open the log file
        let mut file = match File::open(&self.auth_log_path) {
            Ok(f) => f,
            Err(_) => {
                // If the log file is unavailable, return empty metrics
                return Ok(AuthMetrics {
                    failed_attempts: 0,
                    failures_by_ip: vec![],
                    successful_logins: 0,
                });
            }
        };
        
        // Get the file size
        let metadata = file.metadata()?;
        let file_size = metadata.len();

        // If the file was rotated (size decreased), start from the beginning
        if file_size < self.last_position {
            self.last_position = 0;
        }
        
        // Seek to the last known position
        file.seek(SeekFrom::Start(self.last_position))?;

        // Read new lines
        let reader = BufReader::new(file);
        let mut failures: HashMap<String, FailureInfo> = HashMap::new();
        let mut total_failures = 0u64;
        let mut successful_logins = 0u64;
        
        for line_result in reader.lines() {
            let line = line_result?;
            
            // Parse the timestamp from the line
            let timestamp = self.parse_timestamp(&line).unwrap_or_else(SystemTime::now);

            // Parse SSH failures
            if let Some(caps) = self.ssh_failure_regex.captures(&line) {
                let username = caps.name("user")
                    .map_or("unknown", |m| m.as_str())
                    .to_string();
                let ip = caps.name("ip")
                    .map_or("unknown", |m| m.as_str())
                    .to_string();
                
                total_failures += 1;
                
                let key = format!("{}@{}", username, ip);
                failures.entry(key.clone())
                    .and_modify(|info| {
                        info.count += 1;
                        info.last_attempt = timestamp;
                    })
                    .or_insert(FailureInfo {
                        ip: ip.clone(),
                        username: username.clone(),
                        count: 1,
                        last_attempt: timestamp,
                    });
            }
            
            // Parse successful logins
            if self.ssh_success_regex.is_match(&line) {
                successful_logins += 1;
            }
        }
        
        // Update the read position
        self.last_position = file_size;

        // Build the failures-by-IP list
        let mut failures_by_ip: Vec<AuthFailureInfo> = failures
            .into_iter()
            .map(|(_, info)| AuthFailureInfo {
                ip: info.ip,
                username: info.username,
                attempt_count: info.count,
                last_attempt: info.last_attempt,
            })
            .collect();
        
        // Sort by attempt count (highest first)
        failures_by_ip.sort_by(|a, b| b.attempt_count.cmp(&a.attempt_count));

        // Limit to top 20
        failures_by_ip.truncate(20);
        
        Ok(AuthMetrics {
            failed_attempts: total_failures,
            failures_by_ip,
            successful_logins,
        })
    }
    
    /// Parses a timestamp from a syslog line
    /// Format: "Jan 15 10:30:00 hostname sshd[1234]: ..."
    fn parse_timestamp(&self, line: &str) -> Option<SystemTime> {
        let caps = self.timestamp_regex.captures(line)?;
        
        let month_str = caps.name("month")?.as_str();
        let day_str = caps.name("day")?.as_str();
        let time_str = caps.name("time")?.as_str();
        
        // Convert month name to number
        let month = match month_str {
            "Jan" => 1, "Feb" => 2, "Mar" => 3, "Apr" => 4,
            "May" => 5, "Jun" => 6, "Jul" => 7, "Aug" => 8,
            "Sep" => 9, "Oct" => 10, "Nov" => 11, "Dec" => 12,
            _ => return None,
        };
        
        let day: u32 = day_str.trim().parse().ok()?;
        
        // Parse the time
        let time_parts: Vec<&str> = time_str.split(':').collect();
        if time_parts.len() != 3 {
            return None;
        }
        
        let hour: u32 = time_parts[0].parse().ok()?;
        let minute: u32 = time_parts[1].parse().ok()?;
        let second: u32 = time_parts[2].parse().ok()?;
        
        // Determine the current year (syslog does not include the year).
        // Compare the full date (day + month), not just the month:
        // if the entry is dated after today, it belongs to the previous year.
        let now = Local::now();
        let mut year = now.year();
        if let Some(candidate) = chrono::NaiveDate::from_ymd_opt(year, month, day) {
            if candidate > now.naive_local().date() {
                year -= 1;
            }
        }

        // Build the datetime
        let naive_dt = NaiveDateTime::parse_from_str(
            &format!("{}-{:02}-{:02} {}:{}:{}", year, month, day, hour, minute, second),
            "%Y-%m-%d %H:%M:%S"
        ).ok()?;
        
        let dt: DateTime<Local> = Local.from_local_datetime(&naive_dt).single()?;
        
        Some(SystemTime::from(dt))
    }
}

struct FailureInfo {
    ip: String,
    username: String,
    count: u64,
    last_attempt: SystemTime,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_auth_monitor_basic() {
        let mut monitor = AuthMonitor::new().unwrap();
        let result = monitor.collect();
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_ssh_failure_regex_variants() {
        let monitor = AuthMonitor::new().unwrap();
        
        // Various SSH failure log formats
        let test_cases = vec![
            // Standard password failure
            ("Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2", 
             Some(("admin", "192.168.1.100", "54321"))),
            
            // Root user failure
            ("Failed password for root from 10.0.0.5 port 12345 ssh2", 
             Some(("root", "10.0.0.5", "12345"))),
            
            // IPv6 address
            ("Failed password for testuser from 2001:db8::1 port 22 ssh2", 
             Some(("testuser", "2001:db8::1", "22"))),
            
            // Public key failure
            ("Failed publickey for user from 1.2.3.4 port 5555 ssh2", 
             Some(("user", "1.2.3.4", "5555"))),
            
            // No auth method failure
            ("Failed none for invalid user test from 8.8.8.8 port 9999 ssh2", 
             Some(("test", "8.8.8.8", "9999"))),
        ];
        
        for (line, expected) in test_cases {
            let caps = monitor.ssh_failure_regex.captures(line);
            match expected {
                Some((user, ip, port)) => {
                    assert!(caps.is_some(), "Should match: {}", line);
                    let caps = caps.unwrap();
                    assert_eq!(caps.name("user").unwrap().as_str(), user);
                    assert_eq!(caps.name("ip").unwrap().as_str(), ip);
                    assert_eq!(caps.name("port").unwrap().as_str(), port);
                }
                None => {
                    assert!(caps.is_none(), "Should not match: {}", line);
                }
            }
        }
    }
    
    #[test]
    fn test_ssh_success_regex_variants() {
        let monitor = AuthMonitor::new().unwrap();
        
        let test_cases = vec![
            // Password auth
            ("Accepted password for user from 192.168.1.100 port 54321 ssh2", 
             Some(("user", "192.168.1.100", "54321"))),
            
            // Public key auth
            ("Accepted publickey for root from 10.0.0.5 port 12345 ssh2 RSA SHA256:abc123", 
             Some(("root", "10.0.0.5", "12345"))),
            
            // Keyboard-interactive
            ("Accepted keyboard-interactive/pam for admin from 1.2.3.4 port 5678 ssh2", 
             Some(("admin", "1.2.3.4", "5678"))),
        ];
        
        for (line, expected) in test_cases {
            let caps = monitor.ssh_success_regex.captures(line);
            match expected {
                Some((user, ip, port)) => {
                    assert!(caps.is_some(), "Should match: {}", line);
                    let caps = caps.unwrap();
                    assert_eq!(caps.name("user").unwrap().as_str(), user);
                    assert_eq!(caps.name("ip").unwrap().as_str(), ip);
                    assert_eq!(caps.name("port").unwrap().as_str(), port);
                }
                None => {
                    assert!(caps.is_none(), "Should not match: {}", line);
                }
            }
        }
    }
    
    #[test]
    fn test_timestamp_parsing() {
        let monitor = AuthMonitor::new().unwrap();
        
        let test_cases = vec![
            "Jan 15 10:30:00 server sshd[1234]: message",
            "Feb  5 08:15:42 hostname sshd[5678]: message",
            "Dec 31 23:59:59 host sshd[9999]: message",
        ];
        
        for line in test_cases {
            let result = monitor.parse_timestamp(line);
            assert!(result.is_some(), "Should parse timestamp from: {}", line);
        }
    }
    
    #[test]
    fn test_timestamp_accuracy() {
        let monitor = AuthMonitor::new().unwrap();
        
        // Verify that the parsed timestamp roughly matches the expected value
        let line = "Jan 15 10:30:00 server sshd[1234]: message";
        let parsed = monitor.parse_timestamp(line).unwrap();
        
        // Verify the timestamp is not in the future
        let now = SystemTime::now();
        assert!(parsed <= now, "Parsed timestamp should not be in the future");

        // Verify the timestamp is not too old (within the past year)
        let year_ago = now - std::time::Duration::from_secs(365 * 24 * 60 * 60);
        assert!(parsed >= year_ago, "Parsed timestamp should not be more than a year old");
    }
    
    #[test]
    fn test_parse_mock_log_with_timestamps() {
        let mut temp_file = NamedTempFile::new().unwrap();
        
        // Realistic log lines with timestamps
        writeln!(temp_file, "Jan 15 10:30:00 server sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2").unwrap();
        writeln!(temp_file, "Jan 15 10:30:05 server sshd[1235]: Failed password for root from 192.168.1.100 port 54322 ssh2").unwrap();
        writeln!(temp_file, "Jan 15 10:30:10 server sshd[1236]: Accepted password for user from 192.168.1.200 port 54323 ssh2").unwrap();
        writeln!(temp_file, "Jan 15 10:30:15 server sshd[1237]: Failed password for admin from 10.0.0.5 port 12345 ssh2").unwrap();
        writeln!(temp_file, "Jan 15 10:30:20 server sshd[1238]: Failed publickey for testuser from 1.2.3.4 port 9999 ssh2").unwrap();
        
        temp_file.flush().unwrap();
        
        let mut monitor = AuthMonitor::new().unwrap();
        monitor.auth_log_path = temp_file.path().to_string_lossy().to_string();
        
        let metrics = monitor.collect().unwrap();
        
        assert_eq!(metrics.failed_attempts, 4, "Should detect 4 failures");
        assert_eq!(metrics.successful_logins, 1, "Should detect 1 success");
        
        // Verify that timestamps were parsed
        assert!(!metrics.failures_by_ip.is_empty());

        // Top attacker should be 192.168.1.100 with 2 attempts
        let top = &metrics.failures_by_ip[0];
        assert_eq!(top.ip, "192.168.1.100");
        assert_eq!(top.attempt_count, 2);
    }
    
    #[test]
    fn test_incremental_reading() {
        let mut temp_file = NamedTempFile::new().unwrap();
        
        writeln!(temp_file, "Jan 15 10:30:00 server sshd[1234]: Failed password for user1 from 1.1.1.1 port 1234 ssh2").unwrap();
        temp_file.flush().unwrap();
        
        let mut monitor = AuthMonitor::new().unwrap();
        monitor.auth_log_path = temp_file.path().to_string_lossy().to_string();
        
        let metrics1 = monitor.collect().unwrap();
        assert_eq!(metrics1.failed_attempts, 1);
        
        writeln!(temp_file, "Jan 15 10:31:00 server sshd[1235]: Failed password for user2 from 2.2.2.2 port 5678 ssh2").unwrap();
        temp_file.flush().unwrap();
        
        let metrics2 = monitor.collect().unwrap();
        assert_eq!(metrics2.failed_attempts, 1, "Should only count new failures");
        
        let metrics3 = monitor.collect().unwrap();
        assert_eq!(metrics3.failed_attempts, 0, "Should be 0 when no new data");
    }
    
    #[test]
    fn test_log_rotation_handling() {
        let mut temp_file = NamedTempFile::new().unwrap();
        
        writeln!(temp_file, "Jan 15 10:30:00 server sshd[1234]: Failed password for user1 from 1.1.1.1 port 1234 ssh2").unwrap();
        temp_file.flush().unwrap();
        
        let mut monitor = AuthMonitor::new().unwrap();
        monitor.auth_log_path = temp_file.path().to_string_lossy().to_string();
        
        let _ = monitor.collect().unwrap();
        let old_position = monitor.last_position;
        
        drop(temp_file);
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "Jan 15 10:35:00 server sshd[5678]: Failed password for user2 from 2.2.2.2 port 5678 ssh2").unwrap();
        temp_file.flush().unwrap();
        
        monitor.auth_log_path = temp_file.path().to_string_lossy().to_string();
        
        let metrics = monitor.collect().unwrap();
        assert_eq!(metrics.failed_attempts, 1);
        assert!(monitor.last_position < old_position || monitor.last_position == 0, 
                "Should reset position after rotation");
    }
    
    #[test]
    fn test_ipv6_address_parsing() {
        let monitor = AuthMonitor::new().unwrap();
        
        let line = "Jan 15 10:30:00 server sshd[1234]: Failed password for user from 2001:db8::1 port 22 ssh2";
        let caps = monitor.ssh_failure_regex.captures(line).unwrap();
        
        assert_eq!(caps.name("ip").unwrap().as_str(), "2001:db8::1");
    }
    
    #[test]
    fn test_multiple_failures_from_same_ip() {
        let mut temp_file = NamedTempFile::new().unwrap();
        
        // 5 attempts from the same IP
        for i in 0..5 {
            writeln!(temp_file, 
                "Jan 15 10:30:{:02} server sshd[{}]: Failed password for root from 192.168.1.100 port {} ssh2",
                i * 10, 1234 + i, 50000 + i
            ).unwrap();
        }
        
        temp_file.flush().unwrap();
        
        let mut monitor = AuthMonitor::new().unwrap();
        monitor.auth_log_path = temp_file.path().to_string_lossy().to_string();
        
        let metrics = monitor.collect().unwrap();
        
        assert_eq!(metrics.failed_attempts, 5);
        assert_eq!(metrics.failures_by_ip.len(), 1);
        assert_eq!(metrics.failures_by_ip[0].attempt_count, 5);
        assert_eq!(metrics.failures_by_ip[0].ip, "192.168.1.100");
    }
}