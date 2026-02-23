/// Path: PanicMode/scr/monitor/custom_metrics.rs
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Instant, Duration};
use tokio::sync::RwLock;
use tokio::process::Command;
use tokio::time::timeout;

/// Custom metrics executor — runs scripts to collect metric values
pub struct CustomMetricsExecutor {
    // Metric name -> cached result
    cache: Arc<RwLock<HashMap<String, CachedMetric>>>,
}

#[derive(Debug, Clone)]
struct CachedMetric {
    value: f64,
    cached_at: Instant,
    ttl: Duration,
}

impl CustomMetricsExecutor {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Execute custom metric script
    pub async fn execute_metric(
        &self,
        name: &str,
        command: &str,
        timeout_duration: Duration,
        cache_ttl: Option<Duration>,
        output_format: &str,
    ) -> Result<f64> {
        // Check cache
        if let Some(ttl) = cache_ttl {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.get(name) {
                if Instant::now().duration_since(cached.cached_at) < cached.ttl {
                    tracing::debug!("Using cached value for metric '{}'", name);
                    return Ok(cached.value);
                }
            }
        }
        
        // Execute command
        let value = self.execute_command(command, timeout_duration, output_format).await?;
        
        // Update cache
        if let Some(ttl) = cache_ttl {
            let mut cache = self.cache.write().await;
            cache.insert(name.to_string(), CachedMetric {
                value,
                cached_at: Instant::now(),
                ttl,
            });
        }
        
        Ok(value)
    }
    
    async fn execute_command(
        &self,
        command: &str,
        timeout_duration: Duration,
        output_format: &str,
    ) -> Result<f64> {
        if command.trim().is_empty() {
            anyhow::bail!("Empty command");
        }

        // Run via shell so that pipes (|), redirections, and builtins work correctly.
        // E.g.: "redis-cli INFO memory | grep used_memory: | awk -F: '{print $2}'"
        let output = timeout(
            timeout_duration,
            Command::new("/bin/sh").args(["-c", command]).output()
        ).await??;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Command failed: {}", stderr);
        }
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        
        // Parse output based on format
        let value = match output_format {
            "number" => {
                // Parse as number (strip whitespace)
                stdout.trim().parse::<f64>()
                    .map_err(|e| anyhow::anyhow!("Failed to parse output as number: {}", e))?
            }
            "json" => {
                // Parse JSON and extract "value" field
                let json: serde_json::Value = serde_json::from_str(stdout.trim())?;
                json.get("value")
                    .and_then(|v| v.as_f64())
                    .ok_or_else(|| anyhow::anyhow!("JSON missing 'value' field"))?
            }
            "text" => {
                // Count lines or chars (configurable)
                stdout.lines().count() as f64
            }
            _ => {
                anyhow::bail!("Unknown output format: {}", output_format)
            }
        };
        
        Ok(value)
    }
    
    /// Clear cache
    pub async fn clear_cache(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_execute_simple_command() {
        let executor = CustomMetricsExecutor::new();
        
        // Simple echo command
        let result = executor.execute_command(
            "echo 42",
            Duration::from_secs(5),
            "number"
        ).await;
        
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42.0);
    }

    #[tokio::test]
    async fn test_cache() {
        let executor = CustomMetricsExecutor::new();
        
        // Execute with cache
        let result1 = executor.execute_metric(
            "test",
            "echo 100",
            Duration::from_secs(5),
            Some(Duration::from_secs(60)),
            "number"
        ).await.unwrap();
        
        // Second call should use cache
        let result2 = executor.execute_metric(
            "test",
            "echo 999", // Different command but should use cache
            Duration::from_secs(5),
            Some(Duration::from_secs(60)),
            "number"
        ).await.unwrap();
        
        assert_eq!(result1, result2);
    }
}