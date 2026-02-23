use anyhow::Result;
use notify::{Watcher, RecursiveMode, Event, EventKind};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Instant, Duration};
use tokio::sync::RwLock;

/// File watcher for monitoring changes in files and directories
pub struct FileWatcher {
    // Path -> event count within the aggregation window
    event_counts: Arc<RwLock<HashMap<String, PathEvents>>>,
    
    // notify watcher
    _watcher: Box<dyn Watcher>,
    
    // Configuration
    max_events_per_path: usize,
    aggregation_window: Duration,
}

#[derive(Debug, Clone)]
struct PathEvents {
    events: Vec<Instant>,
    last_cleanup: Instant,
}

impl FileWatcher {
    pub fn new(max_events_per_path: usize, aggregation_window: Duration) -> Result<Self> {
        let event_counts = Arc::new(RwLock::new(HashMap::new()));
        let event_counts_clone = event_counts.clone();
        
        // Create notify watcher
        let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
            match res {
                Ok(event) => {
                    // Handle file event
                    if let Some(path) = event.paths.first() {
                        let path_str = path.to_string_lossy().to_string();
                        
                        // Spawn async task to update counts
                        let event_counts = event_counts_clone.clone();
                        tokio::spawn(async move {
                            let mut counts = event_counts.write().await;
                            counts.entry(path_str.clone())
                                .and_modify(|pe| pe.events.push(Instant::now()))
                                .or_insert(PathEvents {
                                    events: vec![Instant::now()],
                                    last_cleanup: Instant::now(),
                                });
                            
                            tracing::debug!("File event: {} on {}", 
                                Self::event_kind_name(&event.kind), path_str);
                        });
                    }
                }
                Err(e) => {
                    tracing::error!("File watcher error: {}", e);
                }
            }
        })?;
        
        Ok(Self {
            event_counts,
            _watcher: Box::new(watcher),
            max_events_per_path,
            aggregation_window,
        })
    }
    
    /// Start watching a path
    pub fn watch_path(&mut self, path: &str) -> Result<()> {
        use std::path::Path;
        
        let path_obj = Path::new(path);
        self._watcher.watch(path_obj, RecursiveMode::Recursive)?;
        
        tracing::info!("Started watching: {}", path);
        Ok(())
    }
    
    /// Stop watching a path
    pub fn unwatch_path(&mut self, path: &str) -> Result<()> {
        use std::path::Path;
        
        let path_obj = Path::new(path);
        self._watcher.unwatch(path_obj)?;
        
        tracing::info!("Stopped watching: {}", path);
        Ok(())
    }
    
    /// Get event count for paths
    pub async fn get_event_count(&self, paths: &[String]) -> u64 {
        let mut counts = self.event_counts.write().await;
        let now = Instant::now();
        let mut total = 0u64;
        
        for path in paths {
            if let Some(path_events) = counts.get_mut(path) {
                // Cleanup old events
                if now.duration_since(path_events.last_cleanup) > Duration::from_secs(60) {
                    path_events.events.retain(|&event_time| {
                        now.duration_since(event_time) < self.aggregation_window
                    });
                    path_events.last_cleanup = now;
                }
                
                // Count recent events
                let recent_count = path_events.events.iter()
                    .filter(|&&event_time| now.duration_since(event_time) < self.aggregation_window)
                    .count();
                
                total += recent_count as u64;
                
                // Limit events stored
                if path_events.events.len() > self.max_events_per_path {
                    path_events.events.drain(0..path_events.events.len() - self.max_events_per_path);
                }
            }
        }
        
        total
    }
    
    fn event_kind_name(kind: &EventKind) -> &'static str {
        match kind {
            EventKind::Create(_) => "create",
            EventKind::Modify(_) => "modify",
            EventKind::Remove(_) => "remove",
            EventKind::Access(_) => "access",
            _ => "other",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_file_watcher() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.txt");
        
        let mut watcher = FileWatcher::new(1000, Duration::from_secs(60)).unwrap();
        watcher.watch_path(temp_dir.path().to_str().unwrap()).unwrap();
        
        // Create file
        fs::write(&test_file, "test").unwrap();
        
        // Wait for event
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        // Check count
        let count = watcher.get_event_count(&[temp_dir.path().to_string_lossy().to_string()]).await;
        assert!(count > 0);
    }
}