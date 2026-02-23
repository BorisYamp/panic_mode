/// Path: PanicMode/scr/storage.rs
///
/// SQLite-backed incident log.
///
/// Every incident that fires (passes deduplication) is written to the DB so
/// that post-mortem analysis doesn't depend on in-process memory or log files.
///
/// Design decisions:
/// - Single `Arc<Mutex<Connection>>` so both file and in-memory paths work.
/// - `spawn_blocking` for every write — SQLite is not async-native.
/// - Directory is created automatically on first open.
/// - Non-fatal: if the DB can't be opened, the caller gets an Err and can
///   fall back to in-memory (no incidents are logged, but monitoring still works).
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};

use crate::detector::{Incident, IncidentSeverity};

// ============================================================================
// Public interface
// ============================================================================

/// Запись о заблокированном IP из таблицы blocked_ips.
#[derive(Debug, Clone)]
pub struct BlockedIp {
    pub ip: String,
    pub blocked_at: i64,
    pub reason: String,
}

pub struct IncidentStorage {
    conn: Arc<Mutex<rusqlite::Connection>>,
}

impl IncidentStorage {
    /// Open (or create) a file-based SQLite DB at `db_path`.
    /// Creates parent directories as needed.
    pub fn new(db_path: &str) -> Result<Self> {
        // Ensure the directory exists before trying to open the file.
        if let Some(parent) = std::path::Path::new(db_path).parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Cannot create directory for incident DB: {}", parent.display()))?;
        }

        let conn = rusqlite::Connection::open(db_path)
            .with_context(|| format!("Cannot open incident DB: {}", db_path))?;

        let storage = Self {
            conn: Arc::new(Mutex::new(conn)),
        };

        storage.init_schema()?;

        Ok(storage)
    }

    /// In-memory database — used in tests.
    pub fn new_in_memory() -> Result<Self> {
        let conn = rusqlite::Connection::open_in_memory()
            .context("Cannot open in-memory incident DB")?;

        let storage = Self {
            conn: Arc::new(Mutex::new(conn)),
        };

        storage.init_schema()?;

        Ok(storage)
    }

    /// Записать заблокированный IP в БД.
    /// Если IP уже есть в списке — ничего не делаем (он уже заблокирован).
    pub async fn add_blocked_ip(&self, ip: &str, reason: &str) -> Result<()> {
        let conn = self.conn.clone();
        let ip = ip.to_string();
        let reason = reason.to_string();
        let blocked_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap_or_else(|e| e.into_inner());
            conn.execute(
                "INSERT OR IGNORE INTO blocked_ips (ip, blocked_at, reason) VALUES (?1, ?2, ?3)",
                rusqlite::params![ip, blocked_at, reason],
            )?;
            Ok::<(), anyhow::Error>(())
        })
        .await??;

        Ok(())
    }

    /// Удалить IP из списка заблокированных.
    pub async fn remove_blocked_ip(&self, ip: &str) -> Result<()> {
        let conn = self.conn.clone();
        let ip = ip.to_string();

        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap_or_else(|e| e.into_inner());
            let rows = conn.execute(
                "DELETE FROM blocked_ips WHERE ip = ?1",
                rusqlite::params![ip],
            )?;
            if rows == 0 {
                anyhow::bail!("IP {} не найден в списке заблокированных", ip);
            }
            Ok::<(), anyhow::Error>(())
        })
        .await??;

        Ok(())
    }

    /// Вернуть список всех заблокированных IP.
    pub async fn get_active_blocked_ips(&self) -> Result<Vec<BlockedIp>> {
        let conn = self.conn.clone();

        let result = tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap_or_else(|e| e.into_inner());
            let mut stmt = conn.prepare(
                "SELECT ip, blocked_at, reason FROM blocked_ips ORDER BY blocked_at DESC",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok(BlockedIp {
                    ip: row.get(0)?,
                    blocked_at: row.get(1)?,
                    reason: row.get(2)?,
                })
            })?;
            let mut ips = Vec::new();
            for row in rows {
                ips.push(row?);
            }
            Ok::<Vec<BlockedIp>, anyhow::Error>(ips)
        })
        .await??;

        Ok(result)
    }

    /// Persist one incident asynchronously (via `spawn_blocking`).
    pub async fn log_incident(&self, incident: &Incident) -> Result<()> {
        let conn = self.conn.clone();

        let fired_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let name = incident.name.clone();
        let severity = severity_str(&incident.severity);
        let description = incident.description.clone();
        let monitor_type = format!("{:?}", incident.metadata.monitor_type);
        let threshold = incident.metadata.threshold;
        let current_value = incident.metadata.current_value;
        let details = incident.metadata.details.clone();

        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap_or_else(|e| e.into_inner());
            conn.execute(
                "INSERT INTO incidents \
                 (fired_at, name, severity, description, monitor_type, threshold, current_value, details) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![
                    fired_at,
                    name,
                    severity,
                    description,
                    monitor_type,
                    threshold,
                    current_value,
                    details,
                ],
            )?;
            Ok::<(), anyhow::Error>(())
        })
        .await??;

        Ok(())
    }
}

// ============================================================================
// Internals
// ============================================================================

impl IncidentStorage {
    fn init_schema(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS incidents (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                fired_at     INTEGER NOT NULL,
                name         TEXT    NOT NULL,
                severity     TEXT    NOT NULL,
                description  TEXT    NOT NULL,
                monitor_type TEXT    NOT NULL,
                threshold    REAL    NOT NULL,
                current_value REAL   NOT NULL,
                details      TEXT    NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_incidents_fired_at ON incidents (fired_at DESC);

            CREATE TABLE IF NOT EXISTS blocked_ips (
                ip         TEXT    PRIMARY KEY,
                blocked_at INTEGER NOT NULL,
                reason     TEXT    NOT NULL
            );",
        )
        .context("Failed to init incident DB schema")?;
        Ok(())
    }
}

fn severity_str(s: &IncidentSeverity) -> &'static str {
    match s {
        IncidentSeverity::Critical => "Critical",
        IncidentSeverity::Warning => "Warning",
        IncidentSeverity::Info => "Info",
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MonitorType;
    use crate::detector::{IncidentMetadata, IncidentSeverity};
    use crate::action::ActionType;

    fn make_incident() -> Incident {
        Incident {
            name: "Test Incident".to_string(),
            severity: IncidentSeverity::Critical,
            description: "CPU spike".to_string(),
            actions: vec![ActionType::AlertCritical],
            metadata: IncidentMetadata {
                monitor_type: MonitorType::CpuUsage,
                threshold: 95.0,
                current_value: 98.5,
                details: "top: nginx (97%)".to_string(),
            },
        }
    }

    #[tokio::test]
    async fn test_log_incident_in_memory() {
        let storage = IncidentStorage::new_in_memory().unwrap();
        let incident = make_incident();

        storage.log_incident(&incident).await.unwrap();

        // Verify row count via blocking query
        let conn = storage.conn.lock().unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM incidents", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_multiple_incidents() {
        let storage = IncidentStorage::new_in_memory().unwrap();
        let incident = make_incident();

        storage.log_incident(&incident).await.unwrap();
        storage.log_incident(&incident).await.unwrap();

        let conn = storage.conn.lock().unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM incidents", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 2);
    }
}
