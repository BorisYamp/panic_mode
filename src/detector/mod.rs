/// Path: PanicMode/scr/detector/mod.rs
use anyhow::Result;
use std::sync::Arc;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Mutex};
use tokio::time::timeout;

use crate::action::ActionExecutor;
use crate::alert::AlertMessage;
use crate::config::{Config, MonitorType, ActionType};
use crate::monitor::{Metrics, MonitorEngine};
use crate::storage::IncidentStorage;

mod rules;
mod anomaly;
mod state;
mod circuit_breaker;

use rules::RuleEvaluator;
use anomaly::AnomalyDetector;
use state::IncidentState;
pub use circuit_breaker::CircuitBreaker;

// ============================================================================
// Incident
// ============================================================================

#[derive(Debug, Clone)]
pub struct Incident {
    pub name: String,
    pub severity: IncidentSeverity,
    pub description: String,
    pub actions: Vec<ActionType>,
    pub metadata: IncidentMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum IncidentSeverity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone)]
pub struct IncidentMetadata {
    pub monitor_type: MonitorType,
    pub threshold: f64,
    pub current_value: f64,
    pub details: String,
}

// ============================================================================
// Detector
// ============================================================================

pub struct Detector {
    config: Arc<Config>,
    monitor_engine: Arc<MonitorEngine>,
    rule_evaluator: RuleEvaluator,
    anomaly_detector: AnomalyDetector,
}

impl Detector {
    pub fn new(config: Arc<Config>, monitor_engine: Arc<MonitorEngine>) -> Self {
        Self {
            rule_evaluator: RuleEvaluator::new(config.clone(), monitor_engine.clone()),
            anomaly_detector: AnomalyDetector::from_config(&config.anomaly),
            config,
            monitor_engine,
        }
    }

    pub async fn check_anomalies(&self, metrics: &Metrics) -> Result<Vec<Incident>> {
        let mut incidents = Vec::new();

        for rule in &self.config.monitors {
            if !rule.enabled {
                continue;
            }

            if let Some(incident) = self.rule_evaluator.evaluate(rule, metrics).await? {
                incidents.push(incident);
            }
        }

        if let Some(anomaly_incident) = self.anomaly_detector.detect_anomalies(metrics)? {
            incidents.push(anomaly_incident);
        }

        incidents.sort_by(|a, b| b.severity.cmp(&a.severity));

        Ok(incidents)
    }
}

impl Clone for Detector {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            monitor_engine: self.monitor_engine.clone(),
            rule_evaluator: self.rule_evaluator.clone(),
            anomaly_detector: self.anomaly_detector.clone(),
        }
    }
}

// ============================================================================
// IncidentHandler
// ============================================================================

/// Orchestrator for incident processing.
///
/// Responsible for:
/// - Deduplication (the same incident is not processed twice within 5 min)
/// - Alert rate limiting (critical: 60s, warning: 300s per incident)
/// - Executing protective actions via ActionExecutor
/// - Sending alerts via alert_tx
/// - Background execution of secondary actions (snapshot, script)
pub struct IncidentHandler {
    config: Arc<Config>,
    action_executor: Arc<ActionExecutor>,
    alert_tx: mpsc::Sender<AlertMessage>,
    state: Arc<Mutex<IncidentState>>,
    incident_rate_limits: Arc<Mutex<HashMap<String, RateLimitState>>>,
    escalation_tracker: Arc<Mutex<EscalationTracker>>,
    critical_alert_cooldown: Duration,
    warning_alert_cooldown: Duration,
    protective_action_timeout: Duration,
    storage: Arc<IncidentStorage>,
}

#[derive(Debug, Clone)]
struct RateLimitState {
    last_alert: Instant,
}

#[derive(Debug, Clone)]
struct EscalationTracker {
    current_contact_index: usize,
    current_contact_attempts: u32,
    last_call: Option<Instant>,
}

impl IncidentHandler {
    pub fn new(
        config: Arc<Config>,
        action_executor: Arc<ActionExecutor>,
        alert_tx: mpsc::Sender<AlertMessage>,
        storage: Arc<IncidentStorage>,
    ) -> Self {
        let state_file = config.storage.state_file.clone();
        Self {
            config,
            action_executor,
            alert_tx,
            state: Arc::new(Mutex::new(IncidentState::load(state_file))),
            incident_rate_limits: Arc::new(Mutex::new(HashMap::new())),
            escalation_tracker: Arc::new(Mutex::new(EscalationTracker {
                current_contact_index: 0,
                current_contact_attempts: 0,
                last_call: None,
            })),
            critical_alert_cooldown: Duration::from_secs(60),
            warning_alert_cooldown: Duration::from_secs(300),
            protective_action_timeout: Duration::from_secs(15),
            storage,
        }
    }

    pub async fn handle_incidents(&self, incidents: Vec<Incident>) -> Result<()> {
        for incident in incidents {
            // Deduplication: check AND record under the same lock acquisition so that
            // any concurrent caller (if ever spawned) cannot slip through between the
            // two operations and fire the same incident twice.
            {
                let mut state = self.state.lock().await;
                if state.is_duplicate(&incident) {
                    tracing::debug!("Skipping duplicate incident: {}", incident.name);
                    continue;
                }
                // Record immediately — before releasing the lock.
                state.record_incident(&incident);
            }

            if let Err(e) = self.handle_incident_safe(incident.clone()).await {
                tracing::error!("Failed to handle incident '{}': {}", incident.name, e);
            }

            // Persist to SQLite in background — never blocks the main loop.
            let storage = self.storage.clone();
            let incident_for_db = incident.clone();
            tokio::spawn(async move {
                if let Err(e) = storage.log_incident(&incident_for_db).await {
                    tracing::error!("Failed to log incident to DB: {}", e);
                }
            });

            // Save state in background, do not block the main loop
            let state_clone = {
                let state = self.state.lock().await;
                state.clone()
            };
            tokio::spawn(async move {
                if let Err(e) = state_clone.save().await {
                    tracing::error!("Failed to persist incident state: {}", e);
                }
            });
        }

        Ok(())
    }

    async fn handle_incident_safe(&self, incident: Incident) -> Result<()> {
        match incident.severity {
            IncidentSeverity::Critical => {
                tracing::error!("CRITICAL: {}", incident.name);
            }
            IncidentSeverity::Warning => {
                tracing::warn!("WARNING: {}", incident.name);
            }
            IncidentSeverity::Info => {
                tracing::info!("INFO: {}", incident.name);
            }
        }

        tracing::info!("Description: {}", incident.description);
        tracing::info!("Details: {}", incident.metadata.details);

        let (protective, alerts, other) = self.categorize_actions(&incident.actions);

        // Protective actions execute with a global timeout
        self.execute_protective_actions(protective, &incident).await;

        // Alerts are sent through the rate limiter
        self.execute_alerts(alerts, &incident).await;

        // Snapshot, script and other secondary actions — in background, do not block
        self.execute_background_actions(other, incident);

        Ok(())
    }

    // -------------------------------------------------------------------------
    // Protective actions: block_ip, freeze, rate_limit, kill
    // -------------------------------------------------------------------------

    async fn execute_protective_actions(
        &self,
        actions: Vec<ActionType>,
        incident: &Incident,
    ) {
        if actions.is_empty() {
            return;
        }

        tracing::info!("Executing {} protective action(s) for '{}'", actions.len(), incident.name);

        // Create a copy of the incident with only protective actions for the executor
        let filtered = Incident {
            actions,
            ..incident.clone()
        };

        match timeout(
            self.protective_action_timeout,
            self.action_executor.execute_actions(&filtered),
        )
        .await
        {
            Ok(result) => {
                if result.failed > 0 {
                    tracing::warn!(
                        "{} protective action(s) failed for '{}': {:?}",
                        result.failed,
                        incident.name,
                        result.failures
                    );
                } else if result.total > 0 {
                    tracing::info!(
                        "All {} protective action(s) succeeded for '{}'",
                        result.total,
                        incident.name
                    );
                }
            }
            Err(_) => {
                tracing::error!(
                    "Protective actions timed out after {:?} for '{}'",
                    self.protective_action_timeout,
                    incident.name
                );
            }
        }
    }

    // -------------------------------------------------------------------------
    // Alert actions: rate limiting + actual dispatch via alert_tx
    // -------------------------------------------------------------------------

    async fn execute_alerts(&self, alerts: Vec<ActionType>, incident: &Incident) {
        if alerts.is_empty() {
            return;
        }

        let incident_key = Self::incident_key(incident);

        for alert in alerts {
            match alert {
                ActionType::AlertCritical => {
                    let should_alert = self
                        .check_and_update_rate_limit(&incident_key, self.critical_alert_cooldown)
                        .await;

                    if should_alert {
                        let msg = AlertMessage::critical(format!(
                            "{}: {}",
                            incident.name, incident.description
                        ));
                        if let Err(_) = self.alert_tx.try_send(msg) {
                            // Channel full — high-priority alerts are already queued.
                            // Write directly to stderr: works even when the system is degraded.
                            eprintln!(
                                "[PANICMODE CRITICAL - channel full] {}: {}",
                                incident.name, incident.description
                            );
                        }

                        // Escalation tracker (respects contact call order)
                        self.update_escalation_tracker(incident).await;
                    } else {
                        tracing::debug!(
                            "Critical alert rate-limited for '{}' (cooldown {}s)",
                            incident.name,
                            self.critical_alert_cooldown.as_secs()
                        );
                    }
                }

                ActionType::AlertWarning => {
                    let should_alert = self
                        .check_and_update_rate_limit(&incident_key, self.warning_alert_cooldown)
                        .await;

                    if should_alert {
                        let msg = AlertMessage::warning(format!(
                            "{}: {}",
                            incident.name, incident.description
                        ));
                        if let Err(e) = self.alert_tx.try_send(msg) {
                            tracing::error!("Failed to queue warning alert: {}", e);
                        }
                    } else {
                        tracing::debug!(
                            "Warning alert rate-limited for '{}' (cooldown {}s)",
                            incident.name,
                            self.warning_alert_cooldown.as_secs()
                        );
                    }
                }

                ActionType::AlertInfo => {
                    // Info alerts are not rate-limited — they are non-critical
                    let msg = AlertMessage::info(format!(
                        "{}: {}",
                        incident.name, incident.description
                    ));
                    if let Err(e) = self.alert_tx.try_send(msg) {
                        tracing::error!("Failed to queue info alert: {}", e);
                    }
                }

                _ => {}
            }
        }
    }

    /// Checks the cooldown and updates the timer. Returns true if the alert should be sent.
    async fn check_and_update_rate_limit(
        &self,
        incident_key: &str,
        cooldown: Duration,
    ) -> bool {
        let mut limits = self.incident_rate_limits.lock().await;

        // Remove expired entries before adding new ones.
        // The map is limited to "live" incidents (active within the last 2x cooldown).
        limits.retain(|_, state| state.last_alert.elapsed() < cooldown * 2);

        let should_alert = match limits.get(incident_key) {
            Some(state) => state.last_alert.elapsed() >= cooldown,
            None => true,
        };

        if should_alert {
            limits.insert(
                incident_key.to_string(),
                RateLimitState { last_alert: Instant::now() },
            );
        }

        should_alert
    }

    /// Updates the escalation tracker: after 3 attempts switches to the next contact.
    async fn update_escalation_tracker(&self, incident: &Incident) {
        let contacts: Vec<String> = self
            .config
            .alerts
            .critical
            .iter()
            .flat_map(|ch| ch.contacts.iter().map(|c| c.phone.clone()))
            .collect();

        if contacts.is_empty() {
            return;
        }

        let mut tracker = self.escalation_tracker.lock().await;

        // 60s cooldown between calls
        if let Some(last) = tracker.last_call {
            if Instant::now().duration_since(last) < Duration::from_secs(60) {
                tracing::debug!("Call escalation on cooldown for '{}'", incident.name);
                return;
            }
        }

        let contact = &contacts[tracker.current_contact_index];
        tracker.current_contact_attempts += 1;
        tracker.last_call = Some(Instant::now());

        tracing::info!(
            "Alert sent to contact {}/{}: {} (attempt {}/3)",
            tracker.current_contact_index + 1,
            contacts.len(),
            contact,
            tracker.current_contact_attempts
        );

        if tracker.current_contact_attempts >= 3 {
            tracker.current_contact_index =
                (tracker.current_contact_index + 1) % contacts.len();
            tracker.current_contact_attempts = 0;

            tracing::warn!(
                "Escalating to next contact: {} ({}/{})",
                contacts[tracker.current_contact_index],
                tracker.current_contact_index + 1,
                contacts.len()
            );
        }
    }

    // -------------------------------------------------------------------------
    // Background actions: snapshot, run_script
    // -------------------------------------------------------------------------

    fn execute_background_actions(&self, actions: Vec<ActionType>, incident: Incident) {
        if actions.is_empty() {
            return;
        }

        let executor = self.action_executor.clone();

        tokio::spawn(async move {
            let filtered = Incident {
                actions,
                ..incident
            };
            let result = executor.execute_actions(&filtered).await;
            if result.failed > 0 {
                tracing::warn!(
                    "{} background action(s) failed for '{}': {:?}",
                    result.failed,
                    filtered.name,
                    result.failures
                );
            }
        });
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    fn categorize_actions(
        &self,
        actions: &[ActionType],
    ) -> (Vec<ActionType>, Vec<ActionType>, Vec<ActionType>) {
        let mut protective = Vec::new();
        let mut alerts = Vec::new();
        let mut other = Vec::new();

        for action in actions {
            match action {
                ActionType::BlockIp
                | ActionType::FreezeTopProcess
                | ActionType::MassFreeze
                | ActionType::MassFreezeTop
                | ActionType::MassFreezeCluster(_)
                | ActionType::KillProcess
                | ActionType::RateLimit => {
                    protective.push(action.clone());
                }
                ActionType::AlertCritical
                | ActionType::AlertWarning
                | ActionType::AlertInfo => {
                    alerts.push(action.clone());
                }
                ActionType::Snapshot | ActionType::RunScript => {
                    other.push(action.clone());
                }
            }
        }

        (protective, alerts, other)
    }

    fn incident_key(incident: &Incident) -> String {
        format!("{}:{:?}", incident.name, incident.metadata.monitor_type)
    }

}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::ActionExecutorBuilder;
    use crate::config::{Config, MonitorType};
    use std::sync::Arc;

    fn make_handler() -> IncidentHandler {
        let config = Arc::new(Config::default());
        let executor = Arc::new(
            ActionExecutorBuilder::new(config.clone())
                .with_snapshot()
                .build()
                .unwrap(),
        );
        let (alert_tx, _alert_rx) = tokio::sync::mpsc::channel(100);
        let storage = Arc::new(crate::storage::IncidentStorage::new_in_memory().unwrap());
        IncidentHandler::new(config, executor, alert_tx, storage)
    }

    fn make_incident(name: &str, monitor_type: MonitorType) -> Incident {
        Incident {
            name: name.to_string(),
            severity: IncidentSeverity::Critical,
            description: format!("Test incident: {}", name),
            actions: vec![ActionType::AlertCritical],
            metadata: IncidentMetadata {
                monitor_type,
                threshold: 80.0,
                current_value: 90.0,
                details: "Test".to_string(),
            },
        }
    }

    #[tokio::test]
    async fn test_per_incident_rate_limiting() {
        let handler = make_handler();

        let incident1 = make_incident("CPU", MonitorType::CpuUsage);
        let incident2 = make_incident("SSH", MonitorType::AuthFailures);

        handler
            .handle_incidents(vec![incident1.clone(), incident2.clone()])
            .await
            .unwrap();

        let limits = handler.incident_rate_limits.lock().await;
        assert_eq!(
            limits.len(),
            2,
            "Should have 2 separate rate limit entries"
        );
    }

    #[tokio::test]
    async fn test_duplicate_incident_skipped() {
        let handler = make_handler();

        let incident = make_incident("CPU", MonitorType::CpuUsage);

        // First call — handle the incident
        handler
            .handle_incidents(vec![incident.clone()])
            .await
            .unwrap();

        // Second call — same incident should be skipped as a duplicate
        let limits_before = {
            let limits = handler.incident_rate_limits.lock().await;
            limits.len()
        };

        handler
            .handle_incidents(vec![incident.clone()])
            .await
            .unwrap();

        let limits_after = {
            let limits = handler.incident_rate_limits.lock().await;
            limits.len()
        };

        // Rate limit must not update a second time (incident skipped as duplicate)
        assert_eq!(limits_before, limits_after);
    }
}
