/// Path: PanicMode/scr/action/executor.rs
use super::r#trait::{Action, ActionContext, ActionType};
use super::registry::ActionRegistry;
use super::result::{ActionExecutionResult, ActionFailure};
use crate::detector::Incident;

/// Orchestrator for executing protective actions.
///
/// # Principles:
/// - Simple loop: registry.resolve → action.execute → collect
/// - No match on ActionType, no filtering
/// - Does NOT stop on error — collects all results
/// - Single dependency — ActionRegistry
pub struct ActionExecutor {
    registry: ActionRegistry,
}

impl ActionExecutor {
    /// Created only inside the action module (via builder).
    pub(super) fn new(registry: ActionRegistry) -> Self {
        Self { registry }
    }

    /// Execute all actions listed in the incident.
    pub async fn execute_actions(&self, incident: &Incident) -> ActionExecutionResult {
        let ctx = ActionContext::new(incident);
        let mut total = 0;
        let mut succeeded = 0;
        let mut failures = Vec::new();

        for action_type in &incident.actions {
            let action = match self.registry.resolve(action_type) {
                Some(a) => a,
                None => {
                    tracing::warn!("No action registered for {}, skipping", action_type);
                    continue;
                }
            };

            total += 1;

            match action.execute(&ctx).await {
                Ok(()) => {
                    tracing::info!("✅ {} succeeded", action.name());
                    succeeded += 1;
                }
                Err(e) => {
                    tracing::error!("❌ {} failed: {}", action.name(), e);
                    failures.push(ActionFailure {
                        action: action_type.clone(),
                        error: e.to_string(),
                    });
                }
            }
        }

        ActionExecutionResult {
            total,
            succeeded,
            failed: failures.len(),
            failures,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::r#trait::Action;
    use crate::config::MonitorType;
    use crate::detector::{IncidentMetadata, IncidentSeverity};
    use anyhow::Result;
    use async_trait::async_trait;
    use std::sync::Arc;

    struct OkAction;

    #[async_trait]
    impl Action for OkAction {
        async fn execute(&self, _ctx: &ActionContext<'_>) -> Result<()> {
            Ok(())
        }
        fn name(&self) -> &str {
            "ok_action"
        }
    }

    struct FailAction;

    #[async_trait]
    impl Action for FailAction {
        async fn execute(&self, _ctx: &ActionContext<'_>) -> Result<()> {
            anyhow::bail!("something went wrong")
        }
        fn name(&self) -> &str {
            "fail_action"
        }
    }

    fn test_incident(actions: Vec<ActionType>) -> Incident {
        Incident {
            name: "test".to_string(),
            severity: IncidentSeverity::Critical,
            description: "test incident".to_string(),
            actions,
            metadata: IncidentMetadata {
                monitor_type: MonitorType::CpuUsage,
                threshold: 80.0,
                current_value: 95.0,
                details: "test".to_string(),
            },
        }
    }

    #[tokio::test]
    async fn test_all_succeed() {
        let mut registry = ActionRegistry::new();
        registry.register(ActionType::BlockIp, Arc::new(OkAction));
        registry.register(ActionType::Snapshot, Arc::new(OkAction));

        let executor = ActionExecutor::new(registry);
        let incident = test_incident(vec![ActionType::BlockIp, ActionType::Snapshot]);

        let result = executor.execute_actions(&incident).await;
        assert!(result.is_success());
        assert_eq!(result.total, 2);
        assert_eq!(result.succeeded, 2);
    }

    #[tokio::test]
    async fn test_partial_failure_continues() {
        let mut registry = ActionRegistry::new();
        registry.register(ActionType::BlockIp, Arc::new(FailAction));
        registry.register(ActionType::Snapshot, Arc::new(OkAction));

        let executor = ActionExecutor::new(registry);
        let incident = test_incident(vec![ActionType::BlockIp, ActionType::Snapshot]);

        let result = executor.execute_actions(&incident).await;
        assert!(!result.is_success());
        assert_eq!(result.total, 2);
        assert_eq!(result.succeeded, 1);
        assert_eq!(result.failed, 1);
        assert_eq!(result.failures[0].action, ActionType::BlockIp);
    }

    #[tokio::test]
    async fn test_unregistered_skipped() {
        let registry = ActionRegistry::new();

        let executor = ActionExecutor::new(registry);
        let incident = test_incident(vec![ActionType::BlockIp, ActionType::RunScript]);

        let result = executor.execute_actions(&incident).await;
        assert!(result.is_success());
        assert_eq!(result.total, 0);
    }

    #[tokio::test]
    async fn test_mixed_registered_and_unregistered() {
        let mut registry = ActionRegistry::new();
        registry.register(ActionType::BlockIp, Arc::new(OkAction));

        let executor = ActionExecutor::new(registry);
        let incident = test_incident(vec![ActionType::BlockIp, ActionType::RunScript]);

        let result = executor.execute_actions(&incident).await;
        assert!(result.is_success());
        assert_eq!(result.total, 1);
        assert_eq!(result.succeeded, 1);
    }

    #[tokio::test]
    async fn test_empty_actions() {
        let registry = ActionRegistry::new();
        let executor = ActionExecutor::new(registry);
        let incident = test_incident(vec![]);

        let result = executor.execute_actions(&incident).await;
        assert!(result.is_success());
        assert_eq!(result.total, 0);
    }
}