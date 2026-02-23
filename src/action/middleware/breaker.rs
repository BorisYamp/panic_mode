/// Path: PanicMode/scr/action/middleware/breaker.rs
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;

use crate::action::r#trait::{Action, ActionContext};
use crate::detector::CircuitBreaker;

/// Transparent decorator: wraps any Action in a CircuitBreaker.
///
/// # Principles:
/// - Implements the Action trait — the executor is unaware of its existence
/// - Uses Arc<dyn Action> internally to allow Clone in closures
/// - Delegates all logic to the inner action + breaker
pub struct BreakerWrapped {
    inner: Arc<dyn Action>,
    breaker: Arc<CircuitBreaker>,
}

impl BreakerWrapped {
    pub fn new<A: Action + 'static>(inner: A, breaker: Arc<CircuitBreaker>) -> Self {
        Self {
            inner: Arc::new(inner),
            breaker,
        }
    }
}

#[async_trait]
impl Action for BreakerWrapped {
    async fn execute(&self, ctx: &ActionContext<'_>) -> Result<()> {
        // Clone owned data for the closure ('static bound requirement)
        let incident = ctx.incident.clone();
        let inner = self.inner.clone();

        self.breaker
            .call(move || {
                let inner = inner.clone();
                let incident = incident.clone();
                async move {
                    let ctx = ActionContext::new(&incident);
                    inner.execute(&ctx).await
                }
            })
            .await
    }

    fn name(&self) -> &str {
        self.inner.name()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::r#trait::ActionType;
    use crate::config::MonitorType;
    use crate::detector::{IncidentMetadata, IncidentSeverity};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    struct CountingAction {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl Action for CountingAction {
        async fn execute(&self, _ctx: &ActionContext<'_>) -> Result<()> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn name(&self) -> &str {
            "counting"
        }
    }

    struct AlwaysFailAction;

    #[async_trait]
    impl Action for AlwaysFailAction {
        async fn execute(&self, _ctx: &ActionContext<'_>) -> Result<()> {
            anyhow::bail!("boom")
        }
        fn name(&self) -> &str {
            "always_fail"
        }
    }

    fn test_incident() -> crate::detector::Incident {
        crate::detector::Incident {
            name: "test".to_string(),
            severity: IncidentSeverity::Critical,
            description: "test".to_string(),
            actions: vec![ActionType::BlockIp],
            metadata: IncidentMetadata {
                monitor_type: MonitorType::CpuUsage,
                threshold: 80.0,
                current_value: 95.0,
                details: "test".to_string(),
            },
        }
    }

    fn test_breaker() -> Arc<CircuitBreaker> {
        Arc::new(
            CircuitBreaker::new(3, Duration::from_secs(60), Duration::from_secs(30))
                .with_timeout(Duration::from_secs(5)),
        )
    }

    #[tokio::test]
    async fn test_delegates_to_inner() {
        let calls = Arc::new(AtomicUsize::new(0));
        let action = BreakerWrapped::new(
            CountingAction { calls: calls.clone() },
            test_breaker(),
        );

        let incident = test_incident();
        let ctx = ActionContext::new(&incident);
        action.execute(&ctx).await.unwrap();

        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_name_delegates() {
        let action = BreakerWrapped::new(
            CountingAction { calls: Arc::new(AtomicUsize::new(0)) },
            test_breaker(),
        );

        assert_eq!(action.name(), "counting");
    }

    #[tokio::test]
    async fn test_breaker_opens_after_failures() {
        let breaker = Arc::new(
            CircuitBreaker::new(2, Duration::from_secs(60), Duration::from_secs(30))
                .with_timeout(Duration::from_secs(5)),
        );

        let action = BreakerWrapped::new(AlwaysFailAction, breaker);

        let incident = test_incident();
        let ctx = ActionContext::new(&incident);

        // 2 failures open the breaker
        let _ = action.execute(&ctx).await;
        let _ = action.execute(&ctx).await;

        // 3rd call — breaker OPEN
        let result = action.execute(&ctx).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("OPEN"));
    }
}
