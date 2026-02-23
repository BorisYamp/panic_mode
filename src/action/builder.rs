/// Path: PanicMode/scr/action/builder.rs
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};

use crate::config::Config;
use crate::detector::CircuitBreaker;
use crate::storage::IncidentStorage;

use super::executor::ActionExecutor;
use super::middleware::BreakerWrapped;
use super::registry::ActionRegistry;
use super::r#trait::ActionType;
use super::implementations::{FirewallAction, ProcessAction, SnapshotAction, ScriptAction};

/// Single place for creating and wiring all dependencies.
///
/// # Principles:
/// - Composition root: creates actions, breakers, wraps them in middleware
/// - Fluent API: builder.with_firewall().with_process().build()
/// - **Fail-fast**: build() validates consistency and returns Err
///   if the system cannot serve any of the configured actions
///
/// # Guarantee:
/// If `build()` returns `Ok` — the system is fully consistent.
/// If not — the system does not start.
pub struct ActionExecutorBuilder {
    config: Arc<Config>,
    registry: ActionRegistry,
    errors: Vec<String>,
}

impl ActionExecutorBuilder {
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            config,
            registry: ActionRegistry::new(),
            errors: Vec::new(),
        }
    }

    pub fn with_firewall(mut self, storage: Arc<IncidentStorage>) -> Self {
        match FirewallAction::new(self.config.clone(), storage) {
            Ok(action) => {
                let breaker = self.default_breaker();
                let wrapped = BreakerWrapped::new(action, breaker);
                self.registry.register(ActionType::BlockIp, Arc::new(wrapped));
            }
            Err(e) => {
                self.errors.push(format!("FirewallAction: {}", e));
            }
        }
        self
    }

    pub fn with_process(mut self) -> Self {
        match ProcessAction::new(self.config.clone()) {
            Ok(action) => {
                let breaker = Arc::new(
                    self.base_breaker()
                        .with_concurrency_limit(3)
                        .with_timeout(Duration::from_secs(5)),
                );
                let wrapped = BreakerWrapped::new(action, breaker);
                self.registry.register(ActionType::FreezeTopProcess, Arc::new(wrapped));
            }
            Err(e) => {
                self.errors.push(format!("ProcessAction: {}", e));
            }
        }
        self
    }

    pub fn with_snapshot(mut self) -> Self {
        match SnapshotAction::new(self.config.clone()) {
            Ok(action) => {
                let breaker = Arc::new(
                    CircuitBreaker::new(
                        3,
                        self.config.circuit_breakers.failure_window,
                        self.config.circuit_breakers.open_duration,
                    )
                    .with_concurrency_limit(self.config.circuit_breakers.max_concurrency)
                    .with_timeout(Duration::from_secs(30)),
                );
                let wrapped = BreakerWrapped::new(action, breaker);
                self.registry.register(ActionType::Snapshot, Arc::new(wrapped));
            }
            Err(e) => {
                self.errors.push(format!("SnapshotAction: {}", e));
            }
        }
        self
    }

    pub fn with_script(mut self) -> Self {
        match ScriptAction::new(self.config.clone()) {
            Ok(action) => {
                let breaker = Arc::new(
                    self.base_breaker()
                        .with_timeout(Duration::from_secs(60)),
                );
                let wrapped = BreakerWrapped::new(action, breaker);
                self.registry.register(ActionType::RunScript, Arc::new(wrapped));
            }
            Err(e) => {
                self.errors.push(format!("ScriptAction: {}", e));
            }
        }
        self
    }

    /// Build the executor with two-level validation.
    ///
    /// # Fatal (Err):
    /// - No actions could be created (registry is empty)
    ///
    /// # Degradable (warn + continue):
    /// - A specific action failed to initialize (missing binary, no permission)
    /// - Monitor is partially covered — as long as alerts work, the system is useful
    ///
    /// If `build()` returns `Ok` — the system can handle at least something.
    pub fn build(self) -> Result<ActionExecutor> {
        // Degradable: log initialization errors but do not crash
        if !self.errors.is_empty() {
            for err in &self.errors {
                tracing::warn!("⚠️  Action creation failed (degraded): {}", err);
            }
        }

        // Fatal: registry is empty — system is completely blind
        let registered = self.registry.registered_types();
        if registered.is_empty() {
            bail!("No actions registered — system cannot handle any incidents");
        }

        // Degradable: warn about partial action coverage
        for monitor in &self.config.monitors {
            if !monitor.enabled {
                continue;
            }

            let missing: Vec<_> = monitor
                .actions
                .iter()
                .filter(|at| self.registry.resolve(at).is_none())
                .collect();

            if !missing.is_empty() {
                tracing::warn!(
                    "⚠️  Monitor '{}': missing actions {:?} (degraded, {} of {} available)",
                    monitor.name,
                    missing,
                    monitor.actions.len() - missing.len(),
                    monitor.actions.len(),
                );
            }
        }

        tracing::info!(
            "✅ ActionExecutor built with {} actions: {:?}",
            registered.len(),
            registered,
        );

        Ok(ActionExecutor::new(self.registry))
    }

    // ========================================================================
    // Private helpers
    // ========================================================================

    fn default_breaker(&self) -> Arc<CircuitBreaker> {
        Arc::new(
            self.base_breaker()
                .with_concurrency_limit(self.config.circuit_breakers.max_concurrency)
                .with_timeout(self.config.circuit_breakers.timeout),
        )
    }

    fn base_breaker(&self) -> CircuitBreaker {
        CircuitBreaker::new(
            self.config.circuit_breakers.max_failures,
            self.config.circuit_breakers.failure_window,
            self.config.circuit_breakers.open_duration,
        )
    }
}