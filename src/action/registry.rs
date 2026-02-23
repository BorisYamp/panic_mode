/// Path: PanicMode/scr/action/registry.rs
use std::collections::HashMap;
use std::sync::Arc;

use super::r#trait::{Action, ActionType};

/// Storage for registered actions.
///
/// # Principles:
/// - Only stores and retrieves actions
/// - Does NOT create actions, breakers, or middleware
/// - Clone + thread-safe (Arc<dyn Action> inside)
/// - Returns None if action not found (no panic!)
#[derive(Clone)]
pub struct ActionRegistry {
    actions: HashMap<ActionType, Arc<dyn Action>>,
}

impl ActionRegistry {
    pub fn new() -> Self {
        Self {
            actions: HashMap::new(),
        }
    }

    /// Register an action for the given type.
    /// Overwrites if already registered.
    pub fn register(&mut self, action_type: ActionType, action: Arc<dyn Action>) {
        tracing::debug!("Registered action: {} -> {}", action_type, action.name());
        self.actions.insert(action_type, action);
    }

    /// Look up an action by type. Returns None if not registered.
    pub fn resolve(&self, action_type: &ActionType) -> Option<Arc<dyn Action>> {
        self.actions.get(action_type).cloned()
    }

    /// List of all registered action types.
    pub fn registered_types(&self) -> Vec<ActionType> {
        self.actions.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::ActionContext;
    use anyhow::Result;
    use async_trait::async_trait;

    struct DummyAction;

    #[async_trait]
    impl Action for DummyAction {
        async fn execute(&self, _ctx: &ActionContext<'_>) -> Result<()> {
            Ok(())
        }
        fn name(&self) -> &str {
            "dummy"
        }
    }

    #[test]
    fn test_register_and_resolve() {
        let mut registry = ActionRegistry::new();
        registry.register(ActionType::BlockIp, Arc::new(DummyAction));

        assert!(registry.resolve(&ActionType::BlockIp).is_some());
        assert!(registry.resolve(&ActionType::Snapshot).is_none());
    }

    #[test]
    fn test_registered_types() {
        let mut registry = ActionRegistry::new();
        registry.register(ActionType::BlockIp, Arc::new(DummyAction));
        registry.register(ActionType::KillProcess, Arc::new(DummyAction));

        let types = registry.registered_types();
        assert_eq!(types.len(), 2);
        assert!(types.contains(&ActionType::BlockIp));
        assert!(types.contains(&ActionType::KillProcess));
    }

    #[test]
    fn test_overwrite() {
        let mut registry = ActionRegistry::new();
        registry.register(ActionType::BlockIp, Arc::new(DummyAction));
        registry.register(ActionType::BlockIp, Arc::new(DummyAction));

        assert_eq!(registry.registered_types().len(), 1);
    }

    #[test]
    fn test_resolve_unknown_returns_none() {
        let registry = ActionRegistry::new();
        assert!(registry.resolve(&ActionType::RunScript).is_none());
    }

    #[test]
    fn test_clone_is_independent() {
        let mut registry = ActionRegistry::new();
        registry.register(ActionType::BlockIp, Arc::new(DummyAction));

        let clone = registry.clone();
        registry.register(ActionType::Snapshot, Arc::new(DummyAction));

        assert_eq!(clone.registered_types().len(), 1);
        assert_eq!(registry.registered_types().len(), 2);
    }
}