/// Path: PanicMode/scr/action/result.rs
use super::r#trait::ActionType;

/// Result of executing a set of actions for an incident.
#[derive(Debug, Clone)]
pub struct ActionExecutionResult {
    pub total: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub failures: Vec<ActionFailure>,
}

impl ActionExecutionResult {
    /// Returns true if all actions succeeded.
    pub fn is_success(&self) -> bool {
        self.failed == 0
    }

    /// Fraction of successful actions (0.0–1.0). Returns 1.0 if total == 0.
    pub fn success_rate(&self) -> f64 {
        if self.total == 0 {
            return 1.0;
        }
        self.succeeded as f64 / self.total as f64
    }
}

/// Details of a single failed action.
#[derive(Debug, Clone)]
pub struct ActionFailure {
    pub action: ActionType,
    pub error: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_succeeded() {
        let result = ActionExecutionResult {
            total: 3,
            succeeded: 3,
            failed: 0,
            failures: vec![],
        };
        assert!(result.is_success());
        assert_eq!(result.success_rate(), 1.0);
    }

    #[test]
    fn test_partial_failure() {
        let result = ActionExecutionResult {
            total: 4,
            succeeded: 3,
            failed: 1,
            failures: vec![ActionFailure {
                action: ActionType::BlockIp,
                error: "timeout".to_string(),
            }],
        };
        assert!(!result.is_success());
        assert_eq!(result.success_rate(), 0.75);
    }

    #[test]
    fn test_empty() {
        let result = ActionExecutionResult {
            total: 0,
            succeeded: 0,
            failed: 0,
            failures: vec![],
        };
        assert!(result.is_success());
        assert_eq!(result.success_rate(), 1.0);
    }
}