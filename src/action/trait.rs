/// Path: PanicMode/scr/action/trait.rs
use anyhow::Result;
use async_trait::async_trait;
use serde::Deserialize;
use crate::detector::Incident;

// ============================================================================
// ActionType — domain enum of protective actions
// ============================================================================

/// Type of a protective action.
///
/// Single source of truth — lives in the action module.
/// config, detector, executor — all import from here.
///
/// Serde: custom implementation because of `MassFreezeCluster(String)`.
/// Format: `"mass_freeze_cluster:website"` in YAML/JSON.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ActionType {
    // Alerts (NOT the action module's responsibility, but needed for completeness)
    AlertCritical,
    AlertWarning,
    AlertInfo,

    // Firewall
    BlockIp,
    RateLimit,

    // Process — freeze
    FreezeTopProcess,
    MassFreeze,
    MassFreezeTop,
    MassFreezeCluster(String),

    // Process — kill
    KillProcess,

    // Snapshot
    Snapshot,

    // Script
    RunScript,
}

impl ActionType {
    /// String representation for serde and logging.
    pub fn as_str(&self) -> String {
        match self {
            Self::AlertCritical => "alert_critical".to_string(),
            Self::AlertWarning => "alert_warning".to_string(),
            Self::AlertInfo => "alert_info".to_string(),
            Self::BlockIp => "block_ip".to_string(),
            Self::RateLimit => "rate_limit".to_string(),
            Self::FreezeTopProcess => "freeze_top_process".to_string(),
            Self::MassFreeze => "mass_freeze".to_string(),
            Self::MassFreezeTop => "mass_freeze_top".to_string(),
            Self::MassFreezeCluster(name) => format!("mass_freeze_cluster:{}", name),
            Self::KillProcess => "kill_process".to_string(),
            Self::Snapshot => "snapshot".to_string(),
            Self::RunScript => "run_script".to_string(),
        }
    }

    /// Parse from string. Supports `mass_freeze_cluster:name`.
    pub fn parse(s: &str) -> Option<Self> {
        // Check parameterized variants first
        if let Some(name) = s.strip_prefix("mass_freeze_cluster:") {
            let name = name.trim();
            if !name.is_empty() {
                return Some(Self::MassFreezeCluster(name.to_string()));
            }
            return None;
        }

        match s {
            "alert_critical" => Some(Self::AlertCritical),
            "alert_warning" => Some(Self::AlertWarning),
            "alert_info" => Some(Self::AlertInfo),
            "block_ip" => Some(Self::BlockIp),
            "rate_limit" => Some(Self::RateLimit),
            "freeze_top_process" => Some(Self::FreezeTopProcess),
            "mass_freeze" => Some(Self::MassFreeze),
            "mass_freeze_top" => Some(Self::MassFreezeTop),
            "kill_process" => Some(Self::KillProcess),
            "snapshot" => Some(Self::Snapshot),
            "run_script" => Some(Self::RunScript),
            _ => None,
        }
    }
}

impl std::fmt::Display for ActionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.as_str())
    }
}

impl serde::Serialize for ActionType {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for ActionType {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::custom(format!("unknown action type: {}", s)))
    }
}


// ============================================================================
// ActionContext
// ============================================================================

/// Execution context passed to every action.
///
/// Wrapper around the data needed to execute an action.
/// Allows extending context without changing the trait signature.
#[derive(Debug, Clone)]
pub struct ActionContext<'a> {
    pub incident: &'a Incident,
}

impl<'a> ActionContext<'a> {
    pub fn new(incident: &'a Incident) -> Self {
        Self { incident }
    }
}

// ============================================================================
// Action trait
// ============================================================================

/// Base trait for all protective actions.
///
/// # Principles:
/// - Pure domain contract
/// - Does NOT know about CircuitBreaker, Config, Registry
/// - Receives &ActionContext (does not own the data)
///
/// # Implementation example:
/// ```ignore
/// struct MyAction;
///
/// #[async_trait]
/// impl Action for MyAction {
///     async fn execute(&self, ctx: &ActionContext<'_>) -> Result<()> {
///         tracing::info!("handling {}", ctx.incident.name);
///         Ok(())
///     }
///
///     fn name(&self) -> &str {
///         "my_action"
///     }
/// }
/// ```
#[async_trait]
pub trait Action: Send + Sync {
    /// Execute the action based on the incident context.
    async fn execute(&self, ctx: &ActionContext<'_>) -> Result<()>;

    /// Action name for logging and identification.
    fn name(&self) -> &str;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_actions() {
        assert_eq!(ActionType::parse("block_ip"), Some(ActionType::BlockIp));
        assert_eq!(ActionType::parse("mass_freeze"), Some(ActionType::MassFreeze));
        assert_eq!(ActionType::parse("mass_freeze_top"), Some(ActionType::MassFreezeTop));
        assert_eq!(ActionType::parse("snapshot"), Some(ActionType::Snapshot));
    }

    #[test]
    fn test_parse_cluster() {
        assert_eq!(
            ActionType::parse("mass_freeze_cluster:website"),
            Some(ActionType::MassFreezeCluster("website".to_string()))
        );
        assert_eq!(
            ActionType::parse("mass_freeze_cluster:crm"),
            Some(ActionType::MassFreezeCluster("crm".to_string()))
        );
    }

    #[test]
    fn test_parse_cluster_empty_name() {
        assert_eq!(ActionType::parse("mass_freeze_cluster:"), None);
    }

    #[test]
    fn test_parse_unknown() {
        assert_eq!(ActionType::parse("totally_unknown"), None);
    }

    #[test]
    fn test_roundtrip_simple() {
        let action = ActionType::BlockIp;
        assert_eq!(ActionType::parse(&action.as_str()), Some(action));
    }

    #[test]
    fn test_roundtrip_cluster() {
        let action = ActionType::MassFreezeCluster("website".to_string());
        assert_eq!(ActionType::parse(&action.as_str()), Some(action));
    }

    #[test]
    fn test_display() {
        assert_eq!(ActionType::MassFreeze.to_string(), "mass_freeze");
        assert_eq!(
            ActionType::MassFreezeCluster("api".to_string()).to_string(),
            "mass_freeze_cluster:api"
        );
    }

    #[test]
    fn test_serde_roundtrip() {
        let actions = vec![
            ActionType::BlockIp,
            ActionType::MassFreeze,
            ActionType::MassFreezeCluster("website".to_string()),
        ];
        let json = serde_json::to_string(&actions).unwrap();
        let parsed: Vec<ActionType> = serde_json::from_str(&json).unwrap();
        assert_eq!(actions, parsed);
    }
}   