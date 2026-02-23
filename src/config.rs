/// Path: PanicMode/src/config.rs
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

// ActionType живёт в action-модуле, но реэкспортируем для обратной совместимости:
// другие модули продолжают делать `use crate::config::ActionType`
pub use crate::action::ActionType;

// ============================================================================
// Main Config Structure
// ============================================================================

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub performance: PerformanceConfig,
    pub monitors: Vec<MonitorRule>,
    pub actions: HashMap<String, ActionConfig>,
    pub alerts: AlertsConfig,
    pub integrations: IntegrationsConfig,

    #[serde(default)]
    pub custom_metrics: HashMap<String, CustomMetricConfig>,

    #[serde(default)]
    pub file_monitor: FileMonitorConfig,

    #[serde(default)]
    pub circuit_breakers: CircuitBreakerConfig,

    #[serde(default)]
    pub storage: StorageConfig,

    /// Пороги встроенного детектора аномалий
    #[serde(default)]
    pub anomaly: AnomalyConfig,

    /// Встроенный HTTP healthcheck endpoint
    #[serde(default)]
    pub http_api: HttpApiConfig,

    /// Настройки блокировки IP фаерволом и CLI-управления
    #[serde(default)]
    pub firewall: FirewallConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            performance: PerformanceConfig {
                cpu_limit: 5.0,
                memory_limit_mb: 50,
                check_interval: Duration::from_secs(5),
            },
            monitors: vec![],
            actions: HashMap::new(),
            alerts: AlertsConfig {
                critical: vec![],
                warning: vec![],
                info: vec![],
            },
            integrations: IntegrationsConfig {
                telegram: None,
                discord: None,
                ntfy: None,
                email: None,
                twilio: None,
            },
            custom_metrics: HashMap::new(),
            file_monitor: FileMonitorConfig::default(),
            circuit_breakers: CircuitBreakerConfig::default(),
            storage: StorageConfig::default(),
            anomaly: AnomalyConfig::default(),
            http_api: HttpApiConfig::default(),
            firewall: FirewallConfig::default(),
        }
    }
}

// ============================================================================
// Performance Config
// ============================================================================

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PerformanceConfig {
    pub cpu_limit: f32,
    pub memory_limit_mb: u64,

    #[serde(with = "humantime_serde")]
    pub check_interval: Duration,
}

// ============================================================================
// Storage Config
// ============================================================================

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StorageConfig {
    /// Path to the SQLite database for incident history.
    #[serde(default = "default_incident_db")]
    pub incident_db: String,

    /// Directory where system snapshots are saved.
    #[serde(default = "default_snapshot_dir")]
    pub snapshot_dir: String,

    /// Directory for rolling log files.
    #[serde(default = "default_log_dir")]
    pub log_dir: String,

    /// JSON file to persist incident deduplication state across restarts.
    /// При рестарте загружается — активные инциденты не дедуплицируются повторно.
    #[serde(default = "default_state_file")]
    pub state_file: String,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            incident_db: default_incident_db(),
            snapshot_dir: default_snapshot_dir(),
            log_dir: default_log_dir(),
            state_file: default_state_file(),
        }
    }
}

fn default_incident_db() -> String {
    "/var/lib/panicmode/incidents.db".to_string()
}
fn default_snapshot_dir() -> String {
    "/var/log/panicmode/snapshots".to_string()
}
fn default_log_dir() -> String {
    "/var/log/panicmode".to_string()
}
fn default_state_file() -> String {
    "/var/lib/panicmode/incident_state.json".to_string()
}

// ============================================================================
// Anomaly Detection Config
// ============================================================================

/// Пороги встроенного детектора аномалий (AnomalyDetector).
///
/// AnomalyDetector работает поверх правил monitors[]: он срабатывает при
/// резком выбросе метрик даже если явных правил в конфиге нет.
///
/// Пример в config.yaml:
/// ```yaml
/// anomaly:
///   cpu_spike_threshold: 95.0
///   memory_spike_threshold: 95.0
///   connection_spike_threshold: 10000
///   suspicious_ip_threshold: 3
///   high_load_threshold: 10.0
/// ```
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AnomalyConfig {
    /// CPU (%) — порог аномального CPU-спайка
    #[serde(default = "default_cpu_spike_threshold")]
    pub cpu_spike_threshold: f32,

    /// RAM (%) — порог аномального потребления памяти (должно быть + heavy swap)
    #[serde(default = "default_memory_spike_threshold")]
    pub memory_spike_threshold: f32,

    /// Активные соединения — порог flood-атаки
    #[serde(default = "default_connection_spike_threshold")]
    pub connection_spike_threshold: u64,

    /// Минимальное число подозрительных IP для координированной атаки
    #[serde(default = "default_suspicious_ip_threshold")]
    pub suspicious_ip_threshold: usize,

    /// Load average 1 min — порог высокой нагрузки (I/O-bound и пр.)
    /// Рекомендуется: кол-во CPU-ядер × 1.5–2.0
    #[serde(default = "default_high_load_threshold")]
    pub high_load_threshold: f64,

    /// Соединений от одного IP — порог для пометки IP как "подозрительного".
    /// Используется NetworkMonitor при вычислении top_ips.is_suspicious.
    /// AnomalyDetector затем смотрит сколько таких IP накопилось (→ suspicious_ip_threshold).
    #[serde(default = "default_suspicious_connections_per_ip")]
    pub suspicious_connections_per_ip: u64,
}

impl Default for AnomalyConfig {
    fn default() -> Self {
        Self {
            cpu_spike_threshold: default_cpu_spike_threshold(),
            memory_spike_threshold: default_memory_spike_threshold(),
            connection_spike_threshold: default_connection_spike_threshold(),
            suspicious_ip_threshold: default_suspicious_ip_threshold(),
            high_load_threshold: default_high_load_threshold(),
            suspicious_connections_per_ip: default_suspicious_connections_per_ip(),
        }
    }
}

fn default_cpu_spike_threshold() -> f32 { 95.0 }
fn default_memory_spike_threshold() -> f32 { 95.0 }
fn default_connection_spike_threshold() -> u64 { 10_000 }
fn default_suspicious_ip_threshold() -> usize { 3 }
fn default_high_load_threshold() -> f64 { 10.0 }
fn default_suspicious_connections_per_ip() -> u64 { 50 }

// ============================================================================
// HTTP API Config
// ============================================================================

/// Встроенный HTTP healthcheck endpoint (опционально).
///
/// Пример в config.yaml:
/// ```yaml
/// http_api:
///   enabled: true
///   bind: "127.0.0.1:8765"
/// ```
///
/// Запрос: GET http://127.0.0.1:8765/health
/// Ответ:  {"status":"ok","uptime_secs":3600,"version":"0.1.0"}
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HttpApiConfig {
    /// Включить HTTP API. По умолчанию выключен.
    #[serde(default)]
    pub enabled: bool,

    /// Адрес для прослушивания. Только localhost — не открывай в интернет!
    #[serde(default = "default_http_bind")]
    pub bind: String,
}

impl Default for HttpApiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: default_http_bind(),
        }
    }
}

fn default_http_bind() -> String {
    "127.0.0.1:8765".to_string()
}

// ============================================================================
// Firewall Config
// ============================================================================

/// Настройки блокировки IP-адресов фаерволом.
///
/// Пример в config.yaml:
/// ```yaml
/// firewall:
///   enabled: true
///   block_script: "/etc/panicmode/scripts/block_ip.sh"
///   unblock_script: "/etc/panicmode/scripts/unblock_ip.sh"
///   restore_on_startup: true
///   ctl_socket: "/run/panicmode/ctl.sock"
/// ```
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FirewallConfig {
    /// Включить блокировку IP. Если false — action block_ip игнорируется.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Скрипт для блокировки IP: вызывается как `block_ip.sh <IP>`.
    /// Переменная окружения PANICMODE_BLOCK_IP_SCRIPT перекрывает это значение.
    #[serde(default = "default_block_script")]
    pub block_script: String,

    /// Скрипт для снятия блокировки: вызывается как `unblock_ip.sh <IP>`.
    /// Переменная окружения PANICMODE_UNBLOCK_IP_SCRIPT перекрывает это значение.
    #[serde(default = "default_unblock_script")]
    pub unblock_script: String,

    /// Восстанавливать заблокированные IP из БД при старте демона.
    /// Необходимо для выживания блоков после перезагрузки сервера.
    #[serde(default = "default_true")]
    pub restore_on_startup: bool,

    /// Путь к Unix-сокету для CLI-утилиты panicmode-ctl.
    #[serde(default = "default_ctl_socket")]
    pub ctl_socket: String,

    /// IP-адреса и подсети, которые НИКОГДА не будут заблокированы.
    /// Поддерживаются точные IP ("1.2.3.4") и CIDR ("1.2.3.0/24", "2001:db8::/32").
    /// RFC1918 и loopback защищены всегда — вне зависимости от этого списка.
    #[serde(default)]
    pub whitelist: Vec<String>,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            block_script: default_block_script(),
            unblock_script: default_unblock_script(),
            restore_on_startup: true,
            ctl_socket: default_ctl_socket(),
            whitelist: Vec::new(),
        }
    }
}

fn default_block_script() -> String {
    "/etc/panicmode/scripts/block_ip.sh".to_string()
}

fn default_unblock_script() -> String {
    "/etc/panicmode/scripts/unblock_ip.sh".to_string()
}

fn default_ctl_socket() -> String {
    "/run/panicmode/ctl.sock".to_string()
}

// ============================================================================
// Monitor Type
// ============================================================================

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MonitorType {
    CpuUsage,
    MemoryUsage,
    DiskUsage,
    ConnectionRate,
    AuthFailures,
    FileMonitor,
    ProcessCount,
    Custom,
    SwapUsage,
    LoadAverage,
    DiskIo,
}

// ============================================================================
// Monitor Rules
// ============================================================================

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MonitorRule {
    pub name: String,

    #[serde(rename = "type")]
    pub monitor_type: MonitorType,

    pub threshold: f64,

    #[serde(default, with = "optional_humantime_serde")]
    pub window: Option<Duration>,

    #[serde(default, with = "optional_humantime_serde")]
    pub duration: Option<Duration>,

    #[serde(default)]
    pub paths: Vec<String>,

    #[serde(deserialize_with = "deserialize_actions")]
    pub actions: Vec<ActionType>,

    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn deserialize_actions<'de, D>(deserializer: D) -> Result<Vec<ActionType>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let strings: Vec<String> = Vec::deserialize(deserializer)?;

    let mut actions = Vec::new();
    let mut unknown = Vec::new();

    for s in &strings {
        match ActionType::parse(s) {
            Some(action) => actions.push(action),
            None => {
                unknown.push(s.clone());
            }
        }
    }

    if !unknown.is_empty() {
        eprintln!("⚠️  WARNING: Unknown action types will be ignored: {:?}", unknown);
    }

    if actions.is_empty() && !strings.is_empty() {
        return Err(serde::de::Error::custom(
            format!("All action types are unknown: {:?}", strings)
        ));
    }

    Ok(actions)
}

// ============================================================================
// Custom Metrics & File Monitor
// ============================================================================

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CustomMetricConfig {
    pub command: String,

    #[serde(with = "humantime_serde")]
    pub timeout: Duration,

    #[serde(default, with = "optional_humantime_serde")]
    pub cache_ttl: Option<Duration>,

    #[serde(default = "default_output_format")]
    pub output_format: String,
}

fn default_output_format() -> String {
    "number".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct FileMonitorConfig {
    #[serde(default = "default_max_events")]
    pub max_events_per_path: usize,

    #[serde(default, with = "optional_humantime_serde")]
    pub aggregation_window: Option<Duration>,
}

fn default_max_events() -> usize {
    1000
}

fn default_true() -> bool {
    true
}

// ============================================================================
// Circuit Breaker Config
// ============================================================================

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CircuitBreakerConfig {
    #[serde(default = "default_max_failures")]
    pub max_failures: u32,

    #[serde(default = "default_failure_window", with = "humantime_serde")]
    pub failure_window: Duration,

    #[serde(default = "default_open_duration", with = "humantime_serde")]
    pub open_duration: Duration,

    #[serde(default = "default_max_concurrency")]
    pub max_concurrency: usize,

    #[serde(default = "default_cb_timeout", with = "humantime_serde")]
    pub timeout: Duration,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            max_failures: default_max_failures(),
            failure_window: default_failure_window(),
            open_duration: default_open_duration(),
            max_concurrency: default_max_concurrency(),
            timeout: default_cb_timeout(),
        }
    }
}

fn default_max_failures() -> u32 { 5 }
fn default_failure_window() -> Duration { Duration::from_secs(60) }
fn default_open_duration() -> Duration { Duration::from_secs(30) }
fn default_max_concurrency() -> usize { 5 }
fn default_cb_timeout() -> Duration { Duration::from_secs(10) }

// ============================================================================
// Action Config
// ============================================================================

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ActionConfig {
    #[serde(rename = "type")]
    pub action_type: OldActionType,

    #[serde(default)]
    pub action: String,

    #[serde(default, with = "optional_humantime_serde")]
    pub duration: Option<Duration>,

    #[serde(default)]
    pub rate: Option<String>,

    #[serde(default)]
    pub capture: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OldActionType {
    Firewall,
    Process,
    System,
    Script,
}

// ============================================================================
// Alerts Config
// ============================================================================

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AlertsConfig {
    #[serde(default)]
    pub critical: Vec<AlertChannel>,

    #[serde(default)]
    pub warning: Vec<AlertChannel>,

    #[serde(default)]
    pub info: Vec<AlertChannel>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AlertChannel {
    pub channel: ChannelType,

    #[serde(default)]
    pub contacts: Vec<Contact>,

    #[serde(default)]
    pub chat_id: Option<String>,

    #[serde(default)]
    pub topic: Option<String>,

    #[serde(default)]
    pub webhook_url: Option<String>,

    #[serde(default)]
    pub email: Option<String>,

    #[serde(default = "default_retries")]
    pub retries: u32,

    #[serde(default = "default_timeout", with = "optional_humantime_serde")]
    pub timeout: Option<Duration>,
}

fn default_retries() -> u32 {
    3
}

fn default_timeout() -> Option<Duration> {
    Some(Duration::from_secs(10))
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Contact {
    pub name: String,
    pub phone: String,

    #[serde(default = "default_retries")]
    pub retries: u32,

    #[serde(default = "default_contact_timeout", with = "humantime_serde")]
    pub timeout: Duration,
}

fn default_contact_timeout() -> Duration {
    Duration::from_secs(120)
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChannelType {
    Telegram,
    Discord,
    Ntfy,
    Email,
    Webhook,
    #[serde(rename = "twilio_call")]
    TwilioCall,
    #[serde(rename = "twilio_sms")]
    TwilioSms,
}

// ============================================================================
// Integrations
// ============================================================================

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IntegrationsConfig {
    #[serde(default)]
    pub telegram: Option<TelegramConfig>,

    #[serde(default)]
    pub discord: Option<DiscordConfig>,

    #[serde(default)]
    pub ntfy: Option<NtfyConfig>,

    #[serde(default)]
    pub email: Option<EmailConfig>,

    #[serde(default)]
    pub twilio: Option<TwilioConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TelegramConfig {
    pub enabled: bool,
    pub bot_token: String,
    pub chat_id: String,
    /// Override the Telegram Bot API base URL (default: https://api.telegram.org).
    /// Useful for self-hosted Bot API servers and for testing with a mock server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_base_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DiscordConfig {
    pub enabled: bool,
    pub webhook_url: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NtfyConfig {
    pub enabled: bool,

    #[serde(default = "default_ntfy_server")]
    pub server: String,

    pub topic: String,

    #[serde(default)]
    pub token: Option<String>,
}

fn default_ntfy_server() -> String {
    "https://ntfy.sh".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EmailConfig {
    pub enabled: bool,
    pub smtp_host: String,
    pub smtp_port: u16,

    #[serde(default)]
    pub smtp_username: Option<String>,

    #[serde(default)]
    pub smtp_password: Option<String>,

    pub from_email: String,
    pub to_email: String,

    #[serde(default = "default_true")]
    pub use_tls: bool,
}

/// Twilio используется для звонков и SMS через REST API.
/// Номера телефонов вводятся пользователем в секции alerts.critical[].contacts[].phone
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TwilioConfig {
    pub enabled: bool,
    pub account_sid: String,
    pub auth_token: String,
    pub from_number: String,
}

// ============================================================================
// Config Implementation
// ============================================================================

impl Config {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let contents = std::fs::read_to_string(path.as_ref())
            .context("Failed to read config file")?;

        let config: Config = serde_yaml::from_str(&contents)
            .context("Failed to parse config YAML")?;

        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.performance.cpu_limit <= 0.0 || self.performance.cpu_limit > 100.0 {
            anyhow::bail!("cpu_limit must be between 0 and 100");
        }

        if self.performance.memory_limit_mb == 0 {
            anyhow::bail!("memory_limit_mb must be greater than 0");
        }

        if self.performance.check_interval.as_secs() == 0 {
            anyhow::bail!("check_interval must be greater than 0");
        }

        for monitor in &self.monitors {
            if monitor.name.is_empty() {
                anyhow::bail!("Monitor rule must have a name");
            }

            if monitor.threshold < 0.0 {
                anyhow::bail!("Monitor '{}': threshold must be >= 0", monitor.name);
            }

            if monitor.actions.is_empty() {
                anyhow::bail!("Monitor '{}': must have at least one action", monitor.name);
            }

            if monitor.monitor_type == MonitorType::FileMonitor && monitor.paths.is_empty() {
                anyhow::bail!("Monitor '{}': file_monitor requires paths", monitor.name);
            }
        }

        if self.alerts.critical.is_empty()
            && self.alerts.warning.is_empty()
            && self.alerts.info.is_empty()
        {
            anyhow::bail!("At least one alert channel must be configured");
        }

        self.validate_alert_integrations(&self.alerts.critical)?;
        self.validate_alert_integrations(&self.alerts.warning)?;
        self.validate_alert_integrations(&self.alerts.info)?;

        Ok(())
    }

    fn validate_alert_integrations(&self, channels: &[AlertChannel]) -> Result<()> {
        for channel in channels {
            match channel.channel {
                ChannelType::Telegram => {
                    // Disabled is allowed — channel will be skipped at runtime.
                    // Only validate credentials when the integration is actually enabled.
                    if let Some(tg) = &self.integrations.telegram {
                        if tg.enabled && (tg.bot_token.is_empty() || tg.chat_id.is_empty()) {
                            anyhow::bail!(
                                "Telegram integration is enabled but missing bot_token or chat_id"
                            );
                        }
                    }
                }
                ChannelType::Discord => {
                    if channel.webhook_url.is_none() {
                        anyhow::bail!("Discord channel requires webhook_url");
                    }
                }
                ChannelType::Ntfy => {
                    if let Some(ntfy) = &self.integrations.ntfy {
                        if ntfy.enabled && ntfy.topic.is_empty() {
                            anyhow::bail!("Ntfy integration is enabled but missing topic");
                        }
                    }
                }
                ChannelType::Email => {
                    // No mandatory credential fields to validate beyond presence of the section.
                }
                ChannelType::TwilioCall | ChannelType::TwilioSms => {
                    if let Some(twilio) = &self.integrations.twilio {
                        if twilio.enabled
                            && (twilio.account_sid.is_empty()
                                || twilio.auth_token.is_empty()
                                || twilio.from_number.is_empty())
                        {
                            anyhow::bail!(
                                "Twilio integration is enabled but missing \
                                 account_sid, auth_token, or from_number"
                            );
                        }
                    }
                }
                ChannelType::Webhook => {
                    if channel.webhook_url.is_none() {
                        anyhow::bail!("Webhook channel requires webhook_url");
                    }
                }
            }
        }
        Ok(())
    }
}

// ============================================================================
// Humantime serde helpers
// Поддерживает составные форматы: "1h30m", "5m30s", "500ms", "1d12h"
// ============================================================================

mod humantime_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{}s", duration.as_secs()))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        super::parse_duration(&s).map_err(serde::de::Error::custom)
    }
}

mod optional_humantime_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Option<Duration>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match duration {
            Some(d) => serializer.serialize_str(&format!("{}s", d.as_secs())),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: Option<String> = Option::deserialize(deserializer)?;
        match s {
            Some(s) => super::parse_duration(&s)
                .map(Some)
                .map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}

/// Парсит строку вида "5s", "10m", "1h", "500ms", "1h30m", "1d12h30m15s".
///
/// Поддерживаемые единицы: d (дни), h (часы), m (минуты), s (секунды), ms (мс).
/// Составные форматы ("1h30m") накапливаются слева направо.
/// Голое число без суффикса = секунды.
pub fn parse_duration(s: &str) -> Result<Duration> {
    let s = s.trim();
    if s.is_empty() {
        anyhow::bail!("Empty duration string");
    }

    let bytes = s.as_bytes();
    let mut total_ms: u64 = 0;
    let mut i = 0;
    let mut parsed_any = false;

    while i < bytes.len() {
        // Парсим число
        let num_start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        if i == num_start {
            anyhow::bail!("Expected digit at position {} in '{}'", i, s);
        }
        let num: u64 = s[num_start..i].parse()?;
        parsed_any = true;

        if i >= bytes.len() {
            // Голое число без суффикса = секунды
            total_ms = total_ms.saturating_add(num.saturating_mul(1_000));
            break;
        }

        // Парсим единицу (ms должен проверяться раньше m!)
        if i + 1 < bytes.len() && bytes[i] == b'm' && bytes[i + 1] == b's' {
            total_ms = total_ms.saturating_add(num);
            i += 2;
        } else if bytes[i] == b's' {
            total_ms = total_ms.saturating_add(num.saturating_mul(1_000));
            i += 1;
        } else if bytes[i] == b'm' {
            total_ms = total_ms.saturating_add(num.saturating_mul(60_000));
            i += 1;
        } else if bytes[i] == b'h' {
            total_ms = total_ms.saturating_add(num.saturating_mul(3_600_000));
            i += 1;
        } else if bytes[i] == b'd' {
            total_ms = total_ms.saturating_add(num.saturating_mul(86_400_000));
            i += 1;
        } else {
            anyhow::bail!(
                "Unknown unit '{}' at position {} in '{}'",
                bytes[i] as char,
                i,
                s
            );
        }
    }

    if !parsed_any {
        anyhow::bail!("No duration value found in '{}'", s);
    }

    Ok(Duration::from_millis(total_ms))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_duration_simple() {
        assert_eq!(parse_duration("5s").unwrap(), Duration::from_secs(5));
        assert_eq!(parse_duration("10m").unwrap(), Duration::from_secs(600));
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_duration("30").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("1d").unwrap(), Duration::from_secs(86400));
    }

    #[test]
    fn test_parse_duration_compound() {
        assert_eq!(parse_duration("1h30m").unwrap(), Duration::from_secs(5400));
        assert_eq!(parse_duration("5m30s").unwrap(), Duration::from_secs(330));
        assert_eq!(parse_duration("1h30m15s").unwrap(), Duration::from_secs(5415));
        assert_eq!(parse_duration("1d12h").unwrap(), Duration::from_secs(129600));
        assert_eq!(parse_duration("1m500ms").unwrap(), Duration::from_millis(60_500));
    }

    #[test]
    fn test_parse_duration_errors() {
        assert!(parse_duration("").is_err());
        assert!(parse_duration("5x").is_err());
        assert!(parse_duration("abc").is_err());
    }
}

// ============================================================================
// Mass Freeze Config (отдельный файл: mass_freeze.yaml)
// ============================================================================

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MassFreezeConfig {
    #[serde(default)]
    pub top_cpu: TopCpuConfig,

    #[serde(default)]
    pub clusters: HashMap<String, Vec<String>>,

    #[serde(default)]
    pub whitelist: Vec<String>,

    #[serde(default, with = "optional_humantime_serde")]
    pub freeze_timeout: Option<Duration>,

    #[serde(default)]
    pub max_processes_to_freeze: Option<usize>,

    #[serde(default)]
    pub dry_run: bool,
}

impl Default for MassFreezeConfig {
    fn default() -> Self {
        Self {
            top_cpu: TopCpuConfig::default(),
            clusters: HashMap::new(),
            whitelist: vec![
                "sshd".to_string(),
                "panicmode".to_string(),
            ],
            freeze_timeout: Some(Duration::from_secs(30)),
            max_processes_to_freeze: Some(1000),
            dry_run: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TopCpuConfig {
    #[serde(default = "default_top_count")]
    pub count: usize,
}

impl Default for TopCpuConfig {
    fn default() -> Self {
        Self { count: 5 }
    }
}

fn default_top_count() -> usize {
    5
}

impl MassFreezeConfig {
    /// Загрузить mass_freeze.yaml с fallback на defaults.
    ///
    /// Приоритет:
    /// 1. Env: PANICMODE_MASS_FREEZE_CONFIG
    /// 2. Рядом с основным конфигом: {config_dir}/mass_freeze.yaml
    /// 3. Системный: /etc/panicmode/mass_freeze.yaml
    /// 4. Hardcoded defaults (с warning)
    pub fn load_from_path_or_default<P: AsRef<Path>>(config_dir: P) -> Result<Self> {
        if let Ok(path) = std::env::var("PANICMODE_MASS_FREEZE_CONFIG") {
            return Self::load(&path);
        }

        let beside_main = config_dir.as_ref().join("mass_freeze.yaml");
        if beside_main.exists() {
            return Self::load(&beside_main);
        }

        let system_path = Path::new("/etc/panicmode/mass_freeze.yaml");
        if system_path.exists() {
            return Self::load(system_path);
        }

        tracing::warn!(
            "mass_freeze.yaml not found, using default configuration. \
             Recommended: create /etc/panicmode/mass_freeze.yaml"
        );
        Ok(Self::default())
    }

    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let contents = std::fs::read_to_string(path.as_ref())
            .context("Failed to read mass_freeze.yaml")?;

        let config: MassFreezeConfig = serde_yaml::from_str(&contents)
            .context("Failed to parse mass_freeze.yaml")?;

        config.validate()?;

        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.top_cpu.count == 0 {
            anyhow::bail!("top_cpu.count must be > 0");
        }

        for (name, processes) in &self.clusters {
            if processes.is_empty() {
                anyhow::bail!("Cluster '{}' has no processes defined", name);
            }
        }

        if !self.whitelist.iter().any(|w| w.contains("sshd")) {
            tracing::error!(
                "⚠️  CRITICAL: 'sshd' is NOT in whitelist! \
                 You may lose remote access during mass freeze."
            );
        }

        Ok(())
    }
}
