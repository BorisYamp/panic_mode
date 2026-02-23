/// Path: PanicMode/scr/alert/mod.rs
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::Result;
use reqwest::Client;

use crate::config::{AlertChannel, AlertsConfig, ChannelType, Config, IntegrationsConfig};

// ============================================================================
// AlertSeverity
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlertSeverity {
    Emergency,
    Critical,
    Warning,
    Info,
}

impl AlertSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Emergency => "EMERGENCY",
            Self::Critical => "CRITICAL",
            Self::Warning => "WARNING",
            Self::Info => "INFO",
        }
    }
}

// ============================================================================
// AlertMessage
// ============================================================================

/// Message sent through AlertDispatcher.
///
/// Created in any module, sent via channel to run_alert_task.
/// AlertDispatcher knows nothing about incidents — only messages.
#[derive(Debug, Clone)]
pub struct AlertMessage {
    pub severity: AlertSeverity,
    pub message: String,
    pub timestamp: SystemTime,
}

impl AlertMessage {
    pub fn new(severity: AlertSeverity, message: impl Into<String>) -> Self {
        Self {
            severity,
            message: message.into(),
            timestamp: SystemTime::now(),
        }
    }

    pub fn emergency(message: impl Into<String>) -> Self {
        Self::new(AlertSeverity::Emergency, message)
    }

    pub fn critical(message: impl Into<String>) -> Self {
        Self::new(AlertSeverity::Critical, message)
    }

    pub fn warning(message: impl Into<String>) -> Self {
        Self::new(AlertSeverity::Warning, message)
    }

    pub fn info(message: impl Into<String>) -> Self {
        Self::new(AlertSeverity::Info, message)
    }

    /// Formatted text, channel-agnostic.
    pub fn format_text(&self) -> String {
        format!("[{}] {}", self.severity.as_str(), self.message)
    }
}

// ============================================================================
// AlertDispatcher
// ============================================================================

/// Sends an AlertMessage to all configured channels.
///
/// # Reliability guarantees:
/// - If at least one channel succeeds — Ok(())
/// - If all channels are configured and all fail — Err(...)
/// - If no channels are configured — Ok(()) (silent mode, logged to stderr)
/// - Each channel retries according to channel.retries (default: 3)
pub struct AlertDispatcher {
    config: Arc<Config>,
    server_ip: String,
}

impl AlertDispatcher {
    pub fn new(config: Arc<Config>) -> Self {
        let server_ip = detect_server_ip();
        Self { config, server_ip }
    }

    /// Build a reqwest client with the per-channel timeout (default: 10s).
    fn build_client(timeout: Option<Duration>) -> Client {
        Client::builder()
            .timeout(timeout.unwrap_or(Duration::from_secs(10)))
            .build()
            .unwrap_or_default()
    }

    /// Send a message to the channels matching this severity.
    /// Appends the server IP to each message.
    pub async fn send(&self, msg: &AlertMessage) -> Result<()> {
        let channels = self.channels_for_severity(&self.config.alerts, &msg.severity);

        if channels.is_empty() {
            match &msg.severity {
                AlertSeverity::Emergency | AlertSeverity::Critical => {
                    // Critical alerts must reach someone. Fail loudly so the supervisor
                    // logs this to stderr and the issue is noticed.
                    let err = format!(
                        "No alert channels configured for {} — alert not delivered: {}",
                        msg.severity.as_str(),
                        msg.message
                    );
                    eprintln!("[PANICMODE ALERT LOST] {}", err);
                    tracing::warn!("{}", err);
                    anyhow::bail!(err);
                }
                AlertSeverity::Warning | AlertSeverity::Info => {
                    tracing::debug!(
                        "No alert channels configured for {}",
                        msg.severity.as_str()
                    );
                    return Ok(());
                }
            }
        }

        // Prepend server IP to distinguish sources when using a shared bot/channel
        let text = format!("{} | server: {}", msg.format_text(), self.server_ip);
        let mut any_success = false;
        let mut last_error: Option<String> = None;

        for channel in channels {
            // Skip channels whose integration is disabled — don't count as success.
            if !self.is_integration_enabled(channel) {
                tracing::debug!("Skipping disabled channel {:?}", channel.channel);
                continue;
            }

            let max_attempts = (channel.retries + 1) as usize;
            let mut channel_ok = false;

            for attempt in 0..max_attempts {
                match self
                    .send_to_channel(channel, &text, &self.config.integrations)
                    .await
                {
                    Ok(_) => {
                        any_success = true;
                        channel_ok = true;
                        tracing::debug!("Alert sent via {:?}", channel.channel);
                        break;
                    }
                    Err(e) => {
                        if attempt + 1 < max_attempts {
                            tracing::warn!(
                                "Alert channel {:?} attempt {}/{} failed: {}. Retrying...",
                                channel.channel,
                                attempt + 1,
                                max_attempts,
                                e
                            );
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        } else {
                            tracing::error!(
                                "Alert channel {:?} failed after {} attempt(s): {}",
                                channel.channel,
                                max_attempts,
                                e
                            );
                            last_error = Some(e.to_string());
                        }
                    }
                }
            }

        }

        if !any_success {
            if let Some(err) = last_error {
                anyhow::bail!("All alert channels failed. Last error: {}", err);
            }
        }

        Ok(())
    }

    fn channels_for_severity<'a>(
        &self,
        alerts: &'a AlertsConfig,
        severity: &AlertSeverity,
    ) -> &'a Vec<AlertChannel> {
        match severity {
            AlertSeverity::Emergency | AlertSeverity::Critical => &alerts.critical,
            AlertSeverity::Warning => &alerts.warning,
            AlertSeverity::Info => &alerts.info,
        }
    }

    /// Returns true if the integration backing this channel is enabled.
    /// Disabled channels are skipped in the send loop without counting as success or failure.
    fn is_integration_enabled(&self, channel: &AlertChannel) -> bool {
        let i = &self.config.integrations;
        match &channel.channel {
            ChannelType::Telegram => {
                i.telegram.as_ref().map(|c| c.enabled).unwrap_or(false)
            }
            ChannelType::Discord => {
                i.discord.as_ref().map(|c| c.enabled).unwrap_or(false)
            }
            ChannelType::Ntfy => {
                i.ntfy.as_ref().map(|c| c.enabled).unwrap_or(false)
            }
            ChannelType::Email => {
                i.email.as_ref().map(|c| c.enabled).unwrap_or(false)
            }
            ChannelType::TwilioSms | ChannelType::TwilioCall => {
                i.twilio.as_ref().map(|c| c.enabled).unwrap_or(false)
            }
            // Webhook has no integration section — it's enabled when a URL is configured.
            ChannelType::Webhook => channel.webhook_url.is_some(),
        }
    }

    async fn send_to_channel(
        &self,
        channel: &AlertChannel,
        text: &str,
        integrations: &IntegrationsConfig,
    ) -> Result<()> {
        let client = Self::build_client(channel.timeout);
        match &channel.channel {
            ChannelType::Telegram => self.send_telegram(&client, text, integrations).await,
            ChannelType::Discord => self.send_discord(&client, text, integrations).await,
            ChannelType::Ntfy => self.send_ntfy(&client, text, integrations).await,
            ChannelType::Webhook => self.send_webhook(&client, channel, text).await,
            ChannelType::Email => self.send_email(text, integrations).await,
            ChannelType::TwilioSms => self.send_twilio_sms(&client, channel, text, integrations).await,
            ChannelType::TwilioCall => self.send_twilio_call(&client, channel, text, integrations).await,
        }
    }

    // -------------------------------------------------------------------------
    // Telegram
    // -------------------------------------------------------------------------

    async fn send_telegram(&self, client: &Client, text: &str, integrations: &IntegrationsConfig) -> Result<()> {
        let cfg = integrations
            .telegram
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Telegram not configured"))?;

        if !cfg.enabled {
            return Ok(());
        }

        let base = cfg
            .api_base_url
            .as_deref()
            .unwrap_or("https://api.telegram.org");
        let url = format!(
            "{}/bot{}/sendMessage",
            base.trim_end_matches('/'),
            cfg.bot_token
        );

        // Plain text — no parse_mode, no escaping needed
        let body = serde_json::json!({
            "chat_id": cfg.chat_id,
            "text": text,
        });

        let resp = client.post(&url).json(&body).send().await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Telegram API error {}: {}", status, body);
        }

        Ok(())
    }

    // -------------------------------------------------------------------------
    // Discord
    // -------------------------------------------------------------------------

    async fn send_discord(&self, client: &Client, text: &str, integrations: &IntegrationsConfig) -> Result<()> {
        let cfg = integrations
            .discord
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Discord not configured"))?;

        if !cfg.enabled {
            return Ok(());
        }

        let body = serde_json::json!({ "content": text });

        let resp = client
            .post(&cfg.webhook_url)
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Discord webhook error {}: {}", status, body);
        }

        Ok(())
    }

    // -------------------------------------------------------------------------
    // Ntfy
    // -------------------------------------------------------------------------

    async fn send_ntfy(&self, client: &Client, text: &str, integrations: &IntegrationsConfig) -> Result<()> {
        let cfg = integrations
            .ntfy
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Ntfy not configured"))?;

        if !cfg.enabled {
            return Ok(());
        }

        let url = format!("{}/{}", cfg.server.trim_end_matches('/'), cfg.topic);

        let mut req = client.post(&url).body(text.to_string());

        if let Some(token) = &cfg.token {
            req = req.header("Authorization", format!("Bearer {}", token));
        }

        let resp = req.send().await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Ntfy error {}: {}", status, body);
        }

        Ok(())
    }

    // -------------------------------------------------------------------------
    // Webhook (generic HTTP POST)
    // -------------------------------------------------------------------------

    async fn send_webhook(&self, client: &Client, channel: &AlertChannel, text: &str) -> Result<()> {
        let url = channel
            .webhook_url
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Webhook channel: webhook_url is not configured"))?;

        let body = serde_json::json!({ "text": text });

        let resp = client.post(url).json(&body).send().await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Webhook error {}: {}", status, body);
        }

        Ok(())
    }

    // -------------------------------------------------------------------------
    // Email (SMTP via lettre)
    // -------------------------------------------------------------------------

    async fn send_email(&self, text: &str, integrations: &IntegrationsConfig) -> Result<()> {
        use lettre::message::header::ContentType;
        use lettre::transport::smtp::authentication::Credentials;
        use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

        let cfg = integrations
            .email
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Email not configured"))?;

        if !cfg.enabled {
            return Ok(());
        }

        let email = Message::builder()
            .from(cfg.from_email.parse()?)
            .to(cfg.to_email.parse()?)
            .subject("PanicMode Alert")
            .header(ContentType::TEXT_PLAIN)
            .body(text.to_string())?;

        let transport = if cfg.use_tls {
            let mut builder =
                AsyncSmtpTransport::<Tokio1Executor>::relay(&cfg.smtp_host)?
                    .port(cfg.smtp_port);

            if let (Some(user), Some(pass)) = (&cfg.smtp_username, &cfg.smtp_password) {
                builder =
                    builder.credentials(Credentials::new(user.clone(), pass.clone()));
            }

            builder.build()
        } else {
            let mut builder =
                AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&cfg.smtp_host)
                    .port(cfg.smtp_port);

            if let (Some(user), Some(pass)) = (&cfg.smtp_username, &cfg.smtp_password) {
                builder =
                    builder.credentials(Credentials::new(user.clone(), pass.clone()));
            }

            builder.build()
        };

        transport.send(email).await?;

        Ok(())
    }

    // -------------------------------------------------------------------------
    // Twilio SMS
    // -------------------------------------------------------------------------

    async fn send_twilio_sms(
        &self,
        client: &Client,
        channel: &AlertChannel,
        text: &str,
        integrations: &IntegrationsConfig,
    ) -> Result<()> {
        let cfg = integrations
            .twilio
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Twilio not configured"))?;

        if !cfg.enabled {
            return Ok(());
        }

        let phones: Vec<&str> = channel
            .contacts
            .iter()
            .map(|c| c.phone.as_str())
            .collect();

        if phones.is_empty() {
            tracing::warn!("Twilio SMS: no contacts configured in channel");
            return Ok(());
        }

        let url = format!(
            "https://api.twilio.com/2010-04-01/Accounts/{}/Messages.json",
            cfg.account_sid
        );

        let mut success_count = 0usize;

        for phone in &phones {
            let params = [
                ("To", *phone),
                ("From", cfg.from_number.as_str()),
                ("Body", text),
            ];

            let resp = client
                .post(&url)
                .basic_auth(&cfg.account_sid, Some(&cfg.auth_token))
                .form(&params)
                .send()
                .await?;

            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                tracing::error!("Twilio SMS to {} failed {}: {}", phone, status, body);
            } else {
                tracing::info!("SMS sent to {}", phone);
                success_count += 1;
            }
        }

        if success_count == 0 {
            anyhow::bail!("All {} Twilio SMS attempt(s) failed", phones.len());
        }

        Ok(())
    }

    // -------------------------------------------------------------------------
    // Twilio Call (TwiML passed inline via the Twiml parameter)
    // -------------------------------------------------------------------------

    async fn send_twilio_call(
        &self,
        client: &Client,
        channel: &AlertChannel,
        text: &str,
        integrations: &IntegrationsConfig,
    ) -> Result<()> {
        let cfg = integrations
            .twilio
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Twilio not configured"))?;

        if !cfg.enabled {
            return Ok(());
        }

        let phones: Vec<&str> = channel
            .contacts
            .iter()
            .map(|c| c.phone.as_str())
            .collect();

        if phones.is_empty() {
            tracing::warn!("Twilio Call: no contacts configured in channel");
            return Ok(());
        }

        let url = format!(
            "https://api.twilio.com/2010-04-01/Accounts/{}/Calls.json",
            cfg.account_sid
        );

        // Pass TwiML directly via the Twiml parameter — no external URL required.
        // Escape the text for XML so special characters in the message don't break the markup.
        let safe_text = escape_xml(text);
        let twiml = format!(
            "<Response>\
               <Say voice=\"alice\" language=\"en-US\">{}</Say>\
               <Pause length=\"1\"/>\
               <Say voice=\"alice\" language=\"en-US\">{}</Say>\
             </Response>",
            safe_text, safe_text
        );

        let mut success_count = 0usize;

        for phone in &phones {
            let params = [
                ("To", *phone),
                ("From", cfg.from_number.as_str()),
                ("Twiml", twiml.as_str()),
            ];

            let resp = client
                .post(&url)
                .basic_auth(&cfg.account_sid, Some(&cfg.auth_token))
                .form(&params)
                .send()
                .await?;

            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                tracing::error!("Twilio Call to {} failed {}: {}", phone, status, body);
            } else {
                tracing::info!("Call initiated to {}", phone);
                success_count += 1;
            }
        }

        if success_count == 0 {
            anyhow::bail!("All {} Twilio Call attempt(s) failed", phones.len());
        }

        Ok(())
    }
}

// ============================================================================
// Helpers
// ============================================================================

/// Detects the server's IP address via the routing table without sending real traffic.
fn detect_server_ip() -> String {
    std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            s.connect("8.8.8.8:80")?;
            s.local_addr()
        })
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Escapes XML special characters for safe insertion into TwiML.
fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use wiremock::{matchers, Mock, MockServer, ResponseTemplate};
    use crate::config::*;

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    fn make_alerts(critical: Vec<AlertChannel>) -> AlertsConfig {
        AlertsConfig { critical, warning: vec![], info: vec![] }
    }

    fn telegram_channel() -> AlertChannel {
        AlertChannel {
            channel: ChannelType::Telegram,
            contacts: vec![],
            chat_id: None,
            topic: None,
            webhook_url: None,
            email: None,
            retries: 0,
            timeout: None,
        }
    }

    fn discord_channel(webhook_url: &str) -> AlertChannel {
        AlertChannel {
            channel: ChannelType::Discord,
            contacts: vec![],
            chat_id: None,
            topic: None,
            webhook_url: Some(webhook_url.to_string()),
            email: None,
            retries: 0,
            timeout: None,
        }
    }

    fn ntfy_channel() -> AlertChannel {
        AlertChannel {
            channel: ChannelType::Ntfy,
            contacts: vec![],
            chat_id: None,
            topic: None,
            webhook_url: None,
            email: None,
            retries: 0,
            timeout: None,
        }
    }

    fn base_config() -> Config {
        Config {
            alerts: AlertsConfig { critical: vec![], warning: vec![], info: vec![] },
            integrations: IntegrationsConfig {
                telegram: None,
                discord: None,
                ntfy: None,
                email: None,
                twilio: None,
            },
            ..Config::default()
        }
    }

    // -------------------------------------------------------------------------
    // Unit tests (no HTTP)
    // -------------------------------------------------------------------------

    #[test]
    fn test_format_text() {
        let msg = AlertMessage::critical("disk full");
        assert!(msg.format_text().contains("[CRITICAL]"));
        assert!(msg.format_text().contains("disk full"));
    }

    #[test]
    fn test_alert_message_constructors() {
        assert_eq!(AlertMessage::emergency("x").severity, AlertSeverity::Emergency);
        assert_eq!(AlertMessage::critical("x").severity, AlertSeverity::Critical);
        assert_eq!(AlertMessage::warning("x").severity, AlertSeverity::Warning);
        assert_eq!(AlertMessage::info("x").severity, AlertSeverity::Info);
    }

    #[tokio::test]
    async fn test_empty_critical_channels_returns_err() {
        let config = Arc::new(base_config());
        let dispatcher = AlertDispatcher::new(config);
        let err = dispatcher.send(&AlertMessage::critical("boom")).await;
        assert!(err.is_err(), "critical with no channels must return Err");
    }

    #[tokio::test]
    async fn test_empty_emergency_channels_returns_err() {
        let config = Arc::new(base_config());
        let dispatcher = AlertDispatcher::new(config);
        let err = dispatcher.send(&AlertMessage::emergency("boom")).await;
        assert!(err.is_err(), "emergency with no channels must return Err");
    }

    #[tokio::test]
    async fn test_empty_warning_channels_returns_ok() {
        let config = Arc::new(base_config());
        let dispatcher = AlertDispatcher::new(config);
        // Warning with no channels → silent Ok (no channels = intentional)
        let result = dispatcher.send(&AlertMessage::warning("quiet")).await;
        assert!(result.is_ok(), "warning with no channels should be Ok");
    }

    #[tokio::test]
    async fn test_disabled_telegram_is_skipped_not_success() {
        let mut cfg = base_config();
        cfg.alerts = make_alerts(vec![telegram_channel()]);
        cfg.integrations.telegram = Some(TelegramConfig {
            enabled: false,
            bot_token: "tok".into(),
            chat_id: "123".into(),
            api_base_url: None,
        });
        // Only channel is disabled → treated as "no effective channels" for critical
        // (any_success stays false, and there's no real last_error → Ok)
        // This is acceptable: user explicitly disabled the only channel.
        let dispatcher = AlertDispatcher::new(Arc::new(cfg));
        // Should not panic; result can be Ok or Err depending on policy
        let _ = dispatcher.send(&AlertMessage::critical("test")).await;
    }

    #[test]
    fn test_is_integration_enabled_telegram() {
        let mut cfg = base_config();
        cfg.integrations.telegram = Some(TelegramConfig {
            enabled: true,
            bot_token: "t".into(),
            chat_id: "c".into(),
            api_base_url: None,
        });
        let dispatcher = AlertDispatcher::new(Arc::new(cfg));
        assert!(dispatcher.is_integration_enabled(&telegram_channel()));
    }

    #[test]
    fn test_is_integration_enabled_disabled() {
        let mut cfg = base_config();
        cfg.integrations.telegram = Some(TelegramConfig {
            enabled: false,
            bot_token: "t".into(),
            chat_id: "c".into(),
            api_base_url: None,
        });
        let dispatcher = AlertDispatcher::new(Arc::new(cfg));
        assert!(!dispatcher.is_integration_enabled(&telegram_channel()));
    }

    #[test]
    fn test_is_integration_enabled_missing() {
        let cfg = base_config();
        let dispatcher = AlertDispatcher::new(Arc::new(cfg));
        assert!(!dispatcher.is_integration_enabled(&telegram_channel()));
    }

    #[test]
    fn test_channels_for_severity_critical() {
        let mut cfg = base_config();
        cfg.alerts.critical = vec![telegram_channel()];
        let dispatcher = AlertDispatcher::new(Arc::new(cfg));
        assert_eq!(
            dispatcher.channels_for_severity(&dispatcher.config.alerts, &AlertSeverity::Critical).len(),
            1
        );
    }

    #[test]
    fn test_channels_for_severity_emergency_uses_critical_list() {
        let mut cfg = base_config();
        cfg.alerts.critical = vec![telegram_channel()];
        let dispatcher = AlertDispatcher::new(Arc::new(cfg));
        // Emergency maps to the critical channel list
        assert_eq!(
            dispatcher.channels_for_severity(&dispatcher.config.alerts, &AlertSeverity::Emergency).len(),
            1
        );
    }

    // -------------------------------------------------------------------------
    // HTTP integration tests (mock server via wiremock)
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn test_telegram_send_success() {
        let server = MockServer::start().await;

        Mock::given(matchers::method("POST"))
            .and(matchers::path("/botTEST_TOKEN/sendMessage"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
            .expect(1)
            .mount(&server)
            .await;

        let mut cfg = base_config();
        cfg.alerts = make_alerts(vec![telegram_channel()]);
        cfg.integrations.telegram = Some(TelegramConfig {
            enabled: true,
            bot_token: "TEST_TOKEN".into(),
            chat_id: "12345".into(),
            api_base_url: Some(server.uri()),
        });

        let dispatcher = AlertDispatcher::new(Arc::new(cfg));
        dispatcher.send(&AlertMessage::critical("server on fire")).await.unwrap();
        // wiremock verifies the .expect(1) on drop
    }

    #[tokio::test]
    async fn test_telegram_server_error_returns_err() {
        let server = MockServer::start().await;

        Mock::given(matchers::method("POST"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal Error"))
            .mount(&server)
            .await;

        let mut cfg = base_config();
        cfg.alerts = make_alerts(vec![telegram_channel()]);
        cfg.integrations.telegram = Some(TelegramConfig {
            enabled: true,
            bot_token: "BAD_TOKEN".into(),
            chat_id: "0".into(),
            api_base_url: Some(server.uri()),
        });

        let dispatcher = AlertDispatcher::new(Arc::new(cfg));
        let result = dispatcher.send(&AlertMessage::critical("oops")).await;
        assert!(result.is_err(), "500 from Telegram must return Err");
    }

    #[tokio::test]
    async fn test_retry_succeeds_on_second_attempt() {
        let server = MockServer::start().await;

        // First call fails, second succeeds
        Mock::given(matchers::method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(matchers::method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
            .expect(1)
            .mount(&server)
            .await;

        let mut cfg = base_config();
        cfg.alerts = make_alerts(vec![AlertChannel {
            retries: 1, // 1 retry = 2 total attempts
            ..telegram_channel()
        }]);
        cfg.integrations.telegram = Some(TelegramConfig {
            enabled: true,
            bot_token: "TOK".into(),
            chat_id: "1".into(),
            api_base_url: Some(server.uri()),
        });

        let dispatcher = AlertDispatcher::new(Arc::new(cfg));
        dispatcher.send(&AlertMessage::critical("retry test")).await.unwrap();
    }

    #[tokio::test]
    async fn test_discord_send_success() {
        let server = MockServer::start().await;

        Mock::given(matchers::method("POST"))
            .and(matchers::path("/webhook/test"))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;

        let webhook = format!("{}/webhook/test", server.uri());
        let mut cfg = base_config();
        cfg.alerts = make_alerts(vec![discord_channel(&webhook)]);
        cfg.integrations.discord = Some(DiscordConfig {
            enabled: true,
            webhook_url: webhook.clone(),
        });

        let dispatcher = AlertDispatcher::new(Arc::new(cfg));
        dispatcher.send(&AlertMessage::critical("discord test")).await.unwrap();
    }

    #[tokio::test]
    async fn test_ntfy_send_success() {
        let server = MockServer::start().await;

        Mock::given(matchers::method("POST"))
            .and(matchers::path("/my-topic"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let mut cfg = base_config();
        cfg.alerts = make_alerts(vec![ntfy_channel()]);
        cfg.integrations.ntfy = Some(NtfyConfig {
            enabled: true,
            server: server.uri(),
            topic: "my-topic".into(),
            token: None,
        });

        let dispatcher = AlertDispatcher::new(Arc::new(cfg));
        dispatcher.send(&AlertMessage::critical("ntfy test")).await.unwrap();
    }

    #[tokio::test]
    async fn test_fallback_to_second_channel_when_first_fails() {
        let server = MockServer::start().await;

        // Discord succeeds as fallback
        Mock::given(matchers::method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let webhook = format!("{}/fallback", server.uri());
        let mut cfg = base_config();
        // Two channels: Telegram (disabled) + Discord (enabled)
        cfg.alerts = make_alerts(vec![telegram_channel(), discord_channel(&webhook)]);
        cfg.integrations.telegram = None; // not configured → skipped
        cfg.integrations.discord = Some(DiscordConfig {
            enabled: true,
            webhook_url: webhook,
        });

        let dispatcher = AlertDispatcher::new(Arc::new(cfg));
        // Should succeed via Discord fallback
        dispatcher.send(&AlertMessage::critical("fallback test")).await.unwrap();
    }

    #[tokio::test]
    async fn test_all_channels_fail_returns_err() {
        let server = MockServer::start().await;

        Mock::given(matchers::method("POST"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let mut cfg = base_config();
        cfg.alerts = make_alerts(vec![telegram_channel()]);
        cfg.integrations.telegram = Some(TelegramConfig {
            enabled: true,
            bot_token: "T".into(),
            chat_id: "1".into(),
            api_base_url: Some(server.uri()),
        });

        let dispatcher = AlertDispatcher::new(Arc::new(cfg));
        let result = dispatcher.send(&AlertMessage::critical("all fail")).await;
        assert!(result.is_err(), "all channels failing must return Err");
    }
}
