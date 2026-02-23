/// Path: PanicMode/src/ctl/mod.rs
///
/// Unix socket сервер для CLI-утилиты panicmode-ctl.
///
/// Протокол: newline-delimited JSON.
/// Запрос:  {"cmd":"list"}\n
///          {"cmd":"unblock","ip":"1.2.3.4"}\n
/// Ответ:   {"ok":true,"data":[...]}\n
///          {"ok":false,"error":"..."}\n
use std::sync::Arc;
use std::time::Duration;

use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio_util::sync::CancellationToken;

use crate::config::Config;
use crate::storage::{BlockedIp, IncidentStorage};

// ============================================================================
// Protocol types
// ============================================================================

#[derive(Debug, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
enum CtlRequest {
    List,
    Unblock { ip: String },
}

#[derive(Debug, Serialize)]
struct CtlResponse<T: Serialize> {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct BlockedIpEntry {
    ip: String,
    blocked_at: i64,
    reason: String,
}

impl From<BlockedIp> for BlockedIpEntry {
    fn from(b: BlockedIp) -> Self {
        Self { ip: b.ip, blocked_at: b.blocked_at, reason: b.reason }
    }
}

impl<T: Serialize> CtlResponse<T> {
    fn ok(data: T) -> Self {
        Self { ok: true, data: Some(data), error: None }
    }
}

fn error_response(msg: impl Into<String>) -> String {
    let r = CtlResponse::<()> { ok: false, data: None, error: Some(msg.into()) };
    serde_json::to_string(&r).unwrap_or_else(|_| r#"{"ok":false,"error":"serialization error"}"#.to_string())
}

// ============================================================================
// CtlServer
// ============================================================================

pub struct CtlServer {
    config: Arc<Config>,
    storage: Arc<IncidentStorage>,
}

impl CtlServer {
    pub fn new(config: Arc<Config>, storage: Arc<IncidentStorage>) -> Self {
        Self { config, storage }
    }

    pub async fn run(&self, cancel: CancellationToken) -> Result<()> {
        let socket_path = &self.config.firewall.ctl_socket;

        // Создаём директорию для сокета если её нет
        if let Some(parent) = std::path::Path::new(socket_path).parent() {
            let _ = tokio::fs::create_dir_all(parent).await;
        }

        // Удаляем старый сокет если остался после краша
        let _ = tokio::fs::remove_file(socket_path).await;

        let listener = UnixListener::bind(socket_path)
            .map_err(|e| anyhow::anyhow!("Cannot bind ctl socket {}: {}", socket_path, e))?;

        // Restrict socket to root/owner only — prevent local users from running ctl commands.
        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| anyhow::anyhow!("Cannot set permissions on ctl socket {}: {}", socket_path, e))?;

        tracing::info!("ctl: listening on {}", socket_path);

        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    tracing::info!("ctl: shutting down");
                    let _ = tokio::fs::remove_file(socket_path).await;
                    break;
                }
                accept = listener.accept() => {
                    let (stream, _) = match accept {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::warn!("ctl: accept error: {}", e);
                            continue;
                        }
                    };

                    let storage = self.storage.clone();
                    let unblock_script = std::env::var("PANICMODE_UNBLOCK_IP_SCRIPT")
                        .unwrap_or_else(|_| self.config.firewall.unblock_script.clone());

                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, storage, unblock_script).await {
                            tracing::warn!("ctl: connection error: {}", e);
                        }
                    });
                }
            }
        }

        Ok(())
    }
}

// ============================================================================
// Connection handler
// ============================================================================

async fn handle_connection(
    stream: tokio::net::UnixStream,
    storage: Arc<IncidentStorage>,
    unblock_script: String,
) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    // Одно соединение = одна команда (keep-alive не нужен)
    let response = if let Ok(Some(line)) = tokio::time::timeout(
        Duration::from_secs(5),
        lines.next_line(),
    ).await {
        dispatch(&line, &storage, &unblock_script).await
    } else {
        error_response("timeout or empty request")
    };

    writer.write_all(response.as_bytes()).await?;
    writer.write_all(b"\n").await?;

    Ok(())
}

// ============================================================================
// Command dispatcher
// ============================================================================

async fn dispatch(
    line: &str,
    storage: &Arc<IncidentStorage>,
    unblock_script: &str,
) -> String {
    let request: CtlRequest = match serde_json::from_str(line) {
        Ok(r) => r,
        Err(e) => return error_response(format!("invalid JSON: {}", e)),
    };

    match request {
        CtlRequest::List => handle_list(storage).await,
        CtlRequest::Unblock { ip } => handle_unblock(&ip, storage, unblock_script).await,
    }
}

async fn handle_list(storage: &Arc<IncidentStorage>) -> String {
    match storage.get_active_blocked_ips().await {
        Ok(ips) => {
            let entries: Vec<BlockedIpEntry> = ips.into_iter().map(Into::into).collect();
            serde_json::to_string(&CtlResponse::ok(entries))
                .unwrap_or_else(|e| error_response(e.to_string()))
        }
        Err(e) => error_response(format!("DB error: {}", e)),
    }
}

async fn handle_unblock(ip: &str, storage: &Arc<IncidentStorage>, unblock_script: &str) -> String {
    // Validate the IP before passing it to the external script.
    if ip.parse::<IpAddr>().is_err() {
        return error_response(format!("invalid IP address: {:?}", ip));
    }

    // Вызываем скрипт разблокировки
    let script_result = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::process::Command::new(unblock_script)
            .arg(ip)
            .status(),
    ).await;

    let script_ok = match script_result {
        Ok(Ok(status)) if status.success() => true,
        Ok(Ok(status)) => {
            tracing::warn!("ctl: unblock script exited with {} for {}", status, ip);
            false
        }
        Ok(Err(e)) => {
            return error_response(format!("failed to run unblock script: {}", e));
        }
        Err(_) => {
            return error_response("unblock script timed out");
        }
    };

    if !script_ok {
        return error_response(format!(
            "unblock script failed for {} (non-zero exit). Check {}",
            ip, unblock_script
        ));
    }

    // Помечаем IP как разблокированный в БД
    match storage.remove_blocked_ip(ip).await {
        Ok(()) => {
            tracing::info!("ctl: unblocked {}", ip);
            serde_json::to_string(&CtlResponse::ok(format!("unblocked {}", ip)))
                .unwrap_or_else(|e| error_response(e.to_string()))
        }
        Err(e) => {
            // Скрипт сработал, но в БД IP не нашли — предупреждаем, но не считаем ошибкой
            tracing::warn!("ctl: unblocked {} via script but not found in DB: {}", ip, e);
            serde_json::to_string(&CtlResponse::ok(
                format!("unblocked {} (not in DB: {})", ip, e)
            )).unwrap_or_else(|e2| error_response(e2.to_string()))
        }
    }
}
