/// Path: PanicMode/scr/main.rs
use anyhow::Result;
use tracing::{info, error, warn};
use std::sync::Arc;
use std::panic::AssertUnwindSafe;
use std::future::Future;
use tokio::sync::{mpsc, Mutex as TokioMutex};
use tokio::signal;
use tokio::time::{sleep, timeout, Duration};
use tokio_util::sync::CancellationToken;
use futures::FutureExt; // for catch_unwind
use tracing_subscriber::prelude::*;

mod config;
mod monitor;
mod detector;
mod action;
mod alert;
mod storage;
mod ctl;

use config::Config;
use storage::IncidentStorage;
use monitor::{MonitorEngine, Metrics};
use detector::{Detector, IncidentHandler};
use alert::{AlertDispatcher, AlertMessage};
use action::ActionExecutorBuilder;

// Constants
const ITERATION_TIMEOUT: Duration = Duration::from_secs(30);
const EMERGENCY_ALERT_DELAY: Duration = Duration::from_secs(2);
const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);
const SELF_CHECK_INTERVAL: Duration = Duration::from_secs(5);
const METRICS_QUEUE_SIZE: usize = 10;
const ALERT_QUEUE_SIZE: usize = 100;
const MAX_TASK_FAILURES: usize = 3;

#[tokio::main]
async fn main() -> Result<()> {
    // Config must be loaded first — we need log/storage paths before tracing init.
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/etc/panicmode/config.yaml".to_string());

    let config = Config::load(&config_path)?;
    config.validate()?;

    // Initialize logging: stdout + daily rolling file.
    let _ = std::fs::create_dir_all(&config.storage.log_dir);
    let file_appender = tracing_appender::rolling::daily(&config.storage.log_dir, "panicmode.log");
    let (non_blocking_file, _log_guard) = tracing_appender::non_blocking(file_appender);

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("panicmode=info"));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer())
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(non_blocking_file)
                .with_ansi(false),
        )
        .init();

    info!("PanicMode starting...");
    info!("Configuration loaded from {}", config_path);
    info!("Logs: {}", config.storage.log_dir);

    // Incident storage (SQLite). Fall back to in-memory if the DB path fails
    // (e.g. permissions) so monitoring still works.
    let incident_storage = match IncidentStorage::new(&config.storage.incident_db) {
        Ok(s) => {
            info!("Incident DB: {}", config.storage.incident_db);
            Arc::new(s)
        }
        Err(e) => {
            warn!("Cannot open incident DB ({}): {}. Falling back to in-memory.", config.storage.incident_db, e);
            Arc::new(IncidentStorage::new_in_memory()?)
        }
    };

    let config = Arc::new(config);

    // Shared cancellation token
    let cancel_token = CancellationToken::new();

    // Communication channels
    let (metrics_tx, metrics_rx) = mpsc::channel::<Metrics>(METRICS_QUEUE_SIZE);
    let metrics_rx = Arc::new(TokioMutex::new(metrics_rx));
    let (alert_tx, alert_rx) = mpsc::channel::<AlertMessage>(ALERT_QUEUE_SIZE);
    let alert_rx = Arc::new(TokioMutex::new(alert_rx));

    // Spawn Ctrl+C handler
    let cancel_token_ctrl_c = cancel_token.clone();
    tokio::spawn(async move {
        signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");
        info!("Received shutdown signal");
        cancel_token_ctrl_c.cancel();
    });

    // Initialize components (Arc for MonitorEngine!)
    let monitor = Arc::new(MonitorEngine::new(config.clone())?);
    let detector = Arc::new(Detector::new(config.clone(), monitor.clone()));
    let alert_dispatcher = Arc::new(AlertDispatcher::new(config.clone()));

    // Восстанавливаем заблокированные IP после перезагрузки сервера
    if config.firewall.restore_on_startup {
        restore_blocked_ips(&config, &incident_storage).await;
    }

    // Build ActionExecutor via builder (fail-fast if nothing is registered)
    let action_executor = Arc::new(
        ActionExecutorBuilder::new(config.clone())
            .with_firewall(incident_storage.clone())
            .with_process()
            .with_snapshot()
            .with_script()
            .build()?,
    );

    info!("All components initialized");

    // IncidentHandler: orchestrator for incident processing.
    // Receives ActionExecutor, alert_tx and IncidentStorage.
    let incident_handler = Arc::new(
        IncidentHandler::new(config.clone(), action_executor.clone(), alert_tx.clone(), incident_storage.clone())
    );

    // Spawn tasks with supervision
    let monitoring_task = {
        let cancel = cancel_token.clone();
        let alert_tx = alert_tx.clone();
        let monitor = monitor.clone();
        let metrics_tx = metrics_tx.clone();
        tokio::spawn(async move {
            let cancel_c = cancel.clone();
            let alert_tx_c = alert_tx.clone();
            supervise_task(
                "monitoring",
                move || run_monitoring_task(monitor.clone(), cancel_c.clone(), metrics_tx.clone(), alert_tx_c.clone()),
                cancel,
                alert_tx,
            ).await
        })
    };

    let detector_task = {
        let cancel = cancel_token.clone();
        let alert_tx = alert_tx.clone();
        let detector = detector.clone();
        let incident_handler = incident_handler.clone();
        tokio::spawn(async move {
            let cancel_c = cancel.clone();
            let alert_tx_c = alert_tx.clone();
            supervise_task(
                "detector",
                move || run_detector_task(
                    detector.clone(),
                    incident_handler.clone(),
                    cancel_c.clone(),
                    metrics_rx.clone(),
                    alert_tx_c.clone(),
                ),
                cancel,
                alert_tx,
            ).await
        })
    };

    let alert_task = {
        let cancel = cancel_token.clone();
        let alert_tx_clone = alert_tx.clone();
        let alert_dispatcher = alert_dispatcher.clone();
        tokio::spawn(async move {
            let cancel_c = cancel.clone();
            supervise_task(
                "alert",
                move || run_alert_task(alert_dispatcher.clone(), alert_rx.clone(), cancel_c.clone()),
                cancel,
                alert_tx_clone,
            ).await
        })
    };

    let self_check_task = {
        let cancel = cancel_token.clone();
        let config = config.clone();
        let alert_tx = alert_tx.clone();
        tokio::spawn(async move {
            let cancel_c = cancel.clone();
            let alert_tx_c = alert_tx.clone();
            supervise_task(
                "self-check",
                move || run_self_check_task(config.clone(), cancel_c.clone(), alert_tx_c.clone()),
                cancel,
                alert_tx,
            ).await
        })
    };

    let http_api_task = {
        let cancel = cancel_token.clone();
        let config = config.clone();
        let alert_tx = alert_tx.clone();
        tokio::spawn(async move {
            if !config.http_api.enabled {
                // HTTP API disabled — wait quietly for shutdown
                cancel.cancelled().await;
                return Ok(());
            }
            let cancel_c = cancel.clone();
            supervise_task(
                "http-api",
                move || run_http_api_task(config.clone(), cancel_c.clone()),
                cancel,
                alert_tx,
            ).await
        })
    };

    // ctl is auxiliary — its failure must NOT bring down core monitoring.
    let ctl_task_handle = {
        let cancel = cancel_token.clone();
        let config = config.clone();
        let storage = incident_storage.clone();
        let alert_tx = alert_tx.clone();
        tokio::spawn(async move {
            if !config.firewall.enabled {
                cancel.cancelled().await;
                return;
            }
            let server = ctl::CtlServer::new(config.clone(), storage);
            let cancel_c = cancel.clone();
            if let Err(e) = supervise_task(
                "ctl",
                move || server.run(cancel_c.clone()),
                cancel,
                alert_tx,
            ).await {
                error!("ctl server permanently failed (panicmode-ctl will be unavailable): {}", e);
            }
        })
    };

    let task_count = if config.http_api.enabled { 5 } else { 4 };
    info!("PanicMode is now active with {} supervised tasks (+ctl auxiliary)", task_count);

    // FAIL-FAST: if any critical task terminates, begin graceful shutdown
    // (use named variables — Vec indexing causes multiple &mut borrow errors)
    tokio::select! {
        result = &mut monitoring_task => {
            error!("Monitoring task terminated: {:?}", result);
            cancel_token.cancel();
        }
        result = &mut detector_task => {
            error!("Detector task terminated: {:?}", result);
            cancel_token.cancel();
        }
        result = &mut alert_task => {
            error!("Alert task terminated: {:?}", result);
            cancel_token.cancel();
        }
        result = &mut self_check_task => {
            error!("Self-check task terminated: {:?}", result);
            cancel_token.cancel();
        }
        result = &mut http_api_task => {
            error!("HTTP API task terminated: {:?}", result);
            cancel_token.cancel();
        }
    }

    // Graceful shutdown: wait for remaining tasks
    info!("Waiting for tasks to complete gracefully...");

    let tasks = [
        ("monitoring", monitoring_task),
        ("detector",   detector_task),
        ("alert",      alert_task),
        ("self-check", self_check_task),
        ("http-api",   http_api_task),
    ];

    for (name, task) in tasks {
        match timeout(GRACEFUL_SHUTDOWN_TIMEOUT, task).await {
            Ok(Ok(_)) => info!("Task '{}' completed", name),
            Ok(Err(e)) => error!("Task '{}' panicked during shutdown: {}", name, e),
            Err(_) => {
                error!("Task '{}' did not complete within timeout", name);
            }
        }
    }

    // Also wait for auxiliary ctl task
    match timeout(GRACEFUL_SHUTDOWN_TIMEOUT, ctl_task_handle).await {
        Ok(_) => info!("Task 'ctl' completed"),
        Err(_) => error!("Task 'ctl' did not complete within timeout"),
    }

    // Extra delay for final alerts
    sleep(EMERGENCY_ALERT_DELAY).await;

    info!("PanicMode shut down");
    Ok(())
}

// ============================================================================
// Task Supervision - restarts task on failure with backoff
// ============================================================================
async fn supervise_task<F, Fut>(
    name: &str,
    task_fn: F,
    cancel: CancellationToken,
    alert_tx: mpsc::Sender<AlertMessage>,
) -> Result<()>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<()>>,
{
    let mut failure_count = 0;
    let mut backoff = Duration::from_secs(1);
    let max_backoff = Duration::from_secs(60);

    loop {
        if cancel.is_cancelled() {
            info!("Task '{}' received cancellation", name);
            break;
        }

        info!("Starting task '{}'", name);
        
        // Wrap task in panic catcher
        let result = AssertUnwindSafe(task_fn())
            .catch_unwind()
            .await;

        match result {
            Ok(Ok(_)) => {
                info!("Task '{}' completed successfully", name);
                failure_count = 0;
                backoff = Duration::from_secs(1);
            }
            Ok(Err(e)) => {
                failure_count += 1;
                error!("Task '{}' failed (attempt {}): {}", name, failure_count, e);

                // Try to send emergency alert (non-blocking!)
                send_alert_with_fallback(
                    &alert_tx,
                    AlertMessage::emergency(
                        format!("Task '{}' failed {} times: {}", name, failure_count, e)
                    ),
                ).await;

                if failure_count >= MAX_TASK_FAILURES {
                    error!("Task '{}' failed {} times, giving up", name, MAX_TASK_FAILURES);
                    return Err(anyhow::anyhow!(
                        "Task '{}' exceeded max failures", name
                    ));
                }

                // Exponential backoff with cancellation check
                warn!("Task '{}' will restart in {:?}", name, backoff);
                if sleep_with_cancel(backoff, &cancel).await {
                    info!("Task '{}' restart cancelled", name);
                    break;
                }
                backoff = std::cmp::min(backoff * 2, max_backoff);
            }
            Err(panic_payload) => {
                failure_count += 1;
                let panic_msg = if let Some(s) = panic_payload.downcast_ref::<&str>() {
                    s.to_string()
                } else if let Some(s) = panic_payload.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "Unknown panic".to_string()
                };
                
                error!("Task '{}' PANICKED (attempt {}): {}", name, failure_count, panic_msg);

                send_alert_with_fallback(
                    &alert_tx,
                    AlertMessage::emergency(
                        format!("Task '{}' PANICKED: {}", name, panic_msg)
                    ),
                ).await;

                if failure_count >= MAX_TASK_FAILURES {
                    error!("Task '{}' panicked {} times, giving up", name, MAX_TASK_FAILURES);
                    return Err(anyhow::anyhow!(
                        "Task '{}' panicked too many times", name
                    ));
                }

                warn!("Task '{}' will restart after panic in {:?}", name, backoff);
                if sleep_with_cancel(backoff, &cancel).await {
                    break;
                }
                backoff = std::cmp::min(backoff * 2, max_backoff);
            }
        }
    }

    Ok(())
}

// ============================================================================
// Alert with fallback - NEVER silently lose critical alerts!
// ============================================================================
async fn send_alert_with_fallback(
    alert_tx: &mpsc::Sender<AlertMessage>,
    alert: AlertMessage,
) {
    // Try non-blocking send first
    match alert_tx.try_send(alert.clone()) {
        Ok(_) => {
            // Success
        }
        Err(mpsc::error::TrySendError::Full(_)) => {
            // Queue full - log to stderr as fallback
            eprintln!("ALERT QUEUE FULL - FALLBACK LOG: {:?}", alert);
            error!("Alert queue full, logged to stderr: {:?}", alert);
            
            // Try blocking send as last resort (with timeout)
            match timeout(Duration::from_secs(1), alert_tx.send(alert.clone())).await {
                Ok(Ok(_)) => {
                    warn!("Alert sent after retry");
                }
                Ok(Err(_)) => {
                    eprintln!("ALERT LOST - channel closed: {:?}", alert);
                }
                Err(_) => {
                    eprintln!("ALERT LOST - timeout: {:?}", alert);
                }
            }
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            // Channel closed - only stderr remains
            eprintln!("ALERT CHANNEL CLOSED: {:?}", alert);
            error!("Alert channel closed: {:?}", alert);
        }
    }
}

// ============================================================================
// Sleep with cancellation check
// ============================================================================
async fn sleep_with_cancel(duration: Duration, cancel: &CancellationToken) -> bool {
    tokio::select! {
        _ = sleep(duration) => false,      // completed normally
        _ = cancel.cancelled() => true,    // cancelled
    }
}

// ============================================================================
// Monitoring Task
// ============================================================================
async fn run_monitoring_task(
    monitor: Arc<MonitorEngine>,
    cancel: CancellationToken,
    metrics_tx: mpsc::Sender<Metrics>,
    alert_tx: mpsc::Sender<AlertMessage>,
) -> Result<()> {
    info!("Monitoring task started");
    
    let check_interval = monitor.check_interval();

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("Monitoring task shutting down");
                break;
            }
            _ = sleep(check_interval) => {
                // Spawn collection in separate task with timeout
                let monitor = monitor.clone();
                let handle = tokio::spawn(async move {
                    monitor.collect_metrics().await
                });

                let abort_handle = handle.abort_handle();

                match timeout(ITERATION_TIMEOUT, handle).await {
                    Ok(Ok(Ok(metrics))) => {
                        // Non-blocking send to avoid deadlock
                        if let Err(e) = metrics_tx.try_send(metrics) {
                            warn!("Dropped metrics (queue full?): {}", e);
                        }
                    }
                    Ok(Ok(Err(e))) => {
                        error!("Metric collection failed: {}", e);
                    }
                    Ok(Err(e)) => {
                        error!("Metric collection task panicked: {}", e);
                    }
                    Err(_) => {
                        error!("Metric collection timed out, aborting");
                        abort_handle.abort();
                        
                        // Non-blocking alert!
                        send_alert_with_fallback(
                            &alert_tx,
                            AlertMessage::emergency("Monitoring task timeout"),
                        ).await;
                    }
                }
            }
        }
    }

    Ok(())
}

// ============================================================================
// Detector Task — detect → IncidentHandler (act + alert + dedup + rate limit)
// ============================================================================
async fn run_detector_task(
    detector: Arc<Detector>,
    incident_handler: Arc<IncidentHandler>,
    cancel: CancellationToken,
    metrics_rx: Arc<TokioMutex<mpsc::Receiver<Metrics>>>,
    alert_tx: mpsc::Sender<AlertMessage>,
) -> Result<()> {
    info!("Detector task started");

    let mut rx = metrics_rx.lock().await;

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("Detector task shutting down");
                break;
            }
            Some(metrics) = rx.recv() => {
                let detector = detector.clone();
                let handler = incident_handler.clone();

                let handle = tokio::spawn(async move {
                    let incidents = detector.check_anomalies(&metrics).await?;
                    handler.handle_incidents(incidents).await?;
                    Ok::<(), anyhow::Error>(())
                });

                let abort_handle = handle.abort_handle();

                match timeout(ITERATION_TIMEOUT, handle).await {
                    Ok(Ok(Ok(_))) => {}
                    Ok(Ok(Err(e))) => {
                        error!("Anomaly detection failed: {}", e);
                        send_alert_with_fallback(
                            &alert_tx,
                            AlertMessage::critical(format!("Detector error: {}", e)),
                        ).await;
                    }
                    Ok(Err(e)) => {
                        error!("Detector task panicked: {}", e);
                        send_alert_with_fallback(
                            &alert_tx,
                            AlertMessage::emergency(format!("Detector panic: {}", e)),
                        ).await;
                    }
                    Err(_) => {
                        error!("Detector timed out, aborting");
                        abort_handle.abort();
                        send_alert_with_fallback(
                            &alert_tx,
                            AlertMessage::emergency("Detector timeout"),
                        ).await;
                    }
                }
            }
        }
    }

    Ok(())
}

// ============================================================================
// Alert Task
// ============================================================================
async fn run_alert_task(
    dispatcher: Arc<AlertDispatcher>,
    alert_rx: Arc<TokioMutex<mpsc::Receiver<AlertMessage>>>,
    cancel: CancellationToken,
) -> Result<()> {
    info!("Alert task started");

    let mut rx = alert_rx.lock().await;

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("Alert task shutting down - draining queue");
                // Drain remaining alerts
                while let Ok(msg) = rx.try_recv() {
                    match timeout(Duration::from_secs(5), dispatcher.send(&msg)).await {
                        Ok(Ok(_)) => {}
                        Ok(Err(e)) => {
                            error!("Failed to send alert during shutdown: {}", e);
                            eprintln!("ALERT LOST DURING SHUTDOWN: {:?}", msg);
                        }
                        Err(_) => {
                            error!("Alert send timed out during shutdown");
                            eprintln!("ALERT LOST (TIMEOUT) DURING SHUTDOWN: {:?}", msg);
                        }
                    }
                }
                break;
            }
            Some(alert) = rx.recv() => {
                let dispatcher = dispatcher.clone();
                let alert = alert.clone();
                let alert_for_log = alert.clone();
                let handle = tokio::spawn(async move {
                    dispatcher.send(&alert).await
                });

                let abort_handle = handle.abort_handle();

                match timeout(Duration::from_secs(10), handle).await {
                    Ok(Ok(Ok(_))) => {
                        // Alert sent
                    }
                    Ok(Ok(Err(e))) => {
                        error!("Failed to send alert: {}", e);
                        eprintln!("ALERT SEND FAILED: {:?} - Error: {}", alert_for_log, e);
                    }
                    Ok(Err(e)) => {
                        error!("Alert sending panicked: {}", e);
                        eprintln!("ALERT SEND PANICKED: {:?}", alert_for_log);
                    }
                    Err(_) => {
                        error!("Alert sending timed out");
                        abort_handle.abort();
                        eprintln!("ALERT SEND TIMEOUT: {:?}", alert_for_log);
                    }
                }
            }
        }
    }

    Ok(())
}

// ============================================================================
// Self-Check Task
// ============================================================================
async fn run_self_check_task(
    config: Arc<Config>,
    cancel: CancellationToken,
    alert_tx: mpsc::Sender<AlertMessage>,
) -> Result<()> {
    info!("Self-check task started");

    let pid = std::process::id();
    let mut baseline_memory: Option<u64> = None;

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("Self-check task shutting down");
                break;
            }
            _ = sleep(SELF_CHECK_INTERVAL) => {
                let config_for_health = config.clone();
                let check_result = tokio::task::spawn_blocking(move || {
                    check_self_health(pid, &config_for_health)
                }).await;

                match check_result {
                    Ok(Ok(health)) => {
                        if baseline_memory.is_none() {
                            baseline_memory = Some(health.memory_mb);
                        }

                        // CPU limit
                        if health.cpu_percent > config.performance.cpu_limit {
                            warn!("Self CPU: {:.1}%", health.cpu_percent);
                            // try_send instead of send — do NOT block!
                            send_alert_with_fallback(
                                &alert_tx,
                                AlertMessage::warning(format!("PanicMode CPU high: {:.1}%", health.cpu_percent)),
                            ).await;
                        }

                        // Memory limit
                        if health.memory_mb > config.performance.memory_limit_mb {
                            warn!("Self memory: {}MB", health.memory_mb);
                            send_alert_with_fallback(
                                &alert_tx,
                                AlertMessage::warning(format!("PanicMode memory high: {}MB", health.memory_mb)),
                            ).await;
                        }

                        // Memory growth
                        if let Some(baseline) = baseline_memory {
                            let growth = health.memory_mb as f64 / baseline as f64;
                            if growth > 2.0 {
                                warn!("Memory leak: {}x growth", growth);
                                send_alert_with_fallback(
                                    &alert_tx,
                                    AlertMessage::critical(format!("Memory leak: {:.1}x", growth)),
                                ).await;
                            }
                        }

                        // FD leak
                        if health.fd_count > 100 {
                            warn!("FD count: {}", health.fd_count);
                            send_alert_with_fallback(
                                &alert_tx,
                                AlertMessage::warning(format!("FD leak: {}", health.fd_count)),
                            ).await;
                        }

                        // Thread leak
                        if health.thread_count > 20 {
                            warn!("Thread count: {}", health.thread_count);
                            send_alert_with_fallback(
                                &alert_tx,
                                AlertMessage::warning(format!("Thread leak: {}", health.thread_count)),
                            ).await;
                        }
                    }
                    Ok(Err(e)) => {
                        error!("Self-check failed: {}", e);
                    }
                    Err(e) => {
                        error!("Self-check panicked: {}", e);
                    }
                }
            }
        }
    }

    Ok(())
}

#[derive(Debug)]
struct SelfHealthMetrics {
    cpu_percent: f32,
    memory_mb: u64,
    fd_count: usize,
    thread_count: usize,
}

fn check_self_health(pid: u32, config: &Config) -> Result<SelfHealthMetrics> {
    use std::fs;

    let proc_path = format!("/proc/{}", pid);

    let cpu_percent = measure_cpu_usage(pid)?;
    
    let status = fs::read_to_string(format!("{}/status", proc_path))?;
    let memory_mb = parse_proc_status_field(&status, "VmRSS:")
        .unwrap_or(0) / 1024;

    let fd_count = fs::read_dir(format!("{}/fd", proc_path))?.count();
    let thread_count = fs::read_dir(format!("{}/task", proc_path))?.count();

    Ok(SelfHealthMetrics {
        cpu_percent,
        memory_mb,
        fd_count,
        thread_count,
    })
}

fn measure_cpu_usage(pid: u32) -> Result<f32> {
    use std::fs;
    use std::thread;

    let stat_path = format!("/proc/{}/stat", pid);
    
    let stat1 = fs::read_to_string(&stat_path)?;
    let (utime1, stime1) = parse_cpu_times(&stat1)?;
    let total1 = read_total_cpu_time()?;
    
    thread::sleep(Duration::from_millis(100));
    
    let stat2 = fs::read_to_string(&stat_path)?;
    let (utime2, stime2) = parse_cpu_times(&stat2)?;
    let total2 = read_total_cpu_time()?;
    
    // Use saturating_sub to prevent underflow!
    let process_delta = (utime2 + stime2).saturating_sub(utime1 + stime1);
    let total_delta = total2.saturating_sub(total1);
    
    if total_delta == 0 {
        return Ok(0.0);
    }
    
    let cpu_cores = num_cpus::get() as f32;
    Ok((process_delta as f32 / total_delta as f32) * 100.0 * cpu_cores)
}

fn parse_cpu_times(stat: &str) -> Result<(u64, u64)> {
    let parts: Vec<&str> = stat.split_whitespace().collect();
    if parts.len() < 15 {
        return Err(anyhow::anyhow!("Invalid stat format"));
    }
    Ok((parts[13].parse()?, parts[14].parse()?))
}

fn read_total_cpu_time() -> Result<u64> {
    let stat = std::fs::read_to_string("/proc/stat")?;
    let first_line = stat.lines().next().ok_or_else(|| anyhow::anyhow!("Empty /proc/stat"))?;
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    
    Ok(parts[1..].iter()
        .filter_map(|s| s.parse::<u64>().ok())
        .sum())
}

fn parse_proc_status_field(status: &str, field: &str) -> Option<u64> {
    status.lines()
        .find(|line| line.starts_with(field))
        .and_then(|line| {
            line.split_whitespace()
                .nth(1)
                .and_then(|val| val.parse().ok())
        })
}

// ============================================================================
// Restore blocked IPs after reboot
// ============================================================================
async fn restore_blocked_ips(config: &config::Config, storage: &storage::IncidentStorage) {
    let block_script = std::env::var("PANICMODE_BLOCK_IP_SCRIPT")
        .unwrap_or_else(|_| config.firewall.block_script.clone());

    let ips = match storage.get_active_blocked_ips().await {
        Ok(list) => list,
        Err(e) => {
            warn!("restore_blocked_ips: cannot read DB: {}", e);
            return;
        }
    };

    if ips.is_empty() {
        info!("restore_blocked_ips: no active blocks to restore");
        return;
    }

    info!("restore_blocked_ips: restoring {} block(s) via {}", ips.len(), block_script);

    for entry in ips {
        let script = block_script.clone();
        let ip = entry.ip.clone();

        let result = tokio::time::timeout(
            Duration::from_secs(10),
            tokio::process::Command::new(&script).arg(&ip).status(),
        ).await;

        match result {
            Ok(Ok(status)) if status.success() => {
                info!("restore_blocked_ips: restored block for {}", ip);
            }
            Ok(Ok(status)) => {
                warn!("restore_blocked_ips: script exited {} for {}", status, ip);
            }
            Ok(Err(e)) => {
                warn!("restore_blocked_ips: failed to run script for {}: {}", ip, e);
            }
            Err(_) => {
                warn!("restore_blocked_ips: script timed out for {}", ip);
            }
        }
    }
}

// ============================================================================
// HTTP API Task — minimal healthcheck endpoint (GET /health)
// ============================================================================
async fn run_http_api_task(
    config: Arc<Config>,
    cancel: CancellationToken,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind(&config.http_api.bind)
        .await
        .map_err(|e| anyhow::anyhow!("HTTP API bind {}: {}", config.http_api.bind, e))?;

    info!("HTTP API listening on http://{}/health", config.http_api.bind);

    let start_time = std::time::Instant::now();

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("HTTP API task shutting down");
                break;
            }
            accept = listener.accept() => {
                let (mut stream, _peer) = match accept {
                    Ok(v) => v,
                    Err(e) => {
                        error!("HTTP API accept error: {}", e);
                        continue;
                    }
                };
                let uptime_secs = start_time.elapsed().as_secs();

                tokio::spawn(async move {
                    let mut buf = [0u8; 512];
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    let request = std::str::from_utf8(&buf[..n]).unwrap_or("");

                    let response = if request.starts_with("GET /health") {
                        let body = format!(
                            "{{\"status\":\"ok\",\"uptime_secs\":{}}}",
                            uptime_secs
                        );
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        )
                    } else {
                        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
                    };

                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        }
    }

    Ok(())
}