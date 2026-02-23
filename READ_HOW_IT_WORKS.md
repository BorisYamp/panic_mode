# How PanicMode Works — A Developer's Guide

This document explains the entire codebase from top to bottom so you can understand,
modify, and extend PanicMode for your own needs. No prior knowledge of the project is assumed.

---

## Table of Contents

1. [What PanicMode Does](#1-what-panicmode-does)
2. [The Big Picture — Data Flow](#2-the-big-picture--data-flow)
3. [Project File Map](#3-project-file-map)
4. [Module Deep-Dives](#4-module-deep-dives)
   - [config.rs — Configuration](#configrs--configuration)
   - [main.rs — Entry Point & Task Supervision](#mainrs--entry-point--task-supervision)
   - [monitor/ — Metric Collection](#monitor--metric-collection)
   - [detector/ — Incident Detection](#detector--incident-detection)
   - [action/ — Protective Actions](#action--protective-actions)
   - [alert/ — Alerting](#alert--alerting)
   - [storage.rs — Persistence](#storagrs--persistence)
5. [Complete Config Reference](#5-complete-config-reference)
6. [How to Add a New Monitor Type](#6-how-to-add-a-new-monitor-type)
7. [How to Add a New Action](#7-how-to-add-a-new-action)
8. [How to Add a New Alert Channel](#8-how-to-add-a-new-alert-channel)
9. [Key Design Patterns Explained](#9-key-design-patterns-explained)
10. [Common Customizations](#10-common-customizations)

---

## 1. What PanicMode Does

PanicMode is a **server monitoring daemon** that:

1. **Watches** your server's CPU, RAM, disk, network, auth logs, and custom metrics
2. **Detects** anomalies and threshold violations
3. **Acts** automatically — blocks IPs, freezes runaway processes, captures diagnostics
4. **Alerts** you via Telegram, Discord, email, SMS, voice calls, or any webhook

The goal is to keep your server alive during attacks or resource spikes, and make sure you know about it immediately.

---

## 2. The Big Picture — Data Flow

Here is exactly what happens every monitoring cycle (default every 5 seconds):

```
┌─────────────────────────────────────────────────────────────┐
│  MONITORING TASK (every 5s)                                 │
│                                                             │
│  MonitorEngine::collect_metrics()                           │
│  ├─ cpu.rs      → CpuMetrics    (usage %, per-core, procs) │
│  ├─ memory.rs   → MemoryMetrics (ram %, swap %)            │
│  ├─ network.rs  → NetworkMetrics (connections, IPs)        │
│  ├─ auth.rs     → AuthMetrics   (ssh failures)             │
│  ├─ disk_io.rs  → DiskIoMetrics (read/write per device)    │
│  └─ disk.rs     → DiskMetrics   (usage % per mount)        │
│                                                             │
│  All collected in PARALLEL via tokio::join!()              │
│  If one fails → returns defaults (0.0), others continue    │
└─────────────────────┬───────────────────────────────────────┘
                      │  Metrics struct sent via channel
                      ▼
┌─────────────────────────────────────────────────────────────┐
│  DETECTOR TASK                                              │
│                                                             │
│  Detector::check_anomalies(&metrics)                        │
│  ├─ RuleEvaluator: checks each monitors[] rule              │
│  │   "if cpu > 80% → create Incident with actions [...]"   │
│  └─ AnomalyDetector: spike detection (no rules needed)     │
│      "if cpu > 95% → CRITICAL incident"                    │
│      "if 50+ IPs each with 50+ connections → CRITICAL"     │
│                                                             │
│  Returns: Vec<Incident>                                     │
│                                                             │
│  IncidentHandler::handle_incidents(incidents)               │
│  ├─ 1. Deduplication: same incident? skip (5-min window)  │
│  ├─ 2. Sort: Critical first, then Warning, then Info       │
│  ├─ 3. Protective actions (BLOCKING, 15s timeout):         │
│  │      FirewallAction → block_ip.sh <IP>                  │
│  │      ProcessAction  → SIGSTOP top CPU hogs              │
│  ├─ 4. Alerts (rate-limited: critical 60s, warning 300s):  │
│  │      → alert_tx channel → Alert Task                    │
│  ├─ 5. Background actions (non-blocking):                  │
│  │      SnapshotAction, ScriptAction                       │
│  └─ 6. Persist to SQLite (background)                      │
└─────────────────────┬───────────────────────────────────────┘
                      │  AlertMessage sent via channel
                      ▼
┌─────────────────────────────────────────────────────────────┐
│  ALERT TASK                                                 │
│                                                             │
│  AlertDispatcher::send(msg)                                 │
│  ├─ Look up channels for this severity                      │
│  ├─ For each channel (skipping disabled ones):              │
│  │   ├─ Build reqwest client with channel's timeout         │
│  │   ├─ Send (with retries, default 3)                     │
│  │   └─ If success → done; if fail → try next channel       │
│  └─ If ALL channels fail → return Err (logged to stderr)   │
│                                                             │
│  Channels: Telegram, Discord, Ntfy, Email,                 │
│            Webhook, Twilio SMS, Twilio Call                 │
└─────────────────────────────────────────────────────────────┘

Also running in parallel:
  SELF-CHECK TASK  — monitors PanicMode's own CPU/RAM every 5s
  HTTP API TASK    — GET /health endpoint (if enabled)
  CTL TASK (aux)   — Unix socket server for panicmode-ctl list/unblock
                     (failure is non-fatal — daemon continues without it)
```

---

## 3. Project File Map

```
src/
├── main.rs                          ← Start here. 5 critical tasks + ctl auxiliary.
├── config.rs                        ← Every config field. Read this to understand YAML.
├── storage.rs                       ← SQLite: incidents + blocked_ips tables.
│
├── ctl/
│   └── mod.rs                       ← Unix socket server for panicmode-ctl CLI
│
├── bin/
│   └── panicmode-ctl.rs             ← CLI binary: list/unblock blocked IPs
│
├── monitor/
│   ├── mod.rs                       ← MonitorEngine, Metrics struct, collect_metrics()
│   ├── cpu.rs                       ← Reads /proc/stat
│   ├── memory.rs                    ← Reads /proc/meminfo
│   ├── network.rs                   ← Reads /proc/net/tcp, /proc/net/tcp6
│   ├── auth.rs                      ← Tails /var/log/auth.log
│   ├── disk_io.rs                   ← Reads /proc/diskstats
│   ├── file_watcher.rs              ← Uses notify crate for file events
│   └── custom_metrics.rs            ← Runs shell commands, parses output
│
├── detector/
│   ├── mod.rs                       ← Detector, Incident, IncidentHandler
│   ├── rules.rs                     ← RuleEvaluator: checks monitors[] thresholds
│   ├── anomaly.rs                   ← AnomalyDetector: spike detection
│   ├── state.rs                     ← IncidentState: dedup + rate limiting
│   └── circuit_breaker.rs           ← CircuitBreaker state machine
│
├── action/
│   ├── trait.rs                     ← Action trait: execute() + name()
│   ├── mod.rs                       ← Module exports
│   ├── executor.rs                  ← ActionExecutor: resolves and runs actions
│   ├── builder.rs                   ← ActionExecutorBuilder: wires everything together
│   ├── registry.rs                  ← ActionRegistry: ActionType → Box<dyn Action>
│   ├── result.rs                    ← ActionExecutionResult
│   ├── middleware/
│   │   └── breaker.rs               ← BreakerWrapped: circuit breaker around actions
│   └── implementations/
│       ├── firewall.rs              ← block IPs via shell script
│       ├── process.rs               ← freeze/kill processes via SIGSTOP/SIGKILL
│       ├── snapshot.rs              ← capture system state to disk
│       └── script.rs                ← run arbitrary user script
│
└── alert/
    └── mod.rs                       ← AlertDispatcher + all channel implementations
```

---

## 4. Module Deep-Dives

### `config.rs` — Configuration

This file defines **every configurable option** in PanicMode. When you write a YAML config,
it gets deserialized into the `Config` struct here.

**The top-level struct:**
```rust
pub struct Config {
    pub performance: PerformanceConfig,
    pub monitors: Vec<MonitorRule>,           // your monitoring rules
    pub actions: HashMap<String, OldActionConfig>, // legacy script config
    pub alerts: AlertsConfig,
    pub integrations: IntegrationsConfig,
    pub custom_metrics: HashMap<String, CustomMetricConfig>,
    pub file_monitor: FileMonitorConfig,
    pub circuit_breakers: CircuitBreakerConfig,
    pub storage: StorageConfig,
    pub anomaly: AnomalyConfig,
    pub http_api: HttpApiConfig,
    pub firewall: FirewallConfig,             // block_ip scripts, whitelist, ctl socket
}
```

**Validation** happens in `Config::validate()`. If your config is wrong, PanicMode exits at
startup with a clear error — it never silently starts with bad config.

---

### `main.rs` — Entry Point & Task Supervision

Main starts 5 critical async tasks plus 1 auxiliary, and supervises them:

```
main()
 ├─ Load config (YAML → Config struct)
 ├─ Restore blocked IPs from DB (if firewall.restore_on_startup)
 ├─ Initialize: MonitorEngine, Detector, ActionExecutor, AlertDispatcher, Storage
 ├─ Create channels:
 │   metrics_tx/rx (MonitorEngine → Detector)
 │   alert_tx/rx   (IncidentHandler → AlertDispatcher)
 ├─ tokio::select! on 5 CRITICAL tasks (any failure → graceful shutdown):
 │   ├─ run_monitoring_task()
 │   ├─ run_detector_task()
 │   ├─ run_alert_task()
 │   ├─ run_self_check_task()
 │   └─ run_http_api_task() (if enabled)
 └─ ctl_task_handle (AUXILIARY — failure logged, daemon keeps running)
     └─ CtlServer::run() → Unix socket at firewall.ctl_socket
```

**Task supervision** — each task is wrapped in `supervise_task()`:
- If a task panics → catches the panic via `catch_unwind`
- Waits with exponential backoff (1s, 2s, 4s... up to 60s)
- After 3 failures in a row → gives up and exits the process
- **This is intentional**: systemd/supervisor should restart PanicMode if it crashes

**Graceful shutdown** — on Ctrl+C:
1. Cancellation token is set
2. Each task gets 10 seconds to finish
3. Alert task drains its queue before stopping
4. 2-second delay to let final alerts send

---

### `monitor/` — Metric Collection

**The key type** is `Metrics`:
```rust
pub struct Metrics {
    pub timestamp: SystemTime,
    pub cpu: CpuMetrics,
    pub memory: MemoryMetrics,
    pub network: NetworkMetrics,
    pub auth: AuthMetrics,
    pub disk: DiskMetrics,
    pub disk_io: DiskIoMetrics,
}
```

**`collect_metrics()`** in `monitor/mod.rs` runs all collectors in parallel:
```rust
// Simplified version of what happens:
let (cpu, memory, network, auth, disk_io) = tokio::join!(
    spawn_blocking(|| cpu::collect()),
    spawn_blocking(|| memory::collect()),
    network::collect(),
    auth::collect(),
    spawn_blocking(|| disk_io::collect()),
);
// disk is cached for 60s to avoid hammering I/O
```

**Graceful degradation**: if `cpu::collect()` fails, CPU metrics are `CpuMetrics::default()`
(all zeros). The other monitors still run. The error is logged.

**`spawn_blocking`** is used for CPU-bound operations that read from `/proc/` files.
Async tasks should not block the executor — `spawn_blocking` moves them to a thread pool.

---

### `detector/` — Incident Detection

**`Incident`** is the core type:
```rust
pub struct Incident {
    pub name: String,
    pub severity: IncidentSeverity,  // Info | Warning | Critical
    pub description: String,
    pub actions: Vec<ActionType>,    // what to do about it
    pub metadata: IncidentMetadata,
}

pub struct IncidentMetadata {
    pub monitor_type: MonitorType,
    pub threshold: f64,
    pub current_value: f64,
    pub details: String,  // human-readable + machine-parseable (IPs live here!)
}
```

**Two detection systems:**

1. **`RuleEvaluator`** (in `rules.rs`) — checks your `monitors:` config:
   ```yaml
   monitors:
     - name: high_cpu
       type: cpu_usage
       threshold: 80.0    # if cpu > 80 → create Incident
       actions: [alert_critical, freeze_top_process]
   ```

2. **`AnomalyDetector`** (in `anomaly.rs`) — built-in spike detection, no config required:
   - CPU > `anomaly.cpu_spike_threshold` (default 95%) → Critical incident
   - Memory > `anomaly.memory_spike_threshold` (default 95%) → Critical
   - Connections > `anomaly.connection_spike_threshold` (default 10,000) → Critical
   - Suspicious IPs (each with >50 connections): count > `suspicious_ip_threshold` → Critical
   - Load average > `anomaly.high_load_threshold` (default 10.0) → Critical

**`IncidentHandler`** (in `detector/mod.rs`) is where incident processing logic lives:

```rust
// Simplified flow:
async fn handle_incidents(&self, incidents: Vec<Incident>) {
    for incident in incidents {
        // 1. Dedup: atomically check AND record under same mutex lock
        {
            let mut state = self.state.lock().await;
            if state.is_duplicate(&incident) { continue; }
            state.record_incident(&incident);
        }

        // 2. Execute protective actions immediately (with timeout)
        execute_protective_actions(&incident).await;

        // 3. Send alert if not rate-limited
        if !rate_limited(&incident) {
            alert_tx.send(AlertMessage::critical(incident.description)).await;
        }

        // 4. Background: snapshot, script
        tokio::spawn(async { execute_background_actions(&incident).await; });

        // 5. Persist
        tokio::spawn(async { storage.record_incident(&incident).await; });
    }
}
```

**`CircuitBreaker`** (in `circuit_breaker.rs`) protects against runaway action execution:
- Trips after N failures within a time window
- While open: skips action execution entirely
- Half-open after `open_duration`: tries one request
- If succeeds → closes again; if fails → stays open
- State: `Closed → Open → HalfOpen → Closed`

---

### `action/` — Protective Actions

**The `Action` trait** (in `action/trait.rs`):
```rust
#[async_trait]
pub trait Action: Send + Sync {
    async fn execute(&self, ctx: &ActionContext<'_>) -> Result<()>;
    fn name(&self) -> &str;
}
```

That's it. Implement these two methods and you have a new action.

**`ActionContext`** gives you access to the incident:
```rust
pub struct ActionContext<'a> {
    pub incident: &'a Incident,
}
```

**Action implementations:**

| File | Action | What It Does |
|------|--------|--------------|
| `firewall.rs` | `FirewallAction` | Parses IPs from `incident.metadata.details`, calls `block_ip.sh <IP>` for each public IP |
| `process.rs` | `ProcessAction` | Sends SIGSTOP/SIGKILL to top CPU-consuming processes (skips whitelist) |
| `snapshot.rs` | `SnapshotAction` | Runs `ps aux`, `netstat`, `top`, etc. and saves output to a timestamped file |
| `script.rs` | `ScriptAction` | Runs user's custom shell script with incident data as env vars |

**`ScriptAction` env vars** (available to your script):
```bash
PANIC_INCIDENT_NAME=high_cpu
PANIC_SEVERITY=Critical
PANIC_DESCRIPTION="CPU usage 97%"
PANIC_DETAILS="..."
PANIC_THRESHOLD=80.0
PANIC_CURRENT_VALUE=97.3
```

**`ActionExecutor`** loops through actions, resolves each via `ActionRegistry`,
and runs them through `BreakerWrapped` (circuit breaker middleware).

**`BreakerWrapped`** (in `action/middleware/breaker.rs`) wraps any `Action`:
```rust
// Usage is transparent — same Action interface
impl Action for BreakerWrapped {
    async fn execute(&self, ctx: &ActionContext<'_>) -> Result<()> {
        self.circuit_breaker.call(async {
            self.inner.execute(ctx).await
        }).await
    }
}
```

---

### `alert/` — Alerting

Everything lives in `alert/mod.rs`.

**`AlertDispatcher`** has one public method:
```rust
pub async fn send(&self, msg: &AlertMessage) -> Result<()>
```

Internally it:
1. Finds channels for `msg.severity` (from `alerts.critical/warning/info` in config)
2. Skips disabled integrations (`is_integration_enabled()`)
3. For each channel: builds an HTTP client with `channel.timeout`, retries up to `channel.retries` times
4. Returns `Ok(())` if **at least one** channel succeeded
5. Returns `Err` if **all channels failed** (or no channels configured for Critical/Emergency)

**Per-channel HTTP client:**
```rust
fn build_client(timeout: Option<Duration>) -> Client {
    Client::builder()
        .timeout(timeout.unwrap_or(Duration::from_secs(10)))
        .build()
        .unwrap_or_default()
}
// Called in send_to_channel() with channel.timeout
```

**Private methods per channel:**
- `send_telegram()` — POST to `https://api.telegram.org/bot{token}/sendMessage`
- `send_discord()` — POST `{"content": text}` to Discord webhook URL
- `send_ntfy()` — POST text body to `{server}/{topic}` with optional Bearer token
- `send_webhook()` — POST `{"text": text}` to any URL
- `send_email()` — SMTP via `lettre` crate (supports TLS, auth)
- `send_twilio_sms()` — POST form to Twilio Messages.json API
- `send_twilio_call()` — POST form to Twilio Calls.json API with inline TwiML

---

### `storage.rs` — Persistence

Three things are persisted:

1. **SQLite database** (`/var/lib/panicmode/incidents.db`) — two tables:
   - `incidents` — record of every fired incident (for post-mortem analysis)
   - `blocked_ips` — currently active IP blocks; survives reboots via `restore_on_startup`
   - Falls back to in-memory SQLite if disk write fails

2. **JSON state file** (`/var/lib/panicmode/incident_state.json`) — deduplication state
   - Written atomically (write to `.tmp` then rename)
   - Survives PanicMode restarts — no duplicate alerts after restart

3. **Unix socket** (`/run/panicmode/ctl.sock`, `chmod 600`) — live management
   - Created by `CtlServer` at startup; removed on shutdown
   - `panicmode-ctl list` — show active blocks
   - `panicmode-ctl unblock <IP>` — remove a block (runs `unblock_ip.sh` + deletes from DB)

---

## 5. Complete Config Reference

```yaml
# ─────────────────────────────────────────────────────────────
# PERFORMANCE — PanicMode's own resource limits
# ─────────────────────────────────────────────────────────────
performance:
  cpu_limit: 5.0             # Max % CPU PanicMode itself should use. Alert if exceeded.
  memory_limit_mb: 50        # Max MB RAM for PanicMode itself.
  check_interval: "5s"       # How often to collect metrics. Format: "5s", "1m", "500ms"

# ─────────────────────────────────────────────────────────────
# MONITORS — Your custom threshold rules
# ─────────────────────────────────────────────────────────────
monitors:
  - name: "high_cpu"
    type: cpu_usage           # See MonitorType list below
    threshold: 80.0           # Numeric threshold (meaning depends on type)
    enabled: true             # Default: true. Set false to disable without removing.
    actions:                  # What to do when triggered (see ActionType list below)
      - alert_critical
      - freeze_top_process
      - snapshot

# MonitorType values:
#   cpu_usage        — CPU % (0–100). Threshold: e.g. 80.0
#   memory_usage     — RAM % (0–100). Threshold: e.g. 85.0
#   swap_usage       — Swap % (0–100). Threshold: e.g. 50.0
#   disk_usage       — Disk % (0–100). Use paths: ["/", "/data"]
#   disk_io          — Disk I/O metrics
#   connection_rate  — New connections/sec. Threshold: e.g. 1000.0
#   auth_failures    — SSH login failures. Threshold: e.g. 50.0
#   file_monitor     — File events. Use paths: ["/etc", "/var/www"]
#   process_count    — Number of running processes. Threshold: e.g. 500.0
#   load_average     — 1-min load average. Threshold: e.g. 8.0
#   custom           — Output of a shell command (see custom_metrics)

# ActionType values:
#   alert_critical       — Send critical alert
#   alert_warning        — Send warning alert
#   alert_info           — Send informational alert
#   block_ip             — Extract IPs from incident, run block_ip.sh <IP>
#   freeze_top_process   — SIGSTOP top N CPU processes
#   mass_freeze          — SIGSTOP all non-whitelisted processes
#   mass_freeze_top      — SIGSTOP top K processes regardless of whitelist
#   mass_freeze_cluster:<name>  — SIGSTOP a named cluster from mass_freeze.yaml
#   kill_process         — SIGKILL top CPU processes
#   rate_limit           — Apply rate limiting (stub — implement in process.rs)
#   snapshot             — Capture system state (ps, netstat, etc.) to file
#   run_script           — Run your custom script (configured in actions: section)

# ─────────────────────────────────────────────────────────────
# ANOMALY DETECTION — Built-in spike detection (no rules needed)
# ─────────────────────────────────────────────────────────────
anomaly:
  cpu_spike_threshold: 95.0              # CPU % to trigger Critical anomaly incident
  memory_spike_threshold: 95.0           # Memory % to trigger Critical incident
  connection_spike_threshold: 10000      # Total connections count
  suspicious_ip_threshold: 3             # How many suspicious IPs to trigger incident
  high_load_threshold: 10.0             # 1-min load average
  suspicious_connections_per_ip: 50      # Connections from a single IP to mark it suspicious

# ─────────────────────────────────────────────────────────────
# ALERTS — Which channels receive which severity
# ─────────────────────────────────────────────────────────────
alerts:
  critical:                    # Also used for "emergency" severity
    - channel: telegram
      retries: 3               # Retry attempts per channel (default: 3)
      timeout: "10s"           # HTTP timeout per attempt (default: 10s)
    - channel: discord
      webhook_url: "https://discordapp.com/api/webhooks/..."

  warning:
    - channel: ntfy
      topic: "panicmode-warn"  # Override ntfy topic per-channel

  info:
    - channel: webhook
      webhook_url: "https://your-server.com/panicmode-hook"

# ─────────────────────────────────────────────────────────────
# INTEGRATIONS — Credentials for each channel
# ─────────────────────────────────────────────────────────────
integrations:
  telegram:
    enabled: true              # Set false to disable without removing config
    bot_token: "123456:ABC..."
    chat_id: "-100123456789"
    api_base_url: null         # Optional: self-hosted Bot API server URL

  discord:
    enabled: true
    webhook_url: "https://discordapp.com/api/webhooks/..."

  ntfy:
    enabled: true
    server: "https://ntfy.sh"  # Or your self-hosted ntfy server
    topic: "panicmode"
    token: null                 # Optional: Bearer token for private topics

  email:
    enabled: true
    smtp_host: "smtp.gmail.com"
    smtp_port: 587
    smtp_username: "you@gmail.com"
    smtp_password: "app-password"
    from_email: "panicmode@yourdomain.com"
    to_email: "alerts@yourdomain.com"
    use_tls: true

  twilio:
    enabled: true
    account_sid: "ACxxxxxxxx"
    auth_token: "your_auth_token"
    from_number: "+15551234567"
    # Contacts (who to call) are defined per-channel in alerts:
    # alerts:
    #   critical:
    #     - channel: twilio_call
    #       contacts:
    #         - name: "Alice"
    #           phone: "+15559876543"

# ─────────────────────────────────────────────────────────────
# CIRCUIT BREAKERS — Protect against cascade failures
# ─────────────────────────────────────────────────────────────
circuit_breakers:
  max_failures: 5        # Trip after this many failures...
  failure_window: "60s"  # ...within this time window
  open_duration: "30s"   # How long to stay tripped (stop trying)
  max_concurrency: 5     # Max concurrent action executions
  timeout: "10s"         # Per-action timeout

# ─────────────────────────────────────────────────────────────
# STORAGE — Where files go
# ─────────────────────────────────────────────────────────────
storage:
  incident_db: "/var/lib/panicmode/incidents.db"
  snapshot_dir: "/var/log/panicmode/snapshots"
  log_dir: "/var/log/panicmode"
  state_file: "/var/lib/panicmode/incident_state.json"

# ─────────────────────────────────────────────────────────────
# CUSTOM METRICS — Run your own commands and monitor their output
# ─────────────────────────────────────────────────────────────
custom_metrics:
  redis_memory_mb:
    command: "/bin/sh -c \"redis-cli INFO memory | grep used_memory: | awk -F: '{print $2}'\""
    timeout: "5s"
    cache_ttl: "10s"          # Cache result to avoid hammering Redis
    output_format: "number"   # Parse stdout as a number

# Then use it in monitors:
# monitors:
#   - name: redis_too_big
#     type: custom
#     # The metric name matches the key above: "redis_memory_mb"
#     threshold: 500.0
#     actions: [alert_warning]

# ─────────────────────────────────────────────────────────────
# FILE MONITOR — Watch paths for filesystem events
# ─────────────────────────────────────────────────────────────
file_monitor:
  max_events_per_path: 1000
  aggregation_window: "60s"

# monitors:
#   - name: etc_changes
#     type: file_monitor
#     paths: ["/etc/passwd", "/etc/ssh"]
#     threshold: 1.0           # Trigger after 1 event
#     actions: [alert_critical, snapshot]

# ─────────────────────────────────────────────────────────────
# HTTP API — Optional health endpoint
# ─────────────────────────────────────────────────────────────
http_api:
  enabled: false
  bind: "127.0.0.1:8765"
  # GET /health → {"status":"ok","uptime_secs":3600}

# ─────────────────────────────────────────────────────────────
# FIREWALL — IP blocking via external scripts
# ─────────────────────────────────────────────────────────────
firewall:
  enabled: true                                    # false disables block_ip entirely

  # Scripts invoked as: block_ip.sh <IP> / unblock_ip.sh <IP>
  # Override with env vars PANICMODE_BLOCK_IP_SCRIPT / PANICMODE_UNBLOCK_IP_SCRIPT
  block_script: "/etc/panicmode/scripts/block_ip.sh"
  unblock_script: "/etc/panicmode/scripts/unblock_ip.sh"

  # Re-apply blocks from DB after daemon restart (iptables rules don't survive reboots)
  restore_on_startup: true

  # Unix socket for panicmode-ctl (chmod 600 — root/owner only)
  ctl_socket: "/run/panicmode/ctl.sock"

  # IPs and subnets that will NEVER be blocked. RFC1918 and loopback are always protected.
  whitelist:
    # - "203.0.113.10"       # office fixed IP
    # - "198.51.100.0/24"    # VPN subnet
    # - "2001:db8::1"        # IPv6 developer address
```

---

## 6. How to Add a New Monitor Type

Let's say you want to monitor **GPU temperature**.

### Step 1: Add the variant to `MonitorType` enum (`src/config.rs`)

Find the `MonitorType` enum and add your variant:
```rust
pub enum MonitorType {
    CpuUsage,
    MemoryUsage,
    // ... existing variants ...
    GpuTemperature,  // ← add here
}
```

### Step 2: Add the metric field to `Metrics` (`src/monitor/mod.rs`)

```rust
pub struct Metrics {
    pub timestamp: SystemTime,
    pub cpu: CpuMetrics,
    // ... existing fields ...
    pub gpu: GpuMetrics,  // ← add here
}

#[derive(Debug, Clone, Default)]
pub struct GpuMetrics {
    pub temperature_celsius: f64,
}
```

### Step 3: Create the collector (`src/monitor/gpu.rs`)

```rust
use anyhow::Result;
use super::GpuMetrics;

pub fn collect() -> Result<GpuMetrics> {
    // Read from nvidia-smi, /sys/class/thermal, or whatever
    let output = std::process::Command::new("nvidia-smi")
        .args(["--query-gpu=temperature.gpu", "--format=csv,noheader"])
        .output()?;

    let temp: f64 = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()?;

    Ok(GpuMetrics { temperature_celsius: temp })
}
```

### Step 4: Add to parallel collection (`src/monitor/mod.rs`)

In `collect_metrics()`, add your monitor to the `tokio::join!` block:
```rust
let (cpu_result, memory_result, /* ... */, gpu_result) = tokio::join!(
    // existing monitors...
    tokio::task::spawn_blocking(|| gpu::collect()),
);

Ok(Metrics {
    timestamp: SystemTime::now(),
    // existing fields...
    gpu: unwrap_monitor(gpu_result, "GPU"),  // unwrap_monitor handles errors gracefully
})
```

### Step 5: Add the rule evaluation case (`src/detector/rules.rs`)

Find the `match monitor_type` block in `RuleEvaluator` and add:
```rust
MonitorType::GpuTemperature => metrics.gpu.temperature_celsius,
```

### Step 6: Add to the module (`src/monitor/mod.rs`)

```rust
mod gpu;  // ← add this line near the other mod declarations
```

### Step 7: Use in config

```yaml
monitors:
  - name: gpu_overheating
    type: gpu_temperature
    threshold: 85.0
    actions: [alert_critical]
```

---

## 7. How to Add a New Action

Let's say you want to add a **CloudflareBlock** action that calls Cloudflare's API to block IPs.

### Step 1: Add the variant to `ActionType` (`src/action/trait.rs`)

```rust
pub enum ActionType {
    BlockIp,
    // ... existing variants ...
    CloudflareBlock,  // ← add here
}
```

Add YAML deserialization (there's a `from_str` or `Deserialize` impl nearby — add a case there too).

### Step 2: Create the implementation (`src/action/implementations/cloudflare.rs`)

```rust
use anyhow::{bail, Result};
use async_trait::async_trait;
use std::sync::Arc;
use crate::action::r#trait::{Action, ActionContext};
use crate::config::Config;

pub struct CloudflareBlockAction {
    api_token: String,
    zone_id: String,
}

impl CloudflareBlockAction {
    pub fn new(config: Arc<Config>) -> Result<Self> {
        // Read credentials from config
        // (add fields to Config/IntegrationsConfig as needed)
        Ok(Self {
            api_token: "your_token".to_string(),
            zone_id: "your_zone".to_string(),
        })
    }
}

#[async_trait]
impl Action for CloudflareBlockAction {
    async fn execute(&self, ctx: &ActionContext<'_>) -> Result<()> {
        // Extract IPs from incident
        let details = &ctx.incident.metadata.details;
        // ... parse IPs, call Cloudflare API ...
        Ok(())
    }

    fn name(&self) -> &str {
        "cloudflare_block"
    }
}
```

### Step 3: Register in `ActionRegistry` (`src/action/registry.rs`)

Find the `resolve()` method and add:
```rust
ActionType::CloudflareBlock => {
    Box::new(CloudflareBlockAction::new(Arc::clone(&self.config))?)
}
```

### Step 4: Add to `implementations/mod.rs`

```rust
pub mod cloudflare;
```

### Step 5: Use in config

```yaml
monitors:
  - name: ddos_detected
    type: connection_rate
    threshold: 5000.0
    actions: [cloudflare_block, alert_critical]
```

---

## 8. How to Add a New Alert Channel

Let's say you want to add **Slack** support.

### Step 1: Add the variant to `ChannelType` (`src/config.rs`)

```rust
pub enum ChannelType {
    Telegram,
    // ... existing ...
    Slack,  // ← add here
}
```

### Step 2: Add Slack config struct (`src/config.rs`)

```rust
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct SlackConfig {
    pub enabled: bool,
    pub webhook_url: String,
}
```

Add it to `IntegrationsConfig`:
```rust
pub struct IntegrationsConfig {
    pub telegram: Option<TelegramConfig>,
    // ... existing ...
    pub slack: Option<SlackConfig>,  // ← add here
}
```

### Step 3: Add validation (`src/config.rs`)

In `validate_alert_integrations()`, add a case:
```rust
ChannelType::Slack => {
    if let Some(slack) = &self.integrations.slack {
        if slack.enabled && slack.webhook_url.is_empty() {
            anyhow::bail!("Slack integration enabled but webhook_url is empty");
        }
    }
}
```

### Step 4: Add `is_integration_enabled` case (`src/alert/mod.rs`)

```rust
fn is_integration_enabled(&self, channel: &AlertChannel) -> bool {
    let i = &self.config.integrations;
    match &channel.channel {
        // ... existing ...
        ChannelType::Slack => i.slack.as_ref().map(|c| c.enabled).unwrap_or(false),
    }
}
```

### Step 5: Add `send_slack()` method (`src/alert/mod.rs`)

```rust
async fn send_slack(&self, client: &Client, text: &str, integrations: &IntegrationsConfig) -> Result<()> {
    let cfg = integrations.slack.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Slack not configured"))?;

    if !cfg.enabled {
        return Ok(());
    }

    let body = serde_json::json!({ "text": text });
    let resp = client.post(&cfg.webhook_url).json(&body).send().await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("Slack error {}: {}", status, body);
    }
    Ok(())
}
```

### Step 6: Add to `send_to_channel()` dispatch (`src/alert/mod.rs`)

```rust
match &channel.channel {
    // ... existing ...
    ChannelType::Slack => self.send_slack(&client, text, integrations).await,
}
```

### Step 7: Use in config

```yaml
integrations:
  slack:
    enabled: true
    webhook_url: "https://hooks.slack.com/services/..."

alerts:
  critical:
    - channel: slack
```

---

## 9. Key Design Patterns Explained

### Pattern: Graceful Degradation in Monitors

Every monitor returns `T::default()` on failure, so a broken monitor doesn't stop others:

```rust
// In monitor/mod.rs
fn unwrap_monitor<T: Default, E1, E2>(result: Result<Result<T, E1>, E2>, name: &str) -> T {
    match result {
        Ok(Ok(metrics)) => metrics,
        Ok(Err(e)) => {
            tracing::error!("{} monitor error: {}", name, e);
            T::default()  // ← zeros, not a crash
        }
        Err(e) => {
            tracing::error!("{} monitor task panicked: {}", name, e);
            T::default()
        }
    }
}
```

**To benefit from this**: any new monitor struct must `#[derive(Default)]`.

---

### Pattern: Atomic Deduplication

The dedup check and dedup record happen under the **same mutex lock**:

```rust
// In detector/mod.rs — this is the CORRECT way:
{
    let mut state = self.state.lock().await;
    if state.is_duplicate(&incident) { continue; }
    state.record_incident(&incident);  // recorded BEFORE releasing lock
}
// Now it's safe to act on the incident — no other task can sneak in
handle_incident(&incident).await;

// WRONG (race condition — don't do this):
// { let s = lock(); if duplicate { continue; } }  ← lock released here
// handle().await;                                  ← another task can see the same incident
// { let mut s = lock(); s.record(); }              ← too late
```

---

### Pattern: Circuit Breaker

Protects against runaway failures. Think of it as a fuse box:

```
Normal:  [Action] → succeeds → counter resets
Failure: [Action] → fails → failure counter++
Trip:    failures > max_failures in window → OPEN state
Open:    [Action] → immediately rejected (no execution)
After open_duration:  → HALF-OPEN state
Half-open: [Action] → one trial execution
  Success → CLOSED (normal)
  Failure → OPEN again (stay tripped)
```

This prevents your `block_ip.sh` from being called 10,000 times per second if it's broken.

---

### Pattern: Per-Channel HTTP Client

Each alert channel gets its own `reqwest::Client` built with that channel's timeout:

```rust
// In send_to_channel():
let client = Self::build_client(channel.timeout);
// channel.timeout is Option<Duration> from config, default: Some(10s)
```

Why not a shared client? Because different channels have different timeout needs:
- Telegram: fast, 5s is plenty
- Your slow corporate email relay: might need 30s
- Emergency webhook: maybe 2s (fail fast, try next channel)

---

### Pattern: Alert Reliability

`send()` returns `Ok(())` if **at least one** channel succeeded. This means:
- Telegram down but Discord works → `Ok(())`, incident handled
- Telegram + Discord both down → `Err(...)`, logged to stderr

The stderr fallback means you never silently lose a critical alert:
```rust
// In alert/mod.rs, run_alert_task:
if let Err(e) = dispatcher.send(&msg).await {
    eprintln!("[PANICMODE ALERT LOST] {}: {}", msg.message, e);
    // stderr is captured by systemd journal
}
```

---

## 10. Common Customizations

### Change the monitoring interval

```yaml
performance:
  check_interval: "30s"  # Default is 5s. Longer = less CPU, slower detection.
```

### Block IPs from attacks automatically

1. Create the scripts:
   ```bash
   sudo mkdir -p /etc/panicmode/scripts

   # block_ip.sh
   echo '#!/bin/bash
   iptables -I INPUT -s "$1" -j DROP' \
     | sudo tee /etc/panicmode/scripts/block_ip.sh
   sudo chmod +x /etc/panicmode/scripts/block_ip.sh

   # unblock_ip.sh (needed for panicmode-ctl unblock)
   echo '#!/bin/bash
   iptables -D INPUT -s "$1" -j DROP' \
     | sudo tee /etc/panicmode/scripts/unblock_ip.sh
   sudo chmod +x /etc/panicmode/scripts/unblock_ip.sh
   ```

2. Configure in `config.yaml`:
   ```yaml
   monitors:
     - name: ssh_brute_force
       type: auth_failures
       threshold: 20.0
       actions: [block_ip, alert_critical]

   firewall:
     enabled: true
     block_script: "/etc/panicmode/scripts/block_ip.sh"
     unblock_script: "/etc/panicmode/scripts/unblock_ip.sh"
     restore_on_startup: true   # re-apply blocks after server reboot
     whitelist:
       # - "YOUR_OFFICE_IP"     # never accidentally block yourself
   ```

3. Manage blocks via CLI:
   ```bash
   panicmode-ctl list              # show all active blocks
   panicmode-ctl unblock 1.2.3.4  # remove a block (runs script + removes from DB)
   ```

The `block_ip` action automatically extracts IPs from the incident's `details` field.
Only **public** IPs are blocked — private (10.x, 192.168.x, 127.x, RFC1918) are always skipped.
Whitelisted IPs are skipped with a log message. Blocks survive server reboots via `restore_on_startup`.

### Run your own script on incidents

1. Create your script (receives incident data as env vars):
   ```bash
   #!/bin/bash
   # /opt/myapp/panicmode-hook.sh
   curl -X POST "https://my-pager.com/alert" \
     -d "incident=$PANIC_INCIDENT_NAME&severity=$PANIC_SEVERITY"
   ```

2. Configure:
   ```yaml
   actions:
     run_script:
       type: script
       action: "/opt/myapp/panicmode-hook.sh"

   monitors:
     - name: high_memory
       type: memory_usage
       threshold: 90.0
       actions: [run_script, alert_warning]
   ```

### Freeze processes during a memory bomb

```yaml
monitors:
  - name: memory_bomb
    type: memory_usage
    threshold: 95.0
    actions: [mass_freeze, alert_critical, snapshot]
```

`mass_freeze` sends SIGSTOP to all processes except those in the whitelist
(`sshd` and `panicmode` are always protected so you can SSH in and fix things).

### Monitor a custom metric

```yaml
custom_metrics:
  app_queue_depth:
    command: "/bin/sh -c \"redis-cli LLEN job_queue\""
    timeout: "3s"
    cache_ttl: "5s"
    output_format: "number"

monitors:
  - name: queue_backed_up
    type: custom
    threshold: 10000.0
    actions: [alert_warning]
```

### Disable an integration without removing its config

```yaml
integrations:
  telegram:
    enabled: false      # ← PanicMode will skip Telegram silently
    bot_token: "..."    # credentials kept for easy re-enabling
    chat_id: "..."
```

### Get notified when PanicMode itself misbehaves

```yaml
performance:
  cpu_limit: 5.0       # If PanicMode uses > 5% CPU → alert
  memory_limit_mb: 50  # If PanicMode uses > 50MB RAM → alert
```

Alerts from self-check always go to the `critical` alert channels.

### Check if PanicMode is alive from another system

```yaml
http_api:
  enabled: true
  bind: "0.0.0.0:8765"  # or 127.0.0.1 for local-only
```

```bash
curl http://your-server:8765/health
# {"status":"ok","uptime_secs":86400}
```

---

## Quick Reference: Where to Find Things

| I want to... | File to look at |
|---|---|
| Change how metrics are collected | `src/monitor/mod.rs`, `src/monitor/cpu.rs` (etc.) |
| Add a new monitor type | `src/config.rs` (MonitorType enum), `src/monitor/`, `src/detector/rules.rs` |
| Change incident detection logic | `src/detector/rules.rs`, `src/detector/anomaly.rs` |
| Add a new protective action | `src/action/trait.rs`, `src/action/implementations/`, `src/action/registry.rs` |
| Change alert sending logic | `src/alert/mod.rs` |
| Add a new alert channel | `src/config.rs` (ChannelType), `src/alert/mod.rs` |
| Change deduplication window | `src/detector/state.rs` |
| Change rate limiting | `src/detector/mod.rs` (look for `rate_limit`) |
| Change circuit breaker behavior | `src/detector/circuit_breaker.rs`, `src/config.rs` (CircuitBreakerConfig) |
| Change what gets persisted | `src/storage.rs` |
| Change startup/shutdown behavior | `src/main.rs` |
| Configure IP blocking (scripts, whitelist) | `src/config.rs` (FirewallConfig), `src/action/implementations/firewall.rs` |
| Manage blocked IPs via CLI | `src/ctl/mod.rs` (socket server), `src/bin/panicmode-ctl.rs` (CLI) |
| Understand all config fields | `src/config.rs` (struct definitions + serde defaults) |
