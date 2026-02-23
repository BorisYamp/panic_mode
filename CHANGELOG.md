# Changelog

All notable changes to PanicMode will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] — 2024

### Added

**Monitoring**
- CPU usage monitor with configurable threshold and rolling window
- Memory usage monitor (RAM + swap)
- Swap usage monitor
- Load average monitor (1/5/15 min)
- Disk usage monitor (per-mount)
- Disk I/O monitor (read/write throughput and IOPS via `/proc/diskstats`)
- Network connections monitor (total open connections)
- Auth failures monitor (failed SSH/sudo logins, brute-force IP detection via `/var/log/auth.log`)
- File watcher monitor (filesystem change notifications via `notify`)
- Custom metrics monitor (arbitrary script output)

**Detection**
- Rule-based threshold evaluation (`RuleEvaluator`)
- Anomaly detection with configurable spike thresholds (`AnomalyDetector`)
- Incident deduplication — same incident is not re-processed within cooldown window
- Rate limiting per incident type (Critical: 60 s, Warning: 300 s)
- Escalation tracker for on-call rotation
- Circuit breaker on action executor — opens after repeated failures, resets automatically

**Actions**
- `freeze_processes` — SIGSTOP top CPU offenders (configurable count, whitelist for `sshd`, `panicmode`, etc.)
- `block_ip` — invoke user-supplied firewall script per attacking IP
- `snapshot` — capture `ps`, `netstat`, `free`, `df`, `uptime` to a timestamped file
- `run_script` — execute custom script with incident context via environment variables
- `alert_critical` / `alert_warning` — dispatch notifications

**Alerting**
- Telegram bot
- Email (SMTP with TLS — Gmail, Outlook, Yahoo, ProtonMail)
- Discord webhook
- ntfy push notifications
- Twilio phone call (optional feature flag)
- Per-channel enable/disable
- Concurrent dispatch — alerts sent in parallel

**Storage & Logging**
- SQLite incident log (every fired incident persisted for post-mortem)
- Graceful fallback to in-memory SQLite if DB path is not accessible
- File logging with daily rotation (`tracing-appender`)
- `RUST_LOG` environment variable support for log level override
- System snapshots saved to configurable directory

**Infrastructure**
- Four supervised async tasks: Monitoring, Detector, Alert, Self-Check
- Each task restarts on failure (up to `MAX_TASK_FAILURES`)
- Graceful shutdown on SIGINT (drains alert queue with per-message timeout)
- `tokio::select!`-based cancellation (no polling loops)
- `CancellationToken` propagated to all tasks
- Configurable via YAML (`/etc/panicmode/config.yaml`)
- All paths configurable via `storage:` section

[0.1.0]: https://github.com/BorisYamp/panicmode/releases/tag/v0.1.0
