# PanicMode

> Self-hosted server monitoring with intelligent panic mode and automatic alerts

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/BorisYamp/panicmode)
[![Platform: Linux](https://img.shields.io/badge/platform-Linux-lightgrey.svg)](https://github.com/BorisYamp/panicmode)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)](https://www.rust-lang.org)

PanicMode watches your Linux server and takes action the moment something goes wrong — before you even check your phone.

---

## What It Does

- **Monitors** CPU, memory, disk, network connections, authentication failures, and custom metrics
- **Detects** threshold breaches and anomalies (spikes, suspicious IPs, brute-force attempts)
- **Acts** immediately — freeze runaway processes, block attacking IPs, take system snapshots
- **Alerts** you via Telegram, email, Discord, ntfy, or phone call (Twilio)
- **Persists** every incident to SQLite for post-mortem analysis
- **Survives** failures — each task is supervised and restarted on crash

---

## Quick Start

### Prerequisites

- Linux (x86\_64 or aarch64)
- Rust 1.75+ (`curl https://sh.rustup.rs -sSf | sh`)

### Build & Install

```bash
git clone https://github.com/BorisYamp/panicmode.git
cd panicmode
cargo build --release
sudo cp target/release/panicmode /usr/local/bin/
sudo cp target/release/panicmode-ctl /usr/local/bin/
```

### Minimal Configuration

Create `/etc/panicmode/config.yaml`:

```yaml
performance:
  cpu_limit: 5.0
  memory_limit_mb: 50
  check_interval: "5s"

monitors:
  - name: "High CPU"
    type: cpu_usage
    threshold: 90.0
    actions: [alert_critical]
    enabled: true

  - name: "High Memory"
    type: memory_usage
    threshold: 85.0
    actions: [alert_warning]
    enabled: true

alerts:
  critical:
    - channel: telegram
  warning:
    - channel: telegram

integrations:
  telegram:
    enabled: true
    bot_token: "YOUR_BOT_TOKEN"
    chat_id: "YOUR_CHAT_ID"
```

### Run

```bash
sudo panicmode /etc/panicmode/config.yaml
```

Logs go to `/var/log/panicmode/panicmode.log` (daily rotation) and stdout. Override log level with `RUST_LOG=debug`.

See [QUICKSTART.md](QUICKSTART.md) for detailed setup of each alert channel.

---

## Alert Channels

| Channel | Free | Setup time |
|---|---|---|
| Telegram | ✅ | ~2 min |
| ntfy (push) | ✅ | ~1 min |
| Discord webhook | ✅ | ~2 min |
| Email (SMTP) | ✅ | ~5 min |
| Twilio phone call | 💰 ~$1/mo | ~5 min |

---

## What Gets Monitored

| Monitor | What it tracks |
|---|---|
| `cpu_usage` | CPU % over a rolling window |
| `memory_usage` | RAM + swap utilization |
| `swap_usage` | Swap pressure |
| `load_average` | 1/5/15 min load averages |
| `disk_usage` | Per-mount disk fill % |
| `disk_io` | Read/write throughput and IOPS |
| `network_connections` | Total open connections |
| `auth_failures` | Failed SSH/sudo logins, brute-force IPs |
| `file_changes` | Modifications to watched paths |
| `custom_metrics` | Output of your own scripts |

---

## Protective Actions

When an incident fires, PanicMode can:

- **`freeze_processes`** — SIGSTOP the top CPU offenders (whitelists `sshd`, `panicmode`, etc.)
- **`block_ip`** — Run your firewall script to drop the attacking IP; blocks are persisted in SQLite and restored after reboot; manage with `panicmode-ctl list` / `panicmode-ctl unblock <IP>`
- **`snapshot`** — Capture `ps`, `netstat`, `free`, `df`, `uptime` to a timestamped file
- **`run_script`** — Execute any custom script with incident context in environment variables
- **`alert_critical` / `alert_warning`** — Send notifications through configured channels

---

## Configuration Reference

See [exampels/config.yaml](exampels/config.yaml) for a fully-annotated example.

Key sections:

```yaml
storage:        # paths for DB, snapshots, logs
monitors:       # which metrics to watch and thresholds
alerts:         # Telegram / email / Discord / ntfy / Twilio
integrations:   # credentials for each alert channel
performance:    # polling intervals, timeouts
firewall:       # block_ip script paths, whitelist, restore_on_startup
actions:        # per-action settings (script paths, etc.)
```

For process freeze whitelist, create `/etc/panicmode/mass_freeze.yaml` (see [exampels/mass_freeze.yaml](exampels/mass_freeze.yaml)).

---

## Architecture

PanicMode runs five supervised async tasks plus one auxiliary (ctl socket):

```
MonitorEngine ──metrics──▶ Detector ──incidents──▶ IncidentHandler
                                                         │
                                               ActionExecutor  AlertDispatcher
                                                    │    │
                                             FirewallAction  (other actions)
                                                    │
                                             IncidentStorage (SQLite)
                                                    │
                                             CtlServer ◀── panicmode-ctl (CLI)
                                          (Unix socket, aux)
```

See [arch.txt](arch.txt) for the full architecture document.

---

## License

Licensed under either of:

- [MIT License](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)

at your option.
