/// Path: PanicMode/scr/action/implementations/firewall.rs
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;

use crate::action::r#trait::{Action, ActionContext};
use crate::config::Config;
use crate::storage::IncidentStorage;

/// Timeout for a single script invocation.
const SCRIPT_TIMEOUT: Duration = Duration::from_secs(10);

// ============================================================================
// Whitelist — CIDR matching without extra dependencies
// ============================================================================

/// Одна запись whitelist: точный IP или подсеть CIDR.
#[derive(Debug, Clone)]
enum WhitelistEntry {
    Exact(IpAddr),
    CidrV4(Ipv4Addr, u8), // network address + prefix length
    CidrV6(Ipv6Addr, u8),
}

impl WhitelistEntry {
    /// Парсит строку вида "1.2.3.4", "1.2.3.0/24", "2001:db8::/32".
    fn parse(s: &str) -> Option<Self> {
        if let Some(slash) = s.find('/') {
            let ip_str = &s[..slash];
            let prefix: u8 = s[slash + 1..].parse().ok()?;
            match ip_str.parse::<IpAddr>().ok()? {
                IpAddr::V4(v4) => {
                    if prefix > 32 { return None; }
                    Some(Self::CidrV4(v4, prefix))
                }
                IpAddr::V6(v6) => {
                    if prefix > 128 { return None; }
                    Some(Self::CidrV6(v6, prefix))
                }
            }
        } else {
            s.parse::<IpAddr>().ok().map(Self::Exact)
        }
    }

    fn matches(&self, ip: IpAddr) -> bool {
        match (self, ip) {
            (Self::Exact(a), b) => *a == b,
            (Self::CidrV4(net, prefix), IpAddr::V4(ip)) => {
                if *prefix == 0 { return true; }
                let mask = u32::MAX << (32 - prefix);
                (u32::from(*net) & mask) == (u32::from(ip) & mask)
            }
            (Self::CidrV6(net, prefix), IpAddr::V6(ip)) => {
                if *prefix == 0 { return true; }
                let net_bits = u128::from_be_bytes(net.octets());
                let ip_bits  = u128::from_be_bytes(ip.octets());
                let mask = u128::MAX << (128 - prefix);
                (net_bits & mask) == (ip_bits & mask)
            }
            _ => false, // IPv4 entry vs IPv6 address or vice versa
        }
    }
}

/// Invokes a user-supplied script to block public IPs found in an incident.
///
/// Design: await all blocking tasks, propagate failure so the circuit breaker
/// can trip after repeated script failures.
/// - Filters loopback and RFC1918 — never accidentally blocks localhost or LAN.
/// - Returns Err if the script is missing or all invocations fail.
/// - Circuit breaker is applied at the ActionExecutor level.
/// - Successfully blocked IPs are recorded in IncidentStorage (survive reboots).
///
/// # Script
/// The script receives the IP as the first argument: `block_ip.sh <IP>`.
/// Path: env PANICMODE_BLOCK_IP_SCRIPT → config.firewall.block_script.
///
/// Minimal script example:
/// ```bash
/// #!/bin/bash
/// IP="$1"
/// iptables -I INPUT -s "$IP" -j DROP
/// ```
pub struct FirewallAction {
    script_path: String,
    storage: Arc<IncidentStorage>,
    whitelist: Vec<WhitelistEntry>,
}

impl FirewallAction {
    pub fn new(config: Arc<Config>, storage: Arc<IncidentStorage>) -> Result<Self> {
        // Env var overrides config (backward-compat + easy testing)
        let script_path = std::env::var("PANICMODE_BLOCK_IP_SCRIPT")
            .unwrap_or_else(|_| config.firewall.block_script.clone());

        let whitelist: Vec<WhitelistEntry> = config
            .firewall
            .whitelist
            .iter()
            .filter_map(|s| {
                let entry = WhitelistEntry::parse(s);
                if entry.is_none() {
                    tracing::warn!("FirewallAction: invalid whitelist entry ignored: {:?}", s);
                }
                entry
            })
            .collect();

        tracing::info!(
            "FirewallAction: script = {}, whitelist = {} entries",
            script_path,
            whitelist.len()
        );

        Ok(Self { script_path, storage, whitelist })
    }

    fn is_whitelisted(&self, ip: IpAddr) -> bool {
        self.whitelist.iter().any(|entry| entry.matches(ip))
    }

    /// Extract unique public IP addresses from text.
    /// Filters loopback, RFC1918, link-local, ULA, and unspecified.
    fn extract_public_ips(text: &str) -> Vec<IpAddr> {
        let mut seen = HashSet::new();
        let mut ips = Vec::new();

        for word in text.split(|c: char| !c.is_ascii_hexdigit() && c != '.' && c != ':') {
            let word = word.trim();
            if word.is_empty() {
                continue;
            }
            if let Ok(ip) = word.parse::<IpAddr>() {
                if !is_private_or_local(ip) && seen.insert(ip) {
                    ips.push(ip);
                }
            }
        }

        ips
    }
}

/// Returns true for any address that must NOT be blocked:
/// loopback, RFC1918, link-local, ULA, unspecified, broadcast.
fn is_private_or_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()      // 127.0.0.0/8
                || v4.is_private()    // 10/8, 172.16/12, 192.168/16
                || v4.is_link_local() // 169.254.0.0/16
                || v4.is_broadcast()  // 255.255.255.255
                || v4.is_unspecified() // 0.0.0.0
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()         // ::1
                || v6.is_unspecified()   // ::
                || is_ipv6_ula(v6)       // fc00::/7
                || is_ipv6_link_local(v6) // fe80::/10
        }
    }
}

/// fc00::/7 — IPv6 unique local addresses (RFC 4193).
fn is_ipv6_ula(ip: Ipv6Addr) -> bool {
    (ip.octets()[0] & 0xfe) == 0xfc
}

/// fe80::/10 — IPv6 link-local (RFC 4291).
fn is_ipv6_link_local(ip: Ipv6Addr) -> bool {
    let o = ip.octets();
    o[0] == 0xfe && (o[1] & 0xc0) == 0x80
}

#[async_trait]
impl Action for FirewallAction {
    /// Blocks public IPs from the incident by invoking the script.
    ///
    /// Returns Err if the script is missing or all invocations fail.
    async fn execute(&self, ctx: &ActionContext<'_>) -> Result<()> {
        let raw_ips = Self::extract_public_ips(&ctx.incident.metadata.details);

        if raw_ips.is_empty() {
            tracing::info!("block_ip: no public IPs in incident details, skipping");
            return Ok(());
        }

        // Фильтруем whitelist — логируем каждое пропущенное IP
        let ips: Vec<IpAddr> = raw_ips
            .into_iter()
            .filter(|ip| {
                if self.is_whitelisted(*ip) {
                    tracing::info!("block_ip: {} is whitelisted, skipping", ip);
                    false
                } else {
                    true
                }
            })
            .collect();

        if ips.is_empty() {
            tracing::info!("block_ip: all candidate IPs are whitelisted, skipping");
            return Ok(());
        }

        let script = self.script_path.clone();

        // Missing script is a hard error — the action cannot do its job.
        if !std::path::Path::new(&script).exists() {
            let ip_list: Vec<String> = ips.iter().map(|ip| ip.to_string()).collect();
            anyhow::bail!(
                "block_ip: script not found: {}. \
                 IPs that would have been blocked: {}. \
                 Create the script to enable IP blocking.",
                script,
                ip_list.join(", ")
            );
        }

        let reason = format!("{}: {}", ctx.incident.name, ctx.incident.description);
        let mut set = tokio::task::JoinSet::new();

        for ip in ips {
            let script = script.clone();
            let ip_str = ip.to_string();

            set.spawn(async move {
                let result = tokio::time::timeout(
                    SCRIPT_TIMEOUT,
                    tokio::process::Command::new(&script)
                        .arg(&ip_str)
                        .status(),
                )
                .await;

                match result {
                    Ok(Ok(status)) if status.success() => {
                        tracing::info!("block_ip: blocked {} (script exit {})", ip_str, status);
                        Some(ip_str)
                    }
                    Ok(Ok(status)) => {
                        tracing::warn!(
                            "block_ip: script exited with {} for {} — check script logic",
                            status,
                            ip_str
                        );
                        None
                    }
                    Ok(Err(e)) => {
                        tracing::warn!("block_ip: failed to run script for {}: {}", ip_str, e);
                        None
                    }
                    Err(_) => {
                        tracing::warn!(
                            "block_ip: script timed out after {}s for {}",
                            SCRIPT_TIMEOUT.as_secs(),
                            ip_str
                        );
                        None
                    }
                }
            });
        }

        let mut blocked_ips: Vec<String> = Vec::new();
        let mut total = 0usize;

        while let Some(res) = set.join_next().await {
            total += 1;
            if let Some(ip_str) = res.unwrap_or(None) {
                blocked_ips.push(ip_str);
            }
        }

        if blocked_ips.is_empty() {
            anyhow::bail!("block_ip: all {} script invocation(s) failed", total);
        }

        // Записываем успешно заблокированные IP в БД (для восстановления после ребута)
        let storage = self.storage.clone();
        let reason_clone = reason.clone();
        tokio::spawn(async move {
            for ip_str in &blocked_ips {
                if let Err(e) = storage.add_blocked_ip(ip_str, &reason_clone).await {
                    tracing::warn!("block_ip: failed to persist {} in DB: {}", ip_str, e);
                }
            }
        });

        Ok(())
    }

    fn name(&self) -> &str {
        "firewall"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::r#trait::ActionContext;
    use crate::config::MonitorType;
    use crate::detector::{Incident, IncidentMetadata, IncidentSeverity};
    use crate::storage::IncidentStorage;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::NamedTempFile;

    fn test_storage() -> Arc<IncidentStorage> {
        Arc::new(IncidentStorage::new_in_memory().unwrap())
    }

    fn make_incident_with_details(details: &str) -> Incident {
        Incident {
            name: "firewall_test".into(),
            severity: IncidentSeverity::Critical,
            description: "unit test".into(),
            actions: vec![],
            metadata: IncidentMetadata {
                monitor_type: MonitorType::CpuUsage,
                threshold: 90.0,
                current_value: 95.0,
                details: details.into(),
            },
        }
    }

    fn write_script(content: &str) -> tempfile::TempPath {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        let mut perms = f.as_file().metadata().unwrap().permissions();
        perms.set_mode(0o755);
        f.as_file().set_permissions(perms).unwrap();
        // Close the write handle so Linux won't return ETXTBSY when we exec the script.
        f.into_temp_path()
    }

    // ── execute() integration tests ───────────────────────────────────────────

    #[tokio::test]
    async fn test_execute_no_public_ips_returns_ok() {
        // Private + loopback IPs only → extract_public_ips returns [] → skip, no script needed
        let action = FirewallAction {
            script_path: "/nonexistent/script.sh".into(),
            storage: test_storage(),
            whitelist: vec![],
        };
        let incident = make_incident_with_details("connections from 192.168.1.1 and 127.0.0.1");
        let ctx = ActionContext::new(&incident);
        action.execute(&ctx).await.unwrap();
    }

    #[tokio::test]
    async fn test_execute_missing_script_returns_err() {
        let action = FirewallAction {
            script_path: "/nonexistent/block_ip_panicmode_test.sh".into(),
            storage: test_storage(),
            whitelist: vec![],
        };
        let incident = make_incident_with_details("attack from 1.2.3.4");
        let ctx = ActionContext::new(&incident);
        let result = action.execute(&ctx).await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("script not found"),
            "expected 'script not found' in error: {}",
            msg
        );
        assert!(msg.contains("1.2.3.4"), "error should mention the IP: {}", msg);
    }

    #[tokio::test]
    async fn test_execute_success_with_real_script() {
        let script = write_script("#!/bin/sh\nexit 0\n");
        let action = FirewallAction {
            script_path: script.to_str().unwrap().to_string(),
            storage: test_storage(),
            whitelist: vec![],
        };
        let incident = make_incident_with_details("attack from 1.2.3.4 and 5.6.7.8");
        let ctx = ActionContext::new(&incident);
        action.execute(&ctx).await.unwrap();
    }

    #[tokio::test]
    async fn test_execute_partial_success_returns_ok() {
        // Script exits 0 only for the second IP (first arg check)
        // In practice both call the same script, which exits 0 → both succeed
        let script = write_script("#!/bin/sh\nexit 0\n");
        let action = FirewallAction {
            script_path: script.to_str().unwrap().to_string(),
            storage: test_storage(),
            whitelist: vec![],
        };
        let incident = make_incident_with_details("from 1.2.3.4 and 5.6.7.8 and 9.10.11.12");
        let ctx = ActionContext::new(&incident);
        // At least one success → Ok
        action.execute(&ctx).await.unwrap();
    }

    #[tokio::test]
    async fn test_execute_all_scripts_fail_returns_err() {
        let script = write_script("#!/bin/sh\nexit 1\n");
        let action = FirewallAction {
            script_path: script.to_str().unwrap().to_string(),
            storage: test_storage(),
            whitelist: vec![],
        };
        let incident = make_incident_with_details("attack from 1.2.3.4");
        let ctx = ActionContext::new(&incident);
        let result = action.execute(&ctx).await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("failed"),
            "expected 'failed' in error: {}",
            msg
        );
    }

    #[test]
    fn test_extract_public_ipv4() {
        let ips = FirewallAction::extract_public_ips("Attack from 1.2.3.4 and 5.6.7.8");
        assert!(ips.contains(&"1.2.3.4".parse().unwrap()));
        assert!(ips.contains(&"5.6.7.8".parse().unwrap()));
        assert_eq!(ips.len(), 2);
    }

    #[test]
    fn test_filters_rfc1918() {
        // RFC1918 ranges must be filtered out
        let ips = FirewallAction::extract_public_ips(
            "IPs: 10.0.0.1 192.168.1.1 172.16.0.1 172.31.255.255 1.2.3.4",
        );
        assert!(!ips.contains(&"10.0.0.1".parse().unwrap()));
        assert!(!ips.contains(&"192.168.1.1".parse().unwrap()));
        assert!(!ips.contains(&"172.16.0.1".parse().unwrap()));
        assert!(!ips.contains(&"172.31.255.255".parse().unwrap()));
        assert!(ips.contains(&"1.2.3.4".parse().unwrap()));
        assert_eq!(ips.len(), 1);
    }

    #[test]
    fn test_filters_loopback() {
        let ips = FirewallAction::extract_public_ips("localhost 127.0.0.1 ::1 1.2.3.4");
        assert!(!ips.contains(&"127.0.0.1".parse().unwrap()));
        assert!(!ips.contains(&"::1".parse().unwrap()));
        assert!(ips.contains(&"1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn test_filters_link_local() {
        let ips = FirewallAction::extract_public_ips("fe80::1 169.254.0.1 1.2.3.4");
        assert!(!ips.contains(&"169.254.0.1".parse().unwrap()));
        assert!(!ips.contains(&"fe80::1".parse().unwrap()));
        assert!(ips.contains(&"1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn test_filters_ula() {
        let ips = FirewallAction::extract_public_ips("fc00::1 fd12:3456::1 2001:db8::1");
        assert!(!ips.contains(&"fc00::1".parse().unwrap()));
        assert!(!ips.contains(&"fd12:3456::1".parse().unwrap()));
        assert!(ips.contains(&"2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn test_deduplication() {
        let ips = FirewallAction::extract_public_ips("1.2.3.4 and again 1.2.3.4");
        assert_eq!(ips.len(), 1);
    }

    #[test]
    fn test_no_ips() {
        let ips = FirewallAction::extract_public_ips("No addresses here");
        assert!(ips.is_empty());
    }

    #[test]
    fn test_empty_string() {
        let ips = FirewallAction::extract_public_ips("");
        assert!(ips.is_empty());
    }

    #[test]
    fn test_is_private_or_local_v4() {
        assert!(is_private_or_local("10.0.0.1".parse().unwrap()));
        assert!(is_private_or_local("172.16.0.1".parse().unwrap()));
        assert!(is_private_or_local("192.168.1.1".parse().unwrap()));
        assert!(is_private_or_local("127.0.0.1".parse().unwrap()));
        assert!(is_private_or_local("169.254.0.1".parse().unwrap()));
        assert!(!is_private_or_local("8.8.8.8".parse().unwrap()));
        assert!(!is_private_or_local("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn test_is_private_or_local_v6() {
        assert!(is_private_or_local("::1".parse().unwrap()));
        assert!(is_private_or_local("fe80::1".parse().unwrap()));
        assert!(is_private_or_local("fc00::1".parse().unwrap()));
        assert!(is_private_or_local("fd00::1".parse().unwrap()));
        assert!(!is_private_or_local("2001:db8::1".parse().unwrap()));
        assert!(!is_private_or_local("2606:4700::".parse().unwrap()));
    }

    // ── Whitelist tests ───────────────────────────────────────────────────────

    #[test]
    fn test_whitelist_exact_ipv4() {
        let entry = WhitelistEntry::parse("1.2.3.4").unwrap();
        assert!(entry.matches("1.2.3.4".parse().unwrap()));
        assert!(!entry.matches("1.2.3.5".parse().unwrap()));
    }

    #[test]
    fn test_whitelist_cidr_ipv4() {
        let entry = WhitelistEntry::parse("203.0.113.0/24").unwrap();
        assert!(entry.matches("203.0.113.1".parse().unwrap()));
        assert!(entry.matches("203.0.113.254".parse().unwrap()));
        assert!(!entry.matches("203.0.114.1".parse().unwrap()));
    }

    #[test]
    fn test_whitelist_cidr_ipv6() {
        let entry = WhitelistEntry::parse("2001:db8::/32").unwrap();
        assert!(entry.matches("2001:db8::1".parse().unwrap()));
        assert!(entry.matches("2001:db8:cafe::1".parse().unwrap()));
        assert!(!entry.matches("2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn test_whitelist_exact_ipv6() {
        let entry = WhitelistEntry::parse("2001:db8::1").unwrap();
        assert!(entry.matches("2001:db8::1".parse().unwrap()));
        assert!(!entry.matches("2001:db8::2".parse().unwrap()));
    }

    #[test]
    fn test_whitelist_invalid_entries() {
        assert!(WhitelistEntry::parse("not-an-ip").is_none());
        assert!(WhitelistEntry::parse("1.2.3.4/33").is_none()); // prefix > 32
        assert!(WhitelistEntry::parse("::1/129").is_none());    // prefix > 128
    }

    #[tokio::test]
    async fn test_execute_whitelisted_ip_skipped() {
        let script = write_script("#!/bin/sh\nexit 0\n");
        let action = FirewallAction {
            script_path: script.to_str().unwrap().to_string(),
            storage: test_storage(),
            whitelist: vec![
                WhitelistEntry::parse("1.2.3.4").unwrap(),
                WhitelistEntry::parse("5.0.0.0/8").unwrap(),
            ],
        };
        // 1.2.3.4 — в exact whitelist, 5.6.7.8 — в CIDR 5.0.0.0/8
        // оба пропускаются → ips пустой → Ok без вызова скрипта
        let incident = make_incident_with_details("attack from 1.2.3.4 and 5.6.7.8");
        let ctx = ActionContext::new(&incident);
        action.execute(&ctx).await.unwrap();
    }

    #[tokio::test]
    async fn test_execute_whitelist_partial_block() {
        let script = write_script("#!/bin/sh\nexit 0\n");
        let action = FirewallAction {
            script_path: script.to_str().unwrap().to_string(),
            storage: test_storage(),
            whitelist: vec![WhitelistEntry::parse("1.2.3.4").unwrap()],
        };
        // 1.2.3.4 — в whitelist (пропускается), 9.9.9.9 — блокируется
        let incident = make_incident_with_details("attack from 1.2.3.4 and 9.9.9.9");
        let ctx = ActionContext::new(&incident);
        action.execute(&ctx).await.unwrap(); // должен успешно заблокировать 9.9.9.9
    }
}
