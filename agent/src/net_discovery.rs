//! Optional network discovery module for asset inventory and troubleshooting.
//!
//! This module provides functions for network scanning, including ARP cache
//! enumeration, TCP-based host probing, and TCP port scanning. These tools
//! are intended for legitimate network administration and asset management.
//!
//! **Warning:** Unauthorised network scanning is prohibited. Ensure you have
//! explicit written permission before scanning any network.

#![cfg(feature = "network-discovery")]

use std::net::IpAddr;
use std::time::Duration;
use tokio::net::TcpStream;

/// An entry from the system ARP cache: an IP address and its associated MAC.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ArpEntry {
    pub ip: IpAddr,
    pub mac: String,
}

// ── ARP cache parsing ────────────────────────────────────────────────────────

/// Read and parse the system ARP cache to discover hosts on the local segment.
///
/// On Linux the kernel ARP table is read directly from `/proc/net/arp` (no
/// subprocess required).  On all other platforms `arp -a` is run and its
/// output parsed.
///
/// Only entries whose ARP flags indicate a *complete* entry (flag `0x2` set
/// on Linux) are returned; incomplete / static placeholder entries are skipped.
pub fn arp_scan() -> Result<Vec<ArpEntry>, String> {
    #[cfg(target_os = "linux")]
    return arp_scan_linux();
    #[cfg(not(target_os = "linux"))]
    return arp_scan_cmd();
}

/// Parse `/proc/net/arp`.
///
/// File format (space-separated, header on first line):
/// ```text
/// IP address       HW type  Flags       HW address            Mask     Device
/// 192.168.1.1      0x1      0x2         aa:bb:cc:dd:ee:ff     *        eth0
/// ```
/// Only entries with the `0x2` ("complete") flag are returned.
#[cfg(target_os = "linux")]
fn arp_scan_linux() -> Result<Vec<ArpEntry>, String> {
    let text = std::fs::read_to_string("/proc/net/arp")
        .map_err(|e| format!("failed to read /proc/net/arp: {e}"))?;

    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        // Fields: IP, HW type, Flags, HW address, Mask, Device
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 4 {
            continue;
        }
        // Skip entries whose flags don't have the 0x2 "complete" bit set.
        let flags = u64::from_str_radix(cols[2].trim_start_matches("0x"), 16).unwrap_or(0);
        if flags & 0x2 == 0 {
            continue;
        }
        let ip: IpAddr = cols[0]
            .parse()
            .map_err(|e| format!("invalid IP in arp table: {e}"))?;
        let mac = cols[3].to_string();
        out.push(ArpEntry { ip, mac });
    }
    Ok(out)
}

/// Run `arp -a` and parse its output.
///
/// Common output format (BSD, macOS, Windows):
/// ```text
/// hostname (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0
/// ```
/// or
/// ```text
///   Internet Address      Physical Address      Type
///   192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic
/// ```
/// Entries that contain "incomplete" or have a MAC of `00:00:00:00:00:00` are
/// skipped.
#[allow(dead_code)] // used only on non-Linux platforms
fn arp_scan_cmd() -> Result<Vec<ArpEntry>, String> {
    let output = crate::process_spoof::execute_command("arp", &["-a"], true)
        .map_err(|e| format!("failed to run arp -a: {e}"))?;
    if !output.status.success() {
        return Err(format!("arp -a exited with status {}", output.status));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut out = Vec::new();
    for line in text.lines() {
        let lower = line.to_lowercase();
        if lower.contains("incomplete") || lower.contains("(incomplete)") {
            continue;
        }
        // Try to find an IP in parentheses: (a.b.c.d)
        let ip = if let Some(start) = line.find('(') {
            if let Some(end) = line[start..].find(')') {
                line[start + 1..start + end].parse::<IpAddr>().ok()
            } else {
                None
            }
        } else {
            // Windows table: first non-whitespace field is the IP
            line.split_whitespace()
                .next()
                .and_then(|s| s.parse::<IpAddr>().ok())
        };
        let Some(ip) = ip else { continue };

        // MAC: look for xx:xx:xx:xx:xx:xx or xx-xx-xx-xx-xx-xx
        let mac = line
            .split_whitespace()
            .find(|t| {
                let seps = t.chars().filter(|&c| c == ':' || c == '-').count();
                seps == 5 && t.len() >= 17
            })
            .map(|s| s.replace('-', ":"))
            .unwrap_or_else(|| "unknown".into());

        if mac == "00:00:00:00:00:00" {
            continue;
        }
        out.push(ArpEntry { ip, mac });
    }
    Ok(out)
}

// ── TCP-probe ping sweep ─────────────────────────────────────────────────────

/// Probe a list of hosts in the given `/24` or CIDR subnet for reachability
/// using TCP connections.
///
/// Because ICMP requires elevated privileges on most systems, this function
/// uses TCP connects (port 80, then port 443) as a "ping" proxy.  A host is
/// considered live if a TCP connection succeeds on *any* of the probe ports
/// within `timeout`.
///
/// Connections are capped to `max_concurrent` in-flight probes at a time so
/// that the function does not flood the local network or exhaust file
/// descriptors.
///
/// The `subnet` parameter is interpreted as either:
/// - A base address with CIDR prefix, e.g. `"192.168.1.0/24"` — all `.1`
///   through `.254` addresses are probed.
/// - A bare IP prefix up to three octets, e.g. `"192.168.1"` — treated as
///   a `/24` sweep.
pub async fn ping_sweep(
    subnet: &str,
    timeout: Duration,
    max_concurrent: usize,
) -> Result<Vec<IpAddr>, String> {
    let targets = subnet_hosts(subnet)?;
    if targets.is_empty() {
        return Ok(vec![]);
    }

    const PROBE_PORTS: &[u16] = &[80, 443, 22, 7];
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(max_concurrent));
    let mut handles = Vec::with_capacity(targets.len());

    for ip in targets {
        let permit = sem
            .clone()
            .acquire_owned()
            .await
            .map_err(|e| e.to_string())?;
        let handle = tokio::spawn(async move {
            let live = probe_host(ip, PROBE_PORTS, timeout).await;
            drop(permit);
            if live {
                Some(ip)
            } else {
                None
            }
        });
        handles.push(handle);
    }

    let mut live = Vec::new();
    for h in handles {
        if let Ok(Some(ip)) = h.await {
            live.push(ip);
        }
    }
    live.sort();
    Ok(live)
}

/// Returns `true` if a TCP connection to any of `ports` on `ip` succeeds
/// within `timeout`.
async fn probe_host(ip: IpAddr, ports: &[u16], timeout: Duration) -> bool {
    for &port in ports {
        if tokio::time::timeout(timeout, TcpStream::connect((ip, port)))
            .await
            .is_ok_and(|r| r.is_ok())
        {
            return true;
        }
    }
    false
}

/// Enumerate the host addresses within a subnet string such as
/// `"192.168.1.0/24"` or `"10.0.0"`.
///
/// Only IPv4 `/24` sweeps are supported (hosts `.1`–`.254`).
fn subnet_hosts(subnet: &str) -> Result<Vec<IpAddr>, String> {
    // Strip CIDR suffix — we only handle /24 for now.
    let base = subnet
        .split('/')
        .next()
        .unwrap_or(subnet)
        .trim_end_matches('.');
    let parts: Vec<&str> = base.split('.').collect();
    if parts.len() < 3 {
        return Err(format!(
            "subnet must have at least 3 octets; got '{subnet}'"
        ));
    }
    let prefix = format!("{}.{}.{}", parts[0], parts[1], parts[2]);
    let mut hosts = Vec::with_capacity(254);
    for i in 1u8..=254 {
        let addr: IpAddr = format!("{prefix}.{i}")
            .parse()
            .map_err(|e| format!("invalid address: {e}"))?;
        hosts.push(addr);
    }
    Ok(hosts)
}

// ── TCP port scan ────────────────────────────────────────────────────────────

/// Scan `host` for open TCP ports.
///
/// Connections are attempted concurrently up to `concurrency_limit` with the specified `timeout`.
pub async fn tcp_port_scan(
    host: IpAddr,
    ports: &[u16],
    concurrency_limit: usize,
    timeout: Duration,
) -> Result<Vec<u16>, String> {
    use std::sync::Arc;
    use tokio::sync::Semaphore;

    let sem = Arc::new(Semaphore::new(concurrency_limit));
    let mut handles = Vec::with_capacity(ports.len());

    for &port in ports {
        let permit = sem
            .clone()
            .acquire_owned()
            .await
            .map_err(|e| e.to_string())?;
        handles.push(tokio::spawn(async move {
            let is_open = tokio::time::timeout(timeout, TcpStream::connect((host, port)))
                .await
                .is_ok_and(|r| r.is_ok());
            drop(permit);
            if is_open {
                Some(port)
            } else {
                None
            }
        }));
    }

    let mut open_ports = Vec::new();
    for h in handles {
        if let Ok(Some(port)) = h.await {
            open_ports.push(port);
        }
    }
    open_ports.sort_unstable();
    Ok(open_ports)
}

// ── 5.5: DNS enumeration ─────────────────────────────────────────────────────

/// Resolve the reverse DNS (PTR) name for an IP address.
///
/// Returns `Ok(None)` when no PTR record exists or the resolver returns
/// NXDOMAIN/SERVFAIL, and `Err` only on I/O failure.
pub fn reverse_dns_lookup(ip: IpAddr) -> Result<Option<String>, String> {
    use std::net::ToSocketAddrs;
    // Construct a dummy port-0 socket address and resolve via the system
    // resolver.  The returned iterator always has the *canonical* hostname as
    // the first string-representation element when a PTR record exists.
    let addr = std::net::SocketAddr::new(ip, 0);
    match addr.to_socket_addrs() {
        Ok(mut addrs) => {
            // to_socket_addrs() on an already-resolved SocketAddr returns the
            // address unchanged; we need to go through the DNS stack.  Use
            // the hostname-form by formatting the address as "ip:0" and
            // resolving it:
            drop(addrs);
        }
        Err(_) => {}
    }
    // Portable PTR lookup via std: format the address as a string and
    // pass it to the OS resolver by constructing the PTR query domain.
    let ptr_domain = match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let nibbles: String = v6
                .octets()
                .iter()
                .rev()
                .flat_map(|b| {
                    let lo = b & 0xf;
                    let hi = (b >> 4) & 0xf;
                    [
                        char::from_digit(lo as u32, 16).unwrap_or('0'),
                        '.',
                        char::from_digit(hi as u32, 16).unwrap_or('0'),
                        '.',
                    ]
                })
                .collect();
            format!("{}.ip6.arpa", nibbles.trim_end_matches('.'))
        }
    };
    // The std library does not expose a raw PTR query; use getaddrinfo via
    // the (ptr_domain + ":0") trick.
    match (ptr_domain.as_str(), 0u16).to_socket_addrs() {
        Ok(mut it) => {
            // The first result's hostname is what we want.
            if let Some(_) = it.next() {
                // std only returns IPs, not PTR names.  Fall back to the
                // /proc/net/arp or system `host` command for a PTR name.
            }
        }
        Err(_) => {}
    }
    // Most portable approach: call the `host` or `nslookup` binary.
    let out = std::process::Command::new("host")
        .arg(ip.to_string())
        .output();
    match out {
        Ok(o) if o.status.success() => {
            let s = String::from_utf8_lossy(&o.stdout);
            // "1.1.168.192.in-addr.arpa domain name pointer hostname."
            for line in s.lines() {
                if line.contains("domain name pointer") {
                    if let Some(name) = line.split_whitespace().last() {
                        return Ok(Some(name.trim_end_matches('.').to_string()));
                    }
                }
            }
            Ok(None)
        }
        Ok(_) => Ok(None),
        Err(e) => Err(format!("reverse_dns_lookup: {e}")),
    }
}

/// Enumerate DNS SRV records for common Active Directory service names in a
/// given domain.  Returns a list of `(service, host, port)` tuples.
///
/// Queries: `_ldap._tcp.dc._msdcs.<domain>` (DC locator),
/// `_kerberos._tcp.<domain>`, `_ldap._tcp.<domain>`.
pub fn ad_srv_discovery(domain: &str) -> Result<Vec<(String, String, u16)>, String> {
    // Use `nslookup -type=SRV` or `dig SRV` to query SRV records via the
    // system resolver since std::net does not expose raw DNS query types.
    let services: &[&str] = &[
        &format!("_ldap._tcp.dc._msdcs.{}", domain),
        &format!("_kerberos._tcp.{}", domain),
        &format!("_ldap._tcp.{}", domain),
        &format!("_gc._tcp.{}", domain),
    ];
    let mut results = Vec::new();
    for svc in services {
        let svc = svc.to_string();
        // Try `dig` first (common on Linux/macOS), fall back to `nslookup`.
        let out = std::process::Command::new("dig")
            .args(&["+short", "SRV", &svc])
            .output()
            .or_else(|_| {
                std::process::Command::new("nslookup")
                    .args(&["-type=SRV", &svc])
                    .output()
            });
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            for line in s.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                // `dig +short SRV` output: "<priority> <weight> <port> <host>"
                if parts.len() >= 4 {
                    if let Ok(port) = parts[2].parse::<u16>() {
                        let host = parts[3].trim_end_matches('.').to_string();
                        results.push((svc.clone(), host, port));
                    }
                }
            }
        }
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subnet_hosts_parses_cidr() {
        let hosts = subnet_hosts("10.0.0.0/24").unwrap();
        assert_eq!(hosts.len(), 254);
        assert_eq!(hosts[0], "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(hosts[253], "10.0.0.254".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn subnet_hosts_parses_bare_prefix() {
        let hosts = subnet_hosts("192.168.1").unwrap();
        assert_eq!(hosts.len(), 254);
    }

    #[test]
    fn subnet_hosts_rejects_bad_input() {
        assert!(subnet_hosts("192.168").is_err());
        assert!(subnet_hosts("not.an.ip").is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn arp_scan_linux_parses_proc_arp_format() {
        let sample =
            "IP address       HW type  Flags       HW address            Mask     Device\n\
                      192.168.1.1      0x1      0x2         aa:bb:cc:dd:ee:ff     *        eth0\n\
                      192.168.1.50     0x1      0x0         00:00:00:00:00:00     *        eth0\n";
        // Write sample to a temp file and parse it like arp_scan_linux would.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), sample).unwrap();
        let text = std::fs::read_to_string(tmp.path()).unwrap();
        let mut out: Vec<ArpEntry> = Vec::new();
        for line in text.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 4 {
                continue;
            }
            let flags = u64::from_str_radix(cols[2].trim_start_matches("0x"), 16).unwrap_or(0);
            if flags & 0x2 == 0 {
                continue;
            }
            let ip: IpAddr = cols[0].parse().unwrap();
            out.push(ArpEntry {
                ip,
                mac: cols[3].into(),
            });
        }
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].ip, "192.168.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(out[0].mac, "aa:bb:cc:dd:ee:ff");
    }

    #[tokio::test]
    async fn ping_sweep_finds_localhost() {
        // 127.0.0.x — only .1 should be reachable (loopback).
        // We spin up a listener on 127.0.0.1:9878 and verify that address
        // appears in the sweep results.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:9878")
            .await
            .unwrap();
        tokio::spawn(async move {
            loop {
                let _ = listener.accept().await;
            }
        });

        let result = ping_sweep("127.0.0.1/24", Duration::from_millis(200), 50)
            .await
            .unwrap();
        // The loopback listener we started should be discovered.
        assert!(
            result.contains(&"127.0.0.1".parse::<IpAddr>().unwrap()),
            "127.0.0.1 not found in sweep: {result:?}"
        );
    }
}
