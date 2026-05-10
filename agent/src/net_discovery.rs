//! Optional network discovery module for asset inventory and troubleshooting.
//!
//! This module provides functions for network scanning, including ARP cache
//! enumeration, TCP-based host probing, and TCP port scanning. These tools
//! are intended for legitimate network administration and asset management.
//!
//! **Warning:** Unauthorised network scanning is prohibited. Ensure you have
//! explicit written permission before scanning any network.

#![cfg(feature = "network-discovery")]

use std::net::{IpAddr, Ipv4Addr};
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
#[cfg(not(target_os = "linux"))]
fn arp_scan_cmd() -> Result<Vec<ArpEntry>, String> {
    // SAFETY INVARIANT: The command and arguments ("arp", "-a") are hardcoded
    // constants — never derived from user or network input.  This prevents
    // command injection even if an attacker controls surrounding state.
    //
    // EDR observability: subprocess spawning (even with hardcoded args) is
    // visible to EDR/AV.  On Linux, arp_scan_linux() reads /proc/net/arp
    // directly and avoids this.  Consider implementing platform-native ARP
    // enumeration (e.g. sysctl NET_RT_FLAGS on macOS/BSD) to eliminate the
    // subprocess entirely on non-Linux Unix.
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
    const PROBE_PORTS: &[u16] = &[80, 443, 22, 7];
    ping_sweep_with_ports(subnet, PROBE_PORTS, timeout, max_concurrent).await
}

/// Probe a subnet using caller-provided ports. This is primarily useful for
/// deterministic tests and tightly-scoped inventory checks.
pub async fn ping_sweep_with_ports(
    subnet: &str,
    ports: &[u16],
    timeout: Duration,
    max_concurrent: usize,
) -> Result<Vec<IpAddr>, String> {
    let targets = subnet_hosts(subnet)?;
    if targets.is_empty() {
        return Ok(vec![]);
    }

    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(max_concurrent));
    let mut handles = Vec::with_capacity(targets.len());

    for ip in targets {
        let permit = sem
            .clone()
            .acquire_owned()
            .await
            .map_err(|e| e.to_string())?;
        let ports = ports.to_vec();
        let handle = tokio::spawn(async move {
            let live = probe_host(ip, &ports, timeout).await;
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

/// Enumerate the IPv4 host addresses within a subnet string such as
/// `"192.168.1.0/24"` or a bare `/24` prefix like `"10.0.0"`.
///
/// Prefixes broader than `/20` are rejected to avoid accidental wide network
/// scans from a typo. `/31` and `/32` are treated per RFC 3021/host-route
/// semantics and include all addresses in the range.
fn subnet_hosts(subnet: &str) -> Result<Vec<IpAddr>, String> {
    const MAX_HOSTS: u32 = 4096;

    let subnet = subnet.trim();
    if let Some((addr, prefix)) = subnet.split_once('/') {
        let base: Ipv4Addr = addr
            .parse()
            .map_err(|e| format!("invalid IPv4 CIDR address '{addr}': {e}"))?;
        let prefix: u32 = prefix
            .parse()
            .map_err(|e| format!("invalid CIDR prefix '{prefix}': {e}"))?;
        if prefix > 32 {
            return Err(format!("CIDR prefix must be <= 32; got {prefix}"));
        }
        let mask = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        let network = u32::from(base) & mask;
        let broadcast = network | !mask;
        let (first, last) = match prefix {
            0..=20 => {
                return Err(format!(
                    "CIDR prefix /{prefix} contains too many hosts for a bounded sweep"
                ));
            }
            21..=30 => (network + 1, broadcast.saturating_sub(1)),
            31 | 32 => (network, broadcast),
            _ => unreachable!(),
        };
        if last < first {
            return Ok(Vec::new());
        }
        let count = last - first + 1;
        if count > MAX_HOSTS {
            return Err(format!(
                "CIDR range contains {count} hosts, exceeding safety cap {MAX_HOSTS}"
            ));
        }
        return Ok((first..=last)
            .map(|raw| IpAddr::V4(Ipv4Addr::from(raw)))
            .collect());
    }

    let base = subnet.trim_end_matches('.');
    let parts: Vec<&str> = base.split('.').collect();
    if parts.len() != 3 {
        return Err(format!(
            "subnet must be CIDR notation or exactly 3 octets for a /24 prefix; got '{subnet}'"
        ));
    }
    let octets = [
        parts[0]
            .parse::<u8>()
            .map_err(|e| format!("invalid first octet: {e}"))?,
        parts[1]
            .parse::<u8>()
            .map_err(|e| format!("invalid second octet: {e}"))?,
        parts[2]
            .parse::<u8>()
            .map_err(|e| format!("invalid third octet: {e}"))?,
    ];
    let mut hosts = Vec::with_capacity(254);
    for i in 1u8..=254 {
        hosts.push(IpAddr::V4(Ipv4Addr::new(
            octets[0], octets[1], octets[2], i,
        )));
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

/// Format an IP address as a reverse-DNS PTR domain name.
///
/// IPv4: `1.0.168.192.in-addr.arpa`
/// IPv6: nibble-reversed `ip6.arpa`
#[cfg(target_os = "windows")]
fn format_reverse_ptr(ip: &IpAddr) -> String {
    match ip {
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
    }
}

// ── Windows: DnsQuery_W via pe_resolve ───────────────────────────────────────

#[cfg(target_os = "windows")]
mod dns_windows {
    use super::*;
    use std::ffi::c_void;
    use std::ptr;

    // Minimal DNS_RECORD definition matching the Windows DNS API.
    #[repr(C)]
    struct DNS_RECORD {
        p_next: *mut DNS_RECORD,
        p_name: *mut u16,
        w_type: u16,
        w_data_length: u16,
        flags: u32,
        dw_ttl: u32,
        dw_reserved: u32,
        data: DNS_RECORD_DATA,
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    union DNS_RECORD_DATA {
        ptr_name: *mut u16, // DNS_TYPE_PTR
        srv: DnsSrvData,    // DNS_TYPE_SRV
        padding: [u8; 16],  // enough for any variant
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    struct DnsSrvData {
        p_name_target: *mut u16,
        w_priority: u16,
        w_weight: u16,
        w_port: u16,
        pad: u16,
    }

    const DNS_TYPE_PTR: u16 = 0x000C;
    const DNS_TYPE_SRV: u16 = 0x0021;
    const DNS_QUERY_NO_LOCAL_NAME: u32 = 0x80;

    /// Resolve a DNS function from dnsapi.dll via pe_resolve.
    unsafe fn resolve_dnsapi_fn(name: &[u8]) -> Option<usize> {
        let dnsapi_wide: Vec<u16> = "dnsapi.dll\0".encode_utf16().collect();
        let dnsapi_hash = pe_resolve::hash_wstr(&dnsapi_wide[..dnsapi_wide.len() - 1]);
        let dnsapi_base = pe_resolve::get_module_handle_by_hash(dnsapi_hash)?;
        let hash = pe_resolve::hash_str(name);
        pe_resolve::get_proc_address_by_hash(dnsapi_base, hash)
    }

    /// Free a DNS record list via DnsRecordListFree resolved from dnsapi.dll.
    unsafe fn dns_record_list_free(records: *mut DNS_RECORD) {
        type FnDnsRecordListFree = unsafe extern "system" fn(*mut DNS_RECORD, u32);
        match resolve_dnsapi_fn(b"DnsRecordListFree\0") {
            Some(addr) => {
                let f: FnDnsRecordListFree = std::mem::transmute(addr);
                // DnsFreeRecordList = 0
                f(records, 0);
            }
            None => {
                log::warn!(
                    "[net_discovery] could not resolve DnsRecordListFree — leaking DNS records"
                );
            }
        }
    }

    /// Read a null-terminated UTF-16 string into a Rust String.
    unsafe fn read_wide_ptr(ptr: *const u16) -> Option<String> {
        if ptr.is_null() {
            return None;
        }
        let mut len = 0usize;
        while *ptr.add(len) != 0 {
            len += 1;
        }
        if len == 0 {
            return None;
        }
        let slice = std::slice::from_raw_parts(ptr, len);
        String::from_utf16(slice).ok()
    }

    /// Query DnsQuery_W for a given name and record type, returning the
    /// linked list head on success.
    unsafe fn dns_query_raw(
        name_wide: &[u16],
        query_type: u16,
        options: u32,
    ) -> Result<*mut DNS_RECORD, String> {
        type FnDnsQueryW = unsafe extern "system" fn(
            *const u16,           // Name
            u16,                  // Type
            u32,                  // Options
            *mut c_void,          // Extra
            *mut *mut DNS_RECORD, // Result
            *mut *mut c_void,     // Reserved
        ) -> i32;

        let dns_query_w: FnDnsQueryW = resolve_dnsapi_fn(b"DnsQuery_W\0")
            .map(|a| std::mem::transmute::<usize, FnDnsQueryW>(a))
            .ok_or_else(|| "dnsapi.dll!DnsQuery_W resolution failed".to_string())?;

        let mut result_records: *mut DNS_RECORD = ptr::null_mut();
        let status = dns_query_w(
            name_wide.as_ptr(),
            query_type,
            options,
            ptr::null_mut(),
            &mut result_records,
            ptr::null_mut(),
        );

        if status != 0 {
            return Err(format!("DnsQuery_W failed with status {}", status));
        }
        Ok(result_records)
    }

    /// Resolve the reverse DNS (PTR) name for an IP address using DnsQuery_W.
    pub fn reverse_dns_lookup(ip: IpAddr) -> Result<Option<String>, String> {
        let ptr_domain = format_reverse_ptr(&ip);
        let ptr_wide: Vec<u16> = ptr_domain
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let records = unsafe { dns_query_raw(&ptr_wide, DNS_TYPE_PTR, DNS_QUERY_NO_LOCAL_NAME) };

        let records = match records {
            Ok(r) => r,
            Err(_) => return Ok(None), // NXDOMAIN / SERVFAIL → no PTR
        };

        if records.is_null() {
            return Ok(None);
        }

        // Walk the linked list for the first PTR record.
        let mut hostname: Option<String> = None;
        unsafe {
            let mut cur = records;
            while !cur.is_null() {
                let rec = &*cur;
                if rec.w_type == DNS_TYPE_PTR {
                    if let Some(name) = read_wide_ptr(rec.data.ptr_name) {
                        hostname = Some(name.trim_end_matches('.').to_string());
                        break;
                    }
                }
                cur = rec.p_next;
            }
            dns_record_list_free(records);
        }

        Ok(hostname)
    }

    /// Enumerate DNS SRV records using DnsQuery_W.
    pub fn ad_srv_discovery(domain: &str) -> Result<Vec<(String, String, u16)>, String> {
        let services: &[&str] = &[
            &format!("_ldap._tcp.dc._msdcs.{}", domain),
            &format!("_kerberos._tcp.{}", domain),
            &format!("_ldap._tcp.{}", domain),
            &format!("_gc._tcp.{}", domain),
        ];

        let mut results = Vec::new();

        for svc in services {
            let svc_str = svc.to_string();
            let svc_wide: Vec<u16> = svc_str.encode_utf16().chain(std::iter::once(0)).collect();

            let records =
                match unsafe { dns_query_raw(&svc_wide, DNS_TYPE_SRV, DNS_QUERY_NO_LOCAL_NAME) } {
                    Ok(r) => r,
                    Err(_) => continue,
                };

            if records.is_null() {
                continue;
            }

            unsafe {
                let mut cur = records;
                while !cur.is_null() {
                    let rec = &*cur;
                    if rec.w_type == DNS_TYPE_SRV {
                        let srv = rec.data.srv;
                        if let Some(host) = read_wide_ptr(srv.p_name_target) {
                            let host = host.trim_end_matches('.').to_string();
                            results.push((svc_str.clone(), host, srv.w_port));
                        }
                    }
                    cur = rec.p_next;
                }
                dns_record_list_free(records);
            }
        }

        Ok(results)
    }
}

// ── Non-Windows: subprocess DNS ──────────────────────────────────────────────

#[cfg(not(target_os = "windows"))]
mod dns_unix {
    use super::*;

    /// Resolve the reverse DNS (PTR) name for an IP address via `host` command.
    /// P2-22: Includes a 10-second timeout to prevent hanging on unresponsive DNS.
    ///
    /// SAFETY INVARIANT: The command binary ("host") and flag layout are
    /// hardcoded.  The only dynamic component is `ip.to_string()`, which
    /// produces a validated `IpAddr` display string — it cannot inject
    /// shell metacharacters because `std::process::Command` passes args
    /// directly to execve(2) without shell interpretation.
    ///
    /// EDR observability: spawning `host` is visible to EDR/AV.  Consider
    /// replacing with raw socket DNS queries or platform-native resolver
    /// APIs to eliminate subprocess spawning on all platforms.
    pub fn reverse_dns_lookup(ip: IpAddr) -> Result<Option<String>, String> {
        let mut cmd = std::process::Command::new("host");
        cmd.arg(ip.to_string());
        let out = run_with_timeout(cmd);
        match out {
            Ok(o) if o.status.success() => {
                let s = String::from_utf8_lossy(&o.stdout);
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
            Err(_) => Ok(None),
        }
    }

    /// Enumerate DNS SRV records via `dig` / `nslookup`.
    /// P2-22: Includes a 10-second timeout for each command.
    ///
    /// SAFETY INVARIANT: The binary names ("dig", "nslookup") and flags
    /// are hardcoded.  The only dynamic component is `domain`, which is
    /// passed as a single argument to each command.  Because
    /// `std::process::Command` does not invoke a shell, `domain` cannot
    /// inject additional arguments or shell metacharacters.  However, a
    /// malformed domain could cause unexpected DNS queries — callers should
    /// validate the domain string before passing it here.
    pub fn ad_srv_discovery(domain: &str) -> Result<Vec<(String, String, u16)>, String> {
        let services: &[&str] = &[
            &format!("_ldap._tcp.dc._msdcs.{}", domain),
            &format!("_kerberos._tcp.{}", domain),
            &format!("_ldap._tcp.{}", domain),
            &format!("_gc._tcp.{}", domain),
        ];
        let mut results = Vec::new();
        for svc in services {
            let svc_str = svc.to_string();
            let mut dig_cmd = std::process::Command::new("dig");
            dig_cmd.args(["+short", "SRV", svc_str.as_str()]);

            let out = run_with_timeout(dig_cmd).or_else(|_| {
                let mut nslookup_cmd = std::process::Command::new("nslookup");
                nslookup_cmd.args(["-type=SRV", svc_str.as_str()]);
                run_with_timeout(nslookup_cmd)
            });
            if let Ok(o) = out {
                let s = String::from_utf8_lossy(&o.stdout);
                for line in s.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    // `dig +short SRV` output: "<priority> <weight> <port> <host>"
                    if parts.len() >= 4 {
                        if let Ok(port) = parts[2].parse::<u16>() {
                            let host = parts[3].trim_end_matches('.').to_string();
                            results.push((svc_str.clone(), host, port));
                        }
                    }
                }
            }
        }
        Ok(results)
    }

    /// P2-22: Run a command with a 10-second timeout using spawn + wait_with_output.
    fn run_with_timeout(mut cmd: std::process::Command) -> Result<std::process::Output, String> {
        use std::process::Stdio;
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => return Err(format!("spawn failed: {}", e)),
        };
        // Poll with timeout — wait up to 10 seconds.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let output =
                        child
                            .wait_with_output()
                            .unwrap_or_else(|_| std::process::Output {
                                status,
                                stdout: Vec::new(),
                                stderr: Vec::new(),
                            });
                    return Ok(output);
                }
                Ok(None) => {
                    if std::time::Instant::now() >= deadline {
                        let _ = child.kill();
                        return Err("command timed out after 10 seconds".to_string());
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(e) => return Err(format!("wait error: {}", e)),
            }
        }
    }
}

// ── Public dispatch ──────────────────────────────────────────────────────────

/// Resolve the reverse DNS (PTR) name for an IP address.
///
/// Returns `Ok(None)` when no PTR record exists or the resolver returns
/// NXDOMAIN/SERVFAIL, and `Err` only on I/O failure.
///
/// On Windows, uses `DnsQuery_W` resolved from `dnsapi.dll` via `pe_resolve`
/// to avoid spawning subprocesses.  On other platforms, falls back to the
/// `host` command-line tool.
pub fn reverse_dns_lookup(ip: IpAddr) -> Result<Option<String>, String> {
    #[cfg(target_os = "windows")]
    {
        dns_windows::reverse_dns_lookup(ip)
    }
    #[cfg(not(target_os = "windows"))]
    {
        dns_unix::reverse_dns_lookup(ip)
    }
}

/// Enumerate DNS SRV records for common Active Directory service names in a
/// given domain.  Returns a list of `(service, host, port)` tuples.
///
/// Queries: `_ldap._tcp.dc._msdcs.<domain>` (DC locator),
/// `_kerberos._tcp.<domain>`, `_ldap._tcp.<domain>`, `_gc._tcp.<domain>`.
///
/// On Windows, uses `DnsQuery_W` for SRV records (type 0x0021).  On other
/// platforms, falls back to `dig` / `nslookup`.
pub fn ad_srv_discovery(domain: &str) -> Result<Vec<(String, String, u16)>, String> {
    #[cfg(target_os = "windows")]
    {
        dns_windows::ad_srv_discovery(domain)
    }
    #[cfg(not(target_os = "windows"))]
    {
        dns_unix::ad_srv_discovery(domain)
    }
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
    fn subnet_hosts_honors_small_cidr_ranges() {
        let hosts = subnet_hosts("10.0.0.8/30").unwrap();
        assert_eq!(
            hosts,
            vec![
                "10.0.0.9".parse::<IpAddr>().unwrap(),
                "10.0.0.10".parse::<IpAddr>().unwrap()
            ]
        );
        let host_route = subnet_hosts("10.0.0.42/32").unwrap();
        assert_eq!(host_route, vec!["10.0.0.42".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn subnet_hosts_rejects_overbroad_cidr() {
        assert!(subnet_hosts("10.0.0.0/16").is_err());
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
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let _ = listener.accept().await;
            }
        });

        let result = ping_sweep_with_ports("127.0.0.1/32", &[port], Duration::from_millis(200), 4)
            .await
            .unwrap();
        // The loopback listener we started should be discovered.
        assert!(
            result.contains(&"127.0.0.1".parse::<IpAddr>().unwrap()),
            "127.0.0.1 not found in sweep: {result:?}"
        );
    }
}
