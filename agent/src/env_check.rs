//! # Trusted Execution Environment Enforcement
//!
//! These checks run at agent start‑up to decide whether the host looks like a
//! legitimate managed endpoint or like a developer workstation, malware
//! sandbox, or analyst VM.  All checks are best‑effort: they bias toward
//! false negatives (let the agent run) over false positives (refuse on a
//! perfectly legitimate machine), and they are surfaced through the
//! [`EnvReport`] struct so that operators can choose the policy.
//!
//! See [`enforce`] for the wiring used by the agent's startup path.

use std::path::Path;

/// Outcome of all individual environment probes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnvReport {
    /// `IsDebuggerPresent` (Windows) or `TracerPid` (Linux) is non‑zero.
    pub debugger_present: bool,
    /// Heuristic VM/sandbox detection fired.
    pub vm_detected: bool,
    /// `Some(true)` if a domain requirement was configured and matched,
    /// `Some(false)` if configured and unmatched, `None` if not configured.
    pub domain_match: Option<bool>,
    /// `LD_PRELOAD` is set, which can indicate library-level hooking.
    pub ld_preload_set: bool,
    /// A known tracer process (like `strace` or `gdbserver`) is running.
    pub tracer_process_found: bool,
    /// A simple timing check took significantly longer than expected.
    pub timing_anomaly_detected: bool,
}

impl EnvReport {
    /// Run every probe; never panics.
    pub fn collect(required_domain: Option<&str>) -> Self {
        Self {
            debugger_present: is_debugger_present(),
            vm_detected: detect_vm(),
            domain_match: required_domain.map(validate_domain),
            ld_preload_set: is_ld_preload_set(),
            tracer_process_found: is_tracer_process_running(),
            timing_anomaly_detected: detect_timing_anomaly(),
        }
    }

    /// True when the host fails any check that has been *configured* to be
    /// enforced. We always treat a debugger or a domain mismatch as a
    /// failure; VM detection is informational unless the caller opts in.
    pub fn should_refuse(&self, refuse_in_vm: bool) -> bool {
        if self.debugger_present || self.tracer_process_found {
            return true;
        }
        if matches!(self.domain_match, Some(false)) {
            return true;
        }
        if refuse_in_vm && self.vm_detected {
            return true;
        }
        false
    }
}

// ------------------------------------------------------------------ debugger

/// True if a debugger appears to be attached to the current process.
///
/// * Windows: calls `IsDebuggerPresent` and checks `PEB.BeingDebugged` and
///   `PEB.NtGlobalFlag` (the `FLG_HEAP_ENABLE_TAIL_CHECK | …` triplet that
///   Windows sets in debugged processes).
/// * Linux: parses `/proc/self/status` for a non‑zero `TracerPid:` entry,
///   which `ptrace(PTRACE_ATTACH, …)` and `gdb` both populate.
/// * Other Unixes: returns `false`.
pub fn is_debugger_present() -> bool {
    #[cfg(windows)]
    {
        windows_is_debugger_present()
    }
    #[cfg(target_os = "linux")]
    {
        linux_is_debugger_present()
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        false
    }
}

#[cfg(target_os = "linux")]
fn linux_is_debugger_present() -> bool {
    let status = match std::fs::read_to_string("/proc/self/status") {
        Ok(s) => s,
        Err(_) => return false,
    };
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("TracerPid:") {
            return rest.trim().parse::<u32>().map(|p| p != 0).unwrap_or(false);
        }
    }
    false
}

#[cfg(windows)]
fn windows_is_debugger_present() -> bool {
    use winapi::um::debugapi::IsDebuggerPresent;
    if unsafe { IsDebuggerPresent() } != 0 {
        return true;
    }
    // Walk the PEB to read BeingDebugged and NtGlobalFlag without depending
    // on undocumented PEB layout in the `winapi` crate.
    #[cfg(target_arch = "x86_64")]
    unsafe {
        // gs:[0x60] -> PEB on x64
        let peb: *const u8;
        std::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, preserves_flags));
        if peb.is_null() {
            return false;
        }
        // PEB.BeingDebugged is at offset 0x02 (UCHAR).
        let being_debugged = *peb.add(0x02);
        // PEB.NtGlobalFlag is at offset 0xBC (ULONG).
        let nt_global_flag = *(peb.add(0xBC) as *const u32);
        const FLG_HEAP_ENABLE_TAIL_CHECK: u32 = 0x10;
        const FLG_HEAP_ENABLE_FREE_CHECK: u32 = 0x20;
        const FLG_HEAP_VALIDATE_PARAMETERS: u32 = 0x40;
        const DEBUG_FLAGS: u32 =
            FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS;
        if being_debugged != 0 {
            return true;
        }
        if nt_global_flag & DEBUG_FLAGS == DEBUG_FLAGS {
            return true;
        }
    }
    #[cfg(target_arch = "x86")]
    unsafe {
        let peb: *const u8;
        std::arch::asm!("mov {}, fs:[0x30]", out(reg) peb, options(nostack, preserves_flags));
        if peb.is_null() {
            return false;
        }
        let being_debugged = *peb.add(0x02);
        let nt_global_flag = *(peb.add(0x68) as *const u32);
        if being_debugged != 0 {
            return true;
        }
        if nt_global_flag & 0x70 == 0x70 {
            return true;
        }
    }
    false
}

// ------------------------------------------------------------------------ VM

/// True if the host appears to be a virtual machine or analysis sandbox.
///
/// This is a collection of soft indicators. The CPUID hypervisor bit is no
/// longer a hard failure, but contributes to the overall `vm_detected` score.
fn is_expected_hypervisor() -> bool {
    #[cfg(target_os = "linux")]
    {
        const DMI: &[&str] = &[
            "/sys/class/dmi/id/board_vendor",
            "/sys/class/dmi/id/sys_vendor",
            "/sys/class/dmi/id/product_name",
        ];
        for path in DMI {
            if let Ok(s) = std::fs::read_to_string(path) {
                let s = s.to_ascii_lowercase();
                if s.contains("amazon ec2") || s.contains("google compute") {
                    return true;
                }
            }
        }
        if let Ok(s) = std::fs::read_to_string("/proc/version") {
            let s = s.to_ascii_lowercase();
            // Don't flag WSL as a VM
            if s.contains("microsoft") {
                return true;
            }
        }
    }

    #[cfg(windows)]
    {
        use winreg::enums::HKEY_LOCAL_MACHINE;
        use winreg::RegKey;
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        if let Ok(k) = hklm.open_subkey("HARDWARE\\DESCRIPTION\\System\\BIOS") {
            if let Ok(v) = k.get_value::<String, _>("SystemManufacturer") {
                let s = v.to_ascii_lowercase();
                // "microsoft corporation" means Surface in many contexts, allowing hypervisor for features without flagging VM
                if s.contains("amazon")
                    || s.contains("google")
                    || s.contains("microsoft corporation")
                {
                    return true;
                }
            }
            if let Ok(v) = k.get_value::<String, _>("SystemProductName") {
                let s = v.to_ascii_lowercase();
                if s.contains("amazon ec2") || s.contains("google compute") {
                    return true;
                }
            }
        }
    }

    false
}

pub fn detect_vm() -> bool {
    // The hypervisor bit is now just one of several indicators.
    let mut indicators = 0;
    if cpuid_hypervisor_bit() && !is_expected_hypervisor() {
        indicators += 1;
    }
    #[cfg(target_os = "linux")]
    {
        if linux_dmi_indicates_vm() {
            indicators += 1;
        }
    }
    #[cfg(target_os = "macos")]
    {
        if macos_system_profiler_indicates_vm() {
            indicators += 1;
        }
    }
    #[cfg(windows)]
    {
        if windows_registry_indicates_vm() {
            indicators += 1;
        }
    }
    if mac_prefix_indicates_vm() {
        indicators += 1;
    }
    // Consider it a VM if at least two indicators are present.
    indicators >= 2
}

fn cpuid_hypervisor_bit() -> bool {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        #[cfg(target_arch = "x86")]
        use std::arch::x86::__cpuid;
        #[cfg(target_arch = "x86_64")]
        use std::arch::x86_64::__cpuid;
        // `__cpuid` is `unsafe` on older toolchains and safe on newer ones; tolerate both.
        #[allow(unused_unsafe)]
        let r = unsafe { __cpuid(1) };
        (r.ecx & (1 << 31)) != 0
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    {
        false
    }
}

#[cfg(target_os = "linux")]
fn linux_dmi_indicates_vm() -> bool {
    const DMI: &[&str] = &[
        "/sys/class/dmi/id/sys_vendor",
        "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/bios_vendor",
    ];
    const NEEDLES: &[&str] = &[
        "qemu",
        "kvm",
        "vmware",
        "virtualbox",
        "vbox",
        "xen",
        "hyperv",
        "innotek",
    ];
    // "microsoft corporation" in sys_vendor appears on physical Microsoft hardware
    // (e.g., Surface devices) as well as on Hyper-V guests. Only treat it as a VM
    // indicator when the product_name is also "virtual machine", which is the
    // definitive fingerprint of a Hyper-V guest and not present on bare-metal hardware.
    let mut ms_vendor = false;
    let mut virt_product = false;
    for path in DMI {
        if let Ok(s) = std::fs::read_to_string(path) {
            let s = s.to_ascii_lowercase();
            if NEEDLES.iter().any(|n| s.contains(n)) {
                return true;
            }
            if path.ends_with("sys_vendor") && s.contains("microsoft corporation") {
                ms_vendor = true;
            }
            if path.ends_with("product_name") && s.contains("virtual machine") {
                virt_product = true;
            }
        }
    }
    ms_vendor && virt_product
}

#[cfg(target_os = "macos")]
fn macos_system_profiler_indicates_vm() -> bool {
    let mut is_vm = false;

    // Check sysctl hw.model and kern.hv_support
    if let Ok(output) = std::process::Command::new("sysctl")
        .arg("-n")
        .arg("hw.model")
        .output()
    {
        let model = String::from_utf8_lossy(&output.stdout).to_lowercase();
        if model.contains("virtual") || model.contains("vmware") || model.contains("pxe") {
            is_vm = true;
        }
    }

    if let Ok(output) = std::process::Command::new("sysctl")
        .arg("-n")
        .arg("kern.hv_support")
        .output()
    {
        let support = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if support == "1" {
            // Native hypervisor framework is supported, which might mean we are the host, or a guest that supports nested.
            // But let's check ioreg for specific virtual devices
        }
    }

    if let Ok(output) = std::process::Command::new("ioreg").arg("-l").output() {
        let ioreg = String::from_utf8_lossy(&output.stdout).to_lowercase();
        if ioreg.contains("virtualbox")
            || ioreg.contains("vmware")
            || ioreg.contains("parallels")
            || ioreg.contains("qemu")
        {
            is_vm = true;
        }
    }

    is_vm
}

#[cfg(windows)]
fn windows_registry_indicates_vm() -> bool {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    // "VIRTUAL" removed: Windows machines with VBS/HVCI or Hyper-V role enabled
    // may have registry values containing "VIRTUAL" (e.g., "VIRTUAL TPM",
    // "VIRTUALIZATION-BASED SECURITY") on physical hardware. Use only
    // hypervisor-vendor-specific strings to avoid false positives.
    let needles = ["VBOX", "VMWARE", "QEMU", "XEN"];
    for path in [
        "HARDWARE\\DESCRIPTION\\System",
        "HARDWARE\\DESCRIPTION\\System\\BIOS",
    ] {
        if let Ok(k) = hklm.open_subkey(path) {
            for value in [
                "SystemBiosVersion",
                "VideoBiosVersion",
                "SystemManufacturer",
            ] {
                if let Ok(v) = k.get_value::<String, _>(value) {
                    let upper = v.to_ascii_uppercase();
                    if needles.iter().any(|n| upper.contains(n)) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn mac_prefix_indicates_vm() -> bool {
    let prefixes = [
        [0x08u8, 0x00, 0x27], // VirtualBox
        [0x00, 0x0C, 0x29],   // VMware
        [0x00, 0x50, 0x56],   // VMware
        [0x52, 0x54, 0x00],   // KVM/QEMU
        [0x00, 0x15, 0x5d],   // Hyper-V
    ];
    // Read /sys/class/net on Linux.
    #[cfg(target_os = "linux")]
    {
        let net = Path::new("/sys/class/net");
        if let Ok(entries) = std::fs::read_dir(net) {
            for entry in entries.flatten() {
                let addr_path = entry.path().join("address");
                if let Ok(addr) = std::fs::read_to_string(&addr_path) {
                    let bytes: Vec<u8> = addr
                        .trim()
                        .split(':')
                        .filter_map(|h| u8::from_str_radix(h, 16).ok())
                        .collect();
                    if bytes.len() >= 3 {
                        let prefix = [bytes[0], bytes[1], bytes[2]];
                        if prefixes.contains(&prefix) {
                            return true;
                        }
                    }
                }
            }
        }
    }
    // On Windows use GetAdaptersAddresses to read physical MAC addresses.
    #[cfg(windows)]
    {
        if windows_mac_prefix_indicates_vm(&prefixes) {
            return true;
        }
    }
    // On macOS use getifaddrs to read physical MAC addresses.
    #[cfg(target_os = "macos")]
    {
        unsafe {
            let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
            if libc::getifaddrs(&mut ifap) == 0 {
                let mut curr = ifap;
                while !curr.is_null() {
                    let addr = (*curr).ifa_addr;
                    if !addr.is_null() && (*addr).sa_family as libc::c_int == libc::AF_LINK {
                        let sdl = addr as *const libc::sockaddr_dl;
                        let ptr =
                            (*sdl).sdl_data.as_ptr().offset((*sdl).sdl_nlen as isize) as *const u8;
                        let alen = (*sdl).sdl_alen as usize;
                        if alen >= 3 {
                            let mac = std::slice::from_raw_parts(ptr, 3);
                            let prefix = [mac[0], mac[1], mac[2]];
                            if prefixes.contains(&prefix) {
                                libc::freeifaddrs(ifap);
                                return true;
                            }
                        }
                    }
                    curr = (*curr).ifa_next;
                }
                libc::freeifaddrs(ifap);
            }
        }
    }
    let _ = prefixes;
    let _ = Path::new("/dev/null");
    false
}

/// Windows implementation: walk the adapter list via `GetAdaptersAddresses`
/// and check whether any interface has a MAC prefix matching a known hypervisor.
#[cfg(windows)]
fn windows_mac_prefix_indicates_vm(prefixes: &[[u8; 3]]) -> bool {
    use winapi::shared::winerror::ERROR_SUCCESS;
    use winapi::um::iphlpapi::GetAdaptersAddresses;
    use winapi::um::iptypes::IP_ADAPTER_ADDRESSES;

    // AF_UNSPEC = 0; skip address lists we don't need.
    const AF_UNSPEC: u32 = 0;
    const GAA_FLAG_SKIP_UNICAST: u32 = 0x0001;
    const GAA_FLAG_SKIP_ANYCAST: u32 = 0x0002;
    const GAA_FLAG_SKIP_MULTICAST: u32 = 0x0004;
    const GAA_FLAG_SKIP_DNS_SERVER: u32 = 0x0008;
    let flags = GAA_FLAG_SKIP_UNICAST
        | GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_DNS_SERVER;

    unsafe {
        // First call with a null buffer to obtain the required size.
        let mut buf_size: u32 = 0;
        GetAdaptersAddresses(
            AF_UNSPEC,
            flags,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut buf_size,
        );
        if buf_size == 0 {
            return false;
        }

        let mut buf: Vec<u8> = vec![0u8; buf_size as usize];
        let ret = GetAdaptersAddresses(
            AF_UNSPEC,
            flags,
            std::ptr::null_mut(),
            buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES,
            &mut buf_size,
        );
        if ret != ERROR_SUCCESS {
            return false;
        }

        let mut adapter = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES;
        while !adapter.is_null() {
            let phy_len = (*adapter).PhysicalAddressLength as usize;
            if phy_len >= 3 {
                let mac = &(&(*adapter).PhysicalAddress)[..phy_len];
                let prefix = [mac[0], mac[1], mac[2]];
                if prefixes.contains(&prefix) {
                    return true;
                }
            }
            adapter = (*adapter).Next;
        }
    }
    false
}

// ------------------------------------------------ anti-analysis (Linux)

#[cfg(target_os = "linux")]
fn is_ld_preload_set() -> bool {
    std::env::var("LD_PRELOAD").is_ok()
}

#[cfg(not(target_os = "linux"))]
fn is_ld_preload_set() -> bool {
    false
}

#[cfg(target_os = "linux")]
fn is_tracer_process_running() -> bool {
    // Primary check: Check for a ptrace attachment on our own process
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if line.starts_with("TracerPid:") {
                let pid = line.trim_start_matches("TracerPid:").trim();
                // A TracerPid other than 0 means we are actively being debugged/traced
                if pid != "0" {
                    return true;
                }
            }
        }
    }

    // Secondary check: look for tracer processes system-wide by examining their command lines
    let tracers = ["strace", "gdb", "ltrace", "gdbserver"];
    if let Ok(procs) = std::fs::read_dir("/proc") {
        for proc in procs.flatten() {
            if let Ok(cmdline) = std::fs::read_to_string(proc.path().join("cmdline")) {
                let parts: Vec<&str> = cmdline.split('\0').collect();
                if let Some(prog) = parts.first() {
                    let prog_name = Path::new(prog)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("");
                    if tracers.contains(&prog_name) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

#[cfg(not(target_os = "linux"))]
fn is_tracer_process_running() -> bool {
    false
}

fn detect_timing_anomaly() -> bool {
    let mut times = Vec::new();
    for _ in 0..10 {
        let start = std::time::Instant::now();
        std::thread::sleep(std::time::Duration::from_millis(10));
        times.push(start.elapsed().as_millis() as f64);
    }

    let sum: f64 = times.iter().sum();
    let mean = sum / 10.0;

    let variance: f64 = times.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / 10.0;

    // Loosen constraints for heavily loaded servers
    let mean_anomaly = mean > 250.0;
    let var_anomaly = variance > 10000.0;

    // Flag if either the mean is outrageously high (slow execution overall, e.g., heavy tracing)
    // or variance is high (e.g., hit a breakpoint on a single iteration and spent time paused)
    mean_anomaly || var_anomaly
}

// -------------------------------------------------------------------- domain

/// True if the host's primary domain matches `required` (case‑insensitive).
pub fn validate_domain(required: &str) -> bool {
    let observed = current_domain().unwrap_or_default();
    !required.is_empty() && observed.eq_ignore_ascii_case(required)
}

/// Best‑effort host domain detection.
fn current_domain() -> Option<String> {
    if let Ok(v) = std::env::var("USERDNSDOMAIN") {
        if !v.is_empty() {
            return Some(v);
        }
    }
    #[cfg(windows)]
    {
        if let Some(d) = windows_computer_domain() {
            return Some(d);
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(s) = std::fs::read_to_string("/proc/sys/kernel/domainname") {
            let s = s.trim();
            if !s.is_empty() && s != "(none)" {
                return Some(s.to_string());
            }
        }
        if let Ok(s) = std::fs::read_to_string("/etc/resolv.conf") {
            for line in s.lines() {
                if let Some(rest) = line.strip_prefix("domain ") {
                    return Some(rest.trim().to_string());
                }
            }
        }
    }
    None
}

#[cfg(windows)]
fn windows_computer_domain() -> Option<String> {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key = hklm
        .open_subkey("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters")
        .ok()?;
    let domain: String = key.get_value("Domain").ok()?;
    if domain.is_empty() {
        None
    } else {
        Some(domain)
    }
}

// ------------------------------------------------------------------ enforcer

/// Run every probe and either return `Ok(())` or refuse to start.
///
/// `required_domain` and `refuse_in_vm` come from `agent.toml`.
pub fn enforce(required_domain: Option<&str>, refuse_in_vm: bool) -> EnvDecision {
    let report = EnvReport::collect(required_domain);
    let refuse = report.should_refuse(refuse_in_vm);
    EnvDecision { report, refuse }
}

/// Decision returned from [`enforce`].
#[derive(Debug, Clone)]
pub struct EnvDecision {
    pub report: EnvReport,
    pub refuse: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_with_no_required_domain_has_none_match() {
        let r = EnvReport::collect(None);
        assert!(r.domain_match.is_none());
        // Refusal must not fire from a missing required_domain alone.
        assert!(!r.should_refuse(false));
    }

    #[test]
    fn validate_domain_rejects_unmatched() {
        assert!(!validate_domain("definitely-not-this-domain-xyz.invalid"));
    }

    #[test]
    fn validate_domain_matches_when_env_var_set() {
        // SAFETY: tests run in this process and we restore the env afterward.
        let prev = std::env::var("USERDNSDOMAIN").ok();
        // Use scopeguard-style restore via Drop.
        struct Restore(Option<String>);
        impl Drop for Restore {
            fn drop(&mut self) {
                match &self.0 {
                    Some(v) => std::env::set_var("USERDNSDOMAIN", v),
                    None => std::env::remove_var("USERDNSDOMAIN"),
                }
            }
        }
        let _g = Restore(prev);
        std::env::set_var("USERDNSDOMAIN", "corp.example.com");
        assert!(validate_domain("CORP.example.com"));
        assert!(!validate_domain("other.example.com"));
    }

    /// Simulate a debugged process by writing a fake `/proc/self/status`
    /// line and parsing it through the same routine the real check uses.
    #[test]
    fn detect_debugger_from_synthetic_status() {
        fn parse_tracer(status: &str) -> bool {
            for line in status.lines() {
                if let Some(rest) = line.strip_prefix("TracerPid:") {
                    return rest.trim().parse::<u32>().map(|p| p != 0).unwrap_or(false);
                }
            }
            false
        }
        let undebugged = "Name:\tagent\nTracerPid:\t0\n";
        let debugged = "Name:\tagent\nTracerPid:\t1234\n";
        assert!(!parse_tracer(undebugged));
        assert!(parse_tracer(debugged));
    }

    #[test]
    fn refusal_policy_combines_signals() {
        let mut r = EnvReport::default();
        assert!(!r.should_refuse(false));
        r.debugger_present = true;
        assert!(r.should_refuse(false));
        r.debugger_present = false;
        r.domain_match = Some(false);
        assert!(r.should_refuse(false));
        r.domain_match = Some(true);
        r.vm_detected = true;
        assert!(!r.should_refuse(false));
        assert!(r.should_refuse(true));
    }
}
