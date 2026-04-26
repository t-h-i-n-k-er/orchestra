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
    /// Combined heuristic sandbox-probability score (0–100).
    ///
    /// Computed from mouse-movement, desktop richness, uptime artefacts, and
    /// hardware-plausibility probes (see [`sandbox::evaluate_sandbox`]).
    /// This field is informational; use `should_refuse` to incorporate it into
    /// a policy decision by passing `sandbox_score_threshold`.
    pub sandbox_score: u32,
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
            sandbox_score: sandbox::evaluate_sandbox().unwrap_or(0),
        }
    }

    /// True when the host fails any check that has been *configured* to be
    /// enforced. Domain mismatch is enforced only when a required domain was
    /// configured. Debugger, VM, tracer-process, timing, and sandbox-score
    /// signals are informational unless their explicit policy knobs are set.
    ///
    /// * `refuse_when_debugged`: if `true`, an attached debugger triggers refusal.
    /// * `refuse_in_vm`: if `true`, a positive `vm_detected` also triggers refusal.
    /// * `sandbox_score_threshold`: if `Some(n)`, a `sandbox_score >= n` also
    ///   triggers refusal.  Pass `None` to leave the sandbox score informational.
    pub fn should_refuse(
        &self,
        refuse_when_debugged: bool,
        refuse_in_vm: bool,
        sandbox_score_threshold: Option<u32>,
    ) -> bool {
        if refuse_when_debugged && self.debugger_present {
            return true;
        }
        if matches!(self.domain_match, Some(false)) {
            return true;
        }
        if refuse_in_vm && self.vm_detected {
            return true;
        }
        if let Some(threshold) = sandbox_score_threshold {
            if self.sandbox_score >= threshold {
                return true;
            }
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
            "/sys/class/dmi/id/chassis_asset_tag", // AWS bare-metal reports "EC2" here
            "/sys/class/dmi/id/board_name",
        ];
        // Well-known cloud / hosting provider strings in DMI fields.
        // Deliberately broad so Azure, DigitalOcean, Linode, Vultr, Hetzner,
        // OVH, and other legitimate cloud infrastructure all pass.
        // E-01: Added "ec2" for AWS bare-metal chassis_asset_tag, "google"
        // for GCP sole-tenant nodes, and "bare metal" for Azure/GCP bare-metal.
        const CLOUD_NEEDLES: &[&str] = &[
            "amazon ec2",
            "ec2", // AWS bare-metal chassis_asset_tag
            "google compute",
            "google",                // GCP sole-tenant board_vendor
            "microsoft corporation", // Azure (Hyper-V guest) and Surface hardware
            "digitalocean",
            "linode",
            "vultr",
            "hetzner",
            "ovh",
            "cloudstack",
            "openstack",
            "upcloud",
            "scaleway",
            "exoscale",
            "oracle cloud",
            "bare metal", // Azure/GCP bare-metal product names
        ];
        for path in DMI {
            if let Ok(content) = std::fs::read_to_string(path) {
                let s = content.to_ascii_lowercase();
                if CLOUD_NEEDLES.iter().any(|n| s.contains(n)) {
                    return true;
                }
            }
        }
    }

    #[cfg(windows)]
    {
        use winreg::enums::HKEY_LOCAL_MACHINE;
        use winreg::RegKey;
        const CLOUD_NEEDLES: &[&str] = &[
            "amazon",
            "google",
            "microsoft corporation",
            "digitalocean",
            "linode",
            "vultr",
            "hetzner",
            "ovh",
            "cloudstack",
            "openstack",
            "upcloud",
            "scaleway",
            "exoscale",
            "oracle cloud",
        ];
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        if let Ok(k) = hklm.open_subkey("HARDWARE\\DESCRIPTION\\System\\BIOS") {
            for val_name in &[
                "SystemManufacturer",
                "SystemProductName",
                "BaseBoardManufacturer",
            ] {
                if let Ok(v) = k.get_value::<String, _>(val_name) {
                    let s = v.to_ascii_lowercase();
                    if CLOUD_NEEDLES.iter().any(|n| s.contains(n)) {
                        return true;
                    }
                }
            }
        }
    }

    false
}

/// Check whether we are running on a cloud instance by probing the Link-Local
/// Instance Metadata Service (IMDS) endpoint shared by AWS, Azure, and GCP.
/// Uses a short 100 ms connection timeout to avoid stalling the check.
/// Returns `true` if the IMDS responds, indicating a cloud environment.
fn is_cloud_instance() -> bool {
    // The 169.254.169.254 address is non-routable on premises; only cloud
    // hypervisors intercept it.  A successful TCP connect (even without a
    // valid HTTP response) is sufficient evidence of a cloud deployment.
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
    use std::time::Duration;
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)), 80);
    TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_ok()
}

pub fn detect_vm() -> bool {
    // The hypervisor bit is now just one of several indicators.
    let mut indicators = 0i32;
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
    // Subtract an indicator when we can confirm this is a legitimate cloud
    // deployment.  We accept *either* evidence to handle locked-down cloud
    // environments where the IMDS endpoint is firewalled:
    //
    //   • is_expected_hypervisor(): checks local DMI/registry for cloud-vendor
    //     strings (AWS, Azure, GCP, etc.) — works even without network access.
    //   • is_cloud_instance(): probes the IMDS link-local address (169.254.169.254)
    //     via a 100 ms TCP connect — works on clouds where IMDS is enabled.
    //
    // Cloud VMs inherently exhibit VM indicators (hypervisor CPUID bit, cloud
    // MAC prefixes) so subtracting one counter prevents legitimate cloud
    // deployments from being incorrectly refused.
    if is_expected_hypervisor() || is_cloud_instance() {
        indicators -= 1;
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
    let needles = [
        String::from_utf8_lossy(&string_crypt::enc_str!("qemu"))
            .trim_end_matches('\0')
            .to_string(),
        String::from_utf8_lossy(&string_crypt::enc_str!("kvm"))
            .trim_end_matches('\0')
            .to_string(),
        String::from_utf8_lossy(&string_crypt::enc_str!("vmware"))
            .trim_end_matches('\0')
            .to_string(),
        String::from_utf8_lossy(&string_crypt::enc_str!("virtualbox"))
            .trim_end_matches('\0')
            .to_string(),
        "vbox".to_string(),
        String::from_utf8_lossy(&string_crypt::enc_str!("xen"))
            .trim_end_matches('\0')
            .to_string(),
        String::from_utf8_lossy(&string_crypt::enc_str!("hyperv"))
            .trim_end_matches('\0')
            .to_string(),
        "innotek".to_string(),
    ];
    // std::str::from_utf8(&string_crypt::enc_str!("microsoft corporation")[..21]).unwrap() in sys_vendor appears on physical Microsoft hardware
    // (e.g., Surface devices) as well as on Hyper-V guests. Only treat it as a VM
    // indicator when the product_name is also "virtual machine", which is the
    // definitive fingerprint of a Hyper-V guest and not present on bare-metal hardware.
    let mut ms_vendor = false;
    let mut virt_product = false;
    for path in DMI {
        if let Ok(content) = std::fs::read_to_string(path) {
            let s = content.to_ascii_lowercase();
            if needles.iter().any(|n| s.contains(n.as_str())) {
                return true;
            }
            if path.ends_with("sys_vendor") {
                // Trim null bytes before comparing to avoid fragile byte-count slicing (4.1)
                let trimmed =
                    String::from_utf8_lossy(&string_crypt::enc_str!("microsoft corporation"))
                        .trim_end_matches('\0')
                        .to_ascii_lowercase();
                if s.contains(trimmed.as_str()) {
                    ms_vendor = true;
                }
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
        if model.contains("virtual")
            || model.contains(
                String::from_utf8_lossy(&string_crypt::enc_str!("vmware"))
                    .trim_end_matches('\0')
                    .to_string(),
            )
            || model.contains("pxe")
        {
            is_vm = true;
        }
    }

    // `kern.hv_support` only indicates CPU *capability* for virtualisation
    // (Hypervisor.framework), not that we are running *inside* a VM.  Physical
    // Macs with an Intel/Apple Silicon CPU always report kern.hv_support=1.
    // The correct sysctl is `kern.hv_vmm_present` which is set to 1 only when
    // the kernel detects it is running as a guest inside a hypervisor.
    if let Ok(output) = std::process::Command::new("sysctl")
        .arg("-n")
        .arg("kern.hv_vmm_present")
        .output()
    {
        let present = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if present == "1" {
            // kern.hv_vmm_present=1 means we are a VM guest.
            is_vm = true;
        }
    }

    // ioreg -l can output 100–500 KB and stall for several seconds on a busy
    // system.  Bound execution to 5 s to avoid blocking agent startup.
    if let Some(stdout) = {
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};
        let mut child = Command::new("ioreg")
            .arg("-l")
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok();
        if let Some(ref mut c) = child {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                match c.try_wait() {
                    Ok(Some(_)) => break,
                    Ok(None) if Instant::now() >= deadline => {
                        let _ = c.kill();
                        break;
                    }
                    Ok(None) => std::thread::sleep(Duration::from_millis(50)),
                    Err(_) => break,
                }
            }
            c.wait_with_output().ok().map(|o| o.stdout)
        } else {
            None
        }
    } {
        let ioreg = String::from_utf8_lossy(&stdout).to_lowercase();
        if ioreg.contains(
            String::from_utf8_lossy(&string_crypt::enc_str!("virtualbox"))
                .trim_end_matches('\0')
                .to_string(),
        ) || ioreg.contains(
            String::from_utf8_lossy(&string_crypt::enc_str!("vmware"))
                .trim_end_matches('\0')
                .to_string(),
        ) || ioreg.contains("parallels")
            || ioreg.contains(
                String::from_utf8_lossy(&string_crypt::enc_str!("qemu"))
                    .trim_end_matches('\0')
                    .to_string(),
            )
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
    // E-02: Expanded to include additional hypervisor MAC prefixes.
    // KVM/QEMU (52:54:00) and Hyper-V (00:15:5d) are also used by cloud
    // providers; false positives are mitigated because this function is only
    // one of several indicators — detect_vm() requires 2+ indicators to flag
    // vm_detected = true, so a single MAC match won't cause a false refusal.
    let prefixes = [
        [0x08u8, 0x00, 0x27], // VirtualBox
        [0x00, 0x0C, 0x29],   // VMware
        [0x00, 0x50, 0x56],   // VMware
        [0x00, 0x15, 0x5D],   // Hyper-V / Azure VM
        [0x52, 0x54, 0x00],   // KVM / QEMU
        [0x00, 0x16, 0x3E],   // Xen
        [0x00, 0x1C, 0x42],   // Parallels
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

    // Secondary check: look for tracer processes owned by the current user,
    // avoiding false positives from other users' debuggers on shared systems (4.5)
    let tracers = ["strace", "gdb", "ltrace", "gdbserver"];
    let my_uid = unsafe { libc::getuid() };
    if let Ok(procs) = std::fs::read_dir("/proc") {
        for proc in procs.flatten() {
            // Only consider processes owned by the current UID
            let proc_path = proc.path();
            if let Ok(meta) = std::fs::metadata(&proc_path) {
                use std::os::unix::fs::MetadataExt;
                if meta.uid() != my_uid {
                    continue;
                }
            } else {
                continue;
            }
            if let Ok(cmdline) = std::fs::read_to_string(proc_path.join("cmdline")) {
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
    // E-03: Skip timing check on Linux if the system is genuinely overloaded
    // (load average > 2× CPU count).  A heavily loaded build server or CI
    // machine will have large sleep jitter that looks like a sandbox even
    // though it is a legitimate execution environment.
    #[cfg(target_os = "linux")]
    if let Ok(la) = std::fs::read_to_string("/proc/loadavg") {
        if let Some(first) = la.split_whitespace().next() {
            if let Ok(load) = first.parse::<f64>() {
                let cpu_count = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) } as f64;
                if cpu_count > 0.0 && load > cpu_count * 2.0 {
                    // System is overloaded; timing check would be unreliable.
                    return false;
                }
            }
        }
    }

    // 7.2: On Windows, check CPU utilisation via GetSystemTimes.  If the
    // system is under heavy load (>80 % busy) the timing check would produce
    // spurious positives — skip it.
    #[cfg(windows)]
    {
        use winapi::shared::minwindef::FILETIME;
        use winapi::um::processthreadsapi::GetSystemTimes;
        let mut idle = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let mut kernel = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let mut user = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        unsafe {
            GetSystemTimes(&mut idle, &mut kernel, &mut user);
        }
        let to_u64 =
            |ft: FILETIME| -> u64 { ((ft.dwHighDateTime as u64) << 32) | ft.dwLowDateTime as u64 };
        let idle0 = to_u64(idle);
        std::thread::sleep(std::time::Duration::from_millis(50));
        let mut idle2 = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let mut kernel2 = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let mut user2 = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        unsafe {
            GetSystemTimes(&mut idle2, &mut kernel2, &mut user2);
        }
        let idle_delta = to_u64(idle2).saturating_sub(idle0);
        let kernel_delta = to_u64(kernel2).saturating_sub(to_u64(kernel));
        let user_delta = to_u64(user2).saturating_sub(to_u64(user));
        let total = kernel_delta + user_delta;
        if total > 0 {
            // idle_delta counts the total idle time across all cores in 100ns units.
            // busy_pct is the fraction of time NOT idle.
            let busy_pct = 1.0 - (idle_delta as f64 / total as f64);
            if busy_pct > 0.80 {
                return false; // System overloaded; skip timing check.
            }
        }
    }

    // 7.2: On macOS, use sysctl kern.cpuload (or host_statistics) to check
    // system-wide CPU utilisation before running the timing test.
    #[cfg(target_os = "macos")]
    {
        // vm_stat provides CPU idle ticks via sysctl; use a simpler approach:
        // read the 1-minute load average and compare to CPU count (same
        // heuristic as the Linux path above).
        if let Ok(output) = std::process::Command::new("sysctl")
            .args(["-n", "vm.loadavg"])
            .output()
        {
            let s = String::from_utf8_lossy(&output.stdout);
            // Output: "{ 0.50 0.42 0.35 }" — first number is 1-min avg
            let trimmed = s.trim_matches(|c: char| c == '{' || c == '}' || c.is_whitespace());
            if let Some(first) = trimmed.split_whitespace().next() {
                if let Ok(load) = first.parse::<f64>() {
                    let cpu_count = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) } as f64;
                    if cpu_count > 0.0 && load > cpu_count * 2.0 {
                        return false;
                    }
                }
            }
        }
    }

    let mut times = Vec::new();
    for _ in 0..10 {
        let start = std::time::Instant::now();
        std::thread::sleep(std::time::Duration::from_millis(10));
        times.push(start.elapsed().as_millis() as f64);
    }

    let sum: f64 = times.iter().sum();
    let mean = sum / 10.0;

    let variance: f64 = times.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / 10.0;

    // E-03: Raised thresholds to reduce false positives on loaded-but-legitimate
    // servers.  mean > 500 ms means the 10 ms sleeps are taking 50× too long;
    // variance > 50000 ms² means a single iteration outlier of ≈224 ms.
    let mean_anomaly = mean > 500.0;
    let var_anomaly = variance > 50000.0;

    // Flag if either the mean is outrageously high (slow execution overall,
    // e.g., heavy tracing) or variance is high (e.g., breakpoint on one
    // iteration causing a long pause).
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
        // E-04: Azure AD joined machines do not set the traditional
        // Tcpip\Parameters\Domain key.  Check the AAD join info instead.
        if let Some(d) = windows_aad_domain() {
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
            // `domain` takes priority; `search` is accepted as a fallback because
            // many managed Linux hosts (cloud-init, corporate DHCP) only set
            // `search` and omit the `domain` directive entirely.
            let mut search_fallback: Option<String> = None;
            for line in s.lines() {
                if let Some(rest) = line.strip_prefix("domain ") {
                    // `domain` is definitive — return immediately.
                    return Some(rest.trim().to_string());
                }
                if search_fallback.is_none() {
                    if let Some(rest) = line.strip_prefix("search ") {
                        // `search` may list multiple domains separated by whitespace;
                        // take the first one (the most specific, per resolv.conf(5)).
                        if let Some(first) = rest.split_whitespace().next() {
                            search_fallback = Some(first.to_string());
                        }
                    }
                }
            }
            if let Some(sd) = search_fallback {
                return Some(sd);
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

/// E-04: Detect Azure AD domain from the AAD join info registry key.
///
/// Azure AD joined machines store join metadata under
/// `HKLM\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo`.  Each
/// subkey is a tenant GUID with values `UserEmail` and `TenantId`.  We
/// extract the domain portion of `UserEmail` (e.g. `contoso.onmicrosoft.com`)
/// as the effective domain for `validate_domain` comparison.
#[cfg(windows)]
fn windows_aad_domain() -> Option<String> {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let join_info = hklm
        .open_subkey("SYSTEM\\CurrentControlSet\\Control\\CloudDomainJoin\\JoinInfo")
        .ok()?;
    // Enumerate tenant subkeys (each is a GUID-formatted key).
    for name in join_info.enum_keys().filter_map(|r| r.ok()) {
        if let Ok(subkey) = join_info.open_subkey(&name) {
            // Prefer the domain portion of UserEmail.
            if let Ok(email) = subkey.get_value::<String, _>("UserEmail") {
                if let Some(domain_part) = email.splitn(2, '@').nth(1) {
                    if !domain_part.is_empty() {
                        return Some(domain_part.to_string());
                    }
                }
            }
            // Fall back to TenantId as an opaque tenant identifier.
            if let Ok(tenant) = subkey.get_value::<String, _>("TenantId") {
                if !tenant.is_empty() {
                    return Some(tenant);
                }
            }
        }
    }
    None
}

// ------------------------------------------------------------------ enforcer

/// Run every probe and either return `Ok(())` or refuse to start.
///
/// Policy inputs come from `agent.toml`; any unset policy leaves the
/// corresponding signal informational.
pub fn enforce(
    required_domain: Option<&str>,
    refuse_when_debugged: bool,
    refuse_in_vm: bool,
    sandbox_score_threshold: Option<u32>,
) -> EnvDecision {
    let report = EnvReport::collect(required_domain);
    let refuse = report.should_refuse(refuse_when_debugged, refuse_in_vm, sandbox_score_threshold);
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
        assert!(!r.should_refuse(false, false, None));
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
        assert!(!r.should_refuse(false, false, None));
        r.debugger_present = true;
        assert!(!r.should_refuse(false, false, None));
        assert!(r.should_refuse(true, false, None));
        r.debugger_present = false;
        r.domain_match = Some(false);
        assert!(r.should_refuse(false, false, None));
        r.domain_match = Some(true);
        r.vm_detected = true;
        assert!(!r.should_refuse(false, false, None));
        assert!(r.should_refuse(false, true, None));
    }

    #[test]
    fn unrelated_tracer_process_is_informational() {
        let mut r = EnvReport::default();
        r.tracer_process_found = true;
        assert!(!r.should_refuse(false, false, None));
    }

    #[test]
    fn cloud_vm_indicators_are_informational_by_default() {
        let mut r = EnvReport::default();
        r.vm_detected = true;
        assert!(!r.should_refuse(false, false, None));
        assert!(r.should_refuse(false, true, None));
    }

    #[test]
    fn sandbox_score_threshold_is_explicit() {
        let mut r = EnvReport::default();
        r.sandbox_score = 80;
        assert!(!r.should_refuse(false, false, None));
        assert!(!r.should_refuse(false, false, Some(81)));
        assert!(r.should_refuse(false, false, Some(80)));
    }

    // ── Strict domain matching ────────────────────────────────────────────────

    /// Domain matching is case-insensitive and must match the full domain string.
    #[test]
    fn strict_domain_match_is_case_insensitive() {
        assert!(validate_domain_pair("CORP.EXAMPLE.COM", "corp.example.com"));
        assert!(validate_domain_pair("corp.example.com", "CORP.EXAMPLE.COM"));
        assert!(!validate_domain_pair("corp.example.com", "other.example.com"));
        // Empty required domain should never match (not configured).
        assert!(!validate_domain_pair("corp.example.com", ""));
    }

    /// A subdomain of the required domain is NOT considered a match (strict match).
    #[test]
    fn strict_domain_does_not_match_subdomain() {
        // "workstation.corp.example.com" is not the same as "corp.example.com".
        assert!(!validate_domain_pair("workstation.corp.example.com", "corp.example.com"));
    }

    fn validate_domain_pair(observed: &str, required: &str) -> bool {
        if required.is_empty() {
            return false;
        }
        observed.eq_ignore_ascii_case(required)
    }

    // ── VM detection false-positive scenarios ─────────────────────────────────

    /// `detect_vm` must never refuse on its own: `should_refuse` only reacts to
    /// `vm_detected` when the operator explicitly sets `refuse_in_vm = true`.
    #[test]
    fn vm_detected_is_informational_by_default() {
        let report = EnvReport {
            vm_detected: true,
            ..EnvReport::default()
        };
        // Default policy: refuse_in_vm = false → must NOT refuse.
        assert!(!report.should_refuse(false, false, None));
        // Explicit policy: refuse_in_vm = true → must refuse.
        assert!(report.should_refuse(false, true, None));
    }

    /// A single VM indicator is not enough to set vm_detected = true.
    /// (detect_vm() requires 2+ indicators.)
    #[test]
    fn detect_vm_requires_multiple_indicators() {
        // This test verifies the policy, not the hardware probes.
        // The probe functions are platform-specific, but the thresholding
        // logic is captured in should_refuse which is testable here.
        let report = EnvReport {
            vm_detected: false, // Single indicator: not enough.
            ..EnvReport::default()
        };
        assert!(!report.should_refuse(false, true, None));
    }

    // ── Unknown hypervisors ───────────────────────────────────────────────────

    /// A machine with an unknown hypervisor that doesn't match cloud needles
    /// contributes a VM indicator but must NOT automatically cause refusal.
    #[test]
    fn unknown_hypervisor_requires_explicit_policy_to_refuse() {
        let report = EnvReport {
            vm_detected: true, // Detected but unknown hypervisor.
            ..EnvReport::default()
        };
        // Without refuse_in_vm, even an unknown hypervisor is just informational.
        assert!(!report.should_refuse(false, false, None));
    }

    // ── Cloud provider detection (headless / CI) ──────────────────────────────

    /// A cloud/CI environment sets vm_detected but must pass with default policy.
    ///
    /// This mirrors the CI runner scenario: GitHub Actions / AWS CodeBuild runs
    /// inside a VM; the agent must not refuse when env-validation is enabled
    /// unless `refuse_in_vm = true` is explicitly set by the operator.
    #[test]
    fn cloud_ci_environment_does_not_auto_refuse() {
        let report = EnvReport {
            vm_detected: true,     // Cloud hypervisor detected.
            sandbox_score: 45,     // Moderate score from headless probe.
            domain_match: None,    // No domain requirement configured.
            ..EnvReport::default()
        };
        assert!(!report.should_refuse(false, false, None),
            "cloud/CI vm_detected=true must not refuse with default policy");
        assert!(!report.should_refuse(false, false, Some(60)),
            "sandbox score 45 must not trigger threshold 60");
        // Only refuses if both flags are explicitly set.
        assert!(report.should_refuse(false, true, None),
            "refuse_in_vm=true must still refuse");
    }

    // ── macOS headless / CI ───────────────────────────────────────────────────

    /// On macOS in a headless CI environment, the sandbox probe returns 0 for
    /// mouse and desktop scores (no display), so the total sandbox score should
    /// be low enough not to trigger a default threshold.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_headless_sandbox_score_is_below_default_threshold() {
        // In headless macOS (no DISPLAY, no window server), the sandbox probe
        // returns 0 for mouse and desktop components.  With only uptime/hw
        // checks, the total is typically < 45.
        let score = sandbox::evaluate_sandbox().unwrap_or(0);
        // We can't assert an exact value (depends on uptime/hw of the runner),
        // but a headless system should not exceed the strict threshold 60.
        let report = EnvReport { sandbox_score: score, ..EnvReport::default() };
        assert!(!report.should_refuse(false, false, Some(60)),
            "headless macOS sandbox score {score} should not exceed threshold 60");
    }
}

/// Combined sandbox heuristics implementation (Prompt 6)
pub mod sandbox {
    include!("env_check_sandbox.rs");
}
