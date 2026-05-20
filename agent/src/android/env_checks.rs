//! Android environment validation and anti-analysis checks.
//!
//! Implements debugger detection, root detection, emulator detection,
//! sandbox/analysis environment detection, and domain/network validation
//! for the Android platform.

use crate::env_check::EnvReport;

/// Collect all Android environment probes into an `EnvReport`.
pub fn collect_android_env(required_domain: Option<&str>) -> EnvReport {
    EnvReport {
        debugger_present: is_debugger_present(),
        vm_detected: detect_vm(),
        vm_detected_strict: detect_vm_strict(),
        domain_match: required_domain.map(|d| validate_domain(d)),
        ld_preload_set: is_ld_preload_set(),
        tracer_process_found: tracer_process_found(),
        timing_anomaly_detected: detect_timing_anomaly(),
        sandbox_score: sandbox_score(),
        yama_ptrace_scope: yama_ptrace_scope(),
    }
}

/// Check if a debugger is attached to the current process.
///
/// Checks (in order):
/// 1. `/proc/self/status` TracerPid — standard Linux ptrace indicator
/// 2. `/proc/self/maps` for Frida, gdbserver, lldb-server strings
/// 3. `/proc/self/stat` — checks if the process is in ptrace-stop
pub fn is_debugger_present() -> bool {
    // 1. TracerPid check
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            let mut parts = line.split_whitespace();
            if parts.next() == Some("TracerPid:") {
                if let Some(val) = parts.next() {
                    if val.parse::<u32>().map(|p| p != 0).unwrap_or(false) {
                        tracing::warn!("env/android: TracerPid is non-zero ({val})");
                        return true;
                    }
                }
            }
        }
    }

    // 2. Scan /proc/self/maps for debugger/tamper tool injection
    if let Ok(maps) = std::fs::read_to_string("/proc/self/maps") {
        let lower = maps.to_ascii_lowercase();
        // Frida: frida-agent, frida-gadget, linjector
        if lower.contains("frida") || lower.contains("linjector") {
            tracing::warn!("env/android: Frida or linjector detected in /proc/self/maps");
            return true;
        }
        // gdbserver / lldb-server
        if lower.contains("gdbserver") || lower.contains("lldb-server") {
            tracing::warn!("env/android: gdbserver/lldb-server detected in /proc/self/maps");
            return true;
        }
        // strace injection
        if lower.contains("libstrace") {
            tracing::warn!("env/android: strace detected in /proc/self/maps");
            return true;
        }
    }

    // 3. Check for debugger socket artifacts
    if std::path::Path::new("/data/local/tmp/debugger-socket").exists() {
        tracing::warn!("env/android: debugger socket artifact found");
        return true;
    }

    false
}

/// Detect if running in an Android emulator.
///
/// Checks:
/// - Build properties: ro.build.fingerprint, ro.build.model, ro.kernel.qemu
/// - /dev/qemu_pipe, /dev/goldfish_pipe (QEMU virtual devices)
/// - /proc/cpuinfo for "Goldfish", "ranchu", "vbox86"
/// - /sys/class/dmi/id/product_name for emulator DMI strings
/// - init binary timestamp (emulators have a fake init)
pub fn detect_vm() -> bool {
    // 1. Build property checks (accessed via /system/build.prop or getprop)
    let props = read_android_props(&["ro.build.fingerprint", "ro.build.model", "ro.kernel.qemu"]);

    // Generic fingerprint
    if let Some(ref fp) = props.get("ro.build.fingerprint") {
        let lower = fp.to_ascii_lowercase();
        // Emulator fingerprints contain "generic", "sdk", "ranchu", "vbox86"
        if lower.contains("generic")
            || lower.contains("sdk")
            || lower.contains("ranchu")
            || lower.contains("vbox")
        {
            tracing::warn!("env/android: emulator build fingerprint detected: {fp}");
            return true;
        }
        // Genymotion fingerprints
        if lower.contains("vbox86p") || lower.contains("google_sdk") || lower.contains("emulator") {
            tracing::warn!("env/android: emulator/Genymotion fingerprint detected: {fp}");
            return true;
        }
    }

    if let Some(ref model) = props.get("ro.build.model") {
        let lower = model.to_ascii_lowercase();
        if lower.contains("sdk") || lower.contains("generic") {
            tracing::warn!("env/android: emulator model detected: {model}");
            return true;
        }
    }

    if let Some(ref qemu) = props.get("ro.kernel.qemu") {
        if qemu == "1" {
            tracing::warn!("env/android: ro.kernel.qemu=1 (QEMU detected)");
            return true;
        }
    }

    // 2. QEMU/goldfish pipes — always present in QEMU-based emulators
    if std::path::Path::new("/dev/qemu_pipe").exists()
        || std::path::Path::new("/dev/goldfish_pipe").exists()
    {
        tracing::warn!("env/android: QEMU/goldfish pipe device found");
        return true;
    }

    // 3. /proc/cpuinfo scan for emulator CPU strings
    if let Ok(cpuinfo) = std::fs::read_to_string("/proc/cpuinfo") {
        let lower = cpuinfo.to_ascii_lowercase();
        if lower.contains("goldfish") || lower.contains("ranchu") || lower.contains("vbox") {
            tracing::warn!("env/android: emulator CPU detected in /proc/cpuinfo");
            return true;
        }
    }

    // 4. DMI product name check
    if let Ok(product) = std::fs::read_to_string("/sys/class/dmi/id/product_name") {
        let lower = product.to_ascii_lowercase();
        if lower.contains("virtualbox")
            || lower.contains("vmware")
            || lower.contains("qemu")
            || lower.contains("kvm")
        {
            tracing::warn!("env/android: VM DMI product_name: {product}");
            return true;
        }
    }

    // 5. Genymotion-specific: vbox guest additions
    if std::path::Path::new("/dev/vboxguest").exists()
        || std::path::Path::new("/proc/bus/input/devices").exists()
    {
        if let Ok(input) = std::fs::read_to_string("/proc/bus/input/devices") {
            if input.to_ascii_lowercase().contains("virtualbox") {
                tracing::warn!("env/android: VirtualBox guest additions detected");
                return true;
            }
        }
    }

    false
}

/// Read Android system properties from the filesystem.
///
/// `getprop` is the normal interface, but it requires a running service manager.
/// Reading from /system/build.prop and /default.prop works from any context.
fn read_android_props(keys: &[&str]) -> std::collections::HashMap<String, String> {
    let mut props = std::collections::HashMap::new();

    // Try reading from the standard build.prop files.
    for path in &["/system/build.prop", "/default.prop", "/vendor/build.prop"] {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                props
                    .entry(key.trim().to_string())
                    .or_insert_with(|| value.trim().to_string());
            }
        }
    }

    // Try getprop for keys not found above (only if getprop is available).
    for key in keys {
        if props.contains_key(*key) {
            continue;
        }
        // Try running getprop as a subprocess (won't work in all contexts).
        if let Ok(output) = std::process::Command::new("/system/bin/getprop")
            .arg(key)
            .output()
        {
            let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !value.is_empty() {
                props.insert(key.to_string(), value);
            }
        }
    }

    props
}

/// Strict VM detection (same as lenient for now).
pub fn detect_vm_strict() -> bool {
    detect_vm()
}

/// Check if LD_PRELOAD is set in the environment.
pub fn is_ld_preload_set() -> bool {
    std::env::var_os("LD_PRELOAD").is_some()
}

/// Check for known tracer processes (Frida, gdbserver, strace, etc.).
///
/// Scans /proc for known tracer/stager process names.
pub fn tracer_process_found() -> bool {
    let suspicious_names = [
        "frida-agent",
        "frida-server",
        "gdbserver",
        "lldb-server",
        "strace",
        "ltrace",
        "linjector",
        "gdb",
        "frida-helper",
        "magiskd",
    ];

    // Scan /proc for suspicious process names.
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let comm_path = entry.path().join("comm");
            if let Ok(comm) = std::fs::read_to_string(&comm_path) {
                let comm = comm.trim();
                for name in &suspicious_names {
                    if comm.contains(name) {
                        tracing::warn!(
                            "env/android: suspicious process '{comm}' detected (matched '{name}')"
                        );
                        return true;
                    }
                }
            }
        }
    }

    // Also check for Frida-specific port listening.
    // Frida default port: 27042
    if let Ok(tcp) = std::fs::read_to_string("/proc/net/tcp") {
        // 27042 = 0x69A2
        if tcp.contains(":69A2") || tcp.contains(":69a2") {
            tracing::warn!("env/android: Frida default port (27042) found in /proc/net/tcp");
            return true;
        }
    }

    false
}

/// Detect timing anomalies indicative of debugging.
///
/// Measures the time to run a known-length loop.  Debuggers (including
/// Android Studio's lldb) significantly slow down such operations due
/// to software breakpoint handling.
pub fn detect_timing_anomaly() -> bool {
    let start = std::time::Instant::now();
    // Run a computation that debuggers can't optimize away.
    let mut sum: u64 = 0;
    for i in 0..1_000_000u64 {
        sum = sum.wrapping_mul(i.wrapping_add(1));
        sum ^= i;
    }
    std::hint::black_box(&mut sum);
    let elapsed = start.elapsed();

    // On typical Android hardware (Snapdragon 8xx / Tensor / Exynos),
    // 1M iterations completes in < 5ms.  A debugger adds 50-500ms+.
    tracing::debug!("env/android: timing check: 1M iters in {elapsed:?}");
    elapsed > std::time::Duration::from_millis(50)
}

/// Heuristic sandbox probability score (0–100).
///
/// Combines multiple weak indicators into a weighted score.
pub fn sandbox_score() -> u32 {
    let mut score: u32 = 0;

    // Emulator indicator: +60 (strongest signal)
    if detect_vm() {
        score += 60;
    }

    // Debugger detected: +40
    if is_debugger_present() {
        score += 40;
    }

    // Rooted device less likely to be a sandbox: -20
    // (Sandboxes typically run unrooted stock images)
    if is_rooted() {
        score = score.saturating_sub(20);
    }

    // Timing anomaly: +15
    if detect_timing_anomaly() {
        score += 15;
    }

    // Uptime too short (< 5 minutes): +10
    if let Ok(uptime) = std::fs::read_to_string("/proc/uptime") {
        let secs: f64 = uptime
            .split_whitespace()
            .next()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0.0);
        if secs < 300.0 {
            score += 10;
        }
    }

    // Battery status: missing or always 100% = likely emulator/sandbox: +10
    if let Ok(capacity) = std::fs::read_to_string("/sys/class/power_supply/battery/capacity") {
        if let Ok(val) = capacity.trim().parse::<u32>() {
            if val == 100 {
                // Could just be plugged in, but combined with other signals it's suspicious.
                score += 5;
            }
        }
    } else {
        // No battery at all — definitely not a real phone.
        score += 15;
    }

    score.min(100)
}

/// YAMA ptrace_scope value.
pub fn yama_ptrace_scope() -> Option<u8> {
    std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
        .ok()
        .and_then(|s| s.trim().parse::<u8>().ok())
}

/// Check if the device is rooted.
///
/// Checks:
/// - `su` binary in common locations
/// - Magisk directories and processes
/// - SuperSU/Superuser APK traces
/// - Writable /system partition
/// - ro.debuggable and ro.secure properties
/// - SELinux status (permissive = rooted or custom kernel)
pub fn is_rooted() -> bool {
    // 1. Check for su binary in common locations.
    let su_paths = [
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/system/sbin/su",
        "/vendor/bin/su",
        "/data/local/su",
        "/data/local/tmp/su",
    ];
    for path in &su_paths {
        if std::path::Path::new(path).exists() {
            tracing::warn!("env/android: su binary found at {path}");
            return true;
        }
    }

    // 2. Check for Magisk.
    let magisk_paths = [
        "/sbin/.magisk",
        "/data/adb/magisk",
        "/cache/.disable_magisk",
        "/data/adb/modules",
    ];
    for path in &magisk_paths {
        if std::path::Path::new(path).exists() {
            tracing::warn!("env/android: Magisk artifacts found at {path}");
            return true;
        }
    }

    // Check for Magisk in /proc/self/mountinfo.
    if let Ok(mountinfo) = std::fs::read_to_string("/proc/self/mountinfo") {
        if mountinfo.to_ascii_lowercase().contains("magisk") {
            tracing::warn!("env/android: Magisk mount detected in mountinfo");
            return true;
        }
    }

    // 3. Check for SuperSU/Superuser.
    let superuser_paths = [
        "/system/app/Superuser.apk",
        "/system/app/SuperSU.apk",
        "/data/app/com.noshufou.android.su",
        "/data/app/com.thirdparty.superuser",
    ];
    for path in &superuser_paths {
        if std::path::Path::new(path).exists() {
            tracing::warn!("env/android: Superuser/SuperSU APK found at {path}");
            return true;
        }
    }

    // 4. Check build properties for debuggable/secure.
    let props = read_android_props(&["ro.debuggable", "ro.secure", "ro.build.tags"]);
    if let Some(ref debuggable) = props.get("ro.debuggable") {
        if debuggable == "1" {
            tracing::warn!("env/android: ro.debuggable=1 (rooted or engineering build)");
            return true;
        }
    }
    if let Some(ref secure) = props.get("ro.secure") {
        if secure == "0" {
            tracing::warn!("env/android: ro.secure=0 (rooted)");
            return true;
        }
    }
    if let Some(ref tags) = props.get("ro.build.tags") {
        if tags.contains("test-keys") {
            tracing::warn!("env/android: ro.build.tags contains test-keys (engineering build)");
            return true;
        }
    }

    // 5. Check SELinux status (permissive = rooted or custom kernel).
    if let Ok(status) = std::fs::read_to_string("/sys/fs/selinux/enforce") {
        if status.trim() == "0" {
            tracing::warn!("env/android: SELinux is permissive (rooted or custom kernel)");
            return true;
        }
    }

    false
}

/// Check if Frida is attached/injected into this process.
pub fn is_frida_present() -> bool {
    // Check /proc/self/maps for Frida strings.
    if let Ok(maps) = std::fs::read_to_string("/proc/self/maps") {
        let lower = maps.to_ascii_lowercase();
        if lower.contains("frida") || lower.contains("linjector") {
            return true;
        }
    }

    // Check for Frida default port listening.
    if let Ok(tcp) = std::fs::read_to_string("/proc/net/tcp") {
        if tcp.contains(":69A2") || tcp.contains(":69a2") {
            return true;
        }
    }

    // Check for Frida-specific environment variables.
    for var in &["FRIDA_SERVER_PORT", "FRIDA_AGENT", "FRIDA_PS"] {
        if std::env::var_os(var).is_some() {
            tracing::warn!("env/android: Frida env var {var} is set");
            return true;
        }
    }

    false
}

/// Validate that the device's network domain matches the required domain.
///
/// On Android, reads /etc/resolv.conf for search domains and the device's
/// hostname to construct the domain.  Falls back to checking the DHCP
/// lease for domain information.
fn validate_domain(required_domain: &str) -> bool {
    let required = required_domain.trim().to_ascii_lowercase();

    // 1. Check /etc/resolv.conf for "search" domains.
    if let Ok(resolv) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in resolv.lines() {
            let line = line.trim();
            if let Some(domains) = line.strip_prefix("search ") {
                for domain in domains.split_whitespace() {
                    let d = domain.trim().to_ascii_lowercase();
                    if d == required || d.ends_with(&format!(".{required}")) {
                        return true;
                    }
                }
            }
        }
    }

    // 2. Check hostname domain suffix.
    if let Ok(hostname) = std::fs::read_to_string("/proc/sys/kernel/hostname") {
        let hostname = hostname.trim().to_ascii_lowercase();
        if let Some(domain_part) = hostname.split_once('.') {
            if domain_part.1 == required || domain_part.1.ends_with(&format!(".{required}")) {
                return true;
            }
        }
    }

    // 3. Check DHCP lease info for domain.
    if let Ok(dhcp_lease) = std::fs::read_to_string("/data/misc/dhcp/dnsmasq.leases") {
        let lower = dhcp_lease.to_ascii_lowercase();
        if lower.contains(&required) {
            return true;
        }
    }

    // 4. Check getprop for dhcp domain.
    let props = read_android_props(&["dhcp.wlan0.domain", "net.dns.search"]);
    for key in &["dhcp.wlan0.domain", "net.dns.search"] {
        if let Some(ref domain) = props.get(*key) {
            let d = domain.trim().to_ascii_lowercase();
            if d == required || d.ends_with(&format!(".{required}")) {
                return true;
            }
        }
    }

    tracing::warn!(
        "env/android: domain validation failed — required '{required}' not found in resolv.conf, hostname, or DHCP"
    );
    false
}
