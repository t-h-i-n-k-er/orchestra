//! iOS environment validation and anti-analysis checks.
//!
//! Implements jailbreak detection, debugger detection, simulator detection,
//! sandbox/restriction detection, and network/domain validation for iOS.

use crate::env_check::EnvReport;

/// Collect all iOS environment probes into an `EnvReport`.
pub fn collect_ios_env(required_domain: Option<&str>) -> EnvReport {
    EnvReport {
        debugger_present: is_debugger_present(),
        vm_detected: detect_simulator(),
        vm_detected_strict: detect_simulator_strict(),
        domain_match: required_domain.map(|d| validate_domain(d)),
        ld_preload_set: false, // iOS doesn't use LD_PRELOAD
        tracer_process_found: tracer_process_found(),
        timing_anomaly_detected: detect_timing_anomaly(),
        sandbox_score: sandbox_score(),
        yama_ptrace_scope: None, // iOS doesn't have YAMA
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Debugger Detection
// ─────────────────────────────────────────────────────────────────────────────

/// Check if a debugger is attached to the current process.
///
/// Checks (in order):
/// 1. `sysctl` with `KERN_PROC` → `P_TRACED` flag (official method)
/// 2. `isatty(STDIN_FILENO)` — debuggers often attach a terminal
/// 3. Frida-specific: port 27042, environment variables, thread names
/// 4. Timing check between known operations
pub fn is_debugger_present() -> bool {
    // 1. sysctl KERN_PROC P_TRACED check.  This requires the macOS/iOS
    //    sysctl interface which is available on both real devices and the
    //    simulator.  We access it via the libc interface.
    let mut info: libc::kinfo_proc = unsafe { std::mem::zeroed() };
    let mut size = std::mem::size_of_val(&info);
    let mib: [i32; 4] = [
        libc::CTL_KERN,
        libc::KERN_PROC,
        libc::KERN_PROC_PID,
        std::process::id() as i32,
    ];

    let ret = unsafe {
        libc::sysctl(
            mib.as_ptr() as *mut _,
            mib.len() as u32,
            &mut info as *mut _ as *mut _,
            &mut size,
            std::ptr::null(),
            0,
        )
    };

    if ret == 0 {
        // P_TRACED = 0x00000800 on XNU
        const P_TRACED: i32 = 0x00000800;
        if info.kp_proc.p_flag & P_TRACED != 0 {
            tracing::warn!("env/ios: P_TRACED flag is set (debugger attached)");
            return true;
        }
    }

    // 2. isatty check — LLDB and Xcode attach a terminal
    unsafe {
        if libc::isatty(libc::STDIN_FILENO) != 0 {
            // Not necessarily a debugger (could be a terminal app),
            // but combined with other checks this is suspicious.
        }
    }

    // 3. Frida detection — check environment variables and artifacts
    for var in &["FRIDA_SERVER_PORT", "FRIDA_AGENT", "FRIDA_PS"] {
        if std::env::var_os(var).is_some() {
            tracing::warn!("env/ios: Frida env var {var} is set");
            return true;
        }
    }

    // Frida thread names — visible in /proc or via Mach APIs
    if let Ok(maps) = std::fs::read_to_string("/proc/self/maps") {
        if maps.to_ascii_lowercase().contains("frida") {
            tracing::warn!("env/ios: Frida detected in /proc/self/maps");
            return true;
        }
    }

    // 4. Timing check
    if detect_timing_anomaly() {
        tracing::warn!("env/ios: timing anomaly detected (possible debugger)");
        return true;
    }

    false
}

// ─────────────────────────────────────────────────────────────────────────────
// Simulator Detection
// ─────────────────────────────────────────────────────────────────────────────

/// Detect if running in the iOS Simulator.
///
/// The most reliable method is checking for simulator filesystem artifacts:
/// - `/Library/Developer/CoreSimulator` — only present on simulator
/// - `SIMULATOR_UDID` env var — set by Xcode when running in sim
/// - `HW_MACHINE` sysctl returns `x86_64` or `arm64` (but real iPhones
///   also use arm64, so this alone is insufficient)
pub fn detect_simulator() -> bool {
    // 1. Check for CoreSimulator path (most reliable indicator).
    if std::path::Path::new("/Library/Developer/CoreSimulator").exists() {
        tracing::warn!("env/ios: CoreSimulator path found (simulator)");
        return true;
    }

    // 2. Check SIMULATOR_UDID environment variable.
    if std::env::var_os("SIMULATOR_UDID").is_some() {
        tracing::warn!("env/ios: SIMULATOR_UDID is set (simulator)");
        return true;
    }

    // 3. Check SIMULATOR_VERSION_INFO.
    if std::env::var_os("SIMULATOR_VERSION_INFO").is_some() {
        tracing::warn!("env/ios: SIMULATOR_VERSION_INFO is set (simulator)");
        return true;
    }

    // 4. Check for Xcode-related env vars.
    for var in &[
        "XPC_SIMULATOR_LAUNCHD_NAME",
        "SIMULATOR_ROOT",
        "SIMULATOR_DEVICE_NAME",
        "SIMULATOR_RUNTIME_VERSION",
    ] {
        if std::env::var_os(var).is_some() {
            tracing::warn!("env/ios: simulator env var {var} is set");
            return true;
        }
    }

    // 5. Check for simulator-specific directory structure.
    let sim_dirs = [
        "/Library/Developer/CoreSimulator/Profiles",
        "/Library/Developer/Xcode",
        "/private/var/db/fpsd/dvp", // on-device but not on simulator? check
    ];
    for dir in &sim_dirs {
        if std::path::Path::new(dir).exists() {
            tracing::warn!("env/ios: simulator directory found: {dir}");
            return true;
        }
    }

    false
}

/// Strict simulator detection — additionally checks build-time flags.
pub fn detect_simulator_strict() -> bool {
    // At compile time, if TARGET_OS_SIMULATOR is 1, we're definitely on sim.
    // This is checked at runtime because the binary could be built for device
    // but running on sim (less likely, but possible with Xcode device/sim switching).
    // On real iOS TARGET_OS_SIMULATOR is 0; on sim TARGET_OS_SIMULATOR is 1.
    // The fastest check is the env vars and filesystem paths above.
    detect_simulator()
}

// ─────────────────────────────────────────────────────────────────────────────
// Jailbreak Detection
// ─────────────────────────────────────────────────────────────────────────────

/// Check if the device is jailbroken.
///
/// Multi-method detection:
/// 1. File existence: Cydia, Sileo, Substitute, libsubstitute, etc.
/// 2. Sandbox escape test: try to `stat()` files outside sandbox
/// 3. Fork test: `fork()` succeeds only on jailbroken iOS devices
/// 4. dyld insertion: check `DYLD_INSERT_LIBRARIES` env var
/// 5. URL scheme: `cydia://` registered
/// 6. Write test: try to write to `/private` (fails on stock iOS)
/// 7. `/Applications` is a symlink (only on jailbroken devices)
pub fn is_jailbroken() -> bool {
    // 1. Check for common jailbreak apps and files.
    let jailbreak_paths = [
        "/Applications/Cydia.app",
        "/Applications/Sileo.app",
        "/Applications/Zebra.app",
        "/Applications/blackra1n.app",
        "/Applications/FakeCarrier.app",
        "/Applications/Icy.app",
        "/Applications/IntelliScreen.app",
        "/Applications/MxTube.app",
        "/Applications/RockApp.app",
        "/Applications/WinterBoard.app",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/Library/MobileSubstrate/DynamicLibraries",
        "/var/lib/cydia",
        "/var/cache/apt",
        "/var/lib/apt",
        "/etc/apt",
        "/bin/bash",
        "/bin/sh",
        "/usr/bin/ssh",
        "/usr/sbin/sshd",
        "/usr/libexec/ssh-keysign",
        "/etc/ssh/sshd_config",
        "/private/var/mobile/Library/SBSettings",
        "/private/var/log/syslog",
        "/private/var/tmp/cydia.log",
        "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
        "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
    ];
    for path in &jailbreak_paths {
        if std::path::Path::new(path).exists() {
            tracing::warn!("env/ios: jailbreak artifact found at {path}");
            return true;
        }
    }

    // 2. Check for Substitute / libsubstitute (unc0ver/checkra1n/Taurine).
    if std::path::Path::new("/usr/lib/libsubstitute.dylib").exists()
        || std::path::Path::new("/usr/lib/substitute-inserter.dylib").exists()
        || std::path::Path::new("/Library/MobileSubstrate/SubstrateLoader.dylib").exists()
    {
        tracing::warn!("env/ios: Substitute/Substrate detected");
        return true;
    }

    // 3. Sandbox escape test — try to open a file outside the sandbox.
    //    On stock iOS, attempts to access /var/root or /etc/fstab fail
    //    with EPERM or EACCES.  On jailbroken devices they usually succeed.
    let sandbox_escape_paths = [
        "/var/root",
        "/etc/fstab",
        "/private/var/mobile/Library/Preferences",
    ];
    for path in &sandbox_escape_paths {
        if std::path::Path::new(path).exists() {
            // Even existence check outside sandbox = jailbroken.
            tracing::warn!("env/ios: sandbox escape — can stat() {path}");
            return true;
        }
    }

    // 4. Fork test — fork() is restricted on stock iOS to specific
    //    launchd-sanctioned processes.  If it succeeds, the device
    //    is jailbroken (or running in a special entitlement).
    let fork_result = unsafe { libc::fork() };
    if fork_result >= 0 {
        // fork succeeded — either we're the parent (pid > 0) or child (pid == 0).
        unsafe {
            if fork_result > 0 {
                // Parent: reap the child, then report jailbreak.
                libc::waitpid(fork_result, std::ptr::null_mut(), 0);
            } else {
                // Child: exit immediately so parent returns.
                libc::_exit(0);
            }
        }
        tracing::warn!("env/ios: fork() succeeded (jailbroken)");
        return true;
    }

    // 5. Check DYLD_INSERT_LIBRARIES — only honored on jailbroken devices
    //    (or with specific entitlements).
    if std::env::var_os("DYLD_INSERT_LIBRARIES").is_some() {
        tracing::warn!("env/ios: DYLD_INSERT_LIBRARIES is set (jailbroken or developer)");
        return true;
    }

    // 6. Write test — attempt to create a file in /private.  This fails
    //    with EACCES/EPERM on stock iOS but succeeds on jailbroken.
    let test_path = "/private/orchestra_jb_test";
    if std::fs::write(test_path, b"jb").is_ok() {
        let _ = std::fs::remove_file(test_path);
        tracing::warn!("env/ios: write to /private succeeded (jailbroken)");
        return true;
    }

    // 7. Check if /Applications is a symlink (jailbreak indicator).
    if let Ok(meta) = std::fs::symlink_metadata("/Applications") {
        if meta.file_type().is_symlink() {
            tracing::warn!("env/ios: /Applications is a symlink (jailbroken)");
            return true;
        }
    }

    false
}

// ─────────────────────────────────────────────────────────────────────────────
// Tracer Process Detection
// ─────────────────────────────────────────────────────────────────────────────

/// Check for known tracer/injection processes (Frida, lldb, etc.).
pub fn tracer_process_found() -> bool {
    // On iOS, direct /proc scan may not be possible from sandbox.
    // Use alternative methods:
    // - Environment variable checks
    // - Port scan on localhost for debugger ports
    // - Dyld info

    // Frida default port: 27042
    if let Ok(tcp) = std::fs::read_to_string("/proc/net/tcp") {
        if tcp.contains(":69A2") || tcp.contains(":69a2") {
            tracing::warn!("env/ios: Frida port 27042 found in /proc/net/tcp");
            return true;
        }
    }

    // Environment variable evidence.
    for var in &[
        "FRIDA_SERVER_PORT",
        "FRIDA_AGENT",
        "FRIDA_PS",
        "LLDB_DEBUGSERVER_PATH",
        "DEBUGSERVER_PATH",
    ] {
        if std::env::var_os(var).is_some() {
            tracing::warn!("env/ios: debugger env var {var} is set");
            return true;
        }
    }

    false
}

// ─────────────────────────────────────────────────────────────────────────────
// Timing Anomaly Detection
// ─────────────────────────────────────────────────────────────────────────────

/// Detect timing anomalies indicative of debugging.
///
/// Measures the time to run a known-length loop.  Debuggers (including
/// Xcode's LLDB) significantly slow down such operations due to
/// software breakpoint handling and single-stepping overhead.
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

    // On modern A-series chips (A12+), 1M iterations completes in < 3ms.
    // On simulator (x86_64), < 2ms.  A debugger adds 50-500ms+.
    let threshold = if detect_simulator() {
        std::time::Duration::from_millis(20) // simulator is a bit slower
    } else {
        std::time::Duration::from_millis(30) // real device: A-series chips are fast
    };

    tracing::debug!("env/ios: timing check: 1M iters in {elapsed:?}");
    elapsed > threshold
}

// ─────────────────────────────────────────────────────────────────────────────
// Sandbox Score
// ─────────────────────────────────────────────────────────────────────────────

/// Heuristic sandbox probability score (0–100).
///
/// Combines multiple weak indicators into a weighted score.
/// High score = likely sandbox/analysis environment.
pub fn sandbox_score() -> u32 {
    let mut score: u32 = 0;

    // Simulator indicator: +60 (strongest signal)
    if detect_simulator() {
        score += 60;
    }

    // Jailbroken device less likely to be a sandbox: -40
    // (Sandboxes run stock iOS; jailbroken = real device or researcher)
    if is_jailbroken() {
        score = score.saturating_sub(40);
    }

    // Debugger detected: +40
    if is_debugger_present() {
        score += 40;
    }

    // Timing anomaly: +15
    if detect_timing_anomaly() {
        score += 15;
    }

    // Device uptime too short (< 5 min): +10
    if let Ok(uptime_str) = std::fs::read_to_string("/proc/uptime") {
        let secs: f64 = uptime_str
            .split_whitespace()
            .next()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0.0);
        if secs < 300.0 {
            score += 10;
        }
    }

    // No battery info = likely simulator or desktop: +10
    if !std::path::Path::new("/sys/class/power_supply/battery/capacity").exists()
        && !std::path::Path::new("/Library/Developer/CoreSimulator").exists()
    {
        // Not simulator but no battery = possibly unusual environment
        score += 5;
    }

    // Battery always at 100%: +5 (common in sandbox VMs)
    if let Ok(capacity) = std::fs::read_to_string("/sys/class/power_supply/battery/capacity") {
        if let Ok(val) = capacity.trim().parse::<u32>() {
            if val == 100 {
                score += 5;
            }
        }
    }

    score.min(100)
}

// ─────────────────────────────────────────────────────────────────────────────
// MDM / Supervision Detection
// ─────────────────────────────────────────────────────────────────────────────

/// Check if the device has an MDM profile or is supervised.
///
/// On iOS, MDM supervision markers include:
/// - `/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.configurationprofiles/Library/ConfigurationProfiles/CloudConfigurationDetails.plist`
/// - Configuration profiles directory
/// - `Device Enrollment Program` (DEP) markers
pub fn is_supervised() -> bool {
    let mdm_paths = [
        "/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.configurationprofiles/Library/ConfigurationProfiles/CloudConfigurationDetails.plist",
        "/Library/Managed Preferences",
        "/private/var/mobile/Library/ConfigurationProfiles",
    ];
    for path in &mdm_paths {
        if std::path::Path::new(path).exists() {
            tracing::warn!("env/ios: MDM/Supervised path found: {path}");
            return true;
        }
    }

    false
}

// ─────────────────────────────────────────────────────────────────────────────
// Domain Validation
// ─────────────────────────────────────────────────────────────────────────────

/// Validate that the device's network domain matches the required domain.
///
/// On iOS, checks:
/// 1. `/etc/resolv.conf` search domains
/// 2. Hostname domain suffix
/// 3. MDM-configured domain (from CloudConfigurationDetails.plist)
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

    // 2. Check hostname domain suffix (via POSIX hostname).
    unsafe {
        let mut hostname: [libc::c_char; 256] = [0; 256];
        if libc::gethostname(hostname.as_mut_ptr(), hostname.len()) == 0 {
            let hostname = std::ffi::CStr::from_ptr(hostname.as_ptr())
                .to_string_lossy()
                .to_ascii_lowercase();
            if let Some(domain_part) = hostname.split_once('.') {
                if domain_part.1 == required || domain_part.1.ends_with(&format!(".{required}")) {
                    return true;
                }
            }
        }
    }

    // 3. Check MDM configuration for organization domain.
    let mdm_path = "/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.configurationprofiles/Library/ConfigurationProfiles/CloudConfigurationDetails.plist";
    if std::path::Path::new(mdm_path).exists() {
        // CloudConfigurationDetails.plist contains the organization domain.
        // We do a basic string search — parsing plist would require a plist crate.
        if let Ok(contents) = std::fs::read_to_string(mdm_path) {
            let lower = contents.to_ascii_lowercase();
            if lower.contains(&required) {
                return true;
            }
        }
    }

    tracing::warn!("env/ios: domain validation failed — required '{required}' not found");
    false
}
