# Orchestra — Mobile Platform Support: Incremental Design & Implementation Prompts

> **Purpose:** A sequence of self-contained prompts to feed into an AI agent, incrementally designing and implementing Android and iOS support for the Orchestra framework. Each prompt builds on the previous one but is complete enough to execute independently.
>
> **How to use:** Copy each prompt into a fresh agent session (or continue in the same session). The prompts are ordered by dependency — later prompts assume earlier work exists. Each prompt includes its own context-gathering phase so the agent can orient itself before starting work.

---

## Prompt 0 — Architecture Assessment & Mobile Abstraction Design

```
You are a senior Rust systems engineer specializing in cross-platform implant development. Your task is to analyze the Orchestra codebase and design the mobile platform abstraction layer — WITHOUT writing any implementation code yet. This is a design-only phase.

## Step 1: Read and Understand the Current Platform Abstraction

Read the following files to understand how Orchestra currently handles cross-platform code:

1. `agent/Cargo.toml` — all feature flags and `#[cfg]` gates
2. `agent/src/lib.rs` or `agent/src/main.rs` — the entry point and module declarations
3. Every file in `agent/src/` that contains `#[cfg(target_os` or `#[cfg(target_family` — map out the current platform gating strategy
4. `common/src/` — shared protocol and utility code
5. `common/Cargo.toml` — dependencies that are platform-conditional
6. `docs/ARCHITECTURE.md` — the initialization sequence and module dependency graph
7. `docs/FEATURES.md` — feature flag definitions and platform attributions
8. `ROADMAP.md` — planned features that may intersect with mobile

## Step 2: Classify Every Module by Portability

For each module in `agent/src/`, classify it as one of:

| Category | Definition | Example |
|----------|-----------|---------|
| **PLATFORM-AGNOSTIC** | Pure Rust, no OS-specific APIs, compiles everywhere | Crypto, config parsing, C2 protocol framing, command dispatch |
| **PLATFORM-ADAPTER** | Has `#[cfg]` gates with per-OS implementations | Env checks, persistence, process creation |
| **WINDOWS-ONLY** | Fundamentally tied to Windows internals | NT syscalls, AMSI bypass, PE loading, hollowing |
| **LINUX-ONLY** | Fundamentally tied to Linux internals | eBPF, systemd persistence, /proc parsing |
| **NEEDS-MOBILE-ADAPTER** | Platform-agnostic interface exists but no Android/iOS impl yet | Sleep obfuscation, memory management, network discovery |

## Step 3: Design the Mobile Trait Architecture

Propose a trait-based abstraction layer that:

1. **Identifies which operations need trait abstraction.** For each PLATFORM-ADAPTER module, define a trait that captures the platform-independent interface. For example:
   - `trait PersistenceProvider` — install/remove/check persistence
   - `trait EnvChecker` — check debugger/VM/sandbox/domain
   - `trait ProcessManager` — list/create/terminate processes
   - `trait MemoryManager` — allocate/protect/encrypt regions
   - `trait NetworkDiscovery` — ARP/ping/TCP scanning
   - `trait PostExploitation` — screenshot/keylog/credential access
   - `trait SleepObfuscator` — encrypt/decrypt memory during sleep

2. **Shows how existing Windows/Linux code maps to these traits.** For each trait, show which existing functions would become the Windows/Linux impl.

3. **Identifies Android/iOS-specific considerations for each trait.** What APIs are available? What are the constraints? (e.g., Android has no `/proc/self/status` but has `Debug.isDebuggerConnected()` via JNI; iOS has no fork() in sandboxed apps.)

4. **Addresses the compilation model.** How should Cargo features and `#[cfg]` gates be organized so that `cargo build --target aarch64-linux-android` pulls in the right code? Propose a feature flag naming scheme (e.g., `mobile-android`, `mobile-ios` vs. reusing existing features).

5. **Addresses the dependency differential.** List every dependency in `agent/Cargo.toml` and `common/Cargo.toml` that will fail to compile for Android/iOS targets. Propose replacements or feature-gated alternatives.

## Output

Produce a design document in Markdown format:

```markdown
# Mobile Platform Abstraction Design

## Current Platform Gating Map
(For each module: file, current cfg gates, portability category)

## Trait Definitions
(For each trait: name, methods with signatures, which modules implement it on each platform)

## Dependency Compatibility Matrix
(For each dependency: works on Android? works on iOS? replacement needed?)

## Proposed Feature Flag Schema
(New feature flags and how they interact with existing ones)

## Module Porting Priority
(Ordered list of which modules to port first based on dependency chain)

## Risk Areas
(Operations that are fundamentally different or impossible on mobile)
```

Do NOT write any Rust implementation code. This is a design document only.
```

---

## Prompt 1 — Android Toolchain Setup & Agent Core Compilation

```
You are a senior Rust engineer. Your task is to set up the Android cross-compilation toolchain for Orchestra and get the platform-agnostic agent core compiling for Android — WITHOUT breaking existing Windows/Linux/macOS builds.

## Context

The Orchestra project is a Rust workspace with an `agent` crate that needs to compile for `aarch64-linux-android` and `x86_64-linux-android`. The agent currently supports Linux, Windows, and macOS. A mobile platform abstraction design has been completed (see the mobile abstraction design doc if it exists, otherwise read the codebase to understand the current `#[cfg]` gating strategy).

## Step 1: Read the Current Build Configuration

Read these files:
1. `Cargo.toml` (workspace root)
2. `agent/Cargo.toml`
3. `agent/build.rs`
4. `common/Cargo.toml`
5. `common/build.rs`
6. Every `*/Cargo.toml` in the workspace — identify which crates the agent depends on

## Step 2: Identify Compilation Blockers

For each crate the agent depends on, determine:
- Does it have any C/C++ native dependencies that need Android NDK compilation?
- Does it use any platform-specific APIs that don't exist on Android?
- Does its `build.rs` hardcode host-platform assumptions?

Run `cargo check --target aarch64-linux-android -p agent --no-default-features` (or the minimal feature set) to see what actually fails. Capture every error.

## Step 3: Implement the Changes

Make the following changes:

### 3.1 Add Android Targets to Cargo
- Add `aarch64-linux-android` and `x86_64-linux-android` to the accepted target list
- Ensure `rustup target add aarch64-linux-android x86_64-linux-android` is documented

### 3.2 Feature-Gate Windows/Linux-Only Dependencies
In `agent/Cargo.toml` and `common/Cargo.toml`, wrap any dependency that cannot compile for Android in appropriate `#[cfg]` or feature gates. For example:
- `nt_syscall` — Windows only
- Any Windows-sys crates — Windows only
- Any libc features that don't exist on Android — gate appropriately
- eBPF-related dependencies — Linux (non-Android) only

### 3.3 Add `#[cfg(target_os = "android")]` Gates
For every module in `agent/src/` that uses Windows or Linux-specific APIs:
- Add `#[cfg(not(target_os = "android"))]` to exclude it from Android builds, OR
- Add `#[cfg(target_os = "android")]` stub/adapter modules where the functionality needs a mobile equivalent

### 3.4 Create Android Module Stubs
Create `agent/src/android/` directory with stub modules for:
- `mod.rs` — module declarations
- `env_checks.rs` — placeholder for Android env checks (debugger, root, emulator, SafetyNet)
- `persistence.rs` — placeholder for Android persistence
- `post_exploitation.rs` — placeholder for Android post-ex

Each stub should have the correct function signatures (matching the trait interfaces from the design phase) but return `Err("not yet implemented on Android")` or equivalent.

### 3.5 Update build.rs
Ensure `agent/build.rs` handles the Android target correctly — no Windows-specific env var requirements, no MSVC-specific logic when targeting Android.

## Step 4: Verify

Run `cargo check --target aarch64-linux-android -p agent` with progressively more feature flags enabled. Document which feature combinations compile and which don't.

## Output

Produce:
1. A list of all files modified and why
2. A feature-flag compatibility matrix showing which features compile on Android
3. Any dependencies that need replacement or removal for Android
4. A list of remaining blockers (native C deps, missing Android APIs, etc.)
```

---

## Prompt 2 — Android JNI Bridge & Shared Library Packaging

```
You are a senior Rust + Android engineer. Your task is to create the JNI bridge layer and Android packaging infrastructure for the Orchestra agent — so the compiled `.so` can be loaded by an Android app.

## Context

The Orchestra agent compiles to `aarch64-linux-android` as a shared library (`.so`). It needs a JNI bridge so a thin Android app (or any Android process) can load and initialize it. This prompt covers the Rust-side JNI bridge and the minimal Android packaging — not the full APK generation (that's a later prompt).

## Step 1: Read Current Agent Architecture

Read:
1. `agent/src/lib.rs` or `agent/src/main.rs` — how the agent currently starts
2. `agent/src/` — the initialization sequence (config loading → env checks → C2 connection → command loop)
3. `agent/Cargo.toml` — current dependencies
4. `common/src/` — the config structures

## Step 2: Design the JNI Interface

Define the Rust-side JNI functions. The interface should be minimal:

```rust
// These are the JNI entry points the Android side will call

#[no_mangle]
pub extern "system" fn Java_com_orchestra_Agent_nativeInit(
    env: *mut JNIEnv,
    class: JClass,
    config_bytes: jbyteArray,
) -> jint;

#[no_mangle]
pub extern "system" fn Java_com_orchestra_Agent_nativeStart(
    env: *mut JNIEnv,
    class: JClass,
) -> jint;

#[no_mangle]
pub extern "system" fn Java_com_orchestra_AgentnativeStop(
    env: *mut JNIEnv,
    class: JClass,
);
```

Design considerations:
- `nativeInit` receives the encrypted config blob as a byte array, decrypts it, and stores it in a global state
- `nativeStart` spawns the agent's command loop on a background thread
- `nativeStop` triggers graceful shutdown
- All logging from Rust should go through Android logcat via `android_logger` crate
- Errors should be communicated back to Java via return codes or callback, not panics (panics across JNI are UB)

## Step 3: Implement the JNI Bridge

Create `agent/src/android/jni_bridge.rs`:

1. Add `jni` crate to `agent/Cargo.toml` with `#[cfg(target_os = "android")]` gate
2. Add `android_logger` and `log` crates similarly
3. Implement the JNI functions
4. Add a `#[cfg(target_os = "android")]` entry point in `lib.rs` that exposes the JNI functions
5. Ensure the agent's panic handler is set to `std::panic::catch_unwind` at the JNI boundary
6. Ensure the agent's initialization and command loop can run on a background `std::thread` spawned from JNI

## Step 4: Create the Minimal Android Wrapper

Create `mobile/android/` directory structure:

```
mobile/android/
├── build.gradle.kts
├── settings.gradle.kts
├── gradle.properties
├── app/
│   ├── build.gradle.kts
│   └── src/main/
│       ├── AndroidManifest.xml
│       ├── java/com/orchestra/
│       │   ├── Agent.java       (JNI interface)
│       │   └── AgentService.java (background service that loads .so)
│       └── jniLibs/
│           └── arm64-v8a/
│               └── liborchestra.so (compiled Rust output)
```

The Java side should:
- Define the `Agent` class with `native` methods matching the JNI bridge
- Define `AgentService` as a foreground service that calls `nativeInit` then `nativeStart`
- Handle permissions (INTERNET, FOREGROUND_SERVICE, etc.)
- Load the `.so` from the app's native library directory

## Step 5: Create the Build Script

Create `mobile/android/build_agent.sh` that:
1. Compiles the Rust agent for `aarch64-linux-android` using `cargo ndk`
2. Copies the `.so` to the Android project's `jniLibs/arm64-v8a/`
3. Runs `./gradlew assembleDebug` to produce the APK
4. Outputs the APK path

## Output

Produce:
1. All created/modified files with full contents
2. Step-by-step build instructions
3. A test procedure: install APK on emulator, verify agent starts and connects to C2
4. Known limitations of this first-pass implementation
```

---

## Prompt 3 — Android Environment Checks & Anti-Analysis

```
You are a senior Android security engineer and Rust developer. Your task is to implement the Android-specific environment validation and anti-analysis checks for the Orchestra agent.

## Context

Orchestra has an `env-validation` feature that performs pre-execution checks (debugger detection, VM/sandbox detection, domain validation) before the agent commits to running. On Windows/Linux/macOS these are already implemented. You need to implement the Android equivalents.

## Step 1: Read Existing Env Check Architecture

Read:
1. All files in `agent/src/` related to env checks — search for `env_validation`, `env_check`, `debugger`, `hypervisor`, `sandbox`, `domain`
2. The config structures for env validation (thresholds, whitelists, behavior on failure)
3. The trait/interface design from the mobile abstraction document
4. `docs/EVASION.md` — evasion subsystem contracts
5. `docs/ARCHITECTURE.md` — how env checks fit into the initialization sequence

## Step 2: Design Android Env Checks

For each check category, design the Android-specific implementation:

### 2.1 Debugger Detection
- **`TracerPid` from `/proc/self/status`** — works on Android (it's Linux). Implement it.
- **`android.os.Debug.isDebuggerConnected()`** — requires JNI call. Design the JNI bridge for this.
- **`ptrace(PTRACE_TRACEME)` self-attach** — works on Android. Implement it.
- **Anti-frida checks** — scan `/proc/self/maps` for `frida-agent`, `frida-gadget`, `linjector`. Check for `frida`-related TCP ports. Check for `gmain` Frida thread.
- **Timing-based detection** — measure execution time between checkpoints; debuggers introduce delays.

### 2.2 Root Detection
- Check for `su` binary in PATH and common locations (`/system/bin/su`, `/system/xbin/su`, `/sbin/su`, `/vendor/bin/su`)
- Check for Magisk: `/sbin/.magisk`, `magisk` in `/proc/self/maps`
- Check for Superuser.apk
- Check for custom recovery (`/system/recovery-from-boot.p`)
- Check for writable `/system` partition
- Check SafetyNet/Play Integrity attestation (requires JNI call to Google Play Services)
- Check for root management apps (Magisk, SuperSU, KingRoot)

### 2.3 Emulator Detection
- Check `android.os.Build` properties via JNI: `Build.FINGERPRINT` contains "generic", `Build.MODEL` contains "sdk", `Build.MANUFACTURER` contains "Genymotion", etc.
- Check for emulator-specific files: `/dev/qemu_pipe`, `/dev/goldfish_pipe`, `/system/lib/libc_malloc_debug_qemu.so`
- Check CPU information: `/proc/cpuinfo` for "Goldfish", "ranchu"
- Check telephony: `android.telephony.TelephonyManager.getDeviceId()` returning all zeros
- Check sensors: emulator has fewer hardware sensors
- Check battery: `android.intent.action.BATTERY_CHANGED` properties

### 2.4 VM/Hypervisor Detection
- CPUID-based VM detection (where available on ARM — check for hypervisor extensions)
- Check `/proc/cpuinfo` for virtualization indicators
- Check for cloud-specific properties (AWS device farms, Firebase Test Lab)
- Cloud instance detection via IMDS (AWS/GCP/Azure metadata endpoints)

### 2.5 Sandbox Detection
- Check for app sandbox indicators: restricted `/proc` access, missing `/proc/self/maps`
- Check for Cuckoo/Droidbox artifacts
- Check for analysis tools: Xposed framework (`/proc/self/maps` for `XposedBridge.jar`)
- Check for hooked methods (comparable to inline hook detection on Windows)
- Weighted scoring system matching the existing sandbox detection architecture

### 2.6 Domain/Network Validation
- Check WiFi/VPN state via JNI
- Check DNS configuration from `/etc/resolv.conf` (if accessible) or via `android.net.wifi.WifiManager`
- Check for corporate MDM enrollment
- Check for specific network characteristics (private IP ranges, etc.)

## Step 3: Implement

For each check, implement it in `agent/src/android/env_checks.rs`:

1. Use direct system access (files, `/proc`) where possible — this avoids JNI overhead
2. Use JNI calls for Android framework APIs (`Build`, `Debug`, `TelephonyManager`) — create a helper module `agent/src/android/jni_helpers.rs` that caches JNI method IDs and provides safe wrappers
3. Implement the weighted scoring system that matches the existing `env-validation` architecture
4. Wire the checks into the agent's initialization sequence via the trait/adapter pattern
5. Ensure all checks gracefully degrade — if a check can't run (permission denied, file not found), it should not crash the agent; it should return a neutral score

## Step 4: Test Design

Write tests (in `agent/tests/` or inline) that verify:
- Each check returns correct results on a physical device
- Each check returns correct results on an emulator
- The scoring system produces expected pass/fail decisions
- JNI helper error handling works correctly
- No panics on permission-denied scenarios

## Output

1. All created/modified files
2. A matrix of env checks showing: check name | method | requires JNI | requires root | false positive risk
3. Recommended scoring weights and thresholds
4. Test results from emulator (if possible to run)
```

---

## Prompt 4 — Android Persistence Mechanisms

```
You are a senior Android security engineer. Your task is to implement persistence mechanisms for the Orchestra agent on Android.

## Context

Orchestra has platform-specific persistence modules (systemd on Linux, schtasks on Windows, launchd on macOS). You need to implement Android equivalents.

## Step 1: Read Existing Persistence Architecture

Read:
1. All files related to persistence in `agent/src/` — search for `persistence`, `install`, `survive reboot`
2. The persistence trait/interface from the mobile abstraction design
3. `docs/ARCHITECTURE.md` — how persistence fits into the agent lifecycle
4. Current Linux persistence implementation for reference (systemd user unit)

## Step 2: Design Android Persistence Strategies

Design implementations for these persistence levels:

### Level 1: Non-Root Persistence (App-Level)
- **Foreground Service** — the primary persistence mechanism. The agent runs as a foreground service with a notification (can be minimized/hidden). Survives app being backgrounded.
- **WorkManager / JobScheduler** — periodic background execution for check-in even if the service is killed. Register a PeriodicWorkRequest that re-initializes the agent.
- **BroadcastReceiver** — register for `BOOT_COMPLETED`, `QUICKBOOT_POWERON`, `USER_PRESENT`, `MY_PACKAGE_REPLACED`, `CONNECTIVITY_CHANGE` to restart the service.
- **AlarmManager** — set exact alarms (if permission granted) or inexact alarms as fallback to periodically wake the agent.
- **AccessibilityService** — if the user grants accessibility access, the service runs persistently and can perform UI automation. This is powerful but requires social engineering to get the user to enable it.
- **Device Admin / Device Owner** — if granted, provides very strong persistence (cannot be uninstalled easily). Requires the user to activate it.

### Level 2: Root Persistence (System-Level)
- **Init.d script** — drop a script in `/system/etc/init.d/` or `/system/etc/init/` (Android init language)
- **Magisk Module** — create a Magisk module that includes the agent and starts it at boot
- **System app** — install as a system app in `/system/app/` or `/system/priv-app/`
- **Modified boot image** — embed the agent in the boot image (extreme persistence)
- **Daemonsu approach** — if su is available, start agent as root daemon via init script

### Level 3: Advanced Persistence
- **ContentProvider** — auto-initializing component that starts before the activity
- **Multi-process** — run the agent in a separate `:agent` process for isolation
- **Package manager hooks** — if Xposed/LSPosed is available, hook package manager to ensure agent stays installed

## Step 3: Implement

### 3.1 Rust-Side Implementation (`agent/src/android/persistence.rs`)
For each persistence mechanism:
1. `install()` — set up the persistence
2. `remove()` — clean up the persistence
3. `check()` — verify persistence is active
4. `repair()` — re-install if persistence is broken

Use direct filesystem operations for root-level persistence. Use JNI calls for app-level persistence (interacting with Android framework APIs).

### 3.2 Android-Side Implementation (`mobile/android/app/src/main/java/com/orchestra/`)
- `AgentService.java` — the foreground service implementation
- `BootReceiver.java` — BroadcastReceiver for BOOT_COMPLETED
- `AgentWorker.java` — WorkManager worker for periodic check-ins
- `AgentAccessibilityService.java` — accessibility service (if applicable)
- Update `AndroidManifest.xml` with all required permissions, services, receivers

### 3.3 Configuration
Add Android-specific persistence config to the agent config schema:
- `persistence_method` — which method(s) to use
- `persistence_level` — root vs non-root
- `service_notification` — how to handle the foreground service notification
- `checkin_interval` — WorkManager interval

## Step 4: Test & Document

1. Test on non-rooted device: verify foreground service survives app kill, reboot, and force-stop
2. Test on rooted device: verify init.d script or Magisk module survives reboot
3. Document which methods work on which Android versions (Android 10+ restrictions, background execution limits)
4. Document which methods require user interaction vs. fully automated

## Output

1. All created/modified files
2. A persistence method comparison table: method | requires root | survives reboot | survives force-stop | Android version compatibility | stealth level
3. Known limitations and Android version-specific restrictions
4. Build and deployment instructions for each persistence method
```

---

## Prompt 5 — Android Post-Exploitation Modules

```
You are a senior Android security researcher and Rust developer. Your task is to implement Android-specific post-exploitation capabilities for the Orchestra agent.

## Context

Orchestra has extensive Windows and Linux post-exploitation modules. You need to implement the Android equivalents: credential access, data theft, surveillance, and lateral movement on Android devices.

## Step 1: Read Existing Post-Exploitation Architecture

Read:
1. All post-exploitation modules in `agent/src/` — search for `post_exploitation`, `screenshot`, `keylog`, `browser_data`, `credential`
2. `docs/POST_EXPLOITATION.md` — post-exploitation module contracts
3. The trait/interface design from the mobile abstraction document
4. `docs/ARCHITECTURE.md` — how post-ex modules are dispatched

## Step 2: Design Android Post-Exploitation Modules

### 2.1 Credential Access
- **Keychain/Keystore extraction** — access Android Keystore via JNI; dump keys that are extractable (hardware-backed keys are not extractable, but software-backed keys are)
- **Chrome/browser credential extraction** — read Chrome's `Login Data` SQLite database from `/data/data/com.android.chrome/` (requires root or accessibility service)
- **Saved WiFi passwords** — read from `/data/misc/wifi/wpa_supplicant.conf` (root) or via `WifiManager` API
- **Account manager** — dump accounts registered with `AccountManager` via JNI
- **App-specific data** — enumerate and read `/data/data/<package>/` for interesting files (root required for other apps)

### 2.2 Surveillance
- **Screen capture** — use MediaProjection API via JNI to capture screen (requires user permission once, then persists until reboot). Alternative: `/dev/graphics/fb0` framebuffer read (root only)
- **Camera access** — use Camera2 API via JNI for photo/video capture (requires camera permission)
- **Microphone access** — use MediaRecorder/AudioRecord via JNI for audio capture (requires microphone permission)
- **Keylogging** — use AccessibilityService to capture all input events (requires accessibility permission)
- **SMS/Call log** — read SMS database and call log via ContentProvider queries (requires permissions)
- **Contact extraction** — query ContactsContract via JNI
- **Location tracking** — use LocationManager/FusedLocationProvider via JNI (requires location permission)
- **Clipboard monitoring** — register ClipboardManager.OnPrimaryClipChangedListener via JNI

### 2.3 Data Exfiltration
- **File browser** — enumerate and read files from accessible storage locations
- **Database dumper** — enumerate and dump SQLite databases from accessible app data directories
- **App data packer** — tar+encrypt entire app data directory for exfiltration
- **Media exfiltration** — access photos, videos, documents from MediaStore

### 2.4 Network Operations
- **Network discovery** — ARP table parsing from `/proc/net/arp`, ping sweeps, port scanning (reuse existing cross-platform code)
- **WiFi scanning** — `WifiManager.startScan()` + `getScanResults()` via JNI for nearby AP discovery
- **Bluetooth scanning** — Bluetooth adapter discovery via JNI
- **Pivot/proxy** — set up SOCKS proxy or TCP relay through the compromised device

### 2.5 App Manipulation
- **Package management** — list installed apps, install/uninstall APKs (via `PackageManager` JNI calls)
- **Intent injection** — craft and send intents to other apps (requires specific permissions)
- **Content provider queries** — enumerate and query accessible content providers
- **Notification listener** — intercept notifications via NotificationListenerService (requires user permission)
- **Device admin escalation** — attempt to activate device administrator

### 2.6 Lateral Movement
- **ADB scanning** — scan local network for devices with ADB over TCP (port 5555)
- **ADB exploitation** — connect to open ADB ports and push/install agent
- ** Nearby device exploitation** — Bluetooth, WiFi Direct attacks
- **SSDP/mDNS discovery** — discover services on local network
- **SSH from Android** — use the existing SSH client code to pivot through the device

## Step 3: Implement

For each module category, implement:

### 3.1 Rust Core (`agent/src/android/post_exploitation/`)
- `credentials.rs` — credential access functions
- `surveillance.rs` — screenshot, camera, mic, keylog
- `exfiltration.rs` — file/directory enumeration and packaging
- `network.rs` — Android-specific network discovery
- `app_manipulation.rs` — package management, intent injection
- `lateral.rs` — ADB scanning, nearby device exploitation

### 3.2 JNI Helpers (`agent/src/android/jni_helpers.rs`)
Add JNI wrapper functions for:
- MediaProjection (screen capture)
- Camera2 (photo/video)
- AudioRecord (microphone)
- AccessibilityService (keylogging)
- ContentResolver (contacts, SMS, call log)
- PackageManager (installed apps)
- LocationManager (GPS)
- AccountManager (accounts)

### 3.3 Command Handlers
Register new Android-specific commands in the command dispatch table:
- `android_screenshot` — capture screen
- `android_photo` — take photo
- `android_record_audio` — record audio
- `android_keylog_start/stop` — start/stop keylogging
- `android_dump_sms` — dump SMS messages
- `android_dump_contacts` — dump contacts
- `android_dump_calls` — dump call log
- `android_list_apps` — list installed applications
- `android_dump_app` — extract app data
- `android_wifi_scan` — scan nearby WiFi
- `android_adb_scan` — scan for ADB devices
- `android_location` — get current location
- `android_clipboard` — get clipboard contents

## Output

1. All created/modified files
2. A capability matrix: module | requires root | requires specific permission | requires user interaction | stealth level
3. Permission requirements per Android API level
4. Test procedures for each module
```

---

## Prompt 6 — iOS Toolchain Setup & Agent Core Compilation

```
You are a senior Rust + iOS engineer. Your task is to set up the iOS cross-compilation toolchain for Orchestra and get the agent core compiling for iOS — producing a static library (.a) that can be linked into an Xcode project.

## Step 1: Read Current Build Configuration

Read:
1. `Cargo.toml` (workspace root)
2. `agent/Cargo.toml`
3. `agent/build.rs`
4. `common/Cargo.toml`
5. Every `*/Cargo.toml` — identify which crates the agent depends on

## Step 2: Identify iOS Compilation Blockers

For each dependency, determine:
- Does it compile for `aarch64-apple-ios`?
- Does it use APIs that don't exist on iOS (e.g., macOS-specific AppKit, iOS-restricted POSIX calls)?
- Does its `build.rs` assume macOS host tools?

Run `cargo check --target aarch64-apple-ios -p agent --no-default-features` to identify actual errors.

## Step 3: Implement

### 3.1 Feature-Gate Platform-Specific Code
In `agent/src/`:
- Add `#[cfg(target_os = "ios")]` gates for iOS-specific modules
- Add `#[cfg(not(target_os = "ios"))]` to exclude modules that can't work on iOS (e.g., NT syscalls, Windows injection, Linux eBPF)
- Create `agent/src/ios/` directory with stub modules

### 3.2 Handle iOS-Specific Constraints
- iOS does not allow `fork()` in sandboxed apps — any process-creation code needs gating
- iOS restricts `/proc` access — env checks need alternatives
- iOS restricts `mmap` with certain flags — verify memory management code
- iOS apps can't daemonize — the agent must run within the app's process lifecycle

### 3.3 Static Library Output
Configure `agent/Cargo.toml` to produce:
- `crate-type = ["staticlib", "lib"]` when targeting iOS (the `.a` archive for Xcode linking)
- `crate-type = ["cdylib", "lib"]` when targeting Android (the `.so` for JNI)

Use Cargo metadata or `cfg` to switch crate types based on target.

### 3.4 iOS Module Stubs
Create `agent/src/ios/` with:
- `mod.rs` — module declarations
- `env_checks.rs` — placeholder for iOS env checks (jailbreak detection, debugger, simulator)
- `persistence.rs` — placeholder for iOS persistence
- `post_exploitation.rs` — placeholder for iOS post-ex

## Step 4: Create the Xcode Bridge

Create `mobile/ios/` directory:
```
mobile/ios/
├── OrchestraBridge/
│   ├── OrchestraBridge.h       (public header exposing C ABI)
│   ├── OrchestraBridge.c       (C bridge calling Rust functions)
│   └── Info.plist
├── OrchestraAgent/
│   ├── AppDelegate.swift       (minimal app delegate)
│   ├── AgentBridge.swift       (Swift wrapper calling C bridge)
│   ├── SceneDelegate.swift
│   ├── Info.plist
│   └── Entitlements.plist
├── OrchestraAgent.xcodeproj/
│   └── project.pbxproj
└── build_agent.sh
```

The bridge should:
- Expose `#[no_mangle] extern "C"` functions from Rust: `orchestra_init(config_ptr, config_len)`, `orchestra_start()`, `orchestra_stop()`
- The Swift side wraps these in a class that manages the agent lifecycle
- Background modes are declared in Info.plist for background execution

## Output

1. All created/modified files
2. Build instructions: `cargo lipo` + Xcode build
3. iOS feature-flag compatibility matrix
4. Known iOS-specific limitations (sandboxing, background restrictions, etc.)
```

---

## Prompt 7 — iOS Environment Checks & Anti-Analysis

```
You are a senior iOS security researcher and Rust developer. Your task is to implement iOS-specific environment validation and anti-analysis checks for the Orchestra agent.

## Step 1: Read Existing Env Check Architecture

Read all env-check related files in `agent/src/` as identified in Prompt 3. Also read the iOS-specific constraints from Prompt 6.

## Step 2: Design iOS Env Checks

### 2.1 Jailbreak Detection (Reverse — Am I Jailbroken?)
On iOS, unlike Android's root detection, the agent needs to determine the device state:
- **File existence checks** — `/Applications/Cydia.app`, `/Library/MobileSubstrate/MobileSubstrate.dylib`, `/bin/bash`, `/usr/sbin/sshd`, `/etc/apt`
- **Symbolic link checks** — `/Applications` is a symlink on jailbroken devices
- **Sandbox test** — try to open a file outside the sandbox; if it succeeds, device is jailbroken
- **Fork test** — `fork()` succeeds only on jailbroken/non-sandboxed processes
- **dyld check** — check if DYLD_INSERT_LIBRARIES is set (jailbreak injection)
- **URL scheme check** — `cydia://` URL scheme is registered on jailbroken devices

### 2.2 Debugger Detection
- `sysctl` with `KERN_PROC` — check `P_TRACED` flag (works on iOS)
- `ptrace(PTRACE_DENY_ATTACH)` — prevent further debugging (works on iOS)
- Timing checks — measure execution time for known operations
- `isatty()` on stdin — detect if attached to a terminal

### 2.3 Simulator Detection
- Check `TARGET_OS_SIMULATOR` compile-time flag
- Runtime: check for simulator-specific files (`/Library/Developer/CoreSimulator`)
- Check hardware: `HW_MACHINE` sysctl returns different values on simulators
- Check for absence of certain hardware features (accelerometer, etc.)

### 2.4 Sandbox/Restriction Detection
- Check for Mobile Device Management (MDM) restrictions
- Check for Screen Time / parental controls
- Check for supervised device status
- Check for app-specific restrictions

### 2.5 Network/Domain Validation
- Parse `/etc/resolv.conf` if accessible
- Check WiFi SSID via `NEHotspotNetwork` (requires NetworkExtension entitlement)
- Check VPN status via `NEVPNManager`
- Check for captive portal detection behavior

## Step 3: Implement

Implement all checks in `agent/src/ios/env_checks.rs`:

1. Use POSIX APIs directly where possible (`sysctl`, `stat`, `open`, `ptrace`)
2. Use Objective-C runtime via the `objc` crate for UIKit/Foundation queries
3. Implement the weighted scoring system matching the existing architecture
4. Wire into the initialization sequence
5. Handle all error cases gracefully — iOS restricts many APIs, and errors should not crash the agent

## Output

1. All created/modified files
2. Check matrix: check name | method | requires jailbreak | works in sandbox | false positive risk
3. Recommended scoring weights
```

---

## Prompt 8 — iOS Persistence & Post-Exploitation

```
You are a senior iOS security researcher and Rust developer. Your task is to implement iOS persistence mechanisms and post-exploitation capabilities.

## Step 1: Read Existing Architecture

Read the persistence and post-exploitation modules from Prompts 4 and 5 for reference patterns.

## Step 2: iOS Persistence Design

### Jailbroken Persistence (root access available)
- **LaunchDaemon** — PLIST in `/Library/LaunchDaemons/` for boot persistence (root-level daemon)
- **LaunchAgent** — PLIST in `/Library/LaunchAgents/` for user-level persistence
- **Cydia Substrate / Substitute tweak** — inject into system process to load agent
- **`.bashrc` / `.profile` modification** — if shell access is available

### Non-Jailbroken Persistence (sandboxed app)
- **Background fetch** — `UIBackgroundModes` → `fetch` in Info.plist; implement `application(_:performFetchWithCompletionHandler:)`
- **Background processing** — BGProcessingTask for longer background execution
- **Silent push notifications** — wake the app via APNs silent push
- **Significant location changes** — CLLocationManager significant-change location service keeps app alive
- **VoIP push** — PushKit VoIP pushes wake the app (requires VoIP entitlement; Apple may reject non-VoIP apps)
- **Audio background mode** — play silent audio to keep app alive (aggressive but effective)
- **Health Kit background delivery** — register for health data updates (requires HealthKit entitlement)

### Semi-Persistence
- **UIStateRestoration** — restore app state quickly so agent can resume
- **Local notifications** — schedule periodic local notifications that trigger app launch

## Step 3: iOS Post-Exploitation Design

### 3.1 Credential Access
- **Keychain extraction** — use `Security.framework` via `objc` crate to query keychain items (the app can access its own keychain items; jailbroken can access all)
- **iCloud Keychain** — if synced, access via Security.framework
- **WiFi passwords** — via `NEHotspotConfigurationManager` or keychain (requires specific entitlements)
- **Browser data** — Safari cookies/history/bookmarks from keychain and filesystem (jailbroken)

### 3.2 Surveillance
- **Screen capture** — use `UIGraphicsImageRenderer` to capture view hierarchy (own app only); or `ReplayKit` for system-wide (requires user permission); jailbroken: `IOSurface` + `IOScreenCapture`
- **Camera** — `AVCaptureSession` via `objc` crate for photo/video
- **Microphone** — `AVAudioEngine` for audio capture
- **Keylogging** — only via Accessibility features or jailbroken IOKit keyboard hooking
- **Location** — `CLLocationManager` via `objc` crate
- **Clipboard** — `UIPasteboard.general` via `objc` crate

### 3.3 Data Exfiltration
- **Contacts** — `CNContactStore` via `objc` crate
- **Photos** — `PHAsset` via `objc` crate
- **Messages/iMessage** — SMS database access (jailbroken only)
- **App data** — enumerate app containers (jailbroken or via DocumentPicker)
- **Notes** — Notes.sqlite database (jailbroken)

### 3.4 Network Operations
- **Network discovery** — reuse cross-platform code; Bonjour service discovery
- **WiFi scanning** — `NEHotspotHelper` (requires NetworkExtension entitlement)
- **Bluetooth** — `CoreBluetooth` scanning
- **Pivot** — `NetworkExtension` VPN tunnel or SOCKS proxy

### 3.5 Lateral Movement
- **AirDrop exploitation** — discover nearby Apple devices
- **USB exploitation** — check for connected devices via `MobileDevice` framework
- **iTunes WiFi Sync** — exploit local sync protocol
- **Handoff/Continuity** — discover nearby Apple devices via BLE

## Step 4: Implement

1. `agent/src/ios/persistence.rs` — all persistence mechanisms
2. `agent/src/ios/post_exploitation.rs` — all post-ex modules
3. `agent/src/ios/objc_helpers.rs` — Objective-C runtime wrappers for iOS APIs
4. Register iOS-specific commands in the dispatch table

## Output

1. All created/modified files
2. Persistence method comparison: method | requires jailbreak | survives reboot | stealth level | Apple review risk
3. Capability matrix: module | requires jailbreak | requires entitlement | requires user permission
4. Known iOS version-specific restrictions
```

---

## Prompt 9 — Builder Pipeline Extension for Mobile Targets

```
You are a senior Rust engineer. Your task is to extend the Orchestra builder pipeline to support Android and iOS artifact generation — so the C2 server can build, sign, and serve mobile payloads.

## Step 1: Read Current Builder Architecture

Read:
1. `builder/src/` — the entire builder crate
2. `orchestra-server/src/` — the server's build queue and API
3. `docs/ARCHITECTURE.md` — builder pipeline design
4. `docs/CONFIGURATION.md` — builder configuration schema
5. `payload-packager/src/` — payload packaging
6. `shellcode_packager/src/` — shellcode packaging
7. The Android and iOS build scripts created in Prompts 2 and 6

## Step 2: Design Mobile Build Pipeline

### 2.1 New Payload Types
Add to the builder's `PayloadType` enum:
- `AndroidApk` — generates a signed APK
- `AndroidSo` — generates just the `.so` library
- `IosIpa` — generates an IPA (requires Apple developer cert)
- `IosA` — generates just the static `.a` library

### 2.2 Build Configuration Extensions
Extend `PayloadConfig` to include:
```rust
pub struct MobileConfig {
    pub platform: MobilePlatform,  // Android, iOS
    pub arch: Vec<MobileArch>,     // Arm64, X86_64
    pub package_type: MobilePackageType,  // Apk, So, Ipa, A
    pub android_config: Option<AndroidBuildConfig>,
    pub ios_config: Option<IosBuildConfig>,
}

pub struct AndroidBuildConfig {
    pub package_name: String,
    pub app_name: String,
    pub min_sdk: u32,
    pub target_sdk: u32,
    pub keystore_path: Option<PathBuf>,  // for signing
    pub keystore_password: Option<String>,
    pub permissions: Vec<String>,
    pub persistence_method: AndroidPersistenceMethod,
}

pub struct IosBuildConfig {
    pub bundle_id: String,
    pub team_id: String,
    pub provisioning_profile_path: Option<PathBuf>,
    pub entitlements_path: Option<PathBuf>,
    pub persistence_method: IosPersistenceMethod,
}
```

### 2.3 Build Worker Extensions
Extend the builder's build worker to:
1. Detect mobile target from `PayloadConfig`
2. Invoke `cargo ndk` for Android builds (with correct `--target` and feature flags)
3. Invoke `cargo lipo` + `xcodebuild` for iOS builds
4. Package the output (APK via Gradle, IPA via `xcodebuild archive + -exportArchive`)
5. Sign the artifact (Android: `apksigner`; iOS: `codesign`)
6. Store the artifact for download via the C2 API

### 2.4 API Extensions
Add new REST endpoints:
- `POST /api/build` — extend the existing endpoint to accept mobile config
- Build status polling — works as-is
- Artifact download — works as-is (just serving different file types)

## Step 3: Implement

1. Extend `builder/src/config.rs` with mobile config types
2. Extend `builder/src/build_worker.rs` with mobile build steps
3. Extend `orchestra-server/src/api.rs` to handle mobile build requests
4. Create `builder/src/mobile.rs` for mobile-specific build logic
5. Update the server's web dashboard to show mobile build options

## Output

1. All created/modified files
2. API documentation for the new mobile build endpoints
3. Build pipeline flow diagrams for Android and iOS
4. Required server-side prerequisites (Android NDK, Xcode, signing keys)
```

---

## Prompt 10 — C2 Transport Adaptation for Mobile

```
You are a senior network security engineer. Your task is to ensure the Orchestra C2 transport layer works correctly on mobile platforms, where network conditions are fundamentally different from desktop/server environments.

## Step 1: Read Current C2 Transport Implementation

Read:
1. `agent/src/c2_http.rs` — HTTP transport with malleable profiles
2. `agent/src/c2_doh.rs` — DNS-over-HTTPS transport
3. `agent/src/c2_quic.rs` — QUIC transport
4. `agent/src/c2_ssh.rs` — SSH transport
5. `agent/src/c2_smb.rs` — SMB transport
6. `agent/src/c2_graph.rs` — Microsoft Graph transport
7. `common/src/` — wire protocol, crypto, framing
8. `agent/src/adaptive_timing.rs` — adaptive timing/jitter

## Step 2: Identify Mobile-Specific Transport Issues

### 2.1 Network Characteristics
Mobile devices have:
- **Frequent IP changes** — WiFi ↔ cellular handoffs, changing IP addresses
- **NAT behind carrier-grade NAT (CGNAT)** — inbound connections impossible
- **Intermittent connectivity** — subway, elevator, airplane mode
- **Metered connections** — data caps, throttling
- **VPN/DNS interception** — corporate MDM VPNs intercepting traffic
- **Certificate pinning enforcement** — some apps pin certs, but the agent itself needs to handle pinning
- **Background network restrictions** — Android/iOS limit background network access

### 2.2 Transport Feasibility on Mobile

| Transport | Android | iOS | Notes |
|-----------|---------|-----|-------|
| HTTP(S) | ✅ | ✅ | Primary transport. Must handle intermittent connectivity. |
| DoH | ✅ | ✅ | Good for mobile. Works through most firewalls. |
| QUIC/HTTP3 | ✅ | ✅ | Excellent for mobile — handles IP changes, fast reconnection. |
| SSH | ⚠️ | ⚠️ | Works but unusual on mobile, may trigger detection. |
| SMB | ❌ | ❌ | Not applicable on mobile (no SMB server). |
| Graph | ✅ | ✅ | Good for mobile — disguised as legitimate API traffic. |

### 2.3 Required Adaptations

For each transport that works on mobile:

1. **HTTP(S):**
   - Add aggressive retry with exponential backoff for connectivity loss
   - Handle DNS changes gracefully (re-resolve on connection failure)
   - Add support for HTTP/2 and HTTP/3 as alternatives
   - Implement connection pooling appropriate for mobile battery life
   - Handle TLS certificate validation on mobile (system trust store vs. custom CA)

2. **DoH:**
   - Verify DNS resolver behavior on mobile (carrier DNS vs. custom)
   - Handle DoH endpoint blocking on cellular networks
   - Add fallback between DoH providers

3. **QUIC:**
   - Optimize for mobile: shorter timeouts, faster reconnection
   - Handle connection migration (IP changes mid-session)
   - Tune congestion control for mobile bandwidth patterns

4. **Graph:**
   - Handle Microsoft Graph API rate limiting more aggressively on mobile
   - Handle authentication token refresh on mobile
   - Consider OneDrive/Outlook API throttling differences

## Step 3: Implement Mobile Transport Adaptations

1. Add mobile-specific retry/reconnection logic to each transport
2. Add network state monitoring (connectivity change detection)
3. Adapt adaptive timing for mobile patterns (longer sleep on battery saver, shorter sleep when charging)
4. Ensure all transports work through mobile proxies and VPNs
5. Add battery-aware scheduling — reduce C2 check-in frequency on low battery

## Output

1. All created/modified files
2. Transport compatibility matrix for mobile
3. Battery/network impact analysis per transport
4. Configuration recommendations for mobile deployments
```

---

## Prompt 11 — Mobile Testing & QA Framework

```
You are a senior QA engineer specializing in mobile security testing. Your task is to create the testing framework and test suites for the Orchestra mobile agent on both Android and iOS.

## Step 1: Read Existing Test Infrastructure

Read:
1. `agent/tests/` — existing agent tests
2. `agent/benches/` — existing benchmarks
3. `orchestra-server/tests/` — server integration tests
4. `launcher/tests/` — launcher tests
5. `docs/LOCAL_TESTING_GUIDE.md` — existing testing guide
6. `docs/INTEGRATION_TEST_WALKTHROUGH.md` — integration test walkthrough

## Step 2: Design Mobile Test Strategy

### 2.1 Test Environments
- **Android Emulator (AVD)** — automated testing via `adb`
- **Android Physical Device** — rooted and non-rooted
- **iOS Simulator** — limited (no jailbreak, different sandbox)
- **iOS Physical Device** — jailbroken and non-jailbroken

### 2.2 Test Categories

#### Unit Tests (run on host machine, cross-compiled)
- Android/iOS env check logic (mocked)
- JNI/ObjC bridge compilation
- Config parsing for mobile payloads
- Transport adaptation logic

#### Integration Tests (run on device/emulator)
- Agent initialization on Android/iOS
- C2 connection and command execution
- Persistence installation and verification
- Post-exploitation module execution
- Sleep obfuscation on ARM64

#### End-to-End Tests (full C2 → agent → feedback loop)
- Build mobile payload via server API
- Deploy to emulator/device
- Verify C2 connection establishment
- Execute command suite
- Verify results in C2 dashboard

### 2.3 Test Automation
- **Android:** Use `adb` commands in shell scripts for install/start/stop/log collection
- **iOS:** Use `xcrun simctl` for simulator, `idevice*` tools for physical devices
- **C2:** Use `curl` against the server API for build/deploy/verify
- **CI Integration:** GitHub Actions with Android emulator, macOS runner for iOS simulator

## Step 3: Implement

1. Create `agent/tests/android_integration.rs` — Android-specific integration tests
2. Create `agent/tests/ios_integration.rs` — iOS-specific integration tests
3. Create `scripts/test_android.sh` — automated Android test runner
4. Create `scripts/test_ios.sh` — automated iOS test runner
5. Create `scripts/test_mobile_e2e.sh` — end-to-end mobile test
6. Update `docs/LOCAL_TESTING_GUIDE.md` with mobile testing instructions
7. Add benchmark configurations for mobile (ARM64 performance baselines)

## Output

1. All created/modified test files
2. Test matrix: test name | platform | requires device | requires root/jailbreak | automated in CI
3. CI configuration for mobile testing
4. Updated testing guide documentation
```

---

## Prompt 12 — Mobile Documentation & ROADMAP Update

```
You are a technical writer and Rust engineer. Your task is to update all Orchestra documentation to reflect the new mobile platform support.

## Step 1: Read All Documentation Files

Read every `.md` file in the `docs/` directory, the root `README.md`, `ROADMAP.md`, and `CHANGELOG.md`.

## Step 2: Update Each Document

Update the following sections across all docs:

### `README.md`
- Add Android and iOS to the supported platforms list
- Add mobile feature highlights
- Update build instructions to include mobile targets

### `ROADMAP.md`
- Move mobile support items to ✅ (or appropriately mark progress)
- Add any discovered limitations as known issues

### `CHANGELOG.md`
- Add `[Unreleased]` entries for mobile support

### `docs/ARCHITECTURE.md`
- Add mobile platform abstraction layer to the architecture diagram
- Update initialization sequence for mobile
- Add Android/iOS-specific command handlers to the dispatch table
- Update module dependency graph

### `docs/FEATURES.md`
- Add Android and iOS columns to the feature support matrix
- Add mobile-specific feature flags
- Add mobile-specific maturity labels

### `docs/CONFIGURATION.md`
- Add mobile configuration schema (AndroidBuildConfig, IosBuildConfig)
- Add mobile-specific config fields
- Document mobile persistence configuration options

### `docs/EVASION.md`
- Add Android/iOS env check documentation
- Add root/jailbreak detection (reverse) documentation
- Add emulator/simulator detection documentation

### `docs/POST_EXPLOITATION.md`
- Add Android post-exploitation module documentation
- Add iOS post-exploitation module documentation
- Document permission requirements for each platform

### `docs/LOCAL_TESTING_GUIDE.md`
- Add mobile testing instructions (emulator setup, device testing)
- Add mobile debugging tips

### Create New: `docs/MOBILE_SUPPORT.md`
- Comprehensive mobile support guide
- Platform differences from desktop
- Build instructions for each mobile target
- Deployment instructions
- Troubleshooting guide

## Output

1. All modified documentation files
2. The new `docs/MOBILE_SUPPORT.md` file
3. A summary of all changes made
```

---

## Appendix: Prompt Execution Order & Dependencies

```
Prompt 0  ──→  Prompt 1 (Android toolchain)
    │                │
    │                ├──→ Prompt 2 (Android JNI + packaging)
    │                │         │
    │                │         ├──→ Prompt 3 (Android env checks)
    │                │         ├──→ Prompt 4 (Android persistence)
    │                │         └──→ Prompt 5 (Android post-ex)
    │                │
    │                └──→ Prompt 6 (iOS toolchain)
    │                          │
    │                          ├──→ Prompt 7 (iOS env checks)
    │                          └──→ Prompt 8 (iOS persistence + post-ex)
    │
    ├──→ Prompt 9 (Builder pipeline)
    ├──→ Prompt 10 (C2 transport adaptation)
    ├──→ Prompt 11 (Testing framework)
    └──→ Prompt 12 (Documentation)
```

**Recommended execution order:** 0 → 1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10 → 11 → 12

**Each prompt can be run independently** as long as the design document from Prompt 0 exists. Later prompts reference earlier work but include their own context-gathering steps.