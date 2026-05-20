# Orchestra Mobile Platform Support

> **Status:** Alpha (stubs + build infrastructure in place; full feature implementation in progress)
> **Last Updated:** 2026-05-19

## Overview

Orchestra now supports Android and iOS as target platforms for agent deployment. The mobile support is implemented as a **platform adapter layer** that provides per-platform implementations of environment validation, persistence, post-exploitation, and transport adaptations while sharing the platform-agnostic core (crypto, protocol framing, command dispatch, C2 transports).

## Platform Status Matrix

| Capability | Android | iOS | Notes |
|------------|---------|-----|-------|
| Agent core compilation | ✅ Staged | ✅ Staged | Requires Android NDK / Xcode for C deps |
| JNI bridge (Android) / C bridge (iOS) | ✅ Implemented | ✅ Implemented | |
| Environment checks | 🟡 Stub | 🟡 Stub | Full impl in progress |
| Persistence | 🟡 Stub | 🟡 Stub | Full impl in progress |
| Post-exploitation | 🟡 Stub | 🟡 Stub | Full impl in progress |
| Builder pipeline integration | 🟡 Stub | 🟡 Stub | Mobile config types defined |
| C2 transport adaptation | 🟡 Pending | 🟡 Pending | HTTP/DoH/QUIC work; SSH/SMB disabled |
| Testing framework | 🟡 Pending | 🟡 Pending | |

Legend: ✅ Complete  🟡 Partial/Stub  ❌ Not applicable

## Directory Structure

```
agent/src/android/           # Android platform adapter (Rust)
├── mod.rs                   # Module declarations
├── env_checks.rs            # Environment validation (debugger, root, emulator)
├── persistence.rs           # Persistence mechanisms
├── post_exploitation.rs     # Credential access, surveillance, exfil
└── jni_bridge.rs            # JNI entry points (nativeInit/Start/Stop)

agent/src/ios/               # iOS platform adapter (Rust)
├── mod.rs                   # Module declarations
├── env_checks.rs            # Environment validation (jailbreak, debugger, simulator)
├── persistence.rs           # Persistence mechanisms
└── post_exploitation.rs     # Keychain, surveillance, exfil

mobile/android/              # Android app wrapper
├── build.gradle.kts         # Root Gradle build
├── settings.gradle.kts      # Gradle settings
├── build_agent.sh           # Build script (Rust → APK)
└── app/
    ├── build.gradle.kts     # App module build
    └── src/main/
        ├── AndroidManifest.xml
        ├── java/com/orchestra/
        │   ├── Agent.java           # JNI native method declarations
        │   ├── AgentService.java    # Foreground service
        │   └── BootReceiver.java    # BOOT_COMPLETED receiver
        └── jniLibs/arm64-v8a/       # Compiled .so output directory

mobile/ios/                  # iOS Xcode bridge
├── build_agent.sh           # Build script (Rust → .a + Xcode)
└── OrchestraBridge/
    ├── OrchestraBridge.h    # C ABI header
    └── OrchestraBridge.c    # C bridge shim (weak symbols)
```

## Build Instructions

### Android

**Prerequisites:**
- Rust toolchain with `aarch64-linux-android` target
- Android NDK (for `ring` crate C compilation)
- Gradle 8.x and Android SDK

```bash
# Install Rust Android target
rustup target add aarch64-linux-android x86_64-linux-android

# Install cargo-ndk (automates NDK toolchain detection)
cargo install cargo-ndk

# Build the agent + APK
cd mobile/android
./build_agent.sh debug arm64

# Output: app/build/outputs/apk/debug/app-debug.apk
```

**Known build blocker:** The `ring` crate (transitive dependency via `rustls`) requires `aarch64-linux-android-clang` from the Android NDK. Install the NDK and set `ANDROID_NDK_HOME`, or use `cargo-ndk` which auto-detects it.

**Feature flag recommendations for Android:**
```bash
cargo ndk --target aarch64-linux-android --platform 26 -- build \
  --no-default-features \
  --features "http-transport,env-validation,persistence,adaptive-timing"
```

### iOS

**Prerequisites:**
- macOS with Xcode 15+
- Rust targets: `aarch64-apple-ios`, `aarch64-apple-ios-sim`

```bash
rustup target add aarch64-apple-ios aarch64-apple-ios-sim

cd mobile/ios
./build_agent.sh debug device

# Output: OrchestraAgent/libs/liborchestra.a
```

**Note:** iOS does not support `ring`'s native C code out of the box. Use `--no-default-features` and avoid features that pull in `rustls`/`ring`:
```bash
cargo build --target aarch64-apple-ios --no-default-features -p agent
```

## Dependency Compatibility Matrix

| Crate | Android | iOS | Notes |
|-------|---------|-----|-------|
| `ring` | ⚠️ Needs NDK clang | ⚠️ Needs Xcode clang | C/asm crypto — requires cross-compiler |
| `rustls` | ⚠️ Via ring | ⚠️ Via ring | Consider `rustls-platform-verifier` for mobile |
| `jni` | ✅ Native | ❌ N/A | Android-only JNI bindings |
| `android_logger` | ✅ Native | ❌ N/A | Routes Rust logs to logcat |
| `libc` | ✅ Works | ✅ Works | POSIX subset available on both |
| `tokio` | ✅ Works | ✅ Works | Async runtime works on mobile |
| `reqwest` | ✅ Works | ✅ Works | HTTP client with rustls-tls |
| `nt_syscall` | ❌ N/A | ❌ N/A | Windows-only, cfg-gated |
| `hollowing` | ❌ N/A | ❌ N/A | Windows-only, cfg-gated |
| `enigo` | ❌ N/A | ❌ N/A | Desktop input automation, cfg-gated |
| `x11rb` | ❌ N/A | ❌ N/A | X11/Wayland, cfg-gated |

## Architecture

### Platform Gating Strategy

The codebase uses three levels of platform gating:

1. **`#[cfg(target_os = "...")]`** — Compile-time target OS checks in `agent/src/lib.rs` for per-OS module declarations
2. **Feature flags** — Feature-gated modules via `#[cfg(feature = "...")]` for optional subsystems
3. **Runtime adapters** — Platform adapter modules (`agent/src/android/`, `agent/src/ios/`) provide per-platform trait implementations

### Android/iOS Differences from Desktop

| Aspect | Desktop (Linux/Windows) | Android | iOS |
|--------|------------------------|---------|-----|
| Process model | Full process control | App sandbox | Strict sandbox |
| `fork()` | Available | Available (Linux kernel) | ❌ Not in sandboxed apps |
| `/proc` filesystem | Full access | Partial access | ❌ Not available |
| Persistence | systemd/schtasks/launchd | Foreground service + WorkManager | Background fetch + silent push |
| Root access | Common | Requires root exploit | Requires jailbreak |
| Network | Full TCP/UDP | Cellular + WiFi (may be behind CGNAT) | Cellular + WiFi |
| File system | Full access | App-private + shared storage (scoped) | App sandbox only (non-jailbroken) |
| System APIs | OS-level FFI | JNI (Java/Kotlin) | Objective-C runtime / Swift interop |

## Known Limitations

1. **`ring` C compilation:** The `ring` crate (used by `rustls` for TLS) requires a C compiler targeting the mobile platform. On Android this means the Android NDK LLVM toolchain; on iOS this means Xcode's clang.
   - **Workaround:** Use `aws-lc-rs` as the crypto backend for `rustls` (supports Android/iOS natively, no C compiler needed)
   - **Mitigation:** The `build_agent.sh` scripts document the NDK requirement and use `cargo-ndk` to auto-configure

2. **No native code execution on non-jailbroken iOS:** iOS apps cannot `fork()`, access `/proc`, or load unsigned dynamic libraries. The agent must run within the app's process sandbox.

3. **Background execution limits:** Android 8+ and iOS aggressively restrict background processes. The foreground service (Android) and background modes (iOS) provide mitigation but are not as reliable as desktop persistence.

4. **Network restrictions:** Mobile carriers may use CGNAT, preventing inbound connections. All C2 must be outbound-only (the agent connects to the server).

5. **Build environment:** Cross-compiling `ring` for Android requires the Android NDK. CI/CD pipelines need `ANDROID_NDK_HOME` and `cargo-ndk`.

## Feature Flag Compatibility for Mobile

| Feature | Android | iOS | Notes |
|---------|---------|-----|-------|
| `http-transport` | ✅ | ✅ | Primary transport for mobile |
| `doh-transport` | ✅ | ✅ | Good for mobile networks |
| `quic-transport` | ✅ | ✅ | Excellent for mobile (connection migration) |
| `ssh-transport` | ⚠️ | ⚠️ | Unusual on mobile, may trigger detection |
| `smb-pipe-transport` | ❌ | ❌ | Windows-only |
| `env-validation` | ✅ | ✅ | Android/iOS stubs implemented |
| `persistence` | ✅ | ✅ | Android/iOS stubs implemented |
| `surveillance` | 🟡 | 🟡 | Requires platform-specific capture APIs |
| `adaptive-timing` | ✅ | ✅ | Cross-platform |
| `browser-data` | 🟡 | 🟡 | Chrome/iOS Safari data access needs platform impl |
| All `windows`-only features | ❌ | ❌ | Compiled out on non-Windows targets |

## Related Documentation

- [Mobile Platform Abstraction Design](MOBILE_DESIGN.md) — Trait definitions and architecture design
- [Architecture Overview](ARCHITECTURE.md) — Agent initialization sequence
- [Evasion Subsystem](EVASION.md) — Environment check contracts
- [Post-Exploitation](POST_EXPLOITATION.md) — Post-ex module contracts
- [Configuration](CONFIGURATION.md) — Mobile config schema
- [Local Testing Guide](LOCAL_TESTING_GUIDE.md) — Mobile testing instructions