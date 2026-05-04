# Feature Flags Reference

This document provides a complete reference for all Cargo feature flags available
in the Orchestra agent. Features are grouped by category: Transport, Stealth,
Capability, and Build.

Enable features in your build profile (`profiles/<name>.toml`):

```toml
features = ["outbound-c", "persistence", "network-discovery"]
```

Or directly with Cargo:

```sh
cargo build -p agent --features "outbound-c,persistence" --bin agent-standalone
```

---

## Transport Features

### `outbound-c`

**Default: no** | **Recommended: yes**

Compiles the agent as a standalone binary that dials the Control Center
automatically and reconnects on disconnection with exponential back-off
(1 s → 64 s).

| Attribute | Value |
|-----------|-------|
| Profile fields | `c2_address`, `c_server_secret`, `server_cert_fingerprint` |
| Baked env vars | `ORCHESTRA_C_ADDR`, `ORCHESTRA_C_SECRET`, `ORCHESTRA_C_CERT_FP` |
| Required for | Production deployments |
| Conflicts with | None |

**How it works:**
The Builder sets compile-time environment variables during `cargo build`.
At runtime, `option_env!()` captures them as string literals. Debug builds
may override with `ORCHESTRA_C` and `ORCHESTRA_SECRET` runtime env vars.

**Example profile:**
```toml
package         = "agent"
bin_name        = "agent-standalone"
features        = ["outbound-c"]
c2_address      = "10.0.0.5:8444"
c_server_secret = "<psk>"
```

---

### `forward-secrecy`

**Default: no** | **Recommended for: production**

Adds an ephemeral X25519 Diffie-Hellman key exchange after the TLS handshake,
deriving a unique session key via HKDF-SHA256. Even if the PSK is later
compromised, recorded sessions cannot be decrypted.

| Attribute | Value |
|-----------|-------|
| Dependencies | `outbound-c` (implied by transport layer) |
| Overhead | One additional round-trip at connection start |
| Platform | All |

**Key exchange flow:**
1. Both sides generate fresh X25519 `EphemeralSecret`.
2. Public keys are exchanged.
3. Session key = `HKDF-SHA256(X25519(priv, peer_pub), SHA-256(PSK), "orchestra-fs-v1")`.
4. All subsequent frames encrypted with derived session key.

**Example profile:**
```toml
features = ["outbound-c", "forward-secrecy"]
```

---

### `http-transport`

**Default: no** | **Experimental**

HTTP-based transport using long-polling for command delivery. Useful for
environments where raw TCP is blocked but HTTPS is allowed.

| Attribute | Value |
|-----------|-------|
| Dependencies | None |
| Platform | All |
| Maturity | Experimental |

---

### `doh-transport`

**Default: no** | **Experimental**

DNS-over-HTTPS transport for agent sessions. Agents tunnel traffic through
DNS TXT/A queries to the Control Center's DoH bridge.

| Attribute | Value |
|-----------|-------|
| Dependencies | Server must have `doh_enabled = true` |
| Platform | All |
| Maturity | Experimental |

**Server-side configuration:**
```toml
doh_enabled         = true
doh_listen_addr     = "0.0.0.0:8053"
doh_domain          = "doh.example.com"
doh_beacon_sentinel = "ORCHESTRA_BEACON"
doh_idle_ip         = "127.0.0.1"
```

---

### `ssh-transport`

**Default: no** | **Experimental**

SSH-based transport channel for agent communication.

| Attribute | Value |
|-----------|-------|
| Dependencies | None |
| Platform | All |
| Maturity | Experimental |

---

### `smb-pipe-transport`

**Default: no** | **Windows only**

Uses Windows named pipes over SMB for agent communication in environments
where TCP traffic is restricted.

| Attribute | Value |
|-----------|-------|
| Dependencies | None |
| Platform | Windows only |
| Maturity | Experimental |

---

### `traffic-normalization`

**Default: no**

Applies traffic pattern normalization to the agent channel to make
connections blend with normal HTTPS traffic.

| Attribute | Value |
|-----------|-------|
| Dependencies | `outbound-c` |
| Platform | All |
| Server config | `agent_traffic_profile = "enterprise"` or `"stealth"` |

---

## Stealth Features

### `stealth` (bundle)

**Default: no** | **Windows-focused**

Convenience meta-feature that enables multiple stealth techniques at once:
- `direct-syscalls`
- `unsafe-runtime-rewrite`
- `memory-guard`
- `ppid-spoofing`

| Attribute | Value |
|-----------|-------|
| Enables | `direct-syscalls`, `unsafe-runtime-rewrite`, `memory-guard`, `ppid-spoofing` |
| Platform | Primarily Windows; some components are cross-platform |

**Example profile:**
```toml
features = ["outbound-c", "stealth"]
```

---

### `direct-syscalls`

**Default: no** | **Windows only**

Uses direct syscall invocation (bypassing the IAT) for Windows API calls.
Avoids API hooks set by security products.

| Attribute | Value |
|-----------|-------|
| Platform | Windows x86_64 + aarch64 |
| Requirements | Inline assembly support |
| aarch64 note | >6-arg syscalls return `EINVAL` (fail-closed) |

**Implementation:**
- x86_64: inline asm with explicit register bindings and clobbers
- aarch64: register-passed syscall convention, 6-arg max (architectural limit)

---

### `stack-spoof`

**Default: no** | **Windows only**

Spoofs the call stack to make agent threads appear as legitimate system
threads when inspected by security tools.

| Attribute | Value |
|-----------|-------|
| Platform | Windows only |
| Dependencies | None |

---

### `manual-map`

**Default: no** | **Windows only**

Enables in-memory PE loading for the `module_loader`, avoiding temporary
file creation. The loader parses PE headers, copies sections, resolves
imports, applies relocations, and calls the entry point entirely in memory.

| Attribute | Value |
|-----------|-------|
| Platform | Windows only |
| Applies to | `module_loader` |
| Alternative | Without this feature, Windows falls back to temp-file loading |

**PE loading steps:**
1. Parse DOS + NT headers with `goblin` crate
2. Allocate memory for the image
3. Copy PE sections
4. Resolve imports via remote module enumeration
5. Apply base relocations
6. Set memory protections per section
7. Call `DllMain(DLL_PROCESS_ATTACH)`

---

### `env-validation`

**Default: no**

Enforces that the agent binary is running inside an approved execution
context. Detects debuggers, hypervisors/VMs, and Active Directory domain
membership. The agent exits if any check fails.

| Attribute | Value |
|-----------|-------|
| Platform | All |
| Behaviour | Agent exits on failure |
| Checks | Debugger, VM/hypervisor, AD domain |

**Checks performed:**

| Check | Method | Platform |
|-------|--------|----------|
| Debugger | `TracerPid` from `/proc/self/status` (Linux); `IsDebuggerPresent()` (Windows) | All |
| VM/Hypervisor | CPUID hypervisor bit, DMI strings, `/proc/cpuinfo` | All |
| AD Domain | `/etc/sssd/sssd.conf` or `/etc/krb5.conf` (Linux); `NetGetJoinInformation` (Windows) | All |

**Adaptive VM detection:**
- Tier 1 (threshold=2): Default for unknown VMs
- Tier 2 (threshold=3): Cloud signal present (expected hypervisor match or IMDS reachability)
- Tier 3 (threshold=4): Strong cloud confirmation (both IMDS and expected hypervisor)

**Cloud whitelisting controls:**
- `cloud_instance_allow_without_imds`: Bypass when IMDS is validated but instance-id parsing unavailable
- `cloud_instance_fallback_ids`: Fallback instance-id patterns when IMDS retrieval fails
- `vm_detection_extra_hypervisor_names`: Operator-supplied hypervisor name fragments

**Example profile:**
```toml
features = ["outbound-c", "env-validation"]
```

---

### `memory-guard`

**Default: no**

Encrypts sensitive key material in memory when not actively in use. The key
is stored in a `Mutex<KeyBufPtr>` that decrypts on lock and re-encrypts on
unlock.

| Attribute | Value |
|-----------|-------|
| Platform | All |
| Part of | `stealth` bundle |
| Overhead | Minimal — only affects key access paths |

**Implementation:**
- Static `KEY_BUF: Mutex<KeyBufPtr>` stores encrypted key material
- Raw pointer extracted from `&'static mut [u8; 32]` before borrow is consumed
- Only accessible while holding the `Mutex` guard

---

### `unsafe-runtime-rewrite`

**Default: no** | **Part of stealth bundle**

Enables the optimizer's metamorphic engine for runtime code transformation.
Applies instruction substitution and NOP insertion to alter code signatures.

| Attribute | Value |
|-----------|-------|
| Platform | x86_64 (requires `mprotect`/`VirtualProtect`) |
| Part of | `stealth` bundle |
| Safety | Verified with test vectors before and after optimization |

---

### `ppid-spoofing`

**Default: no** | **Windows only**

Spoofs the parent process ID to make the agent appear as a child of a
legitimate system process.

| Attribute | Value |
|-----------|-------|
| Platform | Windows only |
| Part of | `stealth` bundle |

---

### `self-reencode`

**Default: no**

Re-encodes the agent binary at runtime to change its static signature,
helping evade file-based detection.

| Attribute | Value |
|-----------|-------|
| Platform | All |
| Overhead | One-time cost at startup |

---

## Capability Features

### `persistence`

**Default: no** | **Opt-in**

Installs a persistence mechanism so the agent survives reboots.

| Attribute | Value |
|-----------|-------|
| Platform | Linux (systemd), Windows (schtasks), macOS (launchd) |
| Default | Off — must be explicitly enabled |
| Config | `persistence_enabled = true` in `agent.toml` |
| Commands | `EnablePersistence`, `DisablePersistence` |

**Platform implementations:**
- **Linux**: systemd user unit file
- **Windows**: Scheduled task via `schtasks`
- **macOS**: `launchd` plist

Each OS registration step checks the return code and propagates errors.

**Example profile:**
```toml
features = ["outbound-c", "persistence"]
```

---

### `network-discovery`

**Default: no**

Enables bounded network scanning for asset inventory: ARP table enumeration,
ICMP ping sweeps, and TCP service detection.

| Attribute | Value |
|-----------|-------|
| Platform | All |
| Command | `DiscoverNetwork` |
| Rate limiting | Yes — minimizes network congestion |

**Discovery methods:**
- **ARP table**: Parse system ARP cache for MAC/IP addresses
- **ICMP ping**: Echo requests to specified subnet
- **TCP connect**: Scan common ports for service identification

**Example profile:**
```toml
features = ["outbound-c", "network-discovery"]
```

---

### `remote-assist`

**Default: no** | **Consent-gated**

Screen capture and input simulation for remote support scenarios. Requires
multiple levels of consent.

| Attribute | Value |
|-----------|-------|
| Platform | Linux (X11), macOS, Windows (partial) |
| Commands | `CaptureScreen`, `SimulateKey`, `SimulateMouse` |
| Consent required | Yes — file/registry flag must exist on target |

**Consent mechanism:**
- **Linux/macOS**: `/var/run/orchestra-consent` file must exist
- **Windows**: Specific registry key must be set

**Screen capture:**
- Linux: X11 via `x11cap` crate
- macOS: `screencapture` CLI with PNG validation
- Windows: Returns unsupported error (input simulation works)

**Example profile:**
```toml
features = ["outbound-c", "remote-assist"]
```

---

### `hci-research`

**Default: no** | **Privacy-preserving** | **Consent-gated**

Collects anonymized user interaction telemetry: key press timing (not
characters), active window titles, stored in a fixed-size in-memory ring
buffer.

| Attribute | Value |
|-----------|-------|
| Platform | All |
| Commands | `StartHciLogging`, `StopHciLogging`, `GetHciLogBuffer` |
| Consent required | Yes — must be started explicitly via command |
| Privacy | Only timing data, not key content |

**Data collected:**
- Key press/release timing (not characters)
- Active window title (periodic polling)
- Stored in fixed-size ring buffer, never written to disk

**Example profile:**
```toml
features = ["outbound-c", "hci-research"]
```

---

### `evdev`

**Default: no** | **Linux only**

Enables evdev-based input event capture on Linux for HCI research.

| Attribute | Value |
|-----------|-------|
| Platform | Linux only |
| Related to | `hci-research` |

---

### `surveillance`

**Default: no** | **Windows only** | **Opt-in**

Enables screenshot capture, keylogger, and clipboard monitoring capabilities.

| Attribute | Value |
|-----------|-------|
| Platform | Windows only |
| Dependencies | `dep:image` (for screenshot PNG encoding) |
| Commands | `Screenshot`, `KeyloggerStart`, `KeyloggerDump`, `KeyloggerStop`, `ClipboardMonitorStart`, `ClipboardMonitorDump`, `ClipboardMonitorStop`, `ClipboardGet` |
| Storage | Encrypted ring buffers (ChaCha20-Poly1305) |

**Capabilities:**

| Capability | Method | Output |
|------------|--------|--------|
| Screenshot | Multi-monitor Win32 API capture | PNG bytes |
| Keylogger | `SetWindowsHookExW(WH_KEYBOARD_LL)` | Encrypted keystroke buffer |
| Clipboard | `OpenClipboard` + `GetClipboardData` | Encrypted clipboard buffer |

All captured data is stored in encrypted ring buffers that are automatically
encrypted/decrypted during sleep obfuscation cycles.

**Example profile:**
```toml
features = ["outbound-c", "surveillance"]
```

---

### `browser-data`

**Default: no** | **Windows only** | **Opt-in**

Enables credential and cookie extraction from Chrome, Edge, and Firefox browsers.

| Attribute | Value |
|-----------|-------|
| Platform | Windows only |
| Dependencies | None (custom SQLite parser, NSS runtime loading) |
| Command | `BrowserData` with `BrowserType` and `BrowserDataType` enums |
| Chrome support | v127+ App-Bound Encryption with 3 bypass strategies |

**Supported browsers and data types:**

| Browser | Credentials | Cookies | Encryption Handling |
|---------|:-----------:|:-------:|---------------------|
| Chrome | ✅ | ✅ | App-Bound Encryption v127+ (3 bypass strategies) |
| Edge | ✅ | ✅ | Same Chromium engine as Chrome |
| Firefox | ✅ | ✅ | NSS `logins.json` + `key4.db` |

**Chrome App-Bound Encryption bypass strategies:**

| Strategy | Method | Requirement |
|----------|--------|-------------|
| Local COM | `IElevator` COM activation in-process | Elevated agent |
| SYSTEM token + DPAPI | Impersonate SYSTEM, call `CryptUnprotectData` | `SeDebugPrivilege` |
| Named-pipe IPC | Communicate with `elevation_service.exe` | Service running |

**Example profile:**
```toml
features = ["outbound-c", "browser-data"]
```

---

### `hwbp-amsi`

**Default: no** | **Windows only**

Uses hardware breakpoints (DR0/DR1) via a Vectored Exception Handler to bypass
AMSI without modifying any code pages. When this feature is **not** enabled,
the agent falls back to the memory-patch AMSI bypass.

| Attribute | Value |
|-----------|-------|
| Platform | Windows only |
| Method | DR0/DR1 execute breakpoints on `AmsiScanBuffer` / `AmsiScanString` |
| VEH handler | Returns `S_OK` + `AMSI_RESULT_CLEAN` |
| Stealth | No code page modifications — invisible to memory integrity checks |

**Example profile:**
```toml
features = ["outbound-c", "hwbp-amsi"]
```

---

## Build Features

### `dev`

**Default: no** | **Development only**

Enables development-mode features including verbose logging and runtime
overrides for baked addresses.

| Attribute | Value |
|-----------|-------|
| Runtime overrides | `ORCHESTRA_C` and `ORCHESTRA_SECRET` env vars |
| Logging | All debug/trace output enabled |
| Use for | Local development only |

---

### `hot-reload`

**Default: no** | **Development only**

Enables hot-reload of agent configuration without restart.

| Attribute | Value |
|-----------|-------|
| Related to | `ReloadConfig` command |
| Use for | Development only |

---

### `module-signatures`

**Default: yes** (on by default)

Enables Ed25519 signature verification for loaded modules. The packager
signs modules with a private key; the loader verifies against a public key
before loading.

| Attribute | Value |
|-----------|-------|
| Default | Enabled |
| Key tool | `cargo run --bin keygen -- --module-signing-key` |
| Wire format | `[64-byte signature][module_data]` |

**Key policy:**

| Mode | Behaviour |
|------|-----------|
| Runtime key provided | Verifies against supplied Ed25519 public key |
| No runtime key | Falls back to compile-time `MODULE_SIGNING_PUBKEY` |
| `strict-module-key` feature | Hard error if no runtime key — use for production |

---

### `strict-module-key`

**Default: no** | **Recommended for production**

Converts the `module-signatures` fallback-to-compile-time-key behaviour into
a hard error. Ensures a runtime verification key is always provided.

| Attribute | Value |
|-----------|-------|
| Dependencies | `module-signatures` |
| Use for | Production builds |

**Example:**
```toml
features = ["outbound-c", "module-signatures", "strict-module-key"]
```

---

### `perf-optimize`

**Default: no**

Enables aggressive performance optimizations including SIMD paths and
microarchitecture-specific dispatch.

| Attribute | Value |
|-----------|-------|
| Platform | x86_64 |
| Overhead | None at runtime — optimizations applied at compile time |

---

## Feature compatibility matrix

### Platform support

| Feature | Linux | Windows | macOS |
|---------|-------|---------|-------|
| `outbound-c` | ✅ | ✅ | ✅ |
| `forward-secrecy` | ✅ | ✅ | ✅ |
| `http-transport` | ✅ | ✅ | ✅ |
| `doh-transport` | ✅ | ✅ | ✅ |
| `ssh-transport` | ✅ | ✅ | ✅ |
| `smb-pipe-transport` | — | ✅ | — |
| `traffic-normalization` | ✅ | ✅ | ✅ |
| `stealth` | ✅ | ✅ | ✅ |
| `direct-syscalls` | — | ✅ | — |
| `stack-spoof` | — | ✅ | — |
| `manual-map` | — | ✅ | — |
| `env-validation` | ✅ | ✅ | ✅ |
| `memory-guard` | ✅ | ✅ | ✅ |
| `unsafe-runtime-rewrite` | ✅ | ✅ | ✅ |
| `ppid-spoofing` | — | ✅ | — |
| `self-reencode` | ✅ | ✅ | ✅ |
| `persistence` | ✅ | ✅ | ✅ |
| `network-discovery` | ✅ | ✅ | ✅ |
| `remote-assist` | ✅ | ✅ | ⚠️ |
| `hci-research` | ✅ | ✅ | ✅ |
| `evdev` | ✅ | — | — |
| `surveillance` | — | ✅ | — |
| `browser-data` | — | ✅ | — |
| `hwbp-amsi` | — | ✅ | — |

### Common feature combinations

**Minimal production agent:**
```toml
features = ["outbound-c"]
```

**Hardened production agent:**
```toml
features = ["outbound-c", "forward-secrecy", "module-signatures", "strict-module-key", "env-validation"]
```

**Windows stealth agent:**
```toml
features = ["outbound-c", "stealth", "manual-map"]
```

**Full capability agent:**
```toml
features = ["outbound-c", "forward-secrecy", "persistence", "network-discovery", "remote-assist", "surveillance", "browser-data"]
```

**Windows full-stealth with post-exploitation:**
```toml
features = ["outbound-c", "stealth", "manual-map", "hwbp-amsi", "surveillance", "browser-data"]
```

**Development/testing:**
```toml
features = ["outbound-c", "dev"]
```

---

## Discovering available features

The Builder reads the agent's feature table at runtime:

```sh
cargo run --release -p builder -- configure --name my-agent
# Interactive wizard lists all available features
```

Or inspect `agent/Cargo.toml` directly:

```sh
grep -A 50 '\[features\]' agent/Cargo.toml
```

---

## Build Diversification & Reproducibility

Every agent build automatically receives **unique random seeds** for code
transformation and optimizer stub values, so even when the same source code
and profile are used, the resulting binary will be different on every build.
This ensures that two deployments never share identical binary signatures.

Two seed environment variables are injected by the builder:

| Variable | Consumer | Purpose |
|---|---|---|
| `OPTIMIZER_STUB_SEED` | `optimizer/build.rs` | Randomizes dead-code constants and stub values |
| `CODE_TRANSFORM_SEED` | `code_transform_macro` | Seeds the ChaCha8 PRNG for instruction substitution, block reordering, and opaque predicates |

### Per-build uniqueness (default)

When no seed is specified, the builder reads 8 bytes from `/dev/urandom`
(Linux/macOS) to generate a fresh seed each time.  This means **every build
produces a unique binary** — even back-to-back builds with identical source
code and the same profile.

### Reproducible builds

For incident response, audit, or testing scenarios where bit-for-bit
reproducibility is required, pass an explicit seed:

**Builder CLI:**
```sh
cargo run --release -p builder -- build my-profile --seed a1b2c3d4e5f6a7b8
```

**Orchestra Server API** (`POST /build`):
```json
{
  "os": "windows",
  "arch": "x86_64",
  "seed": "a1b2c3d4e5f6a7b8",
  ...
}
```

When `seed` is provided, both `OPTIMIZER_STUB_SEED` and
`CODE_TRANSFORM_SEED` are pinned to that value, making the output binary
bit-for-bit identical across machines.

---

## See also

- [QUICKSTART.md](QUICKSTART.md) — Getting started guide
- [ARCHITECTURE.md](ARCHITECTURE.md) — Wire protocol and crypto details
- [CONTROL_CENTER.md](CONTROL_CENTER.md) — Server configuration and REST API
- [SECURITY.md](SECURITY.md) — Security audit and hardening guide
