# Architecture

Deep-dive into Orchestra's internal design: agent module initialization, syscall infrastructure, memory guard lifecycle, evasion subsystem, C2 state machine, injection engine, sleep obfuscation pipeline, and server internals.

---

## Agent Internals

### Module Initialization Order

When the agent binary starts, modules initialize in a specific sequence to ensure dependencies are satisfied before use:

```
1. config.rs          — Load or embed configuration
2. env_check.rs       — Sandbox/debugger/VM detection
3. env_check_sandbox.rs — Extended sandbox scoring
4. nt_syscall         — Map clean ntdll, resolve SSNs (Windows)
5. evasion.rs         — AMSI bypass, ETW patching
6. amsi_defense.rs    — HWBP AMSI or memory-patch AMSI
7. etw_patch.rs       — ETW function hooking
8. c2_*.rs            — Transport initialization
9. sleep_obfuscation  — Memory region tracking
10. memory_guard.rs   — Heap encryption registration
11. injection_engine  — Pre-injection recon cache
12. handlers.rs       — Command dispatch table
```

Each step runs to completion before the next begins. If any security check fails (sandbox detected, debugger present, domain mismatch), the agent exits silently.

### Agent State Machine

```
                    ┌──────────────┐
                    │   Start      │
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │ Env Check    │──── Fail ──► Silent Exit
                    │ (sandbox/    │
                    │  debugger)   │
                    └──────┬───────┘
                           │ Pass
                    ┌──────▼───────┐
                    │ Evasion Init │
                    │ AMSI + ETW   │
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │ C2 Connect   │──── Fail ──► Backoff + Retry
                    │ (malleable)  │
                    └──────┬───────┘
                           │ Connected
                    ┌──────▼───────┐
               ┌──►│  Main Loop   │
               │   └──────┬───────┘
               │          │
               │   ┌──────▼───────┐
               │   │ Sleep Cycle  │
               │   │ (encrypt     │
               │   │  memory)     │
               │   └──────┬───────┘
               │          │ Wake
               │   ┌──────▼───────┐
               │   │ Check Tasks  │──── Task ──► Execute ──┐
               │   │ (beacon)     │                         │
               │   └──────┬───────┘                         │
               │          │ No task                         │
               └──────────┘◄────────────────────────────────┘
```

### Command Dispatch (`handlers.rs`)

The `handle_command()` function receives a `Command` variant and dispatches to the appropriate handler. It takes 6 parameters:

```rust
pub fn handle_command(
    cmd: Command,
    config: &mut Config,
    session: &CryptoSession,
    agent_id: &str,
    extra_args: Option<&str>,
    plugin_manager: &mut PluginManager,
) -> Result<String, String>
```

Each command handler is a separate function in `handlers.rs` or a dedicated module. The 40+ commands include:

| Category | Commands |
|----------|----------|
| **Core** | `Ping`, `GetSystemInfo`, `Shutdown`, `ReloadConfig` |
| **Filesystem** | `ListDirectory`, `ReadFile`, `WriteFile` |
| **Shell** | `StartShell`, `ShellInput`, `ShellOutput`, `CloseShell` |
| **Modules** | `DeployModule`, `ExecutePlugin`, `ListPlugins`, `UnloadPlugin`, `GetPluginInfo`, `DownloadModule`, `ExecutePluginBinary` |
| **Discovery** | `DiscoverNetwork`, `ListProcesses`, `JobStatus` |
| **Remote Assist** | `CaptureScreen`, `SimulateKey`, `SimulateMouse` |
| **HCI Research** | `StartHciLogging`, `StopHciLogging`, `GetHciLogBuffer` |
| **Persistence** | `EnablePersistence`, `DisablePersistence` |
| **Injection** | `MigrateAgent` |
| **Evasion** | `SetReencodeSeed`, `MorphNow` |
| **Token** | `MakeToken`, `StealToken`, `Rev2Self`, `GetSystem` |
| **Lateral** | `PsExec`, `WmiExec`, `DcomExec`, `WinRmExec` |
| **P2P** | `LinkAgents`, `UnlinkAgent`, `ListTopology`, `LinkTo`, `Unlink`, `ListLinks` |

---

## Syscall Infrastructure

### Direct Syscalls (`nt_syscall`)

On Windows, the agent avoids calling ntdll exports directly. Instead, it:

1. **Maps a clean copy of ntdll.dll** from disk (`\KnownDlls\ntdll.dll` or `\SystemRoot\System32\ntdll.dll`)
2. **Resolves syscall stubs** by walking the clean ntdll's export table
3. **Extracts the SSN** (System Service Number) from each stub's `mov eax, IMM32` instruction
4. **Finds a syscall gadget** (`syscall; ret` or `jmp r11`) in the clean ntdll
5. **Caches results** in a static `DashMap<String, SyscallTarget>`

```rust
pub struct SyscallTarget {
    pub ssn: u32,           // System Service Number
    pub gadget_addr: usize, // Address of syscall;ret gadget
}
```

### Halo's Gate Fallback

If a syscall stub has been hooked (e.g., replaced with `jmp <hook>` by an EDR), the agent falls back to Halo's Gate:

1. Examine neighboring syscall stubs (up/down by 32 bytes)
2. Find an unhooked stub and calculate the SSN offset
3. Use the unhooked stub's syscall gadget

This handles the case where EDR products inline-hook specific NT API functions.

### Indirect Syscall Dispatch

For maximum evasion, the agent uses indirect syscalls that dispatch through `NtContinue`:

1. Set up a fake call stack on the heap
2. Push `NtContinue` context with the target syscall's SSN in RAX
3. `NtContinue` transfers execution to the syscall gadget
4. The kernel-mode call stack appears to originate from `ntdll.dll`, not the agent

### SSN Resolution Functions

The agent resolves these NT functions at runtime:

| Function | Purpose |
|----------|---------|
| `NtAllocateVirtualMemory` | Memory allocation (RW/RX) |
| `NtProtectVirtualMemory` | Memory protection changes |
| `NtWriteVirtualMemory` | Cross-process memory writes |
| `NtCreateThreadEx` | Remote thread creation |
| `NtOpenProcess` | Process handle acquisition |
| `NtClose` | Handle closure |
| `NtDelayExecution` | Sleep (used by sleep obfuscation) |
| `NtContinue` | Thread context restoration (stack spoofing) |
| `NtFreeVirtualMemory` | Memory deallocation |
| `NtQueryVirtualMemory` | Memory region enumeration |
| `NtReadVirtualMemory` | Cross-process memory reads |

---

## Memory Guard Lifecycle

The `memory_guard` module provides encrypted heap storage that integrates with the sleep obfuscation cycle.

### Registration

```rust
// Register a heap allocation for automatic encryption during sleep
let guarded = MemoryGuard::new(1024);  // Allocates 1024 bytes
// Data is automatically tracked and will be encrypted during sleep
```

### Lifecycle States

```
  ┌──────────┐
  │Allocated │◄── Initial state after MemoryGuard::new()
  └────┬─────┘
       │ Sleep cycle begins
  ┌────▼─────┐
  │Encrypted │◄── MemoryGuard registers region with sleep subsystem
  └────┬─────┘    Contents encrypted with XChaCha20-Poly1305
       │ Wake
  ┌────▼─────┐
  │Decrypted │◄── Contents restored, integrity verified
  └────┬─────┘
       │ Drop
  ┌────▼─────┐
  │  Freed   │◄── Zeroed before deallocation
  └──────────┘
```

### XMM Register Key Stash (Windows)

On Windows x86_64, the sleep encryption key is stashed in XMM14/XMM15 registers:

- **XMM14**: First 16 bytes of the 32-byte XChaCha20 key
- **XMM15**: Last 16 bytes of the 32-byte XChaCha20 key

These registers are not routinely inspected by EDR memory scanners and survive `NtDelayExecution` calls. The key never exists in process memory as plaintext during the sleep period.

---

## Evasion Subsystem

### AMSI Bypass

The agent implements two AMSI bypass strategies, selectable at build time:

#### HWBP AMSI (`amsi_defense.rs` — HWBP mode)

Uses hardware breakpoints (DR0/DR1) with a Vectored Exception Handler:

1. `AddVectoredExceptionHandler(1, amsi_veh_handler)` — Register VEH as first handler
2. `SetThreadContext` — Set DR0 to address of `AmsiScanBuffer`, DR1 to `AmsiScanString`
3. Set DR7 to enable DR0/DR1 as execute breakpoints
4. When AMSI is called, the CPU triggers a breakpoint exception
5. The VEH handler intercepts the exception, sets `RAX = S_OK` (0) and `Result = AmsiResult::AMSI_RESULT_CLEAN`
6. Execution continues as if the scan returned clean

This approach does not modify any code pages, making it invisible to memory integrity checks.

#### Memory Patch AMSI (`amsi_defense.rs` — Memory mode)

Directly patches `amsiInitFailed` in the `amsi.dll` `.data` section:

1. Resolve `amsi.dll` base via PEB walking
2. Find the `AmsiInitialize` function export
3. Locate the `amsiInitFailed` flag variable in `.data`
4. Use `NtProtectVirtualMemory` (via syscall) to make the page writable
5. Patch the flag to non-zero (forcing initialization failure)
6. All subsequent AMSI scans return `AMSI_RESULT_CLEAN`

Fallback: If patching fails, the agent falls back to returning `E_INVALIDARG` from `AmsiScanBuffer` by patching the function's prologue.

### ETW Patching (`etw_patch.rs`)

Patches ETW functions to suppress event telemetry:

1. Resolve `ntdll.dll` base via PEB walking
2. Find `EtwEventWrite`, `EtwEventWriteEx`, and `NtTraceEvent` exports
3. Use `NtProtectVirtualMemory` syscall to make the code page writable
4. Patch the first bytes of each function to:
   ```asm
   mov eax, 0x00000000  ; STATUS_SUCCESS
   ret
   ```
5. `NtProtectVirtualMemory` to restore original protection

Three patch modes:
- **Safe** — Patch only if no EDR hooks detected on the target functions
- **Always** — Unconditionally patch
- **Never** — Skip ETW patching entirely

---

## C2 State Machine

### HTTP Transport (`c2_http.rs`)

The HTTP transport implements a full malleable C2 state machine:

```
┌──────────────────────────────────────────────────┐
│                 HttpTransport                     │
│                                                  │
│  Fields:                                         │
│  - client: reqwest::Client                       │
│  - session: CryptoSession                        │
│  - agent_id: String                              │
│  - profile: AgentMalleableProfile                │
│  - redirectors: Vec<RedirectorConfig>            │
│  - failover: FailoverState                       │
│  - front_domain: Option<String>                  │
│  - current_sticky: usize (sticky counter)        │
│  - backoff_secs: f64                             │
│  - endpoint_index: usize                         │
└──────────────────────────────────────────────────┘
```

### Request Lifecycle

1. **Select URI** — Randomly pick from `profile.http_get.uri` (beacon) or `profile.http_post.uri` (task result)
2. **Apply transforms** — Prepend, encode (Base64/Mask/NetBIOS), append to data
3. **Set headers** — User-Agent from profile, custom headers
4. **Deliver payload** — Cookie, URI-append, header, or body delivery based on profile
5. **Domain fronting** (if configured) — Connect to front domain IP, send actual Host header
6. **Redirector failover** — On failure, advance to next redirector with exponential backoff

### FailoverState Management

```rust
pub struct FailoverState {
    pub current_index: usize,
    pub sticky_count: usize,
    pub max_sticky: usize,       // Default: 10
    pub backoff_secs: f64,
    pub max_backoff: f64,        // Default: 60.0
    pub full_cycle: bool,
}
```

- **Sticky session**: After a successful request, keep using the same endpoint for `max_sticky` requests
- **Exponential backoff**: On failure, `backoff_secs *= 2.0` up to `max_backoff`
- **Full cycle**: After exhausting all redirectors, fall back to direct C2
- **Recovery**: After direct C2 succeeds, reset and try redirectors again

### DNS-over-HTTPS Transport (`c2_doh.rs`)

The DoH transport encodes C2 data in DNS queries:

1. **Beacon** — Agent sends periodic A-record queries to `beacon_pattern.data.dns_suffix`
2. **Task retrieval** — Server responds with encoded task data in A or TXT records
3. **Data exfiltration** — Agent sends TXT queries with encoded result data
4. **Encoding** — hex, base32, or base64url depending on profile setting
5. **Resolver** — All queries go through `https://dns.google/dns-query` (configurable)

### SSH Transport (`c2_ssh.rs`)

Tunnels C2 traffic through SSH subsystem connections:

1. Connect to SSH server using key, password, or agent authentication
2. Request a subsystem (`IOC_SSH_SUBSYSTEM` — randomized per build)
3. Use the subsystem channel as a `Transport` (bincode frames)
4. Session keepalive via SSH keepalive messages

### SMB Transport (`c2_smb.rs`)

Uses Windows named pipes or TCP relay:

1. Connect to `\\.\pipe\IOC_PIPE_NAME` (randomized per build)
2. Or connect to a TCP relay on the configured port
3. Use the pipe/socket as a `Transport` (bincode frames)
4. Supports both inbound (server creates pipe) and outbound (agent connects) modes

---

## Wire Protocol

### Frame Format

Every frame on the wire follows this format:

```
┌──────────────┬──────────────────────────────────────────┐
│ u32 LE (4 B) │ Encrypted payload                        │
│ length       │                                          │
└──────────────┴──────────────────────────────────────────┘
```

Inside the encrypted payload (protocol v2):

```
┌────────────┬──────────────┬─────────────────────────────┐
│ salt (32B) │ nonce (12B)  │ ciphertext + GCM tag (16B)  │
└────────────┴──────────────┴─────────────────────────────┘
```

- **Salt**: 32 random bytes per message, used for HKDF key derivation
- **Nonce**: 12 random bytes per message
- **Key derivation**: `HKDF-SHA256(salt, psk, info=b"orchestra-v2")` → 32-byte per-message key
- **Ciphertext**: bincode-serialized `Message`, encrypted with AES-256-GCM

### Message Variants

| Variant | Direction | Purpose |
|---------|-----------|---------|
| `VersionHandshake` | bidirectional | Protocol version negotiation (current: v2) |
| `Heartbeat` | agent → server | Liveness + status report |
| `TaskRequest` | server → agent | Execute a `Command` under a `task_id` |
| `TaskResponse` | agent → server | Return result keyed by `task_id` |
| `ModulePush` | server → agent | Deliver encrypted, signed plugin |
| `ModuleRequest` | agent → server | Request a specific module by name |
| `ModuleResponse` | server → agent | Module data response |
| `AuditLog` | agent → server | Audit event for compliance logging |
| `MorphResult` | agent → server | Self-reencode completion notification |
| `P2pForward` | agent → agent | P2P mesh data forwarding |
| `P2pToChild` | parent → child | P2P mesh child-directed message |
| `P2pTopologyReport` | agent → server | P2P mesh topology update |
| `Shutdown` | bidirectional | Graceful session termination |

### CryptoSession API

```rust
impl CryptoSession {
    pub fn from_shared_secret(key: &[u8]) -> Self;
    pub fn from_shared_secret_with_salt(key: &[u8], salt: &[u8]) -> Self;
    pub fn from_key(key: [u8; 32], salt: [u8; 32]) -> Self;
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8>;
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError>;
    pub fn decrypt_with_psk(psk: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError>;
}
```

### Forward Secrecy

When the `forward-secrecy` feature is enabled:

1. Both sides generate X25519 ephemeral keypairs
2. Exchange public keys over the encrypted channel
3. Compute shared secret: `X25519(my_secret, peer_public)`
4. Derive session key: `HKDF-SHA256(shared_secret, SHA256(PSK), "orchestra-fs-v1")`
5. All subsequent frames use the derived session key

Key ordering uses canonical comparison to ensure both sides derive the same key regardless of role.

---

## Server Internals

### Orchestra Server (`orchestra-server`)

Built on `axum` 0.7 with `tokio` async runtime:

| Module | Responsibility |
|--------|---------------|
| `api.rs` | REST API routes (dashboard, build queue, agent management) |
| `state.rs` | `AppState` with `DashMap` for agents, modules, redirectors |
| `config.rs` | Server configuration parsing |
| `malleable.rs` | `MultiProfileManager` — loads, validates, hot-reloads profiles |
| `http_c2.rs` | HTTP C2 listener with malleable profile handling |
| `doh_listener.rs` | DNS-over-HTTPS C2 listener |
| `redirector.rs` | Redirector registration and health monitoring |
| `build_handler.rs` | On-demand agent compilation |
| `agent_link.rs` | Agent session management |
| `audit.rs` | JSONL audit log with HMAC-SHA256 tamper evidence |
| `auth.rs` | Bearer token operator authentication |
| `tls.rs` | TLS configuration and certificate management |
| `smb_relay.rs` | SMB named pipe relay for P2P agent chains |

### Multi-Profile Manager

```rust
pub struct MultiProfileManager {
    profiles: DashMap<String, MalleableProfile>,
    watch_dir: PathBuf,
}
```

- Watches the `profiles/` directory for changes
- Validates profiles before loading
- Supports simultaneous serving of multiple profiles on different ports or via SNI routing
- Hot-reloads without server restart

---

## P2P Mesh Protocol

### Frame Format

```
┌──────────────┬─────────────┬───────────────┬─────────────────┐
│ type (1B)    │ link_id (4B)│ payload_len   │ payload         │
│ P2pFrameType │             │ (4B)          │ (payload_len B) │
└──────────────┴─────────────┴───────────────┴─────────────────┘
```

### Frame Types

| Type | Code | Purpose |
|------|------|---------|
| `LinkRequest` | `0x30` | Initiate a new P2P link |
| `LinkAccept` | `0x31` | Accept link request |
| `LinkReject` | `0x32` | Reject link request (includes reason) |
| `Heartbeat` | `0x33` | Keep-alive + latency measurement |
| `Disconnect` | `0x34` | Graceful link teardown |
| `DataForward` | `0x35` | Relay data toward C2 |
| `CertificateRevocation` | `0x36` | Revoke a mesh certificate |
| `QuarantineReport` | `0x37` | Report quarantined agent |
| `KeyRotation` | `0x38` | Start per-link key rotation |
| `KeyRotationAck` | `0x39` | Acknowledge key rotation |
| `RouteUpdate` | `0x3A` | Distance-vector route advertisement |
| `RouteProbe` | `0x3B` | Measure link latency/hops |
| `RouteProbeReply` | `0x3C` | Reply to route probe |
| `DataAck` | `0x3D` | Acknowledge data receipt |
| `TopologyReport` | `0x3E` | Report mesh topology to server |
| `BandwidthProbe` | `0x3F` | Measure available bandwidth |

### Topology Modes

```
Tree Mode:                  Mesh Mode:                  Hybrid Mode:
                            (all agents peers)          (tree + peer shortcuts)

     Server                      Server                      Server
       │                           │                           │
    Parent                      Agent A                    Parent
    ┌──┼──┐                   ◄──► B ◄──► C               ┌──┼──┐
    A  B  C                   ◄──► D ◄──► E               A  B  C
    (no lateral)               (full mesh)                     ◄──►
                                                             (peer link)
```

- **Tree**: Strict hierarchy — all traffic through parents. Maximum OPSEC.
- **Mesh**: Full peer-to-peer with route discovery. Maximum resilience.
- **Hybrid** (default): Tree backbone with optional peer links.

### Certificate Lifecycle

```
┌───────────┐      ┌──────────────┐      ┌───────────────┐
│  Server   │─────►│   Agent A    │      │   Agent B     │
│  issues   │      │  (presented  │─────►│   (verifies   │
│  MeshCert │      │   to peers)  │      │   signature)  │
└───────────┘      └──────┬───────┘      └───────────────┘
                          │                       │
                   ┌──────▼───────┐        ┌──────▼──────┐
                   │  Renewal     │        │ Revocation  │
                   │  (2h before  │        │ (propagates │
                   │   expiry)    │        │  via mesh)  │
                   └──────────────┘        └─────────────┘
```

- Certificates are signed with the server's Ed25519 `module_signing_key`.
- Lifetime: 24 hours. Renewal window: 2 hours before expiry.
- Revocation propagates through `CertificateRevocation` frames.
- All agents terminate links to revoked peers immediately.

### Key Rotation Timeline

```
Time: 0h          4h          4h+δ         4h+δ+30s
      │            │            │             │
      ├─ normal ──►│ rotation   │ new key     │ old key
      │  traffic   │ starts     │ active      │ discarded
      │            │            │             │
      │            │◄─ overlap ─►│             │
      │            │  (30s)     │             │
      │            │            │             │
      │  OLD key   │ OLD key    │ NEW key     │ NEW key
      │  only      │ + NEW key  │ + OLD key   │ only
```

- Rotation interval: 4 hours per link.
- Overlap period: 30 seconds (both keys accepted).
- Timeout: 60 seconds for `KeyRotationAck`, then retry.
- Max retries: 3 before giving up on rotation.

### Routing

- **Protocol**: Distributed distance-vector (Bellman-Ford).
- **Update interval**: 60 seconds (`RouteUpdate` frames).
- **Quality metric**: Composite of latency (40%), packet loss (40%), jitter (20%).
- **Relay selection**: 70% route quality + 30% inverse hop count.
- **Stale timeout**: Routes expire after 300 seconds without update.

---

## Cryptographic Summary

| Primitive | Usage | Key Size |
|-----------|-------|----------|
| AES-256-GCM | Wire encryption (all transports) | 256-bit |
| ChaCha20-Poly1305 | P2P per-link encryption | 256-bit |
| HKDF-SHA256 | Per-message key derivation, P2P link key derivation | 256-bit |
| X25519 | Forward secrecy ECDH, P2P link handshake & key rotation | 256-bit |
| Ed25519 | Module signing/verification, mesh certificate signing | 256-bit |
| XChaCha20-Poly1305 | Sleep obfuscation memory encryption | 256-bit |
| HMAC-SHA256 | Audit log integrity, config HMAC | 256-bit |
| SHA-256 | Certificate fingerprinting, agent identity hashing, integrity checks | 256-bit |

---

## Module Loading Pipeline

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│ Encrypted    │────►│ Decrypt      │────►│ Verify       │────►│ Load         │
│ Module Blob  │     │ AES-256-GCM  │     │ Ed25519      │     │ Platform-    │
└──────────────┘     └──────────────┘     └──────────────┘     │ specific     │
                                                                └──────┬───────┘
                                                                       │
                                                          ┌────────────▼───────────┐
                                                          │ Linux: memfd_create +  │
                                                          │   libloading           │
                                                          ├────────────────────────┤
                                                          │ Windows: manual_map or │
                                                          │   temp file            │
                                                          └────────────────────────┘
```

### Plugin Interface

```rust
#[repr(C)]
pub struct PluginObject {
    pub vtable: *const PluginVTable,
}

pub struct PluginVTable {
    pub init: extern "C" fn(*mut PluginObject),
    pub execute: extern "C" fn(*mut PluginObject, *const c_char) -> *const c_char,
    pub free_result: extern "C" fn(*const c_char),
    pub destroy: extern "C" fn(*mut PluginObject),
}

pub trait Plugin: Send + Sync {
    fn init(&self);
    fn execute(&self, args: &str) -> String;
    fn execute_binary(&self, input: &[u8]) -> Vec<u8>;
    fn get_metadata(&self) -> PluginMetadata;
}
```

---

## Persistence Subsystem

The `persistence` module implements platform-specific persistence mechanisms:

| Platform | Method | Details |
|----------|--------|---------|
| Windows | Registry Run | Writes to `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` with configurable key name |
| Windows | COM Hijack | Replaces InProcServer32 for a GUID with agent path |
| Windows | WMI Subscription | Creates `__EventFilter` + `CommandLineEventConsumer` binding via COM |
| Linux | LaunchAgent (macOS) | Writes `.plist` to `~/Library/LaunchAgents/` |
| Linux | cron | Adds `@reboot` entry to user crontab |
| Linux | systemd | Creates user service unit in `~/.config/systemd/user/` |
| Linux | shell profile | Appends execution to `.bashrc` / `.zshrc` |

All persistence methods are gated behind the `persistence` feature flag and require an explicit `EnablePersistence` command.

---

## Binary Diversification Stack

Multiple layers ensure no two builds produce identical binaries:

| Layer | Crate | Mechanism |
|-------|-------|-----------|
| **Junk Code** | `junk_macro` | Attribute proc-macro inserts dead stores and calculations at function boundaries |
| **Instruction Scheduling** | `optimizer` | Reorders independent instructions for different execution orderings |
| **NOP Insertion** | `optimizer` | Inserts random NOP sleds (1–5 bytes) between instructions |
| **Instruction Substitution** | `optimizer` | Replaces instructions with equivalent forms (e.g., `xor rax, rax` → `mov rax, 0`) |
| **Opaque Predicates** | `code_transform` | Inserts always-true/false conditional branches that confuse disassemblers |
| **Block Reordering** | `code_transform` | Randomizes basic block order within functions |
| **Register Reallocation** | `code_transform` | Remaps registers to different physical registers |
| **String Encryption** | `string_crypt` | Compile-time XOR encryption of all string literals |
| **Self-Reencode** | `agent` (runtime) | Periodically re-encodes `.text` section with a fresh seed |
| **Per-Build IoCs** | `agent/build.rs` | Randomizes pipe names, DNS prefixes, service names, and other strings |
| **PE Hardening** | `builder` | Randomizes timestamps, section names, DOS stubs, Rich header removal |

---

## Cross-Platform Notes

Platform-specific code is gated with `#[cfg(target_os = "...")]` and feature flags:

```rust
#[cfg(target_os = "windows")]
mod injection;      // Full injection engine

#[cfg(target_os = "linux")]
mod injection;      // memfd_create-based injection only

#[cfg(target_os = "windows")]
mod evasion;        // AMSI, ETW patching

#[cfg(feature = "direct-syscalls")]
mod nt_syscall;     // SSN resolution, Halo's Gate
```

The workspace compiles cleanly on all three platforms via `cargo check --workspace`:
- **Linux**: Full agent features, all tests pass
- **Windows**: Full agent features, injection, evasion, syscalls
- **macOS**: Core features, persistence, remote-assist

---

## See Also

- [MALLEABLE_PROFILES.md](MALLEABLE_PROFILES.md) — Exhaustive TOML profile reference
- [INJECTION_ENGINE.md](INJECTION_ENGINE.md) — Injection techniques deep-dive
- [SLEEP_OBFUSCATION.md](SLEEP_OBFUSCATION.md) — Sleep obfuscation pipeline
- [REDIRECTOR_GUIDE.md](REDIRECTOR_GUIDE.md) — Redirector deployment guide
- [OPERATOR_MANUAL.md](OPERATOR_MANUAL.md) — Operator manual
- [FEATURES.md](FEATURES.md) — Feature flag reference
- [SECURITY.md](SECURITY.md) — Threat model and hardening
