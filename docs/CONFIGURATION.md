# Configuration Reference

Complete TOML configuration reference for Orchestra agent, server, and malleable profiles.

---

## Agent Feature Flags

Agent capabilities are controlled via Cargo feature flags at compile time. Features are organized by category:

### Transport Features

| Feature | Description | Dependencies |
|---------|-------------|--------------|
| `http-transport` | HTTP/HTTPS C2 transport | `reqwest` |
| `smb-transport` | Named pipe C2 transport (SMB) | Windows API |
| `dns-transport` | DNS C2 transport | `trust-dns-client` |
| `doh-transport` | DNS-over-HTTPS C2 transport | `reqwest` |
| `outbound-c` | Outbound connection support | — |

### Stealth Features

| Feature | Description | Dependencies |
|---------|-------------|--------------|
| `direct-syscalls` | Direct syscall dispatch (bypass ntdll hooks) | `nt_syscall` |
| `syscall-emulation` | Route Nt* calls through kernel32/advapi32 | — |
| `stack-spoof` | NtContinue-based call stack spoofing | Windows API |
| `cet-bypass` | CET/shadow-stack bypass (3 strategies) | — |
| `sleep-obfuscation` | Full memory encryption during sleep (Ekko + Cronus) | `aes-gcm`, `chacha20poly1305` |
| `memory-guard` | XChaCha20-Poly1305 memory region encryption | `chacha20poly1305` |
| `evanesco` | Continuous memory hiding (per-page encryption + NOACCESS) | — |
| `evade-edr-transform` | Runtime .text signature scanning + code transformation | — |
| `write-raid-amsi` | AMSI write-raid race bypass | — |
| `forensic-cleanup` | Prefetch/MFT/USN evidence removal | — |
| `self-reencode` | Per-build unique .text section encoding | `code_transform_macro` |

### Capability Features

| Feature | Description | Dependencies |
|---------|-------------|--------------|
| `token-impersonation` | Thread-level token impersonation (encrypted cache) | Windows API |
| `browser-data` | Browser credential extraction (Chrome, Edge, Firefox) | Windows DPAPI |
| `lsass-harvest` | LSASS credential harvesting (indirect syscalls) | `direct-syscalls` |
| `persistence` | Cross-platform persistence mechanisms | — |
| `network-discovery` | Network enumeration and discovery | — |
| `remote-assist` | Remote desktop/assistance capabilities | — |
| `hci-research` | Human-computer interaction research | — |
| `evdev` | Linux evdev input device access | Linux |
| `surveillance` | Screenshot, keylogger, clipboard capture | Platform-specific |
| `interactive-shell` | Interactive shell sessions (cmd/sh/zsh) | — |

### Build Features

| Feature | Description | Dependencies |
|---------|-------------|--------------|
| `static-build` | Fully static linking (no runtime deps) | `musl` or `mingw-static` |
| `optimize-size` | Optimize for binary size (`opt-level = 'z'`) | — |
| `debug-build` | Include debug symbols and logging | — |

### Recommended Feature Combinations

#### Stealth-Focused Windows Agent
```toml
features = [
    "http-transport",
    "outbound-c",
    "direct-syscalls",
    "syscall-emulation",
    "stack-spoof",
    "cet-bypass",
    "sleep-obfuscation",
    "memory-guard",
    "evanesco",
    "evade-edr-transform",
    "write-raid-amsi",
    "forensic-cleanup",
    "token-impersonation",
    "self-reencode",
]
```

#### Speed-Focused Windows Agent
```toml
features = [
    "http-transport",
    "outbound-c",
    "direct-syscalls",
    "stack-spoof",
    "sleep-obfuscation",
    "memory-guard",
    "token-impersonation",
    "browser-data",
    "interactive-shell",
]
```

#### Balanced Windows Agent
```toml
features = [
    "http-transport",
    "outbound-c",
    "direct-syscalls",
    "stack-spoof",
    "cet-bypass",
    "sleep-obfuscation",
    "memory-guard",
    "write-raid-amsi",
    "token-impersonation",
    "browser-data",
    "lsass-harvest",
    "interactive-shell",
    "forensic-cleanup",
]
```

#### Linux Agent
```toml
features = [
    "http-transport",
    "outbound-c",
    "interactive-shell",
]
```

---

## Server Configuration (`orchestra-server.toml`)

The server configuration is a **flat TOML file** (no subsections). All paths
are relative to the working directory from which the server is launched.

### Complete Field Reference

| Field | Type | Default | Required | Description |
|-------|------|---------|----------|-------------|
| `http_addr` | string | `"0.0.0.0:8443"` | No | Operator HTTPS listener |
| `agent_addr` | string | `"0.0.0.0:8444"` | No | Agent listener |
| `agent_shared_secret` | string | — | **Yes** | Base64 PSK for agent authentication |
| `admin_token` | string | — | **Yes** | Bearer token for operator API |
| `tls_cert_path` | path | — | **Yes** | TLS certificate PEM |
| `tls_key_path` | path | — | **Yes** | TLS private key PEM |
| `static_dir` | path | `"orchestra-server/static"` | No | Static files for web dashboard |
| `audit_log_path` | path | `"orchestra-audit.jsonl"` | No | Path for JSONL audit log |
| `command_timeout_secs` | u64 | `30` | No | Max wait for agent command response |
| `builds_output_dir` | path | `"builds"` | No | Output dir for built agent payloads |
| `module_aes_key` | string | — | **Yes*** | Base64 AES-256 key baked into agents |
| `allow_local_builds` | bool | `false` | No | Allow loopback/private IP in build |

> \* `module_aes_key` is required for production agent builds. If omitted, the
> server will still start but build jobs will produce agents that fail at runtime.

### Example Configuration

```toml
# orchestra-server.toml

# Network
http_addr            = "0.0.0.0:8443"
agent_addr           = "0.0.0.0:8444"

# Authentication
agent_shared_secret  = "RvDPwz+Xl7WuOkRnE3mIJjDy9B9oDyMvUg8fYSZ2EFg="
admin_token          = "0juoV2FGURAA8lUJ8HzALnXHOKE_yvdg"

# TLS
tls_cert_path        = "secrets/server.crt"
tls_key_path         = "secrets/server.key"

# Paths
audit_log_path       = "secrets/orchestra-audit.jsonl"
static_dir           = "orchestra-server/static"
builds_output_dir    = "builds"

# Crypto
module_aes_key       = "af1FhprLnRzj8ZZyJmmNBaTQabNS8jGt4nbNCbzrKjw="

# Timing
command_timeout_secs = 30

# Development only — allow building agents with loopback target:
# allow_local_builds = true
```

### Generating Credentials

```bash
# Generate 32-byte base64 secrets
python3 -c "import os,base64; print(base64.b64encode(os.urandom(32)).decode())"

# Or use the keygen utility
cargo run -p keygen

# Generate TLS certificate and key
./scripts/generate-certs.sh
```

### Build Request API Fields

When submitting a build via `POST /api/build`:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `os` | string | Yes | Target OS: `"linux"`, `"windows"`, `"macos"` |
| `arch` | string | Yes | Target arch: `"x86_64"`, `"aarch64"` |
| `host` | string | Yes | C2 host that the agent will connect to |
| `port` | u16 | Yes | C2 port |
| `pin` | string | Yes | 64-hex SHA-256 TLS fingerprint |
| `key` | string | Yes | Base64 AES-256 payload encryption key |
| `features` | object | No | `BuildFeatures` flags (see below) |
| `format` | string | No | Output format: `"elf"`, `"pe"`, `"dylib"` |
| `transport` | string | No | Primary transport: `"tls"`, `"http"`, `"doh"` |
| `sleep_ms` | u64 | No | Base sleep interval (ms) |
| `jitter` | u8 | No | Jitter percentage (0–100) |
| `kill_date` | string | No | ISO 8601 kill date (agent exits after) |
| `version_info` | object | No | PE version info (`file_version`, `product_name`, etc.) |
| `manifest_preset` | string | No | PE manifest preset name |

### BuildFeatures Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `persistence` | bool | `false` | Cross-platform persistence |
| `direct_syscalls` | bool | `false` | Direct/indirect syscall infrastructure |
| `remote_assist` | bool | `false` | Screen capture, input simulation |
| `stealth` | bool | `false` | Full stealth suite (memory guard, AMSI bypass, ETW patch) |
| `network_discovery` | bool | `false` | ARP scan, ping sweep, port scan, reverse DNS |
| `forensic_cleanup` | bool | `false` | Prefetch/MFT/USN evidence removal |
| `self_reencode` | bool | `false` | Runtime metamorphic re-encoding |
| `http_transport` | bool | `false` | HTTP/S malleable C2 transport |
| `doh_transport` | bool | `false` | DNS-over-HTTPS C2 transport |
| `ssh_transport` | bool | `false` | SSH subsystem C2 transport |
| `smb_pipe_transport` | bool | `false` | SMB named pipe C2 transport |
| `evasion_transform` | bool | `false` | Runtime EDR signature scanning + transformation |
| `p2p` | bool | `false` | P2P mesh networking |
| `stack_spoof` | bool | `false` | NtContinue-based call stack spoofing |



---

## Malleable C2 Profiles

Profiles are TOML files in the `profiles/` directory. See the main README for the full TOML schema.

### Stealth-Focused Profile

```toml
[profile]
name = "stealth-cloudfront"
author = "operator"
description = "Cloudfront-fronted stealth profile"

[global]
user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
jitter = 37
sleep_time = 45
dns_idle = "0.0.0.0"
dns_sleep = 0

[ssl]
enabled = true
cert_pin = ""
ja3_fingerprint = ""
sni = "d1k2s3c4.cloudfront.net"

[http_get]
uri = ["/api/v1/feed", "/api/v1/notifications", "/api/v2/timeline"]
verb = "GET"

[http_get.client]
prepend = ""
append = ""
transform = "Base64"

[http_get.metadata]
delivery = "Cookie"
key = "__cf_bm"
transform = "Base64"

[http_post]
uri = ["/api/v1/upload", "/api/v2/media", "/api/v1/attachments"]
verb = "POST"

[http_post.client]
prepend = ""
append = ""
transform = "Base64"

[http_post.output]
delivery = "Body"
key = ""
transform = "Base64"
```

### Speed-Focused Profile

```toml
[profile]
name = "speed-internal"
author = "operator"
description = "Internal network speed profile"

[global]
user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
jitter = 10
sleep_time = 5
dns_idle = "0.0.0.0"
dns_sleep = 0

[ssl]
enabled = true
cert_pin = ""
ja3_fingerprint = ""
sni = ""

[http_get]
uri = ["/status", "/health", "/ping"]
verb = "GET"

[http_get.client]
prepend = ""
append = ""
transform = "None"

[http_get.metadata]
delivery = "Header"
key = "X-Request-Id"
transform = "Base64"

[http_post]
uri = ["/submit", "/data", "/update"]
verb = "POST"

[http_post.client]
prepend = ""
append = ""
transform = "None"

[http_post.output]
delivery = "Body"
key = ""
transform = "None"
```

### DNS-Only Profile

```toml
[profile]
name = "dns-covert"
author = "operator"
description = "DNS-only C2 profile"

[global]
user_agent = ""
jitter = 20
sleep_time = 30

[dns]
enabled = true
beacon = "cdn.{suffix}"
get_A = "api.{suffix}"
get_TXT = "txt.{suffix}"
post = "exfil.{suffix}"
max_txt_size = 252
dns_suffix = "example.com"
encoding = "base64url"

[dns.headers]
doh_server = "https://dns.google/dns-query"
doh_method = "POST"
```

---

## Redirector Configuration

### Command-Line Options

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--listen-addr` | string | `0.0.0.0:443` | Listener address |
| `--c2-addr` | string | (required) | Upstream C2 server address |
| `--profile` | path | (required) | Malleable profile for URI matching |
| `--cover-content` | path | `""` | Directory with cover content |
| `--tls-cert` | path | (required) | TLS certificate |
| `--tls-key` | path | (required) | TLS private key |
| `--server-api` | string | `""` | Orchestra server API URL |
| `--server-token` | string | `""` | Server authentication token |

---

## Agent Runtime Configuration

Runtime configuration is compiled into the agent at build time via the builder API or CLI. Key parameters:

### Sleep Configuration

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `sleep_time` | u64 | From profile | Base sleep interval (seconds) |
| `jitter` | u8 | From profile | Random jitter percentage (0–100) |
| `sleep_technique` | string | `"ekko"` | Sleep technique: `ekko`, `cronus`, `thread` |

### Injection Configuration

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `default_technique` | string | `"auto"` | Default injection technique or `"auto"` for auto-selection |
| `spawnto` | string | `"C:\\Windows\\System32\\svchost.exe"` | Sacrificial process for injection |
| `ppid_spoof` | bool | `false` | Spoof parent process ID |

### Evasion Configuration

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `amsi_method` | string | `"hwbp"` | AMSI bypass: `hwbp`, `patch`, `write-raid` |
| `etw_patch` | bool | `true` | Patch ETW event providers |
| `unhook_ntdll` | bool | `true` | Unhook ntdll from KnownDlls |
| `syscall_strategy` | string | `"auto"` | Syscall strategy: `auto`, `direct`, `emulate`, `standard` |
| `spoof_stack` | bool | `true` | Enable call stack spoofing |
| `cet_strategy` | string | `"auto"` | CET bypass strategy: `auto`, `disable`, `compatible`, `veh` |
| `edr_transform` | bool | `false` | Enable runtime EDR signature transformation |
| `evanesco` | bool | `false` | Enable continuous memory hiding |

### Forensics Configuration

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `cleanup_prefetch` | bool | `true` | Remove prefetch evidence on execution |
| `cleanup_usn` | bool | `true` | Clean USN journal entries |
| `cleanup_timestamps` | bool | `true` | Synchronize MFT timestamps |
| `disable_prefetch_service` | bool | `false` | Disable Prefetch service (requires Admin) |

### Impersonation Configuration

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `cache_tokens` | bool | `true` | Cache stolen tokens (encrypted) |
| `auto_revert` | bool | `true` | Auto-revert token after each command |
| `max_cached_tokens` | usize | `10` | Maximum cached tokens |

---

## Environment Variables

### Build-Time Environment Variables (Agent Build Pipeline)

These are set by the builder and forwarded by `agent/build.rs` as compile-time constants:

| Variable | Rust constant | Description |
|----------|---------------|-------------|
| `ORCHESTRA_C_ADDR` | `SYS_C_ADDR` | C2 host:port baked into agent |
| `ORCHESTRA_C_SECRET` | `SYS_C_SECRET` | PSK baked into agent (= server `agent_shared_secret`) |
| `ORCHESTRA_C_CERT_FP` | `SYS_C_CERT_FP` | TLS fingerprint baked into agent |
| `ORCHESTRA_MODULE_AES_KEY` | `SYS_MODULE_KEY` | Module AES-256 key baked into agent |

All four are forwarded via `agent/build.rs`:
```rust
println!("cargo:rustc-env=SYS_C_ADDR={}", addr);
println!("cargo:rustc-env=SYS_C_SECRET={}", secret);
println!("cargo:rustc-env=SYS_C_CERT_FP={}", fp);
println!("cargo:rustc-env=SYS_MODULE_KEY={}", module_key);
```

And read in `agent/src/lib.rs` / `agent/src/outbound.rs` via `option_env!("SYS_*")`.

### Server Secrets (`secrets/default.env`)

| Variable | Description |
|----------|-------------|
| `ADMIN_TOKEN` | Server admin authentication token |
| `SIGNING_KEY` | Ed25519 module signing key |

> **Note**: The server config file (`orchestra-server.toml`) is the primary source
> of credentials. Environment variables are for CI/CD pipelines that need to
> override specific values without modifying the file.

