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

### `[server]` — Core Server Settings

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `bind_addr` | string | `"0.0.0.0"` | Server bind address |
| `port` | u16 | `8443` | HTTPS listener port |
| `admin_token` | string | (required) | Admin authentication token |
| `operator_token` | string | (required) | Operator authentication token |
| `log_level` | string | `"info"` | Log level: `trace`, `debug`, `info`, `warn`, `error` |
| `database_path` | string | `"orchestra.db"` | SQLite database path |
| `audit_log` | string | `"orchestra-audit.jsonl"` | Audit log file path |

### `[tls]` — TLS Configuration

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `cert_path` | string | (required) | TLS certificate path |
| `key_path` | string | (required) | TLS private key path |
| `min_version` | string | `"1.2"` | Minimum TLS version |

### `[builder]` — Build Server Settings

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `target` | string | `"x86_64-pc-windows-gnu"` | Default build target |
| `profile_dir` | string | `"profiles/"` | Malleable profile directory |
| `output_dir` | string | `"builds/"` | Build output directory |
| `signing_key` | string | `""` | Ed25519 signing key (hex) |

### `[modules]` — Module Delivery

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `module_dir` | string | `"modules/"` | Module storage directory |
| `max_module_size` | u64 | `10485760` | Maximum module size (10 MB) |
| `verify_signatures` | bool | `true` | Verify module signatures |

### `[crypto]` — Cryptographic Settings

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `session_key_rotation` | u64 | `3600` | Session key rotation interval (seconds) |
| `forward_secrecy` | bool | `false` | Enable X25519 ECDH forward secrecy |

### `[rate_limit]` — Rate Limiting

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_connections` | usize | `1000` | Maximum concurrent connections |
| `requests_per_second` | u32 | `100` | Requests per second per agent |
| `burst_size` | u32 | `50` | Burst allowance |

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

### Build-Time Variables

| Variable | Description |
|----------|-------------|
| `ORCHESTRA_BUILD_ID` | Unique build identifier (injected by builder) |
| `ORCHESTRA_PROFILE` | Profile name embedded in agent binary |
| `ORCHESTRA_C2_HOST` | C2 hostname/IP embedded in agent |
| `ORCHESTRA_C2_PORT` | C2 port embedded in agent |
| `ORCHESTRA_SIGNING_KEY` | Ed25519 key for module verification |

### Server Secrets (`secrets/default.env`)

| Variable | Description |
|----------|-------------|
| `ADMIN_TOKEN` | Server admin authentication token |
| `OPERATOR_TOKEN` | Operator authentication token |
| `SIGNING_KEY` | Ed25519 module signing key |
| `DATABASE_KEY` | SQLite database encryption key |

> **Note**: The server refuses to start without explicit credentials. No default credentials are provided.
