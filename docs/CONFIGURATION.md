# Configuration Reference

Complete TOML configuration reference for Orchestra agent, server, and malleable profiles.

---

## Agent Feature Flags

Agent capabilities are controlled via Cargo feature flags at compile time. The
authoritative manifest is `agent/Cargo.toml`; this section mirrors the current
feature names used by the builder and server.

### Transport Features

| Feature | Description | Dependencies / Notes |
|---------|-------------|----------------------|
| `outbound-c` | Standalone agent dials the Control Center using baked C2 address and PSK | — |
| `http-transport` | HTTP/S malleable-profile transport | `reqwest` |
| `doh-transport` | DNS-over-HTTPS C2 transport | `reqwest` |
| `ssh-transport` | SSH subsystem/channel C2 transport | `russh`, `russh-keys` |
| `smb-pipe-transport` | SMB named-pipe transport, with `tcp_relay` mode for relays | Windows named pipe path; TCP relay mode is cross-platform at the relay edge |
| `p2p-tcp` | Peer-to-peer TCP mesh networking | — |
| `forward-secrecy` | X25519 + HKDF session key agreement | `common/forward-secrecy` |
> **⚠️ Experimental — HTTP/DoH forward secrecy:** The `forward-secrecy`
> feature provides proven X25519 ECDH for persistent streams (TLS, SSH,
> SMB).  Forward secrecy over HTTP and DoH transports — where the ECDH
> handshake is carried via `X-ECDH-Pub` headers (HTTP) or DNS TXT
> record labels (DoH) — is **experimental** and has not been validated
> against all malleable-profile transforms.  Use in production at your
> own risk; the static PSK fallback remains available for these
> transports.| `traffic-normalization` | Wire-level traffic shaping profiles | `common::normalized_transport` |

### Stealth and Evasion Features

| Feature | Description | Dependencies / Notes |
|---------|-------------|----------------------|
| `direct-syscalls` | Dynamic NT syscall infrastructure and indirect dispatch | — |
| `syscall-emulation` | User-mode kernel32/advapi32 fallbacks for configured Nt* operations | Implies `direct-syscalls` |
| `stack-spoof` | NtContinue-based call stack spoofing | Implies `direct-syscalls`; Windows x86_64 |
| `trampoline-spoof` | Multi-frame trampoline stack spoofing | Implies `direct-syscalls`; Windows x86_64 |
| `cfg-bypass` | Control Flow Guard bypass helpers | Implies `direct-syscalls`; Windows x86_64 |
| `cet-bypass` | CET/shadow-stack bypass support | Implies `direct-syscalls`; Windows |
| `seh-anti-debug` | SEH/VEH anti-debugging strategies | Windows |
| `page-fault-exec` | PAGE_NOACCESS/page-fault driven execution | Windows x86_64 |
| `memory-guard` | XChaCha20/AES-GCM/ChaCha20 encryption for sensitive regions while idle | `chacha20poly1305`, `aes-gcm` |
| `thread-ctx-encrypt` | Thread CONTEXT, stack pointer, and TLS encryption during sleep | Windows |
| `evanesco` | Continuous memory hiding with encrypted/PAGE_NOACCESS pages | Windows |
| `evasion-transform` | Runtime `.text` signature scanning and transformation | Implies `self-reencode` |
| `self-reencode` | Periodic metamorphic `.text` re-encoding | `code_transform`, `goblin` |
| `write-raid-amsi` | AMSI data-only write-raid race bypass | Windows |
| `hwbp-amsi` | Hardware-breakpoint AMSI/ETW bypass path | Windows |
| `hw-bp-hook` | General-purpose DR0-DR3 hardware-breakpoint hook framework | Implies `direct-syscalls`; Windows x86_64 |
| `etw-check` | ETW auto-logger enumeration via registry | Windows |
| `kernel-callback` | BYOVD kernel callback overwrite support | Implies `direct-syscalls`; Windows |
| `embedded_driver` | Embed an encrypted vulnerable driver payload | Requires `ORCHESTRA_DRIVER_PATH` when enabled |
| `forensic-cleanup` | Prefetch/MFT/USN evidence cleanup | Implies `direct-syscalls`; Windows |
| `adaptive-timing` | Learns traffic timing and adapts callback schedule | Cross-platform |
| `wsl2-evasion` | WSL2 execution/relay evasion helpers | Windows |
| `ebpf` | Linux eBPF evasion loader and graceful-degradation path | Implies `direct-syscalls`; Linux |
| `unsafe-runtime-rewrite` | Optimizer runtime rewrite support | `optimizer/unsafe-runtime-rewrite` |
| `stealth` | Bundle feature enabling `direct-syscalls`, `unsafe-runtime-rewrite`, `memory-guard`, and `ppid-spoofing` | Meta-feature |

### Capability Features

| Feature | Description | Dependencies / Notes |
|---------|-------------|----------------------|
| `persistence` | Registry/startup/WMI/COM plus macOS LaunchAgent/Daemon, cron, and Linux systemd/profile mechanisms | Cross-platform module with platform gates |
| `wmi-persistence` | COM-based WMI permanent event subscriptions | Windows |
| `office-addin` | Office add-in persistence through OneDrive-synced add-in paths | Windows |
| `com-hijack` | Registry-free COM hijack via activation contexts | Windows |
| `uefi-persistence` | UEFI NVRAM/ESP/driver persistence framework | `uefi-persistence` crate |
| `network-discovery` | ARP, ping, port, and DNS discovery operations | — |
| `remote-assist` | Screen capture and input simulation | `enigo`, `image`, Linux `x11rb`, platform gates |
| `hci-research` | Consent-gated HCI timing telemetry; Linux uses built-in evdev polling | `chrono`, `twox-hash` |
| `surveillance` | Screenshot, keylogger, clipboard monitoring | `image`; platform-gated implementations |
| `browser-data` | Chrome/Edge/Firefox stored-data recovery | Windows |
| `lsa-whisperer` | LSA SSP-interface credential extraction | Implies `outbound-c`; Windows |
| `token-impersonation` | Token-only impersonation with process-local token cache and auto-revert | Implies `direct-syscalls`; Windows |
| `kerberos-relay` | Kerberos relay via COM cross-session activation | Windows |
| `dpapi-backup` | DPAPI domain backup key retrieval and secret decryption | Windows |
| `shadow-credentials` | AD Shadow Credentials abuse | Windows |
| `s4u-abuse` | Kerberos S4U2Self/S4U2Proxy abuse | Windows |
| `lolbin-xwizard` | xwizard.exe and alternate LOLBIN dispatchers | Windows |
| `vss-pivot` | VSS-backed SAM/SYSTEM/NTDS reads and parsing | Windows |
| `entra-ptc` | Entra ID pass-the-certificate JWT flow | `ring`; cross-platform |
| `manual-map` | Reflective/manual module mapping through `module_loader` | `module_loader/manual-map` |
| `reflective-loader` | NT section-based reflective DLL loading | Implies `direct-syscalls`; Windows x86_64 |
| `transacted-hollowing` | NTFS transaction-backed process hollowing | Implies `direct-syscalls`; Windows |
| `delayed-stomp` | Delayed module-stomp injection | Implies `direct-syscalls`; Windows |
| `phantom-dll-hollow` | Section-backed phantom DLL hollowing | Implies `direct-syscalls`; Windows x86_64 |
| `coop` | Counterfeit Object-Oriented Programming chains | Windows x86_64 |
| `module-signatures` | Ed25519 module signature verification | `common/module-signatures` |
| `hot-reload` | Agent runtime config hot-reload watcher | `notify` |
| `env-validation` | Environment validation gates | — |
| `perf-optimize` | Performance optimization toggles | — |
| `dev` | Development build toggles | — |

### Recommended Feature Combinations

#### Stealth-Focused Windows Agent
```toml
features = [
    "http-transport",
    "outbound-c",
    "direct-syscalls",
    "syscall-emulation",
    "stack-spoof",
    "trampoline-spoof",
    "cfg-bypass",
    "cet-bypass",
    "memory-guard",
    "evanesco",
    "evasion-transform",
    "self-reencode",
    "write-raid-amsi",
    "forensic-cleanup",
    "token-impersonation",
    "transacted-hollowing",
    "delayed-stomp",
    "phantom-dll-hollow",
]
```

#### Speed-Focused Windows Agent
```toml
features = [
    "http-transport",
    "outbound-c",
    "direct-syscalls",
    "stack-spoof",
    "memory-guard",
    "token-impersonation",
    "browser-data",
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
    "memory-guard",
    "write-raid-amsi",
    "token-impersonation",
    "browser-data",
    "lsa-whisperer",
    "forensic-cleanup",
]
```

#### Linux Agent
```toml
features = [
    "http-transport",
    "outbound-c",
    "doh-transport",
    "p2p-tcp",
    "network-discovery",
    "hci-research",
]
```

---

## Server Configuration (`orchestra-server.toml`)

The server configuration is a **flat TOML file** (no subsections). All paths
are relative to the working directory from which the server is launched.

### Complete Field Reference

| Field | Type | Default | Required | Description |
|-------|------|---------|----------|-------------|
| `http_addr` | string | `"127.0.0.1:8443"` | No | Operator HTTPS listener |
| `agent_addr` | string | `"127.0.0.1:8444"` | No | Agent AES-TCP listener |
| `agent_shared_secret` | string | `"change-me-pre-shared-secret"` | Production | PSK for agent authentication |
| `agent_traffic_profile` | string | unset | No | Optional normalized transport profile, e.g. `"tls"` |
| `admin_token` | string | `"change-me-admin-token"` | Production | Legacy bearer token for operator API |
| `static_dir` | path | `"orchestra-server/static"` | No | Static files for web dashboard |
| `audit_log_path` | path | `"orchestra-audit.jsonl"` | No | Path for JSONL audit log |
| `audit_hmac_key` | string | generated/persisted if absent | No | Base64 HMAC key for audit-log integrity |
| `tls_cert_path` | path | unset | No | TLS certificate PEM; self-signed cert is generated in memory when absent |
| `tls_key_path` | path | unset | No | TLS private key PEM |
| `command_timeout_secs` | u64 | `30` | No | Max wait for agent command response |
| `builds_output_dir` | path | `"/var/lib/orchestra/builds"` | No | Output dir for built agent payloads |
| `build_retention_days` | u32 | `7` | No | Retention window for old build artifacts |
| `max_concurrent_builds` | usize | `1` | No | Build worker concurrency |
| `module_aes_key` | string | unset | Production* | Base64 AES-256 module key baked into agents |
| `module_signing_key` | string | unset | No | Base64 Ed25519 signing seed for module signatures |
| `modules_dir` | path | `"/var/lib/orchestra/builds/modules"` | No | Module blob lookup directory |
| `max_module_size` | usize | `52428800` | No | Maximum decoded module size in bytes |
| `allow_local_builds` | bool | `false` | No | Allow loopback/private IP in build |
| `doh_enabled` | bool | `false` | No | Enable DNS-over-HTTPS bridge listener |
| `doh_listen_addr` | string | `"127.0.0.1:8445"` | No | DoH listener bind address |
| `doh_domain` | string | `"c2.example.com"` | No | Expected DoH query suffix |
| `doh_beacon_sentinel` | string | `"1.2.3.4"` | No | A-query value indicating tasking is available |
| `doh_idle_ip` | string | `"104.18.5.22"` | No | Benign-looking idle A-query response |
| `mtls_enabled` | bool | `false` | No | Require client certs on the agent channel |
| `mtls_ca_cert_path` | path | unset | If mTLS enabled | Agent-client certificate CA |
| `mtls_allowed_cns` | string[] | `[]` | No | Allowed client certificate CN values |
| `mtls_allowed_ous` | string[] | `[]` | No | Allowed client certificate OU values |
| `mtls_crl_path` | path | unset | No | PEM CRL path for revoked agent certificates |
| `operators` | table | `{}` | No | Named operators with `name`, `token` or `token_hash`, and permissions |
| `smb_relay_enabled` | bool | `false` | No | Enable server-side named-pipe/TCP relay bridge |
| `smb_relay_pipe_name` | string | generated IOC pipe name | No | Named pipe to create on Windows relays |
| `smb_relay_max_instances` | u32 | `4` | No | Maximum concurrent pipe instances |
| `http_c2_addr` | string | `"127.0.0.1:8446"` | No | Malleable HTTP C2 listener |
| `profile_dir` | path | unset | No | Directory of server malleable profiles, watched every 30 seconds |
| `profile_path` | path | unset | No | Single server malleable profile file, backward compatibility |
| `redirector_secret` | string | unset | Production | Shared secret for redirector heartbeats |

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

# Optional integrity/signing
# audit_hmac_key      = "<base64-32-byte-key>"
# module_signing_key  = "<base64-ed25519-seed>"

# Optional listeners and relays
# doh_enabled         = false
# doh_listen_addr     = "127.0.0.1:8445"
# http_c2_addr        = "127.0.0.1:8446"
# profile_dir         = "profiles/malleable"
# smb_relay_enabled   = false
# redirector_secret   = "<strong-random-secret>"

# Optional mTLS for the agent channel
# mtls_enabled        = false
# mtls_ca_cert_path   = "secrets/agent-ca.pem"
# mtls_allowed_cns    = ["agent.example.com"]
# mtls_allowed_ous    = ["OrchestraAgents"]
# mtls_crl_path       = "secrets/agent-ca.crl"

# Optional multi-operator records
# [operators.alice]
# name = "Alice"
# token_hash = "sha256:<hex-digest>"
# permissions = ["operator"]

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
| `format` | string | No | Output format: `"exe"` (native executable) or `"shellcode"` (Windows x86_64 only) |
| `transport` | string | No | Primary transport baked into the agent runtime config: `"tls"`, `"http"`, `"doh"`, `"ssh"`, `"smb"` |
| `transport_config` | object | No | Runtime settings for the selected transport (see below) |
| `sleep_ms` | u64 | No | Base sleep interval in milliseconds, baked into the agent |
| `jitter` | u8 | No | Jitter percentage (0–100), baked into the agent |
| `kill_date` | string | No | `YYYY-MM-DD` UTC kill date, baked into the agent |
| `version_info` | object | No | PE version info (`file_version`, `product_name`, etc.) |
| `manifest_preset` | string | No | PE manifest preset name |

`transport` is not only a Cargo feature selector. Server builds bake the matching runtime malleable-profile fields into the agent, so a generated payload can activate HTTP, DoH, SSH, or SMB without an external `agent.toml`.

### Build `transport_config` Fields

| Field | Type | Used By | Description |
|-------|------|---------|-------------|
| `http_endpoint` | string | `http` | HTTP C2 endpoint. Defaults to `http://<host>:<port>` from the build request. |
| `http_host_header` | string | `http` | Optional HTTP Host header/fronting domain. Defaults to the build host. |
| `doh_server_url` | string | `doh` | DoH bridge URL. Defaults to `https://<host>:<port>/dns-query`. |
| `doh_domain` | string | `doh` | DNS suffix expected by the DoH listener. Defaults to the build host. |
| `ssh_host` | string | `ssh` | SSH relay host. Defaults to the build host. |
| `ssh_port` | u16 | `ssh` | SSH relay port. Defaults to the build port when baked, otherwise 22 at runtime. |
| `ssh_username` | string | `ssh` | Required SSH username. |
| `ssh_auth` | object | `ssh` | Required SSH auth config, for example `{ "type": "agent" }`, `{ "type": "password", "password": "..." }`, or `{ "type": "key", "key_path": "/path/id_ed25519" }`. |
| `ssh_host_key_fingerprint` | string | `ssh` | Optional SSH host-key fingerprint pin. |
| `smb_pipe_host` | string | `smb` | SMB named-pipe relay host. Defaults to the build host. |
| `smb_pipe_name` | string | `smb` | Optional pipe name. Defaults to the agent/server IOC pipe name. |
| `smb_pipe_mode` | string | `smb` | `"smb"` or `"tcp_relay"`. |
| `smb_tcp_relay_port` | u16 | `smb` | TCP relay port for `"tcp_relay"` mode. |

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
| `manual_map` | bool | `false` | Reflective/manual module mapping |
| `browser_data` | bool | `false` | Browser stored-data recovery |
| `lsa_whisperer` | bool | `false` | LSA Whisperer support |
| `kernel_callback` | bool | `false` | Kernel callback overwrite support |
| `embedded_driver` | bool | `false` | Embedded driver payload packaging |
| `evanesco` | bool | `false` | Continuous memory hiding |
| `syscall_emulation` | bool | `false` | User-mode syscall emulation |
| `cet_bypass` | bool | `false` | CET/shadow-stack bypass support |
| `token_impersonation` | bool | `false` | Token-only impersonation support |
| `transacted_hollowing` | bool | `false` | NTFS transaction-backed hollowing |
| `delayed_stomp` | bool | `false` | Delayed module-stomp injection |



---

## Malleable C2 Profiles

Profiles are TOML files in the `profiles/` directory. See the main README for the full TOML schema.

### Stealth-Focused Profile

```toml
[profile]
name = "stealth-cloudfront"
author = "operator"
description = "Cloudfront-fronted stealth profile"

[profile.global]
user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
jitter = 37
sleep_time = 45
dns_idle = "0.0.0.0"
dns_sleep = 0

[profile.ssl]
enabled = true
cert_pin = ""
ja3_fingerprint = ""
sni = "d1k2s3c4.cloudfront.net"

[profile.http_get]
uri = ["/api/v1/feed", "/api/v1/notifications", "/api/v2/timeline"]
verb = "GET"

[profile.http_get.client]
prepend = ""
append = ""
transform = "Base64"

[profile.http_get.metadata]
delivery = "Cookie"
key = "__cf_bm"
transform = "Base64"

[profile.http_post]
uri = ["/api/v1/upload", "/api/v2/media", "/api/v1/attachments"]
verb = "POST"

[profile.http_post.client]
prepend = ""
append = ""
transform = "Base64"

[profile.http_post.output]
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

[profile.global]
user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
jitter = 10
sleep_time = 5
dns_idle = "0.0.0.0"
dns_sleep = 0

[profile.ssl]
enabled = true
cert_pin = ""
ja3_fingerprint = ""
sni = ""

[profile.http_get]
uri = ["/status", "/health", "/ping"]
verb = "GET"

[profile.http_get.client]
prepend = ""
append = ""
transform = "None"

[profile.http_get.metadata]
delivery = "Header"
key = "X-Request-Id"
transform = "Base64"

[profile.http_post]
uri = ["/submit", "/data", "/update"]
verb = "POST"

[profile.http_post.client]
prepend = ""
append = ""
transform = "None"

[profile.http_post.output]
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

[profile.global]
user_agent = ""
jitter = 20
sleep_time = 30

[profile.dns]
enabled = true
beacon = "cdn.{suffix}"
get_A = "api.{suffix}"
get_TXT = "txt.{suffix}"
post = "exfil.{suffix}"
max_txt_size = 252
dns_suffix = "example.com"
encoding = "base64url"

[profile.dns.headers]
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

At runtime the agent loads `~/.config/sysd/agent.toml` (or
`./.config/sysd/agent.toml` if no home directory is available). If the file is
absent, `common::config::Config::default()` is used and then build-time overrides
from the builder (`SYS_C_*`, sleep/jitter/kill-date, transport settings) are
applied. When the `hot-reload` feature is compiled in, changes to `agent.toml`
and `agent.toml.sha256` are watched and applied with a 500 ms debounce.

### Top-Level Agent Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `sleep` | table | `SleepConfig::default()` | Sleep method, interval, jitter, working hours, and sleep-mask scheme rotation |
| `malleable-profile` | table | defaults | Runtime transport hints: HTTP/DoH/SSH/SMB endpoints, host header, kill date, cloud/VM controls |
| `exec-strategy` | enum | `indirect` | `indirect`, `direct`, `fallback`, or `kernel-proxy` |
| `allowed-paths` | string[] | platform defaults | File-system paths allowed for file operations |
| `heartbeat-interval-secs` | u64 | `30` | Agent heartbeat interval |
| `persistence-enabled` | bool | `false` | Global persistence toggle |
| `module-repo-url` | string | default repository URL | Remote module repository |
| `module-aes-key` | string | unset | Base64 AES-256-GCM module decryption key; legacy alias: `module_signing_key` |
| `module-verify-key` | string | unset | Base64 Ed25519 public key for module signature verification |
| `module-cache-dir` | string | platform cache path | Pre-staged module cache directory |
| `traffic-profile` | enum | `none` | Wire traffic normalization profile |
| `required-domain` | string | unset | Refuse startup unless the host is joined to this DNS domain |
| `refuse-in-vm` | bool | `false` | Refuse startup when VM/sandbox checks trip |
| `refuse-when-debugged` | bool | `false` | Refuse startup when a debugger is attached |
| `sandbox-score-threshold` | u32 | unset | Refuse startup when sandbox score meets/exceeds this threshold |
| `server-cert-fingerprint` | string | unset | SHA-256 TLS certificate pin for outbound mode |
| `port-scan-concurrency` | usize | default | Network discovery concurrency |
| `port-scan-timeout-ms` | u64 | default | Network discovery connect timeout |
| `persistence` | table | all default mechanisms | Per-platform persistence mechanism toggles and IoC overrides |
| `etw-patch-method` | enum | `direct` | `direct`, `hwbp`, or `hw-bp-hook` |
| `p2p-heartbeat-interval-secs` | u64 | `30` | P2P link heartbeat interval |
| `reencode-interval-secs` | u64 | `14400` | Periodic self-reencoding interval |
| `injection` | table | defaults | Module-stomp DLL candidate and exclusion configuration |
| `evanesco` | table | defaults | Continuous memory hiding scan/idle thresholds |
| `browser-c4-timeout-secs` | u64 | `60` | Chrome App-Bound Encryption C4 timeout |
| `lsa-whisperer` | table | defaults | LSA Whisperer timeout/buffer/auto-inject settings |
| `syscall` | table | defaults | SSN cache validation and resolution strategy |
| `evasion-transform` | table | defaults | Runtime signature scan interval, max transforms, entropy threshold |
| `transacted-hollowing` | table | defaults | NTFS transaction hollowing controls |
| `delayed-stomp` | table | defaults | Delayed module-stomp controls |
| `syscall-emulation` | table | defaults | Kernel32/advapi32 syscall emulation controls |
| `cet-bypass` | table | defaults | CET/shadow-stack bypass controls |
| `token-impersonation` | table | defaults | Token-only impersonation strategy, cache, and auto-revert |
| `prefetch` | table | defaults | Prefetch cleanup method and USN cleanup controls |
| `timestamps` | table | defaults | MFT timestamp sync and USN/$LogFile cleanup controls |

### Common Runtime Sections

```toml
[sleep]
method = "standard"              # ekko | foliage | cronus | hardware-timer | standard
base-interval-secs = 30
jitter-percent = 20
sleep-mask-enabled = false
mask-rotation-interval-secs = 300
mask-rotation-schemes = ["xchacha20-poly1305"]

[malleable-profile]
user-agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
uri = "/api/v1/update"
host-header = "cdn.example.com"
cdn-relay = false
dns-over-https = false
direct-c2-endpoint = ""
doh-server-url = "https://c2.example.com/dns-query"
doh-beacon-sentinel = "1.2.3.4"
kill-date = ""
dns-prefix = "<generated default>"

[malleable-profile.ssh-auth]
type = "agent"                   # key | password | agent

[syscall]
validate-interval = 100
ssn-resolution-method = "hybrid"  # halo-gate | exception-based | hybrid

[token-impersonation]
enabled = true
prefer-set-thread-token = true
cache-tokens = true
auto-revert-on-task-complete = true

[prefetch]
enabled = true
auto-clean-after-injection = true
method = "patch"                 # delete | patch | disable-service
restore-service-after = true
clean-usn-journal = true
```

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

