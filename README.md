# Orchestra

[![CI](https://github.com/t-h-i-n-k-er/orchestra/actions/workflows/ci.yml/badge.svg)](https://github.com/t-h-i-n-k-er/orchestra/actions/workflows/ci.yml)

**Orchestra** is a cross-platform, memory-efficient remote management framework
for enterprise device fleets. It gives IT and DevOps teams a single authenticated
control plane for executing approved maintenance tasks, deploying software updates,
collecting diagnostics, and auditing every operator action across Linux, Windows,
and macOS endpoints.

## Quick start

> **One command from clone to running system.**

```sh
git clone https://github.com/t-h-i-n-k-er/orchestra.git
cd orchestra
./scripts/quickstart.sh        # Linux / macOS
```

```bat
git clone https://github.com/t-h-i-n-k-er/orchestra.git
cd orchestra
scripts\quickstart.bat         # Windows (cmd.exe)
```

The quickstart script checks for Rust, builds the Builder, generates random
credentials and a self-signed TLS certificate, creates a default outbound
profile, builds the agent payload, and prints your dashboard URL and bearer
token. Say **y** when it offers to start the Control Center, then open the
dashboard in a browser.

| Environment variable | Default | Purpose |
|---|---|---|
| `ORCHESTRA_PROFILE` | `default` | Profile name under `profiles/` |
| `ORCHESTRA_HTTP_PORT` | `8443` | HTTPS dashboard port |
| `ORCHESTRA_AGENT_PORT` | `8444` | Agent listener port |
| `ORCHESTRA_SKIP_SERVER` | `0` | Set to `1` to skip auto-starting the server |

For a guided walk-through of every option (target OS, features, addresses,
TLS), use the interactive wizard instead:

```sh
./scripts/setup.sh             # Linux / macOS (full wizard)
./scripts/setup.ps1            # Windows (PowerShell wizard)
```

Verify your environment at any time:

```sh
./scripts/verify-setup.sh
```

## What Orchestra does

- **Authenticated end-to-end.** HKDF-SHA256-derived AES-256-GCM session
  encryption with per-frame random salts and nonces (protocol v2), optional
  X25519 forward secrecy, bearer-token operator auth, and HMAC-SHA256-signed
  JSONL audit logs.
- **Opt-in capability model.** Every non-default capability — persistence,
  network discovery, remote assistance, HCI logging — is a Cargo feature flag
  baked into a deployment profile. Only what you opt into ships in the binary.
- **Cross-platform.** First-class targets: `x86_64-unknown-linux-gnu`,
  `x86_64-pc-windows-msvc`, and `x86_64-apple-darwin`. ARM64 variants build
  from the same sources.
- **Lightweight on the endpoint.** The agent is a single statically-linked
  Rust binary. No runtime, no daemon framework, minimal RSS.
- **Self-hosted control plane.** The Orchestra Control Center
  (`orchestra-server`) gives you an HTTPS dashboard and REST API on
  infrastructure you control.

## Architecture

```
┌──────────────────┐       TLS + AES-256-GCM        ┌──────────────────┐
│  Orchestra       │◄──────────────────────────────►│  Agent            │
│  Control Center  │        bincode frames            │  (endpoint)       │
│  (server)        │                                  │                  │
├──────────────────┤                                  ├──────────────────┤
│ HTTPS dashboard  │       REST + WebSocket           │ Outbound dialer  │
│ REST API         │                                  │ Command loop     │
│ Build queue      │                                  │ Plugin loader    │
│ Audit logger     │                                  │ Policy engine    │
└──────────────────┘                                  └──────────────────┘
```

**Wire protocol (v2):** `u32 length prefix │ bincode-serialised Message`.

**Crypto per message:** `salt(32) ‖ nonce(12) ‖ ciphertext_with_tag`.
HKDF-SHA256 derives a unique AES-256-GCM key from the PSK + per-message salt
for every frame.

### Workspace crates

| Crate | Kind | Purpose |
|---|---|---|
| `agent` | lib + bin | Agent service on managed endpoints. Standalone via `agent-standalone` binary. |
| `orchestra-server` | bin | **Control Center** — HTTPS dashboard, REST/WebSocket API, async build queue, optional DoH bridge. |
| `builder` | bin | CLI for dependency setup, profile management, cross-compilation, and AES payload packaging. |
| `launcher` | bin | Stub that fetches and decrypts an agent payload at runtime. |
| `console` | bin | Legacy protocol-test CLI. |
| `dev-server` | bin | Local HTTPS server for testing payloads. |
| `payload-packager` | bin | Stand-alone AES-256-GCM payload encryptor with polymorphic packaging. |
| `keygen` | bin | Ed25519 keypair generator for module signing. |
| `common` | lib | Wire protocol types, `CryptoSession`, `Transport` trait, audit events. |
| `optimizer` | lib | CPU microarchitecture tuning and build-time software diversification. |
| `module_loader` | lib | Securely fetches, verifies, and loads signed plugins in memory. |
| `hollowing` | lib | Windows process hollowing for in-memory payload execution. |
| `string_crypt` | lib + proc-macro | Compile-time string obfuscation via XOR. |
| `pe_resolve` | lib | PE format parsing for Windows binary analysis. |
| `nt_syscall` | lib | Windows NT direct and indirect syscall wrappers. |
| `code_transform` | lib | Control-flow flattening and code transformation passes. |
| `code_transform_macro` | proc-macro | Helper macros for `code_transform`. |
| `junk_macro` | proc-macro | Junk code barriers at compile time. |
| `orchestra-side-load-gen` | bin | DLL side-loading payload generator (Windows). |
| `orchestra-pe-hardener` | lib | PE binary hardening primitives (stub). |
| `shellcode_packager` | lib | Shellcode packaging utilities. |

## Setup paths

| Goal | Command | Details |
|---|---|---|
| **Clone → running in 60 s** | `./scripts/quickstart.sh` | Auto-detects platform, generates all credentials and certs, builds everything. |
| **Guided wizard** | `./scripts/setup.sh` | Interactive: pick target OS, features, addresses, TLS. |
| **Windows PowerShell** | `./scripts/setup.ps1` | Same wizard, PowerShell edition. |
| **Quick payload build** | `./scripts/quickbuild.sh` | Build a payload + start dev-server in one step. |
| **Verify environment** | `./scripts/verify-setup.sh` | Checks Rust, C compiler, OpenSSL, workspace health. |
| **Generate TLS certs** | `./scripts/generate-certs.sh` | Self-signed cert with custom SANs. |
| **Local dev** | `./scripts/dev-start.sh` | Start server + dev-server together. |

### Prerequisites

| Tool | Required for | Install |
|---|---|---|
| **Rust** (stable) | Everything | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` |
| **C compiler** (gcc / clang / MSVC) | Native builds | System package manager or Visual Studio Build Tools |
| **OpenSSL** | TLS cert generation | `apt install libssl-dev` / `brew install openssl` |
| **pkg-config** | Build scripts | `apt install pkg-config` / `brew install pkg-config` |
| **mingw-w64** or **cargo-zigbuild** | Windows cross-compile from Linux | `apt install mingw-w64` or `cargo install cargo-zigbuild` |
| **Xcode CLI Tools** | macOS native builds | `xcode-select --install` |

Cross-compilation targets are installed with `rustup`:

```sh
rustup target add x86_64-pc-windows-msvc        # Windows (needs MSVC)
rustup target add x86_64-pc-windows-gnu          # Windows (needs mingw-w64)
rustup target add aarch64-unknown-linux-gnu       # ARM64 Linux
```

## Feature flags

Feature flags are organised into four categories. All are **off by default** —
enable only what you need per profile.

### Transport

| Feature | Description |
|---|---|
| `outbound-c` | Agent dials the Control Center automatically; reconnects with exponential backoff. **Recommended for all deployments.** |
| `forward-secrecy` | X25519 ephemeral key exchange before the first message; protects recorded sessions if the PSK is later compromised. |
| `http-transport` | HTTP malleable-profile transport (`c2_http`). Tunnels C2 over HTTPS with configurable headers/URIs. |
| `doh-transport` | DNS-over-HTTPS transport (`c2_doh`). Tunnels C2 through DNS TXT queries. |
| `ssh-transport` | SSH-based transport (`c2_ssh`). Experimental; pure-Rust via `russh`. |
| `smb-pipe-transport` | SMB/TCP named-pipe transport (`c2_smb`). Windows named pipes or TCP relay. |
| `traffic-normalization` | Traffic-shaping compatibility flag for `NormalizedTransport`. |

### Stealth

| Feature | Description |
|---|---|
| `stealth` | Convenience bundle: `direct-syscalls` + `unsafe-runtime-rewrite` + `memory-guard` + `ppid-spoofing`. |
| `direct-syscalls` | Windows direct syscall wrappers; bypasses ntdll imports. |
| `stack-spoof` | Spoofs user-mode call stack during indirect syscall dispatch (Windows x86-64). Implies `direct-syscalls`. |
| `manual-map` | Windows manual PE mapping for in-memory plugin loading. |
| `env-validation` | Startup environment checks: debugger, VM, sandbox, domain. Policy-driven refusal. |
| `memory-guard` | Encrypts sensitive memory regions while the agent is idle (XChaCha20-Poly1305). |
| `unsafe-runtime-rewrite` | Runtime-rewrite compatibility flag. Leave disabled unless a specific test requires it. |
| `ppid-spoofing` | Parent-process metadata spoofing (Windows). |
| `self-reencode` | Runtime self-re-encoding ("Metamorphic Lite"): periodically re-encodes `.text` with a fresh seed. |

### Capability

| Feature | Description |
|---|---|
| `persistence` | Re-launches agent across reboots (systemd / launchd / scheduled task). |
| `network-discovery` | Bounded subnet enumeration for asset inventory. |
| `remote-assist` | Consent-gated screen capture and input simulation for IT support. |
| `hci-research` | HCI telemetry (key timing, focus changes) for usability research. Opt-in, privacy-preserving. |
| `evdev` | **Linux only.** Switches HCI backend from X11/libinput to kernel evdev-rs. Requires `libtool`, `autoconf`, `automake`. |

### Build

| Feature | Description |
|---|---|
| `dev` | Development build flag; enables insecure defaults for local testing. |
| `hot-reload` | Runtime config hot-reload via `notify` crate. |
| `module-signatures` | Ed25519 signature verification for dynamically loaded modules. |
| `perf-optimize` | Experimental optimizer-backed tuning. |

## Documentation index

| Document | Content |
|---|---|
| [**QUICKSTART.md**](docs/QUICKSTART.md) | Step-by-step tutorial: from clone to first command. |
| [**CONTROL_CENTER.md**](docs/CONTROL_CENTER.md) | Server configuration, REST API reference, outbound agents, hardening. |
| [**ARCHITECTURE.md**](docs/ARCHITECTURE.md) | Wire protocol, cryptography, transport abstraction, module loading. |
| [**FEATURES.md**](docs/FEATURES.md) | Complete feature flag reference with examples and interdependencies. |
| [**SECURITY.md**](docs/SECURITY.md) | Threat model, hardening guide, TLS best practices, audit trail. |
| [**LAUNCHER.md**](docs/LAUNCHER.md) | Launcher stub internals and deployment patterns. |
| [**CONTRIBUTING.md**](docs/CONTRIBUTING.md) | Dev setup, test commands, PR process, coding standards. |
| [**ROADMAP.md**](ROADMAP.md) | Project roadmap and contribution opportunities. |

## License

Orchestra is released under the terms in [LICENSE](LICENSE).

## Disclaimer

Orchestra is a remote management framework intended for use by authorised
administrators on systems they own or are explicitly authorised to manage.
Users are solely responsible for ensuring compliance with all applicable laws
and regulations. The authors assume no liability for misuse.
