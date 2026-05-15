# Orchestra Roadmap

The Orchestra framework is feature-complete for its initial milestone:
encrypted console-to-agent control, file and shell operations under a
strict allow-list, dynamic capability plugins, opt-in persistence and
remote-assistance modules, structured audit logging, and mutually-
authenticated TLS transport.

This document describes where the project is going next.

---

## Completed

- ✅ **Trusted Execution Environment enforcement** (`env-validation` feature):
  debugger detection, hypervisor detection, domain validation.
- ✅ **Adaptive VM detection thresholds + cloud fallback controls**:
  tiered VM thresholds, IMDS-aware fallback handling, and operator-extensible
  expected-hypervisor names.
- ✅ **Cross-platform persistence primitives**: Linux systemd user service,
  macOS LaunchAgent/CronJob paths, Windows scheduled-task/autorun mechanisms.
- ✅ **HTTP and DNS-over-HTTPS C2 transports** (`http-transport`,
  `doh-transport`) available as explicit opt-in channels.
  ⚠️ *Forward secrecy over HTTP/DoH (ECDH key exchange via headers/DNS
  labels) is **experimental** — not yet tested end-to-end under all
  malleable-profile transforms.*
- ✅ **Polymorphic payload packaging** with multi-cipher layout variation in
  `payload-packager`.
- ✅ **SSH transport compile path** (`ssh-transport`) available as an
  experimental outbound channel.
- ✅ **Builder runtime feature discovery**: `read_agent_features()` parses
  `agent/Cargo.toml` dynamically; unknown features are warned and excluded.
- ✅ **Console CLI extended** with 11 new subcommands: `discover`,
  `screenshot`, `key`, `mouse`, `hci-start`, `hci-stop`, `hci-log`,
  `persist-enable`, `persist-disable`, `list-procs`, `migrate`.
- ✅ **Windows process hollowing** shared crate (`hollowing`), integrated into
  `launcher` for in-memory payload execution.
- ✅ **enigo `x11rb` backend**: eliminated `libxdo-dev` system dependency on
  Linux for remote-assist builds.
- ✅ **`x11cap` vendor patch**: stable-Rust-compatible fork using `NonNull<T>`.
- ✅ **Routine CI feature check** validates the agent with every declared
  feature except `embedded_driver`, which is intentionally excluded because it
  requires a build-time driver artifact.
- ✅ **Full `--all-features` builds** are supported when `SYS_DRIVER_PATH` or
  `ORCHESTRA_DRIVER_PATH` points to a valid XOR-encrypted `.sys` driver;
  without one, the `embedded_driver` build script fails fast by design.
- ✅ **Clippy with full features** follows the same split: routine checks omit
  `embedded_driver`; full `--all-features -- -D warnings` requires the driver
  environment variable.
- ✅ **`cargo fmt --all`** workspace fully formatted.
- ✅ **HMAC-SHA256 signed audit events**: each JSONL entry is paired with
  an HMAC tag; tampered records are flagged on read. Key derived from
  admin token via HKDF.
- ✅ **Protocol version 2**: per-message HKDF-SHA256 salt derivation with
  wire format `salt(32) ‖ nonce(12) ‖ ciphertext_with_tag`. Includes
  `VersionHandshake` message for version negotiation.
- ✅ **Forward secrecy (X25519 + HKDF)**: the `forward-secrecy` feature
  performs an ephemeral X25519 key exchange to derive a unique session
  key, ensuring recorded sessions cannot be decrypted if the PSK is
  later compromised.  ⚠️ *Forward secrecy over HTTP/DoH transports
  (ECDH via `X-ECDH-Pub` headers and DNS TXT labels) is **experimental**.*
- ✅ **Interactive PTY shell sessions**: `StartShell`, `ShellInput`,
  `ShellOutput`, `CloseShell` commands with non-blocking reader thread
  architecture.
- ✅ **Async build queue**: configurable worker pool for remote agent
  builds via the Control Center REST API (`POST /api/build`, status
  polling, artifact download).
- ✅ **DNS-over-HTTPS bridge**: `doh_listener` module for agent sessions
  tunneled over DNS queries with IP-based rate limiting.
- ✅ **Mutual TLS for agent channel**: server-side mTLS enforcement with
  configurable allowed CNs and OUs.
- ✅ **Stack spoofing**: `stack-spoof` feature for spoofing user-mode
  call stacks during indirect syscall dispatch on Windows x86-64; clean-call
  spoofing also has a Windows ARM64 branch-gadget path.
- ✅ **Hot-reload**: `hot-reload` feature enables runtime config
  hot-reload via the `notify` crate.

### Known limitations

- ⚠️ PE32/WOW64 hollowing compatibility is still being hardened; PE64 remains
  the primary execution path.
- ⚠️ Remote manual mapping can still encounter edge-case failures when local
  and remote ASLR module layouts diverge significantly.
- ⚠️ macOS cloud instance-id detection depends on IMDS reachability and may
  return no identity in restricted metadata environments.
- ⚠️ macOS LoginItem persistence uses ServiceManagement when helper context is
  available, with LaunchAgent fallback otherwise.

---

## Completed (continued — 2025)

- ✅ **NTDLL unhooking pipeline** — Full `.text` re-fetch from `\KnownDlls\ntdll.dll`
  with disk fallback, chunked overwrite, hook detection for 23 critical syscalls,
  post-sleep automatic hook re-check.
- ✅ **In-process .NET assembly execution** (`assembly_loader.rs`) — CLR hosting
  via `mscoree.dll`, lazy init, fresh AppDomain per execution, AMSI bypass,
  configurable timeout, 5-min idle auto-teardown.
- ✅ **BOF / COFF loader** (`coff_loader.rs`) — Beacon-compatible API (18 exports),
  COFF relocation, x86_64 only, compatible with public BOF ecosystem.
- ✅ **Browser data extraction** (`browser_data.rs`) — Chrome v127+ App-Bound
  Encryption (3 bypass strategies), Edge, Firefox. Custom SQLite parser, NSS
  runtime loading. Gated by `browser-data` feature.
- ✅ **Interactive shell sessions** (`interactive_shell.rs`) — PTY sessions with
  background reader threads, async output via `ShellOutput`, sleep obfuscation
  integration, multi-session support.
- ✅ **LSASS credential harvesting** (`lsass_harvest.rs`) — Incremental memory
  reading via indirect syscalls, no MiniDumpWriteDump, build-specific offset
  tables for Windows 19041–26100, MSV/WDigest/Kerberos/DPAPI/DCC2 extraction.
- ✅ **Surveillance module** (`surveillance.rs`) — Screenshot capture,
  keylogger (WH_KEYBOARD_LL), clipboard monitoring, all stored in ChaCha20-Poly1305
  encrypted ring buffers. Gated by `surveillance` feature.
- ✅ **Injection engine expansion** — ThreadPool (8 sub-variants), Fiber,
  Context-Only, Section Mapping, NtSetInformationProcess write bypass,
  Waiting Thread Hijack, Transacted Hollowing, Delayed/Existing Module Stomp,
  Phantom DLL Hollowing, and Callback (12 APIs) techniques. Total: 15
  `InjectionTechnique` variants in the unified injection engine.
- ✅ **Token manipulation commands** — `MakeToken`, `StealToken`, `Rev2Self`,
  `GetSystem` with thread-safe impersonation.
- ✅ **Lateral movement commands** — `PsExec`, `WmiExec`, `DcomExec`, `WinRmExec`.
  No PowerShell used — all native COM/WinRM/NT API.
- ✅ **Halo's Gate unhook callback** — `nt_syscall::set_halo_gate_fallback()`
  registers agent's unhook function; automatic unhook on Halo's Gate failure.
- ✅ **Feature flags for new capabilities** — `surveillance` (Windows, dep:image),
  `browser-data` (Windows), `hwbp-amsi` (Windows, architecture-native hardware
  breakpoint VEH), `write-raid-amsi` (Windows, data-only race condition,
  preferred AMSI bypass).

### Completed (continued — late 2025)

- ✅ **LSA Whisperer** (`lsa-whisperer` feature) — SSP interface credential
  extraction from MSV1_0/Kerberos/WDigest, bypasses Credential Guard and
  RunAsPPL without reading LSASS memory.
- ✅ **Kernel Callback BYOVD** (`kernel-callback` feature) — Surgical EDR
  callback overwrite via 8 vulnerable signed drivers; `ret` pointer defeats
  EDR self-integrity checks; anti-forensic driver unlinking.
- ✅ **Automated EDR Bypass Transform Engine** (`evasion-transform` feature) —
  Runtime `.text` signature scanning with 5 semantic-preserving transformations
  (instruction substitution, register reassignment, NOP sled insertion, constant
  splitting, jump obfuscation).
- ✅ **Evanesco continuous memory hiding** (`evanesco` feature) — Per-page RC4
  encryption at rest, VEH-based auto-decryption, background re-encryption thread,
  sleep obfuscation integration.
- ✅ **C4 Bomb — DPAPI Padding Oracle** (`browser-data` feature) — CBC padding-oracle
  attack against DPAPI `CryptUnprotectData` to recover Chrome v20+ App-Bound
  encryption key without elevation.
- ✅ **Indirect Dynamic Syscall upgrade** — Runtime SSN validation (cross-reference +
  probe methods), build-aware caching from `KUSER_SHARED_DATA`, SSDT nuclear fallback,
  versioned SSN range table for Windows 10/11 builds.
- ✅ **NTFS Transaction-Based Process Hollowing** (`transacted-hollowing` feature) —
  Fileless process hollowing via NTFS transactions with ETW blinding and spoofed
  provider GUIDs.
- ✅ **Delayed Module-Stomp Injection** (`delayed-stomp` feature) — EDR timing-heuristic
  bypass with configurable randomized delay between DLL load and stomping.
- ✅ **AMSI Write-Raid Bypass** (`write-raid-amsi` feature) — Data-only race condition
  overwriting `AmsiInitFailed` flag; zero code/permission/breakpoint modifications.
- ✅ **Cronus Sleep Obfuscation** — Waitable-timer variant (`NtCreateTimer` +
  `NtSetTimer` + `NtWaitForSingleObject`) as alternative to Ekko `NtDelayExecution`.
- ✅ **Unwind-Aware Call Stack Spoofing upgrade** (`stack-spoof` feature) — Multi-frame
  plausible call graph chains, unwind metadata validation, post-sleep revalidation.
- ✅ **COM Hijack** (`com-hijack` feature) — Registry-free COM hijack through activation
  contexts with scan, manifest generation, proxy DLL creation, and activation commands.
- ✅ **DPAPI Backup Key** (`dpapi-backup` feature) — Domain backup-key retrieval, harvesting,
  and blob decryption for offline credential recovery.
- ✅ **Hardware Persistence** (`hardware-persistence` feature) — Thunderbolt/DMA-based
  persistence with VBR and UEFI boot persistence, physical memory read, vulnerability
  detection.
- ✅ **Kerberos Relay** (`kerberos-relay` feature) — Kerberos relay through COM
  cross-session activation with CLSID enumeration.
- ✅ **macOS Post-Exploitation** (`macos-postexp` feature) — TCC check/bypass, SIP
  status/bypass mount, XPC enumeration/exploit, Keychain dump.
- ✅ **Shadow Credentials** (`shadow-credentials` feature) — AD Shadow Credentials
  attack via `msDS-KeyCredentialLink` and PKINIT with access check, cert generation,
  and attack execution.
- ✅ **UEFI Persistence** (`uefi-persistence` feature) — UEFI NVRAM/ESP persistence
  with boot entry enumeration, stub building, driver writing, variable manipulation,
  and runtime driver installation.
- ✅ **WMI Persistence** (`wmi-persistence` feature) — COM-based WMI permanent event
  subscription management with stager generation and cloud upload.
- ✅ **Graph transport** (`graph-transport` feature) — Microsoft Graph API covert C2
  transport channel.
- ✅ **QUIC transport** (`quic-transport` feature) — QUIC/HTTP3 C2 transport with
  certificate verification.
- ✅ **Software Diversification** (`optimizer` crate) — Build-time code diversification
  via instruction substitution, opaque dead-code insertion, and scheduling passes;
  invoked via `--diversify` flag in builder CLI.
- ✅ **Active Directory / Entra ID attack suite** — `adcs-attacks` (ESC1–ESC8),
  `entra-ptc` (Primary Refresh Token theft), `entra-attacks` (credential attacks,
  PRT theft, token abuse), `entra-app-abuse` (OAuth application abuse), `s4u-abuse`
  (S4U2Self/S4U2Proxy delegation abuse), `shadow-credentials` (KeyCredentialLink).
- ✅ **Container escape** (`container-escape` feature) — Linux container escape,
  cloud metadata credential theft, cloud IAM pivoting.
- ✅ **VSS pivot** (`vss-pivot` feature) — Volume Shadow Copy access for locked files
  (SAM, SYSTEM, NTDS.dit).
- ✅ **LPE** (`lpe` feature) — Local privilege escalation modules.
- ✅ **Recon** (`recon` feature) — Automated reconnaissance and situational awareness.

---

## Short term (next 0–3 months)

- **Web GUI console.** A small Axum + React front-end that talks to the
  same `Transport` as the CLI. Shipped as a single static binary.
- **`orchestra-agentd` reference daemon** so administrators don't have
  to write their own wrapper to embed the agent library.
- **Windows MSI installer** built in CI from the release artifacts.
- **Windows and macOS CI build verification hardening.** Keep cross-platform
  `cargo check` jobs stable and promote them from non-blocking to required.
- **PE32 process hollowing support for WOW64 targets.** Complete broader
  runtime validation and compatibility testing for 32-bit payloads.
- **macOS native mouse detection hardening.** Continue validation of the
  CoreGraphics-based path that replaced Python/Quartz subprocess probes.
- **Remote manual-map import resolution under mismatched ASLR bases.** Expand
  regression coverage and failure diagnostics for cross-process module-layout
  divergence.
- **Polymorphic stub emitter variants.** The `payload-packager` stub emitter
  currently ships one x86-64 decoder layout. Planned variants include
  register-shuffled AES-CTR, RC4-stream, and position-independent
  Chacha20-Poly1305 stubs. Register constants (`RDX`, `R8–R11`) and
  encoding helpers (`xor_rr_zero`, `add_r64_imm8`, `jge_rel8`, `jb_rel8`,
  `jmp_rel8`, `movzx_r64_mem8_base_idx`, `mov_mem8_base_idx_r8`,
  `xor_r8_mem8_base_idx`, `mov_r64_imm64`) are retained under
  `#[allow(dead_code)]` in `stub_emitter.rs` for these upcoming variants.

## Code hygiene policies

### `#[allow(dead_code)]` items

The codebase contains ~60 `#[allow(dead_code)]` annotations.  Each one
includes a justification comment.  The categories are:

1. **Windows API constants** kept for completeness and future use
   (e.g., `com_hijack.rs`, `adcs_attacks.rs`, `lsa_whisperer.rs`).
2. **Planned emitter variants** in `payload-packager/src/stub_emitter.rs`
   — register constants and encoding helpers for upcoming polymorphic
   decoder layouts.
3. **Backward-compatible utility functions** (e.g., `c2_http.rs`,
   `poly.rs`, `pe_artifact_kit.rs`) that are not yet wired into every
   code path.
4. **Feature-gated code paths** that become dead when their feature is
   disabled (e.g., `module_loader.rs`, `c2_ssh.rs`).
5. **Platform-specific functions** only reachable on their target OS
   (e.g., `env_check.rs`).
6. **Internal helpers** kept for completeness and testing flexibility
   (e.g., `virtualize.rs`, `optimizer.rs`).

Policy: do not remove these annotations without first confirming that
the symbol is truly unreachable in all feature/OS configurations *and*
not listed on this roadmap for an upcoming capability.  When a new
dead-code annotation is added, it must include a comment explaining why.

### `#[ignore]` tests

Three integration tests are marked `#[ignore]`:

- `launcher/tests/hollowing_test.rs` — requires a writable build
  directory and is invasive; opt-in only.
- `hollowing/src/windows_impl.rs` — manual Windows test requiring an
  explicit 32-bit payload path.
- `agent/src/process_manager.rs` — invasive hollowing test gated behind
  `#[cfg(windows)]`.

These tests cannot run in CI (they require a live Windows environment
with specific filesystem layouts).  Each has a comment explaining the
prerequisite.  Run locally with `cargo test -- --ignored` when needed.

## Medium term (3–9 months)

- **Plugin marketplace.** A signed, public registry from which
  administrators can pull pre-vetted capability modules. Includes a
  reference indexer + signature-verification CLI.
- **Kubernetes node support.** A DaemonSet that runs the agent inside
  every node, exposing pod-level diagnostics through dedicated commands.
- **Sandboxed plugin execution.** seccomp-bpf on Linux and Job Objects on
  Windows to constrain what a loaded plugin can syscall.
- **Per-operator RBAC.** Bind the operator certificate's CN to a role
  and restrict commands accordingly (e.g., `read-only`, `operator`,
  `administrator`).
- **Sleep obfuscation hardening.** Encrypt sensitive agent memory regions
  during dormant/sleep intervals with audited key-lifecycle handling.
  → ✅ Completed. Full XChaCha20-Poly1305 encryption of heap + stack, XMM14/XMM15
  key stash, post-wake NTDLL hook re-check.
- **Malleable C2 profile system.** Expand traffic-shaping controls for
  header/URI cadence, jitter, and profile rotation.
  → ✅ Completed. Full TOML malleable profile system with multi-profile support,
  hot-reload, and per-transaction transforms.
- **BOF-equivalent in-process COFF execution.** Provide a constrained,
  signed object-loader capability for operator task extensions.
  → ✅ Completed. See `coff_loader.rs` in the agent crate.
- **P2P pivoting capability.** Add SMB/TCP relay paths between agents for
  segmented-network operations.
  → ✅ Completed. See P2P Mesh Protocol in `ARCHITECTURE.md` and `P2P_MESH.md`.

## Long term (9+ months)

- **Enterprise identity-provider integration.** LDAP/Active Directory
  and OAuth/OIDC for issuing operator client certificates from existing
  identity sources.
- **Streaming telemetry.** Optional, opt-in metrics export (OpenTelemetry)
  for centralized observability of large fleets.
- **Hot-reloadable agent core.** Use the in-memory module loader to swap
  the agent binary itself without restarting, keeping shell sessions
  alive across upgrades.

- **Formal verification of `validate_path`.** Prove the path-traversal
  guard correct using `prusti` or `kani`.

---

## How to contribute

1. **Find an item** above (or open an issue describing your idea).
2. Open a draft PR early; we discuss design before merging code.
3. Run `cargo fmt --all`, `cargo clippy --workspace -- -D warnings`,
   `cargo test --workspace`, and `cargo audit` locally before pushing.
4. Add or update entries in `docs/ARCHITECTURE.md` for any user-visible
   behaviour change.
5. Sign your commits (`git commit -s`) under the
   [Developer Certificate of Origin](https://developercertificate.org/).

Security-sensitive contributions (new transports, anything inside
`module_loader`, anything that takes user-supplied paths) get an
additional reviewer from the security team. Please be patient with the
extra round-trip — it exists so we can keep the project trustworthy.

---

## Project capabilities, in neutral language

Orchestra today provides:

- A console CLI and a reusable agent library implemented in safe Rust.
- Mutually-authenticated TLS transport (rustls 0.23) plus a
  pre-shared-key TCP transport for development.
- An allow-listed file API, an interactive PTY shell, system-info
  collection, opt-in network discovery, opt-in remote-assistance, and
  opt-in HCI usage logging — each guarded by an explicit feature flag
  and, where applicable, a consent file.
- A signed-and-encrypted plugin loader that executes capability modules
  in process memory.
- Structured per-command audit logging written as HMAC-SHA256-signed
  JSON-lines for tamper-evidence.
- Configurable policy enforcement via TOML, hot-reloadable at runtime.
- Cross-platform CI for Linux, macOS, and Windows, plus a `cargo audit`
  job and a tag-driven release workflow that produces signed archives.

Orchestra is intended for use by authorized administrators on systems
they own or are explicitly authorized to manage.
