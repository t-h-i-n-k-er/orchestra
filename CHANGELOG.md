# Changelog

All notable changes to Orchestra are documented here.

---

## [Unreleased]

### Added

#### NTDLL Unhooking (`agent/ntdll_unhook.rs`)
- **Full NTDLL .text re-fetch pipeline** — Replaces the hooked ntdll `.text` section
  with a clean copy from `\KnownDlls\ntdll.dll`, falling back to disk read via
  `NtCreateFile` + `NtReadFile` when KnownDlls is unavailable.
- **Hook detection** — `are_syscall_stubs_hooked()` inspects 23 critical syscall
  stubs for inline hooks (`E9 jmp`, `FF 25 jmp`, `ud2`, `ret`, `EB jmp`).
- **Chunked overwrite with anti-EDR delays** — 4 KiB chunks with 50 µs inter-chunk
  delay to avoid bulk-write signatures. Post-unhook `NtQueryPerformanceCounter`
  normalization call.
- **Halo's Gate unhook callback** — `nt_syscall::set_halo_gate_fallback()` registers
  the unhook callback; `nt_syscall::invalidate_ssn_cache()` purges stale SSNs.
  When Halo's Gate fails (all adjacent stubs hooked), the callback triggers a full
  unhook automatically.
- **Post-sleep wake hook re-check** — Sleep obfuscation step 12 calls
  `ntdll_unhook::maybe_unhook()` to detect hooks EDR placed while the agent was
  dormant.
- **On-demand `UnhookNtdll` command** — Operator-initiated unhook with
  `UnhookResult { method, bytes_overwritten, hooks_detected, stubs_re_resolved, error }`.

#### .NET Assembly Loader (`agent/assembly_loader.rs`)
- **In-process .NET Framework 4.x assembly execution** via CLR hosting (`mscoree.dll`
  → `CLRCreateInstance` → `ICLRRuntimeHost::ExecuteInDefaultAppDomain`).
- **Lazy CLR initialization** — First call loads CLR; stays loaded for subsequent calls.
- **Fresh AppDomain per execution** — Isolated execution, auto-unloaded on completion.
- **AMSI bypass applied pre-execution** — HWBP or memory-patch bypass active during
  assembly load.
- **5-minute idle auto-teardown** — CLR resources released after 5 minutes idle.
- **Configurable timeout** — Default 60 seconds, max 4 MiB output.

#### BOF / COFF Loader (`agent/coff_loader.rs`)
- **Beacon Object File execution** compatible with the public Cobalt Strike BOF ecosystem.
- **Beacon-compatible API** — 18 exports: `BeaconPrintf`, `BeaconOutput`, `BeaconDataParse`,
  `BeaconDataInt`, `BeaconDataShort`, `BeaconDataLength`, `BeaconDataExtract`,
  `BeaconFormatAlloc`, `BeaconFormatPrintf`, `BeaconFormatToString`, `BeaconFormatFree`,
  `BeaconFormatInt`, `BeaconUseToken`, `BeaconRevertToken`, `BeaconIsAdmin`, `toNative`.
- **COFF relocation support** — `IMAGE_REL_AMD64_ADDR64`, `ADDR32NB`, `REL32`.
- **Max BOF 1 MiB**, max output 1 MiB, synchronous execution.

#### Browser Data Extraction (`agent/browser_data.rs`)
- **Chrome credential and cookie extraction** — Handles App-Bound Encryption (v127+)
  with three bypass strategies: Local COM (`IElevator`), SYSTEM token + DPAPI,
  Named-pipe IPC.
- **Edge credential and cookie extraction** — Same Chromium engine as Chrome.
- **Firefox credential and cookie extraction** — NSS runtime DLL loading, `logins.json`
  + `key4.db` parsing.
- **Custom minimal SQLite parser** — No external dependency for reading Login Data
  and Cookies databases.
- **Gated by `browser-data` feature flag** — `#[cfg(all(windows, feature = "browser-data"))]`.

#### Interactive Shell Sessions (`agent/interactive_shell.rs`)
- **Full interactive PTY/shell sessions** — `cmd.exe` (Windows), `/bin/sh` or custom
  (Linux/macOS).
- **Background reader threads** — Non-blocking stdout/stderr capture.
- **Async output delivery** — `Message::ShellOutput` with session_id, stream type, data.
- **Sleep obfuscation integration** — `pause_all_readers()` / `resume_all_readers()`
  to prevent data corruption during sleep encryption.
- **Session management** — `CreateShell`, `ShellInput`, `ShellClose`, `ShellList`,
  `ShellResize`.

#### LSASS Credential Harvesting (`agent/lsass_harvest.rs`)
- **Incremental LSASS memory reading** via indirect syscalls (`NtReadVirtualMemory`).
- **No MiniDumpWriteDump** — All credential parsing in-process, no disk writes.
- **Build-specific offset tables** — Windows builds 19041 through 26100 (Win10 2004
  through Win11 24H2).
- **Credential type extraction** — MSV1.0 (NT hashes), WDigest (plaintext), Kerberos
  (TGT/TGS), DPAPI master keys, DCC2 (domain cached credentials).

#### Surveillance Module (`agent/surveillance.rs`)
- **Screenshot capture** — Multi-monitor via Win32 API, PNG output.
- **Keylogger** — `SetWindowsHookExW(WH_KEYBOARD_LL)` with encrypted ring buffer.
- **Clipboard monitoring** — `OpenClipboard` + `GetClipboardData` with encrypted ring buffer.
- **Encrypted storage** — ChaCha20-Poly1305 ring buffers for all captured data.
- **Gated by `surveillance` feature flag** — `#[cfg(feature = "surveillance")]`,
  requires `dep:image`.

#### Injection Engine Expansion (`agent/injection_engine.rs`)
- **ThreadPool injection** — 8 sub-variants: `TpAllocWork`, `TpPostWork`,
  `CreateTimerQueueTimer`, `RegisterWaitForSingleObject`, and more.
- **Fiber injection** — `CreateFiber` → `SwitchToFiber`.
- **Context-only injection** — `SetThreadContext` RIP rewrite without shellcode.
- **Section mapping injection** — `NtCreateSection` + `NtMapViewOfSection` dual-mapping.
- **Callback injection** — 12 Windows API callbacks (EnumChildWindows,
  CreateTimerQueueTimer, EnumSystemLocales, etc.).
- **`InjectionHandle`** with `enroll_sleep()` and `eject()` methods.

#### New Feature Flags
- **`surveillance`** — Screenshot, keylogger, clipboard monitoring (Windows, `dep:image`).
- **`browser-data`** — Browser credential/cookie extraction (Windows only).
- **`hwbp-amsi`** — Hardware breakpoint AMSI bypass (Windows only).

#### `common` crate
- **HMAC-SHA256 audit log signing** — `AuditLog::record()` now computes an
  HMAC-SHA256 tag over each JSON line and writes it as a paired line in the
  audit log. Tampered entries are flagged on read. The HMAC key is derived
  from the admin token via `AuditLog::derive_hmac_key()`.
- **Protocol version 2** — `PROTOCOL_VERSION` bumped to 2. Encrypted payloads
  now use the format `salt(32) ‖ nonce(12) ‖ ciphertext_with_tag`, with
  per-message HKDF key derivation from the PSK and embedded salt.
  `CryptoSession::decrypt_with_psk()` handles full wire-format decryption.
- **`VersionHandshake` message** — Agents send a `Message::VersionHandshake`
  as the first message on every new connection; the server echoes back its
  version. Mismatched versions log a warning.
- **P2P mesh wire protocol** — Full set of 16+ frame types in `p2p_proto`:
  `LinkRequest`, `LinkAccept`, `LinkReject`, `Heartbeat`, `Disconnect`,
  `DataForward`, `CertificateRevocation`, `QuarantineReport`, `KeyRotation`,
  `KeyRotationAck`, `RouteUpdate`, `RouteProbe`, `RouteProbeReply`,
  `DataAck`, `TopologyReport`, `BandwidthProbe`. All frames use a 10-byte
  header with per-link ChaCha20-Poly1305 encryption.
- **Distance-vector routing protocol** — `RouteEntry` struct with quality
  scoring (latency 40%, packet loss 40%, jitter 20%). Routes advertised via
  `RouteUpdate` frames every 60 seconds with automatic stale/expiry cleanup.

#### `orchestra-server` crate
- **Async build queue** — New `build_handler` module with configurable
  worker count (`max_concurrent_builds`), job tracking, output directory
  sandboxing, and automatic retention cleanup. REST API endpoints:
  `POST /api/build`, `GET /api/build/status/:id`, `GET /api/build/:id/download`.
- **DNS-over-HTTPS bridge** — New `doh_listener` module. When `doh_enabled = true`
  is set in the server config, the server accepts agent sessions over DNS TXT/A
  queries with IP-based rate limiting and staged authentication.
- **Mutual TLS (agent channel)** — New server config fields: `mtls_enabled`,
  `mtls_ca_cert_path`, `mtls_allowed_cns`, `mtls_allowed_ous`. When enabled,
  the agent-facing TCP listener requires valid client certificates.
- **Interactive shell API** — New REST endpoints for managing PTY sessions
  through the dashboard: `POST /agents/:id/shell`, `POST /agents/:id/shell/:sid/input`,
  `GET /agents/:id/shell/:sid/output`.
- **Server config expansions** — New fields: `builds_output_dir`,
  `build_retention_days`, `max_concurrent_builds`, `doh_enabled`,
  `doh_listen_addr`, `doh_domain`, `doh_beacon_sentinel`, `doh_idle_ip`,
  `agent_traffic_profile`, `mtls_enabled`, `mtls_ca_cert_path`,
  `mtls_allowed_cns`, `mtls_allowed_ous`.
- **Mesh controller** — New mesh controller module for server-side topology
  management. REST endpoints: `GET /mesh/topology`, `GET /mesh/stats`,
  `POST /mesh/connect`, `POST /mesh/disconnect`, `POST /mesh/kill-switch`,
  `POST /mesh/quarantine`, `POST /mesh/clear-quarantine`,
  `POST /mesh/set-compartment`, `POST /mesh/route`, `POST /mesh/broadcast`.
- **Server mesh commands** — Commands to manage mesh: `MeshConnect`,
  `MeshDisconnect`, `MeshKillSwitch`, `MeshQuarantine`,
  `MeshClearQuarantine`, `MeshSetCompartment`, `MeshListTopology`,
  `MeshListLinks`, `MeshBroadcast`.

#### `agent` crate
- **`stack-spoof` feature** — Spoofs the user-mode call stack visible to EDR
  kernel callbacks during indirect syscall dispatch on Windows x86-64.
  Implies `direct-syscalls`.
- **`hot-reload` feature** — Enables runtime config hot-reload via the
  `notify` crate.
- **Full P2P mesh topology** — `MeshMode` enum with Tree/Mesh/Hybrid modes.
  Tree for strict hierarchy, Mesh for full peer-to-peer, Hybrid for balanced
  tree backbone with peer shortcuts (default).
- **Dynamic route discovery** — Distance-vector routing with `RouteUpdate`
  frames. Automatic route quality scoring, stale/expiry cleanup, and
  fallback to server relay when no mesh route exists.
- **Link quality monitoring** — Per-link latency (heartbeat RTT), jitter
  (stddev), packet loss (missed heartbeat ratio), and bandwidth (periodic
  probes). Quality = 40% latency + 40% loss + 20% jitter.
- **Link healing** — Dead link detection (heartbeat timeout, read errors).
  Automatic reconnection with exponential backoff. Route table cleanup and
  re-discovery after reconnection.
- **Adaptive relay selection** — Relay hop chosen by 70% route quality +
  30% inverse hop count. Weighted round-robin for ties within 10%. Congestion
  detection penalizes links with >64 KiB pending data.
- **Server-signed mesh certificates** — Ed25519-signed certificates binding
  agent_id_hash to public key. 24h lifetime, 2h renewal window, automatic
  revocation propagation through `CertificateRevocation` frames.
- **Per-link encryption** — X25519 ECDH handshake → HKDF-derived
  ChaCha20-Poly1305 keys. Every frame payload encrypted independently.
- **Compromise containment** — Kill switch (terminate all P2P links),
  quarantine (isolate agent while keeping server connection), compartment
  isolation (agents only peer within same compartment).
- **Periodic link key rotation** — Automatic 4-hour key rotation per link
  with 30-second overlap period. 3 retries with 60s timeout on failure.
- **Bandwidth-aware relay throttling** — Per-link relay throttle based on
  measured bandwidth. Congestion detection with high/low thresholds.

#### `agent` crate
- **`env_check` module** — Trusted Execution Environment (TEE) enforcement:
  `is_debugger_present()`, `detect_vm()`, `validate_domain(required)`, and
  `enforce()`. Agents can be configured to terminate or degrade gracefully when
  running outside an approved execution context (no debugger, no hypervisor,
  correct Active Directory domain).
- **`remote_assist` updated for enigo 0.2 API** — Constructor changed to
  `Enigo::new(&Settings::default())?`, `key_sequence` replaced by `.text()`,
  `mouse_move_to` replaced by `.move_mouse(x, y, Coordinate::Abs)`.
- **enigo `x11rb` backend** — Linux build now uses `default-features = false,
  features = ["x11rb"]` for `enigo`, eliminating the `libxdo-dev` system
  dependency while retaining full X11 keyboard/mouse simulation.
- **`x11cap` vendor patch** — Local fork of `x11cap 0.1.0` at `vendor/x11cap/`
  replaces the removed `Unique<T>` nightly feature with `NonNull<T>`, allowing
  compilation on stable Rust 1.95+. RGB8 fields are now `pub`.

#### `builder` crate
- **Runtime feature discovery** — `config::read_agent_features()` parses
  `agent/Cargo.toml` at runtime so the interactive configure menu always
  reflects the current feature set without manual maintenance.
- **Unknown-feature guard** — `partition_features()` splits user-requested
  features into known and unknown sets; unknown features emit a warning and are
  excluded from the build invocation.
- **Software Diversification** - The `optimizer` crate and `builder` CLI have been enhanced to support build-time code diversification. This feature helps evade static signature-based detection by producing a unique binary on each build.
    - `optimizer` - Added several new transformation passes:
    - `InstructionSubstitutionPass`: Substitutes instructions with semantically equivalent forms (6 patterns: `ADD<->INC`, `SUB<->DEC`, `MOV->XOR`, `XOR<->SUB`, `TEST<->CMP`, `AND->XOR`).
    - `OpaqueDeadCodePass`: Inserts dead-code blocks with opaque predicates.
    - `InstructionSchedulingPass`: Currently disabled (no-op) and planned to be enabled in a future release after dependency-safe scheduling is implemented.
    - `builder` - A new `--diversify` flag was added to the `build` command. When used, it applies the full set of optimizer passes to the agent binary before encryption, ensuring each build has a unique byte pattern.

### Changed

- **Network Discovery**: Optimized TCP port scanning to run concurrently using a configurable concurrency limit (defaults to 50 concurrent connections). Additionally, reduced the TCP connect timeout per port from a fixed 500ms to a configurable 200ms default via the agent payload profile. This drastically improves the efficiency when scanning subnets.
- `hollowing` - The `hollow_and_execute` function was refactored to correctly map PE files into a host process. It now parses PE headers, maps sections to their virtual addresses, applies base relocations, resolves imports, and sets memory protections. An `NtUnmapViewOfSection` call was added to unmap the original host image before allocating memory for the new payload. This makes the process hollowing more robust.
- `module_loader` - The Windows loading path was overhauled to be completely in-memory, avoiding the temporary `.dll` disk writes that could trigger filesystem monitoring. It now unconditionally uses a custom PE mapper to inject the plugin directly into the process address space, mirroring the Linux `memfd` behavior. Additionally, the manual PE mapper in `manual_map.rs` was updated to resolve imports by walking the PEB/LDR list directly instead of calling `GetModuleHandleA` and `GetProcAddress`. This makes the loader more self-contained and resilient to hooks on standard Windows loader functions. A fallback to `LoadLibraryA` is included for compatibility with API sets.
- `agent/syscalls` - The direct syscall implementation was made more robust. The `get_syscall_id` function now scans for the `syscall` opcode to reliably find the system call number, even on hooked functions. The `syscall!` macro was fixed to handle multiple arguments correctly. Wrappers for `NtWriteVirtualMemory`, `NtProtectVirtualMemory`, and `NtCreateThreadEx` were added.
- **Stealth** - Several changes were made to reduce the agent's visibility on the host system.
    - `launcher` - The `memfd` name is now randomized to a benign-looking value (e.g., `systemd-journal-<pid>`). The `argv[0]` of the executed payload is set to a common value (`/usr/sbin/sshd`). A log message that could reveal the in-memory execution method was moved to debug-only builds.
    - `agent/persistence` - The Windows scheduled task name is now randomized to a benign value to avoid standing out.
- `agent/env_check` - The environment validation logic was improved. The CPUID hypervisor bit is now treated as a soft indicator for VM detection, reducing false positives on cloud and WSL2 environments. New anti-analysis checks were added for Linux, including detection of `LD_PRELOAD`, running tracer processes, and a timing check to detect slow emulation or single-stepping.
- `common/normalized_transport` - The fake `ClientHello` was randomized to better mimic real browser traffic. The cipher suite order is now shuffled per session, and common extensions like SNI, supported groups, and signature algorithms have been added. GREASE values are also included to improve compatibility with network inspection tools.
- **Forward Secrecy** - The `forward-secrecy` feature was integrated into the main agent and server connection flow. When enabled, an X25519 key exchange is performed after the TCP handshake to derive an ephemeral session key. This ensures that even if the long-term pre-shared key is compromised, past session traffic cannot be decrypted.
    - `agent/outbound` - The outbound connection logic now calls `fs_handshake_client` when the `forward-secrecy` feature is active.
    - `orchestra-server/agent_link` - The agent listener now calls `fs_handshake_server` when the `forward-secrecy` feature is active.
    - `agent/Cargo.toml` and `orchestra-server/Cargo.toml` - Added the `forward-secrecy` feature flag.
- `agent/persistence` - The persistence module was made more robust and stealthy.
    - The executable path is now derived at runtime using `std::env::current_exe()`, removing hardcoded paths.
    - Service and task names are now generic (e.g., `UserSessionHelper`) to avoid drawing attention.
    - Fallback persistence methods have been added: a `.desktop` autostart file on Linux and a `Run` registry key on Windows.
    - On Windows, the uninstaller now correctly removes the created persistence entry by storing the randomized task name in a marker file.

### Fixed

- `module_loader` — `MODULE_SIGNING_PUBKEY` was incorrectly reused as both a
  signing seed and a verifying key. Replaced with the actual 32-byte compressed
  point (verifying key) derived from the test seed, stored in a separate
  `MODULE_TEST_SIGNING_SEED` constant. Both tests (`test_load_and_execute_plugin`
  and `test_tampered_module_fails_verification`) now use consistent keys and pass
  with `--features module-signatures`.
- `common` — Removed manual `impl Default for TrafficProfile` and replaced with
  `#[derive(Default)]` + `#[default]` on the `Raw` variant (clippy
  `derivable_impls`).
- `agent/env_check` — Replaced `.iter().any(|p| *p == prefix)` with
  `.contains(&prefix)` (clippy `manual_contains`).
- `image 0.25` — Replaced removed `ImageOutputFormat::Png` with
  `image::ImageFormat::Png`.
- `ed25519-dalek 2.1` — Added `use ed25519_dalek::Signer;` where `.sign()` is
  called.

### Documentation

- **Comprehensive documentation overhaul** — Rewrote and expanded all project documentation:
  - `README.md` — Full rewrite with 11 sections: Architecture Overview, Workspace Crates, Feature Matrix, Quick Start, Malleable Profiles, Injection Engine, Sleep Obfuscation, Redirector Deployment, Configuration Reference, OPSEC Notes, and Building & Development.
  - `docs/ARCHITECTURE.md` — Deep-dive covering agent internals, syscall infrastructure, memory guard lifecycle, evasion subsystem, C2 state machine, wire protocol, server internals, P2P mesh protocol, cryptographic summary, module loading pipeline, persistence subsystem, and binary diversification stack.
  - `docs/MALLEABLE_PROFILES.md` — Exhaustive TOML reference with all sections, transform type deep-dive (None, Base64, Base64Url, Mask, Netbios, NetbiosU), data flow examples, and multi-profile server configuration.
  - `docs/INJECTION_ENGINE.md` — Full reference for all 6 injection techniques with memory layouts, pre-injection reconnaissance, decision flowchart, sleep enrollment, and cleanup procedures.
  - `docs/SLEEP_OBFUSCATION.md` — Memory region tracking, XChaCha20-Poly1305 encryption flow, stack encryption, integrity verification, XMM14/XMM15 key management, and performance benchmarks.
  - `docs/REDIRECTOR_GUIDE.md` — VPS setup, TLS provisioning, CLI reference, failover behavior, CDN integration, systemd service template, and deployment checklist.
  - `docs/OPERATOR_MANUAL.md` — Server management, agent building, profile management, injection technique selection, multi-operator workflows, audit log review, P2P mesh operations, and emergency procedures.
- **Inline rustdoc** — Added `///` and `//!` doc comments to all public API items across 13 source files: `common/src/lib.rs`, `agent/src/config.rs`, `agent/src/handlers.rs`, `agent/src/amsi_defense.rs`, `agent/src/fsops.rs`, `pe_resolve/src/lib.rs`, `hollowing/src/lib.rs`, `builder/src/lib.rs`, `optimizer/src/lib.rs`, `code_transform/src/lib.rs`, `string_crypt/src/lib.rs`, and `shellcode_packager/src/lib.rs`.
- **Cargo.toml descriptions** — Added accurate `description` fields to all 22 workspace crates.

### Build

- `cargo test --workspace --all-features` — **all tests pass** on Linux.
- `cargo clippy --workspace --all-features -- -D warnings` — **zero warnings**.
- `cargo fmt --all` — workspace fully formatted.
