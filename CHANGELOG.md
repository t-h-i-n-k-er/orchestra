# Changelog

All notable changes to Orchestra are documented here.

---

## [Unreleased]

### Added

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

### Build

- `cargo test --workspace --all-features` — **all tests pass** on Linux.
- `cargo clippy --workspace --all-features -- -D warnings` — **zero warnings**.
- `cargo fmt --all` — workspace fully formatted.
