# Orchestra — Deep Codebase Audit Prompt

> **Purpose:** Instruct an advanced coding model to perform an exhaustive correctness, completeness, and functional audit of the Orchestra framework — **static analysis augmented by local empirical testing on this dedicated dev device, zero source-file modifications.**

---

## Instructions for the Auditor Model

You are a senior systems-security engineer and Rust expert. Your task is to perform a **full-spectrum deep audit** of the Orchestra framework — a cross-platform (Linux, Windows, macOS) Rust implant framework with a C2 server, builder pipeline, and supporting tooling.

**Hard constraints:**

- **DO NOT** modify any source file, build script, configuration file, or documentation file — this audit must leave the codebase unchanged.
- **DO** read every relevant source file, build script, test, configuration file, and documentation page before drawing conclusions.
- **DO** produce a structured, prioritized report at the end.

**Local Testing Authorization:** This is a dedicated test and development device — you are explicitly authorized to perform empirical verification to confirm or refute your static-analysis findings. You may run `cargo check`, `cargo build`, `cargo test`, `cargo clippy`, and `cargo fmt -- --check` against any workspace crate, with any combination of feature flags, to surface compilation errors, type mismatches, and macro-expansion failures. You may spin up the Orchestra C2 server locally (e.g. via `scripts/dev-start.sh` or the dev-server crate) and exercise its REST API with `curl` to verify endpoint behavior, mTLS enforcement, build-queue lifecycle, and DoH bridge correctness. You may compile and run the Linux agent with any feature-flag subset to test env-check logic, persistence installation/removal, network-discovery scans, sleep-obfuscation encrypt/decrypt cycles, and shell-session creation — then verify side effects (systemd unit files, filesystem artifacts, process state) using standard Linux tools. You may run the full test suite (`cargo test --workspace`) and any individual crate or integration test to identify failures, panics, and assertion violations. You may inspect build outputs (binaries, artifacts under `builds/`, generated code) to verify correctness. **You may NOT modify any source file** — all testing must be read-only or idempotent (if a test installs persistence, clean it up afterward). Report any command that fails, panics, or produces unexpected output as a finding with the exact command, exit code, and stderr/stdout.

Begin by reading the following documents to orient yourself on the project's intended architecture and capabilities:

1. `docs/ARCHITECTURE.md` — full internal design
2. `docs/FEATURES.md` — all feature flags and what they promise
3. `docs/DESIGN.md` — high-level design philosophy
4. `docs/EVASION.md` — evasion subsystem contracts
5. `docs/INJECTION_ENGINE.md` — injection engine specification
6. `docs/POST_EXPLOITATION.md` — post-exploitation module contracts
7. `docs/SECURITY_AUDIT.md` — known security considerations
8. `docs/SLEEP_OBFUSCATION.md` — sleep obfuscation pipeline
9. `docs/P2P_MESH.md` — peer-to-peer mesh protocol
10. `docs/FORENSICS.md` — forensic cleanup pipeline
11. `docs/CONFIGURATION.md` — configuration schema
12. `ROADMAP.md` — completed vs. planned work
13. `CHANGELOG.md` — recent changes and known limitations
14. `Cargo.toml` (workspace root) — workspace layout
15. `agent/Cargo.toml` — feature flag definitions and dependency tree

Then systematically audit **every crate and module** in the workspace, checking for the categories of issues described below.

---

## Part 1 — Compilation & Macro-Expansion Correctness

Examine every file that uses inline assembly, procedural macros, or build-script code generation. Verify that:

- **`nt_syscall/src/lib.rs`** — inline `asm!()` blocks compile on all intended targets (x86_64 Windows, aarch64 Windows, x86_64 Linux, aarch64 Linux). Check register bindings, clobber lists, and calling-convention alignment for each architecture.
- **`nt_syscall/src/lib.rs`** — `syscall!()` macro expansion produces valid Rust for every supported arity and every feature-gated path (`direct-syscalls`, `stack-spoof`, `cet-bypass`, `syscall-emulation`).
- **`agent/build.rs`** — environment variable propagation (`SYS_MODULE_KEY`, `SYS_C_ADDR`, etc.) handles missing and malformed values gracefully.
- **`code_transform/`** and **`code_transform_macro/`** — proc-macro expansion produces syntactically valid output; attribute parsing is exhaustive.
- **`junk_macro/`** — macro generates compilable code across feature combinations.
- **`string_crypt/`** — build-time string encryption compiles and decrypts correctly at runtime.
- **`common/build.rs`** — any code generation is correct.
- **`pe_resolve/build.rs`** — PE parsing helpers compile.
- **`optimizer/build.rs`** — metamorphic engine build steps compile.
- **`orchestra-side-load-gen/build.rs`** — side-load DLL generation compiles.

For each issue found, note:
- File and line range
- The specific target / feature combination that breaks
- Whether `cargo check` would catch it or if it only manifests at runtime

---

## Part 2 — Logical Bugs & Algorithmic Errors

Trace the logic in these critical subsystems and identify any correctness flaws:

### 2.1 Process Hollowing & Injection Engine

- **`hollowing/src/`** — `hollow_and_execute()`: Verify the complete lifecycle (create suspended → unmap → write → fix imports → resume). Check for race conditions, handle leaks, and incorrect PE header manipulation.
- **`agent/src/injection_engine`** (wherever the unified engine lives) — All 15 `InjectionTechnique` variants: verify each technique's implementation matches its documented contract. Check for missing error paths, unguarded `unsafe` blocks, and incorrect memory-protection restoration.
- **`agent/src/` (transacted hollowing)** — NTFS transaction rollback path: confirm the section survives transaction rollback on all supported Windows versions.
- **`agent/src/` (delayed stomp)** — Timer-based delay mechanism: verify the stomp occurs after the legitimate DLL has fully initialized. Check for TOCTOU races.
- **`agent/src/` (module stomping)** — Verify the target DLL's `.text` section is correctly identified and overwritten without corrupting adjacent data.

### 2.2 Manual PE Mapping (`manual-map` feature)

- **`module_loader/`** — Reflective PE loading: verify section alignment, import resolution, relocation fixups, and entry-point invocation. Check for edge cases: forward exports, delay imports, TLS callbacks, bound imports, exception directories.
- Verify remote-process manual mapping handles ASLR base divergence correctly (acknowledged known limitation in ROADMAP.md).

### 2.3 C2 Transport Layer

- **`agent/src/c2_http.rs`** — Malleable profile application: verify URI selection, header injection, encoding transforms (Base64/Mask/NetBIOS), payload delivery modes (Cookie/URI/header/body). Check failover state machine for stuck states.
- **`agent/src/c2_doh.rs`** — DNS encoding correctness, record type handling, rate limiting logic.
- **`agent/src/c2_ssh.rs`** — SSH subsystem channel framing, keepalive handling, authentication fallback.
- **`agent/src/c2_smb.rs`** — Named pipe connection lifecycle, frame delimiting, error recovery.
- **`agent/src/c2_quic.rs`** — QUIC transport implementation completeness.
- **`agent/src/c2_graph.rs`** — Microsoft Graph API transport completeness.

### 2.4 Cryptographic Protocol

- **`common/src/` (wire protocol)** — Verify frame format: length prefix → salt(32) ‖ nonce(12) ‖ ciphertext+tag. Confirm HKDF-SHA256 derivation with info string `orchestra-v2`. Check for nonce reuse, key derivation edge cases, and forward-secrecy X25519 exchange correctness.
- **`agent/src/` (sleep obfuscation)** — XChaCha20-Poly1305 encryption of heap+stack. Verify key stash in XMM14/XMM15 is correctly saved/restored. Check for key material remaining in registers after wake.
- **`agent/src/` (RC4 stub in Cronus)** — Verify position-independent stub generation, S-box initialization, and RIP-relative addressing.

### 2.5 Syscall Infrastructure

- **`nt_syscall/`** — SSN resolution: verify `mov eax, IMM32` extraction handles all ntdll stub formats (including hooked stubs with different prologues).
- **Halo's Gate** — Adjacent-stub scanning logic: verify SSN offset calculation is correct for up to ±32-byte offsets.
- **NTDLL unhooking** — Verify chunked overwrite timing, protection restoration, and instruction cache flush.
- **SSN cache** — Verify `HashMap` concurrency safety (is it wrapped correctly?). Check build-number-based invalidation logic.
- **Syscall emulation** — Verify all 10 emulated syscall mappings produce equivalent behavior to their NT counterparts. Pay special attention to `NtCreateThreadEx` → `CreateRemoteThread` (no `CREATE_SUSPENDED` support).

### 2.6 Credential Access

- **`agent/src/lsass_harvest.rs`** — Incremental memory reading: verify offset tables for Windows builds 19041–26100. Check MSV/WDigest/Kerberos/DPAPI/DCC2 parsing for structure alignment errors.
- **`agent/src/browser_data.rs`** — Chrome v127+ App-Bound Encryption bypass: verify all 3 strategies. Check custom SQLite parser for edge cases (WAL mode, journal mode, corrupted headers). Verify NSS `key4.db` and `logins.json` parsing.
- **LSA Whisperer** — SSP installation path: verify `SpAcceptCredentials` callback receives and stores credentials correctly.

### 2.7 Token & Privilege Operations

- **Token impersonation** — Verify SetThreadToken path: confirm impersonation token is properly duplicated and that RevertToSelf is called before the main thread ever accesses the token.
- **Token manipulation** — `MakeToken`, `StealToken`, `Rev2Self`, `GetSystem`: verify thread-safe impersonation state doesn't leak across tasks.

### 2.8 Evasion Subsystem

- **AMSI bypass (Write-Raid)** — Verify race thread timing, `AmsiInitFailed` flag address resolution from `AmsiInitialize` prologue, and sleep-obfuscation pause integration.
- **AMSI bypass (HWBP)** — Verify DR0/DR1/DR7 register manipulation on x86_64 and BVR/BCR on ARM64.
- **AMSI bypass (Memory Patch)** — Verify fallback to `E_INVALIDARG` prologue patching.
- **ETW patching** — Verify patch mode logic (Safe/Always/Never) and restoration of original protection.
- **Evasion transform** — Verify semantic preservation for all 5 transform types.

### 2.9 Memory Management

- **`memory_guard`** — Verify XChaCha20-Poly1305 encrypt/decrypt cycle is lossless. Check `Drop` implementation guarantees zeroization.
- **`evanesco` / `page_tracker`** — VEH handler: verify page-fault → decrypt → re-execute flow doesn't infinite-loop. Verify background re-encryption thread doesn't encrypt pages that are currently in use (race condition).
- **Sleep obfuscation** — Verify full encrypt/decrypt cycle covers all registered regions. Check for memory regions that should be encrypted but aren't registered.

### 2.10 Forensic Cleanup

- **Prefetch patching** — Verify PF header format parsing for v17/v23/v26/v30. Check USN journal consistency operations.
- **USN journal cleanup** — Verify selective deletion doesn't corrupt journal structure.
- **MFT timestamp restoration** — Verify `NtSetInformationFile` call correctness.
- **`$LogFile` cleanup** — Verify page checksum recalculation.

---

## Part 3 — Incomplete, Stubbed, or Placeholder Code

Identify any code that:

- Contains `todo!()`, `unimplemented!()`, `panic!("not implemented")`, or equivalent
- Returns hardcoded placeholder values (e.g., empty strings, `Ok(0)`, dummy data)
- Is gated behind a feature flag that compiles but has no substantive implementation
- Contains `// TODO`, `// FIXME`, `// HACK`, `// STUB`, `// PLACEHOLDER` comments
- Has a function signature and documentation but an empty or trivially minimal body
- Is listed in `docs/FEATURES.md` or `docs/ARCHITECTURE.md` as functional but is actually a no-op or returns `Unsupported` / `Err("not implemented")`
- Imports a dependency in `Cargo.toml` that is never referenced in code, or vice versa

For each finding, classify severity:
- **High** — Advertised feature that does nothing or returns wrong results silently
- **Medium** — Feature partially implemented with known gaps
- **Low** — Intentional stub with clear `// TODO` marker

---

## Part 4 — Platform-Specific Issues

For each of the three supported platforms, identify:

### Linux (x86_64 and aarch64)
- `agent/src/` — Linux `direct_syscalls` inline assembly: verify syscall number tables, argument passing (6-arg limit with `EINVAL` fallback), and error code handling.
- `agent/src/` — eBPF modules (`agent/ebpf/*.bpf.c`): verify BPF program correctness, map definitions, and userspace loader integration.
- `agent/src/` — Container escape (`container-escape` feature): verify completeness.
- `agent/src/` — Linux persistence (systemd user unit): verify unit file generation and enabling.
- `agent/src/` — Linux env checks (`/proc/self/status` TracerPid, CPUID, DMI strings): verify robustness.

### Windows (x86_64 and aarch64)
- **ARM64-specific**: Verify all inline assembly paths have ARM64 alternatives. Check BTI/PAC bypass (`pac-bypass` feature) implementation. Verify syscall dispatch uses x8 SSN register.
- **x86_64-specific**: Verify CET bypass strategies all compile and have correct logic. Verify stack-spoofing chain templates have valid unwind metadata.
- Verify all Windows API calls use the correct Unicode (W) variants where applicable.
- Verify `cfg(target_arch)` and `cfg(target_os)` gates are consistent and complete.

### macOS (x86_64 and aarch64)
- `agent/src/` — macOS persistence (LaunchAgent, ServiceManagement): verify both code paths.
- `agent/src/` — macOS env checks: verify `/etc/resolv.conf` parsing, IMDS reachability check.
- `agent/src/` — macOS cloud instance detection: verify graceful degradation when IMDS is unavailable.
- `agent/src/` — `macos-postexp` feature: verify TCC/SIP/XPC/Keychain module completeness.
- Identify any macOS modules that are placeholder-only.

### Cross-Platform Consistency
- Verify that `#[cfg(...)]` gates don't accidentally exclude platform-specific code that is needed.
- Verify that all `unsafe` blocks have safety comments.
- Verify that error handling is consistent across platforms (no silent failures on one platform that are loud on another).

---

## Part 5 — Environment Check & False Positive Analysis

Audit the environment validation subsystem (`env-validation` feature) for correctness and false-positive risk:

### 5.1 Hypervisor Detection
- Verify the CPUID hypervisor bit check doesn't trigger on bare-metal servers with virtualization-enabled BIOS.
- Verify the adaptive VM detection tier system (Tier 1/2/3) correctly distinguishes:
  - Bare-metal hypervisors ( VMware/VirtualBox on workstations)
  - Cloud instances (AWS/Azure/GCP with expected hypervisors + IMDS)
  - Legitimate cloud workloads that should NOT trigger exit
- Verify cloud whitelisting controls (`cloud_instance_allow_without_imds`, `cloud_instance_fallback_ids`) handle all documented cloud providers.

### 5.2 Sandbox Detection
- Verify the weighted indicator scoring system doesn't produce false positives on:
  - CI/CD runner environments
  - Containerized production workloads
  - Hardened corporate endpoints with EDR
- Verify the `sandbox_score_threshold` configuration actually gates the exit behavior.

### 5.3 Debugger Detection
- Verify `TracerPid` parsing handles all `/proc/self/status` format variants on Linux.
- Verify `IsDebuggerPresent()` check on Windows handles both user-mode and kernel-mode debuggers.
- Verify `seh-anti-debug` feature implementation completeness.

### 5.4 Domain Validation
- Verify AD domain detection on Linux parses all valid `/etc/resolv.conf` formats (including `search` with multiple domains).
- Verify Windows registry path for domain detection is correct across Windows 10/11 versions.
- Verify AAD/Entra ID join detection works.

---

## Part 6 — Server & Builder Infrastructure

### 6.1 Orchestra Server (`orchestra-server/`)
- Verify REST API endpoint correctness (`POST /api/build`, status polling, artifact download).
- Verify mTLS enforcement and CN/OU filtering.
- Verify async build queue worker pool: race conditions, resource cleanup, timeout handling.
- Verify DNS-over-HTTPS bridge (`doh_listener`): rate limiting, encoding correctness.
- Verify HMAC-SHA256 audit log signing and tamper detection on read.
- Verify static file serving for the web dashboard.

### 6.2 Builder (`builder/`)
- Verify `read_agent_features()` correctly parses `agent/Cargo.toml` and handles unknown features.
- Verify environment variable propagation chain: server config → `PayloadConfig` → build worker → `cargo:rustc-env` → `option_env!()`.
- Verify profile TOML parsing and feature flag validation.
- Verify build artifact packaging and signing.

### 6.3 Supporting Crates
- **`payload-packager/`** — Verify polymorphic payload layout variation and encryption.
- **`shellcode_packager/`** — Verify shellcode extraction and packaging.
- **`orchestra-pe-hardener/`** — Verify PE hardening operations (checksum recalculation, section manipulation).
- **`orchestra-side-load-gen/`** — Verify DLL generation and export forwarding.
- **`redirector/`** — Verify traffic forwarding logic.
- **`keygen/`** — Verify key generation correctness.
- **`optimizer/`** — Verify metamorphic transformation correctness and semantic preservation.
- **`uefi-persistence/`** — Verify UEFI NVRAM/ESP operations.

---

## Part 7 — Dependency & Supply Chain

- Verify all `Cargo.toml` dependency versions are pinned or have minimum-version constraints.
- Check for any dependency that is unused but listed.
- Check for any dependency version conflict across workspace members.
- Verify `Cargo.lock` is committed and consistent.
- Run `cargo audit` if available, or manually identify any dependency with known vulnerabilities (flag suspiciously old or unmaintained crates).

---

## Part 8 — Test Coverage Assessment

- **`agent/tests/`** — Identify what is tested and what is not.
- **`agent/benches/`** — Verify benchmark harnesses are meaningful.
- **`code_transform/tests/`** — Verify transform correctness tests.
- **`code_transform_macro/tests/`** — Verify macro expansion tests.
- **`orchestra-server/tests/`** — Verify API integration tests.
- **`launcher/tests/`** — Verify launcher tests.
- Identify critical subsystems that have **zero test coverage**.

---

## Part 9 — Functional Status Matrix

After completing the above analysis, produce a **feature-by-feature functional status matrix** in the following format:

| Feature / Module | Crate/Path | Status | Notes |
|-----------------|------------|--------|-------|
| (feature name) | (file path) | ✅ Functional / ⚠️ Partial / ❌ Broken / 🚫 Stub / 🔒 Needs specific env | (brief explanation) |

Cover **all** of the following features/modules:

**Core:**
- Config loading & hot-reload
- Env validation (debugger/VM/sandbox/domain)
- Command dispatch (handlers.rs, 70+ commands)
- Module/plugin loader
- Interactive PTY shell

**Transport:**
- HTTP malleable C2
- DNS-over-HTTPS C2
- SSH subsystem C2
- SMB named pipe C2
- QUIC/HTTP3 C2
- Microsoft Graph C2
- Forward secrecy (X25519)

**Windows Injection (15 techniques):**
- Process Hollowing, ThreadPool (8 sub-variants), Fiber, Context-Only, Section Mapping, NtSetInformationProcess, Waiting Thread Hijack, Transacted Hollowing, Delayed Stomp, Existing Module Stomp, Phantom DLL Hollowing, Callback (12 APIs)

**Windows Evasion:**
- Direct/indirect syscalls (nt_syscall)
- NTDLL unhooking (KnownDlls + disk fallback)
- Halo's Gate
- AMSI bypass (Write-Raid / HWBP / Memory Patch)
- ETW patching (Safe/Always/Never)
- CET/shadow-stack bypass (3 strategies)
- Stack spoofing (NtContinue multi-frame)
- Syscall emulation (10 mapped APIs)
- Evasion transform (5 types)
- Self-reencode

**Windows Credential Access:**
- LSASS harvest (incremental memory read)
- LSA Whisperer (SSP)
- Browser data (Chrome/Edge/Firefox)
- Token manipulation & impersonation
- DPAPI backup key retrieval

**Windows Forensics:**
- Prefetch cleanup (Patch/Delete/Disable)
- USN journal cleanup
- MFT timestamp manipulation
- $LogFile cleanup

**Cross-Platform:**
- Sleep obfuscation (Ekko / Cronus)
- Memory guard
- Evanesco (continuous memory hiding)
- Network discovery (ARP/ping/TCP)
- Persistence (systemd/schtasks/launchd)
- Remote assist (screen capture/input sim)
- Browser data extraction
- eBPF hiding (Linux)

**Post-Exploitation:**
- .NET assembly loader
- BOF/COFF loader
- Lateral movement (PsExec/WmiExec/DcomExec/WinRmExec)
- P2P mesh (SMB/TCP relay)
- Kerberos relay / S4U abuse / Shadow Credentials
- ADCS attacks (ESC1-ESC8)
- Container escape (Linux)
- WSL2 evasion
- COM hijack
- LOLBIN xwizard
- VSS pivot
- Entra ID attacks
- Hardware/firmware persistence
- LPE modules
- macOS post-exploitation
- BTI/PAC bypass (ARM64)

**Infrastructure:**
- Orchestra server (REST API, mTLS, build queue)
- Builder (feature discovery, env propagation)
- Payload packager
- Shellcode packager
- PE hardener
- Side-load generator
- Redirector
- Keygen
- Optimizer
- UEFI persistence
- ZAI provider extension (VS Code)

---

## Part 10 — Output Format

Structure your final report as follows:

```
# Orchestra Deep Audit Report

## Executive Summary
(Brief overview of codebase health: X critical issues, Y high, Z medium, W low)

## Critical Issues (will cause runtime failure or silent misbehavior)
1. [CRIT-001] Description → File:Line → Impact → Reproduction path
...

## High Issues (feature advertised but broken/incomplete)
1. [HIGH-001] Description → File:Line → Impact → Evidence
...

## Medium Issues (partial implementation, edge-case failures)
1. [MED-001] Description → File:Line → Impact → Evidence
...

## Low Issues (stubs, TODOs, minor inconsistencies)
1. [LOW-001] Description → File:Line → Notes
...

## Platform-Specific Findings
### Linux
...
### Windows
...
### macOS
...

## False-Positive / False-Negative Risks
(Environment checks that may incorrectly block or allow execution)
...

## Dependency & Build Issues
...

## Test Coverage Gaps
(List of critical subsystems with zero test coverage)
...

## Functional Status Matrix
(The full table from Part 9)

## Appendix: Files Audited
(Complete list of source files examined)
```

---

## Final Reminders

- **Read before concluding.** Do not assume a module is broken without reading its source. Do not assume a module works without tracing its logic.
- **Distinguish** between "intentionally not implemented" (feature-gated off) and "advertised but broken" (feature-gated on but non-functional).
- **Distinguish** between "known limitation documented in ROADMAP.md" and "undocumented bug."
- **Cross-reference** documentation claims against actual implementation. If `ARCHITECTURE.md` says a module does X but the code does Y, that is a finding.
- **Be specific.** Every finding must include the exact file path and a description of what is wrong. Vague statements like "the injection engine has issues" are not useful.
- **Prioritize.** A crash in a core path is more important than a typo in a comment.