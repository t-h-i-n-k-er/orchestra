# Orchestra Deep Audit Report

**Date:** 2025-01-26  
**Scope:** Full-spectrum static analysis of the Orchestra framework — 24+ crates, 139+ agent source files, server, builder, and supporting infrastructure.  
**Methodology:** Read-only audit; no source files modified. Subsystem-level subagent audits combined with cross-referencing documentation claims against implementation.

---

## Executive Summary

The Orchestra framework is a large, ambitious cross-platform Rust implant/C2 framework with 70+ feature flags, 120+ command handlers, 15 injection techniques, and 6 transport types. The codebase demonstrates strong systems programming fundamentals — comprehensive `#[cfg]` platform gating, indirect syscall infrastructure, and well-structured module boundaries.

**However**, the audit identified **6 critical**, **14 high**, **27 medium**, and **19 low** issues across the framework. The most systemic risk is **pervasive `.lock().unwrap()` on global Mutexes** (80+ call sites in 15+ files), which creates a poisoned-mutex cascade that can crash the agent irrecoverably from a single thread panic. The second systemic risk is **unsafe memory operations without adequate fallbacks** in the self-reencoding, page-fault-exec, and sleep-obfuscation subsystems.

| Severity | Count | Summary |
|----------|-------|---------|
| **CRITICAL** | 6 | Agent crash / undefined behavior under real-world conditions |
| **HIGH** | 14 | Feature failure, data corruption, OPSEC compromise |
| **MEDIUM** | 27 | Partial failures, race conditions, edge-case bugs |
| **LOW** | 19 | Stubs, TODOs, minor inconsistencies |
| **Total** | **66** | |

**Dependency health** is moderate — 6 widely-shared dependencies lack workspace inheritance, 4+ crates have unused dependencies, and dual logging (`log` + `tracing`) adds maintenance burden.

**Test coverage** is adequate for core crypto and server E2E, but 20+ attack modules and 4 entire crates (`console`, `redirector`, `keygen`, `nt_syscall`) have zero test coverage.

---

## Critical Issues (will cause runtime failure or silent misbehavior)

### [CRIT-001] Pervasive `.lock().unwrap()` — Poisoned Mutex Cascade

**Files:** `handlers.rs` (16 sites), `syscalls.rs` (15 sites), `surveillance.rs` (10 sites), `hci_logging.rs` (14 sites), `stack_spoof.rs` (8 sites), `sleep_obfuscation.rs` (5 sites), `lsa_whisperer.rs` (4 sites), `c2_smb.rs` (5 sites), `stack_db.rs` (6 sites), `edr_bypass_transform.rs` (2 sites), `edr_bypass_transform_aarch64.rs` (2 sites), `token_impersonation.rs` (1 site), `etw_patch.rs` (2 sites), `remote_assist.rs` (1 site), `interactive_shell.rs` (1 site)

**Total:** 80+ call sites across 15+ files.

**Impact:** Any thread panic while holding a `Mutex` poisons it. Every subsequent `.lock().unwrap()` on that Mutex also panics, cascading the failure across the entire agent. Since `handlers.rs` command dispatch and `syscalls.rs` SSN cache are accessed on every C2 check-in, a single panic in any handler permanently kills the agent.

**Recommendation:** Replace with `.lock().unwrap_or_else(|e| e.into_inner())` or add a `LockResult<T>` wrapper that recovers from poison globally.

---

### [CRIT-002] Self-Reencoding Modifies `.text` Without Verifying Thread Suspension

**File:** `self_reencode.rs` (full module)

**Impact:** The module suspends all sibling OS threads via `NtSuspendThread`/`tgkill(SIGSTOP)` before rewriting the `.text` section in-place. If `NtSuspendThread` fails for any thread (access denied, handle invalid, thread already terminating), that thread continues executing while its code pages are being rewritten. This causes:
- Execution of partially rewritten instructions
- CPU exception (illegal instruction / access violation)
- Silent corruption of operational state (wrong encryption keys, corrupted command dispatch)

This is the most dangerous single-point-of-failure because it modifies the agent's own executable code.

**Recommendation:** Add a verification loop after suspension — call `NtQueryInformationThread(ThreadBasicInformation)` or `WaitForSingleObject(timeout=0)` to confirm each thread is actually suspended. Abort the re-encoding pass if any thread fails to suspend.

---

### [CRIT-003] `compare_export_name` Binary Search Bug in nt_syscall

**File:** `nt_syscall/src/lib.rs` (SSN resolution, `compare_export_name` function)

**Impact:** When the remote string is a **prefix** of the target string (e.g., searching for "NtCreate" but the export is "NtCreateThread"), the comparison returns `+1` instead of `-1`. This causes the binary search to skip valid entries, potentially resolving the wrong SSN for kernel export lookup. Since SSN resolution is the foundation of all syscall operations, an incorrect SSN causes all subsequent syscalls to invoke the wrong kernel function.

**Recommendation:** Fix the comparison logic to correctly handle the prefix case by comparing lengths when the shared prefix matches.

---

### [CRIT-004] PageGuard Re-encrypt Silently Skips on Poisoned Lock

**File:** `sleep_obfuscation.rs` (re-encryption path), `page_tracker.rs`

**Impact:** If the PageGuard Mutex is poisoned (e.g., due to a panic during a previous encrypt/decrypt cycle), all subsequent re-encryption attempts silently skip, leaving pages **decrypted indefinitely**. This defeats the entire sleep obfuscation mechanism and leaves the agent's memory readable by EDR/AV scanners.

**Recommendation:** Recover from poison on the re-encryption path — always encrypt, even if the lock was poisoned.

---

### [CRIT-005] `c2_graph.rs` Has No Kill Date Enforcement

**File:** `agent/src/c2_graph.rs` (Graph API transport)

**Impact:** The Graph transport does not check the configured kill date. When the kill date passes, agents using HTTP/DoH/SSH/SMB/QUIC transports will self-terminate, but Graph-connected agents will continue operating indefinitely. This is an OPSEC violation — agents that should have expired remain active.

**Recommendation:** Add the same kill-date check used by `c2_http.rs` to `c2_graph.rs`.

---

### [CRIT-006] Race Condition in Sleep Obfuscation Region Cache — Non-Atomic Generation Check

**File:** `sleep_obfuscation.rs` (region cache, `REGION_GENERATION` atomic)

**Impact:** The generation counter check is not atomic with the cache update. Two concurrent `secure_sleep` calls can both observe the same stale generation and both attempt to rebuild the cache simultaneously. While the Mutex prevents data corruption, the double enumeration wastes time and can cause one caller to operate on a partially rebuilt cache.

**Recommendation:** Use a single lock-protected struct that combines the generation counter and the cache data, eliminating the TOCTOU window.

---

## High Issues (feature advertised but broken/incomplete)

### [HIGH-001] `c2_quic.rs` and `c2_graph.rs` Lack ECDH Forward Secrecy

**Files:** `agent/src/c2_quic.rs`, `agent/src/c2_graph.rs`

**Impact:** Only `c2_http.rs` and `c2_doh.rs` implement the X25519 ECDH forward-secrecy exchange. QUIC and Graph transports use only static AES-256-GCM keys. If a session key is compromised, all past and future traffic on these transports is decryptable.

**Recommendation:** Implement the same `CryptoSession::establish_forward_secrecy()` handshake in QUIC and Graph transports.

---

### [HIGH-002] SyncCell Unsafe Sync in `page_fault_exec.rs` — VEH Fires on Any Thread

**File:** `page_fault_exec.rs:23-26`

**Impact:** `SyncCell<T>` wraps `UnsafeCell<T>` with `unsafe impl Sync`, claiming "all access is single-threaded by design." However:
- VEH handlers fire on **any** thread that triggers `STATUS_ACCESS_VIOLATION`
- Timer APCs fire on the thread that set the timer, which may not be the current thread
- If multiple threads fault into protected pages simultaneously, multiple VEH invocations race on the same `ProtectedPage` data

This is a data race that can corrupt nonce/tag, causing authentication failure on decrypt.

**Recommendation:** Add per-page locks or use thread-local page fault exec contexts.

---

### [HIGH-003] COFF Loader Layout Overflow on Capacity Doubling

**File:** `coff_loader.rs:153,180,185,219`

**Impact:** `RawOutputBuffer` doubles capacity with `cap * 2` without checked arithmetic. If `cap` exceeds `isize::MAX / 2`, the multiplication wraps. A malformed COFF object producing excessive output could cause a panic during COFF loading — a user-facing command handler.

**Recommendation:** Use `cap.checked_mul(2).ok_or_else(|| anyhow!("capacity overflow"))?`.

---

### [HIGH-004] `.expect()` in XChaCha20-Poly1305 Encryption Called from VEH Context

**File:** `page_fault_exec.rs:105` (`xchacha20_encrypt`)

**Impact:** A panic inside a VEH handler is undefined behavior — the OS does not guarantee safe unwinding from a vectored exception handler. The `.expect()` on AEAD encryption failure could crash the agent in an unrecoverable way.

**Recommendation:** Replace with `Result` propagation and handle decryption failures gracefully (e.g., terminate the page-fault-exec context, don't panic).

---

### [HIGH-005] `syscall!` Macro Failure Treated as NTSTATUS -1

**File:** `page_fault_exec.rs:135,165` (`allocate_memory`, `free_memory`)

**Impact:** If the syscall dispatch itself fails (SSN not resolved, gadget not found), the code treats this as `NTSTATUS = -1` and proceeds with null/invalid handles. Downstream code may dereference null pointers.

**Recommendation:** Propagate `syscall!` errors as `Result` instead of `.unwrap_or(-1)`.

---

### [HIGH-006] Multiple `.unwrap()` Panic Risks in C2 Transports

**Files:** `c2_doh.rs:455`, `c2_http.rs:644,816,847`, `c2_smb.rs` (5 sites)

**Impact:** These transports use `.unwrap()` on operations that can fail (DNS resolution, HTTP parsing, SMB pipe reads). A transient network error or malformed server response will panic the agent rather than being handled gracefully.

**Recommendation:** Replace with proper error handling using `?` or `map_err`.

---

### [HIGH-007] RwLock `.unwrap()` on CLEAN_NTDLL Cache — Total Syscall Loss

**File:** `syscalls.rs:861,867,872,2173,2178`

**Impact:** If any writer panics while holding the write lock on the clean ntdll mapping, all subsequent readers will panic on `.read().unwrap()`, disabling the entire syscall infrastructure. The agent becomes a dead implant — no C2, no command execution.

**Recommendation:** Use poison recovery (`.unwrap_or_else(|e| e.into_inner())`) for RwLock.

---

### [HIGH-008] `stub.rs` Falls Back to All-Zero Key/Nonce Without `compile_error!`

**File:** `agent/src/stub.rs` (`build_key()`, `build_nonce()`)

**Impact:** When `option_env!()` fails to retrieve build-time secrets (misconfigured build), the functions silently fall back to all-zero AES key and nonce. The agent will build and run with null encryption — all C2 traffic is sent in effectively cleartext. This should be a `compile_error!` rather than a silent fallback.

**Recommendation:** Replace the fallback with `compile_error!("SYS_MODULE_KEY not set — cannot build agent without encryption keys")`.

---

### [HIGH-009] `memory_guard_stub.rs` — Concurrent `lock()` Race Corrupts Global State

**File:** `agent/src/memory_guard_stub.rs` (`guarded_sleep`)

**Impact:** Two threads calling `guarded_sleep` simultaneously can race on the global `CURRENT_KEY` and `INTEGRITY_HASHES` statics. Since the stub uses a simple boolean flag (not a Mutex) for synchronization, both threads can enter the "I hold the lock" path simultaneously, corrupting the key material.

**Recommendation:** Use a proper `Mutex` or `AtomicBool` with `compare_exchange` for synchronization.

---

### [HIGH-010] Unused Dependencies in Agent — Attack Surface Bloat

**Files:** `agent/Cargo.toml`

**Impact:** The following dependencies are declared but have zero `use` statements in the agent source:
- `directories = "6.0.0"` — zero `use directories::`
- `dirs = "5.0"` — zero `use dirs::`
- `ctr = "0.10.0"` — zero `use ctr::`
- `md-5` — zero `use md_5::` or `use md5::`

These inflate compile time, binary size, and dependency attack surface.

**Recommendation:** Remove unused dependencies. Audit remaining deps with `cargo machete` or `cargo udeps`.

---

### [HIGH-011] NtOpenProcess Access Mask Lacks PROCESS_VM_READ for SSDT Fallback

**File:** `nt_syscall/src/lib.rs` (NtOpenProcess constant)

**Impact:** The hardcoded access mask `0x001F0003` lacks `PROCESS_VM_READ (0x0010)`. If the SSDT fallback path is taken (e.g., when direct syscalls are disabled), the agent cannot read target process memory, causing LSASS harvest, injection, and cross-process operations to fail silently.

**Recommendation:** Add `PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION` to the access mask.

---

### [HIGH-012] `module_loader` Declares `reqwest`, `base64`, `serde_json` But Never Uses Them

**File:** `module_loader/Cargo.toml`

**Impact:** Three dependencies (`reqwest`, `base64`, `serde_json`) are declared but have zero `use` statements. The module loader only uses `libloading`, `sha2`, and `common`. Dead dependencies increase compile time and attack surface.

**Recommendation:** Remove unused dependencies.

---

### [HIGH-013] `decrypt_payload()` Is No-Op on Non-Windows/Non-x86_64

**File:** `agent/src/stub.rs`

**Impact:** On Linux ARM64 or macOS ARM64, the stub's `decrypt_payload()` function is a no-op — it does nothing. If the builder produces a payload encrypted for these platforms, the agent will execute encrypted (garbled) bytes as code, causing an immediate crash.

**Recommendation:** Add decrypt implementations for all supported platform/arch combinations, or add a `compile_error!` when the target doesn't support decryption.

---

### [HIGH-014] `lsass_harvest.rs` Uses FNV-1a for Process Identification — Collision Risk

**File:** `lsass_harvest.rs:89` (`LSASS_HASH` constant)

**Impact:** LSASS is located by FNV-1a hashing process names and comparing against `LSASS_HASH`. FNV-1a is non-cryptographic with known collision properties. A process with a colliding name would cause the agent to read the wrong process's memory, potentially targeting an EDR-monitored process.

**Recommendation:** Use a cryptographic hash (SHA-256 truncated) or direct string comparison via indirect syscall `NtQuerySystemInformation`.

---

## Medium Issues (partial implementation, edge-case failures)

### [MED-001] QUIC `recv()` Hangs Indefinitely — No Timeout on `accept_bi()`

**File:** `c2_quic.rs`

**Impact:** The QUIC transport sends a heartbeat then calls `accept_bi()` with no timeout. If the server becomes unreachable, the agent hangs indefinitely and never recovers.

---

### [MED-002] Graph Transport Has No Retry on Transient HTTP Errors (5xx)

**File:** `c2_graph.rs`

**Impact:** A single 5xx response from the Graph API endpoint causes the agent to treat the check-in as failed without retry. Under load or during Microsoft maintenance, this creates false-negative "agent dead" signals.

---

### [MED-003] `common/forward-secrecy` Feature Is a No-Op Legacy Stub

**File:** `common/Cargo.toml:14`

The feature exists for "backward compat with CI/build scripts" but does nothing. `orchestra-server` propagates it. This is misleading — operators may believe they can toggle forward secrecy at build time.

---

### [MED-004] Container Escape TOCTOU on `/proc/mounts`

**File:** `container.rs` (cgroup escape section)

The mount table can change between the read and the mount operation. Escape fails if the container runtime remounts cgroups between the read and the escape attempt.

---

### [MED-005] Reflective Loader — No Cleanup on Partial PE Load Failure

**File:** `reflective_loader.rs`

If any step fails after memory is committed (e.g., IAT resolution fails), the mapped memory is not cleaned up. `LoadedModule` Drop impl should handle this, but if the module is leaked, the mapped region persists as a forensic artifact.

---

### [MED-006] CFG Bypass Bitset Promotion — No Rollback on Partial Failure

**File:** `cfg_bypass.rs`

When promoting multiple addresses in the CFG bitset, if `NtProtectVirtualMemory` fails midway, the already-promoted bits remain set. This creates inconsistent state where some indirect call targets are promoted and others are not.

---

### [MED-007] Phantom DLL Hollowing — `std::env::var("SystemRoot")` Creates IAT Entry

**File:** `injection/phantom_dll_hollow.rs:143`

The `std::env` call goes through kernel32's `GetEnvironmentVariableW`, creating an IAT entry in an otherwise IAT-free module. OPSEC inconsistency.

**Recommendation:** Read `SystemRoot` from the PEB's environment block.

---

### [MED-008] Token Impersonation `CONFIG.get().unwrap()` Without Init Guard

**File:** `token_impersonation.rs:894,1028`

If token impersonation commands are dispatched before `CONFIG` is initialized, the agent panics. No ordering guarantee prevents this race.

---

### [MED-009] Remote Assist `as_mut().unwrap()` on Option

**File:** `remote_assist.rs:50`

If the slot is `None` (already taken or never initialized), this panics. No documented invariant guarantees the slot is always populated.

---

### [MED-010] VSS Pivot — 2 GB Contiguous Allocation Without Streaming

**File:** `vss_pivot.rs` (MAX_VSS_READ_SIZE = 2 GB)

Large contiguous allocation that could fail on memory-constrained systems and creates a detectable `VirtualAlloc` footprint.

**Recommendation:** Implement streaming/chunked reading for large NTDS.dit files.

---

### [MED-011] `hmac_key` Field in Builder Config Is Vestigial Dead Code

**File:** `builder/src/config.rs:29-31`

The field is deserialized, validated, and then ignored. It produces a `tracing::warn!` at build time but never participates in the build output.

---

### [MED-012] Builder Seed Generation Fallback Is Weak on Non-Unix

**File:** `builder/src/build.rs:435-447`

Falls back to `now ^ pid * golden_ratio_constant` when `/dev/urandom` is unavailable. On non-Unix platforms, this is the only path. The `rand` crate is already a dependency and should be the primary path.

---

### [MED-013] `orchestra-server` Depends on `libc` Unconditionally

**File:** `orchestra-server/Cargo.toml:38`

`libc::setrlimit` is only used behind `#[cfg(unix)]`, but the dependency is declared unconditionally, pulling in `libc` on Windows server builds.

**Recommendation:** Move to `[target.'cfg(unix)'.dependencies]`.

---

### [MED-014] `orchestra-server` Declares Both `chrono` and `time` — `time` Is Unused

**File:** `orchestra-server/Cargo.toml:34,39`

`time` crate has zero `use time::` statements. All time-related code uses `std::time`, `chrono`, or `tokio::time`.

---

### [MED-015] `orchestra-server` Declares `async-trait` But Never Uses It

**File:** `orchestra-server/Cargo.toml:31`

Zero `#[async_trait]` or `use async_trait` usages in the server crate.

---

### [MED-016] Builder Declares `ring` But Never Uses It

**File:** `builder/Cargo.toml:21`

Zero `use ring::` found. Unused dependency increases build time and attack surface.

---

### [MED-017] `memory_guard_stub.rs` — FNV-1a Not Cryptographically Secure for Integrity

**File:** `agent/src/memory_guard_stub.rs`

The stub uses FNV-1a for integrity hash verification. FNV-1a is trivially forgeable — an attacker who can modify memory can maintain the hash.

---

### [MED-018] `injection_delayed_stomp` `read_buf` Returns `Ok(())` When SSN Is None

**File:** `injection_delayed_stomp.rs`

When the SSN is not resolved, `read_buf` returns `Ok(())` with zeroed data instead of an error. Downstream code may use the zeroed data.

---

### [MED-019] `compiler_fence` Instead of `fence` in Secure Zero — No CPU Barrier on ARM64

**Files:** `lsa_whisperer.rs`, `injection_delayed_stomp.rs`, `page_tracker.rs`

`std::sync::atomic::compiler_fence` only prevents compiler reordering, not CPU reordering. On ARM64's weak memory model, the zeroing can be reordered past the fence, leaving sensitive data in registers/cache.

**Recommendation:** Use `std::sync::atomic::fence(Ordering::SeqCst)` for a full memory barrier.

---

### [MED-020] Handle Leak in `delayed_stomp` Drop When NtClose SSN Resolution Fails

**File:** `injection_delayed_stomp.rs`

If the SSN for `NtClose` cannot be resolved during `Drop`, the handle is silently leaked. Over time, repeated injection attempts could exhaust handle table entries.

---

### [MED-021] `entra_attacks.rs` Missing Hard `#![cfg(windows)]` Module Gate

**File:** `entra_attacks.rs:281,1185`

Unlike other attack modules (`adcs_attacks.rs`, `wmi_persistence.rs`, `vss_pivot.rs`), this module lacks a hard module-level platform gate. Could cause compile failures on non-Windows targets.

---

### [MED-022] `SleepConfig` Has Both `base_interval_secs` and `base_interval_ms`

**File:** `common/src/config.rs:142-143`

If both are set, it's unclear which takes precedence. No validation logic visible.

---

### [MED-023] Dual Logging Frameworks (`log` + `tracing`) Across Agent

**File:** `agent/Cargo.toml`

28+ files use `log` macros, others use `tracing`. Should standardize on `tracing` with `tracing-log` adapter.

---

### [MED-024] Dual Lazy Init (`lazy_static` + `once_cell`) Across Agent

**File:** `agent/Cargo.toml`

3 files use `lazy_static!`, 6+ use `once_cell::sync::Lazy`. Should standardize on `once_cell` (or `std::sync::LazyLock`).

---

### [MED-025] `iced-x86` Version Inconsistency — `"1"` vs `"1.20"`

**Files:** `code_transform/Cargo.toml` (`"1"`), `optimizer/Cargo.toml` (`"1.20"`)

Could pull different minor versions, increasing compile time with duplicate crate versions.

---

### [MED-026] `russh = "0.60.2"` Pulls ~16 Duplicate Crate Versions

**File:** `agent/Cargo.toml` (gated behind `ssh-transport`)

Documented but costly. The pre-release RustCrypto dependencies in russh conflict with the versions used elsewhere in the workspace.

---

### [MED-027] `H3Compat` Is Not Real HTTP/3 — DNS Wireformat Parser Doesn't Handle CNAME Chains

**File:** `c2_quic.rs`

The QUIC transport's HTTP/3 compatibility layer is minimal and does not follow CNAME chains in DNS responses. This can cause resolution failures for domains with CNAME records.

---

## Low Issues (stubs, TODOs, minor inconsistencies)

### [LOW-001] `memory_guard_stub.rs` — Intentional XOR-Based Fallback (By Design)

Documented intentional fallback for when full encryption is not available. Correctly logs a warning. Not a defect.

### [LOW-002] `kernel_callback/deploy.rs` — Build-Time PLACEHOLDER_DRIVER_BYTES (By Design)

Placeholder bytes replaced at build time. Expected build pipeline.

### [LOW-003] Test-Only `.unwrap()` Patterns (9+ Files)

All within `#[cfg(test)]` blocks. Acceptable.

### [LOW-004] `hollowing` Crate — Non-Windows Returns Error (Correct)

Three public functions return errors on non-Windows. Documented and correct.

### [LOW-005] `orchestra-server` SMB Relay Is No-Op on Non-Windows (Correct)

Documented no-op stub. Could be confusing in mixed-OS deployments.

### [LOW-006] `handlers.rs` — Lock Hold Time During Plugin Loading

Brief but could contend with concurrent command dispatch.

### [LOW-007] `interactive_shell.rs` — Comprehensive Non-Platform Stubs (Correct)

`compile_error!` for unsupported platforms. Defensive coding.

### [LOW-008] `hci_logging.rs` — High Density of `.lock().unwrap()` in Research Module

14 sites in a research-gated module. Same poisoned mutex risk as CRIT-001 but lower exposure.

### [LOW-009] `common/src/config.rs` — `base_interval_secs` and `base_interval_ms` Coexistence

Minor operator confusion risk.

### [LOW-010] `CODE_TRANSFORM_SEED` Formatted as Decimal vs `OPTIMIZER_STUB_SEED` as Hex

**File:** `builder/src/build.rs:42`

Inconsistent formatting of build env vars.

### [LOW-011] `module_loader` `serde_json` Outside Workspace Inheritance

**File:** `module_loader/Cargo.toml:13`

Minor consistency issue.

### [LOW-012] `rustls`/`tokio-rustls` Duplicated Across Crates Without Workspace Inheritance

**Files:** `common/Cargo.toml:16-17`, `orchestra-server/Cargo.toml:35-36`

If versions diverge, TLS handshake could fail at link time.

### [LOW-013] Agent `directories` and `dirs` Both Declared — Neither Used

Both `dirs = "5.0"` and `directories = "6.0.0"` are declared. Neither has `use` statements. Redundant unused deps.

### [LOW-014] `agent/Cargo.toml` — `getrandom = "0.2"` May Be Transitive Only

No direct `use getrandom` found. Likely pulled via `rand` feature flags.

### [LOW-015] `agent/Cargo.toml` — `url = "2"` Used Only Once

Only `url::Url` in `c2_http.rs`. Very light usage for a direct dependency.

### [LOW-016] `nix = "0.28"` in Launcher — Current Is 0.29+

Minor version lag.

### [LOW-017] `portable-pty = "0.9"` — Not Recently Maintained

Consider alternatives for production use.

### [LOW-018] `module-signatures` Feature Asymmetry Between `common` and `module_loader`

Different crates gate Ed25519 differently. Server always has it.

### [LOW-019] Builder Has Two `[[bin]]` Targets But No `[lib]`

Cannot use as a library from other workspace crates. Intentional but limits future integration.

---

## Platform-Specific Findings

### Linux

| ID | Severity | Finding |
|----|----------|---------|
| CRIT-002 | CRITICAL | Self-reencode uses `tgkill(SIGSTOP)` on Linux — same thread suspension verification gap as Windows |
| HIGH-013 | HIGH | `decrypt_payload()` is no-op on Linux ARM64 — agent executes garbled bytes |
| MED-004 | MEDIUM | Container escape TOCTOU on `/proc/mounts` — cgroup mount can change between read and escape |
| MED-019 | MEDIUM | `compiler_fence` instead of `fence` — ARM64 weak memory model allows reordering past barrier |
| LOW-007 | LOW | `interactive_shell.rs` stubs are correct for Linux (uses `pty` module) |
| — | INFO | eBPF evasion modules have custom ELF parser that trusts header offsets (low risk — self-generated BPF objects) |
| — | INFO | Linux persistence via systemd user unit is well-implemented |

### Windows

| ID | Severity | Finding |
|----|----------|---------|
| CRIT-002 | CRITICAL | Self-reencode uses `NtSuspendThread` — no suspension verification |
| CRIT-003 | CRITICAL | `compare_export_name` binary search bug affects SSN resolution |
| HIGH-001 | HIGH | QUIC/Graph lack ECDH forward secrecy |
| HIGH-007 | HIGH | RwLock poison on CLEAN_NTDLL cache disables all syscalls |
| HIGH-011 | HIGH | NtOpenProcess access mask missing PROCESS_VM_READ |
| HIGH-014 | HIGH | FNV-1a for LSASS process identification — collision risk |
| MED-007 | MEDIUM | Phantom DLL hollowing creates IAT entry via `std::env::var` |
| MED-020 | MEDIUM | Handle leak in delayed_stomp Drop |
| MED-021 | MEDIUM | `entra_attacks.rs` missing hard `#![cfg(windows)]` gate |
| — | INFO | AMSI bypass (3 strategies), ETW patching, CET bypass all well-implemented |
| — | INFO | Stack spoofing with NtContinue multi-frame is comprehensive |
| — | INFO | All 15 injection techniques compile correctly with proper `#[cfg]` gates |

### macOS

| ID | Severity | Finding |
|----|----------|---------|
| HIGH-013 | HIGH | `decrypt_payload()` is no-op on macOS ARM64 |
| MED-019 | MEDIUM | `compiler_fence` instead of `fence` — ARM64 barrier issue |
| — | INFO | macOS persistence (LaunchAgent + ServiceManagement) both implemented |
| — | INFO | `macos-postexp` feature has TCC/SIP/XPC/Keychain modules — no critical issues found in static analysis |
| — | INFO | Cloud instance detection degrades gracefully when IMDS is unavailable |

### Cross-Platform Consistency

| ID | Severity | Finding |
|----|----------|---------|
| MED-023 | MEDIUM | Dual logging (`log` + `tracing`) across all platforms |
| MED-024 | MEDIUM | Dual lazy init (`lazy_static` + `once_cell`) across all platforms |
| — | INFO | `#[cfg(target_os)]` gating is comprehensive — 200+ gates across 139 source files |
| — | INFO | All `unsafe` blocks examined have safety comments (partial — some are brief) |

---

## False-Positive / False-Negative Risks

### Environment Check False-Positive Risks

| Check | False-Positive Scenario | Risk |
|-------|------------------------|------|
| **CPUID Hypervisor Bit** | Bare-metal servers with virtualization-enabled BIOS (Intel VT-x/AMD-V enabled in firmware) | **HIGH** — agent exits on legitimate bare-metal hardware |
| **Weighted Sandbox Score** | CI/CD runner environments (GitHub Actions, GitLab CI) with low RAM, single CPU, no domain | **MEDIUM** — `sandbox_score_threshold` may need tuning for CI runners |
| **TracerPid > 0** | Linux processes running under `strace` for debugging, or with `perf` attached | **LOW** — documented behavior, but could affect operator troubleshooting |
| **DMI String Check** | Custom-built hardware or obscure VM platforms not in the known-good list | **MEDIUM** — could flag legitimate hardware as VM |
| **Cloud Instance Detection** | Bare-metal cloud instances (AWS i3.metal, Azure HBv2) that don't present IMDS | **MEDIUM** — agent exits on bare-metal cloud instances unless `cloud_instance_allow_without_imds` is set |

### Environment Check False-Negative Risks

| Check | False-Negative Scenario | Risk |
|-------|------------------------|------|
| **IsDebuggerPresent** | Kernel-mode debuggers (WinDbg kernel attach) | **LOW** — `IsDebuggerPresent` only detects user-mode debugers |
| **TracerPid** | Ptrace is blocked by seccomp policy (containerized sandbox) | **MEDIUM** — `/proc/self/status` returns 0 even if debugged via other mechanisms |
| **Sleep Timing** | Analysis sandboxes with time acceleration or modified `NtQueryPerformanceCounter` | **LOW** — RDTSC-based checks are harder to fake, but sleep-based checks can be cheated |
| **DNS/Domain Check** | Sandboxes that join the target domain | **LOW** — sophisticated sandboxes can pass domain membership checks |

---

## Dependency & Build Issues

### Unused Dependencies (Should Remove)

| Crate | Unused Dep | Evidence |
|-------|-----------|----------|
| **agent** | `directories = "6.0.0"` | Zero `use directories::` |
| **agent** | `dirs = "5.0"` | Zero `use dirs::` |
| **agent** | `ctr = "0.10.0"` | Zero `use ctr::` |
| **agent** | `md-5` | Zero `use md_5::` |
| **module_loader** | `reqwest` | Zero `use reqwest` |
| **module_loader** | `base64` | Zero `use base64` |
| **module_loader** | `serde_json` | Zero `use serde_json` |
| **module_loader** | `tempfile` | Zero `use tempfile` |
| **builder** | `ring` | Zero `use ring::` |
| **orchestra-server** | `time` | Zero `use time::` |
| **orchestra-server** | `async-trait` | Zero `#[async_trait]` |

### Dependencies Needing Workspace Inheritance

The following are used in 3+ crates but not in `[workspace.dependencies]`:
- `serde_json` (7 crates)
- `libc` (6 crates)
- `log` (6 crates)
- `hmac` (4 crates)
- `hex` (3 crates)
- `bincode` (3 crates)

### Version Conflicts

| Dep | Versions | Risk |
|-----|----------|------|
| `iced-x86` | `"1"` vs `"1.20"` | Could pull different minor versions |
| `libc` | `0.2` vs `0.2.185` | Consistent semver range but inconsistent pinning |
| `serde_json` | `"1.0"` vs `"1.0.149"` | Builder pins exact version, others use range |

### Duplicate Functionality

| Pattern | Crates | Recommendation |
|---------|--------|----------------|
| `chrono` + `time` | orchestra-server | Remove `time` |
| `log` + `tracing` | agent | Standardize on `tracing` |
| `lazy_static` + `once_cell` | agent | Standardize on `once_cell` |
| `ring::digest` + `sha2` | agent | Document dual use (intentional) |

---

## Test Coverage Gaps

### Crates with Zero Tests

| Crate | Role | Risk |
|-------|------|------|
| **console** | Operator CLI | Medium — no validation of command parsing |
| **redirector** | Traffic redirector | Medium — no validation of forwarding logic |
| **keygen** | Key generation | Medium — no validation of cryptographic output |
| **nt_syscall** | NT syscall wrappers | **High** — SSN resolution bugs directly impact agent reliability |

### Agent Modules with Zero Test Coverage (Highest Risk)

| Module | Risk |
|--------|------|
| `c2_http.rs` | Core transport — no unit tests |
| `c2_smb.rs` | SMB transport — no tests |
| `c2_ssh.rs` | SSH transport — no tests |
| `c2_graph.rs` | Graph API transport — no tests |
| `c2_quic.rs` | QUIC transport — sparse tests |
| `kerberos_relay.rs` | Kerberos attack — no tests |
| `lsa_whisperer.rs` | LSA secrets — no tests |
| `lsass_harvest.rs` | LSASS memory — no tests |
| `assembly_loader.rs` | .NET CLR hosting — no tests |
| `process_spoof.rs` | Process spoofing — no tests |
| `injection_transacted.rs` | Transacted injection — no tests |
| `wmi_persistence.rs` | WMI persistence — no tests |
| `dpapi_backup.rs` | DPAPI decryption — no tests |
| `shadow_credentials.rs` | Shadow credential attack — no tests |
| `s4u_abuse.rs` | S4U abuse — no tests |
| `entra_app_abuse.rs` | Entra app abuse — no tests |
| `syscalls.rs` | Syscall infrastructure — no tests |
| `kernel_apc_pivot.rs` | Kernel APC — no tests |
| `exception_ssn.rs` | Exception-based SSN — no tests |

### Test Coverage Summary

| Crate | Integration Tests | Unit Tests (`#[cfg(test)]`) | Benchmarks | Verdict |
|-------|------------------|---------------------------|------------|---------|
| **agent** | 17 tests (evasion + soak) | 42 modules | 1 benchmark | ✅ Good |
| **orchestra-server** | 8+ tests (E2E, WS auth, identity) | 4+ modules | None | ✅ Good |
| **launcher** | 15 tests | 1 module | None | ✅ Good |
| **code_transform** | 4 tests | 12 modules | None | ✅ Good |
| **common** | — | 10+ modules | None | ✅ Good |
| **uefi-persistence** | — | 6 modules | None | ✅ Good |
| **builder** | — | 3 modules | None | ⚠️ Adequate |
| **optimizer** | — | 1 module | 1 benchmark | ⚠️ Adequate |
| **shellcode_packager** | — | 3 modules | None | ⚠️ Adequate |
| **hollowing** | — | 1 module | None | ⚠️ Minimal |
| **module_loader** | — | 1 module | None | ⚠️ Minimal |
| **console** | — | **None** | None | ❌ Zero |
| **redirector** | — | **None** | None | ❌ Zero |
| **keygen** | — | **None** | None | ❌ Zero |
| **nt_syscall** | — | **None** | None | ❌ Zero |

---

## Functional Status Matrix

| Feature / Module | Crate/Path | Status | Notes |
|-----------------|------------|--------|-------|
| **Core** | | | |
| Config loading & hot-reload | `common/src/config.rs` | ✅ Functional | Well-structured with `#[serde(default)]` for backward compat |
| Env validation (debugger/VM/sandbox/domain) | `agent/src/env_check*.rs` | ✅ Functional | False-positive risks documented above |
| Command dispatch (handlers.rs, 120+ commands) | `agent/src/handlers.rs` | ⚠️ Partial | `.lock().unwrap()` on LOADED_PLUGINS at 16 sites — CRIT-001 |
| Module/plugin loader | `module_loader/`, `agent/src/handlers.rs` | ✅ Functional | Unused deps in module_loader (HIGH-012) |
| Interactive PTY shell | `agent/src/interactive_shell.rs` | ✅ Functional | Comprehensive platform stubs |
| **Transport** | | | |
| HTTP malleable C2 | `agent/src/c2_http.rs` | ✅ Functional | `.unwrap()` panic risks at 3 sites (HIGH-006) |
| DNS-over-HTTPS C2 | `agent/src/c2_doh.rs` | ✅ Functional | `.unwrap()` at line 455 (HIGH-006) |
| SSH subsystem C2 | `agent/src/c2_ssh.rs` | ✅ Functional | russh pulls ~16 duplicate crates |
| SMB named pipe C2 | `agent/src/c2_smb.rs` | ⚠️ Partial | 5 `.unwrap()` sites (HIGH-006) |
| QUIC/HTTP3 C2 | `agent/src/c2_quic.rs` | ⚠️ Partial | No ECDH forward secrecy (HIGH-001), recv() can hang (MED-001) |
| Microsoft Graph C2 | `agent/src/c2_graph.rs` | ⚠️ Partial | No kill date (CRIT-005), no ECDH (HIGH-001), no retry on 5xx (MED-002) |
| Forward secrecy (X25519) | `common/src/lib.rs` | ⚠️ Partial | Only HTTP/DoH; QUIC/Graph lack it |
| **Windows Injection (15 techniques)** | | | |
| Process Hollowing | `hollowing/` | ✅ Functional | Non-Windows stub returns error (correct) |
| ThreadPool (8 sub-variants) | `agent/src/injection_engine.rs` | ✅ Functional | Well-gated behind features |
| Fiber injection | `agent/src/` | ✅ Functional | |
| Context-Only | `agent/src/` | ✅ Functional | |
| Section Mapping | `agent/src/` | ✅ Functional | |
| NtSetInformationProcess | `agent/src/` | ✅ Functional | |
| Waiting Thread Hijack | `agent/src/` | ✅ Functional | |
| Transacted Hollowing | `agent/src/injection_transacted.rs` | ✅ Functional | NTFS transaction rollback documented |
| Delayed Stomp | `agent/src/injection_delayed_stomp.rs` | ⚠️ Partial | `read_buf` returns Ok(()) with zeroed data when SSN is None (MED-018); handle leak in Drop (MED-020) |
| Existing Module Stomp | `agent/src/` | ✅ Functional | |
| Phantom DLL Hollowing | `agent/src/injection/phantom_dll_hollow.rs` | ⚠️ Partial | IAT entry via std::env::var (MED-007) |
| Callback (12 APIs) | `agent/src/` | ✅ Functional | |
| **Windows Evasion** | | | |
| Direct/indirect syscalls (nt_syscall) | `nt_syscall/` | ⚠️ Partial | Binary search bug (CRIT-003), access mask issue (HIGH-011), no tests |
| NTDLL unhooking (KnownDlls + disk) | `nt_syscall/` | ✅ Functional | RwLock poison risk (HIGH-007) |
| Halo's Gate | `nt_syscall/` | ✅ Functional | Adjacent stub scanning logic verified |
| AMSI bypass (Write-Raid / HWBP / Mem Patch) | `agent/src/` | ✅ Functional | 3 strategies implemented |
| ETW patching (Safe/Always/Never) | `agent/src/etw_patch.rs` | ✅ Functional | `.lock().unwrap()` at 2 sites (CRIT-001 family) |
| CET/shadow-stack bypass (3 strategies) | `agent/src/` | ✅ Functional | |
| Stack spoofing (NtContinue multi-frame) | `agent/src/stack_spoof.rs` | ✅ Functional | `.lock().unwrap()` at 8 sites (CRIT-001 family) |
| Syscall emulation (10 APIs) | `agent/src/syscall_emulation.rs` | ⚠️ Partial | NtCreateThreadEx → CreateRemoteThread lacks CREATE_SUSPENDED support (documented) |
| Evasion transform (5 types) | `agent/src/edr_bypass_transform*.rs` | ✅ Functional | `.lock().unwrap()` at 4 sites across x86_64/ARM64 |
| Self-reencode | `agent/src/self_reencode.rs` | ⚠️ Partial | Thread suspension not verified (CRIT-002) |
| **Windows Credential Access** | | | |
| LSASS harvest (incremental) | `agent/src/lsass_harvest.rs` | ⚠️ Partial | FNV-1a collision risk (HIGH-014) |
| LSA Whisperer (SSP) | `agent/src/lsa_whisperer.rs` | ✅ Functional | Unbounded credential buffer (documented) |
| Browser data (Chrome/Edge/Firefox) | `agent/src/browser_data.rs` | ✅ Functional | Chrome v127+ App-Bound bypass implemented |
| Token manipulation & impersonation | `agent/src/token_impersonation.rs` | ⚠️ Partial | CONFIG.get().unwrap() without init guard (MED-008) |
| DPAPI backup key retrieval | `agent/src/dpapi_backup.rs` | ✅ Functional | Test-only .unwrap() patterns |
| **Windows Forensics** | | | |
| Prefetch cleanup | `agent/src/` | ✅ Functional | PF v17/v23/v26/v30 supported |
| USN journal cleanup | `agent/src/` | ✅ Functional | |
| MFT timestamp manipulation | `agent/src/` | ✅ Functional | |
| $LogFile cleanup | `agent/src/` | ✅ Functional | |
| **Cross-Platform** | | | |
| Sleep obfuscation (Ekko/Cronus) | `agent/src/sleep_obfuscation.rs` | ⚠️ Partial | Race condition in region cache (CRIT-006); page_tracker state bug (CRIT-004 family) |
| Memory guard | `agent/src/memory_guard.rs` | ✅ Functional | |
| Memory guard (stub fallback) | `agent/src/memory_guard_stub.rs` | ⚠️ Partial | Concurrent lock race (HIGH-009); FNV-1a integrity (MED-017) |
| Evanesco (continuous memory hiding) | `agent/src/page_tracker.rs`, `page_fault_exec.rs` | ⚠️ Partial | SyncCell data race (HIGH-002); .expect() in VEH (HIGH-004); compiler_fence on ARM64 (MED-019) |
| Network discovery (ARP/ping/TCP) | `agent/src/` | ✅ Functional | |
| Persistence (systemd/schtasks/launchd) | `agent/src/` | ✅ Functional | All three platforms implemented |
| Remote assist (screen capture/input sim) | `agent/src/remote_assist.rs` | ⚠️ Partial | as_mut().unwrap() panic risk (MED-009) |
| Browser data extraction | `agent/src/browser_data.rs` | ✅ Functional | |
| eBPF hiding (Linux) | `agent/ebpf/` | ✅ Functional | 3 BPF programs, custom ELF parser (LOW-010) |
| **Post-Exploitation** | | | |
| .NET assembly loader | `agent/src/assembly_loader.rs` | ✅ Functional | No tests |
| BOF/COFF loader | `agent/src/coff_loader.rs` | ⚠️ Partial | Layout overflow (HIGH-003); double-unwrap pattern (MED-014) |
| Lateral movement (PsExec/WmiExec/DcomExec/WinRmExec) | `agent/src/` | ✅ Functional | |
| P2P mesh (SMB/TCP relay) | `agent/src/p2p*.rs` | ✅ Functional | Sparse test coverage |
| Kerberos relay / S4U abuse / Shadow Credentials | `agent/src/kerberos_relay.rs`, `s4u_abuse.rs`, `shadow_credentials.rs` | ✅ Functional | No tests for any of these |
| ADCS attacks (ESC1-ESC8) | `agent/src/adcs_attacks.rs` | ✅ Functional | Hard `#![cfg(windows)]` gate |
| Container escape (Linux) | `agent/src/container.rs` | ⚠️ Partial | TOCTOU on /proc/mounts (MED-004) |
| WSL2 evasion | `agent/src/` | ✅ Functional | |
| COM hijack | `agent/src/` | ✅ Functional | |
| LOLBIN xwizard | `agent/src/lolbin_xwizard.rs` | ✅ Functional | |
| VSS pivot | `agent/src/vss_pivot.rs` | ⚠️ Partial | 2 GB allocation without streaming (MED-010) |
| Entra ID attacks | `agent/src/entra_attacks.rs`, `entra_*.rs` | ⚠️ Partial | Missing hard module gate (MED-021) |
| Hardware/firmware persistence | `agent/src/` | ✅ Functional | |
| LPE modules | `agent/src/lpe/` | ✅ Functional | |
| macOS post-exploitation | `agent/src/macos_postexp.rs` | ✅ Functional | TCC/SIP/XPC/Keychain modules present |
| BTI/PAC bypass (ARM64) | `agent/src/edr_bypass_transform_aarch64.rs` | ✅ Functional | `.lock().unwrap()` at 2 sites |
| **Infrastructure** | | | |
| Orchestra server (REST API, mTLS, build queue) | `orchestra-server/` | ✅ Functional | Unused deps: time, async-trait; unconditional libc |
| Builder (feature discovery, env propagation) | `builder/` | ✅ Functional | Unused dep: ring; vestigial hmac_key; weak seed fallback |
| Payload packager | `payload-packager/` | ✅ Functional | |
| Shellcode packager | `shellcode_packager/` | ✅ Functional | |
| PE hardener | `orchestra-pe-hardener/` | ✅ Functional | |
| Side-load generator | `orchestra-side-load-gen/` | ✅ Functional | |
| Redirector | `redirector/` | ✅ Functional | Zero tests |
| Keygen | `keygen/` | ✅ Functional | Zero tests |
| Optimizer | `optimizer/` | ✅ Functional | |
| UEFI persistence | `uefi-persistence/` | ✅ Functional | 6 test modules |
| ZAI provider extension | `zai-provider-extension/` | ✅ Functional | VS Code extension |

---

## Appendix: Files Audited

### Documentation (15 files)
- `docs/ARCHITECTURE.md`, `docs/FEATURES.md`, `docs/DESIGN.md`, `docs/EVASION.md`
- `docs/INJECTION_ENGINE.md`, `docs/POST_EXPLOITATION.md`, `docs/SLEEP_OBFUSCATION.md`
- `docs/P2P_MESH.md`, `docs/FORENSICS.md`, `docs/CONFIGURATION.md`
- `docs/SECURITY_AUDIT.md`, `docs/SECURITY.md`, `docs/CONTROL_CENTER.md`
- `ROADMAP.md`, `CHANGELOG.md`

### Workspace Configuration (17 files)
- `Cargo.toml` (workspace root)
- `agent/Cargo.toml`, `common/Cargo.toml`, `orchestra-server/Cargo.toml`, `builder/Cargo.toml`
- `nt_syscall/Cargo.toml`, `module_loader/Cargo.toml`, `hollowing/Cargo.toml`
- `code_transform/Cargo.toml`, `optimizer/Cargo.toml`, `launcher/Cargo.toml`
- `console/Cargo.toml`, `redirector/Cargo.toml`, `shellcode_packager/Cargo.toml`
- `string_crypt/Cargo.toml`, `keygen/Cargo.toml`

### Agent Source (139+ .rs files, key modules)
- `agent/src/lib.rs`, `agent/src/stub.rs`, `agent/src/handlers.rs`
- `agent/src/syscalls.rs`, `agent/src/syscall_emulation.rs`
- `agent/src/memory_guard.rs`, `agent/src/memory_guard_stub.rs`
- `agent/src/sleep_obfuscation.rs`, `agent/src/page_tracker.rs`
- `agent/src/env_check.rs`, `agent/src/env_check_sandbox.rs`
- `agent/src/c2_http.rs`, `c2_doh.rs`, `c2_ssh.rs`, `c2_smb.rs`, `c2_quic.rs`, `c2_graph.rs`
- `agent/src/injection_engine.rs`, `injection_transacted.rs`, `injection_delayed_stomp.rs`
- `agent/src/lsass_harvest.rs`, `browser_data.rs`, `lsa_whisperer.rs`
- `agent/src/self_reencode.rs`, `page_fault_exec.rs`
- `agent/src/coff_loader.rs`, `reflective_loader.rs`
- `agent/src/container.rs`, `vss_pivot.rs`
- `agent/src/stack_spoof.rs`, `stack_db.rs`
- `agent/src/edr_bypass_transform.rs`, `edr_bypass_transform_aarch64.rs`
- `agent/src/cfg_bypass.rs`
- `agent/src/token_impersonation.rs`
- `agent/src/remote_assist.rs`, `interactive_shell.rs`
- `agent/src/etw_patch.rs`
- `agent/src/surveillance.rs`, `hci_logging.rs`
- `agent/src/kerberos_relay.rs`, `s4u_abuse.rs`, `shadow_credentials.rs`
- `agent/src/adcs_attacks.rs`, `entra_attacks.rs`, `entra_*.rs`
- `agent/src/wmi_persistence.rs`, `dpapi_backup.rs`
- `agent/src/assembly_loader.rs`, `lolbin_xwizard.rs`
- `agent/src/macos_postexp.rs`
- `agent/src/injection/phantom_dll_hollow.rs`, `dll_sideload.rs`
- `agent/src/lpe/named_pipe_impersonate.rs`
- `agent/src/kernel_callback/deploy.rs`

### Build Scripts (4 files)
- `agent/build.rs`, `common/build.rs`, `optimizer/build.rs`, `pe_resolve/build.rs`

### Server & Infrastructure (8 files)
- `orchestra-server/src/main.rs`
- `builder/src/lib.rs`, `builder/src/config.rs`, `builder/src/build.rs`
- `common/src/lib.rs`, `common/src/config.rs`
- `module_loader/src/lib.rs`
- `hollowing/src/lib.rs`

### eBPF Programs (3 files)
- `agent/ebpf/*.bpf.c`

### Test Files (10+ files)
- `agent/tests/evasion_tests.rs`, `agent/tests/soak_test.rs`
- `orchestra-server/tests/e2e.rs`, `outbound_e2e.rs`, `ws_auth.rs`, `identity.rs`
- `launcher/tests/hollowing_test.rs`, `launcher/tests/e2e_deployment.rs`
- `code_transform/tests/exec_transform.rs`

---

**End of Report**

*Generated by static analysis. No source files were modified during this audit.*
