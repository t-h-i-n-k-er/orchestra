# Orchestra — Deep Codebase Audit Prompt

> **Purpose:** Instruct an advanced coding model to perform an exhaustive correctness, completeness, and functional audit of the Orchestra framework — **static analysis augmented by local empirical testing on this dedicated dev device, zero source-file modifications.**

---

## Instructions for the Auditor Model

You are a senior systems-security engineer and Rust expert. Your task is to perform a **full-spectrum deep audit** of the Orchestra framework — a cross-platform (Linux, Windows, macOS, Android, iOS) Rust implant framework with a C2 server, builder pipeline, and supporting tooling.

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
12. `docs/MALLEABLE_PROFILES.md` — malleable C2 profiles
13. `docs/MOBILE_DESIGN.md` — Android/iOS design
14. `docs/MOBILE_SUPPORT.md` — mobile platform support and build instructions
15. `docs/OPERATOR_MANUAL.md` — operator reference
16. `docs/CONTROL_CENTER.md` — server configuration and REST API
17. `docs/REDIRECTOR_GUIDE.md` — redirector deployment
18. `docs/LAUNCHER.md` — launcher design
19. `docs/INTEGRATION_TEST_WALKTHROUGH.md` — integration test guide
20. `docs/LOCAL_TESTING_GUIDE.md` — local testing guide
21. `docs/CONTRIBUTING.md` — contribution guidelines
22. `docs/QUICKSTART.md` — getting started
23. `docs/USER_GUIDE.md` — user guide
24. `ROADMAP.md` — completed vs. planned work
25. `CHANGELOG.md` — recent changes and known limitations
26. `Cargo.toml` (workspace root) — workspace layout (28 crates)
27. `agent/Cargo.toml` — feature flag definitions (70+ features) and dependency tree

Then systematically audit **every crate, module, and source file** in the workspace, checking for the categories of issues described below.

---

## Part 1 — Compilation & Macro-Expansion Correctness

Examine every file that uses inline assembly, procedural macros, or build-script code generation. Verify that:

- **`nt_syscall/src/lib.rs`** — inline `asm!()` blocks compile on all intended targets (x86_64 Windows, aarch64 Windows, x86_64 Linux, aarch64 Linux). Check register bindings, clobber lists, and calling-convention alignment for each architecture.
- **`nt_syscall/src/lib.rs`** — `syscall!()` macro expansion produces valid Rust for every supported arity and every feature-gated path (`direct-syscalls`, `stack-spoof`, `cet-bypass`, `syscall-emulation`).
- **`agent/build.rs`** — environment variable propagation (`SYS_MODULE_KEY`, `SYS_C_ADDR`, `SYS_C_SECRET`, `SYS_C_CERT_FP`, `OPTIMIZER_STUB_SEED`, `CODE_TRANSFORM_SEED`, `SYS_DRIVER_PATH`, etc.) handles missing and malformed values gracefully.
- **`code_transform/`** and **`code_transform_macro/`** — proc-macro expansion produces syntactically valid output; attribute parsing is exhaustive; ChaCha8 PRNG seed handling is correct across all transform types (Register Rename, Instruction Swap, Block Reorder, NOP Sled, Constant Fold).
- **`junk_macro/`** — macro generates compilable junk code across feature combinations; output is syntactically valid in all insertion contexts.
- **`string_crypt/`** — build-time string encryption compiles and decrypts correctly at runtime; verify round-trip correctness.
- **`common/build.rs`** — any code generation is correct.
- **`pe_resolve/build.rs`** — PE parsing helpers compile; hash-based export resolution produces correct addresses.
- **`optimizer/build.rs`** — metamorphic engine build steps compile; stub seed propagation works.
- **`orchestra-side-load-gen/build.rs`** — side-load DLL generation compiles.
- **`agent/src/pe_resolve_macros.rs`** — inline proc macros for PE export resolution produce valid Rust.
- **Mobile build scripts** — `mobile/android/build_agent.sh` and `mobile/ios/build_agent.sh`: check that `cargo-ndk` and Xcode static library paths are valid for their target triples.

For each issue found, note:
- File and line range
- The specific target / feature combination that breaks
- Whether `cargo check` would catch it or if it only manifests at runtime

---

## Part 2 — Logical Bugs & Algorithmic Errors

Trace the logic in these critical subsystems and identify any correctness flaws:

### 2.1 Process Hollowing & Injection Engine

- **`hollowing/src/`** — `hollow_and_execute()`: Verify the complete lifecycle (create suspended → unmap → write → fix imports → resume). Check for race conditions, handle leaks, and incorrect PE header manipulation.
- **`agent/src/injection_engine.rs`** — All 15 `InjectionTechnique` variants: verify each technique's implementation matches its documented contract. Check for missing error paths, unguarded `unsafe` blocks, and incorrect memory-protection restoration.
- **`agent/src/injection/`** — Per-technique modules: verify `callback_exec.rs`, `dll_sideload.rs`, `early_bird.rs`, `existing_module_stomp.rs`, `linux_inject.rs`, `module_stomp.rs`, `nt_create_thread.rs`, `phantom_dll_hollow.rs`, `remote_thread.rs`, `thread_pool.rs` (8 sub-variants: Work, WorkerFactory, Timer, IoCompletion, Wait, Alpc, Direct, AsyncIo).
- **`agent/src/injection_delayed_stomp.rs`** — Timer-based delay mechanism: verify the stomp occurs after the legitimate DLL has fully initialized. Check for TOCTOU races. Verify sacrificial DLL selection excludes critical DLLs.
- **`agent/src/injection_transacted.rs`** — NTFS transaction rollback path: confirm the section survives transaction rollback on all supported Windows versions. Verify ETW blinding with spoofed provider GUIDs.
- **`agent/src/injection_doppelganging.rs`** — Process Doppelganging via NTFS transactions: verify the full NtCreateTransaction → NtCreateFile → NtWriteFile → NtCreateSection → NtRollbackTransaction flow.
- **`agent/src/code_cave.rs`** — Code cave injection: verify cave discovery and payload insertion.
- **`agent/src/callback_exec.rs`** — Callback injection dispatch: verify 12 callback APIs are correctly resolved and invoked.
- **`agent/src/reflective_loader.rs`** — Reflective DLL loading via NtCreateSection: verify relocation fixups and IAT rebuilding.

### 2.2 Manual PE Mapping (`manual-map` feature)

- **`module_loader/`** — Reflective PE loading: verify section alignment, import resolution, relocation fixups, and entry-point invocation. Check for edge cases: forward exports, delay imports, TLS callbacks, bound imports, exception directories.
- Verify remote-process manual mapping handles ASLR base divergence correctly (acknowledged known limitation in ROADMAP.md).

### 2.3 C2 Transport Layer

- **`agent/src/c2_http.rs`** — Malleable profile application: verify URI selection, header injection, encoding transforms (Base64/Mask/NetBIOS), payload delivery modes (Cookie/URI/header/body). Check failover state machine for stuck states.
- **`agent/src/c2_doh.rs`** — DNS encoding correctness, record type handling, rate limiting logic.
- **`agent/src/c2_ssh.rs`** — SSH subsystem channel framing, keepalive handling, authentication fallback.
- **`agent/src/c2_smb.rs`** — Named pipe connection lifecycle, frame delimiting, error recovery.
- **`agent/src/c2_quic.rs`** — QUIC/HTTP3 transport implementation completeness. Verify certificate verification and stream management.
- **`agent/src/c2_graph.rs`** — Microsoft Graph API transport completeness. Verify Outlook/OneDrive/Teams/SharePoint delivery modes.
- **`agent/src/malleable.rs`** — Malleable profile parsing and application.
- **`agent/src/traffic_normalize.rs`** — Traffic pattern normalization correctness.

### 2.4 Cryptographic Protocol

- **`common/src/` (wire protocol)** — Verify frame format: length prefix → salt(32) ‖ nonce(12) ‖ ciphertext+tag. Confirm HKDF-SHA256 derivation with info string `orchestra-v2`. Check for nonce reuse, key derivation edge cases, and forward-secrecy X25519 exchange correctness.
- **`common/src/forward_secrecy.rs`** — X25519 ECDH key exchange: verify ephemeral key generation, public key exchange, and HKDF session key derivation.
- **`common/src/hkdf_info.rs`** — HKDF info string handling and domain separation.
- **`common/src/lock.rs`** — Thread-safe crypto state management.
- **`agent/src/sleep_obfuscation.rs`** — XChaCha20-Poly1305 encryption of heap+stack. Verify key stash in XMM14/XMM15 is correctly saved/restored. Check for key material remaining in registers after wake.
- **`agent/src/obfuscated_sleep.rs`** — Sleep obfuscation integration layer: verify encrypt/decrypt cycle covers all registered regions.
- **`agent/src/` (RC4 stub in Cronus)** — Verify position-independent stub generation, S-box initialization, and RIP-relative addressing.
- **`agent/src/thread_context_encrypt.rs`** — Thread context encryption: verify CONTEXT struct serialization, encryption, and restoration.

### 2.5 Syscall Infrastructure

- **`nt_syscall/`** — SSN resolution: verify `mov eax, IMM32` extraction handles all ntdll stub formats (including hooked stubs with different prologues).
- **`agent/src/syscalls.rs`** — Agent-level syscall wrappers (5100+ lines): verify opaque dispatch, clean-call macro integration, and SSN validation.
- **Halo's Gate** — Adjacent-stub scanning logic: verify SSN offset calculation is correct for up to ±32-byte offsets.
- **Tartarus' Gate** — Extended stub scanning: verify broader offset range and validation logic.
- **NTDLL unhooking** — Verify chunked overwrite timing, protection restoration, and instruction cache flush.
- **SSN cache** — Verify `HashMap` concurrency safety (is it wrapped correctly?). Check build-number-based invalidation logic.
- **Syscall emulation** — Verify all 10 emulated syscall mappings produce equivalent behavior to their NT counterparts. Pay special attention to `NtCreateThreadEx` → `CreateRemoteThread` (no `CREATE_SUSPENDED` support).
- **`agent/src/exception_ssn.rs`** — Exception-based SSN resolution: verify correctness of the exception-driven approach.
- **`agent/src/nt_handle.rs`** — NT handle management: verify handle lifecycle and cleanup.
- **`agent/src/win_types.rs`** — Windows FFI type definitions: verify structure layouts match Windows SDK.

### 2.6 Credential Access

- **`agent/src/lsass_harvest.rs`** — Incremental memory reading: verify offset tables for Windows builds 19041–26100. Check MSV/WDigest/Kerberos/DPAPI/DCC2 parsing for structure alignment errors.
- **`agent/src/browser_data.rs`** — Chrome v127+ App-Bound Encryption bypass: verify all 4 strategies (Local COM, SYSTEM token + DPAPI, Named-pipe IPC, C4 Bomb DPAPI padding oracle). Check custom SQLite parser for edge cases (WAL mode, journal mode, corrupted headers). Verify NSS `key4.db` and `logins.json` parsing.
- **LSA Whisperer** — `agent/src/lsa_whisperer.rs` and `agent/src/lsa_whisperer_ssp.rs`: verify SSP installation path, `SpAcceptCredentials` callback receives and stores credentials correctly, MSV1_0/Kerberos/WDigest enumeration.
- **`agent/src/dpapi_backup.rs`** — DPAPI domain backup-key retrieval: verify MS-BKRP RPC protocol correctness, RSA decryption, and AES-256-CBC blob decryption.

### 2.7 Token & Privilege Operations

- **`agent/src/token_impersonation.rs`** — Token impersonation: verify SetThreadToken path, `ImpersonateNamedPipeClient` avoidance, token duplication, and auto-revert.
- **`agent/src/token_manipulation.rs`** — `MakeToken`, `StealToken`, `Rev2Self`, `GetSystem`: verify thread-safe impersonation state doesn't leak across tasks.
- **`agent/src/kernel_apc_pivot.rs`** — Kernel APC-based privilege pivoting: verify correctness.

### 2.8 Evasion Subsystem

- **AMSI bypass (Write-Raid)** — `agent/src/amsi_defense.rs`: verify race thread timing, `AmsiInitFailed` flag address resolution from `AmsiInitialize` prologue, and sleep-obfuscation pause integration.
- **AMSI bypass (HWBP)** — Verify DR0/DR1/DR7 register manipulation on x86_64 and BVR/BCR on ARM64.
- **AMSI bypass (Memory Patch)** — Verify fallback to `E_INVALIDARG` prologue patching.
- **ETW patching** — `agent/src/etw_patch.rs`: verify patch mode logic (Safe/Always/Never) and restoration of original protection.
- **ETW TI bypass** — `agent/src/etw_ti_bypass.rs`: verify Threat Intelligence ETW provider disablement.
- **Evasion transform** — `agent/src/edr_bypass_transform.rs` and `agent/src/edr_bypass_transform_aarch64.rs`: verify semantic preservation for all 5 transform types (Instruction Substitution, Register Reassignment, NOP Sled Insertion, Constant Splitting, Jump Obfuscation). Check syscall stub exclusion zones and SHA-256 verification.
- **HW BP hook framework** — `agent/src/hw_bp_hook.rs`: verify DR0-DR3 slot management, VEH callback dispatch, and fallback to inline patching.
- **SEH anti-debug** — `agent/src/seh_anti_debug.rs`: verify 6 strategies (trap flag, CloseHandle, int 0x2D, icebp, lock-prefix null deref, instrumentation callback).
- **CET bypass** — `agent/src/cet_bypass.rs`: verify 3 strategies (policy disable, CET-compatible call chains, VEH shadow-stack fix).
- **Stack spoofing** — `agent/src/stack_spoof.rs` and `agent/src/stack_db.rs`: verify multi-frame chain generation, unwind metadata validation, post-sleep revalidation.
- **Trampoline spoofing** — `agent/src/trampoline_spoof.rs`: verify multi-DLL trampoline chain construction.
- **CFG bypass** — `agent/src/cfg_bypass.rs`: verify 3 strategies (bitset manipulation, CFG-valid trampolines, dispatch override).
- **BTI/PAC bypass** — `agent/src/bti_pac_bypass.rs`: verify ARM64 BTI gadget scanning and PAC key extraction.
- **Shadow stack forge** — `agent/src/shadow_stack_forge.rs`: verify CET shadow stack manipulation.
- **IBT bypass** — `agent/src/ibt_bypass.rs`: verify Intel IBT (endbranch) bypass.
- **Self-reencode** — `agent/src/self_reencode.rs`: verify metamorphic re-encoding cycle correctness.
- **Code Transform** — `code_transform/src/` and `code_transform_macro/src/`: verify all 5 semantic-preserving transformations and ChaCha8 PRNG.

### 2.9 Memory Management

- **`agent/src/memory_guard.rs`** — Verify XChaCha20-Poly1305 encrypt/decrypt cycle is lossless. Check `Drop` implementation guarantees zeroization via `write_volatile`/`write_bytes`/`zeroize`.
- **`agent/src/page_tracker.rs`** — Evanesco: VEH handler verify page-fault → decrypt → re-execute flow doesn't infinite-loop. Verify background re-encryption thread doesn't encrypt pages that are currently in use (race condition). Confirm `PageGuard` RAII pattern.
- **Sleep obfuscation** — Verify full encrypt/decrypt cycle covers all registered regions. Check for memory regions that should be encrypted but aren't registered.
- **`agent/src/memory_guard_stub.rs`** — Memory guard stub for unsupported platforms.
- **`agent/src/memory_hygiene.rs`** — Memory wiping and sensitive data cleanup.
- **`agent/src/page_fault_exec.rs`** — PAGE_NOACCESS fault-driven execution: verify VEH handler, timer-based re-encryption, and anomaly detection.

### 2.10 Forensic Cleanup

- **`agent/src/forensic_cleanup/prefetch.rs`** — Prefetch patching: verify PF header format parsing for v17/v23/v26/v30. Check USN journal consistency operations.
- **`agent/src/forensic_cleanup/ntfs_cleanup.rs`** — USN journal cleanup: verify selective deletion doesn't corrupt journal structure.
- **`agent/src/forensic_cleanup/timestamps.rs`** — MFT timestamp restoration: verify `NtSetInformationFile` call correctness.
- **`agent/src/forensic_cleanup/event_log.rs`** — Windows Event Log cleanup: verify log manipulation correctness.
- **`agent/src/forensic_cleanup/memory_protection.rs`** — Memory protection restoration after forensic ops.
- **`agent/src/forensic_cleanup/vss_cleanup.rs`** — Volume Shadow Copy cleanup.

### 2.11 Post-Exploitation Modules

- **`agent/src/adcs_attacks.rs`** — AD CS attacks (ESC1-ESC8): verify LDAP template enumeration, vulnerability detection, certificate requests, and PKINIT authentication.
- **`agent/src/kerberos_relay.rs`** — Kerberos relay via COM cross-session activation: verify AP-REQ parsing from RPC bind security trailer, CLSID enumeration.
- **`agent/src/s4u_abuse.rs`** — S4U2Self/S4U2Proxy delegation abuse: verify TGS-REQ construction, PA-FOR-USER encoding, and ticket application.
- **`agent/src/shadow_credentials.rs`** — AD Shadow Credentials: verify KeyCredentialLink manipulation and PKINIT.
- **`agent/src/entra_attacks.rs`** — Entra ID credential attacks: verify PRT theft, Pass-the-Certificate, Golden SAML.
- **`agent/src/entra_ptc.rs`** — Entra ID Pass-the-Certificate: verify RS256 JWT assertion signing and OAuth2 client-credentials flow.
- **`agent/src/entra_app_abuse.rs`** — Entra ID OAuth application abuse: verify app registration, permission grants, client-credentials authentication.
- **`agent/src/com_hijack.rs`** — Registry-free COM hijack: verify activation context generation, proxy DLL creation, and CLSID redirection.
- **`agent/src/lolbin_xwizard.rs`** — LOLBIN xwizard: verify COM scriptlet generation, SCT XML construction, and fallback LOLBIN dispatchers (odbcconf, pcwrun, forfiles).
- **`agent/src/wsl2_evasion.rs`** — WSL2 evasion: verify ELF execution through WSL, networking relay, and ptrace injection.
- **`agent/src/vss_pivot.rs`** — Volume Shadow Copy pivoting: verify shadow copy discovery, SAM/NTDS file reading, and credential parsing.
- **`agent/src/container.rs`** — Container escape: verify cgroup release_notification, device mount, mount propagation, and cloud IMDS credential theft.
- **`agent/src/lateral_movement.rs`** — Lateral movement (PsExec/WmiExec/DcomExec/WinRmExec): verify no PowerShell dependency, native COM/WinRM/NT API usage.

### 2.12 Hardware Persistence & DMA

- **`agent/src/hardware_persistence/thunderbolt_dma.rs`** — Thunderbolt DMA: verify controller detection, vulnerability assessment, DMA payload generation, and physical memory read.
- **`agent/src/hardware_persistence/boot_persistence.rs`** — Boot persistence: verify VBR and UEFI boot persistence, boot-level artifact detection/removal.
- **`agent/src/hardware_persistence/mod.rs`** — Module dispatch and shared utilities.

### 2.13 Local Privilege Escalation

- **`agent/src/lpe/mod.rs`** — LPE dispatch: verify technique ordering and fallback logic.
- **`agent/src/lpe/named_pipe_impersonate.rs`** — Named pipe impersonation: verify pipe creation, client connection, and token extraction.
- **`agent/src/lpe/print_spooler.rs`** — Print Spooler exploitation: verify spooler interaction and privilege escalation.
- **`agent/src/lpe/token_impersonate.rs`** — Token-based LPE.

### 2.14 Reconnaissance Engine

- **`agent/src/recon/mod.rs`** — Recon dispatch and orchestration.
- **`agent/src/recon/ad_enum.rs`** — Active Directory enumeration via LDAP.
- **`agent/src/recon/attack_paths.rs`** — Graph-based BFS attack path discovery.
- **`agent/src/recon/cloud_fingerprint.rs`** — Cloud environment fingerprinting (registry + IMDS).
- **`agent/src/recon/credential_attacks.rs`** — Credential attack automation (Kerberoasting, AS-REP Roasting, password spraying).
- **`agent/src/recon/report.rs`** — Recon report generation.

### 2.15 Persistence Variants

- **`agent/src/persistence/mod.rs`** — Cross-platform persistence dispatch.
- **`agent/src/persistence/office_addin.rs`** — Office add-in persistence: verify OneDrive-synced add-in paths, OOXML/OLE2 VBA generation, and AccessVBOM registry checks.
- **`agent/src/wmi_persistence.rs`** — WMI permanent event subscriptions: verify COM-based WMI operations, encrypted cloud payload hosting, and stager generation.

### 2.16 eBPF Evasion (Linux)

- **`agent/src/ebpf_evasion.rs`** — Userspace eBPF loader: verify BPF ELF parsing, map creation (BPF_MAP_CREATE), program loading (BPF_PROG_LOAD), and tracepoint attachment via `PERF_EVENT_IOC_SET_BPF`.
- **`agent/ebpf/hide_files.bpf.c`** — File hiding BPF program: verify getdents64 interception.
- **`agent/ebpf/hide_network.bpf.c`** — Network hiding BPF program.
- **`agent/ebpf/hide_process.bpf.c`** — Process hiding BPF program: verify correct BPF map definitions and tracepoint attachment.

### 2.17 Cooperative Object-Oriented Programming (COOP)

- **`agent/src/coop.rs`** — COOP chain construction: verify vtable scanning, virtual function classification (StoreArg0, LoadArg0, CallArg0, Arithmetic, NoOp), counterfeit object construction, and virtual dispatch chaining.

### 2.18 Kernel Callback Subsystem

- **`agent/src/kernel_callback/discover.rs`** — Callback discovery: verify PsSetCreateProcessNotifyRoutine, PsSetCreateThreadNotifyRoutine, PsSetLoadImageNotifyRoutine enumeration.
- **`agent/src/kernel_callback/deploy.rs`** — Driver deployment: verify XOR decryption, NtLoadDriver, registry service entry, and file cleanup.
- **`agent/src/kernel_callback/overwrite.rs`** — Callback overwrite: verify ret pointer finding (IoInvalidDeviceRequest + ntoskrnl .text scan), physical memory write, and anti-forensic driver unlinking.
- **`agent/src/kernel_callback/driver_db.rs`** — Driver database: verify 8 vulnerable driver profiles and SHA-256 hashes.
- **`agent/src/kernel_callback/proxy.rs`** — Driver proxy layer.

### 2.19 macOS Post-Exploitation

- **`agent/src/macos_postexp.rs`** — TCC bypass (database manipulation, synthetic click, vulnerable process delegation), SIP status assessment, XPC service discovery and exploitation, Keychain dump and Secure Enclave key enumeration.
- **`agent/src/macos_ffi.rs`** — macOS FFI bindings (CoreFoundation, CoreGraphics, Security, Foundation): verify inline `#[link]` attribute correctness.

### 2.20 Mobile Platform Support

- **`agent/src/android/mod.rs`** — Android platform adapter dispatch.
- **`agent/src/android/jni_bridge.rs`** — JNI bridge: verify `nativeInit`, `nativeStart`, `nativeStop` entry points and JNIEnv handling.
- **`agent/src/android/env_checks.rs`** — Android environment validation (debugger, emulator, root detection).
- **`agent/src/android/persistence.rs`** — Android persistence (AndroidManifest, broadcast receivers).
- **`agent/src/android/post_exploitation.rs`** — Android post-exploitation stubs.
- **`agent/src/ios/mod.rs`** — iOS platform adapter dispatch.
- **`agent/src/ios/bridge.rs`** — iOS C bridge: verify `orchestra_init`, `orchestra_start`, `orchestra_stop` C ABI functions.
- **`agent/src/ios/env_checks.rs`** — iOS environment validation (jailbreak, debugger detection).
- **`agent/src/ios/persistence.rs`** — iOS persistence.
- **`agent/src/ios/post_exploitation.rs`** — iOS post-exploitation stubs.

### 2.21 Advanced Sleep & Timing

- **`agent/src/hw_timer_sleep.rs`** — Hardware timer-based sleep: verify correctness.
- **`agent/src/adaptive_timing.rs`** — Adaptive C2 timing: verify Gaussian-distributed scheduling, learning phase, and graceful degradation to standard jitter.
- **`agent/src/perf.rs`** — Performance monitoring and microarchitecture detection.

### 2.22 Miscellaneous Agent Modules

- **`agent/src/shell.rs`** — Shell command execution.
- **`agent/src/fsops.rs`** — Filesystem operations.
- **`agent/src/outbound.rs`** — Outbound connection logic.
- **`agent/src/process_manager.rs`** — Process management (create, migrate, monitor).
- **`agent/src/process_spoof.rs`** — PPID spoofing and process attribute manipulation.
- **`agent/src/stub.rs`** — Payload stub generation.
- **`agent/src/remote_assist.rs`** — Screen capture and input simulation across platforms.
- **`agent/src/hci_logging.rs`** — HCI telemetry collection.
- **`agent/src/surveillance.rs`** — Screenshot, keylogger, clipboard monitoring.
- **`agent/src/net_discovery.rs`** — Network discovery (ARP, ICMP, TCP).
- **`agent/src/interactive_shell.rs`** — PTY shell session management.
- **`agent/src/assembly_loader.rs`** — .NET assembly execution via CLR hosting.
- **`agent/src/coff_loader.rs`** — Beacon Object File (BOF/COFF) execution.
- **`agent/src/config.rs`** — Configuration loading.
- **`agent/src/env_check.rs`** — Environment validation (debugger, VM, sandbox, domain).
- **`agent/src/env_check_sandbox.rs`** — Extended sandbox scoring.
- **`agent/src/env_check_hpc.rs`** — Hardware performance counter checks.
- **`agent/src/env_check_rdtsc.rs`** — RDTSC timing checks.
- **`agent/src/env_check_arm64_timer.rs`** — ARM64 timer-based checks.
- **`agent/src/p2p.rs`** — P2P mesh networking.
- **`agent/src/kernel_arg_spoof.rs`** — Kernel argument spoofing.
- **`agent/src/page_size.rs`** — Page size detection.

### 2.23 C2 Server Infrastructure

- **`orchestra-server/src/main.rs`** — Server entry point, TLS configuration, startup sequencing.
- **`orchestra-server/src/agent_link.rs`** — Agent connection management, registry, and link lifecycle.
- **`orchestra-server/src/api.rs`** — REST API handlers.
- **`orchestra-server/src/auth.rs`** — Authentication and rate limiting.
- **`orchestra-server/src/audit.rs`** — HMAC-SHA256 audit log.
- **`orchestra-server/src/build_handler.rs`** — Async build queue worker pool.
- **`orchestra-server/src/config.rs`** — Server configuration.
- **`orchestra-server/src/doh_listener.rs`** — DNS-over-HTTPS bridge.
- **`orchestra-server/src/http_c2.rs`** — HTTP malleable C2 handler.
- **`orchestra-server/src/malleable.rs`** — Malleable profile management.
- **`orchestra-server/src/mesh_controller.rs`** — Mesh topology controller.
- **`orchestra-server/src/redirector.rs`** — Redirector management.
- **`orchestra-server/src/smb_relay.rs`** — SMB pipe relay.
- **`orchestra-server/src/state.rs`** — Shared server state.
- **`orchestra-server/src/tls.rs`** — TLS/mTLS configuration.

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

**Pay special attention to:**
- Android/iOS modules (`agent/src/android/`, `agent/src/ios/`) — alpha/alpha-quality, check for placeholder stubs
- `mobile-postexp` feature module — check implementation depth
- `agent/resources/placeholder_driver.xor` — verify it is a documented placeholder, not a missing driver
- Any feature flag from `agent/Cargo.toml` lines 135–676 that has minimal implementation

For each finding, classify severity:
- **High** — Advertised feature that does nothing or returns wrong results silently
- **Medium** — Feature partially implemented with known gaps
- **Low** — Intentional stub with clear `// TODO` marker

---

## Part 4 — Platform-Specific Issues

For each of the five supported platforms, identify:

### Linux (x86_64 and aarch64)
- `agent/src/syscalls.rs` — Linux `direct_syscalls` inline assembly: verify syscall number tables, argument passing (6-arg limit with `EINVAL` fallback), and error code handling.
- `agent/src/ebpf_evasion.rs` and `agent/ebpf/*.bpf.c` — eBPF modules: verify BPF program correctness, map definitions, and userspace loader integration.
- `agent/src/container.rs` — Container escape (`container-escape` feature): verify completeness of Docker/Podman/Kubernetes/LXC detection, cgroup release_notification, device mount, and mount propagation.
- `agent/src/persistence/mod.rs` — Linux persistence (systemd user unit): verify unit file generation and enabling.
- `agent/src/env_check.rs` — Linux env checks (`/proc/self/status` TracerPid, CPUID, DMI strings): verify robustness.
- `agent/src/env_check_hpc.rs`, `agent/src/env_check_rdtsc.rs` — Timing-based checks on Linux.
- `agent/src/` — Linux injection (`agent/src/injection/linux_inject.rs`): verify ptrace/memfd injection.

### Windows (x86_64 and aarch64)
- **ARM64-specific**: Verify all inline assembly paths have ARM64 alternatives. Check BTI/PAC bypass (`pac-bypass` feature) implementation in `bti_pac_bypass.rs`. Verify syscall dispatch uses x8 SSN register. Check `edr_bypass_transform_aarch64.rs` ARM64 transform correctness.
- **x86_64-specific**: Verify CET bypass strategies all compile and have correct logic in `cet_bypass.rs`. Verify stack-spoofing chain templates in `stack_db.rs` have valid unwind metadata. Check `cfg_bypass.rs`, `trampoline_spoof.rs`, `coop.rs`.
- Verify all Windows API calls use the correct Unicode (W) variants where applicable.
- Verify `cfg(target_arch)` and `cfg(target_os)` gates are consistent and complete.

### macOS (x86_64 and aarch64)
- `agent/src/persistence/mod.rs` — macOS persistence (LaunchAgent, ServiceManagement): verify both code paths.
- `agent/src/env_check.rs` — macOS env checks: verify `/etc/resolv.conf` parsing, IMDS reachability check.
- `agent/src/env_check.rs` — macOS cloud instance detection: verify graceful degradation when IMDS is unavailable.
- `agent/src/macos_postexp.rs` — `macos-postexp` feature: verify TCC/SIP/XPC/Keychain module completeness.
- `agent/src/macos_ffi.rs` — Verify FFI bindings to Apple frameworks are correct for both architectures.
- `agent/src/remote_assist.rs` — macOS screen capture via CoreGraphics.

### Android (aarch64 and x86_64)
- `agent/src/android/jni_bridge.rs` — Verify JNI function signatures match Java/Kotlin expectations.
- `agent/src/android/env_checks.rs` — Verify emulator detection, root detection, and debugger checks.
- `agent/src/android/persistence.rs` — Verify BroadcastReceiver and foreground service registration.
- `agent/src/android/post_exploitation.rs` — Audit implementation depth.
- `mobile/android/` — Verify Gradle build configuration, AgentService foreground service, and BootReceiver.

### iOS (aarch64)
- `agent/src/ios/bridge.rs` — Verify C ABI function signatures for `orchestra_init`, `orchestra_start`, `orchestra_stop`.
- `agent/src/ios/env_checks.rs` — Verify jailbreak detection and debugger checks.
- `agent/src/ios/persistence.rs` and `agent/src/ios/post_exploitation.rs` — Audit implementation depth.
- `mobile/ios/OrchestraBridge/` — Verify Xcode static library build.

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
  - Bare-metal hypervisors (VMware/VirtualBox on workstations)
  - Cloud instances (AWS/Azure/GCP with expected hypervisors + IMDS)
  - Legitimate cloud workloads that should NOT trigger exit
- Verify cloud whitelisting controls (`cloud_instance_allow_without_imds`, `cloud_instance_fallback_ids`) handle all documented cloud providers.

### 5.2 Sandbox Detection
- Verify the weighted indicator scoring system doesn't produce false positives on:
  - CI/CD runner environments
  - Containerized production workloads
  - Hardened corporate endpoints with EDR
- Verify the `sandbox_score_threshold` configuration actually gates the exit behavior.
- Verify `agent/src/env_check_sandbox.rs` scoring calculations.

### 5.3 Debugger Detection
- Verify `TracerPid` parsing handles all `/proc/self/status` format variants on Linux.
- Verify `IsDebuggerPresent()` check on Windows handles both user-mode and kernel-mode debuggers.
- Verify `seh-anti-debug` feature implementation completeness.
- Verify `agent/src/env_check_hpc.rs` HPC-based detection.
- Verify `agent/src/env_check_rdtsc.rs` timing-based detection.
- Verify `agent/src/env_check_arm64_timer.rs` ARM64-specific timing checks.

### 5.4 Domain Validation
- Verify AD domain detection on Linux parses all valid `/etc/resolv.conf` formats (including `search` with multiple domains).
- Verify Windows registry path for domain detection is correct across Windows 10/11 versions.
- Verify AAD/Entra ID join detection works.

---

## Part 6 — Server & Builder Infrastructure

### 6.1 Orchestra Server (`orchestra-server/`)
- Verify REST API endpoint correctness (`POST /api/build`, status polling, artifact download).
- Verify mTLS enforcement and CN/OU filtering in `tls.rs`.
- Verify async build queue worker pool in `build_handler.rs`: race conditions, resource cleanup, timeout handling.
- Verify DNS-over-HTTPS bridge (`doh_listener.rs`): rate limiting, encoding correctness.
- Verify HMAC-SHA256 audit log signing and tamper detection on read in `audit.rs`.
- Verify static file serving for the web dashboard.
- Verify HTTP malleable C2 handler in `http_c2.rs`.
- Verify mesh controller in `mesh_controller.rs`: topology management, REST endpoints, kill switch, quarantine, compartment isolation.
- Verify SMB relay in `smb_relay.rs`.
- Verify agent link lifecycle in `agent_link.rs`: connection registry, heartbeat, cleanup.
- Verify authentication and rate limiting in `auth.rs`.

### 6.2 Builder (`builder/`)
- Verify `read_agent_features()` correctly parses `agent/Cargo.toml` and handles unknown features.
- Verify environment variable propagation chain: server config → `PayloadConfig` → build worker → `cargo:rustc-env` → `option_env!()`.
- Verify profile TOML parsing and feature flag validation.
- Verify build artifact packaging and signing.
- Verify `--diversify` flag invokes optimizer passes correctly.
- Verify `--seed` parameter produces reproducible builds.

### 6.3 Supporting Crates — Full Functional Audit

- **`payload-packager/`** — Polymorphic payload layout variation and encryption. Verify multi-cipher layout, XOR obfuscation, and stub emitter correctness. Check register-shuffled constants and encoding helpers in `stub_emitter.rs`.
- **`shellcode_packager/`** — Shellcode extraction and packaging.
- **`orchestra-pe-hardener/`** — PE hardening operations (checksum recalculation, section manipulation, certificate stripping).
- **`orchestra-side-load-gen/`** — DLL generation and export forwarding. Verify export table construction and proxy DLL generation.
- **`redirector/`** — Traffic forwarding logic, TLS passthrough, and failover.
- **`keygen/`** — Key generation correctness (Ed25519, X25519, module signing keys).
- **`optimizer/`** — Metamorphic transformation correctness and semantic preservation. Verify InstructionSubstitutionPass, OpaqueDeadCodePass, build.rs stub seed propagation.
- **`uefi-persistence/`** — UEFI NVRAM/ESP operations. Verify NVRAM read/write (`GetFirmwareEnvironmentVariableW` on Windows, `/sys/firmware/efi/efivars` on Linux), ESP mounting, boot entry manipulation, and capsule delivery.
- **`code_transform/`** — Semantic-preserving code transforms. Verify all 5 transform types preserve semantics, ChaCha8 PRNG determinism, and attribute macro parsing.
- **`code_transform_macro/`** — Proc-macro attribute parsing and code generation. Verify `#[transform]` attribute exhaustiveness.
- **`string_crypt/`** — Build-time string encryption. Verify encrypt/decrypt round-trip at runtime, build.rs hash generation.
- **`junk_macro/`** — Junk code generation. Verify output is syntactically valid in all contexts (function body, block, expression position).
- **`pe_resolve/`** — PE export resolution by hash. Verify hash-based API resolution produces correct function addresses, IAT-free operation.
- **`hollowing/`** — Process hollowing shared crate. Verify PE header parsing, section mapping, import resolution, and relocation fixups.
- **`module_loader/`** — In-memory PE loading. Verify section alignment, import resolution, and entry-point invocation.
- **`launcher/`** — Payload launcher. Verify memfd/PE hollowing dispatch, argv[0] spoofing, and persistence integration.
- **`console/`** — CLI console. Verify command dispatch, transport layer, and all 11 subcommands.
- **`dev-server/`** — Development server. Verify agent simulation and build workflow.
- **`keygen/`** — Cryptographic key generation for all key types.
- **`plugins/hello_plugin/`** — Reference plugin. Verify module signing and loading integration.

### 6.4 ZAI Provider Extension (`zai-provider-extension/`)
- Verify VS Code extension packaging and activation.
- Verify TypeScript/webview integration with the C2 server.
- Verify any client-side cryptographic operations.

---

## Part 7 — Dependency & Supply Chain

- Verify all `Cargo.toml` dependency versions are pinned or have minimum-version constraints.
- Check for any dependency that is unused but listed.
- Check for any dependency version conflict across workspace members.
- Verify `Cargo.lock` is committed and consistent with `Cargo.toml` files.
- Verify feature flag `implies` chains are correct and non-circular.
- Run `cargo audit` if available, or manually identify any dependency with known vulnerabilities (flag suspiciously old or unmaintained crates).
- Check the russh 0.60.2 situation (pulls ~16 pre-release RustCrypto crate versions) — note any duplicate crate versions in Cargo.lock.
- Verify the `ring` dependency (0.17) usage is correctly gated behind `entra-ptc` feature.
- Check for any version conflicts between `chacha20` (0.9), `chacha20poly1305` (0.10), `aes` (0.9.0), and `aes-gcm` (0.10).
- Verify `windows-sys` 0.59 feature list is sufficient for all Windows API usage across the agent crate.

---

## Part 8 — Test Coverage Assessment

- **`agent/tests/`** — Identify what is tested and what is not. List all test modules and their coverage.
- **`agent/benches/`** — Verify benchmark harnesses are meaningful (criterion-based).
- **`code_transform/tests/`** — Verify transform correctness tests.
- **`code_transform_macro/tests/`** — Verify macro expansion tests.
- **`orchestra-server/tests/`** — Verify API integration tests.
- **`launcher/tests/`** — Verify launcher tests (note: hollowing_test is `#[ignore]` — requires Windows).
- **`hollowing/`** — Note: manual Windows test is `#[ignore]`.
- **`pe_resolve/`** — Verify proptest regression coverage.
- **`common/proptest-regressions/`** — Verify property-based test coverage.
- **`string_crypt/`** — Check for encryption round-trip tests.
- **`junk_macro/`** — Check for compile-output tests.
- **`optimizer/`** — Verify benchmark-only or test coverage.
- **`module_loader/`** — Verify module signing and loading tests.
- **`builder/`** — Verify build workflow tests.
- Identify critical subsystems that have **zero test coverage**.

**Critical subsystems typically with zero test coverage:**
1. Injection engine (all 15 techniques)
2. Sleep obfuscation (Ekko/Cronus)
3. Memory guard / Evanesco
4. All C2 transports (HTTP, DoH, SSH, SMB, QUIC, Graph)
5. AMSI bypass / ETW patching / ETW TI bypass
6. LSASS harvest / LSA Whisperer
7. Browser data extraction / C4 Bomb DPAPI oracle
8. Forensic cleanup pipeline (all stages)
9. P2P mesh protocol
10. All post-exploitation modules (ADCS, Kerberos relay, S4U, shadow creds)
11. Entra ID attack suite
12. Hardware persistence / DMA
13. LPE modules
14. Recon engine
15. Mobile platform modules
16. Container escape / WSL2 evasion
17. COM hijack / LOLBIN xwizard

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
- Command dispatch (handlers.rs, 120+ commands)
- Module/plugin loader
- Interactive PTY shell
- Agent initialization sequence

**Transport:**
- HTTP malleable C2
- DNS-over-HTTPS C2
- SSH subsystem C2
- SMB named pipe C2
- QUIC/HTTP3 C2
- Microsoft Graph C2
- Forward secrecy (X25519)
- Traffic normalization
- Malleable profile system

**Windows Injection (15 techniques):**
- Process Hollowing
- ThreadPool (8 sub-variants: Work, WorkerFactory, Timer, IoCompletion, Wait, Alpc, Direct, AsyncIo)
- Fiber Injection
- Context-Only Injection
- Section Mapping Injection
- NtSetInformationProcess Write Bypass
- Waiting Thread Hijack
- Transacted Hollowing (NTFS transaction + ETW blinding)
- Process Doppelganging
- Delayed Module Stomp
- Existing Module Stomp
- Module Stomp
- Phantom DLL Hollowing
- Callback Injection (12 APIs)
- Early Bird APC Injection
- DLL Sideloading
- Linux ptrace/memfd Injection
- Code Cave Injection
- Reflective DLL Loading (NtCreateSection)

**Windows Evasion:**
- Direct/indirect syscalls (nt_syscall)
- NTDLL unhooking (KnownDlls + disk fallback)
- Halo's Gate
- Tartarus' Gate
- AMSI bypass (Write-Raid / HWBP / Memory Patch)
- ETW patching (Safe/Always/Never)
- ETW TI bypass
- CET/shadow-stack bypass (3 strategies)
- Stack spoofing (NtContinue multi-frame)
- Trampoline spoofing (multi-DLL)
- CFG bypass (3 strategies)
- BTI/PAC bypass (ARM64)
- Shadow stack forge
- IBT bypass
- Syscall emulation (10 mapped APIs)
- Evasion transform (5 types, x86_64 + ARM64)
- Self-reencode
- SEH anti-debug (6 strategies)
- HW BP hook framework (DR0-DR3)
- Code transform (5 semantic-preserving types)
- HW timer sleep
- Kernel argument spoofing
- Kernel APC pivot
- Exception-based SSN resolution

**Windows Credential Access:**
- LSASS harvest (incremental memory read)
- LSA Whisperer (SSP interface)
- Browser data (Chrome/Edge/Firefox)
- C4 Bomb DPAPI padding oracle
- DPAPI backup key retrieval
- Token manipulation & impersonation
- Token-only impersonation (2 strategies)

**Windows Forensics:**
- Prefetch cleanup (Patch/Delete/Disable)
- USN journal cleanup
- MFT timestamp manipulation
- $LogFile cleanup
- Event log cleanup
- Memory protection restoration
- VSS cleanup

**Cross-Platform:**
- Sleep obfuscation (Ekko / Cronus)
- Memory guard
- Evanesco (continuous memory hiding)
- Thread context encryption
- Memory hygiene
- Network discovery (ARP/ping/TCP)
- Persistence (systemd/schtasks/launchd)
- Remote assist (screen capture/input sim)
- File system operations
- HCI research/logging
- Surveillance (screenshot/keylogger/clipboard)
- Adaptive C2 timing

**Post-Exploitation:**
- .NET assembly loader
- BOF/COFF loader
- Lateral movement (PsExec/WmiExec/DcomExec/WinRmExec)
- P2P mesh (SMB/TCP relay)
- Kerberos relay (COM cross-session)
- S4U abuse (S4U2Self/S4U2Proxy)
- Shadow Credentials (KeyCredentialLink)
- ADCS attacks (ESC1-ESC8)
- Container escape (Linux)
- WSL2 evasion
- COM hijack (registry-free)
- LOLBIN xwizard (+ fallback dispatchers)
- VSS pivot
- Entra ID Pass-the-Certificate
- Entra ID credential attacks
- Entra ID OAuth app abuse
- Hardware/firmware persistence (Thunderbolt DMA + boot)
- LPE modules (named pipe + print spooler + token)
- Recon engine (AD enum + attack paths + cloud fingerprint + cred attacks)
- Office add-in persistence
- WMI persistence
- eBPF hiding (Linux)
- COOP chain construction
- Page-fault driven execution
- macOS post-exploitation (TCC/SIP/XPC/Keychain)

**Mobile Platform (Alpha):**
- Android JNI bridge
- Android env checks
- Android persistence
- Android post-exploitation
- iOS C bridge
- iOS env checks
- iOS persistence
- iOS post-exploitation
- Android Gradle build
- iOS Xcode build

**Infrastructure:**
- Orchestra server (REST API, mTLS, build queue)
- Server mesh controller
- Server HTTP C2 handler
- Server SMB relay
- Server DoH bridge
- Server audit log (HMAC-SHA256)
- Builder (feature discovery, env propagation, --diversify, --seed)
- Payload packager (polymorphic layout)
- Shellcode packager
- PE hardener
- Side-load generator
- Redirector
- Keygen
- Optimizer (metamorphic transforms)
- UEFI persistence (NVRAM/ESP)
- Code transform macro
- String crypt
- Junk macro
- PE resolve (hash-based export resolution)
- Hollowing (shared crate)
- Module loader (manual PE mapping)
- Launcher
- Console CLI
- Dev server
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
### Android
...
### iOS
...

## False-Positive / False-Negative Risks
(Environment checks that may incorrectly block or allow execution)
...

## Dependency & Build Issues
...

## Test Coverage Gaps
(List of critical subsystems with zero or minimal test coverage)
...

## Functional Status Matrix
(The full table from Part 9)

## Appendix: Files Audited
(Complete list of source files examined — should include EVERY .rs file in the workspace)
```

---

## Part 11 — Audit Completion Checklist

Before finalizing the report, verify you have covered **every** source file in the workspace. The workspace contains **28 crates** with source files in these directories:

| Crate | Source Directory | Files (approx.) |
|-------|-----------------|-----------------|
| agent | `agent/src/` | 110+ .rs files |
| common | `common/src/` | 16 .rs files |
| console | `console/src/` | ~5 .rs files |
| dev-server | `dev-server/src/` | ~3 .rs files |
| builder | `builder/src/` | ~5 .rs files |
| orchestra-server | `orchestra-server/src/` | 16 .rs files |
| plugins/hello_plugin | `plugins/hello_plugin/src/` | ~2 .rs files |
| keygen | `keygen/src/` | ~2 .rs files |
| hollowing | `hollowing/src/` | ~3 .rs files |
| orchestra-side-load-gen | `orchestra-side-load-gen/src/` | ~3 .rs files |
| redirector | `redirector/src/` | ~3 .rs files |
| string_crypt | `string_crypt/src/` | ~3 .rs files |
| pe_resolve | `pe_resolve/src/` | ~3 .rs files |
| junk_macro | `junk_macro/src/` | ~2 .rs files |
| code_transform | `code_transform/src/` | ~4 .rs files |
| code_transform_macro | `code_transform_macro/src/` | ~2 .rs files |
| nt_syscall | `nt_syscall/src/` | ~2 .rs files |
| shellcode_packager | `shellcode_packager/src/` | ~2 .rs files |
| uefi-persistence | `uefi-persistence/src/` | ~3 .rs files |
| orchestra-pe-hardener | `orchestra-pe-hardener/src/` | ~2 .rs files |
| payload-packager | `payload-packager/src/` | ~3 .rs files |
| module_loader | `module_loader/src/` | ~3 .rs files |
| optimizer | `optimizer/src/` | ~5 .rs files |
| launcher | `launcher/src/` | ~3 .rs files |
| mobile/android | `mobile/android/` | Kotlin/XML + shell scripts |
| mobile/ios | `mobile/ios/` | Swift/ObjC + shell scripts |
| zai-provider-extension | `zai-provider-extension/` | TypeScript |
| agent/ebpf | `agent/ebpf/` | 3 .bpf.c files |

Additionally review:
- Build scripts: `agent/build.rs`, `common/build.rs`, `pe_resolve/build.rs`, `optimizer/build.rs`, `orchestra-side-load-gen/build.rs`, `string_crypt/build.rs`
- Workspace: `Cargo.toml`, `Cargo.lock`
- Documentation: all files in `docs/`
- Scripts: all files in `scripts/`

---

## Final Reminders

- **Read before concluding.** Do not assume a module is broken without reading its source. Do not assume a module works without tracing its logic.
- **Distinguish** between "intentionally not implemented" (feature-gated off) and "advertised but broken" (feature-gated on but non-functional).
- **Distinguish** between "known limitation documented in ROADMAP.md" and "undocumented bug."
- **Cross-reference** documentation claims against actual implementation. If `ARCHITECTURE.md` says a module does X but the code does Y, that is a finding.
- **Mobile modules** (Android/iOS) are alpha-quality — expect stubs and partial implementations. Flag them but don't treat alpha stubs the same as production-module defects.
- **Be specific.** Every finding must include the exact file path, line range, and a description of what is wrong. Vague statements like "the injection engine has issues" are not useful.
- **Prioritize.** A crash in a core path is more important than a typo in a comment.
- **Verify with cargo.** Run `cargo check`, `cargo test`, `cargo clippy` to confirm your findings where possible.