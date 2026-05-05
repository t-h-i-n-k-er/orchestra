# Changelog

All notable changes to Orchestra are documented here.

---

## [Unreleased]

### Feature Categories

| Category | Features |
|----------|----------|
| **Evasion & Stealth** | Evanesco, CET Bypass, Token Impersonation, Syscall Emulation, Kernel Callback (BYOVD), EDR Bypass Transform, AMSI Write-Raid, NTDLL Unhooking, Stack Spoofing |
| **Injection** | Transacted Hollowing, Delayed Module Stomp, Injection Engine Expansion, .NET Assembly Loader, BOF/COFF Loader |
| **Post-Exploitation** | C4 Bomb (DPAPI), LSA Whisperer, Browser Data, LSASS Harvest, Surveillance, Interactive Shells |
| **Forensics** | Prefetch Evidence Removal, Dynamic SSN Validation, Sleep Obfuscation (Ekko + Cronus) |
| **Infrastructure** | P2P Mesh, Server (Build Queue, DoH, mTLS, Mesh Controller), Builder, Protocol v2, Audit HMAC |

### Added

#### Windows Prefetch Evidence Removal (`forensic-cleanup` feature)
- **Prefetch (.pf) evidence removal** — Cleans Windows Prefetch files that
  record process execution evidence (executable name, run count, timestamps,
  loaded DLLs, directories accessed).  EDR and forensic tools parse these to
  build execution timelines.  All NT API calls use indirect syscalls via
  `nt_syscall` to bypass user-mode API hooks.
- **Three cleanup strategies**:
  1. **Patch** (preferred) — Maps the .pf file via `NtCreateSection` +
     `NtMapViewOfSection`, patches the header in-place (zeros run count,
     timestamps, executable name/paths), then unmaps.
  2. **Delete** — Removes the .pf file via `NtDeleteFile`.
  3. **Disable service** — Sets `EnablePrefetcher` registry value to 0 before
     the operation, restores after.
- **USN journal consistency** — Reads USN journal entries referencing the .pf
  file and writes USN close records to cleanly mark them.
- **Post-injection auto-cleanup** — Hooks into `TransactedHollow` and
  `DelayedStomp` injection handlers to automatically clean .pf evidence.
- **PF format support** — Parses MAM-format .pf headers for Windows 8 (v17),
  8.1 (v23), 10 (v26), and 11 (v30).
- **Feature flag** — `forensic-cleanup = ["direct-syscalls"]` in
  `agent/Cargo.toml`.

#### User-Mode NT Kernel Interface Emulation (`syscall-emulation` feature)
- **kernel32/advapi32 syscall emulation** — Frequently-used NT syscalls are
  implemented entirely in user-mode via kernel32/advapi32 fallbacks, eliminating
  all references to ntdll.dll syscall stubs. Makes the agent invisible to EDR
  hooks on ntdll AND to ntdll unhooking detection.
- **9 emulated syscalls**: `NtWriteVirtualMemory`, `NtReadVirtualMemory`,
  `NtAllocateVirtualMemory`, `NtFreeVirtualMemory`, `NtProtectVirtualMemory`,
  `NtCreateThreadEx`, `NtOpenProcess`, `NtClose`, `NtQueryVirtualMemory`.
- **`emulated_syscall!` macro** — Drop-in replacement for `nt_syscall::syscall!`.
  Routes through kernel32/advapi32 when enabled, falls back to indirect syscalls.
- **Call stack legitimacy** — When kernel32 equivalents are used, the call
  stack shows `kernel32!WriteProcessMemory` etc. instead of ntdll syscall stubs.
- **Feature flag** — `syscall-emulation = ["direct-syscalls"]` in
  `agent/Cargo.toml`.

#### CET / Shadow Stack Bypass (`cet-bypass` feature)
- **Windows 11 24H2+ shadow-stack bypass** — Detects and bypasses Intel CET
  hardware-enforced shadow stacks that break traditional stack-spoofing.
- **Three bypass strategies**:
  1. **Policy disable** — `SetProcessMitigationPolicy` or
     `NtSetInformationProcess` (info class 52) to disable CET.
  2. **CET-compatible call chains** — Routes NT API calls through kernel32
     equivalents for valid shadow-stack entries.
  3. **VEH shadow-stack fix** — Vectored Exception Handler for `#CP` exceptions
     to patch shadow-stack entries.
- **Build detection** — Reads Windows build from `KUSER_SHARED_DATA` at
  `0x7FFE0000+0x260`; CET assumed on builds ≥ 26100.
- **Feature flag** — `cet-bypass = ["direct-syscalls"]` in `agent/Cargo.toml`.

#### Token-Only Impersonation (`token-impersonation` feature)
- **EDR-evading token impersonation** — Extracts and applies impersonation
  tokens without calling `ImpersonateNamedPipeClient` on the main thread.
- **Two bypass strategies**:
  1. **SetThreadToken** (preferred) — Briefly impersonates, extracts token,
     reverts immediately, then applies via `SetThreadToken`.
  2. **Impersonation thread** (fallback) — Spawns helper thread for
     `ConnectNamedPipe` + `ImpersonateNamedPipeClient`; main thread extracts
     token via `NtOpenThreadToken` on the helper.
- **Encrypted token cache** — Duplicated tokens stored in `HashMap` with
  user/domain/SID metadata for reuse across operations.
- **Auto-revert** — Optionally reverts impersonation after each C2 task.
- **Integration** — `lsass_harvest` checks cached token first; P2P SMB pipe
  server extracts tokens from connecting peers.
- **Feature flag** — `token-impersonation = ["direct-syscalls"]` in
  `agent/Cargo.toml`.

#### Continuous Memory Hiding — Evanesco (`evanesco` feature)
- **Per-page RC4 encryption at rest** — All enrolled memory pages are kept in
  an encrypted + `PAGE_NOACCESS` state whenever they are not actively being
  executed or read.  Unlike sleep-only encryption (Ekko/Cronus), Evanesco
  operates continuously, not just during `secure_sleep` cycles.
- **JIT decryption via `acquire_pages()`** — Returns a `PageGuard` RAII handle
  that decrypts the requested ranges with the requested access type
  (`ReadWrite` or `Execute`), sets appropriate page protection, and
  automatically re-encrypts on drop.
- **VEH-based auto-decryption** — A Vectored Exception Handler catches
  `STATUS_ACCESS_VIOLATION` on tracked `PAGE_NOACCESS` pages and transparently
  decrypts them for execution.  This allows, e.g., callback-based injection
  methods to fire without explicit `acquire_pages()` calls.
- **Background re-encryption thread** — Scans all tracked pages every
  `scan_interval_ms` (default 50 ms) and re-encrypts any page that has been
  idle longer than `idle_threshold_ms` (default 100 ms).
- **Sleep-obfuscation integration** — `encrypt_all()` is called during
  `secure_sleep` to sweep all pages; `decrypt_minimum()` restores the bare
  minimum on wake.  XChaCha20-Poly1305 is still used for the full sleep sweep,
  RC4 for per-page continuous encryption.
- **`EvanescoConfig`** — New config struct in `common/src/config.rs` with
  `idle_threshold_ms` and `scan_interval_ms` fields.  New `evanesco` section
  in agent TOML config.
- **Runtime commands** — `EvanescoStatus` returns live statistics (page count,
  encrypt/decrypt counters); `EvanescoSetThreshold { idle_ms }` adjusts the
  idle threshold at runtime.
- **Feature flag** — `evanesco = []` in `agent/Cargo.toml`.  All code is
  cfg-gated behind `#[cfg(all(windows, feature = "evanesco"))]`.
- **New module: `agent/src/page_tracker.rs`** — ~550 lines implementing
  `PageTrackerInner`, `PageGuard`, `PageInfo`, `PageState`, `AccessType`,
  RC4 primitives, VEH handler, background thread, and public API.

#### C4 Bomb — DPAPI Padding Oracle (`browser-data` feature)
- **4th App-Bound Encryption bypass strategy** — Implements a full CBC
  padding-oracle attack against Windows DPAPI's `CryptUnprotectData` to
  recover the Chrome v20+ App-Bound encryption key without elevation.
- **Attempted first** — C4 runs before the existing elevated strategies (COM
  IElevator, SYSTEM token impersonation, named-pipe relay), maximizing the
  chance of silent key recovery.
- **Configurable timeout** — `browser_c4_timeout_secs` in agent TOML (default
  60 s). Set to `0` to disable C4 entirely.
- **Cancellation-safe** — `C4_LOCK` serializes attacks; a new request cancels
  any in-progress attack via `AtomicBool`.
- **OPSEC hardening** — Random inter-oracle delays (1–10 ms, LCG-based),
  shuffled candidate bytes (LCG), no heap allocations in the hot loop.
- **pe_resolve integration** — Dynamically resolves `CryptUnprotectData` from
  `crypt32.dll` at runtime via hash-based API resolution (no import table
  entries).
- **Robust blob parsing** — `parse_dpapi_blob()` walks DPAPI blob headers,
  credential/mask keys, and falls back to heuristic offset detection for
  non-standard blob layouts.

#### LSA Whisperer — SSP Interface Credential Extraction (`lsa-whisperer` feature)
- **LSA SSP interface credential extraction** — Harvests credentials from LSA
  authentication packages (MSV1_0, Kerberos, WDigest) through their documented
  interfaces, operating entirely within the LSA process's own security context
  without reading LSASS process memory.
- **Credential Guard bypass** — Credential Guard protects LSASS *process memory*,
  not the SSP interface.  SSP responses are authorized outputs from the LSA
  process itself.
- **RunAsPPL bypass** — No LSASS memory reads means no `NtReadVirtualMemory`
  on the protected process.
- **Two extraction methods**:
  - **Untrusted** — `LsaConnectUntrusted` (any process, no admin required).
    Queries MSV1_0 (EnumUsers, SubAuth), Kerberos (ticket cache), and WDigest.
  - **SSP Inject** — Registers as a logon process via `LsaRegisterLogonProcess`
    (requires SeTcbPrivilege / admin) for richer credential data. Falls back
    to untrusted if not elevated.
- **Auto mode** — Tries SSP injection first, falls back to untrusted.
- **pe_resolve integration** — All 6 LSA API functions dynamically resolved
  from `secur32.dll` via hash-based API resolution (no import table entries).
- **Configurable** — `LsaWhispererConfig` with `timeout_secs` (default 30),
  `buffer_size` (default 1024), `auto_inject` (default true).
- **Runtime commands** — `HarvestLSA { method: LsaMethod }`,
  `LSAWhispererStatus`, `LSAWhispererStop`.
- **Anti-forensic cleanup** — `whisperer_stop()` securely zeroes the
  credential buffer with `write_volatile` + compiler fence.
- **Feature flag** — `lsa-whisperer = []` in `agent/Cargo.toml`.
- **New module: `agent/src/lsa_whisperer.rs`** — ~580 lines implementing
  dynamic API resolution, RAII LSA handle, MSV1_0/Kerberos/WDigest response
  parsers, credential ring buffer, and public API.

#### Indirect Dynamic Syscall Resolution (`direct-syscalls` feature upgrade)
- **Runtime SSN validation** — Two complementary methods detect stale SSN
  caches without re-resolving:
  - **Cross-reference**: Compares the PE `TimeDateStamp` of the loaded ntdll
    with the cached timestamp.  Mismatches (e.g. after Windows Update)
    trigger full cache invalidation.
  - **Probe**: Calls 4 critical syscalls (`NtAllocateVirtualMemory`,
    `NtProtectVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx`)
    with a NULL handle.  `STATUS_INVALID_HANDLE` confirms the SSN is valid;
    `STATUS_INVALID_SYSTEM_SERVICE` means it's stale.
- **SSDT-based nuclear fallback** — When both clean-mapping and Halo's Gate
  fail, resolves SSNs from the kernel's `KeServiceDescriptorTable` via
  `NtQuerySystemInformation(SystemModuleInformation)`.  Uses build-number-
  based SSN range table as the final authoritative source.  Requires
  `SeDebugPrivilege`.
- **Build-aware SSN cache** — Windows build number cached from
  `KUSER_SHARED_DATA` (always mapped at `0x7FFE0000`).  Cache entries
  include the PE timestamp of the ntdll they were resolved from.  Build
  number changes invalidate all entries.
- **Versioned syscall stubs** — Hardcoded SSN range table for the 20 most
  critical syscalls across Windows 10 1903–22H2 and Windows 11 21H2–24H2.
  Resolved SSNs are validated against the expected range and logged if
  out of bounds.
- **Cache invalidation on NtDll unhook** — `ntdll_unhook.rs` calls the new
  `invalidate_syscall_cache()` API which clears the SSN cache and marks the
  clean ntdll mapping as stale, forcing re-resolution from the unhooked ntdll.
- **Periodic validation** — Agent main loop calls `validate_cache()` every N
  iterations (configurable via `syscall.validate_interval`, default 100).
  Failed validation triggers automatic cache invalidation and re-mapping.
- **New public API**:
  - `nt_syscall::invalidate_syscall_cache()` — full cache + mapping reset
  - `nt_syscall::validate_cache() -> Result<usize>` — cross-ref + probe
  - `nt_syscall::get_build_number() -> u32` — cached KUSER_SHARED_DATA read
  - `agent::syscalls::invalidate_syscall_cache()` — same for agent crate
  - `agent::syscalls::validate_cache() -> Result<usize>` — same for agent
  - `agent::syscalls::get_build_number() -> u32` — same for agent
- **New config struct** — `SyscallConfig` in `common/src/config.rs` with
  `validate_interval: u32` (default 100).
- **Upgraded modules**: `nt_syscall/src/lib.rs`, `agent/src/syscalls.rs`,
  `agent/src/ntdll_unhook.rs`, `agent/src/lib.rs`, `common/src/config.rs`.
- **No new feature flag** — upgrade to the existing `direct-syscalls` feature.

#### Kernel Callback Overwrite — BYOVD (`kernel-callback` feature)
- **Surgical EDR callback overwrite via BYOVD** — Overwrites EDR kernel
  callback function pointers to point to a `ret` instruction instead of
  NULLing them.  Defeats EDR self-integrity checks (CrowdStrike, Microsoft
  Defender for Endpoint) that verify their callbacks are still registered by
  checking if the pointer is non-NULL.  A `ret` pointer passes these checks
  (non-NULL, valid executable memory) but causes the callback to immediately
  return without executing any monitoring logic.
- **Vulnerable driver database** — 8 known vulnerable signed drivers (Dell
  DBUtil_2_3.sys, MSI Afterburner rtcore64.sys, Gigabyte gdrv.sys, ASUS
  AsIO/AsIO2, Baidu BdKit, ENE Technology ene.sys, Process Explorer
  procexp152.sys).  Top 3 are embedded (XOR-obfuscated, HKDF-derived key)
  in the agent binary.
- **Driver deployment pipeline** — Scans for pre-loaded drivers via
  `NtQuerySystemInformation(SystemModuleInformation)`, falls back to
  decrypting and dropping an embedded driver, loading via `NtLoadDriver`
  with registry service entry, and cleaning the file from disk.
- **Callback discovery** — Reads kernel memory to locate and enumerate EDR
  callbacks in `PspCreateProcessNotifyRoutine`,
  `PspCreateThreadNotifyRoutine`, `PspLoadImageNotifyRoutine`,
  `KeBugCheckCallbackListHead`, and `CallbackListHead`.  Resolves kernel
  symbols by walking ntoskrnl.exe PE export directory via binary search.
- **Ret pointer finding** — Two methods: (1) resolves
  `IoInvalidDeviceRequest` export (it's just `ret`), (2) scans ntoskrnl
  `.text` section for `0xC3` bytes (prefers 16-byte aligned addresses).
- **Anti-forensic cleanup** — Unlinks the vulnerable driver from
  `PsLoadedModuleList` after overwrite (LIST_ENTRY Flink/Blink manipulation).
- **Safety mechanisms** — KeBugCheck callbacks are **never** overwritten
  (BSOD risk).  Original pointers are saved for `KernelCallbackRestore`.
  Failed physical memory writes are skipped.
- **Three new runtime commands**:
  - `KernelCallbackScan` — discover and report all registered EDR callbacks.
  - `KernelCallbackNuke { drivers: Vec<String> }` — deploy driver, overwrite
    callbacks with ret pointer, save backups, unlink driver.
  - `KernelCallbackRestore` — restore original callback pointers from backup.
- **Feature flag** — `kernel-callback = ["direct-syscalls"]` in
  `agent/Cargo.toml` (implies `direct-syscalls`).
- **New modules**: `agent/src/kernel_callback.rs`,
  `agent/src/kernel_callback/driver_db.rs`,
  `agent/src/kernel_callback/deploy.rs`,
  `agent/src/kernel_callback/discover.rs`,
  `agent/src/kernel_callback/overwrite.rs`.
- **All NT API calls** through `nt_syscall::syscall!`, all strings through
  `string_crypt`.  Driver decryption keys derived from agent's HKDF session
  key with info string `"orchestra-driver-key"`.

#### Automated EDR Bypass Transformation Engine (`evasion-transform` feature)
- **Runtime `.text` signature scanning** — Scans the agent's own compiled
  `.text` section for 9 byte signatures known to be detected by EDR products
  (YARA rules, entropy heuristics, known gadget chains).  Signatures include
  direct syscall stub prologues, `syscall; ret` trampolines, indirect syscall
  via `jmp r10`, common patch patterns, and VirtualAlloc stubs.
- **5 semantic-preserving transformations**:
  1. **Instruction substitution** — `xor rax,rax` → `sub rax,rax`; indirect
     `call [rip+disp32]` → `lea r15,[rip+disp32]; call r15`.
  2. **Register reassignment** — `mov r10,rcx` → `mov r11,rcx` outside
     syscall exclusion zones, breaking EDR's syscall stub pattern matching.
  3. **NOP sled insertion** — Inserts random semantic-equivalent NOPs
     (e.g., `xchg rax,rax`, `lea rsp,[rsp+0]`, `mov rdi,rdi`) at safe
     locations after RET instructions.
  4. **Constant splitting** — `mov rax,imm64` → `mov rcx,imm64` + register
     swap, changing the register encoding pattern without altering the value.
  5. **Jump obfuscation** — Short `EB XX` jumps → long `E9 XXXXXXXX` jumps
     with NOP padding, changing the byte signature of direct jumps.
- **Syscall stub exclusion zone** — 32-byte buffer around every `syscall`
  instruction where no transformations are applied, preventing corruption of
  the agent's syscall trampolines.
- **Shannon entropy filtering** — Regions above the configurable entropy
  threshold (default 6.8) are skipped because they already appear random.
- **SHA-256 hash verification** — Before/after hash comparison of `.text`
  section confirms transformations were applied correctly.
- **Page protection management** — `NtProtectVirtualMemory` (direct syscall)
  makes `.text` writable for transformation and restores original protection
  after.  Instruction cache flushed via `NtFlushInstructionCache`.
- **Integration with `self_reencode`** — Supplements the existing morphing
  pipeline (handles pattern avoidance before/after morphing).  Does not
  modify `self_reencode` logic.  Uses `self_reencode::find_text_section()`
  for safe `.text` section discovery.
- **Configurable** — `EvasionTransformConfig` with `enabled` (default true),
  `scan_interval_secs` (default 300), `max_transforms_per_cycle` (default 12),
  `entropy_threshold` (default 6.8).  Configured in TOML under
  `[evasion.auto_transform]`.
- **Two runtime commands**:
  - `EvasionTransformScan` — scan `.text` for EDR signatures, return JSON
    array of `SignatureHit` objects.
  - `EvasionTransformRun` — run one scan-and-transform cycle, return JSON
    summary with hashes, hits, transforms, and timing.
- **Public API**: `run_edr_bypass_transform(max_transforms, entropy_threshold)`
  and `scan_for_signatures() -> Vec<SignatureHit>`, callable from agent main
  loop for periodic automated scanning.
- **Feature flag** — `evasion-transform = ["self-reencode"]` in
  `agent/Cargo.toml` (implies `self-reencode`).
- **New module: `agent/src/edr_bypass_transform.rs`** — ~650 lines implementing
  the full scan engine, 5 transformation passes, exclusion zones, page
  protection, SHA-256 verification, and public API.

#### NTFS Transaction-Based Process Hollowing with ETW Blinding (`transacted-hollowing` feature)
- **Fileless process hollowing via NTFS transactions** — Creates an NTFS
  transaction with `NtCreateTransaction`, writes the payload into a
  transaction-backed section via `NtCreateSection(SEC_COMMIT)` +
  `NtMapViewOfSection`, maps it into the suspended target process, then
  rolls back the transaction with `NtRollbackTransaction`. The file on disk
  never existed but the section mapping remains valid in the target process.
- **Kernel32 ordinal fallback** — When `NtCreateTransaction` SSN is not in
  the bootstrap syscall table, resolves `RtlCreateTransaction` from kernel32
  by ordinal, falling back to ntdll export. Same fallback chain for
  `NtRollbackTransaction`.
- **Remote ETW blinding** — Resolves `EtwEventWrite` in the target process's
  ntdll by walking the remote PE export table via `NtReadVirtualMemory`, then
  patches the first byte with `0xC3` via `NtWriteVirtualMemory`. This blinds
  EDR's ETW-based process creation monitoring without touching the local
  process.
- **Spoofed ETW provider GUIDs** — Emits 5 fake ETW event artifacts with
  Windows Defender (`{11cd958a-c507-4ef3-b3f2-5fd9dfbd2c78}`), AMSI
  (`{79f7af20-2b5e-4cb1-8b6e-396376e8f8e8}`), and Sysmon
  (`{5770385f-c22a-43e0-bf4c-06f5698ffbd9}`) provider GUIDs to flood EDR
  telemetry with benign-looking events.
- **ETW restore policy** — Original `EtwEventWrite` byte is restored after
  `NtResumeThread`, minimizing the window of blinded ETW.
- **Auto-selection ranking** — `TransactedHollowing` inserted above standard
  `ProcessHollow` in all 4 auto-selection branches (svchost, explorer,
  service, default). Configurable `prefer_over_hollowing` flag.
- **All syscalls through existing indirect syscall infrastructure** —
  `get_syscall_id` + `do_syscall` for NtCreateSection, NtMapViewOfSection,
  NtUnmapViewOfSection, NtWriteVirtualMemory, NtReadVirtualMemory,
  NtResumeThread, NtQueryInformationProcess.
- **Configurable** — `TransactedHollowingConfig` with `enabled` (default true),
  `prefer_over_hollowing` (default true), `etw_blinding` (default true),
  `rollback_timeout_ms` (default 5000). Configured in TOML under
  `[injection.transacted_hollowing]`.
- **Runtime command** — `TransactedHollow { target_process, payload,
  etw_blinding }` returns JSON with pid, base_addr, technique, payload_size.
- **Feature flag** — `transacted-hollowing = ["direct-syscalls"]` in
  `agent/Cargo.toml` (implies `direct-syscalls`).
- **New module: `agent/src/injection_transacted.rs`** — ~750 lines implementing
  transaction creation/fallback, section management, remote ETW patching,
  fake event emission, suspended process creation, thread redirection, and
  the full injection pipeline.
- **Modified files**: `common/src/config.rs` (TransactedHollowingConfig),
  `common/src/lib.rs` (Command::TransactedHollow), `agent/Cargo.toml`
  (feature flag), `agent/src/injection_engine.rs` (technique variant,
  dispatch, auto-selection ranking), `agent/src/lib.rs` (module declaration),
  `agent/src/handlers.rs` (command handler).

#### Delayed Module-Stomp Injection (`delayed-stomp` feature)
- **EDR timing-heuristic bypass** — Loads a sacrificial DLL into the target
  process via `LoadLibraryA`, waits for a configurable randomized delay
  (default 8–15 seconds) to let EDR initial-scan heuristics pass, then
  overwrites the DLL's `.text` section with the payload using
  `NtWriteVirtualMemory` (indirect syscall).  Defeats timing-based EDR
  heuristics that flag modules whose code changes shortly after loading.
- **Two-phase injection** — Phase 1 (load DLL) returns immediately; Phase 2
  (stomp + execute) fires after the delay in a background thread so the
  agent's main task loop is not blocked.
- **Sacrificial DLL selection** — Enumerates target modules via PEB walk,
  selects a DLL NOT already loaded from ~30 curated candidates (version.dll,
  dwmapi.dll, msctf.dll, etc.).  Built-in exclusion list prevents loading
  critical DLLs (ntdll, kernel32, amsi, etc.).
- **PE relocation fixups** — If the payload is a PE (vs raw shellcode),
  base relocations are fixed up relative to the loaded DLL base using the
  relocation directory from the original payload buffer.
- **Non-blocking** — Phase 2 runs in a dedicated background thread
  (`delayed-stomp-phase2`); the operator receives a Phase 1 JSON
  acknowledgement immediately and can query injection status for Phase 2
  completion.
- **Auto-selection ranking** — `DelayedModuleStomp` inserted above standard
  `ModuleStomp` in all four `auto_select_techniques()` branches when the
  feature is enabled.  Configurable `prefer_over_stomp` (default true).
- **Configurable** — `DelayedStompConfig` with `enabled` (default true),
  `min_delay_secs` (default 8), `max_delay_secs` (default 15),
  `sacrificial_dlls` (30 candidates), `prefer_over_stomp` (default true).
  New `[injection.delayed_stomp]` section in agent TOML config.
- **Runtime command** — `DelayedStomp { target_pid, payload, delay_secs }`
  returns JSON with status, target_pid, dll_name, dll_base, delay_secs.
- **Feature flag** — `delayed-stomp = ["direct-syscalls"]` in
  `agent/Cargo.toml` (implies `direct-syscalls`).
- **New module: `agent/src/injection_delayed_stomp.rs`** — ~600 lines
  implementing sacrificial DLL selection, remote module enumeration via PEB
  walk, DLL loading via `LoadLibraryA` remote thread, `.text` section
  parsing, payload stomping, relocation fixups, entry point calculation,
  payload execution, async Phase 2 dispatch, and unit tests.
- **Modified files**: `common/src/config.rs` (DelayedStompConfig),
  `common/src/lib.rs` (Command::DelayedStomp), `agent/Cargo.toml`
  (feature flag), `agent/src/injection_engine.rs` (technique variant,
  dispatch, auto-selection ranking), `agent/src/lib.rs` (module declaration),
  `agent/src/handlers.rs` (command handler).

#### AMSI Write-Raid Bypass (`write-raid-amsi` feature)
- **Data-only race condition** — Spawns a background thread that continuously
  overwrites the `AmsiInitFailed` flag in `amsi.dll`'s `.data` section via
  `NtWriteVirtualMemory` (indirect syscall), causing all subsequent
  `AmsiScanBuffer` calls to return `AMSI_RESULT_CLEAN`.
- **Zero code/permission/breakpoint modifications** — No `.text` patches, no
  `NtProtectVirtualMemory` calls, no DR0–DR7 changes. Blends with normal
  AMSI internal state updates. Most stealthy AMSI bypass available.
- **Runtime-switchable** — New `AmsiBypassMode` command allows switching
  between Write-Raid, HWBP, and Memory-Patch strategies without rebuilding.
  `Auto` mode selects the best available (write-raid > hwbp > memory-patch).
- **Sleep-obfuscation integration** — Race thread automatically pauses during
  `secure_sleep` memory encryption cycles to prevent ciphertext corruption.
- **Feature flag** — `write-raid-amsi = []` in `agent/Cargo.toml`.
- **Shared types** — `AmsiBypassMode` enum added to `common/src/lib.rs`.


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

#### Cronus Sleep Obfuscation (waitable-timer variant)
- **New `SleepVariant` enum** in `sleep_obfuscation.rs` — `Cronus` (default) uses
  `NtCreateTimer` + `NtSetTimer` + `NtWaitForSingleObject` instead of
  `NtDelayExecution`.  Less commonly hooked by EDR.
- **Auto-select with fallback** — When Cronus is selected, verifies that
  `NtSetTimer` resolves.  Falls back to Ekko (NtDelayExecution) with a log
  warning if resolution fails.
- **Position-independent RC4 stub** — Runtime-generated x86-64 code page with
  pre-initialized S-box and key at fixed offsets, RIP-relative addressing.
  Used for remote process sleep encryption.
- **New `SleepMethod::Cronus` variant** in `common/src/config.rs` — Selectable
  via `method = "cronus"` in TOML config.
- **Runtime switching** — New `Command::SetSleepVariant { variant }` enables
  operator-initiated variant change without rebuild.
- **Remote process registry integration** — Timer handle and RC4 stub tracked
  in `RemoteProcess` struct, properly cleaned up on unregister.
- **New syscall wrappers** — `syscall_NtCreateTimer`, `syscall_NtSetTimer`,
  `syscall_NtWaitForSingleObject`, `syscall_NtClose` in `syscalls.rs`.

#### Unwind-Aware Call Stack Spoofing (upgrade to `stack-spoof` feature)
- **New module: `agent/src/stack_db.rs`** — Address database builder, chain template
  generator, and unwind metadata validation functions.
- **Multi-frame plausible call graph chains** — Builds N-frame chains (e.g.
  `kernelbase!CreateProcessW` → `kernel32!CreateProcessA` → `ntdll!NtCreateUserProcess`)
  from 10 pre-built templates. Each `do_syscall` randomly selects a template,
  preventing EDR fingerprinting of consistent call stacks.
- **Unwind metadata consistency** — Every `ret` gadget address is verified against
  `RUNTIME_FUNCTION` entries via `RtlLookupFunctionEntry`. Only addresses with
  valid unwind data are used, ensuring EDR stack walkers can traverse synthetic
  frames without errors.
- **Shadow-stack/CET compatibility** — Spoofed frames never cross the `syscall; ret`
  boundary; they sit between the NtContinue context restore and the target gadget.
- **Post-sleep revalidation** — After sleep obfuscation decrypts memory, cached chain
  addresses are spot-checked via `VirtualQuery` and the database is rebuilt if any
  are stale (handles EDR module rebasing during sleep).
- **Feature flag stays as `stack-spoof`** — This is an upgrade, not a new feature.
  No changes to `Cargo.toml` required.
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
- **Comprehensive IAT elimination** — Replaced all Win32 API imports with NT
  syscall equivalents via the `syscall!` macro across 15+ files, removing
  detectable IAT entries for `VirtualProtect`, `OpenProcess`,
  `WriteProcessMemory`, `VirtualAllocEx`, `VirtualQuery`, `CloseHandle`,
  `WaitForSingleObject`, `GetExitCodeProcess`, `SetHandleInformation`,
  `GetCurrentProcessId`, and `ImpersonateNamedPipeClient`.  Affected modules:
  `process_manager`, `process_spoof`, `token_manipulation`,
  `token_impersonation`, `stub`, `stack_db`, `memory_hygiene`, `p2p`,
  `lsass_harvest`, `sleep_obfuscation`, and `kernel_callback/discover`.
- `agent/syscalls` — Fixed `syscall!` macro to return `Result<i32>` instead of
  raw `i32`, enabling proper error propagation.  All callers updated to handle
  the `Result` type.
- `agent/ntdll_unhook` — Fixed `bytes_overwritten` to report actual bytes
  written instead of hardcoded `0`.  Fixed `NtCreateFile` parameter ordering
  (`CreateDisposition`/`CreateOptions` were swapped).  Migrated from
  `nt_syscall::` to `crate::syscalls::`.
- `agent/token_impersonation` — Rewrote `impersonate_pipe_via_set_thread_token`
  to spawn a helper thread via `NtCreateThreadEx` instead of calling
  `ImpersonateNamedPipeClient` on the main thread.  Added `CachedToken::Drop`
  impl that closes handles via `NtClose`.  Changed `ImpersonationThreadCtx`
  success flag from `bool` to `AtomicBool` with `Release`/`Acquire` ordering.
  Replaced `CreateThread`/`WaitForSingleObject` with
  `NtCreateThreadEx`/`NtWaitForSingleObject`.
- `agent/obfuscated_sleep` — Fixed fiber resource leak via `FiberGuard` RAII
  pattern with `thread_local!`.  Changed post-encryption page protection from
  restoring original protection to `PAGE_NOACCESS`, preventing memory scanners
  from reading encrypted sections.
- `agent/syscall_emulation` — Replaced wildcard imports with specific type-only
  imports.  Added ~200 lines of dynamic `kernel32` resolution functions
  (`resolve_kernel32_fn`, `dynamic_virtual_alloc_ex`,
  `dynamic_write_process_memory`, etc.) to eliminate all IAT entries from the
  emulation layer.
- `agent/process_manager` — Replaced `OpenProcess`, `VirtualAllocEx`,
  `WriteProcessMemory`, `VirtualProtectEx` with `NtOpenProcess`,
  `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`,
  `NtProtectVirtualMemory`.  Handle cleanup via `syscall!("NtClose", ...)`.
- `agent/process_spoof` — Replaced `OpenProcess`, `WaitForSingleObject`,
  `GetExitCodeProcess`, `SetHandleInformation` with NT syscall equivalents
  (`NtOpenProcess`, `NtWaitForSingleObject`, `NtQueryInformationProcess`,
  `NtSetInformationObject`).  Added inline `ObjHandleFlagInfo` and
  `ProcessBasicInformation` structs.
- `agent/token_manipulation` — `CloseHandle` → `syscall!("NtClose", ...)`.
  `GetCurrentProcessId()` → `NtQueryInformationProcess(ProcessBasicInformation)`
  with inline PBI struct.  Migrated from `nt_syscall::` to `crate::syscalls::`.
- `agent/stack_db` — Replaced `VirtualQuery` with `NtQueryVirtualMemory` via
  `syscall!`.  Removed fallback that returned addresses failing unwind
  validation.
- `agent/stub` — Replaced all `VirtualProtect` calls with
  `NtProtectVirtualMemory` via `syscall!`.
- `agent/kernel_callback/discover` — Migrated from `nt_syscall::syscall!` to
  `syscall!`.  Added `translate_va_to_pa` for drivers requiring physical
  addresses (PTE walk via `MmPteBase`).  Added proper
  `walk_bugcheck_callback_list` for `KeBugCheckCallbackListHead` (linked list,
  not flat array).  Fixed `DBUtil_2_3.sys` driver record:
  `needs_physical_addr` corrected to `false` (driver does VA→PA internally).
- `agent/lsa_whisperer` — `LsaCallAuthenticationPackage` return buffer now
  correctly freed via `LsaFreeReturnBuffer` instead of `LocalFree`, preventing
  handle leaks on repeated calls.
- `agent/injection_doppelganging` — **New module**: Process Doppelganging
  injection technique using NTFS transactions
  (`NtCreateTransaction` → `NtCreateFile` → `NtWriteFile` →
  `NtCreateSection` → `NtRollbackTransaction` → `NtMapViewOfSection` →
  `NtCreateThreadEx`).  Zero IAT entries for injection operations.  Gated by
  `transacted-hollowing` feature flag.
- `agent/kernel_callback/driver_db` — Replaced placeholder SHA-256 hashes with
  verified hashes for `rtcore64.sys`, `AsIO.sys`, `AsIO2.sys`, `ene.sys`, and
  `procexp152.sys`.  Updated `BdKit.sys` comments noting hash is still
  unverified.

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
