# Architecture

Deep-dive into Orchestra's internal design: agent module initialization, syscall infrastructure, memory guard lifecycle, evasion subsystem, C2 state machine, injection engine, sleep obfuscation pipeline, and server internals.

---

## Agent Internals

### Module Initialization Order

When the agent binary starts, modules initialize in a specific sequence to ensure dependencies are satisfied before use:

```
1. config.rs          — Load or embed configuration
2. env_check.rs       — Sandbox/debugger/VM detection
3. env_check_sandbox.rs — Extended sandbox scoring
4. nt_syscall         — Map clean ntdll, resolve SSNs (Windows)
5. evanesco           — Continuous page tracker init (BEFORE evasion)
5b. syscall_emulation — Emulation layer init (BEFORE any injection/syscalls)
5c. cet_bypass        — CET/shadow-stack detection and mitigation (BEFORE any spoofed calls)
5d. token_impersonation — Token-only impersonation init (pipe token cache, auto-revert config)
5e. forensic_cleanup  — Prefetch evidence removal init (cleanup method, auto-clean config)
6. evasion.rs         — AMSI bypass, ETW patching
7. amsi_defense.rs    — Write-Raid / HWBP / memory-patch AMSI bypass
8. etw_patch.rs       — ETW function hooking
9. c2_*.rs            — Transport initialization
10. sleep_obfuscation  — Memory region tracking
11. memory_guard.rs   — Heap encryption registration
12. injection_engine  — Pre-injection recon cache
13. handlers.rs       — Command dispatch table
```

Each step runs to completion before the next begins. If any security check fails (sandbox detected, debugger present, domain mismatch), the agent exits silently.

### Module Dependency Graph

```
                    ┌──────────┐
                    │  config  │
                    └────┬─────┘
                         │
                    ┌────▼──────┐
                    │ env_check │──────────────────────────────┐
                    └────┬──────┘                              │
                         │ (exit if sandbox/debugger)          │
                    ┌────▼──────┐                              │
                    │ nt_syscall│ (Windows only)               │
                    └────┬──────┘                              │
              ┌──────────┼──────────┐                          │
              │          │          │                          │
     ┌────────▼───┐ ┌───▼────┐ ┌──▼──────────┐               │
     │  evanesco   │ │syscall │ │ cet_bypass  │               │
     │             │ │emul.   │ │             │               │
     └────────┬───┘ └───┬────┘ └──┬──────────┘               │
              │         │         │                            │
              └────┬────┘─────────┘                            │
                   │                                          │
         ┌─────────▼──────────┐                               │
         │  evasion subsystem │                               │
         │  (AMSI + ETW)      │                               │
         └─────────┬──────────┘                               │
                   │                                          │
         ┌─────────▼──────────┐                               │
         │ token_impersonation│                               │
         └─────────┬──────────┘                               │
                   │                                          │
         ┌─────────▼──────────┐                               │
         │ forensic_cleanup   │                               │
         └─────────┬──────────┘                               │
                   │                                          │
         ┌─────────▼──────────┐                               │
         │  C2 transport      │◄──────────────────────────────┘
         │  (HTTP/SMB/DNS)    │                    (on fail → exit)
         └─────────┬──────────┘
                   │
       ┌───────────┼───────────┐
       │           │           │
  ┌────▼──┐  ┌────▼────┐  ┌──▼──────────┐
  │sleep  │  │memory   │  │injection    │
  │obfusc.│  │guard    │  │engine       │
  └────┬──┘  └────┬────┘  └──┬──────────┘
       │          │          │
       └──────────┼──────────┘
                  │
          ┌───────▼───────┐
          │   handlers    │
          │  (dispatch)   │
          └───────────────┘
                  │
    ┌─────────────┼──────────────┐
    │             │              │
┌───▼───┐  ┌─────▼─────┐  ┌────▼──────┐
│browser │  │LSASS/LSA  │  │ post-ex   │
│data    │  │harvest    │  │ modules   │
└────────┘  └───────────┘  └───────────┘
```

### Evasion Pipeline Flow

The evasion pipeline applies defenses in order, with each stage building on the previous:

```
┌───────────┐    ┌───────────┐    ┌──────────────┐    ┌───────────┐
│ ETW Patch │───▶│ AMSI      │───▶│ NTDLL        │───▶│ Syscall   │
│ (disable  │    │ Bypass    │    │ Unhook       │    │ Strategy  │
│  provider │    │ (write-   │    │ (KnownDlls   │    │ Selection │
│  logging) │    │  raid/    │    │  re-fetch)   │    │ (emulate/ │
│           │    │  HWBP)    │    │              │    │  direct)  │
└───────────┘    └───────────┘    └──────────────┘    └─────┬─────┘
                                                              │
                    ┌─────────────────────────────────────────┘
                    │
         ┌──────────▼──────────┐
         │ CET Bypass          │
         │ (policy / compat /  │
         │  VEH fix)           │
         └──────────┬──────────┘
                    │
         ┌──────────▼──────────┐
         │ Stack Spoofing      │
         │ (NtContinue or      │
         │  unwind-aware)      │
         └──────────┬──────────┘
                    │
         ┌──────────▼──────────┐
         │ EDR Transform       │
         │ (if enabled: scan   │
         │  + transform .text) │
         └──────────┬──────────┘
                    │
         ┌──────────▼──────────┐
         │ Self-Reencode       │
         │ (per-build unique)  │
         └─────────────────────┘
```

### Agent State Machine

```
                    ┌──────────────┐
                    │   Start      │
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │ Env Check    │──── Fail ──► Silent Exit
                    │ (sandbox/    │
                    │  debugger)   │
                    └──────┬───────┘
                           │ Pass
                    ┌──────▼───────┐
                    │ Evasion Init │
                    │ AMSI + ETW   │
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │ C2 Connect   │──── Fail ──► Backoff + Retry
                    │ (malleable)  │
                    └──────┬───────┘
                           │ Connected
                    ┌──────▼───────┐
               ┌──►│  Main Loop   │
               │   └──────┬───────┘
               │          │
               │   ┌──────▼───────┐
               │   │ Sleep Cycle  │
               │   │ (encrypt     │
               │   │  memory)     │
               │   └──────┬───────┘
               │          │ Wake
               │   ┌──────▼───────┐
               │   │ Check Tasks  │──── Task ──► Execute ──┐
               │   │ (beacon)     │                         │
               │   └──────┬───────┘                         │
               │          │ No task                         │
               └──────────┘◄────────────────────────────────┘
```

### Command Dispatch (`handlers.rs`)

The `handle_command()` function receives a `Command` variant and dispatches to the appropriate handler. It takes 6 parameters:

```rust
pub fn handle_command(
    cmd: Command,
    config: &mut Config,
    session: &CryptoSession,
    agent_id: &str,
    extra_args: Option<&str>,
    plugin_manager: &mut PluginManager,
) -> Result<String, String>
```

Each command handler is a separate function in `handlers.rs` or a dedicated module. The 120+ commands include:

| Category | Commands |
|----------|----------|
| **Core** | `Ping`, `GetSystemInfo`, `Shutdown`, `ReloadConfig`, `RunApprovedScript` |
| **Filesystem** | `ListDirectory`, `ReadFile`, `WriteFile` |
| **Modules** | `DeployModule`, `ExecutePlugin`, `ListPlugins`, `UnloadPlugin`, `GetPluginInfo`, `DownloadModule`, `ExecutePluginBinary` |
| **Process** | `ListProcesses`, `MigrateAgent`, `JobStatus` |
| **Discovery** | `DiscoverNetwork`, `NetworkDiscovery` (ARP scan, ping sweep, TCP port scan, reverse DNS, AD SRV) |
| **Remote Assist** | `CaptureScreen`, `SimulateKey`, `SimulateMouse` |
| **HCI Research** | `StartHciLogging`, `StopHciLogging`, `GetHciLogBuffer` |
| **Persistence** | `EnablePersistence`, `DisablePersistence` |
| **Injection — Unified** | `UnifiedInject { target_process, payload, technique, evade }` — unified 15-variant engine with string-based selection for the parser-exposed techniques (`"auto"`, `"ProcessHollow"`, `"ThreadPool"`, `"ThreadPool:Work"`, etc.) |
| **Injection — Legacy** | `TransactedHollow { target_process, payload, etw_blinding }`, `DelayedStomp { target_pid, payload, delay_secs }`, `InjectSideLoad { pid, payload, export_config }`, `ProcessDoppelganging` (NTFS transaction-backed process hollowing — `transacted-hollowing` feature) |
| **Code Morphing** | `SetReencodeSeed`, `MorphNow` |
| **Evasion** | `SyscallEmulationToggle`, `CetStatus`, `UnhookNtdll` (KnownDlls re-fetch + disk fallback), `AmsiBypassMode { mode }` (Hwbp / MemoryPatch / WriteRaid / Auto), `DenyDebuggerAttach` 🆕 — permanently deny debugger attachment via `NtSetInformationProcess(ProcessDebugFlags)` |
| **EDR Bypass Transform** | `EvasionTransformScan`, `EvasionTransformRun`, `EdrBypassStatus` |
| **Token Manipulation** | `MakeToken`, `StealToken`, `Rev2Self`, `GetSystem` |
| **Token Impersonation** | `ImpersonatePipe`, `RevertToken`, `ListTokens` |
| **Forensic Cleanup** | `CleanPrefetch`, `DisablePrefetch`, `RestorePrefetch`, `Timestomp`, `TimestompDirectory`, `CleanUsn`, `SyncTimestamps` |
| **Lateral** | `PsExec`, `WmiExec`, `DcomExec`, `WinRmExec` |
| **P2P** | `LinkAgents`, `UnlinkAgent`, `ListTopology`, `LinkTo`, `Unlink`, `ListLinks` |
| **Mesh** | `MeshConnect`, `MeshDisconnect`, `MeshKillSwitch`, `MeshQuarantine`, `MeshClearQuarantine`, `MeshSetCompartment` |
| **.NET/BOF** | `ExecuteAssembly`, `ExecuteBOF` |
| **Interactive Shell** | `CreateShell`, `ShellInput`, `ShellClose`, `ShellList`, `ShellResize` |
| **Surveillance** | `Screenshot`, `KeyloggerStart`, `KeyloggerDump`, `KeyloggerStop`, `ClipboardMonitorStart`, `ClipboardMonitorDump`, `ClipboardMonitorStop`, `ClipboardGet` |
| **Browser Data** | `BrowserData { browser, data_type }` (Chrome/Edge/Firefox — credentials/cookies/all) |
| **Credential Access** | `HarvestLSASS` (incremental memory reading — no dump file), `HarvestLSA { method }` (Untrusted/SspInject/Auto), `LSAWhispererStatus`, `LSAWhispererStop` |
| **Kernel Callback** | `KernelCallbackScan`, `KernelCallbackNuke { drivers }`, `KernelCallbackRestore` |
| **Sleep** | `SetSleepVariant { variant }` ("cronus" / "ekko") |
| **Evanesco** | `EvanescoStatus`, `EvanescoSetThreshold { idle_ms }`, `PageTrackerStatus` 🆕, `PageTrackerStatusRedacted` 🆕 (live page-tracker statistics with optional credential redaction) |
| **Sandbox** | `SandboxCheck` — weighted indicator breakdown with total score and threshold |
| **COM Hijack** 🆕 | `ComHijackScanTargets`, `ComHijackManifest`, `ComHijackProxyDll`, `ComHijackActivateFile`, `ComHijackActivateMemory` — registry-free COM hijack through activation contexts (`com-hijack` feature) |
| **DPAPI Backup** 🆕 | `DpapiBackupKeyRetrieve`, `DpapiBackupKeyHarvest`, `DpapiBackupKeyDecrypt` — domain backup-key retrieval and blob decryption (`dpapi-backup` feature) |
| **Hardware Persistence** 🆕 | `HwDetectThunderbolt`, `HwCheckDmaVulnerability`, `HwPrepareDmaPayload`, `HwDmaReadPhysical`, `HwBootMode`, `HwInstallVbrPersistence`, `HwInstallUefiBootPersistence`, `HwDetectPersistence`, `HwRemovePersistence` — Thunderbolt/DMA-based hardware persistence (`hardware-persistence` feature) |
| **Kerberos Relay** 🆕 | `KerberosRelay`, `KerberosRelayListClsids` — Kerberos relay through COM cross-session activation (`kerberos-relay` feature) |
| **macOS Post-Exploitation** 🆕 | `MacTccCheck`, `MacTccBypass`, `MacSipStatus`, `MacSipBypassMount`, `MacXpcEnumerate`, `MacXpcExploit`, `MacKeychainDump` — TCC/SIP/XPC/Keychain operations on macOS (`macos-postexp` feature) |
| **Shadow Credentials** 🆕 | `ShadowCredentialsCheckAccess`, `ShadowCredentialsCertGen`, `ShadowCredentialsAttack` — AD Shadow Credentials via `msDS-KeyCredentialLink` and PKINIT (`shadow-credentials` feature) |
| **UEFI Persistence** 🆕 | `UefiMountEsp`, `UefiEnumerateBootEntries`, `UefiBuildStub`, `UefiCheckCapsuleSupport`, `UefiDetectPersistence`, `UefiWriteDriver`, `UefiWriteVariable`, `UefiReadVariable`, `UefiModifyBootEntry`, `UefiInstallRuntimeDriver`, `UefiRemovePersistence` — UEFI NVRAM/ESP persistence (`uefi-persistence` feature) |
| **WMI Persistence** 🆕 | `WmiScanSubscriptions`, `WmiInstallSubscription`, `WmiRemoveSubscription`, `WmiGenerateStager`, `WmiCloudUpload` — COM-based WMI permanent event subscriptions (`wmi-persistence` feature) |

---

## Syscall Infrastructure

### User-Mode NT Kernel Interface Emulation (`syscall-emulation` feature)

On top of the direct-syscall infrastructure, the agent can route configured NT
syscalls ENTIRELY through user-mode kernel32/advapi32 equivalents, bypassing
ntdll.dll syscall stubs completely.

```
┌─────────────────────────────┐
│   Caller (injection_engine, │
│   lsass_harvest, etc.)      │
└──────┬──────────────────────┘
       │ emulated_syscall!("NtWriteVirtualMemory", ...)
       │
┌──────▼──────────────────────┐
│   Emulation dispatch        │
│   (syscall_emulation.rs)    │
│                             │
│   ┌─ Is emulation ON? ────┐│
│   │  AND function in set? ││
│   │                       ││
│   │  YES → kernel32 path  ││
│   │  NO  → indirect path  ││
│   └───────────────────────┘│
└──────┬──────────┬───────────┘
       │          │
  ┌────▼─────┐   ┌▼──────────────┐
  │ kernel32 │   │ Indirect      │
  │ fallback │   │ syscall path  │
  │ (Write-  │   │ (nt_syscall)  │
  │ Process- │   │               │
  │ Memory)  │   │ SSN + gadget  │
  └──────────┘   └───────────────┘
```

**10 emulated syscalls**: `NtWriteVirtualMemory` → `WriteProcessMemory`,
`NtReadVirtualMemory` → `ReadProcessMemory`,
`NtAllocateVirtualMemory` → `VirtualAllocEx`,
`NtFreeVirtualMemory` → `VirtualFreeEx`,
`NtProtectVirtualMemory` → `VirtualProtectEx`,
`NtCreateThreadEx` → `CreateRemoteThread` (limited: no `CREATE_SUSPENDED`),
`NtOpenProcess` → `OpenProcess`,
`NtClose` → `CloseHandle`,
`NtQueryVirtualMemory` → `VirtualQueryEx` (class 0 only),
`NtDuplicateToken` → `DuplicateTokenEx`.

**Configuration**: `[syscall-emulation]` in agent TOML:
- `enabled = true` — Global toggle (can be toggled at runtime via C2)
- `prefer-kernel32 = true` — Try kernel32/advapi32 first
- `fallback-to-indirect = true` — Fall back to indirect syscall on failure
- `emulated-functions = [...]` — List of function names to emulate

**Call stack OPSEC**: When kernel32 equivalents are used, the call stack shows
`kernel32!WriteProcessMemory` instead of ntdll syscall stubs — this looks like
legitimate API usage to EDR products that hook ntdll.

### Direct Syscalls (`nt_syscall`)

On Windows, the agent avoids calling ntdll exports directly. Instead, it:

1. **Maps a clean copy of ntdll.dll** from disk (`\KnownDlls\ntdll.dll` or `\SystemRoot\System32\ntdll.dll`)
2. **Resolves syscall stubs** by walking the clean ntdll's export table
3. **Extracts the SSN** (System Service Number) from each stub's `mov eax, IMM32` instruction
4. **Finds a syscall gadget** (`syscall; ret` or `jmp r11`) in the clean ntdll
5. **Caches results** in a static `HashMap<String, (u32, usize, u32)>` — SSN, gadget address, and PE timestamp
6. **Validates cached SSNs** periodically via cross-reference and probe methods

```rust
pub struct SyscallTarget {
    pub ssn: u32,           // System Service Number
    pub gadget_addr: usize, // Address of syscall;ret gadget
}
```

### Dynamic SSN Validation

Cached SSNs are validated through two complementary methods:

**Cross-reference method**: The PE `TimeDateStamp` of the loaded ntdll is compared
with the timestamp captured when each cache entry was created. If they differ
(e.g., after a Windows Update replaced ntdll), the entire cache is invalidated.

**Probe method**: For 4 critical syscalls, a test call with a NULL handle is made:
- `STATUS_INVALID_HANDLE` → SSN is correct
- `STATUS_INVALID_SYSTEM_SERVICE` → SSN is stale (wrong number)

**Build-aware caching**: The Windows build number is cached from `KUSER_SHARED_DATA`
(`0x7FFE0000 + 0x0260`). Build number changes also trigger cache invalidation.

**Versioned SSN ranges**: A hardcoded table covers 20 critical syscalls across
Windows 10 1903–22H2 and Windows 11 21H2–24H2. Resolved SSNs are checked against
the expected range for the current build.

### SSDT Nuclear Fallback

When both clean-mapping and Halo's Gate fail (all adjacent stubs hooked), the
agent can resolve SSNs from the kernel's `KeServiceDescriptorTable`:

1. `NtQuerySystemInformation(SystemModuleInformation)` → kernel base address
2. Build-number-based SSN range table → midpoint guess for the target syscall
3. Probe to confirm the guessed SSN

This requires `SeDebugPrivilege` and is intentionally conservative.

### Halo's Gate Fallback

If a syscall stub has been hooked (e.g., replaced with `jmp <hook>` by an EDR), the agent falls back to Halo's Gate:

1. Examine neighboring syscall stubs (up/down by 32 bytes)
2. Find an unhooked stub and calculate the SSN offset
3. Use the unhooked stub's syscall gadget

This handles the case where EDR products inline-hook specific NT API functions.

### NTDLL Unhooking Pipeline (`ntdll_unhook.rs`)

When Halo's Gate fails — i.e., **all** adjacent syscall stubs are hooked — the agent performs a full `.text` section re-fetch of ntdll.dll:

```
┌─────────────────────┐
│ syscall!() called    │
└──────┬──────────────┘
       │
┌──────▼──────────────┐     ┌────────────────────┐
│ SSN Cache hit?      │──No►│ Resolve from clean  │
│ (+timestamp check)  │     │ ntdll mapping        │
└──────┬──────────────┘     └──────┬──────────────┘
       │ Yes                       │ Hooked?
       │                    ┌──────▼──────────────┐
       │                    │ Halo's Gate: scan    │
       │                    │ adjacent stubs       │
       │                    └──────┬──────────────┘
       │                           │ All hooked?
       │                    ┌──────▼──────────────┐
       │                    │ NTDLL Unhook:        │
       │                    │ Re-fetch .text from  │
       │                    │ \KnownDlls            │
       │                    └──────┬──────────────┘
       │                           │ Success?
       │                    ┌──────▼──────────────┐
       │                    │ invalidate_cache() + │
       │                    │ Re-resolve SSN       │
       │                    └──────┬──────────────┘
       └───────────────────────────┘
```

**Primary path** (`\KnownDlls\ntdll.dll`):
1. `NtOpenSection("\KnownDlls\ntdll.dll")` — open the kernel-maintained read-only section
2. `NtMapViewOfSection(PAGE_READONLY)` — map a clean copy
3. Parse PE headers to locate `.text` section in both copies
4. `NtProtectVirtualMemory(PAGE_READWRITE)` on the hooked `.text`
5. Chunked overwrite (4 KiB chunks with 50 µs delays between each)
6. `NtProtectVirtualMemory(restore original protection)`
7. `NtFlushInstructionCache` to invalidate CPU instruction cache
8. `NtUnmapViewOfSection` + `NtClose` cleanup

**Fallback path** (disk re-read):
If `\KnownDlls` is blocked by EDR, the agent reads `C:\Windows\System32\ntdll.dll` from disk via `NtCreateFile` + `NtReadFile`. Less stealthy (creates file I/O events), but works when KnownDlls is unavailable.

**Post-unhook operations**:
- **Cache invalidation**: All 23 critical syscall stubs are re-resolved from the now-clean ntdll via `get_syscall_id()`
- **SSN cache purge**: `invalidate_ssn_cache()` clears the `SYSCALL_CACHE` HashMap
- **Execution normalization**: `NtQueryPerformanceCounter` is called immediately after unhooking to normalize the execution flow and avoid detectable call-pattern anomalies

**Automatic trigger points**:
1. **Halo's Gate failure**: When `infer_ssn_halo_gate()` returns `None` (all adjacent stubs hooked), the registered callback `halo_gate_fallback()` is invoked
2. **Post-sleep wake**: Sleep obfuscation step 12 calls `maybe_unhook()` to detect and remove hooks EDR placed while the agent was dormant
3. **On-demand**: Operator sends `UnhookNtdll` command

**Hook detection**: `are_syscall_stubs_hooked()` inspects the first bytes of 23 critical syscall stubs for hook indicators:
- `E9` — `jmp rel32` (inline hook, 5-byte detour)
- `EB` — `jmp rel8` (short jump detour)
- `FF 25` — `jmp [rip+offset]` (absolute indirect jump)
- `0F 0B` — `ud2` (stub neutered)
- `C3` — `ret` (stub neutered)

**Anti-EDR mitigations**:
- Chunked writes (4 KiB) with 50 µs delays to avoid bulk-write signatures
- Post-unhook normalization call to `NtQueryPerformanceCounter`
- `\KnownDlls` preferred to avoid file I/O monitoring

### Indirect Syscall Dispatch

For maximum evasion, the Windows x86_64 agent uses indirect syscalls that can
dispatch through `NtContinue`:

1. Build a multi-frame fake call chain from the `stack_db` module
2. Push `NtContinue` context with the target syscall's SSN in RAX
3. `NtContinue` transfers execution to the syscall gadget
4. The kernel-mode call stack appears to originate from a plausible chain of Win32 API calls (e.g. `kernelbase!CreateProcessW` → `kernel32!CreateProcessA` → `ntdll!NtCreateUserProcess`)

#### Unwind-Aware Call Stack Spoofing (`stack_db`)

The `stack_db` module (gated behind `stack-spoof` + x86_64) builds and maintains a database of valid return addresses from loaded-module export tables. It counters Elastic Security's call-stack consistency checks by:

- **Address database**: Scans export tables of common DLLs (ntdll, kernel32, kernelbase, user32, msvcrt, ucrtbase) and collects function entry points per module
- **Ret gadget scanning**: For each exported function, scans the first 128 bytes for a `ret` (0xC3) instruction that has valid `RUNTIME_FUNCTION` unwind metadata (verified via `RtlLookupFunctionEntry`)
- **Chain templates**: 10 pre-built plausible call graph templates that terminate at NT syscalls (CreateProcessW, VirtualAlloc, WriteFile, ReadFile, CreateFile, OpenProcess, WaitForSingleObject, DeviceIoControl, OpenThread, MapViewOfFile paths)
- **Dynamic selection**: Each `do_syscall` invocation randomly selects a resolved chain from the cache, preventing EDR fingerprinting of consistent call stacks
- **Post-sleep revalidation**: After sleep obfuscation decrypts memory, cached chain addresses are spot-checked and rebuilt if any are stale (modules can be rebased by EDR during sleep)

**Multi-frame chain layout** (NtContinue path):
```
  RSP →  [chain_frame_0]      ← ret gadget in ntdll function (popped by gadget ret)
         [chain_frame_1]      ← ret gadget in kernel32 function
         [chain_frame_2]      ← ret gadget in kernelbase function
         [continuation]       ← real return to do_syscall
         [shadow home 1..3]   ← zeroed (not read by kernel for syscalls)
         [arg 5, arg 6, ...]  ← stack-passed arguments
```

**Shadow-stack/CET compatibility**: Spoofed frames are placed between the NtContinue return and the target syscall gadget — they never cross the `syscall; ret` boundary, so CET shadow-stack verification is not affected.

**Fallback**: When no multi-frame chain resolves, falls back to a single-frame `NtQuerySystemTime` spoof (legacy behavior). When NtContinue's SSN is unavailable, uses a jmp-based single-frame path.

On Windows ARM64, syscall dispatch follows the ARM64 register ABI (`x0`-`x7`
arguments, `x8` SSN) and uses architecture-native call/branch gadgets instead
of x64 `RIP`/`RSP` frame construction.

### SSN Resolution Functions

The agent resolves these NT functions at runtime:

| Function | Purpose |
|----------|---------|
| `NtAllocateVirtualMemory` | Memory allocation (RW/RX) |
| `NtProtectVirtualMemory` | Memory protection changes |
| `NtWriteVirtualMemory` | Cross-process memory writes |
| `NtReadVirtualMemory` | Cross-process memory reads |
| `NtCreateThreadEx` | Remote thread creation |
| `NtOpenProcess` | Process handle acquisition |
| `NtClose` | Handle closure |
| `NtDelayExecution` | Sleep (used by Ekko sleep variant) |
| `NtContinue` | Thread context restoration (unwind-aware multi-frame stack spoofing) |
| `NtFreeVirtualMemory` | Memory deallocation |
| `NtQueryVirtualMemory` | Memory region enumeration |
| `NtCreateTimer` | Waitable timer creation (Cronus sleep variant) |
| `NtSetTimer` | Timer configuration (Cronus sleep variant) |
| `NtWaitForSingleObject` | Timer wait (Cronus sleep variant) |

### CET / Shadow Stack Bypass (`cet-bypass` feature)

Windows 11 24H2 (build ≥ 26100) enables **Intel CET hardware-enforced shadow stacks** by default. CET maintains a separate CPU-managed stack that records return addresses — if a `ret` instruction's target doesn't match the shadow stack entry, a `#CP` (Control Protection) exception fires. This defeats ROP, stack pivoting, and return-address spoofing techniques.

The `cet_bypass` module (gated behind `#[cfg(all(windows, feature = "cet-bypass"))]`) provides three complementary bypass strategies:

```
┌─────────────────────────────────────────────────────────┐
│              clean_call! macro invocation                │
└────────────────────────┬────────────────────────────────┘
                         │
                  ┌──────▼──────────┐
                  │ prepare_spoofing│
                  │ (CET check)     │
                  └──────┬──────────┘
                         │
           ┌─────────────┼─────────────────┐
           │             │                 │
    ┌──────▼──────┐ ┌────▼─────┐  ┌───────▼───────┐
    │ Proceed /   │ │UseCall-  │  │ Abort         │
    │ Disabled    │ │Chain     │  │ (cannot       │
    │             │ │          │  │  bypass)      │
    │ spoof_call  │ │ kernel32 │  └───────────────┘
    │ (existing)  │ │ direct   │
    └─────────────┘ └──────────┘
```

**Strategy 1 — Policy disable** (preferred):
- Self-process: `SetProcessMitigationPolicy(ProcessControlFlowGuardPolicy, ...)`
- Remote process: `NtSetInformationProcess` with info class 52 (ProcessMitigationPolicy)
- Queries `GetProcessMitigationPolicy` to verify CFG/CET state first

**Strategy 2 — CET-compatible call chains**:
- Routes NT API calls through kernel32 equivalents (e.g., `NtWriteVirtualMemory` → `kernel32!WriteProcessMemory`)
- Each `call` instruction pushes a legitimate shadow-stack entry
- 8 NT API names mapped to kernel32 equivalents in a `Lazy<HashMap>` registry

**Strategy 3 — VEH shadow-stack fix** (requires `kernel-callback` feature):
- Installs a Vectored Exception Handler for `#CP` exceptions
- On exception, patches the shadow-stack entry to match the expected return address
- Requires kernel-level access (BYOVD) for shadow-stack memory manipulation

**Detection**: Build number read from `KUSER_SHARED_DATA` (`0x7FFE0000 + 0x260`). CET assumed present on builds ≥ 26100. CFG policy queried via `GetProcessMitigationPolicy` for confirmation.

**Integration with syscalls.rs**: The `clean_call!` macro is the primary integration point — it checks CET state before calling `spoof_call` and routes through CET-compatible paths when shadow stacks are active. A secondary warning in `spoof_call` itself alerts if CET is active and the function is called directly.

### Token-Only Impersonation (`token_impersonation`)

The `token_impersonation` module (gated behind `#[cfg(all(windows, feature = "token-impersonation"))]`) bypasses EDR detection of `ImpersonateNamedPipeClient` by never calling it on the main agent thread:

**Strategy 1 — SetThreadToken (preferred)**:
1. Create a named pipe and wait for client connection
2. Briefly call `ImpersonateNamedPipeClient`, extract token via `NtOpenThreadToken`
3. Immediately revert via `RevertToSelf`
4. Duplicate token via `NtDuplicateToken`, apply via `SetThreadToken(NULL, dup)`
5. EDR monitoring post-revert sees no impersonation context

**Strategy 2 — Impersonation Thread (fallback)**:
1. Spawn helper thread that calls `ConnectNamedPipe` + `ImpersonateNamedPipeClient`
2. Main thread extracts token via `NtOpenThreadToken` on helper thread
3. Apply via `NtSetInformationThread(ThreadImpersonationToken)`
4. Main thread call stack never contains impersonation APIs

**Token Cache**: Extracted tokens are stored in `HashMap<TokenSource, CachedToken>` with user/domain/SID metadata. Active tracking enables auto-revert after task completion.

**Integration Points**:
- `lsass_harvest.rs`: `prepare_privileges()` checks cached tokens first before SeDebugPrivilege/SYSTEM theft
- `p2p.rs`: Pipe server extracts tokens from connecting peers via `import_token()`
- `handlers.rs`: Auto-revert after each task if configured

### Forensic Cleanup — Prefetch Evidence Removal (`forensic_cleanup`)

The `forensic_cleanup::prefetch` module (gated behind `#[cfg(all(windows, feature = "forensic-cleanup"))]`) removes Windows Prefetch (.pf) evidence that records process execution data:

**Why**: Windows stores .pf files in `C:\Windows\Prefetch\` recording executable name, run count, timestamps, loaded DLLs, and accessed directories. EDR and forensic tools parse these to build execution timelines.

**Three Cleanup Strategies**:

1. **Patch** (preferred) — Maps the .pf file via `NtCreateSection` + `NtMapViewOfSection`, patches the header in-place (zeros run count, timestamps, executable name/paths), then unmaps. File remains on disk but contains no useful forensic data.

2. **Delete** — Removes the .pf file via `NtDeleteFile`. More obvious to EDR but simpler.

3. **Disable service** — Sets `EnablePrefetcher` registry value to 0 before the operation, restores after. Prevents new .pf files from being created during the operation window.

**PF Format Support**: Parses MAM-format .pf headers for Windows 8 (v17), 8.1 (v23), 10 (v26), and 11 (v30). Extracts executable name from `EXECUTABLE-HASH.pf` naming convention for targeted cleanup.

**USN Journal Consistency**: Reads USN journal entries referencing the .pf file and writes USN close records to cleanly mark them, preventing forensic timeline analysis from recovering modification events.

**All NT API calls** use indirect syscalls via `nt_syscall` to bypass user-mode hooks:
- `NtCreateFile`, `NtQueryDirectoryFile` — Directory and file enumeration
- `NtDeleteFile` — File deletion
- `NtCreateSection`, `NtMapViewOfSection`, `NtUnmapViewOfSection` — Memory mapping for patching
- `NtOpenKey`, `NtSetValueKey`, `NtQueryValueKey`, `NtClose` — Registry manipulation
- `NtFsControlFile` — USN journal operations

**Post-Injection Hook**: Automatically cleans .pf evidence for the injected process after `TransactedHollow` or `DelayedStomp` completes. The hook is in `handlers.rs`, not `injection_engine.rs` — injection logic is unmodified.

**Collision Note**: This handles DISK evidence only. It does NOT overlap with any memory-hygiene subsystem (which handles MEMORY evidence).

### Forensic Cleanup Pipeline — Full Flow

Beyond prefetch, the forensic cleanup pipeline includes additional stages for comprehensive evidence removal:

```
┌─────────────────────────────────────────────────────────────┐
│                  Forensic Cleanup Pipeline                   │
│                                                              │
│  Stage 1: Prefetch                                          │
│  ├── Scan C:\Windows\Prefetch\ for matching .pf files       │
│  ├── Patch headers (preferred) or delete files               │
│  ├── Optionally disable Prefetch service                     │
│  └── Clean USN journal entries for modified .pf files        │
│                                                              │
│  Stage 2: MFT Timestamps                                     │
│  ├── Record baseline timestamps before file operations       │
│  ├── Restore original timestamps via NtSetInformationFile    │
│  └── Zero MFT entries for deleted files                      │
│                                                              │
│  Stage 3: USN Journal                                        │
│  ├── Enumerate USN entries referencing agent files           │
│  ├── Selective deletion of matching entries                  │
│  └── Nuclear: delete entire USN journal if needed            │
│                                                              │
│  Stage 4: $LogFile                                           │
│  ├── Scan NTFS $LogFile pages for agent references           │
│  ├── Overwrite matching records with zeros                   │
│  └── Recalculate page checksums                              │
│                                                              │
│  Stage 5: Memory Hygiene                                     │
│  ├── SecureZeroMemory all temporary buffers                  │
│  ├── Free all cleanup allocations                            │
│  └── NtFlushBuffersFile to commit changes to disk            │
└─────────────────────────────────────────────────────────────┘
```

See `docs/FORENSICS.md` for detailed documentation of each stage, detection risk assessment, and operational security recommendations.

### Unhook Callback Registration

When the `ntdll_unhook` module is available, it registers a fallback callback with `nt_syscall`:

```rust
// In agent initialization:
nt_syscall::set_halo_gate_fallback(crate::ntdll_unhook::halo_gate_fallback);

// In nt_syscall, when Halo's Gate fails:
if let Some(cb) = HALO_GATE_FALLBACK.load(Ordering::Relaxed) {
    let func: fn(&str) -> Option<SyscallTarget> = unsafe { std::mem::transmute(cb) };
    if let Some(target) = func(syscall_name) {
        return Some(target);
    }
}
```

This avoids a circular dependency: `nt_syscall` cannot depend on `agent`, so the agent registers its unhook callback at startup.

---

## Memory Guard Lifecycle

The `memory_guard` module provides encrypted heap storage that integrates with the sleep obfuscation cycle.

### Registration

```rust
// Register a heap allocation for automatic encryption during sleep
let guarded = MemoryGuard::new(1024);  // Allocates 1024 bytes
// Data is automatically tracked and will be encrypted during sleep
```

### Lifecycle States

```
  ┌──────────┐
  │Allocated │◄── Initial state after MemoryGuard::new()
  └────┬─────┘
       │ Sleep cycle begins
  ┌────▼─────┐
  │Encrypted │◄── MemoryGuard registers region with sleep subsystem
  └────┬─────┘    Contents encrypted with XChaCha20-Poly1305
       │ Wake
  ┌────▼─────┐
  │Decrypted │◄── Contents restored, integrity verified
  └────┬─────┘
       │ Drop
  ┌────▼─────┐
  │  Freed   │◄── Zeroed before deallocation
  └──────────┘
```

### XMM Register Key Stash (Windows)

On Windows x86_64, the sleep encryption key is stashed in XMM14/XMM15 registers:

- **XMM14**: First 16 bytes of the 32-byte XChaCha20 key
- **XMM15**: Last 16 bytes of the 32-byte XChaCha20 key

These registers are not routinely inspected by EDR memory scanners and survive `NtDelayExecution` calls. The key never exists in process memory as plaintext during the sleep period.

### Sleep Variants

The agent supports two sleep mechanisms, selectable via configuration or runtime command:

#### Ekko (NtDelayExecution)

The classic approach: calls `NtDelayExecution` with a negative relative timeout.
Well-tested but heavily monitored by EDR hooks on `ntdll!NtDelayExecution`.

#### Cronus (Waitable Timer) — Default

Uses an unnamed waitable timer created via `NtCreateTimer` and configured with
`NtSetTimer`.  The agent waits on the timer handle with `NtWaitForSingleObject`
(alertable wait).  This approach is less commonly hooked by EDR because
waitable timers are a legitimate synchronization mechanism used by many
applications.

**Auto-select**: When Cronus is configured, the agent verifies that `NtSetTimer`
resolves successfully.  If the syscall cannot be located, it automatically falls
back to Ekko with a log warning.

**RC4 encryption stub**: Cronus includes a position-independent RC4 encryption
stub (generated at runtime) that can be used for remote process sleep encryption.
The stub is allocated as a single RWX page with the pre-initialized S-box and
key embedded at fixed offsets, using RIP-relative addressing.

**Configuration**:
```toml
[sleep]
method = "cronus"   # or "ekko"
```

**Runtime switching**:
```
SetSleepVariant { variant: "cronus" }   # or "ekko"
```

---

## Evanesco — Continuous Memory Hiding

Evanesco is an additional memory-protection layer that keeps all enrolled pages
encrypted and `PAGE_NOACCESS` at all times — not just during sleep.  It sits
alongside (and integrates with) the existing sleep obfuscation subsystem but
operates independently on a per-page basis.

### Architecture Overview

```
  ┌──────────────────────────────────────────────────────────────┐
  │                     PageTrackerInner                         │
  │  ┌────────────────────────────────────────────────────────┐  │
  │  │ pages: RwLock<HashMap<usize, PageInfo>>                │  │
  │  │   key = page-aligned base address                      │  │
  │  │   value = { base, size, state, aead_key: [u8; 32],       │  │
  │  │            last_access, orig_protect, label }          │  │
  │  └────────────────────────────────────────────────────────┘  │
  │  idle_threshold_ms  scan_interval_ms  shutdown flag          │
  │  encrypt_count      decrypt_count                           │
  └──────────┬──────────────────────┬───────────────────────────┘
             │                      │
    ┌────────▼────────┐   ┌────────▼────────┐
    │ Background      │   │ VEH Handler     │
    │ Re-encrypt      │   │ (auto-decrypt)  │
    │ Thread          │   │                 │
    └─────────────────┘   └─────────────────┘
```

### Page States

| State           | Protection        | Description                                    |
|-----------------|-------------------|------------------------------------------------|
| `Encrypted`     | `PAGE_NOACCESS`   | Encrypted with per-page XChaCha20-Poly1305; unreadable |
| `DecryptedRW`   | `PAGE_READWRITE`  | Decrypted, accessible for reading/writing      |
| `DecodedRX`     | `PAGE_EXECUTE_READ` | Decrypted, executable for code execution     |

### Key Flows

**JIT Decryption** (`acquire_pages` → `PageGuard`):
1. Caller requests page range with `AccessType::ReadWrite` or `Execute`.
2. `PageTrackerInner` XChaCha20-Poly1305 decrypts the page in place.
3. `NtProtectVirtualMemory` sets `PAGE_READWRITE` or `PAGE_EXECUTE_READ`.
4. `PageGuard` is returned — holds references, updates `last_access`.
5. On `Drop`, `PageGuard` re-encrypts and restores `PAGE_NOACCESS`.

**VEH Auto-decryption** (transparent):
1. Code executes on a tracked page that is `PAGE_NOACCESS`.
2. CPU raises `STATUS_ACCESS_VIOLATION` (0xC0000005).
3. VEH handler aligns fault address to page boundary.
4. Looks up the page in the tracker.  If found, decrypts with `Execute` access.
5. Returns `EXCEPTION_CONTINUE_EXECUTION` — the faulting instruction retries.

**Background Re-encryption**:
1. Thread wakes every `scan_interval_ms` (default 50 ms).
2. Iterates all tracked pages; collects those with `last_access` older than
   `idle_threshold_ms` (default 100 ms).
3. Re-encrypts each idle page and restores `PAGE_NOACCESS`.

### Integration Points

| Component            | Integration                                           |
|----------------------|-------------------------------------------------------|
| `sleep_obfuscation`  | `encrypt_all()` on sleep, `decrypt_minimum()` on wake |
| `injection_engine`   | `enroll()` to register payload pages                  |
| `memory_guard`       | Additional layer; MemoryGuard heap + Evanesco pages   |
| `handlers.rs`        | `EvanescoStatus`, `EvanescoSetThreshold` commands     |

### Configuration

```toml
[evanesco]
idle-threshold-ms = 100   # re-encrypt after 100 ms idle
scan-interval-ms = 50     # background thread check interval
```

### Cryptography

| Operation           | Algorithm              | Rationale                                   |
|---------------------|------------------------|---------------------------------------------|
| Per-page encrypt    | XChaCha20-Poly1305 (per-page key) | AEAD with integrity, low overhead for frequent ops |
| Full sleep sweep    | XChaCha20-Poly1305     | Stronger AEAD for the longer sleep window   |

### Feature Flag

```toml
# agent/Cargo.toml
[features]
evanesco = []
```

All code lives in `agent/src/page_tracker.rs` and is gated behind
`#[cfg(all(windows, feature = "evanesco"))]`.

---

## Evasion Subsystem

### AMSI Bypass

The agent implements three AMSI bypass strategies, selectable at build time
and switchable at runtime via the `AmsiBypassMode` command:

#### Write-Raid AMSI (`amsi_defense.rs` — `write-raid-amsi` feature) — *Preferred*

A data-only race condition that avoids all code patching, hardware breakpoints,
and `VirtualProtect` calls:

1. Resolve `amsi.dll` base via PEB walking (`pe_resolve`)
2. Locate the `AmsiInitialize` export and scan its prologue for
   `mov dword ptr [rip+disp], 1` — the instruction that sets
   `AmsiInitFailed` during initialization failure
3. Extract the RIP-relative target address (the `AmsiInitFailed` flag in
   `.data`)
4. Spawn a dedicated race thread via `NtCreateThreadEx` (indirect syscall)
5. The race thread continuously writes `1` to the `AmsiInitFailed` flag using
   `NtWriteVirtualMemory` on `NtCurrentProcess()`, causing all subsequent
   `AmsiScanBuffer` calls to short-circuit and return `AMSI_RESULT_CLEAN`
6. Between iterations, the thread yields via `NtDelayExecution(0)` or
   `SwitchToThread()`

**OPSEC advantages:**

- Zero `.text` modifications — code integrity checks pass
- Zero `NtProtectVirtualMemory` calls — no page-protection changes
- Zero hardware breakpoint registers — DR0–DR7 remain clean
- The `.data` write blends with normal AMSI internal state updates
- Thread is registered with sleep obfuscation (pauses during memory encryption)

The bypass can be enabled/disabled at runtime and is compatible with the
sleep obfuscation subsystem (the race thread pauses during memory encryption
cycles to avoid corrupting ciphertext).

#### HWBP AMSI (`amsi_defense.rs` — HWBP mode)

Uses hardware breakpoints with a Vectored Exception Handler. The register set
is architecture-specific: DR0/DR1/DR7 on Windows x86_64, and BVR/BCR slots on
Windows ARM64.

1. `AddVectoredExceptionHandler(1, amsi_veh_handler)` — Register VEH as first handler
2. `SetThreadContext` — Set execute breakpoints on `AmsiScanBuffer` and `AmsiScanString`
3. Enable the selected breakpoint slots in the architecture's context state
4. When AMSI is called, the CPU triggers a breakpoint exception
5. The VEH handler intercepts the exception, sets `RAX = S_OK` (0) and `Result = AmsiResult::AMSI_RESULT_CLEAN`
6. Execution continues as if the scan returned clean

This approach does not modify any code pages, making it invisible to memory integrity checks.

#### Memory Patch AMSI (`amsi_defense.rs` — Memory mode)

Directly patches `amsiInitFailed` in the `amsi.dll` `.data` section:

1. Resolve `amsi.dll` base via PEB walking
2. Find the `AmsiInitialize` function export
3. Locate the `amsiInitFailed` flag variable in `.data`
4. Use `NtProtectVirtualMemory` (via syscall) to make the page writable
5. Patch the flag to non-zero (forcing initialization failure)
6. All subsequent AMSI scans return `AMSI_RESULT_CLEAN`

Fallback: If patching fails, the agent falls back to returning `E_INVALIDARG` from `AmsiScanBuffer` by patching the function's prologue.

### ETW Patching (`etw_patch.rs`)

Patches ETW functions to suppress event telemetry:

1. Resolve `ntdll.dll` base via PEB walking
2. Find `EtwEventWrite`, `EtwEventWriteEx`, and `NtTraceEvent` exports
3. Use `NtProtectVirtualMemory` syscall to make the code page writable
4. Patch the first bytes of each function to:
   ```asm
   mov eax, 0x00000000  ; STATUS_SUCCESS
   ret
   ```
5. `NtProtectVirtualMemory` to restore original protection

Three patch modes:
- **Safe** — Patch only if no EDR hooks detected on the target functions
- **Always** — Unconditionally patch
- **Never** — Skip ETW patching entirely

---

## C2 State Machine

### HTTP Transport (`c2_http.rs`)

The HTTP transport implements a full malleable C2 state machine:

```
┌──────────────────────────────────────────────────┐
│                 HttpTransport                     │
│                                                  │
│  Fields:                                         │
│  - client: reqwest::Client                       │
│  - session: CryptoSession                        │
│  - agent_id: String                              │
│  - profile: AgentMalleableProfile                │
│  - redirectors: Vec<RedirectorConfig>            │
│  - failover: FailoverState                       │
│  - front_domain: Option<String>                  │
│  - current_sticky: usize (sticky counter)        │
│  - backoff_secs: f64                             │
│  - endpoint_index: usize                         │
└──────────────────────────────────────────────────┘
```

### Request Lifecycle

1. **Select URI** — Randomly pick from `profile.http_get.uri` (beacon) or `profile.http_post.uri` (task result)
2. **Apply transforms** — Prepend, encode (Base64/Mask/NetBIOS), append to data
3. **Set headers** — User-Agent from profile, custom headers
4. **Deliver payload** — Cookie, URI-append, header, or body delivery based on profile
5. **Domain fronting** (if configured) — Connect to front domain IP, send actual Host header
6. **Redirector failover** — On failure, advance to next redirector with exponential backoff

### FailoverState Management

```rust
pub struct FailoverState {
    pub current_index: usize,
    pub sticky_count: usize,
    pub max_sticky: usize,       // Default: 10
    pub backoff_secs: f64,
    pub max_backoff: f64,        // Default: 60.0
    pub full_cycle: bool,
}
```

- **Sticky session**: After a successful request, keep using the same endpoint for `max_sticky` requests
- **Exponential backoff**: On failure, `backoff_secs *= 2.0` up to `max_backoff`
- **Full cycle**: After exhausting all redirectors, fall back to direct C2
- **Recovery**: After direct C2 succeeds, reset and try redirectors again

### DNS-over-HTTPS Transport (`c2_doh.rs`)

The DoH transport encodes C2 data in DNS queries:

1. **Beacon** — Agent sends periodic A-record queries to `beacon_pattern.data.dns_suffix`
2. **Task retrieval** — Server responds with encoded task data in A or TXT records
3. **Data exfiltration** — Agent sends TXT queries with encoded result data
4. **Encoding** — hex, base32, or base64url depending on profile setting
5. **Resolver** — All queries go through `https://dns.google/dns-query` (configurable)

### SSH Transport (`c2_ssh.rs`)

Tunnels C2 traffic through SSH subsystem connections:

1. Connect to SSH server using key, password, or agent authentication
2. Request a subsystem (`IOC_SSH_SUBSYSTEM` — randomized per build)
3. Use the subsystem channel as a `Transport` (bincode frames)
4. Session keepalive via SSH keepalive messages

### SMB Transport (`c2_smb.rs`)

Uses Windows named pipes or TCP relay:

1. Connect to `\\.\pipe\IOC_PIPE_NAME` (randomized per build)
2. Or connect to a TCP relay on the configured port
3. Use the pipe/socket as a `Transport` (bincode frames)
4. Supports both inbound (server creates pipe) and outbound (agent connects) modes

---

## Wire Protocol

### Frame Format

Every frame on the wire follows this format:

```
┌──────────────┬──────────────────────────────────────────┐
│ u32 LE (4 B) │ Encrypted payload                        │
│ length       │                                          │
└──────────────┴──────────────────────────────────────────┘
```

Inside the encrypted payload (protocol v2):

```
┌────────────┬──────────────┬─────────────────────────────┐
│ salt (32B) │ nonce (12B)  │ ciphertext + GCM tag (16B)  │
└────────────┴──────────────┴─────────────────────────────┘
```

- **Salt**: 32 random bytes per message, used for HKDF key derivation
- **Nonce**: 12 random bytes per message
- **Key derivation**: `HKDF-SHA256(salt, psk, info=b"orchestra-v2")` → 32-byte per-message key
- **Ciphertext**: bincode-serialized `Message`, encrypted with AES-256-GCM

### Message Variants

| Variant | Direction | Purpose |
|---------|-----------|---------|
| `VersionHandshake` | bidirectional | Protocol version negotiation (current: v2) |
| `Heartbeat` | agent → server | Liveness + status report |
| `TaskRequest` | server → agent | Execute a `Command` under a `task_id` |
| `TaskResponse` | agent → server | Return result keyed by `task_id` |
| `ModulePush` | server → agent | Deliver encrypted, signed plugin |
| `ModuleRequest` | agent → server | Request a specific module by name |
| `ModuleResponse` | server → agent | Module data response |
| `AuditLog` | agent → server | Audit event for compliance logging |
| `MorphResult` | agent → server | Self-reencode completion notification |
| `P2pForward` | agent → agent | P2P mesh data forwarding |
| `P2pToChild` | parent → child | P2P mesh child-directed message |
| `P2pTopologyReport` | agent → server | P2P mesh topology update |
| `Shutdown` | bidirectional | Graceful session termination |

### CryptoSession API

```rust
impl CryptoSession {
    pub fn from_shared_secret(key: &[u8]) -> Self;
    pub fn from_shared_secret_with_salt(key: &[u8], salt: &[u8]) -> Self;
    pub fn from_key(key: [u8; 32], salt: [u8; 32]) -> Self;
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8>;
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError>;
    pub fn decrypt_with_psk(psk: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError>;
}
```

### Forward Secrecy

When the `forward-secrecy` feature is enabled:

1. Both sides generate X25519 ephemeral keypairs
2. Exchange public keys over the encrypted channel
3. Compute shared secret: `X25519(my_secret, peer_public)`
4. Derive session key: `HKDF-SHA256(shared_secret, SHA256(PSK), "orchestra-fs-v1")`
5. All subsequent frames use the derived session key

Key ordering uses canonical comparison to ensure both sides derive the same key regardless of role.

---

## Server Internals

### Orchestra Server (`orchestra-server`)

Built on `axum` 0.7 with `tokio` async runtime:

| Module | Responsibility |
|--------|---------------|
| `api.rs` | REST API routes (dashboard, build queue, agent management, fingerprint) |
| `state.rs` | `AppState` with `DashMap` for agents, modules, redirectors |
| `config.rs` | Server configuration parsing (`ServerConfig`) |
| `malleable.rs` | `MultiProfileManager` — loads, validates, hot-reloads profiles |
| `http_c2.rs` | HTTP C2 listener with malleable profile handling |
| `doh_listener.rs` | DNS-over-HTTPS C2 listener |
| `redirector.rs` | Redirector registration and health monitoring |
| `build_handler.rs` | On-demand agent compilation via build worker pool |
| `agent_link.rs` | Agent session management |
| `audit.rs` | JSONL audit log with HMAC-SHA256 tamper evidence |
| `auth.rs` | Bearer token operator authentication |
| `tls.rs` | TLS configuration and certificate fingerprint computation |
| `smb_relay.rs` | SMB named pipe relay for P2P agent chains |

### Build Pipeline

The build API (`POST /api/build`) compiles an agent binary on-demand with all
C2 parameters baked in as compile-time constants. This avoids the need for a
runtime configuration file on the deployed agent.

```
Operator POST /api/build
{os, arch, host, port, pin, key, features, ...}
           │
           ▼
  build_handler.rs: validate request
  resolve_and_validate_host()
  (blocks loopback unless allow_local_builds = true)
           │
           ▼
  build_profile_from_request()
  → PayloadConfig {
      c_server_addr     = host:port
      c_server_secret   = agent_shared_secret  (verbatim PSK)
      c_cert_pin        = pin (64-hex)
      enc_key           = key (base64 AES-256)
      module_aes_key    = server config module_aes_key
      features          = BuildFeatures { ... }
    }
           │
           ▼
  Serialize PayloadConfig → temp profile TOML file
  in workspace sandbox copy
           │
           ▼
  cargo run -p builder --bin orchestra-builder -- build <profile>
  with env vars:
    ORCHESTRA_C_ADDR        = host:port
    ORCHESTRA_C_SECRET      = PSK
    ORCHESTRA_C_CERT_FP     = pin
    ORCHESTRA_MODULE_AES_KEY= module_aes_key
           │
           ▼
  agent/build.rs forwards each ORCHESTRA_* var:
    cargo:rustc-env=SYS_C_ADDR=...
    cargo:rustc-env=SYS_C_SECRET=...
    cargo:rustc-env=SYS_C_CERT_FP=...
    cargo:rustc-env=SYS_MODULE_KEY=...
           │
           ▼
  agent binary compiled — all values baked in via option_env!()
           │
           ▼
  Binary encrypted with AES-256-GCM + HKDF-SHA256
  Wire format: salt(32) ‖ nonce(12) ‖ ciphertext
  HKDF info: b"\x01\x8c\xa3\xf2\x6b\x4d\xe7\x90\x5a\x1f\xbc\xd8\x3e\x72\x09\xaf"
           │
           ▼
  Saved to builds_output_dir/<date>_<job_id>/agent-<job_id>-<os>-<arch>.enc
           │
           ▼
  Download via GET /api/build/<job_id>/download
```

### module_aes_key Propagation Chain

The module AES key is a 32-byte secret that authenticates deployed modules.
It MUST be present in production (non-debug) agent builds:

```
orchestra-server.toml
  module_aes_key = "<base64>"
       │
       ▼ ServerConfig::module_aes_key
  execute_build_safely(module_aes_key = config.module_aes_key)
       │
       ▼ build_profile_from_request(module_aes_key)
  PayloadConfig { module_aes_key: Some("<base64>") }
       │
       ▼ builder/src/build.rs
  env ORCHESTRA_MODULE_AES_KEY="<base64>"  passed to cargo
       │
       ▼ agent/build.rs
  cargo:rustc-env=SYS_MODULE_KEY=<base64>
       │
       ▼ agent/src/lib.rs  option_env!("SYS_MODULE_KEY")
  let module_aes_key: [u8; 32] = base64::decode(baked)?
```

If `module_aes_key` is not set in the server config, the built agent will fail
at startup with a hard error (`module_aes_key is required in production builds`).

### REST API Routes

All routes under `/api/` require `Authorization: Bearer <admin_token>`.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/agents` | List connected agents |
| `POST` | `/api/agents/<id>/command` | Execute a command, wait for response |
| `POST` | `/api/build` | Submit a build job |
| `GET` | `/api/build/status/<job_id>` | Poll build status and log tail |
| `GET` | `/api/build/<job_id>/download` | Download encrypted `.enc` payload |
| `GET` | `/api/info/fingerprint` | Return server TLS cert SHA-256 hex fingerprint |
| `GET` | `/api/audit` | Return audit log (JSONL) |
| `POST` | `/api/redirector/register` | Redirector self-registration |
| `POST` | `/api/redirector/heartbeat` | Redirector heartbeat |

### Web Dashboard

The operator dashboard is served as static files from `static_dir`
(`orchestra-server/static/`) and provides a 4-tab interface:

| Tab | Purpose |
|-----|---------|
| **Dashboard** | Live agent table, command panel (100+ commands across 10 categories) |
| **Shell** | Interactive shell relay to selected agent |
| **Builder** | Full agent build form: target, C2 params, feature flags, PE artifact kit |
| **Audit Log** | Live-updating JSONL audit log with keyword filter |

The Builder tab includes a "Fetch Pin" button that calls `GET /api/info/fingerprint`
to auto-populate the TLS certificate pin field, eliminating manual SHA-256
computation.

### TLS Certificate Fingerprint

`GET /api/info/fingerprint` reads the configured PEM file, parses the first
certificate, DER-encodes it, and returns the SHA-256 hex digest:

```rust
// SHA-256 of DER body (not fingerprint of PEM text)
let fingerprint = hex::encode(sha256::digest(&der_bytes));
// → {"fingerprint": "9cf7a2d57b0b259e1c8e04a4f2c3721248054ea4d7bcf55ddf2247ac98883bd9"}
```

This value is used as the `pin` field in build requests and as the
`SYS_C_CERT_FP` compile-time constant baked into the agent binary.



```rust
pub struct MultiProfileManager {
    profiles: DashMap<String, MalleableProfile>,
    watch_dir: PathBuf,
}
```

- Watches the `profiles/` directory for changes
- Validates profiles before loading
- Supports simultaneous serving of multiple profiles on different ports or via SNI routing
- Hot-reloads without server restart

---

## P2P Mesh Protocol

### Frame Format

```
┌──────────────┬─────────────┬───────────────┬─────────────────┐
│ type (1B)    │ link_id (4B)│ payload_len   │ payload         │
│ P2pFrameType │             │ (4B)          │ (payload_len B) │
└──────────────┴─────────────┴───────────────┴─────────────────┘
```

### Frame Types

| Type | Code | Purpose |
|------|------|---------|
| `LinkRequest` | `0x30` | Initiate a new P2P link |
| `LinkAccept` | `0x31` | Accept link request |
| `LinkReject` | `0x32` | Reject link request (includes reason) |
| `Heartbeat` | `0x33` | Keep-alive + latency measurement |
| `Disconnect` | `0x34` | Graceful link teardown |
| `DataForward` | `0x35` | Relay data toward C2 |
| `CertificateRevocation` | `0x36` | Revoke a mesh certificate |
| `QuarantineReport` | `0x37` | Report quarantined agent |
| `KeyRotation` | `0x38` | Start per-link key rotation |
| `KeyRotationAck` | `0x39` | Acknowledge key rotation |
| `RouteUpdate` | `0x3A` | Distance-vector route advertisement |
| `RouteProbe` | `0x3B` | Measure link latency/hops |
| `RouteProbeReply` | `0x3C` | Reply to route probe |
| `DataAck` | `0x3D` | Acknowledge data receipt |
| `TopologyReport` | `0x3E` | Report mesh topology to server |
| `BandwidthProbe` | `0x3F` | Measure available bandwidth |

### Topology Modes

```
Tree Mode:                  Mesh Mode:                  Hybrid Mode:
                            (all agents peers)          (tree + peer shortcuts)

     Server                      Server                      Server
       │                           │                           │
    Parent                      Agent A                    Parent
    ┌──┼──┐                   ◄──► B ◄──► C               ┌──┼──┐
    A  B  C                   ◄──► D ◄──► E               A  B  C
    (no lateral)               (full mesh)                     ◄──►
                                                             (peer link)
```

- **Tree**: Strict hierarchy — all traffic through parents. Maximum OPSEC.
- **Mesh**: Full peer-to-peer with route discovery. Maximum resilience.
- **Hybrid** (default): Tree backbone with optional peer links.

### Certificate Lifecycle

```
┌───────────┐      ┌──────────────┐      ┌───────────────┐
│  Server   │─────►│   Agent A    │      │   Agent B     │
│  issues   │      │  (presented  │─────►│   (verifies   │
│  MeshCert │      │   to peers)  │      │   signature)  │
└───────────┘      └──────┬───────┘      └───────────────┘
                          │                       │
                   ┌──────▼───────┐        ┌──────▼──────┐
                   │  Renewal     │        │ Revocation  │
                   │  (2h before  │        │ (propagates │
                   │   expiry)    │        │  via mesh)  │
                   └──────────────┘        └─────────────┘
```

- Certificates are signed with the server's Ed25519 `module_signing_key`.
- Lifetime: 24 hours. Renewal window: 2 hours before expiry.
- Revocation propagates through `CertificateRevocation` frames.
- All agents terminate links to revoked peers immediately.

### Key Rotation Timeline

```
Time: 0h          4h          4h+δ         4h+δ+30s
      │            │            │             │
      ├─ normal ──►│ rotation   │ new key     │ old key
      │  traffic   │ starts     │ active      │ discarded
      │            │            │             │
      │            │◄─ overlap ─►│             │
      │            │  (30s)     │             │
      │            │            │             │
      │  OLD key   │ OLD key    │ NEW key     │ NEW key
      │  only      │ + NEW key  │ + OLD key   │ only
```

- Rotation interval: 4 hours per link.
- Overlap period: 30 seconds (both keys accepted).
- Timeout: 60 seconds for `KeyRotationAck`, then retry.
- Max retries: 3 before giving up on rotation.

### Routing

- **Protocol**: Distributed distance-vector (Bellman-Ford).
- **Update interval**: 60 seconds (`RouteUpdate` frames).
- **Quality metric**: Composite of latency (40%), packet loss (40%), jitter (20%).
- **Relay selection**: 70% route quality + 30% inverse hop count.
- **Stale timeout**: Routes expire after 300 seconds without update.

---

## Cryptographic Summary

| Primitive | Usage | Key Size |
|-----------|-------|----------|
| AES-256-GCM | Wire encryption (all transports) | 256-bit |
| ChaCha20-Poly1305 | P2P per-link encryption | 256-bit |
| HKDF-SHA256 | Per-message key derivation, P2P link key derivation | 256-bit |
| X25519 | Forward secrecy ECDH, P2P link handshake & key rotation | 256-bit |
| Ed25519 | Module signing/verification, mesh certificate signing | 256-bit |
| XChaCha20-Poly1305 | Sleep obfuscation memory encryption | 256-bit |
| HMAC-SHA256 | Audit log integrity, config HMAC | 256-bit |
| SHA-256 | Certificate fingerprinting, agent identity hashing, integrity checks | 256-bit |

---

## Unified Injection Engine (`injection_engine.rs`)

The unified injection engine provides a single framework for all injection techniques with automatic selection, EDR reconnaissance, fallback chains, and ETW evasion.

### Technique Taxonomy — `InjectionTechnique` Enum (15 Variants)

| Variant | Description | Sub-variants |
|---------|-------------|-------------|
| `ProcessHollow` | Classic process hollowing (unmap + rewrite) | — |
| `ModuleStomp` | Overwrite loaded DLL `.text` section | — |
| `ExistingModuleStomp` | Stomp an already-loaded DLL without a new image load | — |
| `EarlyBirdApc` | Queue APC before main thread starts | — |
| `ThreadHijack` | Suspend + redirect instruction pointer | — |
| `ThreadPool { variant }` | PoolParty — leverage existing thread pool | 8: `Work`, `WorkerFactory`, `Timer`, `IoCompletion`, `Wait`, `Alpc`, `Direct`, `AsyncIo` |
| `FiberInject` | Fiber creation + context switch | — |
| `ContextOnly` | CONTEXT-only IP/SP redirect with restore trampoline (no new remote thread) | — |
| `WaitingThreadHijack { target_pid, target_tid }` | Stack return-address overwrite on waiting thread | — |
| `CallbackInjection { target_pid, api }` | Callback-based, no explicit thread creation | 12 APIs: `EnumSystemLocalesA`, `EnumWindows`, `EnumChildWindows`, `EnumDesktopWindows`, `CreateTimerQueueTimer`, `EnumTimeFormatsA`, `EnumResourceTypesW`, `EnumFontFamilies`, `CertEnumSystemStore`, `SHEnumerateUnreadMailAccounts`, `EnumerateLoadedModules`, `CopyFileEx` |
| `SectionMapping { target_pid, exec_method, enhanced }` | `NtCreateSection` + dual `NtMapViewOfSection`; no `WriteProcessMemory` | exec_method: `Apc`, `Thread`, `Callback`; `enhanced` = double-mapped |
| `NtSetInfoProcess { target_pid }` | `ProcessReadWriteVm` (0x6A) write bypass | — |
| `TransactedHollowing` | NTFS transaction-based hollowing with ETW blinding | — |
| `DelayedModuleStomp` | Load DLL, wait 8–15 s, then stomp | — |
| `PhantomDllHollow` | Section-backed phantom DLL mapped into a suspended host process | — |

### Public API

```rust
pub struct InjectionConfig {
    pub technique: Option<InjectionTechnique>,  // None = auto-select
    pub target_process: String,
    pub payload: Vec<u8>,
    pub prefer_same_arch: bool,
    pub evade_etw: bool,
    pub timeout_ms: u32,
}

pub struct InjectionHandle {
    pub target_pid: u32,
    pub technique_used: InjectionTechnique,
    pub injected_base_addr: usize,
    pub payload_size: usize,
    pub sleep_enrolled: bool,
    // private: process_handle, thread_handle, sleep_stub_addr
}

pub fn inject(config: InjectionConfig) -> Result<InjectionHandle, InjectionError>
pub fn evasiveness_inject(config: InjectionConfig) -> Result<InjectionHandle, InjectionError>
pub fn parse_technique(name: &str) -> Result<InjectionTechnique, String>
```

### EDR Reconnaissance (`evasiveness_inject`)

When `evade_etw` is enabled, the engine performs pre-injection reconnaissance:

1. **ETW status check** — Tests whether `EtwEventWrite` is patched (in-agent) to decide if remote ETW blinding is needed
2. **Target process classification** — Identifies the target binary to select context-appropriate techniques
3. **EDR timing heuristic detection** — Adjusts delays and technique selection based on observed EDR scan patterns
4. **Sleep enrollment** — Injected payload pages are optionally enrolled with `sleep_obfuscation` for memory encryption during agent dormancy

### Technique String Parser (`parse_technique`)

The `UnifiedInject` command accepts technique names as strings to keep the `common` crate platform-independent:

| String | Resolved Technique |
|--------|--------------------|
| `"auto"` or omitted | `None` (auto-select) |
| `"ProcessHollow"` | `ProcessHollow` |
| `"ModuleStomp"` | `ModuleStomp` |
| `"EarlyBirdApc"` | `EarlyBirdApc` |
| `"ThreadHijack"` | `ThreadHijack` |
| `"ThreadPool"` | `ThreadPool { variant: None }` |
| `"ThreadPool:Work"` | `ThreadPool { variant: Some(Work) }` |
| `"FiberInject"` | `FiberInject` |
| `"ContextOnly"` | `ContextOnly` |
| `"WaitingThreadHijack"` | `WaitingThreadHijack { .. }` |
| `"CallbackInjection"` | `CallbackInjection { api: None }` |
| `"CallbackInjection:EnumSystemLocalesA"` | `CallbackInjection { api: Some(EnumSystemLocalesA) }` |
| `"SectionMapping"` | `SectionMapping { enhanced: false, .. }` |
| `"SectionMapping:Enhanced"` | `SectionMapping { enhanced: true }` |
| `"SectionMapping:Direct"` | `SectionMapping { exec_method: Some(Direct) }` |
| `"NtSetInfoProcess"` | `NtSetInfoProcess { .. }` |
| `"TransactedHollowing"` | `TransactedHollowing` |
| `"DelayedModuleStomp"` | `DelayedModuleStomp` |
| `"ExistingModuleStomp"` | `ExistingModuleStomp` |

`PhantomDllHollow` is a current enum variant and is included in auto-selection
when the `phantom-dll-hollow` feature is enabled. The current
`parse_technique` helper does not expose a `"PhantomDllHollow"` string.

### Auto-Selection Decision Tree

```
┌─────────────────────────────────────────┐
│ Is target process already running?      │
└────────────┬────────────────────────────┘
             │
     ┌─── Yes ───┴─── No ───┐
     │                       │
┌────▼─────────┐    ┌───────▼────────────┐
│ Is EDR       │    │ Create configured   │
│ aggressive?  │    │ sacrificial process │
└────┬─────────┘    └───────┬────────────┘
     │                      │
 ┌───┴───┐          ┌───────▼────────────┐
 Yes     No         │ EarlyBird APC      │
 │       │          │ (before thread     │
 │       │          │  resumes)          │
┌▼───────▼───────┐  └────────────────────┘
│ Transacted     │
│ Hollowing OR   │
│ Delayed Stomp  │
│ (highest stealth│
│  + timing ev.) │
└────────────────┘
```

### Technique Priority Ranking (Auto-Select)

Default ranking when `technique` is `None`:

```
WaitingThreadHijack > ContextOnly > SectionMapping > NtSetInfoProcess >
CallbackInjection > ThreadPool > EarlyBirdApc > ThreadHijack >
FiberInject > ProcessHollow > DelayedModuleStomp > ModuleStomp
```

Context-specific overrides:
| Condition | Override |
|-----------|----------|
| Target is `svchost.exe` | Prefer ThreadPool or Callback (service context) |
| Target is `explorer.exe` | Prefer ModuleStomping (user context) |
| CET detected and enabled | Avoid ThreadHijack and ContextOnly |
| Specified technique fails | Fall through to next priority |
| `TransactedHollowing` feature enabled | Ranked above standard ProcessHollow |
| `DelayedStomp` feature enabled | Ranked above standard ModuleStomp |

---

## Module Loading Pipeline

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│ Encrypted    │────►│ Decrypt      │────►│ Verify       │────►│ Load         │
│ Module Blob  │     │ AES-256-GCM  │     │ Ed25519      │     │ Platform-    │
└──────────────┘     └──────────────┘     └──────────────┘     │ specific     │
                                                                └──────┬───────┘
                                                                       │
                                                          ┌────────────▼───────────┐
                                                          │ Linux: memfd_create +  │
                                                          │   libloading           │
                                                          ├────────────────────────┤
                                                          │ Windows: manual_map or │
                                                          │   temp file            │
                                                          └────────────────────────┘
```

### Plugin Interface

```rust
#[repr(C)]
pub struct PluginObject {
    pub vtable: *const PluginVTable,
}

pub struct PluginVTable {
    pub init: extern "C" fn(*mut PluginObject),
    pub execute: extern "C" fn(*mut PluginObject, *const c_char) -> *const c_char,
    pub free_result: extern "C" fn(*const c_char),
    pub destroy: extern "C" fn(*mut PluginObject),
}

pub trait Plugin: Send + Sync {
    fn init(&self);
    fn execute(&self, args: &str) -> String;
    fn execute_binary(&self, input: &[u8]) -> Vec<u8>;
    fn get_metadata(&self) -> PluginMetadata;
}
```

---

## Persistence Subsystem

The `persistence` module implements platform-specific persistence mechanisms:

| Platform | Method | Details |
|----------|--------|---------|
| Windows | Registry Run | Writes to `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` with configurable key name |
| Windows | COM Hijack | Replaces InProcServer32 for a GUID with agent path |
| Windows | WMI Subscription | Creates `__EventFilter` + `CommandLineEventConsumer` binding via COM |
| macOS | LaunchAgent | Writes `.plist` to `~/Library/LaunchAgents/` and loads via `launchctl bootstrap gui/$(uid)` |
| Linux | cron | Adds `@reboot` entry to user crontab |
| Linux | systemd | Creates user service unit in `~/.config/systemd/user/` (user) or `/etc/systemd/system/` (root) |
| Linux | shell profile | Appends execution to `.bashrc` / `.zshrc` |

All persistence methods are gated behind the `persistence` feature flag and require an explicit `EnablePersistence` command.

---

## Binary Diversification Stack

Multiple layers ensure no two builds produce identical binaries:

| Layer | Crate | Mechanism |
|-------|-------|-----------|
| **Junk Code** | `junk_macro` | Attribute proc-macro inserts dead stores and calculations at function boundaries |
| **Instruction Scheduling** | `optimizer` | Reorders independent instructions for different execution orderings |
| **NOP Insertion** | `optimizer` | Inserts random NOP sleds (1–5 bytes) between instructions |
| **Instruction Substitution** | `optimizer` | Replaces instructions with equivalent forms (e.g., `xor rax, rax` → `mov rax, 0`) |
| **Opaque Predicates** | `code_transform` | Inserts always-true/false conditional branches that confuse disassemblers |
| **Block Reordering** | `code_transform` | Randomizes basic block order within functions |
| **Register Reallocation** | `code_transform` | Remaps registers to different physical registers |
| **String Encryption** | `string_crypt` | Compile-time XOR encryption of all string literals |
| **Self-Reencode** | `agent` (runtime) | Periodically re-encodes `.text` section with a fresh seed |
| **Per-Build IoCs** | `agent/build.rs` | Randomizes pipe names, DNS prefixes, service names, and other strings |
| **PE Hardening** | `builder` | Randomizes timestamps, section names, DOS stubs, Rich header removal |

---

## Cross-Platform Notes

Platform-specific code is gated with `#[cfg(target_os = "...")]` and feature flags:

```rust
#[cfg(target_os = "windows")]
mod injection;      // Full injection engine

#[cfg(target_os = "linux")]
mod injection;      // memfd_create-based injection only

#[cfg(target_os = "windows")]
mod evasion;        // AMSI, ETW patching

#[cfg(feature = "direct-syscalls")]
mod nt_syscall;     // SSN resolution, Halo's Gate
```

The workspace compiles cleanly with `cargo check --workspace --all-targets`
on the host and with target checks for `x86_64-pc-windows-gnu`,
`x86_64-pc-windows-msvc`, `aarch64-pc-windows-msvc`,
`aarch64-unknown-linux-gnu`, `x86_64-apple-darwin`, and
`aarch64-apple-darwin`:
- **Linux**: Full agent features, all tests pass on the host target; ARM64
   cross-check uses the configured Zig C wrapper.
- **Windows**: Full agent features, injection, evasion, and syscalls check on
   GNU x64 plus MSVC x64/ARM64.
- **macOS**: Core features, persistence, and remote-assist code paths check on
   x64 and ARM64 via the Darwin Zig wrappers.

---

## .NET Assembly Loader (`assembly_loader.rs`)

In-process .NET assembly execution via CLR hosting, compatible with any .NET Framework 4.x assembly:

### Architecture

```
┌──────────────────────┐
│ ExecuteAssembly cmd  │
└──────┬───────────────┘
       │
┌──────▼───────────────┐     ┌─────────────────────────┐
│ Lazy CLR init         │────►│ LoadLibrary(mscoree.dll) │
│ (once per process)    │     │ CLRCreateInstance()      │
└──────┬───────────────┘     │ ICLRMetaHost → ICLRRInfo  │
       │                      │ ICLRRuntimeHost::Start()  │
┌──────▼───────────────┐     └──────────────────────────┘
│ AMSI bypass           │
│ (pre-execution)       │
└──────┬───────────────┘
       │
┌──────▼───────────────┐
│ Create fresh          │
│ AppDomain per exec    │
└──────┬───────────────┘
       │
┌──────▼───────────────┐
│ ICLRRuntimeHost::     │
│ ExecuteInDefaultApp   │
│ Domain()              │
└──────┬───────────────┘
       │
┌──────▼───────────────┐
│ Collect output +      │
│ auto-teardown after   │
│ 5-min idle            │
└──────────────────────┘
```

### Key Properties

| Property | Value |
|----------|-------|
| Assembly source | Byte array received via `ExecuteAssembly` command |
| Arguments | Passed as space-delimited string |
| Timeout | Configurable; default 60 seconds |
| AppDomain | Fresh `AppDomain` per execution; unloaded on completion |
| AMSI bypass | Applied before assembly load via write-raid (preferred), HWBP, or memory patch |
| CLR version | .NET Framework 4.x (mscoree.dll CLRCreateInstance) |
| Auto-teardown | CLR resources released after 5 minutes idle |
| Max output | 4 MiB per execution |

---

## COFF / BOF Loader (`coff_loader.rs`)

Beacon Object File (BOF) execution compatible with the public BOF ecosystem:

### Execution Flow

1. Parse COFF headers, sections, symbols, relocations
2. Allocate RW memory, copy sections
3. Resolve external symbols (Beacon-compatible API)
4. Apply COFF relocations (x86_64: `IMAGE_REL_AMD64_ADDR64`, `ADDR32NB`, `REL32`)
5. `mprotect` to RX
6. Call `void go(char *args, int len)` entry point
7. Collect output from Beacon-compatible output functions

### Beacon-Compatible API

| Export | Purpose |
|--------|---------|
| `BeaconPrintf` | Formatted output (printf-style) |
| `BeaconOutput` | Raw output with type flag |
| `BeaconDataParse` | Parse packed BOF arguments |
| `BeaconDataInt` | Extract integer argument |
| `BeaconDataShort` | Extract short argument |
| `BeaconDataLength` | Get remaining argument length |
| `BeaconDataExtract` | Extract byte buffer argument |
| `BeaconFormatAlloc` | Allocate format buffer |
| `BeaconFormatPrintf` | Printf into format buffer |
| `BeaconFormatToString` | Convert format buffer to string |
| `BeaconFormatFree` | Free format buffer |
| `BeaconFormatInt` | Append integer to format buffer |
| `BeaconUseToken` | Apply stolen token (no-op in Orchestra) |
| `BeaconRevertToken` | Revert to original token (no-op) |
| `BeaconIsAdmin` | Check if running elevated |
| `toNative` | Convert char* to wide string |

| Constraint | Value |
|------------|-------|
| Max BOF size | 1 MiB |
| Max output | 1 MiB |
| Architecture | x86_64 only |
| Execution | Synchronous; blocks until `go()` returns |

---

## Browser Data Extraction (`browser_data.rs`)

Extracts credentials and cookies from Chrome, Edge, and Firefox. Gated behind `#[cfg(all(windows, feature = "browser-data"))]`.

### Supported Browsers and Data Types

| Browser | Credentials | Cookies | Notes |
|---------|:-----------:|:-------:|-------|
| Chrome | ✅ | ✅ | App-Bound Encryption v127+ with 4 bypass strategies (C4 padding oracle first) |
| Edge | ✅ | ✅ | Same Chromium engine as Chrome |
| Firefox | ✅ | ✅ | NSS library (logins.json + key4.db) |

### Chrome App-Bound Encryption (v127+)

Chrome 127+ uses App-Bound Encryption which ties decryption to an elevated service (`elevation_service.exe`). Four bypass strategies, attempted in order:

| Priority | Strategy | Method | Requirements |
|----------|----------|--------|--------------|
| **1st** | **C4 Bomb** (padding oracle) | CBC padding oracle against `CryptUnprotectData` — no elevation needed | `browser_c4_timeout_secs > 0` (default 60 s) |
| **2nd** | **Local COM** | Activate `IElevator` COM object in-process | Agent running elevated |
| **3rd** | **SYSTEM token + DPAPI** | Impersonate SYSTEM token, call `CryptUnprotectData` | Agent running as SYSTEM or with `SeDebugPrivilege` |
| **4th** | **Named-pipe IPC** | Communicate with `elevation_service.exe` via named pipe | Elevation service must be running |

### C4 Bomb — DPAPI Padding Oracle

```
┌───────────────┐     ┌──────────────────┐     ┌──────────────────┐
│ Parse DPAPI   │────►│ CBC Padding      │────►│ Extract AES-256  │
│ blob headers  │     │ Oracle Attack    │     │ key (last 32B)   │
│ (offset/len)  │     │ (CryptUnprotect  │     │                  │
└───────────────┘     │  Data as oracle) │     └──────────────────┘
                      └───────┬──────────┘
                              │
              ┌───────────────┼───────────────┐
              │               │               │
      ┌───────▼──────┐ ┌─────▼──────┐ ┌──────▼──────┐
      │ Random delay │ │ Shuffled   │ │ Cancel-safe │
      │ 1-10 ms      │ │ candidates │ │ AtomicBool  │
      │ (LCG-based)  │ │ (LCG-based)│ │ + timeout   │
      └──────────────┘ └────────────┘ └─────────────┘
```

- **Oracle**: `CryptUnprotectData` returns success (valid PKCS#7 padding) or failure (`ERROR_BAD_DATA`). Each call reveals one byte of plaintext.
- **OPSEC**: Random inter-oracle delays (1–10 ms) and shuffled candidate bytes via LCG PRNG — avoids deterministic timing patterns.
- **Cancellation**: `C4_LOCK` serializes attacks; new requests cancel in-progress attacks. Configurable timeout via `browser_c4_timeout_secs`.
- **Dynamic resolution**: `CryptUnprotectData` resolved at runtime via `pe_resolve` hash-based API lookup (no import table entries for `crypt32.dll`).

### Credential Extraction Pipeline

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│ Locate       │────►│ Decrypt      │────►│ Parse        │
│ Login Data   │     │ v10/v20 key  │     │ SQLite rows  │
│ SQLite DB    │     │ via DPAPI    │     │ (custom parser)│
└──────────────┘     └──────────────┘     └──────┬───────┘
                                                  │
                                           ┌──────▼───────┐
                                           │ Return       │
                                           │ BrowserData  │
                                           │ Result       │
                                           └──────────────┘
```

- Uses a **custom minimal SQLite parser** (no external dependency) for reading Login Data and Cookies databases
- Chrome `v10` / `v20` encrypted values are decrypted using AES-256-GCM with a DPAPI-unwrapped key
- Firefox uses NSS `logins.json` + `key4.db` with runtime DLL loading

---

## LSASS Memory Harvesting (`lsass_harvest.rs`)

Incremental LSASS memory reading via indirect syscalls — **no MiniDumpWriteDump** or disk writes:

### Architecture

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│ Open LSASS   │────►│ Enumerate    │────►│ Read memory  │
│ via NtOpen   │     │ memory       │     │ regions via  │
│ Process      │     │ regions      │     │ NtReadVirtual│
└──────────────┘     └──────────────┘     │ Memory       │
                                          └──────┬───────┘
                                                  │
┌─────────────────────────────────────────────────┘
│
┌──────▼───────────────────────────────────────────┐
│ Parse credential structures in-process:           │
│                                                   │
│ • MSV1.0 (NT hashes)                              │
│ • WDigest (plaintext passwords)                   │
│ • Kerberos (TGT/TGS tickets)                      │
│ • DPAPI master keys                               │
│ • DCC2 (domain cached credentials)                │
└──────┬───────────────────────────────────────────┘
       │
┌──────▼───────────────────────────────────────────┐
│ Return JSON with all extracted credentials         │
└──────────────────────────────────────────────────┘
```

### Build-Specific Offset Tables

| Windows Build | LSASS Version | MSV Offset | WDigest Offset | Tested |
|:-------------|:-------------|:-----------|:---------------|:------:|
| 19041 (2004) | 10.0.19041 | ✅ | ✅ | ✅ |
| 19042 (20H2) | 10.0.19042 | ✅ | ✅ | ✅ |
| 19043 (21H1) | 10.0.19043 | ✅ | ✅ | ✅ |
| 19044 (21H2) | 10.0.19044 | ✅ | ✅ | ✅ |
| 19045 (22H2) | 10.0.19045 | ✅ | ✅ | ✅ |
| 22621 (Win11 22H2) | 10.0.22621 | ✅ | ✅ | ✅ |
| 22631 (Win11 23H2) | 10.0.22631 | ✅ | ✅ | ✅ |
| 26100 (Win11 24H2) | 10.0.26100 | ✅ | ✅ | ✅ |

### OPSEC Properties

- **No file I/O**: All reading done via `NtReadVirtualMemory` syscall
- **No MiniDumpWriteDump**: Avoids the most common LSASS access indicator
- **Indirect syscalls**: LSASS handle opened via syscall gadget, not `OpenProcess`
- **Incremental**: Reads only memory regions containing credential structures

---

## LSA Whisperer — SSP Interface Credential Extraction (`lsa_whisperer.rs`)

Credential extraction via LSA SSP interfaces — **no LSASS memory reads at all**:

### Why It Bypasses Credential Guard & RunAsPPL

| Protection | What It Blocks | Why LSA Whisperer Bypasses |
|:-----------|:--------------|:--------------------------|
| Credential Guard | LSASS *process memory* reads via VBS/isolated LSA | LSA Whisperer uses the **SSP interface**, not memory reads |
| RunAsPPL | Process-level access to LSASS (`NtOpenProcess`) | No `NtReadVirtualMemory` on LSASS; responses are authorized outputs |

### Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    LSA Whisperer                              │
│                                                              │
│  Method 1: Untrusted          Method 2: SSP Inject           │
│  ┌──────────────────┐         ┌──────────────────┐           │
│  │LsaConnectUntrusted│         │LsaRegisterLogon  │           │
│  │(no admin needed) │         │Process (admin)   │           │
│  └────────┬─────────┘         └────────┬─────────┘           │
│           │                            │                     │
│  ┌────────▼────────────────────────────▼─────────┐           │
│  │    LsaCallAuthenticationPackage                │           │
│  │    (resolved from secur32.dll via pe_resolve)  │           │
│  └────────┬──────────────────────────────────────┘           │
│           │                                                   │
│  ┌────────▼──────────────────────────────────────┐           │
│  │  Authentication Package Queries               │           │
│  │                                                │           │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐      │           │
│  │  │ MSV1_0   │ │ Kerberos │ │ WDigest  │      │           │
│  │  │ EnumUsers│ │ TktCache │ │ SubAuth  │      │           │
│  │  │ SubAuth  │ │ Retrieve │ │ Query    │      │           │
│  │  └────┬─────┘ └────┬─────┘ └────┬─────┘      │           │
│  └───────┼─────────────┼────────────┼────────────┘           │
│          │             │            │                         │
│  ┌───────▼─────────────▼────────────▼────────────┐           │
│  │  Response Parsers                              │           │
│  │  • parse_msv_enum_response()                   │           │
│  │  • parse_msv_subauth_response()                │           │
│  │  • parse_kerb_tkt_cache()                      │           │
│  │  • parse_wdigest_response()                    │           │
│  │  • extract_unicode_credentials()               │           │
│  └────────┬──────────────────────────────────────┘           │
│           │                                                   │
│  ┌────────▼──────────────────────────────────────┐           │
│  │  WhisperedCredential → JSON (same format as   │           │
│  │  lsass_harvest::HarvestedCredential)          │           │
│  └────────────────────────────────────────────────┘           │
└──────────────────────────────────────────────────────────────┘
```

### Dynamic API Resolution

All LSA functions resolved at runtime via `pe_resolve` (no import table entries):

| API Function | DLL | Hash Constant |
|:------------|:----|:-------------|
| `LsaConnectUntrusted` | `secur32.dll` | `HASH_LSACONNECTUNTRUSTED` |
| `LsaCallAuthenticationPackage` | `secur32.dll` | `HASH_LSACALLAUTHENTICATIONPACKAGE` |
| `LsaLookupAuthenticationPackage` | `secur32.dll` | `HASH_LSALOOKUPAUTHENTICATIONPACKAGE` |
| `LsaRegisterLogonProcess` | `secur32.dll` | `HASH_LSAREGISTERLOGONPROCESS` |
| `LsaDeregisterLogonProcess` | `secur32.dll` | `HASH_LSADEREGISTERLOGONPROCESS` |
| `LsaFreeReturnBuffer` | `secur32.dll` | `HASH_LSAFREERETURNBUFFER` |

### Commands

| Command | Description |
|:--------|:-----------|
| `HarvestLSA { method: LsaMethod }` | Harvest credentials using specified method (`Untrusted`, `SspInject`, `Auto`) |
| `LSAWhispererStatus` | Return current status (method, credential count, SSP state) |
| `LSAWhispererStop` | Cancel in-progress operation, securely zero credential buffer |

### OPSEC Properties

- **No LSASS memory reads** — entirely API-based
- **No import table entries** — all functions resolved via `pe_resolve` hash lookup
- **All strings encrypted** — via `string_crypt::enc_str!`
- **Anti-forensic cleanup** — `whisperer_stop()` uses `write_volatile` + compiler fence
- **Untrusted method requires zero elevation**

### Configuration

```toml
[lsa-whisperer]
timeout-secs = 30        # Max harvest duration
buffer-size = 1024       # Credential ring buffer capacity
auto-inject = true       # Auto-attempt SSP injection if elevated
```

---

## Kernel Callback Overwrite — BYOVD (`kernel_callback.rs`)

Gated by `#[cfg(all(windows, feature = "kernel-callback"))]`.  Requires and
implies `direct-syscalls`.

### Purpose

Surgically overwrites EDR kernel callback function pointers to point to a `ret`
instruction instead of NULLing them.  This defeats EDR self-integrity checks
(CrowdStrike, Microsoft Defender for Endpoint) that verify their callbacks are
still registered by checking if the pointer is non-NULL.  A `ret` pointer
passes these checks (non-NULL, valid executable memory) but causes the callback
to immediately return without executing any monitoring logic.

### Why "ret, not NULL"?

| Strategy | Pointer Value | EDR Integrity Check | Result |
|----------|--------------|---------------------|--------|
| NULL overwrite | `0x0000000000000000` | `if (ptr == NULL) alert()` | **Detected** — EDR re-registers |
| **Ret overwrite** | `0xFFFFF80012345678` (ret gadget) | `if (ptr == NULL) alert()` | **Bypassed** — non-NULL, valid |
| Ret overwrite | (same) | Callback invoked | Returns immediately (`ret`) |

### Architecture

```
┌─────────────────────────────────────────────────┐
│             kernel_callback.rs (public API)       │
│  scan() · nuke() · restore() · status()          │
├─────────────────────────────────────────────────┤
│                                                   │
│  ┌──────────────┐  ┌──────────────┐              │
│  │  driver_db   │  │   deploy     │              │
│  │              │  │              │              │
│  │ 8 drivers    │  │ scan+load    │              │
│  │ top 3 embed  │  │ IOCTL r/w    │              │
│  └──────────────┘  │ cleanup      │              │
│                    └──────────────┘              │
│                                                   │
│  ┌──────────────┐  ┌──────────────┐              │
│  │  discover    │  │  overwrite   │              │
│  │              │  │              │              │
│  │ PE exports   │  │ find ret     │              │
│  │ callback walk│  │ overwrite    │              │
│  │ module ID    │  │ backup       │              │
│  └──────────────┘  │ unlink driver│              │
│                    └──────────────┘              │
│                                                   │
│  ┌──────────────────────────────────────┐        │
│  │     nt_syscall::syscall! (all NT)    │        │
│  │     string_crypt (all strings)       │        │
│  └──────────────────────────────────────┘        │
└─────────────────────────────────────────────────┘
```

### Vulnerable Driver Database

| # | Driver | Vendor | Memory Access | Status |
|---|--------|--------|--------------|--------|
| 0 | DBUtil_2_3.sys | Dell | PhysicalMemory | **Embedded** |
| 1 | rtcore64.sys | MSI Afterburner | PhysicalMemory | **Embedded** |
| 2 | gdrv.sys | Gigabyte | PhysicalMemory | **Embedded** |
| 3 | AsIO.sys | ASUS | PortIo | Scan only |
| 4 | AsIO2.sys | ASUS | PortIo | Scan only |
| 5 | ene.sys | ENE Technology | PhysicalMemory | Scan only |
| 6 | procexp152.sys | Process Explorer | PhysicalMemory | Scan only |

Top 3 drivers (indices 0–2) are XOR-obfuscated and embedded in the agent binary.  Decryption
key is derived from the HKDF session key with info `"orchestra-driver-key"`.

### Callback Types

| Kernel Symbol | Type | Walk Method | Safe to Overwrite |
|---------------|------|-------------|-------------------|
| `PspCreateProcessNotifyRoutine` | Process | Array (64 entries) | ✅ Yes |
| `PspCreateThreadNotifyRoutine` | Thread | Array (64 entries) | ✅ Yes |
| `PspLoadImageNotifyRoutine` | Image | Array (64 entries) | ✅ Yes |
| `CallbackListHead` | Object Manager | Linked list | ✅ Yes |
| `KeBugCheckCallbackListHead` | BugCheck | Linked list | ❌ **NEVER** |

### Safety Mechanisms

1. **BugCheck exclusion** — `KeBugCheckCallbackListHead` entries are never
   overwritten.  Overwriting these causes BSOD.
2. **Read-before-write** — Original pointer value is read and saved before
   overwrite.  If the read fails, the entry is skipped.
3. **Write verification** — If physical memory write fails, the entry is
   skipped (no garbage writes).
4. **Backup/restore** — All original pointers are saved in a process-local
   backup vector.  `KernelCallbackRestore` writes them back.
5. **Driver unlink** — After overwrite, the vulnerable driver is unlinked from
   `PsLoadedModuleList` (Flink/Blink manipulation) for anti-forensic cleanup.
6. **No driver unload** — The driver is not unloaded (that would zero its
   device object).  It stays loaded but unlinked.

### Runtime Commands

| Command | Description |
|---------|-------------|
| `KernelCallbackScan` | Discover and report all registered EDR callbacks |
| `KernelCallbackNuke { drivers }` | Deploy driver, overwrite callbacks with ret, save backups |
| `KernelCallbackRestore` | Restore original callback pointers from backup |

### Feature Flag

```toml
[features]
kernel-callback = ["direct-syscalls"]
```

All code is cfg-gated behind `#[cfg(all(windows, feature = "kernel-callback"))]`.

---

## Automated EDR Bypass Transformation Engine (`edr_bypass_transform.rs`)

Gated by `#[cfg(feature = "evasion-transform")]`.  Requires and implies
`self-reencode`.

### Purpose

Scans the agent's own compiled `.text` section for byte signatures known to
be detected by EDR products (YARA rules, entropy heuristics, known gadget
chains).  When a detected pattern is found, applies semantic-preserving
transformations at runtime to break the signature without changing program
behavior.

This module **supplements** the existing `self_reencode` pipeline — it handles
**pattern avoidance** before and after morphing.  Self-reencoding handles
runtime `.text` morphing; this module handles **signature evasion**.

### Relationship to Self-Reencoding

```
┌─────────────────────────────────────────────────────┐
│                 Agent Main Loop                      │
│                                                      │
│  ┌──────────────────┐   ┌──────────────────────┐    │
│  │  self_reencode   │   │ edr_bypass_transform  │    │
│  │                  │   │                       │    │
│  │ Runtime morphing │   │ Signature avoidance   │    │
│  │ of .text section │   │ of .text section      │    │
│  │                  │   │                       │    │
│  │ Changes bytes    │   │ Changes specific      │    │
│  │ to evade entropy │   │ patterns to break     │    │
│  │ scanners         │   │ YARA/sig rules        │    │
│  └──────────────────┘   └──────────────────────┘    │
│           ↑                         ↑                 │
│           │    find_text_section()   │                 │
│           └─────────┬───────────────┘                 │
│                     │                                 │
│              .text section                            │
│              (shared target)                          │
└─────────────────────────────────────────────────────┘
```

### Signature Database

9 byte patterns known to be detected by EDR:

| # | Name | Pattern | Severity |
|---|------|---------|----------|
| 0 | `direct_syscall_stub_prologue` | `4C 8B D1 B8` | high |
| 1 | `syscall_instruction` | `0F 05` | high |
| 2 | `ret_after_syscall` | `0F 05 C3` | high |
| 3 | `indirect_syscall_via_r10` | `41 FF E2` | medium |
| 4 | `xor_eax_eax_ret` | `31 C0 C3` | medium |
| 5 | `mov_r10_rcx_mov_eax` | `4C 8B D1 B8` | high |
| 6 | `ntcreatefile_pattern` | `B8 55 00 00 00` | low |
| 7 | `push_pop_shellcode_init` | `50 48 31 C0` | medium |
| 8 | `virtual_alloc_stub` | `48 89 C8 48 C1` | low |

### Transformation Passes

```
┌──────────────────────────────────────────────────────────┐
│                    Transformation Pipeline                │
│                                                          │
│  1. Instruction Substitution                             │
│     xor rax,rax → sub rax,rax                            │
│                                                          │
│  2. Register Reassignment (DISABLED)                     │
│     Requires full data-flow analysis to be safe          │
│                                                          │
│  3. NOP Sled Insertion                                   │
│     Insert semantic NOPs after RET instructions           │
│     (xchg rax,rax · mov rdi,rdi · lea rsp,[rsp+0])       │
│                                                          │
│  4. Constant Splitting (XOR-encoded)                     │
│     mov rax,imm64 → mov rcx,(imm^key); xor rcx,key;      │
│     xchg rax,rcx  (random 32-bit key per hit)            │
│                                                          │
│  5. Register Swap (rax↔rcx) — fallback for #4            │
│     mov rax,imm64 → mov rcx,imm64 + xchg rax,rcx         │
│                                                          │
│  6. Jump Obfuscation                                     │
│     Short jmp (EB XX) → Long jmp (E9 XXXXXXXX) + NOPs    │
│                                                          │
│  7. Indirect Call Obfuscation                            │
│     call [rip+disp32] → lea r15,[rip+disp32]; call r15    │
│                                                          │
│  ┌─────────────────────────────────────────────┐         │
│  │         Syscall Exclusion Zone              │         │
│  │  ±32 bytes around every `syscall` (0F 05)  │         │
│  │  No transformations applied in this zone    │         │
│  └─────────────────────────────────────────────┘         │
└──────────────────────────────────────────────────────────┘
```

### Safety Mechanisms

1. **Syscall stub exclusion zone** — ±32 bytes around every `syscall` (0F 05)
   instruction.  No transformations applied within this zone.
2. **Shannon entropy filtering** — Regions above the configurable entropy
   threshold (default 6.8) are skipped (already appear random).
3. **SHA-256 hash verification** — Hash computed before/after each cycle to
   confirm transformations were applied.
4. **Page protection management** — `NtProtectVirtualMemory` (direct syscall)
   makes `.text` writable, restores original protection after.  Instruction
   cache flushed via `NtFlushInstructionCache`.
5. **No `self_reencode` modification** — Uses `self_reencode::find_text_section()`
   for safe `.text` discovery but does not modify `self_reencode` logic.
6. **XChaCha20 memory guard intact** — Transformations happen on decrypted
   `.text` only; the existing memory encryption guard is not touched.
7. **Same-size transformations preferred** — Most transformations are same-size
   replacements to avoid shifting subsequent code.

### Semantic NOP Table

7 semantic-equivalent NOP instructions used for sled insertion:

| Bytes | Instruction | Length |
|-------|-------------|--------|
| `48 90` | `xchg rax, rax` | 2 |
| `48 89 FF` | `mov rdi, rdi` | 3 |
| `48 8D 24 24` | `lea rsp, [rsp+0]` | 4 |
| `48 87 DB` | `xchg rbx, rbx` | 3 |
| `0F 1F 44 00 00` | `nop dword [rax+rax]` | 5 |
| `48 8D 65 00` | `lea rbp, [rbp+0]` | 4 |
| `48 89 ED` | `mov rbp, rbp` | 3 |

### Config

```toml
[evasion.auto_transform]
enabled = true
scan_interval_secs = 300
max_transforms_per_cycle = 12
entropy_threshold = 6.8
```

### Runtime Commands

| Command | Description |
|---------|-------------|
| `EvasionTransformScan` | Scan `.text` for EDR signatures, return JSON array of `SignatureHit` |
| `EvasionTransformRun` | Run one scan-and-transform cycle, return JSON summary |

### Public API

```rust
// Run one full scan-and-transform cycle
pub fn run_edr_bypass_transform(
    max_transforms: u32,
    entropy_threshold: f64,
) -> Result<TransformCycleResult>

// Scan for signatures without transforming
pub fn scan_for_signatures() -> Result<Vec<SignatureHit>>

// Status query
pub fn status() -> String
```

### Feature Flag

```toml
[features]
evasion-transform = ["self-reencode"]
```

---

## NTFS Transaction-Based Process Hollowing (`injection_transacted.rs`)

Gated by `#[cfg(all(windows, feature = "transacted-hollowing"))]`.  Requires and
implies `direct-syscalls`.

### Purpose

Performs process hollowing without leaving any file artifacts on disk by using
NTFS transactions.  Creates a section backed by an NTFS transaction, maps it
into the target process, then rolls back the transaction.  The section mapping
persists in the target process even though the file never existed on disk.
Additionally blinds ETW in the target process by patching `EtwEventWrite` with
a `RET` instruction and emitting fake events with spoofed provider GUIDs.

### Attack Flow

```
  create_transaction()
       │
  create_transacted_section(SEC_COMMIT)
       │
  write_payload_to_section(local RW map + memcpy)
       │
  create_suspended_process(CREATE_SUSPENDED)
       │
  patch_remote_etw(target EtwEventWrite → 0xC3)
       │
  emit_fake_etw_events(Defender/AMSI/Sysmon GUIDs)
       │
  map_section_to_target(remote RX)
       │
  redirect_thread(SetThreadContext → new RIP)
       │
  rollback_transaction()   ← File gone from disk
       │
  restore_remote_etw(original byte)
       │
  resume_thread()
```

### NTFS Transaction Details

The NTFS transaction mechanism is the core innovation:

1. **`NtCreateTransaction`** — Creates a kernel transaction manager object.
   SSN not in bootstrap table, so resolved at runtime with fallback to
   `RtlCreateTransaction` via kernel32 ordinal.
2. **`NtCreateSection(SEC_COMMIT)`** — Section is backed by the transaction's
   pagefile. No permanent file mapping is created.
3. **`NtRollbackTransaction`** — Rolls back the transaction. All file
   operations within the transaction are undone. But the section mapping
   in the target process survives because the memory manager holds a
   reference to the section object independently of the transaction.

### Remote ETW Blinding

The agent patches `EtwEventWrite` in the **target** process (not the agent's
own process), which is different from the local ETW patching in `etw_patch.rs`:

1. **Find remote ntdll** — Uses shared ASLR base (ntdll loads at the same
   virtual address in all processes).
2. **Walk remote PE exports** — `NtReadVirtualMemory` reads the target's
   ntdll DOS/PE/Export headers to resolve `EtwEventWrite` address.
3. **Patch** — `NtWriteVirtualMemory` writes `0xC3` (RET) to the first byte.
4. **Fake events** — Emits 5 spoofed ETW events with Windows Defender, AMSI,
   and Sysmon provider GUIDs.
5. **Restore** — Original byte restored after thread resume.

### Configuration

```toml
[transacted-hollowing]
enabled = true
prefer-over-hollowing = true    # Rank above standard ProcessHollow
etw-blinding = true             # Patch EtwEventWrite in target
rollback-timeout-ms = 5000      # Timeout for NtRollbackTransaction
```

### Runtime Command

```
Command::TransactedHollow { target_process, payload, etw_blinding }
```

Returns JSON: `{ pid, base_addr, technique, payload_size }`.

### Feature Flag

```toml
[features]
transacted-hollowing = ["direct-syscalls"]
```

---

## Delayed Module-Stomp Injection (`injection_delayed_stomp.rs`)

Two-phase module stomping that defeats EDR timing heuristics by waiting
for the initial-scan window to pass before overwriting the sacrificial
DLL's `.text` section.

### Why Delayed?

Many EDR products record DLL load times and flag modules whose code changes
within a short window after `LoadLibrary` returns.  The delayed stomp waits
8–15 seconds (configurable) — well beyond the typical 1–3 second scan
window — so the `.text` modification blends into normal background memory
activity.

### Two-Phase Design

```
Phase 1 (immediate)          Phase 2 (after delay)
┌─────────────────┐          ┌─────────────────────┐
│ 1. OpenProcess   │          │ 4. Find .text VA    │
│ 2. EnumModules   │          │ 5. Stomp .text      │
│ 3. LoadLibraryA  │   ──►    │    (NtWriteVM)      │
│    (remote thread)│  delay   │ 6. Fix relocations  │
│    into target    │  8-15s   │    (if PE payload)  │
│                  │          │ 7. Execute payload   │
│ Returns JSON     │          │    (NtCreateThreadEx)│
│ immediately      │          └─────────────────────┘
└─────────────────┘
```

Phase 1 returns immediately. Phase 2 runs in a background thread
(`delayed-stomp-phase2`), leaving the agent's main task loop unblocked.

### Sacrificial DLL Selection

1. Walks the target PEB via `NtQueryInformationProcess` to enumerate
   loaded modules.
2. Iterates a curated list of ~30 candidate DLLs (version.dll, dwmapi.dll,
   msctf.dll, uxtheme.dll, netprofm.dll, etc.).
3. Skips any DLL already loaded in the target or on the built-in exclusion
   list (ntdll, kernel32, amsi, ws2_32, wininet, etc.).
4. Loads the selected DLL via `LoadLibraryA` called in a remote thread.

### PE Relocation Fixups

If the payload is a PE (detected by `MZ` signature):
- Parses the base relocation directory from the original payload buffer.
- Calculates delta: `actual_base - preferred_image_base`.
- Applies `IMAGE_REL_BASED_DIR64` (8-byte) and `IMAGE_REL_BASED_HIGHLOW`
  (4-byte) fixups via `NtReadVirtualMemory` + `NtWriteVirtualMemory`.
- Entry point is set to `dll_base + payload_entry_rva`.

For raw shellcode, entry point is the start of the `.text` section.

### Payload State Encryption

The `PendingStomp` struct (target PID, DLL base, payload ciphertext, delay)
is zeroed on drop via `write_volatile` + compiler fence.  Integration with
`memory_guard` encrypts the payload buffer when the agent sleeps.

### Auto-Selection Ranking

`DelayedModuleStomp` is ranked **above** standard `ModuleStomp` in all four
`auto_select_techniques()` branches when the feature is enabled:

```
WTH > ContextOnly > SectionMapping > NtSetInfoProcess > CallbackInjection >
  [TransactedHollowing] > ProcessHollow > DelayedModuleStomp > ModuleStomp > ...
```

### Configuration

```toml
[delayed-stomp]
enabled = true
min-delay-secs = 8
max-delay-secs = 15
prefer-over-stomp = true
sacrificial-dlls = ["version.dll", "dwmapi.dll", "msctf.dll"]
```

### Runtime Command

```
Command::DelayedStomp { target_pid, payload, delay_secs }
```

Returns JSON: `{ status, target_pid, dll_name, dll_base, delay_secs, message }`.

### Feature Flag

```toml
[features]
delayed-stomp = ["direct-syscalls"]
```

---

## Surveillance Module (`surveillance.rs`)

Screenshot capture, keylogger, and clipboard monitoring. Gated by `#[cfg(feature = "surveillance")]`.

### Capabilities

| Capability | API | Storage |
|------------|-----|---------|
| **Screenshot** | Multi-monitor via Win32 API | PNG bytes, returned inline |
| **Keylogger** | `SetWindowsHookEx(WH_KEYBOARD_LL)` | Encrypted ring buffer (ChaCha20-Poly1305) |
| **Clipboard** | `OpenClipboard` + `GetClipboardData` | Encrypted ring buffer |

### Encrypted Ring Buffer

All captured data is stored in encrypted ring buffers:

```
┌─────────────────────────────────────────────────┐
│ RingBuffer<T>                                    │
│                                                  │
│ ┌─────────┐  head ──►  ┌─────────┐              │
│ │ Entry 0 │            │ Entry N │  ◄── tail    │
│ └────┬────┘            └────┬────┘              │
│      │                      │                    │
│  ┌───▼──────────────────────▼───┐                │
│  │ Encrypted with ChaCha20-     │                │
│  │ Poly1305 (per-buffer key)    │                │
│  └──────────────────────────────┘                │
│                                                  │
│ Max: configurable entries, auto-wrap             │
└─────────────────────────────────────────────────┘
```

### Keylogger Lifecycle

1. `KeyloggerStart` — Install `WH_KEYBOARD_LL` hook via `SetWindowsHookExW`
2. Hook callback records keystrokes to encrypted ring buffer
3. `KeyloggerDump` — Return buffered keystrokes (cleared after dump)
4. `KeyloggerStop` — `UnhookWindowsHookEx`, zero and free buffer

### Command Matrix

| Command | Action |
|---------|--------|
| `Screenshot` | Capture all monitors, return PNG bytes |
| `KeyloggerStart` | Install keyboard hook |
| `KeyloggerDump` | Return captured keystrokes |
| `KeyloggerStop` | Remove hook, free buffer |
| `ClipboardMonitorStart` | Begin periodic clipboard monitoring |
| `ClipboardMonitorDump` | Return captured clipboard data |
| `ClipboardMonitorStop` | Stop monitoring, free buffer |
| `ClipboardGet` | One-shot clipboard read |

---

## Interactive Shell Sessions (`interactive_shell.rs`)

Full interactive PTY/shell sessions with background reader threads:

### Session Lifecycle

```
┌──────────┐     ┌──────────────┐     ┌──────────────┐
│ Create   │────►│ Reader       │────►│ ShellOutput  │
│ Shell    │     │ Thread       │     │ (async msg)  │
│ (cmd/    │     │ (background) │     │              │
│  sh/zsh) │     └──────┬───────┘     └──────────────┘
└──────────┘            │
                  ┌─────▼──────┐
                  │ ShellInput │
                  │ (operator) │
                  └────────────┘
```

### Supported Shells

| Platform | Default Shell | Custom Shell |
|----------|--------------|--------------|
| Windows | `cmd.exe` | Configurable path |
| Linux | `/bin/sh` | `/bin/zsh`, `/bin/bash`, custom |
| macOS | `/bin/sh` | `/bin/zsh`, `/bin/bash`, custom |

### Commands

| Command | Direction | Purpose |
|---------|-----------|---------|
| `CreateShell` | Server → Agent | Spawn new shell session |
| `ShellInput` | Server → Agent | Send text to shell stdin |
| `ShellClose` | Server → Agent | Terminate shell session |
| `ShellList` | Server → Agent | List all active sessions |
| `ShellResize` | Server → Agent | Change PTY dimensions |

### Async Output

Shell output is delivered asynchronously via `Message::ShellOutput`:

```rust
pub struct ShellOutput {
    pub session_id: String,
    pub stream: ShellStream,   // Stdout or Stderr
    pub data: Vec<u8>,
}
```

### Sleep Obfuscation Integration

Shell reader threads are **paused** during sleep obfuscation via:
- `pause_all_readers()` — Called before sleep encryption begins
- `resume_all_readers()` — Called after wake decryption completes

This prevents data corruption when the agent's memory is encrypted during sleep.

---

## Sleep Obfuscation — NTDLL Hook Re-check

After waking from sleep obfuscation, the agent performs a post-wake hook detection:

**Step 12** (added to the sleep obfuscation pipeline):

```
... Step 11 (restore thread contexts) ...
       │
┌──────▼──────────────┐
│ Post-wake ntdll     │
│ hook re-check       │
│ maybe_unhook()      │
└──────┬──────────────┘
       │ Hooks detected?
┌──────▼──────────────┐
│ Yes → Full .text    │
│ re-fetch from       │
│ \KnownDlls          │
└──────┬──────────────┘
       │
┌──────▼──────────────┐
│ Continue normal     │
│ operation           │
└─────────────────────┘
```

This is critical because EDR products may hook ntdll syscall stubs **while the agent is dormant** during sleep obfuscation. Without this check, the agent would wake up and immediately use hooked stubs.

---

---

## IAT Hygiene Architecture

The agent avoids import table entries for all security-sensitive APIs. No `LoadLibrary` / `GetProcAddress` calls appear in the import table. Instead, all API resolution uses the `pe_resolve` crate with compile-time hash constants.

### `pe_resolve` Crate

A `#![no_std]` crate providing PE export resolution by hash. No external dependencies.

**Hash algorithm**: Case-insensitive rotational hash — rotate-right 13 bits, XOR in each byte. Build-time seed ensures per-build unique hash values.

```
hash = SEED
for each byte b in name:
    hash = hash.rotate_right(13) ^ to_lowercase(b)
```

| Function | Purpose |
|----------|---------|
| `hash_str(bytes: &[u8]) -> u32` | Hash UTF-8 DLL export name |
| `hash_wstr(bytes: &[u16]) -> u32` | Hash UTF-16 module name from PEB |
| `get_module_handle_by_hash(hash) -> Option<usize>` | PEB InMemoryOrderModuleList walk |
| `get_proc_address_by_hash(base, hash) -> Option<usize>` | PE export directory name/ordinal lookup |
| Forwarded export resolution | Follows `NTDLL.RtlNtStatusToDosError`-style forwarders up to 8 levels deep |
| Address-range validation | Rejects stale RVAs outside `SizeOfImage` bounds |

### Compile-Time Hash Utilities (`pe_resolve_macros.rs`)

`const fn` mirrors of the runtime hash algorithms, enabling compile-time hash constants:

```rust
pub const fn hash_str_const(s: &[u8]) -> u32   // mirrors pe_resolve::hash_str
pub const fn hash_wstr_const(w: &[u16]) -> u32  // mirrors pe_resolve::hash_wstr
```

### `resolve_api!` Macro

Declares a lazily-resolved function pointer in a `OnceLock` static. The PEB walk and hash lookup happen exactly once per symbol; subsequent calls return the cached pointer.

```rust
// Usage — resolves NtClose from ntdll.dll via PEB walking:
let nt_close = resolve_api!(
    NT_CLOSE,                                          // static name
    pe_resolve::hash_str(b"ntdll.dll\0"),              // DLL hash
    "NtClose",                                         // export name
    unsafe extern "system" fn(Handle) -> NTSTATUS      // signature
);
```

### `dynamic_fn!` Macro

Declares a lazily-resolved function pointer with deferred resolution. Used by `token_impersonation.rs` and other modules that need batch resolution:

```rust
// Declare:
dynamic_fn!(GET_TOKEN_INFORMATION, b"advapi32.dll\0", b"GetTokenInformation\0",
            unsafe extern "system" fn(HANDLE, DWORD, LPVOID, DWORD, *mut DWORD) -> i32);

// Resolve on first use:
let fn_ptr = resolve_fn(&GET_TOKEN_INFORMATION, b"advapi32.dll\0", b"GetTokenInformation\0");
```

### IAT-Free Modules

These agent modules resolve ALL API calls via `pe_resolve`, `resolve_api!`, or `dynamic_fn!`:

| Module | APIs Resolved |
|--------|---------------|
| `injection_engine.rs` | `NtOpenProcess`, `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtProtectVirtualMemory`, `NtCreateThreadEx`, `NtClose`, `NtFreeVirtualMemory`, `NtQueryVirtualMemory` |
| `lsass_harvest.rs` | `NtOpenProcess`, `NtReadVirtualMemory`, `NtClose` |
| `lsa_whisperer.rs` | `LsaConnectUntrusted`, `LsaCallAuthenticationPackage`, `LsaLookupAuthenticationPackage`, `LsaRegisterLogonProcess`, `LsaDeregisterLogonProcess`, `LsaFreeReturnBuffer` |
| `token_impersonation.rs` | `GetTokenInformation`, `ConvertSidToStringSidA`, `LookupAccountSidA`, `RevertToSelf`, `ConnectNamedPipe`, `CreateNamedPipeA`, `ImpersonateNamedPipeClient` |
| `kernel_callback/` | All NT API calls via `nt_syscall` |
| `edr_bypass_transform.rs` | `NtProtectVirtualMemory`, `NtFlushInstructionCache` via `nt_syscall` |
| `forensic_cleanup/` | `NtCreateFile`, `NtQueryDirectoryFile`, `NtDeleteFile`, `NtCreateSection`, `NtMapViewOfSection`, `NtFsControlFile`, `NtOpenKey`, `NtSetValueKey` |

---

## HKDF-SHA256 Key Hierarchy

HKDF-SHA256 is used throughout the codebase for key derivation. The `info` parameter ensures domain separation — the same IKM produces different output keys for different purposes.

| Context | IKM | Salt | Info | Output |
|---------|-----|------|------|--------|
| **Per-message encryption** | PSK | Random 32-byte salt per message | `"orchestra-v2"` | 32-byte AES-256-GCM key |
| **Forward secrecy session** | X25519 ECDH shared secret | `HKDF(PSK, "orchestra-fs-hkdf-salt")` | `"orchestra-forward-secret-v1"` | 32-byte session key |
| **HMAC auth key** | PSK | — | `"orchestra-hmac-auth-key"` | HMAC-SHA256 key |
| **P2P link key** | X25519 shared | `None` | `"orchestra-p2p-link-key"` | 32-byte link encryption key |
| **DLL side-load payload** | Build-time seed | `enc_str!("ORCHESTRA_HKDF_SALT")` | `"orchestra-dll-sideload"` | 32-byte XChaCha20-Poly1305 key |
| **Sleep obfuscation** | Master key | — | `"orchestra-sleep-v1"` | Sleep encryption key |
| **Sleep key rotation** | Previous key input | — | `"orchestra-key-rotate"` | New sleep key |
| **Optimizer dead-code values** | `STUB_SEED` | `None` | `index.to_le_bytes()` | 8-byte dead-code value |
| **BYOVD driver XOR key** | Session key | Session salt | `"orchestra-driver-key"` | 32-byte XOR key |

### CryptoSession

```rust
pub struct CryptoSession {
    inner: RwLock<CryptoInner>,              // AES-256-GCM cipher + key
    salt: RwLock<[u8; 32]>,                  // HKDF salt
    pre_shared_secret: Option<LockedSecret>,  // mlock + zeroize-on-drop
    op_counter: AtomicU64,                    // re-key every 10,000 ops
}

pub fn from_shared_secret(key: &[u8]) -> Self;
pub fn from_shared_secret_with_salt(key: &[u8], salt: &[u8]) -> Self;
pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8>;
pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError>;
```

**Counter-based nonces**: 4-byte random prefix + 8-byte monotonic counter. Eliminates per-message randomness dependence while guaranteeing uniqueness.

**LockedSecret**: Wraps key material with `mlock`/`VirtualLock` (prevent swapping) and `zeroize` on drop.

---

## DLL Side-Loading (`injection/dll_sideload.rs`)

Encrypted payload side-loading that masquerades as a legitimate DLL:

### Architecture

1. **Build time** (`orchestra-side-load-gen`): Generates a DLL with a legitimate-looking export table. The payload is encrypted with ChaCha20.
2. **Runtime** (`injection/dll_sideload.rs`): Agent receives the encrypted payload via `InjectSideLoad` command.
3. **Key derivation**: `HKDF-SHA256(build_seed, salt, "orchestra-dll-sideload")` → 32-byte XChaCha20-Poly1305 key.
4. **Execution**: Decrypt → `NtOpenProcess` → `NtAllocateVirtualMemory(RW)` → `NtWriteVirtualMemory` → `NtProtectVirtualMemory(RX)` → `NtCreateThreadEx`.
5. **Export forwarding**: Patches export table entries to forward to the real target DLL resolved via PEB walk.

### Runtime Command

```
Command::InjectSideLoad { pid: u32, payload: Vec<u8>, export_config: ExportConfig }
```

`ExportConfig` specifies `forward_target` DLL and named/ordinal exports to patch.

---

## Workspace Crate Overview

| Crate | Purpose |
|-------|---------|
| **agent** | Implant — multi-transport C2, sleep obfuscation, injection engine, plugin support |
| **common** | Shared protocol types, crypto (`CryptoSession`, `Message`, `Command`), config |
| **builder** | Profile-driven agent build pipeline with PE artifact diversification |
| **orchestra-server** | Control Center — axum-based management plane with malleable profile support |
| **console** | Operator CLI for direct agent connection (TCP PSK or mTLS) |
| **optimizer** | x86-64 binary diversification (NOP, scheduling, substitution, dead-code) |
| **code_transform** | x86-64 instruction-level transformation (opaque predicates, CFF, virtualization) |
| **code_transform_macro** | Attribute proc-macro for `#[code_transform]` |
| **junk_macro** | Proc-macro for compile-time junk code generation |
| **string_crypt** | Compile-time string encryption proc-macros (`encrypt_string!`, `encrypt_bytes!`) |
| **pe_resolve** | `#![no_std]` PE export resolution via API hashing (PEB walking) |
| **nt_syscall** | Direct NT syscall wrappers with SSN resolution (Halo's Gate, SSDT fallback) |
| **hollowing** | Process hollowing, module stomping, and shellcode injection primitives |
| **module_loader** | Dynamic module loading (`memfd_create` on Linux, manual PE map on Windows) |
| **launcher** | In-memory agent launcher (`memfd_create` + `execve` on Linux — no disk writes) |
| **payload-packager** | AES-256-GCM encrypted payload packaging with polymorphic mode |
| **shellcode_packager** | PE-to-shellcode converter with relocation and import resolution |
| **keygen** | Cryptographic key/certificate generation utility (AES keys, Ed25519 keypairs) |
| **redirector** | HTTP reverse proxy for C2 traffic with cover-content serving and mTLS |
| **orchestra-side-load-gen** | Side-loading DLL payload generator (standalone, minimal deps) |
| **dev-server** | Local development server for testing agent builds |

---

## See Also

- [MALLEABLE_PROFILES.md](MALLEABLE_PROFILES.md) — Exhaustive TOML profile reference
- [INJECTION_ENGINE.md](INJECTION_ENGINE.md) — Injection techniques deep-dive
- [SLEEP_OBFUSCATION.md](SLEEP_OBFUSCATION.md) — Sleep obfuscation pipeline
- [REDIRECTOR_GUIDE.md](REDIRECTOR_GUIDE.md) — Redirector deployment guide
- [OPERATOR_MANUAL.md](OPERATOR_MANUAL.md) — Operator manual
- [FEATURES.md](FEATURES.md) — Feature flag reference
- [SECURITY.md](SECURITY.md) — Threat model and hardening
- [P2P_MESH.md](P2P_MESH.md) — P2P mesh protocol and topology
- [USER_GUIDE.md](USER_GUIDE.md) — End-user getting started guide
