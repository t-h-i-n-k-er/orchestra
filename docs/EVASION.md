# Evasion Capabilities

This document provides a comprehensive reference for Orchestra's evasion subsystem, including capability matrices against common EDR products, tradeoff analyses, and decision trees for technique selection.

---

## Evasion Capability Matrix

Effectiveness ratings against major EDR/AV products. Ratings are based on technique category, not specific build configuration.

| Technique | Defender for Endpoint | CrowdStrike Falcon | Elastic Security | SentinelOne | Carbon Black |
|-----------|-----------------------|--------------------|------------------|-------------|--------------|
| **Direct Syscalls** | ✅ Full bypass | ✅ Full bypass | ✅ Full bypass | ⚠️ Partial (userland hooks only) | ✅ Full bypass |
| **Syscall Emulation** | ✅ Full bypass | ✅ Full bypass | ✅ Full bypass | ✅ Full bypass | ✅ Full bypass |
| **HWBP AMSI Bypass** | ✅ Full bypass | ✅ Full bypass | ✅ Full bypass | ✅ Full bypass | ✅ Full bypass |
| **AMSI Write-Raid** | ✅ Full bypass | ✅ Full bypass | ✅ Full bypass | ✅ Full bypass | ✅ Full bypass |
| **ETW Patching** | ✅ Full bypass | ✅ Full bypass | ⚠️ Partial (kernel ETW) | ✅ Full bypass | ✅ Full bypass |
| **NTDLL Unhooking** | ✅ Full bypass | ⚠️ Partial (re-hooks) | ✅ Full bypass | ⚠️ Partial (re-hooks) | ✅ Full bypass |
| **CET Bypass** | ✅ Compatible | ✅ Compatible | ✅ Compatible | ✅ Compatible | ✅ Compatible |
| **Stack Spoofing** | ✅ Undetected | ⚠️ Partial (stack walk) | ✅ Undetected | ⚠️ Partial (stack walk) | ✅ Undetected |
| **EDR Transform Engine** | ✅ Signature evasion | ✅ Signature evasion | ✅ Signature evasion | ✅ Signature evasion | ✅ Signature evasion |
| **Kernel Callback (BYOVD)** | ✅ Callback disabled | ✅ Callback disabled | ✅ Callback disabled | ✅ Callback disabled | ✅ Callback disabled |
| **Sleep Obfuscation (Ekko)** | ✅ Memory encrypted | ✅ Memory encrypted | ✅ Memory encrypted | ⚠️ Partial (timer detect) | ✅ Memory encrypted |
| **Sleep Obfuscation (Cronus)** | ✅ Memory encrypted | ✅ Memory encrypted | ✅ Memory encrypted | ✅ Memory encrypted | ✅ Memory encrypted |
| **Evanesco (Continuous)** | ✅ Pages NOACCESS | ✅ Pages NOACCESS | ✅ Pages NOACCESS | ✅ Pages NOACCESS | ✅ Pages NOACCESS |
| **PEB Unlinking** | ✅ Module hidden | ⚠️ Partial (VAD walk) | ✅ Module hidden | ⚠️ Partial (VAD walk) | ✅ Module hidden |
| **Token Impersonation** | ✅ Thread-level | ✅ Thread-level | ✅ Thread-level | ✅ Thread-level | ✅ Thread-level |
| **Transacted Hollowing** | ✅ Fileless | ✅ Fileless | ✅ Fileless | ✅ Fileless | ✅ Fileless |
| **Delayed Module Stomp** | ✅ Timing bypass | ✅ Timing bypass | ✅ Timing bypass | ✅ Timing bypass | ✅ Timing bypass |
| **Forensic Cleanup** | ✅ Evidence removed | ✅ Evidence removed | ✅ Evidence removed | ✅ Evidence removed | ✅ Evidence removed |

> **Legend**: ✅ = technique achieves its goal against this EDR; ⚠️ = partial success, some detection vectors remain; ❌ = technique is ineffective.

---

## AMSI Bypass Comparison

Orchestra provides three AMSI bypass strategies with different tradeoffs:

| Strategy | Mechanism | Persistence | Detection Risk | Stability |
|----------|-----------|-------------|----------------|-----------|
| **HWBP** (Hardware Breakpoints) | Sets DR6/DR7 debug register on `AmsiScanBuffer` | Process lifetime | Low — no memory modification | High — VEH handles exceptions cleanly |
| **Memory Patch** | Patches `AmsiScanBuffer` prologue to return `AMSI_RESULT_CLEAN` | Process lifetime | Medium — memory integrity checks detect | High — simple patch |
| **Write-Raid** | Data-only race on `AmsiInitFailed` flag | Transient (race window) | Very Low — no code/permission/breakpoint changes | Medium — requires precise timing |

### When to Use Each

- **HWBP** (default): Best balance of stealth and stability. No memory modification to ntdll/amsi DLLs, making integrity checks pass.
- **Memory Patch**: Fallback when HWBP is unavailable (e.g., debug registers already in use). Higher detection risk from memory scanning.
- **Write-Raid**: Most stealthy option. No code modifications at all — only races a boolean flag. Preferred for short-lived operations where maximum stealth is critical.

### AMSI Write-Raid Technical Details

The write-raid bypass exploits a data race on the `AmsiInitFailed` global boolean in `amsi.dll`:

1. A watcher thread monitors `AmsiScanBuffer` calls via hardware breakpoints
2. When an AMSI scan is detected, the thread races to set `AmsiInitFailed = TRUE`
3. `AmsiScanBuffer` reads the flag and returns `AMSI_RESULT_CLEAN` immediately
4. The flag is immediately reset to `FALSE` for the next scan

**Advantages over other approaches**:
- Zero code modifications — no `.text` section writes
- Zero permission changes — no `VirtualProtect` calls
- Zero breakpoint residue — no INT3 or DR modifications visible to scanners
- Transient — the flag is only modified during the race window

---

## CET / Shadow Stack Bypass

Intel Control-flow Enforcement Technology (CET) introduces hardware-enforced shadow stacks that validate return addresses. Orchestra provides three complementary bypass strategies:

### Strategy 1: Policy Disable
Disables CET for the current process using `SetProcessMitigationPolicy` with `ProcessShadowStackPolicy`. This completely removes shadow stack enforcement.

```
SetProcessMitigationPolicy(ProcessShadowStackPolicy)
  → Policy.Flags = PROCESS_SHADOW_STACK_ALWAYS_OFF
```

**When to use**: When the process was launched without CET enforcement (most scenarios). Fallback for older Windows builds.

### Strategy 2: CET-Compatible Call Chains
Constructs all indirect calls (syscalls, callbacks) using CET-compatible sequences that maintain valid shadow stack entries:

```
; Instead of: jmp rax  (invalidates shadow stack)
; Use: push rax; ret   (maintains shadow stack coherence)
```

All injection techniques and syscall dispatchers use this pattern when CET is detected.

### Strategy 3: VEH Shadow-Stack Fix
Registers a Vectored Exception Handler (VEH) that catches `STATUS_SHADOW_STACK_INVALID` exceptions and repairs the shadow stack:

1. VEH catches `STATUS_SHADOW_STACK_INVALID` (0xC000041D)
2. Reads the faulting return address from the trap frame
3. Writes the correct return address to the shadow stack via `RIP-relative` adjustment
4. Returns `EXCEPTION_CONTINUE_EXECUTION`

**When to use**: When other strategies fail or when CET is enforced kernel-side (e.g., Hyper-V enclave scenarios).

---

## Syscall Strategy Decision Tree

Orchestra supports three syscall dispatch strategies. The agent automatically selects the best strategy based on the threat environment:

```
                    ┌────────────────────────────┐
                    │ Is ntdll hooked by EDR?    │
                    └────────────┬───────────────┘
                                 │
                    ┌────────────▼───────────────┐
                    │  Check: read .text section  │
                    │  of ntdll for JMP/INT3      │
                    └────────────┬───────────────┘
                                 │
                    ┌──── No ────┴──── Yes ──────┐
                    │                            │
           ┌────────▼─────────┐        ┌────────▼──────────┐
           │ Standard call    │        │ Is syscall-emulation│
           │ via ntdll        │        │ feature enabled?     │
           │ (fastest path)   │        └────────┬────────────┘
           └──────────────────┘                 │
                                    ┌─── Yes ───┴─── No ────┐
                                    │                        │
                           ┌────────▼─────────┐    ┌────────▼──────────┐
                           │ Route Nt* calls   │    │ Direct syscalls    │
                           │ through kernel32  │    │ (extract SSN +     │
                           │ /advapi32 instead │    │  inline syscall)   │
                           │ of ntdll          │    │                    │
                           │ (invisible to     │    │ Dynamic SSN        │
                           │  ntdll hooks)     │    │ validation:        │
                           └──────────────────┘    │ cross-ref → probe  │
                                                   │ → SSDT fallback    │
                                                   └───────────────────┘
```

### Syscall Emulation vs Direct Syscalls

| Factor | Syscall Emulation | Direct Syscalls |
|--------|-------------------|-----------------|
| **Hook bypass** | Routes around ntdll entirely | Reads SSN, issues syscall directly |
| **ETW visibility** | Calls appear as normal Win32 API | No Win32 API frame in call stack |
| **Stack frame** | Normal kernel32/advapi32 frames | Custom stack frame (needs spoofing) |
| **Performance** | Slightly slower (extra dispatch layer) | Fastest bypass path |
| **Compatibility** | All Windows versions | SSN varies between builds |
| **Detection surface** | Low — looks like legitimate API usage | Medium — syscall from user mode without ntdll frame |
| **Feature flag** | `syscall-emulation` | `direct-syscalls` |

### Dynamic SSN Validation

When using direct syscalls, the agent validates SSNs using a three-tier approach:

1. **Cross-Reference**: Compare SSN extracted from `\KnownDlls\ntdll.dll` against the local copy
2. **Probe Validation**: Issue a benign syscall (e.g., `NtQueryInformationProcess`) to verify the SSN is correct
3. **SSDT Nuclear Fallback**: If validation fails, read the SSDT from kernel memory via BYOVD to extract authoritative SSNs

---

## Stack Spoofing

Orchestra provides two stack spoofing strategies:

### NtContinue-Based Spoofing (Original)

Uses `NtContinue` to replace the call stack with a fake chain of legitimate Windows API calls:

1. Capture current thread context
2. Construct a fake `CONTEXT` structure with crafted `RIP`, `RSP`, and `RBP`
3. Call `NtContinue(&fake_context, FALSE)` to swap to the fake stack
4. Original stack is preserved in encrypted memory for restoration

**Limitation**: On CET-enabled systems, `NtContinue` updates the shadow stack, which can be detected.

### Unwind-Aware Stack Spoofing (Cronus-Enhanced)

The upgraded spoofing technique is CET-compatible and respects unwind information:

1. Builds a synthetic call chain using only functions with valid `.pdata` (unwind) entries
2. Each frame in the chain uses a legitimate Windows API call as a "gadget"
3. The chain is constructed to pass stack-walking validation (RtlVirtualUnwind-compatible)
4. Shadow stack entries are maintained naturally by using CET-compatible call instructions

**Advantages over NtContinue approach**:
- CET/shadow-stack compatible — no `STATUS_SHADOW_STACK_INVALID` exceptions
- Passes `RtlVirtualUnwind` validation — EDR stack walkers see a normal chain
- No `NtContinue` call — avoids the suspicious API pattern entirely

### Detection Comparison

| Detection Method | NtContinue Spoofing | Unwind-Aware Spoofing |
|-----------------|--------------------|-----------------------|
| Basic stack walk | ✅ Bypassed | ✅ Bypassed |
| `RtlVirtualUnwind` | ✅ Bypassed | ✅ Bypassed |
| CET shadow stack | ❌ Detected | ✅ Bypassed |
| Frame pointer walk | ✅ Bypassed | ✅ Bypassed |
| Return address validation | ✅ Bypassed | ✅ Bypassed |
| `.pdata` consistency check | ⚠️ Partial | ✅ Bypassed |

---

## EDR Bypass Transformation Engine

The automated EDR bypass transformation engine scans agent `.text` sections at runtime and applies semantic-preserving code transformations to evade signature-based detection.

### Pipeline Flow

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│   Scan .text │───▶│  Identify    │───▶│  Apply       │───▶│  Verify      │
│   sections   │    │  signatures  │    │  transforms  │    │  integrity   │
└──────────────┘    └──────────────┘    └──────────────┘    └──────────────┘
                                               │
                                    ┌──────────┼──────────┐
                                    │          │          │
                               ┌────▼───┐ ┌────▼───┐ ┌────▼────┐
                               │Register │ │Instr   │ │Block    │
                               │Rename   │ │Swap    │ │Reorder  │
                               └────────┘ └────────┘ └─────────┘
                                    │          │          │
                               ┌────▼───┐ ┌────▼───┐ ┌────▼────┐
                               │NOP     │ │Constant│ │Junk     │
                               │Sled    │ │Fold    │ │Insert   │
                               └────────┘ └────────┘ └─────────┘
```

### Transformation Types

| Transform | Description | Semantic Preservation |
|-----------|-------------|----------------------|
| **Register Rename** | Renames general-purpose registers (`rax` ↔ `rcx`, etc.) | ✅ Preserves data flow |
| **Instruction Swap** | Swaps independent adjacent instructions | ✅ No dependencies changed |
| **Block Reorder** | Reorders basic blocks with adjusted branch targets | ✅ Control flow preserved |
| **NOP Sled Insertion** | Inserts multi-byte NOPs between instructions | ✅ No logic change |
| **Constant Folding** | Replaces compile-time constants with equivalent expressions | ✅ Same result at runtime |

### Usage

Enabled via the `evade-edr-transform` feature flag. The transformation runs:
- At agent initialization, before command dispatch begins
- After each sleep obfuscation wake cycle (post-NTDLL re-check)
- On-demand via the `edr_transform` command from the server

---

## Sleep Obfuscation Strategies

### Ekko (Event-Based)

Uses `CreateTimerQueueTimer` with a waitable timer to trigger memory encryption:

1. Creates a waitable timer
2. Sets `ROP chain` callback to encryption routine
3. All RWX/RW memory pages encrypted with XChaCha20-Poly1305
4. Pages set to `PAGE_NOACCESS`
5. Timer fires → decryption → pages restored → execution continues

### Cronus (Waitable Timer Variant)

Uses `NtSetTimer` with `NTAPI` waitable timers for a cleaner approach:

1. Creates an `NT` waitable timer object
2. Sets timer with absolute timeout and APC callback
3. Memory encrypted and set to `PAGE_READ_WRITE` (not NOACCESS — avoids Memory Allocation forensic artifacts)
4. Timer fires via APC → decryption → execution continues
5. Stack frames are encrypted separately with safety guarantees

### Evanesco (Continuous Memory Hiding)

Unlike Ekko/Cronus which only hide memory during sleep, Evanesco continuously hides memory pages:

1. All executable pages are encrypted with RC4 and set to `PAGE_NOACCESS`
2. When code needs to execute a page, it's briefly decrypted → executed → re-encrypted
3. No period of extended visibility — pages are only decrypted for microseconds
4. Makes memory scanning extremely difficult — the agent appears as a collection of `PAGE_NOACCESS` regions

| Strategy | Memory Visibility | Detection Risk | Performance Impact | Feature Flag |
|----------|-------------------|----------------|-------------------|--------------|
| **Ekko** | Hidden during sleep | Medium (timer artifacts) | Low | `sleep-obfuscation` |
| **Cronus** | Hidden during sleep | Low (NT timer) | Low | `sleep-obfuscation` |
| **Evanesco** | Hidden at all times | Very Low | Medium (page faults) | `evanesco` |

---

## Kernel Callback Overwrite (BYOVD)

Orchestra can disable EDR kernel callbacks by overwriting function pointers in kernel memory using vulnerable drivers.

### Architecture

```
┌─────────────────────────────────────────────────────┐
│                    User Mode                         │
│                                                      │
│  ┌──────────────┐    ┌──────────────────────┐       │
│  │ Select       │───▶│ Load vulnerable       │       │
│  │ target driver│    │ driver (8 available)  │       │
│  └──────────────┘    └──────────┬───────────┘       │
│                                  │                    │
│                       ┌──────────▼───────────┐       │
│                       │ Read callback table   │       │
│                       │ via driver IOCTL      │       │
│                       └──────────┬───────────┘       │
│                                  │                    │
│                       ┌──────────▼───────────┐       │
│                       │ Overwrite ret-ptr     │       │
│                       │ with null/stub        │       │
│                       └──────────────────────┘       │
└─────────────────────────────────────────────────────┘
```

### Supported Vulnerable Drivers

| Driver | Vendor | CVE | Capability |
|--------|--------|-----|------------|
| `RTCore64.sys` | MSI Afterburner | CVE-2019-16098 | Physical memory R/W |
| `DBUtil_2_3.sys` | Dell | CVE-2021-21551 | Physical memory R/W |
| `AsIO.sys` | ASUS | CVE-2021-26357 | Physical memory R/W |
| `gdrv.sys` | Gigabyte | CVE-2018-19320 | Physical memory R/W |
| `ene.sys` | ENE Technology | CVE-2021-42545 | Physical memory R/W |
| `atkex1.sys` | ASUS GPU Tweak | — | Physical memory R/W |
| `procexp152.sys` | Sysinternals | — | Physical memory R/W |
| `msio64.sys` | MSI | CVE-2019-18845 | Physical memory R/W |

### EDR Callbacks Targeted

- `ObRegisterCallbacks` — Process/thread handle protection
- `PsSetCreateProcessNotifyRoutine` — Process creation monitoring
- `PsSetCreateThreadNotifyRoutine` — Thread creation monitoring
- `PsSetLoadImageNotifyRoutine` — Image load monitoring
- `CmRegisterCallback` — Registry monitoring
- `MiniFilter callbacks` — File system monitoring

> **Warning**: BYOVD operations require Administrator privileges and may trigger driver blocklist alerts on fully patched systems. Use with caution in hardened environments.

---

## Anti-Analysis Protections

| Protection | Mechanism | Implementation |
|-----------|-----------|----------------|
| **Compile-Time String Encryption** | All strings encrypted at compile time via `string_crypt` proc-macro | ChaCha20 with per-build random keys |
| **Binary Diversification** | Junk code insertion, register renaming, instruction reordering | `junk_macro`, `optimizer`, `code_transform` crates |
| **Self-Reencoding** | Agent re-encodes its own `.text` section with unique transforms each build | `code_transform_macro` |
| **PEB Unlinking** | Removes agent module from `PEB_LDR_DATA` linked lists | Full unlink from all three lists |
| **Thread Start Address Scrub** | Replaces anomalous thread start addresses with legitimate ones | Points to common Windows entry points |
| **Handle Table Scrub** | Closes/obfuscates suspicious handles in process handle table | Removes `PAGE_EXECUTE_*` handles |
| **Memory Hygiene** | Frees temporary allocations, zeros sensitive data after use | Called after every command execution |
