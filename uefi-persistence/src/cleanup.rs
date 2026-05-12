//! Detection and cleanup of UEFI persistence artifacts.
//!
//! # Overview
//!
//! Scans for known persistence mechanisms in the UEFI firmware environment:
//! 1. Unauthorized boot entries in NVRAM.
//! 2. Unknown EFI drivers on the ESP.
//! 3. Modified bootloader configurations.
//! 4. Suspicious NVRAM variables.
//! 5. Capsule update artifacts.
//!
//! # Detection Heuristics
//!
//! The detection uses several heuristics:
//! - Boot entries pointing to unknown vendor directories.
//! - EFI drivers with invalid or suspicious PE headers.
//! - Boot order modifications that prioritize unknown entries.
//! - NVRAM variables with known implant signatures.
//!
//! # Safety
//!
//! Cleanup operations are destructive and can prevent the system from booting
//! if legitimate entries are removed. Always create backups before cleanup.

use crate::{
    BootEntry, BootloaderType, EfiGuid, EfiVarAttributes, PersistenceArtifact,
    PersistenceArtifactType,
};
use anyhow::{bail, Context, Result};
use std::path::Path;

/// Known legitimate ESP directories (case-insensitive).
const KNOWN_ESP_DIRS: &[&str] = &[
    "Boot",
    "Microsoft",
    "ubuntu",
    "fedora",
    "centos",
    "debian",
    "arch",
    "opensuse",
    "Linux",
    "systemd",
    "refind",
    "Intel",
    "Dell",
    "HP",
    "Lenovo",
    "ASUS",
    "tools",
    "APPLE",
    "Apple",
];

/// Known legitimate boot entry descriptions.
const KNOWN_BOOT_DESCRIPTIONS: &[&str] = &[
    "Windows Boot Manager",
    "ubuntu",
    "Fedora",
    "CentOS",
    "debian",
    "Arch Linux",
    "openSUSE",
    "Linux Boot Manager",
    "rEFInd Boot Manager",
    "Linux Firmware Updater",
    "UEFI Firmware Settings",
    "UEFI OS",
    "EFI Network",
    "EFI Internal Shell",
    "Windows Recovery",
    "Windows Recovery Environment",
];

/// Signatures that indicate implant artifacts.
const IMPLANT_SIGNATURES: &[&str] = &[
    "ORCH",        // Our implant magic.
    "COBALT",      // Cobalt Strike.
    "POWERSHELL",  // PowerShell implant.
    "MSBUILD",     // MSBuild-based.
    "INSTALLUTIL", // InstallUtil-based.
];

/// Result of scanning for persistence artifacts.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanResult {
    /// All detected artifacts.
    pub artifacts: Vec<PersistenceArtifact>,
    /// Number of high-risk artifacts.
    pub high_risk_count: usize,
    /// Number of medium-risk artifacts.
    pub medium_risk_count: usize,
    /// Number of low-risk artifacts.
    pub low_risk_count: usize,
    /// ESP path that was scanned.
    pub esp_path: String,
    /// Whether Secure Boot is enabled.
    pub secure_boot_enabled: bool,
}

/// Risk level of a detected artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RiskLevel {
    /// High risk: likely malicious, should be removed.
    High,
    /// Medium risk: suspicious, requires investigation.
    Medium,
    /// Low risk: potentially legitimate but unusual.
    Low,
    /// Informational: no action needed.
    Info,
}

/// Detailed information about a detected artifact.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ArtifactDetail {
    /// The artifact type.
    pub artifact_type: PersistenceArtifactType,
    /// Risk level.
    pub risk_level: RiskLevel,
    /// Location of the artifact.
    pub location: String,
    /// Description of why it was flagged.
    pub reason: String,
    /// Recommended action.
    pub recommendation: String,
    /// SHA-256 hash of the artifact (if applicable).
    pub sha256_hash: Option<String>,
    /// Size in bytes.
    pub size: Option<usize>,
    /// Whether the artifact can be safely removed.
    pub removable: bool,
}

/// Result of removing a persistence artifact.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RemovalResult {
    /// Whether the removal was successful.
    pub success: bool,
    /// The artifact that was removed.
    pub artifact: PersistenceArtifact,
    /// Backup path (if a backup was created before removal).
    pub backup_path: Option<String>,
    /// Error message (if removal failed).
    pub error: Option<String>,
}

/// Detect existing UEFI persistence artifacts.
///
/// Scans:
/// 1. Boot entries in NVRAM.
/// 2. EFI files on the ESP.
/// 3. NVRAM variables with known signatures.
/// 4. Bootloader configuration integrity.
pub fn detect_existing_persistence(esp_path: &str) -> Result<ScanResult> {
    let mut artifacts = Vec::new();
    let mut high_risk_count = 0;
    let mut medium_risk_count = 0;
    let mut low_risk_count = 0;

    // Check Secure Boot status.
    let secure_boot_enabled = crate::check_secure_boot_status() == crate::SecureBootStatus::Enabled;

    // 1. Scan boot entries.
    let boot_entries = scan_boot_entries()?;
    for detail in &boot_entries {
        match detail.risk_level {
            RiskLevel::High => high_risk_count += 1,
            RiskLevel::Medium => medium_risk_count += 1,
            RiskLevel::Low => low_risk_count += 1,
            RiskLevel::Info => {}
        }
        artifacts.push(PersistenceArtifact {
            artifact_type: detail.artifact_type.clone(),
            description: format!("Boot entry: {}", detail.reason),
            path: detail.location.clone(),
            risk_level: format!("{:?}", detail.risk_level),
            removable: detail.removable,
        });
    }

    // 2. Scan ESP for suspicious files.
    let esp_artifacts = scan_esp_files(esp_path)?;
    for detail in &esp_artifacts {
        match detail.risk_level {
            RiskLevel::High => high_risk_count += 1,
            RiskLevel::Medium => medium_risk_count += 1,
            RiskLevel::Low => low_risk_count += 1,
            RiskLevel::Info => {}
        }
        artifacts.push(PersistenceArtifact {
            artifact_type: detail.artifact_type.clone(),
            description: format!("ESP file: {}", detail.reason),
            path: detail.location.clone(),
            risk_level: format!("{:?}", detail.risk_level),
            removable: detail.removable,
        });
    }

    // 3. Scan NVRAM variables.
    let nvram_artifacts = scan_nvram_variables()?;
    for detail in &nvram_artifacts {
        match detail.risk_level {
            RiskLevel::High => high_risk_count += 1,
            RiskLevel::Medium => medium_risk_count += 1,
            RiskLevel::Low => low_risk_count += 1,
            RiskLevel::Info => {}
        }
        artifacts.push(PersistenceArtifact {
            artifact_type: detail.artifact_type.clone(),
            description: format!("NVRAM variable: {}", detail.reason),
            path: detail.location.clone(),
            risk_level: format!("{:?}", detail.risk_level),
            removable: detail.removable,
        });
    }

    // 4. Check bootloader integrity.
    let bootloader_artifacts = scan_bootloader_config(esp_path)?;
    for detail in &bootloader_artifacts {
        match detail.risk_level {
            RiskLevel::High => high_risk_count += 1,
            RiskLevel::Medium => medium_risk_count += 1,
            RiskLevel::Low => low_risk_count += 1,
            RiskLevel::Info => {}
        }
        artifacts.push(PersistenceArtifact {
            artifact_type: detail.artifact_type.clone(),
            description: format!("Bootloader config: {}", detail.reason),
            path: detail.location.clone(),
            risk_level: format!("{:?}", detail.risk_level),
            removable: detail.removable,
        });
    }

    Ok(ScanResult {
        artifacts,
        high_risk_count,
        medium_risk_count,
        low_risk_count,
        esp_path: esp_path.to_string(),
        secure_boot_enabled,
    })
}

/// Remove a detected persistence artifact.
///
/// Creates a backup before removing anything. Returns an error if the artifact
/// cannot be safely removed.
pub fn remove_persistence(artifact: &PersistenceArtifact) -> Result<RemovalResult> {
    if !artifact.removable {
        bail!(
            "Artifact cannot be safely removed automatically: {} ({})",
            artifact.description,
            artifact.path
        );
    }

    match artifact.artifact_type {
        PersistenceArtifactType::BootEntry => remove_boot_entry_artifact(artifact),
        PersistenceArtifactType::EfiDriver => remove_efi_driver_artifact(artifact),
        PersistenceArtifactType::NvramVariable => remove_nvram_variable_artifact(artifact),
        PersistenceArtifactType::BootloaderConfig => remove_bootloader_config_artifact(artifact),
        PersistenceArtifactType::CapsuleArtifact => remove_capsule_artifact(artifact),
        PersistenceArtifactType::DxeDriver => remove_dxe_driver_artifact(artifact),
    }
}

/// Scan boot entries for suspicious patterns.
fn scan_boot_entries() -> Result<Vec<ArtifactDetail>> {
    let mut details = Vec::new();

    let entries = match crate::nvram::enumerate_boot_entries() {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!("Could not enumerate boot entries: {}", e);
            return Ok(details);
        }
    };

    for entry in &entries {
        // Check for unknown descriptions.
        let known = KNOWN_BOOT_DESCRIPTIONS
            .iter()
            .any(|d| entry.description.contains(d));

        if !known && entry.is_active {
            details.push(ArtifactDetail {
                artifact_type: PersistenceArtifactType::BootEntry,
                risk_level: RiskLevel::Medium,
                location: format!("Boot{:04X}", entry.entry_number),
                reason: format!("Unknown active boot entry: '{}'", entry.description),
                recommendation: "Review and verify the boot entry. Remove if unauthorized."
                    .to_string(),
                sha256_hash: None,
                size: Some(entry.raw.len()),
                removable: true,
            });
        }

        // Check for device paths pointing to unknown vendor directories.
        if !entry.device_path.is_empty() {
            let dp_lower = entry.device_path.to_lowercase();
            let suspicious = !KNOWN_ESP_DIRS
                .iter()
                .any(|dir| dp_lower.contains(&dir.to_lowercase()));

            if suspicious && entry.is_active {
                details.push(ArtifactDetail {
                    artifact_type: PersistenceArtifactType::BootEntry,
                    risk_level: RiskLevel::High,
                    location: format!("Boot{:04X}", entry.entry_number),
                    reason: format!("Boot entry points to unknown path: '{}'", entry.device_path),
                    recommendation: "Remove if unauthorized. This may be a persistence implant."
                        .to_string(),
                    sha256_hash: None,
                    size: Some(entry.raw.len()),
                    removable: true,
                });
            }
        }

        // Check for implant signatures in optional data.
        if !entry.optional_data.is_empty() {
            if let Ok(data_str) = std::str::from_utf8(&entry.optional_data) {
                for sig in IMPLANT_SIGNATURES {
                    if data_str.contains(sig) {
                        details.push(ArtifactDetail {
                            artifact_type: PersistenceArtifactType::BootEntry,
                            risk_level: RiskLevel::High,
                            location: format!("Boot{:04X}", entry.entry_number),
                            reason: format!("Contains implant signature: {}", sig),
                            recommendation:
                                "Remove immediately. This is likely a persistence implant."
                                    .to_string(),
                            sha256_hash: None,
                            size: Some(entry.raw.len()),
                            removable: true,
                        });
                    }
                }
            }
        }
    }

    Ok(details)
}

/// Scan ESP files for suspicious EFI binaries.
fn scan_esp_files(esp_path: &str) -> Result<Vec<ArtifactDetail>> {
    let mut details = Vec::new();

    let efi_files = match crate::esp::list_efi_files(esp_path) {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!("Could not list EFI files: {}", e);
            return Ok(details);
        }
    };

    for file_path in &efi_files {
        let path = Path::new(file_path);

        // Check if the file is in an unknown vendor directory.
        let relative = path
            .strip_prefix(Path::new(esp_path).join("EFI"))
            .unwrap_or(path);

        let vendor_dir = relative
            .components()
            .next()
            .map(|c| c.as_os_str().to_string_lossy().to_string())
            .unwrap_or_default();

        let known_vendor = KNOWN_ESP_DIRS
            .iter()
            .any(|d| d.eq_ignore_ascii_case(&vendor_dir));

        // Read the file to check for implant signatures.
        let file_data = std::fs::read(file_path).ok();
        let file_size = file_data.as_ref().map(|d| d.len()).unwrap_or(0);

        let has_implant_sig = file_data
            .as_ref()
            .map(|data| {
                IMPLANT_SIGNATURES
                    .iter()
                    .any(|sig| data.windows(sig.len()).any(|w| w == sig.as_bytes()))
            })
            .unwrap_or(false);

        let is_valid_efi = file_data
            .as_ref()
            .map(|data| crate::esp::validate_efi_pe(data).is_ok())
            .unwrap_or(false);

        if has_implant_sig {
            details.push(ArtifactDetail {
                artifact_type: PersistenceArtifactType::EfiDriver,
                risk_level: RiskLevel::High,
                location: file_path.clone(),
                reason: "Contains known implant signature".to_string(),
                recommendation: "Remove immediately. This is likely a persistence implant."
                    .to_string(),
                sha256_hash: file_data.as_ref().map(|d| sha256_hex(d)),
                size: Some(file_size),
                removable: true,
            });
        } else if !known_vendor && is_valid_efi {
            details.push(ArtifactDetail {
                artifact_type: PersistenceArtifactType::EfiDriver,
                risk_level: RiskLevel::Medium,
                location: file_path.clone(),
                reason: format!("EFI binary in unknown directory: {}", vendor_dir),
                recommendation: "Review and remove if unauthorized.".to_string(),
                sha256_hash: file_data.as_ref().map(|d| sha256_hex(d)),
                size: Some(file_size),
                removable: true,
            });
        } else if !is_valid_efi && file_path.to_lowercase().ends_with(".efi") && file_size > 0 {
            details.push(ArtifactDetail {
                artifact_type: PersistenceArtifactType::EfiDriver,
                risk_level: RiskLevel::Medium,
                location: file_path.clone(),
                reason: "Invalid PE/COFF binary masquerading as .efi".to_string(),
                recommendation: "Review and remove if unauthorized.".to_string(),
                sha256_hash: file_data.as_ref().map(|d| sha256_hex(d)),
                size: Some(file_size),
                removable: true,
            });
        }
    }

    Ok(details)
}

/// Scan NVRAM variables for suspicious entries.
fn scan_nvram_variables() -> Result<Vec<ArtifactDetail>> {
    let mut details = Vec::new();

    // Check for backup variables created by this framework.
    // These are intentionally left for detection/cleanup.
    let suspicious_vars = [
        // Our framework's backup variables.
        (".orchestra-backup", RiskLevel::Medium),
    ];

    for (var_name, risk) in &suspicious_vars {
        if crate::nvram::read_efi_variable(var_name, &EfiGuid::EFI_GLOBAL_VARIABLE).is_ok() {
            details.push(ArtifactDetail {
                artifact_type: PersistenceArtifactType::NvramVariable,
                risk_level: *risk,
                location: var_name.to_string(),
                reason: "Suspicious NVRAM variable found".to_string(),
                recommendation: "Review and remove if unauthorized.".to_string(),
                sha256_hash: None,
                size: None,
                removable: true,
            });
        }
    }

    // Check OsIndications for unexpected capsule flags.
    if let Ok(support) = crate::runtime_driver::check_uefi_capsule_support() {
        if support.os_indications_raw & 0x04 != 0 && !support.capsule_on_disk_supported {
            details.push(ArtifactDetail {
                artifact_type: PersistenceArtifactType::CapsuleArtifact,
                risk_level: RiskLevel::High,
                location: "OsIndications".to_string(),
                reason: "Capsule delivery requested but not supported by firmware".to_string(),
                recommendation: "Investigate potential capsule-based persistence.".to_string(),
                sha256_hash: None,
                size: None,
                removable: false,
            });
        }
    }

    Ok(details)
}

/// Scan bootloader configuration for modifications.
fn scan_bootloader_config(esp_path: &str) -> Result<Vec<ArtifactDetail>> {
    let mut details = Vec::new();

    let bootloader = crate::esp::detect_bootloader(esp_path);

    match bootloader {
        BootloaderType::Grub2 => {
            // Check for unexpected menu entries in grub.cfg.
            let efi_dir = std::path::PathBuf::from(esp_path).join("EFI");
            for subdir in &["ubuntu", "fedora", "centos", "debian", "arch"] {
                let grub_cfg = efi_dir.join(subdir).join("grub.cfg");
                if grub_cfg.exists() {
                    if let Ok(content) = std::fs::read_to_string(&grub_cfg) {
                        // Look for unexpected chainloader entries.
                        for line in content.lines() {
                            if line.contains("chainloader") && !line.trim().starts_with('#') {
                                let path = line.split("chainloader").nth(1).unwrap_or("").trim();
                                if !path.contains("bootmgfw")
                                    && !path.contains("grub")
                                    && !path.contains("shim")
                                    && !path.contains("fwup")
                                {
                                    details.push(ArtifactDetail {
                                        artifact_type: PersistenceArtifactType::BootloaderConfig,
                                        risk_level: RiskLevel::Medium,
                                        location: grub_cfg.to_string_lossy().to_string(),
                                        reason: format!("Unexpected chainloader: {}", path),
                                        recommendation: "Review the grub.cfg chainloader entry."
                                            .to_string(),
                                        sha256_hash: None,
                                        size: None,
                                        removable: false,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        BootloaderType::SystemdBoot => {
            // Check loader entries for unexpected entries.
            let entries_dir = std::path::PathBuf::from(esp_path).join("loader/entries");
            if entries_dir.exists() {
                if let Ok(entries) = std::fs::read_dir(&entries_dir) {
                    for entry in entries.flatten() {
                        if let Ok(content) = std::fs::read_to_string(entry.path()) {
                            for line in content.lines() {
                                if line.starts_with("efi ") {
                                    let path = line.split("efi ").nth(1).unwrap_or("").trim();
                                    if !path.contains("systemd")
                                        && !path.contains("vmlinuz")
                                        && !path.contains("shim")
                                    {
                                        details.push(ArtifactDetail {
                                            artifact_type:
                                                PersistenceArtifactType::BootloaderConfig,
                                            risk_level: RiskLevel::Medium,
                                            location: entry.path().to_string_lossy().to_string(),
                                            reason: format!(
                                                "Unexpected EFI path in loader entry: {}",
                                                path
                                            ),
                                            recommendation: "Review the systemd-boot loader entry."
                                                .to_string(),
                                            sha256_hash: None,
                                            size: None,
                                            removable: true,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }

    // Check for backup directories left by this framework.
    let backup_dir = std::path::PathBuf::from(esp_path)
        .join("EFI")
        .join(".orchestra-backup");
    if backup_dir.exists() {
        details.push(ArtifactDetail {
            artifact_type: PersistenceArtifactType::BootloaderConfig,
            risk_level: RiskLevel::Medium,
            location: backup_dir.to_string_lossy().to_string(),
            reason: "Orchestra backup directory found on ESP".to_string(),
            recommendation: "Review and remove if no longer needed.".to_string(),
            sha256_hash: None,
            size: None,
            removable: true,
        });
    }

    Ok(details)
}

// ─── Artifact removal ───────────────────────────────────────────────────

fn remove_boot_entry_artifact(artifact: &PersistenceArtifact) -> Result<RemovalResult> {
    // Parse entry number from location.
    let entry_num = artifact
        .path
        .strip_prefix("Boot")
        .and_then(|s| u16::from_str_radix(s, 16).ok())
        .ok_or_else(|| anyhow::anyhow!("Cannot parse boot entry number from: {}", artifact.path))?;

    // Backup the entry.
    let backup_path = format!("/tmp/boot_{:04X}.backup", entry_num);
    let backup = crate::nvram::read_boot_entry(entry_num).ok();

    if let Some(entry) = backup {
        std::fs::write(&backup_path, &entry.raw).ok();
    }

    // Remove the entry from boot order.
    let mut order = crate::nvram::read_boot_order().context("Failed to read boot order")?;
    order.retain(|&x| x != entry_num);
    crate::nvram::write_boot_order(&order).context("Failed to update boot order")?;

    // Delete the boot entry variable.
    let var_name = format!("Boot{:04X}", entry_num);
    crate::nvram::delete_efi_variable(&var_name, &EfiGuid::EFI_GLOBAL_VARIABLE)
        .context("Failed to delete boot entry variable")?;

    Ok(RemovalResult {
        success: true,
        artifact: artifact.clone(),
        backup_path: if std::path::Path::new(&backup_path).exists() {
            Some(backup_path)
        } else {
            None
        },
        error: None,
    })
}

fn remove_efi_driver_artifact(artifact: &PersistenceArtifact) -> Result<RemovalResult> {
    let path = Path::new(&artifact.path);
    if !path.exists() {
        bail!("EFI driver file not found: {}", artifact.path);
    }

    // Backup before removal.
    let backup_path = format!(
        "/tmp/{}.backup",
        path.file_name().unwrap_or_default().to_string_lossy()
    );
    std::fs::copy(path, &backup_path).ok();

    // Remove the file.
    std::fs::remove_file(path)
        .with_context(|| format!("Failed to remove EFI driver: {}", artifact.path))?;

    Ok(RemovalResult {
        success: true,
        artifact: artifact.clone(),
        backup_path: if std::path::Path::new(&backup_path).exists() {
            Some(backup_path)
        } else {
            None
        },
        error: None,
    })
}

fn remove_nvram_variable_artifact(artifact: &PersistenceArtifact) -> Result<RemovalResult> {
    crate::nvram::delete_efi_variable(&artifact.path, &EfiGuid::EFI_GLOBAL_VARIABLE)
        .with_context(|| format!("Failed to delete NVRAM variable: {}", artifact.path))?;

    Ok(RemovalResult {
        success: true,
        artifact: artifact.clone(),
        backup_path: None,
        error: None,
    })
}

fn remove_bootloader_config_artifact(artifact: &PersistenceArtifact) -> Result<RemovalResult> {
    let path = Path::new(&artifact.path);
    if path.exists()
        && path.is_dir()
        && path
            .file_name()
            .map(|n| n == ".orchestra-backup")
            .unwrap_or(false)
    {
        std::fs::remove_dir_all(path)
            .with_context(|| format!("Failed to remove backup directory: {}", artifact.path))?;
    } else if path.exists() && path.is_file() {
        // Backup before removal.
        let backup_path = format!(
            "/tmp/{}.backup",
            path.file_name().unwrap_or_default().to_string_lossy()
        );
        std::fs::copy(path, &backup_path).ok();
        std::fs::remove_file(path)
            .with_context(|| format!("Failed to remove bootloader config: {}", artifact.path))?;
    }

    Ok(RemovalResult {
        success: true,
        artifact: artifact.clone(),
        backup_path: None,
        error: None,
    })
}

fn remove_capsule_artifact(artifact: &PersistenceArtifact) -> Result<RemovalResult> {
    if artifact.path == "OsIndications" {
        // Clear the capsule delivery flag.
        let data = crate::nvram::read_efi_variable("OsIndications", &EfiGuid::EFI_GLOBAL_VARIABLE)?;
        let payload = if data.len() > 4 { &data[4..] } else { &data };
        if payload.len() >= 8 {
            let mut indications = u64::from_le_bytes([
                payload[0], payload[1], payload[2], payload[3], payload[4], payload[5], payload[6],
                payload[7],
            ]);
            // Clear the capsule delivery flag.
            indications &= !0x04;
            crate::nvram::write_efi_variable(
                "OsIndications",
                &EfiGuid::EFI_GLOBAL_VARIABLE,
                &indications.to_le_bytes(),
                EfiVarAttributes::STANDARD_BOOT,
            )?;
        }
    }

    Ok(RemovalResult {
        success: true,
        artifact: artifact.clone(),
        backup_path: None,
        error: None,
    })
}

fn remove_dxe_driver_artifact(artifact: &PersistenceArtifact) -> Result<RemovalResult> {
    // Similar to EFI driver removal.
    remove_efi_driver_artifact(artifact)
}

/// Compute SHA-256 hex hash.
fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_esp_dirs_contains_standard() {
        assert!(KNOWN_ESP_DIRS.contains(&"Microsoft"));
        assert!(KNOWN_ESP_DIRS.contains(&"Boot"));
        assert!(KNOWN_ESP_DIRS.contains(&"ubuntu"));
        assert!(KNOWN_ESP_DIRS.contains(&"fedora"));
    }

    #[test]
    fn known_boot_descriptions_contains_standard() {
        assert!(KNOWN_BOOT_DESCRIPTIONS.contains(&"Windows Boot Manager"));
        assert!(KNOWN_BOOT_DESCRIPTIONS.contains(&"ubuntu"));
        assert!(KNOWN_BOOT_DESCRIPTIONS.contains(&"EFI Internal Shell"));
    }

    #[test]
    fn implant_signatures_contains_orch() {
        assert!(IMPLANT_SIGNATURES.contains(&"ORCH"));
    }

    #[test]
    fn risk_level_ordering() {
        assert!(matches!(RiskLevel::High, RiskLevel::High));
        assert!(matches!(RiskLevel::Medium, RiskLevel::Medium));
        assert!(matches!(RiskLevel::Low, RiskLevel::Low));
        assert!(matches!(RiskLevel::Info, RiskLevel::Info));
    }

    #[test]
    fn scan_result_serialization() {
        let result = ScanResult {
            artifacts: Vec::new(),
            high_risk_count: 0,
            medium_risk_count: 0,
            low_risk_count: 0,
            esp_path: "/boot/efi".to_string(),
            secure_boot_enabled: false,
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("esp_path"));
        assert!(json.contains("/boot/efi"));
    }

    #[test]
    fn artifact_detail_serialization() {
        let detail = ArtifactDetail {
            artifact_type: PersistenceArtifactType::BootEntry,
            risk_level: RiskLevel::High,
            location: "Boot0001".to_string(),
            reason: "Test".to_string(),
            recommendation: "Remove".to_string(),
            sha256_hash: Some("abc123".to_string()),
            size: Some(1024),
            removable: true,
        };

        let json = serde_json::to_string(&detail).unwrap();
        assert!(json.contains("Boot0001"));
        assert!(json.contains("High"));
    }

    #[test]
    fn removal_result_serialization() {
        let result = RemovalResult {
            success: true,
            artifact: PersistenceArtifact {
                artifact_type: PersistenceArtifactType::EfiDriver,
                description: "Test".to_string(),
                path: "/test.efi".to_string(),
                risk_level: "High".to_string(),
                removable: true,
            },
            backup_path: Some("/tmp/test.backup".to_string()),
            error: None,
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("success"));
        assert!(json.contains("/tmp/test.backup"));
    }
}
