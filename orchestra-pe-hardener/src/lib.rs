//! Orchestra PE Hardener — standalone PE post-processing library.
//!
//! Provides a high-level API for applying hardening transformations to Windows
//! PE/PE+ binaries.  Operations include timestamp randomization, Rich header
//! synthesis, section name randomization, DOS stub replacement, signature
//! stripping, debug directory cleanup, overlay removal, and entropy padding.
//!
//! # Quick Start
//!
//! ```ignore
//! use orchestra_pe_hardener::{harden_default, HardenOptions, harden};
//!
//! let mut pe_bytes = std::fs::read("payload.exe")?;
//!
//! // Apply all default hardening operations:
//! harden_default(&mut pe_bytes);
//!
//! // Or use fine-grained control:
//! let opts = HardenOptions {
//!     randomize_timestamp: true,
//!     remove_rich_header: true,
//!     randomize_section_names: true,
//!     replace_dos_stub: true,
//!     strip_overlay: true,
//!     strip_signature: true,
//!     strip_debug_directory: true,
//!     replace_pdb_path: true,
//!     add_entropy_padding: true,
//!     ..Default::default()
//! };
//! harden(&mut pe_bytes, &opts);
//! ```
//!
//! Individual low-level operations are also re-exported for direct use.

use anyhow::Result;
use serde::{Deserialize, Serialize};

// ── Re-export low-level operations from pe_artifact_kit ──────────────────────

pub use builder::pe_artifact_kit::{
    add_entropy_padding, inject_icon, inject_manifest, inject_version_info,
    randomize_section_names, randomize_timestamp, recalculate_checksum, remove_rich_header,
    replace_dos_stub, replace_pdb_path, strip_debug_directory, strip_overlay, strip_signature,
    zero_timestamp,
};

// ── Re-export configuration types ────────────────────────────────────────────

pub use builder::config::VersionInfoConfig;

// ── High-level API ───────────────────────────────────────────────────────────

/// Selective hardening options.
///
/// Each field controls whether the corresponding transformation is applied.
/// All fields default to `true` for maximum hardening.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HardenOptions {
    /// Randomize the COFF TimeDateStamp to a plausible date.
    pub randomize_timestamp: bool,
    /// Remove the real Rich header and inject a synthetic one mimicking VS 2019.
    pub remove_rich_header: bool,
    /// Replace section names with random alphabetic strings.
    pub randomize_section_names: bool,
    /// Replace the DOS stub ("This program cannot be run in DOS mode") with random bytes.
    pub replace_dos_stub: bool,
    /// Truncate overlay/appended data beyond the last section.
    pub strip_overlay: bool,
    /// Zero the certificate table and its data-directory entry.
    pub strip_signature: bool,
    /// Zero the debug directory (removes PDB path references).
    pub strip_debug_directory: bool,
    /// Replace CODEVIEW PDB paths with plausible system DLL paths.
    pub replace_pdb_path: bool,
    /// Append 1–4 KiB of random entropy padding.
    pub add_entropy_padding: bool,
    /// Recalculate the PE checksum after all other operations.
    pub recalculate_checksum: bool,
}

impl Default for HardenOptions {
    fn default() -> Self {
        Self {
            randomize_timestamp: true,
            remove_rich_header: true,
            randomize_section_names: true,
            replace_dos_stub: true,
            strip_overlay: true,
            strip_signature: true,
            strip_debug_directory: true,
            replace_pdb_path: true,
            add_entropy_padding: true,
            recalculate_checksum: true,
        }
    }
}

/// Summary of what was applied during hardening.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HardeningResult {
    /// Number of operations that were applied.
    pub operations_applied: usize,
    /// Total number of operations available.
    pub operations_total: usize,
    /// Size of the PE buffer before hardening.
    pub size_before: usize,
    /// Size of the PE buffer after hardening.
    pub size_after: usize,
}

impl HardeningResult {
    /// Returns `true` if the PE data starts with the `MZ` magic bytes.
    pub fn is_pe(data: &[u8]) -> bool {
        data.len() >= 2 && &data[0..2] == b"MZ"
    }
}

/// Apply selective hardening operations to a PE binary in memory.
///
/// Only operations enabled in `opts` are applied.  The PE checksum is
/// recalculated last if `opts.recalculate_checksum` is true.
///
/// # Returns
///
/// A [`HardeningResult`] describing what was done and the size change.
pub fn harden(buf: &mut Vec<u8>, opts: &HardenOptions) -> HardeningResult {
    let size_before = buf.len();
    let mut applied = 0usize;
    const TOTAL: usize = 10;

    // Bail early for non-PE data.
    if !HardeningResult::is_pe(buf) {
        tracing::warn!("pe-hardener: data does not start with MZ — all operations skipped");
        return HardeningResult {
            operations_applied: 0,
            operations_total: TOTAL,
            size_before,
            size_after: buf.len(),
        };
    }

    // 1. Strip overlay (must come first — truncates the buffer).
    if opts.strip_overlay {
        strip_overlay(buf);
        applied += 1;
    }

    // 2. Replace DOS stub.
    if opts.replace_dos_stub {
        replace_dos_stub(buf);
        applied += 1;
    }

    // 3. Randomize timestamp.
    if opts.randomize_timestamp {
        randomize_timestamp(buf);
        applied += 1;
    }

    // 4. Remove / replace Rich header.
    if opts.remove_rich_header {
        remove_rich_header(buf);
        applied += 1;
    }

    // 5. Replace PDB path (before stripping debug dir).
    if opts.replace_pdb_path {
        replace_pdb_path(buf);
        applied += 1;
    }

    // 6. Strip debug directory.
    if opts.strip_debug_directory {
        strip_debug_directory(buf);
        applied += 1;
    }

    // 7. Strip signature.
    if opts.strip_signature {
        strip_signature(buf);
        applied += 1;
    }

    // 8. Randomize section names.
    if opts.randomize_section_names {
        randomize_section_names(buf);
        applied += 1;
    }

    // 9. Add entropy padding (grows the buffer).
    if opts.add_entropy_padding {
        add_entropy_padding(buf);
        applied += 1;
    }

    // 10. Recalculate checksum (must come last).
    if opts.recalculate_checksum {
        recalculate_checksum(buf);
        applied += 1;
    }

    HardeningResult {
        operations_applied: applied,
        operations_total: TOTAL,
        size_before,
        size_after: buf.len(),
    }
}

/// Apply the full default suite of hardening operations to a PE binary.
///
/// Equivalent to `harden(buf, &HardenOptions::default())`.
///
/// # Returns
///
/// A [`HardeningResult`] describing what was done.
pub fn harden_default(buf: &mut Vec<u8>) -> HardeningResult {
    harden(buf, &HardenOptions::default())
}

/// Apply hardening plus optional resource injection (version info, icon, manifest).
///
/// This is the most comprehensive entry point, combining structural hardening
/// with optional Windows resource injection.
pub fn harden_with_resources(
    buf: &mut Vec<u8>,
    opts: &HardenOptions,
    version_info: Option<&VersionInfoConfig>,
    icon_path: Option<&str>,
    manifest_preset: Option<&str>,
) -> Result<HardeningResult> {
    // Apply structural hardening first.
    let result = harden(buf, opts);

    // Inject version info resource (if requested).
    if let Some(vi) = version_info {
        inject_version_info(buf, vi)?;
    }

    // Inject icon resource (if requested).
    if let Some(ico) = icon_path {
        inject_icon(buf, ico)?;
    }

    // Inject manifest resource (if requested).
    if let Some(m) = manifest_preset {
        inject_manifest(buf, m)?;
    }

    // Always recalculate checksum after resource injection.
    recalculate_checksum(buf);

    Ok(result)
}
