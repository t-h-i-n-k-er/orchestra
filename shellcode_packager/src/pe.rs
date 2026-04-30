//! Minimal PE32+ parser — extracts sections, relocations, and imports needed
//! for shellcode packaging.
//!
//! We intentionally avoid pulling in a full PE parsing crate to keep the
//! dependency tree small and because we only need a handful of structures.

use anyhow::{anyhow, Context, Result};

// ── PE header constants ──────────────────────────────────────────────────────

const DOS_MAGIC: u16 = 0x5A4D; // "MZ"
const NT_SIGNATURE: u32 = 0x0000_4550; // "PE\0\0"
const OPT_MAGIC_PE32_PLUS: u16 = 0x020B;
const OPT_MAGIC_PE32: u16 = 0x010B;

const IMAGE_REL_BASED_DIR64: u16 = 10;
const IMAGE_REL_BASED_HIGHLOW: u16 = 3;
const IMAGE_REL_BASED_ABSOLUTE: u16 = 0; // padding, skip

// ── Parsed PE structures ─────────────────────────────────────────────────────

/// A single PE section header.
#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_size: u32,
    pub raw_offset: u32,
    pub characteristics: u32,
}

/// A single import DLL entry.
#[derive(Debug, Clone)]
pub struct ImportDll {
    pub dll_name: String,
    /// (name or ordinal, thunk_rva) pairs.
    pub functions: Vec<ImportFunc>,
}

/// A single imported function.
#[derive(Debug, Clone)]
pub enum ImportFunc {
    ByName { name: String, thunk_rva: u32 },
    ByOrdinal { ordinal: u16, thunk_rva: u32 },
}

/// A single relocation entry.
#[derive(Debug, Clone)]
pub struct Relocation {
    /// RVA of the relocation (within the PE image).
    pub rva: u32,
    /// Relocation type (IMAGE_REL_BASED_DIR64, HIGHLOW, etc.)
    pub rel_type: u16,
}

/// Parsed PE image containing everything needed for shellcode packaging.
#[derive(Debug, Clone)]
pub struct PeImage {
    /// Raw PE bytes.
    pub raw: Vec<u8>,
    /// Image base address from optional header.
    pub image_base: u64,
    /// Size of the image as mapped in memory.
    pub image_size: u32,
    /// RVA of the entry point.
    pub entry_point_rva: u32,
    /// Section alignment.
    pub section_alignment: u32,
    /// File alignment.
    pub file_alignment: u32,
    /// Size of headers (rounded up to file_alignment).
    pub size_of_headers: u32,
    /// Parsed section headers.
    pub sections: Vec<Section>,
    /// Parsed relocation entries.
    pub relocations: Vec<Relocation>,
    /// Parsed import descriptors.
    pub imports: Vec<ImportDll>,
    /// Data directory RVAs and sizes (index 0..16).
    pub data_directories: Vec<(u32, u32)>,
    /// Whether this is PE32 (false) or PE32+ (true).
    pub is_pe64: bool,
}

impl PeImage {
    /// Parse a PE binary from raw bytes.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 64 {
            return Err(anyhow!("input too small for a PE file"));
        }

        // DOS header
        let dos_magic = u16_from_le(data, 0);
        if dos_magic != DOS_MAGIC {
            return Err(anyhow!("not a valid PE file: bad DOS magic (got 0x{dos_magic:04X})"));
        }
        let e_lfanew = u32_from_le(data, 60) as usize;

        // NT signature
        if data.len() < e_lfanew + 4 {
            return Err(anyhow!("PE headers truncated"));
        }
        let nt_sig = u32_from_le(data, e_lfanew);
        if nt_sig != NT_SIGNATURE {
            return Err(anyhow!("bad NT signature (got 0x{nt_sig:08X})"));
        }

        // COFF header (20 bytes starting at e_lfanew+4)
        let coff_offset = e_lfanew + 4;
        let _machine = u16_from_le(data, coff_offset);
        let num_sections = u16_from_le(data, coff_offset + 2) as usize;
        let optional_header_size = u16_from_le(data, coff_offset + 16) as usize;

        // Optional header
        let opt_offset = coff_offset + 20;
        let opt_magic = u16_from_le(data, opt_offset);
        let is_pe64 = match opt_magic {
            OPT_MAGIC_PE32_PLUS => true,
            OPT_MAGIC_PE32 => false,
            _ => return Err(anyhow!("unsupported optional header magic: 0x{opt_magic:04X}")),
        };

        let (image_base, entry_point_rva, image_size, section_alignment, file_alignment,
             size_of_headers, num_data_dirs) = if is_pe64 {
            // PE32+ layout
            let entry = u32_from_le(data, opt_offset + 16);
            let image_base = u64_from_le(data, opt_offset + 24);
            let section_align = u32_from_le(data, opt_offset + 32);
            let file_align = u32_from_le(data, opt_offset + 36);
            let image_sz = u32_from_le(data, opt_offset + 56);
            let headers_sz = u32_from_le(data, opt_offset + 60);
            let num_dd = u32_from_le(data, opt_offset + 108) as usize;
            (image_base, entry, image_sz, section_align, file_align, headers_sz, num_dd)
        } else {
            // PE32 layout
            let entry = u32_from_le(data, opt_offset + 16);
            let image_base = u64_from(u32_from_le(data, opt_offset + 28));
            let section_align = u32_from_le(data, opt_offset + 32);
            let file_align = u32_from_le(data, opt_offset + 36);
            let image_sz = u32_from_le(data, opt_offset + 56);
            let headers_sz = u32_from_le(data, opt_offset + 60);
            let num_dd = u32_from_le(data, opt_offset + 92) as usize;
            (image_base, entry, image_sz, section_align, file_align, headers_sz, num_dd)
        };

        // Data directories
        let dd_offset = if is_pe64 {
            opt_offset + 112
        } else {
            opt_offset + 96
        };
        let num_data_dirs = num_data_dirs.min(16);
        let mut data_directories = Vec::with_capacity(num_data_dirs);
        for i in 0..num_data_dirs {
            let off = dd_offset + i * 8;
            let rva = u32_from_le(data, off);
            let size = u32_from_le(data, off + 4);
            data_directories.push((rva, size));
        }

        // Section headers
        let sections_offset = opt_offset + optional_header_size;
        let mut sections = Vec::with_capacity(num_sections);
        for i in 0..num_sections {
            let sec_off = sections_offset + i * 40;
            if sec_off + 40 > data.len() {
                return Err(anyhow!("section header {i} truncated"));
            }
            let name_bytes = &data[sec_off..sec_off + 8];
            let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
            let name = String::from_utf8_lossy(&name_bytes[..name_end]).into_owned();
            sections.push(Section {
                name,
                virtual_size: u32_from_le(data, sec_off + 8),
                virtual_address: u32_from_le(data, sec_off + 12),
                raw_size: u32_from_le(data, sec_off + 16),
                raw_offset: u32_from_le(data, sec_off + 20),
                characteristics: u32_from_le(data, sec_off + 36),
            });
        }

        // Parse relocations (data directory index 5 = IMAGE_DIRECTORY_ENTRY_BASERELOC)
        let relocations = parse_relocations(data, &data_directories, &sections)
            .context("failed to parse relocations")?;

        // Parse imports (data directory index 1 = IMAGE_DIRECTORY_ENTRY_IMPORT)
        let imports = parse_imports(data, &data_directories, is_pe64)
            .context("failed to parse imports")?;

        Ok(Self {
            raw: data.to_vec(),
            image_base,
            image_size,
            entry_point_rva,
            section_alignment,
            file_alignment,
            size_of_headers,
            sections,
            relocations,
            imports,
            data_directories,
            is_pe64,
        })
    }

    /// Return the image mapped into a contiguous buffer of `image_size` bytes,
    /// with each section placed at its virtual address and zero-fill between.
    pub fn mapped_image(&self) -> Vec<u8> {
        let mut buf = vec![0u8; self.image_size as usize];
        // Copy headers
        let header_len = self.size_of_headers.min(self.raw.len() as u32) as usize;
        buf[..header_len].copy_from_slice(&self.raw[..header_len]);
        // Copy sections
        for sec in &self.sections {
            let vstart = sec.virtual_address as usize;
            let copy_len = sec.raw_size as usize;
            if copy_len == 0 || vstart >= buf.len() {
                continue;
            }
            let src_end = (sec.raw_offset as usize + copy_len).min(self.raw.len());
            let src = &self.raw[sec.raw_offset as usize..src_end];
            let dst_end = (vstart + src.len()).min(buf.len());
            buf[vstart..dst_end].copy_from_slice(src);
        }
        buf
    }
}

// ── Relocation parsing ───────────────────────────────────────────────────────

fn parse_relocations(
    data: &[u8],
    data_dirs: &[(u32, u32)],
    _sections: &[Section],
) -> Result<Vec<Relocation>> {
    // Data directory index 5 = BASE RELOC
    let (reloc_rva, reloc_size) = data_dirs.get(5).copied().unwrap_or((0, 0));
    if reloc_rva == 0 || reloc_size == 0 {
        return Ok(Vec::new());
    }

    let reloc_off = rva_to_offset(data, reloc_rva).ok_or_else(|| {
        anyhow!("cannot resolve relocation directory RVA 0x{reloc_rva:08X}")
    })?;

    let mut relocs = Vec::new();
    let mut pos = reloc_off as usize;
    let end = (reloc_off as usize + reloc_size as usize).min(data.len());

    while pos + 8 <= end {
        let block_rva = u32_from_le(data, pos);
        let block_size = u32_from_le(data, pos + 4) as usize;
        if block_size < 8 {
            break;
        }
        let block_end = (pos + block_size).min(end);
        let mut entry_pos = pos + 8;
        while entry_pos + 2 <= block_end {
            let entry = u16_from_le(data, entry_pos);
            let rel_type = entry >> 12;
            let offset = entry & 0x0FFF;
            match rel_type {
                IMAGE_REL_BASED_DIR64 | IMAGE_REL_BASED_HIGHLOW => {
                    relocs.push(Relocation {
                        rva: block_rva + offset as u32,
                        rel_type,
                    });
                }
                IMAGE_REL_BASED_ABSOLUTE => { /* padding */ }
                _ => {
                    tracing::debug!(
                        "skipping unknown relocation type {rel_type} at RVA 0x{:08X}",
                        block_rva + offset as u32
                    );
                }
            }
            entry_pos += 2;
        }
        pos += block_size;
    }

    Ok(relocs)
}

// ── Import parsing ───────────────────────────────────────────────────────────

fn parse_imports(
    data: &[u8],
    data_dirs: &[(u32, u32)],
    is_pe64: bool,
) -> Result<Vec<ImportDll>> {
    // Data directory index 1 = IMPORT
    let (import_rva, import_size) = data_dirs.get(1).copied().unwrap_or((0, 0));
    if import_rva == 0 || import_size == 0 {
        return Ok(Vec::new());
    }

    let import_off = rva_to_offset(data, import_rva).ok_or_else(|| {
        anyhow!("cannot resolve import directory RVA 0x{import_rva:08X}")
    })?;

    let mut dlls = Vec::new();
    let mut desc_pos = import_off as usize;
    // Each IMAGE_IMPORT_DESCRIPTOR is 20 bytes; the last is all-zeros.
    loop {
        if desc_pos + 20 > data.len() {
            break;
        }
        let ilt_rva = u32_from_le(data, desc_pos); // OriginalFirstThunk
        let _timestamp = u32_from_le(data, desc_pos + 4);
        let _forwarder = u32_from_le(data, desc_pos + 8);
        let name_rva = u32_from_le(data, desc_pos + 12);
        let iat_rva = u32_from_le(data, desc_pos + 16); // FirstThunk

        // Terminating descriptor: all zeros
        if ilt_rva == 0 && name_rva == 0 && iat_rva == 0 {
            break;
        }

        // Read DLL name (null-terminated ASCII)
        let dll_name = read_cstring(data, name_rva).unwrap_or_else(|| "UNKNOWN".to_string());

        // Walk the ILT (or IAT if ILT is 0)
        let thunk_rva = if ilt_rva != 0 { ilt_rva } else { iat_rva };
        let mut functions = Vec::new();
        let thunk_size = if is_pe64 { 8usize } else { 4 };
        let mut thunk_pos = match rva_to_offset(data, thunk_rva) {
            Some(off) => off as usize,
            None => {
                tracing::warn!("cannot resolve ILT RVA 0x{thunk_rva:08X} for {dll_name}");
                desc_pos += 20;
                continue;
            }
        };

        loop {
            if thunk_pos + thunk_size > data.len() {
                break;
            }
            let thunk_val = if is_pe64 {
                u64_from_le(data, thunk_pos)
            } else {
                u64_from(u32_from_le(data, thunk_pos))
            };

            // Terminating entry
            if thunk_val == 0 {
                break;
            }

            // Calculate the IAT slot RVA for this function
            let iat_slot_rva = iat_rva + ((thunk_pos - rva_to_offset(data, thunk_rva).unwrap() as usize) as u32);

            // Check ordinal flag (bit 63 for PE64, bit 31 for PE32)
            let ordinal_flag = if is_pe64 { 1u64 << 63 } else { 1u64 << 31 };
            if thunk_val & ordinal_flag != 0 {
                let ordinal = (thunk_val & 0xFFFF) as u16;
                functions.push(ImportFunc::ByOrdinal { ordinal, thunk_rva: iat_slot_rva });
            } else {
                let hint_name_rva = (thunk_val & 0x7FFFFFFF) as u32;
                let name = read_cstring_at_rva(data, hint_name_rva.wrapping_add(2))
                    .unwrap_or_else(|| format!("ord_{}", thunk_val & 0xFFFF));
                functions.push(ImportFunc::ByName { name, thunk_rva: iat_slot_rva });
            }

            thunk_pos += thunk_size;
        }

        dlls.push(ImportDll {
            dll_name,
            functions,
        });
        desc_pos += 20;
    }

    Ok(dlls)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn u16_from_le(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

fn u32_from_le(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

fn u64_from_le(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
    ])
}

fn u64_from(v: u32) -> u64 {
    v as u64
}

/// Convert an RVA to a file offset using the PE section table.
fn rva_to_offset(data: &[u8], rva: u32) -> Option<u32> {
    // Quick path: re-parse sections to find which one contains the RVA.
    if data.len() < 64 {
        return None;
    }
    let e_lfanew = u32_from_le(data, 60) as usize;
    let coff_offset = e_lfanew + 4;
    let num_sections = u16_from_le(data, coff_offset + 2) as usize;
    let opt_hdr_size = u16_from_le(data, coff_offset + 16) as usize;
    let sections_offset = coff_offset + 20 + opt_hdr_size;

    for i in 0..num_sections {
        let sec_off = sections_offset + i * 40;
        if sec_off + 40 > data.len() {
            break;
        }
        let va = u32_from_le(data, sec_off + 12);
        let raw_sz = u32_from_le(data, sec_off + 16);
        let raw_off = u32_from_le(data, sec_off + 20);
        let virtual_sz = u32_from_le(data, sec_off + 8);
        let sec_end = va + virtual_sz.max(raw_sz);
        if rva >= va && rva < sec_end {
            let delta = rva - va;
            if delta < raw_sz {
                return Some(raw_off + delta);
            }
            // Within virtual size but not in raw data — headers or zero-fill
            return None;
        }
    }

    // Might be in the headers
    if rva < u32_from_le(data, coff_offset + 20 + 60) {
        Some(rva)
    } else {
        None
    }
}

/// Read a null-terminated ASCII string at the given RVA.
fn read_cstring_at_rva(data: &[u8], rva: u32) -> Option<String> {
    let off = rva_to_offset(data, rva)? as usize;
    let mut end = off;
    while end < data.len() && data[end] != 0 {
        end += 1;
    }
    Some(String::from_utf8_lossy(&data[off..end]).into_owned())
}

/// Read a null-terminated ASCII string from the data at a given RVA.
fn read_cstring(data: &[u8], rva: u32) -> Option<String> {
    read_cstring_at_rva(data, rva)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal PE32+ image in memory for testing.
    fn minimal_pe64() -> Vec<u8> {
        let mut pe = Vec::new();

        // DOS header (64 bytes)
        pe.extend_from_slice(b"MZ"); // e_magic
        pe.extend(&[0u8; 58]); // rest of DOS header
        pe.extend_from_slice(&64u32.to_le_bytes()); // e_lfanew at offset 60

        // PE signature
        pe.extend_from_slice(b"PE\0\0");

        // COFF header (20 bytes)
        pe.extend_from_slice(&0x8664u16.to_le_bytes()); // Machine: AMD64
        pe.extend_from_slice(&0u16.to_le_bytes());      // NumberOfSections
        pe.extend_from_slice(&0u32.to_le_bytes());      // TimeDateStamp
        pe.extend_from_slice(&0u32.to_le_bytes());      // PointerToSymbolTable
        pe.extend_from_slice(&0u32.to_le_bytes());      // NumberOfSymbols
        pe.extend_from_slice(&240u16.to_le_bytes());    // SizeOfOptionalHeader
        pe.extend_from_slice(&0x0022u16.to_le_bytes()); // Characteristics

        // Optional header PE32+ (240 bytes)
        pe.extend_from_slice(&0x020Bu16.to_le_bytes()); // Magic: PE32+
        pe.push(14); // MajorLinkerVersion
        pe.push(0);  // MinorLinkerVersion
        pe.extend(&[0u8; 232]); // Pad rest of optional header with zeros
        // Fill in key fields at their offsets:
        // DOS header: 64 bytes, PE sig: 4 bytes, COFF header: 20 bytes
        // opt_offset = 64 + 4 + 20 = 88
        let opt_start = 88;
        // AddressOfEntryPoint at opt+16
        let off = opt_start + 16;
        if off + 4 <= pe.len() { pe[off..off+4].copy_from_slice(&0x1000u32.to_le_bytes()); }
        // ImageBase at opt+24
        let off = opt_start + 24;
        if off + 8 <= pe.len() { pe[off..off+8].copy_from_slice(&0x140000000u64.to_le_bytes()); }
        // SectionAlignment at opt+32
        let off = opt_start + 32;
        if off + 4 <= pe.len() { pe[off..off+4].copy_from_slice(&0x1000u32.to_le_bytes()); }
        // FileAlignment at opt+36
        let off = opt_start + 36;
        if off + 4 <= pe.len() { pe[off..off+4].copy_from_slice(&0x200u32.to_le_bytes()); }
        // SizeOfImage at opt+56
        let off = opt_start + 56;
        if off + 4 <= pe.len() { pe[off..off+4].copy_from_slice(&0x4000u32.to_le_bytes()); }
        // SizeOfHeaders at opt+60
        let off = opt_start + 60;
        if off + 4 <= pe.len() { pe[off..off+4].copy_from_slice(&0x200u32.to_le_bytes()); }

        // Pad to match declared SizeOfOptionalHeader
        while pe.len() < opt_start + 240 {
            pe.push(0);
        }

        pe
    }

    #[test]
    fn parse_minimal_pe64() {
        let pe_data = minimal_pe64();
        let image = PeImage::parse(&pe_data).expect("should parse minimal PE64");
        assert_eq!(image.image_base, 0x140000000);
        assert_eq!(image.entry_point_rva, 0x1000);
        assert!(image.is_pe64);
        assert!(image.sections.is_empty());
        assert!(image.relocations.is_empty());
        assert!(image.imports.is_empty());
    }

    #[test]
    fn reject_non_pe() {
        // 64 bytes to pass the size check, but bad DOS magic
        let mut bad = vec![0u8; 64];
        bad[0] = b'X';
        bad[1] = b'Y';
        let result = PeImage::parse(&bad);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("bad DOS magic"));
    }

    #[test]
    fn reject_truncated() {
        let result = PeImage::parse(b"MZ");
        assert!(result.is_err());
    }
}
