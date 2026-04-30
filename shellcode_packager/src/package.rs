//! Public API for shellcode packaging.
//!
//! The main entry point is [`package()`] which takes a PE binary and
//! produces a flat, position-independent shellcode blob.

use crate::emitter::{emit_loader, EmitterConfig};
use crate::pe::PeImage;
use anyhow::Result;

/// Configuration for the shellcode packager.
#[derive(Debug, Clone)]
pub struct ShellcodeConfig {
    /// Seed for deterministic output (affects stub diversity).
    pub seed: u64,
    /// Whether to apply code_transform obfuscation to the loader stub.
    pub obfuscate: bool,
}

impl Default for ShellcodeConfig {
    fn default() -> Self {
        Self {
            seed: 0,
            obfuscate: false,
        }
    }
}

/// Convert a PE binary into a position-independent shellcode blob.
///
/// # How it works
///
/// 1. Parses the PE to extract sections, relocations, and imports.
/// 2. Generates a PIC loader that:
///    - Computes its own base address via `call $+5; pop reg`
///    - Applies all relocation fixups (DIR64 / HIGHLOW)
///    - Resolves all imports via inline PEB-walk + export-table hashing
///    - Jumps to the original entry point
/// 3. (Optionally) applies the `code_transform` pipeline to the loader stub.
/// 4. Emits the final blob: `[loader stub][PE image]`.
///
/// # Output format
///
/// The output is a flat binary blob with no headers. It can be:
/// - Written to any RWX memory page and jumped to
/// - Injected via process hollowing (raw shellcode path)
/// - Injected via manual mapping, `ptrace`, etc.
///
/// # Errors
///
/// Returns an error if the input is not a valid PE file or if the PE
/// contains unsupported features.
pub fn package(pe_bytes: &[u8], seed: u64) -> Result<Vec<u8>> {
    package_with_config(pe_bytes, &ShellcodeConfig { seed, ..Default::default() })
}

/// Convert a PE binary into shellcode with full configuration.
pub fn package_with_config(pe_bytes: &[u8], config: &ShellcodeConfig) -> Result<Vec<u8>> {
    // Parse the PE
    let pe = PeImage::parse(pe_bytes)?;

    if !pe.is_pe64 {
        anyhow::bail!(
            "PE32 (32-bit) images are not yet supported — only PE32+ (64-bit)"
        );
    }

    if pe.relocations.is_empty() && pe.imports.is_empty() {
        tracing::warn!(
            "PE has no relocations and no imports — the output will be a simple wrapper"
        );
    }

    // Emit the loader + PE image
    let emitter_config = EmitterConfig {
        seed: config.seed,
        ..Default::default()
    };
    let blob = emit_loader(&pe, &emitter_config)?;

    // Optionally apply code_transform to the loader portion
    #[cfg(feature = "obfuscate")]
    if config.obfuscate {
        let loader_size = blob.len() - pe.image_size as usize;
        let (loader, image) = blob.split_at_mut(loader_size);
        let loader_owned = loader.to_vec();
        let transformed = code_transform::transform(&loader_owned, config.seed);
        // Rebuild: transformed loader + original image
        blob = transformed;
        blob.extend_from_slice(image);
    }

    tracing::info!(
        "shellcode blob: {} bytes (loader) + {} bytes (PE image) = {} bytes total",
        blob.len() - pe.image_size as usize,
        pe.image_size,
        blob.len(),
    );

    Ok(blob)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal PE32+ image with one section and one relocation.
    fn minimal_pe64_with_reloc() -> Vec<u8> {
        // We'll build a minimal PE64 with:
        // - Image base: 0x140000000
        // - Entry point: 0x1000
        // - One section: .text at RVA 0x1000, raw offset 0x200
        // - One relocation at RVA 0x1000 (DIR64)
        // - No imports

        let mut pe = Vec::new();
        let pe_off: usize;

        // DOS header
        pe.extend_from_slice(b"MZ");
        pe.extend(&[0u8; 58]);
        pe.extend_from_slice(&128u32.to_le_bytes()); // e_lfanew = 128
        pe.extend(&[0u8; 64]); // pad to 128

        pe_off = pe.len();

        // PE signature
        pe.extend_from_slice(b"PE\0\0");

        // COFF header
        pe.extend_from_slice(&0x8664u16.to_le_bytes()); // Machine: AMD64
        pe.extend_from_slice(&1u16.to_le_bytes());      // NumberOfSections
        pe.extend_from_slice(&0u32.to_le_bytes());      // TimeDateStamp
        pe.extend_from_slice(&0u32.to_le_bytes());      // PointerToSymbolTable
        pe.extend_from_slice(&0u32.to_le_bytes());      // NumberOfSymbols
        pe.extend_from_slice(&240u16.to_le_bytes());    // SizeOfOptionalHeader
        pe.extend_from_slice(&0x0022u16.to_le_bytes()); // Characteristics

        let opt_off = pe.len();

        // Optional header (PE32+, 240 bytes)
        pe.extend_from_slice(&0x020Bu16.to_le_bytes()); // Magic
        pe.extend(&[0u8; 238]); // pad to 240

        // Fill in key fields
        let w = |buf: &mut Vec<u8>, off: usize, val: &[u8]| {
            buf[off..off + val.len()].copy_from_slice(val);
        };

        // AddressOfEntryPoint at opt+16
        w(&mut pe, opt_off + 16, &0x1000u32.to_le_bytes());
        // ImageBase at opt+24
        w(&mut pe, opt_off + 24, &0x140000000u64.to_le_bytes());
        // SectionAlignment at opt+32
        w(&mut pe, opt_off + 32, &0x1000u32.to_le_bytes());
        // FileAlignment at opt+36
        w(&mut pe, opt_off + 36, &0x200u32.to_le_bytes());
        // SizeOfImage at opt+56
        w(&mut pe, opt_off + 56, &0x3000u32.to_le_bytes());
        // SizeOfHeaders at opt+60
        w(&mut pe, opt_off + 60, &0x200u32.to_le_bytes());
        // NumberOfRvaAndSizes at opt+108 (PE32+)
        w(&mut pe, opt_off + 108, &16u32.to_le_bytes());

        // Data directory: we need reloc directory at index 5
        // DD start at opt+112
        // DD[5] = offset 112 + 5*8 = 152
        // .reloc section at RVA 0x2000, size 0x200 (we'll put it in section 0's raw data for simplicity)
        // Actually, let's put relocs in a separate data area.
        // For simplicity, let's point the reloc DD at the .text section data area.
        // Reloc block: RVA=0x1000, size=16, entries: [DIR64 at offset 0]
        // Block starts at file offset 0x200 + 8 (past our 8 bytes of code)
        let reloc_rva = 0x2000u32;
        let reloc_size = 16u32;
        w(&mut pe, opt_off + 112 + 5 * 8, &reloc_rva.to_le_bytes());
        w(&mut pe, opt_off + 112 + 5 * 8 + 4, &reloc_size.to_le_bytes());

        // Pad optional header to declared size
        while pe.len() < opt_off + 240 {
            pe.push(0);
        }

        // Section header: .text
        pe.extend_from_slice(b".text\0\0\0");          // Name
        pe.extend_from_slice(&0x1000u32.to_le_bytes()); // VirtualSize
        pe.extend_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
        pe.extend_from_slice(&0x200u32.to_le_bytes());  // SizeOfRawData
        pe.extend_from_slice(&0x200u32.to_le_bytes());  // PointerToRawData
        pe.extend(&[0u8; 12]);                           // relocs, linenums
        pe.extend_from_slice(&0x60000020u32.to_le_bytes()); // Characteristics

        // Section header: .reloc
        pe.extend_from_slice(b".reloc\0\0");
        pe.extend_from_slice(&0x200u32.to_le_bytes());  // VirtualSize
        pe.extend_from_slice(&0x2000u32.to_le_bytes()); // VirtualAddress
        pe.extend_from_slice(&0x200u32.to_le_bytes());  // SizeOfRawData
        pe.extend_from_slice(&0x400u32.to_le_bytes());  // PointerToRawData
        pe.extend(&[0u8; 12]);
        pe.extend_from_slice(&0x42000040u32.to_le_bytes()); // Characteristics

        // Update NumberOfSections to 2
        let nsec_off = pe_off + 4 + 2;
        pe[nsec_off..nsec_off + 2].copy_from_slice(&2u16.to_le_bytes());

        // Pad to headers size (0x200)
        while pe.len() < 0x200 {
            pe.push(0);
        }

        // .text raw data: 8 bytes of code at offset 0x200
        // "mov rax, 0x140001000; ret" — contains an absolute address that needs reloc
        // 48 B8 00 10 00 40 01 00 00 00  C3
        let code: &[u8] = &[
            0x48, 0xB8,                                         // mov rax, imm64
            0x00, 0x10, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00,   // = 0x140001000
            0xC3,                                                // ret
        ];
        pe.extend_from_slice(code);
        // Pad to section size
        while pe.len() < 0x200 + 0x200 {
            pe.push(0);
        }

        // .reloc raw data at offset 0x400
        // Reloc block: VirtualAddress=0x1000, SizeOfBlock=16
        pe.extend_from_slice(&0x1000u32.to_le_bytes()); // PageRVA
        pe.extend_from_slice(&16u32.to_le_bytes());      // BlockSize (8 header + 2*4 entries)
        // Entries: DIR64 at offset 2 (the imm64 in the mov rax instruction)
        // DIR64 = type=10, offset=2 → (10 << 12) | 2 = 0xA002
        pe.extend_from_slice(&0xA002u16.to_le_bytes());
        // Padding entry
        pe.extend_from_slice(&0x0000u16.to_le_bytes());
        // Pad to section size
        while pe.len() < 0x400 + 0x200 {
            pe.push(0);
        }

        pe
    }

    #[test]
    fn parse_minimal_pe_with_reloc() {
        let pe_data = minimal_pe64_with_reloc();
        let pe = PeImage::parse(&pe_data).expect("should parse");
        assert_eq!(pe.image_base, 0x140000000);
        assert_eq!(pe.entry_point_rva, 0x1000);
        assert!(pe.is_pe64);
        assert_eq!(pe.sections.len(), 2);
        assert_eq!(pe.relocations.len(), 1);
        assert_eq!(pe.relocations[0].rva, 0x1002);
        assert_eq!(pe.relocations[0].rel_type, 10);
    }

    #[test]
    fn package_minimal_pe() {
        let pe_data = minimal_pe64_with_reloc();
        let result = package(&pe_data, 0);
        assert!(result.is_ok(), "package should succeed");
        let shellcode = result.unwrap();
        // Should be at least as large as the PE image
        assert!(shellcode.len() > 0x3000, "shellcode should be larger than PE image");
    }

    #[test]
    fn reject_32bit_pe() {
        // Build a PE32 (not PE32+) image
        let mut pe = Vec::new();
        pe.extend_from_slice(b"MZ");
        pe.extend(&[0u8; 58]);
        pe.extend_from_slice(&64u32.to_le_bytes());
        pe.extend_from_slice(b"PE\0\0");
        pe.extend_from_slice(&0x014Cu16.to_le_bytes()); // i386
        pe.extend_from_slice(&0u16.to_le_bytes());
        pe.extend(&[0u8; 12]);
        pe.extend_from_slice(&224u16.to_le_bytes()); // SizeOfOptionalHeader
        pe.extend_from_slice(&0x0102u16.to_le_bytes());
        // PE32 optional header
        pe.extend_from_slice(&0x010Bu16.to_le_bytes()); // PE32 magic
        pe.extend(&[0u8; 222]);

        let result = package(&pe, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("32-bit"));
    }
}
