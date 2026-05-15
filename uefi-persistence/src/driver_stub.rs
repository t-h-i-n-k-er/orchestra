//! EFI PE/COFF stub builder — generates minimal valid EFI application binaries.
//!
//! # Overview
//!
//! Builds a minimal PE/COFF binary suitable for execution as an EFI application.
//! The stub:
//! 1. Receives the ImageHandle and SystemTable pointers from the UEFI firmware.
//! 2. Resolves the `EFI_LOADED_IMAGE_PROTOCOL` to find the device handle.
//! 3. Optionally loads an embedded payload from a resource section.
//! 4. Optionally calls a second-stage loader from the ESP.
//! 5. Chains to the original bootloader.
//!
//! # Binary Layout
//!
//! ```text
//! Offset   Size   Content
//! 0x000    0x40   DOS Header (MZ + stub)
//! 0x040    0xF8   PE Optional Header (PE32+)
//! 0x138    0x04   PE Signature
//! 0x13C    0x14   COFF Header
//! 0x150    0x28   Section Header: .text (EFI entry point stub)
//! 0x178    0x28   Section Header: .rdata (embedded payload / config)
//! 0x1A0    0x28   Section Header: .reloc (relocation table)
//! 0x1C8    ???    .text section data
//! 0x???    ???    .rdata section data
//! 0x???    ???    .reloc section data
//! ```

use crate::EfiPayloadConfig;
use anyhow::{bail, Context, Result};

/// Page alignment for EFI sections (4096 bytes).
const EFI_PAGE_SIZE: usize = 0x1000;

/// Section alignment (must be >= file alignment).
const SECTION_ALIGNMENT: u32 = 0x1000;

/// File alignment.
const FILE_ALIGNMENT: u32 = 0x200;

/// Size of the DOS header.
const DOS_HEADER_SIZE: usize = 0x40;

/// Offset to PE header in DOS header.
const DOS_HEADER_LFANEW_OFFSET: usize = 0x3C;

/// PE signature: "PE\0\0".
const PE_SIGNATURE: [u8; 4] = [b'P', b'E', 0x00, 0x00];

/// PE32+ optional header magic.
const PE32_PLUS_MAGIC: u16 = 0x20B;

/// IMAGE_SUBSYSTEM_EFI_APPLICATION.
const IMAGE_SUBSYSTEM_EFI_APPLICATION: u16 = 10;

/// IMAGE_FILE_MACHINE_AMD64.
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;

/// IMAGE_FILE_MACHINE_ARM64.
const IMAGE_FILE_MACHINE_ARM64: u16 = 0xAA64;

/// EFI_GUID size in bytes.
const EFI_GUID_SIZE: usize = 16;

/// EFI_LOADED_IMAGE_PROTOCOL GUID: {5B1B31A1-9562-11D2-8E3F-00A0C969723B}
/// in little-endian wire format (UEFI spec layout).
const EFI_LOADED_IMAGE_PROTOCOL_GUID: [u8; EFI_GUID_SIZE] = [
    0xA1, 0x31, 0x1B, 0x5B, 0x62, 0x95, 0xD2, 0x11, 0x8E, 0x3F, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B,
];

/// EFI_BOOT_SERVICES offsets used by the x64 entry stub.
const EFI_BOOT_SERVICES_LOAD_IMAGE_OFFSET: u32 = 0x00C8;
const EFI_BOOT_SERVICES_START_IMAGE_OFFSET: u32 = 0x00D0;
const EFI_BOOT_SERVICES_OPEN_PROTOCOL_OFFSET: u32 = 0x0118;

/// EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL attribute value.
const EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL: u32 = 0x00000020;

/// IMAGE_FILE_EXECUTABLE_IMAGE.
const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;

/// IMAGE_FILE_LARGE_ADDRESS_AWARE.
const IMAGE_FILE_LARGE_ADDRESS_AWARE: u16 = 0x0020;

/// Number of sections in the stub.
const NUM_SECTIONS: u16 = 3;

/// .text section name.
const TEXT_SECTION_NAME: &[u8; 8] = b".text\0\0\0";

/// .rdata section name.
const RDATA_SECTION_NAME: &[u8; 8] = b".rdata\0\0";

/// .reloc section name.
const RELOC_SECTION_NAME: &[u8; 8] = b".reloc\0\0";

/// Section characteristics.
const IMAGE_SCN_CNT_CODE: u32 = 0x00000020;
const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x00000040;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
const IMAGE_SCN_MEM_READ: u32 = 0x40000000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;
const IMAGE_SCN_MEM_DISCARDABLE: u32 = 0x02000000;
const IMAGE_SCN_ALIGN_1BYTES: u32 = 0x00100000;

/// Result of building an EFI stub.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EfiStubResult {
    /// The raw PE/COFF binary bytes.
    pub binary: Vec<u8>,
    /// Size of the binary.
    pub size: usize,
    /// SHA-256 hash of the binary.
    pub sha256_hash: String,
    /// Entry point RVA.
    pub entry_point_rva: u32,
    /// Size of the .text section.
    pub text_section_size: u32,
    /// Size of the .rdata section (payload + config).
    pub rdata_section_size: u32,
}

// ─── Architecture-specific patch types ──────────────────────────────────
//
// x86-64 uses RIP-relative addressing: a 32-bit displacement is patched
// into a `lea reg, [rip+disp32]` or `lea reg, [rip+disp32]` instruction.
// AArch64 uses ADR (form PC-relative address in a register, ±1 MiB range)
// for the same purpose.

#[cfg(not(target_arch = "aarch64"))]
#[derive(Debug, Clone, Copy)]
struct RipRelativePatch {
    displacement_offset: usize,
    rip_after_offset: usize,
}

#[cfg(not(target_arch = "aarch64"))]
#[derive(Debug, Clone, Copy)]
struct PathImageLoaderPatches {
    device_path_patch: RipRelativePatch,
    loaded_image_guid_patch: RipRelativePatch,
}

/// AArch64 ADR-based patch: records the offset of an ADR instruction whose
/// immediate will be patched to point at the target RVA.
#[cfg(target_arch = "aarch64")]
#[derive(Debug, Clone, Copy)]
struct AdrPatch {
    /// Byte offset of the ADR instruction within .text.
    instr_offset: usize,
}

/// AArch64 path-loader patches: one ADR for the device path, one for the
/// loaded-image GUID.
#[cfg(target_arch = "aarch64")]
#[derive(Debug, Clone, Copy)]
struct PathLoaderPatchesA64 {
    device_path_patch: AdrPatch,
    loaded_image_guid_patch: AdrPatch,
}

// ─── Type aliases (architecture-polymorphic) ─────────────────────────

#[cfg(not(target_arch = "aarch64"))]
type PayloadPatch = RipRelativePatch;
#[cfg(target_arch = "aarch64")]
type PayloadPatch = AdrPatch;

#[cfg(not(target_arch = "aarch64"))]
type LoaderPatches = PathImageLoaderPatches;
#[cfg(target_arch = "aarch64")]
type LoaderPatches = PathLoaderPatchesA64;

struct TextSectionBuild {
    bytes: Vec<u8>,
    embedded_payload_patch: Option<PayloadPatch>,
    second_stage_patch: Option<LoaderPatches>,
    original_bootloader_patch: Option<LoaderPatches>,
}

// ─── x86-64 patch helpers ────────────────────────────────────────────

#[cfg(not(target_arch = "aarch64"))]
fn patch_rip_relative_i32(
    text: &mut [u8],
    patch: RipRelativePatch,
    text_rva: u32,
    target_rva: u32,
    label: &str,
) -> Result<()> {
    let end = patch
        .displacement_offset
        .checked_add(4)
        .context("RIP-relative patch offset overflow")?;
    if end > text.len() {
        bail!(
            "{label} displacement offset {} is outside .text size {}",
            patch.displacement_offset,
            text.len()
        );
    }

    let rip_after = text_rva as i64 + patch.rip_after_offset as i64;
    let displacement = target_rva as i64 - rip_after;
    let displacement = i32::try_from(displacement)
        .with_context(|| format!("{label} RIP-relative displacement out of i32 range"))?;
    text[patch.displacement_offset..end].copy_from_slice(&displacement.to_le_bytes());
    Ok(())
}

#[cfg(not(target_arch = "aarch64"))]
fn emit_jnz_rel32_placeholder(text: &mut Vec<u8>) -> usize {
    text.extend_from_slice(&[0x0F, 0x85]);
    let displacement_offset = text.len();
    text.extend_from_slice(&0i32.to_le_bytes());
    displacement_offset
}

#[cfg(not(target_arch = "aarch64"))]
fn emit_jz_rel32_placeholder(text: &mut Vec<u8>) -> usize {
    text.extend_from_slice(&[0x0F, 0x84]);
    let displacement_offset = text.len();
    text.extend_from_slice(&0i32.to_le_bytes());
    displacement_offset
}

#[cfg(not(target_arch = "aarch64"))]
fn patch_relative_jump(
    text: &mut [u8],
    displacement_offset: usize,
    target_offset: usize,
) -> Result<()> {
    let end = displacement_offset
        .checked_add(4)
        .context("relative jump offset overflow")?;
    if end > text.len() || target_offset > text.len() {
        bail!(
            "relative jump patch out of range (disp={}, target={}, len={})",
            displacement_offset,
            target_offset,
            text.len()
        );
    }
    let rip_after = end as isize;
    let displacement = target_offset as isize - rip_after;
    let displacement =
        i32::try_from(displacement).context("relative jump displacement out of i32 range")?;
    text[displacement_offset..end].copy_from_slice(&displacement.to_le_bytes());
    Ok(())
}

// ─── AArch64 patch helpers ────────────────────────────────────────────

/// Patch an ADR instruction to point at `target_rva`.
///
/// ADR encoding (A64 ISA §C4.1.2):
///   bits[31]    = op = 0 (ADR) / 1 (ADRP)
///   bits[30:29] = immlo (2 bits)
///   bits[28:24] = 10000
///   bits[23:5]  = immhi (19 bits)
///   bits[4:0]   = Rd
///
/// The signed byte offset = immhi:immlo sign-extended to 21 bits, then
/// shifted left by 0 (ADR) or 12 (ADRP).  ADR range = ±1 MiB.
#[cfg(target_arch = "aarch64")]
fn patch_adr_instruction(
    text: &mut [u8],
    patch: AdrPatch,
    text_rva: u32,
    target_rva: u32,
    label: &str,
) -> Result<()> {
    let instr_end = patch
        .instr_offset
        .checked_add(4)
        .context("ADR patch offset overflow")?;
    if instr_end > text.len() {
        bail!(
            "{label} ADR instruction offset {} is outside .text size {}",
            patch.instr_offset,
            text.len()
        );
    }

    let pc = text_rva as i64 + patch.instr_offset as i64;
    let offset = target_rva as i64 - pc;

    // ADR range check: ±1 MiB (signed 21-bit immediate).
    if offset < -(1 << 20) || offset >= (1 << 20) {
        bail!(
            "{label} ADR offset {offset:#x} out of ±1MiB range (text_rva={text_rva:#x}, target_rva={target_rva:#x})"
        );
    }

    let offset = offset as i32;
    let immhi = (offset >> 3) & 0x7FFFF; // bits [23:5] → 19 bits
    let immlo = (offset & 0x3) as u32; // bits [30:29] → 2 bits

    // Read existing instruction to preserve Rd.
    let existing = u32::from_le_bytes([
        text[patch.instr_offset],
        text[patch.instr_offset + 1],
        text[patch.instr_offset + 2],
        text[patch.instr_offset + 3],
    ]);
    let rd = existing & 0x1F;

    let instr = 0x10000000u32 | (immhi as u32) << 5 | immlo << 29 | rd;
    text[patch.instr_offset..instr_end].copy_from_slice(&instr.to_le_bytes());
    Ok(())
}

fn looks_like_pe_coff_image(payload: &[u8]) -> bool {
    if payload.len() < 0x40 || payload.get(0..2) != Some(b"MZ") {
        return false;
    }
    let e_lfanew =
        u32::from_le_bytes([payload[0x3c], payload[0x3d], payload[0x3e], payload[0x3f]]) as usize;
    let signature_end = match e_lfanew.checked_add(4) {
        Some(end) => end,
        None => return false,
    };
    signature_end <= payload.len() && payload[e_lfanew..signature_end] == *b"PE\0\0"
}

fn payload_pages(payload_len: usize) -> Result<u32> {
    let pages = payload_len
        .checked_add(EFI_PAGE_SIZE - 1)
        .context("payload size overflow")?
        / EFI_PAGE_SIZE;
    u32::try_from(pages).context("payload requires more EFI pages than the x64 stub can encode")
}

fn align_up_usize(value: usize, alignment: usize) -> Result<usize> {
    let adjusted = value
        .checked_add(alignment - 1)
        .context("alignment overflow")?;
    Ok(adjusted & !(alignment - 1))
}

fn file_path_device_path_len(path: &str) -> Result<usize> {
    let wchar_count = path.encode_utf16().count() + 1;
    let path_bytes = wchar_count
        .checked_mul(2)
        .context("EFI device path byte length overflow")?;
    let node_length = 4usize
        .checked_add(path_bytes)
        .context("EFI FILE_PATH node length overflow")?;
    if node_length > u16::MAX as usize {
        bail!("EFI FILE_PATH node is too long for path {path:?}");
    }
    node_length
        .checked_add(4)
        .context("EFI device path length overflow")
}

/// Compute the byte offset of the payload data within the .rdata section.
///
/// This mirrors the layout produced by `build_rdata_section` so that
/// `build_efi_stub` can patch the correct RIP-relative displacement for the
/// embedded payload loader in the .text entry-point stub.
fn rdata_payload_start_offset(config: &EfiPayloadConfig) -> usize {
    let path_bytes = config.second_stage_path.as_bytes();
    let raw = 4 + 4 + 4 + 4 + 4 + path_bytes.len() + 1; // ORCH+ver+payload_sz+flags+path_len+path+null
    align_up(raw as u32, 16) as usize
}

/// Compute the byte offset of the FILE_PATH device-path node within the
/// .rdata section.
///
/// The device path is placed after the ORCH header and (optionally) the
/// embedded payload data, both aligned to 16-byte boundaries.
fn rdata_metadata_start_offset(config: &EfiPayloadConfig) -> usize {
    let after_header = rdata_payload_start_offset(config);
    if config.payload_data.is_empty() {
        after_header
    } else {
        let raw = after_header + config.payload_data.len();
        align_up(raw as u32, 16) as usize
    }
}

fn rdata_loaded_image_guid_offset(config: &EfiPayloadConfig) -> usize {
    rdata_metadata_start_offset(config)
}

fn rdata_device_path_base_offset(config: &EfiPayloadConfig) -> usize {
    rdata_loaded_image_guid_offset(config) + align_up(EFI_GUID_SIZE as u32, 16) as usize
}

fn rdata_second_stage_device_path_offset(config: &EfiPayloadConfig) -> usize {
    rdata_device_path_base_offset(config)
}

fn rdata_original_bootloader_device_path_offset(config: &EfiPayloadConfig) -> Result<usize> {
    let mut offset = rdata_device_path_base_offset(config);
    if !config.second_stage_path.is_empty() {
        offset = offset
            .checked_add(align_up_usize(
                file_path_device_path_len(&config.second_stage_path)?,
                16,
            )?)
            .context("original bootloader device path offset overflow")?;
    }
    Ok(offset)
}

/// Build a minimal EFI PE/COFF stub that can load an embedded payload.
///
/// The resulting binary:
/// - Is a valid PE32+ with EFI_APPLICATION subsystem.
/// - Contains the payload embedded in the .rdata section.
/// - Has a minimal .text section with an EFI entry point stub.
/// - Has a .reloc section for relocation fixups.
///
/// **Note**: The entry point stub is minimal x86-64 machine code that:
/// 1. Saves registers.
/// 2. Calls the payload loader.
/// 3. Returns EFI status.
///
/// Embedded EFI PE/COFF images are launched through BootServices->LoadImage and
/// StartImage. Embedded raw payloads are copied into EFI_LOADER_CODE pages
/// before execution so the stub does not jump into non-executable .rdata.
pub fn build_efi_stub(config: &EfiPayloadConfig) -> Result<EfiStubResult> {
    // Validate configuration.
    if config.payload_data.is_empty() && config.second_stage_path.is_empty() {
        bail!("Either payload_data or second_stage_path must be provided");
    }
    if config.payload_data.len() > u32::MAX as usize {
        bail!("payload_data is too large for the ORCH EFI payload header");
    }
    if config.second_stage_path.len() > u32::MAX as usize {
        bail!("second_stage_path is too large for the ORCH EFI payload header");
    }
    if !config.payload_data.is_empty()
        && !looks_like_pe_coff_image(&config.payload_data)
        && config.entry_point_offset as usize >= config.payload_data.len()
    {
        bail!(
            "entry_point_offset {:#x} is outside raw payload size {:#x}",
            config.entry_point_offset,
            config.payload_data.len()
        );
    }
    if config.chain_to_original && config.original_bootloader_path.is_empty() {
        bail!("original_bootloader_path must be provided when chain_to_original is enabled");
    }

    // Build the .text section (EFI entry point stub).
    let text_build = build_text_section(config)?;
    let mut text_section = text_build.bytes;

    // Build the .rdata section (embedded payload + config + device path).
    let rdata_section = build_rdata_section(config)?;

    // Build the .reloc section.
    let reloc_section = build_reloc_section();

    // Calculate section sizes (aligned).
    let text_size_aligned = align_up(text_section.len() as u32, FILE_ALIGNMENT);
    let rdata_size_aligned = align_up(rdata_section.len() as u32, FILE_ALIGNMENT);
    let reloc_size_aligned = align_up(reloc_section.len() as u32, FILE_ALIGNMENT);

    // Calculate RVAs.
    let headers_size = align_up(
        (DOS_HEADER_SIZE + 4 + 20 + 240 + (NUM_SECTIONS as usize * 40)) as u32,
        SECTION_ALIGNMENT,
    );
    let text_rva = headers_size;
    let rdata_rva = text_rva + align_up(text_size_aligned, SECTION_ALIGNMENT);
    let reloc_rva = rdata_rva + align_up(rdata_size_aligned, SECTION_ALIGNMENT);

    let image_size = reloc_rva + align_up(reloc_size_aligned, SECTION_ALIGNMENT);

    // ─── Patch address displacements in .text ────────────────────────────
    if let Some(patch) = text_build.embedded_payload_patch {
        let payload_rva = rdata_rva + rdata_payload_start_offset(config) as u32;
        #[cfg(not(target_arch = "aarch64"))]
        patch_rip_relative_i32(
            &mut text_section,
            patch,
            text_rva,
            payload_rva,
            "embedded payload",
        )?;
        #[cfg(target_arch = "aarch64")]
        patch_adr_instruction(
            &mut text_section,
            patch,
            text_rva,
            payload_rva,
            "embedded payload",
        )?;
    }

    if let Some(patch) = text_build.second_stage_patch {
        let guid_rva = rdata_rva + rdata_loaded_image_guid_offset(config) as u32;
        #[cfg(not(target_arch = "aarch64"))]
        patch_rip_relative_i32(
            &mut text_section,
            patch.loaded_image_guid_patch,
            text_rva,
            guid_rva,
            "second-stage loaded-image protocol GUID",
        )?;
        #[cfg(target_arch = "aarch64")]
        patch_adr_instruction(
            &mut text_section,
            patch.loaded_image_guid_patch,
            text_rva,
            guid_rva,
            "second-stage loaded-image protocol GUID",
        )?;

        let dp_rva = rdata_rva + rdata_second_stage_device_path_offset(config) as u32;
        #[cfg(not(target_arch = "aarch64"))]
        patch_rip_relative_i32(
            &mut text_section,
            patch.device_path_patch,
            text_rva,
            dp_rva,
            "second-stage device path",
        )?;
        #[cfg(target_arch = "aarch64")]
        patch_adr_instruction(
            &mut text_section,
            patch.device_path_patch,
            text_rva,
            dp_rva,
            "second-stage device path",
        )?;
    }

    if let Some(patch) = text_build.original_bootloader_patch {
        let guid_rva = rdata_rva + rdata_loaded_image_guid_offset(config) as u32;
        #[cfg(not(target_arch = "aarch64"))]
        patch_rip_relative_i32(
            &mut text_section,
            patch.loaded_image_guid_patch,
            text_rva,
            guid_rva,
            "original-loader loaded-image protocol GUID",
        )?;
        #[cfg(target_arch = "aarch64")]
        patch_adr_instruction(
            &mut text_section,
            patch.loaded_image_guid_patch,
            text_rva,
            guid_rva,
            "original-loader loaded-image protocol GUID",
        )?;

        let dp_rva = rdata_rva + rdata_original_bootloader_device_path_offset(config)? as u32;
        #[cfg(not(target_arch = "aarch64"))]
        patch_rip_relative_i32(
            &mut text_section,
            patch.device_path_patch,
            text_rva,
            dp_rva,
            "original bootloader device path",
        )?;
        #[cfg(target_arch = "aarch64")]
        patch_adr_instruction(
            &mut text_section,
            patch.device_path_patch,
            text_rva,
            dp_rva,
            "original bootloader device path",
        )?;
    }

    // Calculate file offsets.
    let headers_file_size = align_up(
        (DOS_HEADER_SIZE + 4 + 20 + 240 + (NUM_SECTIONS as usize * 40)) as u32,
        FILE_ALIGNMENT,
    );
    let text_file_offset = headers_file_size;
    let rdata_file_offset = text_file_offset + text_size_aligned;
    let reloc_file_offset = rdata_file_offset + rdata_size_aligned;

    let total_file_size = reloc_file_offset + reloc_size_aligned;

    // Build the PE/COFF binary.
    let mut binary = Vec::with_capacity(total_file_size as usize);

    // ─── DOS Header ─────────────────────────────────────────────────────
    binary.extend_from_slice(&build_dos_header());

    // ─── PE Signature ───────────────────────────────────────────────────
    binary.extend_from_slice(&PE_SIGNATURE);

    // ─── COFF Header ────────────────────────────────────────────────────
    let pe_offset = DOS_HEADER_SIZE as u32;
    let entry_point_rva = text_rva; // Entry point at start of .text.

    binary.extend_from_slice(&build_coff_header(entry_point_rva, text_rva));

    // ─── Optional Header (PE32+) ────────────────────────────────────────
    binary.extend_from_slice(&build_optional_header(
        headers_size,
        image_size,
        entry_point_rva,
        text_rva,
        rdata_rva, // base_of_data
        rdata_rva, // data_directory_rva
        reloc_rva,
        text_size_aligned,
        rdata_size_aligned,
        0, // size_of_uninitialized_data
    ));

    // ─── Section Headers ────────────────────────────────────────────────
    // .text
    binary.extend_from_slice(&build_section_header(
        TEXT_SECTION_NAME,
        text_size_aligned,
        text_rva,
        text_size_aligned,
        text_file_offset,
        IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
    ));

    // .rdata
    binary.extend_from_slice(&build_section_header(
        RDATA_SECTION_NAME,
        rdata_size_aligned,
        rdata_rva,
        rdata_size_aligned,
        rdata_file_offset,
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
    ));

    // .reloc
    binary.extend_from_slice(&build_section_header(
        RELOC_SECTION_NAME,
        reloc_size_aligned,
        reloc_rva,
        reloc_size_aligned,
        reloc_file_offset,
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_DISCARDABLE | IMAGE_SCN_MEM_READ,
    ));

    // ─── Pad headers to file alignment ──────────────────────────────────
    let current_size = binary.len();
    let target_size = headers_file_size as usize;
    if current_size < target_size {
        binary.resize(target_size, 0x00);
    }

    // ─── .text Section Data ─────────────────────────────────────────────
    binary.extend_from_slice(&text_section);
    // Pad to aligned size.
    let text_pad = text_size_aligned as usize - text_section.len();
    binary.resize(binary.len() + text_pad, 0x00);

    // ─── .rdata Section Data ────────────────────────────────────────────
    binary.extend_from_slice(&rdata_section);
    let rdata_pad = rdata_size_aligned as usize - rdata_section.len();
    binary.resize(binary.len() + rdata_pad, 0x00);

    // ─── .reloc Section Data ────────────────────────────────────────────
    binary.extend_from_slice(&reloc_section);
    let reloc_pad = reloc_size_aligned as usize - reloc_section.len();
    binary.resize(binary.len() + reloc_pad, 0x00);

    // Compute hash.
    let sha256_hash = {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(&binary);
        hex::encode(hasher.finalize())
    };

    Ok(EfiStubResult {
        size: binary.len(),
        sha256_hash,
        entry_point_rva,
        text_section_size: text_size_aligned,
        rdata_section_size: rdata_size_aligned,
        binary,
    })
}

/// Build the DOS header.
///
/// The DOS header is 64 bytes and contains:
/// - `e_magic`: "MZ" (0x5A4D)
/// - `e_lfanew`: Offset to PE header (at offset 0x3C)
fn build_dos_header() -> [u8; DOS_HEADER_SIZE] {
    let mut header = [0u8; DOS_HEADER_SIZE];

    // DOS magic: "MZ".
    header[0] = b'M';
    header[1] = b'Z';

    // Last page size.
    header[2] = 0x90;
    header[3] = 0x00;

    // Pages in file.
    header[4] = 0x03;
    header[5] = 0x00;

    // Relocations.
    header[6] = 0x00;
    header[7] = 0x00;

    // Size of header in paragraphs.
    header[8] = 0x04;
    header[9] = 0x00;

    // Min extra paragraphs.
    header[10] = 0x00;
    header[11] = 0x00;

    // Max extra paragraphs.
    header[12] = 0xFF;
    header[13] = 0xFF;

    // Initial SS.
    header[14] = 0x00;
    header[15] = 0x00;

    // Initial SP.
    header[16] = 0xB8;
    header[17] = 0x00;

    // Checksum.
    header[18] = 0x00;
    header[19] = 0x00;

    // Initial IP.
    header[20] = 0x00;
    header[21] = 0x00;

    // Initial CS.
    header[22] = 0x00;
    header[23] = 0x00;

    // Offset to PE header (right after DOS header).
    let pe_offset = DOS_HEADER_SIZE as u32;
    header[DOS_HEADER_LFANEW_OFFSET..DOS_HEADER_LFANEW_OFFSET + 4]
        .copy_from_slice(&pe_offset.to_le_bytes());

    // No DOS stub: the PE header starts immediately at offset 0x40, so there
    // is no space between the 64-byte DOS header and the PE signature for a
    // stub message.  A real linker would shift e_lfanew past the stub, but we
    // keep the binary minimal.

    header
}

/// Build the COFF header.
fn target_machine_type() -> u16 {
    #[cfg(target_arch = "aarch64")]
    {
        IMAGE_FILE_MACHINE_ARM64
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        IMAGE_FILE_MACHINE_AMD64
    }
}

fn build_coff_header(_entry_point_rva: u32, _base_of_code: u32) -> [u8; 20] {
    let mut header = [0u8; 20];

    // Machine: native build target architecture (x64 or ARM64).
    header[0..2].copy_from_slice(&target_machine_type().to_le_bytes());

    // NumberOfSections.
    header[2..4].copy_from_slice(&NUM_SECTIONS.to_le_bytes());

    // TimeDateStamp (0 = deterministic build).
    header[4..8].copy_from_slice(&0u32.to_le_bytes());

    // PointerToSymbolTable (0 = no symbols).
    header[8..12].copy_from_slice(&0u32.to_le_bytes());

    // NumberOfSymbols.
    header[12..16].copy_from_slice(&0u32.to_le_bytes());

    // SizeOfOptionalHeader: 240 for PE32+.
    header[16..18].copy_from_slice(&240u16.to_le_bytes());

    // Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE.
    let characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE;
    header[18..20].copy_from_slice(&characteristics.to_le_bytes());

    header
}

/// Build the PE32+ optional header.
fn build_optional_header(
    size_of_headers: u32,
    size_of_image: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    _base_of_data: u32, // Not used in PE32+
    _data_directory_rva: u32,
    _reloc_rva: u32,
    size_of_code: u32,
    size_of_initialized_data: u32,
    _size_of_uninitialized_data: u32,
) -> [u8; 240] {
    let mut header = [0u8; 240];

    // ─── Standard Fields (PE32+) ────────────────────────────────────────
    // Magic: PE32+.
    header[0..2].copy_from_slice(&PE32_PLUS_MAGIC.to_le_bytes());

    // MajorLinkerVersion.
    header[2] = 14; // MSVC 14.x style.

    // MinorLinkerVersion.
    header[3] = 0;

    // SizeOfCode.
    header[4..8].copy_from_slice(&size_of_code.to_le_bytes());

    // SizeOfInitializedData.
    header[8..12].copy_from_slice(&size_of_initialized_data.to_le_bytes());

    // SizeOfUninitializedData (0).
    header[12..16].copy_from_slice(&0u32.to_le_bytes());

    // AddressOfEntryPoint.
    header[16..20].copy_from_slice(&address_of_entry_point.to_le_bytes());

    // BaseOfCode.
    header[20..24].copy_from_slice(&base_of_code.to_le_bytes());

    // ─── PE32+ Windows-Specific Fields ──────────────────────────────────
    // ImageBase: 0x10000 (typical for EFI applications).
    header[24..32].copy_from_slice(&0x10000u64.to_le_bytes());

    // SectionAlignment.
    header[32..36].copy_from_slice(&SECTION_ALIGNMENT.to_le_bytes());

    // FileAlignment.
    header[36..40].copy_from_slice(&FILE_ALIGNMENT.to_le_bytes());

    // MajorOperatingSystemVersion.
    header[40..42].copy_from_slice(&0u16.to_le_bytes());

    // MinorOperatingSystemVersion.
    header[42..44].copy_from_slice(&0u16.to_le_bytes());

    // MajorImageVersion.
    header[44..46].copy_from_slice(&0u16.to_le_bytes());

    // MinorImageVersion.
    header[46..48].copy_from_slice(&0u16.to_le_bytes());

    // MajorSubsystemVersion.
    header[48..50].copy_from_slice(&0u16.to_le_bytes());

    // MinorSubsystemVersion.
    header[50..52].copy_from_slice(&0u16.to_le_bytes());

    // Win32VersionValue (must be 0).
    header[52..56].copy_from_slice(&0u32.to_le_bytes());

    // SizeOfImage.
    header[56..60].copy_from_slice(&size_of_image.to_le_bytes());

    // SizeOfHeaders.
    header[60..64].copy_from_slice(&size_of_headers.to_le_bytes());

    // CheckSum (0 for EFI).
    header[64..68].copy_from_slice(&0u32.to_le_bytes());

    // Subsystem: EFI_APPLICATION.
    header[68..70].copy_from_slice(&IMAGE_SUBSYSTEM_EFI_APPLICATION.to_le_bytes());

    // DllCharacteristics: 0 (no ASLR/DEP for EFI).
    header[70..72].copy_from_slice(&0u16.to_le_bytes());

    // SizeOfStackReserve: 0x100000 (1 MB).
    header[72..80].copy_from_slice(&0x100000u64.to_le_bytes());

    // SizeOfStackCommit: 0x1000.
    header[80..88].copy_from_slice(&0x1000u64.to_le_bytes());

    // SizeOfHeapReserve: 0x100000.
    header[88..96].copy_from_slice(&0x100000u64.to_le_bytes());

    // SizeOfHeapCommit: 0x1000.
    header[96..104].copy_from_slice(&0x1000u64.to_le_bytes());

    // LoaderFlags (0).
    header[104..108].copy_from_slice(&0u32.to_le_bytes());

    // NumberOfRvaAndSizes: 16.
    header[108..112].copy_from_slice(&16u32.to_le_bytes());

    // Data directories (16 entries × 8 bytes = 128 bytes).
    // All zeroed except:
    // [5] = BASE_RELOCATION (RVA, Size)
    // [6] = DEBUG (empty)
    // We leave them all zero since EFI firmware doesn't use them.
    // Offset 112..240 = 128 bytes of data directories.

    header
}

/// Build a section header.
fn build_section_header(
    name: &[u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    characteristics: u32,
) -> [u8; 40] {
    let mut header = [0u8; 40];

    // Name (8 bytes).
    header[0..8].copy_from_slice(name);

    // VirtualSize.
    header[8..12].copy_from_slice(&virtual_size.to_le_bytes());

    // VirtualAddress.
    header[12..16].copy_from_slice(&virtual_address.to_le_bytes());

    // SizeOfRawData.
    header[16..20].copy_from_slice(&size_of_raw_data.to_le_bytes());

    // PointerToRawData.
    header[20..24].copy_from_slice(&pointer_to_raw_data.to_le_bytes());

    // PointerToRelocations (0).
    header[24..28].copy_from_slice(&0u32.to_le_bytes());

    // PointerToLinenumbers (0).
    header[28..32].copy_from_slice(&0u32.to_le_bytes());

    // NumberOfRelocations (0).
    header[32..34].copy_from_slice(&0u16.to_le_bytes());

    // NumberOfLinenumbers (0).
    header[34..36].copy_from_slice(&0u16.to_le_bytes());

    // Characteristics.
    header[36..40].copy_from_slice(&characteristics.to_le_bytes());

    header
}

// ─── x86-64 .text section builder ─────────────────────────────────────
//
// The stub:
// 1. Saves callee-saved registers.
// 2. Sets up the stack frame.
// 3. Stores ImageHandle (rcx) and SystemTable (rdx) in registers.
// 4. If payload_data is an EFI PE/COFF image: uses BootServices->LoadImage
//    with SourceBuffer/SourceSize, then StartImage.
// 5. If payload_data is raw code: allocates EFI_LOADER_CODE pages, copies the
//    bytes out of .rdata, and calls entry_point_offset from executable memory.
// 6. If second_stage_path is provided: uses BootServices->LoadImage and
//    StartImage to chain-load the second-stage binary from the ESP.
// 7. If chain_to_original is enabled: chain-loads original_bootloader_path.
// 8. Returns EFI_SUCCESS (0).
//
// All address calculations use RIP-relative addressing.

#[cfg(not(target_arch = "aarch64"))]
fn build_text_section(config: &EfiPayloadConfig) -> Result<TextSectionBuild> {
    let mut text = Vec::new();
    let mut embedded_payload_patch = None;
    let mut second_stage_patch = None;
    let mut original_bootloader_patch = None;

    // ─── EFI Entry Point prologue ───────────────────────────────────────
    // rcx = ImageHandle, rdx = EFI_SYSTEM_TABLE*

    // push rbp
    text.extend_from_slice(&[0x55]);
    // mov rbp, rsp
    text.extend_from_slice(&[0x48, 0x89, 0xE5]);
    // push rbx
    text.extend_from_slice(&[0x53]);
    // push rsi
    text.extend_from_slice(&[0x56]);
    // push rdi
    text.extend_from_slice(&[0x57]);
    // push r14  (used for EFI_BOOT_SERVICES*, callee-saved in MS x64 ABI)
    text.extend_from_slice(&[0x41, 0x56]);
    // sub rsp, 0x20  (shadow space for UEFI MS-ABI)
    text.extend_from_slice(&[0x48, 0x83, 0xEC, 0x20]);

    // Save ImageHandle → rbx, SystemTable → rsi
    // mov rbx, rcx
    text.extend_from_slice(&[0x48, 0x89, 0xCB]);
    // mov rsi, rdx
    text.extend_from_slice(&[0x48, 0x89, 0xD6]);

    if !config.payload_data.is_empty() {
        embedded_payload_patch = Some(if looks_like_pe_coff_image(&config.payload_data) {
            emit_embedded_efi_image_loader(&mut text, config.payload_data.len())?
        } else {
            emit_raw_payload_loader(&mut text, config)?
        });
    }

    if !config.second_stage_path.is_empty() {
        second_stage_patch = Some(emit_second_stage_loader(&mut text)?);
    }

    if config.chain_to_original {
        original_bootloader_patch = Some(emit_original_bootloader_loader(&mut text)?);
    }

    // ─── Return EFI_SUCCESS ─────────────────────────────────────────────
    // xor eax, eax
    text.extend_from_slice(&[0x31, 0xC0]);
    // add rsp, 0x20
    text.extend_from_slice(&[0x48, 0x83, 0xC4, 0x20]);
    // pop r14
    text.extend_from_slice(&[0x41, 0x5E]);
    // pop rdi
    text.extend_from_slice(&[0x5F]);
    // pop rsi
    text.extend_from_slice(&[0x5E]);
    // pop rbx
    text.extend_from_slice(&[0x5B]);
    // pop rbp
    text.extend_from_slice(&[0x5D]);
    // ret
    text.extend_from_slice(&[0xC3]);

    // Pad to 16-byte alignment.
    while text.len() % 16 != 0 {
        text.push(0x90);
    }

    Ok(TextSectionBuild {
        bytes: text,
        embedded_payload_patch,
        second_stage_patch,
        original_bootloader_patch,
    })
}

#[cfg(not(target_arch = "aarch64"))]
fn emit_embedded_efi_image_loader(
    text: &mut Vec<u8>,
    payload_len: usize,
) -> Result<RipRelativePatch> {
    // LoadImage(FALSE, ImageHandle, NULL, payload, payload_len, &new_handle)
    // followed by StartImage(new_handle, NULL, NULL).
    text.extend_from_slice(&[0x48, 0x83, 0xEC, 0x30]);
    text.extend_from_slice(&[0x4C, 0x8B, 0x76, 0x60]);
    text.extend_from_slice(&[0x48, 0xB8]);
    text.extend_from_slice(&(payload_len as u64).to_le_bytes());
    text.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x20]);
    text.extend_from_slice(&[0x48, 0x8D, 0x44, 0x24, 0x30]);
    text.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x28]);
    text.extend_from_slice(&[0x31, 0xC9]);
    text.extend_from_slice(&[0x48, 0x89, 0xDA]);
    text.extend_from_slice(&[0x45, 0x31, 0xC0]);
    text.extend_from_slice(&[0x4C, 0x8D, 0x0D]);
    let payload_patch = RipRelativePatch {
        displacement_offset: text.len(),
        rip_after_offset: text.len() + 4,
    };
    text.extend_from_slice(&0i32.to_le_bytes());
    text.extend_from_slice(&[0x41, 0xFF, 0x96, 0xC8, 0x00, 0x00, 0x00]);
    text.extend_from_slice(&[0x85, 0xC0]);
    let load_failed_jump = emit_jnz_rel32_placeholder(text);
    text.extend_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x30]);
    text.extend_from_slice(&[0x31, 0xD2]);
    text.extend_from_slice(&[0x45, 0x31, 0xC0]);
    text.extend_from_slice(&[0x41, 0xFF, 0x96, 0xD0, 0x00, 0x00, 0x00]);
    let done = text.len();
    patch_relative_jump(text, load_failed_jump, done)?;
    text.extend_from_slice(&[0x48, 0x83, 0xC4, 0x30]);
    Ok(payload_patch)
}

#[cfg(not(target_arch = "aarch64"))]
fn emit_raw_payload_loader(
    text: &mut Vec<u8>,
    config: &EfiPayloadConfig,
) -> Result<RipRelativePatch> {
    let pages = payload_pages(config.payload_data.len())?;

    // AllocatePages(AllocateAnyPages, EfiLoaderCode, pages, &entry_buffer),
    // copy the embedded raw bytes into the executable pages, then call
    // entry_buffer + entry_point_offset with the normal EFI entry arguments.
    text.extend_from_slice(&[0x48, 0x83, 0xEC, 0x30]);
    text.extend_from_slice(&[0x4C, 0x8B, 0x76, 0x60]);
    text.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00]);
    text.extend_from_slice(&[0x48, 0x89, 0x74, 0x24, 0x28]);
    text.extend_from_slice(&[0x31, 0xC9]);
    text.extend_from_slice(&[0xBA, 0x02, 0x00, 0x00, 0x00]);
    text.extend_from_slice(&[0x41, 0xB8]);
    text.extend_from_slice(&pages.to_le_bytes());
    text.extend_from_slice(&[0x4C, 0x8D, 0x4C, 0x24, 0x20]);
    text.extend_from_slice(&[0x41, 0xFF, 0x96, 0x28, 0x00, 0x00, 0x00]);
    text.extend_from_slice(&[0x85, 0xC0]);
    let alloc_failed_jump = emit_jnz_rel32_placeholder(text);
    text.extend_from_slice(&[0x48, 0x8B, 0x7C, 0x24, 0x20]);
    text.extend_from_slice(&[0x48, 0x8D, 0x35]);
    let payload_patch = RipRelativePatch {
        displacement_offset: text.len(),
        rip_after_offset: text.len() + 4,
    };
    text.extend_from_slice(&0i32.to_le_bytes());
    text.extend_from_slice(&[0x48, 0xB9]);
    text.extend_from_slice(&(config.payload_data.len() as u64).to_le_bytes());
    text.extend_from_slice(&[0xFC, 0xF3, 0xA4]);
    text.extend_from_slice(&[0x48, 0x8B, 0x7C, 0x24, 0x20]);
    if config.entry_point_offset != 0 {
        text.extend_from_slice(&[0x48, 0xB8]);
        text.extend_from_slice(&(config.entry_point_offset as u64).to_le_bytes());
        text.extend_from_slice(&[0x48, 0x01, 0xC7]);
    }
    text.extend_from_slice(&[0x48, 0x89, 0xD9]);
    text.extend_from_slice(&[0x48, 0x8B, 0x54, 0x24, 0x28]);
    text.extend_from_slice(&[0xFF, 0xD7]);
    let done = text.len();
    patch_relative_jump(text, alloc_failed_jump, done)?;
    text.extend_from_slice(&[0x48, 0x83, 0xC4, 0x30]);
    Ok(payload_patch)
}

#[cfg(not(target_arch = "aarch64"))]
fn emit_second_stage_loader(text: &mut Vec<u8>) -> Result<PathImageLoaderPatches> {
    emit_path_image_loader(text)
}

#[cfg(not(target_arch = "aarch64"))]
fn emit_original_bootloader_loader(text: &mut Vec<u8>) -> Result<PathImageLoaderPatches> {
    emit_path_image_loader(text)
}

#[cfg(not(target_arch = "aarch64"))]
fn emit_path_image_loader(text: &mut Vec<u8>) -> Result<PathImageLoaderPatches> {
    // Robust chain-loader path:
    // 1) Resolve EFI_LOADED_IMAGE_PROTOCOL via OpenProtocol(ImageHandle,...)
    // 2) Read LoadedImage->DeviceHandle (offset 0x18)
    // 3) Call LoadImage(FALSE, ImageHandle, DevicePath, DeviceHandle, ...)
    // 4) StartImage(new_handle, NULL, NULL)
    text.extend_from_slice(&[0x48, 0x83, 0xEC, 0x50]);
    text.extend_from_slice(&[0x4C, 0x8B, 0x76, 0x60]);

    // OpenProtocol(ImageHandle, &EFI_LOADED_IMAGE_PROTOCOL_GUID,
    //              &loaded_image_iface, ImageHandle, NULL,
    //              EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL)
    text.extend_from_slice(&[0x48, 0x89, 0xD9]);
    text.extend_from_slice(&[0x48, 0x8D, 0x15]);
    let loaded_image_guid_patch = RipRelativePatch {
        displacement_offset: text.len(),
        rip_after_offset: text.len() + 4,
    };
    text.extend_from_slice(&0i32.to_le_bytes());
    text.extend_from_slice(&[0x4C, 0x8D, 0x44, 0x24, 0x38]);
    text.extend_from_slice(&[0x49, 0x89, 0xD9]);
    text.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00]);
    text.extend_from_slice(&[0xC7, 0x44, 0x24, 0x28]);
    text.extend_from_slice(&EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL.to_le_bytes());
    text.extend_from_slice(&[0x41, 0xFF, 0x96]);
    text.extend_from_slice(&EFI_BOOT_SERVICES_OPEN_PROTOCOL_OFFSET.to_le_bytes());
    text.extend_from_slice(&[0x85, 0xC0]);
    let open_failed_jump = emit_jnz_rel32_placeholder(text);

    // loaded_image_iface must be non-null.
    text.extend_from_slice(&[0x48, 0x8B, 0x44, 0x24, 0x38]);
    text.extend_from_slice(&[0x48, 0x85, 0xC0]);
    let null_iface_jump = emit_jz_rel32_placeholder(text);

    // r9 = LoadedImage->DeviceHandle (offset 0x18)
    text.extend_from_slice(&[0x4C, 0x8B, 0x48, 0x18]);
    text.extend_from_slice(&[0x4D, 0x85, 0xC9]);
    let null_device_jump = emit_jz_rel32_placeholder(text);

    // LoadImage(FALSE, ImageHandle, DevicePath, DeviceHandle, NULL, &new_handle)
    text.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00]);
    text.extend_from_slice(&[0x48, 0x8D, 0x44, 0x24, 0x30]);
    text.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x28]);
    text.extend_from_slice(&[0x31, 0xC9]);
    text.extend_from_slice(&[0x48, 0x89, 0xDA]);
    text.extend_from_slice(&[0x4C, 0x8D, 0x05]);
    let device_path_patch = RipRelativePatch {
        displacement_offset: text.len(),
        rip_after_offset: text.len() + 4,
    };
    text.extend_from_slice(&0i32.to_le_bytes());
    text.extend_from_slice(&[0x41, 0xFF, 0x96]);
    text.extend_from_slice(&EFI_BOOT_SERVICES_LOAD_IMAGE_OFFSET.to_le_bytes());
    text.extend_from_slice(&[0x85, 0xC0]);
    let load_failed_jump = emit_jnz_rel32_placeholder(text);
    text.extend_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x30]);
    text.extend_from_slice(&[0x31, 0xD2]);
    text.extend_from_slice(&[0x45, 0x31, 0xC0]);
    text.extend_from_slice(&[0x41, 0xFF, 0x96]);
    text.extend_from_slice(&EFI_BOOT_SERVICES_START_IMAGE_OFFSET.to_le_bytes());
    let done = text.len();
    patch_relative_jump(text, open_failed_jump, done)?;
    patch_relative_jump(text, null_iface_jump, done)?;
    patch_relative_jump(text, null_device_jump, done)?;
    patch_relative_jump(text, load_failed_jump, done)?;
    text.extend_from_slice(&[0x48, 0x83, 0xC4, 0x50]);
    Ok(PathImageLoaderPatches {
        device_path_patch,
        loaded_image_guid_patch,
    })
}

// ══════════════════════════════════════════════════════════════════════════
// AArch64 EFI entry-point stub
// ══════════════════════════════════════════════════════════════════════════
//
// AAPCS64 calling convention used by UEFI on AArch64:
//   x0  = 1st arg / return value
//   x1  = 2nd arg
//   x2  = 3rd arg
//   x3  = 4th arg
//   x4-x7 = additional args
//   x19-x28 = callee-saved
//   x29 = FP (frame pointer)
//   x30 = LR (link register)
//   SP must be 16-byte aligned on any public interface.
//
// EFI entry point: ImageHandle in x0, SystemTable* in x1.
//
// Register allocation in the stub:
//   x19 = ImageHandle (callee-saved)
//   x20 = SystemTable* (callee-saved)
//   x21 = BootServices* (callee-saved, cached from SystemTable+0x60)
//   x0-x7 = scratch / function call arguments / return values
//
// Stack frame layout (96 bytes total):
//   [sp+0]   = saved x29 (FP)
//   [sp+8]   = saved x30 (LR)
//   [sp+16]  = saved x19
//   [sp+24]  = saved x20
//   [sp+32]  = saved x21
//   [sp+40]  = saved x22
//   [sp+48]  = local: new_handle (8 bytes)
//   [sp+56]  = padding / local storage
//   [sp+64]  = local: loaded_image_iface (8 bytes)
//   [sp+80]  = padding
//   [sp+88]  = padding

#[cfg(target_arch = "aarch64")]
mod a64 {
    //! AArch64 instruction emission helpers.
    //!
    //! Each helper appends a single 4-byte A64 instruction to a `Vec<u8>`.

    // ─── Instruction encoding constants ─────────────────────────────────

    // STP pre-indexed (64-bit): 10 101 0 011 0 imm7 Rt2 Rn Rt
    const STP_PRE_INDEXED: u32 = 0xA9800000;
    // LDP post-indexed (64-bit): 10 100 0 011 1 imm7 Rt2 Rn Rt
    const LDP_POST_INDEXED: u32 = 0xA8C00000;
    // LDR unsigned offset (64-bit): 11 111 0 01 01 imm12 Rn Rt
    const LDR_UNSIGNED: u32 = 0xF9400000;
    // STR unsigned offset (64-bit): 11 111 0 01 00 imm12 Rn Rt
    const STR_UNSIGNED: u32 = 0xF9000000;
    // MOV (register) = ADD Xd, Xn, #0
    const MOV_ADD_ZERO: u32 = 0x91000000;
    // MOVZ 64-bit: 1 10 100101 hw imm16 Rd
    pub const MOVZ_64: u32 = 0xD2800000;
    // MOVK 64-bit: 1 11 100101 hw imm16 Rd
    const MOVK_64: u32 = 0xF2800000;
    // BLR Xn: 1101 0110 0011 1111 0000 00 Rn 00000
    const BLR: u32 = 0xD63F0000;
    // RET: 1101 0110 0101 1111 0000 00 11111 00000
    const RET: u32 = 0xD65F03C0;
    // NOP: 1101 0101 0000 0011 0010 0000 0001 1111
    const NOP: u32 = 0xD503201F;
    // B.cond: 0101 0100 imm19 0 cond
    const B_COND_BASE: u32 = 0x54000000;
    // CBNZ 64-bit: 1 0110101 imm19 Rt
    const CBNZ_64: u32 = 0xB5000000;
    // CBZ 64-bit: 1 0110100 imm19 Rt
    const CBZ_64: u32 = 0xB4000000;
    // ADD immediate (64-bit): 1 00 100010 sh imm12 Rn Rd
    const ADD_IMM: u32 = 0x91000000;
    // SUB immediate (64-bit): 1 10 100010 sh imm12 Rn Rd
    const SUB_IMM: u32 = 0xD1000000;
    // ADD register (64-bit): 1 00 01011 shift 0 Rm imm6 Rn Rd
    const ADD_REG: u32 = 0x8B000000;
    // ADR: 0 immlo 10000 immhi Rd
    const ADR: u32 = 0x10000000;
    // LDRB unsigned offset: 00 111 0 01 01 imm12 Rn Rt (not scaled)
    const LDRB_UNSIGNED: u32 = 0x39400000;
    // STRB unsigned offset: 00 111 0 01 00 imm12 Rn Rt (not scaled)
    const STRB_UNSIGNED: u32 = 0x39000000;

    // Condition codes
    pub const COND_NE: u32 = 0x1;
    pub const COND_EQ: u32 = 0x0;

    // Register numbers
    pub const SP: u32 = 31; // treated as SP in load/store, but encoded as 31
    pub const X0: u32 = 0;
    pub const X1: u32 = 1;
    pub const X2: u32 = 2;
    pub const X3: u32 = 3;
    pub const X4: u32 = 4;
    pub const X5: u32 = 5;
    pub const X8: u32 = 8;
    pub const X9: u32 = 9;
    pub const X19: u32 = 19;
    pub const X20: u32 = 20;
    pub const X21: u32 = 21;
    pub const X22: u32 = 22;
    pub const X23: u32 = 23;
    pub const X24: u32 = 24;
    pub const X25: u32 = 25;
    pub const FP: u32 = 29;
    pub const LR: u32 = 30;

    /// Emit a single 32-bit instruction in little-endian.
    #[inline]
    pub fn emit(text: &mut Vec<u8>, instr: u32) {
        text.extend_from_slice(&instr.to_le_bytes());
    }

    /// STP Xt1, Xt2, [Xn, #imm]!  (pre-indexed, 64-bit)
    /// imm is in units of 8 bytes (0..×512 → 0..4096 bytes).
    #[inline]
    pub fn stp_pre(text: &mut Vec<u8>, rt1: u32, rt2: u32, rn: u32, imm8: i32) {
        let imm7 = (imm8 >> 3) & 0x7F;
        emit(
            text,
            STP_PRE_INDEXED | ((imm7 as u32) << 15) | (rt2 << 10) | (rn << 5) | rt1,
        );
    }

    /// LDP Xt1, Xt2, [Xn], #imm  (post-indexed, 64-bit)
    /// imm is in units of 8 bytes.
    #[inline]
    pub fn ldp_post(text: &mut Vec<u8>, rt1: u32, rt2: u32, rn: u32, imm8: i32) {
        let imm7 = (imm8 >> 3) & 0x7F;
        emit(
            text,
            LDP_POST_INDEXED | ((imm7 as u32) << 15) | (rt2 << 10) | (rn << 5) | rt1,
        );
    }

    /// LDR Xt, [Xn, #imm]  (unsigned offset, 64-bit)
    /// imm is in bytes, must be a multiple of 8, range 0..32760.
    #[inline]
    pub fn ldr_unsigned(text: &mut Vec<u8>, rt: u32, rn: u32, imm_bytes: u32) {
        debug_assert_eq!(imm_bytes % 8, 0);
        let imm12 = imm_bytes / 8;
        emit(text, LDR_UNSIGNED | (imm12 << 10) | (rn << 5) | rt);
    }

    /// STR Xt, [Xn, #imm]  (unsigned offset, 64-bit)
    /// imm is in bytes, must be a multiple of 8, range 0..32760.
    #[inline]
    pub fn str_unsigned(text: &mut Vec<u8>, rt: u32, rn: u32, imm_bytes: u32) {
        debug_assert_eq!(imm_bytes % 8, 0);
        let imm12 = imm_bytes / 8;
        emit(text, STR_UNSIGNED | (imm12 << 10) | (rn << 5) | rt);
    }

    /// MOV Xd, Xn  (encoded as ADD Xd, Xn, #0)
    #[inline]
    pub fn mov_reg(text: &mut Vec<u8>, rd: u32, rn: u32) {
        emit(text, MOV_ADD_ZERO | (rn << 5) | rd);
    }

    /// MOVZ Xd, #imm16, LSL #shift  (shift = 0, 16, 32, or 48)
    #[inline]
    pub fn movz(text: &mut Vec<u8>, rd: u32, imm16: u16, shift: u32) {
        let hw = shift / 16;
        emit(text, MOVZ_64 | (hw << 21) | ((imm16 as u32) << 5) | rd);
    }

    /// MOVK Xd, #imm16, LSL #shift  (shift = 0, 16, 32, or 48)
    #[inline]
    pub fn movk(text: &mut Vec<u8>, rd: u32, imm16: u16, shift: u32) {
        let hw = shift / 16;
        emit(text, MOVK_64 | (hw << 21) | ((imm16 as u32) << 5) | rd);
    }

    /// Load a 64-bit immediate into Xd using MOVZ + up to 3 MOVK.
    pub fn mov_imm64(text: &mut Vec<u8>, rd: u32, val: u64) {
        let parts = [
            (val & 0xFFFF) as u16,
            ((val >> 16) & 0xFFFF) as u16,
            ((val >> 32) & 0xFFFF) as u16,
            ((val >> 48) & 0xFFFF) as u16,
        ];
        // Find the first non-zero part for MOVZ.
        let first = parts.iter().position(|&p| p != 0).unwrap_or(0);
        movz(text, rd, parts[first], first as u32 * 16);
        for i in (first + 1)..4 {
            if parts[i] != 0 {
                movk(text, rd, parts[i], i as u32 * 16);
            }
        }
    }

    /// BLR Xn  (branch with link to register)
    #[inline]
    pub fn blr(text: &mut Vec<u8>, rn: u32) {
        emit(text, BLR | (rn << 5));
    }

    /// RET
    #[inline]
    pub fn ret(text: &mut Vec<u8>) {
        emit(text, RET);
    }

    /// NOP
    #[inline]
    pub fn nop(text: &mut Vec<u8>) {
        emit(text, NOP);
    }

    /// ADD Xd, Xn, #imm12
    #[inline]
    pub fn add_imm(text: &mut Vec<u8>, rd: u32, rn: u32, imm12: u32) {
        emit(text, ADD_IMM | (imm12 << 10) | (rn << 5) | rd);
    }

    /// SUB Xd, Xn, #imm12
    #[inline]
    pub fn sub_imm(text: &mut Vec<u8>, rd: u32, rn: u32, imm12: u32) {
        emit(text, SUB_IMM | (imm12 << 10) | (rn << 5) | rd);
    }

    /// ADD Xd, Xn, Xm
    #[inline]
    pub fn add_reg(text: &mut Vec<u8>, rd: u32, rn: u32, rm: u32) {
        emit(text, ADD_REG | (rm << 16) | (rn << 5) | rd);
    }

    /// ADR Xd, label  (emit placeholder, return instruction offset)
    /// The immediate will be patched later by patch_adr_instruction.
    #[inline]
    pub fn adr_placeholder(text: &mut Vec<u8>, rd: u32) -> usize {
        let offset = text.len();
        emit(text, ADR | rd); // immhi/immlo = 0 → offset 0 (placeholder)
        offset
    }

    /// B.cond label  (emit placeholder with cond, return instruction offset)
    /// The immediate will be patched later by patch_bcond.
    #[inline]
    pub fn bcond_placeholder(text: &mut Vec<u8>, cond: u32) -> usize {
        let offset = text.len();
        emit(text, B_COND_BASE | cond);
        offset
    }

    /// CBNZ Xn, label  (emit placeholder, return instruction offset)
    #[inline]
    pub fn cbnz_placeholder(text: &mut Vec<u8>, rn: u32) -> usize {
        let offset = text.len();
        emit(text, CBNZ_64 | (rn << 5));
        offset
    }

    /// CBZ Xn, label  (emit placeholder, return instruction offset)
    #[inline]
    pub fn cbz_placeholder(text: &mut Vec<u8>, rn: u32) -> usize {
        let offset = text.len();
        emit(text, CBZ_64 | (rn << 5));
        offset
    }

    /// Patch a B.cond / CBNZ / CBZ conditional branch instruction.
    /// `instr_offset` is the byte offset of the 4-byte instruction.
    /// `target_offset` is the byte offset of the target instruction.
    pub fn patch_cond_branch(
        text: &mut [u8],
        instr_offset: usize,
        target_offset: usize,
        label: &str,
    ) -> anyhow::Result<()> {
        let instr_end = instr_offset + 4;
        if instr_end > text.len() || target_offset > text.len() {
            anyhow::bail!(
                "{label} branch patch out of range (instr={}, target={}, len={})",
                instr_offset,
                target_offset,
                text.len()
            );
        }
        let offset = (target_offset as isize - instr_offset as isize) >> 2;
        if offset < -(1 << 19) as isize || offset >= (1 << 19) as isize {
            anyhow::bail!("{label} conditional branch offset {offset:#x} out of ±1MiB range");
        }
        let existing = u32::from_le_bytes([
            text[instr_offset],
            text[instr_offset + 1],
            text[instr_offset + 2],
            text[instr_offset + 3],
        ]);
        // Clear imm19 (bits 23:5) and write new offset.
        let imm19 = (offset as u32) & 0x7FFFF;
        let patched = (existing & !(0x7FFFF << 5)) | (imm19 << 5);
        text[instr_offset..instr_end].copy_from_slice(&patched.to_le_bytes());
        Ok(())
    }

    /// LDRB Wt, [Xn, #imm]  (unsigned offset, 32-bit register, byte load)
    /// imm is in bytes, NOT scaled, range 0..4095.
    #[inline]
    pub fn ldrb(text: &mut Vec<u8>, rt: u32, rn: u32, imm: u32) {
        emit(text, LDRB_UNSIGNED | (imm << 10) | (rn << 5) | rt);
    }

    /// STRB Wt, [Xn, #imm]  (unsigned offset, byte store)
    /// imm is in bytes, NOT scaled, range 0..4095.
    #[inline]
    pub fn strb(text: &mut Vec<u8>, rt: u32, rn: u32, imm: u32) {
        emit(text, STRB_UNSIGNED | (imm << 10) | (rn << 5) | rt);
    }
}

// ─── AArch64 build_text_section ──────────────────────────────────────

#[cfg(target_arch = "aarch64")]
fn build_text_section(config: &EfiPayloadConfig) -> Result<TextSectionBuild> {
    use a64::*;

    let mut text = Vec::new();
    let mut embedded_payload_patch = None;
    let mut second_stage_patch = None;
    let mut original_bootloader_patch = None;

    // ─── Prologue ───────────────────────────────────────────────────────
    // x0 = ImageHandle, x1 = EFI_SYSTEM_TABLE*

    // Save FP, LR, and callee-saved registers.
    // STP x29, x30, [SP, #-96]!   (pre-decrement SP by 96)
    stp_pre(&mut text, FP, LR, SP, -96);
    // STP x19, x20, [SP, #16]     (signed offset)
    a64_store_pair_signed(&mut text, X19, X20, SP, 16);
    // STP x21, x22, [SP, #32]
    a64_store_pair_signed(&mut text, X21, X22, SP, 32);

    // Save ImageHandle → x19, SystemTable → x20
    mov_reg(&mut text, X19, X0);
    mov_reg(&mut text, X20, X1);

    // Cache BootServices*: ldr x21, [x20, #0x60]
    ldr_unsigned(&mut text, X21, X20, 0x60);

    if !config.payload_data.is_empty() {
        embedded_payload_patch = Some(if looks_like_pe_coff_image(&config.payload_data) {
            emit_embedded_efi_image_loader_a64(&mut text, config.payload_data.len())?
        } else {
            emit_raw_payload_loader_a64(&mut text, config)?
        });
    }

    if !config.second_stage_path.is_empty() {
        second_stage_patch = Some(emit_second_stage_loader_a64(&mut text)?);
    }

    if config.chain_to_original {
        original_bootloader_patch = Some(emit_original_bootloader_loader_a64(&mut text)?);
    }

    // ─── Return EFI_SUCCESS ─────────────────────────────────────────────
    // mov x0, #0  (EFI_SUCCESS)
    emit(&mut text, MOVZ_64 | (0u32 << 5) | X0);
    // Restore callee-saved registers.
    // LDP x21, x22, [SP, #32]
    a64_load_pair_signed(&mut text, X21, X22, SP, 32);
    // LDP x19, x20, [SP, #16]
    a64_load_pair_signed(&mut text, X19, X20, SP, 16);
    // LDP x29, x30, [SP], #96  (post-increment, restore SP)
    ldp_post(&mut text, FP, LR, SP, 96);
    ret(&mut text);

    // Pad to 16-byte alignment (AArch64 instructions are 4 bytes, so
    // pad with NOPs which are safe in the instruction stream).
    while text.len() % 16 != 0 {
        nop(&mut text);
    }

    Ok(TextSectionBuild {
        bytes: text,
        embedded_payload_patch,
        second_stage_patch,
        original_bootloader_patch,
    })
}

/// Helper: STP Xt1, Xt2, [Xn, #imm]  (signed offset, 64-bit)
/// Unlike the pre-indexed form, this does NOT write back to Rn.
#[cfg(target_arch = "aarch64")]
fn a64_store_pair_signed(text: &mut Vec<u8>, rt1: u32, rt2: u32, rn: u32, imm_bytes: i32) {
    use a64::*;
    // STP signed offset: 10 101 0 010 0 imm7 Rt2 Rn Rt
    let base: u32 = 0xA9000000;
    let imm7 = (imm_bytes >> 3) & 0x7F;
    emit(
        text,
        base | ((imm7 as u32) << 15) | (rt2 << 10) | (rn << 5) | rt1,
    );
}

/// Helper: LDP Xt1, Xt2, [Xn, #imm]  (signed offset, 64-bit)
#[cfg(target_arch = "aarch64")]
fn a64_load_pair_signed(text: &mut Vec<u8>, rt1: u32, rt2: u32, rn: u32, imm_bytes: i32) {
    use a64::*;
    // LDP signed offset: 10 101 0 010 1 imm7 Rt2 Rn Rt
    let base: u32 = 0xA9400000;
    let imm7 = (imm_bytes >> 3) & 0x7F;
    emit(
        text,
        base | ((imm7 as u32) << 15) | (rt2 << 10) | (rn << 5) | rt1,
    );
}

/// AArch64 embedded EFI PE/COFF image loader.
///
/// BootServices->LoadImage(0, ImageHandle, NULL, SourceBuffer, SourceSize, &new_handle)
/// BootServices->StartImage(new_handle, NULL, NULL)
#[cfg(target_arch = "aarch64")]
fn emit_embedded_efi_image_loader_a64(
    mut text: &mut Vec<u8>,
    payload_len: usize,
) -> Result<AdrPatch> {
    use a64::*;

    // Subroutine prologue: save scratch regs we'll use.
    // STP x22, x23, [SP, #-16]!  (save temporaries)
    stp_pre(&mut text, X22, X23, SP, -16);

    // ADR x3, payload_data  (will be patched to point into .rdata)
    let payload_instr = adr_placeholder(&mut text, X3);

    // x0 = 0 (ParentImageHandle = NULL for from-buffer load)
    //   Actually UEFI spec says BootServices->LoadImage first arg is
    //   BOOLEAN ParentImageHandle... but on AArch64 it's passed as UINTN.
    //   UEFI LoadImage: arg0=BootPolicy, arg1=ParentImageHandle, arg2=DevicePath,
    //                   arg3=SourceBuffer, arg4=SourceSize, arg5=&ImageHandle
    movz(&mut text, X0, 0, 0); // BootPolicy = FALSE
    mov_reg(&mut text, X1, X19); // ParentImageHandle = ImageHandle
    movz(&mut text, X2, 0, 0); // DevicePath = NULL
                               // x3 already = SourceBuffer (from ADR above)
    mov_imm64(&mut text, X4, payload_len as u64); // SourceSize
    add_imm(&mut text, X5, SP, 16); // &new_handle on stack (above saved regs)

    // ldr x8, [x21, #0xC8]  (BootServices->LoadImage)
    ldr_unsigned(&mut text, X8, X21, 0xC8);
    blr(&mut text, X8);

    // cbnz x0, load_failed
    let load_failed = cbnz_placeholder(&mut text, X0);

    // Load new_handle from stack and call StartImage.
    ldr_unsigned(&mut text, X0, SP, 16); // x0 = new_handle
    movz(&mut text, X1, 0, 0); // ExitDataSize = NULL
    movz(&mut text, X2, 0, 0); // ExitData = NULL
    ldr_unsigned(&mut text, X8, X21, 0xD0); // BootServices->StartImage
    blr(&mut text, X8);

    let done = text.len();

    // load_failed:
    a64::patch_cond_branch(text, load_failed, done, "LoadImage failed")?;

    // Restore temporaries.
    ldp_post(&mut text, X22, X23, SP, 16);

    Ok(AdrPatch {
        instr_offset: payload_instr,
    })
}

/// AArch64 raw payload loader.
///
/// BootServices->AllocatePages(AllocateAnyPages, EfiLoaderCode, pages, &entry_buf)
/// memcpy from .rdata to allocated pages
/// call entry_buf + entry_point_offset(ImageHandle, SystemTable)
#[cfg(target_arch = "aarch64")]
fn emit_raw_payload_loader_a64(
    mut text: &mut Vec<u8>,
    config: &EfiPayloadConfig,
) -> Result<AdrPatch> {
    use a64::*;

    let pages = payload_pages(config.payload_data.len())?;

    // Save temporaries.
    stp_pre(&mut text, X22, X23, SP, -16);

    // AllocatePages(AllocateAnyPages=0, EfiLoaderCode=2, pages, &entry_buf)
    movz(&mut text, X0, 0, 0); // AllocateAnyPages
    movz(&mut text, X1, 2, 0); // EfiLoaderCode
    mov_imm64(&mut text, X2, pages as u64); // NumberOfPages
    add_imm(&mut text, X3, SP, 16); // &entry_buf on stack
    ldr_unsigned(&mut text, X8, X21, 0x28); // BootServices->AllocatePages
    blr(&mut text, X8);
    let alloc_failed = cbnz_placeholder(&mut text, X0);

    // Load entry_buf from stack.
    ldr_unsigned(&mut text, X22, SP, 16); // x22 = entry_buf

    // ADR x2, payload_data  (source = .rdata, will be patched)
    let payload_instr = adr_placeholder(&mut text, X2);

    // x0 = entry_buf (destination)
    mov_reg(&mut text, X0, X22);

    // x1 = payload_len
    mov_imm64(&mut text, X1, config.payload_data.len() as u64);

    // Manual memcpy loop: copy bytes from x2 to x0, length in x1.
    // Use a simple byte-copy loop to avoid alignment issues.
    // Save loop registers.
    emit(&mut text, 0xD503201F); // NOP (alignment padding)
                                 // loop:
    let loop_start = text.len();
    // cbz x1, done_copy
    let copy_done = cbz_placeholder(&mut text, X1);
    // ldrb w3, [x2], #1  (post-indexed load byte)
    // LDRB w3, [x2, #0] then ADD x2, x2, #1
    ldrb(&mut text, X3, X2, 0);
    add_imm(&mut text, X2, X2, 1);
    // strb w3, [x0], #1  (post-indexed store byte)
    strb(&mut text, X3, X0, 0);
    add_imm(&mut text, X0, X0, 1);
    // sub x1, x1, #1
    sub_imm(&mut text, X1, X1, 1);
    // b loop_start
    let loop_branch = text.len();
    emit(&mut text, 0x14000000u32); // B (unconditional) placeholder
                                    // Patch the B instruction.
    {
        let offset = (loop_start as isize - loop_branch as isize) >> 2;
        let imm26 = (offset as u32) & 0x3FFFFFF;
        let instr = 0x14000000u32 | imm26;
        text[loop_branch..loop_branch + 4].copy_from_slice(&instr.to_le_bytes());
    }

    // done_copy:
    let done_copy_offset = text.len();
    a64::patch_cond_branch(text, copy_done, done_copy_offset, "copy_done")?;

    // Compute entry point: entry_buf + entry_point_offset
    mov_reg(&mut text, X0, X22); // x0 = entry_buf
    if config.entry_point_offset != 0 {
        add_imm(&mut text, X0, X0, config.entry_point_offset);
    }

    // Call entry_buf(ImageHandle, SystemTable)
    mov_reg(&mut text, X8, X0); // x8 = entry point address
    mov_reg(&mut text, X0, X19); // x0 = ImageHandle
    mov_reg(&mut text, X1, X20); // x1 = SystemTable
    blr(&mut text, X8);

    let done = text.len();
    a64::patch_cond_branch(text, alloc_failed, done, "AllocatePages failed")?;

    // Restore temporaries.
    ldp_post(&mut text, X22, X23, SP, 16);

    Ok(AdrPatch {
        instr_offset: payload_instr,
    })
}

/// AArch64 second-stage loader (same as path image loader).
#[cfg(target_arch = "aarch64")]
fn emit_second_stage_loader_a64(text: &mut Vec<u8>) -> Result<PathLoaderPatchesA64> {
    emit_path_image_loader_a64(text)
}

/// AArch64 original bootloader loader (same as path image loader).
#[cfg(target_arch = "aarch64")]
fn emit_original_bootloader_loader_a64(text: &mut Vec<u8>) -> Result<PathLoaderPatchesA64> {
    emit_path_image_loader_a64(text)
}

/// AArch64 path image loader.
///
/// 1) OpenProtocol(ImageHandle, &EFI_LOADED_IMAGE_PROTOCOL_GUID,
///                 &iface, ImageHandle, NULL, BY_HANDLE_PROTOCOL)
/// 2) LoadedImage->DeviceHandle (offset 0x18)
/// 3) LoadImage(FALSE, ImageHandle, DevicePath, DeviceHandle, NULL, &new_handle)
/// 4) StartImage(new_handle, NULL, NULL)
#[cfg(target_arch = "aarch64")]
fn emit_path_image_loader_a64(mut text: &mut Vec<u8>) -> Result<PathLoaderPatchesA64> {
    use a64::*;

    // Save temporaries: x22-x25
    stp_pre(&mut text, X22, X23, SP, -32);
    a64_store_pair_signed(&mut text, X24, X25, SP, 16);

    // OpenProtocol(ImageHandle, &GUID, &iface, ImageHandle, NULL, BY_HANDLE_PROTOCOL)
    // x0 = ImageHandle
    mov_reg(&mut text, X0, X19);
    // x1 = &EFI_LOADED_IMAGE_PROTOCOL_GUID  (ADR, to be patched)
    let guid_instr = adr_placeholder(&mut text, X1);
    // x2 = &iface (on stack)
    add_imm(&mut text, X2, SP, 48); // above saved regs
                                    // x3 = ImageHandle (AgentHandle)
    mov_reg(&mut text, X3, X19);
    // x4 = NULL (ControllerHandle)
    movz(&mut text, X4, 0, 0);
    // x5 = EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL (0x20)
    movz(
        &mut text,
        X5,
        EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL as u16,
        0,
    );
    ldr_unsigned(&mut text, X8, X21, 0x118); // BootServices->OpenProtocol
    blr(&mut text, X8);
    let open_failed = cbnz_placeholder(&mut text, X0);

    // Check iface is non-null.
    ldr_unsigned(&mut text, X22, SP, 48); // x22 = loaded_image_iface
    let null_iface = cbz_placeholder(&mut text, X22);

    // x9 = LoadedImage->DeviceHandle (offset 0x18)
    ldr_unsigned(&mut text, X9, X22, 0x18);
    let null_device = cbz_placeholder(&mut text, X9);

    // LoadImage(FALSE, ImageHandle, DevicePath, DeviceHandle, NULL, &new_handle)
    movz(&mut text, X0, 0, 0); // BootPolicy = FALSE
    mov_reg(&mut text, X1, X19); // ParentImageHandle
                                 // x2 = DevicePath (ADR, to be patched)
    let dp_instr = adr_placeholder(&mut text, X2);
    mov_reg(&mut text, X3, X9); // DeviceHandle
    movz(&mut text, X4, 0, 0); // SourceSize = 0 (from device)
    add_imm(&mut text, X5, SP, 56); // &new_handle
    ldr_unsigned(&mut text, X8, X21, 0xC8); // BootServices->LoadImage
    blr(&mut text, X8);
    let load_failed = cbnz_placeholder(&mut text, X0);

    // StartImage(new_handle, NULL, NULL)
    ldr_unsigned(&mut text, X0, SP, 56); // x0 = new_handle
    movz(&mut text, X1, 0, 0); // ExitDataSize = NULL
    movz(&mut text, X2, 0, 0); // ExitData = NULL
    ldr_unsigned(&mut text, X8, X21, 0xD0); // BootServices->StartImage
    blr(&mut text, X8);

    let done = text.len();

    // Patch all error branches to jump to 'done'.
    a64::patch_cond_branch(text, open_failed, done, "OpenProtocol failed")?;
    a64::patch_cond_branch(text, null_iface, done, "null loaded_image_iface")?;
    a64::patch_cond_branch(text, null_device, done, "null DeviceHandle")?;
    a64::patch_cond_branch(text, load_failed, done, "LoadImage failed")?;

    // Restore temporaries.
    a64_load_pair_signed(&mut text, X24, X25, SP, 16);
    ldp_post(&mut text, X22, X23, SP, 32);

    Ok(PathLoaderPatchesA64 {
        device_path_patch: AdrPatch {
            instr_offset: dp_instr,
        },
        loaded_image_guid_patch: AdrPatch {
            instr_offset: guid_instr,
        },
    })
}

/// Build the .rdata section containing the payload data and configuration.
fn build_rdata_section(config: &EfiPayloadConfig) -> Result<Vec<u8>> {
    let mut rdata = Vec::new();

    // ─── Payload Header ─────────────────────────────────────────────────
    // Magic: "ORCH" (4 bytes).
    rdata.extend_from_slice(b"ORCH");

    // Version: 1 (u32 LE).
    rdata.extend_from_slice(&1u32.to_le_bytes());

    // Payload size (u32 LE).
    rdata.extend_from_slice(&(config.payload_data.len() as u32).to_le_bytes());

    // Flags (u32 LE): 0 = embedded payload, 1 = second-stage path.
    let flags: u32 = if config.second_stage_path.is_empty() {
        0
    } else {
        1
    };
    rdata.extend_from_slice(&flags.to_le_bytes());

    // Second-stage path length (u32 LE).
    let path_bytes = config.second_stage_path.as_bytes();
    rdata.extend_from_slice(&(path_bytes.len() as u32).to_le_bytes());

    // Second-stage path (UTF-8, null-terminated).
    rdata.extend_from_slice(path_bytes);
    rdata.push(0x00);

    // Align to 16 bytes.
    while rdata.len() % 16 != 0 {
        rdata.push(0x00);
    }

    // ─── Payload Data ───────────────────────────────────────────────────
    if !config.payload_data.is_empty() {
        rdata.extend_from_slice(&config.payload_data);
    }

    // Align to 16 bytes.
    while rdata.len() % 16 != 0 {
        rdata.push(0x00);
    }

    // GUID blob used by the .text chain-loader to resolve
    // EFI_LOADED_IMAGE_PROTOCOL via OpenProtocol.
    rdata.extend_from_slice(&EFI_LOADED_IMAGE_PROTOCOL_GUID);

    while rdata.len() % 16 != 0 {
        rdata.push(0x00);
    }

    // ─── FILE_PATH Device Path Nodes ───────────────────────────────────
    // Structure (per UEFI spec 9.3):
    //   Media Device Path (type 4) / File Path (subtype 4):
    //     UINT8  Type        = 0x04
    //     UINT8  SubType     = 0x04
    //     UINT16 Length      = 4 + 2*(wchar_count_including_null)
    //     CHAR16 PathName[]  (UTF-16 LE, null-terminated)
    //   End of Hardware Device Path:
    //     UINT8  Type        = 0x7F
    //     UINT8  SubType     = 0xFF
    //     UINT16 Length      = 4
    if !config.second_stage_path.is_empty() {
        append_file_path_device_path(&mut rdata, &config.second_stage_path)?;
    }

    if config.chain_to_original {
        append_file_path_device_path(&mut rdata, &config.original_bootloader_path)?;
    }

    Ok(rdata)
}

fn append_file_path_device_path(rdata: &mut Vec<u8>, path: &str) -> Result<()> {
    let path_utf16: Vec<u16> = path.encode_utf16().chain(std::iter::once(0u16)).collect();
    let path_utf16_bytes = path_utf16
        .len()
        .checked_mul(2)
        .context("EFI FILE_PATH byte length overflow")?;
    let node_length_usize = 4usize
        .checked_add(path_utf16_bytes)
        .context("EFI FILE_PATH node length overflow")?;
    let node_length = u16::try_from(node_length_usize)
        .with_context(|| format!("EFI FILE_PATH node is too long for path {path:?}"))?;

    rdata.push(0x04);
    rdata.push(0x04);
    rdata.extend_from_slice(&node_length.to_le_bytes());

    for &w in &path_utf16 {
        rdata.extend_from_slice(&w.to_le_bytes());
    }

    rdata.push(0x7F);
    rdata.push(0xFF);
    rdata.extend_from_slice(&4u16.to_le_bytes());

    while rdata.len() % 16 != 0 {
        rdata.push(0x00);
    }

    Ok(())
}

/// Build the .reloc section.
///
/// Contains a minimal relocation table for the entry point.
fn build_reloc_section() -> Vec<u8> {
    let mut reloc = Vec::new();

    // Base Relocation Block Header.
    // VirtualAddress: page RVA (0x1000 = start of .text).
    reloc.extend_from_slice(&0x1000u32.to_le_bytes());

    // SizeOfBlock: 8 (header) + 2 (one entry) = 12, but must be aligned to 4.
    // Actually, minimum block is 8 bytes header + N×2 bytes entries.
    // For no relocations, we just have the header with SizeOfBlock=8.
    reloc.extend_from_slice(&8u32.to_le_bytes());

    // No relocation entries needed for position-independent EFI code
    // (we use RIP-relative addressing).

    reloc
}

/// Align a value up to the given alignment.
fn align_up(value: u32, alignment: u32) -> u32 {
    (value + alignment - 1) & !(alignment - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_payload_config() -> EfiPayloadConfig {
        EfiPayloadConfig {
            payload_data: vec![0xCC; 64], // INT3 sled.
            second_stage_path: String::new(),
            entry_point_offset: 0,
            chain_to_original: true,
            original_bootloader_path: String::from(r"\EFI\Microsoft\Boot\bootmgfw.efi"),
        }
    }

    fn minimal_pe_payload() -> Vec<u8> {
        let mut payload = vec![0u8; 0x80];
        payload[0..2].copy_from_slice(b"MZ");
        payload[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        payload[0x40..0x44].copy_from_slice(b"PE\0\0");
        payload
    }

    fn utf16_path_bytes(path: &str) -> Vec<u8> {
        path.encode_utf16()
            .chain(std::iter::once(0u16))
            .flat_map(u16::to_le_bytes)
            .collect()
    }

    #[test]
    fn build_efi_stub_produces_valid_pe() {
        let config = test_payload_config();
        let result = build_efi_stub(&config).unwrap();

        // Verify DOS magic.
        assert_eq!(result.binary[0], b'M');
        assert_eq!(result.binary[1], b'Z');

        // Verify PE signature.
        let pe_offset = u32::from_le_bytes([
            result.binary[0x3C],
            result.binary[0x3D],
            result.binary[0x3E],
            result.binary[0x3F],
        ]) as usize;
        assert_eq!(&result.binary[pe_offset..pe_offset + 4], b"PE\0\0");

        // Verify subsystem is EFI_APPLICATION.
        let coff_offset = pe_offset + 4;
        let opt_offset = coff_offset + 20;
        let subsystem_offset = opt_offset + 68;
        let subsystem = u16::from_le_bytes([
            result.binary[subsystem_offset],
            result.binary[subsystem_offset + 1],
        ]);
        assert_eq!(subsystem, IMAGE_SUBSYSTEM_EFI_APPLICATION);

        // Verify machine type.
        let machine =
            u16::from_le_bytes([result.binary[coff_offset], result.binary[coff_offset + 1]]);
        assert_eq!(machine, target_machine_type());
    }

    #[test]
    fn build_efi_stub_contains_payload() {
        let config = test_payload_config();
        let result = build_efi_stub(&config).unwrap();

        // Search for payload magic.
        assert!(
            find_subsequence(&result.binary, b"ORCH"),
            "Payload magic 'ORCH' not found in binary"
        );

        // Search for payload data (INT3 sled).
        assert!(
            find_subsequence(&result.binary, &[0xCC; 16]),
            "Payload INT3 sled not found in binary"
        );

        // Architecture-specific: verify raw payload loader calls AllocatePages.
        #[cfg(not(target_arch = "aarch64"))]
        {
            assert!(
                find_subsequence(&result.binary, &[0x41, 0xFF, 0x96, 0x28, 0, 0, 0]),
                "Raw payload path should allocate EFI_LOADER_CODE pages via BootServices->AllocatePages"
            );
            assert!(
                !find_subsequence(&result.binary, &[0x48, 0x8D, 0x3D]),
                "Raw payload path must not jump directly into .rdata"
            );
        }
        #[cfg(target_arch = "aarch64")]
        {
            // AArch64: BootServices->AllocatePages is at offset 0x28, loaded via
            // LDR X8, [X21, #0x28].  The unsigned-offset encoding of LDR X8, [X21, #0x28]
            // is 0xF940D168 (imm12=5, Rn=21, Rt=8).
            assert!(
                find_subsequence(&result.binary, &0xF940D168u32.to_le_bytes()),
                "Raw payload path should load BootServices->AllocatePages on AArch64"
            );
        }
    }

    #[test]
    fn build_efi_stub_embedded_pe_uses_load_image() {
        let config = EfiPayloadConfig {
            payload_data: minimal_pe_payload(),
            second_stage_path: String::new(),
            entry_point_offset: 0,
            chain_to_original: false,
            original_bootloader_path: String::new(),
        };
        let result = build_efi_stub(&config).unwrap();

        #[cfg(not(target_arch = "aarch64"))]
        {
            assert!(
                find_subsequence(&result.binary, &[0x4C, 0x8D, 0x0D]),
                "Embedded PE path should pass SourceBuffer via r9"
            );
            assert!(
                find_subsequence(&result.binary, &[0x41, 0xFF, 0x96, 0xC8, 0, 0, 0]),
                "Embedded PE path should call BootServices->LoadImage"
            );
        }
        #[cfg(target_arch = "aarch64")]
        {
            // AArch64: BootServices->LoadImage is at offset 0xC8, loaded via
            // LDR X8, [X21, #0xC8].  Encoding: imm12=25, Rn=21, Rt=8 → 0xF9419468.
            assert!(
                find_subsequence(&result.binary, &0xF9419468u32.to_le_bytes()),
                "Embedded PE path should load BootServices->LoadImage on AArch64"
            );
        }
    }

    #[test]
    fn raw_payload_entry_offset_must_be_in_bounds() {
        let mut config = test_payload_config();
        config.entry_point_offset = config.payload_data.len() as u32;

        assert!(build_efi_stub(&config).is_err());
    }

    #[test]
    fn build_efi_stub_size_reasonable() {
        let config = test_payload_config();
        let result = build_efi_stub(&config).unwrap();

        // The stub should be at least 2048 bytes (headers + sections).
        assert!(
            result.size >= 2048,
            "Stub size {} is too small",
            result.size
        );

        // The stub should not be excessively large.
        assert!(
            result.size < 1024 * 1024,
            "Stub size {} is too large",
            result.size
        );
    }

    #[test]
    fn build_efi_stub_sha256_valid() {
        let config = test_payload_config();
        let result = build_efi_stub(&config).unwrap();

        assert_eq!(result.sha256_hash.len(), 64);
        // Verify the hash is hex.
        for c in result.sha256_hash.chars() {
            assert!(c.is_ascii_hexdigit());
        }
    }

    #[test]
    fn build_efi_stub_rejects_empty_config() {
        let config = EfiPayloadConfig {
            payload_data: Vec::new(),
            second_stage_path: String::new(),
            entry_point_offset: 0,
            chain_to_original: false,
            original_bootloader_path: String::new(),
        };
        assert!(build_efi_stub(&config).is_err());
    }

    #[test]
    fn build_efi_stub_second_stage() {
        let config = EfiPayloadConfig {
            payload_data: Vec::new(),
            second_stage_path: String::from(r"\EFI\Boot\loader.efi"),
            entry_point_offset: 0,
            chain_to_original: true,
            original_bootloader_path: String::from(r"\EFI\Microsoft\Boot\bootmgfw.efi"),
        };
        let result = build_efi_stub(&config).unwrap();

        // Verify the path is embedded.
        assert!(
            find_subsequence(&result.binary, b"\\EFI\\Boot\\loader.efi"),
            "Second-stage path not found in binary"
        );
    }

    #[test]
    fn build_efi_stub_chain_to_original_embeds_original_device_path() {
        let original_path = r"\EFI\Microsoft\Boot\bootmgfw.efi";
        let config = EfiPayloadConfig {
            payload_data: minimal_pe_payload(),
            second_stage_path: String::new(),
            entry_point_offset: 0,
            chain_to_original: true,
            original_bootloader_path: original_path.to_string(),
        };
        let result = build_efi_stub(&config).unwrap();

        assert!(
            find_subsequence(&result.binary, &utf16_path_bytes(original_path)),
            "Original bootloader path should be embedded as an EFI FILE_PATH device path"
        );
        #[cfg(not(target_arch = "aarch64"))]
        assert!(
            find_subsequence(&result.binary, &[0x41, 0xFF, 0x96, 0xC8, 0, 0, 0]),
            "Original bootloader path should be loaded through BootServices->LoadImage"
        );
        #[cfg(target_arch = "aarch64")]
        assert!(
            find_subsequence(&result.binary, &0xF9419468u32.to_le_bytes()),
            "Original bootloader path should be loaded through BootServices->LoadImage on AArch64"
        );
    }

    #[test]
    fn chain_to_original_requires_original_bootloader_path() {
        let config = EfiPayloadConfig {
            payload_data: minimal_pe_payload(),
            second_stage_path: String::new(),
            entry_point_offset: 0,
            chain_to_original: true,
            original_bootloader_path: String::new(),
        };

        assert!(build_efi_stub(&config).is_err());
    }

    #[test]
    fn dos_header_pe_offset_correct() {
        let dos = build_dos_header();
        let pe_offset = u32::from_le_bytes([dos[0x3C], dos[0x3D], dos[0x3E], dos[0x3F]]);
        assert_eq!(pe_offset, DOS_HEADER_SIZE as u32);
    }

    #[test]
    fn align_up_works() {
        assert_eq!(align_up(0, 0x200), 0);
        assert_eq!(align_up(1, 0x200), 0x200);
        assert_eq!(align_up(0x200, 0x200), 0x200);
        assert_eq!(align_up(0x201, 0x200), 0x400);
        assert_eq!(align_up(0x1000, 0x1000), 0x1000);
    }

    #[test]
    fn section_header_layout() {
        let hdr = build_section_header(
            b".text\0\0\0",
            0x200,
            0x1000,
            0x200,
            0x200,
            IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
        );
        assert_eq!(&hdr[0..6], b".text\0");
        assert_eq!(hdr.len(), 40);
    }

    fn find_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }
}
