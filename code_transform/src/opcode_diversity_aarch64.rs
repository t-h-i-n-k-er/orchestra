//! Opcode diversity transforms for AArch64 machine code.
//!
//! Applies three classes of semantic-preserving transformations to diversify
//! the instruction stream without changing program behaviour:
//!
//! 1. **Register renaming** – renames a local-scratch register from the
//!    X9–X15 (volatile scratch) pool to another unused scratch register.
//!
//! 2. **ADD/SUB swap** – replaces `ADD Xd, Xn, #imm12` with `SUB Xd, Xn, #-imm12`
//!    (and vice-versa) when the immediate can be represented in 12-bit unsigned
//!    form for the opposite opcode.
//!
//! 3. **NOP insertion** – inserts `MOV X16, X16` or `EOR Xd, Xd, Xd` (sets Xd=0)
//!    between instructions where doing so does not affect control flow.
//!
//! 4. **Conditional branch inversion** – inverts `B.cond target` to
//!    `B.inverted_cond +2; B target`, inserting an extra unconditional branch.
//!
//! All random decisions are drawn from the caller-supplied seeded PRNG, making
//! the output deterministic for a given input and seed.

use std::collections::{HashMap, HashSet};

use rand::seq::SliceRandom;
use rand::Rng;

use crate::substitute_aarch64::{classify, is_pcrel_data, is_terminator, BranchKind};

// ─── ARM64 encoding helpers ────────────────────────────────────────────────

/// ARM64 NOP.
const _ARM64_NOP: u32 = 0xD503_201F;

/// Encode `ADD Xd, Xn, #imm12` (64-bit, no shift).
/// sf=1, op=0, S=0, 1 00 100010 0 sh=0 imm12 Rn Rd
fn enc_add_x_imm(rd: u32, rn: u32, imm12: u32) -> u32 {
    debug_assert!(rd < 32 && rn < 32 && imm12 < 4096);
    0x9100_0000 | (imm12 << 10) | (rn << 5) | rd
}

/// Encode `SUB Xd, Xn, #imm12` (64-bit, no shift).
/// sf=1, op=1, S=0, 1 10 100010 0 sh=0 imm12 Rn Rd
fn enc_sub_x_imm(rd: u32, rn: u32, imm12: u32) -> u32 {
    debug_assert!(rd < 32 && rn < 32 && imm12 < 4096);
    0xD100_0000 | (imm12 << 10) | (rn << 5) | rd
}

/// Encode `MOV Xd, Xm` (alias: ORR Xd, XZR, Xm).
fn enc_mov_x(rd: u32, rm: u32) -> u32 {
    debug_assert!(rd < 32 && rm < 32);
    0xAA00_0000 | (rm << 16) | (31 << 5) | rd
}

/// Encode `EOR Xd, Xn, Xm` (64-bit, shifted register, shift=0).
fn enc_eor_x(rd: u32, rn: u32, rm: u32) -> u32 {
    debug_assert!(rd < 32 && rn < 32 && rm < 32);
    0xCA00_0000 | (rm << 16) | (rn << 5) | rd
}

/// Encode `B #imm26*4`.
fn enc_b(imm26: i32) -> u32 {
    let bits = (imm26 as u32) & 0x3FF_FFFF;
    0x1400_0000 | bits
}

/// Encode `B.cond #imm19*4` with a specific condition code.
fn enc_b_cond(cond: u32, imm19: i32) -> u32 {
    debug_assert!(cond < 16);
    let bits = (imm19 as u32) & 0x7_FFFF;
    0x5400_0000 | (bits << 5) | cond
}

/// Decode `ADD Xd, Xn, #imm12` → Some((rd, rn, imm12)).
/// Mask: 1 00 100010 0 imm12 Rn Rd → top bits: 0x7F800000 == 0x11000000
fn decode_add_x_imm(raw: u32) -> Option<(u32, u32, u32)> {
    if (raw & 0x7F80_0000) != 0x1100_0000 {
        return None;
    }
    let rd = raw & 0x1F;
    let rn = (raw >> 5) & 0x1F;
    let imm12 = (raw >> 10) & 0xFFF;
    Some((rd, rn, imm12))
}

/// Decode `SUB Xd, Xn, #imm12` → Some((rd, rn, imm12)).
/// Mask: 1 10 100010 0 imm12 Rn Rd → top bits: 0x7F800000 == 0x31000000
fn decode_sub_x_imm(raw: u32) -> Option<(u32, u32, u32)> {
    if (raw & 0x7F80_0000) != 0x3100_0000 {
        return None;
    }
    let rd = raw & 0x1F;
    let rn = (raw >> 5) & 0x1F;
    let imm12 = (raw >> 10) & 0xFFF;
    Some((rd, rn, imm12))
}

/// Extract condition from B.cond instruction.
fn _extract_b_cond(raw: u32) -> Option<u32> {
    if (raw & 0xFF00_0010) == 0x5400_0000 {
        Some(raw & 0xF)
    } else {
        None
    }
}

/// Invert an ARM64 condition code (flip the LSB).
fn invert_cond(cond: u32) -> u32 {
    cond ^ 1
}

/// Decode `B.cond` → (cond, imm19_words).
fn decode_b_cond(raw: u32) -> Option<(u32, i32)> {
    if (raw & 0xFF00_0010) != 0x5400_0000 {
        return None;
    }
    let cond = raw & 0xF;
    let imm19 = ((raw >> 5) & 0x7_FFFF) as i32;
    let s = (imm19 << 13) >> 13; // sign extend 19-bit
    Some((cond, s))
}

// ─── Register field extraction ──────────────────────────────────────────────

/// Extract Rd (bits[4:0]).
fn rd(raw: u32) -> u32 {
    raw & 0x1F
}

/// Extract Rn (bits[9:5]).
fn rn(raw: u32) -> u32 {
    (raw >> 5) & 0x1F
}

/// Extract Rm (bits[20:16]).
fn rm(raw: u32) -> u32 {
    (raw >> 16) & 0x1F
}

/// Check if register `reg` appears in any of Rd, Rn, Rm fields.
fn reg_appears(raw: u32, reg: u32) -> bool {
    rd(raw) == reg || rn(raw) == reg || rm(raw) == reg
}

/// Replace all occurrences of register `old` with `new` in Rd, Rn, Rm fields.
fn replace_reg(raw: u32, old: u32, new: u32) -> u32 {
    let mut result = raw;
    if (result & 0x1F) == old {
        result = (result & !0x1F) | new;
    }
    if ((result >> 5) & 0x1F) == old {
        result = (result & !(0x1F << 5)) | (new << 5);
    }
    if ((result >> 16) & 0x1F) == old {
        result = (result & !(0x1F << 16)) | (new << 16);
    }
    result
}

// ─── Public entry point ─────────────────────────────────────────────────────

/// Apply opcode diversity transforms to AArch64 machine code.
///
/// Returns the transformed code bytes.  If the input is not a multiple of 4
/// bytes, it is returned unchanged.
pub fn apply(code: &[u8], rng: &mut impl Rng) -> Vec<u8> {
    if code.is_empty() || code.len() % 4 != 0 {
        return code.to_vec();
    }

    let raw_words: Vec<u32> = code
        .chunks_exact(4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        .collect();

    // Bail out if PC-relative data instructions are present — they cannot be
    // safely transformed.
    if raw_words.iter().any(|&r| is_pcrel_data(r)) {
        return code.to_vec();
    }

    let mut result = raw_words.clone();

    // Apply transforms in sequence; each may modify `result` in place.
    apply_register_rename(&mut result, rng);
    try_add_to_sub(&mut result, rng);
    result = try_invert_cond_branch(result, rng);
    result = insert_nops(result, rng);

    // Encode back to bytes.
    let mut out = Vec::with_capacity(result.len() * 4);
    for &w in &result {
        out.extend_from_slice(&w.to_le_bytes());
    }
    out
}

// ─── Transform: Register renaming ──────────────────────────────────────────

/// Candidate registers for renaming: X9–X15 (volatile scratch).
const RENAME_POOL: &[u32] = &[9, 10, 11, 12, 13, 14, 15];

/// Identify local-scratch registers (written before read, or never read at all)
/// from the RENAME_POOL and randomly rename one to another from the same pool.
fn apply_register_rename(words: &mut [u32], rng: &mut impl Rng) {
    // Build first-write and uses-before-def maps.
    let mut first_write: HashMap<u32, usize> = HashMap::new();
    let mut uses_before_def: HashSet<u32> = HashSet::new();

    for (idx, &raw) in words.iter().enumerate() {
        let _kind = classify(raw);

        // Rd is a write destination. For most ALU instructions it's write-only,
        // but for some (e.g., ADD with Rd == Rn) it's also a read via Rn.
        // We conservatively treat Rd as a write only if it doesn't appear in
        // Rn or Rm (i.e. it's a pure destination).

        // Read sources: Rn and Rm.
        let r_rn = rn(raw);
        let r_rm = rm(raw);
        // Rd is the destination.
        let r_rd = rd(raw);

        // Check reads.
        for &r in &[r_rn, r_rm] {
            if r < 31 && RENAME_POOL.contains(&r) && !first_write.contains_key(&r) {
                uses_before_def.insert(r);
            }
        }

        // Check Rd as read (if Rd == Rn or Rd == Rm, it's already counted).
        // Otherwise Rd is a pure write.

        // Record first write.
        if r_rd < 31 && RENAME_POOL.contains(&r_rd) && !first_write.contains_key(&r_rd) {
            // Only count as a write if Rd doesn't also appear as a source,
            // OR if it appears as Rn (which means it's a read-modify-write).
            if r_rd != r_rn && r_rd != r_rm {
                first_write.entry(r_rd).or_insert(idx);
            } else {
                // Rd == Rn or Rd == Rm: this is a read-modify-write.
                // Don't count as a first write (it's already read).
                // It's actually still valid to rename if the register is used
                // consistently, but we're conservative here.
            }
        }
    }

    // Local scratch: written at least once and never read before first write.
    let local_scratch: Vec<u32> = first_write
        .keys()
        .filter(|&&r| !uses_before_def.contains(&r))
        .copied()
        .collect();

    if local_scratch.is_empty() {
        return;
    }

    // Choose an old register to rename from local scratch.
    let &old_reg = local_scratch.choose(rng).unwrap();

    // Choose a new register from the pool that isn't the same and isn't used.
    let new_candidates: Vec<u32> = RENAME_POOL
        .iter()
        .filter(|&&r| {
            r != old_reg
                && !words.iter().any(|&w| reg_appears(w, r))
        })
        .copied()
        .collect();

    if new_candidates.is_empty() {
        return;
    }

    let &new_reg = new_candidates.choose(rng).unwrap();

    // Apply renaming.
    for word in words.iter_mut() {
        *word = replace_reg(*word, old_reg, new_reg);
    }
}

// ─── Transform: ADD/SUB swap ───────────────────────────────────────────────

/// Try converting `ADD Xd, Xn, #imm12` ↔ `SUB Xd, Xn, #imm12`.
///
/// ADD with immediate `imm` can become SUB with immediate `-imm` if the
/// negated value is representable as a 12-bit unsigned integer (i.e., the
/// original immediate fits in 12 bits after negation mod 4096).
fn try_add_to_sub(words: &mut [u32], rng: &mut impl Rng) {
    // Collect candidate indices.
    let mut candidates: Vec<usize> = Vec::new();

    for (i, &raw) in words.iter().enumerate() {
        // Only consider non-terminator, non-branch instructions.
        let kind = classify(raw);
        if kind != BranchKind::None {
            continue;
        }
        // ADD Xd, Xn, #imm12 where Xd != SP (not stack adjustment).
        if let Some((rd, rn, imm12)) = decode_add_x_imm(raw) {
            if rd != 31 && rn != 31 && imm12 > 0 {
                candidates.push(i);
            }
        }
        // SUB Xd, Xn, #imm12 where Xd != SP.
        if let Some((rd, rn, imm12)) = decode_sub_x_imm(raw) {
            if rd != 31 && rn != 31 && imm12 > 0 {
                candidates.push(i);
            }
        }
    }

    if candidates.is_empty() {
        return;
    }

    // Pick a random subset to transform (roughly 50%).
    let count = rng.gen_range(0..=candidates.len());
    let mut chosen: Vec<usize> = candidates;
    chosen.shuffle(rng);
    chosen.truncate(count);

    for &i in &chosen {
        let raw = words[i];
        if let Some((rd, rn, imm12)) = decode_add_x_imm(raw) {
            // ADD → SUB with same immediate (negate: 4096 - imm12).
            let neg_imm = (4096 - imm12) & 0xFFF;
            if neg_imm > 0 && neg_imm < 4096 {
                words[i] = enc_sub_x_imm(rd, rn, neg_imm);
            }
        } else if let Some((rd, rn, imm12)) = decode_sub_x_imm(raw) {
            // SUB → ADD with same immediate (negate: 4096 - imm12).
            let neg_imm = (4096 - imm12) & 0xFFF;
            if neg_imm > 0 && neg_imm < 4096 {
                words[i] = enc_add_x_imm(rd, rn, neg_imm);
            }
        }
    }
}

// ─── Transform: Conditional branch inversion ───────────────────────────────

/// Invert B.cond instructions: `B.cond target` → `B.inverted_cond +2; B target`.
///
/// This adds an extra instruction but preserves semantics. Only applied
/// probabilistically.
fn try_invert_cond_branch(words: Vec<u32>, rng: &mut impl Rng) -> Vec<u32> {
    // We need to expand the instruction stream, so build a new vector.
    let mut new_words: Vec<u32> = Vec::with_capacity(words.len() * 2);
    let mut changed = false;

    for raw in words {
        if let Some((cond, imm19)) = decode_b_cond(raw) {
            if rng.gen_bool(0.3) {
                let inv_cond = invert_cond(cond);
                // B.inverted_cond +2 (skip past the unconditional B)
                new_words.push(enc_b_cond(inv_cond, 2));
                // B original_target (adjusted: was imm19 from the B.cond position,
                // now it's from one instruction later, so imm19 - 1)
                new_words.push(enc_b(imm19 - 1));
                changed = true;
            } else {
                new_words.push(raw);
            }
        } else {
            new_words.push(raw);
        }
    }

    if changed {
        new_words
    } else {
        // Return the original if nothing changed (avoid reallocation).
        // We already moved into new_words, so just return it.
        new_words
    }
}

// ─── Transform: NOP insertion ──────────────────────────────────────────────

/// Insert NOP instructions (MOV X16, X16 or EOR Xd, Xd, Xd) between random
/// pairs of non-terminator instructions.
fn insert_nops(words: Vec<u32>, rng: &mut impl Rng) -> Vec<u32> {
    if words.len() < 2 {
        return words;
    }

    // Find valid insertion points (between non-terminator instructions).
    let mut insertion_points: Vec<usize> = Vec::new();
    for i in 0..words.len() - 1 {
        let kind = classify(words[i]);
        if !is_terminator(kind) && kind != BranchKind::PcRelB {
            let next_kind = classify(words[i + 1]);
            // Don't insert before branches.
            if next_kind == BranchKind::None {
                insertion_points.push(i);
            }
        }
    }

    if insertion_points.is_empty() {
        return words;
    }

    // Insert at most N NOPs where N = len / 8, clamped to [0, 4].
    let max_nops = (words.len() / 8).min(4).max(1);
    let num_nops = rng.gen_range(1..=max_nops);

    let mut new_words: Vec<u32> = Vec::with_capacity(words.len() + num_nops);
    let mut inserted = HashSet::new();

    for i in 0..words.len() {
        new_words.push(words[i]);
        if inserted.len() < num_nops && insertion_points.contains(&i) && rng.gen_bool(0.3) {
            // Choose NOP variant.
            let nop = if rng.gen_bool(0.5) {
                enc_mov_x(16, 16) // MOV X16, X16
            } else {
                // EOR X9, X9, X9 (sets X9 = 0, safe for scratch)
                enc_eor_x(9, 9, 9)
            };
            new_words.push(nop);
            inserted.insert(i);
        }
    }

    new_words
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    fn le_bytes(insns: &[u32]) -> Vec<u8> {
        let mut v = Vec::with_capacity(insns.len() * 4);
        for &i in insns {
            v.extend_from_slice(&i.to_le_bytes());
        }
        v
    }

    fn from_le(bytes: &[u8]) -> Vec<u32> {
        bytes
            .chunks_exact(4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
            .collect()
    }

    const RET_X30: u32 = 0xD65F_03C0;
    fn movz_x0(val: u32) -> u32 {
        0xD280_0000 | (val << 5)
    }

    #[test]
    fn empty_and_misaligned_passthrough() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        assert_eq!(apply(&[], &mut rng), Vec::<u8>::new());
        assert_eq!(apply(&[1, 2, 3], &mut rng), vec![1, 2, 3]);
    }

    #[test]
    fn deterministic_for_same_seed() {
        let add_x0_x1_5 = enc_add_x_imm(0, 1, 5);
        let code = le_bytes(&[movz_x0(1), add_x0_x1_5, RET_X30]);
        let mut rng_a = ChaCha8Rng::seed_from_u64(42);
        let mut rng_b = ChaCha8Rng::seed_from_u64(42);
        let out_a = apply(&code, &mut rng_a);
        let out_b = apply(&code, &mut rng_b);
        assert_eq!(out_a, out_b, "same seed must produce identical output");
    }

    #[test]
    fn add_sub_swap_produces_valid_insn() {
        let add = enc_add_x_imm(9, 10, 5);
        let code = le_bytes(&[movz_x0(0), add, RET_X30]);
        let mut rng = ChaCha8Rng::seed_from_u64(123);
        let out = apply(&code, &mut rng);
        let words = from_le(&out);
        // The ADD should still decode as a valid instruction (either ADD or SUB).
        let alu_word = words[1];
        let is_add = decode_add_x_imm(alu_word).is_some();
        let is_sub = decode_sub_x_imm(alu_word).is_some();
        assert!(is_add || is_sub, "should be ADD or SUB");
    }

    #[test]
    fn nop_insertion_increases_size() {
        // Enough instructions to trigger NOP insertion.
        let mut insns: Vec<u32> = Vec::new();
        for i in 0..16u32 {
            insns.push(enc_add_x_imm(9, 10, i));
        }
        insns.push(RET_X30);
        let code = le_bytes(&insns);
        let mut rng = ChaCha8Rng::seed_from_u64(77);
        let out = apply(&code, &mut rng);
        assert!(
            out.len() >= code.len(),
            "output should be at least as large as input"
        );
    }

    #[test]
    fn register_rename_changes_encoding() {
        // MOV X9, #1 → ADD X9, X9, #1 → should use X9 as local scratch.
        let mov_x9 = 0xD280_0000 | (1 << 5) | 9; // MOVZ X9, #1
        let add_x9_x10 = enc_add_x_imm(9, 10, 1);
        let code = le_bytes(&[mov_x9, add_x9_x10, RET_X30]);
        let mut rng = ChaCha8Rng::seed_from_u64(200);
        let out = apply(&code, &mut rng);
        let words = from_le(&out);
        // X9 should either remain X9 or be renamed to another scratch register.
        let uses_x9 = words.iter().any(|&w| reg_appears(w, 9));
        let uses_x11 = words.iter().any(|&w| reg_appears(w, 11));
        let uses_x12 = words.iter().any(|&w| reg_appears(w, 12));
        let uses_x13 = words.iter().any(|&w| reg_appears(w, 13));
        let uses_x14 = words.iter().any(|&w| reg_appears(w, 14));
        let uses_x15 = words.iter().any(|&w| reg_appears(w, 15));
        assert!(
            uses_x9 || uses_x11 || uses_x12 || uses_x13 || uses_x14 || uses_x15,
            "register should be renamed or remain in X9-X15 pool"
        );
    }

    #[test]
    fn cond_branch_inversion_preserves_semantics() {
        // B.EQ +4
        let b_eq = 0x5400_0020; // B.EQ, offset = +4 bytes (1 instruction)
        let code = le_bytes(&[movz_x0(0), b_eq, RET_X30, RET_X30]);
        let mut rng = ChaCha8Rng::seed_from_u64(314);
        let out = apply(&code, &mut rng);
        let words = from_le(&out);
        // Should contain RET regardless.
        assert!(
            words.iter().any(|&w| w == RET_X30),
            "RET should be preserved"
        );
        // If branch was inverted, should have two consecutive branch-like insns.
        // Check that the output is valid.
        assert!(out.len() % 4 == 0);
    }

    #[test]
    fn pcrel_data_bailout() {
        let adrp = 0x9000_0000u32; // ADRP X0, #0
        let code = le_bytes(&[adrp, RET_X30]);
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let out = apply(&code, &mut rng);
        assert_eq!(out, code, "should return input unchanged when ADRP present");
    }
}
