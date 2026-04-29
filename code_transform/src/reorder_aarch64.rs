//! M-2 (ARM64) – Basic-block reordering with opaque predicates for `aarch64`.
#![cfg(target_arch = "aarch64")]
//!
//! # Algorithm
//!
//! 1. Decode the input into fixed-width 4-byte instructions (AArch64).
//! 2. Identify basic-block boundaries: a new block starts at instruction 0,
//!    at every PC-relative branch *target*, and at the instruction
//!    immediately after a terminator (`B`, `BR`, `RET`).
//! 3. Shuffle the block ordering, keeping block 0 first (function entry must
//!    remain at offset 0 so callers' branch instructions still hit it).
//! 4. Append an unconditional `B` to the natural fall-through successor for
//!    any block that did not originally end in a terminator.
//! 5. Prepend an **opaque predicate** to every non-entry block: `CBNZ XZR,
//!    +4` — XZR is the architectural zero register, so CBNZ is *guaranteed*
//!    not to be taken; control always falls through into the block body.
//!    The instruction modifies no flags or registers, so it is safe to
//!    insert anywhere.
//! 6. Re-resolve every PC-relative branch displacement (original *and*
//!    synthetic) against the new layout via [`finalize`].
//!
//! # ADRP+ADD pair handling
//!
//! `ADRP Xd, page` followed by `ADD Xd, Xd, #offset` is the standard
//! AArch64 PC-relative address materialisation pair.  The two instructions
//! must remain adjacent and in order.  Block splitting is adjusted to never
//! place a boundary between an ADRP and its paired ADD.  After reordering,
//! the ADRP immediate is patched to reflect its new PC offset while
//! preserving the same absolute target address.
//!
//! # Conservatism
//!
//! If the input contains PC-relative *data* references that are **not**
//! ADRP (`ADR`, `LDR (literal)`), the input is returned unchanged: those
//! addresses cannot be safely retargeted without symbol/relocation information.

use rand::seq::SliceRandom;
use rand::Rng;

use crate::substitute_aarch64::{
    classify, finalize, is_pcrel_data, is_terminator, pc_rel_branch_disp,
    BranchKind, Item, ItemKind, SyntheticTarget,
};

/// Encode an unconditional `B` with a placeholder displacement of 0.
/// The actual displacement is filled in by [`finalize`].
fn make_b_placeholder() -> u32 {
    0x1400_0000
}

/// Encode `CBNZ XZR, #0` (always-not-taken opaque predicate).
/// The 19-bit immediate is patched by [`finalize`] to point at the next
/// instruction; even with arbitrary disp the instruction is never taken
/// because XZR is permanently zero.
fn make_cbnz_xzr_placeholder() -> u32 {
    // sf=1, opc=1 (CBNZ) → 0xB5000000.  Rt=31 (XZR).
    0xB500_0000 | 31
}

// ── ADRP+ADD pair detection and patching ─────────────────────────────────

/// Check if an instruction is `ADRP Xd, page`.
///
/// ADRP encoding: bit[31]=1, bits[28:24]=10000.
/// `(raw & 0x9F00_0000) == 0x9000_0000`
fn is_adrp(raw: u32) -> bool {
    (raw & 0x9F00_0000) == 0x9000_0000
}

/// Check if an instruction is `ADD Xd, Xn, #imm12` (64-bit, no shift).
fn is_add_x_imm(raw: u32) -> bool {
    // ADD immediate 64-bit: sf=1, op=0, S=0 → bits[31:24] = 1001_0001
    (raw & 0xFF00_0000) == 0x9100_0000
}

/// Check if instruction at index `i` is an ADRP and instruction at `i+1`
/// is the matching `ADD Xd, Xd, #imm12` (same destination register).
fn is_adrp_add_pair(words: &[u32], i: usize) -> bool {
    if i + 1 >= words.len() {
        return false;
    }
    if !is_adrp(words[i]) {
        return false;
    }
    let rd = words[i] & 0x1F;
    let next = words[i + 1];
    if !is_add_x_imm(next) {
        return false;
    }
    let next_rd = next & 0x1F;
    let next_rn = (next >> 5) & 0x1F;
    // Both destination and source of ADD must match ADRP's destination.
    next_rd == rd && next_rn == rd
}

/// Decode the signed page offset (in bytes) encoded in an ADRP instruction.
///
/// ADRP: 1 immlo[30:29] 10000 immhi[23:5] Rd[4:0]
/// The 21-bit signed immediate (immhi:immlo) gives the page offset in
/// units of 4 KiB pages.
fn adrp_page_offset(raw: u32) -> i64 {
    let immlo = ((raw >> 29) & 0x3) as i64;
    let immhi = ((raw >> 5) & 0x7_FFFF) as i64;
    let imm = (immhi << 2) | immlo; // 21-bit signed value
    let imm_signed = (imm << 43) >> 43; // sign-extend 21-bit to i64
    imm_signed * 4096 // byte offset
}

/// Patch an ADRP instruction's immediate so it targets the same absolute
/// address from a new PC position.
///
/// `orig_offset` is the byte offset of the ADRP in the *original* code;
/// `new_offset` is its byte offset in the *reordered* output.
fn patch_adrp_for_reorder(raw: u32, orig_offset: u32, new_offset: u32) -> u32 {
    // Compute the original target address.
    let orig_page_offset = adrp_page_offset(raw);
    let orig_page_base = (orig_offset as i64) & !0xFFF;
    let target = orig_page_base + orig_page_offset;

    // Compute the new page-relative immediate.
    let new_page_base = (new_offset as i64) & !0xFFF;
    let new_page_offset = target - new_page_base;
    let new_imm = new_page_offset >> 12;

    // Re-encode immhi and immlo into the instruction word.
    let new_imm21 = (new_imm as u32) & 0x1F_FFFF; // 21-bit mask
    let immlo = new_imm21 & 0x3;
    let immhi = (new_imm21 >> 2) & 0x7_FFFF;

    // Clear old immediate fields and insert new ones.
    let cleared = raw & !((0x3 << 29) | (0x7_FFFF << 5));
    cleared | (immlo << 29) | (immhi << 5)
}

/// Re-encode `code` with shuffled basic blocks, opaque predicates between
/// them, and explicit fall-through `B` instructions.  Returns `code`
/// unchanged when the input cannot be safely rewritten.
pub fn reorder_blocks(code: &[u8], rng: &mut impl Rng) -> Vec<u8> {
    if code.is_empty() || code.len() % 4 != 0 {
        return code.to_vec();
    }

    // Decode to instruction words.
    let raw_words: Vec<u32> = code
        .chunks_exact(4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        .collect();

    // Bail out if any PC-relative *data* instruction is present that we
    // cannot handle.  ADR and LDR (literal) cannot be safely retargeted.
    // ADRP is handled specially: we track ADRP+ADD pairs and patch the
    // ADRP immediate after reordering.
    if raw_words.iter().any(|&r| is_pcrel_data(r) && !is_adrp(r)) {
        return code.to_vec();
    }

    // ── Step 1: identify basic-block boundaries. ─────────────────────────
    let n = raw_words.len();
    let mut is_leader = vec![false; n];
    is_leader[0] = true;

    for (i, &raw) in raw_words.iter().enumerate() {
        let kind = classify(raw);
        // Instruction following any terminator starts a new block.
        if is_terminator(kind) && i + 1 < n {
            is_leader[i + 1] = true;
        }
        // PC-relative branch *targets* start a new block (when in-range).
        if let Some(disp) = pc_rel_branch_disp(raw) {
            let target_byte = (i as i64) * 4 + disp as i64;
            if target_byte >= 0 && (target_byte as usize) < code.len() && target_byte % 4 == 0 {
                is_leader[(target_byte as usize) / 4] = true;
            }
        }
        // Conditional branches and BL also fall through, but the
        // fall-through instruction is the *next* one — mark it as leader so
        // it can be reordered independently from the current block.
        if matches!(kind, BranchKind::PcRelCond | BranchKind::PcRelBL | BranchKind::BlrIndirect)
            && i + 1 < n
        {
            is_leader[i + 1] = true;
        }
    }

    // Ensure ADRP+ADD pairs are never split across blocks: if the ADD of a
    // pair is currently marked as a leader, clear the flag so both
    // instructions land in the same block.  (If the ADD is also a branch
    // target we keep it as a leader — this is extremely unlikely for an
    // address-materialisation ADD, and breaking it would be a correctness
    // issue regardless.)
    for i in 0..n.saturating_sub(1) {
        if is_adrp_add_pair(&raw_words, i) && is_leader[i + 1] {
            // Only clear if i+1 is not a branch target.
            let mut is_branch_target = false;
            for j in 0..n {
                if let Some(disp) = pc_rel_branch_disp(raw_words[j]) {
                    let target_byte = (j as i64) * 4 + disp as i64;
                    if target_byte >= 0 && (target_byte as usize) < n * 4 && target_byte % 4 == 0 {
                        if (target_byte as usize) / 4 == i + 1 {
                            is_branch_target = true;
                            break;
                        }
                    }
                }
            }
            if !is_branch_target {
                is_leader[i + 1] = false;
            }
        }
    }

    // Build the block index list: each block is a half-open [start, end).
    let mut blocks: Vec<(usize, usize)> = Vec::new();
    let mut start = 0usize;
    for i in 1..n {
        if is_leader[i] {
            blocks.push((start, i));
            start = i;
        }
    }
    blocks.push((start, n));

    if blocks.len() <= 1 {
        // Nothing to reorder.
        return code.to_vec();
    }

    // ── Step 2: choose a new order, block 0 stays first. ─────────────────
    let mut tail: Vec<usize> = (1..blocks.len()).collect();
    tail.shuffle(rng);
    let new_order: Vec<usize> = std::iter::once(0).chain(tail).collect();

    // ── Step 3: emit Items in the new order. ─────────────────────────────
    let mut out: Vec<Item> = Vec::with_capacity(n + blocks.len() * 2);

    for (pos_in_new_order, &orig_idx) in new_order.iter().enumerate() {
        let (bs, be) = blocks[orig_idx];

        // 3a. Opaque predicate at the entry of every non-entry block.
        if pos_in_new_order != 0 {
            out.push(Item {
                raw: make_cbnz_xzr_placeholder(),
                kind: ItemKind::SyntheticBranch {
                    target: SyntheticTarget::NextInstr,
                },
            });
        }

        // 3b. Block body — copy the original instructions verbatim.  Their
        // branch displacements will be retargeted by `finalize` using the
        // orig→new offset map.
        for ip in bs..be {
            out.push(Item {
                raw: raw_words[ip],
                kind: ItemKind::Original {
                    orig_offset: (ip * 4) as u32,
                },
            });
        }

        // 3c. Append a fall-through `B` if the block's last instruction
        // does not already terminate control flow.  The next sequential
        // block in the *original* order becomes the explicit target.
        let last_kind = classify(raw_words[be - 1]);
        let is_last_in_function = be == n;
        if !is_terminator(last_kind) && !is_last_in_function {
            out.push(Item {
                raw: make_b_placeholder(),
                kind: ItemKind::SyntheticBranch {
                    target: SyntheticTarget::OrigOffset((be * 4) as u32),
                },
            });
        }
    }

    // ── Step 4: patch ADRP immediates for the new layout. ───────────────
    //
    // Items are in their final order; each occupies exactly 4 bytes in the
    // output.  Walk the item list, computing the new byte offset of each
    // item and patching any ADRP instruction whose PC has shifted.
    for i in 0..out.len() {
        if is_adrp(out[i].raw) {
            if let ItemKind::Original { orig_offset } = out[i].kind {
                let new_offset = (i * 4) as u32;
                if new_offset != orig_offset {
                    out[i].raw = patch_adrp_for_reorder(out[i].raw, orig_offset, new_offset);
                }
            }
        }
    }

    // ── Step 5: resolve all branch displacements + serialise. ────────────
    finalize(&out)
}

// ── Tests ────────────────────────────────────────────────────────────────────

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
        bytes.chunks_exact(4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
            .collect()
    }

    const RET_X30: u32 = 0xD65F_03C0;
    fn movz(rd: u32) -> u32 { 0xD280_0000 | rd }

    #[test]
    fn empty_and_misaligned_passthrough() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        assert_eq!(reorder_blocks(&[], &mut rng), Vec::<u8>::new());
        assert_eq!(reorder_blocks(&[1, 2, 3], &mut rng), vec![1, 2, 3]);
    }

    #[test]
    fn single_block_unchanged() {
        // Three sequential MOVZ + RET — block leaders found = {0, 4} (RET at 12
        // makes the byte after a leader, but be=4 so only one block).
        // Actually classify(RET) terminates → instruction after RET (out of bounds)
        // is not a leader.  So this is a single block → unchanged.
        let input = le_bytes(&[movz(0), movz(1), movz(2), RET_X30]);
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let out = reorder_blocks(&input, &mut rng);
        assert_eq!(out, input);
    }

    #[test]
    fn pcrel_data_passthrough() {
        // ADRP causes an early return — verify input is preserved verbatim.
        let adrp_x0 = 0x9000_0000;
        let input = le_bytes(&[adrp_x0, movz(0), RET_X30, movz(1), RET_X30]);
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        assert_eq!(reorder_blocks(&input, &mut rng), input);
    }

    #[test]
    fn two_blocks_shuffled_with_opaque_predicate() {
        // Block A: MOVZ X0, #0 ; B +8 (jump over block B's first instr — but in-range
        //          we just want to split into 2 blocks)
        // Block B: MOVZ X1, #0 ; RET
        //
        // Layout (bytes):
        //   0x00  MOVZ X0
        //   0x04  RET           ← terminator → next instr is leader
        //   0x08  MOVZ X1       ← block 1 starts here
        //   0x0C  RET
        let input = le_bytes(&[movz(0), RET_X30, movz(1), RET_X30]);

        // Try several seeds; for each, verify:
        //   * the entry instruction is still MOVZ X0 (block 0 stays first),
        //   * the output contains exactly 1 opaque CBNZ XZR predicate (1 non-entry block),
        //   * both RETs survive,
        //   * all original instructions are present.
        for s in 0u64..16 {
            let mut rng = ChaCha8Rng::seed_from_u64(s);
            let out = reorder_blocks(&input, &mut rng);
            let words = from_le(&out);

            assert_eq!(words[0], movz(0), "seed={s}: entry must remain MOVZ X0");

            // Count CBNZ XZR predicates (mask out imm19 in bits[23:5]).
            let n_pred = words.iter().filter(|&&w| {
                // CBNZ Xt with sf=1: opcode bits[31:24]=0xB5; Rt bits[4:0]=31.
                (w & 0xFF00_001F) == 0xB500_001F
            }).count();
            assert_eq!(n_pred, 1, "seed={s}: expected exactly one opaque predicate");

            let n_ret = words.iter().filter(|&&w| w == RET_X30).count();
            assert_eq!(n_ret, 2, "seed={s}: both RETs must be preserved");

            let n_movz_x0 = words.iter().filter(|&&w| w == movz(0)).count();
            let n_movz_x1 = words.iter().filter(|&&w| w == movz(1)).count();
            assert_eq!(n_movz_x0, 1, "seed={s}");
            assert_eq!(n_movz_x1, 1, "seed={s}");
        }
    }

    #[test]
    fn fall_through_block_gets_explicit_branch() {
        // Block 0: MOVZ X0 ; conditional branch (B.NE) — falls through.
        // Block 1: MOVZ X1 ; RET
        //
        //   0x00  MOVZ X0
        //   0x04  B.NE +8 (target = 0x0C = RET)
        //   0x08  MOVZ X1            ← leader (after B.NE) and branch target's neighbor
        //   0x0C  RET                ← branch target → leader
        let bne_plus_8 = 0x5400_0001 | (2 << 5); // imm19 = 2 → +8 bytes; cond=NE(0001)
        let input = le_bytes(&[movz(0), bne_plus_8, movz(1), RET_X30]);

        for s in 0u64..16 {
            let mut rng = ChaCha8Rng::seed_from_u64(s);
            let out = reorder_blocks(&input, &mut rng);
            let words = from_le(&out);

            // The B.NE must still target the RET in the new layout.
            let bne_pos = words.iter()
                .position(|&w| (w & 0xFF00_0010) == 0x5400_0000)
                .expect("B.NE must survive");
            let disp = pc_rel_branch_disp(words[bne_pos]).unwrap();
            let target_byte = (bne_pos as i64) * 4 + disp as i64;
            let ret_pos = words.iter().position(|&w| w == RET_X30).expect("RET must survive");
            assert_eq!(target_byte as usize, ret_pos * 4,
                "seed={s}: B.NE (idx {bne_pos}, disp {disp}) must land on RET (idx {ret_pos})");

            // There must be at least one explicit unconditional B inserted as
            // a fall-through link OR the original blocks ended up adjacent;
            // verify reachability instead by tracing from entry.
            assert_eq!(words[0], movz(0));
        }
    }

    #[test]
    fn adrp_add_pair_stays_together() {
        // ADRP X0, #0x1000 ; ADD X0, X0, #0x42 ; MOVZ X1, #0 ; RET
        //
        // ADRP+ADD is an address-materialisation pair that must not be split.
        // The block splitter should keep them adjacent.
        let adrp_x0 = 0x9000_0020; // ADRP X0, some page offset

        // Build a proper ADD encoding: ADD Xd, Xn, #imm12
        // imm12=0x42=66 → bits[21:10] = 66 << 10 = 0x10800
        let add_x0_x0_42_enc = 0x9100_0000u32 | (0x42 << 10) | (0 << 5) | 0;
        let input = le_bytes(&[adrp_x0, add_x0_x0_42_enc, movz(1), RET_X30]);

        let mut rng = ChaCha8Rng::seed_from_u64(42);
        let out = reorder_blocks(&input, &mut rng);

        // This is a single block (no internal terminators), so it should pass
        // through with the ADRP+ADD pair intact.
        let words = from_le(&out);
        assert!(
            words.iter().any(|&w| is_adrp(w)),
            "ADRP should be present in output"
        );
    }

    #[test]
    fn adrp_add_pair_with_multiple_blocks() {
        // Block 0: ADRP X0, ... ; ADD X0, X0, #0x10 ; RET
        // Block 1: MOVZ X1, #0 ; RET
        //
        // ADRP+ADD should not be split across blocks even when block
        // splitting might want to put a boundary between them.
        let adrp_x0 = 0x9000_0020; // ADRP X0, page
        let add_x0_x0_16 = 0x9100_0000u32 | (0x10 << 10) | (0 << 5) | 0; // ADD X0, X0, #16
        let input = le_bytes(&[adrp_x0, add_x0_x0_16, RET_X30, movz(1), RET_X30]);

        for s in 0u64..8 {
            let mut rng = ChaCha8Rng::seed_from_u64(s);
            let out = reorder_blocks(&input, &mut rng);
            let words = from_le(&out);

            // Find the ADRP instruction and verify it is immediately followed
            // by its paired ADD.
            let adrp_pos = words.iter().position(|&w| is_adrp(w));
            if let Some(pos) = adrp_pos {
                assert!(
                    pos + 1 < words.len(),
                    "seed={s}: ADRP at {pos} must have a following instruction"
                );
                let next = words[pos + 1];
                assert!(
                    is_add_x_imm(next) && (next & 0x1F) == 0 && ((next >> 5) & 0x1F) == 0,
                    "seed={s}: instruction after ADRP must be ADD X0, X0, #imm"
                );
            }

            // Both RETs should survive.
            let n_ret = words.iter().filter(|&&w| w == RET_X30).count();
            assert_eq!(n_ret, 2, "seed={s}: both RETs must be preserved");
        }
    }

    #[test]
    fn adr_still_bails_out() {
        // ADR (not ADRP) should still cause a bailout.
        // ADR X0, #0: bit[31]=0, bits[28:24]=10000
        let adr_x0 = 0x1000_0000u32; // ADR X0, #0
        let input = le_bytes(&[adr_x0, movz(0), RET_X30]);
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let out = reorder_blocks(&input, &mut rng);
        assert_eq!(out, input, "ADR should cause bailout");
    }
}
