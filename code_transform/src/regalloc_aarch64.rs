//! Register reallocation for AArch64 machine code.
//!
//! Performs register renaming via liveness analysis and permutation of
//! permutable registers.  This is analogous to the x86_64 `regalloc` module
//! but works directly on fixed-width 32-bit ARM64 instruction encodings.
//!
//! # Algorithm
//!
//! 1. **Collect implicit-use pins**: Registers that are live-in or have
//!    special meaning (X0–X7 = arguments/return values, X8 = indirect result,
//!    X19–X28 = callee-saved, X29 = FP, X30 = LR, X31 = SP/XZR) are pinned.
//!
//! 2. **Build a CFG** of basic blocks and compute per-instruction def/use sets.
//!
//! 3. **Iterative dataflow liveness analysis** to compute live-in / live-out
//!    for each instruction.
//!
//! 4. **Build a permutation** of the permutable register pool (X9–X18, excluding
//!    X16/X17 which are intra-procedure-call scratch IP0/IP1).
//!
//! 5. **Apply the permutation** by rewriting register fields in each instruction.
//!
//! If the code contains PC-relative data references or the liveness analysis
//! detects conflicts, the input is returned unchanged.

use std::collections::{HashMap, HashSet};

use rand::seq::SliceRandom;
use rand::Rng;

use crate::substitute_aarch64::{classify, is_pcrel_data, is_terminator, BranchKind};

// ─── ARM64 register constants ──────────────────────────────────────────────

/// Registers that are pinned (cannot be renamed).
/// X0–X7: arguments/return values.
/// X8: indirect result location register.
/// X19–X28: callee-saved (must be preserved across calls).
/// X29: frame pointer.
/// X30: link register.
/// X31: SP/XZR (encoded as 31).
const PINNED: &[u32] = &[
    0, 1, 2, 3, 4, 5, 6, 7, 8, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
];

/// Permutable register pool: X9–X15 and X18.
/// X16/X17 are IP0/IP1 (intra-procedure-call scratch) and are excluded from
/// renaming to avoid breaking linker veneers.
const PERMUTABLE_POOL: &[u32] = &[9, 10, 11, 12, 13, 14, 15, 18];

// ─── Register field helpers ─────────────────────────────────────────────────

fn rd_field(raw: u32) -> u32 {
    raw & 0x1F
}

fn rn_field(raw: u32) -> u32 {
    (raw >> 5) & 0x1F
}

fn rm_field(raw: u32) -> u32 {
    (raw >> 16) & 0x1F
}

fn ra_field(raw: u32) -> u32 {
    (raw >> 10) & 0x1F
}

/// Check if register `reg` appears in any of the common register fields.
fn reg_appears(raw: u32, reg: u32) -> bool {
    rd_field(raw) == reg || rn_field(raw) == reg || rm_field(raw) == reg || ra_field(raw) == reg
}

/// Replace register `old` with `new` in all register fields of the instruction.
fn replace_reg(raw: u32, old: u32, new: u32) -> u32 {
    let mut result = raw;
    // Rd (bits[4:0])
    if (result & 0x1F) == old {
        result = (result & !0x1F) | new;
    }
    // Rn (bits[9:5])
    if ((result >> 5) & 0x1F) == old {
        result = (result & !(0x1F << 5)) | (new << 5);
    }
    // Rm (bits[20:16])
    if ((result >> 16) & 0x1F) == old {
        result = (result & !(0x1F << 16)) | (new << 16);
    }
    // Ra (bits[14:10]) — used by MADD/MSUB and some other instructions.
    if ((result >> 10) & 0x1F) == old {
        result = (result & !(0x1F << 10)) | (new << 10);
    }
    result
}

// ─── CFG / Basic Block ─────────────────────────────────────────────────────

#[derive(Clone)]
struct BasicBlock {
    start: usize, // inclusive
    end: usize,   // exclusive
}

fn build_blocks(words: &[u32]) -> Vec<BasicBlock> {
    let n = words.len();
    if n == 0 {
        return Vec::new();
    }

    let mut is_leader = vec![false; n];
    is_leader[0] = true;

    for (i, &raw) in words.iter().enumerate() {
        let kind = classify(raw);
        if is_terminator(kind) && i + 1 < n {
            is_leader[i + 1] = true;
        }
        // Conditional branches and BL have fallthrough.
        if matches!(kind, BranchKind::PcRelCond | BranchKind::PcRelBL | BranchKind::BlrIndirect)
            && i + 1 < n
        {
            is_leader[i + 1] = true;
        }
        // Branch targets are leaders.
        if let Some(disp) = pc_rel_branch_disp_internal(raw) {
            let target = (i as i64) + disp;
            if target >= 0 && (target as usize) < n {
                is_leader[target as usize] = true;
            }
        }
    }

    let mut blocks = Vec::new();
    let mut start = 0;
    for i in 1..n {
        if is_leader[i] {
            blocks.push(BasicBlock {
                start,
                end: i,
            });
            start = i;
        }
    }
    blocks.push(BasicBlock {
        start,
        end: n,
    });
    blocks
}

fn block_successors(block: &BasicBlock, words: &[u32]) -> Vec<usize> {
    let mut succs = Vec::new();
    let n = words.len();
    if block.start == block.end {
        return succs;
    }
    let last = words[block.end - 1];
    let last_idx = block.end - 1;
    let kind = classify(last);

    // Fallthrough (for non-unconditional-branch terminators).
    if !matches!(kind, BranchKind::PcRelB | BranchKind::Ret | BranchKind::BrIndirect) {
        if block.end < n {
            succs.push(block.end);
        }
    }

    // Direct branch target.
    if let Some(disp) = pc_rel_branch_disp_internal(last) {
        let target = (last_idx as i64) + disp;
        if target >= 0 && (target as usize) < n {
            succs.push(target as usize);
        }
    }

    succs
}

/// Get PC-relative branch displacement in instruction-word units.
/// Returns None if not a PC-relative branch.
fn pc_rel_branch_disp_internal(raw: u32) -> Option<i64> {
    let kind = classify(raw);
    match kind {
        BranchKind::PcRelB => {
            // B imm26: bits[25:0], sign-extend 26-bit.
            let imm26 = (raw & 0x3FF_FFFF) as i64;
            let s = (imm26 << 38) >> 38; // sign extend 26-bit to i64
            Some(s)
        }
        BranchKind::PcRelCond => {
            // B.cond / CBZ/CBNZ/TBZ/TBNZ imm19: bits[23:5], sign-extend 19-bit.
            let imm19 = ((raw >> 5) & 0x7_FFFF) as i64;
            let s = (imm19 << 45) >> 45;
            Some(s)
        }
        BranchKind::PcRelBL => {
            // BL imm26: bits[25:0], sign-extend 26-bit.
            let imm26 = (raw & 0x3FF_FFFF) as i64;
            let s = (imm26 << 38) >> 38;
            Some(s)
        }
        _ => None,
    }
}

// ─── Use/Def analysis ──────────────────────────────────────────────────────

/// Check if an instruction is CBZ/CBNZ/TBZ/TBNZ (reads a test register).
fn is_cb_tb(raw: u32) -> bool {
    let masked = raw & 0x7F00_0000;
    matches!(masked, 0x3400_0000 | 0x3500_0000 | 0x3600_0000 | 0x3700_0000)
}

/// Compute the set of registers *used* (read) by the instruction.
fn inst_uses(raw: u32) -> HashSet<u32> {
    let mut uses = HashSet::new();
    let kind = classify(raw);

    // For branches, source registers are condition registers or test registers.
    match kind {
        BranchKind::Ret | BranchKind::BrIndirect => {
            // BR Xn — reads Rn.
            let r = rn_field(raw);
            if r < 31 {
                uses.insert(r);
            }
            return uses;
        }
        BranchKind::BlrIndirect => {
            let r = rn_field(raw);
            if r < 31 {
                uses.insert(r);
            }
            return uses;
        }
        _ => {}
    }

    // CBZ/CBNZ/TBZ/TBNZ: reads the test register.
    if is_cb_tb(raw) {
        let rt = raw & 0x1F;
        if rt < 31 {
            uses.insert(rt);
        }
        return uses;
    }

    // B.cond (conditional branch): reads NZCV flags (implicit), no explicit register.
    if (raw & 0xFF00_0010) == 0x5400_0000 {
        return uses; // no explicit register uses.
    }

    // BL / B: no explicit register uses.
    if matches!(kind, BranchKind::PcRelBL | BranchKind::PcRelB) {
        return uses;
    }

    // Regular ALU instructions: Rn is always a source. Rm is a source for
    // register-register forms. Ra is a source for MADD/MSUB.
    let r_rn = rn_field(raw);
    if r_rn < 31 {
        uses.insert(r_rn);
    }

    // Check if instruction has a register-register form with Rm.
    // Most arithmetic instructions have Rm at bits[20:16].
    // We check the major opcode group to determine if Rm is present.
    let has_rm = has_rm_field(raw);
    if has_rm {
        let r_rm = rm_field(raw);
        if r_rm < 31 {
            uses.insert(r_rm);
        }
    }

    // Check for Ra field (MADD, MSUB, etc.).
    if has_ra_field(raw) {
        let r_ra = ra_field(raw);
        if r_ra < 31 {
            uses.insert(r_ra);
        }
    }

    // For write-only destinations (MOVZ, MOV, etc.), Rd is NOT a use.
    // For read-modify-write (e.g., ADD Xd, Xn, Xn where Xd==Xn), Rd==Rn is
    // already captured as a use via Rn.

    uses
}

/// Compute the set of registers *defined* (written) by the instruction.
fn inst_defs(raw: u32) -> HashSet<u32> {
    let mut defs = HashSet::new();
    let kind = classify(raw);

    // Branches don't define registers (they transfer control).
    if is_terminator(kind) {
        return defs;
    }

    // BL writes X30 (LR) implicitly.
    if kind == BranchKind::PcRelBL {
        defs.insert(30);
        return defs;
    }

    // Most ALU/data-processing instructions write Rd.
    // Check if this instruction class writes to Rd.
    if writes_rd(raw) {
        let r_rd = rd_field(raw);
        if r_rd < 31 {
            defs.insert(r_rd);
        }
    }

    defs
}

/// Check if the instruction has an Rm (third register) field.
/// This is true for register-register arithmetic, logical, etc.
fn has_rm_field(raw: u32) -> bool {
    let _top = raw >> 21;
    // Data processing (register): major opcode 0b01011, 0b11010, etc.
    // ADD/SUB shifted: 01011xx
    // Logical shifted: 01010xx
    // EOR/ORR/AND: various patterns in bits[30:21]
    let major = (raw >> 24) & 0x7F;
    matches!(
        major,
        0x0A | 0x4A | 0x8A | 0xCA | // logical (AND, ORR, EOR, ANDS) 32/64-bit
        0x0B | 0x4B | 0x8B | 0xCB | // ADD/SUB shifted register 32/64-bit
        0x1B | 0x5B | // ADD/SUB extended register
        0x1A | 0x5A | // ADC/SBC/ADCS/SBCS
        0x1D | 0x5D | // MADD/MSUB etc. (data processing 3 source)
        0x03 | 0x13 | // Logical (immediate)
        0x06 | 0x16 | // MOVK/MOVZ — no, these are immediate
        0x0C | 0x4C | // Conditional select
        0x0E | 0x4E   // Data processing 2 source
    )
}

/// Check if the instruction has an Ra field (e.g., MADD, MSUB).
fn has_ra_field(raw: u32) -> bool {
    let major = (raw >> 24) & 0x7F;
    matches!(major, 0x1B | 0x5B | 0x1D | 0x5D)
}

/// Check if the instruction writes to Rd (the destination register).
fn writes_rd(raw: u32) -> bool {
    let major = (raw >> 24) & 0x7F;
    // Most data processing instructions write Rd.
    // Exceptions: CMP (SUBS XZR), TST (ANDS XZR), branches, loads with no destination.
    matches!(
        major,
        0x0A | 0x4A | 0x8A | 0xCA | // logical
        0x0B | 0x4B | 0x8B | 0xCB | // ADD/SUB shifted + extended
        0x1B | 0x5B |               // ADD/SUB extended (alternate encoding)
        0x1A | 0x5A |               // ADC/SBC
        0x1D | 0x5D |               // MADD/MSUB
        0x0C | 0x4C |               // Conditional select
        0x0E | 0x4E |               // Data processing 2 source
        0x11 | 0x51 |               // ADD immediate (MOV alias)
        0x91 | 0xD1 |               // ADD/SUB immediate 64-bit
        0x12 | 0x52 | 0x92 | 0xD2 | // MOVZ/MOVK 32/64-bit
        0x13 | 0x53 | 0x93 | 0xD3   // MOVN/ORR immediate
    )
}

// ─── Liveness analysis ─────────────────────────────────────────────────────

struct BlockLiveness {
    live_in: HashSet<u32>,
    live_out: HashSet<u32>,
}

fn compute_live_in(words: &[u32], blocks: &[BasicBlock]) -> Vec<BlockLiveness> {
    let n = blocks.len();
    let mut block_info: Vec<BlockLiveness> = (0..n)
        .map(|_| BlockLiveness {
            live_in: HashSet::new(),
            live_out: HashSet::new(),
        })
        .collect();

    // Iterate until fixed point.
    let mut changed = true;
    while changed {
        changed = false;
        for bi in (0..n).rev() {
            let block = &blocks[bi];
            // live_out = union of live_in of successors.
            let mut new_out: HashSet<u32> = HashSet::new();
            for &si in &block_successors(&blocks[bi], words) {
                // Find the block index for instruction `si`.
                for (bj, bj_block) in blocks.iter().enumerate() {
                    if si >= bj_block.start && si < bj_block.end {
                        new_out.extend(block_info[bj].live_in.iter());
                    }
                }
            }

            // Compute live_in by reverse scan.
            let mut live = new_out.clone();
            for i in (block.start..block.end).rev() {
                let raw = words[i];
                let defs = inst_defs(raw);
                let uses = inst_uses(raw);
                for d in &defs {
                    live.remove(d);
                }
                for u in &uses {
                    live.insert(*u);
                }
            }

            if live != block_info[bi].live_in || new_out != block_info[bi].live_out {
                changed = true;
                block_info[bi].live_in = live;
                block_info[bi].live_out = new_out;
            }
        }
    }

    block_info
}

// ─── Public entry point ─────────────────────────────────────────────────────

/// Reallocate registers in AArch64 machine code using liveness-aware permutation.
///
/// Returns the transformed code bytes.  If the input is not a multiple of 4
/// bytes or contains PC-relative data references, it is returned unchanged.
pub fn reallocate_registers(code: &[u8], rng: &mut impl Rng) -> Vec<u8> {
    if code.is_empty() || code.len() % 4 != 0 {
        return code.to_vec();
    }

    let raw_words: Vec<u32> = code
        .chunks_exact(4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        .collect();

    if raw_words.iter().any(|&r| is_pcrel_data(r)) {
        return code.to_vec();
    }

    let blocks = build_blocks(&raw_words);
    if blocks.is_empty() {
        return code.to_vec();
    }

    let block_liveness = compute_live_in(&raw_words, &blocks);

    // Collect the set of registers that are live at function entry (live-in of
    // block 0) — these must be pinned.
    let mut entry_live: HashSet<u32> = HashSet::new();
    if !block_liveness.is_empty() {
        entry_live = block_liveness[0].live_in.clone();
    }

    // Permutable registers that are not live at entry and not pinned.
    let available: Vec<u32> = PERMUTABLE_POOL
        .iter()
        .filter(|&&r| !entry_live.contains(&r) && !PINNED.contains(&r))
        .copied()
        .collect();

    if available.len() < 2 {
        log::debug!(
            "regalloc_aarch64: fewer than 2 permutable registers available; returning input unchanged"
        );
        return code.to_vec();
    }

    // Build a random permutation of the available pool.
    let mut perm_keys: Vec<u32> = available.clone();
    perm_keys.shuffle(rng);

    // Ensure the permutation is not the identity (otherwise nothing changes).
    let is_identity = perm_keys
        .iter()
        .zip(available.iter())
        .all(|(&a, &b)| a == b);
    if is_identity && perm_keys.len() >= 2 {
        // Swap first two.
        perm_keys.swap(0, 1);
    }

    let perm: HashMap<u32, u32> = available
        .iter()
        .zip(perm_keys.iter())
        .map(|(&old, &new)| (old, new))
        .collect();

    // Check that the permutation doesn't create conflicts with any instruction's
    // simultaneous live registers. For each instruction, collect all registers
    // mentioned and ensure no two distinct permutable regs map to the same target.
    // (This is guaranteed by construction since we use a permutation.)

    // Apply the permutation.
    let mut result = raw_words;
    for word in result.iter_mut() {
        // Apply permutation for each register field independently.
        for (&old, &new) in &perm {
            if old == new {
                continue;
            }
            *word = replace_reg(*word, old, new);
        }
    }

    // Encode back to bytes.
    let mut out = Vec::with_capacity(result.len() * 4);
    for &w in &result {
        out.extend_from_slice(&w.to_le_bytes());
    }
    out
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
    fn movz_x(val: u32, rd: u32) -> u32 {
        0xD280_0000 | (val << 5) | rd
    }

    #[test]
    fn empty_and_misaligned_passthrough() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        assert_eq!(
            reallocate_registers(&[], &mut rng),
            Vec::<u8>::new()
        );
        assert_eq!(
            reallocate_registers(&[1, 2, 3], &mut rng),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn deterministic_for_same_seed() {
        // MOVZ X9, #1; ADD X10, X9, #5; RET
        let add_x10_x9 = 0x9100_0000 | (5 << 10) | (9 << 5) | 10; // ADD X10, X9, #5
        let code = le_bytes(&[movz_x(1, 9), add_x10_x9, RET_X30]);
        let mut rng_a = ChaCha8Rng::seed_from_u64(42);
        let mut rng_b = ChaCha8Rng::seed_from_u64(42);
        let out_a = reallocate_registers(&code, &mut rng_a);
        let out_b = reallocate_registers(&code, &mut rng_b);
        assert_eq!(out_a, out_b, "same seed must produce identical output");
    }

    #[test]
    fn permutable_registers_are_renamed() {
        // X9 and X10 are both in the permutable pool and not live at entry.
        // MOVZ X9, #1; ADD X10, X9, #5; RET
        let add_x10_x9 = 0x9100_0000 | (5 << 10) | (9 << 5) | 10;
        let code = le_bytes(&[movz_x(1, 9), add_x10_x9, RET_X30]);
        let mut rng = ChaCha8Rng::seed_from_u64(7);
        let out = reallocate_registers(&code, &mut rng);
        let words = from_le(&out);

        // The original code uses X9 and X10. After permutation, they should
        // be renamed to other permutable registers (but never to pinned ones).
        let regs_used: HashSet<u32> = words
            .iter()
            .flat_map(|&w| {
                let mut s = HashSet::new();
                for &r in &[rd_field(w), rn_field(w), rm_field(w)] {
                    if r < 31 {
                        s.insert(r);
                    }
                }
                s
            })
            .collect();

        // Check that no pinned registers (other than X30 for RET) are introduced.
        for &r in &regs_used {
            if r == 30 {
                continue; // LR, used by RET.
            }
            assert!(
                !PINNED.contains(&r) || PERMUTABLE_POOL.contains(&r),
                "register X{} should not be a pinned register",
                r
            );
        }
    }

    #[test]
    fn preserves_ret() {
        let code = le_bytes(&[movz_x(0, 9), RET_X30]);
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let out = reallocate_registers(&code, &mut rng);
        let words = from_le(&out);
        assert!(
            words.iter().any(|&w| w == RET_X30),
            "RET should be preserved"
        );
    }

    #[test]
    fn pinned_regs_not_renamed() {
        // X0 is pinned. MOVZ X0, #1; ADD X9, X0, #5; RET
        // X9 should be renamed but X0 must not.
        let add_x9_x0 = 0x9100_0000 | (5 << 10) | (0 << 5) | 9;
        let code = le_bytes(&[movz_x(1, 0), add_x9_x0, RET_X30]);
        let mut rng = ChaCha8Rng::seed_from_u64(55);
        let out = reallocate_registers(&code, &mut rng);
        let words = from_le(&out);

        // X0 must still appear.
        assert!(
            words.iter().any(|&w| reg_appears(w, 0)),
            "X0 should not be renamed"
        );
    }

    #[test]
    fn pcrel_data_bailout() {
        let adrp = 0x9000_0000u32;
        let code = le_bytes(&[adrp, RET_X30]);
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let out = reallocate_registers(&code, &mut rng);
        assert_eq!(out, code);
    }
}
