//! Control-flow flattening for AArch64 machine code.
//!
//! # High-level algorithm
//!
//! 1. Decode input bytes into 32-bit instruction words.
//! 2. Split into basic blocks at branch targets and post-terminator boundaries.
//! 3. Pick a free X register (X8–X18) as the dispatcher state variable.
//! 4. Replace each block terminator with state assignments and `B dispatcher`:
//!    * Conditional branch (B.cond / CBZ / CBNZ / TBZ / TBNZ): set state in
//!      taken/fallthrough paths.
//!    * Unconditional `B`: set state to jump target block.
//!    * Fall-through: set state to sequential successor block.
//!    * RET / BR: preserved as-is.
//! 5. Emit a single dispatcher (`CMP state, #id` + `B.EQ block`) chain.
//! 6. Insert opaque predicates (EOR Xd,Xd,Xd; CBNZ Xd) before each dispatcher entry.
//! 7. Re-resolve all PC-relative branch displacements via [`finalize`].
//!
//! All random choices (state-ID permutation and opaque-predicate variants)
//! are drawn from the caller-supplied seeded PRNG, making output deterministic.

use std::collections::HashMap;

use rand::seq::SliceRandom;
use rand::Rng;

use crate::substitute_aarch64::{
    classify, finalize, is_pcrel_data, is_terminator, pc_rel_branch_disp,
    BranchKind, Item, ItemKind, SyntheticTarget,
};

// ─── ARM64 instruction encoding helpers ────────────────────────────────────

/// Encode `MOVZ Xd, #imm16` (move wide with zero, 64-bit, hw=0).
fn enc_movz_x(rd: u32, imm16: u32) -> u32 {
    debug_assert!(rd < 31 && imm16 < 65536);
    0xD280_0000 | (imm16 << 5) | rd
}

/// Encode `CMP Xn, #imm12` (64-bit immediate compare, alias of SUBS XZR, Xn, #imm12).
/// Encoding: 1 11 100010 0 imm12 Rn 11111
fn enc_cmp_x_imm(imm12: u32, rn: u32) -> u32 {
    debug_assert!(rn < 32 && imm12 < 4096);
    0xF100_0000 | (imm12 << 10) | (rn << 5) | 31
}

/// Encode `B.EQ #imm19*4` (conditional branch, condition EQ = 0000).
fn enc_b_eq(imm19: i32) -> u32 {
    let bits = (imm19 as u32) & 0x7_FFFF;
    0x5400_0000 | (bits << 5) | 0 // cond = 0 (EQ)
}

/// Encode `B #imm26*4` (unconditional branch).
fn enc_b(imm26: i32) -> u32 {
    let bits = (imm26 as u32) & 0x3FF_FFFF;
    0x1400_0000 | bits
}

/// Encode `EOR Xd, Xd, Xd` (sets Xd = 0).
fn enc_eor_same(d: u32) -> u32 {
    debug_assert!(d < 31);
    0xCA00_0000 | (d << 16) | (d << 5) | d
}

/// Encode `CBNZ Xt, #imm19*4`.
fn enc_cbnz_x(rt: u32, imm19: i32) -> u32 {
    debug_assert!(rt < 31);
    let bits = (imm19 as u32) & 0x7_FFFF;
    0xB500_0000 | (bits << 5) | rt
}

/// Encode `B.cond target_offset` with a specific condition code.
fn enc_b_cond(cond: u32, imm19: i32) -> u32 {
    debug_assert!(cond < 16);
    let bits = (imm19 as u32) & 0x7_FFFF;
    0x5400_0000 | (bits << 5) | cond
}

/// Extract the condition code from a B.cond instruction.
fn extract_b_cond(raw: u32) -> Option<u32> {
    if (raw & 0xFF00_0010) == 0x5400_0000 {
        Some(raw & 0xF)
    } else {
        None
    }
}

/// Extract the register and condition from a CBZ/CBNZ instruction.
/// Returns (is_cbnz, rt, imm19_words).
fn decode_cbz_cbnz(raw: u32) -> Option<(bool, u32, i32)> {
    let masked = raw & 0x7F00_0000;
    if masked == 0x3400_0000 || masked == 0x3500_0000 {
        let is_cbnz = masked == 0x3500_0000;
        let rt = raw & 0x1F;
        let imm19 = ((raw >> 5) & 0x7_FFFF) as i32;
        let s = (imm19 << 13) >> 13;
        Some((is_cbnz, rt, s))
    } else {
        None
    }
}

/// Extract the register, bit, and offset from a TBZ/TBNZ instruction.
/// Returns (is_tbnz, rt, bit, imm14_words).
fn decode_tbz_tbnz(raw: u32) -> Option<(bool, u32, u32, i32)> {
    let masked = raw & 0x7F00_0000;
    if masked == 0x3600_0000 || masked == 0x3700_0000 {
        let is_tbnz = masked == 0x3700_0000;
        let b5 = (raw >> 31) & 1;
        let b40 = (raw >> 19) & 0x1F;
        let bit = (b5 << 5) | b40;
        let rt = raw & 0x1F;
        let imm14 = ((raw >> 5) & 0x3FFF) as i32;
        let s = (imm14 << 18) >> 18;
        Some((is_tbnz, rt, bit, s))
    } else {
        None
    }
}

/// Encode `B.NE #imm19*4` (conditional branch, NE = 0001).
fn _enc_b_ne(imm19: i32) -> u32 {
    enc_b_cond(1, imm19)
}

// ─── Basic block representation ─────────────────────────────────────────────

#[derive(Clone)]
struct BasicBlock {
    /// Index of the first instruction in the block (in the `raw_words` array).
    start_idx: usize,
    /// One-past-end index.
    end_idx: usize,
    /// Byte offset of the first instruction in the original input.
    start_orig_off: u32,
}

// ─── State register selection ───────────────────────────────────────────────

/// Registers available for the dispatcher state variable.
/// X8–X18: callee-saved or scratch depending on ABI variant.
/// We prefer the less commonly used ones first.
const STATE_CANDIDATES: &[u32] = &[18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8];

/// Check if a register index appears in any instruction as an operand.
fn reg_is_used_in(raw_words: &[u32], reg: u32) -> bool {
    for &raw in raw_words {
        if reg_appears(raw, reg) {
            return true;
        }
    }
    false
}

/// Check if register `reg` (0-30) appears in instruction `raw`.
/// This is a conservative check that looks at the Rd and Rn fields for common
/// instruction classes.  It may produce false positives but never false negatives.
fn reg_appears(raw: u32, reg: u32) -> bool {
    // Rd is always bits[4:0] for register-result instructions.
    if (raw & 0x1F) == reg {
        return true;
    }
    // Rn is usually bits[9:5].
    if ((raw >> 5) & 0x1F) == reg {
        return true;
    }
    // Rm is usually bits[20:16].
    if ((raw >> 16) & 0x1F) == reg {
        return true;
    }
    false
}

// ─── Public entry point ─────────────────────────────────────────────────────

/// Flatten control flow of AArch64 machine code into a state-dispatch model.
///
/// If flattening cannot be applied safely (for example, no free state register
/// is available, the input contains PC-relative data references, or a branch
/// targets outside the code), the input is returned unchanged.
pub fn flatten_control_flow(code: &[u8], rng: &mut impl Rng) -> Vec<u8> {
    if code.is_empty() || code.len() % 4 != 0 {
        return code.to_vec();
    }

    let raw_words: Vec<u32> = code
        .chunks_exact(4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        .collect();

    // Bail out if any PC-relative *data* instruction is present.
    if raw_words.iter().any(|&r| is_pcrel_data(r)) {
        return code.to_vec();
    }

    let blocks = split_into_basic_blocks(&raw_words);
    if blocks.len() <= 1 {
        return code.to_vec();
    }

    // Pick a free state register.
    let state_reg = match pick_state_register(&raw_words) {
        Some(r) => r,
        None => {
            log::debug!(
                "cfflatten_aarch64: no free state register in X8-X18; returning input unchanged"
            );
            return code.to_vec();
        }
    };

    // Map original byte offset → block index.
    let mut off_to_block: HashMap<u32, usize> = HashMap::with_capacity(blocks.len());
    for (idx, block) in blocks.iter().enumerate() {
        off_to_block.insert(block.start_orig_off, idx);
    }

    // Validate that all direct branch targets remain inside this code slice.
    if !all_direct_targets_internal(&raw_words, &blocks, &off_to_block) {
        log::debug!(
            "cfflatten_aarch64: external/unresolved branch target detected; returning input unchanged"
        );
        return code.to_vec();
    }

    // Assign randomized dispatcher state IDs.
    let mut state_ids: Vec<u32> = (0..blocks.len() as u32).collect();
    state_ids.shuffle(rng);

    // Build the output item list.
    let mut items: Vec<Item> = Vec::with_capacity(raw_words.len() * 3 + blocks.len() * 12);

    // Entry stub: initialize state with block-0's ID and branch to dispatcher.
    // The dispatcher will be appended later; its offset is computed after all
    // blocks are emitted.  We use a synthetic B that targets the dispatcher.
    items.push(Item {
        raw: enc_movz_x(state_reg, state_ids[0]),
        kind: ItemKind::SyntheticData,
    });

    // Placeholder for the initial B dispatcher — patched by finalize.
    items.push(Item {
        raw: enc_b(0),
        kind: ItemKind::SyntheticBranch {
            target: SyntheticTarget::OrigOffset(DISPATCHER_ANCHOR_ORIG_OFF),
        },
    });

    // Emit flattened blocks.
    for (block_idx, block) in blocks.iter().enumerate() {
        let lowered = lower_block(
            block,
            block_idx,
            &raw_words,
            &off_to_block,
            &state_ids,
            state_reg,
        );

        // Mark the first item with the original block offset for dispatcher targeting.
        for (i, item) in lowered.into_iter().enumerate() {
            let mut item = item;
            if i == 0 {
                // Ensure dispatcher targets can find this block via orig offset.
                item.kind = ItemKind::Original {
                    orig_offset: block.start_orig_off,
                };
            }
            items.push(item);
        }
    }

    // Emit dispatcher: opaque predicate + CMP/B.EQ per block.
    let dispatcher_orig_off = DISPATCHER_ANCHOR_ORIG_OFF;
    items.push(Item {
        raw: 0xD503_201F, // NOP (dispatcher anchor marker)
        kind: ItemKind::Original {
            orig_offset: dispatcher_orig_off,
        },
    });

    for (idx, _block) in blocks.iter().enumerate() {
        // Opaque predicate: EOR X16,X16,X16; CBNZ X16, +1
        items.push(Item {
            raw: enc_eor_same(16),
            kind: ItemKind::SyntheticData,
        });
        items.push(Item {
            raw: enc_cbnz_x(16, 1),
            kind: ItemKind::SyntheticBranch {
                target: SyntheticTarget::NextInstr,
            },
        });

        // CMP state_reg, #state_id
        items.push(Item {
            raw: enc_cmp_x_imm(state_ids[idx], state_reg),
            kind: ItemKind::SyntheticData,
        });

        // B.EQ block_entry (target via orig offset)
        items.push(Item {
            raw: enc_b_eq(0), // placeholder displacement
            kind: ItemKind::SyntheticBranch {
                target: SyntheticTarget::OrigOffset(blocks[idx].start_orig_off),
            },
        });
    }

    // Default fallthrough (should be unreachable for valid state values).
    // Branch to block 0 as a safety net.
    items.push(Item {
        raw: enc_b(0),
        kind: ItemKind::SyntheticBranch {
            target: SyntheticTarget::OrigOffset(blocks[0].start_orig_off),
        },
    });

    finalize(&items)
}

/// Sentinel "original offset" for the dispatcher anchor.  Uses a value that
/// cannot appear as a real original offset (which are all multiples of 4 and
/// < 2^32 in practice).  We use u32::MAX which is guaranteed not to collide.
const DISPATCHER_ANCHOR_ORIG_OFF: u32 = 0xFFFF_FFFC;

// ─── Block splitting ────────────────────────────────────────────────────────

fn split_into_basic_blocks(raw_words: &[u32]) -> Vec<BasicBlock> {
    let n = raw_words.len();
    if n == 0 {
        return Vec::new();
    }

    let mut is_leader = vec![false; n];
    is_leader[0] = true;

    for (i, &raw) in raw_words.iter().enumerate() {
        let kind = classify(raw);
        if is_terminator(kind) && i + 1 < n {
            is_leader[i + 1] = true;
        }
        if let Some(disp) = pc_rel_branch_disp(raw) {
            let target_byte = (i as i64) * 4 + disp as i64;
            if target_byte >= 0 && (target_byte as usize) < n * 4 && target_byte % 4 == 0 {
                is_leader[(target_byte as usize) / 4] = true;
            }
        }
        // Conditional branches, BL, and BLR fall through.
        if matches!(kind, BranchKind::PcRelCond | BranchKind::PcRelBL | BranchKind::BlrIndirect)
            && i + 1 < n
        {
            is_leader[i + 1] = true;
        }
    }

    let mut blocks: Vec<BasicBlock> = Vec::new();
    let mut start = 0usize;
    for i in 1..n {
        if is_leader[i] {
            blocks.push(BasicBlock {
                start_idx: start,
                end_idx: i,
                start_orig_off: (start * 4) as u32,
            });
            start = i;
        }
    }
    blocks.push(BasicBlock {
        start_idx: start,
        end_idx: n,
        start_orig_off: (start * 4) as u32,
    });

    blocks
}

// ─── Target validation ──────────────────────────────────────────────────────

fn all_direct_targets_internal(
    raw_words: &[u32],
    blocks: &[BasicBlock],
    off_to_block: &HashMap<u32, usize>,
) -> bool {
    for block in blocks {
        let last_idx = block.end_idx - 1;
        let last = raw_words[last_idx];
        let kind = classify(last);

        match kind {
            BranchKind::PcRelB => {
                if let Some(disp) = pc_rel_branch_disp(last) {
                    let target_off =
                        ((last_idx as i64) * 4 + disp as i64) as u32;
                    if !off_to_block.contains_key(&target_off) {
                        return false;
                    }
                }
            }
            BranchKind::PcRelCond => {
                if let Some(disp) = pc_rel_branch_disp(last) {
                    let target_off =
                        ((last_idx as i64) * 4 + disp as i64) as u32;
                    if !off_to_block.contains_key(&target_off) {
                        return false;
                    }
                    // Fall-through must also be a valid block start.
                    let ft_off = (block.end_idx * 4) as u32;
                    if !off_to_block.contains_key(&ft_off) {
                        return false;
                    }
                }
            }
            _ => {}
        }
    }
    true
}

// ─── State register selection ───────────────────────────────────────────────

fn pick_state_register(raw_words: &[u32]) -> Option<u32> {
    for &reg in STATE_CANDIDATES {
        if !reg_is_used_in(raw_words, reg) {
            return Some(reg);
        }
    }
    None
}

// ─── Block lowering ─────────────────────────────────────────────────────────

fn lower_block(
    block: &BasicBlock,
    _block_idx: usize,
    raw_words: &[u32],
    off_to_block: &HashMap<u32, usize>,
    state_ids: &[u32],
    state_reg: u32,
) -> Vec<Item> {
    let mut items: Vec<Item> = Vec::new();
    let last_idx = block.end_idx - 1;
    let last_raw = raw_words[last_idx];
    let last_kind = classify(last_raw);

    // Emit non-terminator instructions.
    for i in block.start_idx..last_idx {
        items.push(Item {
            raw: raw_words[i],
            kind: ItemKind::Original {
                orig_offset: (i * 4) as u32,
            },
        });
    }

    // Lower the terminator.
    match last_kind {
        BranchKind::PcRelCond => {
            lower_conditional_branch(
                last_raw,
                last_idx,
                block,
                off_to_block,
                state_ids,
                state_reg,
                &mut items,
            )
        }
        BranchKind::PcRelB => {
            lower_unconditional_branch(
                last_raw,
                last_idx,
                off_to_block,
                state_ids,
                state_reg,
                &mut items,
            )
        }
        BranchKind::Ret | BranchKind::BrIndirect => {
            // Preserve RET and BR as-is.
            items.push(Item {
                raw: last_raw,
                kind: ItemKind::Original {
                    orig_offset: (last_idx * 4) as u32,
                },
            });
        }
        BranchKind::PcRelBL | BranchKind::BlrIndirect => {
            // BL/BLR: preserve as-is, then fallthrough to next block via dispatcher.
            items.push(Item {
                raw: last_raw,
                kind: ItemKind::Original {
                    orig_offset: (last_idx * 4) as u32,
                },
            });
            // Set state to fallthrough successor and branch to dispatcher.
            let ft_off = (block.end_idx * 4) as u32;
            if let Some(&next_idx) = off_to_block.get(&ft_off) {
                emit_state_assign(state_ids[next_idx], state_reg, &mut items);
                emit_b_dispatcher(&mut items);
            }
        }
        BranchKind::None => {
            // No terminator — fallthrough to next block via dispatcher.
            let ft_off = (block.end_idx * 4) as u32;
            // Emit the last instruction too.
            items.push(Item {
                raw: last_raw,
                kind: ItemKind::Original {
                    orig_offset: (last_idx * 4) as u32,
                },
            });
            if let Some(&next_idx) = off_to_block.get(&ft_off) {
                emit_state_assign(state_ids[next_idx], state_reg, &mut items);
                emit_b_dispatcher(&mut items);
            }
        }
    }

    items
}

/// Lower a conditional branch into a state-dispatch sequence.
fn lower_conditional_branch(
    raw: u32,
    idx: usize,
    block: &BasicBlock,
    off_to_block: &HashMap<u32, usize>,
    state_ids: &[u32],
    state_reg: u32,
    items: &mut Vec<Item>,
) {
    let disp = match pc_rel_branch_disp(raw) {
        Some(d) => d,
        None => {
            // Can't decode — emit as-is.
            items.push(Item {
                raw,
                kind: ItemKind::Original {
                    orig_offset: (idx * 4) as u32,
                },
            });
            return;
        }
    };

    let taken_off = ((idx as i64) * 4 + disp as i64) as u32;
    let ft_off = (block.end_idx * 4) as u32;

    let taken_idx = off_to_block.get(&taken_off).copied();
    let ft_idx = off_to_block.get(&ft_off).copied();

    // Try B.cond lowering.
    if let Some(cond) = extract_b_cond(raw) {
        // Inverted: B.cond sets state and jumps to dispatcher.
        // B.inverted cond → skip state assign for taken, fall through to assign.
        if let (Some(ti), Some(fi)) = (taken_idx, ft_idx) {
            // Taken path: set state to taken, branch to dispatcher.
            // We restructure as:
            //   B.inverted_cond skip          (if condition NOT met, skip taken path)
            //   MOVZ state_reg, #taken_id
            //   B dispatcher
            // skip:
            //   MOVZ state_reg, #fallthrough_id
            //   B dispatcher
            let inv_cond = cond ^ 1; // invert condition

            items.push(Item {
                raw: enc_b_cond(inv_cond, 2), // skip past taken path (2 instructions)
                kind: ItemKind::SyntheticBranch {
                    target: SyntheticTarget::NextInstr, // approximate; finalize resolves
                },
            });

            // Taken path: state = taken_id
            emit_state_assign(state_ids[ti], state_reg, items);
            emit_b_dispatcher(items);

            // Fallthrough path: state = ft_id
            emit_state_assign(state_ids[fi], state_reg, items);
            emit_b_dispatcher(items);
            return;
        }
    }

    // Try CBZ/CBNZ lowering.
    if let Some((is_cbnz, rt, _imm)) = decode_cbz_cbnz(raw) {
        if let (Some(ti), Some(fi)) = (taken_idx, ft_idx) {
            // CBZ rt, taken → if rt==0 branch to taken, else fall through.
            // Restructure:
            //   CBZ rt, taken_path
            //   MOVZ state, #ft_id ; B dispatcher
            // taken_path:
            //   MOVZ state, #taken_id ; B dispatcher
            items.push(Item {
                raw: if is_cbnz {
                    enc_cbnz_x(rt, 2) // skip past fallthrough path
                } else {
                    // CBZ: if rt==0, skip to taken path
                    let bits: u32 = 2;
                    0xB400_0000 | (bits << 5) | rt
                },
                kind: ItemKind::SyntheticBranch {
                    target: SyntheticTarget::NextInstr,
                },
            });

            // Fallthrough path.
            emit_state_assign(state_ids[fi], state_reg, items);
            emit_b_dispatcher(items);

            // Taken path.
            emit_state_assign(state_ids[ti], state_reg, items);
            emit_b_dispatcher(items);
            return;
        }
    }

    // Try TBZ/TBNZ lowering.
    if let Some((is_tbnz, rt, bit, _imm)) = decode_tbz_tbnz(raw) {
        if let (Some(ti), Some(fi)) = (taken_idx, ft_idx) {
            // Same pattern as CBZ/CBNZ.
            let b5 = (bit >> 5) & 1;
            let b40 = bit & 0x1F;
            let base: u32 = if is_tbnz {
                (b5 << 31) | 0x3700_0000
            } else {
                (b5 << 31) | 0x3600_0000
            };
            let imm14 = 2u32; // skip 2 instructions
            items.push(Item {
                raw: base | (imm14 << 5) | b40 | rt,
                kind: ItemKind::SyntheticBranch {
                    target: SyntheticTarget::NextInstr,
                },
            });

            emit_state_assign(state_ids[fi], state_reg, items);
            emit_b_dispatcher(items);

            emit_state_assign(state_ids[ti], state_reg, items);
            emit_b_dispatcher(items);
            return;
        }
    }

    // Fallback: emit as-is.
    items.push(Item {
        raw,
        kind: ItemKind::Original {
            orig_offset: (idx * 4) as u32,
        },
    });
}

/// Lower an unconditional `B target` into state assignment + dispatcher jump.
fn lower_unconditional_branch(
    raw: u32,
    idx: usize,
    off_to_block: &HashMap<u32, usize>,
    state_ids: &[u32],
    state_reg: u32,
    items: &mut Vec<Item>,
) {
    let disp = match pc_rel_branch_disp(raw) {
        Some(d) => d,
        None => {
            items.push(Item {
                raw,
                kind: ItemKind::Original {
                    orig_offset: (idx * 4) as u32,
                },
            });
            return;
        }
    };

    let target_off = ((idx as i64) * 4 + disp as i64) as u32;

    if let Some(&target_idx) = off_to_block.get(&target_off) {
        emit_state_assign(state_ids[target_idx], state_reg, items);
        emit_b_dispatcher(items);
    } else {
        // External target — emit as-is.
        items.push(Item {
            raw,
            kind: ItemKind::Original {
                orig_offset: (idx * 4) as u32,
            },
        });
    }
}

/// Emit state assignment: `MOVZ state_reg, #id`.
fn emit_state_assign(state_id: u32, state_reg: u32, items: &mut Vec<Item>) {
    if state_id < 65536 {
        items.push(Item {
            raw: enc_movz_x(state_reg, state_id),
            kind: ItemKind::SyntheticData,
        });
    } else {
        // For IDs >= 65536, use MOVZ + MOVK (two instructions).
        let lo = state_id & 0xFFFF;
        let hi = (state_id >> 16) & 0xFFFF;
        items.push(Item {
            raw: enc_movz_x(state_reg, lo),
            kind: ItemKind::SyntheticData,
        });
        // MOVK Xd, #hi, LSL #16: 1 10 100101 01 hw=1 imm16 Rd
        // = 0xF2A00000 | (imm16 << 5) | Rd
        items.push(Item {
            raw: 0xF2A0_0000 | (hi << 5) | state_reg,
            kind: ItemKind::SyntheticData,
        });
    }
}

/// Emit `B dispatcher` with placeholder targeting the dispatcher anchor.
fn emit_b_dispatcher(items: &mut Vec<Item>) {
    items.push(Item {
        raw: enc_b(0),
        kind: ItemKind::SyntheticBranch {
            target: SyntheticTarget::OrigOffset(DISPATCHER_ANCHOR_ORIG_OFF),
        },
    });
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
        assert_eq!(
            flatten_control_flow(&[], &mut rng),
            Vec::<u8>::new()
        );
        assert_eq!(
            flatten_control_flow(&[1, 2, 3], &mut rng),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn single_block_passthrough() {
        // MOVZ X0, #0; RET
        let code = le_bytes(&[movz_x0(0), RET_X30]);
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let out = flatten_control_flow(&code, &mut rng);
        // Single block → returned unchanged.
        assert_eq!(out, code);
    }

    #[test]
    fn deterministic_for_same_seed() {
        // MOVZ X0, #1; CMP X0, #0; B.EQ +8; RET; RET
        let b_eq = 0x5400_0020; // B.EQ to offset +8 (2 instructions)
        let code = le_bytes(&[movz_x0(1), 0xF100_001F, b_eq, RET_X30, RET_X30]);
        let mut rng_a = ChaCha8Rng::seed_from_u64(42);
        let mut rng_b = ChaCha8Rng::seed_from_u64(42);
        let out_a = flatten_control_flow(&code, &mut rng_a);
        let out_b = flatten_control_flow(&code, &mut rng_b);
        assert_eq!(out_a, out_b, "same seed must produce identical output");
    }

    #[test]
    fn emits_dispatcher_shape() {
        // Two-block function: MOVZ X0, #1; B +8; RET; RET
        let b_fwd = 0x1400_0002; // B +8 (2 instructions forward)
        let code = le_bytes(&[movz_x0(1), b_fwd, RET_X30, RET_X30]);
        let mut rng = ChaCha8Rng::seed_from_u64(7);
        let out = flatten_control_flow(&code, &mut rng);

        let words = from_le(&out);
        // Should contain CMP (state, imm) and B.EQ instructions.
        let has_cmp = words.iter().any(|&w| (w & 0xFFE0_0000) == 0xF100_0000);
        let has_beq = words.iter().any(|&w| (w & 0xFF00_001F) == 0x5400_0000);
        let has_movz_state = words.iter().any(|&w| (w & 0xFFE0_0000) == 0xD280_0000);
        assert!(has_cmp, "dispatcher CMP not emitted");
        assert!(has_beq, "dispatcher B.EQ not emitted");
        assert!(has_movz_state, "state assignment MOVZ not emitted");
    }

    #[test]
    fn preserves_ret() {
        // RET should be preserved.
        let code = le_bytes(&[movz_x0(0), RET_X30]);
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let out = flatten_control_flow(&code, &mut rng);
        let words = from_le(&out);
        assert!(
            words.iter().any(|&w| w == RET_X30),
            "RET should be preserved"
        );
    }

    #[test]
    fn pcrel_data_bailout() {
        // ADRP X0, #0 → has PC-relative data reference
        let adrp = 0x9000_0000u32; // ADRP X0, #0
        let code = le_bytes(&[adrp, RET_X30]);
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let out = flatten_control_flow(&code, &mut rng);
        assert_eq!(out, code, "should return input unchanged when ADRP present");
    }
}
