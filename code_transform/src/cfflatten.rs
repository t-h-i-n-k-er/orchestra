//! M-1 – Control-flow flattening for x86-64 machine code.
#![cfg(target_arch = "x86_64")]
//!
//! # High-level algorithm
//!
//! 1. Decode input bytes into `Instruction` objects with iced-x86.
//! 2. Split decoded instructions into basic blocks.
//! 3. Pick a free 32-bit GPR (R8D–R15D) as the dispatcher state variable.
//! 4. Replace each block terminator with state assignments and `JMP dispatcher`:
//!    * Conditional jump: set state in taken/fallthrough paths.
//!    * Unconditional jump: set state to jump target block.
//!    * Fallthrough: set state to sequential successor block.
//! 5. Emit a single dispatcher (`CMP state, id` + `JE block`) chain.
//! 6. Insert opaque predicates before each dispatcher entry.
//! 7. Re-encode with `BlockEncoder` so branch displacements are fixed up.
//!
//! All random choices (state-ID permutation and opaque-predicate variants)
//! are drawn from the caller-supplied seeded `ChaCha8Rng`, making output
//! deterministic for reproducible builds.

use std::collections::{HashMap, HashSet};

use iced_x86::{Code, Decoder, DecoderOptions, Instruction, Register};
use rand::{seq::SliceRandom, Rng};
use rand_chacha::ChaCha8Rng;

use crate::substitute::encode_block;

/// Flatten control flow of x86-64 machine code into a state-dispatch model.
///
/// If flattening cannot be applied safely (for example, no free state register
/// is available or a direct branch targets an address outside the input slice),
/// the input is returned unchanged.
pub fn flatten_control_flow(code: &[u8], rng: &mut ChaCha8Rng) -> Vec<u8> {
    let base_ip: u64 = 0;
    let mut decoder = Decoder::with_ip(64, code, base_ip, DecoderOptions::NONE);
    let mut instructions: Vec<Instruction> = Vec::new();
    while decoder.can_decode() {
        instructions.push(decoder.decode());
    }

    if instructions.is_empty() {
        return code.to_vec();
    }

    let blocks = split_into_basic_blocks(&instructions);
    if blocks.len() <= 1 {
        // No meaningful CFG flattening possible.
        return code.to_vec();
    }

    let (state_reg32, state_reg64) = match pick_state_register(&instructions) {
        Some(r) => r,
        None => {
            log::debug!(
                "cfflatten: no free state register in R8D-R15D; returning input unchanged"
            );
            return code.to_vec();
        }
    };

    // Map block entry IP -> block index, used to resolve direct branch edges.
    let mut ip_to_block: HashMap<u64, usize> = HashMap::with_capacity(blocks.len());
    for (idx, block) in blocks.iter().enumerate() {
        ip_to_block.insert(block.start_ip, idx);
    }

    // Validate that all direct jump targets remain inside this code slice.
    if !all_direct_targets_internal(&blocks, &ip_to_block) {
        log::debug!(
            "cfflatten: external/unresolved branch target detected; returning input unchanged"
        );
        return code.to_vec();
    }

    // Assign randomized dispatcher state IDs to blocks.
    let mut state_ids: Vec<u32> = (0..blocks.len() as u32).collect();
    state_ids.shuffle(rng);

    // Synthetic instruction IPs live in a high sentinel range to avoid
    // collisions with original code IPs.
    let mut extra_ip: u64 = 0xFFFC_0000_0000_0000u64;
    let mut next_extra = || {
        let ip = extra_ip;
        extra_ip = extra_ip.wrapping_add(1);
        ip
    };

    let dispatcher_ip = next_extra();

    let mut out: Vec<Instruction> =
        Vec::with_capacity(instructions.len().saturating_mul(3) + blocks.len() * 12 + 8);

    // Entry stub: initialize state and jump into dispatcher.
    emit_state_write_guarded(
        &mut out,
        state_reg32,
        state_reg64,
        state_ids[0],
        &mut next_extra,
        None,
    );

    let mut jmp_dispatcher =
        Instruction::with_branch(Code::Jmp_rel32_64, dispatcher_ip).expect("JMP dispatcher");
    jmp_dispatcher.set_ip(next_extra());
    out.push(jmp_dispatcher);

    // Dispatcher label anchor.
    let mut dispatcher_anchor = Instruction::with(Code::Nopd);
    dispatcher_anchor.set_ip(dispatcher_ip);
    out.push(dispatcher_anchor);

    // Dispatcher switch chain: opaque predicate + cmp+je per block.
    for (idx, block) in blocks.iter().enumerate() {
        emit_dispatcher_opaque_predicate(&mut out, state_reg64, rng, &mut next_extra);

        let mut cmp = Instruction::with2(Code::Cmp_rm32_imm32, state_reg32, state_ids[idx] as i32)
            .expect("CMP state, imm32");
        cmp.set_ip(next_extra());
        out.push(cmp);

        let mut je =
            Instruction::with_branch(Code::Je_rel32_64, block.start_ip).expect("JE block_entry");
        je.set_ip(next_extra());
        out.push(je);
    }

    // Default route (should be unreachable for valid state values).
    let mut default_jmp =
        Instruction::with_branch(Code::Jmp_rel32_64, blocks[0].start_ip).expect("JMP default");
    default_jmp.set_ip(next_extra());
    out.push(default_jmp);

    // Emit flattened blocks.
    for block in &blocks {
        let mut lowered = match lower_block(
            block,
            &ip_to_block,
            &state_ids,
            state_reg32,
            state_reg64,
            dispatcher_ip,
            &mut next_extra,
        ) {
            Some(v) => v,
            None => {
                log::debug!(
                    "cfflatten: failed to lower block at IP {:#x}; returning input unchanged",
                    block.start_ip
                );
                return code.to_vec();
            }
        };

        if let Some(first) = lowered.first_mut() {
            // Ensure dispatcher targets land on each block's original leader IP.
            first.set_ip(block.start_ip);
        }
        out.extend(lowered);
    }

    encode_block(&out, base_ip)
}

#[derive(Clone)]
struct BasicBlock {
    start_ip: u64,
    instructions: Vec<Instruction>,
}

fn split_into_basic_blocks(instructions: &[Instruction]) -> Vec<BasicBlock> {
    if instructions.is_empty() {
        return Vec::new();
    }

    let mut leaders: HashSet<u64> = HashSet::new();
    leaders.insert(instructions[0].ip());

    for (idx, inst) in instructions.iter().enumerate() {
        if inst.is_jcc_short_or_near() || inst.is_jmp_short_or_near() {
            leaders.insert(inst.near_branch64());
        }
        if is_terminator(inst) {
            if let Some(next) = instructions.get(idx + 1) {
                leaders.insert(next.ip());
            }
        }
    }

    let mut blocks: Vec<BasicBlock> = Vec::new();
    let mut current: Vec<Instruction> = Vec::new();

    for &inst in instructions {
        if leaders.contains(&inst.ip()) && !current.is_empty() {
            let start_ip = current[0].ip();
            blocks.push(BasicBlock {
                start_ip,
                instructions: current,
            });
            current = Vec::new();
        }
        current.push(inst);
    }

    if !current.is_empty() {
        let start_ip = current[0].ip();
        blocks.push(BasicBlock {
            start_ip,
            instructions: current,
        });
    }

    blocks
}

fn all_direct_targets_internal(blocks: &[BasicBlock], ip_to_block: &HashMap<u64, usize>) -> bool {
    for block in blocks {
        let Some(last) = block.instructions.last() else {
            continue;
        };

        if last.is_jcc_short_or_near() {
            let target_ip = last.near_branch64();
            if !ip_to_block.contains_key(&target_ip) {
                return false;
            }
            let fallthrough_ip = last.ip().wrapping_add(last.len() as u64);
            if !ip_to_block.contains_key(&fallthrough_ip) {
                return false;
            }
        } else if last.is_jmp_short_or_near() {
            let target_ip = last.near_branch64();
            if !ip_to_block.contains_key(&target_ip) {
                return false;
            }
        }
    }
    true
}

fn lower_block(
    block: &BasicBlock,
    ip_to_block: &HashMap<u64, usize>,
    state_ids: &[u32],
    state_reg32: Register,
    state_reg64: Register,
    dispatcher_ip: u64,
    next_extra: &mut impl FnMut() -> u64,
) -> Option<Vec<Instruction>> {
    let mut out: Vec<Instruction> = Vec::new();
    let last = *block.instructions.last()?;

    // Emit all instructions except block terminator. We'll lower the terminator
    // into state transitions + dispatcher jumps as needed.
    if block.instructions.len() > 1 {
        out.extend_from_slice(&block.instructions[..block.instructions.len() - 1]);
    }

    if last.is_jcc_short_or_near() {
        let target_ip = last.near_branch64();
        let taken_idx = *ip_to_block.get(&target_ip)?;

        let fallthrough_ip = last.ip().wrapping_add(last.len() as u64);
        let fall_idx = *ip_to_block.get(&fallthrough_ip)?;

        let jcc_ip = next_extra();
        let taken_write_ip = next_extra();

        let mut jcc = Instruction::with_branch(last.code(), taken_write_ip).ok()?;
        jcc.set_ip(jcc_ip);
        out.push(jcc);

        emit_state_write_guarded(
            &mut out,
            state_reg32,
            state_reg64,
            state_ids[fall_idx],
            next_extra,
            None,
        );

        let mut jmp_fall = Instruction::with_branch(Code::Jmp_rel32_64, dispatcher_ip).ok()?;
        jmp_fall.set_ip(next_extra());
        out.push(jmp_fall);

        emit_state_write_guarded(
            &mut out,
            state_reg32,
            state_reg64,
            state_ids[taken_idx],
            next_extra,
            Some(taken_write_ip),
        );

        let mut jmp_taken = Instruction::with_branch(Code::Jmp_rel32_64, dispatcher_ip).ok()?;
        jmp_taken.set_ip(next_extra());
        out.push(jmp_taken);

        return Some(out);
    }

    if last.is_jmp_short_or_near() {
        let target_ip = last.near_branch64();
        let target_idx = *ip_to_block.get(&target_ip)?;

        emit_state_write_guarded(
            &mut out,
            state_reg32,
            state_reg64,
            state_ids[target_idx],
            next_extra,
            None,
        );

        let mut jmp_dispatch = Instruction::with_branch(Code::Jmp_rel32_64, dispatcher_ip).ok()?;
        jmp_dispatch.set_ip(next_extra());
        out.push(jmp_dispatch);

        return Some(out);
    }

    if is_unconditional_terminator(&last) {
        // Return/ud2/int3 keep original terminal behavior.
        out.push(last);
        return Some(out);
    }

    // Non-terminator at end of block: lower fallthrough through dispatcher.
    let fallthrough_ip = last.ip().wrapping_add(last.len() as u64);
    if let Some(&next_idx) = ip_to_block.get(&fallthrough_ip) {
        out.push(last);

        emit_state_write_guarded(
            &mut out,
            state_reg32,
            state_reg64,
            state_ids[next_idx],
            next_extra,
            None,
        );

        let mut jmp_dispatch = Instruction::with_branch(Code::Jmp_rel32_64, dispatcher_ip).ok()?;
        jmp_dispatch.set_ip(next_extra());
        out.push(jmp_dispatch);
    } else {
        // Final block with no sequential successor: preserve original behavior.
        out.push(last);
    }

    Some(out)
}

/// Emit a state write sequence guarded by a read of the same register.
///
/// The guard (`pushfq; cmp state,state; popfq`) preserves flags and creates a
/// read-before-def use of the state register within the block, which prevents
/// later local register-renaming passes from renaming the dispatcher state.
fn emit_state_write_guarded(
    out: &mut Vec<Instruction>,
    state_reg32: Register,
    state_reg64: Register,
    state_id: u32,
    next_extra: &mut impl FnMut() -> u64,
    first_ip: Option<u64>,
) {
    let push_ip = match first_ip {
        Some(ip) => ip,
        None => next_extra(),
    };

    let mut pushfq = Instruction::with(Code::Pushfq);
    pushfq.set_ip(push_ip);
    out.push(pushfq);

    let mut cmp =
        Instruction::with2(Code::Cmp_r64_rm64, state_reg64, state_reg64).expect("CMP state,state");
    cmp.set_ip(next_extra());
    out.push(cmp);

    let mut popfq = Instruction::with(Code::Popfq);
    popfq.set_ip(next_extra());
    out.push(popfq);

    let mut mov_state =
        Instruction::with2(Code::Mov_r32_imm32, state_reg32, state_id as i32).expect("MOV state, imm32");
    mov_state.set_ip(next_extra());
    out.push(mov_state);
}

fn emit_dispatcher_opaque_predicate(
    out: &mut Vec<Instruction>,
    state_reg64: Register,
    rng: &mut ChaCha8Rng,
    next_extra: &mut impl FnMut() -> u64,
) {
    let variant = rng.gen::<u8>() % 3;

    let mut pushfq = Instruction::with(Code::Pushfq);
    pushfq.set_ip(next_extra());
    out.push(pushfq);

    let mut cmp =
        Instruction::with2(Code::Cmp_r64_rm64, state_reg64, state_reg64).expect("CMP reg, reg");
    cmp.set_ip(next_extra());
    out.push(cmp);

    let jcc_code = match variant {
        0 => Code::Jne_rel8_64, // never taken after cmp reg,reg
        1 => Code::Je_rel8_64,  // always taken after cmp reg,reg
        _ => Code::Jg_rel8_64,  // never taken after cmp reg,reg
    };

    let jcc_ip = next_extra();
    let skip_ip = next_extra();

    let mut jcc = Instruction::with_branch(jcc_code, skip_ip).expect("opaque Jcc");
    jcc.set_ip(jcc_ip);
    out.push(jcc);

    let mut nop = Instruction::with(Code::Nopd);
    nop.set_ip(skip_ip);
    out.push(nop);

    let mut popfq = Instruction::with(Code::Popfq);
    popfq.set_ip(next_extra());
    out.push(popfq);
}

fn is_terminator(inst: &Instruction) -> bool {
    is_unconditional_terminator(inst) || inst.is_jcc_short_or_near()
}

fn is_unconditional_terminator(inst: &Instruction) -> bool {
    inst.is_jmp_short_or_near()
        || matches!(
            inst.code(),
            Code::Retnq
                | Code::Retnd
                | Code::Retnw
                | Code::Retnq_imm16
                | Code::Retnd_imm16
                | Code::Retnw_imm16
                | Code::Int3
                | Code::Ud2
                | Code::INVALID
        )
}

fn pick_state_register(instructions: &[Instruction]) -> Option<(Register, Register)> {
    // Candidate state registers in preferred order.
    const CANDIDATES: &[(Register, Register, [Register; 4])] = &[
        (Register::R15D, Register::R15, [Register::R15, Register::R15D, Register::R15W, Register::R15L]),
        (Register::R14D, Register::R14, [Register::R14, Register::R14D, Register::R14W, Register::R14L]),
        (Register::R13D, Register::R13, [Register::R13, Register::R13D, Register::R13W, Register::R13L]),
        (Register::R12D, Register::R12, [Register::R12, Register::R12D, Register::R12W, Register::R12L]),
        (Register::R11D, Register::R11, [Register::R11, Register::R11D, Register::R11W, Register::R11L]),
        (Register::R10D, Register::R10, [Register::R10, Register::R10D, Register::R10W, Register::R10L]),
        (Register::R9D, Register::R9, [Register::R9, Register::R9D, Register::R9W, Register::R9L]),
        (Register::R8D, Register::R8, [Register::R8, Register::R8D, Register::R8W, Register::R8L]),
    ];

    for &(reg32, reg64, family) in CANDIDATES {
        if !instructions
            .iter()
            .any(|inst| instruction_uses_family(inst, &family))
        {
            return Some((reg32, reg64));
        }
    }

    None
}

fn instruction_uses_family(inst: &Instruction, family: &[Register; 4]) -> bool {
    let regs = [
        inst.op0_register(),
        inst.op1_register(),
        inst.op2_register(),
        inst.op3_register(),
        inst.op4_register(),
        inst.memory_base(),
        inst.memory_index(),
    ];
    regs.iter().any(|r| family.contains(r))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn deterministic_for_same_seed() {
        // test rdi,rdi ; jz +1 ; ret ; ret
        let code: &[u8] = &[0x48, 0x85, 0xFF, 0x74, 0x01, 0xC3, 0xC3];

        let mut a = ChaCha8Rng::seed_from_u64(0xBEEF);
        let mut b = ChaCha8Rng::seed_from_u64(0xBEEF);

        let out_a = flatten_control_flow(code, &mut a);
        let out_b = flatten_control_flow(code, &mut b);

        assert_eq!(out_a, out_b, "same seed must produce identical output");
    }

    #[test]
    fn emits_dispatcher_shape() {
        // test rax,rax ; jnz +1 ; ret ; ret
        let code: &[u8] = &[0x48, 0x85, 0xC0, 0x75, 0x01, 0xC3, 0xC3];
        let mut rng = ChaCha8Rng::seed_from_u64(7);
        let out = flatten_control_flow(code, &mut rng);

        let mut decoder = Decoder::with_ip(64, &out, 0, DecoderOptions::NONE);
        let mut seen_cmp_imm32 = false;
        let mut seen_je = false;
        let mut seen_state_mov = false;

        while decoder.can_decode() {
            let i = decoder.decode();
            if matches!(i.code(), Code::Cmp_rm32_imm32) {
                seen_cmp_imm32 = true;
            }
            if matches!(i.code(), Code::Je_rel8_64 | Code::Je_rel32_64) {
                seen_je = true;
            }
            if matches!(i.code(), Code::Mov_r32_imm32) {
                seen_state_mov = true;
            }
        }

        assert!(seen_cmp_imm32, "dispatcher compare not emitted");
        assert!(seen_je, "dispatcher JE route not emitted");
        assert!(seen_state_mov, "state assignment not emitted");
    }
}
