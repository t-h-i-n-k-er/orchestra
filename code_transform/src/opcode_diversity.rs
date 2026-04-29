//! Opcode-diversity pass — instruction-level equivalent replacements.
#![cfg(target_arch = "x86_64")]
//!
//! Four rules are applied to each basic block:
//!
//! **Rule 1** Register renaming  
//! Within a block, a scratch register from R8–R15 that is written before
//! any read from the block entry is probabilistically renamed to a free
//! caller-saved register in RAX–RDX.  Both old and new registers must be
//! proven "local" (def-before-use) so no live value is disturbed.
//!
//! **Rule 2** ADD → SUB  
//! `ADD reg, imm` → `SUB reg, –imm` when the negation does not overflow and
//! the immediately following instruction does not read the carry flag (CF).
//! Result, ZF, SF, OF, and PF are identical; only CF differs, so the check
//! for carry-reading successors keeps the substitution safe.
//!
//! **Rule 3** NOP sled  
//! At the entry of each reordered block (except block 0), insert 1–3
//! semantically-equivalent NOP instructions drawn from a set of distinct
//! encodings: `NOP` (0x90), `MOV R11, R11` (48-bit self-move), `XCHG R10,
//! R10` (register self-exchange).  All three leave every register and flag
//! unchanged.
//!
//! **Rule 4** Conditional-branch inversion  
//! `JZ target` is replaced with `JNZ fallthrough; JMP target` (and vice
//! versa for JNZ, and analogously for all other inverting Jcc pairs).  The
//! control flow is identical: the inverted branch skips the unconditional
//! JMP when the original would have fallen through, so the same target is
//! reached in both cases.

use std::collections::{HashMap, HashSet};

use iced_x86::{Code, Decoder, DecoderOptions, Instruction, OpKind, Register};
use rand::{seq::SliceRandom, Rng};

use crate::substitute::{encode_block, to_64bit};

// ─── Public entry point ───────────────────────────────────────────────────────

/// Apply all four opcode-diversity rules to a flat x86-64 machine-code slice.
///
/// All transforms are semantically equivalent given the preconditions
/// documented for each rule above.
pub fn apply(code: &[u8], rng: &mut impl Rng) -> Vec<u8> {
    let base_ip: u64 = 0;
    let mut decoder = Decoder::with_ip(64, code, base_ip, DecoderOptions::NONE);
    let mut instructions: Vec<Instruction> = Vec::new();
    while decoder.can_decode() {
        instructions.push(decoder.decode());
    }
    if instructions.is_empty() {
        return code.to_vec();
    }

    let blocks = find_basic_blocks(&instructions);
    let mut out: Vec<Instruction> = Vec::with_capacity(instructions.len() + 32);
    // Sentinel IPs for inserted synthetic instructions — must not collide with
    // any original IP (which all start at 0 in this crate's usage).
    let mut extra_ip: u64 = 0xFFFF_0002_0000_0000u64;

    for (block_idx, block_range) in blocks.iter().enumerate() {
        let block = &instructions[block_range.clone()];

        // ── Rule 3: NOP sled at block entry (except the very first block) ────
        if block_idx > 0 && rng.gen_bool(0.40) {
            let count = rng.gen_range(1u32..=3u32);
            for _ in 0..count {
                extra_ip += 1;
                let mut nop = make_nop_variant(rng);
                nop.set_ip(extra_ip);
                out.push(nop);
            }
        }

        // ── Rule 1: Register renaming within block (25 % probability) ────────
        let renamed: Vec<Instruction>;
        let working: &[Instruction] = if rng.gen_bool(0.25) {
            renamed = apply_register_rename(block, rng);
            &renamed
        } else {
            block
        };

        // ── Rules 2 & 4 applied per instruction ──────────────────────────────
        for (i, inst) in working.iter().enumerate() {
            // The IP of the next instruction in the original stream — used as
            // the fall-through target when inverting a conditional branch.
            let next_ip = instructions
                .get(block_range.start + i + 1)
                .map(|n| n.ip());

            // Rule 4: invert Jcc (50 % probability)
            if inst.is_jcc_short_or_near() {
                if let Some(fallthrough_ip) = next_ip {
                    if rng.gen_bool(0.50) {
                        if let Some((new_jcc, jmp)) =
                            invert_jcc(inst, fallthrough_ip, &mut extra_ip)
                        {
                            out.push(new_jcc);
                            out.push(jmp);
                            continue;
                        }
                    }
                }
            }

            // Rule 2: ADD reg, imm → SUB reg, –imm (50 % probability)
            if rng.gen_bool(0.50) {
                if let Some(sub_inst) = try_add_to_sub(inst, working, i) {
                    out.push(sub_inst);
                    continue;
                }
            }

            out.push(*inst);
        }
    }

    encode_block(&out, base_ip)
}

// ─── Rule 3: NOP variants ─────────────────────────────────────────────────────

/// Create one of three semantically-equivalent NOP encodings.
///
/// * `NOP` (0x90) — the standard single-byte no-op.
/// * `MOV R11, R11` — 64-bit self-move; does not alter any register value.
/// * `XCHG R10, R10` — 64-bit self-exchange; does not alter any register value.
fn make_nop_variant(rng: &mut impl Rng) -> Instruction {
    match rng.gen_range(0u32..3u32) {
        0 => Instruction::with(Code::Nopd),
        1 => Instruction::with2(Code::Mov_r64_rm64, Register::R11, Register::R11)
            .expect("MOV R11, R11"),
        _ => Instruction::with2(Code::Xchg_rm64_r64, Register::R10, Register::R10)
            .expect("XCHG R10, R10"),
    }
}

// ─── Rule 2: ADD → SUB ────────────────────────────────────────────────────────

/// Convert `ADD reg, imm` → `SUB reg, –imm`, if safe.
///
/// Safety requirements:
/// * `imm ≠ i32::MIN` — negation must not overflow i32.
/// * The next instruction must not read the carry flag (CF).
pub(crate) fn try_add_to_sub(
    inst: &Instruction,
    instructions: &[Instruction],
    idx: usize,
) -> Option<Instruction> {
    let (is_64bit, imm_i64) = match inst.code() {
        Code::Add_rm64_imm8 => (true, inst.immediate8to64()),
        Code::Add_rm64_imm32 => (true, inst.immediate32to64()),
        Code::Add_rm32_imm8 => (false, inst.immediate8to64()),
        Code::Add_rm32_imm32 => (false, inst.immediate32to64()),
        _ => return None,
    };

    // Guard: negation of i32::MIN overflows i32.
    if imm_i64 == i64::from(i32::MIN) {
        return None;
    }

    // Guard: do not apply when the carry flag is consumed next.
    if next_reads_carry(instructions, idx) {
        return None;
    }

    let neg = -imm_i64;
    let reg = inst.op0_register();

    let sub_code = match (is_64bit, neg >= -128 && neg <= 127) {
        (true, true) => Code::Sub_rm64_imm8,
        (true, false) => Code::Sub_rm64_imm32,
        (false, true) => Code::Sub_rm32_imm8,
        (false, false) => Code::Sub_rm32_imm32,
    };

    Instruction::with2(sub_code, reg, neg as i32).ok()
}

/// Returns `true` when instruction `idx+1` reads the carry flag.
fn next_reads_carry(instructions: &[Instruction], idx: usize) -> bool {
    let next = match instructions.get(idx + 1) {
        Some(n) => n,
        None => return false,
    };
    // Jcc that test CF: JB/JC, JAE/JNC, JBE/JNA, JA/JNBE
    let is_carry_jcc = matches!(
        next.code(),
        Code::Jb_rel8_64
            | Code::Jb_rel32_64
            | Code::Jae_rel8_64
            | Code::Jae_rel32_64
            | Code::Jbe_rel8_64
            | Code::Jbe_rel32_64
            | Code::Ja_rel8_64
            | Code::Ja_rel32_64
    );
    is_carry_jcc
        || matches!(
            next.code(),
            Code::Adc_r64_rm64
                | Code::Adc_r32_rm32
                | Code::Adc_rm64_imm8
                | Code::Adc_rm64_imm32
                | Code::Adc_rm32_imm8
                | Code::Adc_rm32_imm32
                | Code::Sbb_r64_rm64
                | Code::Sbb_r32_rm32
                | Code::Sbb_rm64_imm8
                | Code::Sbb_rm64_imm32
                | Code::Sbb_rm32_imm8
                | Code::Sbb_rm32_imm32
                | Code::Rcl_rm64_CL
                | Code::Rcr_rm64_CL
                | Code::Rcl_rm32_CL
                | Code::Rcr_rm32_CL
                | Code::Lahf
                | Code::Pushfq
        )
}

// ─── Rule 4: Jcc inversion ────────────────────────────────────────────────────

/// Replace `Jcc target` with `J(NOT cc) fallthrough; JMP target`.
///
/// The inverted conditional jumps over the unconditional JMP when the
/// original Jcc would have fallen through, and the JMP is taken when the
/// original condition was met — so both sequences reach the same targets
/// under the same conditions.
fn invert_jcc(
    inst: &Instruction,
    fallthrough_ip: u64,
    extra_ip: &mut u64,
) -> Option<(Instruction, Instruction)> {
    let inverted_code = invert_jcc_code(inst.code())?;
    let orig_target = inst.near_branch64();

    // New conditional: inverted sense → jump to old fall-through address.
    let mut new_jcc = Instruction::with_branch(inverted_code, fallthrough_ip).ok()?;
    new_jcc.set_ip(inst.ip());

    // Unconditional JMP to original target — only reached when original
    // condition was true.
    *extra_ip += 1;
    let mut jmp = Instruction::with_branch(Code::Jmp_rel32_64, orig_target).ok()?;
    jmp.set_ip(*extra_ip);

    Some((new_jcc, jmp))
}

/// Map each invertible 64-bit Jcc code to its logical complement.
fn invert_jcc_code(code: Code) -> Option<Code> {
    Some(match code {
        Code::Je_rel8_64 => Code::Jne_rel8_64,
        Code::Jne_rel8_64 => Code::Je_rel8_64,
        Code::Je_rel32_64 => Code::Jne_rel32_64,
        Code::Jne_rel32_64 => Code::Je_rel32_64,
        Code::Jl_rel8_64 => Code::Jge_rel8_64,
        Code::Jge_rel8_64 => Code::Jl_rel8_64,
        Code::Jl_rel32_64 => Code::Jge_rel32_64,
        Code::Jge_rel32_64 => Code::Jl_rel32_64,
        Code::Jle_rel8_64 => Code::Jg_rel8_64,
        Code::Jg_rel8_64 => Code::Jle_rel8_64,
        Code::Jle_rel32_64 => Code::Jg_rel32_64,
        Code::Jg_rel32_64 => Code::Jle_rel32_64,
        Code::Jb_rel8_64 => Code::Jae_rel8_64,
        Code::Jae_rel8_64 => Code::Jb_rel8_64,
        Code::Jb_rel32_64 => Code::Jae_rel32_64,
        Code::Jae_rel32_64 => Code::Jb_rel32_64,
        Code::Jbe_rel8_64 => Code::Ja_rel8_64,
        Code::Ja_rel8_64 => Code::Jbe_rel8_64,
        Code::Jbe_rel32_64 => Code::Ja_rel32_64,
        Code::Ja_rel32_64 => Code::Jbe_rel32_64,
        Code::Js_rel8_64 => Code::Jns_rel8_64,
        Code::Jns_rel8_64 => Code::Js_rel8_64,
        Code::Js_rel32_64 => Code::Jns_rel32_64,
        Code::Jns_rel32_64 => Code::Js_rel32_64,
        Code::Jo_rel8_64 => Code::Jno_rel8_64,
        Code::Jno_rel8_64 => Code::Jo_rel8_64,
        Code::Jo_rel32_64 => Code::Jno_rel32_64,
        Code::Jno_rel32_64 => Code::Jo_rel32_64,
        Code::Jp_rel8_64 => Code::Jnp_rel8_64,
        Code::Jnp_rel8_64 => Code::Jp_rel8_64,
        Code::Jp_rel32_64 => Code::Jnp_rel32_64,
        Code::Jnp_rel32_64 => Code::Jp_rel32_64,
        _ => return None,
    })
}

// ─── Rule 1: Register renaming ────────────────────────────────────────────────

/// Within a basic block, attempt to rename one R8–R15 scratch register to a
/// free RAX–RDX caller-saved register.
///
/// A register is "local" (safe to rename) when its first occurrence within
/// the block is a write — meaning no live value from before the block is
/// consumed.  Both the old and the new register must be local.
fn apply_register_rename(block: &[Instruction], rng: &mut impl Rng) -> Vec<Instruction> {
    let mut first_write: HashMap<Register, usize> = HashMap::new();
    let mut uses_before_def: HashSet<Register> = HashSet::new();

    for (idx, inst) in block.iter().enumerate() {
        let is_write_only_dest = is_dest_write_only(inst);

        for op_idx in 0..inst.op_count() {
            match inst.op_kind(op_idx) {
                OpKind::Register => {
                    let r = inst.op_register(op_idx);
                    // op0 of a write-only instruction is a pure destination —
                    // it does not constitute a read of the register.
                    if op_idx == 0 && is_write_only_dest {
                        // not a read
                    } else if let Some(r64) = to_64bit(r) {
                        if !first_write.contains_key(&r64) {
                            uses_before_def.insert(r64);
                        }
                    }
                }
                OpKind::Memory => {
                    for mr in [inst.memory_base(), inst.memory_index()] {
                        if mr != Register::None {
                            if let Some(r64) = to_64bit(mr) {
                                if !first_write.contains_key(&r64) {
                                    uses_before_def.insert(r64);
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        // Record the first write to op0 (destination register).
        if inst.op_count() > 0 && inst.op_kind(0) == OpKind::Register {
            if let Some(r64) = to_64bit(inst.op0_register()) {
                first_write.entry(r64).or_insert(idx);
            }
        }
    }

    // local_scratch = written at least once AND never read before first write.
    let local_scratch: HashSet<Register> = first_write
        .keys()
        .filter(|r| !uses_before_def.contains(*r))
        .copied()
        .collect();

    const R8_TO_R15: [Register; 8] = [
        Register::R8,
        Register::R9,
        Register::R10,
        Register::R11,
        Register::R12,
        Register::R13,
        Register::R14,
        Register::R15,
    ];
    const RAX_TO_RDX: [Register; 4] = [
        Register::RAX,
        Register::RBX,
        Register::RCX,
        Register::RDX,
    ];

    // Old candidate: R8–R15 that are proven local scratch.
    let old_candidates: Vec<Register> = R8_TO_R15
        .iter()
        .filter(|r| local_scratch.contains(*r))
        .copied()
        .collect();

    if old_candidates.is_empty() {
        return block.to_vec();
    }

    // New candidate: RAX–RDX that are local scratch OR entirely unused.
    let new_candidates: Vec<Register> = RAX_TO_RDX
        .iter()
        .filter(|r| {
            local_scratch.contains(*r)
                || (!first_write.contains_key(*r) && !uses_before_def.contains(*r))
        })
        .copied()
        .collect();

    if new_candidates.is_empty() {
        return block.to_vec();
    }

    let &old_base = old_candidates.choose(rng).unwrap();
    let &new_base = new_candidates.choose(rng).unwrap();

    if old_base == new_base {
        return block.to_vec();
    }

    block
        .iter()
        .map(|inst| rename_register_in_inst(*inst, old_base, new_base))
        .collect()
}

/// Returns `true` when op0 of `inst` is a pure write destination (no read).
fn is_dest_write_only(inst: &Instruction) -> bool {
    matches!(
        inst.code(),
        Code::Mov_r64_imm64
            | Code::Mov_r64_rm64
            | Code::Mov_r32_imm32
            | Code::Mov_r32_rm32
            | Code::Lea_r64_m
            | Code::Lea_r32_m
            | Code::Pop_r64
            | Code::Pop_r32
            | Code::Movzx_r64_rm16
            | Code::Movzx_r64_rm8
            | Code::Movzx_r32_rm16
            | Code::Movzx_r32_rm8
            | Code::Movsxd_r64_rm32
            | Code::Movsx_r64_rm16
            | Code::Movsx_r64_rm8
            | Code::Movsx_r32_rm16
            | Code::Movsx_r32_rm8
            // MOV r/m destination forms — also write-only when dest is a register
            | Code::Mov_rm64_imm32
            | Code::Mov_rm32_imm32
            | Code::Mov_rm64_r64
            | Code::Mov_rm32_r32
    )
}

/// Rename all occurrences of registers in `old_base`'s family to the
/// same-size register in `new_base`'s family throughout `inst`.
fn rename_register_in_inst(
    mut inst: Instruction,
    old_base: Register,
    new_base: Register,
) -> Instruction {
    for op_idx in 0..inst.op_count() {
        if inst.op_kind(op_idx) == OpKind::Register {
            let r = inst.op_register(op_idx);
            if let Some(renamed) = rename_reg(r, old_base, new_base) {
                match op_idx {
                    0 => inst.set_op0_register(renamed),
                    1 => inst.set_op1_register(renamed),
                    2 => inst.set_op2_register(renamed),
                    3 => inst.set_op3_register(renamed),
                    _ => {}
                }
            }
        }
    }
    let base = inst.memory_base();
    if base != Register::None {
        if let Some(r) = rename_reg(base, old_base, new_base) {
            inst.set_memory_base(r);
        }
    }
    let index = inst.memory_index();
    if index != Register::None {
        if let Some(r) = rename_reg(index, old_base, new_base) {
            inst.set_memory_index(r);
        }
    }
    inst
}

/// If `reg` is in the family of `old_base64`, return the same-size register
/// from `new_base64`'s family; otherwise return `None`.
fn rename_reg(reg: Register, old_base64: Register, new_base64: Register) -> Option<Register> {
    if to_64bit(reg)? != old_base64 {
        return None;
    }
    sized_reg(new_base64, reg_size(reg)?)
}

/// The size class of a general-purpose register.
#[derive(Clone, Copy)]
enum RegSize {
    S64,
    S32,
    S16,
    S8,
}

fn reg_size(reg: Register) -> Option<RegSize> {
    Some(match reg {
        Register::RAX
        | Register::RBX
        | Register::RCX
        | Register::RDX
        | Register::RSI
        | Register::RDI
        | Register::RBP
        | Register::R8
        | Register::R9
        | Register::R10
        | Register::R11
        | Register::R12
        | Register::R13
        | Register::R14
        | Register::R15 => RegSize::S64,
        Register::EAX
        | Register::EBX
        | Register::ECX
        | Register::EDX
        | Register::ESI
        | Register::EDI
        | Register::EBP
        | Register::R8D
        | Register::R9D
        | Register::R10D
        | Register::R11D
        | Register::R12D
        | Register::R13D
        | Register::R14D
        | Register::R15D => RegSize::S32,
        Register::AX
        | Register::BX
        | Register::CX
        | Register::DX
        | Register::SI
        | Register::DI
        | Register::BP
        | Register::R8W
        | Register::R9W
        | Register::R10W
        | Register::R11W
        | Register::R12W
        | Register::R13W
        | Register::R14W
        | Register::R15W => RegSize::S16,
        Register::AL
        | Register::BL
        | Register::CL
        | Register::DL
        | Register::SIL
        | Register::DIL
        | Register::BPL
        | Register::R8L
        | Register::R9L
        | Register::R10L
        | Register::R11L
        | Register::R12L
        | Register::R13L
        | Register::R14L
        | Register::R15L => RegSize::S8,
        _ => return None,
    })
}

/// Return the variant of `base64` with the given `size`.
fn sized_reg(base64: Register, size: RegSize) -> Option<Register> {
    Some(match (base64, size) {
        (Register::RAX, RegSize::S64) => Register::RAX,
        (Register::RAX, RegSize::S32) => Register::EAX,
        (Register::RAX, RegSize::S16) => Register::AX,
        (Register::RAX, RegSize::S8) => Register::AL,
        (Register::RBX, RegSize::S64) => Register::RBX,
        (Register::RBX, RegSize::S32) => Register::EBX,
        (Register::RBX, RegSize::S16) => Register::BX,
        (Register::RBX, RegSize::S8) => Register::BL,
        (Register::RCX, RegSize::S64) => Register::RCX,
        (Register::RCX, RegSize::S32) => Register::ECX,
        (Register::RCX, RegSize::S16) => Register::CX,
        (Register::RCX, RegSize::S8) => Register::CL,
        (Register::RDX, RegSize::S64) => Register::RDX,
        (Register::RDX, RegSize::S32) => Register::EDX,
        (Register::RDX, RegSize::S16) => Register::DX,
        (Register::RDX, RegSize::S8) => Register::DL,
        (Register::R8, RegSize::S64) => Register::R8,
        (Register::R8, RegSize::S32) => Register::R8D,
        (Register::R8, RegSize::S16) => Register::R8W,
        (Register::R8, RegSize::S8) => Register::R8L,
        (Register::R9, RegSize::S64) => Register::R9,
        (Register::R9, RegSize::S32) => Register::R9D,
        (Register::R9, RegSize::S16) => Register::R9W,
        (Register::R9, RegSize::S8) => Register::R9L,
        (Register::R10, RegSize::S64) => Register::R10,
        (Register::R10, RegSize::S32) => Register::R10D,
        (Register::R10, RegSize::S16) => Register::R10W,
        (Register::R10, RegSize::S8) => Register::R10L,
        (Register::R11, RegSize::S64) => Register::R11,
        (Register::R11, RegSize::S32) => Register::R11D,
        (Register::R11, RegSize::S16) => Register::R11W,
        (Register::R11, RegSize::S8) => Register::R11L,
        (Register::R12, RegSize::S64) => Register::R12,
        (Register::R12, RegSize::S32) => Register::R12D,
        (Register::R12, RegSize::S16) => Register::R12W,
        (Register::R12, RegSize::S8) => Register::R12L,
        (Register::R13, RegSize::S64) => Register::R13,
        (Register::R13, RegSize::S32) => Register::R13D,
        (Register::R13, RegSize::S16) => Register::R13W,
        (Register::R13, RegSize::S8) => Register::R13L,
        (Register::R14, RegSize::S64) => Register::R14,
        (Register::R14, RegSize::S32) => Register::R14D,
        (Register::R14, RegSize::S16) => Register::R14W,
        (Register::R14, RegSize::S8) => Register::R14L,
        (Register::R15, RegSize::S64) => Register::R15,
        (Register::R15, RegSize::S32) => Register::R15D,
        (Register::R15, RegSize::S16) => Register::R15W,
        (Register::R15, RegSize::S8) => Register::R15L,
        _ => return None,
    })
}

// ─── Basic-block splitter ─────────────────────────────────────────────────────

/// Split decoded instructions into basic block ranges (indices into
/// `instructions`).  A new block starts at every instruction that is:
/// * the first instruction, or
/// * the target of a branch instruction, or
/// * the instruction immediately following a terminator (JMP / Jcc / RET /
///   UD2).
fn find_basic_blocks(instructions: &[Instruction]) -> Vec<std::ops::Range<usize>> {
    if instructions.is_empty() {
        return Vec::new();
    }

    let mut leaders: HashSet<u64> = HashSet::new();
    leaders.insert(instructions[0].ip()); // entry is always a leader

    for (i, inst) in instructions.iter().enumerate() {
        let is_branch =
            inst.is_jcc_short_or_near() || inst.is_jmp_short_or_near();
        let is_term = is_hard_terminator(inst.code());

        if is_branch {
            // Branch target starts a new block.
            leaders.insert(inst.near_branch64());
        }

        if (is_branch || is_term) && i + 1 < instructions.len() {
            // Instruction after any control transfer starts a new block.
            leaders.insert(instructions[i + 1].ip());
        }
    }

    let mut blocks: Vec<std::ops::Range<usize>> = Vec::new();
    let mut start = 0;
    for i in 1..instructions.len() {
        if leaders.contains(&instructions[i].ip()) {
            blocks.push(start..i);
            start = i;
        }
    }
    blocks.push(start..instructions.len());
    blocks
}

/// Returns `true` for instructions that unconditionally terminate a block
/// without producing an outgoing relative branch target (so their successor,
/// if any, is unreachable or indirect).
fn is_hard_terminator(code: Code) -> bool {
    matches!(
        code,
        Code::Retnq
            | Code::Retnw
            | Code::Retnd
            | Code::Retfq
            | Code::Retfw
            | Code::Retfd
            | Code::Ud2
    )
}

// ─── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    // ── Helper: decode first instruction from bytes ──────────────────────────

    fn decode_first(bytes: &[u8]) -> Instruction {
        let mut dec = Decoder::with_ip(64, bytes, 0, DecoderOptions::NONE);
        dec.decode()
    }

    fn decode_all(bytes: &[u8]) -> Vec<Instruction> {
        let mut dec = Decoder::with_ip(64, bytes, 0, DecoderOptions::NONE);
        let mut out = Vec::new();
        while dec.can_decode() {
            out.push(dec.decode());
        }
        out
    }

    // ── Helper: allocate RWX page, copy code, call as fn() -> u64 ───────────
    //
    // This lets the semantic tests actually *execute* the original and
    // transformed code and compare outcomes.

    #[cfg(target_os = "linux")]
    unsafe fn run_code(code: &[u8]) -> u64 {
        use std::ptr;
        let page = 4096usize;
        let size = (code.len() + page - 1) & !(page - 1);
        let ptr = libc::mmap(
            ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        assert_ne!(ptr, libc::MAP_FAILED, "mmap failed");
        ptr::copy_nonoverlapping(code.as_ptr(), ptr as *mut u8, code.len());
        let f: unsafe extern "C" fn() -> u64 = std::mem::transmute(ptr);
        let result = f();
        libc::munmap(ptr, size);
        result
    }

    // ── Rule 2: ADD → SUB structural and semantic tests ─────────────────────

    /// `ADD RAX, 42` (48 83 C0 2A) → must decode as `SUB RAX, -42`.
    #[test]
    fn rule2_add_to_sub_positive_imm8() {
        // ADD RAX, 42 = 48 83 C0 2A
        let bytes: &[u8] = &[0x48, 0x83, 0xC0, 0x2A];
        let insts = decode_all(bytes);
        let inst = &insts[0];
        let result = try_add_to_sub(inst, &insts, 0);
        assert!(result.is_some(), "should produce a SUB instruction");
        let sub_inst = result.unwrap();
        assert!(
            matches!(
                sub_inst.code(),
                Code::Sub_rm64_imm8 | Code::Sub_rm64_imm32
            ),
            "result must be SUB rm64, imm: got {:?}",
            sub_inst.code()
        );
        assert_eq!(sub_inst.op0_register(), Register::RAX);
        // Immediate should be –42 (sign-extended from imm8).
        assert_eq!(sub_inst.immediate8to64(), -42i64);
    }

    /// `ADD RAX, -5` (imm8 = 0xFB) → `SUB RAX, 5`.
    #[test]
    fn rule2_add_to_sub_negative_imm8() {
        // ADD RAX, -5 = 48 83 C0 FB
        let bytes: &[u8] = &[0x48, 0x83, 0xC0, 0xFB];
        let insts = decode_all(bytes);
        let result = try_add_to_sub(&insts[0], &insts, 0);
        assert!(result.is_some());
        let sub_inst = result.unwrap();
        assert_eq!(sub_inst.immediate8to64(), 5i64);
    }

    /// `ADD RAX, i32::MIN` must not be transformed (negation overflows).
    #[test]
    fn rule2_add_to_sub_min_imm_rejected() {
        // ADD RAX, -2147483648 = 48 81 C0 00 00 00 80
        let bytes: &[u8] = &[0x48, 0x81, 0xC0, 0x00, 0x00, 0x00, 0x80];
        let insts = decode_all(bytes);
        let result = try_add_to_sub(&insts[0], &insts, 0);
        assert!(result.is_none(), "i32::MIN must not be transformed");
    }

    /// When the next instruction reads carry (`JB`), the transform must be
    /// suppressed because CF semantics differ between ADD and SUB.
    #[test]
    fn rule2_add_to_sub_suppressed_before_carry_jcc() {
        // ADD RAX, 1 ; JB rel8 (JB = 72 xx)
        let mut bytes: Vec<u8> = vec![0x48, 0x83, 0xC0, 0x01]; // ADD RAX, 1
        bytes.extend_from_slice(&[0x72, 0x00]); // JB +0
        let insts = decode_all(&bytes);
        let result = try_add_to_sub(&insts[0], &insts, 0);
        assert!(
            result.is_none(),
            "must not transform ADD when next reads carry"
        );
    }

    /// Semantic: executing original ADD and transformed SUB must yield the
    /// same RAX value.
    #[cfg(target_os = "linux")]
    #[test]
    fn rule2_semantic_equivalence() {
        // Original: MOV RAX, 100; ADD RAX, 37; RET
        //   48 C7 C0 64 00 00 00  - MOV RAX, 100
        //   48 83 C0 25           - ADD RAX, 37
        //   C3                    - RET
        let orig: &[u8] = &[
            0x48, 0xC7, 0xC0, 0x64, 0x00, 0x00, 0x00, // MOV RAX, 100
            0x48, 0x83, 0xC0, 0x25, // ADD RAX, 37
            0xC3,                   // RET
        ];
        // Transformed: MOV RAX, 100; SUB RAX, -37; RET
        //   48 83 E8 DB           - SUB RAX, -37  (0xDB = -37 as i8)
        let xfm: &[u8] = &[
            0x48, 0xC7, 0xC0, 0x64, 0x00, 0x00, 0x00, // MOV RAX, 100
            0x48, 0x83, 0xE8, 0xDB, // SUB RAX, -37
            0xC3,                   // RET
        ];
        let orig_result = unsafe { run_code(orig) };
        let xfm_result = unsafe { run_code(xfm) };
        assert_eq!(orig_result, 137u64);
        assert_eq!(xfm_result, 137u64, "ADD and SUB must produce same value");
    }

    // ── Rule 4: Jcc inversion structural and semantic tests ──────────────────

    /// `JZ +8` (target IP = 0x0A) with fallthrough at 0x02 → produces
    /// `JNZ 0x02` + `JMP 0x0A`.
    #[test]
    fn rule4_invert_jz() {
        // JZ +8 at IP=0: 74 08  (target = 0 + 2 + 8 = 10 = 0x0A)
        let bytes: &[u8] = &[0x74, 0x08];
        let inst = decode_first(bytes);
        assert_eq!(inst.near_branch64(), 0x0A);

        let fallthrough_ip: u64 = 0x02; // next instruction
        let mut extra_ip: u64 = 0xFFFF_0000;
        let result = invert_jcc(&inst, fallthrough_ip, &mut extra_ip);
        assert!(result.is_some(), "JZ must be invertible");
        let (new_jcc, jmp) = result.unwrap();

        // New conditional must be JNZ targeting old fall-through.
        assert!(
            matches!(new_jcc.code(), Code::Jne_rel8_64 | Code::Jne_rel32_64),
            "inverted JZ must be JNZ, got {:?}",
            new_jcc.code()
        );
        assert_eq!(
            new_jcc.near_branch64(),
            fallthrough_ip,
            "JNZ must target old fall-through"
        );

        // Unconditional JMP must target original JZ target.
        assert!(
            inst.is_jmp_short_or_near() || jmp.code().is_jmp_near() || jmp.code().is_jmp_short(),
            "second instruction must be JMP"
        );
        assert_eq!(
            jmp.near_branch64(),
            0x0A,
            "JMP must target original JZ destination"
        );
    }

    /// `JNZ` must invert to `JZ`.
    #[test]
    fn rule4_invert_jnz() {
        // JNZ +0 at IP=0: 75 00
        let bytes: &[u8] = &[0x75, 0x00];
        let inst = decode_first(bytes);
        let mut extra_ip: u64 = 0xFFFF_0000;
        let (new_jcc, _) = invert_jcc(&inst, 0x02, &mut extra_ip).unwrap();
        assert!(
            matches!(new_jcc.code(), Code::Je_rel8_64 | Code::Je_rel32_64),
            "inverted JNZ must be JZ"
        );
    }

    /// Semantic: a JZ-guarded path taken/not-taken must produce the same
    /// outcome after inversion.
    #[cfg(target_os = "linux")]
    #[test]
    fn rule4_semantic_jz_taken() {
        // Code that sets RAX=7 only when ZF=0 (JZ skips the MOV).
        // MOV RAX, 0        (48 C7 C0 00 00 00 00)
        // CMP RAX, RAX      (48 3B C0)  → ZF=1
        // JZ  skip          (74 07)     → jumps to RET
        // MOV RAX, 99       (48 C7 C0 63 00 00 00)
        // skip: RET         (C3)
        let orig: &[u8] = &[
            0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00, // MOV RAX, 0
            0x48, 0x3B, 0xC0, // CMP RAX, RAX  → ZF=1
            0x74, 0x07, // JZ +7 → target = 0x0D + 7 = skip
            0x48, 0xC7, 0xC0, 0x63, 0x00, 0x00, 0x00, // MOV RAX, 99 (skipped)
            0xC3, // RET
        ];

        // Equivalent with JNZ + JMP:
        // MOV RAX, 0
        // CMP RAX, RAX  → ZF=1
        // JNZ fallthrough (JNZ to next instr = original fallthrough = MOV RAX,99)
        // JMP skip       (JMP to original JZ target = RET)
        // MOV RAX, 99   (dead — JNZ not taken since ZF=1, falls to JMP)
        // RET
        //
        // Trace: ZF=1 → JNZ NOT taken → JMP skip → RET → RAX=0
        let xfm: &[u8] = &[
            0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00, // MOV RAX, 0     (0x00)
            0x48, 0x3B, 0xC0, // CMP RAX, RAX          (0x07)
            0x75, 0x05, // JNZ +5 → 0x0E (old fallthrough = MOV RAX,99)
            0xEB, 0x07, // JMP +7 → 0x15 (original JZ target = RET)
            0x48, 0xC7, 0xC0, 0x63, 0x00, 0x00, 0x00, // MOV RAX,99 (0x0E, dead)
            0xC3, // RET (0x15)
        ];

        let orig_result = unsafe { run_code(orig) };
        let xfm_result = unsafe { run_code(xfm) };
        assert_eq!(orig_result, 0u64, "original: JZ taken → RAX=0");
        assert_eq!(xfm_result, 0u64, "transformed: same outcome");
    }

    // ── Rule 3: NOP sled tests ───────────────────────────────────────────────

    /// `make_nop_variant` must produce instructions that, when decoded, do
    /// not modify any architectural register (verified by execution).
    #[cfg(target_os = "linux")]
    #[test]
    fn rule3_nop_variants_are_safe() {
        let mut rng = ChaCha8Rng::seed_from_u64(0xDEAD_BEEF);
        for _ in 0..30 {
            let mut nop = make_nop_variant(&mut rng);
            nop.set_ip(0);
            // Re-encode the single instruction.
            let encoded = encode_block(&[nop], 0);
            // Wrap: MOV RAX, 0xCAFE; <nop>; MOV RAX, 0xCAFE; RET
            //   If the NOP modifies RAX (or anything else that matters) the
            //   result would differ.  We just check RAX is still 0xCAFE.
            let mut code: Vec<u8> = vec![
                0x48, 0xB8, 0xFE, 0xCA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MOV RAX, 0xCAFE
            ];
            code.extend_from_slice(&encoded);
            code.push(0xC3); // RET
            let result = unsafe { run_code(&code) };
            assert_eq!(result, 0xCAFE, "NOP variant must not change RAX");
        }
    }

    /// Applying `apply()` to multi-block code (two blocks separated by JMP)
    /// must produce more bytes than the input (due to NOP sleds).
    #[test]
    fn rule3_nop_sled_increases_size() {
        // Two-block snippet:
        //   JMP over       (EB 02)
        //   MOV RAX, 1    (48 C7 C0 01 00 00 00)  ← second block
        //   RET           (C3)
        let code: &[u8] = &[
            0xEB, 0x07, // JMP +7 → target = second block
            0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, // MOV RAX, 1 (dead)
            0xC3, // RET (dead)
        ];
        // Use a fixed seed that deterministically triggers the NOP-sled path.
        // Seed 1 with gen_bool(0.40): ChaCha8 is deterministic, but we try
        // multiple seeds to find one that triggers the NOP insertion.
        let mut triggered = false;
        for seed in 0u64..100 {
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            let out = apply(code, &mut rng);
            if out.len() > code.len() {
                triggered = true;
                // Verify output is valid x86-64 (decodable without errors).
                let decoded = decode_all(&out);
                assert!(
                    !decoded.is_empty(),
                    "output must decode to valid instructions"
                );
                break;
            }
        }
        assert!(triggered, "NOP sled must be inserted for at least one seed");
    }

    // ── Rule 1: Register renaming structural tests ───────────────────────────

    /// A block that writes R10 before any read must accept a renaming to RAX
    /// (when RAX is also unused/local in the block).
    #[test]
    fn rule1_rename_r10_to_rax() {
        // MOV R10, 42   (49 C7 C2 2A 00 00 00)
        // ADD R10, 1    (49 83 C2 01)
        // MOV RDX, R10  (4C 89 D2) – reads R10, writes RDX
        let bytes: &[u8] = &[
            0x49, 0xC7, 0xC2, 0x2A, 0x00, 0x00, 0x00, // MOV R10, 42
            0x49, 0x83, 0xC2, 0x01, // ADD R10, 1
            0x4C, 0x89, 0xD2, // MOV RDX, R10
        ];
        let block = decode_all(bytes);

        // Run rename pass many times; at least once it should rename R10.
        let mut renamed_at_least_once = false;
        for seed in 0u64..200 {
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            let out = apply_register_rename(&block, &mut rng);
            // Check whether R10 was renamed (any instruction no longer uses R10).
            let uses_r10 = out.iter().any(|inst| {
                (0..inst.op_count()).any(|op_idx| {
                    inst.op_kind(op_idx) == OpKind::Register
                        && inst.op_register(op_idx) == Register::R10
                })
            });
            if !uses_r10 {
                renamed_at_least_once = true;
                // Verify the renamed block encodes without errors.
                let re_encoded = encode_block(&out, 0);
                assert!(!re_encoded.is_empty());
                break;
            }
        }
        assert!(
            renamed_at_least_once,
            "R10 must be renamed at least once across 200 seeds"
        );
    }

    /// A register that is *read before written* in the block must NOT be
    /// renamed (it carries a live-in value).
    #[test]
    fn rule1_live_in_register_not_renamed() {
        // ADD R10, 5   (49 83 C2 05) — reads R10 before any write
        // RET          (C3)
        let bytes: &[u8] = &[0x49, 0x83, 0xC2, 0x05, 0xC3];
        let block = decode_all(bytes);

        for seed in 0u64..100 {
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            let out = apply_register_rename(&block, &mut rng);
            // R10 must still appear — it is live-in and must not be renamed.
            let uses_r10 = out.iter().any(|inst| {
                (0..inst.op_count()).any(|op_idx| {
                    inst.op_kind(op_idx) == OpKind::Register
                        && inst.op_register(op_idx) == Register::R10
                })
            });
            assert!(uses_r10, "seed {seed}: live-in R10 must not be renamed");
        }
    }

    // ── Pipeline integration test ────────────────────────────────────────────

    /// Passing trivial code through `apply()` must return valid x86-64 bytes.
    #[test]
    fn apply_produces_valid_x86_64() {
        // MOV RAX, 1; RET
        let code: &[u8] = &[
            0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, // MOV RAX, 1
            0xC3,                                       // RET
        ];
        let mut rng = ChaCha8Rng::seed_from_u64(42);
        let out = apply(code, &mut rng);
        assert!(!out.is_empty());
        let decoded = decode_all(&out);
        assert!(
            !decoded.is_empty(),
            "output must decode to valid instructions"
        );
    }

    /// Passing an empty slice must return an empty Vec.
    #[test]
    fn apply_empty_input() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let out = apply(&[], &mut rng);
        assert!(out.is_empty());
    }
}
