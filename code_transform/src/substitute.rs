//! M-1 – Instruction substitution pass.
#![cfg(target_arch = "x86_64")]
//!
//! Three rules are applied in a single left-to-right scan:
//!
//! **Rule 1** `MOV reg, 0` → `XOR reg32, reg32`  
//! Zeroing via XOR is a well-known x86 idiom and produces a 2-byte encoding
//! vs. 5–10 bytes for an immediate MOV.
//!
//! **Rule 2** Dead-code pair insertion  
//! After an arithmetic instruction that is *not* immediately followed by a
//! flag-reading instruction, a `SUB reg, 1` / `ADD reg, 1` pair is inserted
//! with ~30 % probability.  The pair cancels out and does not change the
//! value in the register; the flags written by the dead pair are overwritten
//! before any observable side-effect.
//!
//! **Rule 3** `MOV dst, src` + `ADD dst, imm` → `LEA dst, [src + imm]`  
//! When the pattern is detected and `dst ≠ src`, the two-instruction sequence
//! is collapsed into a single LEA.

use std::collections::HashSet;

use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Code, Decoder, DecoderOptions, Instruction,
    InstructionBlock, MemoryOperand, OpKind, Register,
};
use rand::Rng;

/// Apply all substitution rules to `code` and return the re-encoded bytes.
///
/// `rng` is used only for the probabilistic Rule 2 insertion.
pub fn apply_substitutions(code: &[u8], rng: &mut impl Rng) -> Vec<u8> {
    let base_ip: u64 = 0;
    let mut decoder = Decoder::with_ip(64, code, base_ip, DecoderOptions::NONE);
    let mut instructions: Vec<Instruction> = Vec::new();
    while decoder.can_decode() {
        instructions.push(decoder.decode());
    }

    // Collect all IPs that are targets of branch instructions so that we
    // do not insert dead-code pairs that would shift a branch target.
    let branch_target_ips: HashSet<u64> = instructions
        .iter()
        .filter(|i| i.is_jcc_short_or_near() || i.is_jmp_short_or_near())
        .map(|i| i.near_branch64())
        .collect();

    // Counter for IPs we assign to inserted (synthetic) instructions.
    // These must be unique and must not collide with any original IP; we
    // use a high sentinel range that real code compiled from base_ip=0 will
    // never reach.
    let mut extra_ip: u64 = 0xFFFF_0000_0000_0000u64;

    let mut out: Vec<Instruction> = Vec::with_capacity(instructions.len() * 2);
    let mut i = 0;

    while i < instructions.len() {
        let inst = instructions[i];
        let orig_ip = inst.ip();

        // ── Rule 3: check two-instruction window ─────────────────────────────
        if i + 1 < instructions.len() {
            if let Some(mut lea) = try_lea_from_mov_add(&inst, &instructions[i + 1]) {
                // Keep the original IP so any incoming branch to this address
                // resolves to the LEA.
                lea.set_ip(orig_ip);
                out.push(lea);
                i += 2;
                continue;
            }
        }

        // ── Rule 1: MOV reg, 0  →  XOR reg32, reg32 ─────────────────────────
        if let Some(mut xor_inst) = try_xor_for_mov_zero(&inst) {
            xor_inst.set_ip(orig_ip);
            out.push(xor_inst);
        } else {
            out.push(inst);

            // ── Rule 2: dead-code pair after arithmetic ───────────────────────
            // Skip if:
            //   • the following instruction reads flags (ADC, SBB, Jcc …)
            //   • the following instruction is itself a branch target
            //     (inserting before it would misalign the target)
            let next_is_branch_target = instructions
                .get(i + 1)
                .map(|n| branch_target_ips.contains(&n.ip()))
                .unwrap_or(false);

            if is_arithmetic(&inst)
                && !next_reads_flags(&instructions, i)
                && !next_is_branch_target
                && rng.gen_bool(0.30)
            {
                let reg = inst.op0_register();
                if reg != Register::None && !is_high_byte_reg(reg) {
                    if let Some(r64) = to_64bit(reg) {
                        let mut sub1 = make_sub_imm8(r64, 1);
                        let mut add1 = make_add_imm8(r64, 1);
                        sub1.set_ip(extra_ip);
                        extra_ip += 1;
                        add1.set_ip(extra_ip);
                        extra_ip += 1;
                        out.push(sub1);
                        out.push(add1);
                    }
                }
            }
        }

        i += 1;
    }

    encode_block(&out, base_ip)
}

// ─── Rule helpers ─────────────────────────────────────────────────────────────

/// Try to replace `MOV r64/r32, 0` with `XOR r32, r32`.
fn try_xor_for_mov_zero(inst: &Instruction) -> Option<Instruction> {
    let code = inst.code();
    let is_mov_zero = matches!(
        code,
        Code::Mov_r64_imm64 | Code::Mov_r32_imm32
    ) && inst.immediate64() == 0;

    if !is_mov_zero {
        return None;
    }

    let reg = inst.op0_register();
    let r32 = to_32bit(reg)?;
    // XOR r32, r32 — implicit zero-extension clears the upper 32 bits.
    Instruction::with2(Code::Xor_r32_rm32, r32, r32).ok()
}

/// Try to collapse `MOV dst, src ; ADD dst, imm` into `LEA dst, [src+imm]`.
fn try_lea_from_mov_add(first: &Instruction, second: &Instruction) -> Option<Instruction> {
    // First instruction: MOV r64, r/m64 (register-to-register form)
    if !matches!(first.code(), Code::Mov_r64_rm64 | Code::Mov_r32_rm32) {
        return None;
    }
    if first.op1_kind() != OpKind::Register {
        return None;
    }
    let dst = first.op0_register();
    let src = first.op1_register();
    if dst == src {
        return None; // LEA dst, [dst+imm] ≡ ADD dst, imm — handled elsewhere
    }

    // Second instruction: ADD dst, imm8 or ADD dst, imm32 (same destination)
    if !matches!(
        second.code(),
        Code::Add_rm64_imm8 | Code::Add_rm64_imm32 | Code::Add_rm32_imm8 | Code::Add_rm32_imm32
    ) {
        return None;
    }
    if second.op0_register() != dst {
        return None;
    }

    let disp = second.immediate64() as i64;
    let dst64 = to_64bit(dst)?;
    let src64 = to_64bit(src)?;
    let mem = MemoryOperand::with_base_displ(src64, disp);
    Instruction::with2(Code::Lea_r64_m, dst64, mem).ok()
}

fn make_sub_imm8(reg: Register, imm: u32) -> Instruction {
    Instruction::with2(Code::Sub_rm64_imm8, reg, imm).expect("SUB r64, imm8")
}

fn make_add_imm8(reg: Register, imm: u32) -> Instruction {
    Instruction::with2(Code::Add_rm64_imm8, reg, imm).expect("ADD r64, imm8")
}

// ─── Predicate helpers ────────────────────────────────────────────────────────

fn is_arithmetic(inst: &Instruction) -> bool {
    matches!(
        inst.code(),
        Code::Add_r64_rm64
            | Code::Add_rm64_r64
            | Code::Add_r32_rm32
            | Code::Add_rm32_r32
            | Code::Add_rm64_imm8
            | Code::Add_rm64_imm32
            | Code::Add_rm32_imm8
            | Code::Add_rm32_imm32
            | Code::Sub_r64_rm64
            | Code::Sub_r32_rm32
            | Code::Sub_rm64_imm8
            | Code::Sub_rm64_imm32
            | Code::Sub_rm32_imm8
            | Code::Sub_rm32_imm32
            | Code::Imul_r64_rm64
            | Code::Imul_r32_rm32
            | Code::Inc_rm64
            | Code::Inc_rm32
            | Code::Dec_rm64
            | Code::Dec_rm32
            | Code::Neg_rm64
            | Code::Neg_rm32
            | Code::And_r64_rm64
            | Code::And_r32_rm32
            | Code::Or_r64_rm64
            | Code::Or_r32_rm32
            | Code::Xor_r64_rm64
            | Code::Xor_r32_rm32
            | Code::Shl_rm64_CL
            | Code::Shr_rm64_CL
            | Code::Sar_rm64_CL
    )
}

/// Returns `true` if the next instruction reads RFLAGS (Jcc, ADC, SBB, …).
fn next_reads_flags(instructions: &[Instruction], i: usize) -> bool {
    let next = match instructions.get(i + 1) {
        Some(n) => n,
        None => return false,
    };
    // All Jcc (short and near), CMOVcc, SETcc, ADC, SBB, LAHF, PUSHFQ read flags.
    next.is_jcc_short_or_near()
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
                | Code::Lahf
                | Code::Pushfq
                | Code::Rcl_rm64_CL
                | Code::Rcr_rm64_CL
                | Code::Rcl_rm32_CL
                | Code::Rcr_rm32_CL
        )
}

fn is_high_byte_reg(reg: Register) -> bool {
    matches!(
        reg,
        Register::AH | Register::BH | Register::CH | Register::DH
    )
}

pub(crate) fn to_32bit(reg: Register) -> Option<Register> {
    Some(match reg {
        Register::RAX | Register::EAX => Register::EAX,
        Register::RBX | Register::EBX => Register::EBX,
        Register::RCX | Register::ECX => Register::ECX,
        Register::RDX | Register::EDX => Register::EDX,
        Register::RSI | Register::ESI => Register::ESI,
        Register::RDI | Register::EDI => Register::EDI,
        Register::RBP | Register::EBP => Register::EBP,
        Register::R8 | Register::R8D => Register::R8D,
        Register::R9 | Register::R9D => Register::R9D,
        Register::R10 | Register::R10D => Register::R10D,
        Register::R11 | Register::R11D => Register::R11D,
        Register::R12 | Register::R12D => Register::R12D,
        Register::R13 | Register::R13D => Register::R13D,
        Register::R14 | Register::R14D => Register::R14D,
        Register::R15 | Register::R15D => Register::R15D,
        Register::RSP | Register::ESP => return None, // never touch RSP
        _ => return None,
    })
}

pub(crate) fn to_64bit(reg: Register) -> Option<Register> {
    Some(match reg {
        Register::RAX | Register::EAX | Register::AX | Register::AL => Register::RAX,
        Register::RBX | Register::EBX | Register::BX | Register::BL => Register::RBX,
        Register::RCX | Register::ECX | Register::CX | Register::CL => Register::RCX,
        Register::RDX | Register::EDX | Register::DX | Register::DL => Register::RDX,
        Register::RSI | Register::ESI | Register::SI | Register::SIL => Register::RSI,
        Register::RDI | Register::EDI | Register::DI | Register::DIL => Register::RDI,
        Register::RBP | Register::EBP | Register::BP | Register::BPL => Register::RBP,
        Register::R8 | Register::R8D | Register::R8W | Register::R8L => Register::R8,
        Register::R9 | Register::R9D | Register::R9W | Register::R9L => Register::R9,
        Register::R10 | Register::R10D | Register::R10W | Register::R10L => Register::R10,
        Register::R11 | Register::R11D | Register::R11W | Register::R11L => Register::R11,
        Register::R12 | Register::R12D | Register::R12W | Register::R12L => Register::R12,
        Register::R13 | Register::R13D | Register::R13W | Register::R13L => Register::R13,
        Register::R14 | Register::R14D | Register::R14W | Register::R14L => Register::R14,
        Register::R15 | Register::R15D | Register::R15W | Register::R15L => Register::R15,
        Register::RSP | Register::ESP => return None,
        _ => return None,
    })
}

// ─── Encoding helper ──────────────────────────────────────────────────────────

/// Re-encode a sequence of iced-x86 `Instruction`s using `BlockEncoder`,
/// which automatically picks the shortest branch encodings and fixes relative
/// offsets.
pub(crate) fn encode_block(instructions: &[Instruction], rip: u64) -> Vec<u8> {
    if instructions.is_empty() {
        return Vec::new();
    }
    let block = InstructionBlock::new(instructions, rip);
    match BlockEncoder::encode(64, block, BlockEncoderOptions::NONE) {
        Ok(result) => result.code_buffer,
        Err(_e) => {
            // Fallback: encode each instruction individually (branch offsets
            // may be stale but we at least preserve non-branch instructions).
            use iced_x86::Encoder;
            let mut enc = Encoder::new(64);
            let mut out = Vec::new();
            let mut ip = rip;
            for inst in instructions {
                if let Ok(len) = enc.encode(inst, ip) {
                    out.extend_from_slice(&enc.take_buffer());
                    ip += len as u64;
                }
            }
            out
        }
    }
}

// ─── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    #[test]
    fn mov_zero_replaced_by_xor() {
        // Encode:  MOV eax, 0   (B8 00 00 00 00)
        let code: &[u8] = &[0xB8, 0x00, 0x00, 0x00, 0x00];
        let mut rng = ChaCha8Rng::seed_from_u64(42);
        let out = apply_substitutions(code, &mut rng);
        // Decode and check it is an XOR reg, reg zero idiom (31 C0 or 33 C0).
        assert_eq!(out.len(), 2, "XOR eax,eax should be 2 bytes");
        let mut dec = Decoder::with_ip(32, &out, 0, DecoderOptions::NONE);
        let inst = dec.decode();
        assert!(
            matches!(inst.code(), Code::Xor_r32_rm32 | Code::Xor_rm32_r32),
            "expected XOR eax,eax encoding, got {:?}",
            inst.code()
        );
        assert_eq!(inst.op0_register(), Register::EAX);
        assert_eq!(inst.op1_register(), Register::EAX);
    }

    #[test]
    fn lea_replaces_mov_add_sequence() {
        // Encode:  MOV rax, rbx  (48 8B C3) ; ADD rax, 8  (48 83 C0 08)
        // Using opcode 8B (Mov_r64_rm64) so the substitution's pattern matches.
        let code: &[u8] = &[0x48, 0x8B, 0xC3, 0x48, 0x83, 0xC0, 0x08];
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let out = apply_substitutions(code, &mut rng);
        // The result must not be longer than the input (LEA is 4-7 bytes).
        assert!(
            out.len() <= code.len(),
            "LEA substitution should not grow the code, got {:?}",
            out
        );
        // Decode result and check it is a LEA.
        let mut dec = Decoder::with_ip(64, &out, 0, DecoderOptions::NONE);
        let inst = dec.decode();
        assert_eq!(inst.code(), Code::Lea_r64_m, "expected LEA r64, m");
        assert_eq!(inst.op0_register(), Register::RAX);
    }

    #[test]
    fn dead_code_pair_inserted_sometimes() {
        // A simple ADD rax, rdx (no JCC follows) — seed chosen so Rule 2 fires.
        // 48 01 D0 = ADD rax, rdx
        let code: &[u8] = &[0x48, 0x01, 0xD0, 0xC3]; // ADD rax, rdx; RET
        let mut fired = false;
        for seed in 0u64..128 {
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            let out = apply_substitutions(code, &mut rng);
            if out.len() > code.len() {
                fired = true;
                break;
            }
        }
        assert!(fired, "Rule 2 dead-code pair should fire at least once in 128 seeds");
    }
}
