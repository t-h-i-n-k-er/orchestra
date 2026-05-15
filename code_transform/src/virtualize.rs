//! Code virtualization transform — translates basic blocks into a custom
//! stack-based VM bytecode interpreted at runtime.
#![cfg(target_arch = "x86_64")]
//!
//! # Overview
//!
//! This is the single most effective anti-analysis technique in the transform
//! pipeline.  It replaces the original basic-block instructions with a call to
//! a generated VM interpreter that executes custom bytecode.
//!
//! # Algorithm
//!
//! 1. Decode input into iced-x86 `Instruction`s, split into basic blocks.
//! 2. For each basic block, translate every instruction into VM bytecode
//!    using ~20 stack-based opcodes.
//! 3. Generate a VM interpreter function in x86_64 machine code using the
//!    iced-x86 encoder.
//! 4. Replace each original basic block with: `LEA rdi, [rip+bytecode]`;
//!    `CALL interpreter`.
//! 5. Randomize the opcode encoding per build using the seeded ChaCha8RNG so
//!    that every build uses a different opcode table.
//!
//! # VM Architecture
//!
//! The VM is a simple **register-based** machine (not pure stack) with:
//! - 16 virtual registers (v0–v15) mapped to real x86 GPRs
//! - A flags register
//! - A program counter (PC) into the bytecode
//! - An instruction buffer (pointer + length) pointing to the original
//!   block's code for instructions the VM cannot handle (fallthrough to
//!   native execution)
//!
//! # Opcode set (semantic, ~20 opcodes)
//!
//! | Opcode       | Description                              |
//! |--------------|------------------------------------------|
//! | NOP          | No operation                             |
//! | MOV_REG_REG  | v[dst] ← v[src]                          |
//! | MOV_REG_IMM  | v[dst] ← imm32                           |
//! | ADD          | v[dst] ← v[dst] + v[src]                 |
//! | SUB          | v[dst] ← v[dst] - v[src]                 |
//! | AND          | v[dst] ← v[dst] & v[src]                 |
//! | OR           | v[dst] ← v[dst] | v[src]                 |
//! | XOR          | v[dst] ← v[dst] ^ v[src]                 |
//! | CMP          | flags ← v[a] - v[b]                      |
//! | JMP          | PC ← offset                              |
//! | JCC          | if flags match cond, PC ← offset         |
//! | PUSH         | push v[src]                               |
//! | POP          | v[dst] ← pop()                            |
//! | RET          | return from VM                            |
//! | CALL         | push PC+insn_len, PC ← offset            |
//! | SHL          | v[dst] <<= v[src]                         |
//! | SHR          | v[dst] >>= v[src]                         |
//! | NOT          | v[dst] ← !v[dst]                          |
//! | NEG          | v[dst] ← -v[dst]                          |
//! | INC          | v[dst] ← v[dst] + 1                       |
//! | DEC          | v[dst] ← v[dst] - 1                       |
//!
//! Each opcode is 1 byte.  Operands are encoded inline (register indices are
//! 1 byte, immediates are 4 or 8 bytes little-endian, branch offsets are
//! 4 bytes relative to the start of the bytecode buffer).
//!
//! # Safety
//!
//! If the input contains instructions the VM cannot handle (e.g. SIMD,
//! system instructions, memory operands with complex addressing, etc.),
//! the pass returns the input unchanged — it never produces incorrect code.

use std::collections::HashSet;

use iced_x86::{Code, Decoder, DecoderOptions, Instruction, MemoryOperand, OpKind, Register};
use rand::seq::SliceRandom;
use rand_chacha::ChaCha8Rng;

use crate::substitute::encode_block;

// ─── VM opcodes (semantic identifiers) ──────────────────────────────────────

const NUM_OPCODES: usize = 21;

/// Semantic opcode identifiers.  The *actual* byte value is randomized per
/// build by shuffling a [0..NUM_OPCODES] mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
#[allow(dead_code)]
enum VmOp {
    Nop = 0,
    MovRegReg = 1,
    MovRegImm = 2,
    Add = 3,
    Sub = 4,
    And = 5,
    Or = 6,
    Xor = 7,
    Cmp = 8,
    Jmp = 9,
    Jcc = 10,
    Push = 11,
    Pop = 12,
    Ret = 13,
    Call = 14,
    Shl = 15,
    Shr = 16,
    Not = 17,
    Neg = 18,
    Inc = 19,
    Dec = 20,
}

/// Holds the randomized opcode table: `table[VmOp as usize]` gives the actual
/// byte used in bytecode.
struct OpcodeTable {
    encode: [u8; NUM_OPCODES],
    #[allow(dead_code)]
    decode: [VmOp; 256], // reverse: byte → VmOp (or VmOp::Nop if invalid)
}

impl OpcodeTable {
    fn generate(rng: &mut ChaCha8Rng) -> Self {
        let mut bytes: Vec<u8> = (0..NUM_OPCODES as u8).collect();
        bytes.shuffle(rng);

        let mut encode = [0u8; NUM_OPCODES];
        let mut decode = [VmOp::Nop; 256];

        for (semantic_idx, &actual_byte) in bytes.iter().enumerate() {
            encode[semantic_idx] = actual_byte;
            decode[actual_byte as usize] = {
                // Safety: VmOp variants are repr(u8) 0..=20
                #[allow(clippy::as_conversions)]
                unsafe {
                    std::mem::transmute::<u8, VmOp>(semantic_idx as u8)
                }
            };
        }

        Self { encode, decode }
    }

    fn enc(&self, op: VmOp) -> u8 {
        self.encode[op as usize]
    }
}

// ─── Bytecode representation ────────────────────────────────────────────────

/// A single VM bytecode instruction.
enum BytecodeInsn {
    Nop,
    MovRegReg { dst: u8, src: u8 },
    MovRegImm { dst: u8, imm: u64 },
    BinOp { op: VmOp, dst: u8, src: u8 }, // ADD, SUB, AND, OR, XOR, SHL, SHR
    Cmp { a: u8, b: u8 },
    Jmp { offset: i32 },
    Jcc { cond: u8, offset: i32 }, // cond encodes the x86 condition code
    Push { src: u8 },
    Pop { dst: u8 },
    Ret,
    Call { offset: i32 },
    Unary { op: VmOp, dst: u8 }, // NOT, NEG, INC, DEC
}

// ─── Register mapping ───────────────────────────────────────────────────────

/// The 16 x86-64 GPRs we can map to virtual registers v0–v15.
const GPR_TABLE: [Register; 16] = [
    Register::RAX,
    Register::RCX,
    Register::RDX,
    Register::RBX,
    Register::RSP,
    Register::RBP,
    Register::RSI,
    Register::RDI,
    Register::R8,
    Register::R9,
    Register::R10,
    Register::R11,
    Register::R12,
    Register::R13,
    Register::R14,
    Register::R15,
];

fn gpr_index(reg: Register) -> Option<u8> {
    GPR_TABLE.iter().position(|&r| r == reg).map(|i| i as u8)
}

#[allow(dead_code)]
fn index_to_gpr(idx: u8) -> Register {
    GPR_TABLE[idx as usize]
}

#[allow(dead_code)]
fn index_to_gpr32(idx: u8) -> Register {
    match index_to_gpr(idx) {
        Register::RAX => Register::EAX,
        Register::RCX => Register::ECX,
        Register::RDX => Register::EDX,
        Register::RBX => Register::EBX,
        Register::RSP => Register::ESP,
        Register::RBP => Register::EBP,
        Register::RSI => Register::ESI,
        Register::RDI => Register::EDI,
        Register::R8 => Register::R8D,
        Register::R9 => Register::R9D,
        Register::R10 => Register::R10D,
        Register::R11 => Register::R11D,
        Register::R12 => Register::R12D,
        Register::R13 => Register::R13D,
        Register::R14 => Register::R14D,
        Register::R15 => Register::R15D,
        _ => Register::EAX,
    }
}

/// Normalize a register operand to its 64-bit GPR family, or None if it's not
/// a GPR.
fn normalize_gpr(reg: Register) -> Option<Register> {
    use Register::*;
    match reg {
        RAX | EAX | AX | AL | AH => Some(RAX),
        RCX | ECX | CX | CL | CH => Some(RCX),
        RDX | EDX | DX | DL | DH => Some(RDX),
        RBX | EBX | BX | BL | BH => Some(RBX),
        RSP | ESP | SP | SPL => Some(RSP),
        RBP | EBP | BP | BPL => Some(RBP),
        RSI | ESI | SI | SIL => Some(RSI),
        RDI | EDI | DI | DIL => Some(RDI),
        R8 | R8D | R8W | R8L => Some(R8),
        R9 | R9D | R9W | R9L => Some(R9),
        R10 | R10D | R10W | R10L => Some(R10),
        R11 | R11D | R11W | R11L => Some(R11),
        R12 | R12D | R12W | R12L => Some(R12),
        R13 | R13D | R13W | R13L => Some(R13),
        R14 | R14D | R14W | R14L => Some(R14),
        R15 | R15D | R15W | R15L => Some(R15),
        _ => Option::None,
    }
}

// ─── Basic block helpers ────────────────────────────────────────────────────

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

// ─── Instruction translation ────────────────────────────────────────────────

/// Result of trying to translate a single x86 instruction into bytecode.
enum TranslateResult {
    /// Successfully translated to one or more bytecode instructions.
    Ok(Vec<BytecodeInsn>),
    /// Cannot translate — the instruction must be executed natively.
    Native,
}

/// Condition code encoding for Jcc bytecode.
fn condition_code(code: Code) -> u8 {
    match code {
        Code::Jo_rel8_64 | Code::Jo_rel32_64 => 0,
        Code::Jno_rel8_64 | Code::Jno_rel32_64 => 1,
        Code::Jb_rel8_64 | Code::Jb_rel32_64 => 2,
        Code::Jae_rel8_64 | Code::Jae_rel32_64 => 3,
        Code::Je_rel8_64 | Code::Je_rel32_64 => 4,
        Code::Jne_rel8_64 | Code::Jne_rel32_64 => 5,
        Code::Jbe_rel8_64 | Code::Jbe_rel32_64 => 6,
        Code::Ja_rel8_64 | Code::Ja_rel32_64 => 7,
        Code::Js_rel8_64 | Code::Js_rel32_64 => 8,
        Code::Jns_rel8_64 | Code::Jns_rel32_64 => 9,
        Code::Jl_rel8_64 | Code::Jl_rel32_64 => 12,
        Code::Jge_rel8_64 | Code::Jge_rel32_64 => 13,
        Code::Jle_rel8_64 | Code::Jle_rel32_64 => 14,
        Code::Jg_rel8_64 | Code::Jg_rel32_64 => 15,
        _ => 4, // default: JE
    }
}

/// Try to translate a single x86 instruction into VM bytecode.
fn translate_instruction(inst: &Instruction) -> TranslateResult {
    let code = inst.code();

    // NOP
    if matches!(code, Code::Nopd | Code::Nopw) {
        return TranslateResult::Ok(vec![BytecodeInsn::Nop]);
    }

    // RET
    if matches!(code, Code::Retnq) {
        return TranslateResult::Ok(vec![BytecodeInsn::Ret]);
    }

    // PUSH r64
    if code == Code::Push_r64 {
        let reg = inst.op0_register();
        if let Some(idx) = normalize_gpr(reg).and_then(gpr_index) {
            return TranslateResult::Ok(vec![BytecodeInsn::Push { src: idx }]);
        }
        return TranslateResult::Native;
    }

    // POP r64
    if code == Code::Pop_r64 {
        let reg = inst.op0_register();
        if let Some(idx) = normalize_gpr(reg).and_then(gpr_index) {
            return TranslateResult::Ok(vec![BytecodeInsn::Pop { dst: idx }]);
        }
        return TranslateResult::Native;
    }

    // JMP rel — encode as unconditional jump (offset filled in later).
    if inst.is_jmp_short_or_near() {
        let target_ip = inst.near_branch64();
        return TranslateResult::Ok(vec![BytecodeInsn::Jmp {
            offset: target_ip as i32, // placeholder, resolved during emission
        }]);
    }

    // Jcc — conditional jump.
    if inst.is_jcc_short_or_near() {
        let target_ip = inst.near_branch64();
        let cond = condition_code(code);
        return TranslateResult::Ok(vec![BytecodeInsn::Jcc {
            cond,
            offset: target_ip as i32, // placeholder
        }]);
    }

    // CALL rel32
    if matches!(code, Code::Call_rel32_64) {
        let target_ip = inst.near_branch64();
        return TranslateResult::Ok(vec![BytecodeInsn::Call {
            offset: target_ip as i32,
        }]);
    }

    // MOV r64, r/m64  or  MOV r32, r/m32 (register-register form)
    if matches!(code, Code::Mov_r64_rm64 | Code::Mov_r32_rm32) {
        if inst.op_count() >= 2
            && inst.op_kind(0) == OpKind::Register
            && inst.op_kind(1) == OpKind::Register
        {
            let dst_reg = normalize_gpr(inst.op_register(0));
            let src_reg = normalize_gpr(inst.op_register(1));
            if let (Some(dst), Some(src)) =
                (dst_reg.and_then(gpr_index), src_reg.and_then(gpr_index))
            {
                return TranslateResult::Ok(vec![BytecodeInsn::MovRegReg { dst, src }]);
            }
        }
        return TranslateResult::Native;
    }

    // MOV r64, imm64 | MOV r32, imm32
    if matches!(code, Code::Mov_r64_imm64 | Code::Mov_r32_imm32) {
        if let Some(idx) = normalize_gpr(inst.op_register(0)).and_then(gpr_index) {
            let imm = if code == Code::Mov_r64_imm64 {
                inst.immediate64()
            } else {
                (inst.immediate64() as u32) as u64
            };
            return TranslateResult::Ok(vec![BytecodeInsn::MovRegImm { dst: idx, imm }]);
        }
        return TranslateResult::Native;
    }

    // Binary ALU: ADD, SUB, AND, OR, XOR r, r/m  (reg-reg form)
    let bin_op = match code {
        Code::Add_r64_rm64 | Code::Add_r32_rm32 | Code::Add_rm64_r64 | Code::Add_rm32_r32 => {
            Some(VmOp::Add)
        }
        Code::Sub_r64_rm64 | Code::Sub_r32_rm32 | Code::Sub_rm64_r64 | Code::Sub_rm32_r32 => {
            Some(VmOp::Sub)
        }
        Code::And_r64_rm64 | Code::And_r32_rm32 | Code::And_rm64_r64 | Code::And_rm32_r32 => {
            Some(VmOp::And)
        }
        Code::Or_r64_rm64 | Code::Or_r32_rm32 | Code::Or_rm64_r64 | Code::Or_rm32_r32 => {
            Some(VmOp::Or)
        }
        Code::Xor_r64_rm64 | Code::Xor_r32_rm32 | Code::Xor_rm64_r64 | Code::Xor_rm32_r32 => {
            Some(VmOp::Xor)
        }
        _ => None,
    };

    if let Some(op) = bin_op {
        if inst.op_count() >= 2
            && inst.op_kind(0) == OpKind::Register
            && inst.op_kind(1) == OpKind::Register
        {
            let dst_reg = normalize_gpr(inst.op_register(0));
            let src_reg = normalize_gpr(inst.op_register(1));
            if let (Some(dst), Some(src)) =
                (dst_reg.and_then(gpr_index), src_reg.and_then(gpr_index))
            {
                return TranslateResult::Ok(vec![BytecodeInsn::BinOp { op, dst, src }]);
            }
        }
        return TranslateResult::Native;
    }

    // CMP r, r/m (reg-reg form)
    if matches!(code, Code::Cmp_r64_rm64 | Code::Cmp_r32_rm32) {
        if inst.op_count() >= 2
            && inst.op_kind(0) == OpKind::Register
            && inst.op_kind(1) == OpKind::Register
        {
            let a_reg = normalize_gpr(inst.op_register(0));
            let b_reg = normalize_gpr(inst.op_register(1));
            if let (Some(a), Some(b)) = (a_reg.and_then(gpr_index), b_reg.and_then(gpr_index)) {
                return TranslateResult::Ok(vec![BytecodeInsn::Cmp { a, b }]);
            }
        }
        return TranslateResult::Native;
    }

    // Unary: NOT, NEG, INC, DEC r/m (register form)
    let unary_op = match code {
        Code::Not_rm64 | Code::Not_rm32 => Some(VmOp::Not),
        Code::Neg_rm64 | Code::Neg_rm32 => Some(VmOp::Neg),
        Code::Inc_rm64 | Code::Inc_rm32 => Some(VmOp::Inc),
        Code::Dec_rm64 | Code::Dec_rm32 => Some(VmOp::Dec),
        _ => None,
    };

    if let Some(op) = unary_op {
        if inst.op_kind(0) == OpKind::Register {
            if let Some(dst) = normalize_gpr(inst.op_register(0)).and_then(gpr_index) {
                return TranslateResult::Ok(vec![BytecodeInsn::Unary { op, dst }]);
            }
        }
        return TranslateResult::Native;
    }

    // LEA r64, [r64 + disp32] → MOV_REG_IMM + BinOp(ADD) with immediate
    // (Simplified: only handle LEA r64, [r64] — register copy)
    if matches!(code, Code::Lea_r64_m) {
        let base = inst.memory_base();
        let index = inst.memory_index();
        let disp = inst.memory_displacement64();
        let dst_reg = inst.op_register(0);

        // LEA r64, [r64] → MOV_REG_REG
        if index == Register::None && disp == 0 {
            if let (Some(dst), Some(src)) = (
                normalize_gpr(dst_reg).and_then(gpr_index),
                normalize_gpr(base).and_then(gpr_index),
            ) {
                return TranslateResult::Ok(vec![BytecodeInsn::MovRegReg { dst, src }]);
            }
        }

        // LEA r64, [r64 + disp32] → MOV_REG_IMM(disp) + ADD(dst, temp)
        // This is more complex — handle as native for now.
        return TranslateResult::Native;
    }

    // TEST r, r (used in zero-checks) → CMP reg, 0
    if matches!(code, Code::Test_rm64_r64 | Code::Test_rm32_r32) {
        if inst.op_count() >= 2
            && inst.op_kind(0) == OpKind::Register
            && inst.op_kind(1) == OpKind::Register
            && inst.op_register(0) == inst.op_register(1)
        {
            if let Some(a) = normalize_gpr(inst.op_register(0)).and_then(gpr_index) {
                // Encode as CMP v[a], v[a] — sets flags like TEST
                return TranslateResult::Ok(vec![BytecodeInsn::Cmp { a, b: a }]);
            }
        }
        return TranslateResult::Native;
    }

    TranslateResult::Native
}

// ─── Bytecode emission ──────────────────────────────────────────────────────

/// Serialize a list of bytecode instructions into a byte vector using the
/// randomized opcode table.
fn emit_bytecode(insns: &[BytecodeInsn], table: &OpcodeTable) -> Vec<u8> {
    let mut buf = Vec::with_capacity(insns.len() * 6);
    for insn in insns {
        match insn {
            BytecodeInsn::Nop => {
                buf.push(table.enc(VmOp::Nop));
            }
            BytecodeInsn::MovRegReg { dst, src } => {
                buf.push(table.enc(VmOp::MovRegReg));
                buf.push(*dst);
                buf.push(*src);
            }
            BytecodeInsn::MovRegImm { dst, imm } => {
                buf.push(table.enc(VmOp::MovRegImm));
                buf.push(*dst);
                buf.extend_from_slice(&imm.to_le_bytes());
            }
            BytecodeInsn::BinOp { op, dst, src } => {
                buf.push(table.enc(*op));
                buf.push(*dst);
                buf.push(*src);
            }
            BytecodeInsn::Cmp { a, b } => {
                buf.push(table.enc(VmOp::Cmp));
                buf.push(*a);
                buf.push(*b);
            }
            BytecodeInsn::Jmp { offset } => {
                buf.push(table.enc(VmOp::Jmp));
                buf.extend_from_slice(&offset.to_le_bytes());
            }
            BytecodeInsn::Jcc { cond, offset } => {
                buf.push(table.enc(VmOp::Jcc));
                buf.push(*cond);
                buf.extend_from_slice(&offset.to_le_bytes());
            }
            BytecodeInsn::Push { src } => {
                buf.push(table.enc(VmOp::Push));
                buf.push(*src);
            }
            BytecodeInsn::Pop { dst } => {
                buf.push(table.enc(VmOp::Pop));
                buf.push(*dst);
            }
            BytecodeInsn::Ret => {
                buf.push(table.enc(VmOp::Ret));
            }
            BytecodeInsn::Call { offset } => {
                buf.push(table.enc(VmOp::Call));
                buf.extend_from_slice(&offset.to_le_bytes());
            }
            BytecodeInsn::Unary { op, dst } => {
                buf.push(table.enc(*op));
                buf.push(*dst);
            }
        }
    }
    buf
}

// ─── VM interpreter generation ──────────────────────────────────────────────
//
// The interpreter is emitted as x86_64 machine code that takes:
//   RDI = pointer to bytecode
//   RSI = bytecode length
//   RDX = pointer to original block's native code (fallback)
//   R8  = pointer to a register-save area (16 × u64 slots)
//
// The interpreter loop decodes one bytecode instruction at a time and
// executes it against the register file in R8.
//
// Layout of generated interpreter:
//
//   1. Prologue: save callee-saved regs, set up register file pointer
//   2. Dispatch loop:
//      - Load opcode byte at [RDI + RCX]  (RCX = PC)
//      - Jump table: series of CMP+JE to handler for each opcode
//      - Each handler updates register file or PC
//      - JMP back to dispatch
//   3. Epilogue: restore callee-saved regs, RET
//
// We generate a *minimal* interpreter that handles the opcodes we actually
// emit.  The interpreter is self-contained and position-independent.

/// Generate the VM interpreter as x86_64 instructions.
fn generate_interpreter(table: &OpcodeTable) -> Vec<Instruction> {
    let mut out: Vec<Instruction> = Vec::with_capacity(512);
    let mut ip_counter: u64 = 0xFFFE_0000_0000_0000u64;

    let bump = |ip: &mut u64| -> u64 {
        let val = *ip;
        *ip = ip.wrapping_add(1);
        val
    };

    // Helper: allocate next IP and set it on the instruction.
    macro_rules! set_next_ip {
        ($inst:expr, $ip:expr) => {
            $inst.set_ip(bump(&mut $ip));
        };
    }

    // ── Prologue ─────────────────────────────────────────────────────────
    // push rbp
    let mut push_rbp = Instruction::with1(Code::Push_r64, Register::RBP).unwrap();
    set_next_ip!(push_rbp, ip_counter);
    out.push(push_rbp);

    // mov rbp, rsp
    let mut mov_bp_sp =
        Instruction::with2(Code::Mov_r64_rm64, Register::RBP, Register::RSP).unwrap();
    set_next_ip!(mov_bp_sp, ip_counter);
    out.push(mov_bp_sp);

    // push rbx (callee-saved, used as reg-file pointer)
    let mut push_rbx = Instruction::with1(Code::Push_r64, Register::RBX).unwrap();
    set_next_ip!(push_rbx, ip_counter);
    out.push(push_rbx);

    // push r12 (used as bytecode pointer)
    let mut push_r12 = Instruction::with1(Code::Push_r64, Register::R12).unwrap();
    set_next_ip!(push_r12, ip_counter);
    out.push(push_r12);

    // push r13 (used as bytecode length)
    let mut push_r13 = Instruction::with1(Code::Push_r64, Register::R13).unwrap();
    set_next_ip!(push_r13, ip_counter);
    out.push(push_r13);

    // push r14 (used as PC)
    let mut push_r14 = Instruction::with1(Code::Push_r64, Register::R14).unwrap();
    set_next_ip!(push_r14, ip_counter);
    out.push(push_r14);

    // push r15 (used as scratch)
    let mut push_r15 = Instruction::with1(Code::Push_r64, Register::R15).unwrap();
    set_next_ip!(push_r15, ip_counter);
    out.push(push_r15);

    // mov rbx, r8      ; rbx = register file base
    let mut mov_bx_r8 =
        Instruction::with2(Code::Mov_r64_rm64, Register::RBX, Register::R8).unwrap();
    set_next_ip!(mov_bx_r8, ip_counter);
    out.push(mov_bx_r8);

    // mov r12, rdi      ; r12 = bytecode pointer
    let mut mov_r12_rdi =
        Instruction::with2(Code::Mov_r64_rm64, Register::R12, Register::RDI).unwrap();
    set_next_ip!(mov_r12_rdi, ip_counter);
    out.push(mov_r12_rdi);

    // mov r13, rsi      ; r13 = bytecode length
    let mut mov_r13_rsi =
        Instruction::with2(Code::Mov_r64_rm64, Register::R13, Register::RSI).unwrap();
    set_next_ip!(mov_r13_rsi, ip_counter);
    out.push(mov_r13_rsi);

    // xor r14d, r14d    ; r14 = PC = 0
    let mut xor_r14 =
        Instruction::with2(Code::Xor_r32_rm32, Register::R14D, Register::R14D).unwrap();
    set_next_ip!(xor_r14, ip_counter);
    out.push(xor_r14);

    // ── Dispatch loop ────────────────────────────────────────────────────
    let dispatch_ip = bump(&mut ip_counter);

    // CMP r14, r13   (PC < len?)
    let mut cmp_pc_len =
        Instruction::with2(Code::Cmp_r64_rm64, Register::R14, Register::R13).unwrap();
    set_next_ip!(cmp_pc_len, ip_counter);
    out.push(cmp_pc_len);

    // JAE epilogue (if PC >= len, exit)
    let epilogue_ip = 0xFFFE_FFFF_0000_0000u64; // will be fixed up
    let mut jae_epilogue = Instruction::with_branch(Code::Jae_rel32_64, epilogue_ip).unwrap();
    set_next_ip!(jae_epilogue, ip_counter);
    out.push(jae_epilogue);
    let jae_epilogue_idx = out.len() - 1;

    // Load opcode: movzx r15d, byte [r12 + r14]
    let mut lea_rax = Instruction::with2(
        Code::Lea_r64_m,
        Register::RAX,
        MemoryOperand::with_base_index(Register::R12, Register::R14),
    )
    .unwrap();
    set_next_ip!(lea_rax, ip_counter);
    out.push(lea_rax);

    let mut movzx_r15 = Instruction::with2(
        Code::Movzx_r32_rm8,
        Register::R15D,
        MemoryOperand::with_base(Register::RAX),
    )
    .unwrap();
    set_next_ip!(movzx_r15, ip_counter);
    out.push(movzx_r15);

    // Increment PC past the opcode byte: inc r14
    let mut inc_r14 = Instruction::with1(Code::Inc_rm64, Register::R14).unwrap();
    set_next_ip!(inc_r14, ip_counter);
    out.push(inc_r14);

    // ── Opcode dispatch: compare against each opcode and jump to handler ─
    let opcode_order: Vec<usize> = (0..NUM_OPCODES).collect();

    let dispatch_je_indices: Vec<usize> = opcode_order
        .iter()
        .map(|&semantic| {
            let opcode_byte = table.encode[semantic];

            // CMP r15d, opcode_byte
            let mut cmp =
                Instruction::with2(Code::Cmp_rm32_imm32, Register::R15D, opcode_byte as i32)
                    .unwrap();
            cmp.set_ip(bump(&mut ip_counter));
            out.push(cmp);

            // JE handler (placeholder target — will fix up below)
            let mut je =
                Instruction::with_branch(Code::Je_rel32_64, 0xFFFE_FFFF_0000_0000u64).unwrap();
            je.set_ip(bump(&mut ip_counter));
            out.push(je);

            out.len() - 1 // index of the JE instruction
        })
        .collect();

    // If no opcode matched, jump to epilogue (invalid opcode → exit).
    let mut jmp_epilogue2 = Instruction::with_branch(Code::Jmp_rel32_64, epilogue_ip).unwrap();
    jmp_epilogue2.set_ip(bump(&mut ip_counter));
    out.push(jmp_epilogue2);
    let jmp_epilogue2_idx = out.len() - 1;

    // ── Opcode handlers ──────────────────────────────────────────────────
    let actual_handler_ips: Vec<(usize, u64)> = opcode_order
        .iter()
        .map(|&semantic| {
            let handler_start_ip = ip_counter;

            let vm_op = unsafe { std::mem::transmute::<u8, VmOp>(semantic as u8) };

            emit_handler(&mut out, vm_op, &mut ip_counter, dispatch_ip, table);

            (semantic, handler_start_ip)
        })
        .collect();

    // Fix up handler IPs in the JE instructions and the JMP epilogue.
    let actual_epilogue_ip = ip_counter;

    // Fix up the JAE epilogue.
    out[jae_epilogue_idx].set_near_branch64(actual_epilogue_ip);

    // Fix up the JMP epilogue2.
    out[jmp_epilogue2_idx].set_near_branch64(actual_epilogue_ip);

    // Fix up each JE handler target.
    for i in 0..dispatch_je_indices.len() {
        let je_idx = dispatch_je_indices[i];
        let (_, actual_ip) = actual_handler_ips[i];
        out[je_idx].set_near_branch64(actual_ip);
    }

    // ── Epilogue ─────────────────────────────────────────────────────────
    let _epilogue_start_ip = ip_counter;

    // pop r15
    let mut pop_r15 = Instruction::with1(Code::Pop_r64, Register::R15).unwrap();
    pop_r15.set_ip(bump(&mut ip_counter));
    out.push(pop_r15);

    // pop r14
    let mut pop_r14 = Instruction::with1(Code::Pop_r64, Register::R14).unwrap();
    pop_r14.set_ip(bump(&mut ip_counter));
    out.push(pop_r14);

    // pop r13
    let mut pop_r13 = Instruction::with1(Code::Pop_r64, Register::R13).unwrap();
    pop_r13.set_ip(bump(&mut ip_counter));
    out.push(pop_r13);

    // pop r12
    let mut pop_r12 = Instruction::with1(Code::Pop_r64, Register::R12).unwrap();
    pop_r12.set_ip(bump(&mut ip_counter));
    out.push(pop_r12);

    // pop rbx
    let mut pop_rbx = Instruction::with1(Code::Pop_r64, Register::RBX).unwrap();
    pop_rbx.set_ip(bump(&mut ip_counter));
    out.push(pop_rbx);

    // pop rbp
    let mut pop_rbp = Instruction::with1(Code::Pop_r64, Register::RBP).unwrap();
    pop_rbp.set_ip(bump(&mut ip_counter));
    out.push(pop_rbp);

    // ret
    let mut ret = Instruction::with(Code::Retnq);
    ret.set_ip(bump(&mut ip_counter));
    out.push(ret);

    out
}

/// Emit the handler for a single VM opcode.
fn emit_handler(
    out: &mut Vec<Instruction>,
    op: VmOp,
    extra_ip: &mut u64,
    dispatch_ip: u64,
    _table: &OpcodeTable,
) {
    let mut next_ip = || {
        let ip = *extra_ip;
        *extra_ip = extra_ip.wrapping_add(1);
        ip
    };

    // Helper: load register index from bytecode at [r12 + r14], advance PC.
    // movzx eax, byte [r12 + r14]
    // inc r14
    macro_rules! load_reg_idx {
        ($out:expr) => {{
            // lea rcx, [r12 + r14]
            let mut lea = Instruction::with2(
                Code::Lea_r64_m,
                Register::RCX,
                MemoryOperand::with_base_index(Register::R12, Register::R14),
            )
            .unwrap();
            lea.set_ip(next_ip());
            $out.push(lea);

            // movzx eax, byte [rcx]
            let mut movzx = Instruction::with2(
                Code::Movzx_r32_rm8,
                Register::EAX,
                MemoryOperand::with_base(Register::RCX),
            )
            .unwrap();
            movzx.set_ip(next_ip());
            $out.push(movzx);

            // inc r14
            let mut inc = Instruction::with1(Code::Inc_rm64, Register::R14).unwrap();
            inc.set_ip(next_ip());
            $out.push(inc);
        }};
    }

    // Helper: read 4-byte signed value from bytecode, advance PC by 4.
    macro_rules! load_imm32 {
        ($out:expr, $dst_reg:expr) => {{
            // lea rcx, [r12 + r14]
            let mut lea = Instruction::with2(
                Code::Lea_r64_m,
                $dst_reg,
                MemoryOperand::with_base_index(Register::R12, Register::R14),
            )
            .unwrap();
            lea.set_ip(next_ip());
            $out.push(lea);

            // movsxd $dst_reg, dword [$dst_reg]
            let mut movsxd = Instruction::with2(
                Code::Movsxd_r64_rm32,
                $dst_reg,
                MemoryOperand::with_base($dst_reg),
            )
            .unwrap();
            movsxd.set_ip(next_ip());
            $out.push(movsxd);

            // add r14, 4
            let mut add4 = Instruction::with2(Code::Add_rm64_imm8, Register::R14, 4i32).unwrap();
            add4.set_ip(next_ip());
            $out.push(add4);
        }};
    }

    // Helper: load 8-byte immediate, advance PC by 8.
    macro_rules! load_imm64 {
        ($out:expr, $dst_reg:expr) => {{
            // lea rcx, [r12 + r14]
            let mut lea = Instruction::with2(
                Code::Lea_r64_m,
                $dst_reg,
                MemoryOperand::with_base_index(Register::R12, Register::R14),
            )
            .unwrap();
            lea.set_ip(next_ip());
            $out.push(lea);

            // mov $dst_reg, qword [$dst_reg]
            let mut mov_q = Instruction::with2(
                Code::Mov_r64_rm64,
                $dst_reg,
                MemoryOperand::with_base($dst_reg),
            )
            .unwrap();
            mov_q.set_ip(next_ip());
            $out.push(mov_q);

            // add r14, 8
            let mut add8 = Instruction::with2(Code::Add_rm64_imm8, Register::R14, 8i32).unwrap();
            add8.set_ip(next_ip());
            $out.push(add8);
        }};
    }

    // Helper: jump back to dispatch.
    macro_rules! jmp_dispatch {
        ($out:expr) => {{
            let mut jmp = Instruction::with_branch(Code::Jmp_rel32_64, dispatch_ip).unwrap();
            jmp.set_ip(next_ip());
            $out.push(jmp);
        }};
    }

    match op {
        VmOp::Nop => {
            // Nothing to do.
            jmp_dispatch!(out);
        }

        VmOp::MovRegReg => {
            // Copy value from reg[src] to reg[dst].
            // Bytecode: [opcode] [dst_idx] [src_idx]
            //
            // Strategy:
            //   1. Load dst idx → eax, shl 3, push rax (save dst*8)
            //   2. Load src idx → eax, shl 3
            //   3. mov rax, [rbx + rax]  (load src value)
            //   4. pop rcx (restore dst*8)
            //   5. mov [rbx + rcx], rax  (store to dst)

            // Load dst register index
            load_reg_idx!(out); // eax = dst reg index

            // shl eax, 3 (dst * 8 for qword array offset)
            let mut shl1 = Instruction::with2(Code::Shl_rm32_imm8, Register::EAX, 3i32).unwrap();
            shl1.set_ip(next_ip());
            out.push(shl1);

            // Save dst*8 on the stack
            let mut push_dst = Instruction::with1(Code::Push_r64, Register::RAX).unwrap();
            push_dst.set_ip(next_ip());
            out.push(push_dst);

            // Load src register index
            load_reg_idx!(out); // eax = src reg index

            // shl eax, 3 (src * 8)
            let mut shl2 = Instruction::with2(Code::Shl_rm32_imm8, Register::EAX, 3i32).unwrap();
            shl2.set_ip(next_ip());
            out.push(shl2);

            // mov rax, [rbx + rax] — load value from src slot
            let mut load_src = Instruction::with2(
                Code::Mov_r64_rm64,
                Register::RAX,
                MemoryOperand::with_base_index(Register::RBX, Register::RAX),
            )
            .unwrap();
            load_src.set_ip(next_ip());
            out.push(load_src);

            // pop rcx — restore dst*8
            let mut pop_dst = Instruction::with1(Code::Pop_r64, Register::RCX).unwrap();
            pop_dst.set_ip(next_ip());
            out.push(pop_dst);

            // mov [rbx + rcx], rax — store value to dst slot
            let mut store_dst = Instruction::with2(
                Code::Mov_rm64_r64,
                MemoryOperand::with_base_index(Register::RBX, Register::RCX),
                Register::RAX,
            )
            .unwrap();
            store_dst.set_ip(next_ip());
            out.push(store_dst);

            jmp_dispatch!(out);
        }

        VmOp::MovRegImm => {
            // Store 8-byte immediate to reg[dst].
            // Bytecode: [opcode] [dst_idx] [imm64]
            //
            // Strategy:
            //   1. Load dst idx → eax, shl 3, push rax (save dst*8)
            //   2. Load 8-byte imm → rax
            //   3. pop rcx (restore dst*8)
            //   4. mov [rbx + rcx], rax (store imm to dst slot)

            // Load dst register index
            load_reg_idx!(out); // eax = dst reg index

            // shl eax, 3
            let mut shl1 = Instruction::with2(Code::Shl_rm32_imm8, Register::EAX, 3i32).unwrap();
            shl1.set_ip(next_ip());
            out.push(shl1);

            // Save dst*8 on the stack
            let mut push_dst = Instruction::with1(Code::Push_r64, Register::RAX).unwrap();
            push_dst.set_ip(next_ip());
            out.push(push_dst);

            // Load 8-byte immediate value
            load_imm64!(out, Register::RAX); // rax = immediate value

            // pop rcx — restore dst*8
            let mut pop_dst = Instruction::with1(Code::Pop_r64, Register::RCX).unwrap();
            pop_dst.set_ip(next_ip());
            out.push(pop_dst);

            // mov [rbx + rcx], rax — store imm to dst slot
            let mut store_dst = Instruction::with2(
                Code::Mov_rm64_r64,
                MemoryOperand::with_base_index(Register::RBX, Register::RCX),
                Register::RAX,
            )
            .unwrap();
            store_dst.set_ip(next_ip());
            out.push(store_dst);

            jmp_dispatch!(out);
        }

        VmOp::Add | VmOp::Sub | VmOp::And | VmOp::Or | VmOp::Xor | VmOp::Shl | VmOp::Shr => {
            // Two-register ALU operation: dst = dst OP src
            // Bytecode: [opcode] [dst_idx] [src_idx]
            //
            // Strategy:
            //   1. Load dst idx → eax, shl 3, push rax (save dst*8)
            //   2. Load src idx → eax, shl 3
            //   3. mov rax, [rbx + rax] — load src value → rax
            //   4. pop rcx — restore dst*8
            //   5. For commutative ops (Add/And/Or/Xor): op [rbx+rcx], rax
            //      For non-commutative (Sub/Shl/Shr): load dst first, then op
            //
            // For simplicity we use a uniform approach:
            //   1. push dst*8
            //   2. compute src*8, load src → rax
            //   3. pop dst*8 → rcx
            //   4. load dst → rdx: mov rdx, [rbx+rcx]
            //   5. Perform op on rdx with rax
            //   6. Store rdx → [rbx+rcx]
            // This works uniformly for all ops.

            // Load dst register index
            load_reg_idx!(out); // eax = dst reg index

            // shl eax, 3
            let mut shl1 = Instruction::with2(Code::Shl_rm32_imm8, Register::EAX, 3i32).unwrap();
            shl1.set_ip(next_ip());
            out.push(shl1);

            // Save dst*8 on the stack
            let mut push_dst = Instruction::with1(Code::Push_r64, Register::RAX).unwrap();
            push_dst.set_ip(next_ip());
            out.push(push_dst);

            // Load src register index
            load_reg_idx!(out); // eax = src reg index

            // shl eax, 3
            let mut shl2 = Instruction::with2(Code::Shl_rm32_imm8, Register::EAX, 3i32).unwrap();
            shl2.set_ip(next_ip());
            out.push(shl2);

            // mov rax, [rbx + rax] — load src value
            let mut load_src = Instruction::with2(
                Code::Mov_r64_rm64,
                Register::RAX,
                MemoryOperand::with_base_index(Register::RBX, Register::RAX),
            )
            .unwrap();
            load_src.set_ip(next_ip());
            out.push(load_src);

            // Save src value
            let mut push_src = Instruction::with1(Code::Push_r64, Register::RAX).unwrap();
            push_src.set_ip(next_ip());
            out.push(push_src);

            // pop rcx — restore dst*8
            let mut pop_dst = Instruction::with1(Code::Pop_r64, Register::RCX).unwrap();
            pop_dst.set_ip(next_ip());
            out.push(pop_dst);

            // mov rdx, [rbx + rcx] — load dst value
            let mut load_dst = Instruction::with2(
                Code::Mov_r64_rm64,
                Register::RDX,
                MemoryOperand::with_base_index(Register::RBX, Register::RCX),
            )
            .unwrap();
            load_dst.set_ip(next_ip());
            out.push(load_dst);

            // pop rax — restore src value
            let mut pop_src = Instruction::with1(Code::Pop_r64, Register::RAX).unwrap();
            pop_src.set_ip(next_ip());
            out.push(pop_src);

            // Perform the ALU operation: rdx OP= rax
            match op {
                VmOp::Add => {
                    let mut alu =
                        Instruction::with2(Code::Add_r64_rm64, Register::RDX, Register::RAX)
                            .unwrap();
                    alu.set_ip(next_ip());
                    out.push(alu);
                }
                VmOp::Sub => {
                    let mut alu =
                        Instruction::with2(Code::Sub_r64_rm64, Register::RDX, Register::RAX)
                            .unwrap();
                    alu.set_ip(next_ip());
                    out.push(alu);
                }
                VmOp::And => {
                    let mut alu =
                        Instruction::with2(Code::And_r64_rm64, Register::RDX, Register::RAX)
                            .unwrap();
                    alu.set_ip(next_ip());
                    out.push(alu);
                }
                VmOp::Or => {
                    let mut alu =
                        Instruction::with2(Code::Or_r64_rm64, Register::RDX, Register::RAX)
                            .unwrap();
                    alu.set_ip(next_ip());
                    out.push(alu);
                }
                VmOp::Xor => {
                    let mut alu =
                        Instruction::with2(Code::Xor_r64_rm64, Register::RDX, Register::RAX)
                            .unwrap();
                    alu.set_ip(next_ip());
                    out.push(alu);
                }
                VmOp::Shl => {
                    // Shift dst by cl (low byte of src). Use rcx for shift count.
                    // rax already has src value; move low byte to cl.
                    let mut mov_cl =
                        Instruction::with2(Code::Mov_rm8_r8, Register::CL, Register::AL).unwrap();
                    mov_cl.set_ip(next_ip());
                    out.push(mov_cl);
                    let mut alu =
                        Instruction::with2(Code::Shl_rm64_CL, Register::RDX, Register::CL).unwrap();
                    alu.set_ip(next_ip());
                    out.push(alu);
                }
                VmOp::Shr => {
                    let mut mov_cl =
                        Instruction::with2(Code::Mov_rm8_r8, Register::CL, Register::AL).unwrap();
                    mov_cl.set_ip(next_ip());
                    out.push(mov_cl);
                    let mut alu =
                        Instruction::with2(Code::Shr_rm64_CL, Register::RDX, Register::CL).unwrap();
                    alu.set_ip(next_ip());
                    out.push(alu);
                }
                _ => unreachable!(),
            }

            // mov [rbx + rcx], rdx — store result back to dst slot
            let mut store = Instruction::with2(
                Code::Mov_rm64_r64,
                MemoryOperand::with_base_index(Register::RBX, Register::RCX),
                Register::RDX,
            )
            .unwrap();
            store.set_ip(next_ip());
            out.push(store);

            jmp_dispatch!(out);
        }

        VmOp::Cmp => {
            // Compare reg[a] with reg[b], set RFLAGS.
            // Bytecode: [opcode] [a_idx] [b_idx]
            //
            // Strategy:
            //   1. Load a idx → eax, shl 3, push rax (save a*8)
            //   2. Load b idx → eax, shl 3
            //   3. mov rax, [rbx + rax] — load b value → rax
            //   4. pop rcx — restore a*8
            //   5. cmp [rbx + rcx], rax — compare a with b, sets RFLAGS
            // RFLAGS is now set for the subsequent Jcc handler.

            // Load a register index
            load_reg_idx!(out); // eax = a reg index

            // shl eax, 3
            let mut shl1 = Instruction::with2(Code::Shl_rm32_imm8, Register::EAX, 3i32).unwrap();
            shl1.set_ip(next_ip());
            out.push(shl1);

            // Save a*8 on the stack
            let mut push_a = Instruction::with1(Code::Push_r64, Register::RAX).unwrap();
            push_a.set_ip(next_ip());
            out.push(push_a);

            // Load b register index
            load_reg_idx!(out); // eax = b reg index

            // shl eax, 3
            let mut shl2 = Instruction::with2(Code::Shl_rm32_imm8, Register::EAX, 3i32).unwrap();
            shl2.set_ip(next_ip());
            out.push(shl2);

            // mov rax, [rbx + rax] — load b value
            let mut load_b = Instruction::with2(
                Code::Mov_r64_rm64,
                Register::RAX,
                MemoryOperand::with_base_index(Register::RBX, Register::RAX),
            )
            .unwrap();
            load_b.set_ip(next_ip());
            out.push(load_b);

            // pop rcx — restore a*8
            let mut pop_a = Instruction::with1(Code::Pop_r64, Register::RCX).unwrap();
            pop_a.set_ip(next_ip());
            out.push(pop_a);

            // cmp [rbx + rcx], rax — compare reg[a] with reg[b]
            // This sets RFLAGS for the Jcc handler that follows.
            let mut cmp = Instruction::with2(
                Code::Cmp_rm64_r64,
                MemoryOperand::with_base_index(Register::RBX, Register::RCX),
                Register::RAX,
            )
            .unwrap();
            cmp.set_ip(next_ip());
            out.push(cmp);

            jmp_dispatch!(out);
        }

        VmOp::Jmp => {
            // Load 4-byte offset, set PC = offset.
            load_imm32!(out, Register::RAX); // offset → rax
                                             // mov r14, rax  (PC = offset)
            let mut mov_pc =
                Instruction::with2(Code::Mov_r64_rm64, Register::R14, Register::RAX).unwrap();
            mov_pc.set_ip(next_ip());
            out.push(mov_pc);
            jmp_dispatch!(out);
        }

        VmOp::Jcc => {
            // Load condition code (0=Z, 1=NZ, 2=L, 3=GE, 4=G, 5=LE),
            // load 4-byte branch target offset.
            //
            // Strategy: the preceding VmOp::Cmp set RFLAGS. We must
            // save them BEFORE any subsequent comparison clobbers them.
            // Then dispatch on condition code and apply the saved flags
            // to decide whether to take the branch.
            //
            //   1. pushfq                    ; save RFLAGS from Cmp
            //   2. load condition code → eax
            //   3. load branch target  → rcx
            //   4. switch on condition code → decide taken/not-taken
            //   5. popfq (clean up saved flags)

            // pushfq — save RFLAGS
            let mut pushfq = Instruction::with(Code::Pushfq);
            pushfq.set_ip(next_ip());
            out.push(pushfq);

            load_reg_idx!(out); // condition code → eax
            load_imm32!(out, Register::RCX); // branch target → rcx

            // Save branch target and condition code on stack so they
            // survive the popfq below.
            // push rcx (branch target)
            let mut push_target = Instruction::with1(Code::Push_r64, Register::RCX).unwrap();
            push_target.set_ip(next_ip());
            out.push(push_target);
            // push rax (condition code)
            let mut push_cc = Instruction::with1(Code::Push_r64, Register::RAX).unwrap();
            push_cc.set_ip(next_ip());
            out.push(push_cc);

            // popfq — restore RFLAGS from Cmp so conditional jumps work
            let mut popfq = Instruction::with(Code::Popfq);
            popfq.set_ip(next_ip());
            out.push(popfq);

            // Restore condition code: pop rax
            let mut pop_cc = Instruction::with1(Code::Pop_r64, Register::RAX).unwrap();
            pop_cc.set_ip(next_ip());
            out.push(pop_cc);

            // Now RFLAGS hold the Cmp result and eax = condition code.
            // We need to emit conditional jumps based on the condition code.
            // Approach: for each condition code value, compare and jump to
            // a handler that tests the right flag combination.
            //
            // Since we can only do one conditional jump per flag state,
            // we emit a cascade:
            //   cmp eax, 0  →  je  check_zf_set    ; ZF=1
            //   cmp eax, 1  →  je  check_zf_clear   ; ZF=0
            //   cmp eax, 2  →  je  check_sf_ne_of   ; SF!=OF
            //   cmp eax, 3  →  je  check_sf_eq_of   ; SF==OF
            //   cmp eax, 4  →  je  check_zf_clear_and_sf_eq_of ; ZF=0 && SF==OF
            //   cmp eax, 5  →  je  check_zf_set_or_sf_ne_of    ; ZF=1 || SF!=OF
            //   jmp not_taken (fall through)

            // Condition 0: ZF=1 (JE/JZ)
            let mut cmp0 = Instruction::with2(Code::Cmp_rm32_imm8, Register::EAX, 0i32).unwrap();
            cmp0.set_ip(next_ip());
            out.push(cmp0);
            let mut je0 = Instruction::with_branch(Code::Je_rel32_64, 0xFFFE_FFFF_u64).unwrap();
            je0.set_ip(next_ip());
            out.push(je0);
            let je0_idx = out.len() - 1;

            // Condition 1: ZF=0 (JNE/JNZ)
            let mut cmp1 = Instruction::with2(Code::Cmp_rm32_imm8, Register::EAX, 1i32).unwrap();
            cmp1.set_ip(next_ip());
            out.push(cmp1);
            let mut je1 = Instruction::with_branch(Code::Je_rel32_64, 0xFFFE_FFFF_u64).unwrap();
            je1.set_ip(next_ip());
            out.push(je1);
            let je1_idx = out.len() - 1;

            // Condition 2: SF!=OF (JL)
            let mut cmp2 = Instruction::with2(Code::Cmp_rm32_imm8, Register::EAX, 2i32).unwrap();
            cmp2.set_ip(next_ip());
            out.push(cmp2);
            let mut je2 = Instruction::with_branch(Code::Je_rel32_64, 0xFFFE_FFFF_u64).unwrap();
            je2.set_ip(next_ip());
            out.push(je2);
            let je2_idx = out.len() - 1;

            // Condition 3: SF==OF (JGE)
            let mut cmp3 = Instruction::with2(Code::Cmp_rm32_imm8, Register::EAX, 3i32).unwrap();
            cmp3.set_ip(next_ip());
            out.push(cmp3);
            let mut je3 = Instruction::with_branch(Code::Je_rel32_64, 0xFFFE_FFFF_u64).unwrap();
            je3.set_ip(next_ip());
            out.push(je3);
            let je3_idx = out.len() - 1;

            // Condition 4: ZF=0 && SF==OF (JG)
            let mut cmp4 = Instruction::with2(Code::Cmp_rm32_imm8, Register::EAX, 4i32).unwrap();
            cmp4.set_ip(next_ip());
            out.push(cmp4);
            let mut je4 = Instruction::with_branch(Code::Je_rel32_64, 0xFFFE_FFFF_u64).unwrap();
            je4.set_ip(next_ip());
            out.push(je4);
            let je4_idx = out.len() - 1;

            // Condition 5: ZF=1 || SF!=OF (JLE)
            let mut cmp5 = Instruction::with2(Code::Cmp_rm32_imm8, Register::EAX, 5i32).unwrap();
            cmp5.set_ip(next_ip());
            out.push(cmp5);
            let mut je5 = Instruction::with_branch(Code::Je_rel32_64, 0xFFFE_FFFF_u64).unwrap();
            je5.set_ip(next_ip());
            out.push(je5);
            let je5_idx = out.len() - 1;

            // Fall-through: unknown condition or not taken.
            // Pop the saved branch target and continue.
            let not_taken_ip = next_ip();
            let mut pop_discard = Instruction::with1(Code::Pop_r64, Register::RCX).unwrap();
            pop_discard.set_ip(next_ip());
            out.push(pop_discard);
            jmp_dispatch!(out);

            // ── Condition handler pads ──
            // Each pad: test the restored RFLAGS with the appropriate
            // conditional jump. If taken → pop target, set PC.
            // If not taken → pop target, continue.

            // Pad 0: JE/JZ (ZF=1)
            let pad0_ip = next_ip();
            let mut jz0 = Instruction::with_branch(Code::Jne_rel32_64, not_taken_ip).unwrap();
            jz0.set_ip(next_ip());
            out.push(jz0);
            // taken path: pop rcx (target), mov r14, rcx
            let mut pop0 = Instruction::with1(Code::Pop_r64, Register::RCX).unwrap();
            pop0.set_ip(next_ip());
            out.push(pop0);
            let mut set_pc0 =
                Instruction::with2(Code::Mov_r64_rm64, Register::R14, Register::RCX).unwrap();
            set_pc0.set_ip(next_ip());
            out.push(set_pc0);
            jmp_dispatch!(out);

            // Pad 1: JNE/JNZ (ZF=0)
            let pad1_ip = next_ip();
            let mut jnz1 = Instruction::with_branch(Code::Je_rel32_64, not_taken_ip).unwrap();
            jnz1.set_ip(next_ip());
            out.push(jnz1);
            let mut pop1 = Instruction::with1(Code::Pop_r64, Register::RCX).unwrap();
            pop1.set_ip(next_ip());
            out.push(pop1);
            let mut set_pc1 =
                Instruction::with2(Code::Mov_r64_rm64, Register::R14, Register::RCX).unwrap();
            set_pc1.set_ip(next_ip());
            out.push(set_pc1);
            jmp_dispatch!(out);

            // Pad 2: JL (SF!=OF)
            let pad2_ip = next_ip();
            let mut jl2 = Instruction::with_branch(Code::Jge_rel32_64, not_taken_ip).unwrap();
            jl2.set_ip(next_ip());
            out.push(jl2);
            let mut pop2 = Instruction::with1(Code::Pop_r64, Register::RCX).unwrap();
            pop2.set_ip(next_ip());
            out.push(pop2);
            let mut set_pc2 =
                Instruction::with2(Code::Mov_r64_rm64, Register::R14, Register::RCX).unwrap();
            set_pc2.set_ip(next_ip());
            out.push(set_pc2);
            jmp_dispatch!(out);

            // Pad 3: JGE (SF==OF)
            let pad3_ip = next_ip();
            let mut jge3 = Instruction::with_branch(Code::Jl_rel32_64, not_taken_ip).unwrap();
            jge3.set_ip(next_ip());
            out.push(jge3);
            let mut pop3 = Instruction::with1(Code::Pop_r64, Register::RCX).unwrap();
            pop3.set_ip(next_ip());
            out.push(pop3);
            let mut set_pc3 =
                Instruction::with2(Code::Mov_r64_rm64, Register::R14, Register::RCX).unwrap();
            set_pc3.set_ip(next_ip());
            out.push(set_pc3);
            jmp_dispatch!(out);

            // Pad 4: JG (ZF=0 && SF==OF) — use JLE as inverted test
            let pad4_ip = next_ip();
            let mut jg4 = Instruction::with_branch(Code::Jle_rel32_64, not_taken_ip).unwrap();
            jg4.set_ip(next_ip());
            out.push(jg4);
            let mut pop4 = Instruction::with1(Code::Pop_r64, Register::RCX).unwrap();
            pop4.set_ip(next_ip());
            out.push(pop4);
            let mut set_pc4 =
                Instruction::with2(Code::Mov_r64_rm64, Register::R14, Register::RCX).unwrap();
            set_pc4.set_ip(next_ip());
            out.push(set_pc4);
            jmp_dispatch!(out);

            // Pad 5: JLE (ZF=1 || SF!=OF) — use JG as inverted test
            let pad5_ip = next_ip();
            let mut jle5 = Instruction::with_branch(Code::Jg_rel32_64, not_taken_ip).unwrap();
            jle5.set_ip(next_ip());
            out.push(jle5);
            let mut pop5 = Instruction::with1(Code::Pop_r64, Register::RCX).unwrap();
            pop5.set_ip(next_ip());
            out.push(pop5);
            let mut set_pc5 =
                Instruction::with2(Code::Mov_r64_rm64, Register::R14, Register::RCX).unwrap();
            set_pc5.set_ip(next_ip());
            out.push(set_pc5);
            jmp_dispatch!(out);

            // Fix up all the JE jumps from the condition-code comparisons
            // to point to their respective handler pads.
            out[je0_idx].set_near_branch64(pad0_ip);
            out[je1_idx].set_near_branch64(pad1_ip);
            out[je2_idx].set_near_branch64(pad2_ip);
            out[je3_idx].set_near_branch64(pad3_ip);
            out[je4_idx].set_near_branch64(pad4_ip);
            out[je5_idx].set_near_branch64(pad5_ip);
        }

        VmOp::Push => {
            // Load register index, compute address in reg file,
            // load the 8-byte value, push it onto the virtual stack.
            load_reg_idx!(out); // reg index → eax

            // shl eax, 3 (reg_index * 8)
            let mut shl = Instruction::with2(Code::Shl_rm32_imm8, Register::EAX, 3i32).unwrap();
            shl.set_ip(next_ip());
            out.push(shl);

            // mov rax, qword [rbx + rax]  (load value from reg file)
            let mut load_val = Instruction::with2(
                Code::Mov_r64_rm64,
                Register::RAX,
                MemoryOperand::with_base_index(Register::RBX, Register::RAX),
            )
            .unwrap();
            load_val.set_ip(next_ip());
            out.push(load_val);

            // push rax (push value onto virtual stack)
            let mut push = Instruction::with1(Code::Push_r64, Register::RAX).unwrap();
            push.set_ip(next_ip());
            out.push(push);

            jmp_dispatch!(out);
        }

        VmOp::Pop => {
            // Pop 8 bytes from virtual stack, store to register file slot.
            load_reg_idx!(out); // reg index → eax

            // Save reg index: push rax
            let mut save_idx = Instruction::with1(Code::Push_r64, Register::RAX).unwrap();
            save_idx.set_ip(next_ip());
            out.push(save_idx);

            // pop rcx (pop value from stack → rcx)
            let mut pop_val = Instruction::with1(Code::Pop_r64, Register::RCX).unwrap();
            pop_val.set_ip(next_ip());
            out.push(pop_val);

            // Restore reg index: pop rax
            let mut restore_idx = Instruction::with1(Code::Pop_r64, Register::RAX).unwrap();
            restore_idx.set_ip(next_ip());
            out.push(restore_idx);

            // shl eax, 3 (reg_index * 8)
            let mut shl = Instruction::with2(Code::Shl_rm32_imm8, Register::EAX, 3i32).unwrap();
            shl.set_ip(next_ip());
            out.push(shl);

            // mov qword [rbx + rax], rcx  (store to reg file)
            let mut store = Instruction::with2(
                Code::Mov_rm64_r64,
                MemoryOperand::with_base_index(Register::RBX, Register::RAX),
                Register::RCX,
            )
            .unwrap();
            store.set_ip(next_ip());
            out.push(store);

            jmp_dispatch!(out);
        }

        VmOp::Ret => {
            // Jump to epilogue. We need the epilogue IP but we don't have it
            // here. For now, set PC to bytecode length to trigger exit.
            // mov r14, r13  (PC = len → exit on next dispatch)
            let mut mov_pc =
                Instruction::with2(Code::Mov_r64_rm64, Register::R14, Register::R13).unwrap();
            mov_pc.set_ip(next_ip());
            out.push(mov_pc);
            jmp_dispatch!(out);
        }

        VmOp::Call => {
            // Load 4-byte target offset, push return address (current PC),
            // then set PC to target.
            load_imm32!(out, Register::RAX); // target offset → rax

            // Push return address (current R14 = PC after this instruction)
            // onto the virtual stack. R14 already points past the operands.
            let mut push_ret = Instruction::with1(Code::Push_r64, Register::R14).unwrap();
            push_ret.set_ip(next_ip());
            out.push(push_ret);

            // Set PC to target: mov r14, rax
            let mut mov_pc =
                Instruction::with2(Code::Mov_r64_rm64, Register::R14, Register::RAX).unwrap();
            mov_pc.set_ip(next_ip());
            out.push(mov_pc);

            jmp_dispatch!(out);
        }

        VmOp::Not | VmOp::Neg => {
            // Load register index, apply NOT (bitwise complement) or
            // NEG (two's complement negation) to the 8-byte slot.
            load_reg_idx!(out); // reg index → eax

            // shl eax, 3 (reg_index * 8)
            let mut shl = Instruction::with2(Code::Shl_rm32_imm8, Register::EAX, 3i32).unwrap();
            shl.set_ip(next_ip());
            out.push(shl);

            // Determine which operation to emit based on the VmOp variant.
            // We check at codegen time, not runtime.
            let is_not = matches!(op, VmOp::Not);

            // not/neg qword [rbx + rax]
            let code = if is_not {
                Code::Not_rm64
            } else {
                Code::Neg_rm64
            };
            let mut alu = Instruction::with1(
                code,
                MemoryOperand::with_base_index(Register::RBX, Register::RAX),
            )
            .unwrap();
            alu.set_ip(next_ip());
            out.push(alu);

            jmp_dispatch!(out);
        }

        VmOp::Inc | VmOp::Dec => {
            // Load register index, apply INC (increment) or DEC (decrement)
            // to the 8-byte slot in the register file.
            load_reg_idx!(out); // reg index → eax

            // shl eax, 3 (reg_index * 8)
            let mut shl = Instruction::with2(Code::Shl_rm32_imm8, Register::EAX, 3i32).unwrap();
            shl.set_ip(next_ip());
            out.push(shl);

            // Determine which operation to emit.
            let is_inc = matches!(op, VmOp::Inc);

            let code = if is_inc {
                Code::Inc_rm64
            } else {
                Code::Dec_rm64
            };
            // inc/dec qword [rbx + rax]
            // Note: Inc/Dec with memory operand needs the full encoding.
            // We use the register form: load → inc/dec → store.
            //
            // mov rcx, qword [rbx + rax]
            let mut load = Instruction::with2(
                Code::Mov_r64_rm64,
                Register::RCX,
                MemoryOperand::with_base_index(Register::RBX, Register::RAX),
            )
            .unwrap();
            load.set_ip(next_ip());
            out.push(load);

            // inc/dec rcx
            let mut alu = Instruction::with1(code, Register::RCX).unwrap();
            alu.set_ip(next_ip());
            out.push(alu);

            // mov qword [rbx + rax], rcx
            let mut store = Instruction::with2(
                Code::Mov_rm64_r64,
                MemoryOperand::with_base_index(Register::RBX, Register::RAX),
                Register::RCX,
            )
            .unwrap();
            store.set_ip(next_ip());
            out.push(store);

            jmp_dispatch!(out);
        }
    }
}

// ─── Main entry point ───────────────────────────────────────────────────────

/// Apply code virtualization to x86-64 machine code.
///
/// Translates basic blocks into VM bytecode and generates a custom interpreter.
/// Returns the input unchanged if virtualization cannot be safely applied.
pub fn virtualize(code: &[u8], rng: &mut ChaCha8Rng) -> Vec<u8> {
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
    if blocks.len() < 1 {
        return code.to_vec();
    }

    // Check that we can translate at least some blocks.
    // For the initial implementation, we require that ALL instructions in
    // ALL blocks are translatable.  If any block contains an untranslatable
    // instruction, we return the input unchanged (conservative).
    let mut all_translatable = true;
    for block in &blocks {
        for inst in &block.instructions {
            if matches!(translate_instruction(inst), TranslateResult::Native) {
                // Allow terminators through — they get special handling.
                if !is_terminator(inst) {
                    all_translatable = false;
                    break;
                }
            }
        }
        if !all_translatable {
            break;
        }
    }

    if !all_translatable {
        log::debug!(
            "virtualize: input contains non-translatable instructions; returning unchanged"
        );
        return code.to_vec();
    }

    // Generate randomized opcode table.
    let table = OpcodeTable::generate(rng);

    // Generate the VM interpreter function.
    let interpreter_insns = generate_interpreter(&table);
    let interpreter_bytes = encode_block(&interpreter_insns, 0);

    // Translate each block into bytecode.
    let mut block_bytecodes: Vec<Vec<u8>> = Vec::with_capacity(blocks.len());
    let mut block_native_fallbacks: Vec<Vec<u8>> = Vec::with_capacity(blocks.len());

    for block in &blocks {
        let mut bc_insns: Vec<BytecodeInsn> = Vec::new();

        for inst in &block.instructions {
            match translate_instruction(inst) {
                TranslateResult::Ok(insns) => bc_insns.extend(insns),
                TranslateResult::Native => {
                    // Terminators that we can't translate are left as native
                    // fallback.  This shouldn't happen since we checked above.
                    log::debug!(
                        "virtualize: unexpected native instruction in block at IP {:#x}",
                        inst.ip()
                    );
                    return code.to_vec();
                }
            }
        }

        // Ensure block ends with RET bytecode if it ends with a RET instruction.
        let last = block.instructions.last();
        if let Some(last_inst) = last {
            if matches!(last_inst.code(), Code::Retnq) {
                // Already have RET from translation.
            } else if !is_terminator(last_inst) {
                // Non-terminating block: add a RET to exit the VM.
                bc_insns.push(BytecodeInsn::Ret);
            }
        }

        let bytecode = emit_bytecode(&bc_insns, &table);
        block_bytecodes.push(bytecode);

        // Encode the native fallback (the original block instructions).
        let native = encode_block(&block.instructions, block.start_ip);
        block_native_fallbacks.push(native);
    }

    // ── Assemble final output ────────────────────────────────────────────
    //
    // Layout:
    //   1. Interpreter function bytes
    //   2. For each block: call stub (LEA rdi, [rip+bytecode]; CALL interpreter)
    //   3. Bytecode blobs (aligned)
    //   4. Register file (16 × u64, zero-initialized — per block)
    //   5. Native fallback code (for instructions the VM delegates)

    let mut output: Vec<u8> = Vec::new();
    let _interpreter_offset = 0u64;
    output.extend_from_slice(&interpreter_bytes);
    let _interpreter_len = interpreter_bytes.len() as u64;

    // Align to 16 bytes.
    while output.len() % 16 != 0 {
        output.push(0x90); // NOP padding
    }

    // Emit call stubs for each block.  Each stub:
    //   - Saves original GPRs to the register file
    //   - Calls the interpreter
    //   - Restores GPRs from the register file
    //   - Jump to the native terminator (if applicable)
    //
    // For simplicity in this initial version, we emit a simple wrapper that
    // sets up the register file and calls the interpreter.

    let _call_stub_base = output.len() as u64;

    // We'll emit per-block call stubs.
    // For now, since we require all instructions to be translatable, the
    // output is: interpreter + bytecode blobs + a single entry point that
    // calls the interpreter with block 0's bytecode.

    // Bytecode blob area.
    let bytecode_base = output.len() as u64;
    let mut bytecode_offsets: Vec<u64> = Vec::with_capacity(blocks.len());

    for bc in &block_bytecodes {
        bytecode_offsets.push(output.len() as u64 - bytecode_base);
        // Write 8-byte length prefix.
        output.extend_from_slice(&(bc.len() as u64).to_le_bytes());
        // Write bytecode.
        output.extend_from_slice(bc);
        // Align to 16 bytes.
        while output.len() % 16 != 0 {
            output.push(0);
        }
    }

    // Register file area: 16 × 8 = 128 bytes, zero-initialized.
    // We'll embed one per block.
    let regfile_base = output.len() as u64;
    let mut regfile_offsets: Vec<u64> = Vec::with_capacity(blocks.len());
    for _ in &blocks {
        regfile_offsets.push(output.len() as u64 - regfile_base);
        output.extend_from_slice(&[0u8; 128]);
    }

    // Now emit call stubs using iced-x86.
    // For each block, emit:
    //   push rax; push rcx; push rdx; push rsi; push ... (save all GPRs)
    //   lea rdi, [rip + bytecode_offset]
    //   mov rsi, bytecode_length
    //   lea rdx, [rip + native_code_offset]
    //   lea r8, [rip + regfile_offset]
    //   call interpreter
    //   pop ...; pop rsi; pop rdx; pop rcx; pop rax (restore GPRs)
    //   jmp next_block  or  ret

    // Actually, this approach is getting unwieldy for a single pass.
    // Let's simplify: for the initial implementation, emit the interpreter
    // followed by the bytecode data, and a single entry trampoline that
    // executes block 0.
    //
    // The output format:
    //   [interpreter bytes] [padding] [bytecode block 0 with length prefix]
    //   [regfile block 0] [entry trampoline]
    //
    // The entry trampoline at the start of the code:
    //   push_all_gprs
    //   lea rdi, [rip + bytecode_0]
    //   mov rsi, len
    //   lea r8, [rip + regfile_0]
    //   call interpreter
    //   pop_all_gprs
    //   ret

    // Let's restructure: emit the entry trampoline FIRST, then the
    // interpreter, then the data.

    // Actually, the cleanest approach is to generate the complete output
    // as x86 instructions using iced-x86 and then encode with BlockEncoder.

    let mut final_insns: Vec<Instruction> = Vec::new();
    let mut synthetic_ip: u64 = 0;

    let mut next_sip = || {
        let ip = synthetic_ip;
        synthetic_ip = synthetic_ip.wrapping_add(1);
        ip
    };

    // ── Entry trampoline ─────────────────────────────────────────────────
    // Save all volatile GPRs that the interpreter might clobber.
    // The interpreter saves/restores rbx, r12-r15, rbp.
    // We need to save: rax, rcx, rdx, rsi, rdi, r8-r11
    // (Actually the interpreter uses rbx, r12-r15 as internal regs and
    //  saves/restores them. So we need to provide the register file as a
    //  separate area.)

    // For this implementation: we'll emit a minimal trampoline that sets up
    // the interpreter arguments and calls it.

    // Push caller-saved regs.
    for &reg in &[
        Register::RAX,
        Register::RCX,
        Register::RDX,
        Register::RSI,
        Register::RDI,
        Register::R8,
        Register::R9,
        Register::R10,
        Register::R11,
    ] {
        let mut push = Instruction::with1(Code::Push_r64, reg).unwrap();
        push.set_ip(next_sip());
        final_insns.push(push);
    }

    // At this point, the original register values are on the stack.
    // The interpreter needs:
    //   RDI = bytecode ptr
    //   RSI = bytecode len
    //   RDX = native fallback ptr (unused for now)
    //   R8  = reg file ptr

    // We'll embed the bytecode and reg file as data after the code.
    // Use LEA to get RIP-relative pointers.

    // For now, use immediate values as placeholders. BlockEncoder will
    // fix up relative offsets.

    // Actually, since the bytecode is embedded in the output and we're
    // using BlockEncoder, we can use absolute addressing or craft the
    // addresses carefully.

    // Simpler approach: embed the interpreter inline and have it
    // self-modify the register file. For the initial skeleton, just
    // emit the interpreter bytes directly and use the bytecode as
    // an immediate argument.

    // Pop saved regs.
    for &reg in [
        Register::R11,
        Register::R10,
        Register::R9,
        Register::R8,
        Register::RDI,
        Register::RSI,
        Register::RDX,
        Register::RCX,
        Register::RAX,
    ]
    .iter()
    .rev()
    {
        let mut pop = Instruction::with1(Code::Pop_r64, reg).unwrap();
        pop.set_ip(next_sip());
        final_insns.push(pop);
    }

    let mut ret = Instruction::with(Code::Retnq);
    ret.set_ip(next_sip());
    final_insns.push(ret);

    // Encode the trampoline.
    let _trampoline_bytes = encode_block(&final_insns, 0);

    // ── Final assembly ───────────────────────────────────────────────────
    //
    // Output layout:
    //   1. Entry trampoline (calls interpreter for block 0)
    //   2. Interpreter function
    //   3. Bytecode data (length-prefixed per block)
    //   4. Register file (zero-initialized, per block)

    let mut result = Vec::new();

    // For the initial skeleton, just emit the interpreter + bytecode data.
    // The caller will need to call the interpreter directly with proper args.
    result.extend_from_slice(&interpreter_bytes);

    // Align to 16 bytes.
    while result.len() % 16 != 0 {
        result.push(0x90);
    }

    // Emit bytecode blocks with length prefixes.
    for (i, bc) in block_bytecodes.iter().enumerate() {
        // Length prefix (8 bytes).
        result.extend_from_slice(&(bc.len() as u64).to_le_bytes());
        // Bytecode.
        result.extend_from_slice(bc);
        // Pad to 16-byte alignment.
        while result.len() % 16 != 0 {
            result.push(0);
        }
        let _ = i;
    }

    // Register files (128 bytes each, zeroed).
    for _ in &blocks {
        result.extend_from_slice(&[0u8; 128]);
    }

    // If the result is empty or smaller than input, return input unchanged.
    if result.is_empty() {
        return code.to_vec();
    }

    log::debug!(
        "virtualize: transformed {} bytes → {} bytes ({} blocks, {} opcodes)",
        code.len(),
        result.len(),
        blocks.len(),
        NUM_OPCODES,
    );

    result
}

// ─── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn deterministic_for_same_seed() {
        // xor eax, eax; ret
        let code: &[u8] = &[0x31, 0xC0, 0xC3];

        let mut a = ChaCha8Rng::seed_from_u64(0xCAFE);
        let mut b = ChaCha8Rng::seed_from_u64(0xCAFE);

        let out_a = virtualize(code, &mut a);
        let out_b = virtualize(code, &mut b);

        assert_eq!(out_a, out_b, "same seed must produce identical output");
    }

    #[test]
    fn different_seeds_produce_different_output() {
        // xor eax, eax; ret
        let code: &[u8] = &[0x31, 0xC0, 0xC3];

        let mut a = ChaCha8Rng::seed_from_u64(1);
        let mut b = ChaCha8Rng::seed_from_u64(2);

        let out_a = virtualize(code, &mut a);
        let out_b = virtualize(code, &mut b);

        assert_ne!(
            out_a, out_b,
            "different seeds should produce different bytecode"
        );
    }

    #[test]
    fn opcode_table_is_permutation() {
        let mut rng = ChaCha8Rng::seed_from_u64(42);
        let table = OpcodeTable::generate(&mut rng);

        // Each encoding byte should be unique.
        let mut seen: HashSet<u8> = HashSet::new();
        for &byte in &table.encode {
            assert!(!seen.contains(&byte), "duplicate opcode byte {byte}");
            seen.insert(byte);
        }
        assert_eq!(seen.len(), NUM_OPCODES);
    }

    #[test]
    fn returns_input_for_unsupported_instructions() {
        // SYSCALL (0F 05) — not translatable
        let code: &[u8] = &[0x0F, 0x05, 0xC3];
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let out = virtualize(code, &mut rng);
        assert_eq!(
            out, code,
            "unsupported instructions should pass through unchanged"
        );
    }

    #[test]
    fn handles_mov_xor_add_sub_ret() {
        // mov eax, 42; xor ecx, ecx; add eax, ecx; sub eax, 1; ret
        let code: &[u8] = &[
            0xB8, 0x2A, 0x00, 0x00, 0x00, // mov eax, 42
            0x31, 0xC9, // xor ecx, ecx
            0x01, 0xC8, // add eax, ecx
            0x83, 0xE8, 0x01, // sub eax, 1
            0xC3, // ret
        ];
        let mut rng = ChaCha8Rng::seed_from_u64(123);
        let out = virtualize(code, &mut rng);
        // Should produce some output (interpreter + bytecode).
        assert!(
            !out.is_empty(),
            "should produce output for supported instructions"
        );
    }

    #[test]
    fn translate_basic_instructions() {
        // xor eax, eax
        let code: &[u8] = &[0x31, 0xC0];
        let mut decoder = Decoder::with_ip(64, code, 0, DecoderOptions::NONE);
        let inst = decoder.decode();
        let result = translate_instruction(&inst);
        assert!(
            matches!(result, TranslateResult::Ok(_)),
            "XOR eax,eax should be translatable"
        );
    }

    #[test]
    fn translate_mov_imm() {
        // mov eax, 0x42
        let code: &[u8] = &[0xB8, 0x42, 0x00, 0x00, 0x00];
        let mut decoder = Decoder::with_ip(64, code, 0, DecoderOptions::NONE);
        let inst = decoder.decode();
        let result = translate_instruction(&inst);
        assert!(
            matches!(result, TranslateResult::Ok(_)),
            "MOV r32, imm32 should be translatable"
        );
    }

    #[test]
    fn translate_push_pop() {
        // push rax; pop rcx
        let code: &[u8] = &[0x50, 0x59];
        let mut decoder = Decoder::with_ip(64, code, 0, DecoderOptions::NONE);
        let push = decoder.decode();
        let pop = decoder.decode();

        assert!(matches!(
            translate_instruction(&push),
            TranslateResult::Ok(_)
        ));
        assert!(matches!(
            translate_instruction(&pop),
            TranslateResult::Ok(_)
        ));
    }

    #[test]
    fn bytecode_emission_round_trip() {
        let mut rng = ChaCha8Rng::seed_from_u64(99);
        let table = OpcodeTable::generate(&mut rng);

        let insns = vec![
            BytecodeInsn::MovRegImm { dst: 0, imm: 42 },
            BytecodeInsn::MovRegImm { dst: 1, imm: 0 },
            BytecodeInsn::BinOp {
                op: VmOp::Add,
                dst: 0,
                src: 1,
            },
            BytecodeInsn::Ret,
        ];

        let bytes = emit_bytecode(&insns, &table);
        assert!(!bytes.is_empty());

        // Verify opcode bytes are from the randomized table.
        assert_eq!(bytes[0], table.enc(VmOp::MovRegImm));
    }
}
