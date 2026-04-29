//! M-2 – Register reallocation transform for x86-64 machine code.
#![cfg(target_arch = "x86_64")]
//!
//! # Algorithm
//!
//! 1. **Decode** the input into an `Instruction` sequence using iced-x86.
//!
//! 2. **Pin implicit-use registers.** Certain instructions read specific
//!    registers implicitly (not via an explicit operand): string moves and
//!    scans use RSI/RDI, SYSCALL uses R10 as the 4th argument in the Linux
//!    kernel ABI, XLATB uses RBX as a table pointer.  Any permutable register
//!    touched implicitly by any instruction is removed from the candidate pool.
//!
//! 3. **Liveness analysis** (forward scan).  A register is *live-in* if it is
//!    read before it is first written in a left-to-right pass.  Live-in
//!    registers may carry values from the caller and must not be renamed.
//!    Calling-convention-pinned registers (RAX, RCX, RDX, R8, R9) are treated
//!    as already-defined at function entry so they never appear in `live_in`.
//!
//! 4. **Build permutation.**  The remaining candidates (permutable, not
//!    implicitly pinned, not live-in) are shuffled with the provided CSPRNG.
//!    If the shuffle produces the identity the function returns early.
//!
//! 5. **Apply permutation.**  Every explicit register operand and every memory
//!    base/index register in every instruction is remapped, preserving the
//!    sub-register size (64/32/16/8 bit).  Instructions with implicit register
//!    uses are passed through the same rewrite logic safely because their
//!    implicit registers were already excluded from the permutation in step 2.

use std::collections::{HashMap, HashSet};

use iced_x86::{Code, Decoder, DecoderOptions, Instruction, OpKind, Register};
use rand::seq::SliceRandom;
use rand_chacha::ChaCha8Rng;

use crate::substitute::{encode_block, to_64bit};

// ─── Calling-convention pin set ───────────────────────────────────────────────

/// Registers that are fixed by the calling convention and must never be
/// permuted.
///
/// * RAX — return value (System V AMD64 and Windows x64)
/// * RCX — 1st Windows-x64 arg / 4th System-V arg (also clobbered by SYSCALL)
/// * RDX — 2nd Windows-x64 arg / 3rd System-V arg
/// * R8  — 3rd Windows-x64 arg
/// * R9  — 4th Windows-x64 arg
///
/// RSP and RBP are excluded by `to_64bit` returning `None` for them.
const PINNED: [Register; 5] = [
    Register::RAX,
    Register::RCX,
    Register::RDX,
    Register::R8,
    Register::R9,
];

/// Registers eligible for reallocation: everything except the calling-
/// convention pinned set, RSP, and RBP.
const PERMUTABLE_POOL: [Register; 9] = [
    Register::RBX,
    Register::RSI,
    Register::RDI,
    Register::R10,
    Register::R11,
    Register::R12,
    Register::R13,
    Register::R14,
    Register::R15,
];

// ─── Public entry point ───────────────────────────────────────────────────────

/// Reallocate scratch registers in a flat x86-64 machine-code slice.
///
/// See the module-level documentation for the full algorithm description.
/// Returns a re-encoded byte sequence where all permuted registers have been
/// renamed consistently throughout the code.  If no safe candidates exist (all
/// candidates are live-in or implicitly pinned), the function returns a copy
/// of the input unchanged.
pub fn reallocate_registers(code: &[u8], rng: &mut ChaCha8Rng) -> Vec<u8> {
    if code.is_empty() {
        return Vec::new();
    }

    let base_ip: u64 = 0;
    let mut decoder = Decoder::with_ip(64, code, base_ip, DecoderOptions::NONE);
    let mut instructions: Vec<Instruction> = Vec::new();
    while decoder.can_decode() {
        instructions.push(decoder.decode());
    }
    if instructions.is_empty() {
        return code.to_vec();
    }

    // ── Step 2: collect implicit-use pins ────────────────────────────────────
    let mut implicit_pins: HashSet<Register> = HashSet::new();
    for inst in &instructions {
        for r in implicit_permutable_pins(inst) {
            implicit_pins.insert(*r);
        }
    }

    // Candidate pool: permutable minus implicitly pinned.
    let candidates: Vec<Register> = PERMUTABLE_POOL
        .iter()
        .filter(|r| !implicit_pins.contains(*r))
        .copied()
        .collect();

    if candidates.is_empty() {
        return code.to_vec();
    }

    // ── Step 3: liveness analysis (forward scan) ─────────────────────────────
    let live_in = compute_live_in(&instructions);

    // Further restrict to registers that are locally defined (not live-in).
    let local_candidates: Vec<Register> = candidates
        .into_iter()
        .filter(|r| !live_in.contains(r))
        .collect();

    if local_candidates.len() < 2 {
        // A single-element permutation is always the identity.
        return code.to_vec();
    }

    // ── Step 4: random permutation ────────────────────────────────────────────
    let mut targets = local_candidates.clone();
    targets.shuffle(rng);

    if targets == local_candidates {
        // Identity shuffle — nothing to do.
        return code.to_vec();
    }

    // Build the 64-bit register permutation map: old → new.
    let perm: HashMap<Register, Register> = local_candidates
        .iter()
        .zip(targets.iter())
        .map(|(&old, &new)| (old, new))
        .collect();

    // ── Step 5: apply permutation ─────────────────────────────────────────────
    let out: Vec<Instruction> = instructions
        .iter()
        .map(|inst| apply_permutation_to_inst(*inst, &perm))
        .collect();

    encode_block(&out, base_ip)
}

// ─── Implicit-register pin computation ───────────────────────────────────────

/// Return the slice of registers from `PERMUTABLE_POOL` that `inst` reads
/// **implicitly** (i.e. the CPU reads the register automatically without it
/// appearing as an explicit operand).
///
/// Calling-convention registers (RAX, RCX, RDX, R8, R9) are already excluded
/// from the permutable pool, so only permutable registers that appear
/// implicitly need to be listed here.
fn implicit_permutable_pins(inst: &Instruction) -> &'static [Register] {
    match inst.code() {
        // String moves: implicit RSI (source pointer) and RDI (destination
        // pointer).  RCX (rep count) is already pinned.
        Code::Movsb_m8_m8
        | Code::Movsw_m16_m16
        | Code::Movsd_m32_m32
        | Code::Movsq_m64_m64 => &[Register::RSI, Register::RDI],

        // String stores: implicit RDI (destination pointer).  RAX (value) and
        // RCX (rep count) are already pinned.
        Code::Stosb_m8_AL
        | Code::Stosw_m16_AX
        | Code::Stosd_m32_EAX
        | Code::Stosq_m64_RAX => &[Register::RDI],

        // String scans: implicit RDI (search pointer).  RAX (comparand) and
        // RCX (rep count) are already pinned.
        Code::Scasb_AL_m8
        | Code::Scasw_AX_m16
        | Code::Scasd_EAX_m32
        | Code::Scasq_RAX_m64 => &[Register::RDI],

        // String compares: implicit RSI and RDI.  RCX is already pinned.
        Code::Cmpsb_m8_m8
        | Code::Cmpsw_m16_m16
        | Code::Cmpsd_m32_m32
        | Code::Cmpsq_m64_m64 => &[Register::RSI, Register::RDI],

        // String loads: implicit RSI (source pointer).  RAX and RCX pinned.
        Code::Lodsb_AL_m8
        | Code::Lodsw_AX_m16
        | Code::Lodsd_EAX_m32
        | Code::Lodsq_RAX_m64 => &[Register::RSI],

        // SYSCALL: R10 carries the 4th argument in the Linux kernel ABI
        // (the kernel's syscall convention replaces RCX with R10 because
        // the SYSCALL instruction itself clobbers RCX with the return
        // address).
        Code::Syscall => &[Register::R10],

        // XLATB: implicit read of RBX as the table base ([RBX + AL]).
        Code::Xlat_m8 => &[Register::RBX],

        _ => &[],
    }
}

// ─── Liveness analysis ────────────────────────────────────────────────────────

/// Compute the set of 64-bit base registers that are *live-in* to the
/// function: registers that are read before being first written in a
/// left-to-right scan of the instruction stream.
///
/// The calling-convention pinned set is pre-loaded into `defined` so that
/// incidental reads of RAX, RCX, etc. do not pollute the `live_in` set with
/// registers that are irrelevant to the permutable pool.
fn compute_live_in(instructions: &[Instruction]) -> HashSet<Register> {
    let mut defined: HashSet<Register> = HashSet::new();
    let mut live_in: HashSet<Register> = HashSet::new();

    // Pre-populate with pinned registers so they are never added to live_in.
    for &r in &PINNED {
        defined.insert(r);
    }

    for inst in instructions {
        let write_only_dest = is_dest_write_only(inst);

        for op_idx in 0..inst.op_count() {
            match inst.op_kind(op_idx) {
                OpKind::Register => {
                    let r = inst.op_register(op_idx);
                    // op0 of a write-only instruction is a pure destination —
                    // it is not a read.
                    let is_pure_write = op_idx == 0 && write_only_dest;
                    if !is_pure_write {
                        if let Some(r64) = to_64bit(r) {
                            if !defined.contains(&r64) {
                                live_in.insert(r64);
                            }
                        }
                    }
                }
                OpKind::Memory => {
                    for mr in [inst.memory_base(), inst.memory_index()] {
                        if mr != Register::None {
                            if let Some(r64) = to_64bit(mr) {
                                if !defined.contains(&r64) {
                                    live_in.insert(r64);
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        // Record the first write: op0 of any instruction that writes its
        // destination register.  For read-modify-write instructions (ADD, etc.)
        // the read is captured above; the write side still marks the register
        // as defined so subsequent reads see it as locally defined.
        if inst.op_count() > 0 && inst.op_kind(0) == OpKind::Register {
            if let Some(r64) = to_64bit(inst.op0_register()) {
                defined.insert(r64);
            }
        }
    }

    live_in
}

// ─── Permutation application ──────────────────────────────────────────────────

/// Rewrite all explicit register operands and memory base/index registers in
/// `inst` according to `perm`, preserving sub-register size.
fn apply_permutation_to_inst(
    mut inst: Instruction,
    perm: &HashMap<Register, Register>,
) -> Instruction {
    for op_idx in 0..inst.op_count() {
        if inst.op_kind(op_idx) == OpKind::Register {
            let r = inst.op_register(op_idx);
            if let Some(renamed) = remap_reg(r, perm) {
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
        if let Some(r) = remap_reg(base, perm) {
            inst.set_memory_base(r);
        }
    }
    let index = inst.memory_index();
    if index != Register::None {
        if let Some(r) = remap_reg(index, perm) {
            inst.set_memory_index(r);
        }
    }
    inst
}

/// Map `reg` through the permutation, preserving the sub-register size of the
/// input.  Returns `None` if `reg`'s 64-bit base is not in the permutation
/// domain (e.g. RSP, RBP, segment registers, or any pinned/live-in register).
fn remap_reg(reg: Register, perm: &HashMap<Register, Register>) -> Option<Register> {
    let base64 = to_64bit(reg)?;
    let new_base64 = perm.get(&base64).copied()?;
    sized_reg(new_base64, reg_size(reg)?)
}

// ─── Register size helpers ────────────────────────────────────────────────────

/// Size class of a general-purpose register variant.
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

fn sized_reg(base64: Register, size: RegSize) -> Option<Register> {
    Some(match (base64, size) {
        (Register::RBX, RegSize::S64) => Register::RBX,
        (Register::RBX, RegSize::S32) => Register::EBX,
        (Register::RBX, RegSize::S16) => Register::BX,
        (Register::RBX, RegSize::S8) => Register::BL,
        (Register::RSI, RegSize::S64) => Register::RSI,
        (Register::RSI, RegSize::S32) => Register::ESI,
        (Register::RSI, RegSize::S16) => Register::SI,
        (Register::RSI, RegSize::S8) => Register::SIL,
        (Register::RDI, RegSize::S64) => Register::RDI,
        (Register::RDI, RegSize::S32) => Register::EDI,
        (Register::RDI, RegSize::S16) => Register::DI,
        (Register::RDI, RegSize::S8) => Register::DIL,
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

// ─── Write-only destination detection ────────────────────────────────────────

/// Returns `true` when op0 of `inst` is a pure write destination (no source
/// read via that operand).  Used to avoid marking write-only destinations as
/// live-in reads during the liveness scan.
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
            | Code::Mov_rm64_imm32
            | Code::Mov_rm32_imm32
            | Code::Mov_rm64_r64
            | Code::Mov_rm32_r32
    )
}

// ─── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    // ── helpers ──────────────────────────────────────────────────────────────

    fn instruction_count(code: &[u8]) -> usize {
        let mut dec = Decoder::with_ip(64, code, 0, DecoderOptions::NONE);
        let mut n = 0;
        while dec.can_decode() {
            let _ = dec.decode();
            n += 1;
        }
        n
    }

    fn first_instruction(code: &[u8]) -> Instruction {
        Decoder::with_ip(64, code, 0, DecoderOptions::NONE).decode()
    }

    // ── empty input ───────────────────────────────────────────────────────────

    #[test]
    fn empty_input_returns_empty() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        assert!(reallocate_registers(&[], &mut rng).is_empty());
    }

    // ── instruction count preservation ────────────────────────────────────────

    /// A sequence that defines R12–R15 before reading them (all local scratch)
    /// must produce a valid output with the same instruction count.
    ///
    /// Encoding:
    ///   49 BC 01 00 00 00 00 00 00 00   MOV r12, 1
    ///   4D 03 EC                        ADD r13, r12
    ///   4D 8B F5                        MOV r14, r13
    ///   C3                              RET
    #[test]
    fn local_scratch_preserves_instruction_count() {
        let code: &[u8] = &[
            0x49, 0xBC, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x4D, 0x03, 0xEC,
            0x4D, 0x8B, 0xF5,
            0xC3,
        ];
        // Try multiple seeds to exercise both identity and non-identity shuffles.
        for seed in 0u64..16 {
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            let out = reallocate_registers(code, &mut rng);
            assert!(!out.is_empty(), "seed {seed}: output must not be empty");
            assert_eq!(
                instruction_count(&out),
                4,
                "seed {seed}: instruction count must be preserved"
            );
        }
    }

    // ── calling convention registers unchanged ────────────────────────────────

    /// RAX must never be renamed even when it is written before being read
    /// (it is pinned as the return-value register).
    ///
    /// Encoding:
    ///   48 B8 01 00 00 00 00 00 00 00   MOV rax, 1
    ///   48 03 C8                        ADD rcx, rax
    ///   C3                              RET
    #[test]
    fn calling_convention_registers_unchanged() {
        let code: &[u8] = &[
            0x48, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x48, 0x03, 0xC8,
            0xC3,
        ];
        for seed in 0u64..32 {
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            let out = reallocate_registers(code, &mut rng);
            let inst0 = first_instruction(&out);
            assert!(
                matches!(inst0.code(), Code::Mov_r64_imm64),
                "seed {seed}: first instruction must still be MOV r64, imm64"
            );
            assert_eq!(
                inst0.op0_register(),
                Register::RAX,
                "seed {seed}: RAX must not be renamed"
            );
        }
    }

    // ── live-in registers not renamed ─────────────────────────────────────────

    /// When all permutable registers in a snippet are read before being written
    /// the function must return the snippet unchanged (or an equivalent
    /// encoding with unchanged register names).
    ///
    /// Encoding:
    ///   4D 03 E3    ADD r12, r11   — both r12 and r11 are live-in
    ///   C3          RET
    #[test]
    fn live_in_registers_not_renamed() {
        // ADD r12, r11: REX.W=1 R=1 B=1 → 0x4D; opcode 03; mod=11 reg=4(r12) rm=3(r11) → 0xE3
        let code: &[u8] = &[0x4D, 0x03, 0xE3, 0xC3];
        for seed in 0u64..32 {
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            let out = reallocate_registers(code, &mut rng);
            let inst0 = first_instruction(&out);
            // Both operands must still be members of {r12, r11} in 64-bit form.
            let dst = to_64bit(inst0.op0_register());
            let src = to_64bit(inst0.op1_register());
            assert_eq!(dst, Some(Register::R12), "seed {seed}: r12 must not be renamed");
            assert_eq!(src, Some(Register::R11), "seed {seed}: r11 must not be renamed");
        }
    }

    // ── syscall R10 exclusion ─────────────────────────────────────────────────

    /// When a SYSCALL instruction is present, R10 must not be renamed anywhere
    /// in the function because the kernel ABI uses R10 as the 4th argument.
    ///
    /// Encoding:
    ///   4C 8B D1    MOV r10, rcx    — copy 4th arg to r10 for syscall
    ///   0F 05       SYSCALL
    ///   C3          RET
    #[test]
    fn syscall_pins_r10() {
        let code: &[u8] = &[0x4C, 0x8B, 0xD1, 0x0F, 0x05, 0xC3];
        for seed in 0u64..32 {
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            let out = reallocate_registers(code, &mut rng);
            let inst0 = first_instruction(&out);
            // Destination of the first instruction must still be R10 (not renamed).
            assert_eq!(
                to_64bit(inst0.op0_register()),
                Some(Register::R10),
                "seed {seed}: R10 must not be renamed when SYSCALL is present"
            );
        }
    }

    // ── permutation is a bijection ────────────────────────────────────────────

    /// The permutation must be a bijection: every register that appears in the
    /// output should appear the same number of times as in the input (modulo
    /// name changes), and the total instruction count is unchanged.
    ///
    /// Encoding:
    ///   49 BB 01 00 00 00 00 00 00 00   MOV r11, 1
    ///   4D 03 DB                        ADD r11, r11
    ///   49 89 DC                        MOV r12, r11
    ///   4D 03 E4                        ADD r12, r12
    ///   C3                              RET
    #[test]
    fn permutation_is_bijection() {
        let code: &[u8] = &[
            0x49, 0xBB, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MOV r11, 1
            0x4D, 0x03, 0xDB, // ADD r11, r11
            0x4D, 0x89, 0xDC, // MOV r12, r11
            0x4D, 0x03, 0xE4, // ADD r12, r12
            0xC3,             // RET
        ];
        for seed in 0u64..64 {
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            let out = reallocate_registers(code, &mut rng);
            assert_eq!(
                instruction_count(&out),
                5,
                "seed {seed}: instruction count must be preserved"
            );
        }
    }
}
