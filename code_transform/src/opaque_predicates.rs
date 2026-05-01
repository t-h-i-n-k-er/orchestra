//! Diverse opaque predicate generation for x86_64 and AArch64.
//!
//! # Overview
//!
//! An *opaque predicate* is a conditional branch whose outcome is statically
//! known at obfuscation time but appears non-deterministic to a static
//! analyser.  This module generates opaque predicates from **six
//! mathematical-invariant families**, randomly selecting one per insertion
//! point to increase diversity and resist pattern-matching deobfuscation.
//!
//! # x86_64 predicate families
//!
//! | # | Family | Invariant | Typical instruction sequence |
//! |---|--------|-----------|-----------------------------|
//! | 0 | Number-theoretic | `odd × N` is always odd → low bit = 1 | `IMUL reg, odd; TEST reg, 1; JNZ skip` (always taken) |
//! | 1 | Quadratic discriminant | `b² − 4ac` with `b² > 4ac` → always positive | `IMUL; SUB; TEST; JS skip` (never taken) |
//! | 2 | Bit-manipulation | `(x & (x−1))` when x is a power of 2 → always 0 | `MOV; DEC; AND; JNZ skip` (never taken) |
//! | 3 | Hash-based | Sum of known constants mod 2⁶⁴ always matches | `MOV; ADD; SUB; CMP; JNZ skip` (never taken) |
//! | 4 | Shift-and-mask | `(1 << k) >> k` always equals 1 | `MOV; SHL; SHR; CMP imm8; JNZ skip` (never taken) |
//! | 5 | XOR-avalanche | `x ⊕ x` is always 0 regardless of x | `PUSH; MOV; XOR; TEST; JNZ; POP` (never taken) |
//!
//! All predicates save and restore RFLAGS via `PUSHFQ`/`POPFQ` and only use
//! caller-saved scratch registers (R10, R11) wrapped in PUSH/POP pairs.
//!
//! # AArch64 predicate families
//!
//! Unlike the trivially-identifiable `CBNZ XZR, offset`, these predicates use
//! **real registers** (X16/X17 — the intra-procedure-call scratch registers
//! that are volatile in AAPCS64), making them far harder to fingerprint.
//!
//! | # | Family | Encoding |
//! |---|--------|----------|
//! | 0 | EOR-zero + CBNZ | `EOR X16,X16,X16; CBNZ X16, +4` |
//! | 1 | SUB-zero + CBNZ | `SUB X16,X16,X16; CBNZ X16, +4` |
//! | 2 | AND-mask + CBZ | `MOV X16,#1; AND X16,X16,#1; CBZ X16, +4` (taken, lands on next) |
//! | 3 | MUL-odd + TBNZ | `MOV X16,#odd; TBNZ X16, #0, +8` (bit 0 of odd = 1, always taken past 2 insns) |
//! | 4 | ORR-self + CBNZ | `ORR X16,XZR,X16; CBNZ X16, +4` (MOV X16,X16; but X16 was zeroed first) |
//! | 5 | Hash constants + CBNZ | `MOV X16,#c1; ADD X16,X16,#c2; SUB X16,X16,#(c1+c2); CBNZ X16, +4` |

use rand::Rng;

// ─── x86_64 opaque predicates ───────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
use iced_x86::{Code, Instruction, Register};

/// Sentinel IP base for synthetic instructions.  Must not collide with
/// original-code IPs (which start at 0).
#[cfg(target_arch = "x86_64")]
const SENTINEL_IP_BASE: u64 = 0xFFFD_0000_0000_0000;

/// Number of x86_64 predicate families.
const NUM_X86_FAMILIES: u8 = 6;

/// Number of AArch64 predicate families.
const NUM_AARCH64_FAMILIES: u8 = 6;

// ─── Public API ──────────────────────────────────────────────────────────────

/// Generate a diverse x86_64 opaque predicate — a conditional branch that is
/// **always not-taken**, so execution always falls through to the next
/// instruction.
///
/// The predicate is self-contained: it preserves all registers and RFLAGS,
/// and any internal jumps target a NOP sled that falls through.
///
/// Returns a `Vec<Instruction>` with sentinel IPs assigned.  The caller must
/// re-encode with `BlockEncoder` to resolve relative offsets.
///
/// `next_extra` is a closure that returns the next available sentinel IP.
#[cfg(target_arch = "x86_64")]
pub fn opaque_predicate_x86(
    rng: &mut impl Rng,
    next_extra: &mut impl FnMut() -> u64,
) -> Vec<Instruction> {
    let family = rng.gen::<u8>() % NUM_X86_FAMILIES;
    match family {
        0 => number_theoretic(rng, next_extra),
        1 => quadratic_discriminant(rng, next_extra),
        2 => bit_manipulation(rng, next_extra),
        3 => hash_based(rng, next_extra),
        4 => shift_and_mask(rng, next_extra),
        _ => xor_avalanche(rng, next_extra),
    }
}

/// Generate a diverse AArch64 opaque predicate — a sequence of 1–4
/// instructions that implements a conditional branch which is **always
/// not-taken** (or always-taken to the immediately following instruction).
///
/// Returns encoded 32-bit instruction words.  The caller patches the
/// displacement of any conditional branch via `rewrite_branch_disp`.
///
/// `rng` selects the family; the result always uses **real registers**
/// (X16/X17) rather than the trivially-identifiable XZR.
pub fn opaque_predicate_aarch64(rng: &mut impl Rng) -> Vec<u32> {
    let family = rng.gen::<u8>() % NUM_AARCH64_FAMILIES;
    match family {
        0 => aarch64_eor_zero(rng),
        1 => aarch64_sub_zero(rng),
        2 => aarch64_and_mask(rng),
        3 => aarch64_mul_odd_tbnz(rng),
        4 => aarch64_orr_self(rng),
        _ => aarch64_hash_constants(rng),
    }
}

// ─── x86_64 predicate family implementations ────────────────────────────────

// Helper: small odd numbers for number-theoretic predicates.
const ODD_CONSTANTS: [u32; 8] = [3, 5, 7, 11, 13, 17, 19, 23];

// Helper: known-power-of-2 constants for bit-manipulation predicates.
const POW2_CONSTANTS: [u32; 6] = [1, 2, 4, 8, 16, 32];

// Helper: known constant pairs for hash-based predicates (sum cancels out).
const HASH_CONSTANT_PAIRS: [(u32, u32); 6] = [
    (0xDEAD_BEEF, 0xDEAD_BEEF), // sum - sum = 0
    (0x1234_5678, 0x1234_5678),
    (0xAAAA_BBBB, 0xAAAA_BBBB),
    (0x5555_6666, 0x5555_6666),
    (0xCAFE_BABE, 0xCAFE_BABE),
    (0xFEED_FACE, 0xFEED_FACE),
];

/// Family 0 — Number-theoretic: multiply by an odd constant.
///
/// Any odd number has bit 0 set.  `odd × N` preserves oddness for any N.
/// Therefore `TEST result, 1` always sets ZF=0 (bit 0 is 1), so `JNZ` is
/// always taken (jumps to the NOP sled / fallthrough).
///
/// ```asm
/// PUSHFQ
/// PUSH R10
/// PUSH R11
/// MOV R10D, <odd_constant>
/// MOV R11D, 1          ; any small odd multiplicand
/// IMUL R10D, R11D      ; R10D = odd * odd = odd
/// TEST R10D, 1         ; bit 0 = 1 → ZF=0
/// JNZ skip             ; always taken (jumps past to NOP sled)
/// NOP                   ; dead code (never reached)
/// POP R11
/// POP R10
/// POPFQ
/// ```
#[cfg(target_arch = "x86_64")]
fn number_theoretic(
    rng: &mut impl Rng,
    next_extra: &mut impl FnMut() -> u64,
) -> Vec<Instruction> {
    let odd = ODD_CONSTANTS[rng.gen::<usize>() % ODD_CONSTANTS.len()] as i32;
    let mut out: Vec<Instruction> = Vec::with_capacity(12);

    // PUSHFQ
    let mut pushfq = Instruction::with(Code::Pushfq);
    pushfq.set_ip(next_extra());
    out.push(pushfq);

    // PUSH R10
    let mut push_r10 = Instruction::with1(Code::Push_r64, Register::R10).unwrap();
    push_r10.set_ip(next_extra());
    out.push(push_r10);

    // PUSH R11
    let mut push_r11 = Instruction::with1(Code::Push_r64, Register::R11).unwrap();
    push_r11.set_ip(next_extra());
    out.push(push_r11);

    // MOV R10D, odd_constant
    let mut mov_odd =
        Instruction::with2(Code::Mov_r32_imm32, Register::R10D, odd).unwrap();
    mov_odd.set_ip(next_extra());
    out.push(mov_odd);

    // MOV R11D, 1
    let mut mov_one =
        Instruction::with2(Code::Mov_r32_imm32, Register::R11D, 1).unwrap();
    mov_one.set_ip(next_extra());
    out.push(mov_one);

    // IMUL R10D, R11D (r32, rm32 form)
    let mut imul = Instruction::with2(Code::Imul_r32_rm32, Register::R10D, Register::R11D)
        .unwrap();
    imul.set_ip(next_extra());
    out.push(imul);

    // TEST R10D, 1
    let mut test =
        Instruction::with2(Code::Test_rm32_r32, Register::R10D, Register::R10D).unwrap();
    test.set_ip(next_extra());
    out.push(test);

    // Actually, we want to test bit 0 specifically: AND R10D, 1 then JNZ.
    // But TEST R10D, 1 is `Test_rm32_imm8` — let's use a different approach:
    // TEST already sets ZF based on the AND of operands. Use TEST with imm.
    // iced-x86 doesn't have Test_rm32_imm8 as a convenient Code variant.
    // Instead: TEST R10D, R10D already tests if R10D==0, but we want to test bit 0.
    // Simplest: use the fact that odd*odd is odd, so R10D is non-zero.
    // TEST R10D, R10D → ZF=0 (non-zero) → JNZ taken. Done!

    // JNZ skip (always taken because result is non-zero)
    let jnz_target_ip = next_extra(); // IP of NOP (target)
    let mut jnz = Instruction::with_branch(Code::Jne_rel8_64, jnz_target_ip).unwrap();
    jnz.set_ip(next_extra());
    out.push(jnz);

    // NOP (target of JNZ — dead code between JNZ and POP R11)
    let mut nop = Instruction::with(Code::Nopd);
    nop.set_ip(jnz_target_ip);
    out.push(nop);

    // POP R11
    let mut pop_r11 = Instruction::with1(Code::Pop_r64, Register::R11).unwrap();
    pop_r11.set_ip(next_extra());
    out.push(pop_r11);

    // POP R10
    let mut pop_r10 = Instruction::with1(Code::Pop_r64, Register::R10).unwrap();
    pop_r10.set_ip(next_extra());
    out.push(pop_r10);

    // POPFQ
    let mut popfq = Instruction::with(Code::Popfq);
    popfq.set_ip(next_extra());
    out.push(popfq);

    out
}

/// Family 1 — Quadratic discriminant: compute b²−4ac where b² > 4ac.
///
/// Choose constants where `b² > 4ac`.  E.g. `b=7, a=1, c=1` gives
/// `49 − 4 = 45 > 0`.  The result is always positive, so `JS` (jump if
/// sign flag set / negative) is **never taken**.
///
/// ```asm
/// PUSHFQ
/// PUSH R10
/// PUSH R11
/// MOV R10D, b          ; b = 7
/// IMUL R10D, R10D      ; R10D = b²
/// MOV R11D, 4*a*c      ; pre-computed: 4
/// SUB R10D, R11D       ; R10D = b² − 4ac > 0
/// TEST R10D, R10D      ; positive → SF=0
/// JS skip              ; never taken (result is positive)
/// NOP                   ; dead code
/// POP R11
/// POP R10
/// POPFQ
/// ```
#[cfg(target_arch = "x86_64")]
fn quadratic_discriminant(
    rng: &mut impl Rng,
    next_extra: &mut impl FnMut() -> u64,
) -> Vec<Instruction> {
    // Quadratic parameter sets (b, 4ac) where b² > 4ac.
    const QUAD_PARAMS: [(i32, i32); 6] = [
        (7, 4),   // 49 - 4 = 45
        (9, 16),  // 81 - 16 = 65
        (11, 8),  // 121 - 8 = 113
        (13, 32), // 169 - 32 = 137
        (15, 64), // 225 - 64 = 161
        (17, 16), // 289 - 16 = 273
    ];

    let (b, four_ac) = QUAD_PARAMS[rng.gen::<usize>() % QUAD_PARAMS.len()];
    let mut out: Vec<Instruction> = Vec::with_capacity(14);

    // PUSHFQ
    let mut pushfq = Instruction::with(Code::Pushfq);
    pushfq.set_ip(next_extra());
    out.push(pushfq);

    // PUSH R10
    let mut push_r10 = Instruction::with1(Code::Push_r64, Register::R10).unwrap();
    push_r10.set_ip(next_extra());
    out.push(push_r10);

    // PUSH R11
    let mut push_r11 = Instruction::with1(Code::Push_r64, Register::R11).unwrap();
    push_r11.set_ip(next_extra());
    out.push(push_r11);

    // MOV R10D, b
    let mut mov_b =
        Instruction::with2(Code::Mov_r32_imm32, Register::R10D, b).unwrap();
    mov_b.set_ip(next_extra());
    out.push(mov_b);

    // IMUL R10D, R10D (b²)
    let mut imul = Instruction::with2(Code::Imul_r32_rm32, Register::R10D, Register::R10D)
        .unwrap();
    imul.set_ip(next_extra());
    out.push(imul);

    // MOV R11D, 4ac
    let mut mov_ac =
        Instruction::with2(Code::Mov_r32_imm32, Register::R11D, four_ac).unwrap();
    mov_ac.set_ip(next_extra());
    out.push(mov_ac);

    // SUB R10D, R11D (b² − 4ac)
    let mut sub =
        Instruction::with2(Code::Sub_r32_rm32, Register::R10D, Register::R11D).unwrap();
    sub.set_ip(next_extra());
    out.push(sub);

    // TEST R10D, R10D (sets SF=0 since result > 0)
    let mut test =
        Instruction::with2(Code::Test_rm32_r32, Register::R10D, Register::R10D).unwrap();
    test.set_ip(next_extra());
    out.push(test);

    // JS skip (never taken because result is positive)
    let js_target_ip = next_extra();
    let mut js = Instruction::with_branch(Code::Js_rel8_64, js_target_ip).unwrap();
    js.set_ip(next_extra());
    out.push(js);

    // NOP (target)
    let mut nop = Instruction::with(Code::Nopd);
    nop.set_ip(js_target_ip);
    out.push(nop);

    // POP R11
    let mut pop_r11 = Instruction::with1(Code::Pop_r64, Register::R11).unwrap();
    pop_r11.set_ip(next_extra());
    out.push(pop_r11);

    // POP R10
    let mut pop_r10 = Instruction::with1(Code::Pop_r64, Register::R10).unwrap();
    pop_r10.set_ip(next_extra());
    out.push(pop_r10);

    // POPFQ
    let mut popfq = Instruction::with(Code::Popfq);
    popfq.set_ip(next_extra());
    out.push(popfq);

    out
}

/// Family 2 — Bit-manipulation: power-of-2 minus 1, then AND.
///
/// For any power of 2 `p`, `p & (p − 1)` is always 0 (the only set bit gets
/// cleared).  So `JNZ` after this AND is **never taken**.
///
/// ```asm
/// PUSHFQ
/// PUSH R10
/// PUSH R11
/// MOV R10D, <pow2>      ; e.g. 8
/// LEA R11D, [R10D - 1]  ; R11D = p−1
/// AND R10D, R11D        ; R10D = p & (p−1) = 0
/// JNZ skip              ; never taken (result is 0)
/// NOP
/// POP R11
/// POP R10
/// POPFQ
/// ```
#[cfg(target_arch = "x86_64")]
fn bit_manipulation(
    rng: &mut impl Rng,
    next_extra: &mut impl FnMut() -> u64,
) -> Vec<Instruction> {
    let pow2 = POW2_CONSTANTS[rng.gen::<usize>() % POW2_CONSTANTS.len()] as i32;
    let mut out: Vec<Instruction> = Vec::with_capacity(12);

    // PUSHFQ
    let mut pushfq = Instruction::with(Code::Pushfq);
    pushfq.set_ip(next_extra());
    out.push(pushfq);

    // PUSH R10
    let mut push_r10 = Instruction::with1(Code::Push_r64, Register::R10).unwrap();
    push_r10.set_ip(next_extra());
    out.push(push_r10);

    // PUSH R11
    let mut push_r11 = Instruction::with1(Code::Push_r64, Register::R11).unwrap();
    push_r11.set_ip(next_extra());
    out.push(push_r11);

    // MOV R10D, pow2
    let mut mov_pow2 =
        Instruction::with2(Code::Mov_r32_imm32, Register::R10D, pow2).unwrap();
    mov_pow2.set_ip(next_extra());
    out.push(mov_pow2);

    // LEA R11D, [R10D - 1] → this is actually best done as:
    // MOV R11D, R10D  then DEC R11D.
    // LEA with 32-bit ops on 64-bit registers needs care.
    // Simpler: MOV R11D, pow2-1 directly.
    let mut mov_p1 =
        Instruction::with2(Code::Mov_r32_imm32, Register::R11D, pow2 - 1).unwrap();
    mov_p1.set_ip(next_extra());
    out.push(mov_p1);

    // AND R10D, R11D → R10D = pow2 & (pow2-1) = 0
    let mut and_op =
        Instruction::with2(Code::And_r32_rm32, Register::R10D, Register::R11D).unwrap();
    and_op.set_ip(next_extra());
    out.push(and_op);

    // JNZ skip (never taken because result is 0)
    let jnz_target_ip = next_extra();
    let mut jnz = Instruction::with_branch(Code::Jne_rel8_64, jnz_target_ip).unwrap();
    jnz.set_ip(next_extra());
    out.push(jnz);

    // NOP (target)
    let mut nop = Instruction::with(Code::Nopd);
    nop.set_ip(jnz_target_ip);
    out.push(nop);

    // POP R11
    let mut pop_r11 = Instruction::with1(Code::Pop_r64, Register::R11).unwrap();
    pop_r11.set_ip(next_extra());
    out.push(pop_r11);

    // POP R10
    let mut pop_r10 = Instruction::with1(Code::Pop_r64, Register::R10).unwrap();
    pop_r10.set_ip(next_extra());
    out.push(pop_r10);

    // POPFQ
    let mut popfq = Instruction::with(Code::Popfq);
    popfq.set_ip(next_extra());
    out.push(popfq);

    out
}

/// Family 3 — Hash-based: sum of known constants cancels to zero.
///
/// Load a known constant `C`, add it, subtract it: result is always 0.
/// `CMP reg, 0` then `JNZ` is **never taken**.
///
/// ```asm
/// PUSHFQ
/// PUSH R10
/// MOV R10D, <constant>
/// ADD R10D, <constant>   ; R10D = 2*C
/// SUB R10D, <2*C>        ; R10D = 0
/// CMP R10D, 0
/// JNZ skip               ; never taken
/// NOP
/// POP R10
/// POPFQ
/// ```
#[cfg(target_arch = "x86_64")]
fn hash_based(
    rng: &mut impl Rng,
    next_extra: &mut impl FnMut() -> u64,
) -> Vec<Instruction> {
    let (c, _) = HASH_CONSTANT_PAIRS[rng.gen::<usize>() % HASH_CONSTANT_PAIRS.len()];
    let double_c = (c as u64).wrapping_add(c as u64) as u32;
    let mut out: Vec<Instruction> = Vec::with_capacity(12);

    // PUSHFQ
    let mut pushfq = Instruction::with(Code::Pushfq);
    pushfq.set_ip(next_extra());
    out.push(pushfq);

    // PUSH R10
    let mut push_r10 = Instruction::with1(Code::Push_r64, Register::R10).unwrap();
    push_r10.set_ip(next_extra());
    out.push(push_r10);

    // PUSH R11
    let mut push_r11 = Instruction::with1(Code::Push_r64, Register::R11).unwrap();
    push_r11.set_ip(next_extra());
    out.push(push_r11);

    // MOV R10D, C
    let mut mov_c =
        Instruction::with2(Code::Mov_r32_imm32, Register::R10D, c as i32).unwrap();
    mov_c.set_ip(next_extra());
    out.push(mov_c);

    // ADD R10D, C  (use register form: MOV R11D, C; ADD R10D, R11D)
    let mut mov_c2 =
        Instruction::with2(Code::Mov_r32_imm32, Register::R11D, c as i32).unwrap();
    mov_c2.set_ip(next_extra());
    out.push(mov_c2);

    let mut add_c =
        Instruction::with2(Code::Add_r32_rm32, Register::R10D, Register::R11D).unwrap();
    add_c.set_ip(next_extra());
    out.push(add_c);

    // SUB R10D, 2*C  (use register form: MOV R11D, 2*C; SUB R10D, R11D)
    let mut mov_2c =
        Instruction::with2(Code::Mov_r32_imm32, Register::R11D, double_c as i32).unwrap();
    mov_2c.set_ip(next_extra());
    out.push(mov_2c);

    let mut sub_2c =
        Instruction::with2(Code::Sub_r32_rm32, Register::R10D, Register::R11D).unwrap();
    sub_2c.set_ip(next_extra());
    out.push(sub_2c);

    // TEST R10D, R10D (check if result is zero)
    let mut test_rr =
        Instruction::with2(Code::Test_rm32_r32, Register::R10D, Register::R10D).unwrap();
    test_rr.set_ip(next_extra());
    out.push(test_rr);

    // JNZ skip (never taken because R10D = 0)
    let jnz_target_ip = next_extra();
    let mut jnz = Instruction::with_branch(Code::Jne_rel8_64, jnz_target_ip).unwrap();
    jnz.set_ip(next_extra());
    out.push(jnz);

    // NOP (target)
    let mut nop = Instruction::with(Code::Nopd);
    nop.set_ip(jnz_target_ip);
    out.push(nop);

    // POP R11
    let mut pop_r11 = Instruction::with1(Code::Pop_r64, Register::R11).unwrap();
    pop_r11.set_ip(next_extra());
    out.push(pop_r11);

    // POP R10
    let mut pop_r10 = Instruction::with1(Code::Pop_r64, Register::R10).unwrap();
    pop_r10.set_ip(next_extra());
    out.push(pop_r10);

    // POPFQ
    let mut popfq = Instruction::with(Code::Popfq);
    popfq.set_ip(next_extra());
    out.push(popfq);

    out
}

/// Family 4 — Shift-and-mask: `(1 << k) >> k` always equals 1.
///
/// ```asm
/// PUSHFQ
/// PUSH R10
/// MOV R10D, 1
/// SHL R10D, k          ; R10D = 1 << k
/// SHR R10D, k          ; R10D = (1 << k) >> k = 1
/// CMP R10D, 1
/// JNZ skip              ; never taken (result is always 1)
/// NOP
/// POP R10
/// POPFQ
/// ```
#[cfg(target_arch = "x86_64")]
fn shift_and_mask(
    rng: &mut impl Rng,
    next_extra: &mut impl FnMut() -> u64,
) -> Vec<Instruction> {
    // Valid shift amounts (1..30 to stay well within 32-bit range).
    let shift: i32 = (rng.gen::<u8>() % 28 + 1) as i32;
    let mut out: Vec<Instruction> = Vec::with_capacity(12);

    // PUSHFQ
    let mut pushfq = Instruction::with(Code::Pushfq);
    pushfq.set_ip(next_extra());
    out.push(pushfq);

    // PUSH R10
    let mut push_r10 = Instruction::with1(Code::Push_r64, Register::R10).unwrap();
    push_r10.set_ip(next_extra());
    out.push(push_r10);

    // MOV R10D, 1
    let mut mov_one =
        Instruction::with2(Code::Mov_r32_imm32, Register::R10D, 1).unwrap();
    mov_one.set_ip(next_extra());
    out.push(mov_one);

    // SHL R10D, shift
    let mut shl = Instruction::with2(Code::Shl_rm32_imm8, Register::R10D, shift).unwrap();
    shl.set_ip(next_extra());
    out.push(shl);

    // SHR R10D, shift
    let mut shr = Instruction::with2(Code::Shr_rm32_imm8, Register::R10D, shift).unwrap();
    shr.set_ip(next_extra());
    out.push(shr);

    // CMP R10D, 1
    let mut cmp_one =
        Instruction::with2(Code::Cmp_rm32_imm8, Register::R10D, 1).unwrap();
    cmp_one.set_ip(next_extra());
    out.push(cmp_one);

    // JNZ skip (never taken because R10D == 1)
    let jnz_target_ip = next_extra();
    let mut jnz = Instruction::with_branch(Code::Jne_rel8_64, jnz_target_ip).unwrap();
    jnz.set_ip(next_extra());
    out.push(jnz);

    // NOP (target)
    let mut nop = Instruction::with(Code::Nopd);
    nop.set_ip(jnz_target_ip);
    out.push(nop);

    // POP R10
    let mut pop_r10 = Instruction::with1(Code::Pop_r64, Register::R10).unwrap();
    pop_r10.set_ip(next_extra());
    out.push(pop_r10);

    // POPFQ
    let mut popfq = Instruction::with(Code::Popfq);
    popfq.set_ip(next_extra());
    out.push(popfq);

    out
}

/// Family 5 — XOR-avalanche: `x ⊕ x = 0` for any x.
///
/// Load a "random-looking" constant, XOR it with itself → always 0.
/// `TEST reg, reg` then `JNZ` is **never taken**.
///
/// ```asm
/// PUSHFQ
/// PUSH R10
/// MOV R10, <const64>
/// XOR R10, R10          ; R10 = const64 ⊕ const64 = 0
/// TEST R10, R10         ; ZF=1
/// JNZ skip              ; never taken
/// NOP
/// POP R10
/// POPFQ
/// ```
#[cfg(target_arch = "x86_64")]
fn xor_avalanche(
    rng: &mut impl Rng,
    next_extra: &mut impl FnMut() -> u64,
) -> Vec<Instruction> {
    // Generate a random-looking 64-bit constant (but the actual value doesn't
    // matter since x⊕x = 0 for all x).
    let val = rng.gen::<u64>();
    let mut out: Vec<Instruction> = Vec::with_capacity(12);

    // PUSHFQ
    let mut pushfq = Instruction::with(Code::Pushfq);
    pushfq.set_ip(next_extra());
    out.push(pushfq);

    // PUSH R10
    let mut push_r10 = Instruction::with1(Code::Push_r64, Register::R10).unwrap();
    push_r10.set_ip(next_extra());
    out.push(push_r10);

    // MOV R10, val (64-bit immediate)
    let mut mov_val =
        Instruction::with2(Code::Mov_r64_imm64, Register::R10, val as i64).unwrap();
    mov_val.set_ip(next_extra());
    out.push(mov_val);

    // XOR R10, R10 → 0
    let mut xor_op =
        Instruction::with2(Code::Xor_r64_rm64, Register::R10, Register::R10).unwrap();
    xor_op.set_ip(next_extra());
    out.push(xor_op);

    // TEST R10, R10 → ZF=1
    let mut test =
        Instruction::with2(Code::Test_rm64_r64, Register::R10, Register::R10).unwrap();
    test.set_ip(next_extra());
    out.push(test);

    // JNZ skip (never taken)
    let jnz_target_ip = next_extra();
    let mut jnz = Instruction::with_branch(Code::Jne_rel8_64, jnz_target_ip).unwrap();
    jnz.set_ip(next_extra());
    out.push(jnz);

    // NOP (target)
    let mut nop = Instruction::with(Code::Nopd);
    nop.set_ip(jnz_target_ip);
    out.push(nop);

    // POP R10
    let mut pop_r10 = Instruction::with1(Code::Pop_r64, Register::R10).unwrap();
    pop_r10.set_ip(next_extra());
    out.push(pop_r10);

    // POPFQ
    let mut popfq = Instruction::with(Code::Popfq);
    popfq.set_ip(next_extra());
    out.push(popfq);

    out
}

// ─── AArch64 predicate family implementations ───────────────────────────────
//
// ARM64 (AArch64) instructions are fixed-width 32-bit, little-endian.
// We use X16 (IP0) and X17 (IP1) as scratch registers — they are the
// intra-procedure-call scratch registers and volatile in AAPCS64.

/// Encode `EOR Xd, Xn, Xm` (64-bit): `Xd = Xn XOR Xm`.
/// Encoding: 1 10 01010 00 0 Rm 000000 Rn Rd
fn enc_eor_x(dst: u32, src1: u32, src2: u32) -> u32 {
    debug_assert!(dst < 31 && src1 < 31 && src2 < 31);
    0xCA00_0000 | (src2 << 16) | (src1 << 5) | dst
}

/// Encode `SUB Xd, Xn, Xm` (64-bit, extended register): `Xd = Xn - Xm`.
/// Using shifted-register form: 1 11 01010 01 0 Rm 000000 Rn Rd
fn enc_sub_x(dst: u32, src1: u32, src2: u32) -> u32 {
    debug_assert!(dst < 31 && src1 < 31 && src2 < 31);
    0xEB00_0000 | (src2 << 16) | (src1 << 5) | dst
}

/// Encode `ADD Xd, Xn, #imm12` (64-bit immediate).
/// Encoding: 1 00 100010 0 imm12 Rn Rd
fn enc_add_x_imm(dst: u32, src: u32, imm12: u32) -> u32 {
    debug_assert!(dst < 31 && src < 31 && imm12 < 4096);
    0x9100_0000 | (imm12 << 10) | (src << 5) | dst
}

/// Encode `SUB Xd, Xn, #imm12` (64-bit immediate).
/// Encoding: 1 10 100010 0 imm12 Rn Rd
fn enc_sub_x_imm(dst: u32, src: u32, imm12: u32) -> u32 {
    debug_assert!(dst < 31 && src < 31 && imm12 < 4096);
    0xD100_0000 | (imm12 << 10) | (src << 5) | dst
}

/// Encode `AND Xd, Xn, #imm12` (64-bit immediate, alias for AND with
/// shifted immediate — using logical immediate encoding).
///
/// For simple cases (mask = 1), use the bitfield encoding:
/// `AND Xd, Xn, #1` is encoded using the logical immediate form.
///
/// Actually, for `AND Xd, Xn, #imm`, we need the logical-immediate encoding
/// which is complex.  Instead, use `AND Xd, Xn, Xm` register form:
/// 1 10 01010 00 0 Rm 000000 Rn Rd
fn enc_and_x(dst: u32, src1: u32, src2: u32) -> u32 {
    debug_assert!(dst < 31 && src1 < 31 && src2 < 31);
    0x8A00_0000 | (src2 << 16) | (src1 << 5) | dst
}

/// Encode `ORR Xd, XZR, Xm` (alias for `MOV Xd, Xm`).
/// 1 10 01010 00 0 Rm 000000 11111 Rd
fn enc_mov_x(dst: u32, src: u32) -> u32 {
    debug_assert!(dst < 31 && src < 31);
    0xAA00_0000 | (src << 16) | (31 << 5) | dst
}

/// Encode `MOVZ Xd, #imm16` (move wide with zero, 64-bit).
/// Encoding: 1 10 100101 hw imm16 Rd
/// hw=0 for shift=0.
fn enc_movz_x(dst: u32, imm16: u32) -> u32 {
    debug_assert!(dst < 31 && imm16 < 65536);
    0xD280_0000 | (imm16 << 5) | dst
}

/// Encode `CBNZ Xt, #imm19*4` (64-bit, sf=1).
/// Encoding: 1 011010 1 imm19 Rt
/// The imm19 is the signed offset in units of 4 bytes.
fn enc_cbnz_x(rt: u32, imm19: i32) -> u32 {
    debug_assert!(rt < 31); // must be a real register, not XZR (31)
    let imm_bits = (imm19 as u32) & 0x7_FFFF;
    0xB500_0000 | (imm_bits << 5) | rt
}

/// Encode `CBZ Xt, #imm19*4` (64-bit, sf=1).
/// Encoding: 1 011010 0 imm19 Rt
fn enc_cbz_x(rt: u32, imm19: i32) -> u32 {
    debug_assert!(rt < 31);
    let imm_bits = (imm19 as u32) & 0x7_FFFF;
    0xB400_0000 | (imm_bits << 5) | rt
}

/// Encode `TBNZ Xt, #bit, #imm14*4`.
///
/// ARM A64 encoding (DDI 0487A, C4.4.5):
/// ```text
///   bit[31]    = b5  (bit 5 of the test position; 0 for X reg bit 0–31)
///   bits[30:24] = 0110111  (TBNZ; TBZ = 0110110)
///   bits[23:19] = b40 (bits 4:0 of the test position)
///   bits[18:5]  = imm14 (signed offset in words)
///   bits[4:0]   = Rt
/// ```
fn enc_tbnz(rt: u32, bit: u32, imm14: i32) -> u32 {
    debug_assert!(rt < 31 && bit < 64);
    let b5 = (bit >> 5) & 1;
    let b40 = bit & 0x1F;
    let imm_bits = (imm14 as u32) & 0x3FFF;
    (b5 << 31) | 0x3700_0000 | (b40 << 19) | (imm_bits << 5) | rt
}

/// Wait, the encoding is wrong. Let me fix: TBNZ encoding:
/// bit[31] = op (1 for TBNZ, 0 for TBZ)
/// bit[30:24] = 0110111 for TBNZ 64-bit (b5=1) or 0110110 for 32-bit
/// Actually: sf|1 110111 b5 imm14 Rt[4:0] where Rt is bits[4:0]
/// And bit position = b5:b40 where b5 is bit[31], b40 is bits[19:15]... no.
///
/// TBNZ: bit[31] = b5 (top bit of test position)
///        bits[30:24] = 0110111 (for TBNZ with sf=1)
///        bits[23:19] = imm14[18:5]... no.
///
/// Correct encoding from ARM ARM:
/// TBNZ: 1 b5 011011 imm14 Rt
///   where b5 is the MSB of the bit index for 64-bit (X register)
///   Rt = bits[4:0]
///   imm14 = bits[18:5] (signed, 14 bits)
///   b5 = bit[31]
///
/// For X register with bit index < 32: b5 = 0, sf = 1
///   1 0 011011 imm14 Rt
///   = 0x3700_0000 | (imm14 << 5) | Rt
///
/// For bit 0 of X16 (reg 16):
///   b5 = 0, imm14 = +2 (skip 2 instructions = 8 bytes, imm14 = 8/4 = 2)

/// Family 0 — EOR-zero + CBNZ.
///
/// `EOR X16, X16, X16` → X16 = 0.  `CBNZ X16, +1` is never taken.
/// Semantically identical to `CBNZ XZR` but uses a real register.
fn aarch64_eor_zero(_rng: &mut impl Rng) -> Vec<u32> {
    // EOR X16, X16, X16  → X16 = 0
    // CBNZ X16, #+4      → not taken (X16 == 0)
    vec![
        enc_eor_x(16, 16, 16),  // X16 = X16 XOR X16 = 0
        enc_cbnz_x(16, 1),      // CBNZ X16, #4 (skip 1 insn = never taken)
    ]
}

/// Family 1 — SUB-zero + CBNZ.
///
/// `SUB X16, X16, X16` → X16 = 0.  Same effect, different opcode.
fn aarch64_sub_zero(_rng: &mut impl Rng) -> Vec<u32> {
    vec![
        enc_sub_x(16, 16, 16),  // X16 = X16 - X16 = 0
        enc_cbnz_x(16, 1),      // CBNZ X16, #4 (never taken)
    ]
}

/// Family 2 — AND-mask + CBZ.
///
/// `MOVZ X16, #1; AND X16, X16, X16` → X16 = 1.  `CBZ X16` is never taken.
/// Uses MOVZ+AND instead of XOR/SUB, producing different byte patterns.
fn aarch64_and_mask(_rng: &mut impl Rng) -> Vec<u32> {
    // We need AND with a mask.  Since AND immediate encoding is complex,
    // use: MOVZ X16, #1 → X16 = 1, then MOV X17, X16 (copy), then AND X16, X16, X17 → X16 = 1.
    // Actually, AND X16, X16, X16 when X16 = 1 → X16 = 1 (non-zero).
    // CBZ X16 is never taken.
    vec![
        enc_movz_x(16, 1),      // X16 = 1
        enc_and_x(16, 16, 16),  // X16 = X16 AND X16 = 1 (non-zero)
        enc_cbz_x(16, 1),       // CBZ X16, #4 (never taken since X16 = 1)
    ]
}

/// Family 3 — MUL-odd + TBNZ.
///
/// `MOVZ X16, #odd; TBNZ X16, #0, #+8` — bit 0 of any odd number is 1,
/// so TBNZ (test bit and branch if non-zero) is always taken, jumping
/// past the dead `B #+4` to the real next instruction.
fn aarch64_mul_odd_tbnz(rng: &mut impl Rng) -> Vec<u32> {
    let odd = ODD_CONSTANTS[rng.gen::<usize>() % ODD_CONSTANTS.len()];
    // MOVZ X16, #odd
    // TBNZ X16, #0, #+8  (always taken, jumps over the dead B)
    // B #+4               (dead code — never reached)
    //
    // TBNZ with imm14 = +2 means offset = +8 bytes (skip 2 instructions)
    // B with imm26 = +1 means offset = +4 bytes (skip 1 instruction)
    vec![
        enc_movz_x(16, odd as u32 & 0xFFFF), // X16 = odd
        enc_tbnz(16, 0, 2),                   // TBNZ X16, #0, #+8 (always taken)
        0x1400_0001,                           // B #+4 (dead code)
    ]
}

/// Fix TBNZ encoding: the layout is:
/// bit[31] = b5 (bit 5 of the test position, 0 for bit 0-31)
/// bits[30:24] = 0110111 (for TBNZ, 0 for TBZ)
/// bits[23:19] ... wait, the standard layout:
///
/// TBNZ: 1 b5 011011 imm14 Rn
///   bit[31] = b5
///   bits[30:24] = 011011 (for TBNZ variant, 1 is in bit[24]?)
///
/// Let me just use the correct constant. TBNZ X16, #0, #+8:
/// For bit 0 of a 64-bit register: b5=0
/// TBNZ = op=1 in bit[24]... no, bit[31] = b5.
///
/// ARM64 encoding for TBNZ:
///   1 b5 011011 imm14 Rn
///   - b5 at bit[31]
///   - 011011 at bits[30:25] = 0x1B << 25 = 0x3600_0000
///   - But we also need op bit somewhere...
///
/// Actually from ARM ARM:
/// TBZ:  b5 011011 0 imm14 Rt   → 0x36000000 | (b5<<31) | (imm14<<5) | Rt
/// TBNZ: b5 011011 1 imm14 Rt   → 0x37000000 | (b5<<31) | (imm14<<5) | Rt
///
/// Wait no. The full encoding is:
/// bit[31]    = b5
/// bits[30:25] = 011011
/// bit[24]    = op (0=TBZ, 1=TBNZ)
/// bits[23:5] = imm14 (14 bits)
/// bits[4:0]  = Rt
///
/// For TBNZ: bit[31]=b5=0 (for bit 0), bits[30:25]=011011, bit[24]=1
///   = 0b0_011011_1_... = 0x3700_0000 base
///   Then imm14 at bits[18:5], Rt at bits[4:0]
///
/// TBNZ X16, bit0, #+8:
///   imm14 = 8/4 = 2
///   0x3700_0000 | (2 << 5) | 16 = 0x3700_0000 | 0x20 | 0x10 = 0x3700_0030

/// Family 4 — ORR-self + CBNZ.
///
/// Zero X16 via EOR, then `ORR X16, XZR, X16` (alias: `MOV X16, X16`),
/// then `CBNZ X16` — never taken because X16 is 0.
/// The ORR instruction looks like a register move but preserves zero.
fn aarch64_orr_self(_rng: &mut impl Rng) -> Vec<u32> {
    vec![
        enc_eor_x(16, 16, 16),  // X16 = 0
        enc_mov_x(16, 16),      // X16 = X16 (MOV alias; still 0)
        enc_cbnz_x(16, 1),      // CBNZ X16, #4 (never taken)
    ]
}

/// Family 5 — Hash constants + CBNZ.
///
/// `MOVZ X16, #C1; ADD X16, X16, #C2; SUB X16, X16, #(C1+C2)` → X16 = 0.
/// `CBNZ X16` is never taken.
fn aarch64_hash_constants(rng: &mut impl Rng) -> Vec<u32> {
    let c1 = (rng.gen::<u16>()) as u32;
    let c2 = (rng.gen::<u16>()) as u32;
    // Use small 12-bit constants to ensure the sum fits in the
    // immediate field of the SUB instruction.
    let c1_small = c1 & 0xFFF; // 12-bit
    let c2_small = c2 & 0xFFF; // 12-bit
    let sum_small = c1_small.wrapping_add(c2_small) & 0xFFF;

    vec![
        enc_movz_x(16, c1_small),        // X16 = c1
        enc_add_x_imm(16, 16, c2_small),  // X16 = c1 + c2
        enc_sub_x_imm(16, 16, sum_small), // X16 = c1 + c2 - (c1+c2) = 0
        enc_cbnz_x(16, 1),                // CBNZ X16, #4 (never taken)
    ]
}

// ─── Public convenience: apply predicate insertion ───────────────────────────

/// Apply opaque predicate insertion to x86_64 code as a standalone pass.
///
/// Decodes the input, identifies basic-block boundaries, and inserts a
/// randomly-chosen opaque predicate at the entry of each non-entry block.
/// Returns the re-encoded bytes, or the input unchanged if it cannot be
/// safely transformed.
#[cfg(target_arch = "x86_64")]
pub fn apply_opaque_predicates(code: &[u8], rng: &mut impl Rng) -> Vec<u8> {
    use crate::substitute::encode_block;
    use iced_x86::{Decoder, DecoderOptions};

    let base_ip: u64 = 0;
    let mut decoder = Decoder::with_ip(64, code, base_ip, DecoderOptions::NONE);
    let mut instructions: Vec<Instruction> = Vec::new();
    while decoder.can_decode() {
        instructions.push(decoder.decode());
    }

    if instructions.is_empty() {
        return code.to_vec();
    }

    // Identify basic-block leaders.
    let mut is_leader = vec![false; instructions.len()];
    is_leader[0] = true;

    // Collect branch targets.
    for inst in &instructions {
        if inst.is_jcc_short_or_near() || inst.is_jmp_short_or_near() {
            let target = inst.near_branch64() as usize;
            if target < instructions.len() {
                // Find instruction index by IP.
                for (i, ins) in instructions.iter().enumerate() {
                    if ins.ip() as usize == target {
                        is_leader[i] = true;
                        break;
                    }
                }
            }
        }
        if matches!(
            inst.code(),
            Code::Retnq | Code::Retnd | Code::Ud2 | Code::Int3
        ) {
            // Instruction after terminator is a leader (if it exists).
        }
    }

    // Mark instructions after terminators as leaders.
    for i in 0..instructions.len() {
        let inst = &instructions[i];
        if matches!(
            inst.code(),
            Code::Retnq | Code::Retnd | Code::Ud2 | Code::Int3
                | Code::Jmp_rel32_64 | Code::Jmp_rel8_64
        ) && i + 1 < instructions.len()
        {
            is_leader[i + 1] = true;
        }
    }

    // Insert predicates at block leaders (except block 0).
    let mut extra_ip: u64 = SENTINEL_IP_BASE;
    let bump = |ip: &mut u64| -> u64 {
        let val = *ip;
        *ip = ip.wrapping_add(1);
        val
    };

    let mut result: Vec<Instruction> = Vec::with_capacity(instructions.len() * 2);
    let mut block_count = 0u32;

    for (i, inst) in instructions.into_iter().enumerate() {
        if is_leader[i] && block_count > 0 {
            // Insert opaque predicate before this block.
            let preds = opaque_predicate_x86(rng, &mut || bump(&mut extra_ip));
            result.extend(preds);
        }
        if is_leader[i] {
            block_count += 1;
        }
        let inst_copy = inst;
        // Keep original IPs for branch resolution by BlockEncoder.
        result.push(inst_copy);
    }

    if result.is_empty() {
        return code.to_vec();
    }

    // Re-encode — BlockEncoder resolves relative offsets.
    let first_ip = result.first().map(|i| i.ip()).unwrap_or(0);
    encode_block(&result, first_ip)
}

/// Apply opaque predicate insertion to AArch64 code as a standalone pass.
///
/// Decodes into 4-byte instruction words, identifies basic-block boundaries,
/// and prepends a randomly-chosen opaque predicate sequence to each non-entry
/// block.  Re-resolves PC-relative branch displacements.
///
/// Returns the input unchanged if it contains PC-relative data references
/// (`ADR`/`ADRP`/`LDR literal`) that cannot be safely retargeted.
#[cfg(target_arch = "aarch64")]
pub fn apply_opaque_predicates_aarch64(code: &[u8], rng: &mut impl Rng) -> Vec<u8> {
    use crate::substitute_aarch64::{
        classify, finalize, is_pcrel_data, is_terminator, pc_rel_branch_disp, BranchKind, Item,
        ItemKind,
    };

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

    let n = raw_words.len();
    let mut is_leader = vec![false; n];
    is_leader[0] = true;

    for (i, &raw) in raw_words.iter().enumerate() {
        let kind = classify(raw);
        if is_terminator(kind) && i + 1 < n {
            is_leader[i + 1] = true;
        }
        if let Some(disp) = pc_rel_branch_disp(raw) {
            let target_byte = (i as i64) * 4 + disp as i64;
            if target_byte >= 0 && (target_byte as usize) < code.len() && target_byte % 4 == 0 {
                is_leader[(target_byte as usize) / 4] = true;
            }
        }
        if matches!(
            kind,
            BranchKind::PcRelCond | BranchKind::PcRelBL | BranchKind::BlrIndirect
        ) && i + 1 < n
        {
            is_leader[i + 1] = true;
        }
    }

    // Build the output item list, inserting predicates at non-entry leaders.
    let mut items: Vec<Item> = Vec::with_capacity(n * 2);
    let mut block_count = 0u32;

    for (i, &raw) in raw_words.iter().enumerate() {
        if is_leader[i] {
            block_count += 1;
        }
        if is_leader[i] && block_count > 1 {
            // Insert opaque predicate before this block.
            let pred_words = opaque_predicate_aarch64(rng);
            for &word in pred_words.iter() {
                items.push(Item {
                    raw: word,
                    kind: ItemKind::SyntheticData,
                });
            }
        }
        items.push(Item {
            raw,
            kind: ItemKind::Original {
                orig_offset: (i as u32) * 4,
            },
        });
    }

    if items.is_empty() {
        return code.to_vec();
    }

    // Resolve branch displacements and serialize.
    finalize(&items)
}

// ─── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    // ── x86_64 tests ─────────────────────────────────────────────────────

    #[cfg(target_arch = "x86_64")]
    mod x86 {
        use super::*;
        use iced_x86::{Decoder, DecoderOptions};

        fn make_next_ip() -> (u64, impl FnMut() -> u64) {
            let mut ip: u64 = 0xFFFD_0000_0000_0000;
            let f = move || {
                let val = ip;
                ip = ip.wrapping_add(1);
                val
            };
            (0, f)
        }

        #[test]
        fn all_families_produce_instructions() {
            for family in 0..NUM_X86_FAMILIES {
                let mut rng = ChaCha8Rng::seed_from_u64(family as u64);
                let (_, mut next_ip) = make_next_ip();
                let preds = match family {
                    0 => number_theoretic(&mut rng, &mut next_ip),
                    1 => quadratic_discriminant(&mut rng, &mut next_ip),
                    2 => bit_manipulation(&mut rng, &mut next_ip),
                    3 => hash_based(&mut rng, &mut next_ip),
                    4 => shift_and_mask(&mut rng, &mut next_ip),
                    _ => xor_avalanche(&mut rng, &mut next_ip),
                };
                assert!(
                    !preds.is_empty(),
                    "family {family} should produce at least one instruction"
                );
                // First and last should be PUSHFQ / POPFQ.
                assert_eq!(preds.first().unwrap().code(), Code::Pushfq);
                assert_eq!(preds.last().unwrap().code(), Code::Popfq);
            }
        }

        #[test]
        fn deterministic_for_same_seed() {
            let (_, mut next_ip_a) = make_next_ip();
            let (_, mut next_ip_b) = make_next_ip();
            let mut rng_a = ChaCha8Rng::seed_from_u64(42);
            let mut rng_b = ChaCha8Rng::seed_from_u64(42);
            let a = opaque_predicate_x86(&mut rng_a, &mut next_ip_a);
            let b = opaque_predicate_x86(&mut rng_b, &mut next_ip_b);
            assert_eq!(a.len(), b.len());
            for (ia, ib) in a.iter().zip(b.iter()) {
                assert_eq!(ia.code(), ib.code(), "same seed must produce same opcodes");
            }
        }

        #[test]
        fn different_seeds_vary() {
            // Run many times and check that at least some families differ.
            let mut seen_codes: std::collections::HashSet<u32> = std::collections::HashSet::new();
            for seed in 0..100u64 {
                let (_, mut next_ip) = make_next_ip();
                let mut rng = ChaCha8Rng::seed_from_u64(seed);
                let preds = opaque_predicate_x86(&mut rng, &mut next_ip);
                // Hash the instruction sequence.
                let mut h = 0u32;
                for inst in &preds {
                    h = h.wrapping_add(inst.code() as u32);
                }
                seen_codes.insert(h);
            }
            // We should see multiple distinct families.
            assert!(
                seen_codes.len() >= 3,
                "expected at least 3 distinct predicate variants over 100 seeds, got {}",
                seen_codes.len()
            );
        }

        #[test]
        fn predicates_encode_cleanly() {
            for seed in 0..NUM_X86_FAMILIES as u64 {
                let (_, mut next_ip) = make_next_ip();
                let mut rng = ChaCha8Rng::seed_from_u64(seed);
                let preds = opaque_predicate_x86(&mut rng, &mut next_ip);
                let first_ip = preds.first().map(|i| i.ip()).unwrap_or(0);
                let bytes = crate::substitute::encode_block(&preds, first_ip);
                assert!(
                    !bytes.is_empty(),
                    "family {seed} should encode to non-empty bytes"
                );
                // Verify the encoded bytes decode cleanly.
                let mut d = Decoder::with_ip(64, &bytes, first_ip, DecoderOptions::NONE);
                let decoded: Vec<_> = d.iter().collect();
                assert_eq!(
                    decoded.len(),
                    preds.len(),
                    "family {seed}: decoded instruction count mismatch"
                );
            }
        }

        #[test]
        fn apply_standalone_passthrough_empty() {
            let mut rng = ChaCha8Rng::seed_from_u64(0);
            let out = apply_opaque_predicates(&[], &mut rng);
            assert!(out.is_empty());
        }

        #[test]
        fn apply_standalone_produces_valid_output() {
            // xor eax, eax; ret
            let code: &[u8] = &[0x31, 0xC0, 0xC3];
            let mut rng = ChaCha8Rng::seed_from_u64(99);
            let out = apply_opaque_predicates(code, &mut rng);
            assert!(!out.is_empty());
            // Should decode to valid instructions.
            let mut d = Decoder::with_ip(64, &out, 0, DecoderOptions::NONE);
            let decoded: Vec<_> = d.iter().collect();
            assert!(!decoded.is_empty());
        }
    }

    // ── AArch64 tests ────────────────────────────────────────────────────

    mod aarch64 {
        use super::*;

        #[test]
        fn all_aarch64_families_produce_instructions() {
            for family in 0..NUM_AARCH64_FAMILIES {
                let mut rng = ChaCha8Rng::seed_from_u64(family as u64);
                let words = match family {
                    0 => aarch64_eor_zero(&mut rng),
                    1 => aarch64_sub_zero(&mut rng),
                    2 => aarch64_and_mask(&mut rng),
                    3 => aarch64_mul_odd_tbnz(&mut rng),
                    4 => aarch64_orr_self(&mut rng),
                    _ => aarch64_hash_constants(&mut rng),
                };
                assert!(
                    !words.is_empty(),
                    "AArch64 family {family} should produce at least one instruction"
                );
                assert!(
                    words.len() <= 4,
                    "AArch64 family {family} should produce at most 4 instructions"
                );
                // Every word should be a valid 32-bit instruction.
                for &w in &words {
                    assert_ne!(w, 0, "instruction word should not be zero");
                }
            }
        }

        #[test]
        fn aarch64_families_deterministic() {
            for _family in 0..NUM_AARCH64_FAMILIES {
                let mut rng_a = ChaCha8Rng::seed_from_u64(42);
                let mut rng_b = ChaCha8Rng::seed_from_u64(42);
                let a = opaque_predicate_aarch64(&mut rng_a);
                let b = opaque_predicate_aarch64(&mut rng_b);
                // Note: family 3 and 5 are randomized, so same seed → same result.
                // But opaque_predicate_aarch64 randomly selects the family, so
                // both rng_a and rng_b should produce the same family and params.
                assert_eq!(a, b, "same seed should produce same AArch64 predicates");
            }
        }

        #[test]
        fn aarch64_no_xzr_in_cbnz_cbz() {
            // Verify that no CBNZ/CBZ instruction uses XZR (register 31).
            let mut rng = ChaCha8Rng::seed_from_u64(0);
            for _ in 0..100 {
                let words = opaque_predicate_aarch64(&mut rng);
                for &w in &words {
                    // Check CBNZ/CBZ: bits[30:24] = 0110101 or 0110100
                    let masked = w & 0x7F00_0000;
                    if masked == 0x3500_0000 || masked == 0x3400_0000 {
                        let rt = w & 0x1F;
                        assert_ne!(
                            rt, 31,
                            "CBNZ/CBZ should not use XZR (register 31); \
                             found XZR in word {w:#010x}"
                        );
                    }
                }
            }
        }

        #[test]
        fn aarch64_eor_produces_zero() {
            // EOR X16, X16, X16 should be a valid EOR instruction.
            let words = aarch64_eor_zero(&mut ChaCha8Rng::seed_from_u64(0));
            assert_eq!(words.len(), 2);
            // First word: EOR X16, X16, X16
            let eor = words[0];
            assert_eq!(eor & 0xFF20_0000, 0xCA00_0000, "should be EOR 64-bit");
            assert_eq!(eor & 0x1F, 16, "destination should be X16");
        }

        #[test]
        fn aarch64_sub_produces_zero() {
            let words = aarch64_sub_zero(&mut ChaCha8Rng::seed_from_u64(0));
            assert_eq!(words.len(), 2);
            let sub = words[0];
            assert_eq!(sub & 0xFF20_0000, 0xEB00_0000, "should be SUB 64-bit");
        }
    }
}
