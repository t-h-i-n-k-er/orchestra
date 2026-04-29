//! M-2 – Basic-block reordering with opaque predicates.
#![cfg(target_arch = "x86_64")]
//!
//! # Algorithm
//!
//! 1. Decode the flat byte stream into `Instruction` objects, preserving
//!    original instruction-pointer values.
//! 2. Identify **basic-block boundaries**: a new block starts at every
//!    instruction that is either the first instruction, the target of a
//!    branch, or immediately follows a terminating instruction (unconditional
//!    JMP / RET / UD2).
//! 3. **Shuffle** the block sequence with a seeded PRNG.
//! 4. For blocks whose last instruction "falls through" (i.e., the block ends
//!    with something other than an unconditional JMP or RET), append an
//!    explicit `JMP` to the original fall-through successor.
//! 5. **Opaque predicate** insertion: at the entry of every reordered block
//!    (except block 0, which must remain the entry point) insert a pair of
//!    instructions that form a conditional branch that is always *not* taken,
//!    so control always continues into the block body.  The predicate form is
//!    chosen pseudo-randomly from three variants per build.
//! 6. Re-encode the whole sequence with `BlockEncoder`, which resolves all
//!    relative branch offsets.
//!
//! ## Opaque predicate variants
//!
//! All three variants read `R11` (a caller-saved scratch register in the
//! System V AMD64 ABI) without modifying it, so the predicate is
//! call-convention safe for any position inside a function body.
//!
//! | # | Instructions | Why always not-taken |
//! |---|---|---|
//! | 0 | `CMP R11, R11` / `JNZ skip` | ZF=1 after equal compare; JNZ not taken |
//! | 1 | `TEST R11, R11` then `AND R11, 0` then compare — uses PUSH/POP to restore | Full register preservation |
//! | 2 | `MOV R10, R11` (scratch); `XOR R10, R11` → 0; `JNZ skip` | Result is always 0; JNZ not taken |
//!
//! Variant 1 and 2 modify R10/R11 and are surrounded by PUSH/POP pairs to
//! preserve calling-convention semantics.  Variant 0 is register-read-only.

use std::collections::HashSet;

use iced_x86::{Code, Decoder, DecoderOptions, Instruction, Register};
use rand::seq::SliceRandom;
use rand::Rng;

use crate::substitute::encode_block;

/// Parse `code` into basic blocks, shuffle them, insert opaque predicates,
/// reconnect with `JMP` instructions, and return the re-encoded bytes.
pub fn reorder_blocks(code: &[u8], rng: &mut impl Rng) -> Vec<u8> {
    let base_ip: u64 = 0;
    let mut decoder = Decoder::with_ip(64, code, base_ip, DecoderOptions::NONE);
    let mut instructions: Vec<Instruction> = Vec::new();
    while decoder.can_decode() {
        instructions.push(decoder.decode());
    }

    if instructions.is_empty() {
        return code.to_vec();
    }

    let blocks = split_into_blocks(&instructions);
    if blocks.len() <= 1 {
        // Nothing to reorder.
        return code.to_vec();
    }

    // ── Step 1: build a shuffled order, always keeping block 0 first ─────────
    // Block 0 is the function entry point; reordering it would change the
    // function's entry address relative to the call site.
    let mut tail: Vec<usize> = (1..blocks.len()).collect();
    tail.shuffle(rng);
    let new_order: Vec<usize> = std::iter::once(0).chain(tail).collect();

    // Mapping: original block index → position in new_order (used to find
    // where a given block now lives so we can compute fall-through JMPs).
    let mut orig_to_pos = vec![0usize; blocks.len()];
    for (pos, &orig) in new_order.iter().enumerate() {
        orig_to_pos[orig] = pos;
    }

    // ── Step 2: assign fresh IPs to the new layout ───────────────────────────
    // We need to assign IPs *before* emitting so branch instructions can
    // reference the correct target IPs.
    //
    // Strategy: keep original IPs for original instructions, assign sentinel
    // IPs (0xFFFF_xxxx range) to synthetic instructions (opaque predicates
    // and fall-through JMPs) so they never collide with a branch target.
    let mut extra_ip: u64 = 0xFFFF_8000_0000_0000u64;
    let mut next_extra = || {
        let ip = extra_ip;
        extra_ip += 1;
        ip
    };

    // ── Step 3: emit all instructions in new order ───────────────────────────
    let mut out: Vec<Instruction> = Vec::new();

    for (emit_pos, &orig_idx) in new_order.iter().enumerate() {
        let block = &blocks[orig_idx];

        // Opaque predicate: insert at the start of every block except the
        // very first emitted block (which is the function entry point).
        if emit_pos > 0 {
            let pred = opaque_predicate(rng, &mut next_extra);
            out.extend(pred);
        }

        // Emit the block's own instructions.
        out.extend_from_slice(&block.instructions);

        // Fall-through fixup: if the block doesn't end with an unconditional
        // terminator we must add an explicit JMP to its original successor.
        if block.has_fallthrough {
            if let Some(succ_ip) = block.fallthrough_ip {
                // The target IP is the first instruction of the successor block.
                let mut jmp = Instruction::with_branch(Code::Jmp_rel32_64, succ_ip)
                    .expect("JMP creation failed");
                jmp.set_ip(next_extra());
                out.push(jmp);
            }
        }
    }

    encode_block(&out, base_ip)
}

// ─── Basic-block data ─────────────────────────────────────────────────────────

struct BasicBlock {
    instructions: Vec<Instruction>,
    /// `true` when execution can fall through to the next sequential block.
    has_fallthrough: bool,
    /// IP of the first instruction of the fall-through successor (if any).
    fallthrough_ip: Option<u64>,
}

/// Split a decoded instruction sequence into basic blocks.
fn split_into_blocks(instructions: &[Instruction]) -> Vec<BasicBlock> {
    if instructions.is_empty() {
        return Vec::new();
    }

    // Collect all IPs that are branch targets — they start new blocks.
    let mut leaders: HashSet<u64> = HashSet::new();
    leaders.insert(instructions[0].ip()); // entry is always a leader

    for inst in instructions {
        if is_terminator(inst) {
            // The instruction after a terminator starts a new block.
            if let Some(next) = instructions
                .iter()
                .find(|i| i.ip() == inst.ip() + inst.len() as u64)
            {
                leaders.insert(next.ip());
            }
        }
        if inst.is_jcc_short_or_near() || inst.is_jmp_short_or_near() {
            leaders.insert(inst.near_branch64());
        }
    }

    // Group consecutive instructions into blocks, starting a new block
    // whenever we hit a leader IP.
    let mut blocks: Vec<BasicBlock> = Vec::new();
    let mut current: Vec<Instruction> = Vec::new();

    for &inst in instructions {
        if leaders.contains(&inst.ip()) && !current.is_empty() {
            let blk = finish_block(current, instructions);
            blocks.push(blk);
            current = Vec::new();
        }
        current.push(inst);
    }
    if !current.is_empty() {
        let blk = finish_block(current, instructions);
        blocks.push(blk);
    }

    blocks
}

/// Finalise a block: determine whether it has a fall-through and what its
/// successor IP is.
fn finish_block(instrs: Vec<Instruction>, all: &[Instruction]) -> BasicBlock {
    let last = instrs.last().expect("block must not be empty");
    let has_fallthrough = !is_unconditional_terminator(last);

    let fallthrough_ip = if has_fallthrough {
        // The fall-through target is the instruction immediately after `last`
        // in the original byte stream.
        let after_ip = last.ip() + last.len() as u64;
        if all.iter().any(|i| i.ip() == after_ip) {
            Some(after_ip)
        } else {
            None
        }
    } else {
        None
    };

    BasicBlock {
        instructions: instrs,
        has_fallthrough,
        fallthrough_ip,
    }
}

// ─── Terminator classification ────────────────────────────────────────────────

/// Returns `true` for instructions that end a basic block.
fn is_terminator(inst: &Instruction) -> bool {
    is_unconditional_terminator(inst) || inst.is_jcc_short_or_near()
}

/// Returns `true` for instructions after which execution *cannot* fall
/// through to the next sequential instruction.
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

// ─── Opaque predicate generation ─────────────────────────────────────────────

/// Generate an opaque predicate: a sequence of instructions that always
/// fall through (the conditional branch is never taken) but appear
/// non-deterministic to static analysis.
///
/// Three variants are produced uniformly at random.  All variants leave the
/// architectural state (including RFLAGS) in the same state they found it.
fn opaque_predicate(rng: &mut impl Rng, next_extra: &mut impl FnMut() -> u64) -> Vec<Instruction> {
    // `skip` IP = the sentinel IP we assign to the instruction *after* the
    // conditional jump inside the predicate.  The JCC target points there,
    // meaning "if somehow taken, skip to where we were going anyway" — the
    // opaque predicate occupies a self-contained IP range and the conditional
    // branch can never reach live code on the taken path.
    //
    // Since BlockEncoder resolves relative offsets by IP, we assign unique
    // sentinel IPs to every synthetic instruction; the JCC's target IP is
    // the sentinel IP of the instruction immediately following it.

    let variant = rng.gen::<u8>() % 3;

    let mut preds: Vec<Instruction> = Vec::new();

    // PUSHFQ — preserve RFLAGS across the predicate.
    let mut pushfq = Instruction::with(Code::Pushfq);
    pushfq.set_ip(next_extra());
    preds.push(pushfq);

    match variant {
        // ── Variant 0: CMP R11, R11/ JNZ skip ───────────────────────────────
        // CMP reads R11 without modifying it.  ZF=1 after equal compare.
        // JNZ is never taken (needs ZF=0).
        0 => {
            let mut cmp =
                Instruction::with2(Code::Cmp_r64_rm64, Register::R11, Register::R11)
                    .expect("CMP r11,r11");
            cmp.set_ip(next_extra());
            let jnz_target_ip = next_extra(); // IP of the instruction after JNZ
            let mut jnz =
                Instruction::with_branch(Code::Jne_rel8_64, jnz_target_ip).expect("JNZ");
            jnz.set_ip(next_extra());
            preds.push(cmp);
            preds.push(jnz);

            // Sentinel NOP that is the target of the never-taken JNZ.
            let mut nop = Instruction::with(Code::Nopd);
            nop.set_ip(jnz_target_ip);
            preds.push(nop);
        }

        // ── Variant 1: PUSH R11 / XOR R11,R11 / TEST R11,R11 / JNZ / POP R11 ─
        // R11 is saved/restored, predicate result is 0 XOR 0 = 0 → ZF=1.
        1 => {
            let mut push_r11 = Instruction::with1(Code::Push_r64, Register::R11).expect("PUSH R11");
            push_r11.set_ip(next_extra());

            let mut xor_r11 =
                Instruction::with2(Code::Xor_r64_rm64, Register::R11, Register::R11)
                    .expect("XOR R11,R11");
            xor_r11.set_ip(next_extra());

            let mut test_r11 =
                Instruction::with2(Code::Test_rm64_r64, Register::R11, Register::R11)
                    .expect("TEST R11,R11");
            test_r11.set_ip(next_extra());

            let jnz_target_ip = next_extra();
            let mut jnz =
                Instruction::with_branch(Code::Jne_rel8_64, jnz_target_ip).expect("JNZ");
            jnz.set_ip(next_extra());

            let mut pop_r11 = Instruction::with1(Code::Pop_r64, Register::R11).expect("POP R11");
            pop_r11.set_ip(jnz_target_ip); // target of never-taken JNZ

            preds.extend([push_r11, xor_r11, test_r11, jnz, pop_r11]);
        }

        // ── Variant 2: PUSH R10 / MOV R10,R11 / XOR R10,R11 / JNZ / POP R10 ─
        // R10 = R11; R10 XOR R11 = 0; ZF=1; JNZ not taken.
        _ => {
            let mut push_r10 = Instruction::with1(Code::Push_r64, Register::R10).expect("PUSH R10");
            push_r10.set_ip(next_extra());

            let mut mov_r10_r11 =
                Instruction::with2(Code::Mov_r64_rm64, Register::R10, Register::R11)
                    .expect("MOV R10,R11");
            mov_r10_r11.set_ip(next_extra());

            let mut xor_r10_r11 =
                Instruction::with2(Code::Xor_r64_rm64, Register::R10, Register::R11)
                    .expect("XOR R10,R11");
            xor_r10_r11.set_ip(next_extra());

            let jnz_target_ip = next_extra();
            let mut jnz =
                Instruction::with_branch(Code::Jne_rel8_64, jnz_target_ip).expect("JNZ");
            jnz.set_ip(next_extra());

            let mut pop_r10 = Instruction::with1(Code::Pop_r64, Register::R10).expect("POP R10");
            pop_r10.set_ip(jnz_target_ip);

            preds.extend([push_r10, mov_r10_r11, xor_r10_r11, jnz, pop_r10]);
        }
    }

    // POPFQ — restore RFLAGS.
    let mut popfq = Instruction::with(Code::Popfq);
    popfq.set_ip(next_extra());
    preds.push(popfq);

    preds
}

// ─── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    #[test]
    fn single_block_unchanged() {
        // A trivial function: MOV EAX, EDI ; RET (no branches → 1 block)
        // 89 F8 = MOV eax, edi;  C3 = RET
        let code: &[u8] = &[0x89, 0xF8, 0xC3];
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let out = reorder_blocks(code, &mut rng);
        // No reordering possible; output should decode to the same instructions.
        let mut d_in = Decoder::with_ip(64, code, 0, DecoderOptions::NONE);
        let mut d_out = Decoder::with_ip(64, &out, 0, DecoderOptions::NONE);
        let orig: Vec<_> = d_in.iter().collect();
        let trans: Vec<_> = d_out.iter().collect();
        assert_eq!(
            orig.iter().map(|i| i.code()).collect::<Vec<_>>(),
            trans.iter().map(|i| i.code()).collect::<Vec<_>>(),
            "single-block function must be returned unchanged"
        );
    }

    #[test]
    fn multi_block_output_larger_due_to_predicates() {
        // Function with two blocks separated by a conditional branch:
        //   TEST  RDI, RDI    48 85 FF
        //   JZ    +1          74 01
        //   RET               C3
        //   RET               C3
        let code: &[u8] = &[0x48, 0x85, 0xFF, 0x74, 0x01, 0xC3, 0xC3];
        let mut rng = ChaCha8Rng::seed_from_u64(7);
        let out = reorder_blocks(code, &mut rng);
        // After reordering and opaque predicate insertion the output must be
        // larger than the input (predicates + JMPs add bytes).
        assert!(
            out.len() >= code.len(),
            "reordering must not shrink the code; out={} in={}",
            out.len(),
            code.len()
        );
    }
}
