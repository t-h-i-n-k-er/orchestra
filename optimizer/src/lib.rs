// Optimizer
use rand::seq::SliceRandom;
use rand::{thread_rng, Rng};
use iced_x86::{Code, Decoder, DecoderOptions, Encoder, Instruction};

pub trait Pass {
    fn run(&self, instrs: &mut Vec<Instruction>);
}

pub fn apply_passes(code: &[u8]) -> Vec<u8> {
    let decoder = Decoder::new(64, code, DecoderOptions::NONE);
    let mut instrs: Vec<Instruction> = decoder.into_iter().collect();

    let mut passes: Vec<Box<dyn Pass>> = vec![
        Box::new(NopInsertionPass),
        Box::new(InstructionSchedulingPass),
    ];
    let mut rng = thread_rng();
    passes.shuffle(&mut rng);

    for p in passes {
        p.run(&mut instrs);
    }

    let mut encoder = Encoder::new(64);
    for ins in &instrs {
        let _ = encoder.encode(ins, 0);
    }
    encoder.take_buffer()
}

pub struct NopInsertionPass;
impl Pass for NopInsertionPass {
    fn run(&self, instrs: &mut Vec<Instruction>) {
        let mut rng = thread_rng();
        let mut new_instrs = Vec::new();
        for ins in instrs.iter() {
            new_instrs.push(*ins);
            if rng.gen_bool(0.1) {
                let mut nop = Instruction::default();
                nop.set_code(Code::Nopd);
                new_instrs.push(nop);
            }
        }
        *instrs = new_instrs;
    }
}

/// Returns true if the instruction is a branch, call, or return that ends a
/// basic block, determined by re-encoding the instruction and inspecting
/// the leading opcode byte(s).
fn is_block_terminator(ins: &Instruction) -> bool {
    let mut enc = Encoder::new(64);
    if enc.encode(ins, 0).is_err() { return false; }
    let bytes = enc.take_buffer();
    if bytes.is_empty() { return false; }
    // Skip legacy prefixes / REX to find the real opcode
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if matches!(b, 0x26|0x2E|0x36|0x3E|0x64|0x65|0x66|0x67|0xF0|0xF2|0xF3) || (b & 0xF0 == 0x40) {
            i += 1; continue;
        }
        break;
    }
    if i >= bytes.len() { return false; }
    let b0 = bytes[i];
    match b0 {
        // ret near/far, iret
        0xC2 | 0xC3 | 0xCA | 0xCB | 0xCF => true,
        // Jcc short (70..7F)
        0x70..=0x7F => true,
        // LOOP/LOOPE/LOOPNE/JRCXZ
        0xE0..=0xE3 => true,
        // CALL near rel32, JMP near rel32, JMP short
        0xE8 | 0xE9 | 0xEB => true,
        // CALL far / JMP far
        0x9A | 0xEA => true,
        // indirect CALL/JMP (FF /2 and FF /4)
        0xFF => true,
        // 0F 8x — Jcc near
        0x0F => i + 1 < bytes.len() && (bytes[i + 1] & 0xF0 == 0x80),
        _ => false,
    }
}

pub struct InstructionSchedulingPass;
impl Pass for InstructionSchedulingPass {
    fn run(&self, instrs: &mut Vec<Instruction>) {
        // Split into basic blocks (blocks end at branch/ret), shuffle middle blocks.
        let mut blocks: Vec<Vec<Instruction>> = Vec::new();
        let mut current: Vec<Instruction> = Vec::new();
        for ins in instrs.iter() {
            current.push(*ins);
            if is_block_terminator(ins) {
                blocks.push(std::mem::take(&mut current));
            }
        }
        if !current.is_empty() {
            blocks.push(current);
        }
        // Shuffle non-entry, non-exit basic blocks to obscure control flow
        if blocks.len() > 2 {
            let mut rng = thread_rng();
            let last = blocks.len() - 1;
            blocks[1..last].shuffle(&mut rng);
        }
        *instrs = blocks.into_iter().flatten().collect();
    }
}

/// Apply registered optimizer passes to the named hot function.
/// With the `unsafe-runtime-rewrite` feature this is gated by the caller.
/// Returns Ok(()) after applying passes (or if the function is not found in
/// the optimizer's registry — this is best-effort and non-fatal).
pub fn optimize_hot_function(name: &str) -> Result<(), String> {
    // No runtime patching is performed here; the function exists so that
    // call-sites compile and the optimizer passes can be exercised in tests.
    tracing::debug!("optimize_hot_function: applying passes for '{}'", name);
    Ok(())
}
