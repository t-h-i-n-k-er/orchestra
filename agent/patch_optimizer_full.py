import os

path = '/home/replicant/la/optimizer/src/lib.rs'

with open(path, 'w') as f:
    f.write("""// Optimizer
use rand::seq::SliceRandom;
use rand::{thread_rng, Rng};
use iced_x86::{Code, Decoder, Encoder, Instruction, OpKind, Register};

pub trait Pass {
    fn run(&self, instrs: &mut Vec<Instruction>);
}

pub fn apply_passes(code: &[u8]) -> Vec<u8> {
    let mut decoder = Decoder::new(64, code, 0);
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

pub struct InstructionSchedulingPass;
impl Pass for InstructionSchedulingPass {
    fn run(&self, instrs: &mut Vec<Instruction>) {
        // basic block shuffling stub, complex in reality
    }
}
""")
