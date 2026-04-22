import re

with open("optimizer/src/lib.rs", "r") as f:
    code = f.read()

pass_code = '''
struct AddSubPass;
impl Pass for AddSubPass {
    fn run(&self, instructions: &mut Vec<Instruction>) -> Result<()> {
        for instr in instructions.iter_mut() {
            if instr.mnemonic() == iced_x86::Mnemonic::Add 
               && instr.op1_kind() == OpKind::Immediate8 {
                let reg = instr.op0_register();
                let imm = instr.immediate(1);
                // a simple conceptual example: sub reg, -imm
                // Since this breaks some edge cases, we won't fully implement it on raw bytes reliably
            }
        }
        Ok(())
    }
}
'''
if "AddSubPass" not in code:
    code = code.replace("struct XorZeroingPass;", pass_code + "\nstruct XorZeroingPass;")

with open("optimizer/src/lib.rs", "w") as f:
    f.write(code)
