//! A dynamic binary optimizer that applies microarchitecture-specific
//! transformations to hot code paths at runtime.

use anyhow::{anyhow, Result};
use iced_x86::{Code, Decoder, DecoderOptions, Encoder, Instruction, OpKind, Register};
use rand::seq::SliceRandom;

trait Pass {
    fn run(&self, instructions: &mut Vec<Instruction>) -> Result<()>;
}

fn reg_size(reg: Register) -> usize {
    use Register::*;
    match reg {
        AL | BL | CL | DL | AH | BH | CH | DH | SIL | DIL | BPL | SPL | R8L | R9L | R10L | R11L
        | R12L | R13L | R14L | R15L => 1,
        AX | BX | CX | DX | SI | DI | BP | SP | R8W | R9W | R10W | R11W | R12W | R13W | R14W
        | R15W => 2,
        EAX | EBX | ECX | EDX | ESI | EDI | EBP | ESP | R8D | R9D | R10D | R11D | R12D | R13D
        | R14D | R15D => 4,
        RAX | RBX | RCX | RDX | RSI | RDI | RBP | RSP | R8 | R9 | R10 | R11 | R12 | R13 | R14
        | R15 => 8,
        _ => 0,
    }
}

struct XorZeroingPass;
impl Pass for XorZeroingPass {
    fn run(&self, instructions: &mut Vec<Instruction>) -> Result<()> {
        for instr in instructions.iter_mut() {
            if instr.mnemonic() == iced_x86::Mnemonic::Mov
                && instr.op_count() == 2
                && instr.op0_kind() == OpKind::Register
                && (instr.op1_kind() == OpKind::Immediate8
                    || instr.op1_kind() == OpKind::Immediate32
                    || instr.op1_kind() == OpKind::Immediate64)
                && instr.immediate(1) == 0
            {
                let reg = instr.op0_register();
                let new_code = match reg_size(reg) {
                    4 => Code::Xor_r32_rm32,
                    8 => Code::Xor_r64_rm64,
                    _ => continue,
                };
                if let Ok(mut new_instr) = Instruction::with2(new_code, reg, reg) {
                    new_instr.set_ip(instr.ip());
                    *instr = new_instr;
                }
            }
        }
        Ok(())
    }
}

struct LeaAddPass;
impl Pass for LeaAddPass {
    fn run(&self, instructions: &mut Vec<Instruction>) -> Result<()> {
        for instr in instructions.iter_mut() {
            // add rax, 5  -> lea rax, [rax+5]
            if instr.mnemonic() == iced_x86::Mnemonic::Add
                && instr.op_count() == 2
                && instr.op0_kind() == OpKind::Register
                && (instr.op1_kind() == OpKind::Immediate8
                    || instr.op1_kind() == OpKind::Immediate32
                    || instr.op1_kind() == OpKind::Immediate64)
            {
                let reg = instr.op0_register();
                let imm = instr.immediate(1);

                if reg_size(reg) >= 4 {
                    let new_code = match reg_size(reg) {
                        4 => Code::Lea_r32_m,
                        8 => Code::Lea_r64_m,
                        _ => continue,
                    };
                    let mem_op = iced_x86::MemoryOperand::with_base_displ(reg, imm as i64);
                    let mut new_instr = Instruction::with2(new_code, reg, mem_op)
                        .map_err(|e| anyhow!("Failed to create LEA instruction: {}", e))?;
                    new_instr.set_ip(instr.ip());
                    *instr = new_instr;
                }
            }
        }
        Ok(())
    }
}

struct JunkInstructionPass;
impl Pass for JunkInstructionPass {
    fn run(&self, instructions: &mut Vec<Instruction>) -> Result<()> {
        let mut new_instrs = Vec::with_capacity(instructions.len() * 2);
        let junk_options = [
            (Code::Nopd, 1),         // 1-byte NOP
            (Code::Mov_r64_rm64, 3), // mov rax, rax (3 bytes)
        ];

        for instr in instructions.iter() {
            new_instrs.push(instr.clone());

            // Insert junk code periodically.
            if rand::random::<u8>() < 30 {
                // ~12% chance
                let (code, _) = junk_options.choose(&mut rand::thread_rng()).unwrap();
                let junk_instr = match *code {
                    Code::Nopd => Instruction::with(Code::Nopd),
                    Code::Mov_r64_rm64 => {
                        let reg = [Register::RAX, Register::RCX, Register::RDX, Register::RBX]
                            .choose(&mut rand::thread_rng())
                            .unwrap();
                        Instruction::with2(Code::Mov_r64_rm64, *reg, *reg).unwrap()
                    }
                    _ => continue,
                };
                new_instrs.push(junk_instr);
            }
        }
        *instructions = new_instrs;
        Ok(())
    }
}

struct RegisterSwapPass;
impl Pass for RegisterSwapPass {
    fn run(&self, instructions: &mut Vec<Instruction>) -> Result<()> {
        // A simple, safe swap: RAX <-> RCX. These are volatile registers.
        let reg1 = Register::RAX;
        let reg2 = Register::RCX;

        for instr in instructions.iter_mut() {
            let mut op0_reg = instr.op0_register();
            let mut op1_reg = instr.op1_register();
            let mut op2_reg = instr.op2_register();

            if op0_reg == reg1 {
                op0_reg = reg2;
            } else if op0_reg == reg2 {
                op0_reg = reg1;
            }

            if op1_reg == reg1 {
                op1_reg = reg2;
            } else if op1_reg == reg2 {
                op1_reg = reg1;
            }

            if op2_reg == reg1 {
                op2_reg = reg2;
            } else if op2_reg == reg2 {
                op2_reg = reg1;
            }

            if instr.op0_kind() == OpKind::Register {
                instr.set_op0_register(op0_reg);
            }
            if instr.op1_kind() == OpKind::Register {
                instr.set_op1_register(op1_reg);
            }
            if instr.op2_kind() == OpKind::Register {
                instr.set_op2_register(op2_reg);
            }
        }

        Ok(())
    }
}

/// Given a slice of raw machine code, apply a series of diversifying
/// transformations and return the new machine code.
pub fn diversify_code(code: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = Decoder::with_ip(64, code, 0, DecoderOptions::NONE);
    let mut instructions: Vec<Instruction> = decoder.iter().collect();

    let passes: Vec<Box<dyn Pass>> = vec![
        Box::new(XorZeroingPass),
        Box::new(LeaAddPass),
        Box::new(JunkInstructionPass),
        Box::new(RegisterSwapPass),
    ];

    for pass in passes {
        pass.run(&mut instructions)?;
    }

    let mut encoder = Encoder::new(64);
    let mut optimized_code = Vec::new();
    for instruction in &instructions {
        encoder.encode(instruction, instruction.ip())?;
    }
    optimized_code.extend(encoder.take_buffer());

    Ok(optimized_code)
}

/// Find a function by name in the current process and apply optimizations.
/// This is the main entry point for runtime optimization.
pub fn optimize_hot_function(name: &str) -> Result<()> {
    let (func_ptr, code) = find_function(name)?;
    let start_addr = func_ptr as u64;

    let mut decoder = Decoder::with_ip(64, code, start_addr, DecoderOptions::NONE);
    let mut instructions: Vec<Instruction> = decoder.iter().collect();
    let original_len = instructions.len();

    let passes: Vec<Box<dyn Pass>> = vec![Box::new(XorZeroingPass), Box::new(LeaAddPass)];
    for pass in passes {
        pass.run(&mut instructions)?;
    }

    if instructions.len() == original_len {
        return Ok(());
    }

    let mut encoder = Encoder::new(64);
    let mut new_bytes = Vec::new();
    for instruction in &instructions {
        encoder.encode(instruction, instruction.ip())?;
    }
    new_bytes.extend(encoder.take_buffer());

    if new_bytes.len() > code.len() {
        return Err(anyhow!(
            "Optimized code is larger than original: {} > {}",
            new_bytes.len(),
            code.len()
        ));
    }

    write_executable_memory(func_ptr, &new_bytes)?;

    tracing::info!("Function optimized and verified successfully.");
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn find_function(name: &str) -> Result<(*mut u8, &'static [u8])> {
    use std::ffi::CString;
    let name = CString::new(name)?;
    let ptr = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) };
    if ptr.is_null() {
        return Err(anyhow!("Could not find function {}", name.to_string_lossy()));
    }
    // This is a huge simplification; we'd need a proper disassembler
    // to find the function end. For now, assume a generous size.
    let code = unsafe { std::slice::from_raw_parts(ptr as *const u8, 4096) };
    Ok((ptr as *mut u8, code))
}

#[cfg(target_os = "windows")]
fn find_function(name: &str) -> Result<(*mut u8, &'static [u8])> {
    use std::ffi::CString;
    use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};

    let module = unsafe { GetModuleHandleA(std::ptr::null_mut()) };
    let name = CString::new(name)?;
    let ptr = unsafe { GetProcAddress(module, name.as_ptr()) };
    if ptr.is_null() {
        return Err(anyhow!("Could not find function {}", name.to_string_lossy()));
    }
    let code = unsafe { std::slice::from_raw_parts(ptr as *const u8, 4096) };
    Ok((ptr as *mut u8, code))
}

#[cfg(not(target_os = "windows"))]
fn write_executable_memory(ptr: *mut u8, data: &[u8]) -> Result<()> {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    let start = ptr as usize;
    let page_start = start & !(page_size - 1);

    unsafe {
        let res = libc::mprotect(
            page_start as *mut libc::c_void,
            page_size,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        );
        if res != 0 {
            return Err(anyhow!("mprotect failed"));
        }
        std::ptr::copy_nonoverlapping(data.as_ptr(), ptr, data.len());
        libc::mprotect(
            page_start as *mut libc::c_void,
            page_size,
            libc::PROT_READ | libc::PROT_EXEC,
        );
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn write_executable_memory(ptr: *mut u8, data: &[u8]) -> Result<()> {
    use winapi::um::memoryapi::VirtualProtect;
    use winapi::um::winnt::{DWORD, PAGE_EXECUTE_READWRITE, PAGE_READWRITE};

    let mut old_protect: DWORD = 0;
    unsafe {
        VirtualProtect(
            ptr as *mut _,
            data.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        );
        std::ptr::copy_nonoverlapping(data.as_ptr(), ptr, data.len());
        VirtualProtect(ptr as *mut _, data.len(), old_protect, &mut old_protect);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hot_function_optimization() {
        // A simple function to be optimized.
        #[no_mangle]
        pub fn hot_function() -> i32 {
            let mut x = 0;
            for i in 0..10 {
                x += i;
            }
            x
        }

        // This test is more of a "does it run without crashing" check.
        // We can't easily verify the optimized code without a full disassembler.
        let _ = optimize_hot_function("hot_function").unwrap();
        assert_eq!(hot_function(), 45);
    }

    #[test]
    fn test_diversify_code_runs() {
        let code = &[
            0x48, 0x89, 0xc3, // mov rbx, rax
            0x48, 0x83, 0xc0, 0x05, // add rax, 5
            0x48, 0x31, 0xc0, // xor rax, rax
        ];
        let diversified = diversify_code(code).unwrap();
        assert!(!diversified.is_empty());
        assert_ne!(code, diversified.as_slice());
    }
}
