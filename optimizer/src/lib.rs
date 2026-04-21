//! A dynamic binary optimizer that applies microarchitecture-specific
//! transformations to hot code paths at runtime.

use anyhow::{anyhow, Result};
use iced_x86::{Code, Decoder, DecoderOptions, Encoder, Instruction, OpKind, Register};

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
                && matches!(
                    instr.op1_kind(),
                    OpKind::Immediate8 | OpKind::Immediate32 | OpKind::Immediate64
                )
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

struct IncPass;
impl Pass for IncPass {
    fn run(&self, instructions: &mut Vec<Instruction>) -> Result<()> {
        for instr in instructions.iter_mut() {
            if instr.mnemonic() == iced_x86::Mnemonic::Add
                && instr.op_count() == 2
                && matches!(
                    instr.op1_kind(),
                    OpKind::Immediate8
                        | OpKind::Immediate32
                        | OpKind::Immediate64
                        | OpKind::Immediate8to32
                        | OpKind::Immediate8to64
                )
                && instr.immediate(1) == 1
            {
                let reg = instr.op0_register();
                let new_code = match reg_size(reg) {
                    4 => Code::Inc_rm32,
                    8 => Code::Inc_rm64,
                    _ => continue,
                };
                if let Ok(mut new_instr) = Instruction::with1(new_code, reg) {
                    new_instr.set_ip(instr.ip());
                    *instr = new_instr;
                }
            }
        }
        Ok(())
    }
}

pub struct Optimizer {
    passes: Vec<Box<dyn Pass>>,
}

impl Default for Optimizer {
    fn default() -> Self {
        Self::new()
    }
}

impl Optimizer {
    pub fn new() -> Self {
        Self {
            passes: vec![Box::new(XorZeroingPass), Box::new(IncPass)],
        }
    }

    /// # Safety
    /// Reads, modifies, and overwrites executable memory.
    pub unsafe fn optimize_function(
        &self,
        func_ptr: *const u8,
        original_bytes: &[u8],
    ) -> Result<()> {
        let mut decoder = Decoder::new(64, original_bytes, DecoderOptions::NONE);
        decoder.set_ip(func_ptr as u64);
        let mut instructions: Vec<Instruction> = decoder.into_iter().collect();

        for pass in &self.passes {
            pass.run(&mut instructions)?;
        }

        let mut new_bytes = Vec::new();
        for instr in &instructions {
            let mut encoder = Encoder::new(64);
            encoder
                .encode(instr, instr.ip())
                .map_err(|e| anyhow!("encode failed: {}", e))?;
            new_bytes.extend_from_slice(&encoder.take_buffer());
        }

        if new_bytes.len() > original_bytes.len() {
            return Err(anyhow!(
                "Optimized function is larger than original ({} > {})",
                new_bytes.len(),
                original_bytes.len()
            ));
        }
        while new_bytes.len() < original_bytes.len() {
            new_bytes.push(0x90);
        }

        write_executable_memory(func_ptr, &new_bytes)?;
        Ok(())
    }

    pub fn optimize_safely<R>(&self, func: fn() -> R, test_vector: &[R]) -> Result<()>
    where
        R: PartialEq + std::fmt::Debug,
    {
        let original_results: Vec<R> = test_vector.iter().map(|_| func()).collect();
        let func_ptr = func as *const () as *const u8;
        let original_bytes = unsafe { snapshot_function(func_ptr)? };

        unsafe { self.optimize_function(func_ptr, &original_bytes)? };

        let new_results: Vec<R> = test_vector.iter().map(|_| func()).collect();

        if original_results != new_results {
            unsafe {
                let _ = write_executable_memory(func_ptr, &original_bytes);
            }
            return Err(anyhow!(
                "Optimization verification failed; original code restored."
            ));
        }
        tracing::info!("Function optimized and verified successfully.");
        Ok(())
    }
}

unsafe fn snapshot_function(func_ptr: *const u8) -> Result<Vec<u8>> {
    for i in 0..1024 {
        if *func_ptr.add(i) == 0xC3 {
            return Ok(std::slice::from_raw_parts(func_ptr, i + 1).to_vec());
        }
    }
    Err(anyhow!("Could not find end of function."))
}

unsafe fn write_executable_memory(ptr: *const u8, bytes: &[u8]) -> Result<()> {
    let page_size = region::page::size();
    let start_addr = ptr as usize;
    let page_start = start_addr & !(page_size - 1);
    let end_addr = start_addr + bytes.len();
    let pages_len = ((end_addr - page_start) + page_size - 1) & !(page_size - 1);

    #[cfg(unix)]
    {
        use libc::{mprotect, PROT_EXEC, PROT_READ, PROT_WRITE};
        if mprotect(
            page_start as *mut _,
            pages_len,
            PROT_READ | PROT_WRITE | PROT_EXEC,
        ) != 0
        {
            return Err(anyhow!(
                "mprotect failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr as *mut u8, bytes.len());
        mprotect(page_start as *mut _, pages_len, PROT_READ | PROT_EXEC);
    }
    #[cfg(windows)]
    {
        use winapi::um::memoryapi::VirtualProtect;
        use winapi::um::winnt::{PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE};
        let mut old_protect = 0u32;
        if VirtualProtect(
            page_start as *mut _,
            pages_len,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        ) == 0
        {
            return Err(anyhow!(
                "VirtualProtect failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr as *mut u8, bytes.len());
        let mut tmp = 0u32;
        VirtualProtect(page_start as *mut _, pages_len, PAGE_EXECUTE_READ, &mut tmp);
    }
    Ok(())
}

/// A sample function to be optimized.
#[inline(never)]
pub fn hot_function() -> i32 {
    let mut a: i32 = 0;
    a += 1;
    a += 1;
    a
}

/// Best-effort optimization of well-known hot paths at agent startup.
pub fn optimize_hot_functions() {
    tracing::info!("Attempting to optimize hot functions...");
    let optimizer = Optimizer::new();
    let test_vector: Vec<i32> = vec![0; 5];
    if let Err(e) = optimizer.optimize_safely(hot_function as fn() -> i32, &test_vector) {
        tracing::warn!("Failed to optimize hot_function: {}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hot_function_optimization() {
        assert_eq!(hot_function(), 2);
        let optimizer = Optimizer::new();
        let test_vector: Vec<i32> = vec![0; 5];
        let _ = optimizer.optimize_safely(hot_function as fn() -> i32, &test_vector);
        assert_eq!(hot_function(), 2);
    }
}
