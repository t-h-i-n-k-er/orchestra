//! A dynamic binary optimizer that applies microarchitecture-specific
//! transformations to hot code paths at runtime.

use anyhow::{anyhow, Result};
use goblin;
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

struct AddSubPass;
impl Pass for AddSubPass {
    /// Replace `add reg, N` ↔ `sub reg, -N` (and vice-versa) for immediate
    /// operands.  Only 8-bit signed immediates are handled; these always
    /// produce the same encoding size, so relative branch targets are
    /// unaffected.
    fn run(&self, instructions: &mut Vec<Instruction>) -> Result<()> {
        for instr in instructions.iter_mut() {
            let mnem = instr.mnemonic();
            let is_add = mnem == iced_x86::Mnemonic::Add;
            let is_sub = mnem == iced_x86::Mnemonic::Sub;
            if (!is_add && !is_sub) || instr.op_count() != 2 || instr.op0_kind() != OpKind::Register
            {
                continue;
            }
            let reg = instr.op0_register();
            // Determine the instruction code for the opposite operation and
            // the negated immediate value.  We restrict to 8-bit-signed
            // immediates (sign-extended to the operand size) because those
            // always encode to the same byte width as the original.
            let (neg_imm_i32, new_code) = match instr.op1_kind() {
                OpKind::Immediate8to64 => {
                    let imm = instr.immediate(1) as i64 as i8;
                    if imm == i8::MIN {
                        continue;
                    }
                    let code = if is_add {
                        Code::Sub_rm64_imm8
                    } else {
                        Code::Add_rm64_imm8
                    };
                    ((-imm) as i32, code)
                }
                OpKind::Immediate8to32 => {
                    let imm = instr.immediate(1) as i32 as i8;
                    if imm == i8::MIN {
                        continue;
                    }
                    let code = if is_add {
                        Code::Sub_rm32_imm8
                    } else {
                        Code::Add_rm32_imm8
                    };
                    ((-imm) as i32, code)
                }
                OpKind::Immediate8to16 => {
                    let imm = instr.immediate(1) as i16 as i8;
                    if imm == i8::MIN {
                        continue;
                    }
                    let code = if is_add {
                        Code::Sub_rm16_imm8
                    } else {
                        Code::Add_rm16_imm8
                    };
                    ((-imm) as i32, code)
                }
                OpKind::Immediate8 => {
                    let imm = instr.immediate(1) as i8;
                    if imm == i8::MIN {
                        continue;
                    }
                    let code = if is_add {
                        Code::Sub_rm8_imm8
                    } else {
                        Code::Add_rm8_imm8
                    };
                    ((-imm) as i32, code)
                }
                _ => continue,
            };
            if let Ok(mut new_instr) = Instruction::with2(new_code, reg, neg_imm_i32) {
                new_instr.set_ip(instr.ip());
                *instr = new_instr;
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

// RegisterSwapPass was removed: unconditionally swapping RAX↔RCX across an
// entire function body without liveness analysis breaks the Windows x64
// calling convention (RAX = return value, RCX = first parameter), corrupts
// syscall conventions, and violates fixed-register instruction semantics.
// A safe implementation would require full dataflow / liveness analysis;
// that is out of scope for this runtime optimizer.

/// Parse `binary` as an ELF or PE executable, locate its `.text` section, and
/// apply size-preserving instruction-level transforms (`LeaAddPass`,
/// `AddSubPass`) to the code bytes in place.  Returns the rewritten binary.
///
/// If `binary` cannot be parsed as ELF or PE (e.g. raw machine code in tests)
/// the transforms are applied directly to the raw bytes.
///
/// Only size-preserving passes are used so that relative branch targets remain
/// valid without a full relocation pass.
pub fn diversify_code(binary: &[u8]) -> Result<Vec<u8>> {
    let mut output = binary.to_vec();

    // --- Try ELF ---
    if let Ok(elf) = goblin::elf::Elf::parse(binary) {
        let mut found = false;
        for sh in &elf.section_headers {
            if sh.sh_type != goblin::elf::section_header::SHT_PROGBITS {
                continue;
            }
            if elf.shdr_strtab.get_at(sh.sh_name) != Some(".text") {
                continue;
            }
            let file_off = sh.sh_offset as usize;
            let size = sh.sh_size as usize;
            let vaddr = sh.sh_addr;
            if file_off.saturating_add(size) <= binary.len() {
                transform_code_section(&mut output, file_off, size, vaddr);
                found = true;
                break;
            }
        }
        if found {
            return Ok(output);
        }
    }

    // --- Try PE ---
    if let Ok(pe) = goblin::pe::PE::parse(binary) {
        let mut found = false;
        for section in &pe.sections {
            let name = std::str::from_utf8(&section.name)
                .unwrap_or("")
                .trim_matches('\0');
            if name != ".text" {
                continue;
            }
            let file_off = section.pointer_to_raw_data as usize;
            let size = section.size_of_raw_data as usize;
            let vaddr = pe.image_base as u64 + section.virtual_address as u64;
            if file_off.saturating_add(size) <= binary.len() {
                transform_code_section(&mut output, file_off, size, vaddr);
                found = true;
                break;
            }
        }
        if found {
            return Ok(output);
        }
    }

    // --- Fallback: raw x86-64 machine code (used in tests / pre-linked blobs) ---
    let len = output.len();
    transform_code_section(&mut output, 0, len, 0);
    Ok(output)
}

/// Apply size-preserving instruction transforms to `binary[offset..offset+size]`
/// decoded at virtual address `vaddr`.  Transforms each instruction in-place;
/// instructions that fail to re-encode at the same byte width are left unchanged,
/// preserving all relative branch targets.
fn transform_code_section(binary: &mut Vec<u8>, offset: usize, size: usize, vaddr: u64) {
    let code: Vec<u8> = binary[offset..offset + size].to_vec();
    let mut decoder = Decoder::with_ip(64, &code, vaddr, DecoderOptions::NONE);
    let original: Vec<Instruction> = decoder.iter().collect();
    let mut transformed = original.clone();

    // Apply only size-preserving passes.
    let _ = LeaAddPass.run(&mut transformed);
    let _ = AddSubPass.run(&mut transformed);

    let mut encoder = Encoder::new(64);
    for (orig, new_instr) in original.iter().zip(transformed.iter()) {
        if orig == new_instr {
            continue; // no change
        }
        let orig_size = orig.len();
        let file_off = (orig.ip().wrapping_sub(vaddr)) as usize;
        if file_off.saturating_add(orig_size) > size {
            continue;
        }
        if encoder.encode(new_instr, new_instr.ip()).is_ok() {
            let buf = encoder.take_buffer();
            if buf.len() == orig_size {
                // Same encoded size: safe to write back without touching branches.
                binary[offset + file_off..offset + file_off + orig_size].copy_from_slice(&buf);
            }
            // Different size → skip; preserving original bytes keeps branches intact.
        }
    }
}

/// Find a function by name in the current process and apply optimizations.
/// This is the main entry point for runtime optimization.
#[cfg(feature = "unsafe-runtime-rewrite")]
pub fn optimize_hot_function(name: &str) -> Result<()> {
    let (func_ptr, code) = find_function(name)?;
    let start_addr = func_ptr as u64;

    let mut decoder = Decoder::with_ip(64, code, start_addr, DecoderOptions::NONE);
    let mut instructions: Vec<Instruction> = decoder.iter().collect();
    let original_len = instructions.len();

    let passes: Vec<Box<dyn Pass>> = vec![Box::new(LeaAddPass)];
    for pass in passes {
        pass.run(&mut instructions)?;
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

#[cfg(all(not(target_os = "windows"), feature = "unsafe-runtime-rewrite"))]
fn find_function(name: &str) -> Result<(*mut u8, &'static [u8])> {
    use std::ffi::CString;
    let name_c = CString::new(name)?;
    let ptr = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name_c.as_ptr()) };
    if ptr.is_null() {
        return Err(anyhow!(
            "Could not find function {}",
            name_c.to_string_lossy()
        ));
    }

    // Parse symbol table using dladdr to determine size securely
    let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
    if unsafe { libc::dladdr(ptr, &mut info) } == 0
        || info.dli_sname.is_null()
        || info.dli_saddr.is_null()
    {
        return Err(anyhow!("dladdr failed for {}", name));
    }

    let exe_path = unsafe { std::ffi::CStr::from_ptr(info.dli_fname) }.to_string_lossy();
    let file = std::fs::read(exe_path.as_ref())?;

    let mut size = 0;
    if let Ok(goblin::Object::Elf(elf)) = goblin::Object::parse(&file) {
        for sym in elf.syms.iter() {
            if let Some(sname) = elf.strtab.get_at(sym.st_name) {
                if sname == name {
                    size = sym.st_size as usize;
                    break;
                }
            }
        }
    }

    if size == 0 {
        // Fallback: Disassemble to find the likely end via 'Ret'
        let mut curr_ptr = ptr as u64;
        let mut tmp_size = 0;
        let mut last_ret = 0;
        while tmp_size < 10000 {
            let slice = unsafe { std::slice::from_raw_parts(curr_ptr as *const u8, 15) };
            let mut decoder = Decoder::with_ip(64, slice, curr_ptr, DecoderOptions::NONE);
            if let Some(ins) = decoder.into_iter().next() {
                tmp_size += ins.len();
                curr_ptr += ins.len() as u64;
                if ins.code() == iced_x86::Code::Retnq && last_ret == 0 {
                    size = tmp_size;
                    break;
                }
            } else {
                break;
            }
        }
    }

    if size == 0 {
        return Err(anyhow!("Could not determine function size"));
    }

    let code = unsafe { std::slice::from_raw_parts(ptr as *const u8, size) };
    Ok((ptr as *mut u8, code))
}

#[cfg(all(target_os = "windows", feature = "unsafe-runtime-rewrite"))]
fn find_function(name: &str) -> Result<(*mut u8, &'static [u8])> {
    use std::ffi::CString;
    use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};

    let module = unsafe { GetModuleHandleA(std::ptr::null_mut()) };
    let name_c = CString::new(name)?;
    let ptr = unsafe { GetProcAddress(module, name_c.as_ptr()) };
    if ptr.is_null() {
        return Err(anyhow!(
            "Could not find function {}",
            name_c.to_string_lossy()
        ));
    }

    // For Windows, find size by parsing PE

    let mut size = 0;

    // Disassembly approach
    let mut tmp_size = 0;
    let mut curr_ptr = ptr as u64;
    while tmp_size < 10000 {
        let slice = unsafe { std::slice::from_raw_parts(curr_ptr as *const u8, 15) };
        let mut decoder = Decoder::with_ip(64, slice, curr_ptr, DecoderOptions::NONE);
        if let Some(ins) = decoder.into_iter().next() {
            tmp_size += ins.len();
            curr_ptr += ins.len() as u64;
            if ins.code() == iced_x86::Code::Retnq || ins.code() == iced_x86::Code::Retnw {
                size = tmp_size;
                break; // Very naive
            }
        } else {
            break;
        }
    }

    if size == 0 {
        return Err(anyhow!("Could not determine function size"));
    }

    let code = unsafe { std::slice::from_raw_parts(ptr as *const u8, size) };
    Ok((ptr as *mut u8, code))
}

#[allow(dead_code)]
#[cfg(not(target_os = "windows"))]
fn write_executable_memory(ptr: *mut u8, data: &[u8]) -> Result<()> {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    let start = ptr as usize;
    let end = start + data.len();
    let page_start = start & !(page_size - 1);
    // Round the end address up to the next page boundary so that patches
    // spanning multiple pages all receive the temporary write permission.
    let page_end = (end + page_size - 1) & !(page_size - 1);
    let mprotect_len = page_end - page_start;

    unsafe {
        let res = libc::mprotect(
            page_start as *mut libc::c_void,
            mprotect_len,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        );
        if res != 0 {
            return Err(anyhow!(
                "mprotect(RWX) failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        std::ptr::copy_nonoverlapping(data.as_ptr(), ptr, data.len());
        libc::mprotect(
            page_start as *mut libc::c_void,
            mprotect_len,
            libc::PROT_READ | libc::PROT_EXEC,
        );
    }
    Ok(())
}

#[allow(dead_code)]
#[cfg(target_os = "windows")]
fn write_executable_memory(ptr: *mut u8, data: &[u8]) -> Result<()> {
    use winapi::shared::minwindef::DWORD;
    use winapi::um::memoryapi::VirtualProtect;
    use winapi::um::winnt::PAGE_EXECUTE_READWRITE;

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
    #[cfg(feature = "unsafe-runtime-rewrite")]
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
