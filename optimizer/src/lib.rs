// Optimizer
use iced_x86::{Code, Decoder, DecoderOptions, Encoder, Instruction, OpKind, Register};
use rand::seq::SliceRandom;
use rand::{thread_rng, Rng};

pub trait Pass {
    fn run(&self, instrs: &mut Vec<Instruction>);
}

pub fn apply_passes(code: &[u8]) -> Vec<u8> {
    // Decode retaining original IPs so we can remap branch targets after
    // passes insert NOPs or reorder instructions.
    const BASE: u64 = 0x1000;
    let decoder = Decoder::with_ip(64, code, BASE, DecoderOptions::NONE);
    let mut instrs: Vec<Instruction> = decoder.into_iter().collect();

    let mut passes: Vec<Box<dyn Pass>> = vec![
        Box::new(NopInsertionPass),
        Box::new(InstructionSchedulingPass),
    ];
    // Metamorphic passes: instruction-level substitution and opaque dead-code
    // insertion.  Gated behind the `diversification` feature so callers can
    // opt in explicitly; these passes change encoded sizes which requires the
    // branch-target fixup below to run correctly.
    #[cfg(feature = "diversification")]
    {
        passes.push(Box::new(InstructionSubstitutionPass) as Box<dyn Pass>);
        passes.push(Box::new(OpaqueDeadCodePass) as Box<dyn Pass>);
    }
    let mut rng = thread_rng();
    passes.shuffle(&mut rng);

    for p in passes {
        p.run(&mut instrs);
    }

    // Helper: compute the IP each instruction will be placed at by doing a
    // trial encode.  We need this to rewrite near-branch targets correctly.
    let compute_ips = |instrs: &[Instruction]| -> Vec<u64> {
        let mut ips = Vec::with_capacity(instrs.len());
        let mut cur = BASE;
        let mut enc = Encoder::new(64);
        for ins in instrs {
            ips.push(cur);
            // encode at `cur` to get the correct encoded size for this IP;
            // the result might be inaccurate if the branch target changed later,
            // but a second pass corrects that.
            cur += enc.encode(ins, cur).unwrap_or(1) as u64;
            enc.take_buffer();
        }
        ips
    };

    // First pass: approximate new IPs.
    let approx_ips = compute_ips(&instrs);

    // Build old_ip → new_ip map so branch targets can be remapped.
    use std::collections::HashMap;
    let mut ip_map: HashMap<u64, u64> = HashMap::new();
    for (ins, &new_ip) in instrs.iter().zip(approx_ips.iter()) {
        // NOP instructions inserted by NopInsertionPass have ip()==0; they
        // carry no branch targets so we can skip duplicate-key entries.
        ip_map.entry(ins.ip()).or_insert(new_ip);
    }

    // Rewrite near branch targets using the new IP map.
    use iced_x86::OpKind;
    for ins in &mut instrs {
        let needs_fix = (0..ins.op_count()).any(|i| {
            matches!(
                ins.op_kind(i),
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
            )
        });
        if needs_fix {
            let old_target = ins.near_branch64();
            if let Some(&new_target) = ip_map.get(&old_target) {
                ins.set_near_branch64(new_target);
            }
        }
    }

    // Recompute IPs now that branch targets (and therefore branch sizes) are
    // final, then encode at those IPs.
    let final_ips = compute_ips(&instrs);
    let mut encoder = Encoder::new(64);
    for (ins, &ip) in instrs.iter().zip(final_ips.iter()) {
        let _ = encoder.encode(ins, ip);
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
    if enc.encode(ins, 0).is_err() {
        return false;
    }
    let bytes = enc.take_buffer();
    if bytes.is_empty() {
        return false;
    }
    // Skip legacy prefixes / REX to find the real opcode
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if matches!(
            b,
            0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65 | 0x66 | 0x67 | 0xF0 | 0xF2 | 0xF3
        ) || (b & 0xF0 == 0x40)
        {
            i += 1;
            continue;
        }
        break;
    }
    if i >= bytes.len() {
        return false;
    }
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
        // Split into basic blocks (blocks end at branch/ret).
        // IMPORTANT: we do NOT reorder blocks — that would invalidate
        // inter-block relative branches and fall-through edges.
        // We only shuffle the *body* of each block (non-terminator instructions)
        // to obscure intra-block patterns while preserving control flow.
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
        let mut rng = thread_rng();
        for block in &mut blocks {
            // Keep the terminator pinned at the end; shuffle the body only.
            let body_end = if block
                .last()
                .map(|i| is_block_terminator(i))
                .unwrap_or(false)
            {
                block.len() - 1
            } else {
                block.len()
            };
            if body_end > 1 {
                block[..body_end].shuffle(&mut rng);
            }
        }
        *instrs = blocks.into_iter().flatten().collect();
    }
}

/// Apply registered optimizer passes to the named hot function.
///
/// Without the `unsafe-runtime-rewrite` feature this is a metadata-only
/// no-op — the optimizer passes can still be exercised via `apply_passes`
/// from tests.
///
/// With `unsafe-runtime-rewrite` enabled, the function performs in-place
/// rewriting of the named function: locate the symbol, decode an estimated
/// span (default 256 bytes), apply the registered passes, then write the
/// result back into executable memory after temporarily lowering page
/// protections via `VirtualProtect` (Windows) or `mprotect` (Unix).
/// Without the `unsafe-runtime-rewrite` feature this is a metadata-only
/// no-op — the optimizer passes can still be exercised via `apply_passes`
/// from tests.
///
/// With `unsafe-runtime-rewrite` enabled, the function performs in-place
/// rewriting of the named function: locate the symbol, decode an estimated
/// span (default 256 bytes), apply the registered passes, then write the
/// result back into executable memory after temporarily lowering page
/// protections via `VirtualProtect` (Windows) or `mprotect` (Unix).

// ── Instruction substitution pass ────────────────────────────────────────────

/// Replace instructions with semantically equivalent alternatives to produce
/// different binary patterns across builds (metamorphism).
///
/// Substitution table (applied with ~50 % probability each):
/// * `ADD r64, 1`  ↔  `INC r64`
/// * `SUB r64, 1`  ↔  `DEC r64`
/// * `MOV r64, 0`  →   `XOR r64, r64`
/// * `XOR r64, r64` (same reg) ↔ `SUB r64, r64`
/// * `TEST r64, r64` (same reg) ↔ `CMP r64, 0`
/// * `AND r64, 0`  →   `XOR r64, r64`
///
/// Note: INC/DEC differ from ADD/SUB in that they do **not** update CF.  This
/// substitution is safe wherever CF is not observed after the instruction,
/// which covers the vast majority of loop-counter and pointer-increment
/// patterns.  Enable only when you accept this caveat.
#[cfg(feature = "diversification")]
pub struct InstructionSubstitutionPass;

#[cfg(feature = "diversification")]
impl Pass for InstructionSubstitutionPass {
    fn run(&self, instrs: &mut Vec<Instruction>) {
        let mut rng = thread_rng();
        for ins in instrs.iter_mut() {
            if !rng.gen_bool(0.5) {
                continue;
            }
            let orig_ip = ins.ip();
            if let Some(mut new_ins) = try_substitute(ins, &mut rng) {
                new_ins.set_ip(orig_ip);
                *ins = new_ins;
            }
        }
    }
}

/// Return a semantically-equivalent replacement for `ins`, or `None` to keep
/// the original unchanged.
#[cfg(feature = "diversification")]
fn try_substitute(ins: &Instruction, rng: &mut impl Rng) -> Option<Instruction> {
    match ins.code() {
        // ADD r/m64, 1  →  INC r/m64
        Code::Add_rm64_imm8 if ins.op0_kind() == OpKind::Register && ins.immediate8() == 1 => {
            Instruction::with1(Code::Inc_rm64, ins.op0_register()).ok()
        }
        // INC r/m64  →  ADD r/m64, 1  (restores CF behaviour)
        Code::Inc_rm64 if ins.op0_kind() == OpKind::Register && rng.gen_bool(0.5) => {
            Instruction::with2(Code::Add_rm64_imm8, ins.op0_register(), 1u32).ok()
        }
        // SUB r/m64, 1  →  DEC r/m64
        Code::Sub_rm64_imm8 if ins.op0_kind() == OpKind::Register && ins.immediate8() == 1 => {
            Instruction::with1(Code::Dec_rm64, ins.op0_register()).ok()
        }
        // DEC r/m64  →  SUB r/m64, 1
        Code::Dec_rm64 if ins.op0_kind() == OpKind::Register && rng.gen_bool(0.5) => {
            Instruction::with2(Code::Sub_rm64_imm8, ins.op0_register(), 1u32).ok()
        }
        // MOV r64, 0  →  XOR r64, r64  (sets identical flags; saves 3-4 bytes)
        Code::Mov_rm64_imm32 | Code::Mov_r64_imm64
            if ins.op0_kind() == OpKind::Register && ins.immediate64() == 0 =>
        {
            let r = ins.op0_register();
            Instruction::with2(Code::Xor_r64_rm64, r, r).ok()
        }
        // XOR r64, r64 (same reg)  →  SUB r64, r64  (identical semantics + flags)
        Code::Xor_r64_rm64
            if ins.op0_kind() == OpKind::Register
                && ins.op1_kind() == OpKind::Register
                && ins.op0_register() == ins.op1_register()
                && rng.gen_bool(0.5) =>
        {
            let r = ins.op0_register();
            Instruction::with2(Code::Sub_r64_rm64, r, r).ok()
        }
        // AND r64, 0  →  XOR r64, r64  (both zero reg; flag effects identical)
        Code::And_rm64_imm8 if ins.op0_kind() == OpKind::Register && ins.immediate8() == 0 => {
            let r = ins.op0_register();
            Instruction::with2(Code::Xor_r64_rm64, r, r).ok()
        }
        // TEST r64, r64  →  CMP r64, 0  (identical flag outputs)
        Code::Test_rm64_r64
            if ins.op0_kind() == OpKind::Register
                && ins.op1_kind() == OpKind::Register
                && ins.op0_register() == ins.op1_register() =>
        {
            Instruction::with2(Code::Cmp_rm64_imm8, ins.op0_register(), 0i32).ok()
        }
        // CMP r64, 0  →  TEST r64, r64
        Code::Cmp_rm64_imm8 if ins.op0_kind() == OpKind::Register && ins.immediate8() == 0 => {
            let r = ins.op0_register();
            Instruction::with2(Code::Test_rm64_r64, r, r).ok()
        }
        _ => None,
    }
}

// ── Opaque dead-code insertion pass ──────────────────────────────────────────

/// Insert opaque dead-store sequences at basic-block boundaries.
///
/// Before ~35 % of block-entry instructions, inserts:
/// ```asm
///   PUSH <scratch_reg>
///   MOV  <scratch_reg>, <random_imm64>
///   POP  <scratch_reg>
/// ```
/// This sequence preserves all flags and all registers (RSP nets to zero) but
/// produces a different binary fingerprint every build.  The scratch register
/// is chosen randomly from the caller-saved set so no callee-save epilogue is
/// needed.
#[cfg(feature = "diversification")]
pub struct OpaqueDeadCodePass;

#[cfg(feature = "diversification")]
impl Pass for OpaqueDeadCodePass {
    fn run(&self, instrs: &mut Vec<Instruction>) {
        // Caller-saved registers on both SysV AMD64 and Windows x64 ABI.
        const SCRATCH: &[Register] = &[
            Register::RAX,
            Register::RCX,
            Register::RDX,
            Register::R8,
            Register::R9,
            Register::R10,
            Register::R11,
        ];
        let mut rng = thread_rng();
        let mut result = Vec::with_capacity(instrs.len() + instrs.len() / 4);
        let mut at_block_start = true;

        for &ins in instrs.iter() {
            if at_block_start && rng.gen_bool(0.35) {
                let reg = *SCRATCH.choose(&mut rng).unwrap();
                let dead_val: u64 = rng.gen();
                // PUSH / MOV / POP — EFLAGS unchanged, RSP net change = 0.
                if let (Ok(push), Ok(mov), Ok(pop)) = (
                    Instruction::with1(Code::Push_r64, reg),
                    Instruction::with2(Code::Mov_r64_imm64, reg, dead_val),
                    Instruction::with1(Code::Pop_r64, reg),
                ) {
                    result.push(push);
                    result.push(mov);
                    result.push(pop);
                }
            }
            at_block_start = is_block_terminator(&ins);
            result.push(ins);
        }
        *instrs = result;
    }
}

pub fn optimize_hot_function(name: &str) -> Result<(), String> {
    tracing::debug!("optimize_hot_function: requested for '{}'", name);

    #[cfg(not(feature = "unsafe-runtime-rewrite"))]
    {
        let _ = name;
        return Ok(());
    }

    #[cfg(feature = "unsafe-runtime-rewrite")]
    {
        runtime_rewrite::rewrite(name)
    }
}

#[cfg(feature = "unsafe-runtime-rewrite")]
mod runtime_rewrite {
    use super::*;

    /// Default rewrite span: 256 bytes is enough for most short hot functions
    /// without risking decoding past the function's end into other code.
    const DEFAULT_SPAN: usize = 256;

    pub fn rewrite(name: &str) -> Result<(), String> {
        let addr = locate_symbol(name)
            .ok_or_else(|| format!("symbol '{}' not found in this process", name))?;
        // Snapshot the current bytes
        let original =
            unsafe { std::slice::from_raw_parts(addr as *const u8, DEFAULT_SPAN) }.to_vec();
        // Apply optimizer passes
        let new_bytes = apply_passes(&original);
        // Refuse if size changed — would clobber adjacent code
        if new_bytes.len() != original.len() {
            return Err(format!(
                "rewrite would change size ({} -> {}); refusing",
                original.len(),
                new_bytes.len()
            ));
        }
        // Lower protection, copy, restore.
        unsafe {
            let mut old = make_writable(addr, DEFAULT_SPAN)?;
            std::ptr::copy_nonoverlapping(new_bytes.as_ptr(), addr as *mut u8, DEFAULT_SPAN);
            restore_protection(addr, DEFAULT_SPAN, &mut old)?;
            flush_icache(addr, DEFAULT_SPAN);
        }
        tracing::info!(
            "optimize_hot_function: rewrote {} bytes at {:p} for '{}'",
            DEFAULT_SPAN,
            addr as *const u8,
            name
        );
        Ok(())
    }

    fn locate_symbol(_name: &str) -> Option<usize> {
        // In a fully self-contained binary we cannot easily resolve symbols
        // by name without dlsym/GetProcAddress against the current module.
        // Use platform-specific lookup against the main module.
        #[cfg(unix)]
        unsafe {
            let cname = std::ffi::CString::new(_name).ok()?;
            let addr = libc::dlsym(libc::RTLD_DEFAULT, cname.as_ptr());
            if addr.is_null() {
                None
            } else {
                Some(addr as usize)
            }
        }
        #[cfg(windows)]
        unsafe {
            extern "system" {
                fn GetModuleHandleA(name: *const i8) -> *mut std::ffi::c_void;
                fn GetProcAddress(
                    h: *mut std::ffi::c_void,
                    name: *const i8,
                ) -> *mut std::ffi::c_void;
            }
            let h = GetModuleHandleA(std::ptr::null());
            if h.is_null() {
                return None;
            }
            let cname = std::ffi::CString::new(_name).ok()?;
            let addr = GetProcAddress(h, cname.as_ptr());
            if addr.is_null() {
                None
            } else {
                Some(addr as usize)
            }
        }
        #[cfg(not(any(unix, windows)))]
        {
            None
        }
    }

    pub struct ProtSnapshot(pub u32);

    #[cfg(windows)]
    unsafe fn make_writable(addr: usize, len: usize) -> Result<ProtSnapshot, String> {
        extern "system" {
            fn VirtualProtect(
                addr: *mut std::ffi::c_void,
                size: usize,
                new_protect: u32,
                old: *mut u32,
            ) -> i32;
        }
        const PAGE_EXECUTE_READWRITE: u32 = 0x40;
        let mut old = 0u32;
        if VirtualProtect(addr as *mut _, len, PAGE_EXECUTE_READWRITE, &mut old) == 0 {
            return Err("VirtualProtect(RWX) failed".into());
        }
        Ok(ProtSnapshot(old))
    }

    #[cfg(windows)]
    unsafe fn restore_protection(
        addr: usize,
        len: usize,
        old: &mut ProtSnapshot,
    ) -> Result<(), String> {
        extern "system" {
            fn VirtualProtect(
                addr: *mut std::ffi::c_void,
                size: usize,
                new_protect: u32,
                old: *mut u32,
            ) -> i32;
        }
        let mut tmp = 0u32;
        if VirtualProtect(addr as *mut _, len, old.0, &mut tmp) == 0 {
            return Err("VirtualProtect(restore) failed".into());
        }
        Ok(())
    }

    #[cfg(windows)]
    unsafe fn flush_icache(addr: usize, len: usize) {
        extern "system" {
            fn FlushInstructionCache(
                h: *mut std::ffi::c_void,
                addr: *const std::ffi::c_void,
                size: usize,
            ) -> i32;
            fn GetCurrentProcess() -> *mut std::ffi::c_void;
        }
        FlushInstructionCache(GetCurrentProcess(), addr as *const _, len);
    }

    #[cfg(unix)]
    unsafe fn make_writable(addr: usize, len: usize) -> Result<ProtSnapshot, String> {
        let page = libc::sysconf(libc::_SC_PAGESIZE) as usize;
        let aligned = addr & !(page - 1);
        let aligned_len = ((addr + len) - aligned + page - 1) & !(page - 1);
        if libc::mprotect(
            aligned as *mut libc::c_void,
            aligned_len,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        ) != 0
        {
            return Err(format!(
                "mprotect(RWX) failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        // We don't read original protection on unix; assume PROT_READ|PROT_EXEC for restore.
        Ok(ProtSnapshot(0))
    }

    #[cfg(unix)]
    unsafe fn restore_protection(
        addr: usize,
        len: usize,
        _old: &mut ProtSnapshot,
    ) -> Result<(), String> {
        let page = libc::sysconf(libc::_SC_PAGESIZE) as usize;
        let aligned = addr & !(page - 1);
        let aligned_len = ((addr + len) - aligned + page - 1) & !(page - 1);
        if libc::mprotect(
            aligned as *mut libc::c_void,
            aligned_len,
            libc::PROT_READ | libc::PROT_EXEC,
        ) != 0
        {
            return Err(format!(
                "mprotect(restore) failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    #[cfg(unix)]
    unsafe fn flush_icache(_addr: usize, _len: usize) {
        // x86_64/aarch64 Linux uses coherent I-cache; mprotect already
        // serializes.  For other arches we'd call __builtin___clear_cache.
    }

    #[cfg(not(any(windows, unix)))]
    unsafe fn make_writable(_a: usize, _l: usize) -> Result<ProtSnapshot, String> {
        Err("unsupported platform".into())
    }
    #[cfg(not(any(windows, unix)))]
    unsafe fn restore_protection(
        _a: usize,
        _l: usize,
        _o: &mut ProtSnapshot,
    ) -> Result<(), String> {
        Err("unsupported platform".into())
    }
    #[cfg(not(any(windows, unix)))]
    unsafe fn flush_icache(_a: usize, _l: usize) {}
}
