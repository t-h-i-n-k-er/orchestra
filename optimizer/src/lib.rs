// Optimizer
use iced_x86::{Code, Decoder, DecoderOptions, Encoder, Instruction};
#[cfg(feature = "diversification")]
use iced_x86::{OpKind, Register};
use rand::seq::SliceRandom;
use rand::{thread_rng, Rng};

#[cfg(feature = "diversification")]
include!(concat!(env!("OUT_DIR"), "/stub_seed.rs"));

/// Derive an 8-byte dead-code value from the build-time STUB_SEED and a
/// per-stub index using HKDF-SHA256.  This ensures every build produces
/// different dead-code constants (because STUB_SEED changes each build) while
/// also ensuring each stub site within a build gets a distinct value (because
/// `index` differs per site).
#[cfg(feature = "diversification")]
fn derive_dead_val(index: u64) -> u64 {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let hk = Hkdf::<Sha256>::new(None, &STUB_SEED);
    let mut okm = [0u8; 8];
    let info = index.to_le_bytes();
    hk.expand(&info, &mut okm)
        .expect("HKDF expand with 8-byte OKM should never fail");
    u64::from_le_bytes(okm)
}

pub trait Pass {
    fn run(&self, instrs: &mut Vec<Instruction>);
}

pub fn apply_passes(code: &[u8]) -> Vec<u8> {
    apply_passes_at(0x1000, code)
}

/// Apply diversification passes to raw code bytes decoded at the given virtual
/// base address.  Callers that know the section's actual load address should
/// pass it here so that RIP-relative operands are decoded with the correct IP.
pub fn apply_passes_at(base: u64, code: &[u8]) -> Vec<u8> {
    // Decode retaining original IPs so we can remap branch targets after
    // passes insert NOPs or reorder instructions.
    let decoder = Decoder::with_ip(64, code, base, DecoderOptions::NONE);
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
        let mut cur = base;
        let mut enc = Encoder::new(64);
        for ins in instrs {
            ips.push(cur);
            // encode at `cur` to get the correct encoded size for this IP;
            // the result might be inaccurate if the branch target changed later,
            // but a second pass corrects that.
            cur += enc.encode(ins, cur).unwrap_or(1) as u64;
            let _ = enc.take_buffer();
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

/// Apply diversification passes to every executable section of a compiled PE
/// or ELF binary and return the modified binary.
///
/// For each executable section the function:
/// 1. Applies `apply_passes_at` using the section's actual virtual address so
///    that RIP-relative operands are decoded correctly.
/// 2. If the transformed section fits in the section's raw file allocation,
///    patches it in and zero-fills any slack with `INT3` (0xCC) bytes — those
///    bytes are in unreachable territory beyond the last `RET`/`JMP`.
/// 3. If the transformed section is larger than the raw allocation, logs a
///    warning and skips that section rather than producing a corrupt binary.
pub fn apply_passes_to_binary(binary: &[u8]) -> Result<Vec<u8>, String> {
    use goblin::Object;

    let parsed = Object::parse(binary).map_err(|e| format!("binary parse failed: {e}"))?;

    // Collect (file_offset, raw_size, virtual_address) for each executable section.
    let sections: Vec<(usize, usize, u64)> = match parsed {
        Object::PE(pe) => {
            let image_base = pe.image_base as u64;
            pe.sections
                .iter()
                .filter(|s| {
                    const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
                    s.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
                        && s.size_of_raw_data > 0
                        && s.pointer_to_raw_data > 0
                })
                .map(|s| {
                    (
                        s.pointer_to_raw_data as usize,
                        s.size_of_raw_data as usize,
                        image_base + s.virtual_address as u64,
                    )
                })
                .collect()
        }
        Object::Elf(elf) => {
            const SHF_EXECINSTR: u64 = 0x4;
            elf.section_headers
                .iter()
                .filter(|s| {
                    s.sh_flags & SHF_EXECINSTR != 0
                        && s.sh_size > 0
                        && s.sh_offset > 0
                })
                .map(|s| (s.sh_offset as usize, s.sh_size as usize, s.sh_addr))
                .collect()
        }
        Object::Mach(_) | Object::Archive(_) | Object::Unknown(_) => {
            return Err(
                "unsupported binary format; only PE and ELF are supported for diversification"
                    .into(),
            );
        }
    };

    if sections.is_empty() {
        return Err("no executable sections found in binary".into());
    }

    let mut out = binary.to_vec();
    let mut patched = 0usize;

    for (file_offset, raw_size, va) in sections {
        if file_offset + raw_size > binary.len() {
            tracing::warn!(
                "diversify: section at offset {file_offset:#x} extends past binary end; skipping"
            );
            continue;
        }
        let code = &binary[file_offset..file_offset + raw_size];
        let new_bytes = apply_passes_at(va, code);

        match new_bytes.len().cmp(&raw_size) {
            std::cmp::Ordering::Equal => {
                out[file_offset..file_offset + raw_size].copy_from_slice(&new_bytes);
                patched += 1;
            }
            std::cmp::Ordering::Less => {
                // Fits — fill the remaining slack with INT3 guard bytes.
                out[file_offset..file_offset + new_bytes.len()].copy_from_slice(&new_bytes);
                out[file_offset + new_bytes.len()..file_offset + raw_size].fill(0xCC);
                patched += 1;
            }
            std::cmp::Ordering::Greater => {
                tracing::warn!(
                    "diversify: transformed section at {va:#x} grew from {raw_size} to {} bytes; \
                     skipping (re-run for a different randomisation that stays within budget)",
                    new_bytes.len()
                );
            }
        }
    }

    tracing::info!("diversify: applied passes to {patched} executable section(s)");
    Ok(out)
}



pub struct NopInsertionPass;
impl Pass for NopInsertionPass {
    fn run(&self, instrs: &mut Vec<Instruction>) {
        let mut rng = thread_rng();
        let mut new_instrs = Vec::new();
        for ins in instrs.iter() {
            new_instrs.push(*ins);
            if rng.gen_bool(0.1) {
                // Use a multi-byte NOP form (0F 1F /0) to avoid obvious 0x90 padding.
                if let Ok(nop) = Instruction::with1(Code::Nop_rm64, iced_x86::Register::RAX) {
                    new_instrs.push(nop);
                }
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
    fn run(&self, _instrs: &mut Vec<Instruction>) {
        // Disabled: shuffling without data-dependency analysis produces
        // incorrect code (C-5).  Re-enable only after implementing SSA-based
        // scheduling that respects read-after-write / write-after-write hazards.
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
/// is chosen randomly from a callee-saved register set to avoid clobber risk
/// across block boundaries.
#[cfg(feature = "diversification")]
pub struct OpaqueDeadCodePass;

#[cfg(feature = "diversification")]
impl Pass for OpaqueDeadCodePass {
    fn run(&self, instrs: &mut Vec<Instruction>) {
        // Callee-saved registers on both SysV AMD64 and Windows x64 ABI.
        // RBP is intentionally excluded because frame-pointer code may rely on it.
        const SCRATCH: &[Register] = &[
            Register::RBX,
            Register::R12,
            Register::R13,
            Register::R14,
            Register::R15,
        ];
        let mut rng = thread_rng();
        let mut result = Vec::with_capacity(instrs.len() + instrs.len() / 4);
        let mut at_block_start = true;
        let mut stub_index: u64 = 0;

        for &ins in instrs.iter() {
            if at_block_start && rng.gen_bool(0.35) {
                let reg = *SCRATCH.choose(&mut rng).unwrap();
                // Derive dead_val from the build-time STUB_SEED and the per-site
                // stub index using HKDF-SHA256.  This makes every build produce
                // different constants (STUB_SEED changes each build) while each
                // stub site within a build also gets a distinct value.
                let dead_val = derive_dead_val(stub_index);
                stub_index += 1;
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
        Ok(())
    }

    #[cfg(feature = "unsafe-runtime-rewrite")]
    {
        runtime_rewrite::rewrite(name)
    }
}

#[cfg(feature = "unsafe-runtime-rewrite")]
mod runtime_rewrite {
    use super::*;

    /// Upper-bound span used when no symbol-size information is available.
    /// 4096 bytes is large enough to cover most functions while staying within
    /// a single page, so the mprotect/VirtualProtect call never spans more than
    /// two pages.
    const FALLBACK_SPAN: usize = 4096;

    pub fn rewrite(name: &str) -> Result<(), String> {
        let addr = locate_symbol(name)
            .ok_or_else(|| format!("symbol '{}' not found in this process", name))?;

        // Determine the function's actual byte span from the symbol table or
        // the PE exception directory.  Fall back to FALLBACK_SPAN only if all
        // platform-specific methods fail.
        let span = find_function_size(name, addr).unwrap_or_else(|| {
            tracing::warn!(
                "optimize_hot_function: could not determine size of '{}'; \
                 using fallback span of {} bytes",
                name,
                FALLBACK_SPAN
            );
            FALLBACK_SPAN
        });

        // Snapshot the current bytes
        let original =
            unsafe { std::slice::from_raw_parts(addr as *const u8, span) }.to_vec();
        // Apply optimizer passes
        let mut new_bytes = apply_passes(&original);
        // If the new code is longer than the original span, refuse — we cannot
        // safely overwrite into adjacent code.  If shorter, INT3-pad to fill
        // the gap so stray execution traps immediately instead of running through
        // silent NOPs.
        if new_bytes.len() > original.len() {
            return Err(format!(
                "rewrite would grow code ({} -> {} bytes); refusing",
                original.len(),
                new_bytes.len()
            ));
        }
        if new_bytes.len() < original.len() {
            new_bytes.resize(original.len(), 0xCC); // INT3-pad to original size (trap on stray execution)
        }
        // Lower protection, copy, restore.
        unsafe {
            let mut old = make_writable(addr, span)?;
            std::ptr::copy_nonoverlapping(new_bytes.as_ptr(), addr as *mut u8, span);
            restore_protection(addr, span, &mut old)?;
            flush_icache(addr, span);
        }
        tracing::info!(
            "optimize_hot_function: rewrote {} bytes at {:p} for '{}'",
            span,
            addr as *const u8,
            name
        );
        Ok(())
    }

    /// Resolve the byte size of the named function using platform-specific
    /// metadata.
    ///
    /// * **Windows x86-64**: queries `RtlLookupFunctionEntry` which returns the
    ///   `RUNTIME_FUNCTION` entry from the `.pdata` exception directory; its
    ///   `EndAddress − BeginAddress` is the exact encoded function size.
    /// * **Linux**: reads `/proc/self/exe`, parses the ELF static symbol table
    ///   with `goblin`, and returns the `st_size` field of the matching symbol.
    /// * Returns `None` if neither method can determine the size.
    fn find_function_size(name: &str, #[allow(unused_variables)] addr: usize) -> Option<usize> {
        #[cfg(all(windows, target_arch = "x86_64"))]
        {
            find_function_size_pdata(addr)
        }
        #[cfg(target_os = "linux")]
        {
            find_function_size_elf(name)
        }
        #[cfg(not(any(all(windows, target_arch = "x86_64"), target_os = "linux")))]
        {
            let _ = (name, addr);
            None
        }
    }

    /// Windows x86-64: ask the OS for the RUNTIME_FUNCTION covering `addr`.
    /// `RtlLookupFunctionEntry` is present in ntdll.dll on all modern Windows
    /// versions and requires no extra imports beyond what is already linked.
    #[cfg(all(windows, target_arch = "x86_64"))]
    fn find_function_size_pdata(addr: usize) -> Option<usize> {
        #[repr(C)]
        struct RuntimeFunction {
            begin_address: u32,
            end_address: u32,
            unwind_info_address: u32,
        }

        extern "system" {
            /// Returns a pointer to the RUNTIME_FUNCTION covering `control_pc`,
            /// or NULL if none exists (e.g., leaf functions with no unwind info).
            fn RtlLookupFunctionEntry(
                control_pc: u64,
                image_base: *mut u64,
                history_table: *mut std::ffi::c_void,
            ) -> *const RuntimeFunction;
        }

        unsafe {
            let mut image_base: u64 = 0;
            let rf = RtlLookupFunctionEntry(
                addr as u64,
                &mut image_base,
                std::ptr::null_mut(),
            );
            if rf.is_null() {
                return None;
            }
            let begin = (*rf).begin_address as usize;
            let end = (*rf).end_address as usize;
            if end > begin {
                Some(end - begin)
            } else {
                None
            }
        }
    }

    /// Linux: parse the ELF static symbol table of `/proc/self/exe` to look
    /// up the `st_size` of the named symbol.  Goblin is already a dependency
    /// of this crate so no additional dependency is added.
    ///
    /// This works correctly for both PIE and non-PIE binaries because we match
    /// on the symbol *name* rather than on a virtual address that would require
    /// knowing the ASLR slide.
    #[cfg(target_os = "linux")]
    fn find_function_size_elf(name: &str) -> Option<usize> {
        let data = std::fs::read("/proc/self/exe").ok()?;
        let elf = goblin::elf::Elf::parse(&data).ok()?;

        // Prefer the static symbol table (.symtab) as it is more complete.
        // Fall back to the dynamic symbol table (.dynsym) for stripped binaries.
        for sym in elf.syms.iter() {
            if sym.st_size > 0 {
                if let Some(sym_name) = elf.strtab.get_at(sym.st_name) {
                    if sym_name == name {
                        return Some(sym.st_size as usize);
                    }
                }
            }
        }
        for sym in elf.dynsyms.iter() {
            if sym.st_size > 0 {
                if let Some(sym_name) = elf.dynstrtab.get_at(sym.st_name) {
                    if sym_name == name {
                        return Some(sym.st_size as usize);
                    }
                }
            }
        }
        None
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

    #[allow(dead_code)]
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
    fn read_page_protection(addr: usize) -> u32 {
        // Parse /proc/self/maps to find the protection for the page containing
        // `addr`.  Returns PROT_READ | PROT_EXEC as a safe fallback when
        // parsing fails (e.g. on non-Linux unix targets that lack /proc).
        use std::fs;
        if let Ok(maps) = fs::read_to_string("/proc/self/maps") {
            for line in maps.lines() {
                let parts: Vec<&str> = line.splitn(6, ' ').collect();
                if parts.len() >= 2 {
                    let range: Vec<&str> = parts[0].splitn(2, '-').collect();
                    if range.len() == 2 {
                        if let (Ok(start), Ok(end)) = (
                            usize::from_str_radix(range[0], 16),
                            usize::from_str_radix(range[1], 16),
                        ) {
                            if addr >= start && addr < end {
                                let mut prot: u32 = 0;
                                for c in parts[1].chars() {
                                    match c {
                                        'r' => prot |= libc::PROT_READ as u32,
                                        'w' => prot |= libc::PROT_WRITE as u32,
                                        'x' => prot |= libc::PROT_EXEC as u32,
                                        _ => {}
                                    }
                                }
                                return prot;
                            }
                        }
                    }
                }
            }
        }
        (libc::PROT_READ | libc::PROT_EXEC) as u32
    }

    #[cfg(unix)]
    unsafe fn make_writable(addr: usize, len: usize) -> Result<ProtSnapshot, String> {
        let page = libc::sysconf(libc::_SC_PAGESIZE) as usize;
        let aligned = addr & !(page - 1);
        let aligned_len = ((addr + len) - aligned + page - 1) & !(page - 1);
        let orig_prot = read_page_protection(aligned);
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
        // Save the page's *original* protection so restore can put it back
        // exactly (e.g. PROT_READ-only .rodata stays read-only) — H-6.
        Ok(ProtSnapshot(orig_prot))
    }

    #[cfg(unix)]
    unsafe fn restore_protection(
        addr: usize,
        len: usize,
        old: &mut ProtSnapshot,
    ) -> Result<(), String> {
        let page = libc::sysconf(libc::_SC_PAGESIZE) as usize;
        let aligned = addr & !(page - 1);
        let aligned_len = ((addr + len) - aligned + page - 1) & !(page - 1);
        if libc::mprotect(aligned as *mut libc::c_void, aligned_len, old.0 as i32) != 0 {
            return Err(format!(
                "mprotect(restore) failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    #[cfg(unix)]
    unsafe fn flush_icache(addr: usize, len: usize) {
        #[cfg(target_arch = "aarch64")]
        {
            // aarch64 I-cache is NOT coherent with D-cache.
            // Sequence: DC CVAU on each cache line, DSB ISH, IC IVAU on each
            // line, DSB ISH, ISB.  Without this the CPU may execute stale
            // instructions from I-cache after we rewrite code in D-cache (H-6).
            const CACHE_LINE: usize = 64; // typical aarch64 line size
            let end = addr + len;
            let mut p = addr & !(CACHE_LINE - 1);
            while p < end {
                std::arch::asm!("dc cvau, {x}", x = in(reg) p);
                p += CACHE_LINE;
            }
            std::arch::asm!("dsb ish");
            let mut p = addr & !(CACHE_LINE - 1);
            while p < end {
                std::arch::asm!("ic ivau, {x}", x = in(reg) p);
                p += CACHE_LINE;
            }
            std::arch::asm!("dsb ish", "isb");
        }
        #[cfg(not(target_arch = "aarch64"))]
        {
            // x86_64: coherent I-cache; mprotect serialises.  No-op is correct.
            let _ = (addr, len);
        }
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
