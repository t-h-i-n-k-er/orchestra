//! Shellcode emitter — assembles the full position-independent loader.
//!
//! The emitted blob has the following layout:
//!
//! ```text
//! ┌──────────────────────────────────┐
//! │  Loader prologue                 │
//! │  ┌────────────────────────────┐  │
//! │  │ save registers             │  │
//! │  │ get RIP → base register    │  │
//! │  │ compute PE image base      │  │
//! │  │ apply relocation fixups    │  │
//! │  │ resolve imports (PEB walk) │  │
//! │  │ restore registers          │  │
//! │  │ jump to entry point        │  │
//! │  └────────────────────────────┘  │
//! │                                  │
//! │  Inline PEB-walk resolver        │
//! │                                  │
//! │  PE image (mapped, raw bytes)    │
//! └──────────────────────────────────┘
//! ```

use crate::pe::{ImportFunc, PeImage};
use crate::x86::Emitter;
use anyhow::Result;

/// Configuration for shellcode generation.
#[derive(Debug, Clone)]
pub struct EmitterConfig {
    /// Register used to hold the loader's own base address.
    /// Default: R12 (callee-saved, rarely used by C code).
    pub base_reg: u8,
    /// Register used as scratch for fixups.
    /// Default: R11 (volatile, scratch).
    pub scratch_reg: u8,
    /// Seed for diversity / randomization.
    pub seed: u64,
}

impl Default for EmitterConfig {
    fn default() -> Self {
        Self {
            base_reg: Emitter::R12,
            scratch_reg: Emitter::R11,
            seed: 0,
        }
    }
}

/// Build the PIC shellcode loader for a parsed PE image.
pub fn emit_loader(pe: &PeImage, config: &EmitterConfig) -> Result<Vec<u8>> {
    let mut main = Emitter::new();
    let base = config.base_reg;
    let scratch = config.scratch_reg;
    let scratch2 = Emitter::R10;

    // Build the PEB-walk resolver function
    let resolver = build_resolver_function();

    // ── Step 1: Save callee-saved registers ────────────────────────────
    main.push(Emitter::RBX);
    main.push(Emitter::RSI);
    main.push(Emitter::RDI);
    main.push(Emitter::R12);
    main.push(Emitter::R13);
    main.push(Emitter::R14);
    main.push(Emitter::R15);

    // ── Step 2: Get our own base address ───────────────────────────────
    let _after_get_rip = main.get_rip(base);
    // base_reg now holds the absolute address of the byte after the pop

    // ── Step 3: Compute PE image base ──────────────────────────────────
    // Forward LEA: scratch = &pe_image (patched later)
    let (pe_lea_patch, pe_lea_end) = main.forward_lea_rip(scratch);
    main.mov_r64_r64(Emitter::RBX, scratch); // RBX = PE image base

    // ── Step 4: Apply relocations ──────────────────────────────────────
    for rel in &pe.relocations {
        let rva = rel.rva;
        match rel.rel_type {
            10 => {
                // IMAGE_REL_BASED_DIR64
                emit_lea_rbx_plus_rva(&mut main, scratch, rva);
                main.mov_r64_mr64(scratch2, scratch, 0);
                main.add_r64_r64(scratch2, Emitter::RBX);
                emit_sub_u64(&mut main, scratch2, pe.image_base, scratch);
                main.mov_mr64_r64(scratch, 0, scratch2);
            }
            3 => {
                // IMAGE_REL_BASED_HIGHLOW
                emit_lea_rbx_plus_rva(&mut main, scratch, rva);
                main.mov_r64_mr64(scratch2, scratch, 0);
                main.add_r64_r64(scratch2, Emitter::RBX);
                emit_sub_u64(&mut main, scratch2, pe.image_base, scratch);
                emit_mov_dword_indirect(&mut main, scratch, scratch2);
            }
            _ => {}
        }
    }

    // ── Step 5: Resolve imports via PEB walk ───────────────────────────
    main.push(Emitter::RAX);
    main.push(Emitter::RCX);
    main.push(Emitter::RDX);
    main.push(Emitter::R8);
    main.push(Emitter::R9);
    main.push(Emitter::R10);
    main.push(Emitter::R11);

    // Collect call-site patches for the resolver
    let mut call_patches: Vec<(usize, usize)> = Vec::new();

    for dll in &pe.imports {
        let dll_hash = pe_resolve::hash_str(dll.dll_name.to_uppercase().as_bytes());
        for func in &dll.functions {
            main.mov_r64_imm32(Emitter::RCX, dll_hash);
            match func {
                ImportFunc::ByName { name, thunk_rva } => {
                    let func_hash = pe_resolve::hash_str(name.as_bytes());
                    main.mov_r64_imm32(Emitter::RDX, func_hash);
                    let (patch, end) = main.forward_call();
                    call_patches.push((patch, end));
                    main.mov_mr64_r64(Emitter::RBX, *thunk_rva as i32, Emitter::RAX);
                }
                ImportFunc::ByOrdinal { ordinal, thunk_rva } => {
                    main.mov_r64_imm32(Emitter::RDX, (*ordinal as u32) | 0x80000000);
                    let (patch, end) = main.forward_call();
                    call_patches.push((patch, end));
                    main.mov_mr64_r64(Emitter::RBX, *thunk_rva as i32, Emitter::RAX);
                }
            }
        }
    }

    main.pop(Emitter::R11);
    main.pop(Emitter::R10);
    main.pop(Emitter::R9);
    main.pop(Emitter::R8);
    main.pop(Emitter::RDX);
    main.pop(Emitter::RCX);
    main.pop(Emitter::RAX);

    // ── Step 6: Jump to entry point ────────────────────────────────────
    emit_lea_rbx_plus_rva(&mut main, scratch, pe.entry_point_rva);
    main.jmp_r64(scratch);

    // ── Step 7: Emit resolver function ─────────────────────────────────
    let resolver_offset = main.len();
    for (patch, end) in &call_patches {
        main.patch_rel32(*patch, resolver_offset, *end);
    }
    main.emit_bytes(&resolver);

    // ── Step 8: Patch the PE image LEA ─────────────────────────────────
    let pe_image_offset = main.len();
    main.patch_rip_disp(pe_lea_patch, pe_image_offset, pe_lea_end);

    // ── Step 9: Append the PE image ────────────────────────────────────
    let mapped = pe.mapped_image();
    main.emit_bytes(&mapped);

    Ok(main.into_vec())
}

// ── Helper emitters ──────────────────────────────────────────────────────────

/// `lea reg, [rbx + rva]`
fn emit_lea_rbx_plus_rva(e: &mut Emitter, reg: u8, rva: u32) {
    e.rex_w(reg, Emitter::RBX);
    e.emit_byte(0x8D);
    e.emit_byte(Emitter::modrm(2, reg, Emitter::RBX));
    e.emit_u32_le(rva);
}

/// Subtract a 64-bit constant from `reg`. Uses `tmp` as scratch if needed.
fn emit_sub_u64(e: &mut Emitter, reg: u8, val: u64, tmp: u8) {
    if val <= 0x7FFFFFFF {
        e.sub_r64_imm32(reg, val as u32);
    } else {
        e.push(tmp);
        e.mov_r64_imm64(tmp, val);
        e.rex_w(tmp, reg);
        e.emit_byte(0x29);
        e.emit_byte(Emitter::modrm(3, tmp, reg));
        e.pop(tmp);
    }
}

/// `mov dword [base], src_lo32` — writes the low 32 bits of `src` to `[base]`.
fn emit_mov_dword_indirect(e: &mut Emitter, base: u8, src: u8) {
    let need_rex = base >= 8 || src >= 8;
    if need_rex {
        let mut rex = 0x40u8;
        if src >= 8 { rex |= 0x04; }
        if base >= 8 { rex |= 0x01; }
        e.emit_byte(rex);
    }
    e.emit_byte(0x89);
    e.emit_byte(Emitter::modrm(1, src, base));
    e.emit_byte(0x00);
}

/// Build the inline PEB-walk resolver function.
///
/// ABI:
///   - Input: RCX = DLL name hash (ROR-13), RDX = function name hash (ROR-13)
///   - If bit 31 of RDX is set: RDX[0:15] = ordinal number
///   - Output: RAX = resolved function address (0 on failure)
///   - Clobbers: R8-R11, flags. Preserves RBX, RSI, RDI, RBP, R12-R15.
fn build_resolver_function() -> Vec<u8> {
    let mut e = Emitter::new();

    // Save callee-saved
    e.push(Emitter::RBP);
    e.push(Emitter::RBX);
    e.push(Emitter::RSI);
    e.push(Emitter::RDI);
    e.push(Emitter::R14); // dll_hash
    e.push(Emitter::R15); // func_hash

    e.mov_r64_r64(Emitter::R14, Emitter::RCX);
    e.mov_r64_r64(Emitter::R15, Emitter::RDX);

    // ── PEB walk: find DLL by hash ────────────────────────────────────
    emit_gs_load(&mut e, Emitter::RAX, 0x60);         // PEB
    emit_load_indirect(&mut e, Emitter::RAX, Emitter::RAX, 0x18);  // Ldr
    emit_load_indirect(&mut e, Emitter::RAX, Emitter::RAX, 0x20);  // InMemoryOrderModuleList
    e.mov_r64_r64(Emitter::RDI, Emitter::RAX);         // list head

    // ── Module loop ───────────────────────────────────────────────────
    let mod_loop = e.len();
    emit_load_indirect(&mut e, Emitter::RAX, Emitter::RAX, 0);     // Flink

    e.cmp_r64_imm32(Emitter::RAX, 0);
    let (jz_ret0_a, jz_ret0_a_end) = e.forward_je();
    emit_cmp_reg_reg(&mut e, Emitter::RDI, Emitter::RAX);
    let (jz_ret0_b, jz_ret0_b_end) = e.forward_je();

    // Hash module name: length at [rax+0x48], buffer at [rax+0x50]
    emit_load_indirect(&mut e, Emitter::RSI, Emitter::RAX, 0x48);  // name byte length
    emit_load_indirect(&mut e, Emitter::RBX, Emitter::RAX, 0x50);  // name buffer

    e.xor_r32_r32(Emitter::R8, Emitter::R8);   // hash = 0
    e.xor_r32_r32(Emitter::R9, Emitter::R9);   // i = 0
    e.shr_r64_imm8(Emitter::RSI, 1);            // char_count = byte_len / 2

    // Check for empty name
    e.cmp_r64_imm32(Emitter::RSI, 0);
    let (je_skip_hash_patch, je_skip_hash_end) = e.forward_je();

    let hash_loop = e.len();
    emit_cmp_reg_reg(&mut e, Emitter::RSI, Emitter::R9);
    let (hash_done_jmp, hash_done_jmp_end) = e.forward_jbe();

    // Load u16 char at buf[i*2]
    emit_load_u16_at_index(&mut e, Emitter::RBX, Emitter::R9, Emitter::R10, Emitter::RCX);
    emit_uppercase_16(&mut e, Emitter::RCX);
    emit_ror13_add(&mut e, Emitter::R8, Emitter::RCX, Emitter::R10, Emitter::R11);
    e.inc_r64(Emitter::R9);

    // jmp hash_loop
    let p = e.jmp_rel32_placeholder();
    e.patch_rel32(p, hash_loop, e.len());

    // hash_done:
    let hash_done = e.len();
    e.patch_rel32(hash_done_jmp, hash_done, hash_done_jmp_end);

    // je_skip_hash: skip the hash comparison for empty names
    let skip_hash = e.len();
    e.patch_rel32(je_skip_hash_patch, skip_hash, je_skip_hash_end);

    // Final ROR13 (if not skipped due to empty name, which would have hash=0 anyway)
    // Only do final ror13 if we actually hashed something
    // Actually we always need the final ror13 per the algorithm
    // But if empty name we skip — that's fine, the empty module won't match

    // For non-empty names: apply final ROR13
    // We need a conditional jump over the final ror13 for the empty case
    // Let's restructure: emit final ror13 before the skip_hash label
    // Actually, let me just always emit it — it's harmless for hash=0
    emit_ror13(&mut e, Emitter::R8, Emitter::R10, Emitter::R11);

    // Move skip_hash to after the final ror13
    // (We already patched je_skip_hash to skip_hash which is below)

    // Compare hash with dll_hash (r14)
    emit_cmp_reg_reg(&mut e, Emitter::R14, Emitter::R8);
    let (hash_mismatch_jmp, hash_mismatch_jmp_end) = e.forward_jne();

    // Match! DllBase at [rax + 0x20]
    emit_load_indirect(&mut e, Emitter::RBX, Emitter::RAX, 0x20);

    // ── Export table walk ─────────────────────────────────────────────
    // Check ordinal import
    e.mov_r64_r64(Emitter::RAX, Emitter::R15);
    e.shr_r64_imm8(Emitter::RAX, 31);
    e.cmp_r64_imm32(Emitter::RAX, 1);
    let (ordinal_resolve_jmp, ordinal_resolve_jmp_end) = e.forward_je();

    // ── Name hash resolution ──────────────────────────────────────────
    // Parse export directory
    emit_load_indirect(&mut e, Emitter::RAX, Emitter::RBX, 0x3C);  // e_lfanew
    e.add_r64_r64(Emitter::RAX, Emitter::RBX);                       // NT headers
    e.add_r64_imm32(Emitter::RAX, 24 + 112);                         // &export_dir_rva
    emit_load_indirect(&mut e, Emitter::RAX, Emitter::RAX, 0);       // export dir RVA
    e.cmp_r64_imm32(Emitter::RAX, 0);
    let (no_export_jmp, no_export_jmp_end) = e.forward_je();

    e.add_r64_r64(Emitter::RAX, Emitter::RBX);  // export_dir addr
    e.mov_r64_r64(Emitter::RSI, Emitter::RAX);  // rsi = export_dir

    emit_load_indirect(&mut e, Emitter::R11, Emitter::RSI, 24);     // NumberOfNames
    emit_load_indirect(&mut e, Emitter::R10, Emitter::RSI, 32);     // AddressOfNames RVA
    e.add_r64_r64(Emitter::R10, Emitter::RBX);                       // abs
    emit_load_indirect(&mut e, Emitter::RDI, Emitter::RSI, 28);     // AddressOfFunctions RVA
    e.add_r64_r64(Emitter::RDI, Emitter::RBX);
    emit_load_indirect(&mut e, Emitter::R8, Emitter::RSI, 36);      // AddressOfNameOrdinals RVA
    e.add_r64_r64(Emitter::R8, Emitter::RBX);

    e.xor_r32_r32(Emitter::R9, Emitter::R9); // i = 0

    let export_loop = e.len();
    emit_cmp_reg_reg(&mut e, Emitter::R11, Emitter::R9);
    let (not_found_jmp, not_found_jmp_end) = e.forward_jbe();

    // Load name RVA: rax = names[i]
    e.mov_r64_r64(Emitter::RAX, Emitter::R9);
    e.add_r64_r64(Emitter::RAX, Emitter::RAX);  // *2
    e.add_r64_r64(Emitter::RAX, Emitter::RAX);  // *4
    e.add_r64_r64(Emitter::RAX, Emitter::R10);  // &names[i]
    emit_load_indirect(&mut e, Emitter::RAX, Emitter::RAX, 0);
    e.add_r64_r64(Emitter::RAX, Emitter::RBX);  // name string

    // Hash export name (ASCII)
    e.xor_r32_r32(Emitter::RDX, Emitter::RDX); // hash = 0
    e.mov_r64_r64(Emitter::RCX, Emitter::RAX);

    let name_hash_loop = e.len();
    e.xor_r32_r32(Emitter::RAX, Emitter::RAX);
    e.rex_w(0, Emitter::RCX);
    e.emit_byte(0x0F);
    e.emit_byte(0xB6); // MOVZX r32, r/m8
    e.emit_byte(Emitter::modrm(1, Emitter::RAX, Emitter::RCX));
    e.emit_byte(0x00);

    e.cmp_r64_imm32(Emitter::RAX, 0);
    let (name_hash_done_jmp, name_hash_done_jmp_end) = e.forward_je();

    emit_uppercase_8(&mut e, Emitter::RAX);
    emit_ror13_add(&mut e, Emitter::RDX, Emitter::RAX, Emitter::RSI, Emitter::R12);
    e.inc_r64(Emitter::RCX);

    let p = e.jmp_rel32_placeholder();
    e.patch_rel32(p, name_hash_loop, e.len());

    let name_hash_done = e.len();
    e.patch_rel32(name_hash_done_jmp, name_hash_done, name_hash_done_jmp_end);
    emit_ror13(&mut e, Emitter::RDX, Emitter::RSI, Emitter::R12);

    // Compare with func_hash (r15)
    emit_cmp_reg_reg(&mut e, Emitter::R15, Emitter::RDX);
    let (name_mismatch_jmp, name_mismatch_jmp_end) = e.forward_jne();

    // Found! Get ordinal: ordinal = ordinals[i]
    e.mov_r64_r64(Emitter::RAX, Emitter::R9);
    e.add_r64_r64(Emitter::RAX, Emitter::RAX);  // *2
    e.add_r64_r64(Emitter::RAX, Emitter::R8);   // &ordinals[i]
    e.rex_w(0, Emitter::RAX);
    e.emit_byte(0x0F);
    e.emit_byte(0xB7); // MOVZX r32, r/m16
    e.emit_byte(Emitter::modrm(1, Emitter::RAX, Emitter::RAX));
    e.emit_byte(0x00);

    // function_rva = functions[ordinal]
    e.add_r64_r64(Emitter::RAX, Emitter::RAX);  // *2
    e.add_r64_r64(Emitter::RAX, Emitter::RAX);  // *4
    e.add_r64_r64(Emitter::RAX, Emitter::RDI);  // &functions[ordinal]
    emit_load_indirect(&mut e, Emitter::RAX, Emitter::RAX, 0);
    e.add_r64_r64(Emitter::RAX, Emitter::RBX);

    // Return
    let ret_label = e.len();
    e.pop(Emitter::R15);
    e.pop(Emitter::R14);
    e.pop(Emitter::RDI);
    e.pop(Emitter::RSI);
    e.pop(Emitter::RBX);
    e.pop(Emitter::RBP);
    e.ret();

    // ── name_mismatch: i++ ────────────────────────────────────────────
    let name_mismatch_label = e.len();
    e.patch_rel32(name_mismatch_jmp, name_mismatch_label, name_mismatch_jmp_end);
    e.inc_r64(Emitter::R9);
    let p = e.jmp_rel32_placeholder();
    e.patch_rel32(p, export_loop, e.len());

    // ── not_found ─────────────────────────────────────────────────────
    let not_found_label = e.len();
    e.patch_rel32(not_found_jmp, not_found_label, not_found_jmp_end);
    emit_return_zero(&mut e, ret_label);

    // ── no_export ─────────────────────────────────────────────────────
    let no_export_label = e.len();
    e.patch_rel32(no_export_jmp, no_export_label, no_export_jmp_end);
    emit_return_zero(&mut e, ret_label);

    // ── ordinal_resolve ───────────────────────────────────────────────
    let ordinal_resolve_label = e.len();
    e.patch_rel32(ordinal_resolve_jmp, ordinal_resolve_label, ordinal_resolve_jmp_end);
    emit_ordinal_resolver(&mut e, ret_label);

    // ── hash_mismatch: continue module loop ───────────────────────────
    let hash_mismatch_label = e.len();
    e.patch_rel32(hash_mismatch_jmp, hash_mismatch_label, hash_mismatch_jmp_end);
    let p = e.jmp_rel32_placeholder();
    e.patch_rel32(p, mod_loop, e.len());

    // ── ret0: return 0 ────────────────────────────────────────────────
    let ret0_label = e.len();
    e.patch_rel32(jz_ret0_a, ret0_label, jz_ret0_a_end);
    e.patch_rel32(jz_ret0_b, ret0_label, jz_ret0_b_end);
    emit_return_zero(&mut e, ret_label);

    e.into_vec()
}

/// Emit `xor rax, rax; jmp ret_label`
fn emit_return_zero(e: &mut Emitter, ret_label: usize) {
    e.xor_r32_r32(Emitter::RAX, Emitter::RAX);
    let p = e.jmp_rel32_placeholder();
    e.patch_rel32(p, ret_label, e.len());
}

/// Emit ordinal-based export resolution.
fn emit_ordinal_resolver(mut e: &mut Emitter, ret_label: usize) {
    // Parse export directory from RBX (DllBase)
    emit_load_indirect(&mut e, Emitter::RAX, Emitter::RBX, 0x3C);
    e.add_r64_r64(Emitter::RAX, Emitter::RBX);
    e.add_r64_imm32(Emitter::RAX, 24 + 112);
    emit_load_indirect(&mut e, Emitter::RAX, Emitter::RAX, 0);
    e.cmp_r64_imm32(Emitter::RAX, 0);
    let (no_export_jmp, no_export_jmp_end) = e.forward_je();

    e.add_r64_r64(Emitter::RAX, Emitter::RBX);
    // Base = [export_dir + 16]
    emit_load_indirect(&mut e, Emitter::RSI, Emitter::RAX, 16);
    // NumberOfFunctions = [export_dir + 20]
    emit_load_indirect(&mut e, Emitter::R11, Emitter::RAX, 20);
    // AddressOfFunctions = [export_dir + 28]
    emit_load_indirect(&mut e, Emitter::RDI, Emitter::RAX, 28);
    e.add_r64_r64(Emitter::RDI, Emitter::RBX);

    // ordinal = r15 & 0xFFFF
    e.mov_r64_r64(Emitter::RAX, Emitter::R15);
    e.and_r64_imm32(Emitter::RAX, 0xFFFF);
    // index = ordinal - base
    emit_sub_reg_reg(&mut e, Emitter::RAX, Emitter::RSI);

    // Bounds check
    emit_cmp_reg_reg(&mut e, Emitter::R11, Emitter::RAX);
    let (oob_jmp, oob_jmp_end) = e.forward_jbe();

    // functions[index]
    e.add_r64_r64(Emitter::RAX, Emitter::RAX);
    e.add_r64_r64(Emitter::RAX, Emitter::RAX);
    e.add_r64_r64(Emitter::RAX, Emitter::RDI);
    emit_load_indirect(&mut e, Emitter::RAX, Emitter::RAX, 0);
    e.add_r64_r64(Emitter::RAX, Emitter::RBX);
    let p = e.jmp_rel32_placeholder();
    e.patch_rel32(p, ret_label, e.len());

    // oob
    let oob_label = e.len();
    e.patch_rel32(oob_jmp, oob_label, oob_jmp_end);
    emit_return_zero(e, ret_label);

    // no_export
    let no_export_label = e.len();
    e.patch_rel32(no_export_jmp, no_export_label, no_export_jmp_end);
    emit_return_zero(e, ret_label);
}

// ── Primitive emitters ───────────────────────────────────────────────────────

/// `mov r64, gs:[offset]`
fn emit_gs_load(e: &mut Emitter, reg: u8, offset: u32) {
    e.emit_byte(0x65); // GS segment override
    e.rex_w(0, reg);
    e.emit_byte(0x8B);
    e.emit_byte(Emitter::modrm(2, reg, 5)); // RIP-relative with GS override
    e.emit_u32_le(offset);
}

/// `mov dst, [base + offset]`
fn emit_load_indirect(e: &mut Emitter, dst: u8, base: u8, offset: i32) {
    e.mov_r64_mr64(dst, base, offset);
}

/// `cmp r64, r64`
fn emit_cmp_reg_reg(e: &mut Emitter, a: u8, b: u8) {
    e.rex_w(a, b);
    e.emit_byte(0x39);
    e.emit_byte(Emitter::modrm(3, a, b));
}

/// `sub dst, src` (64-bit)
fn emit_sub_reg_reg(e: &mut Emitter, dst: u8, src: u8) {
    e.rex_w(src, dst);
    e.emit_byte(0x29);
    e.emit_byte(Emitter::modrm(3, src, dst));
}

/// Load u16 at `base[index*2]` into `dst`. Uses `tmp` as scratch.
fn emit_load_u16_at_index(e: &mut Emitter, base: u8, index: u8, tmp: u8, dst: u8) {
    e.mov_r64_r64(tmp, index);
    e.add_r64_r64(tmp, tmp);
    e.add_r64_r64(tmp, base);
    e.xor_r32_r32(dst, dst);
    e.rex_w(0, tmp);
    e.emit_byte(0x0F);
    e.emit_byte(0xB7);
    e.emit_byte(Emitter::modrm(1, dst, tmp));
    e.emit_byte(0x00);
}

/// Uppercase a u16 char in `reg` (if 'a'-'z').
fn emit_uppercase_16(e: &mut Emitter, reg: u8) {
    e.cmp_r64_imm32(reg, 0x61);
    let (jb, jb_end) = e.forward_jb();
    e.cmp_r64_imm32(reg, 0x7A);
    let (ja, ja_end) = e.forward_ja();
    e.sub_r64_imm32(reg, 0x20);
    let done = e.len();
    e.patch_rel32(jb, done, jb_end);
    e.patch_rel32(ja, done, ja_end);
}

/// Uppercase a byte in `reg` (if 'a'-'z').
fn emit_uppercase_8(e: &mut Emitter, reg: u8) {
    e.cmp_r64_imm32(reg, 0x61);
    let (jb, jb_end) = e.forward_jb();
    e.cmp_r64_imm32(reg, 0x7A);
    let (ja, ja_end) = e.forward_ja();
    e.sub_r64_imm32(reg, 0x20);
    let done = e.len();
    e.patch_rel32(jb, done, jb_end);
    e.patch_rel32(ja, done, ja_end);
}

/// `hash = ror13(hash) + val`. Clobbers `tmp`, `tmp2`.
fn emit_ror13_add(e: &mut Emitter, hash: u8, val: u8, tmp: u8, tmp2: u8) {
    emit_ror13(e, hash, tmp, tmp2);
    e.add_r64_r64(hash, val);
}

/// `hash = ror13(hash)`. Clobbers `tmp`, `tmp2`.
fn emit_ror13(e: &mut Emitter, hash: u8, tmp: u8, tmp2: u8) {
    e.mov_r64_r64(tmp, hash);
    e.shr_r64_imm8(tmp, 13);
    e.mov_r64_r64(tmp2, hash);
    e.rex_w(0, tmp2);
    e.emit_byte(0xC1);
    e.emit_byte(Emitter::modrm(3, 4, tmp2)); // SHL
    e.emit_byte(19);
    // tmp |= tmp2
    e.rex_w(tmp2, tmp);
    e.emit_byte(0x09);
    e.emit_byte(Emitter::modrm(3, tmp2, tmp));
    e.mov_r64_r64(hash, tmp);
}
