//! Minimal x86_64 machine-code emitter for the shellcode loader stub.
//!
//! This module builds position-independent x86_64 code using raw byte emission.
//! All addressing is RIP-relative; no absolute addresses appear in the emitted
//! code except as data that gets patched at runtime.

/// Low-level x86_64 instruction emitter.
pub struct Emitter {
    buf: Vec<u8>,
}

impl Emitter {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Consume the emitter and return the raw bytes.
    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }

    /// Current position (offset from start of emitted code).
    pub fn position(&self) -> usize {
        self.buf.len()
    }

    // ── Raw byte emission ─────────────────────────────────────────────────

    pub fn emit_byte(&mut self, b: u8) {
        self.buf.push(b);
    }

    pub fn emit_bytes(&mut self, bs: &[u8]) {
        self.buf.extend_from_slice(bs);
    }

    pub fn emit_u32_le(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn emit_u64_le(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    // ── REX prefix helpers ────────────────────────────────────────────────

    /// Emit REX prefix with W=1 (64-bit operand size) if needed.
    /// `r` and `m` are register indices 0-15 (low 3 bits + R/X/B extensions).
    pub fn rex_w(&mut self, r: u8, m: u8) {
        let mut rex = 0x48u8; // REX.W
        if r >= 8 {
            rex |= 0x04; // REX.R
        }
        if m >= 8 {
            rex |= 0x01; // REX.B
        }
        self.emit_byte(rex);
    }

    /// Emit REX prefix (optional, with W=1) — always emits for clarity.
    fn rex_w_rx(&mut self, r: u8, x: u8, b: u8) {
        let mut rex = 0x48u8; // REX.W
        if r >= 8 { rex |= 0x04; }
        if x >= 8 { rex |= 0x02; }
        if b >= 8 { rex |= 0x01; }
        self.emit_byte(rex);
    }

    /// ModRM byte: mod(2) | reg(3) | rm(3)
    pub fn modrm(mod_: u8, reg: u8, rm: u8) -> u8 {
        (mod_ << 6) | ((reg & 7) << 3) | (rm & 7)
    }

    /// SIB byte: scale(2) | index(3) | base(3)
    fn sib(scale: u8, index: u8, base: u8) -> u8 {
        (scale << 6) | ((index & 7) << 3) | (base & 7)
    }

    // ── Standard registers ────────────────────────────────────────────────

    // RAX=0, RCX=1, RDX=2, RBX=3, RSP=4, RBP=5, RSI=6, RDI=7
    // R8=8, R9=9, R10=10, R11=11, R12=12, R13=13, R14=14, R15=15

    pub const RAX: u8 = 0;
    pub const RCX: u8 = 1;
    pub const RDX: u8 = 2;
    pub const RBX: u8 = 3;
    pub const RSP: u8 = 4;
    pub const RBP: u8 = 5;
    pub const RSI: u8 = 6;
    pub const RDI: u8 = 7;
    pub const R8: u8 = 8;
    pub const R9: u8 = 9;
    pub const R10: u8 = 10;
    pub const R11: u8 = 11;
    pub const R12: u8 = 12;
    pub const R13: u8 = 13;
    pub const R14: u8 = 14;
    pub const R15: u8 = 15;

    // ── Instruction emitters ──────────────────────────────────────────────

    /// `push r64`
    pub fn push(&mut self, reg: u8) {
        if reg >= 8 {
            self.emit_byte(0x41);
        }
        self.emit_byte(0x50 + (reg & 7));
    }

    /// `pop r64`
    pub fn pop(&mut self, reg: u8) {
        if reg >= 8 {
            self.emit_byte(0x41);
        }
        self.emit_byte(0x58 + (reg & 7));
    }

    /// `mov r64, imm64` — 10-byte instruction.
    pub fn mov_r64_imm64(&mut self, reg: u8, imm: u64) {
        self.rex_w(0, reg);
        self.emit_byte(0xB8 + (reg & 7));
        self.emit_u64_le(imm);
    }

    /// `mov r64, imm32` (zero-extended) — 7-byte instruction.
    pub fn mov_r64_imm32(&mut self, reg: u8, imm: u32) {
        self.rex_w(0, reg);
        self.emit_byte(0xC7);
        self.emit_byte(Self::modrm(3, 0, reg));
        self.emit_u32_le(imm);
    }

    /// `mov r64, r64`
    pub fn mov_r64_r64(&mut self, dst: u8, src: u8) {
        self.rex_w(src, dst);
        self.emit_byte(0x89);
        self.emit_byte(Self::modrm(3, src, dst));
    }

    /// `lea r64, [rip + disp32]` — loads a RIP-relative address into a register.
    /// The displacement is computed as `target_offset - (current_offset + 7)`.
    /// Use `lea_rip_placeholder()` and `patch_rip_displacement()` if the
    /// target is not yet known.
    pub fn lea_rip(&mut self, reg: u8, disp: i32) {
        self.rex_w(0, reg);
        self.emit_byte(0x8D);
        self.emit_byte(Self::modrm(0, reg, 5)); // mod=00, rm=101 → RIP-relative
        self.emit_u32_le(disp as u32);
    }

    /// `lea r64, [rip + disp32]` with a placeholder displacement of 0.
    /// Returns the offset of the displacement for later patching.
    pub fn lea_rip_placeholder(&mut self, reg: u8) -> usize {
        self.rex_w(0, reg);
        self.emit_byte(0x8D);
        self.emit_byte(Self::modrm(0, reg, 5));
        let patch_off = self.buf.len();
        self.emit_u32_le(0); // placeholder
        patch_off
    }

    /// Patch a previously emitted RIP-relative displacement.
    pub fn patch_rip_disp(&mut self, patch_off: usize, target_abs: usize, instr_end: usize) {
        let disp = (target_abs as isize - instr_end as isize) as i32;
        self.buf[patch_off..patch_off + 4].copy_from_slice(&disp.to_le_bytes());
    }

    /// `sub r64, imm32`
    pub fn sub_r64_imm32(&mut self, reg: u8, imm: u32) {
        self.rex_w(0, reg);
        self.emit_byte(0x81);
        self.emit_byte(Self::modrm(3, 5, reg));
        self.emit_u32_le(imm);
    }

    /// `add r64, imm32`
    pub fn add_r64_imm32(&mut self, reg: u8, imm: u32) {
        self.rex_w(0, reg);
        self.emit_byte(0x81);
        self.emit_byte(Self::modrm(3, 0, reg));
        self.emit_u32_le(imm);
    }

    /// `add r64, r64`
    pub fn add_r64_r64(&mut self, dst: u8, src: u8) {
        self.rex_w(src, dst);
        self.emit_byte(0x01);
        self.emit_byte(Self::modrm(3, src, dst));
    }

    /// `cmp r64, r64`
    pub fn cmp_r64_r64(&mut self, a: u8, b: u8) {
        self.rex_w(a, b);
        self.emit_byte(0x39);
        self.emit_byte(Self::modrm(3, a, b));
    }

    /// `cmp r64, imm32`
    pub fn cmp_r64_imm32(&mut self, reg: u8, imm: u32) {
        self.rex_w(0, reg);
        self.emit_byte(0x81);
        self.emit_byte(Self::modrm(3, 7, reg));
        self.emit_u32_le(imm);
    }

    /// `test r32, r32` (32-bit operand — shorter encoding, tests low 32 bits).
    pub fn test_r32_r32(&mut self, a: u8, b: u8) {
        // No REX.W — 32-bit test
        let need_rex = a >= 8 || b >= 8;
        if need_rex {
            let mut rex = 0x40u8;
            if a >= 8 { rex |= 0x04; }
            if b >= 8 { rex |= 0x01; }
            self.emit_byte(rex);
        }
        self.emit_byte(0x85);
        self.emit_byte(Self::modrm(3, a, b));
    }

    /// `jmp rel32` — relative jump.
    /// Returns the offset of the displacement for patching.
    pub fn jmp_rel32_placeholder(&mut self) -> usize {
        self.emit_byte(0xE9);
        let patch_off = self.buf.len();
        self.emit_u32_le(0); // placeholder
        patch_off
    }

    /// `je rel32` — jump if equal.
    pub fn je_rel32_placeholder(&mut self) -> usize {
        self.emit_byte(0x0F);
        self.emit_byte(0x84);
        let patch_off = self.buf.len();
        self.emit_u32_le(0);
        patch_off
    }

    /// `jne rel32` — jump if not equal.
    pub fn jne_rel32_placeholder(&mut self) -> usize {
        self.emit_byte(0x0F);
        self.emit_byte(0x85);
        let patch_off = self.buf.len();
        self.emit_u32_le(0);
        patch_off
    }

    /// `call rel32` — relative call.
    /// Returns the offset of the displacement for patching.
    pub fn call_rel32_placeholder(&mut self) -> usize {
        self.emit_byte(0xE8);
        let patch_off = self.buf.len();
        self.emit_u32_le(0);
        patch_off
    }

    /// Patch a rel32 displacement at `patch_off` to target `target_abs`.
    /// `instr_end` is the offset of the byte after the rel32 field.
    pub fn patch_rel32(&mut self, patch_off: usize, target_abs: usize, instr_end: usize) {
        let disp = (target_abs as isize - instr_end as isize) as i32;
        self.buf[patch_off..patch_off + 4].copy_from_slice(&disp.to_le_bytes());
    }

    /// `ret`
    pub fn ret(&mut self) {
        self.emit_byte(0xC3);
    }

    /// `nop` (1-byte)
    pub fn nop(&mut self) {
        self.emit_byte(0x90);
    }

    /// `int3` — breakpoint.
    pub fn int3(&mut self) {
        self.emit_byte(0xCC);
    }

    /// `jmp r64` — absolute indirect jump through register.
    pub fn jmp_r64(&mut self, reg: u8) {
        self.rex_w(0, reg);
        self.emit_byte(0xFF);
        self.emit_byte(Self::modrm(3, 4, reg));
    }

    /// `call r64` — absolute indirect call through register.
    pub fn call_r64(&mut self, reg: u8) {
        self.rex_w(0, reg);
        self.emit_byte(0xFF);
        self.emit_byte(Self::modrm(3, 2, reg));
    }

    /// `mov [r64 + disp32], r64` — store register to memory.
    pub fn mov_mr64_r64(&mut self, base: u8, disp: i32, src: u8) {
        self.rex_w(src, base);
        self.emit_byte(0x89);
        if base == Self::RSP || base == Self::R12 {
            // RSP/R12 need SIB byte
            self.emit_byte(Self::modrm(2, src, 4)); // mod=10 → disp32, rm=100 → SIB
            self.emit_byte(Self::sib(0, 4, base)); // scale=0, index=none(4), base
        } else if base == Self::RBP || base == Self::R13 {
            // RBP/R13 always need mod != 00, so mod=10 (disp32)
            self.emit_byte(Self::modrm(2, src, base));
        } else {
            self.emit_byte(Self::modrm(2, src, base));
        }
        self.emit_u32_le(disp as u32);
    }

    /// `mov r64, [r64 + disp32]` — load register from memory.
    pub fn mov_r64_mr64(&mut self, dst: u8, base: u8, disp: i32) {
        self.rex_w(dst, base);
        self.emit_byte(0x8B);
        if base == Self::RSP || base == Self::R12 {
            self.emit_byte(Self::modrm(2, dst, 4));
            self.emit_byte(Self::sib(0, 4, base));
        } else if base == Self::RBP || base == Self::R13 {
            self.emit_byte(Self::modrm(2, dst, base));
        } else {
            self.emit_byte(Self::modrm(2, dst, base));
        }
        self.emit_u32_le(disp as u32);
    }

    /// `mov byte [r64 + disp32], imm8`
    pub fn mov_byte_imm8(&mut self, base: u8, disp: i32, val: u8) {
        let need_rex = base >= 8;
        if need_rex {
            self.emit_byte(0x41); // REX.B
        }
        self.emit_byte(0xC6);
        self.emit_byte(Self::modrm(2, 0, base));
        self.emit_u32_le(disp as u32);
        self.emit_byte(val);
    }

    /// `xor r32, r32` — 32-bit XOR (shorter, zeros the full 64-bit reg).
    pub fn xor_r32_r32(&mut self, a: u8, b: u8) {
        let need_rex = a >= 8 || b >= 8;
        if need_rex {
            let mut rex = 0x40u8;
            if a >= 8 { rex |= 0x04; }
            if b >= 8 { rex |= 0x01; }
            self.emit_byte(rex);
        }
        self.emit_byte(0x31);
        self.emit_byte(Self::modrm(3, a, b));
    }

    /// `xor r64, r64` — 64-bit XOR.
    pub fn xor_r64_r64(&mut self, a: u8, b: u8) {
        self.rex_w(a, b);
        self.emit_byte(0x31);
        self.emit_byte(Self::modrm(3, a, b));
    }

    /// `shr r64, imm8`
    pub fn shr_r64_imm8(&mut self, reg: u8, count: u8) {
        self.rex_w(0, reg);
        self.emit_byte(0xC1);
        self.emit_byte(Self::modrm(3, 5, reg));
        self.emit_byte(count);
    }

    /// `and r64, imm32`
    pub fn and_r64_imm32(&mut self, reg: u8, imm: u32) {
        self.rex_w(0, reg);
        self.emit_byte(0x81);
        self.emit_byte(Self::modrm(3, 4, reg));
        self.emit_u32_le(imm);
    }

    /// `inc r64`
    pub fn inc_r64(&mut self, reg: u8) {
        self.rex_w(0, reg);
        self.emit_byte(0xFF);
        self.emit_byte(Self::modrm(3, 0, reg));
    }

    /// `dec r64`
    pub fn dec_r64(&mut self, reg: u8) {
        self.rex_w(0, reg);
        self.emit_byte(0xFF);
        self.emit_byte(Self::modrm(3, 1, reg));
    }

    // ── High-level patterns ───────────────────────────────────────────────

    /// `call $+5; pop r64` — obtain the current RIP into a register.
    /// Returns the offset of the instruction after pop (i.e., where the
    /// register now holds the absolute address of the byte right after the pop).
    pub fn get_rip(&mut self, reg: u8) -> usize {
        // call next; next: pop reg
        let call_patch = self.call_rel32_placeholder();
        let call_end = self.buf.len();
        // The call target is the pop instruction right after
        self.patch_rel32(call_patch, call_end, call_end);
        self.pop(reg);
        // Now `reg` holds the return address = address of byte after pop
        self.buf.len()
    }

    /// Emit a forward jump placeholder and return (patch_offset, instruction_end_offset).
    pub fn forward_jmp(&mut self) -> (usize, usize) {
        let patch = self.jmp_rel32_placeholder();
        let end = self.buf.len();
        (patch, end)
    }

    /// Emit a forward je placeholder.
    pub fn forward_je(&mut self) -> (usize, usize) {
        let patch = self.je_rel32_placeholder();
        let end = self.buf.len();
        (patch, end)
    }

    /// Emit a forward jne placeholder.
    pub fn forward_jne(&mut self) -> (usize, usize) {
        let patch = self.jne_rel32_placeholder();
        let end = self.buf.len();
        (patch, end)
    }

    /// Emit a forward call placeholder.
    pub fn forward_call(&mut self) -> (usize, usize) {
        let patch = self.call_rel32_placeholder();
        let end = self.buf.len();
        (patch, end)
    }

    /// Emit a forward lea rip placeholder and return (patch_offset, instruction_end_offset).
    pub fn forward_lea_rip(&mut self, reg: u8) -> (usize, usize) {
        let patch = self.lea_rip_placeholder(reg);
        let end = self.buf.len();
        (patch, end)
    }

    /// Emit a forward jbe placeholder.
    pub fn forward_jbe(&mut self) -> (usize, usize) {
        self.emit_byte(0x0F);
        self.emit_byte(0x86);
        let patch_off = self.buf.len();
        self.emit_u32_le(0);
        (patch_off, self.buf.len())
    }

    /// Emit a forward jb placeholder.
    pub fn forward_jb(&mut self) -> (usize, usize) {
        self.emit_byte(0x0F);
        self.emit_byte(0x82);
        let patch_off = self.buf.len();
        self.emit_u32_le(0);
        (patch_off, self.buf.len())
    }

    /// Emit a forward ja placeholder.
    pub fn forward_ja(&mut self) -> (usize, usize) {
        self.emit_byte(0x0F);
        self.emit_byte(0x87);
        let patch_off = self.buf.len();
        self.emit_u32_le(0);
        (patch_off, self.buf.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emitter_basic_instructions() {
        let mut e = Emitter::new();

        // push rax; pop rdx
        e.push(Emitter::RAX);
        e.pop(Emitter::RDX);

        // mov rax, 0x1122334455667788
        e.mov_r64_imm64(Emitter::RAX, 0x1122334455667788);

        // ret
        e.ret();

        let code = e.into_vec();

        // push rax = 0x50
        assert_eq!(code[0], 0x50);
        // pop rdx = 0x5A
        assert_eq!(code[1], 0x5A);
        // mov rax, imm64: REX.W + B8 + 8 bytes
        assert_eq!(code[2], 0x48); // REX.W
        assert_eq!(code[3], 0xB8); // mov rax, imm64
        // ret = 0xC3
        let ret_off = code.len() - 1;
        assert_eq!(code[ret_off], 0xC3);
    }

    #[test]
    fn lea_rip_encoding() {
        let mut e = Emitter::new();
        // lea rax, [rip + 0x10]
        e.lea_rip(Emitter::RAX, 0x10);
        let code = e.into_vec();
        // REX.W 8D 05 10 00 00 00
        assert_eq!(code, &[0x48, 0x8D, 0x05, 0x10, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn xor_zeroes_register() {
        let mut e = Emitter::new();
        e.xor_r32_r32(Emitter::RAX, Emitter::RAX);
        let code = e.into_vec();
        // 31 C0
        assert_eq!(code, &[0x31, 0xC0]);
    }
}
