//! Raw x86_64 machine-code emitter for per-build polymorphic decryption stubs.
//!
//! [`emit_stub`] generates a position-independent decryption stub as raw
//! machine code.  The seed controls which callee-saved registers are used
//! for each logical role (counter, key pointer, data pointer, length,
//! output pointer), so every build has a structurally different binary.
//!
//! # Calling convention
//!
//! The emitted stub follows the System V AMD64 ABI:
//!
//! ```text
//! extern "C" fn decrypt_stub(
//!     ciphertext:   *const u8,   // RDI
//!     ct_len:       usize,        // RSI
//!     key:          *const u8,   // RDX
//!     output:       *mut u8,     // RCX
//! )
//! ```
//!
//! All callee-saved registers touched by the stub are pushed/popped in
//! the prologue/epilogue.
//!
//! # Position independence
//!
//! All branches use relative offsets; no absolute addresses are embedded.
//! The stub can be copied to any executable page and called from there.

// ── Register encoding (REX+ModRM reg field) ──────────────────────────────────

/// An x86_64 general-purpose register, encoded as (rex_bit, reg3).
/// rex_bit is 1 when the register requires a REX prefix extension.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reg {
    /// Low 3 bits of the register field in ModRM/SIB.
    pub field: u8,
    /// Whether REX.B/R/X extension is needed for this register.
    pub rex_ext: bool,
    /// Textual name — for documentation only.
    pub name: &'static str,
}

impl Reg {
    const fn new(field: u8, rex_ext: bool, name: &'static str) -> Self {
        Self { field, rex_ext, name }
    }
}

// All 64-bit GPRs available as callee-saved (non-argument, non-scratch).
pub const RBX: Reg = Reg::new(3, false, "rbx");
pub const RBP: Reg = Reg::new(5, false, "rbp");
pub const R12: Reg = Reg::new(4, true,  "r12");
pub const R13: Reg = Reg::new(5, true,  "r13");
pub const R14: Reg = Reg::new(6, true,  "r14");
pub const R15: Reg = Reg::new(7, true,  "r15");

/// Argument / scratch registers (caller-saved). Used in prologue to load
/// input arguments into callee-saved slots.
pub const RDI: Reg = Reg::new(7, false, "rdi");
pub const RSI: Reg = Reg::new(6, false, "rsi");
// Reserved for the future external-key ABI path where stubs consume the third
// argument directly instead of always using embedded key bytes.
#[allow(dead_code)]
pub const RDX: Reg = Reg::new(2, false, "rdx");
pub const RCX: Reg = Reg::new(1, false, "rcx");

// Small scratch: used only within single blocks; not saved.
pub const RAX: Reg = Reg::new(0, false, "rax");
// R8 is used directly via raw byte sequences in emit_xor_keystream_stub;
// the const is kept for future emitter variants that reference it by name.
#[allow(dead_code)]
pub const R8:  Reg = Reg::new(0, true,  "r8");
// R9/R10 reserved for future emitter variants (e.g. modulo-free AES-CTR stub).
#[allow(dead_code)]
pub const R9:  Reg = Reg::new(1, true,  "r9");
#[allow(dead_code)]
pub const R10: Reg = Reg::new(2, true,  "r10");
// Reserved scratch for upcoming full-round cipher emitters and alternate
// key-index reducers that use an extra caller-saved register.
#[allow(dead_code)]
pub const R11: Reg = Reg::new(3, true,  "r11");

/// Register assignment for a stub variant.  Roles are filled from the
/// pool of callee-saved registers so the prologue can push them all.
#[derive(Clone, Debug)]
pub struct RegAlloc {
    /// Decryption loop counter (byte index into ciphertext).
    pub r_idx:    Reg,
    /// Pointer to ciphertext input.
    pub r_src:    Reg,
    /// Length of ciphertext (loop limit).
    pub r_len:    Reg,
    /// Pointer to key material.
    pub r_key:    Reg,
    /// Pointer to output buffer.
    pub r_out:    Reg,
    /// All callee-saved registers actually used (for push/pop).
    pub saved:    Vec<Reg>,
}

/// All valid callee-saved register pools ordered by seed index.
const CALLEE_SAVED: [Reg; 6] = [RBX, RBP, R12, R13, R14, R15];

impl RegAlloc {
    /// Deterministically choose a register allocation for the given seed.
    /// Different seeds produce different (but valid) permutations.
    pub fn from_seed(seed: u64) -> Self {
        // Produce a permutation of CALLEE_SAVED using a simple LCG shuffle.
        let mut pool = CALLEE_SAVED;
        let mut s = seed;
        for i in (1..pool.len()).rev() {
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let j = (s >> 33) as usize % (i + 1);
            pool.swap(i, j);
        }
        // Assign the first 5 slots.
        let saved = pool[..5].to_vec();
        RegAlloc {
            r_idx: pool[0],
            r_src: pool[1],
            r_len: pool[2],
            r_key: pool[3],
            r_out: pool[4],
            saved,
        }
    }
}

// ── Low-level byte emitter ───────────────────────────────────────────────────

pub struct Emitter {
    buf: Vec<u8>,
}

impl Emitter {
    pub fn new() -> Self {
        Self { buf: Vec::with_capacity(512) }
    }

    pub fn finish(self) -> Vec<u8> {
        self.buf
    }

    fn byte(&mut self, b: u8) {
        self.buf.push(b);
    }

    fn bytes(&mut self, bs: &[u8]) {
        self.buf.extend_from_slice(bs);
    }

    /// REX.W prefix for 64-bit operands.
    /// rex_r = extension for reg field of ModRM
    /// rex_b = extension for r/m field of ModRM (or base)
    fn rex_w(&mut self, rex_r: bool, rex_b: bool) {
        let r = if rex_r { 0x04 } else { 0 };
        let b = if rex_b { 0x01 } else { 0 };
        self.byte(0x48 | r | b);
    }

    /// REX.W + optional extension bits for two-register ops.
    fn rex_wr(&mut self, dst: Reg, src: Reg) {
        let r = if src.rex_ext { 0x04 } else { 0 };
        let b = if dst.rex_ext { 0x01 } else { 0 };
        self.byte(0x48 | r | b);
    }

    /// ModRM byte: mod=11 (register), reg field = `reg`, rm field = `rm`.
    fn modrm_rr(&self, reg: Reg, rm: Reg) -> u8 {
        0xC0 | ((reg.field & 7) << 3) | (rm.field & 7)
    }

    /// PUSH r64 — callee-save
    pub fn push_r64(&mut self, r: Reg) {
        if r.rex_ext {
            self.byte(0x41); // REX.B
        }
        self.byte(0x50 | (r.field & 7));
    }

    /// POP r64 — callee-restore
    pub fn pop_r64(&mut self, r: Reg) {
        if r.rex_ext {
            self.byte(0x41);
        }
        self.byte(0x58 | (r.field & 7));
    }

    /// MOV dst64, src64
    pub fn mov_rr(&mut self, dst: Reg, src: Reg) {
        self.rex_wr(dst, src);
        self.byte(0x89);
        self.byte(self.modrm_rr(src, dst));
    }

    /// XOR dst64, dst64 (zero register)
    pub fn xor_rr_zero(&mut self, r: Reg) {
        self.rex_w(r.rex_ext, r.rex_ext);
        self.byte(0x33);
        self.byte(self.modrm_rr(r, r));
    }

    /// ADD dst64, src64  (REX.W 01 /r)
    pub fn add_r64_r64(&mut self, dst: Reg, src: Reg) {
        self.rex_wr(dst, src);
        self.byte(0x01);
        self.byte(self.modrm_rr(src, dst));
    }

    // Kept for planned emitter variants that choose compact imm8 pointer bumps.
    #[allow(dead_code)]
    /// ADD dst64, imm8 (sign-extended)
    pub fn add_r64_imm8(&mut self, r: Reg, imm: i8) {
        self.rex_w(false, r.rex_ext);
        self.byte(0x83);
        self.byte(0xC0 | (r.field & 7));
        self.byte(imm as u8);
    }

    /// CMP dst64, src64  — `0x3B /r`: dst is in ModRM.reg, src in ModRM.rm.
    /// REX.R extends dst (reg), REX.B extends src (rm).
    pub fn cmp_rr(&mut self, a: Reg, b: Reg) {
        // 0x3B /r: CMP r64, r/m64. reg=a (extended by REX.R), rm=b (extended by REX.B).
        // rex_wr(rm, reg) → REX.R=reg.rex_ext, REX.B=rm.rex_ext — so call rex_wr(b, a).
        self.rex_wr(b, a);
        self.byte(0x3B);
        self.byte(self.modrm_rr(a, b));
    }

    // Kept for planned compact branch-mode emitters that encode control flow via helpers.
    #[allow(dead_code)]
    /// JGE rel8 (jump if signed greater-or-equal)
    pub fn jge_rel8(&mut self, offset: i8) {
        self.byte(0x7D);
        self.byte(offset as u8);
    }

    // Kept for planned compact branch-mode emitters that encode control flow via helpers.
    #[allow(dead_code)]
    /// JB rel8 (jump if below / unsigned less-than)
    pub fn jb_rel8(&mut self, offset: i8) {
        self.byte(0x72);
        self.byte(offset as u8);
    }

    // Kept for planned compact branch-mode emitters that encode control flow via helpers.
    #[allow(dead_code)]
    /// JMP rel8
    pub fn jmp_rel8(&mut self, offset: i8) {
        self.byte(0xEB);
        self.byte(offset as u8);
    }

    // Kept for planned SIB-based backend variants (currently avoided due encoding traps).
    #[allow(dead_code)]
    /// MOVZX r64, byte [base + index]  — load one byte with zero extension.
    /// Uses: REX.W 0F B6 /r  with ModRM SIB for [base+index].
    pub fn movzx_r64_mem8_base_idx(&mut self, dst: Reg, base: Reg, idx: Reg) {
        // REX.W + optional rex_r (dst ext) + rex_b (base ext) + rex_x (idx ext)
        let rex_r = if dst.rex_ext { 0x04 } else { 0 };
        let rex_b = if base.rex_ext { 0x01 } else { 0 };
        let rex_x = if idx.rex_ext { 0x02 } else { 0 };
        self.byte(0x48 | rex_r | rex_b | rex_x);
        self.byte(0x0F);
        self.byte(0xB6);
        // ModRM: mod=00, reg=dst, rm=100 (SIB follows)
        self.byte((0x00) | ((dst.field & 7) << 3) | 0x04);
        // SIB: scale=00, index=idx, base=base
        self.byte(((idx.field & 7) << 3) | (base.field & 7));
    }

    // Kept for planned SIB-based backend variants (currently avoided due encoding traps).
    #[allow(dead_code)]
    /// MOV byte [base + index], src8 — store lowest byte of src.
    pub fn mov_mem8_base_idx_r8(&mut self, base: Reg, idx: Reg, src: Reg) {
        let rex_r = if src.rex_ext { 0x04 } else { 0 };
        let rex_b = if base.rex_ext { 0x01 } else { 0 };
        let rex_x = if idx.rex_ext { 0x02 } else { 0 };
        // REX prefix (always needed for r8..r15 byte access; also needed for sil/dil etc.)
        self.byte(0x40 | rex_r | rex_b | rex_x);
        self.byte(0x88);
        // ModRM: mod=00, reg=src, rm=100 (SIB follows)
        self.byte((0x00) | ((src.field & 7) << 3) | 0x04);
        // SIB: scale=00, index=idx, base=base
        self.byte(((idx.field & 7) << 3) | (base.field & 7));
    }

    // Kept for planned SIB-based backend variants (currently avoided due encoding traps).
    #[allow(dead_code)]
    /// XOR r8_low, mem8 — XOR byte register with memory byte [base+index].
    pub fn xor_r8_mem8_base_idx(&mut self, dst: Reg, base: Reg, idx: Reg) {
        let rex_r = if dst.rex_ext { 0x04 } else { 0 };
        let rex_b = if base.rex_ext { 0x01 } else { 0 };
        let rex_x = if idx.rex_ext { 0x02 } else { 0 };
        let need_rex = rex_r | rex_b | rex_x;
        if need_rex != 0 {
            self.byte(0x40 | need_rex);
        }
        self.byte(0x32);
        self.byte((0x00) | ((dst.field & 7) << 3) | 0x04);
        self.byte(((idx.field & 7) << 3) | (base.field & 7));
    }

    /// INC r64
    pub fn inc_r64(&mut self, r: Reg) {
        self.rex_w(false, r.rex_ext);
        self.byte(0xFF);
        self.byte(0xC0 | (r.field & 7));
    }

    /// RET
    pub fn ret(&mut self) {
        self.byte(0xC3);
    }

    /// Current length of emitted code — useful for computing branch offsets.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Patch a previously-emitted rel8 byte at `pos`.
    pub fn patch_rel8(&mut self, pos: usize, target: usize) {
        let offset = (target as isize) - (pos as isize) - 1;
        self.buf[pos] = offset as i8 as u8;
    }

    /// Emit a 64-bit immediate move: MOV r64, imm64.
    /// Kept for future emitter variants that need to embed length constants.
    #[allow(dead_code)]
    pub fn mov_r64_imm64(&mut self, dst: Reg, imm: u64) {
        let rex_b = if dst.rex_ext { 0x01 } else { 0 };
        self.byte(0x48 | rex_b);
        self.byte(0xB8 | (dst.field & 7));
        self.bytes(&imm.to_le_bytes());
    }

    /// LEA r64, [rip + disp32] — load RIP-relative address.
    /// `disp32` is relative to the end of the LEA instruction (7 bytes total).
    pub fn lea_r64_rip_rel32(&mut self, dst: Reg, disp: i32) {
        let rex_r = if dst.rex_ext { 0x04 } else { 0 };
        self.byte(0x48 | rex_r);
        self.byte(0x8D);
        // ModRM: mod=00, reg=dst, rm=101 (RIP-relative)
        self.byte(0x05 | ((dst.field & 7) << 3));
        self.bytes(&disp.to_le_bytes());
    }

    // ── Helpers used by the inline ChaCha20 stub (M-4) ───────────────────
    //
    // All of the helpers below operate on 32-bit operands (the natural
    // word width for ChaCha20).  They use `[rsp+disp8]` SIB-form addressing
    // for the 16-word working state held on the stack.

    /// Generic 32-bit `OP <reg>, [rsp+disp8]` (or `[rsp+disp8], <reg>` when the
    /// opcode encodes the memory operand on the destination side).
    /// Always emits `mod=01 rm=100 SIB=0x24` to reach `[rsp+disp8]`.
    fn op_r32_rsp_disp8(&mut self, opcode: u8, reg: Reg, disp: i8) {
        if reg.rex_ext {
            self.byte(0x44); // REX.R
        }
        self.byte(opcode);
        self.byte(0x40 | ((reg.field & 7) << 3) | 0x04);
        self.byte(0x24);
        self.byte(disp as u8);
    }

    /// MOV r32, [rsp+disp8]
    pub fn mov_r32_rsp_disp8(&mut self, dst: Reg, disp: i8) {
        self.op_r32_rsp_disp8(0x8B, dst, disp);
    }

    /// MOV [rsp+disp8], r32
    pub fn mov_rsp_disp8_r32(&mut self, disp: i8, src: Reg) {
        self.op_r32_rsp_disp8(0x89, src, disp);
    }

    /// ADD r32, [rsp+disp8]   (03 /r)
    pub fn add_r32_rsp_disp8(&mut self, dst: Reg, disp: i8) {
        self.op_r32_rsp_disp8(0x03, dst, disp);
    }

    /// ADD [rsp+disp8], r32   (01 /r)
    pub fn add_rsp_disp8_r32(&mut self, disp: i8, src: Reg) {
        self.op_r32_rsp_disp8(0x01, src, disp);
    }

    /// MOV [rsp+disp8], imm32  (C7 /0)
    pub fn mov_rsp_disp8_imm32(&mut self, disp: i8, imm: u32) {
        self.bytes(&[0xC7, 0x44, 0x24, disp as u8]);
        self.bytes(&imm.to_le_bytes());
    }

    /// MOV r32, [base + disp8] for an arbitrary base register.
    /// Handles the R12/RSP rm=100 case by inserting a SIB byte.
    pub fn mov_r32_mem_base_disp8(&mut self, dst: Reg, base: Reg, disp: i8) {
        let mut rex = 0u8;
        if dst.rex_ext  { rex |= 0x04; } // REX.R
        if base.rex_ext { rex |= 0x01; } // REX.B
        if rex != 0 { self.byte(0x40 | rex); }
        self.byte(0x8B);
        if (base.field & 7) == 4 {
            // Base is RSP/R12 → need SIB byte (0x24) with index=none, base=4.
            self.byte(0x40 | ((dst.field & 7) << 3) | 0x04);
            self.byte(0x24);
        } else {
            self.byte(0x40 | ((dst.field & 7) << 3) | (base.field & 7));
        }
        self.byte(disp as u8);
    }

    /// ROL r32, imm8   (C1 /0 ib)
    pub fn rol_r32_imm8(&mut self, reg: Reg, imm: u8) {
        if reg.rex_ext { self.byte(0x41); } // REX.B
        self.byte(0xC1);
        self.byte(0xC0 | (reg.field & 7));
        self.byte(imm);
    }

    /// SUB RSP, imm32  (REX.W 81 /5)
    pub fn sub_rsp_imm32(&mut self, imm: u32) {
        self.bytes(&[0x48, 0x81, 0xEC]);
        self.bytes(&imm.to_le_bytes());
    }

    /// ADD RSP, imm32  (REX.W 81 /0)
    pub fn add_rsp_imm32(&mut self, imm: u32) {
        self.bytes(&[0x48, 0x81, 0xC4]);
        self.bytes(&imm.to_le_bytes());
    }

    /// CMP r64, imm8 (sign-extended)  (REX.W 83 /7 ib)
    pub fn cmp_r64_imm8(&mut self, r: Reg, imm: i8) {
        self.rex_w(false, r.rex_ext);
        self.byte(0x83);
        self.byte(0xF8 | (r.field & 7));
        self.byte(imm as u8);
    }

    /// TEST r64, r64  (REX.W 85 /r with reg==rm)
    pub fn test_rr(&mut self, r: Reg) {
        self.rex_w(r.rex_ext, r.rex_ext);
        self.byte(0x85);
        self.byte(0xC0 | ((r.field & 7) << 3) | (r.field & 7));
    }

    /// DEC r64  (REX.W FF /1)
    pub fn dec_r64(&mut self, r: Reg) {
        self.rex_w(false, r.rex_ext);
        self.byte(0xFF);
        self.byte(0xC8 | (r.field & 7));
    }

    /// JZ rel32  (0F 84 disp32) — returns position of the 4-byte displacement
    /// field for later patching with `patch_rel32`.
    pub fn jz_rel32_placeholder(&mut self) -> usize {
        self.byte(0x0F); self.byte(0x84);
        let p = self.len();
        self.bytes(&[0, 0, 0, 0]);
        p
    }

    /// JMP rel32  (E9 disp32) emitted with a known backward target.
    pub fn jmp_rel32_back(&mut self, target: usize) {
        // Total instruction size = 5 (1 opcode + 4 disp).
        let cur = self.len();
        let disp = (target as isize) - (cur as isize) - 5;
        self.byte(0xE9);
        self.bytes(&(disp as i32).to_le_bytes());
    }

    /// JNZ rel32  (0F 85 disp32) emitted with a known backward target.
    pub fn jnz_rel32_back(&mut self, target: usize) {
        let cur = self.len();
        let disp = (target as isize) - (cur as isize) - 6;
        self.byte(0x0F); self.byte(0x85);
        self.bytes(&(disp as i32).to_le_bytes());
    }

    /// Patch a 4-byte rel32 displacement field at `disp_pos` so the
    /// instruction jumps to `target`.
    pub fn patch_rel32(&mut self, disp_pos: usize, target: usize) {
        let off = (target as isize) - (disp_pos as isize) - 4;
        let bytes = (off as i32).to_le_bytes();
        self.buf[disp_pos..disp_pos + 4].copy_from_slice(&bytes);
    }
}

// ── Stub kinds ────────────────────────────────────────────────────────────────

/// The encryption scheme to generate a raw stub for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StubKind {
    ChaCha20,
    AesCtr,
    /// On-the-fly ChaCha20: only the 32-byte key + 12-byte nonce are embedded
    /// (44 bytes total); the stub generates the keystream itself one block at
    /// a time.  Cuts the embedded data section from `ct_len` down to a fixed
    /// 44 bytes regardless of payload size.
    RawStubInline,
}

/// Emitted stub: machine code bytes + the seed used for register allocation.
pub struct EmittedStub {
    pub code: Vec<u8>,
    // Planned metadata for reproducible build auditing and seed-strategy tuning.
    #[allow(dead_code)]
    pub seed: u64,
    // Planned metadata for downstream tooling that tracks emitted stub family.
    #[allow(dead_code)]
    pub kind: StubKind,
    /// The key (and nonce) baked into the stub (not in code — in the wire blob).
    // Planned fallback for emitters that externalize key material instead of
    // embedding it in trailing bytes.
    #[allow(dead_code)]
    pub key:  Vec<u8>,
}

// ── ChaCha20 raw stub ─────────────────────────────────────────────────────────
//
// Implements a ChaCha20-compatible decryption loop for the RawStub scheme.
// The key bytes embedded in the stub are the *pre-computed ChaCha20 keystream*
// (same length as the ciphertext), so the stub only needs to XOR:
//
//   for i in 0..ct_len {
//       output[i] = ciphertext[i] ^ keystream[i]
//   }
//
// Because keystream.len() == ct_len the old modulo sub-loop is not needed —
// the byte index i is always a valid direct index into the keystream.
// The keystream bytes are embedded as RIP-relative data after the RET, so the
// stub is fully position-independent and carries no repeating-key weakness.
//
// Stub layout (all offsets relative to entry):
//
//   prologue  (push callee-saved, load args)
//   body      (XOR loop: out[i] = src[i] ^ keystream[i])
//   epilogue  (pop callee-saved, ret)
//   [keystream bytes embedded after RET — accessed via RIP-relative LEA]
//
// Registers:
//   r_idx  = loop counter i
//   r_src  = ciphertext pointer   (arg 0: RDI)
//   r_len  = ciphertext length    (arg 1: RSI)
//   r_key  = pointer to keystream (loaded via RIP-relative LEA)
//   r_out  = output pointer       (arg 3: RCX)

pub fn emit_xor_keystream_stub(key: &[u8], alloc: &RegAlloc, kind: StubKind) -> Vec<u8> {
    let _ = kind; // both ChaCha20 and AesCtr use the same XOR loop structure
    let mut e = Emitter::new();

    // ── Prologue: push callee-saved registers ─────────────────────────────
    for &r in &alloc.saved {
        e.push_r64(r);
    }

    // ── Load arguments into callee-saved roles ────────────────────────────
    // We need to be careful about overwriting arguments, so load in safe order.
    // RDI (ciphertext), RSI (ct_len), RCX (output) are the inputs we care about.
    // We load ct_len first (it's needed after other moves may clobber RSI).
    e.mov_rr(alloc.r_len, RSI);  // r_len = ct_len (RSI)
    e.mov_rr(alloc.r_src, RDI);  // r_src = ct ptr (RDI)
    e.mov_rr(alloc.r_out, RCX);  // r_out = output ptr (RCX)

    // ── Load key pointer via RIP-relative LEA ─────────────────────────────
    // Keystream data is appended after the RET. We emit a placeholder LEA and
    // patch the displacement once the full code size is known.
    // Instruction layout: REX.W(1) 8D /r disp32 = 7 bytes.
    let lea_pos = e.len();
    e.lea_r64_rip_rel32(alloc.r_key, 0i32); // patched later

    // ── Zero loop index ───────────────────────────────────────────────────
    e.xor_rr_zero(alloc.r_idx);

    // ── Main loop ─────────────────────────────────────────────────────────
    // The keystream length equals ct_len, so we use r_idx directly as the
    // keystream index — no modulo sub-loop required.
    //
    // Scratch registers used inside the loop body (caller-saved, not saved):
    //   RAX — current byte value / temp
    //   R8  — current ciphertext byte (after MOVZX)
    //   R9  — (unused; kept available for future emitter variants)
    //
    // Loop structure (all [reg] addressing; no SIB):
    //
    //   loop_top:
    //     CMP  r_idx, r_len
    //     JGE  loop_end
    //
    //     ; load ct[i] into R8
    //     MOV  RAX, r_src
    //     ADD  RAX, r_idx           ; RAX = &ct[i]
    //     MOVZX R8, byte [RAX]      ; R8  = ct[i]
    //
    //     ; XOR with keystream[i]
    //     MOV  RAX, r_key
    //     ADD  RAX, r_idx           ; RAX = &keystream[i]
    //     XOR  R8b, byte [RAX]      ; R8b ^= keystream[i]
    //
    //     ; store result
    //     MOV  RAX, r_out
    //     ADD  RAX, r_idx           ; RAX = &out[i]
    //     MOV  byte [RAX], R8b      ; out[i] = R8b
    //
    //     INC  r_idx
    //     JMP  loop_top
    //   loop_end:

    let loop_top = e.len();

    // CMP r_idx, r_len  ;  JGE loop_end
    e.cmp_rr(alloc.r_idx, alloc.r_len);
    let jge_off = e.len(); e.byte(0x7D); e.byte(0x00);

    // RAX = &ct[i]:  MOV RAX, r_src ; ADD RAX, r_idx
    e.mov_rr(RAX, alloc.r_src);
    e.add_r64_r64(RAX, alloc.r_idx);
    // MOVZX R8, byte [RAX]  — 4C 0F B6 00  (REX.W+REX.R for R8, mod=00 rm=000=RAX)
    e.byte(0x4C); e.byte(0x0F); e.byte(0xB6); e.byte(0x00);

    // RAX = &keystream[i]:  MOV RAX, r_key ; ADD RAX, r_idx
    e.mov_rr(RAX, alloc.r_key);
    e.add_r64_r64(RAX, alloc.r_idx);
    // XOR R8b, byte [RAX]: REX.R(R8 ext), 0x32, mod=00 rm=000=[RAX]
    e.byte(0x44); e.byte(0x32); e.byte(0x00);

    // out[i] = R8b:  MOV RAX, r_out ; ADD RAX, r_idx
    e.mov_rr(RAX, alloc.r_out);
    e.add_r64_r64(RAX, alloc.r_idx);
    // MOV byte [RAX], R8b: 44 88 00  (REX.R for R8, 88 /r, mod=00 rm=000=RAX)
    e.byte(0x44); e.byte(0x88); e.byte(0x00);

    // INC r_idx
    e.inc_r64(alloc.r_idx);

    // JMP loop_top
    let jmp_top = e.len(); e.byte(0xEB); e.byte(0x00);
    let loop_end = e.len();

    e.patch_rel8(jge_off + 1, loop_end);
    e.patch_rel8(jmp_top + 1, loop_top);

    // ── Epilogue ──────────────────────────────────────────────────────────
    for &r in alloc.saved.iter().rev() {
        e.pop_r64(r);
    }
    e.ret();

    // ── Keystream data appended after RET ─────────────────────────────────
    let key_offset = e.len();
    e.bytes(key);

    // ── Patch LEA displacement ────────────────────────────────────────────
    // LEA r_key, [rip + disp32] is 7 bytes; RIP = lea_pos + 7 after decode.
    let lea_end = lea_pos + 7;
    let disp = (key_offset as i32) - (lea_end as i32);
    let disp_bytes = disp.to_le_bytes();
    let mut code = e.finish();
    code[lea_pos + 3] = disp_bytes[0];
    code[lea_pos + 4] = disp_bytes[1];
    code[lea_pos + 5] = disp_bytes[2];
    code[lea_pos + 6] = disp_bytes[3];

    code
}

/// On-the-fly ChaCha20 stub: embeds only the 32-byte key + 12-byte nonce
/// (44 bytes) at the end of the code blob and computes the keystream itself
/// one 64-byte block at a time.  Output is identical to the
/// `chacha20_stream` reference in `poly.rs` (RFC 8439 with block counter
/// starting at 1).
///
/// # Stack frame (128 bytes; all offsets fit in disp8)
///
/// ```text
///   [rsp+0  .. rsp+63]   = working state  (16 dwords)
///   [rsp+64 .. rsp+127]  = original state copy (for the final state-add)
/// ```
///
/// # Register usage
///
/// Outer (callee-saved, allocated by `RegAlloc`):
///   * `r_src` — current ciphertext pointer (advanced byte-by-byte)
///   * `r_len` — remaining bytes (decremented byte-by-byte)
///   * `r_out` — current output pointer
///   * `r_key` — RIP-relative pointer to the embedded 44-byte key+nonce
///   * `r_idx` — block counter (32-bit value held in low half)
///
/// Inner scratch (caller-saved): RAX (EAX), RCX (ECX), RDX (EDX),
/// RDI, RSI.
///
/// # Pseudocode
///
/// ```text
///   prologue (push callee-saved; SUB rsp,128)
///   load args; LEA r_key,[rip+key_data]; r_idx = 1
/// main_block_loop:
///   if r_len == 0 goto done
///   init working state from constants/key/r_idx/nonce
///   copy working state into [rsp+64..127]
///   ECX = 10
///   round_loop:
///     8 quarter-rounds (column + diagonal) on stack-resident state
///     dec ECX; jnz round_loop
///   add [rsp+64..127] back into [rsp+0..63]
///   inner xor loop:
///     while r_len > 0 && inner_idx < 64:
///       out[i] = ks[i] ^ ct[i]; advance pointers; r_len--
///   r_idx++; jmp main_block_loop
/// done:
///   ADD rsp,128; pop callee-saved; ret
///   <44 bytes of key+nonce data>
/// ```
fn emit_chacha20_inline_stub(key44: &[u8], alloc: &RegAlloc) -> Vec<u8> {
    debug_assert_eq!(key44.len(), 44);
    let mut e = Emitter::new();

    // ── Prologue ─────────────────────────────────────────────────────────
    for &r in &alloc.saved {
        e.push_r64(r);
    }
    // Allocate 128 bytes of stack for the working state + saved copy.
    e.sub_rsp_imm32(128);

    // Save arguments into callee-saved roles.
    e.mov_rr(alloc.r_len, RSI);
    e.mov_rr(alloc.r_src, RDI);
    e.mov_rr(alloc.r_out, RCX);

    // r_key = &key_data via RIP-relative LEA (patched at the end).
    let lea_pos = e.len();
    e.lea_r64_rip_rel32(alloc.r_key, 0i32);

    // r_idx = 1  (ChaCha20 block counter starts at 1, matching `chacha20_stream`).
    e.xor_rr_zero(alloc.r_idx);
    e.inc_r64(alloc.r_idx);

    // ── main_block_loop ─────────────────────────────────────────────────
    let main_loop_top = e.len();

    // if r_len == 0 → goto done  (rel32 forward; patched after epilogue)
    e.test_rr(alloc.r_len);
    let done_jz_disp = e.jz_rel32_placeholder();

    // ── Initialize working state at [rsp+0..63] ─────────────────────────
    // Constants ("expand 32-byte k") at offsets 0..15.
    e.mov_rsp_disp8_imm32(0,  0x61707865);
    e.mov_rsp_disp8_imm32(4,  0x3320646e);
    e.mov_rsp_disp8_imm32(8,  0x79622d32);
    e.mov_rsp_disp8_imm32(12, 0x6b206574);

    // 8 key dwords from [r_key + 0..32] → [rsp + 16..48].
    for i in 0..8u8 {
        e.mov_r32_mem_base_disp8(RAX, alloc.r_key, (i * 4) as i8);
        e.mov_rsp_disp8_r32((16 + i * 4) as i8, RAX);
    }
    // Counter (low 32 bits of r_idx) → [rsp+48].
    e.mov_rsp_disp8_r32(48, alloc.r_idx);
    // 3 nonce dwords from [r_key + 32..44] → [rsp + 52..64].
    for i in 0..3u8 {
        e.mov_r32_mem_base_disp8(RAX, alloc.r_key, (32 + i * 4) as i8);
        e.mov_rsp_disp8_r32((52 + i * 4) as i8, RAX);
    }

    // ── Copy working state to [rsp+64..127] (saved for final add) ───────
    for i in 0..16u8 {
        e.mov_r32_rsp_disp8(RAX, (i * 4) as i8);
        e.mov_rsp_disp8_r32((64 + i * 4) as i8, RAX);
    }

    // ── 10 double-rounds via inner counter ECX ──────────────────────────
    // MOV ECX, 10  (B9 imm32, no REX since ECX is field=1).
    e.byte(0xB9);
    e.bytes(&10u32.to_le_bytes());

    let round_loop_top = e.len();
    // Column rounds.
    emit_chacha20_qr(&mut e, 0, 4,  8, 12);
    emit_chacha20_qr(&mut e, 1, 5,  9, 13);
    emit_chacha20_qr(&mut e, 2, 6, 10, 14);
    emit_chacha20_qr(&mut e, 3, 7, 11, 15);
    // Diagonal rounds.
    emit_chacha20_qr(&mut e, 0, 5, 10, 15);
    emit_chacha20_qr(&mut e, 1, 6, 11, 12);
    emit_chacha20_qr(&mut e, 2, 7,  8, 13);
    emit_chacha20_qr(&mut e, 3, 4,  9, 14);
    // DEC ECX  (FF C9, no REX).
    e.byte(0xFF); e.byte(0xC9);
    // JNZ round_loop_top  (rel32 backward — body is ~hundreds of bytes).
    e.jnz_rel32_back(round_loop_top);

    // ── Add original state [rsp+64..127] into working state [rsp+0..63] ─
    for i in 0..16u8 {
        e.mov_r32_rsp_disp8(RAX, (64 + i * 4) as i8);
        e.add_rsp_disp8_r32((i * 4) as i8, RAX);
    }

    // ── Inner XOR loop: out[i] = ks[i] ^ ct[i] for up to 64 bytes ────────
    // Move the cipher/output pointers into RDI/RSI scratch (cheap clean-rm
    // base regs), and ECX = 0 = inner index (0..64).
    e.mov_rr(RDI, alloc.r_src);
    e.mov_rr(RSI, alloc.r_out);
    e.xor_rr_zero(RCX); // RCX = 0

    let inner_loop_top = e.len();

    // test r_len, r_len ; jz block_advance (rel8 forward, patched).
    e.test_rr(alloc.r_len);
    e.byte(0x74); let inner_jz_pos = e.len(); e.byte(0x00);
    // cmp rcx, 64 ; jge block_advance (rel8 forward, patched).
    e.cmp_r64_imm8(RCX, 64);
    e.byte(0x7D); let inner_jge_pos = e.len(); e.byte(0x00);

    // movzx eax, byte [rsp + rcx]   (0F B6 04 0C)
    //   ModRM 0x04 = mod=00 reg=EAX=0 rm=100(SIB)
    //   SIB    0x0C = scale=00 index=RCX=1 base=RSP=4
    e.bytes(&[0x0F, 0xB6, 0x04, 0x0C]);

    // movzx edx, byte [rdi]         (0F B6 17)
    //   ModRM 0x17 = mod=00 reg=EDX=2 rm=RDI=7
    e.bytes(&[0x0F, 0xB6, 0x17]);

    // xor eax, edx                  (33 C2)  — XOR r32, r/m32; reg=EAX, rm=EDX
    e.bytes(&[0x33, 0xC2]);

    // mov byte [rsi], al            (88 06)  — reg=AL=0, rm=RSI=6
    e.bytes(&[0x88, 0x06]);

    // inc rdi ; inc rsi ; inc rcx ; dec r_len
    e.inc_r64(RDI);
    e.inc_r64(RSI);
    e.inc_r64(RCX);
    e.dec_r64(alloc.r_len);

    // jmp inner_loop_top  (rel8 backward; loop body fits in i8 range).
    let cur = e.len();
    let back = (inner_loop_top as isize) - (cur as isize) - 2;
    debug_assert!(back >= -128 && back <= 127, "inner loop too large for rel8 jmp");
    e.byte(0xEB); e.byte(back as i8 as u8);

    // ── block_advance: persist updated pointers and bump counter ────────
    let block_advance = e.len();
    e.patch_rel8(inner_jz_pos, block_advance);
    e.patch_rel8(inner_jge_pos, block_advance);

    e.mov_rr(alloc.r_src, RDI);
    e.mov_rr(alloc.r_out, RSI);
    e.inc_r64(alloc.r_idx);

    // jmp main_block_loop  (rel32 backward — far away).
    e.jmp_rel32_back(main_loop_top);

    // ── done ─────────────────────────────────────────────────────────────
    let done_label = e.len();
    e.patch_rel32(done_jz_disp, done_label);

    e.add_rsp_imm32(128);
    for &r in alloc.saved.iter().rev() {
        e.pop_r64(r);
    }
    e.ret();

    // ── 44-byte key+nonce data section appended after RET ────────────────
    let key_offset = e.len();
    e.bytes(key44);

    // Patch the LEA disp32 (LEA is 7 bytes; disp lives at lea_pos+3..+7).
    let lea_end = lea_pos + 7;
    let disp = (key_offset as i32) - (lea_end as i32);
    let disp_bytes = disp.to_le_bytes();
    let mut code = e.finish();
    code[lea_pos + 3] = disp_bytes[0];
    code[lea_pos + 4] = disp_bytes[1];
    code[lea_pos + 5] = disp_bytes[2];
    code[lea_pos + 6] = disp_bytes[3];

    code
}

/// Emit one ChaCha20 quarter-round operating on stack-resident dword slots.
/// `a`, `b`, `c`, `d` are word indices (0..16) into `[rsp + i*4]`.
///
/// Uses EAX as the "addend / xor source" temp and EDX as the rotated word.
fn emit_chacha20_qr(e: &mut Emitter, a: u8, b: u8, c: u8, d: u8) {
    let oa = (a * 4) as i8;
    let ob = (b * 4) as i8;
    let oc = (c * 4) as i8;
    let od = (d * 4) as i8;

    // a += b
    e.mov_r32_rsp_disp8(RAX, oa);
    e.add_r32_rsp_disp8(RAX, ob);
    e.mov_rsp_disp8_r32(oa, RAX);
    // d ^= a; d <<<= 16
    e.mov_r32_rsp_disp8(RDX, od);
    e.bytes(&[0x33, 0xD0]); // xor edx, eax  (reg=EDX=2, rm=EAX=0)
    e.rol_r32_imm8(RDX, 16);
    e.mov_rsp_disp8_r32(od, RDX);
    // c += d
    e.mov_r32_rsp_disp8(RAX, oc);
    e.bytes(&[0x03, 0xC2]); // add eax, edx  (reg=EAX, rm=EDX)
    e.mov_rsp_disp8_r32(oc, RAX);
    // b ^= c; b <<<= 12
    e.mov_r32_rsp_disp8(RDX, ob);
    e.bytes(&[0x33, 0xD0]); // xor edx, eax
    e.rol_r32_imm8(RDX, 12);
    e.mov_rsp_disp8_r32(ob, RDX);

    // a += b
    e.mov_r32_rsp_disp8(RAX, oa);
    e.bytes(&[0x03, 0xC2]); // add eax, edx
    e.mov_rsp_disp8_r32(oa, RAX);
    // d ^= a; d <<<= 8
    e.mov_r32_rsp_disp8(RDX, od);
    e.bytes(&[0x33, 0xD0]);
    e.rol_r32_imm8(RDX, 8);
    e.mov_rsp_disp8_r32(od, RDX);
    // c += d
    e.mov_r32_rsp_disp8(RAX, oc);
    e.bytes(&[0x03, 0xC2]);
    e.mov_rsp_disp8_r32(oc, RAX);
    // b ^= c; b <<<= 7
    e.mov_r32_rsp_disp8(RDX, ob);
    e.bytes(&[0x33, 0xD0]);
    e.rol_r32_imm8(RDX, 7);
    e.mov_rsp_disp8_r32(ob, RDX);
}

/// Emit a stub for the given `kind` using `key`, with register allocation
/// determined by `seed`.  Returns an [`EmittedStub`] containing the code bytes.
pub fn emit_stub(kind: StubKind, key: &[u8], seed: u64) -> EmittedStub {
    let alloc = RegAlloc::from_seed(seed);
    let code = match kind {
        StubKind::ChaCha20 | StubKind::AesCtr => emit_xor_keystream_stub(key, &alloc, kind),
        StubKind::RawStubInline => {
            assert_eq!(
                key.len(),
                44,
                "RawStubInline requires exactly 44 bytes (32-byte key + 12-byte nonce); got {}",
                key.len()
            );
            emit_chacha20_inline_stub(key, &alloc)
        }
    };
    EmittedStub {
        code,
        seed,
        kind,
        key: key.to_vec(),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reg_alloc_is_deterministic() {
        let a1 = RegAlloc::from_seed(42);
        let a2 = RegAlloc::from_seed(42);
        assert_eq!(a1.r_idx.name, a2.r_idx.name);
        assert_eq!(a1.r_key.name, a2.r_key.name);
    }

    #[test]
    fn reg_alloc_varies_with_seed() {
        let a0 = RegAlloc::from_seed(0);
        let a1 = RegAlloc::from_seed(1);
        // At least one role should differ between seed 0 and seed 1.
        let same = a0.r_idx.name == a1.r_idx.name
            && a0.r_src.name == a1.r_src.name
            && a0.r_key.name == a1.r_key.name;
        assert!(!same, "seed 0 and seed 1 should produce different register allocations");
    }

    #[test]
    fn stub_code_is_non_empty() {
        let key = vec![0u8; 32];
        let stub = emit_stub(StubKind::ChaCha20, &key, 0);
        assert!(!stub.code.is_empty());
        // Code must end with a RET (0xC3) or key data after it — but
        // there are key bytes after RET, so we check the RET is somewhere.
        assert!(stub.code.contains(&0xC3));
    }

    #[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn stub_decrypts_correctly() {
        // The stub expects the embedded "key" bytes to be the pre-computed
        // keystream (same length as the ciphertext), not a short repeating key.
        // Simulate what poly.rs does: encrypt with keystream XOR, pass the full
        // keystream to emit_stub.  Any arbitrary keystream works here; in
        // production poly.rs uses chacha20_stream(zeros, key_44) as the keystream.
        let plaintext: Vec<u8> = (0u8..64).map(|b| b.wrapping_add(0xA5)).collect();
        // Keystream is the same length as the plaintext (not a short repeating key).
        let keystream: Vec<u8> = (0u8..64).map(|b| b.wrapping_mul(7).wrapping_add(0x3C)).collect();
        let ciphertext: Vec<u8> = plaintext
            .iter()
            .zip(keystream.iter())
            .map(|(&p, &k)| p ^ k)
            .collect();

        // Stub receives the keystream directly; no modulo — keystream[i] == key[i].
        let stub = emit_stub(StubKind::ChaCha20, &keystream, 7);

        unsafe {
            use libc::{mmap, mprotect, munmap, MAP_ANONYMOUS, MAP_PRIVATE, PROT_EXEC, PROT_READ, PROT_WRITE};
            let page_size = 4096usize;
            let code_len = ((stub.code.len() + page_size - 1) / page_size) * page_size;

            let page = mmap(
                std::ptr::null_mut(), code_len,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0,
            ) as *mut u8;
            assert!(!page.is_null());
            std::ptr::copy_nonoverlapping(stub.code.as_ptr(), page, stub.code.len());
            mprotect(page as *mut _, code_len, PROT_READ | PROT_EXEC);

            let mut output = vec![0u8; plaintext.len()];
            let f: extern "C" fn(*const u8, usize, *const u8, *mut u8) =
                std::mem::transmute(page);
            f(ciphertext.as_ptr(), ciphertext.len(), keystream.as_ptr(), output.as_mut_ptr());

            munmap(page as *mut _, code_len);
            assert_eq!(output, plaintext, "stub decryption did not match expected plaintext");
        }
    }

    // ── Reference ChaCha20 (RFC 8439, counter starts at 1) used to oracle ──
    // the inline-stub test below.  Mirrors `chacha20_stream` in poly.rs.
    #[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
    fn ref_chacha20(data: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Vec<u8> {
        fn qr(mut a: u32, mut b: u32, mut c: u32, mut d: u32) -> (u32, u32, u32, u32) {
            a = a.wrapping_add(b); d ^= a; d = d.rotate_left(16);
            c = c.wrapping_add(d); b ^= c; b = b.rotate_left(12);
            a = a.wrapping_add(b); d ^= a; d = d.rotate_left(8);
            c = c.wrapping_add(d); b ^= c; b = b.rotate_left(7);
            (a, b, c, d)
        }
        fn block(state: &[u32; 16]) -> [u8; 64] {
            let mut w = *state;
            for _ in 0..10 {
                let (w0,w4,w8,w12) = qr(w[0],w[4],w[8],w[12]);
                w[0]=w0; w[4]=w4; w[8]=w8; w[12]=w12;
                let (w1,w5,w9,w13) = qr(w[1],w[5],w[9],w[13]);
                w[1]=w1; w[5]=w5; w[9]=w9; w[13]=w13;
                let (w2,w6,w10,w14) = qr(w[2],w[6],w[10],w[14]);
                w[2]=w2; w[6]=w6; w[10]=w10; w[14]=w14;
                let (w3,w7,w11,w15) = qr(w[3],w[7],w[11],w[15]);
                w[3]=w3; w[7]=w7; w[11]=w11; w[15]=w15;
                let (w0,w5,w10,w15) = qr(w[0],w[5],w[10],w[15]);
                w[0]=w0; w[5]=w5; w[10]=w10; w[15]=w15;
                let (w1,w6,w11,w12) = qr(w[1],w[6],w[11],w[12]);
                w[1]=w1; w[6]=w6; w[11]=w11; w[12]=w12;
                let (w2,w7,w8,w13) = qr(w[2],w[7],w[8],w[13]);
                w[2]=w2; w[7]=w7; w[8]=w8; w[13]=w13;
                let (w3,w4,w9,w14) = qr(w[3],w[4],w[9],w[14]);
                w[3]=w3; w[4]=w4; w[9]=w9; w[14]=w14;
            }
            let mut out = [0u8; 64];
            for i in 0..16 {
                let added = w[i].wrapping_add(state[i]);
                out[i*4..i*4+4].copy_from_slice(&added.to_le_bytes());
            }
            out
        }
        let mut kw = [0u32; 8];
        for i in 0..8 { kw[i] = u32::from_le_bytes(key[i*4..i*4+4].try_into().unwrap()); }
        let mut nw = [0u32; 3];
        for i in 0..3 { nw[i] = u32::from_le_bytes(nonce[i*4..i*4+4].try_into().unwrap()); }
        let cs: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
        let mut out = Vec::with_capacity(data.len());
        let mut counter: u32 = 1;
        let mut pos = 64usize;
        let mut ks = [0u8; 64];
        for &byte in data {
            if pos >= 64 {
                let state = [
                    cs[0],cs[1],cs[2],cs[3],
                    kw[0],kw[1],kw[2],kw[3],
                    kw[4],kw[5],kw[6],kw[7],
                    counter, nw[0],nw[1],nw[2],
                ];
                ks = block(&state);
                pos = 0;
                counter = counter.wrapping_add(1);
            }
            out.push(byte ^ ks[pos]);
            pos += 1;
        }
        out
    }

    #[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
    fn run_inline_stub(stub: &[u8], ct: &[u8], len: usize) -> Vec<u8> {
        unsafe {
            use libc::{mmap, mprotect, munmap, MAP_ANONYMOUS, MAP_PRIVATE, PROT_EXEC, PROT_READ, PROT_WRITE};
            let page_size = 4096usize;
            let code_len = ((stub.len() + page_size - 1) / page_size) * page_size;
            let page = mmap(
                std::ptr::null_mut(), code_len,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0,
            ) as *mut u8;
            assert!(!page.is_null());
            std::ptr::copy_nonoverlapping(stub.as_ptr(), page, stub.len());
            mprotect(page as *mut _, code_len, PROT_READ | PROT_EXEC);
            let mut output = vec![0u8; len];
            let f: extern "C" fn(*const u8, usize, *const u8, *mut u8) =
                std::mem::transmute(page);
            f(ct.as_ptr(), len, std::ptr::null(), output.as_mut_ptr());
            munmap(page as *mut _, code_len);
            output
        }
    }

    #[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn inline_stub_data_section_is_44_bytes() {
        let key = [0u8; 44];
        let stub = emit_stub(StubKind::RawStubInline, &key, 0);
        // Last 44 bytes of the code blob must be the embedded key+nonce data.
        assert!(stub.code.len() >= 44);
        let trailing = &stub.code[stub.code.len() - 44..];
        assert_eq!(trailing, &key[..]);
    }

    #[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn inline_stub_decrypts_empty() {
        // Edge case: ct_len == 0 must return immediately without crashing.
        let mut key = [0u8; 44];
        for (i, b) in key.iter_mut().enumerate() { *b = (i as u8).wrapping_mul(13); }
        let stub = emit_stub(StubKind::RawStubInline, &key, 1);
        let out = run_inline_stub(&stub.code, &[], 0);
        assert_eq!(out.len(), 0);
    }

    #[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn inline_stub_matches_reference_for_various_lengths() {
        // Try several lengths spanning <1 block, 1 full block, multi-block,
        // and multi-block with partial tail.
        let mut key_arr = [0u8; 32];
        let mut nonce_arr = [0u8; 12];
        for (i, b) in key_arr.iter_mut().enumerate()   { *b = (i as u8).wrapping_mul(31).wrapping_add(7); }
        for (i, b) in nonce_arr.iter_mut().enumerate() { *b = (i as u8).wrapping_mul(53).wrapping_add(11); }
        let mut key44 = [0u8; 44];
        key44[..32].copy_from_slice(&key_arr);
        key44[32..].copy_from_slice(&nonce_arr);

        for (seed, len) in [(0u64, 0usize), (1, 1), (2, 17), (3, 63), (4, 64), (5, 65), (6, 128), (7, 200)] {
            let plaintext: Vec<u8> = (0..len).map(|i| ((i as u32).wrapping_mul(2654435761) >> 24) as u8).collect();
            let ciphertext = ref_chacha20(&plaintext, &key_arr, &nonce_arr);
            let stub = emit_stub(StubKind::RawStubInline, &key44, seed);
            let decrypted = run_inline_stub(&stub.code, &ciphertext, len);
            assert_eq!(decrypted, plaintext,
                "inline stub mismatch at seed={} len={}", seed, len);
        }
    }
}
