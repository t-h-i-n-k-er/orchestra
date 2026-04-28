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
}

// ── Stub kinds ────────────────────────────────────────────────────────────────

/// The encryption scheme to generate a raw stub for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StubKind {
    ChaCha20,
    AesCtr,
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

/// Emit a stub for the given `kind` using `key`, with register allocation
/// determined by `seed`.  Returns an [`EmittedStub`] containing the code bytes.
pub fn emit_stub(kind: StubKind, key: &[u8], seed: u64) -> EmittedStub {
    let alloc = RegAlloc::from_seed(seed);
    let code = emit_xor_keystream_stub(key, &alloc, kind);
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
}
