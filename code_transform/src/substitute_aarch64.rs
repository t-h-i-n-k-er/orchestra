//! M-1 (ARM64) – Instruction substitution pass for `aarch64`.
#![cfg(target_arch = "aarch64")]
//!
//! ARM64 (AArch64) instructions are fixed-width 32-bit values stored in
//! little-endian byte order.  This makes a minimal in-house parser/encoder
//! sufficient — `iced-x86` only supports x86 families.
//!
//! # Substitution rules
//!
//! **Rule 1** `MOVZ Xd, #0, LSL #0` → `EOR Xd, Xd, Xd`
//! Length-preserving (4 bytes).  Both encodings produce the same 64-bit
//! value (zero) and identical N/Z/C/V state (none — neither EOR nor MOVZ
//! sets flags).
//!
//! **Rule 2** `MOV Xd, Xn`  →  `ADD Xd, Xn, #0`
//! `MOV (register)` is canonically the alias `ORR Xd, XZR, Xn`; the
//! replacement uses the `ADD (immediate)` form with `imm12 = 0`.  Same
//! semantics, no flag change, length-preserving.
//!
//! **Rule 3 (insertion)** Insert a `MOV X16, X16` (`ORR X16, XZR, X16`)
//! NOP-equivalent after non-branch, non-PC-relative-data instructions with
//! ~5 % probability.  X16 (IP0) is the architectural intra-procedure-call
//! scratch register and is volatile across calls in the AAPCS64 ABI.
//!
//! # Branch retargeting
//!
//! Insertion shifts the code, so every PC-relative branch
//! (`B`, `BL`, `B.cond`, `CBZ/CBNZ`, `TBZ/TBNZ`) is rewritten to point at
//! the *new* offset of its original target.  We track each instruction's
//! original byte offset and rebuild the displacement after layout is
//! finalised.
//!
//! # Safety conservatism
//!
//! If the input contains PC-relative *data* references (`ADR`, `ADRP`, or
//! `LDR (literal)`), insertion is disabled because those addresses would
//! otherwise silently desync.  Length-preserving rules still apply.

use rand::Rng;

// ── Branch / PC-relative classification ──────────────────────────────────────

/// PC-relative *data* references (ADR/ADRP/LDR-literal) — these point at
/// addresses outside the ordinary control-flow graph and we cannot safely
/// retarget them without symbol information.
pub(crate) fn is_pcrel_data(raw: u32) -> bool {
    // ADR / ADRP: bits[28:24] = 10000.  The bit[31] flag selects ADR vs ADRP.
    if (raw & 0x1F00_0000) == 0x1000_0000 {
        return true;
    }
    // LDR (literal): bits[29:27]=011, bit[24]=0 → mask 0x3B000000 == 0x18000000.
    // Covers GP (32/64-bit) and SIMD/FP literal loads (LDR/PRFM literal share
    // the encoding family).
    if (raw & 0x3B00_0000) == 0x1800_0000 {
        return true;
    }
    false
}

/// Decode the *byte* displacement encoded in a PC-relative branch instruction.
/// Returns `None` for non-branch or for register-indirect branches.
pub(crate) fn pc_rel_branch_disp(raw: u32) -> Option<i32> {
    // B / BL: bits[30:26] = 00101, bit[31] = 0 (B) or 1 (BL).
    let top6 = raw >> 26;
    if top6 == 0b000101 || top6 == 0b100101 {
        let imm26 = (raw & 0x03FF_FFFF) as i32;
        // Sign-extend from 26 bits.
        let s = (imm26 << 6) >> 6;
        return Some(s * 4);
    }
    // B.cond: bits[31:24] = 01010100, bit[4] = 0.
    if (raw & 0xFF00_0010) == 0x5400_0000 {
        let imm19 = ((raw >> 5) & 0x7_FFFF) as i32;
        let s = (imm19 << 13) >> 13;
        return Some(s * 4);
    }
    // CBZ / CBNZ: bits[30:25] = 011010, bit[24] selects Z/NZ.
    let masked = raw & 0x7F00_0000;
    if masked == 0x3400_0000 || masked == 0x3500_0000 {
        let imm19 = ((raw >> 5) & 0x7_FFFF) as i32;
        let s = (imm19 << 13) >> 13;
        return Some(s * 4);
    }
    // TBZ / TBNZ: bits[30:25] = 011011.
    if masked == 0x3600_0000 || masked == 0x3700_0000 {
        let imm14 = ((raw >> 5) & 0x3FFF) as i32;
        let s = (imm14 << 18) >> 18;
        return Some(s * 4);
    }
    None
}

/// Re-encode a PC-relative branch with a new byte displacement.
///
/// Out-of-range displacements are clamped by truncation; the caller is
/// responsible for ensuring the new layout keeps every branch within the
/// encoding width of its instruction class.
pub(crate) fn rewrite_branch_disp(raw: u32, new_disp_bytes: i32) -> u32 {
    debug_assert_eq!(new_disp_bytes & 0x3, 0, "branch displacement must be 4-byte aligned");
    let imm = new_disp_bytes >> 2;

    let top6 = raw >> 26;
    if top6 == 0b000101 || top6 == 0b100101 {
        let imm26 = (imm as u32) & 0x03FF_FFFF;
        return (raw & 0xFC00_0000) | imm26;
    }
    if (raw & 0xFF00_0010) == 0x5400_0000 {
        let imm19 = (imm as u32) & 0x7_FFFF;
        return (raw & !(0x7_FFFF << 5)) | (imm19 << 5);
    }
    let masked = raw & 0x7F00_0000;
    if masked == 0x3400_0000 || masked == 0x3500_0000 {
        let imm19 = (imm as u32) & 0x7_FFFF;
        return (raw & !(0x7_FFFF << 5)) | (imm19 << 5);
    }
    if masked == 0x3600_0000 || masked == 0x3700_0000 {
        let imm14 = (imm as u32) & 0x3FFF;
        return (raw & !(0x3FFF << 5)) | (imm14 << 5);
    }
    raw
}

/// Categorise a branch for control-flow purposes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BranchKind {
    /// Not a branch at all.
    None,
    /// Conditional / compare-and-branch / test-and-branch — falls through.
    PcRelCond,
    /// Unconditional `B` PC-relative — terminator.
    PcRelB,
    /// `BL` — call, returns to next instruction; not a terminator.
    PcRelBL,
    /// `BR Xn` — register-indirect branch, terminator.
    BrIndirect,
    /// `BLR Xn` — register-indirect call, not a terminator.
    BlrIndirect,
    /// `RET Xn` — return, terminator.
    Ret,
}

pub(crate) fn classify(raw: u32) -> BranchKind {
    let top6 = raw >> 26;
    if top6 == 0b000101 {
        return BranchKind::PcRelB;
    }
    if top6 == 0b100101 {
        return BranchKind::PcRelBL;
    }
    if (raw & 0xFF00_0010) == 0x5400_0000 {
        return BranchKind::PcRelCond;
    }
    let masked = raw & 0x7F00_0000;
    if masked == 0x3400_0000 || masked == 0x3500_0000
        || masked == 0x3600_0000 || masked == 0x3700_0000
    {
        return BranchKind::PcRelCond;
    }
    // Unconditional register-indirect branches: 1101_0110_000_x_xxxx_000000_Rn_00000
    // BR  Xn = 0xD61F0000 | (Rn<<5)
    // BLR Xn = 0xD63F0000 | (Rn<<5)
    // RET Xn = 0xD65F0000 | (Rn<<5)   default RET = 0xD65F03C0 (Xn=X30)
    if (raw & 0xFFFF_FC1F) == 0xD61F_0000 {
        return BranchKind::BrIndirect;
    }
    if (raw & 0xFFFF_FC1F) == 0xD63F_0000 {
        return BranchKind::BlrIndirect;
    }
    if (raw & 0xFFFF_FC1F) == 0xD65F_0000 {
        return BranchKind::Ret;
    }
    BranchKind::None
}

/// Returns true for instructions that end a basic block (control does not
/// fall through to the next instruction).
pub(crate) fn is_terminator(kind: BranchKind) -> bool {
    matches!(kind, BranchKind::PcRelB | BranchKind::BrIndirect | BranchKind::Ret)
}

// ── Length-preserving substitution detectors / encoders ──────────────────────

/// Detect `MOVZ Xd, #0, LSL #0` (sf=1, hw=00, imm16=0).
fn is_movz_xd_zero(raw: u32) -> bool {
    // Encoding: 1_10_100101_00_0000000000000000_Rd  →  0xD2800000 | Rd
    (raw & 0xFFFF_FFE0) == 0xD280_0000
}

/// Build `EOR Xd, Xd, Xd` (shifted register, shift=0, imm6=0):
/// `1_10_01010_00_0_Rm_000000_Rn_Rd`  →  `0xCA000000 | (Rm<<16) | (Rn<<5) | Rd`.
fn make_eor_same(d: u32) -> u32 {
    debug_assert!(d < 32);
    0xCA00_0000 | (d << 16) | (d << 5) | d
}

/// Detect the `MOV Xd, Xn` alias (`ORR Xd, XZR, Xn`, shift=0, imm6=0).
/// Excludes XZR/SP-using forms which carry different semantics.
fn is_mov_xd_xn(raw: u32) -> Option<(u32, u32)> {
    // Mask: 1_01_01010_00_0_xxxxx_000000_11111_xxxxx
    if (raw & 0xFFE0_FC1F) != 0xAA00_03E0 {
        return None;
    }
    let rd = raw & 0x1F;
    let rm = (raw >> 16) & 0x1F;
    // XZR-as-target or XZR-as-source corner cases — leave them alone.
    if rd == 31 || rm == 31 || rd == rm {
        return None;
    }
    Some((rd, rm))
}

/// Build `ADD Xd, Xn, #0` (sf=1, sh=0, imm12=0): `0x91000000 | (Rn<<5) | Rd`.
fn make_add_imm0(d: u32, n: u32) -> u32 {
    debug_assert!(d < 32 && n < 32);
    0x9100_0000 | (n << 5) | d
}

/// `MOV Xd, Xd` NOP equivalent, encoded as `ORR Xd, XZR, Xd`.
pub(crate) fn make_mov_xd_xd(d: u32) -> u32 {
    debug_assert!(d < 31, "use of XZR as Xd would change semantics");
    0xAA00_03E0 | (d << 16) | d
}

/// Architectural NOP: `D5 03 20 1F`.
pub(crate) const ARM64_NOP: u32 = 0xD503_201F;

// ── Item / layout machinery ──────────────────────────────────────────────────

/// One position in the post-transform instruction stream.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Item {
    pub raw: u32,
    pub kind: ItemKind,
}

/// Where an item came from and (for synthetic branches) where it must point.
#[derive(Clone, Copy, Debug)]
pub(crate) enum ItemKind {
    /// Carried over from the input — `orig_offset` is the instruction's
    /// original byte offset within the input `code` slice.
    Original { orig_offset: u32 },
    /// Synthetic non-branch instruction (e.g. a NOP-equivalent MOV).
    SyntheticData,
    /// Synthetic branch; `target` indicates the intended destination.
    SyntheticBranch { target: SyntheticTarget },
}

/// Resolution policy for a synthetic branch.
#[derive(Clone, Copy, Debug)]
pub(crate) enum SyntheticTarget {
    /// Skip to the instruction immediately after this one (rel +4).
    NextInstr,
    /// Branch to whatever new offset the original instruction at this byte
    /// offset ends up at after the layout pass.
    OrigOffset(u32),
}

/// Resolve all branch displacements (original *and* synthetic) and serialise
/// `items` to a flat byte vector.
pub(crate) fn finalize(items: &[Item]) -> Vec<u8> {
    use std::collections::HashMap;

    // 1. Build the orig→new offset map.
    let mut orig_to_new: HashMap<u32, u32> = HashMap::with_capacity(items.len());
    for (i, it) in items.iter().enumerate() {
        if let ItemKind::Original { orig_offset } = it.kind {
            orig_to_new.insert(orig_offset, (i * 4) as u32);
        }
    }

    // 2. Emit each instruction with its displacement adjusted.
    let mut out = Vec::with_capacity(items.len() * 4);
    for (i, it) in items.iter().enumerate() {
        let new_off = (i * 4) as u32;
        let raw = match it.kind {
            ItemKind::Original { orig_offset } => {
                if let Some(disp_orig) = pc_rel_branch_disp(it.raw) {
                    let target_orig = (orig_offset as i64) + (disp_orig as i64);
                    // If the target maps to a known new offset, retarget.
                    // Otherwise (out-of-range branch into trailing data or
                    // pre-input prologue), preserve the *absolute* target by
                    // re-deriving the displacement from the new position.
                    let target_new = match orig_to_new.get(&(target_orig as u32)) {
                        Some(&n) => n as i64,
                        None => target_orig, // best effort
                    };
                    let new_disp = target_new - (new_off as i64);
                    if let Ok(n) = i32::try_from(new_disp) {
                        rewrite_branch_disp(it.raw, n & !0x3)
                    } else {
                        it.raw
                    }
                } else {
                    it.raw
                }
            }
            ItemKind::SyntheticData => it.raw,
            ItemKind::SyntheticBranch { target } => {
                let target_new = match target {
                    SyntheticTarget::NextInstr => (new_off + 4) as i64,
                    SyntheticTarget::OrigOffset(o) => match orig_to_new.get(&o) {
                        Some(&n) => n as i64,
                        None => new_off as i64 + 4, // fall through harmlessly
                    },
                };
                let disp = target_new - (new_off as i64);
                if let Ok(n) = i32::try_from(disp) {
                    rewrite_branch_disp(it.raw, n & !0x3)
                } else {
                    it.raw
                }
            }
        };
        out.extend_from_slice(&raw.to_le_bytes());
    }
    out
}

// ── Public substitution entry point ──────────────────────────────────────────

/// Apply the AArch64 substitution rules to `code` and return the rewritten
/// bytes.  The input length must be a multiple of 4 (AArch64 instruction
/// alignment); inputs that are not a multiple of 4 are returned unchanged.
pub fn apply_substitutions(code: &[u8], rng: &mut impl Rng) -> Vec<u8> {
    if code.is_empty() || code.len() % 4 != 0 {
        return code.to_vec();
    }

    // Build initial Item list from the input.
    let mut items: Vec<Item> = code
        .chunks_exact(4)
        .enumerate()
        .map(|(i, b)| Item {
            raw: u32::from_le_bytes(b.try_into().unwrap()),
            kind: ItemKind::Original { orig_offset: (i * 4) as u32 },
        })
        .collect();

    // Pass 1: length-preserving rewrites.  Operates instruction-locally so
    // there is no layout impact and no need for branch retargeting yet.
    for it in &mut items {
        if is_movz_xd_zero(it.raw) {
            let rd = it.raw & 0x1F;
            it.raw = make_eor_same(rd);
            continue;
        }
        if let Some((rd, rn)) = is_mov_xd_xn(it.raw) {
            it.raw = make_add_imm0(rd, rn);
            continue;
        }
        if it.raw == ARM64_NOP && rng.gen_bool(0.30) {
            it.raw = make_mov_xd_xd(16); // X16 (IP0) — call-clobbered scratch
            continue;
        }
    }

    // Pass 2: optional NOP-equivalent insertion.  Disabled when the input
    // contains PC-relative *data* references we cannot safely retarget.
    let has_pcrel_data = items.iter().any(|it| is_pcrel_data(it.raw));
    if !has_pcrel_data {
        let mut expanded: Vec<Item> = Vec::with_capacity(items.len() + items.len() / 16);
        for it in items.into_iter() {
            let kind = classify(it.raw);
            expanded.push(it);
            // Don't insert immediately after a terminator (would be unreachable)
            // or before/after PC-rel data instructions (handled by the gate).
            // Keep the probability low so the size blow-up is bounded.
            if kind == BranchKind::None && rng.gen_bool(0.05) {
                let nop_raw = if rng.gen_bool(0.5) {
                    make_mov_xd_xd(16) // MOV X16, X16
                } else {
                    ARM64_NOP // architectural NOP
                };
                expanded.push(Item {
                    raw: nop_raw,
                    kind: ItemKind::SyntheticData,
                });
            }
        }
        items = expanded;
    }

    // Pass 3: re-resolve all branch displacements and emit bytes.
    finalize(&items)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    fn le_bytes(insns: &[u32]) -> Vec<u8> {
        let mut v = Vec::with_capacity(insns.len() * 4);
        for &i in insns {
            v.extend_from_slice(&i.to_le_bytes());
        }
        v
    }

    fn from_le(bytes: &[u8]) -> Vec<u32> {
        bytes.chunks_exact(4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
            .collect()
    }

    #[test]
    fn movz_zero_to_eor_same_register() {
        // MOVZ X3, #0  → EOR X3, X3, X3
        let movz_x3 = 0xD280_0000 | 3;
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let out = apply_substitutions(&le_bytes(&[movz_x3]), &mut rng);
        let words = from_le(&out);
        assert_eq!(words.len(), 1);
        // EOR X3, X3, X3 = 0xCA030063
        assert_eq!(words[0], make_eor_same(3));
    }

    #[test]
    fn mov_reg_to_add_imm_zero() {
        // MOV X5, X9 = ORR X5, XZR, X9 = 0xAA0903E5
        let mov = 0xAA00_03E0 | (9 << 16) | 5;
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let out = apply_substitutions(&le_bytes(&[mov]), &mut rng);
        let words = from_le(&out);
        assert_eq!(words[0], make_add_imm0(5, 9));
    }

    #[test]
    fn nop_sometimes_replaced_with_mov_x16_x16() {
        // Run many seeds; at least one must have replaced the NOP.
        let mut replaced_any = false;
        for s in 0u64..32 {
            let mut rng = ChaCha8Rng::seed_from_u64(s);
            let out = apply_substitutions(&le_bytes(&[ARM64_NOP]), &mut rng);
            let words = from_le(&out);
            // First instruction must either remain NOP or become MOV X16, X16.
            assert!(words[0] == ARM64_NOP || words[0] == make_mov_xd_xd(16));
            if words[0] == make_mov_xd_xd(16) {
                replaced_any = true;
            }
        }
        assert!(replaced_any, "NOP substitution should fire for at least one seed in [0,32)");
    }

    #[test]
    fn empty_and_misaligned_input_passthrough() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        assert_eq!(apply_substitutions(&[], &mut rng), Vec::<u8>::new());
        assert_eq!(apply_substitutions(&[0x00, 0x01, 0x02], &mut rng), vec![0x00, 0x01, 0x02]);
    }

    #[test]
    fn branches_retargeted_after_insertion() {
        // Layout (orig offsets):
        //   0x00  MOVZ X0, #0            (length-preserving rewrite)
        //   0x04  B    +0x10  (target = 0x14)
        //   0x08  MOVZ X1, #0
        //   0x0C  MOVZ X2, #0
        //   0x10  MOVZ X3, #0
        //   0x14  RET
        let movz = |rd: u32| 0xD280_0000 | rd;
        let b_plus_10 = 0x1400_0000 | (4 & 0x03FF_FFFF); // +4 instructions = +16 bytes
        let ret_x30 = 0xD65F_03C0;
        let input = le_bytes(&[movz(0), b_plus_10, movz(1), movz(2), movz(3), ret_x30]);

        // Try several seeds.  After the transformation, the B's new
        // displacement must still land on the (possibly relocated) RET.
        for s in 0u64..16 {
            let mut rng = ChaCha8Rng::seed_from_u64(s);
            let out = apply_substitutions(&input, &mut rng);
            let words = from_le(&out);

            // Locate the RET in the new layout.
            let ret_pos = words.iter().position(|&w| w == ret_x30)
                .expect("RET must survive the transform");

            // Locate the (only) unconditional B in the new layout.
            let b_pos = words.iter().position(|&w| classify(w) == BranchKind::PcRelB)
                .expect("B must survive the transform");

            // Decode the B's target and verify it points at the RET.
            let disp = pc_rel_branch_disp(words[b_pos]).unwrap();
            let target_byte_offset = (b_pos as i64) * 4 + disp as i64;
            assert_eq!(target_byte_offset as usize, ret_pos * 4,
                "seed={s}: B at idx {b_pos} with disp {disp} should land on RET at idx {ret_pos}");
        }
    }

    #[test]
    fn pcrel_data_disables_insertion() {
        // ADRP X0, #0 — PC-relative data reference; insertion must be skipped.
        let adrp_x0 = 0x9000_0000;
        let movz_x1 = 0xD280_0000 | 1;
        let input = le_bytes(&[adrp_x0, movz_x1, movz_x1, movz_x1, movz_x1]);

        for s in 0u64..16 {
            let mut rng = ChaCha8Rng::seed_from_u64(s);
            let out = apply_substitutions(&input, &mut rng);
            // No insertion → output length must equal input length.
            assert_eq!(out.len(), input.len(),
                "seed={s}: insertion must be disabled when ADRP is present");
        }
    }

    #[test]
    fn branch_disp_round_trip() {
        // Verify rewrite_branch_disp / pc_rel_branch_disp invert each other
        // for each branch family across a range of displacements.
        let cases: &[u32] = &[
            0x1400_0000, // B
            0x9400_0000, // BL
            0x5400_0001, // B.NE
            0x3400_001F, // CBZ X31 (XZR)
            0x3500_001F, // CBNZ XZR
            0xB6F8_001F, // TBZ XZR, #63, ...
            0xB7F8_001F, // TBNZ XZR, #63, ...
        ];
        for &base in cases {
            // Pick displacements that fit the smallest field (TBZ: 14-bit ×4 = ±32KB).
            for &d in &[-1024i32, -4, 0, 4, 4096, 16384] {
                let rebuilt = rewrite_branch_disp(base, d);
                let decoded = pc_rel_branch_disp(rebuilt).expect("must decode");
                assert_eq!(decoded, d, "round-trip failed for base 0x{base:08X} disp {d}");
            }
        }
    }
}
