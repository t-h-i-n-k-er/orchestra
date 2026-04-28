//! x86-64 instruction-level code transformation for obfuscation.
//!
//! # Pipeline
//!
//! 1. **Instruction substitution** (M-1): replaces instruction sequences with
//!    semantically equivalent alternatives that look different on the wire:
//!    - `MOV reg, 0`  →  `XOR reg, reg`  (Rule 1)
//!    - Insert `SUB reg, 1` / `ADD reg, 1` dead-code pair after arithmetic
//!      instructions (Rule 2, probabilistic 30 %)
//!    - `MOV dst, src` + `ADD dst, imm`  →  `LEA dst, [src+imm]`  (Rule 3)
//!
//! 2. **Basic-block reordering with opaque predicates** (M-2): splits the
//!    code into basic blocks, shuffles their order, reconnects them with
//!    explicit `JMP` instructions, and inserts opaque predicates (always-
//!    taken / never-taken conditional branches that appear non-deterministic)
//!    at the entry of each reordered block.
//!
//! All transforms are **deterministic** given the same seed (uses ChaCha8RNG),
//! making the build fully reproducible when the same `CODE_TRANSFORM_SEED` is
//! provided.
//!
//! Functions that contain inline assembly must be excluded by the caller before
//! passing their machine code to these routines.

pub mod reorder;
pub mod runtime;
pub mod substitute;

use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

/// Apply the full transformation pipeline to a flat slice of x86-64 machine
/// code and return the (possibly larger) transformed byte sequence.
///
/// `seed` must be the same value on every build for a reproducible output.
///
/// # Panics
/// Will not panic on well-formed code; malformed or truncated encodings are
/// silently passed through by `BlockEncoder`.
pub fn transform(code: &[u8], seed: u64) -> Vec<u8> {
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let after_sub = substitute::apply_substitutions(code, &mut rng);
    reorder::reorder_blocks(&after_sub, &mut rng)
}
