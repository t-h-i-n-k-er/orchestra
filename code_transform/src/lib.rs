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
//! 3. **Control-flow flattening** (M-1 prompt): rewrites block-to-block edges
//!    into explicit dispatcher-state transitions (`state = id; jmp dispatcher`)
//!    and routes execution through a single dispatcher `cmp+jmp` chain with
//!    opaque predicates before each entry.
//!
//! All transforms are **deterministic** given the same seed (uses ChaCha8RNG),
//! making the build fully reproducible when the same `CODE_TRANSFORM_SEED` is
//! provided.
//!
//! Functions that contain inline assembly must be excluded by the caller before
//! passing their machine code to these routines.

pub mod runtime;
#[cfg(target_arch = "x86_64")]
pub mod cfflatten;
#[cfg(target_arch = "x86_64")]
pub mod opcode_diversity;
#[cfg(target_arch = "x86_64")]
pub mod regalloc;
#[cfg(target_arch = "x86_64")]
pub mod reorder;
#[cfg(target_arch = "x86_64")]
pub mod substitute;

#[cfg(target_arch = "aarch64")]
pub mod substitute_aarch64;
#[cfg(target_arch = "aarch64")]
pub mod reorder_aarch64;

#[cfg(target_arch = "x86_64")]
use rand::SeedableRng;
#[cfg(target_arch = "x86_64")]
use rand_chacha::ChaCha8Rng;

/// Apply the full transformation pipeline to a flat slice of x86-64 machine
/// code and return the (possibly larger) transformed byte sequence.
///
/// `seed` must be the same value on every build for a reproducible output.
///
/// # Panics
/// Will not panic on well-formed code; malformed or truncated encodings are
/// silently passed through by `BlockEncoder`.
#[cfg(target_arch = "x86_64")]
pub fn transform(code: &[u8], seed: u64) -> Vec<u8> {
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let after_sub = substitute::apply_substitutions(code, &mut rng);
    let after_reorder = reorder::reorder_blocks(&after_sub, &mut rng);
    let after_flatten = cfflatten::flatten_control_flow(&after_reorder, &mut rng);
    opcode_diversity::apply(&after_flatten, &mut rng)
}

/// AArch64 transform pipeline.  Runs the substitution pass followed by the
/// basic-block reorder pass.  Both passes are length-aware and re-resolve
/// PC-relative branch displacements; inputs containing PC-relative *data*
/// references (`ADR`/`ADRP`/`LDR (literal)`) are returned unchanged from the
/// reorder pass to stay safe.
///
/// `seed` produces deterministic output for reproducible builds.
#[cfg(target_arch = "aarch64")]
pub fn transform(code: &[u8], seed: u64) -> Vec<u8> {
    use rand::SeedableRng;
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(seed);
    let after_sub = substitute_aarch64::apply_substitutions(code, &mut rng);
    reorder_aarch64::reorder_blocks(&after_sub, &mut rng)
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub fn transform(code: &[u8], _seed: u64) -> Vec<u8> {
    log::warn!(
        "code_transform: instruction transformation is not supported on architecture '{}'; returning input unchanged",
        std::env::consts::ARCH
    );
    code.to_vec()
}
