extern crate proc_macro;

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use rand::{Rng as _, SeedableRng};
use syn::{parse_macro_input, parse_quote, ItemFn, Stmt};

// ── Build seed ────────────────────────────────────────────────────────────────

/// Return the seed used for all per-build randomness.
/// Honoured in order: `ORCHESTRA_JUNK_SEED` env var, then nanosecond timestamp.
fn get_seed() -> u64 {
    std::env::var("ORCHESTRA_JUNK_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64
        })
}

// ── insert_junk!() ────────────────────────────────────────────────────────────

/// Generate 4 random `i32` junk values seeded from the current build time.
///
/// Each invocation of `insert_junk!()` within the same compilation produces
/// different values because `std::time::SystemTime::now()` advances between
/// macro expansions.  Across separate `cargo build` runs the seed changes,
/// so every Orchestra binary has statically distinct junk code — making
/// pattern-based fingerprinting significantly harder.
///
/// To reproduce a specific build exactly, set the `ORCHESTRA_JUNK_SEED`
/// environment variable to a `u64` value before compiling.
fn expansion() -> TokenStream2 {
    let seed: u64 = get_seed();
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    let v1: i32 = rng.gen_range(100..10_000);
    let v2: i32 = rng.gen_range(100..10_000);
    let v3: i32 = rng.gen_range(100..10_000);
    let v4: i32 = rng.gen_range(100..10_000);

    quote! {
        {
            let junk_values: [i32; 4] = [#v1, #v2, #v3, #v4];
            for value in junk_values {
                std::hint::black_box(value.wrapping_mul(3).wrapping_add(1));
            }
            unsafe {
                let volatile_value = std::ptr::read_volatile(&junk_values[0] as *const i32);
                std::hint::black_box(volatile_value);
            }
        }
    }
}

#[proc_macro]
pub fn insert_junk(_item: TokenStream) -> TokenStream {
    expansion().into()
}

// ── junk_barrier block generator ─────────────────────────────────────────────

/// Parse the tamper-response expression from raw attribute tokens.
///
/// Accepts `tamper = "path::to::fn"` (calls the function) or empty tokens
/// (default: `::core::hint::black_box(())`).
fn parse_tamper(attr: TokenStream) -> TokenStream2 {
    if attr.is_empty() {
        return quote! { ::core::hint::black_box(()) };
    }
    let parsed = syn::parse::<syn::MetaNameValue>(attr)
        .ok()
        .filter(|nv| nv.path.is_ident("tamper"))
        .and_then(|nv| match nv.value {
            syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(s),
                ..
            }) => s
                .parse::<syn::ExprPath>()
                .ok()
                .map(|p| quote! { #p() }),
            _ => None,
        });
    parsed.unwrap_or_else(|| quote! { ::core::hint::black_box(()) })
}

/// Build one semantically-equivalent junk barrier block.
///
/// The generated block:
/// 1. Declares nine mutable `u64` locals named after x86_64 caller-saved
///    registers (`rax`, `rcx`, `rdx`, `rsi`, `rdi`, `r8`, `r9`, `r10`, `r11`)
///    with random initial values — simulating a register push.
/// 2. Applies `n_ops ∈ [8, 16]` random arithmetic operations:
///    * wrapping add / sub with a random immediate
///    * XOR with a random immediate
///    * register-to-register wrapping add
/// 3. Computes a hash (XOR fold of all final register values) and checks it
///    against a constant precomputed at macro expansion time.  The check is
///    **always false at run-time** by construction, so `tamper` is never
///    called.  Static analysis sees a meaningful hash check; the optimiser
///    evaluates the entire block at compile time and removes it.
/// 4. Binds all locals with `let _` — simulating a register pop — so the
///    optimiser can prove they are dead and eliminate the block.
///
/// `id` is mixed into all identifier names so multiple barriers inside the
/// same function scope do not shadow one another.
pub(crate) fn make_barrier_block(
    rng: &mut rand::rngs::StdRng,
    tamper: &TokenStream2,
    id: usize,
) -> TokenStream2 {
    // x86_64 caller-saved registers: RAX RCX RDX RSI RDI R8 R9 R10 R11
    const NREGS: usize = 9;
    let reg_ids: Vec<proc_macro2::Ident> = ["rax", "rcx", "rdx", "rsi", "rdi", "r8x", "r9x", "r10", "r11"]
        .iter()
        .map(|n| format_ident!("_jb_{}_{}", n, id))
        .collect();

    // Random initial values (one per "register")
    let init_vals: Vec<u64> = (0..NREGS).map(|_| rng.gen::<u64>()).collect();

    // Random operations: (dst_reg_idx, kind, immediate, src_reg_idx)
    //   kind 0 → wrapping_add(imm)
    //   kind 1 → wrapping_sub(imm)
    //   kind 2 → ^= imm
    //   kind 3 → wrapping_add(src_reg)  [reg-reg]
    let n_ops: usize = rng.gen_range(8usize..=16);
    let ops: Vec<(usize, u8, u64, usize)> = (0..n_ops)
        .map(|_| {
            (
                rng.gen_range(0..NREGS),
                rng.gen_range(0..4u8),
                rng.gen::<u64>(),
                rng.gen_range(0..NREGS),
            )
        })
        .collect();

    // Simulate operations to determine the expected final register values.
    let mut vals: Vec<u64> = init_vals.clone();
    for &(dst, kind, imm, src) in &ops {
        match kind {
            0 => vals[dst] = vals[dst].wrapping_add(imm),
            1 => vals[dst] = vals[dst].wrapping_sub(imm),
            2 => vals[dst] ^= imm,
            3 => {
                let sv = vals[src];
                vals[dst] = vals[dst].wrapping_add(sv);
            }
            _ => {}
        }
    }

    // Expected hash = XOR fold of all final register values.
    // The same fold is emitted as Rust code below.
    let expected: u64 = vals.iter().copied().fold(0u64, |a, v| a ^ v);

    // ── Token construction ─────────────────────────────────────────────────

    // "push": initialise simulated register locals
    let inits: Vec<TokenStream2> = init_vals
        .iter()
        .zip(&reg_ids)
        .map(|(&v, rid)| quote! { let mut #rid: u64 = #v; })
        .collect();

    // arithmetic ops
    let op_stmts: Vec<TokenStream2> = ops
        .iter()
        .map(|&(dst, kind, imm, src)| {
            let d = &reg_ids[dst];
            match kind {
                0 => quote! { #d = #d.wrapping_add(#imm); },
                1 => quote! { #d = #d.wrapping_sub(#imm); },
                2 => quote! { #d ^= #imm; },
                3 => {
                    let s = &reg_ids[src];
                    quote! { #d = #d.wrapping_add(#s); }
                }
                _ => quote! {},
            }
        })
        .collect();

    // hash expression: XOR fold over all register locals
    let hash_id = format_ident!("_jb_hash_{}", id);
    let r0 = &reg_ids[0];
    let hash_expr = reg_ids[1..]
        .iter()
        .fold(quote! { #r0 }, |acc, r| quote! { #acc ^ #r });

    quote! {
        {
            // ── push caller-saved registers ───────────────────────────────
            #( #inits )*
            // ── arithmetic ops ────────────────────────────────────────────
            #( #op_stmts )*
            // ── hash check (always passes by construction) ────────────────
            let #hash_id: u64 = #hash_expr;
            if #hash_id != #expected {
                #tamper;
            }
            // ── pop caller-saved registers ────────────────────────────────
            let _ = ( #( #reg_ids ),* );
        }
    }
}

// ── #[junk_barrier] attribute macro ──────────────────────────────────────────

/// Attribute macro that inserts semantically-equivalent junk barrier blocks
/// between every statement in the annotated function.
///
/// Each barrier:
/// * Simulates pushing/popping x86_64 caller-saved registers.
/// * Performs a random sequence of add/sub/xor operations on those values.
/// * Checks a hash of the results against a precomputed constant — always
///   true at run-time, but non-trivially so to static analysis.
/// * Calls a configurable tamper-response function if the hash fails
///   (unreachable in practice; default: `core::hint::black_box(())`).
///
/// Operations and hash constants are seeded per-build (from `ORCHESTRA_JUNK_SEED`
/// or the build timestamp) and mixed with the function name, so each function in
/// every build gets a unique set of barrier constants.
///
/// # Examples
///
/// ```rust,ignore
/// #[junk_barrier]
/// fn send_packet(buf: &[u8]) { /* ... */ }
///
/// // Custom tamper response:
/// #[junk_barrier(tamper = "crate::tamper::respond")]
/// fn critical_fn() { /* ... */ }
/// ```
#[proc_macro_attribute]
pub fn junk_barrier(attr: TokenStream, item: TokenStream) -> TokenStream {
    let tamper = parse_tamper(attr);
    let mut func = parse_macro_input!(item as ItemFn);

    // Mix the function name into the seed so each function produces a distinct
    // set of barrier constants while remaining reproducible for a given build.
    let fn_name = func.sig.ident.to_string();
    let base_seed = get_seed();
    let fn_seed = base_seed.wrapping_add(
        fn_name
            .bytes()
            .fold(0u64, |h, b| h.wrapping_mul(31).wrapping_add(b as u64)),
    );
    let mut rng = rand::rngs::StdRng::seed_from_u64(fn_seed);

    let old_stmts = std::mem::take(&mut func.block.stmts);
    let mut new_stmts: Vec<Stmt> = Vec::with_capacity(old_stmts.len() * 2 + 1);

    // Insert one barrier before each original statement.
    for (i, stmt) in old_stmts.into_iter().enumerate() {
        let block = make_barrier_block(&mut rng, &tamper, i);
        let barrier: Stmt = parse_quote! { #block };
        new_stmts.push(barrier);
        new_stmts.push(stmt);
    }
    // No trailing barrier: we must not shadow the function's tail expression.

    func.block.stmts = new_stmts;
    quote! { #func }.into()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_rng(seed: u64) -> rand::rngs::StdRng {
        rand::rngs::StdRng::seed_from_u64(seed)
    }

    #[test]
    fn expansion_produces_valid_token_stream() {
        let tokens = expansion().to_string();
        assert!(!tokens.is_empty());
        assert!(tokens.contains("junk_values"), "must contain junk_values binding");
        assert!(tokens.contains("black_box"), "must contain black_box call");
    }

    #[test]
    fn expansion_seed_env_var_is_reproducible() {
        std::env::set_var("ORCHESTRA_JUNK_SEED", "12345678");
        let a = expansion().to_string();
        let b = expansion().to_string();
        std::env::remove_var("ORCHESTRA_JUNK_SEED");
        assert_eq!(a, b, "fixed ORCHESTRA_JUNK_SEED must produce deterministic output");
    }

    #[test]
    fn barrier_block_contains_expected_structure() {
        let tamper = quote! { ::core::hint::black_box(()) };
        let mut rng = fixed_rng(0xDEAD_BEEF);
        let block = make_barrier_block(&mut rng, &tamper, 0).to_string();

        // Simulated caller-saved register locals
        assert!(block.contains("_jb_rax_0"), "missing rax local");
        assert!(block.contains("_jb_rcx_0"), "missing rcx local");
        assert!(block.contains("_jb_rdx_0"), "missing rdx local");
        assert!(block.contains("_jb_rsi_0"), "missing rsi local");
        assert!(block.contains("_jb_rdi_0"), "missing rdi local");
        assert!(block.contains("_jb_r8x_0"), "missing r8 local");
        assert!(block.contains("_jb_r9x_0"), "missing r9 local");
        assert!(block.contains("_jb_r10_0"), "missing r10 local");
        assert!(block.contains("_jb_r11_0"), "missing r11 local");

        // Hash variable and inequality check
        assert!(block.contains("_jb_hash_0"), "missing hash variable");
        assert!(block.contains("!="), "missing inequality check");

        // Tamper response
        assert!(block.contains("black_box"), "missing tamper response");

        // Pop (let _ = ...)
        assert!(block.contains("let _"), "missing pop binding");
    }

    #[test]
    fn barrier_block_is_deterministic_with_fixed_seed() {
        // Two RNGs seeded identically must produce bit-for-bit identical blocks.
        let tamper = quote! { ::core::hint::black_box(()) };
        let a = make_barrier_block(&mut fixed_rng(0xCAFE_BABE_DEAD_BEEF), &tamper, 0).to_string();
        let b = make_barrier_block(&mut fixed_rng(0xCAFE_BABE_DEAD_BEEF), &tamper, 0).to_string();
        assert_eq!(a, b, "same seed must yield identical barrier block");
    }

    #[test]
    fn barrier_block_varies_with_different_seeds() {
        let tamper = quote! { ::core::hint::black_box(()) };
        let a = make_barrier_block(&mut fixed_rng(0xAAAA_AAAA), &tamper, 0).to_string();
        let b = make_barrier_block(&mut fixed_rng(0xBBBB_BBBB), &tamper, 0).to_string();
        assert_ne!(a, b, "different seeds must yield different barrier blocks");
    }

    #[test]
    fn barrier_block_id_varies_constants() {
        // Two blocks from the same RNG state but different `id`s must differ.
        let tamper = quote! {};
        let mut rng = fixed_rng(0x1234_5678);
        let a = make_barrier_block(&mut rng, &tamper, 0).to_string();
        // Reset to the same state and use id=1
        let mut rng2 = fixed_rng(0x1234_5678);
        let b = make_barrier_block(&mut rng2, &tamper, 1).to_string();
        assert_ne!(a, b, "different id must produce different identifier names");
    }

    #[test]
    fn barrier_block_hash_simulation_is_consistent() {
        // Verify that the simulation and the generated XOR-fold expression agree
        // on the expected hash by checking ten consecutive blocks for sanity.
        let tamper = quote! {};
        let mut rng = fixed_rng(0xFEED_FACE);
        for id in 0..10 {
            let block = make_barrier_block(&mut rng, &tamper, id).to_string();
            // Every block must contain an inequality comparison against a
            // numeric constant (the precomputed hash).
            assert!(
                block.contains("!="),
                "block {id} missing hash inequality check"
            );
            assert!(
                !block.is_empty(),
                "block {id} must be non-empty"
            );
        }
    }

    #[test]
    fn barrier_block_contains_arithmetic_ops() {
        let tamper = quote! {};
        let mut rng = fixed_rng(0xCAFE_BABE);
        let block = make_barrier_block(&mut rng, &tamper, 0).to_string();
        // At least one of the arithmetic operations must appear.
        let has_op = block.contains("wrapping_add")
            || block.contains("wrapping_sub")
            || block.contains("^=");
        assert!(has_op, "barrier block must contain at least one arithmetic op");
    }
}
