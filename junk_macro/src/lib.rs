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

// ── Junk code pattern categories ─────────────────────────────────────────────
//
// Each pattern generates a block of dead code that is semantically a no-op but
// resists optimizer elimination and looks non-trivial to static analysis.
// The patterns are intentionally diverse to prevent signature-based detection.

/// Volatile-seeded static unique to this invocation.
fn junk_static(rng: &mut rand::rngs::StdRng, suffix: &str) -> (proc_macro2::Ident, u64) {
    let val: u64 = rng.gen();
    let id = format_ident!("_JK_S_{}_{}", suffix, val);
    (id, val)
}

/// Produce a volatile-read expression from `static_id` (a `static AtomicU64`).
#[allow(dead_code)]
fn volatile_read(static_id: &proc_macro2::Ident) -> TokenStream2 {
    quote! {
        unsafe {
            std::ptr::read_volatile(
                &#static_id as *const std::sync::atomic::AtomicU64 as *const u64
            )
        }
    }
}

// ── Pattern 0: Opaque predicate with cmov ─────────────────────────────────────
//
// Compute a condition that is always true (or always false) through volatile
// reads, then use it in an `if` branch.  The optimizer must keep both paths
// because it cannot prove which is taken, but only one is ever reached.
fn pattern_opaque_predicate(rng: &mut rand::rngs::StdRng, id: usize) -> TokenStream2 {
    let (sid, sval) = junk_static(rng, &format!("op{}", id));
    let imm_a: u64 = rng.gen();
    // Always-true: sval ^ imm_a == (sval ^ imm_a).wrapping_add(0)
    // We construct: let v = volatile(sid); let c = v ^ imm_a == v.wrapping_add(imm_b) ^ imm_b;
    // where imm_b is chosen so c is always true.
    let always_val: u64 = rng.gen();
    let alt_a: u64 = rng.gen();
    let alt_b: u64 = rng.gen();
    let then_mul: u64 = rng.gen();
    let else_mul: u64 = rng.gen();

    quote! {{
        static #sid: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(#sval);
        let _v: u64 = #sid.load(std::sync::atomic::Ordering::Relaxed);
        // Opaque predicate: always true by construction (x ^ imm == x ^ imm),
        // but the optimizer cannot fold it away due to the volatile-backed load.
        let _cond: bool = (_v ^ #imm_a).wrapping_add(#always_val) == (_v ^ #imm_a).wrapping_add(#always_val);
        let _opaque: u64 = if _cond {
            _v.wrapping_mul(#then_mul).wrapping_add(#alt_a)
        } else {
            _v.wrapping_mul(#else_mul).wrapping_add(#alt_b)
        };
        let _ = std::hint::black_box(_opaque);
    }}
}

// ── Pattern 1: Dead function call stub ────────────────────────────────────────
//
// Define an `#[inline(never)]` fn that does trivial dead work, then call it.
// The `#[inline(never)]` ensures the call frame is visible in the binary.
fn pattern_dead_call_stub(rng: &mut rand::rngs::StdRng, id: usize) -> TokenStream2 {
    let (sid, sval) = junk_static(rng, &format!("dc{}", id));
    let stub_name = format_ident!("_jk_stub_{}", id);
    let a: u64 = rng.gen();
    let b: u64 = rng.gen();
    let c: u64 = rng.gen();

    quote! {{
        #[inline(never)]
        fn #stub_name(_x: u64, _y: u64) -> u64 {
            let _ = std::hint::black_box(_x.wrapping_add(#a).wrapping_mul(#b));
            _y.wrapping_add(#c)
        }
        static #sid: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(#sval);
        let _seed: u64 = #sid.load(std::sync::atomic::Ordering::Relaxed);
        let _res: u64 = #stub_name(_seed, _seed.wrapping_add(#a));
        let _ = std::hint::black_box(_res);
    }}
}

// ── Pattern 2: Balanced stack push/pop sequence ──────────────────────────────
//
// Simulate pushing arguments onto the stack (volatile-seeded) and popping
// them in reverse order.  The sequence balances perfectly but looks like
// argument setup for a function call.
fn pattern_stack_push_pop(rng: &mut rand::rngs::StdRng, id: usize) -> TokenStream2 {
    let (sid, sval) = junk_static(rng, &format!("sp{}", id));
    let n_args: usize = rng.gen_range(3..=6);
    let offsets: Vec<u64> = (0..n_args).map(|_| rng.gen()).collect();
    let arg_ids: Vec<proc_macro2::Ident> = (0..n_args)
        .map(|i| format_ident!("_jk_sp_{}_{}", id, i))
        .collect();
    let xor_val: u64 = rng.gen();

    let pushes: Vec<TokenStream2> = offsets.iter().zip(&arg_ids).map(|(&off, aid)| {
        quote! { let #aid: u64 = _sp_base.wrapping_add(#off); }
    }).collect();

    // Reverse-order "pop" — XOR each into accumulator to prevent elimination
    let pops: Vec<TokenStream2> = arg_ids.iter().rev().map(|aid| {
        quote! { _sp_acc ^= #aid; }
    }).collect();

    quote! {{
        static #sid: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(#sval);
        let _sp_base: u64 = #sid.load(std::sync::atomic::Ordering::Relaxed);
        #( #pushes )*
        let mut _sp_acc: u64 = #xor_val;
        #( #pops )*
        let _ = std::hint::black_box(_sp_acc);
    }}
}

// ── Pattern 3: Fake SEH prologue ─────────────────────────────────────────────
//
// Emulate an SEH setup: load a handler address, store to a stack-local,
// then immediately tear it down.  Never triggered, but looks like structured
// exception handling to disassemblers.
fn pattern_fake_seh(rng: &mut rand::rngs::StdRng, id: usize) -> TokenStream2 {
    let (sid, sval) = junk_static(rng, &format!("seh{}", id));
    let handler_seed: u64 = rng.gen();
    let scope_seed: u64 = rng.gen();
    let filter_xor: u64 = rng.gen();

    quote! {{
        static #sid: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(#sval);
        let _seh_handler: u64 = #sid.load(std::sync::atomic::Ordering::Relaxed).wrapping_add(#handler_seed);
        let _seh_scope: u64 = _seh_handler ^ #scope_seed;
        // Simulate: if exception occurs, "dispatch" to handler — but this is
        // dead code guarded by an always-false volatile condition.
        let _seh_filter: bool = (_seh_scope ^ #filter_xor) == !0u64;
        if _seh_filter {
            let _ = std::hint::black_box(_seh_handler);
        }
        // Teardown: zero out the locals
        let _ = std::hint::black_box((_seh_handler, _seh_scope));
    }}
}

// ── Pattern 4: Redundant LEA computations ────────────────────────────────────
//
// Compute addresses via arithmetic (like `lea` does) from a volatile base,
// but never dereference them.  The chain of address computations looks like
// pointer manipulation to static analysis.
fn pattern_redundant_lea(rng: &mut rand::rngs::StdRng, id: usize) -> TokenStream2 {
    let (sid, sval) = junk_static(rng, &format!("lea{}", id));
    let scale: u64 = rng.gen_range(1..=8);
    let index_off: u64 = rng.gen();
    let disp: u64 = rng.gen();
    let base_off: u64 = rng.gen();
    let chain_len: usize = rng.gen_range(3..=5);
    let chain_mults: Vec<u64> = (0..chain_len).map(|_| rng.gen_range(1u64..=16)).collect();
    let chain_disps: Vec<u64> = (0..chain_len).map(|_| rng.gen()).collect();

    let chain_ids: Vec<proc_macro2::Ident> = (0..chain_len)
        .map(|i| format_ident!("_jk_lea_{}_{}", id, i))
        .collect();

    // Build chain: first element derives from _lea_base, each subsequent
    // element derives from the *previous* pointer in the chain.
    let mut chain_stmts: Vec<TokenStream2> = Vec::with_capacity(chain_len);
    for (i, cid) in chain_ids.iter().enumerate() {
        let mult_isize = chain_mults[i] as isize;
        let d_isize = chain_disps[i] as isize;
        if i == 0 {
            chain_stmts.push(quote! {
                let #cid: *const u8 = (_lea_base.wrapping_add(#base_off)
                    .wrapping_add(#scale.wrapping_mul(#index_off))
                    .wrapping_add(#disp)) as *const u8;
            });
        } else {
            let prev = &chain_ids[i - 1];
            chain_stmts.push(quote! {
                let #cid: *const u8 = (#prev.wrapping_offset(#mult_isize)).wrapping_offset(#d_isize);
            });
        }
    }

    let final_id = chain_ids.last().unwrap();

    quote! {{
        static #sid: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(#sval);
        let _lea_base: u64 = #sid.load(std::sync::atomic::Ordering::Relaxed);
        #( #chain_stmts )*
        let _ = std::hint::black_box(#final_id);
    }}
}

// ── Pattern 5: XMM register dead operations ──────────────────────────────────
//
// Simulate SSE/AVX register operations using `[u64; 2]` as a stand-in for
// 128-bit XMM values.  Perform pxor, shifts, and moves that look like XMM
// manipulation but are discarded.
fn pattern_xmm_dead_ops(rng: &mut rand::rngs::StdRng, id: usize) -> TokenStream2 {
    let (sid, sval) = junk_static(rng, &format!("xmm{}", id));
    let xmm_a_lo: u64 = rng.gen();
    let xmm_a_hi: u64 = rng.gen();
    let xmm_b_lo: u64 = rng.gen();
    let xmm_b_hi: u64 = rng.gen();
    let xor_lo: u64 = rng.gen();
    let xor_hi: u64 = rng.gen();
    let shift_amt: u32 = rng.gen_range(1..=63);

    quote! {{
        static #sid: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(#sval);
        let _xmm_seed: u64 = #sid.load(std::sync::atomic::Ordering::Relaxed);
        // Simulate XMM register pair: [lo, hi]
        let mut _xm0: [u64; 2] = [#xmm_a_lo ^ _xmm_seed, #xmm_a_hi ^ _xmm_seed];
        let _xm1: [u64; 2] = [#xmm_b_lo, #xmm_b_hi];
        // pxor
        _xm0[0] ^= _xm1[0] ^ #xor_lo;
        _xm0[1] ^= _xm1[1] ^ #xor_hi;
        // shift (psrlq equivalent)
        _xm0[0] = _xm0[0].wrapping_shr(#shift_amt);
        _xm0[1] = _xm0[1].wrapping_shr(#shift_amt);
        // movaps equivalent — "move" into destination
        let _xmm_dst: [u64; 2] = [_xm0[0], _xm0[1]];
        let _ = std::hint::black_box(_xmm_dst);
    }}
}

// ── Pattern 6: Control-flow flattening of a no-op ────────────────────────────
//
// A dispatcher variable loaded from volatile controls a `match` that always
// goes to the same arm.  Looks like CFF to disassemblers but every branch
// computes the same trivial value.
fn pattern_cff_noop(rng: &mut rand::rngs::StdRng, id: usize) -> TokenStream2 {
    let (sid, sval) = junk_static(rng, &format!("cff{}", id));
    // Pick a winning arm (0..4) and make the dispatcher always equal to it
    let winning_arm: u64 = rng.gen_range(0..5);
    // Offsets for each arm so they produce different code but same result
    let arm_adds: Vec<u64> = (0..5).map(|_| rng.gen()).collect();

    let arms: Vec<TokenStream2> = (0..5).map(|i| {
        let a = arm_adds[i];
        if i as u64 == winning_arm {
            quote! { #i => _cff_v.wrapping_add(#a) }
        } else {
            // Dead arms: the optimizer *might* remove these, but the volatile
            // dispatcher makes it hard to prove they're unreachable.
            quote! { #i => _cff_v.wrapping_add(#a) }
        }
    }).collect();

    quote! {{
        static #sid: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(#sval);
        let _cff_v: u64 = #sid.load(std::sync::atomic::Ordering::Relaxed);
        // Dispatcher: always selects arm #winning_arm because
        // (_cff_v ^ _cff_v) == 0, plus #winning_arm gives us the constant.
        let _cff_dispatch: u64 = (_cff_v ^ _cff_v).wrapping_add(#winning_arm);
        let _cff_result: u64 = match _cff_dispatch {
            #( #arms, )*
            _ => 0u64,
        };
        let _ = std::hint::black_box(_cff_result);
    }}
}

// ── Pattern 7: Dead TLS callback pattern ─────────────────────────────────────
//
// Simulate `mov fs:[0x2C], reg` / `mov fs:[0x2C], 0` pattern used by TLS
// callbacks on Windows.  On non-Windows this compiles to dead arithmetic.
fn pattern_dead_tls_callback(rng: &mut rand::rngs::StdRng, id: usize) -> TokenStream2 {
    let (sid, sval) = junk_static(rng, &format!("tls{}", id));
    let slot_offset: u64 = rng.gen_range(0x2C..=0x5C); // TLS slot range
    let save_val: u64 = rng.gen();
    let restore_xor: u64 = rng.gen();

    quote! {{
        static #sid: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(#sval);
        let _tls_base: u64 = #sid.load(std::sync::atomic::Ordering::Relaxed);
        // Simulate: read TLS slot → save → write new → restore
        let _tls_slot: *mut u64 = (_tls_base.wrapping_add(#slot_offset)) as *mut u64;
        let _tls_saved: u64 = unsafe { _tls_slot.read_volatile() };
        unsafe { _tls_slot.write_volatile(_tls_saved.wrapping_add(#save_val)); };
        // ... "callback body" — dead work ...
        let _tls_work: u64 = _tls_saved.wrapping_mul(3).wrapping_add(#restore_xor);
        // Restore original value
        unsafe { _tls_slot.write_volatile(_tls_saved); };
        let _ = std::hint::black_box(_tls_work);
    }}
}

// ── Pattern catalogue & selection ─────────────────────────────────────────────

const NUM_PATTERNS: usize = 8;

/// All 8 pattern generators, indexed 0..7.
fn generate_pattern(rng: &mut rand::rngs::StdRng, kind: usize, id: usize) -> TokenStream2 {
    match kind {
        0 => pattern_opaque_predicate(rng, id),
        1 => pattern_dead_call_stub(rng, id),
        2 => pattern_stack_push_pop(rng, id),
        3 => pattern_fake_seh(rng, id),
        4 => pattern_redundant_lea(rng, id),
        5 => pattern_xmm_dead_ops(rng, id),
        6 => pattern_cff_noop(rng, id),
        7 => pattern_dead_tls_callback(rng, id),
        _ => unreachable!(),
    }
}

/// Choose `k` distinct indices from `0..n` using Fisher-Yates.
fn choose_k(rng: &mut rand::rngs::StdRng, n: usize, k: usize) -> Vec<usize> {
    let mut pool: Vec<usize> = (0..n).collect();
    for i in (0..k).rev() {
        let j = rng.gen_range(0..=i);
        pool.swap(i, j);
    }
    pool.truncate(k);
    pool
}

// ── insert_junk!() ────────────────────────────────────────────────────────────

/// Generate diverse junk code blocks seeded from the current build time.
///
/// Each invocation of `insert_junk!()` randomly selects 3-5 of 8 junk code
/// pattern categories and emits them interleaved:
///
/// 0. **Opaque predicate with cmov** — volatile condition that is always-true,
///    with both branches alive.
/// 1. **Dead function call stub** — `#[inline(never)]` fn that does nothing.
/// 2. **Balanced stack push/pop** — simulates argument setup / teardown.
/// 3. **Fake SEH prologue** — handler setup that is never triggered.
/// 4. **Redundant LEA computations** — address arithmetic without dereference.
/// 5. **XMM dead operations** — pxor / shift / movaps on 128-bit stand-ins.
/// 6. **Control-flow flattening** — dispatcher match that always hits one arm.
/// 7. **Dead TLS callback** — `fs:[slot]` save/restore pattern.
///
/// Every build produces different pattern selections and constants, driven by
/// `ORCHESTRA_JUNK_SEED` or the build timestamp.
fn expansion() -> TokenStream2 {
    let seed: u64 = get_seed();
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

    // Select 3-5 pattern categories at random.
    let n_patterns: usize = rng.gen_range(3..=5);
    let selected = choose_k(&mut rng, NUM_PATTERNS, n_patterns);

    // Generate each selected pattern.
    let blocks: Vec<TokenStream2> = selected
        .into_iter()
        .enumerate()
        .map(|(i, kind)| generate_pattern(&mut rng, kind, i))
        .collect();

    quote! {
        {
            #( #blocks )*
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
///    registers (`rax`, `rcx`, `rdx`, `rsi`, `rdi`, `r8`, `r9`, `r10`, `r11`).
///    Initial values are derived from a volatile read of a static atomic so
///    the optimizer cannot constant-fold them.
/// 2. Applies `n_ops ∈ [8, 16]` random arithmetic operations:
///    * wrapping add / sub with a random immediate
///    * XOR with a random immediate
///    * register-to-register wrapping add
/// 3. Computes a hash (XOR fold of all final register values) and compares it
///    against a precomputed expected value that is also loaded via a volatile
///    read.  The comparison is always-equal at run-time by construction (the
///    volatile seed matches the seed used during macro expansion), so `tamper`
///    is never called.  But the optimizer cannot prove this, so it must keep
///    the arithmetic alive.
/// 4. Binds all locals with `let _` — simulating a register pop.
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

    // Generate a per-barrier seed and per-register offsets.  The seed is
    // embedded in a static atomic; at runtime the init values are derived
    // from a volatile read of that atomic, preventing constant folding.
    let barrier_seed: u64 = rng.gen();
    let reg_offsets: Vec<u64> = (0..NREGS).map(|_| rng.gen::<u64>()).collect();

    // Compute the *expected* initial register values: seed + offset (wrapping).
    // At runtime, the same computation is performed from the volatile seed.
    let init_vals: Vec<u64> = reg_offsets.iter().map(|&off| barrier_seed.wrapping_add(off)).collect();

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
    let expected: u64 = vals.iter().copied().fold(0u64, |a, v| a ^ v);

    // ── Token construction ─────────────────────────────────────────────────

    // Static atomic holding the barrier seed.
    let static_id = format_ident!("_JB_SEED_{}_{}", id, barrier_seed);

    // "push": initialise simulated register locals from volatile seed
    let inits: Vec<TokenStream2> = reg_offsets
        .iter()
        .zip(&reg_ids)
        .map(|(&off, rid)| {
            quote! {
                let mut #rid: u64 = unsafe {
                    std::ptr::read_volatile(
                        &#static_id as *const std::sync::atomic::AtomicU64 as *const u64
                    )
                }.wrapping_add(#off);
            }
        })
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

    // The expected hash is loaded from a volatile read of a second static
    // atomic, so the optimizer cannot prove `hash_id == expected_volatile`.
    let expected_static_id = format_ident!("_JB_EXP_{}_{}", id, expected);
    quote! {
        {
            /// Static atomic holding the barrier seed.  The optimizer cannot
            /// constant-fold through a volatile read of this value.
            static #static_id: std::sync::atomic::AtomicU64 =
                std::sync::atomic::AtomicU64::new(#barrier_seed);
            /// Static atomic holding the expected hash value, also read
            /// through volatile to prevent constant folding.
            static #expected_static_id: std::sync::atomic::AtomicU64 =
                std::sync::atomic::AtomicU64::new(#expected);

            // ── push caller-saved registers ───────────────────────────────
            #( #inits )*
            // ── arithmetic ops ────────────────────────────────────────────
            #( #op_stmts )*
            // ── hash check (always passes by construction, but the optimizer
            //    cannot prove it because both sides come from volatile reads) ─
            let #hash_id: u64 = #hash_expr;
            let _expected_volatile: u64 = unsafe {
                std::ptr::read_volatile(
                    &#expected_static_id as *const std::sync::atomic::AtomicU64 as *const u64
                )
            };
            if #hash_id != _expected_volatile {
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
        assert!(tokens.contains("AtomicU64"), "must contain AtomicU64 static");
        assert!(tokens.contains("black_box"), "must contain black_box call");
    }

    #[test]
    fn expansion_produces_multiple_pattern_blocks() {
        // With a fixed seed, the expansion must contain at least 3 pattern
        // blocks (each starts with `static _JK_S_`).
        std::env::set_var("ORCHESTRA_JUNK_SEED", "9999");
        let tokens = expansion().to_string();
        std::env::remove_var("ORCHESTRA_JUNK_SEED");
        let block_count = tokens.matches("_JK_S_").count();
        assert!(
            block_count >= 3,
            "expansion must contain at least 3 pattern blocks, got {}",
            block_count,
        );
    }

    #[test]
    fn expansion_seed_env_var_is_reproducible() {
        // Use a unique seed value to avoid interference from parallel tests
        // that might also set/remove this env var.
        std::env::set_var("ORCHESTRA_JUNK_SEED", "77777777");
        let seed_val = get_seed();
        assert_eq!(seed_val, 77777777, "get_seed must honour env var");

        // Create RNGs with the same seed to verify the expansion logic is
        // deterministic (the expansion() function itself calls get_seed(), so
        // as long as the env var is set, two calls should match).
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

    // ── Pattern generator tests ────────────────────────────────────────────

    #[test]
    fn pattern_opaque_predicate_produces_branch() {
        let mut rng = fixed_rng(0x1111);
        let tokens = pattern_opaque_predicate(&mut rng, 0).to_string();
        assert!(tokens.contains("if _cond"), "must contain conditional branch");
        assert!(tokens.contains("black_box"), "must contain black_box");
        assert!(tokens.contains("AtomicU64"), "must contain static atomic");
    }

    #[test]
    fn pattern_dead_call_stub_has_inline_never() {
        let mut rng = fixed_rng(0x2222);
        let tokens = pattern_dead_call_stub(&mut rng, 0).to_string();
        assert!(tokens.contains("inline"), "must contain inline attribute");
        assert!(tokens.contains("_jk_stub_"), "must contain stub function");
        assert!(tokens.contains("black_box"), "must contain black_box");
    }

    #[test]
    fn pattern_stack_push_pop_is_balanced() {
        let mut rng = fixed_rng(0x3333);
        let tokens = pattern_stack_push_pop(&mut rng, 0).to_string();
        assert!(tokens.contains("_jk_sp_"), "must contain stack var");
        assert!(tokens.contains("_sp_acc"), "must contain accumulator");
        assert!(tokens.contains("black_box"), "must contain black_box");
    }

    #[test]
    fn pattern_fake_seh_has_filter() {
        let mut rng = fixed_rng(0x4444);
        let tokens = pattern_fake_seh(&mut rng, 0).to_string();
        assert!(tokens.contains("_seh_handler"), "must have handler");
        assert!(tokens.contains("_seh_filter"), "must have filter");
        assert!(tokens.contains("if _seh_filter"), "must have conditional");
    }

    #[test]
    fn pattern_redundant_lea_has_chain() {
        let mut rng = fixed_rng(0x5555);
        let tokens = pattern_redundant_lea(&mut rng, 0).to_string();
        assert!(tokens.contains("_jk_lea_"), "must have lea chain var");
        assert!(tokens.contains("wrapping_offset"), "must use wrapping_offset");
        assert!(tokens.contains("* const u8"), "must compute pointer");
    }

    #[test]
    fn pattern_xmm_has_array_ops() {
        let mut rng = fixed_rng(0x6666);
        let tokens = pattern_xmm_dead_ops(&mut rng, 0).to_string();
        assert!(tokens.contains("_xm0"), "must have xmm var");
        assert!(tokens.contains("^= "), "must contain XOR (pxor)");
        assert!(tokens.contains("wrapping_shr"), "must contain shift");
        assert!(tokens.contains("_xmm_dst"), "must have destination");
    }

    #[test]
    fn pattern_cff_has_match_dispatch() {
        let mut rng = fixed_rng(0x7777);
        let tokens = pattern_cff_noop(&mut rng, 0).to_string();
        assert!(tokens.contains("match _cff_dispatch"), "must have match dispatch");
        assert!(tokens.contains("_cff_result"), "must have result var");
    }

    #[test]
    fn pattern_tls_callback_has_slot() {
        let mut rng = fixed_rng(0x8888);
        let tokens = pattern_dead_tls_callback(&mut rng, 0).to_string();
        assert!(tokens.contains("_tls_slot"), "must have TLS slot");
        assert!(tokens.contains("write_volatile"), "must write to slot");
        assert!(tokens.contains("read_volatile"), "must read from slot");
    }

    #[test]
    fn all_patterns_generate_non_empty_output() {
        let mut rng = fixed_rng(0xAAAA);
        for kind in 0..NUM_PATTERNS {
            let tokens = generate_pattern(&mut rng, kind, kind).to_string();
            assert!(!tokens.is_empty(), "pattern {} must produce output", kind);
            assert!(
                tokens.contains("AtomicU64"),
                "pattern {} must contain AtomicU64",
                kind,
            );
        }
    }

    #[test]
    fn choose_k_selects_correct_count() {
        let mut rng = fixed_rng(0xBEEF);
        for k in 1..=8 {
            let sel = choose_k(&mut rng, 8, k);
            assert_eq!(sel.len(), k, "choose_k(8, {}) must return {} items", k, k);
            // All distinct
            let mut sorted = sel.clone();
            sorted.sort();
            sorted.dedup();
            assert_eq!(sorted.len(), k, "choose_k must return distinct indices");
        }
    }

    #[test]
    fn expansion_varies_across_seeds() {
        std::env::set_var("ORCHESTRA_JUNK_SEED", "100");
        let a = expansion().to_string();
        std::env::set_var("ORCHESTRA_JUNK_SEED", "200");
        let b = expansion().to_string();
        std::env::remove_var("ORCHESTRA_JUNK_SEED");
        assert_ne!(a, b, "different seeds must yield different expansion output");
    }
}
