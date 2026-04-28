//! Proc-macro attribute `#[code_transform]` for the Orchestra agent.
//!
//! # What it does
//!
//! Marks a function so the agent's build system can identify it for the
//! binary-level instruction-substitution and block-reordering pass
//! implemented in the `code_transform` crate.
//!
//! ## Compile-time guards
//!
//! * **Inline assembly rejection**: If the function body contains an `asm!`
//!   or `global_asm!` macro invocation the attribute emits a `compile_error!`
//!   and refuses to transform the function — inline assembly produces
//!   hand-crafted bytes that are not safe to rewrite.
//!
//! * **Entry-point emission**: The macro emits a `#[doc(hidden)]` compile-time
//!   constant whose name encodes the function ident.  The agent build.rs can
//!   collect these markers (via `env!("CODE_TRANSFORM_SEED")`) to make the
//!   seed available at compile time.
//!
//! ## Runtime behaviour
//!
//! The attribute wraps the original function body with a one-shot self-
//! patching initialiser (guarded by `std::sync::Once`).  On the first call
//! the initialiser:
//!
//! 1. Obtains the function's own machine-code address via a raw function
//!    pointer cast.
//! 2. Reads the bytes of the function body with a conservative size estimate
//!    (scans forward for a `RET` instruction, capped at 4 096 bytes).
//! 3. Applies `code_transform::transform(bytes, seed)` to produce a
//!    transformed copy.
//! 4. Re-maps the function's page as RW, writes the transformed bytes, and
//!    re-maps as RX.
//!
//! This is intentionally limited to `x86_64 linux` where the calling
//! convention and page-permission model are known.  On other targets the
//! wrapper is a no-op that calls the inner function directly.

extern crate proc_macro;

use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
use syn::{
    parse_macro_input,
    visit::Visit,
    ItemFn,
    Macro,
};

// ─── ASM detection ────────────────────────────────────────────────────────────

struct AsmVisitor {
    found: bool,
}

impl<'ast> Visit<'ast> for AsmVisitor {
    fn visit_macro(&mut self, mac: &'ast Macro) {
        let path = &mac.path;
        let last = path.segments.last().map(|s| s.ident.to_string());
        if matches!(last.as_deref(), Some("asm") | Some("global_asm")) {
            self.found = true;
        }
        syn::visit::visit_macro(self, mac);
    }
}

fn contains_asm(func: &ItemFn) -> bool {
    let mut v = AsmVisitor { found: false };
    v.visit_item_fn(func);
    v.found
}

// ─── Attribute macro ──────────────────────────────────────────────────────────

/// Mark a function for the instruction-substitution / block-reorder
/// transformation.
///
/// ```no_run
/// use code_transform_macro::code_transform;
///
/// #[code_transform]
/// pub fn example(x: i64) -> i64 {
///     x * 2 + 1
/// }
/// ```
///
/// The build script in the `agent` crate sets `CODE_TRANSFORM_SEED` via
/// `cargo:rustc-env` so the seed is baked into the binary at compile time.
#[proc_macro_attribute]
pub fn code_transform(attrs: TokenStream, item: TokenStream) -> TokenStream {
    let _ = attrs; // no attribute arguments currently

    let func = parse_macro_input!(item as ItemFn);

    // ── Guard: reject functions that contain inline assembly ─────────────────
    if contains_asm(&func) {
        let msg = format!(
            "#[code_transform]: function `{}` contains inline assembly and \
             cannot be transformed — remove the attribute or the `asm!` block.",
            func.sig.ident
        );
        return quote! {
            compile_error!(#msg);
        }
        .into();
    }

    gen_wrapper(func).into()
}

/// Produce the final token stream for the wrapper function.
fn gen_wrapper(func: ItemFn) -> proc_macro2::TokenStream {
    let vis = &func.vis;
    let sig = &func.sig;
    let fn_name = &func.sig.ident;
    let block = &func.block;
    let outer_attrs = &func.attrs;

    let inner_name = syn::Ident::new(&format!("__{fn_name}_inner"), Span::call_site());

    let marker_const_name = syn::Ident::new(
        &format!(
            "__CODE_TRANSFORM_MARKER_{}",
            fn_name.to_string().to_uppercase()
        ),
        Span::call_site(),
    );

    // Collect argument names for forwarding.
    let arg_names: Vec<_> = func
        .sig
        .inputs
        .iter()
        .filter_map(|arg| {
            if let syn::FnArg::Typed(pat_type) = arg {
                if let syn::Pat::Ident(pi) = &*pat_type.pat {
                    return Some(pi.ident.clone());
                }
            }
            None
        })
        .collect();

    // Inner function: identical signature but without visibility.
    let inner_inputs = &sig.inputs;
    let inner_output = &sig.output;
    let inner_generics = &sig.generics;

    quote! {
        // ── compile-time marker (detected by build.rs) ────────────────────
        #[doc(hidden)]
        #[allow(non_upper_case_globals, dead_code)]
        const #marker_const_name: &str =
            concat!(module_path!(), "::", stringify!(#fn_name));

        // ── original implementation (unexported) ──────────────────────────
        #[allow(clippy::all, non_snake_case)]
        fn #inner_name #inner_generics (#inner_inputs) #inner_output
            #block

        // ── public wrapper ────────────────────────────────────────────────
        #(#outer_attrs)*
        #vis #sig {
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            {
                use std::sync::Once;
                static __INIT: Once = Once::new();
                __INIT.call_once(|| {
                    // Safety: we have exclusive write access during Once init;
                    // the page containing the inner function is remapped RW
                    // and then back to RX by apply_to_fn.
                    unsafe {
                        code_transform::runtime::apply_to_fn(
                            #inner_name as usize as *mut u8,
                            ::std::env!("CODE_TRANSFORM_SEED")
                                .parse::<u64>()
                                .unwrap_or(0xDEAD_BEEF_CAFE_BABE),
                        );
                    }
                });
            }
            #inner_name(#(#arg_names),*)
        }
    }
}
