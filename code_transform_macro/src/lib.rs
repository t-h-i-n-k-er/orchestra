extern crate proc_macro;

use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::process::Command;
use std::sync::OnceLock;
use syn::{
    parse_macro_input,
    visit::Visit,
    FnArg,
    ItemFn,
    Macro,
    Pat,
    ReturnType,
    Type,
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

fn unsupported_signature_reason(func: &ItemFn) -> Option<String> {
    if func.sig.asyncness.is_some() {
        return Some("async functions are not yet supported".to_string());
    }
    if func.sig.constness.is_some() {
        return Some("const functions are not yet supported".to_string());
    }
    if !func.sig.generics.params.is_empty() {
        return Some("generic functions are not yet supported".to_string());
    }
    if func.sig.variadic.is_some() {
        return Some("variadic functions are not supported".to_string());
    }
    for arg in &func.sig.inputs {
        match arg {
            FnArg::Receiver(_) => {
                return Some("methods with self receiver are not supported".to_string());
            }
            FnArg::Typed(pat_ty) => {
                if !matches!(&*pat_ty.pat, Pat::Ident(_)) {
                    return Some(
                        "only identifier parameter patterns are supported (no tuple/struct destructuring)"
                            .to_string(),
                    );
                }
            }
        }
    }
    None
}

fn parse_seed() -> u64 {
    static FALLBACK: OnceLock<u64> = OnceLock::new();
    if let Ok(seed_txt) = std::env::var("CODE_TRANSFORM_SEED") {
        if let Ok(seed) = seed_txt.trim().parse::<u64>() {
            return seed;
        }
    }
    *FALLBACK.get_or_init(|| {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let pid = std::process::id() as u128;
        let mut h = DefaultHasher::new();
        now.hash(&mut h);
        pid.hash(&mut h);
        "code_transform_macro".hash(&mut h);
        let seed = h.finish();
        eprintln!(
            "code_transform_macro: CODE_TRANSFORM_SEED not set; using generated seed {}",
            seed
        );
        seed
    })
}

fn helper_source(func: &ItemFn) -> String {
    let helper_ident = syn::Ident::new("__ct_target", Span::call_site());
    let mut helper = func.clone();
    helper.attrs.clear();
    helper.attrs.push(syn::parse_quote!(#[no_mangle]));
    helper.vis = syn::parse_quote!(pub);
    helper.sig.ident = helper_ident;
    helper.sig.abi = Some(syn::Abi {
        extern_token: <syn::token::Extern>::default(),
        name: Some(syn::LitStr::new("C", Span::call_site())),
    });
    let helper_tokens = quote! {
        #![allow(dead_code, unused_variables, clippy::all, non_snake_case)]
        #helper
    };
    helper_tokens.to_string()
}

fn compile_helper_obj(func: &ItemFn) -> Result<std::path::PathBuf, String> {
    let mut h = DefaultHasher::new();
    quote!(#func).to_string().hash(&mut h);
    std::process::id().hash(&mut h);
    let unique = format!("ct_macro_{:016x}", h.finish());

    let temp_dir = std::env::temp_dir().join(unique);
    if let Err(e) = std::fs::create_dir_all(&temp_dir) {
        return Err(format!("failed to create temp dir {}: {}", temp_dir.display(), e));
    }

    let src_path = temp_dir.join("input.rs");
    let obj_path = temp_dir.join("input.o");
    let src = helper_source(func);
    if let Err(e) = std::fs::write(&src_path, src) {
        return Err(format!("failed to write temp source {}: {}", src_path.display(), e));
    }

    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    let mut cmd = Command::new(&rustc);
    cmd.arg("--edition=2021")
        .arg("--crate-type")
        .arg("lib")
        .arg("--emit=obj")
        .arg("-C")
        .arg("opt-level=3")
        .arg("-C")
        .arg("overflow-checks=off")
        .arg("-C")
        .arg("panic=abort")
        .arg("-o")
        .arg(&obj_path)
        .arg(&src_path);
    if let Ok(target) = std::env::var("TARGET") {
        if !target.trim().is_empty() {
            cmd.arg("--target").arg(target.trim());
        }
    }

    let out = cmd
        .output()
        .map_err(|e| format!("failed to invoke rustc at '{}': {}", rustc, e))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!(
            "failed to compile helper function for byte extraction:\n{}",
            stderr
        ));
    }

    Ok(obj_path)
}

fn parse_objdump_bytes(obj: &std::path::Path) -> Result<Vec<u8>, String> {
    let out = Command::new("objdump")
        .arg("-d")
        .arg(obj)
        .output()
        .map_err(|e| format!("failed to run objdump: {}", e))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!("objdump failed: {}", stderr));
    }
    let text = String::from_utf8_lossy(&out.stdout);

    let mut in_symbol = false;
    let mut bytes = Vec::new();

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.ends_with("<__ct_target>:") {
            in_symbol = true;
            continue;
        }
        if !in_symbol {
            continue;
        }

        if trimmed.is_empty() {
            if !bytes.is_empty() {
                break;
            }
            continue;
        }

        if trimmed.ends_with(":") && trimmed.contains('<') && trimmed.contains('>') {
            break;
        }

        let Some((_, rhs)) = line.split_once(':') else {
            continue;
        };
        for tok in rhs.split_whitespace() {
            if tok.len() == 2 && tok.as_bytes().iter().all(|b| b.is_ascii_hexdigit()) {
                match u8::from_str_radix(tok, 16) {
                    Ok(v) => bytes.push(v),
                    Err(_) => break,
                }
            } else {
                break;
            }
        }
    }

    if bytes.is_empty() {
        return Err("could not find function bytes for symbol __ct_target in objdump output".to_string());
    }

    if let Some(ret_pos) = bytes.iter().position(|&b| b == 0xC3) {
        bytes.truncate(ret_pos + 1);
    }
    if bytes.is_empty() {
        return Err("extracted function bytes were empty after RET trimming".to_string());
    }
    Ok(bytes)
}

fn extract_and_transform(func: &ItemFn, seed: u64) -> Result<Vec<u8>, String> {
    let obj = compile_helper_obj(func)?;
    let raw = parse_objdump_bytes(&obj)?;
    let transformed = code_transform::transform(&raw, seed);
    if transformed.is_empty() {
        return Err("code_transform::transform returned empty output".to_string());
    }
    if !transformed.iter().any(|&b| b == 0xC3) {
        return Err(
            "transformed function bytes do not contain a RET (0xC3); refusing to emit"
                .to_string(),
        );
    }
    Ok(transformed)
}

fn byte_asm_string(bytes: &[u8]) -> String {
    let mut out = String::new();
    for chunk in bytes.chunks(16) {
        out.push_str(".byte ");
        for (i, b) in chunk.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            out.push_str(&format!("0x{b:02x}"));
        }
        out.push('\n');
    }
    out
}

fn compile_error(msg: &str) -> TokenStream {
    quote! {
        compile_error!(#msg);
    }
    .into()
}

// ─── Attribute macro ──────────────────────────────────────────────────────────

/// Compile-time function transformation attribute.
///
/// This macro compiles a helper copy of the annotated function, extracts its
/// machine code via `objdump`, applies `code_transform::transform`, and emits
/// a transformed implementation as raw bytes via `global_asm!`.
#[proc_macro_attribute]
pub fn transform(attrs: TokenStream, item: TokenStream) -> TokenStream {
    let _ = attrs;

    let func = parse_macro_input!(item as ItemFn);

    if contains_asm(&func) {
        let msg = format!(
            "#[code_transform::transform]: function '{}' contains inline assembly and cannot be transformed",
            func.sig.ident
        );
        return compile_error(&msg);
    }

    if let Some(reason) = unsupported_signature_reason(&func) {
        let msg = format!(
            "#[code_transform::transform]: function '{}' is unsupported in the simple compile-time backend: {}",
            func.sig.ident, reason
        );
        return compile_error(&msg);
    }

    let seed = parse_seed();
    let transformed = match extract_and_transform(&func, seed) {
        Ok(b) => b,
        Err(e) => {
            let msg = format!(
                "#[code_transform::transform]: compile-time byte extraction failed for '{}': {}",
                func.sig.ident, e
            );
            return compile_error(&msg);
        }
    };

    gen_transformed_wrapper(func, &transformed).into()
}

/// Backward-compatible alias for legacy `#[code_transform]` uses.
#[proc_macro_attribute]
pub fn code_transform(attrs: TokenStream, item: TokenStream) -> TokenStream {
    transform(attrs, item)
}

fn gen_transformed_wrapper(func: ItemFn, transformed: &[u8]) -> proc_macro2::TokenStream {
    let vis = &func.vis;
    let sig = &func.sig;
    let fn_name = &func.sig.ident;
    let block = &func.block;
    let outer_attrs = &func.attrs;

    let mut h = DefaultHasher::new();
    quote!(#sig).to_string().hash(&mut h);
    transformed.len().hash(&mut h);
    let uniq = h.finish();

    let extern_name = syn::Ident::new(
        &format!("__ct_entry_{}_{}", fn_name, uniq),
        Span::call_site(),
    );
    let sym_name = format!("__ct_blob_{}_{}", fn_name, uniq);
    let sym_name_lit = syn::LitStr::new(&sym_name, Span::call_site());

    let arg_types: Vec<Type> = func
        .sig
        .inputs
        .iter()
        .filter_map(|arg| match arg {
            FnArg::Typed(pt) => Some((*pt.ty).clone()),
            FnArg::Receiver(_) => None,
        })
        .collect();

    let arg_names: Vec<_> = func
        .sig
        .inputs
        .iter()
        .filter_map(|arg| {
            if let FnArg::Typed(pat_type) = arg {
                if let Pat::Ident(pi) = &*pat_type.pat {
                    return Some(pi.ident.clone());
                }
            }
            None
        })
        .collect();

    let output = match &sig.output {
        ReturnType::Default => quote!(),
        ReturnType::Type(_, ty) => quote!(-> #ty),
    };

    let asm_payload = byte_asm_string(transformed);
    let asm_payload_lit = syn::LitStr::new(&asm_payload, Span::call_site());

    quote! {
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        core::arch::global_asm!(
            concat!(
                ".text\n",
                ".p2align 4\n",
                ".global ", #sym_name_lit, "\n",
                #sym_name_lit, ":\n",
                #asm_payload_lit
            )
        );

        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        unsafe extern "C" {
            #[link_name = #sym_name_lit]
            fn #extern_name(#(#arg_names: #arg_types),*) #output;
        }

        #(#outer_attrs)*
        #vis #sig {
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            {
                unsafe { #extern_name(#(#arg_names),*) }
            }
            #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
            #block
        }
    }
}
