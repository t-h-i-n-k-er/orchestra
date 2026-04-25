
extern crate proc_macro;
use proc_macro::TokenStream;
use quote::quote;
use rand::Rng;

#[proc_macro]
pub fn insert_junk(_item: TokenStream) -> TokenStream {
    let mut rng = rand::thread_rng();
    let num_statements = rng.gen_range(3..8);
    let mut stmts = Vec::new();

    for _ in 0..num_statements {
        let op_type = rng.gen_range(0..3);
        match op_type {
            0 => {
                // Volatile read / black_box
                let val = rng.gen_range(100..9999);
                stmts.push(quote! {
                    unsafe {
                        let vol_val = std::ptr::read_volatile(&#val as *const i32);
                        std::hint::black_box(vol_val);
                    }
                });
            },
            1 => {
                // Junk function calls
                let arg1 = rng.gen_range(0..100);
                stmts.push(quote! {
                    std::hint::black_box(#arg1);
                });
            },
            _ => {
                // Junk memory operations via inline ASM
                // NOTE: sub/add modify EFLAGS so we must NOT use preserves_flags.
                // Also guard on architecture so we don't emit x86 instructions on
                // aarch64 or other targets.
                let stack_sz = rng.gen_range(8..32) * 8; // align by 8
                stmts.push(quote! {
                    #[cfg(target_arch = "x86_64")]
                    unsafe {
                        std::arch::asm!(
                            concat!("sub rsp, ", stringify!(#stack_sz)),
                            concat!("add rsp, ", stringify!(#stack_sz)),
                            // no options(preserves_flags) — sub/add modify EFLAGS
                        );
                    }
                    #[cfg(target_arch = "aarch64")]
                    unsafe {
                        std::arch::asm!(
                            concat!("sub sp, sp, #", stringify!(#stack_sz)),
                            concat!("add sp, sp, #", stringify!(#stack_sz)),
                        );
                    }
                    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
                    {
                        // Fallback: use black_box on an opaque value to prevent
                        // the compiler from collapsing the junk block entirely.
                        std::hint::black_box(#stack_sz);
                    }
                });
            }
        }
    }

    let expanded = quote! {
        {
            #(#stmts)*
        }
    };
    expanded.into()
}
