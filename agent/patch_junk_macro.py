import re

path = '/home/replicant/la/junk_macro/src/lib.rs'

code = """
extern crate proc_macro;
use proc_macro::TokenStream;
use quote::quote;
use rand::Rng;

#[proc_macro]
pub fn inject_junk(_item: TokenStream) -> TokenStream {
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
                let stack_sz = rng.gen_range(8..32) * 8; // align by 8
                stmts.push(quote! {
                    unsafe {
                        std::arch::asm!(
                            concat!("sub rsp, ", stringify!(#stack_sz)),
                            concat!("add rsp, ", stringify!(#stack_sz)),
                            options(preserves_flags)
                        );
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
"""

with open(path, 'w') as f:
    f.write(code)

print("junk_macro patched")
