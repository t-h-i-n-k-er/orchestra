extern crate proc_macro;
use proc_macro::TokenStream;
use quote::quote;
use rand::Rng;

#[proc_macro]
pub fn insert_junk(_input: TokenStream) -> TokenStream {
    let mut rng = rand::thread_rng();
    let num_stmts = rng.gen_range(3..10);
    
    let mut statements = Vec::new();
    for _ in 0..num_stmts {
        let op_type = rng.gen_range(0..4);
        let val1: u32 = rng.gen();
        let val2: u32 = rng.gen();
        
        // Random junk operations (dead stores, identity operations)
        match op_type {
            0 => statements.push(quote! { let _ = #val1 ^ #val2; }),
            1 => statements.push(quote! { let mut _x = #val1; _x = _x.wrapping_add(#val2); }),
            2 => statements.push(quote! { 
                if #val1 == #val2 {
                    let _y = #val1.wrapping_mul(2);
                } 
            }),
            _ => statements.push(quote! { let _ = (#val1 ^ #val2) ^ #val2; }), // identity sequence
        }
    }
    
    let expanded = quote! { { #(#statements)* } };
    expanded.into()
}
