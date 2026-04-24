extern crate proc_macro;
use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, LitStr};
use rand::Rng;
use std::time::{SystemTime, UNIX_EPOCH};
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;

fn get_build_rotation() -> usize {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let mut hasher = DefaultHasher::new();
    now.hash(&mut hasher);
    (hasher.finish() % 3) as usize
}

#[proc_macro]
pub fn enc_str(input: TokenStream) -> TokenStream {
    let lit = parse_macro_input!(input as LitStr);
    let pt: Vec<u8> = lit.value().into_bytes();
    let mut pt_with_null = pt.clone();
    pt_with_null.push(0); // Null-terminate for C APIs
    let len = pt_with_null.len();

    let method = get_build_rotation();
    let mut rng = rand::thread_rng();

    if method == 0 {
        // XOR
        let key: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
        let ct: Vec<u8> = pt_with_null.iter().zip(key.iter()).map(|(p, k)| p ^ k).collect();
        
        let expanded = quote! {
            {
                let ct = [#(#ct),*];
                let key = [#(#key),*];
                let mut pt = [0u8; #len];
                for i in 0..#len {
                    pt[i] = ct[i] ^ key[i];
                }
                pt
            }
        };
        expanded.into()
    } else if method == 1 {
        // RC4-like
        let key: [u8; 16] = rng.gen();
        let mut s = [0u8; 256];
        for i in 0..=255 { s[i] = i as u8; }
        let mut j: usize = 0;
        for i in 0..=255 {
            j = (j.wrapping_add(s[i] as usize).wrapping_add(key[i % 16] as usize)) % 256;
            s.swap(i, j);
        }
        let mut ct = Vec::with_capacity(len);
        let mut i: usize = 0;
        j = 0;
        for b in &pt_with_null {
            i = (i.wrapping_add(1)) % 256;
            j = (j.wrapping_add(s[i] as usize)) % 256;
            s.swap(i, j);
            let k = s[(s[i] as usize).wrapping_add(s[j] as usize) % 256];
            ct.push(*b ^ k);
        }

        let expanded = quote! {
            {
                let ct = [#(#ct),*];
                let key = [#(#key),*];
                let mut s = [0u8; 256];
                let mut pt = [0u8; #len];
                for i in 0..=255 { s[i] = i as u8; }
                let mut j: usize = 0;
                for i in 0..=255 {
                    j = (j.wrapping_add(s[i] as usize).wrapping_add(key[i % 16] as usize)) % 256;
                    s.swap(i, j);
                }
                let mut i: usize = 0;
                j = 0;
                for n in 0..#len {
                    i = (i.wrapping_add(1)) % 256;
                    j = (j.wrapping_add(s[i] as usize)) % 256;
                    s.swap(i, j);
                    let k = s[(s[i] as usize).wrapping_add(s[j] as usize) % 256];
                    pt[n] = ct[n] ^ k;
                }
                pt
            }
        };
        expanded.into()
    } else {
        // AES-CTR conceptually, or a fallback to multi-key XOR for simplicity
        let key1: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
        let key2: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
        let ct: Vec<u8> = pt_with_null.iter().enumerate().map(|(i, p)| p ^ key1[i] ^ key2[i]).collect();
        
        let expanded = quote! {
            {
                let ct = [#(#ct),*];
                let key1 = [#(#key1),*];
                let key2 = [#(#key2),*];
                let mut pt = [0u8; #len];
                for i in 0..#len {
                    pt[i] = ct[i] ^ key1[i] ^ key2[i];
                }
                pt
            }
        };
        expanded.into()
    }
}

#[proc_macro]
pub fn enc_wstr(input: TokenStream) -> TokenStream {
    let lit = parse_macro_input!(input as LitStr);
    let s = lit.value();
    let pt: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
    let pt_bytes: Vec<u8> = pt.iter().flat_map(|&w| w.to_le_bytes()).collect();
    let len = pt_bytes.len();
    let wlen = pt.len();

    let mut rng = rand::thread_rng();
    let key: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
    let ct: Vec<u8> = pt_bytes.iter().zip(key.iter()).map(|(p, k)| p ^ k).collect();
    
    let expanded = quote! {
        {
            let ct = [#(#ct),*];
            let key = [#(#key),*];
            let mut pt_bytes = [0u8; #len];
            for i in 0..#len {
                pt_bytes[i] = ct[i] ^ key[i];
            }
            
            // Reconstruct the u16 array
            let mut pt_w = [0u16; #wlen];
            for i in 0..#wlen {
                pt_w[i] = u16::from_le_bytes([pt_bytes[i * 2], pt_bytes[i * 2 + 1]]);
            }
            pt_w
        }
    };
    expanded.into()
}

#[proc_macro]
pub fn stack_str(input: TokenStream) -> TokenStream {
    let lit = parse_macro_input!(input as LitStr);
    let pt: Vec<u8> = lit.value().into_bytes().into_iter().chain(std::iter::once(0)).collect();
    
    let assigns = pt.iter().enumerate().map(|(i, &b)| {
        quote! { pt[#i] = #b; }
    });
    
    let len = pt.len();

    // Use assignments to defeat basic string extraction of static data
    let expanded = quote! {
        {
            let mut pt = [0u8; #len];
            #(#assigns)*
            pt
        }
    };
    expanded.into()
}
