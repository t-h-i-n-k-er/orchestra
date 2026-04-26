extern crate proc_macro;
use proc_macro::TokenStream;
use quote::quote;

fn expansion() -> proc_macro2::TokenStream {
    quote! {
        {
            let junk_values: [i32; 4] = [173, 409, 977, 2027];
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expansion_is_deterministic() {
        assert_eq!(expansion().to_string(), expansion().to_string());
    }
}
