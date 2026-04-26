extern crate proc_macro;
use proc_macro::TokenStream;
use quote::quote;
use rand::SeedableRng;
use rand::Rng as _;

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
fn expansion() -> proc_macro2::TokenStream {
    // Seed: honour an explicit env var first (reproducible builds / CI), then
    // fall back to the current nanosecond timestamp (per-build randomness).
    let seed: u64 = std::env::var("ORCHESTRA_JUNK_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64
        });

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expansion_produces_valid_token_stream() {
        // Verify that expansion() returns a non-empty token stream with the
        // expected structural elements.
        let tokens = expansion().to_string();
        assert!(!tokens.is_empty());
        assert!(tokens.contains("junk_values"), "must contain junk_values binding");
        assert!(tokens.contains("black_box"), "must contain black_box call");
    }

    #[test]
    fn expansion_seed_env_var_is_reproducible() {
        // With a fixed seed the output must be identical across calls.
        std::env::set_var("ORCHESTRA_JUNK_SEED", "12345678");
        let a = expansion().to_string();
        let b = expansion().to_string();
        std::env::remove_var("ORCHESTRA_JUNK_SEED");
        assert_eq!(a, b, "fixed ORCHESTRA_JUNK_SEED must produce deterministic output");
    }
}
