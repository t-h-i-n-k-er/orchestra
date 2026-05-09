//! PE hardening utilities.
//!
//! **Note:** The primary PE hardener implementation lives in the `builder` crate
//! under `builder/src/bin/orchestra-pe-hardener.rs`, which wraps the
//! `pe_artifact_kit` module.  This crate is a placeholder that re-exports
//! the builder's hardening primitives so other crates can depend on
//! `orchestra-pe-hardener` directly without coupling to the full `builder`.

/// Re-export the PE artifact kit from the builder crate for convenience.
pub use builder::pe_artifact_kit;
