//! Malleable C2 profile types — re-exported from the common crate.
//!
//! All shared types (TransformType, DeliveryMethod, MalleableProfile, etc.)
//! are defined in `common::malleable_types` to eliminate schema drift between
//! the agent and the server.

pub use common::malleable_types::*;
