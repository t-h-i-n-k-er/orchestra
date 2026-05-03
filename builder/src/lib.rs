//! Agent build pipeline and profile-driven compilation.
//!
//! This crate provides the build tool that compiles agent binaries with
//! specific malleable profiles, feature sets, and target architectures.
//! It handles dependency resolution, feature flag injection, cross-compilation
//! setup, and post-build PE artifact manipulation.

/// Core build orchestration: compiles agent binaries from profiles.
pub mod build;

/// Build configuration: profile parsing and validation.
pub mod config;

/// Dependency management: crate feature resolution.
pub mod deps;

/// PE artifact manipulation: section renaming, timestamp randomization,
/// Rich header removal, and other post-link diversification.
pub mod pe_artifact_kit;
