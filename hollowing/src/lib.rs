//! Process hollowing and injection primitives.
//!
//! This crate provides the core process hollowing implementation used by
//! the Orchestra agent for injecting payloads into legitimate processes.
//! The technique replaces the main module of a target process with the
//! payload while maintaining the original process's appearance in the
//! process list.
//!
//! # Platform Support
//!
//! Full implementation on Windows; no-op stubs on other platforms.

pub mod windows_impl;

/// Hollow out a target process and execute a payload in its place.
///
/// Creates a new instance of the target executable in a suspended state,
/// unmaps its original image, writes the payload, and resumes execution
/// at the payload's entry point.
///
/// # Arguments
///
/// * `target_path` - Path to the legitimate executable to hollow
/// * `payload` - PE payload bytes to inject
///
/// # Returns
///
/// `Ok(())` on successful injection and execution.
pub use windows_impl::hollow_and_execute;

/// Inject shellcode into a running process.
///
/// Allocates memory in the target process, writes the shellcode, and
/// creates a remote thread to execute it.
///
/// # Arguments
///
/// * `pid` - Process ID of the target process
/// * `shellcode` - Raw shellcode bytes to inject
///
/// # Returns
///
/// `Ok(())` on successful injection.
pub use windows_impl::inject_into_process;
