//! **shellcode_packager** — Convert a PE binary into a position-independent shellcode blob.
//!
//! # Overview
//!
//! This crate takes a compiled PE (or PE64) binary and produces a flat, fully
//! position-independent shellcode blob that can be injected via any method
//! (process hollowing, manual mapping, `ptrace`, `mmap`, etc.) and executed
//! from any RWX page **without loader support**.
//!
//! # Pipeline
//!
//! 1. **Parse** the PE headers, sections, relocations, and import table.
//! 2. **Generate fixup stubs** for every relocation that patches absolute
//!    addresses at runtime using RIP-relative addressing.
//! 3. **Generate PEB-walk import resolution** code that resolves every import
//!    at runtime via `pe_resolve` API hashing (no IAT, no `LoadLibrary`).
//! 4. **Emit a loader prologue** that:
//!    - computes its own base address (`call $+5; pop rax`),
//!    - applies all relocation fixups,
//!    - resolves all imports via PEB walk,
//!    - jumps to the original entry point.
//! 5. **(optional)** Apply the `code_transform` pipeline to the loader stub
//!    for instruction substitution and block reordering.
//! 6. **Output** a single flat binary: `[loader stub][PE image]`.
//!
//! # Usage
//!
//! ```rust,ignore
//! use shellcode_packager::package;
//!
//! let pe_bytes = std::fs::read("agent.exe")?;
//! let shellcode = package(&pe_bytes, 0)?;   // seed=0 for deterministic output
//! std::fs::write("agent.bin", &shellcode)?;
//! // agent.bin is now injectable shellcode
//! ```

#![deny(unsafe_op_in_unsafe_fn)]

mod pe;
mod x86;
mod emitter;
mod package;

pub use package::{package, ShellcodeConfig};
