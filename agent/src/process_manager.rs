//! Process management and load-balancing migration helpers.
//!
//! This module exposes a small, OS-agnostic API for enumerating processes and
//! attempting to migrate the agent into a long-running system process.
//! Migration is intentionally a *stub* on every platform in this initial
//! release: the returned `Err` documents the missing primitives so an operator
//! who invokes the command sees a clear, non-destructive failure.
//!
//! Process *enumeration* is fully implemented and tested.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use sysinfo::System;

// Windows-only process hollowing now lives in the shared `hollowing` crate.

/// A lightweight, serializable view over a process suitable for shipping back
/// to the operator console.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub cpu_usage: f32,
    pub memory_bytes: u64,
}

/// Snapshot the current process table.
pub fn list_processes() -> Vec<ProcessInfo> {
    let mut sys = System::new_all();
    sys.refresh_all();
    sys.processes()
        .iter()
        .map(|(pid, p)| ProcessInfo {
            pid: pid.as_u32(),
            name: p.name().to_string(),
            cpu_usage: p.cpu_usage(),
            memory_bytes: p.memory(),
        })
        .collect()
}

/// Attempt to migrate the running agent into the address space of `target_pid`.
///
/// This is a deliberate **stub** in the public release: cross-process memory
/// rewriting is OS-specific (Windows: `NtUnmapViewOfSection` +
/// `VirtualAllocEx` + `WriteProcessMemory` + `SetThreadContext`; Linux:
/// `ptrace(PTRACE_ATTACH)` + `process_vm_writev`) and carries enough
/// stability and security risk that we expose the API surface but refuse to
/// perform the operation until the implementation has had a thorough review.
#[cfg(not(windows))]
pub fn migrate_to_process(target_pid: u32) -> Result<()> {
    tracing::warn!(
        target_pid,
        "MigrateAgent invoked but migration is not yet implemented; returning a controlled error."
    );
    anyhow::bail!("Process migration is not implemented in this release (target pid {target_pid}).")
}

#[cfg(windows)]
pub fn migrate_to_process(target_pid: u32) -> Result<()> {
    tracing::warn!(
        target_pid,
        "Injection into an existing process is not yet implemented; returning a controlled error."
    );
    anyhow::bail!("Injection into an existing process is not yet implemented.")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_processes_returns_at_least_self() {
        let procs = list_processes();
        assert!(!procs.is_empty(), "expected at least the test process");
        let me = std::process::id();
        assert!(
            procs.iter().any(|p| p.pid == me),
            "the current process ({me}) should be in the list"
        );
    }

    #[test]
    #[cfg(not(windows))]
    fn migrate_returns_controlled_error() {
        let err = migrate_to_process(1).unwrap_err();
        assert!(err.to_string().contains("not implemented"));
    }

    #[test]
    #[ignore]
    #[cfg(windows)]
    fn test_hollowing() {
        // This test is ignored because it's invasive, but can be run manually.
        // It requires a dummy executable to be present at `target/debug/dummy.exe`.
        // You can create one with `rustc -o target/debug/dummy.exe --crate-type bin tests/dummy_process.rs`
        let payload = std::fs::read("target/debug/dummy.exe").expect("dummy.exe not found");
        assert!(migrate_to_process(0).is_ok());
    }
}
