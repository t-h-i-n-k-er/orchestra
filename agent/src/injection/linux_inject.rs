use crate::injection::Injector;
use anyhow::{anyhow, Result};

pub struct LinuxPtraceInjector {
    /// When false (default), keep the original fire-and-forget behaviour.
    /// When true, execute payload via a trampoline and restore original
    /// registers after payload return + INT3 breakpoint.
    pub restore_after: bool,
}

impl Default for LinuxPtraceInjector {
    fn default() -> Self {
        Self {
            restore_after: false,
        }
    }
}

impl LinuxPtraceInjector {
    pub const fn new() -> Self {
        Self {
            restore_after: false,
        }
    }

    pub const fn with_restore_after(restore_after: bool) -> Self {
        Self { restore_after }
    }
}

#[cfg(target_os = "linux")]
impl Injector for LinuxPtraceInjector {
    /// Linux ptrace injection.
    ///
    /// Default behaviour is fire-and-forget (restore_after=false): redirect RIP
    /// to the injected shellcode and detach without restoring execution context.
    ///
    /// Optional restore mode (restore_after=true): redirect RIP to a small
    /// trampoline that calls shellcode and executes INT3; once the breakpoint
    /// stop is observed, restore original registers, then detach.
    ///
    /// In fire-and-forget mode (`restore_after=false`), payloads must either
    /// call `execve()`, call `exit()`, or implement their own transfer back to
    /// a stable endpoint. In restore mode (`restore_after=true`), payloads are
    /// expected to return normally so the trampoline can trigger INT3 and
    /// restore the original register context.
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
            let staged_len = if self.restore_after {
                payload
                    .len()
                    .checked_add(RESTORE_TRAMPOLINE_LEN)
                    .ok_or_else(|| anyhow!("LinuxPtraceInjector: payload length overflow"))?
            } else {
                payload.len()
            };

            let remote_addr = remote_mmap_rw(target_pid, staged_len, &original_regs)?;

            write_payload(target_pid, remote_addr, payload)?;

            let (entry_rip, expected_break_rip) = if self.restore_after {
                let trampoline_addr = remote_addr
                    .checked_add(payload.len())
                    .ok_or_else(|| anyhow!("LinuxPtraceInjector: trampoline address overflow"))?;
                let trampoline = build_restore_trampoline(remote_addr);
                write_payload(target_pid, trampoline_addr, &trampoline)?;
                (
                    trampoline_addr as u64,
                    Some((trampoline_addr + RESTORE_TRAMPOLINE_LEN) as u64),
                )
            } else {
                (remote_addr as u64, None)
            };

            remote_mprotect_rx(target_pid, remote_addr, staged_len, &original_regs)?;

            let mut exec_regs = original_regs;
            exec_regs.rip = entry_rip;
            ptrace_setregs(target_pid, &exec_regs)?;

            if let Some(expected_rip) = expected_break_rip {
                ptrace_continue_and_wait(target_pid)?;

                let stopped_regs = ptrace_getregs(target_pid)?;
                if stopped_regs.rip != expected_rip {
                    ptrace_setregs(target_pid, &original_regs)?;
                    return Err(anyhow!(
                        "LinuxPtraceInjector: restore breakpoint mismatch (expected RIP=0x{:x}, got RIP=0x{:x})",
                        expected_rip,
                        stopped_regs.rip
                    ));
                }

                ptrace_setregs(target_pid, &original_regs)?;
            }

            log::info!(
                "LinuxPtraceInjector: staged {} bytes at 0x{:x} in pid {}",
                staged_len,
                remote_addr,
                pid
            );
            Ok(())
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const RESTORE_TRAMPOLINE_LEN: usize = 13;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn build_restore_trampoline(shellcode_addr: usize) -> [u8; RESTORE_TRAMPOLINE_LEN] {
    // movabs rax, <shellcode_addr>
    // call   rax
    // int3
    let mut trampoline = [0u8; RESTORE_TRAMPOLINE_LEN];
    trampoline[0] = 0x48;
    trampoline[1] = 0xB8;
    trampoline[2..10].copy_from_slice(&(shellcode_addr as u64).to_le_bytes());
    trampoline[10] = 0xFF;
    trampoline[11] = 0xD0;
    trampoline[12] = 0xCC;
    trampoline
}

#[cfg(target_os = "linux")]
struct AttachGuard {
    pid: libc::pid_t,
    attached: bool,
}

/// Read `/proc/sys/kernel/yama/ptrace_scope` and return the integer value.
///
/// Returns `None` when the file is absent (YAMA LSM not compiled in), which
/// means there are no YAMA restrictions on ptrace.
///
/// Possible values:
///   0 — no restriction (classic behaviour)
///   1 — restricted: only parent/child processes or those that have been
///       granted access via `prctl(PR_SET_PTRACER)` can attach
///   2 — admin-only: requires `CAP_SYS_PTRACE`
///   3 — no attachment: ptrace attach is disabled even for root/`CAP_SYS_PTRACE`
#[cfg(target_os = "linux")]
fn read_yama_ptrace_scope() -> Option<u8> {
    std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
        .ok()?
        .trim()
        .parse::<u8>()
        .ok()
}

/// Return `true` if the current process has `CAP_SYS_PTRACE` (bit 19) in its
/// effective capability set, by parsing `/proc/self/status`.
///
/// Falls back to `false` if the file cannot be read or parsed.
#[cfg(target_os = "linux")]
fn has_cap_sys_ptrace() -> bool {
    const CAP_SYS_PTRACE_BIT: u64 = 1 << 19;
    let status = match std::fs::read_to_string("/proc/self/status") {
        Ok(s) => s,
        Err(_) => return false,
    };
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("CapEff:\t") {
            if let Ok(caps) = u64::from_str_radix(rest.trim(), 16) {
                return caps & CAP_SYS_PTRACE_BIT != 0;
            }
        }
    }
    false
}

/// Return `true` if `pid` is a direct child of the current process.
///
/// Reads `/proc/{pid}/status` and looks for a `PPid:` line whose value
/// matches `std::process::id()`.  Falls back to `false` on any I/O error so
/// the caller can still attempt the attach.
#[cfg(target_os = "linux")]
fn is_child_process(pid: libc::pid_t) -> bool {
    let path = format!("/proc/{pid}/status");
    let status = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let our_pid = std::process::id();
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("PPid:") {
            return rest.trim().parse::<u32>().map(|ppid| ppid == our_pid).unwrap_or(false);
        }
    }
    false
}

#[cfg(target_os = "linux")]
impl AttachGuard {
    fn attach(pid: libc::pid_t) -> Result<Self> {
        // ── YAMA ptrace scope pre-flight ────────────────────────────────────
        // Check the YAMA LSM ptrace_scope setting before issuing PTRACE_ATTACH.
        // Without this check, permission failures surface as a bare EPERM with
        // no hint about the root cause or the remediation steps.
        match read_yama_ptrace_scope() {
            // scope=3: attachment is unconditionally disabled by policy.
            // PTRACE_ATTACH will always fail; report immediately.
            Some(3) => {
                return Err(anyhow!(
                    "LinuxPtraceInjector: PTRACE_ATTACH({pid}) is blocked by \
                     kernel.yama.ptrace_scope=3 (no ptrace attachment allowed). \
                     To enable injection, an administrator must set \
                     /proc/sys/kernel/yama/ptrace_scope to 0 or 1."
                ));
            }
            // scope=2: only processes with CAP_SYS_PTRACE may attach.
            // Fail early if the effective capability set does not include it.
            Some(2) => {
                if !has_cap_sys_ptrace() {
                    return Err(anyhow!(
                        "LinuxPtraceInjector: PTRACE_ATTACH({pid}) requires CAP_SYS_PTRACE \
                         (kernel.yama.ptrace_scope=2). Run as root or grant the capability \
                         with: setcap cap_sys_ptrace+ep <binary>"
                    ));
                }
            }
            // scope=1: attachment is restricted to parent/child relationships
            // or processes that called prctl(PR_SET_PTRACER).  Check whether
            // the target is a direct child of this process so we can give a
            // precise diagnostic if the attach subsequently fails.
            Some(1) => {
                let is_child = is_child_process(pid);
                if is_child {
                    log::debug!(
                        "LinuxPtraceInjector: kernel.yama.ptrace_scope=1; \
                         pid {pid} is a child of this process — attach should succeed"
                    );
                } else {
                    log::warn!(
                        "LinuxPtraceInjector: kernel.yama.ptrace_scope=1; \
                         pid {pid} is NOT a child of this process (ppid mismatch). \
                         PTRACE_ATTACH will fail with EPERM unless that process has \
                         called prctl(PR_SET_PTRACER, {}) or a privileged peer has \
                         granted access. Consider running as root or adjusting \
                         /proc/sys/kernel/yama/ptrace_scope.",
                        std::process::id()
                    );
                }
            }
            // scope=0 or YAMA not present: no additional restrictions.
            _ => {}
        }

        // ── PTRACE_ATTACH ────────────────────────────────────────────────────
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
            let os_err = std::io::Error::last_os_error();
            // Enrich EPERM errors with ptrace_scope context so the operator
            // knows whether a policy setting is the root cause.
            let scope_note = if os_err.raw_os_error() == Some(libc::EPERM) {
                match read_yama_ptrace_scope() {
                    Some(s) => format!(
                        " (kernel.yama.ptrace_scope={s}: \
                          check /proc/sys/kernel/yama/ptrace_scope)"
                    ),
                    None => String::new(),
                }
            } else {
                String::new()
            };
            return Err(anyhow!(
                "LinuxPtraceInjector: PTRACE_ATTACH({pid}) failed: {os_err}{scope_note}"
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

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod tests {
    use super::*;

    #[test]
    fn default_injector_preserves_fire_and_forget_mode() {
        assert!(!LinuxPtraceInjector::default().restore_after);
        assert!(!LinuxPtraceInjector::new().restore_after);
    }

    #[test]
    fn restore_trampoline_is_call_then_int3() {
        let shellcode_addr = 0x1122_3344_5566_7788usize;
        let tr = build_restore_trampoline(shellcode_addr);

        assert_eq!(tr.len(), RESTORE_TRAMPOLINE_LEN);
        assert_eq!(tr[0], 0x48); // movabs rax, imm64
        assert_eq!(tr[1], 0xB8);
        assert_eq!(
            u64::from_le_bytes(tr[2..10].try_into().expect("imm64 slice")),
            shellcode_addr as u64
        );
        assert_eq!(tr[10], 0xFF); // call rax
        assert_eq!(tr[11], 0xD0);
        assert_eq!(tr[12], 0xCC); // int3
    }
}
