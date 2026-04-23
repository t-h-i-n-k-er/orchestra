//! Direct syscalls for Windows and Linux.
#![cfg(all(
    any(windows, target_os = "linux"),
    any(target_arch = "x86_64", target_arch = "aarch64"),
    feature = "direct-syscalls"
))]

use anyhow::{anyhow, Result};
use std::arch::asm;

#[cfg(windows)]
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};

#[cfg(windows)]
/// Retrieves the syscall number (SSN) for a given NT function.
///
/// **Disk-first strategy**: reads `ntdll.dll` from the `System32` directory on
/// disk and resolves the SSN from that clean copy.  This avoids the common EDR
/// hook pattern where the in-memory NTDLL prologue is patched with a `jmp`
/// trampoline that redirects execution to a monitoring DLL—if the patch
/// replaces the `mov eax, <ssn>` instruction, the in-memory scan would return
/// the wrong number or fail entirely.
///
/// Falls back to the in-memory scan if the file cannot be read or parsed, so
/// that the function continues to work in environments where disk access is
/// restricted.
#[doc(hidden)]
#[cfg(windows)]
pub fn get_syscall_id(func_name: &str) -> Result<u32> {
    // Try the clean disk copy first.
    if let Ok(ssn) = get_syscall_id_from_disk(func_name) {
        return Ok(ssn);
    }
    // Fall back to scanning the in-memory (possibly hooked) copy.
    get_syscall_id_from_memory(func_name)
}

/// Read the SSN from a freshly mapped (un-hooked) copy of ntdll.dll on disk.
fn get_syscall_id_from_disk(func_name: &str) -> Result<u32> {
    // Build the path to System32\ntdll.dll from the SystemRoot environment
    // variable so we respect non-standard Windows installations.
    let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    let ntdll_path = format!("{}\\System32\\ntdll.dll", sysroot);

    let bytes = std::fs::read(&ntdll_path)
        .map_err(|e| anyhow!("failed to read {ntdll_path} from disk: {e}"))?;

    // Minimal PE parsing — no external crate needed.
    if bytes.len() < 0x40 {
        anyhow::bail!("ntdll.dll on disk is too small");
    }
    let e_magic = u16::from_le_bytes(bytes[0..2].try_into()?);
    if e_magic != 0x5A4D {
        anyhow::bail!("ntdll.dll on disk has wrong DOS magic");
    }
    let e_lfanew = u32::from_le_bytes(bytes[0x3c..0x40].try_into()?) as usize;
    if bytes.len() < e_lfanew + 0x18 + 2 {
        anyhow::bail!("ntdll.dll truncated before optional header magic");
    }
    let nt_sig = u32::from_le_bytes(bytes[e_lfanew..e_lfanew + 4].try_into()?);
    if nt_sig != 0x4550 {
        anyhow::bail!("ntdll.dll on disk has wrong PE signature");
    }

    // FileHeader is at e_lfanew+4 (20 bytes); OptionalHeader starts at e_lfanew+24.
    let num_sections = u16::from_le_bytes(bytes[e_lfanew + 6..e_lfanew + 8].try_into()?) as usize;
    let opt_header_size =
        u16::from_le_bytes(bytes[e_lfanew + 0x14..e_lfanew + 0x16].try_into()?) as usize;
    let opt_hdr_start = e_lfanew + 24;
    let magic = u16::from_le_bytes(bytes[opt_hdr_start..opt_hdr_start + 2].try_into()?);

    // Offset of DataDirectory[0] (export RVA + size) within the optional header.
    // PE32 (x86): 0x60; PE32+ (x64): 0x70.
    let dd_rel = match magic {
        0x020b => 0x70usize, // PE32+
        0x010b => 0x60usize, // PE32
        _ => anyhow::bail!("unknown PE optional-header magic {magic:#x}"),
    };
    let dd_off = opt_hdr_start + dd_rel;
    if bytes.len() < dd_off + 8 {
        anyhow::bail!("ntdll.dll truncated before export data-directory entry");
    }
    let export_rva = u32::from_le_bytes(bytes[dd_off..dd_off + 4].try_into()?) as usize;
    if export_rva == 0 {
        anyhow::bail!("ntdll.dll has no export directory");
    }

    // Section headers start immediately after the optional header.
    let sections_off = opt_hdr_start + opt_header_size;

    // Translate an RVA to a flat file offset using the section table.
    // IMAGE_SECTION_HEADER is 40 bytes:
    //   +0  Name[8]
    //   +8  Misc.VirtualSize
    //   +12 VirtualAddress
    //   +16 SizeOfRawData
    //   +20 PointerToRawData
    let rva_to_off = |rva: usize| -> Option<usize> {
        for i in 0..num_sections {
            let base = sections_off + i * 40;
            if base + 40 > bytes.len() {
                return None;
            }
            let virt_addr =
                u32::from_le_bytes(bytes[base + 12..base + 16].try_into().ok()?) as usize;
            let virt_size =
                u32::from_le_bytes(bytes[base + 8..base + 12].try_into().ok()?) as usize;
            let raw_size =
                u32::from_le_bytes(bytes[base + 16..base + 20].try_into().ok()?) as usize;
            let raw_off = u32::from_le_bytes(bytes[base + 20..base + 24].try_into().ok()?) as usize;
            let extent = if virt_size == 0 { raw_size } else { virt_size };
            if rva >= virt_addr && rva < virt_addr + extent {
                return Some(raw_off + (rva - virt_addr));
            }
        }
        None
    };

    let export_off =
        rva_to_off(export_rva).ok_or_else(|| anyhow!("export directory RVA not in any section"))?;

    // IMAGE_EXPORT_DIRECTORY (40 bytes):
    //  +24 NumberOfNames
    //  +28 AddressOfFunctions (RVA)
    //  +32 AddressOfNames     (RVA)
    //  +36 AddressOfNameOrdinals (RVA)
    if export_off + 40 > bytes.len() {
        anyhow::bail!("export directory overruns ntdll.dll bytes");
    }
    let num_names =
        u32::from_le_bytes(bytes[export_off + 24..export_off + 28].try_into()?) as usize;
    let funcs_rva =
        u32::from_le_bytes(bytes[export_off + 28..export_off + 32].try_into()?) as usize;
    let names_rva =
        u32::from_le_bytes(bytes[export_off + 32..export_off + 36].try_into()?) as usize;
    let ords_rva = u32::from_le_bytes(bytes[export_off + 36..export_off + 40].try_into()?) as usize;

    let funcs_off = rva_to_off(funcs_rva)
        .ok_or_else(|| anyhow!("AddressOfFunctions RVA not in any section"))?;
    let names_off =
        rva_to_off(names_rva).ok_or_else(|| anyhow!("AddressOfNames RVA not in any section"))?;
    let ords_off = rva_to_off(ords_rva)
        .ok_or_else(|| anyhow!("AddressOfNameOrdinals RVA not in any section"))?;

    for i in 0..num_names {
        let name_rva_off = names_off + i * 4;
        if name_rva_off + 4 > bytes.len() {
            break;
        }
        let name_rva =
            u32::from_le_bytes(bytes[name_rva_off..name_rva_off + 4].try_into()?) as usize;
        let name_off = match rva_to_off(name_rva) {
            Some(o) => o,
            None => continue,
        };
        let name_end = bytes[name_off..].iter().position(|&b| b == 0).unwrap_or(0);
        let name = match std::str::from_utf8(&bytes[name_off..name_off + name_end]) {
            Ok(n) => n,
            Err(_) => continue,
        };
        if name != func_name {
            continue;
        }

        // Found the name — resolve ordinal → function RVA.
        let ord_off = ords_off + i * 2;
        if ord_off + 2 > bytes.len() {
            anyhow::bail!("ordinal array overruns ntdll.dll");
        }
        let ordinal = u16::from_le_bytes(bytes[ord_off..ord_off + 2].try_into()?) as usize;
        let func_rva_off = funcs_off + ordinal * 4;
        if func_rva_off + 4 > bytes.len() {
            anyhow::bail!("function RVA array overruns ntdll.dll");
        }
        let func_rva =
            u32::from_le_bytes(bytes[func_rva_off..func_rva_off + 4].try_into()?) as usize;
        let func_off = rva_to_off(func_rva)
            .ok_or_else(|| anyhow!("function RVA not in any section for {func_name}"))?;

        // Scan up to 32 bytes of the function body for the SSN.
        let scan_end = (func_off + 32).min(bytes.len());
        let func_bytes = &bytes[func_off..scan_end];
        for j in 0..func_bytes.len().saturating_sub(1) {
            if func_bytes[j] == 0x0f && func_bytes[j + 1] == 0x05 {
                for k in (0..j).rev() {
                    if func_bytes[k] == 0xb8 && k + 5 <= func_bytes.len() {
                        let ssn = u32::from_le_bytes(func_bytes[k + 1..k + 5].try_into()?);
                        return Ok(ssn);
                    }
                }
            }
        }
        anyhow::bail!("could not find syscall ID for {func_name} in disk image");
    }
    anyhow::bail!("function {func_name} not found in ntdll.dll export table")
}

/// Original in-memory scan — used as fallback when the disk read fails.
fn get_syscall_id_from_memory(func_name: &str) -> Result<u32> {
    unsafe {
        let name_c = std::ffi::CString::new("ntdll.dll").expect("static literal is valid C string");
        let ntdll = GetModuleHandleA(name_c.as_ptr());
        if ntdll.is_null() {
            return Err(anyhow!("GetModuleHandleA(ntdll) failed"));
        }
        let func_c = std::ffi::CString::new(func_name)
            .map_err(|e| anyhow!("invalid syscall name {func_name}: {e}"))?;
        let func_addr = GetProcAddress(ntdll, func_c.as_ptr());
        if func_addr.is_null() {
            return Err(anyhow!("Could not find function {}", func_name));
        }

        let bytes = std::slice::from_raw_parts(func_addr as *const u8, 32);

        // Scan for `syscall` instruction (0x0f, 0x05)
        for i in 0..bytes.len() - 1 {
            if bytes[i] == 0x0f && bytes[i + 1] == 0x05 {
                // Found syscall, now search backwards for `mov eax, <ssn>` (0xb8, ....)
                for j in (0..i).rev() {
                    if bytes[j] == 0xb8 && j + 5 <= bytes.len() {
                        let ssn_bytes: [u8; 4] = bytes[j + 1..j + 5]
                            .try_into()
                            .map_err(|_| anyhow!("Failed to read SSN bytes for {}", func_name))?;
                        return Ok(u32::from_le_bytes(ssn_bytes));
                    }
                }
            }
        }
    }
    Err(anyhow!("Could not find syscall ID for {}", func_name))
}

/// Invokes a Windows NT syscall with a variable number of arguments.
///
/// The first four arguments go in `rcx`, `rdx`, `r8`, `r9` per the Windows x64
/// calling convention. Any additional arguments are copied onto the stack at
/// `[rsp+0x28]` (immediately above the 0x20-byte shadow space and the 8-byte
/// slot that `syscall` treats as the "return address" area). RSP is saved,
/// re-aligned to 16 bytes, and restored around the `syscall` instruction so
/// this works for any number of arguments, not just <= 4.
#[macro_export]
macro_rules! syscall {
    ($func_name:expr $(, $args:expr)* $(,)?) => {{
        let ssn: u32 = $crate::syscalls::get_syscall_id($func_name)?;
        let args: &[u64] = &[$($args as u64),*];
        $crate::syscalls::do_syscall(ssn, args)
    }};
}

/// Internal helper: invoke `syscall` with `ssn` as the syscall number and
/// `args` laid out per the Windows x64 ABI.
#[doc(hidden)]
#[inline(never)]
pub unsafe fn do_syscall(ssn: u32, args: &[u64]) -> i32 {
    #[cfg(target_arch = "x86_64")]
    {
    let a1 = args.get(0).copied().unwrap_or(0);
    let a2 = args.get(1).copied().unwrap_or(0);
    let a3 = args.get(2).copied().unwrap_or(0);
    let a4 = args.get(3).copied().unwrap_or(0);
    let stack_args: &[u64] = if args.len() > 4 { &args[4..] } else { &[] };
    let nstack: usize = stack_args.len();
    let stack_ptr: *const u64 = stack_args.as_ptr();
    let status: i32;

    asm!(
        // Save the original rsp so we can restore it regardless of how much
        // we subtract for stack arguments and ABI alignment.
        "mov r14, rsp",
        // Compute bytes to reserve: 0x28 (32-byte shadow space + 8-byte
        // fake-return slot) + 8 * nstack, rounded up to 16 for ABI alignment.
        "mov rax, {nstack}",
        "shl rax, 3",
        "add rax, 0x28 + 15",
        "and rax, -16",
        "sub rsp, rax",
        // Copy stack args to [rsp + 0x28 ..] if any.  This clobbers rcx, rsi,
        // rdi, so a1/a2 are deliberately *not* passed via "rcx"/"rdx"
        // constraints — they are bound to compiler-chosen GPRs (`{a1}`/`{a2}`)
        // and only moved into rcx/rdx *after* the rep movsq below.
        "test {nstack}, {nstack}",
        "jz 2f",
        "mov rcx, {nstack}",
        "mov rsi, {stack_ptr}",
        "lea rdi, [rsp + 0x28]",
        "cld",
        "rep movsq",
        "2:",
        // Now load the syscall register arguments.  r8/r9 came from their
        // dedicated "r8"/"r9" constraints and were never disturbed.
        "mov rcx, {a1}",
        "mov rdx, {a2}",
        "mov r10, rcx",
        "mov eax, {ssn:e}",
        "syscall",
        // Restore rsp.  Net effect of this asm block on the stack pointer is
        // zero, but the compiler is informed via `options(nostack)` that it
        // need not maintain stack-relative invariants across this block.
        "mov rsp, r14",
        ssn        = in(reg) ssn,
        nstack     = in(reg) nstack,
        stack_ptr  = in(reg) stack_ptr,
        a1         = in(reg) a1,
        a2         = in(reg) a2,
        in("r8")  a3,
        in("r9")  a4,
        lateout("rax") status,
        // Clobbers (everything we touch that isn't an input/output).
        out("rcx") _, out("rdx") _, out("r10") _, out("r11") _,
        out("r14") _,
        out("rsi") _, out("rdi") _,
        // The asm restores rsp to its entry value before returning, so the
        // compiler can treat the stack as untouched.  Without this the
        // compiler may insert a stack realignment that would corrupt the
        // shadow-space layout we set up above.
        options(nostack),
    );

    status
    }
    #[cfg(target_arch = "aarch64")]
    {
        // Direct syscalls currently unsupported on Windows ARM64
        tracing::error!("Direct syscalls not yet implemented for aarch64 Windows");
        -1
    }
}

#[cfg(target_os = "linux")]
#[macro_export]
macro_rules! syscall {
    ($func_name:expr $(, $args:expr)* $(,)?) => {{
        let ssn = $crate::syscalls::get_syscall_id($func_name).expect("unknown linux syscall");
        let args: &[u64] = &[$($args as u64),*];
        unsafe { $crate::syscalls::do_syscall(ssn as u32, args).unwrap_or_else(|e| {
            // caller can handle Err or panic, returning !0 to signal caller as typically done
            (u64::MAX - (e as u64) + 1)
        }) }
    }};
}

#[cfg(target_os = "linux")]
pub fn get_syscall_id(name: &str) -> anyhow::Result<u32> {
    #[cfg(target_arch = "x86_64")]
    match name {
        "read" => Ok(0),
        "write" => Ok(1),
        "open" => Ok(2),
        "close" => Ok(3),
        "stat" => Ok(4),
        "fstat" => Ok(5),
        "lstat" => Ok(6),
        "poll" => Ok(7),
        "lseek" => Ok(8),
        "mmap" => Ok(9),
        "mprotect" => Ok(10),
        "munmap" => Ok(11),
        "brk" => Ok(12),
        "rt_sigaction" => Ok(13),
        "rt_sigprocmask" => Ok(14),
        "rt_sigreturn" => Ok(15),
        "ioctl" => Ok(16),
        "pread64" => Ok(17),
        "pwrite64" => Ok(18),
        "readv" => Ok(19),
        "writev" => Ok(20),
        "access" => Ok(21),
        "pipe" => Ok(22),
        "select" => Ok(23),
        "sched_yield" => Ok(24),
        "mremap" => Ok(25),
        "msync" => Ok(26),
        "mincore" => Ok(27),
        "madvise" => Ok(28),
        "shmget" => Ok(29),
        "shmat" => Ok(30),
        "shmctl" => Ok(31),
        "dup" => Ok(32),
        "dup2" => Ok(33),
        "pause" => Ok(34),
        "nanosleep" => Ok(35),
        "getitimer" => Ok(36),
        "alarm" => Ok(37),
        "setitimer" => Ok(38),
        "getpid" => Ok(39),
        "sendfile" => Ok(40),
        "socket" => Ok(41),
        "connect" => Ok(42),
        "accept" => Ok(43),
        "sendto" => Ok(44),
        "recvfrom" => Ok(45),
        "sendmsg" => Ok(46),
        "recvmsg" => Ok(47),
        "shutdown" => Ok(48),
        "bind" => Ok(49),
        "listen" => Ok(50),
        "getsockname" => Ok(51),
        "getpeername" => Ok(52),
        "socketpair" => Ok(53),
        "setsockopt" => Ok(54),
        "getsockopt" => Ok(55),
        "clone" => Ok(56),
        "fork" => Ok(57),
        "vfork" => Ok(58),
        "execve" => Ok(59),
        "exit" => Ok(60),
        "wait4" => Ok(61),
        "kill" => Ok(62),
        "uname" => Ok(63),
        "semget" => Ok(64),
        "semop" => Ok(65),
        "semctl" => Ok(66),
        "shmdt" => Ok(67),
        "msgget" => Ok(68),
        "msgsnd" => Ok(69),
        "msgrcv" => Ok(70),
        "msgctl" => Ok(71),
        "fcntl" => Ok(72),
        "flock" => Ok(73),
        "fsync" => Ok(74),
        "fdatasync" => Ok(75),
        "truncate" => Ok(76),
        "ftruncate" => Ok(77),
        "getdents" => Ok(78),
        "getcwd" => Ok(79),
        "chdir" => Ok(80),
        "fchdir" => Ok(81),
        "rename" => Ok(82),
        "mkdir" => Ok(83),
        "rmdir" => Ok(84),
        "creat" => Ok(85),
        "link" => Ok(86),
        "unlink" => Ok(87),
        "symlink" => Ok(88),
        "readlink" => Ok(89),
        "chmod" => Ok(90),
        "fchmod" => Ok(91),
        "chown" => Ok(92),
        "fchown" => Ok(93),
        "lchown" => Ok(94),
        "umask" => Ok(95),
        "gettimeofday" => Ok(96),
        "getrlimit" => Ok(97),
        "getrusage" => Ok(98),
        "sysinfo" => Ok(99),
        "times" => Ok(100),
        "ptrace" => Ok(101),
        "getuid" => Ok(102),
        "syslog" => Ok(103),
        "getgid" => Ok(104),
        "setuid" => Ok(105),
        "setgid" => Ok(106),
        "geteuid" => Ok(107),
        "getegid" => Ok(108),
        "setpgid" => Ok(109),
        "getppid" => Ok(110),
        "getpgrp" => Ok(111),
        "setsid" => Ok(112),
        "setreuid" => Ok(113),
        "setregid" => Ok(114),
        "getgroups" => Ok(115),
        "setgroups" => Ok(116),
        "setresuid" => Ok(117),
        "setresgid" => Ok(118),
        "getresuid" => Ok(119),
        "getresgid" => Ok(120),
        "getpgid" => Ok(121),
        "setfsuid" => Ok(122),
        "setfsgid" => Ok(123),
        "getsid" => Ok(124),
        "capget" => Ok(125),
        "capset" => Ok(126),
        "rt_sigpending" => Ok(127),
        "rt_sigtimedwait" => Ok(128),
        "rt_sigqueueinfo" => Ok(129),
        "rt_sigsuspend" => Ok(130),
        "sigaltstack" => Ok(131),
        "utime" => Ok(132),
        "mknod" => Ok(133),
        "uselib" => Ok(134),
        "personality" => Ok(135),
        "ustat" => Ok(136),
        "statfs" => Ok(137),
        "fstatfs" => Ok(138),
        "sysfs" => Ok(139),
        "getpriority" => Ok(140),
        "setpriority" => Ok(141),
        "sched_setparam" => Ok(142),
        "sched_getparam" => Ok(143),
        "sched_setscheduler" => Ok(144),
        "sched_getscheduler" => Ok(145),
        "sched_get_priority_max" => Ok(146),
        "sched_get_priority_min" => Ok(147),
        "sched_rr_get_interval" => Ok(148),
        "mlock" => Ok(149),
        "munlock" => Ok(150),
        "mlockall" => Ok(151),
        "munlockall" => Ok(152),
        "vhangup" => Ok(153),
        "modify_ldt" => Ok(154),
        "pivot_root" => Ok(155),
        "_sysctl" => Ok(156),
        "prctl" => Ok(157),
        "arch_prctl" => Ok(158),
        "adjtimex" => Ok(159),
        "setrlimit" => Ok(160),
        "chroot" => Ok(161),
        "sync" => Ok(162),
        "acct" => Ok(163),
        "settimeofday" => Ok(164),
        "mount" => Ok(165),
        "umount2" => Ok(166),
        "swapon" => Ok(167),
        "swapoff" => Ok(168),
        "reboot" => Ok(169),
        "sethostname" => Ok(170),
        "setdomainname" => Ok(171),
        "iopl" => Ok(172),
        "ioperm" => Ok(173),
        "create_module" => Ok(174),
        "init_module" => Ok(175),
        "delete_module" => Ok(176),
        "get_kernel_syms" => Ok(177),
        "query_module" => Ok(178),
        "quotactl" => Ok(179),
        "nfsservctl" => Ok(180),
        "getpmsg" => Ok(181),
        "putpmsg" => Ok(182),
        "afs_syscall" => Ok(183),
        "tuxcall" => Ok(184),
        "security" => Ok(185),
        "gettid" => Ok(186),
        "readahead" => Ok(187),
        "setxattr" => Ok(188),
        "lsetxattr" => Ok(189),
        "fsetxattr" => Ok(190),
        "getxattr" => Ok(191),
        "lgetxattr" => Ok(192),
        "fgetxattr" => Ok(193),
        "listxattr" => Ok(194),
        "llistxattr" => Ok(195),
        "flistxattr" => Ok(196),
        "removexattr" => Ok(197),
        "lremovexattr" => Ok(198),
        "fremovexattr" => Ok(199),
        "tkill" => Ok(200),
        "time" => Ok(201),
        "futex" => Ok(202),
        "sched_setaffinity" => Ok(203),
        "sched_getaffinity" => Ok(204),
        "set_thread_area" => Ok(205),
        "io_setup" => Ok(206),
        "io_destroy" => Ok(207),
        "io_getevents" => Ok(208),
        "io_submit" => Ok(209),
        "io_cancel" => Ok(210),
        "get_thread_area" => Ok(211),
        "lookup_dcookie" => Ok(212),
        "epoll_create" => Ok(213),
        "epoll_ctl_old" => Ok(214),
        "epoll_wait_old" => Ok(215),
        "remap_file_pages" => Ok(216),
        "getdents64" => Ok(217),
        "set_tid_address" => Ok(218),
        "restart_syscall" => Ok(219),
        "semtimedop" => Ok(220),
        "fadvise64" => Ok(221),
        "timer_create" => Ok(222),
        "timer_settime" => Ok(223),
        "timer_gettime" => Ok(224),
        "timer_getoverrun" => Ok(225),
        "timer_delete" => Ok(226),
        "clock_settime" => Ok(227),
        "clock_gettime" => Ok(228),
        "clock_getres" => Ok(229),
        "clock_nanosleep" => Ok(230),
        "exit_group" => Ok(231),
        "epoll_wait" => Ok(232),
        "epoll_ctl" => Ok(233),
        "tgkill" => Ok(234),
        "utimes" => Ok(235),
        "vserver" => Ok(236),
        "mbind" => Ok(237),
        "set_mempolicy" => Ok(238),
        "get_mempolicy" => Ok(239),
        "mq_open" => Ok(240),
        "mq_unlink" => Ok(241),
        "mq_timedsend" => Ok(242),
        "mq_timedreceive" => Ok(243),
        "mq_notify" => Ok(244),
        "mq_getsetattr" => Ok(245),
        "kexec_load" => Ok(246),
        "waitid" => Ok(247),
        "add_key" => Ok(248),
        "request_key" => Ok(249),
        "keyctl" => Ok(250),
        "ioprio_set" => Ok(251),
        "ioprio_get" => Ok(252),
        "inotify_init" => Ok(253),
        "inotify_add_watch" => Ok(254),
        "inotify_rm_watch" => Ok(255),
        "migrate_pages" => Ok(256),
        "openat" => Ok(257),
        "mkdirat" => Ok(258),
        "mknodat" => Ok(259),
        "fchownat" => Ok(260),
        "futimesat" => Ok(261),
        "newfstatat" => Ok(262),
        "unlinkat" => Ok(263),
        "renameat" => Ok(264),
        "linkat" => Ok(265),
        "symlinkat" => Ok(266),
        "readlinkat" => Ok(267),
        "fchmodat" => Ok(268),
        "faccessat" => Ok(269),
        "pselect6" => Ok(270),
        "ppoll" => Ok(271),
        "unshare" => Ok(272),
        "set_robust_list" => Ok(273),
        "get_robust_list" => Ok(274),
        "splice" => Ok(275),
        "tee" => Ok(276),
        "sync_file_range" => Ok(277),
        "vmsplice" => Ok(278),
        "move_pages" => Ok(279),
        "utimensat" => Ok(280),
        "epoll_pwait" => Ok(281),
        "signalfd" => Ok(282),
        "timerfd_create" => Ok(283),
        "timerfd_settime" => Ok(284),
        "timerfd_gettime" => Ok(285),
        "eventfd" => Ok(286),
        "fallocate" => Ok(287),
        "timerfd" => Ok(288),
        "signalfd4" => Ok(289),
        "eventfd2" => Ok(290),
        "epoll_create1" => Ok(291),
        "dup3" => Ok(292),
        "pipe2" => Ok(293),
        "inotify_init1" => Ok(294),
        "preadv" => Ok(295),
        "pwritev" => Ok(296),
        "rt_tgsigqueueinfo" => Ok(297),
        "perf_event_open" => Ok(298),
        "recvmmsg" => Ok(299),
        "fanotify_init" => Ok(300),
        "fanotify_mark" => Ok(301),
        "prlimit64" => Ok(302),
        "name_to_handle_at" => Ok(303),
        "open_by_handle_at" => Ok(304),
        "clock_adjtime" => Ok(305),
        "syncfs" => Ok(306),
        "sendmmsg" => Ok(307),
        "setns" => Ok(308),
        "getcpu" => Ok(309),
        "process_vm_readv" => Ok(310),
        "process_vm_writev" => Ok(311),
        "kcmp" => Ok(312),
        "finit_module" => Ok(313),
        "memfd_create" => Ok(319),
        "execveat" => Ok(322),
        "userfaultfd" => Ok(323),
        "copy_file_range" => Ok(326),
        "bpf" => Ok(321),
        "getrandom" => Ok(318),
        _ => Err(anyhow::anyhow!("Unknown syscall: {}", name)),
    }
    
    #[cfg(target_arch = "aarch64")]
    match name {
        "read" => Ok(63),
        "write" => Ok(64),
        "openat" => Ok(56),
        "close" => Ok(57),
        "fstat" => Ok(80),
        "newfstatat" => Ok(79),
        "lseek" => Ok(62),
        "mmap" => Ok(222),
        "mprotect" => Ok(226),
        "munmap" => Ok(215),
        "brk" => Ok(214),
        "rt_sigaction" => Ok(134),
        "rt_sigprocmask" => Ok(135),
        "rt_sigreturn" => Ok(139),
        "ioctl" => Ok(29),
        "pread64" => Ok(67),
        "pwrite64" => Ok(68),
        "readv" => Ok(65),
        "writev" => Ok(66),
        "pipe2" => Ok(59),
        "dup" => Ok(23),
        "dup3" => Ok(24),
        "getpid" => Ok(172),
        "socket" => Ok(198),
        "connect" => Ok(203),
        "accept" => Ok(202),
        "sendto" => Ok(206),
        "recvfrom" => Ok(207),
        "sendmsg" => Ok(211),
        "recvmsg" => Ok(212),
        "shutdown" => Ok(210),
        "bind" => Ok(200),
        "listen" => Ok(201),
        "getsockname" => Ok(204),
        "getpeername" => Ok(205),
        "socketpair" => Ok(199),
        "setsockopt" => Ok(208),
        "getsockopt" => Ok(209),
        "clone" => Ok(220),
        "execve" => Ok(221),
        "exit" => Ok(93),
        "wait4" => Ok(260),
        "kill" => Ok(129),
        "uname" => Ok(160),
        "fcntl" => Ok(25),
        "flock" => Ok(32),
        "fsync" => Ok(82),
        "fdatasync" => Ok(83),
        "truncate" => Ok(45),
        "ftruncate" => Ok(46),
        "getdents64" => Ok(61),
        "getcwd" => Ok(17),
        "chdir" => Ok(49),
        "fchdir" => Ok(50),
        "mkdirat" => Ok(34),
        "unlinkat" => Ok(35),
        "renameat" => Ok(38),
        "linkat" => Ok(37),
        "symlinkat" => Ok(36),
        "readlinkat" => Ok(78),
        "fchmodat" => Ok(53),
        "faccessat" => Ok(48),
        "gettimeofday" => Ok(169),
        "sysinfo" => Ok(179),
        "bpf" => Ok(280),
        "userfaultfd" => Ok(282),
        "memfd_create" => Ok(279),
        "copy_file_range" => Ok(285),
        "getrandom" => Ok(278),
        _ => Err(anyhow::anyhow!("Unknown aarch64 syscall: {}", name)),
    }
}


#[cfg(target_os = "linux")]
pub unsafe fn do_syscall(ssn: u32, args: &[u64]) -> Result<u64, i32> {
    let mut status: u64;
    let a1 = *args.get(0).unwrap_or(&0);
    let a2 = *args.get(1).unwrap_or(&0);
    let a3 = *args.get(2).unwrap_or(&0);
    let a4 = *args.get(3).unwrap_or(&0);
    let a5 = *args.get(4).unwrap_or(&0);
    let a6 = *args.get(5).unwrap_or(&0);

    #[cfg(target_arch = "x86_64")]
    {
        asm!(
            "mov rax, {ssn:e}",
            "mov rdi, {a1}",
            "mov rsi, {a2}",
            "mov rdx, {a3}",
            "mov r10, {a4}",
            "mov r8, {a5}",
            "mov r9, {a6}",
            "syscall",
            ssn = in(reg) ssn,
            a1 = in(reg) a1,
            a2 = in(reg) a2,
            a3 = in(reg) a3,
            a4 = in(reg) a4,
            a5 = in(reg) a5,
            a6 = in(reg) a6,
            lateout("rax") status,
            out("rcx") _, out("r11") _, // syscall clobbers rcx and r11
            options(nostack)
        );
    }

    #[cfg(target_arch = "aarch64")]
    {
        asm!(
            "svc 0",
            in("x8") ssn as u64,
            in("x0") a1,
            in("x1") a2,
            in("x2") a3,
            in("x3") a4,
            in("x4") a5,
            in("x5") a6,
            lateout("x0") status,
            options(nostack)
        );
    }

    if status > 0xfffffffffffff000 {
        Err((!status + 1) as i32)
    } else {
        Ok(status)
    }
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct dirent64 {
    pub d_ino: u64,
    pub d_off: i64,
    pub d_reclen: u16,
    pub d_type: u8,
    pub d_name: [u8; 256],
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct stat64 {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_nlink: u64,
    pub st_mode: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub __pad0: i32,
    pub st_rdev: u64,
    pub st_size: i64,
    pub st_blksize: i64,
    pub st_blocks: i64,
    pub st_atime: i64,
    pub st_atime_nsec: i64,
    pub st_mtime: i64,
    pub st_mtime_nsec: i64,
    pub st_ctime: i64,
    pub st_ctime_nsec: i64,
    pub __unused: [i64; 3],
}
