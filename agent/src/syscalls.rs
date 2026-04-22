//! Direct syscalls for Windows.
#![cfg(all(windows, feature = "direct-syscalls"))]

use anyhow::{anyhow, Result};
use std::arch::asm;
use std::ffi::{c_void, CStr};
use winapi::um::winnt::{HANDLE, OBJECT_ATTRIBUTES, PVOID, ULONG};

/// Retrieves the syscall number (SSN) for a given NT function.
///
/// This function is designed to be resilient to API hooking. It finds the address
/// of the specified function in `ntdll.dll` and scans its byte sequence. It looks
/// for the `syscall` instruction (`0F 05`) and then walks backward to find the
/// preceding `mov eax, <ssn>` instruction, from which it extracts the syscall number.
/// This approach avoids relying on a fixed offset from the function start, which
/// can be unreliable if the function prologue is modified by a hook.
fn get_syscall_id(func_name: &str) -> Result<u32> {
    unsafe {
        let ntdll = windows::Win32::System::LibraryLoader::GetModuleHandleA("ntdll.dll")?;
        let func_addr =
            windows::Win32::System::LibraryLoader::GetProcAddress(ntdll, func_name)
                .ok_or_else(|| anyhow!("Could not find function {}", func_name))?;

        let bytes = std::slice::from_raw_parts(func_addr as *const u8, 32);

        // Scan for `syscall` instruction (0x0f, 0x05)
        for i in 0..bytes.len() - 1 {
            if bytes[i] == 0x0f && bytes[i + 1] == 0x05 {
                // Found syscall, now search backwards for `mov eax, <ssn>` (0xb8, ....)
                for j in (0..i).rev() {
                    if bytes[j] == 0xb8 {
                        let ssn_bytes: [u8; 4] =
                            bytes[j + 1..j + 5].try_into().map_err(|_| {
                                anyhow!("Failed to read SSN bytes for {}", func_name)
                            })?;
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
/// This macro retrieves the syscall number at runtime and uses inline assembly
/// to perform the `syscall`. It adheres to the x64 fastcall convention by passing
/// the first four arguments in `rcx`, `rdx`, `r8`, and `r9`. The syscall number
/// is moved into `eax`, and `r10` is used as a temporary register as required by
/// the syscall convention.
///
/// Note: This implementation currently supports up to 4 arguments.
#[macro_export]
macro_rules! syscall {
    ($func_name:expr) => {
        syscall!($func_name,)
    };
    ($func_name:expr, $arg1:expr) => {
        syscall!($func_name, $arg1,)
    };
    ($func_name:expr, $arg1:expr, $arg2:expr) => {
        syscall!($func_name, $arg1, $arg2,)
    };
    ($func_name:expr, $arg1:expr, $arg2:expr, $arg3:expr) => {
        syscall!($func_name, $arg1, $arg2, $arg3,)
    };
    ($func_name:expr, $arg1:expr, $arg2:expr, $arg3:expr, $arg4:expr) => {
        syscall!($func_name, $arg1, $arg2, $arg3, $arg4,)
    };
    ($func_name:expr, $($args:expr),*) => {
        {
            let ssn = get_syscall_id($func_name)?;
            let status: i32;
            let mut arg_iter = [$($args as u64),*].into_iter();
            asm!(
                "mov r10, rcx",
                "mov eax, {ssn}",
                "syscall",
                "ret",
                ssn = in(reg) ssn,
                in("rcx") arg_iter.next().unwrap_or(0),
                in("rdx") arg_iter.next().unwrap_or(0),
                in("r8") arg_iter.next().unwrap_or(0),
                in("r9") arg_iter.next().unwrap_or(0),
                // Additional args would go on the stack here
                lateout("rax") status,
                options(nostack)
            );
            status
        }
    };
}

pub fn allocate_virtual_memory(
    process_handle: HANDLE,
    base_address: &mut *mut c_void,
    region_size: &mut usize,
    allocation_type: u32,
    protect: u32,
) -> Result<()> {
    let status = unsafe {
        syscall!(
            "NtAllocateVirtualMemory",
            process_handle,
            base_address as *mut _ as isize,
            0,
            region_size as *mut _ as isize,
            allocation_type,
            protect
        )
    };
    if status >= 0 {
        Ok(())
    } else {
        Err(anyhow!(
            "NtAllocateVirtualMemory failed with status {:#x}",
            status
        ))
    }
}

pub fn write_virtual_memory(
    process_handle: HANDLE,
    base_address: PVOID,
    buffer: PVOID,
    number_of_bytes_to_write: usize,
    number_of_bytes_written: *mut usize,
) -> Result<()> {
    let status = unsafe {
        syscall!(
            "NtWriteVirtualMemory",
            process_handle,
            base_address,
            buffer,
            number_of_bytes_to_write,
            number_of_bytes_written
        )
    };
    if status >= 0 {
        Ok(())
    } else {
        Err(anyhow!(
            "NtWriteVirtualMemory failed with status {:#x}",
            status
        ))
    }
}

pub fn protect_virtual_memory(
    process_handle: HANDLE,
    base_address: &mut PVOID,
    region_size: &mut usize,
    new_protect: ULONG,
    old_protect: *mut ULONG,
) -> Result<()> {
    let status = unsafe {
        syscall!(
            "NtProtectVirtualMemory",
            process_handle,
            base_address,
            region_size,
            new_protect,
            old_protect
        )
    };
    if status >= 0 {
        Ok(())
    } else {
        Err(anyhow!(
            "NtProtectVirtualMemory failed with status {:#x}",
            status
        ))
    }
}

pub fn create_thread_ex(
    thread_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *mut OBJECT_ATTRIBUTES,
    process_handle: HANDLE,
    start_routine: *mut c_void,
    argument: *mut c_void,
    create_flags: u32,
    zero_bits: usize,
    stack_size: usize,
    maximum_stack_size: usize,
    attribute_list: *mut c_void,
) -> Result<()> {
    let status = unsafe {
        syscall!(
            "NtCreateThreadEx",
            thread_handle as isize,
            desired_access,
            object_attributes as isize,
            process_handle,
            start_routine as isize,
            argument as isize,
            create_flags,
            zero_bits,
            stack_size,
            maximum_stack_size,
            attribute_list as isize
        )
    };
    if status >= 0 {
        Ok(())
    } else {
        Err(anyhow!("NtCreateThreadEx failed with status {:#x}", status))
    }
}
