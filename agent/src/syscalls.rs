//! Direct syscalls for Windows.
#![cfg(all(windows, feature = "direct-syscalls"))]

use anyhow::{anyhow, Result};
use std::arch::asm;
use std::ffi::c_void;
use winapi::shared::minwindef::ULONG;
use winapi::shared::ntdef::OBJECT_ATTRIBUTES;
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use winapi::um::winnt::{HANDLE, PVOID};

/// Retrieves the syscall number (SSN) for a given NT function.
///
/// This function is designed to be resilient to API hooking. It finds the address
/// of the specified function in `ntdll.dll` and scans its byte sequence. It looks
/// for the `syscall` instruction (`0F 05`) and then walks backward to find the
/// preceding `mov eax, <ssn>` instruction, from which it extracts the syscall number.
/// This approach avoids relying on a fixed offset from the function start, which
/// can be unreliable if the function prologue is modified by a hook.
#[doc(hidden)]
pub fn get_syscall_id(func_name: &str) -> Result<u32> {
    unsafe {
        let name_c = std::ffi::CString::new("ntdll.dll")
            .expect("static literal is valid C string");
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
    let a1 = args.get(0).copied().unwrap_or(0);
    let a2 = args.get(1).copied().unwrap_or(0);
    let a3 = args.get(2).copied().unwrap_or(0);
    let a4 = args.get(3).copied().unwrap_or(0);
    let stack_args: &[u64] = if args.len() > 4 { &args[4..] } else { &[] };
    let nstack: usize = stack_args.len();
    let stack_ptr: *const u64 = stack_args.as_ptr();
    let status: i32;

    asm!(
        // Stash caller-provided register args that our stack-copy code will
        // clobber (rcx/rdx are used by `rep movsq`).
        "mov r12, rcx",
        "mov r13, rdx",
        // Save original rsp so we can restore it regardless of alignment.
        "mov r14, rsp",
        // Compute bytes to reserve: 0x28 (shadow + fake-ret slot) + 8*nstack,
        // rounded up to 16 for ABI alignment.
        "mov rax, {nstack}",
        "shl rax, 3",
        "add rax, 0x28 + 15",
        "and rax, -16",
        "sub rsp, rax",
        // Copy stack args to [rsp + 0x28 ..] if any.
        "test {nstack}, {nstack}",
        "jz 2f",
        "mov rcx, {nstack}",
        "mov rsi, {stack_ptr}",
        "lea rdi, [rsp + 0x28]",
        "cld",
        "rep movsq",
        "2:",
        // Restore register args (r8/r9 were never touched).
        "mov rcx, r12",
        "mov rdx, r13",
        "mov r10, rcx",
        "mov eax, {ssn:e}",
        "syscall",
        // Restore rsp.
        "mov rsp, r14",
        ssn        = in(reg) ssn,
        nstack     = in(reg) nstack,
        stack_ptr  = in(reg) stack_ptr,
        in("rcx") a1,
        in("rdx") a2,
        in("r8")  a3,
        in("r9")  a4,
        lateout("rax") status,
        // Clobbers:
        out("r10") _, out("r11") _,
        out("r12") _, out("r13") _, out("r14") _,
        out("rsi") _, out("rdi") _,
    );

    status
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
            base_address as usize,
            buffer as usize,
            number_of_bytes_to_write,
            number_of_bytes_written as usize
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
            base_address as *mut _ as usize,
            region_size as *mut _ as usize,
            new_protect,
            old_protect as usize
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
