//! Direct syscalls for Windows.
#![cfg(all(windows, feature = "direct-syscalls"))]

use anyhow::{anyhow, Result};
use ntapi::ntmmapi::{NtAllocateVirtualMemory, NtProtectVirtualMemory, NtWriteVirtualMemory};
use ntapi::ntpsapi::NtCreateThreadEx;
use std::arch::asm;
use std::ffi::c_void;
use windows::Win32::System::SystemServices::IMAGE_DOS_HEADER;

// A simplified version. A real implementation would parse the EAT of ntdll.
fn get_syscall_id(func_name: &str) -> Result<u32> {
    unsafe {
        let ntdll = windows::Win32::System::LibraryLoader::GetModuleHandleA("ntdll.dll")?;
        let func_addr = windows::Win32::System::LibraryLoader::GetProcAddress(ntdll, func_name);
        if let Some(addr) = func_addr {
            // In x64, syscall stubs often look like:
            // mov r10, rcx
            // mov eax, <syscall_id>
            // syscall
            let bytes = std::slice::from_raw_parts(addr as *const u8, 8);
            if bytes[0] == 0x4c && bytes[1] == 0x8b && bytes[2] == 0xd1 && bytes[3] == 0xb8 {
                let id = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
                return Ok(id);
            }
        }
    }
    Err(anyhow!("Could not find syscall ID for {}", func_name))
}

macro_rules! syscall {
    ($func_name:expr, $($arg:expr),*) => {
        {
            let ssn = get_syscall_id($func_name)?;
            let status: i32;
            asm!(
                "mov r10, rcx",
                "mov eax, {ssn}",
                "syscall",
                "ret",
                ssn = in(reg) ssn,
                in("rcx") $($arg),*,
                lateout("rax") status
            );
            status
        }
    };
}

pub fn allocate_virtual_memory(
    process_handle: isize,
    base_address: &mut *mut c_void,
    region_size: &mut usize,
    allocation_type: u32,
    protect: u32,
) -> Result<()> {
    let status = unsafe {
        syscall!(
            "NtAllocateVirtualMemory",
            process_handle,
            base_address,
            0,
            region_size,
            allocation_type,
            protect
        )
    };
    if status >= 0 {
        Ok(())
    } else {
        Err(anyhow!(
            "NtAllocateVirtualMemory failed with status {}",
            status
        ))
    }
}

// Add wrappers for NtWriteVirtualMemory, NtProtectVirtualMemory, NtCreateThreadEx
