//! UEFI NVRAM variable manipulation — read/write EFI variables, enumerate and modify boot entries.
//!
//! # Platform Support
//!
//! - **Windows**: Uses `GetFirmwareEnvironmentVariableA` / `SetFirmwareEnvironmentVariableA`
//!   (requires `SeSystemEnvironmentPrivilege`).
//! - **Linux**: Reads from / writes to `/sys/firmware/efi/efivars/<name>-<guid>`.
//! - **macOS**: Uses the `nvram` command-line tool (`/usr/sbin/nvram`) to read/write
//!   EFI variables.  Requires root privileges (SIP-protected on Apple Silicon, but
//!   accessible via `nvram` on Intel Macs with UEFI firmware).
//!
//! # Safety
//!
//! All NVRAM writes validate data before committing. Boot entries are backed up
//! before modification.

use crate::{BootEntry, EfiGuid, EfiVarAttributes};
use anyhow::{bail, Context, Result};
use std::fmt;

// ─── EFI_LOAD_OPTION flags ──────────────────────────────────────────────
const LOAD_OPTION_ACTIVE: u16 = 0x0001;
const LOAD_OPTION_FORCE_RECONNECT: u16 = 0x0002;
const LOAD_OPTION_HIDDEN: u16 = 0x0008;
const _LOAD_OPTION_CATEGORY: u16 = 0x01F0;

// ─── EFI Device Path types ──────────────────────────────────────────────
const _END_DEVICE_PATH_TYPE: u8 = 0x7F;
const END_ENTIRE_DEVICE_PATH_SUBTYPE: u8 = 0xFF;
const HARDWARE_DEVICE_PATH: u8 = 0x01;
const ACPI_DEVICE_PATH: u8 = 0x02;
const MESSAGING_DEVICE_PATH: u8 = 0x03;
const MEDIA_DEVICE_PATH: u8 = 0x04;
const _BBS_DEVICE_PATH: u8 = 0x05;

const MEDIA_FILE_PATH_DP_SUBTYPE: u8 = 0x04;
const MEDIA_VENDOR_DP_SUBTYPE: u8 = 0x03;

/// Result of boot entry backup/restore operations.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BootEntryBackup {
    /// The entry number that was backed up.
    pub entry_number: u16,
    /// Original raw bytes of the EFI_LOAD_OPTION.
    pub original_data: Vec<u8>,
    /// Timestamp of the backup.
    pub timestamp: String,
}

/// Result of boot order modification.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BootOrderResult {
    /// The original boot order before modification.
    pub original_order: Vec<u16>,
    /// The new boot order after modification.
    pub new_order: Vec<u16>,
    /// Backups created during the operation.
    pub backups: Vec<BootEntryBackup>,
}

// ─── Platform-specific EFI variable I/O ─────────────────────────────────

/// Read an EFI variable by name and GUID.
///
/// On Linux, the returned data includes the 4-byte attribute header.
/// On Windows, the returned data is the raw variable value.
pub fn read_efi_variable(name: &str, guid: &EfiGuid) -> Result<Vec<u8>> {
    #[cfg(target_os = "linux")]
    {
        read_efi_variable_linux(name, guid)
    }
    #[cfg(target_os = "windows")]
    {
        read_efi_variable_windows(name, guid)
    }
    #[cfg(target_os = "macos")]
    {
        read_efi_variable_macos(name, guid)
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        let _ = (name, guid);
        bail!("EFI variable operations are not supported on this platform");
    }
}

/// Write an EFI variable by name and GUID with the specified attributes.
///
/// **Safety**: The data is validated before writing. On Linux, the variable
/// must already exist or the kernel may reject the write depending on sysfs
/// permissions. Callers should ensure they have the necessary privileges.
pub fn write_efi_variable(
    name: &str,
    guid: &EfiGuid,
    data: &[u8],
    attrs: EfiVarAttributes,
) -> Result<()> {
    if data.is_empty() {
        bail!("Cannot write empty EFI variable — this could delete the variable");
    }

    #[cfg(target_os = "linux")]
    {
        write_efi_variable_linux(name, guid, data, attrs)
    }
    #[cfg(target_os = "windows")]
    {
        write_efi_variable_windows(name, guid, data, attrs)
    }
    #[cfg(target_os = "macos")]
    {
        write_efi_variable_macos(name, guid, data, attrs)
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        let _ = (name, guid, data, attrs);
        bail!("EFI variable operations are not supported on this platform");
    }
}

/// Delete an EFI variable.
///
/// **WARNING**: Deleting critical boot variables can prevent the system from
/// booting. Use with extreme caution.
pub fn delete_efi_variable(name: &str, guid: &EfiGuid) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let path = format!("/sys/firmware/efi/efivars/{}-{}", name, guid.to_string());
        let p = std::path::Path::new(&path);
        if !p.exists() {
            bail!("EFI variable {} does not exist", name);
        }
        std::fs::remove_file(p).with_context(|| format!("Failed to delete EFI variable {}", name))
    }
    #[cfg(target_os = "windows")]
    {
        // GetFirmwareEnvironmentVariableW / SetFirmwareEnvironmentVariableW:
        //   lpName = variable name only (e.g. "BootOrder")
        //   lpGuid = GUID string (e.g. "{8be4df61-93ca-11d2-aa0d-00e098032b8c}")
        let wide_name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let wide_guid: Vec<u16> = format!("{{{}}}", guid.to_string())
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        unsafe {
            let result = windows_sys::Win32::System::WindowsProgramming::SetFirmwareEnvironmentVariableW(
                wide_name.as_ptr(),
                wide_guid.as_ptr(),
                std::ptr::null_mut(),
                0,
            );
            if result == 0 {
                let err = windows_sys::Win32::Foundation::GetLastError();
                bail!(
                    "SetFirmwareEnvironmentVariableW failed for {}: error {}",
                    name,
                    err
                );
            }
        }
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        // macOS nvram -d deletes a variable by name.
        // Use the GUID-qualified name to be precise.
        let nvram_name = format!("{}:{}", guid.to_string(), name);
        let output = std::process::Command::new("/usr/sbin/nvram")
            .arg("-d")
            .arg(&nvram_name)
            .output()
            .context("Failed to execute nvram")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // nvram returns error if variable doesn't exist; that's fine for delete.
            if stderr.contains("not found") || stderr.contains("No such") {
                return Ok(());
            }
            bail!("nvram -d failed for {}: {}", name, stderr);
        }
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        let _ = (name, guid);
        bail!("EFI variable operations are not supported on this platform");
    }
}

// ─── Linux implementation ───────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn read_efi_variable_linux(name: &str, guid: &EfiGuid) -> Result<Vec<u8>> {
    let path = format!("/sys/firmware/efi/efivars/{}-{}", name, guid.to_string());
    let data = std::fs::read(&path)
        .with_context(|| format!("Failed to read EFI variable {} from {}", name, path))?;
    // Linux efivars format: first 4 bytes are attributes, rest is data.
    if data.len() < 4 {
        bail!(
            "EFI variable {} has unexpected short data ({} bytes)",
            name,
            data.len()
        );
    }
    // Return attributes + data (caller can strip attributes if needed).
    Ok(data)
}

#[cfg(target_os = "linux")]
fn write_efi_variable_linux(
    name: &str,
    guid: &EfiGuid,
    data: &[u8],
    attrs: EfiVarAttributes,
) -> Result<()> {
    let path = format!("/sys/firmware/efi/efivars/{}-{}", name, guid.to_string());
    let p = std::path::Path::new(&path);

    // Linux efivars format: 4 bytes attributes + data.
    let mut out = Vec::with_capacity(4 + data.len());
    out.extend_from_slice(&attrs.0.to_le_bytes());
    out.extend_from_slice(data);

    // If the variable already exists, we need to remove the immutable flag
    // (chattr -i) before writing. Some distros set this.
    if p.exists() {
        // Try to write directly first.
        match std::fs::write(p, &out) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                // Try removing immutable flag via chattr.
                let chattr_result = std::process::Command::new("chattr")
                    .arg("-i")
                    .arg(&path)
                    .output();
                if let Ok(output) = chattr_result {
                    if output.status.success() {
                        std::fs::write(p, &out)
                            .with_context(|| format!("Failed to write EFI variable {}", name))?;
                        // Re-set immutable flag for safety.
                        let _ = std::process::Command::new("chattr")
                            .arg("+i")
                            .arg(&path)
                            .output();
                        return Ok(());
                    }
                }
                bail!(
                    "Permission denied writing EFI variable {} (tried chattr -i)",
                    name
                );
            }
            Err(e) => bail!("Failed to write EFI variable {}: {}", name, e),
        }
    } else {
        // Create new variable.
        std::fs::write(p, &out)
            .with_context(|| format!("Failed to create EFI variable {}", name))?;
    }
    Ok(())
}

// ─── Windows implementation ─────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn read_efi_variable_windows(name: &str, guid: &EfiGuid) -> Result<Vec<u8>> {
    // GetFirmwareEnvironmentVariableW expects the variable name and GUID
    // as separate parameters:
    //   lpName = variable name only (e.g. "BootOrder")
    //   lpGuid = GUID string (e.g. "{8be4df61-93ca-11d2-aa0d-00e098032b8c}")
    let wide_name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let wide_guid: Vec<u16> = format!("{{{}}}", guid.to_string())
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        // First call to get the required buffer size.
        let size = windows_sys::Win32::System::WindowsProgramming::GetFirmwareEnvironmentVariableW(
            wide_name.as_ptr(),
            wide_guid.as_ptr(),
            std::ptr::null_mut(),
            0,
        );
        if size == 0 {
            let err = windows_sys::Win32::Foundation::GetLastError();
            bail!(
                "GetFirmwareEnvironmentVariableW failed for {}: error {}",
                name,
                err
            );
        }

        let mut buf = vec![0u8; size as usize];
        let read = windows_sys::Win32::System::WindowsProgramming::GetFirmwareEnvironmentVariableW(
            wide_name.as_ptr(),
            wide_guid.as_ptr(),
            buf.as_mut_ptr() as *mut _,
            size,
        );
        if read == 0 {
            let err = windows_sys::Win32::Foundation::GetLastError();
            bail!(
                "GetFirmwareEnvironmentVariableW read failed for {}: error {}",
                name,
                err
            );
        }
        buf.truncate(read as usize);
        Ok(buf)
    }
}

#[cfg(target_os = "windows")]
fn write_efi_variable_windows(
    name: &str,
    guid: &EfiGuid,
    data: &[u8],
    _attrs: EfiVarAttributes,
) -> Result<()> {
    let wide_name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let wide_guid: Vec<u16> = format!("{{{}}}", guid.to_string())
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let result = windows_sys::Win32::System::WindowsProgramming::SetFirmwareEnvironmentVariableW(
            wide_name.as_ptr(),
            wide_guid.as_ptr(),
            data.as_ptr() as *mut _,
            data.len() as u32,
        );
        if result == 0 {
            let err = windows_sys::Win32::Foundation::GetLastError();
            bail!(
                "SetFirmwareEnvironmentVariableW failed for {}: error {}",
                name,
                err
            );
        }
    }
    Ok(())
}

// ─── macOS implementation ───────────────────────────────────────────────
//
// macOS does not expose EFI variables through a filesystem like Linux or
// through a Win32 API like Windows.  Instead, the `nvram` command-line tool
// (`/usr/sbin/nvram`) provides read/write access to firmware (NVRAM) variables.
//
// On Intel Macs with UEFI firmware, all standard EFI variables (BootOrder,
// BootXXXX, etc.) are accessible via `nvram`.  On Apple Silicon Macs, the
// firmware NVRAM namespace is more restricted; only Apple-defined variables
// are typically accessible.  For UEFI boot kit purposes, Intel Macs are the
// primary target — Apple Silicon Macs use an entirely different boot flow
// (iBoot + Secure Enclave) where UEFI persistence does not apply.
//
// Variable naming convention for nvram:
//   - Standard UEFI variables use the GUID-qualified form: `<GUID>:<Name>`
//     e.g. `8BE4DF61-93CA-11D2-AA0D-00E098032B8C:BootOrder`
//   - The `nvram -p` output lists variables as `<Name>  <hex data>`, where
//     `<Name>` already includes the GUID prefix for firmware variables.
//   - For read: `nvram <name>` prints `<name>\t<hex bytes>`
//   - For write: `nvram <name>=<hex value>` (no spaces around =)
//   - For delete: `nvram -d <name>`

#[cfg(target_os = "macos")]
fn nvram_var_name(name: &str, guid: &EfiGuid) -> String {
    format!("{}:{}", guid.to_string().to_uppercase(), name)
}

#[cfg(target_os = "macos")]
fn read_efi_variable_macos(name: &str, guid: &EfiGuid) -> Result<Vec<u8>> {
    let var_name = nvram_var_name(name, guid);
    let output = std::process::Command::new("/usr/sbin/nvram")
        .arg(&var_name)
        .output()
        .context("Failed to execute /usr/sbin/nvram")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("nvram read failed for {}: {}", name, stderr.trim());
    }

    // nvram output format: "<name>\t<value>\n"
    // The value is typically hex-encoded ASCII bytes, e.g.:
    //   %01%00%00%00%00%00
    // or plain hex like:
    //   01000000 0000
    // Parse the tab-separated output.
    let stdout = String::from_utf8_lossy(&output.stdout);
    let value_part = stdout
        .find('\t')
        .map(|i| &stdout[i + 1..])
        .or_else(|| stdout.find(' ').map(|i| &stdout[i + 1..]))
        .unwrap_or("")
        .trim();

    if value_part.is_empty() {
        bail!("nvram returned empty value for {}", name);
    }

    // Try parsing as %-encoded hex first (%XX format used by macOS nvram).
    let data = if value_part.contains('%') {
        parse_nvram_percent_encoded(value_part)?
    } else {
        // Try plain hex (space-separated hex bytes).
        parse_nvram_hex(value_part)?
    };

    Ok(data)
}

/// Parse macOS nvram %-encoded value (e.g. "%01%00%00%00").
#[cfg(target_os = "macos")]
fn parse_nvram_percent_encoded(s: &str) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            let byte = u8::from_str_radix(&hex, 16)
                .with_context(|| format!("Invalid %-encoded hex: %{}", hex))?;
            result.push(byte);
        } else if c.is_ascii_whitespace() {
            continue;
        } else {
            // Plain ASCII character (not %-encoded) — treat as literal byte.
            result.push(c as u8);
        }
    }
    Ok(result)
}

/// Parse space-separated hex value (e.g. "0100 0000 0000").
#[cfg(target_os = "macos")]
fn parse_nvram_hex(s: &str) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    for token in s.split_whitespace() {
        // Each token may be a multi-byte hex string.
        if token.len() % 2 != 0 {
            bail!("Invalid hex token (odd length): {}", token);
        }
        for i in (0..token.len()).step_by(2) {
            let byte = u8::from_str_radix(&token[i..i + 2], 16)
                .with_context(|| format!("Invalid hex byte in token: {}", token))?;
            result.push(byte);
        }
    }
    Ok(result)
}

#[cfg(target_os = "macos")]
fn write_efi_variable_macos(
    name: &str,
    guid: &EfiGuid,
    data: &[u8],
    _attrs: EfiVarAttributes,
) -> Result<()> {
    let var_name = nvram_var_name(name, guid);

    // Encode data as %-escaped hex for nvram.
    let mut hex_value = String::with_capacity(data.len() * 3);
    for &byte in data {
        hex_value.push_str(&format!("%{:02x}", byte));
    }

    let assignment = format!("{}={}", var_name, hex_value);

    let output = std::process::Command::new("/usr/sbin/nvram")
        .arg(&assignment)
        .output()
        .context("Failed to execute /usr/sbin/nvram")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("nvram write failed for {}: {}", name, stderr.trim());
    }
    Ok(())
}

// ─── Boot entry operations ──────────────────────────────────────────────

/// Strip the Linux efivars 4-byte attribute header from raw variable data.
fn strip_linux_attr_header(data: &[u8]) -> &[u8] {
    #[cfg(target_os = "linux")]
    {
        if data.len() > 4 {
            &data[4..]
        } else {
            data
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        data
    }
}

/// Read the EFI boot order variable.
///
/// Returns the list of boot entry numbers in priority order.
pub fn read_boot_order() -> Result<Vec<u16>> {
    let data = read_efi_variable("BootOrder", &EfiGuid::EFI_GLOBAL_VARIABLE)?;
    let payload = strip_linux_attr_header(&data);
    if payload.len() % 2 != 0 {
        bail!(
            "BootOrder variable has odd length ({} bytes)",
            payload.len()
        );
    }
    let mut order = Vec::new();
    for chunk in payload.chunks(2) {
        order.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }
    Ok(order)
}

/// Write the EFI boot order variable.
pub fn write_boot_order(order: &[u16]) -> Result<()> {
    let mut data = Vec::with_capacity(order.len() * 2);
    for &entry in order {
        data.extend_from_slice(&entry.to_le_bytes());
    }
    write_efi_variable(
        "BootOrder",
        &EfiGuid::EFI_GLOBAL_VARIABLE,
        &data,
        EfiVarAttributes::STANDARD_BOOT,
    )
    .context("Failed to write BootOrder EFI variable")
}

/// Read a single boot entry by number.
///
/// Reads the `BootXXXX` variable and parses the EFI_LOAD_OPTION structure.
pub fn read_boot_entry(entry_num: u16) -> Result<BootEntry> {
    let var_name = format!("Boot{:04X}", entry_num);
    let data = read_efi_variable(&var_name, &EfiGuid::EFI_GLOBAL_VARIABLE)?;
    let payload = strip_linux_attr_header(&data);
    parse_load_option(entry_num, payload, &data)
}

/// Enumerate all boot entries from the EFI BootOrder variable.
///
/// Reads BootOrder, then reads and parses each BootXXXX variable.
pub fn enumerate_boot_entries() -> Result<Vec<BootEntry>> {
    let order = read_boot_order()?;
    let mut entries = Vec::new();
    for &num in &order {
        match read_boot_entry(num) {
            Ok(entry) => entries.push(entry),
            Err(e) => {
                // Log but don't fail — some boot entries may be malformed.
                tracing::warn!("Skipping boot entry {:04X}: {}", num, e);
            }
        }
    }
    Ok(entries)
}

/// Parse an EFI_LOAD_OPTION structure.
///
/// Structure layout (UEFI spec 3.1.3):
/// ```text
/// Offset  Size  Field
/// 0       4     Attributes (u32)
/// 4       2     FilePathListLength (u16)
/// 6       2     Description (UCS-2 null-terminated)
/// 6+N*2   F     FilePathList (device paths)
/// 6+N*2+F ?     OptionalData
/// ```
fn parse_load_option(entry_num: u16, data: &[u8], raw: &[u8]) -> Result<BootEntry> {
    if data.len() < 8 {
        bail!(
            "Boot entry {:04X} too short ({} bytes)",
            entry_num,
            data.len()
        );
    }

    let attributes = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let file_path_list_length = u16::from_le_bytes([data[4], data[5]]) as usize;
    let is_active = (attributes as u16) & LOAD_OPTION_ACTIVE != 0;

    // Description starts at offset 6, UCS-2 LE null-terminated.
    let mut desc_end = 6;
    while desc_end + 1 < data.len() {
        let char = u16::from_le_bytes([data[desc_end], data[desc_end + 1]]);
        if char == 0 {
            break;
        }
        desc_end += 2;
    }
    let description = if desc_end > 6 {
        let desc_ucs2 = &data[6..desc_end];
        // Convert UCS-2 LE to String (lossy).
        desc_ucs2
            .chunks(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]) as u32)
            .map(|c| char::from_u32(c).unwrap_or('?'))
            .collect()
    } else {
        String::from("(no description)")
    };

    // Device path list starts after the description null terminator.
    let dp_start = desc_end + 2;
    let dp_end = dp_start + file_path_list_length;

    let device_path = if dp_start < data.len() && dp_end <= data.len() {
        parse_device_path_list(&data[dp_start..dp_end])
    } else {
        "(invalid device path)".to_string()
    };

    // Optional data is everything after the device path list.
    let optional_data = if dp_end < data.len() {
        data[dp_end..].to_vec()
    } else {
        Vec::new()
    };

    Ok(BootEntry {
        entry_number: entry_num,
        description,
        device_path,
        optional_data,
        is_active,
        raw: raw.to_vec(),
    })
}

/// Parse an EFI device path list into a human-readable string.
fn parse_device_path_list(data: &[u8]) -> String {
    let mut paths = Vec::new();
    let mut offset = 0;

    while offset + 4 <= data.len() {
        let dp_type = data[offset] & 0x7F;
        let subtype = data[offset + 1];
        let length = u16::from_le_bytes([data[offset + 2], data[offset + 3]]) as usize;

        if length < 4 || offset + length > data.len() {
            break;
        }

        let dp_data = &data[offset + 4..offset + length];

        let desc = match dp_type {
            MEDIA_DEVICE_PATH if subtype == MEDIA_FILE_PATH_DP_SUBTYPE => {
                // File path: UCS-2 LE null-terminated string.
                parse_ucs2_path(dp_data)
            }
            MEDIA_DEVICE_PATH if subtype == MEDIA_VENDOR_DP_SUBTYPE => {
                format!("Vendor({})", hex::encode(&dp_data[..dp_data.len().min(16)]))
            }
            HARDWARE_DEVICE_PATH => format!("HW(type={}, sub={})", dp_type, subtype),
            ACPI_DEVICE_PATH => format!("ACPI(sub={})", subtype),
            MESSAGING_DEVICE_PATH => format!("Msg(sub={})", subtype),
            _ => format!("DP(type={}, sub={})", dp_type, subtype),
        };

        paths.push(desc);

        // Check for end-of-device-path.
        if dp_type == (_END_DEVICE_PATH_TYPE & 0x7F) && subtype == END_ENTIRE_DEVICE_PATH_SUBTYPE {
            break;
        }

        offset += length;
    }

    if paths.is_empty() {
        "(empty device path)".to_string()
    } else {
        paths.join(" / ")
    }
}

/// Parse a UCS-2 LE file path from device path data.
fn parse_ucs2_path(data: &[u8]) -> String {
    let mut result = String::new();
    let mut i = 0;
    while i + 1 < data.len() {
        let c = u16::from_le_bytes([data[i], data[i + 1]]);
        if c == 0 {
            break;
        }
        result.push(char::from_u32(c as u32).unwrap_or('?'));
        i += 2;
    }
    result
}

/// Modify an existing boot entry to point to a new EFI driver path.
///
/// **Safety**: Backs up the original entry before modification.
pub fn modify_boot_entry(entry_num: u16, new_path: &str) -> Result<BootEntryBackup> {
    // Backup the original entry.
    let var_name = format!("Boot{:04X}", entry_num);
    let original_data = read_efi_variable(&var_name, &EfiGuid::EFI_GLOBAL_VARIABLE)?;

    let backup = BootEntryBackup {
        entry_number: entry_num,
        original_data: original_data.clone(),
        timestamp: chrono_now_iso(),
    };

    // Parse the original entry to preserve most fields.
    let payload = strip_linux_attr_header(&original_data);
    if payload.len() < 8 {
        bail!("Boot entry {:04X} too short to modify", entry_num);
    }

    let attributes = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);

    // Find the description end.
    let mut desc_end = 6;
    while desc_end + 1 < payload.len() {
        let c = u16::from_le_bytes([payload[desc_end], payload[desc_end + 1]]);
        if c == 0 {
            break;
        }
        desc_end += 2;
    }
    let desc_null_end = desc_end + 2; // Include the null terminator.

    // Build new device path for the EFI driver.
    let new_dp = build_file_device_path(new_path);
    let mut new_entry = Vec::new();

    // Attributes (preserve original).
    new_entry.extend_from_slice(&attributes.to_le_bytes());
    // FilePathListLength.
    new_entry.extend_from_slice(&(new_dp.len() as u16).to_le_bytes());
    // Description (preserve original).
    if desc_null_end <= payload.len() {
        new_entry.extend_from_slice(&payload[6..desc_null_end]);
    }
    // New device path.
    new_entry.extend_from_slice(&new_dp);
    // End-of-device-path.
    new_entry.extend_from_slice(&[0x7F, 0xFF, 0x04, 0x00]);
    // No optional data.

    // Write the modified entry.
    // NOTE: `new_entry` contains only the EFI_LOAD_OPTION payload (no Linux
    // efivars 4-byte attribute header).  `write_efi_variable` will prepend
    // the attribute header on Linux, so we must NOT call
    // `rebuild_with_attr_header` here — that would cause a double-prepend.
    write_efi_variable(
        &var_name,
        &EfiGuid::EFI_GLOBAL_VARIABLE,
        &new_entry,
        EfiVarAttributes::STANDARD_BOOT,
    )?;

    Ok(backup)
}

/// Add a new boot entry for the given EFI driver path.
///
/// The entry is inserted at the beginning of the boot order so it runs first.
pub fn add_boot_entry(
    entry_num: u16,
    description: &str,
    driver_path: &str,
) -> Result<BootOrderResult> {
    // Backup current boot order.
    let original_order = read_boot_order()?;

    // Build the EFI_LOAD_OPTION.
    let dp = build_file_device_path(driver_path);
    let desc_ucs2 = string_to_ucs2(description);
    let mut load_option = Vec::new();

    // Attributes: ACTIVE.
    load_option.extend_from_slice(&(LOAD_OPTION_ACTIVE as u32).to_le_bytes());
    // FilePathListLength (includes end-of-path node).
    let total_dp_len = dp.len() + 4; // +4 for end-of-path.
    load_option.extend_from_slice(&(total_dp_len as u16).to_le_bytes());
    // Description (UCS-2 null-terminated).
    load_option.extend_from_slice(&desc_ucs2);
    // Device path.
    load_option.extend_from_slice(&dp);
    // End-of-device-path.
    load_option.extend_from_slice(&[0x7F, 0xFF, 0x04, 0x00]);

    // Write the boot entry variable.
    let var_name = format!("Boot{:04X}", entry_num);
    write_efi_variable(
        &var_name,
        &EfiGuid::EFI_GLOBAL_VARIABLE,
        &load_option,
        EfiVarAttributes::STANDARD_BOOT,
    )?;

    // Insert the new entry at the beginning of the boot order.
    let mut new_order = vec![entry_num];
    for &e in &original_order {
        if e != entry_num {
            new_order.push(e);
        }
    }
    write_boot_order(&new_order)?;

    // Backup the created entry.
    let entry_data = read_efi_variable(&var_name, &EfiGuid::EFI_GLOBAL_VARIABLE)?;
    let backups = vec![BootEntryBackup {
        entry_number: entry_num,
        original_data: entry_data,
        timestamp: chrono_now_iso(),
    }];

    Ok(BootOrderResult {
        original_order,
        new_order,
        backups,
    })
}

/// Restore a boot entry from a backup.
pub fn restore_boot_entry(backup: &BootEntryBackup) -> Result<()> {
    let var_name = format!("Boot{:04X}", backup.entry_number);
    // Strip the Linux efivars 4-byte attribute header (if present) to get
    // the raw EFI_LOAD_OPTION payload.  `write_efi_variable` will re-add
    // the attribute header on Linux, so we must NOT use
    // `rebuild_with_attr_header` here — that would cause a double-prepend.
    let payload = strip_linux_attr_header(&backup.original_data);

    write_efi_variable(
        &var_name,
        &EfiGuid::EFI_GLOBAL_VARIABLE,
        payload,
        EfiVarAttributes::STANDARD_BOOT,
    )
}

/// Restore boot order from a BootOrderResult.
pub fn restore_boot_order(result: &BootOrderResult) -> Result<()> {
    write_boot_order(&result.original_order)
}

/// Build an EFI device path for a file on the ESP.
///
/// The path should be in EFI notation (backslash-separated, e.g. `\EFI\Vendor\Driver.efi`).
pub fn build_file_device_path(path: &str) -> Vec<u8> {
    let mut dp = Vec::new();

    // Media device path - file path subtype.
    let path_ucs2 = string_to_ucs2(path);

    // Type=Media (0x04), Subtype=FilePath (0x04)
    dp.push(MEDIA_DEVICE_PATH);
    dp.push(MEDIA_FILE_PATH_DP_SUBTYPE);

    // Length includes the 4-byte header + UCS-2 path.
    let total_len = 4 + path_ucs2.len();
    dp.extend_from_slice(&(total_len as u16).to_le_bytes());
    dp.extend_from_slice(&path_ucs2);

    dp
}

/// Convert a Rust string to UCS-2 LE null-terminated bytes.
pub fn string_to_ucs2(s: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for c in s.chars() {
        let v = c as u16;
        bytes.push((v & 0xFF) as u8);
        bytes.push((v >> 8) as u8);
    }
    // Null terminator.
    bytes.push(0);
    bytes.push(0);
    bytes
}

/// Get the current timestamp as ISO 8601.
fn chrono_now_iso() -> String {
    // Simple timestamp without chrono dependency.
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("unix:{}", duration.as_secs())
}

/// Rebuild data with the Linux 4-byte attribute header if the original had it.
fn rebuild_with_attr_header(original: &[u8], new_payload: &[u8]) -> Vec<u8> {
    // Check if the original started with a Linux efivars attribute header.
    // Heuristic: if original has 4 extra bytes at the start that look like
    // a valid attribute mask, prepend the same attributes.
    let original_payload = strip_linux_attr_header(original);
    if original.len() > original_payload.len() {
        // Linux format: prepend 4-byte attributes from original.
        let mut out = Vec::with_capacity(4 + new_payload.len());
        out.extend_from_slice(&original[..4]); // preserve attributes
        out.extend_from_slice(new_payload);
        out
    } else {
        new_payload.to_vec()
    }
}

/// Find the next available boot entry number.
pub fn find_free_boot_entry() -> Result<u16> {
    // Scan Boot0000..BootFFFF to find an unused slot.
    for num in 0u16..=0xFFFF {
        let var_name = format!("Boot{:04X}", num);
        if read_efi_variable(&var_name, &EfiGuid::EFI_GLOBAL_VARIABLE).is_err() {
            return Ok(num);
        }
    }
    bail!("No free boot entry numbers available");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_load_option_minimal() {
        // Minimal valid EFI_LOAD_OPTION:
        // attributes(4) + path_list_length(2) + description_null(2) + end_dp(4)
        let mut data = Vec::new();
        data.extend_from_slice(&0x00000001u32.to_le_bytes()); // attributes: ACTIVE
        data.extend_from_slice(&0x0004u16.to_le_bytes()); // path length: 4 (just end node)
        data.extend_from_slice(&[0x00, 0x00]); // description: empty
        data.extend_from_slice(&[0x7F, 0xFF, 0x04, 0x00]); // end-of-device-path

        let entry = parse_load_option(0x0001, &data, &data).unwrap();
        assert_eq!(entry.entry_number, 0x0001);
        assert_eq!(entry.description, "(no description)");
        assert!(entry.is_active);
    }

    #[test]
    fn parse_load_option_with_description() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x00000001u32.to_le_bytes()); // attributes: ACTIVE
        data.extend_from_slice(&0x0004u16.to_le_bytes()); // path length: 4

        // Description: "Windows Boot Manager" in UCS-2 LE.
        let desc = "Windows Boot Manager";
        let desc_ucs2 = string_to_ucs2(desc);
        data.extend_from_slice(&desc_ucs2);

        data.extend_from_slice(&[0x7F, 0xFF, 0x04, 0x00]); // end-of-device-path

        let entry = parse_load_option(0x0000, &data, &data).unwrap();
        assert_eq!(entry.description, desc);
    }

    #[test]
    fn parse_load_option_with_file_path() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x00000001u32.to_le_bytes()); // attributes: ACTIVE

        // Build device path for \EFI\Microsoft\Boot\bootmgfw.efi
        let dp = build_file_device_path("\\EFI\\Microsoft\\Boot\\bootmgfw.efi");
        data.extend_from_slice(&((dp.len() + 4) as u16).to_le_bytes()); // path length (dp + end)

        let desc_ucs2 = string_to_ucs2("Windows Boot Manager");
        data.extend_from_slice(&desc_ucs2);
        data.extend_from_slice(&dp);
        data.extend_from_slice(&[0x7F, 0xFF, 0x04, 0x00]);

        let entry = parse_load_option(0x0001, &data, &data).unwrap();
        assert!(entry.device_path.contains("EFI"));
        assert!(entry.device_path.contains("bootmgfw.efi"));
    }

    #[test]
    fn string_to_ucs2_roundtrip() {
        let original = "\\EFI\\Test\\Driver.efi";
        let ucs2 = string_to_ucs2(original);
        assert!(ucs2.len() > 4); // at least 2 chars + null
        assert_eq!(&ucs2[ucs2.len() - 2..], &[0x00, 0x00]); // null terminator

        // Verify first character.
        let first_char = u16::from_le_bytes([ucs2[0], ucs2[1]]);
        assert_eq!(first_char, '\\' as u16);
    }

    #[test]
    fn parse_device_path_list_empty() {
        let result = parse_device_path_list(&[]);
        assert!(result.contains("empty"));
    }

    #[test]
    fn parse_device_path_file_path() {
        let path = "\\EFI\\Boot\\bootx64.efi";
        let dp = build_file_device_path(path);
        // The device path should start with Media/FilePath headers.
        assert_eq!(dp[0], MEDIA_DEVICE_PATH);
        assert_eq!(dp[1], MEDIA_FILE_PATH_DP_SUBTYPE);

        // Verify the path is in the data.
        let parsed = parse_device_path_list(&dp);
        assert!(parsed.contains("EFI"));
        assert!(parsed.contains("bootx64.efi"));
    }

    #[test]
    fn boot_order_parsing() {
        // Simulate BootOrder data: [0x0001, 0x0002, 0x0003]
        let mut data = Vec::new();
        data.extend_from_slice(&0x0001u16.to_le_bytes());
        data.extend_from_slice(&0x0002u16.to_le_bytes());
        data.extend_from_slice(&0x0003u16.to_le_bytes());

        let mut order = Vec::new();
        for chunk in data.chunks(2) {
            order.push(u16::from_le_bytes([chunk[0], chunk[1]]));
        }
        assert_eq!(order, vec![0x0001, 0x0002, 0x0003]);
    }

    #[test]
    fn build_file_device_path_structure() {
        let dp = build_file_device_path("\\EFI\\Test\\Driver.efi");
        // Verify type/subtype.
        assert_eq!(dp[0], MEDIA_DEVICE_PATH);
        assert_eq!(dp[1], MEDIA_FILE_PATH_DP_SUBTYPE);

        // Verify length field.
        let len = u16::from_le_bytes([dp[2], dp[3]]) as usize;
        assert_eq!(len, dp.len());

        // Verify the path string is present (skip 4-byte header).
        let path_data = &dp[4..];
        let first_char = u16::from_le_bytes([path_data[0], path_data[1]]);
        assert_eq!(first_char, '\\' as u16);
    }

    #[test]
    fn parse_load_option_active_flag() {
        // Active entry.
        let mut data = Vec::new();
        data.extend_from_slice(&0x00000001u32.to_le_bytes());
        data.extend_from_slice(&0x0004u16.to_le_bytes());
        data.extend_from_slice(&[0x00, 0x00]);
        data.extend_from_slice(&[0x7F, 0xFF, 0x04, 0x00]);
        let entry = parse_load_option(0, &data, &data).unwrap();
        assert!(entry.is_active);

        // Inactive entry.
        data[0] = 0;
        data[1] = 0;
        data[2] = 0;
        data[3] = 0;
        let entry = parse_load_option(0, &data, &data).unwrap();
        assert!(!entry.is_active);
    }
}
