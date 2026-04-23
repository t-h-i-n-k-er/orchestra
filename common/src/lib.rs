//! Shared protocol, error, and cryptographic primitives for the Orchestra
//! console <-> agent channel.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Length in bytes of the AES-256 key used by [`CryptoSession`].
pub const KEY_LEN: usize = 32;
/// Length in bytes of the AES-GCM nonce prepended to each ciphertext.
pub const NONCE_LEN: usize = 12;

pub mod audit;
pub mod config;
pub mod normalized_transport;
pub mod tls_transport;

pub use audit::{AuditEvent, Outcome};

/// Top-level wire message exchanged between a console and an agent.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Message {
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
    },
    /// Push a signed, AES-GCM-encrypted capability module to the agent.
    /// `encrypted_blob` is the same wire format produced by
    /// `CryptoSession::encrypt`.
    ModulePush {
        module_name: String,
        version: String,
        encrypted_blob: Vec<u8>,
    },
    AuditLog(AuditEvent),
    Shutdown,
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
}

impl CryptoSession {
    /// Build a session by hashing `pre_shared_secret` with SHA-256 to produce
    /// the 32-byte AES key.
    pub fn from_shared_secret(pre_shared_secret: &[u8]) -> Self {
        let hk = hkdf::Hkdf::<Sha256>::new(None, pre_shared_secret);
        let mut key_bytes = [0u8; KEY_LEN];
        hk.expand(b"orchestra-aes-gcm", &mut key_bytes)
            .expect("HKDF-SHA256 expand must succeed");
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        Self {
            cipher: Aes256Gcm::new(key),
        }
    }

    /// Build a session directly from a 32-byte key.
    pub fn from_key(key_bytes: [u8; KEY_LEN]) -> Self {
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        Self {
            cipher: Aes256Gcm::new(key),
        }
    }

    /// Encrypt `plaintext` and return `nonce || ciphertext_with_tag`.
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .expect("AES-GCM encryption is infallible for valid inputs");

        let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        out
    }

    /// Decrypt a buffer produced by [`Self::encrypt`].
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if ciphertext.len() < NONCE_LEN {
            return Err(CryptoError::Truncated);
        }
        let (nonce_bytes, body) = ciphertext.split_at(NONCE_LEN);
        let nonce = Nonce::from_slice(nonce_bytes);
        self.cipher
            .decrypt(nonce, body)
            .map_err(|_| CryptoError::AuthenticationFailed)
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
        let session = CryptoSession::from_shared_secret(b"orchestra-dev-secret");
        let plaintext = b"hello orchestra";
        let ct = session.encrypt(plaintext);
        assert!(ct.len() > NONCE_LEN);
        let pt = session.decrypt(&ct).expect("decrypt");
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn nonces_are_unique_per_encryption() {
        let session = CryptoSession::from_shared_secret(b"k");
        let a = session.encrypt(b"same");
        let b = session.encrypt(b"same");
        assert_ne!(a[..NONCE_LEN], b[..NONCE_LEN]);
        assert_ne!(a, b);
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let session = CryptoSession::from_shared_secret(b"k");
        let mut ct = session.encrypt(b"payload");
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        let err = session.decrypt(&ct).unwrap_err();
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
        let bytes = serde_json::to_vec(&msg).unwrap();
        let back: Message = serde_json::from_slice(&bytes).unwrap();
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
