use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{anyhow, Result};
use hmac::Mac;
use sha2::Sha256;

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// One-shot encryption with AES-256-GCM using a key and HMAC tag.
pub fn encrypt_aes_gcm(data: &[u8], key: &[u8], hmac_key: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce_bytes = rand::random::<[u8; NONCE_LEN]>();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|e| anyhow!("AES encryption failed: {e}"))?;

    let mut mac = hmac::Hmac::<Sha256>::new_from_slice(hmac_key)?;
    mac.update(&ciphertext);
    let tag = mac.finalize().into_bytes();

    let mut result = Vec::with_capacity(NONCE_LEN + TAG_LEN + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&tag);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// One-shot decryption with AES-256-GCM using a key and HMAC tag.
pub fn decrypt_aes_gcm(data: &[u8], key: &[u8], hmac_key: &[u8]) -> Result<Vec<u8>> {
    if data.len() < NONCE_LEN + TAG_LEN {
        return Err(anyhow!("Data too short for nonce and tag"));
    }
    let (nonce_bytes, rest) = data.split_at(NONCE_LEN);
    let (tag_bytes, ciphertext) = rest.split_at(TAG_LEN);

    let mut mac = hmac::Hmac::<Sha256>::new_from_slice(hmac_key)?;
    mac.update(ciphertext);
    mac.verify_slice(tag_bytes)?;

    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow!("AES decryption failed: {e}"))
}
//!
//! # Usage
//!
//! Enable the `forward-secrecy` feature in `Cargo.toml`:
//!
//! ```toml
//! [features]
//! forward-secrecy = ["common/forward-secrecy"]
//! ```
//!
//! Then wrap your stream before creating a [`CryptoSession`]:
//!
//! ```rust,ignore
//! use common::crypto::{fs_handshake_server, fs_handshake_client};
//!
//! // Server side (agent-link):
//! let session = fs_handshake_server(&mut stream, psk).await?;
//!
//! // Client side (agent outbound / console):
//! let session = fs_handshake_client(&mut stream, psk).await?;
//! ```

use crate::{CryptoSession, KEY_LEN};
use anyhow::{Context, Result};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use x25519_dalek::{EphemeralSecret, PublicKey};

const FS_INFO: &[u8] = b"orchestra-fs-v1";

/// Derive a session key from the raw X25519 shared secret and the PSK.
///
/// `salt` = SHA-256(PSK)  — binds the derived key to the pre-shared secret
/// so that a forward-secret session is still inaccessible without the PSK.
fn derive_key(shared_secret: &[u8], psk: &[u8]) -> [u8; KEY_LEN] {
    let salt: [u8; 32] = {
        use sha2::Digest;
        sha2::Sha256::digest(psk).into()
    };
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared_secret);
    let mut key = [0u8; KEY_LEN];
    hk.expand(FS_INFO, &mut key)
        .expect("HKDF-SHA256 expand into 32 bytes always succeeds");
    key
}

/// Perform the server side of the X25519 forward-secrecy handshake.
///
/// Reads the client's ephemeral public key, sends the server's ephemeral
/// public key, derives a shared session key, and returns a
/// [`CryptoSession`] bound to that key.
pub async fn fs_handshake_server<S>(stream: &mut S, psk: &[u8]) -> Result<CryptoSession>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let server_secret = EphemeralSecret::random_from_rng(OsRng);
    let server_pub = PublicKey::from(&server_secret);

    // Read the client's public key first (32 bytes).
    let mut client_pub_bytes = [0u8; 32];
    stream
        .read_exact(&mut client_pub_bytes)
        .await
        .context("FS handshake: failed to read client public key")?;

    // Send our public key.
    stream
        .write_all(server_pub.as_bytes())
        .await
        .context("FS handshake: failed to send server public key")?;
    stream.flush().await?;

    let client_pub = PublicKey::from(client_pub_bytes);
    let shared = server_secret.diffie_hellman(&client_pub);
    let key = derive_key(shared.as_bytes(), psk);
    Ok(CryptoSession::from_key(key))
}

/// Perform the client side of the X25519 forward-secrecy handshake.
///
/// Sends the client's ephemeral public key, reads the server's ephemeral
/// public key, derives a shared session key, and returns a
/// [`CryptoSession`] bound to that key.
pub async fn fs_handshake_client<S>(stream: &mut S, psk: &[u8]) -> Result<CryptoSession>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let client_secret = EphemeralSecret::random_from_rng(OsRng);
    let client_pub = PublicKey::from(&client_secret);

    // Send our public key.
    stream
        .write_all(client_pub.as_bytes())
        .await
        .context("FS handshake: failed to send client public key")?;
    stream.flush().await?;

    // Read the server's public key.
    let mut server_pub_bytes = [0u8; 32];
    stream
        .read_exact(&mut server_pub_bytes)
        .await
        .context("FS handshake: failed to read server public key")?;

    let server_pub = PublicKey::from(server_pub_bytes);
    let shared = client_secret.diffie_hellman(&server_pub);
    let key = derive_key(shared.as_bytes(), psk);
    Ok(CryptoSession::from_key(key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn handshake_produces_matching_sessions() {
        let (mut client_stream, mut server_stream) = duplex(1024);
        let psk = b"test-pre-shared-key";

        let server_fut =
            tokio::spawn(async move { fs_handshake_server(&mut server_stream, psk).await });
        let client_session = fs_handshake_client(&mut client_stream, psk).await.unwrap();
        let server_session = server_fut.await.unwrap().unwrap();

        // Encrypt with one session, decrypt with the other.
        let plaintext = b"forward secrecy works";
        let ct = client_session.encrypt(plaintext);
        let recovered = server_session.decrypt(&ct).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[tokio::test]
    async fn wrong_psk_produces_distinct_keys() {
        let (mut c1, mut s1) = duplex(1024);
        let (mut c2, mut s2) = duplex(1024);

        let srv1 = tokio::spawn(async move { fs_handshake_server(&mut s1, b"psk-A").await });
        let srv2 = tokio::spawn(async move { fs_handshake_server(&mut s2, b"psk-B").await });

        let cli1 = fs_handshake_client(&mut c1, b"psk-A").await.unwrap();
        let cli2 = fs_handshake_client(&mut c2, b"psk-B").await.unwrap();
        srv1.await.unwrap().unwrap();
        srv2.await.unwrap().unwrap();

        let ct = cli1.encrypt(b"hello");
        // Decrypting with the session from psk-B must fail.
        assert!(
            cli2.decrypt(&ct).is_err(),
            "different PSKs should produce different session keys"
        );
    }
}

//! A session-level encryption wrapper using AES-256-GCM with a random nonce.
//!
//! This module provides a simple `CryptoSession` that can encrypt and decrypt
//! byte slices. It's used by both the agent and the server to secure their
//! communication channel.
//!
//! # Key Derivation
//!
//! The session key is derived from a pre-shared secret using HKDF-SHA256. This
//! allows for a simple, memorable secret to be used to generate a
//! cryptographically strong key.
//!
//! ```rust,ignore
//! use common::crypto::CryptoSession;
//!
//! let session = CryptoSession::from_shared_secret(b"my-secret-password");
//! let plaintext = b"hello world";
//! let encrypted = session.encrypt(plaintext);
//! let decrypted = session.decrypt(&encrypted).unwrap();
//! assert_eq!(plaintext, decrypted.as_slice());
//! ```
//!
//! # Forward Secrecy
//!
//! When the `forward-secrecy` feature is enabled, an ephemeral X25519 key
//! exchange is performed at the start of each session to derive a unique
//! session key. See the `fs` submodule for details.

use aes_gcm::aead::{Aead, KeyInit, OsRng, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{anyhow, Context, Result};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

#[cfg(feature = "forward-secrecy")]
pub mod fs;

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// An established, key-agreed cryptographic session.
pub struct CryptoSession {
    cipher: Aes256Gcm,
}

impl CryptoSession {
    /// Create a new session from a raw 32-byte key.
    pub fn new(key: &[u8; KEY_LEN]) -> Self {
        Self {
            cipher: Aes256Gcm::new(key.into()),
        }
    }

    /// Create a new session by deriving a key from a shared secret.
    pub fn from_shared_secret(secret: &[u8]) -> Self {
        let hk = Hkdf::<Sha256>::new(None, secret);
        let mut key = [0u8; KEY_LEN];
        hk.expand(b"orchestra-aes-gcm-key", &mut key)
            .expect("HKDF-SHA256 expand into 32 bytes always succeeds");
        Self::new(&key)
    }

    /// Encrypt a plaintext buffer, prepending a random 12-byte nonce.
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let nonce = Nonce::from_slice(rand::random::<[u8; NONCE_LEN]>().as_slice());
        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .expect("AES-256-GCM encryption cannot fail with 12-byte nonce");

        let mut result = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        result.extend_from_slice(nonce.as_slice());
        result.extend_from_slice(&ciphertext);
        result
    }

    /// Decrypt a ciphertext buffer, assuming a 12-byte nonce prefix.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < NONCE_LEN {
            return Err(anyhow!("Ciphertext is too short to contain a nonce"));
        }
        let (nonce_bytes, cipher_bytes) = ciphertext.split_at(NONCE_LEN);
        let nonce = Nonce::from_slice(nonce_bytes);
        self.cipher
            .decrypt(nonce, cipher_bytes)
            .map_err(|e| anyhow!("Decryption failed: {}", e))
    }
}

/// One-shot encryption with AES-256-GCM using a key and HMAC tag.
pub fn encrypt_aes_gcm(data: &[u8], key: &[u8], hmac_key: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from_slice(rand::random::<[u8; NONCE_LEN]>().as_slice());
    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|e| anyhow!("AES encryption failed: {e}"))?;

    let mut mac = hmac::Hmac::<Sha256>::new_from_slice(hmac_key)?;
    mac.update(&ciphertext);
    let tag = mac.finalize().into_bytes();

    let mut result = Vec::with_capacity(NONCE_LEN + ciphertext.len() + TAG_LEN);
    result.extend_from_slice(nonce.as_slice());
    result.extend_from_slice(&tag);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// One-shot decryption with AES-256-GCM using a key and HMAC tag.
pub fn decrypt_aes_gcm(data: &[u8], key: &[u8], hmac_key: &[u8]) -> Result<Vec<u8>> {
    if data.len() < NONCE_LEN + TAG_LEN {
        return Err(anyhow!("Data too short for nonce and tag"));
    }
    let (nonce_bytes, rest) = data.split_at(NONCE_LEN);
    let (tag_bytes, ciphertext) = rest.split_at(TAG_LEN);

    let mut mac = hmac::Hmac::<Sha256>::new_from_slice(hmac_key)?;
    mac.update(ciphertext);
    mac.verify_slice(tag_bytes)?;

    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow!("AES decryption failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let session = CryptoSession::from_shared_secret(b"test secret");
        let plaintext = b"the eagle has landed";
        let encrypted = session.encrypt(plaintext);
        let decrypted = session.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let session = CryptoSession::from_shared_secret(b"test secret");
        let plaintext = b"the eagle has landed";
        let mut encrypted = session.encrypt(plaintext);
        let last_byte_idx = encrypted.len() - 1;
        encrypted[last_byte_idx] ^= 0x01; // Flip a bit
        assert!(session.decrypt(&encrypted).is_err());
    }

    #[test]
    fn truncated_ciphertext_is_rejected() {
        let session = CryptoSession::from_shared_secret(b"test secret");
        let plaintext = b"the eagle has landed";
        let encrypted = session.encrypt(plaintext);
        assert!(session.decrypt(&encrypted[..encrypted.len() - 1]).is_err());
    }

    #[test]
    fn nonces_are_unique_per_encryption() {
        let session = CryptoSession::from_shared_secret(b"test secret");
        let plaintext = b"the eagle has landed";
        let encrypted1 = session.encrypt(plaintext);
        let encrypted2 = session.encrypt(plaintext);
        assert_ne!(encrypted1, encrypted2);
        assert_ne!(&encrypted1[..12], &encrypted2[..12]); // Nonces should differ
    }

    #[test]
    fn message_serialization_roundtrip() {
        use crate::Message;
        let msg = Message::Ping;
        let bytes = msg.to_bytes().unwrap();
        let back = Message::from_bytes(&bytes).unwrap();
        assert_eq!(back, Message::Ping);
    }

    #[test]
    #[cfg(feature = "forward-secrecy")]
    fn handshake_produces_matching_sessions() {
        use tokio::io::duplex;

        let psk = b"test psk";
        let (mut client, mut server) = duplex(128);

        let client_task = tokio::spawn(async move {
            fs::fs_handshake_client(&mut client, psk).await.unwrap()
        });
        let server_task = tokio::spawn(async move {
            fs::fs_handshake_server(&mut server, psk).await.unwrap()
        });

        let (client_session, server_session) =
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let c = client_task.await.unwrap();
                let s = server_task.await.unwrap();
                (c, s)
            });

        let plaintext = b"test message";
        let encrypted = client_session.encrypt(plaintext);
        let decrypted = server_session.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    #[cfg(feature = "forward-secrecy")]
    fn wrong_psk_produces_distinct_keys() {
        use tokio::io::duplex;

        let psk1 = b"test psk 1";
        let psk2 = b"test psk 2";
        let (mut client, mut server) = duplex(128);

        let client_task = tokio::spawn(async move {
            fs::fs_handshake_client(&mut client, psk1).await.unwrap()
        });
        let server_task = tokio::spawn(async move {
            fs::fs_handshake_server(&mut server, psk2).await.unwrap()
        });

        let (client_session, server_session) =
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let c = client_task.await.unwrap();
                let s = server_task.await.unwrap();
                (c, s)
            });

        let plaintext = b"test message";
        let encrypted = client_session.encrypt(plaintext);
        assert!(server_session.decrypt(&encrypted).is_err());
    }
}
