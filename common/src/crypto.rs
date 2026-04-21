//! Optional ephemeral X25519 key exchange for forward secrecy.
//!
//! # Protocol
//!
//! After the TCP connection is established (and TLS, if enabled), both peers
//! perform a one-shot Diffie-Hellman step **before** any application-level
//! [`Message`] is sent:
//!
//! ```text
//! Client                                Server
//!   │  ── ephemeral_pub_c (32 bytes) ──▶  │
//!   │  ◀─ ephemeral_pub_s (32 bytes) ──   │
//!   │                                      │
//!   │   session_key = HKDF-SHA256(         │
//!   │     ikm  = X25519(priv, peer_pub),   │
//!   │     salt = SHA-256(PSK),             │
//!   │     info = b"orchestra-fs-v1"        │
//!   │   )                                  │
//! ```
//!
//! Both sides derive the same 32-byte `session_key`, which is used to
//! construct a fresh [`CryptoSession`] for the connection.  The PSK is still
//! required to connect; it merely becomes a salt rather than the direct key,
//! so a passive observer who records ciphertext and later learns the PSK
//! cannot retroactively decrypt past sessions.
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
