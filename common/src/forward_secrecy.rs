//! Per-session key derivation via X25519 ECDH authenticated by the pre-shared
//! key (PSK).
//!
//! When the `forward-secrecy` feature is enabled, both sides of the connection
//! perform an ephemeral X25519 Diffie–Hellman exchange immediately after the
//! TLS handshake.  The resulting shared secret is mixed with the PSK via
//! HKDF-SHA256 to derive the per-session AES-256-GCM key used by
//! [`crate::CryptoSession`].
//!
//! **Security properties**
//!
//! * The PSK is used as the HKDF salt, meaning a future PSK compromise does
//!   **not** expose past session ciphertexts (those require the ephemeral
//!   private keys which are securely erased after the exchange).
//! * The exchange is carried inside the established TLS channel, so an
//!   on-path attacker cannot observe or tamper with the ephemeral public keys.
//!
//! **Protocol**
//!
//! Client sends its 32-byte X25519 public key, then reads the server's 32-byte
//! public key.  Server does the inverse.  Both sides then compute:
//!
//! ```text
//! session_key = HKDF-SHA256(ikm=ECDH_shared, salt=psk, info="orchestra-forward-secret-v1")[..32]
//! ```

use crate::{CryptoSession, KEY_LEN};
use anyhow::Result;
use hkdf::Hkdf;
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use x25519_dalek::{EphemeralSecret, PublicKey};

/// Perform an X25519 ECDH key exchange over `stream` and derive a per-session
/// [`CryptoSession`] authenticated by `psk`.
///
/// Set `is_client = true` on the connecting side (sends its public key first)
/// and `is_client = false` on the accepting side (reads first, then sends).
pub async fn negotiate_session_key<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    psk: &[u8],
    is_client: bool,
) -> Result<CryptoSession> {
    let our_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
    let our_public = PublicKey::from(&our_secret);

    let peer_pub_bytes: [u8; 32] = if is_client {
        // Client sends its public key first, then reads the server's.
        stream.write_all(our_public.as_bytes()).await?;
        let mut buf = [0u8; 32];
        stream.read_exact(&mut buf).await?;
        buf
    } else {
        // Server reads the client's public key first, then sends its own.
        let mut buf = [0u8; 32];
        stream.read_exact(&mut buf).await?;
        stream.write_all(our_public.as_bytes()).await?;
        buf
    };

    let peer_public = PublicKey::from(peer_pub_bytes);
    let shared = our_secret.diffie_hellman(&peer_public);

    // HKDF: salt = PSK, IKM = ECDH shared secret.
    let h = Hkdf::<Sha256>::new(Some(psk), shared.as_bytes());
    let mut session_key = [0u8; KEY_LEN];
    h.expand(b"orchestra-forward-secret-v1", &mut session_key)
        .map_err(|_| anyhow::anyhow!("HKDF expand failed (output too long)"))?;

    Ok(CryptoSession::from_key(session_key))
}
