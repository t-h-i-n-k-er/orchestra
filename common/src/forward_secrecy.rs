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
//! * The PSK authenticates the exchanged public keys via HMAC-SHA256, binding
//!   the key exchange to the pre-shared secret.  Only parties holding the PSK
//!   can produce or verify valid MACs, preventing MITM even if the TLS channel
//!   is somehow intercepted.
//! * The PSK is used as the HKDF salt, meaning a future PSK compromise does
//!   **not** expose past session ciphertexts (those require the ephemeral
//!   private keys which are securely erased after the exchange).
//!
//! **Protocol**
//!
//! Each side sends a 64-byte message: the 32-byte X25519 public key followed
//! by a 32-byte HMAC-SHA256 tag.  The HMAC is computed as:
//!
//! ```text
//! tag = HMAC-SHA256(key=psk, msg=local_pubkey || remote_pubkey)
//! ```
//!
//! The sender orders the public keys canonically so both sides compute the
//! same tag: the **client's** public key comes first in the concatenation.
//!
//! After both sides have verified the peer's tag, session key derivation
//! proceeds as before:
//!
//! ```text
//! session_key = HKDF-SHA256(ikm=ECDH_shared, salt=psk, info="orchestra-forward-secret-v1")[..32]
//! ```

use crate::{CryptoSession, KEY_LEN};
use anyhow::Result;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use x25519_dalek::{EphemeralSecret, PublicKey};

/// HMAC-SHA256 type alias.
type HmacSha256 = Hmac<Sha256>;

/// Size of the HMAC-SHA256 tag appended to each public key on the wire.
const HMAC_TAG_LEN: usize = 32;

/// Wire message: 32-byte public key + 32-byte HMAC tag.
const MSG_LEN: usize = 32 + HMAC_TAG_LEN;

/// Compute the authentication tag: `HMAC-SHA256(psk, client_pub || server_pub)`.
///
/// The ordering is canonical — client pubkey always first — so both sides
/// produce the same tag.
fn compute_auth_tag(psk: &[u8], client_pub: &[u8; 32], server_pub: &[u8; 32]) -> [u8; HMAC_TAG_LEN] {
    let mut mac = HmacSha256::new_from_slice(psk)
        .expect("HMAC accepts any key length");
    mac.update(client_pub);
    mac.update(server_pub);
    mac.finalize().into_bytes().into()
}

/// Perform an X25519 ECDH key exchange over `stream`, authenticate the public
/// keys with the PSK via HMAC-SHA256, and derive a per-session
/// [`CryptoSession`].
///
/// Set `is_client = true` on the connecting side (sends its public key first)
/// and `is_client = false` on the accepting side (reads first, then sends).
///
/// # Errors
///
/// Returns an error if the peer's HMAC tag does not verify, indicating the
/// peer does not hold the correct PSK (possible MITM).
pub async fn negotiate_session_key<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    psk: &[u8],
    is_client: bool,
) -> Result<CryptoSession> {
    let our_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
    let our_public = PublicKey::from(&our_secret);
    let our_pub_bytes: [u8; 32] = *our_public.as_bytes();

    // ── Exchange public keys with HMAC authentication ───────────────────
    //
    // Wire format (each direction): [ public_key (32B) | hmac_tag (32B) ]
    //
    // The HMAC covers both public keys in canonical order:
    //   HMAC(psk, client_pub || server_pub)
    //
    // Because each side needs to know the *other* side's public key before
    // it can compute its own tag, we split the exchange:
    //   1. Sender: sends only the public key (32 bytes).
    //   2. Receiver: reads the sender's public key, now knows both keys,
    //      computes its tag, and sends its full message (pubkey + tag).
    //   3. Sender: reads the receiver's full message, verifies the tag,
    //      then sends its own tag.

    let peer_pub_bytes: [u8; 32] = if is_client {
        // Step 1: Client sends its public key first (no tag yet — we need
        // the server's public key to compute the tag).
        stream.write_all(&our_pub_bytes).await?;

        // Step 2: Read server's full message (pubkey + tag).
        let mut srv_msg = [0u8; MSG_LEN];
        stream.read_exact(&mut srv_msg).await?;
        let mut srv_pub = [0u8; 32];
        srv_pub.copy_from_slice(&srv_msg[..32]);
        let srv_tag: &[u8] = &srv_msg[32..MSG_LEN];

        // Verify server's tag.
        let expected_tag = compute_auth_tag(psk, &our_pub_bytes, &srv_pub);
        if !hmac_verify(&expected_tag, srv_tag) {
            anyhow::bail!("forward secrecy: server HMAC verification failed — PSK mismatch or MITM");
        }

        // Step 3: Send our tag (client's tag).
        let our_tag = compute_auth_tag(psk, &our_pub_bytes, &srv_pub);
        stream.write_all(&our_tag).await?;

        srv_pub
    } else {
        // Step 1: Read client's public key (no tag yet).
        let mut cli_pub = [0u8; 32];
        stream.read_exact(&mut cli_pub).await?;

        // Step 2: Server sends its full message (pubkey + tag).
        let our_tag = compute_auth_tag(psk, &cli_pub, &our_pub_bytes);
        let mut srv_msg = [0u8; MSG_LEN];
        srv_msg[..32].copy_from_slice(&our_pub_bytes);
        srv_msg[32..MSG_LEN].copy_from_slice(&our_tag);
        stream.write_all(&srv_msg).await?;

        // Step 3: Read client's tag and verify it.
        let mut cli_tag = [0u8; HMAC_TAG_LEN];
        stream.read_exact(&mut cli_tag).await?;
        let expected_tag = compute_auth_tag(psk, &cli_pub, &our_pub_bytes);
        if !hmac_verify(&expected_tag, &cli_tag) {
            anyhow::bail!("forward secrecy: client HMAC verification failed — PSK mismatch or MITM");
        }

        cli_pub
    };

    // ── Key derivation (unchanged) ──────────────────────────────────────
    let peer_public = PublicKey::from(peer_pub_bytes);
    let shared = our_secret.diffie_hellman(&peer_public);

    // HKDF: salt = PSK, IKM = ECDH shared secret.
    let h = Hkdf::<Sha256>::new(Some(psk), shared.as_bytes());
    let mut session_key = [0u8; KEY_LEN];
    h.expand(b"orchestra-forward-secret-v1", &mut session_key)
        .map_err(|_| anyhow::anyhow!("HKDF expand failed (output too long)") )?;

    Ok(CryptoSession::from_key(session_key))
}

/// Constant-time HMAC comparison to prevent timing side channels.
fn hmac_verify(expected: &[u8; HMAC_TAG_LEN], actual: &[u8]) -> bool {
    use std::cmp::Ordering;
    let mut diff: u8 = 0;
    for (a, b) in expected.iter().zip(actual.iter()) {
        diff |= a ^ b;
    }
    // Also guard against length mismatches (should never happen with our
    // fixed-size slices, but defensive).
    match actual.len().cmp(&HMAC_TAG_LEN) {
        Ordering::Equal => diff == 0,
        _ => false,
    }
}
