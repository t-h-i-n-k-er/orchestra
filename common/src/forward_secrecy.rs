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
//! * The PSK is used to derive a domain-separated HMAC key (via HKDF with
//!   info [`hkdf_info::FS_HMAC`]) that authenticates the exchanged
//!   public keys, binding the key exchange to the pre-shared secret.  Only
//!   parties holding the PSK can produce or verify valid MACs, preventing
//!   MITM even if the TLS channel is somehow intercepted.
//! * A second sub-key derived from the PSK (info [`hkdf_info::FS_SALT`])
//!   is used as the HKDF salt, meaning a future PSK compromise does
//!   **not** expose past session ciphertexts (those require the ephemeral
//!   private keys which are securely erased after the exchange).
//!
//! **Protocol**
//!
//! Each side sends a 64-byte message: the 32-byte X25519 public key followed
//! by a 32-byte HMAC-SHA256 tag.  The HMAC is computed as:
//!
//! ```text
//! hmac_key = HKDF-Expand(ikm=psk, info=hkdf_info::FS_HMAC)
//! tag = HMAC-SHA256(key=hmac_key, msg=local_pubkey || remote_pubkey)
//! ```
//!
//! P1-04: The HMAC key is now a domain-separated sub-key derived from the PSK
//! via HKDF, not the raw PSK.  This prevents cross-protocol attacks from
//! reusing the same key material for different purposes.
//!
//! The sender orders the public keys canonically so both sides compute the
//! same tag: the **client's** public key comes first in the concatenation.
//!
//! After both sides have verified the peer's tag, session key derivation
//! proceeds:
//!
//! ```text
//! fs_salt  = HKDF-Expand(ikm=psk, info=hkdf_info::FS_SALT)
//! session_key = HKDF-SHA256(ikm=ECDH_shared, salt=fs_salt, info=hkdf_info::FS_SESSION)[..32]
//! ```

use crate::{CryptoSession, LockedSecret, KEY_LEN};
use anyhow::Result;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use x25519_dalek::{EphemeralSecret, PublicKey};

/// HMAC-SHA256 type alias.
type HmacSha256 = Hmac<Sha256>;

/// Size of the HMAC-SHA256 tag appended to each public key on the wire.
const HMAC_TAG_LEN: usize = 32;

/// Wire message: 32-byte public key + 32-byte HMAC tag.
const MSG_LEN: usize = 32 + HMAC_TAG_LEN;

// ── P1-04: Domain-separated sub-key derivation ─────────────────────────────
//
// The PSK was previously used directly as (1) the HMAC-SHA256 key for ECDH
// authentication, (2) the HKDF IKM for session-key derivation in
// CryptoSession::from_shared_secret, and (3) the HKDF salt in forward-secrecy
// negotiation.  Using the same key material for multiple cryptographic
// purposes without domain separation is a cryptographic misuse.
//
// We now derive two purpose-specific sub-keys from the PSK via HKDF-Expand
// with distinct info strings so the keys are cryptographically independent.

/// Derive the HMAC authentication sub-key from the PSK.
fn derive_hmac_key(psk: &[u8]) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(None, psk);
    let mut key = [0u8; 32];
    hkdf.expand(crate::hkdf_info::FS_HMAC, &mut key)
        .expect("HKDF expand for HMAC key must succeed");
    key
}

/// Derive the HKDF salt sub-key from the PSK for forward-secrecy key
/// derivation.  This replaces using the raw PSK as the HKDF salt.
fn derive_fs_salt(psk: &[u8]) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(None, psk);
    let mut salt = [0u8; 32];
    hkdf.expand(crate::hkdf_info::FS_SALT, &mut salt)
        .expect("HKDF expand for FS salt must succeed");
    salt
}

/// Compute the authentication tag: `HMAC-SHA256(derived_hmac_key, client_pub || server_pub)`.
///
/// P1-04: The HMAC key is now a domain-separated sub-key derived from the PSK
/// via HKDF, not the raw PSK itself.  The ordering is canonical — client pubkey
/// always first — so both sides produce the same tag.
fn compute_auth_tag(
    psk: &[u8],
    client_pub: &[u8; 32],
    server_pub: &[u8; 32],
) -> [u8; HMAC_TAG_LEN] {
    let hmac_key = derive_hmac_key(psk);
    let mut mac = HmacSha256::new_from_slice(&hmac_key).expect("HMAC accepts any key length");
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
    // Copy the PSK into a zeroizable buffer so we can wipe it after key
    // derivation.  The caller's `String` or `Vec` is *not* modified.
    let mut psk_buf = psk.to_vec();

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
        let expected_tag = compute_auth_tag(&psk_buf, &our_pub_bytes, &srv_pub);
        if !hmac_verify(&expected_tag, srv_tag) {
            anyhow::bail!(
                "forward secrecy: server HMAC verification failed — PSK mismatch or MITM"
            );
        }

        // Step 3: Send our tag (client's tag).
        let our_tag = compute_auth_tag(&psk_buf, &our_pub_bytes, &srv_pub);
        stream.write_all(&our_tag).await?;

        srv_pub
    } else {
        // Step 1: Read client's public key (no tag yet).
        let mut cli_pub = [0u8; 32];
        stream.read_exact(&mut cli_pub).await?;

        // Step 2: Server sends its full message (pubkey + tag).
        let our_tag = compute_auth_tag(&psk_buf, &cli_pub, &our_pub_bytes);
        let mut srv_msg = [0u8; MSG_LEN];
        srv_msg[..32].copy_from_slice(&our_pub_bytes);
        srv_msg[32..MSG_LEN].copy_from_slice(&our_tag);
        stream.write_all(&srv_msg).await?;

        // Step 3: Read client's tag and verify it.
        let mut cli_tag = [0u8; HMAC_TAG_LEN];
        stream.read_exact(&mut cli_tag).await?;
        let expected_tag = compute_auth_tag(&psk_buf, &cli_pub, &our_pub_bytes);
        if !hmac_verify(&expected_tag, &cli_tag) {
            anyhow::bail!(
                "forward secrecy: client HMAC verification failed — PSK mismatch or MITM"
            );
        }

        cli_pub
    };

    // ── Key derivation ──────────────────────────────────────────────────
    let peer_public = PublicKey::from(peer_pub_bytes);
    let shared = our_secret.diffie_hellman(&peer_public);

    // P1-04: Use a domain-separated sub-key as the HKDF salt instead of
    // the raw PSK, so the PSK is never used directly as a cryptographic
    // parameter in more than one context.
    let fs_salt = derive_fs_salt(&psk_buf);

    // HKDF: salt = derived FS salt, IKM = ECDH shared secret.
    let h = Hkdf::<Sha256>::new(Some(&fs_salt), shared.as_bytes());

    // Zeroize the local PSK copy now that key derivation is complete.
    use zeroize::Zeroize;
    psk_buf.zeroize();
    let mut session_key = [0u8; KEY_LEN];
    h.expand(crate::hkdf_info::FS_SESSION, &mut session_key)
        .map_err(|_| anyhow::anyhow!("HKDF expand failed (output too long)"))?;

    Ok(CryptoSession::from_key(session_key))
}

/// Synchronous variant of [`negotiate_session_key`] for transports that
/// perform blocking I/O (e.g. Windows named pipes opened via NT syscalls).
///
/// The protocol is identical — only the I/O is synchronous.  The caller
/// must wrap the invocation in [`tokio::task::spawn_blocking`] when called
/// from an async context.
pub fn negotiate_session_key_blocking<S: std::io::Read + std::io::Write>(
    stream: &mut S,
    psk: &[u8],
    is_client: bool,
) -> Result<CryptoSession> {
    let mut psk_buf = psk.to_vec();

    let our_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
    let our_public = PublicKey::from(&our_secret);
    let our_pub_bytes: [u8; 32] = *our_public.as_bytes();

    let peer_pub_bytes: [u8; 32] = if is_client {
        // Step 1: Client sends its public key first.
        stream.write_all(&our_pub_bytes)?;
        stream.flush()?;

        // Step 2: Read server's full message (pubkey + tag).
        let mut srv_msg = [0u8; MSG_LEN];
        stream.read_exact(&mut srv_msg)?;
        let mut srv_pub = [0u8; 32];
        srv_pub.copy_from_slice(&srv_msg[..32]);
        let srv_tag: &[u8] = &srv_msg[32..MSG_LEN];

        // Verify server's tag.
        let expected_tag = compute_auth_tag(&psk_buf, &our_pub_bytes, &srv_pub);
        if !hmac_verify(&expected_tag, srv_tag) {
            anyhow::bail!(
                "forward secrecy: server HMAC verification failed — PSK mismatch or MITM"
            );
        }

        // Step 3: Send our tag.
        let our_tag = compute_auth_tag(&psk_buf, &our_pub_bytes, &srv_pub);
        stream.write_all(&our_tag)?;
        stream.flush()?;

        srv_pub
    } else {
        // Step 1: Read client's public key.
        let mut cli_pub = [0u8; 32];
        stream.read_exact(&mut cli_pub)?;

        // Step 2: Server sends its full message (pubkey + tag).
        let our_tag = compute_auth_tag(&psk_buf, &cli_pub, &our_pub_bytes);
        let mut srv_msg = [0u8; MSG_LEN];
        srv_msg[..32].copy_from_slice(&our_pub_bytes);
        srv_msg[32..MSG_LEN].copy_from_slice(&our_tag);
        stream.write_all(&srv_msg)?;
        stream.flush()?;

        // Step 3: Read client's tag and verify it.
        let mut cli_tag = [0u8; HMAC_TAG_LEN];
        stream.read_exact(&mut cli_tag)?;
        let expected_tag = compute_auth_tag(&psk_buf, &cli_pub, &our_pub_bytes);
        if !hmac_verify(&expected_tag, &cli_tag) {
            anyhow::bail!(
                "forward secrecy: client HMAC verification failed — PSK mismatch or MITM"
            );
        }

        cli_pub
    };

    // Key derivation (identical to async version).
    let peer_public = PublicKey::from(peer_pub_bytes);
    let shared = our_secret.diffie_hellman(&peer_public);
    let fs_salt = derive_fs_salt(&psk_buf);
    let h = Hkdf::<Sha256>::new(Some(&fs_salt), shared.as_bytes());

    use zeroize::Zeroize;
    psk_buf.zeroize();

    let mut session_key = [0u8; KEY_LEN];
    h.expand(crate::hkdf_info::FS_SESSION, &mut session_key)
        .map_err(|_| anyhow::anyhow!("HKDF expand failed (output too long)"))?;

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

// ── P1-21: PSK Rotation ─────────────────────────────────────────────────────
//
// The PSK is used for the lifetime of the deployment without rotation.
// If the PSK is compromised, all past and future sessions are at risk.
// The PSK rotation mechanism derives a new PSK from the old one using HKDF
// with a monotonic rotation counter, ensuring forward secrecy at the PSK
// level.
//
// ## Protocol
//
// 1. After N sessions or M hours (configurable), the server derives a new
//    PSK: `new_psk = HKDF(ikm=old_psk, info=hkdf_info::PSK_ROTATION::<counter>)`.
// 2. The new PSK is distributed to connected agents via the existing
//    encrypted channel (inside a `Command::RotatePsk` message).
// 3. Both sides update their stored PSK atomically.
// 4. Future session negotiations use the new PSK.
//
// Because the rotation is one-way (HKDF is not invertible), compromise of
// the current PSK does not allow recovery of previous PSKs.

/// Default number of sessions after which PSK rotation is triggered.
pub const PSK_ROTATION_SESSIONS: u64 = 1000;

/// Default interval (in seconds) after which PSK rotation is triggered.
pub const PSK_ROTATION_INTERVAL_SECS: u64 = 3600 * 24; // 24 hours

/// Derive a rotated PSK from the old PSK and a monotonic rotation counter.
///
/// Uses HKDF-SHA256 with domain-separated info string so each rotation
/// produces a cryptographically independent key.  The derivation is one-way:
/// knowing `new_psk` does not allow recovering `old_psk`.
///
/// ```text
/// new_psk = HKDF-Expand(ikm=old_psk, salt=rotation_counter_be, info=hkdf_info::PSK_ROTATION)[:32]
/// ```
pub fn derive_rotated_psk(old_psk: &[u8], rotation_counter: u64) -> [u8; 32] {
    let salt = rotation_counter.to_be_bytes();
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), old_psk);
    let mut new_psk = [0u8; 32];
    hkdf.expand(crate::hkdf_info::PSK_ROTATION, &mut new_psk)
        .expect("HKDF expand for PSK rotation must succeed");
    new_psk
}

/// State machine for PSK rotation tracking.
///
/// Thread-safe: the session counter uses atomic operations and the timestamp
/// is protected by a Mutex (only consulted on rotation checks, not on every
/// session).
pub struct PskRotationState {
    /// Monotonic rotation counter — incremented each time a new PSK is derived.
    rotation_counter: AtomicU64,
    /// Number of sessions established since the last rotation.
    sessions_since_rotation: AtomicU64,
    /// Instant of the last rotation (protected by Mutex to avoid
    /// `Instant` not being `Send` on some platforms).
    last_rotation: Mutex<Instant>,
    /// The current PSK, wrapped in LockedSecret for mlock + zeroize-on-drop.
    current_psk: Mutex<LockedSecret>,
    /// The previous PSK, kept during the transition window so that
    /// in-flight session negotiations can still complete.
    previous_psk: Mutex<Option<LockedSecret>>,
    /// Instant when the current PSK was installed.  Used to expire
    /// `previous_psk` after the transition window.
    rotation_time: Mutex<Instant>,
    /// How long `previous_psk` is retained after a rotation before
    /// being zeroized and dropped.
    transition_window: Duration,
    /// Threshold: rotate after this many sessions.
    session_threshold: u64,
    /// Threshold: rotate after this many seconds have elapsed.
    interval_secs: u64,
}

impl PskRotationState {
    /// Create a new rotation state with the given initial PSK and thresholds.
    /// Default transition window: the previous PSK is retained for 5 minutes
    /// after a rotation so that in-flight negotiations can complete.
    pub const DEFAULT_TRANSITION_WINDOW_SECS: u64 = 300; // 5 minutes

    pub fn new(initial_psk: &[u8], session_threshold: u64, interval_secs: u64) -> Self {
        Self {
            rotation_counter: AtomicU64::new(0),
            sessions_since_rotation: AtomicU64::new(0),
            last_rotation: Mutex::new(Instant::now()),
            current_psk: Mutex::new(LockedSecret::new(initial_psk)),
            previous_psk: Mutex::new(None),
            rotation_time: Mutex::new(Instant::now()),
            transition_window: Duration::from_secs(Self::DEFAULT_TRANSITION_WINDOW_SECS),
            session_threshold,
            interval_secs,
        }
    }

    /// Create with default thresholds (1000 sessions or 24 hours).
    pub fn new_default(initial_psk: &[u8]) -> Self {
        Self::new(
            initial_psk,
            PSK_ROTATION_SESSIONS,
            PSK_ROTATION_INTERVAL_SECS,
        )
    }

    /// Record that a new session has been established.
    /// Returns `true` if a PSK rotation should be triggered.
    pub fn record_session(&self) -> bool {
        let count = self
            .sessions_since_rotation
            .fetch_add(1, AtomicOrdering::Relaxed)
            + 1;

        // Check session threshold.
        if count >= self.session_threshold {
            return true;
        }

        // Check time threshold.
        if let Ok(last) = self.last_rotation.lock() {
            if last.elapsed().as_secs() >= self.interval_secs {
                return true;
            }
        }

        false
    }

    /// Perform PSK rotation: derive a new PSK from the current one using
    /// HKDF with the rotation counter.  Returns the new rotation counter.
    ///
    /// The current PSK is moved to `previous_psk` for the transition window
    /// so that in-flight negotiations can still complete.
    ///
    /// The caller is responsible for distributing the new PSK to connected
    /// agents via the encrypted channel.
    pub fn rotate(&self) -> u64 {
        let new_counter = self.rotation_counter.fetch_add(1, AtomicOrdering::SeqCst) + 1;

        let mut new_psk_bytes = {
            let psk = self.current_psk.lock().unwrap();
            derive_rotated_psk(psk.as_bytes(), new_counter)
        };

        // Move current PSK to previous (for transition window), then install
        // the new PSK.  LockedSecret zeroizes the old previous_psk on drop.
        {
            let mut prev = self.previous_psk.lock().unwrap();
            let cur = self.current_psk.lock().unwrap();
            *prev = Some(LockedSecret::new(cur.as_bytes()));
            drop(cur);
            let mut cur = self.current_psk.lock().unwrap();
            *cur = LockedSecret::new(&new_psk_bytes);
        }

        // Record the rotation timestamp for transition-window expiry.
        if let Ok(mut rt) = self.rotation_time.lock() {
            *rt = Instant::now();
        }

        // Reset session counter and timestamp.
        self.sessions_since_rotation
            .store(0, AtomicOrdering::Relaxed);
        if let Ok(mut last) = self.last_rotation.lock() {
            *last = Instant::now();
        }

        log::info!(
            "PSK rotated: counter={}, new_psk_prefix={:02x}{:02x}...",
            new_counter,
            new_psk_bytes[0],
            new_psk_bytes[1]
        );

        // Zeroize the local copy of the new PSK bytes.
        use zeroize::Zeroize;
        new_psk_bytes.zeroize();

        new_counter
    }

    /// Get a reference to the current PSK bytes for session negotiation.
    ///
    /// The returned guard keeps the Mutex locked so the PSK cannot be
    /// rotated while a negotiation is in progress.
    pub fn current_psk(&self) -> std::sync::MutexGuard<'_, LockedSecret> {
        self.current_psk.lock().unwrap()
    }

    /// Get the current rotation counter.
    pub fn rotation_counter(&self) -> u64 {
        self.rotation_counter.load(AtomicOrdering::Relaxed)
    }

    /// Apply an externally-received PSK rotation (e.g. from the server).
    /// Increments the rotation counter, moves the current PSK to
    /// `previous_psk` for the transition window, and installs the new PSK.
    pub fn apply_rotation(&self, new_psk: &[u8], expected_counter: u64) -> bool {
        let current = self.rotation_counter.load(AtomicOrdering::SeqCst);
        if expected_counter <= current {
            log::warn!(
                "ignoring PSK rotation with stale counter {} (current: {})",
                expected_counter,
                current
            );
            return false;
        }

        // Move current PSK to previous for transition window.
        {
            let mut prev = self.previous_psk.lock().unwrap();
            let cur = self.current_psk.lock().unwrap();
            *prev = Some(LockedSecret::new(cur.as_bytes()));
            drop(cur);
            let mut cur = self.current_psk.lock().unwrap();
            *cur = LockedSecret::new(new_psk);
        }

        // Record rotation timestamp.
        if let Ok(mut rt) = self.rotation_time.lock() {
            *rt = Instant::now();
        }

        self.rotation_counter
            .store(expected_counter, AtomicOrdering::SeqCst);
        self.sessions_since_rotation
            .store(0, AtomicOrdering::Relaxed);
        if let Ok(mut last) = self.last_rotation.lock() {
            *last = Instant::now();
        }

        log::info!("PSK rotation applied: counter={}", expected_counter);
        true
    }

    /// Verify an authentication tag against both the current and (if still
    /// within the transition window) previous PSK.
    ///
    /// Returns `Ok(())` if verification succeeds with either PSK, or an
    /// error if neither PSK verifies.  A successful verification with the
    /// previous PSK logs a warning that a stale PSK was used.
    ///
    /// If the transition window has expired, `previous_psk` is cleared to
    /// `None` (zeroized on drop).
    pub fn verify_auth_tag(
        &self,
        client_pub: &[u8; 32],
        server_pub: &[u8; 32],
        received_tag: &[u8],
    ) -> Result<()> {
        // Expire previous_psk if the transition window has elapsed.
        {
            let rt = self.rotation_time.lock().unwrap();
            if rt.elapsed() > self.transition_window {
                drop(rt);
                let mut prev = self.previous_psk.lock().unwrap();
                if prev.is_some() {
                    log::info!("PSK transition window expired — clearing previous PSK");
                    *prev = None;
                }
            }
        }

        // Try current PSK first.
        {
            let psk = self.current_psk.lock().unwrap();
            let expected = compute_auth_tag(psk.as_bytes(), client_pub, server_pub);
            if hmac_verify(&expected, received_tag) {
                return Ok(());
            }
        }

        // Try previous PSK if available.
        {
            let prev = self.previous_psk.lock().unwrap();
            if let Some(ref prev_psk) = *prev {
                let expected = compute_auth_tag(prev_psk.as_bytes(), client_pub, server_pub);
                if hmac_verify(&expected, received_tag) {
                    log::warn!(
                        "HMAC verified with previous (stale) PSK — peer may not have rotated yet"
                    );
                    return Ok(());
                }
            }
        }

        anyhow::bail!(
            "HMAC verification failed against both current and previous PSK — PSK mismatch or MITM"
        )
    }
}
