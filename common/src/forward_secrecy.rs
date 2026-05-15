//! Per-session key derivation via X25519 ECDH authenticated by the pre-shared
//! key (PSK).
//!
//! Both sides of the connection perform an ephemeral X25519 Diffie–Hellman
//! exchange immediately after the TLS handshake.  The resulting shared secret
//! is mixed with the PSK via HKDF-SHA256 to derive the per-session AES-256-GCM
//! key used by [`crate::CryptoSession`].
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
use base64::Engine;
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
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

// ── HTTP/DoH Forward Secrecy ────────────────────────────────────────────────
//
// HTTP and DoH transports are request/response-based: there is no persistent
// bidirectional stream to run the 3-way ECDH handshake from
// `negotiate_session_key`.  Instead, the agent and server perform a single-
// round-trip ECDH exchange embedded in HTTP headers.
//
// ## Protocol
//
// 1. **Agent (every request)**: Sends its ephemeral public key + HMAC tag
//    in the `X-ECDH-Pub` header (base64-encoded 64 bytes).
// 2. **Server (first request from a session)**: Generates its own ephemeral
//    keypair, verifies the agent's HMAC tag, derives the session key, stores
//    it keyed by session ID, and returns its public key + HMAC tag in the
//    `X-ECDH-Pub` response header.
// 3. **Server (subsequent requests)**: Looks up the already-derived session
//    key and returns it (no new ECDH needed). Still echoes back the same
//    server pubkey+tag in the response header so the agent can identify a
//    server restart / key change.
// 4. **Agent (on first response)**: Reads the server's public key from the
//    response header, verifies the HMAC, derives the session key, and stores
//    it for all subsequent encrypt/decrypt operations.
//
// The HMAC authenticates the key exchange to the PSK, preventing MITM even
// if TLS is somehow intercepted.  The same `compute_auth_tag` and
// `derive_fs_salt` functions are reused for consistency with stream-based FS.
//
// ## Wire format
//
// The header value is base64(`[client_pubkey_32 | hmac_tag_32]`) = 88 chars.
//
// ## Key derivation
//
// ```text
// fs_salt  = HKDF-Expand(ikm=psk, info=hkdf_info::FS_SALT)
// session_key = HKDF-SHA256(ikm=ECDH_shared, salt=fs_salt, info=hkdf_info::FS_HTTP_SESSION)[..32]
// ```
//
// Uses `FS_HTTP_SESSION` instead of `FS_SESSION` for domain separation from
// stream-based ECDH sessions.

/// HTTP header name used for the ECDH public key + HMAC tag exchange.
pub const ECDH_HEADER_NAME: &str = "X-ECDH-Pub";

/// Binary ECDH framing marker for non-HTTP transports (QUIC, Graph).
/// Prepended to ciphertext when the ECDH handshake is in progress.
/// Format: `[ECDH_BIN_MARKER: 2 bytes] [payload_len: 2 bytes BE] [base64 payload] [ciphertext]`
pub const ECDH_BIN_MARKER: [u8; 2] = [0xEC, 0xD1];

/// Encode an ECDH payload as a binary frame suitable for prepending to
/// ciphertext in non-HTTP transports (QUIC, Graph).
///
/// Format: `[ECDH_BIN_MARKER: 2 bytes] [payload_len: 2 bytes BE] [payload bytes]`
///
/// Returns the complete frame to prepend before the ciphertext.
pub fn encode_ecdh_bin_frame(ecdh_b64: &str) -> Vec<u8> {
    let payload = ecdh_b64.as_bytes();
    let len = payload.len() as u16;
    let mut frame = Vec::with_capacity(2 + 2 + payload.len());
    frame.extend_from_slice(&ECDH_BIN_MARKER);
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// Try to extract and remove an ECDH binary frame from the start of a
/// received data buffer.
///
/// If the buffer starts with `ECDH_BIN_MARKER`, parses the frame, returns
/// the base64 payload string, and the remaining bytes after the frame.
/// If no marker is found, returns `None` (no ECDH data in this message).
pub fn try_extract_ecdh_bin_frame<'a>(data: &'a [u8]) -> Option<(String, &'a [u8])> {
    if data.len() < 4 {
        return None;
    }
    if data[0] != ECDH_BIN_MARKER[0] || data[1] != ECDH_BIN_MARKER[1] {
        return None;
    }
    let len = u16::from_be_bytes([data[2], data[3]]) as usize;
    if data.len() < 4 + len {
        return None;
    }
    let payload = &data[4..4 + len];
    let rest = &data[4 + len..];
    match std::str::from_utf8(payload) {
        Ok(s) => Some((s.to_string(), rest)),
        Err(_) => None,
    }
}

/// Wire message size for HTTP ECDH: 32-byte public key + 32-byte HMAC tag.
const HTTP_ECDH_MSG_LEN: usize = 32 + HMAC_TAG_LEN;

/// Client-side state for HTTP/DoH forward secrecy.
///
/// Holds an ephemeral X25519 keypair and derives a per-session
/// `CryptoSession` from the server's response header.
pub struct HttpEcdhClient {
    secret: Option<EphemeralSecret>,
    public: PublicKey,
    psk: Vec<u8>,
}

impl HttpEcdhClient {
    /// Create a new client-side ECDH state with the given PSK.
    pub fn new(psk: &[u8]) -> Self {
        let secret = EphemeralSecret::random_from_rng(rand::thread_rng());
        let public = PublicKey::from(&secret);
        Self {
            secret: Some(secret),
            public,
            psk: psk.to_vec(),
        }
    }

    /// Return the base64-encoded wire message for the `X-ECDH-Pub` header.
    ///
    /// Format: `[client_pubkey_32 | hmac_tag_32]` where the HMAC is computed
    /// over `client_pubkey || client_pubkey` (we don't know the server's key
    /// yet, so we self-sign with a placeholder — the server will verify the
    /// full HMAC once it sends its key and the agent confirms).
    ///
    /// Actually, since the HMAC must cover *both* public keys and the client
    /// sends first, we send just the public key without a tag in the initial
    /// message. The server replies with its pubkey + a tag covering both keys,
    /// then the client sends a tag covering both keys in the *next* request.
    ///
    /// Simplification: the first request carries only the 32-byte public key
    /// (base64). The server responds with pubkey + tag. From the second request
    /// onward, the agent includes pubkey + tag.
    ///
    /// **Final design**: To keep the protocol simple and stateless on the
    /// server side, the client always sends `[pubkey_32 | tag_32]` where the
    /// tag is `HMAC(hmac_key, client_pub || client_pub)` — a self-HMAC. The
    /// server verifies this self-HMAC to confirm PSK possession, then computes
    /// its own tag over both keys for the response.
    pub fn header_value(&self) -> String {
        let mut msg = [0u8; HTTP_ECDH_MSG_LEN];
        msg[..32].copy_from_slice(self.public.as_bytes());
        // Self-HMAC: tag = HMAC(key, client_pub || client_pub)
        let self_tag = compute_auth_tag(&self.psk, self.public.as_bytes(), self.public.as_bytes());
        msg[32..HTTP_ECDH_MSG_LEN].copy_from_slice(&self_tag);
        base64::engine::general_purpose::STANDARD.encode(msg)
    }

    /// Derive a `CryptoSession` from the server's response header value.
    ///
    /// The response header contains `[server_pubkey_32 | server_tag_32]`
    /// (base64-encoded). The server tag covers `(client_pub, server_pub)`.
    ///
    /// After verification, the ECDH shared secret is mixed with the PSK to
    /// derive the session key.
    pub fn derive_session_from_response(&mut self, header_value: &str) -> Result<CryptoSession> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(header_value.trim())
            .map_err(|e| anyhow::anyhow!("base64 decode of ECDH header failed: {e}"))?;

        if bytes.len() != HTTP_ECDH_MSG_LEN {
            anyhow::bail!(
                "ECDH response header: expected {} bytes, got {}",
                HTTP_ECDH_MSG_LEN,
                bytes.len()
            );
        }

        let mut server_pub = [0u8; 32];
        server_pub.copy_from_slice(&bytes[..32]);
        let server_tag: &[u8] = &bytes[32..HTTP_ECDH_MSG_LEN];

        // Verify server's HMAC tag: HMAC(psk, client_pub || server_pub)
        let expected_tag = compute_auth_tag(&self.psk, self.public.as_bytes(), &server_pub);
        if !hmac_verify(&expected_tag, server_tag) {
            anyhow::bail!(
                "HTTP ECDH: server HMAC verification failed — PSK mismatch or MITM"
            );
        }

        // ECDH key agreement.
        let server_public = PublicKey::from(server_pub);
        let secret = self.secret.take().expect("derive_session_from_response called twice");
        let shared = secret.diffie_hellman(&server_public);

        // Derive session key: HKDF(salt=fs_salt, ikm=shared, info=FS_HTTP_SESSION)
        let fs_salt = derive_fs_salt(&self.psk);
        let h = Hkdf::<Sha256>::new(Some(&fs_salt), shared.as_bytes());

        let mut session_key = [0u8; KEY_LEN];
        h.expand(crate::hkdf_info::FS_HTTP_SESSION, &mut session_key)
            .map_err(|_| anyhow::anyhow!("HKDF expand failed (output too long)"))?;

        Ok(CryptoSession::from_key(session_key))
    }
}

// Make HttpEcdhClient zeroize-safe: the PSK buffer is zeroized on drop.
impl Drop for HttpEcdhClient {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.psk.zeroize();
    }
}

/// Server-side per-session ECDH state for HTTP/DoH forward secrecy.
///
/// On first request from a session, the server generates an ephemeral keypair,
/// verifies the client's self-HMAC, derives the session key, and stores this
/// struct. On subsequent requests, the stored session key is reused.
pub struct HttpEcdhServerSession {
    /// The derived CryptoSession for encrypt/decrypt.
    session: CryptoSession,
    /// Our ephemeral public key (sent in every response header).
    public_bytes: [u8; 32],
    /// Our HMAC tag covering (client_pub, our_pub), sent in every response.
    response_tag: [u8; HMAC_TAG_LEN],
}

impl HttpEcdhServerSession {
    /// Create a new server-side ECDH session.
    ///
    /// - `psk`: The pre-shared secret.
    /// - `client_header_value`: The base64-encoded `[pubkey_32 | self_hmac_32]`
    ///   from the client's first request.
    ///
    /// Verifies the client's self-HMAC to confirm PSK possession, then
    /// derives the session key.
    pub fn new(psk: &[u8], client_header_value: &str) -> Result<Self> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(client_header_value.trim())
            .map_err(|e| anyhow::anyhow!("base64 decode of client ECDH header failed: {e}"))?;

        if bytes.len() != HTTP_ECDH_MSG_LEN {
            anyhow::bail!(
                "ECDH client header: expected {} bytes, got {}",
                HTTP_ECDH_MSG_LEN,
                bytes.len()
            );
        }

        let mut client_pub = [0u8; 32];
        client_pub.copy_from_slice(&bytes[..32]);
        let client_self_tag: &[u8] = &bytes[32..HTTP_ECDH_MSG_LEN];

        // Verify client's self-HMAC: HMAC(psk, client_pub || client_pub)
        let expected_self_tag = compute_auth_tag(psk, &client_pub, &client_pub);
        if !hmac_verify(&expected_self_tag, client_self_tag) {
            anyhow::bail!(
                "HTTP ECDH: client self-HMAC verification failed — PSK mismatch"
            );
        }

        // Generate server's ephemeral keypair.
        let our_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
        let our_public = PublicKey::from(&our_secret);
        let our_pub_bytes: [u8; 32] = *our_public.as_bytes();

        // Compute response HMAC tag: HMAC(psk, client_pub || server_pub)
        let response_tag = compute_auth_tag(psk, &client_pub, &our_pub_bytes);

        // ECDH key agreement.
        let client_public = PublicKey::from(client_pub);
        let shared = our_secret.diffie_hellman(&client_public);

        // Derive session key.
        let fs_salt = derive_fs_salt(psk);
        let h = Hkdf::<Sha256>::new(Some(&fs_salt), shared.as_bytes());
        let mut session_key = [0u8; KEY_LEN];
        h.expand(crate::hkdf_info::FS_HTTP_SESSION, &mut session_key)
            .map_err(|_| anyhow::anyhow!("HKDF expand failed (output too long)"))?;

        Ok(Self {
            session: CryptoSession::from_key(session_key),
            public_bytes: our_pub_bytes,
            response_tag,
        })
    }

    /// Return the base64-encoded response header value.
    ///
    /// Format: `[server_pubkey_32 | hmac_tag_32]`
    pub fn response_header_value(&self) -> String {
        let mut msg = [0u8; HTTP_ECDH_MSG_LEN];
        msg[..32].copy_from_slice(&self.public_bytes);
        msg[32..HTTP_ECDH_MSG_LEN].copy_from_slice(&self.response_tag);
        base64::engine::general_purpose::STANDARD.encode(msg)
    }

    /// Get a reference to the derived `CryptoSession`.
    pub fn session(&self) -> &CryptoSession {
        &self.session
    }

    /// Take ownership of the derived `CryptoSession`.
    pub fn into_session(self) -> CryptoSession {
        self.session
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── derive_hmac_key / derive_fs_salt ────────────────────────────────

    #[test]
    fn derive_hmac_key_deterministic() {
        let psk = b"test-psk-for-hmac-key";
        let k1 = derive_hmac_key(psk);
        let k2 = derive_hmac_key(psk);
        assert_eq!(k1, k2, "same PSK must produce the same HMAC key");
    }

    #[test]
    fn derive_hmac_key_different_psks() {
        let k1 = derive_hmac_key(b"psk-a");
        let k2 = derive_hmac_key(b"psk-b");
        assert_ne!(k1, k2, "different PSKs must produce different HMAC keys");
    }

    #[test]
    fn derive_fs_salt_deterministic() {
        let psk = b"test-psk-for-fs-salt";
        let s1 = derive_fs_salt(psk);
        let s2 = derive_fs_salt(psk);
        assert_eq!(s1, s2, "same PSK must produce the same FS salt");
    }

    #[test]
    fn derive_fs_salt_different_from_hmac_key() {
        let psk = b"test-psk";
        let hmac_key = derive_hmac_key(psk);
        let salt = derive_fs_salt(psk);
        assert_ne!(
            hmac_key, salt,
            "HMAC key and FS salt must be domain-separated"
        );
    }

    // ── compute_auth_tag / hmac_verify ──────────────────────────────────

    #[test]
    fn compute_auth_tag_deterministic() {
        let psk = b"auth-tag-psk";
        let client = [0xAA; 32];
        let server = [0xBB; 32];
        let t1 = compute_auth_tag(psk, &client, &server);
        let t2 = compute_auth_tag(psk, &client, &server);
        assert_eq!(t1, t2);
    }

    #[test]
    fn compute_auth_tag_key_ordering_matters() {
        let psk = b"ordering-psk";
        let client = [0xAA; 32];
        let server = [0xBB; 32];
        let t_forward = compute_auth_tag(psk, &client, &server);
        let t_reverse = compute_auth_tag(psk, &server, &client);
        assert_ne!(
            t_forward, t_reverse,
            "swapping client/server pubkeys must produce a different tag"
        );
    }

    #[test]
    fn compute_auth_tag_different_psk() {
        let client = [0xAA; 32];
        let server = [0xBB; 32];
        let t1 = compute_auth_tag(b"psk-1", &client, &server);
        let t2 = compute_auth_tag(b"psk-2", &client, &server);
        assert_ne!(t1, t2, "different PSKs must produce different tags");
    }

    #[test]
    fn hmac_verify_accepts_valid_tag() {
        let psk = b"verify-psk";
        let client = [0x01; 32];
        let server = [0x02; 32];
        let tag = compute_auth_tag(psk, &client, &server);
        assert!(hmac_verify(&tag, &tag));
    }

    #[test]
    fn hmac_verify_rejects_invalid_tag() {
        let psk = b"verify-psk";
        let client = [0x01; 32];
        let server = [0x02; 32];
        let tag = compute_auth_tag(psk, &client, &server);
        let mut bad_tag = tag;
        bad_tag[0] ^= 0xFF;
        assert!(!hmac_verify(&tag, &bad_tag));
    }

    #[test]
    fn hmac_verify_rejects_wrong_length() {
        let tag = [0xAB; 32];
        // hmac_verify checks actual.len() == HMAC_TAG_LEN
        assert!(!hmac_verify(&tag, &[0xAB; 16]));
        assert!(!hmac_verify(&tag, &[0xAB; 48]));
    }

    // ── derive_rotated_psk ──────────────────────────────────────────────

    #[test]
    fn derive_rotated_psk_deterministic() {
        let psk = b"rotation-psk";
        let r1 = derive_rotated_psk(psk, 1);
        let r2 = derive_rotated_psk(psk, 1);
        assert_eq!(r1, r2);
    }

    #[test]
    fn derive_rotated_psk_different_counters() {
        let psk = b"rotation-psk";
        let r1 = derive_rotated_psk(psk, 1);
        let r2 = derive_rotated_psk(psk, 2);
        assert_ne!(r1, r2, "different counters must produce different PSKs");
    }

    #[test]
    fn derive_rotated_psk_different_base_psks() {
        let r1 = derive_rotated_psk(b"psk-a", 1);
        let r2 = derive_rotated_psk(b"psk-b", 1);
        assert_ne!(r1, r2, "different base PSKs must produce different rotations");
    }

    #[test]
    fn derive_rotated_psk_not_equal_to_base() {
        let base = b"base-psk-value";
        let rotated = derive_rotated_psk(base, 1);
        // Rotated PSK should differ from base (HKDF is a PRF).
        assert_ne!(
            &rotated[..],
            &base[..base.len().min(32)],
            "rotated PSK must differ from the base PSK"
        );
    }

    #[test]
    fn derive_rotated_psk_one_way() {
        // Two rotations forward should produce a different result from a
        // single rotation with counter=2. This confirms the counter is
        // used as salt and each step is distinct.
        let base = b"one-way-psk";
        let single = derive_rotated_psk(base, 2);
        let step1 = derive_rotated_psk(base, 1);
        let step2 = derive_rotated_psk(&step1, 2);
        // These should be different because the salt changes.
        assert_ne!(single, step2);
    }

    // ── PskRotationState ────────────────────────────────────────────────

    #[test]
    fn psk_rotation_state_new() {
        let state = PskRotationState::new(b"initial-psk", 100, 3600);
        assert_eq!(state.rotation_counter(), 0);
        let psk = state.current_psk();
        assert_eq!(psk.as_bytes(), b"initial-psk");
    }

    #[test]
    fn psk_rotation_state_record_session_no_rotation() {
        let state = PskRotationState::new(b"psk", 10, 999999);
        for _ in 0..9 {
            assert!(!state.record_session(), "should not trigger rotation yet");
        }
    }

    #[test]
    fn psk_rotation_state_record_session_triggers_rotation() {
        let state = PskRotationState::new(b"psk", 3, 999999);
        assert!(!state.record_session()); // 1
        assert!(!state.record_session()); // 2
        assert!(state.record_session()); // 3 → threshold reached
    }

    #[test]
    fn psk_rotation_state_rotate() {
        let state = PskRotationState::new(b"initial-psk", 100, 999999);
        let counter = state.rotate();
        assert_eq!(counter, 1);
        assert_eq!(state.rotation_counter(), 1);
        // The current PSK should have changed.
        let psk = state.current_psk();
        assert_ne!(psk.as_bytes(), b"initial-psk");
    }

    #[test]
    fn psk_rotation_state_multiple_rotations() {
        let state = PskRotationState::new(b"initial", 100, 999999);
        let c1 = state.rotate();
        let c2 = state.rotate();
        let c3 = state.rotate();
        assert_eq!(c1, 1);
        assert_eq!(c2, 2);
        assert_eq!(c3, 3);
        assert_eq!(state.rotation_counter(), 3);
    }

    #[test]
    fn psk_rotation_state_apply_rotation() {
        let state = PskRotationState::new(b"initial", 100, 999999);
        let new_psk = derive_rotated_psk(b"initial", 5);
        let applied = state.apply_rotation(&new_psk, 5);
        assert!(applied);
        assert_eq!(state.rotation_counter(), 5);
        let psk = state.current_psk();
        assert_eq!(psk.as_bytes(), new_psk);
    }

    #[test]
    fn psk_rotation_state_apply_stale_rotation_rejected() {
        let state = PskRotationState::new(b"initial", 100, 999999);
        state.rotate(); // counter = 1
        state.rotate(); // counter = 2
        let applied = state.apply_rotation(b"stale", 1);
        assert!(!applied, "stale counter should be rejected");
        assert_eq!(state.rotation_counter(), 2);
    }

    #[test]
    fn psk_rotation_state_verify_auth_tag_current_psk() {
        let psk = b"verify-psk";
        let state = PskRotationState::new(psk, 100, 999999);
        let client_pub = [0x01; 32];
        let server_pub = [0x02; 32];
        let tag = compute_auth_tag(psk, &client_pub, &server_pub);
        assert!(state.verify_auth_tag(&client_pub, &server_pub, &tag).is_ok());
    }

    #[test]
    fn psk_rotation_state_verify_auth_tag_wrong_psk() {
        let state = PskRotationState::new(b"correct-psk", 100, 999999);
        let client_pub = [0x01; 32];
        let server_pub = [0x02; 32];
        let tag = compute_auth_tag(b"wrong-psk", &client_pub, &server_pub);
        assert!(state.verify_auth_tag(&client_pub, &server_pub, &tag).is_err());
    }

    // ── negotiate_session_key (async, via duplex pipe) ──────────────────

    /// Create a bidirectional in-memory pipe for testing.
    /// Returns (client_stream, server_stream).
    fn duplex_pipe() -> (
        tokio::io::DuplexStream,
        tokio::io::DuplexStream,
    ) {
        tokio::io::duplex(4096)
    }

    #[tokio::test]
    async fn negotiate_session_key_same_psk() {
        let (mut client, mut server) = duplex_pipe();
        let psk = b"shared-secret-for-test";

        let client_handle = tokio::spawn(async move {
            negotiate_session_key(&mut client, psk, true).await
        });
        let server_handle = tokio::spawn(async move {
            negotiate_session_key(&mut server, psk, false).await
        });

        let client_session = client_handle.await.unwrap().unwrap();
        let server_session = server_handle.await.unwrap().unwrap();

        // Both sides should derive the same session key.
        let plaintext = b"negotiation test";
        let ct = client_session.encrypt(plaintext);
        let pt = server_session.decrypt(&ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[tokio::test]
    async fn negotiate_session_key_different_psk_fails() {
        let (mut client, mut server) = duplex_pipe();

        let client_handle = tokio::spawn(async move {
            negotiate_session_key(&mut client, b"client-psk", true).await
        });
        let server_handle = tokio::spawn(async move {
            negotiate_session_key(&mut server, b"server-psk", false).await
        });

        let client_result = client_handle.await.unwrap();
        let server_result = server_handle.await.unwrap();

        // At least one side should fail.
        assert!(
            client_result.is_err() || server_result.is_err(),
            "different PSKs must cause negotiation failure"
        );
    }

    // ── negotiate_session_key_blocking ──────────────────────────────────

    #[test]
    fn negotiate_session_key_blocking_same_psk() {
        // Use a paired pipe with blocking-style reads (spin-wait) for
        // synchronous bidirectional I/O.
        use std::sync::{Arc, Mutex};

        struct Pipe {
            buf: Vec<u8>,
            read_pos: usize,
        }

        struct Duplex {
            a_to_b: Arc<Mutex<Pipe>>,
            b_to_a: Arc<Mutex<Pipe>>,
        }

        impl Duplex {
            fn new() -> Self {
                Self {
                    a_to_b: Arc::new(Mutex::new(Pipe { buf: Vec::new(), read_pos: 0 })),
                    b_to_a: Arc::new(Mutex::new(Pipe { buf: Vec::new(), read_pos: 0 })),
                }
            }
        }

        struct PipeEnd {
            read_from: Arc<Mutex<Pipe>>,
            write_to: Arc<Mutex<Pipe>>,
        }

        impl std::io::Read for PipeEnd {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                // Spin-wait for data (simulates blocking I/O).
                loop {
                    let mut src = self.read_from.lock().unwrap();
                    let available = src.buf.len().saturating_sub(src.read_pos);
                    if available > 0 {
                        let n = buf.len().min(available);
                        buf[..n].copy_from_slice(&src.buf[src.read_pos..src.read_pos + n]);
                        src.read_pos += n;
                        return Ok(n);
                    }
                    drop(src);
                    std::thread::yield_now();
                }
            }
        }

        impl std::io::Write for PipeEnd {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                let mut dst = self.write_to.lock().unwrap();
                dst.buf.extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let duplex = Arc::new(Duplex::new());
        let dup2 = duplex.clone();
        let mut client_end = PipeEnd {
            read_from: duplex.b_to_a.clone(),
            write_to: duplex.a_to_b.clone(),
        };
        let mut server_end = PipeEnd {
            read_from: dup2.a_to_b.clone(),
            write_to: dup2.b_to_a.clone(),
        };

        let psk = b"blocking-shared-secret";

        // Run client and server in separate threads to avoid deadlock.
        let client_psk = psk.to_vec();
        let server_psk = psk.to_vec();

        let client_thread = std::thread::spawn(move || {
            negotiate_session_key_blocking(&mut client_end, &client_psk, true)
        });
        let server_thread = std::thread::spawn(move || {
            negotiate_session_key_blocking(&mut server_end, &server_psk, false)
        });

        let client_session = client_thread.join().unwrap().unwrap();
        let server_session = server_thread.join().unwrap().unwrap();

        // Both should derive the same session key.
        let plaintext = b"blocking test";
        let ct = client_session.encrypt(plaintext);
        let pt = server_session.decrypt(&ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    // ── HttpEcdhClient / HttpEcdhServerSession ──────────────────────────

    #[test]
    fn http_ecdh_full_roundtrip() {
        let psk = b"http-ecdh-test-psk";

        // Client creates its state and generates a header.
        let mut client = HttpEcdhClient::new(psk);
        let client_header = client.header_value();

        // Decode and validate the client header format (64 bytes base64 = 88 chars).
        let client_bytes = base64::engine::general_purpose::STANDARD
            .decode(&client_header)
            .unwrap();
        assert_eq!(client_bytes.len(), HTTP_ECDH_MSG_LEN);

        // Server processes the client header.
        let server = HttpEcdhServerSession::new(psk, &client_header).unwrap();
        let server_header = server.response_header_value();

        // Client derives the session from the server's response header.
        let client_session = client.derive_session_from_response(&server_header).unwrap();
        let server_session = server.into_session();

        // Both should derive the same session key → encrypt on one side
        // decrypts on the other.
        let plaintext = b"http ecdh roundtrip";
        let ct = client_session.encrypt(plaintext);
        let pt = server_session.decrypt(&ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn http_ecdh_wrong_psk_fails() {
        let client_psk = b"client-psk";
        let server_psk = b"server-psk";

        let client = HttpEcdhClient::new(client_psk);
        let client_header = client.header_value();

        let result = HttpEcdhServerSession::new(server_psk, &client_header);
        assert!(
            result.is_err(),
            "server must reject the client header when PSKs differ"
        );
    }

    #[test]
    fn http_ecdh_rejects_truncated_header() {
        let psk = b"test-psk";
        let short = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
        let result = HttpEcdhServerSession::new(psk, &short);
        assert!(result.is_err());
    }

    #[test]
    fn http_ecdh_rejects_invalid_base64() {
        let psk = b"test-psk";
        let result = HttpEcdhServerSession::new(psk, "!!!not-base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn http_ecdh_client_rejects_wrong_server_response() {
        let psk = b"test-psk";
        let mut client = HttpEcdhClient::new(psk);
        // Forge a response with wrong keys.
        let fake_response = base64::engine::general_purpose::STANDARD
            .encode([0xFF; HTTP_ECDH_MSG_LEN]);
        let result = client.derive_session_from_response(&fake_response);
        assert!(
            result.is_err(),
            "client must reject a response with invalid HMAC tag"
        );
    }

    #[test]
    fn http_ecdh_client_rejects_truncated_response() {
        let psk = b"test-psk";
        let mut client = HttpEcdhClient::new(psk);
        let short = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
        let result = client.derive_session_from_response(&short);
        assert!(result.is_err());
    }

    #[test]
    fn http_ecdh_header_is_valid_base64() {
        let client = HttpEcdhClient::new(b"psk");
        let header = client.header_value();
        // Should be valid base64 with no padding issues.
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&header)
            .unwrap();
        assert_eq!(decoded.len(), HTTP_ECDH_MSG_LEN);
    }

    #[test]
    fn http_ecdh_different_clients_produce_different_keys() {
        let psk = b"shared-psk";
        let mut client1 = HttpEcdhClient::new(psk);
        let header1 = client1.header_value();
        let server1 = HttpEcdhServerSession::new(psk, &header1).unwrap();
        let resp1 = server1.response_header_value();
        let session1 = client1.derive_session_from_response(&resp1).unwrap();

        let mut client2 = HttpEcdhClient::new(psk);
        let header2 = client2.header_value();
        let server2 = HttpEcdhServerSession::new(psk, &header2).unwrap();
        let resp2 = server2.response_header_value();
        let session2 = client2.derive_session_from_response(&resp2).unwrap();

        // Different ephemeral keypairs → different session keys.
        let ct1 = session1.encrypt(b"test");
        let ct2 = session2.encrypt(b"test");
        assert_ne!(ct1, ct2, "different ECDH runs must produce different keys");
    }
}

/// Property-based tests for cryptographic primitives using proptest.
#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    // ── derive_hmac_key properties ─────────────────────────────────────

    proptest! {
        #[test]
        fn hmac_key_deterministic(psk in any::<[u8; 32]>()) {
            let k1 = derive_hmac_key(&psk);
            let k2 = derive_hmac_key(&psk);
            prop_assert_eq!(k1, k2);
        }

        #[test]
        fn hmac_key_sensitive_to_bit_flip(
            psk in any::<[u8; 32]>(),
            flip_byte in 0usize..32,
        ) {
            let k1 = derive_hmac_key(&psk);
            let mut modified = psk;
            modified[flip_byte] ^= 0x01;
            let k2 = derive_hmac_key(&modified);
            prop_assert_ne!(k1, k2, "flipping any byte should change the HMAC key");
        }

        #[test]
        fn fs_salt_deterministic(psk in any::<[u8; 32]>()) {
            let s1 = derive_fs_salt(&psk);
            let s2 = derive_fs_salt(&psk);
            prop_assert_eq!(s1, s2);
        }

        #[test]
        fn fs_salt_differs_from_hmac_key(psk in any::<[u8; 32]>()) {
            let hmac_key = derive_hmac_key(&psk);
            let salt = derive_fs_salt(&psk);
            prop_assert_ne!(hmac_key.as_slice(), salt.as_slice(),
                "HMAC key and FS salt must be domain-separated");
        }

        #[test]
        fn auth_tag_deterministic(
            psk in any::<[u8; 32]>(),
            client_pub in any::<[u8; 32]>(),
            server_pub in any::<[u8; 32]>(),
        ) {
            let t1 = compute_auth_tag(&psk, &client_pub, &server_pub);
            let t2 = compute_auth_tag(&psk, &client_pub, &server_pub);
            prop_assert_eq!(t1, t2);
        }

        #[test]
        fn auth_tag_sensitive_to_client_pub(
            psk in any::<[u8; 32]>(),
            client_pub in any::<[u8; 32]>(),
            server_pub in any::<[u8; 32]>(),
        ) {
            let t1 = compute_auth_tag(&psk, &client_pub, &server_pub);
            let mut modified = client_pub;
            modified[0] ^= 0x01;
            let t2 = compute_auth_tag(&psk, &modified, &server_pub);
            prop_assert_ne!(t1, t2, "changing client pub must change the auth tag");
        }

        #[test]
        fn auth_tag_sensitive_to_server_pub(
            psk in any::<[u8; 32]>(),
            client_pub in any::<[u8; 32]>(),
            server_pub in any::<[u8; 32]>(),
        ) {
            let t1 = compute_auth_tag(&psk, &client_pub, &server_pub);
            let mut modified = server_pub;
            modified[0] ^= 0x01;
            let t2 = compute_auth_tag(&psk, &client_pub, &modified);
            prop_assert_ne!(t1, t2, "changing server pub must change the auth tag");
        }

        #[test]
        fn auth_tag_key_ordering_matters(
            psk in any::<[u8; 32]>(),
            client_pub in any::<[u8; 32]>(),
            server_pub in any::<[u8; 32]>(),
        ) {
            prop_assume!(client_pub != server_pub);
            let t1 = compute_auth_tag(&psk, &client_pub, &server_pub);
            let t2 = compute_auth_tag(&psk, &server_pub, &client_pub);
            prop_assert_ne!(t1, t2, "key ordering in HMAC must matter");
        }

        #[test]
        fn hmac_verify_accepts_valid_tag(
            psk in any::<[u8; 32]>(),
            client_pub in any::<[u8; 32]>(),
            server_pub in any::<[u8; 32]>(),
        ) {
            let tag = compute_auth_tag(&psk, &client_pub, &server_pub);
            prop_assert!(hmac_verify(&tag, &tag));
        }

        #[test]
        fn hmac_verify_rejects_flipped_tag(
            psk in any::<[u8; 32]>(),
            client_pub in any::<[u8; 32]>(),
            server_pub in any::<[u8; 32]>(),
            flip_byte in 0usize..32,
        ) {
            let tag = compute_auth_tag(&psk, &client_pub, &server_pub);
            let mut modified = tag;
            modified[flip_byte] ^= 0x01;
            prop_assert!(!hmac_verify(&tag, &modified));
        }

        #[test]
        fn hmac_verify_rejects_wrong_length(tag in any::<[u8; 16]>()) {
            let expected = [0u8; 32];
            prop_assert!(!hmac_verify(&expected, &tag));
        }

        #[test]
        fn rotated_psk_deterministic(
            psk in any::<[u8; 32]>(),
            counter in any::<u64>(),
        ) {
            let r1 = derive_rotated_psk(&psk, counter);
            let r2 = derive_rotated_psk(&psk, counter);
            prop_assert_eq!(r1, r2);
        }

        #[test]
        fn rotated_psk_differs_for_different_counters(
            psk in any::<[u8; 32]>(),
            c1 in any::<u64>(),
            c2 in any::<u64>(),
        ) {
            prop_assume!(c1 != c2);
            let r1 = derive_rotated_psk(&psk, c1);
            let r2 = derive_rotated_psk(&psk, c2);
            prop_assert_ne!(r1, r2, "different counters must produce different PSKs");
        }

        #[test]
        fn rotated_psk_one_way(
            psk in any::<[u8; 32]>(),
            counter in any::<u64>(),
        ) {
            let rotated = derive_rotated_psk(&psk, counter);
            // Rotated PSK should differ from original (one-way).
            prop_assert_ne!(psk, rotated);
        }

        #[test]
        fn encrypt_decrypt_roundtrip(
            key in any::<[u8; 32]>(),
            plaintext in any::<Vec<u8>>(),
        ) {
            let session = CryptoSession::from_key(key);
            let ciphertext = session.encrypt(&plaintext);
            let decrypted = session.decrypt(&ciphertext);
            prop_assert!(decrypted.is_ok());
            prop_assert_eq!(decrypted.unwrap(), plaintext);
        }

        #[test]
        fn encrypt_produces_different_ciphertexts(
            key in any::<[u8; 32]>(),
            plaintext in any::<Vec<u8>>(),
        ) {
            let session = CryptoSession::from_key(key);
            let ct1 = session.encrypt(&plaintext);
            let ct2 = session.encrypt(&plaintext);
            // AES-GCM uses random nonce, so ciphertexts should differ.
            prop_assert_ne!(ct1, ct2, "random nonces should produce different ciphertexts");
        }

        #[test]
        fn wrong_key_fails_decryption(
            key1 in any::<[u8; 32]>(),
            key2 in any::<[u8; 32]>(),
            plaintext in any::<Vec<u8>>(),
        ) {
            prop_assume!(key1 != key2);
            let session1 = CryptoSession::from_key(key1);
            let session2 = CryptoSession::from_key(key2);
            let ciphertext = session1.encrypt(&plaintext);
            prop_assert!(session2.decrypt(&ciphertext).is_err());
        }
    }
}
