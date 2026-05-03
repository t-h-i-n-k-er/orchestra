//! Agent-facing listener: an AES-encrypted TCP socket that reuses
//! [`common::CryptoSession`].
//!
//! ## Identity binding
//!
//! On every `accept()` the server generates a fresh `connection_id`
//! (`Uuid::new_v4()`).  That UUID becomes the registry key — not the
//! `agent_id` the agent claims in its `Heartbeat`.  An agent can no longer
//! hijack another agent's registry slot by spoofing its `agent_id`; the
//! worst a rogue agent can do is register under a different `agent_id` label
//! while being tracked under its own, server-assigned `connection_id`.
//!
//! Duplicate `agent_id` reports (common during rapid reconnects) are logged
//! at `WARN` level but allowed; both entries coexist in the registry until
//! the old socket's TCP EOF cleans up the stale entry.

use crate::state::{now_secs, AgentEntry, AppState};
use anyhow::{Context as _, Result};
use common::normalized_transport::NormalizedTransport;
use common::{CryptoSession, Message};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

const MAX_FRAME_BYTES: u32 = 16 * 1024 * 1024; // 16 MiB hard cap

async fn read_frame<S: AsyncReadExt + Unpin>(r: &mut S, sess: &CryptoSession) -> Result<Message> {
    let len = r.read_u32_le().await?;
    if len > MAX_FRAME_BYTES {
        anyhow::bail!("agent frame too large: {len} bytes");
    }
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf).await?;
    let plain = sess
        .decrypt(&buf)
        .map_err(|e| anyhow::anyhow!("decrypt failed: {e:?}"))?;
    Ok(bincode::deserialize(&plain)?)
}

async fn write_frame<S: AsyncWriteExt + Unpin>(
    w: &mut S,
    sess: &CryptoSession,
    msg: &Message,
) -> Result<()> {
    let plain = bincode::serialize(msg)?;
    let enc = sess.encrypt(&plain);
    w.write_u32_le(enc.len() as u32).await?;
    w.write_all(&enc).await?;
    Ok(())
}

pub async fn run(
    state: Arc<AppState>,
    addr: std::net::SocketAddr,
    secret: String,
    tls: Arc<rustls::ServerConfig>,
) -> Result<()> {
    // If mTLS is enabled, rebuild the ServerConfig with a client certificate
    // verifier.  The HTTPS dashboard keeps the original config (no client
    // cert required so browsers can reach the operator GUI).
    let tls = if state.config.mtls_enabled {
        crate::tls::build_agent_tls_config(&state.config)
            .context("building mTLS ServerConfig for agent listener")?
    } else {
        tls
    };
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, "agent listener bound");
    serve(state, listener, secret, tls).await
}

/// Drive a pre-bound listener. Useful for tests that want an ephemeral port.
pub async fn serve(
    state: Arc<AppState>,
    listener: TcpListener,
    secret: String,
    tls: Arc<rustls::ServerConfig>,
) -> Result<()> {
    loop {
        let (sock, peer) = listener.accept().await?;
        let state_c = state.clone();
        let secret_c = secret.clone();
        let tls_c = tls.clone();
        // Assign a server-controlled connection ID before touching the agent.
        let connection_id = Uuid::new_v4().to_string();
        tokio::spawn(async move {
            if let Err(e) = handle_agent(
                sock,
                peer.to_string(),
                connection_id.clone(),
                state_c,
                secret_c,
                tls_c,
            )
            .await
            {
                tracing::warn!(connection_id = %connection_id, %peer, "agent connection ended: {e}");
            }
        });
    }
}

async fn handle_agent(
    sock: TcpStream,
    peer: String,
    connection_id: String,
    state: Arc<AppState>,
    secret: String,
    tls_config: Arc<rustls::ServerConfig>,
) -> Result<()> {
    sock.set_nodelay(true).ok();

    let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);
    // `mut` is needed because negotiate_session_key takes &mut tls_stream.
    let mut tls_stream = acceptor.accept(sock).await?;

    // Forward secrecy: perform an X25519 ECDH exchange before the first
    // application message.  The derived per-session key replaces the
    // static PSK-derived key, providing PFS at the application layer.
    // This is mandatory — if the handshake fails, the connection is rejected.
    let session = Arc::new(
        common::forward_secrecy::negotiate_session_key(
            &mut tls_stream,
            secret.as_bytes(),
            false, // server reads client key first
        )
        .await?,
    );

    // mTLS: after the TLS handshake, extract and log the client certificate CN.
    // When mtls_enabled is true the WebPkiClientVerifier has already verified
    // the certificate chain at the TLS layer; this block provides audit
    // logging and defense-in-depth rejection for the case where a cert was
    // somehow omitted.
    if state.config.mtls_enabled {
        let (_, server_conn) = tls_stream.get_ref();
        match server_conn.peer_certificates().and_then(|c| c.first()) {
            Some(cert_der) => {
                let cn = crate::tls::extract_cn(cert_der)
                    .unwrap_or_else(|| "<unparseable>".to_string());
                tracing::info!(
                    connection_id = %connection_id,
                    %peer,
                    client_cert_cn = %cn,
                    "mTLS: client certificate accepted"
                );
            }
            None => {
                tracing::warn!(
                    connection_id = %connection_id,
                    %peer,
                    "mTLS: no client certificate presented; closing connection"
                );
                return Ok(());
            }
        }
    }

    let stream: common::normalized_transport::CleartextStream =
        if let Some(profile) = state.config.agent_traffic_profile {
            tracing::debug!(
                connection_id = %connection_id,
                profile = ?profile,
                "agent listener: enabling server-side normalized transport acceptance"
            );
            NormalizedTransport::accept(tls_stream, profile).await?
        } else {
            Box::new(tls_stream)
        };

    let (mut r, mut w) = tokio::io::split(stream);

    // Bounded channel for the API layer to push commands to this connection.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Message>(32);

    // Writer task drains commands from the API layer onto the wire.
    let writer_session = session.clone();
    let writer = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if let Err(e) = write_frame(&mut w, &writer_session, &msg).await {
                tracing::warn!("agent write error: {e}");
                break;
            }
        }
    });

    // Reader loop runs in the connection task.
    let conn_id = connection_id.clone();
    let mut registered = false;

    loop {
        let msg = match read_frame(&mut r, &session).await {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!(connection_id = %conn_id, %peer, "agent read terminated: {e}");
                break;
            }
        };

        match msg {
            // ── Protocol version handshake (M-2) ─────────────────────────────
            // Agent sends VersionHandshake as its first message.  Echo back our
            // version so the agent can detect a server/agent version mismatch
            // and refuse to proceed if they differ.
            Message::VersionHandshake { version } => {
                if version != common::PROTOCOL_VERSION {
                    tracing::warn!(
                        connection_id = %conn_id,
                        agent_version = version,
                        server_version = common::PROTOCOL_VERSION,
                        "agent/server protocol version mismatch; \
                         the connection may be unstable — update to matching releases"
                    );
                }
                // Echo our version regardless of match so the agent can decide.
                if tx
                    .send(Message::VersionHandshake {
                        version: common::PROTOCOL_VERSION,
                    })
                    .await
                    .is_err()
                {
                    tracing::warn!(connection_id = %conn_id, "writer task closed during version handshake");
                    break;
                }
                tracing::debug!(connection_id = %conn_id, version, "version handshake completed");
            }
            Message::Heartbeat {
                agent_id,
                status,
                timestamp: _,
            } => {
                // Warn about duplicate agent_id but do not reject — it may be
                // a legitimate reconnect racing with cleanup of the old socket.
                if state
                    .registry
                    .iter()
                    .any(|e| e.value().agent_id == agent_id && e.key() != &conn_id)
                {
                    tracing::warn!(
                        agent_id = %agent_id,
                        new_connection = %conn_id,
                        "duplicate agent_id: another connection is already using this agent_id; \
                         both will remain registered until the old socket closes"
                    );
                }

                // Generate a unique morph seed for this session.  The seed is
                // tracked in `assigned_seeds` to ensure no two active agents
                // share the same transformation.
                let morph_seed = state.generate_unique_seed();
                state.assigned_seeds.insert(morph_seed);

                let entry = AgentEntry {
                    connection_id: conn_id.clone(),
                    agent_id: agent_id.clone(),
                    hostname: status,
                    last_seen: now_secs(),
                    tx: tx.clone(),
                    peer: peer.clone(),
                    morph_seed,
                    text_hash: None,
                };
                state.registry.insert(conn_id.clone(), entry);
                registered = true;
                tracing::debug!(
                    connection_id = %conn_id,
                    agent_id = %agent_id,
                    %peer,
                    morph_seed = format!("0x{morph_seed:016x}"),
                    "agent registered"
                );

                // Immediately send the morph seed to the agent so it can
                // perform its first re-encode.  Using SetReencodeSeed (not
                // MorphNow) because the first morph should be asynchronous —
                // the agent applies it during its next periodic cycle or on
                // its own schedule.  Operators can use MorphNow later for an
                // immediate synchronous re-encode.
                if tx
                    .send(Message::TaskRequest {
                        task_id: uuid::Uuid::new_v4().to_string(),
                        command: common::Command::SetReencodeSeed { seed: morph_seed },
                        operator_id: None,
                    })
                    .await
                    .is_err()
                {
                    tracing::warn!(
                        connection_id = %conn_id,
                        "failed to send initial morph seed — writer task closed"
                    );
                }
            }
            Message::TaskResponse { task_id, result, .. } => {
                if let Some((_, sender)) = state.pending.remove(&task_id) {
                    let _ = sender.send(result);
                } else {
                    tracing::debug!(%task_id, "received TaskResponse with no pending waiter");
                }
            }
            Message::AuditLog(ev) => {
                state.audit.record(ev);
            }
            Message::MorphResult {
                connection_id: conn_id_ref,
                text_hash,
            } => {
                // Record the agent's post-morph .text hash.  Only accept
                // reports that match this connection to prevent spoofing.
                if conn_id_ref == conn_id {
                    state.update_text_hash(&conn_id, &text_hash);
                    tracing::info!(
                        connection_id = %conn_id,
                        %text_hash,
                        "agent reported post-morph .text hash"
                    );
                } else {
                    tracing::warn!(
                        connection_id = %conn_id,
                        reported_conn = %conn_id_ref,
                        "agent sent MorphResult with mismatched connection_id — ignoring"
                    );
                }
            }
            other => {
                tracing::debug!("ignoring agent->server message: {:?}", other);
            }
        }
    }

    drop(tx);
    let _ = writer.await;
    if registered {
        // Release the morph seed back to the available pool.
        if let Some(entry) = state.registry.remove(&conn_id) {
            state.release_seed(entry.1.morph_seed);
        } else {
            state.registry.remove(&conn_id);
        }
        tracing::debug!(connection_id = %conn_id, "agent entry removed from registry");
    }
    Ok(())
}
