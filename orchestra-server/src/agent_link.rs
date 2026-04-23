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
use anyhow::Result;
use common::{CryptoSession, Message};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use uuid::Uuid;

const CHANNEL_DEPTH: usize = 64;
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
    Ok(serde_json::from_slice(&plain)?)
}

async fn write_frame<S: AsyncWriteExt + Unpin>(
    w: &mut S,
    sess: &CryptoSession,
    msg: &Message,
) -> Result<()> {
    let plain = serde_json::to_vec(msg)?;
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
    let tls_stream = acceptor.accept(sock).await?;

    let (mut r, mut w) = tokio::io::split(tls_stream);

    let (tx, mut rx) = mpsc::channel::<Message>(CHANNEL_DEPTH);
    let session = Arc::new(CryptoSession::from_shared_secret(secret.as_bytes()));

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

                let entry = AgentEntry {
                    connection_id: conn_id.clone(),
                    agent_id: agent_id.clone(),
                    hostname: status,
                    last_seen: now_secs(),
                    tx: tx.clone(),
                    peer: peer.clone(),
                };
                state.registry.insert(conn_id.clone(), entry);
                registered = true;
                tracing::debug!(
                    connection_id = %conn_id,
                    agent_id = %agent_id,
                    %peer,
                    "agent registered"
                );
            }
            Message::TaskResponse { task_id, result } => {
                if let Some((_, sender)) = state.pending.remove(&task_id) {
                    let _ = sender.send(result);
                } else {
                    tracing::debug!(%task_id, "received TaskResponse with no pending waiter");
                }
            }
            Message::AuditLog(ev) => {
                state.audit.record(ev);
            }
            other => {
                tracing::debug!("ignoring agent->server message: {:?}", other);
            }
        }
    }

    drop(tx);
    let _ = writer.await;
    if registered {
        state.registry.remove(&conn_id);
        tracing::debug!(connection_id = %conn_id, "agent entry removed from registry");
    }
    Ok(())
}
