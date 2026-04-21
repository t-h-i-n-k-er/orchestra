//! Agent-facing listener: an AES-encrypted TCP socket that reuses
//! [`common::CryptoSession`].
//!
//! Each connection runs a reader task (driving the registry + pending-task
//! routing) and a writer task (forwarding [`Message`] values from the API
//! layer to the agent).

use crate::state::{now_secs, AgentEntry, AppState};
use anyhow::Result;
use common::{CryptoSession, Message};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

const CHANNEL_DEPTH: usize = 64;
const MAX_FRAME_BYTES: u32 = 16 * 1024 * 1024; // 16 MiB hard cap

async fn read_frame(r: &mut OwnedReadHalf, sess: &CryptoSession) -> Result<Message> {
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

async fn write_frame(w: &mut OwnedWriteHalf, sess: &CryptoSession, msg: &Message) -> Result<()> {
    let plain = serde_json::to_vec(msg)?;
    let enc = sess.encrypt(&plain);
    w.write_u32_le(enc.len() as u32).await?;
    w.write_all(&enc).await?;
    Ok(())
}

pub async fn run(state: Arc<AppState>, addr: std::net::SocketAddr, secret: String) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, "agent listener bound");
    serve(state, listener, secret).await
}

/// Drive a pre-bound listener. Useful for tests that want an ephemeral port.
pub async fn serve(
    state: Arc<AppState>,
    listener: TcpListener,
    secret: String,
) -> Result<()> {
    loop {
        let (sock, peer) = listener.accept().await?;
        let state_c = state.clone();
        let secret_c = secret.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_agent(sock, peer.to_string(), state_c, secret_c).await {
                tracing::warn!(%peer, "agent connection ended: {e}");
            }
        });
    }
}

async fn handle_agent(
    sock: TcpStream,
    peer: String,
    state: Arc<AppState>,
    secret: String,
) -> Result<()> {
    sock.set_nodelay(true).ok();
    let session = Arc::new(CryptoSession::from_shared_secret(secret.as_bytes()));
    let (mut r, mut w) = sock.into_split();

    let (tx, mut rx) = mpsc::channel::<Message>(CHANNEL_DEPTH);

    // Writer task drains commands from the API layer onto the wire.
    let sess_w = session.clone();
    let writer = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if let Err(e) = write_frame(&mut w, &sess_w, &msg).await {
                tracing::warn!("agent write error: {e}");
                break;
            }
        }
    });

    // Reader loop runs in the connection task.
    let mut bound_id: Option<String> = None;

    loop {
        let msg = match read_frame(&mut r, &session).await {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!(%peer, "agent read terminated: {e}");
                break;
            }
        };

        match msg {
            Message::Heartbeat {
                agent_id,
                status,
                timestamp: _,
            } => {
                let entry = AgentEntry {
                    agent_id: agent_id.clone(),
                    hostname: status,
                    last_seen: now_secs(),
                    tx: tx.clone(),
                    peer: peer.clone(),
                };
                state.registry.insert(agent_id.clone(), entry);
                bound_id = Some(agent_id);
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
    if let Some(id) = bound_id {
        // Only remove if the registry entry still belongs to this connection
        // (a reconnect may have replaced it already).
        state.registry.remove_if(&id, |_, e| e.peer == peer);
    }
    Ok(())
}
