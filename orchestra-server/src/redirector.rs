//! Redirector chain management.
//!
//! Maintains a registry of active redirectors, tracks their health via
//! heartbeat, and provides API endpoints for registration and monitoring.
//!
//! ## Redirector lifecycle
//!
//! 1. A redirector binary starts and calls `POST /redirector/register` with
//!    its URL and profile name.
//! 2. The server records it in the registry and returns a redirector ID.
//! 3. The redirector pings `POST /redirector/heartbeat` every 60 seconds.
//! 4. If no heartbeat is received for 5 minutes, the redirector is marked
//!    stale and excluded from the agent config.
//! 5. Operators can add/remove redirectors via CLI commands or the API.

use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::state::AppState;

// ── Data types ───────────────────────────────────────────────────────────────

/// Health status of a redirector.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedirectorHealth {
    /// Actively heartbeating and forwarding traffic.
    Healthy,
    /// No heartbeat received for 5 minutes.
    Stale,
    /// Manually paused by an operator.
    Paused,
}

impl std::fmt::Display for RedirectorHealth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RedirectorHealth::Healthy => write!(f, "healthy"),
            RedirectorHealth::Stale => write!(f, "stale"),
            RedirectorHealth::Paused => write!(f, "paused"),
        }
    }
}

/// A registered redirector entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RedirectorEntry {
    /// Unique identifier for this redirector.
    pub id: String,
    /// The URL agents should connect to (e.g. "https://cdn-front.example.com").
    pub url: String,
    /// The malleable profile name this redirector is configured for.
    pub profile_name: String,
    /// Current health status.
    pub health: RedirectorHealth,
    /// UNIX timestamp of the last received heartbeat.
    pub last_heartbeat: u64,
    /// UNIX timestamp when the redirector first registered.
    pub registered_at: u64,
    /// IP address or domain the redirector sees itself as.
    #[serde(default)]
    pub external_addr: String,
    /// Domain fronting domain for this redirector. When set, the agent's TLS
    /// SNI uses this domain while the HTTP Host header carries the redirector
    /// URL domain. This enables multi-CDN scenarios where different redirectors
    /// sit behind different CDNs.
    #[serde(default)]
    pub front_domain: Option<String>,
}

/// Shared state for redirector management.
#[derive(Clone)]
pub struct RedirectorState {
    /// Registered redirectors keyed by ID.
    pub redirectors: Arc<DashMap<String, RedirectorEntry>>,
    /// How long before a redirector is considered stale (seconds).
    pub stale_timeout_secs: u64,
}

impl RedirectorState {
    pub fn new() -> Self {
        Self {
            redirectors: Arc::new(DashMap::new()),
            stale_timeout_secs: 300, // 5 minutes
        }
    }

    /// Generate a unique redirector ID.
    fn generate_id(&self) -> String {
        uuid::Uuid::new_v4().to_string()
    }

    /// Register a new redirector.
    pub fn register(
        &self,
        url: String,
        profile_name: String,
        external_addr: String,
        front_domain: Option<String>,
    ) -> RedirectorEntry {
        let now = now_secs();
        let id = self.generate_id();
        let entry = RedirectorEntry {
            id,
            url,
            profile_name,
            health: RedirectorHealth::Healthy,
            last_heartbeat: now,
            registered_at: now,
            external_addr,
            front_domain,
        };
        self.redirectors.insert(entry.id.clone(), entry.clone());
        tracing::info!(
            id = %entry.id,
            url = %entry.url,
            profile = %entry.profile_name,
            "redirector registered"
        );
        entry
    }

    /// Process a heartbeat from a redirector.
    pub fn heartbeat(&self, id: &str) -> Result<RedirectorEntry, String> {
        let mut entry = self
            .redirectors
            .get_mut(id)
            .ok_or_else(|| format!("redirector {} not found", id))?;
        entry.health = RedirectorHealth::Healthy;
        entry.last_heartbeat = now_secs();
        Ok(entry.clone())
    }

    /// Remove a redirector by ID.
    pub fn remove(&self, id: &str) -> Result<RedirectorEntry, String> {
        self.redirectors
            .remove(id)
            .map(|(_, v)| {
                tracing::info!(id = %v.id, url = %v.url, "redirector removed");
                v
            })
            .ok_or_else(|| format!("redirector {} not found", id))
    }

    /// Remove a redirector by URL.
    pub fn remove_by_url(&self, url: &str) -> Result<RedirectorEntry, String> {
        let id = self
            .redirectors
            .iter()
            .find(|e| e.value().url == url)
            .map(|e| e.key().clone())
            .ok_or_else(|| format!("no redirector with URL {}", url))?;
        self.remove(&id)
    }

    /// Mark stale redirectors (no heartbeat for `stale_timeout_secs`).
    pub fn mark_stale(&self) -> Vec<String> {
        let now = now_secs();
        let threshold = now.saturating_sub(self.stale_timeout_secs);
        let mut stale_ids = Vec::new();
        for mut entry in self.redirectors.iter_mut() {
            if entry.health == RedirectorHealth::Healthy
                && entry.last_heartbeat < threshold
            {
                tracing::warn!(
                    id = %entry.id,
                    url = %entry.url,
                    last_heartbeat = entry.last_heartbeat,
                    "marking redirector as stale"
                );
                entry.health = RedirectorHealth::Stale;
                stale_ids.push(entry.id.clone());
            }
        }
        stale_ids
    }

    /// List all registered redirectors.
    pub fn list(&self) -> Vec<RedirectorEntry> {
        self.redirectors.iter().map(|e| e.value().clone()).collect()
    }

    /// Get healthy redirectors for a given profile, in registration order.
    /// Used to build the agent's redirector chain configuration.
    pub fn healthy_for_profile(&self, profile_name: &str) -> Vec<RedirectorEntry> {
        self.redirectors
            .iter()
            .filter(|e| {
                e.value().health == RedirectorHealth::Healthy
                    && e.value().profile_name == profile_name
            })
            .map(|e| e.value().clone())
            .collect()
    }
}

/// Current time as UNIX timestamp in seconds.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── API request/response types ───────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RegisterRequest {
    /// The URL agents should connect to.
    pub url: String,
    /// Malleable profile name this redirector serves.
    pub profile_name: String,
    /// External address the redirector sees itself as.
    #[serde(default)]
    pub external_addr: String,
    /// Domain fronting domain for this redirector.
    #[serde(default)]
    pub front_domain: Option<String>,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub id: String,
    pub url: String,
    pub profile_name: String,
}

#[derive(Deserialize)]
pub struct HeartbeatRequest {
    pub id: String,
}

#[derive(Serialize)]
pub struct HeartbeatResponse {
    pub status: String,
}

#[derive(Deserialize)]
pub struct RemoveRequest {
    /// Redirector ID or URL to remove.
    pub identifier: String,
}

#[derive(Serialize)]
pub struct ListResponse {
    pub redirectors: Vec<RedirectorEntry>,
}

#[derive(Serialize)]
pub struct AgentConfigResponse {
    /// Ordered list of redirector URLs for the agent to try.
    pub redirectors: Vec<RedirectorConfigEntry>,
}

#[derive(Serialize, Clone)]
pub struct RedirectorConfigEntry {
    pub url: String,
    pub headers: std::collections::HashMap<String, String>,
    pub profile_name: String,
    /// Domain fronting domain for this redirector (overrides the global front_domain).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub front_domain: Option<String>,
}

// ── API handlers ─────────────────────────────────────────────────────────────

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/redirector/register", post(handle_register))
        .route("/redirector/heartbeat", post(handle_heartbeat))
        .route("/redirector/list", get(handle_list))
        .route("/redirector/remove", post(handle_remove))
        .route("/redirector/agent-config/:profile", get(handle_agent_config))
        .with_state(state)
}

pub async fn handle_register(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<RegisterResponse>), (StatusCode, String)> {
    // Validate URL.
    if req.url.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "url is required".to_string()));
    }
    if req.profile_name.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "profile_name is required".to_string()));
    }

    let entry = state
        .redirector_state
        .register(req.url, req.profile_name, req.external_addr, req.front_domain);

    Ok((
        StatusCode::OK,
        Json(RegisterResponse {
            id: entry.id,
            url: entry.url,
            profile_name: entry.profile_name,
        }),
    ))
}

pub async fn handle_heartbeat(
    State(state): State<Arc<AppState>>,
    Json(req): Json<HeartbeatRequest>,
) -> Result<Json<HeartbeatResponse>, (StatusCode, String)> {
    let entry = state
        .redirector_state
        .heartbeat(&req.id)
        .map_err(|e| (StatusCode::NOT_FOUND, e))?;
    Ok(Json(HeartbeatResponse {
        status: entry.health.to_string(),
    }))
}

pub async fn handle_list(
    State(state): State<Arc<AppState>>,
) -> Json<ListResponse> {
    Json(ListResponse {
        redirectors: state.redirector_state.list(),
    })
}

pub async fn handle_remove(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RemoveRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    // Try as ID first, then as URL.
    if state.redirector_state.remove(&req.identifier).is_ok() {
        return Ok(StatusCode::NO_CONTENT);
    }
    state
        .redirector_state
        .remove_by_url(&req.identifier)
        .map_err(|e| (StatusCode::NOT_FOUND, e))?;
    Ok(StatusCode::NO_CONTENT)
}

/// Return the redirector chain configuration for agents using a specific
/// profile. This is called by agents at startup to discover their redirectors.
pub async fn handle_agent_config(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(profile): axum::extract::Path<String>,
) -> Json<AgentConfigResponse> {
    let entries = state.redirector_state.healthy_for_profile(&profile);
    let configs = entries
        .into_iter()
        .map(|e| RedirectorConfigEntry {
            url: e.url,
            headers: std::collections::HashMap::new(),
            profile_name: e.profile_name,
            front_domain: e.front_domain,
        })
        .collect();
    Json(AgentConfigResponse {
        redirectors: configs,
    })
}

// ── Stale detection background task ──────────────────────────────────────────

/// Spawn a background task that periodically marks stale redirectors.
pub fn spawn_stale_detector(state: Arc<AppState>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            let stale = state.redirector_state.mark_stale();
            if !stale.is_empty() {
                tracing::info!(count = stale.len(), "marked stale redirectors");
            }
        }
    });
}
