//! Shared application state: the agent registry and pending-task table.
//!
//! ## Identity model
//!
//! The registry is keyed by a server-assigned **connection ID** (`Uuid`), not
//! by the agent-reported `agent_id`.  A malicious agent cannot hijack another
//! agent's slot by claiming its `agent_id`; the worst it can do is add a
//! duplicate entry under its own connection ID, which the operator can see in
//! the dashboard and clean up by closing the rogue connection.

use crate::audit::AuditLog;
use crate::config::ServerConfig;
use common::Message;
use dashmap::DashMap;
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

/// One connected agent.  `connection_id` is assigned by the server on accept.
/// `agent_id` and `hostname` are whatever the agent reported in its Heartbeat.
#[derive(Clone)]
pub struct AgentEntry {
    /// Server-assigned, per-connection UUID — the canonical registry key.
    pub connection_id: String,
    /// Self-reported agent identifier (informational; not trusted for routing).
    pub agent_id: String,
    pub hostname: String,
    pub last_seen: u64,
    /// Channel into the per-connection writer task.
    pub tx: mpsc::Sender<Message>,
    pub peer: String,
}

/// JSON-friendly snapshot of an agent for the dashboard.
#[derive(Serialize, Clone)]
pub struct AgentView {
    pub connection_id: String,
    pub agent_id: String,
    pub hostname: String,
    pub last_seen: u64,
    pub peer: String,
}

impl From<&AgentEntry> for AgentView {
    fn from(e: &AgentEntry) -> Self {
        Self {
            connection_id: e.connection_id.clone(),
            agent_id: e.agent_id.clone(),
            hostname: e.hostname.clone(),
            last_seen: e.last_seen,
            peer: e.peer.clone(),
        }
    }
}

pub struct AppState {
    /// Registry keyed by connection_id.
    pub registry: DashMap<String, AgentEntry>,
    pub pending: DashMap<String, oneshot::Sender<Result<String, String>>>,
    pub audit: Arc<AuditLog>,
    pub admin_token: String,
    pub command_timeout_secs: u64,
    pub config: ServerConfig,
}

impl AppState {
    pub fn new(
        audit: Arc<AuditLog>,
        admin_token: String,
        command_timeout_secs: u64,
        config: ServerConfig,
    ) -> Self {
        Self {
            registry: DashMap::new(),
            pending: DashMap::new(),
            audit,
            admin_token,
            command_timeout_secs,
            config,
        }
    }

    pub fn list_agents(&self) -> Vec<AgentView> {
        self.registry
            .iter()
            .map(|e| AgentView::from(e.value()))
            .collect()
    }

    /// Find an agent entry by its *reported* `agent_id`.
    /// When multiple connections report the same `agent_id` (e.g. a reconnect
    /// racing with the old socket cleanup) the most-recently-seen one wins.
    pub fn find_by_agent_id(&self, agent_id: &str) -> Option<AgentEntry> {
        self.registry
            .iter()
            .filter(|e| e.value().agent_id == agent_id)
            .max_by_key(|e| e.value().last_seen)
            .map(|e| e.value().clone())
    }

    /// Find an agent entry by its server-assigned `connection_id`.
    pub fn find_by_connection_id(&self, connection_id: &str) -> Option<AgentEntry> {
        self.registry.get(connection_id).map(|e| e.value().clone())
    }
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
