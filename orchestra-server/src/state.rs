//! Shared application state: the agent registry and pending-task table.

use crate::audit::AuditLog;
use common::Message;
use dashmap::DashMap;
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

/// One connected agent.
#[derive(Clone)]
pub struct AgentEntry {
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
    pub agent_id: String,
    pub hostname: String,
    pub last_seen: u64,
    pub peer: String,
}

impl From<&AgentEntry> for AgentView {
    fn from(e: &AgentEntry) -> Self {
        Self {
            agent_id: e.agent_id.clone(),
            hostname: e.hostname.clone(),
            last_seen: e.last_seen,
            peer: e.peer.clone(),
        }
    }
}

pub struct AppState {
    pub registry: DashMap<String, AgentEntry>,
    pub pending: DashMap<String, oneshot::Sender<Result<String, String>>>,
    pub audit: Arc<AuditLog>,
    pub admin_token: String,
    pub command_timeout_secs: u64,
}

impl AppState {
    pub fn new(audit: Arc<AuditLog>, admin_token: String, command_timeout_secs: u64) -> Self {
        Self {
            registry: DashMap::new(),
            pending: DashMap::new(),
            audit,
            admin_token,
            command_timeout_secs,
        }
    }

    pub fn list_agents(&self) -> Vec<AgentView> {
        self.registry.iter().map(|e| AgentView::from(e.value())).collect()
    }
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
