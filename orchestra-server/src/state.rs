//! Shared application state: the agent registry and pending-task table.
//!
//! ## Identity model
//!
//! The registry is keyed by a server-assigned **connection ID** (`Uuid`), not
//! by the agent-reported `agent_id`.  A malicious agent cannot hijack another
//! agent's slot by claiming its `agent_id`; the worst it can do is add a
//! duplicate entry under its own connection ID, which the operator can see in
//! the dashboard and clean up by closing the rogue connection.
//!
//! ## `AgentId` newtype
//!
//! An [`AgentId`] wraps a `String` to distinguish agent identifiers from other
//! strings (connection IDs, hostnames, operator IDs).  This prevents accidental
//! misuse — e.g. passing a `connection_id` where an `agent_id` is expected.

use crate::audit::AuditLog;
use crate::config::{OperatorRecord, ServerConfig};
use crate::redirector::RedirectorState;
use chrono::{DateTime, Utc};
use common::{LockedSecret, Message};
use dashmap::{DashMap, DashSet};
use rand::RngCore;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio::sync::{mpsc, oneshot, RwLock};

// ── AgentId newtype ────────────────────────────────────────────────────

/// Type-safe wrapper around an agent identifier string.
///
/// Prevents accidental confusion between `agent_id`, `connection_id`,
/// `hostname`, and other string-typed identifiers.  The inner value is the
/// agent's self-reported identifier (e.g. `"DESKTOP-WIN10-agent-01"`).
///
/// Implements the usual traits for use as `HashMap` keys, `DashMap` keys,
/// Axum path extraction, JSON (de)serialization, etc.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct AgentId(pub String);

impl AgentId {
    /// Create a new `AgentId` from a string.
    #[inline]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Borrow the inner string.
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for AgentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for AgentId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for AgentId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl std::str::FromStr for AgentId {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_string()))
    }
}

impl AsRef<str> for AgentId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::borrow::Borrow<str> for AgentId {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl PartialEq<String> for AgentId {
    fn eq(&self, other: &String) -> bool {
        &self.0 == other
    }
}

impl PartialEq<str> for AgentId {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<AgentId> for String {
    fn eq(&self, other: &AgentId) -> bool {
        self == &other.0
    }
}

impl<'a> PartialEq<&'a str> for AgentId {
    fn eq(&self, other: &&'a str) -> bool {
        self.0 == *other
    }
}

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
    /// Server-issued mesh certificate for this agent (set on check-in).
    pub mesh_certificate: Option<common::MeshCertificate>,
    /// Last mesh Ed25519 public key reported by the agent heartbeat.
    pub mesh_public_key: Option<[u8; 32]>,
    /// Compartment assigned to this agent (operator-configured).
    pub compartment: Option<String>,
    /// P2-17: The client certificate identity (CN) extracted during the
    /// mTLS handshake.  When set, the agent's self-reported `agent_id`
    /// must match this identity, binding the logical agent identity to
    /// its cryptographic credential.
    pub cert_identity: Option<String>,
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
    pub compartment: Option<String>,
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
            compartment: e.compartment.clone(),
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
    /// Recent link failure reports (bounded, newest first).
    pub link_failures: Vec<LinkFailureRecord>,
}

/// Record of a P2P link failure reported by an agent.
#[derive(Clone, Debug, Serialize)]
pub struct LinkFailureRecord {
    /// Agent that reported the failure.
    pub agent_id: String,
    /// Agent ID of the dead peer.
    pub dead_peer_id: String,
    /// Link type: 0=parent, 1=child, 2=peer.
    pub link_type: u8,
    /// How long the link was alive (seconds).
    pub uptime_secs: u64,
    /// Last known RTT (ms).
    pub latency_ms: u32,
    /// Packet loss ratio (0.0–1.0).
    pub packet_loss: f32,
    /// Estimated bandwidth at time of failure (bps).
    pub bandwidth_bps: u64,
    /// When this report was received by the server.
    pub timestamp: DateTime<Utc>,
}

/// Maximum number of link failure records to keep.
const MAX_LINK_FAILURE_RECORDS: usize = 1000;

pub struct AppState {
    /// Registry keyed by connection_id.
    pub registry: DashMap<String, AgentEntry>,
    pub pending: DashMap<String, oneshot::Sender<Result<String, String>>>,
    pub audit: Arc<AuditLog>,
    /// Legacy single-admin token kept for backward compat and as a fallback
    /// when no `[operators]` section is defined in the config.
    /// Stored as a SHA-256 hash (hex-encoded) so the plaintext never resides
    /// in memory after initialisation.  Compare with
    /// `OperatorRecord::hash_token(presented)` using constant-time equality.
    pub admin_token_hash: String,
    /// Per-operator records keyed by operator ID.  Populated at startup from
    /// the `[operators]` TOML section.  When empty, the legacy `admin_token`
    /// is used instead.
    pub operators: HashMap<String, OperatorRecord>,
    pub command_timeout_secs: u64,
    pub config: ServerConfig,
    /// Agent PSK wrapped in LockedSecret (mlocked + zeroize-on-drop) so the
    /// plaintext never lingers in heap memory.  Use `.as_bytes()` for
    /// constant-time comparisons; never extract into a String.
    pub agent_shared_secret: LockedSecret,
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
    /// Mesh controller with Dijkstra pathfinding for mesh-aware routing.
    pub mesh_controller: RwLock<crate::mesh_controller::MeshController>,
    /// Revoked mesh certificate hashes (SHA-256 of agent_id).  Any agent
    /// whose `agent_id_hash` appears in this set will be rejected during
    /// P2P link handshake and have existing links terminated.
    pub revoked_certificates: DashSet<[u8; 32]>,
    /// P2-16: Reference to the mTLS CnOuVerifier (if mTLS is enabled with
    /// CN/OU restrictions or CRL).  Allows runtime CRL reload via the API
    /// without restarting the server.
    pub mtls_verifier: std::sync::RwLock<Option<std::sync::Arc<crate::tls::CnOuVerifier>>>,
    /// Per-IP rate limiter for authentication endpoints (brute-force
    /// protection).  Each IP gets its own sliding window of ~10 attempts
    /// per 5 minutes.
    pub auth_rate_limiters: crate::auth::PerIpRateLimiter,
    /// Development mode: relaxes certain production security checks (e.g.,
    /// WebSocket localhost origin bypass).  Set via `--dev` CLI flag.
    pub dev_mode: bool,
    /// One-time session IDs for WebSocket authentication.  Maps a random
    /// session UUID to the authenticated operator ID.  Prevents the real
    /// bearer token from being echoed in the `Sec-WebSocket-Protocol`
    /// response header (visible to proxies and browser dev tools).
    pub ws_sessions: DashMap<String, String>,
    /// Shell output buffers keyed by (agent_id, session_id).
    /// Accumulates output from agent `Message::ShellOutput` events for
    /// operator polling via GET /api/agents/:id/shell/:sid/output.
    pub shell_output_buffers:
        DashMap<(String, u32), std::sync::Mutex<std::collections::VecDeque<String>>>,
}

impl AppState {
    pub fn new(
        audit: Arc<AuditLog>,
        admin_token: String,
        command_timeout_secs: u64,
        config: ServerConfig,
        dev_mode: bool,
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
        // P1-17: Hash the admin token at construction so the plaintext
        // never persists in the AppState.
        let admin_token_hash = crate::config::OperatorRecord::hash_token(&admin_token);
        drop(admin_token); // ensure the plaintext is dropped

        // N1-02: Wrap the agent PSK in LockedSecret so it is mlocked and
        // zeroized on drop, preventing plaintext exposure in memory dumps.
        let agent_shared_secret = LockedSecret::new(config.agent_shared_secret.as_bytes());

        Self {
            registry: DashMap::new(),
            pending: DashMap::new(),
            audit,
            admin_token_hash,
            operators,
            command_timeout_secs,
            config,
            agent_shared_secret,
            assigned_seeds: DashSet::new(),
            topology: RwLock::new(TopologyMap::default()),
            redirector_state: RedirectorState::new(),
            mesh_controller: RwLock::new(crate::mesh_controller::MeshController::new()),
            revoked_certificates: DashSet::new(),
            mtls_verifier: std::sync::RwLock::new(None),
            auth_rate_limiters: crate::auth::PerIpRateLimiter::new(
                10,                                     // max attempts per IP
                std::time::Duration::from_secs(60 * 5), // per 5-minute window
            ),
            dev_mode,
            ws_sessions: DashMap::new(),
            shell_output_buffers: DashMap::new(),
        }
    }

    /// Look up a bearer token against the operator store.  Returns the
    /// operator ID and permissions on match, or `None` if no operator matched.
    ///
    /// Comparison is constant-time: the presented token is hashed with
    /// SHA-256, then compared against each stored hash with `subtle::ct_eq`.
    ///
    /// P1-26: Now returns `(String, Vec<String>)` carrying the operator's
    /// permission set so that `require_bearer` can embed it in the
    /// `AuthenticatedUser` extension.
    pub fn authenticate_operator(&self, presented_token: &str) -> Option<(String, Vec<String>)> {
        let presented_hash = OperatorRecord::hash_token(presented_token);
        for op in self.operators.values() {
            let ok: bool = presented_hash
                .as_bytes()
                .ct_eq(op.token_hash.as_bytes())
                .into();
            if ok {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                op.last_seen
                    .store(now, std::sync::atomic::Ordering::Relaxed);
                return Some((op.id.clone(), op.permissions.clone()));
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
        // ── Validation ────────────────────────────────────────────────
        // 1. The reporter must be a known, connected agent.
        if self.find_by_agent_id(reporter_agent_id).is_none() {
            tracing::warn!(
                reporter = %reporter_agent_id,
                "rejected topology report: reporter not in agent registry"
            );
            return;
        }

        let child_ids: Vec<String> = children.iter().map(|c| c.agent_id.clone()).collect();

        // 2. Reject self-referential reports (agent claiming itself as child).
        if child_ids.iter().any(|id| id == reporter_agent_id) {
            tracing::warn!(
                reporter = %reporter_agent_id,
                "rejected topology report: reporter listed itself as a child"
            );
            return;
        }

        // 3. Reject duplicate children in a single report.
        {
            let mut seen = std::collections::HashSet::new();
            for id in &child_ids {
                if !seen.insert(id.as_str()) {
                    tracing::warn!(
                        reporter = %reporter_agent_id,
                        duplicate = %id,
                        "rejected topology report: duplicate child agent_id"
                    );
                    return;
                }
            }
        }

        // Acquire the write lock only after cheap checks pass.
        let mut topo = self.topology.write().await;

        // 4. Each reported child must be either already known in the
        //    topology map *or* present in the agent registry.  Unknown
        //    children are silently rejected to prevent a rogue agent from
        //    polluting the topology with phantom nodes.
        for child_id in &child_ids {
            let known_in_topology = topo.nodes.contains_key(child_id);
            let known_in_registry = self.find_by_agent_id(child_id).is_some();
            if !known_in_topology && !known_in_registry {
                tracing::warn!(
                    reporter = %reporter_agent_id,
                    child = %child_id,
                    "rejected topology report: unknown child agent_id"
                );
                return;
            }
        }

        // 5. Cycle detection: walk from each child's *existing* parent
        //    chain (if any) toward the root and verify it does not pass
        //    through the reporter.  This prevents a child from becoming
        //    its own ancestor.
        for child_id in &child_ids {
            let mut cursor = Some(child_id.clone());
            let mut steps = 0u32;
            let max_depth = topo.nodes.len().saturating_add(1) as u32;
            while let Some(id) = cursor {
                if id == reporter_agent_id {
                    tracing::warn!(
                        reporter = %reporter_agent_id,
                        child = %child_id,
                        "rejected topology report: cycle detected"
                    );
                    return;
                }
                steps += 1;
                if steps > max_depth {
                    // Safety valve: the existing topology has a cycle.
                    // Break out rather than looping forever.
                    tracing::warn!(
                        reporter = %reporter_agent_id,
                        child = %child_id,
                        "rejected topology report: existing topology contains a cycle"
                    );
                    return;
                }
                cursor = topo.nodes.get(&id).and_then(|n| n.parent.clone());
            }
        }

        // ── Apply updates ─────────────────────────────────────────────
        // Determine the reporter's depth.  If the reporter is directly
        // connected (no parent in the topology), depth is 0.
        let reporter_depth = topo
            .nodes
            .get(reporter_agent_id)
            .and_then(|n| n.parent.as_ref())
            .and_then(|parent_id| topo.nodes.get(parent_id))
            .map(|n| n.depth + 1)
            .unwrap_or(0);

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

    /// Record a link failure report from an agent.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_link_failure(
        &self,
        agent_id: &str,
        dead_peer_id: &str,
        link_type: u8,
        uptime_secs: u64,
        latency_ms: u32,
        packet_loss: f32,
        bandwidth_bps: u64,
    ) {
        let mut topo = self.topology.write().await;

        let record = LinkFailureRecord {
            agent_id: agent_id.to_string(),
            dead_peer_id: dead_peer_id.to_string(),
            link_type,
            uptime_secs,
            latency_ms,
            packet_loss,
            bandwidth_bps,
            timestamp: Utc::now(),
        };

        // Insert at front, trim to max capacity.
        topo.link_failures.insert(0, record);
        topo.link_failures.truncate(MAX_LINK_FAILURE_RECORDS);

        // Clean up stale child_link_map entries for the dead link.
        match link_type {
            // child link: agent_id was the parent, dead_peer_id was the child
            1 => {
                topo.child_link_map
                    .remove(&(agent_id.to_string(), dead_peer_id.to_string()));
                // Remove dead child from parent's children list.
                if let Some(parent_node) = topo.nodes.get_mut(agent_id) {
                    parent_node.children.retain(|c| c != dead_peer_id);
                }
                // Clear parent pointer on the dead child.
                if let Some(child_node) = topo.nodes.get_mut(dead_peer_id) {
                    child_node.parent = None;
                }
            }
            // parent link: agent_id was the child, dead_peer_id was the parent
            0 => {
                topo.child_link_map
                    .remove(&(dead_peer_id.to_string(), agent_id.to_string()));
                if let Some(child_node) = topo.nodes.get_mut(agent_id) {
                    child_node.parent = None;
                }
            }
            _ => {}
        }

        tracing::info!(
            %agent_id,
            %dead_peer_id,
            link_type,
            "recorded link failure, total failures recorded: {}",
            topo.link_failures.len()
        );
    }

    /// Generate a Graphviz DOT representation of the current mesh topology.
    ///
    /// Produces a directed graph where each node is an agent and edges
    /// represent parent→child relationships.  Node shape reflects depth:
    /// the server is a doubleoctagon, direct agents are boxes, and deeper
    /// agents are ellipses.
    pub async fn topology_to_dot(&self) -> String {
        let topo = self.topology.read().await;
        let mut dot = String::from("digraph p2p_mesh {\n");
        dot.push_str("    rankdir=TB;\n");
        dot.push_str("    node [fontname=\"monospace\"];\n");
        dot.push_str("    SERVER [shape=doubleoctagon, label=\"Server\"];\n\n");

        for (agent_id, node) in &topo.nodes {
            let label_short = if agent_id.len() > 12 {
                &agent_id[..12]
            } else {
                agent_id
            };
            let shape = if node.depth == 0 { "box" } else { "ellipse" };
            dot.push_str(&format!(
                "    \"{aid}\" [shape={shape}, label=\"{label_short}\\nd={d}\\nchildren={nc}\"];\n",
                aid = agent_id,
                shape = shape,
                label_short = label_short,
                d = node.depth,
                nc = node.children.len(),
            ));

            // Draw edge from parent to child (or server to root agent).
            match &node.parent {
                Some(parent_id) => {
                    dot.push_str(&format!(
                        "    \"{pid}\" -> \"{aid}\";\n",
                        pid = parent_id,
                        aid = agent_id,
                    ));
                }
                None => {
                    // Directly connected to server.
                    dot.push_str(&format!("    SERVER -> \"{aid}\";\n", aid = agent_id,));
                }
            }
        }

        dot.push_str("}\n");
        dot
    }

    /// Return a summary of mesh topology statistics.
    pub async fn mesh_stats(&self) -> MeshStats {
        let topo = self.topology.read().await;
        let total_nodes = topo.nodes.len();
        let max_depth = topo.nodes.values().map(|n| n.depth).max().unwrap_or(0);
        let direct_agents = topo.nodes.values().filter(|n| n.parent.is_none()).count();
        let total_edges: usize = topo.nodes.values().map(|n| n.children.len()).sum();
        let total_peer_links = topo.child_link_map.len();
        let recent_failures = topo.link_failures.len();

        // Compute average fan-out (children per non-leaf node).
        let non_leaf_count = topo
            .nodes
            .values()
            .filter(|n| !n.children.is_empty())
            .count();
        let avg_fanout = if non_leaf_count > 0 {
            total_edges as f64 / non_leaf_count as f64
        } else {
            0.0
        };

        MeshStats {
            total_nodes,
            max_depth,
            direct_agents,
            total_edges,
            total_peer_links,
            recent_failures,
            avg_fanout,
        }
    }
}

/// Send a `Message` to a child agent through the P2P relay chain.
///
/// If the child is directly connected, sends directly via its `tx`.
/// Otherwise, wraps the message in `P2pToChild` routing envelopes and
/// sends it through the first directly-connected hop.
pub async fn send_to_child(
    state: &AppState,
    child_agent_id: &str,
    msg: &Message,
) -> anyhow::Result<()> {
    // If the child is directly connected, send directly.
    if let Some(entry) = state.find_by_agent_id(child_agent_id) {
        return entry
            .tx
            .send(msg.clone())
            .await
            .map_err(|_| anyhow::anyhow!("child agent disconnected"));
    }

    // Not directly connected — route through P2P relay chain.
    let route = state
        .route_to_agent(child_agent_id)
        .await
        .ok_or_else(|| anyhow::anyhow!("no route to child agent '{}'", child_agent_id))?;

    // Serialize the inner message.
    let mut payload = bincode::serde::encode_to_vec(msg, bincode::config::legacy())?;

    // Wrap in routing blobs from innermost hop to outermost,
    // skipping the first hop (its link_id goes in the P2pToChild envelope).
    for (_, link_id) in route.iter().skip(1).rev() {
        let mut blob = Vec::with_capacity(4 + 4 + payload.len());
        blob.extend_from_slice(&link_id.to_le_bytes());
        blob.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        blob.extend_from_slice(&payload);
        payload = blob;
    }

    // Send the outermost P2pToChild to the directly-connected agent.
    let first_hop_agent_id = &route[0].0;
    let first_hop_entry = state
        .find_by_agent_id(first_hop_agent_id)
        .ok_or_else(|| anyhow::anyhow!("first-hop agent '{}' disconnected", first_hop_agent_id))?;

    let first_link_id = route[0].1;
    let p2p_msg = Message::P2pToChild {
        child_link_id: first_link_id,
        data: payload,
    };

    first_hop_entry
        .tx
        .send(p2p_msg)
        .await
        .map_err(|_| anyhow::anyhow!("first-hop agent send failed"))?;

    Ok(())
}

/// Summary statistics for the P2P mesh topology.
#[derive(Clone, Debug, Serialize)]
pub struct MeshStats {
    /// Total number of nodes in the topology.
    pub total_nodes: usize,
    /// Maximum depth from the server.
    pub max_depth: u32,
    /// Number of directly-connected agents (depth 0).
    pub direct_agents: usize,
    /// Total parent→child edges.
    pub total_edges: usize,
    /// Total entries in the peer link map.
    pub total_peer_links: usize,
    /// Number of recent link failure records.
    pub recent_failures: usize,
    /// Average number of children per non-leaf node.
    pub avg_fanout: f64,
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
