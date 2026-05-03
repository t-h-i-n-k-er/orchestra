//! Server-side mesh controller with Dijkstra pathfinding.
//!
//! Maintains a weighted graph of all known agents (both directly connected
//! and relayed) and provides shortest-path routing.  The topology is updated
//! from both regular `P2pTopologyReport` (parent→child tree edges) and
//! `P2pEnhancedTopologyReport` (peer links + route entries with quality).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use crate::state::AppState;

// ── Data types ────────────────────────────────────────────────────────────

/// One node (agent) in the mesh graph.
#[derive(Clone, Debug, Default)]
pub struct MeshNode {
    /// Agent ID.
    pub agent_id: String,
    /// Whether this agent is directly connected to the server.
    pub directly_connected: bool,
    /// Total number of links this agent has.
    pub link_count: u32,
    /// Best known link quality to any neighbor (0.0–1.0).
    pub best_quality: f32,
    /// Number of hops from the server (0 = direct).
    pub hop_count: u32,
    /// Transport types used by this agent's links.
    pub transports: HashSet<String>,
}

/// One edge in the mesh graph (bidirectional).
#[derive(Clone, Debug)]
pub struct MeshEdge {
    /// Source agent_id.
    pub from: String,
    /// Destination agent_id.
    pub to: String,
    /// Link quality (0.0–1.0), higher is better.
    pub quality: f32,
    /// Latency in milliseconds.
    pub latency_ms: u32,
    /// Link type: 0 = parent/child, 1 = peer, 2 = mesh.
    pub link_type: u8,
    /// Transport: "tcp", "smb", etc.
    pub transport: String,
}

/// Weighted adjacency list for the mesh graph.
pub type AdjacencyMap = HashMap<String, Vec<MeshEdge>>;

/// Full mesh topology snapshot.
#[derive(Clone, Debug, Default)]
pub struct MeshTopology {
    /// Nodes keyed by agent_id.
    pub nodes: HashMap<String, MeshNode>,
    /// Adjacency list keyed by source agent_id.
    pub edges: AdjacencyMap,
    /// Edge count.
    pub edge_count: usize,
    /// When this snapshot was built (epoch seconds).
    pub built_at: u64,
}

/// Result of a shortest-path query.
#[derive(Clone, Debug)]
pub struct MeshRoute {
    /// Ordered list of agent_ids from source to destination (inclusive).
    pub path: Vec<String>,
    /// Total cost (lower is better).
    pub cost: f64,
    /// Number of hops (path.len() - 1).
    pub hop_count: usize,
}

/// Statistics about the mesh.
#[derive(Clone, Debug, serde::Serialize)]
pub struct MeshStats {
    pub total_nodes: usize,
    pub total_edges: usize,
    pub directly_connected: usize,
    pub avg_hop_count: f64,
    pub max_hop_count: u32,
}

// ── MeshController ────────────────────────────────────────────────────────

/// Server-side mesh controller.
///
/// Builds a weighted graph from topology reports and provides Dijkstra
/// shortest-path routing.  The controller is owned by `AppState` and
/// protected by an async `RwLock`.
#[derive(Debug, Default)]
pub struct MeshController {
    topology: MeshTopology,
}

impl MeshController {
    pub fn new() -> Self {
        Self {
            topology: MeshTopology::default(),
        }
    }

    // ── Topology updates ──────────────────────────────────────────────

    /// Rebuild the mesh topology from the existing `TopologyMap` plus any
    /// enhanced topology data.  Called periodically or on demand.
    pub fn rebuild_from_topology_map(
        &mut self,
        topo_nodes: &HashMap<String, crate::state::TopologyNode>,
        directly_connected: &HashSet<String>,
    ) {
        let mut new_topo = MeshTopology::default();

        // Create nodes.
        for (agent_id, node) in topo_nodes {
            let is_direct = directly_connected.contains(agent_id);
            let mesh_node = MeshNode {
                agent_id: agent_id.clone(),
                directly_connected: is_direct,
                hop_count: node.depth,
                ..Default::default()
            };
            new_topo.nodes.insert(agent_id.clone(), mesh_node);
        }

        // Create edges from parent→child relationships.
        for (agent_id, node) in topo_nodes {
            for child_id in &node.children {
                // Parent→child edge.
                new_topo.edges
                    .entry(agent_id.clone())
                    .or_default()
                    .push(MeshEdge {
                        from: agent_id.clone(),
                        to: child_id.clone(),
                        quality: 0.8, // Default quality for tree edges
                        latency_ms: 50, // Default estimate
                        link_type: 0,
                        transport: "tcp".to_string(),
                    });

                // Child→parent edge (bidirectional).
                new_topo.edges
                    .entry(child_id.clone())
                    .or_default()
                    .push(MeshEdge {
                        from: child_id.clone(),
                        to: agent_id.clone(),
                        quality: 0.8,
                        latency_ms: 50,
                        link_type: 0,
                        transport: "tcp".to_string(),
                    });
            }
        }

        new_topo.edge_count = new_topo.edges.values().map(|v| v.len()).sum();
        new_topo.built_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.topology = new_topo;
    }

    /// Merge enhanced topology data from an agent's
    /// `P2pEnhancedTopologyReport`.  This adds peer links and updates
    /// quality/latency information.
    pub fn merge_enhanced_topology(
        &mut self,
        agent_id: &str,
        peers: &[common::P2pPeerInfo],
        routes: &[common::P2pRouteInfo],
    ) {
        // Ensure the reporting agent has a node entry.
        self.topology
            .nodes
            .entry(agent_id.to_string())
            .or_insert_with(|| MeshNode {
                agent_id: agent_id.to_string(),
                ..Default::default()
            });

        // Update node metadata.
        if let Some(node) = self.topology.nodes.get_mut(agent_id) {
            node.link_count = peers.len() as u32;
            let mut best_q = 0.0f32;
            for p in peers {
                if p.quality > best_q {
                    best_q = p.quality;
                }
            }
            node.best_quality = best_q;
            node.transports.clear();
            for p in peers {
                let t = match p.link_type {
                    0 => "tcp",
                    1 => "smb",
                    _ => "unknown",
                };
                node.transports.insert(t.to_string());
            }
        }

        // Add peer edges.
        for peer in peers {
            let peer_id = &peer.peer_id;

            // Ensure the peer has a node entry.
            self.topology
                .nodes
                .entry(peer_id.clone())
                .or_insert_with(|| MeshNode {
                    agent_id: peer_id.clone(),
                    ..Default::default()
                });

            // Compute edge weight from quality (inverse: higher quality →
            // lower weight).
            let quality = peer.quality.clamp(0.01, 1.0);

            // Determine link type: if we have a tree edge for this pair,
            // keep it as parent/child (0); otherwise mark as peer (1).
            let link_type = peer.link_type; // Use the agent-reported type

            let transport = match peer.link_type {
                0 => "tcp",
                1 => "smb",
                _ => "unknown",
            };

            // Add bidirectional edge.
            let out_edge = MeshEdge {
                from: agent_id.to_string(),
                to: peer_id.clone(),
                quality,
                latency_ms: peer.latency_ms,
                link_type,
                transport: transport.to_string(),
            };
            let in_edge = MeshEdge {
                from: peer_id.clone(),
                to: agent_id.to_string(),
                quality,
                latency_ms: peer.latency_ms,
                link_type,
                transport: transport.to_string(),
            };

            let adj = self.topology.edges.entry(agent_id.to_string()).or_default();
            // Remove existing edge to the same peer if present.
            adj.retain(|e| e.to != *peer_id);
            adj.push(out_edge);

            let adj = self.topo_mut().edges.entry(peer_id.clone()).or_default();
            adj.retain(|e| e.to != agent_id);
            adj.push(in_edge);
        }

        // Update hop counts from route info.
        for route in routes {
            // Route hop_count from the agent's perspective tells us
            // the distance to that destination.
            if let Some(node) = self.topology.nodes.get_mut(&route.destination) {
                // Only update if this gives us a lower hop count.
                let new_hops = route.hop_count as u32;
                if new_hops < node.hop_count || node.hop_count == 0 {
                    node.hop_count = new_hops;
                }
            }
        }

        // Recount edges.
        self.topology.edge_count = self.topology.edges.values().map(|v| v.len()).sum();
    }

    // ── Dijkstra shortest path ────────────────────────────────────────

    /// Compute the shortest path from `source` to `destination` using
    /// Dijkstra's algorithm with quality-weighted edges.
    ///
    /// Edge weight = `1.0 - quality + latency_ms as f64 / 10000.0`.
    /// This balances link quality against latency.
    pub fn shortest_path(&self, source: &str, destination: &str) -> Option<MeshRoute> {
        if source == destination {
            return Some(MeshRoute {
                path: vec![source.to_string()],
                cost: 0.0,
                hop_count: 0,
            });
        }

        let mut dist: HashMap<String, f64> = HashMap::new();
        let mut prev: HashMap<String, String> = HashMap::new();
        let mut visited: HashSet<String> = HashSet::new();

        // Use a BTreeMap as a simple priority queue.  We convert f64 to a
        // sortable representation by using the bit pattern (which preserves
        // ordering for non-NaN values).
        let mut pq: BTreeMap<(u64, String), ()> = BTreeMap::new();

        // Initialize all nodes with infinity.
        for node_id in self.topology.nodes.keys() {
            dist.insert(node_id.clone(), f64::INFINITY);
        }
        dist.insert(source.to_string(), 0.0);
        pq.insert((0.0f64.to_bits(), source.to_string()), ());

        while let Some(((cost_bits, current), _)) = pq.pop_first() {
            let cost = f64::from_bits(cost_bits);
            if visited.contains(&current) {
                continue;
            }
            visited.insert(current.clone());

            if current == destination {
                break;
            }

            // Get neighbors.
            if let Some(neighbors) = self.topology.edges.get(&current) {
                for edge in neighbors {
                    if visited.contains(&edge.to) {
                        continue;
                    }
                    // Weight = inverse quality + latency factor.
                    let weight = (1.0 - edge.quality as f64)
                        + (edge.latency_ms as f64 / 10000.0);
                    let new_dist = cost + weight;

                    let cur_dist = dist.get(&edge.to).copied().unwrap_or(f64::INFINITY);
                    if new_dist < cur_dist {
                        dist.insert(edge.to.clone(), new_dist);
                        prev.insert(edge.to.clone(), current.clone());
                        pq.insert((new_dist.to_bits(), edge.to.clone()), ());
                    }
                }
            }
        }

        // Reconstruct path.
        let final_cost = dist.get(destination).copied().unwrap_or(f64::INFINITY);
        if final_cost == f64::INFINITY {
            return None;
        }

        let mut path = Vec::new();
        let mut current = destination.to_string();
        while let Some(p) = prev.get(&current) {
            path.push(current);
            current = p.clone();
        }
        path.push(source.to_string());
        path.reverse();

        Some(MeshRoute {
            hop_count: path.len() - 1,
            cost: final_cost,
            path,
        })
    }

    /// Find the shortest path from any directly-connected agent to the
    /// given destination.  Returns the best route.
    pub fn route_from_server(&self, destination: &str) -> Option<MeshRoute> {
        let direct_nodes: Vec<String> = self
            .topology
            .nodes
            .values()
            .filter(|n| n.directly_connected)
            .map(|n| n.agent_id.clone())
            .collect();

        let mut best: Option<MeshRoute> = None;
        for src in &direct_nodes {
            if let Some(route) = self.shortest_path(src, destination) {
                if best.as_ref().map_or(true, |b| route.cost < b.cost) {
                    best = Some(route);
                }
            }
        }
        best
    }

    /// Broadcast route: find paths from each directly-connected agent to
    /// all other agents.  Returns a map of destination → route.
    pub fn broadcast_routes(&self) -> HashMap<String, MeshRoute> {
        let direct_nodes: Vec<String> = self
            .topology
            .nodes
            .values()
            .filter(|n| n.directly_connected)
            .map(|n| n.agent_id.clone())
            .collect();

        let mut routes = HashMap::new();
        for target in self.topology.nodes.keys() {
            // Skip directly-connected agents (we can reach them directly).
            if direct_nodes.iter().any(|d| d == target) {
                continue;
            }
            if let Some(route) = self.route_from_server(target) {
                routes.insert(target.clone(), route);
            }
        }
        routes
    }

    // ── Mesh stats ────────────────────────────────────────────────────

    /// Compute mesh statistics.
    pub fn stats(&self) -> MeshStats {
        let total_nodes = self.topology.nodes.len();
        let directly_connected = self
            .topology
            .nodes
            .values()
            .filter(|n| n.directly_connected)
            .count();

        let mut max_hop = 0u32;
        let mut total_hops = 0u64;
        let mut hop_count = 0u64;
        for node in self.topology.nodes.values() {
            if node.hop_count > 0 {
                total_hops += node.hop_count as u64;
                hop_count += 1;
            }
            if node.hop_count > max_hop {
                max_hop = node.hop_count;
            }
        }

        MeshStats {
            total_nodes,
            total_edges: self.topology.edge_count,
            directly_connected,
            avg_hop_count: if hop_count > 0 {
                total_hops as f64 / hop_count as f64
            } else {
                0.0
            },
            max_hop_count: max_hop,
        }
    }

    /// Get a reference to the current topology.
    pub fn topology(&self) -> &MeshTopology {
        &self.topology
    }

    /// Get a mutable reference to the topology.
    fn topo_mut(&mut self) -> &mut MeshTopology {
        &mut self.topology
    }

    /// Get a node by agent_id.
    pub fn get_node(&self, agent_id: &str) -> Option<&MeshNode> {
        self.topology.nodes.get(agent_id)
    }

    /// Get all edges for an agent.
    pub fn get_edges(&self, agent_id: &str) -> Vec<&MeshEdge> {
        self.topology
            .edges
            .get(agent_id)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }
}

// ── Integration with AppState ─────────────────────────────────────────────

/// Periodically rebuild the mesh topology from the `TopologyMap`.
pub async fn rebuild_mesh_topology(state: &Arc<AppState>) {
    let (topo_nodes, direct_agents) = {
        let topo = state.topology.read().await;
        let nodes = topo.nodes.clone();
        // Collect directly-connected agent IDs.
        let direct: HashSet<String> = state
            .registry
            .iter()
            .map(|e| e.value().agent_id.clone())
            .collect();
        (nodes, direct)
    };

    let mut mesh = state.mesh_controller.write().await;
    mesh.rebuild_from_topology_map(&topo_nodes, &direct_agents);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shortest_path_simple() {
        let mut ctrl = MeshController::new();

        // Build a simple topology: A — B — C
        ctrl.topology.nodes.insert(
            "A".to_string(),
            MeshNode {
                agent_id: "A".to_string(),
                directly_connected: true,
                ..Default::default()
            },
        );
        ctrl.topology.nodes.insert(
            "B".to_string(),
            MeshNode {
                agent_id: "B".to_string(),
                ..Default::default()
            },
        );
        ctrl.topology.nodes.insert(
            "C".to_string(),
            MeshNode {
                agent_id: "C".to_string(),
                ..Default::default()
            },
        );

        ctrl.topology.edges.insert(
            "A".to_string(),
            vec![MeshEdge {
                from: "A".to_string(),
                to: "B".to_string(),
                quality: 0.9,
                latency_ms: 10,
                link_type: 0,
                transport: "tcp".to_string(),
            }],
        );
        ctrl.topology.edges.insert(
            "B".to_string(),
            vec![
                MeshEdge {
                    from: "B".to_string(),
                    to: "A".to_string(),
                    quality: 0.9,
                    latency_ms: 10,
                    link_type: 0,
                    transport: "tcp".to_string(),
                },
                MeshEdge {
                    from: "B".to_string(),
                    to: "C".to_string(),
                    quality: 0.7,
                    latency_ms: 50,
                    link_type: 0,
                    transport: "tcp".to_string(),
                },
            ],
        );
        ctrl.topology.edges.insert(
            "C".to_string(),
            vec![MeshEdge {
                from: "C".to_string(),
                to: "B".to_string(),
                quality: 0.7,
                latency_ms: 50,
                link_type: 0,
                transport: "tcp".to_string(),
            }],
        );
        ctrl.topology.edge_count = 4;

        // A → C should go A → B → C.
        let route = ctrl.shortest_path("A", "C").unwrap();
        assert_eq!(route.path, vec!["A", "B", "C"]);
        assert_eq!(route.hop_count, 2);
    }

    #[test]
    fn test_shortest_path_no_route() {
        let mut ctrl = MeshController::new();
        ctrl.topology.nodes.insert(
            "A".to_string(),
            MeshNode {
                agent_id: "A".to_string(),
                directly_connected: true,
                ..Default::default()
            },
        );
        ctrl.topology.nodes.insert(
            "Z".to_string(),
            MeshNode {
                agent_id: "Z".to_string(),
                ..Default::default()
            },
        );

        let route = ctrl.shortest_path("A", "Z");
        assert!(route.is_none());
    }

    #[test]
    fn test_mesh_stats() {
        let mut ctrl = MeshController::new();
        ctrl.topology.nodes.insert(
            "A".to_string(),
            MeshNode {
                agent_id: "A".to_string(),
                directly_connected: true,
                hop_count: 0,
                ..Default::default()
            },
        );
        ctrl.topology.nodes.insert(
            "B".to_string(),
            MeshNode {
                agent_id: "B".to_string(),
                hop_count: 1,
                ..Default::default()
            },
        );
        ctrl.topology.nodes.insert(
            "C".to_string(),
            MeshNode {
                agent_id: "C".to_string(),
                hop_count: 2,
                ..Default::default()
            },
        );
        ctrl.topology.edge_count = 4;

        let stats = ctrl.stats();
        assert_eq!(stats.total_nodes, 3);
        assert_eq!(stats.directly_connected, 1);
        assert_eq!(stats.max_hop_count, 2);
        assert!((stats.avg_hop_count - 1.5).abs() < 0.01);
    }
}
