//! P2P mesh wire-protocol types and framing.
//!
//! Defines the frame format used by agent-to-agent P2P links.  Each frame
//! carries a 10-byte header followed by an encrypted payload:
//!
//! ```text
//!  Offset  Size  Field
//!  ------  ----  -----
//!  0       1     frame_type   (P2pFrameType discriminant)
//!  1       1     reserved     (MUST be zero on transmit; ignored on receive)
//!  2       4     link_id      (little-endian u32 — random link identifier)
//!  6       4     payload_len  (little-endian u32 — byte length of `payload`)
//!  10      …     payload      (ChaCha20-Poly1305 ciphertext + 16-byte tag)
//! ```
//!
//! The payload key is derived per-link via X25519 ECDH during link
//! establishment.  The 16-byte Poly1305 authentication tag is appended to
//! the ciphertext by the AEAD construction and is included in `payload_len`.

use serde::{Deserialize, Serialize};

/// Maximum allowed payload size (16 MiB, matching the SMB pipe cap).
pub const MAX_PAYLOAD_BYTES: u32 = 16 * 1024 * 1024;

/// Wire header size in bytes: frame_type(1) + reserved(1) + link_id(4) + payload_len(4).
pub const HEADER_SIZE: usize = 10;

/// P2P frame type discriminant.
///
/// Each variant maps to a single `u8` on the wire.  Unknown discriminants
/// MUST cause the receiver to discard the frame and log a warning.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum P2pFrameType {
    /// Child → Parent: request to establish a link.
    LinkRequest = 0x01,
    /// Parent → Child: accept the link request.
    LinkAccept = 0x02,
    /// Parent → Child: reject the link request.
    LinkReject = 0x03,
    /// Bidirectional: keep-alive / heartbeat.
    LinkHeartbeat = 0x04,
    /// Bidirectional: graceful link teardown.
    LinkDisconnect = 0x05,
    /// Parent → Server or Server → Child: forward C2 data.
    DataForward = 0x10,
    /// Acknowledgment for forwarded data.
    DataAck = 0x11,
    /// Child → Parent: report child's own children for topology awareness.
    TopologyReport = 0x20,
    /// Distance-vector routing table broadcast (periodic, every 60 s).
    RouteUpdate = 0x30,
    /// On-demand route probe — discover path to a specific destination.
    RouteProbe = 0x31,
    /// Reply to a `RouteProbe` containing discovered route info.
    RouteProbeReply = 0x32,
    /// Server → Agent: peer discovery directive with connection details.
    PeerDiscovery = 0x33,
    /// Bidirectional: bandwidth probe — payload is random bytes; receiver
    /// echoes it back immediately so the sender can measure round-trip time.
    BandwidthProbe = 0x34,
    /// Agent → Server: report that a P2P link has died, including quality
    /// metrics captured at the time of failure.
    LinkFailureReport = 0x35,
}

impl P2pFrameType {
    /// Convert a raw `u8` to `P2pFrameType`, returning `None` for unknown
    /// values.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::LinkRequest),
            0x02 => Some(Self::LinkAccept),
            0x03 => Some(Self::LinkReject),
            0x04 => Some(Self::LinkHeartbeat),
            0x05 => Some(Self::LinkDisconnect),
            0x10 => Some(Self::DataForward),
            0x11 => Some(Self::DataAck),
            0x20 => Some(Self::TopologyReport),
            0x30 => Some(Self::RouteUpdate),
            0x31 => Some(Self::RouteProbe),
            0x32 => Some(Self::RouteProbeReply),
            0x33 => Some(Self::PeerDiscovery),
            0x34 => Some(Self::BandwidthProbe),
            0x35 => Some(Self::LinkFailureReport),
            _ => None,
        }
    }
}

/// A single P2P frame exchanged between linked agents.
///
/// The `payload` field contains the AEAD ciphertext (ChaCha20-Poly1305)
/// including the 16-byte authentication tag.  Encryption / decryption is
/// performed at the transport layer using the per-link key; this type is
/// the *post-parse* representation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2pFrame {
    /// Discriminant identifying the purpose of this frame.
    pub frame_type: P2pFrameType,
    /// Random link identifier assigned during link establishment.
    pub link_id: u32,
    /// Length of the encrypted payload in bytes.
    pub payload_len: u32,
    /// Encrypted payload (ciphertext || 16-byte Poly1305 tag).
    pub payload: Vec<u8>,
}

impl P2pFrame {
    /// Serialize the frame into its wire representation.
    ///
    /// Returns a `Vec<u8>` containing the 10-byte header followed by the
    /// encrypted payload.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_SIZE + self.payload.len());
        buf.push(self.frame_type as u8);
        buf.push(0u8); // reserved
        buf.extend_from_slice(&self.link_id.to_le_bytes());
        buf.extend_from_slice(&self.payload_len.to_le_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Parse a frame from its wire representation.
    ///
    /// Returns `Ok(P2pFrame)` on success, or a descriptive error string on
    /// failure (undersized buffer, unknown frame type, payload length
    /// mismatch).
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        if data.len() < HEADER_SIZE {
            return Err(format!(
                "buffer too short for P2P header: {} < {HEADER_SIZE}",
                data.len()
            ));
        }

        let frame_type = P2pFrameType::from_u8(data[0]).ok_or_else(|| {
            format!("unknown P2P frame type: 0x{:02X}", data[0])
        })?;

        // data[1] is reserved — skip.
        let link_id = u32::from_le_bytes([data[2], data[3], data[4], data[5]]);
        let payload_len = u32::from_le_bytes([data[6], data[7], data[8], data[9]]);

        if payload_len > MAX_PAYLOAD_BYTES {
            return Err(format!(
                "P2P payload too large: {payload_len} > {MAX_PAYLOAD_BYTES}"
            ));
        }

        let payload_start = HEADER_SIZE;
        let payload_end = payload_start + payload_len as usize;
        if data.len() < payload_end {
            return Err(format!(
                "P2P frame truncated: have {} bytes, need {payload_end}",
                data.len()
            ));
        }

        let payload = data[payload_start..payload_end].to_vec();

        Ok(Self {
            frame_type,
            link_id,
            payload_len,
            payload,
        })
    }
}

// ══════════════════════════════════════════════════════════════════════════
// Route discovery serialization helpers
// ══════════════════════════════════════════════════════════════════════════

/// A single entry in a distance-vector routing table.
///
/// Wire format inside a `RouteUpdate` frame:
/// ```text
/// [ destination: u32 LE ] [ next_hop: u32 LE ] [ hop_count: u8 ] [ route_quality: f32 LE ]
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteEntry {
    /// The destination agent or link ID.
    pub destination: u32,
    /// The next-hop link to forward through.
    pub next_hop: u32,
    /// Number of hops to reach the destination.
    pub hop_count: u8,
    /// Quality metric (0.0–1.0, higher is better).
    pub route_quality: f32,
}

impl RouteEntry {
    /// Serialized size of one route entry: 4 + 4 + 1 + 4 = 13 bytes.
    pub const WIRE_SIZE: usize = 13;

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::WIRE_SIZE);
        buf.extend_from_slice(&self.destination.to_le_bytes());
        buf.extend_from_slice(&self.next_hop.to_le_bytes());
        buf.push(self.hop_count);
        buf.extend_from_slice(&self.route_quality.to_le_bytes());
        buf
    }

    /// Deserialize from bytes. Returns `(entry, bytes_consumed)`.
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        if data.len() < Self::WIRE_SIZE {
            return Err(format!(
                "RouteEntry buffer too short: {} < {}",
                data.len(),
                Self::WIRE_SIZE
            ));
        }
        let destination = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let next_hop = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let hop_count = data[8];
        let route_quality = f32::from_le_bytes([data[9], data[10], data[11], data[12]]);
        Ok(Self {
            destination,
            next_hop,
            hop_count,
            route_quality,
        })
    }
}

/// Serialize a list of route entries into bytes for a `RouteUpdate` frame.
///
/// Wire format:
/// ```text
/// [ count: u16 LE ] [ RouteEntry 0 ] [ RouteEntry 1 ] …
/// ```
pub fn serialize_route_update(entries: &[RouteEntry]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2 + entries.len() * RouteEntry::WIRE_SIZE);
    buf.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    for e in entries {
        buf.extend_from_slice(&e.to_bytes());
    }
    buf
}

/// Deserialize a `RouteUpdate` payload into a list of route entries.
pub fn deserialize_route_update(data: &[u8]) -> Result<Vec<RouteEntry>, String> {
    if data.len() < 2 {
        return Err("RouteUpdate payload too short".to_string());
    }
    let count = u16::from_le_bytes([data[0], data[1]]) as usize;
    let mut entries = Vec::with_capacity(count);
    let mut offset = 2;
    for _ in 0..count {
        let entry = RouteEntry::from_bytes(&data[offset..])?;
        offset += RouteEntry::WIRE_SIZE;
        entries.push(entry);
    }
    Ok(entries)
}

// ══════════════════════════════════════════════════════════════════════════
// RouteProbe / RouteProbeReply serialization
// ══════════════════════════════════════════════════════════════════════════

/// Serialize a `RouteProbe` payload — just the destination we want to find.
///
/// Wire format: `[ destination: u32 LE ]`
pub fn serialize_route_probe(destination: u32) -> Vec<u8> {
    destination.to_le_bytes().to_vec()
}

/// Deserialize a `RouteProbe` payload.
pub fn deserialize_route_probe(data: &[u8]) -> Result<u32, String> {
    if data.len() < 4 {
        return Err(format!(
            "RouteProbe payload too short: {} < 4",
            data.len()
        ));
    }
    Ok(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
}

/// Serialize a `RouteProbeReply` payload.
///
/// Wire format: `[ destination: u32 LE ] [ next_hop: u32 LE ] [ hop_count: u8 ] [ route_quality: f32 LE ]`
pub fn serialize_route_probe_reply(entry: &RouteEntry) -> Vec<u8> {
    entry.to_bytes()
}

/// Deserialize a `RouteProbeReply` payload.
pub fn deserialize_route_probe_reply(data: &[u8]) -> Result<RouteEntry, String> {
    RouteEntry::from_bytes(data)
}

// ══════════════════════════════════════════════════════════════════════════
// PeerDiscovery serialization
// ══════════════════════════════════════════════════════════════════════════


/// A target agent to connect to, as specified in a `PeerDiscovery` frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerTarget {
    /// Agent ID of the target.
    pub agent_id: String,
    /// Transport protocol to use (`"tcp"` or `"smb"`).
    pub transport: String,
    /// Connection address (host:port for TCP, pipe path for SMB).
    pub address: String,
}

impl PeerTarget {
    /// Serialize a list of peer targets.
    ///
    /// Wire format:
    /// ```text
    /// [ count: u16 LE ]
    /// For each target:
    ///   [ agent_id_len: u16 LE ] [ agent_id: bytes ]
    ///   [ transport_len: u16 LE ] [ transport: bytes ]
    ///   [ address_len: u16 LE ] [ address: bytes ]
    /// ```
    pub fn serialize_list(targets: &[PeerTarget]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(targets.len() as u16).to_le_bytes());
        for t in targets {
            let id_bytes = t.agent_id.as_bytes();
            buf.extend_from_slice(&(id_bytes.len() as u16).to_le_bytes());
            buf.extend_from_slice(id_bytes);

            let tp_bytes = t.transport.as_bytes();
            buf.extend_from_slice(&(tp_bytes.len() as u16).to_le_bytes());
            buf.extend_from_slice(tp_bytes);

            let addr_bytes = t.address.as_bytes();
            buf.extend_from_slice(&(addr_bytes.len() as u16).to_le_bytes());
            buf.extend_from_slice(addr_bytes);
        }
        buf
    }

    /// Deserialize a list of peer targets.
    pub fn deserialize_list(data: &[u8]) -> Result<Vec<PeerTarget>, String> {
        if data.len() < 2 {
            return Err("PeerDiscovery payload too short".to_string());
        }
        let count = u16::from_le_bytes([data[0], data[1]]) as usize;
        let mut targets = Vec::with_capacity(count);
        let mut offset = 2;

        for _ in 0..count {
            // agent_id
            if data.len() < offset + 2 {
                return Err("PeerDiscovery: truncated agent_id_len".to_string());
            }
            let id_len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;
            if data.len() < offset + id_len {
                return Err("PeerDiscovery: truncated agent_id".to_string());
            }
            let agent_id = String::from_utf8(data[offset..offset + id_len].to_vec())
                .map_err(|e| format!("PeerDiscovery: invalid agent_id UTF-8: {e}"))?;
            offset += id_len;

            // transport
            if data.len() < offset + 2 {
                return Err("PeerDiscovery: truncated transport_len".to_string());
            }
            let tp_len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;
            if data.len() < offset + tp_len {
                return Err("PeerDiscovery: truncated transport".to_string());
            }
            let transport = String::from_utf8(data[offset..offset + tp_len].to_vec())
                .map_err(|e| format!("PeerDiscovery: invalid transport UTF-8: {e}"))?;
            offset += tp_len;

            // address
            if data.len() < offset + 2 {
                return Err("PeerDiscovery: truncated address_len".to_string());
            }
            let addr_len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;
            if data.len() < offset + addr_len {
                return Err("PeerDiscovery: truncated address".to_string());
            }
            let address = String::from_utf8(data[offset..offset + addr_len].to_vec())
                .map_err(|e| format!("PeerDiscovery: invalid address UTF-8: {e}"))?;
            offset += addr_len;

            targets.push(PeerTarget {
                agent_id,
                transport,
                address,
            });
        }
        Ok(targets)
    }
}

// ══════════════════════════════════════════════════════════════════════════
// BandwidthProbe serialization
// ══════════════════════════════════════════════════════════════════════════

/// Bandwidth probe payload: just raw bytes (random padding).
/// The receiver echoes the exact same payload back.
///
/// Wire format: `[payload_len: u32 LE] [padding: bytes]`
///
/// Note: the actual P2P frame already carries `payload_len`, so the
/// serialization here is simply the raw padding bytes.  The 4-byte length
/// prefix is **not** duplicated — it lives in the frame header.

/// Default bandwidth probe payload size (4 KiB).
pub const BANDWIDTH_PROBE_SIZE: usize = 4096;

/// Serialize a `BandwidthProbe` payload — just random bytes.
///
/// The caller should fill `padding` with cryptographically random data.
pub fn serialize_bandwidth_probe(padding: &[u8]) -> Vec<u8> {
    padding.to_vec()
}

/// Deserialize a `BandwidthProbe` payload — returns the raw bytes.
pub fn deserialize_bandwidth_probe(data: &[u8]) -> Vec<u8> {
    data.to_vec()
}

// ══════════════════════════════════════════════════════════════════════════
// LinkFailureReport serialization
// ══════════════════════════════════════════════════════════════════════════

/// Data about a failed link, sent from the agent to the server.
///
/// Wire format:
/// ```text
/// [ dead_peer_id_len: u16 LE ] [ dead_peer_id: bytes ]
/// [ link_type: u8 ]            (0 = Parent, 1 = Child, 2 = Peer)
/// [ uptime_secs: u64 LE ]
/// [ latency_ms: u32 LE ]
/// [ packet_loss: f32 LE ]
/// [ bandwidth_bps: u64 LE ]
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkFailureReportData {
    /// Agent ID of the peer on the dead link.
    pub dead_peer_id: String,
    /// Topology type of the dead link.
    pub link_type: u8,
    /// How long the link was alive before failure, in seconds.
    pub uptime_secs: u64,
    /// Last-known latency in milliseconds.
    pub latency_ms: u32,
    /// Last-known packet loss ratio (0.0–1.0).
    pub packet_loss: f32,
    /// Last-known estimated bandwidth in bits per second.
    pub bandwidth_bps: u64,
}

impl LinkFailureReportData {
    /// Serialize the report into bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let id_bytes = self.dead_peer_id.as_bytes();
        buf.extend_from_slice(&(id_bytes.len() as u16).to_le_bytes());
        buf.extend_from_slice(id_bytes);
        buf.push(self.link_type);
        buf.extend_from_slice(&self.uptime_secs.to_le_bytes());
        buf.extend_from_slice(&self.latency_ms.to_le_bytes());
        buf.extend_from_slice(&self.packet_loss.to_le_bytes());
        buf.extend_from_slice(&self.bandwidth_bps.to_le_bytes());
        buf
    }

    /// Deserialize a `LinkFailureReport` payload.
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        if data.len() < 2 {
            return Err("LinkFailureReport: payload too short".to_string());
        }
        let id_len = u16::from_le_bytes([data[0], data[1]]) as usize;
        if data.len() < 2 + id_len + 1 + 8 + 4 + 4 + 8 {
            return Err(format!(
                "LinkFailureReport: payload too short: {} < {}",
                data.len(),
                2 + id_len + 25
            ));
        }
        let mut offset = 2;
        let dead_peer_id = String::from_utf8(data[offset..offset + id_len].to_vec())
            .map_err(|e| format!("LinkFailureReport: invalid peer_id UTF-8: {e}"))?;
        offset += id_len;
        let link_type = data[offset];
        offset += 1;
        let uptime_secs = u64::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
            data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
        ]);
        offset += 8;
        let latency_ms = u32::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        ]);
        offset += 4;
        let packet_loss = f32::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        ]);
        offset += 4;
        let bandwidth_bps = u64::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
            data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
        ]);
        Ok(Self {
            dead_peer_id,
            link_type,
            uptime_secs,
            latency_ms,
            packet_loss,
            bandwidth_bps,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_link_request() {
        let frame = P2pFrame {
            frame_type: P2pFrameType::LinkRequest,
            link_id: 0xDEAD_BEEF,
            payload_len: 5,
            payload: vec![1, 2, 3, 4, 5],
        };
        let bytes = frame.to_bytes();
        assert_eq!(bytes.len(), HEADER_SIZE + 5);
        assert_eq!(bytes[0], P2pFrameType::LinkRequest as u8);
        assert_eq!(bytes[1], 0u8); // reserved

        let parsed = P2pFrame::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.frame_type, P2pFrameType::LinkRequest);
        assert_eq!(parsed.link_id, 0xDEAD_BEEF);
        assert_eq!(parsed.payload_len, 5);
        assert_eq!(parsed.payload, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn reject_unknown_frame_type() {
        let mut buf = vec![0xFFu8, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
        let err = P2pFrame::from_bytes(&buf).unwrap_err();
        assert!(err.contains("unknown P2P frame type"));
    }

    #[test]
    fn reject_truncated_frame() {
        let buf = [0x01u8, 0x00]; // too short
        let err = P2pFrame::from_bytes(&buf).unwrap_err();
        assert!(err.contains("buffer too short"));
    }

    #[test]
    fn all_discriminants_roundtrip() {
        for v in [
            P2pFrameType::LinkRequest,
            P2pFrameType::LinkAccept,
            P2pFrameType::LinkReject,
            P2pFrameType::LinkHeartbeat,
            P2pFrameType::LinkDisconnect,
            P2pFrameType::DataForward,
            P2pFrameType::DataAck,
            P2pFrameType::TopologyReport,
            P2pFrameType::RouteUpdate,
            P2pFrameType::RouteProbe,
            P2pFrameType::RouteProbeReply,
            P2pFrameType::PeerDiscovery,
            P2pFrameType::BandwidthProbe,
            P2pFrameType::LinkFailureReport,
        ] {
            assert_eq!(P2pFrameType::from_u8(v as u8), Some(v));
        }
    }

    #[test]
    fn route_entry_roundtrip() {
        let entry = RouteEntry {
            destination: 0xAABB_CCDD,
            next_hop: 0x1122_3344,
            hop_count: 3,
            route_quality: 0.85,
        };
        let bytes = entry.to_bytes();
        assert_eq!(bytes.len(), RouteEntry::WIRE_SIZE);

        let parsed = RouteEntry::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.destination, entry.destination);
        assert_eq!(parsed.next_hop, entry.next_hop);
        assert_eq!(parsed.hop_count, entry.hop_count);
        assert!((parsed.route_quality - entry.route_quality).abs() < f32::EPSILON);
    }

    #[test]
    fn route_update_roundtrip() {
        let entries = vec![
            RouteEntry {
                destination: 1,
                next_hop: 10,
                hop_count: 1,
                route_quality: 1.0,
            },
            RouteEntry {
                destination: 2,
                next_hop: 10,
                hop_count: 2,
                route_quality: 0.75,
            },
        ];
        let bytes = serialize_route_update(&entries);
        let parsed = deserialize_route_update(&bytes).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].destination, 1);
        assert_eq!(parsed[1].hop_count, 2);
    }

    #[test]
    fn route_probe_roundtrip() {
        let dest: u32 = 0xDEAD_BEEF;
        let bytes = serialize_route_probe(dest);
        assert_eq!(bytes.len(), 4);
        let parsed = deserialize_route_probe(&bytes).unwrap();
        assert_eq!(parsed, dest);
    }

    #[test]
    fn peer_target_roundtrip() {
        let targets = vec![
            PeerTarget {
                agent_id: "agent-1".to_string(),
                transport: "tcp".to_string(),
                address: "10.0.0.1:9050".to_string(),
            },
            PeerTarget {
                agent_id: "agent-2".to_string(),
                transport: "smb".to_string(),
                address: r"\\.\pipe\test-pipe".to_string(),
            },
        ];
        let bytes = PeerTarget::serialize_list(&targets);
        let parsed = PeerTarget::deserialize_list(&bytes).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].agent_id, "agent-1");
        assert_eq!(parsed[0].transport, "tcp");
        assert_eq!(parsed[0].address, "10.0.0.1:9050");
        assert_eq!(parsed[1].agent_id, "agent-2");
        assert_eq!(parsed[1].address, r"\\.\pipe\test-pipe");
    }

    #[test]
    fn bandwidth_probe_roundtrip() {
        let padding = vec![0xAB; BANDWIDTH_PROBE_SIZE];
        let serialized = serialize_bandwidth_probe(&padding);
        assert_eq!(serialized.len(), BANDWIDTH_PROBE_SIZE);
        let deserialized = deserialize_bandwidth_probe(&serialized);
        assert_eq!(deserialized, padding);
    }

    #[test]
    fn link_failure_report_roundtrip() {
        let report = LinkFailureReportData {
            dead_peer_id: "agent-dead-42".to_string(),
            link_type: 2, // Peer
            uptime_secs: 3600,
            latency_ms: 150,
            packet_loss: 0.05,
            bandwidth_bps: 1_000_000,
        };
        let bytes = report.to_bytes();
        let parsed = LinkFailureReportData::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.dead_peer_id, "agent-dead-42");
        assert_eq!(parsed.link_type, 2);
        assert_eq!(parsed.uptime_secs, 3600);
        assert_eq!(parsed.latency_ms, 150);
        assert!((parsed.packet_loss - 0.05).abs() < f32::EPSILON);
        assert_eq!(parsed.bandwidth_bps, 1_000_000);
    }
}
