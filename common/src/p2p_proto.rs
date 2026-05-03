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
        ] {
            assert_eq!(P2pFrameType::from_u8(v as u8), Some(v));
        }
    }
}
